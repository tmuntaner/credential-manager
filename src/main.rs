pub mod aws;
mod http;
pub mod okta;
mod settings;
pub mod verify;

use crate::settings::{AwsHost, AwsSsoHost};
use anyhow::{anyhow, Result};
use clap::{AppSettings, Clap};
use log::LevelFilter;
use simple_logger::SimpleLogger;
use std::io::{self, BufRead, Write};
use url::Url;

#[derive(Clap)]
#[clap(
    version = "1.0",
    author = "Thomas Muntaner <thomas.muntaner@gmail.com>"
)]
#[clap(setting = AppSettings::ColoredHelp)]
struct Opts {
    #[clap(subcommand)]
    sub_command: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    Config(Config),
    Creds(Credentials),
}

#[derive(Clap)]
enum CredentialsSubCommands {
    Aws(AwsCredentials),
    AwsSso(AwsSsoCredentials),
}

#[derive(Clap)]
struct Credentials {
    #[clap(subcommand)]
    sub_command: CredentialsSubCommands,
}

#[derive(Clap)]
struct AwsCredentials {
    #[clap(long)]
    app_url: Option<String>,
    #[clap(short, long)]
    username: Option<String>,
    #[clap(short, long)]
    with_password: bool,
    #[clap(short, long)]
    role_arn: Option<String>,
}

#[derive(Clap)]
struct AwsSsoCredentials {
    #[clap(long)]
    app_url: Option<String>,
    #[clap(short, long)]
    username: Option<String>,
    #[clap(short, long)]
    with_password: bool,
    #[clap(long)]
    region: Option<String>,
    #[clap(short, long)]
    role_arn: Option<String>,
}

#[derive(Clap)]
struct Config {
    #[clap(subcommand)]
    sub_command: ConfigSubCommand,
}

#[derive(Clap)]
enum ConfigSubCommand {
    Add(ConfigAdd),
}

#[derive(Clap)]
struct ConfigAdd {
    #[clap(subcommand)]
    sub_command: ConfigAddSubCommand,
}

#[derive(Clap)]
enum ConfigAddSubCommand {
    Aws(ConfigAddAws),
    AwsSso(ConfigAddAwsSso),
}

#[derive(Clap)]
struct ConfigAddAws {
    #[clap(required = true, long)]
    app_url: String,
    #[clap(required = true, short, long)]
    username: String,
}

#[derive(Clap)]
struct ConfigAddAwsSso {
    #[clap(required = true, long)]
    app_url: String,
    #[clap(required = true, short, long)]
    username: String,
    #[clap(required = true, short, long)]
    region: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt: Opts = Opts::parse();
    let mut settings = settings::Config::read_config()?;

    SimpleLogger::new().with_level(LevelFilter::Info).init()?;

    match opt.sub_command {
        SubCommand::Config(val) => match val.sub_command {
            ConfigSubCommand::Add(val) => match val.sub_command {
                ConfigAddSubCommand::Aws(val) => {
                    let host = AwsHost::new(val.app_url, val.username)?;
                    settings.add_aws_host(host);
                    settings.write_config()?;
                }
                ConfigAddSubCommand::AwsSso(val) => {
                    let host = AwsSsoHost::new(val.app_url, val.username, val.region)?;
                    settings.add_aws_sso_host(host);
                    settings.write_config()?;
                }
            },
        },
        SubCommand::Creds(val) => match val.sub_command {
            CredentialsSubCommands::AwsSso(val) => {
                let default_settings = match val.app_url.clone() {
                    Some(app_url) => settings.find_aws_sso_host(app_url),
                    None => settings.aws_sso_hosts(),
                };

                let app_url = val.app_url(&default_settings)?;
                let username = val.username(&default_settings)?;
                let region = val.region(&default_settings)?;
                let password = get_password(app_url.clone(), username.clone(), val.with_password)?;

                let client = okta::okta_client::OktaClient::new()?;
                let aws_credentials = client
                    .aws_sso_credentials(username, password, app_url, region, val.role_arn)
                    .await?;

                for credential in aws_credentials {
                    println!(
                        "{}\nexport AWS_ACCESS_KEY_ID=\"{}\"\nexport AWS_SECRET_ACCESS_KEY=\"{}\"\nexport AWS_SESSION_TOKEN=\"{}\"\n",
                        credential.role_arn, credential.access_key_id, credential.secret_access_key, credential.session_token
                    );
                }
            }
            CredentialsSubCommands::Aws(val) => {
                let default_settings = match val.app_url.clone() {
                    Some(app_url) => settings.find_aws_host(app_url),
                    None => settings.aws_hosts(),
                };

                let app_url = val.app_url(&default_settings)?;
                let username = val.username(&default_settings)?;
                let password = get_password(app_url.clone(), username.clone(), val.with_password)?;

                let client = okta::okta_client::OktaClient::new()?;
                let aws_credentials = client
                    .aws_credentials(username, password, app_url, val.role_arn)
                    .await?;

                for credential in aws_credentials {
                    println!(
                        "{}\nexport AWS_ACCESS_KEY_ID=\"{}\"\nexport AWS_SECRET_ACCESS_KEY=\"{}\"\nexport AWS_SESSION_TOKEN=\"{}\"\n",
                        credential.role_arn, credential.access_key_id, credential.secret_access_key, credential.session_token
                    );
                }
            }
        },
    }

    Ok(())
}

fn get_password(app_url: String, username: String, with_password: bool) -> Result<String> {
    let app_domain = Url::parse(app_url.as_str())?;
    let app_domain = app_domain.domain().ok_or_else(|| anyhow!("foo"))?;
    let service = format!("c9s -- {}", app_domain);

    let keyring = keyring::Keyring::new(service.as_str(), username.as_str());

    let password = match with_password {
        true => {
            let password = rpassword::prompt_password_stdout("Password: ")?;

            print!("Save password? (y/n) ");
            let _ = io::stdout().flush();
            let mut buffer = String::new();
            io::stdin().lock().read_line(&mut buffer)?;
            // remove \n on unix or \r\n on windows
            let len = buffer.trim_end_matches(&['\r', '\n'][..]).len();
            buffer.truncate(len);

            if buffer == "y" {
                keyring.set_password(password.as_str()).unwrap();
            }

            password
        }
        false => keyring
            .get_password()
            .map_err(|_e| anyhow!("please supply a password"))?,
    };

    Ok(password)
}

impl AwsSsoCredentials {
    fn app_url(&self, default_settings: &Option<AwsSsoHost>) -> Result<String> {
        let username = match self.app_url.clone() {
            Some(app_url) => app_url,
            None => match default_settings {
                Some(default) => default.app_url(),
                None => {
                    return Err(anyhow!("please supply an app-url"));
                }
            },
        };

        Ok(username)
    }

    fn region(&self, default_settings: &Option<AwsSsoHost>) -> Result<String> {
        let region = match self.region.clone() {
            Some(region) => region,
            None => match default_settings {
                Some(default) => default.region(),
                None => {
                    return Err(anyhow!("please supply a region"));
                }
            },
        };

        Ok(region)
    }

    fn username(&self, default_settings: &Option<AwsSsoHost>) -> Result<String> {
        let username = match self.username.clone() {
            Some(username) => username,
            None => match default_settings {
                Some(default) => default.username(),
                None => {
                    return Err(anyhow!("please supply a username"));
                }
            },
        };

        Ok(username)
    }
}

impl AwsCredentials {
    fn app_url(&self, default_settings: &Option<AwsHost>) -> Result<String> {
        let username = match self.app_url.clone() {
            Some(app_url) => app_url,
            None => match default_settings {
                Some(default) => default.app_url(),
                None => {
                    return Err(anyhow!("please supply an app-url"));
                }
            },
        };

        Ok(username)
    }

    fn username(&self, default_settings: &Option<AwsHost>) -> Result<String> {
        let username = match self.username.clone() {
            Some(username) => username,
            None => match default_settings {
                Some(default) => default.username(),
                None => {
                    return Err(anyhow!("please supply a username"));
                }
            },
        };

        Ok(username)
    }
}
