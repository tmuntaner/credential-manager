pub mod aws;
pub mod okta;
mod settings;
pub mod verify;

use crate::settings::Host;
use anyhow::{anyhow, Result};
use clap::{AppSettings, Clap};
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
    Creds(Creds),
}

#[derive(Clap)]
struct Config {
    #[clap(subcommand)]
    sub_command: ConfigSubCommand,
}

#[derive(Clap)]
struct Creds {
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
enum ConfigSubCommand {
    Add(ConfigAdd),
}

#[derive(Clap)]
struct ConfigAdd {
    #[clap(required = true, long)]
    app_url: String,
    #[clap(required = true, short, long)]
    username: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt: Opts = Opts::parse();

    match opt.sub_command {
        SubCommand::Config(val) => match val.sub_command {
            ConfigSubCommand::Add(val) => {
                let mut settings = settings::Config::read_config().unwrap();
                let host = Host::new(val.app_url, val.username)?;
                settings.add_host(host)?;
                settings.write_config()?;
            }
        },
        SubCommand::Creds(val) => {
            let settings = settings::Config::read_config().unwrap();

            let default_settings = match val.app_url.clone() {
                Some(app_url) => settings.find_host(app_url),
                None => settings.host(),
            };

            let app_url = match val.app_url {
                Some(app_url) => app_url,
                None => match default_settings.clone() {
                    Some(default) => default.app_url(),
                    None => {
                        return Err(anyhow!("please supply an app-url"));
                    }
                },
            };

            let username = match val.username {
                Some(username) => username,
                None => match default_settings {
                    Some(default) => default.username(),
                    None => {
                        return Err(anyhow!("please supply a username"));
                    }
                },
            };

            let app_domain = Url::parse(app_url.as_str())?;
            let app_domain = app_domain.domain().ok_or_else(|| anyhow!("foo"))?;
            let service = format!("c9s -- {}", app_domain);

            let keyring = keyring::Keyring::new(service.as_str(), username.as_str());

            let password = match val.with_password {
                true => {
                    let password = rpassword::prompt_password_stdout("Password: ").unwrap();

                    print!("Save password? (y/n) ");
                    let _ = io::stdout().flush();
                    let mut buffer = String::new();
                    io::stdin().lock().read_line(&mut buffer).unwrap();
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

            let state_machine = okta::state_machine::Factory {};
            state_machine
                .run(username, password, app_url, val.role_arn)
                .await
                .unwrap();
        }
    }

    Ok(())
}
