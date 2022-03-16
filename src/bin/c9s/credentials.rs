use crate::utils;
use anyhow::{anyhow, Result};
use c9s::aws::Credential;
use c9s::okta::okta_client::{MfaSelection, OktaClient};
use c9s::settings::{AppConfig, OktaMfa};
use clap::ArgEnum;
use clap::Parser;
use serde_json::json;

#[derive(Parser)]
pub struct Credentials {
    #[clap(subcommand)]
    sub_command: CredentialsSubCommands,
}

#[derive(Parser)]
enum CredentialsSubCommands {
    OktaAws(OktaAwsCredentials),
    OktaAwsSso(OktaAwsSsoCredentials),
}

#[derive(ArgEnum, PartialEq, Debug, Clone)]
enum OutputOptions {
    Env,
    AwsProfile,
}

impl Default for OutputOptions {
    fn default() -> Self {
        OutputOptions::Env
    }
}

#[derive(Parser)]
struct OktaAwsCredentials {
    #[clap(long)]
    app_url: Option<String>,
    #[clap(short, long)]
    username: Option<String>,
    #[clap(short, long)]
    with_password: bool,
    #[clap(short, long)]
    role_arn: Option<String>,
    #[clap(short, long)]
    mfa: Option<String>,
    #[clap(long)]
    mfa_provider: Option<String>,
    #[clap(long, arg_enum)]
    output: Option<OutputOptions>,
    #[clap(long)]
    desktop_notifications: bool,
}

#[derive(Parser)]
struct OktaAwsSsoCredentials {
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
    #[clap(short, long)]
    mfa: Option<String>,
    #[clap(long)]
    mfa_provider: Option<String>,
    #[clap(long, arg_enum)]
    output: Option<OutputOptions>,
    #[clap(long)]
    desktop_notifications: bool,
}

impl Credentials {
    pub async fn run(&self, settings: AppConfig) -> Result<()> {
        match &self.sub_command {
            CredentialsSubCommands::OktaAwsSso(val) => val.run(settings).await,
            CredentialsSubCommands::OktaAws(val) => val.run(settings).await,
        }
    }
}

impl OktaAwsSsoCredentials {
    async fn run(&self, settings: AppConfig) -> Result<()> {
        let default_settings = match self.app_url.clone() {
            Some(app_url) => settings.find_aws_sso_host(app_url),
            None => settings.aws_sso_hosts(),
        };
        let app_url = self.app_url.clone().unwrap_or(
            default_settings
                .clone()
                .ok_or_else(|| anyhow!("please supply an app-url"))?
                .app_url(),
        );
        let username = self.username.clone().unwrap_or(
            default_settings
                .clone()
                .ok_or_else(|| anyhow!("please supply a username"))?
                .username(),
        );
        let region = self.region.clone().unwrap_or(
            default_settings
                .clone()
                .ok_or_else(|| anyhow!("please supply a region"))?
                .region(),
        );
        let mfa = get_mfa_option(self.mfa.clone(), &default_settings);
        let mfa_provider = get_mfa_provider(self.mfa_provider.clone(), &default_settings);

        let password = utils::get_password(
            app_url.clone(),
            username.clone(),
            self.with_password,
            settings.keyring_enabled(),
        )?;

        let client = OktaClient::new(self.desktop_notifications)?;
        let aws_credentials = client
            .aws_sso_credentials(
                username,
                password,
                app_url,
                region,
                self.role_arn.clone(),
                mfa,
                mfa_provider,
            )
            .await?;

        print_credentials(aws_credentials, self.output.clone())?;

        Ok(())
    }
}

impl OktaAwsCredentials {
    async fn run(&self, settings: AppConfig) -> Result<()> {
        let default_settings = match self.app_url.clone() {
            Some(app_url) => settings.find_aws_host(app_url),
            None => settings.aws_hosts(),
        };
        let app_url = self.app_url.clone().unwrap_or(
            default_settings
                .clone()
                .ok_or_else(|| anyhow!("please supply an app-url"))?
                .app_url(),
        );
        let username = self.username.clone().unwrap_or(
            default_settings
                .clone()
                .ok_or_else(|| anyhow!("please supply a username"))?
                .username(),
        );
        let mfa = get_mfa_option(self.mfa.clone(), &default_settings);
        let mfa_provider = get_mfa_provider(self.mfa_provider.clone(), &default_settings);

        let password = utils::get_password(
            app_url.clone(),
            username.clone(),
            self.with_password,
            settings.keyring_enabled(),
        )?;

        let client = OktaClient::new(self.desktop_notifications)?;
        let aws_credentials = client
            .aws_credentials(
                username,
                password,
                app_url,
                self.role_arn.clone(),
                mfa,
                mfa_provider,
            )
            .await?;
        print_credentials(aws_credentials, self.output.clone())?;

        Ok(())
    }
}

fn get_mfa_option<T: OktaMfa>(
    mfa: Option<String>,
    default_settings: &Option<T>,
) -> Option<MfaSelection> {
    match mfa {
        Some(mfa) => Some(MfaSelection::from_string(mfa)),
        None => match default_settings {
            Some(settings) => settings.mfa(),
            None => None,
        },
    }
}

fn get_mfa_provider<T: OktaMfa>(
    mfa_provider: Option<String>,
    default_settings: &Option<T>,
) -> Option<String> {
    match mfa_provider {
        Some(mfa) => Some(mfa),
        None => match default_settings {
            Some(default_settings) => default_settings.mfa_provider(),
            None => None,
        },
    }
}

fn print_credentials(
    aws_credentials: Vec<Credential>,
    output: Option<OutputOptions>,
) -> Result<()> {
    match output.unwrap_or_default() {
        OutputOptions::Env => {
            for credential in aws_credentials {
                let role_arn = credential
                    .role_arn()
                    .ok_or_else(|| anyhow!("role arn missing for credential"))?;
                println!(
                    "export AWS_ROLE_ARN=\"{}\"\nexport AWS_ACCESS_KEY_ID=\"{}\"\nexport AWS_SECRET_ACCESS_KEY=\"{}\"\nexport AWS_SESSION_TOKEN=\"{}\"\n",
                    role_arn, credential.access_key_id(), credential.secret_access_key(), credential.session_token()
                );
            }
        }
        OutputOptions::AwsProfile => {
            if aws_credentials.len() > 1 || aws_credentials.is_empty() {
                return Err(anyhow!(format!(
                    "command should return 1 credential, but got {}",
                    aws_credentials.len()
                )));
            }
            let credential = aws_credentials
                .get(0)
                .ok_or_else(|| anyhow!("failed to get credential"))?;
            let json = json!({
                "Version": 1,
                "AccessKeyId" : credential.access_key_id(),
                "SecretAccessKey" : credential.secret_access_key(),
                "SessionToken" : credential.session_token(),
                "Expiration" : credential.expiration()
            });

            println!("{}", json)
        }
    }

    Ok(())
}
