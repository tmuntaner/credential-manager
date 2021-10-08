use crate::utils;
use anyhow::{anyhow, Result};
use c9s::okta::okta_client::OktaClient;
use c9s::settings::AppConfig;
use clap::Clap;

#[derive(Clap)]
pub struct Credentials {
    #[clap(subcommand)]
    sub_command: CredentialsSubCommands,
}

#[derive(Clap)]
enum CredentialsSubCommands {
    Aws(AwsCredentials),
    AwsSso(AwsSsoCredentials),
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

impl Credentials {
    pub async fn run(&self, settings: AppConfig) -> Result<()> {
        match &self.sub_command {
            CredentialsSubCommands::AwsSso(val) => val.run(settings).await,
            CredentialsSubCommands::Aws(val) => val.run(settings).await,
        }
    }
}

impl AwsSsoCredentials {
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
                .ok_or_else(|| anyhow!("please supply a region"))?
                .region(),
        );
        let password = utils::get_password(app_url.clone(), username.clone(), self.with_password)?;

        let client = OktaClient::new()?;
        let aws_credentials = client
            .aws_sso_credentials(username, password, app_url, region, self.role_arn.clone())
            .await?;

        for credential in aws_credentials {
            println!(
                "{}\nexport AWS_ACCESS_KEY_ID=\"{}\"\nexport AWS_SECRET_ACCESS_KEY=\"{}\"\nexport AWS_SESSION_TOKEN=\"{}\"\n",
                credential.role_arn, credential.access_key_id, credential.secret_access_key, credential.session_token
            );
        }

        Ok(())
    }
}

impl AwsCredentials {
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
        let password = utils::get_password(app_url.clone(), username.clone(), self.with_password)?;

        let client = OktaClient::new()?;
        let aws_credentials = client
            .aws_credentials(username, password, app_url, self.role_arn.clone())
            .await?;

        for credential in aws_credentials {
            println!(
                "{}\nexport AWS_ACCESS_KEY_ID=\"{}\"\nexport AWS_SECRET_ACCESS_KEY=\"{}\"\nexport AWS_SESSION_TOKEN=\"{}\"\n",
                credential.role_arn, credential.access_key_id, credential.secret_access_key, credential.session_token
            );
        }

        Ok(())
    }
}
