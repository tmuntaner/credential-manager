use crate::utils;
use anyhow::{anyhow, Result};
use c9s::okta::okta_client::OktaClient;
use c9s::settings::{AppConfig, AwsHost, AwsSsoHost};
use clap::Clap;

#[derive(Clap)]
pub enum CredentialsSubCommands {
    Aws(AwsCredentials),
    AwsSso(AwsSsoCredentials),
}

#[derive(Clap)]
pub struct Credentials {
    #[clap(subcommand)]
    pub sub_command: CredentialsSubCommands,
}

#[derive(Clap)]
pub struct AwsCredentials {
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
pub struct AwsSsoCredentials {
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

impl AwsSsoCredentials {
    pub async fn run(&self, settings: AppConfig) -> Result<()> {
        let default_settings = match self.app_url.clone() {
            Some(app_url) => settings.find_aws_sso_host(app_url),
            None => settings.aws_sso_hosts(),
        };

        let app_url = self.app_url(&default_settings)?;
        let username = self.username(&default_settings)?;
        let region = self.region(&default_settings)?;
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
    pub async fn run(&self, settings: AppConfig) -> Result<()> {
        let default_settings = match self.app_url.clone() {
            Some(app_url) => settings.find_aws_host(app_url),
            None => settings.aws_hosts(),
        };

        let app_url = self.app_url(&default_settings)?;
        let username = self.username(&default_settings)?;
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
