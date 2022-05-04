use crate::utils;
use anyhow::{anyhow, Result};
use c9s::aws::Credential;
use c9s::okta::okta_client::{MfaSelection, OktaClient};
use c9s::settings::{AppConfig, OktaMfa, SsoProvider};
use clap::ArgEnum;
use clap::Parser;
use serde_json::json;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Parser)]
pub struct Credentials {
    #[clap(subcommand)]
    sub_command: CredentialsSubCommands,
}

#[derive(Parser)]
enum CredentialsSubCommands {
    Aws(AwsCredentials),
}

#[derive(ArgEnum, PartialEq, Debug, Clone, Copy)]
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
struct AwsCredentials {
    #[clap(long)]
    app_url: Option<String>,
    #[clap(short, long)]
    username: Option<String>,
    #[clap(short, long)]
    with_password: bool,
    #[clap(short, long)]
    role_arn: Option<String>,
    #[clap(long)]
    region: Option<String>,
    #[clap(short, long)]
    mfa: Option<String>,
    #[clap(long)]
    mfa_provider: Option<String>,
    #[clap(long, arg_enum)]
    output: Option<OutputOptions>,
    #[clap(long)]
    enable_desktop_notifications: bool,
    #[clap(long)]
    cached: bool,
    #[clap(long, arg_enum)]
    sso_provider: Option<SsoProvider>,
}

impl Credentials {
    pub async fn run(&self, settings: AppConfig) -> Result<()> {
        match &self.sub_command {
            CredentialsSubCommands::Aws(val) => val.run(settings).await,
        }
    }
}

impl AwsCredentials {
    async fn run(&self, settings: AppConfig) -> Result<()> {
        if let Some(credential) =
            cached_credential(self.role_arn.clone(), settings.keyring_enabled())
        {
            print_credentials(&[credential], self.output)?;

            return Ok(());
        }

        let aws_settings = self.find_settings(&settings)?;

        let password = utils::get_password(
            aws_settings.app_url.clone(),
            aws_settings.username.clone(),
            self.with_password,
            settings.keyring_enabled(),
        )?;

        let client = OktaClient::new(self.enable_desktop_notifications)?;

        let aws_credentials = match aws_settings.provider {
            SsoProvider::OktaAws => {
                client
                    .aws_credentials(
                        aws_settings.username,
                        password,
                        aws_settings.app_url,
                        self.role_arn.clone(),
                        aws_settings.mfa,
                        aws_settings.mfa_provider,
                    )
                    .await?
            }
            SsoProvider::OktaAwsSso => {
                client
                    .aws_sso_credentials(
                        aws_settings.username,
                        password,
                        aws_settings.app_url,
                        aws_settings
                            .region
                            .ok_or_else(|| anyhow!("missing region"))?,
                        self.role_arn.clone(),
                        aws_settings.mfa,
                        aws_settings.mfa_provider,
                    )
                    .await?
            }
        };

        print_credentials(&aws_credentials, self.output)?;
        if let Some(role_arn) = &self.role_arn {
            if aws_credentials.len() == 1 {
                let credential = aws_credentials
                    .get(0)
                    .ok_or_else(|| anyhow!("failed to get credential"))?;
                utils::set_cached_credential(role_arn, credential, settings.keyring_enabled())?;
            }
        }

        Ok(())
    }

    fn find_settings(&self, settings: &AppConfig) -> Result<AwsSettings> {
        let app_url;
        let username;
        let mut region = None;
        let mfa;
        let mfa_provider;

        let provider = self
            .sso_provider
            .unwrap_or_else(|| settings.aws_defaults().sso_provider());

        match provider {
            SsoProvider::OktaAws => {
                let default_settings = match self.app_url.clone() {
                    Some(app_url) => settings.find_aws_host(app_url),
                    None => settings.aws_hosts(),
                };

                mfa = get_mfa_option(self.mfa.clone(), &default_settings);
                mfa_provider = get_mfa_provider(self.mfa_provider.clone(), &default_settings);
                app_url = match self.app_url.clone() {
                    None => default_settings
                        .clone()
                        .ok_or_else(|| anyhow!("please supply an app-url"))?
                        .app_url(),
                    Some(url) => url,
                };

                username = match self.username.clone() {
                    None => default_settings
                        .ok_or_else(|| anyhow!("please supply a username"))?
                        .username(),
                    Some(url) => url,
                };
            }
            SsoProvider::OktaAwsSso => {
                let default_settings = match self.app_url.clone() {
                    Some(app_url) => settings.find_aws_sso_host(app_url),
                    None => settings.aws_sso_hosts(),
                };

                mfa = get_mfa_option(self.mfa.clone(), &default_settings);
                mfa_provider = get_mfa_provider(self.mfa_provider.clone(), &default_settings);

                app_url = match self.app_url.clone() {
                    None => default_settings
                        .clone()
                        .ok_or_else(|| anyhow!("please supply an app-url"))?
                        .app_url(),
                    Some(url) => url,
                };

                username = match self.username.clone() {
                    None => default_settings
                        .clone()
                        .ok_or_else(|| anyhow!("please supply a username"))?
                        .username(),
                    Some(url) => url,
                };

                region = match self.region.clone() {
                    None => {
                        let region = default_settings
                            .ok_or_else(|| anyhow!("please supply a region"))?
                            .region();
                        Some(region)
                    }
                    Some(region) => Some(region),
                };
            }
        }

        Ok(AwsSettings {
            app_url,
            username,
            region,
            mfa,
            mfa_provider,
            provider,
        })
    }
}

struct AwsSettings {
    app_url: String,
    username: String,
    region: Option<String>,
    mfa: Option<MfaSelection>,
    mfa_provider: Option<String>,
    provider: SsoProvider,
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

fn cached_credential(role_arn: Option<String>, keyring_enabled: bool) -> Option<Credential> {
    if let Some(role_arn) = role_arn {
        let credential =
            utils::get_cached_credential(&role_arn, keyring_enabled).unwrap_or_default();
        if let Some(credential) = &credential {
            let expires = OffsetDateTime::parse(credential.expiration().as_str(), &Rfc3339).ok()?;
            let now = OffsetDateTime::now_utc();
            if now > expires {
                return None;
            }
        }

        return credential;
    }

    None
}

fn print_credentials(aws_credentials: &[Credential], output: Option<OutputOptions>) -> Result<()> {
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
