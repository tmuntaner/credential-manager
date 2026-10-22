use crate::utils;
use anyhow::{anyhow, Result};
use c9s::authentik::client::AuthentikClient;
use c9s::authentik::mfa::MfaSelection;
use c9s::aws::Credential;
use c9s::settings::{AppConfig, MfaConfig, SsoProvider};
use clap::Parser;
use clap::ValueEnum;
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

#[derive(ValueEnum, PartialEq, Debug, Clone, Copy, Default)]
enum OutputOptions {
    #[default]
    Env,
    AwsProfile,
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
    #[clap(long, value_enum)]
    output: Option<OutputOptions>,
    #[clap(long)]
    enable_desktop_notifications: bool,
    #[clap(long)]
    cached: bool,
    #[clap(long, value_enum)]
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

        let client = AuthentikClient::new(self.enable_desktop_notifications)?;

        let aws_credentials = match aws_settings.provider {
            SsoProvider::AuthentikAws => {
                client
                    .aws_credentials(
                        aws_settings.username,
                        password,
                        aws_settings.app_url,
                        self.role_arn.clone(),
                        aws_settings.mfa,
                    )
                    .await?
            }
            SsoProvider::AuthentikAwsSso => {
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
                    )
                    .await?
            }
        };

        print_credentials(&aws_credentials, self.output)?;
        if let Some(role_arn) = &self.role_arn {
            if aws_credentials.len() == 1 {
                let credential = aws_credentials
                    .first()
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

        let provider = self
            .sso_provider
            .unwrap_or_else(|| settings.aws_defaults().sso_provider());

        match provider {
            SsoProvider::AuthentikAws => {
                let default_settings = match self.app_url.clone() {
                    Some(app_url) => settings.find_aws_host(app_url),
                    None => settings.aws_hosts(),
                };

                mfa = get_mfa_option(self.mfa.clone(), &default_settings);
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
            SsoProvider::AuthentikAwsSso => {
                let default_settings = match self.app_url.clone() {
                    Some(app_url) => settings.find_aws_sso_host(app_url),
                    None => settings.aws_sso_hosts(),
                };

                mfa = get_mfa_option(self.mfa.clone(), &default_settings);

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
            provider,
        })
    }
}

struct AwsSettings {
    app_url: String,
    username: String,
    region: Option<String>,
    mfa: Option<MfaSelection>,
    provider: SsoProvider,
}

fn get_mfa_option<T: MfaConfig>(
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
                .first()
                .ok_or_else(|| anyhow!("failed to get credential"))?;
            let json = json!({
                "Version": 1,
                "AccessKeyId" : credential.access_key_id(),
                "SecretAccessKey" : credential.secret_access_key(),
                "SessionToken" : credential.session_token(),
                "Expiration" : credential.expiration()
            });

            println!("{json}")
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use c9s::settings::AwsHost;

    const AWS_URL: &str = "https://id.example.com/application/saml/aws/sso/binding/init";
    const SSO_URL: &str = "https://id.example.com/application/saml/sso/sso/binding/init";

    fn settings(default_provider: &str) -> AppConfig {
        toml::from_str(&format!(
            r#"
            [global_settings.aws_defaults]
            sso_provider = "{default_provider}"

            [[authentik_aws_hosts]]
            app_url = "{AWS_URL}"
            username = "aws-user@example.com"
            mfa = "totp"

            [[authentik_aws_sso_hosts]]
            app_url = "{SSO_URL}"
            username = "sso-user@example.com"
            region = "eu-central-1"
            mfa = "webauthn"
            "#
        ))
        .unwrap()
    }

    fn aws_credentials(args: &[&str]) -> Result<AwsCredentials, clap::Error> {
        let mut argv = vec!["creds", "aws"];
        argv.extend(args);

        let credentials = Credentials::try_parse_from(argv)?;
        let CredentialsSubCommands::Aws(aws) = credentials.sub_command;

        Ok(aws)
    }

    #[test]
    fn parses_the_authentik_providers() {
        for (name, provider) in [
            ("authentik-aws", SsoProvider::AuthentikAws),
            ("authentik-aws-sso", SsoProvider::AuthentikAwsSso),
        ] {
            let aws = aws_credentials(&["--sso-provider", name]).unwrap();
            assert_eq!(aws.sso_provider, Some(provider));
        }
    }

    #[test]
    fn the_okta_provider_and_mfa_provider_flag_are_gone() {
        assert!(aws_credentials(&["--sso-provider", "okta-aws"]).is_err());
        assert!(aws_credentials(&["--mfa-provider", "google"]).is_err());
    }

    #[test]
    fn uses_the_default_provider_and_its_first_host() {
        let aws = aws_credentials(&[]).unwrap();

        let found = aws.find_settings(&settings("authentik-aws")).unwrap();
        assert_eq!(found.provider, SsoProvider::AuthentikAws);
        assert_eq!(found.app_url, AWS_URL);
        assert_eq!(found.username, "aws-user@example.com");
        assert!(found.region.is_none());
        assert!(matches!(found.mfa, Some(MfaSelection::Totp)));

        let found = aws.find_settings(&settings("authentik-aws-sso")).unwrap();
        assert_eq!(found.provider, SsoProvider::AuthentikAwsSso);
        assert_eq!(found.app_url, SSO_URL);
        assert_eq!(found.region.as_deref(), Some("eu-central-1"));
        assert!(matches!(found.mfa, Some(MfaSelection::WebAuthn)));
    }

    #[test]
    fn flags_override_the_stored_host() {
        let aws = aws_credentials(&[
            "--sso-provider",
            "authentik-aws-sso",
            "--app-url",
            SSO_URL,
            "--username",
            "other@example.com",
            "--region",
            "us-east-1",
            "--mfa",
            "totp",
        ])
        .unwrap();

        let found = aws.find_settings(&settings("authentik-aws")).unwrap();
        assert_eq!(found.username, "other@example.com");
        assert_eq!(found.region.as_deref(), Some("us-east-1"));
        assert!(matches!(found.mfa, Some(MfaSelection::Totp)));
    }

    #[test]
    fn settings_are_required_when_nothing_is_stored() {
        let empty: AppConfig = toml::from_str("").unwrap();

        let err = aws_credentials(&[])
            .unwrap()
            .find_settings(&empty)
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "please supply an app-url");

        let err = aws_credentials(&["--sso-provider", "authentik-aws-sso", "--app-url", SSO_URL])
            .unwrap()
            .find_settings(&empty)
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "please supply a username");
    }

    #[test]
    fn a_url_that_is_not_stored_needs_a_username() {
        let aws = aws_credentials(&["--app-url", "https://other.example.com/init"]).unwrap();

        let err = aws.find_settings(&settings("authentik-aws")).err().unwrap();
        assert_eq!(err.to_string(), "please supply a username");
    }

    #[test]
    fn an_sso_url_without_a_region_needs_one() {
        let aws = aws_credentials(&[
            "--sso-provider",
            "authentik-aws-sso",
            "--app-url",
            "https://other.example.com/init",
            "--username",
            "u",
        ])
        .unwrap();

        let err = aws.find_settings(&settings("authentik-aws")).err().unwrap();
        assert_eq!(err.to_string(), "please supply a region");
    }

    #[test]
    fn an_mfa_flag_wins_over_the_stored_selection() {
        let stored: Option<AwsHost> = settings("authentik-aws").aws_hosts();

        assert!(matches!(
            get_mfa_option(Some("webauthn".to_string()), &stored),
            Some(MfaSelection::WebAuthn)
        ));
        assert!(matches!(
            get_mfa_option(None, &stored),
            Some(MfaSelection::Totp)
        ));
        assert!(get_mfa_option::<AwsHost>(None, &None).is_none());
    }
}
