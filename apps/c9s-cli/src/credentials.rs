use crate::app::CliApplication;
use crate::args::AwsAppTypeArg;
use crate::utils::parse_ttl;
use anyhow::{anyhow, Result};
use c9s::app::aws::{issue_aws, AwsRequest};
use c9s::app::cache::{cache_warning, get_cached_credential, set_cached_credential_best_effort};
use c9s::app::passwords::get_password;
use c9s::app::secrets::{create_secret_stores, SecretStores};
use c9s::domain::models::aws::Credential;
use c9s::domain::models::idp::IdpType;
use c9s::domain::models::login::{AwsOverrides, RancherOverrides};
use c9s::domain::models::mfa::MfaSelection;
use c9s::domain::models::rancher_credentials::RancherCredential;
use c9s::domain::models::settings::AppConfig;
use c9s::domain::models::user_credentials::UserCredentials;
use c9s::domain::ports::login::LoginResolver;
use c9s::domain::ports::notifier::Notifier;
use c9s::domain::ports::rancher::{KubeconfigRenderer, RancherCredentialIssuer};
use c9s::domain::ports::user_interaction::UserInteraction;
use c9s::domain::services::login_resolver::LoginResolverService;
use c9s::domain::services::rancher_credential_issuer::RancherCredentialIssuerService;
use c9s::outbound::authentik::{AuthentikOidcClient, StoredSessions};
use c9s::outbound::rancher::{RancherClient, RancherKubeconfig};
use clap::Parser;
use clap::ValueEnum;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

#[derive(Parser)]
pub struct Credentials {
    #[clap(subcommand)]
    sub_command: CredentialsSubCommands,
}

#[derive(Parser)]
enum CredentialsSubCommands {
    Aws(AwsCredentials),
    Rancher(RancherCredentials),
}

#[derive(ValueEnum, PartialEq, Debug, Clone, Copy, Default)]
enum RancherOutput {
    /// A kubeconfig for the cluster
    #[default]
    Kubeconfig,
    /// The output of a kubectl credential plugin
    ExecCredential,
}

/// Creates a short-lived token for a cluster behind Rancher
#[derive(Parser)]
struct RancherCredentials {
    /// The Rancher url, defaults to the first configured one
    #[clap(long)]
    url: Option<String>,
    #[clap(short, long)]
    username: Option<String>,
    #[clap(short, long)]
    with_password: bool,
    #[clap(short, long)]
    mfa: Option<MfaSelection>,
    /// The display name of the cluster in Rancher
    #[clap(short, long)]
    cluster: String,
    /// How long the token lives, e.g., 30m, 1h, or 1d
    #[clap(long, default_value = "1h", value_parser = parse_ttl)]
    ttl: Duration,
    #[clap(long, value_enum)]
    output: Option<RancherOutput>,
    #[clap(long)]
    enable_desktop_notifications: bool,
}

/// A token that expires within this long is not handed out from the cache.
const CACHE_MARGIN: time::Duration = time::Duration::seconds(60);

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
    #[clap(long, value_enum)]
    output: Option<OutputOptions>,
    #[clap(long)]
    enable_desktop_notifications: bool,
    #[clap(long)]
    cached: bool,
    #[clap(short, long)]
    mfa: Option<MfaSelection>,
    /// Only needed when it can't be discovered by the configured hosts
    #[clap(long, value_enum)]
    app_type: Option<AwsAppTypeArg>,
}

impl Credentials {
    pub async fn run(&self, application: &CliApplication) -> Result<()> {
        let settings = application.config().clone();
        let prompt = Arc::new(application.interaction());
        let notifier = Arc::new(application.notifier());
        let resolver = LoginResolverService::new(settings.clone());
        match &self.sub_command {
            CredentialsSubCommands::Aws(val) => val.run(prompt, notifier, settings).await,
            CredentialsSubCommands::Rancher(val) => {
                val.run(resolver, prompt, notifier, settings).await
            }
        }
    }
}

impl AwsCredentials {
    async fn run<U: UserInteraction + 'static, N: Notifier + 'static>(
        &self,
        prompt: Arc<U>,
        notifier: Arc<N>,
        settings: AppConfig,
    ) -> Result<()> {
        let credentials = issue_aws(&settings, &self.request(), prompt, notifier).await?;

        print_credentials(&credentials, self.output)
    }

    fn request(&self) -> AwsRequest {
        AwsRequest {
            overrides: self.overrides(),
            role_arn: self.role_arn.clone(),
            with_password: self.with_password,
            enable_desktop_notifications: self.enable_desktop_notifications,
        }
    }

    fn overrides(&self) -> AwsOverrides {
        AwsOverrides {
            app_url: self.app_url.clone(),
            app_type: self.app_type.map(Into::into),
            username: self.username.clone(),
            mfa: self.mfa,
            region: self.region.clone(),
        }
    }
}

impl RancherCredentials {
    async fn run<U: UserInteraction + 'static, N: Notifier + 'static>(
        &self,
        resolver: LoginResolverService,
        prompt: Arc<U>,
        notifier: Arc<N>,
        settings: AppConfig,
    ) -> Result<()> {
        let rancher = resolver.resolve_rancher(&self.overrides())?;
        let cache_key = format!("rancher:{}:{}", rancher.url, self.cluster);
        let SecretStores {
            idp: idp_store,
            cache: cache_store,
            session: session_store,
        } = create_secret_stores(&settings, prompt.clone(), notifier.clone())?;

        let cached: Option<RancherCredential> =
            get_cached_credential(&cache_key, cache_store.as_deref())
                .await
                .unwrap_or_default();
        if let Some(credential) = cached
            .filter(|credential| credential.is_valid_at(OffsetDateTime::now_utc(), CACHE_MARGIN))
        {
            return self.print(&credential);
        }

        let password = get_password(
            rancher.idp_url.clone(),
            rancher.username.clone(),
            self.with_password,
            idp_store.as_deref(),
            prompt.as_ref(),
        )
        .await?;

        let authorizer = match rancher.idp_type {
            IdpType::Authentik => Box::new(AuthentikOidcClient::new(
                rancher.idp_url,
                rancher.client_id,
                self.enable_desktop_notifications,
                prompt.clone(),
                notifier.clone(),
                StoredSessions::new(session_store),
            )),
        };

        let credential = RancherCredentialIssuerService::new(
            authorizer,
            Box::new(RancherClient::new(&rancher.url)?),
        )
        .issue(
            UserCredentials {
                username: rancher.username,
                password,
                mfa: rancher.mfa,
            },
            &self.cluster,
            self.ttl,
        )
        .await?;

        self.print(&credential)?;
        // The cache only saves a login: the credential was printed, so a failure is only a warning.
        if let Some(error) =
            set_cached_credential_best_effort(&cache_key, &credential, cache_store.as_deref()).await
        {
            eprintln!("warning: {}", cache_warning(&error));
        }

        Ok(())
    }

    fn print(&self, credential: &RancherCredential) -> Result<()> {
        let renderer = RancherKubeconfig;
        match self.output.unwrap_or_default() {
            RancherOutput::Kubeconfig => print!("{}", renderer.kubeconfig(credential)),
            RancherOutput::ExecCredential => println!("{}", renderer.exec_credential(credential)?),
        }

        Ok(())
    }

    fn overrides(&self) -> RancherOverrides {
        RancherOverrides {
            url: self.url.clone(),
            username: self.username.clone(),
            mfa: self.mfa,
        }
    }
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
    use c9s::domain::models::settings::AwsAppType;

    const SSO_URL: &str = "https://id.example.com/application/saml/sso/sso/binding/init";

    fn aws_credentials(args: &[&str]) -> Result<AwsCredentials, clap::Error> {
        let mut argv = vec!["creds", "aws"];
        argv.extend(args);

        let credentials = Credentials::try_parse_from(argv)?;
        let CredentialsSubCommands::Aws(aws) = credentials.sub_command else {
            panic!("expected the aws subcommand");
        };

        Ok(aws)
    }

    fn rancher_credentials(args: &[&str]) -> Result<RancherCredentials, clap::Error> {
        let mut argv = vec!["creds", "rancher"];
        argv.extend(args);

        let credentials = Credentials::try_parse_from(argv)?;
        let CredentialsSubCommands::Rancher(rancher) = credentials.sub_command else {
            panic!("expected the rancher subcommand");
        };

        Ok(rancher)
    }

    #[test]
    fn parses_the_app_types() {
        for (name, app_type) in [("aws", AwsAppType::Aws), ("aws-sso", AwsAppType::AwsSso)] {
            let aws = aws_credentials(&["--app-type", name]).unwrap();
            assert_eq!(aws.app_type.map(AwsAppType::from), Some(app_type));
        }
        assert!(aws_credentials(&["--app-type", "authentik-aws"]).is_err());
    }

    #[test]
    fn the_okta_provider_and_mfa_provider_flag_are_gone() {
        assert!(aws_credentials(&["--app-type", "okta-aws"]).is_err());
        assert!(aws_credentials(&["--mfa-provider", "google"]).is_err());
    }

    #[test]
    fn the_flags_become_the_overrides() {
        let aws = aws_credentials(&[
            "--app-type",
            "aws-sso",
            "--app-url",
            SSO_URL,
            "-u",
            "user",
            "-m",
            "TOTP",
            "--region",
            "us-east-1",
        ])
        .unwrap();

        let overrides = aws.overrides();
        assert_eq!(overrides.app_type, Some(AwsAppType::AwsSso));
        assert_eq!(overrides.app_url.as_deref(), Some(SSO_URL));
        assert_eq!(overrides.username.as_deref(), Some("user"));
        assert_eq!(overrides.mfa, Some(MfaSelection::Totp));
        assert_eq!(overrides.region.as_deref(), Some("us-east-1"));

        let rancher = rancher_credentials(&["-c", "x", "--url", "https://r", "-m", "webauthn"])
            .unwrap()
            .overrides();
        assert_eq!(rancher.url.as_deref(), Some("https://r"));
        assert_eq!(rancher.mfa, Some(MfaSelection::WebAuthn));
        assert!(rancher.username.is_none());
    }

    #[test]
    fn an_unknown_mfa_is_rejected_while_parsing() {
        assert!(aws_credentials(&["-m", "sms"]).is_err());
        assert!(rancher_credentials(&["-c", "x", "-m", "sms"]).is_err());
    }

    #[test]
    fn rancher_needs_a_cluster_and_defaults_to_an_hour() {
        assert!(rancher_credentials(&[]).is_err());

        let rancher = rancher_credentials(&["--cluster", "op-prg2-1"]).unwrap();
        assert_eq!(rancher.ttl, Duration::from_secs(3600));
        assert!(rancher.output.is_none());

        let rancher =
            rancher_credentials(&["-c", "x", "--output", "exec-credential", "--ttl", "5m"])
                .unwrap();
        assert_eq!(rancher.output, Some(RancherOutput::ExecCredential));
    }
}
