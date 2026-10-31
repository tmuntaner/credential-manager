use crate::args::IdpTypeArg;
use crate::utils::true_or_false;
use anyhow::anyhow;
use anyhow::Result;
use c9s::domain::models::mfa::MfaSelection;
use c9s::domain::models::settings::{AppConfig, AwsHost, AwsSsoHost, Idp, RancherHost};
use c9s::domain::ports::notifier::Notifier;
use c9s::domain::ports::user_interaction::UserInteraction;
use clap::Parser;
use std::sync::Arc;

#[derive(Parser)]
pub struct Config {
    #[clap(subcommand)]
    sub_command: ConfigSubCommand,
}

#[derive(Parser)]
enum ConfigSubCommand {
    Idp(ConfigIdp),
    Aws(ConfigAws),
    Rancher(ConfigRancher),
    Global(ConfigGlobal),
}

#[derive(Parser)]
/// Adds an identity provider, or updates the one with the same name
struct ConfigIdp {
    #[clap(required = true, long)]
    name: String,
    #[clap(long, value_enum, default_value_t)]
    r#type: IdpTypeArg,
    /// The url of the instance, e.g. https://id.example.com
    #[clap(required = true, long)]
    url: String,
    #[clap(required = true, short, long)]
    username: String,
    #[clap(short, long)]
    mfa: Option<MfaSelection>,
    /// Use it for the apps that name no identity provider
    #[clap(long)]
    default: bool,
}

#[derive(Parser)]
/// Adds a Rancher, or updates the one with the same url
struct ConfigRancher {
    #[clap(required = true, long)]
    url: String,
    #[clap(required = true, long)]
    client_id: String,
    /// The identity provider to log in with, defaults to the default one
    #[clap(long)]
    idp: Option<String>,
    /// Overrides the username of the identity provider
    #[clap(short, long)]
    username: Option<String>,
    /// Overrides the MFA selection of the identity provider
    #[clap(short, long)]
    mfa: Option<MfaSelection>,
}

#[derive(Parser)]
struct ConfigAws {
    #[clap(subcommand)]
    sub_command: ConfigAwsSubCommand,
}

#[derive(Parser)]
enum ConfigAwsSubCommand {
    App(ConfigAwsApp),
    Sso(ConfigAwsSso),
}

#[derive(Parser)]
struct ConfigAwsApp {
    #[clap(required = true, long)]
    app_url: String,
    /// The identity provider to log in with, defaults to the default one
    #[clap(long)]
    idp: Option<String>,
    /// Overrides the username of the identity provider
    #[clap(short, long)]
    username: Option<String>,
    /// Overrides the MFA selection of the identity provider
    #[clap(short, long)]
    mfa: Option<MfaSelection>,
}

#[derive(Parser)]
struct ConfigAwsSso {
    #[clap(required = true, long)]
    app_url: String,
    /// The identity provider to log in with, defaults to the default one
    #[clap(long)]
    idp: Option<String>,
    /// Overrides the username of the identity provider
    #[clap(short, long)]
    username: Option<String>,
    #[clap(required = true, short, long)]
    region: String,
    /// Overrides the MFA selection of the identity provider
    #[clap(short, long)]
    mfa: Option<MfaSelection>,
}

#[derive(Parser)]
struct ConfigGlobal {
    #[clap(subcommand)]
    sub_command: ConfigGlobalSubCommand,
}

#[derive(Parser)]
enum ConfigGlobalSubCommand {
    UseKeyring(ConfigGlobalUseKeyRing),
    DefaultIdp(ConfigGlobalDefaultIdp),
    Yubikey(ConfigGlobalYubikey),
}

#[derive(Parser)]
/// Configure YubiKey secret wrapping for credentials stored in the keyring.
struct ConfigGlobalYubikey {
    #[clap(subcommand)]
    sub_command: ConfigGlobalYubikeySubCommand,
}

#[derive(Parser)]
enum ConfigGlobalYubikeySubCommand {
    /// Enroll a YubiKey for hardware-backed secret wrapping
    Enroll(ConfigGlobalYubikeyEnroll),
    /// Disable YubiKey secret wrapping
    Disable(ConfigGlobalYubikeyDisable),
    /// Show current YubiKey enrollment and wrapping status
    Status(ConfigGlobalYubikeyStatus),
    /// Configure whether generated session secrets (AWS & Rancher tokens) are wrapped
    WrapCached(ConfigGlobalYubikeyWrapCached),
}

#[derive(Parser)]
struct ConfigGlobalYubikeyEnroll {
    /// Relying party ID for WebAuthn/FIDO2 enrollment (defaults to "localhost")
    #[clap(long, default_value = "localhost")]
    rp_id: String,
}

#[derive(Parser)]
struct ConfigGlobalYubikeyDisable {}

#[derive(Parser)]
struct ConfigGlobalYubikeyStatus {}

#[derive(Parser)]
struct ConfigGlobalYubikeyWrapCached {
    /// Accepted values: "true" or "false"
    #[clap(long, action = clap::ArgAction::Set, value_parser = true_or_false)]
    enabled: bool,
}

#[derive(Parser)]
/// The identity provider for the apps that name none
struct ConfigGlobalDefaultIdp {
    #[clap(required = true, long)]
    name: String,
}

#[derive(Parser)]
/// Whether c9s should use a keyring service.
struct ConfigGlobalUseKeyRing {
    /// Accepted values: "true" or "false"
    #[clap(long, action = clap::ArgAction::Set, value_parser = true_or_false)]
    enabled: bool,
}

impl Config {
    pub async fn run(
        &self,
        settings: &mut AppConfig,
        interaction: Arc<impl UserInteraction + 'static>,
        notifier: Arc<impl Notifier + 'static>,
    ) -> Result<()> {
        match &self.sub_command {
            ConfigSubCommand::Idp(val) => val.run(settings),
            ConfigSubCommand::Aws(val) => match &val.sub_command {
                ConfigAwsSubCommand::App(val) => val.run(settings),
                ConfigAwsSubCommand::Sso(val) => val.run(settings),
            },
            ConfigSubCommand::Rancher(val) => val.run(settings),
            ConfigSubCommand::Global(val) => match &val.sub_command {
                ConfigGlobalSubCommand::UseKeyring(val) => val.run(settings),
                ConfigGlobalSubCommand::DefaultIdp(val) => val.run(settings),
                ConfigGlobalSubCommand::Yubikey(val) => {
                    val.run(settings, interaction, notifier).await
                }
            },
        }
    }
}

/// The username has to come from the app or from the identity provider it resolves to.
fn check_identity(
    settings: &AppConfig,
    idp: Option<&str>,
    username: &Option<String>,
) -> Result<()> {
    if username.is_none() && settings.resolve_idp(idp)?.is_none() {
        return Err(anyhow!(
            "please supply a username, or an identity provider with `--idp` (see `c9s config idp`)"
        ));
    }

    Ok(())
}

impl ConfigIdp {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        let idp = Idp::new(
            self.name.clone(),
            self.r#type.into(),
            self.url.clone(),
            self.username.clone(),
            self.mfa,
        )?;
        settings.add_idp(idp);
        if self.default {
            settings.set_default_idp(&self.name)?;
        }

        Ok(())
    }
}

impl ConfigAwsApp {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        check_identity(settings, self.idp.as_deref(), &self.username)?;
        let host = AwsHost::new(
            self.app_url.clone(),
            self.username.clone(),
            self.idp.clone(),
            self.mfa,
        )?;
        settings.add_aws_host(host);

        Ok(())
    }
}

impl ConfigAwsSso {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        check_identity(settings, self.idp.as_deref(), &self.username)?;
        let host = AwsSsoHost::new(
            self.app_url.clone(),
            self.username.clone(),
            self.idp.clone(),
            self.region.clone(),
            self.mfa,
        )?;
        settings.add_aws_sso_host(host);

        Ok(())
    }
}

impl ConfigRancher {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        if settings.resolve_idp(self.idp.as_deref())?.is_none() {
            return Err(anyhow!(
                "rancher needs an identity provider, run `c9s config idp`"
            ));
        }
        let host = RancherHost::new(
            self.url.clone(),
            self.client_id.clone(),
            self.idp.clone(),
            self.username.clone(),
            self.mfa,
        )?;
        settings.add_rancher_host(host);

        Ok(())
    }
}

impl ConfigGlobalDefaultIdp {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        settings.set_default_idp(&self.name)?;

        Ok(())
    }
}

impl ConfigGlobalUseKeyRing {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        settings.set_use_keyring(self.enabled);

        Ok(())
    }
}

impl ConfigGlobalYubikey {
    async fn run(
        &self,
        settings: &mut AppConfig,
        interaction: Arc<impl UserInteraction + 'static>,
        notifier: Arc<impl Notifier + 'static>,
    ) -> Result<()> {
        match &self.sub_command {
            ConfigGlobalYubikeySubCommand::Enroll(val) => {
                val.run(settings, interaction, notifier).await
            }
            ConfigGlobalYubikeySubCommand::Disable(val) => val.run(settings),
            ConfigGlobalYubikeySubCommand::Status(val) => val.run(settings),
            ConfigGlobalYubikeySubCommand::WrapCached(val) => val.run(settings),
        }
    }
}

impl ConfigGlobalYubikeyEnroll {
    async fn run(
        &self,
        settings: &mut AppConfig,
        interaction: Arc<impl UserInteraction + 'static>,
        notifier: Arc<impl Notifier + 'static>,
    ) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            let _ = (settings, interaction, notifier);
            Err(anyhow!("YubiKey wrapping is not supported on Windows"))
        }

        #[cfg(not(target_os = "windows"))]
        {
            let config = c9s::outbound::yubikey::enroll(&self.rp_id, interaction, notifier).await?;
            settings.set_yubikey(Some(config));
            println!("YubiKey successfully enrolled for secret wrapping.");
            Ok(())
        }
    }
}

impl ConfigGlobalYubikeyDisable {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        settings.set_yubikey(None);
        println!("YubiKey secret wrapping disabled.");
        Ok(())
    }
}

impl ConfigGlobalYubikeyStatus {
    fn run(&self, settings: &AppConfig) -> Result<()> {
        match settings.yubikey_config() {
            Some(yk) => {
                println!("YubiKey status: Enrolled");
                println!("Relying Party: {}", yk.rp_id());
                println!(
                    "Wrap cached secrets (AWS/Rancher): {}",
                    if settings.wrap_cached_secrets_enabled() {
                        "enabled"
                    } else {
                        "disabled (stored in plain keyring)"
                    }
                );
            }
            None => {
                println!("YubiKey status: Not enrolled (disabled)");
            }
        }
        Ok(())
    }
}

impl ConfigGlobalYubikeyWrapCached {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        settings.set_wrap_cached_secrets(self.enabled);
        println!(
            "Protection for cached secrets (AWS/Rancher) is now {}.",
            if self.enabled { "enabled" } else { "disabled" }
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use c9s::domain::models::idp::IdpType;

    const APP_URL: &str = "https://id.example.com/application/saml/aws/sso/binding/init/";

    fn parse(args: &[&str]) -> Result<Config, clap::Error> {
        let mut argv = vec!["config"];
        argv.extend(args);

        Config::try_parse_from(argv)
    }

    #[test]
    fn parses_the_aws_app_subcommand() {
        let config = parse(&[
            "aws",
            "app",
            "--app-url",
            APP_URL,
            "--idp",
            "suse",
            "--mfa",
            "totp",
        ])
        .unwrap();

        let ConfigSubCommand::Aws(aws) = config.sub_command else {
            panic!("expected the aws subcommand");
        };
        let ConfigAwsSubCommand::App(host) = aws.sub_command else {
            panic!("expected app");
        };
        assert_eq!(host.app_url, APP_URL);
        assert_eq!(host.idp.as_deref(), Some("suse"));
        assert!(host.username.is_none());
        assert_eq!(host.mfa, Some(MfaSelection::Totp));
    }

    #[test]
    fn parses_the_aws_sso_subcommand() {
        let config =
            parse(&["aws", "sso", "--app-url", APP_URL, "-u", "user", "-r", "eu"]).unwrap();

        let ConfigSubCommand::Aws(aws) = config.sub_command else {
            panic!("expected the aws subcommand");
        };
        let ConfigAwsSubCommand::Sso(host) = aws.sub_command else {
            panic!("expected sso");
        };
        assert_eq!(host.region, "eu");
        assert_eq!(host.username.as_deref(), Some("user"));
    }

    #[test]
    fn parses_the_idp_subcommand() {
        let config = parse(&[
            "idp",
            "--name",
            "suse",
            "--url",
            "https://id.example.com",
            "-u",
            "user",
            "--default",
        ])
        .unwrap();

        let ConfigSubCommand::Idp(idp) = config.sub_command else {
            panic!("expected the idp subcommand");
        };
        assert_eq!(idp.name, "suse");
        assert_eq!(IdpType::from(idp.r#type), IdpType::Authentik);
        assert!(idp.default);
        assert!(idp.mfa.is_none());

        assert!(parse(&["idp", "--name", "x", "--url", "u"]).is_err());
        assert!(
            parse(&["idp", "--name", "x", "--url", "u", "-u", "u", "--type", "keycloak"]).is_err()
        );
    }

    #[test]
    fn parses_the_default_idp_subcommand() {
        let config = parse(&["global", "default-idp", "--name", "suse"]).unwrap();

        let ConfigSubCommand::Global(global) = config.sub_command else {
            panic!("expected the global subcommand");
        };
        let ConfigGlobalSubCommand::DefaultIdp(default) = global.sub_command else {
            panic!("expected default-idp");
        };
        assert_eq!(default.name, "suse");
        assert!(parse(&["global", "default-idp"]).is_err());
    }

    #[test]
    fn parses_the_rancher_subcommand() {
        let config = parse(&[
            "rancher",
            "--url",
            "https://rancher.example.com",
            "--client-id",
            "rancher",
        ])
        .unwrap();

        let ConfigSubCommand::Rancher(rancher) = config.sub_command else {
            panic!("expected the rancher subcommand");
        };
        assert_eq!(rancher.client_id, "rancher");
        assert!(rancher.idp.is_none());
        assert!(rancher.username.is_none());
        assert!(rancher.mfa.is_none());

        assert!(parse(&[
            "rancher",
            "--url",
            "u",
            "--client-id",
            "c",
            "--idp",
            "suse",
            "-u",
            "x",
            "-m",
            "totp"
        ])
        .is_ok());
    }

    #[test]
    fn rancher_no_longer_takes_an_issuer() {
        assert!(parse(&[
            "rancher",
            "--url",
            "https://r.example.com",
            "--client-id",
            "c",
            "--issuer",
            "https://id.example.com/",
        ])
        .is_err());
        assert!(parse(&["rancher", "--url", "https://r.example.com"]).is_err());
    }

    #[test]
    fn an_unknown_mfa_is_rejected_while_parsing() {
        assert!(parse(&["rancher", "--url", "u", "--client-id", "c", "-m", "sms"]).is_err());
        assert!(parse(&["rancher", "--url", "u", "--client-id", "c", "-m", "TOTP"]).is_ok());
    }

    #[test]
    fn parses_the_yubikey_enroll_subcommand() {
        let config = parse(&["global", "yubikey", "enroll", "--rp-id", "c9s.dev"]).unwrap();
        let ConfigSubCommand::Global(global) = config.sub_command else {
            panic!("expected global");
        };
        let ConfigGlobalSubCommand::Yubikey(yk) = global.sub_command else {
            panic!("expected yubikey");
        };
        let ConfigGlobalYubikeySubCommand::Enroll(enroll) = yk.sub_command else {
            panic!("expected enroll");
        };
        assert_eq!(enroll.rp_id, "c9s.dev");
    }

    #[test]
    fn parses_the_yubikey_disable_and_status_subcommands() {
        let config = parse(&["global", "yubikey", "disable"]).unwrap();
        let ConfigSubCommand::Global(global) = config.sub_command else {
            panic!("expected global");
        };
        let ConfigGlobalSubCommand::Yubikey(yk) = global.sub_command else {
            panic!("expected yubikey");
        };
        assert!(matches!(
            yk.sub_command,
            ConfigGlobalYubikeySubCommand::Disable(_)
        ));

        let config = parse(&["global", "yubikey", "status"]).unwrap();
        let ConfigSubCommand::Global(global) = config.sub_command else {
            panic!("expected global");
        };
        let ConfigGlobalSubCommand::Yubikey(yk) = global.sub_command else {
            panic!("expected yubikey");
        };
        assert!(matches!(
            yk.sub_command,
            ConfigGlobalYubikeySubCommand::Status(_)
        ));
    }

    #[test]
    fn parses_the_yubikey_wrap_cached_subcommand() {
        let config = parse(&["global", "yubikey", "wrap-cached", "--enabled", "true"]).unwrap();
        let ConfigSubCommand::Global(global) = config.sub_command else {
            panic!("expected global");
        };
        let ConfigGlobalSubCommand::Yubikey(yk) = global.sub_command else {
            panic!("expected yubikey");
        };
        let ConfigGlobalYubikeySubCommand::WrapCached(wrap) = yk.sub_command else {
            panic!("expected wrap-cached");
        };
        assert!(wrap.enabled);
    }
}
