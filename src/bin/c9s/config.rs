use crate::app::CliApplication;
use crate::args::IdpTypeArg;
use crate::utils::true_or_false;
use anyhow::{Context, Result};
use c9s::app::settings::{export_text, import_text, usernames_needed};
use c9s::domain::models::mfa::MfaSelection;
use c9s::domain::services::settings_editor::{
    AwsAppInput, AwsAppKind, IdpInput, ImportMode, ImportReport, RancherInput, SaveAs,
};
use c9s::outbound::config::bundle::TomlBundleCodec;
use clap::Parser;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;
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
    Export(ConfigExport),
    Import(ConfigImport),
}

#[derive(Parser)]
/// Writes an onboarding file.
struct ConfigExport {
    /// The identity provider to export.
    #[clap(long = "idp", required_unless_present = "all", conflicts_with = "all")]
    idps: Vec<String>,
    /// Exports every identity provider
    #[clap(long)]
    all: bool,
    /// The file to write, the standard output when not given
    #[clap(short, long)]
    output: Option<PathBuf>,
}

#[derive(Parser)]
/// Imports an onboarding file.
struct ConfigImport {
    /// The onboarding file to read, `-` for the standard input
    file: PathBuf,
    /// Updates entries that are set up already, instead of keeping them
    #[clap(long)]
    overwrite: bool,
    /// Your username at the new identity providers (an onboarding file holds none).
    /// `--username me` for all of them or `--username corp=me` for one, repeat for more
    #[clap(short, long = "username")]
    usernames: Vec<String>,
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
}

#[derive(Parser)]
/// Adds a Rancher, or updates the one with the same url
struct ConfigRancher {
    #[clap(required = true, long)]
    url: String,
    #[clap(required = true, long)]
    client_id: String,
    /// The identity provider to log in with (see `c9s config idp`)
    #[clap(required = true, long)]
    idp: String,
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
    /// The identity provider to log in with (see `c9s config idp`)
    #[clap(required = true, long)]
    idp: String,
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
    /// The identity provider to log in with (see `c9s config idp`)
    #[clap(required = true, long)]
    idp: String,
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
    /// Configure whether issued credentials are wrapped.
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
/// Whether c9s should use a keyring service.
struct ConfigGlobalUseKeyRing {
    /// Accepted values: "true" or "false"
    #[clap(long, action = clap::ArgAction::Set, value_parser = true_or_false)]
    enabled: bool,
}

impl Config {
    pub async fn run(&self, application: &CliApplication) -> Result<()> {
        match &self.sub_command {
            ConfigSubCommand::Idp(val) => val.run(application),
            ConfigSubCommand::Aws(val) => match &val.sub_command {
                ConfigAwsSubCommand::App(val) => val.run(application),
                ConfigAwsSubCommand::Sso(val) => val.run(application),
            },
            ConfigSubCommand::Rancher(val) => val.run(application),
            ConfigSubCommand::Export(val) => val.run(application),
            ConfigSubCommand::Import(val) => val.run(application),
            ConfigSubCommand::Global(val) => match &val.sub_command {
                ConfigGlobalSubCommand::UseKeyring(val) => val.run(application),
                ConfigGlobalSubCommand::Yubikey(val) => val.run(application).await,
            },
        }
    }
}

impl ConfigExport {
    fn run(&self, application: &CliApplication) -> Result<()> {
        let names = if self.all {
            application
                .settings_service()
                .load()?
                .idps()
                .iter()
                .map(|idp| idp.name().to_string())
                .collect()
        } else {
            self.idps.clone()
        };

        let text = export_text(application.settings_service(), &TomlBundleCodec, &names)?;

        match &self.output {
            Some(path) => std::fs::write(path, text)
                .with_context(|| format!("could not write {}", path.display()))?,
            None => print!("{text}"),
        }

        Ok(())
    }
}

impl ConfigImport {
    fn run(&self, application: &CliApplication) -> Result<()> {
        let text = if self.file.as_os_str() == "-" {
            let mut text = String::new();
            std::io::stdin().read_to_string(&mut text)?;
            text
        } else {
            std::fs::read_to_string(&self.file)
                .with_context(|| format!("could not read {}", self.file.display()))?
        };

        let mode = if self.overwrite {
            ImportMode::Overwrite
        } else {
            ImportMode::SkipExisting
        };

        let usernames = self.usernames(&usernames_needed(
            application.settings_service(),
            &TomlBundleCodec,
            &text,
        )?);
        let report = import_text(
            application.settings_service(),
            &TomlBundleCodec,
            &text,
            mode,
            &usernames,
        )?;
        println!("{}", describe(&report));

        Ok(())
    }
}

impl ConfigImport {
    /// The username for each of the `needed` identity providers.
    /// The one named for it or the generic one for all.
    fn usernames(&self, needed: &[String]) -> BTreeMap<String, String> {
        let mut named = BTreeMap::new();
        let mut for_all = None;

        for given in &self.usernames {
            match given.split_once('=') {
                Some((idp, username)) => {
                    named.insert(idp.to_string(), username.to_string());
                }
                None => for_all = Some(given.clone()),
            }
        }

        needed
            .iter()
            .filter_map(|idp| {
                let username = named.get(idp).cloned().or_else(|| for_all.clone())?;
                Some((idp.clone(), username))
            })
            .collect()
    }
}

fn describe(report: &ImportReport) -> String {
    format!(
        "Added {}, updated {}, kept {} that were set up already.",
        report.added(),
        report.overwritten(),
        report.skipped()
    )
}

impl ConfigIdp {
    fn run(&self, application: &CliApplication) -> Result<()> {
        let mut input = IdpInput::new(
            self.name.clone(),
            self.r#type.into(),
            self.url.clone(),
            self.username.clone(),
        );
        input.mfa = self.mfa;
        application
            .settings_service()
            .save_idp(input, SaveAs::Upsert)?;

        Ok(())
    }
}

impl ConfigAwsApp {
    fn run(&self, application: &CliApplication) -> Result<()> {
        let mut input = AwsAppInput::new(self.app_url.clone(), self.idp.clone());
        input.username = self.username.clone();
        input.mfa = self.mfa;
        application
            .settings_service()
            .save_aws_app(input, AwsAppKind::Aws, SaveAs::Upsert)?;

        Ok(())
    }
}

impl ConfigAwsSso {
    fn run(&self, application: &CliApplication) -> Result<()> {
        let mut input = AwsAppInput::new(self.app_url.clone(), self.idp.clone());
        input.username = self.username.clone();
        input.mfa = self.mfa;
        let kind = AwsAppKind::AwsSso {
            region: self.region.clone(),
        };
        application
            .settings_service()
            .save_aws_app(input, kind, SaveAs::Upsert)?;

        Ok(())
    }
}

impl ConfigRancher {
    fn run(&self, application: &CliApplication) -> Result<()> {
        let mut input =
            RancherInput::new(self.url.clone(), self.client_id.clone(), self.idp.clone());
        input.username = self.username.clone();
        input.mfa = self.mfa;
        application
            .settings_service()
            .save_rancher(input, SaveAs::Upsert)?;

        Ok(())
    }
}

impl ConfigGlobalUseKeyRing {
    fn run(&self, application: &CliApplication) -> Result<()> {
        application
            .settings_service()
            .set_use_keyring(self.enabled)?;

        Ok(())
    }
}

impl ConfigGlobalYubikey {
    async fn run(&self, application: &CliApplication) -> Result<()> {
        match &self.sub_command {
            ConfigGlobalYubikeySubCommand::Enroll(val) => val.run(application).await,
            ConfigGlobalYubikeySubCommand::Disable(val) => val.run(application),
            ConfigGlobalYubikeySubCommand::Status(val) => val.run(application),
            ConfigGlobalYubikeySubCommand::WrapCached(val) => val.run(application),
        }
    }
}

impl ConfigGlobalYubikeyEnroll {
    async fn run(&self, application: &CliApplication) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            let _ = application;
            Err(anyhow::anyhow!(
                "YubiKey wrapping is not supported on Windows"
            ))
        }

        #[cfg(not(target_os = "windows"))]
        {
            let config = c9s::outbound::yubikey::enroll(
                &self.rp_id,
                Arc::new(application.interaction()),
                Arc::new(application.notifier()),
            )
            .await?;
            application.settings_service().set_yubikey(Some(config))?;
            println!("YubiKey successfully enrolled for secret wrapping.");
            Ok(())
        }
    }
}

impl ConfigGlobalYubikeyDisable {
    fn run(&self, application: &CliApplication) -> Result<()> {
        application.settings_service().set_yubikey(None)?;
        println!("YubiKey secret wrapping disabled.");
        Ok(())
    }
}

impl ConfigGlobalYubikeyStatus {
    fn run(&self, application: &CliApplication) -> Result<()> {
        let settings = application.settings_service().load()?;
        match settings.yubikey_config() {
            Some(yk) => {
                println!("YubiKey status: Enrolled");
                println!("Relying Party: {}", yk.rp_id());
                println!("IdP session cache: enabled (encrypted)");
                println!(
                    "Wrap issued credentials (AWS/Rancher): {}",
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
    fn run(&self, application: &CliApplication) -> Result<()> {
        application
            .settings_service()
            .set_wrap_cached_secrets(self.enabled)?;
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
    use c9s::domain::models::secret::SafeSecret;
    use c9s::domain::models::user_interaction::{
        ChoicePrompt, ConfirmPrompt, SecretPrompt, UserNotice,
    };
    use c9s::domain::ports::notifier::{Notifier, NotifyError};
    use c9s::domain::ports::user_interaction::{InteractionError, UserInteraction};
    use c9s::domain::services::settings_editor::SettingsService;

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
        assert_eq!(host.idp, "suse");
        assert!(host.username.is_none());
        assert_eq!(host.mfa, Some(MfaSelection::Totp));
    }

    #[test]
    fn parses_the_aws_sso_subcommand() {
        let config = parse(&[
            "aws",
            "sso",
            "--app-url",
            APP_URL,
            "--idp",
            "suse",
            "-u",
            "user",
            "-r",
            "eu",
        ])
        .unwrap();

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
        ])
        .unwrap();

        let ConfigSubCommand::Idp(idp) = config.sub_command else {
            panic!("expected the idp subcommand");
        };
        assert_eq!(idp.name, "suse");
        assert_eq!(IdpType::from(idp.r#type), IdpType::Authentik);
        assert!(idp.mfa.is_none());

        assert!(parse(&["idp", "--name", "x", "--url", "u"]).is_err());
        assert!(
            parse(&["idp", "--name", "x", "--url", "u", "-u", "u", "--type", "keycloak"]).is_err()
        );
    }

    #[test]
    fn an_app_needs_an_idp() {
        assert!(parse(&["aws", "app", "--app-url", APP_URL]).is_err());
        assert!(parse(&["aws", "sso", "--app-url", APP_URL, "-r", "eu"]).is_err());
        assert!(parse(&["rancher", "--url", "u", "--client-id", "c"]).is_err());
    }

    #[test]
    fn parses_the_rancher_subcommand() {
        let config = parse(&[
            "rancher",
            "--url",
            "https://rancher.example.com",
            "--client-id",
            "rancher",
            "--idp",
            "suse",
        ])
        .unwrap();

        let ConfigSubCommand::Rancher(rancher) = config.sub_command else {
            panic!("expected the rancher subcommand");
        };
        assert_eq!(rancher.client_id, "rancher");
        assert_eq!(rancher.idp, "suse");
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
            "--idp",
            "suse",
            "--issuer",
            "https://id.example.com/",
        ])
        .is_err());
        assert!(parse(&["rancher", "--url", "https://r.example.com"]).is_err());
    }

    #[test]
    fn an_unknown_mfa_is_rejected_while_parsing() {
        assert!(parse(&[
            "rancher",
            "--url",
            "u",
            "--client-id",
            "c",
            "--idp",
            "s",
            "-m",
            "sms"
        ])
        .is_err());
        assert!(parse(&[
            "rancher",
            "--url",
            "u",
            "--client-id",
            "c",
            "--idp",
            "s",
            "-m",
            "TOTP"
        ])
        .is_ok());
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

    struct NoInteraction;

    #[async_trait::async_trait(?Send)]
    impl UserInteraction for NoInteraction {
        async fn ask_secret(&self, _: SecretPrompt) -> Result<SafeSecret, InteractionError> {
            Err(InteractionError::Unavailable)
        }
        async fn confirm(&self, _: ConfirmPrompt) -> Result<bool, InteractionError> {
            Err(InteractionError::Unavailable)
        }
        async fn choose(&self, _: &ChoicePrompt) -> Result<usize, InteractionError> {
            Err(InteractionError::Unavailable)
        }
    }

    struct NoNotifier;

    #[async_trait::async_trait(?Send)]
    impl Notifier for NoNotifier {
        async fn notify(&self, _: &UserNotice) -> Result<(), NotifyError> {
            Err(NotifyError::Unavailable)
        }
    }

    fn test_application(settings: SettingsService) -> CliApplication {
        CliApplication::new(
            Default::default(),
            settings,
            Arc::new(NoInteraction),
            Arc::new(NoNotifier),
        )
    }

    #[test]
    fn a_read_only_command_never_writes_the_settings() {
        use c9s::outbound::config::config_store::ConfigFileAdapter;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c9s").join("settings.toml");
        let service = SettingsService::new(Arc::new(ConfigFileAdapter::at(path.clone())));
        let service = test_application(service);

        ConfigGlobalYubikeyStatus {}.run(&service).unwrap();
        assert!(!path.exists());

        // A command that changes something does write.
        ConfigGlobalUseKeyRing { enabled: false }
            .run(&service)
            .unwrap();
        assert!(path.exists());
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        ConfigGlobalYubikeyStatus {}.run(&service).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            modified
        );
    }
}
