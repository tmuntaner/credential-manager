//! The settings as they are written in the settings file. The format is kept apart from the domain model, so
//! a change of one does not break the other.

use crate::domain::models::idp::IdpType;
use crate::domain::models::mfa::{MfaSelection, MfaSelectionError};
use crate::domain::models::prompt_mode::PromptMode;
use crate::domain::models::settings::{
    AppConfig, AwsHost, AwsSsoHost, GlobalSettings, Idp, RancherHost, SettingsError, YubikeyConfig,
};
use crate::domain::ports::config::ConfigError;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Default)]
pub(super) struct FileConfig {
    global_settings: Option<FileGlobalSettings>,
    idps: Option<Vec<FileIdp>>,
    aws_hosts: Option<Vec<FileAwsHost>>,
    aws_sso_hosts: Option<Vec<FileAwsSsoHost>>,
    rancher_hosts: Option<Vec<FileRancherHost>>,
}

#[derive(Serialize, Deserialize, Default)]
struct FileGlobalSettings {
    use_keyring: Option<bool>,
    default_idp: Option<String>,
    yubikey: Option<FileYubikey>,
    wrap_cached_secrets: Option<bool>,
    prompt: Option<FilePromptMode>,
    pinentry: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
struct FileYubikey {
    credential_id: String,
    rp_id: String,
    salt: String,
}

#[derive(Serialize, Deserialize)]
struct FileIdp {
    name: String,
    #[serde(rename = "type", default)]
    idp_type: FileIdpType,
    url: String,
    username: String,
    mfa: Option<FileMfa>,
}

#[derive(Serialize, Deserialize)]
struct FileAwsHost {
    app_url: String,
    username: Option<String>,
    idp: Option<String>,
    mfa: Option<FileMfa>,
}

#[derive(Serialize, Deserialize)]
struct FileAwsSsoHost {
    app_url: String,
    username: Option<String>,
    idp: Option<String>,
    region: String,
    mfa: Option<FileMfa>,
}

#[derive(Serialize, Deserialize)]
struct FileRancherHost {
    url: String,
    client_id: String,
    idp: Option<String>,
    username: Option<String>,
    mfa: Option<FileMfa>,
}

#[derive(Serialize, Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
enum FileIdpType {
    #[default]
    Authentik,
}

#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum FilePromptMode {
    Auto,
    Gui,
    Terminal,
}

/// Read case-insensitively, written in lowercase.
#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(try_from = "String", into = "String")]
struct FileMfa(MfaSelection);

impl TryFrom<String> for FileMfa {
    type Error = MfaSelectionError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse().map(Self)
    }
}

impl From<FileMfa> for String {
    fn from(mfa: FileMfa) -> Self {
        mfa.0.to_string()
    }
}

impl From<&AppConfig> for FileConfig {
    fn from(config: &AppConfig) -> Self {
        Self {
            global_settings: Some(config.global_settings().into()),
            idps: some_if_any(config.idps().iter().map(Into::into).collect()),
            aws_hosts: some_if_any(config.aws_hosts().iter().map(Into::into).collect()),
            aws_sso_hosts: some_if_any(config.aws_sso_hosts().iter().map(Into::into).collect()),
            rancher_hosts: some_if_any(config.rancher_hosts().iter().map(Into::into).collect()),
        }
    }
}

fn some_if_any<T>(items: Vec<T>) -> Option<Vec<T>> {
    (!items.is_empty()).then_some(items)
}

impl From<&GlobalSettings> for FileGlobalSettings {
    fn from(settings: &GlobalSettings) -> Self {
        Self {
            use_keyring: settings.use_keyring,
            default_idp: settings.default_idp.clone(),
            yubikey: settings.yubikey.as_ref().map(Into::into),
            wrap_cached_secrets: settings.wrap_cached_secrets,
            prompt: settings.prompt.map(Into::into),
            pinentry: settings.pinentry.clone(),
        }
    }
}

impl From<&YubikeyConfig> for FileYubikey {
    fn from(config: &YubikeyConfig) -> Self {
        Self {
            credential_id: STANDARD.encode(config.credential_id()),
            rp_id: config.rp_id().to_string(),
            salt: STANDARD.encode(config.salt()),
        }
    }
}

impl From<&Idp> for FileIdp {
    fn from(idp: &Idp) -> Self {
        Self {
            name: idp.name().to_string(),
            idp_type: idp.idp_type().into(),
            url: idp.url().to_string(),
            username: idp.username().to_string(),
            mfa: idp.mfa().map(FileMfa),
        }
    }
}

impl From<&AwsHost> for FileAwsHost {
    fn from(host: &AwsHost) -> Self {
        Self {
            app_url: host.app_url().to_string(),
            username: host.username().map(str::to_string),
            idp: host.idp().map(str::to_string),
            mfa: host.mfa().map(FileMfa),
        }
    }
}

impl From<&AwsSsoHost> for FileAwsSsoHost {
    fn from(host: &AwsSsoHost) -> Self {
        Self {
            app_url: host.app_url().to_string(),
            username: host.username().map(str::to_string),
            idp: host.idp().map(str::to_string),
            region: host.region().to_string(),
            mfa: host.mfa().map(FileMfa),
        }
    }
}

impl From<&RancherHost> for FileRancherHost {
    fn from(host: &RancherHost) -> Self {
        Self {
            url: host.url().to_string(),
            client_id: host.client_id().to_string(),
            idp: host.idp().map(str::to_string),
            username: host.username().map(str::to_string),
            mfa: host.mfa().map(FileMfa),
        }
    }
}

impl From<IdpType> for FileIdpType {
    fn from(idp_type: IdpType) -> Self {
        match idp_type {
            IdpType::Authentik => Self::Authentik,
        }
    }
}

impl From<FileIdpType> for IdpType {
    fn from(idp_type: FileIdpType) -> Self {
        match idp_type {
            FileIdpType::Authentik => Self::Authentik,
        }
    }
}

impl From<PromptMode> for FilePromptMode {
    fn from(mode: PromptMode) -> Self {
        match mode {
            PromptMode::Auto => Self::Auto,
            PromptMode::Gui => Self::Gui,
            PromptMode::Terminal => Self::Terminal,
        }
    }
}

impl From<FilePromptMode> for PromptMode {
    fn from(mode: FilePromptMode) -> Self {
        match mode {
            FilePromptMode::Auto => Self::Auto,
            FilePromptMode::Gui => Self::Gui,
            FilePromptMode::Terminal => Self::Terminal,
        }
    }
}

impl TryFrom<FileConfig> for AppConfig {
    type Error = ConfigError;

    fn try_from(file: FileConfig) -> Result<Self, Self::Error> {
        let mut config = AppConfig::default();

        if let Some(global_settings) = file.global_settings {
            config.set_global_settings(global_settings.try_into()?);
        }
        for idp in file.idps.into_iter().flatten() {
            config.add_idp(idp.try_into()?);
        }
        for host in file.aws_hosts.into_iter().flatten() {
            config.add_aws_host(host.try_into()?);
        }
        for host in file.aws_sso_hosts.into_iter().flatten() {
            config.add_aws_sso_host(host.try_into()?);
        }
        for host in file.rancher_hosts.into_iter().flatten() {
            config.add_rancher_host(host.try_into()?);
        }

        Ok(config)
    }
}

impl TryFrom<FileGlobalSettings> for GlobalSettings {
    type Error = ConfigError;

    fn try_from(file: FileGlobalSettings) -> Result<Self, Self::Error> {
        Ok(Self {
            use_keyring: file.use_keyring,
            default_idp: file.default_idp,
            yubikey: file.yubikey.map(YubikeyConfig::try_from).transpose()?,
            wrap_cached_secrets: file.wrap_cached_secrets,
            prompt: file.prompt.map(Into::into),
            pinentry: file.pinentry,
        })
    }
}

impl TryFrom<FileYubikey> for YubikeyConfig {
    type Error = ConfigError;

    fn try_from(file: FileYubikey) -> Result<Self, Self::Error> {
        let failed = |e: base64::DecodeError| ConfigError::Failed(Box::new(e));
        let credential_id = STANDARD.decode(file.credential_id).map_err(failed)?;
        let salt: [u8; 32] = STANDARD
            .decode(file.salt)
            .map_err(failed)?
            .try_into()
            .map_err(|_| ConfigError::Failed("the yubikey salt must be exactly 32 bytes".into()))?;

        Ok(YubikeyConfig::new(&credential_id, file.rp_id, &salt))
    }
}

impl TryFrom<FileIdp> for Idp {
    type Error = ConfigError;

    fn try_from(file: FileIdp) -> Result<Self, Self::Error> {
        Ok(Idp::new(
            file.name,
            file.idp_type.into(),
            file.url,
            file.username,
            file.mfa.map(|m| m.0),
        )?)
    }
}

impl TryFrom<FileAwsHost> for AwsHost {
    type Error = SettingsError;

    fn try_from(file: FileAwsHost) -> Result<Self, Self::Error> {
        AwsHost::new(file.app_url, file.username, file.idp, file.mfa.map(|m| m.0))
    }
}

impl TryFrom<FileAwsSsoHost> for AwsSsoHost {
    type Error = SettingsError;

    fn try_from(file: FileAwsSsoHost) -> Result<Self, Self::Error> {
        AwsSsoHost::new(
            file.app_url,
            file.username,
            file.idp,
            file.region,
            file.mfa.map(|m| m.0),
        )
    }
}

impl TryFrom<FileRancherHost> for RancherHost {
    type Error = SettingsError;

    fn try_from(file: FileRancherHost) -> Result<Self, Self::Error> {
        RancherHost::new(
            file.url,
            file.client_id,
            file.idp,
            file.username,
            file.mfa.map(|m| m.0),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INIT_URL: &str = "https://id.example.com/application/saml/aws/sso/binding/init/";

    fn load(toml: &str) -> AppConfig {
        toml::from_str::<FileConfig>(toml)
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn save(config: &AppConfig) -> String {
        toml::to_string(&FileConfig::from(config)).unwrap()
    }

    #[test]
    fn hosts_round_trip() {
        let mut settings = AppConfig::default();
        settings.add_aws_host(
            AwsHost::new(
                INIT_URL.to_string(),
                Some("user@example.com".to_string()),
                None,
                Some(MfaSelection::Totp),
            )
            .unwrap(),
        );
        settings.add_aws_sso_host(
            AwsSsoHost::new(
                INIT_URL.to_string(),
                None,
                None,
                "eu-central-1".to_string(),
                None,
            )
            .unwrap(),
        );

        let toml = save(&settings);
        assert!(toml.contains("[[aws_hosts]]"), "{toml}");
        assert!(toml.contains("[[aws_sso_hosts]]"), "{toml}");

        let settings = load(&toml);
        let host = settings.first_aws_host().unwrap();
        assert_eq!(host.username(), Some("user@example.com"));
        assert_eq!(host.mfa(), Some(MfaSelection::Totp));
        assert_eq!(
            settings.first_aws_sso_host().unwrap().region(),
            "eu-central-1"
        );
    }

    #[test]
    fn an_aws_host_without_an_idp_resolves_to_none() {
        let settings = load(&format!(
            r#"
            [[aws_hosts]]
            app_url = "{INIT_URL}"
            username = "user@example.com"
            mfa = "totp"
            "#
        ));

        let host = settings.first_aws_host().unwrap();
        assert_eq!(host.username(), Some("user@example.com"));
        assert!(host.idp().is_none());
        assert!(settings.resolve_idp(host.idp()).unwrap().is_none());
    }

    #[test]
    fn idps_round_trip() {
        let mut settings = AppConfig::default();
        settings.add_idp(
            Idp::new(
                "suse".to_string(),
                IdpType::Authentik,
                "https://id.example.com/".to_string(),
                "me@example.com".to_string(),
                Some(MfaSelection::Totp),
            )
            .unwrap(),
        );
        settings.set_default_idp("suse").unwrap();

        let toml = save(&settings);
        assert!(toml.contains("[[idps]]"), "{toml}");
        assert!(toml.contains(r#"type = "authentik""#), "{toml}");
        assert!(toml.contains(r#"default_idp = "suse""#), "{toml}");

        let found = load(&toml);
        let found = found.find_idp("suse").unwrap();
        assert_eq!(found.url(), "https://id.example.com");
        assert_eq!(found.username(), "me@example.com");
        assert_eq!(found.idp_type(), IdpType::Authentik);
        assert_eq!(found.mfa(), Some(MfaSelection::Totp));
    }

    #[test]
    fn rancher_hosts_round_trip() {
        let mut settings = AppConfig::default();
        settings.add_rancher_host(
            RancherHost::new(
                "https://rancher.example.com/".to_string(),
                "rancher".to_string(),
                Some("suse".to_string()),
                Some("me@example.com".to_string()),
                Some(MfaSelection::Totp),
            )
            .unwrap(),
        );

        let toml = save(&settings);
        assert!(toml.contains("[[rancher_hosts]]"), "{toml}");
        assert!(toml.contains(r#"idp = "suse""#), "{toml}");

        let settings = load(&toml);
        let host = settings.first_rancher_host().unwrap();
        assert_eq!(host.url(), "https://rancher.example.com");
        assert_eq!(host.username(), Some("me@example.com"));
        assert_eq!(host.client_id(), "rancher");
        assert_eq!(host.idp(), Some("suse"));
        assert_eq!(host.mfa(), Some(MfaSelection::Totp));
    }

    #[test]
    fn global_settings_round_trip() {
        let mut settings = AppConfig::default();
        let yk = YubikeyConfig::new(&[1, 2, 3, 4], "localhost", &[0x55; 32]);
        settings.set_yubikey(Some(yk.clone()));
        settings.set_wrap_cached_secrets(true);
        settings.set_use_keyring(false);

        let settings = load(&save(&settings));

        assert_eq!(settings.yubikey_config(), Some(&yk));
        assert!(settings.wrap_cached_secrets_enabled());
        assert!(!settings.keyring_enabled());
    }

    #[test]
    fn prompt_and_pinentry_round_trip() {
        let mut settings = AppConfig::default();
        settings.set_global_settings(GlobalSettings {
            prompt: Some(PromptMode::Terminal),
            pinentry: Some(PathBuf::from("/usr/bin/pinentry")),
            ..Default::default()
        });

        let toml = save(&settings);
        assert!(toml.contains(r#"prompt = "terminal""#), "{toml}");

        let settings = load(&toml);
        assert_eq!(settings.prompt_mode(), Some(PromptMode::Terminal));
        assert_eq!(
            settings.pinentry_program(),
            Some(PathBuf::from("/usr/bin/pinentry"))
        );
    }

    #[test]
    fn nothing_configured_writes_no_lists() {
        let toml = save(&AppConfig::default());

        assert!(!toml.contains("[["), "{toml}");
    }

    #[test]
    fn settings_without_yubikey_load() {
        let settings = load(
            r#"
            [global_settings]
            use_keyring = true
            default_idp = "suse"
            "#,
        );

        assert!(settings.keyring_enabled());
        assert_eq!(settings.yubikey_config(), None);
        assert!(!settings.wrap_cached_secrets_enabled());
    }

    #[test]
    fn an_unknown_mfa_selection_in_the_file_fails_to_load() {
        let err = toml::from_str::<FileConfig>(&format!(
            r#"
            [[aws_hosts]]
            app_url = "{INIT_URL}"
            mfa = "carrier-pigeon"
            "#
        ))
        .err()
        .unwrap();
        assert!(err.to_string().contains("invalid MFA selection"), "{err}");

        for section in ["idps", "rancher_hosts", "aws_sso_hosts"] {
            let toml = format!(
                r#"
                [[{section}]]
                name = "n"
                url = "https://id.example.com"
                app_url = "{INIT_URL}"
                client_id = "c"
                username = "u"
                region = "r"
                mfa = "sms"
                "#
            );
            assert!(toml::from_str::<FileConfig>(&toml).is_err(), "{section}");
        }
    }

    #[test]
    fn a_url_that_is_not_a_url_fails_to_load() {
        let file: FileConfig = toml::from_str(
            r#"
            [[rancher_hosts]]
            url = "not a url"
            client_id = "c"
            "#,
        )
        .unwrap();

        assert!(matches!(
            AppConfig::try_from(file),
            Err(ConfigError::Invalid(SettingsError::Url(_)))
        ));
    }

    #[test]
    fn a_salt_of_the_wrong_size_fails_to_load() {
        let file: FileConfig = toml::from_str(
            r#"
            [global_settings.yubikey]
            credential_id = "AQID"
            rp_id = "localhost"
            salt = "AQID"
            "#,
        )
        .unwrap();

        assert!(matches!(
            AppConfig::try_from(file),
            Err(ConfigError::Failed(_))
        ));
    }
}
