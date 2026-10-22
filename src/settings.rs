use crate::authentik::mfa::{MfaSelection, MfaSelectionError};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum SettingsError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    ParseToml(#[from] toml::de::Error),

    #[error(transparent)]
    SerializeToml(#[from] toml::ser::Error),

    #[error(transparent)]
    Url(#[from] url::ParseError),

    #[error(transparent)]
    Mfa(#[from] MfaSelectionError),

    #[error("could not determine config directory")]
    NoConfigDir,

    #[error("cannot be base")]
    CannotBeBase,
}

#[derive(Serialize, Deserialize)]
pub struct AppConfig {
    global_settings: Option<GlobalSettings>,
    authentik_aws_hosts: Option<Vec<AwsHost>>,
    authentik_aws_sso_hosts: Option<Vec<AwsSsoHost>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GlobalSettings {
    use_keyring: Option<bool>,
    aws_defaults: Option<AwsDefaults>,
}

impl GlobalSettings {
    fn default() -> Self {
        Self {
            use_keyring: None,
            aws_defaults: Some(AwsDefaults::default()),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AwsHost {
    app_url: String,
    username: String,
    mfa: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AwsSsoHost {
    app_url: String,
    username: String,
    region: String,
    mfa: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct AwsDefaults {
    sso_provider: SsoProvider,
}

#[derive(ValueEnum, PartialEq, Eq, Debug, Clone, Copy, Deserialize, Serialize, Default)]
pub enum SsoProvider {
    // The `okta-*` names are accepted so that a settings file written for the Okta version still loads.
    #[serde(rename = "authentik-aws", alias = "okta-aws")]
    #[default]
    AuthentikAws,
    #[serde(rename = "authentik-aws-sso", alias = "okta-aws-sso")]
    AuthentikAwsSso,
}

impl AppConfig {
    pub fn set_aws_defaults(&mut self, defaults: AwsDefaults) {
        let global_settings = self
            .global_settings
            .get_or_insert(GlobalSettings::default());

        global_settings.aws_defaults = Some(defaults);
    }

    pub fn aws_defaults(&self) -> AwsDefaults {
        match self.global_settings.clone() {
            Some(global_settings) => global_settings.aws_defaults.unwrap_or_default(),
            None => AwsDefaults::default(),
        }
    }

    pub fn set_use_keyring(&mut self, enable_keyring: bool) {
        let global_settings = self
            .global_settings
            .get_or_insert(GlobalSettings::default());
        global_settings.use_keyring = Some(enable_keyring);
    }

    pub fn keyring_enabled(&self) -> bool {
        match self.global_settings.clone() {
            Some(global_settings) => global_settings.use_keyring.unwrap_or(true),
            None => true,
        }
    }

    pub fn add_aws_host(&mut self, host: AwsHost) {
        let hosts = self.authentik_aws_hosts.get_or_insert(vec![]);

        match hosts.iter_mut().find(|i| i.app_url == host.app_url.clone()) {
            Some(existing) => {
                existing.username = host.username;
                existing.mfa = host.mfa;
            }
            None => {
                hosts.push(host);
            }
        }
    }

    pub fn add_aws_sso_host(&mut self, host: AwsSsoHost) {
        let hosts = self.authentik_aws_sso_hosts.get_or_insert(vec![]);

        match hosts.iter_mut().find(|i| i.app_url == host.app_url.clone()) {
            Some(existing) => {
                existing.username = host.username;
                existing.region = host.region;
                existing.mfa = host.mfa;
            }
            None => {
                hosts.push(host);
            }
        }
    }

    pub fn aws_hosts(&self) -> Option<AwsHost> {
        self.authentik_aws_hosts.clone()?.first().cloned()
    }

    pub fn aws_sso_hosts(&self) -> Option<AwsSsoHost> {
        self.authentik_aws_sso_hosts.clone()?.first().cloned()
    }

    pub fn find_aws_sso_host(&self, app_url: String) -> Option<AwsSsoHost> {
        let hosts = self.authentik_aws_sso_hosts.clone();
        match hosts {
            Some(hosts) => hosts
                .iter()
                .find(|host| same_app_url(&app_url, &host.app_url))
                .cloned(),
            None => None,
        }
    }
    pub fn find_aws_host(&self, app_url: String) -> Option<AwsHost> {
        let hosts = self.authentik_aws_hosts.clone();
        match hosts {
            Some(hosts) => hosts
                .iter()
                .find(|host| same_app_url(&app_url, &host.app_url))
                .cloned(),
            None => None,
        }
    }

    pub fn read_config() -> Result<Self, SettingsError> {
        let config_file = AppConfig::config_file()?;
        if !Path::new(&config_file).exists() {
            fs::write(config_file.clone(), "")?;
        }
        let config_contents = fs::read(config_file)?;
        let config_contents = String::from_utf8(config_contents)?;
        let config: AppConfig = toml::from_str(config_contents.as_str())?;

        Ok(config)
    }

    pub fn write_config(&self) -> Result<(), SettingsError> {
        let config_dir = AppConfig::config_dir()?;
        fs::create_dir_all(config_dir)?;

        let config_file = AppConfig::config_file()?;

        let toml = toml::to_string(&self)?;
        fs::write(config_file, toml).expect("Unable to write file");

        Ok(())
    }

    fn config_dir() -> Result<PathBuf, SettingsError> {
        let config_dir = dirs::config_dir()
            .ok_or(SettingsError::NoConfigDir)?
            .join("c9s");
        fs::create_dir_all(config_dir.clone())?;

        Ok(config_dir)
    }

    fn config_file() -> Result<PathBuf, SettingsError> {
        let config_file = AppConfig::config_dir()?.join("settings.toml");

        Ok(config_file)
    }
}

/// Compares two app URLs ignoring a trailing slash and the query string.
fn same_app_url(a: &str, b: &str) -> bool {
    fn normalize(url: &str) -> String {
        let url = url.split('?').next().unwrap_or(url);
        url.trim_end_matches('/').to_string()
    }

    normalize(a) == normalize(b)
}

impl AwsHost {
    pub fn new(
        app_url: String,
        username: String,
        mfa: Option<String>,
    ) -> Result<Self, SettingsError> {
        let mut app_url = Url::parse(app_url.as_str())?;

        // remove query
        app_url.set_query(None);

        // remove trailing slash
        app_url
            .path_segments_mut()
            .map_err(|_| SettingsError::CannotBeBase)?
            .pop_if_empty();

        MfaSelection::validate(mfa.clone())?;

        Ok(AwsHost {
            app_url: String::from(app_url),
            mfa,
            username,
        })
    }

    pub fn app_url(&self) -> String {
        self.app_url.clone()
    }

    pub fn username(&self) -> String {
        self.username.clone()
    }
}

impl AwsSsoHost {
    pub fn new(
        app_url: String,
        username: String,
        region: String,
        mfa: Option<String>,
    ) -> Result<Self, SettingsError> {
        let mut app_url = Url::parse(app_url.as_str())?;

        // remove query
        app_url.set_query(None);

        // remove trailing slash
        app_url
            .path_segments_mut()
            .map_err(|_| SettingsError::CannotBeBase)?
            .pop_if_empty();

        MfaSelection::validate(mfa.clone())?;

        Ok(AwsSsoHost {
            app_url: String::from(app_url),
            username,
            region,
            mfa,
        })
    }

    pub fn app_url(&self) -> String {
        self.app_url.clone()
    }

    pub fn username(&self) -> String {
        self.username.clone()
    }

    pub fn region(&self) -> String {
        self.region.clone()
    }
}

pub trait MfaConfig {
    fn mfa(&self) -> Option<MfaSelection>;
}

impl MfaConfig for AwsHost {
    fn mfa(&self) -> Option<MfaSelection> {
        self.mfa.clone().map(MfaSelection::from_string)
    }
}

impl MfaConfig for AwsSsoHost {
    fn mfa(&self) -> Option<MfaSelection> {
        self.mfa.clone().map(MfaSelection::from_string)
    }
}

impl AwsDefaults {
    pub fn new(sso_provider: SsoProvider) -> Self {
        Self { sso_provider }
    }

    pub fn sso_provider(&self) -> SsoProvider {
        self.sso_provider
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INIT_URL: &str = "https://id.example.com/application/saml/aws/sso/binding/init/";

    fn config(toml: &str) -> AppConfig {
        toml::from_str(toml).unwrap()
    }

    fn aws_host(mfa: Option<&str>) -> AwsHost {
        AwsHost::new(
            INIT_URL.to_string(),
            "user@example.com".to_string(),
            mfa.map(str::to_string),
        )
        .unwrap()
    }

    #[test]
    fn the_new_keys_round_trip() {
        let mut settings = config("");
        settings.add_aws_host(aws_host(Some("totp")));
        settings.add_aws_sso_host(
            AwsSsoHost::new(
                INIT_URL.to_string(),
                "user@example.com".to_string(),
                "eu-central-1".to_string(),
                None,
            )
            .unwrap(),
        );
        settings.set_aws_defaults(AwsDefaults::new(SsoProvider::AuthentikAwsSso));

        let toml = toml::to_string(&settings).unwrap();
        assert!(toml.contains("[[authentik_aws_hosts]]"), "{}", toml);
        assert!(toml.contains("[[authentik_aws_sso_hosts]]"), "{}", toml);
        assert!(
            toml.contains(r#"sso_provider = "authentik-aws-sso""#),
            "{}",
            toml
        );
        assert!(!toml.contains("mfa_provider"), "{}", toml);

        let settings = config(&toml);
        let host = settings.aws_hosts().unwrap();
        assert_eq!(host.username(), "user@example.com");
        assert!(matches!(host.mfa(), Some(MfaSelection::Totp)));
        assert_eq!(settings.aws_sso_hosts().unwrap().region(), "eu-central-1");
        assert_eq!(
            settings.aws_defaults().sso_provider(),
            SsoProvider::AuthentikAwsSso
        );
    }

    #[test]
    fn leftover_okta_settings_still_load_and_yield_no_hosts() {
        let settings = config(
            r#"
            [global_settings]
            use_keyring = false

            [global_settings.aws_defaults]
            sso_provider = "okta-aws-sso"

            [[okta_aws_hosts]]
            app_url = "https://example.okta.com/home/amazon_aws/0on/272"
            username = "user@example.com"
            mfa = "push"
            mfa_provider = "google"

            [[okta_aws_sso_hosts]]
            app_url = "https://example.okta.com/home/amazon_aws_sso/0on/272"
            username = "user@example.com"
            region = "eu-central-1"
            "#,
        );

        assert!(settings.aws_hosts().is_none());
        assert!(settings.aws_sso_hosts().is_none());
        assert!(!settings.keyring_enabled());
        // The old default provider maps to its authentik counterpart.
        assert_eq!(
            settings.aws_defaults().sso_provider(),
            SsoProvider::AuthentikAwsSso
        );
    }

    #[test]
    fn a_leftover_mfa_provider_in_a_host_is_ignored() {
        let settings = config(
            r#"
            [[authentik_aws_hosts]]
            app_url = "https://id.example.com/application/saml/aws/sso/binding/init/"
            username = "user@example.com"
            mfa_provider = "google"
            "#,
        );

        assert_eq!(settings.aws_hosts().unwrap().username(), "user@example.com");
    }

    #[test]
    fn the_default_provider_is_authentik_aws() {
        assert_eq!(
            config("").aws_defaults().sso_provider(),
            SsoProvider::AuthentikAws
        );
    }

    #[test]
    fn hosts_validate_the_mfa_selection() {
        assert!(AwsHost::new(
            INIT_URL.to_string(),
            "u".to_string(),
            Some("totp".to_string())
        )
        .is_ok());
        assert!(AwsHost::new(INIT_URL.to_string(), "u".to_string(), None).is_ok());

        let err = AwsHost::new(
            INIT_URL.to_string(),
            "u".to_string(),
            Some("push".to_string()),
        )
        .err()
        .unwrap();
        assert_eq!(err.to_string(), "invalid MFA selection");

        let err = AwsSsoHost::new(
            INIT_URL.to_string(),
            "u".to_string(),
            "eu-central-1".to_string(),
            Some("carrier-pigeon".to_string()),
        )
        .err()
        .unwrap();
        assert_eq!(err.to_string(), "invalid MFA selection");
    }

    #[test]
    fn hosts_must_have_a_valid_url() {
        assert!(AwsHost::new("not a url".to_string(), "u".to_string(), None).is_err());
        assert!(AwsSsoHost::new(
            "mailto:someone@example.com".to_string(),
            "u".to_string(),
            "r".to_string(),
            None
        )
        .is_err());
    }

    #[test]
    fn the_stored_url_loses_its_query_and_trailing_slash() {
        // The authentik client adds the slash again when it builds the entry url.
        let host = AwsHost::new(format!("{INIT_URL}?foo=bar"), "u".to_string(), None).unwrap();

        assert_eq!(
            host.app_url(),
            "https://id.example.com/application/saml/aws/sso/binding/init"
        );
    }

    #[test]
    fn hosts_are_found_with_or_without_a_trailing_slash() {
        let mut settings = config("");
        settings.add_aws_host(aws_host(None));
        settings.add_aws_sso_host(
            AwsSsoHost::new(
                INIT_URL.to_string(),
                "u".to_string(),
                "eu-central-1".to_string(),
                None,
            )
            .unwrap(),
        );

        let bare = INIT_URL.trim_end_matches('/').to_string();
        assert!(settings.find_aws_host(INIT_URL.to_string()).is_some());
        assert!(settings.find_aws_host(bare.clone()).is_some());
        assert!(settings.find_aws_sso_host(INIT_URL.to_string()).is_some());
        assert!(settings.find_aws_sso_host(bare).is_some());
    }

    #[test]
    fn adding_a_host_twice_updates_it() {
        let mut settings = config("");
        settings.add_aws_host(aws_host(None));
        settings.add_aws_host(
            AwsHost::new(
                INIT_URL.to_string(),
                "other@example.com".to_string(),
                Some("totp".to_string()),
            )
            .unwrap(),
        );

        let host = settings.aws_hosts().unwrap();
        assert_eq!(host.username(), "other@example.com");
        assert!(matches!(host.mfa(), Some(MfaSelection::Totp)));
        assert_eq!(settings.authentik_aws_hosts.unwrap().len(), 1);
    }

    #[test]
    fn sso_hosts_are_updated_by_url_too() {
        let new_host = |region: &str| {
            AwsSsoHost::new(
                INIT_URL.to_string(),
                "u".to_string(),
                region.to_string(),
                Some("webauthn".to_string()),
            )
            .unwrap()
        };
        let mut settings = config("");
        settings.add_aws_sso_host(new_host("eu-central-1"));
        settings.add_aws_sso_host(new_host("us-east-1"));

        let host = settings.aws_sso_hosts().unwrap();
        assert_eq!(host.region(), "us-east-1");
        assert!(matches!(host.mfa(), Some(MfaSelection::WebAuthn)));
        assert_eq!(settings.authentik_aws_sso_hosts.unwrap().len(), 1);
    }

    #[test]
    fn hosts_are_found_by_their_stored_url() {
        let mut settings = config("");
        let host = aws_host(None);
        let stored_url = host.app_url();
        settings.add_aws_host(host);

        assert!(settings.find_aws_host(stored_url.clone()).is_some());
        assert!(settings
            .find_aws_host("https://elsewhere".to_string())
            .is_none());
        assert!(settings.find_aws_sso_host(stored_url).is_none());
        assert!(config("").find_aws_host("x".to_string()).is_none());
        assert!(config("").find_aws_sso_host("x".to_string()).is_none());
    }

    #[test]
    fn keyring_is_enabled_unless_turned_off() {
        let mut settings = config("");
        assert!(settings.keyring_enabled());

        settings.set_use_keyring(false);
        assert!(!settings.keyring_enabled());
    }
}
