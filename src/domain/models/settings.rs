use crate::domain::models::idp::IdpType;
use crate::domain::models::mfa::MfaSelection;
use crate::domain::models::prompt_mode::PromptMode;
use std::path::PathBuf;
use thiserror::Error;
use url::Url;

/// Why a setting is not valid.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SettingsError {
    /// A url is not a url.
    #[error(transparent)]
    Url(#[from] url::ParseError),

    /// A named identity provider is not in the settings.
    #[error("the identity provider \"{0}\" is not configured, run `c9s config idp`")]
    UnknownIdp(String),

    /// A url that cannot have a path, like `mailto:`.
    #[error("cannot be base")]
    CannotBeBase,
}

/// Everything the user configured.
#[derive(Default, Clone)]
pub struct AppConfig {
    global_settings: GlobalSettings,
    idps: Vec<Idp>,
    aws_hosts: Vec<AwsHost>,
    aws_sso_hosts: Vec<AwsSsoHost>,
    rancher_hosts: Vec<RancherHost>,
}

/// Settings that are not about one app. `None` is "not set", so the default applies.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct GlobalSettings {
    pub use_keyring: Option<bool>,
    pub default_idp: Option<String>,
    pub yubikey: Option<YubikeyConfig>,
    pub wrap_cached_secrets: Option<bool>,
    pub prompt: Option<PromptMode>,
    pub pinentry: Option<PathBuf>,
}

/// Configuration for hardware-backed secret wrapping using a YubiKey.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YubikeyConfig {
    credential_id: Vec<u8>,
    rp_id: String,
    salt: [u8; 32],
}

impl YubikeyConfig {
    pub fn new(credential_id: &[u8], rp_id: impl Into<String>, salt: &[u8; 32]) -> Self {
        Self {
            credential_id: credential_id.to_vec(),
            rp_id: rp_id.into(),
            salt: *salt,
        }
    }

    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }
}

/// An identity provider that apps log in with, so that the instance, username and MFA are configured once.
#[derive(Clone)]
pub struct Idp {
    name: String,
    idp_type: IdpType,
    url: String,
    username: String,
    mfa: Option<MfaSelection>,
}

#[derive(Clone)]
pub struct AwsHost {
    app_url: String,
    username: Option<String>,
    idp: Option<String>,
    mfa: Option<MfaSelection>,
}

#[derive(Clone)]
pub struct AwsSsoHost {
    app_url: String,
    username: Option<String>,
    idp: Option<String>,
    region: String,
    mfa: Option<MfaSelection>,
}

#[derive(Clone)]
pub struct RancherHost {
    url: String,
    client_id: String,
    idp: Option<String>,
    username: Option<String>,
    mfa: Option<MfaSelection>,
}

/// The kind of AWS application in authentik.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum AwsAppType {
    /// The AWS SAML application, with IAM roles
    Aws,
    /// The AWS IAM Identity Center application
    AwsSso,
}

impl AppConfig {
    pub fn global_settings(&self) -> &GlobalSettings {
        &self.global_settings
    }

    pub fn set_global_settings(&mut self, global_settings: GlobalSettings) {
        self.global_settings = global_settings;
    }

    pub fn idps(&self) -> &[Idp] {
        &self.idps
    }

    pub fn aws_hosts(&self) -> &[AwsHost] {
        &self.aws_hosts
    }

    pub fn aws_sso_hosts(&self) -> &[AwsSsoHost] {
        &self.aws_sso_hosts
    }

    pub fn rancher_hosts(&self) -> &[RancherHost] {
        &self.rancher_hosts
    }

    pub fn set_use_keyring(&mut self, enable_keyring: bool) {
        self.global_settings.use_keyring = Some(enable_keyring);
    }

    pub fn keyring_enabled(&self) -> bool {
        self.global_settings.use_keyring.unwrap_or(true)
    }

    pub fn yubikey_config(&self) -> Option<&YubikeyConfig> {
        self.global_settings.yubikey.as_ref()
    }

    pub fn set_yubikey(&mut self, config: Option<YubikeyConfig>) {
        self.global_settings.yubikey = config;
    }

    pub fn wrap_cached_secrets_enabled(&self) -> bool {
        self.global_settings.wrap_cached_secrets.unwrap_or(false)
    }

    pub fn set_wrap_cached_secrets(&mut self, enabled: bool) {
        self.global_settings.wrap_cached_secrets = Some(enabled);
    }

    pub fn prompt_mode(&self) -> Option<PromptMode> {
        self.global_settings.prompt
    }

    pub fn pinentry_program(&self) -> Option<PathBuf> {
        self.global_settings.pinentry.clone()
    }

    pub fn add_idp(&mut self, idp: Idp) {
        match self.idps.iter_mut().find(|i| i.name == idp.name) {
            Some(existing) => *existing = idp,
            None => self.idps.push(idp),
        }
    }

    pub fn find_idp(&self, name: &str) -> Option<&Idp> {
        self.idps.iter().find(|idp| idp.name == name)
    }

    pub fn set_default_idp(&mut self, name: &str) -> Result<(), SettingsError> {
        if self.find_idp(name).is_none() {
            return Err(SettingsError::UnknownIdp(name.to_string()));
        }

        self.global_settings.default_idp = Some(name.to_string());

        Ok(())
    }

    /// An explicitly named identity provider must exist. Without a name, the default is used, then the only
    /// configured one.
    pub fn resolve_idp(&self, name: Option<&str>) -> Result<Option<&Idp>, SettingsError> {
        if let Some(name) = name {
            return self
                .find_idp(name)
                .map(Some)
                .ok_or_else(|| SettingsError::UnknownIdp(name.to_string()));
        }

        if let Some(name) = self.global_settings.default_idp.as_deref() {
            return self
                .find_idp(name)
                .map(Some)
                .ok_or_else(|| SettingsError::UnknownIdp(name.to_string()));
        }

        match self.idps.as_slice() {
            [only] => Ok(Some(only)),
            _ => Ok(None),
        }
    }

    pub fn add_aws_host(&mut self, host: AwsHost) {
        match self
            .aws_hosts
            .iter_mut()
            .find(|i| i.app_url == host.app_url)
        {
            Some(existing) => {
                existing.username = host.username;
                existing.idp = host.idp;
                existing.mfa = host.mfa;
            }
            None => self.aws_hosts.push(host),
        }
    }

    pub fn add_aws_sso_host(&mut self, host: AwsSsoHost) {
        match self
            .aws_sso_hosts
            .iter_mut()
            .find(|i| i.app_url == host.app_url)
        {
            Some(existing) => {
                existing.username = host.username;
                existing.idp = host.idp;
                existing.region = host.region;
                existing.mfa = host.mfa;
            }
            None => self.aws_sso_hosts.push(host),
        }
    }

    pub fn add_rancher_host(&mut self, host: RancherHost) {
        match self
            .rancher_hosts
            .iter_mut()
            .find(|i| same_app_url(&i.url, &host.url))
        {
            Some(existing) => *existing = host,
            None => self.rancher_hosts.push(host),
        }
    }

    pub fn first_rancher_host(&self) -> Option<&RancherHost> {
        self.rancher_hosts.first()
    }

    pub fn find_rancher_host(&self, url: &str) -> Option<&RancherHost> {
        self.rancher_hosts
            .iter()
            .find(|host| same_app_url(url, &host.url))
    }

    pub fn first_aws_host(&self) -> Option<&AwsHost> {
        self.aws_hosts.first()
    }

    pub fn first_aws_sso_host(&self) -> Option<&AwsSsoHost> {
        self.aws_sso_hosts.first()
    }

    pub fn find_aws_host(&self, app_url: &str) -> Option<&AwsHost> {
        self.aws_hosts
            .iter()
            .find(|host| same_app_url(app_url, &host.app_url))
    }

    pub fn find_aws_sso_host(&self, app_url: &str) -> Option<&AwsSsoHost> {
        self.aws_sso_hosts
            .iter()
            .find(|host| same_app_url(app_url, &host.app_url))
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
    pub fn mfa(&self) -> Option<MfaSelection> {
        self.mfa
    }

    pub fn new(
        app_url: String,
        username: Option<String>,
        idp: Option<String>,
        mfa: Option<MfaSelection>,
    ) -> Result<Self, SettingsError> {
        let mut app_url = Url::parse(app_url.as_str())?;

        // remove query
        app_url.set_query(None);

        // remove trailing slash
        app_url
            .path_segments_mut()
            .map_err(|_| SettingsError::CannotBeBase)?
            .pop_if_empty();

        Ok(AwsHost {
            app_url: String::from(app_url),
            mfa,
            username,
            idp,
        })
    }

    pub fn app_url(&self) -> &str {
        &self.app_url
    }

    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    pub fn idp(&self) -> Option<&str> {
        self.idp.as_deref()
    }
}

impl AwsSsoHost {
    pub fn mfa(&self) -> Option<MfaSelection> {
        self.mfa
    }

    pub fn new(
        app_url: String,
        username: Option<String>,
        idp: Option<String>,
        region: String,
        mfa: Option<MfaSelection>,
    ) -> Result<Self, SettingsError> {
        let mut app_url = Url::parse(app_url.as_str())?;

        // remove query
        app_url.set_query(None);

        // remove trailing slash
        app_url
            .path_segments_mut()
            .map_err(|_| SettingsError::CannotBeBase)?
            .pop_if_empty();

        Ok(AwsSsoHost {
            app_url: String::from(app_url),
            username,
            idp,
            region,
            mfa,
        })
    }

    pub fn app_url(&self) -> &str {
        &self.app_url
    }

    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    pub fn idp(&self) -> Option<&str> {
        self.idp.as_deref()
    }

    pub fn region(&self) -> &str {
        &self.region
    }
}

impl Idp {
    pub fn mfa(&self) -> Option<MfaSelection> {
        self.mfa
    }

    pub fn new(
        name: String,
        idp_type: IdpType,
        url: String,
        username: String,
        mfa: Option<MfaSelection>,
    ) -> Result<Self, SettingsError> {
        // the url is only kept when it parses, and without a trailing slash
        let url = Url::parse(&url)?
            .to_string()
            .trim_end_matches('/')
            .to_string();

        Ok(Idp {
            name,
            idp_type,
            url,
            username,
            mfa,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn idp_type(&self) -> IdpType {
        self.idp_type
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn username(&self) -> &str {
        &self.username
    }
}

impl RancherHost {
    pub fn mfa(&self) -> Option<MfaSelection> {
        self.mfa
    }

    pub fn new(
        url: String,
        client_id: String,
        idp: Option<String>,
        username: Option<String>,
        mfa: Option<MfaSelection>,
    ) -> Result<Self, SettingsError> {
        // the url is only kept when it parses, and without a trailing slash
        let url = Url::parse(&url)?
            .to_string()
            .trim_end_matches('/')
            .to_string();

        Ok(RancherHost {
            url,
            client_id,
            idp,
            username,
            mfa,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    pub fn idp(&self) -> Option<&str> {
        self.idp.as_deref()
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    const INIT_URL: &str = "https://id.example.com/application/saml/aws/sso/binding/init/";

    fn aws_host(mfa: Option<MfaSelection>) -> AwsHost {
        AwsHost::new(
            INIT_URL.to_string(),
            Some("user@example.com".to_string()),
            None,
            mfa,
        )
        .unwrap()
    }

    fn sso_host(region: &str, mfa: Option<MfaSelection>) -> AwsSsoHost {
        AwsSsoHost::new(
            INIT_URL.to_string(),
            Some("u".to_string()),
            None,
            region.to_string(),
            mfa,
        )
        .unwrap()
    }

    fn idp(name: &str) -> Idp {
        Idp::new(
            name.to_string(),
            IdpType::Authentik,
            format!("https://{name}.example.com/"),
            format!("{name}@example.com"),
            Some(MfaSelection::Totp),
        )
        .unwrap()
    }

    #[test]
    fn idps_are_replaced_by_name() {
        let mut settings = AppConfig::default();
        settings.add_idp(idp("suse"));
        settings.add_idp(
            Idp::new(
                "suse".to_string(),
                IdpType::Authentik,
                "https://new.example.com".to_string(),
                "new@example.com".to_string(),
                None,
            )
            .unwrap(),
        );
        settings.add_idp(idp("other"));
        settings.set_default_idp("other").unwrap();

        let found = settings.find_idp("suse").unwrap();
        assert_eq!(found.url(), "https://new.example.com");
        assert_eq!(found.username(), "new@example.com");
        assert_eq!(found.idp_type(), IdpType::Authentik);
        assert!(found.mfa().is_none());
        assert!(matches!(
            settings.find_idp("other").unwrap().mfa(),
            Some(MfaSelection::Totp)
        ));
        assert_eq!(settings.idps().len(), 2);
        assert!(settings.find_idp("missing").is_none());
    }

    #[test]
    fn an_idp_needs_a_valid_url() {
        let new = |url: &str| {
            Idp::new(
                "n".to_string(),
                IdpType::Authentik,
                url.to_string(),
                "u".to_string(),
                Some(MfaSelection::Totp),
            )
        };

        assert!(new("not a url").is_err());
        assert!(new("https://id.example.com").is_ok());
    }

    #[test]
    fn the_default_idp_must_exist() {
        let mut settings = AppConfig::default();
        let err = settings.set_default_idp("suse").err().unwrap();
        assert!(matches!(err, SettingsError::UnknownIdp(name) if name == "suse"));

        settings.add_idp(idp("suse"));
        settings.set_default_idp("suse").unwrap();
    }

    #[test]
    fn idps_resolve_by_name_then_default_then_the_only_one() {
        let mut settings = AppConfig::default();
        assert!(settings.resolve_idp(None).unwrap().is_none());

        settings.add_idp(idp("a"));
        let sole = settings.resolve_idp(None).unwrap().unwrap();
        assert_eq!(sole.name(), "a");

        settings.add_idp(idp("b"));
        assert!(settings.resolve_idp(None).unwrap().is_none());

        settings.set_default_idp("b").unwrap();
        assert_eq!(settings.resolve_idp(None).unwrap().unwrap().name(), "b");
        assert_eq!(
            settings.resolve_idp(Some("a")).unwrap().unwrap().name(),
            "a"
        );

        let err = settings.resolve_idp(Some("missing")).err().unwrap();
        assert!(matches!(err, SettingsError::UnknownIdp(name) if name == "missing"));
    }

    #[test]
    fn hosts_must_have_a_valid_url() {
        assert!(AwsHost::new("not a url".to_string(), None, None, None).is_err());
        assert!(AwsSsoHost::new(
            "mailto:someone@example.com".to_string(),
            None,
            None,
            "r".to_string(),
            None
        )
        .is_err());
    }

    #[test]
    fn the_stored_url_loses_its_query_and_trailing_slash() {
        // The authentik client adds the slash again when it builds the entry url.
        let host = AwsHost::new(format!("{INIT_URL}?foo=bar"), None, None, None).unwrap();

        assert_eq!(
            host.app_url(),
            "https://id.example.com/application/saml/aws/sso/binding/init"
        );
    }

    #[test]
    fn hosts_are_found_with_or_without_a_trailing_slash() {
        let mut settings = AppConfig::default();
        settings.add_aws_host(aws_host(None));
        settings.add_aws_sso_host(sso_host("eu-central-1", None));

        let bare = INIT_URL.trim_end_matches('/').to_string();
        assert!(settings.find_aws_host(INIT_URL).is_some());
        assert!(settings.find_aws_host(&bare).is_some());
        assert!(settings.find_aws_sso_host(INIT_URL).is_some());
        assert!(settings.find_aws_sso_host(&bare).is_some());
    }

    #[test]
    fn adding_a_host_twice_updates_it() {
        let mut settings = AppConfig::default();
        settings.add_aws_host(aws_host(None));
        settings.add_aws_host(
            AwsHost::new(
                INIT_URL.to_string(),
                Some("other@example.com".to_string()),
                Some("suse".to_string()),
                Some(MfaSelection::Totp),
            )
            .unwrap(),
        );

        let host = settings.first_aws_host().unwrap();
        assert_eq!(host.username(), Some("other@example.com"));
        assert_eq!(host.idp(), Some("suse"));
        assert!(matches!(host.mfa(), Some(MfaSelection::Totp)));
        assert_eq!(settings.aws_hosts().len(), 1);
    }

    #[test]
    fn sso_hosts_are_updated_by_url_too() {
        let mut settings = AppConfig::default();
        settings.add_aws_sso_host(sso_host("eu-central-1", Some(MfaSelection::WebAuthn)));
        settings.add_aws_sso_host(sso_host("us-east-1", Some(MfaSelection::WebAuthn)));

        let host = settings.first_aws_sso_host().unwrap();
        assert_eq!(host.region(), "us-east-1");
        assert!(matches!(host.mfa(), Some(MfaSelection::WebAuthn)));
        assert_eq!(settings.aws_sso_hosts().len(), 1);
    }

    #[test]
    fn hosts_are_found_by_their_stored_url() {
        let mut settings = AppConfig::default();
        let host = aws_host(None);
        let stored_url = host.app_url().to_string();
        settings.add_aws_host(host);

        assert!(settings.find_aws_host(&stored_url).is_some());
        assert!(settings.find_aws_host("https://elsewhere").is_none());
        assert!(settings.find_aws_sso_host(&stored_url).is_none());
        assert!(AppConfig::default().find_aws_host("x").is_none());
        assert!(AppConfig::default().find_aws_sso_host("x").is_none());
    }

    #[test]
    fn keyring_is_enabled_unless_turned_off() {
        let mut settings = AppConfig::default();
        assert!(settings.keyring_enabled());

        settings.set_use_keyring(false);
        assert!(!settings.keyring_enabled());
    }

    fn rancher_host(username: &str) -> RancherHost {
        RancherHost::new(
            "https://rancher.example.com/".to_string(),
            "rancher".to_string(),
            Some("suse".to_string()),
            Some(username.to_string()),
            Some(MfaSelection::Totp),
        )
        .unwrap()
    }

    #[test]
    fn a_rancher_host_needs_a_valid_url() {
        let new = |url: &str| RancherHost::new(url.to_string(), "c".to_string(), None, None, None);

        assert!(new("not a url").is_err());
        assert!(new("https://rancher.example.com").is_ok());
    }

    #[test]
    fn rancher_hosts_are_replaced_by_url() {
        let mut settings = AppConfig::default();
        settings.add_rancher_host(rancher_host("first@example.com"));
        settings.add_rancher_host(rancher_host("second@example.com"));

        let host = settings.first_rancher_host().unwrap();
        assert_eq!(settings.rancher_hosts().len(), 1);
        assert_eq!(host.url(), "https://rancher.example.com");
        assert_eq!(host.username(), Some("second@example.com"));
        assert_eq!(host.client_id(), "rancher");
        assert!(settings
            .find_rancher_host("https://rancher.example.com/")
            .is_some());
        assert!(settings
            .find_rancher_host("https://other.example.com")
            .is_none());
    }

    #[test]
    fn a_default_idp_that_vanished_is_an_error() {
        let mut settings = AppConfig::default();
        settings.set_global_settings(GlobalSettings {
            default_idp: Some("gone".to_string()),
            ..Default::default()
        });

        assert!(settings.resolve_idp(None).is_err());
    }
}
