use crate::domain::models::idp::IdpType;
use base::models::mfa::MfaSelection;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum SettingsError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    ParseToml(#[from] toml::de::Error),

    #[error(transparent)]
    SerializeToml(#[from] toml::ser::Error),

    #[error(transparent)]
    Url(#[from] url::ParseError),

    #[error("the identity provider \"{0}\" is not configured, run `c9s config idp`")]
    UnknownIdp(String),

    #[error("could not determine config directory")]
    NoConfigDir,

    #[error("cannot be base")]
    CannotBeBase,

    #[error("base64 decode error: {0}")]
    DecodeBase64(String),
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct AppConfig {
    global_settings: Option<GlobalSettings>,
    idps: Option<Vec<Idp>>,
    aws_hosts: Option<Vec<AwsHost>>,
    aws_sso_hosts: Option<Vec<AwsSsoHost>>,
    rancher_hosts: Option<Vec<RancherHost>>,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq, Eq)]
pub struct GlobalSettings {
    use_keyring: Option<bool>,
    default_idp: Option<String>,
    yubikey: Option<YubikeyConfig>,
    wrap_cached_secrets: Option<bool>,
}

/// Configuration for hardware-backed secret wrapping using a YubiKey.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct YubikeyConfig {
    pub credential_id: String,
    pub rp_id: String,
    pub salt: String,
}

impl YubikeyConfig {
    pub fn new(credential_id: &[u8], rp_id: impl Into<String>, salt: &[u8; 32]) -> Self {
        use base64::Engine;
        Self {
            credential_id: base64::engine::general_purpose::STANDARD.encode(credential_id),
            rp_id: rp_id.into(),
            salt: base64::engine::general_purpose::STANDARD.encode(salt),
        }
    }

    pub fn decode_credential_id(&self) -> Result<Vec<u8>, SettingsError> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&self.credential_id)
            .map_err(|e| SettingsError::DecodeBase64(e.to_string()))
    }

    pub fn decode_salt(&self) -> Result<[u8; 32], SettingsError> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.salt)
            .map_err(|e| SettingsError::DecodeBase64(e.to_string()))?;
        bytes
            .try_into()
            .map_err(|_| SettingsError::DecodeBase64("salt must be exactly 32 bytes".to_string()))
    }
}

/// An identity provider that apps log in with, so that the instance, username and MFA are configured once.
#[derive(Serialize, Deserialize, Clone)]
pub struct Idp {
    name: String,
    #[serde(rename = "type", default)]
    idp_type: IdpType,
    url: String,
    username: String,
    mfa: Option<MfaSelection>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AwsHost {
    app_url: String,
    username: Option<String>,
    idp: Option<String>,
    mfa: Option<MfaSelection>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AwsSsoHost {
    app_url: String,
    username: Option<String>,
    idp: Option<String>,
    region: String,
    mfa: Option<MfaSelection>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RancherHost {
    url: String,
    client_id: String,
    idp: Option<String>,
    username: Option<String>,
    mfa: Option<MfaSelection>,
}

/// The kind of AWS application in authentik.
#[derive(ValueEnum, PartialEq, Eq, Debug, Clone, Copy)]
pub enum AwsAppType {
    /// The AWS SAML application, with IAM roles
    #[value(name = "aws")]
    Aws,
    /// The AWS IAM Identity Center application
    #[value(name = "aws-sso")]
    AwsSso,
}

impl AppConfig {
    pub fn set_use_keyring(&mut self, enable_keyring: bool) {
        let global_settings = self.global_settings.get_or_insert_with(Default::default);
        global_settings.use_keyring = Some(enable_keyring);
    }

    pub fn keyring_enabled(&self) -> bool {
        self.global_settings
            .as_ref()
            .and_then(|global_settings| global_settings.use_keyring)
            .unwrap_or(true)
    }

    pub fn yubikey_config(&self) -> Option<&YubikeyConfig> {
        self.global_settings
            .as_ref()
            .and_then(|g| g.yubikey.as_ref())
    }

    pub fn set_yubikey(&mut self, config: Option<YubikeyConfig>) {
        let global_settings = self.global_settings.get_or_insert_with(Default::default);
        global_settings.yubikey = config;
    }

    pub fn wrap_cached_secrets_enabled(&self) -> bool {
        self.global_settings
            .as_ref()
            .and_then(|g| g.wrap_cached_secrets)
            .unwrap_or(false)
    }

    pub fn set_wrap_cached_secrets(&mut self, enabled: bool) {
        let global_settings = self.global_settings.get_or_insert_with(Default::default);
        global_settings.wrap_cached_secrets = Some(enabled);
    }

    pub fn add_idp(&mut self, idp: Idp) {
        let idps = self.idps.get_or_insert(vec![]);

        match idps.iter_mut().find(|i| i.name == idp.name) {
            Some(existing) => *existing = idp,
            None => idps.push(idp),
        }
    }

    pub fn find_idp(&self, name: &str) -> Option<&Idp> {
        self.idps.as_ref()?.iter().find(|idp| idp.name == name)
    }

    pub fn set_default_idp(&mut self, name: &str) -> Result<(), SettingsError> {
        if self.find_idp(name).is_none() {
            return Err(SettingsError::UnknownIdp(name.to_string()));
        }

        let global_settings = self.global_settings.get_or_insert_with(Default::default);
        global_settings.default_idp = Some(name.to_string());

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

        let default_idp = self
            .global_settings
            .as_ref()
            .and_then(|global_settings| global_settings.default_idp.as_deref());
        if let Some(name) = default_idp {
            return self
                .find_idp(name)
                .map(Some)
                .ok_or_else(|| SettingsError::UnknownIdp(name.to_string()));
        }

        match self.idps.as_deref() {
            Some([only]) => Ok(Some(only)),
            _ => Ok(None),
        }
    }

    pub fn add_aws_host(&mut self, host: AwsHost) {
        let hosts = self.aws_hosts.get_or_insert(vec![]);

        match hosts.iter_mut().find(|i| i.app_url == host.app_url) {
            Some(existing) => {
                existing.username = host.username;
                existing.idp = host.idp;
                existing.mfa = host.mfa;
            }
            None => {
                hosts.push(host);
            }
        }
    }

    pub fn add_aws_sso_host(&mut self, host: AwsSsoHost) {
        let hosts = self.aws_sso_hosts.get_or_insert(vec![]);

        match hosts.iter_mut().find(|i| i.app_url == host.app_url) {
            Some(existing) => {
                existing.username = host.username;
                existing.idp = host.idp;
                existing.region = host.region;
                existing.mfa = host.mfa;
            }
            None => {
                hosts.push(host);
            }
        }
    }

    pub fn add_rancher_host(&mut self, host: RancherHost) {
        let hosts = self.rancher_hosts.get_or_insert(vec![]);

        match hosts.iter_mut().find(|i| same_app_url(&i.url, &host.url)) {
            Some(existing) => *existing = host,
            None => hosts.push(host),
        }
    }

    pub fn first_rancher_host(&self) -> Option<&RancherHost> {
        self.rancher_hosts.as_ref()?.first()
    }

    pub fn find_rancher_host(&self, url: &str) -> Option<&RancherHost> {
        self.rancher_hosts
            .as_ref()?
            .iter()
            .find(|host| same_app_url(url, &host.url))
    }

    pub fn first_aws_host(&self) -> Option<&AwsHost> {
        self.aws_hosts.as_ref()?.first()
    }

    pub fn first_aws_sso_host(&self) -> Option<&AwsSsoHost> {
        self.aws_sso_hosts.as_ref()?.first()
    }

    pub fn find_aws_host(&self, app_url: &str) -> Option<&AwsHost> {
        self.aws_hosts
            .as_ref()?
            .iter()
            .find(|host| same_app_url(app_url, &host.app_url))
    }

    pub fn find_aws_sso_host(&self, app_url: &str) -> Option<&AwsSsoHost> {
        self.aws_sso_hosts
            .as_ref()?
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

    fn config(toml: &str) -> AppConfig {
        toml::from_str(toml).unwrap()
    }

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
    fn the_new_keys_round_trip() {
        let mut settings = config("");
        settings.add_aws_host(aws_host(Some(MfaSelection::Totp)));
        settings.add_aws_sso_host(sso_host("eu-central-1", None));

        let toml = toml::to_string(&settings).unwrap();
        assert!(toml.contains("[[aws_hosts]]"), "{}", toml);
        assert!(toml.contains("[[aws_sso_hosts]]"), "{}", toml);

        let settings = config(&toml);
        let host = settings.first_aws_host().unwrap();
        assert_eq!(host.username(), Some("user@example.com"));
        assert!(matches!(host.mfa(), Some(MfaSelection::Totp)));
        assert_eq!(
            settings.first_aws_sso_host().unwrap().region(),
            "eu-central-1"
        );
    }

    #[test]
    fn an_aws_host_without_an_idp_resolves_to_none() {
        let settings = config(&format!(
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
    fn idps_round_trip_and_are_replaced_by_name() {
        let mut settings = config("");
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

        let toml = toml::to_string(&settings).unwrap();
        assert!(toml.contains("[[idps]]"), "{}", toml);
        assert!(toml.contains(r#"type = "authentik""#), "{}", toml);
        assert!(toml.contains(r#"default_idp = "other""#), "{}", toml);

        let settings = config(&toml);
        let found = settings.find_idp("suse").unwrap();
        assert_eq!(found.url(), "https://new.example.com");
        assert_eq!(found.username(), "new@example.com");
        assert_eq!(found.idp_type(), IdpType::Authentik);
        assert!(found.mfa().is_none());
        assert!(matches!(
            settings.find_idp("other").unwrap().mfa(),
            Some(MfaSelection::Totp)
        ));
        assert_eq!(settings.idps.as_ref().unwrap().len(), 2);
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
        let mut settings = config("");
        let err = settings.set_default_idp("suse").err().unwrap();
        assert!(matches!(err, SettingsError::UnknownIdp(name) if name == "suse"));

        settings.add_idp(idp("suse"));
        settings.set_default_idp("suse").unwrap();
    }

    #[test]
    fn idps_resolve_by_name_then_default_then_the_only_one() {
        let mut settings = config("");
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
    fn a_default_idp_that_vanished_is_an_error() {
        let settings = config(
            r#"
            [global_settings]
            default_idp = "gone"
            "#,
        );

        assert!(settings.resolve_idp(None).is_err());
    }

    #[test]
    fn an_unknown_mfa_selection_in_the_file_fails_to_load() {
        let err = toml::from_str::<AppConfig>(&format!(
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
            assert!(toml::from_str::<AppConfig>(&toml).is_err(), "{section}");
        }
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
        let mut settings = config("");
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
        let mut settings = config("");
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
        assert_eq!(settings.aws_hosts.unwrap().len(), 1);
    }

    #[test]
    fn sso_hosts_are_updated_by_url_too() {
        let mut settings = config("");
        settings.add_aws_sso_host(sso_host("eu-central-1", Some(MfaSelection::WebAuthn)));
        settings.add_aws_sso_host(sso_host("us-east-1", Some(MfaSelection::WebAuthn)));

        let host = settings.first_aws_sso_host().unwrap();
        assert_eq!(host.region(), "us-east-1");
        assert!(matches!(host.mfa(), Some(MfaSelection::WebAuthn)));
        assert_eq!(settings.aws_sso_hosts.unwrap().len(), 1);
    }

    #[test]
    fn hosts_are_found_by_their_stored_url() {
        let mut settings = config("");
        let host = aws_host(None);
        let stored_url = host.app_url().to_string();
        settings.add_aws_host(host);

        assert!(settings.find_aws_host(&stored_url).is_some());
        assert!(settings.find_aws_host("https://elsewhere").is_none());
        assert!(settings.find_aws_sso_host(&stored_url).is_none());
        assert!(config("").find_aws_host("x").is_none());
        assert!(config("").find_aws_sso_host("x").is_none());
    }

    #[test]
    fn keyring_is_enabled_unless_turned_off() {
        let mut settings = config("");
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
    fn rancher_hosts_round_trip_and_are_replaced_by_url() {
        let mut settings = config("");
        settings.add_rancher_host(rancher_host("first@example.com"));
        settings.add_rancher_host(rancher_host("second@example.com"));

        let toml = toml::to_string(&settings).unwrap();
        assert!(toml.contains("[[rancher_hosts]]"), "{}", toml);
        assert!(toml.contains(r#"idp = "suse""#), "{}", toml);
        assert!(!toml.contains("issuer"), "{}", toml);

        let settings = config(&toml);
        let host = settings.first_rancher_host().unwrap();
        assert_eq!(host.url(), "https://rancher.example.com");
        assert_eq!(host.username(), Some("second@example.com"));
        assert_eq!(host.client_id(), "rancher");
        assert_eq!(host.idp(), Some("suse"));
        assert!(matches!(host.mfa(), Some(MfaSelection::Totp)));
        assert!(settings
            .find_rancher_host("https://rancher.example.com/")
            .is_some());
        assert!(settings
            .find_rancher_host("https://other.example.com")
            .is_none());
    }

    #[test]
    fn a_rancher_host_needs_a_valid_url() {
        let new = |url: &str| RancherHost::new(url.to_string(), "c".to_string(), None, None, None);

        assert!(new("not a url").is_err());
        assert!(new("https://rancher.example.com").is_ok());
    }

    #[test]
    fn settings_roundtrip_with_yubikey_and_wrap_cached() {
        let mut settings = config("");
        let yk = YubikeyConfig::new(&[1, 2, 3, 4], "localhost", &[0x55; 32]);
        settings.set_yubikey(Some(yk.clone()));
        settings.set_wrap_cached_secrets(true);

        let toml_str = toml::to_string(&settings).unwrap();
        let deserialized: AppConfig = toml::from_str(&toml_str).unwrap();

        assert_eq!(deserialized.yubikey_config(), Some(&yk));
        assert!(deserialized.wrap_cached_secrets_enabled());

        let cred_id = yk.decode_credential_id().unwrap();
        assert_eq!(cred_id, vec![1, 2, 3, 4]);
        let salt = yk.decode_salt().unwrap();
        assert_eq!(salt, [0x55; 32]);
    }

    #[test]
    fn legacy_settings_without_yubikey_deserializes_correctly() {
        let toml_str = r#"
            [global_settings]
            use_keyring = true
            default_idp = "suse"
        "#;
        let settings: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(settings.keyring_enabled());
        assert_eq!(settings.yubikey_config(), None);
        assert!(!settings.wrap_cached_secrets_enabled());
    }
}
