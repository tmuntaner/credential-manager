use crate::app::settings::SECURITY_KEY_SUPPORTED;
use crate::domain::models::mfa::MfaSelection;
/// Whether two URLs are the same entry: the one rule of the settings.
pub use crate::domain::models::settings::same_app_url as same_url;
use crate::domain::models::settings::{AppConfig, AwsAppType};
use crate::domain::services::settings_editor::fields::allow_insecure_localhost;

/// The MFA choice from the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MfaChoice {
    /// Ask each time which method to use.
    Ask,
    Totp,
    /// A security key, e.g., a YubiKey.
    SecurityKey,
}

impl MfaChoice {
    /// The selection to save: "ask" is no selection.
    pub fn selection(self) -> Option<MfaSelection> {
        match self {
            MfaChoice::Ask => None,
            MfaChoice::Totp => Some(MfaSelection::Totp),
            MfaChoice::SecurityKey => Some(MfaSelection::WebAuthn),
        }
    }
}

impl From<MfaSelection> for MfaChoice {
    fn from(value: MfaSelection) -> Self {
        match value {
            MfaSelection::Totp => MfaChoice::Totp,
            MfaSelection::WebAuthn => MfaChoice::SecurityKey,
        }
    }
}

/// A field from a form. Ever form field is here so that we can put an error with the right input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Field {
    IdpName,
    IdpUrl,
    IdpUsername,
    IdpMfa,
    AwsAppUrl,
    AwsRegion,
    AwsIdp,
    AwsUsername,
    AwsMfa,
    RancherUrl,
    RancherClientId,
    RancherIdp,
    RancherUsername,
    RancherMfa,
}

/// The form to manage an identity provider.
#[derive(Clone, Debug)]
pub struct IdpForm {
    /// Change the existing one called `name`, instead of adding one.
    pub editing: bool,
    pub name: String,
    pub url: String,
    pub username: String,
    pub mfa: MfaChoice,
}

/// Which AWS app we need to manage. It's identified by its kind and URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AwsAppKey {
    pub app_url: String,
    pub kind: AwsAppType,
}

/// The form to manage an AWS app.
#[derive(Clone, Debug)]
pub struct AwsAppForm {
    /// The app we're working on (which may change URLs).
    pub original: Option<AwsAppKey>,
    pub app_url: String,
    pub kind: AwsAppType,
    /// Only for [`AwsAppType::AwsSso`].
    pub region: Option<String>,
    /// The identity provider the app logs in with. Required.
    pub idp: String,
    pub username: Option<String>,
    pub mfa: Option<MfaChoice>,
}

/// A form to manage a Rancher application.
#[derive(Clone, Debug)]
pub struct RancherForm {
    /// The url of the rancher we're working on (which may change URLs).
    pub original_url: Option<String>,
    pub url: String,
    pub client_id: String,
    /// The identity provider the app logs in with. Required.
    pub idp: String,
    pub username: Option<String>,
    pub mfa: Option<MfaChoice>,
}

/// The summary of an identity provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdpSummary {
    pub name: String,
    pub url: String,
    pub username: String,
    pub mfa: MfaChoice,
    /// A list of apps that log in with it by URL. We prevent removing it while this list has values.
    pub used_by: Vec<String>,
}

/// The summary of an AWS app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AwsAppSummary {
    pub app_url: String,
    pub kind: AwsAppType,
    pub region: Option<String>,
    pub idp: String,
    pub username: Option<String>,
    pub mfa: Option<MfaChoice>,
}

/// The summary of a Rancher app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RancherSummary {
    pub url: String,
    pub client_id: String,
    pub idp: String,
    pub username: Option<String>,
    pub mfa: Option<MfaChoice>,
}

/// The first run steps and whether each step is done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checklist {
    /// Required: setting up at least one idp.
    pub idp: bool,
    /// Optional.
    pub aws: bool,
    /// Optional.
    pub rancher: bool,
}

/// The full settings view with all settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettingsView {
    pub idps: Vec<IdpSummary>,
    pub aws_apps: Vec<AwsAppSummary>,
    pub rancher_hosts: Vec<RancherSummary>,
    pub use_keyring: bool,
    pub security_key_supported: bool,
    /// Whether a security key is enrolled to encrypt secrets.
    pub security_key_enrolled: bool,
    /// The relying party id of the enrolled security key.
    pub security_key_rp_id: Option<String>,
    /// Whether issued credentials (AWS/Rancher) are encrypted too, not only the IdP password and session.
    pub wrap_cached: bool,
    /// Plain `http://localhost` is accepted (debug builds only).
    pub insecure_localhost_allowed: bool, // todo: don't add this setting to production builds?
    pub checklist: Checklist,
}

impl From<AppConfig> for SettingsView {
    fn from(value: AppConfig) -> Self {
        let settings = &value;

        let idps: Vec<IdpSummary> = settings
            .idps()
            .iter()
            .map(|idp| IdpSummary {
                name: idp.name().to_string(),
                url: idp.url().to_string(),
                username: idp.username().to_string(),
                mfa: match idp.mfa() {
                    Some(mfa) => mfa.into(),
                    None => MfaChoice::Ask,
                },
                used_by: settings.apps_using_idp(idp.name()),
            })
            .collect();

        let mut aws_apps: Vec<AwsAppSummary> = settings
            .aws_hosts()
            .iter()
            .map(|host| AwsAppSummary {
                app_url: host.app_url().to_string(),
                kind: AwsAppType::Aws,
                region: None,
                idp: host.idp().to_string(),
                username: host.username().map(str::to_string),
                mfa: host.mfa().map(|mfa| mfa.into()),
            })
            .collect();
        aws_apps.extend(settings.aws_sso_hosts().iter().map(|host| AwsAppSummary {
            app_url: host.app_url().to_string(),
            kind: AwsAppType::AwsSso,
            region: Some(host.region().to_string()),
            idp: host.idp().to_string(),
            username: host.username().map(str::to_string),
            mfa: host.mfa().map(|mfa| mfa.into()),
        }));

        let rancher_hosts: Vec<RancherSummary> = settings
            .rancher_hosts()
            .iter()
            .map(|host| RancherSummary {
                url: host.url().to_string(),
                client_id: host.client_id().to_string(),
                idp: host.idp().to_string(),
                username: host.username().map(str::to_string),
                mfa: host.mfa().map(|mfa| mfa.into()),
            })
            .collect();

        SettingsView {
            checklist: Checklist {
                idp: !idps.is_empty(),
                aws: !aws_apps.is_empty(),
                rancher: !rancher_hosts.is_empty(),
            },
            idps,
            aws_apps,
            rancher_hosts,
            use_keyring: settings.keyring_enabled(),
            security_key_supported: SECURITY_KEY_SUPPORTED,
            security_key_enrolled: settings.yubikey_config().is_some(),
            security_key_rp_id: settings.yubikey_config().map(|yk| yk.rp_id().to_string()),
            wrap_cached: settings.wrap_cached_secrets_enabled(),
            insecure_localhost_allowed: allow_insecure_localhost(),
        }
    }
}

/// An error from a form field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldError {
    pub field: Field,
    pub message: String,
}

/// An error form a settings change.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SetupError {
    pub fields: Vec<FieldError>,
    /// A general problem that is not specific to one field.
    pub message: Option<String>,
}

impl SetupError {
    pub fn field(field: Field, message: impl Into<String>) -> Self {
        Self {
            fields: vec![FieldError {
                field,
                message: message.into(),
            }],
            message: None,
        }
    }

    pub fn general(message: impl Into<String>) -> Self {
        Self {
            fields: vec![],
            message: Some(message.into()),
        }
    }

    /// The whole error as one sentence.
    pub fn sentence(&self) -> String {
        let mut parts: Vec<&str> = self.message.iter().map(String::as_str).collect();
        parts.extend(self.fields.iter().map(|f| f.message.as_str()));
        if parts.is_empty() {
            "The change could not be saved.".to_string()
        } else {
            parts.join(" ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_the_same_entry_despite_a_slash_or_query() {
        assert!(same_url("https://a.example.com/", "https://a.example.com"));
        assert!(same_url(
            "https://a.example.com/x?y=1",
            "https://a.example.com/x"
        ));
        assert!(!same_url("https://a.example.com", "https://b.example.com"));
    }

    #[test]
    fn an_error_reads_as_one_sentence() {
        let mut error = SetupError::general("First.");
        error.fields = SetupError::field(Field::IdpUrl, "Second.").fields;
        assert_eq!(error.sentence(), "First. Second.");
        assert_eq!(
            SetupError::default().sentence(),
            "The change could not be saved."
        );
    }
}
