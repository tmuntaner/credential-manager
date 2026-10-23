//! Works out what to log in with, from the settings and what the user gave on the command line.
//!
//! The precedence is the same everywhere: a command line value wins over the app entry in the settings, which
//! wins over the identity provider.

use crate::domain::models::login::{
    AwsLogin, AwsOverrides, RancherLogin, RancherOverrides, ResolveError,
};
use crate::domain::models::settings::{AppConfig, AwsAppType, AwsHost, AwsSsoHost, Idp};
use crate::domain::ports::login::LoginResolver;
use base::models::mfa::MfaSelection;

/// Resolves logins from the settings.
pub struct LoginResolverService {
    settings: AppConfig,
}

impl LoginResolverService {
    pub fn new(settings: AppConfig) -> Self {
        Self { settings }
    }

    /// An explicit app type wins. Otherwise it is the type that has an entry for the app url, or without an app
    /// url, the only type that has entries.
    fn aws_app_type(&self, overrides: &AwsOverrides) -> Result<AwsAppType, ResolveError> {
        if let Some(app_type) = overrides.app_type {
            return Ok(app_type);
        }

        let app_url = overrides.app_url.as_deref();
        let (is_aws, is_aws_sso) = match app_url {
            Some(url) => (
                self.settings.find_aws_host(url).is_some(),
                self.settings.find_aws_sso_host(url).is_some(),
            ),
            None => (
                self.settings.first_aws_host().is_some(),
                self.settings.first_aws_sso_host().is_some(),
            ),
        };

        match (is_aws, is_aws_sso, app_url) {
            (true, false, _) => Ok(AwsAppType::Aws),
            (false, true, _) => Ok(AwsAppType::AwsSso),
            (true, true, Some(_)) => Err(ResolveError::AppUrlInBothTypes),
            (true, true, None) => Err(ResolveError::BothTypesConfigured),
            (false, false, Some(_)) => Err(ResolveError::AppUrlNotConfigured),
            (false, false, None) => Err(ResolveError::NoAppUrl),
        }
    }
}

impl LoginResolver for LoginResolverService {
    fn resolve_aws(&self, overrides: &AwsOverrides) -> Result<AwsLogin, ResolveError> {
        let app_type = self.aws_app_type(overrides)?;
        let app_url = overrides.app_url.as_deref();

        let entry: Option<AwsEntry> = match (app_type, app_url) {
            (AwsAppType::Aws, Some(url)) => self.settings.find_aws_host(url).map(Into::into),
            (AwsAppType::Aws, None) => self.settings.first_aws_host().map(Into::into),
            (AwsAppType::AwsSso, Some(url)) => self.settings.find_aws_sso_host(url).map(Into::into),
            (AwsAppType::AwsSso, None) => self.settings.first_aws_sso_host().map(Into::into),
        };
        let app_url = match (app_url, &entry) {
            (Some(url), _) => url.to_string(),
            (None, Some(entry)) => entry.app_url.to_string(),
            (None, None) => return Err(ResolveError::NoAppUrl),
        };

        let idp = self
            .settings
            .resolve_idp(entry.as_ref().and_then(|entry| entry.idp))?;
        let identity = Identity::resolve(
            overrides.username.as_deref(),
            overrides.mfa,
            entry.as_ref().and_then(|entry| entry.username),
            entry.as_ref().and_then(|entry| entry.mfa),
            idp,
        );
        let username = identity.username.ok_or(ResolveError::NoUsername)?;

        let region = match app_type {
            AwsAppType::Aws => None,
            AwsAppType::AwsSso => Some(
                overrides
                    .region
                    .as_deref()
                    .or_else(|| entry.as_ref().and_then(|entry| entry.region))
                    .ok_or(ResolveError::NoRegion)?
                    .to_string(),
            ),
        };

        Ok(AwsLogin {
            app_url,
            idp_url: idp.map(|idp| idp.url().to_string()),
            username,
            region,
            mfa: identity.mfa,
            app_type,
        })
    }

    fn resolve_rancher(&self, overrides: &RancherOverrides) -> Result<RancherLogin, ResolveError> {
        let host = match &overrides.url {
            Some(url) => self.settings.find_rancher_host(url),
            None => self.settings.first_rancher_host(),
        }
        .ok_or(ResolveError::RancherNotConfigured)?;

        let idp = self
            .settings
            .resolve_idp(host.idp())?
            .ok_or(ResolveError::RancherNeedsIdp)?;
        let identity = Identity::resolve(
            overrides.username.as_deref(),
            overrides.mfa,
            host.username(),
            host.mfa(),
            Some(idp),
        );

        Ok(RancherLogin {
            url: host.url().to_string(),
            username: identity.username.ok_or(ResolveError::NoUsername)?,
            mfa: identity.mfa,
            idp_type: idp.idp_type(),
            idp_url: idp.url().to_string(),
            client_id: host.client_id().to_string(),
        })
    }
}

/// The username and MFA selection to log in with.
#[derive(Debug, Default, PartialEq, Eq)]
struct Identity {
    username: Option<String>,
    mfa: Option<MfaSelection>,
}

impl Identity {
    /// `flag_*` come from the command line, `app_*` from the entry of the app.
    fn resolve(
        flag_username: Option<&str>,
        flag_mfa: Option<MfaSelection>,
        app_username: Option<&str>,
        app_mfa: Option<MfaSelection>,
        idp: Option<&Idp>,
    ) -> Self {
        Identity {
            username: flag_username
                .or(app_username)
                .or_else(|| idp.map(Idp::username))
                .map(str::to_string),
            mfa: flag_mfa.or(app_mfa).or_else(|| idp.and_then(Idp::mfa)),
        }
    }
}

/// An AWS entry of either app type.
struct AwsEntry<'a> {
    app_url: &'a str,
    username: Option<&'a str>,
    idp: Option<&'a str>,
    mfa: Option<MfaSelection>,
    region: Option<&'a str>,
}

impl<'a> From<&'a AwsHost> for AwsEntry<'a> {
    fn from(host: &'a AwsHost) -> Self {
        AwsEntry {
            app_url: host.app_url(),
            username: host.username(),
            idp: host.idp(),
            mfa: host.mfa(),
            region: None,
        }
    }
}

impl<'a> From<&'a AwsSsoHost> for AwsEntry<'a> {
    fn from(host: &'a AwsSsoHost) -> Self {
        AwsEntry {
            app_url: host.app_url(),
            username: host.username(),
            idp: host.idp(),
            mfa: host.mfa(),
            region: Some(host.region()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::idp::IdpType;

    const AWS_URL: &str = "https://id.example.com/application/saml/aws/sso/binding/init";
    const SSO_URL: &str = "https://id.example.com/application/saml/sso/sso/binding/init";
    const OTHER_URL: &str = "https://other.example.com/init";

    fn settings() -> AppConfig {
        toml::from_str(&format!(
            r#"
            [[aws_hosts]]
            app_url = "{AWS_URL}"
            username = "aws-user@example.com"
            mfa = "totp"

            [[aws_sso_hosts]]
            app_url = "{SSO_URL}"
            username = "sso-user@example.com"
            region = "eu-central-1"
            mfa = "webauthn"
            "#
        ))
        .unwrap()
    }

    fn idp_settings() -> AppConfig {
        toml::from_str(&format!(
            r#"
            [global_settings]
            default_idp = "suse"

            [[idps]]
            name = "suse"
            type = "authentik"
            url = "https://suse.example.com"
            username = "idp-user@example.com"
            mfa = "totp"

            [[idps]]
            name = "other"
            url = "https://other.example.com"
            username = "other-user@example.com"

            [[aws_hosts]]
            app_url = "{AWS_URL}"

            [[aws_sso_hosts]]
            app_url = "{SSO_URL}"
            username = "app-user@example.com"
            idp = "other"
            region = "eu-central-1"
            mfa = "webauthn"

            [[rancher_hosts]]
            url = "https://rancher.example.com"
            client_id = "rancher"

            [[rancher_hosts]]
            url = "https://rancher2.example.com"
            client_id = "rancher"
            idp = "other"
            username = "app-user@example.com"
            mfa = "webauthn"
            "#
        ))
        .unwrap()
    }

    fn aws(app_type: Option<AwsAppType>, app_url: Option<&str>) -> AwsOverrides {
        AwsOverrides {
            app_type,
            app_url: app_url.map(str::to_string),
            ..Default::default()
        }
    }

    fn error(result: Result<impl std::fmt::Debug, ResolveError>) -> String {
        result.unwrap_err().to_string()
    }

    #[test]
    fn uses_the_first_host_of_the_app_type() {
        let found = LoginResolverService::new(settings())
            .resolve_aws(&aws(Some(AwsAppType::Aws), None))
            .unwrap();
        assert_eq!(found.app_type, AwsAppType::Aws);
        assert_eq!(found.app_url, AWS_URL);
        assert_eq!(found.username, "aws-user@example.com");
        assert!(found.region.is_none());
        assert_eq!(found.mfa, Some(MfaSelection::Totp));

        let found = LoginResolverService::new(settings())
            .resolve_aws(&aws(Some(AwsAppType::AwsSso), None))
            .unwrap();
        assert_eq!(found.app_type, AwsAppType::AwsSso);
        assert_eq!(found.app_url, SSO_URL);
        assert_eq!(found.region.as_deref(), Some("eu-central-1"));
        assert_eq!(found.mfa, Some(MfaSelection::WebAuthn));
    }

    #[test]
    fn flags_override_the_stored_host() {
        let overrides = AwsOverrides {
            app_type: Some(AwsAppType::AwsSso),
            app_url: Some(SSO_URL.to_string()),
            username: Some("other@example.com".to_string()),
            mfa: Some(MfaSelection::Totp),
            region: Some("us-east-1".to_string()),
        };

        let found = LoginResolverService::new(settings())
            .resolve_aws(&overrides)
            .unwrap();
        assert_eq!(found.username, "other@example.com");
        assert_eq!(found.region.as_deref(), Some("us-east-1"));
        assert_eq!(found.mfa, Some(MfaSelection::Totp));
    }

    #[test]
    fn a_configured_app_url_picks_its_app_type() {
        let found = LoginResolverService::new(settings())
            .resolve_aws(&aws(None, Some(SSO_URL)))
            .unwrap();
        assert_eq!(found.app_type, AwsAppType::AwsSso);
        assert_eq!(found.username, "sso-user@example.com");

        let found = LoginResolverService::new(settings())
            .resolve_aws(&aws(None, Some(AWS_URL)))
            .unwrap();
        assert_eq!(found.app_type, AwsAppType::Aws);

        let overrides = AwsOverrides {
            username: Some("u".to_string()),
            region: Some("eu-central-1".to_string()),
            ..aws(Some(AwsAppType::AwsSso), Some(AWS_URL))
        };
        let found = LoginResolverService::new(settings())
            .resolve_aws(&overrides)
            .unwrap();
        assert_eq!(found.app_type, AwsAppType::AwsSso);
    }

    #[test]
    fn the_only_configured_app_type_is_used_without_an_app_url() {
        let settings: AppConfig = toml::from_str(&format!(
            r#"
            [[aws_sso_hosts]]
            app_url = "{SSO_URL}"
            username = "u"
            region = "eu-central-1"
            "#
        ))
        .unwrap();

        let found = LoginResolverService::new(settings)
            .resolve_aws(&aws(None, None))
            .unwrap();
        assert_eq!(found.app_type, AwsAppType::AwsSso);
    }

    #[test]
    fn the_app_type_is_needed_when_it_cannot_be_told() {
        assert_eq!(
            error(LoginResolverService::new(settings()).resolve_aws(&aws(None, None))),
            "both app types are configured, please supply an app-type or an app-url"
        );
        assert_eq!(
            error(LoginResolverService::new(settings()).resolve_aws(&aws(None, Some(OTHER_URL)))),
            "the app-url is not configured, please supply an app-type"
        );

        let both: AppConfig = toml::from_str(&format!(
            r#"
            [[aws_hosts]]
            app_url = "{AWS_URL}"
            username = "u"

            [[aws_sso_hosts]]
            app_url = "{AWS_URL}"
            username = "u"
            region = "eu-central-1"
            "#
        ))
        .unwrap();
        assert_eq!(
            error(LoginResolverService::new(both).resolve_aws(&aws(None, Some(AWS_URL)))),
            "the app-url is configured as both app types, please supply an app-type"
        );
    }

    #[test]
    fn settings_are_required_when_nothing_is_stored() {
        let empty = AppConfig::default();

        assert_eq!(
            error(LoginResolverService::new(empty.clone()).resolve_aws(&aws(None, None))),
            "please supply an app-url"
        );
        assert_eq!(
            error(
                LoginResolverService::new(empty.clone())
                    .resolve_aws(&aws(Some(AwsAppType::Aws), None))
            ),
            "please supply an app-url"
        );
        assert_eq!(
            error(
                LoginResolverService::new(empty)
                    .resolve_aws(&aws(Some(AwsAppType::AwsSso), Some(OTHER_URL)))
            ),
            "please supply a username"
        );
    }

    #[test]
    fn a_url_that_is_not_stored_needs_a_username_and_for_sso_a_region() {
        assert_eq!(
            error(
                LoginResolverService::new(settings())
                    .resolve_aws(&aws(Some(AwsAppType::Aws), Some(OTHER_URL)))
            ),
            "please supply a username"
        );

        let overrides = AwsOverrides {
            username: Some("u".to_string()),
            ..aws(Some(AwsAppType::AwsSso), Some(OTHER_URL))
        };
        assert_eq!(
            error(LoginResolverService::new(settings()).resolve_aws(&overrides)),
            "please supply a region"
        );
    }

    #[test]
    fn aws_falls_back_to_the_default_idp_and_the_password_follows_it() {
        let found = LoginResolverService::new(idp_settings())
            .resolve_aws(&aws(Some(AwsAppType::Aws), None))
            .unwrap();
        assert_eq!(found.username, "idp-user@example.com");
        assert_eq!(found.mfa, Some(MfaSelection::Totp));
        assert_eq!(found.idp_url.as_deref(), Some("https://suse.example.com"));
        assert_eq!(found.password_url(), "https://suse.example.com");
        assert_eq!(found.app_url, AWS_URL);
    }

    #[test]
    fn aws_app_settings_win_over_the_idp_and_flags_win_over_both() {
        let found = LoginResolverService::new(idp_settings())
            .resolve_aws(&aws(Some(AwsAppType::AwsSso), None))
            .unwrap();
        assert_eq!(found.username, "app-user@example.com");
        assert_eq!(found.mfa, Some(MfaSelection::WebAuthn));
        assert_eq!(found.password_url(), "https://other.example.com");

        let overrides = AwsOverrides {
            username: Some("flag".to_string()),
            mfa: Some(MfaSelection::Totp),
            ..aws(Some(AwsAppType::AwsSso), None)
        };
        let found = LoginResolverService::new(idp_settings())
            .resolve_aws(&overrides)
            .unwrap();
        assert_eq!(found.username, "flag");
        assert_eq!(found.mfa, Some(MfaSelection::Totp));
    }

    #[test]
    fn aws_without_an_idp_keeps_the_app_domain_for_the_password() {
        let found = LoginResolverService::new(settings())
            .resolve_aws(&aws(Some(AwsAppType::Aws), None))
            .unwrap();
        assert!(found.idp_url.is_none());
        assert_eq!(found.password_url(), AWS_URL);
    }

    #[test]
    fn aws_with_an_unknown_idp_is_an_error() {
        let settings: AppConfig = toml::from_str(&format!(
            r#"
            [[aws_hosts]]
            app_url = "{AWS_URL}"
            idp = "missing"
            "#
        ))
        .unwrap();

        let message = error(
            LoginResolverService::new(settings).resolve_aws(&aws(Some(AwsAppType::Aws), None)),
        );
        assert!(message.contains("missing"), "{message}");
    }

    #[test]
    fn the_identity_is_resolved_flag_then_app_then_idp() {
        let settings = idp_settings();
        let idp = settings.find_idp("suse");

        let found = Identity::resolve(None, None, None, None, idp);
        assert_eq!(found.username.as_deref(), Some("idp-user@example.com"));
        assert_eq!(found.mfa, Some(MfaSelection::Totp));

        let found = Identity::resolve(None, None, Some("app"), Some(MfaSelection::WebAuthn), idp);
        assert_eq!(found.username.as_deref(), Some("app"));
        assert_eq!(found.mfa, Some(MfaSelection::WebAuthn));

        let found = Identity::resolve(
            Some("flag"),
            Some(MfaSelection::Totp),
            Some("app"),
            Some(MfaSelection::WebAuthn),
            idp,
        );
        assert_eq!(found.username.as_deref(), Some("flag"));
        assert_eq!(found.mfa, Some(MfaSelection::Totp));

        assert_eq!(
            Identity::resolve(None, None, None, None, None),
            Identity::default()
        );
    }

    #[test]
    fn rancher_uses_the_default_idp_and_flags_override_it() {
        let found = LoginResolverService::new(idp_settings())
            .resolve_rancher(&RancherOverrides::default())
            .unwrap();
        assert_eq!(found.url, "https://rancher.example.com");
        assert_eq!(found.username, "idp-user@example.com");
        assert_eq!(found.client_id, "rancher");
        assert_eq!(found.idp_url, "https://suse.example.com");
        assert_eq!(found.idp_type, IdpType::Authentik);
        assert_eq!(found.mfa, Some(MfaSelection::Totp));

        let overrides = RancherOverrides {
            username: Some("other".to_string()),
            mfa: Some(MfaSelection::WebAuthn),
            ..Default::default()
        };
        let found = LoginResolverService::new(idp_settings())
            .resolve_rancher(&overrides)
            .unwrap();
        assert_eq!(found.username, "other");
        assert_eq!(found.mfa, Some(MfaSelection::WebAuthn));
    }

    #[test]
    fn rancher_app_settings_win_over_the_idp() {
        let overrides = RancherOverrides {
            url: Some("https://rancher2.example.com".to_string()),
            ..Default::default()
        };
        let found = LoginResolverService::new(idp_settings())
            .resolve_rancher(&overrides)
            .unwrap();
        assert_eq!(found.idp_url, "https://other.example.com");
        assert_eq!(found.username, "app-user@example.com");
        assert_eq!(found.mfa, Some(MfaSelection::WebAuthn));

        let overrides = RancherOverrides {
            username: Some("flag".to_string()),
            ..overrides
        };
        let found = LoginResolverService::new(idp_settings())
            .resolve_rancher(&overrides)
            .unwrap();
        assert_eq!(found.username, "flag");
    }

    #[test]
    fn rancher_needs_an_idp() {
        let settings: AppConfig = toml::from_str(
            r#"
            [[rancher_hosts]]
            url = "https://rancher.example.com"
            client_id = "rancher"
            username = "user@example.com"
            "#,
        )
        .unwrap();

        let message = error(
            LoginResolverService::new(settings).resolve_rancher(&RancherOverrides::default()),
        );
        assert!(message.contains("c9s config idp"), "{message}");
    }

    #[test]
    fn rancher_needs_a_configured_host() {
        let none = RancherOverrides::default();
        assert!(LoginResolverService::new(AppConfig::default())
            .resolve_rancher(&none)
            .is_err());

        let other = RancherOverrides {
            url: Some("https://other.example.com".to_string()),
            ..Default::default()
        };
        assert!(LoginResolverService::new(idp_settings())
            .resolve_rancher(&other)
            .is_err());
    }
}
