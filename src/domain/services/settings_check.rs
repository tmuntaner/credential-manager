use crate::domain::models::login::{AwsOverrides, RancherOverrides, ResolveError};
use crate::domain::models::settings::{AppConfig, AwsAppType};
use crate::domain::ports::login::LoginResolver;
use crate::domain::services::login_resolver::LoginResolverService;
use crate::domain::services::settings_editor::SettingsEditError;

/// An app in the settings, by its key.
pub(super) enum Entry {
    Aws(String, AwsAppType),
    Rancher(String),
}

impl Entry {
    fn url(&self) -> &str {
        match self {
            Entry::Aws(url, _) | Entry::Rancher(url) => url,
        }
    }
}

fn entries(settings: &AppConfig) -> Vec<Entry> {
    let aws = settings
        .aws_hosts()
        .iter()
        .map(|host| Entry::Aws(host.app_url().to_string(), AwsAppType::Aws));

    let sso = settings
        .aws_sso_hosts()
        .iter()
        .map(|host| Entry::Aws(host.app_url().to_string(), AwsAppType::AwsSso));

    let rancher = settings
        .rancher_hosts()
        .iter()
        .map(|host| Entry::Rancher(host.url().to_string()));

    aws.chain(sso).chain(rancher).collect()
}

/// Resolves the login of one app using a provided resolver, as `c9s creds aws --app-url` or `c9s creds rancher --url` would.
fn resolve_with<R: LoginResolver>(resolver: &R, entry: &Entry) -> Result<(), ResolveError> {
    match entry {
        Entry::Aws(url, app_type) => resolver
            .resolve_aws(&AwsOverrides {
                app_url: Some(url.clone()),
                app_type: Some(*app_type),
                ..Default::default()
            })
            .map(|_| ()),
        Entry::Rancher(url) => resolver
            .resolve_rancher(&RancherOverrides {
                url: Some(url.clone()),
                ..Default::default()
            })
            .map(|_| ()),
    }
}

/// Resolves the login of one app, as `c9s creds aws --app-url` or `c9s creds rancher --url` would.
pub(super) fn resolve(settings: &AppConfig, entry: &Entry) -> Result<(), SettingsEditError> {
    let resolver = LoginResolverService::new(settings.clone());

    resolve_with(&resolver, entry).map_err(SettingsEditError::DoesNotResolve)
}

/// Refuses a change that breaks an app that worked before it.
pub(super) fn still_resolves(
    before: &AppConfig,
    after: &AppConfig,
) -> Result<(), SettingsEditError> {
    let before_resolver = LoginResolverService::new(before.clone());
    let after_resolver = LoginResolverService::new(after.clone());

    // Only the apps of `after` are checked, so an app the change removed is never reported. An app is
    // broken when it resolved before and fails now.
    let urls: Vec<String> = entries(after)
        .into_iter()
        .filter(|entry| {
            resolve_with(&before_resolver, entry).is_ok()
                && resolve_with(&after_resolver, entry).is_err()
        })
        .map(|entry| entry.url().to_string())
        .collect();

    if urls.is_empty() {
        return Ok(());
    }

    Err(SettingsEditError::WouldBreak { urls })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::idp::IdpType;
    use crate::domain::services::settings_editor::{
        apply_aws_app, apply_aws_sso_app, apply_idp, AwsAppInput, IdpInput,
    };

    const URL: &str = "https://id.example.com/application/saml/aws/sso/binding/init/";

    fn settings() -> AppConfig {
        let mut settings = AppConfig::default();
        apply_idp(
            &mut settings,
            IdpInput::new("a", IdpType::Authentik, "https://a.example.com", "user"),
        )
        .unwrap();
        apply_aws_app(&mut settings, AwsAppInput::new(URL, "a")).unwrap();
        settings
    }

    #[test]
    fn a_removed_app_is_not_reported() {
        let before = settings();
        let mut after = before.clone();
        after.remove_aws_host(URL);

        assert!(still_resolves(&before, &after).is_ok());
    }

    #[test]
    fn an_app_that_resolved_and_now_fails_is_reported() {
        let before = settings();
        let mut after = before.clone();
        after.remove_idp("a");

        match still_resolves(&before, &after) {
            Err(SettingsEditError::WouldBreak { urls }) => {
                assert_eq!(urls, vec![URL.trim_end_matches('/').to_string()])
            }
            other => panic!("expected WouldBreak, got {other:?}"),
        }
    }

    #[test]
    fn an_aws_app_and_an_sso_app_with_one_url_are_independent() {
        let mut before = settings();
        apply_aws_sso_app(&mut before, AwsAppInput::new(URL, "a"), "eu-west-1").unwrap();

        let mut without_aws = before.clone();
        without_aws.remove_aws_host(URL);
        let mut without_sso = before.clone();
        without_sso.remove_aws_sso_host(URL);

        assert!(still_resolves(&before, &without_aws).is_ok());
        assert!(still_resolves(&before, &without_sso).is_ok());

        // Losing the identity provider breaks both, and each is named.
        let mut broken = before.clone();
        broken.remove_idp("a");
        match still_resolves(&before, &broken) {
            Err(SettingsEditError::WouldBreak { urls }) => assert_eq!(urls.len(), 2),
            other => panic!("expected WouldBreak, got {other:?}"),
        }
    }
}
