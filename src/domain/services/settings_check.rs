use crate::domain::models::login::{AwsOverrides, LoginTarget, RancherOverrides, ResolveError};
use crate::domain::models::settings::{AppConfig, AwsAppType};
use crate::domain::ports::login::LoginResolver;
use crate::domain::ports::login_check::LoginCheck;
use crate::domain::services::login_resolver::LoginResolverService;
use crate::domain::services::settings_editor::SettingsEditError;

/// The real implementation of LoginCheck.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResolvingLoginCheck;

impl LoginCheck for ResolvingLoginCheck {
    fn resolves(&self, settings: &AppConfig, target: &LoginTarget) -> Result<(), ResolveError> {
        let resolver = LoginResolverService::new(settings.clone());

        match target {
            LoginTarget::Aws { app_url, app_type } => resolver
                .resolve_aws(&AwsOverrides {
                    app_url: Some(app_url.clone()),
                    app_type: Some(*app_type),
                    ..Default::default()
                })
                .map(|_| ()),
            LoginTarget::Rancher { url } => resolver
                .resolve_rancher(&RancherOverrides {
                    url: Some(url.clone()),
                    ..Default::default()
                })
                .map(|_| ()),
        }
    }
}

/// All LoginTargets from an AppConfig.
pub(super) fn targets(settings: &AppConfig) -> Vec<LoginTarget> {
    let aws = settings.aws_hosts().iter().map(|host| LoginTarget::Aws {
        app_url: host.app_url().to_string(),
        app_type: AwsAppType::Aws,
    });

    let sso = settings
        .aws_sso_hosts()
        .iter()
        .map(|host| LoginTarget::Aws {
            app_url: host.app_url().to_string(),
            app_type: AwsAppType::AwsSso,
        });

    let rancher = settings
        .rancher_hosts()
        .iter()
        .map(|host| LoginTarget::Rancher {
            url: host.url().to_string(),
        });

    aws.chain(sso).chain(rancher).collect()
}

/// Verifies that changed applications will still resolve after the change is made.
pub(super) fn verify<C: LoginCheck>(
    check: &C,
    before: &AppConfig,
    after: &AppConfig,
    touched: &[LoginTarget],
) -> Result<(), SettingsEditError> {
    for target in touched {
        check
            .resolves(after, target)
            .map_err(SettingsEditError::DoesNotResolve)?;
    }

    // Only the apps of `after` are checked, so an app the change removed is never reported. An app is
    // broken when it resolved before and fails now.
    let urls: Vec<String> = targets(after)
        .into_iter()
        .filter(|target| {
            check.resolves(before, target).is_ok() && check.resolves(after, target).is_err()
        })
        .map(|target| target.url().to_string())
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

        assert!(verify(&ResolvingLoginCheck, &before, &after, &[]).is_ok());
    }

    #[test]
    fn an_app_that_resolved_and_now_fails_is_reported() {
        let before = settings();
        let mut after = before.clone();
        after.remove_idp("a");

        match verify(&ResolvingLoginCheck, &before, &after, &[]) {
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

        assert!(verify(&ResolvingLoginCheck, &before, &without_aws, &[]).is_ok());
        assert!(verify(&ResolvingLoginCheck, &before, &without_sso, &[]).is_ok());

        // Losing the identity provider breaks both, and each is named.
        let mut broken = before.clone();
        broken.remove_idp("a");
        match verify(&ResolvingLoginCheck, &before, &broken, &[]) {
            Err(SettingsEditError::WouldBreak { urls }) => assert_eq!(urls.len(), 2),
            other => panic!("expected WouldBreak, got {other:?}"),
        }
    }
}
