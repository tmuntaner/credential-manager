use super::models::{
    AwsAppKind, AwsAppSummary, Checklist, IdpSummary, MfaChoice, RancherSummary, SettingsView,
};
use super::SECURITY_KEY_SUPPORTED;
use crate::domain::models::mfa::MfaSelection;
use crate::domain::models::settings::AppConfig;
use crate::domain::services::settings_editor::idp_used_by;
use crate::domain::services::settings_validation::allow_insecure_localhost;

fn mfa_choice(mfa: Option<MfaSelection>) -> MfaChoice {
    match mfa {
        None => MfaChoice::Ask,
        Some(MfaSelection::Totp) => MfaChoice::Totp,
        Some(MfaSelection::WebAuthn) => MfaChoice::SecurityKey,
    }
}

pub(super) fn summarize(settings: &AppConfig) -> SettingsView {
    let idps: Vec<IdpSummary> = settings
        .idps()
        .iter()
        .map(|idp| IdpSummary {
            name: idp.name().to_string(),
            url: idp.url().to_string(),
            username: idp.username().to_string(),
            mfa: mfa_choice(idp.mfa()),
            used_by: idp_used_by(settings, idp.name()),
        })
        .collect();

    let mut aws_apps: Vec<AwsAppSummary> = settings
        .aws_hosts()
        .iter()
        .map(|host| AwsAppSummary {
            app_url: host.app_url().to_string(),
            kind: AwsAppKind::Aws,
            region: None,
            idp: host.idp().to_string(),
            username: host.username().map(str::to_string),
            mfa: host.mfa().map(|mfa| mfa_choice(Some(mfa))),
        })
        .collect();
    aws_apps.extend(settings.aws_sso_hosts().iter().map(|host| AwsAppSummary {
        app_url: host.app_url().to_string(),
        kind: AwsAppKind::AwsSso,
        region: Some(host.region().to_string()),
        idp: host.idp().to_string(),
        username: host.username().map(str::to_string),
        mfa: host.mfa().map(|mfa| mfa_choice(Some(mfa))),
    }));

    let rancher_hosts: Vec<RancherSummary> = settings
        .rancher_hosts()
        .iter()
        .map(|host| RancherSummary {
            url: host.url().to_string(),
            client_id: host.client_id().to_string(),
            idp: host.idp().to_string(),
            username: host.username().map(str::to_string),
            mfa: host.mfa().map(|mfa| mfa_choice(Some(mfa))),
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
