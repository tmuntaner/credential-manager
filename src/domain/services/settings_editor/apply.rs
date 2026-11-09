use super::error::SettingsEditError;
use super::fields::security_key_supported;
use super::input::{AwsAppInput, AwsAppKind, IdpInput, RancherInput};
use super::validate::{validate_aws, validate_idp, validate_rancher};
use crate::domain::models::settings::{
    same_app_url, AppConfig, AwsAppType, AwsHost, AwsSsoHost, Idp, RancherHost, SettingsError,
};

/// Adds an identity provider, or updates the one with the same name.
pub(crate) fn apply_idp(
    settings: &mut AppConfig,
    input: IdpInput,
) -> Result<(), SettingsEditError> {
    let valid =
        validate_idp(&input, security_key_supported()).map_err(SettingsEditError::InvalidFields)?;
    let idp = Idp::new(
        valid.name,
        input.idp_type,
        valid.url,
        valid.username,
        input.mfa,
    )?;
    settings.add_idp(idp);

    Ok(())
}

/// Adds an AWS IAM role app, or updates the one with the same url.
pub(crate) fn apply_aws_app(
    settings: &mut AppConfig,
    input: AwsAppInput,
) -> Result<(), SettingsEditError> {
    let valid = validate_aws(settings, &input, &AwsAppKind::Aws, security_key_supported())
        .map_err(SettingsEditError::InvalidFields)?;
    let host = AwsHost::new(valid.app_url, valid.username, valid.idp, input.mfa)?;
    settings.add_aws_host(host);

    Ok(())
}

/// Adds an AWS IAM Identity Center app, or updates the one with the same url.
pub(crate) fn apply_aws_sso_app(
    settings: &mut AppConfig,
    input: AwsAppInput,
    region: impl Into<String>,
) -> Result<(), SettingsEditError> {
    let kind = AwsAppKind::AwsSso {
        region: region.into(),
    };
    let valid = validate_aws(settings, &input, &kind, security_key_supported())
        .map_err(SettingsEditError::InvalidFields)?;
    let region = valid.region.unwrap_or_default();
    let host = AwsSsoHost::new(valid.app_url, valid.username, valid.idp, region, input.mfa)?;
    settings.add_aws_sso_host(host);

    Ok(())
}

/// Adds a Rancher, or updates the one with the same url.
pub(crate) fn apply_rancher(
    settings: &mut AppConfig,
    input: RancherInput,
) -> Result<(), SettingsEditError> {
    let valid = validate_rancher(settings, &input, security_key_supported())
        .map_err(SettingsEditError::InvalidFields)?;
    let host = RancherHost::new(
        valid.url,
        valid.client_id,
        valid.idp,
        valid.username,
        input.mfa,
    )?;
    settings.add_rancher_host(host);

    Ok(())
}

/// Adds an AWS app of either kind, or updates the one of that kind with the same url.
pub(crate) fn apply_aws_app_of_kind(
    settings: &mut AppConfig,
    input: AwsAppInput,
    kind: AwsAppKind,
) -> Result<(), SettingsEditError> {
    match kind {
        AwsAppKind::Aws => apply_aws_app(settings, input),
        AwsAppKind::AwsSso { region } => apply_aws_sso_app(settings, input, region),
    }
}

/// Replaces the AWS app at `old_url` of `old_type` with `input`, which may have another url or kind. The key of
/// an app is its url (and kind), so changing it is a removal and an addition. A new key that is another app's
/// is refused with `AlreadyExists`, and nothing changes.
pub(crate) fn apply_replace_aws_app(
    settings: &mut AppConfig,
    old_url: &str,
    old_type: AwsAppType,
    input: AwsAppInput,
    kind: AwsAppKind,
) -> Result<(), SettingsEditError> {
    let new_type = kind.app_type();
    // `has_aws_app` and `same_app_url` normalise the same way, so a tidy-up of the url (a slash, a query) is not a
    // change of key, while a url another entry has under its tidy form is a collision.
    let changes_key = !same_app_url(&input.app_url, old_url) || new_type != old_type;
    if changes_key && settings.has_aws_app(&input.app_url, new_type) {
        return Err(SettingsEditError::AlreadyExists { key: input.app_url });
    }
    apply_remove_aws_app(settings, old_url, old_type)?;
    apply_aws_app_of_kind(settings, input, kind)
}

/// Replaces the Rancher at `old_url` with `input`, which may have another url. A url that is another Rancher's
/// is refused with `AlreadyExists`, and nothing changes.
pub(crate) fn apply_replace_rancher(
    settings: &mut AppConfig,
    old_url: &str,
    input: RancherInput,
) -> Result<(), SettingsEditError> {
    if !same_app_url(&input.url, old_url) && settings.find_rancher_host(&input.url).is_some() {
        return Err(SettingsEditError::AlreadyExists { key: input.url });
    }
    apply_remove_rancher(settings, old_url)?;
    apply_rancher(settings, input)
}

/// Removes an identity provider no app logs in with.
pub(crate) fn apply_remove_idp(
    settings: &mut AppConfig,
    name: &str,
) -> Result<(), SettingsEditError> {
    if settings.find_idp(name).is_none() {
        return Err(SettingsError::UnknownIdp(name.to_string()).into());
    }
    let used_by = settings.apps_using_idp(name);
    if !used_by.is_empty() {
        return Err(SettingsEditError::IdpInUse {
            name: name.to_string(),
            used_by,
        });
    }

    settings.remove_idp(name);

    Ok(())
}

/// Removes the AWS app of `app_type` at `app_url`.
pub(crate) fn apply_remove_aws_app(
    settings: &mut AppConfig,
    app_url: &str,
    app_type: AwsAppType,
) -> Result<(), SettingsEditError> {
    let removed = match app_type {
        AwsAppType::Aws => settings.remove_aws_host(app_url),
        AwsAppType::AwsSso => settings.remove_aws_sso_host(app_url),
    };
    if !removed {
        return Err(SettingsEditError::UnknownApp(app_url.to_string()));
    }

    Ok(())
}

/// Removes the Rancher at `url`.
pub(crate) fn apply_remove_rancher(
    settings: &mut AppConfig,
    url: &str,
) -> Result<(), SettingsEditError> {
    if !settings.remove_rancher_host(url) {
        return Err(SettingsEditError::UnknownApp(url.to_string()));
    }

    Ok(())
}
