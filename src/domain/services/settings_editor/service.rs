use super::apply::*;
use super::error::SettingsEditError;
use super::input::{AwsAppInput, AwsAppKind, AwsAppRef, IdpInput, RancherInput, SaveAs};
use crate::domain::models::login::LoginTarget;
use crate::domain::models::settings::{AppConfig, AwsAppType, YubikeyConfig};
use crate::domain::ports::config::ConfigStore;
use crate::domain::ports::login_check::LoginCheck;
use crate::domain::services::settings_check::{verify, ResolvingLoginCheck};
use std::sync::Arc;

/// Checks the existence rule of a save once, for every kind: `New` refuses a taken key, `Replace` refuses an old
/// key that is gone, `Upsert` refuses neither.
pub(super) fn check_mode<K>(
    mode: &SaveAs<K>,
    key: &str,
    new_key_taken: bool,
    old_exists: impl FnOnce(&K) -> bool,
) -> Result<(), SettingsEditError> {
    match mode {
        SaveAs::Upsert => Ok(()),
        SaveAs::New if new_key_taken => Err(SettingsEditError::AlreadyExists {
            key: key.to_string(),
        }),
        SaveAs::New => Ok(()),
        SaveAs::Replace(old) if !old_exists(old) => Err(SettingsEditError::Gone),
        SaveAs::Replace(_) => Ok(()),
    }
}

/// Edits the settings kept in a [`ConfigStore`]: every change is loaded, applied, login-checked and saved here,
/// and nothing is saved when a change is refused.
///
/// A change to the apps (the `save_*`, `remove_*` and `import` methods) is refused when what it sets up does not
/// resolve a login, or when it stops an app that resolved before from resolving. The check is the [`LoginCheck`]
/// port; [`SettingsService::new`] resolves the way the CLI would.
///
/// Concurrent writers are last-write-wins: the whole file is rewritten from what this process loaded. The file
/// store replaces the file atomically, so a reader never sees a half written file, but two programs saving at
/// the same moment can lose one change.
#[derive(Clone)]
pub struct SettingsService<C: LoginCheck = ResolvingLoginCheck> {
    pub(super) store: Arc<dyn ConfigStore + Send + Sync>,
    check: C,
}

impl SettingsService<ResolvingLoginCheck> {
    pub fn new(store: Arc<dyn ConfigStore + Send + Sync>) -> Self {
        Self::with_login_check(store, ResolvingLoginCheck)
    }
}

impl<C: LoginCheck> SettingsService<C> {
    pub fn with_login_check(store: Arc<dyn ConfigStore + Send + Sync>, check: C) -> Self {
        Self { store, check }
    }

    /// The settings as stored. Never saves.
    pub fn load(&self) -> Result<AppConfig, SettingsEditError> {
        Ok(self.store.load()?)
    }

    /// Loads the settings, applies `change` and saves the result, which is returned. No login check: for the
    /// global settings. Nothing is saved when `change` fails.
    pub fn update(
        &self,
        change: impl FnOnce(&mut AppConfig) -> Result<(), SettingsEditError>,
    ) -> Result<AppConfig, SettingsEditError> {
        let mut config = self.store.load()?;
        change(&mut config)?;
        self.store.save(&config)?;

        Ok(config)
    }

    /// Loads the settings, applies `change` (which gets the settings before, the ones to change, and returns the
    /// apps it set up), checks the logins and saves. Nothing is saved when anything fails.
    pub(super) fn edit(
        &self,
        change: impl FnOnce(&AppConfig, &mut AppConfig) -> Result<Vec<LoginTarget>, SettingsEditError>,
    ) -> Result<AppConfig, SettingsEditError> {
        let before = self.store.load()?;
        let mut config = before.clone();
        let touched = change(&before, &mut config)?;
        verify(&self.check, &before, &config, &touched)?;
        self.store.save(&config)?;

        Ok(config)
    }

    /// Adds an identity provider, or updates the one with the same name.
    pub fn save_idp(
        &self,
        input: IdpInput,
        mode: SaveAs<()>,
    ) -> Result<AppConfig, SettingsEditError> {
        self.edit(|before, config| {
            let taken = before.find_idp(&input.name).is_some();
            check_mode(&mode, &input.name, taken, |_| taken)?;
            apply_idp(config, input)?;

            Ok(vec![])
        })
    }

    pub fn remove_idp(&self, name: &str) -> Result<AppConfig, SettingsEditError> {
        self.edit(|_, config| {
            apply_remove_idp(config, name)?;

            Ok(vec![])
        })
    }

    /// Adds an AWS app of either kind, or replaces one (its url and kind may change).
    pub fn save_aws_app(
        &self,
        input: AwsAppInput,
        kind: AwsAppKind,
        mode: SaveAs<AwsAppRef>,
    ) -> Result<AppConfig, SettingsEditError> {
        let app_type = kind.app_type();
        let url = input.app_url.clone();
        self.edit(|before, config| {
            let taken = before.has_aws_app(&url, app_type);
            check_mode(&mode, &url, taken, |(old_url, old_type)| {
                before.has_aws_app(old_url, *old_type)
            })?;
            match &mode {
                SaveAs::Replace((old_url, old_type)) => {
                    apply_replace_aws_app(config, old_url, *old_type, input, kind)?
                }
                SaveAs::Upsert | SaveAs::New => apply_aws_app_of_kind(config, input, kind)?,
            }

            Ok(vec![LoginTarget::Aws {
                app_url: url,
                app_type,
            }])
        })
    }

    pub fn remove_aws_app(
        &self,
        app_url: &str,
        app_type: AwsAppType,
    ) -> Result<AppConfig, SettingsEditError> {
        self.edit(|_, config| {
            apply_remove_aws_app(config, app_url, app_type)?;

            Ok(vec![])
        })
    }

    /// Adds a Rancher, or replaces one (its url may change).
    pub fn save_rancher(
        &self,
        input: RancherInput,
        mode: SaveAs<String>,
    ) -> Result<AppConfig, SettingsEditError> {
        let url = input.url.clone();
        self.edit(|before, config| {
            let taken = before.find_rancher_host(&url).is_some();
            check_mode(&mode, &url, taken, |old_url| {
                before.find_rancher_host(old_url).is_some()
            })?;
            match &mode {
                SaveAs::Replace(old_url) => apply_replace_rancher(config, old_url, input)?,
                SaveAs::Upsert | SaveAs::New => apply_rancher(config, input)?,
            }

            Ok(vec![LoginTarget::Rancher { url }])
        })
    }

    pub fn remove_rancher(&self, url: &str) -> Result<AppConfig, SettingsEditError> {
        self.edit(|_, config| {
            apply_remove_rancher(config, url)?;

            Ok(vec![])
        })
    }

    pub fn set_use_keyring(&self, enabled: bool) -> Result<AppConfig, SettingsEditError> {
        self.update(|config| {
            config.set_use_keyring(enabled);
            Ok(())
        })
    }

    /// Sets the YubiKey that wraps secrets, or `None` to stop wrapping.
    pub fn set_yubikey(
        &self,
        yubikey: Option<YubikeyConfig>,
    ) -> Result<AppConfig, SettingsEditError> {
        self.update(|config| {
            config.set_yubikey(yubikey);
            Ok(())
        })
    }

    pub fn set_wrap_cached_secrets(&self, enabled: bool) -> Result<AppConfig, SettingsEditError> {
        self.update(|config| {
            config.set_wrap_cached_secrets(enabled);
            Ok(())
        })
    }
}
