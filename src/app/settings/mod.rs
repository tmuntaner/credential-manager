//! The settings page: identity providers, AWS apps and Ranchers, each listed, added, changed and removed on its
//! own. Every change goes through the same service as `c9s config ...`.
//!
//! The page only checks the form and shows what went wrong under the right field. [`SettingsService`] decides
//! whether a change is written: always (there is no mode), and only when what it sets up resolves a login the way
//! the CLI would (a dry run on a copy), and when nothing that resolved before stops resolving.
//!
//! A driving adapter (the egui window) brings its own screens and calls this page.

mod aws;
mod errors;
mod idp;
mod models;
mod rancher;
mod security_key;
#[cfg(test)]
mod tests;
mod transfer;

pub use models::{
    same_url, AwsAppForm, AwsAppKey, AwsAppKind, AwsAppSummary, Checklist, Field, FieldError,
    IdpForm, IdpSummary, MfaChoice, RancherForm, RancherSummary, SettingsView, SetupError,
};

use crate::domain::models::mfa::MfaSelection;
use crate::domain::models::settings::YubikeyConfig;
use crate::domain::ports::notifier::Notifier;
use crate::domain::ports::user_interaction::UserInteraction;
use crate::domain::services::settings_editor::SettingsService;
use crate::domain::services::settings_validation::check_name;
use errors::{edit_error, Form};
use std::sync::Arc;

pub use security_key::{enroll_security_key, DEFAULT_RP_ID};
pub use transfer::{export_text, import_text, usernames_needed, ExportChoice, TransferError};

/// Whether security keys can be used on this machine.
const SECURITY_KEY_SUPPORTED: bool = cfg!(any(target_os = "linux", target_os = "macos"));

pub struct SettingsPage {
    settings: SettingsService,
}

impl SettingsPage {
    pub fn new(store: SettingsService) -> Self {
        Self { settings: store }
    }

    pub fn view(&self) -> Result<SettingsView, SetupError> {
        let settings = self
            .settings
            .load()
            .map_err(|e| edit_error(e, Form::Action))?;

        Ok(settings.into())
    }

    pub fn set_use_keyring(&self, enabled: bool) -> Result<SettingsView, SetupError> {
        let settings = self
            .settings
            .set_use_keyring(enabled)
            .map_err(|e| edit_error(e, Form::Action))?;

        Ok(settings.into())
    }
}

impl SettingsPage {
    /// Chooses whether issued credentials (AWS/Rancher) are encrypted with the security key.
    pub fn set_wrap_cached(&self, enabled: bool) -> Result<SettingsView, SetupError> {
        let settings = self
            .settings
            .set_wrap_cached_secrets(enabled)
            .map_err(|e| edit_error(e, Form::Action))?;

        Ok(settings.into())
    }

    /// Saves the enrolled security key, or `None` to stop using it.
    pub fn set_security_key(&self, key: Option<YubikeyConfig>) -> Result<SettingsView, SetupError> {
        let settings = self
            .settings
            .set_yubikey(key)
            .map_err(|e| edit_error(e, Form::Action))?;

        Ok(settings.into())
    }

    /// Enrolls a security key for `rp_id` and saves it.
    pub async fn enroll_security_key<U: UserInteraction + 'static, N: Notifier + 'static>(
        &self,
        rp_id: &str,
        interaction: Arc<U>,
        notifier: Arc<N>,
    ) -> Result<SettingsView, SetupError> {
        let key = enroll_security_key(rp_id, interaction, notifier).await?;
        self.set_security_key(Some(key))
    }
}

/// Every app logs in through an identity provider, so one has to be chosen.
fn check_idp(input: &str) -> Result<String, String> {
    match input.trim() {
        "" => Err("Choose an identity provider.".into()),
        name => check_name(name),
    }
}

fn mfa_selection(choice: MfaChoice) -> Result<Option<MfaSelection>, String> {
    match (choice, SECURITY_KEY_SUPPORTED) {
        (MfaChoice::Ask, _) => Ok(None),
        (MfaChoice::Totp, _) => Ok(Some(MfaSelection::Totp)),
        (MfaChoice::SecurityKey, true) => Ok(Some(MfaSelection::WebAuthn)),
        (MfaChoice::SecurityKey, false) => Err(
            "Security keys are not supported on this computer yet. Choose the authenticator app code."
                .into(),
        ),
    }
}

/// `None` (and "ask") keeps the choice of the identity provider.
fn mfa_override(choice: Option<MfaChoice>) -> Result<Option<MfaSelection>, String> {
    choice.map_or(Ok(None), mfa_selection)
}
