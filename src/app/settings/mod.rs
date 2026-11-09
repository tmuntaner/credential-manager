//! The settings page: identity providers, AWS apps and Ranchers, each listed, added, changed and removed on its
//! own. Every change goes through the same service as `c9s config ...`.
//!
//! The page only translates form state and shows what went wrong under the right field; it validates nothing itself. [`SettingsService`] decides
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
use crate::domain::models::settings::{AppConfig, YubikeyConfig};
use crate::domain::ports::notifier::Notifier;
use crate::domain::ports::user_interaction::UserInteraction;
use crate::domain::services::settings_editor::{SettingsEditError, SettingsService};
use errors::{edit_error, Form};
use std::sync::Arc;

pub use security_key::{
    enroll_and_save, enroll_security_key, DEFAULT_RP_ID, SECURITY_KEY_SUPPORTED,
};
pub use transfer::{
    check_import_username, describe_import, export_bundle, plan_import, ExportChoice, ImportPlan,
    TransferError,
};

pub struct SettingsPage {
    settings: SettingsService,
}

impl SettingsPage {
    pub fn new(store: SettingsService) -> Self {
        Self { settings: store }
    }

    pub fn view(&self) -> Result<SettingsView, SetupError> {
        self.run(Form::Action, |s| s.load())
    }

    /// Runs one change of the service, and tells the form what went wrong.
    fn run(
        &self,
        form: Form,
        op: impl FnOnce(&SettingsService) -> Result<AppConfig, SettingsEditError>,
    ) -> Result<SettingsView, SetupError> {
        op(&self.settings)
            .map(Into::into)
            .map_err(|e| edit_error(e, form))
    }

    pub fn set_use_keyring(&self, enabled: bool) -> Result<SettingsView, SetupError> {
        self.run(Form::Action, |s| s.set_use_keyring(enabled))
    }
}

impl SettingsPage {
    /// Chooses whether issued credentials (AWS/Rancher) are encrypted with the security key.
    pub fn set_wrap_cached(&self, enabled: bool) -> Result<SettingsView, SetupError> {
        self.run(Form::Action, |s| s.set_wrap_cached_secrets(enabled))
    }

    /// Saves the enrolled security key, or `None` to stop using it.
    pub fn set_security_key(&self, key: Option<YubikeyConfig>) -> Result<SettingsView, SetupError> {
        self.run(Form::Action, |s| s.set_yubikey(key))
    }

    /// Enrolls a security key for `rp_id` and saves it.
    pub async fn enroll_security_key<U: UserInteraction + 'static, N: Notifier + 'static>(
        &self,
        rp_id: &str,
        interaction: Arc<U>,
        notifier: Arc<N>,
    ) -> Result<SettingsView, SetupError> {
        enroll_and_save(&self.settings, rp_id, interaction, notifier)
            .await
            .map(Into::into)
    }
}

fn mfa_selection(choice: MfaChoice) -> Result<Option<MfaSelection>, String> {
    mfa_selection_on(choice, SECURITY_KEY_SUPPORTED)
}

fn mfa_selection_on(choice: MfaChoice, supported: bool) -> Result<Option<MfaSelection>, String> {
    match (choice, supported) {
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
