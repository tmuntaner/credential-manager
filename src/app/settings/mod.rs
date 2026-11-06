//! The settings page: identity providers, AWS apps and Ranchers, each listed, added, changed and removed on its
//! own. Every change goes through the same service as `c9s config ...`.
//!
//! The page only checks the form and shows what went wrong under the right field. [`SettingsService`] decides
//! whether a change is written: only when what it sets up resolves a login the way the CLI would (a dry run on a
//! copy), and when nothing that resolved before stops resolving.
//!
//! A driving adapter (the egui window) brings its own screens and calls this page.

mod aws;
mod errors;
mod idp;
mod models;
mod rancher;
mod summary;
#[cfg(test)]
mod tests;

pub use models::{
    same_url, AwsAppForm, AwsAppKey, AwsAppKind, AwsAppSummary, Checklist, Field, FieldError,
    IdpForm, IdpSummary, MfaChoice, RancherForm, RancherSummary, SettingsView, SetupError,
};

use crate::domain::models::mfa::MfaSelection;
use crate::domain::ports::config::ConfigStore;
use crate::domain::services::settings_editor::SettingsService;
use crate::domain::services::settings_validation::check_name;
use errors::{edit_error, Form};
use summary::summarize;

/// Whether security keys can be used on this machine.
const SECURITY_KEY_SUPPORTED: bool = cfg!(any(target_os = "linux", target_os = "macos"));

pub struct SettingsPage<S: ConfigStore> {
    settings: SettingsService<S>,
}

impl<S: ConfigStore> SettingsPage<S> {
    pub fn new(store: S) -> Self {
        Self {
            settings: SettingsService::new(store).with_login_checks(),
        }
    }

    pub fn view(&self) -> Result<SettingsView, SetupError> {
        let settings = self
            .settings
            .load()
            .map_err(|e| edit_error(e, Form::Action))?;

        Ok(summarize(&settings))
    }

    pub fn set_use_keyring(&self, enabled: bool) -> Result<SettingsView, SetupError> {
        let settings = self
            .settings
            .set_use_keyring(enabled)
            .map_err(|e| edit_error(e, Form::Action))?;

        Ok(summarize(&settings))
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
