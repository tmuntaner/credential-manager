use super::errors::Form;
use super::models::{MfaChoice, RancherForm, SettingsView, SetupError};
use super::SettingsPage;
use crate::domain::services::settings_editor::{RancherInput, SaveAs};

impl SettingsPage {
    /// Adds or edits a rancher application.
    pub fn save_rancher(&self, form: RancherForm) -> Result<SettingsView, SetupError> {
        let mut input = RancherInput::new(form.url, form.client_id, form.idp);
        input.username = form.username;
        input.mfa = form.mfa.and_then(MfaChoice::selection);
        let mode = match form.original_url {
            Some(old) => SaveAs::Replace(old),
            None => SaveAs::New,
        };

        self.run(Form::RANCHER, |s| s.save_rancher(input, mode))
    }

    pub fn remove_rancher(&self, url: &str) -> Result<SettingsView, SetupError> {
        self.run(Form::ACTION, |s| s.remove_rancher(url))
    }
}
