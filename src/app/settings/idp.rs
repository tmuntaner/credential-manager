use super::errors::Form;
use super::models::{IdpForm, SettingsView, SetupError};
use super::SettingsPage;
use crate::domain::models::idp::IdpType;
use crate::domain::services::settings_editor::{IdpInput, SaveAs};

impl SettingsPage {
    /// Adds or edits an IDP.
    pub fn save_idp(&self, form: IdpForm) -> Result<SettingsView, SetupError> {
        let mut input = IdpInput::new(form.name, IdpType::Authentik, form.url, form.username);
        input.mfa = form.mfa.selection();
        let mode = if form.editing {
            SaveAs::Replace(())
        } else {
            SaveAs::New
        };

        self.run(Form::IDP, |s| s.save_idp(input, mode))
    }

    pub fn remove_idp(&self, name: &str) -> Result<SettingsView, SetupError> {
        self.run(Form::ACTION, |s| s.remove_idp(name))
    }
}
