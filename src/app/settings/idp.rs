use super::errors::{with_mfa, Form};
use super::models::{Field, IdpForm, SettingsView, SetupError};
use super::{mfa_selection, SettingsPage};
use crate::domain::models::idp::IdpType;
use crate::domain::services::settings_editor::{IdpInput, SaveAs};

impl SettingsPage {
    /// Adds or edits an IDP.
    pub fn save_idp(&self, form: IdpForm) -> Result<SettingsView, SetupError> {
        let mfa = mfa_selection(form.mfa);
        let mut input = IdpInput::new(form.name, IdpType::Authentik, form.url, form.username);
        let mode = if form.editing {
            SaveAs::Replace(())
        } else {
            SaveAs::New
        };

        match mfa {
            Ok(mfa) => {
                input.mfa = mfa;
                self.run(Form::Idp, |s| s.save_idp(input, mode))
            }
            Err(message) => Err(with_mfa(
                Form::Idp,
                Field::IdpMfa,
                message,
                self.settings.check_idp(&input),
            )),
        }
    }

    pub fn remove_idp(&self, name: &str) -> Result<SettingsView, SetupError> {
        self.run(Form::Action, |s| s.remove_idp(name))
    }
}
