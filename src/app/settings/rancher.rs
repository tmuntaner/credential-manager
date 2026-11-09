use super::errors::{with_mfa, Form};
use super::models::{Field, RancherForm, SettingsView, SetupError};
use super::{mfa_override, SettingsPage};
use crate::domain::services::settings_editor::{RancherInput, SaveAs};

impl SettingsPage {
    /// Adds or edits a rancher application.
    pub fn save_rancher(&self, form: RancherForm) -> Result<SettingsView, SetupError> {
        let mfa = mfa_override(form.mfa);
        let mut input = RancherInput::new(form.url, form.client_id, form.idp);
        input.username = form.username;
        let mode = match form.original_url {
            Some(old) => SaveAs::Replace(old),
            None => SaveAs::New,
        };

        match mfa {
            Ok(mfa) => {
                input.mfa = mfa;
                self.run(Form::Rancher, |s| s.save_rancher(input, mode))
            }
            Err(message) => Err(with_mfa(
                Form::Rancher,
                Field::RancherMfa,
                message,
                self.settings.check_rancher(&input),
            )),
        }
    }

    pub fn remove_rancher(&self, url: &str) -> Result<SettingsView, SetupError> {
        self.run(Form::Action, |s| s.remove_rancher(url))
    }
}
