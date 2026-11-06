use super::errors::{edit_error, Errors, Form};
use super::models::{Field, IdpForm, SettingsView, SetupError};
use super::summary::summarize;
use super::{mfa_selection, SettingsPage};
use crate::domain::models::idp::IdpType;
use crate::domain::ports::config::ConfigStore;
use crate::domain::services::settings_editor::{IdpInput, SaveAs};
use crate::domain::services::settings_validation::{
    allow_insecure_localhost, check_name, check_url, check_username,
};

impl<S: ConfigStore> SettingsPage<S> {
    /// Adds or edits an IDP.
    pub fn save_idp(&self, form: IdpForm) -> Result<SettingsView, SetupError> {
        let mut errors = Errors::default();

        let name = errors.keep(Field::IdpName, check_name(&form.name));
        let url = errors.keep(
            Field::IdpUrl,
            check_url(&form.url, allow_insecure_localhost()),
        );
        let username = errors.keep(Field::IdpUsername, check_username(&form.username));
        let mfa = errors.keep(Field::IdpMfa, mfa_selection(form.mfa));

        errors.into_result()?;

        let (Some(name), Some(url), Some(username), Some(mfa)) = (name, url, username, mfa) else {
            unreachable!("every field is valid");
        };

        let mut input = IdpInput::new(name, IdpType::Authentik, url, username);
        input.mfa = mfa;
        let mode = if form.editing {
            SaveAs::Replace(())
        } else {
            SaveAs::New
        };

        let settings = self
            .settings
            .save_idp(input, mode)
            .map_err(|e| edit_error(e, Form::Idp))?;

        Ok(summarize(&settings))
    }

    pub fn remove_idp(&self, name: &str) -> Result<SettingsView, SetupError> {
        let settings = self
            .settings
            .remove_idp(name)
            .map_err(|e| edit_error(e, Form::Action))?;

        Ok(summarize(&settings))
    }
}
