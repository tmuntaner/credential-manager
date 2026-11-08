use super::errors::{edit_error, Errors, Form};
use super::models::{Field, RancherForm, SettingsView, SetupError};
use super::{check_idp, mfa_override, SettingsPage};
use crate::domain::services::settings_editor::{RancherInput, SaveAs};
use crate::domain::services::settings_validation::{
    allow_insecure_localhost, check_client_id, check_optional_username, check_url,
};

impl SettingsPage {
    /// Adds or edits a rancher application.
    pub fn save_rancher(&self, form: RancherForm) -> Result<SettingsView, SetupError> {
        let mut errors = Errors::default();
        let url = errors.keep(
            Field::RancherUrl,
            check_url(&form.url, allow_insecure_localhost()),
        );
        let client_id = errors.keep(Field::RancherClientId, check_client_id(&form.client_id));
        let username = errors.keep(
            Field::RancherUsername,
            check_optional_username(form.username.as_deref()),
        );
        let mfa = errors.keep(Field::RancherMfa, mfa_override(form.mfa));
        let idp = errors.keep(Field::RancherIdp, check_idp(&form.idp));
        errors.into_result()?;
        let (Some(url), Some(client_id), Some(username), Some(mfa), Some(idp)) =
            (url, client_id, username, mfa, idp)
        else {
            unreachable!("every field is valid");
        };

        let mut input = RancherInput::new(url, client_id, idp);
        input.username = username;
        input.mfa = mfa;
        let mode = match form.original_url {
            Some(old) => SaveAs::Replace(old),
            None => SaveAs::New,
        };

        let settings = self
            .settings
            .save_rancher(input, mode)
            .map_err(|e| edit_error(e, Form::Rancher))?;

        Ok(settings.into())
    }

    pub fn remove_rancher(&self, url: &str) -> Result<SettingsView, SetupError> {
        let settings = self
            .settings
            .remove_rancher(url)
            .map_err(|e| edit_error(e, Form::Action))?;

        Ok(settings.into())
    }
}
