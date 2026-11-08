use super::errors::{edit_error, Errors, Form};
use super::models::{AwsAppForm, AwsAppKey, AwsAppKind, Field, SettingsView, SetupError};
use super::{check_idp, mfa_override, SettingsPage};
use crate::domain::services::settings_editor::{self, AwsAppInput, SaveAs};
use crate::domain::services::settings_validation::{
    allow_insecure_localhost, check_optional_username, check_region, check_url,
};

impl SettingsPage {
    /// Adds or edits an AWS app.
    pub fn save_aws_app(&self, form: AwsAppForm) -> Result<SettingsView, SetupError> {
        let mut errors = Errors::default();

        // try to get the AWS app URL
        let app_url = errors.keep(
            Field::AwsAppUrl,
            check_url(&form.app_url, allow_insecure_localhost()),
        );

        // try to figure out what kind of AWS application we're dealing with.
        let kind = match form.kind {
            AwsAppKind::Aws => Some(settings_editor::AwsAppKind::Aws),
            AwsAppKind::AwsSso => errors
                // first get the region
                .keep(
                    Field::AwsRegion,
                    check_region(form.region.as_deref().unwrap_or("")),
                )
                // build an AwsSso kind, which needs the region
                .map(|region| settings_editor::AwsAppKind::AwsSso { region }),
        };

        let username = errors.keep(
            Field::AwsUsername,
            check_optional_username(form.username.as_deref()),
        );
        let mfa = errors.keep(Field::AwsMfa, mfa_override(form.mfa));
        let idp = errors.keep(Field::AwsIdp, check_idp(&form.idp));

        // if there are any errors yet, return with an Error
        errors.into_result()?;

        let (Some(app_url), Some(kind), Some(username), Some(mfa), Some(idp)) =
            (app_url, kind, username, mfa, idp)
        else {
            unreachable!("every field is valid");
        };

        let mut input = AwsAppInput::new(app_url, idp);
        input.username = username;
        input.mfa = mfa;
        let mode = match form.original {
            Some(key) => SaveAs::Replace((key.app_url, key.kind.into())),
            None => SaveAs::New,
        };

        let settings = self
            .settings
            .save_aws_app(input, kind, mode)
            .map_err(|e| edit_error(e, Form::Aws))?;

        Ok(settings.into())
    }

    pub fn remove_aws_app(&self, key: AwsAppKey) -> Result<SettingsView, SetupError> {
        let settings = self
            .settings
            .remove_aws_app(&key.app_url, key.kind.into())
            .map_err(|e| edit_error(e, Form::Action))?;

        Ok(settings.into())
    }
}
