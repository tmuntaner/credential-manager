use super::errors::Form;
use super::models::{AwsAppForm, AwsAppKey, MfaChoice, SettingsView, SetupError};
use super::SettingsPage;
use crate::domain::models::settings::AwsAppType;
use crate::domain::services::settings_editor::{AwsAppInput, AwsAppKind, SaveAs};

impl SettingsPage {
    /// Adds or edits an AWS app.
    pub fn save_aws_app(&self, form: AwsAppForm) -> Result<SettingsView, SetupError> {
        let mut input = AwsAppInput::new(form.app_url, form.idp);
        input.username = form.username;
        input.mfa = form.mfa.and_then(MfaChoice::selection);

        let kind = match form.kind {
            AwsAppType::Aws => AwsAppKind::Aws,
            AwsAppType::AwsSso => AwsAppKind::AwsSso {
                region: form.region.unwrap_or_default(),
            },
        };

        let mode = match form.original {
            Some(key) => SaveAs::Replace((key.app_url, key.kind)),
            None => SaveAs::New,
        };

        self.run(Form::AWS, |s| s.save_aws_app(input, kind, mode))
    }

    pub fn remove_aws_app(&self, key: AwsAppKey) -> Result<SettingsView, SetupError> {
        self.run(Form::ACTION, |s| s.remove_aws_app(&key.app_url, key.kind))
    }
}
