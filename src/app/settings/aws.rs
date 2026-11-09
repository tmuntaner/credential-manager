use super::errors::{with_mfa, Form};
use super::models::{AwsAppForm, AwsAppKey, Field, SettingsView, SetupError};
use super::{mfa_override, SettingsPage};
use crate::domain::models::settings::AwsAppType;
use crate::domain::services::settings_editor::{self, AwsAppInput, SaveAs};

impl SettingsPage {
    /// Adds or edits an AWS app.
    pub fn save_aws_app(&self, form: AwsAppForm) -> Result<SettingsView, SetupError> {
        let mfa = mfa_override(form.mfa);

        let mut input = AwsAppInput::new(form.app_url, form.idp);
        input.username = form.username;

        let kind = match form.kind {
            AwsAppType::Aws => settings_editor::AwsAppKind::Aws,
            AwsAppType::AwsSso => settings_editor::AwsAppKind::AwsSso {
                region: form.region.unwrap_or_default(),
            },
        };

        let mode = match form.original {
            Some(key) => SaveAs::Replace((key.app_url, key.kind)),
            None => SaveAs::New,
        };

        match mfa {
            Ok(mfa) => {
                input.mfa = mfa;
                self.run(Form::Aws, |s| s.save_aws_app(input, kind, mode))
            }
            Err(message) => Err(with_mfa(
                Form::Aws,
                Field::AwsMfa,
                message,
                self.settings.check_aws_app(&input, &kind),
            )),
        }
    }

    pub fn remove_aws_app(&self, key: AwsAppKey) -> Result<SettingsView, SetupError> {
        self.run(Form::Action, |s| s.remove_aws_app(&key.app_url, key.kind))
    }
}
