use super::sign_in::{SignInFields, SignInKeys};
use super::{DialogOutcome, FormContext, Saved};
use crate::app::FocusTarget;
use crate::ui::dialog::dialog;
use crate::ui::errors::{general_error, FormErrors};
use crate::ui::field::{submitted, text_field, TextOptions};
use c9s::app::settings::{
    same_url, AwsAppForm, AwsAppKey, AwsAppSummary, AwsAppType, Field, SettingsPage, SettingsView,
};
use eframe::egui::{Context, RichText};

const FIELDS: [Field; 5] = [
    Field::AwsAppUrl,
    Field::AwsRegion,
    Field::AwsIdp,
    Field::AwsUsername,
    Field::AwsMfa,
];

const SIGN_IN: SignInKeys = SignInKeys {
    idp: Field::AwsIdp,
    username: Field::AwsUsername,
    mfa: Field::AwsMfa,
};

pub struct AwsDialog {
    original: Option<AwsAppKey>,
    app_url: String,
    kind: AwsAppType,
    region: String,
    sign_in: SignInFields,
    first_frame: bool,
    errors: FormErrors,
}

impl AwsDialog {
    /// Adds a new AWS application.
    pub fn add(form: &FormContext) -> Self {
        Self {
            original: None,
            app_url: String::new(),
            kind: AwsAppType::Aws,
            region: String::new(),
            sign_in: SignInFields::new(SIGN_IN, form),
            first_frame: true,
            errors: FormErrors::default(),
        }
    }

    /// Edits an existing AWS application.
    pub fn edit(app: &AwsAppSummary, form: &FormContext) -> Self {
        Self {
            original: Some(AwsAppKey {
                app_url: app.app_url.clone(),
                kind: app.kind,
            }),
            app_url: app.app_url.clone(),
            kind: app.kind,
            region: app.region.clone().unwrap_or_default(),
            sign_in: SignInFields::new(SIGN_IN, form).with(
                app.idp.clone(),
                app.username.clone(),
                app.mfa,
            ),
            ..Self::add(form)
        }
    }

    /// Takes the changes and generates a `Saved` result.
    pub fn submit(&mut self, page: &SettingsPage) -> Result<Saved, String> {
        let form = self.form();

        match page.save_aws_app(form.clone()) {
            Ok(view) => {
                let focus = saved_entry(&view, form.kind, &form.app_url);
                Ok(Saved {
                    view,
                    message: "AWS account saved.".to_string(),
                    focus,
                })
            }
            Err(error) => Err(self.errors.fail(error, &FIELDS)),
        }
    }

    pub fn ui(&mut self, ctx: &Context) -> DialogOutcome {
        let title = if self.original.is_some() {
            "Edit AWS account"
        } else {
            "Add AWS account"
        };

        let first = std::mem::take(&mut self.first_frame);

        dialog(ctx, "aws", title, "Save", |ui| {
            ui.label("This is the AWS tile in your identity provider.");
            ui.add_space(8.0);

            let input = text_field(
                ui,
                &mut self.errors,
                Field::AwsAppUrl,
                "Web address of the application",
                &mut self.app_url,
                TextOptions {
                    hint: Some("Copy it from the application in your identity provider."),
                    autofocus: first,
                    ..Default::default()
                },
            );

            let mut entered = submitted(&input);

            ui.label(RichText::new("Type of application").strong());

            // radio value for kind
            ui.radio_value(&mut self.kind, AwsAppType::Aws, "AWS with IAM roles");
            ui.radio_value(
                &mut self.kind,
                AwsAppType::AwsSso,
                "AWS IAM Identity Center",
            );

            ui.add_space(8.0);

            // if the radio is AwsSso, get the region
            if self.kind == AwsAppType::AwsSso {
                let input = text_field(
                    ui,
                    &mut self.errors,
                    Field::AwsRegion,
                    "AWS region of Identity Center",
                    &mut self.region,
                    TextOptions {
                        hint: Some("For example eu-west-1."),
                        ..Default::default()
                    },
                );
                entered |= submitted(&input);
            }

            entered |= self.sign_in.ui(ui, &mut self.errors);
            general_error(ui, &self.errors);
            entered
        })
    }

    /// Generates the form from the result.
    fn form(&self) -> AwsAppForm {
        AwsAppForm {
            original: self.original.clone(),
            app_url: self.app_url.trim().to_string(),
            kind: self.kind,
            region: (self.kind == AwsAppType::AwsSso).then(|| self.region.trim().to_string()),
            idp: self.sign_in.idp.clone(),
            username: self.sign_in.username(),
            mfa: self.sign_in.mfa,
        }
    }
}

/// Gets the AWS widget that was saved to take a focus.
fn saved_entry(view: &SettingsView, kind: AwsAppType, app_url: &str) -> Option<FocusTarget> {
    view.aws_apps
        .iter()
        .find(|a| a.kind == kind && same_url(&a.app_url, app_url))
        .map(|a| {
            FocusTarget::AwsApp(AwsAppKey {
                app_url: a.app_url.clone(),
                kind: a.kind,
            })
        })
}

#[cfg(test)]
impl AwsDialog {
    pub fn type_into(&mut self, app_url: &str) {
        self.app_url = app_url.into();
    }
}
