use super::{DialogOutcome, FormContext, Saved};
use crate::app::FocusTarget;
use crate::ui::dialog::dialog;
use crate::ui::errors::{general_error, FormErrors};
use crate::ui::field::{fixed_field, submitted, text_field, TextOptions};
use crate::ui::select::{mfa_options, select};
use c9s::app::settings::{Field, IdpForm, IdpSummary, MfaChoice, SettingsPage};
use c9s::domain::ports::config::ConfigStore;
use eframe::egui::Context;

const FIELDS: [Field; 4] = [
    Field::IdpName,
    Field::IdpUrl,
    Field::IdpUsername,
    Field::IdpMfa,
];

pub struct IdpDialog {
    editing: bool,
    name: String,
    url: String,
    username: String,
    mfa: MfaChoice,
    security_key: bool,
    first_frame: bool,
    errors: FormErrors,
}

impl IdpDialog {
    pub fn add(form: &FormContext) -> Self {
        Self {
            editing: false,
            name: String::new(),
            url: String::new(),
            username: String::new(),
            mfa: MfaChoice::Ask,
            security_key: form.security_key,
            first_frame: true,
            errors: FormErrors::default(),
        }
    }

    pub fn edit(idp: &IdpSummary, form: &FormContext) -> Self {
        Self {
            editing: true,
            name: idp.name.clone(),
            url: idp.url.clone(),
            username: idp.username.clone(),
            // A choice this computer cannot offer falls back to asking.
            mfa: match idp.mfa {
                MfaChoice::SecurityKey if !form.security_key => MfaChoice::Ask,
                mfa => mfa,
            },
            ..Self::add(form)
        }
    }

    fn form(&self) -> IdpForm {
        IdpForm {
            editing: self.editing,
            name: self.name.trim().to_string(),
            url: self.url.trim().to_string(),
            username: self.username.trim().to_string(),
            mfa: self.mfa,
        }
    }

    pub fn submit<S: ConfigStore>(&mut self, page: &SettingsPage<S>) -> Result<Saved, String> {
        let name = self.name.trim().to_string();
        match page.save_idp(self.form()) {
            Ok(view) => Ok(Saved {
                view,
                message: format!("Identity provider {name} saved."),
                focus: Some(FocusTarget::Idp(name)),
            }),
            Err(error) => Err(self.errors.fail(error, &FIELDS)),
        }
    }

    pub fn ui(&mut self, ctx: &Context) -> DialogOutcome {
        let title = if self.editing {
            format!("Edit {}", self.name)
        } else {
            "Add identity provider".to_string()
        };
        let first = std::mem::take(&mut self.first_frame);

        dialog(ctx, "idp", &title, "Save", |ui| {
            ui.label("This is the service you sign in with.");
            ui.add_space(8.0);

            let mut entered = false;
            if self.editing {
                fixed_field(
                    ui,
                    "Name",
                    &self.name,
                    "The name cannot be changed. To rename, add a new one and remove this one.",
                );
            } else {
                let input = text_field(
                    ui,
                    &mut self.errors,
                    Field::IdpName,
                    "Name",
                    &mut self.name,
                    TextOptions {
                        hint: Some("A short name so you can recognise it, like work."),
                        autofocus: first,
                        ..Default::default()
                    },
                );
                entered |= submitted(&input);
            }

            let input = text_field(
                ui,
                &mut self.errors,
                Field::IdpUrl,
                "Web address",
                &mut self.url,
                TextOptions {
                    hint: Some("Starts with https://"),
                    placeholder: Some("https://id.example.com"),
                    autofocus: first && self.editing,
                    ..Default::default()
                },
            );
            entered |= submitted(&input);

            let input = text_field(
                ui,
                &mut self.errors,
                Field::IdpUsername,
                "User name",
                &mut self.username,
                TextOptions::default(),
            );
            entered |= submitted(&input);

            select(
                ui,
                &mut self.errors,
                Field::IdpMfa,
                "MFA",
                Some("Second factor authentication tool."),
                &mut self.mfa,
                &mfa_options(self.security_key),
            );

            general_error(ui, &self.errors);
            entered
        })
    }
}

#[cfg(test)]
impl IdpDialog {
    pub fn type_into(&mut self, name: &str, url: &str, username: &str) {
        self.name = name.into();
        self.url = url.into();
        self.username = username.into();
    }

    pub fn mfa(&self) -> MfaChoice {
        self.mfa
    }
}
