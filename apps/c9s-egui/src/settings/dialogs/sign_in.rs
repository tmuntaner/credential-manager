use super::FormContext;
use crate::ui::errors::FormErrors;
use crate::ui::field::{submitted, text_field, TextOptions};
use crate::ui::heading;
use crate::ui::select::{idp_options, mfa_override_options, select};
use c9s::app::settings::{Field, MfaChoice};
use eframe::egui::Ui;

/// The fields of a form that are these three, so each form says which of its fields they are.
#[derive(Clone, Copy)]
pub struct SignInKeys {
    pub idp: Field,
    pub username: Field,
    pub mfa: Field,
}

pub struct SignInFields {
    keys: SignInKeys,
    form: FormContext,
    pub idp: String,
    username: String,
    pub mfa: Option<MfaChoice>,
}

impl SignInFields {
    pub fn new(keys: SignInKeys, form: &FormContext) -> Self {
        Self {
            keys,
            form: form.clone(),
            // A new app starts on the first identity provider, so there is always a choice made.
            idp: form.idps.first().cloned().unwrap_or_default(),
            username: String::new(),
            mfa: None,
        }
    }

    pub fn with(mut self, idp: String, username: Option<String>, mfa: Option<MfaChoice>) -> Self {
        self.idp = idp;
        self.username = username.unwrap_or_default();
        self.mfa = mfa;
        self
    }

    /// The username, or none when it was left empty.
    pub fn username(&self) -> Option<String> {
        Some(self.username.trim().to_string()).filter(|u| !u.is_empty())
    }

    pub fn ui(&mut self, ui: &mut Ui, errors: &mut FormErrors) -> bool {
        heading(ui, "Signing in");
        let options = idp_options(&self.form.idps, &self.idp);
        if options.is_empty() {
            ui.label("Add an identity provider first, an application signs in through one.");
        }

        select(
            ui,
            errors,
            self.keys.idp,
            "Identity provider",
            None,
            &mut self.idp,
            &options,
        );

        let input = text_field(
            ui,
            errors,
            self.keys.username,
            "User name (optional)",
            &mut self.username,
            TextOptions {
                hint: Some("Leave empty to use the user name of the identity provider."),
                ..Default::default()
            },
        );
        let entered = submitted(&input);

        select(
            ui,
            errors,
            self.keys.mfa,
            "Second step (optional)",
            None,
            &mut self.mfa,
            &mfa_override_options(self.form.security_key),
        );
        entered
    }
}
