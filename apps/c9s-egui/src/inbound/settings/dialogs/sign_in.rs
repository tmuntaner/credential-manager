use super::FormContext;
use crate::core::ui::errors::FormErrors;
use crate::core::ui::field::{submitted, text_field, TextOptions};
use crate::core::ui::heading;
use crate::core::ui::select::{idp_options, mfa_override_options, select};
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
    pub keys: SignInKeys,
    pub form: FormContext,
    pub idp: String,
    pub username: String,
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
            ui.label("Add an identity provider");
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
            "Username override (optional)",
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
            "MFA (optional)",
            None,
            &mut self.mfa,
            &mfa_override_options(self.form.security_key),
        );
        entered
    }
}
