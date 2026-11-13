use super::sign_in::{SignInFields, SignInKeys};
use super::{DialogOutcome, FormContext, SavedResult};
use crate::core::ui::dialog::dialog;
use crate::core::ui::errors::{general_error, FormErrors};
use crate::core::ui::field::{submitted, text_field, TextOptions};
use crate::inbound::app::FocusTarget;
use c9s::app::settings::{same_url, Field, RancherForm, RancherSummary, SettingsPage};
use eframe::egui::Context;

const FIELDS: [Field; 5] = [
    Field::RancherUrl,
    Field::RancherClientId,
    Field::RancherIdp,
    Field::RancherUsername,
    Field::RancherMfa,
];

const SIGN_IN: SignInKeys = SignInKeys {
    idp: Field::RancherIdp,
    username: Field::RancherUsername,
    mfa: Field::RancherMfa,
};

pub struct RancherDialog {
    pub original_url: Option<String>,
    pub url: String,
    pub client_id: String,
    pub sign_in: SignInFields,
    pub first_frame: bool,
    pub errors: FormErrors,
}

impl RancherDialog {
    pub fn add(form: &FormContext) -> Self {
        Self {
            original_url: None,
            url: String::new(),
            client_id: "".to_string(),
            sign_in: SignInFields::new(SIGN_IN, form),
            first_frame: true,
            errors: FormErrors::default(),
        }
    }

    pub fn edit(host: &RancherSummary, form: &FormContext) -> Self {
        Self {
            original_url: Some(host.url.clone()),
            url: host.url.clone(),
            client_id: host.client_id.clone(),
            sign_in: SignInFields::new(SIGN_IN, form).with(
                host.idp.clone(),
                host.username.clone(),
                host.mfa,
            ),
            ..Self::add(form)
        }
    }

    fn form(&self) -> RancherForm {
        RancherForm {
            original_url: self.original_url.clone(),
            url: self.url.trim().to_string(),
            client_id: self.client_id.trim().to_string(),
            idp: self.sign_in.idp.clone(),
            username: self.sign_in.username(),
            mfa: self.sign_in.mfa,
        }
    }

    pub fn submit(&mut self, page: &SettingsPage) -> Result<SavedResult, String> {
        let form = self.form();

        match page.save_rancher(form.clone()) {
            Ok(view) => {
                let focus = view
                    .rancher_hosts
                    .iter()
                    .find(|h| same_url(&h.url, &form.url))
                    .map(|h| FocusTarget::Rancher(h.url.clone()));
                Ok(SavedResult {
                    view,
                    message: "Rancher saved.".to_string(),
                    focus,
                })
            }
            Err(error) => Err(self.errors.fail(error, &FIELDS)),
        }
    }

    pub fn ui(&mut self, ctx: &Context) -> DialogOutcome {
        let title = if self.original_url.is_some() {
            "Edit Rancher"
        } else {
            "Add Rancher"
        };
        let first = std::mem::take(&mut self.first_frame);

        dialog(ctx, "rancher", title, "Save", |ui| {
            ui.label("A Rancher that you sign in to through your identity provider.");
            ui.add_space(8.0);

            let input = text_field(
                ui,
                &mut self.errors,
                Field::RancherUrl,
                "The URL of Rancher",
                &mut self.url,
                TextOptions {
                    placeholder: Some("https://rancher.example.com"),
                    autofocus: first,
                    ..Default::default()
                },
            );
            let mut entered = submitted(&input);

            let input = text_field(
                ui,
                &mut self.errors,
                Field::RancherClientId,
                "Client ID",
                &mut self.client_id,
                TextOptions {
                    hint: Some(
                        "The client ID of the Rancher application in your identity provider.",
                    ),
                    ..Default::default()
                },
            );
            entered |= submitted(&input);

            entered |= self.sign_in.ui(ui, &mut self.errors);
            general_error(ui, &self.errors);
            entered
        })
    }
}
