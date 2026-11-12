use super::{DialogOutcome, SavedResult};
use crate::core::ui::a11y;
use crate::core::ui::dialog::modal;
use crate::core::ui::errors::error_label;
use crate::core::ui::heading;
use crate::inbound::app::{FocusTarget, Section};
use c9s::app::settings::{AwsAppKey, SettingsPage};
use eframe::egui::{Context, RichText};

/// What to remove.
#[derive(Clone, Debug)]
pub enum Removal {
    Idp(String),
    AwsApp(AwsAppKey),
    Rancher(String),
    /// Stops using the enrolled security key.
    SecurityKey,
}

pub struct RemoveDialog {
    pub removal: Removal,
    pub title: String,
    pub description: String,
    /// The label of the button that confirms.
    pub confirm: String,
    /// A description of what was removed.
    pub done_description: String,
    pub error: Option<String>,
    pub first_frame: bool,
}

impl RemoveDialog {
    pub fn new(
        removal: Removal,
        title: impl Into<String>,
        description: impl Into<String>,
        done: impl Into<String>,
    ) -> Self {
        Self {
            removal,
            title: title.into(),
            description: description.into(),
            confirm: "Remove".to_string(),
            done_description: done.into(),
            error: None,
            first_frame: true,
        }
    }

    /// Names the confirming button after what it does (default "Remove").
    pub fn confirm_with(mut self, label: impl Into<String>) -> Self {
        self.confirm = label.into();
        self
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Remove the entry and gives focus to the add button of its add section.
    pub fn submit(&mut self, page: &SettingsPage) -> Result<SavedResult, String> {
        let (result, section) = match &self.removal {
            Removal::Idp(name) => (page.remove_idp(name), Section::Idp),
            Removal::AwsApp(key) => (page.remove_aws_app(key.clone()), Section::Aws),
            Removal::Rancher(url) => (page.remove_rancher(url), Section::Rancher),
            Removal::SecurityKey => (page.set_security_key(None), Section::Security),
        };

        match result {
            Ok(view) => Ok(SavedResult {
                view,
                message: self.done_description.clone(),
                focus: Some(FocusTarget::Add(section)),
            }),
            Err(error) => {
                self.error = Some(error.sentence());
                self.first_frame = true;
                Err("Not removed.".to_string())
            }
        }
    }

    pub fn ui(&mut self, ctx: &Context) -> DialogOutcome {
        let mut outcome = DialogOutcome::Nothing;
        let first = std::mem::take(&mut self.first_frame);

        let close = modal(ctx, "remove", |ui| {
            heading(ui, &self.title);

            ui.label(&self.description);

            if let Some(error) = &self.error {
                let label = error_label(ui, error);
                a11y::live(ui, &label);
            }

            ui.separator();

            ui.horizontal_wrapped(|ui| {
                // if the confirming button was clicked, set the outcome as submit.
                if self.error.is_none()
                    && ui.button(RichText::new(&self.confirm).strong()).clicked()
                {
                    outcome = DialogOutcome::Submit;
                }

                let name = if self.error.is_some() {
                    "Close"
                } else {
                    "Cancel"
                };

                // set the cancel as the initial focus
                let cancel = ui.button(name);
                if first {
                    cancel.request_focus();
                }

                // if the user clicked cancel, set it as the outcome.
                if cancel.clicked() {
                    outcome = DialogOutcome::Cancel;
                }
            });
        });

        // if the window was closed, set the outcome as cancel.
        if outcome == DialogOutcome::Nothing && close {
            outcome = DialogOutcome::Cancel;
        }

        outcome
    }
}
