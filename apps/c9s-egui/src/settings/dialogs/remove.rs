use super::{DialogOutcome, Saved};
use crate::app::{FocusTarget, Route};
use crate::ui::a11y;
use crate::ui::dialog::modal;
use crate::ui::errors::error_label;
use crate::ui::heading;
use c9s::app::settings::{AwsAppKey, SettingsPage};
use c9s::domain::ports::config::ConfigStore;
use eframe::egui::{Context, RichText};

/// What to remove.
#[derive(Clone, Debug)]
pub enum Removal {
    Idp(String),
    AwsApp(AwsAppKey),
    Rancher(String),
}

pub struct RemoveDialog {
    removal: Removal,
    title: String,
    description: String,
    /// A description of what was removed.
    done_description: String,
    error: Option<String>,
    first_frame: bool,
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
            done_description: done.into(),
            error: None,
            first_frame: true,
        }
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Remove the entry and gives focus to the add button of its add section.
    pub fn submit<S: ConfigStore>(&mut self, page: &SettingsPage<S>) -> Result<Saved, String> {
        let (result, section) = match &self.removal {
            Removal::Idp(name) => (page.remove_idp(name), Route::SettingsIdp),
            Removal::AwsApp(key) => (page.remove_aws_app(key.clone()), Route::SettingsAws),
            Removal::Rancher(url) => (page.remove_rancher(url), Route::SettingsRancher),
        };

        match result {
            Ok(view) => Ok(Saved {
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
                // if the "Remove" button was clicked, set the outcome as submit.
                if self.error.is_none() && ui.button(RichText::new("Remove").strong()).clicked() {
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
