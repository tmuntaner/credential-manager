use super::DialogOutcome;
use crate::ui::dialog::dialog;
use crate::ui::errors::error_label;
use crate::ui::field::{hint, submitted, INPUT_WIDTH};
use c9s::domain::services::settings_validation::check_username;
use eframe::egui::{Context, RichText, TextEdit};
use std::collections::BTreeMap;

/// A user onboarding file doesn't have usernames. This ask the user to fill one in when needed.
pub struct UsernamesDialog {
    idps: Vec<(String, String)>,
    error: Option<String>,
    first_frame: bool,
}

impl UsernamesDialog {
    pub fn new(idps: &[String]) -> Self {
        Self {
            idps: idps
                .iter()
                .map(|name| (name.clone(), String::new()))
                .collect(),
            error: None,
            first_frame: true,
        }
    }

    /// The usernames for each identity provider.
    pub fn usernames(&mut self) -> Result<BTreeMap<String, String>, String> {
        let mut usernames = BTreeMap::new();

        for (idp, username) in &self.idps {
            let username = check_username(username).map_err(|e| format!("{idp}: {e}"))?;
            usernames.insert(idp.clone(), username);
        }

        Ok(usernames)
    }

    pub fn ui(&mut self, ctx: &Context) -> DialogOutcome {
        let first = std::mem::take(&mut self.first_frame);
        let error = self.error.clone();

        let outcome = dialog(ctx, "usernames", "Import onboarding file", "Import", |ui| {
            ui.label("Enter the username for each identity provider.");
            ui.add_space(8.0);

            let mut entered = false;
            for (index, (idp, username)) in self.idps.iter_mut().enumerate() {
                let label = ui.label(RichText::new(format!("User name for {idp}")).strong());
                hint(
                    ui,
                    "It should be the user you log into with your identity provider.",
                );
                let input = ui
                    .add(
                        TextEdit::singleline(username)
                            .desired_width(INPUT_WIDTH.min(ui.available_width())),
                    )
                    .labelled_by(label.id);

                // if it's the first frame, set the focus
                if first && index == 0 {
                    input.request_focus();
                }

                entered |= submitted(&input);
                ui.add_space(8.0);
            }

            if let Some(message) = &error {
                error_label(ui, message);
            }

            entered
        });

        // check the usernames for a mistake
        if outcome == DialogOutcome::Submit {
            if let Err(message) = self.usernames() {
                self.error = Some(message);
                return DialogOutcome::Nothing;
            }
            self.error = None;
        }

        outcome
    }
}
