mod aws;
mod dialogs;
mod home;
mod idps;
mod rancher;

use crate::app::{Focus, FocusTarget, Route, Shell};
use c9s::app::settings::{
    AwsAppSummary, IdpSummary, MfaChoice, RancherSummary, SettingsPage, SettingsView, SetupError,
};
use c9s::outbound::config::config_store::ConfigFileAdapter;
use dialogs::{Dialog, DialogOutcome, FormContext, RemoveDialog};
use eframe::egui::{Id, Ui};

/// The user's action on a settings screen.
pub enum SettingsAction {
    Go(Route),
    AddIdp,
    EditIdp(IdpSummary),
    SetKeyring(bool),
    AddAws,
    EditAws(AwsAppSummary),
    AddRancher,
    EditRancher(RancherSummary),
    Remove(RemoveDialog),
}

pub struct SettingsState {
    page: SettingsPage<ConfigFileAdapter>,
    /// The settings view, or error message
    view: Result<SettingsView, String>,
    dialog: Option<Dialog>,
    /// What initially had the focus. It'll get it back when the dialog is canceled.
    opener: Option<Id>,
}

impl SettingsState {
    pub fn new(store: ConfigFileAdapter) -> Self {
        let page = SettingsPage::new(store);
        let view = page.view().map_err(|e| e.sentence());
        Self {
            page,
            view,
            dialog: None,
            opener: None,
        }
    }

    /// The settings, if they could be read.
    pub fn view(&self) -> Option<&SettingsView> {
        self.view.as_ref().ok()
    }

    /// Whether the first steps (an identity provider and an AWS account) are done.
    pub fn is_set_up(&self) -> bool {
        matches!(self.view(), Some(view) if view.checklist.idp && view.checklist.aws)
    }

    /// Renders the screen of settings `route`.
    pub fn ui(&self, ui: &mut Ui, route: Route, focus: &mut Focus) -> Option<SettingsAction> {
        let view = match &self.view {
            Ok(view) => view,
            Err(error) => {
                crate::ui::errors::error_label(ui, error);
                return None;
            }
        };

        match route {
            Route::Home => home::ui(ui, view),
            Route::SettingsIdp => idps::ui(ui, view, focus),
            Route::SettingsAws => aws::ui(ui, view, focus),
            Route::SettingsRancher => rancher::ui(ui, view, focus),
        }
    }

    /// Updates the settings page with an incoming action.
    pub fn update(&mut self, shell: &mut Shell, action: SettingsAction) {
        let Ok(view) = &self.view else { return };
        let form = FormContext::of(view);

        match action {
            SettingsAction::Go(route) => shell.go(route),
            SettingsAction::AddIdp => self.open(shell, Dialog::add_idp(&form)),
            SettingsAction::EditIdp(idp) => self.open(shell, Dialog::edit_idp(&idp, &form)),
            SettingsAction::AddAws => self.open(shell, Dialog::add_aws(&form)),
            SettingsAction::EditAws(app) => self.open(shell, Dialog::edit_aws(&app, &form)),
            SettingsAction::AddRancher => self.open(shell, Dialog::add_rancher(&form)),
            SettingsAction::EditRancher(host) => {
                self.open(shell, Dialog::edit_rancher(&host, &form))
            }
            SettingsAction::Remove(dialog) => self.open(shell, Dialog::Remove(dialog)),
            SettingsAction::SetKeyring(enabled) => {
                let result = self.page.set_use_keyring(enabled);
                let said = if enabled {
                    "Passwords may be kept in the keyring."
                } else {
                    "Passwords will be asked every time."
                };
                self.changed(shell, result, said.to_string(), None);
            }
        }
    }

    /// Opens a dialog.
    pub fn dialog(&mut self, shell: &mut Shell) {
        // if there is no dialog, return
        let Some(dialog) = &mut self.dialog else {
            return;
        };

        match dialog.ui(shell.ctx) {
            DialogOutcome::Nothing => {}
            DialogOutcome::Cancel => {
                self.dialog = None;
                shell.ctx.request_repaint();

                if let Some(opener) = self.opener.take() {
                    shell.ctx.memory_mut(|m| m.request_focus(opener));
                }
            }
            DialogOutcome::Submit => {
                self.submit(shell);
                shell.ctx.request_repaint();
            }
        }
    }

    fn submit(&mut self, shell: &mut Shell) {
        // if there is no dialog, return early
        let Some(dialog) = &mut self.dialog else {
            return;
        };

        // submit the dialog
        match dialog.submit(&self.page) {
            Ok(saved) => {
                self.view = Ok(saved.view);
                self.dialog = None;
                self.opener = None;

                // if we have a focus after the save, focus on it.
                if let Some(target) = saved.focus {
                    shell.focus(target);
                }

                // add a message to the status line.
                shell.say(saved.message);
            }

            Err(said) => {
                shell.fail(said);
                self.view = self.page.view().map_err(|e| e.sentence());
            }
        }
    }

    fn open(&mut self, shell: &Shell, dialog: Dialog) {
        self.opener = shell.ctx.memory(|m| m.focused());
        self.dialog = Some(dialog);
    }

    /// Shows the settings a change made, or why it failed.
    fn changed(
        &mut self,
        shell: &mut Shell,
        result: Result<SettingsView, SetupError>,
        said: String,
        focus: Option<FocusTarget>,
    ) {
        match result {
            Ok(view) => {
                self.view = Ok(view);
                if let Some(target) = focus {
                    shell.focus(target);
                }

                shell.say(said);
            }
            Err(error) => {
                shell.fail(error.sentence());
                self.view = self.page.view().map_err(|e| e.sentence());
            }
        }
    }
}

fn signs_in_with(idp: &str, username: Option<&str>, mfa: Option<MfaChoice>) -> String {
    let mut parts = vec![format!("Signs in with {idp}")];

    if let Some(username) = username {
        parts.push(format!("as {username}"));
    }

    if let Some(mfa) = mfa {
        parts.push(format!(
            "second step: {}",
            crate::ui::select::mfa_label(mfa)
        ));
    }

    parts.join(", ") + "."
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sentence_says_who_signs_in_how() {
        assert_eq!(signs_in_with("work", None, None), "Signs in with work.");
        assert_eq!(
            signs_in_with("lab", Some("me"), Some(MfaChoice::Totp)),
            "Signs in with lab, as me, second step: Code from an authenticator app."
        );
    }
}
