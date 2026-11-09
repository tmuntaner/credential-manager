mod aws;
mod dialogs;
mod enrolling;
mod home;
mod idps;
mod rancher;
mod security;
mod share;
mod transfer;

use crate::app::{Focus, FocusTarget, Route, Section, Shell};
use crate::prompts::Bridge;
use c9s::app::settings::{
    describe_import, AwsAppSummary, IdpSummary, ImportPlan, MfaChoice, RancherSummary,
    SettingsPage, SettingsView, SetupError,
};
use c9s::domain::services::settings_editor::{ImportMode, SettingsService};
use c9s::outbound::config::bundle::TomlBundleCodec;
use c9s::outbound::config::config_store::ConfigFileAdapter;
use dialogs::{
    Dialog, DialogOutcome, ExportDialog, FormContext, Removal, RemoveDialog, Submitted,
    UsernamesDialog,
};
use eframe::egui::{Id, Ui};
pub use enrolling::Enroller;
use enrolling::Enrolling;
use std::collections::BTreeMap;
use std::sync::Arc;
pub use transfer::{FilePicker, Pick};
use transfer::{FileTransfer, Transfer};

/// The user's action on a settings screen.
pub enum SettingsAction {
    Go(Route),
    AddIdp,
    EditIdp(IdpSummary),
    SetKeyring(bool),
    EnrollSecurityKey,
    DisableSecurityKey,
    SetWrapCached(bool),
    AddAws,
    EditAws(AwsAppSummary),
    AddRancher,
    EditRancher(RancherSummary),
    Remove(RemoveDialog),
    /// Opens a dialog to choose where to export an onboarding file.
    Export,
    /// Opens a dialog to choose which file should be used for onboarding..
    Import,
    SetImportOverwrite(bool),
}

pub struct SettingsState {
    bridge: Bridge,
    enrolling: Enrolling,
    transfer: FileTransfer,
    page: SettingsPage,
    /// The settings view, or error message
    view: Result<SettingsView, String>,
    dialog: Option<Dialog>,
    /// What initially had the focus. It'll get it back when the dialog is canceled.
    opener: Option<Id>,
}

impl SettingsState {
    pub fn new(store: ConfigFileAdapter, bridge: Bridge) -> Self {
        let settings = SettingsService::new(Arc::new(store));
        let page = SettingsPage::new(settings);
        let view = page.view().map_err(|e| e.sentence());
        Self {
            bridge,
            enrolling: Enrolling::new(),
            transfer: FileTransfer::new(),
            page,
            view,
            dialog: None,
            opener: None,
        }
    }

    /// Replaces how a security key is enrolled.
    pub fn set_enroller(&mut self, enroller: Enroller) {
        self.enrolling.set_enroller(enroller);
    }

    /// Replaces the file picker which asks the user to choose a file to import from or export to.
    pub fn set_file_picker(&mut self, chooser: FilePicker) {
        self.transfer.set_picker(chooser);
    }

    /// The settings, if they could be read.
    pub fn view(&self) -> Option<&SettingsView> {
        self.view.as_ref().ok()
    }

    /// Whether the user has set up an idp.
    pub fn is_set_up(&self) -> bool {
        matches!(self.view(), Some(view) if view.checklist.idp)
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
            Route::Setup => home::ui(ui, view, focus),
            Route::Credentials => {
                crate::ui::card::card_header(ui, "Credentials", "Nothing here yet.");
                None
            }
            Route::Settings(Section::Idp) => idps::ui(ui, view, focus),
            Route::Settings(Section::Share) => share::ui(
                ui,
                view,
                self.transfer.overwrite(),
                self.transfer.is_choosing(),
                focus,
            ),
            Route::Settings(Section::Aws) => aws::ui(ui, view, focus),
            Route::Settings(Section::Rancher) => rancher::ui(ui, view, focus),
            Route::Settings(Section::Security) => {
                security::ui(ui, view, self.enrolling.is_running(), focus)
            }
        }
    }

    /// The sections that still need something done before c9s can be used.
    pub fn pending_sections(&self) -> Vec<Section> {
        let Some(view) = self.view() else {
            return Vec::new();
        };
        let mut pending = Vec::new();
        if !view.checklist.idp {
            pending.push(Section::Idp);
        }
        pending
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
            SettingsAction::EnrollSecurityKey => self.enrolling.start(shell, &self.bridge),
            SettingsAction::Export => {
                self.open(shell, Dialog::Export(ExportDialog::new(view)));
            }
            SettingsAction::Import => {
                let mode = self.transfer.import_mode();
                self.transfer
                    .choose(shell, Transfer::Import(mode), Pick::Open);
            }
            SettingsAction::SetImportOverwrite(overwrite) => self.transfer.set_overwrite(overwrite),
            SettingsAction::DisableSecurityKey => {
                let rp_id = view.security_key_rp_id.clone().unwrap_or_default();
                self.open(
                    shell,
                    Dialog::Remove(
                        RemoveDialog::new(
                            Removal::SecurityKey,
                            "Disable the security key?",
                            format!(
                                "c9s will stop encrypting with the security key ({rp_id}). Secrets that are already encrypted may need you to sign in again."
                            ),
                            "Security key disabled.",
                        )
                        .confirm_with("Disable"),
                    ),
                )
            }
            SettingsAction::SetWrapCached(enabled) => {
                let result = self.page.set_wrap_cached(enabled);
                let said = if enabled {
                    "Issued credentials will be encrypted."
                } else {
                    "Issued credentials will not be encrypted."
                };
                self.changed(shell, result, said.to_string(), None);
            }
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

    /// Handles the file the user chose for an export or import, once they did. Called every frame.
    fn poll_choosing(&mut self, shell: &mut Shell) {
        let Some((transfer, path)) = self.transfer.poll() else {
            return;
        };

        match transfer {
            Transfer::Export(choice) => {
                // export the onboarding data to a file
                match self
                    .page
                    .export_choice_to_file(&TomlBundleCodec, &choice, &path)
                {
                    Ok(()) => shell.say(format!("Exported to {}.", path.display())),
                    Err(error) => shell.fail(error.sentence()),
                }
            }
            Transfer::Import(mode) => {
                // import the onboarding data
                // we need to check if there is anything new which requires a username
                // if so, we need to ask the user for one
                match self.page.plan_import_from_file(&TomlBundleCodec, &path) {
                    Err(error) => shell.fail(error.sentence()),
                    // Nothing is new, so there is no username to ask for.
                    Ok(plan) if plan.usernames_needed().is_empty() => {
                        self.import(shell, &plan, mode, &BTreeMap::new())
                    }
                    Ok(plan) => {
                        let dialog = UsernamesDialog::new(plan.usernames_needed());
                        self.transfer.hold(plan, mode);
                        self.open(shell, Dialog::Usernames(dialog));
                    }
                }
            }
        }
        shell.ctx.request_repaint();
    }

    fn import(
        &mut self,
        shell: &mut Shell,
        plan: &ImportPlan,
        mode: ImportMode,
        usernames: &BTreeMap<String, String>,
    ) {
        match self.page.apply_import(plan, mode, usernames) {
            Ok((view, report)) => {
                self.view = Ok(view);
                // From the checklist, the next step is to leave it.
                shell.focus(if shell.route() == Route::Setup {
                    FocusTarget::FinishOnBoarding
                } else {
                    FocusTarget::Add(Section::Share)
                });
                shell.say(describe_import(&report));
            }
            Err(error) => shell.fail(error.sentence()),
        }
    }

    /// Takes in the result of the enrolling, once it is done. Called every frame.
    pub fn poll(&mut self, shell: &mut Shell) {
        self.poll_choosing(shell);

        let Some(result) = self.enrolling.poll() else {
            return;
        };

        let saved = result.and_then(|key| self.page.set_security_key(Some(key)));
        self.changed(
            shell,
            saved,
            "Security key enrolled.".to_string(),
            Some(FocusTarget::Add(Section::Security)),
        );
        shell.ctx.request_repaint();
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
                self.transfer.forget_held();
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

        match dialog.submit(&self.page) {
            Ok(Submitted::Saved(saved)) => {
                self.view = Ok(saved.view);
                self.close_dialog();

                // if we have a focus after the save, focus on it.
                if let Some(target) = saved.focus {
                    shell.focus(target);
                }

                // add a message to the status line.
                shell.say(saved.message);
            }

            // Exporting needs a file, so the dialog closes and the user chooses one.
            Ok(Submitted::Export(choice)) => {
                self.close_dialog();
                self.transfer
                    .choose(shell, Transfer::Export(choice), Pick::Save);
            }

            // Importing has what it needs now: the file, and the user names.
            Ok(Submitted::Usernames(usernames)) => {
                self.close_dialog();
                if let Some((plan, mode)) = self.transfer.take_held() {
                    self.import(shell, &plan, mode, &usernames);
                }
            }

            Ok(Submitted::StillOpen) => {}

            Err(said) => {
                shell.fail(said);
                self.refresh_view();
            }
        }
    }

    fn close_dialog(&mut self) {
        self.dialog = None;
        self.opener = None;
    }

    /// Reads the settings again, so that the screen shows what is stored.
    fn refresh_view(&mut self) {
        self.view = self.page.view().map_err(|e| e.sentence());
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
                self.refresh_view();
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
