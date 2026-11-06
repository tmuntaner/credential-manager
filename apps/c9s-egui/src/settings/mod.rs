mod aws;
mod dialogs;
mod home;
mod idps;
mod rancher;
mod security;
mod share;
mod transfer;

use crate::app::{Focus, FocusTarget, Route, Section, Shell};
use crate::prompts::Bridge;
use c9s::app::prompts::{WindowInteraction, WindowNotifier};
use c9s::app::settings::{
    enroll_security_key, AwsAppSummary, IdpSummary, MfaChoice, RancherSummary, SettingsPage,
    SettingsView, SetupError, DEFAULT_RP_ID,
};
use c9s::domain::models::settings::YubikeyConfig;
use c9s::domain::services::settings_editor::{ImportMode, ImportReport};
use c9s::outbound::config::bundle::TomlBundleCodec;
use c9s::outbound::config::config_store::ConfigFileAdapter;
use dialogs::{
    Dialog, DialogOutcome, ExportDialog, FormContext, Removal, RemoveDialog, UsernamesDialog,
};
use eframe::egui::{Id, Ui};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::Arc;
use transfer::{real_file_picker, ChosenFile, Transfer};
pub use transfer::{FilePicker, Pick};

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

/// Enrolls a security key for a relying party id, blocking until the user is done. It runs on its own thread
/// and asks its questions through the bridge. Tests replace it.
pub type Enroller = Arc<dyn Fn(&str, Bridge) -> Result<YubikeyConfig, SetupError> + Send + Sync>;

/// The enroller that uses the real security key.
fn real_enroller() -> Enroller {
    Arc::new(|rp_id, bridge| {
        // The enrolling future is not `Send`, so it gets a runtime of its own on this thread.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| SetupError::general(format!("Could not start enrolling: {e}.")))?;
        let result = runtime.block_on(enroll_security_key(
            rp_id,
            Arc::new(WindowInteraction::new(bridge.clone())),
            Arc::new(WindowNotifier::new(bridge.clone())),
        ));
        // The "touch your key" notice stays until it is cleared.
        bridge.clear_notices();
        result
    })
}

pub struct SettingsState {
    bridge: Bridge,
    enroller: Enroller,
    /// The result of the enrolling that is in progress.
    enrolling: Option<Receiver<Result<YubikeyConfig, SetupError>>>,
    file_picker: FilePicker,
    /// The file the user chose for an export or import.
    file_picker_choice: Option<ChosenFile>,
    /// Whether an import overwrites existing settings.
    import_overwrite: bool,
    /// The file being imported while the user enters their user names.
    importing: Option<(PathBuf, ImportMode)>,
    page: SettingsPage<ConfigFileAdapter>,
    /// The settings view, or error message
    view: Result<SettingsView, String>,
    dialog: Option<Dialog>,
    /// What initially had the focus. It'll get it back when the dialog is canceled.
    opener: Option<Id>,
}

impl SettingsState {
    pub fn new(store: ConfigFileAdapter, bridge: Bridge) -> Self {
        let page = SettingsPage::new(store);
        let view = page.view().map_err(|e| e.sentence());
        Self {
            bridge,
            enroller: real_enroller(),
            enrolling: None,
            file_picker: real_file_picker(),
            file_picker_choice: None,
            import_overwrite: false,
            importing: None,
            page,
            view,
            dialog: None,
            opener: None,
        }
    }

    /// Replaces how a security key is enrolled.
    pub fn set_enroller(&mut self, enroller: Enroller) {
        self.enroller = enroller;
    }

    /// Replaces the file picker which asks teh user to choose a file to import from or export to.
    pub fn set_file_picker(&mut self, chooser: FilePicker) {
        self.file_picker = chooser;
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
                self.import_overwrite,
                self.file_picker_choice.is_some(),
                focus,
            ),
            Route::Settings(Section::Aws) => aws::ui(ui, view, focus),
            Route::Settings(Section::Rancher) => rancher::ui(ui, view, focus),
            Route::Settings(Section::Security) => {
                security::ui(ui, view, self.enrolling.is_some(), focus)
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
            SettingsAction::EnrollSecurityKey => self.enroll(shell),
            SettingsAction::Export => {
                self.open(shell, Dialog::Export(ExportDialog::new(view)));
            }
            SettingsAction::Import => {
                let mode = if self.import_overwrite {
                    ImportMode::Overwrite
                } else {
                    ImportMode::SkipExisting
                };
                self.choose(shell, Transfer::Import(mode), Pick::Open);
            }
            SettingsAction::SetImportOverwrite(overwrite) => self.import_overwrite = overwrite,
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

    /// Starts enrolling a security key on its own thread.
    fn enroll(&mut self, shell: &mut Shell) {
        if self.enrolling.is_some() {
            return;
        }

        let (sender, receiver) = mpsc::channel();
        let enroller = self.enroller.clone();
        let bridge = self.bridge.clone();
        let ctx = shell.ctx.clone();
        let spawned = std::thread::Builder::new()
            .name("enroll-security-key".into())
            .spawn(move || {
                let _ = sender.send(enroller(DEFAULT_RP_ID, bridge));
                ctx.request_repaint();
            });

        match spawned {
            Ok(_) => {
                self.enrolling = Some(receiver);
                shell.say("Enrolling the security key. Follow the instructions on the screen.");
            }
            Err(e) => shell.fail(format!("Could not start enrolling: {e}.")),
        }
    }

    /// Asks the user to choose a file.
    fn choose(&mut self, shell: &mut Shell, transfer: Transfer, pick: Pick) {
        // ensure there is actually a file that the user chose.
        if self.file_picker_choice.is_some() {
            return;
        }

        // create a channel and get the file path from the file picker
        let (sender, file) = mpsc::channel();
        let chooser = self.file_picker.clone();
        let ctx = shell.ctx.clone();
        let spawned = std::thread::Builder::new()
            .name("choose-file".into())
            .spawn(move || {
                let _ = sender.send(chooser(pick));
                ctx.request_repaint();
            });

        match spawned {
            Ok(_) => self.file_picker_choice = Some(ChosenFile { transfer, file }),
            Err(e) => shell.fail(format!("Could not ask for a file: {e}.")),
        }
    }

    /// Pools to see if a user selected anything from the file picker. Called every frame.
    fn poll_choosing(&mut self, shell: &mut Shell) {
        // return unless there is a selected file picker file yet
        let Some(choice) = &self.file_picker_choice else {
            return;
        };

        // try to receive the file from the receiver
        let file = match choice.file.try_recv() {
            Ok(file) => file,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => None,
        };

        // take the file and leave none in its place
        let Some(ChosenFile { transfer, .. }) = self.file_picker_choice.take() else {
            return;
        };

        // if there is no file, return
        let Some(path) = file else { return };

        // handle the file event
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
                match self.page.usernames_needed_by_file(&TomlBundleCodec, &path) {
                    Err(error) => shell.fail(error.sentence()),
                    // Nothing is new, so there is no username to ask for.
                    Ok(needed) if needed.is_empty() => {
                        self.import(shell, &path, mode, &BTreeMap::new())
                    }
                    Ok(needed) => {
                        self.importing = Some((path, mode));
                        self.open(shell, Dialog::Usernames(UsernamesDialog::new(&needed)));
                    }
                }
            }
        }
        shell.ctx.request_repaint();
    }

    fn import(
        &mut self,
        shell: &mut Shell,
        path: &std::path::Path,
        mode: ImportMode,
        usernames: &BTreeMap<String, String>,
    ) {
        match self
            .page
            .import_from_file(&TomlBundleCodec, path, mode, usernames)
        {
            Ok((view, report)) => {
                self.view = Ok(view);
                // From the checklist, the next step is to leave it.
                shell.focus(if shell.route() == Route::Setup {
                    FocusTarget::FinishOnBoarding
                } else {
                    FocusTarget::Add(Section::Share)
                });
                shell.say(imported(&report));
            }
            Err(error) => shell.fail(error.sentence()),
        }
    }

    /// Takes in the result of the enrolling, once it is done. Called every frame.
    pub fn poll(&mut self, shell: &mut Shell) {
        self.poll_choosing(shell);

        let Some(receiver) = &self.enrolling else {
            return;
        };

        let result = match receiver.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err(SetupError::general(
                "Enrolling the security key stopped unexpectedly.",
            )),
        };
        self.enrolling = None;

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
                self.importing = None;
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

        // Importing has what it needs now: the file, and the user names.
        if let Dialog::Usernames(names) = dialog {
            let Ok(usernames) = names.usernames() else {
                return;
            };
            self.dialog = None;
            self.opener = None;
            if let Some((path, mode)) = self.importing.take() {
                self.import(shell, &path, mode, &usernames);
            }
            return;
        }

        // Exporting needs a file, so the dialog closes and the user chooses one.
        if let Dialog::Export(export) = dialog {
            let choice = export.chosen();
            self.dialog = None;
            self.opener = None;
            self.choose(shell, Transfer::Export(choice), Pick::Save);
            return;
        }

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

/// Says what an import did.
fn imported(report: &ImportReport) -> String {
    let (added, updated, kept) = (report.added(), report.overwritten(), report.skipped());
    if added + updated == 0 {
        return format!("Nothing new to import, {kept} were set up already.");
    }
    let mut parts = vec![format!("{added} added")];
    if updated > 0 {
        parts.push(format!("{updated} updated"));
    }
    if kept > 0 {
        parts.push(format!("{kept} kept as they were"));
    }

    format!("Imported: {}.", parts.join(", "))
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
