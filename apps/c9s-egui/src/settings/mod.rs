mod aws;
mod dialogs;
mod home;
mod idps;
mod rancher;
mod security;

use crate::app::{Focus, FocusTarget, Route, Section, Shell};
use crate::prompts::Bridge;
use c9s::app::prompts::{WindowInteraction, WindowNotifier};
use c9s::app::settings::{
    enroll_security_key, AwsAppSummary, IdpSummary, MfaChoice, RancherSummary, SettingsPage,
    SettingsView, SetupError, DEFAULT_RP_ID,
};
use c9s::domain::models::settings::YubikeyConfig;
use c9s::outbound::config::config_store::ConfigFileAdapter;
use dialogs::{Dialog, DialogOutcome, FormContext, Removal, RemoveDialog};
use eframe::egui::{Id, Ui};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::Arc;

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
            Route::Setup => home::ui(ui, view),
            Route::Credentials => {
                crate::ui::card::card_header(ui, "Credentials", "Nothing here yet.");
                None
            }
            Route::Settings(Section::Idp) => idps::ui(ui, view, focus),
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
        if !view.checklist.aws {
            pending.push(Section::Aws);
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

    /// Takes in the result of the enrolling, once it is done. Called every frame.
    pub fn poll(&mut self, shell: &mut Shell) {
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
