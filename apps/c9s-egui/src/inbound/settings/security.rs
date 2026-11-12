//! Security: how c9s keeps secrets.

use super::SettingsAction;
use crate::core::ui::card::card_header;
use crate::core::ui::heading;
use crate::inbound::app::{Focus, FocusTarget, Section};
use c9s::app::settings::SettingsView;
use eframe::egui::{RichText, Ui};

pub fn ui(
    ui: &mut Ui,
    view: &SettingsView,
    enrolling: bool,
    focus: &mut Focus,
) -> Option<SettingsAction> {
    card_header(ui, "Security", "How c9s keeps your secrets.");
    let mut action = None;

    heading(ui, "Passwords");
    let mut use_keyring = view.use_keyring;
    if ui
        .checkbox(
            &mut use_keyring,
            "Remember my password in the system keyring (recommended)",
        )
        .changed()
    {
        action = Some(SettingsAction::SetKeyring(use_keyring));
    }

    ui.label(
        RichText::new(
            "c9s asks for your password the first time and offers to keep it in your computer's secure storage. It is never saved in the settings file.",
        )
        .weak(),
    );

    ui.add_space(16.0);
    heading(ui, "Security key");
    if let Some(a) = security_key(ui, view, enrolling, focus) {
        action = Some(a);
    }
    action
}

fn security_key(
    ui: &mut Ui,
    view: &SettingsView,
    enrolling: bool,
    focus: &mut Focus,
) -> Option<SettingsAction> {
    let mut action = None;

    if !view.security_key_supported {
        ui.label(RichText::new("Security keys are not supported on this system.").weak());
    }

    let status = match (&view.security_key_rp_id, view.security_key_enrolled) {
        (Some(rp_id), true) => format!("Enrolled ({rp_id})"),
        (None, true) => "Enrolled".to_string(),
        _ => "Not enrolled".to_string(),
    };
    ui.label(format!("Status: {status}"));

    ui.horizontal_wrapped(|ui| {
        let can_enroll = view.security_key_supported && !enrolling;
        let enroll = ui.add_enabled(can_enroll, eframe::egui::Button::new("Enroll security key"));
        focus.apply(FocusTarget::Add(Section::Security), &enroll);
        if enroll.clicked() {
            action = Some(SettingsAction::EnrollSecurityKey);
        }

        if view.security_key_enrolled
            && ui
                .add_enabled(!enrolling, eframe::egui::Button::new("Disable"))
                .accessible_name("Disable security key")
                .clicked()
        {
            action = Some(SettingsAction::DisableSecurityKey);
        }
    });
    if enrolling {
        ui.label(RichText::new("Enrolling… touch the key when it asks.").weak());
    }

    ui.add_space(8.0);
    let mut wrap_cached = view.wrap_cached;
    let changed = ui
        .add_enabled_ui(view.security_key_enrolled, |ui| {
            ui.checkbox(&mut wrap_cached, "Encrypt issued credentials (AWS/Rancher)")
                .changed()
        })
        .inner;
    if changed {
        action = Some(SettingsAction::SetWrapCached(wrap_cached));
    }
    ui.label(
        RichText::new(
            "When a security key is enrolled, your identity provider password and session are always encrypted with it. This also encrypts the AWS and Rancher credentials c9s issues. Enroll a key to turn it on.",
        )
        .weak(),
    );

    action
}
