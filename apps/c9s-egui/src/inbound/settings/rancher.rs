//! Rancher: the Ranchers that are set up, with Edit and Remove.

use super::dialogs::{Removal, RemoveDialog};
use super::{signs_in_with, SettingsAction};
use crate::core::ui::card::{card, card_button, card_header};
use crate::inbound::app::{Focus, FocusTarget, Section};
use c9s::app::settings::{RancherSummary, SettingsView};
use eframe::egui::Ui;

pub fn ui(ui: &mut Ui, view: &SettingsView, focus: &mut Focus) -> Option<SettingsAction> {
    card_header(
        ui,
        "Rancher",
        "Optional. Rancher signs in through an identity provider. For now, get Rancher credentials with `c9s creds rancher` in a terminal; it uses what you set up here.",
    );
    let mut action = None;

    if view.rancher_hosts.is_empty() {
        ui.label("No Rancher yet.");
    }

    for host in &view.rancher_hosts {
        if let Some(a) = host_entry(ui, host, focus) {
            action = Some(a);
        }
        ui.add_space(8.0);
    }

    let add = ui.button("Add Rancher");
    focus.apply(FocusTarget::Add(Section::Rancher), &add);
    if add.clicked() {
        action = Some(SettingsAction::AddRancher);
    }

    action
}

fn host_entry(ui: &mut Ui, host: &RancherSummary, focus: &mut Focus) -> Option<SettingsAction> {
    let details = [
        format!("Client ID: {}.", host.client_id),
        signs_in_with(&host.idp, host.username.as_deref(), host.mfa),
    ];

    card(ui, &host.url, &[], &details, |ui| {
        let edit = card_button(ui, "Edit", &host.url);
        focus.apply(FocusTarget::Rancher(host.url.clone()), &edit);
        if edit.clicked() {
            return Some(SettingsAction::EditRancher(host.clone()));
        }

        if card_button(ui, "Remove", &host.url).clicked() {
            return Some(SettingsAction::Remove(RemoveDialog::new(
                Removal::Rancher(host.url.clone()),
                "Remove this Rancher?",
                format!("c9s will no longer use the Rancher at {}.", host.url),
                "Rancher removed.",
            )));
        }
        None
    })
}
