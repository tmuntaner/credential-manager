//! Identity providers: the list, with Edit and Remove.

use super::dialogs::{Removal, RemoveDialog};
use super::SettingsAction;
use crate::core::ui::card::{card, card_button, card_header};
use crate::core::ui::select::mfa_label;
use crate::inbound::app::{Focus, FocusTarget, Section};
use c9s::app::settings::{IdpSummary, SettingsView};
use eframe::egui::Ui;

pub fn ui(ui: &mut Ui, view: &SettingsView, focus: &mut Focus) -> Option<SettingsAction> {
    card_header(
        ui,
        "Identity providers",
        "The services you use to sign in with.",
    );
    let mut action = None;

    if view.idps.is_empty() {
        ui.label("No identity provider yet.");
    }

    for idp in &view.idps {
        if let Some(a) = idp_entry(ui, idp, focus) {
            action = Some(a);
        }
        ui.add_space(8.0);
    }

    let add = ui.button("Add identity provider");
    focus.apply(FocusTarget::Add(Section::Idp), &add);
    if add.clicked() {
        action = Some(SettingsAction::AddIdp);
    }

    action
}

fn used_by(idp: &IdpSummary) -> String {
    match idp.used_by.len() {
        0 => "Not used by any application yet.".to_string(),
        1 => "Used by 1 application.".to_string(),
        n => format!("Used by {n} applications."),
    }
}

fn idp_entry(ui: &mut Ui, idp: &IdpSummary, focus: &mut Focus) -> Option<SettingsAction> {
    let details = [
        format!("URL: {}", idp.url.clone()),
        format!("Username: {}", idp.username),
        format!("MFA: {}.", mfa_label(idp.mfa)),
        used_by(idp),
    ];

    card(ui, &idp.name, &[], &details, |ui| {
        let edit = card_button(ui, "Edit", &idp.name);
        focus.apply(FocusTarget::Idp(idp.name.clone()), &edit);
        if edit.clicked() {
            return Some(SettingsAction::EditIdp(idp.clone()));
        }

        if card_button(ui, "Remove", &idp.name).clicked() {
            return Some(SettingsAction::Remove(RemoveDialog::new(
                Removal::Idp(idp.name.clone()),
                format!("Remove {}?", idp.name),
                format!(
                    "The identity provider {} ({}) will be deleted.",
                    idp.name, idp.url
                ),
                format!("{} removed.", idp.name),
            )));
        }
        None
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use c9s::app::settings::MfaChoice;

    #[test]
    fn the_use_of_an_idp_is_counted_in_words() {
        let mut idp = IdpSummary {
            name: "work".into(),
            url: "https://id".into(),
            username: "me".into(),
            mfa: MfaChoice::Ask,
            used_by: vec![],
        };
        assert_eq!(used_by(&idp), "Not used by any application yet.");
        idp.used_by = vec!["a".into()];
        assert_eq!(used_by(&idp), "Used by 1 application.");
        idp.used_by = vec!["a".into(), "b".into()];
        assert_eq!(used_by(&idp), "Used by 2 applications.");
    }
}
