use super::SettingsAction;
use crate::app::{Focus, FocusTarget, Section};
use crate::ui::card::card_header;
use c9s::app::settings::SettingsView;
use eframe::egui::{Button, RichText, Ui};

pub fn ui(
    ui: &mut Ui,
    view: &SettingsView,
    overwrite: bool,
    busy: bool,
    focus: &mut Focus,
) -> Option<SettingsAction> {
    card_header(
        ui,
        "Import / Export",
        "Share your identity providers with a colleague, or start from theirs.",
    );
    ui.label(
        "An onboarding file holds your identity providers and their applications, so a colleague can start from them. \
         It does not contain user names and or user specific settings. It's not your c9s settings file, which you should not share.",
    );
    ui.add_space(8.0);

    let mut action = None;

    ui.label(RichText::new("Export").strong());
    ui.label("Choose which identity providers to include.");
    let export = ui.add_enabled(!busy && !view.idps.is_empty(), Button::new("Export…"));
    if export.clicked() {
        action = Some(SettingsAction::Export);
    }

    ui.add_space(16.0);
    ui.separator();
    ui.label(RichText::new("Import").strong());
    ui.label("Add the identity providers and applications from an onboarding file you received.");

    let mut update = overwrite;
    if ui
        .checkbox(&mut update, "Update entries that are set up already")
        .changed()
    {
        action = Some(SettingsAction::SetImportOverwrite(update));
    }

    let import = ui.add_enabled(!busy, Button::new("Import…"));
    focus.apply(FocusTarget::Add(Section::Share), &import);
    if import.clicked() {
        action = Some(SettingsAction::Import);
    }

    action
}
