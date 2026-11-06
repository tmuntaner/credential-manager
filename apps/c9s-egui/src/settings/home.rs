//! Home: the "Get started" checklist, with a link to each section. Each step says "Done", "To do" or
//! "Optional" in words.

use super::SettingsAction;
use crate::app::{Route, Section};
use crate::ui::card::card_header;
use c9s::app::settings::SettingsView;
use eframe::egui::{RichText, Ui};

pub fn ui(ui: &mut Ui, view: &SettingsView) -> Option<SettingsAction> {
    let c = view.checklist;
    let title = if c.idp && c.aws {
        "You are set up"
    } else {
        "Get started"
    };

    card_header(
        ui,
        title,
        "Set up these steps once. Your settings are saved in the same file the c9s command uses.",
    );

    let steps = [
        (
            Route::Settings(Section::Idp),
            "Add your identity provider",
            c.idp,
            false,
        ),
        (
            Route::Settings(Section::Aws),
            "Add an AWS account",
            c.aws,
            false,
        ),
        (
            Route::Settings(Section::Rancher),
            "Add a Rancher",
            c.rancher,
            true,
        ),
    ];
    let mut action = None;

    for (number, (route, text, done, optional)) in steps.into_iter().enumerate() {
        ui.horizontal_wrapped(|ui| {
            ui.label(format!("{}.", number + 1));
            if ui.link(text).clicked() {
                action = Some(SettingsAction::Go(route));
            }
            let state = match (done, optional) {
                (true, _) => RichText::new("(Done)").strong(),
                (false, true) => RichText::new("(Optional)").weak(),
                (false, false) => RichText::new("(To do)").weak(),
            };
            ui.label(state);
        });
    }

    action
}
