use super::SettingsAction;
use crate::core::ui::card::card_header;
use crate::inbound::app::{Focus, FocusTarget, Route, Section};
use c9s::app::settings::SettingsView;
use eframe::egui::{RichText, Ui};

pub fn ui(ui: &mut Ui, view: &SettingsView, focus: &mut Focus) -> Option<SettingsAction> {
    let c = view.checklist;
    let title = if c.idp {
        "You are set up"
    } else {
        "Get started"
    };

    card_header(
        ui,
        title,
        "Start by setting your identity provider, the rest can wait until you need it.",
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
            true,
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

    // the idp is required. If the user set that up, we can skip the rest.
    if c.idp {
        ui.add_space(12.0);
        let finish = ui.button(RichText::new("Finish setup").strong());
        focus.apply(FocusTarget::FinishOnBoarding, &finish);
        if finish.clicked() {
            action = Some(SettingsAction::Go(Route::Credentials));
        }
    }

    // if there is no idp yet, allow the user to upload an onboarding file.
    if !c.idp {
        ui.add_space(12.0);
        ui.label("Has a colleague sent you an onboarding file?");
        if ui.button("Import an onboarding file…").clicked() {
            action = Some(SettingsAction::Import);
        }
    }

    action
}
