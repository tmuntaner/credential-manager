use crate::core::ui::dialog::DialogOutcome;
use crate::core::ui::dialog::dialog;
use c9s::app::settings::{ExportChoice, SettingsView};
use eframe::egui::Context;

pub struct App {
    /// The url which identifies the app
    pub key: String,
    pub label: String,
    pub on: bool,
}

pub struct Provider {
    pub name: String,
    pub on: bool,
    pub aws: Vec<App>,
    pub rancher: Vec<App>,
}

/// Choose which apps to export. We always include the identity provider, and allow the user to select
/// which apps should be included.
pub struct ExportDialog {
    pub idps: Vec<Provider>,
}

impl ExportDialog {
    pub fn new(view: &SettingsView) -> Self {
        let idps = view
            .idps
            .iter()
            .map(|idp| Provider {
                name: idp.name.clone(),
                on: true,
                aws: view
                    .aws_apps
                    .iter()
                    .filter(|a| a.idp == idp.name)
                    .map(|a| App {
                        key: a.app_url.clone(),
                        label: format!("AWS: {}", a.app_url),
                        on: true,
                    })
                    .collect(),
                rancher: view
                    .rancher_hosts
                    .iter()
                    .filter(|r| r.idp == idp.name)
                    .map(|r| App {
                        key: r.url.clone(),
                        label: format!("Rancher: {}", r.url),
                        on: true,
                    })
                    .collect(),
            })
            .collect();
        Self { idps }
    }

    /// Returns what the user chose to export.
    pub fn chosen(&self) -> ExportChoice {
        let on = || self.idps.iter().filter(|i| i.on);

        ExportChoice::new(
            on().map(|i| i.name.clone()).collect(),
            on().flat_map(|i| &i.aws)
                .filter(|a| a.on)
                .map(|a| a.key.clone())
                .collect(),
            on().flat_map(|i| &i.rancher)
                .filter(|a| a.on)
                .map(|a| a.key.clone())
                .collect(),
        )
    }

    pub fn ui(&mut self, ctx: &Context) -> DialogOutcome {
        let nothing = self.chosen().idps.is_empty();
        let outcome = dialog(
            ctx,
            "export",
            "Export onboarding file",
            "Choose file…",
            |ui| {
                ui.label(
                    "Choose the identity providers and the applications to share. \
                     User specific settings, like keyring configuration and enrolled security key are never exported.",
                );
                ui.add_space(8.0);

                for idp in &mut self.idps {
                    ui.checkbox(&mut idp.on, idp.name.as_str());
                    ui.add_enabled_ui(idp.on, |ui| {
                        ui.indent(idp.name.as_str(), |ui| {
                            for app in idp.aws.iter_mut().chain(idp.rancher.iter_mut()) {
                                ui.checkbox(&mut app.on, app.label.as_str());
                            }
                        });
                    });
                }
                false
            },
        );

        // Nothing is chosen, so there is nothing to write.
        if outcome == DialogOutcome::Submit && nothing {
            return DialogOutcome::Nothing;
        }

        outcome
    }
}
