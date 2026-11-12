//! The places of the window, and the sidebar that switches between them.

use super::focus::{Focus, FocusTarget};
use eframe::egui::{Layout, RichText, Ui};

/// A page of the settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    Idp,
    Aws,
    Rancher,
    Share,
    Security,
}

impl Section {
    pub const ALL: [Section; 5] = [
        Section::Idp,
        Section::Aws,
        Section::Rancher,
        Section::Security,
        Section::Share,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Section::Idp => "Identity providers",
            Section::Aws => "AWS accounts",
            Section::Rancher => "Rancher",
            Section::Share => "Import / Export",
            Section::Security => "Security",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// The "Get started" checklist.
    Setup,
    Credentials,
    Settings(Section),
}

impl Route {
    /// The places outside of the settings.
    pub const TOP: [Route; 2] = [Route::Setup, Route::Credentials];

    pub fn name(self) -> &'static str {
        match self {
            Route::Setup => "Setup",
            Route::Credentials => "Credentials",
            Route::Settings(section) => section.name(),
        }
    }
}

/// The state of the sidebar
#[derive(Clone, Copy, Default)]
pub struct SidebarState<'a> {
    /// Whether the setup checklist is still offered.
    pub setup: bool,
    /// The sections that still need something done.
    pub pending: &'a [Section],
}

/// The sidebar
pub fn sidebar(
    ui: &mut Ui,
    current: Route,
    focus: &mut Focus,
    state: SidebarState<'_>,
) -> Option<Route> {
    let mut chosen = None;
    let mut entry = |ui: &mut Ui, route: Route, pending: bool| {
        ui.horizontal(|ui| {
            let button = ui.selectable_label(current == route, route.name());
            focus.apply(FocusTarget::Nav(route), &button);
            if button.clicked() {
                chosen = Some(route);
            }
            if pending {
                ui.label(RichText::new("!").strong())
                    .on_hover_text("Still to do");
            }
        });
    };

    ui.with_layout(Layout::top_down(eframe::egui::Align::Min), |ui| {
        if state.setup || current == Route::Setup {
            entry(ui, Route::Setup, false);
        }
        entry(ui, Route::Credentials, false);

        ui.add_space(8.0);
        ui.label(RichText::new("Settings").weak());
        for section in Section::ALL {
            entry(
                ui,
                Route::Settings(section),
                state.pending.contains(&section),
            );
        }
    });

    chosen
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<Route> {
        Route::TOP
            .into_iter()
            .chain(Section::ALL.into_iter().map(Route::Settings))
            .collect()
    }

    #[test]
    fn every_place_is_in_the_sidebar_once_with_its_own_name() {
        let all = all();
        for (i, route) in all.iter().enumerate() {
            assert_eq!(all.iter().filter(|r| *r == route).count(), 1);
            assert!(!route.name().is_empty());
            assert!(all[..i].iter().all(|r| r.name() != route.name()));
        }
    }
}
