//! The places of the window, and the bar that switches between them.

use super::focus::{Focus, FocusTarget};
use eframe::egui::Ui;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Home,
    SettingsIdp,
    SettingsAws,
    SettingsRancher,
}

impl Route {
    pub const ALL: [Route; 4] = [
        Route::Home,
        Route::SettingsIdp,
        Route::SettingsAws,
        Route::SettingsRancher,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Route::Home => "Home",
            Route::SettingsIdp => "Identity providers",
            Route::SettingsAws => "AWS accounts",
            Route::SettingsRancher => "Rancher",
        }
    }
}

/// The navigation bar
pub fn bar(ui: &mut Ui, current: Route, focus: &mut Focus) -> Option<Route> {
    let mut chosen = None;

    ui.horizontal_wrapped(|ui| {
        for route in Route::ALL {
            let button = ui.selectable_label(current == route, route.name());
            focus.apply(FocusTarget::Nav(route), &button);

            if button.clicked() {
                chosen = Some(route);
            }
        }
    });

    chosen
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_place_is_in_the_bar_once_with_its_own_name() {
        for (i, route) in Route::ALL.iter().enumerate() {
            assert_eq!(Route::ALL.iter().filter(|r| *r == route).count(), 1);
            assert!(!route.name().is_empty());
            assert!(Route::ALL[..i].iter().all(|r| r.name() != route.name()));
        }
    }
}
