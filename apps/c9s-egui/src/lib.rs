//! The c9s desktop app (egui)
//! It's a driving adapter for the `c9s` library.
//!
//! - [`app`]: the egui application shell.
//! - `settings`: the pages to manage c9s settings.
//! - `prompts`: the questions and notices for flows.
//! - `ui`: reusable widgets

mod core;
pub mod inbound;
pub mod outbound;

pub use inbound::settings::{Enroller, FilePicker, Pick};

use crate::inbound::app::C9sApp;
use c9s::outbound::config::config_store::ConfigFileAdapter;
use inbound::settings;
use outbound::prompts;

const WINDOW_SIZE: [f32; 2] = [900.0, 700.0];

pub fn run() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("c9s")
            .with_app_id("c9s")
            .with_inner_size(WINDOW_SIZE)
            .with_min_inner_size([420.0, 360.0]),
        ..Default::default()
    };

    eframe::run_native(
        "c9s",
        options,
        Box::new(|cc| {
            let store = ConfigFileAdapter::in_user_config_dir()?;
            let (bridge, prompts) = prompts::connect(cc.egui_ctx.clone());
            let settings = settings::SettingsState::new(store, bridge.clone());
            Ok(Box::new(C9sApp::new(
                cc.egui_ctx.clone(),
                settings,
                bridge,
                prompts,
            )))
        }),
    )
}
