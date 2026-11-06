//! The c9s desktop app (egui)
//! It's a driving adapter for the `c9s` library.
//!
//! - [`app`]: the egui application shell.
//! - `settings`: the pages to manage c9s settings.
//! - `prompts`: the questions and notices for flows.
//! - `ui`: reusable widgets

pub mod app;
mod prompts;
mod settings;
mod ui;

pub use settings::Enroller;

use app::C9sApp;
use c9s::outbound::config::config_store::ConfigFileAdapter;

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
            Ok(Box::new(C9sApp::new(cc.egui_ctx.clone(), store)))
        }),
    )
}
