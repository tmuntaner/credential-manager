// No console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> eframe::Result {
    // Logs go to stderr, and are set with `RUST_LOG`.
    env_logger::init();

    c9s_egui::run()
}
