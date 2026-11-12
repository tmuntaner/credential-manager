pub mod a11y;
pub mod card;
pub mod dialog;
pub mod errors;
pub mod field;
pub mod select;
pub mod style;

use eframe::egui::{Response, RichText, Ui};

pub fn heading(ui: &mut Ui, text: &str) -> Response {
    ui.label(RichText::new(text).heading().strong())
}
