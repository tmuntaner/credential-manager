use crate::core::ui::a11y;
use crate::core::ui::errors::error_color;
use eframe::egui::{RichText, Ui};

#[derive(Default)]
pub struct Status {
    message: String,
    is_error: bool,
}

impl Status {
    /// Adds a message to the status.
    pub fn say(&mut self, message: impl Into<String>) {
        self.message = message.into();
        self.is_error = false;
    }

    /// Adds an error message to the status.
    pub fn fail(&mut self, message: impl Into<String>) {
        self.message = message.into();
        self.is_error = true;
    }

    /// Render the status message.
    pub fn ui(&self, ui: &mut Ui) {
        // if it's an error, give it some error styling. If not, just normal rich text.
        let text = if self.is_error {
            RichText::new(format!("Error: {}", self.message))
                .color(error_color(ui))
                .strong()
        } else {
            RichText::new(&self.message)
        };

        let label = ui.label(text);
        a11y::live(ui, &label);
    }
}
