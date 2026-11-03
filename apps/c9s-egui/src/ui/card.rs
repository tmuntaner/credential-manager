use eframe::egui::{self, Response, RichText, Ui};

const ENTRY_WIDTH: f32 = 720.0;

/// The heading of a card
pub fn card_header(ui: &mut Ui, title: &str, intro: &str) {
    ui.label(RichText::new(title).size(22.0).strong());
    ui.label(RichText::new(intro).weak());
    ui.add_space(12.0);
}

pub fn card<R>(
    ui: &mut Ui,
    title: &str,
    badges: &[&str],
    details: &[String],
    buttons: impl FnOnce(&mut Ui) -> R,
) -> R {
    egui::Frame::group(ui.style())
        .inner_margin(12.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width().min(ENTRY_WIDTH));
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(title).strong().size(17.0));
                for badge in badges {
                    // A badge says what it is in words, with a frame, not colour only.
                    egui::Frame::new()
                        .stroke(ui.visuals().widgets.noninteractive.fg_stroke)
                        .corner_radius(8.0)
                        .inner_margin(egui::Margin::symmetric(6, 1))
                        .show(ui, |ui| ui.label(RichText::new(*badge).strong()));
                }
            });
            for line in details {
                ui.label(line);
            }
            ui.add_space(4.0);
            ui.horizontal_wrapped(buttons).inner
        })
        .inner
}

pub fn card_button(ui: &mut Ui, text: &str, entry: &str) -> Response {
    ui.button(text).accessible_name(format!("{text} {entry}"))
}
