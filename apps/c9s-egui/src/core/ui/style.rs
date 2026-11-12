use eframe::egui::{self, Context, FontId, TextStyle};

pub fn apply(ctx: &Context) {
    ctx.all_styles_mut(|style| {
        style.text_styles = [
            (TextStyle::Heading, FontId::proportional(20.0)),
            (TextStyle::Body, FontId::proportional(16.0)),
            (TextStyle::Button, FontId::proportional(16.0)),
            (TextStyle::Monospace, FontId::monospace(15.0)),
            (TextStyle::Small, FontId::proportional(13.0)),
        ]
        .into();
        style.spacing.interact_size.y = 32.0;
        style.spacing.button_padding = egui::vec2(12.0, 6.0);
        style.spacing.item_spacing = egui::vec2(10.0, 8.0);
    });
}
