use eframe::egui::accesskit::{Invalid, Live};
use eframe::egui::{Context, Response, Ui};

/// Marks a label as a live region, which the screen reader reads when we change it.
pub fn live(ui: &Ui, label: &Response) {
    ui.ctx().accesskit_node_builder(label.id, |node| {
        node.set_live(Live::Polite);
    });
}

/// Describes an input field for accessibility.
pub fn describe_input(
    ctx: &Context,
    input: &Response,
    label: &Response,
    hint: Option<&Response>,
    error: Option<&Response>,
) {
    ctx.accesskit_node_builder(input.id, |node| {
        node.clear_label();
        node.push_labelled_by(label.id.accesskit_id());
        if let Some(hint) = hint {
            node.push_described_by(hint.id.accesskit_id());
        }
        if let Some(error) = error {
            node.push_described_by(error.id.accesskit_id());
            node.set_invalid(Invalid::True);
        }
    });
}
