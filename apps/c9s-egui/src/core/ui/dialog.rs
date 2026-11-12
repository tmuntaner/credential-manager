use super::heading;
use eframe::egui::{self, Id, Modal, Response, RichText, ScrollArea, Ui};
use std::fmt::Debug;
use std::hash::Hash;

/// The widest a normal popup gets (e.g., a question or confirmation).
const POPUP_WIDTH: f32 = 520.0;

/// Widest a dialog gets.
const DIALOG_WIDTH: f32 = 560.0;

/// The padding along a dialog.
const DIALOG_PADDING: f32 = 200.0;

/// The min length of a dialog.
const MIN_BODY: f32 = 120.0;

/// Margins of a modal.
const MODAL_MARGIN: f32 = 48.0;

/// The outcome of the dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogOutcome {
    Nothing,
    Submit,
    Cancel,
}

/// Renders a modal over the window, blocking what's under it, and settles to its size.
/// It returns whether it should close.
pub fn modal(ctx: &egui::Context, id: impl Hash + Debug, body: impl FnOnce(&mut Ui)) -> bool {
    let response = Modal::new(Id::unique(("modal", id))).show(ctx, |ui| {
        ui.set_max_width(POPUP_WIDTH.min(ctx.content_rect().width() - MODAL_MARGIN));
        body(ui);
    });

    settle(ctx, &response.response);

    response.should_close()
}

/// Renders a new diagram modal and returns the outcome of the dialog.
pub fn dialog(
    ctx: &egui::Context,
    id: &str,
    title: &str,
    submit_label: &str,
    body: impl FnOnce(&mut Ui) -> bool,
) -> DialogOutcome {
    let mut outcome = DialogOutcome::Nothing;

    let close = modal(ctx, ("dialog", id), |ui| {
        ui.set_width(DIALOG_WIDTH.min(ctx.content_rect().width() - MODAL_MARGIN));

        heading(ui, title);
        ui.add_space(8.0);

        // The body can scroll, so set the max height to keep everything within the dialog.
        let max_height = (ctx.content_rect().height() - DIALOG_PADDING).max(MIN_BODY);
        let entered = ScrollArea::vertical()
            .max_height(max_height)
            .show(ui, body)
            .inner;

        ui.separator();

        ui.horizontal_wrapped(|ui| {
            if ui.button(RichText::new(submit_label).strong()).clicked() || entered {
                outcome = DialogOutcome::Submit;
            }
            if ui.button("Cancel").clicked() {
                outcome = DialogOutcome::Cancel;
            }
        });
    });

    if outcome == DialogOutcome::Nothing && close {
        outcome = DialogOutcome::Cancel;
    }

    outcome
}

/// Egui measures a new area from the frame before, so a dialog takes a few frames to settle into place.
/// Without this, it would wait for the next mouse move.
fn settle(ctx: &egui::Context, modal: &Response) {
    let key = Id::unique(("modal-rect", modal.id));

    let moved = ctx.data_mut(|d| {
        let last = d.get_temp::<egui::Rect>(key);
        d.insert_temp(key, modal.rect);
        last != Some(modal.rect)
    });

    if moved {
        ctx.request_repaint();
    }
}
