mod prompt;
mod question;
mod sink;

pub use prompt::{Bridge, Prompts};

use crate::prompts::question::{OpenQuestion, PromptField};
use crate::ui::a11y;
use crate::ui::dialog::{self, DialogOutcome};
use crate::ui::errors::{general_error, FormErrors};
use crate::ui::field::{submitted, text_field, TextOptions};
use crate::ui::heading;
use c9s::app::prompts::{
    NoticeEvent, NoticeLevel, PromptAnswer, PromptBridge, PromptRequest, SecretText,
};
use c9s::domain::models::user_interaction::SecretKind;
use eframe::egui::{Context, RichText};
use sink::ChannelSink;
use std::sync::mpsc::{self};
use std::sync::Arc;

/// Makes the bridge for flows to ask through, and the part of the window that shows what they ask.
pub fn connect(ctx: Context) -> (Bridge, Prompts) {
    let (events, received) = mpsc::channel();

    let bridge: Bridge = Arc::new(PromptBridge::new(ChannelSink::new(events, ctx)));

    let prompts = Prompts::new(bridge.clone(), received);

    (bridge, prompts)
}

/// The placeholder of the input for what is asked.
fn secret_hint(kind: SecretKind) -> Option<&'static str> {
    match kind {
        SecretKind::Totp => Some("6-digit code"),
        SecretKind::Pin => Some("Security key PIN"),
        _ => None,
    }
}

fn show(ctx: &Context, open: &mut OpenQuestion) -> Option<PromptAnswer> {
    let first = std::mem::take(&mut open.first_frame);

    match &open.request {
        PromptRequest::Secret {
            id,
            title,
            description,
            label,
            error,
            kind,
        } => {
            let mut errors: FormErrors<PromptField> =
                error.as_ref().map(FormErrors::general).unwrap_or_default();

            let outcome = dialog::dialog(ctx, &format!("prompt-{id}"), title, "Continue", |ui| {
                if let Some(description) = description {
                    ui.label(description);
                }

                general_error(ui, &errors);

                let input = text_field(
                    ui,
                    &mut errors,
                    PromptField::Secret,
                    label,
                    &mut open.secret,
                    TextOptions {
                        password: *kind != SecretKind::Totp,
                        placeholder: secret_hint(*kind),
                        autofocus: first,
                        ..Default::default()
                    },
                );
                submitted(&input)
            });

            match outcome {
                DialogOutcome::Nothing => None,
                DialogOutcome::Cancel => Some(PromptAnswer::Cancel),
                DialogOutcome::Submit => Some(PromptAnswer::Secret {
                    value: SecretText::new(std::mem::take(&mut open.secret)),
                }),
            }
        }
        PromptRequest::Confirm {
            id,
            title,
            description,
            ok_label,
            cancel_label,
        } => {
            let mut answer = None;
            let close = dialog::modal(ctx, ("prompt", id), |ui| {
                heading(ui, title);
                ui.label(description);
                ui.separator();
                ui.horizontal_wrapped(|ui| {
                    if ui.button(ok_label.as_deref().unwrap_or("Yes")).clicked() {
                        answer = Some(PromptAnswer::Confirm { accepted: true });
                    }
                    let no = ui.button(cancel_label.as_deref().unwrap_or("No"));
                    if first {
                        no.request_focus();
                    }
                    if no.clicked() {
                        answer = Some(PromptAnswer::Confirm { accepted: false });
                    }
                });
            });
            answer.or_else(|| close.then_some(PromptAnswer::Cancel))
        }
        PromptRequest::Choice {
            id,
            title,
            description,
            options,
        } => {
            let mut answer = None;
            let close = dialog::modal(ctx, ("prompt", id), |ui| {
                heading(ui, title);
                ui.label(RichText::new(description).strong());
                for (index, option) in options.iter().enumerate() {
                    let radio = ui.radio_value(&mut open.choice, index, option);
                    if first && index == 0 {
                        radio.request_focus();
                    }
                }
                ui.separator();
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Continue").clicked() {
                        answer = Some(PromptAnswer::Choice { index: open.choice });
                    }
                    if ui.button("Cancel").clicked() {
                        answer = Some(PromptAnswer::Cancel);
                    }
                });
            });
            answer.or_else(|| close.then_some(PromptAnswer::Cancel))
        }
    }
}

fn show_notice(ctx: &Context, notice: &NoticeEvent) -> bool {
    let title = match notice.level {
        NoticeLevel::Info => "Action needed",
        NoticeLevel::Warning => "Warning",
        NoticeLevel::Error => "Problem",
    };
    let mut clicked = false;
    let close = dialog::modal(ctx, "notice", |ui| {
        heading(ui, title);
        let message = ui.label(&notice.message);
        a11y::live(ui, &message);
        if notice.cancellable {
            ui.label(
                RichText::new(
                    "The security key stops waiting when you cancel. It also stops by itself after one minute.",
                )
                .weak(),
            );
        }
        ui.separator();
        let button = ui.button(if notice.cancellable {
            "Cancel"
        } else {
            "Close"
        });
        button.request_focus();
        clicked = button.clicked();
    });
    clicked || close
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_kind_of_secret_has_its_hint() {
        assert_eq!(secret_hint(SecretKind::Totp), Some("6-digit code"));
        assert_eq!(secret_hint(SecretKind::Pin), Some("Security key PIN"));
        assert_eq!(secret_hint(SecretKind::Password), None);
    }
}
