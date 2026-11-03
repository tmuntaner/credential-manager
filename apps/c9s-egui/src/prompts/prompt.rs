use crate::prompts::question::OpenQuestion;
use crate::prompts::sink::ChannelSink;
use crate::prompts::{show, show_notice};
use c9s::app::prompts::{AnswerError, NoticeEvent, PromptBridge, PromptId, UiEvent};
use eframe::egui::Context;
use std::collections::VecDeque;
use std::sync::mpsc::Receiver;
use std::sync::Arc;

pub type Bridge = Arc<PromptBridge<ChannelSink>>;

pub struct Prompts {
    bridge: Bridge,
    events: Receiver<UiEvent>,
    open: VecDeque<OpenQuestion>,
    notice: Option<NoticeEvent>,
}

impl Prompts {
    pub fn new(bridge: Bridge, events: Receiver<UiEvent>) -> Self {
        Self {
            bridge,
            events,
            open: VecDeque::new(),
            notice: None,
        }
    }

    /// Whether a question or a notice is on the screen.
    pub fn is_showing(&self) -> bool {
        !self.open.is_empty() || self.notice.is_some()
    }

    pub fn ui(&mut self, ctx: &Context) -> Option<String> {
        let mut status = None;

        // handle incoming events
        while let Ok(event) = self.events.try_recv() {
            match event {
                UiEvent::Prompt { prompt } => self.open.push_back(OpenQuestion::new(prompt)),
                UiEvent::Withdraw { id } => self.close(ctx, id),
                UiEvent::Notice { notice } => {
                    status = Some(notice.message.clone());
                    self.notice = Some(notice);
                }
                UiEvent::ClearNotices => self.notice = None,
            }
        }

        // if there is an open question, render it.
        if let Some(open) = self.open.front_mut() {
            if let Some(answer) = show(ctx, open) {
                let id = open.request.id();

                // No matter what the result is, the question should close.
                let result = self.bridge.answer(id, answer);
                self.close(ctx, id);
                status = answer_status(&result);
            }
        }

        // if there is a notice, show it.
        if let Some(notice) = &self.notice {
            if show_notice(ctx, notice) {
                if notice.cancellable {
                    self.bridge.cancel_notice(notice.id);
                    status = Some("Cancelled.".to_string());
                }
                self.notice = None;
            }
        }

        status
    }

    /// Closes a prompt.
    fn close(&mut self, ctx: &Context, id: PromptId) {
        if let Some(at) = self.open.iter().position(|o| o.request.id() == id) {
            if let Some(mut open) = self.open.remove(at) {
                open.wipe(ctx);
            }
        }
    }
}

/// What the status should be based on the user's answer.
/// This is used to let the user know about errors.
fn answer_status(result: &Result<(), AnswerError>) -> Option<String> {
    match result {
        Ok(()) | Err(AnswerError::Unknown) => None,
        Err(AnswerError::Mismatch) => {
            log::error!("the window answered a question with something that does not fit");
            Some("The answer could not be used.".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stale_question_closes_silently() {
        assert_eq!(answer_status(&Err(AnswerError::Unknown)), None);
        assert_eq!(answer_status(&Ok(())), None);
    }

    #[test]
    fn a_mismatch_is_reported() {
        assert!(answer_status(&Err(AnswerError::Mismatch)).is_some());
    }
}
