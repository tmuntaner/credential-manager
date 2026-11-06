//! The questions and notices of an application flow.
//! For example, it will ask the user a password, one-time code, or even just provide a notice.
//!
//! [`WindowInteraction`] and [`WindowNotifier`] implement the driven ports. Each question becomes a
//! [`UiEvent`] for the adapter's [`PromptSink`] and waits for the answer, which comes back through
//! [`PromptBridge::answer`]. The bridge only needs a sink, so it runs without a window in tests.

mod bridge;
mod model;

pub use crate::domain::models::user_interaction::NoticeLevel;
pub use bridge::{AnswerError, PromptBridge, PromptSink, WindowInteraction, WindowNotifier};
pub use model::{
    NoticeEvent, NoticeId, PromptAnswer, PromptId, PromptRequest, SecretText, UiEvent,
};
