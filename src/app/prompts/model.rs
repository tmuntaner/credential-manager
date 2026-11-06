use crate::domain::models::user_interaction::{NoticeLevel, SecretKind};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The id of an open prompt.
pub type PromptId = u64;

/// The id of a notice that waits for the user to act. Cancelling is done per notice.
pub type NoticeId = u64;

/// The secret text the user typed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretText(String);

impl SecretText {
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    /// Moves the text out, into the typed secret of the domain.
    pub fn into_secret(mut self) -> crate::domain::models::secret::SafeSecret {
        crate::domain::models::secret::SafeSecret::new(std::mem::take(&mut self.0))
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretText([REDACTED])")
    }
}

/// A prompt to the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PromptRequest {
    Secret {
        id: PromptId,
        title: String,
        description: Option<String>,
        label: String,
        error: Option<String>,
        /// What is asked for, so the window can hint at it.
        kind: SecretKind,
    },
    Confirm {
        id: PromptId,
        title: String,
        description: String,
        ok_label: Option<String>,
        cancel_label: Option<String>,
    },
    Choice {
        id: PromptId,
        title: String,
        description: String,
        options: Vec<String>,
    },
}

impl PromptRequest {
    pub fn id(&self) -> PromptId {
        match self {
            Self::Secret { id, .. } | Self::Confirm { id, .. } | Self::Choice { id, .. } => *id,
        }
    }
}

/// The answer from the user.
#[derive(Debug)]
pub enum PromptAnswer {
    Secret { value: SecretText },
    Confirm { accepted: bool },
    Choice { index: usize },
    Cancel,
}

/// A message that stays on the screen until it's replaced, dismissed, or cleared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoticeEvent {
    /// Identifies the notice, for [`crate::app::prompts::PromptBridge::cancel_notice`].
    pub id: NoticeId,
    pub level: NoticeLevel,
    pub message: String,
    /// A notice that waits for the user to act (touch the key). The user can cancel it.
    pub cancellable: bool,
}

/// An event that the prompt gives to the window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UiEvent {
    Prompt {
        prompt: PromptRequest,
    },
    /// The prompt is no longer needed (e.g., the flow ended), so the window can close it.
    Withdraw {
        id: PromptId,
    },
    Notice {
        notice: NoticeEvent,
    },
    ClearNotices,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_answer_is_not_printed() {
        let answer = PromptAnswer::Secret {
            value: SecretText::new("hunter2"),
        };

        assert!(!format!("{answer:?}").contains("hunter2"));
        assert!(!format!("{answer:#?}").contains("hunter2"));
    }

    #[test]
    fn a_prompt_has_its_id() {
        let prompt = PromptRequest::Choice {
            id: 7,
            title: String::new(),
            description: String::new(),
            options: vec![],
        };
        assert_eq!(prompt.id(), 7);
    }
}
