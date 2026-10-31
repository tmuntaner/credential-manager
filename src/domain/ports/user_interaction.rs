use crate::domain::models::secret::SafeSecret;
use crate::domain::models::user_interaction::{ChoicePrompt, ConfirmPrompt, SecretPrompt};
use async_trait::async_trait;
use std::error::Error;
use thiserror::Error;

/// A user interaction error
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum InteractionError {
    /// The user canceled the prompt.
    #[error("cancelled by the user")]
    Cancelled,

    /// The prompt is unavailable
    #[error("user interaction is unavailable")]
    Unavailable,

    /// Other prompt errors
    #[error(transparent)]
    Failed(Box<dyn Error + Send + Sync>),
}

impl InteractionError {
    pub fn failed<E>(err: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        Self::Failed(err.into())
    }
}

#[cfg_attr(test, mockall::automock)]
#[async_trait(?Send)]
pub trait UserInteraction: Send + Sync {
    /// Asks the user for a secret, e.g., a PIN or password.
    async fn ask_secret(&self, prompt: SecretPrompt) -> Result<SafeSecret, InteractionError>;

    /// Asks the user a yes or no question
    async fn confirm(&self, prompt: ConfirmPrompt) -> Result<bool, InteractionError>;

    /// Asks to pick an option and returns its index.
    async fn choose(&self, prompt: &ChoicePrompt) -> Result<usize, InteractionError>;
}
