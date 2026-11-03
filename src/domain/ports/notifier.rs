use crate::domain::models::user_interaction::UserNotice;
use async_trait::async_trait;
use std::error::Error;
use thiserror::Error;

/// A notification error
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NotifyError {
    /// The notifier cannot show notices here.
    #[error("notifications are unavailable")]
    Unavailable,

    /// Other notification errors
    #[error(transparent)]
    Failed(Box<dyn Error + Send + Sync>),
}

impl NotifyError {
    pub fn failed<E>(err: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        Self::Failed(err.into())
    }
}

#[cfg_attr(test, mockall::automock)]
#[async_trait(?Send)]
pub trait Notifier: Send + Sync {
    /// Shows the user a notice and does not wait for an answer.
    async fn notify(&self, notice: &UserNotice) -> Result<(), NotifyError>;

    /// Resolves when the user gives up on a notice that [`awaits an action`](UserNotice::awaiting_action),
    /// e.g., by cancelling it. Whoever waits for the action then stops waiting.
    ///
    /// It must resolve only after the user acts on a notice shown for this operation, and never for earlier or
    /// unrelated notices. It may be polled before the notice is shown.
    ///
    /// The default never resolves: notifiers that cannot be cancelled by the user do not need to implement it.
    async fn dismissed(&self) {
        std::future::pending::<()>().await
    }
}
