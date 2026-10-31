use crate::domain::ports::user_interaction::InteractionError;
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PinentryError {
    #[error("could not start pinentry: {0}")]
    NotStarted(String),

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("pinentry exited unexpectedly ({0})")]
    Exited(String),

    #[error("pinentry did not answer within {0} seconds")]
    TimedOut(u64),

    #[error("pinentry sent something unexpected: {0}")]
    Protocol(String),

    #[error("pinentry command failed: {0}")]
    Command(String),

    #[error("pinentry returned an invalid UTF-8 secret")]
    NotUtf8,

    #[error("the user cancelled the prompt")]
    Cancelled,
}

impl From<PinentryError> for InteractionError {
    fn from(e: PinentryError) -> Self {
        match e {
            PinentryError::NotStarted(reason) => {
                log::debug!("pinentry is unavailable: {reason}");
                InteractionError::Unavailable
            }
            PinentryError::Cancelled => InteractionError::Cancelled,
            e => InteractionError::failed(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_errors_to_interaction_errors() {
        assert!(matches!(
            InteractionError::from(PinentryError::NotStarted("x".into())),
            InteractionError::Unavailable
        ));
        assert!(matches!(
            InteractionError::from(PinentryError::Cancelled),
            InteractionError::Cancelled
        ));
        assert!(matches!(
            InteractionError::from(PinentryError::NotUtf8),
            InteractionError::Failed(_)
        ));
    }
}
