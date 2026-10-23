use std::error::Error;
use thiserror::Error;

/// Hands out the OAuth `state` that ties an authorization response to its request.
#[cfg_attr(test, mockall::automock)]
pub trait StateSource {
    /// A new, unguessable value for every call.
    fn state(&self) -> Result<String, StateError>;
}

/// Why no state could be made.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StateError {
    #[error(transparent)]
    Failed(Box<dyn Error + Send + Sync>),
}
