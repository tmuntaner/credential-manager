use std::error::Error;
use thiserror::Error;

/// Provides the OAuth `state` tying an authorization response to its request.
#[cfg_attr(test, mockall::automock)]
pub trait StateSource {
    /// A new, unguessable value for every call.
    fn state(&self) -> Result<String, StateError>;
}

/// The error for an authorization state.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StateError {
    #[error(transparent)]
    Failed(Box<dyn Error + Send + Sync>),
}
