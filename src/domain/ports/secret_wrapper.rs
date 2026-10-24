use std::error::Error;
use thiserror::Error;

use crate::domain::ports::secret_store::Secret;

/// Error wrapping or unwrapping a secret.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WrapError {
    #[error("YubiKey device is not present")]
    DeviceNotPresent,

    #[error("operation was cancelled or timed out")]
    Cancelled,

    #[error("secret payload is not wrapped")]
    NotWrapped,

    #[error("wrapped secret payload is corrupt")]
    Corrupt,

    #[error(transparent)]
    Failed(Box<dyn Error + Send + Sync>),
}

impl WrapError {
    pub fn failed<E>(err: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        Self::Failed(err.into())
    }
}

/// Driven port for wrapping (encrypting) and unwrapping (decrypting) secrets.
#[cfg_attr(test, mockall::automock)]
pub trait SecretWrapper: Send + Sync {
    /// Wraps `plaintext` using authenticated encryption bound to `aad`.
    fn wrap(&self, aad: &[u8], plaintext: &Secret) -> Result<Secret, WrapError>;

    /// Unwraps `ciphertext` verifying the authenticity against `aad`.
    fn unwrap(&self, aad: &[u8], ciphertext: &Secret) -> Result<Secret, WrapError>;
}
