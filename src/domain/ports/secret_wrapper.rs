use crate::domain::models::secret::SafeSecret;
use async_trait::async_trait;
use std::error::Error;
use thiserror::Error;

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
#[async_trait(?Send)]
pub trait SecretWrapper: Send + Sync {
    /// Wraps `plaintext` using authenticated encryption bound to `aad`.
    async fn wrap(&self, aad: &[u8], plaintext: &SafeSecret) -> Result<SafeSecret, WrapError>;

    /// Unwraps `ciphertext` verifying the authenticity against `aad`.
    async fn unwrap(&self, aad: &[u8], ciphertext: &SafeSecret) -> Result<SafeSecret, WrapError>;
}
