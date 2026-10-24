use std::error::Error;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Key identifying a secret in the store.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct SecretKey {
    pub username: String,
    pub service: String,
    pub application: String,
}

impl SecretKey {
    pub fn new(
        username: impl Into<String>,
        service: impl Into<String>,
        application: impl Into<String>,
    ) -> Self {
        Self {
            username: username.into(),
            service: service.into(),
            application: application.into(),
        }
    }

    /// Computes the Additional Authenticated Data (AAD) bound to this secret key.
    pub fn aad(&self) -> Vec<u8> {
        format!("{}:{}:{}", self.username, self.service, self.application).into_bytes()
    }
}

/// A secret value whose in-memory representation is zeroized on drop and redacted in debug formatting.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Secret(String);

impl Secret {
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Secret").field(&"[REDACTED]").finish()
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

/// An error interacting with the secret store.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SecretStoreError {
    #[error("secret store is unavailable")]
    Unavailable,

    #[error(transparent)]
    Failed(Box<dyn Error + Send + Sync>),
}

impl SecretStoreError {
    pub fn failed<E>(err: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        Self::Failed(err.into())
    }
}

impl From<crate::domain::ports::secret_wrapper::WrapError> for SecretStoreError {
    fn from(err: crate::domain::ports::secret_wrapper::WrapError) -> Self {
        SecretStoreError::Failed(Box::new(err))
    }
}

/// Driven port for storing and retrieving secrets.
#[cfg_attr(test, mockall::automock)]
pub trait SecretStore: Send + Sync {
    /// Retrieves a secret by key. Returns `Ok(None)` if no secret exists for the key.
    fn get(&self, key: &SecretKey) -> Result<Option<Secret>, SecretStoreError>;

    /// Stores a secret at the given key.
    fn set(&self, key: &SecretKey, value: Secret) -> Result<(), SecretStoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted() {
        let secret = Secret::new("super-secret-password");
        assert_eq!(format!("{secret:?}"), "Secret(\"[REDACTED]\")");
    }

    #[test]
    fn secret_exposes_value_correctly() {
        let secret = Secret::new("my-secret");
        assert_eq!(secret.expose_secret(), "my-secret");
        assert_eq!(secret.as_str(), "my-secret");
        assert_eq!(secret.into_inner(), "my-secret");
    }

    #[test]
    fn secret_key_initialization() {
        let key = SecretKey::new("alice", "c9s -- example.com", "c9s");
        assert_eq!(key.username, "alice");
        assert_eq!(key.service, "c9s -- example.com");
        assert_eq!(key.application, "c9s");
    }

    #[test]
    fn mock_secret_store_works() {
        let mut mock = MockSecretStore::new();
        let key = SecretKey::new("alice", "svc", "app");
        let key_clone = key.clone();

        mock.expect_get()
            .withf(move |k| k == &key_clone)
            .times(1)
            .returning(|_| Ok(Some(Secret::new("p@ssword"))));

        let res = mock.get(&key).unwrap();
        assert_eq!(res.unwrap().expose_secret(), "p@ssword");
    }
}
