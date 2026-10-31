use crate::domain::models::secret::SafeSecret;
use async_trait::async_trait;
use std::error::Error;
use thiserror::Error;

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
#[async_trait(?Send)]
pub trait SecretStore: Send + Sync {
    /// Retrieves a secret by key. Returns `Ok(None)` if no secret exists for the key.
    async fn get(&self, key: &SecretKey) -> Result<Option<SafeSecret>, SecretStoreError>;

    /// Stores a secret at the given key.
    async fn set(&self, key: &SecretKey, value: SafeSecret) -> Result<(), SecretStoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted() {
        let secret = SafeSecret::new("super-secret-password");
        assert_eq!(format!("{secret:?}"), "SafeSecret(\"[REDACTED]\")");
    }

    #[test]
    fn secret_exposes_value_correctly() {
        let secret = SafeSecret::new("my-secret");
        assert_eq!(secret.expose_secret(), "my-secret");
        assert_eq!(secret.expose_secret(), "my-secret");
        assert_eq!(secret.into_inner(), "my-secret");
    }

    #[test]
    fn secret_key_initialization() {
        let key = SecretKey::new("alice", "c9s -- example.com", "c9s");
        assert_eq!(key.username, "alice");
        assert_eq!(key.service, "c9s -- example.com");
        assert_eq!(key.application, "c9s");
    }

    #[tokio::test]
    async fn mock_secret_store_works() {
        let mut mock = MockSecretStore::new();
        let key = SecretKey::new("alice", "svc", "app");
        let key_clone = key.clone();

        mock.expect_get()
            .withf(move |k| k == &key_clone)
            .times(1)
            .returning(|_| Ok(Some(SafeSecret::new("p@ssword"))));

        let res = mock.get(&key).await.unwrap();
        assert_eq!(res.unwrap().expose_secret(), "p@ssword");
    }
}
