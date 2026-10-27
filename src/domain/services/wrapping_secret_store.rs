use crate::domain::models::secret::SafeSecret;
use crate::domain::ports::secret_store::{SecretKey, SecretStore, SecretStoreError};
use crate::domain::ports::secret_wrapper::{SecretWrapper, WrapError};
use async_trait::async_trait;

/// Policy for handling unwrapped (legacy plaintext) secrets in the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WrappingPolicy {
    /// Unwrapped secrets are accepted and read as-is (for migration).
    #[default]
    Lenient,
    /// Unwrapped secrets are rejected (treated as cache miss).
    Strict,
}

/// Decorator that transparently wraps and unwraps secrets stored in an underlying `SecretStore`.
pub struct WrappingSecretStore<S, W> {
    store: S,
    wrapper: W,
    policy: WrappingPolicy,
}

impl<S: SecretStore, W: SecretWrapper> WrappingSecretStore<S, W> {
    pub fn new(store: S, wrapper: W) -> Self {
        Self {
            store,
            wrapper,
            policy: WrappingPolicy::Lenient,
        }
    }

    pub fn with_policy(store: S, wrapper: W, policy: WrappingPolicy) -> Self {
        Self {
            store,
            wrapper,
            policy,
        }
    }

    pub fn policy(&self) -> WrappingPolicy {
        self.policy
    }
}

#[async_trait(?Send)]
impl<S: SecretStore, W: SecretWrapper> SecretStore for WrappingSecretStore<S, W> {
    async fn get(&self, key: &SecretKey) -> Result<Option<SafeSecret>, SecretStoreError> {
        let raw = self.store.get(key).await?;
        let raw = match raw {
            Some(raw) => raw,
            None => return Ok(None),
        };

        let aad = key.aad();
        match self.wrapper.unwrap(&aad, &raw).await {
            Ok(plaintext) => Ok(Some(plaintext)),
            Err(WrapError::NotWrapped) => match self.policy {
                WrappingPolicy::Lenient => {
                    log::warn!("a stored secret is not wrapped; it is accepted as it is");
                    Ok(Some(raw))
                }
                WrappingPolicy::Strict => Ok(None),
            },
            Err(WrapError::Corrupt) => Ok(None),
            Err(
                err @ (WrapError::DeviceNotPresent | WrapError::Cancelled | WrapError::Failed(_)),
            ) => Err(SecretStoreError::from(err)),
        }
    }

    async fn set(&self, key: &SecretKey, value: SafeSecret) -> Result<(), SecretStoreError> {
        let aad = key.aad();
        let wrapped = self.wrapper.wrap(&aad, &value).await?;
        self.store.set(key, wrapped).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ports::secret_store::MockSecretStore;
    use crate::domain::ports::secret_wrapper::MockSecretWrapper;

    #[tokio::test]
    async fn set_wraps_with_aad_and_stores_in_inner_store() {
        let mut mock_store = MockSecretStore::new();
        let mut mock_wrapper = MockSecretWrapper::new();

        let key = SecretKey::new("alice", "c9s -- auth", "c9s");
        let key_clone = key.clone();
        let expected_aad = key.aad();

        mock_wrapper
            .expect_wrap()
            .withf(move |aad, pt| aad == expected_aad && pt.expose_secret() == "my-password")
            .times(1)
            .returning(|_, _| Ok(SafeSecret::new("c9s-yk1:enc-ciphertext")));

        mock_store
            .expect_set()
            .withf(move |k, val| k == &key_clone && val.expose_secret() == "c9s-yk1:enc-ciphertext")
            .times(1)
            .returning(|_, _| Ok(()));

        let wrapping_store = WrappingSecretStore::new(mock_store, mock_wrapper);
        wrapping_store
            .set(&key, SafeSecret::new("my-password"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn get_unwraps_and_returns_plaintext() {
        let mut mock_store = MockSecretStore::new();
        let mut mock_wrapper = MockSecretWrapper::new();

        let key = SecretKey::new("alice", "c9s -- auth", "c9s");
        let key_clone = key.clone();
        let expected_aad = key.aad();

        mock_store
            .expect_get()
            .withf(move |k| k == &key_clone)
            .times(1)
            .returning(|_| Ok(Some(SafeSecret::new("c9s-yk1:enc-ciphertext"))));

        mock_wrapper
            .expect_unwrap()
            .withf(move |aad, ct| {
                aad == expected_aad && ct.expose_secret() == "c9s-yk1:enc-ciphertext"
            })
            .times(1)
            .returning(|_, _| Ok(SafeSecret::new("my-password")));

        let wrapping_store = WrappingSecretStore::new(mock_store, mock_wrapper);
        let result = wrapping_store.get(&key).await.unwrap();

        assert_eq!(result.unwrap().expose_secret(), "my-password");
    }

    #[tokio::test]
    async fn get_lenient_policy_returns_plaintext_on_not_wrapped() {
        let mut mock_store = MockSecretStore::new();
        let mut mock_wrapper = MockSecretWrapper::new();

        let key = SecretKey::new("alice", "c9s -- auth", "c9s");

        mock_store
            .expect_get()
            .times(1)
            .returning(|_| Ok(Some(SafeSecret::new("plain-password"))));

        mock_wrapper
            .expect_unwrap()
            .times(1)
            .returning(|_, _| Err(WrapError::NotWrapped));

        let wrapping_store =
            WrappingSecretStore::with_policy(mock_store, mock_wrapper, WrappingPolicy::Lenient);
        let result = wrapping_store.get(&key).await.unwrap();

        assert_eq!(result.unwrap().expose_secret(), "plain-password");
    }

    #[tokio::test]
    async fn get_strict_policy_returns_none_on_not_wrapped() {
        let mut mock_store = MockSecretStore::new();
        let mut mock_wrapper = MockSecretWrapper::new();

        let key = SecretKey::new("alice", "c9s -- auth", "c9s");

        mock_store
            .expect_get()
            .times(1)
            .returning(|_| Ok(Some(SafeSecret::new("plain-password"))));

        mock_wrapper
            .expect_unwrap()
            .times(1)
            .returning(|_, _| Err(WrapError::NotWrapped));

        let wrapping_store =
            WrappingSecretStore::with_policy(mock_store, mock_wrapper, WrappingPolicy::Strict);
        let result = wrapping_store.get(&key).await.unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn get_returns_none_on_corrupt_payload() {
        let mut mock_store = MockSecretStore::new();
        let mut mock_wrapper = MockSecretWrapper::new();

        let key = SecretKey::new("alice", "c9s -- auth", "c9s");

        mock_store
            .expect_get()
            .times(1)
            .returning(|_| Ok(Some(SafeSecret::new("c9s-yk1:corrupted"))));

        mock_wrapper
            .expect_unwrap()
            .times(1)
            .returning(|_, _| Err(WrapError::Corrupt));

        let wrapping_store = WrappingSecretStore::new(mock_store, mock_wrapper);
        let result = wrapping_store.get(&key).await.unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn get_propagates_device_not_present_error() {
        let mut mock_store = MockSecretStore::new();
        let mut mock_wrapper = MockSecretWrapper::new();

        let key = SecretKey::new("alice", "c9s -- auth", "c9s");

        mock_store
            .expect_get()
            .times(1)
            .returning(|_| Ok(Some(SafeSecret::new("c9s-yk1:enc"))));

        mock_wrapper
            .expect_unwrap()
            .times(1)
            .returning(|_, _| Err(WrapError::DeviceNotPresent));

        let wrapping_store = WrappingSecretStore::new(mock_store, mock_wrapper);
        let err = wrapping_store.get(&key).await.unwrap_err();

        assert!(err.to_string().contains("YubiKey device is not present"));
    }

    #[tokio::test]
    async fn get_propagates_cancelled_error() {
        let mut mock_store = MockSecretStore::new();
        let mut mock_wrapper = MockSecretWrapper::new();

        let key = SecretKey::new("alice", "c9s -- auth", "c9s");

        mock_store
            .expect_get()
            .times(1)
            .returning(|_| Ok(Some(SafeSecret::new("c9s-yk1:enc"))));

        mock_wrapper
            .expect_unwrap()
            .times(1)
            .returning(|_, _| Err(WrapError::Cancelled));

        let wrapping_store = WrappingSecretStore::new(mock_store, mock_wrapper);
        let err = wrapping_store.get(&key).await.unwrap_err();

        assert!(err.to_string().contains("cancelled or timed out"));
    }
}
