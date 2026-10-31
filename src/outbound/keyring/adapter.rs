use crate::domain::models::secret::SafeSecret;
use crate::domain::ports::secret_store::{SecretKey, SecretStore, SecretStoreError};
use async_trait::async_trait;
use keyring::KeyringClient;

/// Adapter implementing `SecretStore` backed by the OS keyring via `keyring::KeyringClient`.
#[derive(Default, Debug, Clone)]
pub struct KeyringSecretStore;

impl KeyringSecretStore {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait(?Send)]
impl SecretStore for KeyringSecretStore {
    async fn get(&self, key: &SecretKey) -> Result<Option<SafeSecret>, SecretStoreError> {
        let client = KeyringClient::new(&key.username, &key.service, &key.application)?;
        let val = client.get_password()?;
        Ok(val.map(SafeSecret::new))
    }

    async fn set(&self, key: &SecretKey, value: SafeSecret) -> Result<(), SecretStoreError> {
        let client = KeyringClient::new(&key.username, &key.service, &key.application)?;
        client.set_password(value.into_inner())?;
        Ok(())
    }
}
