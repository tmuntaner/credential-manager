use crate::domain::ports::secret_store::{Secret, SecretKey, SecretStore, SecretStoreError};
use keyring::KeyringClient;

/// Adapter implementing `SecretStore` backed by the OS keyring via `keyring::KeyringClient`.
#[derive(Default, Debug, Clone)]
pub struct KeyringSecretStore;

impl KeyringSecretStore {
    pub fn new() -> Self {
        Self
    }
}

impl SecretStore for KeyringSecretStore {
    fn get(&self, key: &SecretKey) -> Result<Option<Secret>, SecretStoreError> {
        let client = KeyringClient::new(&key.username, &key.service, &key.application)?;
        let val = client.get_password()?;
        Ok(val.map(Secret::new))
    }

    fn set(&self, key: &SecretKey, value: Secret) -> Result<(), SecretStoreError> {
        let client = KeyringClient::new(&key.username, &key.service, &key.application)?;
        client.set_password(value.into_inner())?;
        Ok(())
    }
}
