//! Conversions between the `keyring` crate errors and domain port errors.

use crate::domain::ports::secret_store::SecretStoreError;

impl From<keyring::KeyringError> for SecretStoreError {
    fn from(err: keyring::KeyringError) -> Self {
        SecretStoreError::Failed(Box::new(err))
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn converts_keyring_error_to_secret_store_error() {
        let err = SecretStoreError::from(keyring::KeyringError::NoSecret);
        assert!(matches!(err, SecretStoreError::Failed(_)));
        assert_eq!(err.to_string(), "could not get secret");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn converts_keyring_error_to_secret_store_error() {
        let err = SecretStoreError::from(keyring::KeyringError::InvalidUtf8(
            String::from_utf8(vec![0xFF]).unwrap_err(),
        ));
        assert!(matches!(err, SecretStoreError::Failed(_)));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn converts_keyring_error_to_secret_store_error() {
        let err = SecretStoreError::from(keyring::KeyringError::SaveCredential);
        assert!(matches!(err, SecretStoreError::Failed(_)));
        assert_eq!(err.to_string(), "failed to save windows credential");
    }
}
