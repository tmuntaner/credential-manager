use crate::domain::models::aws::Credential;
use crate::domain::models::secret::SafeSecret;
use crate::domain::ports::secret_store::SecretStoreError;
use crate::domain::ports::secret_store::{SecretKey, SecretStore};
use serde::de::DeserializeOwned;
use serde::Serialize;
use time::OffsetDateTime;

/// An error with the cache.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CacheError {
    #[error("the secret store failed")]
    Store(#[source] SecretStoreError),
    #[error("could not encode the credential for the cache")]
    Encode(#[source] serde_json::Error),
    #[error("the cached credential is not readable")]
    Decode(#[source] serde_json::Error),
}

pub async fn get_cached_credential<T: DeserializeOwned>(
    key: &str,
    store: Option<&dyn SecretStore>,
) -> Result<Option<T>, CacheError> {
    let cached_credential = if let Some(store) = store {
        let service = format!("c9s credential -- {key}");
        let secret_key = SecretKey::new(key, &service, "c9s");
        store
            .get(&secret_key)
            .await
            .map_err(CacheError::Store)?
            .map(|s| s.into_inner())
    } else {
        None
    };

    if let Some(cached_credential) = cached_credential {
        let credentials: T =
            serde_json::from_str(cached_credential.as_str()).map_err(CacheError::Decode)?;

        return Ok(Some(credentials));
    }

    Ok(None)
}

pub async fn set_cached_credential<T: Serialize>(
    key: &str,
    credential: &T,
    store: Option<&dyn SecretStore>,
) -> Result<(), CacheError> {
    if let Some(store) = store {
        let service = format!("c9s credential -- {key}");
        let secret_key = SecretKey::new(key, &service, "c9s");
        let json = serde_json::to_string(credential).map_err(CacheError::Encode)?;
        store
            .set(&secret_key, SafeSecret::new(json))
            .await
            .map_err(CacheError::Store)?;
    }

    Ok(())
}

/// Caches the credential. A failure never fails the caller (the credential was issued already), but it is
/// logged and returned so the caller can tell the user.
pub async fn set_cached_credential_best_effort<T: Serialize>(
    key: &str,
    credential: &T,
    store: Option<&dyn SecretStore>,
) -> Option<CacheError> {
    match set_cached_credential(key, credential, store).await {
        Ok(()) => None,
        Err(e) => {
            log::warn!("could not cache the issued credential: {e}");
            Some(e)
        }
    }
}

/// The one-line warning shown to the user when the cache write failed.
pub fn cache_warning(error: &CacheError) -> String {
    describe("could not cache the credential", error)
}

/// `what`, followed by the error and its causes. A cause the message names already is not repeated.
fn describe(what: &str, error: &(dyn std::error::Error + 'static)) -> String {
    let mut message = format!("{what}: {error}");
    let mut source = error.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !message.contains(&cause_text) {
            message.push_str(&format!(": {cause_text}"));
        }
        source = cause.source();
    }

    message
}

/// The cached credential of the role, if there is one that is still valid.
pub async fn cached_aws_credential(
    role_arn: Option<&str>,
    store: Option<&dyn SecretStore>,
) -> Option<Credential> {
    let credential: Option<Credential> = match get_cached_credential(role_arn?, store).await {
        Ok(credential) => credential,
        Err(e) => {
            log::warn!("could not read the cached credential, logging in instead: {e}");
            None
        }
    };

    credential.filter(|credential| credential.is_valid_at(OffsetDateTime::now_utc()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ports::secret_store::MockSecretStore;

    #[tokio::test]
    async fn invalid_json_is_a_decode_error() {
        let mut store = MockSecretStore::new();
        store
            .expect_get()
            .returning(|_| Ok(Some(SafeSecret::new("{not json"))));
        let result = get_cached_credential::<Credential>("role", Some(&store)).await;
        assert!(matches!(result, Err(CacheError::Decode(_))));
    }

    #[tokio::test]
    async fn a_failing_store_is_a_store_error() {
        let mut store = MockSecretStore::new();
        store
            .expect_set()
            .returning(|_, _| Err(SecretStoreError::Unavailable));
        let result = set_cached_credential("role", &"x", Some(&store)).await;
        assert!(matches!(result, Err(CacheError::Store(_))));
    }

    #[tokio::test]
    async fn an_unreadable_cache_is_a_miss() {
        let mut store = MockSecretStore::new();
        store
            .expect_get()
            .returning(|_| Ok(Some(SafeSecret::new("{not json"))));
        assert!(cached_aws_credential(Some("role"), Some(&store))
            .await
            .is_none());

        let mut store = MockSecretStore::new();
        store
            .expect_get()
            .returning(|_| Err(SecretStoreError::Unavailable));
        assert!(cached_aws_credential(Some("role"), Some(&store))
            .await
            .is_none());
    }

    #[test]
    fn a_cause_the_message_names_already_is_not_repeated() {
        #[derive(Debug, thiserror::Error)]
        #[error("store error: {0}")]
        struct Wrapper(#[source] Inner);
        #[derive(Debug, thiserror::Error)]
        #[error("unavailable")]
        struct Inner;

        assert_eq!(
            describe("could not cache", &Wrapper(Inner)),
            "could not cache: store error: unavailable"
        );
    }

    #[tokio::test]
    async fn a_failing_cache_write_does_not_fail() {
        let mut store = MockSecretStore::new();
        store
            .expect_set()
            .times(1)
            .returning(|_, _| Err(SecretStoreError::Unavailable));
        // Does not panic; the caller keeps its credential and gets the error back.
        let error = set_cached_credential_best_effort("role", &"x", Some(&store)).await;
        assert!(matches!(error, Some(CacheError::Store(_))));
        assert!(cache_warning(&error.unwrap()).starts_with("could not cache the credential"));

        let mut store = MockSecretStore::new();
        store.expect_set().returning(|_, _| Ok(()));
        assert!(
            set_cached_credential_best_effort("role", &"x", Some(&store))
                .await
                .is_none()
        );
    }
}
