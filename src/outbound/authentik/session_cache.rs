use crate::domain::models::secret::SafeSecret;
use crate::domain::ports::secret_store::{SecretKey, SecretStore};
use async_trait::async_trait;
use authentik::{AuthentikSession, SessionCache, SessionCacheError};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

const SERVICE: &str = "c9s authentik session";
const APPLICATION: &str = "c9s";
/// The same for every host, which is already in the service.
const USERNAME: &str = "session";

/// The stored form of an `AuthentikSession`.
#[derive(Serialize, Deserialize)]
struct StoredSession {
    cookies: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

/// Keeps the authentik sessions in a secret store. The session authenticates as the user, so the store
/// must encrypt it. Without a store, nothing is remembered.
pub struct StoredSessions {
    store: Option<Box<dyn SecretStore>>,
}

impl StoredSessions {
    pub fn new(store: Option<Box<dyn SecretStore>>) -> Self {
        Self { store }
    }

    fn key(idp_host: &str) -> SecretKey {
        // The Linux keyring finds items by service and application only, so the host goes into the service.
        SecretKey::new(USERNAME, format!("{SERVICE} -- {idp_host}"), APPLICATION)
    }
}

fn failed(e: impl std::error::Error + Send + Sync + 'static) -> SessionCacheError {
    SessionCacheError::Failed(Box::new(e))
}

#[async_trait(?Send)]
impl SessionCache for StoredSessions {
    async fn load(&self, idp_host: &str) -> Result<Option<AuthentikSession>, SessionCacheError> {
        // if there is no secret store, return `None`.
        let Some(store) = &self.store else {
            return Ok(None);
        };

        // see if the secret is in the store.
        let Some(secret) = store.get(&Self::key(idp_host)).await.map_err(failed)? else {
            return Ok(None);
        };

        Ok(
            serde_json::from_str::<StoredSession>(secret.expose_secret())
                .ok()
                .map(|s| AuthentikSession::new(s.cookies, s.created_at)),
        )
    }

    async fn store(
        &self,
        idp_host: &str,
        session: &AuthentikSession,
    ) -> Result<(), SessionCacheError> {
        // if there is no secret store, return `None`.
        let Some(store) = &self.store else {
            return Ok(());
        };

        // convert the session to json.
        let json = serde_json::to_string(&StoredSession {
            cookies: session.cookies().to_string(),
            created_at: session.created_at(),
        })
        .map_err(failed)?;

        // store the secret in the store.
        store
            .set(&Self::key(idp_host), SafeSecret::new(json))
            .await
            .map_err(failed)
    }

    async fn clear(&self, idp_host: &str) -> Result<(), SessionCacheError> {
        // if there is no secret store, return `Ok`.
        let Some(store) = &self.store else {
            return Ok(());
        };

        // set the secret an empty string
        store
            .set(&Self::key(idp_host), SafeSecret::new(String::new()))
            .await
            .map_err(failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ports::secret_store::MockSecretStore;

    fn session() -> AuthentikSession {
        AuthentikSession::new("authentik_session=abc", OffsetDateTime::UNIX_EPOCH)
    }

    #[tokio::test]
    async fn stores_the_session_as_json_under_the_host() {
        let mut store = MockSecretStore::new();
        store
            .expect_set()
            .withf(|key, value| {
                key == &StoredSessions::key("id.example.com")
                    && serde_json::from_str::<StoredSession>(value.expose_secret()).is_ok()
            })
            .times(1)
            .returning(|_, _| Ok(()));

        StoredSessions::new(Some(Box::new(store)))
            .store("id.example.com", &session())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn loads_what_it_stored() {
        let json = serde_json::to_string(&StoredSession {
            cookies: "authentik_session=abc".to_string(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        })
        .unwrap();
        let mut store = MockSecretStore::new();
        store
            .expect_get()
            .times(1)
            .returning(move |_| Ok(Some(SafeSecret::new(json.clone()))));

        let loaded = StoredSessions::new(Some(Box::new(store)))
            .load("id.example.com")
            .await
            .unwrap();

        assert_eq!(loaded, Some(session()));
    }

    #[tokio::test]
    async fn unreadable_content_is_a_miss() {
        let mut store = MockSecretStore::new();
        store
            .expect_get()
            .returning(|_| Ok(Some(SafeSecret::new("not json"))));

        let loaded = StoredSessions::new(Some(Box::new(store)))
            .load("id.example.com")
            .await
            .unwrap();

        assert_eq!(loaded, None);
    }

    #[tokio::test]
    async fn without_a_store_nothing_is_remembered() {
        let sessions = StoredSessions::new(None);

        sessions.store("id.example.com", &session()).await.unwrap();

        assert_eq!(sessions.load("id.example.com").await.unwrap(), None);
    }
}
