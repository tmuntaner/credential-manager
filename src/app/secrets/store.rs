use crate::domain::models::settings::AppConfig;
use crate::domain::ports::notifier::Notifier;
use crate::domain::ports::secret_store::SecretStore;
use crate::domain::ports::user_interaction::UserInteraction;
use crate::outbound::keyring::KeyringSecretStore;
use std::sync::Arc;

/// Why the secret store failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretStoresError {
    #[cfg_attr(not(windows), allow(dead_code))]
    #[error("YubiKey wrapping is not supported on Windows")]
    YubikeyUnsupported,
}

pub type OptionalStore = Option<Box<dyn SecretStore>>;

/// The secret stores of a run.
pub struct SecretStores {
    /// Holds the passwords of the identity provider.
    pub idp: OptionalStore,
    /// Holds the issued credentials.
    pub cache: OptionalStore,
    /// Holds the idp sessions. Only set when a security key is enrolled.
    pub session: OptionalStore,
}

pub fn create_secret_stores<U: UserInteraction + 'static, N: Notifier + 'static>(
    settings: &AppConfig,
    prompt: Arc<U>,
    notifier: Arc<N>,
) -> Result<SecretStores, SecretStoresError> {
    // if the keyring is disabled, return early
    if !settings.keyring_enabled() {
        return Ok(SecretStores {
            idp: None,
            cache: None,
            session: None,
        });
    }

    // get the yubikey from the config
    if let Some(yk) = settings.yubikey_config() {
        #[cfg(target_os = "windows")]
        {
            let _ = (yk, prompt, notifier);
            return Err(SecretStoresError::YubikeyUnsupported);
        }

        #[cfg(not(target_os = "windows"))]
        {
            // find the yubikey and the salt
            let credential_id = yk.credential_id().to_vec();
            let salt = *yk.salt();

            // build the wrapper
            let yk_wrapper = crate::outbound::yubikey::YubikeyWrapper::new(
                yk.rp_id(),
                credential_id,
                salt,
                prompt,
                notifier,
            );

            let wrapper: Arc<dyn crate::domain::ports::secret_wrapper::SecretWrapper> = if settings
                .daemon_enabled()
            {
                let socket_path = settings
                    .daemon_config()
                    .and_then(|d| d.socket_path())
                    .cloned()
                    .unwrap_or_else(crate::outbound::daemon::peer_cred::default_socket_path);

                let daemon_wrapper = crate::outbound::daemon::DaemonSecretWrapper::new(socket_path)
                    .with_fallback(Box::new(yk_wrapper))
                    .with_auto_spawn(true);

                Arc::new(daemon_wrapper)
            } else {
                Arc::new(yk_wrapper)
            };

            // build the wrapping secret store
            let idp_store =
                crate::domain::services::wrapping_secret_store::WrappingSecretStore::new(
                    KeyringSecretStore::new(),
                    wrapper.clone(),
                );

            // Get the cache store depending on if wrapped cached secrets are enabled.
            // If enabled, it will wrap secrets other than idp credentials.
            let wrap_cached = settings.wrap_cached_secrets_enabled();
            let cache_store: Box<dyn SecretStore> = if wrap_cached {
                Box::new(
                    crate::domain::services::wrapping_secret_store::WrappingSecretStore::new(
                        KeyringSecretStore::new(),
                        wrapper.clone(),
                    ),
                )
            } else {
                Box::new(KeyringSecretStore::new())
            };

            // creates the session store to cache the user's session in the idp.
            let session_store: OptionalStore = Some(Box::new(
                crate::domain::services::wrapping_secret_store::WrappingSecretStore::with_policy(
                    KeyringSecretStore::new(),
                    wrapper,
                    crate::domain::services::wrapping_secret_store::WrappingPolicy::Strict,
                ),
            ));

            return Ok(SecretStores {
                idp: Some(Box::new(idp_store)),
                cache: Some(cache_store),
                session: session_store,
            });
        }
    }

    // if we don't wrap secrets, there is no session stores.
    Ok(SecretStores {
        idp: Some(Box::new(KeyringSecretStore::new())),
        cache: Some(Box::new(KeyringSecretStore::new())),
        session: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::secret::SafeSecret;
    use crate::domain::models::user_interaction::{
        ChoicePrompt, ConfirmPrompt, SecretPrompt, UserNotice,
    };
    use crate::domain::ports::notifier::NotifyError;
    use crate::domain::ports::user_interaction::InteractionError;

    /// Stands in for the user. The tests only build the stores, so nothing is ever asked.
    struct NoInteraction;

    #[async_trait::async_trait(?Send)]
    impl UserInteraction for NoInteraction {
        async fn ask_secret(&self, _: SecretPrompt) -> Result<SafeSecret, InteractionError> {
            Err(InteractionError::Unavailable)
        }

        async fn confirm(&self, _: ConfirmPrompt) -> Result<bool, InteractionError> {
            Err(InteractionError::Unavailable)
        }

        async fn choose(&self, _: &ChoicePrompt) -> Result<usize, InteractionError> {
            Err(InteractionError::Unavailable)
        }
    }

    #[async_trait::async_trait(?Send)]
    impl Notifier for NoInteraction {
        async fn notify(&self, _: &UserNotice) -> Result<(), NotifyError> {
            Err(NotifyError::Unavailable)
        }
    }

    #[test]
    fn secret_stores_disabled_when_keyring_disabled() {
        let mut settings = AppConfig::default();
        settings.set_use_keyring(false);

        let SecretStores {
            idp: idp_store,
            cache: cache_store,
            session: session_store,
        } = create_secret_stores(&settings, Arc::new(NoInteraction), Arc::new(NoInteraction))
            .unwrap();
        assert!(idp_store.is_none());
        assert!(cache_store.is_none());
        assert!(session_store.is_none());
    }

    #[test]
    fn secret_stores_plain_keyring_when_not_enrolled() {
        let settings = AppConfig::default();

        let SecretStores {
            idp: idp_store,
            cache: cache_store,
            session: session_store,
        } = create_secret_stores(&settings, Arc::new(NoInteraction), Arc::new(NoInteraction))
            .unwrap();
        assert!(idp_store.is_some());
        assert!(cache_store.is_some());
        // Without wrapping, sessions are not stored.
        assert!(session_store.is_none());
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn secret_stores_when_yubikey_enrolled() {
        let mut settings = AppConfig::default();
        let yk = crate::domain::models::settings::YubikeyConfig::new(
            &[1, 2, 3],
            "localhost",
            &[0x42; 32],
        );
        settings.set_yubikey(Some(yk));

        // Default: wrap_cached_secrets = false
        let SecretStores {
            idp: idp_store,
            cache: cache_store,
            session: session_store,
        } = create_secret_stores(&settings, Arc::new(NoInteraction), Arc::new(NoInteraction))
            .unwrap();
        assert!(idp_store.is_some());
        assert!(cache_store.is_some());
        // Sessions are always cached (encrypted) when a YubiKey is enrolled.
        assert!(session_store.is_some());

        // Configured: wrap_cached_secrets = true
        settings.set_wrap_cached_secrets(true);
        let SecretStores {
            idp: idp_store,
            cache: cache_store,
            session: session_store,
        } = create_secret_stores(&settings, Arc::new(NoInteraction), Arc::new(NoInteraction))
            .unwrap();
        assert!(idp_store.is_some());
        assert!(cache_store.is_some());
        assert!(session_store.is_some());

        // Keyring disabled: nothing is stored, even when wrapping is on.
        settings.set_use_keyring(false);
        let stores =
            create_secret_stores(&settings, Arc::new(NoInteraction), Arc::new(NoInteraction))
                .unwrap();
        assert!(stores.session.is_none());
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn secret_stores_when_yubikey_enrolled() {
        let mut settings = AppConfig::default();
        let yk = crate::domain::models::settings::YubikeyConfig::new(
            &[1, 2, 3],
            "localhost",
            &[0x42; 32],
        );
        settings.set_yubikey(Some(yk));

        let err =
            match create_secret_stores(&settings, Arc::new(NoInteraction), Arc::new(NoInteraction))
            {
                Err(e) => e,
                Ok(_) => panic!("expected create_secret_stores to fail on Windows"),
            };
        assert_eq!(
            err.to_string(),
            "YubiKey wrapping is not supported on Windows"
        );
    }
}
