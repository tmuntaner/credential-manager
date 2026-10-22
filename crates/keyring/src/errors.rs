use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyringError {
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Session(#[from] crate::secret_service::session::SessionError),

    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Collection(#[from] crate::secret_service::collection::NewCollectionError),

    #[cfg(target_os = "linux")]
    #[error(transparent)]
    CreateSecret(#[from] crate::secret_service::collection::CreateSecretError),

    #[cfg(target_os = "linux")]
    #[error(transparent)]
    SearchSecrets(#[from] crate::secret_service::collection::SearchSecretsError),

    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Secret(#[from] crate::secret_service::SecretError),

    #[cfg(target_os = "linux")]
    #[error(transparent)]
    ZBus(#[from] zbus::Error),

    #[cfg(target_os = "linux")]
    #[error("could not get secret")]
    NoSecret,

    #[cfg(target_os = "macos")]
    #[error(transparent)]
    SecurityFramework(#[from] security_framework::base::Error),

    #[cfg(target_os = "macos")]
    #[error(transparent)]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    #[cfg(target_os = "windows")]
    #[error(transparent)]
    InvalidString(#[from] widestring::error::ContainsNul<u16>),

    #[cfg(target_os = "windows")]
    #[error("failed to save windows credential")]
    SaveCredential,
}
