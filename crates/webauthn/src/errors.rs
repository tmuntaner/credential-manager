use thiserror::Error;

#[derive(Debug, Error)]
pub enum WebauthnError {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[error(transparent)]
    Authenticator(#[from] authenticator::errors::AuthenticatorError),

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[error(transparent)]
    InvalidOrigin(#[from] url::ParseError),

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[error(transparent)]
    ClientData(#[from] serde_json::Error),

    #[cfg(feature = "notifications")]
    #[error(transparent)]
    Notification(#[from] notify_rust::error::Error),

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[error("the challenge has no usable credential ids")]
    NoUsableCredentialIds,

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[error("could not start signing: {0:?}")]
    StartSigning(authenticator::errors::AuthenticatorError),

    #[error("Problem receiving, unable to continue")]
    ReceiveSignResult,

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[error("There was an issue authenticating your security key ({0}). Please ensure that it's set up on your account, plugged in, and that you activate it.")]
    SecurityKey(authenticator::errors::AuthenticatorError),

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[error("the security key did not say which credential signed")]
    UnknownCredential,

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[error("could not start registration: {0:?}")]
    StartRegistering(authenticator::errors::AuthenticatorError),

    #[error("Problem receiving registration result, unable to continue")]
    ReceiveRegisterResult,

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[error("the security key does not support the hmac-secret extension")]
    HmacSecretNotSupported,

    #[error("WebAuthn operations are not supported on Windows yet")]
    UnsupportedPlatform,
}
