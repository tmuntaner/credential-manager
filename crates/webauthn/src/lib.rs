#[cfg(any(target_os = "linux", target_os = "macos"))]
mod utils;

pub trait WebauthnNotifier {
    fn notify_start(&self) -> Result<(), WebauthnError>;
    fn notify_end(&self) -> Result<(), WebauthnError>;
}

#[cfg(feature = "progress_bar")]
mod progress_bar;

#[cfg(feature = "progress_bar")]
use crate::progress_bar::ProgressBarFallbackNotifier;

#[cfg(feature = "notifications")]
mod desktop_notifications;

#[cfg(feature = "notifications")]
use crate::desktop_notifications::DesktopNotificationsFallbackNotifier;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod mozilla;

mod errors;

pub use errors::WebauthnError;

/// The raw parts of a WebAuthn assertion. Encoding them is up to the caller.
#[derive(Debug, Clone, PartialEq)]
pub struct WebauthnAssertion {
    /// The key handle that signed (the assertion `id` / `rawId`).
    pub credential_id: Vec<u8>,
    pub client_data_json: Vec<u8>,
    /// `rpIdHash(32) || flags(1) || counter(4)`
    pub authenticator_data: Vec<u8>,
    /// DER ECDSA
    pub signature: Vec<u8>,
}

/// The result of enrolling a FIDO2 credential with the `hmac-secret` extension enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HmacEnrollment {
    pub credential_id: Vec<u8>,
}

/// Enrolls a new credential with the FIDO2 `hmac-secret` extension enabled.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn enroll_hmac_secret(rp_id: &str) -> Result<HmacEnrollment, WebauthnError> {
    mozilla::enroll_hmac_secret(rp_id)
}

/// Enrolls a new credential with the FIDO2 `hmac-secret` extension enabled.
#[cfg(target_os = "windows")]
pub fn enroll_hmac_secret(_rp_id: &str) -> Result<HmacEnrollment, WebauthnError> {
    Err(WebauthnError::UnsupportedPlatform)
}

/// Derives a 32-byte secret from a credential using the FIDO2 `hmac-secret` extension and a 32-byte salt.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn derive_hmac_secret(
    rp_id: &str,
    credential_id: &[u8],
    salt: &[u8; 32],
) -> Result<[u8; 32], WebauthnError> {
    mozilla::derive_hmac_secret(rp_id, credential_id, salt)
}

/// Derives a 32-byte secret from a credential using the FIDO2 `hmac-secret` extension and a 32-byte salt.
#[cfg(target_os = "windows")]
pub fn derive_hmac_secret(
    _rp_id: &str,
    _credential_id: &[u8],
    _salt: &[u8; 32],
) -> Result<[u8; 32], WebauthnError> {
    Err(WebauthnError::UnsupportedPlatform)
}

#[derive(Default)]
pub struct WebauthnClient {
    notifiers: Vec<Box<dyn WebauthnNotifier>>,
}

impl WebauthnClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_notifier(&mut self, notifier: Box<dyn WebauthnNotifier>) -> &mut WebauthnClient {
        self.notifiers.push(notifier);

        self
    }

    #[cfg(feature = "progress_bar")]
    pub fn add_progress_bar_notifier(&mut self) -> &mut WebauthnClient {
        let notifier = Box::new(ProgressBarFallbackNotifier::new());

        self.add_notifier(notifier)
    }

    #[cfg(feature = "notifications")]
    pub fn add_desktop_notification_notifier(&mut self) -> &mut WebauthnClient {
        let notifier = Box::new(DesktopNotificationsFallbackNotifier::new());

        self.add_notifier(notifier)
    }

    /// Signs a WebAuthn challenge. `challenge` is the base64url string from the server and is placed
    /// verbatim in the client data, `credential_ids` are base64url. `rp_id` and `origin` come from the
    /// caller (the IdP host and `https://<host>`).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn sign_assertion(
        self,
        challenge: String,
        rp_id: String,
        origin: String,
        credential_ids: Vec<String>,
    ) -> Result<WebauthnAssertion, WebauthnError> {
        mozilla::sign_assertion(challenge, rp_id, origin, credential_ids, self.notifiers)
    }

    #[cfg(target_os = "windows")]
    pub fn sign_assertion(
        self,
        _challenge: String,
        _rp_id: String,
        _origin: String,
        _credential_ids: Vec<String>,
    ) -> Result<WebauthnAssertion, WebauthnError> {
        Err(WebauthnError::UnsupportedPlatform)
    }
}
