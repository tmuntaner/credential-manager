use async_trait::async_trait;
use std::error::Error;
use std::fmt;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A security key's PIN.
/// We use zeroize to protect the value within memory.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecurityKeyPin(String);

impl SecurityKeyPin {
    pub fn new(pin: impl Into<String>) -> Self {
        Self(pin.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecurityKeyPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecurityKeyPin(<redacted>)")
    }
}

/// The request to a user for the Security key's pin.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PinRequest {
    /// Whether this is a retry attempt at a PIN.
    pub retry: bool,
    /// How many attempts are left before the key blocks.
    pub attempts_left: Option<u8>,
}

impl PinRequest {
    pub fn new(retry: bool, attempts_left: Option<u8>) -> Self {
        Self {
            retry,
            attempts_left,
        }
    }

    /// Look if there is a retry message and, if there is, give it to the user.
    pub fn retry_message(&self) -> Option<String> {
        if !self.retry {
            return None;
        }

        Some(match self.attempts_left {
            Some(1) => "Wrong PIN, 1 attempt left.".to_string(),
            Some(attempts) => format!("Wrong PIN, {attempts} attempts left."),
            None => "Wrong PIN.".to_string(),
        })
    }
}

/// An event from the security key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyEvent {
    /// The user must touch the security key to continue.
    TouchRequired,
    /// More than one key is available, and the user has to select the device by touching it.
    SelectDevice,
    /// The user had too many wrong PINs. The key will need to be unplugged and plugged in again.
    PinAuthBlocked,
    /// The PIN is blocked, and the user will need to reset it.
    PinBlocked,
}

impl KeyEvent {
    pub fn is_error(&self) -> bool {
        matches!(self, KeyEvent::PinAuthBlocked | KeyEvent::PinBlocked)
    }
}

impl fmt::Display for KeyEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeyEvent::TouchRequired => "Touch your security key to continue...",
            KeyEvent::SelectDevice => "Several security keys found. Touch the one you want to use.",
            KeyEvent::PinAuthBlocked => {
                "Too many wrong PINs. Unplug the security key and plug it in again."
            }
            KeyEvent::PinBlocked => {
                "The security key PIN is blocked. Reset the key to use it again."
            }
        })
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PinError {
    /// The user dismissed the PIN prompt.
    #[error("cancelled by the user")]
    Cancelled,

    /// Another type of error occurred.
    #[error(transparent)]
    Failed(Box<dyn Error + Send + Sync>),
}

/// This trait sets how the user interacts with the security key. Mainly, to get the PIN.
///
/// This caller implements this trait.
#[async_trait(?Send)]
pub trait SecurityKeyUi: Send + Sync {
    /// Asks the user for the security key's PIN.
    async fn request_pin(&self, request: &PinRequest) -> Result<SecurityKeyPin, PinError>;

    /// Gives a message to the user from the security key.
    async fn notify(&self, event: KeyEvent);
}

/// Default `SecurityKeyUi` implementation.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Default)]
pub struct TerminalSecurityKeyUi;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[async_trait(?Send)]
impl SecurityKeyUi for TerminalSecurityKeyUi {
    async fn request_pin(&self, request: &PinRequest) -> Result<SecurityKeyPin, PinError> {
        if let Some(message) = request.retry_message() {
            eprintln!("{message}");
        }

        // Reading from the terminal blocks, so keep it off the async threads.
        tokio::task::spawn_blocking(|| rpassword::prompt_password("Security key PIN: "))
            .await
            .map_err(|e| PinError::Failed(Box::new(e)))?
            .map(SecurityKeyPin::new)
            .map_err(|e| PinError::Failed(Box::new(e)))
    }

    async fn notify(&self, event: KeyEvent) {
        eprintln!("{event}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pin_is_not_printed() {
        assert_eq!(
            format!("{:?}", SecurityKeyPin::new("1234")),
            "SecurityKeyPin(<redacted>)"
        );
    }

    #[test]
    fn only_a_retry_has_a_message() {
        assert_eq!(PinRequest::new(false, Some(3)).retry_message(), None);
        assert_eq!(
            PinRequest::new(true, Some(1)).retry_message().as_deref(),
            Some("Wrong PIN, 1 attempt left.")
        );
        assert_eq!(
            PinRequest::new(true, Some(2)).retry_message().as_deref(),
            Some("Wrong PIN, 2 attempts left.")
        );
        assert_eq!(
            PinRequest::new(true, None).retry_message().as_deref(),
            Some("Wrong PIN.")
        );
    }

    #[test]
    fn blocked_keys_are_errors() {
        assert!(KeyEvent::PinBlocked.is_error());
        assert!(KeyEvent::PinAuthBlocked.is_error());
        assert!(!KeyEvent::TouchRequired.is_error());
        assert!(!KeyEvent::SelectDevice.is_error());
    }
}
