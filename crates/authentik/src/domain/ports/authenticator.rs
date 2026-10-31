use crate::domain::models::mfa::{MfaMethod, WebauthnAssertion, WebauthnRequest};
use crate::domain::models::secret::TotpCode;
use async_trait::async_trait;
use std::error::Error;
use thiserror::Error;

/// The authenticator handles the MFA challenge for a user. Asking them for which device to use
/// and sending the response back to Authentik.
///
/// The caller must implement this trait.
#[cfg_attr(test, mockall::automock)]
#[async_trait(?Send)]
pub trait Authenticator {
    /// Asks for a TOTP code.
    async fn totp_code(&self) -> Result<TotpCode, AuthenticatorError>;

    /// Asks the user which of MFA `methods` it wants to use.
    async fn choose_method(&self, methods: &[MfaMethod]) -> Result<MfaMethod, AuthenticatorError>;

    /// Lets the user know that Authentik rejected its MFA challenge.
    async fn mfa_rejected(&self, reason: &str);

    /// Signs a WebAuthn challenge.
    async fn sign(
        &self,
        request: &WebauthnRequest,
    ) -> Result<WebauthnAssertion, AuthenticatorError>;
}

/// Why the MFA challenge failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthenticatorError {
    #[error(transparent)]
    Failed(Box<dyn Error + Send + Sync>),
}
