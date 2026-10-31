use crate::domain::models::mfa::{MfaChallenge, MfaResponse};
use crate::domain::models::saml::SamlAssertion;
use crate::domain::models::user_credentials::UserCredentials;
use crate::domain::ports::authenticator::AuthenticatorError;
use async_trait::async_trait;
use std::error::Error;
use thiserror::Error;
use url::Url;

/// Runs the Authentik authentication flow.
#[async_trait(?Send)]
pub trait FlowExecutor {
    /// Runs the flows for a SAML application.
    async fn saml(
        &self,
        entry_url: &Url,
        login: &UserCredentials,
        mfa: &dyn SecondFactor,
    ) -> Result<SamlAssertion, FlowError>;

    /// Runs the flows for an OAuth application.
    async fn oauth(
        &self,
        authorize_url: &Url,
        redirect_uri: &str,
        login: &UserCredentials,
        mfa: &dyn SecondFactor,
    ) -> Result<Url, FlowError>;
}

/// Answers MFA challenges during an Authentik flow.
///
/// Implemented by the caller and passed to the [`FlowExecutor`].
#[async_trait(?Send)]
pub trait SecondFactor {
    /// Answers `challenge`. `idp_host` is the host of the authentik instance, e.g. `id.example.com`.
    async fn respond(
        &self,
        challenge: &MfaChallenge,
        idp_host: &str,
    ) -> Result<MfaResponse, MfaError>;

    /// Called when authentik rejected the previous answer, with its reason. `Ok(())` allows another
    /// [`respond`](SecondFactor::respond), `Err` gives up.
    async fn rejected(&self, reason: &str) -> Result<(), MfaError>;
}

/// The Authentik flow errors
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FlowError {
    #[error("authentik rejected the username: {0}")]
    UsernameRejected(String),

    #[error("authentik rejected the password: {0}")]
    PasswordRejected(String),

    #[error("authentik denied access: {0}")]
    AccessDenied(String),

    /// The MFA challenge failed.
    #[error(transparent)]
    Mfa(#[from] MfaError),

    #[error(transparent)]
    Failed(Box<dyn Error + Send + Sync>),
}

/// The MFA errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MfaError {
    #[error(transparent)]
    Authenticator(#[from] AuthenticatorError),

    /// authentik rejected after too many attempts.
    #[error("MFA rejected {attempts} times: {reason}")]
    TooManyRejections { attempts: usize, reason: String },

    /// The user picked an invalid factor type.
    #[error("you've selected an invalid Factor Type")]
    InvalidFactorType,

    #[error("this IdP requires PIN user verification (CTAP2), not supported yet; use TOTP")]
    PinRequired,

    #[error("the WebAuthn challenge is for {rp_id}, not for the IdP host {idp_host}")]
    WrongRelyingParty { rp_id: String, idp_host: String },

    #[error("the WebAuthn challenge has no challenge")]
    NoWebauthnChallenge,

    #[error("the WebAuthn challenge has no allowed credentials")]
    NoAllowedCredentials,

    #[error("TOTP was selected but is not offered (offered: {0})")]
    TotpNotOffered(String),

    #[error("WebAuthn was selected but is not offered (offered: {0})")]
    WebauthnNotOffered(String),

    #[error("no supported MFA method (offered: {0})")]
    NoSupportedMethod(String),
}
