use async_trait::async_trait;
use std::error::Error;
use thiserror::Error;

/// Why no assertion was signed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WebauthnError {
    /// The signing failed in the adapter.
    #[error(transparent)]
    Failed(Box<dyn Error + Send + Sync>),
}

/// A signed WebAuthn assertion.
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

/// Signs WebAuthn challenges with a security key.
#[async_trait(?Send)]
pub trait WebauthnClientPort {
    /// Signs `challenge` for `rp_id` at `origin` with one of the keys in `credential_ids`.
    async fn sign_assertion(
        &self,
        challenge: String,
        rp_id: String,
        origin: String,
        credential_ids: Vec<String>,
    ) -> Result<WebauthnAssertion, WebauthnError>;
}
