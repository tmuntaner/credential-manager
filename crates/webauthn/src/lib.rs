mod utils;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod mozilla;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// <https://www.w3.org/TR/webauthn-2/#dictdef-collectedclientdata>
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CollectedClientData {
    #[serde(rename = "type")]
    sign_type: String,
    challenge: String,
    origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cross_origin: Option<bool>,
    token_binding: Option<TokenBinding>,
}

/// <https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-tokenbinding>
#[derive(Debug, Clone, Deserialize, Serialize)]
struct TokenBinding {
    status: String,
    id: Option<String>,
}

pub struct SignatureResponse {
    pub client_data: String,
    pub signature_data: String,
    pub authenticator_data: String,
}

#[cfg(target_os = "windows")]
pub fn sign(
    challenge_str: String,
    host: String,
    credential_ids: Vec<String>,
) -> Result<SignatureResponse> {
    windows::sign(challenge_str, host, credential_ids)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn sign(
    challenge_str: String,
    host: String,
    credential_ids: Vec<String>,
) -> Result<SignatureResponse> {
    mozilla::sign(challenge_str, host, credential_ids)
}
