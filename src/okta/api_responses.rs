use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OktaError {
    error_code: String,
    error_summary: String,
    error_link: String,
    error_id: String,
}

impl OktaError {
    pub fn summary(&self) -> String {
        format!(
            "okta error code {} - {}",
            self.error_code, self.error_summary
        )
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub enum TransactionState {
    #[serde(rename = "MFA_REQUIRED")]
    MfaRequired,
    #[serde(rename = "MFA_CHALLENGE")]
    MfaChallenge,
    #[serde(rename = "SUCCESS")]
    Success,
    #[serde(other)]
    Unimplemented,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AuthResponse {
    pub state_token: Option<String>,
    #[serde(rename = "_embedded")]
    pub embedded: Option<Embedded>,
    pub status: Option<TransactionState>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    pub state_token: Option<String>,
    #[serde(rename = "_embedded")]
    pub embedded: Option<Embedded>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResultResponse {
    pub session_token: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    pub challenge: String,
    pub user_verification: Option<String>,
    pub extensions: Option<Value>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Embedded {
    #[serde(default)]
    pub factor_types: Option<Vec<FactorType>>,

    #[serde(default)]
    pub factors: Option<Vec<FactorType>>,

    #[serde(default)]
    pub challenge: Option<Challenge>,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum Links {
    Single(Link),
    Multi(Vec<Link>),
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Link {
    name: Option<String>,
    pub href: String,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub credential_id: Option<String>,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase", tag = "factorType")]
pub enum FactorType {
    WebAuthn {
        profile: Option<Profile>,

        #[serde(rename = "_links")]
        links: Option<HashMap<String, Links>>,
    },
    #[serde(other)]
    Unimplemented,
}
