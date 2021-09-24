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
    /// Returns an error summary
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
pub struct Response {
    state_token: Option<String>,
    session_token: Option<String>,
    #[serde(rename = "_embedded")]
    embedded: Option<Embedded>,
    status: Option<TransactionState>,
    #[serde(rename = "_links")]
    links: Option<HashMap<String, Links>>,
}

impl Response {
    /// Tries to return the [`TransactionState`] of a response.
    pub fn status(&self) -> Option<TransactionState> {
        self.status.clone()
    }

    /// Tries to return the state token to keep track of the transaction.
    ///
    /// This should always be filled.
    pub fn state_token(&self) -> Option<String> {
        self.state_token.clone()
    }

    /// Tries to return the session token to run authorized API requests.
    ///
    /// This will only be filled if we successfully authorized the user.
    pub fn session_token(&self) -> Option<String> {
        self.session_token.clone()
    }

    /// Tries to return the valid MFA factors.
    pub fn factors(&self) -> Option<Vec<FactorType>> {
        // collect the general webauthn factor (used to authorize against all webauthn factors)
        let mut factors_types = self
            .embedded
            .as_ref()?
            .factor_types
            .clone()
            .unwrap_or_default();

        // collect all other MFA factors
        let mut factors = self.embedded.as_ref()?.factors.clone().unwrap_or_default();

        factors_types.append(&mut factors);
        Some(factors_types)
    }

    /// Tries to return the next page in the transaction.
    pub fn next(&self) -> Option<String> {
        self.links.as_ref()?.get("next")?.link()
    }

    /// Tries to return the MFA challenge.
    pub fn challenge(&self) -> Option<String> {
        Some(
            self.embedded
                .as_ref()?
                .challenge
                .as_ref()?
                .challenge
                .clone(),
        )
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct Challenge {
    challenge: String,
    user_verification: Option<String>,
    extensions: Option<Value>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct Embedded {
    #[serde(default)]
    factor_types: Option<Vec<FactorType>>,

    #[serde(default)]
    factors: Option<Vec<FactorType>>,

    #[serde(default)]
    challenge: Option<Challenge>,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum Links {
    Single(Link),
    Multi(Vec<Link>),
}

impl Links {
    /// Tries to return a valid link.
    fn link(&self) -> Option<String> {
        match self {
            Links::Single(l) => Some(l.href.clone()),
            Links::Multi(list) => {
                let link = list.get(0)?;
                Some(link.href.clone())
            }
        }
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Link {
    name: Option<String>,
    href: String,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    credential_id: Option<String>,
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

impl FactorType {
    /// Tries to get the verification URL for a factor.
    pub fn get_verification_url(&self) -> Option<String> {
        return match self {
            FactorType::WebAuthn { ref links, .. } => links.as_ref()?.get("next")?.link(),
            FactorType::Unimplemented => None,
        };
    }

    /// Tries to get the credential ID for a factor.
    pub fn get_credential_id(&self) -> Option<String> {
        return match self {
            FactorType::WebAuthn { ref profile, .. } => {
                let profile = profile.as_ref()?;

                Some(profile.credential_id.as_ref()?.clone())
            }
            FactorType::Unimplemented => None,
        };
    }
}
