use std::error::Error;
use thiserror::Error;

/// Why the identity provider did not hand out a SAML assertion.
#[derive(Debug, Error)]
pub enum SamlLoginError {
    #[error(transparent)]
    Failed(Box<dyn Error + Send + Sync>),
}

/// The SAML response handed out by the authorization flow, to be POSTed to the service provider.
#[derive(Debug, Clone, PartialEq)]
pub struct SamlAssertion {
    /// Base64, exactly as in `attrs.SAMLResponse`.
    pub saml_response: String,
    /// The ACS URL.
    pub destination: String,
    pub relay_state: Option<String>,
}
