/// The SAML response from the authorization flow.
#[derive(Debug, Clone, PartialEq)]
pub struct SamlAssertion {
    /// Base64 from `attrs.SAMLResponse`.
    pub saml_response: String,
    /// The ACS URL.
    pub destination: String,
    /// The `RelayState`, if the flow set one.
    pub relay_state: Option<String>,
}
