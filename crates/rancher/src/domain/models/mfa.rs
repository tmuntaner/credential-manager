/// The MFA method to log in with at the identity provider.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MfaMethod {
    WebAuthn,
    Totp,
}
