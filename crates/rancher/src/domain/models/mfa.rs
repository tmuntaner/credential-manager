/// The MFA method.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MfaMethod {
    WebAuthn,
    Totp,
}
