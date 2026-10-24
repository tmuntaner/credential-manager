use crate::domain::models::secret::TotpCode;

/// The MFA method to authenticate with.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MfaMethod {
    /// A security key, e.g., a Yubikey.
    WebAuthn,
    /// A code from an authenticator app.
    Totp,
}

/// The MFA challenge from Authentik.
#[derive(Debug, Clone, PartialEq)]
pub struct MfaChallenge {
    /// The MFA devices from Authentik.
    pub devices: Vec<MfaDevice>,
}

/// An MFA device.
#[derive(Debug, Clone, PartialEq)]
pub enum MfaDevice {
    /// A TOTP app.
    Totp,
    /// A security key, e.g., a Yubikey.
    WebAuthn(WebauthnOptions),
    /// An unknown device.
    Other(String),
}

impl MfaDevice {
    /// The device class.
    pub fn class(&self) -> &str {
        match self {
            MfaDevice::Totp => "totp",
            MfaDevice::WebAuthn(_) => "webauthn",
            MfaDevice::Other(class) => class,
        }
    }
}

/// The challenge response.
#[derive(Debug, Clone, PartialEq)]
pub enum MfaResponse {
    /// The TOTP code for the device at `device` in [`MfaChallenge::devices`].
    Totp { device: usize, code: TotpCode },
    /// The webauthn signature.
    WebAuthn(WebauthnAssertion),
}

/// The Webauthn challenge options.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct WebauthnOptions {
    /// The challenge (Base64url encoded).
    pub challenge: Option<String>,
    /// The relaying party.
    pub rp_id: Option<String>,
    /// A Base64url encoded list of the user's credential ids.
    pub credential_ids: Vec<String>,
    /// Whether we must verify the user.
    pub user_verification_required: bool,
}

/// The Webauthn challenge request we must sign.
#[derive(Debug, Clone, PartialEq)]
pub struct WebauthnRequest {
    /// The challenge (Base64url encoded).
    pub challenge: String,
    pub rp_id: String,
    /// The origin.
    pub origin: String,
    /// A Base64url encoded list of the user's credential ids that may sign the request.
    pub credential_ids: Vec<String>,
}

/// The webauthn signature, in raw bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct WebauthnAssertion {
    /// The key that signed the challenge.
    pub credential_id: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
}
