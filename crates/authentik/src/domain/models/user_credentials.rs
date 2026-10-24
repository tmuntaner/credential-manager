use crate::domain::models::mfa::MfaMethod;
use crate::domain::models::secret::Password;

/// The users credentials for Authentik.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UserCredentials {
    pub username: String,
    pub password: Password,
    /// The MFA method for the login.
    pub mfa: Option<MfaMethod>,
}

impl UserCredentials {
    pub fn new(username: String, password: Password, mfa: Option<MfaMethod>) -> Self {
        Self {
            username,
            password,
            mfa,
        }
    }
}
