use crate::domain::models::mfa::MfaMethod;

/// The user's idp credentials.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UserCredentials {
    pub username: String,
    pub password: String,
    /// The selected MFA method.
    pub mfa: Option<MfaMethod>,
}

impl UserCredentials {
    pub fn new(username: String, password: String, mfa: Option<MfaMethod>) -> Self {
        Self {
            username,
            password,
            mfa,
        }
    }
}
