use crate::domain::models::mfa::MfaMethod;

/// What a user logs in with at the identity provider.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UserCredentials {
    pub username: String,
    pub password: String,
    /// The method to use when the identity provider asks for a second factor.
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
