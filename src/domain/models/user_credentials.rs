use crate::domain::models::mfa::MfaSelection;
use crate::domain::models::secret::SafeSecret;

#[derive(Debug, Clone)]
pub struct UserCredentials {
    pub username: String,
    pub password: SafeSecret,
    pub mfa: Option<MfaSelection>,
}
