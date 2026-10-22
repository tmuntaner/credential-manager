use base::models::mfa::MfaSelection;

#[derive(Debug, Clone)]
pub struct UserCredentials {
    pub username: String,
    pub password: String,
    pub mfa: Option<MfaSelection>,
}
