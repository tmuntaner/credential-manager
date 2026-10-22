use crate::domain::models::session::AuthCode;
use crate::domain::models::user_credentials::UserCredentials;
use async_trait::async_trait;
use std::error::Error;
use thiserror::Error;

/// Logs a user in at an OpenID Connect identity provider and provides an OAuth authorization code.
///
/// Implemented by the application that uses this crate.
#[cfg_attr(test, mockall::automock)]
#[async_trait(?Send)]
pub trait OidcAuthorizer {
    /// `redirect_uri` is where the identity provider sends the user back to after the login.
    async fn authorize(
        &self,
        login: UserCredentials,
        redirect_uri: &str,
    ) -> Result<AuthCode, OidcError>;
}

/// Why the identity provider did not hand out an authorization code.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OidcError {
    #[error(transparent)]
    Failed(Box<dyn Error + Send + Sync>),
}
