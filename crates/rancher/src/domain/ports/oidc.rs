use crate::domain::models::session::AuthCode;
use crate::domain::models::user_credentials::UserCredentials;
use async_trait::async_trait;
use std::error::Error;
use thiserror::Error;

/// Logs a user in with OIDC.
///
/// Implemented by the caller application.
#[cfg_attr(test, mockall::automock)]
#[async_trait(?Send)]
pub trait OidcAuthorizer {
    /// `redirect_uri` is where the idp redirects after a login.
    async fn authorize(
        &self,
        login: UserCredentials,
        redirect_uri: &str,
    ) -> Result<AuthCode, OidcError>;
}

/// An OIDC error.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OidcError {
    #[error(transparent)]
    Failed(Box<dyn Error + Send + Sync>),
}
