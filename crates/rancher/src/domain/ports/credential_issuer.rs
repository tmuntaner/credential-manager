use crate::domain::models::rancher_credentials::RancherCredential;
use crate::domain::models::user_credentials::UserCredentials;
use crate::domain::ports::oidc::OidcAuthorizer;
use crate::domain::ports::oidc::OidcError;
use crate::domain::ports::rancher_api::RancherApiError;
use async_trait::async_trait;
use std::time::Duration;
use thiserror::Error;

/// Driving port: callers use this to get a Rancher token.
#[async_trait(?Send)]
pub trait IssueCredential {
    /// Logs in through `authorizer` and generates a token for `cluster_name`.
    async fn generate(
        &self,
        authorizer: &dyn OidcAuthorizer,
        login: UserCredentials,
        cluster_name: &str,
        ttl: Duration,
    ) -> Result<RancherCredential, RancherError>;
}

/// A rancher error.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RancherError {
    /// The idp login failed.
    #[error("could not log in at the identity provider: {0}")]
    Authorize(#[from] OidcError),

    /// The rancher api returned an error.
    #[error(transparent)]
    Api(#[from] RancherApiError),

    /// The TTL was too long.
    #[error("the ttl of the token is too long")]
    TtlTooLong,
}
