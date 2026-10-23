use crate::domain::models::rancher_credentials::RancherCredential;
use crate::domain::models::user_credentials::UserCredentials;
use crate::domain::ports::oidc::OidcAuthorizer;
use crate::domain::ports::oidc::OidcError;
use crate::domain::ports::rancher_api::RancherApiError;
use async_trait::async_trait;
use std::time::Duration;
use thiserror::Error;

/// Driving port: what callers use to get a token for a cluster behind Rancher.
#[async_trait(?Send)]
pub trait IssueCredential {
    /// Logs in through `authorizer` and creates a token for `cluster_name` that lives for `ttl`.
    async fn generate(
        &self,
        authorizer: &dyn OidcAuthorizer,
        login: UserCredentials,
        cluster_name: &str,
        ttl: Duration,
    ) -> Result<RancherCredential, RancherError>;
}

/// Why no credential was issued.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RancherError {
    /// The identity provider did not hand out an authorization code.
    #[error("could not log in at the identity provider: {0}")]
    Authorize(#[from] OidcError),

    /// Rancher refused a request or could not be reached.
    #[error(transparent)]
    Api(#[from] RancherApiError),

    /// The expiry of a token that lives that long cannot be represented.
    #[error("the ttl of the token is too long")]
    TtlTooLong,
}
