use crate::domain::models::session::{AuthCode, SessionToken};
use async_trait::async_trait;
use std::error::Error;
use std::time::Duration;
use thiserror::Error;

/// Why a call to Rancher failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RancherApiError {
    /// Rancher rejected the session or the code (401).
    #[error("rancher rejected the token (401)")]
    Unauthorized,

    /// No cluster with that display name.
    #[error("cluster {0} not found")]
    ClusterNotFound(String),

    /// Rancher could not be reached or answered with something unusable.
    #[error(transparent)]
    Failed(Box<dyn Error + Send + Sync>),
}

/// A cluster that Rancher manages.
#[derive(Debug, Clone, PartialEq)]
pub struct Cluster {
    pub id: String,
    pub server_url: String,
}

/// A rancher API token.
#[derive(Debug, Clone, PartialEq)]
pub struct ApiToken {
    pub id: String,
    pub token: String,
}

/// Driven port: the calls the domain makes to Rancher.
///
/// Implemented by [`RancherApiClient`](crate::RancherApiClient) over HTTP.
#[cfg_attr(test, mockall::automock)]
#[async_trait(?Send)]
pub trait RancherApi {
    /// Where the idp redirects to after a login.
    fn redirect_uri(&self) -> String;

    /// Exchanges the authorization code for a session.
    async fn login(&self, code: &AuthCode) -> Result<SessionToken, RancherApiError>;

    async fn logout(&self, session: &SessionToken) -> Result<(), RancherApiError>;

    async fn find_cluster(
        &self,
        session: &SessionToken,
        name: &str,
    ) -> Result<Cluster, RancherApiError>;

    async fn ca_cert(&self, session: &SessionToken) -> Result<String, RancherApiError>;

    /// An explicit ttl is always sent
    /// Note: a ttl of 0 does not expire.
    async fn create_token(
        &self,
        session: &SessionToken,
        cluster_id: &str,
        ttl: Duration,
    ) -> Result<ApiToken, RancherApiError>;
}
