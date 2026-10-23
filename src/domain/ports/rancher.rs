use crate::domain::models::oidc::OidcError;
use crate::domain::models::rancher_credentials::RancherCredential;
use crate::domain::models::user_credentials::UserCredentials;
use crate::domain::ports::login::OidcAuthorizer;
use async_trait::async_trait;
use std::error::Error;
use std::time::Duration;
use thiserror::Error;

/// Renders a Rancher credential for kubectl.
pub trait KubeconfigRenderer {
    /// A kubeconfig for the cluster of `credential`.
    fn kubeconfig(&self, credential: &RancherCredential) -> String;

    /// The output of a `client.authentication.k8s.io` exec plugin for `credential`.
    fn exec_credential(&self, credential: &RancherCredential) -> String;
}

/// Logs in at Rancher and hands out a token for one of its clusters.
#[async_trait(?Send)]
pub trait RancherCredentialIssuer {
    /// The token lives for `ttl`.
    async fn issue(
        &self,
        login: UserCredentials,
        cluster_name: &str,
        ttl: Duration,
    ) -> Result<RancherCredential, RancherError>;
}

/// Why no credential for a Rancher cluster was issued.
#[derive(Debug, Error)]
pub enum RancherError {
    #[error(transparent)]
    Oidc(#[from] OidcError),

    #[error(transparent)]
    Failed(Box<dyn Error + Send + Sync>),
}

/// Trades a login at the identity provider of Rancher for a token of one of its clusters.
#[async_trait(?Send)]
pub trait RancherCredentials {
    /// `authorizer` logs `login` in at the identity provider; the token lives for `ttl`.
    async fn credential(
        &self,
        authorizer: &dyn OidcAuthorizer,
        login: UserCredentials,
        cluster_name: &str,
        ttl: Duration,
    ) -> Result<RancherCredential, RancherError>;
}
