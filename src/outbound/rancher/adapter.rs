use crate::domain::models::rancher_credentials::RancherCredential;
use crate::domain::models::user_credentials::UserCredentials;
use crate::domain::ports::login::OidcAuthorizer;
use crate::domain::ports::rancher::{KubeconfigRenderer, RancherCredentials, RancherError};
use async_trait::async_trait;
use rancher::{IssueCredential, RancherApiClient, RancherCredentialService};
use std::time::Duration;

/// Issues Rancher credentials with the `rancher` crate.
pub struct RancherClient {
    service: RancherCredentialService<RancherApiClient>,
}

impl RancherClient {
    pub fn new(rancher_url: &str) -> Result<Self, RancherError> {
        let api = RancherApiClient::new(rancher_url)?;

        Ok(Self {
            service: RancherCredentialService::new(api),
        })
    }
}

#[async_trait(?Send)]
impl RancherCredentials for RancherClient {
    async fn credential(
        &self,
        authorizer: &dyn OidcAuthorizer,
        login: UserCredentials,
        cluster_name: &str,
        ttl: Duration,
    ) -> Result<RancherCredential, RancherError> {
        let credential = self
            .service
            .generate(
                &AuthorizerAdapter(authorizer),
                login.into(),
                cluster_name,
                ttl,
            )
            .await?;

        Ok(credential.into())
    }
}

/// Lets the `rancher` crate use an `OidcAuthorizer` of this application.
struct AuthorizerAdapter<'a>(&'a dyn OidcAuthorizer);

#[async_trait(?Send)]
impl rancher::OidcAuthorizer for AuthorizerAdapter<'_> {
    async fn authorize(
        &self,
        login: rancher::UserCredentials,
        redirect_uri: &str,
    ) -> Result<rancher::AuthCode, rancher::OidcError> {
        self.0
            .authorize(login.into(), redirect_uri)
            .await
            .map(rancher::AuthCode::new)
            .map_err(|e| rancher::OidcError::Failed(Box::new(e)))
    }
}

/// Renders kubeconfigs with the `rancher` crate.
pub struct RancherKubeconfig;

impl KubeconfigRenderer for RancherKubeconfig {
    fn kubeconfig(&self, credential: &RancherCredential) -> String {
        rancher::kubeconfig(&credential.into())
    }

    fn exec_credential(&self, credential: &RancherCredential) -> String {
        rancher::exec_credential(&credential.into())
    }
}
