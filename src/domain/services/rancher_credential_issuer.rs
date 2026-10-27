//! Logs in at the identity provider of Rancher and trades the login for a cluster token.

use crate::domain::models::rancher_credentials::RancherCredential;
use crate::domain::models::user_credentials::UserCredentials;
use crate::domain::ports::login::OidcAuthorizer;
use crate::domain::ports::rancher::{RancherCredentialIssuer, RancherCredentials, RancherError};
use async_trait::async_trait;
use std::time::Duration;

/// Issues Rancher credentials through the identity provider of Rancher.
pub struct RancherCredentialIssuerService {
    authorizer: Box<dyn OidcAuthorizer>,
    rancher: Box<dyn RancherCredentials>,
}

impl RancherCredentialIssuerService {
    pub fn new(authorizer: Box<dyn OidcAuthorizer>, rancher: Box<dyn RancherCredentials>) -> Self {
        Self {
            authorizer,
            rancher,
        }
    }
}

#[async_trait(?Send)]
impl RancherCredentialIssuer for RancherCredentialIssuerService {
    async fn issue(
        &self,
        login: UserCredentials,
        cluster_name: &str,
        ttl: Duration,
    ) -> Result<RancherCredential, RancherError> {
        self.rancher
            .credential(self.authorizer.as_ref(), login, cluster_name, ttl)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::oidc::OidcError;
    use crate::domain::models::secret::SafeSecret;
    use time::OffsetDateTime;

    struct FixedCode;

    #[async_trait(?Send)]
    impl OidcAuthorizer for FixedCode {
        async fn authorize(
            &self,
            _login: UserCredentials,
            _redirect_uri: &str,
        ) -> Result<String, OidcError> {
            Ok("abc".to_string())
        }
    }

    struct FakeRancher;

    #[async_trait(?Send)]
    impl RancherCredentials for FakeRancher {
        async fn credential(
            &self,
            authorizer: &dyn OidcAuthorizer,
            login: UserCredentials,
            cluster_name: &str,
            ttl: Duration,
        ) -> Result<RancherCredential, RancherError> {
            let code = authorizer.authorize(login, "https://r/verify-auth").await?;

            Ok(RancherCredential {
                token: code,
                token_id: "i".to_string(),
                expiry: OffsetDateTime::UNIX_EPOCH + ttl,
                cluster_name: cluster_name.to_string(),
                cluster_id: "c".to_string(),
                server_url: "https://r".to_string(),
                ca: "ca".to_string(),
            })
        }
    }

    #[tokio::test]
    async fn logs_in_through_the_authorizer_for_the_cluster() {
        let issuer =
            RancherCredentialIssuerService::new(Box::new(FixedCode), Box::new(FakeRancher));
        let login = UserCredentials {
            username: "user".to_string(),
            password: SafeSecret::new("secret"),
            mfa: None,
        };

        let credential = issuer
            .issue(login, "op-prg2-1", Duration::from_secs(60))
            .await
            .unwrap();

        assert_eq!(credential.token, "abc");
        assert_eq!(credential.cluster_name, "op-prg2-1");
        assert_eq!(
            credential.expiry,
            OffsetDateTime::UNIX_EPOCH + Duration::from_secs(60)
        );
    }
}
