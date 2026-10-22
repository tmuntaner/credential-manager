use crate::domain::models::rancher_credentials::RancherCredential;
use crate::domain::models::session::SessionToken;
use crate::domain::models::user_credentials::UserCredentials;
use crate::domain::ports::credential_issuer::{IssueCredential, RancherError};
use crate::domain::ports::oidc::OidcAuthorizer;
use crate::domain::ports::rancher_api::RancherApi;
use async_trait::async_trait;
use std::time::Duration;
use time::OffsetDateTime;

/// Creates tokens for clusters behind a Rancher that uses an OIDC provider for logins.
pub struct RancherCredentialService<A> {
    api: A,
}

impl<A: RancherApi> RancherCredentialService<A> {
    pub fn new(api: A) -> Self {
        Self { api }
    }

    async fn credential(
        &self,
        session: &SessionToken,
        cluster_name: &str,
        ttl: Duration,
    ) -> Result<RancherCredential, RancherError> {
        let expiry = time::Duration::try_from(ttl)
            .ok()
            .and_then(|ttl| OffsetDateTime::now_utc().checked_add(ttl))
            .ok_or(RancherError::TtlTooLong)?;
        let cluster = self.api.find_cluster(session, cluster_name).await?;
        let ca = self.api.ca_cert(session).await?;
        let token = self.api.create_token(session, &cluster.id, ttl).await?;

        Ok(RancherCredential {
            token: token.token,
            token_id: token.id,
            expiry,
            cluster_name: cluster_name.to_string(),
            server_url: cluster.server_url,
            cluster_id: cluster.id,
            ca,
        })
    }
}

#[async_trait(?Send)]
impl<A: RancherApi> IssueCredential for RancherCredentialService<A> {
    /// Logs in through `authorizer`, creates a token for `cluster_name` that lives for `ttl`, and logs out of
    /// the session again: the token is independent of the session it was created from.
    async fn generate(
        &self,
        authorizer: &dyn OidcAuthorizer,
        login: UserCredentials,
        cluster_name: &str,
        ttl: Duration,
    ) -> Result<RancherCredential, RancherError> {
        let code = authorizer
            .authorize(login, &self.api.redirect_uri())
            .await?;
        let session = self.api.login(&code).await?;

        let credential = self.credential(&session, cluster_name, ttl).await;
        if let Err(e) = self.api.logout(&session).await {
            log::warn!("could not log out of rancher: {e}");
        }

        credential
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::session::AuthCode;
    use crate::domain::ports::oidc::MockOidcAuthorizer;
    use crate::domain::ports::oidc::OidcError;
    use crate::domain::ports::rancher_api::{ApiToken, Cluster, MockRancherApi, RancherApiError};

    const SERVER_URL: &str = "https://rancher/k8s/clusters/c-m-j2xw7jk8";

    /// An authorizer that expects the login of `login()` and answers with `code`.
    fn authorizer(code: Result<&'static str, &'static str>) -> MockOidcAuthorizer {
        let mut authorizer = MockOidcAuthorizer::new();
        authorizer
            .expect_authorize()
            .withf(|login, redirect_uri| {
                login.username == "user"
                    && login.password == "secret"
                    && redirect_uri == "https://rancher/verify-auth"
            })
            .returning(move |_, _| {
                code.map(AuthCode::new)
                    .map_err(|e| OidcError::Failed(e.into()))
            });
        authorizer
    }

    fn login() -> UserCredentials {
        UserCredentials {
            username: "user".to_string(),
            password: "secret".to_string(),
            mfa: None,
        }
    }

    const TTL: Duration = Duration::from_secs(3600);

    /// Rancher where the code `abc` is exchanged for the session `session`.
    fn api() -> MockRancherApi {
        let mut api = MockRancherApi::new();
        api.expect_redirect_uri()
            .returning(|| "https://rancher/verify-auth".to_string());
        api.expect_login()
            .withf(|code| code.as_str() == "abc")
            .returning(|_| Ok(SessionToken::new("session")));
        api
    }

    fn cluster() -> Cluster {
        Cluster {
            id: "c-m-j2xw7jk8".to_string(),
            server_url: SERVER_URL.to_string(),
        }
    }

    async fn generate(
        api: MockRancherApi,
        authorizer: MockOidcAuthorizer,
        cluster_name: &str,
    ) -> Result<RancherCredential, RancherError> {
        RancherCredentialService::new(api)
            .generate(&authorizer, login(), cluster_name, TTL)
            .await
    }

    #[tokio::test]
    async fn generates_a_credential_and_logs_out() {
        let mut api = api();
        api.expect_find_cluster()
            .withf(|session, name| session.as_str() == "session" && name == "op-prg2-1")
            .returning(|_, _| Ok(cluster()));
        api.expect_ca_cert()
            .withf(|session| session.as_str() == "session")
            .returning(|_| Ok("PEM".to_string()));
        api.expect_create_token()
            .withf(|session, cluster_id, ttl| {
                session.as_str() == "session" && cluster_id == "c-m-j2xw7jk8" && *ttl == TTL
            })
            .returning(|_, _, _| {
                Ok(ApiToken {
                    id: "token-bpx5g".to_string(),
                    token: "token-bpx5g:secret".to_string(),
                })
            });
        api.expect_logout()
            .withf(|session| session.as_str() == "session")
            .times(1)
            .returning(|_| Ok(()));

        let before = OffsetDateTime::now_utc();
        let credential = generate(api, authorizer(Ok("abc")), "op-prg2-1")
            .await
            .unwrap();

        assert!(credential.expiry >= before + TTL - time::Duration::seconds(1));
        assert!(credential.expiry <= OffsetDateTime::now_utc() + TTL);
        assert_eq!(
            credential,
            RancherCredential {
                token: "token-bpx5g:secret".to_string(),
                token_id: "token-bpx5g".to_string(),
                expiry: credential.expiry,
                cluster_name: "op-prg2-1".to_string(),
                cluster_id: "c-m-j2xw7jk8".to_string(),
                server_url: SERVER_URL.to_string(),
                ca: "PEM".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn a_ttl_that_is_too_long_creates_no_token() {
        let mut api = api();
        api.expect_create_token().never();
        api.expect_logout().times(1).returning(|_| Ok(()));

        let err = RancherCredentialService::new(api)
            .generate(&authorizer(Ok("abc")), login(), "op-prg2-1", Duration::MAX)
            .await
            .unwrap_err();

        assert!(matches!(err, RancherError::TtlTooLong));
    }

    #[tokio::test]
    async fn logs_out_when_the_cluster_does_not_exist() {
        let mut api = api();
        api.expect_find_cluster()
            .returning(|_, name| Err(RancherApiError::ClusterNotFound(name.to_string())));
        api.expect_create_token().never();
        api.expect_logout().times(1).returning(|_| Ok(()));

        let err = generate(api, authorizer(Ok("abc")), "missing")
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            RancherError::Api(RancherApiError::ClusterNotFound(name)) if name == "missing"
        ));
    }

    #[tokio::test]
    async fn logs_out_when_the_token_cannot_be_created() {
        let mut api = api();
        api.expect_find_cluster().returning(|_, _| Ok(cluster()));
        api.expect_ca_cert().returning(|_| Ok("PEM".to_string()));
        api.expect_create_token()
            .returning(|_, _, _| Err(RancherApiError::Unauthorized));
        api.expect_logout().times(1).returning(|_| Ok(()));

        let err = generate(api, authorizer(Ok("abc")), "op-prg2-1")
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            RancherError::Api(RancherApiError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn a_failed_logout_does_not_fail_the_credential() {
        let mut api = api();
        api.expect_find_cluster().returning(|_, _| Ok(cluster()));
        api.expect_ca_cert().returning(|_| Ok("PEM".to_string()));
        api.expect_create_token().returning(|_, _, _| {
            Ok(ApiToken {
                id: "token-bpx5g".to_string(),
                token: "token-bpx5g:secret".to_string(),
            })
        });
        api.expect_logout()
            .times(1)
            .returning(|_| Err(RancherApiError::Failed("boom".into())));

        let credential = generate(api, authorizer(Ok("abc")), "op-prg2-1").await;

        assert!(credential.is_ok());
    }

    #[tokio::test]
    async fn an_unauthorized_login_is_reported() {
        let mut api = MockRancherApi::new();
        api.expect_redirect_uri()
            .returning(|| "https://rancher/verify-auth".to_string());
        api.expect_login()
            .returning(|_| Err(RancherApiError::Unauthorized));
        api.expect_logout().never();

        let err = generate(api, authorizer(Ok("abc")), "op-prg2-1")
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            RancherError::Api(RancherApiError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn an_identity_provider_failure_stops_before_rancher_is_logged_in() {
        let mut api = MockRancherApi::new();
        api.expect_redirect_uri()
            .returning(|| "https://rancher/verify-auth".to_string());
        api.expect_login().never();
        api.expect_logout().never();

        let err = generate(api, authorizer(Err("wrong password")), "op-prg2-1")
            .await
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "could not log in at the identity provider: wrong password"
        );
    }
}
