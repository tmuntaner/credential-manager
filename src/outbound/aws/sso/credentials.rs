use crate::domain::models::aws::AwsError;
use crate::domain::models::aws::RoleError;
use crate::domain::models::aws::{Credential, Role};
use crate::domain::models::saml::SamlAssertion;
use crate::domain::ports::aws::AwsSsoCredentials;
use crate::outbound::aws::sso::login::SsoLoginError;
use crate::outbound::aws::sso::login::SsoPortalLogin;
use crate::outbound::aws::sso::portal_api::SsoPortalError;
use crate::outbound::aws::sso::portal_client::SsoPortalClient;
use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AwsSsoError {
    #[error(transparent)]
    Login(#[from] SsoLoginError),

    #[error(transparent)]
    Portal(#[from] SsoPortalError),

    #[error(transparent)]
    Role(#[from] RoleError),
}

pub struct SsoCredentials {
    sso_portal_login: SsoPortalLogin,
    /// Replaces `https://portal.sso.{region}.amazonaws.com`, for tests.
    portal_url: Option<String>,
}

impl SsoCredentials {
    /// Generates a new [`SsoCredentials`] object.
    pub fn new() -> Result<SsoCredentials, AwsSsoError> {
        let sso_portal_login = SsoPortalLogin::new()?;
        Ok(SsoCredentials {
            sso_portal_login,
            portal_url: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_portal_url(portal_url: String) -> Result<SsoCredentials, AwsSsoError> {
        Ok(SsoCredentials {
            portal_url: Some(portal_url),
            ..SsoCredentials::new()?
        })
    }

    /// Call this function to get credentials from AWS SSO.
    async fn run(
        &self,
        assertion: SamlAssertion,
        region: String,
        role_arn: Option<String>,
    ) -> Result<Vec<Credential>, AwsSsoError> {
        let portal_url = self
            .portal_url
            .clone()
            .unwrap_or_else(|| format!("https://portal.sso.{region}.amazonaws.com"));
        let token = self
            .sso_portal_login
            .run(assertion, portal_url.clone())
            .await?;
        let sso_client = SsoPortalClient::new(portal_url)?;

        let roles = match role_arn {
            Some(arn) => {
                let role_arn = Role::from_arn(&arn)?;
                vec![role_arn]
            }
            None => sso_client.list_role_arns(token.clone()).await?,
        };
        let credentials = sso_client.list_credentials(token, roles).await?;

        Ok(credentials)
    }
}

#[async_trait(?Send)]
impl AwsSsoCredentials for SsoCredentials {
    async fn credentials(
        &self,
        assertion: &SamlAssertion,
        region: &str,
        role_arn: Option<&str>,
    ) -> Result<Vec<Credential>, AwsError> {
        self.run(
            assertion.clone(),
            region.to_string(),
            role_arn.map(str::to_string),
        )
        .await
        .map_err(|e| AwsError::Failed(Box::new(e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::Method::{GET, POST};
    use httpmock::MockServer;
    use serde_json::json;

    #[test]
    fn can_be_created() {
        assert!(SsoCredentials::new().is_ok());
    }

    #[tokio::test]
    async fn goes_from_the_assertion_to_role_credentials() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST)
                .path("/acs")
                .form_urlencoded_tuple("SAMLResponse", "assertion");
            then.status(302)
                .header("Location", "/start/?workflowResultHandle=handle");
        });
        server.mock(|when, then| {
            when.method(GET).path("/start/");
            then.status(200);
        });
        server.mock(|when, then| {
            when.method(POST)
                .path("/auth/sso-token")
                .form_urlencoded_tuple("authCode", "handle");
            then.status(200).body(r#"{"token": "portal-token"}"#);
        });
        let credentials = server.mock(|when, then| {
            when.method(GET)
                .path("/federation/credentials")
                .header("x-amz-sso_bearer_token", "portal-token")
                .query_param("account_id", "111111111111")
                .query_param("role_name", "ExampleAdmin");
            then.status(200)
                .header("content-type", "application/json")
                .body(
                    json!({"roleCredentials": {
                        "secretAccessKey": "secret-key",
                        "accessKeyId": "access-key",
                        "sessionToken": "session-token",
                        "expiration": 1_800_000_000_000_u64,
                    }})
                    .to_string(),
                );
        });
        let assertion = SamlAssertion {
            saml_response: "assertion".to_string(),
            destination: server.url("/acs"),
            relay_state: None,
        };

        let credentials_list = SsoCredentials::with_portal_url(server.base_url())
            .unwrap()
            .credentials(
                &assertion,
                "eu-central-1",
                Some("arn:aws:iam::111111111111:role/ExampleAdmin"),
            )
            .await
            .unwrap();

        credentials.assert();
        assert_eq!(credentials_list.len(), 1);
        assert_eq!(credentials_list[0].access_key_id(), "access-key");
        assert_eq!(credentials_list[0].session_token(), "session-token");
    }
}
