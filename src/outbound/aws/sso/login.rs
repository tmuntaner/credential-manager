use crate::domain::models::saml::SamlAssertion;
use base::api_client::{AcceptType, ApiClient, ApiError};
use serde::Deserialize;
use std::collections::HashMap;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum SsoLoginError {
    #[error(transparent)]
    Api(#[from] ApiError),

    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error(transparent)]
    Url(#[from] url::ParseError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("could not get host")]
    NoHost,

    #[error("could not get org-id")]
    NoOrgId,

    #[error("could not get auth code")]
    NoAuthCode,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct TokenResponse {
    token: String,
}

struct WorkflowStartResponse {
    org_id: String,
    auth_code: String,
}

pub struct SsoPortalLogin {
    client: ApiClient,
}

impl SsoPortalLogin {
    /// Generates a new [`SsoPortalLogin`] object.
    pub fn new() -> Result<SsoPortalLogin, SsoLoginError> {
        let client = ApiClient::new()?;
        Ok(SsoPortalLogin { client })
    }

    /// Posts the assertion to the Identity Center ACS and trades the result for a portal token.
    pub async fn run(
        &self,
        assertion: SamlAssertion,
        portal_url: String,
    ) -> Result<String, SsoLoginError> {
        let workflow_start = self
            .workflow_start(assertion.saml_response, assertion.destination)
            .await?;
        let token_response = self
            .token_response(portal_url, workflow_start.auth_code, workflow_start.org_id)
            .await?;

        Ok(token_response.token)
    }

    async fn workflow_start(
        &self,
        saml_response: String,
        saml_destination: String,
    ) -> Result<WorkflowStartResponse, SsoLoginError> {
        let mut form: HashMap<String, String> = HashMap::new();
        form.insert(String::from("SAMLResponse"), saml_response);
        form.insert(String::from("RelayState"), String::from(""));

        let response = self
            .client
            .post_form(saml_destination.as_str(), &form, AcceptType::Html)
            .await?;

        let hash_query: HashMap<_, _> = response.url().query_pairs().into_owned().collect();

        // url is in the form of "org-id.awsapps.com" and we want the org-id from it
        let org_id = response
            .url()
            .host_str()
            .ok_or(SsoLoginError::NoHost)?
            .split('.')
            .next()
            .ok_or(SsoLoginError::NoOrgId)?
            .to_string();
        let auth_code = hash_query
            .get("workflowResultHandle")
            .ok_or(SsoLoginError::NoAuthCode)?
            .to_owned();

        Ok(WorkflowStartResponse { org_id, auth_code })
    }

    async fn token_response(
        &self,
        base_url: String,
        auth_code: String,
        org_id: String,
    ) -> Result<TokenResponse, SsoLoginError> {
        let mut token_url = Url::parse(base_url.as_str())?;
        token_url.set_path("/auth/sso-token");

        let mut form: HashMap<String, String> = HashMap::new();
        form.insert(String::from("authCode"), auth_code);
        form.insert(String::from("orgId"), org_id);

        let response = self
            .client
            .post_form(token_url.as_str(), &form, AcceptType::Json)
            .await?;
        let body = response.text().await?;
        let response: TokenResponse = serde_json::from_str(body.as_str())?;

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::Method::{GET, POST};
    use httpmock::MockServer;

    /// The ACS answers `307` and then `302` to the awsapps start page, as in the capture.
    fn mock_acs(server: &MockServer) {
        server.mock(|when, then| {
            when.method(POST)
                .path("/acs")
                .form_urlencoded_tuple("SAMLResponse", "assertion")
                .form_urlencoded_tuple("RelayState", "");
            then.status(307).header("Location", "/acs-2");
        });
        server.mock(|when, then| {
            when.method(POST).path("/acs-2");
            then.status(302)
                .header("Location", "/start/?workflowResultHandle=handle-1");
        });
        server.mock(|when, then| {
            when.method(GET).path("/start/");
            then.status(200);
        });
    }

    #[tokio::test]
    async fn workflow_start_follows_the_acs_redirects() {
        let server = MockServer::start();
        mock_acs(&server);

        let start = SsoPortalLogin::new()
            .unwrap()
            .workflow_start("assertion".to_string(), server.url("/acs"))
            .await
            .unwrap();

        assert_eq!(start.auth_code, "handle-1");
        // The org id is the first label of the final host.
        assert_eq!(start.org_id, "127");
    }

    #[tokio::test]
    async fn workflow_start_fails_without_a_workflow_handle() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/acs");
            then.status(200);
        });

        let err = SsoPortalLogin::new()
            .unwrap()
            .workflow_start("assertion".to_string(), server.url("/acs"))
            .await
            .err()
            .unwrap();

        assert_eq!(err.to_string(), "could not get auth code");
    }

    #[tokio::test]
    async fn token_response_posts_the_auth_code_and_org_id() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/auth/sso-token")
                .header("Accept", "application/json")
                .form_urlencoded_tuple("authCode", "handle-1")
                .form_urlencoded_tuple("orgId", "d-123");
            then.status(200).body(r#"{"token": "portal-token"}"#);
        });

        let response = SsoPortalLogin::new()
            .unwrap()
            .token_response(
                server.base_url(),
                "handle-1".to_string(),
                "d-123".to_string(),
            )
            .await
            .unwrap();

        assert_eq!(response.token, "portal-token");
        mock.assert();
    }

    #[tokio::test]
    async fn token_response_fails_on_an_unexpected_body() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/auth/sso-token");
            then.status(200).body("<html>nope</html>");
        });

        let result = SsoPortalLogin::new()
            .unwrap()
            .token_response(server.base_url(), "h".to_string(), "o".to_string())
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn run_posts_the_assertion_and_returns_the_portal_token() {
        let server = MockServer::start();
        let acs = server.mock(|when, then| {
            when.method(POST)
                .path("/acs")
                .form_urlencoded_tuple("SAMLResponse", "assertion")
                .form_urlencoded_tuple("RelayState", "");
            then.status(302)
                .header("Location", "/start/?workflowResultHandle=handle-2");
        });
        server.mock(|when, then| {
            when.method(GET).path("/start/");
            then.status(200);
        });
        server.mock(|when, then| {
            when.method(POST)
                .path("/auth/sso-token")
                .form_urlencoded_tuple("authCode", "handle-2")
                .form_urlencoded_tuple("orgId", "127");
            then.status(200).body(r#"{"token": "portal-token"}"#);
        });

        // The ACS url of the assertion is used as is.
        let token = SsoPortalLogin::new()
            .unwrap()
            .run(
                SamlAssertion {
                    saml_response: "assertion".to_string(),
                    destination: server.url("/acs"),
                    relay_state: None,
                },
                server.base_url(),
            )
            .await
            .unwrap();

        assert_eq!(token, "portal-token");
        acs.assert();
    }
}
