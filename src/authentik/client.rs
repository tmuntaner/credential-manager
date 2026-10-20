use crate::authentik::flow::mfa::InteractiveMfa;
use crate::authentik::flow::session::{FlowError, FlowSession, SamlAssertion};
use crate::authentik::mfa::MfaSelection;
use crate::aws::sso::credentials::{AwsSSOCredentials, AwsSsoError};
use crate::aws::sts::credentials::{AwsCredentials, AwsCredentialsError};
use crate::aws::Credential;
use crate::http::api_client::ApiError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthentikError {
    #[error(transparent)]
    Api(#[from] ApiError),

    #[error(transparent)]
    Flow(#[from] FlowError),

    #[error(transparent)]
    AwsCredentials(#[from] AwsCredentialsError),

    #[error(transparent)]
    AwsSso(#[from] AwsSsoError),
}

/// This is the entrypoint to communicate with authentik to generate temporary credentials.
pub struct AuthentikClient {
    enable_desktop_notifications: bool,
    aws_credentials: AwsCredentials,
    aws_sso_credentials: AwsSSOCredentials,
}

impl AuthentikClient {
    /// Generates a new [`AuthentikClient`] object.
    pub fn new(enable_desktop_notifications: bool) -> Result<AuthentikClient, AuthentikError> {
        Ok(AuthentikClient {
            enable_desktop_notifications,
            aws_credentials: AwsCredentials::new()?,
            aws_sso_credentials: AwsSSOCredentials::new()?,
        })
    }

    pub async fn aws_credentials(
        &self,
        username: String,
        password: String,
        app_url: String,
        role_arn: Option<String>,
        mfa: Option<MfaSelection>,
    ) -> Result<Vec<Credential>, AuthentikError> {
        let assertion = self.login(&username, &password, &app_url, mfa).await?;

        Ok(self.aws_credentials.run(assertion, role_arn).await?)
    }

    pub async fn aws_sso_credentials(
        &self,
        username: String,
        password: String,
        app_url: String,
        region: String,
        role_arn: Option<String>,
        mfa: Option<MfaSelection>,
    ) -> Result<Vec<Credential>, AuthentikError> {
        let assertion = self.login(&username, &password, &app_url, mfa).await?;

        Ok(self
            .aws_sso_credentials
            .run(assertion, region, role_arn)
            .await?)
    }

    /// Runs the authentik flows for the SAML application at `app_url` and returns its assertion.
    async fn login(
        &self,
        username: &str,
        password: &str,
        app_url: &str,
        mfa: Option<MfaSelection>,
    ) -> Result<SamlAssertion, AuthentikError> {
        let mfa = InteractiveMfa::new(mfa, self.enable_desktop_notifications);

        Ok(FlowSession::new(Box::new(mfa))?
            .login(&entry_url(app_url), username, password)
            .await?)
    }
}

/// The SAML app url as the flow needs it. authentik answers `404` for `.../init` without the trailing
/// slash, and the settings store the url without it.
pub fn entry_url(app_url: &str) -> String {
    if app_url.ends_with('/') {
        app_url.to_string()
    } else {
        format!("{app_url}/")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authentik::flow::session::tests::{
        challenge_response, mock_authentication, AUTH_EXEC, INIT,
    };
    use httpmock::Method::{GET, POST};
    use httpmock::MockServer;
    use serde_json::json;

    const STORED_URL: &str = "https://id.example.com/application/saml/aws/sso/binding/init";

    #[test]
    fn entry_url_adds_the_trailing_slash_once() {
        assert_eq!(entry_url(STORED_URL), format!("{STORED_URL}/"));
        assert_eq!(
            entry_url(&format!("{STORED_URL}/")),
            format!("{STORED_URL}/")
        );
    }

    fn autosubmit(destination: &str, saml_response: &str) -> String {
        json!({
            "component": "ak-stage-autosubmit",
            "url": destination,
            "attrs": {"SAMLResponse": saml_response},
        })
        .to_string()
    }

    /// The whole authentication flow without MFA, then `init` redirecting into the authorization flow
    /// that ends in an autosubmit stage for `destination`.
    fn mock_login(server: &MockServer, destination: &str, saml_response: &str) {
        mock_authentication(
            server,
            &json!({"component": "xak-flow-redirect", "to": INIT}).to_string(),
        );
        server.mock(|when, then| {
            when.method(GET)
                .path(INIT)
                .header_includes("Cookie", "authentik_session=ok");
            then.status(302).header("Location", "/if/flow/authz/");
        });
        let body = autosubmit(destination, saml_response);
        server.mock(|when, then| {
            when.method(GET)
                .path("/api/v3/flows/executor/authz/")
                .query_param("query", "");
            challenge_response(then, &body);
        });
    }

    #[tokio::test]
    async fn logs_in_at_the_entry_url_with_the_trailing_slash() {
        let server = MockServer::start();
        mock_login(&server, "https://signin.aws.amazon.com/saml", "assertion");

        // The stored url has no trailing slash; the mocks only know the one with it.
        let assertion = AuthentikClient::new(false)
            .unwrap()
            .login(
                "user",
                "secret",
                &server.url(INIT.trim_end_matches('/')),
                None,
            )
            .await
            .unwrap();

        assert_eq!(assertion.saml_response, "assertion");
        assert_eq!(assertion.destination, "https://signin.aws.amazon.com/saml");
    }

    #[tokio::test]
    async fn aws_credentials_logs_in_and_selects_the_role() {
        let server = MockServer::start();
        let saml_response = crate::authentik::saml_parsers::tests::base64_encode(include_str!(
            "../../testdata/assertion_sts.xml"
        ));
        mock_login(
            &server,
            "https://signin.aws.amazon.com/saml",
            &saml_response,
        );

        // STS is not reachable from a test, but a role that is not in the assertion is refused first.
        let err = AuthentikClient::new(false)
            .unwrap()
            .aws_credentials(
                "user".to_string(),
                "secret".to_string(),
                server.url(INIT.trim_end_matches('/')),
                Some("arn:aws:iam::999999999999:role/Missing".to_string()),
                None,
            )
            .await
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "could not find role_arn arn:aws:iam::999999999999:role/Missing"
        );
    }

    #[tokio::test]
    async fn aws_sso_credentials_goes_from_the_flow_to_role_credentials() {
        let server = MockServer::start();
        mock_login(&server, &server.url("/acs"), "assertion");
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

        let client = AuthentikClient {
            enable_desktop_notifications: false,
            aws_credentials: AwsCredentials::new().unwrap(),
            aws_sso_credentials: AwsSSOCredentials::with_portal_url(server.base_url()).unwrap(),
        };
        let credentials_list = client
            .aws_sso_credentials(
                "user".to_string(),
                "secret".to_string(),
                server.url(INIT.trim_end_matches('/')),
                "eu-central-1".to_string(),
                Some("arn:aws:iam::111111111111:role/ExampleAdmin".to_string()),
                None,
            )
            .await
            .unwrap();

        credentials.assert();
        assert_eq!(credentials_list.len(), 1);
        assert_eq!(credentials_list[0].access_key_id(), "access-key");
        assert_eq!(credentials_list[0].session_token(), "session-token");
    }

    #[tokio::test]
    async fn a_failed_login_is_reported() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path(INIT);
            then.status(404);
        });
        server.mock(|when, then| {
            when.method(POST).path(AUTH_EXEC);
            then.status(404);
        });

        let err = AuthentikClient::new(false)
            .unwrap()
            .aws_credentials(
                "user".to_string(),
                "secret".to_string(),
                server.url(INIT),
                None,
                None,
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("to redirect to a flow"), "{err}");
    }
}
