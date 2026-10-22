use crate::domain::models::saml::SamlAssertion;
use crate::domain::models::user_credentials::UserCredentials;
use crate::domain::ports::flow::{FlowError, FlowExecutor, SecondFactor};
use crate::outbound::flow::session::FlowSession;
use async_trait::async_trait;
use url::Url;

/// Runs the flows through the flow executor API of authentik, as its web interface does.
#[derive(Debug, Default)]
pub struct HttpFlowExecutor;

impl HttpFlowExecutor {
    pub fn new() -> Self {
        HttpFlowExecutor
    }
}

#[async_trait(?Send)]
impl FlowExecutor for HttpFlowExecutor {
    async fn saml(
        &self,
        entry_url: &Url,
        login: &UserCredentials,
        mfa: &dyn SecondFactor,
    ) -> Result<SamlAssertion, FlowError> {
        Ok(FlowSession::new(mfa)?
            .login(entry_url, &login.username, login.password.as_str())
            .await?)
    }

    async fn oauth(
        &self,
        authorize_url: &Url,
        redirect_uri: &str,
        login: &UserCredentials,
        mfa: &dyn SecondFactor,
    ) -> Result<Url, FlowError> {
        Ok(FlowSession::new(mfa)?
            .login_oidc(
                authorize_url,
                redirect_uri,
                &login.username,
                login.password.as_str(),
            )
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::mfa::MfaResponse;
    use crate::domain::models::secret::{Password, TotpCode};
    use crate::domain::ports::flow::MfaError;
    use crate::outbound::flow::test_support::{
        challenge_response, mock_authentication, FakeMfa, AUTOSUBMIT_STS, INIT, VALIDATE,
    };
    use httpmock::Method::GET;
    use httpmock::MockServer;
    use serde_json::json;

    fn credentials() -> UserCredentials {
        UserCredentials::new("user".to_string(), Password::new("secret"), None)
    }

    #[tokio::test]
    async fn saml_returns_the_assertion() {
        let server = MockServer::start();
        mock_authentication(
            &server,
            &json!({"component": "xak-flow-redirect", "to": INIT}).to_string(),
        );
        server.mock(|when, then| {
            when.method(GET)
                .path(INIT)
                .header_includes("Cookie", "authentik_session=ok");
            then.status(302).header("Location", "/if/flow/authz/");
        });
        server.mock(|when, then| {
            when.method(GET)
                .path("/api/v3/flows/executor/authz/")
                .query_param("query", "");
            challenge_response(then, AUTOSUBMIT_STS);
        });

        let assertion = HttpFlowExecutor::new()
            .saml(
                &Url::parse(&server.url(INIT)).unwrap(),
                &credentials(),
                &FakeMfa::default(),
            )
            .await
            .unwrap();

        assert_eq!(assertion.destination, "https://signin.aws.amazon.com/saml");
    }

    #[tokio::test]
    async fn authorize_returns_the_redirect_to_the_client() {
        let server = MockServer::start();
        let target = server.url("/verify-auth?code=abc&state=xyz");
        mock_authentication(
            &server,
            &json!({"component": "xak-flow-redirect", "to": target}).to_string(),
        );

        let redirect = HttpFlowExecutor::new()
            .oauth(
                &Url::parse(&server.url(INIT)).unwrap(),
                &server.url("/verify-auth"),
                &credentials(),
                &FakeMfa::default(),
            )
            .await
            .unwrap();

        assert_eq!(redirect.as_str(), target);
    }

    async fn saml_error(server: &MockServer, mfa: &FakeMfa) -> FlowError {
        HttpFlowExecutor::new()
            .saml(&Url::parse(&server.url(INIT)).unwrap(), &credentials(), mfa)
            .await
            .unwrap_err()
    }

    #[tokio::test]
    async fn a_rejected_password_keeps_its_variant() {
        let server = MockServer::start();
        mock_authentication(
            &server,
            include_str!("../../../testdata/password_rejected.json"),
        );

        let err = saml_error(&server, &FakeMfa::default()).await;

        assert!(
            matches!(&err, FlowError::PasswordRejected(reason) if reason == "password: Invalid password"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn access_denied_keeps_its_variant() {
        let server = MockServer::start();
        mock_authentication(
            &server,
            r#"{"component": "ak-stage-access-denied", "error_message": "Not allowed"}"#,
        );

        let err = saml_error(&server, &FakeMfa::default()).await;

        assert!(
            matches!(&err, FlowError::AccessDenied(reason) if reason == "Not allowed"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn an_mfa_error_of_the_domain_is_handed_back_as_it_was() {
        let server = MockServer::start();
        mock_authentication(&server, VALIDATE);

        let err = saml_error(&server, &FakeMfa::default()).await;

        assert!(
            matches!(err, FlowError::Mfa(MfaError::NoSupportedMethod(_))),
            "{err}"
        );
    }

    #[tokio::test]
    async fn other_failures_keep_their_message() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path(INIT);
            then.status(404);
        });
        let mfa = FakeMfa::answering(MfaResponse::Totp {
            device: 0,
            code: TotpCode::new("1"),
        });

        let err = saml_error(&server, &mfa).await;

        assert!(matches!(err, FlowError::Failed(_)));
        assert!(err.to_string().contains("to redirect to a flow"), "{err}");
    }
}
