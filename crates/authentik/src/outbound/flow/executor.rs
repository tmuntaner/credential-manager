use crate::domain::models::saml::SamlAssertion;
use crate::domain::models::session::AuthentikSession;
use crate::domain::models::user_credentials::UserCredentials;
use crate::domain::ports::flow::{FlowError, FlowExecutor, Flowed, SecondFactor};
use crate::outbound::flow::session::FlowSession;
use async_trait::async_trait;
use time::OffsetDateTime;
use url::Url;

/// Runs the Authentik auth flow.
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
        session: Option<&AuthentikSession>,
    ) -> Result<Flowed<SamlAssertion>, FlowError> {
        let flow = FlowSession::new(mfa)?;
        if let Some(session) = session {
            flow.resume(entry_url, session);
        }

        let value = flow
            .login_saml(entry_url, &login.username, login.password.as_str())
            .await?;

        Ok(Flowed {
            value,
            session: session_after(&flow, entry_url, session),
        })
    }

    async fn oauth(
        &self,
        authorize_url: &Url,
        redirect_uri: &str,
        login: &UserCredentials,
        mfa: &dyn SecondFactor,
        session: Option<&AuthentikSession>,
    ) -> Result<Flowed<Url>, FlowError> {
        let flow = FlowSession::new(mfa)?;
        if let Some(session) = session {
            flow.resume(authorize_url, session);
        }

        let value = flow
            .login_oidc(
                authorize_url,
                redirect_uri,
                &login.username,
                login.password.as_str(),
            )
            .await?;

        Ok(Flowed {
            value,
            session: session_after(&flow, authorize_url, session),
        })
    }
}

/// The session after a flow ended.
fn session_after(
    flow: &FlowSession<'_>,
    url: &Url,
    before: Option<&AuthentikSession>,
) -> Option<AuthentikSession> {
    let after = flow.session(url, OffsetDateTime::now_utc())?;

    match before {
        Some(before) if before.cookies() == after.cookies() => Some(before.clone()),
        _ => Some(after),
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
    use time::OffsetDateTime;

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

        let flowed = HttpFlowExecutor::new()
            .saml(
                &Url::parse(&server.url(INIT)).unwrap(),
                &credentials(),
                &FakeMfa::default(),
                None,
            )
            .await
            .unwrap();

        assert_eq!(
            flowed.value.destination,
            "https://signin.aws.amazon.com/saml"
        );
        let session = flowed.session.expect("a session after the login");
        assert!(session.cookies().contains("authentik_session=ok"));
    }

    #[tokio::test]
    async fn saml_starts_from_the_session_it_is_given() {
        let server = MockServer::start();
        let resumed = server.mock(|when, then| {
            when.method(GET)
                .path(INIT)
                .header_includes("Cookie", "authentik_session=old");
            then.status(302).header("Location", "/if/flow/authz/");
        });
        server.mock(|when, then| {
            when.method(GET)
                .path("/api/v3/flows/executor/authz/")
                .query_param("query", "");
            challenge_response(then, AUTOSUBMIT_STS);
        });
        let before = AuthentikSession::new("authentik_session=old", OffsetDateTime::UNIX_EPOCH);

        // The fake MFA answers nothing, so the login must not need a second factor.
        let flowed = HttpFlowExecutor::new()
            .saml(
                &Url::parse(&server.url(INIT)).unwrap(),
                &credentials(),
                &FakeMfa::default(),
                Some(&before),
            )
            .await
            .unwrap();

        resumed.assert();
        // Unchanged cookies keep their age.
        assert_eq!(flowed.session, Some(before));
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
                None,
            )
            .await
            .unwrap();

        assert_eq!(redirect.value.as_str(), target);
    }

    async fn saml_error(server: &MockServer, mfa: &FakeMfa) -> FlowError {
        HttpFlowExecutor::new()
            .saml(
                &Url::parse(&server.url(INIT)).unwrap(),
                &credentials(),
                mfa,
                None,
            )
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
