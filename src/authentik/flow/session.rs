use crate::authentik::flow::challenge::{self, AutosubmitChallenge, Challenge, ChallengeError};
use crate::authentik::flow::mfa::{MfaError, MfaHandler};
use crate::http::api_client::{AcceptType, ApiClient, ApiError, RawResponse};
use reqwest::StatusCode;
use serde_json::{json, Value};
use thiserror::Error;
use url::{form_urlencoded, Url};

/// Flows chained after one another (authentication, then authorization, ...) before giving up.
const MAX_FLOWS: usize = 5;
/// Stages of a single flow before giving up.
const MAX_STAGES: usize = 20;

#[derive(Debug, Error)]
pub enum FlowError {
    #[error(transparent)]
    Api(#[from] ApiError),

    #[error(transparent)]
    Url(#[from] url::ParseError),

    #[error(transparent)]
    Challenge(#[from] ChallengeError),

    #[error(transparent)]
    Mfa(#[from] MfaError),

    #[error("the authentik app url must end with a `/`: {0}")]
    EntryUrlWithoutSlash(String),

    #[error("the authentik app url has no host: {0}")]
    NoHost(String),

    #[error("gave up after {MAX_FLOWS} chained flows, the last one redirected to {0}")]
    TooManyFlows(Url),

    #[error("expected {url} to redirect to a flow, got status {status}")]
    NotARedirect { url: Url, status: StatusCode },

    #[error("the redirect from {0} has no Location header")]
    NoLocation(Url),

    #[error("the redirect to {0} is not an authentik flow")]
    NotAFlow(Url),

    #[error("authentik rejected the username: {0}")]
    UsernameRejected(String),

    #[error("authentik rejected the password: {0}")]
    PasswordRejected(String),

    #[error("authentik denied access: {0}")]
    AccessDenied(String),

    #[error("unexpected stage {component}: {challenge}")]
    UnexpectedStage { component: String, challenge: Value },

    #[error("the flow did not finish after {MAX_STAGES} stages, the last challenge was: {0}")]
    TooManyStages(Value),

    #[error("authentik returned {status}: {body}")]
    ErrorStatus { status: StatusCode, body: String },

    #[error("authentik denied the request (status {status}, content type {content_type})")]
    NotJson {
        status: StatusCode,
        content_type: String,
    },

    #[error("unexpected status {0} from authentik")]
    UnexpectedStatus(StatusCode),

    #[error("authentik returned invalid JSON")]
    InvalidJson(#[source] serde_json::Error),

    #[error("the autosubmit stage has no SAMLResponse")]
    NoSamlResponse,
}

/// The SAML response handed out by the authorization flow, to be POSTed to the service provider.
#[derive(Debug, Clone, PartialEq)]
pub struct SamlAssertion {
    /// Base64, exactly as in `attrs.SAMLResponse`.
    pub saml_response: String,
    /// The ACS URL.
    pub destination: String,
    pub relay_state: Option<String>,
}

enum FlowOutcome {
    Assertion(SamlAssertion),
    /// The flow finished; continue by requesting this URL (may be relative).
    Redirect(String),
}

/// Drives authentik's flow executor API headlessly. One session owns one cookie jar, which carries the
/// authentik session through every chained flow.
pub struct FlowSession {
    client: ApiClient,
    mfa: Box<dyn MfaHandler>,
}

impl FlowSession {
    pub fn new(mfa: Box<dyn MfaHandler>) -> Result<Self, FlowError> {
        Ok(FlowSession {
            client: ApiClient::new_no_redirect()?,
            mfa,
        })
    }

    /// Runs flows from `entry_url` (the SAML app `.../sso/binding/init/`, trailing slash required) until the
    /// autosubmit challenge, and returns the assertion.
    pub async fn login(
        &self,
        entry_url: &str,
        username: &str,
        password: &str,
    ) -> Result<SamlAssertion, FlowError> {
        if !entry_url.ends_with('/') {
            return Err(FlowError::EntryUrlWithoutSlash(entry_url.to_string()));
        }

        let mut next = Url::parse(entry_url)?;
        let idp_host = next
            .host_str()
            .ok_or_else(|| FlowError::NoHost(entry_url.to_string()))?
            .to_string();
        let origin = Url::parse(&next.origin().ascii_serialization())?;

        for _ in 0..MAX_FLOWS {
            let exec_url = self.start_flow(&next).await?;
            match self
                .run_stages(&exec_url, &idp_host, username, password)
                .await?
            {
                FlowOutcome::Assertion(assertion) => return Ok(assertion),
                FlowOutcome::Redirect(to) => next = origin.join(&to)?,
            }
        }

        Err(FlowError::TooManyFlows(next))
    }

    /// Requests `url` and turns the redirect into a flow into the executor URL of that flow.
    async fn start_flow(&self, url: &Url) -> Result<Url, FlowError> {
        let response = self.client.get_raw(url.as_str(), AcceptType::Html).await?;
        if !response.status.is_redirection() {
            return Err(FlowError::NotARedirect {
                url: url.clone(),
                status: response.status,
            });
        }

        let location = response
            .location
            .ok_or_else(|| FlowError::NoLocation(url.clone()))?;
        let target = url.join(&location)?;
        let slug = flow_slug(target.path()).ok_or_else(|| FlowError::NotAFlow(target.clone()))?;

        let query: String =
            form_urlencoded::byte_serialize(target.query().unwrap_or_default().as_bytes())
                .collect();
        let mut exec_url = url.join(&format!("/api/v3/flows/executor/{slug}/"))?;
        exec_url.set_query(Some(&format!("query={query}")));

        Ok(exec_url)
    }

    async fn run_stages(
        &self,
        exec_url: &Url,
        idp_host: &str,
        username: &str,
        password: &str,
    ) -> Result<FlowOutcome, FlowError> {
        let mut current = self.get_challenge(exec_url).await?;

        for _ in 0..MAX_STAGES {
            let rejection = challenge::rejection_of(&current);

            let body = match Challenge::parse(&current)? {
                Challenge::Identification => {
                    if let Some(reason) = rejection {
                        return Err(FlowError::UsernameRejected(reason));
                    }
                    json!({"component": "ak-stage-identification", "uid_field": username})
                }
                Challenge::Password => {
                    if let Some(reason) = rejection {
                        return Err(FlowError::PasswordRejected(reason));
                    }
                    json!({"component": "ak-stage-password", "password": password})
                }
                Challenge::Validate(validate) => {
                    if let Some(reason) = rejection {
                        self.mfa.rejected(&reason)?;
                    }
                    self.mfa.respond(&validate, idp_host).await?
                }
                Challenge::Autosubmit(autosubmit) => {
                    return Ok(FlowOutcome::Assertion(assertion(autosubmit)?));
                }
                Challenge::Redirect { to } => return Ok(FlowOutcome::Redirect(to)),
                Challenge::AccessDenied { error_message } => {
                    return Err(FlowError::AccessDenied(
                        error_message.unwrap_or_else(|| "no reason given".to_string()),
                    ));
                }
                Challenge::Unexpected { component } => {
                    return Err(FlowError::UnexpectedStage {
                        component,
                        challenge: current,
                    });
                }
            };

            current = self.post_challenge(exec_url, &body).await?;
        }

        Err(FlowError::TooManyStages(current))
    }

    async fn get_challenge(&self, exec_url: &Url) -> Result<Value, FlowError> {
        let response = self
            .client
            .get_raw(exec_url.as_str(), AcceptType::Json)
            .await?;
        self.challenge_from(response, exec_url).await
    }

    async fn post_challenge(&self, exec_url: &Url, body: &Value) -> Result<Value, FlowError> {
        let response = self.client.post_json_raw(exec_url.as_str(), body).await?;
        self.challenge_from(response, exec_url).await
    }

    /// Turns a response of the executor into a challenge. A successful stage answers `302` back to the
    /// executor; that is followed once.
    async fn challenge_from(&self, response: RawResponse, base: &Url) -> Result<Value, FlowError> {
        let response = if response.status.is_redirection() {
            let location = response
                .location
                .ok_or_else(|| FlowError::NoLocation(base.clone()))?;
            let next = base.join(&location)?;
            self.client.get_raw(next.as_str(), AcceptType::Json).await?
        } else {
            response
        };

        if response.status.as_u16() >= 400 {
            return Err(FlowError::ErrorStatus {
                status: response.status,
                body: response.body,
            });
        }

        let is_json = response
            .content_type
            .as_deref()
            .is_some_and(|content_type| content_type.contains("json"));
        if !is_json {
            return Err(FlowError::NotJson {
                status: response.status,
                content_type: response.content_type.unwrap_or_else(|| "none".to_string()),
            });
        }
        if response.status != reqwest::StatusCode::OK {
            return Err(FlowError::UnexpectedStatus(response.status));
        }

        serde_json::from_str(&response.body).map_err(FlowError::InvalidJson)
    }
}

/// The flow slug of an `/if/flow/<slug>/` path.
fn flow_slug(path: &str) -> Option<&str> {
    let (_, rest) = path.split_once("/if/flow/")?;
    rest.split('/').next().filter(|slug| !slug.is_empty())
}

fn assertion(mut autosubmit: AutosubmitChallenge) -> Result<SamlAssertion, FlowError> {
    let saml_response = autosubmit
        .attrs
        .remove("SAMLResponse")
        .ok_or(FlowError::NoSamlResponse)?;

    Ok(SamlAssertion {
        saml_response,
        destination: autosubmit.url,
        relay_state: autosubmit.attrs.remove("RelayState"),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::authentik::flow::challenge::ValidateChallenge;
    use crate::authentik::flow::mfa::NoMfaHandler;
    use async_trait::async_trait;
    use httpmock::Method::{GET, POST};
    use httpmock::MockServer;

    const IDENTIFICATION: &str = include_str!("../../../testdata/identification.json");
    const PASSWORD: &str = include_str!("../../../testdata/password.json");
    const PASSWORD_REJECTED: &str = include_str!("../../../testdata/password_rejected.json");
    pub(crate) const VALIDATE: &str = include_str!("../../../testdata/validate_totp_webauthn.json");
    pub(crate) const AUTOSUBMIT_STS: &str = include_str!("../../../testdata/autosubmit_sts.json");

    pub(crate) const INIT: &str = "/application/saml/example/sso/binding/init/";
    pub(crate) const AUTH_EXEC: &str = "/api/v3/flows/executor/default-authentication-flow/";
    // The raw query of the authentication flow is `next=%2Fapplication...`; it is escaped once more for `query=`.
    const AUTH_QUERY: &str = "next=%2Fapplication%2Fsaml%2Fexample%2Fsso%2Fbinding%2Finit%2F";
    pub(crate) const AUTH_LOCATION: &str = "/api/v3/flows/executor/default-authentication-flow/?query=next%3D%252Fapplication%252Fsaml%252Fexample%252Fsso%252Fbinding%252Finit%252F";

    pub(crate) fn challenge_response(then: httpmock::Then, body: &str) {
        then.status(200)
            .header("Content-Type", "application/json")
            .body(body);
    }

    /// Mocks the login flow up to the stage after which `then` is mocked by the caller. State is carried by
    /// a `stage` cookie, like the real session.
    pub(crate) fn mock_authentication(server: &MockServer, after_password: &str) {
        server.mock(|when, then| {
            when.method(GET).path(INIT).header_missing("Cookie");
            then.status(302).header(
                "Location",
                format!("/if/flow/default-authentication-flow/?{AUTH_QUERY}"),
            );
        });
        server.mock(|when, then| {
            when.method(GET)
                .path(AUTH_EXEC)
                .query_param("query", AUTH_QUERY)
                .header_missing("Cookie");
            challenge_response(then, IDENTIFICATION);
        });
        server.mock(|when, then| {
            when.method(POST).path(AUTH_EXEC).json_body(json!({
                "component": "ak-stage-identification",
                "uid_field": "user"
            }));
            then.status(302)
                .header("Location", AUTH_LOCATION)
                .header("Set-Cookie", "stage=password; Path=/");
        });
        server.mock(|when, then| {
            when.method(GET)
                .path(AUTH_EXEC)
                .header_includes("Cookie", "stage=password");
            challenge_response(then, PASSWORD);
        });
        server.mock(|when, then| {
            when.method(POST).path(AUTH_EXEC).json_body(json!({
                "component": "ak-stage-password",
                "password": "secret"
            }));
            then.status(302)
                .header("Location", AUTH_LOCATION)
                .header("Set-Cookie", "stage=done; Path=/")
                .header("Set-Cookie", "authentik_session=ok; Path=/");
        });
        server.mock(|when, then| {
            when.method(GET)
                .path(AUTH_EXEC)
                .header_includes("Cookie", "stage=done");
            challenge_response(then, after_password);
        });
    }

    fn redirect_to_init() -> String {
        json!({"component": "xak-flow-redirect", "to": INIT}).to_string()
    }

    fn session() -> FlowSession {
        FlowSession::new(Box::new(NoMfaHandler)).unwrap()
    }

    #[tokio::test]
    async fn logs_in_through_chained_flows_without_mfa() {
        let server = MockServer::start();
        mock_authentication(&server, &redirect_to_init());
        // With a session, `init` redirects into the authorization flow, without a query string.
        server.mock(|when, then| {
            when.method(GET)
                .path(INIT)
                .header_includes("Cookie", "authentik_session=ok");
            then.status(302).header(
                "Location",
                "/if/flow/default-provider-authorization-implicit-consent/",
            );
        });
        server.mock(|when, then| {
            when.method(GET)
                .path("/api/v3/flows/executor/default-provider-authorization-implicit-consent/")
                .query_param("query", "");
            challenge_response(then, AUTOSUBMIT_STS);
        });

        let assertion = session()
            .login(&server.url(INIT), "user", "secret")
            .await
            .unwrap();

        let fixture: Value = serde_json::from_str(AUTOSUBMIT_STS).unwrap();
        assert_eq!(assertion.destination, "https://signin.aws.amazon.com/saml");
        assert_eq!(
            assertion.saml_response,
            fixture["attrs"]["SAMLResponse"].as_str().unwrap()
        );
        assert_eq!(assertion.relay_state, None);
    }

    #[tokio::test]
    async fn reports_why_the_password_was_rejected() {
        let server = MockServer::start();
        mock_authentication(&server, PASSWORD_REJECTED);

        let err = session()
            .login(&server.url(INIT), "user", "secret")
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("rejected the password: password: Invalid password"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn fails_on_unexpected_stages() {
        let server = MockServer::start();
        mock_authentication(&server, r#"{"component": "ak-stage-consent"}"#);

        let err = session()
            .login(&server.url(INIT), "user", "secret")
            .await
            .unwrap_err();

        assert!(err
            .to_string()
            .contains("unexpected stage ak-stage-consent"));
    }

    #[tokio::test]
    async fn validate_stage_without_mfa_handler_fails() {
        let server = MockServer::start();
        mock_authentication(&server, VALIDATE);

        let err = session()
            .login(&server.url(INIT), "user", "secret")
            .await
            .unwrap_err();

        assert!(err.to_string().contains("MFA required but not implemented"));
    }

    struct CodeHandler;

    #[async_trait]
    impl MfaHandler for CodeHandler {
        async fn respond(
            &self,
            challenge: &ValidateChallenge,
            idp_host: &str,
        ) -> Result<Value, MfaError> {
            assert_eq!(challenge.device_challenges.len(), 2);
            assert_eq!(idp_host, "127.0.0.1");
            Ok(json!({"component": "ak-stage-authenticator-validate", "code": "123456"}))
        }
    }

    #[tokio::test]
    async fn posts_the_body_returned_by_the_mfa_handler() {
        let server = MockServer::start();
        mock_authentication(&server, VALIDATE);
        let mfa_post = server.mock(|when, then| {
            when.method(POST).path(AUTH_EXEC).json_body(json!({
                "component": "ak-stage-authenticator-validate",
                "code": "123456"
            }));
            then.status(200)
                .header("Content-Type", "application/json")
                .body(r#"{"component": "xak-flow-redirect", "to": "/done/"}"#);
        });
        server.mock(|when, then| {
            when.method(GET).path("/done/");
            then.status(302).header("Location", "/if/flow/authz/");
        });
        server.mock(|when, then| {
            when.method(GET)
                .path("/api/v3/flows/executor/authz/")
                .query_param("query", "");
            challenge_response(then, AUTOSUBMIT_STS);
        });

        let assertion = FlowSession::new(Box::new(CodeHandler))
            .unwrap()
            .login(&server.url(INIT), "user", "secret")
            .await
            .unwrap();

        mfa_post.assert();
        assert_eq!(assertion.destination, "https://signin.aws.amazon.com/saml");
    }

    #[tokio::test]
    async fn rejected_mfa_response_gives_up_by_default() {
        let server = MockServer::start();
        let rejected = json!({
            "component": "ak-stage-authenticator-validate",
            "response_errors": {"code": [{"string": "Invalid Token", "code": "invalid"}]},
            "device_challenges": []
        })
        .to_string();
        mock_authentication(&server, &rejected);

        let err = session()
            .login(&server.url(INIT), "user", "secret")
            .await
            .unwrap_err();

        // NoMfaHandler keeps the default `rejected`, which gives up.
        assert!(err.to_string().contains("MFA rejected"), "{err}");
    }

    #[tokio::test]
    async fn stops_after_too_many_chained_flows() {
        let server = MockServer::start();
        let init = server.mock(|when, then| {
            when.method(GET).path(INIT);
            then.status(302).header("Location", "/if/flow/loop/");
        });
        server.mock(|when, then| {
            when.method(GET).path("/api/v3/flows/executor/loop/");
            challenge_response(then, &redirect_to_init());
        });

        let err = session()
            .login(&server.url(INIT), "user", "secret")
            .await
            .unwrap_err();

        assert!(err.to_string().contains("5 chained flows"), "{err}");
        init.assert_calls(MAX_FLOWS);
    }

    #[tokio::test]
    async fn fails_without_a_location() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path(INIT);
            then.status(302);
        });

        let err = session()
            .login(&server.url(INIT), "user", "secret")
            .await
            .unwrap_err();

        assert!(err.to_string().contains("no Location header"), "{err}");
    }

    #[tokio::test]
    async fn fails_when_the_entry_url_does_not_redirect() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path(INIT);
            then.status(404);
        });

        let err = session()
            .login(&server.url(INIT), "user", "secret")
            .await
            .unwrap_err();

        assert!(err.to_string().contains("to redirect to a flow"), "{err}");
    }

    #[tokio::test]
    async fn fails_on_non_json_responses() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path(INIT);
            then.status(302).header("Location", "/if/flow/denied/");
        });
        server.mock(|when, then| {
            when.method(GET).path("/api/v3/flows/executor/denied/");
            then.status(200)
                .header("Content-Type", "text/html")
                .body("<html>blocked</html>");
        });

        let err = session()
            .login(&server.url(INIT), "user", "secret")
            .await
            .unwrap_err();

        assert!(err.to_string().contains("denied the request"), "{err}");
    }

    #[tokio::test]
    async fn fails_on_error_statuses_with_the_body() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path(INIT);
            then.status(302).header("Location", "/if/flow/broken/");
        });
        server.mock(|when, then| {
            when.method(GET).path("/api/v3/flows/executor/broken/");
            then.status(500)
                .header("Content-Type", "application/json")
                .body(r#"{"detail": "boom"}"#);
        });

        let err = session()
            .login(&server.url(INIT), "user", "secret")
            .await
            .unwrap_err();

        assert!(err.to_string().contains("500"), "{err}");
        assert!(err.to_string().contains("boom"), "{err}");
    }

    #[tokio::test]
    async fn requires_a_trailing_slash() {
        let err = session()
            .login(
                "https://id.example.com/application/saml/x/sso/binding/init",
                "u",
                "p",
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("must end with a `/`"));
    }

    #[test]
    fn extracts_flow_slugs() {
        assert_eq!(
            flow_slug("/if/flow/default-authentication-flow/"),
            Some("default-authentication-flow")
        );
        assert_eq!(flow_slug("/if/flow//"), None);
        assert_eq!(flow_slug("/somewhere/else/"), None);
    }

    /// Mocks `init` redirecting into a flow `slug` without a query.
    fn mock_flow_start(server: &MockServer, slug: &str) {
        let location = format!("/if/flow/{slug}/");
        server.mock(|when, then| {
            when.method(GET).path(INIT);
            then.status(302).header("Location", location);
        });
    }

    async fn login_error(server: &MockServer) -> String {
        session()
            .login(&server.url(INIT), "user", "secret")
            .await
            .unwrap_err()
            .to_string()
    }

    #[tokio::test]
    async fn reports_why_the_username_was_rejected() {
        let server = MockServer::start();
        mock_flow_start(&server, "auth");
        server.mock(|when, then| {
            when.method(GET).path("/api/v3/flows/executor/auth/");
            challenge_response(
                then,
                r#"{"component": "ak-stage-identification", "response_errors": {"uid_field": [{"string": "Failed to authenticate.", "code": "invalid"}]}}"#,
            );
        });

        let err = login_error(&server).await;

        assert!(
            err.contains("rejected the username: uid_field: Failed to authenticate."),
            "{err}"
        );
    }

    #[tokio::test]
    async fn reports_access_denied_with_and_without_a_reason() {
        let server = MockServer::start();
        mock_authentication(
            &server,
            r#"{"component": "ak-stage-access-denied", "error_message": "Not allowed"}"#,
        );
        assert!(login_error(&server)
            .await
            .contains("authentik denied access: Not allowed"));

        let server = MockServer::start();
        mock_authentication(&server, r#"{"component": "ak-stage-access-denied"}"#);
        assert!(login_error(&server)
            .await
            .contains("authentik denied access: no reason given"));
    }

    #[tokio::test]
    async fn stops_after_too_many_stages() {
        let server = MockServer::start();
        mock_flow_start(&server, "stuck");
        // A stage that never advances (e.g. a prompt that is always shown again).
        let stage = r#"{"component": "ak-stage-identification"}"#;
        server.mock(|when, then| {
            when.method(GET).path("/api/v3/flows/executor/stuck/");
            challenge_response(then, stage);
        });
        let posts = server.mock(|when, then| {
            when.method(POST).path("/api/v3/flows/executor/stuck/");
            challenge_response(then, stage);
        });

        let err = login_error(&server).await;

        assert!(err.contains("did not finish after 20 stages"), "{err}");
        posts.assert_calls(MAX_STAGES);
    }

    #[tokio::test]
    async fn fails_on_successful_non_200_json_responses() {
        let server = MockServer::start();
        mock_flow_start(&server, "empty");
        server.mock(|when, then| {
            when.method(GET).path("/api/v3/flows/executor/empty/");
            then.status(204).header("Content-Type", "application/json");
        });

        assert!(login_error(&server).await.contains("unexpected status 204"));
    }

    #[tokio::test]
    async fn fails_on_invalid_json() {
        let server = MockServer::start();
        mock_flow_start(&server, "garbled");
        server.mock(|when, then| {
            when.method(GET).path("/api/v3/flows/executor/garbled/");
            challenge_response(then, "{not json");
        });

        assert!(login_error(&server).await.contains("invalid JSON"));
    }

    #[tokio::test]
    async fn fails_on_a_stage_redirect_without_a_location() {
        let server = MockServer::start();
        mock_flow_start(&server, "redirecting");
        server.mock(|when, then| {
            when.method(GET).path("/api/v3/flows/executor/redirecting/");
            then.status(302);
        });

        assert!(login_error(&server).await.contains("no Location header"));
    }

    #[tokio::test]
    async fn fails_when_the_redirect_is_not_a_flow() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path(INIT);
            then.status(302).header("Location", "/if/user/");
        });

        assert!(login_error(&server)
            .await
            .contains("is not an authentik flow"));
    }

    #[tokio::test]
    async fn requires_a_host_in_the_entry_url() {
        let err = session()
            .login("data:text/plain/", "u", "p")
            .await
            .unwrap_err();

        assert!(err.to_string().contains("has no host"), "{err}");
    }

    #[tokio::test]
    async fn an_autosubmit_stage_without_a_saml_response_is_an_error() {
        let server = MockServer::start();
        mock_flow_start(&server, "authz");
        server.mock(|when, then| {
            when.method(GET).path("/api/v3/flows/executor/authz/");
            challenge_response(
                then,
                r#"{"component": "ak-stage-autosubmit", "url": "https://signin.aws.amazon.com/saml", "attrs": {}}"#,
            );
        });

        assert!(login_error(&server).await.contains("no SAMLResponse"));
    }

    #[tokio::test]
    async fn passes_the_relay_state_through() {
        let server = MockServer::start();
        mock_flow_start(&server, "authz");
        server.mock(|when, then| {
            when.method(GET).path("/api/v3/flows/executor/authz/");
            challenge_response(
                then,
                r#"{"component": "ak-stage-autosubmit", "url": "https://signin.aws.amazon.com/saml", "attrs": {"SAMLResponse": "abc", "RelayState": "xyz"}}"#,
            );
        });

        let assertion = session()
            .login(&server.url(INIT), "user", "secret")
            .await
            .unwrap();

        assert_eq!(assertion.relay_state.as_deref(), Some("xyz"));
        assert_eq!(assertion.saml_response, "abc");
    }
}
