use crate::domain::models::saml::SamlAssertion;
use crate::domain::ports::flow::{FlowError, MfaError, SecondFactor};
use crate::outbound::flow::challenge::{self, AutosubmitChallenge, Challenge, ChallengeError};
use crate::outbound::flow::mfa;
use base::api_client::{AcceptType, ApiClient, ApiError, RawResponse};
use reqwest::StatusCode;
use serde_json::{json, Value};
use thiserror::Error;
use url::{form_urlencoded, Url};

/// The maximum amount of Flows before giving up.
const MAX_FLOWS: usize = 5;

/// The maximum amount of stages of a single flow has before giving up.
const MAX_STAGES: usize = 20;

/// The FlowExecutor error.
#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error(transparent)]
    Domain(#[from] FlowError),

    #[error(transparent)]
    Api(#[from] ApiError),

    #[error(transparent)]
    Url(#[from] url::ParseError),

    #[error(transparent)]
    Challenge(#[from] ChallengeError),

    #[error("the authentik app url has no host: {0}")]
    NoHost(Url),

    #[error("gave up after {MAX_FLOWS} chained flows, the last one redirected to {0}")]
    TooManyFlows(Url),

    #[error("expected {url} to redirect to a flow, got status {status}")]
    NotARedirect { url: Url, status: StatusCode },

    #[error("the redirect from {0} has no Location header")]
    NoLocation(Url),

    #[error("the redirect to {0} is not an authentik flow")]
    NotAFlow(Url),

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

    #[error("the flow ended in a SAML autosubmit stage, but an OIDC redirect was expected")]
    UnexpectedAssertion,

    #[error("the flow ended in a redirect to {0}, but a SAML assertion was expected")]
    UnexpectedRedirect(Url),

    #[error("the autosubmit stage has no SAMLResponse")]
    NoSamlResponse,

    #[error("the second factor answered with device {0}, which authentik did not offer")]
    UnknownDevice(usize),
}

impl From<MfaError> for ExecutorError {
    fn from(e: MfaError) -> Self {
        ExecutorError::Domain(FlowError::Mfa(e))
    }
}

impl From<ExecutorError> for FlowError {
    fn from(e: ExecutorError) -> Self {
        match e {
            ExecutorError::Domain(e) => e,
            e => FlowError::Failed(Box::new(e)),
        }
    }
}

/// How the flow chain ended.
enum Finished {
    Assertion(SamlAssertion),
    /// The flow redirected to the OIDC client.
    Redirect(Url),
}

/// How the flow chain started.
enum FlowStart {
    /// A new flow url
    Flow(Url),
    /// The flow redirected back to the client (OIDC).
    Finished(Url),
}

/// The outcome of a flow.
enum FlowOutcome {
    Assertion(SamlAssertion),
    /// The flow finished with a new flow url to start a new one.
    Redirect(String),
}

/// Runs the flow executor API headlessly, with a cookie jar to keep state.
pub struct FlowSession<'a> {
    client: ApiClient,
    mfa: &'a dyn SecondFactor,
}

impl<'a> FlowSession<'a> {
    pub fn new(mfa: &'a dyn SecondFactor) -> Result<Self, ExecutorError> {
        Ok(FlowSession {
            client: ApiClient::new_no_redirect()?,
            mfa,
        })
    }

    /// Starts the SAML login flow.
    pub async fn login_saml(
        &self,
        entry_url: &Url,
        username: &str,
        password: &str,
    ) -> Result<SamlAssertion, ExecutorError> {
        match self.run_flows(entry_url, None, username, password).await? {
            Finished::Assertion(assertion) => Ok(assertion),
            Finished::Redirect(redirect) => Err(ExecutorError::UnexpectedRedirect(redirect)),
        }
    }

    /// Starts the OIDC login flow.
    pub async fn login_oidc(
        &self,
        authorize_url: &Url,
        redirect_uri: &str,
        username: &str,
        password: &str,
    ) -> Result<Url, ExecutorError> {
        match self
            .run_flows(authorize_url, Some(redirect_uri), username, password)
            .await?
        {
            Finished::Redirect(redirect) => Ok(redirect),
            Finished::Assertion(_) => Err(ExecutorError::UnexpectedAssertion),
        }
    }

    /// Runs the chained flows until an assertion or redirect.
    async fn run_flows(
        &self,
        start: &Url,
        redirect_uri: Option<&str>,
        username: &str,
        password: &str,
    ) -> Result<Finished, ExecutorError> {
        let idp_host = start
            .host_str()
            .ok_or_else(|| ExecutorError::NoHost(start.clone()))?
            .to_string();
        let origin = Url::parse(&start.origin().ascii_serialization())?;
        let mut next = start.clone();

        // run a chain of flows until max
        for _ in 0..MAX_FLOWS {
            // If it's a redirect back to the client (application), the flow is complete.
            if is_client(&next, redirect_uri) {
                return Ok(Finished::Redirect(next));
            }

            // start the flow and get the executor URL
            let exec_url = match self.start_flow(&next, redirect_uri).await? {
                FlowStart::Flow(exec_url) => exec_url,
                FlowStart::Finished(redirect) => return Ok(Finished::Redirect(redirect)),
            };

            // run the stages of the flow
            match self
                .run_stages(&exec_url, &idp_host, username, password)
                .await?
            {
                FlowOutcome::Assertion(assertion) => return Ok(Finished::Assertion(assertion)),
                FlowOutcome::Redirect(to) => next = origin.join(&to)?,
            }
        }

        Err(ExecutorError::TooManyFlows(next))
    }

    /// Starts the flow and returns the executor URL.
    async fn start_flow(
        &self,
        url: &Url,
        redirect_uri: Option<&str>,
    ) -> Result<FlowStart, ExecutorError> {
        // get the response from the URL
        let response = self.client.get_raw(url.as_str(), AcceptType::Html).await?;
        if !response.status.is_redirection() {
            return Err(ExecutorError::NotARedirect {
                url: url.clone(),
                status: response.status,
            });
        }

        // Get the location from the response (next redirect).
        let location = response
            .location
            .ok_or_else(|| ExecutorError::NoLocation(url.clone()))?;

        // generate the target URL
        let target = url.join(&location)?;

        // if the target is the OIDC client, we're done
        if is_client(&target, redirect_uri) {
            return Ok(FlowStart::Finished(target));
        }

        // get the flow slug from the target URL
        let slug =
            flow_slug(target.path()).ok_or_else(|| ExecutorError::NotAFlow(target.clone()))?;

        // build the query string
        let query: String =
            form_urlencoded::byte_serialize(target.query().unwrap_or_default().as_bytes())
                .collect();

        // generate the executor URL
        let mut exec_url = url.join(&format!("/api/v3/flows/executor/{slug}/"))?;
        exec_url.set_query(Some(&format!("query={query}")));

        Ok(FlowStart::Flow(exec_url))
    }

    /// Runs the stages of the flow
    async fn run_stages(
        &self,
        exec_url: &Url,
        idp_host: &str,
        username: &str,
        password: &str,
    ) -> Result<FlowOutcome, ExecutorError> {
        // get the challenge from the executor
        let mut current = self.get_challenge(exec_url).await?;

        // run through the stages of the flow.
        // if successful, return the outcome within the loop.
        for _ in 0..MAX_STAGES {
            let rejection = challenge::rejection_of(&current);

            // generate the challenge body based on the challenge type
            let body = match Challenge::parse(&current)? {
                Challenge::Identification => {
                    if let Some(reason) = rejection {
                        return Err(FlowError::UsernameRejected(reason).into());
                    }
                    json!({"component": "ak-stage-identification", "uid_field": username})
                }
                Challenge::Password => {
                    if let Some(reason) = rejection {
                        return Err(FlowError::PasswordRejected(reason).into());
                    }
                    json!({"component": "ak-stage-password", "password": password})
                }
                Challenge::Validate(validate) => {
                    if let Some(reason) = rejection {
                        self.mfa.rejected(&reason).await?;
                    }
                    let response = self
                        .mfa
                        .respond(&mfa::challenge(&validate), idp_host)
                        .await?;
                    mfa::body(&validate, response)?
                }
                Challenge::Autosubmit(autosubmit) => {
                    return Ok(FlowOutcome::Assertion(assertion(autosubmit)?));
                }
                Challenge::Redirect { to } => return Ok(FlowOutcome::Redirect(to)),
                Challenge::AccessDenied { error_message } => {
                    return Err(FlowError::AccessDenied(
                        error_message.unwrap_or_else(|| "no reason given".to_string()),
                    )
                    .into());
                }
                Challenge::Unexpected { component } => {
                    return Err(ExecutorError::UnexpectedStage {
                        component,
                        challenge: current,
                    });
                }
            };

            // post the challenge to get the next
            current = self.post_challenge(exec_url, &body).await?;
        }

        Err(ExecutorError::TooManyStages(current))
    }

    /// Gets the challenge from the executor URL.
    async fn get_challenge(&self, exec_url: &Url) -> Result<Value, ExecutorError> {
        let response = self
            .client
            .get_raw(exec_url.as_str(), AcceptType::Json)
            .await?;

        self.challenge_from(response, exec_url).await
    }

    /// Sends the challenge response to the executor URL.
    async fn post_challenge(&self, exec_url: &Url, body: &Value) -> Result<Value, ExecutorError> {
        let response = self.client.post_json_raw(exec_url.as_str(), body).await?;
        self.challenge_from(response, exec_url).await
    }

    /// Parses the challenge from the response.
    async fn challenge_from(
        &self,
        response: RawResponse,
        base: &Url,
    ) -> Result<Value, ExecutorError> {
        // get the response and follow redirects
        let response = if response.status.is_redirection() {
            let location = response
                .location
                .ok_or_else(|| ExecutorError::NoLocation(base.clone()))?;
            let next = base.join(&location)?;
            self.client.get_raw(next.as_str(), AcceptType::Json).await?
        } else {
            response
        };

        // if it's not a success, return an error
        if response.status.as_u16() >= 400 {
            return Err(ExecutorError::ErrorStatus {
                status: response.status,
                body: response.body,
            });
        }

        // ensure the response is json
        let is_json = response
            .content_type
            .as_deref()
            .is_some_and(|content_type| content_type.contains("json"));
        if !is_json {
            return Err(ExecutorError::NotJson {
                status: response.status,
                content_type: response.content_type.unwrap_or_else(|| "none".to_string()),
            });
        }

        // it should be a status OK
        if response.status != reqwest::StatusCode::OK {
            return Err(ExecutorError::UnexpectedStatus(response.status));
        }

        serde_json::from_str(&response.body).map_err(ExecutorError::InvalidJson)
    }
}

/// Check whether the `url` is the client's URL for OIDC.
fn is_client(url: &Url, redirect_uri: Option<&str>) -> bool {
    redirect_uri.is_some_and(|uri| url.as_str().starts_with(uri))
}

/// Parses the flow slug from the path.
fn flow_slug(path: &str) -> Option<&str> {
    let (_, rest) = path.split_once("/if/flow/")?;
    rest.split('/').next().filter(|slug| !slug.is_empty())
}

/// Parses the assertion from the autosubmit challenge.
fn assertion(mut autosubmit: AutosubmitChallenge) -> Result<SamlAssertion, ExecutorError> {
    let saml_response = autosubmit
        .attrs
        .remove("SAMLResponse")
        .ok_or(ExecutorError::NoSamlResponse)?;

    Ok(SamlAssertion {
        saml_response,
        destination: autosubmit.url,
        relay_state: autosubmit.attrs.remove("RelayState"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::mfa::MfaResponse;
    use crate::domain::models::secret::TotpCode;
    use crate::outbound::flow::test_support::*;
    use httpmock::Method::{GET, POST};
    use httpmock::MockServer;

    const PASSWORD_REJECTED: &str = include_str!("../../../testdata/password_rejected.json");

    fn redirect_to_init() -> String {
        json!({"component": "xak-flow-redirect", "to": INIT}).to_string()
    }

    /// A session for flows that must not need a second factor.
    fn session() -> FlowSession<'static> {
        FlowSession::new(Box::leak(Box::new(FakeMfa::default()))).unwrap()
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
            .login_saml(&url(&server, INIT), "user", "secret")
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
    async fn oidc_login_returns_the_redirect_to_the_client_without_requesting_it() {
        let server = MockServer::start();
        mock_authentication(&server, &redirect_to_init());
        // With a session, the authorize endpoint redirects straight back to the client.
        server.mock(|when, then| {
            when.method(GET)
                .path(INIT)
                .header_includes("Cookie", "authentik_session=ok");
            then.status(302)
                .header("Location", server.url("/verify-auth?code=abc&state=xyz"));
        });
        let client = server.mock(|when, then| {
            when.method(GET).path("/verify-auth");
            then.status(200);
        });

        let redirect = session()
            .login_oidc(
                &url(&server, INIT),
                &server.url("/verify-auth"),
                "user",
                "secret",
            )
            .await
            .unwrap();

        assert_eq!(redirect.path(), "/verify-auth");
        assert_eq!(redirect.query(), Some("code=abc&state=xyz"));
        client.assert_calls(0);
    }

    #[tokio::test]
    async fn oidc_login_stops_at_a_flow_redirect_to_the_client() {
        let server = MockServer::start();
        let target = server.url("/verify-auth?code=abc&state=xyz");
        mock_authentication(
            &server,
            &json!({"component": "xak-flow-redirect", "to": target}).to_string(),
        );
        let client = server.mock(|when, then| {
            when.method(GET).path("/verify-auth");
            then.status(200);
        });

        let redirect = session()
            .login_oidc(
                &url(&server, INIT),
                &server.url("/verify-auth"),
                "user",
                "secret",
            )
            .await
            .unwrap();

        assert_eq!(redirect.as_str(), target);
        client.assert_calls(0);
    }

    #[tokio::test]
    async fn reports_why_the_password_was_rejected() {
        let server = MockServer::start();
        mock_authentication(&server, PASSWORD_REJECTED);

        let err = session()
            .login_saml(&url(&server, INIT), "user", "secret")
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
            .login_saml(&url(&server, INIT), "user", "secret")
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
            .login_saml(&url(&server, INIT), "user", "secret")
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            ExecutorError::Domain(FlowError::Mfa(MfaError::NoSupportedMethod(_)))
        ));
    }

    #[tokio::test]
    async fn posts_the_answer_of_the_second_factor() {
        let server = MockServer::start();
        mock_authentication(&server, VALIDATE);
        let mfa_post = server.mock(|when, then| {
            when.method(POST).path(AUTH_EXEC).json_body_includes(
                json!({
                    "component": "ak-stage-authenticator-validate",
                    "code": "123456"
                })
                .to_string(),
            );
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

        let mfa = FakeMfa::answering(MfaResponse::Totp {
            device: 0,
            code: TotpCode::new("123456"),
        });
        let assertion = FlowSession::new(&mfa)
            .unwrap()
            .login_saml(&url(&server, INIT), "user", "secret")
            .await
            .unwrap();

        mfa_post.assert();
        let asked = mfa.asked.borrow();
        assert_eq!(asked[0].0.devices.len(), 2);
        assert_eq!(asked[0].1, "127.0.0.1");
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
            .login_saml(&url(&server, INIT), "user", "secret")
            .await
            .unwrap_err();

        // The fake gives up on the first rejection.
        assert!(err.to_string().contains("MFA rejected"), "{err}");
        assert!(err.to_string().contains("code: Invalid Token"), "{err}");
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
            .login_saml(&url(&server, INIT), "user", "secret")
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
            .login_saml(&url(&server, INIT), "user", "secret")
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
            .login_saml(&url(&server, INIT), "user", "secret")
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
            .login_saml(&url(&server, INIT), "user", "secret")
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
            .login_saml(&url(&server, INIT), "user", "secret")
            .await
            .unwrap_err();

        assert!(err.to_string().contains("500"), "{err}");
        assert!(err.to_string().contains("boom"), "{err}");
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
            .login_saml(&url(server, INIT), "user", "secret")
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
            .login_saml(&Url::parse("data:text/plain/").unwrap(), "u", "p")
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
            .login_saml(&url(&server, INIT), "user", "secret")
            .await
            .unwrap();

        assert_eq!(assertion.relay_state.as_deref(), Some("xyz"));
        assert_eq!(assertion.saml_response, "abc");
    }
}
