//! Logs in through the public API only: the service with the real flow executor against a mock authentik.

use async_trait::async_trait;
use authentik::{
    AuthCode, Authenticator, AuthenticatorError, AuthentikError, AuthentikService, FlowError,
    HttpFlowExecutor, MfaMethod, Password, StateError, StateSource, TotpCode, UserCredentials,
    WebauthnAssertion, WebauthnRequest,
};
use httpmock::Method::{GET, POST};
use httpmock::{MockServer, Then};
use serde_json::{json, Value};

const IDENTIFICATION: &str = include_str!("../testdata/identification.json");
const PASSWORD: &str = include_str!("../testdata/password.json");
const PASSWORD_REJECTED: &str = include_str!("../testdata/password_rejected.json");
const VALIDATE: &str = include_str!("../testdata/validate_totp_webauthn.json");
const AUTOSUBMIT: &str = include_str!("../testdata/autosubmit_sts.json");

struct FixedState;

impl StateSource for FixedState {
    fn state(&self) -> Result<String, StateError> {
        Ok("s".to_string())
    }
}

/// Types the TOTP code `123456` and has no security key.
struct TypedCode;

#[async_trait(?Send)]
impl Authenticator for TypedCode {
    async fn totp_code(&self) -> Result<TotpCode, AuthenticatorError> {
        Ok(TotpCode::new("123456"))
    }

    async fn choose_method(&self, methods: &[MfaMethod]) -> Result<MfaMethod, AuthenticatorError> {
        Ok(methods[0])
    }

    async fn mfa_rejected(&self, _reason: &str) {}

    async fn sign(
        &self,
        _request: &WebauthnRequest,
    ) -> Result<WebauthnAssertion, AuthenticatorError> {
        Err(AuthenticatorError::Failed("no security key".into()))
    }
}

fn service() -> AuthentikService<HttpFlowExecutor, FixedState, TypedCode> {
    AuthentikService::new(HttpFlowExecutor::new(), FixedState, TypedCode)
}

fn login(mfa: Option<MfaMethod>) -> UserCredentials {
    UserCredentials::new("user".to_string(), Password::new("secret"), mfa)
}

fn challenge(then: Then, body: &str) {
    then.status(200)
        .header("Content-Type", "application/json")
        .body(body);
}

/// Mocks a flow `slug` that asks for the username and the password, then answers with `after_password`.
fn mock_login_flow(server: &MockServer, slug: &str, after_password: &str) {
    let path = format!("/api/v3/flows/executor/{slug}/");
    server.mock(|when, then| {
        when.method(GET).path(&path).query_param("query", "");
        challenge(then, IDENTIFICATION);
    });
    server.mock(|when, then| {
        when.method(POST)
            .path(&path)
            .json_body(json!({"component": "ak-stage-identification", "uid_field": "user"}));
        challenge(then, PASSWORD);
    });
    server.mock(|when, then| {
        when.method(POST)
            .path(&path)
            .json_body(json!({"component": "ak-stage-password", "password": "secret"}));
        challenge(then, after_password);
    });
}

fn mock_start(server: &MockServer, path: &str, slug: &str) {
    let location = format!("/if/flow/{slug}/");
    server.mock(|when, then| {
        when.method(GET).path(path);
        then.status(302).header("Location", location);
    });
}

fn redirect(to: &str) -> String {
    json!({"component": "xak-flow-redirect", "to": to}).to_string()
}

#[tokio::test]
async fn logs_in_to_oidc_with_a_totp_code_and_hands_out_the_code() {
    let server = MockServer::start();
    mock_start(&server, "/application/o/authorize/", "auth");
    mock_login_flow(&server, "auth", VALIDATE);
    let totp = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v3/flows/executor/auth/")
            .json_body_includes(
                json!({"component": "ak-stage-authenticator-validate", "code": "123456"})
                    .to_string(),
            );
        challenge(then, &redirect("/verify-auth?code=abc&state=s"));
    });
    let client = server.mock(|when, then| {
        when.method(GET).path("/verify-auth");
        then.status(200);
    });

    let code: AuthCode = service()
        .oidc_code(
            login(Some(MfaMethod::Totp)),
            &server.url("/application/o/rancher/"),
            "rancher",
            &server.url("/verify-auth"),
        )
        .await
        .unwrap();

    assert_eq!(code.as_str(), "abc");
    totp.assert();
    // The code can only be used once: it is left to the client.
    client.assert_calls(0);
}

#[tokio::test]
async fn logs_in_to_saml_without_the_trailing_slash_of_the_stored_url() {
    let server = MockServer::start();
    mock_start(&server, "/application/saml/aws/sso/binding/init/", "auth");
    mock_login_flow(&server, "auth", &redirect("/done/"));
    mock_start(&server, "/done/", "authz");
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v3/flows/executor/authz/")
            .query_param("query", "");
        challenge(then, AUTOSUBMIT);
    });

    let assertion = service()
        .saml_assertion(
            &server.url("/application/saml/aws/sso/binding/init"),
            login(None),
        )
        .await
        .unwrap();

    let fixture: Value = serde_json::from_str(AUTOSUBMIT).unwrap();
    assert_eq!(assertion.destination, "https://signin.aws.amazon.com/saml");
    assert_eq!(
        assertion.saml_response,
        fixture["attrs"]["SAMLResponse"].as_str().unwrap()
    );
}

#[tokio::test]
async fn a_rejected_password_is_reported_with_its_reason() {
    let server = MockServer::start();
    mock_start(&server, "/application/o/authorize/", "auth");
    mock_login_flow(&server, "auth", PASSWORD_REJECTED);

    let err = service()
        .oidc_code(
            login(None),
            &server.url("/"),
            "rancher",
            &server.url("/verify-auth"),
        )
        .await
        .unwrap_err();

    assert!(
        matches!(&err, AuthentikError::Flow(FlowError::PasswordRejected(reason))
            if reason == "password: Invalid password"),
        "{err}"
    );
}
