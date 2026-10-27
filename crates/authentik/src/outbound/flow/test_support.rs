//! Fixtures and fakes shared by the tests of the flow adapter.

use crate::domain::models::mfa::{MfaChallenge, MfaResponse};
use crate::domain::ports::flow::{MfaError, SecondFactor};
use async_trait::async_trait;
use httpmock::Method::{GET, POST};
use httpmock::MockServer;
use serde_json::json;
use std::cell::RefCell;
use url::Url;

/// Answers the second factor with `response`, or fails without one, and records what it was asked. Gives
/// up on the first rejection.
#[derive(Default)]
pub struct FakeMfa {
    pub response: Option<MfaResponse>,
    pub asked: RefCell<Vec<(MfaChallenge, String)>>,
}

impl FakeMfa {
    pub fn answering(response: MfaResponse) -> Self {
        FakeMfa {
            response: Some(response),
            ..Default::default()
        }
    }
}

#[async_trait(?Send)]
impl SecondFactor for FakeMfa {
    async fn respond(
        &self,
        challenge: &MfaChallenge,
        idp_host: &str,
    ) -> Result<MfaResponse, MfaError> {
        self.asked
            .borrow_mut()
            .push((challenge.clone(), idp_host.to_string()));
        self.response
            .clone()
            .ok_or_else(|| MfaError::NoSupportedMethod("none in this test".to_string()))
    }

    async fn rejected(&self, reason: &str) -> Result<(), MfaError> {
        Err(MfaError::TooManyRejections {
            attempts: 1,
            reason: reason.to_string(),
        })
    }
}

const IDENTIFICATION: &str = include_str!("../../../testdata/identification.json");
const PASSWORD: &str = include_str!("../../../testdata/password.json");
pub const VALIDATE: &str = include_str!("../../../testdata/validate_totp_webauthn.json");
pub const AUTOSUBMIT_STS: &str = include_str!("../../../testdata/autosubmit_sts.json");

/// The url of `path` on the mock `server`.
pub fn url(server: &MockServer, path: &str) -> Url {
    Url::parse(&server.url(path)).unwrap()
}

pub const INIT: &str = "/application/saml/example/sso/binding/init/";
pub const AUTH_EXEC: &str = "/api/v3/flows/executor/default-authentication-flow/";
// The raw query of the authentication flow is `next=%2Fapplication...`; it is escaped once more for `query=`.
const AUTH_QUERY: &str = "next=%2Fapplication%2Fsaml%2Fexample%2Fsso%2Fbinding%2Finit%2F";
pub const AUTH_LOCATION: &str = "/api/v3/flows/executor/default-authentication-flow/?query=next%3D%252Fapplication%252Fsaml%252Fexample%252Fsso%252Fbinding%252Finit%252F";

pub fn challenge_response(then: httpmock::Then, body: &str) {
    then.status(200)
        .header("Content-Type", "application/json")
        .body(body);
}

/// Mocks the login flow up to the stage after which `then` is mocked by the caller. State is carried by
/// a `stage` cookie, like the real session.
pub fn mock_authentication(server: &MockServer, after_password: &str) {
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
