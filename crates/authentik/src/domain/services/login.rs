use crate::domain::models::oidc::AuthCode;
use crate::domain::models::saml::SamlAssertion;
use crate::domain::models::user_credentials::UserCredentials;
use crate::domain::ports::authenticator::Authenticator;
use crate::domain::ports::flow::{FlowError, FlowExecutor};
use crate::domain::ports::state::{StateError, StateSource};
use crate::domain::services::mfa::InteractiveMfa;
use std::error::Error;
use thiserror::Error;
use url::Url;

/// How many times authentik may reject the second factor before giving up.
pub(crate) const MAX_MFA_ATTEMPTS: usize = 3;

/// Authentik login errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthentikError {
    #[error(transparent)]
    Flow(#[from] FlowError),

    #[error(transparent)]
    State(#[from] StateError),

    #[error("authentik refused the authorization: {0}")]
    OidcRefused(String),

    #[error("the state of the authorization response does not match the request")]
    OidcStateMismatch,

    #[error("the authorization response has no code: {0}")]
    OidcNoCode(String),

    #[error(transparent)]
    Failed(Box<dyn Error + Send + Sync>),
}

impl From<url::ParseError> for AuthentikError {
    fn from(e: url::ParseError) -> Self {
        AuthentikError::Failed(Box::new(e))
    }
}

/// Logs users into Authentik.
pub struct AuthentikService<F, S, A> {
    flows: F,
    state: S,
    authenticator: A,
}

impl<F: FlowExecutor, S: StateSource, A: Authenticator> AuthentikService<F, S, A> {
    pub fn new(flows: F, state: S, authenticator: A) -> Self {
        Self {
            flows,
            state,
            authenticator,
        }
    }

    /// Logs into Authentik with a SAML application.
    pub async fn saml_assertion(
        &self,
        app_url: &str,
        login: UserCredentials,
    ) -> Result<SamlAssertion, AuthentikError> {
        let mfa = InteractiveMfa::new(login.mfa, &self.authenticator);

        Ok(self.flows.saml(&entry_url(app_url)?, &login, &mfa).await?)
    }

    /// Logs into Authentik with an OIDC applicaiton.
    pub async fn oidc_code(
        &self,
        login: UserCredentials,
        issuer: &str,
        client_id: &str,
        redirect_uri: &str,
    ) -> Result<AuthCode, AuthentikError> {
        let state = self.state.state()?;
        let authorize_url = authorize_url(issuer, client_id, redirect_uri, &state)?;
        let mfa = InteractiveMfa::new(login.mfa, &self.authenticator);

        let redirect = self
            .flows
            .oauth(&authorize_url, redirect_uri, &login, &mfa)
            .await?;

        code_from_redirect(&redirect, &state)
    }
}

/// The OAuth authorization request for `client_id`, on the authentik behind `issuer`.
fn authorize_url(
    issuer: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
) -> Result<Url, AuthentikError> {
    let issuer = Url::parse(issuer)?;
    let mut url =
        Url::parse(&issuer.origin().ascii_serialization())?.join("/application/o/authorize/")?;
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", "openid profile email groups")
        .append_pair("state", state);

    Ok(url)
}

/// Reads the code of the redirect back to the client, after checking it answers our request.
fn code_from_redirect(redirect: &Url, state: &str) -> Result<AuthCode, AuthentikError> {
    let param = |name: &str| {
        redirect
            .query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };

    if let Some(error) = param("error") {
        let description = param("error_description").unwrap_or_default();
        return Err(AuthentikError::OidcRefused(
            format!("{error} {description}").trim().to_string(),
        ));
    }
    if param("state").as_deref() != Some(state) {
        return Err(AuthentikError::OidcStateMismatch);
    }

    param("code")
        .filter(|code| !code.is_empty())
        .map(AuthCode::new)
        .ok_or_else(|| AuthentikError::OidcNoCode(redirect.path().to_string()))
}

/// The SAML app url as the flow needs it. authentik answers `404` for `.../init` without the trailing
/// slash, and the settings store the url without it.
fn entry_url(app_url: &str) -> Result<Url, AuthentikError> {
    if app_url.ends_with('/') {
        Ok(Url::parse(app_url)?)
    } else {
        Ok(Url::parse(&format!("{app_url}/"))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::secret::Password;
    use crate::domain::ports::authenticator::MockAuthenticator;
    use crate::domain::ports::flow::SecondFactor;
    use crate::domain::ports::state::MockStateSource;
    use async_trait::async_trait;
    use std::cell::RefCell;

    const ISSUER: &str = "https://id.example.com/application/o/rancher/";
    const REDIRECT_URI: &str = "https://rancher.example.com/verify-auth";
    const STORED_URL: &str = "https://id.example.com/application/saml/aws/sso/binding/init";

    /// A flow executor that ends every flow in `result` and records the urls it was asked to start at.
    /// (mockall cannot mock the borrowed `&dyn SecondFactor` of an `async_trait`.)
    struct FakeFlows {
        result: RefCell<Option<Result<Url, FlowError>>>,
        assertion: Option<SamlAssertion>,
        calls: RefCell<Vec<(Url, String)>>,
    }

    impl FakeFlows {
        fn redirecting_to(query: &str) -> Self {
            Self::ending_in(Ok(Url::parse(&format!("{REDIRECT_URI}?{query}")).unwrap()))
        }

        fn ending_in(result: Result<Url, FlowError>) -> Self {
            FakeFlows {
                result: RefCell::new(Some(result)),
                assertion: None,
                calls: RefCell::new(vec![]),
            }
        }

        fn handing_out(assertion: SamlAssertion) -> Self {
            FakeFlows {
                result: RefCell::new(None),
                assertion: Some(assertion),
                calls: RefCell::new(vec![]),
            }
        }
    }

    #[async_trait(?Send)]
    impl FlowExecutor for &FakeFlows {
        async fn saml(
            &self,
            entry_url: &Url,
            login: &UserCredentials,
            _mfa: &dyn SecondFactor,
        ) -> Result<SamlAssertion, FlowError> {
            self.calls
                .borrow_mut()
                .push((entry_url.clone(), login.password.as_str().to_string()));
            Ok(self.assertion.clone().expect("no SAML login in this test"))
        }

        async fn oauth(
            &self,
            authorize_url: &Url,
            redirect_uri: &str,
            _login: &UserCredentials,
            _mfa: &dyn SecondFactor,
        ) -> Result<Url, FlowError> {
            self.calls
                .borrow_mut()
                .push((authorize_url.clone(), redirect_uri.to_string()));
            self.result
                .borrow_mut()
                .take()
                .expect("no OIDC login in this test")
        }
    }

    fn credentials() -> UserCredentials {
        UserCredentials::new("user".to_string(), Password::new("secret"), None)
    }

    fn state(value: &'static str) -> MockStateSource {
        let mut state = MockStateSource::new();
        state
            .expect_state()
            .times(1)
            .returning(move || Ok(value.to_string()));
        state
    }

    fn service(
        flows: &FakeFlows,
        state: MockStateSource,
    ) -> AuthentikService<&FakeFlows, MockStateSource, MockAuthenticator> {
        AuthentikService::new(flows, state, MockAuthenticator::new())
    }

    async fn oidc_code(flows: &FakeFlows) -> Result<AuthCode, AuthentikError> {
        service(flows, state("s"))
            .oidc_code(credentials(), ISSUER, "rancher", REDIRECT_URI)
            .await
    }

    #[tokio::test]
    async fn sends_the_authorize_request_with_the_state_and_returns_the_code() {
        let flows = FakeFlows::redirecting_to("code=abc&state=s");

        let code = oidc_code(&flows).await.unwrap();

        assert_eq!(code.as_str(), "abc");
        let calls = flows.calls.borrow();
        assert_eq!(calls.len(), 1);
        let (url, redirect_uri) = &calls[0];
        assert_eq!(url.path(), "/application/o/authorize/");
        assert!(url
            .query_pairs()
            .any(|(key, value)| key == "state" && value == "s"));
        assert_eq!(redirect_uri, REDIRECT_URI);
    }

    #[tokio::test]
    async fn rejects_a_redirect_with_a_foreign_state_or_without_a_code() {
        let err = oidc_code(&FakeFlows::redirecting_to("code=abc&state=other"))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthentikError::OidcStateMismatch));

        let err = oidc_code(&FakeFlows::redirecting_to("state=s"))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthentikError::OidcNoCode(path) if path == "/verify-auth"));
    }

    #[tokio::test]
    async fn reports_an_error_response() {
        let flows =
            FakeFlows::redirecting_to("error=access_denied&error_description=no+access&state=s");

        let err = oidc_code(&flows).await.unwrap_err();

        assert_eq!(
            err.to_string(),
            "authentik refused the authorization: access_denied no access"
        );
    }

    #[tokio::test]
    async fn without_a_state_no_flow_is_run() {
        let mut state = MockStateSource::new();
        state
            .expect_state()
            .times(1)
            .returning(|| Err(StateError::Failed("no randomness".into())));
        let flows = FakeFlows::redirecting_to("code=abc&state=s");

        let err = service(&flows, state)
            .oidc_code(credentials(), ISSUER, "rancher", REDIRECT_URI)
            .await
            .unwrap_err();

        assert!(matches!(err, AuthentikError::State(_)));
        assert!(flows.calls.borrow().is_empty());
    }

    #[tokio::test]
    async fn a_failed_flow_is_passed_on() {
        let flows = FakeFlows::ending_in(Err(FlowError::PasswordRejected("wrong".to_string())));

        let err = oidc_code(&flows).await.unwrap_err();

        assert!(matches!(
            err,
            AuthentikError::Flow(FlowError::PasswordRejected(_))
        ));
    }

    #[tokio::test]
    async fn logs_in_to_saml_at_the_entry_url_with_the_trailing_slash() {
        let assertion = SamlAssertion {
            saml_response: "assertion".to_string(),
            destination: "https://signin.aws.amazon.com/saml".to_string(),
            relay_state: None,
        };
        let flows = FakeFlows::handing_out(assertion.clone());
        let mut state = MockStateSource::new();
        state.expect_state().never();

        let found = service(&flows, state)
            .saml_assertion(STORED_URL, credentials())
            .await
            .unwrap();

        assert_eq!(found, assertion);
        let calls = flows.calls.borrow();
        assert_eq!(calls[0].0.as_str(), format!("{STORED_URL}/"));
        assert_eq!(calls[0].1, "secret");
    }

    #[test]
    fn entry_url_adds_the_trailing_slash_once() {
        assert_eq!(
            entry_url(STORED_URL).unwrap().as_str(),
            format!("{STORED_URL}/")
        );
        assert_eq!(
            entry_url(&format!("{STORED_URL}/")).unwrap().as_str(),
            format!("{STORED_URL}/")
        );
    }

    #[test]
    fn builds_the_authorize_url_on_the_issuer_origin() {
        let url = authorize_url(ISSUER, "rancher", REDIRECT_URI, "s").unwrap();

        assert_eq!(url.path(), "/application/o/authorize/");
        assert_eq!(url.host_str(), Some("id.example.com"));
        let query: Vec<_> = url.query_pairs().into_owned().collect();
        assert!(query.contains(&("client_id".to_string(), "rancher".to_string())));
        assert!(query.contains(&("response_type".to_string(), "code".to_string())));
        assert!(query.contains(&("redirect_uri".to_string(), REDIRECT_URI.to_string())));
        assert!(query.contains(&(
            "scope".to_string(),
            "openid profile email groups".to_string()
        )));
        assert!(query.contains(&("state".to_string(), "s".to_string())));
    }
}
