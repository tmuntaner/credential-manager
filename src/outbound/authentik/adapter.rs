use crate::domain::models::oidc::OidcError;
use crate::domain::models::saml::{SamlAssertion, SamlLoginError};
use crate::domain::models::user_credentials::UserCredentials;
use crate::domain::ports::login::{OidcAuthorizer, SamlIdentityProvider};
use crate::outbound::authentik::authenticator::TerminalAuthenticator;
use async_trait::async_trait;
use authentik::{AuthentikService, HttpFlowExecutor, RandomState};

/// The `authentik` crate, asking on the terminal and signing with a USB security key.
type Service = AuthentikService<HttpFlowExecutor, RandomState, TerminalAuthenticator>;

/// With `enable_desktop_notifications`, a desktop notification asks to touch the security key.
fn service(enable_desktop_notifications: bool) -> Service {
    AuthentikService::new(
        HttpFlowExecutor::new(),
        RandomState::new(),
        TerminalAuthenticator::new(enable_desktop_notifications),
    )
}

/// Logs users in to the SAML applications of authentik with the `authentik` crate.
pub struct AuthentikClient {
    service: Service,
}

impl AuthentikClient {
    pub fn new(enable_desktop_notifications: bool) -> Self {
        Self {
            service: service(enable_desktop_notifications),
        }
    }
}

#[async_trait(?Send)]
impl SamlIdentityProvider for AuthentikClient {
    async fn login(
        &self,
        app_url: &str,
        credentials: UserCredentials,
    ) -> Result<SamlAssertion, SamlLoginError> {
        let assertion = self
            .service
            .saml_assertion(app_url, credentials.into())
            .await?;

        Ok(assertion.into())
    }
}

/// An OIDC application in authentik.
pub struct AuthentikOidc {
    service: Service,
    issuer: String,
    client_id: String,
}

impl AuthentikOidc {
    /// `issuer` is the authentik instance, of which only the origin is used.
    pub fn new(issuer: String, client_id: String, enable_desktop_notifications: bool) -> Self {
        Self {
            service: service(enable_desktop_notifications),
            issuer,
            client_id,
        }
    }
}

#[async_trait(?Send)]
impl OidcAuthorizer for AuthentikOidc {
    async fn authorize(
        &self,
        login: UserCredentials,
        redirect_uri: &str,
    ) -> Result<String, OidcError> {
        let code = self
            .service
            .oidc_code(login.into(), &self.issuer, &self.client_id, redirect_uri)
            .await?;

        Ok(code.into_string())
    }
}
