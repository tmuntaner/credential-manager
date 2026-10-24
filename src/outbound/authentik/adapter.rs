use crate::domain::models::oidc::OidcError;
use crate::domain::models::saml::{SamlAssertion, SamlLoginError};
use crate::domain::models::user_credentials::UserCredentials;
use crate::domain::ports::login::{OidcAuthorizer, SamlIdentityProvider};
use crate::outbound::authentik::authenticator::TerminalAuthenticator;
use async_trait::async_trait;
use authentik::{AuthentikService, HttpFlowExecutor, RandomState};

/// The `authentik` service.
type Service = AuthentikService<HttpFlowExecutor, RandomState, TerminalAuthenticator>;

fn service(enable_desktop_notifications: bool) -> Service {
    AuthentikService::new(
        HttpFlowExecutor::new(),
        RandomState::new(),
        TerminalAuthenticator::new(enable_desktop_notifications),
    )
}

/// Builds an Authentik SAML client.
pub struct AuthentikSamlClient {
    service: Service,
}

impl AuthentikSamlClient {
    pub fn new(enable_desktop_notifications: bool) -> Self {
        Self {
            service: service(enable_desktop_notifications),
        }
    }
}

#[async_trait(?Send)]
impl SamlIdentityProvider for AuthentikSamlClient {
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
pub struct AuthentikOidcClient {
    service: Service,
    issuer: String,
    client_id: String,
}

impl AuthentikOidcClient {
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
impl OidcAuthorizer for AuthentikOidcClient {
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
