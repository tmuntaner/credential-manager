use crate::domain::models::oidc::OidcError;
use crate::domain::models::saml::{SamlAssertion, SamlLoginError};
use crate::domain::models::user_credentials::UserCredentials;
use crate::domain::ports::login::{OidcAuthorizer, SamlIdentityProvider};
use crate::domain::ports::notifier::Notifier;
use crate::domain::ports::user_interaction::UserInteraction;
use crate::outbound::authentik::authenticator::InteractiveAuthenticator;
use crate::outbound::webauthn::adapter::WebauthnAdapter;
use crate::outbound::webauthn::ui::UserInteractionKeyUi;
use async_trait::async_trait;
use authentik::{AuthentikService, HttpFlowExecutor, RandomState};
use std::rc::Rc;
use std::sync::Arc;

/// The `authentik` service.
type Service<U, N> = AuthentikService<
    HttpFlowExecutor,
    RandomState,
    InteractiveAuthenticator<WebauthnAdapter, U, N>,
>;

fn service<U: UserInteraction + 'static, N: Notifier + 'static>(
    enable_desktop_notifications: bool,
    interaction: Arc<U>,
    notifier: Arc<N>,
) -> Service<U, N> {
    let key_ui = Arc::new(UserInteractionKeyUi::new(
        interaction.clone(),
        notifier.clone(),
    ));
    let webauthn_adapter = Rc::new(WebauthnAdapter::new(enable_desktop_notifications, key_ui));

    AuthentikService::new(
        HttpFlowExecutor::new(),
        RandomState::new(),
        InteractiveAuthenticator::new(webauthn_adapter, interaction, notifier),
    )
}

/// Builds an Authentik SAML client.
pub struct AuthentikSamlClient<U: UserInteraction + 'static, N: Notifier + 'static> {
    service: Service<U, N>,
}

impl<U: UserInteraction + 'static, N: Notifier + 'static> AuthentikSamlClient<U, N> {
    pub fn new(enable_desktop_notifications: bool, interaction: Arc<U>, notifier: Arc<N>) -> Self {
        Self {
            service: service(enable_desktop_notifications, interaction, notifier),
        }
    }
}

#[async_trait(?Send)]
impl<U: UserInteraction + 'static, N: Notifier + 'static> SamlIdentityProvider
    for AuthentikSamlClient<U, N>
{
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
pub struct AuthentikOidcClient<U: UserInteraction + 'static, N: Notifier + 'static> {
    service: Service<U, N>,
    issuer: String,
    client_id: String,
}

impl<U: UserInteraction + 'static, N: Notifier + 'static> AuthentikOidcClient<U, N> {
    /// `issuer` is the authentik instance, of which only the origin is used.
    pub fn new(
        issuer: String,
        client_id: String,
        enable_desktop_notifications: bool,
        interaction: Arc<U>,
        notifier: Arc<N>,
    ) -> Self {
        Self {
            service: service(enable_desktop_notifications, interaction, notifier),
            issuer,
            client_id,
        }
    }
}

#[async_trait(?Send)]
impl<U: UserInteraction + 'static, N: Notifier + 'static> OidcAuthorizer
    for AuthentikOidcClient<U, N>
{
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
