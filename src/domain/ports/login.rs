use crate::domain::models::login::{
    AwsLogin, AwsOverrides, RancherLogin, RancherOverrides, ResolveError,
};
use crate::domain::models::oidc::OidcError;
use crate::domain::models::saml::{SamlAssertion, SamlLoginError};
use crate::domain::models::user_credentials::UserCredentials;
use async_trait::async_trait;

/// Works out what to log in with: what the user gave wins over the app entry in the settings, which wins over
/// the identity provider.
pub trait LoginResolver {
    fn resolve_aws(&self, overrides: &AwsOverrides) -> Result<AwsLogin, ResolveError>;

    fn resolve_rancher(&self, overrides: &RancherOverrides) -> Result<RancherLogin, ResolveError>;
}

/// Logs a user in at an OpenID Connect identity provider and hands out the OAuth authorization code.
#[async_trait(?Send)]
pub trait OidcAuthorizer {
    /// `redirect_uri` is where the identity provider sends the user back to after the login.
    async fn authorize(
        &self,
        login: UserCredentials,
        redirect_uri: &str,
    ) -> Result<String, OidcError>;
}

/// Logs a user in at the identity provider of a SAML application and hands out the SAML assertion.
#[async_trait(?Send)]
pub trait SamlIdentityProvider {
    /// `app_url` is the entry point of the SAML application at the identity provider.
    async fn login(
        &self,
        app_url: &str,
        credentials: UserCredentials,
    ) -> Result<SamlAssertion, SamlLoginError>;
}
