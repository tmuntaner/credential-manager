use crate::app::secrets::cache::{
    cache_warning, get_cached_credential, set_cached_credential_best_effort,
};
use crate::app::secrets::passwords::get_password;
use crate::app::secrets::passwords::PasswordError;
use crate::app::secrets::store::SecretStoresError;
use crate::app::secrets::store::{create_secret_stores, SecretStores};
use crate::domain::models::idp::IdpType;
use crate::domain::models::login::{RancherOverrides, ResolveError};
use crate::domain::models::rancher_credentials::RancherCredential;
use crate::domain::models::settings::AppConfig;
use crate::domain::models::user_credentials::UserCredentials;
use crate::domain::models::user_interaction::UserNotice;
use crate::domain::ports::login::LoginResolver;
use crate::domain::ports::notifier::Notifier;
use crate::domain::ports::rancher::{RancherCredentialIssuer, RancherError};
use crate::domain::ports::user_interaction::UserInteraction;
use crate::domain::services::login_resolver::LoginResolverService;
use crate::domain::services::rancher_credential_issuer::RancherCredentialIssuerService;
use crate::outbound::authentik::{AuthentikOidcClient, StoredSessions};
use crate::outbound::rancher::RancherClient;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

/// A token that expires within this long is not handed out from the cache.
const CACHE_MARGIN: time::Duration = time::Duration::seconds(60);

/// An issue of a Rancher cluster token.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IssueRancherError {
    #[error("could not set up the secret stores")]
    Secrets(#[source] SecretStoresError),
    #[error("could not work out what to log in to")]
    Resolve(#[source] ResolveError),
    #[error("could not get the password")]
    Password(#[source] PasswordError),
    #[error("could not set up the Rancher client")]
    Setup(#[source] RancherError),
    #[error("could not issue the credential")]
    Issue(#[source] RancherError),
}

impl IssueRancherError {
    /// Whether the user canceled a prompt.
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Password(e) if e.is_cancelled())
    }
}

/// What to issue.
#[derive(Debug)]
pub struct RancherRequest {
    /// What the caller chose, on top of the settings.
    pub overrides: RancherOverrides,
    /// The display name of the cluster in Rancher.
    pub cluster: String,
    /// How long the token lives.
    pub ttl: Duration,
    /// Ask for the password even when it is stored.
    pub with_password: bool,
    pub enable_desktop_notifications: bool,
}

/// Issues a token for the cluster of the request, from the cache when a valid one is there.
pub async fn issue_rancher<U: UserInteraction + 'static, N: Notifier + 'static>(
    settings: &AppConfig,
    request: &RancherRequest,
    prompt: Arc<U>,
    notifier: Arc<N>,
) -> Result<RancherCredential, IssueRancherError> {
    let rancher = LoginResolverService::new(settings.clone())
        .resolve_rancher(&request.overrides)
        .map_err(IssueRancherError::Resolve)?;
    let cache_key = format!("rancher:{}:{}", rancher.url, request.cluster);
    let SecretStores {
        idp: idp_store,
        cache: cache_store,
        session: session_store,
    } = create_secret_stores(settings, prompt.clone(), notifier.clone())
        .map_err(IssueRancherError::Secrets)?;

    let cached: Option<RancherCredential> =
        match get_cached_credential(&cache_key, cache_store.as_deref()).await {
            Ok(credential) => credential,
            Err(e) => {
                log::warn!("could not read the cached credential, logging in instead: {e}");
                None
            }
        };
    if let Some(credential) =
        cached.filter(|credential| credential.is_valid_at(OffsetDateTime::now_utc(), CACHE_MARGIN))
    {
        return Ok(credential);
    }

    let password = get_password(
        rancher.idp_url.clone(),
        rancher.username.clone(),
        request.with_password,
        idp_store.as_deref(),
        prompt.as_ref(),
    )
    .await
    .map_err(IssueRancherError::Password)?;

    let authorizer = match rancher.idp_type {
        IdpType::Authentik => Box::new(AuthentikOidcClient::new(
            rancher.idp_url,
            rancher.client_id,
            request.enable_desktop_notifications,
            prompt.clone(),
            notifier.clone(),
            StoredSessions::new(session_store),
        )),
    };

    let credential = RancherCredentialIssuerService::new(
        authorizer,
        Box::new(RancherClient::new(&rancher.url).map_err(IssueRancherError::Setup)?),
    )
    .issue(
        UserCredentials {
            username: rancher.username,
            password,
            mfa: rancher.mfa,
        },
        &request.cluster,
        request.ttl,
    )
    .await
    .map_err(IssueRancherError::Issue)?;

    if let Some(error) =
        set_cached_credential_best_effort(&cache_key, &credential, cache_store.as_deref()).await
    {
        // The credential is good, so this only warns, and a notice that cannot be shown is only logged.
        if let Err(e) = notifier
            .notify(&UserNotice::warning(cache_warning(&error)))
            .await
        {
            log::warn!("could not tell the user the credential was not cached: {e}");
        }
    }

    Ok(credential)
}
