use crate::app::secrets::cache::{cache_warning, cached_aws_credential, set_cached_credential_best_effort};
use crate::app::secrets::passwords::get_password;
use crate::app::secrets::passwords::PasswordError;
use crate::app::secrets::store::SecretStoresError;
use crate::app::secrets::store::{create_secret_stores, SecretStores};
use crate::domain::models::aws::AwsError;
use crate::domain::models::aws::Credential;
use crate::domain::models::login::AwsOverrides;
use crate::domain::models::login::ResolveError;
use crate::domain::models::settings::AppConfig;
use crate::domain::models::user_interaction::UserNotice;
use crate::domain::ports::aws::AwsCredentialIssuer;
use crate::domain::ports::login::LoginResolver;
use crate::domain::ports::notifier::Notifier;
use crate::domain::ports::user_interaction::UserInteraction;
use crate::domain::services::aws_credential_issuer::AwsCredentialIssuerService;
use crate::domain::services::login_resolver::LoginResolverService;
use crate::outbound::authentik::{AuthentikSamlClient, StoredSessions};
use crate::outbound::aws::{SsoCredentials, StsCredentials};
use std::sync::Arc;

/// An issue with an AWS app.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IssueAwsError {
    #[error("could not set up the secret stores")]
    Secrets(#[source] SecretStoresError),
    #[error("could not work out what to log in to")]
    Resolve(#[source] ResolveError),
    #[error("could not get the password")]
    Password(#[source] PasswordError),
    #[error("could not set up AWS SSO: {0}")]
    SsoSetup(String),
    #[error("could not issue the credentials")]
    Issue(#[source] AwsError),
}

impl IssueAwsError {
    /// Whether the user canceled a prompt.
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Password(e) if e.is_cancelled())
    }
}

/// What to issue.
#[derive(Debug, Default)]
pub struct AwsRequest {
    /// What the caller chose, on top of the settings.
    pub overrides: AwsOverrides,
    /// Only this role. Needed for the credential to be cached.
    pub role_arn: Option<String>,
    /// Ask for the password even when it is stored.
    pub with_password: bool,
    pub enable_desktop_notifications: bool,
}

/// Issues the credentials of the request, from the cache when a valid one is there. A single issued credential
/// of a named role is cached.
pub async fn issue_aws<U: UserInteraction + 'static, N: Notifier + 'static>(
    settings: &AppConfig,
    request: &AwsRequest,
    prompt: Arc<U>,
    notifier: Arc<N>,
) -> Result<Vec<Credential>, IssueAwsError> {
    let SecretStores {
        idp: idp_store,
        cache: cache_store,
        session: session_store,
    } = create_secret_stores(settings, prompt.clone(), notifier.clone())
        .map_err(IssueAwsError::Secrets)?;

    if let Some(credential) =
        cached_aws_credential(request.role_arn.as_deref(), cache_store.as_deref()).await
    {
        return Ok(vec![credential]);
    }

    let login = LoginResolverService::new(settings.clone())
        .resolve_aws(&request.overrides)
        .map_err(IssueAwsError::Resolve)?;

    let password = get_password(
        login.password_url().to_string(),
        login.username.clone(),
        request.with_password,
        idp_store.as_deref(),
        prompt.as_ref(),
    )
    .await
    .map_err(IssueAwsError::Password)?;

    let credentials = AwsCredentialIssuerService::new(
        Box::new(AuthentikSamlClient::new(
            request.enable_desktop_notifications,
            prompt.clone(),
            notifier.clone(),
            StoredSessions::new(session_store),
        )),
        Box::new(StsCredentials::new()),
        Box::new(SsoCredentials::new().map_err(|e| IssueAwsError::SsoSetup(e.to_string()))?),
    )
    .issue(&login, password, request.role_arn.as_deref())
    .await
    .map_err(IssueAwsError::Issue)?;

    if let (Some(role_arn), [credential]) = (&request.role_arn, credentials.as_slice()) {
        if let Some(error) =
            set_cached_credential_best_effort(role_arn, credential, cache_store.as_deref()).await
        {
            // The credential is good, so this only warns, and a notice that cannot be shown is only logged.
            if let Err(e) = notifier
                .notify(&UserNotice::warning(cache_warning(&error)))
                .await
            {
                log::warn!("could not tell the user the credential was not cached: {e}");
            }
        }
    }

    Ok(credentials)
}
