use crate::authentik::flow::session::SamlAssertion;
use crate::aws::sso::login::SsoLoginError;
use crate::aws::sso::login::SsoPortalLogin;
use crate::aws::sso::portal_api::SsoPortalError;
use crate::aws::sso::portal_client::SsoPortalClient;
use crate::aws::RoleError;
use crate::aws::{Credential, Role};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AwsSsoError {
    #[error(transparent)]
    Login(#[from] SsoLoginError),

    #[error(transparent)]
    Portal(#[from] SsoPortalError),

    #[error(transparent)]
    Role(#[from] RoleError),
}

pub struct AwsSSOCredentials {
    sso_portal_login: SsoPortalLogin,
    /// Replaces `https://portal.sso.{region}.amazonaws.com`, for tests.
    portal_url: Option<String>,
}

impl AwsSSOCredentials {
    /// Generates a new [`AwsSsoCredentials`] object.
    pub fn new() -> Result<AwsSSOCredentials, AwsSsoError> {
        let sso_portal_login = SsoPortalLogin::new()?;
        Ok(AwsSSOCredentials {
            sso_portal_login,
            portal_url: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_portal_url(portal_url: String) -> Result<AwsSSOCredentials, AwsSsoError> {
        Ok(AwsSSOCredentials {
            portal_url: Some(portal_url),
            ..AwsSSOCredentials::new()?
        })
    }

    /// Call this function to get credentials from AWS SSO.
    pub async fn run(
        &self,
        assertion: SamlAssertion,
        region: String,
        role_arn: Option<String>,
    ) -> Result<Vec<Credential>, AwsSsoError> {
        let portal_url = self
            .portal_url
            .clone()
            .unwrap_or_else(|| format!("https://portal.sso.{region}.amazonaws.com"));
        let token = self
            .sso_portal_login
            .run(assertion, portal_url.clone())
            .await?;
        let sso_client = SsoPortalClient::new(portal_url)?;

        let roles = match role_arn {
            Some(arn) => {
                let role_arn = Role::from_arn(&arn)?;
                vec![role_arn]
            }
            None => sso_client.list_role_arns(token.clone()).await?,
        };
        let credentials = sso_client.list_credentials(token, roles).await?;

        Ok(credentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_be_created() {
        assert!(AwsSSOCredentials::new().is_ok());
    }
}
