use crate::aws::sso_portal_client::SsoPortalClient;
use crate::aws::{Credential, Role};
use crate::okta::aws_sso::sso_portal_login::SsoPortalLogin;
use anyhow::Result;

pub struct AwsSSOCredentials {
    sso_portal_login: SsoPortalLogin,
}

impl AwsSSOCredentials {
    /// Generates a new [`AwsSsoCredentials`] object.
    pub fn new() -> Result<AwsSSOCredentials> {
        let sso_portal_login = SsoPortalLogin::new()?;
        Ok(AwsSSOCredentials { sso_portal_login })
    }

    /// Call this function to get credentials from AWS SSO.
    pub async fn run(
        &self,
        app_url: String,
        session_token: String,
        region: String,
        role_arn: Option<String>,
    ) -> Result<Vec<Credential>> {
        let portal_url = format!("https://portal.sso.{region}.amazonaws.com", region = region);
        let token = self
            .sso_portal_login
            .run(app_url, session_token, portal_url.clone())
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
