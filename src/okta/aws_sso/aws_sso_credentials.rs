use crate::aws::sso_portal::SsoPortal;
use crate::aws::sts::AwsCredential;
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
    ///
    /// # Examples
    ///
    /// Return only one role:
    ///
    /// ```rust
    /// let aws_credentials = AwsSSOCredentials::new()?;
    /// aws_credentials.run("https://the.app.url", "the session token", Some("role arn"))?;
    /// ```
    ///
    /// Return all roles:
    ///
    /// ```rust
    /// let aws_credentials = AwsSSOCredentials::new()?;
    /// aws_credentials.run("https://the.app.url", "the session token", NONE)?;
    /// ```
    pub async fn run(
        &self,
        app_url: String,
        session_token: String,
        region: String,
        role_arn: Option<String>,
    ) -> Result<Vec<AwsCredential>> {
        let portal_url = format!("https://portal.sso.{region}.amazonaws.com", region = region);
        let token = self
            .sso_portal_login
            .run(app_url, session_token, portal_url.clone())
            .await?;
        let sso_portal = SsoPortal::new(portal_url)?;
        let mut credentials = vec![];

        let roles = match role_arn {
            Some(arn) => {
                let role_arn = SsoPortal::parse_role_arn(arn)?;
                vec![role_arn]
            }
            None => sso_portal.list_role_arns(token.clone()).await?,
        };

        for role in roles {
            let credential = sso_portal.list_credentials(token.clone(), role).await?;
            credentials.push(credential);
        }

        Ok(credentials)
    }
}
