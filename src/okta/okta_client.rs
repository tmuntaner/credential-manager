use crate::aws::sts::AwsCredential;
use crate::okta::authenticator::Authenticator;
use crate::okta::aws_credentials::AwsCredentials;
use crate::okta::aws_sso::aws_sso_credentials::AwsSSOCredentials;
use anyhow::Result;

/// This is the entrypoint to communicate with Okta to generate temporary credentials.
///
/// # Example
///
/// ```rust
/// let client = OktaClient::new()?;
/// ```
pub struct OktaClient {
    authorizer: Authenticator,
    aws_credentials: AwsCredentials,
    aws_sso_credentials: AwsSSOCredentials,
}

impl OktaClient {
    /// Generates a new [`OktaClient`] object.
    pub fn new() -> Result<OktaClient> {
        Ok(OktaClient {
            authorizer: Authenticator::new()?,
            aws_credentials: AwsCredentials::new()?,
            aws_sso_credentials: AwsSSOCredentials::new()?,
        })
    }

    /// Retrieves AWS Credentials
    ///
    /// # Example
    ///
    /// Without an AWS Role Arn:
    ///
    /// ```rust
    /// let client = OktaClient::new()?;
    /// let result = client.run("foo@domain.com", "correct horse battery staple", "https://domain.okta.com/aws", NONE))?;
    /// ```
    ///
    /// With an AWS Role ARN:
    ///
    /// ```rust
    /// let client = OktaClient::new()?;
    /// let result = client.run("foo@domain.com", "correct horse battery staple", "https://domain.okta.com/aws", Some("AWS_ARN"))?;
    /// ```
    pub async fn aws_credentials(
        &self,
        username: String,
        password: String,
        app_url: String,
        role_arn: Option<String>,
    ) -> Result<Vec<AwsCredential>> {
        let session_token = self
            .authorizer
            .run(app_url.clone(), username, password)
            .await?;

        let credentials = self
            .aws_credentials
            .run(app_url, session_token, role_arn)
            .await?;

        Ok(credentials)
    }

    pub async fn aws_sso_credentials(
        &self,
        username: String,
        password: String,
        app_url: String,
        region: String,
        role_arn: Option<String>,
    ) -> Result<Vec<AwsCredential>> {
        let session_token = self
            .authorizer
            .run(app_url.clone(), username, password)
            .await?;

        let credentials = self
            .aws_sso_credentials
            .run(app_url, session_token, region, role_arn)
            .await?;

        Ok(credentials)
    }
}
