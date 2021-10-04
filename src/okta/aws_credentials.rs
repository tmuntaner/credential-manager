use crate::aws;
use crate::aws::sts::AwsCredential;
use crate::okta::okta_api_client::OktaApiClient;
use crate::okta::saml_parsers::OktaAwsSamlParser;
use anyhow::{anyhow, Result};

/// This struct contacts the AWS application in Okta, goes through its SAML response, and then
/// uses the result to generate credentials with STS.
///
/// # Examples
///
/// ```rust
/// let aws_credentials = AwsCredentials::new()?;
/// ```
pub struct AwsCredentials {
    client: OktaApiClient,
}

impl AwsCredentials {
    /// Generates a new [`AwsCredentials`] object.
    pub fn new() -> Result<AwsCredentials> {
        let client = OktaApiClient::new().map_err(|e| anyhow!(e))?;
        Ok(AwsCredentials { client })
    }

    /// Call this function to get credentials from the AWS.
    ///
    /// # Examples
    ///
    /// Return only one role:
    ///
    /// ```rust
    /// let aws_credentials = AwsCredentials::new()?;
    /// aws_credentials.run("https://the.app.url", "the session token", Some("role arn"))?;
    /// ```
    ///
    /// Return all roles:
    ///
    /// ```rust
    /// let aws_credentials = AwsCredentials::new()?;
    /// aws_credentials.run("https://the.app.url", "the session token", NONE)?;
    /// ```
    pub async fn run(
        &self,
        app_url: String,
        session_token: String,
        role_arn: Option<String>,
    ) -> Result<Vec<AwsCredential>> {
        let body = self
            .client
            .get(app_url, Some(session_token.clone()))
            .await
            .map_err(|e| anyhow!(e))?;

        let aws_credentials = self
            .get_saml_response(body.clone(), role_arn)
            .await
            .map_err(|e| anyhow!(e))?;

        Ok(aws_credentials)
    }

    async fn get_saml_response(
        &self,
        body: String,
        role_arn: Option<String>,
    ) -> Result<Vec<AwsCredential>> {
        let saml_parser = OktaAwsSamlParser::new(body)?;
        let saml_aws_credentials = match role_arn {
            Some(role_arn) => {
                let credentials = saml_parser.credentials()?;
                let role = credentials
                    .iter()
                    .find(|cred| cred.role_arn == role_arn)
                    .ok_or_else(|| anyhow!("could not find role_arn {}", role_arn))?;
                vec![role.clone()]
            }
            None => saml_parser.credentials()?,
        };
        let aws_credentials = aws::sts::generate_sts_credentials(
            saml_parser.raw_saml_response(),
            saml_aws_credentials,
        )
        .await;

        Ok(aws_credentials)
    }
}
