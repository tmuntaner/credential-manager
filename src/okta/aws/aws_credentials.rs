use crate::aws;
use crate::aws::sts::AwsCredential;
use crate::http::api_client::{AcceptType, ApiClient};
use crate::okta::saml_parsers::OktaAwsSamlParser;
use anyhow::{anyhow, Result};
use std::collections::HashMap;

/// This struct contacts the AWS application in Okta, goes through its SAML response, and then
/// uses the result to generate credentials with STS.
///
/// # Examples
///
/// ```rust
/// use c9s::okta::aws::aws_credentials::AwsCredentials;
/// let aws_credentials = AwsCredentials::new().unwrap();
/// ```
pub struct AwsCredentials {
    client: ApiClient,
}

impl AwsCredentials {
    /// Generates a new [`AwsCredentials`] object.
    pub fn new() -> Result<AwsCredentials> {
        let client = ApiClient::new()?;
        Ok(AwsCredentials { client })
    }

    /// Call this function to get credentials from the AWS.
    pub async fn run(
        &self,
        app_url: String,
        session_token: String,
        role_arn: Option<String>,
    ) -> Result<Vec<AwsCredential>> {
        let mut params = HashMap::new();
        params.insert(String::from("sessionToken"), session_token);

        let response = self
            .client
            .get(app_url, Some(params), None, AcceptType::Json)
            .await?;

        let body = response.text().await?;

        let aws_credentials = self.get_saml_response(body.clone(), role_arn).await?;

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
