use crate::aws;
use crate::aws::sts::AwsCredential;
use crate::okta::okta_api_client::OktaApiClient;
use crate::verify;
use anyhow::{anyhow, Result};

pub struct AwsCredentials {
    client: OktaApiClient,
}

impl AwsCredentials {
    pub fn new() -> Result<AwsCredentials> {
        let client = OktaApiClient::new().map_err(|e| anyhow!(e))?;
        Ok(AwsCredentials { client })
    }

    pub async fn run(
        &self,
        app_url: String,
        session_token: String,
        role_arn: Option<String>,
    ) -> Result<()> {
        let body = self
            .client
            .get(app_url, Some(session_token.clone()))
            .await
            .map_err(|e| anyhow!(e))?;

        let aws_credentials = self
            .get_saml_response(body.clone(), role_arn)
            .await
            .map_err(|e| anyhow!(e))?;

        for credential in aws_credentials {
            println!(
                "{}\n{}\n{}\n",
                credential.role_arn, credential.access_key_id, credential.secret_access_key
            );
        }

        Ok(())
    }

    async fn get_saml_response(
        &self,
        body: String,
        role_arn: Option<String>,
    ) -> Result<Vec<AwsCredential>> {
        let saml_response = verify::saml::SamlResponse::new(body)
            .ok_or_else(|| anyhow!("could not get saml response"))?;
        let saml_aws_credentials = match role_arn {
            Some(role_arn) => {
                let credentials = saml_response.credentials();
                let role = credentials
                    .iter()
                    .find(|cred| cred.role_arn == role_arn)
                    .ok_or_else(|| anyhow!("could not find role_arn {}", role_arn))?;
                vec![role.clone()]
            }
            None => saml_response.credentials(),
        };
        let aws_credentials =
            aws::sts::generate_sts_credentials(saml_response.raw, saml_aws_credentials).await;

        Ok(aws_credentials)
    }
}
