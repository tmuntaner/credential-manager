use crate::aws::Credential;
use anyhow::{anyhow, Result};
use aws_sdk_sts::config::Region;
use aws_sdk_sts::operation::assume_role_with_saml::AssumeRoleWithSamlOutput;
use aws_smithy_types_convert::date_time::DateTimeExt;
use futures::future;
use time::format_description::well_known::Rfc3339;

pub struct StsClient {}

impl StsClient {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }

    pub async fn generate_sts_credentials(
        &self,
        saml_response: String,
        saml_aws_credentials: Vec<SamlAWSRole>,
    ) -> Result<Vec<Credential>> {
        let futures = future::join_all(saml_aws_credentials.into_iter().map(|role| {
            let config = aws_sdk_sts::Config::builder()
                .region(Some(Region::new(String::from("eu-central-1"))))
                .build();
            let bar = aws_sdk_sts::Client::from_conf(config);
            let saml = bar
                .assume_role_with_saml()
                .set_role_arn(Some(role.role_arn.clone()))
                .set_saml_assertion(Some(saml_response.clone()))
                .set_principal_arn(Some(role.principal_arn))
                .set_duration_seconds(Some(60 * 60))
                .send();

            let role_arn = role.role_arn;
            async move {
                let response = saml.await.map_err(|e| anyhow!(e.to_string()));

                StsFuture {
                    role_arn,
                    request: response,
                }
            }
        }))
        .await;

        let mut aws_credentials = vec![];

        for future in futures {
            let response = future.request?;
            let credentials = response
                .credentials
                .ok_or_else(|| anyhow!("Could not get credentials from STS"))?;
            let expiration_timestamp = credentials
                .expiration
                .unwrap()
                .to_time()
                .unwrap()
                .format(&Rfc3339)
                .unwrap();
            aws_credentials.push(Credential {
                secret_access_key: credentials.secret_access_key.unwrap(),
                access_key_id: credentials.access_key_id.unwrap(),
                role_arn: Some(future.role_arn),
                session_token: credentials.session_token.unwrap(),
                expiration: expiration_timestamp,
            });
        }

        Ok(aws_credentials)
    }
}

#[derive(Clone)]
pub struct SamlAWSRole {
    pub principal_arn: String,
    pub role_arn: String,
}

struct StsFuture {
    role_arn: String,
    request: Result<AssumeRoleWithSamlOutput>,
}
