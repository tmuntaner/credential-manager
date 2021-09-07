use crate::okta::authorizer::Authorizer;
use crate::okta::aws_credentials::AwsCredentials;
use anyhow::Result;

pub struct OktaClient {
    authorizer: Authorizer,
    aws_credentials: AwsCredentials,
}

impl OktaClient {
    pub fn new() -> Result<OktaClient> {
        Ok(OktaClient {
            authorizer: Authorizer::new()?,
            aws_credentials: AwsCredentials::new()?,
        })
    }

    pub async fn run(
        &self,
        username: String,
        password: String,
        app_url: String,
        role_arn: Option<String>,
    ) -> Result<()> {
        let session_token = self
            .authorizer
            .run(app_url.clone(), username, password)
            .await?;
        self.aws_credentials
            .run(app_url, session_token, role_arn)
            .await?;

        Ok(())
    }
}
