use crate::aws::Credential;
use crate::okta::authenticator::authenticator_client::AuthenticatorClient;
use crate::okta::aws::aws_credentials::AwsCredentials;
use crate::okta::aws_sso::aws_sso_credentials::AwsSSOCredentials;
use anyhow::{anyhow, Result};

/// This is the entrypoint to communicate with Okta to generate temporary credentials.
pub struct OktaClient {
    authorizer: AuthenticatorClient,
    aws_credentials: AwsCredentials,
    aws_sso_credentials: AwsSSOCredentials,
}

#[derive(Copy, Clone)]
pub enum MfaSelection {
    WebAuthn,
    Totp,
    OktaPush,
    Invalid,
}

impl MfaSelection {
    pub fn from_string(s: String) -> Self {
        match s.to_lowercase().as_str() {
            "webauthn" => MfaSelection::WebAuthn,
            "totp" => MfaSelection::Totp,
            "push" => MfaSelection::OktaPush,
            "oktapush" => MfaSelection::OktaPush,
            _ => MfaSelection::Invalid,
        }
    }

    pub fn validate(mfa_option: Option<String>) -> Result<()> {
        if let Some(mfa) = mfa_option {
            let selection = MfaSelection::from_string(mfa);
            match selection {
                MfaSelection::Invalid => Err(anyhow!("invalid MFA selection")),
                _ => Ok(()),
            }
        } else {
            Ok(())
        }
    }
}

impl OktaClient {
    /// Generates a new [`OktaClient`] object.
    pub fn new(enable_desktop_notifications: bool) -> Result<OktaClient> {
        Ok(OktaClient {
            authorizer: AuthenticatorClient::new(enable_desktop_notifications)?,
            aws_credentials: AwsCredentials::new()?,
            aws_sso_credentials: AwsSSOCredentials::new()?,
        })
    }

    pub async fn aws_credentials(
        &self,
        username: String,
        password: String,
        app_url: String,
        role_arn: Option<String>,
        mfa: Option<MfaSelection>,
        mfa_provider: Option<String>,
    ) -> Result<Vec<Credential>> {
        let session_token = self
            .authorizer
            .run(app_url.clone(), username, password, mfa, mfa_provider)
            .await?;

        let credentials = self
            .aws_credentials
            .run(app_url, session_token, role_arn)
            .await?;

        Ok(credentials)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn aws_sso_credentials(
        &self,
        username: String,
        password: String,
        app_url: String,
        region: String,
        role_arn: Option<String>,
        mfa: Option<MfaSelection>,
        mfa_provider: Option<String>,
    ) -> Result<Vec<Credential>> {
        let session_token = self
            .authorizer
            .run(app_url.clone(), username, password, mfa, mfa_provider)
            .await?;

        let credentials = self
            .aws_sso_credentials
            .run(app_url, session_token, region, role_arn)
            .await?;

        Ok(credentials)
    }
}
