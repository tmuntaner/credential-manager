use crate::okta::authenticator::api_responses::{Response, TransactionState};
use crate::okta::authenticator::okta_api_client::OktaApiClient;

use crate::verify;
use anyhow::{anyhow, Result};
use url::Url;

/// Goes through the Okta Authentication state machine to finally generate a session token.
///
/// See <https://developer.okta.com/docs/reference/api/authn/#transaction-state> for more details
/// on how Okta handles the authentication process.
///
/// # Examples
///
/// ```rust
/// let authenticator = Authenticator::new()?;
/// ```
pub struct AuthenticatorClient {
    client: OktaApiClient,
}

impl AuthenticatorClient {
    /// Creates a new [`Authenticator`] object.
    pub fn new() -> Result<AuthenticatorClient> {
        let client = OktaApiClient::new().map_err(|e| anyhow!(e))?;
        Ok(AuthenticatorClient { client })
    }

    /// Runs the authentication process for an app/username/password.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let authenticator = Authenticator::new()?;
    /// let result = authenticator.run("https://the.app.url", "username", "correct battery horse staple")?;
    /// ```
    pub async fn run(&self, app_url: String, username: String, password: String) -> Result<String> {
        let mut response = self
            .try_authorize(app_url.clone(), username, password)
            .await?;

        // loop over the mutated response until we reach a success state or an error.
        loop {
            match response
                .status()
                .ok_or_else(|| anyhow!("could not get status"))?
            {
                TransactionState::MfaRequired => response = self.mfa_required(&response).await?,
                TransactionState::MfaChallenge => {
                    response = self.mfa_challenge(&response, app_url.clone()).await?
                }
                TransactionState::Success => {
                    let session_token = response
                        .session_token()
                        .ok_or_else(|| anyhow!("could not get session token"))?;

                    return Ok(session_token);
                }
                TransactionState::Unimplemented => return Err(anyhow!("unimplemented")),
            }
        }
    }

    /// Try to authenticate against Okta
    ///
    /// <https://developer.okta.com/docs/reference/api/authn/#primary-authentication>
    async fn try_authorize(
        &self,
        app_url: String,
        username: String,
        password: String,
    ) -> Result<Response> {
        let mut url = Url::parse(app_url.as_str())?;
        url.set_path("/api/v1/authn");

        let json = &serde_json::json!({
            "username": username,
            "password": password,
        });

        Ok(self
            .client
            .post(url.as_str(), json)
            .await
            .map_err(|e| anyhow!(e))?)
    }

    /// An MFA challenge is required.
    ///
    /// This happens when the username/password isn't enough (should always be the case). The user
    /// chooses an MFA option and Okta will provide it with a challenge.
    ///
    /// <https://developer.okta.com/docs/reference/api/authn/#verify-factor>
    async fn mfa_required(&self, response: &Response) -> Result<Response> {
        let state_token = response
            .state_token()
            .ok_or_else(|| anyhow!("could not get state token"))?;

        let factors = response
            .factors()
            .ok_or_else(|| anyhow!("could not get factors"))?;

        let factor = factors
            .get(0)
            .ok_or_else(|| anyhow!("cannot get MFA factor"))?;

        let url = factor
            .get_verification_url()
            .ok_or_else(|| anyhow!("could not get verification url"))?;

        let json = &serde_json::json!({
           "stateToken": state_token,
        });

        Ok(self
            .client
            .post(url.as_str(), json)
            .await
            .map_err(|e| anyhow!(e))?)
    }

    /// Attempt an MFA challenge
    ///
    /// After a user chose an MFA option, it reaches this state with the MFA challenge. Here we try
    /// the challenge and, if successful, we'll receive a session token in our next response.
    ///
    /// <https://developer.okta.com/docs/reference/api/authn/#verify-factor>
    async fn mfa_challenge(&self, response: &Response, app_url: String) -> Result<Response> {
        let factors = response
            .factors()
            .ok_or_else(|| anyhow!("could not get mfa factors"))?;
        let state_token = response
            .state_token()
            .ok_or_else(|| anyhow!("could not get state token"))?;
        let challenge = response
            .challenge()
            .ok_or_else(|| anyhow!("could not get challenge"))?;

        let credential_ids: Vec<String> = factors
            .iter()
            .map(|factor| factor.get_credential_id())
            .flatten()
            .collect();

        let origin = Url::parse(app_url.as_str())?;
        if origin.scheme() != "https" {
            return Err(anyhow!("U2F request should be https"));
        }

        let host = origin
            .host()
            .ok_or_else(|| anyhow!("couldn't get host from url"))?
            .to_string();

        let u2f_response = verify::webauthn::webauthn_sign(challenge, host, credential_ids);
        let json = &serde_json::json!({
            "stateToken": state_token,
            "clientData": u2f_response.client_data,
            "signatureData": u2f_response.signature_data,
            "authenticatorData": u2f_response.authenticator_data,
        });

        let url = response
            .next()
            .ok_or_else(|| anyhow!("could not get next page"))?;

        Ok(self
            .client
            .post(url.as_str(), json)
            .await
            .map_err(|e| anyhow!(e))?)
    }
}
