use crate::okta::api_responses::{TransactionState};
use crate::okta::okta_client::OktaClient;
use crate::verify;
use anyhow::{anyhow, Result};
use url::Url;

pub struct Authorizer {}

impl Authorizer {
    pub async fn run(self, app_url: String, username: String, password: String) -> Result<String> {
        let client = OktaClient::new().map_err(|e| anyhow!(e))?;
        let mut url = Url::parse(app_url.as_str())?;
        url.set_path("/api/v1/authn");

        let json = &serde_json::json!({
            "username": username,
            "password": password,
        });
        let mut response = client
            .post(url.as_str(), json)
            .await
            .map_err(|e| anyhow!(e))?;

        loop {
            match response
                .status()
                .ok_or_else(|| anyhow!("could not get status"))?
            {
                TransactionState::MfaRequired => {
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
                    response = client
                        .post(url.as_str(), json)
                        .await
                        .map_err(|e| anyhow!(e))?;
                }
                TransactionState::MfaChallenge => {
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

                    let origin = Url::parse(url.clone().as_str())?;
                    if origin.scheme() != "https" {
                        return Err(anyhow!("U2F request should be https"));
                    }

                    let origin_url: String = format!(
                        "https://{}",
                        origin
                            .host()
                            .ok_or_else(|| anyhow!("couldn't get host from url"))?
                            .to_string()
                    );

                    let u2f_response =
                        verify::webauthn::webauthn_sign(challenge, origin_url, credential_ids);
                    let json = &serde_json::json!({
                        "stateToken": state_token,
                        "clientData": u2f_response.client_data,
                        "signatureData": u2f_response.signature_data,
                        "authenticatorData": u2f_response.authenticator_data,
                    });

                    let url = response
                        .next()
                        .ok_or_else(|| anyhow!("could not get next page"))?;
                    response = client
                        .post(url.as_str(), json)
                        .await
                        .map_err(|e| anyhow!(e))?;
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
}
