use crate::okta::authenticator::api_responses::{
    FactorResult, FactorType, Response, TransactionState,
};
use std::io::{self, BufRead, Write};
use std::{thread, time};

use crate::http::api_client::ApiClient;
use crate::okta::okta_client::MfaSelection;
use anyhow::{anyhow, Result};
use tmuntaner_webauthn::WebauthnClient;
use url::Url;

/// Goes through the Okta Authentication state machine to finally generate a session token.
///
/// See <https://developer.okta.com/docs/reference/api/authn/#transaction-state> for more details
/// on how Okta handles the authentication process.
pub struct AuthenticatorClient {
    client: ApiClient,
    enable_desktop_notifications: bool,
}

impl AuthenticatorClient {
    /// Creates a new [`Authenticator`] object.
    pub fn new(enable_desktop_notifications: bool) -> Result<AuthenticatorClient> {
        let client = ApiClient::new()?;
        Ok(AuthenticatorClient {
            client,
            enable_desktop_notifications,
        })
    }

    /// Runs the authentication process for an app/username/password.
    pub async fn run(
        &self,
        app_url: String,
        username: String,
        password: String,
        mfa: Option<MfaSelection>,
        mfa_provider: Option<String>,
    ) -> Result<String> {
        let mut response = self
            .try_authorize(app_url.clone(), username, password)
            .await?;

        // loop over the mutated response until we reach a success state or an error.
        loop {
            match response
                .status()
                .ok_or_else(|| anyhow!("could not get status"))?
            {
                TransactionState::MfaRequired => {
                    response = self
                        .mfa_required(&response, mfa, mfa_provider.clone())
                        .await?
                }
                TransactionState::MfaChallenge => {
                    let result = response
                        .factor_result()
                        .ok_or_else(|| anyhow!("could not get factor result"))?;

                    match result {
                        FactorResult::Challenge => {
                            response = self.mfa_challenge(&response, app_url.clone()).await?
                        }
                        FactorResult::Waiting => {
                            response = self.mfa_challenge_waiting(&response).await?
                        }
                        FactorResult::Rejected => {
                            return Err(anyhow!("MFA Challenge was rejected-"))
                        }
                        FactorResult::Timeout => return Err(anyhow!("MFA Challenge timed out")),
                        FactorResult::Unimplemented => {
                            return Err(anyhow!("unimplemented MFA factor"))
                        }
                    }
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

        let response = self
            .client
            .post_json(url.as_str(), json)
            .await
            .map_err(|e| anyhow!(e))?;

        let body = response.text().await?;
        let response: Response = serde_json::from_str(body.as_str())?;
        Ok(response)
    }

    /// An MFA challenge is required.
    ///
    /// This happens when the username/password isn't enough (should always be the case). The user
    /// chooses an MFA option and Okta will provide it with a challenge.
    ///
    /// <https://developer.okta.com/docs/reference/api/authn/#verify-factor>
    async fn mfa_required(
        &self,
        response: &Response,
        mfa: Option<MfaSelection>,
        mfa_provider: Option<String>,
    ) -> Result<Response> {
        let state_token = response
            .state_token()
            .ok_or_else(|| anyhow!("could not get state token"))?;

        let factors = response
            .factors()
            .ok_or_else(|| anyhow!("could not get factors"))?;

        let factor = self.selected_mfa_factor(factors, mfa, mfa_provider)?;

        let url = factor
            .get_verification_url()
            .ok_or_else(|| anyhow!("could not get verification url"))?;

        let json = match factor {
            FactorType::Totp { .. } => {
                let totp = self.ask_user_for_totp()?;

                serde_json::json!({
                    "passCode": totp,
                    "stateToken": state_token,
                })
            }
            _ => {
                serde_json::json!({
                    "stateToken": state_token,
                })
            }
        };

        let response = self.client.post_json(url.as_str(), &json).await?;
        let body = response.text().await?;
        let response: Response = serde_json::from_str(body.as_str())?;

        Ok(response)
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
            .filter_map(|factor| factor.get_credential_id())
            .collect();

        let origin = Url::parse(app_url.as_str())?;
        if origin.scheme() != "https" {
            return Err(anyhow!("U2F request should be https"));
        }

        let host = origin
            .host()
            .ok_or_else(|| anyhow!("couldn't get host from url"))?
            .to_string();

        let mut webauthn_client = WebauthnClient::new();
        if self.enable_desktop_notifications {
            webauthn_client.add_desktop_notification_notifier();
        }
        webauthn_client.add_progress_bar_notifier();
        let u2f_response = webauthn_client.sign(challenge, host, credential_ids)?;
        let json = &serde_json::json!({
            "stateToken": state_token,
            "clientData": u2f_response.client_data,
            "signatureData": u2f_response.signature_data,
            "authenticatorData": u2f_response.authenticator_data,
        });

        let url = response
            .next()
            .ok_or_else(|| anyhow!("could not get next page"))?;

        let response = self.client.post_json(url.as_str(), json).await?;
        let body = response.text().await?;
        let response: Response = serde_json::from_str(body.as_str())?;

        Ok(response)
    }

    /// Polls during an MFA Challenge
    ///
    /// <https://developer.okta.com/docs/reference/api/authn/#response-example-waiting-for-3-number-verification-challenge-response>
    async fn mfa_challenge_waiting(&self, response: &Response) -> Result<Response> {
        let state_token = response
            .state_token()
            .ok_or_else(|| anyhow!("could not get state token"))?;

        let url = response
            .next()
            .ok_or_else(|| anyhow!("could not get next page"))?;

        let json = &serde_json::json!({
           "stateToken": state_token,
        });

        let ten_millis = time::Duration::from_millis(1000);

        thread::sleep(ten_millis);

        let response = self.client.post_json(url.as_str(), json).await?;
        let body = response.text().await?;
        let response: Response = serde_json::from_str(body.as_str())?;

        Ok(response)
    }

    fn selected_mfa_factor(
        &self,
        factors: Vec<FactorType>,
        mfa: Option<MfaSelection>,
        mfa_provider: Option<String>,
    ) -> Result<FactorType> {
        let factors: Vec<FactorType> = factors
            .into_iter()
            .filter(|factor_type| {
                match factor_type {
                    FactorType::WebAuthn { ref profile, .. } => {
                        // We want to filter out the WebAuthn selections with a profile
                        // the one without, is a general one which can be used for all
                        // U2F tokens.
                        profile.is_none()
                    }
                    _ => true,
                }
            })
            .collect();

        match mfa {
            Some(mfa) => match mfa {
                MfaSelection::Totp => {
                    let factors: Vec<FactorType> = factors
                        .into_iter()
                        .filter(|factor| matches!(factor, FactorType::Totp { .. }))
                        .filter(|factor| match &mfa_provider {
                            Some(mfa_provider) => match factor.provider() {
                                Some(factor_provider) => {
                                    factor_provider.to_lowercase() == mfa_provider.to_lowercase()
                                }
                                None => false,
                            },
                            None => false,
                        })
                        .collect();
                    let factor = factors
                        .get(0)
                        .ok_or_else(|| anyhow!("MFA Factor not found"))?
                        .clone();

                    Ok(factor)
                }
                MfaSelection::OktaPush => {
                    let factors: Vec<FactorType> = factors
                        .into_iter()
                        .filter(|factor| matches!(factor, FactorType::Push { .. }))
                        .collect();
                    let factor = factors
                        .get(0)
                        .ok_or_else(|| anyhow!("MFA Factor not found"))?
                        .clone();

                    Ok(factor)
                }
                MfaSelection::WebAuthn => {
                    let factors: Vec<FactorType> = factors
                        .into_iter()
                        .filter(|factor| matches!(factor, FactorType::WebAuthn { .. }))
                        .collect();
                    let factor = factors
                        .get(0)
                        .ok_or_else(|| anyhow!("MFA Factor not found"))?
                        .clone();

                    Ok(factor)
                }
                _ => Err(anyhow!("MFA Factor not found")),
            },
            None => self.ask_user_for_mfa_factor(factors),
        }
    }

    fn ask_user_for_mfa_factor(&self, factors: Vec<FactorType>) -> Result<FactorType> {
        let min: usize = 0;
        let max: usize = factors.len();

        eprintln!("Please select a MFA Factor Type:");
        for (i, factor) in factors.iter().enumerate() {
            eprintln!("( {} ) {}", i, factor.human_friendly_name());
        }

        eprint!("Factor Type? ({min} - {max}) ");
        let _ = io::stdout().flush();
        let mut buffer = String::new();
        io::stdin().lock().read_line(&mut buffer)?;
        // remove \n on unix or \r\n on windows
        let len = buffer.trim_end_matches(&['\r', '\n'][..]).len();
        buffer.truncate(len);

        let selection: usize = buffer
            .parse()
            .map_err(|_| anyhow!("failed to parse your selection"))?;
        if selection > max {
            return Err(anyhow!("you've selected an invalid Factor Type"));
        }
        let factor = factors.get(selection).ok_or_else(|| anyhow!(""))?;

        Ok(factor.clone())
    }

    fn ask_user_for_totp(&self) -> Result<String> {
        eprint!("TOTP Code: ");
        let _ = io::stdout().flush();
        let mut buffer = String::new();
        io::stdin().lock().read_line(&mut buffer)?;
        // remove \n on unix or \r\n on windows
        let len = buffer.trim_end_matches(&['\r', '\n'][..]).len();
        buffer.truncate(len);

        Ok(buffer)
    }
}
