use crate::aws;
use crate::aws::sts::AwsCredential;
use crate::okta::api_responses::{
    AuthResponse, ChallengeResponse, ChallengeResultResponse, FactorType, Links,
};
use crate::okta::okta_client::OktaClient;
use crate::verify;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use thiserror::Error;
use url::Url;

macro_rules! missing_required_key_error {
    ($msg:literal $(,)?) => {
        ParseError::RequiredMissing {
            key: String::from($msg),
        }
    };
}

#[derive(Error, Debug)]
enum ParseError {
    #[error("required key {key:?} not in response")]
    RequiredMissing { key: String },
}

#[derive(Debug, Clone)]
enum Event {
    AuthorizeSuccess {
        session_token: String,
    },
    MfaRequired {
        state_token: String,
        factor: FactorType,
        url: String,
    },
    Done,
}

#[async_trait]
trait Runnable {
    async fn run(&self, client: &OktaClient) -> Result<Event>;
}

struct Authorize {
    username: String,
    password: String,
    base_url: String,
}

impl Authorize {
    pub fn new(username: String, password: String, base_url: String) -> Authorize {
        Authorize {
            username,
            password,
            base_url,
        }
    }
}

impl Authorize {
    fn get_verification_url(&self, factor: &FactorType) -> Result<String> {
        match *factor {
            FactorType::WebAuthn { ref links, .. } => {
                let links = links.as_ref().ok_or(missing_required_key_error!("links"))?;
                let next = links
                    .get("next")
                    .ok_or(missing_required_key_error!("next"))?;

                return match next {
                    Links::Single(l) => Ok(l.href.clone()),
                    Links::Multi(list) => {
                        let link = list.get(0).ok_or_else(|| anyhow!("cannot get link"))?;
                        Ok(link.href.clone())
                    }
                };
            }
            FactorType::Unimplemented => {}
        }

        Err(anyhow!("could not retrieve verification url"))
    }
}

#[async_trait]
impl Runnable for Authorize {
    async fn run(&self, client: &OktaClient) -> Result<Event> {
        let json = &serde_json::json!({
            "username": self.username,
            "password": self.password,
        });
        let mut url = Url::parse(self.base_url.as_str())?;
        url.set_path("/api/v1/authn");

        let body = client
            .post(url.as_str(), json)
            .await
            .map_err(|e| anyhow!(e))?;

        let response: AuthResponse = serde_json::from_str(body.as_str())?;
        let state_token = response
            .state_token
            .ok_or(missing_required_key_error!("state_token"))?;

        let factors = response
            .embedded
            .ok_or(missing_required_key_error!("embedded"))?
            .factor_types
            .ok_or(missing_required_key_error!("factor_types"))?;

        if factors.is_empty() {
            return Err(anyhow!("no MFA factors"));
        }

        let factor = factors
            .get(0)
            .ok_or_else(|| anyhow!("cannot get MFA factor"))?;

        let url = self.get_verification_url(factor)?;

        Ok(Event::MfaRequired {
            url,
            state_token,
            factor: factor.clone(),
        })
    }
}

struct Challenge {
    state_token: String,
    factor: FactorType,
    url: String,
}

impl Challenge {
    fn get_verification_url(&self, factor: &FactorType) -> Result<String> {
        match *factor {
            FactorType::WebAuthn { ref links, .. } => {
                let links = links.as_ref().ok_or(missing_required_key_error!("links"))?;
                let next = links
                    .get("next")
                    .ok_or(missing_required_key_error!("next"))?;

                return match next {
                    Links::Single(l) => Ok(l.href.clone()),
                    Links::Multi(list) => {
                        let link = list.get(0).ok_or_else(|| anyhow!("could not get link"))?;
                        Ok(link.href.clone())
                    }
                };
            }
            FactorType::Unimplemented => Err(anyhow!("not implemented factor type")),
        }
    }

    fn get_challenge_id(&self, factor: &FactorType) -> Result<String> {
        return match *factor {
            FactorType::WebAuthn { ref profile, .. } => {
                let profile = profile
                    .as_ref()
                    .ok_or(missing_required_key_error!("profile"))?;

                Ok(profile
                    .credential_id
                    .as_ref()
                    .ok_or(missing_required_key_error!("credential_id"))?
                    .clone())
            }
            FactorType::Unimplemented => Err(anyhow!("unimplemented")),
        };
    }
}

#[async_trait]
impl Runnable for Challenge {
    async fn run(&self, client: &OktaClient) -> Result<Event> {
        let url = self.get_verification_url(&self.factor)?;

        let json = &serde_json::json!({
            "stateToken": self.state_token,
        });

        let body = client
            .post(self.url.as_str(), json)
            .await
            .map_err(|e| anyhow!(e))?;

        let challenge_response: ChallengeResponse = serde_json::from_str(body.as_str())?;

        let state_token = challenge_response
            .state_token
            .ok_or(missing_required_key_error!("state_token"))?;

        let embedded = challenge_response
            .embedded
            .ok_or(missing_required_key_error!("embedded"))?;

        let factors = &embedded
            .factors
            .ok_or(missing_required_key_error!("factors"))?;

        let credential_ids: Vec<String> = factors
            .iter()
            .map(|factor| self.get_challenge_id(factor))
            .filter_map(|factor| factor.ok())
            .collect();

        let challenge = embedded
            .challenge
            .ok_or(missing_required_key_error!("challenge"))?
            .challenge;

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

        let u2f_response = verify::webauthn::webauthn_sign(challenge, origin_url, credential_ids);
        let json = &serde_json::json!({
            "stateToken": state_token,
            "clientData": u2f_response.client_data,
            "signatureData": u2f_response.signature_data,
            "authenticatorData": u2f_response.authenticator_data,
        });

        let body = client
            .post(url.as_str(), json)
            .await
            .map_err(|e| anyhow!(e))?;

        let challenge_result_response: ChallengeResultResponse =
            serde_json::from_str(body.as_str()).map_err(|e| anyhow!(e))?;
        let session_token = challenge_result_response
            .session_token
            .ok_or(missing_required_key_error!("session_token"))?;

        Ok(Event::AuthorizeSuccess { session_token })
    }
}

struct AwsCredentials {
    session_token: String,
}

impl AwsCredentials {
    async fn get_saml_response(&self, body: String) -> Result<Vec<AwsCredential>> {
        let saml_response = verify::saml::SamlResponse::new(body)
            .ok_or_else(|| anyhow!("could not get saml response"))?;
        let saml_aws_credentials = saml_response.credentials();
        let aws_credentials =
            aws::sts::generate_sts_credentials(saml_response.raw, saml_aws_credentials).await;

        Ok(aws_credentials)
    }
}

#[async_trait]
impl Runnable for AwsCredentials {
    async fn run(&self, client: &OktaClient) -> Result<Event> {
        let body = client
            .get(
                "/home/amazon_aws/0oa1crzseqkrZUctZ357/272".to_string(),
                Some(self.session_token.clone()),
            )
            .await
            .map_err(|e| anyhow!(e))?;

        let aws_credentials = self
            .get_saml_response(body.clone())
            .await
            .map_err(|e| anyhow!(e))?;

        for credential in aws_credentials {
            println!(
                "{}\n{}\n{}\n",
                credential.role_arn, credential.access_key_id, credential.secret_access_key
            );
        }

        Ok(Event::Done)
    }
}

enum StateMachineWrapper {
    Authorize(Authorize),
    Challenge(Challenge),
    AwsCredentials(AwsCredentials),
}

impl StateMachineWrapper {
    fn step(self, event: Event) -> Result<StateMachineWrapper> {
        match (self, event) {
            (
                StateMachineWrapper::Authorize(_val),
                Event::MfaRequired {
                    ref state_token,
                    url,
                    factor,
                    ..
                },
            ) => Ok(StateMachineWrapper::Challenge(Challenge {
                url,
                factor,
                state_token: state_token.clone(),
            })),
            (
                StateMachineWrapper::Challenge(_val),
                Event::AuthorizeSuccess {
                    ref session_token, ..
                },
            ) => Ok(StateMachineWrapper::AwsCredentials(AwsCredentials {
                session_token: session_token.clone(),
            })),
            _ => Err(anyhow!("unimplemented")),
        }
    }

    async fn run(&self, client: &OktaClient) -> Result<Event> {
        match self {
            StateMachineWrapper::Authorize(val) => Ok(val.run(client).await?),
            StateMachineWrapper::Challenge(val) => Ok(val.run(client).await?),
            StateMachineWrapper::AwsCredentials(val) => Ok(val.run(client).await?),
        }
    }
}

pub struct Factory {}

impl Factory {
    pub async fn run(self, username: String, password: String, base_url: String) -> Result<()> {
        let mut state: StateMachineWrapper =
            StateMachineWrapper::Authorize(Authorize::new(username, password, base_url));
        let client = OktaClient::new().map_err(|e| anyhow!(e))?;

        loop {
            let event = state.run(&client).await?;
            match event {
                Event::Done => {
                    break;
                }
                _ => {
                    state = state.step(event)?;
                }
            }
        }

        Ok(())
    }
}
