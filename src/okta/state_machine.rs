use crate::aws;
use crate::aws::sts::AwsCredential;
use crate::okta::api_responses::{FactorType, OktaError, Response};
use crate::okta::okta_client::OktaClient;
use crate::verify;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use url::Url;

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
    async fn run(&self, client: &OktaClient, config: Config) -> Result<Event>;
}

struct OktaAuthorize {
    username: String,
    password: String,
}

impl OktaAuthorize {
    pub fn new(username: String, password: String) -> OktaAuthorize {
        OktaAuthorize { username, password }
    }
}

#[async_trait]
impl Runnable for OktaAuthorize {
    async fn run(&self, client: &OktaClient, config: Config) -> Result<Event> {
        let json = &serde_json::json!({
            "username": self.username,
            "password": self.password,
        });
        let mut url = Url::parse(config.app_url.as_str())?;
        url.set_path("/api/v1/authn");

        let (body, status) = client
            .post(url.as_str(), json)
            .await
            .map_err(|e| anyhow!(e))?;

        match status {
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::TOO_MANY_REQUESTS => {
                let response: OktaError = serde_json::from_str(body.as_str())?;
                Err(anyhow!(response.summary()))
            }
            reqwest::StatusCode::OK => {
                let response: Response = serde_json::from_str(body.as_str())?;
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

                Ok(Event::MfaRequired {
                    url,
                    state_token,
                    factor: factor.clone(),
                })
            }
            _ => Err(anyhow!("unimplemented")),
        }
    }
}

struct OktaMfaChallenge {
    state_token: String,
    factor: FactorType,
    url: String,
}

#[async_trait]
impl Runnable for OktaMfaChallenge {
    async fn run(&self, client: &OktaClient, _config: Config) -> Result<Event> {
        let url = self
            .factor
            .get_verification_url()
            .ok_or_else(|| anyhow!("could not get verification url"))?;

        let json = &serde_json::json!({
            "stateToken": self.state_token,
        });

        let (body, _status) = client
            .post(self.url.as_str(), json)
            .await
            .map_err(|e| anyhow!(e))?;

        let response: Response = serde_json::from_str(body.as_str())?;
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

        let u2f_response = verify::webauthn::webauthn_sign(challenge, origin_url, credential_ids);
        let json = &serde_json::json!({
            "stateToken": state_token,
            "clientData": u2f_response.client_data,
            "signatureData": u2f_response.signature_data,
            "authenticatorData": u2f_response.authenticator_data,
        });

        let (body, _status) = client
            .post(url.as_str(), json)
            .await
            .map_err(|e| anyhow!(e))?;

        let response: Response = serde_json::from_str(body.as_str()).map_err(|e| anyhow!(e))?;
        let session_token = response
            .session_token()
            .ok_or_else(|| anyhow!("could not get session token"))?;

        Ok(Event::AuthorizeSuccess { session_token })
    }
}

struct OktaGetCredentials {
    session_token: String,
}

impl OktaGetCredentials {
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

#[async_trait]
impl Runnable for OktaGetCredentials {
    async fn run(&self, client: &OktaClient, config: Config) -> Result<Event> {
        let body = client
            .get(config.app_url, Some(self.session_token.clone()))
            .await
            .map_err(|e| anyhow!(e))?;

        let aws_credentials = self
            .get_saml_response(body.clone(), config.role_arn)
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
    Authorize(OktaAuthorize),
    Challenge(OktaMfaChallenge),
    GetCredentials(OktaGetCredentials),
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
            ) => Ok(StateMachineWrapper::Challenge(OktaMfaChallenge {
                url,
                factor,
                state_token: state_token.clone(),
            })),
            (
                StateMachineWrapper::Challenge(_val),
                Event::AuthorizeSuccess {
                    ref session_token, ..
                },
            ) => Ok(StateMachineWrapper::GetCredentials(OktaGetCredentials {
                session_token: session_token.clone(),
            })),
            _ => Err(anyhow!("unimplemented")),
        }
    }

    async fn run(&self, client: &OktaClient, config: Config) -> Result<Event> {
        match self {
            StateMachineWrapper::Authorize(val) => Ok(val.run(client, config).await?),
            StateMachineWrapper::Challenge(val) => Ok(val.run(client, config).await?),
            StateMachineWrapper::GetCredentials(val) => Ok(val.run(client, config).await?),
        }
    }
}

#[derive(Clone)]
struct Config {
    app_url: String,
    role_arn: Option<String>,
}

pub struct Factory {}

impl Factory {
    pub async fn run(
        self,
        username: String,
        password: String,
        app_url: String,
        role_arn: Option<String>,
    ) -> Result<()> {
        let mut state: StateMachineWrapper =
            StateMachineWrapper::Authorize(OktaAuthorize::new(username, password));
        let client = OktaClient::new().map_err(|e| anyhow!(e))?;
        let config = Config { app_url, role_arn };

        loop {
            let event = state.run(&client, config.clone()).await?;
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
