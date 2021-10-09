use crate::okta::authenticator::api_responses::{OktaError, Response};
use anyhow::{anyhow, Result};
use reqwest::header::{HeaderValue, ACCEPT};
use reqwest::Client;
use serde_json::Value;

/// An API client to contact Okta
pub struct OktaApiClient {
    http_client: Client,
}

impl OktaApiClient {
    /// Returns a new [`OktaApiClient`]
    pub fn new() -> Result<OktaApiClient> {
        Ok(OktaApiClient {
            http_client: Client::builder().cookie_store(true).build()?,
        })
    }

    /// HTTP POST to generate a [`Response`]
    pub async fn post(&self, uri: &str, json: &Value) -> Result<Response> {
        let res = self
            .http_client
            .post(uri)
            .json(json)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .send()
            .await?;
        let status = res.status();
        let body = res.text().await?;

        match status {
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::TOO_MANY_REQUESTS => {
                let response: OktaError = serde_json::from_str(body.as_str())?;
                Err(anyhow!(response.summary()))
            }
            reqwest::StatusCode::OK => {
                let response: Response = serde_json::from_str(body.as_str())?;
                Ok(response)
            }
            _ => Err(anyhow!("unimplemented")),
        }
    }
}
