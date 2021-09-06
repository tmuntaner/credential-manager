use crate::okta::api_responses::{OktaError, Response};
use anyhow::{anyhow, Result};
use reqwest::header::{HeaderValue, ACCEPT};
use reqwest::Client;
use serde_json::Value;
use url::Url;

pub struct OktaClient {
    client: Client,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Role {
    pub provider_arn: String,
    pub role_arn: String,
}

impl OktaClient {
    pub fn new() -> Result<OktaClient> {
        Ok(OktaClient {
            client: Client::builder().cookie_store(true).build()?,
        })
    }

    pub async fn post(&self, uri: &str, json: &Value) -> Result<Response> {
        let res = self
            .client
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

    pub async fn get(&self, url: String, session_token: Option<String>) -> Result<String> {
        let mut url = Url::parse(url.as_str())?;

        if let Some(token) = session_token {
            url.query_pairs_mut()
                .append_pair("sessionToken", token.as_str());
        }

        let res = self.client.get(url).send().await?;
        let body = res.text().await?;

        //println!("Body: {}", body);
        Ok(body)
    }
}
