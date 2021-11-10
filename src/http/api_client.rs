use anyhow::{anyhow, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT};
use reqwest::{Client, Response};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use url::Url;

#[derive(Clone)]
pub enum AcceptType {
    Json,
    Html,
}

pub struct ApiClient {
    http_client: Client,
}

impl ApiClient {
    pub fn new() -> Result<ApiClient> {
        Ok(ApiClient {
            http_client: Client::builder().cookie_store(true).build()?,
        })
    }

    pub async fn post_json(&self, uri: &str, json: &Value) -> Result<Response> {
        let response = self
            .http_client
            .post(uri)
            .json(json)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .send()
            .await?;

        if response.status() != reqwest::StatusCode::OK {
            return Err(anyhow!("non 200 response"));
        }

        Ok(response)
    }

    pub async fn post_form(
        &self,
        uri: &str,
        form: &HashMap<String, String>,
        accept_type: AcceptType,
    ) -> Result<reqwest::Response> {
        let accept_header = ApiClient::accept_header(accept_type);

        let res = self
            .http_client
            .post(uri)
            .form(form)
            .header(ACCEPT, accept_header)
            .send()
            .await?;

        Ok(res)
    }

    pub async fn get_backoff(
        &self,
        url: String,
        params: Option<HashMap<String, String>>,
        headers: Option<HashMap<String, String>>,
        accept_type: AcceptType,
    ) -> Result<Response> {
        let mut retries = 3;
        let mut wait = 1;

        let response = loop {
            match self
                .get(
                    url.clone(),
                    params.clone(),
                    headers.clone(),
                    accept_type.clone(),
                )
                .await
            {
                Err(e) => {
                    if retries > 0 {
                        retries -= 1;
                        tokio::time::sleep(Duration::from_secs(wait)).await;
                        wait *= 2;
                    } else {
                        return Err(e);
                    }
                }
                res => break res?,
            }
        };

        Ok(response)
    }

    pub async fn get(
        &self,
        url: String,
        params: Option<HashMap<String, String>>,
        headers: Option<HashMap<String, String>>,
        accept_type: AcceptType,
    ) -> Result<Response> {
        let accept_header = ApiClient::accept_header(accept_type);
        let mut url = Url::parse(url.as_str())?;

        for (key, value) in &params.unwrap_or_default() {
            url.query_pairs_mut()
                .append_pair(key.as_str(), value.as_str());
        }

        let mut header_map = HeaderMap::new();
        header_map.insert(ACCEPT, accept_header);
        for (key, value) in &headers.unwrap_or_default() {
            let header_value = HeaderValue::from_str(value.as_str())?;
            let header_key = HeaderName::from_lowercase(key.as_bytes())?;
            header_map.insert(header_key, header_value);
        }

        let request = self.http_client.get(url).headers(header_map);
        let response = request.send().await?;

        if response.status() != reqwest::StatusCode::OK {
            return Err(anyhow!("non 200 response"));
        }

        Ok(response)
    }

    fn accept_header(accept_type: AcceptType) -> HeaderValue {
        match accept_type {
            AcceptType::Html => {
                HeaderValue::from_static("text/html,application/xhtml+xml,application/xml")
            }
            AcceptType::Json => HeaderValue::from_static("application/json"),
        }
    }
}
