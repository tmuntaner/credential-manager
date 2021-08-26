use reqwest::header::{HeaderValue, ACCEPT};
use reqwest::Client;
use serde_json::Value;
use url::Url;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub struct OktaClient {
    client: Client,
    pub base_url: Url,
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
            base_url: Url::parse("https://suse.okta.com")?,
        })
    }

    pub async fn post(&self, uri: &str, json: &Value) -> Result<String> {
        let res = self
            .client
            .post(uri)
            .json(json)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .send()
            .await?;
        let body = res.text().await?;

        //println!("Url: {}", uri);
        //println!("Body: {}", body);

        Ok(body)
    }

    pub async fn get(&self, path: String, session_token: Option<String>) -> Result<String> {
        let mut url = self.base_url.clone();

        url.set_path(path.as_str());

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
