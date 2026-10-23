use reqwest::header::{
    HeaderMap, HeaderName, HeaderValue, ACCEPT, CONTENT_TYPE, LOCATION, SET_COOKIE,
};
use reqwest::{Client, Method, Response, StatusCode};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;
use url::Url;

/// A browser user agent. AWS sign-in answers an ACS POST without browser-like headers with a generic 500 page.
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:157.0) Gecko/20100101 Firefox/157.0";

#[derive(Clone)]
pub enum AcceptType {
    Json,
    Html,
}

/// A response that has not been checked for errors or redirected.
pub struct RawResponse {
    pub status: StatusCode,
    /// The `Location` header as sent (may be relative).
    pub location: Option<String>,
    pub content_type: Option<String>,
    /// The `Set-Cookie` headers as sent.
    pub set_cookies: Vec<String>,
    pub body: String,
}

#[derive(Debug, Error)]
pub enum ApiError {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error(transparent)]
    Url(#[from] url::ParseError),

    #[error(transparent)]
    InvalidHeaderValue(#[from] reqwest::header::InvalidHeaderValue),

    #[error(transparent)]
    InvalidHeaderName(#[from] reqwest::header::InvalidHeaderName),

    #[error("non 200 response")]
    NonOkResponse,
}

pub struct ApiClient {
    http_client: Client,
}

impl RawResponse {
    async fn from_response(response: Response) -> Result<RawResponse, ApiError> {
        let status = response.status();
        let header = |name| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let location = header(LOCATION);
        let content_type = header(CONTENT_TYPE);
        let set_cookies = response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(str::to_string)
            .collect();
        let body = response.text().await?;

        Ok(RawResponse {
            status,
            location,
            content_type,
            set_cookies,
            body,
        })
    }
}

impl ApiClient {
    pub fn new() -> Result<ApiClient, ApiError> {
        Ok(ApiClient {
            http_client: Client::builder()
                .cookie_store(true)
                .user_agent(USER_AGENT)
                .build()?,
        })
    }

    /// Same as [`ApiClient::new`] but keeps no cookies, so every request authenticates only by what the caller sends.
    pub fn new_cookieless() -> Result<ApiClient, ApiError> {
        Ok(ApiClient {
            http_client: Client::builder().user_agent(USER_AGENT).build()?,
        })
    }

    /// Same as [`ApiClient::new`] but does not follow redirects, so the caller can inspect them.
    pub fn new_no_redirect() -> Result<ApiClient, ApiError> {
        Ok(ApiClient {
            http_client: Client::builder()
                .cookie_store(true)
                .user_agent(USER_AGENT)
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        })
    }

    /// GET without any status check.
    pub async fn get_raw(
        &self,
        url: &str,
        accept_type: AcceptType,
    ) -> Result<RawResponse, ApiError> {
        let response = self
            .http_client
            .get(url)
            .header(ACCEPT, ApiClient::accept_header(accept_type))
            .send()
            .await?;

        RawResponse::from_response(response).await
    }

    /// POSTs a JSON body with `Accept: application/json`, without any status check.
    pub async fn post_json_raw(&self, uri: &str, json: &Value) -> Result<RawResponse, ApiError> {
        let response = self
            .http_client
            .post(uri)
            .json(json)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .send()
            .await?;

        RawResponse::from_response(response).await
    }

    /// Sends `method` with an optional bearer token and JSON body, `Accept: application/json`, without any
    /// status check. `query` is appended to the url.
    pub async fn send_json_raw(
        &self,
        method: Method,
        url: &str,
        query: &[(&str, &str)],
        bearer_token: Option<&str>,
        json: Option<&Value>,
    ) -> Result<RawResponse, ApiError> {
        self.send_json_raw_with_headers(method, url, query, bearer_token, &[], json)
            .await
    }

    /// Same as [`ApiClient::send_json_raw`] with additional request headers.
    pub async fn send_json_raw_with_headers(
        &self,
        method: Method,
        url: &str,
        query: &[(&str, &str)],
        bearer_token: Option<&str>,
        headers: &[(&str, &str)],
        json: Option<&Value>,
    ) -> Result<RawResponse, ApiError> {
        let mut url = Url::parse(url)?;
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }

        let mut request = self
            .http_client
            .request(method, url)
            .header(ACCEPT, HeaderValue::from_static("application/json"));
        if let Some(token) = bearer_token {
            request = request.bearer_auth(token);
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if let Some(json) = json {
            request = request.json(json);
        }

        RawResponse::from_response(request.send().await?).await
    }

    pub async fn post_form(
        &self,
        uri: &str,
        form: &HashMap<String, String>,
        accept_type: AcceptType,
    ) -> Result<reqwest::Response, ApiError> {
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
    ) -> Result<Response, ApiError> {
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
    ) -> Result<Response, ApiError> {
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
            return Err(ApiError::NonOkResponse);
        }

        Ok(response)
    }

    fn accept_header(accept_type: AcceptType) -> HeaderValue {
        match accept_type {
            AcceptType::Html => HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
            AcceptType::Json => HeaderValue::from_static("application/json"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::MockServer;
    use serde_json::json;

    #[tokio::test]
    async fn get_raw_does_not_follow_redirects() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/start");
            then.status(302).header("Location", "/if/flow/example/");
        });
        let target = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/if/flow/example/");
            then.status(200);
        });

        let client = ApiClient::new_no_redirect().unwrap();
        let res = client
            .get_raw(&server.url("/start"), AcceptType::Json)
            .await
            .unwrap();

        assert_eq!(res.status, StatusCode::FOUND);
        assert_eq!(res.location.as_deref(), Some("/if/flow/example/"));
        mock.assert();
        target.assert_calls(0);
    }

    #[tokio::test]
    async fn raw_requests_return_error_statuses_with_body() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/missing")
                .header("Accept", "application/json");
            then.status(404)
                .header("Content-Type", "application/json")
                .body(r#"{"detail":"not found"}"#);
        });
        server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/boom")
                .header("Accept", "application/json")
                .json_body(json!({"a": 1}));
            then.status(500)
                .header("Content-Type", "application/json")
                .body(r#"{"detail":"boom"}"#);
        });

        let client = ApiClient::new_no_redirect().unwrap();

        let res = client
            .get_raw(&server.url("/missing"), AcceptType::Json)
            .await
            .unwrap();
        assert_eq!(res.status, StatusCode::NOT_FOUND);
        assert_eq!(res.content_type.as_deref(), Some("application/json"));
        assert_eq!(res.body, r#"{"detail":"not found"}"#);
        assert!(res.location.is_none());

        let res = client
            .post_json_raw(&server.url("/boom"), &json!({"a": 1}))
            .await
            .unwrap();
        assert_eq!(res.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(res.body, r#"{"detail":"boom"}"#);
    }

    #[tokio::test]
    async fn requests_carry_a_browser_user_agent_and_a_wide_html_accept() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/acs")
                .header_includes("User-Agent", "Mozilla/5.0")
                .header(
                    "Accept",
                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                );
            then.status(200);
        });

        for client in [
            ApiClient::new().unwrap(),
            ApiClient::new_no_redirect().unwrap(),
        ] {
            client
                .post_form(&server.url("/acs"), &HashMap::new(), AcceptType::Html)
                .await
                .unwrap();
        }

        mock.assert_calls(2);
    }

    #[tokio::test]
    async fn cookies_are_sent_on_the_next_request() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/login");
            then.status(200)
                .header("Set-Cookie", "session=abc123; Path=/");
        });
        let with_cookie = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/next")
                .header_includes("Cookie", "session=abc123");
            then.status(200);
        });

        let client = ApiClient::new_no_redirect().unwrap();
        client
            .get_raw(&server.url("/login"), AcceptType::Json)
            .await
            .unwrap();
        client
            .get_raw(&server.url("/next"), AcceptType::Json)
            .await
            .unwrap();

        with_cookie.assert();
    }

    #[tokio::test]
    async fn default_client_still_follows_redirects() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/start");
            then.status(302).header("Location", "/end");
        });
        let end = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/end");
            then.status(200).body("done");
        });

        let client = ApiClient::new().unwrap();
        let res = client
            .get(server.url("/start"), None, None, AcceptType::Json)
            .await
            .unwrap();

        assert_eq!(res.text().await.unwrap(), "done");
        end.assert();
    }
}
