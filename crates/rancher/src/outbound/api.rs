use crate::domain::models::session::{AuthCode, SessionToken};
use crate::domain::ports::rancher_api::{ApiToken, Cluster, RancherApi, RancherApiError};
use async_trait::async_trait;
use base::api_client::{ApiClient, ApiError, RawResponse};
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;
use thiserror::Error;

/// A rancher request failure.
#[derive(Debug, Error)]
enum RequestError {
    #[error(transparent)]
    Api(#[from] ApiError),

    #[error("rancher returned {status} for {method} {path}: {body}")]
    ErrorStatus {
        method: Method,
        path: String,
        status: u16,
        body: String,
    },

    #[error("rancher did not hand out a CSRF cookie")]
    MissingCsrfCookie,

    #[error("rancher returned an unexpected response")]
    InvalidJson(#[source] serde_json::Error),
}

impl From<RequestError> for RancherApiError {
    fn from(e: RequestError) -> Self {
        RancherApiError::Failed(Box::new(e))
    }
}

#[derive(Deserialize)]
struct Session {
    token: String,
}

#[derive(Deserialize)]
struct Token {
    id: String,
    token: String,
}

#[derive(Deserialize)]
struct Clusters {
    data: Vec<ClusterResource>,
}

#[derive(Deserialize)]
struct ClusterResource {
    id: String,
    spec: ClusterSpec,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClusterSpec {
    display_name: String,
}

#[derive(Deserialize)]
struct CaCert {
    value: String,
}

/// Rancher API client, using an OIDC provider to login.
pub struct RancherApiClient {
    url: String,
    api: ApiClient,
}

impl RancherApiClient {
    pub fn new(rancher_url: &str) -> Result<RancherApiClient, RancherApiError> {
        Ok(RancherApiClient {
            url: rancher_url.trim_end_matches('/').to_string(),
            // No cookie store: we must set the CSRF cookie for each POST request.
            // The session travels with a bearer token.
            api: ApiClient::new_cookieless().map_err(RequestError::from)?,
        })
    }

    /// Sends a request to the Rancher server.
    pub async fn send<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        bearer_token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<T, RancherApiError> {
        let response = self
            .request(method, path, query, bearer_token, body)
            .await?;

        // serialize the response with serde JSON to sanitize the body and then deserialize
        // it into the requested type
        serde_json::from_str::<Value>(&response.body)
            .and_then(serde_json::from_value)
            .map_err(|e| RequestError::InvalidJson(e).into())
    }

    /// Sends a POST request to the Rancher server.
    /// Note: all POST requests must include CSRF.
    pub async fn post(
        &self,
        path: &str,
        query: &[(&str, &str)],
        bearer_token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<RawResponse, RancherApiError> {
        let csrf = self.csrf_token().await?;
        let cookie = format!("CSRF={csrf}");

        self.request_with_headers(
            Method::POST,
            path,
            query,
            bearer_token,
            &[("Cookie", &cookie), ("X-Api-Csrf", &csrf)],
            body,
        )
        .await
    }

    /// Get the CSRF token from the Rancher server.
    async fn csrf_token(&self) -> Result<String, RancherApiError> {
        let response = self
            .request(Method::GET, "/v3-public", &[], None, None)
            .await?;

        response
            .set_cookies
            .iter()
            .find_map(|cookie| cookie.strip_prefix("CSRF=")?.split(';').next())
            .map(str::to_string)
            .ok_or_else(|| RequestError::MissingCsrfCookie.into())
    }

    /// A request without headers.
    async fn request(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        bearer_token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<RawResponse, RancherApiError> {
        self.request_with_headers(method, path, query, bearer_token, &[], body)
            .await
    }

    /// A request with headers.
    async fn request_with_headers(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        bearer_token: Option<&str>,
        headers: &[(&str, &str)],
        body: Option<&Value>,
    ) -> Result<RawResponse, RancherApiError> {
        let url = format!("{}{path}", self.url);
        let response = self
            .api
            .send_json_raw_with_headers(method.clone(), &url, query, bearer_token, headers, body)
            .await
            .map_err(RequestError::from)?;

        if response.status == StatusCode::UNAUTHORIZED {
            return Err(RancherApiError::Unauthorized);
        }
        if !response.status.is_success() {
            return Err(RequestError::ErrorStatus {
                method,
                path: path.to_string(),
                status: response.status.as_u16(),
                body: response.body,
            }
            .into());
        }

        Ok(response)
    }
}

#[async_trait(?Send)]
impl RancherApi for RancherApiClient {
    fn redirect_uri(&self) -> String {
        format!("{}/verify-auth", self.url)
    }

    async fn login(&self, code: &AuthCode) -> Result<SessionToken, RancherApiError> {
        let body = json!({"description": "UI session", "code": code.as_str()});
        let response = self
            .post(
                "/v3-public/genericOIDCProviders/genericoidc",
                &[("action", "login")],
                None,
                Some(&body),
            )
            .await?;
        let session: Session = serde_json::from_str::<Value>(&response.body)
            .and_then(serde_json::from_value)
            .map_err(RequestError::InvalidJson)?;

        Ok(SessionToken::new(session.token))
    }

    async fn logout(&self, session: &SessionToken) -> Result<(), RancherApiError> {
        self.post(
            "/v3/tokens",
            &[("action", "logout")],
            Some(session.as_str()),
            None,
        )
        .await?;

        Ok(())
    }

    async fn find_cluster(
        &self,
        session: &SessionToken,
        name: &str,
    ) -> Result<Cluster, RancherApiError> {
        let clusters: Clusters = self
            .send(
                Method::GET,
                "/v1/management.cattle.io.cluster",
                &[("exclude", "metadata.managedFields")],
                Some(session.as_str()),
                None,
            )
            .await?;

        clusters
            .data
            .into_iter()
            .find(|cluster| cluster.spec.display_name == name)
            .map(|cluster| Cluster {
                server_url: format!("{}/k8s/clusters/{}", self.url, cluster.id),
                id: cluster.id,
            })
            .ok_or_else(|| RancherApiError::ClusterNotFound(name.to_string()))
    }

    async fn ca_cert(&self, session: &SessionToken) -> Result<String, RancherApiError> {
        let ca: CaCert = self
            .send(
                Method::GET,
                "/v1/management.cattle.io.settings/cacerts",
                &[],
                Some(session.as_str()),
                None,
            )
            .await?;

        Ok(ca.value)
    }

    async fn create_token(
        &self,
        session: &SessionToken,
        cluster_id: &str,
        ttl: Duration,
    ) -> Result<ApiToken, RancherApiError> {
        let body = json!({
            "type": "token",
            "metadata": {},
            "description": "c9s",
            "clusterId": cluster_id,
            "ttl": ttl.as_millis() as u64,
        });

        let response = self
            .post("/v3/tokens", &[], Some(session.as_str()), Some(&body))
            .await?;
        let token: Token = serde_json::from_str::<Value>(&response.body)
            .and_then(serde_json::from_value)
            .map_err(RequestError::InvalidJson)?;

        Ok(ApiToken {
            id: token.id,
            token: token.token,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::Method::{GET, POST};
    use httpmock::MockServer;

    const TOKEN: &str = include_str!("../../testdata/rancher_token.json");

    fn client(server: &MockServer) -> RancherApiClient {
        RancherApiClient::new(&server.base_url()).unwrap()
    }

    #[tokio::test]
    async fn a_response_with_a_repeated_key_is_still_read() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET)
                .path("/v1/management.cattle.io.settings/cacerts");
            then.status(200)
                .body(r#"{"id":"a","id":"a","value":"PEM"}"#);
        });

        let ca = client(&server)
            .ca_cert(&SessionToken::new("session:secret"))
            .await
            .unwrap();

        assert_eq!(ca, "PEM");
    }

    /// Serves the CSRF cookie and expects the POST to echo it.
    fn csrf_mock<'a>(server: &'a MockServer) -> httpmock::Mock<'a> {
        server.mock(|when, then| {
            when.method(GET).path("/v3-public");
            then.status(200)
                .header("Set-Cookie", "CSRF=token123; Path=/; Secure");
        })
    }

    #[test]
    fn the_redirect_uri_is_the_verify_auth_page() {
        let client = RancherApiClient::new("https://rancher.example/").unwrap();

        assert_eq!(client.redirect_uri(), "https://rancher.example/verify-auth");
    }

    #[tokio::test]
    async fn login_exchanges_the_code_for_a_session() {
        let server = MockServer::start();
        let csrf = csrf_mock(&server);
        let login = server.mock(|when, then| {
            when.method(POST)
                .path("/v3-public/genericOIDCProviders/genericoidc")
                .query_param("action", "login")
                .header("X-Api-Csrf", "token123")
                .header_includes("Cookie", "CSRF=token123")
                .json_body(json!({"description": "UI session", "code": "abc"}));
            then.status(201)
                .json_body(json!({"token": "session:secret"}));
        });

        let session = client(&server).login(&AuthCode::new("abc")).await.unwrap();

        assert_eq!(session, SessionToken::new("session:secret"));
        csrf.assert();
        login.assert();
    }

    #[tokio::test]
    async fn login_without_a_csrf_cookie_is_an_error() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/v3-public");
            then.status(200);
        });

        let result = client(&server).login(&AuthCode::new("abc")).await;

        assert!(matches!(result, Err(RancherApiError::Failed(_))));
    }

    #[tokio::test]
    async fn logout_posts_the_session() {
        let server = MockServer::start();
        csrf_mock(&server);
        let logout = server.mock(|when, then| {
            when.method(POST)
                .path("/v3/tokens")
                .header("X-Api-Csrf", "token123")
                .query_param("action", "logout")
                .header("Authorization", "Bearer session:secret");
            then.status(200);
        });

        client(&server)
            .logout(&SessionToken::new("session:secret"))
            .await
            .unwrap();

        logout.assert();
    }

    #[tokio::test]
    async fn find_cluster_matches_the_display_name() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET)
                .path("/v1/management.cattle.io.cluster")
                .query_param("exclude", "metadata.managedFields")
                .header("Authorization", "Bearer session:secret");
            then.status(200).json_body(json!({"data": [
                {"id": "local", "spec": {"displayName": "local"}},
                {"id": "c-m-j2xw7jk8", "spec": {"displayName": "op-prg2-1"}},
            ]}));
        });

        let cluster = client(&server)
            .find_cluster(&SessionToken::new("session:secret"), "op-prg2-1")
            .await
            .unwrap();

        assert_eq!(
            cluster,
            Cluster {
                id: "c-m-j2xw7jk8".to_string(),
                server_url: server.url("/k8s/clusters/c-m-j2xw7jk8"),
            }
        );
    }

    #[tokio::test]
    async fn find_cluster_reports_a_missing_cluster() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/v1/management.cattle.io.cluster");
            then.status(200).json_body(json!({"data": []}));
        });

        let err = client(&server)
            .find_cluster(&SessionToken::new("session:secret"), "missing")
            .await
            .unwrap_err();

        assert!(matches!(err, RancherApiError::ClusterNotFound(name) if name == "missing"));
    }

    #[tokio::test]
    async fn ca_cert_returns_the_value() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET)
                .path("/v1/management.cattle.io.settings/cacerts")
                .header("Authorization", "Bearer session:secret");
            then.status(200).json_body(json!({"value": "PEM"}));
        });

        let ca = client(&server)
            .ca_cert(&SessionToken::new("session:secret"))
            .await
            .unwrap();

        assert_eq!(ca, "PEM");
    }

    #[tokio::test]
    async fn create_token_sends_the_ttl_in_milliseconds() {
        let server = MockServer::start();
        csrf_mock(&server);
        let create = server.mock(|when, then| {
            when.method(POST)
                .path("/v3/tokens")
                .header("X-Api-Csrf", "token123")
                .header("Authorization", "Bearer session:secret")
                .json_body(json!({
                    "type": "token",
                    "metadata": {},
                    "description": "c9s",
                    "clusterId": "c-m-j2xw7jk8",
                    "ttl": 3_600_000,
                }));
            then.status(201)
                .header("Content-Type", "application/json")
                .body(TOKEN);
        });

        let token = client(&server)
            .create_token(
                &SessionToken::new("session:secret"),
                "c-m-j2xw7jk8",
                Duration::from_secs(3600),
            )
            .await
            .unwrap();

        assert_eq!(
            token,
            ApiToken {
                id: "token-bpx5g".to_string(),
                token: "token-bpx5g:secret".to_string(),
            }
        );
        create.assert();
    }

    #[tokio::test]
    async fn a_401_is_unauthorized() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET)
                .path("/v1/management.cattle.io.settings/cacerts");
            then.status(401);
        });

        let err = client(&server)
            .ca_cert(&SessionToken::new("expired"))
            .await
            .unwrap_err();

        assert!(matches!(err, RancherApiError::Unauthorized));
    }

    #[tokio::test]
    async fn another_error_status_carries_the_status_and_body() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET)
                .path("/v1/management.cattle.io.settings/cacerts");
            then.status(500).body("boom");
        });

        let err = client(&server)
            .ca_cert(&SessionToken::new("session"))
            .await
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "rancher returned 500 for GET /v1/management.cattle.io.settings/cacerts: boom"
        );
    }

    #[tokio::test]
    async fn an_unexpected_body_is_a_failure() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET)
                .path("/v1/management.cattle.io.settings/cacerts");
            then.status(200).body("not json");
        });

        let err = client(&server)
            .ca_cert(&SessionToken::new("session"))
            .await
            .unwrap_err();

        assert!(matches!(err, RancherApiError::Failed(_)));
    }
}
