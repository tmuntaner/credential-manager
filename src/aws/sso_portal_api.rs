use crate::aws::{Account, Credential, Role};
use crate::http::api_client::{AcceptType, ApiClient};
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, UNIX_EPOCH};
use url::Url;

// https://docs.aws.amazon.com/singlesignon/latest/PortalAPIReference/ssoportal-api.pdf
pub struct SsoPortal {
    portal_base_url: String,
    client: ApiClient,
}

impl SsoPortal {
    pub fn new(portal_base_url: String) -> Result<SsoPortal> {
        let client = ApiClient::new()?;
        Ok(SsoPortal {
            client,
            portal_base_url,
        })
    }
}

#[async_trait]
pub trait SsoPortalApi {
    async fn generate_credentials(&self, token: String, role: &Role) -> Result<Credential>;
    async fn list_accounts(&self, token: String) -> Result<Vec<Account>>;
    async fn list_roles(&self, token: String, account_id: String) -> Result<Vec<Role>>;
}

#[async_trait]
impl SsoPortalApi for SsoPortal {
    async fn generate_credentials(&self, token: String, role: &Role) -> Result<Credential> {
        let mut token_url = Url::parse(self.portal_base_url.as_str())?;
        token_url.set_path("/federation/credentials");

        let mut params = HashMap::new();
        params.insert(String::from("account_id"), role.account_id());
        params.insert(String::from("role_name"), role.role_name());

        let mut headers = HashMap::new();
        headers.insert(String::from("x-amz-sso_bearer_token"), token.clone());

        let response = self
            .client
            .get_backoff(
                token_url.to_string(),
                Some(params.clone()),
                Some(headers.clone()),
                AcceptType::Json,
            )
            .await?;
        let body = response.text().await?;
        let response: RoleCredentialResponse = serde_json::from_str(body.as_str())?;
        let duration = UNIX_EPOCH + Duration::from_millis(response.role_credentials.expiration);
        let date_time: DateTime<Utc> = DateTime::from(duration);
        let expiration = date_time.to_rfc3339();

        Ok(Credential {
            access_key_id: response.role_credentials.access_key_id.clone(),
            role_arn: Some(role.role_arn()),
            secret_access_key: response.role_credentials.secret_access_key.clone(),
            session_token: response.role_credentials.session_token,
            expiration,
        })
    }

    async fn list_accounts(&self, token: String) -> Result<Vec<Account>> {
        let mut next_token: Option<String> = None;
        let mut accounts: Vec<Account> = vec![];

        loop {
            let mut token_url = Url::parse(self.portal_base_url.as_str())?;
            token_url.set_path("/assignment/accounts");

            let mut params = HashMap::new();
            params.insert(String::from("max_result"), String::from("100"));

            if let Some(next) = next_token {
                params.insert(String::from("next_token"), next);
            }

            let mut headers = HashMap::new();
            headers.insert(String::from("x-amz-sso_bearer_token"), token.clone());

            let response = self
                .client
                .get_backoff(
                    token_url.to_string(),
                    Some(params),
                    Some(headers),
                    AcceptType::Json,
                )
                .await?;
            let body = response.text().await?;
            let response: ListAccountResponse = serde_json::from_str(body.as_str())?;

            accounts.append(&mut response.account_list.clone());
            if response.next_token.is_some() {
                next_token = response.next_token.clone()
            } else {
                break;
            }
        }

        Ok(accounts)
    }

    async fn list_roles(&self, token: String, account_id: String) -> Result<Vec<Role>> {
        let mut next_token: Option<String> = None;
        let mut roles: Vec<Role> = vec![];

        loop {
            let mut token_url = Url::parse(self.portal_base_url.as_str())?;
            token_url.set_path("/assignment/roles");

            let mut params = HashMap::new();
            params.insert(String::from("max_result"), String::from("100"));
            params.insert(String::from("account_id"), account_id.clone());

            if let Some(next) = next_token {
                params.insert(String::from("next_token"), next);
            }

            let mut headers = HashMap::new();
            headers.insert(String::from("x-amz-sso_bearer_token"), token.clone());

            let response = self
                .client
                .get_backoff(
                    token_url.to_string(),
                    Some(params),
                    Some(headers),
                    AcceptType::Json,
                )
                .await?;
            let body = response.text().await?;
            let response: ListAccountRolesResponse = serde_json::from_str(body.as_str())?;

            roles.append(&mut response.role_list.clone());
            if response.next_token.is_some() {
                next_token = response.next_token.clone()
            } else {
                break;
            }
        }

        Ok(roles)
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ListAccountResponse {
    next_token: Option<String>,
    account_list: Vec<Account>,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct RoleCredentialResponse {
    role_credentials: RoleCredential,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct RoleCredential {
    secret_access_key: String,
    access_key_id: String,
    session_token: String,
    expiration: u64,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ListAccountRolesResponse {
    next_token: Option<String>,
    role_list: Vec<Role>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::MockServer;

    #[test]
    fn test_new() {
        let client = SsoPortal::new(String::from("https://www.foo.com"));
        assert_eq!(true, client.is_ok());
    }

    #[tokio::test]
    async fn test_generate_credentials() {
        let token = String::from("TheToken");
        let secret_access_key = String::from("SecretAccessKey");
        let access_key_id = String::from("AccessKeyId");
        let session_token = String::from("SessionToken");
        let account_id = String::from("AccountId");
        let role_name = String::from("RoleName");
        let response = RoleCredentialResponse {
            role_credentials: RoleCredential {
                secret_access_key: secret_access_key.clone(),
                access_key_id: access_key_id.clone(),
                session_token: session_token.clone(),
                expiration: 1,
            },
        };
        let json = serde_json::to_string(&response).unwrap();

        let server = MockServer::start();
        let response_mock = server.mock(|when, then| {
            when.method("GET")
                .path("/federation/credentials")
                .header("x-amz-sso_bearer_token", token.as_str())
                .header_exists("x-amz-sso_bearer_token")
                .query_param("account_id", account_id.as_str())
                .query_param_exists("account_id")
                .query_param("role_name", role_name.as_str())
                .query_param_exists("role_name");
            then.status(200)
                .header("content-type", "application/json")
                .body(json);
        });
        let role = Role {
            account_id: account_id.clone(),
            role_name: role_name.clone(),
        };
        let client = SsoPortal::new(server.url("")).unwrap();
        let credentials = client.generate_credentials(token, &role).await.unwrap();

        response_mock.assert();
        assert_eq!(
            credentials.role_arn,
            Some(format!("arn:aws:iam::{}:role/{}", account_id, role_name))
        );
        assert_eq!(credentials.session_token, session_token);
        assert_eq!(credentials.secret_access_key, secret_access_key);
        assert_eq!(credentials.access_key_id, access_key_id);
    }

    #[tokio::test]
    async fn test_list_accounts() {
        let token = String::from("TheToken");
        let next_token = String::from("TheNextToken");
        let account_1_id = String::from("Account1Id");
        let account_1_name = String::from("Account1Name");
        let account_1_email = String::from("Account1Email");
        let account_2_id = String::from("Account2Id");
        let account_2_name = String::from("Account2Name");
        let account_2_email = String::from("Account2Email");
        let response_1 = ListAccountResponse {
            next_token: Some(next_token.clone()),
            account_list: vec![Account {
                account_id: account_1_id.clone(),
                account_name: account_1_name.clone(),
                email_address: account_1_email.clone(),
            }],
        };
        let response_2 = ListAccountResponse {
            next_token: None,
            account_list: vec![Account {
                account_id: account_2_id.clone(),
                account_name: account_2_name.clone(),
                email_address: account_2_email.clone(),
            }],
        };
        let json_1 = serde_json::to_string(&response_1).unwrap();
        let json_2 = serde_json::to_string(&response_2).unwrap();

        let server = MockServer::start();
        let response_2_mock = server.mock(|when, then| {
            when.method("GET")
                .path("/assignment/accounts")
                .header("x-amz-sso_bearer_token", token.as_str())
                .header_exists("x-amz-sso_bearer_token")
                .query_param("next_token", next_token.as_str())
                .query_param_exists("next_token");
            then.status(200)
                .header("content-type", "application/json")
                .body(json_2);
        });
        let response_1_mock = server.mock(|when, then| {
            when.method("GET")
                .path("/assignment/accounts")
                .header("x-amz-sso_bearer_token", token.as_str())
                .header_exists("x-amz-sso_bearer_token");
            then.status(200)
                .header("content-type", "application/json")
                .body(json_1);
        });

        let client = SsoPortal::new(server.url("")).unwrap();
        let accounts = client.list_accounts(token).await.unwrap();

        response_1_mock.assert();
        response_2_mock.assert();
        assert_eq!(accounts.get(0).unwrap().account_id, account_1_id);
        assert_eq!(accounts.get(0).unwrap().account_name, account_1_name);
        assert_eq!(accounts.get(0).unwrap().email_address, account_1_email);
        assert_eq!(accounts.get(1).unwrap().account_id, account_2_id);
        assert_eq!(accounts.get(1).unwrap().account_name, account_2_name);
        assert_eq!(accounts.get(1).unwrap().email_address, account_2_email);
    }

    #[tokio::test]
    async fn test_list_roles() {
        let token = String::from("TheToken");
        let account_id = String::from("TheAccountId");
        let role_name_1 = String::from("TheRoleName1");
        let role_name_2 = String::from("TheRoleName2");
        let next_token = String::from("TheNextToken");
        let response_1 = ListAccountRolesResponse {
            next_token: Some(next_token.clone()),
            role_list: vec![Role {
                account_id: account_id.clone(),
                role_name: role_name_1.clone(),
            }],
        };
        let response_2 = ListAccountRolesResponse {
            next_token: None,
            role_list: vec![Role {
                account_id: account_id.clone(),
                role_name: role_name_2.clone(),
            }],
        };
        let json_1 = serde_json::to_string(&response_1).unwrap();
        let json_2 = serde_json::to_string(&response_2).unwrap();

        let server = MockServer::start();
        let response_2_mock = server.mock(|when, then| {
            when.method("GET")
                .path("/assignment/roles")
                .header("x-amz-sso_bearer_token", token.as_str())
                .header_exists("x-amz-sso_bearer_token")
                .query_param("account_id", account_id.as_str())
                .query_param_exists("account_id")
                .query_param("next_token", next_token.as_str())
                .query_param_exists("next_token");
            then.status(200)
                .header("content-type", "application/json")
                .body(json_2);
        });
        let response_1_mock = server.mock(|when, then| {
            when.method("GET")
                .path("/assignment/roles")
                .header("x-amz-sso_bearer_token", token.as_str())
                .header_exists("x-amz-sso_bearer_token")
                .query_param("account_id", account_id.as_str())
                .query_param_exists("account_id");
            then.status(200)
                .header("content-type", "application/json")
                .body(json_1);
        });

        let client = SsoPortal::new(server.url("")).unwrap();
        let roles = client.list_roles(token, account_id.clone()).await.unwrap();

        response_1_mock.assert();
        response_2_mock.assert();
        assert_eq!(roles.get(0).unwrap().account_id(), account_id);
        assert_eq!(roles.get(0).unwrap().role_name(), role_name_1);
        assert_eq!(roles.get(1).unwrap().account_id(), account_id);
        assert_eq!(roles.get(1).unwrap().role_name(), role_name_2);
    }
}
