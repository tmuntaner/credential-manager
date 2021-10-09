use crate::aws::sts::AwsCredential;
use crate::http::api_client::{AcceptType, ApiClient};
use anyhow::{anyhow, Result};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use url::Url;

pub struct SsoPortal {
    portal_base_url: String,
    client: ApiClient,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ListAccountResponse {
    next_token: Option<String>,
    account_list: Vec<Account>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct RoleCredentialResponse {
    role_credentials: RoleCredential,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ListAccountRolesResponse {
    next_token: Option<String>,
    role_list: Vec<Role>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct Account {
    account_id: String,
    account_name: String,
    email_address: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct Role {
    account_id: String,
    role_name: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct RoleCredential {
    secret_access_key: String,
    access_key_id: String,
    session_token: String,
}

pub struct AwsRole {
    account_id: String,
    role_arn: String,
    role_name: String,
}

// https://docs.aws.amazon.com/singlesignon/latest/PortalAPIReference/ssoportal-api.pdf
impl SsoPortal {
    pub fn new(portal_base_url: String) -> Result<SsoPortal> {
        let client = ApiClient::new()?;
        Ok(SsoPortal {
            client,
            portal_base_url,
        })
    }

    pub fn parse_role_arn(arn: String) -> Result<AwsRole> {
        let re = Regex::new(r"arn:aws:iam::([0-9]*):role/(.*)")?;
        let captures = re
            .captures(arn.as_str())
            .ok_or_else(|| anyhow!("arn could not be parsed"))?;
        let account_id = captures
            .get(1)
            .ok_or_else(|| anyhow!("could not parse account id"))?
            .as_str()
            .to_string();
        let role_name = captures
            .get(2)
            .ok_or_else(|| anyhow!("could not parse role name"))?
            .as_str()
            .to_string();

        Ok(AwsRole {
            account_id,
            role_name,
            role_arn: arn,
        })
    }

    pub async fn list_role_arns(&self, token: String) -> Result<Vec<AwsRole>> {
        let accounts = self.list_accounts(token.clone()).await?;
        let mut roles = vec![];
        for account in accounts {
            let account_roles = self
                .list_roles(token.clone(), account.account_id.clone())
                .await?;
            for role in account_roles {
                let role_arn = format!("arn:aws:iam::{}:role/{}", role.account_id, role.role_name);
                roles.push(AwsRole {
                    role_arn,
                    role_name: role.role_name,
                    account_id: account.account_id.clone(),
                });
            }
        }

        Ok(roles)
    }

    pub async fn list_credentials(&self, token: String, role: AwsRole) -> Result<AwsCredential> {
        let mut token_url = Url::parse(self.portal_base_url.as_str())?;
        token_url.set_path("/federation/credentials");

        let mut params = HashMap::new();
        params.insert(String::from("account_id"), role.account_id);
        params.insert(String::from("role_name"), role.role_name);

        let mut headers = HashMap::new();
        headers.insert(String::from("x-amz-sso_bearer_token"), token.clone());

        let response = self
            .client
            .get(
                token_url.to_string(),
                Some(params),
                Some(headers),
                AcceptType::Json,
            )
            .await?;
        let body = response.text().await?;
        let response: RoleCredentialResponse = serde_json::from_str(body.as_str())?;

        Ok(AwsCredential {
            access_key_id: response.role_credentials.access_key_id.clone(),
            role_arn: role.role_arn,
            secret_access_key: response.role_credentials.secret_access_key.clone(),
            session_token: response.role_credentials.session_token,
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
                .get(
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
                .get(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_role_arn() {
        let account_id = String::from("000222111000");
        let role_name = String::from("the arn");
        let arn = format!("arn:aws:iam::{}:role/{}", account_id, role_name);
        let parsed = SsoPortal::parse_role_arn(arn.clone()).unwrap();

        assert_eq!(parsed.role_arn, arn);
        assert_eq!(parsed.account_id, account_id);
        assert_eq!(parsed.role_name, role_name);
    }
}
