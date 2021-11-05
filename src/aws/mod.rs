use anyhow::{anyhow, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};

mod sso_portal_api;
pub mod sso_portal_client;
pub mod sts;

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    account_id: String,
    account_name: String,
    email_address: String,
}

impl Account {
    pub fn account_id(&self) -> String {
        self.account_id.clone()
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Role {
    account_id: String,
    role_name: String,
}

impl Role {
    pub fn role_arn(&self) -> String {
        format!("arn:aws:iam::{}:role/{}", self.account_id, self.role_name)
    }

    pub fn role_name(&self) -> String {
        self.role_name.clone()
    }

    pub fn account_id(&self) -> String {
        self.account_id.clone()
    }

    pub fn from_arn(arn: &str) -> Result<Self> {
        let re = Regex::new(r"arn:aws:iam::([0-9]*):role/(.*)")?;
        let captures = re
            .captures(arn)
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

        Ok(Self {
            account_id,
            role_name,
        })
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    secret_access_key: String,
    access_key_id: String,
    session_token: String,
    role_arn: Option<String>,
    expiration: String,
}

impl Credential {
    pub fn secret_access_key(&self) -> String {
        self.secret_access_key.clone()
    }

    pub fn access_key_id(&self) -> String {
        self.access_key_id.clone()
    }

    pub fn session_token(&self) -> String {
        self.session_token.clone()
    }

    pub fn role_arn(&self) -> Option<String> {
        self.role_arn.clone()
    }

    pub fn expiration(&self) -> String {
        self.expiration.clone()
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

        let parsed = Role::from_arn(&arn).unwrap();

        assert_eq!(parsed.account_id, account_id);
        assert_eq!(parsed.role_name, role_name);
    }
}
