use crate::domain::models::saml::SamlLoginError;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::error::Error;
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Why no AWS credentials were handed out.
#[derive(Debug, Error)]
pub enum AwsError {
    #[error(transparent)]
    Login(#[from] SamlLoginError),

    #[error("could not find role_arn {0}")]
    RoleNotFound(String),

    #[error("please supply a region")]
    MissingRegion,

    #[error(transparent)]
    Failed(Box<dyn Error + Send + Sync>),
}

#[derive(Debug, Error)]
pub enum RoleError {
    #[error(transparent)]
    Regex(#[from] regex::Error),

    #[error("arn could not be parsed")]
    UnparsableArn,

    #[error("could not parse account id")]
    MissingAccountId,

    #[error("could not parse role name")]
    MissingRoleName,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub account_id: String,
    pub account_name: String,
    pub email_address: String,
}

impl Account {
    pub fn account_id(&self) -> String {
        self.account_id.clone()
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Role {
    pub account_id: String,
    pub role_name: String,
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

    pub fn from_arn(arn: &str) -> Result<Self, RoleError> {
        let re = Regex::new(r"arn:aws:iam::([0-9]*):role/(.*)")?;
        let captures = re.captures(arn).ok_or(RoleError::UnparsableArn)?;

        let account_id = captures
            .get(1)
            .ok_or(RoleError::MissingAccountId)?
            .as_str()
            .to_string();

        let role_name = captures
            .get(2)
            .ok_or(RoleError::MissingRoleName)?
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
    pub secret_access_key: String,
    pub access_key_id: String,
    pub session_token: String,
    pub role_arn: Option<String>,
    pub expiration: String,
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

    /// Whether the credential has not expired at `now`. An expiration that cannot be read means it has.
    pub fn is_valid_at(&self, now: OffsetDateTime) -> bool {
        OffsetDateTime::parse(&self.expiration, &Rfc3339).is_ok_and(|expiration| now <= expiration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_role_arn() {
        let account_id = String::from("000222111000");
        let role_name = String::from("the arn");
        let arn = format!("arn:aws:iam::{account_id}:role/{role_name}");

        let parsed = Role::from_arn(&arn).unwrap();

        assert_eq!(parsed.account_id, account_id);
        assert_eq!(parsed.role_name, role_name);
    }

    #[test]
    fn a_credential_is_valid_until_it_expires() {
        let credential = |expiration: &str| Credential {
            secret_access_key: "s".to_string(),
            access_key_id: "a".to_string(),
            session_token: "t".to_string(),
            role_arn: None,
            expiration: expiration.to_string(),
        };
        let now = OffsetDateTime::parse("2026-01-01T12:00:00Z", &Rfc3339).unwrap();

        assert!(credential("2026-01-01T12:00:01Z").is_valid_at(now));
        assert!(!credential("2026-01-01T11:59:59Z").is_valid_at(now));
        assert!(!credential("soon").is_valid_at(now));
    }
}
