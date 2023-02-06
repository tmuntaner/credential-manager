use crate::aws::sso_portal_api::{SsoPortal, SsoPortalApi};
use crate::aws::{Credential, Role};
use anyhow::Result;
use futures::future;

pub struct SsoPortalClient {
    api_client: Box<dyn SsoPortalApi>,
}

impl SsoPortalClient {
    pub fn new(portal_base_url: String) -> Result<Self> {
        let api_client = SsoPortal::new(portal_base_url)?;

        Ok(SsoPortalClient {
            api_client: Box::new(api_client),
        })
    }

    pub async fn list_credentials(
        &self,
        token: String,
        roles: Vec<Role>,
    ) -> Result<Vec<Credential>> {
        let mut credentials = vec![];

        let futures = future::join_all(roles.into_iter().map(|role| {
            let token = token.clone();
            async move {
                let credentials = self.api_client.generate_credentials(token, &role).await;

                CredentialsFuture { credentials }
            }
        }))
        .await;

        for future in futures {
            let credential = future.credentials?;
            credentials.push(credential);
        }

        Ok(credentials)
    }

    pub async fn list_role_arns(&self, token: String) -> Result<Vec<Role>> {
        let accounts = self.api_client.list_accounts(token.clone()).await?;
        let mut roles = vec![];

        let futures = future::join_all(accounts.into_iter().map(|account| {
            let token = token.clone();
            async move {
                let roles = self
                    .api_client
                    .list_roles(token, account.account_id())
                    .await;
                RolesFuture { roles }
            }
        }))
        .await;

        for future in futures {
            let mut future_roles = future.roles?;
            roles.append(&mut future_roles);
        }

        Ok(roles)
    }
}

struct RolesFuture {
    roles: Result<Vec<Role>>,
}

struct CredentialsFuture {
    credentials: Result<Credential>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aws::Account;
    use async_trait::async_trait;

    struct SsoPortalApiTest {}

    #[async_trait]
    impl SsoPortalApi for SsoPortalApiTest {
        async fn generate_credentials(&self, _token: String, role: &Role) -> Result<Credential> {
            let role_arn = Some(role.role_arn());

            Ok(Credential {
                secret_access_key: format!("TheSecretAccessKey for {}", role.role_name()),
                access_key_id: format!("TheAccessKeyId for {}", role.role_name()),
                session_token: format!("TheSessionToken for {}", role.role_name()),
                role_arn,
                expiration: "".to_string(),
            })
        }

        async fn list_accounts(&self, _token: String) -> Result<Vec<Account>> {
            Ok(vec![
                Account {
                    account_id: String::from("AccountId1"),
                    account_name: String::from("account_1"),
                    email_address: String::from("account1@foo.com"),
                },
                Account {
                    account_id: String::from("AccountId2"),
                    account_name: String::from("account_2"),
                    email_address: String::from("account2@foo.com"),
                },
            ])
        }

        async fn list_roles(&self, _token: String, account_id: String) -> Result<Vec<Role>> {
            Ok(vec![Role {
                role_name: format!("Role for account {account_id}"),
                account_id,
            }])
        }
    }

    #[test]
    fn test_new() {
        let client = SsoPortalClient::new(String::from("https://foo.com"));
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_list_credentials() {
        let client = SsoPortalClient {
            api_client: Box::new(SsoPortalApiTest {}),
        };
        let token = String::from("TheToken");
        let roles = vec![
            Role {
                account_id: String::from("account 1"),
                role_name: String::from("Role1"),
            },
            Role {
                account_id: String::from("account 2"),
                role_name: String::from("Role2"),
            },
        ];
        let credentials = client.list_credentials(token, roles).await.unwrap();
        assert_eq!(
            credentials.get(0).unwrap().secret_access_key,
            String::from("TheSecretAccessKey for Role1")
        );
        assert_eq!(
            credentials.get(0).unwrap().access_key_id,
            String::from("TheAccessKeyId for Role1")
        );
        assert_eq!(
            credentials.get(0).unwrap().session_token,
            String::from("TheSessionToken for Role1")
        );
        assert_eq!(
            credentials.get(1).unwrap().secret_access_key,
            String::from("TheSecretAccessKey for Role2")
        );
        assert_eq!(
            credentials.get(1).unwrap().access_key_id,
            String::from("TheAccessKeyId for Role2")
        );
        assert_eq!(
            credentials.get(1).unwrap().session_token,
            String::from("TheSessionToken for Role2")
        );
    }

    #[tokio::test]
    async fn test_list_role_arns() {
        let client = SsoPortalClient {
            api_client: Box::new(SsoPortalApiTest {}),
        };
        let token = String::from("TheToken");
        let role_arns = client.list_role_arns(token).await.unwrap();
        assert_eq!(
            role_arns.get(0).unwrap().role_name,
            "Role for account AccountId1"
        );
        assert_eq!(
            role_arns.get(1).unwrap().role_name,
            "Role for account AccountId2"
        );
        assert_eq!(role_arns.get(0).unwrap().account_id, "AccountId1");
        assert_eq!(role_arns.get(1).unwrap().account_id, "AccountId2");
    }
}
