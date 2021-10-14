use crate::aws::Credential;
use anyhow::{anyhow, Result};
use futures::future;
use rusoto_core::request::HttpClient;
use rusoto_core::{Region, RusotoError};
use rusoto_credential::StaticProvider;
use rusoto_sts::{
    AssumeRoleWithSAMLError, AssumeRoleWithSAMLRequest, AssumeRoleWithSAMLResponse, Sts,
};

pub struct StsClient {
    client: Box<dyn Sts>,
}

impl StsClient {
    pub fn new() -> Result<Self> {
        let provider = StaticProvider::new_minimal(String::from(""), String::from(""));
        let client = rusoto_sts::StsClient::new_with(
            HttpClient::new().unwrap(),
            provider,
            Region::default(),
        );

        Ok(Self {
            client: Box::new(client),
        })
    }

    pub async fn generate_sts_credentials(
        &self,
        saml_response: String,
        saml_aws_credentials: Vec<SamlAWSRole>,
    ) -> Result<Vec<Credential>> {
        let futures = future::join_all(saml_aws_credentials.into_iter().map(|role| {
            let req = AssumeRoleWithSAMLRequest {
                duration_seconds: Some(60 * 60),
                policy: None,
                policy_arns: None,
                principal_arn: role.principal_arn,
                role_arn: role.role_arn,
                saml_assertion: saml_response.clone(),
            };

            async move {
                StsFuture {
                    role_arn: req.role_arn.clone(),
                    request: self.client.assume_role_with_saml(req).await,
                }
            }
        }))
        .await;

        let mut aws_credentials = vec![];

        for future in futures {
            let response = future.request?;
            let credentials = response
                .credentials
                .ok_or_else(|| anyhow!("Could not get credentials from STS"))?;
            aws_credentials.push(Credential {
                secret_access_key: credentials.secret_access_key,
                access_key_id: credentials.access_key_id,
                role_arn: Some(future.role_arn.clone()),
                session_token: credentials.session_token,
            });
        }

        Ok(aws_credentials)
    }
}

#[derive(Clone)]
pub struct SamlAWSRole {
    pub principal_arn: String,
    pub role_arn: String,
}

struct StsFuture {
    request: Result<AssumeRoleWithSAMLResponse, RusotoError<AssumeRoleWithSAMLError>>,
    role_arn: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use rusoto_sts::{
        AssumeRoleError, AssumeRoleRequest, AssumeRoleResponse, AssumeRoleWithWebIdentityError,
        AssumeRoleWithWebIdentityRequest, AssumeRoleWithWebIdentityResponse, Credentials,
        DecodeAuthorizationMessageError, DecodeAuthorizationMessageRequest,
        DecodeAuthorizationMessageResponse, GetAccessKeyInfoError, GetAccessKeyInfoRequest,
        GetAccessKeyInfoResponse, GetCallerIdentityError, GetCallerIdentityRequest,
        GetCallerIdentityResponse, GetFederationTokenError, GetFederationTokenRequest,
        GetFederationTokenResponse, GetSessionTokenError, GetSessionTokenRequest,
        GetSessionTokenResponse,
    };

    #[test]
    fn test_new() {
        let client = StsClient::new();
        assert_eq!(true, client.is_ok());
    }

    #[tokio::test]
    async fn test_generate_sts_credentials() {
        let client = StsClient {
            client: Box::new(TestStsClient {}),
        };

        let roles = vec![
            SamlAWSRole {
                principal_arn: String::from("PrincipalArn1"),
                role_arn: String::from("RoleArn1"),
            },
            SamlAWSRole {
                principal_arn: String::from("PrincipalArn2"),
                role_arn: String::from("RoleArn2"),
            },
        ];

        let credentials = client
            .generate_sts_credentials(String::from("Saml"), roles)
            .await
            .unwrap();
        assert_eq!(
            credentials.get(0).unwrap().access_key_id,
            "AccessKeyId for RoleArn1"
        );
        assert_eq!(
            credentials.get(0).unwrap().session_token,
            "SessionToken for RoleArn1"
        );
        assert_eq!(
            credentials.get(0).unwrap().secret_access_key,
            "SecretAccessKey for RoleArn1"
        );
        assert_eq!(
            credentials.get(1).unwrap().access_key_id,
            "AccessKeyId for RoleArn2"
        );
        assert_eq!(
            credentials.get(1).unwrap().session_token,
            "SessionToken for RoleArn2"
        );
        assert_eq!(
            credentials.get(1).unwrap().secret_access_key,
            "SecretAccessKey for RoleArn2"
        );
    }

    struct TestStsClient {}

    #[async_trait]
    impl Sts for TestStsClient {
        async fn assume_role(
            &self,
            _input: AssumeRoleRequest,
        ) -> std::prelude::rust_2015::Result<AssumeRoleResponse, RusotoError<AssumeRoleError>>
        {
            todo!()
        }

        async fn assume_role_with_saml(
            &self,
            input: AssumeRoleWithSAMLRequest,
        ) -> std::prelude::rust_2015::Result<
            AssumeRoleWithSAMLResponse,
            RusotoError<AssumeRoleWithSAMLError>,
        > {
            Ok(AssumeRoleWithSAMLResponse {
                assumed_role_user: None,
                audience: None,
                credentials: Some(Credentials {
                    access_key_id: format!("AccessKeyId for {}", input.role_arn),
                    expiration: String::from(""),
                    secret_access_key: format!("SecretAccessKey for {}", input.role_arn),
                    session_token: format!("SessionToken for {}", input.role_arn),
                }),
                issuer: None,
                name_qualifier: None,
                packed_policy_size: None,
                source_identity: None,
                subject: None,
                subject_type: None,
            })
        }

        async fn assume_role_with_web_identity(
            &self,
            _input: AssumeRoleWithWebIdentityRequest,
        ) -> std::prelude::rust_2015::Result<
            AssumeRoleWithWebIdentityResponse,
            RusotoError<AssumeRoleWithWebIdentityError>,
        > {
            todo!()
        }

        async fn decode_authorization_message(
            &self,
            _input: DecodeAuthorizationMessageRequest,
        ) -> std::prelude::rust_2015::Result<
            DecodeAuthorizationMessageResponse,
            RusotoError<DecodeAuthorizationMessageError>,
        > {
            todo!()
        }

        async fn get_access_key_info(
            &self,
            _input: GetAccessKeyInfoRequest,
        ) -> std::prelude::rust_2015::Result<
            GetAccessKeyInfoResponse,
            RusotoError<GetAccessKeyInfoError>,
        > {
            todo!()
        }

        async fn get_caller_identity(
            &self,
            _input: GetCallerIdentityRequest,
        ) -> std::prelude::rust_2015::Result<
            GetCallerIdentityResponse,
            RusotoError<GetCallerIdentityError>,
        > {
            todo!()
        }

        async fn get_federation_token(
            &self,
            _input: GetFederationTokenRequest,
        ) -> std::prelude::rust_2015::Result<
            GetFederationTokenResponse,
            RusotoError<GetFederationTokenError>,
        > {
            todo!()
        }

        async fn get_session_token(
            &self,
            _input: GetSessionTokenRequest,
        ) -> std::prelude::rust_2015::Result<
            GetSessionTokenResponse,
            RusotoError<GetSessionTokenError>,
        > {
            todo!()
        }
    }
}
