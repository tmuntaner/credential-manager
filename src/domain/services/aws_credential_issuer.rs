//! Logs in at the identity provider and trades the SAML assertion for AWS credentials.

use crate::domain::models::aws::{AwsError, Credential};
use crate::domain::models::login::AwsLogin;
use crate::domain::models::secret::SafeSecret;
use crate::domain::models::settings::AwsAppType;
use crate::domain::models::user_credentials::UserCredentials;
use crate::domain::ports::aws::{AwsCredentialIssuer, AwsSsoCredentials, AwsStsCredentials};
use crate::domain::ports::login::SamlIdentityProvider;
use async_trait::async_trait;

/// Issues AWS credentials through the identity provider and the AWS service of the app type.
pub struct AwsCredentialIssuerService {
    identity_provider: Box<dyn SamlIdentityProvider>,
    sts: Box<dyn AwsStsCredentials>,
    sso: Box<dyn AwsSsoCredentials>,
}

impl AwsCredentialIssuerService {
    pub fn new(
        identity_provider: Box<dyn SamlIdentityProvider>,
        sts: Box<dyn AwsStsCredentials>,
        sso: Box<dyn AwsSsoCredentials>,
    ) -> Self {
        Self {
            identity_provider,
            sts,
            sso,
        }
    }
}

#[async_trait(?Send)]
impl AwsCredentialIssuer for AwsCredentialIssuerService {
    async fn issue(
        &self,
        login: &AwsLogin,
        password: SafeSecret,
        role_arn: Option<&str>,
    ) -> Result<Vec<Credential>, AwsError> {
        let credentials = UserCredentials {
            username: login.username.to_string(),
            password,
            mfa: login.mfa,
        };
        let assertion = self
            .identity_provider
            .login(&login.app_url, credentials)
            .await?;

        match login.app_type {
            AwsAppType::Aws => self.sts.credentials(&assertion, role_arn).await,
            AwsAppType::AwsSso => {
                let region = login.region.as_deref().ok_or(AwsError::MissingRegion)?;

                self.sso.credentials(&assertion, region, role_arn).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::mfa::MfaSelection;
    use crate::domain::models::saml::{SamlAssertion, SamlLoginError};
    use std::cell::RefCell;
    use std::rc::Rc;

    /// What the fakes were asked, in order.
    type Calls = Rc<RefCell<Vec<String>>>;

    struct FakeIdp {
        calls: Calls,
        fail: bool,
    }

    #[async_trait(?Send)]
    impl SamlIdentityProvider for FakeIdp {
        async fn login(
            &self,
            app_url: &str,
            credentials: UserCredentials,
        ) -> Result<SamlAssertion, SamlLoginError> {
            self.calls.borrow_mut().push(format!(
                "login {app_url} {} {} {:?}",
                credentials.username,
                credentials.password.into_inner(),
                credentials.mfa
            ));
            if self.fail {
                return Err(SamlLoginError::Failed("wrong password".into()));
            }

            Ok(SamlAssertion {
                saml_response: "assertion".to_string(),
                destination: "https://destination".to_string(),
                relay_state: None,
            })
        }
    }

    struct FakeAws(Calls);

    fn credential(role_arn: &str) -> Credential {
        Credential {
            secret_access_key: "secret".to_string(),
            access_key_id: "access".to_string(),
            session_token: "token".to_string(),
            role_arn: Some(role_arn.to_string()),
            expiration: "2030-01-01T00:00:00Z".to_string(),
        }
    }

    #[async_trait(?Send)]
    impl AwsStsCredentials for FakeAws {
        async fn credentials(
            &self,
            assertion: &SamlAssertion,
            role_arn: Option<&str>,
        ) -> Result<Vec<Credential>, AwsError> {
            self.0
                .borrow_mut()
                .push(format!("sts {} {role_arn:?}", assertion.saml_response));

            Ok(vec![credential("sts-role")])
        }
    }

    #[async_trait(?Send)]
    impl AwsSsoCredentials for FakeAws {
        async fn credentials(
            &self,
            assertion: &SamlAssertion,
            region: &str,
            role_arn: Option<&str>,
        ) -> Result<Vec<Credential>, AwsError> {
            self.0.borrow_mut().push(format!(
                "sso {} {region} {role_arn:?}",
                assertion.saml_response
            ));

            Ok(vec![credential("sso-role")])
        }
    }

    fn issuer(fail_login: bool) -> (AwsCredentialIssuerService, Calls) {
        let calls = Calls::default();
        let service = AwsCredentialIssuerService::new(
            Box::new(FakeIdp {
                calls: calls.clone(),
                fail: fail_login,
            }),
            Box::new(FakeAws(calls.clone())),
            Box::new(FakeAws(calls.clone())),
        );

        (service, calls)
    }

    fn login(app_type: AwsAppType, region: Option<&str>) -> AwsLogin {
        AwsLogin {
            app_url: "https://id.example.com/app".to_string(),
            idp_url: None,
            username: "user".to_string(),
            region: region.map(str::to_string),
            mfa: Some(MfaSelection::Totp),
            app_type,
        }
    }

    #[tokio::test]
    async fn the_app_type_aws_goes_through_sts() {
        let (issuer, calls) = issuer(false);

        let credentials = issuer
            .issue(
                &login(AwsAppType::Aws, None),
                SafeSecret::new("secret"),
                Some("arn"),
            )
            .await
            .unwrap();

        assert_eq!(credentials[0].role_arn().as_deref(), Some("sts-role"));
        assert_eq!(
            *calls.borrow(),
            [
                "login https://id.example.com/app user secret Some(Totp)",
                "sts assertion Some(\"arn\")"
            ]
        );
    }

    #[tokio::test]
    async fn the_app_type_aws_sso_goes_through_the_portal_of_its_region() {
        let (issuer, calls) = issuer(false);

        let credentials = issuer
            .issue(
                &login(AwsAppType::AwsSso, Some("eu-central-1")),
                SafeSecret::new("secret"),
                None,
            )
            .await
            .unwrap();

        assert_eq!(credentials[0].role_arn().as_deref(), Some("sso-role"));
        assert_eq!(calls.borrow()[1], "sso assertion eu-central-1 None");
    }

    #[tokio::test]
    async fn sso_needs_a_region() {
        let (issuer, _) = issuer(false);

        let err = issuer
            .issue(
                &login(AwsAppType::AwsSso, None),
                SafeSecret::new("secret"),
                None,
            )
            .await
            .unwrap_err();

        assert!(matches!(err, AwsError::MissingRegion));
    }

    #[tokio::test]
    async fn a_failed_login_stops_before_aws_is_called() {
        let (issuer, calls) = issuer(true);

        let err = issuer
            .issue(
                &login(AwsAppType::Aws, None),
                SafeSecret::new("secret"),
                None,
            )
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "wrong password");
        assert_eq!(calls.borrow().len(), 1);
    }
}
