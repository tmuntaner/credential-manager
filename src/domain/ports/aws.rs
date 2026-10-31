use crate::domain::models::aws::{AwsError, Credential};
use crate::domain::models::login::AwsLogin;
use crate::domain::models::saml::SamlAssertion;
use crate::domain::models::secret::SafeSecret;
use async_trait::async_trait;

/// Trades the SAML assertion of the IAM role application for the credentials of its roles.
#[async_trait(?Send)]
pub trait AwsStsCredentials {
    /// Only the role `role_arn` if given, else every role in the assertion.
    async fn credentials(
        &self,
        assertion: &SamlAssertion,
        role_arn: Option<&str>,
    ) -> Result<Vec<Credential>, AwsError>;
}

/// Logs in for AWS and hands out the credentials of its roles.
#[async_trait(?Send)]
pub trait AwsCredentialIssuer {
    /// Only the role `role_arn` if given, else every role the login gives access to.
    async fn issue(
        &self,
        login: &AwsLogin,
        password: SafeSecret,
        role_arn: Option<&str>,
    ) -> Result<Vec<Credential>, AwsError>;
}

/// Trades the SAML assertion of the IAM Identity Center application for the credentials of its roles.
#[async_trait(?Send)]
pub trait AwsSsoCredentials {
    /// `region` is the one of the Identity Center instance. Only the role `role_arn` if given, else every role
    /// the user can use.
    async fn credentials(
        &self,
        assertion: &SamlAssertion,
        region: &str,
        role_arn: Option<&str>,
    ) -> Result<Vec<Credential>, AwsError>;
}
