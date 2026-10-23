use crate::domain::models::aws::AwsError;
use crate::domain::models::aws::Credential;
use crate::domain::models::saml::SamlAssertion;
use crate::domain::ports::aws::AwsStsCredentials;
use crate::outbound::aws::sts::client::{SamlAWSRole, StsClient, StsError};
use crate::outbound::aws::sts::saml_parser::AwsSamlParser;
use crate::outbound::aws::sts::saml_parser::SamlParseError;
use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AwsCredentialsError {
    #[error(transparent)]
    Saml(#[from] SamlParseError),

    #[error(transparent)]
    Sts(#[from] StsError),

    #[error("could not find role_arn {0}")]
    RoleNotFound(String),
}

/// Takes the SAML assertion of the IAM role application, picks the roles and generates credentials for
/// them with STS.
#[derive(Default)]
pub struct StsCredentials {
    sts_client: StsClient,
}

impl StsCredentials {
    /// Generates a new [`StsCredentials`] object.
    pub fn new() -> StsCredentials {
        StsCredentials::default()
    }

    /// Call this function to get credentials from the AWS.
    async fn run(
        &self,
        assertion: SamlAssertion,
        role_arn: Option<String>,
    ) -> Result<Vec<Credential>, AwsCredentialsError> {
        let saml_parser = AwsSamlParser::from_base64(&assertion.saml_response)?;
        let roles = select_roles(&saml_parser, role_arn)?;

        self.sts_client
            .generate_sts_credentials(saml_parser.raw_saml_response(), roles)
            .await
            .map_err(AwsCredentialsError::from)
    }
}

#[async_trait(?Send)]
impl AwsStsCredentials for StsCredentials {
    async fn credentials(
        &self,
        assertion: &SamlAssertion,
        role_arn: Option<&str>,
    ) -> Result<Vec<Credential>, AwsError> {
        self.run(assertion.clone(), role_arn.map(str::to_string))
            .await
            .map_err(|e| match e {
                AwsCredentialsError::RoleNotFound(role_arn) => AwsError::RoleNotFound(role_arn),
                e => AwsError::Failed(Box::new(e)),
            })
    }
}

/// The roles in the assertion, or only the one with `role_arn` if given.
fn select_roles(
    saml_parser: &AwsSamlParser,
    role_arn: Option<String>,
) -> Result<Vec<SamlAWSRole>, AwsCredentialsError> {
    let roles = saml_parser.credentials()?;

    match role_arn {
        Some(role_arn) => {
            let role = roles
                .iter()
                .find(|role| role.role_arn == role_arn)
                .ok_or_else(|| AwsCredentialsError::RoleNotFound(role_arn.clone()))?;
            Ok(vec![role.clone()])
        }
        None => Ok(roles),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::aws::sts::saml_parser::tests::base64_encode;

    const ASSERTION_STS: &str = include_str!("../../../../testdata/assertion_sts.xml");

    fn parser() -> AwsSamlParser {
        AwsSamlParser::from_base64(&base64_encode(ASSERTION_STS)).unwrap()
    }

    #[test]
    fn selects_every_role_without_a_filter() {
        let roles = select_roles(&parser(), None).unwrap();

        assert_eq!(roles.len(), 2);
        assert_eq!(
            roles[0].role_arn,
            "arn:aws:iam::111111111111:role/ExampleAdmin"
        );
        assert_eq!(
            roles[0].principal_arn,
            "arn:aws:iam::111111111111:saml-provider/EXAMPLEID"
        );
    }

    #[test]
    fn selects_only_the_requested_role() {
        let roles = select_roles(
            &parser(),
            Some("arn:aws:iam::222222222222:role/ExampleReadOnly".to_string()),
        )
        .unwrap();

        assert_eq!(roles.len(), 1);
        assert_eq!(
            roles[0].principal_arn,
            "arn:aws:iam::222222222222:saml-provider/EXAMPLEID"
        );
    }

    #[test]
    fn fails_for_a_role_that_is_not_in_the_assertion() {
        let err = select_roles(
            &parser(),
            Some("arn:aws:iam::999999999999:role/Missing".to_string()),
        )
        .err()
        .unwrap();

        assert_eq!(
            err.to_string(),
            "could not find role_arn arn:aws:iam::999999999999:role/Missing"
        );
    }

    fn assertion(saml_response: String) -> SamlAssertion {
        SamlAssertion {
            saml_response,
            destination: "https://signin.aws.amazon.com/saml".to_string(),
            relay_state: None,
        }
    }

    #[tokio::test]
    async fn run_fails_for_a_role_that_is_not_in_the_assertion() {
        // The role is checked before anything is sent to STS.
        let err = StsCredentials::new()
            .run(
                assertion(base64_encode(ASSERTION_STS)),
                Some("arn:aws:iam::999999999999:role/Missing".to_string()),
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("could not find role_arn"));
    }

    #[tokio::test]
    async fn run_fails_for_an_invalid_assertion() {
        let result = StsCredentials::new()
            .run(assertion("***".to_string()), None)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn the_port_reports_a_missing_role_as_such() {
        let err = StsCredentials::new()
            .credentials(
                &assertion(base64_encode(ASSERTION_STS)),
                Some("arn:aws:iam::999999999999:role/Missing"),
            )
            .await
            .unwrap_err();

        assert!(
            matches!(err, AwsError::RoleNotFound(arn) if arn == "arn:aws:iam::999999999999:role/Missing")
        );
    }
}
