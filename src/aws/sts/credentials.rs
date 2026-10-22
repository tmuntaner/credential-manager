use crate::authentik::flow::session::SamlAssertion;
use crate::authentik::saml_parsers::AwsSamlParser;
use crate::authentik::saml_parsers::SamlParseError;
use crate::aws::sts::client::{SamlAWSRole, StsClient, StsError};
use crate::aws::Credential;
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
pub struct AwsCredentials {
    sts_client: StsClient,
}

impl AwsCredentials {
    /// Generates a new [`AwsCredentials`] object.
    pub fn new() -> Result<AwsCredentials, AwsCredentialsError> {
        let sts_client = StsClient::new()?;
        Ok(AwsCredentials { sts_client })
    }

    /// Call this function to get credentials from the AWS.
    pub async fn run(
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
    use crate::authentik::saml_parsers::tests::base64_encode;

    const ASSERTION_STS: &str = include_str!("../../../testdata/assertion_sts.xml");

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
        let err = AwsCredentials::new()
            .unwrap()
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
        let result = AwsCredentials::new()
            .unwrap()
            .run(assertion("***".to_string()), None)
            .await;

        assert!(result.is_err());
    }
}
