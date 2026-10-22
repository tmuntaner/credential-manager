use crate::aws::sts::client::SamlAWSRole;
use base64::{alphabet, engine, Engine};
use quick_xml::events::Event;
use quick_xml::NsReader;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SamlParseError {
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),

    #[error(transparent)]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    Attribute(#[from] quick_xml::events::attributes::AttrError),

    #[error("destination not found")]
    DestinationNotFound,

    #[error("malformed role attribute value, expected a role ARN and a provider ARN: {0}")]
    MalformedRole(String),
}

pub struct AwsSsoSamlParser {
    saml_body: String,
    saml_raw: String,
}

impl AwsSsoSamlParser {
    /// Parses the base64 `SAMLResponse` as handed out by the authentik autosubmit stage.
    pub fn from_base64(saml_response: &str) -> Result<AwsSsoSamlParser, SamlParseError> {
        let saml_parser = BaseSamlParser::from_base64(saml_response)?;

        Ok(AwsSsoSamlParser {
            saml_raw: saml_parser.raw(),
            saml_body: saml_parser.body(),
        })
    }

    pub fn raw_saml_response(&self) -> String {
        self.saml_raw.clone()
    }

    pub fn destination(&self) -> Result<String, SamlParseError> {
        let body = self.saml_body.clone();

        let mut reader = NsReader::from_str(body.as_str());
        reader.config_mut().trim_text(true);

        loop {
            match reader.read_resolved_event() {
                Ok((_, Event::Start(e))) => {
                    let local = e.local_name();
                    if let "Response" = local.as_ref() {
                        for el in e.attributes() {
                            let e = el?;
                            let key = e.key.into_inner();
                            let value = e.value.as_ref();
                            if key == "Destination" {
                                return Ok(value.to_string());
                            }
                        }
                    }
                }
                Ok((_, Event::Eof)) => break,
                Err(_e) => break,
                _ => (),
            }
        }

        Err(SamlParseError::DestinationNotFound)
    }
}

pub struct AwsSamlParser {
    saml_body: String,
    saml_raw: String,
}

impl AwsSamlParser {
    /// Parses the base64 `SAMLResponse` as handed out by the authentik autosubmit stage.
    pub fn from_base64(saml_response: &str) -> Result<AwsSamlParser, SamlParseError> {
        let saml_parser = BaseSamlParser::from_base64(saml_response)?;

        Ok(AwsSamlParser {
            saml_raw: saml_parser.raw(),
            saml_body: saml_parser.body(),
        })
    }

    pub fn raw_saml_response(&self) -> String {
        self.saml_raw.clone()
    }

    pub fn credentials(&self) -> Result<Vec<SamlAWSRole>, SamlParseError> {
        let body = self.saml_body.clone();

        let mut reader = NsReader::from_str(body.as_str());
        reader.config_mut().trim_text(true);

        #[derive(Clone, Copy)]
        enum State {
            RoleAttributes,
            Other,
        }

        #[derive(Clone, Copy)]
        enum Name {
            AttributeValue,
            Other,
        }

        let mut name = Name::Other;
        let mut state = State::Other;
        let mut credentials: Vec<SamlAWSRole> = vec![];

        loop {
            match reader.read_resolved_event() {
                Ok((_, Event::Start(e))) => {
                    let local = e.local_name();
                    match local.as_ref() {
                        "Attribute" => {
                            for el in e.attributes() {
                                let e = el?;
                                let key = e.key.into_inner();
                                let value = e.value.as_ref();
                                if let ("Name", "https://aws.amazon.com/SAML/Attributes/Role") =
                                    (key, value)
                                {
                                    state = State::RoleAttributes;
                                    break;
                                }
                            }
                        }
                        "AttributeValue" => {
                            name = Name::AttributeValue;
                        }
                        _ => name = Name::Other,
                    }
                }
                Ok((_, Event::Text(e))) => {
                    if let (State::RoleAttributes, Name::AttributeValue) = (state, name) {
                        let value: &str = &e;
                        credentials.push(parse_role_value(value)?);
                    }
                }
                Ok((_, Event::End(e))) => {
                    let local = e.local_name();
                    if let "Attribute" = local.as_ref() {
                        state = State::Other
                    }
                }
                Ok((_, Event::Eof)) => break,
                Err(_e) => break,
                _ => (),
            }
        }

        Ok(credentials)
    }
}

/// Splits a Role attribute value into its role and provider ARN. Identity providers differ in which comes
/// first (authentik lists the role first), so the ARNs are told apart by their resource type.
fn parse_role_value(value: &str) -> Result<SamlAWSRole, SamlParseError> {
    let malformed = || SamlParseError::MalformedRole(value.to_string());

    let arns: Vec<&str> = value.split(',').map(str::trim).collect();
    if arns.len() != 2 {
        return Err(malformed());
    }

    let role_arn = arns.iter().find(|arn| arn.contains(":role/"));
    let principal_arn = arns.iter().find(|arn| arn.contains(":saml-provider/"));

    match (role_arn, principal_arn) {
        (Some(role_arn), Some(principal_arn)) => Ok(SamlAWSRole {
            role_arn: role_arn.to_string(),
            principal_arn: principal_arn.to_string(),
        }),
        _ => Err(malformed()),
    }
}

struct BaseSamlParser {
    raw: String,
    parsed: String,
}

impl BaseSamlParser {
    fn from_base64(response: &str) -> Result<BaseSamlParser, SamlParseError> {
        let response = response.trim();
        let base64 = engine::GeneralPurpose::new(&alphabet::STANDARD, engine::general_purpose::PAD);
        let decoded = String::from_utf8(base64.decode(response)?)?;

        Ok(BaseSamlParser {
            raw: response.to_string(),
            parsed: decoded,
        })
    }

    fn body(&self) -> String {
        self.parsed.clone()
    }

    fn raw(&self) -> String {
        self.raw.clone()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const ASSERTION_STS: &str = include_str!("../../testdata/assertion_sts.xml");
    const ASSERTION_SSO: &str = include_str!("../../testdata/assertion_sso.xml");

    pub(crate) fn base64_encode(xml: &str) -> String {
        engine::GeneralPurpose::new(&alphabet::STANDARD, engine::general_purpose::PAD).encode(xml)
    }

    /// The provider ARN first and the role ARN second (the order authentik does not use).
    const PROVIDER_FIRST_ROLES: &str = r#"<Response><Assertion><AttributeStatement>
        <Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
            <AttributeValue>arn:aws:iam::1:saml-provider/P,arn:aws:iam::1:role/A</AttributeValue>
            <AttributeValue>arn:aws:iam::2:saml-provider/P,arn:aws:iam::2:role/B</AttributeValue>
        </Attribute>
        <Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName">
            <AttributeValue>not,a,role</AttributeValue>
        </Attribute>
    </AttributeStatement></Assertion></Response>"#;

    #[test]
    fn sso_parser_reads_the_destination_and_the_raw_response() {
        let parser = AwsSsoSamlParser::from_base64(&base64_encode(ASSERTION_SSO)).unwrap();

        assert_eq!(
            parser.destination().unwrap(),
            "https://eu-central-1.signin.aws.amazon.com/platform/saml/acs/00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(parser.raw_saml_response(), base64_encode(ASSERTION_SSO));
    }

    #[test]
    fn sso_parser_reads_the_destination_from_base64() {
        let parser = AwsSsoSamlParser::from_base64(&base64_encode(ASSERTION_SSO)).unwrap();

        assert!(parser
            .destination()
            .unwrap()
            .starts_with("https://eu-central-1.signin.aws.amazon.com/platform/saml/acs/"));
    }

    #[test]
    fn sso_parser_fails_without_a_destination() {
        let parser =
            AwsSsoSamlParser::from_base64(&base64_encode("<Response><Assertion/></Response>"))
                .unwrap();
        assert_eq!(
            parser.destination().unwrap_err().to_string(),
            "destination not found"
        );

        // Malformed XML ends the scan the same way.
        let parser =
            AwsSsoSamlParser::from_base64(&base64_encode("<Response><a></b></Response>")).unwrap();
        assert_eq!(
            parser.destination().unwrap_err().to_string(),
            "destination not found"
        );
    }

    #[test]
    fn parser_reads_only_the_role_attribute() {
        let parser = AwsSamlParser::from_base64(&base64_encode(PROVIDER_FIRST_ROLES)).unwrap();
        let roles = parser.credentials().unwrap();

        assert_eq!(roles.len(), 2);
        assert_eq!(roles[0].role_arn, "arn:aws:iam::1:role/A");
        assert_eq!(roles[0].principal_arn, "arn:aws:iam::1:saml-provider/P");
        assert_eq!(roles[1].role_arn, "arn:aws:iam::2:role/B");
        assert_eq!(
            parser.raw_saml_response(),
            base64_encode(PROVIDER_FIRST_ROLES)
        );
    }

    #[test]
    fn parser_finds_every_role_of_an_authentik_assertion() {
        // authentik lists the role ARN first and the provider ARN second.
        let parser = AwsSamlParser::from_base64(&base64_encode(ASSERTION_STS)).unwrap();
        let roles = parser.credentials().unwrap();

        assert_eq!(roles.len(), 2);
        assert_eq!(
            roles[0].role_arn,
            "arn:aws:iam::111111111111:role/ExampleAdmin"
        );
        assert_eq!(
            roles[0].principal_arn,
            "arn:aws:iam::111111111111:saml-provider/EXAMPLEID"
        );
        assert_eq!(
            roles[1].role_arn,
            "arn:aws:iam::222222222222:role/ExampleReadOnly"
        );
    }

    #[test]
    fn roles_in_either_order_give_the_same_result() {
        let role = "arn:aws:iam::1:role/A";
        let provider = "arn:aws:iam::1:saml-provider/P";

        for value in [format!("{role},{provider}"), format!("{provider},{role}")] {
            let parsed = parse_role_value(&value).unwrap();
            assert_eq!(parsed.role_arn, role);
            assert_eq!(parsed.principal_arn, provider);
        }
    }

    #[test]
    fn malformed_role_values_are_errors_not_panics() {
        for value in [
            "",
            "arn:aws:iam::1:role/A",
            "arn:aws:iam::1:role/A,arn:aws:iam::1:role/B",
            "arn:aws:iam::1:saml-provider/P,arn:aws:iam::1:saml-provider/Q",
            "a,b",
            "arn:aws:iam::1:role/A,arn:aws:iam::1:saml-provider/P,extra",
        ] {
            let err = parse_role_value(value).err().unwrap();
            assert!(
                err.to_string().contains("malformed role attribute value"),
                "{value}: {err}"
            );
        }
    }

    #[test]
    fn a_malformed_role_in_the_assertion_fails_the_whole_parse() {
        let xml = r#"<Response><Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
            <AttributeValue>just-one-value</AttributeValue></Attribute></Response>"#;
        let parser = AwsSamlParser::from_base64(&base64_encode(xml)).unwrap();

        assert!(parser.credentials().is_err());
    }

    #[test]
    fn from_base64_keeps_the_raw_response_and_ignores_surrounding_whitespace() {
        let encoded = base64_encode(ASSERTION_STS);
        let parser = AwsSamlParser::from_base64(&format!("  {encoded}\n")).unwrap();

        assert_eq!(parser.raw_saml_response(), encoded);
    }

    #[test]
    fn from_base64_rejects_invalid_input() {
        assert!(AwsSamlParser::from_base64("***").is_err());
        assert!(AwsSsoSamlParser::from_base64("***").is_err());
    }

    #[test]
    fn the_autosubmit_url_is_the_destination_of_the_assertion() {
        // `SamlAssertion.destination` is the challenge url; it must agree with the XML.
        for (autosubmit, assertion) in [
            (
                include_str!("../../testdata/autosubmit_sts.json"),
                ASSERTION_STS,
            ),
            (
                include_str!("../../testdata/autosubmit_sso.json"),
                ASSERTION_SSO,
            ),
        ] {
            let challenge: serde_json::Value = serde_json::from_str(autosubmit).unwrap();
            let parser = AwsSsoSamlParser::from_base64(&base64_encode(assertion)).unwrap();

            assert_eq!(
                parser.destination().unwrap(),
                challenge["url"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn parser_finds_no_roles_in_an_identity_center_assertion() {
        let parser = AwsSamlParser::from_base64(&base64_encode(ASSERTION_SSO)).unwrap();

        assert!(parser.credentials().unwrap().is_empty());
    }

    #[test]
    fn parser_stops_at_malformed_xml() {
        let parser =
            AwsSamlParser::from_base64(&base64_encode("<Response><a></b></Response>")).unwrap();

        assert!(parser.credentials().unwrap().is_empty());
    }

    #[test]
    fn parsing_fails_for_invalid_base64() {
        assert!(AwsSamlParser::from_base64("***").is_err());
        assert!(AwsSsoSamlParser::from_base64("").is_ok_and(|p| p.destination().is_err()));
    }

    #[test]
    fn parsing_fails_for_non_utf8_content() {
        let invalid =
            engine::GeneralPurpose::new(&alphabet::STANDARD, engine::general_purpose::PAD)
                .encode([0xff, 0xfe, 0xfd]);

        assert!(AwsSamlParser::from_base64(&invalid).is_err());
    }
}
