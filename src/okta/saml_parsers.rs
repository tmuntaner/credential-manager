use crate::aws::sts::SamlAWSRole;
use anyhow::{anyhow, Result};
use quick_xml::events::Event;
use quick_xml::Reader;
use select::document::Document;
use select::predicate::Attr;

pub struct OktaAwsSsoSamlParser {
    saml_body: String,
    saml_raw: String,
}

impl OktaAwsSsoSamlParser {
    pub fn new(saml_body: String) -> Result<OktaAwsSsoSamlParser> {
        let saml_parser = BaseSamlParser::new(saml_body)?;

        Ok(OktaAwsSsoSamlParser {
            saml_raw: saml_parser.raw(),
            saml_body: saml_parser.body(),
        })
    }

    pub fn raw_saml_response(&self) -> String {
        self.saml_raw.clone()
    }

    pub fn destination(&self) -> Result<String> {
        let body = self.saml_body.clone();

        let mut reader = Reader::from_str(body.as_str());
        reader.trim_text(true);
        let mut buf = Vec::new();
        let mut ns_buffer = Vec::new();

        loop {
            match reader.read_namespaced_event(&mut buf, &mut ns_buffer) {
                Ok((_, Event::Start(e))) => {
                    if let b"Response" = e.local_name() {
                        for el in e.attributes() {
                            let e = el?;
                            let key = std::str::from_utf8(e.key)?;
                            let value = std::str::from_utf8(e.value.as_ref())?;
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

        Err(anyhow!("destination not found"))
    }
}

pub struct OktaAwsSamlParser {
    saml_body: String,
    saml_raw: String,
}

impl OktaAwsSamlParser {
    pub fn new(saml_body: String) -> Result<OktaAwsSamlParser> {
        let saml_parser = BaseSamlParser::new(saml_body)?;

        Ok(OktaAwsSamlParser {
            saml_raw: saml_parser.raw(),
            saml_body: saml_parser.body(),
        })
    }

    pub fn raw_saml_response(&self) -> String {
        self.saml_raw.clone()
    }

    pub fn credentials(&self) -> Result<Vec<SamlAWSRole>> {
        let body = self.saml_body.clone();

        let mut reader = Reader::from_str(body.as_str());
        reader.trim_text(true);
        let mut buf = Vec::new();
        let mut ns_buffer = Vec::new();

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
            match reader.read_namespaced_event(&mut buf, &mut ns_buffer) {
                Ok((_, Event::Start(e))) => match e.local_name() {
                    b"Attribute" => {
                        for el in e.attributes() {
                            let e = el?;
                            let key = std::str::from_utf8(e.key)?;
                            let value = std::str::from_utf8(e.value.as_ref())?;
                            if let ("Name", "https://aws.amazon.com/SAML/Attributes/Role") =
                                (key, value)
                            {
                                state = State::RoleAttributes;
                                break;
                            }
                        }
                    }
                    b"AttributeValue" => {
                        name = Name::AttributeValue;
                    }
                    _ => name = Name::Other,
                },
                Ok((_, Event::Text(e))) => {
                    if let (State::RoleAttributes, Name::AttributeValue) = (state, name) {
                        let value = e.unescape_and_decode(&reader).unwrap();
                        let split: Vec<&str> = value.split(',').collect();

                        credentials.push(SamlAWSRole {
                            role_arn: String::from(split[1]),
                            principal_arn: String::from(split[0]),
                        })
                    }
                }
                Ok((_, Event::End(e))) => {
                    if let b"Attribute" = e.local_name() {
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

struct BaseSamlParser {
    raw: String,
    parsed: String,
}

impl BaseSamlParser {
    fn new(body: String) -> Result<BaseSamlParser> {
        let document = Document::from(body.as_str());
        let node = document.find(Attr("name", "SAMLResponse")).next();

        if let Some(element) = node {
            let response: String = element
                .attr("value")
                .map(|value| value.parse())
                .ok_or_else(|| anyhow!("could not get SAMLResponse"))??;
            let decoded = String::from_utf8(base64::decode(response.clone())?)?;

            Ok(BaseSamlParser {
                raw: response,
                parsed: decoded,
            })
        } else {
            Err(anyhow!("could not get SAMLResponse"))
        }
    }

    fn body(&self) -> String {
        self.parsed.clone()
    }

    fn raw(&self) -> String {
        self.raw.clone()
    }
}
