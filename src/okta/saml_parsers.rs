use crate::aws::sts::SamlAWSRole;
use anyhow::{anyhow, Result};
use select::document::Document;
use select::predicate::Attr;
use sxd_document::parser;
use sxd_xpath::nodeset::Node;
use sxd_xpath::{Context, Factory};

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
        let package = parser::parse(body.as_str())?;
        let document = package.as_document();

        let xpath = Factory::new()
            .build("/saml2p:Response//@Destination")?
            .ok_or_else(|| anyhow!("could not build xpath"))?;
        let mut context = Context::new();
        context.set_namespace("saml2p", "urn:oasis:names:tc:SAML:2.0:protocol");
        let value = xpath.evaluate(&context, document.root())?;

        let saml_destination = match value {
            sxd_xpath::Value::Nodeset(ns) => ns
                .document_order()
                .into_iter()
                .map(|node| {
                    if let Node::Attribute(attr) = node {
                        Some(String::from(attr.value()))
                    } else {
                        None
                    }
                })
                .next()
                .ok_or_else(|| anyhow!("could not find destination in saml response"))?,
            _ => None,
        };

        let destination = saml_destination
            .ok_or_else(|| anyhow!("could not retrieve destination from saml response"))?;

        Ok(destination)
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
        let package = parser::parse(body.as_str())?;
        let document = package.as_document();

        let xpath = Factory::new()
            .build("//saml2:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/Role']/saml2:AttributeValue")?
            .ok_or_else(|| anyhow!("could not get xpath in SAMLResponse"))?;

        let mut context = Context::new();
        context.set_namespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");

        let value = xpath.evaluate(&context, document.root())?;

        let credentials = match value {
            sxd_xpath::Value::Nodeset(ns) => ns
                .iter()
                .map(|node| {
                    let value = node.string_value();
                    let split: Vec<&str> = value.split(',').collect();

                    SamlAWSRole {
                        role_arn: String::from(split[1]),
                        principal_arn: String::from(split[0]),
                    }
                })
                .collect(),
            _ => vec![],
        };

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
