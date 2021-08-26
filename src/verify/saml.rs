use crate::aws::sts::SamlAWSRole;
use select::document::Document;
use select::predicate::Attr;
use sxd_document::parser;
use sxd_xpath::{Context, Factory};

pub struct SamlResponse {
    pub raw: String,
}

impl SamlResponse {
    pub fn new(body: String) -> Option<SamlResponse> {
        let document = Document::from(body.as_str());
        let node = document.find(Attr("name", "SAMLResponse")).next();

        if let Some(element) = node {
            element.attr("value").map(|value| SamlResponse {
                raw: value.parse().unwrap(),
            })
        } else {
            None
        }
    }
    fn decode_response(&self) -> String {
        String::from_utf8(base64::decode(self.raw.clone()).unwrap()).unwrap()
    }

    pub fn credentials(&self) -> Vec<SamlAWSRole> {
        let response = self.decode_response();
        let package = parser::parse(response.as_str()).unwrap();
        let document = package.as_document();

        let xpath = Factory::new()
            .build("//saml2:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/Role']/saml2:AttributeValue").unwrap().unwrap();

        let mut context = Context::new();
        context.set_namespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");

        match xpath.evaluate(&context, document.root()).unwrap() {
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
        }
    }
}
