use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ChallengeError {
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("challenge has no component: {0}")]
    NoComponent(Value),

    #[error("redirect challenge has no `to`: {0}")]
    NoRedirectTarget(Value),
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ErrorDetail {
    pub string: String,
    pub code: String,
}

/// sorted by key so the order is stable
pub type ResponseErrors = BTreeMap<String, Vec<ErrorDetail>>;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceChallenge {
    pub device_class: String,
    pub device_uid: String,
    #[serde(default)]
    pub challenge: Value,
    #[serde(default)]
    pub last_used: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValidateChallenge {
    #[serde(default)]
    pub device_challenges: Vec<DeviceChallenge>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AutosubmitChallenge {
    pub url: String,
    #[serde(default)]
    pub attrs: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub enum Challenge {
    Identification,
    Password,
    Validate(ValidateChallenge),
    Autosubmit(AutosubmitChallenge),
    Redirect { to: String },
    AccessDenied { error_message: Option<String> },
    Unexpected { component: String },
}

impl Challenge {
    pub fn parse(value: &Value) -> Result<Challenge, ChallengeError> {
        let component = value
            .get("component")
            .and_then(Value::as_str)
            .ok_or_else(|| ChallengeError::NoComponent(value.clone()))?;

        Ok(match component {
            "ak-stage-identification" => Challenge::Identification,
            "ak-stage-password" => Challenge::Password,
            "ak-stage-authenticator-validate" => {
                Challenge::Validate(serde_json::from_value(value.clone())?)
            }
            "ak-stage-autosubmit" => Challenge::Autosubmit(serde_json::from_value(value.clone())?),
            "xak-flow-redirect" => Challenge::Redirect {
                to: value
                    .get("to")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ChallengeError::NoRedirectTarget(value.clone()))?
                    .to_string(),
            },
            "ak-stage-access-denied" => Challenge::AccessDenied {
                error_message: value
                    .get("error_message")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            },
            other => Challenge::Unexpected {
                component: other.to_string(),
            },
        })
    }
}

pub fn rejection(errors: &ResponseErrors) -> String {
    errors
        .iter()
        .flat_map(|(field, details)| {
            details.iter().map(move |detail| {
                if field == "non_field_errors" {
                    detail.string.clone()
                } else {
                    format!("{field}: {}", detail.string)
                }
            })
        })
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn rejection_of(challenge: &Value) -> Option<String> {
    let errors = challenge.get("response_errors")?;
    match serde_json::from_value::<ResponseErrors>(errors.clone()) {
        Ok(errors) if errors.is_empty() => None,
        Ok(errors) => Some(rejection(&errors)),
        Err(_) if errors.is_null() => None,
        Err(_) => Some(errors.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD_REJECTED: &str = include_str!("../../../testdata/password_rejected.json");
    const VALIDATE: &str = include_str!("../../../testdata/validate_totp_webauthn.json");
    const VALIDATE_EMPTY: &str = include_str!("../../../testdata/validate_empty_response.json");
    const REDIRECT: &str = include_str!("../../../testdata/redirect.json");
    const AUTOSUBMIT: &str = include_str!("../../../testdata/autosubmit_sts.json");

    fn parse(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn rejection_formats_fields_sorted_and_non_field_errors_unprefixed() {
        let errors: ResponseErrors = serde_json::from_value(serde_json::json!({
            "password": [{"string": "Invalid password", "code": "invalid"}],
            "non_field_errors": [{"string": "Denied", "code": "invalid"}],
            "code": [{"string": "Too short", "code": "min_length"}, {"string": "Not digits", "code": "invalid"}],
        }))
        .unwrap();

        assert_eq!(
            rejection(&errors),
            "code: Too short; code: Not digits; Denied; password: Invalid password"
        );
    }

    #[test]
    fn rejection_of_reads_the_captured_wrong_password() {
        let value = parse(PASSWORD_REJECTED);
        assert_eq!(
            rejection_of(&value).as_deref(),
            Some("password: Invalid password")
        );
        assert!(matches!(
            Challenge::parse(&value).unwrap(),
            Challenge::Password
        ));
    }

    #[test]
    fn rejection_of_is_none_without_errors() {
        assert_eq!(rejection_of(&parse(VALIDATE)), None);
        assert_eq!(
            rejection_of(&serde_json::json!({"response_errors": {}})),
            None
        );
    }

    #[test]
    fn selection_acknowledgement_is_reported_as_an_error() {
        // The browser's device selection round trip; handlers must tolerate it.
        assert_eq!(
            rejection_of(&parse(VALIDATE_EMPTY)).as_deref(),
            Some("Empty response")
        );
    }

    #[test]
    fn parses_the_captured_validate_challenge() {
        let Challenge::Validate(validate) = Challenge::parse(&parse(VALIDATE)).unwrap() else {
            panic!("expected a validate challenge");
        };

        assert_eq!(validate.device_challenges.len(), 2);
        assert_eq!(validate.device_challenges[0].device_class, "totp");
        let webauthn = &validate.device_challenges[1];
        assert_eq!(webauthn.device_class, "webauthn");
        assert_eq!(webauthn.challenge["userVerification"], "preferred");
        assert_eq!(
            webauthn.challenge["allowCredentials"]
                .as_array()
                .unwrap()
                .len(),
            6
        );
    }

    #[test]
    fn parses_redirect_and_autosubmit() {
        let Challenge::Redirect { to } = Challenge::parse(&parse(REDIRECT)).unwrap() else {
            panic!("expected a redirect");
        };
        assert_eq!(to, "/");

        let Challenge::Autosubmit(auto) = Challenge::parse(&parse(AUTOSUBMIT)).unwrap() else {
            panic!("expected an autosubmit");
        };
        assert_eq!(auto.url, "https://signin.aws.amazon.com/saml");
        assert!(auto.attrs.contains_key("SAMLResponse"));
        assert!(!auto.attrs.contains_key("RelayState"));
    }

    #[test]
    fn unknown_components_are_unexpected() {
        let value = serde_json::json!({"component": "ak-stage-consent"});
        assert!(matches!(
            Challenge::parse(&value).unwrap(),
            Challenge::Unexpected { component } if component == "ak-stage-consent"
        ));
        assert!(Challenge::parse(&serde_json::json!({})).is_err());
    }

    #[test]
    fn parses_access_denied_with_and_without_a_message() {
        let Challenge::AccessDenied { error_message } = Challenge::parse(&serde_json::json!({
            "component": "ak-stage-access-denied",
            "error_message": "Not allowed"
        }))
        .unwrap() else {
            panic!("expected access denied");
        };
        assert_eq!(error_message.as_deref(), Some("Not allowed"));

        let Challenge::AccessDenied { error_message } =
            Challenge::parse(&serde_json::json!({"component": "ak-stage-access-denied"})).unwrap()
        else {
            panic!("expected access denied");
        };
        assert_eq!(error_message, None);
    }

    #[test]
    fn a_redirect_without_a_target_is_an_error() {
        let value = serde_json::json!({"component": "xak-flow-redirect"});
        assert!(Challenge::parse(&value).is_err());
    }

    #[test]
    fn rejection_of_handles_unexpected_error_shapes() {
        assert_eq!(
            rejection_of(&serde_json::json!({"response_errors": null})),
            None
        );
        assert_eq!(rejection_of(&serde_json::json!({})), None);
        assert_eq!(
            rejection_of(&serde_json::json!({"response_errors": "oops"})).as_deref(),
            Some("\"oops\"")
        );
    }
}
