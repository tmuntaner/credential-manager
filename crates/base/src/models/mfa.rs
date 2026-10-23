use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("invalid MFA selection")]
pub struct MfaSelectionError;

/// The MFA method to log in with. It is parsed once, so a value of this type is always a known method.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum MfaSelection {
    WebAuthn,
    Totp,
}

impl FromStr for MfaSelection {
    type Err = MfaSelectionError;

    /// Case-insensitive.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "webauthn" => Ok(MfaSelection::WebAuthn),
            "totp" => Ok(MfaSelection::Totp),
            _ => Err(MfaSelectionError),
        }
    }
}

impl fmt::Display for MfaSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MfaSelection::WebAuthn => write!(f, "webauthn"),
            MfaSelection::Totp => write!(f, "totp"),
        }
    }
}

impl TryFrom<String> for MfaSelection {
    type Error = MfaSelectionError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<MfaSelection> for String {
    fn from(selection: MfaSelection) -> Self {
        selection.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_is_case_insensitive() {
        assert_eq!(
            "WebAuthn".parse::<MfaSelection>().unwrap(),
            MfaSelection::WebAuthn
        );
        assert_eq!("TOTP".parse::<MfaSelection>().unwrap(), MfaSelection::Totp);
    }

    #[test]
    fn unknown_methods_are_errors() {
        for method in ["push", "sms", ""] {
            let err = method.parse::<MfaSelection>().unwrap_err();
            assert_eq!(err.to_string(), "invalid MFA selection", "{}", method);
        }
    }

    #[test]
    fn displays_what_it_parses() {
        for selection in [MfaSelection::WebAuthn, MfaSelection::Totp] {
            assert_eq!(
                selection.to_string().parse::<MfaSelection>().unwrap(),
                selection
            );
        }
    }

    #[test]
    fn serializes_as_a_lowercase_string() {
        #[derive(Serialize, Deserialize)]
        struct Holder {
            mfa: MfaSelection,
        }

        let toml = toml::to_string(&Holder {
            mfa: MfaSelection::WebAuthn,
        })
        .unwrap();
        assert_eq!(toml.trim(), r#"mfa = "webauthn""#);

        let holder: Holder = toml::from_str(r#"mfa = "TOTP""#).unwrap();
        assert_eq!(holder.mfa, MfaSelection::Totp);
        assert!(toml::from_str::<Holder>(r#"mfa = "sms""#).is_err());
    }
}
