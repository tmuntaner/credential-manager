use thiserror::Error;

#[derive(Debug, Error)]
pub enum MfaSelectionError {
    #[error("invalid MFA selection")]
    Invalid,
}

#[derive(Copy, Clone)]
pub enum MfaSelection {
    WebAuthn,
    Totp,
    Invalid,
}

impl MfaSelection {
    pub fn from_string(s: String) -> Self {
        match s.to_lowercase().as_str() {
            "webauthn" => MfaSelection::WebAuthn,
            "totp" => MfaSelection::Totp,
            _ => MfaSelection::Invalid,
        }
    }

    pub fn validate(mfa_option: Option<String>) -> Result<(), MfaSelectionError> {
        if let Some(mfa) = mfa_option {
            let selection = MfaSelection::from_string(mfa);
            match selection {
                MfaSelection::Invalid => Err(MfaSelectionError::Invalid),
                _ => Ok(()),
            }
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_string_is_case_insensitive() {
        assert!(matches!(
            MfaSelection::from_string("WebAuthn".to_string()),
            MfaSelection::WebAuthn
        ));
        assert!(matches!(
            MfaSelection::from_string("TOTP".to_string()),
            MfaSelection::Totp
        ));
    }

    #[test]
    fn okta_and_unknown_methods_are_invalid() {
        for method in ["push", "oktapush", "sms", ""] {
            assert!(
                matches!(
                    MfaSelection::from_string(method.to_string()),
                    MfaSelection::Invalid
                ),
                "{}",
                method
            );
        }
    }

    #[test]
    fn validate_accepts_known_selections_and_none() {
        assert!(MfaSelection::validate(None).is_ok());
        assert!(MfaSelection::validate(Some("totp".to_string())).is_ok());
    }

    #[test]
    fn validate_rejects_unknown_selections() {
        let err = MfaSelection::validate(Some("carrier-pigeon".to_string())).unwrap_err();
        assert_eq!(err.to_string(), "invalid MFA selection");
    }
}
