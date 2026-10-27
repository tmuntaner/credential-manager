use crate::domain::models::mfa::MfaSelection;
use crate::domain::models::oidc::OidcError;
use crate::domain::models::saml::{SamlAssertion, SamlLoginError};
use crate::domain::models::user_credentials::UserCredentials;
use crate::domain::ports::webauthn::WebauthnAssertion;

impl From<UserCredentials> for authentik::UserCredentials {
    fn from(c: UserCredentials) -> Self {
        authentik::UserCredentials::new(
            c.username,
            authentik::Password::new(c.password.into_inner()),
            c.mfa.map(|mfa| match mfa {
                MfaSelection::WebAuthn => authentik::MfaMethod::WebAuthn,
                MfaSelection::Totp => authentik::MfaMethod::Totp,
            }),
        )
    }
}

impl From<authentik::SamlAssertion> for SamlAssertion {
    fn from(a: authentik::SamlAssertion) -> Self {
        SamlAssertion {
            saml_response: a.saml_response,
            destination: a.destination,
            relay_state: a.relay_state,
        }
    }
}

impl From<WebauthnAssertion> for authentik::WebauthnAssertion {
    fn from(value: WebauthnAssertion) -> Self {
        Self {
            credential_id: value.credential_id,
            client_data_json: value.client_data_json,
            authenticator_data: value.authenticator_data,
            signature: value.signature,
        }
    }
}

impl From<authentik::AuthentikError> for SamlLoginError {
    fn from(e: authentik::AuthentikError) -> Self {
        SamlLoginError::Failed(Box::new(e))
    }
}

impl From<authentik::AuthentikError> for OidcError {
    fn from(e: authentik::AuthentikError) -> Self {
        OidcError::Failed(Box::new(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::secret::SafeSecret;

    #[test]
    fn keeps_the_mfa_selection() {
        let login = UserCredentials {
            username: "user".to_string(),
            password: SafeSecret::new("secret"),
            mfa: Some(MfaSelection::Totp),
        };

        let login = authentik::UserCredentials::from(login);

        assert_eq!(login.username, "user");
        assert_eq!(login.password.as_str(), "secret");
        assert_eq!(login.mfa, Some(authentik::MfaMethod::Totp));
    }

    #[test]
    fn errors_keep_their_message() {
        let err = SamlLoginError::from(authentik::AuthentikError::OidcStateMismatch);

        assert_eq!(
            err.to_string(),
            "the state of the authorization response does not match the request"
        );
    }
}
