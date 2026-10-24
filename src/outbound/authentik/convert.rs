use crate::domain::models::oidc::OidcError;
use crate::domain::models::saml::{SamlAssertion, SamlLoginError};
use crate::domain::models::user_credentials::UserCredentials;
use base::models::mfa::MfaSelection;

impl From<UserCredentials> for authentik::UserCredentials {
    fn from(c: UserCredentials) -> Self {
        authentik::UserCredentials::new(
            c.username,
            authentik::Password::new(c.password),
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

pub fn assertion(a: webauthn::WebauthnAssertion) -> authentik::WebauthnAssertion {
    authentik::WebauthnAssertion {
        credential_id: a.credential_id,
        client_data_json: a.client_data_json,
        authenticator_data: a.authenticator_data,
        signature: a.signature,
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

    #[test]
    fn keeps_the_mfa_selection() {
        let login = UserCredentials {
            username: "user".to_string(),
            password: "secret".to_string(),
            mfa: Some(MfaSelection::Totp),
        };

        let login = authentik::UserCredentials::from(login);

        assert_eq!(login.username, "user");
        assert_eq!(login.password.as_str(), "secret");
        assert_eq!(login.mfa, Some(authentik::MfaMethod::Totp));
    }

    #[test]
    fn keeps_every_part_of_the_signature() {
        let signed = assertion(webauthn::WebauthnAssertion {
            credential_id: vec![1],
            client_data_json: vec![2],
            authenticator_data: vec![3],
            signature: vec![4],
        });

        assert_eq!(signed.credential_id, vec![1]);
        assert_eq!(signed.client_data_json, vec![2]);
        assert_eq!(signed.authenticator_data, vec![3]);
        assert_eq!(signed.signature, vec![4]);
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
