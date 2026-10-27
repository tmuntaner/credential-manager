//! Conversions between the models of this application and those of the `rancher` crate.

use crate::domain::models::mfa::MfaSelection;
use crate::domain::models::oidc::OidcError;
use crate::domain::models::rancher_credentials::RancherCredential;
use crate::domain::models::secret::SafeSecret;
use crate::domain::models::user_credentials::UserCredentials;
use crate::domain::ports::rancher::RancherError;

impl From<rancher::RancherCredential> for RancherCredential {
    fn from(c: rancher::RancherCredential) -> Self {
        RancherCredential {
            token: c.token,
            token_id: c.token_id,
            expiry: c.expiry,
            cluster_name: c.cluster_name,
            cluster_id: c.cluster_id,
            server_url: c.server_url,
            ca: c.ca,
        }
    }
}

impl From<&RancherCredential> for rancher::RancherCredential {
    fn from(c: &RancherCredential) -> Self {
        rancher::RancherCredential {
            token: c.token.clone(),
            token_id: c.token_id.clone(),
            expiry: c.expiry,
            cluster_name: c.cluster_name.clone(),
            cluster_id: c.cluster_id.clone(),
            server_url: c.server_url.clone(),
            ca: c.ca.clone(),
        }
    }
}

impl From<UserCredentials> for rancher::UserCredentials {
    fn from(c: UserCredentials) -> Self {
        rancher::UserCredentials::new(
            c.username,
            c.password.into_inner(),
            c.mfa.map(|mfa| match mfa {
                MfaSelection::WebAuthn => rancher::MfaMethod::WebAuthn,
                MfaSelection::Totp => rancher::MfaMethod::Totp,
            }),
        )
    }
}

impl From<rancher::UserCredentials> for UserCredentials {
    fn from(c: rancher::UserCredentials) -> Self {
        UserCredentials {
            username: c.username,
            password: SafeSecret::new(c.password),
            mfa: c.mfa.map(|mfa| match mfa {
                rancher::MfaMethod::WebAuthn => MfaSelection::WebAuthn,
                rancher::MfaMethod::Totp => MfaSelection::Totp,
            }),
        }
    }
}

/// A failed login at the identity provider is the `OidcError` of the application that went through the
/// crate, so it is handed back as it was.
impl From<rancher::RancherError> for RancherError {
    fn from(e: rancher::RancherError) -> Self {
        match e {
            rancher::RancherError::Authorize(rancher::OidcError::Failed(cause)) => {
                match cause.downcast::<OidcError>() {
                    Ok(oidc) => RancherError::Oidc(*oidc),
                    Err(cause) => RancherError::Failed(cause),
                }
            }
            e => RancherError::Failed(Box::new(e)),
        }
    }
}

impl From<rancher::RancherApiError> for RancherError {
    fn from(e: rancher::RancherApiError) -> Self {
        RancherError::Failed(Box::new(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_login_comes_back_as_the_oidc_error_of_the_application() {
        let cause =
            rancher::OidcError::Failed(Box::new(OidcError::Failed("wrong password".into())));

        let err = RancherError::from(rancher::RancherError::Authorize(cause));

        assert!(matches!(err, RancherError::Oidc(_)));
        assert_eq!(err.to_string(), "wrong password");
    }

    #[test]
    fn other_errors_keep_their_message() {
        let err = RancherError::from(rancher::RancherError::Api(
            rancher::RancherApiError::Unauthorized,
        ));

        assert!(matches!(err, RancherError::Failed(_)));
        assert_eq!(err.to_string(), "rancher rejected the token (401)");
    }
}
