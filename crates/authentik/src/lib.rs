//! Logs users in to the applications of an authentik instance by running its flows, without a browser.
//!
//! Entry points:
//! - [`AuthentikService::saml_assertion`] logs in to a SAML application and returns its [`SamlAssertion`].
//! - [`AuthentikService::oidc_code`] runs the authorization code flow of an OIDC application and returns the
//!   [`AuthCode`].
//!
//! Build the service with adapters of its ports:
//! - [`FlowExecutor`]: [`HttpFlowExecutor`] runs the flows against authentik.
//! - [`StateSource`]: [`RandomState`] makes the OAuth state.
//! - [`Authenticator`] answers the second factor; implement it to ask the user and to sign with a security key.

mod domain;
mod outbound;

pub use domain::models::{
    mfa::{
        MfaChallenge, MfaDevice, MfaMethod, MfaResponse, WebauthnAssertion, WebauthnOptions,
        WebauthnRequest,
    },
    oidc::AuthCode,
    saml::SamlAssertion,
    secret::{Password, TotpCode},
    user_credentials::UserCredentials,
};
pub use domain::ports::authenticator::{Authenticator, AuthenticatorError};
pub use domain::ports::flow::{FlowError, FlowExecutor, MfaError, SecondFactor};
pub use domain::ports::state::{StateError, StateSource};
pub use domain::services::login::{AuthentikError, AuthentikService};
pub use outbound::flow::HttpFlowExecutor;
pub use outbound::random::RandomState;
