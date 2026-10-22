//! Credentials for clusters behind a Rancher that uses an OIDC provider for logins.
//!
//! Entry points:
//! - [`RancherCredentialService`] issues a credential through [`IssueCredential`]; build it with an
//!   adapter of the [`RancherApi`] port, such as [`RancherApiClient`].
//! - [`kubeconfig`] and [`exec_credential`] render a credential for kubectl.
//! - Implement [`OidcAuthorizer`] to supply the login at the identity provider.

mod domain;
mod outbound;
mod render;

pub use domain::models::{
    mfa::MfaMethod,
    rancher_credentials::RancherCredential,
    session::{AuthCode, SessionToken},
    user_credentials::UserCredentials,
};
pub use domain::ports::credential_issuer::{IssueCredential, RancherError};
pub use domain::ports::oidc::{OidcAuthorizer, OidcError};
pub use domain::ports::rancher_api::{ApiToken, Cluster, RancherApi, RancherApiError};
pub use domain::services::credentials::RancherCredentialService;
pub use outbound::api::RancherApiClient;
pub use render::{exec_credential, kubeconfig};
