//! Credentials for downstream rancher clusters.
//!
//! Entry points:
//! - [`RancherCredentialService`] generates a credential through [`IssueCredential`].
//! - Implement [`OidcAuthorizer`] to log in with oidc.
//!   Create an adapter of the [`RancherApi`] port, e.g., as [`RancherApiClient`].
//! - [`kubeconfig`] and [`exec_credential`] render credentials for kubectl.

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
