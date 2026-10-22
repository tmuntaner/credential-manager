// Driving port: implemented by the domain, used by callers.
pub mod credential_issuer;
// Driven ports: used by the domain, implemented by adapters or by the host application.
pub mod oidc;
pub mod rancher_api;
