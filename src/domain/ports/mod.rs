// Driving ports: implemented by the domain, used by callers.
pub mod aws;
pub mod config;
pub mod login;
pub mod rancher;

// Driven ports: used by the domain, implemented by adapters or by the host.
pub mod notifier;
pub mod secret_store;
pub mod secret_wrapper;
pub mod user_interaction;
pub mod webauthn;
