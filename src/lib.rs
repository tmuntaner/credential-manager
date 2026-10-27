//! Credential issuing for c9s.
//!
//! - [`domain`]: models, ports and services; knows nothing of HTTP, the keyring or the terminal.
//! - [`outbound`]: adapters of the driven ports.
//!
//! The `c9s` binary is the composition root and the only driving adapter.

pub mod domain;
pub mod outbound;
