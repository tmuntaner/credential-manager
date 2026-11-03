//! Credential issuing for c9s.
//!
//! - [`domain`]: models, ports and services; knows nothing of HTTP, the keyring or the terminal.
//! - [`outbound`]: adapters of the driven ports.
//!
//! - [`app`]: composition helpers shared by the driving adapters, so the CLI and the GUI call the same use cases.
//!
//! The `c9s` binary is the composition root of the CLI; other driving adapters (the GUI) bring their own prompts.

pub mod app;
pub mod domain;
pub mod outbound;
