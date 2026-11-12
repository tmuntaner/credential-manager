//! Composition helpers shared by the driving adapters (the CLI, the GUI).
//!
//! The use cases need the secret stores, the password and the cache wired to the real adapters. Doing that in
//! each binary would duplicate it, so it lives here. A caller still chooses its own prompts and notifier.
//!
//! [`settings`] and [`prompts`] are the toolkit-neutral logic of the desktop apps: the settings page (forms,
//! validation, the dry run of a login) and the bridge that carries a flow's questions to a window.

pub mod credentials;
pub mod prompts;
pub mod secrets;
pub mod settings;
