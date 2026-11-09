//! Changes to the settings, and the validation that goes with them.
//!
//! A change is validated once, here: every field is checked and all the problems come back together, in form
//! order, as [`SettingsEditError::InvalidFields`], each naming its [`InvalidField`].
//!
//! Every driving adapter (the CLI, the GUI) edits the settings through here, so they accept and refuse the same
//! things. The `apply` functions change settings in memory; [`SettingsService`] is the one way to load, change and
//! save them: every change goes through it, every change to an app is login-checked, and
//! nothing is saved when a change is refused.

mod apply;
mod error;
pub mod fields;
mod import;
mod input;
mod service;
#[cfg(test)]
mod tests;
mod validate;

#[cfg(test)]
pub(crate) use apply::{apply_aws_app, apply_aws_sso_app, apply_idp};
pub use error::{FieldProblem, InvalidField, Problem, SettingsEditError};
pub use import::{ImportCounts, ImportMode, ImportReport};
pub use input::{AwsAppInput, AwsAppKind, AwsAppRef, IdpInput, RancherInput, SaveAs};
pub use service::SettingsService;
