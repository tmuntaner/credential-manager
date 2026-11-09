use crate::domain::models::login::ResolveError;
use crate::domain::models::settings::SettingsError;
use crate::domain::ports::config::ConfigError;
use thiserror::Error;

/// The value of a change that failed the checks of `fields`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidField {
    Name,
    Url,
    Username,
    /// The second step (MFA) the sign in uses.
    Mfa,
    ClientId,
    Region,
    /// The identity provider an app logs in with.
    Idp,
}

/// What is wrong with a field.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Problem {
    /// A sentence that says what to change.
    Message(String),
    /// The identity provider is not configured (it keeps its own wording).
    UnknownIdp(String),
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Problem::Message(message) => f.write_str(message),
            Problem::UnknownIdp(name) => {
                write!(f, "{}", SettingsError::UnknownIdp(name.clone()))
            }
        }
    }
}

/// A field of a change and what is wrong with it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FieldProblem {
    pub field: InvalidField,
    pub problem: Problem,
}

impl FieldProblem {
    pub(super) fn message(field: InvalidField, message: String) -> Self {
        Self {
            field,
            problem: Problem::Message(message),
        }
    }
}

impl std::fmt::Display for FieldProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.problem.fmt(f)
    }
}

fn join_problems(problems: &[FieldProblem]) -> String {
    problems
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Why the settings were not changed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SettingsEditError {
    /// A value is not valid.
    #[error(transparent)]
    Invalid(#[from] SettingsError),

    /// Values do not pass the checks of the settings (an `http` web address, a bad region, ...). Every problem
    /// of the change, in form order. Never empty.
    #[error("{}", join_problems(.0))]
    InvalidFields(Vec<FieldProblem>),

    /// An identity provider that apps still log in with cannot be removed.
    #[error(
        "the identity provider \"{name}\" is still used by {}, change or remove those first",
        used_by.join(", ")
    )]
    IdpInUse { name: String, used_by: Vec<String> },

    /// There is no app or Rancher at this url.
    #[error("nothing is configured at {0}")]
    UnknownApp(String),

    /// A username is necessary for an idp.
    #[error("enter the user name for the identity provider \"{0}\"")]
    UsernameNeeded(String),

    /// What was meant as new is there already, at this name or url.
    #[error("{key} is set up already")]
    AlreadyExists { key: String },

    /// What was meant to be changed is no longer in the settings.
    #[error("this entry is no longer in the settings, it may have been changed elsewhere")]
    Gone,

    /// The change would stop apps that sign in now from signing in.
    #[error("this change would stop these from signing in: {}", urls.join(", "))]
    WouldBreak { urls: Vec<String> },

    /// What was set up cannot be used to sign in.
    #[error("these settings cannot be used to sign in: {0}")]
    DoesNotResolve(ResolveError),

    /// The settings could not be read or written.
    #[error("the settings could not be read or written: {0}")]
    Store(#[from] ConfigError),
}
