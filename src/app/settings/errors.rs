use super::models::{Field, FieldError, SetupError};
use crate::domain::models::login::ResolveError;
use crate::domain::models::settings::SettingsError;
use crate::domain::services::settings_editor::{
    FieldProblem, InvalidField, Problem, SettingsEditError,
};

/// The form a change came from.
#[derive(Clone, Copy)]
pub(super) enum Form {
    Idp,
    Aws,
    Rancher,
    /// Not a form, a button such as "Remove".
    Action,
}

impl Form {
    /// Returns the URL field if the form has one.
    fn url(self) -> Option<Field> {
        match self {
            Form::Idp => Some(Field::IdpUrl),
            Form::Aws => Some(Field::AwsAppUrl),
            Form::Rancher => Some(Field::RancherUrl),
            Form::Action => None,
        }
    }

    /// Returns the field that identifies the entry.
    fn key(self) -> Option<Field> {
        match self {
            Form::Idp => Some(Field::IdpName),
            Form::Aws => Some(Field::AwsAppUrl),
            Form::Rancher => Some(Field::RancherUrl),
            Form::Action => None,
        }
    }

    /// Returns the field of the form that holds a value the domain refused.
    fn invalid_field(self, field: InvalidField) -> Option<Field> {
        // Every pair is named, so a new `InvalidField` fails to compile here until a form decides where it goes.
        match self {
            Form::Idp => match field {
                InvalidField::Name => Some(Field::IdpName),
                InvalidField::Url => Some(Field::IdpUrl),
                InvalidField::Username => Some(Field::IdpUsername),
                InvalidField::ClientId | InvalidField::Region | InvalidField::Idp => None,
            },
            Form::Aws => match field {
                InvalidField::Url => Some(Field::AwsAppUrl),
                InvalidField::Username => Some(Field::AwsUsername),
                InvalidField::Region => Some(Field::AwsRegion),
                InvalidField::Idp => Some(Field::AwsIdp),
                InvalidField::Name | InvalidField::ClientId => None,
            },
            Form::Rancher => match field {
                InvalidField::Url => Some(Field::RancherUrl),
                InvalidField::Username => Some(Field::RancherUsername),
                InvalidField::ClientId => Some(Field::RancherClientId),
                InvalidField::Idp => Some(Field::RancherIdp),
                InvalidField::Name | InvalidField::Region => None,
            },
            Form::Action => match field {
                InvalidField::Name
                | InvalidField::Url
                | InvalidField::Username
                | InvalidField::ClientId
                | InvalidField::Region
                | InvalidField::Idp => None,
            },
        }
    }

    /// Returns the field for the idp.
    fn idp(self) -> Option<Field> {
        match self {
            Form::Aws => Some(Field::AwsIdp),
            Form::Rancher => Some(Field::RancherIdp),
            Form::Idp | Form::Action => None,
        }
    }
}

fn gone() -> SetupError {
    SetupError::general(
        "This entry is no longer in the settings. It may have been changed elsewhere. Close the form and try again.",
    )
}

fn resolve_error(error: ResolveError, form: Form) -> SetupError {
    match error {
        ResolveError::Settings(SettingsError::UnknownIdp(name)) => unknown_idp(form, &name),
        other => SetupError::general(format!(
            "These settings cannot be used to sign in: {other}."
        )),
    }
}

fn under(field: Option<Field>, message: impl Into<String>) -> SetupError {
    match field {
        Some(field) => SetupError::field(field, message),
        None => SetupError::general(message),
    }
}

fn unknown_idp_message(name: &str) -> String {
    format!("There is no identity provider called {name}. Choose another one.")
}

fn unknown_idp(form: Form, name: &str) -> SetupError {
    under(form.idp(), unknown_idp_message(name))
}

/// One error per problem the form has a field for; the others are told in general.
fn field_problems(form: Form, problems: Vec<FieldProblem>) -> SetupError {
    let mut error = SetupError::default();
    let mut general = Vec::new();
    for FieldProblem { field, problem } in problems {
        let message = match problem {
            Problem::Message(message) => message,
            Problem::UnknownIdp(name) => unknown_idp_message(&name),
        };
        match form.invalid_field(field) {
            Some(field) => error.fields.push(FieldError { field, message }),
            None => general.push(message),
        }
    }
    if !general.is_empty() {
        error.message = Some(general.join(" "));
    }

    error
}

/// The error of a form that has a problem of its own (`message` under `field`, the platform cannot do what was
/// chosen) next to what the domain found (`domain`). The own problem comes before the identity provider's, so the
/// order stays that of the form: url, region, username, mfa, idp.
pub(super) fn with_mfa(
    form: Form,
    field: Field,
    message: String,
    domain: Result<(), SettingsEditError>,
) -> SetupError {
    let mut error = match domain {
        Ok(()) => SetupError::default(),
        Err(e) => edit_error(e, form),
    };
    let own = FieldError { field, message };
    let at = error
        .fields
        .iter()
        .position(|f| Some(f.field) == form.idp())
        .unwrap_or(error.fields.len());
    error.fields.insert(at, own);

    error
}

pub(super) fn edit_error(error: SettingsEditError, form: Form) -> SetupError {
    match error {
        SettingsEditError::Invalid(SettingsError::UnknownIdp(name)) => unknown_idp(form, &name),
        SettingsEditError::Invalid(_) => match form.url() {
            Some(field) => SetupError::field(field, "This web address cannot be used."),
            None => SetupError::general("A web address is not valid."),
        },
        SettingsEditError::InvalidFields(problems) => field_problems(form, problems),
        SettingsEditError::IdpInUse { name, used_by } => SetupError::general(format!(
            "{name} cannot be removed: {} still sign{} in with it ({}). Choose another identity provider for {}, or remove {} first.",
            count(used_by.len()),
            if used_by.len() == 1 { "s" } else { "" },
            used_by.join(", "),
            if used_by.len() == 1 { "it" } else { "them" },
            if used_by.len() == 1 { "it" } else { "them" },
        )),
        SettingsEditError::UsernameNeeded(idp) => SetupError::general(format!(
            "Enter the username to sign in with at {idp}."
        )),
        SettingsEditError::UnknownApp(_) | SettingsEditError::Gone => gone(),
        SettingsEditError::AlreadyExists { key } => already_exists(form, &key),
        SettingsEditError::WouldBreak { urls } => SetupError::general(format!(
            "This change would stop these from signing in: {}. Nothing was saved.",
            urls.join(", ")
        )),
        SettingsEditError::DoesNotResolve(error) => resolve_error(error, form),
        SettingsEditError::Store(cause) => SetupError::general(format!(
            "The settings file could not be read or written ({cause}). Check that you can write to your config folder."
        )),
    }
}

fn already_exists(form: Form, key: &str) -> SetupError {
    let message = match form {
        Form::Idp => format!(
            "An identity provider called {key} exists already. Edit it, or choose another name."
        ),
        Form::Aws => "This application is set up already. Edit it in the list instead.".into(),
        Form::Rancher => "This Rancher is set up already. Edit it in the list instead.".into(),
        Form::Action => format!("{key} exists already."),
    };

    under(form.key(), message)
}

fn count(n: usize) -> String {
    match n {
        1 => "1 application".to_string(),
        n => format!("{n} applications"),
    }
}
