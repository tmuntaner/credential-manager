use super::models::{Field, FieldError, SetupError};
use crate::domain::models::login::ResolveError;
use crate::domain::models::settings::SettingsError;
use crate::domain::services::settings_editor::{
    FieldProblem, InvalidField, Problem, SettingsEditError,
};

/// The form a change came from.
#[derive(Clone, Copy)]
pub(super) struct Form {
    name: Option<Field>,
    url: Option<Field>,
    username: Option<Field>,
    mfa: Option<Field>,
    client_id: Option<Field>,
    region: Option<Field>,
    idp: Option<Field>,
    /// The input that identifies the entry.
    key: Option<Field>,
    already_exists: fn(&str) -> String,
}

impl Form {
    pub(super) const IDP: Form = Form {
        name: Some(Field::IdpName),
        url: Some(Field::IdpUrl),
        username: Some(Field::IdpUsername),
        mfa: Some(Field::IdpMfa),
        client_id: None,
        region: None,
        idp: None,
        key: Some(Field::IdpName),
        already_exists: |key| {
            format!(
                "An identity provider called {key} exists already. Edit it, or choose another name."
            )
        },
    };

    pub(super) const AWS: Form = Form {
        name: None,
        url: Some(Field::AwsAppUrl),
        username: Some(Field::AwsUsername),
        mfa: Some(Field::AwsMfa),
        client_id: None,
        region: Some(Field::AwsRegion),
        idp: Some(Field::AwsIdp),
        key: Some(Field::AwsAppUrl),
        already_exists: |_| {
            "This application is set up already. Edit it in the list instead.".into()
        },
    };

    pub(super) const RANCHER: Form = Form {
        name: None,
        url: Some(Field::RancherUrl),
        username: Some(Field::RancherUsername),
        mfa: Some(Field::RancherMfa),
        client_id: Some(Field::RancherClientId),
        region: None,
        idp: Some(Field::RancherIdp),
        key: Some(Field::RancherUrl),
        already_exists: |_| "This Rancher is set up already. Edit it in the list instead.".into(),
    };

    /// Not a form, a button such as "Remove".
    pub(super) const ACTION: Form = Form {
        name: None,
        url: None,
        username: None,
        mfa: None,
        client_id: None,
        region: None,
        idp: None,
        key: None,
        already_exists: |key| format!("{key} exists already."),
    };

    /// The input that holds a value the domain refused.
    fn input_of(self, field: InvalidField) -> Option<Field> {
        // Every field is named, so a new `InvalidField` fails to compile here until the forms can place it.
        match field {
            InvalidField::Name => self.name,
            InvalidField::Url => self.url,
            InvalidField::Username => self.username,
            InvalidField::Mfa => self.mfa,
            InvalidField::ClientId => self.client_id,
            InvalidField::Region => self.region,
            InvalidField::Idp => self.idp,
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
    under(form.idp, unknown_idp_message(name))
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
        match form.input_of(field) {
            Some(field) => error.fields.push(FieldError { field, message }),
            None => general.push(message),
        }
    }
    if !general.is_empty() {
        error.message = Some(general.join(" "));
    }

    error
}

pub(super) fn edit_error(error: SettingsEditError, form: Form) -> SetupError {
    match error {
        SettingsEditError::Invalid(SettingsError::UnknownIdp(name)) => unknown_idp(form, &name),
        SettingsEditError::Invalid(_) => match form.url {
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
    under(form.key, (form.already_exists)(key))
}

fn count(n: usize) -> String {
    match n {
        1 => "1 application".to_string(),
        n => format!("{n} applications"),
    }
}
