use crate::app::settings::Field;
use crate::domain::services::settings_editor::InvalidField;

/// The form a change came from.
#[derive(Clone, Copy)]
pub(super) struct Form {
    pub name: Option<Field>,
    pub url: Option<Field>,
    pub username: Option<Field>,
    pub mfa: Option<Field>,
    pub client_id: Option<Field>,
    pub region: Option<Field>,
    pub idp: Option<Field>,
    /// The input that identifies the entry.
    pub key: Option<Field>,
    pub already_exists: fn(&str) -> String,
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
    pub fn input_of(self, field: InvalidField) -> Option<Field> {
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
