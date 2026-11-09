use crate::domain::models::idp::IdpType;
use crate::domain::models::mfa::MfaSelection;
use crate::domain::models::settings::AwsAppType;

/// How a save treats an entry that may be there already.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SaveAs<K> {
    /// Add it, or update the one with the same key (what `c9s config ...` does).
    Upsert,
    /// Add it, refused when the key is taken.
    New,
    /// Replace the entry with this key, refused when it is gone. The new key may differ.
    Replace(K),
}

/// The key of an AWS app: its url and kind.
pub type AwsAppRef = (String, AwsAppType);

/// Which AWS app an [`AwsAppInput`] is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AwsAppKind {
    /// The AWS SAML application, with IAM roles.
    Aws,
    /// The AWS IAM Identity Center application, in a region.
    AwsSso { region: String },
}

impl AwsAppKind {
    pub(super) fn app_type(&self) -> AwsAppType {
        match self {
            AwsAppKind::Aws => AwsAppType::Aws,
            AwsAppKind::AwsSso { .. } => AwsAppType::AwsSso,
        }
    }
}

/// An identity provider to add, or to update when one has the same name.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IdpInput {
    pub name: String,
    pub idp_type: IdpType,
    pub url: String,
    pub username: String,
    pub mfa: Option<MfaSelection>,
}

impl IdpInput {
    pub fn new(
        name: impl Into<String>,
        idp_type: IdpType,
        url: impl Into<String>,
        username: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            idp_type,
            url: url.into(),
            username: username.into(),
            mfa: None,
        }
    }
}

/// An AWS app to add: the IAM role application, or with a region, the IAM Identity Center one.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AwsAppInput {
    pub app_url: String,
    /// The identity provider to log in with.
    pub idp: String,
    /// Overrides the username of the identity provider.
    pub username: Option<String>,
    /// Overrides the MFA selection of the identity provider.
    pub mfa: Option<MfaSelection>,
}

impl AwsAppInput {
    pub fn new(app_url: impl Into<String>, idp: impl Into<String>) -> Self {
        Self {
            app_url: app_url.into(),
            idp: idp.into(),
            username: None,
            mfa: None,
        }
    }
}

/// A Rancher to add, or to update when one has the same url.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RancherInput {
    pub url: String,
    pub client_id: String,
    pub idp: String,
    pub username: Option<String>,
    pub mfa: Option<MfaSelection>,
}

impl RancherInput {
    pub fn new(
        url: impl Into<String>,
        client_id: impl Into<String>,
        idp: impl Into<String>,
    ) -> Self {
        Self {
            url: url.into(),
            client_id: client_id.into(),
            idp: idp.into(),
            username: None,
            mfa: None,
        }
    }
}
