//! What the login resolver is asked, and what it answers.

use crate::domain::models::idp::IdpType;
use crate::domain::models::mfa::MfaSelection;
use crate::domain::models::settings::{AwsAppType, SettingsError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error(transparent)]
    Settings(#[from] SettingsError),

    #[error("please supply an app-url")]
    NoAppUrl,

    #[error("please supply a region")]
    NoRegion,

    #[error("the app-url is configured as both app types, please supply an app-type")]
    AppUrlInBothTypes,

    #[error("both app types are configured, please supply an app-type or an app-url")]
    BothTypesConfigured,

    #[error("the app-url is not configured, please supply an app-type")]
    AppUrlNotConfigured,

    #[error("rancher is not configured, run `c9s config rancher`")]
    RancherNotConfigured,
}

/// An app in the setting by its identifiers (urls and possible other fields like type)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginTarget {
    Aws {
        app_url: String,
        app_type: AwsAppType,
    },
    Rancher {
        url: String,
    },
}

impl LoginTarget {
    /// The url of the app within the identity provider.
    pub fn url(&self) -> &str {
        match self {
            LoginTarget::Aws { app_url, .. } => app_url,
            LoginTarget::Rancher { url } => url,
        }
    }
}

/// What the user gave on the command line for AWS.
#[derive(Debug, Default)]
pub struct AwsOverrides {
    pub app_url: Option<String>,
    pub app_type: Option<AwsAppType>,
    pub username: Option<String>,
    pub mfa: Option<MfaSelection>,
    pub region: Option<String>,
}

/// Everything needed to log in for AWS.
#[derive(Debug)]
pub struct AwsLogin {
    pub app_url: String,
    /// The identity provider the entry logs in with.
    pub idp_url: String,
    pub username: String,
    /// Only for the IAM Identity Center application.
    pub region: Option<String>,
    pub mfa: Option<MfaSelection>,
    pub app_type: AwsAppType,
}

impl AwsLogin {
    /// The url whose domain a saved password belongs to: the identity provider.
    pub fn password_url(&self) -> &str {
        &self.idp_url
    }
}

/// What the user gave on the command line for Rancher.
#[derive(Debug, Default)]
pub struct RancherOverrides {
    pub url: Option<String>,
    pub username: Option<String>,
    pub mfa: Option<MfaSelection>,
}

/// Everything needed to log in to a Rancher.
#[derive(Debug)]
pub struct RancherLogin {
    pub url: String,
    pub username: String,
    pub mfa: Option<MfaSelection>,
    pub idp_type: IdpType,
    pub idp_url: String,
    pub client_id: String,
}
