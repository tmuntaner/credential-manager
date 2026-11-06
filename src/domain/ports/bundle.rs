use crate::domain::models::settings::SettingsBundle;
use std::error::Error;
use thiserror::Error;

/// The error for importing/exporting a bundle.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BundleError {
    /// The text is not a valid onboarding bundle.
    #[error("not a valid settings bundle: {0}")]
    Invalid(Box<dyn Error + Send + Sync>),

    /// The bundle was made by a newer c9s.
    #[error("the bundle has version {0}, which this c9s does not understand")]
    UnsupportedVersion(u32),
}

/// The text form of a [`SettingsBundle`], which user share..
#[cfg_attr(test, mockall::automock)]
pub trait BundleCodec {
    fn encode(&self, bundle: &SettingsBundle) -> Result<String, BundleError>;

    fn decode(&self, text: &str) -> Result<SettingsBundle, BundleError>;
}
