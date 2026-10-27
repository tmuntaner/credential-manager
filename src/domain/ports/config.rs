use crate::domain::models::settings::{AppConfig, SettingsError};
use std::error::Error;
use thiserror::Error;

/// Why the settings could not be read or written.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// What is stored holds a setting that is not valid.
    #[error(transparent)]
    Invalid(#[from] SettingsError),

    /// The store could not be read, written or understood.
    #[error(transparent)]
    Failed(Box<dyn Error + Send + Sync>),
}

/// Where the settings are kept.
pub trait ConfigStore {
    /// Nothing stored yet is the same as empty settings.
    fn load(&self) -> Result<AppConfig, ConfigError>;

    fn save(&self, config: &AppConfig) -> Result<(), ConfigError>;
}
