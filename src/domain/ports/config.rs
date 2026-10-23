use crate::domain::models::settings::{AppConfig, SettingsError};

/// Where the settings are kept.
pub trait ConfigStore {
    /// Nothing stored yet is the same as empty settings.
    fn load(&self) -> Result<AppConfig, SettingsError>;

    fn save(&self, config: &AppConfig) -> Result<(), SettingsError>;
}
