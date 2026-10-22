use crate::domain::models::settings::{AppConfig, SettingsError};
use crate::domain::ports::config::ConfigStore;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

/// Reads and writes the settings file.
pub struct ConfigFileAdapter {
    path: PathBuf,
}

impl ConfigFileAdapter {
    /// The settings file in the config directory of the user, `~/.config/c9s/settings.toml` on Linux.
    pub fn in_user_config_dir() -> Result<Self, SettingsError> {
        let path = dirs::config_dir()
            .ok_or(SettingsError::NoConfigDir)?
            .join("c9s")
            .join("settings.toml");

        Ok(Self::at(path))
    }

    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }
}

impl ConfigStore for ConfigFileAdapter {
    /// A missing file is the same as an empty one; nothing is created.
    fn load(&self) -> Result<AppConfig, SettingsError> {
        match fs::read_to_string(&self.path) {
            Ok(contents) => Ok(toml::from_str(&contents)?),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(AppConfig::default()),
            Err(e) => Err(e.into()),
        }
    }

    fn save(&self, config: &AppConfig) -> Result<(), SettingsError> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(&self.path, toml::to_string(config)?)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("c9s-config-store-{}-{nanos}", std::process::id()))
    }

    #[test]
    fn loading_a_missing_file_gives_the_defaults_and_creates_nothing() {
        let dir = temp_dir();
        let store = ConfigFileAdapter::at(dir.join("c9s").join("settings.toml"));

        let config = store.load().unwrap();

        assert!(config.keyring_enabled());
        assert!(!dir.exists());
    }

    #[test]
    fn saved_settings_are_loaded_again() {
        let dir = temp_dir();
        let store = ConfigFileAdapter::at(dir.join("c9s").join("settings.toml"));
        let mut config = AppConfig::default();
        config.set_use_keyring(false);

        store.save(&config).unwrap();

        assert!(!store.load().unwrap().keyring_enabled());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_invalid_file_is_an_error() {
        let dir = temp_dir();
        let path = dir.join("settings.toml");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&path, "[[aws_hosts]]\nmfa = \"sms\"").unwrap();

        assert!(ConfigFileAdapter::at(path).load().is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
