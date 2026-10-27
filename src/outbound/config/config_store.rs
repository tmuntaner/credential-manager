use crate::domain::models::settings::AppConfig;
use crate::domain::ports::config::{ConfigError, ConfigStore};
use crate::outbound::config::file::FileConfig;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

/// Reads and writes the settings file.
pub struct ConfigFileAdapter {
    path: PathBuf,
}

impl ConfigFileAdapter {
    /// The settings file in the config directory of the user, `~/.config/c9s/settings.toml` on Linux.
    pub fn in_user_config_dir() -> Result<Self, ConfigError> {
        let path = dirs::config_dir()
            .ok_or_else(|| ConfigError::Failed("could not determine config directory".into()))?
            .join("c9s")
            .join("settings.toml");

        Ok(Self::at(path))
    }

    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }
}

fn failed(e: impl std::error::Error + Send + Sync + 'static) -> ConfigError {
    ConfigError::Failed(Box::new(e))
}

impl ConfigStore for ConfigFileAdapter {
    /// A missing file is the same as an empty one; nothing is created.
    fn load(&self) -> Result<AppConfig, ConfigError> {
        match fs::read_to_string(&self.path) {
            Ok(contents) => toml::from_str::<FileConfig>(&contents)
                .map_err(failed)?
                .try_into(),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(AppConfig::default()),
            Err(e) => Err(failed(e)),
        }
    }

    fn save(&self, config: &AppConfig) -> Result<(), ConfigError> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir).map_err(failed)?;
        }
        let contents = toml::to_string(&FileConfig::from(config)).map_err(failed)?;
        fs::write(&self.path, contents).map_err(failed)?;

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
