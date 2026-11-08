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
#[cfg_attr(test, mockall::automock)]
pub trait ConfigStore {
    /// Nothing stored yet is the same as empty settings.
    fn load(&self) -> Result<AppConfig, ConfigError>;

    fn save(&self, config: &AppConfig) -> Result<(), ConfigError>;
}

/// An in-memory store for tests: counts the saves and can refuse them.
#[cfg(test)]
pub(crate) mod memory {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    #[derive(Default)]
    pub(crate) struct MemoryStore {
        saved: Mutex<Option<AppConfig>>,
        saves: AtomicUsize,
        fail_save: AtomicBool,
    }

    impl MemoryStore {
        pub(crate) fn saves(&self) -> usize {
            self.saves.load(Ordering::SeqCst)
        }

        /// Makes every following save fail.
        pub(crate) fn fail_saves(&self) {
            self.fail_save.store(true, Ordering::SeqCst);
        }
    }

    impl ConfigStore for MemoryStore {
        fn load(&self) -> Result<AppConfig, ConfigError> {
            Ok(self.saved.lock().unwrap().clone().unwrap_or_default())
        }

        fn save(&self, config: &AppConfig) -> Result<(), ConfigError> {
            if self.fail_save.load(Ordering::SeqCst) {
                return Err(ConfigError::Failed("disk full".into()));
            }
            *self.saved.lock().unwrap() = Some(config.clone());
            self.saves.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
}
