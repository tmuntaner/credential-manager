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
    use std::cell::{Cell, RefCell};

    #[derive(Default)]
    pub(crate) struct MemoryStore {
        saved: RefCell<Option<AppConfig>>,
        saves: Cell<usize>,
        fail_save: Cell<bool>,
    }

    impl MemoryStore {
        pub(crate) fn saves(&self) -> usize {
            self.saves.get()
        }

        /// Makes every following save fail.
        pub(crate) fn fail_saves(&self) {
            self.fail_save.set(true);
        }
    }

    impl ConfigStore for &MemoryStore {
        fn load(&self) -> Result<AppConfig, ConfigError> {
            Ok(self.saved.borrow().clone().unwrap_or_default())
        }

        fn save(&self, config: &AppConfig) -> Result<(), ConfigError> {
            if self.fail_save.get() {
                return Err(ConfigError::Failed("disk full".into()));
            }
            *self.saved.borrow_mut() = Some(config.clone());
            self.saves.set(self.saves.get() + 1);
            Ok(())
        }
    }
}
