use crate::domain::models::settings::AppConfig;
use crate::domain::ports::config::{ConfigError, ConfigStore};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

/// A [`ConfigStore`] that keeps the settings in memory: for tests, and for callers that want no file.
#[derive(Default)]
pub struct InMemoryConfigStore {
    saved: Mutex<Option<AppConfig>>,
    saves: AtomicUsize,
    fail_save: AtomicBool,
}

impl InMemoryConfigStore {
    /// An empty store, the same as [`Default`].
    pub fn new() -> Self {
        Self::default()
    }

    /// A store that already holds `config`; it counts no saves.
    pub fn with_config(config: AppConfig) -> Self {
        Self {
            saved: Mutex::new(Some(config)),
            ..Self::default()
        }
    }

    /// How many saves succeeded.
    pub fn saves(&self) -> usize {
        self.saves.load(Ordering::SeqCst)
    }

    /// Makes every following save fail.
    pub fn fail_saves(&self) {
        self.fail_save.store(true, Ordering::SeqCst);
    }

    /// What is stored; `None` when nothing was saved or seeded.
    pub fn snapshot(&self) -> Option<AppConfig> {
        self.saved.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl ConfigStore for InMemoryConfigStore {
    fn load(&self) -> Result<AppConfig, ConfigError> {
        Ok(self.snapshot().unwrap_or_default())
    }

    fn save(&self, config: &AppConfig) -> Result<(), ConfigError> {
        if self.fail_save.load(Ordering::SeqCst) {
            return Err(ConfigError::Failed("disk full".into()));
        }
        *self.saved.lock().unwrap_or_else(|e| e.into_inner()) = Some(config.clone());
        self.saves.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_store_is_empty() {
        let store = InMemoryConfigStore::new();

        assert!(store.snapshot().is_none());
        assert_eq!(store.saves(), 0);
        assert!(store.load().unwrap().keyring_enabled());
    }

    #[test]
    fn a_seeded_store_loads_its_config_without_counting_a_save() {
        let mut config = AppConfig::default();
        config.set_use_keyring(false);
        let store = InMemoryConfigStore::with_config(config);

        assert!(!store.load().unwrap().keyring_enabled());
        assert_eq!(store.saves(), 0);
    }

    #[test]
    fn saves_are_counted_and_stored() {
        let store = InMemoryConfigStore::new();
        let mut config = AppConfig::default();
        config.set_use_keyring(false);

        store.save(&config).unwrap();
        store.save(&config).unwrap();

        assert_eq!(store.saves(), 2);
        assert!(!store.snapshot().unwrap().keyring_enabled());
    }

    #[test]
    fn failing_saves_store_nothing_and_count_nothing() {
        let store = InMemoryConfigStore::new();
        store.fail_saves();

        let err = store.save(&AppConfig::default()).unwrap_err();

        assert!(err.to_string().contains("disk full"));
        assert_eq!(store.saves(), 0);
        assert!(store.snapshot().is_none());
    }
}
