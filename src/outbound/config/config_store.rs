use crate::domain::models::settings::AppConfig;
use crate::domain::ports::config::{ConfigError, ConfigStore};
use crate::outbound::config::file::FileConfig;
use std::fs::{self, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

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
        let contents = toml::to_string(&FileConfig::from(config)).map_err(failed)?;
        write_atomically(&self.path, contents.as_bytes()).map_err(failed)
    }
}

/// Writes `bytes` to a temporary file in the same folder, flushes it to disk and renames it over `path`,
/// so a reader sees the old file or the new one, never half of it.
///
/// A symlinked file is written through (the link stays), and an existing file keeps its permissions.
/// On Windows the rename fails if another program holds the file open without sharing deletes; that
/// is retried briefly and then returned as an error, and the folder is not synced (std cannot).
fn write_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    // Saves from this process take turns: on Windows, renames over the same file race with each other
    // and fail with "access denied" or "not found". Other programs are covered by the retry below.
    static SAVING: Mutex<()> = Mutex::new(());
    let _turn = SAVING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let existing = fs::canonicalize(path).ok();
    let target = existing.as_deref().unwrap_or(path);
    let dir = match target.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    fs::create_dir_all(dir)?;

    let name = target
        .file_name()
        .ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidInput,
                "the settings path has no file name",
            )
        })?
        .to_string_lossy();
    let tmp = dir.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));

    let written = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        if existing.is_some() {
            // On Windows the file can briefly be missing while a concurrent save replaces it.
            match fs::metadata(target) {
                Ok(meta) => fs::set_permissions(&tmp, meta.permissions())?,
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        rename_over(&tmp, target)
    })();

    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    #[cfg(unix)]
    if let Ok(dir) = fs::File::open(dir) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Renames `from` over `to`. On Windows a concurrent save or reader makes the rename fail briefly with
/// "access denied", so it is retried for a short while; elsewhere it is a plain rename.
fn rename_over(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        let mut attempts = 0;
        loop {
            match fs::rename(from, to) {
                Err(e) if e.kind() == ErrorKind::PermissionDenied && attempts < 100 => {
                    attempts += 1;
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                result => return result,
            }
        }
    }
    #[cfg(not(windows))]
    fs::rename(from, to)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::settings::YubikeyConfig;
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

    fn config_with(keyring: bool) -> AppConfig {
        let mut config = AppConfig::default();
        config.set_use_keyring(keyring);
        config
    }

    fn key(id: &[u8]) -> YubikeyConfig {
        YubikeyConfig::new(id, "c9s.test", &[1; 32])
    }

    #[test]
    fn save_creates_the_folder_and_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a").join("b").join("settings.toml");

        ConfigFileAdapter::at(path.clone())
            .save(&config_with(false))
            .unwrap();

        assert!(path.is_file());
    }

    #[test]
    fn save_leaves_no_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigFileAdapter::at(dir.path().join("settings.toml"));

        store.save(&config_with(false)).unwrap();
        store.save(&config_with(true)).unwrap();

        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("settings.toml")]);
    }

    #[test]
    fn save_replaces_the_old_contents_completely() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.toml");
        let store = ConfigFileAdapter::at(path.clone());
        let mut big = config_with(false);
        big.set_yubikey(Some(key(&[7; 400])));
        store.save(&big).unwrap();
        let big_len = fs::metadata(&path).unwrap().len();

        store.save(&config_with(true)).unwrap();

        assert!(fs::metadata(&path).unwrap().len() <= big_len);
        assert!(store.load().unwrap().keyring_enabled());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            toml::to_string(&FileConfig::from(&config_with(true))).unwrap()
        );
    }

    #[test]
    fn a_save_into_an_unwritable_place_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("file");
        fs::write(&blocker, "x").unwrap();

        let store = ConfigFileAdapter::at(blocker.join("settings.toml"));

        assert!(store.save(&AppConfig::default()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_save_keeps_the_old_file_and_removes_the_temp_file() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigFileAdapter::at(dir.path().join("settings.toml"));
        store.save(&config_with(false)).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o555)).unwrap();

        let result = store.save(&config_with(true));

        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(result.is_err());
        assert!(!store.load().unwrap().keyring_enabled());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn save_preserves_the_permissions_of_the_existing_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.toml");
        let store = ConfigFileAdapter::at(path.clone());
        store.save(&config_with(false)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

        store.save(&config_with(true)).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o640);
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_through_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        let target = real.join("settings.toml");
        let link = dir.path().join("settings.toml");
        ConfigFileAdapter::at(target.clone())
            .save(&config_with(true))
            .unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        ConfigFileAdapter::at(link.clone())
            .save(&config_with(false))
            .unwrap();

        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!ConfigFileAdapter::at(target)
            .load()
            .unwrap()
            .keyring_enabled());
    }

    #[test]
    fn concurrent_saves_never_leave_a_torn_file() {
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.toml");
        let store = Arc::new(ConfigFileAdapter::at(path));
        store.save(&config_with(true)).unwrap();
        let done = Arc::new(AtomicBool::new(false));

        let reader = {
            let (store, done) = (store.clone(), done.clone());
            std::thread::spawn(move || {
                while !done.load(Ordering::SeqCst) {
                    store.load().expect("a reader saw a torn file");
                }
            })
        };
        let writers: Vec<_> = (0..8)
            .map(|t| {
                let store = store.clone();
                std::thread::spawn(move || {
                    for i in 0..50 {
                        let mut config = config_with((t + i) % 2 == 0);
                        config.set_yubikey(Some(key(&[t as u8; 3][..].repeat(i + 1))));
                        store.save(&config).unwrap();
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().unwrap();
        }
        done.store(true, Ordering::SeqCst);
        reader.join().unwrap();

        store.load().unwrap();
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
