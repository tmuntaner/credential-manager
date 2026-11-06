use super::errors::{edit_error, Form};
use super::models::{SettingsView, SetupError};
use super::summary::summarize;
use super::SettingsPage;
use crate::domain::ports::bundle::{BundleCodec, BundleError};
use crate::domain::ports::config::ConfigStore;
use crate::domain::services::settings_editor::{
    ImportMode, ImportReport, SettingsEditError, SettingsService,
};
use std::collections::BTreeMap;
use std::path::Path;
use thiserror::Error;

/// An error for transferring an onboarding file.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TransferError {
    /// The settings refused it, or it could not be read or written.
    #[error(transparent)]
    Settings(#[from] SettingsEditError),

    /// The text is not a bundle.
    #[error(transparent)]
    Bundle(#[from] BundleError),
}

/// Renders the settings export text (does not save) for an onboarding bundle.
pub fn export_text<S: ConfigStore, C: BundleCodec>(
    settings: &SettingsService<S>,
    codec: &C,
    names: &[String],
) -> Result<String, TransferError> {
    let bundle = settings.export(names)?;

    Ok(codec.encode(&bundle)?)
}

/// Imports settings from an onboarding bundle.
pub fn import_text<S: ConfigStore, C: BundleCodec>(
    settings: &SettingsService<S>,
    codec: &C,
    text: &str,
    mode: ImportMode,
    usernames: &BTreeMap<String, String>,
) -> Result<ImportReport, TransferError> {
    let bundle = codec.decode(text)?;
    let (_, report) = settings.import(&bundle, mode, usernames)?;

    Ok(report)
}

/// Returns which usernames are needed for this onboarding bundle.
pub fn usernames_needed<S: ConfigStore, C: BundleCodec>(
    settings: &SettingsService<S>,
    codec: &C,
    text: &str,
) -> Result<Vec<String>, TransferError> {
    Ok(settings.usernames_needed(&codec.decode(text)?)?)
}

fn setup_error(error: TransferError) -> SetupError {
    match error {
        TransferError::Settings(e) => edit_error(e, Form::Action),
        TransferError::Bundle(e) => {
            SetupError::general(format!("This is not a c9s onboarding file. Make one with Export. Your c9s settings file cannot be imported. ({e})"))
        }
    }
}

fn io_error(action: &str, path: &Path, error: std::io::Error) -> SetupError {
    SetupError::general(format!("Could not {action} {}: {error}.", path.display()))
}

/// The user choices for what to export.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ExportChoice {
    /// The identity providers, by name.
    pub idps: Vec<String>,
    /// The AWS apps, by url.
    pub aws_apps: Vec<String>,
    /// The Rancher apps, by url.
    pub rancher_hosts: Vec<String>,
}

impl ExportChoice {
    pub fn new(idps: Vec<String>, aws_apps: Vec<String>, rancher_hosts: Vec<String>) -> Self {
        Self {
            idps,
            aws_apps,
            rancher_hosts,
        }
    }
}

impl<S: ConfigStore> SettingsPage<S> {
    /// Export onboarding choices to a file at a specific `path`.
    pub fn export_choice_to_file<C: BundleCodec>(
        &self,
        codec: &C,
        choice: &ExportChoice,
        path: &Path,
    ) -> Result<(), SetupError> {
        if choice.idps.is_empty() {
            return Err(SetupError::general(
                "Choose at least one identity provider to export.",
            ));
        }

        let mut bundle = self
            .settings
            .export(&choice.idps)
            .map_err(|e| setup_error(e.into()))?;

        bundle.retain_apps(&choice.aws_apps, &choice.rancher_hosts);

        let text = codec.encode(&bundle).map_err(|e| setup_error(e.into()))?;

        std::fs::write(path, text).map_err(|e| io_error("write", path, e))
    }

    /// Returns what usernames are needed for an onboarding file.
    pub fn usernames_needed_by_file<C: BundleCodec>(
        &self,
        codec: &C,
        path: &Path,
    ) -> Result<Vec<String>, SetupError> {
        let text = std::fs::read_to_string(path).map_err(|e| io_error("read", path, e))?;

        usernames_needed(&self.settings, codec, &text).map_err(setup_error)
    }

    /// Imports the user onboarding bundle.
    pub fn import_from_file<C: BundleCodec>(
        &self,
        codec: &C,
        path: &Path,
        mode: ImportMode,
        usernames: &BTreeMap<String, String>,
    ) -> Result<(SettingsView, ImportReport), SetupError> {
        let text = std::fs::read_to_string(path).map_err(|e| io_error("read", path, e))?;
        let report =
            import_text(&self.settings, codec, &text, mode, usernames).map_err(setup_error)?;
        let settings = self
            .settings
            .load()
            .map_err(|e| edit_error(e, Form::Action))?;

        Ok((summarize(&settings), report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::idp::IdpType;
    use crate::domain::models::settings::YubikeyConfig;
    use crate::domain::services::settings_editor::{AwsAppInput, AwsAppKind, IdpInput, SaveAs};
    use crate::outbound::config::bundle::TomlBundleCodec;
    use crate::outbound::config::config_store::ConfigFileAdapter;

    fn store(dir: &Path) -> ConfigFileAdapter {
        ConfigFileAdapter::at(dir.join("c9s").join("settings.toml"))
    }

    #[test]
    fn a_bundle_moves_between_machines_without_security_settings() {
        let dir = tempfile::tempdir().unwrap();
        let (mine, theirs) = (dir.path().join("mine"), dir.path().join("theirs"));

        let service = SettingsService::new(store(&mine));
        service
            .save_idp(
                IdpInput::new("corp", IdpType::Authentik, "https://id.example.com", "me"),
                SaveAs::Upsert,
            )
            .unwrap();
        service
            .save_aws_app(
                AwsAppInput::new("https://id.example.com/app/", "corp"),
                AwsAppKind::Aws,
                SaveAs::Upsert,
            )
            .unwrap();
        service
            .set_yubikey(Some(YubikeyConfig::new(b"id", "localhost", &[7; 32])))
            .unwrap();
        service.set_use_keyring(false).unwrap();

        let file = dir.path().join("bundle.toml");
        SettingsPage::new(store(&mine))
            .export_choice_to_file(
                &TomlBundleCodec,
                &ExportChoice::new(
                    vec!["corp".into()],
                    vec!["https://id.example.com/app".into()],
                    vec![],
                ),
                &file,
            )
            .unwrap();
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(!text.contains("yubikey") && !text.contains("keyring"));
        assert!(!text.contains("username"));

        let page = SettingsPage::new(store(&theirs));
        let (view, report) = page
            .import_from_file(
                &TomlBundleCodec,
                &file,
                ImportMode::SkipExisting,
                &BTreeMap::from([("corp".to_string(), "them".to_string())]),
            )
            .unwrap();
        assert_eq!(report.added(), 2);
        assert_eq!(view.idps.len(), 1);
        assert_eq!(view.aws_apps.len(), 1);

        let imported = SettingsService::new(store(&theirs)).load().unwrap();
        // The importer's own user name, not the one of the exporter.
        assert_eq!(imported.resolve_idp("corp").unwrap().username(), "them");
        assert!(imported.yubikey_config().is_none());
        assert!(imported.keyring_enabled());
    }

    #[test]
    fn exporting_nothing_or_importing_junk_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let page = SettingsPage::new(store(dir.path()));
        let file = dir.path().join("x.toml");

        assert!(page
            .export_choice_to_file(&TomlBundleCodec, &ExportChoice::default(), &file)
            .is_err());
        assert!(!file.exists());

        std::fs::write(&file, "[global_settings]\nuse_keyring = false\n").unwrap();
        let error = page
            .import_from_file(
                &TomlBundleCodec,
                &file,
                ImportMode::SkipExisting,
                &BTreeMap::from([("corp".to_string(), "them".to_string())]),
            )
            .unwrap_err();
        assert!(error.sentence().contains("not a c9s onboarding file"));

        let missing = dir.path().join("missing.toml");
        assert!(page
            .import_from_file(
                &TomlBundleCodec,
                &missing,
                ImportMode::SkipExisting,
                &BTreeMap::new(),
            )
            .is_err());
    }
}
