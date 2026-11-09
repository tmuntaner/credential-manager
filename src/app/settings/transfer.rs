use super::errors::{edit_error, Form};
use super::models::{SettingsView, SetupError};
use super::SettingsPage;
use crate::domain::models::settings::SettingsBundle;
use crate::domain::ports::bundle::{BundleCodec, BundleError};
use crate::domain::services::settings_editor::fields::check_username;
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

    /// No identity provider was chosen to export.
    #[error("choose at least one identity provider to export")]
    NoIdp,
}

/// A decoded onboarding bundle and what info it needs.
pub struct ImportPlan {
    bundle: SettingsBundle,
    usernames_needed: Vec<String>,
}

impl ImportPlan {
    /// Imported IDPs will need a username before we can use them.
    pub fn usernames_needed(&self) -> &[String] {
        &self.usernames_needed
    }

    /// Applies an onboarding bundle.
    pub fn apply(
        &self,
        settings: &SettingsService,
        mode: ImportMode,
        usernames: &BTreeMap<String, String>,
    ) -> Result<ImportReport, TransferError> {
        let (_, report) = settings.import(&self.bundle, mode, usernames)?;

        Ok(report)
    }
}

/// Plans an import by decoding the onboarding file and figuring out which usernames it needs.
pub fn plan_import<C: BundleCodec>(
    settings: &SettingsService,
    codec: &C,
    text: &str,
) -> Result<ImportPlan, TransferError> {
    let bundle = codec.decode(text)?;
    let usernames_needed = settings.usernames_needed(&bundle)?;

    Ok(ImportPlan {
        bundle,
        usernames_needed,
    })
}

/// A pre-flight check for an IDP's usernames.
pub fn check_import_username(idp: &str, input: &str) -> Result<String, String> {
    check_username(input).map_err(|e| format!("{idp}: {e}"))
}

/// A short description for what an import did.
pub fn describe_import(report: &ImportReport) -> String {
    let (added, updated, kept) = (report.added(), report.overwritten(), report.skipped());

    if added + updated + kept == 0 {
        return "Nothing to import.".to_string();
    }

    if added + updated == 0 {
        return format!("Nothing new to import, {kept} were set up already.");
    }

    let mut parts = vec![format!("{added} added")];

    if updated > 0 {
        parts.push(format!("{updated} updated"));
    }

    if kept > 0 {
        parts.push(format!("{kept} kept as they were"));
    }

    format!("Imported: {}.", parts.join(", "))
}

fn setup_error(error: TransferError) -> SetupError {
    match error {
        TransferError::Settings(e) => edit_error(e, Form::ACTION),
        TransferError::NoIdp => SetupError::general("Choose at least one identity provider to export."),
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
    /// Keep every app of the chosen identity providers, ignoring `aws_apps` and `rancher_hosts`.
    pub all_apps: bool,
}

impl ExportChoice {
    pub fn new(idps: Vec<String>, aws_apps: Vec<String>, rancher_hosts: Vec<String>) -> Self {
        Self {
            idps,
            aws_apps,
            rancher_hosts,
            all_apps: false,
        }
    }

    /// Export everything for these idps.
    /// We don't sepcify any apps because all of them will be used.
    pub fn everything_of(idps: Vec<String>) -> Self {
        Self {
            all_apps: true,
            ..Self::new(idps, vec![], vec![])
        }
    }
}

/// Renders the export for a choice.
pub fn export_bundle<C: BundleCodec>(
    settings: &SettingsService,
    codec: &C,
    choice: &ExportChoice,
) -> Result<String, TransferError> {
    if choice.idps.is_empty() {
        return Err(TransferError::NoIdp);
    }

    let mut bundle = settings.export(&choice.idps)?;
    if !choice.all_apps {
        bundle.retain_apps(&choice.aws_apps, &choice.rancher_hosts);
    }

    Ok(codec.encode(&bundle)?)
}

impl SettingsPage {
    /// Export onboarding choices to a file at a specific `path`.
    pub fn export_choice_to_file<C: BundleCodec>(
        &self,
        codec: &C,
        choice: &ExportChoice,
        path: &Path,
    ) -> Result<(), SetupError> {
        let text = export_bundle(&self.settings, codec, choice).map_err(setup_error)?;

        std::fs::write(path, text).map_err(|e| io_error("write", path, e))
    }

    /// Reads and decodes an onboarding file.
    pub fn plan_import_from_file<C: BundleCodec>(
        &self,
        codec: &C,
        path: &Path,
    ) -> Result<ImportPlan, SetupError> {
        let text = std::fs::read_to_string(path).map_err(|e| io_error("read", path, e))?;

        plan_import(&self.settings, codec, &text).map_err(setup_error)
    }

    /// Imports a planned onboarding file.
    pub fn apply_import(
        &self,
        plan: &ImportPlan,
        mode: ImportMode,
        usernames: &BTreeMap<String, String>,
    ) -> Result<(SettingsView, ImportReport), SetupError> {
        let report = plan
            .apply(&self.settings, mode, usernames)
            .map_err(setup_error)?;
        let view = self.run(Form::ACTION, |s| s.load())?;

        Ok((view, report))
    }

    /// Imports the user onboarding bundle: one read, one decode.
    pub fn import_from_file<C: BundleCodec>(
        &self,
        codec: &C,
        path: &Path,
        mode: ImportMode,
        usernames: &BTreeMap<String, String>,
    ) -> Result<(SettingsView, ImportReport), SetupError> {
        let plan = self.plan_import_from_file(codec, path)?;

        self.apply_import(&plan, mode, usernames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::idp::IdpType;
    use crate::domain::models::settings::YubikeyConfig;
    use crate::domain::ports::bundle::MockBundleCodec;
    use crate::domain::services::settings_editor::{
        AwsAppInput, AwsAppKind, IdpInput, ImportCounts, SaveAs,
    };
    use crate::outbound::config::bundle::TomlBundleCodec;
    use crate::outbound::config::in_memory::InMemoryConfigStore;
    use std::sync::Arc;

    #[test]
    fn a_bundle_moves_between_machines_without_security_settings() {
        let dir = tempfile::tempdir().unwrap();
        let (mine, theirs) = (
            Arc::new(InMemoryConfigStore::new()),
            Arc::new(InMemoryConfigStore::new()),
        );

        let service = SettingsService::new(mine.clone());
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
        SettingsPage::new(SettingsService::new(mine.clone()))
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

        let page = SettingsPage::new(SettingsService::new(theirs.clone()));
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

        let imported = SettingsService::new(theirs.clone()).load().unwrap();
        // The importer's own user name, not the one of the exporter.
        assert_eq!(imported.resolve_idp("corp").unwrap().username(), "them");
        assert!(imported.yubikey_config().is_none());
        assert!(imported.keyring_enabled());
    }

    #[test]
    fn exporting_nothing_or_importing_junk_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let page = SettingsPage::new(SettingsService::new(Arc::new(InMemoryConfigStore::new())));
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

    fn report(added: usize, overwritten: usize, skipped: usize) -> ImportReport {
        ImportReport {
            idps: ImportCounts {
                added,
                overwritten,
                skipped,
            },
            ..Default::default()
        }
    }

    #[test]
    fn an_import_is_described_in_one_sentence() {
        for (counts, sentence) in [
            ((2, 0, 0), "Imported: 2 added."),
            (
                (2, 1, 3),
                "Imported: 2 added, 1 updated, 3 kept as they were.",
            ),
            ((0, 0, 4), "Nothing new to import, 4 were set up already."),
            ((0, 2, 0), "Imported: 0 added, 2 updated."),
            ((0, 0, 0), "Nothing to import."),
        ] {
            assert_eq!(
                describe_import(&report(counts.0, counts.1, counts.2)),
                sentence
            );
        }
    }

    const FIRST_APP: &str = "https://id.example.com/first/";
    const SECOND_APP: &str = "https://id.example.com/second/";

    /// A service with the identity provider "corp" and two AWS apps.
    fn with_two_apps() -> SettingsService {
        let service = SettingsService::new(Arc::new(InMemoryConfigStore::new()));
        service
            .save_idp(
                IdpInput::new("corp", IdpType::Authentik, "https://id.example.com", "me"),
                SaveAs::Upsert,
            )
            .unwrap();
        for url in [FIRST_APP, SECOND_APP] {
            service
                .save_aws_app(
                    AwsAppInput::new(url, "corp"),
                    AwsAppKind::Aws,
                    SaveAs::Upsert,
                )
                .unwrap();
        }

        service
    }

    #[test]
    fn a_plan_decodes_once_and_applying_it_does_not_decode_again() {
        let bundle = with_two_apps().export(&["corp".to_string()]).unwrap();
        let mut codec = MockBundleCodec::new();
        codec
            .expect_decode()
            .times(1)
            .returning(move |_| Ok(bundle.clone()));

        let theirs = SettingsService::new(Arc::new(InMemoryConfigStore::new()));
        let plan = plan_import(&theirs, &codec, "text").unwrap();
        let usernames = BTreeMap::from([("corp".to_string(), "them".to_string())]);

        let report = plan
            .apply(&theirs, ImportMode::SkipExisting, &usernames)
            .unwrap();
        assert_eq!(report.added(), 3);

        let again = plan
            .apply(&theirs, ImportMode::SkipExisting, &usernames)
            .unwrap();
        assert_eq!((again.added(), again.skipped()), (0, 3));
    }

    #[test]
    fn a_plan_asks_only_for_the_identity_providers_that_are_new() {
        let mine = with_two_apps();
        let bundle = mine.export(&["corp".to_string()]).unwrap();
        let mut codec = MockBundleCodec::new();
        codec.expect_decode().returning(move |_| Ok(bundle.clone()));

        let theirs = SettingsService::new(Arc::new(InMemoryConfigStore::new()));
        assert_eq!(
            plan_import(&theirs, &codec, "").unwrap().usernames_needed(),
            ["corp"]
        );
        assert!(plan_import(&mine, &codec, "")
            .unwrap()
            .usernames_needed()
            .is_empty());
    }

    #[test]
    fn exporting_needs_an_identity_provider_and_keeps_the_chosen_apps() {
        let service = with_two_apps();

        let error = export_bundle(&service, &TomlBundleCodec, &ExportChoice::default());
        assert!(matches!(error, Err(TransferError::NoIdp)));

        let chosen = export_bundle(
            &service,
            &TomlBundleCodec,
            &ExportChoice::new(
                vec!["corp".into()],
                vec![FIRST_APP.trim_end_matches('/').into()],
                vec![],
            ),
        )
        .unwrap();
        assert!(chosen.contains("first") && !chosen.contains("second"));

        let everything = export_bundle(
            &service,
            &TomlBundleCodec,
            &ExportChoice::everything_of(vec!["corp".into()]),
        )
        .unwrap();
        assert!(everything.contains("first") && everything.contains("second"));
    }

    #[test]
    fn a_file_is_planned_then_applied() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("bundle.toml");
        let mine = SettingsPage::new(with_two_apps());
        mine.export_choice_to_file(
            &TomlBundleCodec,
            &ExportChoice::everything_of(vec!["corp".into()]),
            &file,
        )
        .unwrap();

        let theirs = SettingsPage::new(SettingsService::new(Arc::new(InMemoryConfigStore::new())));
        let plan = theirs
            .plan_import_from_file(&TomlBundleCodec, &file)
            .unwrap();
        assert_eq!(plan.usernames_needed(), ["corp"]);

        let (view, report) = theirs
            .apply_import(
                &plan,
                ImportMode::SkipExisting,
                &BTreeMap::from([("corp".to_string(), "them".to_string())]),
            )
            .unwrap();
        assert_eq!((report.added(), view.aws_apps.len()), (3, 2));
    }
}
