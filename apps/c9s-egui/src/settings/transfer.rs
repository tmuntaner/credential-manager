use c9s::app::settings::ExportChoice;
use c9s::domain::services::settings_editor::ImportMode;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::sync::Arc;

/// Which file to ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pick {
    /// A new file to write.
    Save,
    /// A file that exists, to read.
    Open,
}

/// Asks the user for a file.
/// It blocks until they chose a file, and returns `None` if they chose nothing. It also runs on
/// its own thread.
pub type FilePicker = Arc<dyn Fn(Pick) -> Option<PathBuf> + Send + Sync>;

/// The name an export starts with.
pub const EXPORT_FILE: &str = "c9s-onboarding.toml";

/// A file picker that opens a file picking dialog on the system.
pub fn real_file_picker() -> FilePicker {
    Arc::new(|pick| {
        // The dialog is async, so it gets a runtime of its own on this thread.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()?;

        // open a dialog with a filter for toml files
        let dialog = rfd::AsyncFileDialog::new().add_filter("c9s onboarding file", &["toml"]);

        // react to the result of the dialog and return a filepath
        runtime.block_on(async {
            let file = match pick {
                Pick::Save => dialog.set_file_name(EXPORT_FILE).save_file().await,
                Pick::Open => dialog.pick_file().await,
            };
            file.map(|f| f.path().to_path_buf())
        })
    })
}

/// The choice for an import/export onboarding.
pub enum Transfer {
    Export(ExportChoice),
    Import(ImportMode),
}

/// The choice for the user's file from the file picker.
pub struct ChosenFile {
    pub transfer: Transfer,
    pub file: Receiver<Option<PathBuf>>,
}
