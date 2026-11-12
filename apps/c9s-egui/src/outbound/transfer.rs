use crate::inbound::app::Shell;
use c9s::app::settings::{ExportChoice, ImportPlan};
use c9s::domain::services::settings_editor::ImportMode;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
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

/// The files of an export or an import.
/// Asked for on their own thread, and taken in when the user chose one.
pub struct FileTransfer {
    pub picker: FilePicker,
    /// The file the user is choosing for an export or import.
    choice: Option<ChosenFile>,
    /// Whether an import overwrites existing settings.
    overwrite: bool,
    /// The onboarding bundle we're importing, while the usernames are asked.
    importing: Option<(ImportPlan, ImportMode)>,
}

impl FileTransfer {
    pub fn new() -> Self {
        Self {
            picker: real_file_picker(),
            choice: None,
            overwrite: false,
            importing: None,
        }
    }

    /// Replaces the file picker which asks the user to choose a file to import from or export to.
    pub fn set_picker(&mut self, picker: FilePicker) {
        self.picker = picker;
    }

    pub fn is_choosing(&self) -> bool {
        self.choice.is_some()
    }

    pub fn overwrite(&self) -> bool {
        self.overwrite
    }

    pub fn set_overwrite(&mut self, overwrite: bool) {
        self.overwrite = overwrite;
    }

    /// What an import does with what is there already.
    pub fn import_mode(&self) -> ImportMode {
        if self.overwrite {
            ImportMode::Overwrite
        } else {
            ImportMode::SkipExisting
        }
    }

    /// Holds an import until its usernames are known.
    pub fn hold(&mut self, plan: ImportPlan, mode: ImportMode) {
        self.importing = Some((plan, mode));
    }

    /// The import that was held.
    pub fn take_held(&mut self) -> Option<(ImportPlan, ImportMode)> {
        self.importing.take()
    }

    /// Drops the import that was held.
    pub fn forget_held(&mut self) {
        self.importing = None;
    }

    /// Asks the user to choose a file.
    pub fn choose(&mut self, shell: &mut Shell, transfer: Transfer, pick: Pick) {
        // one question at a time
        if self.is_choosing() {
            return;
        }

        // create a channel and get the file path from the file picker
        let (sender, file) = mpsc::channel();
        let picker = self.picker.clone();
        let ctx = shell.ctx.clone();
        let spawned = std::thread::Builder::new()
            .name("choose-file".into())
            .spawn(move || {
                let _ = sender.send(picker(pick));
                ctx.request_repaint();
            });

        match spawned {
            Ok(_) => self.choice = Some(ChosenFile { transfer, file }),
            Err(e) => shell.fail(format!("Could not ask for a file: {e}.")),
        }
    }

    /// The file the user chose, once they did. Nothing comes back when they chose none. Called every frame.
    pub fn poll(&mut self) -> Option<(Transfer, PathBuf)> {
        let choice = self.choice.as_ref()?;

        // try to receive the file from the receiver
        let file = match choice.file.try_recv() {
            Ok(file) => file,
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => None,
        };

        // take the choice and leave none in its place
        let ChosenFile { transfer, .. } = self.choice.take()?;

        file.map(|path| (transfer, path))
    }
}

impl Default for FileTransfer {
    fn default() -> Self {
        Self::new()
    }
}
