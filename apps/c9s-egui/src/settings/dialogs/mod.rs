mod aws;
mod export;
mod idp;
mod rancher;
mod remove;
mod sign_in;
mod usernames;

pub use crate::ui::dialog::DialogOutcome;
pub use export::ExportDialog;
pub use remove::{Removal, RemoveDialog};
pub use usernames::UsernamesDialog;

use crate::app::FocusTarget;
use aws::AwsDialog;
use c9s::app::settings::{AwsAppSummary, IdpSummary, RancherSummary, SettingsPage, SettingsView};
use c9s::domain::ports::config::ConfigStore;
use eframe::egui::Context;
use idp::IdpDialog;
use rancher::RancherDialog;

/// The context of a form dialog.
#[derive(Clone, Debug, Default)]
pub struct FormContext {
    pub idps: Vec<String>,
    pub security_key: bool,
}

impl FormContext {
    /// Create a new form context based on a `SettingsView`.
    pub fn of(view: &SettingsView) -> Self {
        Self {
            idps: view.idps.iter().map(|i| i.name.clone()).collect(),
            security_key: view.security_key_supported,
        }
    }
}

/// The result of a dialog.
#[derive(Debug)]
pub struct Saved {
    /// The new settings after the dialog was edited.
    pub view: SettingsView,
    /// The message for the status line.
    pub message: String,
    /// The widget that should get the focus after the dialog closes.
    pub focus: Option<FocusTarget>,
}

/// The dialog popups.
pub enum Dialog {
    Idp(IdpDialog),
    Aws(AwsDialog),
    Rancher(RancherDialog),
    Remove(RemoveDialog),
    Export(ExportDialog),
    Usernames(UsernamesDialog),
}

impl Dialog {
    /// Add a new identity provider.
    pub fn add_idp(form: &FormContext) -> Self {
        Self::Idp(IdpDialog::add(form))
    }

    /// Edit an existing identity provider.
    pub fn edit_idp(idp: &IdpSummary, form: &FormContext) -> Self {
        Self::Idp(IdpDialog::edit(idp, form))
    }

    /// Adds an AWS application.
    pub fn add_aws(form: &FormContext) -> Self {
        Self::Aws(AwsDialog::add(form))
    }

    /// Removes an AWS application.
    pub fn edit_aws(app: &AwsAppSummary, form: &FormContext) -> Self {
        Self::Aws(AwsDialog::edit(app, form))
    }

    /// Adds a Rancher.
    pub fn add_rancher(form: &FormContext) -> Self {
        Self::Rancher(RancherDialog::add(form))
    }

    /// Edits a Rancher.
    pub fn edit_rancher(host: &RancherSummary, form: &FormContext) -> Self {
        Self::Rancher(RancherDialog::edit(host, form))
    }

    /// Renders the dialog.
    pub fn ui(&mut self, ctx: &Context) -> DialogOutcome {
        match self {
            Dialog::Idp(d) => d.ui(ctx),
            Dialog::Aws(d) => d.ui(ctx),
            Dialog::Rancher(d) => d.ui(ctx),
            Dialog::Remove(d) => d.ui(ctx),
            Dialog::Export(d) => d.ui(ctx),
            Dialog::Usernames(d) => d.ui(ctx),
        }
    }

    /// Submits the dialog form to the settings page to be saved.
    pub fn submit<S: ConfigStore>(&mut self, page: &SettingsPage<S>) -> Result<Saved, String> {
        match self {
            Dialog::Idp(d) => d.submit(page),
            Dialog::Aws(d) => d.submit(page),
            Dialog::Rancher(d) => d.submit(page),
            Dialog::Remove(d) => d.submit(page),
            // Exporting writes a file the user chooses next, the state takes it from there.
            Dialog::Export(_) | Dialog::Usernames(_) => {
                Err("Choose a file to export to.".to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use c9s::app::settings::{AwsAppKind, MfaChoice};
    use c9s::outbound::config::config_store::ConfigFileAdapter;

    fn page() -> (tempfile::TempDir, SettingsPage<ConfigFileAdapter>) {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigFileAdapter::at(dir.path().join("c9s").join("settings.toml"));
        (dir, SettingsPage::new(store))
    }

    fn form(page: &SettingsPage<ConfigFileAdapter>) -> FormContext {
        FormContext::of(&page.view().unwrap())
    }

    fn typed_idp(page: &SettingsPage<ConfigFileAdapter>) -> Dialog {
        let mut dialog = Dialog::add_idp(&form(page));
        let Dialog::Idp(d) = &mut dialog else {
            unreachable!()
        };
        d.type_into("work", " https://id.example.com/ ", "me@example.com");
        dialog
    }

    #[test]
    fn a_saved_identity_provider_gives_back_the_view_and_the_focus() {
        let (_dir, page) = page();
        let mut dialog = typed_idp(&page);

        let saved = dialog.submit(&page).unwrap();

        assert_eq!(saved.message, "Identity provider work saved.");
        assert_eq!(saved.focus, Some(FocusTarget::Idp("work".into())));
        assert_eq!(saved.view.idps[0].url, "https://id.example.com");
    }

    #[test]
    fn an_invalid_form_keeps_its_errors_and_says_how_many() {
        let (_dir, page) = page();
        let mut dialog = Dialog::add_idp(&form(&page));

        let said = dialog.submit(&page).unwrap_err();

        assert_eq!(said, "3 problems to fix.");
        assert!(page.view().unwrap().idps.is_empty());
    }

    #[test]
    fn a_saved_aws_app_focuses_the_entry_the_view_stored() {
        let (_dir, page) = page();
        typed_idp(&page).submit(&page).unwrap();
        let mut dialog = Dialog::add_aws(&form(&page));
        let Dialog::Aws(d) = &mut dialog else {
            unreachable!()
        };
        d.type_into("https://id.example.com/application/saml/aws/binding/init/");

        let saved = dialog.submit(&page).unwrap();

        // The settings keep the url without the trailing slash, the focus finds it all the same.
        assert_eq!(
            saved.focus,
            Some(FocusTarget::AwsApp(c9s::app::settings::AwsAppKey {
                app_url: "https://id.example.com/application/saml/aws/binding/init".into(),
                kind: AwsAppKind::Aws,
            }))
        );
    }

    #[test]
    fn a_removal_that_is_refused_is_explained_in_the_dialog() {
        let (_dir, page) = page();
        typed_idp(&page).submit(&page).unwrap();
        let mut add = Dialog::add_aws(&form(&page));
        let Dialog::Aws(d) = &mut add else {
            unreachable!()
        };
        d.type_into("https://id.example.com/application/saml/aws/binding/init");
        add.submit(&page).unwrap();
        let mut remove = Dialog::Remove(RemoveDialog::new(
            Removal::Idp("work".into()),
            "Remove work?",
            "d",
            "work removed.",
        ));

        assert_eq!(remove.submit(&page).unwrap_err(), "Not removed.");
        let Dialog::Remove(d) = &remove else {
            unreachable!()
        };
        assert!(d.error().unwrap().contains("cannot be removed"));
    }

    #[test]
    fn a_removal_goes_back_to_the_add_button() {
        let (_dir, page) = page();
        typed_idp(&page).submit(&page).unwrap();
        let mut remove = Dialog::Remove(RemoveDialog::new(
            Removal::Idp("work".into()),
            "Remove work?",
            "d",
            "work removed.",
        ));

        let saved = remove.submit(&page).unwrap();

        assert_eq!(saved.message, "work removed.");
        assert_eq!(
            saved.focus,
            Some(FocusTarget::Add(crate::app::Section::Idp))
        );
    }

    #[test]
    fn an_edit_of_an_unsupported_second_step_falls_back_to_asking() {
        let idp = IdpSummary {
            name: "work".into(),
            url: "https://id.example.com".into(),
            username: "me".into(),
            mfa: MfaChoice::SecurityKey,
            used_by: vec![],
        };
        let without_key = FormContext::default();

        let Dialog::Idp(d) = Dialog::edit_idp(&idp, &without_key) else {
            unreachable!()
        };

        assert_eq!(d.mfa(), MfaChoice::Ask);
    }
}
