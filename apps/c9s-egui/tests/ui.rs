//! The window, driven through its accessibility tree (what a screen reader sees), without a native window.
//!
//! Each test uses its own settings file, and checks the file the way the CLI reads it.

use c9s::app::prompts::WindowInteraction;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use c9s::app::settings::SetupError;
use c9s::app::settings::{AwsAppForm, AwsAppType, ExportChoice, IdpForm, MfaChoice, SettingsPage};
use c9s::domain::models::login::{AwsOverrides, RancherOverrides};
use c9s::domain::models::settings::YubikeyConfig;
use c9s::domain::models::user_interaction::SecretPrompt;
use c9s::domain::ports::config::ConfigStore;
use c9s::domain::ports::login::LoginResolver;
use c9s::domain::ports::user_interaction::UserInteraction;
use c9s::domain::services::login_resolver::LoginResolverService;
use c9s::domain::services::settings_editor::SettingsService;
use c9s::outbound::config::bundle::TomlBundleCodec;
use c9s::outbound::config::config_store::ConfigFileAdapter;
use c9s_egui::inbound::app::C9sApp;
use c9s_egui::inbound::settings;
use c9s_egui::outbound::prompts;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use c9s_egui::Enroller;
use c9s_egui::FilePicker;
use eframe::egui::accesskit::Role;
use egui_kittest::kittest::{NodeT, Queryable};
use egui_kittest::Harness;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

const APP_URL: &str = "https://id.example.com/application/saml/aws/sso/binding/init";

struct Window {
    dir: tempfile::TempDir,
}

impl Window {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self) -> PathBuf {
        self.dir.path().join("c9s").join("settings.toml")
    }

    fn store(&self) -> ConfigFileAdapter {
        ConfigFileAdapter::at(self.path())
    }

    /// The app, created on the first frame (it needs the context of the harness).
    fn open(&self) -> Harness<'static, Option<C9sApp>> {
        self.open_with(|_| {})
    }

    /// Like `open`, with `configure` applied to the settings before the app gets them.
    fn open_with(
        &self,
        configure: impl FnOnce(&mut settings::SettingsState) + 'static,
    ) -> Harness<'static, Option<C9sApp>> {
        let path = self.path();
        let mut configure = Some(configure);
        let mut harness = Harness::builder()
            .with_size([900.0, 900.0])
            // A new dialog takes a few frames to find its size (see `ui::dialog::modal`).
            .with_max_steps(12)
            .build_ui_state(
                move |ui, app: &mut Option<C9sApp>| {
                    app.get_or_insert_with(|| {
                        let store = ConfigFileAdapter::at(path.clone());
                        let (bridge, prompts) = prompts::connect(ui.ctx().clone());
                        let mut settings = settings::SettingsState::new(store, bridge.clone());
                        if let Some(configure) = configure.take() {
                            configure(&mut settings);
                        }
                        C9sApp::new(ui.ctx().clone(), settings, bridge, prompts)
                    })
                    .show(ui);
                },
                None,
            );
        harness.run();
        harness
    }

    /// Settings made without the window, as if by `c9s config`.
    fn with_idp_and_aws(&self) {
        let settings = SettingsService::new(Arc::new(self.store()));
        let page = SettingsPage::new(settings);
        page.save_idp(IdpForm {
            editing: false,
            name: "work".into(),
            url: "https://id.example.com".into(),
            username: "me@example.com".into(),
            mfa: MfaChoice::Totp,
        })
        .unwrap();
        page.save_aws_app(AwsAppForm {
            original: None,
            app_url: APP_URL.into(),
            kind: AwsAppType::Aws,
            region: None,
            idp: "work".into(),
            username: None,
            mfa: None,
        })
        .unwrap();
    }
}

fn click_button(harness: &mut Harness<'_, Option<C9sApp>>, name: &str) {
    harness.get_by_role_and_label(Role::Button, name).click();
    harness.run();
}

/// Draws frames until `ready` holds. For what another thread does (a flow asks a question): the window cannot
/// know when it comes, so it is waited for with a deadline and a clear failure, not a fixed number of tries.
fn wait_until(
    harness: &mut Harness<'_, Option<C9sApp>>,
    what: &str,
    ready: impl Fn(&Harness<'_, Option<C9sApp>>) -> bool,
) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        harness.run();
        if ready(harness) {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn type_into(harness: &mut Harness<'_, Option<C9sApp>>, field: &str, text: &str) {
    harness.get_by_label(field).focus();
    harness.run();
    harness.get_by_label(field).type_text(text);
    harness.run();
}

#[test]
fn a_first_run_starts_on_the_checklist() {
    let window = Window::new();
    let harness = window.open();

    harness.get_by_label("Get started");
    harness.get_by_label("Add your identity provider");
    // Only the identity provider is needed, the apps can come later.
    assert_eq!(harness.get_all_by_label("(To do)").count(), 1);
    assert_eq!(harness.get_all_by_label("(Optional)").count(), 2);
}

#[test]
fn an_identity_provider_and_an_aws_account_are_set_up_and_found_by_the_cli() {
    let window = Window::new();
    let mut harness = window.open();

    harness.get_by_label("Add your identity provider").click();
    harness.run();
    click_button(&mut harness, "Add identity provider");
    // The first field has the focus when the dialog opens.
    assert!(harness.get_by_label("Name").is_focused());
    type_into(&mut harness, "Name", "work");
    type_into(&mut harness, "Web address", " https://id.example.com/ ");
    type_into(&mut harness, "User name", "me@example.com");
    click_button(&mut harness, "Save");

    harness.get_by_label("Identity provider work saved.");
    // The focus lands on the entry that was saved.
    assert!(harness
        .get_by_role_and_label(Role::Button, "Edit work")
        .is_focused());

    click_button(&mut harness, "AWS accounts");
    click_button(&mut harness, "Add AWS account");
    type_into(&mut harness, "Web address of the application", APP_URL);
    click_button(&mut harness, "Save");
    harness.get_by_label("AWS account saved.");

    let settings = window.store().load().unwrap();
    let login = LoginResolverService::new(settings)
        .resolve_aws(&AwsOverrides::default())
        .unwrap();
    assert_eq!(login.username, "me@example.com");
    assert_eq!(login.idp_url, "https://id.example.com");
}

#[test]
fn every_bad_field_is_shown_under_it_and_nothing_is_written() {
    let window = Window::new();
    let mut harness = window.open();

    click_button(&mut harness, "Identity providers");
    click_button(&mut harness, "Add identity provider");
    type_into(&mut harness, "Web address", "http://id.example.com");
    click_button(&mut harness, "Save");

    harness.get_by_label("Error: Enter a name, like work");
    harness.get_by_label_contains("Error: The web address must start with https://");
    harness.get_by_label("Error: Enter your user name.");
    harness.get_by_label("Error: 3 problems to fix.");
    // The focus moves to the first field with an error.
    assert!(harness.get_by_label("Name").is_focused());
    assert!(!window.path().exists());

    // Esc closes the dialog without saving.
    harness.key_press(eframe::egui::Key::Escape);
    harness.run();
    assert!(harness.query_by_label("Name").is_none());
}

#[test]
fn an_identity_provider_in_use_is_not_removed() {
    let window = Window::new();
    window.with_idp_and_aws();
    let mut harness = window.open();

    click_button(&mut harness, "Identity providers");
    click_button(&mut harness, "Remove work");
    harness.get_by_label("Remove work?");
    // Removing is chosen on purpose: the focus starts on Cancel.
    assert!(harness
        .get_by_role_and_label(Role::Button, "Cancel")
        .is_focused());
    click_button(&mut harness, "Remove");

    harness.get_by_label_contains("Error: work cannot be removed");
    assert!(harness
        .query_by_role_and_label(Role::Button, "Remove")
        .is_none());
    click_button(&mut harness, "Close");
    assert_eq!(window.store().load().unwrap().idps().len(), 1);
}

#[test]
fn a_rancher_is_set_up_with_the_default_identity_provider() {
    let window = Window::new();
    window.with_idp_and_aws();
    let mut harness = window.open();

    click_button(&mut harness, "Rancher");
    click_button(&mut harness, "Add Rancher");
    type_into(
        &mut harness,
        "Web address of Rancher",
        "https://rancher.example.com",
    );
    click_button(&mut harness, "Save");
    harness.get_by_label("Rancher saved.");

    let settings = window.store().load().unwrap();
    let login = LoginResolverService::new(settings)
        .resolve_rancher(&RancherOverrides::default())
        .unwrap();
    assert_eq!(login.client_id, "rancher");
    assert_eq!(login.username, "me@example.com");
}

#[test]
fn every_input_is_named_by_its_label() {
    let window = Window::new();
    window.with_idp_and_aws();
    let mut harness = window.open();

    for (section, add) in [
        ("Identity providers", "Add identity provider"),
        ("AWS accounts", "Add AWS account"),
        ("Rancher", "Add Rancher"),
    ] {
        click_button(&mut harness, section);
        click_button(&mut harness, add);
        let inputs: Vec<_> = harness.get_all_by_role(Role::TextInput).collect();
        assert!(!inputs.is_empty(), "{add}");
        for input in inputs {
            let name = input.accesskit_node().label().unwrap_or_default();
            assert!(!name.trim().is_empty(), "{add}: an input without a name");
        }
        click_button(&mut harness, "Cancel");
    }
    // Buttons that repeat in every entry say which entry.
    click_button(&mut harness, "Identity providers");
    harness.get_by_role_and_label(Role::Button, "Edit work");
}

#[test]
fn a_password_is_asked_in_the_window_and_not_exposed() {
    let window = Window::new();
    let mut harness = window.open();
    let bridge = harness.state().as_ref().unwrap().bridge();

    // A flow runs on its own thread with its own runtime, as credential flows will.
    let flow = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            WindowInteraction::new(bridge)
                .ask_secret(SecretPrompt::new("Sign in to work", "Password"))
                .await
                .map(|secret| secret.expose_secret().to_string())
        })
    });
    wait_until(&mut harness, "the password question", |h| {
        h.query_by_label("Password").is_some()
    });

    let field = harness.get_by_label("Password");
    assert!(field.is_focused());
    field.type_text("hunter2");
    harness.run();
    // The screen reader and the screen get dots, not the password.
    let shown = harness.get_by_label("Password").value().unwrap_or_default();
    assert!(!shown.contains("hunter2"), "{shown}");
    assert_eq!(shown.chars().count(), 7);
    click_button(&mut harness, "Continue");

    assert_eq!(flow.join().unwrap().unwrap(), "hunter2");
    assert!(harness.query_by_label("Password").is_none());
}

#[test]
#[ignore]
fn credentials_run_as_a_job_that_asks_in_the_window() {
    let window = Window::new();
    window.with_idp_and_aws();
    let mut harness = window.open();

    click_button(&mut harness, "Credentials");
    click_button(&mut harness, &format!("Get credentials {APP_URL}"));
    // The flow runs: the screen says so and offers to cancel it.
    harness.get_by_role_and_label(Role::Button, "Cancel");
    // The question of the flow is on top; nothing can be started again meanwhile.
    wait_until(&mut harness, "the question of the flow", |h| {
        h.query_by_label("Credentials are not available yet")
            .is_some()
    });
    harness.get_by_role_and_label(Role::Button, "Yes").click();
    harness.run();

    wait_until(&mut harness, "the end of the flow", |h| {
        h.query_by_label_contains("Pretended to sign in").is_some()
    });
    // The job is over: the buttons are back.
    assert!(harness
        .query_by_role_and_label(Role::Button, "Cancel")
        .is_none());
}

#[test]
#[ignore]
fn a_cancelled_question_ends_the_flow_with_an_error() {
    let window = Window::new();
    window.with_idp_and_aws();
    let mut harness = window.open();

    click_button(&mut harness, "Credentials");
    click_button(&mut harness, &format!("Get credentials {APP_URL}"));
    wait_until(&mut harness, "the question of the flow", |h| {
        h.query_by_label("Credentials are not available yet")
            .is_some()
    });
    // Esc cancels the question; the flow then ends with an error.
    harness.key_press(eframe::egui::Key::Escape);
    wait_until(&mut harness, "the end of the flow", |h| {
        h.query_by_label_contains("Error:").is_some()
    });
    assert!(harness
        .query_by_label("Credentials are not available yet")
        .is_none());
}

const WRAP_LABEL: &str = "Encrypt issued credentials (AWS/Rancher)";

fn yubikey() -> YubikeyConfig {
    YubikeyConfig::new(&[1, 2, 3], "example.test", &[7; 32])
}

/// The enroller of a test: no key is touched.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn enroller(result: Result<YubikeyConfig, SetupError>) -> Enroller {
    Arc::new(move |_rp_id, _bridge| result.clone())
}

fn wrap_checkbox<'a>(harness: &'a Harness<'_, Option<C9sApp>>) -> egui_kittest::Node<'a> {
    harness.get_by_role_and_label(Role::CheckBox, WRAP_LABEL)
}

#[test]
fn the_keyring_choice_is_on_the_security_page() {
    let window = Window::new();
    let mut harness = window.open();

    click_button(&mut harness, "Security");
    harness
        .get_by_role_and_label(
            Role::CheckBox,
            "Remember my password in the system keyring (recommended)",
        )
        .click();
    harness.run();

    assert!(!window.store().load().unwrap().keyring_enabled());
}

#[test]
fn issued_credentials_can_only_be_encrypted_with_a_key_enrolled() {
    let window = Window::new();
    let mut harness = window.open();

    click_button(&mut harness, "Security");
    harness.get_by_label("Status: Not enrolled");
    assert!(wrap_checkbox(&harness).accesskit_node().is_disabled());
    assert!(harness
        .query_by_role_and_label(Role::Button, "Disable security key")
        .is_none());
}

#[test]
fn issued_credentials_are_encrypted_when_chosen() {
    let window = Window::new();
    let settings = SettingsService::new(Arc::new(window.store()));
    SettingsPage::new(settings)
        .set_security_key(Some(yubikey()))
        .unwrap();
    let mut harness = window.open();

    click_button(&mut harness, "Security");
    harness.get_by_label("Status: Enrolled (example.test)");
    assert!(!wrap_checkbox(&harness).accesskit_node().is_disabled());
    wrap_checkbox(&harness).click();
    harness.run();

    assert!(window.store().load().unwrap().wrap_cached_secrets_enabled());
}

#[test]
fn a_security_key_is_disabled_after_asking() {
    let window = Window::new();
    let settings = SettingsService::new(Arc::new(window.store()));
    SettingsPage::new(settings)
        .set_security_key(Some(yubikey()))
        .unwrap();
    let mut harness = window.open();

    click_button(&mut harness, "Security");
    click_button(&mut harness, "Disable security key");
    harness.get_by_label("Disable the security key?");
    // Cancel leaves it as it was.
    click_button(&mut harness, "Cancel");
    assert!(window.store().load().unwrap().yubikey_config().is_some());

    click_button(&mut harness, "Disable security key");
    click_button(&mut harness, "Disable");
    harness.get_by_label("Security key disabled.");
    harness.get_by_label("Status: Not enrolled");
    assert!(window.store().load().unwrap().yubikey_config().is_none());
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn a_security_key_is_enrolled_and_found_by_the_cli() {
    let window = Window::new();
    let mut harness = window.open_with(move |s| s.enrolling.enroller = enroller(Ok(yubikey())));

    click_button(&mut harness, "Security");
    click_button(&mut harness, "Enroll security key");
    wait_until(&mut harness, "the end of the enrolling", |h| {
        h.query_by_label("Security key enrolled.").is_some()
    });

    harness.get_by_label("Status: Enrolled (example.test)");
    assert_eq!(
        window.store().load().unwrap().yubikey_config(),
        Some(&yubikey())
    );
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn a_failed_enrolling_is_shown_and_nothing_is_written() {
    let window = Window::new();
    let mut harness = window.open_with(move |s| {
        s.enrolling.enroller = enroller(Err(SetupError::general(
            "No security key was found. Plug it in and try again.",
        )))
    });

    click_button(&mut harness, "Security");
    click_button(&mut harness, "Enroll security key");
    wait_until(&mut harness, "the end of the enrolling", |h| {
        h.query_by_label_contains("No security key was found")
            .is_some()
    });

    harness.get_by_label("Status: Not enrolled");
    assert!(!window.path().exists());
}

#[test]
fn a_set_up_window_starts_on_credentials_without_the_checklist() {
    let window = Window::new();
    window.with_idp_and_aws();
    let harness = window.open();

    harness.get_by_label("Nothing here yet.");
    assert!(harness.query_by_label("Get started").is_none());
    assert!(harness
        .query_by_role_and_label(Role::Button, "Setup")
        .is_none());
}

/// The chooser of a test: the user always picks `path`, no dialog opens.
fn chooser(path: Option<PathBuf>) -> FilePicker {
    Arc::new(move |_pick| path.clone())
}

#[test]
fn export_and_import_live_on_their_own_page() {
    let window = Window::new();
    window.with_idp_and_aws();
    let mut harness = window.open();

    click_button(&mut harness, "Identity providers");
    assert!(harness.query_by_label("Export…").is_none());
    assert!(harness.query_by_label("Import…").is_none());

    click_button(&mut harness, "Import / Export");
    harness.get_by_label("Export…");
    harness.get_by_label("Import…");
}

#[test]
fn identity_providers_are_exported_to_a_file_without_security_settings() {
    let window = Window::new();
    window.with_idp_and_aws();
    let settings = SettingsService::new(Arc::new(window.store()));
    SettingsPage::new(settings)
        .set_security_key(Some(yubikey()))
        .unwrap();
    let file = window.dir.path().join("share.toml");
    let mut harness = window.open_with({
        let file = file.clone();
        move |s| s.transfer.picker = chooser(Some(file))
    });

    click_button(&mut harness, "Import / Export");
    click_button(&mut harness, "Export…");
    harness.get_by_label("Export onboarding file");
    click_button(&mut harness, "Choose file…");
    wait_until(&mut harness, "the export", |h| {
        h.query_by_label_contains("Exported to").is_some()
    });

    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.contains("name = \"work\"") && text.contains("[[aws_hosts]]"));
    assert!(!text.contains("yubikey") && !text.contains("global_settings"));
    assert!(!text.contains("username") && !text.contains("me@example.com"));
}

#[test]
fn an_app_that_is_unchecked_is_left_out_of_the_export() {
    let window = Window::new();
    window.with_idp_and_aws();
    let file = window.dir.path().join("share.toml");
    let mut harness = window.open_with({
        let file = file.clone();
        move |s| s.transfer.picker = chooser(Some(file))
    });

    click_button(&mut harness, "Import / Export");
    click_button(&mut harness, "Export…");
    // Every app starts checked.
    let app = format!("AWS: {APP_URL}");
    harness.get_by_label_contains(&app).click();
    harness.run();
    click_button(&mut harness, "Choose file…");
    wait_until(&mut harness, "the export", |h| {
        h.query_by_label_contains("Exported to").is_some()
    });

    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.contains("name = \"work\""));
    assert!(!text.contains("[[aws_hosts]]"), "{text}");
}

#[test]
fn an_export_needs_an_identity_provider_chosen() {
    let window = Window::new();
    window.with_idp_and_aws();
    let file = window.dir.path().join("share.toml");
    let mut harness = window.open_with({
        let file = file.clone();
        move |s| s.transfer.picker = chooser(Some(file))
    });

    click_button(&mut harness, "Import / Export");
    click_button(&mut harness, "Export…");
    harness
        .get_by_role_and_label(Role::CheckBox, "work")
        .click();
    harness.run();
    click_button(&mut harness, "Choose file…");

    // The dialog stays, and nothing is written.
    harness.get_by_label("Export onboarding file");
    assert!(!file.exists());
}

#[test]
fn a_file_is_imported_and_found_by_the_cli() {
    let sharer = Window::new();
    sharer.with_idp_and_aws();
    let file = sharer.dir.path().join("share.toml");
    let settings = SettingsService::new(Arc::new(sharer.store()));
    SettingsPage::new(settings)
        .export_choice_to_file(
            &TomlBundleCodec,
            &ExportChoice::new(vec!["work".into()], vec![APP_URL.into()], vec![]),
            &file,
        )
        .unwrap();

    let window = Window::new();
    let mut harness = window.open_with(move |s| s.transfer.picker = chooser(Some(file)));

    click_button(&mut harness, "Import / Export");
    click_button(&mut harness, "Import…");
    // The file holds no user name: it is asked for.
    wait_until(&mut harness, "the question for the user name", |h| {
        h.query_by_label("Import onboarding file").is_some()
    });
    click_button(&mut harness, "Import");
    harness.get_by_label_contains("Enter your user name.");
    assert!(!window.path().exists());

    type_into(&mut harness, "User name for work", "newcomer@example.com");
    click_button(&mut harness, "Import");
    harness.get_by_label("Imported: 2 added.");

    let settings = window.store().load().unwrap();
    let login = LoginResolverService::new(settings)
        .resolve_aws(&AwsOverrides::default())
        .unwrap();
    // The user name is the importer's, not the one of the exporter.
    assert_eq!(login.username, "newcomer@example.com");
}

#[test]
fn importing_the_same_file_again_says_nothing_is_new() {
    let sharer = Window::new();
    sharer.with_idp_and_aws();
    let file = sharer.dir.path().join("share.toml");
    SettingsPage::new(SettingsService::new(Arc::new(sharer.store())))
        .export_choice_to_file(
            &TomlBundleCodec,
            &ExportChoice::new(vec!["work".into()], vec![APP_URL.into()], vec![]),
            &file,
        )
        .unwrap();

    let window = Window::new();
    let mut harness = window.open_with(move |s| s.transfer.picker = chooser(Some(file)));

    click_button(&mut harness, "Import / Export");
    click_button(&mut harness, "Import…");
    wait_until(&mut harness, "the question for the user name", |h| {
        h.query_by_label("Import onboarding file").is_some()
    });
    type_into(&mut harness, "User name for work", "newcomer@example.com");
    click_button(&mut harness, "Import");
    harness.get_by_label("Imported: 2 added.");

    click_button(&mut harness, "Import…");
    wait_until(&mut harness, "the second report", |h| {
        h.query_by_label("Nothing new to import, 2 were set up already.")
            .is_some()
    });
}

#[test]
fn a_file_that_is_not_an_export_is_refused_and_nothing_is_written() {
    let window = Window::new();
    let file = window.dir.path().join("junk.toml");
    std::fs::write(&file, "[global_settings]\nuse_keyring = false\n").unwrap();
    let mut harness = window.open_with(move |s| s.transfer.picker = chooser(Some(file)));

    click_button(&mut harness, "Import / Export");
    click_button(&mut harness, "Import…");
    wait_until(&mut harness, "the refusal", |h| {
        h.query_by_label_contains("cannot be imported").is_some()
    });

    assert!(!window.path().exists());
}

#[test]
fn closing_the_file_dialog_changes_nothing() {
    let window = Window::new();
    let mut harness = window.open_with(move |s| s.transfer.picker = chooser(None));

    click_button(&mut harness, "Import / Export");
    click_button(&mut harness, "Import…");
    for _ in 0..5 {
        harness.run();
        std::thread::sleep(Duration::from_millis(5));
    }

    assert!(!window.path().exists());
    assert!(harness.query_by_label_contains("Imported").is_none());
}

#[test]
fn a_first_run_is_set_up_by_importing_a_file() {
    let sharer = Window::new();
    sharer.with_idp_and_aws();
    let file = sharer.dir.path().join("share.toml");
    let settings = SettingsService::new(Arc::new(sharer.store()));
    SettingsPage::new(settings)
        .export_choice_to_file(
            &TomlBundleCodec,
            &ExportChoice::new(vec!["work".into()], vec![APP_URL.into()], vec![]),
            &file,
        )
        .unwrap();

    let window = Window::new();
    let mut harness = window.open_with(move |s| s.transfer.picker = chooser(Some(file)));

    harness.get_by_label("Get started");
    click_button(&mut harness, "Import an onboarding file…");
    wait_until(&mut harness, "the question for the user name", |h| {
        h.query_by_label("Import onboarding file").is_some()
    });
    type_into(&mut harness, "User name for work", "newcomer@example.com");
    click_button(&mut harness, "Import");

    // Both steps are done, with no manual set up.
    harness.get_by_label("You are set up");
    assert_eq!(harness.get_all_by_label("(Done)").count(), 2);
    assert!(harness
        .query_by_role_and_label(Role::Button, "Import an onboarding file…")
        .is_none());

    // The way out is next, and leaves the checklist.
    assert!(harness
        .get_by_role_and_label(Role::Button, "Finish setup")
        .is_focused());
    click_button(&mut harness, "Finish setup");
    harness.get_by_label("Nothing here yet.");
    assert!(harness
        .query_by_role_and_label(Role::Button, "Setup")
        .is_none());
}

#[test]
fn an_identity_provider_alone_is_enough_to_be_set_up() {
    let window = Window::new();
    let settings = SettingsService::new(Arc::new(window.store()));
    SettingsPage::new(settings)
        .save_idp(IdpForm {
            editing: false,
            name: "work".into(),
            url: "https://id.example.com".into(),
            username: "me@example.com".into(),
            mfa: MfaChoice::Totp,
        })
        .unwrap();
    let harness = window.open();

    // It starts on credentials, with no checklist in the way.
    harness.get_by_label("Nothing here yet.");
    assert!(harness
        .query_by_role_and_label(Role::Button, "Setup")
        .is_none());
    // Nothing is marked as still to do in the sidebar: the apps are added when they are wanted.
    assert!(harness.query_by_label("!").is_none());
}
