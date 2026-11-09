//! The settings page against a real settings file in a temporary folder.

use super::*;
use crate::domain::models::login::{AwsOverrides, RancherOverrides};
use crate::domain::models::settings::AwsAppType;
use crate::domain::models::settings::YubikeyConfig;
use crate::domain::ports::login::LoginResolver;
use crate::domain::ports::secret_wrapper::WrapError;
use crate::domain::services::login_resolver::LoginResolverService;
use crate::domain::services::settings_editor::SettingsService;
use crate::outbound::config::config_store::ConfigFileAdapter;

const APP_URL: &str = "https://id.example.com/application/saml/aws/sso/binding/init/";
const STORED_APP_URL: &str = "https://id.example.com/application/saml/aws/sso/binding/init";
const RANCHER_URL: &str = "https://rancher.example.com";

fn idp(name: &str) -> IdpForm {
    IdpForm {
        editing: false,
        name: name.into(),
        url: format!(" https://{name}.example.com/ "),
        username: format!("me@{name}.example.com"),
        mfa: MfaChoice::Totp,
    }
}

fn aws() -> AwsAppForm {
    AwsAppForm {
        original: None,
        app_url: APP_URL.into(),
        kind: AwsAppKind::Aws,
        region: None,
        idp: "work".into(),
        username: None,
        mfa: None,
    }
}

fn rancher() -> RancherForm {
    RancherForm {
        original_url: None,
        url: format!("{RANCHER_URL}/"),
        client_id: "rancher".into(),
        idp: "work".into(),
        username: None,
        mfa: None,
    }
}

fn page() -> (tempfile::TempDir, SettingsPage) {
    let dir = tempfile::tempdir().unwrap();
    let settings = SettingsService::new(Arc::new(store(&dir)));
    let page = SettingsPage::new(settings);

    (dir, page)
}

fn store(dir: &tempfile::TempDir) -> ConfigFileAdapter {
    ConfigFileAdapter::at(dir.path().join("c9s").join("settings.toml"))
}

fn fields(error: &SetupError) -> Vec<Field> {
    error.fields.iter().map(|f| f.field).collect()
}

#[test]
fn nothing_is_configured_at_first() {
    let (_dir, page) = page();

    let view = page.view().unwrap();
    assert_eq!(
        view.checklist,
        Checklist {
            idp: false,
            aws: false,
            rancher: false
        }
    );
    assert!(view.idps.is_empty());
    assert!(view.use_keyring);
}

#[test]
fn what_is_set_up_here_is_found_by_the_cli() {
    let (dir, page) = page();

    page.save_idp(idp("work")).unwrap();
    page.save_aws_app(aws()).unwrap();
    let view = page.save_rancher(rancher()).unwrap();
    assert_eq!(
        view.checklist,
        Checklist {
            idp: true,
            aws: true,
            rancher: true
        }
    );
    assert_eq!(view.idps[0].url, "https://work.example.com");
    assert_eq!(view.idps[0].used_by.len(), 2);

    // The CLI reads the same file: `c9s creds aws` and `c9s creds rancher` without flags.
    let resolver =
        LoginResolverService::new(SettingsService::new(Arc::new(store(&dir))).load().unwrap());
    let login = resolver.resolve_aws(&AwsOverrides::default()).unwrap();
    assert_eq!(login.username, "me@work.example.com");
    assert_eq!(login.app_type, AwsAppType::Aws);
    assert_eq!(login.mfa, Some(MfaSelection::Totp));
    let login = resolver
        .resolve_rancher(&RancherOverrides::default())
        .unwrap();
    assert_eq!(login.url, RANCHER_URL);
    assert_eq!(login.client_id, "rancher");
    assert_eq!(login.idp_url, "https://work.example.com");
}

#[test]
fn the_overrides_of_an_app_win_over_its_idp() {
    let (dir, page) = page();
    page.save_idp(idp("work")).unwrap();
    page.save_idp(idp("lab")).unwrap();

    let mut app = aws();
    app.idp = "lab".into();
    app.username = Some(" other ".into());
    app.mfa = Some(MfaChoice::Ask);
    let view = page.save_aws_app(app).unwrap();
    assert_eq!(view.aws_apps[0].idp, "lab");
    assert_eq!(view.aws_apps[0].username.as_deref(), Some("other"));
    // "Ask" as an override is no override.
    assert_eq!(view.aws_apps[0].mfa, None);

    let login =
        LoginResolverService::new(SettingsService::new(Arc::new(store(&dir))).load().unwrap())
            .resolve_aws(&AwsOverrides::default())
            .unwrap();
    assert_eq!(login.username, "other");
    assert_eq!(login.idp_url, "https://lab.example.com");
}

#[test]
fn an_app_has_to_name_an_idp() {
    let (_dir, page) = page();
    page.save_idp(idp("work")).unwrap();

    let mut app = aws();
    app.idp = "  ".into();
    assert_eq!(
        fields(&page.save_aws_app(app).unwrap_err()),
        [Field::AwsIdp]
    );

    let mut app = rancher();
    app.idp = String::new();
    assert_eq!(
        fields(&page.save_rancher(app).unwrap_err()),
        [Field::RancherIdp]
    );
    assert!(page.view().unwrap().aws_apps.is_empty());
}

#[test]
fn a_second_idp_does_not_move_an_app() {
    let (_dir, page) = page();
    page.save_idp(idp("work")).unwrap();
    let view = page.save_aws_app(aws()).unwrap();
    assert_eq!(view.aws_apps[0].idp, "work");

    let view = page.save_idp(idp("lab")).unwrap();
    assert_eq!(view.aws_apps[0].idp, "work");
    assert_eq!(
        view.idps.iter().find(|i| i.name == "lab").unwrap().used_by,
        Vec::<String>::new()
    );
    assert_eq!(
        view.idps
            .iter()
            .find(|i| i.name == "work")
            .unwrap()
            .used_by
            .len(),
        1
    );
}

#[test]
fn an_idp_in_use_is_not_removed() {
    let (_dir, page) = page();
    page.save_idp(idp("work")).unwrap();
    page.save_aws_app(aws()).unwrap();
    page.save_rancher(rancher()).unwrap();

    let error = page.remove_idp("work").unwrap_err();
    let message = error.message.unwrap();
    assert!(message.contains("2 applications"), "{message}");
    assert!(message.contains(RANCHER_URL), "{message}");
    assert_eq!(page.view().unwrap().idps.len(), 1);

    page.remove_aws_app(AwsAppKey {
        app_url: STORED_APP_URL.into(),
        kind: AwsAppKind::Aws,
    })
    .unwrap();
    page.remove_rancher(RANCHER_URL).unwrap();
    let view = page.remove_idp("work").unwrap();
    assert!(view.idps.is_empty());
    assert!(!view.checklist.idp && !view.checklist.aws);
}

#[test]
fn an_edit_can_change_the_url_and_the_kind() {
    let (_dir, page) = page();
    page.save_idp(idp("work")).unwrap();
    page.save_aws_app(aws()).unwrap();
    page.save_rancher(rancher()).unwrap();

    let mut edit = aws();
    edit.original = Some(AwsAppKey {
        app_url: STORED_APP_URL.into(),
        kind: AwsAppKind::Aws,
    });
    edit.kind = AwsAppKind::AwsSso;
    edit.region = Some("eu-west-1".into());
    let view = page.save_aws_app(edit).unwrap();
    assert_eq!(view.aws_apps.len(), 1);
    assert_eq!(view.aws_apps[0].kind, AwsAppKind::AwsSso);
    assert_eq!(view.aws_apps[0].region.as_deref(), Some("eu-west-1"));

    let mut edit = rancher();
    edit.original_url = Some(RANCHER_URL.into());
    edit.url = "https://new.example.com".into();
    let view = page.save_rancher(edit).unwrap();
    assert_eq!(view.rancher_hosts.len(), 1);
    assert_eq!(view.rancher_hosts[0].url, "https://new.example.com");
}

#[test]
fn an_edit_of_an_idp_keeps_its_name() {
    let (_dir, page) = page();
    page.save_idp(idp("work")).unwrap();

    let mut edit = idp("work");
    edit.editing = true;
    edit.username = "new@example.com".into();
    let view = page.save_idp(edit).unwrap();
    assert_eq!(view.idps.len(), 1);
    assert_eq!(view.idps[0].username, "new@example.com");

    // Editing one that is not there is refused, it would add one.
    let mut ghost = idp("ghost");
    ghost.editing = true;
    assert!(page.save_idp(ghost).unwrap_err().message.is_some());
}

#[test]
fn adding_what_exists_is_refused_instead_of_overwriting() {
    let (_dir, page) = page();
    page.save_idp(idp("work")).unwrap();
    page.save_aws_app(aws()).unwrap();
    page.save_rancher(rancher()).unwrap();

    assert_eq!(
        fields(&page.save_idp(idp("work")).unwrap_err()),
        [Field::IdpName]
    );
    assert_eq!(
        fields(&page.save_aws_app(aws()).unwrap_err()),
        [Field::AwsAppUrl]
    );
    assert_eq!(
        fields(&page.save_rancher(rancher()).unwrap_err()),
        [Field::RancherUrl]
    );
    // The same url as the other kind of AWS app is a different app.
    let mut sso = aws();
    sso.kind = AwsAppKind::AwsSso;
    sso.region = Some("eu-west-1".into());
    assert_eq!(page.save_aws_app(sso).unwrap().aws_apps.len(), 2);
}

#[test]
fn every_bad_field_is_reported_and_nothing_is_written() {
    let (dir, page) = page();
    let path = dir.path().join("c9s").join("settings.toml");

    let mut bad = idp("work");
    bad.name = "a/b".into();
    bad.url = "http://id.example.com".into();
    bad.username = " ".into();
    let error = page.save_idp(bad).unwrap_err();
    assert_eq!(
        fields(&error),
        [Field::IdpName, Field::IdpUrl, Field::IdpUsername]
    );

    let mut bad = aws();
    bad.app_url = "https://u:p@id.example.com".into();
    bad.kind = AwsAppKind::AwsSso;
    bad.region = Some("eu-west-1; rm".into());
    bad.username = Some("a\nb".into());
    bad.idp = "x=y".into();
    let error = page.save_aws_app(bad).unwrap_err();
    assert_eq!(
        fields(&error),
        [
            Field::AwsAppUrl,
            Field::AwsRegion,
            Field::AwsUsername,
            Field::AwsIdp
        ]
    );

    let mut bad = rancher();
    bad.url = "javascript:alert(1)".into();
    bad.client_id = "two words".into();
    let error = page.save_rancher(bad).unwrap_err();
    assert_eq!(fields(&error), [Field::RancherUrl, Field::RancherClientId]);

    assert!(!path.exists());
}

#[test]
fn an_app_that_could_not_sign_in_is_not_written() {
    let (dir, page) = page();
    let path = dir.path().join("c9s").join("settings.toml");

    // No identity provider is configured yet.
    assert_eq!(
        fields(&page.save_aws_app(aws()).unwrap_err()),
        [Field::AwsIdp]
    );
    assert_eq!(
        fields(&page.save_rancher(rancher()).unwrap_err()),
        [Field::RancherIdp]
    );
    page.save_idp(idp("work")).unwrap();
    let mut unknown = aws();
    unknown.idp = "nope".into();
    assert_eq!(
        fields(&page.save_aws_app(unknown).unwrap_err()),
        [Field::AwsIdp]
    );

    let saved = std::fs::read_to_string(path).unwrap();
    assert!(!saved.contains("binding"), "{saved}");
}

#[test]
fn the_keyring_choice_is_kept() {
    let (_dir, page) = page();

    assert!(!page.set_use_keyring(false).unwrap().use_keyring);
    assert!(page.set_use_keyring(true).unwrap().use_keyring);
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn a_security_key_is_offered_where_it_works() {
    let (_dir, page) = page();
    let mut key = idp("work");
    key.mfa = MfaChoice::SecurityKey;

    let view = page.save_idp(key).unwrap();
    assert_eq!(view.idps[0].mfa, MfaChoice::SecurityKey);
    assert!(view.security_key_supported);
}

#[test]
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn a_security_key_is_refused_where_it_does_not_work() {
    let (_dir, page) = page();
    let mut key = idp("work");
    key.mfa = MfaChoice::SecurityKey;
    assert_eq!(fields(&page.save_idp(key).unwrap_err()), [Field::IdpMfa]);

    page.save_idp(idp("work")).unwrap();
    let mut app = aws();
    app.mfa = Some(MfaChoice::SecurityKey);
    assert_eq!(
        fields(&page.save_aws_app(app).unwrap_err()),
        [Field::AwsMfa]
    );
}

#[test]
fn a_broken_settings_file_is_a_readable_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.toml");
    std::fs::write(&path, "this is [not toml").unwrap();
    let settings = SettingsService::new(Arc::new(ConfigFileAdapter::at(path)));
    let page = SettingsPage::new(settings);

    let error = page.save_idp(idp("work")).unwrap_err();
    assert!(error.message.unwrap().contains("settings file"));
}

#[test]
fn removing_what_is_not_there_says_so() {
    let (_dir, page) = page();

    assert!(page
        .remove_rancher(RANCHER_URL)
        .unwrap_err()
        .message
        .is_some());
    assert!(page.remove_idp("work").unwrap_err().message.is_some());
}

#[test]
fn a_failed_save_is_a_readable_error_with_its_cause() {
    use crate::domain::ports::config::memory::MemoryStore;

    let store = Arc::new(MemoryStore::default());
    let settings = SettingsService::new(store.clone());
    let page = SettingsPage::new(settings);
    page.save_idp(idp("work")).unwrap();
    store.fail_saves();

    let error = page.save_aws_app(aws()).unwrap_err();
    assert!(error.fields.is_empty());
    let message = error.message.unwrap();
    assert!(message.contains("settings file"), "{message}");
    assert!(message.contains("disk full"), "{message}");
    assert_eq!(store.saves(), 1);
    assert!(page.set_use_keyring(false).is_err());
}

#[test]
fn a_change_that_would_break_an_app_is_refused_and_not_saved() {
    use crate::domain::ports::config::memory::MemoryStore;
    let store = Arc::new(MemoryStore::default());
    let page = SettingsPage::new(SettingsService::new(store.clone()));
    page.save_idp(idp("work")).unwrap();
    page.save_aws_app(aws()).unwrap();
    let saves = store.saves();

    // Pointing the default at nothing the app can use: removing the idp is refused as in use.
    let error = page.remove_idp("work").unwrap_err();
    assert!(error.message.is_some());
    assert_eq!(store.saves(), saves);
}

#[test]
fn the_kind_of_error_picks_the_field() {
    use super::errors::edit_error;
    use crate::domain::services::settings_editor::SettingsEditError as E;

    let key = || "x".to_string();
    assert_eq!(
        fields(&edit_error(E::AlreadyExists { key: key() }, Form::Idp)),
        [Field::IdpName]
    );
    assert_eq!(
        fields(&edit_error(E::AlreadyExists { key: key() }, Form::Aws)),
        [Field::AwsAppUrl]
    );
    assert_eq!(
        fields(&edit_error(E::AlreadyExists { key: key() }, Form::Rancher)),
        [Field::RancherUrl]
    );
    let unknown = || {
        E::Invalid(crate::domain::models::settings::SettingsError::UnknownIdp(
            key(),
        ))
    };
    assert_eq!(fields(&edit_error(unknown(), Form::Aws)), [Field::AwsIdp]);
    assert_eq!(
        fields(&edit_error(unknown(), Form::Rancher)),
        [Field::RancherIdp]
    );
    let gone = edit_error(E::Gone, Form::Aws);
    assert!(gone.fields.is_empty() && gone.message.is_some());
    let broken = edit_error(E::WouldBreak { urls: vec![key()] }, Form::Idp);
    assert!(broken.message.unwrap().contains("Nothing was saved"));
}

fn yubikey() -> YubikeyConfig {
    YubikeyConfig::new(&[1, 2, 3], "example.test", &[7; 32])
}

#[test]
fn no_security_key_is_enrolled_at_first() {
    let (_dir, page) = page();

    let view = page.view().unwrap();
    assert!(!view.security_key_enrolled);
    assert_eq!(view.security_key_rp_id, None);
    assert!(!view.wrap_cached);
}

#[test]
fn a_security_key_is_saved_shown_and_removed() {
    let (dir, page) = page();

    let view = page.set_security_key(Some(yubikey())).unwrap();
    assert!(view.security_key_enrolled);
    assert_eq!(view.security_key_rp_id.as_deref(), Some("example.test"));
    assert_eq!(page.view().unwrap(), view);

    // The CLI reads what the page wrote.
    let settings = SettingsService::new(Arc::new(store(&dir))).load().unwrap();
    assert_eq!(settings.yubikey_config(), Some(&yubikey()));

    let view = page.set_security_key(None).unwrap();
    assert!(!view.security_key_enrolled);
    assert_eq!(view.security_key_rp_id, None);
    assert!(SettingsService::new(Arc::new(store(&dir)))
        .load()
        .unwrap()
        .yubikey_config()
        .is_none());
}

#[test]
fn wrapping_issued_credentials_is_saved_and_found_by_the_cli() {
    let (dir, page) = page();

    assert!(page.set_wrap_cached(true).unwrap().wrap_cached);
    assert!(SettingsService::new(Arc::new(store(&dir)))
        .load()
        .unwrap()
        .wrap_cached_secrets_enabled());

    assert!(!page.set_wrap_cached(false).unwrap().wrap_cached);
}

#[test]
fn a_failed_save_of_the_security_key_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    // The settings file's folder is a file, so nothing can be written.
    let blocker = dir.path().join("c9s");
    std::fs::write(&blocker, "x").unwrap();
    let page = SettingsPage::new(SettingsService::new(Arc::new(store(&dir))));

    assert!(page.set_security_key(Some(yubikey())).is_err());
    assert!(page.set_wrap_cached(true).is_err());
}

#[test]
fn a_missing_security_key_is_explained() {
    let error = security_key::wrap_error(WrapError::DeviceNotPresent);
    assert!(error.sentence().contains("Plug it in"));
    let error = security_key::wrap_error(WrapError::Cancelled);
    assert!(error.sentence().contains("cancelled"));
}
