//! The settings page against an in-memory store.

use super::*;
use crate::domain::models::login::{AwsOverrides, RancherOverrides};
use crate::domain::models::settings::AwsAppType;
use crate::domain::models::settings::YubikeyConfig;
use crate::domain::ports::config::{ConfigError, InMemoryConfigStore, MockConfigStore};
use crate::domain::ports::login::LoginResolver;
use crate::domain::ports::secret_wrapper::WrapError;
use crate::domain::services::login_resolver::LoginResolverService;
use crate::domain::services::settings_editor::SettingsService;

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

fn page() -> (Arc<InMemoryConfigStore>, SettingsPage) {
    let store = Arc::new(InMemoryConfigStore::new());
    let page = SettingsPage::new(SettingsService::new(store.clone()));

    (store, page)
}

/// What the CLI would see: another service on the same store.
fn another_service(store: &Arc<InMemoryConfigStore>) -> SettingsService {
    SettingsService::new(store.clone())
}

fn fields(error: &SetupError) -> Vec<Field> {
    error.fields.iter().map(|f| f.field).collect()
}

#[test]
fn nothing_is_configured_at_first() {
    let (_store, page) = page();

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
    let (store, page) = page();

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
    let resolver = LoginResolverService::new(another_service(&store).load().unwrap());
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
    let (store, page) = page();
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

    let login = LoginResolverService::new(another_service(&store).load().unwrap())
        .resolve_aws(&AwsOverrides::default())
        .unwrap();
    assert_eq!(login.username, "other");
    assert_eq!(login.idp_url, "https://lab.example.com");
}

#[test]
fn an_app_has_to_name_an_idp() {
    let (_store, page) = page();
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
fn an_idp_in_use_is_not_removed() {
    let (_store, page) = page();
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
fn every_bad_field_is_reported_and_nothing_is_written() {
    let (store, page) = page();

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
    // The idp `work` is not configured either, and that is reported together with the bad fields.
    assert_eq!(
        fields(&error),
        [Field::RancherUrl, Field::RancherClientId, Field::RancherIdp]
    );

    assert_eq!(store.saves(), 0);
}

#[test]
fn the_keyring_choice_is_kept() {
    let (_store, page) = page();

    assert!(!page.set_use_keyring(false).unwrap().use_keyring);
    assert!(page.set_use_keyring(true).unwrap().use_keyring);
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn a_security_key_is_offered_where_it_works() {
    let (_store, page) = page();
    let mut key = idp("work");
    key.mfa = MfaChoice::SecurityKey;

    let view = page.save_idp(key).unwrap();
    assert_eq!(view.idps[0].mfa, MfaChoice::SecurityKey);
    assert!(view.security_key_supported);
}

#[test]
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn a_security_key_is_refused_where_it_does_not_work() {
    let (_store, page) = page();
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
fn a_failed_save_is_a_readable_error_with_its_cause() {
    let (store, page) = page();
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
fn the_kind_of_error_picks_the_field() {
    use super::errors::edit_error;
    use crate::domain::services::settings_editor::SettingsEditError as E;
    use crate::domain::services::settings_editor::{FieldProblem, InvalidField, Problem};

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
    let problems = || {
        E::InvalidFields(vec![
            FieldProblem {
                field: InvalidField::Url,
                problem: Problem::Message("Bad url.".into()),
            },
            FieldProblem {
                field: InvalidField::Idp,
                problem: Problem::UnknownIdp(key()),
            },
        ])
    };
    let error = edit_error(problems(), Form::Aws);
    assert_eq!(fields(&error), [Field::AwsAppUrl, Field::AwsIdp]);
    assert_eq!(
        error.fields[1].message,
        "There is no identity provider called x. Choose another one."
    );
    assert_eq!(
        fields(&edit_error(problems(), Form::Rancher)),
        [Field::RancherUrl, Field::RancherIdp]
    );
    // The identity provider form has no field for the reference, an action has no fields at all.
    assert_eq!(fields(&edit_error(problems(), Form::Idp)), [Field::IdpUrl]);
    let general = edit_error(problems(), Form::Action);
    assert!(general.fields.is_empty());
    assert!(general.message.unwrap().starts_with("Bad url. "));
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
    let (_store, page) = page();

    let view = page.view().unwrap();
    assert!(!view.security_key_enrolled);
    assert_eq!(view.security_key_rp_id, None);
    assert!(!view.wrap_cached);
}

#[test]
fn a_security_key_is_saved_shown_and_removed() {
    let (store, page) = page();

    let view = page.set_security_key(Some(yubikey())).unwrap();
    assert!(view.security_key_enrolled);
    assert_eq!(view.security_key_rp_id.as_deref(), Some("example.test"));
    assert_eq!(page.view().unwrap(), view);

    // The CLI reads what the page wrote.
    let settings = another_service(&store).load().unwrap();
    assert_eq!(settings.yubikey_config(), Some(&yubikey()));

    let view = page.set_security_key(None).unwrap();
    assert!(!view.security_key_enrolled);
    assert_eq!(view.security_key_rp_id, None);
    assert!(another_service(&store)
        .load()
        .unwrap()
        .yubikey_config()
        .is_none());
}

#[test]
fn wrapping_issued_credentials_is_saved_and_found_by_the_cli() {
    let (store, page) = page();

    assert!(page.set_wrap_cached(true).unwrap().wrap_cached);
    assert!(another_service(&store)
        .load()
        .unwrap()
        .wrap_cached_secrets_enabled());

    assert!(!page.set_wrap_cached(false).unwrap().wrap_cached);
}

#[test]
fn a_missing_security_key_is_explained() {
    let error = security_key::wrap_error(WrapError::DeviceNotPresent);
    assert!(error.sentence().contains("Plug it in"));
    let error = security_key::wrap_error(WrapError::Cancelled);
    assert!(error.sentence().contains("cancelled"));
}

#[test]
fn with_mfa_keeps_form_order() {
    use super::errors::with_mfa;
    use crate::domain::services::settings_editor::{
        FieldProblem, InvalidField, Problem, SettingsEditError as E,
    };
    let problem = |field| FieldProblem {
        field,
        problem: Problem::Message("m".into()),
    };
    let domain = Err(E::InvalidFields(vec![
        problem(InvalidField::Url),
        problem(InvalidField::Idp),
    ]));

    let error = with_mfa(Form::Aws, Field::AwsMfa, "mfa".into(), domain);
    assert_eq!(
        fields(&error),
        [Field::AwsAppUrl, Field::AwsMfa, Field::AwsIdp]
    );

    let error = with_mfa(Form::Idp, Field::IdpMfa, "mfa".into(), Ok(()));
    assert_eq!(fields(&error), [Field::IdpMfa]);
}

#[test]
fn security_keys_need_a_supported_platform() {
    assert!(mfa_selection_on(MfaChoice::SecurityKey, false).is_err());
    assert!(mfa_selection_on(MfaChoice::Totp, false).is_ok());
    assert_eq!(mfa_selection_on(MfaChoice::Ask, false), Ok(None));
    assert!(mfa_selection_on(MfaChoice::SecurityKey, true).is_ok());
}

#[test]
fn a_broken_settings_file_is_a_readable_error() {
    let mut store = MockConfigStore::new();
    store
        .expect_load()
        .returning(|| Err(ConfigError::Failed("this is [not toml".into())));
    let page = SettingsPage::new(SettingsService::new(Arc::new(store)));

    let error = page.save_idp(idp("work")).unwrap_err();
    assert!(error.message.unwrap().contains("settings file"));
}

#[test]
fn a_failed_save_of_the_security_key_is_an_error() {
    let (store, page) = page();
    store.fail_saves();

    assert!(page.set_security_key(Some(yubikey())).is_err());
    assert!(page.set_wrap_cached(true).is_err());
}
