use super::apply::*;
use super::service::check_mode;
use super::*;
use crate::domain::models::idp::IdpType;
use crate::domain::models::login::{LoginTarget, ResolveError};
use crate::domain::models::settings::*;
use crate::domain::ports::config::ConfigError;
use crate::domain::ports::config::MockConfigStore;
use crate::domain::ports::login_check::LoginCheck;
use crate::domain::ports::login_check::{MockLoginCheck, NoLoginCheck};
use crate::outbound::config::in_memory::InMemoryConfigStore;
use std::collections::BTreeMap;
use std::sync::Arc;

const IDP_URL: &str = "https://id.example.com/";
const APP_URL: &str = "https://id.example.com/application/saml/aws/sso/binding/init/";

fn fields_of(problems: &[FieldProblem]) -> Vec<InvalidField> {
    problems.iter().map(|p| p.field).collect()
}

fn is_unknown_idp(error: &SettingsEditError) -> bool {
    matches!(error, SettingsEditError::InvalidFields(problems)
            if matches!(problems.as_slice(), [FieldProblem { field: InvalidField::Idp, problem: Problem::UnknownIdp(_) }]))
}

fn idp_input() -> IdpInput {
    IdpInput::new("suse", IdpType::Authentik, IDP_URL, "user")
}

#[test]
fn adds_an_idp() {
    let mut settings = AppConfig::default();
    apply_idp(&mut settings, idp_input()).unwrap();

    let idp = settings.resolve_idp("suse").unwrap();
    assert_eq!(idp.name(), "suse");
    assert_eq!(idp.url(), "https://id.example.com");
}

#[test]
fn refuses_an_idp_with_a_bad_url() {
    let mut settings = AppConfig::default();
    let mut input = idp_input();
    input.url = "not a url".into();

    assert!(matches!(
        apply_idp(&mut settings, input),
        Err(SettingsEditError::InvalidFields(problems))
            if fields_of(&problems) == [InvalidField::Url]
    ));
    assert!(settings.idps().is_empty());
}

#[test]
fn an_app_needs_a_configured_idp() {
    let mut settings = AppConfig::default();
    let err = apply_aws_app(&mut settings, AwsAppInput::new(APP_URL, "suse"))
        .map(|_| ())
        .unwrap_err();
    assert!(is_unknown_idp(&err));

    apply_idp(&mut settings, idp_input()).unwrap();
    apply_aws_app(&mut settings, AwsAppInput::new(APP_URL, "suse")).unwrap();
    assert_eq!(settings.aws_hosts().len(), 1);
    assert_eq!(settings.aws_hosts()[0].idp(), "suse");
}

#[test]
fn an_app_uses_the_only_idp() {
    let mut settings = AppConfig::default();
    apply_idp(&mut settings, idp_input()).unwrap();

    apply_aws_sso_app(
        &mut settings,
        AwsAppInput::new(APP_URL, "suse"),
        "eu-west-1",
    )
    .unwrap();
    assert_eq!(settings.aws_sso_hosts()[0].region(), "eu-west-1");
}

#[test]
fn an_app_cannot_name_an_unknown_idp() {
    let mut settings = AppConfig::default();
    let input = AwsAppInput::new(APP_URL, "nope");

    assert!(is_unknown_idp(
        &apply_aws_app(&mut settings, input).unwrap_err()
    ));
}

#[test]
fn rancher_needs_a_configured_idp() {
    let mut settings = AppConfig::default();
    let input = RancherInput::new("https://rancher.example.com", "rancher", "suse");
    assert!(is_unknown_idp(
        &apply_rancher(&mut settings, input.clone()).unwrap_err()
    ));

    apply_idp(&mut settings, idp_input()).unwrap();
    apply_rancher(&mut settings, input).unwrap();
    assert_eq!(settings.rancher_hosts().len(), 1);
}

#[test]
fn every_problem_is_returned_together_in_form_order() {
    use InvalidField::*;
    let mut settings = AppConfig::default();
    let fields = |e: SettingsEditError| match e {
        SettingsEditError::InvalidFields(problems) => fields_of(&problems),
        other => panic!("not field problems: {other}"),
    };

    let mut bad = idp_input();
    bad.name = "a/b".into();
    bad.url = "nope".into();
    bad.username = " ".into();
    let err = apply_idp(&mut settings, bad).unwrap_err();
    assert_eq!(fields(err), [Name, Url, Username]);

    let mut input = AwsAppInput::new("not a url", "suse");
    input.username = Some("a\nb".into());
    let err = apply_aws_sso_app(&mut settings, input, "mars").unwrap_err();
    assert_eq!(fields(err), [Url, Region, Username, Idp]);

    let mut input = RancherInput::new("not a url", "", "suse");
    input.username = Some("a\nb".into());
    let err = apply_rancher(&mut settings, input).unwrap_err();
    assert_eq!(fields(err), [Url, ClientId, Username, Idp]);

    let err = apply_aws_app(&mut settings, AwsAppInput::new("not a url", "suse")).unwrap_err();
    match err {
        SettingsEditError::InvalidFields(problems) => {
            assert_eq!(fields_of(&problems), [Url, Idp]);
            assert_eq!(problems[1].problem, Problem::UnknownIdp("suse".into()));
        }
        other => panic!("not field problems: {other}"),
    }
}

#[test]
fn a_blank_idp_reference_is_a_field_problem() {
    let mut settings = AppConfig::default();
    let err = apply_aws_app(&mut settings, AwsAppInput::new(APP_URL, "  ")).unwrap_err();
    match err {
        SettingsEditError::InvalidFields(problems) => assert_eq!(
            problems,
            [FieldProblem {
                field: InvalidField::Idp,
                problem: Problem::Message("Choose an identity provider.".into())
            }]
        ),
        other => panic!("not field problems: {other}"),
    }
}

#[test]
fn display_joins_the_messages() {
    let mut settings = AppConfig::default();
    let err = apply_aws_app(&mut settings, AwsAppInput::new("not a url", "suse")).unwrap_err();
    let text = err.to_string();
    assert!(
        text.ends_with("the identity provider \"suse\" is not configured, run `c9s config idp`")
    );
    assert!(
        text.contains(". ") || text.contains("web address"),
        "{text}"
    );
}

#[test]
fn two_services_on_one_store_see_each_others_saved_changes() {
    let store = Arc::new(InMemoryConfigStore::default());
    let first = SettingsService::new(store.clone());
    let second = SettingsService::new(store.clone());

    first.save_idp(idp_input(), SaveAs::Upsert).unwrap();

    assert_eq!(second.load().unwrap().idps().len(), 1);
}

#[test]
fn update_saves_once_on_success_and_never_on_error() {
    let store = Arc::new(InMemoryConfigStore::default());
    let service = SettingsService::new(store.clone());

    let err = service
        .update(|config| apply_aws_app(config, AwsAppInput::new(APP_URL, "suse")))
        .map(|_| ())
        .unwrap_err();
    assert!(is_unknown_idp(&err));
    assert_eq!(store.saves(), 0);

    let saved = service
        .update(|config| apply_idp(config, idp_input()))
        .unwrap();
    assert_eq!(saved.idps().len(), 1);
    assert_eq!(store.saves(), 1);
    assert_eq!(service.load().unwrap().idps().len(), 1);
    assert_eq!(store.saves(), 1, "load does not save");
}

#[test]
fn a_failed_save_is_an_error_with_its_cause() {
    let store = Arc::new(InMemoryConfigStore::default());
    store.fail_saves();
    let service = SettingsService::new(store.clone());

    let err = service.set_use_keyring(false).map(|_| ()).unwrap_err();
    assert!(matches!(err, SettingsEditError::Store(_)));
    assert!(err.to_string().contains("disk full"), "{err}");
}

#[test]
fn a_failed_load_saves_nothing() {
    let mut mock = MockConfigStore::new();
    mock.expect_load()
        .returning(|| Err(ConfigError::Failed("unreadable".into())));
    mock.expect_save().never();
    let service = SettingsService::new(Arc::new(mock));

    assert!(matches!(
        service.set_wrap_cached_secrets(true),
        Err(SettingsEditError::Store(_))
    ));
}

/// A check that fails for every app, or only for those the settings no longer have an identity provider for.
struct FailAfterRemoval;

impl LoginCheck for FailAfterRemoval {
    fn resolves(&self, settings: &AppConfig, _: &LoginTarget) -> Result<(), ResolveError> {
        if settings.find_idp("suse").is_some() {
            Ok(())
        } else {
            Err(ResolveError::RancherNotConfigured)
        }
    }
}

fn failing_check() -> MockLoginCheck {
    let mut check = MockLoginCheck::new();
    check
        .expect_resolves()
        .returning(|_, _| Err(ResolveError::RancherNotConfigured));
    check
}

#[test]
fn a_change_that_breaks_an_app_is_refused() {
    let store = Arc::new(InMemoryConfigStore::default());
    let setup = SettingsService::with_login_check(store.clone(), NoLoginCheck);
    setup.save_idp(idp_input(), SaveAs::New).unwrap();
    setup
        .save_aws_app(
            AwsAppInput::new(APP_URL, "suse"),
            AwsAppKind::Aws,
            SaveAs::New,
        )
        .unwrap();
    let saves = store.saves();

    // The app resolved before; the edit leaves it without its identity provider.
    let service = SettingsService::with_login_check(store.clone(), FailAfterRemoval);
    let err = service
        .edit(|_, config| {
            config.remove_idp("suse");
            Ok(vec![])
        })
        .map(|_| ())
        .unwrap_err();
    match err {
        SettingsEditError::WouldBreak { urls } => assert_eq!(urls.len(), 1),
        other => panic!("{other:?}"),
    }
    assert_eq!(store.saves(), saves);

    // `update` does not look.
    service
        .update(|config| {
            config.remove_idp("suse");
            Ok(())
        })
        .unwrap();
    assert_eq!(store.saves(), saves + 1);
}

fn bundle_of_two() -> SettingsBundle {
    let mut settings = with_idps(&["suse"]);
    apply_aws_app(&mut settings, AwsAppInput::new(APP_URL, "suse")).unwrap();
    apply_rancher(
        &mut settings,
        RancherInput::new("https://rancher.example.com", "c", "suse"),
    )
    .unwrap();
    settings.export(&["suse".to_string()]).unwrap()
}

#[test]
fn checks_run_for_every_kind_and_for_the_cli_constructor() {
    let store = Arc::new(InMemoryConfigStore::default());
    let service = SettingsService::new(store.clone());
    service.save_idp(idp_input(), SaveAs::New).unwrap();
    service
        .save_aws_app(
            AwsAppInput::new(APP_URL, "suse"),
            AwsAppKind::Aws,
            SaveAs::New,
        )
        .unwrap();
    service
        .save_aws_app(
            AwsAppInput::new(APP_URL, "suse"),
            AwsAppKind::AwsSso {
                region: "eu-west-1".into(),
            },
            SaveAs::New,
        )
        .unwrap();
    service
        .save_rancher(
            RancherInput::new("https://rancher.example.com", "c", "suse"),
            SaveAs::New,
        )
        .unwrap();
    let fresh = SettingsService::new(Arc::new(InMemoryConfigStore::default()));
    fresh.save_idp(idp_input(), SaveAs::New).unwrap();
    fresh
        .import(&bundle_of_two(), ImportMode::Overwrite, &BTreeMap::new())
        .unwrap();
}

#[test]
fn a_failing_check_saves_nothing_for_aws_rancher_and_import() {
    let store = Arc::new(InMemoryConfigStore::default());
    SettingsService::with_login_check(store.clone(), NoLoginCheck)
        .save_idp(idp_input(), SaveAs::New)
        .unwrap();
    let saves = store.saves();
    let service = SettingsService::with_login_check(store.clone(), failing_check());

    let aws = service.save_aws_app(
        AwsAppInput::new(APP_URL, "suse"),
        AwsAppKind::Aws,
        SaveAs::New,
    );
    assert!(matches!(aws, Err(SettingsEditError::DoesNotResolve(_))));
    assert_eq!(store.saves(), saves);

    let rancher = service.save_rancher(
        RancherInput::new("https://rancher.example.com", "c", "suse"),
        SaveAs::New,
    );
    assert!(matches!(rancher, Err(SettingsEditError::DoesNotResolve(_))));
    assert_eq!(store.saves(), saves);

    let import = service.import(&bundle_of_two(), ImportMode::Overwrite, &BTreeMap::new());
    assert!(matches!(import, Err(SettingsEditError::DoesNotResolve(_))));
    assert_eq!(store.saves(), saves);
}

#[test]
fn import_checks_only_what_it_wrote() {
    let store = Arc::new(InMemoryConfigStore::default());
    let setup = SettingsService::with_login_check(store.clone(), NoLoginCheck);
    setup.save_idp(idp_input(), SaveAs::New).unwrap();
    setup
        .save_aws_app(
            AwsAppInput::new(APP_URL, "suse"),
            AwsAppKind::Aws,
            SaveAs::New,
        )
        .unwrap();

    // Only the Rancher is new: the AWS app is skipped, so one touched check plus the regression pass
    // (before and after) for each of the two apps of the result.
    let mut check = MockLoginCheck::new();
    check
        .expect_resolves()
        .withf(|_, target| matches!(target, LoginTarget::Rancher { .. }))
        .times(3)
        .returning(|_, _| Ok(()));
    check
        .expect_resolves()
        .withf(|_, target| matches!(target, LoginTarget::Aws { .. }))
        .times(2)
        .returning(|_, _| Ok(()));
    let service = SettingsService::with_login_check(store, check);
    let (_, report) = service
        .import(&bundle_of_two(), ImportMode::SkipExisting, &BTreeMap::new())
        .unwrap();

    assert_eq!(report.added(), 1);
    assert_eq!(report.skipped(), 2);
}

#[test]
fn no_login_check_lets_everything_through() {
    let store = Arc::new(InMemoryConfigStore::default());
    let service = SettingsService::with_login_check(store, NoLoginCheck);
    service.save_idp(idp_input(), SaveAs::New).unwrap();
    service
        .save_aws_app(
            AwsAppInput::new(APP_URL, "suse"),
            AwsAppKind::Aws,
            SaveAs::New,
        )
        .unwrap();
}

#[test]
fn check_mode_applies_the_existence_rule() {
    use SaveAs::{New, Replace, Upsert};
    let ok = |m: SaveAs<()>, taken: bool, old: bool| check_mode(&m, "k", taken, |_| old).is_ok();
    let is = |m: SaveAs<()>, taken: bool, old: bool, want: fn(&SettingsEditError) -> bool| {
        check_mode(&m, "k", taken, |_| old).map_err(|e| want(&e)) == Err(true)
    };
    assert!(ok(Upsert, true, false));
    assert!(ok(Upsert, false, true));
    assert!(ok(New, false, false));
    assert!(is(New, true, true, |e| matches!(
        e,
        SettingsEditError::AlreadyExists { .. }
    )));
    assert!(ok(Replace(()), true, true));
    assert!(ok(Replace(()), false, true));
    assert!(is(Replace(()), true, false, |e| matches!(
        e,
        SettingsEditError::Gone
    )));
}

#[test]
fn new_refuses_what_exists_and_replace_refuses_what_is_gone() {
    let store = Arc::new(InMemoryConfigStore::default());
    let service = SettingsService::new(store.clone());
    service.save_idp(idp_input(), SaveAs::New).unwrap();
    service
        .save_aws_app(
            AwsAppInput::new(APP_URL, "suse"),
            AwsAppKind::Aws,
            SaveAs::New,
        )
        .unwrap();
    service
        .save_rancher(
            RancherInput::new("https://rancher.example.com", "rancher", "suse"),
            SaveAs::New,
        )
        .unwrap();
    let saves = store.saves();

    assert!(matches!(
        service.save_idp(idp_input(), SaveAs::New),
        Err(SettingsEditError::AlreadyExists { .. })
    ));
    assert!(matches!(
        service.save_aws_app(
            AwsAppInput::new(APP_URL, "suse"),
            AwsAppKind::Aws,
            SaveAs::New
        ),
        Err(SettingsEditError::AlreadyExists { .. })
    ));
    assert!(matches!(
        service.save_rancher(
            RancherInput::new("https://rancher.example.com/", "rancher", "suse"),
            SaveAs::New
        ),
        Err(SettingsEditError::AlreadyExists { .. })
    ));
    assert!(matches!(
        service.save_idp(idp_named("ghost"), SaveAs::Replace(())),
        Err(SettingsEditError::Gone)
    ));
    assert!(matches!(
        service.save_aws_app(
            AwsAppInput::new(APP_URL, "suse"),
            AwsAppKind::Aws,
            SaveAs::Replace(("https://nope.example.com".into(), AwsAppType::Aws))
        ),
        Err(SettingsEditError::Gone)
    ));
    assert!(matches!(
        service.save_rancher(
            RancherInput::new("https://rancher.example.com", "rancher", "suse"),
            SaveAs::Replace("https://nope.example.com".into())
        ),
        Err(SettingsEditError::Gone)
    ));
    assert_eq!(store.saves(), saves);

    // Saving over itself, and upserting, are fine.
    service
        .save_aws_app(
            AwsAppInput::new(APP_URL, "suse"),
            AwsAppKind::Aws,
            SaveAs::Replace((APP_URL.into(), AwsAppType::Aws)),
        )
        .unwrap();
    service.save_idp(idp_input(), SaveAs::Upsert).unwrap();
    assert_eq!(store.saves(), saves + 2);

    // The same url as the other kind of AWS app is a different app.
    let config = service
        .save_aws_app(
            AwsAppInput::new(APP_URL, "suse"),
            AwsAppKind::AwsSso {
                region: "eu-west-1".into(),
            },
            SaveAs::New,
        )
        .unwrap();
    assert_eq!(config.aws_hosts().len(), 1);
    assert_eq!(config.aws_sso_hosts().len(), 1);
}

#[test]
fn a_replace_onto_another_entry_is_refused() {
    let store = Arc::new(InMemoryConfigStore::default());
    let service = SettingsService::new(store.clone());
    service.save_idp(idp_input(), SaveAs::New).unwrap();
    let other = "https://id.example.com/application/saml/other/sso/binding/init";
    for url in [APP_URL, other] {
        service
            .save_aws_app(AwsAppInput::new(url, "suse"), AwsAppKind::Aws, SaveAs::New)
            .unwrap();
    }
    let saves = store.saves();

    let err = service
        .save_aws_app(
            AwsAppInput::new(other, "suse"),
            AwsAppKind::Aws,
            SaveAs::Replace((APP_URL.into(), AwsAppType::Aws)),
        )
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(err, SettingsEditError::AlreadyExists { .. }));
    assert_eq!(store.saves(), saves);
    assert_eq!(service.load().unwrap().aws_hosts().len(), 2);
}

#[test]
fn a_replace_that_only_tidies_the_url_is_not_a_collision() {
    let store = Arc::new(InMemoryConfigStore::default());
    let service = SettingsService::new(store.clone());
    let idp = IdpInput::new("suse", IdpType::Authentik, IDP_URL, "user");
    service.save_idp(idp, SaveAs::New).unwrap();
    let slash = "https://id.example.com/app/init/";
    let plain = "https://id.example.com/app/init";
    let query = "https://id.example.com/app/init?x=1";

    for (old, new) in [(slash, plain), (plain, query), (query, slash)] {
        let region = || AwsAppKind::AwsSso {
            region: "eu-west-1".into(),
        };
        service
            .save_aws_app(
                AwsAppInput::new(old, "suse"),
                AwsAppKind::Aws,
                SaveAs::Upsert,
            )
            .unwrap();
        service
            .save_aws_app(
                AwsAppInput::new(new, "suse"),
                AwsAppKind::Aws,
                SaveAs::Replace((old.into(), AwsAppType::Aws)),
            )
            .unwrap();
        service
            .save_aws_app(AwsAppInput::new(old, "suse"), region(), SaveAs::Upsert)
            .unwrap();
        service
            .save_aws_app(
                AwsAppInput::new(new, "suse"),
                region(),
                SaveAs::Replace((old.into(), AwsAppType::AwsSso)),
            )
            .unwrap();
        service
            .save_rancher(RancherInput::new(old, "client", "suse"), SaveAs::Upsert)
            .unwrap();
        service
            .save_rancher(
                RancherInput::new(new, "client", "suse"),
                SaveAs::Replace(old.to_string()),
            )
            .unwrap();
    }
    let config = service.load().unwrap();
    assert_eq!(config.aws_hosts().len(), 1);
    assert_eq!(config.aws_sso_hosts().len(), 1);
    assert_eq!(config.rancher_hosts().len(), 1);
}

#[test]
fn a_rancher_replace_onto_another_rancher_is_refused() {
    let store = Arc::new(InMemoryConfigStore::default());
    let service = SettingsService::new(store.clone());
    service.save_idp(idp_input(), SaveAs::New).unwrap();
    for url in ["https://a.example.com", "https://b.example.com"] {
        service
            .save_rancher(RancherInput::new(url, "c", "suse"), SaveAs::New)
            .unwrap();
    }
    let err = service
        .save_rancher(
            RancherInput::new("https://b.example.com/", "c", "suse"),
            SaveAs::Replace("https://a.example.com".into()),
        )
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(err, SettingsEditError::AlreadyExists { .. }));
}

#[test]
fn editing_an_idp_keeps_the_apps_that_use_it() {
    for mode in [SaveAs::Upsert, SaveAs::Replace(())] {
        let store = Arc::new(InMemoryConfigStore::default());
        let service = SettingsService::new(store.clone());
        service.save_idp(idp_input(), SaveAs::New).unwrap();
        service
            .save_aws_app(
                AwsAppInput::new(APP_URL, "suse"),
                AwsAppKind::Aws,
                SaveAs::New,
            )
            .unwrap();

        let mut edited = idp_input();
        edited.url = "https://new.example.com".into();
        let config = service.save_idp(edited, mode).unwrap();

        assert_eq!(config.aws_hosts()[0].idp(), "suse");
        assert_eq!(
            config.find_idp("suse").unwrap().url(),
            "https://new.example.com"
        );
    }
}

#[test]
fn a_second_idp_never_changes_the_idp_of_an_app() {
    let mut settings = with_idps(&["a"]);
    apply_aws_app(&mut settings, AwsAppInput::new(APP_URL, "a")).unwrap();
    apply_rancher(
        &mut settings,
        RancherInput::new("https://rancher.example.com", "rancher", "a"),
    )
    .unwrap();

    apply_idp(&mut settings, idp_named("b")).unwrap();

    assert_eq!(settings.aws_hosts()[0].idp(), "a");
    assert_eq!(settings.rancher_hosts()[0].idp(), "a");
    assert!(matches!(
        apply_remove_idp(&mut settings, "a"),
        Err(SettingsEditError::IdpInUse { .. })
    ));
    apply_remove_idp(&mut settings, "b").unwrap();
}

#[test]
fn a_replace_onto_the_tidied_key_of_another_entry_is_refused() {
    let mut settings = with_idps(&["a"]);
    let other = "https://id.example.com/application/saml/other/sso/binding/init";
    apply_aws_app(&mut settings, AwsAppInput::new(APP_URL, "a")).unwrap();
    apply_aws_app(&mut settings, AwsAppInput::new(other, "a")).unwrap();

    // The other entry is stored without the slash, the new key has a slash and a query.
    for tidy in [format!("{other}/"), format!("{other}?x=1")] {
        let err = apply_replace_aws_app(
            &mut settings,
            APP_URL,
            AwsAppType::Aws,
            AwsAppInput::new(tidy, "a"),
            AwsAppKind::Aws,
        );
        assert!(matches!(err, Err(SettingsEditError::AlreadyExists { .. })));
        assert_eq!(settings.aws_hosts().len(), 2);
    }
}

#[test]
fn the_service_refuses_what_the_forms_refuse() {
    let store = Arc::new(InMemoryConfigStore::default());
    let service = SettingsService::new(store.clone());
    let invalid = |field| move |e| matches!(e, SettingsEditError::InvalidFields(p) if fields_of(&p) == [field]);

    let mut bad = idp_input();
    bad.url = "http://id.example.com".into();
    let err = service
        .save_idp(bad, SaveAs::Upsert)
        .map(|_| ())
        .unwrap_err();
    assert!(invalid(InvalidField::Url)(err));

    let mut bad = idp_input();
    bad.name = "no/slash".into();
    let err = service
        .save_idp(bad, SaveAs::Upsert)
        .map(|_| ())
        .unwrap_err();
    assert!(invalid(InvalidField::Name)(err));

    service.save_idp(idp_input(), SaveAs::Upsert).unwrap();
    let err = service
        .save_aws_app(
            AwsAppInput::new(APP_URL, "suse"),
            AwsAppKind::AwsSso {
                region: "mars".into(),
            },
            SaveAs::Upsert,
        )
        .map(|_| ())
        .unwrap_err();
    assert!(invalid(InvalidField::Region)(err));

    let err = service
        .save_rancher(
            RancherInput::new("http://rancher.example.com", "c", "suse"),
            SaveAs::Upsert,
        )
        .map(|_| ())
        .unwrap_err();
    assert!(invalid(InvalidField::Url)(err));
    assert_eq!(service.load().unwrap().idps().len(), 1);
}

#[test]
fn the_global_settings_are_saved_through_the_service() {
    let store = Arc::new(InMemoryConfigStore::default());
    let service = SettingsService::new(store.clone());

    assert!(!service.set_use_keyring(false).unwrap().keyring_enabled());
    assert!(!service
        .set_wrap_cached_secrets(false)
        .unwrap()
        .wrap_cached_secrets_enabled());
    assert!(service
        .set_yubikey(None)
        .unwrap()
        .yubikey_config()
        .is_none());
    assert_eq!(store.saves(), 3);
}

fn idp_named(name: &str) -> IdpInput {
    IdpInput::new(
        name,
        IdpType::Authentik,
        format!("https://{name}.example.com"),
        "user",
    )
}

fn with_idps(names: &[&str]) -> AppConfig {
    let mut settings = AppConfig::default();
    for name in names {
        apply_idp(&mut settings, idp_named(name)).unwrap();
    }
    settings
}

#[test]
fn an_unused_idp_is_removed() {
    let mut settings = with_idps(&["a", "b"]);
    apply_aws_app(&mut settings, AwsAppInput::new(APP_URL, "b")).unwrap();

    apply_remove_idp(&mut settings, "a").unwrap();
    assert!(settings.find_idp("a").is_none());
    assert!(matches!(
        apply_remove_idp(&mut settings, "a"),
        Err(SettingsEditError::Invalid(SettingsError::UnknownIdp(_)))
    ));
}

#[test]
fn replacing_an_app_with_the_key_of_another_is_refused() {
    let mut settings = with_idps(&["a"]);
    let other = "https://id.example.com/application/saml/other/sso/binding/init";
    apply_aws_app(&mut settings, AwsAppInput::new(APP_URL, "a")).unwrap();
    apply_aws_app(&mut settings, AwsAppInput::new(other, "a")).unwrap();

    let err = apply_replace_aws_app(
        &mut settings,
        APP_URL,
        AwsAppType::Aws,
        AwsAppInput::new(other, "a"),
        AwsAppKind::Aws,
    );
    assert!(matches!(err, Err(SettingsEditError::AlreadyExists { .. })));
    assert_eq!(settings.aws_hosts().len(), 2);

    apply_rancher(
        &mut settings,
        RancherInput::new("https://a.example.com", "x", "a"),
    )
    .unwrap();
    apply_rancher(
        &mut settings,
        RancherInput::new("https://b.example.com", "y", "a"),
    )
    .unwrap();
    let err = apply_replace_rancher(
        &mut settings,
        "https://a.example.com",
        RancherInput::new("https://b.example.com", "z", "a"),
    );
    assert!(matches!(err, Err(SettingsEditError::AlreadyExists { .. })));
    assert_eq!(settings.rancher_hosts().len(), 2);
}

#[test]
fn an_idp_that_an_app_names_is_not_removed() {
    let mut settings = with_idps(&["a", "b"]);
    let rancher = RancherInput::new("https://rancher.example.com", "rancher", "b");
    apply_rancher(&mut settings, rancher).unwrap();

    let err = apply_remove_idp(&mut settings, "b")
        .map(|_| ())
        .unwrap_err();
    match &err {
        SettingsEditError::IdpInUse { name, used_by } => {
            assert_eq!(name, "b");
            assert_eq!(used_by, &["https://rancher.example.com"]);
        }
        other => panic!("{other:?}"),
    }
    assert!(err.to_string().contains("https://rancher.example.com"));
    assert!(settings.find_idp("b").is_some());
}

#[test]
fn apps_are_removed_by_url_and_kind() {
    let mut settings = with_idps(&["a"]);
    apply_aws_app(&mut settings, AwsAppInput::new(APP_URL, "a")).unwrap();
    apply_rancher(
        &mut settings,
        RancherInput::new("https://rancher.example.com/", "rancher", "a"),
    )
    .unwrap();

    assert!(matches!(
        apply_remove_aws_app(&mut settings, APP_URL, AwsAppType::AwsSso),
        Err(SettingsEditError::UnknownApp(_))
    ));
    apply_remove_aws_app(&mut settings, APP_URL, AwsAppType::Aws).unwrap();
    apply_remove_rancher(&mut settings, "https://rancher.example.com").unwrap();
    assert!(matches!(
        apply_remove_rancher(&mut settings, "https://rancher.example.com"),
        Err(SettingsEditError::UnknownApp(_))
    ));
    // Nothing uses it now.
    apply_remove_idp(&mut settings, "a").unwrap();
}

#[test]
fn an_edit_can_change_the_url() {
    let mut settings = with_idps(&["a"]);
    apply_aws_app(&mut settings, AwsAppInput::new(APP_URL, "a")).unwrap();
    let new_url = "https://id.example.com/application/saml/other/sso/binding/init";

    apply_replace_aws_app(
        &mut settings,
        APP_URL,
        AwsAppType::Aws,
        AwsAppInput::new(new_url, "a"),
        AwsAppKind::Aws,
    )
    .unwrap();
    assert_eq!(settings.aws_hosts().len(), 1);
    assert_eq!(settings.aws_hosts()[0].app_url(), new_url);

    apply_rancher(
        &mut settings,
        RancherInput::new("https://old.example.com", "rancher", "a"),
    )
    .unwrap();
    apply_replace_rancher(
        &mut settings,
        "https://old.example.com/",
        RancherInput::new("https://new.example.com", "other", "a"),
    )
    .unwrap();
    assert_eq!(settings.rancher_hosts().len(), 1);
    assert_eq!(settings.rancher_hosts()[0].client_id(), "other");
}

#[test]
fn an_edit_can_switch_the_kind_of_aws_app() {
    let mut settings = with_idps(&["a"]);
    apply_aws_app(&mut settings, AwsAppInput::new(APP_URL, "a")).unwrap();

    let to_sso = AwsAppKind::AwsSso {
        region: "eu-west-1".into(),
    };
    apply_replace_aws_app(
        &mut settings,
        APP_URL,
        AwsAppType::Aws,
        AwsAppInput::new(APP_URL, "a"),
        to_sso,
    )
    .unwrap();
    assert!(settings.aws_hosts().is_empty());
    assert_eq!(settings.aws_sso_hosts()[0].region(), "eu-west-1");

    apply_replace_aws_app(
        &mut settings,
        APP_URL,
        AwsAppType::AwsSso,
        AwsAppInput::new(APP_URL, "a"),
        AwsAppKind::Aws,
    )
    .unwrap();
    assert!(settings.aws_sso_hosts().is_empty());
    assert_eq!(settings.aws_hosts().len(), 1);
}

#[test]
fn a_refused_edit_or_removal_saves_nothing() {
    let store = Arc::new(InMemoryConfigStore::default());
    let service = SettingsService::new(store.clone());
    service.save_idp(idp_input(), SaveAs::Upsert).unwrap();
    service
        .save_aws_app(
            AwsAppInput::new(APP_URL, "suse"),
            AwsAppKind::Aws,
            SaveAs::Upsert,
        )
        .unwrap();
    let saves = store.saves();

    assert!(service.remove_idp("suse").is_err());
    assert!(service
        .remove_rancher("https://rancher.example.com")
        .is_err());

    // The old app is removed in memory, but the new one is refused: nothing is saved.
    let bad = AwsAppInput::new(APP_URL, "missing");
    assert!(service
        .save_aws_app(
            bad,
            AwsAppKind::Aws,
            SaveAs::Replace((APP_URL.into(), AwsAppType::Aws))
        )
        .is_err());
    assert_eq!(store.saves(), saves);
    assert_eq!(service.load().unwrap().aws_hosts().len(), 1);

    service.remove_aws_app(APP_URL, AwsAppType::Aws).unwrap();
    service.remove_idp("suse").unwrap();
    assert!(service.load().unwrap().idps().is_empty());
}

/// A store with the `suse` and `other` idps, an AWS app of each, and a Rancher of `suse`.
fn seeded() -> Arc<InMemoryConfigStore> {
    let store = Arc::new(InMemoryConfigStore::default());
    let service = SettingsService::new(store.clone());
    service.save_idp(idp_input(), SaveAs::Upsert).unwrap();
    let mut other = idp_input();
    other.name = "other".into();
    other.url = "https://other.example.com".into();
    service.save_idp(other, SaveAs::Upsert).unwrap();
    service
        .save_aws_app(
            AwsAppInput::new(APP_URL, "suse"),
            AwsAppKind::Aws,
            SaveAs::Upsert,
        )
        .unwrap();
    service
        .save_aws_app(
            AwsAppInput::new("https://other.example.com/app/", "other"),
            AwsAppKind::Aws,
            SaveAs::Upsert,
        )
        .unwrap();
    service
        .save_rancher(
            RancherInput::new("https://rancher.example.com", "client", "suse"),
            SaveAs::Upsert,
        )
        .unwrap();

    store
}

/// The user name the importer gives to `suse`.
fn names() -> BTreeMap<String, String> {
    BTreeMap::from([("suse".to_string(), "newcomer".to_string())])
}

#[test]
fn an_export_holds_no_user_names() {
    let store = seeded();
    let service = SettingsService::new(store.clone());
    let mut input = AwsAppInput::new("https://id.example.com/personal/", "suse");
    input.username = Some("me-too".into());
    service
        .save_aws_app(input, AwsAppKind::Aws, SaveAs::Upsert)
        .unwrap();

    let bundle = service.export(&["suse".to_string()]).unwrap();

    assert_eq!(bundle.idps()[0].username(), "");
    assert!(bundle.aws_hosts().iter().all(|h| h.username().is_none()));
}

#[test]
fn an_import_needs_a_user_name_for_each_new_idp() {
    let bundle = SettingsService::new(seeded())
        .export(&["suse".to_string()])
        .unwrap();
    let target = Arc::new(InMemoryConfigStore::default());
    let service = SettingsService::new(target.clone());

    assert_eq!(service.usernames_needed(&bundle).unwrap(), ["suse"]);
    assert!(matches!(
        service.import(&bundle, ImportMode::SkipExisting, &BTreeMap::new()),
        Err(SettingsEditError::UsernameNeeded(name)) if name == "suse"
    ));
    assert_eq!(target.saves(), 0);

    let (config, _) = service
        .import(&bundle, ImportMode::SkipExisting, &names())
        .unwrap();
    assert_eq!(config.resolve_idp("suse").unwrap().username(), "newcomer");
    // Set up now, so nothing is asked a second time and the user name stays.
    assert!(service.usernames_needed(&bundle).unwrap().is_empty());
    let (config, _) = service
        .import(&bundle, ImportMode::Overwrite, &BTreeMap::new())
        .unwrap();
    assert_eq!(config.resolve_idp("suse").unwrap().username(), "newcomer");
}

#[test]
fn an_export_holds_the_idp_and_only_its_apps() {
    let store = seeded();
    let bundle = SettingsService::new(store.clone())
        .export(&["suse".to_string()])
        .unwrap();

    assert_eq!(bundle.idps().len(), 1);
    assert_eq!(bundle.aws_hosts().len(), 1);
    assert_eq!(bundle.aws_hosts()[0].idp(), "suse");
    assert_eq!(bundle.rancher_hosts().len(), 1);
    assert!(bundle.aws_sso_hosts().is_empty());
}

#[test]
fn exporting_an_unknown_idp_is_refused() {
    let store = seeded();

    assert!(matches!(
        SettingsService::new(store.clone()).export(&["nope".to_string()]),
        Err(SettingsEditError::Invalid(SettingsError::UnknownIdp(_)))
    ));
}

#[test]
fn an_import_adds_everything_and_keeps_the_global_settings() {
    let bundle = SettingsService::new(seeded())
        .export(&["suse".to_string()])
        .unwrap();
    let target = Arc::new(InMemoryConfigStore::default());
    let service = SettingsService::new(target.clone());
    service.set_use_keyring(false).unwrap();
    service.set_wrap_cached_secrets(true).unwrap();

    let (config, report) = service
        .import(&bundle, ImportMode::SkipExisting, &names())
        .unwrap();

    assert_eq!(report.added(), 3);
    assert_eq!(report.skipped(), 0);
    assert_eq!(config.idps().len(), 1);
    assert_eq!(config.aws_hosts().len(), 1);
    assert_eq!(config.rancher_hosts().len(), 1);
    assert!(!config.keyring_enabled());
    assert!(config.wrap_cached_secrets_enabled());
}

#[test]
fn an_import_skips_what_exists_unless_told_to_overwrite() {
    let bundle = SettingsService::new(seeded())
        .export(&["suse".to_string()])
        .unwrap();
    let target = Arc::new(InMemoryConfigStore::default());
    let service = SettingsService::new(target.clone());
    let mut mine = idp_input();
    mine.username = "mine".into();
    service.save_idp(mine, SaveAs::Upsert).unwrap();

    let (config, report) = service
        .import(&bundle, ImportMode::SkipExisting, &names())
        .unwrap();
    assert_eq!(report.idps.skipped, 1);
    assert_eq!(report.added(), 2);
    assert_eq!(config.resolve_idp("suse").unwrap().username(), "mine");

    let (config, report) = service
        .import(&bundle, ImportMode::Overwrite, &names())
        .unwrap();
    assert_eq!(report.idps.overwritten, 1);
    assert_eq!(report.overwritten(), 3);
    assert_eq!(config.resolve_idp("suse").unwrap().username(), "newcomer");
}

#[test]
fn an_import_of_an_app_without_its_idp_saves_nothing() {
    let bundle = SettingsService::new(seeded())
        .export(&["suse".to_string()])
        .unwrap();
    let only_apps = SettingsBundle::new(
        Vec::new(),
        bundle.aws_hosts().to_vec(),
        Vec::new(),
        Vec::new(),
    );
    let target = Arc::new(InMemoryConfigStore::default());

    assert!(matches!(
        SettingsService::new(target.clone()).import(
            &only_apps,
            ImportMode::SkipExisting,
            &names()
        ),
        Err(ref e) if is_unknown_idp(e)
    ));
    assert_eq!(target.saves(), 0);
}

#[test]
fn an_import_with_an_insecure_url_saves_nothing() {
    let http = Idp::new(
        "bad".into(),
        IdpType::Authentik,
        "http://id.example.com".into(),
        "user".into(),
        None,
    )
    .unwrap();
    let bundle = SettingsBundle::new(vec![http], Vec::new(), Vec::new(), Vec::new());
    let target = Arc::new(InMemoryConfigStore::default());

    assert!(matches!(
        SettingsService::new(target.clone()).import(
            &bundle,
            ImportMode::SkipExisting,
            &BTreeMap::from([("bad".to_string(), "user".to_string())])
        ),
        Err(SettingsEditError::InvalidFields(problems))
            if fields_of(&problems) == [InvalidField::Url]
    ));
    assert_eq!(target.saves(), 0);
}

#[test]
fn a_security_key_where_none_works_is_a_problem_of_the_mfa_field_in_form_order() {
    use super::validate::{validate_aws, validate_idp, validate_rancher};

    let mut settings = AppConfig::default();
    apply_idp(&mut settings, idp_input()).unwrap();
    let key = Some(crate::domain::models::mfa::MfaSelection::WebAuthn);

    let mut idp = idp_input();
    idp.mfa = key;
    assert!(validate_idp(&idp, true).is_ok());
    let Err(problems) = validate_idp(&idp, false) else {
        panic!("refused")
    };
    assert_eq!(fields_of(&problems), [InvalidField::Mfa]);

    let mut app = AwsAppInput::new("nope", "missing");
    app.mfa = key;
    let Err(problems) = validate_aws(&settings, &app, &AwsAppKind::Aws, false) else {
        panic!("refused")
    };
    assert_eq!(
        fields_of(&problems),
        [InvalidField::Url, InvalidField::Mfa, InvalidField::Idp]
    );

    let mut rancher = RancherInput::new("nope", "c", "missing");
    rancher.mfa = key;
    let Err(problems) = validate_rancher(&settings, &rancher, false) else {
        panic!("refused")
    };
    assert_eq!(
        fields_of(&problems),
        [InvalidField::Url, InvalidField::Mfa, InvalidField::Idp]
    );
}
