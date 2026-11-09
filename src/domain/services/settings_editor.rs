//! Changes to the settings, and the validation that goes with them.
//!
//! A change is validated once, here: every field is checked and all the problems come back together, in form
//! order, as [`SettingsEditError::InvalidFields`], each naming its [`InvalidField`].
//!
//! Every driving adapter (the CLI, the GUI) edits the settings through here, so they accept and refuse the same
//! things. The `apply` functions change settings in memory; [`SettingsService`] is the one way to load, change and
//! save them: every change goes through it, every change to an app is login-checked (there is no mode), and
//! nothing is saved when a change is refused.

use crate::domain::models::idp::IdpType;
use crate::domain::models::login::{LoginTarget, ResolveError};
use crate::domain::models::mfa::MfaSelection;
use crate::domain::models::settings::{
    same_app_url, AppConfig, AwsAppType, AwsHost, AwsSsoHost, Idp, RancherHost, SettingsBundle,
    SettingsError, YubikeyConfig,
};
use crate::domain::ports::config::{ConfigError, ConfigStore};
use crate::domain::ports::login_check::LoginCheck;
use crate::domain::services::settings_check::{verify, ResolvingLoginCheck};
use crate::domain::services::settings_validation::{
    allow_insecure_localhost, check_client_id, check_name, check_optional_username, check_region,
    check_url, check_username,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use thiserror::Error;

/// The value of a change that failed the checks of `settings_validation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidField {
    Name,
    Url,
    Username,
    ClientId,
    Region,
    /// The identity provider an app logs in with.
    Idp,
}

/// What is wrong with a field.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Problem {
    /// A sentence that says what to change.
    Message(String),
    /// The identity provider is not configured (it keeps its own wording).
    UnknownIdp(String),
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Problem::Message(message) => f.write_str(message),
            Problem::UnknownIdp(name) => {
                write!(f, "{}", SettingsError::UnknownIdp(name.clone()))
            }
        }
    }
}

/// A field of a change and what is wrong with it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FieldProblem {
    pub field: InvalidField,
    pub problem: Problem,
}

impl FieldProblem {
    fn message(field: InvalidField, message: String) -> Self {
        Self {
            field,
            problem: Problem::Message(message),
        }
    }
}

impl std::fmt::Display for FieldProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.problem.fmt(f)
    }
}

fn join_problems(problems: &[FieldProblem]) -> String {
    problems
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Why the settings were not changed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SettingsEditError {
    /// A value is not valid.
    #[error(transparent)]
    Invalid(#[from] SettingsError),

    /// Values do not pass the checks of the settings (an `http` web address, a bad region, ...). Every problem
    /// of the change, in form order. Never empty.
    #[error("{}", join_problems(.0))]
    InvalidFields(Vec<FieldProblem>),

    /// An identity provider that apps still log in with cannot be removed.
    #[error(
        "the identity provider \"{name}\" is still used by {}, change or remove those first",
        used_by.join(", ")
    )]
    IdpInUse { name: String, used_by: Vec<String> },

    /// There is no app or Rancher at this url.
    #[error("nothing is configured at {0}")]
    UnknownApp(String),

    /// A username is necessary for an idp.
    #[error("enter the user name for the identity provider \"{0}\"")]
    UsernameNeeded(String),

    /// What was meant as new is there already, at this name or url.
    #[error("{key} is set up already")]
    AlreadyExists { key: String },

    /// What was meant to be changed is no longer in the settings.
    #[error("this entry is no longer in the settings, it may have been changed elsewhere")]
    Gone,

    /// The change would stop apps that sign in now from signing in.
    #[error("this change would stop these from signing in: {}", urls.join(", "))]
    WouldBreak { urls: Vec<String> },

    /// What was set up cannot be used to sign in.
    #[error("these settings cannot be used to sign in: {0}")]
    DoesNotResolve(ResolveError),

    /// The settings could not be read or written.
    #[error("the settings could not be read or written: {0}")]
    Store(#[from] ConfigError),
}

/// How a save treats an entry that may be there already.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SaveAs<K> {
    /// Add it, or update the one with the same key (what `c9s config ...` does).
    Upsert,
    /// Add it, refused when the key is taken.
    New,
    /// Replace the entry with this key, refused when it is gone. The new key may differ.
    Replace(K),
}

/// The key of an AWS app: its url and kind.
pub type AwsAppRef = (String, AwsAppType);

/// Which AWS app an [`AwsAppInput`] is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AwsAppKind {
    /// The AWS SAML application, with IAM roles.
    Aws,
    /// The AWS IAM Identity Center application, in a region.
    AwsSso { region: String },
}

impl AwsAppKind {
    fn app_type(&self) -> AwsAppType {
        match self {
            AwsAppKind::Aws => AwsAppType::Aws,
            AwsAppKind::AwsSso { .. } => AwsAppType::AwsSso,
        }
    }
}

/// An identity provider to add, or to update when one has the same name.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IdpInput {
    pub name: String,
    pub idp_type: IdpType,
    pub url: String,
    pub username: String,
    pub mfa: Option<MfaSelection>,
}

impl IdpInput {
    pub fn new(
        name: impl Into<String>,
        idp_type: IdpType,
        url: impl Into<String>,
        username: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            idp_type,
            url: url.into(),
            username: username.into(),
            mfa: None,
        }
    }
}

/// An AWS app to add: the IAM role application, or with a region, the IAM Identity Center one.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AwsAppInput {
    pub app_url: String,
    /// The identity provider to log in with.
    pub idp: String,
    /// Overrides the username of the identity provider.
    pub username: Option<String>,
    /// Overrides the MFA selection of the identity provider.
    pub mfa: Option<MfaSelection>,
}

impl AwsAppInput {
    pub fn new(app_url: impl Into<String>, idp: impl Into<String>) -> Self {
        Self {
            app_url: app_url.into(),
            idp: idp.into(),
            username: None,
            mfa: None,
        }
    }
}

/// A Rancher to add, or to update when one has the same url.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RancherInput {
    pub url: String,
    pub client_id: String,
    pub idp: String,
    pub username: Option<String>,
    pub mfa: Option<MfaSelection>,
}

impl RancherInput {
    pub fn new(
        url: impl Into<String>,
        client_id: impl Into<String>,
        idp: impl Into<String>,
    ) -> Self {
        Self {
            url: url.into(),
            client_id: client_id.into(),
            idp: idp.into(),
            username: None,
            mfa: None,
        }
    }
}

struct ValidIdp {
    name: String,
    url: String,
    username: String,
}

struct ValidAws {
    app_url: String,
    username: Option<String>,
    idp: String,
    region: Option<String>,
}

struct ValidRancher {
    url: String,
    client_id: String,
    username: Option<String>,
    idp: String,
}

/// Runs one check of `settings_validation` and keeps the problem, if any, under `field`.
fn keep<T>(
    problems: &mut Vec<FieldProblem>,
    field: InvalidField,
    result: Result<T, String>,
) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(message) => {
            problems.push(FieldProblem::message(field, message));
            None
        }
    }
}

/// The identity provider an app logs in with: chosen, well-formed and configured.
fn keep_idp(problems: &mut Vec<FieldProblem>, settings: &AppConfig, input: &str) -> Option<String> {
    let name = match input.trim() {
        "" => Err("Choose an identity provider.".to_string()),
        name => check_name(name),
    };
    let name = keep(problems, InvalidField::Idp, name)?;
    match settings.resolve_idp(&name) {
        Ok(idp) => Some(idp.name().to_string()),
        Err(_) => {
            problems.push(FieldProblem {
                field: InvalidField::Idp,
                problem: Problem::UnknownIdp(name),
            });
            None
        }
    }
}

fn validate_idp(input: &IdpInput) -> Result<ValidIdp, Vec<FieldProblem>> {
    let mut problems = Vec::new();
    let name = keep(&mut problems, InvalidField::Name, check_name(&input.name));
    let url = keep(
        &mut problems,
        InvalidField::Url,
        check_url(&input.url, allow_insecure_localhost()),
    );
    let username = keep(
        &mut problems,
        InvalidField::Username,
        check_username(&input.username),
    );
    match (name, url, username) {
        (Some(name), Some(url), Some(username)) => Ok(ValidIdp {
            name,
            url,
            username,
        }),
        _ => Err(problems),
    }
}

fn validate_aws(
    settings: &AppConfig,
    input: &AwsAppInput,
    kind: &AwsAppKind,
) -> Result<ValidAws, Vec<FieldProblem>> {
    let mut problems = Vec::new();
    let app_url = keep(
        &mut problems,
        InvalidField::Url,
        check_url(&input.app_url, allow_insecure_localhost()),
    );
    let region = match kind {
        AwsAppKind::Aws => Some(None),
        AwsAppKind::AwsSso { region } => {
            keep(&mut problems, InvalidField::Region, check_region(region)).map(Some)
        }
    };
    let username = keep(
        &mut problems,
        InvalidField::Username,
        check_optional_username(input.username.as_deref()),
    );
    let idp = keep_idp(&mut problems, settings, &input.idp);
    match (app_url, region, username, idp) {
        (Some(app_url), Some(region), Some(username), Some(idp)) => Ok(ValidAws {
            app_url,
            username,
            idp,
            region,
        }),
        _ => Err(problems),
    }
}

fn validate_rancher(
    settings: &AppConfig,
    input: &RancherInput,
) -> Result<ValidRancher, Vec<FieldProblem>> {
    let mut problems = Vec::new();
    let url = keep(
        &mut problems,
        InvalidField::Url,
        check_url(&input.url, allow_insecure_localhost()),
    );
    let client_id = keep(
        &mut problems,
        InvalidField::ClientId,
        check_client_id(&input.client_id),
    );
    let username = keep(
        &mut problems,
        InvalidField::Username,
        check_optional_username(input.username.as_deref()),
    );
    let idp = keep_idp(&mut problems, settings, &input.idp);
    match (url, client_id, username, idp) {
        (Some(url), Some(client_id), Some(username), Some(idp)) => Ok(ValidRancher {
            url,
            client_id,
            username,
            idp,
        }),
        _ => Err(problems),
    }
}

/// Adds an identity provider, or updates the one with the same name.
pub fn apply_idp(settings: &mut AppConfig, input: IdpInput) -> Result<(), SettingsEditError> {
    let valid = validate_idp(&input).map_err(SettingsEditError::InvalidFields)?;
    let idp = Idp::new(
        valid.name,
        input.idp_type,
        valid.url,
        valid.username,
        input.mfa,
    )?;
    settings.add_idp(idp);

    Ok(())
}

/// Adds an AWS IAM role app, or updates the one with the same url.
pub fn apply_aws_app(
    settings: &mut AppConfig,
    input: AwsAppInput,
) -> Result<(), SettingsEditError> {
    let valid = validate_aws(settings, &input, &AwsAppKind::Aws)
        .map_err(SettingsEditError::InvalidFields)?;
    let host = AwsHost::new(valid.app_url, valid.username, valid.idp, input.mfa)?;
    settings.add_aws_host(host);

    Ok(())
}

/// Adds an AWS IAM Identity Center app, or updates the one with the same url.
pub fn apply_aws_sso_app(
    settings: &mut AppConfig,
    input: AwsAppInput,
    region: impl Into<String>,
) -> Result<(), SettingsEditError> {
    let kind = AwsAppKind::AwsSso {
        region: region.into(),
    };
    let valid = validate_aws(settings, &input, &kind).map_err(SettingsEditError::InvalidFields)?;
    let region = valid.region.unwrap_or_default();
    let host = AwsSsoHost::new(valid.app_url, valid.username, valid.idp, region, input.mfa)?;
    settings.add_aws_sso_host(host);

    Ok(())
}

/// Adds a Rancher, or updates the one with the same url.
pub fn apply_rancher(
    settings: &mut AppConfig,
    input: RancherInput,
) -> Result<(), SettingsEditError> {
    let valid = validate_rancher(settings, &input).map_err(SettingsEditError::InvalidFields)?;
    let host = RancherHost::new(
        valid.url,
        valid.client_id,
        valid.idp,
        valid.username,
        input.mfa,
    )?;
    settings.add_rancher_host(host);

    Ok(())
}

/// Adds an AWS app of either kind, or updates the one of that kind with the same url.
pub fn apply_aws_app_of_kind(
    settings: &mut AppConfig,
    input: AwsAppInput,
    kind: AwsAppKind,
) -> Result<(), SettingsEditError> {
    match kind {
        AwsAppKind::Aws => apply_aws_app(settings, input),
        AwsAppKind::AwsSso { region } => apply_aws_sso_app(settings, input, region),
    }
}

/// Replaces the AWS app at `old_url` of `old_type` with `input`, which may have another url or kind. The key of
/// an app is its url (and kind), so changing it is a removal and an addition. A new key that is another app's
/// is refused with `AlreadyExists`, and nothing changes.
pub fn apply_replace_aws_app(
    settings: &mut AppConfig,
    old_url: &str,
    old_type: AwsAppType,
    input: AwsAppInput,
    kind: AwsAppKind,
) -> Result<(), SettingsEditError> {
    let new_type = kind.app_type();
    // `has_aws` and `same_app_url` normalise the same way, so a tidy-up of the url (a slash, a query) is not a
    // change of key, while a url another entry has under its tidy form is a collision.
    let changes_key = !same_app_url(&input.app_url, old_url) || new_type != old_type;
    if changes_key && has_aws(settings, &input.app_url, new_type) {
        return Err(SettingsEditError::AlreadyExists { key: input.app_url });
    }
    apply_remove_aws_app(settings, old_url, old_type)?;
    apply_aws_app_of_kind(settings, input, kind)
}

/// Replaces the Rancher at `old_url` with `input`, which may have another url. A url that is another Rancher's
/// is refused with `AlreadyExists`, and nothing changes.
pub fn apply_replace_rancher(
    settings: &mut AppConfig,
    old_url: &str,
    input: RancherInput,
) -> Result<(), SettingsEditError> {
    if !same_app_url(&input.url, old_url) && settings.find_rancher_host(&input.url).is_some() {
        return Err(SettingsEditError::AlreadyExists { key: input.url });
    }
    apply_remove_rancher(settings, old_url)?;
    apply_rancher(settings, input)
}

/// The apps (by url) that log in with the identity provider `name`.
pub fn idp_used_by(settings: &AppConfig, name: &str) -> Vec<String> {
    let aws = settings
        .aws_hosts()
        .iter()
        .filter(|host| host.idp() == name)
        .map(|host| host.app_url().to_string());
    let sso = settings
        .aws_sso_hosts()
        .iter()
        .filter(|host| host.idp() == name)
        .map(|host| host.app_url().to_string());
    let rancher = settings
        .rancher_hosts()
        .iter()
        .filter(|host| host.idp() == name)
        .map(|host| host.url().to_string());

    aws.chain(sso).chain(rancher).collect()
}

/// Removes an identity provider no app logs in with.
pub fn apply_remove_idp(settings: &mut AppConfig, name: &str) -> Result<(), SettingsEditError> {
    if settings.find_idp(name).is_none() {
        return Err(SettingsError::UnknownIdp(name.to_string()).into());
    }
    let used_by = idp_used_by(settings, name);
    if !used_by.is_empty() {
        return Err(SettingsEditError::IdpInUse {
            name: name.to_string(),
            used_by,
        });
    }

    settings.remove_idp(name);

    Ok(())
}

/// Removes the AWS app of `app_type` at `app_url`.
pub fn apply_remove_aws_app(
    settings: &mut AppConfig,
    app_url: &str,
    app_type: AwsAppType,
) -> Result<(), SettingsEditError> {
    let removed = match app_type {
        AwsAppType::Aws => settings.remove_aws_host(app_url),
        AwsAppType::AwsSso => settings.remove_aws_sso_host(app_url),
    };
    if !removed {
        return Err(SettingsEditError::UnknownApp(app_url.to_string()));
    }

    Ok(())
}

/// Removes the Rancher at `url`.
pub fn apply_remove_rancher(settings: &mut AppConfig, url: &str) -> Result<(), SettingsEditError> {
    if !settings.remove_rancher_host(url) {
        return Err(SettingsEditError::UnknownApp(url.to_string()));
    }

    Ok(())
}

/// Whether to keep the secrets in the keyring.
pub fn apply_use_keyring(settings: &mut AppConfig, enabled: bool) {
    settings.set_use_keyring(enabled);
}

/// Sets the YubiKey that wraps secrets, or `None` to stop wrapping.
pub fn apply_yubikey(settings: &mut AppConfig, config: Option<YubikeyConfig>) {
    settings.set_yubikey(config);
}

/// Whether the cached session secrets are wrapped too.
pub fn apply_wrap_cached_secrets(settings: &mut AppConfig, enabled: bool) {
    settings.set_wrap_cached_secrets(enabled);
}

fn has_aws(settings: &AppConfig, url: &str, app_type: AwsAppType) -> bool {
    match app_type {
        AwsAppType::Aws => settings.find_aws_host(url).is_some(),
        AwsAppType::AwsSso => settings.find_aws_sso_host(url).is_some(),
    }
}

/// What an import does with an entry that is in the settings already.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ImportMode {
    /// Keep what is there, add only what is new.
    #[default]
    SkipExisting,
    /// Update what is there to what the bundle says.
    Overwrite,
}

#[derive(Clone, Copy)]
enum Kind {
    Idp,
    Aws,
    AwsSso,
    Rancher,
}

/// How many entries of one kind an import added, updated and left alone.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImportCounts {
    pub added: usize,
    pub overwritten: usize,
    pub skipped: usize,
}

/// What an import did, by kind of entry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImportReport {
    pub idps: ImportCounts,
    pub aws_apps: ImportCounts,
    pub aws_sso_apps: ImportCounts,
    pub rancher_apps: ImportCounts,
}

impl ImportReport {
    fn tally(&mut self, kind: Kind, exists: bool, overwrite: bool) -> bool {
        let counts = match kind {
            Kind::Idp => &mut self.idps,
            Kind::Aws => &mut self.aws_apps,
            Kind::AwsSso => &mut self.aws_sso_apps,
            Kind::Rancher => &mut self.rancher_apps,
        };
        match (exists, overwrite) {
            (false, _) => counts.added += 1,
            (true, true) => counts.overwritten += 1,
            (true, false) => {
                counts.skipped += 1;
                return false;
            }
        }

        true
    }

    pub fn added(&self) -> usize {
        self.each().map(|c| c.added).sum()
    }

    pub fn overwritten(&self) -> usize {
        self.each().map(|c| c.overwritten).sum()
    }

    pub fn skipped(&self) -> usize {
        self.each().map(|c| c.skipped).sum()
    }

    fn each(&self) -> impl Iterator<Item = &ImportCounts> {
        [
            &self.idps,
            &self.aws_apps,
            &self.aws_sso_apps,
            &self.rancher_apps,
        ]
        .into_iter()
    }
}

/// Checks the existence rule of a save once, for every kind: `New` refuses a taken key, `Replace` refuses an old
/// key that is gone, `Upsert` refuses neither.
fn check_mode<K>(
    mode: &SaveAs<K>,
    key: &str,
    new_key_taken: bool,
    old_exists: impl FnOnce(&K) -> bool,
) -> Result<(), SettingsEditError> {
    match mode {
        SaveAs::Upsert => Ok(()),
        SaveAs::New if new_key_taken => Err(SettingsEditError::AlreadyExists {
            key: key.to_string(),
        }),
        SaveAs::New => Ok(()),
        SaveAs::Replace(old) if !old_exists(old) => Err(SettingsEditError::Gone),
        SaveAs::Replace(_) => Ok(()),
    }
}

/// Edits the settings kept in a [`ConfigStore`]: every change is loaded, applied, login-checked and saved here,
/// and nothing is saved when a change is refused.
///
/// A change to the apps (the `save_*`, `remove_*` and `import` methods) is refused when what it sets up does not
/// resolve a login, or when it stops an app that resolved before from resolving. The check is the [`LoginCheck`]
/// port; [`SettingsService::new`] resolves the way the CLI would.
///
/// Concurrent writers are last-write-wins: the whole file is rewritten from what this process loaded. The file
/// store replaces the file atomically, so a reader never sees a half written file, but two programs saving at
/// the same moment can lose one change.
#[derive(Clone)]
pub struct SettingsService<C: LoginCheck = ResolvingLoginCheck> {
    store: Arc<dyn ConfigStore + Send + Sync>,
    check: C,
}

impl SettingsService<ResolvingLoginCheck> {
    pub fn new(store: Arc<dyn ConfigStore + Send + Sync>) -> Self {
        Self::with_login_check(store, ResolvingLoginCheck)
    }
}

impl<C: LoginCheck> SettingsService<C> {
    pub fn with_login_check(store: Arc<dyn ConfigStore + Send + Sync>, check: C) -> Self {
        Self { store, check }
    }

    /// The settings as stored. Never saves.
    pub fn load(&self) -> Result<AppConfig, SettingsEditError> {
        Ok(self.store.load()?)
    }

    /// Loads the settings, applies `change` and saves the result, which is returned. No login check: for the
    /// global settings. Nothing is saved when `change` fails.
    pub fn update(
        &self,
        change: impl FnOnce(&mut AppConfig) -> Result<(), SettingsEditError>,
    ) -> Result<AppConfig, SettingsEditError> {
        let mut config = self.store.load()?;
        change(&mut config)?;
        self.store.save(&config)?;

        Ok(config)
    }

    /// Loads the settings, applies `change` (which gets the settings before, the ones to change, and returns the
    /// apps it set up), checks the logins and saves. Nothing is saved when anything fails.
    fn edit(
        &self,
        change: impl FnOnce(&AppConfig, &mut AppConfig) -> Result<Vec<LoginTarget>, SettingsEditError>,
    ) -> Result<AppConfig, SettingsEditError> {
        let before = self.store.load()?;
        let mut config = before.clone();
        let touched = change(&before, &mut config)?;
        verify(&self.check, &before, &config, &touched)?;
        self.store.save(&config)?;

        Ok(config)
    }

    /// Whether `input` passes the checks of an identity provider. Never saves.
    pub fn check_idp(&self, input: &IdpInput) -> Result<(), SettingsEditError> {
        validate_idp(input)
            .map(drop)
            .map_err(SettingsEditError::InvalidFields)
    }

    /// Whether `input` passes the checks of an AWS app of `kind`. Never saves.
    pub fn check_aws_app(
        &self,
        input: &AwsAppInput,
        kind: &AwsAppKind,
    ) -> Result<(), SettingsEditError> {
        let settings = self.store.load()?;
        validate_aws(&settings, input, kind)
            .map(drop)
            .map_err(SettingsEditError::InvalidFields)
    }

    /// Whether `input` passes the checks of a Rancher. Never saves.
    pub fn check_rancher(&self, input: &RancherInput) -> Result<(), SettingsEditError> {
        let settings = self.store.load()?;
        validate_rancher(&settings, input)
            .map(drop)
            .map_err(SettingsEditError::InvalidFields)
    }

    /// Adds an identity provider, or updates the one with the same name.
    pub fn save_idp(
        &self,
        input: IdpInput,
        mode: SaveAs<()>,
    ) -> Result<AppConfig, SettingsEditError> {
        self.edit(|before, config| {
            let taken = before.find_idp(&input.name).is_some();
            check_mode(&mode, &input.name, taken, |_| taken)?;
            apply_idp(config, input)?;

            Ok(vec![])
        })
    }

    pub fn remove_idp(&self, name: &str) -> Result<AppConfig, SettingsEditError> {
        self.edit(|_, config| {
            apply_remove_idp(config, name)?;

            Ok(vec![])
        })
    }

    /// Adds an AWS app of either kind, or replaces one (its url and kind may change).
    pub fn save_aws_app(
        &self,
        input: AwsAppInput,
        kind: AwsAppKind,
        mode: SaveAs<AwsAppRef>,
    ) -> Result<AppConfig, SettingsEditError> {
        let app_type = kind.app_type();
        let url = input.app_url.clone();
        self.edit(|before, config| {
            let taken = has_aws(before, &url, app_type);
            check_mode(&mode, &url, taken, |(old_url, old_type)| {
                has_aws(before, old_url, *old_type)
            })?;
            match &mode {
                SaveAs::Replace((old_url, old_type)) => {
                    apply_replace_aws_app(config, old_url, *old_type, input, kind)?
                }
                SaveAs::Upsert | SaveAs::New => apply_aws_app_of_kind(config, input, kind)?,
            }

            Ok(vec![LoginTarget::Aws {
                app_url: url,
                app_type,
            }])
        })
    }

    pub fn remove_aws_app(
        &self,
        app_url: &str,
        app_type: AwsAppType,
    ) -> Result<AppConfig, SettingsEditError> {
        self.edit(|_, config| {
            apply_remove_aws_app(config, app_url, app_type)?;

            Ok(vec![])
        })
    }

    /// Adds a Rancher, or replaces one (its url may change).
    pub fn save_rancher(
        &self,
        input: RancherInput,
        mode: SaveAs<String>,
    ) -> Result<AppConfig, SettingsEditError> {
        let url = input.url.clone();
        self.edit(|before, config| {
            let taken = before.find_rancher_host(&url).is_some();
            check_mode(&mode, &url, taken, |old_url| {
                before.find_rancher_host(old_url).is_some()
            })?;
            match &mode {
                SaveAs::Replace(old_url) => apply_replace_rancher(config, old_url, input)?,
                SaveAs::Upsert | SaveAs::New => apply_rancher(config, input)?,
            }

            Ok(vec![LoginTarget::Rancher { url }])
        })
    }

    pub fn remove_rancher(&self, url: &str) -> Result<AppConfig, SettingsEditError> {
        self.edit(|_, config| {
            apply_remove_rancher(config, url)?;

            Ok(vec![])
        })
    }

    /// The identity providers called `names` and the apps that log in with them. Never saves.
    pub fn export(&self, names: &[String]) -> Result<SettingsBundle, SettingsEditError> {
        Ok(self.store.load()?.export(names)?)
    }

    /// The identity providers of `bundle` that are not set up yet, so an import needs a user name for each.
    pub fn usernames_needed(
        &self,
        bundle: &SettingsBundle,
    ) -> Result<Vec<String>, SettingsEditError> {
        let config = self.store.load()?;

        Ok(bundle
            .idps()
            .iter()
            .filter(|idp| config.find_idp(idp.name()).is_none())
            .map(|idp| idp.name().to_string())
            .collect())
    }

    /// Adds what `bundle` holds. All or nothing: one entry that is refused (an `http` url, an app of an
    /// identity provider that is in neither the bundle nor the settings, ...) saves nothing. The global settings
    /// are never touched.
    ///
    /// A bundle holds no user names. `usernames` gives, by name, the one to sign in with at each identity
    /// provider that is new (see [`usernames_needed`](Self::usernames_needed)); one that is set up already keeps its own.
    pub fn import(
        &self,
        bundle: &SettingsBundle,
        mode: ImportMode,
        usernames: &BTreeMap<String, String>,
    ) -> Result<(AppConfig, ImportReport), SettingsEditError> {
        let mut report = ImportReport::default();
        let config = self.edit(|before, config| {
            let mut touched = Vec::new();
            let overwrite = mode == ImportMode::Overwrite;

            for idp in bundle.idps() {
                let exists = before.find_idp(idp.name()).is_some();
                if !report.tally(Kind::Idp, exists, overwrite) {
                    continue;
                }
                let username = match (usernames.get(idp.name()), before.find_idp(idp.name())) {
                    (Some(username), _) => username.clone(),
                    (None, Some(mine)) => mine.username().to_string(),
                    (None, None) => {
                        return Err(SettingsEditError::UsernameNeeded(idp.name().to_string()))
                    }
                };
                let mut input = IdpInput::new(idp.name(), idp.idp_type(), idp.url(), username);
                input.mfa = idp.mfa();
                apply_idp(config, input)?;
            }

            for host in bundle.aws_hosts() {
                let exists = before.find_aws_host(host.app_url()).is_some();
                if !report.tally(Kind::Aws, exists, overwrite) {
                    continue;
                }
                let mut input = AwsAppInput::new(host.app_url(), host.idp());
                input.username = host.username().map(str::to_string);
                input.mfa = host.mfa();
                apply_aws_app(config, input)?;
                touched.push(LoginTarget::Aws {
                    app_url: host.app_url().to_string(),
                    app_type: AwsAppType::Aws,
                });
            }

            for host in bundle.aws_sso_hosts() {
                let exists = before.find_aws_sso_host(host.app_url()).is_some();
                if !report.tally(Kind::AwsSso, exists, overwrite) {
                    continue;
                }
                let mut input = AwsAppInput::new(host.app_url(), host.idp());
                input.username = host.username().map(str::to_string);
                input.mfa = host.mfa();
                apply_aws_sso_app(config, input, host.region())?;
                touched.push(LoginTarget::Aws {
                    app_url: host.app_url().to_string(),
                    app_type: AwsAppType::AwsSso,
                });
            }

            for host in bundle.rancher_hosts() {
                let exists = before.find_rancher_host(host.url()).is_some();
                if !report.tally(Kind::Rancher, exists, overwrite) {
                    continue;
                }
                let mut input = RancherInput::new(host.url(), host.client_id(), host.idp());
                input.username = host.username().map(str::to_string);
                input.mfa = host.mfa();
                apply_rancher(config, input)?;
                touched.push(LoginTarget::Rancher {
                    url: host.url().to_string(),
                });
            }

            Ok(touched)
        })?;

        Ok((config, report))
    }

    pub fn set_use_keyring(&self, enabled: bool) -> Result<AppConfig, SettingsEditError> {
        self.update(|config| {
            apply_use_keyring(config, enabled);
            Ok(())
        })
    }

    /// Sets the YubiKey that wraps secrets, or `None` to stop wrapping.
    pub fn set_yubikey(
        &self,
        yubikey: Option<YubikeyConfig>,
    ) -> Result<AppConfig, SettingsEditError> {
        self.update(|config| {
            apply_yubikey(config, yubikey);
            Ok(())
        })
    }

    pub fn set_wrap_cached_secrets(&self, enabled: bool) -> Result<AppConfig, SettingsEditError> {
        self.update(|config| {
            apply_wrap_cached_secrets(config, enabled);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ports::config::InMemoryConfigStore;
    use crate::domain::ports::config::MockConfigStore;
    use crate::domain::ports::login_check::{MockLoginCheck, NoLoginCheck};

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
        assert!(text
            .ends_with("the identity provider \"suse\" is not configured, run `c9s config idp`"));
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
    fn check_aws_app_never_saves() {
        let store = Arc::new(InMemoryConfigStore::default());
        let service = SettingsService::new(store.clone());
        service.save_idp(idp_input(), SaveAs::Upsert).unwrap();
        let saves = store.saves();

        service
            .check_aws_app(&AwsAppInput::new(APP_URL, "suse"), &AwsAppKind::Aws)
            .unwrap();
        assert!(service
            .check_aws_app(&AwsAppInput::new("nope", "suse"), &AwsAppKind::Aws)
            .is_err());
        assert!(service.check_idp(&idp_input()).is_ok());
        assert!(service
            .check_rancher(&RancherInput::new("nope", "c", "suse"))
            .is_err());
        assert_eq!(store.saves(), saves);
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
        let ok =
            |m: SaveAs<()>, taken: bool, old: bool| check_mode(&m, "k", taken, |_| old).is_ok();
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
}
