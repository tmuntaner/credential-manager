//! Changes to the settings, and the validation that goes with them.
//!
//! Every driving adapter (the CLI, the GUI) edits the settings through here, so they accept and refuse the same
//! things. The `apply` functions change settings in memory; [`SettingsService`] is the one way to load, change and
//! save them: every change goes through it, and nothing is saved when a change is refused.

use crate::domain::models::idp::IdpType;
use crate::domain::models::login::ResolveError;
use crate::domain::models::mfa::MfaSelection;
use crate::domain::models::settings::{
    same_app_url, AppConfig, AwsAppType, AwsHost, AwsSsoHost, Idp, RancherHost, SettingsBundle,
    SettingsError, YubikeyConfig,
};
use crate::domain::ports::config::{ConfigError, ConfigStore};
use crate::domain::services::settings_check::{resolve, still_resolves, Entry};
use crate::domain::services::settings_validation::{
    allow_insecure_localhost, check_client_id, check_name, check_optional_username, check_region,
    check_url, check_username,
};
use std::collections::BTreeMap;
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
}

/// Why the settings were not changed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SettingsEditError {
    /// A value is not valid.
    #[error(transparent)]
    Invalid(#[from] SettingsError),

    /// A value does not pass the checks of the settings (an `http` web address, a bad region, ...).
    #[error("{message}")]
    InvalidField {
        field: InvalidField,
        message: String,
    },

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

/// Runs one check of `settings_validation`, and names the field when it fails.
fn valid(field: InvalidField, result: Result<String, String>) -> Result<String, SettingsEditError> {
    result.map_err(|message| SettingsEditError::InvalidField { field, message })
}

fn valid_url(input: &str) -> Result<String, SettingsEditError> {
    valid(
        InvalidField::Url,
        check_url(input, allow_insecure_localhost()),
    )
}

fn valid_username(input: Option<String>) -> Result<Option<String>, SettingsEditError> {
    check_optional_username(input.as_deref()).map_err(|message| SettingsEditError::InvalidField {
        field: InvalidField::Username,
        message,
    })
}

/// The identity provider an app logs in with has to be configured.
fn known_idp(settings: &AppConfig, idp: &str) -> Result<String, SettingsEditError> {
    Ok(settings.resolve_idp(idp)?.name().to_string())
}

/// Adds an identity provider, or updates the one with the same name.
pub fn apply_idp(settings: &mut AppConfig, input: IdpInput) -> Result<(), SettingsEditError> {
    let name = valid(InvalidField::Name, check_name(&input.name))?;
    let url = valid_url(&input.url)?;
    let username = valid(InvalidField::Username, check_username(&input.username))?;
    let idp = Idp::new(name, input.idp_type, url, username, input.mfa)?;
    settings.add_idp(idp);

    Ok(())
}

/// Adds an AWS IAM role app, or updates the one with the same url.
pub fn apply_aws_app(
    settings: &mut AppConfig,
    input: AwsAppInput,
) -> Result<(), SettingsEditError> {
    let idp = known_idp(settings, &input.idp)?;
    let app_url = valid_url(&input.app_url)?;
    let username = valid_username(input.username)?;
    let host = AwsHost::new(app_url, username, idp, input.mfa)?;
    settings.add_aws_host(host);

    Ok(())
}

/// Adds an AWS IAM Identity Center app, or updates the one with the same url.
pub fn apply_aws_sso_app(
    settings: &mut AppConfig,
    input: AwsAppInput,
    region: impl Into<String>,
) -> Result<(), SettingsEditError> {
    let idp = known_idp(settings, &input.idp)?;
    let app_url = valid_url(&input.app_url)?;
    let username = valid_username(input.username)?;
    let region = valid(InvalidField::Region, check_region(&region.into()))?;
    let host = AwsSsoHost::new(app_url, username, idp, region, input.mfa)?;
    settings.add_aws_sso_host(host);

    Ok(())
}

/// Adds a Rancher, or updates the one with the same url.
pub fn apply_rancher(
    settings: &mut AppConfig,
    input: RancherInput,
) -> Result<(), SettingsEditError> {
    let idp = known_idp(settings, &input.idp)?;
    let url = valid_url(&input.url)?;
    let client_id = valid(InvalidField::ClientId, check_client_id(&input.client_id))?;
    let username = valid_username(input.username)?;
    let host = RancherHost::new(url, client_id, idp, username, input.mfa)?;
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

/// Edits the settings kept in a [`ConfigStore`]: every change is loaded, applied and saved here, and nothing is
/// saved when a change is refused.
pub struct SettingsService<S: ConfigStore> {
    store: S,
    login_checks: bool,
}

impl<S: ConfigStore> SettingsService<S> {
    pub fn new(store: S) -> Self {
        Self {
            store,
            login_checks: false,
        }
    }

    /// Opt in to login checks. The changes still save; the changes to apps (the `save_*` and `remove_*` methods)
    /// are also refused when what they set up does not resolve a login, or when they stop an app that resolved before from resolving.
    pub fn with_login_checks(mut self) -> Self {
        self.login_checks = true;

        self
    }

    /// The settings as stored. Never saves.
    pub fn load(&self) -> Result<AppConfig, SettingsEditError> {
        Ok(self.store.load()?)
    }

    /// Loads the settings, applies `change` and saves the result, which is returned.
    /// Nothing is saved when `change` fails.
    pub fn update(
        &self,
        change: impl FnOnce(&mut AppConfig) -> Result<(), SettingsEditError>,
    ) -> Result<AppConfig, SettingsEditError> {
        let mut config = self.store.load()?;
        change(&mut config)?;
        self.store.save(&config)?;

        Ok(config)
    }

    /// Like [`update`](Self::update), and refuses a change that stops an app that resolved a login before from
    /// resolving it. `change` receives the settings before the change, and the ones to change.
    pub fn update_checked(
        &self,
        change: impl FnOnce(&AppConfig, &mut AppConfig) -> Result<(), SettingsEditError>,
    ) -> Result<AppConfig, SettingsEditError> {
        let before = self.store.load()?;
        let mut config = before.clone();
        change(&before, &mut config)?;
        still_resolves(&before, &config)?;
        self.store.save(&config)?;

        Ok(config)
    }

    fn edit(
        &self,
        change: impl FnOnce(&AppConfig, &mut AppConfig) -> Result<(), SettingsEditError>,
    ) -> Result<AppConfig, SettingsEditError> {
        if self.login_checks {
            self.update_checked(change)
        } else {
            self.update(|config| {
                let before = config.clone();
                change(&before, config)
            })
        }
    }

    /// Adds an identity provider, or updates the one with the same name.
    pub fn save_idp(
        &self,
        input: IdpInput,
        mode: SaveAs<()>,
    ) -> Result<AppConfig, SettingsEditError> {
        self.edit(|before, config| {
            match (&mode, before.find_idp(&input.name).is_some()) {
                (SaveAs::New, true) => {
                    return Err(SettingsEditError::AlreadyExists { key: input.name })
                }
                (SaveAs::Replace(()), false) => return Err(SettingsEditError::Gone),
                _ => {}
            }

            apply_idp(config, input)
        })
    }

    pub fn remove_idp(&self, name: &str) -> Result<AppConfig, SettingsEditError> {
        self.edit(|_, config| apply_remove_idp(config, name))
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
            match &mode {
                SaveAs::Upsert => apply_aws_app_of_kind(config, input, kind)?,
                SaveAs::New => {
                    if has_aws(before, &url, app_type) {
                        return Err(SettingsEditError::AlreadyExists { key: url });
                    }
                    apply_aws_app_of_kind(config, input, kind)?;
                }
                SaveAs::Replace((old_url, old_type)) => {
                    if !has_aws(before, old_url, *old_type) {
                        return Err(SettingsEditError::Gone);
                    }
                    apply_replace_aws_app(config, old_url, *old_type, input, kind)?;
                }
            }

            if self.login_checks {
                resolve(config, &Entry::Aws(url, app_type))?;
            }

            Ok(())
        })
    }

    pub fn remove_aws_app(
        &self,
        app_url: &str,
        app_type: AwsAppType,
    ) -> Result<AppConfig, SettingsEditError> {
        self.edit(|_, config| apply_remove_aws_app(config, app_url, app_type))
    }

    /// Adds a Rancher, or replaces one (its url may change).
    pub fn save_rancher(
        &self,
        input: RancherInput,
        mode: SaveAs<String>,
    ) -> Result<AppConfig, SettingsEditError> {
        let url = input.url.clone();
        self.edit(|before, config| {
            match &mode {
                SaveAs::Upsert => apply_rancher(config, input)?,
                SaveAs::New => {
                    if before.find_rancher_host(&url).is_some() {
                        return Err(SettingsEditError::AlreadyExists { key: url });
                    }
                    apply_rancher(config, input)?;
                }
                SaveAs::Replace(old_url) => {
                    if before.find_rancher_host(old_url).is_none() {
                        return Err(SettingsEditError::Gone);
                    }
                    apply_replace_rancher(config, old_url, input)?;
                }
            }

            if self.login_checks {
                resolve(config, &Entry::Rancher(url))?;
            }

            Ok(())
        })
    }

    pub fn remove_rancher(&self, url: &str) -> Result<AppConfig, SettingsEditError> {
        self.edit(|_, config| apply_remove_rancher(config, url))
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
                if self.login_checks {
                    resolve(
                        config,
                        &Entry::Aws(host.app_url().to_string(), AwsAppType::Aws),
                    )?;
                }
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
                if self.login_checks {
                    resolve(
                        config,
                        &Entry::Aws(host.app_url().to_string(), AwsAppType::AwsSso),
                    )?;
                }
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
                if self.login_checks {
                    resolve(config, &Entry::Rancher(host.url().to_string()))?;
                }
            }

            Ok(())
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
    use crate::domain::ports::config::memory::MemoryStore;
    use crate::domain::ports::config::MockConfigStore;

    const IDP_URL: &str = "https://id.example.com/";
    const APP_URL: &str = "https://id.example.com/application/saml/aws/sso/binding/init/";

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
            Err(SettingsEditError::InvalidField {
                field: InvalidField::Url,
                ..
            })
        ));
        assert!(settings.idps().is_empty());
    }

    #[test]
    fn an_app_needs_a_configured_idp() {
        let mut settings = AppConfig::default();
        let err = apply_aws_app(&mut settings, AwsAppInput::new(APP_URL, "suse"))
            .map(|_| ())
            .unwrap_err();
        assert!(matches!(
            err,
            SettingsEditError::Invalid(SettingsError::UnknownIdp(_))
        ));

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

        assert!(matches!(
            apply_aws_app(&mut settings, input),
            Err(SettingsEditError::Invalid(SettingsError::UnknownIdp(_)))
        ));
    }

    #[test]
    fn rancher_needs_a_configured_idp() {
        let mut settings = AppConfig::default();
        let input = RancherInput::new("https://rancher.example.com", "rancher", "suse");
        assert!(matches!(
            apply_rancher(&mut settings, input.clone()),
            Err(SettingsEditError::Invalid(SettingsError::UnknownIdp(_)))
        ));

        apply_idp(&mut settings, idp_input()).unwrap();
        apply_rancher(&mut settings, input).unwrap();
        assert_eq!(settings.rancher_hosts().len(), 1);
    }

    #[test]
    fn the_idp_is_checked_before_the_rest_of_an_app() {
        // The same order for every kind of app: the identity provider first, so a form is not fixed field by
        // field only to find out it has no identity provider.
        let mut settings = AppConfig::default();
        let unknown = |e: SettingsEditError| {
            matches!(e, SettingsEditError::Invalid(SettingsError::UnknownIdp(_)))
        };

        let err = apply_aws_app(&mut settings, AwsAppInput::new("not a url", "suse")).unwrap_err();
        assert!(unknown(err));
        let err = apply_aws_sso_app(&mut settings, AwsAppInput::new("not a url", "suse"), "mars")
            .unwrap_err();
        assert!(unknown(err));
        let err =
            apply_rancher(&mut settings, RancherInput::new("not a url", "", "suse")).unwrap_err();
        assert!(unknown(err));
    }

    #[test]
    fn update_saves_once_on_success_and_never_on_error() {
        let store = MemoryStore::default();
        let service = SettingsService::new(&store);

        let err = service
            .update(|config| apply_aws_app(config, AwsAppInput::new(APP_URL, "suse")))
            .map(|_| ())
            .unwrap_err();
        assert!(matches!(err, SettingsEditError::Invalid(_)));
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
        let store = MemoryStore::default();
        store.fail_saves();
        let service = SettingsService::new(&store);

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
        let service = SettingsService::new(mock);

        assert!(matches!(
            service.set_wrap_cached_secrets(true),
            Err(SettingsEditError::Store(_))
        ));
    }

    #[test]
    fn update_checked_refuses_a_change_that_breaks_an_app() {
        let store = MemoryStore::default();
        let service = SettingsService::new(&store).with_login_checks();
        service.save_idp(idp_input(), SaveAs::New).unwrap();
        service
            .save_aws_app(
                AwsAppInput::new(APP_URL, "suse"),
                AwsAppKind::Aws,
                SaveAs::New,
            )
            .unwrap();
        let saves = store.saves();

        // Without any identity provider the app would have no username.
        let err = service
            .update_checked(|_, config| {
                config.remove_idp("suse");
                Ok(())
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

    #[test]
    fn new_refuses_what_exists_and_replace_refuses_what_is_gone() {
        let store = MemoryStore::default();
        let service = SettingsService::new(&store);
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
    }

    #[test]
    fn a_replace_onto_another_entry_is_refused() {
        let store = MemoryStore::default();
        let service = SettingsService::new(&store);
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
        let store = MemoryStore::default();
        let service = SettingsService::new(&store);
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
        let store = MemoryStore::default();
        let service = SettingsService::new(&store);
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
            let store = MemoryStore::default();
            let service = SettingsService::new(&store).with_login_checks();
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
        let store = MemoryStore::default();
        let service = SettingsService::new(&store);
        let invalid = |field| move |e| matches!(e, SettingsEditError::InvalidField { field: f, .. } if f == field);

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
        let store = MemoryStore::default();
        let service = SettingsService::new(&store);

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
        let store = MemoryStore::default();
        let service = SettingsService::new(&store);
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
    fn seeded() -> MemoryStore {
        let store = MemoryStore::default();
        let service = SettingsService::new(&store);
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
        let service = SettingsService::new(&store);
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
        let bundle = SettingsService::new(&seeded())
            .export(&["suse".to_string()])
            .unwrap();
        let target = MemoryStore::default();
        let service = SettingsService::new(&target);

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
        let bundle = SettingsService::new(&store)
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
            SettingsService::new(&store).export(&["nope".to_string()]),
            Err(SettingsEditError::Invalid(SettingsError::UnknownIdp(_)))
        ));
    }

    #[test]
    fn an_import_adds_everything_and_keeps_the_global_settings() {
        let bundle = SettingsService::new(&seeded())
            .export(&["suse".to_string()])
            .unwrap();
        let target = MemoryStore::default();
        let service = SettingsService::new(&target);
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
        let bundle = SettingsService::new(&seeded())
            .export(&["suse".to_string()])
            .unwrap();
        let target = MemoryStore::default();
        let service = SettingsService::new(&target);
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
        let bundle = SettingsService::new(&seeded())
            .export(&["suse".to_string()])
            .unwrap();
        let only_apps = SettingsBundle::new(
            Vec::new(),
            bundle.aws_hosts().to_vec(),
            Vec::new(),
            Vec::new(),
        );
        let target = MemoryStore::default();

        assert!(matches!(
            SettingsService::new(&target).import(&only_apps, ImportMode::SkipExisting, &names()),
            Err(SettingsEditError::Invalid(SettingsError::UnknownIdp(_)))
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
        let target = MemoryStore::default();

        assert!(matches!(
            SettingsService::new(&target).import(
                &bundle,
                ImportMode::SkipExisting,
                &BTreeMap::from([("bad".to_string(), "user".to_string())])
            ),
            Err(SettingsEditError::InvalidField {
                field: InvalidField::Url,
                ..
            })
        ));
        assert_eq!(target.saves(), 0);
    }
}
