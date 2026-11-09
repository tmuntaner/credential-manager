use super::apply::{apply_aws_app, apply_aws_sso_app, apply_idp, apply_rancher};
use super::error::SettingsEditError;
use super::input::{AwsAppInput, IdpInput, RancherInput};
use super::service::SettingsService;
use crate::domain::models::login::LoginTarget;
use crate::domain::models::settings::{AppConfig, AwsAppType, SettingsBundle};
use crate::domain::ports::login_check::LoginCheck;
use std::collections::BTreeMap;

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

impl<C: LoginCheck> SettingsService<C> {
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
}
