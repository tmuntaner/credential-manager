use crate::okta::okta_client::MfaSelection;
use anyhow::{anyhow, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use url::Url;

#[derive(Serialize, Deserialize)]
pub struct AppConfig {
    global_settings: Option<GlobalSettings>,
    okta_aws_hosts: Option<Vec<AwsHost>>,
    okta_aws_sso_hosts: Option<Vec<AwsSsoHost>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GlobalSettings {
    use_keyring: Option<bool>,
    aws_defaults: Option<AwsDefaults>,
}

impl GlobalSettings {
    fn default() -> Self {
        Self {
            use_keyring: None,
            aws_defaults: Some(AwsDefaults::default()),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AwsHost {
    app_url: String,
    username: String,
    mfa: Option<String>,
    mfa_provider: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AwsSsoHost {
    app_url: String,
    username: String,
    region: String,
    mfa: Option<String>,
    mfa_provider: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct AwsDefaults {
    sso_provider: SsoProvider,
}

#[derive(ValueEnum, PartialEq, Eq, Debug, Clone, Copy, Deserialize, Serialize, Default)]
pub enum SsoProvider {
    #[serde(rename = "okta-aws")]
    #[default]
    OktaAws,
    #[serde(rename = "okta-aws-sso")]
    OktaAwsSso,
}

impl AppConfig {
    pub fn set_aws_defaults(&mut self, defaults: AwsDefaults) {
        let global_settings = self
            .global_settings
            .get_or_insert(GlobalSettings::default());

        global_settings.aws_defaults = Some(defaults);
    }

    pub fn aws_defaults(&self) -> AwsDefaults {
        match self.global_settings.clone() {
            Some(global_settings) => global_settings.aws_defaults.unwrap_or_default(),
            None => AwsDefaults::default(),
        }
    }

    pub fn set_use_keyring(&mut self, enable_keyring: bool) {
        let global_settings = self
            .global_settings
            .get_or_insert(GlobalSettings::default());
        global_settings.use_keyring = Some(enable_keyring);
    }

    pub fn keyring_enabled(&self) -> bool {
        match self.global_settings.clone() {
            Some(global_settings) => global_settings.use_keyring.unwrap_or(true),
            None => true,
        }
    }

    pub fn add_aws_host(&mut self, host: AwsHost) {
        let hosts = self.okta_aws_hosts.get_or_insert(vec![]);

        match hosts.iter_mut().find(|i| i.app_url == host.app_url.clone()) {
            Some(existing) => {
                existing.username = host.username;
                existing.mfa = host.mfa;
            }
            None => {
                hosts.push(host);
            }
        }
    }

    pub fn add_aws_sso_host(&mut self, host: AwsSsoHost) {
        let hosts = self.okta_aws_sso_hosts.get_or_insert(vec![]);

        match hosts.iter_mut().find(|i| i.app_url == host.app_url.clone()) {
            Some(existing) => {
                existing.username = host.username;
                existing.region = host.region;
                existing.mfa = host.mfa;
            }
            None => {
                hosts.push(host);
            }
        }
    }

    pub fn aws_hosts(&self) -> Option<AwsHost> {
        self.okta_aws_hosts.clone()?.first().cloned()
    }

    pub fn aws_sso_hosts(&self) -> Option<AwsSsoHost> {
        self.okta_aws_sso_hosts.clone()?.first().cloned()
    }

    pub fn find_aws_sso_host(&self, app_url: String) -> Option<AwsSsoHost> {
        let hosts = self.okta_aws_sso_hosts.clone();
        match hosts {
            Some(hosts) => hosts.iter().find(|host| app_url == host.app_url).cloned(),
            None => None,
        }
    }
    pub fn find_aws_host(&self, app_url: String) -> Option<AwsHost> {
        let hosts = self.okta_aws_hosts.clone();
        match hosts {
            Some(hosts) => hosts.iter().find(|host| app_url == host.app_url).cloned(),
            None => None,
        }
    }

    pub fn read_config() -> Result<Self> {
        let config_file = AppConfig::config_file()?;
        if !Path::new(&config_file).exists() {
            fs::write(config_file.clone(), "")?;
        }
        let config_contents = fs::read(config_file)?;
        let config_contents = String::from_utf8(config_contents)?;
        let config: AppConfig = toml::from_str(config_contents.as_str())?;

        Ok(config)
    }

    pub fn write_config(&self) -> Result<()> {
        let config_dir = AppConfig::config_dir()?;
        fs::create_dir_all(config_dir)?;

        let config_file = AppConfig::config_file()?;

        let toml = toml::to_string(&self)?;
        fs::write(config_file, toml).expect("Unable to write file");

        Ok(())
    }

    fn config_dir() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| anyhow!("could not determine config directory"))?
            .join("c9s");
        fs::create_dir_all(config_dir.clone())?;

        Ok(config_dir)
    }

    fn config_file() -> Result<PathBuf> {
        let config_file = AppConfig::config_dir()?.join("settings.toml");

        Ok(config_file)
    }
}

impl AwsHost {
    pub fn new(
        app_url: String,
        username: String,
        mfa: Option<String>,
        mfa_provider: Option<String>,
    ) -> Result<Self> {
        let mut app_url = Url::parse(app_url.as_str())?;

        // remove query
        app_url.set_query(None);

        // remove trailing slash
        app_url
            .path_segments_mut()
            .map_err(|_| anyhow!("cannot be base"))?
            .pop_if_empty();

        MfaSelection::validate(mfa.clone())?;

        Ok(AwsHost {
            app_url: String::from(app_url),
            mfa,
            username,
            mfa_provider,
        })
    }

    pub fn app_url(&self) -> String {
        self.app_url.clone()
    }

    pub fn username(&self) -> String {
        self.username.clone()
    }
}

impl AwsSsoHost {
    pub fn new(
        app_url: String,
        username: String,
        region: String,
        mfa: Option<String>,
        mfa_provider: Option<String>,
    ) -> Result<Self> {
        let mut app_url = Url::parse(app_url.as_str())?;

        // remove query
        app_url.set_query(None);

        // remove trailing slash
        app_url
            .path_segments_mut()
            .map_err(|_| anyhow!("cannot be base"))?
            .pop_if_empty();

        MfaSelection::validate(mfa.clone())?;

        Ok(AwsSsoHost {
            app_url: String::from(app_url),
            username,
            region,
            mfa,
            mfa_provider,
        })
    }

    pub fn app_url(&self) -> String {
        self.app_url.clone()
    }

    pub fn username(&self) -> String {
        self.username.clone()
    }

    pub fn region(&self) -> String {
        self.region.clone()
    }
}

pub trait OktaMfa {
    fn mfa(&self) -> Option<MfaSelection>;
    fn mfa_provider(&self) -> Option<String>;
}

impl OktaMfa for AwsHost {
    fn mfa(&self) -> Option<MfaSelection> {
        self.mfa.clone().map(MfaSelection::from_string)
    }

    fn mfa_provider(&self) -> Option<String> {
        self.mfa_provider.clone()
    }
}

impl OktaMfa for AwsSsoHost {
    fn mfa(&self) -> Option<MfaSelection> {
        self.mfa.clone().map(MfaSelection::from_string)
    }

    fn mfa_provider(&self) -> Option<String> {
        self.mfa_provider.clone()
    }
}

impl AwsDefaults {
    pub fn new(sso_provider: SsoProvider) -> Self {
        Self { sso_provider }
    }

    pub fn sso_provider(&self) -> SsoProvider {
        self.sso_provider
    }
}
