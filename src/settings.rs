use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use url::Url;

#[derive(Serialize, Deserialize)]
pub struct Config {
    hosts: Option<Vec<Host>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Host {
    app_url: String,
    username: String,
}

impl Config {
    pub fn add_host(&mut self, host: Host) -> Result<()> {
        let hosts = self.hosts.get_or_insert(vec![]);
        match hosts.iter_mut().find(|i| i.app_url == host.app_url.clone()) {
            Some(existing) => {
                existing.username = host.username;
            }
            None => {
                hosts.push(host);
            }
        }

        Ok(())
    }

    pub fn host(self) -> Option<Host> {
        self.hosts?.get(0).cloned()
    }

    pub fn find_host(self, app_url: String) -> Option<Host> {
        match self.hosts {
            Some(hosts) => hosts.iter().find(|host| app_url == host.app_url).cloned(),
            None => None,
        }
    }

    pub fn read_config() -> Result<Self> {
        let config_file = Config::config_file()?;
        let config_contents = fs::read(config_file)?;
        let config_contents = String::from_utf8(config_contents)?;
        let config: Config = toml::from_str(config_contents.as_str())?;

        Ok(config)
    }

    pub fn write_config(&self) -> Result<()> {
        let config_dir = Config::config_dir()?;
        fs::create_dir_all(config_dir)?;

        let config_file = Config::config_file()?;

        let toml = toml::to_string(&self)?;
        fs::write(config_file, toml).expect("Unable to write file");

        Ok(())
    }

    fn config_dir() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| anyhow!("could not determine config directory"))?
            .join("c9s");

        Ok(config_dir)
    }

    fn config_file() -> Result<PathBuf> {
        let config_file = Config::config_dir()?.join("settings.toml");

        Ok(config_file)
    }
}

impl Host {
    pub fn new(app_url: String, username: String) -> Result<Self> {
        let mut app_url = Url::parse(app_url.as_str())?;

        // remove query
        app_url.set_query(None);

        // remove trailing slash
        app_url
            .path_segments_mut()
            .map_err(|_| "cannot be base")
            .map_err(|e| anyhow!(e))?
            .pop_if_empty();

        Ok(Host {
            app_url: String::from(app_url),
            username,
        })
    }

    pub fn app_url(&self) -> String {
        self.app_url.clone()
    }

    pub fn username(&self) -> String {
        self.username.clone()
    }
}
