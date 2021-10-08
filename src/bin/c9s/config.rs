use anyhow::Result;
use c9s::settings::{AppConfig, AwsHost, AwsSsoHost};
use clap::Clap;

#[derive(Clap)]
pub struct Config {
    #[clap(subcommand)]
    pub sub_command: ConfigSubCommand,
}

#[derive(Clap)]
pub enum ConfigSubCommand {
    Add(ConfigAdd),
}

#[derive(Clap)]
pub struct ConfigAdd {
    #[clap(subcommand)]
    pub sub_command: ConfigAddSubCommand,
}

#[derive(Clap)]
pub enum ConfigAddSubCommand {
    Aws(ConfigAddAws),
    AwsSso(ConfigAddAwsSso),
}

#[derive(Clap)]
pub struct ConfigAddAws {
    #[clap(required = true, long)]
    app_url: String,
    #[clap(required = true, short, long)]
    username: String,
}

#[derive(Clap)]
pub struct ConfigAddAwsSso {
    #[clap(required = true, long)]
    app_url: String,
    #[clap(required = true, short, long)]
    username: String,
    #[clap(required = true, short, long)]
    region: String,
}

impl ConfigAddAws {
    pub fn run(&self, settings: &mut AppConfig) -> Result<()> {
        let host = AwsHost::new(self.app_url.clone(), self.username.clone())?;
        settings.add_aws_host(host);
        settings.write_config()?;

        Ok(())
    }
}

impl ConfigAddAwsSso {
    pub fn run(&self, settings: &mut AppConfig) -> Result<()> {
        let host = AwsSsoHost::new(
            self.app_url.clone(),
            self.username.clone(),
            self.region.clone(),
        )?;
        settings.add_aws_sso_host(host);
        settings.write_config()?;

        Ok(())
    }
}
