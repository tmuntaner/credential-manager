use anyhow::Result;
use c9s::settings::{AppConfig, AwsHost, AwsSsoHost};
use clap::Clap;

#[derive(Clap)]
pub struct Config {
    #[clap(subcommand)]
    sub_command: ConfigSubCommand,
}

#[derive(Clap)]
enum ConfigSubCommand {
    Add(ConfigAdd),
}

#[derive(Clap)]
struct ConfigAdd {
    #[clap(subcommand)]
    sub_command: ConfigAddSubCommand,
}

#[derive(Clap)]
enum ConfigAddSubCommand {
    Aws(ConfigAddAws),
    AwsSso(ConfigAddAwsSso),
}

#[derive(Clap)]
struct ConfigAddAws {
    #[clap(required = true, long)]
    app_url: String,
    #[clap(required = true, short, long)]
    username: String,
}

#[derive(Clap)]
struct ConfigAddAwsSso {
    #[clap(required = true, long)]
    app_url: String,
    #[clap(required = true, short, long)]
    username: String,
    #[clap(required = true, short, long)]
    region: String,
}

impl Config {
    pub fn run(&self, settings: &mut AppConfig) -> Result<()> {
        match &self.sub_command {
            ConfigSubCommand::Add(val) => match &val.sub_command {
                ConfigAddSubCommand::Aws(val) => val.run(settings),
                ConfigAddSubCommand::AwsSso(val) => val.run(settings),
            },
        }
    }
}

impl ConfigAddAws {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        let host = AwsHost::new(self.app_url.clone(), self.username.clone())?;
        settings.add_aws_host(host);
        settings.write_config()?;

        Ok(())
    }
}

impl ConfigAddAwsSso {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
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
