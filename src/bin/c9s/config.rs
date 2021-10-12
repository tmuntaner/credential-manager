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
    OktaAws(ConfigAddOktaAws),
    OktaAwsSso(ConfigAddOktaAwsSso),
}

#[derive(Clap)]
struct ConfigAddOktaAws {
    #[clap(required = true, long)]
    app_url: String,
    #[clap(required = true, short, long)]
    username: String,
    #[clap(short, long)]
    mfa: Option<String>,
    #[clap(long)]
    mfa_provider: Option<String>,
}

#[derive(Clap)]
struct ConfigAddOktaAwsSso {
    #[clap(required = true, long)]
    app_url: String,
    #[clap(required = true, short, long)]
    username: String,
    #[clap(required = true, short, long)]
    region: String,
    #[clap(short, long)]
    mfa: Option<String>,
    #[clap(long)]
    mfa_provider: Option<String>,
}

impl Config {
    pub fn run(&self, settings: &mut AppConfig) -> Result<()> {
        match &self.sub_command {
            ConfigSubCommand::Add(val) => match &val.sub_command {
                ConfigAddSubCommand::OktaAws(val) => val.run(settings),
                ConfigAddSubCommand::OktaAwsSso(val) => val.run(settings),
            },
        }
    }
}

impl ConfigAddOktaAws {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        let host = AwsHost::new(
            self.app_url.clone(),
            self.username.clone(),
            self.mfa.clone(),
            self.mfa_provider.clone(),
        )?;
        settings.add_aws_host(host);
        settings.write_config()?;

        Ok(())
    }
}

impl ConfigAddOktaAwsSso {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        let host = AwsSsoHost::new(
            self.app_url.clone(),
            self.username.clone(),
            self.region.clone(),
            self.mfa.clone(),
            self.mfa_provider.clone(),
        )?;
        settings.add_aws_sso_host(host);
        settings.write_config()?;

        Ok(())
    }
}
