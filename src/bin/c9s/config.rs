use crate::utils::true_or_false;
use anyhow::Result;
use c9s::settings::{AppConfig, AwsHost, AwsProvider, AwsSsoHost};
use clap::Parser;

#[derive(Parser)]
pub struct Config {
    #[clap(subcommand)]
    sub_command: ConfigSubCommand,
}

#[derive(Parser)]
enum ConfigSubCommand {
    Add(ConfigAdd),
    Global(ConfigGlobal),
}

#[derive(Parser)]
struct ConfigAdd {
    #[clap(subcommand)]
    sub_command: ConfigAddSubCommand,
}

#[derive(Parser)]
enum ConfigAddSubCommand {
    OktaAws(ConfigAddOktaAws),
    OktaAwsSso(ConfigAddOktaAwsSso),
}

#[derive(Parser)]
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

#[derive(Parser)]
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

#[derive(Parser)]
struct ConfigGlobal {
    #[clap(subcommand)]
    sub_command: ConfigGlobalSubCommand,
}

#[derive(Parser)]
enum ConfigGlobalSubCommand {
    UseKeyring(ConfigGlobalUseKeyRing),
    DefaultAwsProvider(DefaultAwsProvider),
}

#[derive(Parser)]
/// Whether or not c9s should use a keyring service.
struct ConfigGlobalUseKeyRing {
    /// Accepted values: "true" or "false"
    #[clap(long, parse(try_from_str = true_or_false))]
    enabled: bool,
}

#[derive(Parser)]
/// Sets the default AWS provider
struct DefaultAwsProvider {
    #[clap(long, arg_enum)]
    provider: AwsProvider,
}

impl Config {
    pub fn run(&self, settings: &mut AppConfig) -> Result<()> {
        match &self.sub_command {
            ConfigSubCommand::Add(val) => match &val.sub_command {
                ConfigAddSubCommand::OktaAws(val) => val.run(settings),
                ConfigAddSubCommand::OktaAwsSso(val) => val.run(settings),
            },
            ConfigSubCommand::Global(val) => match &val.sub_command {
                ConfigGlobalSubCommand::UseKeyring(val) => val.run(settings),
                ConfigGlobalSubCommand::DefaultAwsProvider(val) => val.run(settings),
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

impl ConfigGlobalUseKeyRing {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        settings.set_use_keyring(self.enabled);
        settings.write_config()?;

        Ok(())
    }
}

impl DefaultAwsProvider {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        settings.set_default_aws_provider(self.provider);
        settings.write_config()?;

        Ok(())
    }
}
