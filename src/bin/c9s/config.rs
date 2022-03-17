use crate::utils::true_or_false;
use anyhow::Result;
use c9s::settings::{AppConfig, AwsDefaults, AwsHost, AwsSsoHost, SsoProvider};
use clap::Parser;

#[derive(Parser)]
pub struct Config {
    #[clap(subcommand)]
    sub_command: ConfigSubCommand,
}

#[derive(Parser)]
enum ConfigSubCommand {
    Aws(ConfigAws),
    Global(ConfigGlobal),
}

#[derive(Parser)]
struct ConfigAws {
    #[clap(subcommand)]
    sub_command: ConfigAwsSubCommand,
}

#[derive(Parser)]
enum ConfigAwsSubCommand {
    Defaults(ConfigAwsDefaults),
    OktaAws(ConfigAwsOktaAws),
    OktaAwsSso(ConfigAwsOktaAwsSso),
}

#[derive(Parser)]
struct ConfigAwsOktaAws {
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
struct ConfigAwsOktaAwsSso {
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
struct ConfigAwsDefaults {
    #[clap(long, arg_enum)]
    sso_provider: SsoProvider,
}

impl Config {
    pub fn run(&self, settings: &mut AppConfig) -> Result<()> {
        match &self.sub_command {
            ConfigSubCommand::Aws(val) => match &val.sub_command {
                ConfigAwsSubCommand::Defaults(val) => val.run(settings),
                ConfigAwsSubCommand::OktaAws(val) => val.run(settings),
                ConfigAwsSubCommand::OktaAwsSso(val) => val.run(settings),
            },
            ConfigSubCommand::Global(val) => match &val.sub_command {
                ConfigGlobalSubCommand::UseKeyring(val) => val.run(settings),
            },
        }
    }
}

impl ConfigAwsOktaAws {
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

impl ConfigAwsOktaAwsSso {
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

impl ConfigAwsDefaults {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        let defaults = AwsDefaults::new(self.sso_provider);

        settings.set_aws_defaults(defaults);
        settings.write_config()?;

        Ok(())
    }
}
