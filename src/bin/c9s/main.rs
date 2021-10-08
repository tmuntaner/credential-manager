mod config;
mod credentials;
mod utils;

use crate::config::{Config, ConfigAddSubCommand, ConfigSubCommand};
use crate::credentials::{Credentials, CredentialsSubCommands};
use anyhow::Result;
use c9s::settings::AppConfig;
use clap::{AppSettings, Clap};
use log::LevelFilter;
use simple_logger::SimpleLogger;

#[derive(Clap)]
#[clap(
    version = "1.0",
    author = "Thomas Muntaner <thomas.muntaner@gmail.com>"
)]
#[clap(setting = AppSettings::ColoredHelp)]
struct Opts {
    #[clap(subcommand)]
    sub_command: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    Config(Config),
    Creds(Credentials),
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt: Opts = Opts::parse();
    let mut settings = AppConfig::read_config()?;

    SimpleLogger::new().with_level(LevelFilter::Info).init()?;

    match opt.sub_command {
        SubCommand::Config(val) => match val.sub_command {
            ConfigSubCommand::Add(val) => match val.sub_command {
                ConfigAddSubCommand::Aws(val) => val.run(&mut settings)?,
                ConfigAddSubCommand::AwsSso(val) => val.run(&mut settings)?,
            },
        },
        SubCommand::Creds(val) => match val.sub_command {
            CredentialsSubCommands::AwsSso(val) => val.run(settings).await?,
            CredentialsSubCommands::Aws(val) => val.run(settings).await?,
        },
    }

    Ok(())
}
