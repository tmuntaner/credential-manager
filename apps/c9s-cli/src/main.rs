pub mod app;
mod args;
mod config;
mod credentials;
#[cfg(unix)]
mod daemon;
mod utils;

use crate::app::CliApplication;
use crate::args::PromptModeArg;
use crate::config::Config;
use crate::credentials::Credentials;
#[cfg(unix)]
use crate::daemon::Daemon;
use anyhow::Result;
use c9s::domain::services::settings_editor::SettingsService;
use c9s::outbound::config::config_store::ConfigFileAdapter;
use clap::Parser;
use std::sync::Arc;

#[derive(Parser)]
#[clap(version, author = "Thomas Muntaner <thomas.muntaner@gmail.com>")]
struct Opts {
    /// How to ask for secrets: a popup when available, or only the terminal
    #[clap(long, global = true, value_enum, env = "C9S_PROMPT")]
    prompt: Option<PromptModeArg>,
    #[clap(subcommand)]
    sub_command: SubCommand,
}

#[derive(Parser)]
enum SubCommand {
    Config(Config),
    Creds(Credentials),
    #[cfg(unix)]
    Daemon(Daemon),
    Licenses(Licenses),
}

#[derive(Parser)]
pub struct Licenses {}

impl Licenses {
    pub fn run(&self) -> Result<()> {
        let my_str = include_str!("../../../license.txt");
        print!("{my_str}");

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt: Opts = Opts::parse();
    let settings_service = SettingsService::new(Arc::new(ConfigFileAdapter::in_user_config_dir()?));
    let config = settings_service.load()?;
    let (interaction, notifier) = utils::interaction(&config, opt.prompt.map(Into::into));
    let application = CliApplication::new(config, settings_service, interaction, notifier);

    match opt.sub_command {
        SubCommand::Config(val) => val.run(&application).await?,
        SubCommand::Creds(val) => val.run(&application).await?,
        #[cfg(unix)]
        SubCommand::Daemon(val) => val.run(&application).await?,
        SubCommand::Licenses(val) => val.run()?,
    }

    Ok(())
}
