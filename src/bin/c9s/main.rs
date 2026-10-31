mod args;
mod config;
mod credentials;
mod utils;

use crate::args::PromptModeArg;
use crate::config::Config;
use crate::credentials::Credentials;
use anyhow::Result;
use c9s::domain::ports::config::ConfigStore;
use c9s::outbound::config::config_store::ConfigFileAdapter;
use clap::Parser;

#[derive(Parser)]
#[clap(
    version = "1.0",
    author = "Thomas Muntaner <thomas.muntaner@gmail.com>"
)]
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
    let store = ConfigFileAdapter::in_user_config_dir()?;
    let mut settings = store.load()?;
    let (interaction, notifier) = utils::interaction(&settings, opt.prompt.map(Into::into));

    match opt.sub_command {
        SubCommand::Config(val) => {
            val.run(&mut settings, interaction, notifier).await?;
            store.save(&settings)?;
        }
        SubCommand::Creds(val) => val.run(settings, interaction, notifier).await?,
        SubCommand::Licenses(val) => val.run()?,
    }

    Ok(())
}
