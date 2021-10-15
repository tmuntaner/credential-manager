mod config;
mod credentials;
mod utils;

use crate::config::Config;
use crate::credentials::Credentials;
use anyhow::Result;
use c9s::settings::AppConfig;
use clap::Parser;
use log::LevelFilter;
use simple_logger::SimpleLogger;

#[derive(Parser)]
#[clap(
    version = "1.0",
    author = "Thomas Muntaner <thomas.muntaner@gmail.com>"
)]
struct Opts {
    #[clap(subcommand)]
    sub_command: SubCommand,
}

#[derive(Parser)]
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
        SubCommand::Config(val) => val.run(&mut settings)?,
        SubCommand::Creds(val) => val.run(settings).await?,
    }

    Ok(())
}
