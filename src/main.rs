mod app;
mod authority_ops;
mod cli;
mod config;
mod doctor;
mod interactive;
mod keystore;
mod output;
mod pairing;
mod protocol_ops;
mod runtime;
mod swarm_ops;
mod transport;

use anyhow::Result;
use clap::Parser;

use app::{AppContext, run_command};
use cli::Cli;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let ctx = AppContext::from_cli(&cli)?;
    run_command(ctx, cli)
}
