mod config;
mod proxy;
mod seccomp;
mod supervisor;
mod tcp_broker;

use anyhow::{Context, Result};
use clap::Parser;

use crate::config::Cli;

fn main() {
    let result = if supervisor::is_child_stage() {
        supervisor::run_child_stage()
    } else {
        run_supervisor()
    };

    match result {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("yatht: {err:#}");
            std::process::exit(1);
        }
    }
}

fn run_supervisor() -> Result<i32> {
    let cli = Cli::parse();
    let cfg = config::EffectiveConfig::load(cli).context("load configuration")?;

    seccomp::query_notif_sizes().context("kernel does not support seccomp user notification")?;

    supervisor::run(cfg)
}
