//! wlsctx — give a Wayland socket an attached security context so the
//! compositor can identify sandboxed clients.
//!
//! For now this is the original single-purpose mode (the future
//! `wlsctx wayland` subcommand); the rework (PLAN.md) turns this into a
//! subcommand-based CLI with the in-process sandbox.

mod cli;
mod profile;
mod sandbox;
mod testutil;
mod wayland;

use anyhow::Result;
use clap::Parser;
use env_logger::Env;
use log::{Level, info, log_enabled, warn};

use crate::cli::Cli;
use crate::wayland::context::create_security_context;
use crate::wayland::listener::obtain_listener;
use crate::wayland::signals::run_signal_loop;

fn main() -> Result<()> {
    let env = Env::default().default_filter_or("warn");
    env_logger::init_from_env(env);
    let cli = Cli::parse();
    let (app_id, instance_id, listener) = obtain_listener(&cli)?;
    let sandbox_engine = cli.sandbox_engine;

    if log_enabled!(Level::Info)
        && let Ok(local_addr) = listener.local_addr()
    {
        info!("Listening on {local_addr:?}")
    }

    // Keep BOTH the reference pipe (close_fd) and our copy of the tagged
    // listener (listener) open until process exit: the compositor holds
    // its own copies, so nothing is double-closed, but releasing either
    // here would make the socket's lifecycle diverge from ours. See the
    // ownership note on create_security_context.
    let close_fd = create_security_context(&listener, &sandbox_engine, &app_id, &instance_id)?;
    info!("Holding close_fd open to keep the tagged Wayland socket available {close_fd:?}");
    // SAFETY: called from main() before any threads are spawned
    if let Err(e) = unsafe { sd_notify::notify_and_unset_env(&[sd_notify::NotifyState::Ready]) } {
        // With Notify=true a failed READY means
        // systemd will time the service out; say so, since the failure
        // would otherwise be invisible in our own log.
        warn!("notifying the service manager (READY) failed: {e}");
    }

    run_signal_loop()?;
    info!("Shutting down.");
    Ok(())
}
