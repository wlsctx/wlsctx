use anyhow::{Context, Result, bail};
use log::{Level, debug, error, info, log_enabled, warn};

use clap::Parser;
use env_logger::Env;
use nix::sys::{
    signal::Signal,
    signal::Signal::*,
    signalfd::{SfdFlags, SigSet, SignalFd},
    wait::{WaitPidFlag, WaitStatus, waitpid},
};
use sd_notify;
use std::fs;
use std::io;
use std::ops::Not;
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::os::unix::{fs::FileTypeExt, net::UnixListener};
use std::path;
use wayland_client::{
    Connection, QueueHandle, delegate_noop,
    globals::{GlobalListContents, registry_queue_init},
    protocol::wl_registry,
};
use wayland_protocols::wp::security_context::v1::client::{
    wp_security_context_manager_v1, wp_security_context_v1,
};
use xdg;

/// Set up a Wayland socket with an attached security context
///
/// See https://wayland.app/protocols/security-context-v1
#[derive(Parser, Debug)]
#[command(version, about, long_about)]
struct Cli {
    /// Application ID in security context
    #[arg(long, env = "WLSCTX_APP_ID")]
    app_id: String,
    /// Instance ID in security context
    #[arg(long, env = "WLSCTX_INSTANCE_ID")]
    instance_id: String,
    /// Sandbox engine ID in security context
    #[arg(long, env = "WLSCTX_SANDBOX_ENGINE")]
    sandbox_engine: String,
    /// Listen on Unix socket
    #[arg(
        long,
        env = "WLSCTX_SOCKET_PATH",
        required_unless_present = "socket_activation"
    )]
    listen: Option<path::PathBuf>,
    /// Receive socket via systemd socket activation (LISTEN_FDS)
    #[arg(long, conflicts_with = "listen")]
    socket_activation: bool,
}

struct State;

impl wayland_client::Dispatch<wl_registry::WlRegistry, GlobalListContents> for State {
    fn event(
        _state: &mut Self,
        _proxy: &wl_registry::WlRegistry,
        _event: wl_registry::Event,
        // This mutex contains an up-to-date list of the currently known globals
        // including the one that was just added or destroyed
        _data: &GlobalListContents,
        _conn: &Connection,
        _qhandle: &QueueHandle<Self>,
    ) {
        /* react to dynamic global events here */
    }
}

// The security context protocol has no events that we need to manage
delegate_noop!(State: wp_security_context_manager_v1::WpSecurityContextManagerV1);
delegate_noop!(State: wp_security_context_v1::WpSecurityContextV1);

// The main function of our program
fn main() -> Result<()> {
    let env = Env::default().default_filter_or("warn");
    env_logger::init_from_env(env);
    let cli = Cli::parse();
    let (app_id, instance_id, listener) = obtain_listener(&cli)?;
    let sandbox_engine = cli.sandbox_engine;

    if log_enabled!(Level::Info) {
        if let Ok(local_addr) = listener.local_addr() {
            info!("Listening on {local_addr:?}")
        }
    }

    let close_fd =
        create_security_context(&listener, &sandbox_engine, &app_id, &instance_id)?;
    info!("Holding close_fd open to keep the tagged Wayland socket available {close_fd:?}");
    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]);

    run_signal_loop()?;
    info!("Shutting down.");
    Ok(())
}

/// Get the Unix listener to tag, either from a systemd socket activation
/// or by binding the socket ourselves. Returns (app_id, instance_id,
/// listener).
fn obtain_listener(cli: &Cli) -> Result<(String, String, UnixListener)> {
    let app_id = cli.app_id.clone();
    let instance_id = cli.instance_id.clone();
    if cli.socket_activation {
        // The IDs come from --app-id/--instance-id (or the
        // WLSCTX_APP_ID / WLSCTX_INSTANCE_ID environment variables). They
        // used to be derived from the fd name, but that only worked for
        // "app@instance" instance names and wlsctx@.socket sets
        // FileDescriptorName=%i, so the name normally contains no '@' and
        // the derivation panicked.
        match sd_notify::listen_fds_with_names(true).map(|mut it| it.next()) {
            Ok(Some((raw_fd, name))) => {
                info!("Received socket {name} ({raw_fd:#?}) from parent");
                // SAFETY: sd_notify::listen_fds_with_names(true) unsets the LISTEN_FDS variable so we should be
                // the only user of this fd
                let listener = unsafe { UnixListener::from_raw_fd(raw_fd) };
                Ok((app_id, instance_id, listener))
            }
            _ => bail!(
                "no socket was received via systemd socket activation (LISTEN_FDS is not set \
                 or empty); run wlsctx through the wlsctx@.socket unit or use --listen instead"
            ),
        }
    } else {
        let socket_path = cli.listen.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "--listen is required when --socket-activation is not set \
                 (or set WLSCTX_SOCKET_PATH)"
            )
        })?;
        let socket_abspath = match socket_path.is_absolute() {
            true => socket_path.clone(),
            false => xdg::BaseDirectories::new()
                .place_runtime_file(socket_path)
                .with_context(|| {
                    format!(
                        "placing {socket_path:?} in the runtime directory \
                         (is XDG_RUNTIME_DIR set?)"
                    )
                })?,
        };
        // A stale socket left by a previous run is removed; any other
        // pre-existing path is an error, since binding would fail.
        match fs::metadata(&socket_abspath) {
            Ok(meta) if meta.file_type().is_socket() => {
                info!("Removing old socket {socket_abspath:?}");
                let _ = fs::remove_file(&socket_abspath).inspect_err(|e| {
                    error!("Failed to remove stale socket {socket_abspath:?}: {e}")
                });
            }
            Ok(_) => bail!(
                "{socket_abspath:?} already exists and is not a socket; \
                 move or delete it before starting wlsctx"
            ),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => bail!("stat {socket_abspath:?} failed: {e}"),
        }
        let listener = UnixListener::bind(&socket_abspath).with_context(|| {
            format!(
                "binding {socket_abspath:?} failed (a stale socket could not be removed, \
                 or the path is not writable)"
            )
        })?;
        Ok((app_id, instance_id, listener))
    }
}

/// Create a tagged Wayland listening socket for the given app/instance.
///
/// The tagged socket is the listener itself: the compositor keeps it alive
/// as long as the reference pipe (the protocol "close" fd) is open, so this
/// function hands the write end of that pipe back to the caller, which must
/// keep it open for as long as the socket should stay tagged.
fn create_security_context(
    listener: &UnixListener,
    sandbox_engine: &str,
    app_id: &str,
    instance_id: &str,
) -> Result<OwnedFd> {
    // Create a Wayland connection by connecting to the server through the
    // environment-provided configuration.
    let conn = Connection::connect_to_env().context(
        "connecting to the upstream Wayland compositor failed (NoCompositor); \
         check that WAYLAND_DISPLAY/WAYLAND_SOCKET reach the host compositor \
         (the wl-display@ sidecar passes the host wayland-1 socket via stdin, \
         wlsctx@ mounts it into the container)"
    )?;
    let (globals, mut event_queue) =
        registry_queue_init::<State>(&conn).context("initialising the Wayland protocol queue")?;
    let qh = &event_queue.handle();
    let security_context_manager: wp_security_context_manager_v1::WpSecurityContextManagerV1 =
        globals.bind(qh, 1..=1, ()).with_context(|| {
            "the compositor does not provide wp_security_context_manager_v1; this needs a \
             wlroots compositor (e.g. sway) — check with `wlsinfo -t` that the global \
             wp_security_context_manager_v1 is present"
        })?;
    let (reader, writer) =
        io::pipe().context("creating the reference pipe that keeps the tagged socket alive")?;
    let security_context =
        security_context_manager.create_listener(listener.as_fd(), reader.as_fd(), qh, ());
    security_context_manager.destroy();
    info!("Create security context mapping for {sandbox_engine} app: {app_id} ({instance_id})");
    security_context.set_sandbox_engine(sandbox_engine.to_string());
    security_context.set_app_id(app_id.to_string());
    security_context.set_instance_id(instance_id.to_string());
    security_context.commit();
    security_context.destroy();
    event_queue.roundtrip(&mut State {}).context(
        "the compositor returned a protocol error while committing the security context \
         (the tagged socket is still in an inconsistent state); check the compositor log"
    )?;
    Ok(writer.into())
}

/// Block on a signalfd(2) until the process should exit.
///
/// SIGHUP is not treated as a restart (none is implemented); the process
/// exits with status 129 (128+SIGHUP), like a process killed by the
/// signal, so the cause is distinguishable in the journal.
///
/// This signal handler is inspired by the implementation in catatonit:
/// https://github.com/openSUSE/catatonit/blob/56579adbb42c0c7ad94fc12d844b38fc5b37b3ce/catatonit.c#L538-L588
fn run_signal_loop() -> Result<()> {
    // Block all signals except the ones generated by the kernel if we have a problem in our own program.
    let mask: SigSet = SigSet::all()
        .iter()
        .filter(|sig| {
            (SIGFPE | SIGILL | SIGSEGV | SIGBUS | SIGABRT | SIGTRAP | SIGSYS)
                .contains(*sig)
                .not()
        })
        .collect();
    mask.thread_block()
        .map_err(|e| anyhow::anyhow!("blocking signals failed: {e}"))?;

    // Handle signals synchronously via signalfd(2)
    let sigfd = SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC)
        .map_err(|e| anyhow::anyhow!("creating signalfd failed: {e}"))?;
    while let Some(siginfo) = sigfd
        .read_signal()
        .map_err(|e| anyhow::anyhow!("reading from signalfd failed: {e}"))?
    {
        debug!("Signal: {siginfo:?}");
        let signal = Signal::try_from(siginfo.ssi_signo as i32)
            .map_err(|e| anyhow::anyhow!("unknown signal number {}: {e}", siginfo.ssi_signo))?;
        match signal {
            SIGTERM | SIGINT => {
                debug!("Stopping");
                break;
            }
            SIGHUP => {
                // No restart is implemented: exit with 129 (128+SIGHUP),
                // like a process killed by the signal.
                info!("SIGHUP received; exiting with status 129 (no restart is implemented)");
                std::process::exit(129);
            }
            SIGCHLD => {
                debug!("reap zombies");
                // WNOHANG yields StillAlive for children that have not
                // exited yet (and Stopped/Continued if WUNTRACED were set),
                // so the loop must stop on those, not only on error.
                while let Ok(status) = waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                    match status {
                        WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _) => {
                            debug!("reaped: {status:?}")
                        }
                        _ => break,
                    }
                }
            }
            SIGTSTP | SIGTTOU | SIGTTIN => {
                debug!("ignoring kernel attempting to stop us: tty has TOSTOP set");
            }
            sig => {
                warn!("Unexpected signal ignored ({sig:#?})");
            }
        }
    }
    Ok(())
}
