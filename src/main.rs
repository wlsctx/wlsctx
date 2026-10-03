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
    #[arg(long, env = "WLSCTX_APP_ID", required = true)]
    app_id: Option<String>,
    /// Instance ID in security context
    #[arg(long, env = "WLSCTX_INSTANCE_ID", required = true)]
    instance_id: Option<String>,
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
fn main() {
    let env = Env::default().default_filter_or("warn");
    env_logger::init_from_env(env);
    let cli = Cli::parse();

    let sandbox_engine = cli.sandbox_engine;
    let (app_id, instance_id, listener) = match (cli.socket_activation, cli.listen) {
        (true, None) => match sd_notify::listen_fds_with_names(true).map(|mut it| it.next()) {
            Ok(Some((raw_fd, name))) => {
                info!("Received socket {name} ({raw_fd:#?}) from parent");
                // SAFETY: sd_notify::listen_fds_with_names(true) unsets the LISTEN_FDS variable so we should be
                // the only user of this fd
                let listener = unsafe { UnixListener::from_raw_fd(raw_fd) };
                // The IDs are taken from --app-id/--instance-id (or their
                // environment variables). They used to be derived from the
                // fd name, but that only worked for "app@instance" instance
                // names and wlsctx@.socket sets FileDescriptorName=%i, so
                // the name normally contains no '@' and the derivation
                // panicked.
                let (app_id, instance_id) = (
                    cli.app_id.expect("clap guarantees --app-id is present"),
                    cli
                        .instance_id
                        .expect("clap guarantees --instance-id is present"),
                );
                (app_id, instance_id, listener)
            }
            _ => {
                panic!("Failed to get socket FD from activation environment")
            }
        },
        (_, Some(socket_path)) => {
            let socket_abspath = match socket_path.is_absolute() {
                true => socket_path,
                false => xdg::BaseDirectories::new()
                    .place_runtime_file(socket_path)
                    .unwrap(),
            };
            let _ = fs::metadata(&socket_abspath).map(|meta| {
                    meta.file_type().is_socket().then(|| {
                        info!("Removing old socket {socket_abspath:?}");
                        let _ = fs::remove_file(&socket_abspath)
                            .inspect_err(|e| error!("Remove existing socket failed with error {e}. bind() will likely fail."));
                    }).unwrap_or_else(||{
                        error!("Path already exists and is not a socket {socket_abspath:?}");
                    });
            });
            (
                cli.app_id.unwrap(),
                cli.instance_id.unwrap(),
                UnixListener::bind(socket_abspath).expect("Failed to bind to Unix socket"),
            )
        }
        _ => {
            panic!("No listening socket provided")
        }
    };
    if log_enabled!(Level::Info) {
        if let Ok(local_addr) = listener.local_addr() {
            info!("Listening on {local_addr:?}")
        }
    }

    let close_fd: OwnedFd = {
        // Create a Wayland connection by connecting to the server through the
        // environment-provided configuration.
        let conn = Connection::connect_to_env().expect("upstream Wayland connection failed");
        let (globals, mut event_queue) = registry_queue_init::<State>(&conn).unwrap();
        let qh = &event_queue.handle();
        let security_context_manager: wp_security_context_manager_v1::WpSecurityContextManagerV1 =
            globals.bind(qh, 1..=1, ()).unwrap();
        let (reader, writer) = io::pipe().unwrap();
        let security_context =
            security_context_manager.create_listener(listener.as_fd(), reader.as_fd(), qh, ());
        security_context_manager.destroy();
        info!("Create security context mapping for {sandbox_engine} app: {app_id} ({instance_id})");
        security_context.set_sandbox_engine(sandbox_engine);
        security_context.set_app_id(app_id.clone());
        security_context.set_instance_id(instance_id.clone());
        security_context.commit();
        security_context.destroy();
        event_queue.roundtrip(&mut State {}).unwrap();
        writer.into()
    };
    info!("Holding close_fd open to keep the tagged Wayland socket available {close_fd:?}");
    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]);

    // This signal handler is inspired by the implementation in catatonit:
    // https://github.com/openSUSE/catatonit/blob/56579adbb42c0c7ad94fc12d844b38fc5b37b3ce/catatonit.c#L538-L588
    //
    // Block all signals except the ones generated by the kernel if we have a problem in our own program.
    let mask: SigSet = SigSet::all()
        .iter()
        .filter(|sig| {
            (SIGFPE | SIGILL | SIGSEGV | SIGBUS | SIGABRT | SIGTRAP | SIGSYS)
                .contains(*sig)
                .not()
        })
        .collect();
    mask.thread_block().unwrap();

    // Handle signals synchronously via signalfd(2)
    let sigfd = SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC).unwrap();
    while let Some(siginfo) = sigfd.read_signal().unwrap() {
        debug!("Signal: {siginfo:?}");
        match Signal::try_from(siginfo.ssi_signo as i32).unwrap() {
            SIGTERM | SIGINT => {
                debug!("Stopping");
                break;
            }
            SIGHUP => {
                warn!("TODO: SIGHUP restart");
                break;
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
    info!("Shutting down.");
}
