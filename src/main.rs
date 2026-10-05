use anyhow::{Context, Result, bail};
use log::{Level, debug, error, info, log_enabled, warn};

use clap::builder::TypedValueParser;
use clap::Parser;
use env_logger::Env;
use nix::sys::{
    signal::Signal,
    signal::Signal::*,
    signalfd::{SfdFlags, SigSet, SignalFd},
    wait::{WaitPidFlag, WaitStatus, waitpid},
};
use std::fs;
use std::io;
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path;
use wayland_client::{
    Connection, QueueHandle, delegate_noop,
    globals::{GlobalListContents, registry_queue_init},
    protocol::wl_registry,
};
use wayland_protocols::wp::security_context::v1::client::{
    wp_security_context_manager_v1, wp_security_context_v1,
};

/// Set up a Wayland socket with an attached security context
///
/// See https://wayland.app/protocols/security-context-v1
#[derive(Parser, Debug)]
#[command(version, about, long_about)]
struct Cli {
    /// Application ID in security context (must not be empty)
    #[arg(long, env = "WLSCTX_APP_ID", value_parser = NonEmpty::new("app-id"))]
    app_id: String,
    /// Instance ID in security context (must not be empty)
    #[arg(long, env = "WLSCTX_INSTANCE_ID", value_parser = NonEmpty::new("instance-id"))]
    instance_id: String,
    /// Sandbox engine ID in security context (must not be empty)
    #[arg(long, env = "WLSCTX_SANDBOX_ENGINE", value_parser = NonEmpty::new("sandbox-engine"))]
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

/// A value parser that rejects the empty string for the security-context
/// IDs.
///
/// Clap treats an *empty* environment variable as present-with-a-value
/// (`WLSCTX_APP_ID=` in an environment.d file is a very common typo).
/// An empty ID would tag the socket with a context that matches no
/// compositor policy — the security labeling silently stops working while
/// the process looks healthy. Rejecting it at parse time fails loudly
/// instead.
#[derive(Clone, Copy, Debug)]
struct NonEmpty {
    field: &'static str,
}

impl NonEmpty {
    fn new(field: &'static str) -> Self {
        Self { field }
    }
}

impl TypedValueParser for NonEmpty {
    type Value = String;

    fn parse_ref(
        &self,
        _cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let value = value.to_string_lossy();
        if value.is_empty() {
            let field = self.field;
            return Err(clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                format!(
                    "--{field} (or its WLSCTX_* environment variable) must not be empty: \
                     an empty ID would tag the socket with a context that matches no \
                     compositor policy, silently disabling the sandbox; set a non-empty value"
                ),
            ));
        }
        Ok(value.into_owned())
    }
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

    if log_enabled!(Level::Info)
        && let Ok(local_addr) = listener.local_addr()
    {
        info!("Listening on {local_addr:?}")
    }

    let close_fd = create_security_context(&listener, &sandbox_engine, &app_id, &instance_id)?;
    info!("Holding close_fd open to keep the tagged Wayland socket available {close_fd:?}");
    // SAFETY: called from main() before any threads are spawned
    if let Err(e) =
        unsafe { sd_notify::notify_and_unset_env(&[sd_notify::NotifyState::Ready]) }
    {
        // With Notify=true (both deployment units) a failed READY means
        // systemd will time the service out; say so, since the failure
        // would otherwise be invisible in our own log.
        warn!("notifying the service manager (READY) failed: {e}");
    }

    run_signal_loop()?;
    info!("Shutting down.");
    Ok(())
}

/// Get the Unix listener to tag, either from a systemd socket activation
/// or by binding the socket ourselves (refusing to steal a socket that a
/// live process still serves). Returns (app_id, instance_id, listener).
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
        match unsafe { sd_notify::listen_fds_with_names_and_unset_env() } {
            Ok(mut it) => match it.len() {
                0 => bail!(
                    "no socket was received via systemd socket activation (LISTEN_FDS is \
                     not set or empty); run wlsctx through the wlsctx@.socket unit or \
                     use --listen instead"
                ),
                1 => {
                    let (raw_fd, name) = it
                        .next()
                        .expect("iterator has exactly one element (len checked above)");
                    info!("Received socket {name} ({raw_fd:#?}) from parent");
                    // SAFETY: sd_notify::listen_fds_with_names_and_unset_env() unsets the LISTEN_FDS variable so we should be
                    // the only user of this fd
                    let listener = unsafe { UnixListener::from_raw_fd(raw_fd) };
                    Ok((app_id, instance_id, listener))
                }
                n => bail!(
                    "systemd passed {n} sockets via socket activation, but wlsctx tags \
                     exactly one; remove the extra ListenStream= line(s) from the socket \
                     unit and try again"
                ),
            },
            Err(_) => bail!(
                "no socket was received via systemd socket activation (LISTEN_FDS is not \
                 set or empty, or LISTEN_FDNAMES does not match LISTEN_FDS); run wlsctx \
                 through the wlsctx@.socket unit or use --listen instead"
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
        bind_socket(&socket_abspath).map(|listener| (app_id, instance_id, listener))
    }
}

/// Bind a listening socket at `path`, refusing to steal a socket that a
/// live process still serves and only replacing genuinely stale ones.
///
/// A socket file is *stale* only if no process holds its listener open
/// (connect(2) then fails with ECONNREFUSED). A successful connect means
/// the path is actively served — including a previous hung wlsctx that
/// is still alive, or a `--listen` typo pointing at a socket owned by
/// some other service (e.g. the compositor's own wayland-1): unlinking
/// that would break it, so we bail instead. The probe itself creates one
/// pending connection on a live listener, which we close immediately.
fn bind_socket(path: &path::Path) -> Result<UnixListener> {
    match fs::metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => match UnixStream::connect(path) {
            Ok(_) => bail!(
                "{path:?} is served by a live process (connect succeeded); \
                 stop that process first (a previous wlsctx still hanging? or a \
                 --listen typo pointing at a socket owned by another service, e.g. \
                 the compositor's own)"
            ),
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                info!("Removing stale socket {path:?}");
                let _ = fs::remove_file(path).inspect_err(|e| {
                    error!("Failed to remove stale socket {path:?}: {e}")
                });
            }
            Err(e) => bail!("probing {path:?} failed: {e}"),
        },
        Ok(_) => bail!(
            "{path:?} already exists and is not a socket; \
             move or delete it before starting wlsctx"
        ),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => bail!("stat {path:?} failed: {e}"),
    }
    let listener = UnixListener::bind(path).with_context(|| {
        format!(
            "binding {path:?} failed (a stale socket could not be removed, \
             or the path is not writable)"
        )
    })?;
    // bind(2) creates the socket file with umask-derived permissions
    // (typically 0755): tighten it so only the owner can connect, even
    // if the containing directory ends up more permissive than it
    // should be (the socket-activation mode is covered by the unit's
    // SocketMode=0600, this covers --listen, i.e. mode B and manual use).
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).inspect_err(|e| {
        warn!("chmod {path:?} to 0600 failed (continuing with umask permissions): {e}")
    });
    Ok(listener)
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
         wlsctx@ mounts it into the container)",
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
         (the tagged socket is still in an inconsistent state); check the compositor log",
    )?;
    Ok(writer.into())
}

/// The set of signals blocked in the signalfd(2) loop.
///
/// Everything is blocked and routed through the signalfd, *including the
/// Linux real-time range (34-64)*. The set therefore starts from
/// `SigSet::all()` (sigfillset) and only removes exceptions — building it
/// by iterating `Signal` values would silently drop the real-time bits,
/// because nix's `Signal` enum only names 1-31, leaving the real-time
/// signals at their default-terminate disposition (a same-uid process —
/// in mode B, the sandboxed app itself — could kill wlsctx with
/// `kill -34`, bypassing the clean-shutdown path).
///
/// The only signals left unblocked are those the kernel generates for
/// fatal faults in our own code (SIGFPE, SIGILL, SIGSEGV, SIGBUS,
/// SIGABRT, SIGTRAP, SIGSYS): they must stay unblocked so the process
/// still dies with the faulting signal (core dump, correct journal
/// entry) instead of parking in the loop.
///
/// SIGKILL/SIGSTOP are in the set but cannot be blocked by POSIX; they
/// act regardless of the mask (inherent limitation, not a bug).
fn signal_block_mask() -> SigSet {
    let kernel_faults = [SIGFPE, SIGILL, SIGSEGV, SIGBUS, SIGABRT, SIGTRAP, SIGSYS];
    let mut mask = SigSet::all();
    for sig in kernel_faults {
        mask.remove(sig);
    }
    mask
}

/// What the signalfd loop does for a delivered signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignalAction {
    /// Stop the loop and shut down cleanly (SIGTERM, SIGINT).
    Stop,
    /// Exit with the given status (SIGHUP → 129 = 128 + SIGHUP, like a
    /// process killed by the signal; no restart is implemented).
    Exit(i32),
    /// Reap exited children (SIGCHLD).
    Reap,
    /// Deliberately dropped: a controlling tty with TOSTOP set trying to
    /// stop us (SIGTSTP, SIGTTOU, SIGTTIN).
    Ignore,
    /// Any other blocked signal: warn and keep waiting.
    Unexpected,
}

fn classify_signal(signal: Signal) -> SignalAction {
    match signal {
        SIGTERM | SIGINT => SignalAction::Stop,
        SIGHUP => SignalAction::Exit(129),
        SIGCHLD => SignalAction::Reap,
        SIGTSTP | SIGTTOU | SIGTTIN => SignalAction::Ignore,
        _ => SignalAction::Unexpected,
    }
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
    let mask = signal_block_mask();
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
        let signal = match Signal::try_from(siginfo.ssi_signo as i32) {
            Ok(signal) => signal,
            // The real-time range (34-64 on Linux) is blocked and
            // delivered here, but nix's Signal enum cannot name it:
            // treat it like any other unhandled signal, warn, and keep
            // waiting.
            Err(_) => {
                warn!(
                    "Unexpected signal {} ignored (unnameable signal number, e.g. real-time range)",
                    siginfo.ssi_signo
                );
                continue;
            }
        };
        match classify_signal(signal) {
            SignalAction::Stop => {
                debug!("Stopping");
                break;
            }
            SignalAction::Exit(code) => {
                // No restart is implemented: exit with 129 (128+SIGHUP),
                // like a process killed by the signal.
                info!("{signal} received; exiting with status {code} (no restart is implemented)");
                std::process::exit(code);
            }
            SignalAction::Reap => {
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
            SignalAction::Ignore => {
                debug!("ignoring kernel attempting to stop us: tty has TOSTOP set");
            }
            SignalAction::Unexpected => {
                warn!("Unexpected signal ignored ({signal:#?})");
            }
        }
    }
    Ok(())
}

// Unit tests. `create_security_context` and the end-to-end `main` are
// deliberately not unit-tested: they need a live wlroots compositor
// providing `wp_security_context_manager_v1` (see README, "Compositor
// requirements & verify your setup") — that part is covered by running
// the real unit (mode A) or a pod (mode B).
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    // clap reads the process environment for its `env` attributes, and
    // tests run in parallel, so environment-mutating tests must be
    // serialised against each other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // systemd passes socket-activated fds starting at 3 (SD_LISTEN_FDS_START);
    // only one test at a time may install a fd there.
    static LISTEN_FD_LOCK: Mutex<()> = Mutex::new(());

    /// A uniquely named directory under the system temp dir, removed on
    /// drop. The counter makes every instance unique *within* a test
    /// binary, so parallel tests never share (or drop) the same
    /// directory even when they pass the same label.
    struct TmpDir {
        path: path::PathBuf,
    }

    static TMP_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    impl TmpDir {
        fn new(name: &str) -> Self {
            let n = TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("wlsctx-test-{}-{name}-{n}", std::process::id()));
            fs::create_dir_all(&path).unwrap_or_else(|e| panic!("creating {path:?}: {e}"));
            Self { path }
        }

        fn path(&self) -> &path::Path {
            &self.path
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    /// A TmpDir made usable as XDG_RUNTIME_DIR (which xdg requires to
    /// have exactly 0700 permissions).
    fn xdg_runtime_dir(mode: u32) -> TmpDir {
        let dir = TmpDir::new("runtime");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(mode))
            .unwrap_or_else(|e| panic!("chmod {}: {e}", dir.path().display()));
        dir
    }

    fn test_cli_listen(listen: &str) -> Cli {
        Cli {
            app_id: "rustrover".into(),
            instance_id: "work".into(),
            sandbox_engine: "podman".into(),
            listen: Some(path::PathBuf::from(listen)),
            socket_activation: false,
        }
    }

    fn test_cli_socket_activation() -> Cli {
        Cli {
            app_id: "rustrover".into(),
            instance_id: "work".into(),
            sandbox_engine: "podman".into(),
            listen: None,
            socket_activation: true,
        }
    }

    /// The bound path of a Unix listener, if it is path-based.
    fn socket_path(listener: &UnixListener) -> Option<path::PathBuf> {
        listener
            .local_addr()
            .ok()
            .and_then(|addr| addr.as_pathname().map(path::PathBuf::from))
    }

    /// Close a listener's fd behind the wrapper's back, leaving the
    /// socket file in place — i.e. simulate a stale socket left by a
    /// previous wlsctx that died without unlinking it.
    fn leave_stale_socket(listener: UnixListener) {
        let raw = listener.as_raw_fd();
        // SAFETY: the wrapper takes over the close of `raw`, which is
        // still owned by `listener`; `listener` (owned) is forgotten
        // directly below so the same fd is never closed twice.
        drop(unsafe { OwnedFd::from_raw_fd(raw) });
        std::mem::forget(listener);
    }

    // dup2(2), bound locally so the test code does not need nix's
    // feature-gated wrappers (the production dependency stays lean).
    unsafe extern "C" {
        fn dup2(oldfd: i32, newfd: i32) -> i32;
    }

    /// Duplicate a listener onto `target` (systemd passes socket-activated
    /// fds starting at fd 3, SD_LISTEN_FDS_START), and leave `target` open
    /// so `obtain_listener` can take ownership of it. Refuses (with a
    /// message) if the fd is already in use in the test process. The
    /// listener is consumed: on success only `target` remains open, on
    /// error the listener is dropped normally.
    fn install_on_fd(target: i32, listener: UnixListener) -> std::io::Result<()> {
        // /proc/self/fd/N exists only while fd N is open: a side-effect
        // free probe (Linux only — this binary's platform).
        match fs::symlink_metadata(format!("/proc/self/fd/{target}")) {
            Ok(_) => {
                return Err(std::io::Error::other(
                    format!("fd {target} is in use in the test process"),
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(std::io::Error::other(format!("probing fd {target}: {e}"))),
        }
        let raw = listener.as_raw_fd();
        // SAFETY: the probe established fd `target` is closed, so dup2(2)
        // closes nothing; it returns `target` (or -1), which the OwnedFd
        // below takes ownership of and is forgotten right away so it
        // never closes `target` again.
        let dup = unsafe { dup2(raw, target) };
        if dup < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let target_fd = unsafe { OwnedFd::from_raw_fd(dup) };
        // Close the listener's original fd, then forget both wrappers:
        // fd `target` is the only remaining reference to the socket.
        // SAFETY: as in leave_stale_socket — the wrapper takes over the
        // close, `listener` (owned) is forgotten so there is no
        // double close.
        drop(unsafe { OwnedFd::from_raw_fd(raw) });
        std::mem::forget(listener);
        std::mem::forget(target_fd);
        Ok(())
    }

    /// Set (Some) or unset (None) the given environment variables for the
    /// duration of `f`, restoring whatever was there before.
    fn with_env(vars: &[(&str, Option<&str>)], f: impl FnOnce()) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved: Vec<(&str, Option<String>)> = vars
            .iter()
            .map(|(name, _)| (*name, std::env::var(name).ok()))
            .collect();
        // SAFETY: ENV_LOCK guarantees no other test or code path reads or
        // writes these variables while they are held.
        unsafe {
            for (name, value) in vars {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
        f();
        // SAFETY: as above.
        unsafe {
            for (name, value) in saved {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }

    fn without_wlsctx_env(f: impl FnOnce()) {
        with_env(
            &[
                ("WLSCTX_APP_ID", None),
                ("WLSCTX_INSTANCE_ID", None),
                ("WLSCTX_SANDBOX_ENGINE", None),
                ("WLSCTX_SOCKET_PATH", None),
            ],
            f,
        );
    }

    #[test]
    fn parses_explicit_arguments() {
        without_wlsctx_env(|| {
            let cli = Cli::try_parse_from([
                "wlsctx",
                "--listen",
                "/run/pod/wayland-1",
                "--app-id",
                "rustrover",
                "--instance-id",
                "work",
                "--sandbox-engine",
                "podman",
            ])
            .expect("explicit arguments must parse");
            assert_eq!(
                cli.listen.as_deref(),
                Some(std::path::Path::new("/run/pod/wayland-1"))
            );
            assert_eq!(cli.app_id, "rustrover");
            assert_eq!(cli.instance_id, "work");
            assert_eq!(cli.sandbox_engine, "podman");
            assert!(!cli.socket_activation);
        });
    }

    #[test]
    fn requires_listen_without_socket_activation() {
        without_wlsctx_env(|| {
            let err = Cli::try_parse_from([
                "wlsctx",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "podman",
            ])
            .expect_err("--listen is required unless --socket-activation is set");
            assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        });
    }

    #[test]
    fn requires_app_id_and_instance_id() {
        without_wlsctx_env(|| {
            let err = Cli::try_parse_from([
                "wlsctx",
                "--listen",
                "/run/pod/wayland-1",
                "--sandbox-engine",
                "podman",
            ])
            .expect_err("app_id/instance_id are always required (no fd-name fallback)");
            assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
            assert!(err.to_string().contains("--app-id"));
            assert!(err.to_string().contains("--instance-id"));
        });
    }

    #[test]
    fn socket_activation_conflicts_with_listen() {
        without_wlsctx_env(|| {
            let err = Cli::try_parse_from([
                "wlsctx",
                "--socket-activation",
                "--listen",
                "/run/pod/wayland-1",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "podman",
            ])
            .expect_err("--socket-activation and --listen must conflict");
            assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
        });
    }

    #[test]
    fn socket_activation_parsing_needs_no_listen() {
        without_wlsctx_env(|| {
            let cli = Cli::try_parse_from([
                "wlsctx",
                "--socket-activation",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "podman",
            ])
            .expect("socket activation mode needs no --listen");
            assert!(cli.socket_activation);
            assert!(cli.listen.is_none());
        });
    }

    #[test]
    fn socket_activation_still_requires_explicit_ids() {
        without_wlsctx_env(|| {
            // The IDs must come from --app-id/--instance-id or their
            // environment variables; nothing is derived from LISTEN_FDNAMES.
            let err = Cli::try_parse_from([
                "wlsctx",
                "--socket-activation",
                "--sandbox-engine",
                "podman",
            ])
            .expect_err("socket-activation mode still requires explicit IDs");
            assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        });
    }

    #[test]
    fn environment_variables_fill_required_arguments() {
        with_env(
            &[
                ("WLSCTX_APP_ID", Some("envapp")),
                ("WLSCTX_INSTANCE_ID", Some("envinst")),
                ("WLSCTX_SANDBOX_ENGINE", Some("envengine")),
                ("WLSCTX_SOCKET_PATH", Some("/run/pod/wayland-1")),
            ],
            || {
                let cli = Cli::try_parse_from(["wlsctx"]).expect("env vars satisfy all args");
                assert_eq!(cli.app_id, "envapp");
                assert_eq!(cli.instance_id, "envinst");
                assert_eq!(cli.sandbox_engine, "envengine");
                assert_eq!(
                    cli.listen.as_deref(),
                    Some(std::path::Path::new("/run/pod/wayland-1"))
                );
            },
        );
    }

    #[test]
    fn explicit_arguments_take_precedence_over_env() {
        // Deployment mode B relies on exactly this: the quadlet passes
        // --listen on the command line while the IDs come from the
        // WLSCTX_* environment, and the two sources may disagree.
        with_env(
            &[
                ("WLSCTX_APP_ID", Some("envapp")),
                ("WLSCTX_INSTANCE_ID", Some("envinst")),
                ("WLSCTX_SANDBOX_ENGINE", Some("envengine")),
                ("WLSCTX_SOCKET_PATH", Some("/env/socket")),
            ],
            || {
                let cli = Cli::try_parse_from([
                    "wlsctx",
                    "--listen",
                    "/run/pod/wayland-1",
                    "--app-id",
                    "flagapp",
                ])
                .expect("flag + env mix must parse");
                // CLI wins for the flag that was given explicitly…
                assert_eq!(
                    cli.listen.as_deref(),
                    Some(std::path::Path::new("/run/pod/wayland-1"))
                );
                assert_eq!(cli.app_id, "flagapp");
                // …and env still fills the arguments that were not given.
                assert_eq!(cli.instance_id, "envinst");
                assert_eq!(cli.sandbox_engine, "envengine");
                assert!(!cli.socket_activation);
            },
        );
    }

    #[test]
    fn requires_sandbox_engine() {
        without_wlsctx_env(|| {
            let err = Cli::try_parse_from([
                "wlsctx",
                "--listen",
                "/run/pod/wayland-1",
                "--app-id",
                "a",
                "--instance-id",
                "i",
            ])
            .expect_err("sandbox_engine is always required (no default)");
            assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
            assert!(err.to_string().contains("--sandbox-engine"));
        });
    }

    #[test]
    fn listen_given_twice_is_rejected() {
        // clap models a repeated single-value flag as the argument
        // conflicting with itself (ArgAction::Set does not override
        // itself unless `args_override_self` is set): the second --listen
        // is an error, it never silently wins.
        without_wlsctx_env(|| {
            let err = Cli::try_parse_from([
                "wlsctx",
                "--listen",
                "/run/pod/wayland-1",
                "--listen",
                "/other/socket",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "podman",
            ])
            .expect_err("--listen must not be repeatable");
            assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
        });
    }

    #[test]
    fn socket_activation_conflicts_with_socket_path_env() {
        // WLSCTX_SOCKET_PATH in the environment counts as --listen being
        // present for clap's conflict check, so a stray env var (e.g. left
        // over from a mode B shell) makes mode A refuse to start instead
        // of silently ignoring the path.
        with_env(
            &[("WLSCTX_SOCKET_PATH", Some("/run/pod/wayland-1"))],
            || {
                let err = Cli::try_parse_from([
                    "wlsctx",
                    "--socket-activation",
                    "--app-id",
                    "a",
                    "--instance-id",
                    "i",
                    "--sandbox-engine",
                    "podman",
                ])
                .expect_err("--socket-activation must conflict with an env-provided --listen");
                assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
            },
        );
    }

    #[test]
    fn empty_env_values_are_rejected() {
        // An *empty* WLSCTX_* variable is a value for clap, not "unset"
        // (a common environment.d typo). It used to be accepted, which
        // tagged the socket with an empty ID matching no compositor
        // policy and silently disabled the sandbox: each ID is now
        // rejected at parse time.
        let valid: [(&str, &str); 3] = [
            ("WLSCTX_APP_ID", "a"),
            ("WLSCTX_INSTANCE_ID", "i"),
            ("WLSCTX_SANDBOX_ENGINE", "podman"),
        ];
        for (target, field) in [
            ("WLSCTX_APP_ID", "--app-id"),
            ("WLSCTX_INSTANCE_ID", "--instance-id"),
            ("WLSCTX_SANDBOX_ENGINE", "--sandbox-engine"),
        ] {
            let pairs: Vec<(&str, Option<&str>)> = valid
                .iter()
                .map(|(name, value)| (*name, Some(if *name == target { "" } else { *value })))
                .chain(std::iter::once((
                    "WLSCTX_SOCKET_PATH",
                    Some("/run/pod/wayland-1"),
                )))
                .collect();
            with_env(&pairs, || {
                let err = Cli::try_parse_from(["wlsctx"])
                    .expect_err("an empty WLSCTX_* value must be rejected at parse time");
                assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue, "{target}");
                let msg = err.to_string();
                assert!(msg.contains(field), "{target}: {msg}");
                assert!(msg.contains("not be empty"), "{target}: {msg}");
            });
        }
    }

    #[test]
    fn empty_flag_values_are_rejected() {
        // The same guard applies to explicit flags (`--app-id ""`).
        without_wlsctx_env(|| {
            let fields: [(&str, &str); 3] = [
                ("--app-id", "a"),
                ("--instance-id", "i"),
                ("--sandbox-engine", "podman"),
            ];
            for (flag, _valid) in fields {
                let mut argv: Vec<&str> = vec!["wlsctx", "--listen", "/run/pod/wayland-1"];
                for (f, v) in fields {
                    argv.push(f);
                    argv.push(if f == flag { "" } else { v });
                }
                let err = Cli::try_parse_from(&argv).expect_err("an empty flag value must be rejected");
                assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue, "{flag}");
                let msg = err.to_string();
                assert!(msg.contains(flag), "{msg}");
                assert!(msg.contains("not be empty"), "{msg}");
            }
        });
    }

    #[test]
    fn signal_block_mask_keeps_fatal_kernel_faults_unblocked() {
        let mask = signal_block_mask();
        for sig in [SIGFPE, SIGILL, SIGSEGV, SIGBUS, SIGABRT, SIGTRAP, SIGSYS] {
            assert!(!mask.contains(sig), "{sig:?} must stay unblocked");
        }
    }

    #[test]
    fn signal_block_mask_blocks_every_signal_the_loop_handles() {
        let mask = signal_block_mask();
        for sig in [
            SIGTERM, SIGINT, SIGHUP, SIGCHLD, SIGTSTP, SIGTTOU, SIGTTIN, SIGUSR1, SIGPIPE,
        ] {
            assert!(
                mask.contains(sig),
                "{sig:?} must be blocked and routed to the signalfd"
            );
        }
    }

    // The real-time range can only be checked on the raw bits: nix's
    // Signal enum stops at 31, so a mask built by iterating Signal values
    // would silently drop these bits, leaving the default-terminate
    // disposition in place.
    #[cfg(target_os = "linux")]
    fn raw_mask(mask: SigSet) -> libc::sigset_t {
        // SAFETY: SigSet is #[repr(transparent)] over libc::sigset_t, so
        // the transmute is a bit-for-bit read of the same words.
        unsafe { std::mem::transmute::<SigSet, libc::sigset_t>(mask) }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn signal_block_mask_blocks_the_realtime_range() {
        let raw = raw_mask(signal_block_mask());
        for signo in 34..=64 {
            assert_ne!(
                unsafe { libc::sigismember(&raw, signo) },
                0,
                "signal {signo} (real-time range) must be blocked"
            );
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn signal_block_mask_raw_bits_cover_the_standard_range_exactly() {
        // The full sigfillset minus exactly the seven fatal faults:
        // every other standard signal (1-31) must be blocked.
        let raw = raw_mask(signal_block_mask());
        let fatal = [SIGFPE, SIGILL, SIGSEGV, SIGBUS, SIGABRT, SIGTRAP, SIGSYS]
            .iter()
            .map(|s| *s as i32)
            .collect::<Vec<_>>();
        for signo in 1..=31 {
            let blocked = unsafe { libc::sigismember(&raw, signo) } != 0;
            if fatal.contains(&signo) {
                assert!(!blocked, "signal {signo} must stay unblocked");
            } else {
                assert!(blocked, "signal {signo} must be blocked");
            }
        }
    }

    #[test]
    fn classifies_stop_and_reap_signals() {
        assert_eq!(classify_signal(SIGTERM), SignalAction::Stop);
        assert_eq!(classify_signal(SIGINT), SignalAction::Stop);
        assert_eq!(classify_signal(SIGCHLD), SignalAction::Reap);
    }

    #[test]
    fn classifies_sighup_as_exit_129_not_restart() {
        assert_eq!(classify_signal(SIGHUP), SignalAction::Exit(129));
        // 129 = 128 + SIGHUP, so the exit status matches a process killed
        // by the signal and stays distinguishable in the journal.
        assert_eq!(128 + Signal::SIGHUP as i32, 129);
    }

    #[test]
    fn classifies_tty_stop_signals_as_ignored() {
        for sig in [SIGTSTP, SIGTTOU, SIGTTIN] {
            assert_eq!(classify_signal(sig), SignalAction::Ignore, "{sig:?}");
        }
    }

    #[test]
    fn classifies_remaining_blocked_signals_as_unexpected() {
        // Everything the loop blocks that is none of the above falls into
        // the warn-and-continue branch (SIGPIPE included: writes to a
        // closed peer surface as EPIPE instead of killing us).
        for sig in [SIGUSR1, SIGUSR2, SIGPIPE, SIGCONT, SIGWINCH, SIGALRM] {
            assert_eq!(classify_signal(sig), SignalAction::Unexpected, "{sig:?}");
        }
    }

    #[test]
    fn listen_absolute_binds_at_exact_path() {
        // An absolute path is used as-is; no XDG involvement, so this
        // holds even with XDG_RUNTIME_DIR unset.
        let dir = TmpDir::new("listen-abs");
        let sock = dir.path().join("wayland-1");
        with_env(&[("XDG_RUNTIME_DIR", None)], || {
            let (_, _, listener) = obtain_listener(&test_cli_listen(sock.to_str().unwrap()))
                .expect("absolute path must bind");
            assert!(sock.exists());
            assert_eq!(socket_path(&listener), Some(sock));
        });
    }

    #[test]
    fn listen_socket_is_created_owner_only() {
        // bind(2) leaves the socket file with umask-derived permissions
        // (typically 0755): wlsctx must tighten it to 0600 so that only
        // the owner can connect, even if the surrounding directory (or
        // the umask) ends up permissive.
        let dir = TmpDir::new("listen-perm");
        let sock = dir.path().join("wayland-1");
        with_env(&[("XDG_RUNTIME_DIR", None)], || {
            let _ = obtain_listener(&test_cli_listen(sock.to_str().unwrap()))
                .expect("absolute path must bind");
            let mode = fs::metadata(&sock)
                .expect("socket exists")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "the bound socket must be owner-only");
        });
    }

    #[test]
    fn listen_replaces_stale_socket() {
        // A socket file left by a previous run is removed and re-bound;
        // any other pre-existing path is an error.
        let dir = TmpDir::new("listen-stale");
        let sock = dir.path().join("wayland-1");
        let stale = UnixListener::bind(&sock).expect("creating the stale socket");
        leave_stale_socket(stale);
        assert!(sock.exists());

        let (_, _, listener) = obtain_listener(&test_cli_listen(sock.to_str().unwrap()))
            .expect("stale socket replaced");
        // Binding over an existing path fails with EADDRINUSE, so a
        // successful bind proves the old file was removed first.
        assert_eq!(socket_path(&listener), Some(sock));
    }

    #[test]
    fn listen_rejects_socket_with_live_listener() {
        // A socket whose listener fd is still open — a previous wlsctx
        // that is hung but not yet dead, or a --listen typo over a
        // foreign service's socket (e.g. the compositor's own) — must
        // not be unlinked: connect(2) succeeds, so the error must name
        // it, and the file must be left in place.
        let dir = TmpDir::new("listen-live");
        let sock = dir.path().join("wayland-1");
        let _live = UnixListener::bind(&sock).expect("creating the live socket");
        let err = obtain_listener(&test_cli_listen(sock.to_str().unwrap()))
            .expect_err("a live listener must be left alone");
        let msg = format!("{err:#}");
        assert!(msg.contains("live process"), "{msg}");
        assert!(sock.exists(), "the live socket file must be left in place");
    }

    #[test]
    fn listen_rejects_existing_regular_file() {
        let dir = TmpDir::new("listen-file");
        let sock = dir.path().join("wayland-1");
        fs::write(&sock, "not a socket").unwrap();
        let err = obtain_listener(&test_cli_listen(sock.to_str().unwrap()))
            .expect_err("a non-socket file must be rejected");
        assert!(
            format!("{err:#}").contains("not a socket"),
            "clear error expected, got: {err:#}"
        );
        assert!(sock.exists(), "the file must be left alone");
    }

    #[test]
    fn listen_rejects_existing_directory() {
        let dir = TmpDir::new("listen-dir");
        let sock = dir.path().join("wayland-1");
        fs::create_dir(&sock).unwrap();
        let err = obtain_listener(&test_cli_listen(sock.to_str().unwrap()))
            .expect_err("a directory must be rejected");
        assert!(
            format!("{err:#}").contains("not a socket"),
            "clear error expected, got: {err:#}"
        );
    }

    #[test]
    fn listen_empty_string_fails_cleanly() {
        // "" is a relative path that resolves to the runtime directory
        // itself, which exists and is a directory: a clear error, not a
        // panic or a bind on an unexpected path.
        let runtime = xdg_runtime_dir(0o700);
        with_env(
            &[("XDG_RUNTIME_DIR", Some(runtime.path().to_str().unwrap()))],
            || {
                let err = obtain_listener(&test_cli_listen("")).expect_err("empty path must fail");
                assert!(
                    format!("{err:#}").contains("not a socket"),
                    "clear error expected, got: {err:#}"
                );
            },
        );
    }

    #[test]
    fn listen_relative_path_placed_in_xdg_runtime_dir() {
        // Relative paths go into $XDG_RUNTIME_DIR; nested names (mode A
        // uses wlsctx/<instance>/wayland-1) create their subdirectories.
        let runtime = xdg_runtime_dir(0o700);
        with_env(
            &[("XDG_RUNTIME_DIR", Some(runtime.path().to_str().unwrap()))],
            || {
                let expected = runtime.path().join("wlsctx/work/wayland-1");
                let (_, _, listener) = obtain_listener(&test_cli_listen("wlsctx/work/wayland-1"))
                    .expect("relative path must land in the runtime dir");
                assert_eq!(socket_path(&listener), Some(expected));
                assert!(runtime.path().join("wlsctx/work").is_dir());
            },
        );
    }

    #[test]
    fn listen_relative_path_without_xdg_runtime_dir_fails() {
        with_env(&[("XDG_RUNTIME_DIR", None)], || {
            let err = obtain_listener(&test_cli_listen("wayland-1"))
                .expect_err("no runtime dir, no relative placement");
            assert!(
                format!("{err:#}").contains("XDG_RUNTIME_DIR"),
                "actionable error expected, got: {err:#}"
            );
        });
    }

    #[test]
    fn listen_relative_path_with_relative_xdg_runtime_dir_fails() {
        // The XDG spec treats a relative XDG_RUNTIME_DIR as unset; the
        // xdg crate does, and so does the error.
        with_env(&[("XDG_RUNTIME_DIR", Some("relative-run-dir"))], || {
            let err = obtain_listener(&test_cli_listen("wayland-1"))
                .expect_err("a relative runtime dir is not a runtime dir");
            assert!(
                format!("{err:#}").contains("XDG_RUNTIME_DIR"),
                "actionable error expected, got: {err:#}"
            );
        });
    }

    #[test]
    fn listen_relative_path_with_insecure_xdg_runtime_dir_fails() {
        // xdg requires 0700 exactly; a world-accessible runtime dir is
        // rejected and the cause is visible in the error chain.
        let runtime = xdg_runtime_dir(0o755);
        with_env(
            &[("XDG_RUNTIME_DIR", Some(runtime.path().to_str().unwrap()))],
            || {
                let err = obtain_listener(&test_cli_listen("wayland-1"))
                    .expect_err("0755 is not a secure runtime dir");
                assert!(
                    format!("{err:#}").contains("0o700"),
                    "permission cause expected, got: {err:#}"
                );
            },
        );
    }

    #[test]
    fn listen_oversized_path_fails_to_bind() {
        // AF_UNIX sun_path is 108 bytes; longer names fail at bind(2),
        // and the error must say binding failed rather than crash.
        let runtime = xdg_runtime_dir(0o700);
        let long_name = format!("{}wayland-1", "a".repeat(112));
        assert!(long_name.len() > 108);
        with_env(
            &[("XDG_RUNTIME_DIR", Some(runtime.path().to_str().unwrap()))],
            || {
                let err = obtain_listener(&test_cli_listen(&long_name))
                    .expect_err("overlong path must fail at bind");
                assert!(
                    format!("{err:#}").contains("binding"),
                    "bind context expected, got: {err:#}"
                );
            },
        );
    }

    #[test]
    fn socket_activation_without_listen_fds_fails() {
        // No LISTEN_PID/LISTEN_FDS at all (running wlsctx by hand, not
        // through the socket unit): a clear error pointing at the two
        // ways to fix it.
        with_env(
            &[
                ("LISTEN_FDS", None),
                ("LISTEN_PID", None),
                ("LISTEN_FDNAMES", None),
            ],
            || {
                let err = obtain_listener(&test_cli_socket_activation())
                    .expect_err("nothing was passed, nothing to tag");
                assert!(
                    format!("{err:#}")
                        .contains("no socket was received via systemd socket activation"),
                    "actionable error expected, got: {err:#}"
                );
            },
        );
    }

    #[test]
    fn socket_activation_with_stale_listen_pid_fails() {
        // sd-notify silently yields an empty fd list when LISTEN_PID
        // does not match the current process (a stale value inherited
        // from a parent shell or service); the failure must look like
        // the no-fds case, not like a random crash on a foreign fd.
        with_env(
            &[
                ("LISTEN_FDS", Some("1")),
                ("LISTEN_PID", Some("99999999")),
                ("LISTEN_FDNAMES", None),
            ],
            || {
                let err = obtain_listener(&test_cli_socket_activation())
                    .expect_err("a pid mismatch must not adopt a foreign fd");
                assert!(
                    format!("{err:#}")
                        .contains("no socket was received via systemd socket activation"),
                    "actionable error expected, got: {err:#}"
                );
            },
        );
    }

    #[test]
    fn socket_activation_rejects_fdname_count_mismatch() {
        let _fd_lock = LISTEN_FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = TmpDir::new("socket-activation-mismatch");
        let sock = dir.path().join("wayland-1");
        let listener = match UnixListener::bind(&sock) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("skipping (cannot bind {sock:?}): {e}");
                return;
            }
        };
        match install_on_fd(3, listener) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("skipping: {e}");
                return;
            }
        }
        let pid = std::process::id().to_string();
        with_env(
            &[
                ("LISTEN_FDS", Some("1")),
                ("LISTEN_PID", Some(&pid)),
                ("LISTEN_FDNAMES", Some("a:b")), // 2 names, 1 fd
            ],
            || {
                let err = obtain_listener(&test_cli_socket_activation())
                    .expect_err("fdname count mismatch must fail before any fd is adopted");
                assert!(
                    format!("{err:#}")
                        .contains("no socket was received via systemd socket activation"),
                    "actionable error expected, got: {err:#}"
                );
            },
        );
        // obtain_listener bailed before taking ownership: close fd 3
        // ourselves (its wrapper was forgotten in install_on_fd).
        // SAFETY: fd 3 is open here (install_on_fd succeeded) and no
        // other code in the test process references it.
        drop(unsafe { OwnedFd::from_raw_fd(3) });
    }

    #[test]
    fn socket_activation_rejects_multiple_fds() {
        // wlsctx tags exactly one socket: a unit handing over more
        // (extra ListenStream= lines) must fail loudly instead of
        // silently adopting the first and leaking the rest.
        let _fd_lock = LISTEN_FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = TmpDir::new("socket-activation-multi");
        let sock_a = dir.path().join("wayland-a");
        let sock_b = dir.path().join("wayland-b");
        let listener_a = match UnixListener::bind(&sock_a) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("skipping (cannot bind {sock_a:?}): {e}");
                return;
            }
        };
        let listener_b = match UnixListener::bind(&sock_b) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("skipping (cannot bind {sock_b:?}): {e}");
                return;
            }
        };
        // Both fds must be in place before either listener is consumed.
        if install_on_fd(3, listener_a).is_err() {
            eprintln!("skipping: fd 3 unavailable in the test process");
            return;
        }
        match install_on_fd(4, listener_b) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("skipping: fd 4 unavailable in the test process: {e}");
                // fd 3 was installed but fd 4 could not be: release fd 3
                // so it does not leak into later tests.
                // SAFETY: install_on_fd(3, …) succeeded, so fd 3 is open
                // and no other code in the test process references it.
                drop(unsafe { OwnedFd::from_raw_fd(3) });
                return;
            }
        }
        let pid = std::process::id().to_string();
        with_env(
            &[
                ("LISTEN_FDS", Some("2")),
                ("LISTEN_PID", Some(&pid)),
                ("LISTEN_FDNAMES", Some("a:b")),
            ],
            || {
                let err = obtain_listener(&test_cli_socket_activation())
                    .expect_err("more than one fd must be rejected");
                let msg = format!("{err:#}");
                assert!(msg.contains("tags exactly one"), "{msg}");
            },
        );
        // obtain_listener bailed before adopting: close both fds
        // ourselves (their wrappers were forgotten in install_on_fd).
        // SAFETY: fd 3 and fd 4 are open here (install_on_fd succeeded)
        // and no other code in the test process references them.
        drop(unsafe { OwnedFd::from_raw_fd(3) });
        drop(unsafe { OwnedFd::from_raw_fd(4) });
    }

    #[test]
    fn socket_activation_adopts_fd_from_systemd() {
        let _fd_lock = LISTEN_FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = TmpDir::new("socket-activation");
        let sock = dir.path().join("wayland-1");
        let listener = match UnixListener::bind(&sock) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("skipping (cannot bind {sock:?}): {e}");
                return;
            }
        };
        match install_on_fd(3, listener) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("skipping: {e}");
                return;
            }
        }
        let pid = std::process::id().to_string();
        with_env(
            &[
                ("LISTEN_FDS", Some("1")),
                ("LISTEN_PID", Some(&pid)),
                ("LISTEN_FDNAMES", Some("rustrover-work")), // FileDescriptorName=%i
            ],
            || {
                let (app_id, instance_id, listener) =
                    obtain_listener(&test_cli_socket_activation())
                        .expect("the passed fd must be adopted");
                assert_eq!(app_id, "rustrover");
                assert_eq!(instance_id, "work");
                assert_eq!(socket_path(&listener), Some(sock));
                // the unset_env variant scrubs the variables so no
                // child process can mistake them for its own activation
                for var in ["LISTEN_FDS", "LISTEN_PID", "LISTEN_FDNAMES"] {
                    assert!(
                        std::env::var(var).is_err(),
                        "{var} must be unset after adoption"
                    );
                }
            },
        );
        // The adopted listener returned by obtain_listener is dropped at
        // the end of the closure, closing fd 3; `dir` is then dropped
        // and removes the socket file.
    }
}
