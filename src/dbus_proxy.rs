//! The D-Bus session-bus sidecar (Phase 7.2).
//!
//! `wlsctx dbus-proxy` runs a host-side [`xdg-dbus-proxy`] (the
//! standalone tool the flatpak project broke out) that bridges a
//! *public* unix socket — placed in the per-instance runtime dir, so
//! the sandboxed app points at it with
//! `DBUS_SESSION_BUS_ADDRESS=unix:path=…/bus.sock` — to the session
//! bus (`ADDRESS`). The sidecar owns the child: it blocks the proxy
//! signal mask, spawns the proxy, and parks on a `poll(2)` loop that
//! watches a signalfd and the child's pidfd. SIGTERM/SIGINT/SIGHUP
//! terminate the child and exit — there is no in-place rebuild of a
//! D-Bus proxy (the sidecar is a documented manual run, like
//! `wayland --proxy`, not a systemd unit) — and a child that dies on
//! its own is reaped and the sidecar exits with its status.
//!
//! Lifetime is by fd: the sidecar hands the proxy one end of a
//! private socketpair as `--fd=3` (non-CLOEXEC — the inverse of the
//! reflex, since `execve(2)` *closes* CLOEXEC descriptors) and keeps
//! the other end open for the sidecar's life; the proxy exits when
//! that fd sees the peer close (G_IO_HUP), so even a sidecar killed
//! with SIGKILL tears the proxy down. A socketpair, not a pipe:
//! `xdg-dbus-proxy` 0.1.9's `g_io_add_watch(G_IO_ERR|G_IO_HUP)` does
//! not fire on *pipe* EOF with the installed GLib, but does on a
//! socket peer close — which is also what flatpak passes. (GLib 2.90
//! masks exactly those bits out of the `ppoll(2)` events — an old
//! IRIX workaround — so the watch polls with *zero* requested
//! events and fires anyway only because the kernel reports `POLLHUP`
//! in `revents` unrequested; verified with an `LD_PRELOAD` ppoll
//! tracer.) The proxy
//! writes a single `x` byte to the fd on startup; the sidecar reads
//! it as a readiness gate. The fd is deliberately non-CLOEXEC in the
//! child: `xdg-dbus-proxy` does not fork, so it cannot leak into
//! grandchildren.
//!
//! The sidecar sets `umask(0077)` before creating anything: the
//! instance dir (if new) and the socket the proxy creates are
//! owner-only from birth, and the socket is `chmod 0600`ed once it
//! exists, matching the wayland listener's tightening.
//!
//! Policy: the proxy is pass-through unless the sidecar is given
//! `--see` / `--talk` / `--own` / `--call` / `--broadcast` rules,
//! which it forwards verbatim to the proxy; once a rule is present
//! the proxy fails closed on anything not explicitly allowed.
//!
//! [`xdg-dbus-proxy`]: https://github.com/flatpak/xdg-dbus-proxy

use std::io::{self, Write as _};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt as _;
use std::process;

use anyhow::{Context, Result};
use log::{debug, info};
use nix::sys::signal::{
    SIGABRT, SIGBUS, SIGFPE, SIGILL, SIGSEGV, SIGSYS, SIGTRAP, SigSet, SigmaskHow, Signal,
};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use rustix::event::{PollFd, PollFlags, poll};

/// One forwarding rule passed to `xdg-dbus-proxy` verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// `see`, `talk`, `own`, `call`, or `broadcast`.
    pub kind: &'static str,
    /// The rule body after `=` (a bus name, or `name=rule` for
    /// call/broadcast).
    pub body: String,
}

/// How the sidecar runs.
#[derive(Debug, Clone)]
pub struct Config {
    /// Application id (part of the instance name).
    pub app_id: String,
    /// Instance id (part of the instance name).
    pub instance_id: String,
    /// The session bus address (`ADDRESS`); defaults to the
    /// `DBUS_SESSION_BUS_ADDRESS` environment variable when empty.
    pub bus_address: String,
    /// The public socket's file name inside the instance runtime dir
    /// (default `bus.sock`).
    pub socket_name: String,
    /// Forwarding rules (empty = pass-through).
    pub rules: Vec<Rule>,
    /// The proxy binary (default `xdg-dbus-proxy`, resolved on `PATH`).
    pub proxy_bin: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            app_id: "app".into(),
            instance_id: "1".into(),
            bus_address: String::new(),
            socket_name: "bus.sock".into(),
            rules: Vec::new(),
            proxy_bin: "xdg-dbus-proxy".into(),
        }
    }
}

/// The instance name: `<app>-<instance>`.
///
/// Must stay in sync with `sandbox::namespaces::cgroup_name_for`
/// (binary-only, unreachable from the library) — the instance runtime
/// dir, cgroup and hostname all use this same form.
fn instance_name(app_id: &str, instance_id: &str) -> String {
    format!("{app_id}-{instance_id}")
}

/// The per-instance runtime dir on the host
/// (`$XDG_RUNTIME_DIR/wlsctx/<app>-<inst>`).
pub fn host_instance_dir(app_id: &str, instance_id: &str) -> String {
    let uid = nix::unistd::getuid().as_raw();
    let xdg = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| format!("/run/user/{uid}"));
    format!("{xdg}/wlsctx/{}", instance_name(app_id, instance_id))
}

/// The public socket path inside the instance runtime dir.
pub fn public_socket_path(cfg: &Config) -> String {
    format!(
        "{}/{}",
        host_instance_dir(&cfg.app_id, &cfg.instance_id),
        cfg.socket_name
    )
}

/// The bus address, defaulting to the session bus in the environment.
pub fn bus_address(cfg: &Config) -> String {
    if cfg.bus_address.is_empty() {
        std::env::var("DBUS_SESSION_BUS_ADDRESS").unwrap_or_else(|_| {
            format!("unix:path=/run/user/{}/bus", nix::unistd::getuid().as_raw())
        })
    } else {
        cfg.bus_address.clone()
    }
}

/// Ids become directory components under `$XDG_RUNTIME_DIR/wlsctx`,
/// so reject anything that could climb out (mirrors the sandbox's
/// `validate_id`, which enforces the same charset for the hostname and
/// cgroup names).
fn validate_id(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        anyhow::bail!("{field} must be non-empty and contain only [A-Za-z0-9._-]: {value:?}");
    }
    Ok(())
}

/// The sidecar signal mask: every signal except the seven
/// kernel-generated fatal faults, which must keep their default
/// disposition (mirrors `proxy::proxy_signal_mask` — built from
/// `SigSet::all()`, never the `Signal` enum, which stops at 31 and
/// would leave the real-time range at default-terminate).
fn signal_mask() -> SigSet {
    let fatal = [SIGFPE, SIGILL, SIGSEGV, SIGBUS, SIGABRT, SIGTRAP, SIGSYS];
    let mut mask = SigSet::all();
    for sig in fatal {
        mask.remove(sig);
    }
    mask
}

/// Block the mask on the calling thread and create the signalfd.
fn setup_signalfd() -> Result<SignalFd> {
    let mask = signal_mask();
    mask.thread_block().map_err(io::Error::other)?;
    SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC)
        .map_err(|e| anyhow::anyhow!("creating the signalfd: {e}"))
}

/// `pidfd_open(2)` via the raw syscall (the `libc` crate does not
/// expose it on all targets); zero flags, explicit.
fn pidfd_open(pid: i32) -> Result<OwnedFd> {
    // SAFETY: syscall(2) with a valid pid and zero flags; returns a
    // new fd or -1.
    let r = unsafe {
        libc::syscall(
            libc::SYS_pidfd_open as libc::c_long,
            pid as libc::c_long,
            0 as libc::c_long,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error()).with_context(|| format!("pidfd_open({pid})"));
    }
    // SAFETY: the syscall returned a fresh fd we now own; it cannot
    // alias any other descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(r as i32) };
    // CLOEXEC so a pidfd never leaks into a later spawn.
    // SAFETY: our own fd; F_SETFD is non-failing.
    let _ = unsafe { libc::fcntl(fd.as_fd().as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    Ok(fd)
}

/// The socketpair behind `--fd=3`: `(side, child)`. The sidecar keeps
/// `side` (CLOEXEC) and parks on it; the child's `pre_exec` dups
/// `child` onto fd 3 and *clears* CLOEXEC so `execve` keeps it. When
/// the sidecar dies (any way) `side` is closed and the proxy's fd 3
/// sees G_IO_HUP — its exit condition.
fn side_socketpair() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    // SAFETY: socketpair(2) with valid family/type; writes both fds
    // on success.
    let r = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error()).context("socketpair(2) for the proxy lifetime");
    }
    let side = unsafe { OwnedFd::from_raw_fd(fds[0]) }; // CLOEXEC, ours alone
    // The child's end must survive execve: remove the flag.
    // SAFETY: our own fresh fd; F_SETFD is non-failing.
    let _ = unsafe { libc::fcntl(fds[1], libc::F_SETFD, 0) };
    let child = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((side, child))
}

/// The `xdg-dbus-proxy` command line: `BIN ADDRESS PATH --fd=3
/// [--filter] [--kind=body ...]`.
///
/// `--fd=3` is *always* present: it names the sidecar's socketpair end
/// (handed over in `pre_exec`) as the proxy's lifetime fd — the proxy
/// writes its sync byte there and exits when it sees the peer close.
/// `--filter` is added exactly when rules are present: without it the
/// proxy is a pure pass-through (the default, which is what an
/// unfiltered bridge should be), and the see/talk/own/call/broadcast
/// rules only take effect once filtering is on — with it, anything not
/// explicitly allowed is refused (fail-closed).
fn proxy_argv(cfg: &Config, socket: &str) -> Vec<String> {
    let mut argv = vec![
        cfg.proxy_bin.clone(),
        bus_address(cfg),
        socket.to_string(),
        "--fd=3".to_string(),
    ];
    if !cfg.rules.is_empty() {
        argv.push("--filter".to_string());
    }
    for r in &cfg.rules {
        argv.push(format!("--{}={}", r.kind, r.body));
    }
    argv
}

/// What a trapped signal asks the sidecar to do.
///
/// Deliberately *not* `proxy::interpret_signal`: its SIGCHLD arm
/// reaps with `waitpid(None, WNOHANG)`, which would steal this
/// sidecar's only child away from the pidfd-based reap below. Here
/// SIGCHLD is pure "continue" (the pidfd is the reliable
/// notification), and SIGHUP exits like SIGTERM — the sidecar has
/// nothing to rebuild in place (no compositor connection, no
/// re-bound listener).
fn sidecar_action(signal: Signal) -> &'static str {
    match signal {
        Signal::SIGTERM | Signal::SIGINT | Signal::SIGHUP => "stop",
        Signal::SIGCHLD => {
            debug!("SIGCHLD: the pidfd is the authoritative notification; continuing");
            "continue"
        }
        sig => {
            debug!("ignoring {sig:?}");
            "continue"
        }
    }
}

/// Run the sidecar: block signals, spawn the proxy, and park until a
/// stop signal or the child's exit.
pub fn run(cfg: Config) -> Result<()> {
    validate_id(&cfg.app_id, "--app-id")?;
    validate_id(&cfg.instance_id, "--instance-id")?;

    // Phase 8.2 (MCS): narrow our range to the instance's category
    // before creating anything (instance dir, bus socket), so they
    // carry the category and the post-re-exec pass starts clean.
    // No-op in unconfined mode.
    crate::mcs::self_reexec_with_category(&cfg.app_id, &cfg.instance_id)?;

    let sigfd = setup_signalfd()?;

    let dir = host_instance_dir(&cfg.app_id, &cfg.instance_id);
    let socket = public_socket_path(&cfg);

    // Tight umask before creating anything: the instance dir (if new)
    // and the socket the proxy creates are owner-only from birth.
    // Restored after the spawn below.
    let old_umask = unsafe { libc::umask(0o077) };
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating the per-instance runtime dir {dir:?}"))?;
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));

    let (side_end, child_end) = side_socketpair()?;
    let child_end_fd = child_end.as_fd().as_raw_fd();

    let argv = proxy_argv(&cfg, &socket);

    // A stable owned copy of the program name: `Command::new(&argv[0])`
    // would deref-coerce the `String` into a *temporary* `OsStr` that
    // dies at the end of the statement, while the `Command` outlives
    // it.
    // The `Command` is a named binding, not a chained temporary: the
    // builder methods return `&mut Command`, and binding that into a
    // let statement over a chained `Command::new(...)` would borrow a
    // temporary that dies at the end of the statement.
    let mut cmd = process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdin(process::Stdio::null())
        .stdout(process::Stdio::inherit())
        .stderr(process::Stdio::inherit());
    // Hand the proxy its lifetime fd: dup the socketpair end onto fd
    // 3, then *remove* CLOEXEC — `execve(2)` closes CLOEXEC
    // descriptors, so the fd must be unmarked to reach the proxy
    // (adding the flag here would silently kill the mechanism).
    // SAFETY: pre_exec runs in the forked child before exec; the
    // closure only calls dup2/fcntl (async-signal-safe) and returns
    // an Err on failure, which aborts the child without exec.
    // SAFETY: fd 3 exists (just dup'd in the same closure); F_GETFD/
    // F_SETFD are non-failing.
    unsafe {
        cmd.pre_exec(move || {
            // The sidecar runs with its full mask blocked; the child
            // must not inherit that: a proxy orphaned with every
            // signal blocked could only be killed with SIGKILL.
            // Reset to the default disposition.
            nix::sys::signal::sigprocmask(SigmaskHow::SIG_SETMASK, Some(&SigSet::empty()), None)
                .map_err(io::Error::other)?;
            // Phase 8.2 (MCS): carry the instance's category into the
            // wlsctx_app_t exec, so the bus socket the proxy creates
            // in the instance dir carries it. A write failure just
            // drops the range (noted on stderr; the child's stderr is
            // inherited); the exec goes on.
            if let Err(e) = crate::mcs::set_exec_context("wlsctx_app_t") {
                let _ = writeln!(io::stderr(), "wlsctx: {e}");
            }
            let rc = libc::dup2(child_end_fd, 3);
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            let _ = libc::fcntl(
                3,
                libc::F_SETFD,
                libc::fcntl(3, libc::F_GETFD, 0) & !libc::FD_CLOEXEC,
            );
            // Close the original: the child must hold *exactly one*
            // reference to its socket end. A second fd for the same
            // end (this process's inherited copy of the dup'd end)
            // prevents the GLib HUP watch from firing when the peer
            // closes — verified against xdg-dbus-proxy 0.1.9.
            if child_end_fd != 3 {
                libc::close(child_end_fd);
            }
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning the D-Bus proxy {}", argv[0]))?;

    // The child holds its own copy (fd 3); drop ours.
    drop(child_end);

    // Readiness gate: the proxy writes a single `x` to its fd 3 on
    // startup. Consuming it proves the exec succeeded and the proxy
    // reached its main loop; a peer that died before writing gives
    // EOF (0 bytes) and we bail.
    let mut sync = [0u8; 1];
    // SAFETY: our own fd; a one-byte read into a valid buffer.
    let n = unsafe { libc::read(side_end.as_fd().as_raw_fd(), sync.as_mut_ptr().cast(), 1) };
    match n {
        0 => anyhow::bail!("the D-Bus proxy exited before its sync handshake"),
        1 if sync[0] == b'x' => {}
        n if n > 0 => anyhow::bail!("unexpected sync payload from the proxy ({n} bytes)"),
        _ => {
            return Err(anyhow::anyhow!(
                "reading the proxy's sync byte: {}",
                io::Error::last_os_error()
            ));
        }
    }

    // The proxy created its socket during the spawn; tighten it now.
    let _ = std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600));
    let _ = unsafe { libc::umask(old_umask) };

    let pidfd = pidfd_open(child.id() as i32)
        .with_context(|| format!("opening a pidfd for the proxy (pid {})", child.id()))?;

    let mode = if cfg.rules.is_empty() {
        "pass-through".to_string()
    } else {
        format!("{} rule(s)", cfg.rules.len())
    };
    info!("D-Bus proxy: {} -> {} ({mode})", socket, bus_address(&cfg));

    loop {
        let mut polls = [
            PollFd::new(&sigfd, PollFlags::IN),
            PollFd::new(&pidfd, PollFlags::IN),
        ];
        match poll(&mut polls, None) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(anyhow::anyhow!("poll(2) in the D-Bus proxy loop: {e}")),
        }

        // A signal asked us to stop?
        if polls[0].revents().intersects(PollFlags::IN) {
            let siginfo = sigfd
                .read_signal()
                .map_err(|e| anyhow::anyhow!("reading the signalfd: {e}"))?
                .ok_or_else(|| anyhow::anyhow!("signalfd closed"))?;
            let action = match Signal::try_from(siginfo.ssi_signo as i32) {
                Ok(signal) => sidecar_action(signal),
                // A signal number outside nix's enum (the real-time
                // range 34-64): blocked, routed here, ignored.
                Err(_) => {
                    debug!(
                        "ignoring signal number {} (real-time range)",
                        siginfo.ssi_signo
                    );
                    "continue"
                }
            };
            if action == "stop" {
                info!("D-Bus proxy: stop signal; terminating the child and exiting");
                terminate_child(&mut child);
                return Ok(());
            }
        }

        // The proxy exited on its own?
        if polls[1].revents().intersects(PollFlags::IN) {
            match child.wait() {
                Ok(status) => {
                    let code = status.code().unwrap_or(0);
                    info!("D-Bus proxy: child exited with {code}; exiting");
                    if code != 0 {
                        std::process::exit(code);
                    }
                    return Ok(());
                }
                Err(e) => return Err(anyhow::anyhow!("waiting on the D-Bus proxy child: {e}")),
            }
        }
    }
}

fn terminate_child(child: &mut process::Child) {
    let pid = child.id() as i32;
    // SIGTERM first; SIGKILL after a grace period (the proxy may be
    // mid-frame). The wait reaps it so nothing is left behind.
    // SAFETY: a valid pid we own; kill(2) of our own child.
    let _ = unsafe { libc::kill(pid, libc::SIGTERM) };
    std::thread::sleep(std::time::Duration::from_secs(2));
    // SAFETY: as above.
    let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_name_is_app_dash_instance() {
        let dir = host_instance_dir("firefox", "1");
        let base = dir.rsplit('/').next().unwrap();
        assert_eq!(base, "firefox-1");
        assert!(dir.ends_with("wlsctx/firefox-1"));
    }

    #[test]
    fn public_socket_lands_in_instance_dir() {
        let cfg = Config {
            app_id: "firefox".into(),
            instance_id: "1".into(),
            ..Default::default()
        };
        assert_eq!(
            public_socket_path(&cfg),
            format!("{}/bus.sock", host_instance_dir("firefox", "1"))
        );
    }

    #[test]
    fn bus_address_prefers_explicit() {
        let cfg = Config {
            bus_address: "unix:path=/run/user/1000/bus".into(),
            ..Default::default()
        };
        assert_eq!(bus_address(&cfg), "unix:path=/run/user/1000/bus");
    }

    #[test]
    fn rules_format_as_proxy_arguments() {
        // The sidecar forwards rules verbatim as --kind=body, and
        // enables --filter exactly when rules are present (the proxy
        // only applies them with filtering on).
        let cfg = Config {
            proxy_bin: "proxy".into(),
            bus_address: "unix:u".into(),
            rules: vec![
                Rule {
                    kind: "see",
                    body: "org.freedesktop.DBus".into(),
                },
                Rule {
                    kind: "talk",
                    body: "org.freedesktop.portal.*".into(),
                },
            ],
            ..Default::default()
        };
        let expected: Vec<String> = vec![
            "proxy".into(),
            "unix:u".into(),
            "/p".into(),
            // --fd=3 is always present (the proxy's lifetime fd).
            "--fd=3".into(),
            "--filter".into(),
            "--see=org.freedesktop.DBus".into(),
            "--talk=org.freedesktop.portal.*".into(),
        ];
        assert_eq!(proxy_argv(&cfg, "/p"), expected);

        // No rules: pure pass-through, no --filter, but --fd=3 stays.
        let passthrough = Config {
            proxy_bin: "proxy".into(),
            bus_address: "unix:u".into(),
            ..Default::default()
        };
        let expected: Vec<String> = vec![
            "proxy".into(),
            "unix:u".into(),
            "/p".into(),
            "--fd=3".into(),
        ];
        assert_eq!(proxy_argv(&passthrough, "/p"), expected);
    }

    #[test]
    fn id_validation_rejects_path_climbers() {
        assert!(validate_id("firefox", "app").is_ok());
        assert!(validate_id("app-1", "instance").is_ok());
        assert!(validate_id("", "app").is_err());
        assert!(validate_id("../..", "app").is_err());
        assert!(validate_id("a/b", "app").is_err());
    }

    #[test]
    fn side_socketpair_ends_are_connected_with_opposite_cloexec() {
        let (side, child) = side_socketpair().unwrap();
        // The ends are peers: a write on one arrives on the other.
        // SAFETY: our own fds; one-byte writes/reads into valid buffers.
        let sfd = side.as_fd().as_raw_fd();
        let cfd = child.as_fd().as_raw_fd();
        // SAFETY: as above.
        let _ = unsafe { libc::write(cfd, b"x".as_ptr().cast(), 1) };
        let mut buf = [0u8; 1];
        // SAFETY: as above.
        let n = unsafe { libc::read(sfd, buf.as_mut_ptr().cast(), 1) };
        assert_eq!(n, 1);
        assert_eq!(buf, [b'x']);
        // Ours is CLOEXEC (never crosses a spawn); the child's end is
        // unmarked so `execve` keeps it alive past the exec.
        // SAFETY: F_GETFD is non-failing on our own fds.
        let side_flags = unsafe { libc::fcntl(sfd, libc::F_GETFD, 0) };
        let child_flags = unsafe { libc::fcntl(cfd, libc::F_GETFD, 0) };
        assert_ne!(side_flags & libc::FD_CLOEXEC, 0);
        assert_eq!(child_flags & libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn signal_mask_matches_the_proxy_contract() {
        let mask = signal_mask();
        // The seven kernel fatal faults must stay unblocked.
        for sig in [SIGFPE, SIGILL, SIGSEGV, SIGBUS, SIGABRT, SIGTRAP, SIGSYS] {
            assert!(!mask.contains(sig), "{sig:?} must stay unblocked");
        }
        // Everything the sidecar acts on must be blocked.
        for sig in [
            Signal::SIGTERM,
            Signal::SIGINT,
            Signal::SIGHUP,
            Signal::SIGCHLD,
        ] {
            assert!(mask.contains(sig), "{sig:?} must be blocked");
        }
    }
}
