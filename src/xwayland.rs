//! The Xwayland satellite (Phase 7.3, decision #37).
//!
//! `wlsctx xwayland` runs a per-instance [`Xwayland`] on the *host* —
//! an ordinary Wayland client of the desktop compositor — and shares
//! only its X socket into the sandbox through the per-instance
//! runtime dir. The sandboxed app points at it with
//! `DISPLAY=unix:…/xwayland.sock` and `XAUTHORITY=…/xwayland-auth`
//! (the *in-sandbox* paths, decision #28).
//!
//! Why host-side (not in-sandbox): the X server is the least-trusted
//! component of the X stack — it reads every client's pixels and can
//! inject input. Inside the sandbox it would hold the app's full
//! capability set (network, home rw); as a host satellite it sits at
//! the same documented trust tier as the `dbus-proxy` sidecar and the
//! relay. It also avoids dragging the whole X/GL stack into the
//! private rootfs.
//!
//! The sidecar owns the child exactly like the `dbus-proxy` sidecar:
//! it blocks the proxy signal mask, spawns Xwayland, and parks on a
//! `poll(2)` loop watching a signalfd and the child's pidfd.
//! SIGTERM/SIGINT/SIGHUP terminate the child (TERM, then KILL after
//! 2 s) and exit with its status; a child that dies on its own is
//! reaped and the sidecar exits with its status. There is no
//! in-place rebuild (a manual run, like `dbus-proxy`).
//!
//! Two fds are handed over in `pre_exec`, both made *non*-CLOEXEC
//! (`execve(2)` closes CLOEXEC descriptors — the decision-#36 fd
//! contract):
//!
//! - **fd 4, `-listenfd`**: the X socket the *sidecar* created and
//!   bound (`<instance-dir>/xwayland.sock`, owner-only from birth).
//!   Xwayland calls `listen(2)` on it. This is the same pattern sway
//!   uses to spawn its own Xwayland.
//! - **fd 5, `-displayfd`**: one end of a private socketpair. Xwayland
//!   writes the display number in use when it is ready to take
//!   clients and closes it; the sidecar reads it as the readiness
//!   gate and cross-checks it against the requested `--display` — a
//!   mismatch is a hard error (the app's profile must name a stable
//!   display, so a silent renumbering would be worse than a failure).
//!
//! Other arguments: `-auth <instance-dir>/xwayland-auth` (Xwayland
//! writes its MIT cookie there; the app's `XAUTHORITY` points at the
//! in-sandbox copy), `-nolisten tcp` (never a TCP listener), `-once`
//! (the server exits when the *last* X client disconnects — a
//! SIGKILL'd satellite leaves a self-cleaning Xwayland), and
//! `-rootless` by default (the window integrates with the desktop;
//! `--no-rootless` for the framed window).
//!
//! The sidecar sets `umask(0077)` before creating anything: the
//! instance dir (if new) and the socket it binds are owner-only from
//! birth, and the auth file Xwayland creates is tightened once it
//! exists (the wayland listener's pattern).
//!
//! Note: Xwayland *additionally* binds the conventional
//! `/tmp/.X11-unix/X<N>` on the host (it always does, even with
//! `-listenfd` — sway's own instance shows it). That socket is
//! cookie-gated and owner-reachable; it is a `:N` convenience on the
//! host, not an extra exposure.
//!
//! [`Xwayland`]: https://www.x.org/archive/commission/xace/docs/xwayland/

use std::io;
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

/// The fd number the sidecar hands Xwayland as `-listenfd` (the X
/// socket). Fixed, mirrored by `pre_exec` below.
const LISTEN_FD: i32 = 4;
/// The fd number the sidecar hands Xwayland as `-displayfd` (the
/// readiness socketpair end). Fixed, mirrored by `pre_exec` below.
const DISPLAY_FD: i32 = 5;

/// How the satellite runs.
#[derive(Debug, Clone)]
pub struct Config {
    /// Application id (part of the instance name).
    pub app_id: String,
    /// Instance id (part of the instance name).
    pub instance_id: String,
    /// The X display number (e.g. 97 → `:97`). Kept clear of the
    /// compositor's auto-spawned Xwayland.
    pub display: u16,
    /// The X socket's file name inside the instance runtime dir
    /// (default `xwayland.sock`).
    pub socket_name: String,
    /// The auth file's name inside the instance runtime dir
    /// (default `xwayland-auth`).
    pub auth_name: String,
    /// The host compositor's Wayland display; defaults to the
    /// `WAYLAND_DISPLAY` environment variable.
    pub wayland_display: String,
    /// The Xwayland binary (default `Xwayland`, resolved on `PATH`).
    pub xwayland_bin: String,
    /// Run rootless (the default) or as a framed window.
    pub rootless: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            app_id: "app".into(),
            instance_id: "1".into(),
            display: 97,
            socket_name: "xwayland.sock".into(),
            auth_name: "xwayland-auth".into(),
            wayland_display: String::new(),
            xwayland_bin: "Xwayland".into(),
            rootless: true,
        }
    }
}

/// The instance name: `<app>-<instance>`.
///
/// Must stay in sync with `sandbox::namespaces::cgroup_name_for`
/// (binary-only, unreachable from the library) and
/// `dbus_proxy::instance_name` — the instance runtime dir, cgroup and
/// hostname all use this same form.
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

/// The per-instance runtime dir's path *inside the sandbox*: the
/// systemd-standard location, regardless of the host's
/// `XDG_RUNTIME_DIR` (decision #28). This is the path the app's
/// `DISPLAY`/`XAUTHORITY` env must use.
pub fn sandbox_instance_dir(app_id: &str, instance_id: &str) -> String {
    let uid = nix::unistd::getuid().as_raw();
    format!(
        "/run/user/{uid}/wlsctx/{}",
        instance_name(app_id, instance_id)
    )
}

/// The X socket path inside the instance runtime dir.
pub fn listen_socket_path(cfg: &Config) -> String {
    format!(
        "{}/{}",
        host_instance_dir(&cfg.app_id, &cfg.instance_id),
        cfg.socket_name
    )
}

/// The auth file path inside the instance runtime dir.
pub fn auth_path(cfg: &Config) -> String {
    format!(
        "{}/{}",
        host_instance_dir(&cfg.app_id, &cfg.instance_id),
        cfg.auth_name
    )
}

/// The Wayland display to connect to, defaulting to the environment.
pub fn wayland_display(cfg: &Config) -> Result<String> {
    if !cfg.wayland_display.is_empty() {
        return Ok(cfg.wayland_display.clone());
    }
    std::env::var("WAYLAND_DISPLAY").context(
        "no --wayland-display given and no WAYLAND_DISPLAY in the environment; \
         Xwayland needs the host compositor",
    )
}

/// Ids become directory components under `$XDG_RUNTIME_DIR/wlsctx`,
/// so reject anything that could climb out (mirrors `dbus-proxy`'s
/// `validate_id`, which enforces the same charset).
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

/// Display numbers are conventional 0–9999; 0 is the "real" display
/// and is what sway's auto-Xwayland takes on many setups, so the
/// satellite requires 1–9999.
pub fn validate_display(display: u16) -> Result<()> {
    if !(1..=9999).contains(&display) {
        anyhow::bail!("--display must be 1..=9999 (0 is the conventional real display): {display}");
    }
    Ok(())
}

/// The satellite signal mask: every signal except the seven
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

/// The socketpair behind `-displayfd`: `(side, child)`. The sidecar
/// keeps `side` (CLOEXEC); the child's `pre_exec` dups `child` onto
/// fd 5 and *clears* CLOEXEC so `execve` keeps it. Xwayland writes
/// the display number there and closes it; the sidecar reads it as
/// the readiness gate.
fn displayfd_socketpair() -> Result<(OwnedFd, OwnedFd)> {
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
        return Err(io::Error::last_os_error()).context("socketpair(2) for the displayfd");
    }
    let side = unsafe { OwnedFd::from_raw_fd(fds[0]) }; // CLOEXEC, ours alone
    // The child's end must survive execve: remove the flag.
    // SAFETY: our own fresh fd; F_SETFD is non-failing.
    let _ = unsafe { libc::fcntl(fds[1], libc::F_SETFD, 0) };
    let child = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((side, child))
}

/// Create, bind, and return the X socket (owner-only from birth).
///
/// A stale socket file from a crashed run is removed first (a
/// `bind(2)` onto an existing unix socket path is `EADDRINUSE`).
fn create_listen_socket(path: &str) -> Result<OwnedFd> {
    let fd = socket_cloexec()?;
    if let Err(e) = bind_unix(&fd.as_fd(), path) {
        drop(fd);
        // A failed bind (e.g. `EADDRINUSE`) would otherwise leave an
        // unbound socket file behind; don't.
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    Ok(fd)
}

/// `socket(2)`, `AF_UNIX`/`SOCK_STREAM`/`SOCK_CLOEXEC`.
fn socket_cloexec() -> Result<OwnedFd> {
    // SAFETY: socket(2) with valid family/type/protocol; returns a
    // new fd or -1.
    let r = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if r < 0 {
        return Err(io::Error::last_os_error()).context("socket(2) for the X socket");
    }
    // SAFETY: the syscall returned a fresh fd we now own.
    Ok(unsafe { OwnedFd::from_raw_fd(r) })
}

/// `bind(2)` a unix socket fd to a path; removes a stale socket file
/// first. The path is NUL-terminated (decision #17).
fn bind_unix(fd: &std::os::fd::BorrowedFd<'_>, path: &str) -> Result<()> {
    let _ = std::fs::remove_file(path); // stale socket from a crashed run
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as u16;
    let bytes = path.as_bytes();
    if bytes.len() > addr.sun_path.len() {
        anyhow::bail!("socket path too long (>{})", addr.sun_path.len());
    }
    // SAFETY: `addr` is zeroed; `sun_path` (a `[i8]` in this libc) is
    // filled with the path bytes, and the zero-init padding supplies
    // the trailing NUL (decision #17: every path handed to C is
    // NUL-terminated).
    unsafe {
        for (slot, &b) in addr.sun_path[..bytes.len()].iter_mut().zip(bytes) {
            *slot = b as i8;
        }
        let r = libc::bind(
            fd.as_raw_fd(),
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as u32,
        );
        if r < 0 {
            return Err(io::Error::last_os_error()).with_context(|| format!("bind({path})"));
        }
    }
    Ok(())
}

/// The `Xwayland` command line: `BIN :N -listenfd 4 -displayfd 5
/// -auth <path> -nolisten tcp -once [-rootless]`.
///
/// `-listenfd`/`-displayfd` name the two fds handed over in
/// `pre_exec` (decision #36's fd contract — non-CLOEXEC, since
/// `execve(2)` closes CLOEXEC descriptors). `-once` makes a SIGKILL'd
/// satellite's orphan self-clean: Xwayland exits when its last X
/// client (the sandboxed app) disconnects.
fn xwayland_argv(cfg: &Config, auth: &str) -> Vec<String> {
    let mut argv = vec![
        cfg.xwayland_bin.clone(),
        format!(":{}", cfg.display),
        "-listenfd".to_string(),
        LISTEN_FD.to_string(),
        "-displayfd".to_string(),
        DISPLAY_FD.to_string(),
        "-auth".to_string(),
        auth.to_string(),
        "-nolisten".to_string(),
        "tcp".to_string(),
        "-once".to_string(),
    ];
    if cfg.rootless {
        argv.push("-rootless".to_string());
    }
    argv
}

/// What a trapped signal asks the satellite to do.
///
/// Deliberately *not* `proxy::interpret_signal`: its SIGCHLD arm
/// reaps with `waitpid(None, WNOHANG)`, which would steal this
/// sidecar's only child away from the pidfd-based reap below. Here
/// SIGCHLD is pure "continue" (the pidfd is the reliable
/// notification), and SIGHUP stops like SIGTERM — the satellite has
/// nothing to rebuild in place.
fn satellite_action(signal: Signal) -> &'static str {
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

/// Run the satellite: block signals, create the X socket, spawn
/// Xwayland, gate on its display number, and park until a stop
/// signal or the child's exit.
pub fn run(cfg: Config) -> Result<()> {
    validate_id(&cfg.app_id, "--app-id")?;
    validate_id(&cfg.instance_id, "--instance-id")?;
    validate_display(cfg.display)?;

    let sigfd = setup_signalfd()?;

    let dir = host_instance_dir(&cfg.app_id, &cfg.instance_id);
    let socket = listen_socket_path(&cfg);
    let auth = auth_path(&cfg);

    // Tight umask before creating anything: the instance dir (if new)
    // and the socket are owner-only from birth, and the auth file
    // Xwayland creates inherits it. Restored after the spawn below.
    let old_umask = unsafe { libc::umask(0o077) };
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating the per-instance runtime dir {dir:?}"))?;
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));

    let listen = create_listen_socket(&socket)?;
    let (df_side, df_child) = displayfd_socketpair()?;
    let listen_fd = listen.as_fd().as_raw_fd();
    let df_child_fd = df_child.as_fd().as_raw_fd();

    let argv = xwayland_argv(&cfg, &auth);
    let wl_display = wayland_display(&cfg)?;

    // A stable owned copy of the program name (same note as the
    // `dbus-proxy` sidecar): `Command::new(&argv[0])` would
    // deref-coerce the `String` into a *temporary* `OsStr` that dies
    // at the end of the statement, while the `Command` outlives it.
    // The `Command` is a named binding, not a chained temporary.
    let mut cmd = process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .env("WAYLAND_DISPLAY", &wl_display)
        .stdin(process::Stdio::null())
        .stdout(process::Stdio::inherit())
        .stderr(process::Stdio::inherit());
    // Hand Xwayland its two fds: dup each onto its fixed number and
    // *remove* CLOEXEC — `execve(2)` closes CLOEXEC descriptors, so
    // both must be unmarked to reach Xwayland.
    // SAFETY: pre_exec runs in the forked child before exec; the
    // closure only calls dup2/fcntl (async-signal-safe) and returns
    // an Err on failure, which aborts the child without exec.
    unsafe {
        cmd.pre_exec(move || {
            // The satellite runs with its full mask blocked; the
            // child must not inherit that: an orphaned Xwayland with
            // every signal blocked could only be killed with
            // SIGKILL. Reset to the default disposition.
            nix::sys::signal::sigprocmask(SigmaskHow::SIG_SETMASK, Some(&SigSet::empty()), None)
                .map_err(io::Error::other)?;
            let rc = libc::dup2(listen_fd, LISTEN_FD);
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            let _ = libc::fcntl(
                LISTEN_FD,
                libc::F_SETFD,
                libc::fcntl(LISTEN_FD, libc::F_GETFD, 0) & !libc::FD_CLOEXEC,
            );
            let rc = libc::dup2(df_child_fd, DISPLAY_FD);
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            let _ = libc::fcntl(
                DISPLAY_FD,
                libc::F_SETFD,
                libc::fcntl(DISPLAY_FD, libc::F_GETFD, 0) & !libc::FD_CLOEXEC,
            );
            // Close the originals: the child must hold *exactly one*
            // reference to each fd it was handed.
            if listen_fd != LISTEN_FD {
                libc::close(listen_fd);
            }
            if df_child_fd != DISPLAY_FD {
                libc::close(df_child_fd);
            }
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning Xwayland {}", argv[0]))?;

    // The child holds its own copies; drop ours.
    drop(df_child);

    // Readiness gate: Xwayland writes the display number in use to
    // its `-displayfd` when it can take clients, then closes it.
    // Consuming through to EOF proves the exec succeeded and Xwayland
    // reached the listener; a peer that died before writing gives EOF
    // with nothing and we bail.
    let raw = read_to_eof(&df_side)?;
    // The number may be followed by a newline/whitespace.
    let num: String = raw
        .iter()
        .take_while(|&b| b.is_ascii_digit())
        .map(|&b| b as char)
        .collect();
    if num.is_empty() {
        anyhow::bail!("Xwayland closed its displayfd without a display number (read {raw:?})");
    }
    let reported: u32 = num
        .parse()
        .with_context(|| format!("displayfd payload {raw:?}"))?;
    if reported != u32::from(cfg.display) {
        anyhow::bail!(
            "Xwayland reports display :{reported}, but :{} was requested; \
             is that display already taken on the host?",
            cfg.display
        );
    }

    // Xwayland created its auth file during startup (our umask made
    // it 0600); tighten it explicitly, matching the wayland
    // listener's pattern.
    let _ = std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o600));
    let _ = unsafe { libc::umask(old_umask) };

    let pidfd = pidfd_open(child.id() as i32)
        .with_context(|| format!("opening a pidfd for Xwayland (pid {})", child.id()))?;

    let sand = sandbox_instance_dir(&cfg.app_id, &cfg.instance_id);
    info!(
        "xwayland: ready — display :{}, socket {}, auth {} (rootless: {})",
        cfg.display, socket, auth, cfg.rootless
    );
    info!(
        "xwayland: profile [env] → DISPLAY=unix:{}/{}, XAUTHORITY={}/{}",
        sand, cfg.socket_name, sand, cfg.auth_name
    );

    loop {
        let mut polls = [
            PollFd::new(&sigfd, PollFlags::IN),
            PollFd::new(&pidfd, PollFlags::IN),
        ];
        match poll(&mut polls, None) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(anyhow::anyhow!("poll(2) in the xwayland loop: {e}")),
        }

        // A signal asked us to stop?
        if polls[0].revents().intersects(PollFlags::IN) {
            let siginfo = sigfd
                .read_signal()
                .map_err(|e| anyhow::anyhow!("reading the signalfd: {e}"))?
                .ok_or_else(|| anyhow::anyhow!("signalfd closed"))?;
            let action = match Signal::try_from(siginfo.ssi_signo as i32) {
                Ok(signal) => satellite_action(signal),
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
                info!("xwayland: stop signal; terminating the child and exiting");
                terminate_child(&mut child);
                return Ok(());
            }
        }

        // Xwayland exited on its own?
        if polls[1].revents().intersects(PollFlags::IN) {
            match child.wait() {
                Ok(status) => {
                    let code = status.code().unwrap_or(0);
                    info!("xwayland: child exited with {code}; exiting");
                    if code != 0 {
                        std::process::exit(code);
                    }
                    return Ok(());
                }
                Err(e) => return Err(anyhow::anyhow!("waiting on the Xwayland child: {e}")),
            }
        }
    }
}

/// Read `fd` until EOF (or 256 bytes, whatever comes first).
///
/// Xwayland's displayfd payload is a few ASCII digits; a blocking
/// read loop would hang forever if the child wrote but never closed,
/// so the side read is made non-blocking first and polled in a tight
/// loop: `EAGAIN` just means "not all of it yet", `0` is the close.
fn read_to_eof(fd: &OwnedFd) -> Result<Vec<u8>> {
    let raw = fd.as_fd().as_raw_fd();
    // SAFETY: our own fd; O_NONBLOCK is a safe flag combination.
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFL, 0) };
    if flags < 0 {
        return Err(io::Error::last_os_error()).context("F_GETFL on the displayfd side end");
    }
    // SAFETY: as above; keep every existing flag.
    let _ = unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) };

    let mut buf = Vec::new();
    loop {
        let mut b = [0u8; 64];
        // SAFETY: our own fd; a read into a valid buffer.
        let n = unsafe { libc::read(raw, b.as_mut_ptr().cast(), b.len()) };
        if n > 0 {
            buf.extend_from_slice(&b[..n as usize]);
            if buf.len() > 256 {
                break;
            }
        } else if n == 0 {
            break; // EOF: Xwayland closed its end
        } else {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN)
                || err.raw_os_error() == Some(libc::EWOULDBLOCK)
            {
                continue; // partial: more is coming
            }
            return Err(err).context("reading Xwayland's display number");
        }
    }
    Ok(buf)
}

fn terminate_child(child: &mut process::Child) {
    let pid = child.id() as i32;
    // SIGTERM first; SIGKILL after a grace period (Xwayland may be
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
        let host = host_instance_dir("firefox", "1");
        assert!(host.ends_with("wlsctx/firefox-1"));
        // The sandbox path is the systemd-standard location,
        // regardless of the host's XDG_RUNTIME_DIR (decision #28).
        let uid = nix::unistd::getuid().as_raw();
        assert_eq!(
            sandbox_instance_dir("firefox", "1"),
            format!("/run/user/{uid}/wlsctx/firefox-1")
        );
    }

    #[test]
    fn listen_socket_and_auth_land_in_instance_dir() {
        let cfg = Config {
            app_id: "firefox".into(),
            instance_id: "1".into(),
            ..Default::default()
        };
        assert_eq!(
            listen_socket_path(&cfg),
            format!("{}/xwayland.sock", host_instance_dir("firefox", "1"))
        );
        assert_eq!(
            auth_path(&cfg),
            format!("{}/xwayland-auth", host_instance_dir("firefox", "1"))
        );
    }

    #[test]
    fn display_validation_bounds() {
        assert!(validate_display(0).is_err());
        assert!(validate_display(1).is_ok());
        assert!(validate_display(97).is_ok());
        assert!(validate_display(9999).is_ok());
        assert!(validate_display(10000).is_err());
    }

    #[test]
    fn argv_is_listendf_displayfd_auth_nolisten_once() {
        // Rootless (the default): the trailing -rootless is present.
        let cfg = Config {
            xwayland_bin: "Xwayland".into(),
            display: 97,
            rootless: true,
            ..Default::default()
        };
        let expected: Vec<String> = vec![
            "Xwayland".into(),
            ":97".into(),
            "-listenfd".into(),
            "4".into(),
            "-displayfd".into(),
            "5".into(),
            "-auth".into(),
            "/a/xwayland-auth".into(),
            "-nolisten".into(),
            "tcp".into(),
            "-once".into(),
            "-rootless".into(),
        ];
        assert_eq!(xwayland_argv(&cfg, "/a/xwayland-auth"), expected);
        // Rootful: no trailing -rootless.
        let rootful = Config {
            rootless: false,
            ..cfg
        };
        let argv = xwayland_argv(&rootful, "/a/xwayland-auth");
        assert!(!argv.contains(&"-rootless".to_string()));
        assert_eq!(argv.len(), 11);
    }

    #[test]
    fn displayfd_socketpair_ends_are_connected_with_opposite_cloexec() {
        let (side, child) = displayfd_socketpair().unwrap();
        // The ends are peers: a write on one arrives on the other.
        // SAFETY: our own fds; a small write/read into valid buffers.
        let cfd = child.as_fd().as_raw_fd();
        // SAFETY: as above.
        let _ = unsafe { libc::write(cfd, b"97".as_ptr().cast(), 2) };
        let mut buf = [0u8; 2];
        // SAFETY: as above.
        let n = unsafe { libc::read(side.as_fd().as_raw_fd(), buf.as_mut_ptr().cast(), 2) };
        assert_eq!(n, 2);
        assert_eq!(buf, [b'9', b'7']);
        // Ours is CLOEXEC (never crosses a spawn); the child's end is
        // unmarked so `execve` keeps it alive past the exec.
        // SAFETY: F_GETFD is non-failing on our own fds.
        let side_flags = unsafe { libc::fcntl(side.as_fd().as_raw_fd(), libc::F_GETFD, 0) };
        let child_flags = unsafe { libc::fcntl(cfd, libc::F_GETFD, 0) };
        assert_ne!(side_flags & libc::FD_CLOEXEC, 0);
        assert_eq!(child_flags & libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn signal_mask_matches_the_sidecar_contract() {
        let mask = signal_mask();
        // The seven kernel fatal faults must stay unblocked.
        for sig in [SIGFPE, SIGILL, SIGSEGV, SIGBUS, SIGABRT, SIGTRAP, SIGSYS] {
            assert!(!mask.contains(sig), "{sig:?} must stay unblocked");
        }
        // Everything the satellite acts on must be blocked.
        for sig in [
            Signal::SIGTERM,
            Signal::SIGINT,
            Signal::SIGHUP,
            Signal::SIGCHLD,
        ] {
            assert!(mask.contains(sig), "{sig:?} must be blocked");
        }
    }

    #[test]
    fn id_validation_rejects_path_climbers() {
        assert!(validate_id("firefox", "app").is_ok());
        assert!(validate_id("app-1", "instance").is_ok());
        assert!(validate_id("", "app").is_err());
        assert!(validate_id("../..", "app").is_err());
        assert!(validate_id("a/b", "app").is_err());
    }
}
