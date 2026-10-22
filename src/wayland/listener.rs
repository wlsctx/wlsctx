//! Getting the Unix listener to tag: systemd socket activation
//! (LISTEN_FDS) or a self-bound socket, refusing to steal a socket
//! that a live process still serves.

use crate::cli::WaylandArgs;
use anyhow::{Context, Result, bail};
use log::{error, info, warn};
use std::fs;
use std::io;
use std::os::fd::FromRawFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path;

/// Get the Unix listener to tag, either from a systemd socket activation
/// or by binding the socket ourselves (refusing to steal a socket that a
/// live process still serves). Returns (app_id, instance_id, listener).
pub fn obtain_listener(args: &WaylandArgs) -> Result<(String, String, UnixListener)> {
    let app_id = args.app_id.clone();
    let instance_id = args.instance_id.clone();
    if args.socket_activation {
        // The IDs come from --app-id/--instance-id (or the
        // WLSCTX_APP_ID / WLSCTX_INSTANCE_ID environment variables). They
        // used to be derived from the fd name, but that only worked for
        // "app@instance" instance names and the socket unit sets
        // FileDescriptorName=%i, so the name normally contains no '@' and
        // the derivation panicked.
        match unsafe { sd_notify::listen_fds_with_names_and_unset_env() } {
            Ok(mut it) => match it.len() {
                0 => bail!(
                    "no socket was received via systemd socket activation (LISTEN_FDS is \
                     not set or empty); run wlsctx through a socket unit or \
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
                 through a socket unit or use --listen instead"
            ),
        }
    } else {
        let socket_path = args.listen.as_ref().ok_or_else(|| {
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
                let _ = fs::remove_file(path)
                    .inspect_err(|e| error!("Failed to remove stale socket {path:?}: {e}"));
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
    // SocketMode=0600, this covers --listen, i.e. the in-pod sidecar
    // mode and manual use).
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600)).inspect_err(|e| {
        warn!("chmod {path:?} to 0600 failed (continuing with umask permissions): {e}")
    });
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{LISTEN_FD_LOCK, TmpDir, xdg_runtime_dir, with_env};
    use std::os::fd::{AsRawFd, OwnedFd};

    fn test_wayland_listen(listen: &str) -> WaylandArgs {
        WaylandArgs {
            app_id: "rustrover".into(),
            instance_id: "work".into(),
            sandbox_engine: "podman".into(),
            listen: Some(path::PathBuf::from(listen)),
            socket_activation: false,
        }
    }

    fn test_wayland_socket_activation() -> WaylandArgs {
        WaylandArgs {
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
                return Err(std::io::Error::other(format!(
                    "fd {target} is in use in the test process"
                )));
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

    #[test]
    fn listen_absolute_binds_at_exact_path() {
        // An absolute path is used as-is; no XDG involvement, so this
        // holds even with XDG_RUNTIME_DIR unset.
        let dir = TmpDir::new("listen-abs");
        let sock = dir.path().join("wayland-1");
        with_env(&[("XDG_RUNTIME_DIR", None)], || {
            let (_, _, listener) = obtain_listener(&test_wayland_listen(sock.to_str().unwrap()))
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
            let _ = obtain_listener(&test_wayland_listen(sock.to_str().unwrap()))
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

        let (_, _, listener) = obtain_listener(&test_wayland_listen(sock.to_str().unwrap()))
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
        let err = obtain_listener(&test_wayland_listen(sock.to_str().unwrap()))
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
        let err = obtain_listener(&test_wayland_listen(sock.to_str().unwrap()))
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
        let err = obtain_listener(&test_wayland_listen(sock.to_str().unwrap()))
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
                let err = obtain_listener(&test_wayland_listen("")).expect_err("empty path must fail");
                assert!(
                    format!("{err:#}").contains("not a socket"),
                    "clear error expected, got: {err:#}"
                );
            },
        );
    }

    #[test]
    fn listen_relative_path_placed_in_xdg_runtime_dir() {
        // Relative paths go into $XDG_RUNTIME_DIR; nested names (the
        // standalone mode uses wlsctx/<instance>/wayland-1) create their
        // subdirectories.
        let runtime = xdg_runtime_dir(0o700);
        with_env(
            &[("XDG_RUNTIME_DIR", Some(runtime.path().to_str().unwrap()))],
            || {
                let expected = runtime.path().join("wlsctx/work/wayland-1");
                let (_, _, listener) = obtain_listener(&test_wayland_listen("wlsctx/work/wayland-1"))
                    .expect("relative path must land in the runtime dir");
                assert_eq!(socket_path(&listener), Some(expected));
                assert!(runtime.path().join("wlsctx/work").is_dir());
            },
        );
    }

    #[test]
    fn listen_relative_path_without_xdg_runtime_dir_fails() {
        with_env(&[("XDG_RUNTIME_DIR", None)], || {
            let err = obtain_listener(&test_wayland_listen("wayland-1"))
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
            let err = obtain_listener(&test_wayland_listen("wayland-1"))
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
                let err = obtain_listener(&test_wayland_listen("wayland-1"))
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
                let err = obtain_listener(&test_wayland_listen(&long_name))
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
                let err = obtain_listener(&test_wayland_socket_activation())
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
                let err = obtain_listener(&test_wayland_socket_activation())
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
        // obtain_listener bails before adopting the fd (that is the
        // behaviour under test), so we hold it in an OwnedFd from here
        // until the end of the test: it is closed on every exit path,
        // including a panic inside the closure, so a failing test cannot
        // leak fd 3 and make later socket-activation tests silently skip.
        // SAFETY: fd 3 is open (install_on_fd succeeded) and no other
        // code in the test process references it; this wrapper is the
        // sole owner and is dropped exactly once.
        let fd3 = unsafe { OwnedFd::from_raw_fd(3) };
        with_env(
            &[
                ("LISTEN_FDS", Some("1")),
                ("LISTEN_PID", Some(&pid)),
                ("LISTEN_FDNAMES", Some("a:b")), // 2 names, 1 fd
            ],
            || {
                let err = obtain_listener(&test_wayland_socket_activation())
                    .expect_err("fdname count mismatch must fail before any fd is adopted");
                assert!(
                    format!("{err:#}")
                        .contains("no socket was received via systemd socket activation"),
                    "actionable error expected, got: {err:#}"
                );
            },
        );
        drop(fd3);
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
        // SAFETY: as in the fdname-mismatch test — fd 3 is open
        // (install_on_fd succeeded) and exclusively ours; the wrapper
        // keeps it closed-on-every-exit-path from here on.
        let fd3 = unsafe { OwnedFd::from_raw_fd(3) };
        match install_on_fd(4, listener_b) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("skipping: fd 4 unavailable in the test process: {e}");
                return; // fd3 is closed by its drop
            }
        }
        // SAFETY: same, for fd 4.
        let fd4 = unsafe { OwnedFd::from_raw_fd(4) };
        let pid = std::process::id().to_string();
        with_env(
            &[
                ("LISTEN_FDS", Some("2")),
                ("LISTEN_PID", Some(&pid)),
                ("LISTEN_FDNAMES", Some("a:b")),
            ],
            || {
                let err = obtain_listener(&test_wayland_socket_activation())
                    .expect_err("more than one fd must be rejected");
                let msg = format!("{err:#}");
                assert!(msg.contains("tags exactly one"), "{msg}");
            },
        );
        // Both fds are closed by their drops (and on unwind, if the
        // closure above panicked).
        drop((fd3, fd4));
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
                    obtain_listener(&test_wayland_socket_activation())
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
