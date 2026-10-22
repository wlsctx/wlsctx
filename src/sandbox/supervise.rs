//! The supervisor and the notify-listener handoff (PLAN.md Phase 4,
//! decisions #22–#25).
//!
//! B (the app) installs the *combined* seccomp-notify filter plus the
//! Landlock floor ([`crate::sandbox::policy::apply`]), which yields a
//! single notify-listener fd. That fd must be serviced by S (the
//! supervisor, `wlsctx` itself) so B's trapped syscalls get a verdict,
//! but the fd is born inside B and B's `sendmsg` is itself trapped —
//! so B can `SCM_RIGHTS` it to no one. The handoff therefore crosses
//! the two process boundaries without any send from B (#23):
//!
//! ```text
//! B  writes the listener's *fd number* to a pre-made B→A pipe.
//! A  (B's direct parent — the only process Yama `ptrace_scope=1`
//!    lets `pidfd_getfd` B) opens B by pidfd, `pidfd_getfd`s that
//!    number into its own fd table, and `SCM_RIGHTS`es it to S over a
//!    pre-made S↔A socketpair.
//! S  receives the listener and runs the supervisor loop.
//! ```
//!
//! The supervisor's role is *mediation and logging, never expansion*
//! (#25): for `openat`/`openat2` it resolves the path and confirms it
//! is inside the granted subtrees (the same `CapabilitySet` that built
//! the Landlock floor, so they cannot disagree), then either lets the
//! syscall run (Landlock re-asserts the floor) or answers `EACCES` and
//! logs it; for the socket syscalls it mediates AF_UNIX only — a
//! pathname socket must be one the capability set granted, and
//! abstract/unnamed sockets are denied; every non-UNIX address family
//! passes through (the network mode governs it). It never opens a path
//! on the app's behalf or injects an fd, so it can never widen what
//! the floor already allows.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use nono::capability::{CapabilitySet, UnixSocketOp};
use nono::sandbox::{
    classify_access_from_flags, continue_notif, read_msghdr_dest,
    read_mmsghdr_dests, read_notif_path, read_notif_sockaddr, read_open_how, recv_notif,
    resolve_notif_path, respond_notif_errno, validate_openat2_size, SeccompNotif,
    UnixSocketKind, SYS_BIND, SYS_CONNECT, SYS_OPENAT, SYS_OPENAT2, SYS_SENDMMSG, SYS_SENDMSG,
    SYS_SENDTO,
};

/// A seccomp-notify listener has exactly one reader at a time; the
/// supervisor's poll loop therefore wakes at most this often when the
/// app is idle, bounding how long the "stop" flag takes to be noticed
/// when the app dies.
const POLL_TIMEOUT_MS: i32 = 50;

// ---------------------------------------------------------------------
// Channel construction
// ---------------------------------------------------------------------

/// Create a pipe; returns `(read_end, write_end)`.
///
/// `O_CLOEXEC` is set so neither end can leak across an `exec` into
/// the app; B closes its write end explicitly before exec anyway.
pub(crate) fn create_pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    // SAFETY: `fds` is a valid 2-slot out array for pipe(2).
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io_err("pipe2"));
    }
    // SAFETY: pipe2(2) returned two valid fds we now own.
    let r = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let w = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((r, w))
}

/// Create a `AF_UNIX`/`SOCK_STREAM` socketpair; returns
/// `(end_a, end_b)`.
pub(crate) fn create_socketpair() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    // SAFETY: `fds` is a valid 2-slot out array for socketpair(2).
    if unsafe {
        libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr())
    } != 0
    {
        return Err(io_err("socketpair"));
    }
    // SAFETY: socketpair(2) returned two valid fds we now own.
    let a = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let b = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((a, b))
}

/// Leak an `OwnedFd`, returning its raw number. The raw fd stays open in
/// every forked copy until a branch closes it explicitly; `forget`ing
/// the wrapper means no later drop (on either side of a fork) can close
/// a shared end.
pub(crate) fn leak(fd: OwnedFd) -> RawFd {
    let raw = fd.as_raw_fd();
    std::mem::forget(fd);
    raw
}

// ---------------------------------------------------------------------
// The fd-number pipe (B → A)
// ---------------------------------------------------------------------

/// Write `fdnum` to the pipe as a little-endian `i32`.
///
/// B calls this with the notify listener's fd number.
pub(crate) fn write_fdnum(w: RawFd, fdnum: i32) -> Result<()> {
    let buf = fdnum.to_le_bytes();
    // SAFETY: a single write(2) of a 4-byte stack buffer; a partial
    // write of 4 bytes from an in-memory buffer cannot occur on a
    // pipe (writes are at most the buffer size, and 4 < PIPE_BUF).
    let n = unsafe { libc::write(w, buf.as_ptr().cast(), buf.len()) };
    if n as usize != buf.len() {
        return Err(io_err("writing the fd number to the B→A pipe"));
    }
    Ok(())
}

/// Read one `i32` fd number from the pipe.
///
/// Returns `None` on EOF (the writer closed without sending — B died
/// before the handoff) so the caller can fall back to a plain wait.
pub(crate) fn read_fdnum(r: RawFd) -> Result<Option<i32>> {
    let mut buf = [0u8; 4];
    // SAFETY: read(2) into a valid 4-byte stack buffer, in a loop to
    // absorb short reads; `n == 0` is EOF.
    let mut got = 0;
    while got < buf.len() {
        let n = unsafe { libc::read(r, buf[got..].as_mut_ptr().cast(), buf.len() - got) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e.into());
        }
        if n == 0 {
            return Ok(None);
        }
        got += n as usize;
    }
    Ok(Some(i32::from_le_bytes(buf)))
}

// ---------------------------------------------------------------------
// The handoff verdict (A → B)
// ---------------------------------------------------------------------

/// A: send B the handoff verdict — `1` = the listener is in S's hands
/// (B may exec) or `0` = the handoff failed (B must not exec).
pub(crate) fn send_ack(w: RawFd, ack: u8) -> Result<()> {
    // SAFETY: a single 1-byte write(2) from a stack value; a partial
    // write of one byte cannot occur on a pipe.
    let n = unsafe { libc::write(w, &ack as *const u8 as *const libc::c_void, 1) };
    if n as usize != 1 {
        return Err(io_err("writing the handoff verdict to B"));
    }
    Ok(())
}

/// B: block (up to `timeout_ms`) for A's handoff verdict.
///
/// The verdict must be deterministic (decision #26): the listener is
/// `O_CLOEXEC` in B's table, and `pidfd_getfd` on B succeeds only
/// while B is the still-dumpable *pre-exec* process, so B may not
/// start its exec until A has extracted the listener and handed it to
/// S.
pub(crate) fn wait_ack(r: RawFd, timeout_ms: i32) -> Result<u8> {
    let mut pfd = libc::pollfd {
        fd: r,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: a single pollfd we own; the timeout bounds each call.
        let n = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e.into());
        }
        if n == 0 {
            return Err(anyhow!("timed out waiting for the handoff verdict"));
        }
        if pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) == 0 {
            continue;
        }
        let mut b = 0u8;
        // SAFETY: read(2) into a valid 1-byte stack buffer.
        let n = unsafe { libc::read(r, &mut b as *mut u8 as *mut libc::c_void, 1) };
        if n == 1 {
            return Ok(b);
        }
        if n == 0 {
            return Err(anyhow!("the verdict pipe closed before a verdict arrived"));
        }
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e.into());
        }
    }
}

// ---------------------------------------------------------------------
// SCM_RIGHTS over the S↔A socketpair (A → S)
// ---------------------------------------------------------------------

/// Send `fd` to the peer of `sock` as an out-of-band `SCM_RIGHTS`
/// message (with one byte of payload, as the kernel requires a
/// non-empty `msg_iov`).
pub(crate) fn send_fd(sock: RawFd, fd: RawFd) -> Result<()> {
    let payload = *b"F";
    let mut iov = libc::iovec {
        iov_base: &payload as *const u8 as *mut libc::c_void,
        iov_len: 1,
    };
    let space = unsafe { libc::CMSG_SPACE(4) } as libc::socklen_t;
    let mut control = vec![0u8; space as usize];
    let msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr() as *mut libc::c_void,
        msg_controllen: space as usize,
        msg_flags: 0,
    };
    // SAFETY: the msghdr/iovec/control buffer are all valid and
    // properly sized; CMSG_FIRSTHDR is valid because
    // msg_controllen >= CMSG_SPACE(4).
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(anyhow!("no control-message space for SCM_RIGHTS"));
    }
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(4) as usize;
        // The fd travels as a 4-byte integer in the control data.
        let data = libc::CMSG_DATA(cmsg) as *mut i32;
        std::ptr::write(data, fd);
        let n = libc::sendmsg(sock, &msg, 0);
        if n < 0 {
            return Err(io_err("sendmsg(SCM_RIGHTS) to the supervisor"));
        }
    }
    Ok(())
}

/// Receive one fd from the peer of `sock` via `SCM_RIGHTS`.
///
/// Returns `None` on EOF (the sender closed without sending — the
/// handoff did not happen) so the caller can skip the supervisor.
pub(crate) fn recv_fd(sock: RawFd) -> Result<Option<OwnedFd>> {
    let mut payload = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    let space = unsafe { libc::CMSG_SPACE(4) } as libc::socklen_t;
    let mut control = vec![0u8; space as usize];
    let mut msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr() as *mut libc::c_void,
        msg_controllen: space as usize,
        msg_flags: 0,
    };
    let n = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if n < 0 {
        return Err(io_err("recvmsg(SCM_RIGHTS) from the handoff child"));
    }
    if n == 0 {
        return Ok(None);
    }
    // SAFETY: a non-EOF recvmsg with control space present.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() || unsafe { (*cmsg).cmsg_type } != libc::SCM_RIGHTS {
        return Err(anyhow!("handoff message carried no SCM_RIGHTS descriptor"));
    }
    let fd = unsafe { *(libc::CMSG_DATA(cmsg) as *const i32) };
    // SAFETY: the kernel validated and duplicated the descriptor into a
    // new fd in our table; we now own it.
    Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }))
}

// ---------------------------------------------------------------------
// The A-side handoff: B's fd number -> A's own fd -> S
// ---------------------------------------------------------------------

/// Open `b_pid` by pidfd (a direct child of A, so Yama `restricted`
/// permits it) and copy the fd numbered `fdnum` from B's table into
/// ours, then `SCM_RIGHTS` that copy to `sock_to_s`.
///
/// Returns the extracted listener as an `OwnedFd` (A closes it after
/// the send; S's is the one that gets serviced).
pub(crate) fn extract_and_send(b_pid: i32, fdnum: i32, sock_to_s: RawFd) -> Result<OwnedFd> {
    let pidfd = pidfd_open(b_pid)?;
    let listener = pidfd_getfd(pidfd.as_raw_fd(), fdnum)?;
    send_fd(sock_to_s, listener.as_raw_fd())?;
    Ok(listener)
}

/// `pidfd_open(2)` via the raw syscall (the `libc` crate exposes the
/// number but no wrapper for this glibc target).
///
/// The explicit zero `flags` argument is **required**, not stylistic:
/// the kernel rejects any flags it does not know (`find_get_pid`
/// resolves the pid *globally*, so the caller's own pid namespace is
/// irrelevant — the host pid is correct from inside A's pidns), and
/// an uninitialised `rsi` from a one-argument `syscall(2)` call is
/// exactly how we get a spurious `EINVAL`.
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
        return Err(io_err(&format!("pidfd_open({pid})")));
    }
    // SAFETY: the syscall returned a valid fd we now own.
    Ok(unsafe { OwnedFd::from_raw_fd(r as i32) })
}

/// `pidfd_getfd(2)` via the raw syscall: duplicate `target_fd` from
/// the target process (reached by `pidfd`) into our own table.
///
/// Again the explicit zero `flags` is required: the kernel does
/// `if (flags) return -EINVAL`, so a garbage `rdx` fails the call.
fn pidfd_getfd(pidfd: RawFd, target_fd: i32) -> Result<OwnedFd> {
    // SAFETY: syscall(2) with valid pidfd/fd and zero flags; returns
    // a new fd or -1.
    let r = unsafe {
        libc::syscall(
            libc::SYS_pidfd_getfd as libc::c_long,
            pidfd as libc::c_long,
            target_fd as libc::c_long,
            0 as libc::c_long,
        )
    };
    if r < 0 {
        return Err(io_err(&format!("pidfd_getfd(fd {target_fd})")));
    }
    // SAFETY: the syscall returned a valid fd we now own.
    Ok(unsafe { OwnedFd::from_raw_fd(r as i32) })
}

// ---------------------------------------------------------------------
// The S-side supervisor loop
// ---------------------------------------------------------------------

/// Service the app's seccomp-notify listener until `stop` is set.
///
/// Runs on its own thread so the caller (S) can block in `waitpid`
/// for the app to die; when it does, the caller sets `stop` and joins
/// this thread. Each notification is dispatched by syscall number
/// ([`handle_notif`]); a notification for a dead/already-reaped app
/// is dropped.
pub(crate) fn supervisor(notify: OwnedFd, caps: CapabilitySet, stop: Arc<AtomicBool>) {
    let fd = notify.as_raw_fd();
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        // SAFETY: a single pollfd we own; the timeout bounds each call
        // so a dead app cannot block us past one tick.
        let n = unsafe { libc::poll(&mut pfd, 1, POLL_TIMEOUT_MS) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            log::warn!("supervisor: poll: {e}");
            break;
        }
        if n == 0 {
            continue; // timeout: re-check `stop`
        }
        if pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) == 0 {
            continue;
        }
        match recv_notif(fd) {
            Ok(notif) => {
                if let Err(e) = handle_notif(fd, &notif, &caps) {
                    log::warn!("supervisor: handling notification {}: {e:#}", notif.id);
                    // A failed verdict must not hang the app: fail
                    // closed with EPERM.
                    let _ = respond_notif_errno(fd, notif.id, libc::EPERM);
                }
            }
            Err(e) => {
                // The app (or a thread of it) died and its pending
                // notification was dropped; the fd stays open but
                // never becomes readable again. Stop servicing.
                log::debug!("supervisor: notification queue drained ({e}); stopping");
                break;
            }
        }
    }
}

/// Dispatch one notification by its syscall number and respond.
fn handle_notif(fd: RawFd, notif: &SeccompNotif, caps: &CapabilitySet) -> Result<()> {
    match notif.data.nr {
        SYS_OPENAT | SYS_OPENAT2 => handle_open(fd, notif, caps),
        SYS_CONNECT | SYS_BIND => handle_connect_bind(fd, notif, caps),
        SYS_SENDTO | SYS_SENDMSG | SYS_SENDMMSG => handle_send(fd, notif, caps),
        // The combined filter traps exactly the syscalls above; any
        // other number is a surprise (a kernel/BPF drift) — let it run
        // so the Landlock floor remains the last line of defence.
        other => {
            log::debug!("supervisor: untrapped syscall {other} (pid {}): continuing", notif.pid);
            continue_notif(fd, notif.id).map_err(anyhow::Error::from)
        }
    }
}

/// `openat`/`openat2`: resolve the target path, classify the access
/// mode, and confirm it lies inside a granted subtree.
fn handle_open(fd: RawFd, notif: &SeccompNotif, caps: &CapabilitySet) -> Result<()> {
    let pid = notif.pid;
    let dirfd = notif.data.args[0];
    let path_ptr = notif.data.args[1];

    let raw = read_notif_path(pid, path_ptr).with_context(|| {
        format!(
            "reading the open path from pid {pid} (notif {})",
            notif.id
        )
    })?;
    let resolved = resolve_notif_path(pid, dirfd, &raw)?;

    let access = if notif.data.nr == SYS_OPENAT2 {
        let size = notif.data.args[3] as usize;
        if !validate_openat2_size(size) {
            // A malformed openat2 — refuse to read a partial struct.
            log::info!(
                "supervisor: deny openat2 {resolved:?} (bad how size {size}): EACCES"
            );
            return respond_notif_errno(fd, notif.id, libc::EACCES).map_err(anyhow::Error::from);
        }
        let how = read_open_how(pid, notif.data.args[2])
            .with_context(|| format!("reading open_how from pid {pid}"))?;
        classify_access_from_flags(how.flags as i32)
    } else {
        classify_access_from_flags(notif.data.args[2] as i32)
    };

    if caps.path_covered_with_access(&resolved, access) {
        log::debug!("supervisor: allow {access} {resolved:?}");
        continue_notif(fd, notif.id).map_err(anyhow::Error::from)
    } else {
        log::info!(
            "supervisor: deny {access} {resolved:?} (not a granted subtree): EACCES"
        );
        respond_notif_errno(fd, notif.id, libc::EACCES).map_err(anyhow::Error::from)
    }
}

/// `connect`/`bind`: only AF_UNIX is mediated (by pathname, against
/// the granted socket list); non-UNIX families pass through.
fn handle_connect_bind(fd: RawFd, notif: &SeccompNotif, caps: &CapabilitySet) -> Result<()> {
    let pid = notif.pid;
    let addr_ptr = notif.data.args[1];
    let addrlen = notif.data.args[2];
    let op = if notif.data.nr == SYS_BIND {
        UnixSocketOp::Bind
    } else {
        UnixSocketOp::Connect
    };
    let op_name = if notif.data.nr == SYS_BIND { "bind" } else { "connect" };

    match read_notif_sockaddr(pid, addr_ptr, addrlen) {
        Ok(sa) => match sa.family as i32 {
            libc::AF_UNIX => {
                // Only a *pathname* AF_UNIX socket is mediatable;
                // abstract and unnamed are denied (#25).
                match (sa.unix_kind, sa.unix_path.as_ref()) {
                    (Some(UnixSocketKind::Pathname), Some(path)) => {
                        if caps.unix_socket_allowed(path, op) {
                            log::debug!("supervisor: allow {op_name} {path:?}");
                            continue_notif(fd, notif.id).map_err(anyhow::Error::from)
                        } else {
                            log::info!("supervisor: deny {op_name} {path:?} (not granted): EACCES");
                            respond_notif_errno(fd, notif.id, libc::EACCES).map_err(anyhow::Error::from)
                        }
                    }
                    (kind, _) => {
                        let k = kind
                            .map(|k| match k {
                                UnixSocketKind::Abstract => "abstract",
                                UnixSocketKind::Unnamed => "unnamed",
                                UnixSocketKind::Pathname => "pathname",
                            })
                            .unwrap_or("unclassified");
                        log::info!(
                            "supervisor: deny {op_name} (non-pathname {k} AF_UNIX): EACCES"
                        );
                        respond_notif_errno(fd, notif.id, libc::EACCES).map_err(anyhow::Error::from)
                    }
                }
            }
            // Non-UNIX (TCP/UDP/…): the network mode governs it — pass.
            family => {
                log::debug!("supervisor: pass {op_name} (af {family})");
                continue_notif(fd, notif.id).map_err(anyhow::Error::from)
            }
        },
        Err(e) => {
            // Fail closed: we could not even tell what it was.
            log::info!("supervisor: deny {op_name} (unreadable sockaddr: {e}): EACCES");
            respond_notif_errno(fd, notif.id, libc::EACCES).map_err(anyhow::Error::from)
        }
    }
}

/// `sendto`/`sendmsg`/`sendmmsg`: gather the destination address(es),
/// and for AF_UNIX require the target to be a granted pathname socket.
/// Non-UNIX or unnamed (connected) sends pass through.
fn handle_send(fd: RawFd, notif: &SeccompNotif, caps: &CapabilitySet) -> Result<()> {
    let pid = notif.pid;
    // One or more (name_ptr, namelen) pairs; a `None` entry means the
    // send carried no destination (a connected socket) and is fine.
    let dests: Vec<Option<(u64, u64)>> = match notif.data.nr {
        SYS_SENDTO => vec![Some((notif.data.args[3], notif.data.args[4]))],
        SYS_SENDMSG => vec![read_msghdr_dest(pid, notif.data.args[1]).unwrap_or(None)],
        SYS_SENDMMSG => read_mmsghdr_dests(pid, notif.data.args[1], notif.data.args[2])
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    let op_name = match notif.data.nr {
        SYS_SENDTO => "sendto",
        SYS_SENDMSG => "sendmsg",
        _ => "sendmmsg",
    };

    for dest in &dests {
        let Some((name_ptr, namelen)) = dest else {
            continue; // connected socket, no address to check
        };
        // A zero-length "address" is an unnamed socket — fine.
        if *namelen == 0 {
            continue;
        }
        match read_notif_sockaddr(pid, *name_ptr, *namelen) {
            Ok(sa) => match sa.family as i32 {
                libc::AF_UNIX => match (sa.unix_kind, sa.unix_path.as_ref()) {
                    (Some(UnixSocketKind::Pathname), Some(path)) => {
                        if !caps.unix_socket_allowed(path, UnixSocketOp::Send) {
                            log::info!(
                                "supervisor: deny {op_name} {path:?} (not granted): EACCES"
                            );
                            return respond_notif_errno(fd, notif.id, libc::EACCES).map_err(anyhow::Error::from);
                        }
                    }
                    _ => {
                        // Non-pathname AF_UNIX send: denied (#25).
                        log::info!(
                            "supervisor: deny {op_name} (non-pathname AF_UNIX): EACCES"
                        );
                        return respond_notif_errno(fd, notif.id, libc::EACCES).map_err(anyhow::Error::from);
                    }
                },
                // Non-UNIX send: pass (network mode governs it).
                _ => {}
            },
            Err(e) => {
                // We cannot even read the address: fail closed.
                log::info!("supervisor: deny {op_name} (unreadable sockaddr: {e}): EACCES");
                return respond_notif_errno(fd, notif.id, libc::EACCES).map_err(anyhow::Error::from);
            }
        }
    }
    log::debug!("supervisor: pass {op_name}");
    continue_notif(fd, notif.id).map_err(anyhow::Error::from)
}

/// `io::Error::last_os_error` wrapped as `anyhow`, with a label.
fn io_err(what: &str) -> anyhow::Error {
    let e = std::io::Error::last_os_error();
    anyhow!(format!("{what}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::mounts;
    use crate::sandbox::namespaces::NetworkMode;
    use crate::sandbox::userns::tests::{run_in_child, ChildOut};
    use crate::sandbox::{run_sandboxed, SandboxConfig};
    use std::ffi::OsString;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    /// A minimal `log` sink on stderr (first test to run installs it;
    /// `set_logger` is once-per-process, the rest no-op). Makes the
    /// supervisor's verdicts visible with `--nocapture`.
    struct ErrLog;
    impl log::Log for ErrLog {
        fn enabled(&self, _m: &log::Metadata) -> bool {
            true
        }
        fn log(&self, r: &log::Record) {
            let _ = writeln!(std::io::stderr(), "[{}] {} {}", r.level(), r.target(), r.args());
        }
        fn flush(&self) {}
    }
    static TEST_LOGGER: ErrLog = ErrLog;

    fn install_test_logger() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = log::set_logger(&TEST_LOGGER);
            log::set_max_level(log::LevelFilter::Debug);
        });
    }

    fn cfg(app: &str, inst: &str, net: NetworkMode) -> SandboxConfig {
        SandboxConfig {
            app_id: app.to_string(),
            instance_id: inst.to_string(),
            network: net,
            gpu: false,
            profile: crate::profile::Profile::adhoc(),
        }
    }

    /// Run a command through `run_sandboxed` from inside a forked
    /// capture child (the multithreaded test process itself never
    /// enters a namespace).
    fn run_cmd(command: &[String], config: &SandboxConfig) -> (Option<i32>, String, String) {
        install_test_logger();
        let _lock = crate::testutil::SANDBOX_LOCK
            .lock()
            .unwrap_or_else(|e| panic!("SANDBOX_LOCK poisoned: {e}"));
        let command: Vec<OsString> = command.iter().map(OsString::from).collect();
        let config = config.clone();
        run_in_child(move |o: &mut ChildOut| match run_sandboxed(&command, &config) {
            Ok(code) => code,
            Err(e) => {
                let _ = writeln!(o.err(), "run_sandboxed: {e:#}");
                2
            }
        })
    }

    /// True when the failure is "the environment cannot create the
    /// namespaces" (the test must `return`); panics when the kernel
    /// rejected our map (a design failure, never a skip).
    fn skip_if_unsupported(err: &str) -> bool {
        if err.contains("uid_map") || err.contains("gid_map") {
            panic!(
                "the kernel rejected the single-extent map (design failure, not an environment skip):\n{err}"
            );
        }
        if err.contains("rootfs construction failed") || err.contains("sandbox setup failed") {
            panic!("a setup step failed inside the namespaces (a real failure, not an environment skip):\n{err}");
        }
        eprintln!("skipping (environment cannot create the namespaces):\n{err}");
        true
    }

    /// Classify a `run_cmd` result for a command that must exit 0;
    /// `Ok` = it did, `Err` = environment skip (return from the test).
    fn expect_ok(code: Option<i32>, out: &str, err: &str, what: &str) -> Result<(), ()> {
        match code {
            Some(0) => Ok(()),
            Some(126) => {
                if skip_if_unsupported(err) {
                    Err(())
                } else {
                    panic!("{what} failed (exit 126):\n{out}\n{err}")
                }
            }
            Some(other) => panic!("{what} failed (exit {other}, expected 0):\n{out}\n{err}"),
            None => panic!("test harness failed"),
        }
    }

    /// The instance dir is bind-mounted into the sandbox's fresh `/run`
    /// at `/run/user/<uid>/wlsctx/<inst>`. The capability set grants it
    /// by its *host* path (`$XDG_RUNTIME_DIR/wlsctx/<inst>`), so the two
    /// strings agree only when XDG is the systemd default (a divergent
    /// XDG dir is the path-translation problem of Phase 5).
    fn xdg_runtime_matches_run_user() -> bool {
        match std::env::var("XDG_RUNTIME_DIR") {
            Ok(x) => x == format!("/run/user/{}", nix::unistd::getuid().as_raw()),
            Err(_) => true, // instance_runtime_dir defaults to /run/user/<uid>
        }
    }

    /// A write outside every granted subtree is denied by the sandbox
    /// itself (DAC alone would allow it), while a write into the
    /// granted instance subtree succeeds and lands on the host through
    /// the bind mount.
    #[test]
    fn openat_write_denied_outside_granted_subtrees() {
        let uid = nix::unistd::getuid().as_raw();
        let config = cfg("app", "1", NetworkMode::Shared);
        let inst = mounts::instance_runtime_dir(&config);
        let denied = format!("/run/user/{uid}/wlsctx-p4-deny-file");
        let ctrl = format!("{inst}/p4-ctrl");
        let script = format!(
            "echo x > {denied} 2>/dev/null; a=$?; echo ctrl > {ctrl} 2>/dev/null; b=$?; echo a=$a b=$b"
        );
        let (code, out, err) =
            run_cmd(&["/bin/sh".into(), "-c".into(), script], &config);
        if expect_ok(code, &out, &err, "openat write probe").is_err() {
            return;
        }
        // The fresh /run dir is ours (DAC allows both writes); only
        // the instance subtree is granted — so exactly one may pass.
        assert!(
            out.contains("a=1"),
            "the write outside the granted subtrees must be denied (EACCES), got:\n{out}\n{err}"
        );
        assert!(
            out.contains("b=0"),
            "the write into the instance dir must be allowed, got:\n{out}\n{err}"
        );
        // The allowed write crossed the bind mount to the host.
        let host_ctrl = std::fs::read_to_string(&ctrl)
            .unwrap_or_else(|e| panic!("reading the host-side copy of {ctrl:?}: {e}"));
        assert_eq!(host_ctrl.trim(), "ctrl", "got {host_ctrl:?}");
        // The denied write never materialized.
        assert!(
            !std::path::Path::new(&denied).exists(),
            "the denied write must not have created {denied}"
        );
    }

    /// A read of a base-granted path goes through the openat
    /// notification and is allowed — the app sees the host's file.
    ///
    /// The probe is `/etc/os-release` (granted via the base `/etc`
    /// read grant), not `/etc/hostname`: the latter is a bare newline
    /// on this host, which would make any content assertion vacuous.
    #[test]
    fn openat_read_of_granted_path_is_allowed() {
        let (code, out, err) = run_cmd(
            &["/bin/sh".into(), "-c".into(), "cat /etc/os-release".into()],
            &cfg("app", "4", NetworkMode::Shared),
        );
        if expect_ok(code, &out, &err, "openat read probe").is_err() {
            return;
        }
        let host = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
        assert!(
            !host.trim().is_empty(),
            "the probe file is empty on the host; the test itself is broken"
        );
        assert_eq!(
            out.trim(),
            host.trim(),
            "the sandbox must read the host's /etc/os-release verbatim:\n{out}\n--- host ---\n{host}\n{err}"
        );
    }

    /// `connect(2)` to an AF_UNIX socket that the path grants cover
    /// but the socket grants do not (a listener in `$HOME`) is denied
    /// by the supervisor with EACCES.
    #[test]
    fn connect_to_ungranted_unix_socket_is_denied() {
        let home = std::env::home_dir().expect("the test needs $HOME");
        let sock = home.join(".wlsctx-p4-deny.sock");
        let _ = std::fs::remove_file(&sock);
        let _listener = UnixListener::bind(&sock)
            .unwrap_or_else(|e| panic!("binding {sock:?}: {e}"));
        let script = format!(
            "import socket; s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); \
             s.connect({:?}); print('CONNECTED')",
            sock.to_str().unwrap()
        );
        let (code, out, err) = run_cmd(
            &["/usr/bin/python3".into(), "-c".into(), script],
            &cfg("app", "2", NetworkMode::Shared),
        );
        let _ = std::fs::remove_file(&sock);
        match code {
            Some(0) => panic!("connect to an ungranted socket was allowed:\n{out}\n{err}"),
            Some(126) => {
                if skip_if_unsupported(&err) {
                    return;
                }
                panic!("sandbox setup failed:\n{out}\n{err}")
            }
            Some(_) => {} // denied: the expected non-zero exit
            None => panic!("test harness failed"),
        }
        assert!(
            out.contains("PermissionError")
                || out.contains("Permission denied")
                || err.contains("PermissionError")
                || err.contains("Permission denied"),
            "the denial must be EACCES from the supervisor, got:\n{out}\n{err}"
        );
        assert!(!out.contains("CONNECTED"), "got:\n{out}");
    }

    /// The tagged-socket flow: `connect(2)` to a socket inside the
    /// granted instance subtree is mediated *allow* — the connection
    /// reaches the host-side listener and the payload crosses.
    #[test]
    fn connect_to_instance_dir_socket_is_allowed() {
        if !xdg_runtime_matches_run_user() {
            eprintln!(
                "skipping: XDG_RUNTIME_DIR differs from /run/user/<uid>; \
                 instance-dir path translation is Phase 5"
            );
            return;
        }
        let config = cfg("app", "3", NetworkMode::Shared);
        let inst = mounts::instance_runtime_dir(&config);
        std::fs::create_dir_all(&inst)
            .unwrap_or_else(|e| panic!("creating {inst:?}: {e}"));
        let sock = format!("{inst}/wayland-0");
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock)
            .unwrap_or_else(|e| panic!("binding {sock:?}: {e}"));
        let script = format!(
            "import socket; s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); \
             s.connect({sock:?}); s.sendall(b'P4-OK'); print('CONNECTED')"
        );
        let (code, out, err) = run_cmd(
            &["/usr/bin/python3".into(), "-c".into(), script],
            &config,
        );
        let _ = std::fs::remove_file(&sock);
        if expect_ok(code, &out, &err, "instance-dir connect").is_err() {
            return;
        }
        assert!(out.contains("CONNECTED"), "the app side:\n{out}\n{err}");
        // We (S, the listener's owner) must be able to accept the
        // connection the supervisor let through, and read the payload.
        let fd = listener.as_raw_fd();
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `fd` is a valid fd of this process.
        let rc = unsafe { libc::poll(&mut pfd, 1, 2000) };
        assert_eq!(
            rc,
            1,
            "no pending connection after the app's connect: the supervisor did not mediate an allow"
        );
        let (mut conn, _) = listener.accept().expect("accepting the app's connection");
        let mut buf = [0u8; 5];
        conn.read_exact(&mut buf)
            .expect("reading the app's payload over the mediated connection");
        assert_eq!(&buf, b"P4-OK", "the payload must cross the sandbox boundary");
    }
}
