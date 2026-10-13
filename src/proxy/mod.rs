//! The transparent Wayland proxy (`--proxy`).
//!
//! ## Topology
//!
//! The proxy runs two listening sockets:
//!
//! * **public** (`--listen`): the socket the sandboxed app actually
//!   connects to (`WAYLAND_DISPLAY`). It carries *no* security context;
//!   only the proxy accepts on it.
//! * **tagged** (`--tagged-socket`): bound by the proxy and passed to
//!   the compositor via `wp_security_context_manager_v1.create_listener()`
//!   (see [`crate::security_context`]). The proxy never accepts on it.
//!   For every app connection it opens a fresh connection to that path,
//!   and the compositor — which holds the listener — accepts the other
//!   end and stamps it with the security context
//!   (sandbox_engine/app_id/instance_id).
//!
//! The relay between the two ends of each app connection is a raw,
//! bidirectional pass-through of the Wayland protocol: object IDs pass
//! through unchanged (the proxy never allocates any) and fd arguments
//! are forwarded out-of-band (SCM_RIGHTS) in signature order. Each relay
//! keeps per-connection object bookkeeping ([`objects::ObjectTables`])
//! so it can parse every message — the foundation for the interception
//! phases (global allowlist, clipboard gating, …).
//!
//! The relay is convention-agnostic: it does not assume which object-ID
//! convention the peers use (C libwayland: display at ID 0; Rust
//! wayland-backend: ID 1). Each connection's first message is always
//! addressed to the display, which pins the convention for that
//! connection; two ends that disagree fail closed (see [`objects`]).
//!
//! ## Fail-closed
//!
//! Every error path drops both ends of the affected connection (the
//! `OwnedFd`s are dropped, the peers see a clean EOF): a parse error, a
//! protocol violation the bookkeeping detects (message on an unknown
//! object, ID-range violation, reuse of a live ID, bind of an interface
//! the proxy cannot parse), a partial send, or any I/O error. A clean
//! EOF (the app quit, or the compositor closed the tagged connection)
//! ends the relay the same way — that is the normal teardown.
//!
//! One OS thread per app connection; the main thread runs the accept
//! loop on a signalfd (production) or a stop flag (tests).

pub mod interfaces;
pub mod objects;
pub mod wire;

/// `wayland-scanner` tables for the vendored wlroots protocol XMLs
/// (`protocols/`); only the crate-internal `__interfaces` module is
/// consumed (by [`interfaces`]).
mod wlr_tables;

use std::collections::VecDeque;
use std::fs;
use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixStream, UnixListener};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use log::{debug, info, warn};
use nix::sys::signal::{Signal, Signal::*, SigSet};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use rustix::event::{poll, Timespec, PollFd, PollFlags};
use rustix::io::Errno;
use rustix::net::{
    recvmsg, send, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
};
use wayland_backend::protocol::{Argument, ArgumentType, Interface, MessageDesc};

use self::objects::{BookkeepingError, Dir, ObjectTables};

/// Max number of fds accepted in a single `recvmsg` (a Wayland message
/// carries a handful; 28 matches wayland-backend's socket).
const MAX_FDS: usize = 28;
/// Receive chunk size. Wayland messages may in principle be arbitrarily
/// large (str/array arguments); the per-direction reassembly buffer
/// handles whatever exceeds a chunk.
const READ_SIZE: usize = 4096;

// ------------------------------------------------------------------------
// Socket I/O
// ------------------------------------------------------------------------

/// A connected Wayland socket with fd-passing I/O.
///
/// The proxy belongs to neither protocol side, so it cannot use
/// wayland-backend's client or server `Socket`; this mirrors the calls
/// wayland-backend's `rs/socket.rs` makes (`rustix` there, `nix` here)
/// on top of the standalone codec in [`crate::proxy::wire`].
struct ProxySocket {
    fd: OwnedFd,
}

impl ProxySocket {
    fn new(stream: UnixStream) -> Self {
        // `OwnedFd::from_raw_fd` is a `FromRawFd` trait method in this
        // toolchain; `UnixStream` exposes its fd via `IntoRawFd`.
        let raw = stream.into_raw_fd();
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // Protocol sockets must not leak into child processes.
        let _ = rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC);
        Self { fd }
    }

    /// Send one complete Wayland message.
    ///
    /// Returns the number of bytes written; the caller must treat
    /// `n < bytes.len()` as fatal (a partial send cannot be retried: if
    /// the message carried fds, those were already handed to the
    /// kernel's send buffer, and re-sending them would deliver them
    /// twice). In practice a partial send cannot occur: one message is
    /// at most 4 KiB, far below the (200 KiB-class) socket buffers of a
    /// Unix stream pair whose peer is our own poll-driven loop.
    fn send(&self, bytes: &[u8], fds: &[OwnedFd]) -> io::Result<usize> {
        let flags = SendFlags::DONTWAIT | SendFlags::NOSIGNAL;
        if fds.is_empty() {
            return send(self.fd.as_fd(), bytes, flags).map_err(Into::into);
        }
        let iov = [IoSlice::new(bytes)];
        let mut cmsg_space =
            vec![MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(fds.len()))];
        let mut cmsg_buffer = SendAncillaryBuffer::new(&mut cmsg_space);
        let borrowed: Vec<BorrowedFd> = fds.iter().map(|f| f.as_fd()).collect();
        cmsg_buffer.push(SendAncillaryMessage::ScmRights(&borrowed));
        // `send`/`sendmsg` return a rustix `Errno`, not `io::Error`; convert.
        sendmsg(self.fd.as_fd(), &iov, &mut cmsg_buffer, flags).map_err(Into::into)
    }

    /// Read up to one chunk of the stream into `buf`, delivering any
    /// out-of-band fds (SCM_RIGHTS) to `fds`, in the order they arrive.
    ///
    /// Returns 0 on clean EOF.
    fn recv(&self, buf: &mut [u8], fds: &mut VecDeque<OwnedFd>) -> io::Result<usize> {
        let flags = RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC;
        let mut cmsg_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS))];
        let mut cmsg_buffer = RecvAncillaryBuffer::new(&mut cmsg_space);
        let mut iov = [IoSliceMut::new(buf)];
        let msg = recvmsg(self.fd.as_fd(), &mut iov, &mut cmsg_buffer, flags)?;
        for cmsg in cmsg_buffer.drain() {
            if let RecvAncillaryMessage::ScmRights(iter) = cmsg {
                // `CMSG_CLOEXEC` fds arrive exactly once and are exclusively
                // ours from here on; rustix hands them back as `OwnedFd`.
                fds.extend(iter);
            }
        }
        Ok(msg.bytes)
    }
}

// ------------------------------------------------------------------------
// Relay
// ------------------------------------------------------------------------

/// How a relay ends. Everything here results in both ends being
/// dropped (a clean EOF is the ordinary end of a connection; the rest
/// are fail-closed).
#[derive(Debug)]
pub enum RelayEnd {
    /// The peer closed the connection cleanly (the app quit, or the
    /// compositor closed the tagged connection).
    Eof,
    /// An I/O error on either end.
    Io(io::Error),
    /// A protocol violation (parse/bookkeeping failure, partial send).
    Protocol(String),
}

/// One app connection and its tagged upstream, relayed bidirectionally
/// on the calling thread.
struct Relay {
    /// The app end: a plain connection accepted on the public socket.
    down: ProxySocket,
    /// The compositor end: a connection to the tagged listener, stamped
    /// with the security context.
    up: ProxySocket,
    /// Bytes from each peer, not yet part of a complete message.
    down_buf: Vec<u8>,
    up_buf: Vec<u8>,
    /// Fds received from each peer, in message order, not yet consumed
    /// by a parsed message.
    down_fds: VecDeque<OwnedFd>,
    up_fds: VecDeque<OwnedFd>,
    tables: ObjectTables,
}

impl Relay {
    fn new(down: UnixStream, up: UnixStream) -> Self {
        Self {
            down: ProxySocket::new(down),
            up: ProxySocket::new(up),
            down_buf: Vec::with_capacity(READ_SIZE),
            up_buf: Vec::with_capacity(READ_SIZE),
            down_fds: VecDeque::new(),
            up_fds: VecDeque::new(),
            tables: ObjectTables::new(),
        }
    }

    /// Run until the relay ends; the caller drops both sockets.
    fn run(&mut self) -> RelayEnd {
        loop {
            let mut polls = [
                PollFd::new(&self.down.fd, PollFlags::IN),
                PollFd::new(&self.up.fd, PollFlags::IN),
            ];
            match poll(&mut polls, None) {
                Ok(0) => continue,
                Ok(_) => {}
                // EINTR cannot happen here: this thread has the
                // signalfd-bound mask blocked (see [`spawn_relay`]).
                Err(Errno::INTR) => continue,
                Err(e) => return RelayEnd::Io(e.into()),
            }
            let client_ready = polls[0]
                .revents()
                .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR);
            let server_ready = polls[1]
                .revents()
                .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR);
            // `polls` (which borrows both fds) is dead here, so the
            // mutable `pump` borrows below no longer conflict.
            // (Not collapsible: `pump` has side effects and must not
            // run when the corresponding side is not ready.)
            #[allow(clippy::collapsible_if)]
            if client_ready {
                if let Err(end) = self.pump(Dir::ClientToServer) {
                    return end;
                }
            }
            #[allow(clippy::collapsible_if)]
            if server_ready {
                if let Err(end) = self.pump(Dir::ServerToClient) {
                    return end;
                }
            }
        }
    }

    /// Read one chunk from the given direction and relay every complete
    /// message it yields to the other side.
    fn pump(&mut self, dir: Dir) -> Result<(), RelayEnd> {
        let (sock, reassembled, fds, dst) = match dir {
            Dir::ClientToServer => (&self.down, &mut self.down_buf, &mut self.down_fds, &self.up),
            Dir::ServerToClient => (&self.up, &mut self.up_buf, &mut self.up_fds, &self.down),
        };
        let mut chunk = [0u8; READ_SIZE];
        let n = sock.recv(&mut chunk, fds).map_err(RelayEnd::Io)?;
        if n == 0 {
            return Err(RelayEnd::Eof);
        }
        reassembled.extend_from_slice(&chunk[..n]);
        loop {
            let len = match wire::message_len(reassembled) {
                Some(len) => len,
                None => return Ok(()),
            };
            let raw = &reassembled[..len];
            Self::forward(&mut self.tables, dir, raw, fds, dst)?;
            reassembled.drain(..len);
        }
    }

    /// Parse, validate and bookkeep one complete message, then relay
    /// its original bytes (with its fds) to the other side.
    fn forward(
        tables: &mut ObjectTables,
        dir: Dir,
        raw: &[u8],
        src_fds: &mut VecDeque<OwnedFd>,
        dst: &ProxySocket,
    ) -> Result<(), RelayEnd> {
        if raw.len() < wire::HEADER_SIZE {
            return Err(RelayEnd::Protocol("message shorter than a header".into()));
        }
        let sender_id = u32::from_le_bytes(raw[0..4].try_into().unwrap());
        let word2 = u32::from_le_bytes(raw[4..8].try_into().unwrap());
        let opcode = (word2 & 0xFFFF) as u16;

        let sender = tables
            .sender_interface(sender_id)
            .map_err(|e: BookkeepingError| RelayEnd::Protocol(e.to_string()))?;
        let desc = match_desc(dir, sender, opcode)?;

        // The parse validates the message against the signature and
        // consumes the fds that belong to it (in order).
        let n_fds = desc
            .signature
            .iter()
            .filter(|t| matches!(t, ArgumentType::Fd))
            .count();
        let take = src_fds.len().min(n_fds);
        let mut scratch = src_fds.split_off(src_fds.len() - take);
        let (msg, rest) = wire::parse_message(raw, desc.signature, &mut scratch)
            .map_err(|e| RelayEnd::Protocol(e.to_string()))?;
        if !rest.is_empty() {
            // The message carries more data than its signature
            // declares: the sender is lying about its protocol.
            return Err(RelayEnd::Protocol(format!(
                "request/event '{}' on {} is longer than its signature",
                desc.name, sender.name
            )));
        }
        tables
            .apply(dir, &msg, desc, sender)
            .map_err(|e| RelayEnd::Protocol(e.to_string()))?;

        // Forward the original bytes with the fds the parse consumed.
        let mut out_fds = Vec::with_capacity(msg.args.len());
        for a in &msg.args {
            if let Argument::Fd(f) = a {
                out_fds.push(f.try_clone().map_err(RelayEnd::Io)?);
            }
        }
        let n = dst.send(raw, &out_fds).map_err(RelayEnd::Io)?;
        if n != raw.len() {
            return Err(RelayEnd::Protocol(format!(
                "partial send of '{}' ({} of {} bytes)",
                desc.name,
                n,
                raw.len()
            )));
        }
        Ok(())
    }
}

/// Resolve the request/event descriptor an opcode names on `sender`,
/// given the direction of travel. Requests and events live in separate
/// opcode spaces per direction: the on-wire opcode is the raw index
/// into the interface's `requests` array (client → server) or `events`
/// array (server → client) — the convention both C libwayland and Rust
/// wayland-backend use (verified against the scanner codegen and the
/// backend's `send_delete_id`, which writes event index 1 for
/// `wl_display.delete_id`).
fn match_desc(dir: Dir, sender: &Interface, opcode: u16) -> Result<&'static MessageDesc, RelayEnd> {
    let desc = match dir {
        Dir::ClientToServer => sender.requests.get(opcode as usize),
        Dir::ServerToClient => sender.events.get(opcode as usize),
    };
    let what = if dir == Dir::ClientToServer { "request" } else { "event" };
    desc.ok_or_else(|| {
        RelayEnd::Protocol(format!(
            "unknown {what} opcode {opcode} for interface {}",
            sender.name
        ))
    })
}

// ------------------------------------------------------------------------
// Accept loop
// ------------------------------------------------------------------------

/// Bind a listening Wayland socket at `path`, removing a stale socket
/// file first. The socket file is chmod'ed to 0600 (the default bind
/// mode is `0777 & !umask`).
pub fn bind_listener(path: &Path) -> io::Result<UnixListener> {
    match fs::metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            debug!("Removing stale socket {path:?}");
            let _ = fs::remove_file(path);
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("{path:?} already exists and is not a socket"),
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    let _ = listener.set_nonblocking(true);
    Ok(listener)
}

/// Connect a fresh Wayland client to `tagged_path` and spawn the relay
/// thread for one app connection.
///
/// The tagged connection is the one the compositor stamps with the
/// security context; the app's own connection (on the public socket)
/// carries none.
fn spawn_relay(app: UnixStream, tagged_path: &Path) -> io::Result<()> {
    let up = UnixStream::connect(tagged_path).map_err(|e| {
        io::Error::other(format!(
            "connecting to the tagged socket {tagged_path:?} failed: {e}"
        ))
    })?;
    std::thread::Builder::new()
        .name("wlsctx-relay".into())
        .spawn(move || {
            // Block the signalfd-bound mask so SIGTERM/SIGINT/SIGHUP
            // reach the main thread's signalfd, not this thread.
            let _ = proxy_signal_mask().thread_block();
            let mut relay = Relay::new(app, up);
            let end = relay.run();
            match &end {
                RelayEnd::Eof => debug!("relay closed: peer disconnected"),
                RelayEnd::Io(e) => warn!("relay dropped: I/O error: {e}"),
                RelayEnd::Protocol(p) => warn!("relay dropped: {p}"),
            }
            // Both ends are closed here (the OwnedFds drop).
        })
        .map_err(|e| io::Error::other(format!("spawning the relay thread failed: {e}")))?;
    Ok(())
}

/// The proxy event loop: accept app connections on `public`, spawn a
/// relay per connection (each upstream-connects to `tagged_path`).
///
/// If `stop` is `None` the loop is the process's signal handler: the
/// signalfd-bound mask is blocked on this thread and SIGTERM/SIGINT
/// make it return `Ok` (SIGHUP exits with status 129, like
/// [`run_signal_loop`]). If `stop` is `Some`, no signals are handled:
/// the loop polls with a 200 ms timeout and returns as soon as the flag
/// is set (the test hook).
pub fn event_loop(
    public: &UnixListener,
    tagged_path: &Path,
    stop: Option<Arc<AtomicBool>>,
) -> io::Result<()> {
    let sigfd = match stop {
        None => Some(setup_signalfd()?),
        Some(_) => None,
    };
    // The stop flag is polled on a 200 ms timeout tick; in
    // production (infinite) the signalfd/listener give the wakeups.
    let tick = Timespec {
        tv_sec: 0,
        tv_nsec: 200_000_000,
    };
    let timeout: Option<&Timespec> = stop.as_ref().map(|_| &tick);
    loop {
        let mut polls: Vec<PollFd> = Vec::with_capacity(2);
        if let Some(sf) = &sigfd {
            polls.push(PollFd::new(sf, PollFlags::IN));
        }
        polls.push(PollFd::new(public, PollFlags::IN));
        match poll(&mut polls, timeout) {
            Ok(_) => {}
            Err(Errno::INTR) => continue,
            Err(e) => return Err(e.into()),
        }
        for (idx, pf) in polls.iter().enumerate() {
            if !pf.revents().intersects(PollFlags::IN) {
                continue;
            }
            // Index 0 is the signalfd when present; the last entry is
            // always the public listener.
            if let Some(sf) = sigfd.as_ref().filter(|_| idx == 0) {
                if handle_signal(sf)? {
                    return Ok(());
                }
            } else {
                match public.accept() {
                    Ok((stream, _)) => {
                        if let Err(e) = spawn_relay(stream, tagged_path) {
                            warn!("dropping app connection: {e}");
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
            }
        }
        // Test hook: the stop flag is checked on every 200 ms tick.
        let stopped = stop
            .as_ref()
            .is_some_and(|s| s.load(Ordering::SeqCst));
        if stopped {
            return Ok(());
        }
    }
}

// ------------------------------------------------------------------------
// Signals
// ------------------------------------------------------------------------

/// The signal mask this process blocks: everything except the
/// kernel-generated fatal signals (the catatonit trick — we want
/// synchronous, signalfd-mediated handling of every other signal).
fn proxy_signal_mask() -> SigSet {
    SigSet::all()
        .iter()
        .filter(|sig| {
            !(SIGFPE | SIGILL | SIGSEGV | SIGBUS | SIGABRT | SIGTRAP | SIGSYS).contains(*sig)
        })
        .collect()
}

/// Block the proxy signal mask on the calling thread and create the
/// signalfd that receives it.
fn setup_signalfd() -> io::Result<SignalFd> {
    let mask = proxy_signal_mask();
    mask.thread_block().map_err(io::Error::other)?;
    SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC).map_err(io::Error::other)
}

/// Read one signal from the signalfd and act on it.
///
/// Returns `true` when the process should exit (SIGTERM/SIGINT).
/// SIGHUP exits with status 129 directly (no restart is implemented);
/// SIGCHLD reaps children; the rest is ignored.
fn handle_signal(sigfd: &SignalFd) -> io::Result<bool> {
    let siginfo = sigfd.read_signal().map_err(io::Error::other)?.ok_or_else(|| {
        io::Error::new(io::ErrorKind::BrokenPipe, "signalfd closed")
    })?;
    let signal = Signal::try_from(siginfo.ssi_signo as i32).map_err(|e| {
        io::Error::other(format!(
            "unknown signal number {}: {e}",
            siginfo.ssi_signo
        ))
    })?;
    debug!("Signal: {signal:?}");
    Ok(match signal {
        SIGTERM | SIGINT => {
            debug!("Stopping");
            true
        }
        SIGHUP => {
            // No restart is implemented: exit with 129 (128+SIGHUP),
            // like a process killed by the signal.
            info!("SIGHUP received; exiting with status 129 (no restart is implemented)");
            std::process::exit(129);
        }
        SIGCHLD => {
            debug!("Reap zombies");
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
            false
        }
        SIGTSTP | SIGTTOU | SIGTTIN => {
            debug!("ignoring {signal:?} (the kernel tried to stop us: tty has TOSTOP set)");
            false
        }
        sig => {
            warn!("Unexpected signal ignored ({sig:#?})");
            false
        }
    })
}

/// Block on a signalfd until the process should exit (SIGTERM/SIGINT).
///
/// This is the "tag-and-park" main loop. SIGHUP is not treated as a
/// restart (none is implemented); the process exits with status 129
/// (128+SIGHUP), like a process killed by the signal, so the cause is
/// distinguishable in the journal.
///
/// This signal handler is inspired by the implementation in catatonit:
/// https://github.com/openSUSE/catatonit/blob/56579adbb42c0c7ad94fc12d844b38fc5b37b3ce/catatonit.c#L538-L588
pub fn run_signal_loop() -> anyhow::Result<()> {
    let sigfd =
        setup_signalfd().map_err(|e| anyhow::anyhow!("setting up the signalfd failed: {e}"))?;
    loop {
        if handle_signal(&sigfd)? {
            break;
        }
    }
    Ok(())
}
