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
//! ## Global allowlist (Phase 2)
//!
//! With an active [`policy::Policy`], the proxy filters the
//! `wl_registry` traffic of each connection: `global` events for
//! interfaces outside the allowlist are dropped (and so is the matching
//! `global_remove`), and any `bind` of a name the client was never
//! shown is answered with a synthetic `wl_display.error`
//! (`invalid_object`) and the connection is torn down. This matters
//! because a client can `bind` a global by name even if it never saw
//! the announcement, so hiding the registry alone would not hide the
//! object. With the default (inactive) policy the proxy is a pure
//! pass-through.
//!
//! ## Selection gate (Phase 3, extended in Phase 5)
//!
//! With an active [`clipboard::ClipboardGate`] (the `deny` policy),
//! the proxy gates the one request shape that moves selection data
//! into a sandboxed app — on *either* of the two protocols that
//! carry selections: `wl_data_offer.receive` (the stable
//! clipboard) and `zwp_primary_selection_offer_v1.receive` (the
//! X-style primary selection, the `wp_primary_selection_unstable_v1`
//! protocol wlroots/sway implements; Phase 5 closed it as a second
//! instance of the same gate, because the stable protocol alone
//! left middle-click paste wide open). Each hands the app's own fd
//! to the compositor, which makes the current selection owner write
//! into it — and the owner may be the host desktop. The gate relays
//! a `receive` only when the data it reads is provably the app's own
//! (a read-back of the selection the app itself set *on that
//! protocol*; the two echo sequences are tracked separately); every
//! other read is dropped silently (the app sees an empty selection
//! instead of crashing). In both policies a `receive` whose fd is
//! not an in-memory channel (memfd/pipe/socket) is a fatal protocol
//! error: compositors do not inspect the fd they are handed, so
//! without the check a sandboxed app could direct selection data
//! into a path in its mount space (the shared `downloads` volume)
//! instead of keeping it in memory.
//!
//! ## The prompt broker (Phase 4)
//!
//! The `deny` policy is a safe default, not a wall: the user may
//! legitimately want to paste host data into the sandbox once in a
//! while. When the relay is configured with a [`broker::BrokerConfig`]
//! (the `--broker-socket` flag), a read the gate would drop is first
//! *asked*: the relay opens a fresh connection to the host broker
//! (which announces the request to the desktop and waits for the
//! user's decision — see [`crate::broker`]) and, if the user allows
//! it, calls [`clipboard::ClipboardGate::unlock`] with the intent
//! window from the answer (1500 ms by default) and forwards the read.
//! The window covers the burst an approved paste usually comes in
//! (one `receive` per mime type, retries); after it, the gate is
//! closed again. A missing broker, a timeout, or a malformed answer
//! keeps the drop — the broker is optional and fails closed.
//!
//! ## The selection audit log (Phase 9)
//!
//! Every selection event the relay observes becomes one record under
//! the `audit` log target (see [`audit`]): a **write** (`set_selection`
//! with a non-NULL source), a **clear** (a NULL source), a **read**
//! (`receive`, with the gate's decision), and a **serve** (a `send`
//! event on one of the app's source objects — the per-mime byte flow
//! behind a write). The record carries app, instance, selection,
//! action, origin, mime, the gate's decision, the fd's class, and the
//! payload *size* — never the contents. The default sink writes one
//! line per record, which in deployment reaches the host journal
//! (mode B via the pod's passthrough logging, mode A via the unit's
//! `StandardError=journal`): the persistent, cross-pod record, as
//! opposed to the Phase 6 notification (visible in the moment only).
//! The audit is always on while the relay runs (one line per event;
//! `RUST_LOG=warn` suppresses the stream).
//!
//! A payload size is only measurable where a size is reported: a
//! memfd grows as its writer writes, so the relay keeps a duplicate
//! of the relevant fd and re-measures it (an `fstat`, never a read)
//! at a short poll tick until the size settles; a pipe or socket
//! reports no size (the record omits the field). A dropped read
//! records 0 bytes — the app's fd stayed empty, which is the truth.
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

pub mod audit;
pub mod broker;
pub mod clipboard;
pub mod interfaces;
pub mod objects;
pub mod policy;
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
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use log::{debug, info, warn};
use nix::sys::signal::{SigSet, Signal, Signal::*};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, send, sendmsg,
};
use std::collections::HashSet;
use std::ffi::CString;
use std::time::{Duration, Instant};

use wayland_backend::protocol::{Argument, ArgumentType, Interface, Message, MessageDesc};
use wayland_client::protocol::__interfaces::WL_DISPLAY_INTERFACE;

pub use self::audit::{AuditConfig, AuditRecord, AuditSink, JournalAuditSink, format_audit};
pub use self::broker::BrokerConfig;
pub use self::clipboard::{ClipboardGate, ClipboardPolicy};
use self::clipboard::{FdKind, SelectionWrite, fd_class};
use self::objects::{BookkeepingError, Dir, ObjectTables};
pub use self::policy::Policy;

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
        let mut cmsg_space = vec![MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(fds.len()))];
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

/// What the interceptors (global allowlist, clipboard gate) do with
/// one parsed message.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ForwardAction {
    /// Relay the original bytes to the peer (the default).
    Forward,
    /// Consume the message silently (a hidden global, or the matching
    /// `global_remove` of one); the client never sees it.
    Drop,
}

/// The per-connection global-allowlist interceptor state: the shared
/// policy plus the set of globals the proxy has shown vs. hidden to
/// this client (Phase 2).
struct GlobalInterceptor {
    /// The allowlist policy (shared, immutable across relays).
    policy: Arc<Policy>,
    /// Globals the compositor has announced that the proxy has *shown*
    /// to the client (allowlisted). A `bind` of one of these is
    /// forwarded; of anything else it is rejected.
    shown: HashSet<u32>,
    /// Globals the compositor has announced that the proxy has *hidden*
    /// from the client (not allowlisted). Tracked so the matching
    /// `global_remove` can be dropped (the client never saw it).
    hidden: HashSet<u32>,
}

/// How often a pending size probe is re-measured (and the relay's
/// poll tick while one is pending): long enough that a settled size
/// is caught in one or two ticks, short enough that the record
/// lags the transfer by well under a second.
const PROBE_TICK: Timespec = Timespec {
    tv_sec: 0,
    tv_nsec: 250_000_000,
};
/// A probe is resolved (its record emitted) after this long even if
/// the size never settles (the writer wrote nothing, or is pathologically
/// slow): the record carries whatever was measured (0 if nothing).
const PROBE_DEADLINE: Duration = Duration::from_secs(5);
/// Consecutive measurements at the same non-zero size before the
/// size is considered settled.
const PROBE_STABLE: u32 = 2;

/// A pending payload-size measurement (Phase 9): a retained duplicate
/// of an fd that will carry selection payload across this
/// connection.
///
/// The size is not known at the moment the fd crosses the boundary —
/// the writer (the selection owner, for a forwarded `read`; the app
/// itself, for a `send` on one of its sources) fills it *after* the
/// message, out of band — so the relay keeps a duplicate and
/// re-measures it (`fstat`, never a read: the data is the app's or
/// the owner's, and the audit must not touch it) at each tick until
/// it settles. A memfd reports a size; a pipe/socket does not (such
/// a probe is resolved at once, without a size), and a writer that
/// never writes leaves 0 (the record says so).
struct SizeProbe {
    /// The retained duplicate (closed when the probe resolves).
    fd: OwnedFd,
    /// Whether the size is measurable at all (a memfd: yes).
    measurable: bool,
    /// The audit fields captured at the decision point; the
    /// `payload_bytes` is filled in as the probe settles.
    record: AuditRecord,
    /// The last measured size.
    last_size: u64,
    /// Consecutive measurements at the current non-zero size.
    stable: u32,
    /// Resolve by this instant at the latest (whatever was measured).
    deadline: Instant,
}

impl SizeProbe {
    /// Retain a duplicate of `fd` and start measuring it. The first
    /// measurement is taken now (the writer may have already written
    /// some); the relay re-measures on every tick until it settles.
    /// A `dup` failure is surfaced to the caller, which then emits
    /// the record without a size (the audit must never break the
    /// relay over a measurement).
    fn new(fd: &OwnedFd, record: AuditRecord) -> io::Result<Self> {
        let probe_fd = fd.try_clone()?;
        let measurable = matches!(fd_class(fd), Some(FdKind::Memfd));
        let last_size = if measurable {
            rustix::fs::fstat(&probe_fd)
                .map(|st| st.st_size as u64)
                .unwrap_or(0)
        } else {
            0
        };
        Ok(Self {
            fd: probe_fd,
            measurable,
            record,
            last_size,
            stable: 0,
            deadline: Instant::now() + PROBE_DEADLINE,
        })
    }
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
    g: GlobalInterceptor,
    /// The clipboard receive-gate (Phase 3): origin state the proxy
    /// infers from the protocol traffic, deciding `wl_data_offer.
    /// receive` requests.
    clipboard: ClipboardGate,
    /// The audit identity and sink (Phase 9): every selection event
    /// the relay observes becomes one record under the `audit` target
    /// (the host journal in deployment).
    audit: AuditConfig,
    /// Pending payload-size probes (Phase 9): retained duplicates of
    /// fds that will carry selection payload, measured as they settle.
    probes: Vec<SizeProbe>,
    /// The optional prompt broker (Phase 4): consulted before a
    /// dropped foreign read is consumed; an approved answer unlocks
    /// the gate for its intent window.
    broker: Option<BrokerConfig>,
}

impl Relay {
    fn new(
        down: UnixStream,
        up: UnixStream,
        policy: Arc<Policy>,
        clipboard: ClipboardPolicy,
        audit: AuditConfig,
        broker: Option<BrokerConfig>,
    ) -> Self {
        Self {
            down: ProxySocket::new(down),
            up: ProxySocket::new(up),
            down_buf: Vec::with_capacity(READ_SIZE),
            up_buf: Vec::with_capacity(READ_SIZE),
            down_fds: VecDeque::new(),
            up_fds: VecDeque::new(),
            tables: ObjectTables::new(),
            g: GlobalInterceptor {
                policy,
                shown: HashSet::new(),
                hidden: HashSet::new(),
            },
            clipboard: ClipboardGate::new(clipboard),
            audit,
            probes: Vec::new(),
            broker,
        }
    }

    /// Run until the relay ends; the caller drops both sockets.
    fn run(&mut self) -> RelayEnd {
        let end = loop {
            let mut polls = [
                PollFd::new(&self.down.fd, PollFlags::IN),
                PollFd::new(&self.up.fd, PollFlags::IN),
            ];
            // A tick only while a size probe is pending (Phase 9):
            // the writer fills the fd out of band, *after* the event,
            // so a fully blocked relay would never wake to measure
            // it — and an idle relay pays no tick cost.
            let timeout = if self.probes.is_empty() {
                None
            } else {
                Some(&PROBE_TICK)
            };
            match poll(&mut polls, timeout) {
                // `Ok(0)` is a tick (no socket ready): it falls
                // straight to the probe re-measure below, which is
                // all that happened.
                Ok(_) => {}
                // EINTR cannot happen here: this thread has the
                // signalfd-bound mask blocked (see [`spawn_relay`]).
                Err(Errno::INTR) => continue,
                // Any other poll error is terminal: break to the
                // teardown (which flushes any pending size probes).
                Err(e) => break RelayEnd::Io(e.into()),
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
                    break end;
                }
            }
            #[allow(clippy::collapsible_if)]
            if server_ready {
                if let Err(end) = self.pump(Dir::ServerToClient) {
                    break end;
                }
            }
            // Re-measure the probes on every wake: a size change
            // usually arrives with traffic, and the tick catches the
            // quiet ones.
            self.poll_probes();
        };
        // Teardown: emit whatever probe is still pending, with the
        // size measured so far (the record exists either way).
        self.flush_probes();
        end
    }

    /// Re-measure the pending size probes (Phase 9). A memfd that
    /// reported the same non-zero size [`PROBE_STABLE`] times in a
    /// row has settled — its record is emitted. A stream (pipe/
    /// socket) is emitted at once, without a size (a stream reports
    /// none). A probe past its deadline is emitted with whatever it
    /// measured (0 if the writer wrote nothing).
    fn poll_probes(&mut self) {
        if self.probes.is_empty() {
            return;
        }
        let now = Instant::now();
        let mut i = 0;
        while i < self.probes.len() {
            let resolved = {
                let p = &mut self.probes[i];
                if !p.measurable {
                    p.record.payload_bytes = None;
                    true
                } else if now >= p.deadline {
                    p.record.payload_bytes = Some(p.last_size);
                    true
                } else {
                    let size = rustix::fs::fstat(&p.fd)
                        .map(|st| st.st_size as u64)
                        .unwrap_or(p.last_size);
                    if size != 0 && size == p.last_size {
                        p.stable += 1;
                        p.last_size = size;
                        p.record.payload_bytes = Some(size);
                        p.stable >= PROBE_STABLE
                    } else {
                        p.stable = 1;
                        p.last_size = size;
                        p.record.payload_bytes = Some(size);
                        false
                    }
                }
            };
            if resolved {
                self.audit.audit(&self.probes[i].record);
                self.probes.remove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Emit every still-pending probe (the relay is ending; the
    /// sizes are whatever was measured — an under-estimate at worst,
    /// the record itself is exact about what happened).
    fn flush_probes(&mut self) {
        for p in &mut self.probes {
            p.record.payload_bytes = if p.measurable {
                Some(p.last_size)
            } else {
                None
            };
            self.audit.audit(&p.record);
        }
        self.probes.clear();
    }

    /// Read one chunk from the given direction and relay every complete
    /// message it yields to the other side.
    fn pump(&mut self, dir: Dir) -> Result<(), RelayEnd> {
        let (sock, reassembled, fds) = match dir {
            Dir::ClientToServer => (&self.down, &mut self.down_buf, &mut self.down_fds),
            Dir::ServerToClient => (&self.up, &mut self.up_buf, &mut self.up_fds),
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
            Self::forward(
                &mut self.tables,
                &mut self.g,
                &mut self.clipboard,
                self.broker.as_ref(),
                &self.audit,
                &mut self.probes,
                dir,
                raw,
                fds,
                &self.down,
                &self.up,
            )?;
            reassembled.drain(..len);
        }
    }

    /// Parse, validate, bookkeep and — where the policy says to —
    /// intercept one complete message, then relay its original bytes
    /// (with its fds) to the other side.
    ///
    /// `down` is the app's socket and `up` the tagged upstream; the
    /// ordinary destination is whichever end the message is headed for,
    /// but the `wl_registry` interceptor may instead drop the message or
    /// inject a synthetic `wl_display.error` back to the app.
    // These are the per-message relay's natural parameters; bundling
    // them into a struct would add indirection for no clarity (a
    // RelayCtx holding tables/g/clipboard is possible but churny).
    #[allow(clippy::too_many_arguments)]
    fn forward(
        tables: &mut ObjectTables,
        g: &mut GlobalInterceptor,
        clipboard: &mut ClipboardGate,
        broker: Option<&BrokerConfig>,
        audit: &AuditConfig,
        probes: &mut Vec<SizeProbe>,
        dir: Dir,
        raw: &[u8],
        src_fds: &mut VecDeque<OwnedFd>,
        down: &ProxySocket,
        up: &ProxySocket,
    ) -> Result<(), RelayEnd> {
        let dst = match dir {
            Dir::ClientToServer => up,
            Dir::ServerToClient => down,
        };
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

        // The clipboard gate observes every relayed message so its
        // origin state tracks the data_device/offer traffic as a whole
        // (it only reacts to that; everything else is a no-op). It
        // never hides events — the single decision point is the
        // `receive` request below.
        clipboard.observe(dir, sender, desc, &msg);

        // ---- Phase 6 + 9: a selection write or clear (the app's
        // `set_selection`). ----
        // A client `set_selection` with a non-NULL source is the app
        // placing data on that selection — the one direction that
        // moves data *out* of the sandbox (the read-gate below covers
        // the reverse); a NULL source clears it. No interceptor
        // touches `set_selection`: the request is always forwarded.
        // But two things happen here:
        //
        // * Phase 9: one audit record per event (`set` or `clear`).
        //   The `set` records the *declaration* — the data itself is
        //   served later, per mime, as the `serve` records (a `send`
        //   event on the app's source objects), which is where the
        //   payload size is measured. A `set` is always `own` (the
        //   source is one this client created).
        // * Phase 6: a copy-out *notification* (fire-and-forget) for a
        //   `set` only — a `clear` places nothing, so there is nothing
        //   to warn about. Fail-open: a missing/unreachable broker
        //   only loses the notice; the write is forwarded regardless.
        if let Some((selection, write)) = ClipboardGate::set_selection(dir, sender, desc, &msg) {
            match write {
                SelectionWrite::Set => {
                    audit.audit(&AuditRecord {
                        selection,
                        action: "set",
                        origin: Some("own"),
                        mime: None,
                        gate: None,
                        fd_kind: None,
                        payload_bytes: None,
                    });
                    if let Some(broker) = broker.filter(|b| b.notify_copy_out)
                        && let Err(e) = broker.notify_write(selection)
                    {
                        warn!(
                            "{selection} copy-out note: broker unreachable ({e}); the write is forwarded regardless"
                        );
                    }
                }
                SelectionWrite::Clear => {
                    // The origin removed is whatever the gate last
                    // attributed to this selection. `observe` (run
                    // before this) leaves that state untouched by the
                    // clear request itself — it is updated later, by
                    // the compositor's confirming `selection` echo —
                    // so this is the origin of the selection that is
                    // about to be cleared.
                    let origin = if selection == "primary" {
                        clipboard.primary_selection_origin()
                    } else {
                        clipboard.selection_origin()
                    };
                    audit.audit(&AuditRecord {
                        selection,
                        action: "clear",
                        origin: origin.map(|o| o.as_str()),
                        mime: None,
                        gate: None,
                        fd_kind: None,
                        payload_bytes: None,
                    });
                }
            }
        }

        // ---- Phase 2 + 3 (+ 5): the interceptors. ----
        // Only `wl_registry` and the `receive` requests of the two
        // selection protocols (`wl_data_offer`, and
        // `zwp_primary_selection_offer_v1` since Phase 5) are
        // decided on; everything else is a straight pass-through.
        //
        // Phase 2, the global allowlist: a hidden global is never
        // announced to the client, so the only way it could be
        // reached is a `bind` of a name the client was never shown —
        // the proxy rejects that with a fatal `invalid_object` error
        // instead of letting the compositor create the object by name.
        //
        // Phase 3, the clipboard receive-gate: a `receive` (client →
        // server) is the only request that hands a client-created fd
        // to the selection owner for the owner to write into. Under
        // `deny` the request is forwarded only when the data it reads
        // is provably the app's own (a read-back of the selection or
        // drag the app itself set); otherwise it is consumed silently
        // — the compositor never serves it, the app's fd (an
        // in-memory channel, see the fd sanity check) stays empty,
        // and the app sees an empty clipboard read instead of
        // crashing. An error here (a `receive` fd that is not an
        // in-memory channel, in either policy) fails the connection
        // closed.
        let action = if dir == Dir::ClientToServer
            && desc.name == "receive"
            && matches!(
                sender.name,
                "wl_data_offer" | "zwp_primary_selection_offer_v1"
            ) {
            // Which selection the read is about (for the broker
            // prompt and the audit; both protocols read identically
            // from here).
            let primary = sender.name == "zwp_primary_selection_offer_v1";
            let selection = if primary { "primary" } else { "clipboard" };
            // The request is `receive(mime, fd)`: the mime names the
            // data, the fd is the app's in-memory channel the
            // selection owner will fill.
            let mime = msg
                .args
                .iter()
                .find_map(|a| {
                    if let Argument::Str(Some(s)) = a {
                        Some(s.to_string_lossy().into_owned())
                    } else {
                        None
                    }
                })
                .unwrap_or_default();
            let recv_fd = msg.args.iter().find_map(|a| {
                if let Argument::Fd(f) = a {
                    Some(f)
                } else {
                    None
                }
            });

            let decision = clipboard
                .on_receive(&msg, primary)
                .map_err(RelayEnd::Protocol)?;

            // The gate's decision as the audit spells it. A forward
            // is either the policy's own allow (`forward`) or a
            // broker approval (`approved`); a drop is a policy deny,
            // a broker deny, a timeout, or an unreachable broker
            // (`dropped` — fail closed).
            let (final_action, gate) = match (decision.action, broker) {
                (ForwardAction::Forward, _) => (ForwardAction::Forward, "forward"),
                // The gate dropped a read of a foreign selection (the
                // `deny` policy with no active consent window). If a
                // prompt broker is configured, ask the user before
                // consuming the fd: an allow opens the gate's intent
                // window (this read, and the burst that comes with
                // it, go through) and the read is forwarded; a deny,
                // a timeout, or an unreachable broker keeps the drop
                // (fail closed).
                (ForwardAction::Drop, Some(broker)) => match broker.ask(selection, &mime) {
                    Ok(true) => {
                        clipboard.unlock(Instant::now() + broker.window);
                        info!(
                            "{selection} gate: the user approved the read; \
                             the intent window ({} ms) opens foreign reads",
                            broker.window.as_millis()
                        );
                        (ForwardAction::Forward, "approved")
                    }
                    Ok(false) => (ForwardAction::Drop, "dropped"),
                    Err(e) => {
                        warn!(
                            "{selection} gate: the broker is unreachable ({e}); dropping the read"
                        );
                        (ForwardAction::Drop, "dropped")
                    }
                },
                (ForwardAction::Drop, None) => (ForwardAction::Drop, "dropped"),
            };

            // Phase 9: audit the read, and arrange to measure the
            // payload. The size is only known after the (possibly
            // never) write: a dropped read's fd stays empty (0
            // bytes, emitted now); a forwarded/approved read's fd is
            // filled out-of-band by the selection owner — a memfd is
            // probed for its size, a stream (pipe/socket) reports
            // none (the field is then omitted).
            let mut record = AuditRecord {
                selection,
                action: "read",
                origin: Some(decision.origin.as_str()),
                mime: Some(mime),
                gate: Some(gate),
                fd_kind: Some(decision.fd_kind.as_str()),
                payload_bytes: None,
            };
            if final_action == ForwardAction::Drop {
                // The fd was never handed to the compositor: it
                // stayed empty, which is the truth the record keeps.
                record.payload_bytes = Some(0);
                audit.audit(&record);
            } else {
                let measurable = decision.fd_kind == FdKind::Memfd;
                if let (true, Some(fd)) = (measurable, recv_fd) {
                    match SizeProbe::new(fd, record.clone()) {
                        Ok(p) => probes.push(p),
                        Err(e) => {
                            // A dup failure does not break the relay
                            // (the read still goes through); the
                            // record is emitted without a size.
                            warn!(
                                "read audit: dup of the receive fd failed ({e}); emitting without a size"
                            );
                            audit.audit(&record);
                        }
                    }
                } else {
                    audit.audit(&record);
                }
            }

            final_action
        } else if dir == Dir::ServerToClient
            && desc.name == "send"
            && matches!(
                sender.name,
                "wl_data_source" | "zwp_primary_selection_source_v1"
            )
        {
            // Phase 9: audit the serve. A `send(mime, fd)` on the
            // app's source object is the compositor telling the app
            // to write its own data for a requester's read — the
            // per-mime byte flow behind a `set`/`start_drag`. The
            // data is the app's (a copy-out), so the origin is `own`
            // and there is no gate; we record the mime, the fd's
            // class, and (when measurable) the size the app writes.
            // The event is always forwarded (the app is entitled to
            // it; no interceptor drops a `send`).
            let selection = if sender.name == "zwp_primary_selection_source_v1" {
                "primary"
            } else {
                "clipboard"
            };
            let mime = msg
                .args
                .iter()
                .find_map(|a| {
                    if let Argument::Str(Some(s)) = a {
                        Some(s.to_string_lossy().into_owned())
                    } else {
                        None
                    }
                })
                .unwrap_or_default();
            let send_fd = msg.args.iter().find_map(|a| {
                if let Argument::Fd(f) = a {
                    Some(f)
                } else {
                    None
                }
            });
            let fd_kind: Option<FdKind> = send_fd.and_then(fd_class);
            let record = AuditRecord {
                selection,
                action: "serve",
                origin: Some("own"),
                mime: Some(mime),
                gate: None,
                fd_kind: fd_kind.map(|k| k.as_str()),
                payload_bytes: None,
            };
            let measurable = matches!(fd_kind, Some(FdKind::Memfd));
            if let (true, Some(fd)) = (measurable, send_fd) {
                match SizeProbe::new(fd, record.clone()) {
                    Ok(p) => probes.push(p),
                    Err(e) => {
                        warn!(
                            "serve audit: dup of the send fd failed ({e}); emitting without a size"
                        );
                        audit.audit(&record);
                    }
                }
            } else {
                audit.audit(&record);
            }
            ForwardAction::Forward
        } else if sender.name == "wl_registry" {
            match (dir, desc.name) {
                (Dir::ServerToClient, "global") => {
                    let (name, iface) = match (&msg.args[0], &msg.args[1]) {
                        (Argument::Uint(n), Argument::Str(Some(s))) => {
                            (*n, s.to_string_lossy().into_owned())
                        }
                        _ => {
                            return Err(RelayEnd::Protocol(
                                "malformed wl_registry.global event".into(),
                            ));
                        }
                    };
                    if g.policy.allows(&iface) {
                        g.shown.insert(name);
                        ForwardAction::Forward
                    } else {
                        g.hidden.insert(name);
                        debug!("hiding global {name} ({iface}) per the allowlist");
                        ForwardAction::Drop
                    }
                }
                (Dir::ServerToClient, "global_remove") => {
                    let name = match &msg.args[0] {
                        Argument::Uint(n) => *n,
                        _ => {
                            return Err(RelayEnd::Protocol(
                                "malformed wl_registry.global_remove event".into(),
                            ));
                        }
                    };
                    if g.hidden.remove(&name) {
                        // We hid it, so the client never saw the
                        // announcement: the removal is unneeded.
                        debug!("dropping global_remove {name} (the global was hidden)");
                        ForwardAction::Drop
                    } else {
                        // Shown (the client must be told to drop its binding)
                        // or a stray removal the client will ignore.
                        g.shown.remove(&name);
                        ForwardAction::Forward
                    }
                }
                (Dir::ClientToServer, "bind") => {
                    let name = match &msg.args[0] {
                        Argument::Uint(n) => *n,
                        _ => {
                            return Err(RelayEnd::Protocol(
                                "malformed wl_registry.bind request".into(),
                            ));
                        }
                    };
                    if g.shown.contains(&name) {
                        ForwardAction::Forward
                    } else {
                        let what = format!(
                            "wlsctx: bind of global {name} is blocked by the global allowlist"
                        );
                        let err = Self::display_error(tables, 0 /* invalid_object */, &what)?;
                        let n = down.send(&err, &[]).map_err(RelayEnd::Io)?;
                        if n != err.len() {
                            return Err(RelayEnd::Protocol(
                                "partial send of the injected wl_display.error".into(),
                            ));
                        }
                        warn!("{what}");
                        // The error is fatal: the app exits on it and the
                        // relay tears down both ends.
                        return Err(RelayEnd::Protocol(format!(
                            "rejected the app's bind of non-allowlisted global {name}"
                        )));
                    }
                }
                _ => ForwardAction::Forward,
            }
        } else {
            ForwardAction::Forward
        };

        if matches!(action, ForwardAction::Drop) {
            // `scratch` (any fds belonging to this message) is dropped
            // with it here; nothing is forwarded to the peer.
            return Ok(());
        }

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

    /// Serialize a synthetic `wl_display.error` event addressed to this
    /// connection's display object.
    ///
    /// The shape follows what a real compositor posts for a display-level
    /// failure — both `libwayland` (`wl_resource_post_error(
    /// display_resource, WL_DISPLAY_ERROR_*, …)`) and wayland-backend
    /// (`Client::post_display_error`) emit it from the display object,
    /// with the `object_id` argument also naming the display:
    /// `error(object_id, code, message)`.
    fn display_error(tables: &ObjectTables, code: u32, message: &str) -> Result<Vec<u8>, RelayEnd> {
        let (opcode, desc) = WL_DISPLAY_INTERFACE
            .events
            .iter()
            .enumerate()
            .find(|(_, d)| d.name == "error")
            .ok_or_else(|| {
                RelayEnd::Protocol("no wl_display.error event in the protocol".into())
            })?;
        let display_id = tables.display().unwrap_or(1);
        let msg = Message {
            sender_id: display_id,
            opcode: opcode as u16,
            args: vec![
                Argument::Object(display_id),
                Argument::Uint(code),
                Argument::Str(Some(Box::new(CString::new(message).map_err(|e| {
                    RelayEnd::Protocol(format!("bad error message: {e}"))
                })?))),
            ]
            .into(),
        };
        let mut buf = vec![0u8; 512];
        let mut fds = Vec::new();
        let n = wire::write_message(&msg, desc.signature, &mut buf, &mut fds)
            .map_err(|e| RelayEnd::Protocol(e.to_string()))?;
        Ok(buf[..n].to_vec())
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
    let what = if dir == Dir::ClientToServer {
        "request"
    } else {
        "event"
    };
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
            ));
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
fn spawn_relay(
    app: UnixStream,
    tagged_path: &Path,
    policy: Arc<Policy>,
    clipboard: ClipboardPolicy,
    audit: AuditConfig,
    broker: Option<BrokerConfig>,
) -> io::Result<()> {
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
            let mut relay = Relay::new(app, up, policy, clipboard, audit, broker);
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
    policy: &Policy,
    clipboard: ClipboardPolicy,
    audit: AuditConfig,
    broker: Option<BrokerConfig>,
    stop: Option<Arc<AtomicBool>>,
) -> io::Result<()> {
    let policy = Arc::new(policy.clone());
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
                        if let Err(e) = spawn_relay(
                            stream,
                            tagged_path,
                            policy.clone(),
                            clipboard,
                            audit.clone(),
                            broker.clone(),
                        ) {
                            warn!("dropping app connection: {e}");
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
            }
        }
        // Test hook: the stop flag is checked on every 200 ms tick.
        let stopped = stop.as_ref().is_some_and(|s| s.load(Ordering::SeqCst));
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
    let siginfo = sigfd
        .read_signal()
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "signalfd closed"))?;
    let signal = Signal::try_from(siginfo.ssi_signo as i32).map_err(|e| {
        io::Error::other(format!("unknown signal number {}: {e}", siginfo.ssi_signo))
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
