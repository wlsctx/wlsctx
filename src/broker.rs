//! The prompt broker (Phase 4).
//!
//! ## Why the broker
//!
//! Under `--clipboard-policy=deny` the proxy drops every read of a
//! selection the sandboxed app did not create itself (see
//! [`crate::proxy::clipboard`]): the app sees an empty clipboard. That
//! is the safe default, but the user may legitimately want to paste
//! host data into the sandbox — for one read, at the moment it
//! happens, decided by the *user* and not by the app. The broker is
//! where that decision lives: it runs on the **host** (a user service
//! in the desktop session, outside every sandbox), because only the
//! host can see the user and answer for them.
//!
//! ## The protocol
//!
//! Newline-delimited JSON over two Unix stream sockets.
//!
//! **The broker socket** (the proxy → the broker; one line each way
//! per connection):
//!
//! * A *consent request*: the proxy (which hit a foreign read its
//!   gate dropped) connects and sends
//!   `{"v":1,"kind":"clipboard-read","app":"…","instance":"…","mime":"…"}`.
//!   The broker announces the prompt to the desktop (`notify-send`)
//!   and registers it in its queue of pending prompts, then answers
//!   — after the user's decision or the timeout — with one line:
//!   `{"decision":"allow","window_ms":1500}` or
//!   `{"decision":"deny","reason":"…"}`.
//! * A *copy-out notification* (Phase 6, one-way): when a sandboxed
//!   app *writes* to the clipboard or the primary selection (a
//!   `set_selection`), the proxy connects and sends
//!   `{"v":1,"kind":"clipboard-write","app":"…","instance":"…","selection":"…"}`.
//!   The broker fires a desktop notification (`notify-send`) and
//!   closes the connection **without a reply**. The notification is
//!   fire-and-forget and **fails open**: a missing or busy broker
//!   simply loses the notice; the write itself is never altered or
//!   delayed. This is the copy-*out* signal — the data the app just
//!   placed is now reachable by every client on the desktop (the
//!   consent flow above covers the copy-*in* direction). See Phase 6
//!   in the README threat model.
//!
//! **The decision socket** (`wlsctx --decide` → the broker): bound
//! **once, for the life of the session** (in interactive mode), at
//! the runtime directory's [`DECISION_SOCKET`] — no more per-prompt
//! bind, no more `latest` pointer:
//!
//! * `{"v":1,"kind":"list"}` receives
//!   `{"v":1,"kind":"pending","prompts":[{…},…]}` — the pending
//!   prompts in arrival order (oldest first), each with an id,
//!   app/instance, selection, mime, and the time left on its
//!   deadline.
//! * `{"v":1,"kind":"decide","decision":"allow"|"deny","prompt":<id>?}`
//!   receives either `{"v":1,"kind":"resolved","prompt":<id>,
//!   "decision":"…"}` or
//!   `{"v":1,"kind":"error","reason":"no-pending-prompt" |
//!   "unknown-prompt" | …}`. Omitting `prompt` targets the **oldest**
//!   pending prompt.
//!
//! The run loop is event-driven: the main thread services both
//! sockets via `poll(2)` while each proxy connection gets its own
//! thread (a prompt waiting on the user parks that thread on a
//! condvar). Several prompts can therefore be pending at once, and
//! the decider can list them or target any of them by id.
//!
//! On an allow, the proxy opens the gate's *intent window*
//! ([`crate::proxy::clipboard::ClipboardGate::unlock`] with the
//! `window_ms` from the response, 1500 ms by default): this read, and
//! any further reads until the window closes, go through without
//! another prompt — an approved paste usually comes in a short burst
//! (one `receive` per mime type, or the app retrying). After the
//! window, the gate is closed again. Every failure path — the broker
//! missing, a timeout, a malformed answer — fails closed on both
//! sides and the read is dropped as if there were no broker.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::os::fd::FromRawFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use log::{info, warn};
use rustix::event::{PollFd, PollFlags, poll};
use serde::{Deserialize, Serialize};

/// The broker's default wait for the user's decision.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// The intent window the broker offers on an allow (milliseconds):
/// what the proxy passes to [`crate::proxy::clipboard::ClipboardGate::unlock`].
pub const INTENT_WINDOW_MS: u64 = 1500;
/// The consent request kind: the proxy asks about a dropped foreign
/// read (request/response; the broker prompts the user and answers).
pub const REQUEST_KIND: &str = "clipboard-read";
/// The copy-out notification kind (Phase 6): the app wrote to a
/// selection (one-way; the broker notifies and never answers).
pub const NOTIFY_KIND: &str = "clipboard-write";
/// The protocol version in every line (both directions).
pub const PROTOCOL_VERSION: u8 = 1;

/// The decision socket's file name, inside the runtime directory
/// (`$XDG_RUNTIME_DIR/wlsctx`). Bound once for the life of a session
/// (interactive mode only) and answered by `wlsctx --decide`.
pub const DECISION_SOCKET: &str = "decision.sock";
/// How long the main loop's read of a decider connection is given:
/// the decider is a trusted local CLI whose line arrives on connect,
/// so a short bound keeps the loop responsive (a stuck decider can
/// never hold a prompt's queue or the next accept).
pub const DECIDER_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// The decider request kind: list the pending prompts.
pub const LIST_KIND: &str = "list";
/// The decider request kind: decide one pending prompt.
pub const DECIDE_KIND: &str = "decide";
/// The response kind to a list: the pending prompts, oldest first.
pub const PENDING_KIND: &str = "pending";
/// The response kind to a decide that found its target.
pub const RESOLVED_KIND: &str = "resolved";
/// The response kind for a failed decide (or a malformed line).
pub const ERROR_KIND: &str = "error";
/// No prompt is pending (the queue is empty).
pub const REASON_NO_PENDING: &str = "no-pending-prompt";
/// The targeted prompt id is unknown: already resolved or expired
/// (a decided prompt leaves the queue atomically with its decision),
/// or never existed in this session.
pub const REASON_UNKNOWN_PROMPT: &str = "unknown-prompt";
/// The line was not a valid decider request.
pub const REASON_PROTOCOL: &str = "protocol";

/// A request from the proxy: the app behind it is trying to read a
/// selection it did not create, and the proxy's gate dropped the read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipboardRead {
    /// The protocol version (currently 1).
    pub v: u8,
    /// The request kind (currently only [`REQUEST_KIND`]).
    pub kind: String,
    /// The app ID from the sandbox's security context.
    pub app: String,
    /// The instance ID from the sandbox's security context.
    pub instance: String,
    /// The mime type the app asked to read.
    pub mime: String,
    /// Which selection the app was reading: `"clipboard"` (the
    /// stable selection) or `"primary"` (the X-style primary
    /// selection, the `wp_primary_selection_unstable_v1` protocol,
    /// Phase 5). Optional on the wire: a peer without the field
    /// (an older build) reads as `"clipboard"`.
    #[serde(default = "default_selection")]
    pub selection: String,
}

fn default_selection() -> String {
    "clipboard".into()
}

/// A one-way notification from the proxy (Phase 6): the app behind it
/// just wrote to a selection, so its data is now reachable by every
/// client on the desktop (a copy-*out*). The broker announces this to
/// the desktop and closes the connection without replying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipboardWrite {
    /// The protocol version (currently 1).
    pub v: u8,
    /// The notification kind ([`NOTIFY_KIND`]).
    pub kind: String,
    /// The app ID from the sandbox's security context.
    pub app: String,
    /// The instance ID from the sandbox's security context.
    pub instance: String,
    /// Which selection the app wrote: `"clipboard"` (the stable
    /// selection) or `"primary"` (the X-style primary selection).
    /// Optional on the wire; reads as `"clipboard"` when absent.
    #[serde(default = "default_selection")]
    pub selection: String,
}

/// The broker's answer to the proxy: allow the read (opening an
/// intent window of `window_ms`) or drop it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    /// Serve the read; the proxy unlocks foreign reads for `window_ms`.
    Allow { window_ms: u64 },
    /// Drop the read; the app sees an empty clipboard.
    Deny { reason: String },
}

/// The user's answer on the decision socket (no window: the broker
/// supplies the intent window from its own configuration).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum UserDecision {
    Allow,
    Deny,
}

/// The decider's (`wlsctx --decide`) request on the session decision
/// socket: `kind` is [`LIST_KIND`] (no other fields) or
/// [`DECIDE_KIND`] (with a `decision`; an optional `prompt` id to
/// target a specific pending prompt, the oldest when absent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecideRequest {
    /// The protocol version (currently 1).
    pub v: u8,
    /// The request kind ([`LIST_KIND`] or [`DECIDE_KIND`]).
    pub kind: String,
    /// The decision (`"allow"` or `"deny"`): required for a
    /// [`DECIDE_KIND`] request, absent for a [`LIST_KIND`] one.
    #[serde(default)]
    pub decision: Option<String>,
    /// The id of the pending prompt to decide: absent means the
    /// oldest pending prompt.
    #[serde(default)]
    pub prompt: Option<u32>,
}

/// One pending prompt as listed back to the decider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingPromptView {
    /// The prompt's id (monotonic per broker session; what
    /// `--prompt` names).
    pub id: u32,
    /// The app ID from the sandbox's security context.
    pub app: String,
    /// The instance ID from the sandbox's security context.
    pub instance: String,
    /// Which selection the app was reading.
    pub selection: String,
    /// The mime type the app asked to read.
    pub mime: String,
    /// How much of the prompt's deadline is left (milliseconds).
    pub expires_in_ms: u64,
}

/// The broker's answer to a [`LIST_KIND`] request: the pending
/// prompts in arrival order (oldest first; empty when none).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingList {
    /// The protocol version (currently 1).
    pub v: u8,
    /// The response kind ([`PENDING_KIND`]).
    pub kind: String,
    pub prompts: Vec<PendingPromptView>,
}

/// The broker's confirmation that a pending prompt was resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resolution {
    /// The protocol version (currently 1).
    pub v: u8,
    /// The response kind ([`RESOLVED_KIND`]).
    pub kind: String,
    /// The id of the prompt that was resolved.
    pub prompt: u32,
    /// The decision that was applied (`"allow"` / `"deny"`).
    pub decision: String,
}

/// The broker's error reply on the decision socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorReply {
    /// The protocol version (currently 1).
    pub v: u8,
    /// The response kind ([`ERROR_KIND`]).
    pub kind: String,
    /// The prompt id the failed decide targeted (absent for
    /// [`REASON_NO_PENDING`] and [`REASON_PROTOCOL`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<u32>,
    /// The reason: [`REASON_NO_PENDING`], [`REASON_UNKNOWN_PROMPT`],
    /// or [`REASON_PROTOCOL`].
    pub reason: String,
}

/// Encode a wire line (message + trailing newline).
fn encode<T: Serialize>(msg: &T) -> io::Result<String> {
    Ok(format!(
        "{}\n",
        serde_json::to_string(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
    ))
}

/// Decode one wire line (a newline is optional in input; the
/// `Decision`/`UserDecision` tags must be the given value).
fn decode<T: for<'de> Deserialize<'de>>(line: &str) -> Result<T, String> {
    serde_json::from_str(line.trim()).map_err(|e| format!("malformed line {line:?}: {e}"))
}

/// Encode a request line (the proxy → broker direction).
pub fn encode_request(req: &ClipboardRead) -> io::Result<String> {
    encode(req)
}

/// Decode a request line; the version and kind must match.
pub fn decode_request(line: &str) -> Result<ClipboardRead, String> {
    let req = decode::<ClipboardRead>(line)?;
    if req.v != PROTOCOL_VERSION {
        return Err(format!(
            "unsupported protocol version {} (the broker speaks {PROTOCOL_VERSION})",
            req.v
        ));
    }
    if req.kind != REQUEST_KIND {
        return Err(format!("unknown request kind {:?}", req.kind));
    }
    Ok(req)
}

/// Encode a copy-out notification line (the proxy → broker direction,
/// Phase 6). Like a request, but the broker never answers it.
pub fn encode_notification(note: &ClipboardWrite) -> io::Result<String> {
    encode(note)
}

/// Decode a copy-out notification line; the version and kind must
/// match.
pub fn decode_notification(line: &str) -> Result<ClipboardWrite, String> {
    let note = decode::<ClipboardWrite>(line)?;
    if note.v != PROTOCOL_VERSION {
        return Err(format!(
            "unsupported protocol version {} (the broker speaks {PROTOCOL_VERSION})",
            note.v
        ));
    }
    if note.kind != NOTIFY_KIND {
        return Err(format!("unknown notification kind {:?}", note.kind));
    }
    Ok(note)
}

/// The minimal envelope the daemon sniffs to decide the handling path
/// before committing to a full decode (the `kind` is the only field it
/// needs; version and the rest are re-validated by the per-kind
/// decoders).
#[derive(Debug, Deserialize)]
struct Envelope {
    kind: String,
}

/// Decode just the `kind` of a wire line, for dispatch.
fn decode_envelope(line: &str) -> Result<Envelope, String> {
    decode::<Envelope>(line)
}

/// Encode a decision line (the broker → proxy direction).
pub fn encode_decision(d: &Decision) -> io::Result<String> {
    encode(d)
}

/// Decode a decision line.
pub fn decode_decision(line: &str) -> Result<Decision, String> {
    decode(line)
}

/// Encode a user-decision line (the `--decide` → broker direction).
pub fn encode_user_decision(d: &UserDecision) -> io::Result<String> {
    encode(d)
}

/// Decode a user-decision line.
pub fn decode_user_decision(line: &str) -> Result<UserDecision, String> {
    decode(line)
}

/// Encode a `list` request line (the decider → broker direction).
pub fn encode_list_request() -> io::Result<String> {
    encode(&DecideRequest {
        v: PROTOCOL_VERSION,
        kind: LIST_KIND.to_string(),
        decision: None,
        prompt: None,
    })
}

/// Encode a `decide` request line (the decider → broker direction);
/// `prompt` targets a specific pending prompt (the oldest when `None`).
pub fn encode_decide_request(d: &UserDecision, prompt: Option<u32>) -> io::Result<String> {
    encode(&DecideRequest {
        v: PROTOCOL_VERSION,
        kind: DECIDE_KIND.to_string(),
        decision: Some(decision_name(d).to_string()),
        prompt,
    })
}

/// Decode a decider request line; the version, the kind, and (for a
/// `decide`) the decision must all be valid.
pub fn decode_decider_request(line: &str) -> Result<DecideRequest, String> {
    let req = decode::<DecideRequest>(line)?;
    if req.v != PROTOCOL_VERSION {
        return Err(format!(
            "unsupported protocol version {} (the broker speaks {PROTOCOL_VERSION})",
            req.v
        ));
    }
    match req.kind.as_str() {
        LIST_KIND | DECIDE_KIND => {}
        other => return Err(format!("unknown request kind {other:?}")),
    }
    if req.kind == DECIDE_KIND {
        let d = req
            .decision
            .as_deref()
            .ok_or_else(|| "a decide request needs a decision (allow or deny)".to_string())?;
        parse_decision(d)?;
    }
    Ok(req)
}

/// The on-the-wire (and CLI) name of a decision.
pub fn decision_name(d: &UserDecision) -> &'static str {
    match d {
        UserDecision::Allow => "allow",
        UserDecision::Deny => "deny",
    }
}

/// Encode a `pending` response line (the broker → decider direction).
pub fn encode_pending_list(list: &PendingList) -> io::Result<String> {
    encode(list)
}

/// Decode a `pending` response line; the version and kind must match.
pub fn decode_pending_list(line: &str) -> Result<PendingList, String> {
    let list = decode::<PendingList>(line)?;
    if list.v != PROTOCOL_VERSION {
        return Err(format!(
            "unsupported protocol version {} (the broker speaks {PROTOCOL_VERSION})",
            list.v
        ));
    }
    if list.kind != PENDING_KIND {
        return Err(format!("unknown response kind {:?}", list.kind));
    }
    Ok(list)
}

/// Encode a `resolved` response line (the broker → decider direction).
pub fn encode_resolution(r: &Resolution) -> io::Result<String> {
    encode(r)
}

/// Decode a `resolved` response line; the version and kind must match.
pub fn decode_resolution(line: &str) -> Result<Resolution, String> {
    let r = decode::<Resolution>(line)?;
    if r.v != PROTOCOL_VERSION {
        return Err(format!(
            "unsupported protocol version {} (the broker speaks {PROTOCOL_VERSION})",
            r.v
        ));
    }
    if r.kind != RESOLVED_KIND {
        return Err(format!("unknown response kind {:?}", r.kind));
    }
    Ok(r)
}

/// Encode an `error` response line (the broker → decider direction).
pub fn encode_error_reply(e: &ErrorReply) -> io::Result<String> {
    encode(e)
}

/// Decode an `error` response line; the version and kind must match.
pub fn decode_error_reply(line: &str) -> Result<ErrorReply, String> {
    let e = decode::<ErrorReply>(line)?;
    if e.v != PROTOCOL_VERSION {
        return Err(format!(
            "unsupported protocol version {} (the broker speaks {PROTOCOL_VERSION})",
            e.v
        ));
    }
    if e.kind != ERROR_KIND {
        return Err(format!("unknown response kind {:?}", e.kind));
    }
    Ok(e)
}

/// Read one `\n`-terminated line from `r` into `out` (the newline is
/// kept; the line is UTF-8 lossy). Rust 1.99's `BufRead` no longer
/// provides `read_line`/`read_until`, so the reader is manual:
/// chunked `read`s until a newline or EOF. A timeout on a socket with
/// `SO_RCVTIMEO` set surfaces through the underlying `read` as the
/// caller's usual I/O error.
pub fn read_line(r: &mut impl io::Read, out: &mut String) -> io::Result<usize> {
    let mut line = Vec::with_capacity(128);
    let mut chunk = [0u8; 256];
    loop {
        let n = r.read(&mut chunk)?;
        if n == 0 {
            break; // EOF: return whatever was buffered
        }
        match chunk[..n].iter().position(|b| *b == b'\n') {
            Some(rel) => {
                line.extend_from_slice(&chunk[..rel + 1]);
                out.clear();
                out.push_str(&String::from_utf8_lossy(&line));
                return Ok(line.len());
            }
            None => line.extend_from_slice(&chunk[..n]),
        }
    }
    out.clear();
    out.push_str(&String::from_utf8_lossy(&line));
    Ok(out.len())
}

/// Parse a decision keyword (`allow`/`deny`) from the CLI.
pub fn parse_decision(s: &str) -> Result<UserDecision, String> {
    match s {
        "allow" => Ok(UserDecision::Allow),
        "deny" => Ok(UserDecision::Deny),
        other => Err(format!(
            "unknown decision {other:?} (expected `allow` or `deny`)"
        )),
    }
}

/// How the broker decides when no user is in the loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoDecide {
    Allow,
    Deny,
}

/// The broker's configuration (what `main` assembles from the CLI).
/// Cloned per spawned connection thread.
#[derive(Clone)]
pub struct BrokerArgs {
    /// Where the session decision socket lives:
    /// `$XDG_RUNTIME_DIR/wlsctx`.
    pub runtime_dir: PathBuf,
    /// Skip prompting entirely (a test hook): decide every request
    /// the given way (no decision socket is bound in this mode).
    pub auto_decide: Option<AutoDecide>,
    /// How long to wait for the user's decision (the deadline of
    /// each pending prompt).
    pub timeout: Duration,
}

/// One prompt waiting for the user's decision: the facts the
/// decider's listing shows, the deadline, and the decision itself
/// (recorded by the main loop when the user answers). The record is
/// `Arc`'d: the main loop and the connection thread owning the
/// waiting proxy both reach it through the queue.
struct PendingPrompt {
    /// The prompt's id (monotonic per session; what `--prompt` names).
    id: u32,
    app: String,
    instance: String,
    selection: String,
    mime: String,
    /// The prompt's deadline (its creation + the broker's timeout).
    deadline: Instant,
    /// The user's decision once the main loop records it.
    decision: Mutex<Option<UserDecision>>,
    /// Wakes the waiting connection thread when a decision lands.
    waker: Condvar,
}

/// The broker's session state: the queue of pending prompts (in
/// arrival order, oldest first) and whether the decision socket is
/// usable. A decided prompt leaves the queue **atomically with its
/// decision** ([`BrokerCore::decide`]), so a second decide for the
/// same id is a clean `unknown-prompt`, never a double resolution; an
/// expired prompt is removed by its own waiting thread.
pub struct BrokerCore {
    queue: Mutex<Queue>,
    /// The session decision socket could not be bound: interactive
    /// prompts are denied at once (`no-decision-socket`) instead of
    /// waited on, and there is no socket for the decider to reach.
    degraded: bool,
}

struct Queue {
    /// The next id to hand out (1-based, monotonic per session).
    next_id: u32,
    /// The pending prompts, oldest first.
    prompts: VecDeque<Arc<PendingPrompt>>,
}

impl Default for BrokerCore {
    fn default() -> Self {
        Self::new()
    }
}

impl BrokerCore {
    /// An interactive core (the decision socket is usable).
    pub fn new() -> Self {
        Self {
            queue: Mutex::new(Queue {
                next_id: 0,
                prompts: VecDeque::new(),
            }),
            degraded: false,
        }
    }

    /// A core whose decision socket is unusable (the broker degrades:
    /// interactive prompts are denied at once).
    fn new_degraded() -> Self {
        let mut core = Self::new();
        core.degraded = true;
        core
    }

    /// Whether the decision socket is unusable.
    pub fn is_degraded(&self) -> bool {
        self.degraded
    }

    /// Register an interactive prompt (the connection thread calls
    /// this before announcing and waiting). Returns the record.
    fn add_prompt(&self, req: &ClipboardRead, timeout: Duration) -> Arc<PendingPrompt> {
        let mut q = self.queue.lock().unwrap();
        q.next_id += 1;
        let prompt = Arc::new(PendingPrompt {
            id: q.next_id,
            app: req.app.clone(),
            instance: req.instance.clone(),
            selection: req.selection.clone(),
            mime: req.mime.clone(),
            deadline: Instant::now() + timeout,
            decision: Mutex::new(None),
            waker: Condvar::new(),
        });
        q.prompts.push_back(prompt.clone());
        prompt
    }

    /// Record the user's decision on one prompt: the targeted id if
    /// given, otherwise the oldest pending. Returns the resolved id.
    /// The prompt is removed from the queue at the same time.
    pub fn decide(&self, target: Option<u32>, d: UserDecision) -> Result<u32, &'static str> {
        let mut q = self.queue.lock().unwrap();
        let pos = match target {
            Some(id) => q
                .prompts
                .iter()
                .position(|p| p.id == id)
                .ok_or(REASON_UNKNOWN_PROMPT)?,
            None => {
                if q.prompts.is_empty() {
                    return Err(REASON_NO_PENDING);
                }
                0
            }
        };
        let prompt = q
            .prompts
            .remove(pos)
            .expect("position came from the same queue");
        *prompt.decision.lock().unwrap() = Some(d);
        prompt.waker.notify_one();
        Ok(prompt.id)
    }

    /// Snapshot of the pending prompts for a `list` reply, oldest
    /// first.
    pub fn pending_view(&self) -> Vec<PendingPromptView> {
        let q = self.queue.lock().unwrap();
        q.prompts
            .iter()
            .map(|p| PendingPromptView {
                id: p.id,
                app: p.app.clone(),
                instance: p.instance.clone(),
                selection: p.selection.clone(),
                mime: p.mime.clone(),
                expires_in_ms: p
                    .deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis() as u64,
            })
            .collect()
    }

    /// Remove a resolved or expired prompt (the waiting thread calls
    /// this when it finishes; a prompt `decide` already removed is a
    /// no-op).
    pub fn remove(&self, id: u32) {
        let mut q = self.queue.lock().unwrap();
        if let Some(pos) = q.prompts.iter().position(|p| p.id == id) {
            q.prompts.remove(pos);
        }
    }
}

/// Bind the broker's listening socket (the `--listen` path when not
/// socket-activated). Like the proxy's bind, a stale socket file is
/// removed first and the new one is chmod'ed 0600; unlike it, the
/// listener stays *blocking* (the broker blocks on `accept`).
pub fn bind_listener(path: &Path) -> io::Result<UnixListener> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            let _ = std::fs::remove_file(path);
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
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    Ok(listener)
}

/// Take the socket handed by systemd socket activation (LISTEN_FDS),
/// if any.
pub fn take_activated_socket() -> Option<UnixListener> {
    sd_notify::listen_fds()
        .ok()
        .and_then(|mut it| it.next())
        .map(|fd| {
            // SAFETY: listen_fds() consumed the LISTEN_* environment
            // variables, so this process is the sole user of the fd.
            unsafe { UnixListener::from_raw_fd(fd) }
        })
}

/// Run the broker until killed: service both sockets on a
/// `poll(2)` loop. Each proxy connection gets its own thread (a
/// prompt waiting on the user parks that thread on a condvar), so
/// the main thread stays free to accept the next request and to
/// service the session decision socket — which is what lets several
/// prompts be pending at once.
pub fn run(args: &BrokerArgs, listener: UnixListener) -> io::Result<()> {
    // The decision socket is only meaningful in interactive mode: an
    // auto-deciding broker never prompts, so it never binds one.
    let (decision, core) = if args.auto_decide.is_some() {
        (None, Arc::new(BrokerCore::new()))
    } else {
        let _ = std::fs::create_dir_all(&args.runtime_dir);
        // The runtime dir is user-private: the decision socket
        // inside must stay that way even if the directory pre-existed
        // with a looser mode.
        let _ = std::fs::set_permissions(&args.runtime_dir, std::fs::Permissions::from_mode(0o700));
        let path = args.runtime_dir.join(DECISION_SOCKET);
        match bind_decision_socket(&path) {
            Ok(l) => (Some(l), Arc::new(BrokerCore::new())),
            Err(e) => {
                warn!(
                    "broker: binding the decision socket {path:?} failed: {e}; \
                     interactive prompts will be denied at once (no-decision-socket) instead of waited on"
                );
                (None, Arc::new(BrokerCore::new_degraded()))
            }
        }
    };
    if decision.is_some() {
        let path = args.runtime_dir.join(DECISION_SOCKET);
        info!(
            "prompt broker: deciding by the user on the decision socket {path:?} \
             (waiting up to {} per prompt)",
            args.timeout.as_millis()
        );
    } else {
        info!(
            "prompt broker: deciding {} (waiting up to {} for the user)",
            match args.auto_decide {
                Some(AutoDecide::Allow) => "allow (auto)",
                Some(AutoDecide::Deny) => "deny (auto)",
                // Interactive, but the decision socket could not be
                // bound: prompts deny at once instead of hanging.
                None => "by the user (degraded: no decision socket)",
            },
            args.timeout.as_millis()
        );
    }
    loop {
        let mut polls = Vec::with_capacity(2);
        polls.push(PollFd::new(&listener, PollFlags::IN));
        let has_decision = decision.is_some();
        if has_decision {
            // `decision` lives for the whole loop, so the borrow
            // into `polls` (and the later `accept`) always holds.
            polls.push(PollFd::new(
                decision.as_ref().expect("checked by has_decision"),
                PollFlags::IN,
            ));
        }
        match poll(&mut polls, None) {
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => {
                return Err(io::Error::other(format!(
                    "polling the broker sockets failed: {e}"
                )));
            }
            Ok(_) => {
                // Index 0 is always the broker (proxy) listener:
                // each connection runs on its own thread.
                if polls[0].revents().intersects(PollFlags::IN) {
                    match listener.accept() {
                        Ok((stream, addr)) => {
                            info!("broker request from {addr:?}");
                            let args = args.clone();
                            let core = core.clone();
                            thread::spawn(move || handle_connection(stream, &args, &core));
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(e) => {
                            return Err(io::Error::other(format!(
                                "accepting on the broker socket failed: {e}"
                            )));
                        }
                    }
                }
                // Index 1 (when present) is the decision listener:
                // the decider is a trusted local CLI, serviced right
                // here on the main thread.
                if has_decision
                    && let Some(d) = decision.as_ref()
                    && polls[1].revents().intersects(PollFlags::IN)
                    && let Ok((stream, _)) = d.accept()
                {
                    handle_decider(stream, &core);
                }
            }
        }
    }
}

/// Service one decider (`wlsctx --decide`) connection on the session
/// decision socket: read one request line, dispatch (`list` or
/// `decide`), write one reply line, and close. Runs on the main
/// thread: the decider is a trusted local CLI that sends its line
/// on connect, and [`DECIDER_READ_TIMEOUT`] bounds how long a stuck
/// one can hold the loop.
fn handle_decider(mut stream: UnixStream, core: &BrokerCore) {
    let _ = stream.set_read_timeout(Some(DECIDER_READ_TIMEOUT));
    let mut line = String::new();
    if read_line(&mut stream, &mut line).is_err() || line.is_empty() {
        warn!("broker: the decision connection timed out or closed before a line; ignoring");
        return;
    }
    let reply = match decode_decider_request(&line) {
        Ok(req) => match req.kind.as_str() {
            LIST_KIND => encode_pending_list(&PendingList {
                v: PROTOCOL_VERSION,
                kind: PENDING_KIND.to_string(),
                prompts: core.pending_view(),
            }),
            // A decide request: resolve the targeted prompt (or the
            // oldest) and confirm — or refuse with a reason.
            _ => match parse_decision(req.decision.as_deref().unwrap_or("")) {
                Ok(d) => {
                    let name = decision_name(&d).to_string();
                    match core.decide(req.prompt, d) {
                        Ok(id) => encode_resolution(&Resolution {
                            v: PROTOCOL_VERSION,
                            kind: RESOLVED_KIND.to_string(),
                            prompt: id,
                            decision: name,
                        }),
                        Err(reason) => {
                            info!("decide refused: {reason}");
                            encode_error_reply(&ErrorReply {
                                v: PROTOCOL_VERSION,
                                kind: ERROR_KIND.to_string(),
                                prompt: req.prompt,
                                reason: reason.to_string(),
                            })
                        }
                    }
                }
                Err(e) => {
                    warn!("broker: rejecting the decide request: {e}");
                    encode_error_reply(&ErrorReply {
                        v: PROTOCOL_VERSION,
                        kind: ERROR_KIND.to_string(),
                        prompt: None,
                        reason: REASON_PROTOCOL.to_string(),
                    })
                }
            },
        },
        Err(e) => {
            warn!("broker: rejecting the decider's line: {e}");
            encode_error_reply(&ErrorReply {
                v: PROTOCOL_VERSION,
                kind: ERROR_KIND.to_string(),
                prompt: None,
                reason: REASON_PROTOCOL.to_string(),
            })
        }
    };
    if let Ok(reply) = reply {
        let _ = stream.write_all(reply.as_bytes());
    }
}

/// Handle one request connection to completion. Never fails the
/// broker: a bad request gets a `deny` answer, a dead proxy a
/// dropped reply, and the loop continues. Runs on the connection's
/// own thread (spawned by [`run`]); public so that tests can drive
/// the daemon's per-connection path without its accept loop.
///
/// The line's `kind` decides the handling path: a *consent request*
/// (`clipboard-read`) is answered (the connection stays open until
/// the decision — on the user, via the session decision socket, or on
/// the deadline) and a *copy-out notification* (`clipboard-write`)
/// fires a desktop notification and closes with no reply.
pub fn handle_connection(mut stream: UnixStream, args: &BrokerArgs, core: &BrokerCore) {
    let _ = stream.set_read_timeout(Some(args.timeout));
    let mut line = String::new();
    if read_line(&mut stream, &mut line).is_err() || line.is_empty() {
        warn!("broker: the request connection closed before a line; ignoring");
        return;
    }
    let kind = match decode_envelope(&line) {
        Ok(env) => env.kind,
        Err(e) => {
            warn!("broker: rejecting the request: {e}");
            deny_reply(&mut stream, "protocol");
            return;
        }
    };
    match kind.as_str() {
        REQUEST_KIND => {
            let req = match decode_request(&line) {
                Ok(req) => req,
                Err(e) => {
                    warn!("broker: rejecting the request: {e}");
                    deny_reply(&mut stream, "protocol");
                    return;
                }
            };
            handle_read(&mut stream, &req, args, core);
        }
        // One-way: fire the notification, close, no reply.
        NOTIFY_KIND => {
            let note = match decode_notification(&line) {
                Ok(note) => note,
                Err(e) => {
                    warn!("broker: dropping the notification: {e}");
                    return;
                }
            };
            handle_write(&note);
        }
        _ => {
            warn!("broker: unknown request kind {kind:?}");
            deny_reply(&mut stream, "unknown-kind");
        }
    }
}

/// The consent path (a `clipboard-read` request): decide, then answer.
fn handle_read(stream: &mut UnixStream, req: &ClipboardRead, args: &BrokerArgs, core: &BrokerCore) {
    info!(
        "consent request: app {}/{} wants to read the {} (`{}`; its own reads were never asked about)",
        req.app,
        req.instance,
        selection_name(&req.selection),
        req.mime
    );

    let decision = match args.auto_decide {
        Some(AutoDecide::Allow) => Decision::Allow {
            window_ms: INTENT_WINDOW_MS,
        },
        Some(AutoDecide::Deny) => Decision::Deny {
            reason: "auto".into(),
        },
        // Interactive, but the session decision socket could not be
        // bound: deny at once rather than hanging on a prompt nobody
        // can answer (the old per-prompt bind failure behaved the
        // same way, per prompt).
        None if core.is_degraded() => Decision::Deny {
            reason: "no-decision-socket".into(),
        },
        None => decide_interactive(req, args, core),
    };

    let answered = match encode_decision(&decision) {
        Ok(answer) => stream.write_all(answer.as_bytes()).is_ok(),
        Err(_) => false,
    };
    if !answered {
        // The proxy gave up on us (its own deadline expired): the
        // decision is moot, the read was dropped over there.
        warn!(
            "broker: the request connection is gone; the {} decision is moot",
            decision_reason(&decision)
        );
    } else {
        info!(
            "clipboard consent: {} ({})",
            decision_reason(&decision),
            decision_detail(&decision)
        );
    }
}

/// The copy-out path (a `clipboard-write` notification, Phase 6):
/// announce the write to the desktop. One-way — no decision, no
/// intent window, no reply. Fire-and-forget: a missing `notify-send`
/// or an unreachable session bus just loses the notice.
fn handle_write(note: &ClipboardWrite) {
    info!(
        "copy-out notification: app {}/{} wrote to the {}",
        note.app,
        note.instance,
        selection_name(&note.selection)
    );
    announce_write(note);
}

/// A `deny` reply to a request-shaped line (the only reply such a
/// line can receive; a notification gets none).
fn deny_reply(stream: &mut UnixStream, reason: &str) {
    if let Ok(answer) = encode_decision(&Decision::Deny {
        reason: reason.to_string(),
    }) {
        let _ = stream.write_all(answer.as_bytes());
    }
}

fn decision_reason(d: &Decision) -> &'static str {
    match d {
        Decision::Allow { .. } => "allow",
        Decision::Deny { .. } => "deny",
    }
}

fn decision_detail(d: &Decision) -> String {
    match d {
        Decision::Allow { window_ms } => format!("intent window {window_ms} ms"),
        Decision::Deny { reason } => format!("reason: {reason}"),
    }
}

/// The real prompt: register the request in the session queue (a
/// prompt the decider can list or target by id), announce it to the
/// desktop, and wait for the user's decision — recorded by the main
/// loop on the session decision socket — or the deadline (a timeout
/// is a deny).
fn decide_interactive(req: &ClipboardRead, args: &BrokerArgs, core: &BrokerCore) -> Decision {
    let prompt = core.add_prompt(req, args.timeout);
    announce(req, prompt.id, &args.runtime_dir.join(DECISION_SOCKET));

    // Wait for the user's decision (the main loop records it on the
    // prompt and wakes it) or the deadline.
    let mut guard = prompt.decision.lock().unwrap();
    let answer = loop {
        if let Some(d) = *guard {
            break Some(d);
        }
        let remaining = prompt.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break None;
        }
        // A wake before the deadline (spurious or otherwise) just
        // re-checks; the deadline is absolute, so this loop always
        // ends by it.
        guard = prompt.waker.wait_timeout(guard, remaining).unwrap().0;
    };
    drop(guard);
    // The prompt is out of the queue now: `decide` has already
    // removed a decided one, and this covers the timeout path.
    core.remove(prompt.id);
    match answer {
        Some(UserDecision::Allow) => Decision::Allow {
            window_ms: INTENT_WINDOW_MS,
        },
        Some(UserDecision::Deny) => Decision::Deny {
            reason: "user".into(),
        },
        None => Decision::Deny {
            reason: "timeout".into(),
        },
    }
}

/// Bind the session decision socket, removing a stale file first.
/// Bound once per session (in [`run`]); a stale file left by a
/// crashed broker session is replaced.
fn bind_decision_socket(path: &Path) -> io::Result<UnixListener> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            let _ = std::fs::remove_file(path);
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("{path:?} exists and is not a socket"),
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    Ok(listener)
}

/// The human-facing name of the selection a request is about
/// (`"primary"` is the X-style primary selection; anything else —
/// including an unknown value from a future protocol — reads as the
/// plain clipboard).
fn selection_name(s: &str) -> &'static str {
    if s == "primary" {
        "primary selection (middle-click paste)"
    } else {
        "clipboard"
    }
}

/// Tell the desktop about the pending prompt (carrying its id, so a
/// busy session can be answered without a prior listing).
/// Fire-and-forget: if `notify-send` is missing or the session bus is
/// unreachable the user can still answer — the prompt is listed by
/// `wlsctx --decide` on the session decision socket (whose path is
/// logged).
fn announce(req: &ClipboardRead, prompt_id: u32, decision_path: &Path) {
    let summary = "wlsctx: clipboard consent";
    let body = format!(
        "The sandboxed app {}/{} wants to read your {} (`{}`).\n\
         Prompt #{prompt_id} — reply: wlsctx --decide --prompt {prompt_id} --decision=allow (or =deny)",
        req.app,
        req.instance,
        selection_name(&req.selection),
        req.mime
    );
    info!(
        "waiting for the user's decision (prompt #{prompt_id}; the decider answers on {decision_path:?})"
    );
    match process::Command::new("notify-send")
        .args(["--app-name", "wlsctx", summary, &body])
        .spawn()
    {
        Ok(_) => {}
        Err(e) => warn!("notify-send failed ({e}); the prompt is on the decision socket only"),
    }
}

/// Tell the desktop that a sandboxed app just wrote to a selection
/// (Phase 6, copy-*out*). Fire-and-forget: a missing `notify-send` or
/// an unreachable session bus simply loses the notice; the write
/// itself is unaffected (it never waited on this).
fn announce_write(note: &ClipboardWrite) {
    let summary = "wlsctx: clipboard write (copy-out)";
    let body = format!(
        "The sandboxed app {}/{} just placed data on your {}.\n\
         (copy-out only — it was not asked to read anything from the host)",
        note.app,
        note.instance,
        selection_name(&note.selection)
    );
    match process::Command::new("notify-send")
        .args(["--app-name", "wlsctx", summary, &body])
        .spawn()
    {
        Ok(_) => {}
        Err(e) => {
            warn!("notify-send failed ({e}); the copy-out notice is lost (the write is unaffected)")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> ClipboardRead {
        ClipboardRead {
            v: PROTOCOL_VERSION,
            kind: REQUEST_KIND.to_string(),
            app: "jetbrains".into(),
            instance: "rustrover".into(),
            mime: "text/plain".into(),
            selection: "primary".into(),
        }
    }

    #[test]
    fn request_roundtrip() {
        let r = sample_request();
        let line = encode_request(&r).unwrap();
        assert!(line.ends_with('\n'));
        assert_eq!(decode_request(&line).unwrap(), r);
    }

    #[test]
    fn request_without_selection_field_defaults_to_clipboard() {
        // An older peer (pre-Phase-5) does not send the field: the
        // decode must still succeed and read as the plain clipboard.
        let line =
            r#"{"v":1,"kind":"clipboard-read","app":"a","instance":"i","mime":"text/plain"}"#;
        let r = decode_request(line).unwrap();
        assert_eq!(r.selection, "clipboard");
    }

    #[test]
    fn request_rejects_other_versions_and_kinds() {
        let mut r = sample_request();
        r.v = 2;
        assert!(decode_request(&encode_request(&r).unwrap()).is_err());
        let mut r = sample_request();
        r.kind = "something-else".into();
        assert!(decode_request(&encode_request(&r).unwrap()).is_err());
    }

    fn sample_notification() -> ClipboardWrite {
        ClipboardWrite {
            v: PROTOCOL_VERSION,
            kind: NOTIFY_KIND.to_string(),
            app: "jetbrains".into(),
            instance: "rustrover".into(),
            selection: "primary".into(),
        }
    }

    #[test]
    fn notification_roundtrip() {
        let n = sample_notification();
        let line = encode_notification(&n).unwrap();
        assert!(line.ends_with('\n'));
        assert_eq!(decode_notification(&line).unwrap(), n);
    }

    #[test]
    fn notification_without_selection_defaults_to_clipboard() {
        let line = r#"{"v":1,"kind":"clipboard-write","app":"a","instance":"i"}"#;
        let n = decode_notification(line).unwrap();
        assert_eq!(n.selection, "clipboard");
    }

    #[test]
    fn notification_rejects_other_kinds_and_versions() {
        let mut n = sample_notification();
        n.v = 2;
        assert!(decode_notification(&encode_notification(&n).unwrap()).is_err());
        let mut n = sample_notification();
        n.kind = "clipboard-read".into();
        assert!(decode_notification(&encode_notification(&n).unwrap()).is_err());
    }

    #[test]
    fn envelope_sniffs_the_kind() {
        // The daemon sniffs the kind before a full decode; both kinds
        // carry a `kind` field, so the envelope is enough to dispatch.
        assert_eq!(
            decode_envelope(&encode_request(&sample_request()).unwrap())
                .unwrap()
                .kind,
            REQUEST_KIND
        );
        assert_eq!(
            decode_envelope(&encode_notification(&sample_notification()).unwrap())
                .unwrap()
                .kind,
            NOTIFY_KIND
        );
        // A line with no `kind` field cannot be dispatched.
        assert!(decode_envelope(r#"{"v":1}"#).is_err());
    }

    #[test]
    fn decision_roundtrip() {
        let a = Decision::Allow {
            window_ms: INTENT_WINDOW_MS,
        };
        let d = Decision::Deny {
            reason: "timeout".into(),
        };
        assert_eq!(decode_decision(&encode_decision(&a).unwrap()).unwrap(), a);
        assert_eq!(decode_decision(&encode_decision(&d).unwrap()).unwrap(), d);
        // The on-the-wire shape: tagged enum, snake_case.
        assert_eq!(
            encode_decision(&a).unwrap().trim(),
            r#"{"decision":"allow","window_ms":1500}"#
        );
    }

    #[test]
    fn user_decision_roundtrip() {
        assert_eq!(
            decode_user_decision(&encode_user_decision(&UserDecision::Allow).unwrap()).unwrap(),
            UserDecision::Allow
        );
        assert_eq!(
            encode_user_decision(&UserDecision::Deny).unwrap().trim(),
            r#"{"decision":"deny"}"#
        );
        assert!(decode_user_decision("nonsense").is_err());
    }

    /// A `clipboard-write` line through the daemon's real per-connection
    /// path (`handle_connection`): it must be handled without error and
    /// produce **no reply** (the notification is one-way; the stream
    /// closes with no decision line).
    #[test]
    fn handle_connection_serves_a_notification_without_a_reply() {
        use std::io::Read as _;

        let (mut client, broker_end) = UnixStream::pair().unwrap();
        client
            .write_all(
                encode_notification(&sample_notification())
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap();
        // A notification never touches the runtime dir (no decision
        // socket); the args and the core here are inert for this
        // path.
        let args = BrokerArgs {
            runtime_dir: std::env::temp_dir().join("wlsctx-broker-nt-test"),
            auto_decide: None,
            timeout: Duration::from_secs(1),
        };
        handle_connection(broker_end, &args, &BrokerCore::new());

        // The client must see a clean EOF, not a decision line.
        let mut reply = String::new();
        client.read_to_string(&mut reply).unwrap();
        assert!(
            reply.trim().is_empty(),
            "a notification must not produce a reply, got: {reply:?}"
        );
    }

    #[test]
    fn parse_decision_cli() {
        assert_eq!(parse_decision("allow").unwrap(), UserDecision::Allow);
        assert_eq!(parse_decision("deny").unwrap(), UserDecision::Deny);
        assert!(parse_decision("maybe").is_err());
    }

    #[test]
    fn decider_request_roundtrip() {
        // The list line.
        let list = encode_list_request().unwrap();
        let r = decode_decider_request(&list).unwrap();
        assert_eq!(r.kind, LIST_KIND);
        assert!(r.decision.is_none());
        assert!(r.prompt.is_none());
        // A decide with no target (the oldest) and with one.
        let no_target = encode_decide_request(&UserDecision::Allow, None).unwrap();
        let r = decode_decider_request(&no_target).unwrap();
        assert_eq!(r.kind, DECIDE_KIND);
        assert_eq!(r.decision.as_deref(), Some("allow"));
        assert!(r.prompt.is_none());
        let targeted = encode_decide_request(&UserDecision::Deny, Some(7)).unwrap();
        let r = decode_decider_request(&targeted).unwrap();
        assert_eq!(r.decision.as_deref(), Some("deny"));
        assert_eq!(r.prompt, Some(7));
    }

    #[test]
    fn decider_request_rejects_bad_lines() {
        // A wrong version.
        assert!(decode_decider_request(r#"{"v":2,"kind":"list"}"#).is_err());
        // An unknown kind.
        assert!(decode_decider_request(r#"{"v":1,"kind":"bogus"}"#).is_err());
        // A decide without a decision.
        assert!(decode_decider_request(r#"{"v":1,"kind":"decide"}"#).is_err());
        // A decide with an unknown decision.
        assert!(decode_decider_request(r#"{"v":1,"kind":"decide","decision":"maybe"}"#).is_err());
    }

    #[test]
    fn pending_list_and_replies_roundtrip() {
        let list = PendingList {
            v: PROTOCOL_VERSION,
            kind: PENDING_KIND.to_string(),
            prompts: vec![PendingPromptView {
                id: 3,
                app: "jetbrains".into(),
                instance: "rustrover".into(),
                selection: "primary".into(),
                mime: "text/plain".into(),
                expires_in_ms: 2500,
            }],
        };
        let line = encode_pending_list(&list).unwrap();
        assert_eq!(decode_pending_list(&line).unwrap(), list);
        // A different kind is rejected by the decoder.
        let other_kind = encode_resolution(&Resolution {
            v: PROTOCOL_VERSION,
            kind: RESOLVED_KIND.to_string(),
            prompt: 1,
            decision: "allow".into(),
        })
        .unwrap();
        assert!(decode_pending_list(&other_kind).is_err());

        let resolution = Resolution {
            v: PROTOCOL_VERSION,
            kind: RESOLVED_KIND.to_string(),
            prompt: 3,
            decision: "allow".into(),
        };
        assert_eq!(
            decode_resolution(&encode_resolution(&resolution).unwrap()).unwrap(),
            resolution
        );

        // The error reply: `prompt` is present for a targeted fail and
        // omitted otherwise (skip_serializing_if).
        let with_prompt = ErrorReply {
            v: PROTOCOL_VERSION,
            kind: ERROR_KIND.to_string(),
            prompt: Some(9),
            reason: REASON_UNKNOWN_PROMPT.to_string(),
        };
        let line = encode_error_reply(&with_prompt).unwrap();
        assert!(line.contains("\"prompt\":9"));
        assert_eq!(decode_error_reply(&line).unwrap(), with_prompt);
        let without = ErrorReply {
            prompt: None,
            ..with_prompt.clone()
        };
        let line = encode_error_reply(&without).unwrap();
        assert!(!line.contains("\"prompt\""));
        assert_eq!(decode_error_reply(&line).unwrap(), without);
    }

    fn read_request(app: &str, mime: &str) -> ClipboardRead {
        ClipboardRead {
            v: PROTOCOL_VERSION,
            kind: REQUEST_KIND.to_string(),
            app: app.into(),
            instance: "instance".into(),
            mime: mime.into(),
            selection: "clipboard".into(),
        }
    }

    #[test]
    fn core_decide_targets_oldest_by_default() {
        let core = BrokerCore::new();
        let a = core.add_prompt(&read_request("app-a", "text/plain"), Duration::from_secs(5));
        let b = core.add_prompt(
            &read_request("app-b", "text/uri-list"),
            Duration::from_secs(5),
        );
        assert_eq!(a.id, 1);
        assert_eq!(b.id, 2);
        // Untargeted: the oldest (id 1) resolves; the newest survives.
        assert_eq!(core.decide(None, UserDecision::Allow).unwrap(), 1);
        assert_eq!(core.decide(None, UserDecision::Deny).unwrap(), 2);
        assert!(core.pending_view().is_empty());
        assert_eq!(
            core.decide(None, UserDecision::Allow),
            Err(REASON_NO_PENDING)
        );
    }

    #[test]
    fn core_decide_targets_explicit_id() {
        let core = BrokerCore::new();
        core.add_prompt(&read_request("app-a", "text/plain"), Duration::from_secs(5));
        core.add_prompt(
            &read_request("app-b", "text/uri-list"),
            Duration::from_secs(5),
        );
        // Explicit: the newest first, then the rest is oldest-first.
        assert_eq!(core.decide(Some(2), UserDecision::Allow).unwrap(), 2);
        assert_eq!(core.decide(None, UserDecision::Deny).unwrap(), 1);
        // The decided id is gone from the queue: a second decide for
        // it is a clean unknown-prompt, never a double resolution.
        assert_eq!(
            core.decide(Some(2), UserDecision::Allow),
            Err(REASON_UNKNOWN_PROMPT)
        );
    }

    #[test]
    fn core_decide_unknown_id_on_an_empty_queue() {
        let core = BrokerCore::new();
        assert_eq!(
            core.decide(Some(1), UserDecision::Allow),
            Err(REASON_UNKNOWN_PROMPT)
        );
    }

    #[test]
    fn core_pending_view_and_remove() {
        let core = BrokerCore::new();
        let p = core.add_prompt(&read_request("app-a", "text/plain"), Duration::from_secs(5));
        let view = core.pending_view();
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].id, 1);
        assert_eq!(view[0].app, "app-a");
        assert_eq!(view[0].mime, "text/plain");
        // The full window is (roughly) there.
        assert!(view[0].expires_in_ms >= 4_900 && view[0].expires_in_ms <= 5_000);
        // Removing a missing id is a no-op; removing the real one empties
        // the view.
        core.remove(99);
        assert_eq!(core.pending_view().len(), 1);
        core.remove(p.id);
        assert!(core.pending_view().is_empty());
    }

    /// The interactive consent path in-process: the connection thread
    /// registers the prompt in the core; when `decide`, the "user"
    /// (this test thread) records a decision on it; either way the
    /// proxy-side stream receives the answer.
    fn run_interactive_prompt(
        core: &Arc<BrokerCore>,
        req: &ClipboardRead,
        timeout: Duration,
        decide: bool,
    ) -> String {
        use std::io::{Read as _, Write as _};

        let (mut client, broker_end) = UnixStream::pair().unwrap();
        let args = BrokerArgs {
            runtime_dir: std::env::temp_dir().join("wlsctx-broker-it-test"),
            auto_decide: None,
            timeout,
        };
        // The proxy's request line, on the client side of the pair.
        let line = encode_request(req).unwrap();
        client.write_all(line.as_bytes()).unwrap();
        // The thread gets its own `Arc` clone; the caller's `Arc`
        // stays with the test thread (the reference must not outlive
        // this function).
        let core_for_thread = core.clone();
        let broker_thread =
            thread::spawn(move || handle_connection(broker_end, &args, &core_for_thread));
        // The prompt must be in the queue before the "user" answers;
        // bound the wait so a stuck thread fails the test, not the
        // machine.
        let started = Instant::now();
        while core.pending_view().is_empty() && started.elapsed() < Duration::from_secs(2) {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            !core.pending_view().is_empty(),
            "the prompt never reached the queue"
        );
        if decide {
            // The decider's decision, on the oldest (only) prompt.
            assert_eq!(core.decide(None, UserDecision::Allow).unwrap(), 1);
        }
        let mut reply = String::new();
        client.read_to_string(&mut reply).unwrap();
        broker_thread.join().unwrap();
        reply
    }

    #[test]
    fn interactive_prompt_is_answered_via_the_core() {
        let core = Arc::new(BrokerCore::new());
        let reply = run_interactive_prompt(
            &core,
            &read_request("app-a", "text/plain"),
            Duration::from_secs(5),
            true,
        );
        assert_eq!(
            decode_decision(&reply).unwrap(),
            Decision::Allow {
                window_ms: INTENT_WINDOW_MS
            }
        );
        // The prompt resolved: it is out of the queue again.
        assert!(core.pending_view().is_empty());
    }

    #[test]
    fn interactive_prompt_times_out_without_a_decision() {
        let core = Arc::new(BrokerCore::new());
        let reply = run_interactive_prompt(
            &core,
            &read_request("app-a", "text/plain"),
            Duration::from_millis(100),
            false,
        );
        assert_eq!(
            decode_decision(&reply).unwrap(),
            Decision::Deny {
                reason: "timeout".into()
            }
        );
        assert!(core.pending_view().is_empty());
    }

    /// A degraded core (the decision socket could not be bound): the
    /// prompt is denied at once, never waited on.
    #[test]
    fn degraded_core_denies_at_once() {
        use std::io::{Read as _, Write as _};

        let (mut client, broker_end) = UnixStream::pair().unwrap();
        let line = encode_request(&read_request("app-a", "text/plain")).unwrap();
        client.write_all(line.as_bytes()).unwrap();
        let args = BrokerArgs {
            runtime_dir: std::env::temp_dir().join("wlsctx-broker-degraded-test"),
            auto_decide: None,
            timeout: Duration::from_secs(30),
        };
        let core = BrokerCore::new_degraded();
        handle_connection(broker_end, &args, &core);
        let mut reply = String::new();
        client.read_to_string(&mut reply).unwrap();
        assert_eq!(
            decode_decision(&reply).unwrap(),
            Decision::Deny {
                reason: "no-decision-socket".into()
            }
        );
    }
}
