//! The selection receive-gate (Phase 3; extended in Phase 5).
//!
//! ## What it protects
//!
//! A `wl_data_offer.receive` request (stable protocol) — or its
//! primary-selection twin, `zwp_primary_selection_offer_v1.receive`
//! (`wp_primary_selection_unstable_v1`, the protocol wlroots/sway
//! implements for X-style primary selection) — hands an fd created
//! by the *app* to the compositor, and the compositor makes the
//! **current selection owner** write the selection data into that
//! fd. The owner may be the host desktop or another sandboxed app,
//! and what they write may include host secrets (passwords, tokens)
//! — exactly the data the sandbox must not reach. Both protocols
//! have the same shape (a `*device_manager` that creates `*source`
//! objects, a per-seat `*device` whose `set_selection` is echoed by
//! a `data_offer` + `selection` pair, and an `*offer` whose
//! `receive(mime, fd)` is the only request that hands an app-created
//! fd to the selection owner), so the gate inspects every
//! `receive` of both:
//!
//! * [`ClipboardPolicy::Allow`] (the default): pass-through — the
//!   request is relayed unchanged (subject to the fd sanity check
//!   below).
//! * [`ClipboardPolicy::Deny`]: the request is relayed only if the
//!   data being read is provably the app's own — a read-back of the
//!   selection the app itself put on the clipboard. The app already
//!   has that data (it served it to the compositor from its own
//!   source), so the read-back leaks nothing and keeps the app's
//!   own copy/paste working. Every other read is **dropped
//!   silently**: the compositor never serves it, the app's fd stays
//!   empty (an immediate EOF for the standard memfd), and the app
//!   sees an empty clipboard read instead of crashing.
//!
//! ## Proving the origin
//!
//! Neither protocol has a "who owns this selection" field: the
//! `selection` event carries an *offer* object — which the
//! compositor creates separately on *every* client connection — not
//! the source behind it. The proof is temporal, and it is sound
//! under the threat model (the attacker is the *sandboxed* app; the
//! other clients on the desktop are the user's own, trusted
//! applications):
//!
//! * The gate tracks every source this client created —
//!   `wl_data_device_manager.create_data_source` (stable) and
//!   `zwp_primary_selection_device_manager_v1.create_source`
//!   (primary) — such an object can only ever serve the client's
//!   own data.
//! * When the client sends its own source as the new selection
//!   (`wl_data_device.set_selection`/`start_drag`, or
//!   `zwp_primary_selection_device_v1.set_selection`), the gate
//!   marks the *next* offer that protocol announces (`data_offer`)
//!   as **own**; the compositor echoes selection changes in the
//!   order they happened, so that next `data_offer` + `selection`
//!   pair is precisely the app's own change. The two protocols
//!   echo independently, so their pendings never cross: a stable
//!   `set_selection` cannot attribute a primary `data_offer`, and
//!   vice versa.
//! * Every other offer is **foreign**, including drag-and-drop
//!   offers (announced before a `wl_data_device.enter` — the
//!   primary-selection protocol has no drag), so a foreign drag
//!   cannot feed the sandbox either.
//!
//! A compromised app cannot forge the proof: it can only create its
//! own sources and observe compositor events, and an offer is marked
//! own only if the compositor actually echoed *that app's*
//! `set_selection`/`start_drag` as the new selection of that
//! protocol. (The one inescapable race — a hostile *other* client
//! winning a selection-change race in the microseconds between the
//! app's request and the compositor processing it — inverts at most
//! one attribution, and such a client is outside the threat model.
//! For the primary selection the compositor sends the confirming
//! `selection` only to the keyboard-focused client; if the app is
//! not focused when it sets its own source the echo goes elsewhere,
//! the app simply cannot read it back — which is no worse than the
//! protocol itself providing.)
//!
//! ## The fd sanity check (always on, both policies)
//!
//! Regardless of policy, the fd of a `receive` must be an
//! **ephemeral in-memory channel**: a memfd, an anonymous pipe, or a
//! socket. The fd has been passed to the proxy (SCM_RIGHTS), so the
//! kernel tells us what it is: `/proc/self/fd/<n>` reads
//! `memfd:…` (or, on newer kernels, `/memfd:… (deleted)`),
//! `pipe:[…]`, or `socket:[…]` for those, and a path for anything
//! else. Anything else — a regular file, a named fifo, a device — is
//! rejected and the connection is torn down. Compositors
//! do not inspect the fd they are handed (wlroots passes it straight
//! to the selection owner to write into), so without this check a
//! sandboxed app could direct clipboard data into a path in its own
//! mount space — including the *shared* `downloads` volume every pod
//! mounts — persisting host data to disk where the host and other
//! sandboxes can read it, instead of keeping it in memory where it
//! dies with the app.
//!
//! ## The consent window (Phase 4)
//!
//! [`ClipboardGate::unlock`] opens the gate for foreign reads —
//! of *either* protocol — until a given instant. The prompt broker
//! (Phase 4) calls it with the 1500 ms "intent window" when the
//! user approves one read by the sandboxed app; the window is
//! selection-wide on purpose, so an approved paste covers the burst
//! of follow-on reads (one `receive` per mime type, or retries)
//! without re-prompting for each of them.

use std::collections::HashSet;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::time::Instant;

use log::info;
use wayland_backend::protocol::{Argument, Interface, Message, MessageDesc};

use super::ForwardAction;
use super::objects::Dir;

/// The clipboard policy for sandboxed clients.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClipboardPolicy {
    /// Pass-through (the default): `wl_data_offer.receive` requests
    /// are relayed unchanged (subject to the fd sanity check).
    Allow,
    /// A `receive` is relayed only if the data it reads is provably
    /// the app's own (a read-back of a selection or drag the app
    /// itself set); every other read is dropped.
    Deny,
}

impl ClipboardPolicy {
    /// Parse a policy from the command line / environment.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            other => Err(format!(
                "unknown clipboard policy {other:?} (expected `allow` or `deny`)"
            )),
        }
    }

    /// Whether the policy actually filters (for startup logging).
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Deny)
    }
}

/// Who the data behind an offer belongs to, as the proxy sees it on
/// this connection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Origin {
    /// The source object was created by this (sandboxed) client:
    /// reading the offer can only return the client's own data.
    Own,
    /// The source belongs to another client (or is unknown): the
    /// data is host/foreign and must not reach the sandbox.
    Foreign,
}

impl Origin {
    /// The audit spelling (Phase 9).
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Own => "own",
            Self::Foreign => "foreign",
        }
    }
}

/// The gate's attribution of the data a `read` pulls in, with the
/// audit's third state: `Unknown` (no attribution yet — the read
/// arrived before the protocol told us who owns the selection).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum OriginInfo {
    /// The offer is one the gate attributed to this client (or the
    /// current selection's owner is this client).
    Own,
    /// The data belongs to another client (the host desktop, or
    /// another sandboxed app).
    Foreign,
    /// The gate has no attribution yet (a read before any
    /// `selection` event, or of an offer it never saw announced).
    Unknown,
}

impl OriginInfo {
    /// The audit spelling (Phase 9).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Own => "own",
            Self::Foreign => "foreign",
            Self::Unknown => "unknown",
        }
    }
}

/// The class of an in-memory channel an fd refers to, per the
/// kernel's `/proc/self/fd/<n>` symlink: `memfd` (an anonymous file
/// — the only class that *reports a size*), `pipe` (an anonymous
/// pipe), or `socket` (a unix socket).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum FdKind {
    Memfd,
    Pipe,
    Socket,
}

impl FdKind {
    /// The audit spelling (Phase 9).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Memfd => "memfd",
            Self::Pipe => "pipe",
            Self::Socket => "socket",
        }
    }
}

/// What a client request the gate is waiting to be echoed: the next
/// `data_offer` event is attributed to the request of this kind,
/// consumed by the matching confirming event (`selection` for a
/// `set_selection`, `enter` for a `start_drag`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PendingKind {
    Selection,
    Drag,
}

/// The per-connection clipboard gate: the shared policy plus the
/// origin state the proxy infers from the protocol traffic it is on
/// the path of.
pub struct ClipboardGate {
    policy: ClipboardPolicy,
    /// Sources this client created (`wl_data_device_manager.
    /// create_data_source`); a `set_selection`/`start_drag` with one
    /// of these is attributable to this client and nothing else.
    own_sources: HashSet<u32>,
    /// The client's last own `set_selection`/`start_drag`, awaiting
    /// the compositor's echo.
    pending: Option<PendingKind>,
    /// The origin of the current clipboard selection (the last
    /// `selection` event). Informational; the Phase 4 broker prompt
    /// reports it to the user.
    selection: Option<Origin>,
    /// Primary-selection sources this client created
    /// (`zwp_primary_selection_device_manager_v1.create_source`).
    /// Phase 5: the `wp_primary_selection_unstable_v1` twin of
    /// `own_sources` (its pendings never cross, see the module docs).
    own_psel_sources: HashSet<u32>,
    /// The client's last own `zwp_primary_selection_device_v1.
    /// set_selection`, awaiting the compositor's echo.
    pending_psel: bool,
    /// The origin of the current primary selection (the last zwp
    /// `selection` event). Informational, like `selection`.
    primary_selection: Option<Origin>,
    /// The offers the gate has attributed to this client — of
    /// *either* protocol (recorded when a `data_offer` event
    /// follows one of the client's own selection-setting requests,
    /// removed when the client destroys the offer; object IDs are
    /// unique per connection, so one set serves both protocols).
    own_offers: HashSet<u32>,
    /// Phase 4 hook: while set and in the future, even foreign reads
    /// (either protocol) are allowed (the user's approved intent
    /// window).
    unlocked_until: Option<Instant>,
}

/// The gate's decision on one `receive`, with the facts the
/// audit record (Phase 9) needs alongside the action: the
/// receive fd's class, and the attribution of the data the read
/// pulls in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct ReceiveDecision {
    /// Relay the request as-is, or consume it (the app's fd
    /// stays empty and the read comes back empty).
    pub action: ForwardAction,
    /// The receive fd's class (the always-on sanity check
    /// guarantees it is an in-memory channel).
    pub fd_kind: FdKind,
    /// Who the data behind this read belongs to.
    pub origin: OriginInfo,
}

/// What a client `set_selection` does to the selection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SelectionWrite {
    /// A non-NULL source: the app is placing data on the
    /// selection — data now reachable by every client on the
    /// desktop, i.e. a copy-*out* (the read-gate and the
    /// broker's consent flow cover the copy-*in* direction).
    Set,
    /// A NULL source: the app is clearing the selection.
    Clear,
}

impl ClipboardGate {
    pub fn new(policy: ClipboardPolicy) -> Self {
        Self {
            policy,
            own_sources: HashSet::new(),
            pending: None,
            selection: None,
            own_psel_sources: HashSet::new(),
            pending_psel: false,
            primary_selection: None,
            own_offers: HashSet::new(),
            unlocked_until: None,
        }
    }

    /// The origin of the current clipboard selection, if any.
    ///
    /// Phase 4 hook: the prompt broker reports it to the user when
    /// asking for consent to a foreign read. Phase 9: the `clear`
    /// audit record carries it (the origin of the selection that was
    /// removed).
    pub(crate) fn selection_origin(&self) -> Option<Origin> {
        self.selection
    }

    /// The origin of the current primary selection, if any (Phase
    /// 5). Same use as [`Self::selection_origin`].
    pub(crate) fn primary_selection_origin(&self) -> Option<Origin> {
        self.primary_selection
    }

    /// The Phase 4 hook: allow all reads — including foreign ones —
    /// until `until` (the user's approved intent window).
    pub fn unlock(&mut self, until: Instant) {
        self.unlocked_until = Some(until);
    }

    /// Observe a relayed message (everything, including the
    /// `wl_data_offer.receive` request the gate itself decides on,
    /// which is a no-op for the state): update the origin state. The
    /// observed message is always forwarded by the caller — the gate
    /// only inspects, it never hides events.
    pub(super) fn observe(
        &mut self,
        dir: Dir,
        sender: &Interface,
        desc: &MessageDesc,
        msg: &Message<u32, OwnedFd>,
    ) {
        match (dir, sender.name, desc.name) {
            (Dir::ClientToServer, "wl_data_device_manager", "create_data_source") => {
                // The NewId is the first argument of the request.
                if let Some(Argument::NewId(id)) = msg.args.first()
                    && *id != 0
                {
                    self.own_sources.insert(*id);
                }
            }
            (Dir::ClientToServer, "wl_data_source", "destroy") => {
                self.own_sources.remove(&msg.sender_id);
            }
            (Dir::ClientToServer, "wl_data_device", "set_selection")
            | (Dir::ClientToServer, "wl_data_device", "start_drag") => {
                let kind = if desc.name == "set_selection" {
                    PendingKind::Selection
                } else {
                    PendingKind::Drag
                };
                // The source is the first argument of both requests
                // (`allow-null`): a NULL source (a clear) or one the
                // client does not own cannot be attributed to it.
                self.pending = match msg.args.first() {
                    Some(Argument::Object(id)) if self.own_sources.contains(id) => Some(kind),
                    _ => None,
                };
            }
            (Dir::ServerToClient, "wl_data_device", "data_offer") => {
                // The new offer is the first argument; attribute it
                // to the pending request if one is live (the
                // compositor echoes changes in the order they
                // happened, so this data_offer is that request's
                // announcement).
                if let Some(Argument::NewId(id)) = msg.args.first()
                    && *id != 0
                    && self.pending.is_some()
                {
                    self.own_offers.insert(*id);
                }
            }
            (Dir::ServerToClient, "wl_data_device", "selection") => {
                // A new selection: the pending attribution — whatever
                // it was — is consumed by this echo.
                let offer = match msg.args.first() {
                    // NULL: the selection was cleared.
                    None | Some(Argument::Object(0)) => {
                        self.selection = None;
                        self.pending = None;
                        return;
                    }
                    Some(Argument::Object(id)) => *id,
                    // Malformed; the parse would have failed — fail
                    // safe either way.
                    _ => {
                        self.selection = None;
                        self.pending = None;
                        return;
                    }
                };
                self.selection = Some(if self.own_offers.contains(&offer) {
                    Origin::Own
                } else {
                    Origin::Foreign
                });
                self.pending = None;
            }
            (Dir::ServerToClient, "wl_data_device", "enter") => {
                // A drag-and-drop session (re)starts: the pending
                // `start_drag` (if any) is consumed by this echo.
                self.pending = None;
            }
            (Dir::ClientToServer, "wl_data_offer", "destroy") => {
                self.own_offers.remove(&msg.sender_id);
            }
            // ---- Phase 5: the primary-selection protocol
            // (wp_primary_selection_unstable_v1, the zwp_* family).
            // Structurally the same origin proof, on its own
            // echo sequence.
            (Dir::ClientToServer, "zwp_primary_selection_device_manager_v1", "create_source") => {
                if let Some(Argument::NewId(id)) = msg.args.first()
                    && *id != 0
                {
                    self.own_psel_sources.insert(*id);
                }
            }
            (Dir::ClientToServer, "zwp_primary_selection_source_v1", "destroy") => {
                self.own_psel_sources.remove(&msg.sender_id);
            }
            (Dir::ClientToServer, "zwp_primary_selection_device_v1", "set_selection") => {
                // The source is the first argument (`allow-null`): a
                // NULL source (a clear) or one the client does not
                // own cannot be attributed to it.
                self.pending_psel = matches!(
                    msg.args.first(),
                    Some(Argument::Object(id)) if self.own_psel_sources.contains(id)
                );
            }
            (Dir::ServerToClient, "zwp_primary_selection_device_v1", "data_offer") => {
                if let Some(Argument::NewId(id)) = msg.args.first()
                    && *id != 0
                    && self.pending_psel
                {
                    self.own_offers.insert(*id);
                }
            }
            (Dir::ServerToClient, "zwp_primary_selection_device_v1", "selection") => {
                // A new primary selection (or a NULL: cleared, or
                // the app lost keyboard focus — the protocol sends
                // the confirming event only to the focused client):
                // the pending attribution is consumed by this echo.
                let offer = match msg.args.first() {
                    None | Some(Argument::Object(0)) => {
                        self.primary_selection = None;
                        self.pending_psel = false;
                        return;
                    }
                    Some(Argument::Object(id)) => *id,
                    _ => {
                        self.primary_selection = None;
                        self.pending_psel = false;
                        return;
                    }
                };
                self.primary_selection = Some(if self.own_offers.contains(&offer) {
                    Origin::Own
                } else {
                    Origin::Foreign
                });
                self.pending_psel = false;
            }
            (Dir::ClientToServer, "zwp_primary_selection_offer_v1", "destroy") => {
                self.own_offers.remove(&msg.sender_id);
            }
            _ => {}
        }
    }

    /// Gate one `receive` request — `wl_data_offer.receive` (stable
    /// clipboard) or `zwp_primary_selection_offer_v1.receive`
    /// (primary selection, Phase 5). Both have the same shape (a
    /// mime string and an fd argument), the same drop semantics, and
    /// the same attribution state (`own_offers` is shared, object
    /// IDs are unique per connection), so one implementation serves
    /// both; `primary` only selects *which* protocol's selection
    /// state the audit attribution reads (the two echo sequences
    /// are tracked separately).
    ///
    /// An error is a protocol violation (the fd is not an in-memory
    /// channel, or the message is malformed): the caller must fail
    /// the connection closed.
    pub(crate) fn on_receive(
        &mut self,
        msg: &Message<u32, OwnedFd>,
        primary: bool,
    ) -> Result<ReceiveDecision, String> {
        // 1. The fd sanity check (always, both policies). The fd is
        // the last argument of the request in every version of the
        // interface; find it rather than assume a position.
        let Some(fd) = msg.args.iter().find_map(|a| {
            if let Argument::Fd(f) = a {
                Some(f)
            } else {
                None
            }
        }) else {
            return Err("wl_data_offer.receive without an fd argument".into());
        };
        let fd_kind = fd_kind(fd)?;
        let origin = Self::read_origin(self, msg.sender_id, primary);

        // 2. The policy.
        match self.policy {
            ClipboardPolicy::Allow => Ok(ReceiveDecision {
                action: ForwardAction::Forward,
                fd_kind,
                origin,
            }),
            ClipboardPolicy::Deny => {
                let consented = self
                    .unlocked_until
                    .is_some_and(|until| Instant::now() < until);
                if consented || self.own_offers.contains(&msg.sender_id) {
                    Ok(ReceiveDecision {
                        action: ForwardAction::Forward,
                        fd_kind,
                        origin,
                    })
                } else {
                    info!(
                        "selection gate (deny): dropping a read of a {} selection \
                         (the app will see an empty read)",
                        if primary { "primary" } else { "clipboard" }
                    );
                    Ok(ReceiveDecision {
                        action: ForwardAction::Drop,
                        fd_kind,
                        origin,
                    })
                }
            }
        }
    }

    /// The audit attribution of the data a `read` on `offer_id`
    /// pulls in (Phase 9): `own` when the gate attributed the offer
    /// to this client (the precise per-offer proof), else the
    /// current selection's origin for that protocol (the offer was
    /// announced but never attributed own), else `unknown` (no
    /// attribution yet).
    fn read_origin(&self, offer_id: u32, primary: bool) -> OriginInfo {
        if self.own_offers.contains(&offer_id) {
            return OriginInfo::Own;
        }
        let selection = if primary {
            self.primary_selection
        } else {
            self.selection
        };
        match selection {
            Some(Origin::Own) => OriginInfo::Own,
            Some(Origin::Foreign) => OriginInfo::Foreign,
            None => OriginInfo::Unknown,
        }
    }

    /// The selection this `set_selection` message acts on, and how
    /// (Phase 6: the copy-out detector; Phase 9: the audit's
    /// write/clear distinction).
    ///
    /// A client `set_selection` on either selection protocol whose
    /// source argument is **not NULL** is the app placing data on
    /// that selection (a `Set`); a NULL source is a `Clear` (not a
    /// write: nothing is placed, the previous data is simply
    /// removed). Every other message — including the server's
    /// `selection` *event*, which only ever echoes a prior write —
    /// returns `None`.
    ///
    /// The source of a `Set` is guaranteed to be one *this* client
    /// created: the relay's bookkeeping (run before this, in
    /// `forward`) rejects any reference to an object the client
    /// does not own, and a client can only set a selection with a
    /// source it created itself. So a `Set` is unambiguously the
    /// app writing — no origin-tracking state is needed (nor wanted:
    /// a write must be reported even for a source the read-gate
    /// later attributes foreign, because the *write* is what
    /// matters).
    ///
    /// Returns the human-facing name — `"clipboard"` (the stable
    /// selection) or `"primary"` (the X-style primary selection) —
    /// and the kind; `None` otherwise.
    pub(crate) fn set_selection(
        dir: Dir,
        sender: &Interface,
        desc: &MessageDesc,
        msg: &Message<u32, OwnedFd>,
    ) -> Option<(&'static str, SelectionWrite)> {
        if dir != Dir::ClientToServer || desc.name != "set_selection" {
            return None;
        }
        // The source is the first argument (`allow-null`). A NULL
        // source is a clear; any non-NULL object is a write (the
        // bookkeeping guarantees the object is one this client
        // created); a malformed arg is not possible (the parse
        // would have caught it).
        let write = match msg.args.first() {
            Some(Argument::Object(0)) => SelectionWrite::Clear,
            Some(Argument::Object(_)) => SelectionWrite::Set,
            _ => return None,
        };
        let selection = match sender.name {
            "wl_data_device" => "clipboard",
            "zwp_primary_selection_device_v1" => "primary",
            _ => return None,
        };
        Some((selection, write))
    }
}

/// The kernel's own name for an fd: the `/proc/self/fd/<n>` symlink
/// target (`memfd:…` — or, on newer kernels, `/memfd:… (deleted)` —
/// for a memfd, `pipe:[inode]` for an anonymous pipe,
/// `socket:[inode]` for a socket, a path for anything else —
/// including `path (deleted)` for an unlinked regular file).
fn proc_target(fd: &OwnedFd) -> Result<String, String> {
    let path = format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd());
    std::fs::read_link(&path)
        .map_err(|e| format!("inspecting the fd ({path}) failed: {e}"))?
        .into_os_string()
        .into_string()
        .map_err(|t| format!("non-UTF8 /proc entry for the fd: {t:?}"))
}

/// The class of an in-memory channel `fd` refers to — an error
/// (the message the relay fails the connection with) for anything
/// else.
fn fd_kind(fd: &OwnedFd) -> Result<FdKind, String> {
    let target = proc_target(fd)?;
    if target.starts_with("memfd:") || target.starts_with("/memfd:") {
        Ok(FdKind::Memfd)
    } else if target.starts_with("pipe:[") {
        Ok(FdKind::Pipe)
    } else if target.starts_with("socket:[") {
        Ok(FdKind::Socket)
    } else {
        Err(format!(
            "the receive fd ({target:?}) is not an in-memory channel (memfd/pipe/socket): \
             a sandboxed app must not direct clipboard data to a file"
        ))
    }
}

/// Best-effort class of *any* fd (no error): `Some` of the class
/// when it is an in-memory channel, `None` otherwise. Used for fds
/// the relay *measures* but does not police — the requester's fd in
/// a `send` event, which the (trusted) compositor handed over, not
/// the app (Phase 9).
pub(crate) fn fd_class(fd: &OwnedFd) -> Option<FdKind> {
    match proc_target(fd) {
        Ok(target) => {
            if target.starts_with("memfd:") || target.starts_with("/memfd:") {
                Some(FdKind::Memfd)
            } else if target.starts_with("pipe:[") {
                Some(FdKind::Pipe)
            } else if target.starts_with("socket:[") {
                Some(FdKind::Socket)
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{FromRawFd, IntoRawFd};
    use wayland_client::protocol::__interfaces::{
        WL_DATA_DEVICE_INTERFACE, WL_DATA_DEVICE_MANAGER_INTERFACE, WL_DATA_OFFER_INTERFACE,
    };
    use wayland_protocols::wp::primary_selection::zv1::client::__interfaces::{
        ZWP_PRIMARY_SELECTION_DEVICE_MANAGER_V1_INTERFACE,
        ZWP_PRIMARY_SELECTION_DEVICE_V1_INTERFACE, ZWP_PRIMARY_SELECTION_OFFER_V1_INTERFACE,
        ZWP_PRIMARY_SELECTION_SOURCE_V1_INTERFACE,
    };

    /// The 0-based opcode a request/event of `name` has in `table`
    /// (the on-wire convention this proxy enforces).
    fn opcode(table: &Interface, kind: &str, name: &str) -> u16 {
        let arr = if kind == "req" {
            table.requests
        } else {
            table.events
        };
        u16::try_from(arr.iter().position(|d| d.name == name).unwrap()).expect("opcode fits a u16")
    }

    fn msg(sender: u32, opcode: u16, args: Vec<Argument<u32, OwnedFd>>) -> Message<u32, OwnedFd> {
        Message {
            sender_id: sender,
            opcode,
            args: args.into(),
        }
    }

    fn memfd() -> OwnedFd {
        rustix::fs::memfd_create("test", rustix::fs::MemfdFlags::empty()).expect("memfd_create")
    }

    /// Rust (wayland-backend) convention: the display is object ID 1;
    /// the manager and data device are the first server allocations,
    /// the app's source a client-range id.
    const MGR: u32 = 0xFF00_0001;
    const DEVICE: u32 = 0xFF00_0002;
    const SRC: u32 = 30;
    const SURFACE: u32 = 40;
    const OFFER_FOREIGN: u32 = 0xFF00_0100;
    const OFFER_OWN: u32 = 0xFF00_0101;
    const OFFER_DRAG: u32 = 0xFF00_0102;

    // Phase 5: the primary-selection protocol objects.
    const PS_MGR: u32 = 0xFF00_0200;
    const PS_DEVICE: u32 = 0xFF00_0201;
    const PS_SRC: u32 = 50;
    const PS_OFFER_FOREIGN: u32 = 0xFF00_0300;
    const PS_OFFER_OWN: u32 = 0xFF00_0301;

    fn ps_event(name: &str) -> (u16, &'static MessageDesc) {
        let d = &ZWP_PRIMARY_SELECTION_DEVICE_V1_INTERFACE
            .events
            .iter()
            .find(|d| d.name == name)
            .unwrap();
        (
            opcode(&ZWP_PRIMARY_SELECTION_DEVICE_V1_INTERFACE, "ev", name),
            d,
        )
    }

    fn ps_device_request(name: &str) -> (u16, &'static MessageDesc) {
        let d = &ZWP_PRIMARY_SELECTION_DEVICE_V1_INTERFACE
            .requests
            .iter()
            .find(|d| d.name == name)
            .unwrap();
        (
            opcode(&ZWP_PRIMARY_SELECTION_DEVICE_V1_INTERFACE, "req", name),
            d,
        )
    }

    fn ps_mgr_request(name: &str) -> (u16, &'static MessageDesc) {
        let d = &ZWP_PRIMARY_SELECTION_DEVICE_MANAGER_V1_INTERFACE
            .requests
            .iter()
            .find(|d| d.name == name)
            .unwrap();
        (
            opcode(
                &ZWP_PRIMARY_SELECTION_DEVICE_MANAGER_V1_INTERFACE,
                "req",
                name,
            ),
            d,
        )
    }

    /// The app created a zwp primary-selection source.
    fn app_creates_psel_source(g: &mut ClipboardGate) {
        let (op, d) = ps_mgr_request("create_source");
        g.observe(
            Dir::ClientToServer,
            &ZWP_PRIMARY_SELECTION_DEVICE_MANAGER_V1_INTERFACE,
            d,
            &msg(PS_MGR, op, vec![Argument::NewId(PS_SRC)]),
        );
    }

    /// The app sets its own primary selection; the compositor
    /// echoes it (a new offer, then the selection event).
    fn app_sets_own_psel(g: &mut ClipboardGate) {
        let (op, d) = ps_device_request("set_selection");
        g.observe(
            Dir::ClientToServer,
            &ZWP_PRIMARY_SELECTION_DEVICE_V1_INTERFACE,
            d,
            &msg(
                PS_DEVICE,
                op,
                vec![Argument::Object(PS_SRC), Argument::Uint(0)],
            ),
        );
        let (op, d) = ps_event("data_offer");
        g.observe(
            Dir::ServerToClient,
            &ZWP_PRIMARY_SELECTION_DEVICE_V1_INTERFACE,
            d,
            &msg(PS_DEVICE, op, vec![Argument::NewId(PS_OFFER_OWN)]),
        );
        let (op, d) = ps_event("selection");
        g.observe(
            Dir::ServerToClient,
            &ZWP_PRIMARY_SELECTION_DEVICE_V1_INTERFACE,
            d,
            &msg(PS_DEVICE, op, vec![Argument::Object(PS_OFFER_OWN)]),
        );
    }

    /// The compositor announces a *foreign* primary selection (an
    /// offer the compositor created for a source another client
    /// owns).
    fn foreign_psel(g: &mut ClipboardGate, offer: u32) {
        let (op, d) = ps_event("data_offer");
        g.observe(
            Dir::ServerToClient,
            &ZWP_PRIMARY_SELECTION_DEVICE_V1_INTERFACE,
            d,
            &msg(PS_DEVICE, op, vec![Argument::NewId(offer)]),
        );
        let (op, d) = ps_event("selection");
        g.observe(
            Dir::ServerToClient,
            &ZWP_PRIMARY_SELECTION_DEVICE_V1_INTERFACE,
            d,
            &msg(PS_DEVICE, op, vec![Argument::Object(offer)]),
        );
    }

    /// One `zwp_primary_selection_offer_v1.receive` on `offer`
    /// (the primary protocol — the gate's audit attribution reads
    /// the primary selection state).
    fn ps_receive(g: &mut ClipboardGate, offer: u32) -> Result<ForwardAction, String> {
        let (op, d) = (
            opcode(&ZWP_PRIMARY_SELECTION_OFFER_V1_INTERFACE, "req", "receive"),
            &ZWP_PRIMARY_SELECTION_OFFER_V1_INTERFACE
                .requests
                .iter()
                .find(|d| d.name == "receive")
                .unwrap(),
        );
        let mk = || {
            msg(
                offer,
                op,
                vec![
                    Argument::Str(Some(Box::new(
                        std::ffi::CString::new("text/plain").unwrap(),
                    ))),
                    Argument::Fd(memfd()),
                ],
            )
        };
        g.observe(
            Dir::ClientToServer,
            &ZWP_PRIMARY_SELECTION_OFFER_V1_INTERFACE,
            d,
            &mk(),
        );
        g.on_receive(&mk(), true).map(|d| d.action)
    }

    fn event(name: &str) -> (u16, &'static MessageDesc) {
        let d = &WL_DATA_DEVICE_INTERFACE
            .events
            .iter()
            .find(|d| d.name == name)
            .unwrap();
        (opcode(&WL_DATA_DEVICE_INTERFACE, "ev", name), d)
    }

    fn request(name: &str) -> (u16, &'static MessageDesc) {
        let d = &WL_DATA_DEVICE_INTERFACE
            .requests
            .iter()
            .find(|d| d.name == name)
            .unwrap();
        (opcode(&WL_DATA_DEVICE_INTERFACE, "req", name), d)
    }

    /// The app created a `wl_data_source` (client object `SRC`) and
    /// the compositor announced a *foreign* selection (an offer the
    /// compositor created for a source owned by another client).
    fn own_source_then_foreign_selection(g: &mut ClipboardGate) {
        let (op, d) = (
            opcode(
                &WL_DATA_DEVICE_MANAGER_INTERFACE,
                "req",
                "create_data_source",
            ),
            &WL_DATA_DEVICE_MANAGER_INTERFACE
                .requests
                .iter()
                .find(|d| d.name == "create_data_source")
                .unwrap(),
        );
        g.observe(
            Dir::ClientToServer,
            &WL_DATA_DEVICE_MANAGER_INTERFACE,
            d,
            &msg(MGR, op, vec![Argument::NewId(SRC)]),
        );
        // data_offer(foreign) — no pending request is live.
        let (op, d) = event("data_offer");
        g.observe(
            Dir::ServerToClient,
            &WL_DATA_DEVICE_INTERFACE,
            d,
            &msg(DEVICE, op, vec![Argument::NewId(OFFER_FOREIGN)]),
        );
        // selection(foreign offer).
        let (op, d) = event("selection");
        g.observe(
            Dir::ServerToClient,
            &WL_DATA_DEVICE_INTERFACE,
            d,
            &msg(DEVICE, op, vec![Argument::Object(OFFER_FOREIGN)]),
        );
    }

    /// The app sets its own selection; the compositor echoes it (a
    /// new offer, attributed own, then the selection event).
    fn app_sets_own_selection(g: &mut ClipboardGate) {
        let (op, d) = request("set_selection");
        g.observe(
            Dir::ClientToServer,
            &WL_DATA_DEVICE_INTERFACE,
            d,
            &msg(DEVICE, op, vec![Argument::Object(SRC), Argument::Uint(0)]),
        );
        let (op, d) = event("data_offer");
        g.observe(
            Dir::ServerToClient,
            &WL_DATA_DEVICE_INTERFACE,
            d,
            &msg(DEVICE, op, vec![Argument::NewId(OFFER_OWN)]),
        );
        let (op, d) = event("selection");
        g.observe(
            Dir::ServerToClient,
            &WL_DATA_DEVICE_INTERFACE,
            d,
            &msg(DEVICE, op, vec![Argument::Object(OFFER_OWN)]),
        );
    }

    /// The copy-out/clear detector: a client `set_selection` with a
    /// non-NULL source (either protocol) is a `Set`; with a NULL
    /// source a `Clear`; a compositor `selection` echo, and any
    /// other request, is neither.
    #[test]
    fn set_selection_detects_writes_and_clears() {
        use SelectionWrite::{Clear, Set};
        // A stable `set_selection` with a non-NULL source is a
        // write (copy-out).
        let (op, d) = request("set_selection");
        assert_eq!(
            ClipboardGate::set_selection(
                Dir::ClientToServer,
                &WL_DATA_DEVICE_INTERFACE,
                d,
                &msg(DEVICE, op, vec![Argument::Object(SRC)]),
            ),
            Some(("clipboard", Set))
        );
        // The primary-selection twin.
        let (op, d) = ps_device_request("set_selection");
        assert_eq!(
            ClipboardGate::set_selection(
                Dir::ClientToServer,
                &ZWP_PRIMARY_SELECTION_DEVICE_V1_INTERFACE,
                d,
                &msg(PS_DEVICE, op, vec![Argument::Object(PS_SRC)]),
            ),
            Some(("primary", Set))
        );
        // A NULL source is a clear, not a write (both protocols).
        let (op, d) = request("set_selection");
        assert_eq!(
            ClipboardGate::set_selection(
                Dir::ClientToServer,
                &WL_DATA_DEVICE_INTERFACE,
                d,
                &msg(DEVICE, op, vec![Argument::Object(0)]),
            ),
            Some(("clipboard", Clear))
        );
        let (op, d) = ps_device_request("set_selection");
        assert_eq!(
            ClipboardGate::set_selection(
                Dir::ClientToServer,
                &ZWP_PRIMARY_SELECTION_DEVICE_V1_INTERFACE,
                d,
                &msg(PS_DEVICE, op, vec![Argument::Object(0)]),
            ),
            Some(("primary", Clear))
        );
        // The compositor's `selection` *event* is an echo of a prior
        // write, not a write (server -> client).
        let (op, d) = event("selection");
        assert_eq!(
            ClipboardGate::set_selection(
                Dir::ServerToClient,
                &WL_DATA_DEVICE_INTERFACE,
                d,
                &msg(DEVICE, op, vec![Argument::Object(OFFER_OWN)]),
            ),
            None
        );
        // An unrelated request on the device (`start_drag`) is not a
        // `set_selection`.
        let (op, d) = request("start_drag");
        assert_eq!(
            ClipboardGate::set_selection(
                Dir::ClientToServer,
                &WL_DATA_DEVICE_INTERFACE,
                d,
                &msg(DEVICE, op, vec![]),
            ),
            None
        );
    }

    /// The fd classification (Phase 9): each in-memory channel class
    /// is recognized, and anything else is rejected with the message
    /// the relay fails the connection with.
    #[test]
    fn fd_kind_classifies_each_channel() {
        assert_eq!(fd_kind(&memfd()).unwrap(), FdKind::Memfd);

        // Anonymous pipe.
        let (pipe_read, _pipe_write) = std::io::pipe().unwrap();
        let pipe_fd = unsafe { OwnedFd::from_raw_fd(pipe_read.into_raw_fd()) };
        assert_eq!(fd_kind(&pipe_fd).unwrap(), FdKind::Pipe);
        drop(pipe_fd);

        // Unix socket pair end.
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let socket_fd = unsafe { OwnedFd::from_raw_fd(a.into_raw_fd()) };
        assert_eq!(fd_kind(&socket_fd).unwrap(), FdKind::Socket);
        drop(socket_fd);

        // A regular file must not pass (this is the whole point).
        // Move the File out (into_raw_fd) so the OwnedFd below is
        // the sole owner of the fd — a second owner would
        // double-close on drop and abort the test process with an
        // IO safety violation.
        let path = std::env::temp_dir().join(format!("wlsctx-fdtest-{}", std::process::id()));
        let file = std::fs::File::create(&path).unwrap();
        let file_fd = unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) };
        let err = fd_kind(&file_fd).unwrap_err();
        assert!(err.contains("not an in-memory channel"), "{err}");
        drop(file_fd);
        let _ = std::fs::remove_file(&path);
    }

    /// One `wl_data_offer.receive` on `offer`, exactly as the relay
    /// calls the gate (observe is a no-op for it, but the path is
    /// exercised).
    fn receive(g: &mut ClipboardGate, offer: u32) -> Result<ForwardAction, String> {
        let (op, d) = (
            opcode(&WL_DATA_OFFER_INTERFACE, "req", "receive"),
            &WL_DATA_OFFER_INTERFACE
                .requests
                .iter()
                .find(|d| d.name == "receive")
                .unwrap(),
        );
        let mk = || {
            msg(
                offer,
                op,
                vec![
                    Argument::Str(Some(Box::new(
                        std::ffi::CString::new("text/plain").unwrap(),
                    ))),
                    Argument::Fd(memfd()),
                ],
            )
        };
        g.observe(Dir::ClientToServer, &WL_DATA_OFFER_INTERFACE, d, &mk());
        g.on_receive(&mk(), false).map(|d| d.action)
    }

    #[test]
    fn policy_parse() {
        assert_eq!(
            ClipboardPolicy::parse("allow").unwrap(),
            ClipboardPolicy::Allow
        );
        assert_eq!(
            ClipboardPolicy::parse("deny").unwrap(),
            ClipboardPolicy::Deny
        );
        let err = ClipboardPolicy::parse("sometimes").unwrap_err();
        assert!(err.contains("sometimes"), "{err}");
    }

    #[test]
    /// The best-effort classifier (Phase 9): in-memory channels map to
    /// their class; anything else (a path in the app's mount space) is
    /// `None`, so a `send` fd that is not a memfd simply records no
    /// size rather than failing the connection.
    fn fd_classification() {
        assert_eq!(fd_class(&memfd()), Some(FdKind::Memfd));

        // Anonymous pipe.
        let (pipe_read, _pipe_write) = std::io::pipe().unwrap();
        let pipe_fd = unsafe { OwnedFd::from_raw_fd(pipe_read.into_raw_fd()) };
        assert_eq!(fd_class(&pipe_fd), Some(FdKind::Pipe));
        drop(pipe_fd);

        // Unix socket pair end.
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let socket_fd = unsafe { OwnedFd::from_raw_fd(a.into_raw_fd()) };
        assert_eq!(fd_class(&socket_fd), Some(FdKind::Socket));
        drop(socket_fd);

        // A regular file is not an in-memory channel: `None`.
        // Move the File out (into_raw_fd) so the OwnedFd below is the
        // sole owner of the fd — a second owner would double-close on
        // drop and abort the test process with an IO safety violation.
        let path = std::env::temp_dir().join(format!("wlsctx-fdtest-{}", std::process::id()));
        let file = std::fs::File::create(&path).unwrap();
        let file_fd = unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) };
        assert_eq!(fd_class(&file_fd), None, "a path must not be classified");
        drop(file_fd);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn deny_blocks_foreign_and_allows_own_readback() {
        let mut g = ClipboardGate::new(ClipboardPolicy::Deny);
        own_source_then_foreign_selection(&mut g);

        // Reading the host selection: dropped silently.
        assert_eq!(receive(&mut g, OFFER_FOREIGN).unwrap(), ForwardAction::Drop);

        // The app copies (sets its own selection); the read-back of
        // its own offer is forwarded.
        app_sets_own_selection(&mut g);
        assert_eq!(receive(&mut g, OFFER_OWN).unwrap(), ForwardAction::Forward);

        // A new foreign selection replaces it; the stale own offer
        // still only serves the app's own data (the source behind it
        // is the app's), so it stays readable — and the new foreign
        // offer is not.
        let (op, d) = event("data_offer");
        g.observe(
            Dir::ServerToClient,
            &WL_DATA_DEVICE_INTERFACE,
            d,
            &msg(DEVICE, op, vec![Argument::NewId(0xFF00_0103)]),
        );
        let (op, d) = event("selection");
        g.observe(
            Dir::ServerToClient,
            &WL_DATA_DEVICE_INTERFACE,
            d,
            &msg(DEVICE, op, vec![Argument::Object(0xFF00_0103)]),
        );
        assert_eq!(receive(&mut g, OFFER_OWN).unwrap(), ForwardAction::Forward);
        assert_eq!(receive(&mut g, 0xFF00_0103).unwrap(), ForwardAction::Drop);
    }

    #[test]
    fn allow_passes_everything() {
        let mut g = ClipboardGate::new(ClipboardPolicy::Allow);
        own_source_then_foreign_selection(&mut g);
        assert_eq!(
            receive(&mut g, OFFER_FOREIGN).unwrap(),
            ForwardAction::Forward
        );
    }

    #[test]
    fn unlock_opens_foreign_reads_until_the_deadline() {
        let mut g = ClipboardGate::new(ClipboardPolicy::Deny);
        own_source_then_foreign_selection(&mut g);

        // In the past: no effect.
        g.unlock(Instant::now() - std::time::Duration::from_secs(1));
        assert_eq!(receive(&mut g, OFFER_FOREIGN).unwrap(), ForwardAction::Drop);

        // In the future: the foreign read is allowed.
        g.unlock(Instant::now() + std::time::Duration::from_secs(5));
        assert_eq!(
            receive(&mut g, OFFER_FOREIGN).unwrap(),
            ForwardAction::Forward
        );
    }

    #[test]
    fn drags_are_attributed_like_selections() {
        let mut g = ClipboardGate::new(ClipboardPolicy::Deny);
        // The app's own source exists.
        let (op, d) = (
            opcode(
                &WL_DATA_DEVICE_MANAGER_INTERFACE,
                "req",
                "create_data_source",
            ),
            &WL_DATA_DEVICE_MANAGER_INTERFACE
                .requests
                .iter()
                .find(|d| d.name == "create_data_source")
                .unwrap(),
        );
        g.observe(
            Dir::ClientToServer,
            &WL_DATA_DEVICE_MANAGER_INTERFACE,
            d,
            &msg(MGR, op, vec![Argument::NewId(SRC)]),
        );

        // A foreign drag: data_offer + enter, no pending request.
        let (op, d) = event("data_offer");
        g.observe(
            Dir::ServerToClient,
            &WL_DATA_DEVICE_INTERFACE,
            d,
            &msg(DEVICE, op, vec![Argument::NewId(0xFF00_0104)]),
        );
        let (op, d) = event("enter");
        g.observe(
            Dir::ServerToClient,
            &WL_DATA_DEVICE_INTERFACE,
            d,
            &msg(
                DEVICE,
                op,
                vec![
                    Argument::Uint(1),
                    Argument::Object(SURFACE),
                    Argument::Fixed(0),
                    Argument::Fixed(0),
                    Argument::Object(0xFF00_0104),
                ],
            ),
        );
        assert_eq!(receive(&mut g, 0xFF00_0104).unwrap(), ForwardAction::Drop);

        // The app's own drag (intra-app drag-and-drop): its
        // start_drag is echoed as an own offer.
        let (op, d) = request("start_drag");
        g.observe(
            Dir::ClientToServer,
            &WL_DATA_DEVICE_INTERFACE,
            d,
            &msg(
                DEVICE,
                op,
                vec![
                    Argument::Object(SRC),
                    Argument::Object(SURFACE),
                    Argument::Object(0),
                    Argument::Uint(1),
                ],
            ),
        );
        let (op, d) = event("data_offer");
        g.observe(
            Dir::ServerToClient,
            &WL_DATA_DEVICE_INTERFACE,
            d,
            &msg(DEVICE, op, vec![Argument::NewId(OFFER_DRAG)]),
        );
        let (op, d) = event("enter");
        g.observe(
            Dir::ServerToClient,
            &WL_DATA_DEVICE_INTERFACE,
            d,
            &msg(
                DEVICE,
                op,
                vec![
                    Argument::Uint(2),
                    Argument::Object(SURFACE),
                    Argument::Fixed(0),
                    Argument::Fixed(0),
                    Argument::Object(OFFER_DRAG),
                ],
            ),
        );
        assert_eq!(receive(&mut g, OFFER_DRAG).unwrap(), ForwardAction::Forward);
    }

    #[test]
    fn clearing_the_selection_does_not_leak_the_pending() {
        let mut g = ClipboardGate::new(ClipboardPolicy::Deny);
        // The app's own source exists.
        let (op, d) = (
            opcode(
                &WL_DATA_DEVICE_MANAGER_INTERFACE,
                "req",
                "create_data_source",
            ),
            &WL_DATA_DEVICE_MANAGER_INTERFACE
                .requests
                .iter()
                .find(|d| d.name == "create_data_source")
                .unwrap(),
        );
        g.observe(
            Dir::ClientToServer,
            &WL_DATA_DEVICE_MANAGER_INTERFACE,
            d,
            &msg(MGR, op, vec![Argument::NewId(SRC)]),
        );
        // A set_selection with an own source is pending…
        let (op, d) = request("set_selection");
        g.observe(
            Dir::ClientToServer,
            &WL_DATA_DEVICE_INTERFACE,
            d,
            &msg(DEVICE, op, vec![Argument::Object(SRC), Argument::Uint(0)]),
        );
        // …but the echo that arrives clears the selection (another
        // client won the race, or the app cleared it): the pending
        // must not stick to the *next* foreign change.
        let (op, d) = event("selection");
        g.observe(
            Dir::ServerToClient,
            &WL_DATA_DEVICE_INTERFACE,
            d,
            &msg(DEVICE, op, vec![Argument::Object(0)]),
        );
        let (op, d) = event("data_offer");
        g.observe(
            Dir::ServerToClient,
            &WL_DATA_DEVICE_INTERFACE,
            d,
            &msg(DEVICE, op, vec![Argument::NewId(0xFF00_0105)]),
        );
        let (op, d) = event("selection");
        g.observe(
            Dir::ServerToClient,
            &WL_DATA_DEVICE_INTERFACE,
            d,
            &msg(DEVICE, op, vec![Argument::Object(0xFF00_0105)]),
        );
        assert_eq!(receive(&mut g, 0xFF00_0105).unwrap(), ForwardAction::Drop);
    }

    #[test]
    fn receive_without_an_fd_fails() {
        let mut g = ClipboardGate::new(ClipboardPolicy::Allow);
        let op = opcode(&WL_DATA_OFFER_INTERFACE, "req", "receive");
        let err = g
            .on_receive(
                &msg(
                    OFFER_FOREIGN,
                    op,
                    vec![Argument::Str(Some(Box::new(
                        std::ffi::CString::new("text/plain").unwrap(),
                    )))],
                ),
                false,
            )
            .unwrap_err();
        assert!(err.contains("without an fd"), "{err}");
    }

    // ---- Phase 5: the primary-selection protocol. ----

    #[test]
    fn primary_deny_blocks_foreign_and_allows_own_readback() {
        let mut g = ClipboardGate::new(ClipboardPolicy::Deny);

        // A host app owns the primary selection: dropped silently.
        foreign_psel(&mut g, PS_OFFER_FOREIGN);
        assert_eq!(g.primary_selection_origin(), Some(Origin::Foreign));
        assert_eq!(
            ps_receive(&mut g, PS_OFFER_FOREIGN).unwrap(),
            ForwardAction::Drop
        );

        // The app selects text (sets its own primary source); the
        // read-back of its own offer is forwarded.
        app_creates_psel_source(&mut g);
        app_sets_own_psel(&mut g);
        assert_eq!(g.primary_selection_origin(), Some(Origin::Own));
        assert_eq!(
            ps_receive(&mut g, PS_OFFER_OWN).unwrap(),
            ForwardAction::Forward
        );
    }

    #[test]
    fn primary_allow_passes_everything() {
        let mut g = ClipboardGate::new(ClipboardPolicy::Allow);
        foreign_psel(&mut g, PS_OFFER_FOREIGN);
        assert_eq!(
            ps_receive(&mut g, PS_OFFER_FOREIGN).unwrap(),
            ForwardAction::Forward
        );
    }

    #[test]
    fn primary_unlock_opens_foreign_reads_too() {
        // The consent window (Phase 4) is selection-wide: one allow
        // covers both protocols' foreign reads.
        let mut g = ClipboardGate::new(ClipboardPolicy::Deny);
        own_source_then_foreign_selection(&mut g);
        foreign_psel(&mut g, PS_OFFER_FOREIGN);

        g.unlock(Instant::now() + std::time::Duration::from_secs(5));
        assert_eq!(
            ps_receive(&mut g, PS_OFFER_FOREIGN).unwrap(),
            ForwardAction::Forward
        );
        assert_eq!(
            receive(&mut g, OFFER_FOREIGN).unwrap(),
            ForwardAction::Forward
        );
    }

    #[test]
    fn stable_and_primary_pendings_never_cross() {
        let mut g = ClipboardGate::new(ClipboardPolicy::Deny);

        // The app's stable set_selection is pending (the source is
        // one the app created, so the request is attributable).
        let (op, d) = (
            opcode(
                &WL_DATA_DEVICE_MANAGER_INTERFACE,
                "req",
                "create_data_source",
            ),
            &WL_DATA_DEVICE_MANAGER_INTERFACE
                .requests
                .iter()
                .find(|d| d.name == "create_data_source")
                .unwrap(),
        );
        g.observe(
            Dir::ClientToServer,
            &WL_DATA_DEVICE_MANAGER_INTERFACE,
            d,
            &msg(MGR, op, vec![Argument::NewId(SRC)]),
        );
        let (op, d) = request("set_selection");
        g.observe(
            Dir::ClientToServer,
            &WL_DATA_DEVICE_INTERFACE,
            d,
            &msg(DEVICE, op, vec![Argument::Object(SRC), Argument::Uint(0)]),
        );
        // …but the *next* zwp data_offer must not be attributed to
        // it: different protocol, different echo sequence.
        let (op, d) = ps_event("data_offer");
        g.observe(
            Dir::ServerToClient,
            &ZWP_PRIMARY_SELECTION_DEVICE_V1_INTERFACE,
            d,
            &msg(PS_DEVICE, op, vec![Argument::NewId(PS_OFFER_OWN)]),
        );
        assert_eq!(
            ps_receive(&mut g, PS_OFFER_OWN).unwrap(),
            ForwardAction::Drop,
            "a stable pending must not attribute a primary offer"
        );

        // The stable echo arrives and is consumed by the stable
        // selection event.
        let (op, d) = event("data_offer");
        g.observe(
            Dir::ServerToClient,
            &WL_DATA_DEVICE_INTERFACE,
            d,
            &msg(DEVICE, op, vec![Argument::NewId(OFFER_OWN)]),
        );
        let (op, d) = event("selection");
        g.observe(
            Dir::ServerToClient,
            &WL_DATA_DEVICE_INTERFACE,
            d,
            &msg(DEVICE, op, vec![Argument::Object(OFFER_OWN)]),
        );
        assert_eq!(
            receive(&mut g, OFFER_OWN).unwrap(),
            ForwardAction::Forward,
            "the stable echo still attributes the stable offer"
        );

        // And the reverse direction: the app's primary
        // set_selection pending must not attribute a stable
        // data_offer.
        app_creates_psel_source(&mut g);
        let (op, d) = ps_device_request("set_selection");
        g.observe(
            Dir::ClientToServer,
            &ZWP_PRIMARY_SELECTION_DEVICE_V1_INTERFACE,
            d,
            &msg(
                PS_DEVICE,
                op,
                vec![Argument::Object(PS_SRC), Argument::Uint(0)],
            ),
        );
        let (op, d) = event("data_offer");
        g.observe(
            Dir::ServerToClient,
            &WL_DATA_DEVICE_INTERFACE,
            d,
            &msg(DEVICE, op, vec![Argument::NewId(0xFF00_0104)]),
        );
        assert_eq!(
            receive(&mut g, 0xFF00_0104).unwrap(),
            ForwardAction::Drop,
            "a primary pending must not attribute a stable offer"
        );
        // The primary echo attributes the primary offer instead.
        let (op, d) = ps_event("data_offer");
        g.observe(
            Dir::ServerToClient,
            &ZWP_PRIMARY_SELECTION_DEVICE_V1_INTERFACE,
            d,
            &msg(PS_DEVICE, op, vec![Argument::NewId(PS_OFFER_OWN)]),
        );
        let (op, d) = ps_event("selection");
        g.observe(
            Dir::ServerToClient,
            &ZWP_PRIMARY_SELECTION_DEVICE_V1_INTERFACE,
            d,
            &msg(PS_DEVICE, op, vec![Argument::Object(PS_OFFER_OWN)]),
        );
        assert_eq!(
            ps_receive(&mut g, PS_OFFER_OWN).unwrap(),
            ForwardAction::Forward
        );
    }

    #[test]
    fn primary_null_selection_clears_origin_and_pending() {
        let mut g = ClipboardGate::new(ClipboardPolicy::Deny);
        app_creates_psel_source(&mut g);
        app_sets_own_psel(&mut g);
        assert_eq!(g.primary_selection_origin(), Some(Origin::Own));

        // A NULL selection (cleared, or the app lost keyboard focus
        // — the protocol sends the confirming event only to the
        // focused client) clears the origin and any live pending.
        let (op, d) = ps_event("selection");
        g.observe(
            Dir::ServerToClient,
            &ZWP_PRIMARY_SELECTION_DEVICE_V1_INTERFACE,
            d,
            &msg(PS_DEVICE, op, Vec::new()),
        );
        assert_eq!(g.primary_selection_origin(), None);

        // The (not yet destroyed) own offer stays attributable: the
        // data behind it is still the app's.
        assert_eq!(
            ps_receive(&mut g, PS_OFFER_OWN).unwrap(),
            ForwardAction::Forward
        );
    }

    #[test]
    fn primary_source_destroy_stops_attribution() {
        let mut g = ClipboardGate::new(ClipboardPolicy::Deny);
        app_creates_psel_source(&mut g);
        app_sets_own_psel(&mut g);

        // The client destroys the source (the protocol says to,
        // once it is no longer the selection owner); the gate must
        // stop attributing future echoes to it.
        let op = opcode(&ZWP_PRIMARY_SELECTION_SOURCE_V1_INTERFACE, "req", "destroy");
        let d = &ZWP_PRIMARY_SELECTION_SOURCE_V1_INTERFACE
            .requests
            .iter()
            .find(|d| d.name == "destroy")
            .unwrap();
        g.observe(
            Dir::ClientToServer,
            &ZWP_PRIMARY_SELECTION_SOURCE_V1_INTERFACE,
            d,
            &msg(PS_SRC, op, Vec::new()),
        );
        let (op, d) = ps_device_request("set_selection");
        g.observe(
            Dir::ClientToServer,
            &ZWP_PRIMARY_SELECTION_DEVICE_V1_INTERFACE,
            d,
            &msg(
                PS_DEVICE,
                op,
                vec![Argument::Object(PS_SRC), Argument::Uint(0)],
            ),
        );
        let (op, d) = ps_event("data_offer");
        g.observe(
            Dir::ServerToClient,
            &ZWP_PRIMARY_SELECTION_DEVICE_V1_INTERFACE,
            d,
            &msg(PS_DEVICE, op, vec![Argument::NewId(0xFF00_0302)]),
        );
        let (op, d) = ps_event("selection");
        g.observe(
            Dir::ServerToClient,
            &ZWP_PRIMARY_SELECTION_DEVICE_V1_INTERFACE,
            d,
            &msg(PS_DEVICE, op, vec![Argument::Object(0xFF00_0302)]),
        );
        assert_eq!(
            ps_receive(&mut g, 0xFF00_0302).unwrap(),
            ForwardAction::Drop,
            "a destroyed source cannot be attributed to the app"
        );
    }

    #[test]
    fn primary_receive_with_a_path_fd_fails() {
        // The fd sanity check applies to the primary protocol
        // exactly like the stable one: a regular file (here, this
        // source file) is not an in-memory channel.
        let mut g = ClipboardGate::new(ClipboardPolicy::Allow);
        let op = opcode(&ZWP_PRIMARY_SELECTION_OFFER_V1_INTERFACE, "req", "receive");
        let file = std::fs::File::open("Cargo.toml").expect("open Cargo.toml");
        let fd = std::os::fd::OwnedFd::from(file);
        let err = g
            .on_receive(
                &msg(
                    PS_OFFER_FOREIGN,
                    op,
                    vec![
                        Argument::Str(Some(Box::new(
                            std::ffi::CString::new("text/plain").unwrap(),
                        ))),
                        Argument::Fd(fd),
                    ],
                ),
                true,
            )
            .unwrap_err();
        assert!(err.contains("not an in-memory channel"), "{err}");
    }
}
