//! The clipboard receive-gate (Phase 3).
//!
//! ## What it protects
//!
//! A `wl_data_offer.receive` request hands an fd — created by the
//! *app* — to the compositor, and the compositor makes the
//! **current selection owner** write the selection data into that
//! fd. The owner may be the host desktop or another sandboxed app,
//! and what they write may include host secrets (passwords, tokens)
//! — exactly the data the sandbox must not reach. The gate inspects
//! every `receive`:
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
//! The protocol has no "who owns this selection" field: the
//! `wl_data_device.selection` event carries an *offer* object —
//! which the compositor creates separately on *every* client
//! connection — not the `wl_data_source` behind it. The proof is
//! temporal, and it is sound under the threat model (the attacker is
//! the *sandboxed* app; the other clients on the desktop are the
//! user's own, trusted applications):
//!
//! * The gate tracks every `wl_data_source` this client created
//!   (`wl_data_device_manager.create_data_source`) — such an object
//!   can only ever serve the client's own data.
//! * When the client sends `wl_data_device.set_selection` (or
//!   `start_drag`) with one of its own sources, the gate marks the
//!   *next* offer the compositor announces (`wl_data_device.
//!   data_offer`) as **own**; the compositor echoes selection
//!   changes in the order they happened, so that next
//!   `data_offer` + `selection` pair is precisely the app's own
//!   change.
//! * Every other offer is **foreign**, including drag-and-drop
//!   offers (announced before a `wl_data_device.enter`), so a
//!   foreign drag cannot feed the sandbox either.
//!
//! A compromised app cannot forge the proof: it can only create its
//! own sources and observe compositor events, and an offer is marked
//! own only if the compositor actually echoed *that app's*
//! `set_selection`/`start_drag` as the new selection. (The one
//! inescapable race — a hostile *other* client winning a
//! selection-change race in the microseconds between the app's
//! request and the compositor processing it — inverts at most one
//! attribution, and such a client is outside the threat model.)
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
//! ## The consent window (Phase 4 hook)
//!
//! [`ClipboardGate::unlock`] opens the gate for foreign reads until
//! a given instant. Phase 4's prompt broker will call it with the
//! 1500 ms "intent window" when the user approves one clipboard read
//! by the sandboxed app; until then the hook is inert.

use std::collections::HashSet;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::time::Instant;

use log::info;
use wayland_backend::protocol::{Argument, Interface, Message, MessageDesc};

use super::objects::Dir;
use super::ForwardAction;

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
    /// `selection` event). Informational for now; the Phase 4 broker
    /// prompt reports it to the user.
    selection: Option<Origin>,
    /// The offers the gate has attributed to this client (recorded
    /// when a `data_offer` event follows one of the client's own
    /// `set_selection`/`start_drag` requests, removed when the
    /// client destroys the offer).
    own_offers: HashSet<u32>,
    /// Phase 4 hook: while set and in the future, even foreign reads
    /// are allowed (the user's approved intent window).
    unlocked_until: Option<Instant>,
}

impl ClipboardGate {
    pub fn new(policy: ClipboardPolicy) -> Self {
        Self {
            policy,
            own_sources: HashSet::new(),
            pending: None,
            selection: None,
            own_offers: HashSet::new(),
            unlocked_until: None,
        }
    }

    /// The origin of the current clipboard selection, if any.
    ///
    /// Phase 4 hook: the prompt broker will report it to the user
    /// when asking for consent to a foreign read. Inert for now.
    #[allow(dead_code)]
    pub(crate) fn selection_origin(&self) -> Option<Origin> {
        self.selection
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
                    Some(Argument::Object(id)) if self.own_sources.contains(id) => {
                        Some(kind)
                    }
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
            _ => {}
        }
    }

    /// Gate one `wl_data_offer.receive` request.
    ///
    /// Returns the action for the relay: [`ForwardAction::Forward`]
    /// (relay the request as-is) or [`ForwardAction::Drop`] (consume
    /// it silently — the app's fd stays empty and the read comes back
    /// empty). An error is a protocol violation (the fd is not an
    /// in-memory channel, or the message is malformed): the caller
    /// must fail the connection closed.
    pub(crate) fn on_receive(
        &mut self,
        msg: &Message<u32, OwnedFd>,
    ) -> Result<ForwardAction, String> {
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
        fd_is_memchannel(fd)?;

        // 2. The policy.
        match self.policy {
            ClipboardPolicy::Allow => Ok(ForwardAction::Forward),
            ClipboardPolicy::Deny => {
                let consented = self
                    .unlocked_until
                    .is_some_and(|until| Instant::now() < until);
                if consented || self.own_offers.contains(&msg.sender_id) {
                    Ok(ForwardAction::Forward)
                } else {
                    info!(
                        "clipboard gate (deny): dropping a read of a foreign selection \
                         (the app will see an empty clipboard)"
                    );
                    Ok(ForwardAction::Drop)
                }
            }
        }
    }
}

/// Verify that `fd` is an ephemeral in-memory channel (memfd,
/// anonymous pipe, or socket), not a path in the app's mount space.
///
/// The fd has been passed to this process (SCM_RIGHTS), so the
/// kernel's own `/proc/self/fd/<n>` symlink tells us what it is:
/// `memfd:…` (or, on newer kernels, `/memfd:… (deleted)`),
/// `pipe:[inode]`, and `socket:[inode]` for the allowed kinds; a
/// path for anything else (a regular file, a named fifo, a device —
/// including `path (deleted)` for an unlinked regular file, which
/// must not be admitted).
fn fd_is_memchannel(fd: &OwnedFd) -> Result<(), String> {
    let path = format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd());
    let target = std::fs::read_link(&path)
        .map_err(|e| format!("inspecting the receive fd ({path}) failed: {e}"))?
        .into_os_string()
        .into_string()
        .map_err(|t| format!("non-UTF8 /proc entry for the receive fd: {t:?}"))?;
    let memfd = target.starts_with("memfd:") || target.starts_with("/memfd:");
    let pipe = target.starts_with("pipe:[");
    let socket = target.starts_with("socket:[");
    if memfd || pipe || socket {
        Ok(())
    } else {
        Err(format!(
            "the receive fd ({target:?}) is not an in-memory channel (memfd/pipe/socket): \
             a sandboxed app must not direct clipboard data to a file"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{FromRawFd, IntoRawFd};
    use wayland_client::protocol::__interfaces::{
        WL_DATA_DEVICE_INTERFACE, WL_DATA_DEVICE_MANAGER_INTERFACE, WL_DATA_OFFER_INTERFACE,
    };

    /// The 0-based opcode a request/event of `name` has in `table`
    /// (the on-wire convention this proxy enforces).
    fn opcode(table: &Interface, kind: &str, name: &str) -> u16 {
        let arr = if kind == "req" {
            table.requests
        } else {
            table.events
        };
        u16::try_from(arr.iter().position(|d| d.name == name).unwrap())
            .expect("opcode fits a u16")
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
            &WL_DATA_DEVICE_MANAGER_INTERFACE.requests
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
            &msg(
                DEVICE,
                op,
                vec![Argument::Object(OFFER_FOREIGN)],
            ),
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
            &msg(
                DEVICE,
                op,
                vec![Argument::Object(SRC), Argument::Uint(0)],
            ),
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
        g.on_receive(&mk())
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
    fn fd_classification() {
        assert!(fd_is_memchannel(&memfd()).is_ok(), "memfd must pass");

        // Anonymous pipe.
        let (pipe_read, _pipe_write) = std::io::pipe().unwrap();
        let pipe_fd = unsafe { OwnedFd::from_raw_fd(pipe_read.into_raw_fd()) };
        assert!(fd_is_memchannel(&pipe_fd).is_ok(), "pipe must pass");
        drop(pipe_fd);

        // Unix socket pair end.
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let socket_fd = unsafe { OwnedFd::from_raw_fd(a.into_raw_fd()) };
        assert!(fd_is_memchannel(&socket_fd).is_ok(), "socket must pass");

        // A regular file must not pass (this is the whole point).
        // Move the File out (into_raw_fd) so the OwnedFd below is the
        // sole owner of the fd — a second owner would double-close on
        // drop and abort the test process with an IO safety violation.
        let path =
            std::env::temp_dir().join(format!("wlsctx-fdtest-{}", std::process::id()));
        let file = std::fs::File::create(&path).unwrap();
        let file_fd = unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) };
        let err = fd_is_memchannel(&file_fd).unwrap_err();
        assert!(err.contains("not an in-memory channel"), "{err}");
        assert!(err.contains("file"), "{err}");
        drop(file_fd);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn deny_blocks_foreign_and_allows_own_readback() {
        let mut g = ClipboardGate::new(ClipboardPolicy::Deny);
        own_source_then_foreign_selection(&mut g);

        // Reading the host selection: dropped silently.
        assert_eq!(
            receive(&mut g, OFFER_FOREIGN).unwrap(),
            ForwardAction::Drop
        );

        // The app copies (sets its own selection); the read-back of
        // its own offer is forwarded.
        app_sets_own_selection(&mut g);
        assert_eq!(
            receive(&mut g, OFFER_OWN).unwrap(),
            ForwardAction::Forward
        );

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
        assert_eq!(
            receive(&mut g, OFFER_OWN).unwrap(),
            ForwardAction::Forward
        );
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
        assert_eq!(
            receive(&mut g, OFFER_FOREIGN).unwrap(),
            ForwardAction::Drop
        );

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
            &WL_DATA_DEVICE_MANAGER_INTERFACE.requests
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
        assert_eq!(
            receive(&mut g, OFFER_DRAG).unwrap(),
            ForwardAction::Forward
        );
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
            &WL_DATA_DEVICE_MANAGER_INTERFACE.requests
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
            &msg(
                DEVICE,
                op,
                vec![Argument::Object(SRC), Argument::Uint(0)],
            ),
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
        assert_eq!(
            receive(&mut g, 0xFF00_0105).unwrap(),
            ForwardAction::Drop
        );
    }

    #[test]
    fn receive_without_an_fd_fails() {
        let mut g = ClipboardGate::new(ClipboardPolicy::Allow);
        let op = opcode(&WL_DATA_OFFER_INTERFACE, "req", "receive");
        let err = g
            .on_receive(&msg(
                OFFER_FOREIGN,
                op,
                vec![Argument::Str(Some(Box::new(
                    std::ffi::CString::new("text/plain").unwrap(),
                )))],
            ))
            .unwrap_err();
        assert!(err.contains("without an fd"), "{err}");
    }
}
