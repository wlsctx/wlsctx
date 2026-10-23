//! Per-connection object bookkeeping for the proxy.
//!
//! The proxy never allocates object IDs: they are passed through
//! unchanged between the app (a Wayland client) and the compositor (a
//! Wayland server). To parse messages it must know each object's
//! interface, which it learns the same way the protocol says to:
//!
//! * `wl_registry.bind` carries the interface name (`str`) and version;
//! * a `NewId` argument names the new object's interface
//!   (`MessageDesc::child_interface`);
//! * destructor requests/events and the `wl_display.delete_id` event
//!   drive the object's lifetime (see below).
//!
//! Object IDs share one space per connection: client-owned IDs are
//! below the server-ID boundary, server-owned IDs at or above it. The
//! boundary — and the ID of the implicit `wl_display` — depend on which
//! implementation family the peers come from:
//!
//! * **C (libwayland)**: display at object ID 0, client IDs from 1,
//!   server IDs at or above [`SERVER_ID_LIMIT_C`] (sway/wlroots and
//!   Firefox/Librewolf all use this).
//! * **Rust (wayland-backend)**: display at object ID 1 (ID 0 is simply
//!   never allocated), client IDs from 2, server IDs at or above
//!   [`SERVER_ID_LIMIT`].
//!
//! The proxy never *assumes* a convention: the first message of a
//! connection is always addressed to the display, so the first message
//! on an untracked reserved ID (0 or 1) pins the convention for that
//! connection (`ObjectTables::display`). A connection whose two ends
//! disagree about it cannot interoperate and fails closed.
//!
//! # Lifetime model
//!
//! Each entry tracks the two halves of an object's lifetime, mirroring
//! what both peer families actually do (verified against
//! `libwayland`'s client map/zombie machinery and
//! `wayland-backend`'s `Object` flags):
//!
//! * a **destructor request** (client → server) ends the *client* half
//!   (`client_destroyed`);
//! * a **destructor event** (`type="destructor"` in the protocol, e.g.
//!   `wl_callback.done`) ends *both* halves: the object is one-shot on
//!   the server and is consumed by the client on dispatch;
//! * the **`wl_display.delete_id`** event is the server's confirmation
//!   for client-range objects; processing it with the client half
//!   already done removes the entry, freeing the ID. A client cannot
//!   reuse an ID before that confirmation has been processed by it —
//!   and, since the proxy sits on the path, the proxy has already
//!   processed it too — so waiting for it never rejects a legal reuse.
//!
//! A client-range entry whose server half is done but whose client half
//! is not (the object had no destructor, and the client's local drop is
//! invisible on the wire) is kept. If the client later reallocates that
//! ID, the entry is *replaced*: that is the only way a C client frees
//! such a slot (the user calling `wl_proxy_destroy` after `delete_id`),
//! and the reallocation is the proxy's proof of it. Server-range
//! entries are removed as soon as both halves are done (there is no
//! `delete_id` for them), and a server reallocating such an ID replaces
//! the entry.
//!
//! Anything else — reallocating a live ID, or one whose deletion is
//! unconfirmed — is a protocol violation and the connection fails
//! closed. The proxy is deliberately stricter than the clients (which
//! merely log or error out on some of these); its job is to fail
//! closed, not to emulate their allocators exactly.

use std::collections::HashMap;
use std::fmt;
use std::os::fd::OwnedFd;

use wayland_backend::protocol::{Argument, Interface, Message, MessageDesc};
use wayland_client::protocol::__interfaces::WL_DISPLAY_INTERFACE;

use crate::proxy::interfaces;

/// Boundary between client-allocated and server-allocated object IDs
/// in the Rust (wayland-backend) convention
/// (`wayland-backend::rs::map::SERVER_ID_LIMIT`).
pub const SERVER_ID_LIMIT: u32 = 0xFF00_0000;

/// The same boundary in the C (libwayland) convention
/// (`src/wayland-server.c::SERVER_ID_LIMIT`, `1 << 31`).
pub const SERVER_ID_LIMIT_C: u32 = 0x8000_0000;

/// Direction of a message as seen from the proxy's downstream (app) side:
/// [`Dir::ClientToServer`] is app → proxy → compositor (requests),
/// [`Dir::ServerToClient`] is compositor → proxy → app (events).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    ClientToServer,
    ServerToClient,
}

/// A bookkeeping error: the peer violated the protocol, or the proxy
/// cannot explain a message. The connection must be terminated
/// (fail-closed).
#[derive(Debug)]
pub struct BookkeepingError(pub String);

impl fmt::Display for BookkeepingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "protocol violation: {}", self.0)
    }
}

impl std::error::Error for BookkeepingError {}

#[derive(Clone, Debug)]
pub struct Entry {
    pub iface: &'static Interface,
    /// The version the binding/creating side asked for. Informational:
    /// message signatures do not change across interface versions, and
    /// version enforcement is the compositor's job.
    pub version: u32,
    pub client_destroyed: bool,
    pub server_destroyed: bool,
}

/// Both object tables of one connection (client-owned + server-owned IDs
/// share a single ID space, so they cannot collide).
#[derive(Default)]
pub struct ObjectTables {
    client: HashMap<u32, Entry>,
    server: HashMap<u32, Entry>,
    /// The implicit `wl_display` object of this connection: 0 for C
    /// (libwayland) peers, 1 for Rust (wayland-backend) peers. `None`
    /// until the first message — which is always addressed to the
    /// display — pins it.
    display: Option<u32>,
}

impl ObjectTables {
    /// The boundary between client-allocated and server-allocated
    /// object IDs for this connection's convention. Undetected
    /// connections default to the C (production) convention.
    fn server_limit(&self) -> u32 {
        match self.display {
            Some(1) => SERVER_ID_LIMIT,
            _ => SERVER_ID_LIMIT_C,
        }
    }

    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve the interface a message is addressed to, detecting the
    /// connection's display-convention on the way (see the module docs).
    ///
    /// A tracked object resolves from the tables (this also covers the
    /// C convention, where e.g. the registry sits at ID 1). An
    /// *untracked* ID of 0 or 1 is the implicit `wl_display`: if the
    /// convention is not pinned yet, this message pins it; if it
    /// disagrees with the pinned convention, the connection's two ends
    /// cannot interoperate and the error fails it closed. Any other
    /// untracked ID is an unknown object, likewise fatal.
    pub fn sender_interface(&mut self, id: u32) -> Result<&'static Interface, BookkeepingError> {
        if Some(id) == self.display {
            return Ok(&WL_DISPLAY_INTERFACE);
        }
        if let Some(e) = self.client.get(&id).or_else(|| self.server.get(&id)) {
            return Ok(e.iface);
        }
        if id == 0 || id == 1 {
            if let Some(d) = self.display {
                return Err(BookkeepingError(format!(
                    "message on reserved object ID {id}: this connection's display is {d} (mismatched peer conventions)"
                )));
            }
            self.display = Some(id);
            return Ok(&WL_DISPLAY_INTERFACE);
        }
        Err(BookkeepingError(format!("message on unknown object {id}")))
    }

    /// Apply the bookkeeping a relayed message implies, then check it is
    /// consistent with the protocol rules the proxy enforces.
    ///
    /// `desc` is the matched request/event descriptor of `sender`;
    /// `msg` is the parsed message (its `NewId` / `delete_id` arguments
    /// and destructor-ness drive object creation and deletion).
    pub fn apply(
        &mut self,
        dir: Dir,
        msg: &Message<u32, OwnedFd>,
        desc: &MessageDesc,
        sender: &'static Interface,
    ) -> Result<(), BookkeepingError> {
        let limit = self.server_limit();

        // `wl_display.delete_id`: the server's confirmation that it has
        // destroyed a client-range object. Both implementations send it
        // only for IDs below the server-ID boundary, never for the
        // display; anything else is a violation.
        if dir == Dir::ServerToClient && sender.name == "wl_display" && desc.name == "delete_id" {
            let id = match &msg.args.first() {
                Some(Argument::Uint(id)) => *id,
                _ => return Err(BookkeepingError("malformed delete_id".into())),
            };
            if Some(id) == self.display {
                return Err(BookkeepingError(format!(
                    "delete_id on the wl_display object ({id})"
                )));
            }
            if id == 0 {
                return Err(BookkeepingError(
                    "delete_id for object 0 (never allocated in this connection's convention)"
                        .to_string(),
                ));
            }
            if id >= limit {
                return Err(BookkeepingError(format!(
                    "delete_id for server-range object {id} (IDs at or above {limit:#x} are server-allocated; delete_id only confirms client objects)"
                )));
            }
            match self.client.get_mut(&id) {
                Some(e) => {
                    e.server_destroyed = true;
                    // The ID frees on the client when this confirmation
                    // is processed and the client half is already done
                    // (zombie removal in C, flag-gated removal in Rust).
                    if e.client_destroyed {
                        self.client.remove(&id);
                    }
                }
                None => {
                    return Err(BookkeepingError(format!(
                        "delete_id for object {id} the proxy never saw"
                    )));
                }
            }
            return Ok(());
        }

        // A request on an object the client has already destroyed: both
        // client implementations refuse to send one (Rust rejects in
        // send_request; C marks the proxy destroyed), and the server
        // would kill the connection for it. Fail closed.
        if dir == Dir::ClientToServer && Some(msg.sender_id) != self.display {
            let table = if msg.sender_id < limit {
                &self.client
            } else {
                &self.server
            };
            if table
                .get(&msg.sender_id)
                .is_some_and(|e| e.client_destroyed)
            {
                return Err(BookkeepingError(format!(
                    "request '{}' on object {} the client already destroyed",
                    desc.name, msg.sender_id
                )));
            }
        }

        // A destructor request: the client half of the object's
        // lifetime is over.
        if dir == Dir::ClientToServer && desc.is_destructor && Some(msg.sender_id) != self.display {
            let table = if msg.sender_id < limit {
                &mut self.client
            } else {
                &mut self.server
            };
            if let Some(e) = table.get_mut(&msg.sender_id) {
                e.client_destroyed = true;
                // Both halves done: the ID is free. (Client range: the
                // delete_id confirmation has already been processed —
                // it precedes any later reuse the client could send.
                // Server range: the server's own map is gone; there is
                // no delete_id for these.)
                if e.server_destroyed {
                    table.remove(&msg.sender_id);
                }
            }
            // If the object was unknown, sender_interface() already failed.
        }

        // A destructor event: the object is one-shot — the server has
        // destroyed it (no further confirmation for these) and the
        // client consumes it on dispatch. Both implementations treat it
        // as ending both halves. Client-range entries stay allocated
        // until the delete_id confirmation frees them; server-range
        // entries are removed (nothing else will ever free them).
        if dir == Dir::ServerToClient && desc.is_destructor && Some(msg.sender_id) != self.display {
            let table = if msg.sender_id < limit {
                &mut self.client
            } else {
                &mut self.server
            };
            if let Some(e) = table.get_mut(&msg.sender_id) {
                e.client_destroyed = true;
                e.server_destroyed = true;
                if msg.sender_id >= limit {
                    table.remove(&msg.sender_id);
                }
            }
        }

        // NewId argument(s): create the object. Protocol rule: a request
        // creates a client-owned object, an event a server-owned one.
        for arg in &msg.args {
            let Argument::NewId(id) = arg else {
                continue;
            };
            if *id == 0 {
                return Err(BookkeepingError("NewId is 0 (never allocated)".into()));
            }
            if Some(*id) == self.display {
                return Err(BookkeepingError(format!(
                    "NewId is the wl_display ID ({id})"
                )));
            }
            let (iface, version) = if let Some(child) = desc.child_interface {
                (child, child.version)
            } else {
                // The untyped NewId form: only `wl_registry.bind` uses it
                // (uint name, str interface, uint version, new_id) — the
                // scanner expands it that way (see phase0 tests).
                let name = match msg.args.get(1) {
                    Some(Argument::Str(Some(s))) => s.to_string_lossy().into_owned(),
                    _ => {
                        return Err(BookkeepingError(format!(
                            "untyped NewId in non-bind message '{}'",
                            desc.name
                        )));
                    }
                };
                let version = match msg.args.get(2) {
                    Some(Argument::Uint(v)) => *v,
                    _ => {
                        return Err(BookkeepingError(format!(
                            "malformed bind in '{}'",
                            desc.name
                        )));
                    }
                };
                // Fail-closed: the proxy must be able to parse every
                // message on the object it just accepted.
                let iface = interfaces::lookup(&name).ok_or_else(|| {
                    BookkeepingError(format!(
                        "bind of unknown interface {name:?} ({})",
                        desc.name
                    ))
                })?;
                (iface, version)
            };

            let (table, who) = match dir {
                Dir::ClientToServer => {
                    if *id >= limit {
                        return Err(BookkeepingError(format!(
                            "request allocated server-range ID {id} (limit {limit:#x})"
                        )));
                    }
                    (&mut self.client, "client")
                }
                Dir::ServerToClient => {
                    if *id < limit {
                        return Err(BookkeepingError(format!(
                            "event allocated client-range ID {id} (limit {limit:#x})"
                        )));
                    }
                    (&mut self.server, "server")
                }
            };

            // Is the ID still occupied? A well-behaved peer only
            // reallocates an ID whose slot it has freed locally, which
            // (the proxy being on the path) implies exactly these
            // states; anything else is a live or unconfirmed ID.
            if let Some(e) = table.get(id) {
                let (cd, sd) = (e.client_destroyed, e.server_destroyed);
                let legal_reuse = match (dir, cd, sd) {
                    // The client freed the slot: the server deleted
                    // the object (delete_id processed, above) and the
                    // client's own drop — invisible on the wire for C
                    // — has happened. Reuse is proven by the
                    // reallocation itself.
                    (Dir::ClientToServer, false, true) => true,
                    // The server's map slot is free: the client
                    // destroyed the object (destructor request or
                    // event, both seen above) and the server
                    // reallocates it.
                    (Dir::ServerToClient, true, _) => true,
                    // (F,F): live object. (T,*): the client's slot is
                    // still allocated until the delete_id confirmation,
                    // which the proxy has not processed, so the client
                    // cannot have freed it.
                    _ => false,
                };
                if !legal_reuse {
                    return Err(BookkeepingError(format!(
                        "{who} reused object ID {id} (interface {}, client-destroyed: {cd}, server-destroyed: {sd})",
                        iface.name
                    )));
                }
                // The old object is dead on the allocating side;
                // replace the entry with the new one.
            }

            table.insert(
                *id,
                Entry {
                    iface,
                    version,
                    client_destroyed: false,
                    server_destroyed: false,
                },
            );
        }
        Ok(())
    }

    /// Number of live entries (both tables); for tests and logging.
    pub fn len(&self) -> usize {
        self.client.len() + self.server.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The connection's implicit `wl_display` object ID (0 for C peers,
    /// 1 for Rust), once pinned by the first message; `None` before
    /// that. Used to address synthesized `wl_display` events (the
    /// interceptor's `wl_display.error`).
    pub fn display(&self) -> Option<u32> {
        self.display
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn registry_bind_iface() -> &'static Interface {
        &wayland_client::protocol::__interfaces::WL_REGISTRY_INTERFACE
    }

    fn wl_compositor_iface() -> &'static Interface {
        &wayland_client::protocol::__interfaces::WL_COMPOSITOR_INTERFACE
    }

    fn wl_surface_iface() -> &'static Interface {
        &wayland_client::protocol::__interfaces::WL_SURFACE_INTERFACE
    }

    fn wl_callback_iface() -> &'static Interface {
        &wayland_client::protocol::__interfaces::WL_CALLBACK_INTERFACE
    }

    fn display_iface() -> &'static Interface {
        &wayland_client::protocol::__interfaces::WL_DISPLAY_INTERFACE
    }

    fn msg(sender: u32, opcode: u16, args: Vec<Argument<u32, OwnedFd>>) -> Message<u32, OwnedFd> {
        Message {
            sender_id: sender,
            opcode,
            args: args.into(),
        }
    }

    /// Rust (wayland-backend) convention: the first message is
    /// addressed to the display at ID 1.
    fn rust_tables() -> ObjectTables {
        let mut t = ObjectTables::new();
        assert_eq!(t.sender_interface(1).unwrap().name, "wl_display");
        t
    }

    /// C (libwayland) convention: the first message is addressed to the
    /// display at ID 0.
    fn c_tables() -> ObjectTables {
        let mut t = ObjectTables::new();
        assert_eq!(t.sender_interface(0).unwrap().name, "wl_display");
        t
    }

    #[test]
    fn display_id_detection_pins_the_convention() {
        let mut t = ObjectTables::new();
        assert_eq!(t.sender_interface(1).unwrap().name, "wl_display");
        assert_eq!(t.display, Some(1));
        let mut c = ObjectTables::new();
        assert_eq!(c.sender_interface(0).unwrap().name, "wl_display");
        assert_eq!(c.display, Some(0));
    }

    #[test]
    fn mismatched_display_convention_is_an_error() {
        let mut t = ObjectTables::new();
        t.sender_interface(0).unwrap(); // C convention pinned
        let err = t.sender_interface(1).unwrap_err(); // Rust's display, untracked
        assert!(err.0.contains("mismatched"), "{}", err.0);
        let mut r = ObjectTables::new();
        r.sender_interface(1).unwrap();
        let err = r.sender_interface(0).unwrap_err();
        assert!(err.0.contains("mismatched"), "{}", err.0);
    }

    #[test]
    fn registry_bind_creates_client_object() {
        let mut t = rust_tables();
        let bind = &registry_bind_iface().requests[0];
        assert_eq!(bind.name, "bind");
        // Rust convention: the registry (the sender of bind) is ID 2,
        // the first client allocation after the display (ID 1).
        let m = msg(
            2,
            0,
            vec![
                Argument::Uint(7),
                Argument::Str(Some(Box::new(CString::new(b"wl_compositor").unwrap()))),
                Argument::Uint(5),
                Argument::NewId(100),
            ],
        );
        t.apply(Dir::ClientToServer, &m, bind, registry_bind_iface())
            .unwrap();
        let e = t.client.get(&100).unwrap();
        assert_eq!(e.iface.name, "wl_compositor");
        assert_eq!(e.version, 5);
    }

    #[test]
    fn c_convention_registry_at_id_1() {
        // C libwayland: the display is ID 0 and the first client object
        // (the registry) is ID 1 — an ID the Rust convention reserves.
        // A message on the *tracked* ID 1 must resolve as the object,
        // not as the display.
        let mut t = c_tables();
        // First message: get_registry, which allocates the registry at
        // ID 1 (the C client's first allocation, after the display).
        let get_registry = &display_iface().requests[1];
        assert_eq!(get_registry.name, "get_registry");
        let m = msg(0, 1, vec![Argument::NewId(1)]);
        t.apply(Dir::ClientToServer, &m, get_registry, display_iface())
            .unwrap();
        assert_eq!(t.client.get(&1).unwrap().iface.name, "wl_registry");
        // bind is addressed to that tracked ID 1, not to the display.
        let bind = &registry_bind_iface().requests[0];
        let m = msg(
            1,
            0,
            vec![
                Argument::Uint(7),
                Argument::Str(Some(Box::new(CString::new(b"wl_compositor").unwrap()))),
                Argument::Uint(5),
                Argument::NewId(2),
            ],
        );
        t.apply(Dir::ClientToServer, &m, bind, registry_bind_iface())
            .unwrap();
        assert_eq!(t.client.get(&2).unwrap().iface.name, "wl_compositor");
        assert_eq!(t.sender_interface(1).unwrap().name, "wl_registry");
    }

    #[test]
    fn bind_of_unknown_interface_is_an_error() {
        let mut t = rust_tables();
        let bind = &registry_bind_iface().requests[0];
        let m = msg(
            2,
            0,
            vec![
                Argument::Uint(8),
                Argument::Str(Some(Box::new(
                    CString::new(b"zwp_totally_bogus_v99").unwrap(),
                ))),
                Argument::Uint(1),
                Argument::NewId(101),
            ],
        );
        let err = t
            .apply(Dir::ClientToServer, &m, bind, registry_bind_iface())
            .unwrap_err();
        assert!(err.0.contains("unknown interface"), "{}", err.0);
    }

    #[test]
    fn typed_newid_learns_child_interface() {
        let mut t = rust_tables();
        // seed: client object 10 is a wl_compositor
        t.client.insert(
            10,
            Entry {
                iface: wl_compositor_iface(),
                version: 5,
                client_destroyed: false,
                server_destroyed: false,
            },
        );
        let create_surface = &wl_compositor_iface().requests[0];
        assert_eq!(create_surface.name, "create_surface");
        let m = msg(10, 0, vec![Argument::NewId(11)]);
        t.apply(
            Dir::ClientToServer,
            &m,
            create_surface,
            wl_compositor_iface(),
        )
        .unwrap();
        assert_eq!(t.client.get(&11).unwrap().iface.name, "wl_surface");
    }

    #[test]
    fn event_newid_creates_server_object() {
        // Rust convention: server allocation starts at 0xFF00_0000.
        let mut t = rust_tables();
        let sync = &display_iface().requests[0];
        assert_eq!(sync.name, "sync");
        let m = msg(1, 0, vec![Argument::NewId(0xFF00_0001)]);
        t.apply(Dir::ServerToClient, &m, sync, display_iface())
            .unwrap();
        assert_eq!(
            t.server.get(&0xFF00_0001).unwrap().iface.name,
            "wl_callback"
        );
    }

    #[test]
    fn c_convention_server_object_range() {
        // C convention: server allocation starts at 0x8000_0000 — below
        // the Rust limit, so it is only accepted when the C convention
        // is pinned.
        let sync = &display_iface().requests[0];
        let mut c = c_tables();
        let m = msg(0, 0, vec![Argument::NewId(0x8000_0000)]);
        c.apply(Dir::ServerToClient, &m, sync, display_iface())
            .unwrap();
        assert_eq!(
            c.server.get(&0x8000_0000).unwrap().iface.name,
            "wl_callback"
        );
        // The same ID in a Rust-convention connection is a violation.
        let mut r = rust_tables();
        let err = r
            .apply(
                Dir::ServerToClient,
                &msg(1, 0, vec![Argument::NewId(0x8000_0000)]),
                sync,
                display_iface(),
            )
            .unwrap_err();
        assert!(err.0.contains("client-range"), "{}", err.0);
    }

    #[test]
    fn client_range_id_in_event_is_an_error() {
        let mut t = rust_tables();
        let sync = &display_iface().requests[0];
        // the compositor must allocate server-range IDs for objects it
        // creates; a client-range ID here is a protocol violation
        let m = msg(1, 0, vec![Argument::NewId(5)]);
        let err = t
            .apply(Dir::ServerToClient, &m, sync, display_iface())
            .unwrap_err();
        assert!(err.0.contains("client-range"), "{}", err.0);
    }

    #[test]
    fn two_phase_destruction_removes_entry() {
        let mut t = rust_tables();
        // seed: client object 20 is a wl_surface (created via
        // wl_compositor.create_surface in a real client)
        t.client.insert(
            20,
            Entry {
                iface: wl_surface_iface(),
                version: 4,
                client_destroyed: false,
                server_destroyed: false,
            },
        );

        // The client half: the destructor request.
        let destroy = &wl_surface_iface()
            .requests
            .iter()
            .find(|d| d.is_destructor)
            .unwrap();
        assert_eq!(destroy.name, "destroy");
        let m = msg(20, 0, vec![]);
        t.apply(Dir::ClientToServer, &m, destroy, wl_surface_iface())
            .unwrap();
        assert!(
            t.client.contains_key(&20),
            "still alive: server side not done"
        );

        // The server half: the wl_display.delete_id event (wire opcode
        // = the event's 0-based index in the interface = 1).
        let delete_id = &display_iface().events[1];
        assert_eq!(delete_id.name, "delete_id");
        let m = msg(1, 1, vec![Argument::Uint(20)]);
        t.apply(Dir::ServerToClient, &m, delete_id, display_iface())
            .unwrap();
        assert!(!t.client.contains_key(&20), "removed after both halves");
    }

    #[test]
    fn delete_id_of_display_is_an_error() {
        let mut t = c_tables();
        let delete_id = &display_iface().events[1];
        let err = t
            .apply(
                Dir::ServerToClient,
                &msg(0, 1, vec![Argument::Uint(0)]),
                delete_id,
                display_iface(),
            )
            .unwrap_err();
        assert!(err.0.contains("wl_display"), "{}", err.0);
    }

    #[test]
    fn delete_id_for_unknown_object_is_an_error() {
        let mut t = rust_tables();
        let delete_id = &display_iface().events[1];
        let err = t
            .apply(
                Dir::ServerToClient,
                &msg(1, 1, vec![Argument::Uint(999)]),
                delete_id,
                display_iface(),
            )
            .unwrap_err();
        assert!(err.0.contains("never saw"), "{}", err.0);
    }

    #[test]
    fn delete_id_for_server_range_is_an_error() {
        // delete_id only ever confirms client-allocated objects; both
        // implementations guard their senders with the ID boundary.
        let mut t = rust_tables();
        let delete_id = &display_iface().events[1];
        let err = t
            .apply(
                Dir::ServerToClient,
                &msg(1, 1, vec![Argument::Uint(0xFF00_0001)]),
                delete_id,
                display_iface(),
            )
            .unwrap_err();
        assert!(err.0.contains("server-range"), "{}", err.0);
    }

    #[test]
    fn newid_of_display_id_is_an_error() {
        let mut t = rust_tables();
        let bind = &registry_bind_iface().requests[0];
        let m = msg(
            2,
            0,
            vec![
                Argument::Uint(7),
                Argument::Str(Some(Box::new(CString::new(b"wl_compositor").unwrap()))),
                Argument::Uint(4),
                Argument::NewId(1),
            ],
        );
        let err = t
            .apply(Dir::ClientToServer, &m, bind, registry_bind_iface())
            .unwrap_err();
        assert!(err.0.contains("wl_display"), "{}", err.0);
    }

    #[test]
    fn reuse_of_live_id_is_an_error() {
        let mut t = rust_tables();
        let bind = &registry_bind_iface().requests[0];
        let mk = |id: u32| {
            msg(
                2,
                0,
                vec![
                    Argument::Uint(7),
                    Argument::Str(Some(Box::new(CString::new(b"wl_compositor").unwrap()))),
                    Argument::Uint(4),
                    Argument::NewId(id),
                ],
            )
        };
        t.apply(Dir::ClientToServer, &mk(30), bind, registry_bind_iface())
            .unwrap();
        let err = t
            .apply(Dir::ClientToServer, &mk(30), bind, registry_bind_iface())
            .unwrap_err();
        assert!(err.0.contains("reused object ID"), "{}", err.0);
        assert!(
            err.0
                .contains("client-destroyed: false, server-destroyed: false"),
            "{}",
            err.0
        );
    }

    #[test]
    fn client_reuse_before_confirmation_is_an_error() {
        // The client destroyed the object (destructor request sent) but
        // the server's delete_id has not arrived: in both client
        // families the ID slot is still allocated (C: zombie; Rust:
        // entry kept), so a reallocation is a violation.
        let mut t = rust_tables();
        t.client.insert(
            20,
            Entry {
                iface: wl_surface_iface(),
                version: 4,
                client_destroyed: true,
                server_destroyed: false,
            },
        );
        let bind = &registry_bind_iface().requests[0];
        let m = msg(
            2,
            0,
            vec![
                Argument::Uint(7),
                Argument::Str(Some(Box::new(CString::new(b"wl_compositor").unwrap()))),
                Argument::Uint(4),
                Argument::NewId(20),
            ],
        );
        let err = t
            .apply(Dir::ClientToServer, &m, bind, registry_bind_iface())
            .unwrap_err();
        assert!(err.0.contains("reused object ID 20"), "{}", err.0);
        assert!(
            err.0
                .contains("client-destroyed: true, server-destroyed: false"),
            "{}",
            err.0
        );
    }

    #[test]
    fn client_reuse_after_server_deletion_replaces_entry() {
        // Server destroyed the object (delete_id processed) but it had
        // no destructor request and the client's local drop is
        // invisible on the wire (C: the user called wl_proxy_destroy).
        // The client's reallocation of the ID proves the slot is free:
        // replace the entry, do not reject.
        let mut t = rust_tables();
        t.client.insert(
            20,
            Entry {
                iface: wl_surface_iface(),
                version: 4,
                client_destroyed: false,
                server_destroyed: true,
            },
        );
        let bind = &registry_bind_iface().requests[0];
        let m = msg(
            2,
            0,
            vec![
                Argument::Uint(7),
                Argument::Str(Some(Box::new(CString::new(b"wl_compositor").unwrap()))),
                Argument::Uint(4),
                Argument::NewId(20),
            ],
        );
        t.apply(Dir::ClientToServer, &m, bind, registry_bind_iface())
            .unwrap();
        let e = t.client.get(&20).unwrap();
        assert_eq!(e.iface.name, "wl_compositor");
        assert!(!e.client_destroyed && !e.server_destroyed);
    }

    #[test]
    fn destructor_event_consumes_object_and_delete_id_frees_id() {
        // wl_callback.done is a destructor event: it ends both halves.
        // The client-range entry stays (the ID slot is still the
        // client's) until the delete_id confirmation removes it. This
        // is the sync-callback lifecycle that trips naive two-phase
        // bookkeeping.
        let mut t = rust_tables();
        t.client.insert(
            30,
            Entry {
                iface: wl_callback_iface(),
                version: 1,
                client_destroyed: false,
                server_destroyed: false,
            },
        );
        let done = &wl_callback_iface().events[0];
        assert_eq!(done.name, "done");
        assert!(done.is_destructor);
        // wire opcode = the event's 0-based index = 0
        t.apply(
            Dir::ServerToClient,
            &msg(30, 0, vec![Argument::Uint(0)]),
            done,
            wl_callback_iface(),
        )
        .unwrap();
        let e = t.client.get(&30).unwrap();
        assert!(e.client_destroyed && e.server_destroyed);
        assert!(
            t.client.contains_key(&30),
            "ID still allocated until delete_id"
        );

        let delete_id = &display_iface().events[1];
        t.apply(
            Dir::ServerToClient,
            &msg(1, 1, vec![Argument::Uint(30)]),
            delete_id,
            display_iface(),
        )
        .unwrap();
        assert!(!t.client.contains_key(&30), "freed after delete_id");
    }

    #[test]
    fn server_reuse_after_destructor_event_replaces_entry() {
        // Server-range object destroyed by a destructor event: both
        // halves end, the entry is removed, and the server may reuse
        // the ID for a new object.
        let mut t = rust_tables();
        t.server.insert(
            0xFF00_0010,
            Entry {
                iface: wl_callback_iface(),
                version: 1,
                client_destroyed: false,
                server_destroyed: false,
            },
        );
        let done = &wl_callback_iface().events[0];
        t.apply(
            Dir::ServerToClient,
            &msg(0xFF00_0010, 0, vec![Argument::Uint(0)]),
            done,
            wl_callback_iface(),
        )
        .unwrap();
        assert!(
            !t.server.contains_key(&0xFF00_0010),
            "both halves done: removed"
        );

        // The server reallocates the same ID (via an event with a
        // NewId; using the display's sync descriptor as the NewId
        // carrier — the NewId handling is what is under test).
        let sync = &display_iface().requests[0];
        t.apply(
            Dir::ServerToClient,
            &msg(1, 0, vec![Argument::NewId(0xFF00_0010)]),
            sync,
            display_iface(),
        )
        .unwrap();
        assert_eq!(
            t.server.get(&0xFF00_0010).unwrap().iface.name,
            "wl_callback"
        );
    }

    #[test]
    fn request_on_client_destroyed_object_is_an_error() {
        // Both client implementations refuse to send requests on
        // objects they destroyed; a server that kills the connection
        // for it anyway makes this safe to fail closed early.
        let mut t = rust_tables();
        t.client.insert(
            20,
            Entry {
                iface: wl_surface_iface(),
                version: 4,
                client_destroyed: true,
                server_destroyed: true,
            },
        );
        // wl_surface.commit: requests[6], no arguments
        let commit = &wl_surface_iface().requests[6];
        assert_eq!(commit.name, "commit");
        let err = t
            .apply(
                Dir::ClientToServer,
                &msg(20, 6, vec![]),
                commit,
                wl_surface_iface(),
            )
            .unwrap_err();
        assert!(err.0.contains("already destroyed"), "{}", err.0);
    }

    #[test]
    fn sender_interface_lookup() {
        let mut t = rust_tables();
        assert_eq!(t.sender_interface(1).unwrap().name, "wl_display");
        let err = t.sender_interface(0).unwrap_err(); // the other convention's display
        assert!(err.0.contains("mismatched"), "{}", err.0);
        let bind = &registry_bind_iface().requests[0];
        let m = msg(
            2,
            0,
            vec![
                Argument::Uint(7),
                Argument::Str(Some(Box::new(CString::new(b"wl_compositor").unwrap()))),
                Argument::Uint(4),
                Argument::NewId(40),
            ],
        );
        t.apply(Dir::ClientToServer, &m, bind, registry_bind_iface())
            .unwrap();
        assert_eq!(t.sender_interface(40).unwrap().name, "wl_compositor");
        assert!(t.sender_interface(41).is_err());
    }
}
