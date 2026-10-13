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
//! * a destructor request marks the client-side half of the object's
//!   lifetime as over;
//! * the `wl_display.delete_id` event marks the server-side half.
//!
//! Object IDs share one space per connection: client-owned IDs are
//! below [`SERVER_ID_LIMIT`], server-owned IDs at or above it (the same
//! boundary as wayland-backend's object map). ID 0 is the implicit
//! `wl_display` object and is never allocated.
//!
//! The proxy keeps an entry until *both* halves are done (mirroring the
//! backend's `client_destroyed`/`server_destroyed` flags); fully deleted
//! entries are removed, since IDs are never reused by a well-behaved
//! peer and a reuse of a live ID is a protocol violation (fail-closed).

use std::collections::HashMap;
use std::fmt;
use std::os::fd::OwnedFd;

use wayland_backend::protocol::{Argument, Interface, Message, MessageDesc};

use crate::proxy::interfaces;

/// Boundary between client-allocated and server-allocated object IDs.
/// (wayland-backend: `rs/map.rs::SERVER_ID_LIMIT`.)
pub const SERVER_ID_LIMIT: u32 = 0xFF00_0000;

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
}

impl ObjectTables {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve the interface a message is addressed to: ID 0 is the
    /// implicit `wl_display`, other IDs are looked up in the tables.
    ///
    /// Fail-closed: a message on an object the proxy has never seen is a
    /// protocol violation (it cannot be parsed, and the peer is in an
    /// unknown state).
    pub fn sender_interface(&self, id: u32) -> Result<&'static Interface, BookkeepingError> {
        if id == 0 {
            return Ok(&wayland_client::protocol::__interfaces::WL_DISPLAY_INTERFACE);
        }
        let table = if id < SERVER_ID_LIMIT { &self.client } else { &self.server };
        table
            .get(&id)
            .map(|e| e.iface)
            .ok_or_else(|| BookkeepingError(format!("message on unknown object {id}")))
    }

    /// Apply the bookkeeping a relayed message implies, then check it is
    /// consistent with the protocol rules the proxy enforces.
    ///
    /// `desc` is the matched request/event descriptor of `sender`;
    /// `msg` is the parsed message (its `NewId` / `delete_id` arguments
    /// drive object creation and deletion).
    pub fn apply(
        &mut self,
        dir: Dir,
        msg: &Message<u32, OwnedFd>,
        desc: &MessageDesc,
        sender: &'static Interface,
    ) -> Result<(), BookkeepingError> {
        // `wl_display.delete_id`: the server has dropped the object.
        if dir == Dir::ServerToClient
            && sender.name == "wl_display"
            && desc.name == "delete_id"
        {
            let id = match &msg.args.first() {
                Some(Argument::Uint(id)) => *id,
                _ => return Err(BookkeepingError("malformed delete_id".into())),
            };
            if id == 0 {
                return Err(BookkeepingError("delete_id on wl_display (0)".into()));
            }
            let table = if id < SERVER_ID_LIMIT { &mut self.client } else { &mut self.server };
            match table.get_mut(&id) {
                Some(e) => {
                    e.server_destroyed = true;
                    if e.client_destroyed {
                        table.remove(&id);
                    }
                }
                None => {
                    return Err(BookkeepingError(format!(
                        "delete_id for object {id} the proxy never saw"
                    )))
                }
            }
            return Ok(());
        }

        // A destructor request: the client side of the object's lifetime
        // is over. (Only requests have destructors.)
        if dir == Dir::ClientToServer && desc.is_destructor && msg.sender_id != 0 {
            let table = if msg.sender_id < SERVER_ID_LIMIT {
                &mut self.client
            } else {
                &mut self.server
            };
            if let Some(e) = table.get_mut(&msg.sender_id) {
                e.client_destroyed = true;
                if e.server_destroyed {
                    table.remove(&msg.sender_id);
                }
            }
            // If the object was unknown, sender_interface() already failed.
        }

        // NewId argument(s): create the object. Protocol rule: a request
        // creates a client-owned object, an event a server-owned one.
        for arg in &msg.args {
            let Argument::NewId(id) = arg else {
                continue;
            };
            if *id == 0 {
                return Err(BookkeepingError("NewId is 0 (reserved for wl_display)".into()));
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
                        )))
                    }
                };
                let version = match msg.args.get(2) {
                    Some(Argument::Uint(v)) => *v,
                    _ => {
                        return Err(BookkeepingError(format!(
                            "malformed bind in '{}'",
                            desc.name
                        )))
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
                    if *id >= SERVER_ID_LIMIT {
                        return Err(BookkeepingError(format!(
                            "request allocated server-range ID {id}"
                        )));
                    }
                    (&mut self.client, "client")
                }
                Dir::ServerToClient => {
                    if *id < SERVER_ID_LIMIT {
                        return Err(BookkeepingError(format!(
                            "event allocated client-range ID {id}"
                        )));
                    }
                    (&mut self.server, "server")
                }
            };
            if table.contains_key(id) {
                return Err(BookkeepingError(format!(
                    "{who} reused live object ID {id} (interface {})",
                    iface.name
                )));
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
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use super::*;

    fn registry_bind_iface() -> &'static Interface {
        &wayland_client::protocol::__interfaces::WL_REGISTRY_INTERFACE
    }

    fn wl_compositor_iface() -> &'static Interface {
        &wayland_client::protocol::__interfaces::WL_COMPOSITOR_INTERFACE
    }

    fn wl_surface_iface() -> &'static Interface {
        &wayland_client::protocol::__interfaces::WL_SURFACE_INTERFACE
    }

    fn display_iface() -> &'static Interface {
        &wayland_client::protocol::__interfaces::WL_DISPLAY_INTERFACE
    }

    fn msg(sender: u32, opcode: u16, args: Vec<Argument<u32, OwnedFd>>) -> Message<u32, OwnedFd> {
        Message { sender_id: sender, opcode, args: args.into() }
    }

    #[test]
    fn registry_bind_creates_client_object() {
        let mut t = ObjectTables::new();
        let bind = &registry_bind_iface().requests[0];
        assert_eq!(bind.name, "bind");
        let m = msg(1, 0, vec![
            Argument::Uint(7),
            Argument::Str(Some(Box::new(CString::new(b"wl_compositor").unwrap()))),
            Argument::Uint(5),
            Argument::NewId(100),
        ]);
        t.apply(Dir::ClientToServer, &m, bind, registry_bind_iface()).unwrap();
        let e = t.client.get(&100).unwrap();
        assert_eq!(e.iface.name, "wl_compositor");
        assert_eq!(e.version, 5);
    }

    #[test]
    fn bind_of_unknown_interface_is_an_error() {
        let mut t = ObjectTables::new();
        let bind = &registry_bind_iface().requests[0];
        let m = msg(1, 0, vec![
            Argument::Uint(8),
            Argument::Str(Some(Box::new(CString::new(b"zwp_totally_bogus_v99").unwrap()))),
            Argument::Uint(1),
            Argument::NewId(101),
        ]);
        let err = t.apply(Dir::ClientToServer, &m, bind, registry_bind_iface()).unwrap_err();
        assert!(err.0.contains("unknown interface"), "{}", err.0);
    }

    #[test]
    fn typed_newid_learns_child_interface() {
        let mut t = ObjectTables::new();
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
        t.apply(Dir::ClientToServer, &m, create_surface, wl_compositor_iface()).unwrap();
        assert_eq!(t.client.get(&11).unwrap().iface.name, "wl_surface");
    }

    #[test]
    fn event_newid_creates_server_object() {
        let mut t = ObjectTables::new();
        // wl_display.sync → wl_callback (server-allocated ID)
        let sync = &display_iface().requests[0];
        assert_eq!(sync.name, "sync");
        // wl_display.sync → wl_callback (server-allocated ID): the
        // compositor answers the request with an event carrying the
        // new object, so this flows server-to-client.
        let m = msg(0, 0, vec![Argument::NewId(0xFF00_0001)]);
        t.apply(Dir::ServerToClient, &m, sync, display_iface()).unwrap();
        assert_eq!(t.server.get(&0xFF00_0001).unwrap().iface.name, "wl_callback");
    }

    #[test]
    fn client_range_id_in_event_is_an_error() {
        let mut t = ObjectTables::new();
        let sync = &display_iface().requests[0];
        // the compositor must allocate server-range IDs for objects it
        // creates; a client-range ID here is a protocol violation
        let m = msg(0, 0, vec![Argument::NewId(5)]);
        let err = t.apply(Dir::ServerToClient, &m, sync, display_iface()).unwrap_err();
        assert!(err.0.contains("client-range"), "{}", err.0);
    }

    #[test]
    fn two_phase_destruction_removes_entry() {
        let mut t = ObjectTables::new();
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
        t.apply(Dir::ClientToServer, &m, destroy, wl_surface_iface()).unwrap();
        assert!(t.client.contains_key(&20), "still alive: server side not done");

        // The server half: the wl_display.delete_id event.
        let delete_id = &display_iface().events[1];
        assert_eq!(delete_id.name, "delete_id");
        let m = msg(0, 1, vec![Argument::Uint(20)]);
        t.apply(Dir::ServerToClient, &m, delete_id, display_iface()).unwrap();
        assert!(!t.client.contains_key(&20), "removed after both halves");
    }

    #[test]
    fn delete_id_for_unknown_object_is_an_error() {
        let mut t = ObjectTables::new();
        let delete_id = &display_iface().events[1];
        let m = msg(0, 1, vec![Argument::Uint(999)]);
        let err = t
            .apply(Dir::ServerToClient, &m, delete_id, display_iface())
            .unwrap_err();
        assert!(err.0.contains("never saw"), "{}", err.0);
    }

    #[test]
    fn reuse_of_live_id_is_an_error() {
        let mut t = ObjectTables::new();
        let bind = &registry_bind_iface().requests[0];
        let mk = |id: u32| msg(1, 0, vec![
            Argument::Uint(7),
            Argument::Str(Some(Box::new(CString::new(b"wl_compositor").unwrap()))),
            Argument::Uint(4),
            Argument::NewId(id),
        ]);
        t.apply(Dir::ClientToServer, &mk(30), bind, registry_bind_iface()).unwrap();
        let err = t.apply(Dir::ClientToServer, &mk(30), bind, registry_bind_iface()).unwrap_err();
        assert!(err.0.contains("reused live"), "{}", err.0);
    }

    #[test]
    fn sender_interface_lookup() {
        let mut t = ObjectTables::new();
        assert_eq!(t.sender_interface(0).unwrap().name, "wl_display");
        let bind = &registry_bind_iface().requests[0];
        let m = msg(1, 0, vec![
            Argument::Uint(7),
            Argument::Str(Some(Box::new(CString::new(b"wl_compositor").unwrap()))),
            Argument::Uint(4),
            Argument::NewId(40),
        ]);
        t.apply(Dir::ClientToServer, &m, bind, registry_bind_iface()).unwrap();
        assert_eq!(t.sender_interface(40).unwrap().name, "wl_compositor");
        assert!(t.sender_interface(41).is_err());
    }
}
