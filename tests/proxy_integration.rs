//! End-to-end tests of the transparent proxy: a fake compositor
//! (`wayland-server`) behind the tagged socket, a real `wayland-client`
//! in front of the public socket, with the wlsctx relay between them.
//!
//! The pass-through test verifies, in order, that the relay passes
//! through:
//! 1. the registry handshake (server -> client `wl_registry.global`),
//! 2. bound globals (client -> server `wl_registry.bind`),
//! 3. a request whose reply is an event (client `wl_display.sync` ->
//!    server `wl_callback.done`),
//! 4. an out-of-band fd argument (client `wl_shm.create_pool` ->
//!    server, written back through by the fake compositor),
//! 5. a second app session after the first one has gone (per-
//!    connection isolation).
//!
//! The allowlist test runs the proxy with an active global allowlist
//! (`wl_compositor` only) and verifies:
//! 1. only the allowlisted globals are announced to the client,
//! 2. the allowlisted path still works end to end (bind, sync),
//! 3. a `global_remove` of a hidden global never reaches the client,
//! 4. a `bind` of a hidden global name is rejected with a fatal
//!    `wl_display.error` (`invalid_object`) that tears the relay down.
//!
//! The clipboard tests run the proxy with the Phase 3 receive-gate:
//! a fake compositor that speaks the `wl_data_device` protocol, and
//! an app that (1) puts its own data on the clipboard and reads it
//! back, then (2) reads the selection after the compositor has
//! switched it to a foreign (host-owned) source. Under
//! `ClipboardPolicy::Deny` the gate must forward only the read-back
//! of the app's own offer (the app's memfd gets the data) and
//! consume the read of the foreign offer (the app's memfd stays
//! empty, the compositor never sees the request); under
//! `ClipboardPolicy::Allow` both reads reach the compositor and
//! both memfds are filled.
//!
//! The primary-selection tests (Phase 5) run the same scenario on
//! the `wp_primary_selection_unstable_v1` protocol: a fake
//! compositor that speaks the zwp_* interfaces, and an app that
//! copies and reads back its own primary selection, then reads the
//! selection after the compositor switches it to a foreign (host
//! desktop) source. The gate covers both protocols' `receive`
//! requests, so the per-policy outcomes are identical to the
//! clipboard tests'.
//!
//! The broker tests wire the deny gate to a broker (the Phase 4
//! prompt broker): an auto-allow daemon makes the foreign read flow
//! end to end, a counting stand-in that answers `deny` proves the
//! gate consulted the broker before dropping, and a stand-in that
//! answers after the proxy's deadline proves every failure path
//! fails closed (read dropped, session intact, empty clipboard).

use std::io::{Read as _, Seek, SeekFrom, Write as _};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use wayland_client::protocol::{
    wl_buffer, wl_callback, wl_compositor, wl_data_device, wl_data_device_manager, wl_data_offer,
    wl_data_source, wl_registry, wl_seat, wl_shm, wl_shm_pool, wl_surface,
};
use wayland_client::{Connection, Dispatch, QueueHandle};
use wayland_server::Dispatch as ServerDispatch;
use wayland_server::backend::{ClientData, ClientId, DisconnectReason};
use wayland_server::protocol::{
    wl_buffer as srv_wl_buffer, wl_compositor as srv_wl_compositor,
    wl_data_device as srv_wl_data_device, wl_data_device_manager as srv_wl_data_device_manager,
    wl_data_offer as srv_wl_data_offer, wl_data_source as srv_wl_data_source,
    wl_seat as srv_wl_seat, wl_shm as srv_wl_shm, wl_shm_pool as srv_wl_shm_pool,
    wl_surface as srv_wl_surface,
};
use wayland_server::{
    Client, DataInit, Display, DisplayHandle, GlobalDispatch, ListeningSocket, New, Resource,
};

// ------------------------------------------------------------------------
// Fake compositor (server side)
// ------------------------------------------------------------------------

/// Fake-compositor state. One instance is shared across all clients; the
/// `ClientData` impls keep the live-client count in `live`.
struct Srv {
    /// The fd the client last sent with `wl_shm.create_pool`.
    received: Arc<Mutex<Option<OwnedFd>>>,
}

/// Per-client data. The fake compositor keeps a global live-client count
/// so the test can wait for a session's upstream connection to actually
/// close (a plain boolean flag races when a new client connects while the
/// previous one is still disconnecting).
struct ClientDataImpl {
    live: Arc<AtomicUsize>,
}

impl ClientData for ClientDataImpl {
    fn initialized(&self, _client_id: ClientId) {
        self.live.fetch_add(1, Ordering::SeqCst);
    }

    fn disconnected(&self, _client_id: ClientId, _reason: DisconnectReason) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

impl GlobalDispatch<srv_wl_compositor::WlCompositor, ()> for Srv {
    fn bind(
        _state: &mut Self,
        _handle: &DisplayHandle,
        _client: &Client,
        resource: New<srv_wl_compositor::WlCompositor>,
        _global_data: &(),
        data_init: &mut DataInit<'_, Self>,
    ) {
        data_init.init(resource, ());
    }
}

impl ServerDispatch<srv_wl_compositor::WlCompositor, ()> for Srv {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &srv_wl_compositor::WlCompositor,
        request: srv_wl_compositor::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        // Only `CreateSurface` allocates (child `wl_surface`). The
        // generated enum is `#[non_exhaustive]`; the rest
        // (`CreateRegion`, `Release`) are ignored.
        if let srv_wl_compositor::Request::CreateSurface { id } = request {
            data_init.init(id, ());
        }
    }
}

impl GlobalDispatch<srv_wl_shm::WlShm, ()> for Srv {
    fn bind(
        _state: &mut Self,
        _handle: &DisplayHandle,
        _client: &Client,
        resource: New<srv_wl_shm::WlShm>,
        _global_data: &(),
        data_init: &mut DataInit<'_, Self>,
    ) {
        data_init.init(resource, ());
    }
}

impl ServerDispatch<srv_wl_shm::WlShm, ()> for Srv {
    fn request(
        state: &mut Self,
        _client: &Client,
        _resource: &srv_wl_shm::WlShm,
        request: srv_wl_shm::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        // Only `CreatePool` allocates; `Release` (v2) is a plain
        // destructor. Fd probe: write a byte through a dup of the fd
        // the client sent (a dup of the client's pipe write end,
        // forwarded by the proxy).
        if let srv_wl_shm::Request::CreatePool { id, fd, .. } = request {
            let dup = fd.try_clone().unwrap();
            *state.received.lock().unwrap() = Some(fd);
            let _ = std::fs::File::from(dup).write_all(&[0x5c]);
            data_init.init(id, ());
        }
    }
}

impl ServerDispatch<srv_wl_shm_pool::WlShmPool, ()> for Srv {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &srv_wl_shm_pool::WlShmPool,
        request: srv_wl_shm_pool::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        // Only `CreateBuffer` allocates; `Destroy`, `Resize` ignored.
        if let srv_wl_shm_pool::Request::CreateBuffer { id, .. } = request {
            data_init.init(id, ());
        }
    }
}

impl ServerDispatch<srv_wl_buffer::WlBuffer, ()> for Srv {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &srv_wl_buffer::WlBuffer,
        _request: srv_wl_buffer::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
    }
}

impl ServerDispatch<srv_wl_surface::WlSurface, ()> for Srv {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &srv_wl_surface::WlSurface,
        _request: srv_wl_surface::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
    }
}

/// Optional on-demand removal of the fake compositor's `wl_shm`
/// global (used by the allowlist test to exercise `global_remove` of a
/// hidden global).
#[derive(Default)]
struct RemoveTrigger {
    /// The test sets this to request the removal.
    requested: Arc<AtomicBool>,
    /// The compositor sets this once the global is disabled and the
    /// `global_remove` event has been sent to all connected clients.
    done: Arc<AtomicBool>,
}

/// A minimal compositor: listens on the tagged socket, advertises
/// `wl_compositor` and `wl_shm`, creates whatever the client asks for,
/// and writes a probe byte through the fd of every `create_pool`.
///
/// With a [`RemoveTrigger`], it additionally disables (and thereby
/// removes, from every client's point of view) the `wl_shm` global
/// once the trigger is requested.
///
/// Exits when `stop` is set and no clients are live any more.
fn run_fake_compositor(
    tagged_path: PathBuf,
    ready: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    live: Arc<AtomicUsize>,
    received: Arc<Mutex<Option<OwnedFd>>>,
    remove: Option<RemoveTrigger>,
) -> std::io::Result<()> {
    let tagged = ListeningSocket::bind_absolute(tagged_path)
        .map_err(|e| std::io::Error::other(format!("bind tagged socket: {e}")))?;
    let mut display =
        Display::<Srv>::new().map_err(|e| std::io::Error::other(format!("display init: {e}")))?;
    let mut handle = display.handle();
    let _comp_global = handle.create_global::<Srv, srv_wl_compositor::WlCompositor, ()>(4, ());
    let shm_global = handle.create_global::<Srv, srv_wl_shm::WlShm, ()>(2, ());
    let mut state = Srv { received };
    ready.store(true, Ordering::SeqCst);

    loop {
        while let Ok(Some(stream)) = tagged.accept() {
            let data = Arc::new(ClientDataImpl { live: live.clone() });
            handle.insert_client(stream, data)?;
        }
        // On-demand removal: `disable_global` posts `global_remove` to
        // every connected registry (and hides the global from new
        // clients) before this iteration's dispatch/flush run.
        if let Some(trigger) = &remove
            && trigger.requested.load(Ordering::SeqCst)
            && !trigger.done.swap(true, Ordering::SeqCst)
        {
            handle.disable_global::<Srv>(shm_global.clone());
        }
        display.dispatch_clients(&mut state)?;
        display.flush_clients()?;
        if stop.load(Ordering::SeqCst) && live.load(Ordering::SeqCst) == 0 {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(2));
    }
}

// ------------------------------------------------------------------------
// App client (client side)
// ------------------------------------------------------------------------

struct App {
    /// `(global name, interface, version)` from `wl_registry.global`.
    globals: Vec<(u32, String, u32)>,
    /// Set when the `wl_callback.done` of the test `sync` arrives.
    sync_done: Arc<AtomicBool>,
}

impl Dispatch<wl_registry::WlRegistry, ()> for App {
    fn event(
        state: &mut Self,
        _resource: &wl_registry::WlRegistry,
        event: wl_registry::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        if let wl_registry::Event::Global {
            name,
            interface,
            version,
        } = event
        {
            state.globals.push((name, interface, version));
        }
    }
}

impl Dispatch<wl_callback::WlCallback, ()> for App {
    fn event(
        state: &mut Self,
        _resource: &wl_callback::WlCallback,
        event: wl_callback::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        if let wl_callback::Event::Done { .. } = event {
            state.sync_done.store(true, Ordering::SeqCst);
        }
    }
}

/// No-op dispatch for bound interfaces that carry no events this test
/// cares about (required for `registry.bind::<I, (), T>` to typecheck).
macro_rules! no_events {
    ($t:ty, $iface:ty, $event:ty) => {
        impl Dispatch<$iface, ()> for $t {
            fn event(
                _state: &mut Self,
                _resource: &$iface,
                _event: $event,
                _data: &(),
                _conn: &Connection,
                _qh: &QueueHandle<Self>,
            ) {
            }
        }
    };
}

no_events!(App, wl_compositor::WlCompositor, wl_compositor::Event);
no_events!(App, wl_shm::WlShm, wl_shm::Event);
no_events!(App, wl_shm_pool::WlShmPool, wl_shm_pool::Event);
no_events!(App, wl_buffer::WlBuffer, wl_buffer::Event);
no_events!(App, wl_surface::WlSurface, wl_surface::Event);

/// The allowlist test's app: like [`App`], but also records the
/// `global_remove` events it is given (there should be none for the
/// hidden global) and keeps the bound objects alive for the session.
struct AllowlistApp {
    /// `(global name, interface, version)` from `wl_registry.global`.
    globals: Vec<(u32, String, u32)>,
    /// Names from `wl_registry.global_remove`.
    removes: Vec<u32>,
    /// Set when the `wl_callback.done` of the test `sync` arrives.
    sync_done: Arc<AtomicBool>,
}

impl Dispatch<wl_registry::WlRegistry, ()> for AllowlistApp {
    fn event(
        state: &mut Self,
        _resource: &wl_registry::WlRegistry,
        event: wl_registry::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        match event {
            wl_registry::Event::Global {
                name,
                interface,
                version,
            } => {
                state.globals.push((name, interface, version));
            }
            wl_registry::Event::GlobalRemove { name } => {
                state.removes.push(name);
            }
            _ => {}
        }
    }
}

impl Dispatch<wl_callback::WlCallback, ()> for AllowlistApp {
    fn event(
        state: &mut Self,
        _resource: &wl_callback::WlCallback,
        event: wl_callback::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        if let wl_callback::Event::Done { .. } = event {
            state.sync_done.store(true, Ordering::SeqCst);
        }
    }
}

no_events!(
    AllowlistApp,
    wl_compositor::WlCompositor,
    wl_compositor::Event
);
no_events!(AllowlistApp, wl_shm::WlShm, wl_shm::Event);
no_events!(AllowlistApp, wl_surface::WlSurface, wl_surface::Event);

/// A throwaway client that connects *directly* to the tagged socket
/// (bypassing the proxy, so nothing is filtered) to learn the global
/// names the compositor announces — including the hidden one the
/// sandboxed client must never see.
struct Snooper {
    /// `(global name, interface, version)` from `wl_registry.global`.
    globals: Vec<(u32, String, u32)>,
}

impl Dispatch<wl_registry::WlRegistry, ()> for Snooper {
    fn event(
        state: &mut Self,
        _resource: &wl_registry::WlRegistry,
        event: wl_registry::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        if let wl_registry::Event::Global {
            name,
            interface,
            version,
        } = event
        {
            state.globals.push((name, interface, version));
        }
    }
}

/// The `(wl_compositor name, wl_shm name)` pair as seen on the tagged
/// socket.
fn snooper_names(
    tagged_path: &Path,
) -> Result<(u32, u32), Box<dyn std::error::Error + Send + Sync>> {
    let stream = UnixStream::connect(tagged_path)?;
    let conn = Connection::from_socket(stream)?;
    let mut snooper = Snooper {
        globals: Vec::new(),
    };
    let mut eq = conn.new_event_queue::<Snooper>();
    let qh = eq.handle();
    let display = conn.display();
    let _registry = display.get_registry(&qh, ());
    eq.roundtrip(&mut snooper)?;

    let comp = snooper
        .globals
        .iter()
        .find(|(_, iface, _)| iface == "wl_compositor")
        .ok_or("no wl_compositor global on the tagged socket")?
        .0;
    let shm = snooper
        .globals
        .iter()
        .find(|(_, iface, _)| iface == "wl_shm")
        .ok_or("no wl_shm global on the tagged socket")?
        .0;
    assert_ne!(comp, shm, "global names must be distinct");
    Ok((comp, shm))
}

/// One sandboxed app session through a proxy with an active allowlist
/// (only `wl_compositor` is shown).
fn one_allowlist_session(
    public_path: &Path,
    comp_name: u32,
    shm_name: u32,
    remove_shm: Arc<AtomicBool>,
    shm_removed: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sync_done = Arc::new(AtomicBool::new(false));
    let stream = UnixStream::connect(public_path)?;
    let conn = Connection::from_socket(stream)?;
    let mut app = AllowlistApp {
        globals: Vec::new(),
        removes: Vec::new(),
        sync_done: sync_done.clone(),
    };
    let mut eq = conn.new_event_queue::<AllowlistApp>();
    let qh = eq.handle();
    let display = conn.display();
    let registry = display.get_registry(&qh, ());
    eq.roundtrip(&mut app)?;

    // (a) Only the allowlisted global is announced, under the
    // compositor's real name.
    assert_eq!(
        app.globals.len(),
        1,
        "expected exactly one announced global, got: {:?}",
        app.globals
    );
    assert_eq!(app.globals[0].1, "wl_compositor");
    assert_eq!(
        app.globals[0].0, comp_name,
        "the announced name must be the compositor's real name"
    );

    // (b) The allowlisted path still works end to end: the bound
    // object is usable, and `sync` gets its `done`.
    let compositor =
        registry.bind::<wl_compositor::WlCompositor, (), AllowlistApp>(comp_name, 4, &qh, ());
    let surface = compositor.create_surface(&qh, ());
    let _callback = display.sync(&qh, ());
    eq.roundtrip(&mut app)?;
    assert!(
        sync_done.load(Ordering::SeqCst),
        "wl_callback.done never arrived"
    );
    surface.destroy();
    eq.roundtrip(&mut app)?;

    // (c) The compositor removes the hidden global; the matching
    // `global_remove` must never reach the client.
    remove_shm.store(true, Ordering::SeqCst);
    wait_until(|| shm_removed.load(Ordering::SeqCst), 10);
    eq.roundtrip(&mut app)?;
    assert!(
        app.removes.is_empty(),
        "a global_remove leaked to the client: {:?} (hidden global was {shm_name})",
        app.removes
    );

    // (d) Binding the hidden global by name must be rejected with a
    // fatal `invalid_object` error — the only way a client could
    // reach an object it was never shown.
    let _shm = registry.bind::<wl_shm::WlShm, (), AllowlistApp>(shm_name, 2, &qh, ());
    // The injected error makes this roundtrip fail; that is the point.
    let _ = eq.roundtrip(&mut app);
    let err = conn
        .protocol_error()
        .ok_or("no protocol error after the blocked bind")?;
    assert_eq!(err.code, 0, "expected invalid_object (0), got {}", err.code);
    assert!(
        err.message.contains("allowlist"),
        "unexpected error message: {}",
        err.message
    );
    Ok(())
}

/// One full app session through the proxy.
fn one_app_session(public_path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sync_done = Arc::new(AtomicBool::new(false));
    let stream = UnixStream::connect(public_path)?;
    let conn = Connection::from_socket(stream)?;
    let mut app = App {
        globals: Vec::new(),
        sync_done: sync_done.clone(),
    };
    let mut eq = conn.new_event_queue::<App>();
    let qh = eq.handle();
    let display = conn.display();
    let registry = display.get_registry(&qh, ());
    eq.roundtrip(&mut app)?;

    let compositor_name = app
        .globals
        .iter()
        .find(|(_, iface, _)| iface == "wl_compositor")
        .ok_or("no wl_compositor global in the registry")?
        .0;
    let shm_name = app
        .globals
        .iter()
        .find(|(_, iface, _)| iface == "wl_shm")
        .ok_or("no wl_shm global in the registry")?
        .0;

    let compositor =
        registry.bind::<wl_compositor::WlCompositor, (), App>(compositor_name, 4, &qh, ());
    let shm = registry.bind::<wl_shm::WlShm, (), App>(shm_name, 2, &qh, ());
    let surface = compositor.create_surface(&qh, ());
    let _callback = display.sync(&qh, ());
    eq.roundtrip(&mut app)?;
    assert!(
        sync_done.load(Ordering::SeqCst),
        "wl_callback.done never arrived"
    );

    // The fd probe: a blocking reader on the read end of a pipe runs in
    // its own thread; the fake compositor writes through the fd the
    // client handed over.
    let (probe_tx, probe_rx) = mpsc::channel();
    let (reader, writer) = std::io::pipe()?;
    let probe = thread::Builder::new()
        .name("fd-probe".into())
        .spawn(move || {
            let mut reader = reader;
            let mut buf = [0u8; 1];
            probe_tx.send(reader.read(&mut buf)).ok();
        })
        .unwrap();
    let pool = shm.create_pool(writer.as_fd(), 4, &qh, ());
    let buffer = pool.create_buffer(0, 1, 1, 4, wl_shm::Format::Argb8888, &qh, ());
    eq.roundtrip(&mut app)?;
    match probe_rx.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(1)) => {}
        Ok(Ok(n)) => return Err(format!("fd probe: read {n} bytes, expected 1").into()),
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err("fd probe: the compositor never wrote through the fd".into()),
    }
    drop(probe);

    // Tear down the objects we created (wl_compositor, wl_shm and
    // wl_registry have no `destroy` request in the core protocol), then
    // drop the connection.
    buffer.destroy();
    pool.destroy();
    surface.destroy();
    eq.roundtrip(&mut app)?;
    assert!(
        conn.protocol_error().is_none(),
        "protocol error: {:?}",
        conn.protocol_error()
    );
    Ok(())
}

// ------------------------------------------------------------------------
// The test
// ------------------------------------------------------------------------

#[test]
fn relay_passes_messages_and_fds() {
    // The proxy (and the fake compositor) log via `log`; without a
    // logger in this test process the relay's fail-closed warnings
    // would be silent.
    let _ = env_logger::Builder::new()
        .filter_level(::log::LevelFilter::Info)
        .try_init();

    let dir = tempfile::tempdir().unwrap();
    let public_path = dir.path().join("wl-public");
    let tagged_path = dir.path().join("wl-tagged");

    let stop = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(AtomicBool::new(false));
    let live: Arc<AtomicUsize> = Arc::default();
    let received: Arc<Mutex<Option<OwnedFd>>> = Arc::default();

    // The proxy: public listener + one relay per app connection, each
    // connected to the tagged socket.
    let public = wlsctx::proxy::bind_listener(&public_path).unwrap();
    let tagged_for_proxy = tagged_path.clone();
    let stop_proxy = stop.clone();
    let proxy = thread::Builder::new()
        .name("wlsctx-proxy".into())
        .spawn(move || {
            let _ = wlsctx::proxy::event_loop(
                &public,
                &tagged_for_proxy,
                &wlsctx::proxy::Policy::all(),
                wlsctx::proxy::ClipboardPolicy::Allow,
                wlsctx::proxy::AuditConfig::default(),
                None,
                Some(stop_proxy),
            );
        })
        .unwrap();

    // The fake compositor on the tagged socket.
    let (ready_c, live_c, recv_c) = (ready.clone(), live.clone(), received.clone());
    let stop_comp = stop.clone();
    let comp = thread::Builder::new()
        .name("fake-compositor".into())
        .spawn(move || run_fake_compositor(tagged_path, ready_c, stop_comp, live_c, recv_c, None))
        .unwrap();

    wait_until(|| ready.load(Ordering::SeqCst), 10);

    // App 1: a full session (registry, bind, sync, fd, teardown).
    one_app_session(&public_path).expect("app 1 failed");
    wait_until(|| live.load(Ordering::SeqCst) == 0, 10);

    // App 2: a second, independent session while the proxy keeps running.
    one_app_session(&public_path).expect("app 2 failed");
    wait_until(|| live.load(Ordering::SeqCst) == 0, 10);

    // Shut down the fake compositor, then the proxy.
    stop.store(true, Ordering::SeqCst);
    let _ = comp.join();
    let _ = proxy.join();

    // The fd the client sent must have reached the compositor.
    assert!(
        received.lock().unwrap().is_some(),
        "the compositor never received the fd"
    );

    drop(dir);
}

#[test]
fn allowlist_hides_globals_and_rejects_their_binds() {
    let _ = env_logger::Builder::new()
        .filter_level(::log::LevelFilter::Info)
        .try_init();

    let dir = tempfile::tempdir().unwrap();
    let public_path = dir.path().join("wl-public");
    let tagged_path = dir.path().join("wl-tagged");

    let stop = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(AtomicBool::new(false));
    let live: Arc<AtomicUsize> = Arc::default();
    let received: Arc<Mutex<Option<OwnedFd>>> = Arc::default();
    let remove_shm = Arc::new(AtomicBool::new(false));
    let shm_removed = Arc::new(AtomicBool::new(false));

    // The proxy, with an allowlist that shows only `wl_compositor`.
    let public = wlsctx::proxy::bind_listener(&public_path).unwrap();
    let tagged_for_proxy = tagged_path.clone();
    let stop_proxy = stop.clone();
    let proxy = thread::Builder::new()
        .name("wlsctx-proxy".into())
        .spawn(move || {
            let _ = wlsctx::proxy::event_loop(
                &public,
                &tagged_for_proxy,
                &wlsctx::proxy::Policy::from_csv("wl_compositor"),
                wlsctx::proxy::ClipboardPolicy::Allow,
                wlsctx::proxy::AuditConfig::default(),
                None,
                Some(stop_proxy),
            );
        })
        .unwrap();

    // The fake compositor on the tagged socket, with the on-demand
    // removal of its `wl_shm` global.
    let (ready_c, live_c, recv_c) = (ready.clone(), live.clone(), received.clone());
    let (req_c, done_c) = (remove_shm.clone(), shm_removed.clone());
    let stop_comp = stop.clone();
    let tagged_for_comp = tagged_path.clone();
    let comp = thread::Builder::new()
        .name("fake-compositor".into())
        .spawn(move || {
            run_fake_compositor(
                tagged_for_comp,
                ready_c,
                stop_comp,
                live_c,
                recv_c,
                Some(RemoveTrigger {
                    requested: req_c,
                    done: done_c,
                }),
            )
        })
        .unwrap();

    wait_until(|| ready.load(Ordering::SeqCst), 10);

    // Learn the real global names on the tagged socket (the proxy
    // filters them out for the sandboxed client, so it cannot know
    // them itself).
    let (comp_name, shm_name) = snooper_names(&tagged_path).expect("snooper failed");
    wait_until(|| live.load(Ordering::SeqCst) == 0, 10);

    // The sandboxed session: hidden global never announced, allowlisted
    // path works, hidden global_remove never delivered, bind of the
    // hidden name fatal.
    one_allowlist_session(&public_path, comp_name, shm_name, remove_shm, shm_removed)
        .expect("allowlist session failed");

    // The relay was torn down after the fatal error: the compositor must
    // see its (upstream) connection go away.
    wait_until(|| live.load(Ordering::SeqCst) == 0, 10);

    // Shut down the fake compositor, then the proxy.
    stop.store(true, Ordering::SeqCst);
    let _ = comp.join();
    let _ = proxy.join();

    drop(dir);
}

// ------------------------------------------------------------------------
// Phase 3: the clipboard receive-gate
// ------------------------------------------------------------------------

/// What the app's own source serves when the compositor reads it.
const OWN_DATA: &str = "wlsctx-own-data";
/// What the foreign (host) selection serves.
const FOREIGN_DATA: &str = "host-secret";

/// Per-`wl_data_source` state: the mime the app offered on it.
struct SourceState {
    mime: std::sync::Mutex<Option<String>>,
}

/// Per-`wl_data_offer` state: the payload the (fake) selection owner
/// writes when the app receives on it, whether the selection behind
/// it is the app's own or a foreign (host) one, and — for an own
/// offer — the source the data belongs to: a real compositor serves
/// an own read by asking the *owner* (the app) to write the data
/// (a `send` event), which is what the fake does for own offers; a
/// foreign offer has no app-side source, and the fake stands in for
/// the (host) owner there.
#[derive(Clone)]
struct OfferState {
    data: Vec<u8>,
    foreign: bool,
    source: Option<srv_wl_data_source::WlDataSource>,
}

/// The clipboard fake compositor. Like [`Srv`], it answers everything
/// the app asks for, but speaks the data-device protocol: it creates
/// an offer for the app's own source when the app sets the selection,
/// and — once it has served that read-back — switches the selection
/// to a synthetic foreign source (a stand-in for the host desktop),
/// announcing it with a fresh `data_offer` + `selection` pair.
struct Srv2 {
    /// `(origin tag, mime)` for every `wl_data_offer.receive` served.
    received: Arc<Mutex<Vec<(String, String)>>>,
    /// The foreign selection is announced only once.
    foreign_announced: bool,
    /// The app's `wl_data_device` (events for the foreign selection
    /// are sent on it).
    device: Option<srv_wl_data_device::WlDataDevice>,
    /// The current selection's offer (kept alive for the client).
    current_offer: Option<srv_wl_data_offer::WlDataOffer>,
}

impl GlobalDispatch<srv_wl_data_device_manager::WlDataDeviceManager, ()> for Srv2 {
    fn bind(
        _state: &mut Self,
        _handle: &DisplayHandle,
        _client: &Client,
        resource: New<srv_wl_data_device_manager::WlDataDeviceManager>,
        _global_data: &(),
        data_init: &mut DataInit<'_, Self>,
    ) {
        data_init.init(resource, ());
    }
}

impl GlobalDispatch<srv_wl_seat::WlSeat, ()> for Srv2 {
    fn bind(
        _state: &mut Self,
        _handle: &DisplayHandle,
        _client: &Client,
        resource: New<srv_wl_seat::WlSeat>,
        _global_data: &(),
        data_init: &mut DataInit<'_, Self>,
    ) {
        data_init.init(resource, ());
    }
}

impl ServerDispatch<srv_wl_data_device_manager::WlDataDeviceManager, ()> for Srv2 {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &srv_wl_data_device_manager::WlDataDeviceManager,
        request: srv_wl_data_device_manager::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        match request {
            srv_wl_data_device_manager::Request::CreateDataSource { id } => {
                data_init.init(
                    id,
                    SourceState {
                        mime: std::sync::Mutex::new(None),
                    },
                );
            }
            // The seat argument is only validated; the device carries
            // no per-client state in this fake.
            srv_wl_data_device_manager::Request::GetDataDevice { seat: _, id } => {
                data_init.init(id, ());
            }
            _ => {}
        }
    }
}

impl ServerDispatch<srv_wl_seat::WlSeat, ()> for Srv2 {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &srv_wl_seat::WlSeat,
        _request: srv_wl_seat::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
    }
}

impl ServerDispatch<srv_wl_data_device::WlDataDevice, ()> for Srv2 {
    fn request(
        state: &mut Self,
        client: &Client,
        resource: &srv_wl_data_device::WlDataDevice,
        request: srv_wl_data_device::Request,
        _data: &(),
        dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
        match request {
            // The app sets the selection to a source it created:
            // create an offer for it and announce it, exactly like a
            // compositor would (the `data_offer` first, then the
            // `selection` that confirms the change).
            srv_wl_data_device::Request::SetSelection {
                source: Some(src), ..
            } => {
                state.device = Some(resource.clone());
                let offer = client
                    .create_resource::<srv_wl_data_offer::WlDataOffer, OfferState, Srv2>(
                        dhandle,
                        3,
                        OfferState {
                            data: OWN_DATA.as_bytes().to_vec(),
                            foreign: false,
                            source: Some(src.clone()),
                        },
                    )
                    .expect("create the offer for the app's own source");
                state.current_offer = Some(offer.clone());
                resource.data_offer(&offer);
                resource.selection(Some(&offer));
            }
            srv_wl_data_device::Request::SetSelection { source: None, .. } => {
                state.current_offer = None;
                resource.selection(None);
            }
            // start_drag / release: the app never uses them.
            _ => {}
        }
    }
}

impl ServerDispatch<srv_wl_data_source::WlDataSource, SourceState> for Srv2 {
    fn request(
        _state: &mut Self,
        _client: &Client,
        resource: &srv_wl_data_source::WlDataSource,
        request: srv_wl_data_source::Request,
        _data: &SourceState,
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
        // `offer` records the mime; `destroy`/`set_actions` are no-ops.
        if let srv_wl_data_source::Request::Offer { mime_type } = request {
            *resource.data::<SourceState>().unwrap().mime.lock().unwrap() = Some(mime_type);
        }
    }
}

impl ServerDispatch<srv_wl_data_offer::WlDataOffer, OfferState> for Srv2 {
    fn request(
        state: &mut Self,
        client: &Client,
        _resource: &srv_wl_data_offer::WlDataOffer,
        request: srv_wl_data_offer::Request,
        data: &OfferState,
        dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
        // The only request that matters: the app hands us an fd to
        // write the selection into. Write it, close it (the app sees
        // the data — or nothing, if the request was never served),
        // and log who the selection belongs to.
        if let srv_wl_data_offer::Request::Receive { mime_type, fd } = request {
            let foreign = data.foreign;
            state.received.lock().unwrap().push((
                if foreign { "foreign" } else { "own" }.to_string(),
                mime_type.clone(),
            ));
            if let Some(source) = &data.source {
                // The app's own selection: like a real compositor,
                // ask the owner (the app) to write the data into the
                // requester's fd — the app does that on the `send`
                // event (its `wl_data_source` handler below).
                source.send(mime_type, fd.as_fd());
            } else {
                // A foreign selection: the fake stands in for the
                // (host) owner and writes directly.
                let mut f = std::fs::File::from(fd);
                f.write_all(&data.data).expect("write the selection data");
                drop(f);
            }
            // Having served the app's read-back, simulate the host
            // desktop changing the clipboard: a new selection owned
            // by a source the app never created.
            if !foreign
                && !state.foreign_announced
                && let Some(device) = &state.device
            {
                state.foreign_announced = true;
                let offer = client
                    .create_resource::<srv_wl_data_offer::WlDataOffer, OfferState, Srv2>(
                        dhandle,
                        3,
                        OfferState {
                            data: FOREIGN_DATA.as_bytes().to_vec(),
                            foreign: true,
                            source: None,
                        },
                    )
                    .expect("create the foreign offer");
                state.current_offer = Some(offer.clone());
                device.data_offer(&offer);
                device.selection(Some(&offer));
            }
        }
        // accept / finish / set_actions / destroy: no-ops.
    }
}

/// The clipboard fake compositor: listens on the tagged socket,
/// advertises `wl_data_device_manager` and `wl_seat`, and serves
/// `receive` on every offer it created. Exits when `stop` is set and
/// no clients are live.
fn run_fake_data_device_compositor(
    tagged_path: PathBuf,
    ready: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    live: Arc<AtomicUsize>,
    received: Arc<Mutex<Vec<(String, String)>>>,
) -> std::io::Result<()> {
    let tagged = ListeningSocket::bind_absolute(tagged_path)
        .map_err(|e| std::io::Error::other(format!("bind tagged socket: {e}")))?;
    let mut display =
        Display::<Srv2>::new().map_err(|e| std::io::Error::other(format!("display init: {e}")))?;
    let mut handle = display.handle();
    handle.create_global::<Srv2, srv_wl_data_device_manager::WlDataDeviceManager, ()>(3, ());
    handle.create_global::<Srv2, srv_wl_seat::WlSeat, ()>(10, ());
    let mut state = Srv2 {
        received,
        foreign_announced: false,
        device: None,
        current_offer: None,
    };
    ready.store(true, Ordering::SeqCst);

    loop {
        while let Ok(Some(stream)) = tagged.accept() {
            let data = Arc::new(ClientDataImpl { live: live.clone() });
            handle.insert_client(stream, data)?;
        }
        display.dispatch_clients(&mut state)?;
        display.flush_clients()?;
        if stop.load(Ordering::SeqCst) && live.load(Ordering::SeqCst) == 0 {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(2));
    }
}

/// The sandboxed app for the clipboard tests: it binds the
/// data-device stack, puts its own data on the clipboard and reads it
/// back, then — when the compositor switches the selection to a
/// foreign source — reads that one too. Each read goes into its own
/// memfd (kept by the app, so the test can inspect what the
/// selection owner wrote — or didn't).
struct ClipboardApp {
    /// `(global name, interface, version)` from `wl_registry.global`.
    globals: Vec<(u32, String, u32)>,
    /// The app's read target for its own selection's read-back.
    own_fd: OwnedFd,
    /// The app's read target for the foreign selection's read.
    foreign_fd: OwnedFd,
    /// Set when the app called `receive` on the (first) selection.
    own_received: Arc<AtomicBool>,
    /// Set when the app called `receive` on the (second, foreign) one.
    foreign_received: Arc<AtomicBool>,
    /// How many `selection` events with a non-NULL offer arrived.
    selections: u32,
}

impl Dispatch<wl_registry::WlRegistry, ()> for ClipboardApp {
    fn event(
        state: &mut Self,
        _resource: &wl_registry::WlRegistry,
        event: wl_registry::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        if let wl_registry::Event::Global {
            name,
            interface,
            version,
        } = event
        {
            state.globals.push((name, interface, version));
        }
    }
}

impl Dispatch<wl_data_device::WlDataDevice, ()> for ClipboardApp {
    fn event(
        state: &mut Self,
        _resource: &wl_data_device::WlDataDevice,
        event: wl_data_device::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        // data_offer / enter / leave / motion / drop: unused here.
        if let wl_data_device::Event::Selection { id: Some(offer) } = event {
            state.selections += 1;
            if state.selections == 1 {
                // The read-back of the app's own selection:
                // forwarded under both policies.
                offer.receive("text/plain".into(), state.own_fd.as_fd());
                state.own_received.store(true, Ordering::SeqCst);
            } else {
                // The foreign (host) selection: forwarded only
                // under `Allow`; under `Deny` the gate consumes
                // the request and this fd stays empty.
                offer.receive("text/plain".into(), state.foreign_fd.as_fd());
                state.foreign_received.store(true, Ordering::SeqCst);
            }
            offer.destroy();
        }
    }

    // The `data_offer` event creates a `wl_data_offer` child; the
    // macro above only handles events, so the user-data
    // specialization has to be given explicitly.
    wayland_client::event_created_child!(ClipboardApp, wl_data_device::WlDataDevice, [
        wl_data_device::EVT_DATA_OFFER_OPCODE => (wl_data_offer::WlDataOffer, ()),
    ]);
}

no_events!(
    ClipboardApp,
    wl_data_device_manager::WlDataDeviceManager,
    wl_data_device_manager::Event
);
impl Dispatch<wl_data_source::WlDataSource, ()> for ClipboardApp {
    fn event(
        _state: &mut Self,
        _resource: &wl_data_source::WlDataSource,
        event: wl_data_source::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        // The (fake) compositor asks the app — the selection owner —
        // to write its own data into the requester's fd, exactly like
        // a real compositor would (the per-mime byte flow behind a
        // set; the relay audits it as a `serve`).
        if let wl_data_source::Event::Send { mime_type, fd } = event
            && mime_type == "text/plain"
        {
            let mut f = std::fs::File::from(fd);
            f.write_all(OWN_DATA.as_bytes())
                .expect("write the offered data");
        }
    }
}
no_events!(ClipboardApp, wl_seat::WlSeat, wl_seat::Event);
no_events!(
    ClipboardApp,
    wl_data_offer::WlDataOffer,
    wl_data_offer::Event
);

/// One clipboard session through the proxy: the app copies (its own
/// selection) and then reads a foreign one. Returns the contents of
/// the two memfds after the session.
/// One clipboard session through the proxy: the app copies (its own
/// selection) and then reads a foreign one. `settle` is a quiet
/// window after both reads, before the teardown — the audit tests
/// use it to let the relay's size probes settle (two 250 ms ticks).
/// `clear_selection` makes the app clear the (now foreign)
/// selection *after* that window — the audit tests use it for the
/// `clear` record, which is emitted immediately (no probe), so it
/// comes last. Returns the contents of the two memfds after the
/// session.
fn one_clipboard_session(
    public_path: &Path,
    settle: Duration,
    clear_selection: bool,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    let memfd = |name: &str| -> std::io::Result<OwnedFd> {
        Ok(rustix::fs::memfd_create(
            name,
            rustix::fs::MemfdFlags::empty(),
        )?)
    };
    let own_fd = memfd("wlsctx-test-own")?;
    let foreign_fd = memfd("wlsctx-test-foreign")?;

    let own_received = Arc::new(AtomicBool::new(false));
    let foreign_received = Arc::new(AtomicBool::new(false));

    let stream = UnixStream::connect(public_path)?;
    let conn = Connection::from_socket(stream)?;
    let mut app = ClipboardApp {
        globals: Vec::new(),
        own_fd,
        foreign_fd,
        own_received: own_received.clone(),
        foreign_received: foreign_received.clone(),
        selections: 0,
    };
    let mut eq = conn.new_event_queue::<ClipboardApp>();
    let qh = eq.handle();
    let display = conn.display();
    let registry = display.get_registry(&qh, ());
    eq.roundtrip(&mut app)?;

    let ddm_name = app
        .globals
        .iter()
        .find(|(_, iface, _)| iface == "wl_data_device_manager")
        .ok_or("no wl_data_device_manager global in the registry")?
        .0;
    let seat_name = app
        .globals
        .iter()
        .find(|(_, iface, _)| iface == "wl_seat")
        .ok_or("no wl_seat global in the registry")?
        .0;

    let ddm = registry.bind::<wl_data_device_manager::WlDataDeviceManager, (), ClipboardApp>(
        ddm_name,
        3,
        &qh,
        (),
    );
    let seat = registry.bind::<wl_seat::WlSeat, (), ClipboardApp>(seat_name, 10, &qh, ());
    let device = ddm.get_data_device(&seat, &qh, ());

    // The app copies: a new source offering text/plain becomes the
    // selection. The compositor echoes it with a data_offer +
    // selection pair, and the first `selection` handler below does
    // the read-back into `own_fd`.
    let source = ddm.create_data_source(&qh, ());
    source.offer("text/plain".into());
    device.set_selection(Some(&source), 0);

    // Pump until the app has performed both reads (its own
    // read-back, then the foreign read after the compositor's
    // selection switch). `blocking_dispatch` flushes the app's
    // queued requests, blocks until the compositor's events arrive,
    // and dispatches them — `dispatch_pending` alone would never
    // read the socket.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        eq.blocking_dispatch(&mut app)?;
        if app.own_received.load(Ordering::SeqCst) && app.foreign_received.load(Ordering::SeqCst) {
            break;
        }
        if Instant::now() > deadline {
            return Err(format!(
                "timed out: own={} foreign={} selections={}",
                app.own_received.load(Ordering::SeqCst),
                app.foreign_received.load(Ordering::SeqCst),
                app.selections
            )
            .into());
        }
        thread::sleep(Duration::from_millis(1));
    }

    // The app may hold unflushed requests: wayland-client's
    // `blocking_dispatch` only flushes when it had to block, so the
    // last `receive` can still be sitting in the queue here. Flush
    // before the settle window, so the relay's probes measure from
    // a settled state (and nothing is released in a burst at the
    // end of the window).
    eq.flush()?;
    if !settle.is_zero() {
        thread::sleep(settle);
    }
    if clear_selection {
        // The app clears the (now foreign) selection: a
        // `set_selection` with a NULL source. The relay audits the
        // `clear`; the compositor echoes the empty selection. A
        // short tail lets the clear round-trip before the teardown.
        device.set_selection(None, 0);
        eq.flush()?;
        thread::sleep(Duration::from_millis(100));
    }

    // Tear down (the compositor confirms with delete_id); no
    // protocol error may be pending on either end of the session.
    source.destroy();
    device.release();
    seat.release();
    // Each destructor is answered by a `delete_id`, so the blocking
    // read also surfaces any pending protocol error; the final
    // `dispatch_pending` drains the rest of the same datagram.
    eq.blocking_dispatch(&mut app)?;
    eq.dispatch_pending(&mut app)?;
    assert!(
        conn.protocol_error().is_none(),
        "protocol error: {:?}",
        conn.protocol_error()
    );

    let mut own = Vec::new();
    let mut own_fd = std::fs::File::from(app.own_fd);
    own_fd.seek(SeekFrom::Start(0))?;
    own_fd.read_to_end(&mut own)?;
    let mut foreign = Vec::new();
    let mut foreign_fd = std::fs::File::from(app.foreign_fd);
    foreign_fd.seek(SeekFrom::Start(0))?;
    foreign_fd.read_to_end(&mut foreign)?;
    Ok((own, foreign))
}

/// Run the whole three-party scenario (compositor, proxy with
/// `policy` and `audit`, one app session) and assert the outcome for
/// that policy.
fn run_clipboard_session(
    policy: wlsctx::proxy::ClipboardPolicy,
    audit: wlsctx::proxy::AuditConfig,
    settle: Duration,
    clear_selection: bool,
) {
    let _ = env_logger::Builder::new()
        .filter_level(::log::LevelFilter::Info)
        .try_init();

    let dir = tempfile::tempdir().unwrap();
    let public_path = dir.path().join("wl-public");
    let tagged_path = dir.path().join("wl-tagged");

    let stop = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(AtomicBool::new(false));
    let live: Arc<AtomicUsize> = Arc::default();
    let received: Arc<Mutex<Vec<(String, String)>>> = Arc::default();

    let public = wlsctx::proxy::bind_listener(&public_path).unwrap();
    let tagged_for_proxy = tagged_path.clone();
    let stop_proxy = stop.clone();
    let proxy = thread::Builder::new()
        .name("wlsctx-proxy".into())
        .spawn(move || {
            let _ = wlsctx::proxy::event_loop(
                &public,
                &tagged_for_proxy,
                &wlsctx::proxy::Policy::all(),
                policy,
                audit,
                None,
                Some(stop_proxy),
            );
        })
        .unwrap();

    let (ready_c, live_c, recv_c) = (ready.clone(), live.clone(), received.clone());
    let stop_comp = stop.clone();
    let comp = thread::Builder::new()
        .name("fake-compositor".into())
        .spawn(move || {
            run_fake_data_device_compositor(tagged_path, ready_c, stop_comp, live_c, recv_c)
        })
        .unwrap();

    wait_until(|| ready.load(Ordering::SeqCst), 10);

    let (own, foreign) = one_clipboard_session(&public_path, settle, clear_selection)
        .expect("clipboard session failed");

    // The app disconnected before the shutdown, so the compositor's
    // view must settle to zero live clients before it exits.
    wait_until(|| live.load(Ordering::SeqCst) == 0, 10);
    stop.store(true, Ordering::SeqCst);
    let _ = comp.join();
    let _ = proxy.join();

    match policy {
        wlsctx::proxy::ClipboardPolicy::Allow => {
            // Pass-through: both reads were served, from both origins.
            assert_eq!(own, OWN_DATA.as_bytes(), "own read-back payload");
            assert_eq!(foreign, FOREIGN_DATA.as_bytes(), "foreign payload");
            assert_eq!(
                *received.lock().unwrap(),
                vec![
                    ("own".to_string(), "text/plain".to_string()),
                    ("foreign".to_string(), "text/plain".to_string()),
                ],
                "the compositor must have served both reads"
            );
        }
        wlsctx::proxy::ClipboardPolicy::Deny => {
            // The own read-back went through; the foreign read was
            // consumed by the gate — the compositor never saw it, and
            // the app's fd for it stayed empty (an empty clipboard
            // read, not a crash).
            assert_eq!(own, OWN_DATA.as_bytes(), "own read-back payload");
            assert!(foreign.is_empty(), "foreign read must stay empty");
            assert_eq!(
                *received.lock().unwrap(),
                vec![("own".to_string(), "text/plain".to_string())],
                "the foreign receive never reached the compositor"
            );
        }
    }

    drop(dir);
}

#[test]
fn clipboard_allow_is_a_passthrough() {
    run_clipboard_session(
        wlsctx::proxy::ClipboardPolicy::Allow,
        wlsctx::proxy::AuditConfig::default(),
        Duration::ZERO,
        false,
    );
}

#[test]
fn clipboard_deny_allows_own_readback_and_drops_foreign() {
    run_clipboard_session(
        wlsctx::proxy::ClipboardPolicy::Deny,
        wlsctx::proxy::AuditConfig::default(),
        Duration::ZERO,
        false,
    );
}

/// The audit capture sink (Phase 9): records the rendered lines in
/// emission order, for assertion after the session.
struct CaptureSink {
    lines: Arc<Mutex<Vec<String>>>,
}

impl wlsctx::proxy::AuditSink for CaptureSink {
    fn audit(&self, app: &str, instance: &str, record: &wlsctx::proxy::AuditRecord) {
        self.lines
            .lock()
            .unwrap()
            .push(wlsctx::proxy::format_audit(app, instance, record));
    }
}

/// Phase 9: the audit log of an allow-policy clipboard session. The
/// session (copy, read-back, foreign read, clear) produces exactly
/// five records — one per selection event the relay saw — each
/// saying only what a record is allowed to say: names, decisions,
/// sizes; never the data. The read/serve sizes settle in the settle
/// window (the probes see the final size before the teardown).
#[test]
fn clipboard_session_is_audited() {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let audit = wlsctx::proxy::AuditConfig::with_sink(
        "testapp".into(),
        "inst".into(),
        Arc::new(CaptureSink {
            lines: lines.clone(),
        }),
    );
    run_clipboard_session(
        wlsctx::proxy::ClipboardPolicy::Allow,
        audit,
        Duration::from_millis(700),
        true,
    );

    let lines = lines.lock().unwrap();
    assert_eq!(
        *lines,
        vec![
            "app=testapp instance=inst selection=clipboard action=set origin=own",
            "app=testapp instance=inst selection=clipboard action=read origin=own mime=text/plain gate=forward fd_kind=memfd payload_bytes=15",
            "app=testapp instance=inst selection=clipboard action=serve origin=own mime=text/plain fd_kind=memfd payload_bytes=15",
            "app=testapp instance=inst selection=clipboard action=read origin=foreign mime=text/plain gate=forward fd_kind=memfd payload_bytes=11",
            "app=testapp instance=inst selection=clipboard action=clear origin=foreign",
        ],
        "the session's five selection events, in order"
    );
}

/// Phase 9: the audit log of a deny-policy clipboard session. The
/// own read-back goes through (the gate's exemption) and settles to
/// its size; the foreign read is consumed by the gate and audited
/// as `dropped` with 0 bytes *at once* (the fd was never handed
/// over, so there is nothing to probe — the record precedes the
/// deferred probe records); the clear records the origin of the
/// selection that was removed (the foreign one the compositor
/// switched to).
#[test]
fn clipboard_deny_is_audited_with_a_drop() {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let audit = wlsctx::proxy::AuditConfig::with_sink(
        "testapp".into(),
        "inst".into(),
        Arc::new(CaptureSink {
            lines: lines.clone(),
        }),
    );
    run_clipboard_session(
        wlsctx::proxy::ClipboardPolicy::Deny,
        audit,
        Duration::from_millis(700),
        true,
    );

    let lines = lines.lock().unwrap();
    assert_eq!(
        *lines,
        vec![
            "app=testapp instance=inst selection=clipboard action=set origin=own",
            "app=testapp instance=inst selection=clipboard action=read origin=foreign mime=text/plain gate=dropped fd_kind=memfd payload_bytes=0",
            "app=testapp instance=inst selection=clipboard action=read origin=own mime=text/plain gate=forward fd_kind=memfd payload_bytes=15",
            "app=testapp instance=inst selection=clipboard action=serve origin=own mime=text/plain fd_kind=memfd payload_bytes=15",
            "app=testapp instance=inst selection=clipboard action=clear origin=foreign",
        ],
        "the session's five selection events: the drop is immediate, the probes settle in the window"
    );
}

// ------------------------------------------------------------------------
// Two fd-bearing messages in one datagram
// ------------------------------------------------------------------------
//
// Regression test for the Phase 1 fd-misrouting defect in
// `Relay::forward()`. A wayland client (or compositor) batches every
// buffered message *and* every buffered fd into a single `sendmsg` on
// flush; a multi-mime paste is therefore two `receive` requests with
// two fds in one datagram, and `forward()` must hand the i-th message
// of the batch the i-th fd in arrival order (it once peeled the
// *tail* of the queue while the parse consumed the *front* — two fds,
// a full swap).
//
// This drives the real three-party path: a fake compositor (`Srv4`)
// announces two `wl_data_offer` objects — one per mime, each with its
// own sentinel payload — and a real `wayland-client` app issues the
// two `receive` requests back to back, inside one dispatch pass and
// with no flush in between, so wayland-client's next flush carries
// both requests and both fds in one `sendmsg`. The fake writes its
// own sentinel into whichever fd each `receive` is handed; the
// assertion is per-fd content — each app memfd must hold the payload
// of the offer *it* asked about. Under the tail-slice defect the
// two sentinels come back swapped.

/// One sentinel per offer, distinct (even in length), so a
/// cross-wired pairing is unambiguous.
const PLAIN_SENTINEL: &[u8] = b"PLAIN-SENTINEL";
const HTML_SENTINEL: &[u8] = b"HTML-SENTINEL";

/// The two-offer fake compositor. As soon as the app gets a
/// `wl_data_device`, it announces two `wl_data_offer` objects in one
/// flush, each standing in for a selection with a different mime and
/// a different payload. Each `receive` is served by writing the
/// offer's own sentinel into the fd it is handed; once both are
/// served it sends one `wl_data_device.selection` — a synchronization
/// ack the app waits on before reading its fds (the write happens
/// before the event on this thread, and the socket preserves order,
/// so the fd is fully written by the time the ack arrives).
struct Srv4 {
    /// `(origin tag, mime)` for every `wl_data_offer.receive` served.
    received: Arc<Mutex<Vec<(String, String)>>>,
    /// The offers, in announcement order (kept alive for the
    /// session: the app's `receive` requests address them).
    offers: Vec<srv_wl_data_offer::WlDataOffer>,
    /// The device the offers are announced on (for the ack).
    device: Option<srv_wl_data_device::WlDataDevice>,
    /// How many `receive` requests have been served.
    served: u32,
    /// The post-serve ack has been sent.
    ack_sent: bool,
}

impl GlobalDispatch<srv_wl_data_device_manager::WlDataDeviceManager, ()> for Srv4 {
    fn bind(
        _state: &mut Self,
        _handle: &DisplayHandle,
        _client: &Client,
        resource: New<srv_wl_data_device_manager::WlDataDeviceManager>,
        _global_data: &(),
        data_init: &mut DataInit<'_, Self>,
    ) {
        data_init.init(resource, ());
    }
}

impl GlobalDispatch<srv_wl_seat::WlSeat, ()> for Srv4 {
    fn bind(
        _state: &mut Self,
        _handle: &DisplayHandle,
        _client: &Client,
        resource: New<srv_wl_seat::WlSeat>,
        _global_data: &(),
        data_init: &mut DataInit<'_, Self>,
    ) {
        data_init.init(resource, ());
    }
}

impl ServerDispatch<srv_wl_data_device_manager::WlDataDeviceManager, ()> for Srv4 {
    fn request(
        state: &mut Self,
        client: &Client,
        _resource: &srv_wl_data_device_manager::WlDataDeviceManager,
        request: srv_wl_data_device_manager::Request,
        _data: &(),
        dhandle: &DisplayHandle,
        data_init: &mut DataInit<Self>,
    ) {
        // The app's one request here: it gets a device, and the
        // fake immediately announces the two offers on it — in one
        // flush, the same shape as a real compositor announcing a
        // new selection. (The app never creates a data source here:
        // a `create_data_source` is a no-op.)
        if let srv_wl_data_device_manager::Request::GetDataDevice { seat: _, id } = request {
            let device = data_init.init::<srv_wl_data_device::WlDataDevice, _>(id, ());
            state.device = Some(device.clone());
            let offer_a = client
                .create_resource::<srv_wl_data_offer::WlDataOffer, OfferState, Srv4>(
                    dhandle,
                    3,
                    OfferState {
                        data: PLAIN_SENTINEL.to_vec(),
                        foreign: true,
                        source: None,
                    },
                )
                .expect("create the first offer");
            let offer_b = client
                .create_resource::<srv_wl_data_offer::WlDataOffer, OfferState, Srv4>(
                    dhandle,
                    3,
                    OfferState {
                        data: HTML_SENTINEL.to_vec(),
                        foreign: true,
                        source: None,
                    },
                )
                .expect("create the second offer");
            state.offers = vec![offer_a.clone(), offer_b];
            device.data_offer(&state.offers[0]);
            device.data_offer(&state.offers[1]);
        }
    }
}

impl ServerDispatch<srv_wl_seat::WlSeat, ()> for Srv4 {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &srv_wl_seat::WlSeat,
        _request: srv_wl_seat::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<Self>,
    ) {
    }
}

impl ServerDispatch<srv_wl_data_device::WlDataDevice, ()> for Srv4 {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &srv_wl_data_device::WlDataDevice,
        _request: srv_wl_data_device::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<Self>,
    ) {
        // The app sends no requests on the device.
    }
}

impl ServerDispatch<srv_wl_data_offer::WlDataOffer, OfferState> for Srv4 {
    fn request(
        state: &mut Self,
        _client: &Client,
        _resource: &srv_wl_data_offer::WlDataOffer,
        request: srv_wl_data_offer::Request,
        data: &OfferState,
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<Self>,
    ) {
        // The only request that matters: the app handed us an fd to
        // write the selection into. Write this offer's own sentinel
        // into whatever fd arrived with the request — if the relay
        // mispaired the batch, that is the wrong fd, and the
        // app's per-fd assertion catches it.
        if let srv_wl_data_offer::Request::Receive { mime_type, fd } = request {
            state.received.lock().unwrap().push((
                if data.foreign { "foreign" } else { "own" }.to_string(),
                mime_type.clone(),
            ));
            let mut f = std::fs::File::from(fd);
            f.write_all(&data.data).expect("write the selection data");
            drop(f);
            state.served += 1;
            // Both serves done: send the app its ack.
            if state.served == 2
                && !state.ack_sent
                && let Some(device) = &state.device
            {
                state.ack_sent = true;
                if let Some(offer) = state.offers.first() {
                    device.selection(Some(offer));
                }
            }
        }
        // accept / finish / set_actions / destroy: no-ops.
    }
}

/// The two-offer fake compositor: the
/// [`run_fake_data_device_compositor`] harness with [`Srv4`].
fn run_fake_two_offer_compositor(
    tagged_path: PathBuf,
    ready: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    live: Arc<AtomicUsize>,
    received: Arc<Mutex<Vec<(String, String)>>>,
) -> std::io::Result<()> {
    let tagged = ListeningSocket::bind_absolute(tagged_path)
        .map_err(|e| std::io::Error::other(format!("bind tagged socket: {e}")))?;
    let mut display =
        Display::<Srv4>::new().map_err(|e| std::io::Error::other(format!("display init: {e}")))?;
    let mut handle = display.handle();
    handle.create_global::<Srv4, srv_wl_data_device_manager::WlDataDeviceManager, ()>(3, ());
    handle.create_global::<Srv4, srv_wl_seat::WlSeat, ()>(10, ());
    let mut state = Srv4 {
        received,
        offers: Vec::new(),
        device: None,
        served: 0,
        ack_sent: false,
    };
    ready.store(true, Ordering::SeqCst);

    loop {
        while let Ok(Some(stream)) = tagged.accept() {
            let data = Arc::new(ClientDataImpl { live: live.clone() });
            handle.insert_client(stream, data)?;
        }
        display.dispatch_clients(&mut state)?;
        display.flush_clients()?;
        if stop.load(Ordering::SeqCst) && live.load(Ordering::SeqCst) == 0 {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(2));
    }
}

/// The sandboxed app for the two-fd test: it binds the data-device
/// stack, and — once the (fake) compositor has announced both offers
/// — issues the two `receive` requests back to back, inside one
/// dispatch pass and with no flush in between: wayland-client's next
/// flush sends both requests, with their two fds, in one `sendmsg`,
/// the exact shape of a real multi-mime paste. Each read goes into
/// its own memfd, which the test inspects after the fake's ack.
struct TwoOfferApp {
    /// `(global name, interface, version)` from `wl_registry.global`.
    globals: Vec<(u32, String, u32)>,
    /// The announced offers, in announcement order.
    offers: Vec<wl_data_offer::WlDataOffer>,
    /// The app's read target for the first offer's read.
    fd_a: OwnedFd,
    /// The app's read target for the second offer's read.
    fd_b: OwnedFd,
    /// Set when the fake's post-serve ack arrives.
    acked: Arc<AtomicBool>,
}

impl Dispatch<wl_registry::WlRegistry, ()> for TwoOfferApp {
    fn event(
        state: &mut Self,
        _resource: &wl_registry::WlRegistry,
        event: wl_registry::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        if let wl_registry::Event::Global {
            name,
            interface,
            version,
        } = event
        {
            state.globals.push((name, interface, version));
        }
    }
}

impl Dispatch<wl_data_device::WlDataDevice, ()> for TwoOfferApp {
    fn event(
        state: &mut Self,
        _resource: &wl_data_device::WlDataDevice,
        event: wl_data_device::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        match event {
            wl_data_device::Event::DataOffer { id } => {
                state.offers.push(id);
                if state.offers.len() == 2 {
                    // Two back-to-back `receive`s, inside one
                    // dispatch pass: the queue is not flushed
                    // between them, so the next flush carries both
                    // requests — and both fds — in one `sendmsg`.
                    state.offers[0].receive("text/plain".into(), state.fd_a.as_fd());
                    state.offers[1].receive("text/html".into(), state.fd_b.as_fd());
                }
            }
            // The fake's post-serve ack: by the time it arrives both
            // memfds have been written (see the Srv4 docs).
            wl_data_device::Event::Selection { id: Some(_) } => {
                state.acked.store(true, Ordering::SeqCst);
            }
            // data_offer(NULL) / enter / leave / motion / drop:
            // unused here.
            _ => {}
        }
    }

    // The `data_offer` event creates a `wl_data_offer` child; the
    // macro above only handles events, so the user-data
    // specialization has to be given explicitly.
    wayland_client::event_created_child!(TwoOfferApp, wl_data_device::WlDataDevice, [
        wl_data_device::EVT_DATA_OFFER_OPCODE => (wl_data_offer::WlDataOffer, ()),
    ]);
}

no_events!(
    TwoOfferApp,
    wl_data_device_manager::WlDataDeviceManager,
    wl_data_device_manager::Event
);
no_events!(
    TwoOfferApp,
    wl_data_offer::WlDataOffer,
    wl_data_offer::Event
);
no_events!(TwoOfferApp, wl_seat::WlSeat, wl_seat::Event);

/// One two-fd session through the proxy. Returns the contents of
/// the app's two memfds after the fake has served both reads.
fn one_two_offer_session(
    public_path: &Path,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    let memfd = |name: &str| -> std::io::Result<OwnedFd> {
        Ok(rustix::fs::memfd_create(
            name,
            rustix::fs::MemfdFlags::empty(),
        )?)
    };
    let fd_a = memfd("wlsctx-test-fd-a")?;
    let fd_b = memfd("wlsctx-test-fd-b")?;
    let acked = Arc::new(AtomicBool::new(false));

    let stream = UnixStream::connect(public_path)?;
    let conn = Connection::from_socket(stream)?;
    let mut app = TwoOfferApp {
        globals: Vec::new(),
        offers: Vec::new(),
        fd_a,
        fd_b,
        acked: acked.clone(),
    };
    let mut eq = conn.new_event_queue::<TwoOfferApp>();
    let qh = eq.handle();
    let display = conn.display();
    let registry = display.get_registry(&qh, ());
    eq.roundtrip(&mut app)?;

    let ddm_name = app
        .globals
        .iter()
        .find(|(_, iface, _)| iface == "wl_data_device_manager")
        .ok_or("no wl_data_device_manager global in the registry")?
        .0;
    let seat_name = app
        .globals
        .iter()
        .find(|(_, iface, _)| iface == "wl_seat")
        .ok_or("no wl_seat global in the registry")?
        .0;

    let ddm = registry.bind::<wl_data_device_manager::WlDataDeviceManager, (), TwoOfferApp>(
        ddm_name,
        3,
        &qh,
        (),
    );
    let seat = registry.bind::<wl_seat::WlSeat, (), TwoOfferApp>(seat_name, 10, &qh, ());
    ddm.get_data_device(&seat, &qh, ());

    // Wait for the fake to announce both offers and serve both
    // receives; the break is on the fake's ack (its `selection`
    // after the second serve), which — see Srv4 — arrives only
    // after both memfds are written.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        eq.blocking_dispatch(&mut app)?;
        if app.acked.load(Ordering::SeqCst) {
            break;
        }
        if Instant::now() > deadline {
            return Err(format!(
                "timed out: offers={} acked={}",
                app.offers.len(),
                app.acked.load(Ordering::SeqCst)
            )
            .into());
        }
        thread::sleep(Duration::from_millis(1));
    }

    assert!(
        conn.protocol_error().is_none(),
        "protocol error: {:?}",
        conn.protocol_error()
    );

    let read = |fd: OwnedFd| -> std::io::Result<Vec<u8>> {
        let mut f = std::fs::File::from(fd);
        f.seek(SeekFrom::Start(0))?;
        let mut v = Vec::new();
        f.read_to_end(&mut v)?;
        Ok(v)
    };
    let a = read(app.fd_a)?;
    let b = read(app.fd_b)?;
    Ok((a, b))
}

#[test]
fn two_fd_messages_in_one_datagram_keep_their_fds() {
    // The proxy (and the fake compositor) log via `log`; without a
    // logger in this test process the relay's fail-closed warnings
    // would be silent.
    let _ = env_logger::Builder::new()
        .filter_level(::log::LevelFilter::Info)
        .try_init();

    let dir = tempfile::tempdir().unwrap();
    let public_path = dir.path().join("wl-public");
    let tagged_path = dir.path().join("wl-tagged");

    let stop = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(AtomicBool::new(false));
    let live: Arc<AtomicUsize> = Arc::default();
    let received: Arc<Mutex<Vec<(String, String)>>> = Arc::default();

    // The proxy: `Allow` (pure pass-through) — the gate's
    // forward/drop decision is keyed on the sender id, not the fd,
    // so the defect is visible on the forwarded path.
    let public = wlsctx::proxy::bind_listener(&public_path).unwrap();
    let tagged_for_proxy = tagged_path.clone();
    let stop_proxy = stop.clone();
    let proxy = thread::Builder::new()
        .name("wlsctx-proxy".into())
        .spawn(move || {
            let _ = wlsctx::proxy::event_loop(
                &public,
                &tagged_for_proxy,
                &wlsctx::proxy::Policy::all(),
                wlsctx::proxy::ClipboardPolicy::Allow,
                wlsctx::proxy::AuditConfig::default(),
                None,
                Some(stop_proxy),
            );
        })
        .unwrap();

    // The fake two-offer compositor on the tagged socket.
    let (ready_c, live_c, recv_c) = (ready.clone(), live.clone(), received.clone());
    let stop_comp = stop.clone();
    let comp = thread::Builder::new()
        .name("fake-compositor".into())
        .spawn(move || {
            run_fake_two_offer_compositor(tagged_path, ready_c, stop_comp, live_c, recv_c)
        })
        .unwrap();

    wait_until(|| ready.load(Ordering::SeqCst), 10);

    let (fd_a, fd_b) = one_two_offer_session(&public_path).expect("two-fd session failed");

    // The app disconnected before the shutdown, so the compositor's
    // view must settle to zero live clients before it exits.
    wait_until(|| live.load(Ordering::SeqCst) == 0, 10);
    stop.store(true, Ordering::SeqCst);
    let _ = comp.join();
    let _ = proxy.join();

    // The heart of it: each app fd holds the payload of the offer
    // *its own* `receive` asked about — not the other offer's. The
    // Phase 1 tail-slice defect paired the first message with the
    // second fd (and vice versa), and these come back swapped.
    assert_eq!(
        fd_a,
        PLAIN_SENTINEL.to_vec(),
        "the first fd must hold the first offer's payload"
    );
    assert_eq!(
        fd_b,
        HTML_SENTINEL.to_vec(),
        "the second fd must hold the second offer's payload"
    );
    // Sanity: both reads reached the compositor, in message order
    // (the relay forwards messages in order even when it mispairs
    // their fds, so this holds pre-fix as well).
    assert_eq!(
        *received.lock().unwrap(),
        vec![
            ("foreign".to_string(), "text/plain".to_string()),
            ("foreign".to_string(), "text/html".to_string()),
        ],
        "both reads reached the compositor, in order"
    );

    drop(dir);
}

// ------------------------------------------------------------------------
// Phase 5: primary selection (wp_primary_selection_unstable_v1)
// ------------------------------------------------------------------------
//
// The same three-party scenario as the clipboard tests, on the
// primary-selection protocol: a fake compositor that speaks the
// zwp_* protocol, and an app that copies (its own primary
// selection) and reads it back, then reads the selection after the
// compositor switches it to a foreign (host-owned) source. The
// receive-gate covers both protocols' `receive` requests (Phase 5),
// so the outcomes must be identical to the clipboard tests' for each
// policy.

use wayland_protocols::wp::primary_selection::zv1::client::{
    zwp_primary_selection_device_manager_v1 as cl_zps_mgr,
    zwp_primary_selection_device_v1 as cl_zps_device,
    zwp_primary_selection_offer_v1 as cl_zps_offer,
    zwp_primary_selection_source_v1 as cl_zps_source,
};
use wayland_protocols::wp::primary_selection::zv1::server::{
    zwp_primary_selection_device_manager_v1 as srv_zps_mgr,
    zwp_primary_selection_device_v1 as srv_zps_device,
    zwp_primary_selection_offer_v1 as srv_zps_offer,
    zwp_primary_selection_source_v1 as srv_zps_source,
};

/// The primary-selection fake compositor: the [`Srv2`] twin on the
/// zwp_* protocol. It answers `create_source`/`get_device`, echoes a
/// `set_selection` with `data_offer` + `selection` (its own data),
/// serves `receive` on its offers, and — after serving the own
/// read-back — switches the selection to a synthetic foreign source
/// the app never created.
struct Srv3 {
    /// `(origin tag, mime)` for every `receive` served.
    received: Arc<Mutex<Vec<(String, String)>>>,
    /// The foreign selection is announced only once.
    foreign_announced: bool,
    /// The app's `zwp_primary_selection_device_v1` (the foreign
    /// selection is announced on it).
    device: Option<srv_zps_device::ZwpPrimarySelectionDeviceV1>,
    /// The current selection's offer (kept alive for the client).
    current_offer: Option<srv_zps_offer::ZwpPrimarySelectionOfferV1>,
}

impl GlobalDispatch<srv_zps_mgr::ZwpPrimarySelectionDeviceManagerV1, ()> for Srv3 {
    fn bind(
        _state: &mut Self,
        _handle: &DisplayHandle,
        _client: &Client,
        resource: New<srv_zps_mgr::ZwpPrimarySelectionDeviceManagerV1>,
        _global_data: &(),
        data_init: &mut DataInit<'_, Self>,
    ) {
        data_init.init(resource, ());
    }
}

impl GlobalDispatch<srv_wl_seat::WlSeat, ()> for Srv3 {
    fn bind(
        _state: &mut Self,
        _handle: &DisplayHandle,
        _client: &Client,
        resource: New<srv_wl_seat::WlSeat>,
        _global_data: &(),
        data_init: &mut DataInit<'_, Self>,
    ) {
        data_init.init(resource, ());
    }
}

impl ServerDispatch<srv_zps_mgr::ZwpPrimarySelectionDeviceManagerV1, ()> for Srv3 {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &srv_zps_mgr::ZwpPrimarySelectionDeviceManagerV1,
        request: srv_zps_mgr::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        match request {
            srv_zps_mgr::Request::CreateSource { id } => {
                data_init.init(id, ());
            }
            // The seat argument is only validated.
            srv_zps_mgr::Request::GetDevice { id, .. } => {
                data_init.init(id, ());
            }
            _ => {}
        }
    }
}

impl ServerDispatch<srv_wl_seat::WlSeat, ()> for Srv3 {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &srv_wl_seat::WlSeat,
        _request: srv_wl_seat::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
    }
}

impl ServerDispatch<srv_zps_device::ZwpPrimarySelectionDeviceV1, ()> for Srv3 {
    fn request(
        state: &mut Self,
        client: &Client,
        resource: &srv_zps_device::ZwpPrimarySelectionDeviceV1,
        request: srv_zps_device::Request,
        _data: &(),
        dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
        match request {
            // The app sets the primary selection to a source it
            // created: echo it like a compositor (data_offer first,
            // then the confirming selection).
            srv_zps_device::Request::SetSelection {
                source: Some(_), ..
            } => {
                state.device = Some(resource.clone());
                let offer = client
                    .create_resource::<srv_zps_offer::ZwpPrimarySelectionOfferV1, OfferState, Srv3>(
                        dhandle,
                        1,
                        OfferState {
                            data: OWN_DATA.as_bytes().to_vec(),
                            foreign: false,
                            source: None,
                        },
                    )
                    .expect("create the offer for the app's own primary selection");
                state.current_offer = Some(offer.clone());
                resource.data_offer(&offer);
                resource.selection(Some(&offer));
            }
            srv_zps_device::Request::SetSelection { source: None, .. } => {
                state.current_offer = None;
                resource.selection(None);
            }
            _ => {}
        }
    }
}

impl ServerDispatch<srv_zps_source::ZwpPrimarySelectionSourceV1, ()> for Srv3 {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &srv_zps_source::ZwpPrimarySelectionSourceV1,
        _request: srv_zps_source::Request,
        _data: &(),
        _dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
    }
}

impl ServerDispatch<srv_zps_offer::ZwpPrimarySelectionOfferV1, OfferState> for Srv3 {
    fn request(
        state: &mut Self,
        client: &Client,
        _resource: &srv_zps_offer::ZwpPrimarySelectionOfferV1,
        request: srv_zps_offer::Request,
        data: &OfferState,
        dhandle: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
        if let srv_zps_offer::Request::Receive { mime_type, fd } = request {
            let payload = data.data.clone();
            let foreign = data.foreign;
            let mut f = std::fs::File::from(fd);
            f.write_all(&payload)
                .expect("write the primary selection data");
            drop(f);
            state.received.lock().unwrap().push((
                if foreign { "foreign" } else { "own" }.to_string(),
                mime_type,
            ));
            // After serving the own read-back, simulate the host
            // desktop changing the primary selection to a source the
            // app never created.
            if !foreign
                && !state.foreign_announced
                && let Some(device) = &state.device
            {
                state.foreign_announced = true;
                let offer = client
                    .create_resource::<srv_zps_offer::ZwpPrimarySelectionOfferV1, OfferState, Srv3>(
                        dhandle,
                        1,
                        OfferState {
                            data: FOREIGN_DATA.as_bytes().to_vec(),
                            foreign: true,
                            source: None,
                        },
                    )
                    .expect("create the foreign primary offer");
                state.current_offer = Some(offer.clone());
                device.data_offer(&offer);
                device.selection(Some(&offer));
            }
        }
        // destroy: no-op.
    }
}

/// The primary-selection fake compositor: listens on the tagged
/// socket, advertises `zwp_primary_selection_device_manager_v1` (and
/// `wl_seat`, which `get_device` requires), and serves `receive` on
/// every offer it created.
fn run_fake_primary_compositor(
    tagged_path: PathBuf,
    ready: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    live: Arc<AtomicUsize>,
    received: Arc<Mutex<Vec<(String, String)>>>,
) -> std::io::Result<()> {
    let tagged = ListeningSocket::bind_absolute(tagged_path)
        .map_err(|e| std::io::Error::other(format!("bind tagged socket: {e}")))?;
    let mut display =
        Display::<Srv3>::new().map_err(|e| std::io::Error::other(format!("display init: {e}")))?;
    let mut handle = display.handle();
    handle.create_global::<Srv3, srv_zps_mgr::ZwpPrimarySelectionDeviceManagerV1, ()>(1, ());
    handle.create_global::<Srv3, srv_wl_seat::WlSeat, ()>(10, ());
    let mut state = Srv3 {
        received,
        foreign_announced: false,
        device: None,
        current_offer: None,
    };
    ready.store(true, Ordering::SeqCst);

    loop {
        while let Ok(Some(stream)) = tagged.accept() {
            let data = Arc::new(ClientDataImpl { live: live.clone() });
            handle.insert_client(stream, data)?;
        }
        display.dispatch_clients(&mut state)?;
        display.flush_clients()?;
        if stop.load(Ordering::SeqCst) && live.load(Ordering::SeqCst) == 0 {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(2));
    }
}

/// The sandboxed app for the primary-selection tests: it puts its
/// own data on the primary selection and reads it back, then — when
/// the compositor switches the selection to a foreign source — reads
/// that one too. Each read goes into its own memfd, so the test can
/// inspect what the selection owner wrote (or didn't).
struct PrimaryApp {
    /// `(global name, interface, version)` from `wl_registry.global`.
    globals: Vec<(u32, String, u32)>,
    /// Read target for the own selection's read-back.
    own_fd: OwnedFd,
    /// Read target for the foreign selection's read.
    foreign_fd: OwnedFd,
    /// Set when the app called `receive` on the first selection.
    own_received: Arc<AtomicBool>,
    /// Set when the app called `receive` on the second one.
    foreign_received: Arc<AtomicBool>,
    /// How many non-NULL `selection` events arrived.
    selections: u32,
}

impl Dispatch<cl_zps_device::ZwpPrimarySelectionDeviceV1, ()> for PrimaryApp {
    fn event(
        state: &mut Self,
        _resource: &cl_zps_device::ZwpPrimarySelectionDeviceV1,
        event: cl_zps_device::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        if let cl_zps_device::Event::Selection { id: Some(offer) } = event {
            state.selections += 1;
            if state.selections == 1 {
                // The read-back of the app's own selection.
                offer.receive("text/plain".into(), state.own_fd.as_fd());
                state.own_received.store(true, Ordering::SeqCst);
            } else {
                // The foreign (host) selection: forwarded only under
                // `Allow` (or inside an intent window); under
                // `Deny` the gate consumes the request and this fd
                // stays empty.
                offer.receive("text/plain".into(), state.foreign_fd.as_fd());
                state.foreign_received.store(true, Ordering::SeqCst);
            }
            offer.destroy();
        }
    }

    // The `data_offer` event creates a `zwp_primary_selection_offer_v1`
    // child; the user-data specialization has to be given explicitly.
    wayland_client::event_created_child!(PrimaryApp, cl_zps_device::ZwpPrimarySelectionDeviceV1, [
        cl_zps_device::EVT_DATA_OFFER_OPCODE => (cl_zps_offer::ZwpPrimarySelectionOfferV1, ()),
    ]);
}

impl Dispatch<wl_registry::WlRegistry, ()> for PrimaryApp {
    fn event(
        state: &mut Self,
        _resource: &wl_registry::WlRegistry,
        event: wl_registry::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        if let wl_registry::Event::Global {
            name,
            interface,
            version,
        } = event
        {
            state.globals.push((name, interface, version));
        }
    }
}

no_events!(
    PrimaryApp,
    cl_zps_mgr::ZwpPrimarySelectionDeviceManagerV1,
    cl_zps_mgr::Event
);
no_events!(
    PrimaryApp,
    cl_zps_source::ZwpPrimarySelectionSourceV1,
    cl_zps_source::Event
);
no_events!(
    PrimaryApp,
    cl_zps_offer::ZwpPrimarySelectionOfferV1,
    cl_zps_offer::Event
);
no_events!(PrimaryApp, wl_seat::WlSeat, wl_seat::Event);

/// One primary-selection session through the proxy: the app copies
/// (its own selection) and then reads a foreign one. Returns the
/// contents of the two memfds after the session.
fn one_primary_session(
    public_path: &Path,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    let memfd = |name: &str| -> std::io::Result<OwnedFd> {
        Ok(rustix::fs::memfd_create(
            name,
            rustix::fs::MemfdFlags::empty(),
        )?)
    };
    let own_fd = memfd("wlsctx-test-own-primary")?;
    let foreign_fd = memfd("wlsctx-test-foreign-primary")?;

    let own_received = Arc::new(AtomicBool::new(false));
    let foreign_received = Arc::new(AtomicBool::new(false));

    let stream = UnixStream::connect(public_path)?;
    let conn = Connection::from_socket(stream)?;
    let mut app = PrimaryApp {
        globals: Vec::new(),
        own_fd,
        foreign_fd,
        own_received: own_received.clone(),
        foreign_received: foreign_received.clone(),
        selections: 0,
    };
    let mut eq = conn.new_event_queue::<PrimaryApp>();
    let qh = eq.handle();
    let display = conn.display();
    let registry = display.get_registry(&qh, ());
    eq.roundtrip(&mut app)?;

    let psm_name = app
        .globals
        .iter()
        .find(|(_, iface, _)| iface == "zwp_primary_selection_device_manager_v1")
        .ok_or("no zwp_primary_selection_device_manager_v1 global in the registry")?
        .0;
    let seat_name = app
        .globals
        .iter()
        .find(|(_, iface, _)| iface == "wl_seat")
        .ok_or("no wl_seat global in the registry")?
        .0;

    let psm = registry.bind::<cl_zps_mgr::ZwpPrimarySelectionDeviceManagerV1, (), PrimaryApp>(
        psm_name,
        1,
        &qh,
        (),
    );
    let seat = registry.bind::<wl_seat::WlSeat, (), PrimaryApp>(seat_name, 10, &qh, ());
    let device = psm.get_device(&seat, &qh, ());

    // The app copies: a new source offering text/plain becomes the
    // primary selection. The compositor echoes it with a
    // data_offer + selection pair, and the first `selection`
    // handler does the read-back into `own_fd`.
    let source = psm.create_source(&qh, ());
    source.offer("text/plain".into());
    device.set_selection(Some(&source), 0);

    // Pump until the app has performed both reads.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        eq.blocking_dispatch(&mut app)?;
        if app.own_received.load(Ordering::SeqCst) && app.foreign_received.load(Ordering::SeqCst) {
            break;
        }
        if Instant::now() > deadline {
            return Err(format!(
                "timed out: own={} foreign={} selections={}",
                app.own_received.load(Ordering::SeqCst),
                app.foreign_received.load(Ordering::SeqCst),
                app.selections
            )
            .into());
        }
        thread::sleep(Duration::from_millis(1));
    }

    // Tear down (each destructor is answered by a `delete_id`, so the
    // blocking read also surfaces any pending protocol error).
    source.destroy();
    device.destroy();
    seat.release();
    eq.blocking_dispatch(&mut app)?;
    eq.dispatch_pending(&mut app)?;
    assert!(
        conn.protocol_error().is_none(),
        "protocol error: {:?}",
        conn.protocol_error()
    );

    let mut own = Vec::new();
    let mut own_fd = std::fs::File::from(app.own_fd);
    own_fd.seek(SeekFrom::Start(0))?;
    own_fd.read_to_end(&mut own)?;
    let mut foreign = Vec::new();
    let mut foreign_fd = std::fs::File::from(app.foreign_fd);
    foreign_fd.seek(SeekFrom::Start(0))?;
    foreign_fd.read_to_end(&mut foreign)?;
    Ok((own, foreign))
}

/// Run the whole three-party primary-selection scenario (compositor,
/// proxy with `policy`, one app session) and assert the outcome.
fn run_primary_session(policy: wlsctx::proxy::ClipboardPolicy) {
    let _ = env_logger::Builder::new()
        .filter_level(::log::LevelFilter::Info)
        .try_init();

    let dir = tempfile::tempdir().unwrap();
    let public_path = dir.path().join("wl-public");
    let tagged_path = dir.path().join("wl-tagged");

    let stop = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(AtomicBool::new(false));
    let live: Arc<AtomicUsize> = Arc::default();
    let received: Arc<Mutex<Vec<(String, String)>>> = Arc::default();

    let public = wlsctx::proxy::bind_listener(&public_path).unwrap();
    let tagged_for_proxy = tagged_path.clone();
    let stop_proxy = stop.clone();
    let proxy = thread::Builder::new()
        .name("wlsctx-proxy".into())
        .spawn(move || {
            let _ = wlsctx::proxy::event_loop(
                &public,
                &tagged_for_proxy,
                &wlsctx::proxy::Policy::all(),
                policy,
                wlsctx::proxy::AuditConfig::default(),
                None,
                Some(stop_proxy),
            );
        })
        .unwrap();

    let (ready_c, live_c, recv_c) = (ready.clone(), live.clone(), received.clone());
    let stop_comp = stop.clone();
    let comp = thread::Builder::new()
        .name("fake-primary-compositor".into())
        .spawn(move || run_fake_primary_compositor(tagged_path, ready_c, stop_comp, live_c, recv_c))
        .unwrap();

    wait_until(|| ready.load(Ordering::SeqCst), 10);

    let (own, foreign) =
        one_primary_session(&public_path).expect("primary-selection session failed");

    wait_until(|| live.load(Ordering::SeqCst) == 0, 10);
    stop.store(true, Ordering::SeqCst);
    let _ = comp.join();
    let _ = proxy.join();

    match policy {
        wlsctx::proxy::ClipboardPolicy::Allow => {
            // Pass-through: both reads were served, from both origins.
            assert_eq!(own, OWN_DATA.as_bytes(), "own read-back payload");
            assert_eq!(foreign, FOREIGN_DATA.as_bytes(), "foreign payload");
            assert_eq!(
                *received.lock().unwrap(),
                vec![
                    ("own".to_string(), "text/plain".to_string()),
                    ("foreign".to_string(), "text/plain".to_string()),
                ],
                "the compositor must have served both reads"
            );
        }
        wlsctx::proxy::ClipboardPolicy::Deny => {
            // The own read-back went through; the foreign read was
            // consumed by the gate — the compositor never saw it, and
            // the app's fd for it stayed empty.
            assert_eq!(own, OWN_DATA.as_bytes(), "own read-back payload");
            assert!(foreign.is_empty(), "foreign read must stay empty");
            assert_eq!(
                *received.lock().unwrap(),
                vec![("own".to_string(), "text/plain".to_string())],
                "the foreign receive never reached the compositor"
            );
        }
    }

    drop(dir);
}

#[test]
fn primary_selection_allow_is_a_passthrough() {
    run_primary_session(wlsctx::proxy::ClipboardPolicy::Allow);
}

#[test]
fn primary_selection_deny_allows_own_readback_and_drops_foreign() {
    run_primary_session(wlsctx::proxy::ClipboardPolicy::Deny);
}

/// Phase 4: the same three-party clipboard session, but with the
/// proxy wired to a broker for the reads the gate drops. The gate
/// is `Deny` in every case below, so the outcome differs from the
/// Phase 3 deny test only through what the broker answers:
///
/// * `AutoAllow`: the *real* broker daemon's per-connection path
///   (`wlsctx::broker::handle_connection` with `AutoDecide::Allow`)
///   on its own socket. The foreign read must flow end to end: the
///   gate drops it, the proxy asks, the allow opens the intent
///   window, the read is forwarded, the compositor serves it, and
///   the app's memfd gets the host data. Only an allow could do
///   that under a deny gate.
/// * `AutoDeny`: a stand-in broker that counts the proxy's asks and
///   answers `deny`. The session must come out exactly like the
///   Phase 3 deny test — and the counter proves the gate *asked*
///   the broker rather than merely dropping in silence.
/// * `Timeout`: a stand-in that answers only after the proxy's own
///   (short) deadline. Fail-closed: the read is dropped, the
///   session completes, and the app sees an empty clipboard.
#[derive(Clone, Copy)]
enum BrokerOutcome {
    AutoAllow,
    AutoDeny,
    Timeout,
}

fn run_broker_session(
    outcome: BrokerOutcome,
    audit: wlsctx::proxy::AuditConfig,
    settle: Duration,
    clear_selection: bool,
) {
    let _ = env_logger::Builder::new()
        .filter_level(::log::LevelFilter::Info)
        .try_init();

    let dir = tempfile::tempdir().unwrap();
    let public_path = dir.path().join("wl-public");
    let tagged_path = dir.path().join("wl-tagged");
    let broker_path = dir.path().join("broker.sock");

    let stop = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(AtomicBool::new(false));
    let live: Arc<AtomicUsize> = Arc::default();
    let received: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
    let broker_queries: Arc<AtomicUsize> = Arc::default();

    let public = wlsctx::proxy::bind_listener(&public_path).unwrap();
    let tagged_for_proxy = tagged_path.clone();
    let stop_proxy = stop.clone();
    let broker_for_proxy = broker_path.clone();
    let proxy = thread::Builder::new()
        .name("wlsctx-proxy".into())
        .spawn(move || {
            // The relay's ask to the broker: short a deadline for
            // the fail-closed test, comfortable otherwise.
            let broker_cfg = wlsctx::proxy::BrokerConfig {
                socket: broker_for_proxy,
                app: "testapp".into(),
                instance: "inst".into(),
                timeout: match outcome {
                    BrokerOutcome::Timeout => Duration::from_millis(400),
                    _ => Duration::from_secs(10),
                },
                window: Duration::from_millis(1500),
                // This test exercises the consent (read) flow only;
                // the Phase 6 copy-out notification has its own test.
                notify_copy_out: false,
            };
            let _ = wlsctx::proxy::event_loop(
                &public,
                &tagged_for_proxy,
                &wlsctx::proxy::Policy::all(),
                wlsctx::proxy::ClipboardPolicy::Deny,
                audit,
                Some(broker_cfg),
                Some(stop_proxy),
            );
        })
        .unwrap();

    let (ready_c, live_c, recv_c) = (ready.clone(), live.clone(), received.clone());
    let stop_comp = stop.clone();
    let comp = thread::Builder::new()
        .name("fake-compositor".into())
        .spawn(move || {
            run_fake_data_device_compositor(tagged_path, ready_c, stop_comp, live_c, recv_c)
        })
        .unwrap();

    let (queries_c, broker_c) = (broker_queries.clone(), broker_path.clone());
    let broker = thread::Builder::new()
        .name("broker".into())
        .spawn(move || {
            let listener = wlsctx::broker::bind_listener(&broker_c).unwrap();
            // One request per session: accept it, serve it, exit.
            let (mut stream, _) = listener.accept().unwrap();
            queries_c.fetch_add(1, Ordering::SeqCst);
            match outcome {
                BrokerOutcome::AutoAllow => {
                    // The daemon's real per-connection path, minus
                    // its accept loop: decode the request, auto-
                    // decide, answer. (The interactive announce and
                    // decision socket are not on this path.)
                    let args = wlsctx::broker::BrokerArgs {
                        runtime_dir: std::env::temp_dir().join("wlsctx-broker-test"),
                        auto_decide: Some(wlsctx::broker::AutoDecide::Allow),
                        timeout: Duration::from_secs(5),
                    };
                    wlsctx::broker::handle_connection(stream, &args);
                }
                BrokerOutcome::AutoDeny => {
                    let line = wlsctx::broker::encode_decision(&wlsctx::broker::Decision::Deny {
                        reason: "auto".into(),
                    })
                    .unwrap();
                    let _ = stream.write_all(line.as_bytes());
                }
                BrokerOutcome::Timeout => {
                    // The proxy's 400 ms read deadline expires long
                    // before this answer; writing it afterwards is
                    // moot (the decision is gone over there) but
                    // proves the stand-in behaved like a slow user.
                    thread::sleep(Duration::from_secs(2));
                    let line = wlsctx::broker::encode_decision(&wlsctx::broker::Decision::Allow {
                        window_ms: wlsctx::broker::INTENT_WINDOW_MS,
                    })
                    .unwrap();
                    let _ = stream.write_all(line.as_bytes());
                }
            }
        })
        .unwrap();

    wait_until(|| ready.load(Ordering::SeqCst), 10);

    let (own, foreign) = one_clipboard_session(&public_path, settle, clear_selection)
        .expect("clipboard session with the broker failed");

    // The app disconnected before the shutdown, so the compositor's
    // view must settle to zero live clients before it exits.
    wait_until(|| live.load(Ordering::SeqCst) == 0, 10);
    stop.store(true, Ordering::SeqCst);
    let _ = comp.join();
    let _ = broker.join();
    let _ = proxy.join();

    // The own read-back always goes through: the gate is exempt
    // for the app's own selections, and therefore for the broker.
    assert_eq!(own, OWN_DATA.as_bytes(), "own read-back payload");
    assert_eq!(
        broker_queries.load(Ordering::SeqCst),
        1,
        "the gate must have asked the broker exactly once about the foreign read"
    );
    match outcome {
        BrokerOutcome::AutoAllow => {
            // The gate is deny by default; only the broker's allow
            // (and its intent window) could move host data into the
            // app's memfd.
            assert_eq!(
                foreign,
                FOREIGN_DATA.as_bytes(),
                "broker-allowed foreign payload"
            );
            assert_eq!(
                *received.lock().unwrap(),
                vec![
                    ("own".to_string(), "text/plain".to_string()),
                    ("foreign".to_string(), "text/plain".to_string()),
                ],
                "the allow let the compositor serve the foreign read"
            );
        }
        BrokerOutcome::AutoDeny | BrokerOutcome::Timeout => {
            assert!(
                foreign.is_empty(),
                "denied/timed-out foreign read must stay empty"
            );
            assert_eq!(
                *received.lock().unwrap(),
                vec![("own".to_string(), "text/plain".to_string())],
                "only the own read reached the compositor"
            );
        }
    }

    drop(dir);
}

#[test]
fn broker_auto_allow_opens_the_intent_window() {
    run_broker_session(
        BrokerOutcome::AutoAllow,
        wlsctx::proxy::AuditConfig::default(),
        Duration::ZERO,
        false,
    );
}

#[test]
fn broker_auto_deny_stays_dropped_and_is_consulted() {
    run_broker_session(
        BrokerOutcome::AutoDeny,
        wlsctx::proxy::AuditConfig::default(),
        Duration::ZERO,
        false,
    );
}

#[test]
fn broker_timeout_fails_closed() {
    run_broker_session(
        BrokerOutcome::Timeout,
        wlsctx::proxy::AuditConfig::default(),
        Duration::ZERO,
        false,
    );
}

/// Phase 9: the audit log of a broker-approved foreign read. The
/// same session shape as the deny audit test, but the stand-in
/// broker answers `allow`: the foreign read is forwarded and audited
/// as `approved`, and its size settles like any forwarded read (the
/// consent window opened the gate, but the audit does not record
/// *who* approved — the decision's gate is the fact it records).
#[test]
fn broker_approval_is_audited() {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let audit = wlsctx::proxy::AuditConfig::with_sink(
        "testapp".into(),
        "inst".into(),
        Arc::new(CaptureSink {
            lines: lines.clone(),
        }),
    );
    run_broker_session(
        BrokerOutcome::AutoAllow,
        audit,
        Duration::from_millis(700),
        true,
    );

    let lines = lines.lock().unwrap();
    assert_eq!(
        *lines,
        vec![
            "app=testapp instance=inst selection=clipboard action=set origin=own",
            "app=testapp instance=inst selection=clipboard action=read origin=own mime=text/plain gate=forward fd_kind=memfd payload_bytes=15",
            "app=testapp instance=inst selection=clipboard action=serve origin=own mime=text/plain fd_kind=memfd payload_bytes=15",
            "app=testapp instance=inst selection=clipboard action=read origin=foreign mime=text/plain gate=approved fd_kind=memfd payload_bytes=11",
            "app=testapp instance=inst selection=clipboard action=clear origin=foreign",
        ],
        "the session's five selection events: the foreign read is approved and settled"
    );
}

/// Phase 6: the copy-out notification. The same three-party clipboard
/// session, but the proxy has a copy-out notifier wired to a stand-in
/// broker. When the app sets its own selection (a `set_selection`),
/// the relay (1) forwards the write to the compositor — the read-back
/// works, proving the notification never blocks or alters the write —
/// and (2) fires a one-way `clipboard-write` line at the broker. The
/// stand-in records the line and (like the daemon) never answers.
///
/// Two outcomes:
/// * reachable — the stand-in receives exactly one notification with
///   the app's identity and the `clipboard` selection.
/// * unreachable — no broker is bound; the notify fails and the
///   session still completes (fail-open).
fn run_copy_out_session(broker_reachable: bool) {
    let _ = env_logger::Builder::new()
        .filter_level(::log::LevelFilter::Info)
        .try_init();

    let dir = tempfile::tempdir().unwrap();
    let public_path = dir.path().join("wl-public");
    let tagged_path = dir.path().join("wl-tagged");
    let broker_path = dir.path().join("broker.sock");

    let stop = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(AtomicBool::new(false));
    let live: Arc<AtomicUsize> = Arc::default();
    let received: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
    let notifications: Arc<Mutex<Vec<(String, String, String)>>> = Arc::default();

    let public = wlsctx::proxy::bind_listener(&public_path).unwrap();
    let tagged_for_proxy = tagged_path.clone();
    let stop_proxy = stop.clone();
    let broker_for_proxy = broker_path.clone();
    let proxy = thread::Builder::new()
        .name("wlsctx-proxy".into())
        .spawn(move || {
            let broker_cfg = wlsctx::proxy::BrokerConfig {
                socket: broker_for_proxy,
                app: "testapp".into(),
                instance: "inst".into(),
                notify_copy_out: true,
                ..Default::default()
            };
            let _ = wlsctx::proxy::event_loop(
                &public,
                &tagged_for_proxy,
                &wlsctx::proxy::Policy::all(),
                wlsctx::proxy::ClipboardPolicy::Allow,
                wlsctx::proxy::AuditConfig::default(),
                Some(broker_cfg),
                Some(stop_proxy),
            );
        })
        .unwrap();

    let (ready_c, live_c, recv_c) = (ready.clone(), live.clone(), received.clone());
    let stop_comp = stop.clone();
    let comp = thread::Builder::new()
        .name("fake-compositor".into())
        .spawn(move || {
            run_fake_data_device_compositor(tagged_path, ready_c, stop_comp, live_c, recv_c)
        })
        .unwrap();

    // The stand-in broker: a non-blocking accept loop that reads each
    // notification line, records it, and never answers (fire-and-forget
    // — the daemon's `handle_write` behaves the same way).
    let (notifs_c, broker_c, stop_b) = (notifications.clone(), broker_path.clone(), stop.clone());
    let broker = thread::Builder::new()
        .name("broker".into())
        .spawn(move || {
            if !broker_reachable {
                // No listener is bound: the socket file never exists,
                // so the proxy's connect fails (the fail-open path).
                thread::sleep(Duration::from_secs(1));
                return;
            }
            let listener = wlsctx::broker::bind_listener(&broker_c).unwrap();
            let _ = listener.set_nonblocking(true);
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let mut line = String::new();
                        if wlsctx::broker::read_line(&mut stream, &mut line).is_ok()
                            && !line.is_empty()
                            && let Ok(note) = wlsctx::broker::decode_notification(&line)
                        {
                            notifs_c.lock().unwrap().push((
                                note.app,
                                note.instance,
                                note.selection,
                            ));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if stop_b.load(Ordering::SeqCst) || Instant::now() > deadline {
                            break;
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        })
        .unwrap();

    wait_until(|| ready.load(Ordering::SeqCst), 10);

    let (own, _foreign) = one_clipboard_session(&public_path, Duration::ZERO, false)
        .expect("clipboard session (copy-out) failed");

    // The app disconnected; let the compositor's view settle.
    wait_until(|| live.load(Ordering::SeqCst) == 0, 10);
    stop.store(true, Ordering::SeqCst);
    let _ = comp.join();
    let _ = broker.join();
    let _ = proxy.join();

    // The write is always forwarded: the own read-back always works,
    // regardless of whether the notification reached a broker.
    assert_eq!(own, OWN_DATA.as_bytes(), "own read-back payload");

    if broker_reachable {
        let n = notifications.lock().unwrap();
        assert_eq!(
            *n,
            vec![(
                "testapp".to_string(),
                "inst".to_string(),
                "clipboard".to_string()
            )],
            "the app's single set_selection fired exactly one copy-out notification"
        );
    } else {
        assert!(
            notifications.lock().unwrap().is_empty(),
            "no broker means no recorded notification — but the write still went through"
        );
    }

    drop(dir);
}

#[test]
fn copy_out_write_fires_a_notification() {
    run_copy_out_session(true);
}

#[test]
fn copy_out_fail_open_when_no_broker() {
    run_copy_out_session(false);
}

fn wait_until(pred: impl Fn() -> bool, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !pred() {
        if Instant::now() > deadline {
            panic!("timed out after {secs}s");
        }
        thread::sleep(Duration::from_millis(5));
    }
}
