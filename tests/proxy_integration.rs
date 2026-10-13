//! End-to-end test of the transparent proxy: a fake compositor
//! (`wayland-server`) behind the tagged socket, a real `wayland-client`
//! in front of the public socket, with the wlsctx relay between them.
//!
//! Each app session verifies, in order, that the relay passes through:
//! 1. the registry handshake (server -> client `wl_registry.global`),
//! 2. bound globals (client -> server `wl_registry.bind`),
//! 3. a request whose reply is an event (client `wl_display.sync` ->
//!    server `wl_callback.done`),
//! 4. an out-of-band fd argument (client `wl_shm.create_pool` ->
//!    server, written back through by the fake compositor),
//! 5. a second app session after the first one has gone (per-
//!    connection isolation).

use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use wayland_client::protocol::{
    wl_buffer, wl_callback, wl_compositor, wl_registry, wl_shm, wl_shm_pool, wl_surface,
};
use wayland_client::{Connection, Dispatch, QueueHandle};
use wayland_server::backend::{ClientData, ClientId, DisconnectReason};
use wayland_server::protocol::{
    wl_buffer as srv_wl_buffer, wl_compositor as srv_wl_compositor, wl_shm as srv_wl_shm,
    wl_shm_pool as srv_wl_shm_pool, wl_surface as srv_wl_surface,
};
use wayland_server::Dispatch as ServerDispatch;
use wayland_server::{Client, DataInit, Display, DisplayHandle, GlobalDispatch, ListeningSocket, New};

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

/// A minimal compositor: listens on the tagged socket, advertises
/// `wl_compositor` and `wl_shm`, creates whatever the client asks for,
/// and writes a probe byte through the fd of every `create_pool`.
///
/// Exits when `stop` is set and no clients are live any more.
fn run_fake_compositor(
    tagged_path: PathBuf,
    ready: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    live: Arc<AtomicUsize>,
    received: Arc<Mutex<Option<OwnedFd>>>,
) -> std::io::Result<()> {
    let tagged = ListeningSocket::bind_absolute(tagged_path)
        .map_err(|e| std::io::Error::other(format!("bind tagged socket: {e}")))?;
    let mut display = Display::<Srv>::new()
        .map_err(|e| std::io::Error::other(format!("display init: {e}")))?;
    let mut handle = display.handle();
    let _ = handle.create_global::<Srv, srv_wl_compositor::WlCompositor, ()>(4, ());
    let _ = handle.create_global::<Srv, srv_wl_shm::WlShm, ()>(2, ());
    let mut state = Srv { received };
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
        if let wl_registry::Event::Global { name, interface, version } = event {
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
/// cares about (required for `registry.bind::<I, (), App>` to typecheck).
macro_rules! no_events {
    ($iface:ty, $event:ty) => {
        impl Dispatch<$iface, ()> for App {
            fn event(
                _state: &mut Self,
                _resource: &$iface,
                _event: $event,
                _data: &(),
                _conn: &Connection,
                _qh: &QueueHandle<Self>,
            ) {}
        }
    };
}

no_events!(wl_compositor::WlCompositor, wl_compositor::Event);
no_events!(wl_shm::WlShm, wl_shm::Event);
no_events!(wl_shm_pool::WlShmPool, wl_shm_pool::Event);
no_events!(wl_buffer::WlBuffer, wl_buffer::Event);
no_events!(wl_surface::WlSurface, wl_surface::Event);

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

    let compositor = registry.bind::<wl_compositor::WlCompositor, (), App>(
        compositor_name, 4, &qh, (),
    );
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
            let _ = wlsctx::proxy::event_loop(&public, &tagged_for_proxy, Some(stop_proxy));
        })
        .unwrap();

    // The fake compositor on the tagged socket.
    let (ready_c, live_c, recv_c) = (ready.clone(), live.clone(), received.clone());
    let stop_comp = stop.clone();
    let comp = thread::Builder::new()
        .name("fake-compositor".into())
        .spawn(move || {
            run_fake_compositor(tagged_path, ready_c, stop_comp, live_c, recv_c)
        })
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

fn wait_until(pred: impl Fn() -> bool, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !pred() {
        if Instant::now() > deadline {
            panic!("timed out after {secs}s");
        }
        thread::sleep(Duration::from_millis(5));
    }
}
