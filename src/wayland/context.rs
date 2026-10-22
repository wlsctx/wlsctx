//! Creating the tagged Wayland socket via `wp_security_context_v1`.
//!
//! `create_security_context` (and the end-to-end flow) is deliberately
//! not unit-tested: it needs a live wlroots compositor providing
//! `wp_security_context_manager_v1` (see README, "Compositor
//! requirements & verify your setup") — that part is covered by
//! running the real binary against a real compositor.

use crate::wayland::roundtrip::{ROUNDTRIP_TIMEOUT, bounded_roundtrip};
use anyhow::{Context, Result};
use log::info;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use wayland_client::{
    Connection, QueueHandle,
    delegate_noop,
    globals::{GlobalListContents, registry_queue_init},
    protocol::{wl_callback, wl_registry},
};
use wayland_protocols::wp::security_context::v1::client::{
    wp_security_context_manager_v1, wp_security_context_v1,
};

pub struct State;

impl wayland_client::Dispatch<wl_registry::WlRegistry, GlobalListContents> for State {
    fn event(
        _state: &mut Self,
        _proxy: &wl_registry::WlRegistry,
        _event: wl_registry::Event,
        // This mutex contains an up-to-date list of the currently known globals
        // including the one that was just added or destroyed
        _data: &GlobalListContents,
        _conn: &Connection,
        _qhandle: &QueueHandle<Self>,
    ) {
        /* react to dynamic global events here */
    }
}

// The one-shot `wl_display.sync` callback that `bounded_roundtrip` waits
// on: flip the shared flag the moment the compositor fires `done`, which
// guarantees every request sent before it has been processed.
impl wayland_client::Dispatch<wl_callback::WlCallback, Arc<AtomicBool>> for State {
    fn event(
        _state: &mut Self,
        _proxy: &wl_callback::WlCallback,
        event: wl_callback::Event,
        data: &Arc<AtomicBool>,
        _conn: &Connection,
        _qhandle: &QueueHandle<Self>,
    ) {
        if let wl_callback::Event::Done { .. } = event {
            data.store(true, Ordering::Relaxed);
        }
    }
}

// The security context protocol has no events that we need to manage
delegate_noop!(State: wp_security_context_manager_v1::WpSecurityContextManagerV1);
delegate_noop!(State: wp_security_context_v1::WpSecurityContextV1);

/// Create a tagged Wayland listening socket for the given app/instance.
///
/// The tagged socket is the listener itself: the compositor keeps it alive
/// as long as the reference pipe (the protocol "close" fd) is open, so this
/// function hands the write end of that pipe back to the caller, which must
/// keep it open for as long as the socket should stay tagged.
///
/// Ownership note: per the protocol, `create_listener` transfers ownership
/// of the listener fd to the compositor (which holds its own dup). wlsctx
/// nevertheless keeps *its* copy of the fd open for the process lifetime
/// (see `main`) and drops it only on exit, together with the reference
/// pipe: that keeps "wlsctx is alive" equivalent to "the tagged socket is
/// valid", and makes the tagged socket's fate visible in this process's fd
/// table (lsof). Dropping our copy early would not unbind the socket — the
/// compositor's copy keeps it alive — but do not "clean it up".
pub fn create_security_context(
    listener: &UnixListener,
    sandbox_engine: &str,
    app_id: &str,
    instance_id: &str,
) -> Result<OwnedFd> {
    // Create a Wayland connection by connecting to the server through the
    // environment-provided configuration.
    let conn = Connection::connect_to_env().context(
        "connecting to the upstream Wayland compositor failed (NoCompositor); \
         check that WAYLAND_DISPLAY/WAYLAND_SOCKET reach the host compositor",
    )?;

    let (globals, mut event_queue) =
        registry_queue_init::<State>(&conn).context("initialising the Wayland protocol queue")?;
    let qh = &event_queue.handle();
    let security_context_manager: wp_security_context_manager_v1::WpSecurityContextManagerV1 =
        globals.bind(qh, 1..=1, ()).with_context(|| {
            "the compositor does not provide wp_security_context_manager_v1; this needs a \
             wlroots compositor (e.g. sway) — check with `wlsinfo -t` that the global \
             wp_security_context_manager_v1 is present"
        })?;
    let (reader, writer) =
        io::pipe().context("creating the reference pipe that keeps the tagged socket alive")?;
    let security_context =
        security_context_manager.create_listener(listener.as_fd(), reader.as_fd(), qh, ());
    security_context_manager.destroy();
    info!("Create security context mapping for {sandbox_engine} app: {app_id} ({instance_id})");
    security_context.set_sandbox_engine(sandbox_engine.to_string());
    security_context.set_app_id(app_id.to_string());
    security_context.set_instance_id(instance_id.to_string());
    security_context.commit();
    security_context.destroy();
    bounded_roundtrip(
        &conn,
        &mut event_queue,
        &mut State {},
        Instant::now() + ROUNDTRIP_TIMEOUT,
    )?;
    Ok(writer.into())
}
