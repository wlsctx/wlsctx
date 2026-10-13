//! Tagging a listening socket with a `wp_security_context_v1` context.
//!
//! wlsctx repurposes the protocol in the reverse of its intended
//! direction (the README explains the threat model): instead of an app
//! handing a *child process* a tagged socket, wlsctx tags a socket that
//! *sandboxed clients* connect to, so the compositor can apply
//! per-context policy (which globals a sandbox may see, which
//! operations it may perform) to them.

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixListener;

use anyhow::{Context, Result};
use log::info;
use wayland_client::{
    Connection, QueueHandle, delegate_noop,
    globals::{GlobalListContents, registry_queue_init},
    protocol::wl_registry,
};
use wayland_protocols::wp::security_context::v1::client::{
    wp_security_context_manager_v1, wp_security_context_v1,
};

/// Dispatch state for the setup connection: it only needs the global
/// list (to find the security context manager); the protocol has no
/// events to react to.
pub struct State;

impl wayland_client::Dispatch<wl_registry::WlRegistry, GlobalListContents> for State {
    fn event(
        _state: &mut Self,
        _proxy: &wl_registry::WlRegistry,
        _event: wl_registry::Event,
        // This mutex contains an up-to-date list of the currently known
        // globals including the one that was just added or destroyed.
        _data: &GlobalListContents,
        _conn: &Connection,
        _qhandle: &QueueHandle<Self>,
    ) {
        /* react to dynamic global events here */
    }
}

// The security context protocol has no events that we need to manage.
delegate_noop!(State: wp_security_context_manager_v1::WpSecurityContextManagerV1);
delegate_noop!(State: wp_security_context_v1::WpSecurityContextV1);

/// Tag `listener` with the given context over `conn` and return the
/// protocol's reference pipe (the *write* end).
///
/// The compositor takes ownership of the listener (it accepts
/// connections on it and stamps them with the context) as long as the
/// returned fd stays open; closing it invalidates the tagged socket.
/// The caller must therefore keep the fd open for the whole time the
/// socket should stay tagged (wlsctx holds it for its lifetime).
///
/// `conn` is the connection the setup exchange runs on. It is a plain,
/// untagged client connection (in the in-pod sidecar that is the host
/// socket passed as the container's stdin, `WAYLAND_SOCKET=0`; in
/// standalone mode a name-based connection to the mounted host socket).
pub fn create_security_context(
    conn: Connection,
    listener: &UnixListener,
    sandbox_engine: &str,
    app_id: &str,
    instance_id: &str,
) -> Result<OwnedFd> {
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
    info!("Creating security context {sandbox_engine} for app {app_id} (instance {instance_id})");
    security_context.set_sandbox_engine(sandbox_engine.to_string());
    security_context.set_app_id(app_id.to_string());
    security_context.set_instance_id(instance_id.to_string());
    security_context.commit();
    security_context.destroy();
    event_queue.roundtrip(&mut State {}).context(
        "the compositor returned a protocol error while committing the security context \
         (the tagged socket is still in an inconsistent state); check the compositor log",
    )?;
    Ok(writer.into())
}
