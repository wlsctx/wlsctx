//! The tagged Wayland socket: everything the original single-purpose
//! wlsctx did.
//!
//! `wlsctx wayland` (the original mode) wraps
//! [`listener::obtain_listener`] + [`context::create_security_context`];
//! the `wlsctx run` pipeline (PLAN.md Phase 5.1) creates the tagged
//! socket from the supervisor side, *before* the first fork, via
//! [`prepare_tagged_socket`].

pub mod context;
pub mod listener;
pub mod roundtrip;

use crate::cli::WaylandArgs;
use anyhow::{Context, Result};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixListener;

/// The tagged Wayland socket of a `run` pipeline (Phase 5.1): created
/// by S before the first fork, held by S for as long as the app
/// lives, untagged when S exits.
pub(crate) struct TaggedWayland {
    /// The path the listener is bound at (host-side).
    pub host_path: String,
    /// S's own copy of the listener. The compositor keeps its own
    /// dup (the protocol transfers a copy at `create_listener`), so
    /// holding this open is what makes "S is alive" mean "the socket
    /// is tagged" (see the ownership note on
    /// [`crate::wayland::context::create_security_context`]).
    pub listener: UnixListener,
    /// The reference pipe's write end — the protocol's "close" fd.
    /// The compositor drops the tag when it closes.
    pub close_fd: OwnedFd,
}

/// The path a `run` binds its tagged Wayland socket at: an
/// absolute `listen` is used as given; a relative `listen` — and no
/// `listen` at all — is placed in the per-instance runtime dir
/// (default name `wayland-1`).
///
/// The per-instance runtime dir is carried into the sandbox (the
/// decision-#28 scratch), so for the systemd-default XDG
/// (`/run/user/<uid>`) the same path exists inside the sandbox, at
/// the fresh `/run`'s instance dir.
pub(crate) fn resolve_socket_path(runtime_dir: &str, listen: Option<&str>) -> String {
    match listen {
        Some(l) if std::path::Path::new(l).is_absolute() => l.to_string(),
        Some(l) => format!("{runtime_dir}/{l}"),
        None => format!("{runtime_dir}/wayland-1"),
    }
}

/// Create the tagged Wayland socket for a `run` pipeline (Phase
/// 5.1): bind (or systemd-adopt) the listener, tag it via
/// `wp_security_context_v1` (reusing [`listener`] and [`context`]),
/// and return the two fds S must keep open for the app's lifetime
/// (5.2).
///
/// The socket file is created *before* the first fork, so the
/// rootfs build's step-1 carry moves it into the scratch and it
/// reaches the sandbox's fresh `/run` instance dir.
pub(crate) fn prepare_tagged_socket(
    app_id: &str,
    instance_id: &str,
    runtime_dir: &str,
    listen: Option<&str>,
    socket_activation: bool,
    sandbox_engine: &str,
) -> Result<TaggedWayland> {
    let (host_path, listener) = if socket_activation {
        // The adoption path ignores `listen` (the path is systemd's).
        let args = WaylandArgs {
            app_id: app_id.to_string(),
            instance_id: instance_id.to_string(),
            sandbox_engine: sandbox_engine.to_string(),
            listen: None,
            socket_activation: true,
            proxy: false,
            tagged_socket: None,
            allow_globals: vec![],
            clipboard_policy: "allow".into(),
            broker_socket: None,
            notify_copy_out: false,
        };
        // `listener::` here is the module (the local binding shares
        // its name but lives in the value namespace).
        let (_app, _inst, listener) = listener::obtain_listener(&args)?;
        (
            listener
                .local_addr()
                .ok()
                .and_then(|a| a.as_pathname().map(|p| p.to_string_lossy().into_owned()))
                .context("reading the socket-activated listener's path")?,
            listener,
        )
    } else {
        let path = resolve_socket_path(runtime_dir, listen);
        (
            path.clone(),
            listener::bind_socket(std::path::Path::new(&path))
                .with_context(|| format!("binding the tagged Wayland socket {path}"))?,
        )
    };
    let close_fd = context::create_security_context(&listener, sandbox_engine, app_id, instance_id)
        .inspect_err(|_e| {
            // The tag failed: unbind the path we created (an
            // socket-activated file belongs to systemd — leave it).
            if !socket_activation {
                let _ = std::fs::remove_file(&host_path);
            }
        })?;
    Ok(TaggedWayland {
        host_path,
        listener,
        close_fd,
    })
}

#[cfg(test)]
mod tests {
    use super::resolve_socket_path;

    #[test]
    fn resolve_defaults_to_wayland_1_in_the_runtime_dir() {
        assert_eq!(
            resolve_socket_path("/run/user/1000/wlsctx/app-1", None),
            "/run/user/1000/wlsctx/app-1/wayland-1"
        );
    }

    #[test]
    fn resolve_relative_listen_is_placed_in_the_runtime_dir() {
        assert_eq!(
            resolve_socket_path("/run/user/1000/wlsctx/app-1", Some("wl-probe")),
            "/run/user/1000/wlsctx/app-1/wl-probe"
        );
    }

    #[test]
    fn resolve_absolute_listen_is_used_as_given() {
        assert_eq!(
            resolve_socket_path("/run/user/1000/wlsctx/app-1", Some("/elsewhere/sock")),
            "/elsewhere/sock"
        );
    }
}
