//! wlsctx: an in-process sandbox for GUI apps on a wlroots Wayland
//! desktop, plus the tagged-socket, relay, and broker that enforce
//! per-security-context policy around it.
//!
//! The binary (`src/main.rs`) is a thin CLI wrapper around the library
//! modules below (plus binary-only modules for the in-process sandbox
//! and the tagged-socket machinery that live next to `main.rs`):
//!
//! * [`proxy`] — the transparent Wayland relay (`wayland --proxy`):
//!   forwards a sandboxed app's connection to the compositor, applies
//!   the global allowlist, the clipboard/selection gate, and the copy-out
//!   notification;
//! * [`broker`] — the host-side consent broker (`broker` / `decide`):
//!   answers the relay's `clipboard-read` prompts and fires the
//!   `clipboard-write` notifications.
//! * [`mcs`] — per-instance MCS categories (phase 8.2): each app
//!   instance runs in its own SELinux category, so its processes are
//!   unreachable from other instances (confined mode only; object
//!   separation is the namespaced rootfs's job).

pub mod broker;
pub mod dbus_proxy;
pub mod mcs;
pub mod pdeathsig;
pub mod proxy;
pub mod xwayland;
