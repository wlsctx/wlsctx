//! wlsctx: Wayland security context setup and the transparent Wayland
//! proxy that enforces per-context policy.
//!
//! The binary (`src/main.rs`) is a thin CLI wrapper around:
//!
//! * [`security_context`] — tag a listening socket with a
//!   `wp_security_context_v1` security context (the "tag-and-park" mode,
//!   and the setup step of the proxy);
//! * [`proxy`] — relay sandboxed apps' Wayland connections to the
//!   compositor through security-context connections (the "proxy" mode,
//!   `--proxy`).

pub mod broker;
pub mod proxy;
pub mod security_context;
