//! The tagged Wayland socket: everything the original single-purpose
//! wlsctx did.
//!
//! This is what the `wlsctx wayland` subcommand will wrap; the new
//! `wlsctx run` pipeline (PLAN.md) reuses [`context::create_security_context`]
//! from the supervisor side.

pub mod context;
pub mod listener;
pub mod roundtrip;
pub mod signals;
