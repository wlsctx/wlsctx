//! Per-instance MCS categories (confined mode only; phase 8.2).
//!
//! Each app instance gets one category `cN` of the user's
//! `s0-s0:c0.c1023` range (a stable hash of app-id + instance-id),
//! so files one instance creates (its per-instance dir and contents,
//! scratch, sockets, and everything the app writes, e.g. in its
//! home) carry `cN` and are unreadable/unwritable by another
//! instance's category — the same isolation podman gets from its
//! `cNNN,cMMM` pairs.
//!
//! How the category gets there (see `selinux/README.md`):
//!
//! - **S** (and the standalone proxy/satellites) narrows its *own*
//!   label from `wlsctx_t:s0` to `wlsctx_t:s0-s0:cN` by writing its
//!   exec context (`/proc/self/attr/exec` — the setexecfilecon
//!   equivalent; the module allows the `wlsctx_t` self-
//!   `dyntransition`) and re-execing `/proc/self/exe` once at
//!   startup (before it binds or creates anything, so the second
//!   pass starts clean). Every child it forks inherits the range,
//!   and objects created with no explicit fscreate context take the
//!   creator's range — so the instance dir, scratch and sockets
//!   carry `cN` for free.
//! - **B** writes the exec context `wlsctx_app_t:<current range>`
//!   before execing the app (module: `wlsctx_t → wlsctx_app_t`
//!   `dyntransition`).
//! - The **Xwayland** and **dbus-proxy** satellites do the same for
//!   their execs (`xserver_t` / `wlsctx_app_t`), so the X socket,
//!   MIT auth file and the bus socket they create carry `cN`.
//! - The **broker** (shared by all instances) narrows its range to
//!   **single-level `s0`** the same way (`self_reexec_to_s0`),
//!   before it binds or creates anything: the objects it creates
//!   (the session-level runtime dir, the decision socket) must stay
//!   reachable from every `cN`. A category set contains no
//!   category, so an `s0` object remains readable/writable from a
//!   `cN` process, while a `cN` object is unreachable from a
//!   different category. (The session dir's range is decided by
//!   whichever process creates it first — on a socket-activated
//!   deployment that is the first instance, not the broker; see
//!   `selinux/README.md`.)
//!
//! In unconfined mode (module uninstalled / binary not relabeled —
//! the current label is not `wlsctx_t`) every function here is a
//! no-op and the historical behavior stands.

use anyhow::{Context, Result};
use std::io;

/// The categories available in the user's `s0-s0:c0.c1023` range.
const NUM_CATEGORIES: u32 = 1024;

/// One stable category per (app-id, instance-id) — the same input
/// yields the same category in every process (the `run` pipeline and
/// the standalone proxy must agree). FNV-1a 64, low bits.
pub fn instance_category(app_id: &str, instance_id: &str) -> u32 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in format!("{app_id}\0{instance_id}").as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h as u32 % NUM_CATEGORIES
}

/// Parse `/proc/self/attr/current` into (user, role, type, range).
fn current_label() -> Option<(String, String, String, String)> {
    let s = std::fs::read_to_string("/proc/self/attr/current").ok()?;
    let mut parts = s.trim().splitn(4, ':');
    let user = parts.next()?.to_string();
    let role = parts.next()?.to_string();
    let ty = parts.next()?.to_string();
    let range = parts.next()?.to_string();
    Some((user, role, ty, range))
}

/// Confined mode: the current label's type is the module's
/// `wlsctx_t` (the binary carries `wlsctx_exec_t`).
pub fn is_confined() -> bool {
    current_label().is_some_and(|l| l.2 == "wlsctx_t")
}

/// Write the process' exec context (the setexecfilecon equivalent).
/// The kernel validates the context on the *exec*; a write failure
/// here (bad type, out-of-range category) degrades the caller to a
/// run without MCS.
fn write_exec_context(ctx: &str) -> io::Result<()> {
    let mut b = ctx.as_bytes().to_vec();
    b.push(0); // attr files take NUL-terminated contexts
    std::fs::write("/proc/self/attr/exec", &b).map_err(|e| {
        io::Error::other(format!(
            "writing /proc/self/attr/exec ({ctx:?}): {e} — the module may \
             not be installed or the category may be out of the user's \
             range; continuing without per-instance MCS"
        ))
    })
}

/// S (and the standalone proxy/satellites): narrow our own range to
/// the instance's category by a one-time self re-exec.
///
/// No-op in unconfined mode and when the range is already narrowed
/// (the post-re-exec invocation) — that double call is the loop
/// guard. On a write failure (logged) the run simply continues
/// without MCS.
pub fn self_reexec_with_category(app_id: &str, instance_id: &str) -> Result<()> {
    self_reexec_to_range(&format!(
        "s0-s0:c{}",
        instance_category(app_id, instance_id)
    ))
}

/// The **broker** (shared by all instances): narrow our own range to
/// single-level `s0` by a one-time self re-exec, before it binds or
/// creates anything.
///
/// The broker's objects — the session-level runtime dir it creates
/// and the decision socket inside it — must stay reachable from
/// every per-instance category. An object created at the full spawn
/// range `s0-s0:c0.c1023` is **not** `add_name`-able by a `cN`
/// process (an object's level must be dominated by the subject's
/// range high — `c0.c1023` is not below `cN`), so on a fresh
/// machine a broker-created session dir would break every instance
/// dir creation. Single-level `s0` is dominated by every range high
/// and dominates no category, so `s0` objects stay usable from every
/// `cN`. No-op in unconfined mode and when already at `s0` (the
/// post-re-exec invocation — the loop guard).
pub fn self_reexec_to_s0() -> Result<()> {
    self_reexec_to_range("s0")
}

/// The one-time self re-exec to a target range, shared by
/// [`self_reexec_with_category`] (an instance's `s0-s0:cN`) and
/// [`self_reexec_to_s0`] (the broker's `s0`).
///
/// No-op in unconfined mode and when the current range is already
/// the target (the post-re-exec invocation — the loop guard). A
/// write failure means the target is outside the user's exp-range
/// (a non-standard MCS setup) or the module lacks the
/// self-`dyntransition`; the caller degrades to a run without MCS
/// rather than aborting.
fn self_reexec_to_range(target: &str) -> Result<()> {
    let Some((user, role, ty, range)) = current_label() else {
        return Ok(());
    };
    if ty != "wlsctx_t" {
        return Ok(()); // unconfined mode
    }
    if range == target {
        return Ok(()); // already at the target (post-re-exec invocation)
    }
    if let Err(e) = write_exec_context(&format!("{user}:{role}:wlsctx_t:{target}")) {
        log::warn!("{e}");
        return Ok(());
    }
    // `re_exec`'s `preserve_range` skips a pending explicit context
    // (it writes only when none is set), so the target range above
    // survives the exec.
    crate::proxy::re_exec().context("MCS re-exec (execve of /proc/self/exe) failed")
}

/// Before an exec from the `wlsctx_t` domain, set the exec context's
/// *type* to `target_type` while carrying the current (instance)
/// range — the dyntransition the module allows. No-op in unconfined
/// mode.
pub fn set_exec_context(target_type: &str) -> Result<()> {
    let Some((user, role, ty, range)) = current_label() else {
        return Ok(());
    };
    if ty != "wlsctx_t" {
        return Ok(()); // unconfined mode: keep the stock behavior
    }
    write_exec_context(&format!("{user}:{role}:{target_type}:{range}"))
        .map_err(|e| anyhow::anyhow!("{e} — continuing the exec without the per-instance range"))
}

/// Preserve the current label (type *and* range) across a
/// `/proc/self/exe` re-exec: without an exec context the exec would
/// reset the range to the file context's `s0`, losing the category.
/// Called by `proxy::re_exec`; no-op in unconfined mode. If an
/// explicit exec context is already pending (the self-narrowing in
/// [`self_reexec_with_category`] sets one right before its re-exec),
/// it is left untouched — writing the *current* label here would
/// clobber the target range and the narrowing would loop forever.
pub fn preserve_range() -> Result<()> {
    let Some((user, role, ty, range)) = current_label() else {
        return Ok(());
    };
    if ty != "wlsctx_t" {
        return Ok(());
    }
    let pending = std::fs::read_to_string("/proc/self/attr/exec").unwrap_or_default();
    if !pending.trim().is_empty() && pending.trim() != "default" {
        return Ok(()); // an explicit context is already set; keep it
    }
    write_exec_context(&format!("{user}:{role}:{ty}:{range}")).map_err(|e| {
        anyhow::anyhow!("{e} — the re-exec will reset the range to the file context's")
    })
}
