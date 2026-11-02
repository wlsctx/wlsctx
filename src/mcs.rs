//! Per-instance MCS categories (confined mode only; phase 8.2).
//!
//! Each app instance gets one category `cN` of the user's
//! `s0-s0:c0.c1023` range (a stable hash of app-id + instance-id).
//! The category isolates the instance's **processes**: a `cN`
//! subject may only signal/ptrace/transition a same-`cN` process
//! (a single category is incomparable with any other — *stronger*
//! than podman's `cNNN,cMMM` model). It does **not** isolate the
//! instance's **objects**: a `dir`/`file`/`sock_file` created under
//! the `s0` runtime parent takes the *parent's* low level
//! (`default_range … target low`), so it is `s0`, not `cN`, and any
//! category may access it — file-level separation is the work of the
//! namespaces + landlock rootfs, not SELinux (LESSONS #29).
//!
//! How the category gets there (see `selinux/README.md`):
//!
//! - **S** (and the standalone proxy/satellites) narrows its *own*
//!   label from `wlsctx_t:s0` to the instance's category (a low==high
//!   `s0-s0:cN`, which the kernel reports as the single level
//!   `s0:cN` — range strings are canonical-form on read) by writing
//!   its exec context (`/proc/self/attr/exec` — the setexecfilecon
//!   equivalent; the module allows the `wlsctx_t` self-
//!   `dyntransition`) and re-execing `/proc/self/exe` once at
//!   startup (before it binds or creates anything, so the second
//!   pass starts clean). Every child it forks inherits the range (a
//!   process takes its creator's full range), so the pipeline and
//!   satellites all run at `cN`; objects created under the `s0`
//!   parent stay `s0` (see the header note above).
//! - **B** writes the exec context `wlsctx_app_t:<current range>`
//!   before execing the app (module: `wlsctx_t → wlsctx_app_t`
//!   `dyntransition`).
//! - The **Xwayland** and **dbus-proxy** satellites do the same for
//!   their execs (`xserver_t` / `wlsctx_app_t`), so those *processes*
//!   run at `cN` (the X socket, MIT auth file and bus socket they
//!   create are `s0` — under the `s0` parent).
//! - The **broker** (shared by all instances) narrows its range to
//!   **single-level `s0`** the same way (`self_reexec_to_s0`),
//!   before it binds or creates anything. This keeps the broker's
//!   own *subject* range minimal, so a compromised broker cannot act
//!   as a full-range subject or reach another instance's `cN`
//!   processes (an `s0` high does not dominate a `cN`). The
//!   session-level objects it serves (the runtime dir, the decision
//!   socket) are `s0` by construction (the parent's low level), so
//!   they stay reachable from every `cN` — no pre-creating needed.
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
    parse_label(&s)
}

/// Parse a `user:role:type:range` context string.
///
/// The kernel NUL-terminates the selinuxfs attr strings, and
/// `str::trim` does *not* strip a NUL (it is not Unicode whitespace)
/// — truncate at the first NUL first. Without that, the range comes
/// back as `s0\0`, the `range == target` loop guard in
/// [`self_reexec_to_range`] never matches, and the one-time self
/// re-exec becomes an infinite loop (260k execves in one strace
/// session).
fn parse_label(s: &str) -> Option<(String, String, String, String)> {
    let s = &s[..s.find('\0').unwrap_or(s.len())];
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
///
/// The open deliberately omits `O_CREAT`: the file always exists
/// (procfs instantiates it on lookup), while `O_CREAT` turns the
/// first open in a fresh in-sandbox procfs into a `may_o_create`
/// probe (namei.c) that SELinux answers with an `add_name` denial
/// on the self-labeled `attr/` directory — non-fatal (the kernel
/// drops `O_CREAT` and re-resolves, and the open still succeeds),
/// but an audit record on every run. The plain open hits only the
/// file's own permissions, which the module grants.
fn write_exec_context(ctx: &str) -> io::Result<()> {
    use std::io::Write;
    let mut b = ctx.as_bytes().to_vec();
    b.push(0); // attr files take NUL-terminated contexts
    let res = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open("/proc/self/attr/exec")?;
        f.write_all(&b)
    })();
    res.map_err(|e| {
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
    // The kernel reports a low==high range as a *single* level
    // (`mls_sid_to_context` collapses it — `s0:cN`, not `s0-s0:cN`),
    // and the loop guard in `self_reexec_to_range` compares the
    // current range against this target, so the target must be in
    // that canonical form. Writing either form as the exec context
    // parses to the same range; reporting only happens on read.
    self_reexec_to_range(&format!("s0:c{}", instance_category(app_id, instance_id)))
}

/// The **broker** (shared by all instances): narrow our own range to
/// single-level `s0` by a one-time self re-exec, before it binds or
/// creates anything.
///
/// The session-level objects it serves — the runtime dir and the
/// decision socket inside it — are `s0` *by construction* (the
/// parent's low level, not the creator's range — `default_range …
/// target low`), so they stay reachable from every per-instance
/// `cN` no matter who creates them first. The narrowing is a
/// *range-hygiene* measure: it keeps the broker's own **subject**
/// range minimal (a single `s0`, not the full spawn range
/// `s0-s0:c0.c1023`), so a compromised broker cannot act as a
/// full-range subject or reach another instance's `cN` processes (an
/// `s0` high does not dominate a `cN`). No-op in unconfined mode and
/// when already at `s0` (the post-re-exec invocation — the loop
/// guard).
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
///
/// The guard compares the range *as the kernel reports it* from
/// `/proc/self/attr/current`: a low==high range is collapsed to a
/// single level (`s0:cN`, not `s0-s0:cN`; plain `s0` stays `s0`),
/// so `target` must be in that canonical form, or the guard never
/// matches and this becomes an infinite re-exec loop.
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
    // Same NUL-termination trap as `current_label`: the pending
    // context (and the literal `default`) is NUL-terminated, and
    // `trim` does not strip that — without the truncation
    // `default\0` would look like an explicit context.
    let pending = std::fs::read_to_string("/proc/self/attr/exec").unwrap_or_default();
    let pending = &pending[..pending.find('\0').unwrap_or(pending.len())];
    let pending = pending.trim();
    if !pending.is_empty() && pending != "default" {
        return Ok(()); // an explicit context is already set; keep it
    }
    write_exec_context(&format!("{user}:{role}:{ty}:{range}")).map_err(|e| {
        anyhow::anyhow!("{e} — the re-exec will reset the range to the file context's")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kernel NUL-terminates the selinuxfs attr strings; the parse
    /// must strip it, or the range carries the NUL, the `range ==
    /// target` loop guard never matches, and the one-time self re-exec
    /// loops forever (the 260k-execve incident).
    #[test]
    fn parse_label_strips_nul_termination() {
        let l = parse_label("unconfined_u:unconfined_r:wlsctx_t:s0\0").unwrap();
        assert_eq!(
            l,
            (
                "unconfined_u".into(),
                "unconfined_r".into(),
                "wlsctx_t".into(),
                "s0".into()
            )
        );
        // The canonical single-level form the kernel reports for a
        // low==high category range (post instance re-exec).
        let l = parse_label("unconfined_u:unconfined_r:wlsctx_t:s0:c264\0").unwrap();
        assert_eq!(l.3, "s0:c264");
        // A low!=high range is not collapsed; both sides are reported.
        let l = parse_label("unconfined_u:unconfined_r:wlsctx_t:s0-s0:c0.c1023\0").unwrap();
        assert_eq!(l.3, "s0-s0:c0.c1023");
        // And a payload that stops carrying a NUL still parses.
        let l = parse_label("u:r:ty:s0").unwrap();
        assert_eq!(l.3, "s0");
    }

    #[test]
    fn parse_label_rejects_garbage() {
        assert!(parse_label("").is_none());
        assert!(parse_label("u:r:ty\0").is_none());
        assert!(parse_label("u:r\0:ty:range").is_none()); // NUL inside the string
    }

    #[test]
    fn instance_category_is_stable_and_in_range() {
        assert_eq!(
            instance_category("claw", "1"),
            instance_category("claw", "1")
        );
        assert!(instance_category("claw", "1") < NUM_CATEGORIES);
        // FNV-1a 64 low bits: these two inputs hash to c885 and c604.
        assert_ne!(
            instance_category("claw", "1"),
            instance_category("claw", "2")
        );
    }
}
