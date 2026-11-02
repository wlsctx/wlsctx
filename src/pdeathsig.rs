//! The `PR_SET_PDEATHSIG` lifetime backstop: when a process's
//! parent dies — whatever the cause (exit, `SIGKILL`, a crash) —
//! the kernel sends it the signal it holds. The delivery happens
//! in `forget_original_parent` (`kernel/exit.c`:
//! `group_send_sig_info(pdeath_signal, SEND_SIG_NOINFO, …)`),
//! which no parent-side blocking, masking, or handler can prevent
//! — exactly what a "the supervisor is gone" backstop needs.
//!
//! Users: the `xwayland` satellite (decision #37, `SIGTERM`) and
//! the run pipeline (decision #42, `SIGUSR1`). The `dbus-proxy`
//! sidecar has none of this (its kill-backstop is the decision-#36
//! fd lifetime) and would be a candidate for the same belt.
//!
//! **Linux 7.2 semantics** (the running kernel; verified against
//! the `v7.2.11` source, `~/src/linux`):
//!
//! * `fork(2)` **resets** the value to 0 (`kernel/fork.c`:
//!   `p->pdeath_signal = 0`) — it is *not* inherited. Every link
//!   in a cascade must set it itself, after its own fork;
//! * `execve` **clears** it on a *domain-changing* exec: the
//!   `bprm->secureexec` clear in `fs/exec.c` fires whenever
//!   `secureexec` is set, and a SELinux exec that **changes the
//!   process's domain** (the confined run: `wlsctx_t` →
//!   `wlsctx_app_t` / `xserver_t`) sets it unless the policy
//!   grants the `noatsecure` process permission between the two
//!   SIDs (`security/selinux/hooks.c`:
//!   `bprm->secureexec |= !!avc_has_perm(…, PROCESS__NOATSECURE, …)`)
//!   — that permission is denied by default, so the belt is
//!   cleared and the post-exec shim re-arms it. setuid/setgid and
//!   a capability change set `secureexec` too, and `commit_creds`
//!   (`kernel/cred.c`) clears it independently when uid/gid/caps
//!   actually change. A *same-domain* exec (unconfined) sets none
//!   of these, so the pre-exec belt survives — which is why the
//!   shim is built only in confined mode. (The shim was also
//!   field-verified necessary on the decision-#37-era kernel,
//!   LESSONS #19–20; it covers any kernel or exec that clears the
//!   belt.)
//! * `PR_GET_PDEATHSIG` **writes the value to the pointer in
//!   `arg2`** and returns 0 (or -EFAULT) — the ≤ 6.x convention of
//!   returning the value is gone (`kernel/sys.c`).
//!
//! The belt is two layers for an execing process:
//!
//! * **pre-exec**: set the signal after the fork, before the exec
//!   (the `fork` reset makes this the only way to arm it);
//! * **post-exec (the shim)**: a small `LD_PRELOAD` `.so` whose
//!   constructor re-arms the signal after the transition.
//!   `prctl(2)` is not trapped by the sandbox's seccomp-notify
//!   filter, so the constructor is safe to run under it; the
//!   loader's `openat` of the `.so` *is* trapped but permitted —
//!   the file sits in the app's own writable runtime dir.
//!
//! A failed shim build (no `cc` on the host) degrades to the
//! pre-exec belt alone: the protected process then runs without
//! the post-exec backstop, and a supervisor that dies with a
//! cleared belt leaves it behind until something else kills it
//! (the same degradation decision #37 documents for the `Xwayland`
//! satellite).

use std::path::PathBuf;

/// The C source of the pdeathsig-restore shim for `sig` (numeric
/// signal number).
pub(crate) fn shim_src(sig: i32) -> String {
    format!(
        r#"
#define _GNU_SOURCE
#include <signal.h>
#include <sys/prctl.h>
__attribute__((constructor)) static void wlsctx_restore_pdeathsig(void) {{
    prctl(PR_SET_PDEATHSIG, {sig});
}}
"#
    )
}

/// Compile (or reuse) the pdeathsig-restore shim in `dir` for
/// `sig` (numeric signal number).
///
/// The object is named `pdeathsig-restore-<sig>.so`: the
/// per-instance runtime dir is shared by the `run` pipeline
/// (`SIGUSR1`) and the satellites (`SIGTERM`), and
/// `ensure_shim` reuses whatever file is already there — so
/// different signals must not collide on one name.
///
/// Returns the `.so` path, or `None` (with a warning) when no
/// compiler is available (see the module docs for the
/// degradation).
pub fn ensure_shim(dir: &str, sig: i32) -> Option<PathBuf> {
    let dir = std::path::Path::new(dir);
    let so = dir.join(format!("pdeathsig-restore-{sig}.so"));
    if so.exists() {
        return Some(so);
    }
    let c = dir.join(format!("pdeathsig-restore-{sig}.c"));
    if std::fs::write(&c, shim_src(sig)).is_err() {
        eprintln!("wlsctx: warning: could not write the pdeathsig-restore shim source {c:?}");
        return None;
    }
    match std::process::Command::new("cc")
        .arg("-shared")
        .arg("-fPIC")
        .arg("-o")
        .arg(&so)
        .arg(&c)
        .status()
    {
        Ok(s) if s.success() => Some(so),
        _ => {
            eprintln!(
                "wlsctx: warning: could not compile the pdeathsig-restore shim {c:?}; \
                 a SIGKILL'd supervisor would leave its child behind"
            );
            None
        }
    }
}

/// Set the calling process's parent-death signal to `sig`
/// (numeric signal number). The kernel delivers it when the
/// parent dies, whatever the cause (exit, any signal).
///
/// Returns `true` on success.
///
/// # Safety
/// Fixed `PR_SET_PDEATHSIG` opcode; the remaining arguments are
/// zeros.
pub fn set(sig: i32) -> bool {
    // SAFETY: see the function docs.
    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, sig, 0, 0, 0) == 0 }
}

/// Read the calling process's current parent-death signal (0 =
/// none). Used by the tests to verify the set/fork-reset mechanics.
///
/// Returns -1 when the syscall itself fails.
///
/// # Safety
/// Fixed `PR_GET_PDEATHSIG` opcode. Linux ≥ 7.0 writes the value
/// to the pointer passed in `arg2` (the return is 0 on success,
/// -EFAULT on a bad pointer) — the ≤ 6.x convention of returning
/// the value is gone; the pointer must be the *second* argument.
pub fn get() -> i32 {
    let mut v: i32 = 0;
    let r = unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut v as *mut i32, 0, 0, 0) };
    if r != 0 {
        return -1;
    }
    v
}
