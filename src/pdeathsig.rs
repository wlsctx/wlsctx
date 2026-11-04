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
//! * `execve` **clears** it on any *SID-changing* exec,
//!   **unconditionally**: `selinux_bprm_committing_creds`
//!   (`security/selinux/hooks.c:2545`, commit `4ac212ad4e8f`)
//!   sets `current->pdeath_signal = 0` whenever the exec changes
//!   the process's SID (`new_crsec->sid != new_crsec->osid`) —
//!   the confined runs do (`wlsctx_t` → `wlsctx_app_t` /
//!   `xserver_t`). No permission can prevent it (in particular,
//!   this policy's granted `noatsecure` on the `wlsctx_t` →
//!   `wlsctx_app_t` transition is irrelevant to it). The legacy
//!   paths coexist: a *denied* `noatsecure` check sets
//!   `bprm->secureexec` (the `xserver_t` transition, where it is
//!   not granted, takes it), `fs/exec.c` clears the belt on
//!   `secureexec` (setuid/setgid and a capability change set it
//!   too), and `commit_creds` (`kernel/cred.c`) clears it
//!   independently on an actual credential change. But on this
//!   policy the unconditional SID-transition clear is the
//!   mechanism that fires on every confined exec — including the
//!   ones where `noatsecure` is granted. A *same-domain* exec
//!   (unconfined) changes no SID and none of these fire, so the
//!   pre-exec belt survives — which is why the run pipeline
//!   builds the shim only in confined mode (the `xwayland`
//!   satellite builds it unconditionally: its exec transitions to
//!   `xserver_t` in confined mode and the re-arm is idempotent in
//!   the other). (The shim was also field-verified necessary on
//!   the decision-#37-era kernel, LESSONS #19–20; it covers any
//!   kernel or exec that clears the belt.)
//!
//!   **The `.so`'s label:** in confined mode `ensure_shim`
//!   relabels the compiled `.so` to the module's dedicated
//!   `wlsctx_shim_t` type (setxattr — on this kernel `filecon`
//!   does not label created inodes). A confined consumer maps it
//!   with `PROT_EXEC`, which on 7.2 needs `file:execute`
//!   (`file_map_prot_to_av`) — granted on `wlsctx_shim_t` by the
//!   two consumer types only, and on no base-policy type an
//!   app can read from the instance runtime dir. A failed
//!   relabel degrades like a failed build (a warning; the
//!   confined consumer cannot map a mislabeled `.so`). And the
//!   on-demand compile itself runs with the current context
//!   *pinned* into the cred's one-shot exec context (written to
//!   `/proc/self/attr/exec` before the vfork of `cc`, cleared
//!   after): the vforked child shares this cred, and the explicit
//!   context keeps the compiler in `wlsctx_t` instead of the
//!   module's `typetransition` dragging it into `wlsctx_app_t`
//!   (`wlsctx_t + bin_t:process`), which lacks the `tmp_t`
//!   grants for its temp files.
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
/// In confined mode the `.so` is (re)labeled to the module's
/// `wlsctx_shim_t` type after compilation — and on the reuse
/// path, when a file left by an older build does not carry it yet
/// (see the module docs for why a confined consumer cannot map a
/// mislabeled `.so`).
///
/// In confined mode the `cc` spawn additionally runs under a
/// pinned exec context (`pin_self_exec_context` /
/// `clear_exec_context` below): the compiler is vforked from
/// this process and shares its cred, and the module's
/// `typetransition` rules would otherwise carry it into
/// `wlsctx_app_t` (see those functions for why that matters).
///
/// Returns the `.so` path, or `None` (with a warning) when no
/// compiler is available (see the module docs for the
/// degradation).
pub fn ensure_shim(dir: &str, sig: i32) -> Option<PathBuf> {
    let dir = std::path::Path::new(dir);
    let so = dir.join(format!("pdeathsig-restore-{sig}.so"));
    if so.exists() {
        relabel_if_needed(&so);
        return Some(so);
    }
    let c = dir.join(format!("pdeathsig-restore-{sig}.c"));
    if std::fs::write(&c, shim_src(sig)).is_err() {
        eprintln!("wlsctx: warning: could not write the pdeathsig-restore shim source {c:?}");
        return None;
    }
    pin_self_exec_context();
    let compiled = match std::process::Command::new("cc")
        .arg("-shared")
        .arg("-fPIC")
        .arg("-o")
        .arg(&so)
        .arg(&c)
        .status()
    {
        Ok(s) if s.success() => true,
        _ => {
            eprintln!(
                "wlsctx: warning: could not compile the pdeathsig-restore shim {c:?}; \
                 a SIGKILL'd supervisor would leave its child behind"
            );
            false
        }
    };
    clear_exec_context();
    if !compiled {
        return None;
    }
    relabel_if_needed(&so);
    Some(so)
}

/// Write the current process's own context into the one-shot exec
/// context (`/proc/self/attr/exec`), so that a child which `exec`s
/// out of this process's *shared cred* — the `cc` below, vforked by
/// the std `Command` — lands in **exactly this** context. The
/// explicit context bypasses the module's `typetransition` rules
/// (`wlsctx_t + bin_t:process` → `wlsctx_app_t` would otherwise
/// carry the compiler into the app domain, which lacks the
/// `tmp_t` dir/file grants for its temp files — a hard failure when
/// the CWD is not a writable `user_tmp_t` dir, and denials even
/// when it is) — and because the old and new SID are identical,
/// `check_nnp_nosuid` (`security/selinux/hooks.c`) takes its
/// `new_crsec->sid == old_crsec->sid` fast path: no `noatsecure`,
/// no NNP/NOSUID checks at all.
///
/// The write is *one-shot per cred*: the consuming child's `exec`
/// copies the cred (`bprm_set_creds`) and zeroes its own copy of
/// `exec_sid`, while this process's cred keeps the pending SID
/// until `clear_exec_context` — so the two are always paired.
fn pin_self_exec_context() {
    if !crate::mcs::is_confined() {
        return;
    }
    let cur = match std::fs::read_to_string("/proc/self/attr/current") {
        Ok(c) => c.trim().to_string(),
        Err(_) => return, // no readable current context; nothing to pin
    };
    if std::fs::write("/proc/self/attr/exec", &cur).is_err() {
        eprintln!(
            "wlsctx: warning: could not pin the exec context before the shim compile \
             ({cur:?}); the compiler may transition into wlsctx_app_t (the module's \
             typetransition) and hit temp-file denials"
        );
    }
}

/// Clear the one-shot exec context pending on this process's cred
/// (an empty `attr/exec` write zeroes `exec_sid` — the 7.2 setattr
/// path treats a zero-length value as "no context"), so that
/// children forked *later* (the S→A→B pipeline, the satellite
/// processes) do not inherit a stale one: if their own
/// `attr/exec` write ever fails, a stale pending context would
/// make them `exec` into *this* context instead of the module's
/// `typetransition` target.
fn clear_exec_context() {
    if !crate::mcs::is_confined() {
        return;
    }
    let _ = std::fs::write("/proc/self/attr/exec", "");
}

/// The SELinux context the shim `.so` must carry for a confined
/// consumer to map it: the module's `wlsctx_shim_t` type at level
/// `s0` (objects created in the instance dir take the parent's low
/// level, and `s0` is dominated by every `s0:cN`, so every
/// instance's consumers can map it).
fn shim_context() -> Option<String> {
    // The user comes from the current process context (the
    // context must belong to a user allowed to use `object_r`).
    let user = std::fs::read_to_string("/proc/self/attr/current")
        .ok()?
        .split(':')
        .next()?
        .trim()
        .to_string();
    Some(format!("{user}:object_r:wlsctx_shim_t:s0"))
}

/// Read the file's current SELinux label (the `security.selinux`
/// xattr), or `None` (SELinux off or the xattr absent).
fn current_label(so: &std::path::Path) -> Option<String> {
    use std::os::unix::ffi::OsStrExt;
    // A `CString`: the kernel reads the path as a NUL-terminated
    // string, and a raw Rust `String` buffer does not guarantee a
    // NUL at `len` (a reused allocator block can carry stale
    // bytes past it — the kernel then walks into them and the
    // call fails ENOENT on a mangled path; LESSONS #43).
    let path = std::ffi::CString::new(so.as_os_str().as_bytes()).ok()?;
    let mut buf = [0u8; 256];
    // SAFETY: `path` is a valid NUL-terminated C string; `buf` is
    // valid for `buf.len()` bytes.
    let n = unsafe {
        libc::getxattr(
            path.as_ptr(),
            c"security.selinux".as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    (0 < n).then(|| {
        let n = n as usize;
        String::from_utf8_lossy(&buf[..n])
            .trim_end_matches('\0')
            .to_string()
    })
}

/// Set the shim's SELinux label to the module's `wlsctx_shim_t`
/// (confined mode only) when it does not already carry it. A
/// failed relabel only warns — the degradation is the documented
/// one (a confined consumer cannot map a mislabeled `.so`, and a
/// SIGKILL'd supervisor would leave its child behind).
fn relabel_if_needed(so: &std::path::Path) {
    if !crate::mcs::is_confined() {
        return;
    }
    let want = match shim_context() {
        Some(c) => c,
        None => return, // no readable current context; nothing to do
    };
    if current_label(so).as_deref() == Some(want.as_str()) {
        return;
    }
    // The 7.2 setxattr relabel path (selinux_inode_setxattr):
    // `file:relabelfrom` (subject → the old label),
    // `file:relabelto` (subject → this one), and
    // `filesystem:associate` (this SID → the mount's SID) — all
    // granted by the module. The kernel NUL-terminates the value
    // itself (`kmemdup_nul`), so the exact length is passed for
    // it; the *path* is read as a C string, so it must be a
    // `CString` (a raw `String` buffer's byte at `len` is not a
    // guaranteed NUL — on a reused allocator block the kernel
    // walks into the stale tail and the call fails `ENOENT` on
    // a mangled path, while every Rust-level log of the path
    // looks correct; LESSONS #43).
    use std::os::unix::ffi::OsStrExt;
    let path = match std::ffi::CString::new(so.as_os_str().as_bytes()) {
        Ok(p) => p,
        Err(_) => {
            eprintln!(
                "wlsctx: warning: could not label the pdeathsig-restore shim {so:?} \
                 (non-UTF-8 path); a confined consumer cannot map it \
                 (`file:execute` is granted only on wlsctx_shim_t) — a \
                 SIGKILL'd supervisor would leave its child behind"
            );
            return;
        }
    };
    // SAFETY: `path` is a valid NUL-terminated C string; `want`
    // is a valid byte sequence of length `want.len()` (the
    // kernel appends the NUL).
    let r = unsafe {
        libc::setxattr(
            path.as_ptr(),
            c"security.selinux".as_ptr(),
            want.as_bytes().as_ptr() as *const libc::c_void,
            want.len(),
            0,
        )
    };
    if r != 0 {
        let e = std::io::Error::last_os_error();
        eprintln!(
            "wlsctx: warning: could not label the pdeathsig-restore shim {so:?} \
             as {want:?} ({e}); a confined consumer cannot map it \
             (`file:execute` is granted only on wlsctx_shim_t) — a \
             SIGKILL'd supervisor would leave its child behind"
        );
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
