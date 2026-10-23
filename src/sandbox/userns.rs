//! User namespace creation and the credential sequence (PLAN.md §3.1,
//! decisions #9 and #10).
//!
//! Kernel rules (verified against the v7.2.11 source —
//! `kernel/user_namespace.c` — and empirically on this machine):
//!
//! * `uid_map`/`gid_map` accept **exactly one successful write**
//!   (decision #9); after that the file is read-only for the life of
//!   the process.
//! * An unprivileged creator may write **only a single extent of
//!   count 1 whose in-ns id equals its own uid/gid**
//!   (`new_idmap_permitted()`; `create_user_ns()` sets the ns owner
//!   to the creator's euid, so the "owner == euid" gate passes).
//!   Multi-extent maps are unreachable for us: `mappings_overlap()`
//!   forbids two extents sharing a parent id, and an unprivileged
//!   creator can only map its own id — so the old two-entry
//!   `0 → uid; uid → uid` map is EINVAL on modern kernels
//!   (decision #10). bwrap works around this with the setuid
//!   `newuidmap` helper; we deliberately don't.
//! * `setgroups` must be written **before** the maps; while
//!   setgroups is not allowed, the gid self-map is permitted
//!   unprivileged as well.
//!
//! So the map is the single extent `<real uid> → <real uid>` (and
//! `<real gid> → <real gid>`). The process's in-ns id is the real
//! uid **from the start** — its parent-ns id re-read through the map
//! — and in-ns `0` is simply not in the map. The app can never be
//! `0`, never another user, and can never move: a second map write
//! is impossible (write-once), and `setresuid(0)` is EINVAL because
//! `0` is unmapped.
//!
//! `set_cred_user_ns()` grants the creator **CAP_FULL_SET in the new
//! ns**, and nothing in this sequence clears it — the capability
//! set stays full at exec time. That is safe *by construction of the
//! map*: every ns-local capability (dac, kill, ptrace, mount, …)
//! acts only on the single mapped identity — our own uid/gid — and
//! the mounts we make (phase 3) happen in our private mount ns. The
//! hard privilege boundary is nono's landlock + seccomp filter
//! (phase 4).
//!
//! Mapping a subuid range (for file ownership) needs a second extent
//! and hence a setuid helper; deferred (decision #10).

use std::io::{self, Write};

use anyhow::{Context, Result, bail};

/// The real (host) credentials to map into the user namespace.
pub(crate) struct Credentials {
    /// The real uid; also the in-ns uid (the map is one extent).
    pub uid: u32,
    /// The real gid; also the in-ns gid (the map is one extent).
    pub gid: u32,
    // (A subuid range for file ownership would need a second map
    // extent and a setuid helper; deferred — decision #10.)
}

impl Credentials {
    /// The current process's *real* (not effective) uid/gid.
    pub(crate) fn current() -> Result<Self> {
        let mut ruid: u32 = 0;
        let mut euid: u32 = 0;
        let mut suid: u32 = 0;
        if unsafe { libc::getresuid(&mut ruid, &mut euid, &mut suid) } != 0 {
            return Err(io::Error::last_os_error()).context("getresuid(2)");
        }
        let mut rgid: u32 = 0;
        let mut egid: u32 = 0;
        let mut sgid: u32 = 0;
        if unsafe { libc::getresgid(&mut rgid, &mut egid, &mut sgid) } != 0 {
            return Err(io::Error::last_os_error()).context("getresgid(2)");
        }
        Ok(Self {
            uid: ruid,
            gid: rgid,
        })
    }
}

/// Enter a new user namespace and write the single, final uid/gid
/// maps. Must be called from the forked child, before any other
/// namespace or mount work.
pub(crate) fn enter_userns(creds: &Credentials) -> Result<()> {
    // A new user namespace for this process (and its future forks)
    // only; the caller is a forked child, so wlsctx itself stays
    // outside (PLAN.md §3.2).
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
        return Err(io::Error::last_os_error()).context(
            "unshare(CLONE_NEWUSER) failed (is unprivileged user namespace creation enabled? \
             check user.max_user_namespaces)",
        );
    }

    // setgroups must be written before the maps, and exactly once.
    write_map_file("/proc/self/setgroups", "deny")?;

    // The single write of the maps (decision #9).
    let (uid_map, gid_map) = map_contents(creds);
    write_map_file("/proc/self/uid_map", &uid_map)?;
    write_map_file("/proc/self/gid_map", &gid_map)?;

    Ok(())
}

/// The single `uid_map`/`gid_map` payloads (decision #9: written
/// exactly once; decision #10: one extent, because that is all an
/// unprivileged creator may write).
fn map_contents(creds: &Credentials) -> (String, String) {
    (
        format!("{} {} 1\n", creds.uid, creds.uid),
        format!("{} {} 1\n", creds.gid, creds.gid),
    )
}

/// Write a /proc map file (`setgroups`, `uid_map`, `gid_map`). The
/// kernel permits exactly one successful write; after that the file
/// is read-only for the life of the process.
fn write_map_file(path: &str, contents: &str) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("opening {path}"))?;
    file.write_all(contents.as_bytes()).with_context(|| {
        format!("writing {path} (the kernel permits exactly one successful write)")
    })?;
    Ok(())
}

/// Verify the post-map credential state (the old `drop_ns_root` was
/// a privilege drop; with the single-extent map there is nothing to
/// drop — the identity is the real uid from the start, locked in by
/// the map itself). Everything here is a *check*, and a failure
/// aborts the sandbox setup (exit 126) before the app is exec'd.
pub(crate) fn verify_locked(creds: &Credentials) -> Result<()> {
    check_resids(creds)?;
    check_caps_present()?;
    check_repriv_blocked()?;
    Ok(())
}

/// Verify the ruid/euid/suid (and gid) triple.
fn check_resids(creds: &Credentials) -> Result<()> {
    let mut ruid: u32 = 0;
    let mut euid: u32 = 0;
    let mut suid: u32 = 0;
    if unsafe { libc::getresuid(&mut ruid, &mut euid, &mut suid) } != 0 {
        return Err(io::Error::last_os_error()).context("getresuid(2) during verification");
    }
    if (ruid, euid, suid) != (creds.uid, creds.uid, creds.uid) {
        bail!(
            "ruid={ruid} euid={euid} suid={suid}; expected the real uid {} on all three",
            creds.uid
        );
    }
    let mut rgid: u32 = 0;
    let mut egid: u32 = 0;
    let mut sgid: u32 = 0;
    if unsafe { libc::getresgid(&mut rgid, &mut egid, &mut sgid) } != 0 {
        return Err(io::Error::last_os_error()).context("getresgid(2) during verification");
    }
    if (rgid, egid, sgid) != (creds.gid, creds.gid, creds.gid) {
        bail!(
            "rgid={rgid} egid={egid} sgid={sgid}; expected the real gid {} on all three",
            creds.gid
        );
    }
    Ok(())
}

/// The process's effective capability set (from /proc/self/status).
fn cap_eff() -> Result<u64> {
    let status =
        std::fs::read_to_string("/proc/self/status").context("reading /proc/self/status")?;
    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:") {
            return u64::from_str_radix(hex.trim(), 16)
                .with_context(|| format!("parsing CapEff {hex:?}"));
        }
    }
    bail!("no CapEff line in /proc/self/status");
}

/// The creator holds the full ns capability set, and the design
/// relies on it (phase 3 builds the rootfs with ns-local
/// CAP_SYS_ADMIN). It must still be here at this point: if a kernel
/// change clears it, the rootfs phase is broken, so fail loudly
/// instead of discovering it in the mount phase.
fn check_caps_present() -> Result<()> {
    let caps = cap_eff()?;
    if caps == 0 {
        bail!(
            "CapEff is 0 before the exec; the design relies on the creator's ns capability set (PLAN §3.1)"
        );
    }
    if caps & (1 << 21) == 0 {
        bail!(
            "CapEff is {caps:#018x} without CAP_SYS_ADMIN; the rootfs phase cannot mount (PLAN §3.1)"
        );
    }
    Ok(())
}

/// In-ns `0` is not in the map, so no set*uid call can ever reach it:
/// the kernel rejects the attempt with EINVAL. Anything else
/// (success, a different errno) would mean the id can move, which
/// breaks the "locked at the real uid" invariant.
fn check_repriv_blocked() -> Result<()> {
    assert_errno("setresuid(0,0,0)", libc::EINVAL, || unsafe {
        libc::setresuid(0, 0, 0)
    })?;
    assert_errno("setresgid(0,0,0)", libc::EINVAL, || unsafe {
        libc::setresgid(0, 0, 0)
    })?;
    Ok(())
}

/// Run `call` (a raw syscall returning 0 on success) and require
/// exactly `want` — anything else (success included) is a design
/// violation.
fn assert_errno(what: &str, want: i32, call: impl FnOnce() -> i32) -> Result<()> {
    if call() == 0 {
        bail!(
            "{what} SUCCEEDED — the credential state can move, this breaks the design (PLAN §3.1)"
        );
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() != Some(want) {
        bail!("{what} failed with {err:?}; expected errno {want}");
    }
    Ok(())
}

/// The forked-child test harness (`run_in_child` + `ChildOut`) and the
/// `enter_userns` failure classifier, shared with the `namespaces`
/// tests (both modules run in a multithreaded cargo-test process and
/// must never enter namespaces in the parent).
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sandbox::run_sandboxed;
    use nix::sys::wait::{WaitStatus, waitpid};
    use nix::unistd::ForkResult;
    use std::ffi::OsString;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;

    /// One raw `write(2)` to `fd` (short writes are allowed — the
    /// `writeln!`/`write_all` machinery retries).
    pub(crate) fn raw_write(fd: i32, buf: &[u8]) -> io::Result<usize> {
        // SAFETY: `fd` is a valid, open file descriptor; `buf` is valid
        // for its length.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    /// The child's output channel: **unbuffered** writers straight to
    /// the pipe fds. The body must use this (and `o.err()`) instead
    /// of `println!`/`eprintln!`: Rust's global stdout is a buffered
    /// `LineWriter` whose buffer is silently dropped by
    /// `process::exit` — a final line ending in `'\n'` never reaches
    /// the pipe (that was the fork+pipe "0 bytes" bug).
    pub(crate) struct ChildOut {
        out_fd: i32,
        err_fd: i32,
    }

    impl ChildOut {
        /// A writer for the child's *stderr* pipe (diagnostics).
        pub(crate) fn err(&mut self) -> ErrWriter<'_> {
            ErrWriter {
                fd: self.err_fd,
                _marker: std::marker::PhantomData,
            }
        }
    }

    /// An unbuffered writer to the child's stderr pipe.
    pub(crate) struct ErrWriter<'a> {
        fd: i32,
        _marker: std::marker::PhantomData<&'a ()>,
    }

    impl Write for ErrWriter<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            raw_write(self.fd, buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Write for ChildOut {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            raw_write(self.out_fd, buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Run `body` in a forked child and return (exit code, stdout,
    /// stderr). The child's exit code is what `body` returns (101 on
    /// panic); its output is what `body` wrote to `ChildOut`.
    ///
    /// fd 1/2 are also dup'd to the same pipes, so an exec'd
    /// grandchild (the `run_sandboxed` test) and raw panic messages
    /// still land in the capture.
    ///
    /// Returns (None, ..) if the harness itself fails.
    ///
    /// NOTE: forking a multithreaded test process is only safe here
    /// because the child never blocks on a lock another test thread
    /// could hold (it only does file I/O, writes, and exits); if you
    /// ever see a hang, re-run with `-- --test-threads=1`.
    pub(crate) fn run_in_child(
        body: impl FnOnce(&mut ChildOut) -> i32 + Send,
    ) -> (Option<i32>, String, String) {
        let mut fds: [i32; 4] = [-1; 4];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0
            || unsafe { libc::pipe(fds.as_mut_ptr().add(2)) } != 0
        {
            eprintln!("test setup: pipe(2): {}", io::Error::last_os_error());
            return (None, String::new(), String::new());
        }
        let (r_out, w_out, r_err, w_err) = (fds[0], fds[1], fds[2], fds[3]);

        // SAFETY: fork(2); the child below only exits, never returns.
        match unsafe { nix::unistd::fork() } {
            Ok(ForkResult::Child) => {
                unsafe { libc::close(r_out) };
                unsafe { libc::close(r_err) };
                // Point fd 1/2 at the pipes (for exec'd grandchildren
                // and panic messages); save the originals in case the
                // redirect fails.
                let saved_out = unsafe { libc::dup(1) };
                let saved_err = unsafe { libc::dup(2) };
                if saved_out < 0
                    || saved_err < 0
                    || unsafe { libc::dup2(w_out, 1) } < 0
                    || unsafe { libc::dup2(w_err, 2) } < 0
                {
                    eprintln!("test setup: redirecting stdout/stderr failed");
                    std::process::exit(126);
                }
                // The test harness has no logger (main's env_logger
                // init never runs in tests), and A/B report their
                // setup failures via `log::error!` before `exit(126)`
                // — initialize one (to the captured stderr) so those
                // messages actually reach the assertion.
                let _ = env_logger::try_init_from_env(
                    env_logger::Env::default().default_filter_or("warn"),
                );
                let code = body(&mut ChildOut {
                    out_fd: w_out,
                    err_fd: w_err,
                });
                // Close the write ends explicitly (fd 1/2 share the
                // same pipe; `exit` closes everything regardless) so
                // the parent's read reaches EOF.
                unsafe { libc::close(w_out) };
                unsafe { libc::close(w_err) };
                std::process::exit(code);
            }
            Ok(ForkResult::Parent { child }) => {
                unsafe { libc::close(w_out) };
                unsafe { libc::close(w_err) };
                // Wait first (all writes are then complete), then
                // drain the pipes to EOF.
                let code = match waitpid(Some(child), None) {
                    Ok(WaitStatus::Exited(_, code)) => Some(code),
                    Ok(WaitStatus::Signaled(_, sig, _)) => Some(128 + sig as i32),
                    Ok(other) => {
                        eprintln!("test setup: unexpected wait status: {other:?}");
                        None
                    }
                    Err(e) => {
                        eprintln!("test setup: waitpid: {e}");
                        None
                    }
                };
                let mut out = String::new();
                let mut err = String::new();
                // SAFETY: `r_out`/`r_err` are ours at this point (the
                // child closed its copies before exiting); the
                // `File`s close them again on drop.
                let mut f_out = unsafe { std::fs::File::from_raw_fd(r_out) };
                let mut f_err = unsafe { std::fs::File::from_raw_fd(r_err) };
                let _ = f_out.read_to_string(&mut out);
                let _ = f_err.read_to_string(&mut err);
                (code, out, err)
            }
            Err(e) => {
                eprintln!("test setup: fork(2): {e}");
                (None, String::new(), String::new())
            }
        }
    }

    /// Fetch the credentials or abort the test.
    pub(crate) fn creds() -> Result<Credentials> {
        Credentials::current()
    }

    /// The single extent the map carries (decision #10).
    fn single_extent(c: &Credentials) -> (String, String) {
        (
            format!("{} {} 1", c.uid, c.uid),
            format!("{} {} 1", c.gid, c.gid),
        )
    }

    /// `/proc` map files format their columns with multiple spaces;
    /// normalize to single spaces before comparing.
    fn normalize_map(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Classify an `enter_userns` failure from the child's side:
    /// exit 1 = the environment cannot create the namespace at all
    /// (skip); exit 20 = the namespace was created but the kernel
    /// rejected our map (hard fail — the design is broken here).
    pub(crate) fn enter_or_classify(o: &mut ChildOut, creds: &Credentials) -> i32 {
        match enter_userns(creds) {
            Ok(()) => 0,
            Err(e) => {
                let msg = format!("{e:#}");
                if msg.contains("uid_map") || msg.contains("gid_map") {
                    let _ = writeln!(o, "MAP-REJECTED: {msg}");
                    20
                } else {
                    let _ = writeln!(o, "NS-FAIL: {msg}");
                    1
                }
            }
        }
    }

    #[test]
    fn enter_then_verify_credential_sequence() {
        let creds = match creds() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skipping: cannot read current credentials: {e}");
                return;
            }
        };

        let (code, out, err) = run_in_child(move |o| {
            // 1. Enter: unshare + setgroups + the single map write.
            let rc = enter_or_classify(o, &creds);
            if rc != 0 {
                return rc;
            }

            // The map must be exactly the single extent — one line,
            // no `0` entry.
            let map = std::fs::read_to_string("/proc/self/uid_map").unwrap_or_default();
            let (want_uid, want_gid) = single_extent(&creds);
            let lines: Vec<&str> = map.lines().collect();
            if lines.len() != 1 || normalize_map(lines[0]) != want_uid {
                let _ = writeln!(
                    o,
                    "FAIL uid_map is {map:?}; want the single extent {want_uid:?}"
                );
                return 2;
            }
            let gmap = std::fs::read_to_string("/proc/self/gid_map").unwrap_or_default();
            let glines: Vec<&str> = gmap.lines().collect();
            if glines.len() != 1 || normalize_map(glines[0]) != want_gid {
                let _ = writeln!(
                    o,
                    "FAIL gid_map is {gmap:?}; want the single extent {want_gid:?}"
                );
                return 3;
            }

            let setgroups = std::fs::read_to_string("/proc/self/setgroups").unwrap_or_default();
            if setgroups.trim() != "deny" {
                let _ = writeln!(o, "FAIL setgroups is {setgroups:?}; want \"deny\"");
                return 4;
            }

            // The creator holds the full ns capability set, and the
            // design relies on it (it is never cleared on this path).
            match cap_eff() {
                Err(e) => {
                    let _ = writeln!(o, "FAIL reading CapEff: {e:#}");
                    return 5;
                }
                Ok(0) => {
                    let _ = writeln!(
                        o,
                        "FAIL CapEff is 0 after the map write; the design needs the full ns set"
                    );
                    return 5;
                }
                Ok(caps) if caps & (1 << 21) == 0 => {
                    let _ = writeln!(
                        o,
                        "FAIL CapEff is {caps:#018x} without CAP_SYS_ADMIN; the rootfs phase cannot mount"
                    );
                    return 5;
                }
                Ok(_) => {}
            }

            // 2. Verify the lock (identity is the real uid by
            //    construction; 0 is unmapped and unreachable).
            if let Err(e) = verify_locked(&creds) {
                let _ = writeln!(o, "SETUP-FAIL verify_locked: {e:#}");
                return 6;
            }

            // 3. The result.
            let _ = writeln!(
                o,
                "OK: uid locked at {} / gid {} (0 unmapped, setresuid(0) EINVAL, ns cap set retained for phase 3/4)",
                creds.uid, creds.gid
            );
            0
        });

        match code {
            Some(0) => {}
            // The environment cannot create a (nested) user namespace
            // here at all: skip, don't fail.
            Some(1) => {
                eprintln!("skipping (environment cannot create a user namespace):\n{out}\n{err}");
                return;
            }
            // The namespace was created but the kernel rejected our
            // map: this is a design/kernel mismatch, not an
            // environment quirk — fail loudly (this is the case that
            // used to hide behind a "skip").
            Some(20) => panic!(
                "the kernel rejected the single-extent map (this is a design failure, not an environment skip):\n{out}\n{err}"
            ),
            Some(other) => panic!("credential sequence failed (exit {other}):\n{out}\n{err}"),
            None => panic!("test harness failed"),
        }
        assert!(
            out.contains("OK: uid locked"),
            "expected an OK line; got:\n{out}\n{err}"
        );
    }

    /// Decision #9 probe: the kernel permits exactly one successful
    /// write to the map files. After the first write, a second write
    /// with *any* content (identical, the old two-entry form, or an
    /// unrelated entry) must be rejected, and the map must remain
    /// unchanged. This is the kernel constraint the whole credential
    /// design relies on.
    #[test]
    fn uid_map_is_write_once() {
        let creds = match creds() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skipping: cannot read current credentials: {e}");
                return;
            }
        };

        let (code, out, err) = run_in_child(move |o| {
            let rc = enter_or_classify(o, &creds);
            if rc != 0 {
                return rc;
            }

            let identical = map_contents(&creds).0.clone();
            let old_two_entry = format!("0 {} 1\n{} {} 1\n", creds.uid, creds.uid, creds.uid);
            let unrelated = format!("0 {} 1\n", creds.uid);
            for (label, contents) in [
                ("identical", identical),
                ("the old two-entry form", old_two_entry),
                ("unrelated single entry (0 -> real uid)", unrelated),
            ] {
                match write_map_file("/proc/self/uid_map", &contents) {
                    Ok(()) => {
                        let _ = writeln!(
                            o,
                            "FAIL: the second write ({label}) was ACCEPTED — write-once is not in effect on this kernel"
                        );
                        return 10;
                    }
                    Err(e) => {
                        let is_eperm = e.chain().any(|c| {
                            c.downcast_ref::<io::Error>()
                                .is_some_and(|io| io.raw_os_error() == Some(libc::EPERM))
                        });
                        if !is_eperm {
                            let _ = writeln!(
                                o,
                                "FAIL: second write ({label}) failed with {e:#}; expected EPERM"
                            );
                            return 11;
                        }
                    }
                }
            }

            // The map must be exactly what we first wrote.
            let map = std::fs::read_to_string("/proc/self/uid_map").unwrap_or_default();
            let (want, _) = single_extent(&creds);
            if normalize_map(&map) != want {
                let _ = writeln!(
                    o,
                    "FAIL: the map changed after the rejected writes: {map:?}"
                );
                return 12;
            }

            let _ = writeln!(
                o,
                "OK: write-once holds (second writes rejected with EPERM, map unchanged)"
            );
            0
        });

        match code {
            Some(0) => {}
            Some(1) => {
                eprintln!("skipping (environment cannot create a user namespace):\n{out}\n{err}");
                return;
            }
            Some(20) => panic!("the kernel rejected the single-extent map:\n{out}\n{err}"),
            Some(other) => panic!("write-once probe failed (exit {other}):\n{out}\n{err}"),
            None => panic!("test harness failed"),
        }
        assert!(
            out.contains("OK: write-once holds"),
            "expected an OK line; got:\n{out}\n{err}"
        );
    }

    /// End-to-end: `wlsctx run -- id` executes the command in the new
    /// user namespace and the command sees the *real* uid/gid.
    #[test]
    fn run_sandboxed_command_sees_the_real_uid() {
        let _lock = crate::testutil::SANDBOX_LOCK
            .lock()
            .unwrap_or_else(|e| panic!("SANDBOX_LOCK poisoned: {e}"));
        let creds = match creds() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skipping: cannot read current credentials: {e}");
                return;
            }
        };

        // The outer fork+pipe captures the *great-grandchild* (the
        // sandboxed `id`) stdout and the intermediate children's
        // stderr (where setup errors are logged).
        let config = crate::sandbox::SandboxConfig {
            app_id: "app".to_string(),
            instance_id: "1".to_string(),
            network: crate::sandbox::namespaces::NetworkMode::Shared,
            profile: crate::profile::Profile::adhoc(),
            gpu: false,
            wayland: None,
        };
        let (code, out, err) =
            run_in_child(
                move |o| match run_sandboxed(&[OsString::from("id")], &config) {
                    Ok(code) => code,
                    Err(e) => {
                        let _ = writeln!(o.err(), "run_sandboxed error: {e:#}");
                        2
                    }
                },
            );

        match code {
            Some(0) => {}
            // 126 = setup failed inside the grandchild. Distinguish
            // "cannot create the namespace here" (skip) from "the
            // kernel rejected our map" (hard fail).
            Some(126) => {
                if err.contains("uid_map") || err.contains("gid_map") {
                    panic!(
                        "the kernel rejected the single-extent map (design failure, not an environment skip):\n{err}"
                    );
                }
                eprintln!("skipping (environment cannot create a user namespace):\n{err}");
                return;
            }
            Some(other) => panic!("run_sandboxed exited with {other}:\n{out}\n{err}"),
            None => panic!("test harness failed"),
        }

        let want = format!("uid={}(", creds.uid);
        assert!(
            out.contains(&want),
            "expected `{want}` in `id` output; got:\n{out}\n{err}"
        );
        let want = format!("gid={}(", creds.gid);
        assert!(
            out.contains(&want),
            "expected `{want}` in `id` output; got:\n{out}\n{err}"
        );
    }
}
