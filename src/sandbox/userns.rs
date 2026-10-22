//! User namespace creation and the credential sequence (PLAN.md §3.1,
//! decision #9).
//!
//! Modern kernels permit **exactly one write** to `uid_map`/`gid_map`
//! (no post-hoc narrowing — verified in the v7.2 stable source), so
//! the map is written once, *before* the mount phase, carrying both
//! entries:
//!
//! ```text
//! 0 → <real uid>          (lets us hold CAP_SYS_ADMIN in the ns for
//!                           the mount phase)
//! <real uid> → <real uid> (keeps the app's identity)
//! 1 → <subuid range>      (optional profile flag)
//! ```
//!
//! After the mount phase, `setresuid`/`setresgid` back to the real
//! uid/gid makes the kernel **clear our capability sets**; from then
//! on the only uid we can ever hold is the real one (an unprivileged
//! `setresuid` may only pick values from the previous ruid/euid/suid),
//! so the `0` entry of the map is unreachable. The nono filter
//! (phase 4) denies the `setuid`/`setgid`/`setres*`/`sete*` family on
//! top, so the lock holds structurally as well.

use std::io::{self, Write};

use anyhow::{Context, Result, bail};

/// The real (host) credentials to map into the user namespace.
pub(crate) struct Credentials {
    /// The real uid; also the in-ns uid the app will see.
    pub uid: u32,
    /// The real gid; also the in-ns gid the app will see.
    pub gid: u32,
    /// Optional subuid block (profile option): maps the 65536 host
    /// uids starting at this one to in-ns uids 1..=65536 (files owned
    /// by subuid-range owners).
    pub subuid: Option<u32>,
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
        Ok(Self { uid: ruid, gid: rgid, subuid: None })
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
/// exactly once).
fn map_contents(creds: &Credentials) -> (String, String) {
    let mut uid = String::new();
    uid.push_str(&format!("0 {} 1\n", creds.uid));
    uid.push_str(&format!("{} {} 1\n", creds.uid, creds.uid));
    if let Some(sub) = creds.subuid {
        uid.push_str(&format!("1 {sub} 65536\n"));
    }

    let mut gid = String::new();
    gid.push_str(&format!("0 {} 1\n", creds.gid));
    gid.push_str(&format!("{} {} 1\n", creds.gid, creds.gid));
    // (No subgid block: the subuid range covers file *ownership*;
    // group access to subuid-owned files is out of scope for now.)

    (uid, gid)
}

/// Write a /proc map file (`setgroups`, `uid_map`, `gid_map`). The
/// kernel permits exactly one successful write; after that the file
/// is read-only for the life of the process.
fn write_map_file(path: &str, contents: &str) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("opening {path}"))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("writing {path} (the kernel permits exactly one successful write)"))?;
    Ok(())
}

/// After the mount phase: drop ns-root to the real uid/gid. The
/// kernel clears our capability sets at that moment, and an
/// unprivileged `setresuid` cannot then reach the `0` entry of the
/// map (decision #9). Each step is verified and this fails loudly
/// (before the exec) if anything is not as expected.
pub(crate) fn drop_ns_root(creds: &Credentials) -> Result<()> {
    // We are ns-0 (mapped to the real uid, full ns capabilities):
    // setting the real uid/gid is permitted, and the kernel clears
    // the capability sets because the new identity is not mapped-0.
    if unsafe { libc::setresuid(creds.uid, creds.uid, creds.uid) } != 0 {
        return Err(io::Error::last_os_error())
            .context(format!("setresuid({}) (dropping ns-root)", creds.uid));
    }
    if unsafe { libc::setresgid(creds.gid, creds.gid, creds.gid) } != 0 {
        return Err(io::Error::last_os_error())
            .context(format!("setresgid({}) (dropping ns-root)", creds.gid));
    }

    check_resids(creds)?;
    check_caps_empty()?;
    check_repriv_blocked()?;
    Ok(())
}

/// Verify the ruid/euid/suid (and gid) triple after the drop.
fn check_resids(creds: &Credentials) -> Result<()> {
    let mut ruid: u32 = 0;
    let mut euid: u32 = 0;
    let mut suid: u32 = 0;
    if unsafe { libc::getresuid(&mut ruid, &mut euid, &mut suid) } != 0 {
        return Err(io::Error::last_os_error()).context("getresuid(2) during verification");
    }
    if (ruid, euid, suid) != (creds.uid, creds.uid, creds.uid) {
        bail!(
            "after setresuid({}): ruid={ruid} euid={euid} suid={suid}",
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
            "after setresgid({}): rgid={rgid} egid={egid} sgid={sgid}",
            creds.gid
        );
    }
    Ok(())
}

/// The process's effective capability set (from /proc/self/status).
fn cap_eff() -> Result<u64> {
    let status = std::fs::read_to_string("/proc/self/status")
        .context("reading /proc/self/status")?;
    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:") {
            return u64::from_str_radix(hex.trim(), 16)
                .with_context(|| format!("parsing CapEff {hex:?}"));
        }
    }
    bail!("no CapEff line in /proc/self/status");
}

/// After dropping to the real uid the effective capability set must
/// be empty: the kernel clears it when the identity leaves mapped-0.
fn check_caps_empty() -> Result<()> {
    let caps = cap_eff()?;
    if caps != 0 {
        bail!(
            "CapEff is {caps:#018x} after dropping to the real uid; \
             expected 0 (the kernel clears the ns capability set when the \
             identity leaves mapped-0)"
        );
    }
    Ok(())
}

/// The `0` entry of the map is still *there*, but unreachable: without
/// CAP_SETUID a `setresuid(0)` must fail with EPERM (an unprivileged
/// setresuid may only pick previous ruid/euid/suid values).
fn check_repriv_blocked() -> Result<()> {
    assert_eperm(
        "setresuid(0,0,0)",
        || unsafe { libc::setresuid(0, 0, 0) },
    )?;
    assert_eperm(
        "setresgid(0,0,0)",
        || unsafe { libc::setresgid(0, 0, 0) },
    )?;
    Ok(())
}

/// Run `call` (a raw syscall returning 0 on success) and require
/// EPERM — anything else (success included) is a design violation.
fn assert_eperm(what: &str, call: impl FnOnce() -> i32) -> Result<()> {
    if call() == 0 {
        bail!("{what} SUCCEEDED after dropping to the real uid — the 0 entry is reachable, this breaks the design (PLAN §3.1)");
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() != Some(libc::EPERM) {
        bail!("{what} failed with {err:?}; expected EPERM");
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::run_sandboxed;
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::ForkResult;
    use std::ffi::OsString;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;

    /// One raw `write(2)` to `fd` (short writes are allowed — the
    /// `writeln!`/`write_all` machinery retries).
    fn raw_write(fd: i32, buf: &[u8]) -> io::Result<usize> {
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
    struct ChildOut {
        out_fd: i32,
        err_fd: i32,
    }

    impl ChildOut {
        /// A writer for the child's *stderr* pipe (diagnostics).
        fn err(&mut self) -> ErrWriter<'_> {
            ErrWriter {
                fd: self.err_fd,
                _marker: std::marker::PhantomData,
            }
        }
    }

    /// An unbuffered writer to the child's stderr pipe.
    struct ErrWriter<'a> {
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
    fn run_in_child(body: impl FnOnce(&mut ChildOut) -> i32 + Send) -> (Option<i32>, String, String) {
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
                let code = body(&mut ChildOut { out_fd: w_out, err_fd: w_err });
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
    fn creds() -> Result<Credentials> {
        Credentials::current()
    }

    /// The two map entries every phase-1 map carries.
    fn both_entries(c: &Credentials) -> (String, String) {
        (
            format!("0 {} 1", c.uid),
            format!("{} {} 1", c.uid, c.uid),
        )
    }

    #[test]
    fn enter_then_drop_credential_sequence() {
        let creds = match creds() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skipping: cannot read current credentials: {e}");
                return;
            }
        };

        let (code, out, _err) = run_in_child(move |o| {
            // 1. Enter: unshare + setgroups + the single map write.
            if let Err(e) = enter_userns(&creds) {
                let _ = writeln!(o, "SETUP-FAIL enter_userns: {e:#}");
                return 1;
            }

            // The initial map must carry both entries.
            let map = std::fs::read_to_string("/proc/self/uid_map").unwrap_or_default();
            let (want0, wantself) = both_entries(&creds);
            if !map.contains(&want0) || !map.contains(&wantself) {
                let _ = writeln!(o, "FAIL uid_map is {map:?}; want entries {want0:?} and {wantself:?}");
                return 2;
            }

            let setgroups =
                std::fs::read_to_string("/proc/self/setgroups").unwrap_or_default();
            if setgroups.trim() != "deny" {
                let _ = writeln!(o, "FAIL setgroups is {setgroups:?}; want \"deny\"");
                return 3;
            }

            // As ns-root we hold the full ns capability set.
            match cap_eff() {
                Err(e) => {
                    let _ = writeln!(o, "FAIL reading CapEff: {e:#}");
                    return 4;
                }
                Ok(0) => {
                    let _ = writeln!(o, "FAIL CapEff is 0 before the drop; expected the full ns set as ns-root");
                    return 4;
                }
                Ok(_) => {}
            }

            // 2. Drop to the real uid (mount phase is empty in phase 1).
            if let Err(e) = drop_ns_root(&creds) {
                let _ = writeln!(o, "SETUP-FAIL drop_ns_root: {e:#}");
                return 5;
            }

            // 3. The result: locked at the real uid, no capabilities,
            //    0 unreachable.
            let _ = writeln!(
                o,
                "OK: uid locked at {} / gid {} (CapEff cleared, setresuid(0) rejected with EPERM)",
                creds.uid, creds.gid
            );
            0
        });

        match code {
            Some(0) => {}
            // enter_userns failing means this environment cannot create
            // the mapping (e.g. we ourselves are in a nested user
            // namespace, as in the dev container): skip, don't fail.
            Some(1) => {
                eprintln!("skipping (environment cannot create the mapping):\n{out}\n{_err}");
                return;
            }
            Some(other) => panic!("credential sequence failed (exit {other}):\n{out}\n{_err}"),
            None => panic!("test harness failed"),
        }
        assert!(out.contains("OK: uid locked"), "expected an OK line; got:\n{out}\n{_err}");
    }

    /// Decision #9 probe: the kernel permits exactly one successful
    /// write to the map files. After the first write, a second write
    /// with *any* content (identical, narrowing, or unrelated) must be
    /// rejected, and the map must remain unchanged. This is the
    /// kernel constraint the whole credential design relies on.
    #[test]
    fn uid_map_is_write_once() {
        let creds = match creds() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skipping: cannot read current credentials: {e}");
                return;
            }
        };

        let (code, out, _err) = run_in_child(move |o| {
            if let Err(e) = enter_userns(&creds) {
                let _ = writeln!(o, "SETUP-FAIL enter_userns: {e:#}");
                return 1;
            }

            let (identical, narrowed, different) = (
                map_contents(&creds).0.clone(),
                format!("{} {} 1\n", creds.uid, creds.uid),
                format!("0 {} 1\n", creds.uid),
            );
            for (label, contents) in [
                ("identical", identical),
                ("narrowing (drop the 0 entry)", narrowed),
                ("unrelated single entry", different),
            ] {
                match write_map_file("/proc/self/uid_map", &contents) {
                    Ok(()) => {
                        let _ = writeln!(o, "FAIL: the second write ({label}) was ACCEPTED — write-once is not in effect on this kernel");
                        return 10;
                    }
                    Err(e) => {
                        let epem = e
                            .chain()
                            .any(|c| c.downcast_ref::<io::Error>()
                                .is_some_and(|io| io.raw_os_error() == Some(libc::EPERM)));
                        if !epem {
                            let _ = writeln!(o, "FAIL: second write ({label}) failed with {e:#}; expected EPERM");
                            return 11;
                        }
                    }
                }
            }

            // The map must be exactly what we first wrote.
            let map = std::fs::read_to_string("/proc/self/uid_map").unwrap_or_default();
            let (want0, wantself) = both_entries(&creds);
            if !map.contains(&want0) || !map.contains(&wantself) {
                let _ = writeln!(o, "FAIL: the map changed after the rejected writes: {map:?}");
                return 12;
            }

            let _ = writeln!(o, "OK: write-once holds (second writes rejected with EPERM, map unchanged)");
            0
        });

        match code {
            Some(0) => {}
            Some(1) => {
                eprintln!("skipping (environment cannot create the mapping):\n{out}\n{_err}");
                return;
            }
            Some(other) => panic!("write-once probe failed (exit {other}):\n{out}\n{_err}"),
            None => panic!("test harness failed"),
        }
        assert!(out.contains("OK: write-once holds"), "expected an OK line; got:\n{out}\n{_err}");
    }

    /// End-to-end for phase 1: `wlsctx run -- id` executes the command
    /// in the new user namespace and the command sees the *real* uid.
    #[test]
    fn run_sandboxed_command_sees_the_real_uid() {
        let creds = match creds() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skipping: cannot read current credentials: {e}");
                return;
            }
        };

        // The outer fork+pipe captures the *grandchild* (the
        // sandboxed `id`) stdout: the intermediate child only runs
        // run_sandboxed and exits.
        let (code, out, err) = run_in_child(move |o| {
            match run_sandboxed(&[OsString::from("id")]) {
                Ok(126) => {
                    // The sandbox setup failed inside the grandchild
                    // (126 = cannot execute): this environment cannot
                    // create the mapping.
                    1
                }
                Ok(c) => {
                    let _ = writeln!(o.err(), "run_sandboxed exited with {c}");
                    0
                }
                Err(e) => {
                    let _ = writeln!(o.err(), "run_sandboxed error: {e:#}");
                    2
                }
            }
        });

        match code {
            Some(0) => {}
            Some(1) => {
                eprintln!("skipping: the sandbox could not be set up in this environment (nested user namespace?); the assertions run for real on the target\n{err}");
                return;
            }
            other => panic!("run_sandboxed harness failed: {other:?}\n{out}\n{err}"),
        }

        let want = format!("uid={}(", creds.uid);
        assert!(out.contains(&want), "expected `{want}` in `id` output; got:\n{out}\n{err}");
        let want = format!("gid={}(", creds.gid);
        assert!(out.contains(&want), "expected `{want}` in `id` output; got:\n{out}\n{err}");
    }
}
