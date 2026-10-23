//! The remaining namespaces (PLAN.md §3.2), entered in order after the
//! user namespace:
//!
//!   A (the intermediate child):  mount → pid
//!   B (the app, PID 1):          ipc → uts → cgroup → net (per mode)
//!
//! All findings below verified on 7.2.11-300.fc45 (Phase 2 probes):
//!
//! * **mount**: `unshare(CLONE_NEWNS)` then
//!   `mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)` makes our view
//!   private so host mount events don't propagate in (and Phase 3
//!   mounts don't propagate out). Works with the ns-local CAP_SYS_ADMIN
//!   from decision #10.
//! * **pid**: `unshare(CLONE_NEWPID)` in `A`; the *next fork* (`B`) is
//!   PID 1 of the new pidns. Teardown (decision #14): when `B` dies the
//!   kernel's `zap_pid_ns_processes()` *does* run — it disables PID
//!   allocation in the ns (a post-death `fork` fails with ENOMEM) — but
//!   the SIGKILL it sends to the remaining members is **not
//!   delivered** on this kernel (probed: strays and non-init members
//!   keep running; strays get reparented across the namespace
//!   boundary). There are therefore no orphans *by our design*: `A`
//!   reaps `B` and exits with `B`'s status immediately (verified: exit
//!   codes and 128+signal propagate reliably through the double fork),
//!   and the kernel frees the ns object when the last member exits.
//! * **ipc / uts**: plain unshares; UTS sets the hostname
//!   `wlsctx-<app>-<instance>` (kernel limit 64 bytes; 65 is EINVAL —
//!   probed).
//! * **cgroup** (decision #12): the cgroup2 *filesystem* is **not**
//!   re-rooted by the cgroup namespace on this kernel — the full tree
//!   stays reachable by full path from inside the ns; only
//!   `/proc/*/cgroup` is namespaced (the view is relative to the ns
//!   root). So the dance is: **capture the full cgroup path before
//!   unsharing** (afterwards `/proc/self/cgroup` reads `0::/`),
//!   unshare (view root = the session cgroup), `mkdir` the sub-cgroup
//!   at the full path, and move into it; the view then reads
//!   `0::/<name>`. Creating a cgroup *directly under the cgroup2 root*
//!   is EPERM for us (that needs init-userns CAP_SYS_ADMIN) — we never
//!   do that; the sub-cgroup always sits under the session scope.
//!   `rmdir` of the (then empty) sub-cgroup is done by the supervisor
//!   after the instance dies (best effort).
//! * **net**: per mode (PLAN §5). `shared` (default): no unshare — the
//!   app keeps the host netns; nono filters it in Phase 4.
//!   `none`: bare new netns with loopback brought up.
//!
//! **Pidns-init signal immunity** (affects Phase 5.4, not this file):
//! a pidns init carries `SIGNAL_UNKILLABLE`, so it *ignores* any
//! default-disposition signal other than `SIGKILL`/`SIGSTOP`
//! (`sig_task_ignored()` + `get_signal()` in kernel/signal.c). Signals
//! it installs handlers for are delivered normally. Shutdown must
//! therefore be TERM (the app handles it) with a KILL fallback.

use std::io::{self, Write};

use anyhow::{Context, Result, bail};

/// Network mode of the sandbox (PLAN §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NetworkMode {
    /// The default: keep the host netns; nono filters it in Phase 4.
    Shared,
    /// A bare new netns with only loopback (up).
    None,
}

/// `wlsctx-<app>-<instance>` — the UTS hostname of the instance.
pub(crate) fn hostname_for(app_id: &str, instance_id: &str) -> String {
    format!("wlsctx-{app_id}-{instance_id}")
}

/// `<app>-<instance>` — the name of the per-instance sub-cgroup
/// (visible inside the cgroup ns as `/app-1` etc.).
pub(crate) fn cgroup_name_for(app_id: &str, instance_id: &str) -> String {
    format!("{app_id}-{instance_id}")
}

/// App and instance IDs feed the hostname (RFC 1123-ish characters)
/// and the cgroup name (path component); anything outside this set
/// would break one of them, so reject it before forking.
pub(crate) fn validate_id(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        bail!(
            "{field} must be non-empty and contain only [A-Za-z0-9._-] \
             (it becomes part of the hostname and cgroup name): {value:?}"
        );
    }
    Ok(())
}

fn unshare(flag: i32, what: &str) -> Result<()> {
    if unsafe { libc::unshare(flag) } != 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("unshare({what}) failed (we are in a fresh user ns with the full ns capability set — check the environment)"));
    }
    Ok(())
}

/// Mount namespace + a private root view (PLAN §3.2). The actual
/// rootfs is built in Phase 3; Phase 2 only claims the namespace.
pub(crate) fn enter_mountns() -> Result<()> {
    unshare(libc::CLONE_NEWNS, "CLONE_NEWNS")?;
    // Make every mount in our view private so propagation stops
    // working in both directions.
    // SAFETY: NULL source/… with a target of "/" and propagation
    // flags only.
    if unsafe {
        libc::mount(
            std::ptr::null(),
            b"/\0".as_ptr().cast(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error())
            .context("mount(NULL, \"/\", MS_REC|MS_PRIVATE) failed (making the view private)");
    }
    Ok(())
}

/// Pid namespace. The *next fork* from the caller becomes PID 1; the
/// caller itself is not. See the module docs for the death semantics
/// (decision #14).
pub(crate) fn enter_pidns() -> Result<()> {
    unshare(libc::CLONE_NEWPID, "CLONE_NEWPID")
}

/// Fresh IPC namespace (private System V + shared-memory view).
pub(crate) fn enter_ipcns() -> Result<()> {
    unshare(libc::CLONE_NEWIPC, "CLONE_NEWIPC")
}

/// UTS namespace + the instance hostname. The kernel limit is 64
/// bytes (65 is EINVAL — probed); the caller is responsible for
/// keeping IDs short enough that `wlsctx-<app>-<instance>` fits.
pub(crate) fn enter_utsns(hostname: &str) -> Result<()> {
    unshare(libc::CLONE_NEWUTS, "CLONE_NEWUTS")?;
    let bytes = hostname.as_bytes();
    if bytes.len() > 64 {
        bail!(
            "hostname {hostname:?} is {len} bytes; the kernel limit is 64 (shorten --app-id/--instance-id)",
            len = bytes.len()
        );
    }
    // SAFETY: `bytes` is valid for its length; length ≤ 64 checked.
    if unsafe { libc::sethostname(bytes.as_ptr().cast(), bytes.len()) } != 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("sethostname({hostname:?}) failed"));
    }
    Ok(())
}

/// The full cgroup v2 path of the calling process, e.g.
/// `/user.slice/user-1000.slice/user@1000.service/app.slice/app-foot.slice/app-foot-5724.scope`.
/// Must be captured **before** unsharing the cgroup namespace (after
/// the unshare, `/proc/self/cgroup` shows the namespaced view `0::/`).
///
/// `pub(crate)` because the supervisor (which never unshares the
/// cgroup namespace) computes the per-instance sub-cgroup path from
/// it to clean it up after the instance dies.
pub(crate) fn full_cgroup_path() -> Result<String> {
    let contents =
        std::fs::read_to_string("/proc/self/cgroup").context("reading /proc/self/cgroup")?;
    for line in contents.lines() {
        // cgroup v2: "0::<path>"
        let Some(hierarchies) = line.strip_prefix("0::") else {
            continue;
        };
        if !hierarchies.is_empty() {
            return Ok(hierarchies.to_string());
        }
    }
    bail!("no cgroup v2 (\"0::\") entry in /proc/self/cgroup: {contents:?}")
}

/// Cgroup namespace: unshare while the process is still in the
/// session cgroup (view root = that cgroup), create the per-instance
/// sub-cgroup under it, and move into it — so the instance's
/// `/proc/self/cgroup` reads a clean, stable `0::<name>`
/// (decision #12).
///
/// Returns the *full* path of the session cgroup.
pub(crate) fn enter_cgroupns(name: &str) -> Result<String> {
    let full = full_cgroup_path()?;
    // The cgroup ns's root is the unsharing task's cgroup **at
    // unshare time**, so the instance sub-cgroup must be created
    // and entered *before* the unshare: the app then sees `0::`
    // (its own cgroup is the ns root) and can never see the session
    // tree or sibling instances (decision #20). The cgroup2
    // filesystem is not re-rooted by the namespace on this kernel,
    // so the sub-cgroup is reachable by its full path (Phase 2).
    let sub = format!("/sys/fs/cgroup{full}/{name}");
    match std::fs::create_dir(&sub) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => {
            return Err(e).with_context(|| {
                format!(
                    "creating the sub-cgroup {sub} failed (the session cgroup must be \
                     user-owned and writable — e.g. a systemd user-slice scope)"
                )
            });
        }
    }

    // Move ourselves in: the forked app inherits the membership.
    let procs = format!("{sub}/cgroup.procs");
    let mut f =
        std::fs::OpenOptions::new().write(true).open(&procs).with_context(|| {
            format!(
                "opening {procs} for writing (requires CAP_SYS_ADMIN in our user ns \
                 over the user-owned scope)"
            )
        })?;
    f.write_all(format!("{}\n", std::process::id()).as_bytes())
        .with_context(|| format!("moving into {procs}"))?;
    unshare(libc::CLONE_NEWCGROUP, "CLONE_NEWCGROUP")?;
    Ok(full)
}

/// Network namespace, `--network=none` mode: a bare netns with
/// loopback up. `Shared` mode never unshares.
pub(crate) fn enter_netns() -> Result<()> {
    unshare(libc::CLONE_NEWNET, "CLONE_NEWNET")?;

    // Bring loopback up (it exists but is down in a fresh netns).
    let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if s < 0 {
        return Err(io::Error::last_os_error()).context("socket(AF_INET, SOCK_DGRAM)");
    }
    // SAFETY: stack ifreq filled below; lifetimes local.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in "lo".bytes().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    if unsafe { libc::ioctl(s, libc::SIOCGIFFLAGS as _, &mut ifr) } != 0 {
        unsafe { libc::close(s) };
        return Err(io::Error::last_os_error()).context("SIOCGIFFLAGS(\"lo\")");
    }
    // SAFETY: the SIOCGIFFLAGS ioctl above just wrote the union
    // member (and it was zeroed before), so the flags field holds
    // valid data.
    unsafe {
        ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as i16;
    }
    if unsafe { libc::ioctl(s, libc::SIOCSIFFLAGS as _, &mut ifr) } != 0 {
        unsafe { libc::close(s) };
        return Err(io::Error::last_os_error()).context("SIOCSIFFLAGS(\"lo\", IFF_UP)");
    }
    unsafe { libc::close(s) };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::run_sandboxed;
    use std::os::unix::fs::MetadataExt;
    use crate::sandbox::userns::tests::{
        run_in_child, enter_or_classify, creds, ChildOut,
    };
    use crate::sandbox::SandboxConfig;
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::io::Write;

    fn cfg(app: &str, inst: &str, net: NetworkMode) -> SandboxConfig {
        SandboxConfig {
            app_id: app.to_string(),
            instance_id: inst.to_string(),
            network: net,
            // Phase 2 tests run without the GPU: the precheck and the
            // `/dev/dri` build are skipped.
            gpu: false,
            profile: crate::profile::Profile::adhoc(),
            wayland: None,
        }
    }

    /// The outer (test-process) value of a `/proc/self/ns/<kind>`
    /// symlink.
    fn outer_ns(kind: &str) -> String {
        std::fs::read_link(format!("/proc/self/ns/{kind}"))
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// Run a command through `run_sandboxed` from inside a forked
    /// capture child (the multithreaded test process itself never
    /// enters a namespace).
    fn run_cmd(command: &[&str], config: &SandboxConfig) -> (Option<i32>, String, String) {
        let _lock = crate::testutil::SANDBOX_LOCK
            .lock()
            .unwrap_or_else(|e| panic!("SANDBOX_LOCK poisoned: {e}"));
        let command: Vec<OsString> = command.iter().map(OsString::from).collect();
        let config = config.clone();
        run_in_child(move |o: &mut ChildOut| match run_sandboxed(&command, &config) {
            Ok(code) => code,
            Err(e) => {
                let _ = writeln!(o.err(), "run_sandboxed: {e:#}");
                2
            }
        })
    }

    /// True when the failure is "the environment cannot create the
    /// namespaces" (the test must `return`); panics when the kernel
    /// rejected our map (a design failure, never a skip).
    fn skip_if_unsupported(err: &str) -> bool {
        if err.contains("uid_map") || err.contains("gid_map") {
            panic!("the kernel rejected the single-extent map (design failure, not an environment skip):\n{err}");
        }
        if err.contains("rootfs construction failed") || err.contains("sandbox setup failed") {
            panic!("a setup step failed inside the namespaces (a real failure, not an environment skip):\n{err}");
        }
        eprintln!("skipping (environment cannot create the namespaces):\n{err}");
        true
    }

    /// Classify a `run_cmd` result whose command must have exited 0:
    /// Ok = it did (assert on `out` next); Err = environment skip.
    fn expect(code: Option<i32>, out: &str, err: &str, what: &str) -> Result<(), &'static str> {
        match code {
            Some(0) => Ok(()),
            Some(126) => Err(if skip_if_unsupported(err) {
                "environment"
            } else {
                unreachable!()
            }),
            Some(other) => panic!("{what} failed (exit {other}, expected 0):\n{out}\n{err}"),
            None => panic!("test harness failed"),
        }
    }

    /// The optional fields (propagation group, …) of the `/` entry.
    fn root_optional_fields(mountinfo: &str) -> String {
        mountinfo
            .lines()
            .find(|l| l.split_whitespace().nth(4) == Some("/"))
            .map(|l| {
                l.split(" - ")
                    .next()
                    .unwrap_or_default()
                    .split_whitespace()
                    .skip(5)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default()
    }

    #[test]
    fn mount_ns_makes_the_view_private() {
        // Precondition: the host's `/` must show its propagation
        // group (`shared:`) — that is the signal the assertion
        // below discriminates on. (systemd's host `/` is `shared:1`
        // on Fedora; a hard fail here means this environment
        // changed and the test needs adjusting, not skipping.)
        let host_mountinfo =
            std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        let host_optional = root_optional_fields(&host_mountinfo);
        if !host_optional.contains("shared") {
            panic!("precondition: the host's `/` is not a shared mount (no `shared:` token, optional fields: {host_optional:?}); the private-view assertion cannot discriminate");
        }

        let (code, out, err) = run_in_child(|o| {
            let creds = match creds() {
                Ok(c) => c,
                Err(e) => {
                    let _ = writeln!(o, "NS-FAIL: {e:#}");
                    return 1;
                }
            };
            let rc = enter_or_classify(o, &creds);
            if rc != 0 {
                return rc;
            }
            if let Err(e) = enter_mountns() {
                let _ = writeln!(o, "FAIL enter_mountns: {e:#}");
                return 2;
            }
            // The root entry of our mountinfo: the optional fields
            // (between the mountpoint and " - ") must carry no
            // propagation token. On this kernel `private` is the
            // default and is *omitted* — a token only appears for
            // shared:/slave/unbindable (probed: a fresh mount ns
            // and an explicit MS_REC|MS_PRIVATE both print no token,
            // while the host's `/` prints `shared:1`).
            let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
            let root = mountinfo
                .lines()
                .find(|l| l.split_whitespace().nth(4) == Some("/"))
                .unwrap_or_default();
            let optional = root_optional_fields(&mountinfo);
            if root.is_empty() || optional.contains("shared") || optional.contains("slave") {
                let _ = writeln!(
                    o,
                    "FAIL root mount still propagates (optional fields: {optional:?}): {root:?}"
                );
                return 3;
            }
            // And a tmpfs mount works with our ns-local CAP_SYS_ADMIN.
            let dir = std::env::temp_dir().join(format!("wlsctx-priv-{}", std::process::id()));
            if let Err(e) = std::fs::create_dir_all(&dir) {
                let _ = writeln!(o, "FAIL creating the mount target dir {dir:?}: {e}");
                return 4;
            }
            // The mount target must be a NUL-terminated C string: a
            // Rust &str buffer has no trailing NUL, and mount() would
            // over-read it. (The "mount ENOENT flake" chased during
            // Phase 2 was exactly that: a non-terminated pointer whose
            // over-read occasionally produced a garbage-suffixed path
            // that no longer named the dir — sticky per allocation,
            // invisible to stat(), and easily mistaken for a kernel
            // lookup race. v7.2's dcache/namei were examined and are
            // not at fault.)
            let pre = std::fs::metadata(&dir);
            let pre_s = pre
                .as_ref()
                .map(|s| format!("ok (ino {})", s.ino()))
                .unwrap_or_else(|e| format!("GONE: {e}"));
            let dir_c = format!("{}\0", dir.to_str().unwrap());
            let st = unsafe {
                libc::mount(
                    b"tmpfs\0".as_ptr().cast(),
                    dir_c.as_ptr().cast::<libc::c_char>(),
                    b"tmpfs\0".as_ptr().cast(),
                    0,
                    std::ptr::null(),
                )
            };
            if st != 0 {
                let e = io::Error::last_os_error();
                let post = std::fs::metadata(&dir);
                let parent = std::fs::metadata(std::env::temp_dir());
                let mut mi = String::new();
                for line in std::fs::read_to_string("/proc/self/mountinfo")
                    .unwrap_or_default()
                    .lines()
                {
                    if line.contains(" /tmp ") || line.contains(" /tmp\t") {
                        mi = line.to_string();
                    }
                }
                let _ = writeln!(
                    o,
                    "FAIL mounting tmpfs in the private view: {e}; pre-mount stat: {pre_s}; post-mount stat dir: {}; parent {:?}: {}; /tmp line: {mi}",
                    post
                        .as_ref()
                        .map(|s| format!("ok (ino {})", s.ino()))
                        .unwrap_or_else(|e| format!("GONE: {e}")),
                    std::env::temp_dir(),
                    parent
                        .as_ref()
                        .map(|s| format!("ok (ino {})", s.ino()))
                        .unwrap_or_else(|e| format!("GONE: {e}"))
                );
                return 4;
            }
            let _ = unsafe { libc::umount(dir_c.as_ptr().cast::<libc::c_char>()) };
            let _ = std::fs::remove_dir_all(&dir);
            let _ = writeln!(o, "OK: view private, tmpfs mount works");
            0
        });
        match code {
            Some(0) => {}
            Some(1) => {
                eprintln!("skipping (environment cannot create the namespaces):\n{out}\n{err}");
                return;
            }
            Some(20) => panic!("kernel rejected the map (design failure):\n{out}\n{err}"),
            Some(other) => panic!("mount ns test failed (exit {other}):\n{out}\n{err}"),
            None => panic!("test harness failed"),
        }
        assert!(out.contains("OK: view private"), "{out}\n{err}");
    }

    #[test]
    fn app_is_pid_1_and_exit_codes_propagate() {
        // The shape that matters for real use: the app is PID 1 of
        // its pidns, and its exit code survives *both* forks to the
        // caller of `run_sandboxed`.
        let (code, out, err) = run_cmd(
            &["/bin/sh", "-c", "echo pid=$$; exit 42"],
            &cfg("app", "1", NetworkMode::Shared),
        );
        match code {
            Some(126) => {
                if skip_if_unsupported(&err) {
                    return;
                }
            }
            Some(42) => {}
            Some(other) => panic!("pid ns propagation failed (exit {other}, expected 42):\n{out}\n{err}"),
            None => panic!("test harness failed"),
        }
        assert!(
            out.contains("pid=1"),
            "the app must be PID 1 of its pidns; got:\n{out}\n{err}"
        );
    }

    /// The `(comm)` field of a `/proc/<pid>/stat` line.
    fn comm_of(stat: &str) -> &str {
        let open = stat.find('(').unwrap_or(0);
        let close = stat.rfind(')').unwrap_or(open);
        stat[open + 1..close].trim_matches(' ')
    }

    /// The `sleep` process that is a live descendant of `root`
    /// (breadth-first walk over `/proc` parent links — the test
    /// binary's S → A → B chain), or none.
    fn find_sleep_descendant(root: i32) -> Option<i32> {
        let mut children: BTreeMap<i32, Vec<i32>> = BTreeMap::new();
        for entry in std::fs::read_dir("/proc").ok()?.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
                continue;
            };
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
                continue;
            };
            // Fields after the last ')': state ppid ...
            let Some(ppid) = stat.rfind(')')
                .map(|c| stat[c + 1..].split_whitespace().nth(1).unwrap_or_default())
                .and_then(|t| t.parse::<i32>().ok())
            else {
                continue;
            };
            children.entry(ppid).or_default().push(pid);
        }
        let mut queue = vec![root];
        while let Some(p) = queue.pop() {
            for &k in children.get(&p).into_iter().flatten() {
                match std::fs::read_to_string(format!("/proc/{k}/stat")) {
                    Ok(stat) if comm_of(&stat) == "sleep" => return Some(k),
                    Ok(_) => queue.push(k),
                    Err(_) => {} // vanished between the listing and the read
                }
            }
        }
        None
    }

    #[test]
    fn killing_the_app_takes_down_the_whole_ns() {
        let _lock = crate::testutil::SANDBOX_LOCK
            .lock()
            .unwrap_or_else(|e| panic!("SANDBOX_LOCK poisoned: {e}"));
        // Decision #14: the kernel's pidns teardown does NOT kill
        // surviving members on this kernel, so the "no orphans"
        // guarantee is ours to build: when the app (PID 1) dies, the
        // intermediate child `A` must reap it and exit with its status
        // (137 for a SIGKILL), and nothing may be left behind.
        //
        // The killer runs in the **parent** (test) process, not inside
        // the forked child: a thread inside the child would make the
        // second fork (A) happen from a multithreaded process, which
        // deadlocks on a lock held by a now-dead thread (a futex
        // wait that never resolves). The parent is already
        // multithreaded, so a thread here is safe; the child stays
        // single-threaded like every other sandbox test.
        let command = vec![OsString::from("/usr/bin/sleep"), OsString::from("60")];
        let config = cfg("app", "1", NetworkMode::Shared);
        let (tx, rx) = std::sync::mpsc::channel::<i32>();
        let killer = std::thread::spawn(move || {
            let root = std::process::id() as i32;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            while std::time::Instant::now() < deadline {
                if let Some(b) = find_sleep_descendant(root) {
                    let _ = tx.send(b);
                    eprintln!("killing B (pid {b}, in-ns PID 1) with SIGKILL");
                    unsafe { libc::kill(b, libc::SIGKILL) };
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        });

        let (code, out, err) = run_in_child(move |o: &mut ChildOut| {
            match run_sandboxed(&command, &config) {
                Ok(c) => {
                    let _ = writeln!(o, "status={c}");
                    0
                }
                Err(e) => {
                    let _ = writeln!(o.err(), "run_sandboxed: {e:#}");
                    2
                }
            }
        });
        let _ = killer.join();
        let b_pid = rx.recv().unwrap_or(-1);
        match code {
            Some(0) => {
                assert!(
                    out.contains("status=137"),
                    "the app must die of the SIGKILL and A must carry 137 to the supervisor:\n{out}\n{err}"
                );
                assert!(
                    b_pid > 0 && std::fs::read_to_string(format!("/proc/{b_pid}/stat")).is_err(),
                    "B (pid {b_pid}) must be gone after the SIGKILL"
                );
            }
            Some(126) => {
                if skip_if_unsupported(&err) {
                    return;
                }
            }
            Some(other) => panic!("killing test failed (exit {other}):\n{out}\n{err}"),
            None => panic!("test harness failed"),
        }
        // No stray may survive: the only descendants of the capture
        // child were A (exited) and B (SIGKILLed) — both are gone, so
        // the test process has no `sleep` descendants of its own.
        let strays = std::fs::read_to_string(format!(
            "/proc/{}/task/{}/children",
            std::process::id(),
            std::process::id()
        ))
        .map(|s| {
            s.split_whitespace()
                .filter_map(|t| t.parse::<u32>().ok())
                .filter(|p| {
                    std::fs::read_to_string(format!("/proc/{p}/comm"))
                        .map(|c| c.trim() == "sleep")
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0);
        assert_eq!(strays, 0, "a `sleep` process survived the namespace teardown");
    }

    #[test]
    fn ipc_ns_is_fresh() {
        let (code, out, err) = run_cmd(
            &["/bin/sh", "-c", "readlink /proc/self/ns/ipc"],
            &cfg("app", "1", NetworkMode::Shared),
        );
        if expect(code, &out, &err, "ipc ns").is_err() {
            return;
        }
        let inner = out.trim();
        // Kernel format: `ipc:[<inum>]` (the kind is *before* the brackets).
        assert!(inner.starts_with("ipc:["), "inner ns identity; got {inner:?}");
        assert_ne!(inner, &outer_ns("ipc"), "the ipc ns must differ from the host's");
    }

    #[test]
    fn uts_ns_sets_the_instance_hostname() {
        let (code, out, err) = run_cmd(
            &["/bin/sh", "-c", "uname -n"],
            &cfg("rustrover", "work", NetworkMode::Shared),
        );
        if expect(code, &out, &err, "uts ns").is_err() {
            return;
        }
        assert_eq!(out.trim(), "wlsctx-rustrover-work", "got:\n{out}\n{err}");
    }

    #[test]
    fn cgroup_ns_shows_a_clean_view() {
        let (code, out, err) = run_cmd(
            &["/bin/sh", "-c", "cat /proc/self/cgroup"],
            &cfg("app", "7", NetworkMode::Shared),
        );
        if expect(code, &out, &err, "cgroup ns").is_err() {
            return;
        }
        // The instance cgroup is the ns root (moved in before the
        // unshare, decision #20): 7.2 renders the ns root as "/".
        assert_eq!(out.trim(), "0::/", "got:\n{out}\n{err}");
        // And the outside world still sees the session's full path.
        let outer = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
        assert!(outer.starts_with("0::/"), "outer view must be the full path: {outer:?}");
    }

    /// The interface list of the *reader's* netns, from
    /// `/proc/net/dev` (a per-reader namespaced view). `/sys/class/net`
    /// must not be used for this: it is the global sysfs tree and
    /// lists interfaces of *all* netns (probed on this kernel).
    fn net_dev_interfaces() -> Vec<String> {
        std::fs::read_to_string("/proc/net/dev")
            .map(|s| {
                s.lines()
                    .skip(2)
                    .filter_map(|l| l.split(':').next())
                    .map(str::trim)
                    .filter(|n| !n.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn network_none_gives_a_bare_ns_with_loopback_up() {
        let (code, out, err) = run_cmd(
            &[
                "/bin/sh",
                "-c",
                "readlink /proc/self/ns/net; awk 'NR>2 {print $1}' /proc/net/dev; ip -o link show lo",
            ],
            &cfg("app", "1", NetworkMode::None),
        );
        if expect(code, &out, &err, "net ns (none)").is_err() {
            return;
        }
        // Line 1: the netns identity; line 2: the only interface the
        // ns holds (`lo:`); line 3: loopback state from netlink
        // (`ip` is namespaced, `/sys` is not).
        let mut lines = out.lines();
        let inner_ns = lines.next().unwrap_or_default();
        let inner_ifs = lines.next().unwrap_or_default();
        let lo_line = lines.next().unwrap_or_default();
        assert_ne!(inner_ns, &outer_ns("net"), "the net ns must be fresh; got {inner_ns:?}");
        assert_eq!(inner_ifs, "lo:", "the bare ns must hold only loopback; got:\n{out}\n{err}");
        assert!(
            lo_line.starts_with("1: lo:") && lo_line.contains("LOOPBACK,UP"),
            "loopback must be up in the fresh netns; got: {lo_line:?}"
        );
    }

    #[test]
    fn network_shared_keeps_the_host_ns() {
        let (code, out, err) = run_cmd(
            &[
                "/bin/sh",
                "-c",
                "readlink /proc/self/ns/net; awk 'NR>2 {print $1}' /proc/net/dev",
            ],
            &cfg("app", "1", NetworkMode::Shared),
        );
        if expect(code, &out, &err, "net ns (shared)").is_err() {
            return;
        }
        let mut lines = out.trim().lines();
        let inner_ns = lines.next().unwrap_or_default();
        assert_eq!(inner_ns, &outer_ns("net"), "shared mode must keep the host netns");
        let inner_ifs: Vec<String> =
            lines.map(|l| l.trim().trim_end_matches(':').to_string()).collect();
        assert_eq!(
            inner_ifs,
            net_dev_interfaces(),
            "shared mode must see the host interfaces (per-reader /proc/net/dev)"
        );
        assert!(
            !inner_ifs.is_empty(),
            "the host netns is unexpectedly empty; got:\n{out}\n{err}"
        );
    }

    #[test]
    fn the_full_ns_set_is_fresh() {
        // The 2.6 reference check, self-contained: every namespaced
        // identity except the (deliberately) shared net ns must differ
        // from the host's. (Note: on this kernel the mount namespace
        // symlink is named `mnt`, not `mount`.)
        let (code, out, err) = run_cmd(
            &[
                "/bin/sh",
                "-c",
                "for n in user mnt pid ipc uts cgroup net; do readlink /proc/self/ns/$n; done",
            ],
            &cfg("app", "1", NetworkMode::Shared),
        );
        if expect(code, &out, &err, "full ns set").is_err() {
            return;
        }
        let kinds = ["user", "mnt", "pid", "ipc", "uts", "cgroup", "net"];
        let inner: Vec<&str> = out.lines().collect();
        assert_eq!(inner.len(), 7, "got: {out:?}");
        for (kind, line) in kinds.iter().zip(&inner) {
            if *kind == "net" {
                assert_eq!(*line, &outer_ns("net"), "net ns must stay shared");
            } else {
                assert_ne!(
                    *line,
                    &outer_ns(kind),
                    "{kind} ns must differ from the host's; inner={line:?} outer={:?}",
                    outer_ns(kind)
                );
            }
        }
    }
}
