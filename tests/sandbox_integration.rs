//! Phase 8.4 — the in-process sandbox, integration-tested end to
//! end through the real `wlsctx run` subcommand (the built binary,
//! spawned as a subprocess) with a small python3 probe as the app.
//! The probe prints structured `KEY=VALUE` lines from inside the
//! sandbox; the tests assert on them:
//!
//! * **identity** — non-root uid (locked: `setuid(0)` fails), the
//!   single-extent `uid_map`, PID 1 of its own pid namespace, the
//!   cgroup-namespace root `0::/`, the `wlsctx-<app>-<instance>`
//!   hostname;
//! * **the rebuilt rootfs** — fresh `/dev` (only the standard
//!   nodes), fresh `/sys` (`/sys/fs` empty), fresh `/run` (only the
//!   per-instance tree), fresh `/tmp`, a namespaced `/proc`;
//! * **the Landlock floor** — writes denied outside the granted
//!   subtrees (the user-owned but ungranted `/run/user/<uid>`
//!   root) and allowed inside them (the instance dir, `/tmp`),
//!   read-granted paths unwritable; the seccomp filter active
//!   (`PR_GET_SECCOMP` reports the filter mode);
//! * **the network** — `shared` keeps the host netns (a host-side
//!   listener is reachable through loopback); `--network=none`
//!   denies `bind`/`connect` (even on loopback) and its netns
//!   holds only loopback;
//! * **the tagged Wayland socket** — the app sees only the tagged
//!   socket (`WAYLAND_DISPLAY` points at it, it is the only socket
//!   in the instance dir) and connects through it; after the run
//!   the socket is no longer served. Skipped without a running
//!   wlroots compositor;
//! * **lifecycle** — `READY=1` sd-notify when the app is up;
//!   SIGTERM forwarded to a handling app (clean exit 0), and
//!   escalated to SIGKILL two seconds later for one that ignores
//!   it (exit 137).
//!
//! Everything runs as a regular user (unprivileged user + mount +
//! pid + cgroup + ipc + uts + net namespaces, the single-extent
//! map, the Landlock floor, the seccomp-notify filter). An
//! environment that cannot create a user namespace skips the suite
//! (the run fails before the fork with a diagnostic naming the
//! failed `unshare`); an environment without `/usr/bin/python3`
//! skips it too.

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const PYTHON: &str = "/usr/bin/python3";
/// The app id of every run below (no profile TOML or built-in
/// exists for it, so each run gets the ad-hoc default profile).
const APP: &str = "itest";

/// The probe's view of the per-instance dir name
/// (`<app>-<instance>`), handed over as an env var.
fn instance_name(inst: &str) -> String {
    format!("{APP}-{inst}")
}

fn host_uid() -> u32 {
    nix::unistd::getuid().as_raw()
}

/// The session `$XDG_RUNTIME_DIR`, which the product (and this
/// suite) require to be the systemd-standard `/run/user/<uid>`
/// (decision #28): the supervisor builds its capability set against
/// the *in-sandbox* instance-dir path, which only exists on the
/// host when the host's XDG is that same path, and
/// `run --wayland` reaches the upstream compositor's socket through
/// the session XDG. A divergent XDG (e.g. a test harness redirecting
/// it) silently disables the supervisor (trapped syscalls then die
/// with ENOSYS) and breaks the upstream connection, so the suite
/// skips rather than asserts there.
fn session_xdg() -> Option<PathBuf> {
    let uid = host_uid();
    let std_path = PathBuf::from(format!("/run/user/{uid}"));
    let xdg = PathBuf::from(std::env::var("XDG_RUNTIME_DIR").unwrap_or_default());
    if xdg == std_path {
        Some(xdg)
    } else {
        eprintln!(
            "skipping (the session XDG {xdg:?} is not the systemd-standard \
             {std_path:?} the in-sandbox path translation (decision #28) \
             assumes)"
        );
        None
    }
}

/// The per-instance runtime directory as it lives **on the host**
/// (`$XDG/wlsctx/<app>-<instance>`).
fn host_instance_dir(inst: &str) -> Option<PathBuf> {
    Some(session_xdg()?.join("wlsctx").join(instance_name(inst)))
}

/// Remove a host instance directory — pre-run hermeticity (a fresh
/// per-instance tree, no stale socket or state from a previous run)
/// and post-run tidiness. A missing or half-removed directory is
/// not an error.
fn clean_instance(inst: &str) {
    if let Some(p) = host_instance_dir(inst) {
        let _ = std::fs::remove_dir_all(&p);
    }
}

/// The probe: in-ns identity.
const IDENTITY: &str = r#"
import os, socket
print("UID=%d" % os.getuid())
print("EUID=%d" % os.geteuid())
print("PID=%d" % os.getpid())
try:
    print("CGROUP=" + open("/proc/self/cgroup").read().strip())
except Exception as e:
    print("CGROUP_ERR=%r" % (e,))
print("HOSTNAME=" + socket.gethostname())
try:
    os.setuid(0)
    print("SETUID0=OK-BAD")
except OSError as e:
    print("SETUID0=ERR:%d" % e.errno)
print("UIDMAP=" + open("/proc/self/uid_map").read().strip())
"#;

/// The probe: the rebuilt rootfs. For each mountpoint the *last*
/// match in `/proc/mounts` is the topmost mount (the recursive
/// self-bind leaves the host's `/dev`/`/sys` shadows under the
/// fresh ones in the stack).
const ROOTFS: &str = r#"
import os, glob
def fstype(mp):
    r = None
    for l in open("/proc/mounts"):
        p = l.split()
        if len(p) >= 3 and p[1] == mp:
            r = p[2]
    return r or "ABSENT"
for k, mp in [("MT_DEV","/dev"),("MT_SYS","/sys"),("MT_RUN","/run"),
              ("MT_TMP","/tmp"),("MT_PROC","/proc")]:
    print(k + "=" + fstype(mp))
print("DEV_NODES=" + "|".join(sorted(os.path.basename(x) for x in glob.glob("/dev/*"))))
print("SYS_FS=" + "|".join(sorted(os.listdir("/sys/fs"))))
print("SYS_NET=" + "|" .join(sorted(os.listdir("/sys/class/net"))))
ru = "/run/user/%d" % os.getuid()
print("RUN_USER=" + "|".join(sorted(os.listdir(ru))))
inst = ru + "/wlsctx/" + os.environ["WLSCTX_TEST_INST"]
print("RUN_INST=" + ("DIR" if os.path.isdir(inst) else "ABSENT"))
"#;

/// The probe: the Landlock floor and the seccomp filter.
/// `PR_GET_SECCOMP` (21) reports 2 when a BPF filter is installed.
const LANDLOCK: &str = r#"
import os, ctypes
libc = ctypes.CDLL("libc.so.6", use_errno=True)
print("SECCOMP_MODE=%d" % libc.prctl(21, 0, 0, 0, 0))
ru = "/run/user/%d" % os.getuid()
inst = ru + "/wlsctx/" + os.environ["WLSCTX_TEST_INST"]
def attempt(tag, path):
    try:
        open(path, "w").close()
        print(tag + "=OK")
    except OSError as e:
        print(tag + "=ERR:%d" % e.errno)
# user-owned (DAC-writable) but not in the capability set: a pure
# Landlock write-deny target
attempt("RUNUSER_WRITE", ru + "/wlsctx-probe-deny")
# granted subtrees
attempt("INST_WRITE", inst + "/probe-ok")
attempt("TMP_WRITE", "/tmp/wlsctx-probe-tmp")
# read-granted, not write-granted
attempt("ETC_WRITE", "/etc/wlsctx-probe-deny")
"#;

/// The probe: the shared netns reaches a host-side listener. `IFACES`
/// comes from `/proc/net/dev` (the namespaced view) — `/sys/class/net`
/// is a host sysfs bind and would show the host's devices either way.
const NET_SHARED: &str = r#"
import os, socket
port = int(os.environ["PROBE_PORT"])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(("127.0.0.1", port))
    s.sendall(b"ping")
    print("HOSTLISTEN=" + repr(s.recv(4)))
except OSError as e:
    print("HOSTLISTEN=ERR:%d" % e.errno)
finally:
    s.close()
print("IFACES=" + "|".join(sorted(l.split(":")[0].strip() for l in open("/proc/net/dev").readlines()[2:] if l.strip())))
"#;

/// The probe: `--network=none` denies every real communication; the
/// `IFACES` from `/proc/net/dev` must hold only loopback (the bare
/// netns is the second, kernel-level layer under the seccomp block).
const NET_NONE: &str = r#"
import os, socket
port = int(os.environ["PROBE_PORT"])
for tag, addr in [("BIND", ("127.0.0.1", 0)),
                  ("CONNECT", ("127.0.0.1", port))]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        if tag == "BIND":
            s.bind(addr)
        else:
            s.connect(addr)
        print(tag + "=OK-BAD")
    except OSError as e:
        print(tag + "=ERR:%d" % e.errno)
    finally:
        s.close()
print("IFACES=" + "|".join(sorted(l.split(":")[0].strip() for l in open("/proc/net/dev").readlines()[2:] if l.strip())))
"#;

/// The probe: the tagged Wayland socket.
const WAYLAND_PROBE: &str = r#"
import os, socket, stat
wd = os.environ.get("WAYLAND_DISPLAY", "")
xdg = os.environ.get("XDG_RUNTIME_DIR", "")
print("WD=" + wd)
print("XDG=" + xdg)
p = os.path.join(xdg, wd)
print("FILE=" + ("SOCK" if stat.S_ISSOCK(os.lstat(p).st_mode) else "NO"))
print("RUNDIR_SOCKETS=" + "|".join(sorted(os.listdir(os.path.dirname(p)))))
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect(p)
    print("CONNECT=OK")
except OSError as e:
    print("CONNECT=ERR:%d" % e.errno)
finally:
    s.close()
"#;

/// The lifecycle app: handles SIGTERM (a handler runs even for
/// pid-namespace init; only the *default action* is ignored).
const TERM_APP: &str = r#"
import signal, sys, time
def h(sig, frm):
    print("GOT-TERM", flush=True)
    sys.exit(0)
signal.signal(signal.SIGTERM, h)
print("UP", flush=True)
time.sleep(60)
"#;

/// The lifecycle app: no SIGTERM handler (as pid-namespace init it
/// ignores the default action, so only the escalation kills it).
const SLEEP_APP: &str = r#"
import time
print("UP", flush=True)
time.sleep(60)
"#;

/// A finished probe run. The per-instance dir is left in place
/// (`$XDG/wlsctx/<app>-<inst>`) so a test can inspect it after the
/// run; each test cleans it up at the end.
struct ProbeRun {
    code: i32,
    out: String,
    err: String,
}

/// Run `wlsctx run --app-id itest --instance-id <inst> <extra> --
/// /usr/bin/python3 -c <script>` to completion (30 s deadline),
/// against the (systemd-standard) session `$XDG_RUNTIME_DIR`: the
/// per-instance dir is removed first, so every run starts from a
/// fresh one. Returns `None` when the test should skip (no python3,
/// a non-standard session XDG, or the environment cannot create a
/// user namespace — the run then fails before the fork with a
/// diagnostic naming the failed `unshare`); a non-zero exit is
/// returned as-is for the test to judge.
fn run_probe(
    inst: &str,
    extra_args: &[&str],
    extra_env: &[(&str, &str)],
    script: &str,
) -> Option<ProbeRun> {
    if !Path::new(PYTHON).exists() {
        eprintln!("skipping ({PYTHON} is not present in this environment)");
        return None;
    }
    let xdg = session_xdg()?;
    clean_instance(inst);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wlsctx"));
    cmd.arg("run");
    cmd.args(["--app-id", APP, "--instance-id", inst]);
    for a in extra_args {
        cmd.arg(a);
    }
    cmd.args(["--", PYTHON, "-c", script]);
    cmd.env("XDG_RUNTIME_DIR", &xdg);
    cmd.env("WLSCTX_TEST_INST", instance_name(inst));
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    // Its own process group: a timed-out run is killed as a group
    // (the whole S->A->B tree; the supervisor blocks TERM, but
    // SIGKILL cannot be blocked).
    cmd.process_group(0);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("skipping (could not spawn the wlsctx binary: {e})");
            return None;
        }
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {
                if Instant::now() > deadline {
                    let pid = child.id() as i32;
                    // SAFETY: the child's pid is a valid pid_t and,
                    // being its own process-group leader, names the
                    // group we created.
                    unsafe { libc::killpg(pid, libc::SIGKILL) };
                    let _ = child.wait();
                    panic!("the sandbox run timed out after 30 s and was killed as a group");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("waiting on the wlsctx run failed: {e}"),
        }
    };
    let mut out = String::new();
    let mut err = String::new();
    if let Some(mut so) = child.stdout.take() {
        let _ = so.read_to_string(&mut out);
    }
    if let Some(mut se) = child.stderr.take() {
        let _ = se.read_to_string(&mut err);
    }
    if !status.success() && err.contains("unshare(") {
        eprintln!("skipping (environment cannot create a user namespace):\n{err}");
        return None;
    }
    Some(ProbeRun {
        code: status.code().unwrap_or(-1),
        out,
        err,
    })
}

/// Expect a successful probe run (the skip reasons were already
/// printed); panic with the child's output on any other failure.
fn expect_ok(r: Option<ProbeRun>, what: &str) -> ProbeRun {
    let run = r.expect("the probe was skipped (see the skip reason above)");
    assert_eq!(
        run.code, 0,
        "{what}: the run exited {}:
{}
{}",
        run.code, run.out, run.err
    );
    run
}

/// A `KEY=VALUE` line of a probe's output.
fn kv<'a>(out: &'a str, key: &str) -> Option<&'a str> {
    out.lines().find_map(|l| {
        l.split_once('=')
            .filter(|(k, _)| *k == key)
            .map(|(_, v)| v.trim())
    })
}

#[test]
fn identity_is_namespaced() {
    let run = expect_ok(run_probe("it-id", &[], &[], IDENTITY), "the identity probe");
    let uid = host_uid();
    assert_ne!(
        uid, 0,
        "this suite is the unprivileged design and runs as a regular user"
    );
    let want = uid.to_string();
    assert_eq!(
        kv(&run.out, "UID"),
        Some(want.as_str()),
        "the in-ns uid is not the real uid (the single-extent self-map):\n{}",
        run.out
    );
    assert_eq!(
        kv(&run.out, "EUID"),
        Some(want.as_str()),
        "the in-ns euid is not the real uid:\n{}",
        run.out
    );
    assert_eq!(
        kv(&run.out, "PID"),
        Some("1"),
        "the app is not PID 1 of its own pid namespace:\n{}",
        run.out
    );
    assert_eq!(
        kv(&run.out, "CGROUP"),
        Some("0::/"),
        "the app is not the cgroup-namespace root:\n{}",
        run.out
    );
    assert_eq!(
        kv(&run.out, "HOSTNAME"),
        Some(format!("wlsctx-{APP}-it-id").as_str()),
        "the hostname is not wlsctx-<app>-<instance> (uts namespace):\n{}",
        run.out
    );
    assert!(
        matches!(kv(&run.out, "SETUID0"), Some("ERR:1" | "ERR:22")),
        "setuid(0) did not fail (EPERM/EINVAL) — the identity is not locked:\n{}",
        run.out
    );
    // The kernel column-pads the map's fields; compare them
    // whitespace-normalised so the single-extent shape is what is
    // asserted, not the padding.
    let uidmap = kv(&run.out, "UIDMAP").map(|v| v.split_whitespace().collect::<Vec<_>>().join(" "));
    assert_eq!(
        uidmap.as_deref(),
        Some(format!("{uid} {uid} 1").as_str()),
        "the uid_map is not the single extent (0 must be unmapped):\n{}",
        run.out
    );
    clean_instance("it-id");
}

#[test]
fn rootfs_is_rebuilt_not_masked() {
    let run = expect_ok(run_probe("it-fs", &[], &[], ROOTFS), "the rootfs probe");
    for (k, want) in [
        ("MT_DEV", "tmpfs"),
        ("MT_SYS", "tmpfs"),
        ("MT_RUN", "tmpfs"),
        ("MT_TMP", "tmpfs"),
        ("MT_PROC", "proc"),
    ] {
        assert_eq!(
            kv(&run.out, k),
            Some(want),
            "{k} is not the fresh filesystem (the rebuilt rootfs):\n{}",
            run.out
        );
    }
    assert_eq!(
        kv(&run.out, "DEV_NODES"),
        Some("full|null|ptmx|pts|random|tty|urandom|zero"),
        "/dev holds more than the standard nodes (it is not a fresh tmpfs of binds):\n{}",
        run.out
    );
    assert_eq!(
        kv(&run.out, "SYS_FS"),
        Some(""),
        "/sys/fs is not empty (the cgroup2 filesystem must stay out of the sandbox):\n{}",
        run.out
    );
    assert!(
        kv(&run.out, "SYS_NET").is_some_and(|i| i.split('|').any(|n| n == "lo")),
        "loopback is missing from the netns:\n{}",
        run.out
    );
    assert_eq!(
        kv(&run.out, "RUN_USER"),
        Some("wlsctx"),
        "the fresh /run holds more than the per-instance tree (the host's runtime dir must be invisible):\n{}",
        run.out
    );
    assert_eq!(
        kv(&run.out, "RUN_INST"),
        Some("DIR"),
        "the per-instance dir is not in the sandbox at its systemd-standard path:\n{}",
        run.out
    );
    clean_instance("it-fs");
}

#[test]
fn landlock_denies_outside_the_grants() {
    let run = expect_ok(run_probe("it-ll", &[], &[], LANDLOCK), "the landlock probe");
    assert_eq!(
        kv(&run.out, "SECCOMP_MODE"),
        Some("2"),
        "no seccomp filter is installed (PR_GET_SECCOMP is not the filter mode):\n{}",
        run.out
    );
    assert_eq!(
        kv(&run.out, "RUNUSER_WRITE"),
        Some("ERR:13"),
        "a write outside the granted subtrees was not denied (the Landlock floor failed):\n{}",
        run.out
    );
    assert_eq!(
        kv(&run.out, "INST_WRITE"),
        Some("OK"),
        "a write inside the granted per-instance dir failed:\n{}",
        run.out
    );
    assert_eq!(
        kv(&run.out, "TMP_WRITE"),
        Some("OK"),
        "a write inside the granted /tmp failed:\n{}",
        run.out
    );
    assert_eq!(
        kv(&run.out, "ETC_WRITE"),
        Some("ERR:13"),
        "a write to a read-granted path was not denied:\n{}",
        run.out
    );
    clean_instance("it-ll");
}

#[test]
fn network_shared_reaches_the_host() {
    // The host-side listener, answered by a helper thread (the app
    // waits for the reply, so the answer must come while the run is
    // still inside the sandbox).
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("binding the host-side listener");
    let port = listener.local_addr().expect("the listener's port").port();
    let responder = std::thread::spawn(move || -> bool {
        // Non-blocking accept polled against a deadline: a failed
        // probe must never leave this thread parked forever on the
        // accept (the caller joins it).
        listener.set_nonblocking(true).ok();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match listener.accept() {
                Ok((mut s, _)) => {
                    let mut buf = [0u8; 4];
                    return s.read_exact(&mut buf).is_ok()
                        && &buf == b"ping"
                        && s.write_all(b"pong").is_ok();
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => return false,
            }
        }
    });
    let run = expect_ok(
        run_probe(
            "it-net",
            &[],
            &[("PROBE_PORT", &port.to_string())],
            NET_SHARED,
        ),
        "the shared-network probe",
    );
    assert!(
        responder.join().expect("the responder thread panicked"),
        "the host-side listener never saw the app's connection"
    );
    assert_eq!(
        kv(&run.out, "HOSTLISTEN"),
        Some("b'pong'"),
        "the app did not complete the ping/pong with the host (shared netns broken):\n{}",
        run.out
    );
    assert!(
        kv(&run.out, "IFACES").is_some_and(|i| i.split('|').any(|n| n == "lo")),
        "the shared netns has no loopback:\n{}",
        run.out
    );
    clean_instance("it-net");
}

#[test]
fn network_none_denies_all_communication() {
    // The listener exists but must never see a connection: in none
    // mode the connect is denied before any packet leaves (the bare
    // netns is the second, kernel-level layer).
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("binding the host-side listener");
    let port = listener.local_addr().expect("the listener's port").port();
    let run = expect_ok(
        run_probe(
            "it-nonet",
            &["--network=none"],
            &[("PROBE_PORT", &port.to_string())],
            NET_NONE,
        ),
        "the none-network probe",
    );
    for k in ["BIND", "CONNECT"] {
        assert!(
            matches!(kv(&run.out, k), Some("ERR:13" | "ERR:1")),
            "{k} was not denied in --network=none mode:\n{}",
            run.out
        );
    }
    assert_eq!(
        kv(&run.out, "IFACES"),
        Some("lo"),
        "the bare netns holds more than loopback:\n{}",
        run.out
    );
    clean_instance("it-nonet");
}

#[test]
fn wayland_tagged_socket_is_the_only_socket() {
    let wd = std::env::var("WAYLAND_DISPLAY").unwrap_or_default();
    if wd.is_empty() {
        eprintln!("skipping (no running wlroots compositor in this environment)");
        return;
    }
    let xdg = match session_xdg() {
        Some(x) => x,
        None => return, // the skip reason was already printed
    };
    // `run --wayland` reaches the upstream compositor through the
    // session XDG; if that socket is gone the compositor is not
    // running — skip rather than fail.
    let upstream = xdg.join(&wd);
    if !upstream.exists() {
        eprintln!("skipping (the session Wayland socket {upstream:?} is absent)");
        return;
    }
    let run = expect_ok(
        run_probe("it-wl", &["--listen", "wl-it"], &[], WAYLAND_PROBE),
        "the wayland probe",
    );
    let uid = host_uid();
    let inst = instance_name("it-wl");
    assert_eq!(
        kv(&run.out, "WD"),
        Some("wl-it"),
        "the app's WAYLAND_DISPLAY is not the tagged socket's name:\n{}",
        run.out
    );
    assert_eq!(
        kv(&run.out, "XDG"),
        Some(format!("/run/user/{uid}/wlsctx/{inst}").as_str()),
        "the app's XDG_RUNTIME_DIR is not the in-sandbox instance dir:\n{}",
        run.out
    );
    assert_eq!(
        kv(&run.out, "FILE"),
        Some("SOCK"),
        "the tagged socket file is not a unix socket:\n{}",
        run.out
    );
    assert_eq!(
        kv(&run.out, "RUNDIR_SOCKETS"),
        Some("wl-it"),
        "the app sees more than the tagged socket (the host's sockets must be invisible):\n{}",
        run.out
    );
    assert_eq!(
        kv(&run.out, "CONNECT"),
        Some("OK"),
        "the app could not connect to the tagged socket:\n{}",
        run.out
    );
    // 5.4: the run's cleanup removes the per-instance runtime dir —
    // the tagged socket (carried into the sandbox by a *bind*,
    // decision #28) is gone with it, so nothing a later process
    // could connect to remains on the host.
    let host_inst =
        host_instance_dir("it-wl").expect("the session XDG is the standard one (checked above)");
    assert!(
        !host_inst.exists(),
        "the per-instance runtime dir {host_inst:?} remains after the run (the 5.4 cleanup failed)"
    );
    clean_instance("it-wl");
}

/// Spawn a lifecycle run (session XDG + a `NOTIFY_SOCKET` datagram
/// in a scratch dir) and wait until the app is *demonstrably* up.
///
/// `READY=1` alone is not that: S sends it when B is *about to* exec
/// (B reports its pid pre-exec), and a TERM forwarded in that window
/// hits the pid-namespace init before the app has installed a
/// handler — the default action is ignored there — so the 2 s
/// escalation would SIGKILL the app (exit 137) instead of the clean
/// 0 the test asserts. Both lifecycle apps print `UP` as their first
/// line, after handler install, so the wait extends to that line.
/// Returns `(child, notify, up)`, `up` being the app output
/// consumed while waiting; the stdout handle is put back on the
/// child, so a test's post-run read continues after it.
fn spawn_lifecycle(inst: &str, app: &str) -> Option<(Child, UnixDatagram, String)> {
    let xdg = session_xdg()?;
    // Scratch dir for the notify datagram only; the XDG itself stays
    // at the session's standard path (see `session_xdg`).
    let scratch = TempDir::new().ok()?;
    let notify_path = scratch.path().join("notify.sock");
    let notify = UnixDatagram::bind(&notify_path).ok()?;
    clean_instance(inst);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wlsctx"));
    cmd.args(["run", "--app-id", APP, "--instance-id", inst]);
    cmd.args(["--", PYTHON, "-c", app]);
    cmd.env("XDG_RUNTIME_DIR", &xdg);
    cmd.env("NOTIFY_SOCKET", notify_path.to_str().unwrap_or_default());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.process_group(0);
    let mut child = cmd.spawn().ok()?;
    // `READY=1` when B is about to exec (within 15 s).
    notify
        .set_read_timeout(Some(Duration::from_millis(200)))
        .ok();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut buf = [0u8; 64];
    let mut ready = false;
    while Instant::now() < deadline {
        if let Ok((n, _)) = notify.recv_from(&mut buf)
            && String::from_utf8_lossy(&buf[..n]).contains("READY=1")
        {
            ready = true;
            break;
        }
    }
    if !ready {
        let pid = child.id() as i32;
        // SAFETY: as in run_probe.
        unsafe { libc::killpg(pid, libc::SIGKILL) };
        let _ = child.wait();
        eprintln!("skipping (no READY=1 within 15 s)");
        return None;
    }
    // The app's first line (both apps print `UP` after handler
    // install): a forwarded TERM is only meaningful once it exists.
    // The read cannot hang: these apps print or exit within
    // milliseconds of the exec, and an EOF (a failed exec) ends it.
    let mut out = child.stdout.take().expect("the stdout pipe");
    let mut seen = String::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    while !seen.contains("UP") && Instant::now() < deadline {
        let n = out.read(&mut buf).unwrap_or(0);
        if n == 0 {
            break;
        }
        seen.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    child.stdout = Some(out);
    if !seen.contains("UP") {
        let pid = child.id() as i32;
        // SAFETY: as in run_probe.
        unsafe { libc::killpg(pid, libc::SIGKILL) };
        let _ = child.wait();
        eprintln!("skipping (no UP from the app within 15 s)");
        return None;
    }
    Some((child, notify, seen))
}

#[test]
fn lifecycle_term_reaches_the_app() {
    let (mut child, _notify, seen) =
        spawn_lifecycle("it-term", TERM_APP).expect("skipped (see above)");
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    )
    .expect("sending TERM");
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            _ => {
                let pid = child.id() as i32;
                // SAFETY: as in run_probe.
                unsafe { libc::killpg(pid, libc::SIGKILL) };
                let _ = child.wait();
                panic!("the run did not exit within 10 s of the TERM");
            }
        }
    };
    let mut out = seen;
    if let Some(mut so) = child.stdout.take() {
        let _ = so.read_to_string(&mut out);
    }
    assert_eq!(
        status.code(),
        Some(0),
        "a TERM to an app that handles it must be a clean exit 0, got {status:?}:\n{out}"
    );
    assert!(
        out.contains("UP"),
        "the app's startup output is missing:\n{out}"
    );
    assert!(
        out.contains("GOT-TERM"),
        "the app's SIGTERM handler never ran (the TERM was not forwarded):\n{out}"
    );
    clean_instance("it-term");
}

#[test]
fn lifecycle_term_escalates_to_kill() {
    let (mut child, _notify, _seen) =
        spawn_lifecycle("it-kill", SLEEP_APP).expect("skipped (see above)");
    let term_at = Instant::now();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    )
    .expect("sending TERM");
    let deadline = term_at + Duration::from_secs(15);
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            _ => {
                let pid = child.id() as i32;
                // SAFETY: as in run_probe.
                unsafe { libc::killpg(pid, libc::SIGKILL) };
                let _ = child.wait();
                panic!("the run did not exit within 15 s of the TERM");
            }
        }
    };
    let elapsed = term_at.elapsed();
    assert_eq!(
        status.code(),
        Some(137),
        "an app that ignores TERM (pid-namespace init) must die by the 2 s KILL escalation (exit 137), got {status:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(1500),
        "the escalation was immediate (the KILL follows after 2 s): {elapsed:?}"
    );
    clean_instance("it-kill");
}
