//! The in-process sandbox (PLAN.md): the namespace set
//! (user → mount → pid → ipc → uts → cgroup → net), the private
//! rootfs, and the landlock + seccomp policy applied via `nono`.
//!
//! Phase 1: the user namespace and the credential model ([userns] —
//! the single-extent map, decision #10). Phase 2: the remaining
//! namespaces ([namespaces]) and the double-fork in [run_sandboxed]
//! that makes the app PID 1 of a fresh pid namespace. Phase 3: the
//! private rootfs ([mounts]) and the per-app profiles
//! (`crate::profile`). Phase 4: the Landlock floor and the
//! supervisor-meditated seccomp-notify filter ([policy], [supervise]).

pub(crate) mod mounts;
pub(crate) mod namespaces;
pub(crate) mod policy;
pub(crate) mod supervise;
pub(crate) mod userns;

use anyhow::{Context, Result, anyhow, bail};
use log::error;
use std::os::fd::AsRawFd;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{ForkResult, fork};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::ffi::OsString;
use std::os::unix::process::CommandExt;

/// The tagged Wayland socket of this run (Phase 5.1), created by S
/// before the first fork; `None` = no tagged socket.
#[derive(Clone, Debug, Default)]
pub struct WaylandSpec {
    /// The socket path: an absolute path as given; a relative path —
    /// or no path at all (default name `wayland-1`) — in the
    /// per-instance runtime dir.
    pub listen: Option<String>,
    /// Adopt the listener from systemd socket activation (LISTEN_FDS)
    /// instead of binding a path.
    pub socket_activation: bool,
    /// The value the socket is tagged with
    /// (`wp_security_context_v1.set_sandbox_engine`).
    pub sandbox_engine: String,
}

/// The per-instance identity and mode of a sandboxed run (PLAN §5).
#[derive(Clone, Debug)]
pub(crate) struct SandboxConfig {
    /// Application ID: part of the hostname (`wlsctx-<app>-<inst>`)
    /// and of the per-instance cgroup name.
    pub app_id: String,
    /// Instance ID: part of the hostname and cgroup name.
    pub instance_id: String,
    /// Network mode (PLAN §5); the default is the shared host netns.
    pub network: namespaces::NetworkMode,
    /// The app profile (TOML file, built-in, or the ad-hoc default).
    pub profile: crate::profile::Profile,
    /// The final GPU decision: the profile's value unless overridden
    /// by `--gpu`/`--no-gpu`.
    pub gpu: bool,
    /// The tagged Wayland socket (Phase 5.1); `None` = none.
    pub wayland: Option<WaylandSpec>,
}

/// Run `command` inside the full namespace set, as our real uid
/// (PLAN.md §3; decisions #9, #10, #12, #14). Returns the command's
/// exit code.
///
/// Topology (PLAN §3.2):
///
/// ```text
/// S (wlsctx — outside every namespace; the GPU precheck and the
/// per-instance runtime dir live here)
/// ├─ A: user → mount → pid → cgroup ns; builds the rootfs; forks B;
/// │     reaps B, exits with B's status
/// │  └─ B: ipc → uts → net (per mode) → fresh /proc → verify → exec (PID 1)
/// ```
///
/// `S` (us) never enters a namespace, so the app remains a normal,
/// reappable child for signalling and `waitpid`. When `B` (PID 1)
/// dies the kernel's pidns teardown does *not* kill `A` on this
/// kernel (decision #14) — `A` reaps `B` and exits with `B`'s status
/// by choice, so there are no orphans, and the exit code (or
/// 128+signal) propagates to us through both forks (probed: reliable
/// for exit codes and signals).
///
/// Setup failures inside a child are reported on stderr and exit
/// with 126 (the shell convention for "cannot execute").
pub(crate) fn run_sandboxed(command: &[OsString], config: &SandboxConfig) -> Result<i32> {
    if command.is_empty() {
        return Err(anyhow!("no command to run"));
    }
    namespaces::validate_id(&config.app_id, "--app-id")?;
    namespaces::validate_id(&config.instance_id, "--instance-id")?;
    let hostname = namespaces::hostname_for(&config.app_id, &config.instance_id);
    if hostname.len() > 64 {
        bail!(
            "hostname {hostname:?} is {} bytes; the kernel limit is 64 (shorten --app-id/--instance-id)",
            hostname.len()
        );
    }
    let creds =
        userns::Credentials::current().context("reading the current uid/gid (getresuid/getresgid)")?;

    // The full (host) path of the session cgroup, computed here — `S`
    // never unshares the cgroup namespace — so that after the
    // instance dies we can clean up its per-instance sub-cgroup.
    let sub_cgroup = format!(
        "/sys/fs/cgroup{}/{}",
        namespaces::full_cgroup_path()?,
        namespaces::cgroup_name_for(&config.app_id, &config.instance_id)
    );

    // The GPU precheck runs here (host-side properties: `/dev/dri`
    // exists, the user is in the `render` group) so a bad
    // configuration fails before any namespace is entered.
    if config.gpu {
        mounts::precheck_gpu()?;
    }
    // The per-instance runtime dir on the host: created before the
    // fork, so A can bind it into the fresh `/run` (it is also the
    // future home of the tagged Wayland socket — Phase 5).
    let runtime_dir = mounts::instance_runtime_dir(&config);
    std::fs::create_dir_all(&runtime_dir)
        .with_context(|| format!("creating the per-instance runtime dir {runtime_dir}"))?;
    // The same dir's path *inside the sandbox* (the fresh `/run`'s
    // systemd-standard location, decision #28). The policy grants
    // and the app's env use this string: it is the one the app sees,
    // and it equals the host path only for the default XDG.
    let sandbox_runtime = mounts::sandbox_instance_dir(&config);

    // Phase 5.1: the tagged Wayland socket is created *here*, ahead
    // of the first fork: the rootfs build's step-1 carry (which runs
    // in A immediately after the fork) must already see the socket
    // file, and the tagging roundtrip must complete before A masks
    // anything. S keeps its listener copy and the reference pipe
    // open until this function returns (5.2) — the compositor drops
    // the tag when they close, which the process exit guarantees.
    // On a tagging failure the bound file is unlinked by the
    // preparation itself, and we remove the runtime dir (no fork
    // happened, so nothing will clean it up).
    let tagged = if let Some(spec) = &config.wayland {
        let t = match crate::wayland::prepare_tagged_socket(
            &config.app_id,
            &config.instance_id,
            &runtime_dir,
            spec.listen.as_deref(),
            spec.socket_activation,
            &spec.sandbox_engine,
        ) {
            Ok(t) => t,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&runtime_dir);
                return Err(e).context("creating the tagged Wayland socket");
            }
        };
        if log::log_enabled!(log::Level::Info)
            && let Ok(local_addr) = t.listener.local_addr()
        {
            log::info!(
                "Tagged Wayland socket at {local_addr:?} (engine: {}, app: {}, instance: {})",
                spec.sandbox_engine,
                config.app_id,
                config.instance_id
            );
        }
        Some(t)
    } else {
        None
    };

    // The supervisor handoff channels, created before the first fork so
    // both S and A (and, down to B) inherit them (decisions #23, #26):
    //   * `pipe` — B→A: B writes the notify listener's *fd number* here.
    //   * `sock` — S↔A: A `pidfd_getfd`s B's listener into its own table
    //     and `SCM_RIGHTS`es it to S over this socketpair.
    //   * `ack` — A→B: A's handoff verdict (`1` = exec, `0` = die); B
    //     blocks on it before execing, which makes the handoff
    //     deterministic (the listener is `O_CLOEXEC` in B's table, and
    //     `pidfd_getfd` on B only works pre-exec — decision #26).
    // The raw fd numbers are identical in S and A after the fork; each
    // process closes the ends it does not use and leaks the ones it keeps
    // (`supervise::leak`), so an `OwnedFd` drop never closes a shared end.
    let (pipe_read, pipe_write) = supervise::create_pipe().context("creating the B→A pipe")?;
    let (sock_a, sock_s) =
        supervise::create_socketpair().context("creating the S↔A socketpair")?;
    let (ack_read, ack_write) =
        supervise::create_pipe().context("creating the A→B verdict pipe")?;
    let pr = supervise::leak(pipe_read);
    let pw = supervise::leak(pipe_write);
    let sa = supervise::leak(sock_a);
    let ss = supervise::leak(sock_s);
    let ar = supervise::leak(ack_read);
    let aw = supervise::leak(ack_write);

    // SAFETY: fork(2) from a single-threaded point in the process
    // lifecycle; the parent only handles `child` below.
    match unsafe { fork() }.context("forking the sandbox child")? {
        // A: the intermediate child. Everything from here on runs in
        // the user/mount/pid namespaces we claim below; on success we
        // never return (we exit with the app's status).
        ForkResult::Child => {
            // A keeps the B→A pipe (read end `pr`, write end `pw` until
            // the second fork), the A→S socketpair end `sa`, the A→B
            // verdict pipe write end `aw`, and — until the second
            // fork — the verdict pipe read end `ar` too: B is the
            // verdict's reader and must *inherit* it, so A closes its
            // copy only *after* the fork (mirroring `pw`). A never
            // uses S's socketpair end, so close that now (before
            // forking B, so B does not inherit it).
            unsafe { libc::close(ss) };
            log::debug!(
                "A[{}]: arm=A (kept pr={} pw={} sa={} aw={})",
                std::process::id(),
                pr,
                pw,
                sa,
                aw
            );
            if let Err(e) = userns::enter_userns(&creds) {
                error!("user namespace setup failed: {e:#}");
                std::process::exit(126);
            }
            if let Err(e) = namespaces::enter_mountns() {
                error!("mount namespace setup failed: {e:#}");
                std::process::exit(126);
            }
            if let Err(e) = namespaces::enter_pidns() {
                error!("pid namespace setup failed: {e:#}");
                std::process::exit(126);
            }
            // The cgroup ns must be unshared **before** the rootfs
            // build: the ro-bind of `/` makes cgroup2 read-only, and
            // the instance sub-cgroup is created and entered here
            // (decision #12). B, a fork of A, inherits the namespace
            // and the membership.
            let cgroup_name =
                namespaces::cgroup_name_for(&config.app_id, &config.instance_id);
            if let Err(e) = namespaces::enter_cgroupns(&cgroup_name) {
                error!("cgroup namespace setup failed: {e:#}");
                std::process::exit(126);
            }
            if let Err(e) = mounts::build_rootfs(&config) {
                error!("rootfs construction failed: {e:#}");
                std::process::exit(126);
            }
            // The second fork: B is the app and is PID 1 of the new
            // pid namespace.
            let app = match unsafe { fork() } {
                Ok(app) => app,
                Err(e) => {
                    error!("forking the app child: {e}");
                    std::process::exit(126);
                }
            };
            match app {
                ForkResult::Child => {
                    // B: the app. It keeps only the B→A pipe write end
                    // (`pw`) and the A→B verdict read end (`ar`); the
                    // other ends are closed now so none reaches the
                    // exec'd app (decisions #23, #26).
                    unsafe { libc::close(pr) };
                    unsafe { libc::close(sa) };
                    unsafe { libc::close(aw) };
                    log::debug!(
                        "B[{}]: arm=B (kept pw={} ar={})",
                        std::process::id(),
                        pw,
                        ar
                    );
                    // The remaining namespaces, the credential check,
                    // and — Phase 4 — the combined seccomp-notify filter
                    // plus the Landlock floor, then the exec.
                    if let Err(e) = (|| -> Result<()> {
                        namespaces::enter_ipcns()?;
                        namespaces::enter_utsns(&hostname)?;
                        if config.network == namespaces::NetworkMode::None {
                            namespaces::enter_netns()?;
                        }
                        // The fresh procfs must be mounted by B, the
                        // member of the new pid ns, so the view is
                        // namespaced (the app is PID 1).
                        mounts::mount_namespaced()?;
                        userns::verify_locked(&creds)?;
                        // Phase 4: build the single capability set that
                        // drives both floors, install the combined
                        // filter first, then the Landlock floor (the
                        // filter must precede Landlock — decision #22).
                        let caps =
                            policy::capability_set(&config, std::path::Path::new(&sandbox_runtime))
                                .context("building the app's capability set")?;
                        let notify = policy::apply(&caps)
                            .context("installing the seccomp-notify filter + Landlock floor")?;
                        // Hand the listener up to the supervisor
                        // (decision #23): B's own `sendmsg` is trapped,
                        // so it cannot `SCM_RIGHTS` the fd — write its
                        // *number* to the B→A pipe instead; A (B's
                        // parent) extracts it via `pidfd_getfd` and
                        // forwards it to S.
                        supervise::write_fdnum(pw, notify.as_raw_fd())
                            .context("handing the listener fd number to A")?;
                        unsafe { libc::close(pw) };
                        // Deterministic handoff (decision #26): the
                        // listener is `O_CLOEXEC` in our table, and
                        // A's `pidfd_getfd` on us succeeds only while
                        // we are the still-dumpable *pre-exec* process
                        // — so we must not start the exec until A has
                        // extracted the listener and handed it to S.
                        // If the verdict is a failure, exec is futile
                        // anyway (every openat the dynamic loader
                        // makes would be answered `ENOSYS`), so exit.
                        match supervise::wait_ack(ar, 10_000) {
                            Ok(1) => {
                                unsafe { libc::close(ar) };
                                // Close our copy; S's (the one it
                                // services) is the only one left.
                                drop(notify);
                                Ok(())
                            }
                            _ => bail!("the supervisor handoff did not complete; refusing to exec an unsupervised process"),
                        }
                    })() {
                        error!("sandbox setup failed: {e:#}");
                        std::process::exit(126);
                    }
                    exec_app(command, &app_env(&config, &runtime_dir));
                }
                ForkResult::Parent { child } => {
                    // A is done with the B→A pipe's write end (B holds
                    // the only writer now). Read the listener's fd
                    // number B wrote, complete the handoff
                    // (decision #23) — as B's direct parent, the one
                    // process Yama `restricted` lets `pidfd_getfd` B,
                    // extract a copy of B's listener into our own
                    // table and `SCM_RIGHTS` it to S — and send B the
                    // verdict (decision #26): this runs while B is
                    // still pre-exec (blocked in `wait_ack`), so the
                    // extract cannot race the exec. On failure we
                    // tell B to die: the Landlock floor B installed
                    // still holds, and we just reap and propagate B's
                    // status.
                    //
                    // Drop our copy of the verdict read end now that B
                    // has it: B becomes the pipe's only reader, and B
                    // closes it after the verdict (or at exit).
                    unsafe { libc::close(ar) };
                    // Ignore SIGPIPE: on the failure path our verdict
                    // write below can hit a pipe whose reader (B) is
                    // already gone, which would otherwise kill us
                    // before we reap B and corrupt B's exit status. B
                    // (and the app it execs) already inherited the
                    // default disposition from the fork above.
                    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
                    log::debug!(
                        "A[{}]: arm=A2, B pid {} (kept pr={} sa={} aw={}); waiting for the fd number",
                        std::process::id(),
                        child.as_raw(),
                        pr,
                        sa,
                        aw
                    );
                    let handed_off = match supervise::read_fdnum(pr) {
                        Ok(Some(num)) => {
                            let ok = match supervise::extract_and_send(child.as_raw(), num, sa) {
                                Ok(listener) => {
                                    drop(listener);
                                    true
                                }
                                Err(e) => {
                                    log::debug!("A: listener handoff failed: {e:#}");
                                    false
                                }
                            };
                            let _ = supervise::send_ack(aw, if ok { 1 } else { 0 });
                            ok
                        }
                        Ok(None) => {
                            // B died before writing (setup failure):
                            // tell it not to exec — the write may hit
                            // a closed pipe, which is exactly the point.
                            let _ = supervise::send_ack(aw, 0);
                            false
                        }
                        Err(e) => {
                            log::debug!("A: reading the listener fd number failed: {e:#}");
                            let _ = supervise::send_ack(aw, 0);
                            false
                        }
                    };
                    unsafe { libc::close(pr) };
                    unsafe { libc::close(aw) };
                    unsafe { libc::close(sa) };
                    if !handed_off {
                        log::debug!("A: no supervisor (handoff failed; B will not exec)");
                    }
                    // Reap B and exit with B's status: exit codes and
                    // 128+signal propagate reliably through this fork
                    // (probed in Phase 2). The kernel does not kill us
                    // when B (the pid namespace's PID 1) dies
                    // (decision #14) — we exit by choice, so no
                    // orphans.
                    let code = match waitpid(Some(child), None) {
                        Ok(WaitStatus::Exited(_, code)) => code,
                        Ok(WaitStatus::Signaled(_, sig, _)) => 128 + sig as i32,
                        other => {
                            error!("waiting for the app child failed: {other:?}");
                            126
                        }
                    };
                    std::process::exit(code);
                }
            }
        }
        ForkResult::Parent { child } => {
            // S (us): the supervisor. We keep only the S↔A socketpair
            // end (`ss`); the B→A pipe, the A→S end, and both ends of
            // the verdict pipe are ours to drop here (decisions
            // #23, #26). `ss` receives the notify listener from A
            // (blocking; A sends it once B has handed up the fd
            // number, or A exits early and `ss` sees EOF).
            unsafe { libc::close(pr) };
            unsafe { libc::close(pw) };
            unsafe { libc::close(sa) };
            unsafe { libc::close(ar) };
            unsafe { libc::close(aw) };
            log::debug!(
                "S[{}]: arm=S (kept ss={}); waiting for the listener",
                std::process::id(),
                ss
            );
            // 5.2: the tagged Wayland socket is held *by this branch*
            // (S, the supervisor) from here until the process exits:
            // the listener copy and the reference pipe ("close" fd)
            // drop only when `run_sandboxed` returns, and their
            // close — the compositor's untag trigger — happens no
            // later than the app's death (which is what ends this
            // function).
            if let Some(t) = &tagged {
                log::debug!(
                    "S: holding the tagged Wayland socket {} (close_fd {})",
                    t.host_path,
                    t.close_fd.as_raw_fd()
                );
            }

            // The supervisor runs on a side thread so this one can
            // block in `waitpid` for A. It services B's trapped
            // syscalls; S itself never installs the filter.
            let stop = Arc::new(AtomicBool::new(false));
            let mut supervisor: Option<std::thread::JoinHandle<()>> = None;
            match supervise::recv_fd(ss) {
                Ok(Some(notify)) => {
                    unsafe { libc::close(ss) };
                    log::debug!("S[{}]: got the listener (fd {})", std::process::id(), notify.as_raw_fd());
                    match policy::capability_set(&config, std::path::Path::new(&sandbox_runtime)) {
                        Ok(caps) => {
                            let stop2 = Arc::clone(&stop);
                            supervisor = Some(std::thread::spawn(move || {
                                supervise::supervisor(notify, caps, stop2)
                            }));
                        }
                        Err(e) => {
                            // Mediation needs the same capability set
                            // that built the floor; without it we
                            // cannot decide, so disable the supervisor
                            // (the Landlock floor B installed still
                            // holds). `notify` closes here.
                            log::warn!(
                                "supervisor: capability set unavailable ({e:#}); supervisor disabled"
                            );
                        }
                    }
                }
                _ => {
                    // EOF (B died before the handoff) or a recv error:
                    // nothing to supervise; the floor still holds in
                    // whatever B ran.
                    unsafe { libc::close(ss) };
                    log::debug!("S: no supervisor (handoff did not complete)");
                }
            }

            // Reap A, which carries B's status.
            let code =
                match waitpid(Some(child), None).context("waiting for the sandbox child")? {
                    WaitStatus::Exited(_, code) => code,
                    // 128+signal, the shell convention.
                    WaitStatus::Signaled(_, sig, _) => 128 + sig as i32,
                    other => {
                        return Err(anyhow!(
                            "unexpected wait status for the sandbox child: {other:?}"
                        ))
                    }
                };
            // The app (and A) are gone: tell the supervisor to stop and
            // join it (it exits within one poll tick).
            stop.store(true, Ordering::Relaxed);
            if let Some(t) = supervisor {
                let _ = t.join();
            }
            // Best-effort cleanup of the per-instance sub-cgroup: the
            // app is dead, so it is empty (a parallel instance sharing
            // the name may still hold it — that just makes the rmdir
            // fail with ENOTEMPTY, which we ignore).
            if let Err(e) = std::fs::remove_dir(&sub_cgroup) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    log::warn!("cleaning up the sub-cgroup {sub_cgroup} failed: {e}");
                }
            }
            // Best-effort removal of the rootfs scratch (its mounts
            // died with the children's mount ns; the directory
            // itself is a plain host directory on /var/tmp).
            let scratch = mounts::rootfs_scratch_dir(&config);
            if let Err(e) = std::fs::remove_dir_all(&scratch) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    log::warn!("cleaning up the rootfs scratch {scratch} failed: {e}");
                }
            }
            // The scratch's parent may be left empty (a sibling
            // instance still running makes this ENOTEMPTY — ignored).
            if let Some(parent) = std::path::Path::new(&scratch).parent() {
                let _ = std::fs::remove_dir(parent);
            }
            Ok(code)
        }
    }
}

/// The app's environment (Phase 5.3): the profile's variables, plus
/// — when this run has a tagged Wayland socket — the per-instance
/// runtime dir as `XDG_RUNTIME_DIR` and the socket's name as
/// `WAYLAND_DISPLAY`. The app thereby reaches *only* the tagged
/// socket: the host's Wayland socket sits directly under the host
/// XDG dir, which the fresh (mostly empty) `/run` in the sandbox
/// hides.
///
/// `XDG_RUNTIME_DIR` is the *in-sandbox* instance dir (the
/// step-5 location, decision #28), so the bare socket name
/// resolves inside the sandbox even when the host's XDG is not
/// systemd's default.
fn app_env(config: &SandboxConfig, runtime_dir: &str) -> std::collections::BTreeMap<String, String> {
    let mut env = config.profile.env.clone();
    if let Some(spec) = &config.wayland {
        let host_path = crate::wayland::resolve_socket_path(runtime_dir, spec.listen.as_deref());
        let name = host_path.rsplit('/').next().unwrap_or("wayland-1");
        env.insert("XDG_RUNTIME_DIR".into(), mounts::sandbox_instance_dir(config));
        env.insert("WAYLAND_DISPLAY".into(), name.to_string());
    }
    env
}

/// Replace this (child) process with `command`, adding the profile's
/// environment variables on top of the session environment. Never
/// returns on success; on failure the error is logged and the child
/// exits with 126.
fn exec_app(command: &[OsString], env: &std::collections::BTreeMap<String, String>) -> ! {
    let (program, args) = command
        .split_first()
        .expect("command is non-empty (checked in run_sandboxed)");
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    cmd.envs(env);
    // On success exec(3) never returns: this process is replaced. The
    // returned error means the exec itself failed (bad path,
    // permissions, …).
    let e = cmd.exec();
    error!("exec of {command:?} failed: {e}");
    std::process::exit(126);
}

#[cfg(test)]
mod tests {
    use super::{run_sandboxed, SandboxConfig, WaylandSpec};
    use crate::sandbox::mounts;
    use crate::sandbox::namespaces::NetworkMode;
    use crate::sandbox::userns::tests::run_in_child;
    use std::ffi::OsString;
    use std::io::Write;
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::net::UnixStream;

    /// The tagged-socket run used by the live test below.
    fn tagged_config() -> SandboxConfig {
        SandboxConfig {
            app_id: "wlt".to_string(),
            instance_id: "1".to_string(),
            network: NetworkMode::Shared,
            profile: crate::profile::Profile::adhoc(),
            gpu: false,
            wayland: Some(WaylandSpec {
                listen: Some("wl-probe".to_string()),
                socket_activation: false,
                sandbox_engine: "wlsctx-test".to_string(),
            }),
        }
    }

    /// Phase 5.1/5.2/5.3, end to end against the running compositor:
    /// the tagged Wayland socket is created by S *ahead of the fork*
    /// (5.1), carried into the sandbox by the rootfs build, and the
    /// app's `WAYLAND_DISPLAY`/`XDG_RUNTIME_DIR` point at it (5.3),
    /// so the app reaches only the tagged socket; the app's
    /// `connect(2)` succeeds (the compositor holds the listener, the
    /// supervisor mediates the allow). When the run ends, S's
    /// listener copy and the reference pipe close with the process
    /// (5.2): the socket file remains (nothing unlinks it) but no
    /// longer serves — a host-side `connect(2)` is refused.
    ///
    /// Needs a running wlroots compositor providing
    /// `wp_security_context_v1` (this project's target desktop,
    /// sway): without one the tagging fails before the fork and the
    /// run exits non-zero — an honest failure, not a skip.
    #[test]
    fn tagged_socket_is_carried_reachable_and_untagged() {
        // The test relies on the session's real XDG/WAYLAND
        // environment; serialise against env-mutating tests and
        // against other full-sandbox runs (per-instance host state).
        let _env_lock = crate::testutil::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _sb_lock = crate::testutil::SANDBOX_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let config = tagged_config();
        let host_runtime = mounts::instance_runtime_dir(&config);
        let host_socket = format!("{host_runtime}/wl-probe");
        let sandbox_runtime = mounts::sandbox_instance_dir(&config);

        // A fresh start: no stale dir or socket from a previous run.
        let _ = std::fs::remove_dir_all(&host_runtime);
        assert!(
            !std::path::Path::new(&host_socket).exists(),
            "{host_socket} exists before the run (stale state?)"
        );

        // The app: report the environment `run` set, then connect to
        // the tagged socket (`connect(2)`; a bare `open(2)` on a unix
        // socket is not a connect on this kernel).
        let script = "\
import os, socket, stat\n\
print('WD=%s' % os.environ['WAYLAND_DISPLAY'])\n\
print('XDG=%s' % os.environ['XDG_RUNTIME_DIR'])\n\
p = os.path.join(os.environ['XDG_RUNTIME_DIR'], os.environ['WAYLAND_DISPLAY'])\n\
print('FILE-OK' if stat.S_ISSOCK(os.lstat(p).st_mode) else 'FILE-NO')\n\
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
s.connect(p)\n\
print('CONNECT-OK')";
        let command = vec![
            OsString::from("/usr/bin/python3"),
            OsString::from("-c"),
            OsString::from(script),
        ];
        let (code, out, err) = run_in_child(move |o| match run_sandboxed(&command, &config) {
            Ok(code) => code,
            Err(e) => {
                let _ = writeln!(o.err(), "run_sandboxed: {e:#}");
                2
            }
        });
        match code {
            Some(0) => {}
            Some(other) => panic!(
                "the tagged-socket run exited with {other} — with no running \
                 compositor the tagging fails before the fork and the \
                 error below says so:\n{out}\n{err}"
            ),
            None => panic!("the test harness failed:\n{out}\n{err}"),
        }
        // 5.3: the environment `run` gave the app.
        assert!(
            out.contains("WD=wl-probe\n")
                && out.contains(&format!("XDG={sandbox_runtime}\n")),
            "the app's WAYLAND_DISPLAY/XDG_RUNTIME_DIR are not what run sets \
             (expected WD=wl-probe, XDG={sandbox_runtime}):\n{out}\n{err}"
        );
        // 5.1: the socket file is in the sandbox, at the in-sandbox
        // instance dir.
        assert!(
            out.contains("FILE-OK\n"),
            "the tagged socket file is not in the sandbox:\n{out}\n{err}"
        );
        // The app's connect reached the listener the compositor holds
        // (the tag succeeded pre-fork) and the supervisor let it
        // through.
        assert!(
            out.contains("CONNECT-OK\n"),
            "the app could not connect to the tagged socket:\n{out}\n{err}"
        );

        // 5.2: the run is over and with it S's listener copy and the
        // reference pipe: the file remains (nothing unlinks it) but
        // no longer serves.
        assert!(
            std::fs::symlink_metadata(&host_socket)
                .map(|m| m.file_type().is_socket())
                .unwrap_or(false),
            "the socket file {host_socket} is gone after the run (it should remain, stale)"
        );
        match UnixStream::connect(&host_socket) {
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {}
            other => panic!(
                "the tagged socket still serves after the run (the tag was \
                 not released): {other:?}"
            ),
        }

        // Tidy: the stale socket and the per-instance dir.
        let _ = std::fs::remove_file(&host_socket);
        let _ = std::fs::remove_dir_all(&host_runtime);
    }
}
