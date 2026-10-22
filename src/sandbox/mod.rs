//! The in-process sandbox (PLAN.md): the namespace set
//! (user → mount → pid → ipc → uts → cgroup → net), the private
//! rootfs, and the landlock + seccomp policy applied via `nono`.
//!
//! Phase 1: the user namespace and the credential model ([userns] —
//! the single-extent map, decision #10). Phase 2: the remaining
//! namespaces ([namespaces]) and the double-fork in [run_sandboxed]
//! that makes the app PID 1 of a fresh pid namespace. Phases 3
//! (rootfs) and 4 (nono) fill in the marked slots in [run_sandboxed].

pub(crate) mod namespaces;
pub(crate) mod userns;

use anyhow::{Context, Result, anyhow, bail};
use log::error;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{ForkResult, fork};
use std::ffi::OsString;
use std::os::unix::process::CommandExt;

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
}

/// Run `command` inside the full namespace set, as our real uid
/// (PLAN.md §3; decisions #9, #10, #12, #14). Returns the command's
/// exit code.
///
/// Topology (PLAN §3.2):
///
/// ```text
/// S (wlsctx — outside every namespace)
/// ├─ A: user → mount → pid ns; forks B; reaps B, exits with B's status
/// │  └─ B: ipc → uts → cgroup → net (per mode) → verify → exec (PID 1)
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

    // SAFETY: fork(2) from a single-threaded point in the process
    // lifecycle; the parent only handles `child` below.
    match unsafe { fork() }.context("forking the sandbox child")? {
        // A: the intermediate child. Everything from here on runs in
        // the user/mount/pid namespaces we claim below; on success we
        // never return (we exit with the app's status).
        ForkResult::Child => {
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
                    // B: the app. The remaining namespaces, the
                    // credential check, and the exec.
                    if let Err(e) = (|| -> Result<()> {
                        namespaces::enter_ipcns()?;
                        namespaces::enter_utsns(&hostname)?;
                        namespaces::enter_cgroupns(&namespaces::cgroup_name_for(
                            &config.app_id,
                            &config.instance_id,
                        ))?;
                        if config.network == namespaces::NetworkMode::None {
                            namespaces::enter_netns()?;
                        }
                        userns::verify_locked(&creds)
                    })() {
                        error!("sandbox setup failed: {e:#}");
                        std::process::exit(126);
                    }
                    // (Phase 3 slot: rootfs construction; we hold the
                    //  full ns capability set — the map, not a drop,
                    //  locks the identity)
                    // (Phase 4 slot: nono landlock + seccomp, then exec)
                    exec_app(command);
                }
                ForkResult::Parent { child } => {
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
            // S (us): reap A, which carries B's status.
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
            // Best-effort cleanup of the per-instance sub-cgroup: the
            // app is dead, so it is empty (a parallel instance sharing
            // the name may still hold it — that just makes the rmdir
            // fail with ENOTEMPTY, which we ignore).
            if let Err(e) = std::fs::remove_dir(&sub_cgroup) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    log::warn!("cleaning up the sub-cgroup {sub_cgroup} failed: {e}");
                }
            }
            Ok(code)
        }
    }
}

/// Replace this (child) process with `command`. Never returns on
/// success; on failure the error is logged and the child exits with
/// 126.
fn exec_app(command: &[OsString]) -> ! {
    let (program, args) = command
        .split_first()
        .expect("command is non-empty (checked in run_sandboxed)");
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    // On success exec(3) never returns: this process is replaced. The
    // returned error means the exec itself failed (bad path,
    // permissions, …).
    let e = cmd.exec();
    error!("exec of {command:?} failed: {e}");
    std::process::exit(126);
}
