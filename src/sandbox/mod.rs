//! The in-process sandbox (PLAN.md): the namespace set
//! (user → mount → pid → ipc → uts → cgroup → net), the private
//! rootfs, and the landlock + seccomp policy applied via `nono`.
//!
//! Phase 1: the user namespace and the non-root credential sequence
//! ([userns]), plus the `wlsctx run -- <cmd>` path that executes a
//! command through it. The later phases fill in the marked slots in
//! [run_sandboxed].

pub(crate) mod userns;

use anyhow::{Context, Result, anyhow};
use log::error;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{ForkResult, fork};
use std::ffi::OsString;
use std::os::unix::process::CommandExt;

/// Run `command` inside a new user namespace, as our real uid
/// (PLAN.md §3.1, decision #9). Returns the command's exit code.
///
/// All namespace work happens in a forked child: wlsctx itself stays
/// *outside* the namespaces, so the app remains a normal, reappable
/// child for signalling and `waitpid`. (In the pid-namespace phase
/// the app becomes PID 1 one fork deeper; the parent of this fork
/// is always our process — PLAN.md §3.2.)
///
/// Setup failures inside the child are reported on stderr and exit
/// with 126 (the shell convention for "cannot execute").
pub(crate) fn run_sandboxed(command: &[OsString]) -> Result<i32> {
    if command.is_empty() {
        return Err(anyhow!("no command to run"));
    }
    let creds =
        userns::Credentials::current().context("reading the current uid/gid (getresuid/getresgid)")?;

    // SAFETY: fork(2) from a single-threaded point in the process
    // lifecycle; the parent only handles `child` below.
    match unsafe { fork() }.context("forking the sandbox child")? {
        // The child: everything from here runs inside the new user
        // namespace. On success we never return (we exec).
        ForkResult::Child => {
            if let Err(e) = userns::enter_userns(&creds) {
                error!("user namespace setup failed: {e:#}");
                std::process::exit(126);
            }
            // (Phase 2 slot: mount, pid, ipc, uts, cgroup, net namespaces)
            // (Phase 3 slot: rootfs construction, while we are ns-root)
            if let Err(e) = userns::drop_ns_root(&creds) {
                error!("dropping to the real uid failed: {e:#}");
                std::process::exit(126);
            }
            // (Phase 4 slot: nono landlock + seccomp, then exec)
            exec_app(command);
        }
        ForkResult::Parent { child } => match waitpid(Some(child), None).context("waiting for the sandbox child")? {
            WaitStatus::Exited(_, code) => Ok(code),
            // 128+signal, the shell convention.
            WaitStatus::Signaled(_, sig, _) => Ok(128 + sig as i32),
            other => Err(anyhow!("unexpected wait status for the sandbox child: {other:?}")),
        },
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
