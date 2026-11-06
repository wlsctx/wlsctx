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
use log::{debug, error, info, warn};
use nix::errno::Errno;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork};
use std::ffi::OsString;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::process::CommandExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Instant;

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
/// The pdeathsig cascade (decision #42) covers S dying without a
/// controlled exit (a SIGKILL, a crash): A carries
/// pdeathsig←S(`SIGUSR1`) and kills B, and B carries
/// pdeathsig←A — re-armed across its confined exec by the
/// `LD_PRELOAD` shim (`wlsctx::pdeathsig`) — so no member of the
/// lineage is left behind unsupervised.
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
    // Phase 8.2 (MCS): confine before S touches anything — the exec
    // context narrows our range to the instance's category and
    // re-execs us once (a no-op in unconfined mode and on the
    // post-re-exec invocation, which is the loop guard). Everything
    // S creates from here (instance dir, scratch, tagged socket,
    // sidecars) inherits the category. Must run before the signal
    // block below: execve resets the mask.
    wlsctx::mcs::self_reexec_with_category(&config.app_id, &config.instance_id)?;
    namespaces::validate_id(&config.app_id, "--app-id")?;
    namespaces::validate_id(&config.instance_id, "--instance-id")?;
    let hostname = namespaces::hostname_for(&config.app_id, &config.instance_id);
    if hostname.len() > 64 {
        bail!(
            "hostname {hostname:?} is {} bytes; the kernel limit is 64 (shorten --app-id/--instance-id)",
            hostname.len()
        );
    }
    let creds = userns::Credentials::current()
        .context("reading the current uid/gid (getresuid/getresgid)")?;

    // 5.4, amended in Phase 6: block the forwardable signals
    // (TERM/INT/HUP) on this thread before the session-bus scope
    // call below. That call is driven on a tokio runtime built in
    // `src/systemd.rs` — a *current-thread* one: a fresh local
    // runtime per call (never a process-global one), and
    // current-thread rather than multi-thread so that no background
    // workers outlive the drop and linger across the fork that
    // follows (`src/systemd.rs::with_local_runtime`). It therefore
    // runs on *this* thread, which is why the block must be in place
    // here: while `S` is blocked inside the D-Bus `block_on`, an
    // unblocked default-action SIGTERM would take the whole process
    // down before the forwarder could service it. Blocked here, the
    // three signals stay pending on every thread of the process; the
    // forwarder (S branch, below) routes each to the app (decision
    // #33). A keeps the block (it must survive a group-wide signal
    // until it has reaped B); B unblocks before exec, so the app
    // keeps its historical (unblocked) behavior.
    let mut fwd_mask = nix::sys::signal::SigSet::empty();
    for sig in [
        nix::sys::signal::Signal::SIGTERM,
        nix::sys::signal::Signal::SIGINT,
        nix::sys::signal::Signal::SIGHUP,
    ] {
        fwd_mask.add(sig);
    }
    let fwd_mask = match fwd_mask.thread_block() {
        Ok(()) => Some(fwd_mask),
        Err(e) => {
            log::warn!(
                "blocking the forwardable signals failed: {e}; \
                 signal forwarding disabled"
            );
            None
        }
    };

    // Phase 6 (#35): before any fork, move `S` into a transient
    // systemd scope on the user session bus. Afterwards both this
    // function's `sub_cgroup` and A's pre-unshare cgroup capture
    // (decision #20) root under the scope, and systemd removes the
    // scope *and its children* recursively when `S` — the last
    // member — exits. Any failure degrades to the raw-cgroup tier:
    // the sandbox itself is unchanged, the run simply has no unit
    // visibility/accounting, and the instance sub-cgroup is created
    // under `S`'s current cgroup instead (see `ScopeTier::
    // Unavailable`). A run is never aborted over this.
    let scope_unit = format!("wlsctx-{}-{}.scope", config.app_id, config.instance_id);
    match crate::systemd::attach_scope(&scope_unit, &format!("wlsctx sandbox: {}", config.app_id)) {
        crate::systemd::ScopeTier::Joined { unit } => {
            debug!("cgroup accounting: systemd scope {unit}")
        }
        crate::systemd::ScopeTier::Unavailable(reason) => {
            debug!("cgroup accounting: raw cgroup (no systemd unit: {reason})")
        }
    }

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
    let runtime_dir = mounts::instance_runtime_dir(config);
    std::fs::create_dir_all(&runtime_dir)
        .with_context(|| format!("creating the per-instance runtime dir {runtime_dir}"))?;
    // decision #42: the pdeathsig-restore shim (B's post-exec
    // re-arm; see `wlsctx::pdeathsig`), built here — before any
    // fork — into the instance runtime dir, which the rootfs carry
    // brings into the sandbox at `sandbox_runtime` (defined below).
    // Only in confined mode: a confined exec changes the process's
    // SID, and the kernel unconditionally clears pdeathsig on any
    // SID change (`selinux_bprm_committing_creds`,
    // `security/selinux/hooks.c:2545`); unconfined, the pre-exec
    // setting below already survives the exec, and there is no
    // reason to put an `LD_PRELOAD` in front of the app. A failed
    // build (or relabel) degrades to the pre-exec belt alone
    // (logged in `ensure_shim`) — an app's launch must never
    // depend on the shim existing.
    let shim = if wlsctx::mcs::is_confined() {
        wlsctx::pdeathsig::ensure_shim(&runtime_dir, libc::SIGUSR1)
    } else {
        None
    };
    // The same dir's path *inside the sandbox* (the fresh `/run`'s
    // systemd-standard location, decision #28). The policy grants
    // and the app's env use this string: it is the one the app sees,
    // and it equals the host path only for the default XDG.
    let sandbox_runtime = mounts::sandbox_instance_dir(config);

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
                // No fork happened, so this run leaves nothing that
                // outlives the process — but the dir may hold a live
                // sidecar's socket (a relay sharing the instance dir),
                // which a blind `remove_dir_all` would destroy
                // (decision #40).
                remove_runtime_dir(&runtime_dir, None);
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
    let (sock_a, sock_s) = supervise::create_socketpair().context("creating the S↔A socketpair")?;
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
            // decision #42: the pdeathsig cascade, first link
            // (A←S): whenever S dies — a SIGKILL, a crash, anything
            // the AppKillGuard cannot intercept — the kernel queues
            // SIGUSR1 at us. SIGUSR1, deliberately not SIGTERM: A
            // keeps the pre-fork block on TERM/INT/HUP (below), and
            // a pdeathsig that lands in a block stays *pending*
            // forever and would never be delivered, while the block
            // itself must stay (a group-wide Ctrl-C must not kill
            // A before it reaps B). Nothing else in the pipeline
            // sends USR1, so the signal means exactly "S is gone".
            // A never execs, so the setting survives (unlike B's —
            // see the shim). 7.2 `fork` resets the value to 0 (it
            // is *not* inherited), so B arms its own link itself,
            // explicitly, right before its exec.
            if !wlsctx::pdeathsig::set(libc::SIGUSR1) {
                let e = std::io::Error::last_os_error();
                error!(
                    "A: setting the pdeathsig failed: {e}; \
                     the S-death backstop is off for this run"
                );
            }
            // A *keeps* the pre-fork block on the forwardable
            // signals: it must survive a group-wide TERM/INT/HUP
            // (Ctrl-C, `timeout`, systemd's kill) until it has
            // reaped B — if A died first, S would end the run while
            // the app is still alive and the supervisor is gone,
            // and the app's trapped syscalls would all fail,
            // freezing it on screen (B unblocks them before exec,
            // below).
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
            let cgroup_name = namespaces::cgroup_name_for(&config.app_id, &config.instance_id);
            if let Err(e) = namespaces::enter_cgroupns(&cgroup_name) {
                error!("cgroup namespace setup failed: {e:#}");
                std::process::exit(126);
            }
            if let Err(e) = mounts::build_rootfs(config) {
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
                    // The app keeps its historical (unblocked)
                    // signal behavior: undo the inherited pre-fork
                    // block so the exec'd app receives TERM/INT/HUP
                    // normally (a handler runs only for unblocked
                    // signals; B is pid 1 of its own pid namespace,
                    // so default-action delivery is ignored
                    // regardless — decision #13).
                    if let Some(m) = &fwd_mask
                        && let Err(e) = m.thread_unblock()
                    {
                        log::warn!("B: unblocking the forwardable signals failed: {e}");
                    }
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
                        // Phase 8.2 (MCS): carry the instance's
                        // category into the app's exec (the module's
                        // `wlsctx_t → wlsctx_app_t` dyntransition).
                        // This must happen *before* `policy::apply`
                        // below: the openat of `/proc/self/attr/exec`
                        // would then be trapped by the seccomp-notify
                        // filter and answered `EACCES` by the
                        // supervisor (`/proc` is Read-only in the
                        // capability set), and denied by the Landlock
                        // floor for the same reason — the write only
                        // works from a floor-less `wlsctx_t` process,
                        // like S's. A write failure just drops the
                        // range (logged); the exec goes on.
                        if let Err(e) = wlsctx::mcs::set_exec_context("wlsctx_app_t") {
                            warn!("{e}");
                        }
                        // Phase 4: build the single capability set that
                        // drives both floors, install the combined
                        // filter first, then the Landlock floor (the
                        // filter must precede Landlock — decision #22).
                        let caps =
                            policy::capability_set(config, std::path::Path::new(&sandbox_runtime))
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
                            _ => bail!(
                                "the supervisor handoff did not complete; refusing to exec an unsupervised process"
                            ),
                        }
                    })() {
                        error!("sandbox setup failed: {e:#}");
                        std::process::exit(126);
                    }
                    // decision #42: B's link in the cascade (B←A).
                    // 7.2 `fork` reset the value to 0, so this set
                    // is an arming, not a re-arm (the belt). In
                    // confined mode the shim (the bridle) re-arms
                    // it *after* the transition: the confined exec
                    // (`wlsctx_t` → `wlsctx_app_t`) changes the
                    // process's SID, and `selinux_bprm_committing_creds`
                    // (`security/selinux/hooks.c:2545`, commit
                    // `4ac212ad4e8f`) *unconditionally* zeros
                    // `pdeath_signal` on any SID change — no
                    // permission (not even the granted `noatsecure`)
                    // can prevent it. (The legacy `secureexec`
                    // clear in `fs/exec.c` — set on a *denied*
                    // `noatsecure` check, setuid, or a capability
                    // change — and `commit_creds`'s independent
                    // clear on an actual credential change are
                    // secondary: this policy grants `noatsecure` on
                    // this transition, and the uid/caps are
                    // unchanged.) In unconfined mode the exec
                    // changes no SID, the belt survives as is, and
                    // no shim is built (above) or loaded.
                    // `prctl` is not trapped by the filter
                    // installed above, so the constructor is safe
                    // to run under it; the loader's `openat` of the
                    // `.so` is trapped and allowed (the file sits in
                    // the app's own writable runtime dir).
                    if !wlsctx::pdeathsig::set(libc::SIGUSR1) {
                        let e = std::io::Error::last_os_error();
                        warn!("B: re-arming the pdeathsig failed: {e}");
                    }
                    let mut env = app_env(config, &runtime_dir);
                    if let Some(shim) = &shim {
                        let shim_in = std::path::Path::new(&sandbox_runtime)
                            .join(shim.file_name().expect("the shim path has a file name"));
                        let shim_s = shim_in.to_string_lossy().into_owned();
                        // Append, never clobber: a profile may set
                        // its own LD_PRELOAD.
                        if let Some(existing) = env.get("LD_PRELOAD").cloned() {
                            env.insert("LD_PRELOAD".into(), format!("{existing}:{shim_s}"));
                        } else {
                            env.insert("LD_PRELOAD".into(), shim_s);
                        }
                    }
                    exec_app(command, &env);
                }
                ForkResult::Parent { child } => {
                    // decision #42: install the pdeathsig handler
                    // now — *after* the second fork, so B does not
                    // inherit it (B's USR1 stays at its default
                    // disposition: a delivery to B kills B, which
                    // is the pre-exec answer to "A is gone"; B's
                    // exec resets the handler again, and in
                    // confined mode the loader re-arms the
                    // *signal*). The handler only sets a flag (a
                    // single word store — the only
                    // async-signal-safe action it takes); the
                    // actual teardown runs in normal context
                    // below, woken by the `EINTR` the delivery
                    // causes in A's blocking operations. `sa_mask`
                    // is A's current block, so the TERM/INT/HUP
                    // block is not dropped for the handler's
                    // duration (an empty `sa_mask` would unblock
                    // them while the handler runs).
                    {
                        let mask = match &fwd_mask {
                            Some(m) => *m,
                            None => nix::sys::signal::SigSet::empty(),
                        };
                        let act = nix::sys::signal::SigAction::new(
                            nix::sys::signal::SigHandler::Handler(a_s_gone_handler),
                            nix::sys::signal::SaFlags::empty(),
                            mask,
                        );
                        // SAFETY: a valid handler and a valid mask
                        // (A's own block or empty); no SA_SIGINFO.
                        if let Err(e) = unsafe {
                            nix::sys::signal::sigaction(nix::sys::signal::Signal::SIGUSR1, &act)
                        } {
                            warn!(
                                "A: installing the pdeathsig handler failed: {e}; \
                                 the S-death backstop is off for this run"
                            );
                        }
                    }
                    // A is done with the B→A pipe's write end (B holds
                    // the only writer now) — close our copy *before*
                    // blocking on the read below: if B dies before
                    // writing (any setup failure) its copy is released
                    // at exit, and with ours closed the read sees EOF
                    // instead of blocking forever (our copy would
                    // otherwise be the pipe's last writer, holding the
                    // read open past B's death — a zombie B releases
                    // its fds at exit, so only A's copy would remain).
                    unsafe { libc::close(pw) };
                    // Read the listener's fd number B wrote, complete
                    // the handoff (decision #23) — as B's direct
                    // parent, the one process Yama `restricted` lets
                    // `pidfd_getfd` B, extract a copy of B's listener
                    // into our own table and `SCM_RIGHTS` it to S —
                    // and send B the verdict (decision #26): this
                    // runs while B is still pre-exec (blocked in
                    // `wait_ack`), so the extract cannot race the
                    // exec. On failure we tell B to die: the Landlock
                    // floor B installed still holds, and we just reap
                    // and propagate B's status.
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
                                    // 5.4: report B's host-visible pid to S,
                                    // right after the listener, so S can
                                    // signal the app (A is outside the new
                                    // pid ns, so this is the pid S sees).
                                    // If the send fails the run continues
                                    // un-signalled: the floors still hold.
                                    let _ = supervise::send_app_pid(sa, child.as_raw());
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
                    // `EINTR` is retried, never fatal (decision #41):
                    // A inherits S's narrow signal block (the three
                    // forwarded signals only), so any other signal
                    // that reaches it interrupts this wait — and a
                    // fatal `EINTR` here used to exit 126 *without*
                    // reaping B, leaving B (reparented to the host
                    // init) running on forever, unsupervised.
                    // decision #42: if the pdeathsig was delivered
                    // while A was in one of its fast (non-blocking)
                    // operations, tear down before entering the
                    // blocking wait.
                    a_pdeath_check(child.as_raw());
                    let code = match waitpid_retry(child, "the app child", Some(&A_S_GONE)) {
                        Ok(WaitStatus::Exited(_, code)) => code,
                        Ok(WaitStatus::Signaled(_, sig, _)) => 128 + sig as i32,
                        Ok(other) => {
                            error!("unexpected wait status for the app child: {other:?}");
                            126
                        }
                        // The pdeathsig escape (see `waitpid_retry`):
                        // S is gone — kill B and leave.
                        Err(e) if e.downcast_ref::<Errno>() == Some(&Errno::EINTR) => {
                            a_tear_down(child.as_raw());
                        }
                        Err(e) => {
                            error!("waiting for the app child failed: {e:#}");
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
            // 5.4/Phase 6: this thread already has the forwardable
            // signals (TERM/INT/HUP) blocked — the block was moved
            // ahead of the session-bus scope call (before any fork or
            // thread exists) so that even the zbus/tokio worker
            // threads inherit it, and no default-action delivery can
            // kill the process during the handoff. The forwarder
            // thread (below) reads them from a signalfd and turns
            // each into a signal at the app; if the earlier block
            // failed, `fwd_mask` is `None` and forwarding is disabled
            // (the pre-5.4 behavior) — the run itself does not
            // depend on it.
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
            let flags = Arc::new(AppSignalFlags::default());
            let mut supervisor: Option<std::thread::JoinHandle<()>> = None;
            // Assigned in both arms below (armed or not).
            let forwarder: Option<std::thread::JoinHandle<()>>;
            // decision #41: armed once the handoff completes, held to
            // the end of the run (see the struct's docs).
            let mut kill_guard = AppKillGuard::disarmed();
            let handoff_ok = match supervise::recv_fd(ss) {
                Ok(Some(notify)) => {
                    // 5.4: A reported B's host-visible pid right after
                    // the listener (same socket, same order).
                    let app_pid = match supervise::recv_app_pid(ss) {
                        Ok(Some(p)) => Some(p),
                        _ => {
                            log::debug!("S: no app pid reported; forwarding disabled");
                            None
                        }
                    };
                    // decision #41: the app is running; from this
                    // instant, any exit of this process must not
                    // leave its lineage behind (see the guard).
                    kill_guard.sub_cgroup = Some(sub_cgroup.clone());
                    unsafe { libc::close(ss) };
                    log::debug!(
                        "S[{}]: got the listener (fd {})",
                        std::process::id(),
                        notify.as_raw_fd()
                    );
                    match policy::capability_set(config, std::path::Path::new(&sandbox_runtime)) {
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
                    forwarder = arm_signal_forwarder(
                        fwd_mask.as_ref(),
                        app_pid,
                        Arc::clone(&flags),
                        Arc::clone(&stop),
                    );
                    // 5.4: sd-notify — the app is running (or about
                    // to exec), so the unit is up. No-op (and
                    // `Ok`) when `$NOTIFY_SOCKET` is unset; a send
                    // failure (socket gone) is logged, not fatal.
                    if let Err(e) = sd_notify::notify(&[sd_notify::NotifyState::Ready]) {
                        log::debug!("sd-notify READY=1: {e}");
                    }
                    true
                }
                _ => {
                    // EOF (B died before the handoff) or a recv error:
                    // nothing to supervise; the floor still holds in
                    // whatever B ran.
                    unsafe { libc::close(ss) };
                    log::debug!("S: no supervisor (handoff did not complete)");
                    // 5.4: arm the forwarder anyway (there is no app
                    // pid to signal): a TERM/INT in this short window
                    // is a clean shutdown (S exits 0, below) rather
                    // than a signal stuck blocked, and a HUP keeps
                    // its 129.
                    forwarder = arm_signal_forwarder(
                        fwd_mask.as_ref(),
                        None,
                        Arc::clone(&flags),
                        Arc::clone(&stop),
                    );
                    false
                }
            };

            // Reap A, which carries B's status. `EINTR` is retried,
            // never fatal (decision #41): S blocks only the three
            // signals it forwards, so any other signal that reaches
            // it (a terminal session's TSTP/TTIN/TTOU/CHLD — even a
            // plain SIGSTOP→SIGCONT cycle) interrupts the blocking
            // wait, and a fatal `EINTR` here used to kill S — and
            // with it the forwarder thread, whose TERM→KILL
            // escalation is the only thing keeping B finite.
            let code = match waitpid_retry(child, "the sandbox child", None)? {
                WaitStatus::Exited(_, code) => code,
                // 128+signal, the shell convention.
                WaitStatus::Signaled(_, sig, _) => 128 + sig as i32,
                other => {
                    return Err(anyhow!(
                        "unexpected wait status for the sandbox child: {other:?}"
                    ));
                }
            };
            // The app (and A) are gone: tell the supervisor and the
            // forwarder to stop and join them (each exits within one
            // poll tick; the forwarder's signalfd closes with its
            // thread).
            stop.store(true, Ordering::Relaxed);
            if let Some(t) = supervisor {
                let _ = t.join();
            }
            if let Some(t) = forwarder {
                let _ = t.join();
            }
            // 5.2/5.4: the tagged Wayland socket closes exactly now
            // that the app is dead: dropping S's listener copy and
            // the reference pipe is what triggers the compositor's
            // untag (the pipe's EOF), and that happens no later than
            // this point. The path is captured before the drop: the
            // cleanup below unlinks that one file by path (the untag
            // already happened; a liveness probe could still be
            // accepted by the compositor's now-dying dup).
            let own_tagged = tagged.as_ref().map(|t| t.host_path.clone());
            drop(tagged);
            // Best-effort cleanup of the per-instance sub-cgroup: the
            // app is dead, so it is empty (a parallel instance sharing
            // the name may still hold it — that just makes the rmdir
            // fail with ENOTEMPTY, which we ignore).
            if let Err(e) = std::fs::remove_dir(&sub_cgroup)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                log::warn!("cleaning up the sub-cgroup {sub_cgroup} failed: {e}");
            }
            // Best-effort removal of the rootfs scratch (its mounts
            // died with the children's mount ns; the directory
            // itself is a plain host directory on /var/tmp).
            let scratch = mounts::rootfs_scratch_dir(config);
            if let Err(e) = std::fs::remove_dir_all(&scratch)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                log::warn!("cleaning up the rootfs scratch {scratch} failed: {e}");
            }
            // The scratch's parent may be left empty (a sibling
            // instance still running makes this ENOTEMPTY — ignored).
            if let Some(parent) = std::path::Path::new(&scratch).parent() {
                let _ = std::fs::remove_dir(parent);
            }
            // 5.4: the per-instance runtime dir is no longer needed
            // (the tagged socket, and whatever the app created in
            // it). The step-1 carry is a *bind*, so the dir is still
            // at its host path (decision #28). But the dir is
            // *shared*: a long-lived sidecar (the `--proxy` relay,
            // `dbus-proxy`, `xwayland`) may bind its public socket
            // here too, and a blind `remove_dir_all` would destroy a
            // running sidecar's socket file (decision #40) — so the
            // removal spares the live ones.
            remove_runtime_dir(&runtime_dir, own_tagged.as_deref());
            // 5.4: the signals S was asked to stop on override the
            // app's status: HUP keeps the historical `wlsctx`
            // semantics — 129 (128+SIGHUP) — and a TERM/INT that
            // reached S with no app to forward to (handoff failure)
            // is a clean shutdown (0). When the app ran, its status
            // (possibly after the forwarded-and-escalated stop) wins.
            let code = if flags.hup.load(Ordering::Relaxed) {
                129
            } else if flags.term.load(Ordering::Relaxed) && !handoff_ok {
                0
            } else {
                code
            };
            Ok(code)
        }
    }
}

/// Best-effort removal of the per-instance runtime dir that spares
/// the **live** sockets of the sidecars sharing it (decision #40).
///
/// The `--proxy` relay, the `dbus-proxy` sidecar, and the `xwayland`
/// satellite all bind their public socket inside the same
/// per-instance runtime dir the `run` pipeline creates. A blind
/// `remove_dir_all` (the historical behaviour) destroyed a running
/// sidecar's socket file: its listener fd survives the unlink, but
/// the path is gone, so the next `run`'s carry handed the sandbox an
/// empty dir and the app found no compositor ("no compositor
/// running?"). The sidecar's own `--listen` path therefore outlives
/// every `run`:
///
/// * every **socket** file in the dir is liveness-probed with
///   `connect(2)` — the same test
///   [`crate::wayland::listener::bind_socket`] uses when it refuses
///   to steal a socket — and kept while a live process serves it
///   (a successful connect; the probe connection is dropped
///   straight away). A refused connect is a stale socket of a dead
///   server and is removed, exactly as `remove_dir_all` used to.
///   A probe that fails for any other reason keeps the file: never
///   destroy what cannot be identified.
/// * S's **own** tagged socket (`own_tagged`; it is served by the
///   compositor's dup, not by this process, and the compositor's
///   now-dying dup could still accept a probe) is unlinked by path
///   without probing, as before.
/// * everything else — the app's per-run state, dead sidecars'
///   leftovers, subdirectories — is removed recursively, as before.
/// * finally the dir itself is `rmdir`'d: it survives (logged)
///   while a kept socket remains in it, and is removed the first
///   time a run tears down with nothing live left — the cleanup is
///   lazy, and the sidecar never has to do it for itself.
///
/// All steps are best-effort: a failure here only loses hygiene,
/// never the run's result.
fn remove_runtime_dir(dir: &str, own_tagged: Option<&str>) {
    let dir = std::path::Path::new(dir);
    let mut kept = 0usize;
    sweep_runtime_dir(dir, own_tagged, &mut kept);
    match std::fs::remove_dir(dir) {
        Ok(()) => debug!("runtime dir removed: {dir:?}"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty && kept > 0 => {
            info!(
                "instance dir {dir:?} kept: {kept} live sidecar socket(s) share it \
                 (the sidecar outlives this run; the next run will re-expose the \
                 socket through the carry)"
            );
        }
        Err(e) => warn!("cleaning up the runtime dir {dir:?} failed: {e}"),
    }
}

/// One level of [`remove_runtime_dir`]: remove every entry of `dir`
/// except a socket file a live process serves (and is not
/// `own_tagged`); recurse into subdirectories.
fn sweep_runtime_dir(dir: &std::path::Path, own_tagged: Option<&str>, kept: &mut usize) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            warn!(
                "cleaning the runtime dir {}: read_dir failed: {e}",
                dir.display()
            );
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!("cleaning the runtime dir {}: {e}", dir.display());
                continue;
            }
        };
        let path = entry.path();
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    "cleaning {}: stat {} failed: {e}; leaving it in place",
                    dir.display(),
                    path.display()
                );
                continue;
            }
        };
        if meta.file_type().is_socket() {
            if own_tagged.is_some_and(|o| same_path(&path, o)) {
                // S's own tagged socket: the untag already happened
                // with the listener drop; unlink it by path without
                // probing (see [`remove_runtime_dir`]).
                let _ = std::fs::remove_file(&path);
                continue;
            }
            match std::os::unix::net::UnixStream::connect(&path) {
                Ok(conn) => {
                    // A live process serves this path: keep it. The
                    // probe's connection is dropped here; the server
                    // (a relay) sees one instantly-closed connection.
                    drop(conn);
                    *kept += 1;
                    info!(
                        "keeping {}: served by a live sidecar sharing the \
                         instance dir",
                        path.display()
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    // A stale socket of a dead server: removed, as
                    // `remove_dir_all` used to.
                    let _ = std::fs::remove_file(&path);
                }
                Err(e) => {
                    warn!("cannot liveness-probe {} ({e}); keeping it", path.display());
                    *kept += 1;
                }
            }
        } else if meta.file_type().is_dir() {
            sweep_runtime_dir(&path, own_tagged, kept);
            if let Err(e) = std::fs::remove_dir(&path)
                && e.kind() != std::io::ErrorKind::NotFound
                && e.kind() != std::io::ErrorKind::DirectoryNotEmpty
            {
                warn!(
                    "cleaning {}: rmdir {} failed: {e}",
                    dir.display(),
                    path.display()
                );
            }
        } else {
            // A regular file, symlink, or fifo: per-run app state —
            // gone, as before.
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Path equality that tolerates a symlinked ancestor: canonicalize
/// both sides when possible, fall back to a byte comparison.
fn same_path(a: &std::path::Path, b: &str) -> bool {
    match (a.canonicalize(), std::path::Path::new(b).canonicalize()) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == std::path::Path::new(b),
    }
}

/// The signals S was asked to stop on, as seen by the forwarder
/// thread (Phase 5.4): read by S after the app is reaped to choose
/// the exit status (HUP → 129; TERM/INT with no app → 0).
#[derive(Default)]
struct AppSignalFlags {
    term: AtomicBool,
    hup: AtomicBool,
}

/// The signal-forwarder thread (Phase 5.4).
///
/// S has blocked SIGTERM/SIGINT/SIGHUP on every thread of the
/// `wlsctx` process (the S main thread before it spawned anyone,
/// every spawned thread inherits it), so the kernel delivers them
/// to the signalfd instead of acting on them. Each one becomes a
/// stop request for the **app**:
///
/// * TERM/INT — a courtesy TERM to the app, then an escalation to
///   SIGKILL if the app is still alive after a 2s grace: the app is
///   PID 1 of its own pid namespace and **ignores** default-action
///   signals that come from outside the namespace (decision #13), so
///   the escalation is the actual stop. The `term` flag is set
///   regardless (S exits 0 when no app was running to forward to).
/// * HUP — the same termination, plus the `hup` flag: S exits with
///   129 (128+SIGHUP), the long-standing `wlsctx` semantics.
///
/// The thread exits when `stop` is set (the app is reaped); the
/// signalfd closes with the thread (`O_CLOEXEC`).
fn app_signal_forwarder(
    fd: nix::sys::signalfd::SignalFd,
    app_pid: Option<i32>,
    flags: Arc<AppSignalFlags>,
    stop: Arc<AtomicBool>,
) {
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let sig = match fd.read_signal() {
            Ok(Some(si)) => si.ssi_signo as i32,
            Ok(None) => {
                // EAGAIN (SFD_NONBLOCK): no signal yet.
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            Err(e) => {
                log::warn!("signal forwarder: signalfd read failed: {e}");
                break;
            }
        };
        match sig {
            libc::SIGHUP => flags.hup.store(true, Ordering::Relaxed),
            libc::SIGTERM | libc::SIGINT => flags.term.store(true, Ordering::Relaxed),
            // Only the blocked set can arrive; anything else is a
            // programming error and ignored on purpose.
            _ => continue,
        }
        if let Some(pid) = app_pid {
            terminate_app(pid, &stop);
        }
    }
}

/// Stop the app: a courtesy TERM, then — because the app is PID 1
/// of its own pid namespace and ignores default-action signals from
/// outside it (decision #13) — a SIGKILL escalation after a 2s
/// grace, bounded by `stop` (the app was reaped meanwhile).
fn terminate_app(pid: i32, stop: &Arc<AtomicBool>) {
    // SAFETY: signalling a pid that was valid when reported; a
    // failure (ESRCH: already gone) is exactly the desired state.
    let _ = unsafe { libc::kill(pid, libc::SIGTERM) };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        // SAFETY: as above; 0 = probe.
        let alive = unsafe { libc::kill(pid, 0) } == 0;
        if !alive {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ESRCH) {
                return; // gone
            }
            // A probe failure other than ESRCH (EPERM: should be
            // impossible — we created this process): keep polling
            // rather than escalating on a spurious error.
            if Instant::now() >= deadline {
                let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        }
        if Instant::now() >= deadline {
            // The courtesy TERM was ignored (pid-ns init): escalate.
            let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// decision #42: set by A's SIGUSR1 handler (the pdeathsig: S has
/// died), consumed by A's loops and teardown. A plain `i32` is a
/// `sig_atomic_t` on this platform: the handler's single-word
/// store is atomic on this architecture, which is the whole of its
/// async-signal-safe work. A is single-threaded, so there is no
/// other writer and no synchronization beyond that.
static A_S_GONE: AtomicI32 = AtomicI32::new(0);

/// A's pdeathsig handler (decision #42): set the flag and return.
/// The teardown deliberately does *not* run here — a signal handler
/// may only do async-signal-safe work, and the teardown's logging
/// and `kill` sequence belongs in normal context. The delivery
/// interrupts A's blocking `waitpid` with `EINTR`, and that is the
/// wake-up. The only action is the single word store (a
/// `sig_atomic_t` on this platform), which is atomic on this
/// architecture.
extern "C" fn a_s_gone_handler(_sig: i32) {
    A_S_GONE.store(1, Ordering::Relaxed);
}

/// decision #42: check the pdeathsig flag (call sites: A's fast
/// operations, before its blocking wait). Never returns when the
/// flag is set.
fn a_pdeath_check(b_host_pid: i32) {
    if A_S_GONE.load(Ordering::Relaxed) != 0 {
        a_tear_down(b_host_pid);
    }
}

/// decision #42: A's answer to "S is gone": kill B and exit.
///
/// B is the only process that matters here, and a `SIGKILL` from
/// A reaches it both pre-exec and post-exec (decision #13: a
/// pid-ns init ignores *default-action* signals from outside its
/// namespace, but `SIGKILL`/`SIGSTOP` from an ancestor namespace
/// are delivered — A is in the host ns, an ancestor of B's). B's
/// descendants (the app's children) die with the pid namespace
/// when its init is killed (the kernel's `zap_pid_ns_processes`);
/// A cannot sweep the instance sub-cgroup itself — the fresh
/// rootfs has no cgroup2 view (decision #12: on 7.2 the cgroup2
/// filesystem is not re-rooted by the cgroup ns) — and S, the
/// process that can (the [`AppKillGuard`]), is exactly the one
/// that is dead. The exit code is 137 (128+`SIGKILL`), the
/// convention for "killed"; it is consumed by nobody (S, the only
/// reader of A's status, is dead), it just marks the run.
fn a_tear_down(b_host_pid: i32) -> ! {
    warn!(
        "A: the supervisor is gone (pdeathsig) — killing the app \
         (pid {b_host_pid}) and exiting: the run cannot survive S"
    );
    // SAFETY: signalling a pid that was valid at the second fork;
    // a failure (ESRCH: B died meanwhile) is the desired state.
    let _ = unsafe { libc::kill(b_host_pid, libc::SIGKILL) };
    std::process::exit(137);
}

/// A `waitpid` that retries `EINTR` (decision #41).
///
/// Both reapers live to block in `waitpid` and on nothing else: S
/// blocks only the three signals it forwards (the signalfd thread
/// is their sole consumer), and A inherits that block. Any *other*
/// signal that reaches either of them — a terminal session's
/// `SIGTSTP`/`SIGTTIN`/`SIGTTOU`/`SIGCHLD`, even a plain
/// `SIGSTOP`→`SIGCONT` cycle (a signal sent without `SA_RESTART`
/// is not restarted) — interrupts the blocking wait, and the old
/// code treated the resulting `EINTR` as fatal in both places (S's
/// `?`, A's `126` exit). Either death orphans B: a dead A reaps
/// nothing, and a dead S takes the forwarder thread — and with it
/// the 2 s KILL escalation — with it. Retrying turns the
/// interrupt into a non-event; the [`AppKillGuard`] is the
/// backstop for whatever still goes wrong.
///
/// `interrupted` (decision #42): when `Some` and set by the time
/// an `EINTR` arrives, the retry loop stops and reports the
/// *unwrapped* `Errno::EINTR` to the caller instead of continuing
/// — the caller (A) distinguishes this from any other error and
/// tears down. `None` (S) retries every `EINTR` as before.
fn waitpid_retry(pid: Pid, what: &str, interrupted: Option<&AtomicI32>) -> Result<WaitStatus> {
    loop {
        // nix 0.31: `waitpid` returns `Result<WaitStatus, Errno>`
        // (`nix::Error` is a type alias for `Errno`).
        match waitpid(Some(pid), None) {
            Err(Errno::EINTR) => {
                if interrupted.is_some_and(|f| f.load(Ordering::Relaxed) != 0) {
                    // Deliberately not `with_context`'d: the caller
                    // must be able to tell this `EINTR` apart
                    // (`downcast_ref::<Errno>`).
                    return Err(anyhow!(Errno::EINTR));
                }
                continue;
            }
            other => return other.with_context(|| format!("waiting for {what}")),
        }
    }
}

/// The app-kill backstop (decision #41).
///
/// B is the sandbox's pid namespace's PID 1: while it lives, the
/// app (and its descendants) live, and no signal from outside the
/// namespace can default-kill it (decision #13) — a reparented B is
/// immortal in practice. The supervision that keeps B finite (the
/// forwarder thread's TERM→KILL escalation) runs inside S, so *any*
/// exit of S with the app still alive (an error `?`, a panic) used
/// to orphan the whole app forever.
///
/// The guard is armed the moment the handoff completes and dropped
/// at the end of S's run. Its sweep kills every process still in
/// the instance sub-cgroup (`cgroup.procs` is recursive: B and all
/// of its descendants — B entered the sub-cgroup with A, decision
/// #20). The kernel's own zap of a dying pidns init is *not* relied
/// on (decision #14: on 7.2.11 the SIGKILL to surviving members was
/// empirically a no-op — strays reparent and survive). On the
/// normal path the sweep is an empty no-op (B and its lineage have
/// already been reaped, and the sub-cgroup has been removed); it
/// fires — loudly, with a warning — only when a live process is
/// found, i.e. exactly the incident it exists to end.
struct AppKillGuard {
    /// `None` until the handoff completes (no armed guard, no app).
    sub_cgroup: Option<String>,
}

impl AppKillGuard {
    fn disarmed() -> Self {
        Self { sub_cgroup: None }
    }
}

impl Drop for AppKillGuard {
    fn drop(&mut self) {
        let Some(cg) = self.sub_cgroup.take() else {
            return;
        };
        let mut killed = 0usize;
        if let Ok(list) = std::fs::read_to_string(format!("{cg}/cgroup.procs")) {
            for line in list.lines() {
                let p = match line.trim().parse::<i32>() {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                // SAFETY: signalling a host pid read from the
                // kernel's own bookkeeping; a failure (ESRCH: it
                // exited between the read and the signal) is
                // exactly the desired state.
                if unsafe { libc::kill(p, libc::SIGKILL) } == 0 {
                    killed += 1;
                }
            }
        }
        if killed > 0 {
            warn!(
                "app-kill guard: the run is ending with {killed} process(es) \
                 still alive in {cg} — SIGKILL sent to all of them"
            );
        }
    }
}

/// Spawn the signal-forwarder thread (Phase 5.4). `None` when
/// forwarding is disabled (the signal block failed — the run keeps
/// the pre-5.4 behavior) or the signalfd could not be created.
fn arm_signal_forwarder(
    mask: Option<&nix::sys::signal::SigSet>,
    app_pid: Option<i32>,
    flags: Arc<AppSignalFlags>,
    stop: Arc<AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    let mask = mask?;
    let fd = match nix::sys::signalfd::SignalFd::with_flags(
        mask,
        nix::sys::signalfd::SfdFlags::SFD_CLOEXEC | nix::sys::signalfd::SfdFlags::SFD_NONBLOCK,
    ) {
        Ok(fd) => fd,
        Err(e) => {
            log::warn!("signal forwarder: signalfd failed: {e}; forwarding disabled");
            return None;
        }
    };
    Some(std::thread::spawn(move || {
        app_signal_forwarder(fd, app_pid, flags, stop)
    }))
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
fn app_env(
    config: &SandboxConfig,
    runtime_dir: &str,
) -> std::collections::BTreeMap<String, String> {
    let mut env = config.profile.env.clone();
    if let Some(spec) = &config.wayland {
        let host_path = crate::wayland::resolve_socket_path(runtime_dir, spec.listen.as_deref());
        let name = host_path.rsplit('/').next().unwrap_or("wayland-1");
        env.insert(
            "XDG_RUNTIME_DIR".into(),
            mounts::sandbox_instance_dir(config),
        );
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
    use super::{
        A_S_GONE, SandboxConfig, WaylandSpec, a_pdeath_check, a_s_gone_handler, a_tear_down,
        remove_runtime_dir, run_sandboxed, waitpid_retry,
    };
    use crate::sandbox::mounts;
    use crate::sandbox::namespaces::NetworkMode;
    use crate::sandbox::userns::tests::run_in_child;
    use nix::errno::Errno;
    use nix::unistd::ForkResult;
    use std::ffi::OsString;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::{Duration, Instant};

    // A listener whose fd is closed behind the wrapper's back,
    // leaving the socket file in place — a sidecar (relay,
    // satellite) that died without unlinking.
    fn leave_stale_socket(listener: UnixListener) {
        let raw = listener.as_raw_fd();
        // SAFETY: `raw` is the listener's own fd; closing it out from
        // under the wrapper and forgetting the wrapper means the fd
        // is closed exactly once, and the (now dead) socket file
        // stays put.
        unsafe { libc::close(raw) };
        std::mem::forget(listener);
    }

    /// Decision #40: the run's teardown must not destroy a
    /// long-lived sidecar's socket that shares the instance dir —
    /// live ones are kept (the dir survives), stale ones and the
    /// app's state are removed.
    #[test]
    fn runtime_dir_cleanup_keeps_live_foreign_socket() {
        let dir = crate::testutil::TmpDir::new("runtime-cleanup");
        let inst = dir.path().join("inst");
        std::fs::create_dir(&inst).unwrap();
        let live = inst.join("wayland-1");
        let stale = inst.join("bus.sock");
        let regular = inst.join("app-state");
        let sub = inst.join("nested");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("f"), "x").unwrap();
        std::fs::write(&regular, "state").unwrap();
        let live_l = UnixListener::bind(&live).unwrap();
        let stale_l = UnixListener::bind(&stale).unwrap();
        leave_stale_socket(stale_l);

        remove_runtime_dir(inst.to_str().unwrap(), None);

        assert!(
            live.exists(),
            "a live sidecar's socket must survive the run's teardown"
        );
        UnixStream::connect(&live)
            .unwrap_or_else(|e| panic!("the kept socket must still serve: {e}"));
        assert!(!stale.exists(), "a stale socket must be removed");
        assert!(!regular.exists(), "the app's per-run state must be removed");
        assert!(!sub.exists(), "nested app state must be removed");
        assert!(
            inst.exists(),
            "the dir must remain while a live socket is in it"
        );
        drop(live_l);
    }

    /// The run's *own* tagged socket is served by the compositor's
    /// dup, not by this process: the liveness probe would keep it,
    /// so it is removed by path instead (the untag already happened
    /// with the listener drop).
    #[test]
    fn runtime_dir_cleanup_removes_own_tagged_even_if_served() {
        let dir = crate::testutil::TmpDir::new("runtime-cleanup-own");
        let inst = dir.path().join("inst");
        std::fs::create_dir(&inst).unwrap();
        let own = inst.join("wayland-1");
        let _l = UnixListener::bind(&own).unwrap();

        remove_runtime_dir(inst.to_str().unwrap(), Some(own.to_str().unwrap()));

        assert!(
            !own.exists(),
            "the run's own tagged socket is removed by path, not probed"
        );
        assert!(!inst.exists(), "the now-empty dir must go with it");
    }

    /// With nothing live left, the lazy cleanup removes the dir
    /// itself (the historical behaviour, restored once no sidecar
    /// shares the dir).
    #[test]
    fn runtime_dir_cleanup_removes_dir_when_nothing_live() {
        let dir = crate::testutil::TmpDir::new("runtime-cleanup-empty");
        let inst = dir.path().join("inst");
        std::fs::create_dir(&inst).unwrap();
        let stale = inst.join("wayland-1");
        let l = UnixListener::bind(&stale).unwrap();
        leave_stale_socket(l);
        std::fs::write(inst.join("state"), "x").unwrap();

        remove_runtime_dir(inst.to_str().unwrap(), None);

        assert!(!inst.exists(), "with nothing live the dir itself must go");
    }

    #[test]
    fn runtime_dir_cleanup_missing_dir_is_a_noop() {
        let dir = crate::testutil::TmpDir::new("runtime-cleanup-missing");
        remove_runtime_dir(dir.path().join("nope").to_str().unwrap(), None);
    }

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
    /// (5.2) — the compositor untags on the pipe's EOF — and the
    /// run's cleanup unlinks the socket file and removes the
    /// per-instance runtime dir (5.4; decision #40 spares only
    /// *foreign* live sockets, and there is no sidecar in this
    /// test, so the dir goes).
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
            out.contains("WD=wl-probe\n") && out.contains(&format!("XDG={sandbox_runtime}\n")),
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

        // 5.2/5.4: the run is over and with it S's listener copy and
        // the reference pipe: the compositor's untag (the pipe's
        // EOF) happened when S dropped them, and the run's cleanup
        // removed the per-instance runtime dir — the socket file is
        // gone (it was carried by a *bind*, decision #28, so the
        // host-side copy is the one that is removed).
        assert!(
            !std::path::Path::new(&host_runtime).exists(),
            "the per-instance runtime dir {host_runtime} remains after the run \
             (5.4 cleanup failed)"
        );
    }

    /// Phase 5.4: run a long-lived app and, from *inside* the run
    /// (standing in for the user), send `sig` to the S process once
    /// the app is up. The in-run killer thread blocks the
    /// forwardable signals on itself (no thread may hold a
    /// default-action disposition, or the kernel would pick it
    /// instead of the signalfd); every other thread in the process
    /// inherits the block from the pre-fork block in `run_sandboxed`
    /// (Phase 6), so the forwarder's signalfd is the sole consumer. The app signals "up" by
    /// touching a marker in its (in-sandbox) runtime dir — a bind
    /// chain, so the same file appears at the host path the killer
    /// polls (decision #28).
    fn signal_run(sig: i32) -> (Option<i32>, String, String) {
        let _env_lock = crate::testutil::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _sb_lock = crate::testutil::SANDBOX_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let config = SandboxConfig {
            app_id: "sig".to_string(),
            instance_id: "1".to_string(),
            network: NetworkMode::Shared,
            profile: {
                let mut p = crate::profile::Profile::adhoc();
                p.env.insert(
                    "MARKER".to_string(),
                    format!(
                        "{}/ready",
                        mounts::sandbox_instance_dir(&SandboxConfig {
                            app_id: "sig".to_string(),
                            instance_id: "1".to_string(),
                            network: NetworkMode::Shared,
                            profile: crate::profile::Profile::adhoc(),
                            gpu: false,
                            wayland: None,
                        })
                    ),
                );
                p
            },
            gpu: false,
            wayland: None,
        };
        let host_marker = format!("{}/ready", mounts::instance_runtime_dir(&config));
        let _ = std::fs::remove_dir_all(mounts::instance_runtime_dir(&config));

        // A *single* process (the `exec` replaces sh): killing it
        // kills the whole pid ns, so nothing strays out of the
        // namespace to hold the run_in_child pipes (or the test
        // harness' stdout) open — decision #14 says the kernel's
        // zap of a dead pid ns's strays is a no-op on this kernel.
        let command = vec![
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from("echo ok > \"$MARKER\"; exec sleep 30"),
        ];
        let host_marker2 = host_marker.clone();
        run_in_child(move |o| {
            // The "user": block the forwardable signals on this
            // thread, wait for the app's marker, signal S.
            std::thread::spawn(move || {
                let mut mask = nix::sys::signal::SigSet::empty();
                for s in [
                    nix::sys::signal::Signal::SIGTERM,
                    nix::sys::signal::Signal::SIGINT,
                    nix::sys::signal::Signal::SIGHUP,
                ] {
                    mask.add(s);
                }
                let _ = mask.thread_block();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                while !std::path::Path::new(&host_marker2).exists() {
                    if std::time::Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
                // SAFETY: signalling our own process.
                unsafe { libc::kill(std::process::id() as i32, sig) };
                // We die with the process; no join required.
                std::thread::sleep(std::time::Duration::from_secs(60));
            });
            match run_sandboxed(&command, &config) {
                Ok(code) => code,
                Err(e) => {
                    let _ = writeln!(o.err(), "run_sandboxed: {e:#}");
                    2
                }
            }
        })
    }

    /// Phase 5.4: a TERM to the `wlsctx` process stops the app. The
    /// app is PID 1 of its own pid namespace, so the courtesy TERM
    /// from outside the ns is ignored (decision #13) and the stop
    /// lands as the SIGKILL escalation — S (and this child) reports
    /// 128+9. The per-instance runtime dir is cleaned up.
    #[test]
    fn term_is_forwarded_to_the_app_and_exits_137() {
        let (code, out, err) = signal_run(libc::SIGTERM);
        assert_eq!(
            code,
            Some(137),
            "the app was not stopped by the forwarded TERM (escalates \
             to SIGKILL, 128+9):\n{out}\n{err}"
        );
        let config = SandboxConfig {
            app_id: "sig".to_string(),
            instance_id: "1".to_string(),
            network: NetworkMode::Shared,
            profile: crate::profile::Profile::adhoc(),
            gpu: false,
            wayland: None,
        };
        assert!(
            !std::path::Path::new(&mounts::instance_runtime_dir(&config)).exists(),
            "the runtime dir remains after the run (5.4 cleanup failed)"
        );
    }

    /// Phase 5.4: a HUP keeps the historical `wlsctx` semantics —
    /// the app is killed and the process exits with 129
    /// (128+SIGHUP), no restart.
    #[test]
    fn hup_is_forwarded_to_the_app_and_exits_129() {
        let (code, out, err) = signal_run(libc::SIGHUP);
        assert_eq!(
            code,
            Some(129),
            "HUP must exit 129 (128+SIGHUP), the historical wlsctx \
             semantics:\n{out}\n{err}"
        );
    }

    /// Phase 5.4: sd-notify — with `$NOTIFY_SOCKET` set (as systemd
    /// does), the run sends `READY=1` when the app is up.
    #[test]
    fn sd_notify_reports_ready_when_the_app_runs() {
        let tmp = crate::testutil::TmpDir::new("sd-notify");
        let sock_path = tmp.path().join("notify.sock");
        let datagram = std::os::unix::net::UnixDatagram::bind(&sock_path)
            .expect("binding the notify datagram");

        let config = SandboxConfig {
            app_id: "sdr".to_string(),
            instance_id: "1".to_string(),
            network: NetworkMode::Shared,
            profile: crate::profile::Profile::adhoc(),
            gpu: false,
            wayland: None,
        };
        let command = vec![OsString::from("/bin/true")];
        let sock_str = sock_path.to_string_lossy().into_owned();
        // `with_env` takes `ENV_LOCK` itself (the lock is not
        // reentrant), so it is the *outer* guard here: every
        // full-sandbox test orders the locks ENV_LOCK → SANDBOX_LOCK,
        // and taking them in the opposite order across parallel tests
        // deadlocks (ABBA).
        let mut result: (Option<i32>, String, String) = (None, String::new(), String::new());
        crate::testutil::with_env(&[("NOTIFY_SOCKET", Some(&sock_str))], || {
            let _sb_lock = crate::testutil::SANDBOX_LOCK
                .lock()
                .unwrap_or_else(|e| panic!("SANDBOX_LOCK poisoned: {e}"));
            result = run_in_child(move |o| match run_sandboxed(&command, &config) {
                Ok(code) => code,
                Err(e) => {
                    let _ = writeln!(o.err(), "run_sandboxed: {e:#}");
                    2
                }
            });
        });
        let (code, out, err) = result;
        assert_eq!(code, Some(0), "the trivial run failed:\n{out}\n{err}");
        let mut buf = [0u8; 128];
        let (n, _from) = datagram
            .recv_from(&mut buf)
            .expect("receiving the sd-notify datagram");
        let msg = String::from_utf8_lossy(&buf[..n]);
        assert!(
            msg.contains("READY=1"),
            "the notify message is not READY=1: {msg:?}"
        );
    }

    /// decision #42: the A-side teardown path,
    /// driven end to end inside one test child: the production
    /// handler install (the same `SigAction`/`sigaction` call A
    /// makes), a *kernel-initiated* USR1 at a process blocked in
    /// `waitpid` (a one-shot `timer_create` — the pdeathsig's own
    /// delivery shape: the kernel queues the signal, no other
    /// process sends it, and no pid namespace is involved — a raw
    /// pidns probe is never run in a live session, LESSONS #39),
    /// the `waitpid_retry` escape, and `a_tear_down` (kill the app
    /// child, exit 137). The pdeathsig *delivery itself* (S dying)
    /// is covered by the field verification, not here.
    #[test]
    fn a_tear_down_on_s_death_flag() {
        let (code, out, err) = run_in_child(|o| {
            // Play A: the production handler install (empty block:
            // this flat test child has none to preserve).
            let act = nix::sys::signal::SigAction::new(
                nix::sys::signal::SigHandler::Handler(a_s_gone_handler),
                nix::sys::signal::SaFlags::empty(),
                nix::sys::signal::SigSet::empty(),
            );
            // SAFETY: valid handler and mask; no SA_SIGINFO.
            if unsafe { nix::sys::signal::sigaction(nix::sys::signal::Signal::SIGUSR1, &act) }
                .is_err()
            {
                let _ = writeln!(o, "sigaction: failed");
                return 3;
            }
            // Play B: a grandchild that lives until killed.
            // SAFETY: fork(2) in a test child; it only sleeps.
            match unsafe { nix::unistd::fork() } {
                Ok(ForkResult::Child) => loop {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                },
                Ok(ForkResult::Parent { child }) => {
                    let _ = writeln!(o, "bpid: {}", child.as_raw());
                    // One-shot timer 500 ms out, delivering USR1 to
                    // this process (kernel-initiated).
                    // SAFETY: fixed `timer_create`/`timer_settime`;
                    // both structs are fully initialized.
                    let mut sev: libc::sigevent = unsafe { std::mem::zeroed() };
                    sev.sigev_notify = libc::SIGEV_SIGNAL;
                    sev.sigev_signo = libc::SIGUSR1;
                    let spec = libc::itimerspec {
                        it_interval: libc::timespec {
                            tv_sec: 0,
                            tv_nsec: 0,
                        },
                        it_value: libc::timespec {
                            tv_sec: 0,
                            tv_nsec: 500_000_000,
                        },
                    };
                    let mut t: libc::timer_t = std::ptr::null_mut();
                    if unsafe { libc::timer_create(libc::CLOCK_MONOTONIC, &mut sev, &mut t) } != 0
                        || unsafe { libc::timer_settime(t, 0, &spec, std::ptr::null_mut()) } != 0
                    {
                        let _ = writeln!(o, "timer: failed");
                        return 4;
                    }
                    // If the USR1 was already delivered (early,
                    // before the wait — the same race A covers with
                    // its pre-wait check), tear down without
                    // waiting; the handler has set the flag.
                    a_pdeath_check(child.as_raw());
                    let r = waitpid_retry(child, "test app", Some(&A_S_GONE));
                    let is_eintr = r.as_ref().err().and_then(|e| e.downcast_ref::<Errno>())
                        == Some(&Errno::EINTR);
                    let _ = writeln!(o, "escape: {is_eintr}");
                    if is_eintr {
                        a_tear_down(child.as_raw());
                    }
                    5
                }
                Err(e) => {
                    let _ = writeln!(o, "fork: {e}");
                    2
                }
            }
        });
        assert_eq!(
            code,
            Some(137),
            "the teardown must exit 137 (128+SIGKILL):\n{out}\n{err}"
        );
        // The USR1 may have been consumed *before* the blocking wait
        // (the pre-wait check tore down — correct behaviour, no
        // escape line to report); if a wait was entered, its only
        // way out is the pdeathsig escape.
        if let Some(line) = out.lines().find(|l| l.starts_with("escape: ")) {
            assert_eq!(
                line, "escape: true",
                "an interrupted wait must be the pdeathsig escape:\n{out}"
            );
        }
        // B must be dead. The test process is not a child subreaper,
        // so the SIGKILL'd grandchild is a *zombie* until init reaps
        // it after the child's death — tolerate that window: dead
        // means ESRCH on the probe or state `Z` in `/proc`.
        let bpid = out
            .lines()
            .find_map(|l| l.strip_prefix("bpid: "))
            .and_then(|s| s.trim().parse::<i32>().ok())
            .expect("the child reported B's pid");
        let mut dead = false;
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            // SAFETY: liveness probe of a pid this test created.
            dead = unsafe { libc::kill(bpid, 0) } != 0
                || std::fs::read_to_string(format!("/proc/{bpid}/status"))
                    .ok()
                    .is_some_and(|s| {
                        s.lines().any(|l| {
                            l.strip_prefix("State:")
                                .is_some_and(|v| v.trim().starts_with('Z'))
                        })
                    });
            if dead {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(dead, "B must be dead after the teardown (pid {bpid})");
    }
}
