//! Transient systemd scope attachment (phase 6, decision #35).
//!
//! Before the first fork, `S` asks the *user* systemd over the
//! session bus (`org.freedesktop.systemd1.Manager.StartTransientUnit`)
//! for a transient scope containing itself: `PIDs=[self]` (type
//! `au`, property name `PIDs` — that spelling since scopes exist,
//! v252) plus `Description`. Then both `S`'s own sub-cgroup path and A's pre-unshare cgroup capture (decision #20) root under the
//! scope, and systemd removes the scope **and its children**
//! recursively when the last member (the supervisor, which exits
//! last) leaves.
//!
//! Deliberately no other properties: `StopWhenUnneeded` is actively
//! harmful on v261 scopes (it stops any active jobless scope at once
//! — the empty-cgroup auto-stop already gives the lifecycle we want),
//! and `Delegate=` is unnecessary because the entire user-session
//! cgroup subtree is already user-owned (verified on the Fedora 45
//! target; #35).
//!
//! Best-effort by design: no session bus, no user systemd, or any
//! call failure degrades to the raw-cgroup tier (proceed with
//! wherever `S` currently is) — a logged, documented degradation,
//! never an abort of the run.
//!
//! The call itself is asynchronous twice over: the method returns as
//! soon as the start *job* is queued, before the pid move lands. And
//! `StartTransientUnit` refuses a unit that is merely *loaded*
//! (`UnitExists` — v261 does not distinguish active from inactive
//! here): a stale unit left by a crashed previous run, or a live
//! scope we are already a member of. In that case the unit is
//! *adopted*: if we are already a member there is nothing to do; if
//! the scope is empty (no tasks) it is stopped, its stored `PIDs`
//! refreshed to point at us, and it is started again (`StartUnit` —
//! also asynchronous, hence a short settle after the stop before the
//! property write). If the scope is *not* empty, some other live
//! process set lives in it, and it is left alone (the run degrades):
//! `StopUnit` on a scope **kills its members** (`scope_enter_dead` →
//! `unit_kill_context`), so a busy foreign scope is never touched.
//! Since the very next step in the pipeline captures
//! `/proc/self/cgroup` (decision #20), the whole thing ends in a
//! short poll of `/proc/self/cgroup` until the scope is the process's
//! own cgroup (or a few seconds pass, in which case the run degrades
//! to the raw-cgroup tier). That poll is the arbiter of success.
//!
//! The whole interaction is one one-shot method call, made in the
//! single-threaded pre-fork part of the supervisor. It is driven on a
//! **fresh, local** tokio runtime via zbus's *async* API,
//! deliberately **never** on `zbus::blocking` (zbus 5): the blocking
//! wrapper hides a *process-global* tokio runtime in an
//! `OnceLock`, and that global is **poisoned** in a process that was
//! `fork(2)`-ed after it was built — `fork` clones only the calling
//! thread, so the runtime's worker threads vanish in the child while
//! the `OnceLock` still reports the runtime as built, and `block_on`
//! on it hangs forever (the worker pool it submits to no longer
//! exists). The test harness forks this very code path
//! (`run_in_child` → `run_sandboxed` → `attach_scope`), and the
//! harness process may already have built the global (the systemd
//! test itself, run in parallel), so the implementation must not
//! depend on any process-global runtime at all. The runtime is built
//! *here* and, crucially, is a **current-thread** runtime — see
//! [`with_local_runtime`] for why a multi-thread one would be unsafe:
//! `attach_scope` runs in `S` before the supervisor forks `A`, and a
//! multi-thread runtime's un-joined worker threads would linger across
//! that fork and hand the child a locked global. (zbus 6 removed the
//! blocking API; migrating is a later task, but the async API used
//! here is the same one 6 is built on.)

use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use log::{debug, info, warn};

use zbus::zvariant::Value;
use zbus::{Connection, Proxy};

/// The outcome of the scope-attachment attempt.
#[derive(Debug)]
pub(crate) enum ScopeTier {
    /// The supervisor now lives in this transient scope unit.
    Joined { unit: String },
    /// No scope (reason string for the log); proceed raw-cgroup.
    Unavailable(String),
}

/// Ask the user systemd for a transient scope containing the calling
/// process. Never fails: every error becomes [`ScopeTier::Unavailable`].
pub(crate) fn attach_scope(unit: &str, description: &str) -> ScopeTier {
    match start_transient(unit, description, std::process::id()) {
        Ok(()) => {
            info!(
                "phase 6: joined the systemd scope {unit} \
                 (the instance's cgroups now live under it)"
            );
            ScopeTier::Joined { unit: unit.into() }
        }
        Err(e) => {
            warn!(
                "no systemd scope ({e:#}); proceeding with the raw \
                 cgroup path (no unit visibility/accounting)"
            );
            ScopeTier::Unavailable(format!("{e:#}"))
        }
    }
}

/// Run `fut` to completion on a **fresh, local, current-thread** tokio
/// runtime.
///
/// Two constraints shape this, and they pull in the same direction:
///
/// 1. **Never a process-global runtime.** `zbus::blocking` (zbus 5)
///    hides a process-global runtime in an `OnceLock`; that global is
///    dead in a `fork(2)`-ed child (see the module docs). We build a
///    runtime here instead.
///
/// 2. **Current-thread, not multi-thread.** `attach_scope` runs in `S`
///    *before* `run_sandboxed` forks `A`. A `new_multi_thread()` runtime
///    spawns background worker threads that are **not joined when the
///    `Runtime` is dropped** — they linger for a few milliseconds after
///    `block_on` returns. If the fork lands inside that window, the
///    child inherits those threads' state: `std`'s process-global
///    `thread_info` mutex (used by the stack-overflow guard on every
///    thread start) is left held by a thread that no longer exists in
///    the child, and the first thread the child creates deadlocks on it
///    forever (the whole test binary then hangs, the forking test's
///    lock never released). A **current-thread** runtime has no
///    background workers — all futures run on the calling thread, so
///    dropping it is synchronous and leaves nothing for the fork to
///    inherit. The D-Bus calls here are sequential awaits, so a
///    cooperative single-thread runtime is exactly right.
fn with_local_runtime<F: std::future::Future>(fut: F) -> F::Output {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("building the local tokio runtime for the session bus");
    rt.block_on(fut)
}

/// The `StartTransientUnit` body, exactly as systemd's D-Bus reader
/// expects: `(ssa(sv)a(sa(sv)))`. The property maps are **arrays of
/// `(s, v)` pairs** (`a(sv)`), not dicts: v261 rejects `a{sv}` with
/// `InvalidArgs` (verified on the Fedora 45 target; the GDBus probe
/// got away with a dict only because GVariant coerces on send).
type ManagerArgs = (
    String,
    String,
    Vec<(String, Value<'static>)>,
    Vec<(String, Vec<(String, Value<'static>)>)>,
);

/// Give an in-flight `StopUnit` job this long to complete before
/// writing properties (a stop in progress may clear the stored
/// `PIDs`).
const STOP_SETTLE: Duration = Duration::from_millis(200);
/// How long to wait for the pid move to land after starting.
const MOVE_TIMEOUT: Duration = Duration::from_secs(3);
const MOVE_POLL: Duration = Duration::from_millis(5);

fn start_transient(unit: &str, description: &str, pid: u32) -> Result<()> {
    // `unit` must survive the async block (the `wait_in_scope` poll
    // below uses it), so the block captures a clone of it and the
    // original stays put. `description` is consumed inside.
    let unit = unit.to_string();
    let description = description.to_string();
    let call_unit = unit.clone();

    with_local_runtime(async move {
        let unit = call_unit;
        // --- The whole D-Bus interaction, on the fresh local runtime ---
        let conn = Connection::session().await.map_err(|e| {
            anyhow!(
                "connecting to the session bus: {e} \
                 (is DBUS_SESSION_BUS_ADDRESS / the user bus available?)"
            )
        })?;

        let proxy = Proxy::new(
            &conn,
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
        )
        .await
        .map_err(|e| anyhow!("building the systemd1 manager proxy: {e}"))?;

        // `PIDs` is `au`: build the array from the raw `u32` so its
        // element signature is `u` (an array of `Value` would serialize
        // as `av`, which systemd rejects with ENXIO/"Unexpected message
        // contents" in the scope property setter).
        let props: Vec<(String, Value<'static>)> = vec![
            (
                "PIDs".into(),
                Value::Array(zbus::zvariant::Array::from(vec![pid])),
            ),
            ("Description".into(), Value::from(description)),
        ];

        let args: ManagerArgs = (unit.clone(), "replace".into(), props, Vec::new());

        match start_once(&proxy, &args).await {
            Ok(()) => {}
            Err(e) if is_unit_exists(&e) => {
                if own_cgroup_path().ok().is_some_and(|p| p.ends_with(&unit)) {
                    // We are already a member of this scope (a second
                    // attach in the same run): the loaded unit is fine
                    // as-is; the wait below confirms it immediately.
                    debug!("unit {unit} already loaded and we are a member; keeping it");
                } else if unit_task_count(&conn, &unit).await? == 0 {
                    // An empty (or inactive) unit — a stale leftover:
                    // safe to stop, because there is nothing inside that
                    // the stop could kill. Let the asynchronous stop
                    // settle (a pending stop may clear the stored PIDs
                    // before our write), refresh PIDs to point at us,
                    // and start it again.
                    debug!("unit {unit} loaded but empty; adopting it (stop, refresh PIDs, start)");
                    let stop: &(&String, &str) = &(&args.0, "replace");
                    let _ = proxy.call_method("StopUnit", stop).await.map(|_| ());
                    tokio::time::sleep(STOP_SETTLE).await;
                    let pids: Vec<(String, Value<'static>)> = vec![(
                        "PIDs".into(),
                        Value::Array(zbus::zvariant::Array::from(vec![pid])),
                    )];
                    let set = (&args.0, pids, false);
                    let _ = proxy
                        .call_method("SetUnitProperties", &set)
                        .await
                        .map(|_| ());
                    let start = (&args.0, "replace".to_string());
                    let _ = proxy.call_method("StartUnit", &start).await.map(|_| ());
                } else {
                    // A live, busy scope of some other process set holds
                    // the name (e.g. two runs of the same instance):
                    // stopping it would kill those processes, so leave
                    // it alone and degrade to the raw-cgroup tier.
                    let tasks = unit_task_count(&conn, &unit).await?;
                    bail!(
                        "the unit {unit} is already in use by other \
                         processes ({tasks} tasks); not stopping it"
                    );
                }
            }
            Err(e) => return Err(anyhow!("StartTransientUnit: {e:#}")),
        }
        Ok(())
    })?;

    // The start job is asynchronous: only now does the pid move
    // actually land. Wait for it before the caller captures
    // /proc/self/cgroup (decision #20). Pure file polling — no bus
    // round-trip — so it runs on the ordinary thread, after the local
    // runtime is done. This poll is what makes or breaks the attempt.
    wait_in_scope(&unit)
}

async fn start_once<'a>(
    proxy: &Proxy<'a>,
    args: &ManagerArgs,
) -> std::result::Result<(), zbus::Error> {
    proxy
        .call_method("StartTransientUnit", args)
        .await
        .map(|_| ())
}

fn is_unit_exists(e: &zbus::Error) -> bool {
    matches!(
        e,
        zbus::Error::MethodError(name, _, _) if name.contains("UnitExists")
    )
}

/// The `Tasks` property of the unit (the number of processes in its
/// cgroup; 0 for an inactive one).
async fn unit_task_count(conn: &Connection, unit: &str) -> Result<u64> {
    // systemd's D-Bus object-path escaping: every character outside
    // [A-Za-z0-9] becomes "_xx" (lowercase hex of the byte value) —
    // so "wlsctx-foo.scope" → "wlsctx_2dfoo_2escope".
    // (unit names are ASCII, per systemd's unit-name rules)
    let escaped: String = unit
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_string()
            } else {
                format!("_{:02x}", c as u8)
            }
        })
        .collect();
    let path = format!("/org/freedesktop/systemd1/unit/{escaped}");
    let props = Proxy::new(
        conn,
        "org.freedesktop.systemd1",
        path.as_str(),
        "org.freedesktop.DBus.Properties",
    )
    .await
    .map_err(|e| anyhow!("building the properties proxy for {unit}: {e}"))?;
    let body = (
        "org.freedesktop.systemd1.Unit".to_string(),
        "Tasks".to_string(),
    );
    let v: zbus::zvariant::OwnedValue = props
        .call("Get", &body)
        .await
        .map_err(|e| anyhow!("reading Tasks on {unit}: {e:#}"))?;
    let n: u64 = v
        .try_into()
        .map_err(|e| anyhow!("unexpected Tasks value on {unit}: {e}"))?;
    Ok(n)
}

/// The full cgroup v2 path of the calling process (`0::<path>`).
fn own_cgroup_path() -> Result<String> {
    let line = std::fs::read_to_string("/proc/self/cgroup").context("reading /proc/self/cgroup")?;
    let path = line
        .trim()
        .split("::")
        .nth(1)
        .ok_or_else(|| anyhow!("no cgroup v2 entry in /proc/self/cgroup"))?;
    Ok(path.to_string())
}

/// Block until the calling process's cgroup becomes the scope's
/// (i.e. the start job's pid move has landed), or fail after
/// [`MOVE_TIMEOUT`].
fn wait_in_scope(unit: &str) -> Result<()> {
    let deadline = Instant::now() + MOVE_TIMEOUT;
    loop {
        if own_cgroup_path()?.ends_with(unit) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "the scope {unit} was started, but the pid move did not \
                 complete within {MOVE_TIMEOUT:?}"
            );
        }
        std::thread::sleep(MOVE_POLL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reachable session bus? Driven on a fresh local runtime (see the
    /// module docs) so this probe never builds or touches the
    /// process-global tokio runtime either.
    fn bus_available() -> bool {
        with_local_runtime(async { Connection::session().await.is_ok() })
    }

    fn own_cgroup() -> String {
        own_cgroup_path().expect("reading /proc/self/cgroup")
    }

    #[test]
    fn attach_moves_self_and_replaces_a_stale_unit() {
        let unit = "wlsctx-systest-scope.scope";

        let tier = attach_scope(unit, "wlsctx test scope");
        if !bus_available() {
            // Degraded environment: assert the documented fallback
            // tier rather than silently skipping.
            assert!(
                matches!(&tier, ScopeTier::Unavailable(_)),
                "expected Unavailable without a session bus, got {tier:?}"
            );
            return;
        }
        assert!(
            matches!(&tier, ScopeTier::Joined { unit: u } if u == unit),
            "expected Joined({unit}), got {tier:?}"
        );
        assert!(
            own_cgroup().ends_with(unit),
            "expected /proc/self/cgroup to end in {unit}, got {}",
            own_cgroup()
        );

        // The scope dir is user-owned: a child cgroup accepts a pid
        // (the very operation A's enter_cgroupns performs below it).
        let child = format!("/sys/fs/cgroup{}/wlsctx-systest-child", own_cgroup());
        std::fs::create_dir_all(&child).expect("mkdir child cgroup in the scope");

        // Same unit name again: exercises UnitExists → StopUnit →
        // retry, and the scope must end up containing us still.
        let tier2 = attach_scope(unit, "wlsctx test scope (retry)");
        assert!(
            matches!(&tier2, ScopeTier::Joined { unit: u } if u == unit),
            "expected the retry to join {unit}, got {tier2:?}"
        );
        assert!(
            own_cgroup().ends_with(unit),
            "after the retry, got {}",
            own_cgroup()
        );

        let _ = std::fs::remove_dir_all(&child);
        // No explicit stop: the scope auto-removes when this test
        // process (its last member) exits — that is the phase-6
        // teardown contract.
    }
}
