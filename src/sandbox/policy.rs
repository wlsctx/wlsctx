//! The nono capability set of a sandboxed run (PLAN.md Phase 4,
//! decisions #22–#25): the Landlock floor and the supervisor's
//! allowlist are both derived from this single `CapabilitySet`, so
//! they cannot disagree.
//!
//! Built identically in S and in B from the same pure function (B
//! re-runs it after the forks — the value itself is not shared).

use anyhow::{Context, Result, bail};
use nono::capability::{AccessMode, CapabilitySet, IpcMode, SignalMode, UnixSocketMode};
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::Path;

use crate::sandbox::SandboxConfig;

/// Base grants every app needs, independent of its profile.
///
/// `/` is Read (refer/traverse): Landlock is a default-deny floor, so
/// without the ancestor grant the app could not even resolve the
/// granted subtrees (decision #24). The self-bind of `/` already
/// shows the app every top-level directory, so this adds no
/// visibility.
const BASE_READ: &[&str] = &[
    "/", "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/sys",
];

/// The capability set for `config`: the base app grants plus the
/// profile's binds, sockets, network, signal and IPC modes.
///
/// `instance_dir` is the per-instance runtime dir's path **as the
/// app sees it inside the sandbox** (the fresh `/run`'s
/// systemd-standard location — `mounts::sandbox_instance_dir`). It
/// is that string the supervisor matches on (the app presents
/// sandbox-side paths to its trapped syscalls) and that the
/// Landlock floor binds in B; for the default XDG it equals the
/// host path, for a divergent XDG it does not (decision #28, the
/// Phase-5 path translation).
pub(crate) fn capability_set(config: &SandboxConfig, instance_dir: &Path) -> Result<CapabilitySet> {
    let mut caps = CapabilitySet::new();
    for p in BASE_READ {
        caps = caps
            .allow_path(*p, AccessMode::Read)
            .with_context(|| format!("granting read access to {p}"))?;
    }
    // The fresh /dev tmpfs holds only the nodes we bound (plus the
    // pts instance), so RW on it means exactly "the app's devices".
    caps = caps
        .allow_path("/dev", AccessMode::ReadWrite)
        .context("granting /dev")?;
    // /tmp is a fresh tmpfs (sized by the profile).
    caps = caps
        .allow_path("/tmp", AccessMode::ReadWrite)
        .context("granting /tmp")?;
    // The per-instance /run dir (the tagged Wayland socket's home —
    // Phase 5), and its socket subtree.
    caps = caps
        .allow_path(instance_dir, AccessMode::ReadWrite)
        .with_context(|| format!("granting the instance dir {instance_dir:?}"))?;
    caps = caps
        .allow_unix_socket_subtree(instance_dir, UnixSocketMode::Connect)
        .with_context(|| format!("granting the socket subtree of {instance_dir:?}"))?;
    // GUI apps keep their data in $HOME.
    if let Some(home) = std::env::home_dir() {
        caps = caps
            .allow_path(&home, AccessMode::ReadWrite)
            .with_context(|| format!("granting $HOME {home:?}"))?;
    }
    // Profile grants (a missing path is a hard error, like a bad
    // rootfs bind).
    for p in &config.profile.ro_binds {
        caps = caps
            .allow_path(p, AccessMode::Read)
            .with_context(|| format!("granting read access to the ro-bind {p}"))?;
    }
    for p in &config.profile.rw_binds {
        caps = caps
            .allow_path(p, AccessMode::ReadWrite)
            .with_context(|| format!("granting read+write access to the rw-bind {p}"))?;
    }
    for p in &config.profile.unix_sockets {
        caps = caps
            .allow_unix_socket(p, UnixSocketMode::Connect)
            .with_context(|| format!("granting the unix socket {p}"))?;
    }
    // Network: the shared host netns stays open (the network
    // default); `--network=none` also installs the static block.
    if config.network == crate::sandbox::namespaces::NetworkMode::None {
        caps = caps.block_network();
    }
    // Signal / IPC modes per profile (the defaults are the
    // restricted ones).
    match config.profile.signals.as_str() {
        "isolated" => caps = caps.set_signal_mode(SignalMode::Isolated),
        "all" => caps = caps.set_signal_mode(SignalMode::AllowAll),
        other => bail!("profile signals {other:?} is not \"isolated\" or \"all\""),
    }
    match config.profile.ipc.as_str() {
        "shm" => caps = caps.set_ipc_mode(IpcMode::SharedMemoryOnly),
        "full" => caps = caps.set_ipc_mode(IpcMode::Full),
        other => bail!("profile ipc {other:?} is not \"shm\" or \"full\""),
    }
    Ok(caps)
}

/// Apply the policy in this (child) process. Three stages, in this
/// order (decision #22 — the notify filter must be the *only*
/// NEW_LISTENER filter, and it must precede the Landlock floor so
/// the supervisor sees every path the floor would block):
///
/// 1. **Prepare** the Landlock policy (`detect_abi` +
///    `prepare_landlock_with_abi`): the rule paths are opened here,
///    *before* the filter exists. If this ran after the filter, its
///    `openat`(O_PATH) calls would be trapped and B would block on
///    its own install, with no supervisor yet holding the listener.
/// 2. **Install** the combined seccomp-notify filter (it sets
///    `no_new_privs` itself).
/// 3. **`apply_raw`**: builds the ruleset from the pre-opened fds
///    (no path opens — nothing left to trap), re-asserts
///    `no_new_privs` (locking the single-extent identity — #10) and
///    `restrict_self` — the irreversible floor.
///
/// Returns the notify listener fd. It has no CLOEXEC flag, so it
/// survives the app's exec (the supervisor services it — #23).
pub(crate) fn apply(caps: &CapabilitySet) -> Result<OwnedFd> {
    let abi = nono::sandbox::detect_abi()
        .map_err(|e| anyhow::anyhow!("detecting the Landlock ABI: {e}"))?;
    let prepared = nono::sandbox::prepare_landlock_with_abi(caps, &abi)
        .map_err(|e| anyhow::anyhow!("preparing the Landlock policy: {e}"))?;
    let notify = nono::sandbox::prepare_seccomp_af_unix_filter()
        .with_openat_notifications()
        .install_raw()
        .map_err(|e| {
            anyhow::anyhow!(
                "installing the seccomp-notify filter failed at {:?} ({})",
                e.stage(),
                std::io::Error::from_raw_os_error(e.errno())
            )
        })?;
    prepared.apply_raw().map_err(|e| {
        anyhow::anyhow!(
            "applying the Landlock floor failed at {:?} ({})",
            e.stage(),
            std::io::Error::from_raw_os_error(e.errno())
        )
    })?;
    Ok(unsafe { OwnedFd::from_raw_fd(notify) })
}
