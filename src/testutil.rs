//! Shared test utilities: environment-mutating helpers and temporary
//! directories, used across the crate's test modules.
//!
//! clap reads the process environment for its `env` attributes, and
//! tests run in parallel, so environment-mutating tests must be
//! serialised against each other.
#![cfg(test)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path;
use std::sync::Mutex;

pub static ENV_LOCK: Mutex<()> = Mutex::new(());

/// systemd passes socket-activated fds starting at 3 (SD_LISTEN_FDS_START);
/// only one test at a time may install a fd there.
pub static LISTEN_FD_LOCK: Mutex<()> = Mutex::new(());

/// A uniquely named directory under the system temp dir, removed on
/// drop. The counter makes every instance unique *within* a test
/// binary, so parallel tests never share (or drop) the same
/// directory even when they pass the same label.
pub struct TmpDir {
    path: path::PathBuf,
}

static TMP_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

impl TmpDir {
    pub fn new(name: &str) -> Self {
        let n = TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("wlsctx-test-{}-{name}-{n}", std::process::id()));
        fs::create_dir_all(&path).unwrap_or_else(|e| panic!("creating {path:?}: {e}"));
        Self { path }
    }

    pub fn path(&self) -> &path::Path {
        &self.path
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// A TmpDir made usable as XDG_RUNTIME_DIR (which xdg requires to
/// have exactly 0700 permissions).
pub fn xdg_runtime_dir(mode: u32) -> TmpDir {
    let dir = TmpDir::new("runtime");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(mode))
        .unwrap_or_else(|e| panic!("chmod {}: {e}", dir.path().display()));
    dir
}

/// Set (Some) or unset (None) the given environment variables for the
/// duration of `f`, restoring whatever was there before — on unwind
/// too, so a panicking test does not leak its environment into other
/// tests.
pub fn with_env(vars: &[(&str, Option<&str>)], f: impl FnOnce()) {
    let _lock_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _env_guard = EnvGuard::new(vars);
    f();
}

/// RAII half of [`with_env`]: records the current value of each
/// variable, applies the requested values, and restores the recorded
/// ones in `Drop` (which also runs when the protected closure
/// panics). Must only be used while holding `ENV_LOCK`.
pub struct EnvGuard<'a> {
    /// (name, previous value) pairs to restore on drop, in the
    /// original order.
    restore: Vec<(&'a str, Option<String>)>,
}

impl<'a> EnvGuard<'a> {
    fn new(vars: &[(&'a str, Option<&'a str>)]) -> Self {
        let restore = vars
            .iter()
            .map(|(name, _)| (*name, std::env::var(name).ok()))
            .collect();
        // SAFETY: ENV_LOCK guarantees no other test or code path
        // reads or writes these variables while they are held.
        unsafe {
            for (name, value) in vars {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
        Self { restore }
    }
}

impl Drop for EnvGuard<'_> {
    fn drop(&mut self) {
        // Runs on every exit path of the protected closure,
        // including panic.
        // SAFETY: as in EnvGuard::new — ENV_LOCK is held by the
        // with_env that created this guard and outlives it (the
        // lock guard is declared first, so it drops last).
        unsafe {
            for (name, value) in &self.restore {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

pub fn without_wlsctx_env(f: impl FnOnce()) {
    with_env(
        &[
            ("WLSCTX_APP_ID", None),
            ("WLSCTX_INSTANCE_ID", None),
            ("WLSCTX_SANDBOX_ENGINE", None),
            ("WLSCTX_SOCKET_PATH", None),
        ],
        f,
    );
}
