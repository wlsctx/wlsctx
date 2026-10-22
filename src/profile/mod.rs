//! Per-app sandbox profiles (PLAN.md §5): TOML files under
//! `~/.config/wlsctx/apps/<app-id>.toml` describing ro/rw binds,
//! masked paths, environment variables and GPU access — the
//! replacement for the old quadlet drop-ins.
//!
//! The file is optional: [builtin] covers the known apps, and a
//! profile-less `run` (ad-hoc command) falls back to
//! [Profile::adhoc]. A malformed file is a hard error — it never
//! silently degrades the sandbox.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde::Deserialize;

/// One app's sandbox profile (the data section of
/// `~/.config/wlsctx/apps/<app-id>.toml`).
///
/// All path fields are absolute; `~` is not expanded (the kernel
/// does not expand it, and profiles are data, not shell).
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Profile {
    /// GPU access: build `/dev/dri` in the sandbox (`true`) or skip
    /// it entirely (`false`; the CLI's `--no-gpu` overrides this).
    pub gpu: bool,
    /// Size of the fresh `/tmp` in MiB (`0` = the kernel default).
    pub tmp_size_mib: u64,
    /// Read-only paths, e.g. the app's install dir (`/opt/<app>`).
    /// Everything under `/` is already ro from the recursive
    /// self-bind; this list documents the app's dir and exempts it
    /// from the `/opt/*` mask.
    pub ro_binds: Vec<String>,
    /// Extra writable self-binds, on top of the standard XDG set
    /// (`$HOME`, config, cache, state, data).
    pub rw_binds: Vec<String>,
    /// Extra paths to mask (an empty tmpfs over them), on top of the
    /// defaults (`/root`, `/home/*` except ours, `/boot`, `/var`,
    /// `/srv`, `/media`, `/mnt`, `/opt/*` except the app's).
    pub mask: Vec<String>,
    /// Environment variables added for the app (on top of the
    /// session environment).
    pub env: BTreeMap<String, String>,
    /// AF_UNIX socket paths the app may use, on top of the
    /// per-instance dir (the tagged wayland socket — Phase 5).
    pub unix_sockets: Vec<String>,
    /// IPC mode: `"shm"` (POSIX shared memory only; the default) or
    /// `"full"` (also semaphores).
    pub ipc: String,
    /// Signal mode: `"isolated"` (the default — the app may only
    /// signal itself and its descendants; Landlock V6) or `"all"`.
    pub signals: String,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            gpu: true,
            tmp_size_mib: 2048,
            ro_binds: Vec::new(),
            rw_binds: Vec::new(),
            mask: Vec::new(),
            env: BTreeMap::new(),
            unix_sockets: Vec::new(),
            ipc: "shm".to_string(),
            signals: "isolated".to_string(),
        }
    }
}

impl Profile {
    /// The profile of an ad-hoc `run` (no app profile): no GPU by
    /// default, the standard XDG rw-set, the standard masks.
    pub(crate) fn adhoc() -> Self {
        let mut p = Self::default();
        p.gpu = false;
        p
    }
}

/// The built-in defaults for the known apps, used when no TOML file
/// exists.
pub(crate) fn builtin(app_id: &str) -> Option<Profile> {
    let mut p = Profile::default();
    match app_id {
        "rustrover" => {
            p.ro_binds = vec!["/opt/rustrover".to_string()];
        }
        "librewolf" => {
            p.ro_binds = vec!["/usr/lib64/librewolf".to_string()];
        }
        _ => return None,
    }
    Some(p)
}

/// Load the profile for `app_id`: the TOML file under the user
/// config dir (if present — parse errors propagate), else the
/// built-in default, else `None` (ad-hoc `run` without a profile).
pub(crate) fn load(app_id: &str) -> Result<Option<Profile>> {
    let home =
        std::env::var("HOME").context("HOME is required to locate the profile dir")?;
    let base =
        std::env::var("XDG_CONFIG_HOME").unwrap_or_else(|_| format!("{home}/.config"));
    let path = format!("{base}/wlsctx/apps/{app_id}.toml");
    if std::path::Path::new(&path).is_file() {
        let s = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
        let p: Profile = toml::from_str(&s).with_context(|| format!("parsing {path}"))?;
        Ok(Some(p))
    } else {
        Ok(builtin(app_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TmpDir, with_env};

    #[test]
    fn builtin_defaults_cover_the_known_apps() {
        let p = builtin("rustrover").expect("rustrover has a builtin");
        assert!(p.gpu);
        assert_eq!(p.ro_binds, vec!["/opt/rustrover".to_string()]);
        let p = builtin("librewolf").expect("librewolf has a builtin");
        assert!(p.gpu);
        assert!(!p.ro_binds.is_empty());
        assert!(builtin("no-such-app").is_none());
    }

    #[test]
    fn adhoc_is_the_same_as_default_without_gpu() {
        let a = Profile::adhoc();
        let d = Profile::default();
        assert!(!a.gpu && d.gpu);
        assert_eq!(a.tmp_size_mib, d.tmp_size_mib);
    }

    #[test]
    fn load_reads_the_toml_file_when_present() {
        let tmp = TmpDir::new("config");
        std::fs::create_dir_all(tmp.path().join("wlsctx/apps")).unwrap();
        std::fs::write(
            tmp.path().join("wlsctx/apps/demo.toml"),
            "gpu = false\ntmp_size_mib = 512\nro_binds = [\"/opt/demo\"]\n\
             rw_binds = [\"/home/demo/docs\"]\nmask = [\"/private\"]\n\
             [env]\nDEMO = \"1\"\n",
        )
        .unwrap();
        with_env(
            &[(
                "XDG_CONFIG_HOME",
                Some(tmp.path().to_str().unwrap_or_else(|| panic!("not utf-8"))),
            )],
            || {
                let p = load("demo")
                    .expect("a present TOML must load")
                    .expect("Some");
                assert!(!p.gpu);
                assert_eq!(p.tmp_size_mib, 512);
                assert_eq!(p.ro_binds, vec!["/opt/demo".to_string()]);
                assert_eq!(p.rw_binds, vec!["/home/demo/docs".to_string()]);
                assert_eq!(p.mask, vec!["/private".to_string()]);
                assert_eq!(p.env.get("DEMO").map(String::as_str), Some("1"));
            },
        );
    }

    #[test]
    fn load_falls_back_to_builtin_then_none() {
        let tmp = TmpDir::new("config-empty");
        with_env(
            &[(
                "XDG_CONFIG_HOME",
                Some(tmp.path().to_str().unwrap_or_else(|| panic!("not utf-8"))),
            )],
            || {
                assert!(
                    load("rustrover").unwrap().is_some(),
                    "no file → the builtin default"
                );
                assert!(
                    load("mystery-app").unwrap().is_none(),
                    "no file and no builtin → None (ad-hoc)"
                );
            },
        );
    }

    #[test]
    fn a_malformed_toml_is_a_hard_error() {
        let tmp = TmpDir::new("config-bad");
        std::fs::create_dir_all(tmp.path().join("wlsctx/apps")).unwrap();
        std::fs::write(
            tmp.path().join("wlsctx/apps/bad.toml"),
            "gpu = not-a-bool\n",
        )
        .unwrap();
        with_env(
            &[(
                "XDG_CONFIG_HOME",
                Some(tmp.path().to_str().unwrap_or_else(|| panic!("not utf-8"))),
            )],
            || {
                let e = load("bad").expect_err("a malformed TOML must not fall back");
                let msg = e.to_string();
                assert!(msg.contains("bad.toml"), "{msg}");
            },
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let tmp = TmpDir::new("config-unknown");
        std::fs::create_dir_all(tmp.path().join("wlsctx/apps")).unwrap();
        std::fs::write(
            tmp.path().join("wlsctx/apps/unk.toml"),
            "typos = true\n",
        )
        .unwrap();
        with_env(
            &[(
                "XDG_CONFIG_HOME",
                Some(tmp.path().to_str().unwrap_or_else(|| panic!("not utf-8"))),
            )],
            || {
                let e = load("unk").expect_err("unknown fields must be rejected");
                // The field name lives in the inner TOML error; walk
                // the whole anyhow chain, not just the outer context.
                let chain: Vec<String> = e.chain().map(|e| e.to_string()).collect();
                assert!(chain.iter().any(|s| s.contains("typos")), "{chain:?}");
            },
        );
    }
}
