//! Private rootfs construction (PLAN.md §3.3) — the mount phase of
//! the double fork, run in process A as ns-root of the fresh mount
//! namespace.
//!
//! The order matters:
//!
//! 1. **Before** `/` becomes read-only, copy out what must survive
//!    it: the standard `/dev` node files, the `/sys` subpaths we
//!    keep, and the per-instance runtime dir itself, bound into a
//!    scratch dir on `/var/tmp` (outside every masked tree).
//! 2. The one-shot recursive self-bind of `/` (`MS_BIND|MS_REC` —
//!    verified unprivileged on 7.2.11). Everything below layers over
//!    it. The `MS_RDONLY` that the §3.3 table once called for is
//!    **not applicable**: on 7.2.11 it is silently dropped on a bind
//!    of a foreign superblock, and the two-step
//!    bind→`MS_REMOUNT|MS_RDONLY` is EPERM (the sb is owned by the
//!    init user ns — probed; decision #21). Read-only semantics for
//!    the host tree come from the app's real uid plus the nono
//!    policy (Phase 4).
//! 3. The volatile trees are rebuilt: `/dev` (fresh tmpfs + node
//!    binds + a fresh devpts instance), `/sys` (fresh tmpfs + ro
//!    binds of `devices/` and `class/` — the sysfs *mount root*
//!    cannot be bound unprivileged, decision #18), `/run` (fresh
//!    tmpfs carrying **only** the per-instance dir), `/tmp` (fresh
//!    tmpfs sized by the profile).
//! 4. XDG **rw** self-binds: a single plain `MS_BIND` on a path
//!    under the ro view makes it writable again (verified on
//!    7.2.11; the textbook bind+`MS_REMOUNT` two-step is EPERM for
//!    mounts we do not own — and unnecessary).
//! 5. Masks: an empty tmpfs over the paths the app must not see.
//! 6. `chroot("/")` into the assembled root.
//!
//! Everything happens **before** nono (Phase 4) is applied, so the
//! app's seccomp filter never needs to permit `mount`/`mknod`.
//!
//! NUL-termination rule (decision #17): every path that crosses into
//! a C interface goes through [cstr].

use std::io;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

use anyhow::{Context, Result, bail};

use super::SandboxConfig;
use super::namespaces;

/// The standard `/dev` node files carried over by bind (not
/// `mknod`): a bind keeps the node's canonical genfs SELinux label
/// (`null_t`, `urandom_t`, …) so a future confined domain needs plain
/// `open/read/write` rules (AGENTS.md; matches rootless-runc).
const DEV_NODES: [&str; 6] = ["null", "zero", "full", "urandom", "random", "tty"];

/// The per-instance runtime dir on the **host**
/// (`$XDG_RUNTIME_DIR/wlsctx/<app>-<inst>`): home of the tagged
/// Wayland socket (Phase 5), of the build scratch, and the dir that
/// the app sees as its own runtime dir (bound into the fresh `/run`).
/// The rootfs scratch dir on the **host**: a per-instance directory
/// on `/var/tmp`, outside `/dev`, `/sys`, `/run` and `/tmp` — the
/// four trees the build replaces — so every bind source and target
/// in it stays resolvable through the whole build.
///
/// It is not part of the capability set: the Landlock floor (and the
/// supervisor, for the syscalls the filter traps) keeps the app out
/// of it, and its contents are binds of things the app already sees
/// via `/dev` and `/sys` anyway. `S` removes it on exit.
pub(crate) fn rootfs_scratch_dir(cfg: &SandboxConfig) -> String {
    let inst = namespaces::cgroup_name_for(&cfg.app_id, &cfg.instance_id);
    format!("/var/tmp/.wlsctx/{inst}")
}

/// The per-instance runtime dir's path *inside the sandbox*: the
/// step-5 bind always places it at the systemd-standard location,
/// regardless of the host's `XDG_RUNTIME_DIR` (the path-translation
/// case of decision #28 — the host path and this string agree only
/// for the default XDG, and the policy grants / the app's env use
/// *this* string so the two floors mediate the path the app sees).
pub(crate) fn sandbox_instance_dir(cfg: &SandboxConfig) -> String {
    let uid = nix::unistd::getuid().as_raw();
    format!(
        "/run/user/{uid}/wlsctx/{}",
        namespaces::cgroup_name_for(&cfg.app_id, &cfg.instance_id)
    )
}

pub(crate) fn instance_runtime_dir(cfg: &SandboxConfig) -> String {
    let uid = nix::unistd::getuid().as_raw();
    let xdg = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| format!("/run/user/{uid}"));
    format!(
        "{xdg}/wlsctx/{}",
        namespaces::cgroup_name_for(&cfg.app_id, &cfg.instance_id)
    )
}

/// Decision #17: NUL-terminate every path that crosses into C.
fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

/// `mount(2)` with NUL-terminated paths and a reported errno.
fn mount(src: &str, target: &str, fstype: &str, flags: u64, data: &str) -> Result<()> {
    let (s, t, f, d) = (cstr(src), cstr(target), cstr(fstype), cstr(data));
    // SAFETY: all four are valid NUL-terminated C strings; the
    // pointers outlive the `mount(2)` call.
    let rc = unsafe {
        libc::mount(
            s.as_ptr().cast(),
            t.as_ptr().cast(),
            f.as_ptr().cast(),
            flags,
            d.as_ptr().cast::<libc::c_void>(),
        )
    };
    if rc != 0 {
        bail!(
            "mount({src}, {target}, {fstype}, flags={flags}, data={data:?}): {}",
            io::Error::last_os_error()
        )
    }
    Ok(())
}

fn chroot(path: &str) -> Result<()> {
    let p = cstr(path);
    // SAFETY: a valid NUL-terminated path.
    let rc = unsafe { libc::chroot(p.as_ptr().cast()) };
    if rc != 0 {
        bail!("chroot({path}): {}", io::Error::last_os_error())
    }
    Ok(())
}

fn env_or(var: &str, fallback: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| fallback.to_string())
}

/// The GPU (`/dev/dri`) for the app: the host's directory is
/// **bind-mounted** into the fresh `/dev` — `/dev/dri` is a
/// *subdirectory* of devtmpfs, and subpath binds work unprivileged
/// (only the devtmpfs mount root is EINVAL — decision #18). A bind
/// keeps the nodes' canonical genfs SELinux labels (AGENTS.md);
/// `mknod` is no alternative — unprivileged `mknod` of device nodes
/// is EPERM on 7.2.11 (probed, SELinux enforcing; decision #19).
/// The bind is not ro (decision #21): the directory is root-owned
/// and the nodes' access follows the `render` group either way.
///
/// Access to the nodes follows the host's group rule: the user must
/// be in the `render` group (the same requirement rootless podman
/// documents) — [precheck_gpu] enforces it before the fork.
fn build_gpu() -> Result<()> {
    if !Path::new("/dev/dri").is_dir() {
        bail!("GPU requested but the host has no /dev/dri (pass --no-gpu)");
    }
    std::fs::create_dir("/dev/dri").context("creating /dev/dri")?;
    mount("/dev/dri", "/dev/dri", "none", libc::MS_BIND, "")?;
    Ok(())
}

/// The GPU precheck, run in the supervisor **before** the fork (it
/// tests host-side properties): `/dev/dri` must exist, and the user
/// must be in the `render` group (the same requirement as rootless
/// podman). `--no-gpu` skips the whole path.
pub(crate) fn precheck_gpu() -> Result<()> {
    if !Path::new("/dev/dri").is_dir() {
        bail!(
            "GPU requested but the host has no /dev/dri (pass --no-gpu) — \
             the sandbox would have no graphics"
        );
    }
    if !in_render_group() {
        bail!(
            "GPU requested but the current user is not in the `render` group \
             (required for GPU access, same as rootless podman). Add it: \
             `usermod -aG render <user>`, then log in again — or pass --no-gpu"
        );
    }
    Ok(())
}

/// Whether the current process is in the `render` group (primary or
/// supplementary).
fn in_render_group() -> bool {
    let name = cstr("render");
    // SAFETY: a valid NUL-terminated name; `getgrnam` returns a
    // static, libc-owned group entry (or NULL).
    let grp = unsafe { libc::getgrnam(name.as_ptr().cast()) };
    if grp.is_null() {
        return false;
    }
    let gid = unsafe { (*grp).gr_gid }; // SAFETY: non-null from getgrnam
    if nix::unistd::getgid().as_raw() == gid {
        return true;
    }
    nix::unistd::getgroups()
        .map(|gs| gs.iter().any(|g| g.as_raw() == gid))
        .unwrap_or(false)
}

/// The rootfs build (the §3.3 table as code). Runs in A: after the
/// user/mount/pid/**cgroup** namespaces (the cgroup ns must be
/// unshared *before* the ro-bind, which makes cgroup2 read-only —
/// decision #12) and before the second fork.
pub(crate) fn build_rootfs(cfg: &SandboxConfig) -> Result<()> {
    let prof = &cfg.profile;
    let uid = nix::unistd::getuid().as_raw();
    let home = std::env::var("HOME").context("HOME is required for the XDG rw-binds")?;
    let host_runtime = instance_runtime_dir(cfg);
    let inst_name = namespaces::cgroup_name_for(&cfg.app_id, &cfg.instance_id);

    // 1) Scratch: carry out of the tree what must survive the masks.
    //    It lives on `/var/tmp` — a plain rootfs directory outside
    //    `/dev`, `/sys`, `/run` and `/tmp`, the four trees this
    //    build replaces — because the scratch must stay resolvable
    //    through every step, including step 5's fresh `/run` (which
    //    masks the per-instance runtime dir itself: for the default
    //    `XDG_RUNTIME_DIR=/run/user/<uid>` a scratch inside that
    //    dir would be unresolvable after the mask). Not being in the
    //    capability set, the Landlock floor keeps the app out of it;
    //    `S` removes it on exit.
    let scratch = rootfs_scratch_dir(cfg);
    for d in [
        format!("{scratch}/dev"),
        format!("{scratch}/sys/devices"),
        format!("{scratch}/sys/class"),
        format!("{scratch}/runtime"),
    ] {
        std::fs::create_dir_all(&d).with_context(|| format!("creating the scratch dir {d}"))?;
    }
    // Other users must not walk the scratch on the host: it carries
    // the per-instance runtime dir (future home of the tagged
    // Wayland socket).
    std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("setting the mode of {scratch}"))?;
    for n in DEV_NODES {
        let src = format!("/dev/{n}");
        if !Path::new(&src).exists() {
            bail!("the host node {src} is missing; /dev cannot be built");
        }
        // `mount(2)` bind requires the target to exist; `create_dir_all`
        // made the dirs but not the files.
        let tgt = format!("{scratch}/dev/{n}");
        std::fs::File::create(&tgt).with_context(|| format!("creating the bind target {tgt}"))?;
        mount(&src, &tgt, "none", libc::MS_BIND, "")?;
    }
    mount(
        "/sys/devices",
        &format!("{scratch}/sys/devices"),
        "none",
        libc::MS_BIND,
        "",
    )?;
    mount(
        "/sys/class",
        &format!("{scratch}/sys/class"),
        "none",
        libc::MS_BIND,
        "",
    )?;
    // The per-instance runtime dir, carried the same way: for the
    // default XDG location it sits under `/run`, which the fresh
    // `/run` tmpfs of step 5 masks — a bind source resolved there
    // would silently hit the fresh tmpfs's empty stand-in directory
    // (a self-bind no-op that never crosses to the host).
    mount(
        &host_runtime,
        &format!("{scratch}/runtime"),
        "none",
        libc::MS_BIND,
        "",
    )?;

    // 2) A new layer over the whole tree (one-shot recursive
    //    self-bind — verified unprivileged on 7.2.11). Not ro:
    //    `MS_RDONLY` is silently dropped on a bind of a foreign
    //    superblock on this kernel (decision #21).
    mount("/", "/", "none", libc::MS_BIND | libc::MS_REC, "")?;

    // 3) /dev: a fresh tmpfs with the standard nodes (bound, so they
    //    keep their genfs labels), a fresh devpts instance (isolated
    //    from the host's pts) and a fresh /dev/shm.
    mount("none", "/dev", "tmpfs", 0, "mode=755")?;
    for n in DEV_NODES {
        // The fresh tmpfs is empty: the bind target must exist first.
        let tgt = format!("/dev/{n}");
        std::fs::File::create(&tgt).with_context(|| format!("creating {tgt}"))?;
        mount(
            &format!("{scratch}/dev/{n}"),
            &tgt,
            "none",
            libc::MS_BIND,
            "",
        )?;
    }
    std::fs::create_dir("/dev/pts").context("creating /dev/pts")?;
    // `MS_NOSUID` only — never `MS_NODEV` here: the VFS `may_open_dev`
    // denies `open(2)` of any device file underneath an `MNT_NODEV`
    // mount (EACCES, decided before any LSM hook), which would make the
    // ptmx — the very point of this mount — unopenable (decision #39).
    mount(
        "none",
        "/dev/pts",
        "devpts",
        libc::MS_NOSUID,
        "newinstance,ptmxmode=0666,mode=0620",
    )?;
    // The new instance's ptmx — binding the host's would hand the
    // app the host's pts master. Relative target, devtmpfs style.
    symlink("pts/ptmx", "/dev/ptmx").context("symlinking /dev/ptmx")?;
    // /dev/shm: a fresh private tmpfs (mode 1777, like the host's).
    // The build previously never created it, so any app that opens a
    // shared-memory file (or maps one through the `wl_shm`/`posix`
    // path) got `ENOENT` on the directory — the `wev` windowing test
    // hit exactly this. It is not part of the carried tree, so it
    // must be built here on the fresh `/dev` tmpfs. Its inodes take
    // the fresh-tmpfs default label (`tmpfs_t`), which the app's
    // `tmpfs_t` grants (dir + file) already cover; no new policy.
    std::fs::create_dir("/dev/shm").context("creating /dev/shm")?;
    mount("none", "/dev/shm", "tmpfs", 0, "mode=1777")?;
    if cfg.gpu {
        build_gpu()?;
    }

    // 4) /sys: a fresh tmpfs with binds of the subpaths. The sysfs
    //    mount root itself cannot be bound unprivileged (decision
    //    #18), and `devices/` + `class/` are all the app needs
    //    (PCI/DRM discovery). The binds are not ro (decision #21).
    //    `/sys/fs` is left empty: on 7.2 the cgroup2 filesystem is
    //    not re-rooted by the cgroup ns (decision #12), so there is
    //    no clean view to mount.
    mount("none", "/sys", "tmpfs", 0, "mode=755")?;
    for sub in ["devices", "class", "fs"] {
        std::fs::create_dir(format!("/sys/{sub}"))
            .with_context(|| format!("creating /sys/{sub}"))?;
    }
    mount(
        &format!("{scratch}/sys/devices"),
        "/sys/devices",
        "none",
        libc::MS_BIND,
        "",
    )?;
    mount(
        &format!("{scratch}/sys/class"),
        "/sys/class",
        "none",
        libc::MS_BIND,
        "",
    )?;

    // 5) /run: a fresh tmpfs with **only** the per-instance dir. The
    //    host's Wayland sockets sit directly under $XDG_RUNTIME_DIR
    //    and are deliberately invisible here — the app may reach only
    //    the tagged socket (Phase 5), never the host's. The
    //    instance dir's *content* arrives from the step-1 carry
    //    (`scratch/runtime`): its own host path is masked by this
    //    very mount, so binding it directly here would be a
    //    self-bind onto the fresh tmpfs's empty stand-in.
    mount("none", "/run", "tmpfs", 0, "mode=755")?;
    std::fs::create_dir("/run/user").context("creating /run/user")?;
    let user_dir = format!("/run/user/{uid}");
    std::fs::create_dir(&user_dir).context("creating the per-uid runtime dir")?;
    std::fs::set_permissions(&user_dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("setting the mode of {user_dir}"))?;
    let inst_dir = format!("{user_dir}/wlsctx/{inst_name}");
    std::fs::create_dir_all(&inst_dir).with_context(|| format!("creating {inst_dir}"))?;
    mount(
        &format!("{scratch}/runtime"),
        &inst_dir,
        "none",
        libc::MS_BIND,
        "",
    )?;

    // 6) /tmp: a fresh tmpfs sized by the profile.
    let data = if prof.tmp_size_mib == 0 {
        "mode=1777".to_string()
    } else {
        format!("mode=1777,size={mib}M", mib = prof.tmp_size_mib)
    };
    mount("none", "/tmp", "tmpfs", 0, &data)?;

    // 7) XDG rw self-binds: the standard set (always) plus the
    //    profile's extras. A single plain `MS_BIND` over the ro view
    //    makes the path writable again — verified on 7.2.11 (no
    //    `MS_REMOUNT` step: that is EPERM for mounts we do not own,
    //    and unnecessary).
    let mut dirs = vec![
        home.clone(),
        env_or("XDG_CONFIG_HOME", &format!("{home}/.config")),
        env_or("XDG_CACHE_HOME", &format!("{home}/.cache")),
        env_or("XDG_STATE_HOME", &format!("{home}/.local/state")),
        env_or("XDG_DATA_HOME", &format!("{home}/.local/share")),
    ];
    dirs.extend(prof.rw_binds.iter().cloned());
    for d in &dirs {
        if Path::new(d).is_dir() {
            mount(d, d, "none", libc::MS_BIND, "")?;
        }
    }

    // 8) Masks: empty tmpfs over the paths the app must not see
    //    (§3.3: `/root`, `/home/*` except ours, `/boot`, `/var`,
    //    `/srv`, `/media`, `/mnt`, `/opt/*` except the app's own
    //    dir, plus the profile's).
    let mut masks: Vec<String> = vec![
        "/root".into(),
        "/boot".into(),
        "/var".into(),
        "/srv".into(),
        "/media".into(),
        "/mnt".into(),
    ];
    if let Ok(rd) = std::fs::read_dir("/home") {
        for e in rd.flatten() {
            let p = e.path();
            if p != Path::new(&home) {
                masks.push(p.to_string_lossy().into_owned());
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir("/opt") {
        for e in rd.flatten() {
            let s = e.path().to_string_lossy().into_owned();
            if !prof.ro_binds.iter().any(|a| a == &s) {
                masks.push(s);
            }
        }
    }
    masks.extend(prof.mask.iter().cloned());
    for m in &masks {
        mount("none", m, "tmpfs", 0, "mode=755")?;
    }

    // 9) The assembled root becomes the process root.
    chroot("/")?;
    Ok(())
}

/// B's part of the filesystem setup: a **fresh** procfs. It must be
/// mounted by B itself — the member of the new pid ns — so the view
/// is namespaced (the app is PID 1 and does not see the host's
/// process tree). The ro-bind of the host's `/proc` is already in
/// place from step 2 of [build_rootfs]; this overlays it.
pub(crate) fn mount_namespaced() -> Result<()> {
    mount(
        "proc",
        "/proc",
        "proc",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::namespaces::NetworkMode;
    use crate::sandbox::run_sandboxed;
    use crate::sandbox::userns::tests::{ChildOut, run_in_child};
    use std::ffi::OsString;
    use std::io::Write;

    fn cfg(app: &str, inst: &str, gpu: bool) -> SandboxConfig {
        let mut p = crate::profile::Profile::adhoc();
        p.gpu = gpu;
        SandboxConfig {
            app_id: app.to_string(),
            instance_id: inst.to_string(),
            network: NetworkMode::Shared,
            gpu,
            profile: p,
            wayland: None,
        }
    }

    fn run_cmd(command: &[&str], config: &SandboxConfig) -> (Option<i32>, String, String) {
        let _lock = crate::testutil::SANDBOX_LOCK
            .lock()
            .unwrap_or_else(|e| panic!("SANDBOX_LOCK poisoned: {e}"));
        let command: Vec<OsString> = command.iter().map(OsString::from).collect();
        let config = config.clone();
        run_in_child(
            move |o: &mut ChildOut| match run_sandboxed(&command, &config) {
                Ok(code) => code,
                Err(e) => {
                    let _ = writeln!(o.err(), "run_sandboxed: {e:#}");
                    2
                }
            },
        )
    }

    /// Classify a `run_cmd` result whose command must have exited 0.
    /// Returns true when the command ran (assert on the output next);
    /// environment skips are reported, kernel map rejection panics.
    fn expect_ok(code: Option<i32>, out: &str, err: &str, what: &str) -> bool {
        match code {
            Some(0) => true,
            Some(126) => {
                if err.contains("uid_map") || err.contains("gid_map") {
                    panic!(
                        "the kernel rejected the single-extent map (design failure, not a skip):\n{err}"
                    );
                }
                if err.contains("rootfs construction failed")
                    || err.contains("sandbox setup failed")
                {
                    panic!(
                        "{what}: a setup step failed inside the namespaces (a real failure, not a skip):\n{err}"
                    );
                }
                eprintln!("skipping {what} (environment cannot create the namespaces):\n{err}");
                false
            }
            Some(other) => panic!("{what} failed (exit {other}, expected 0):\n{out}\n{err}"),
            None => panic!("test harness failed"),
        }
    }

    /// The fstype of a host mount (from the test process's view).
    fn host_fstype(mountpoint: &str) -> String {
        std::fs::read_to_string("/proc/mounts")
            .unwrap_or_default()
            .lines()
            .find(|l| l.split_whitespace().nth(1) == Some(mountpoint))
            .map(|l| l.split_whitespace().nth(2).unwrap_or_default().to_string())
            .unwrap_or_default()
    }

    /// 3.4: the assembled rootfs as the app sees it — the mount table
    /// matches the §3.3 reference, the root is read-only, `/dev`
    /// nodes are openable, the host Wayland socket is absent, and the
    /// namespaced views (pid 1, own cgroup, real uid) are right.
    #[test]
    fn the_rootfs_matches_the_reference() {
        let script = r#"
            for m in / /dev /dev/pts /proc /sys /sys/devices /sys/class /run /tmp /root /boot /var /srv /media /mnt; do
                # The topmost mount at each point: /proc/mounts lists
                # the whole stack (bottom first), so take the last line.
                echo "MNT $m: $(awk -v m="$m" '$2==m{l=$3" "$4} END{print l}' /proc/mounts)"
            done
            echo "ROOTMI: $(awk -v m=/ '$5==m{print $1, $6, $8}' /proc/self/mountinfo | tr '\n' ';')"
            echo "LSROOT: $(ls /)"
            echo "PTMX: $(readlink /dev/ptmx)"
            echo "URAND: $(head -c 4 /dev/urandom 2>&1 | od -An -tx1 | tr -d ' \n' | wc -c)"
            echo "NULL: $(echo ok > /dev/null 2>&1 && echo ok || echo fail)"
            echo "RUN: $(ls /run/user/$(id -u) 2>/dev/null)"
            echo "WAYLAND: $(ls /run/user/$(id -u) 2>/dev/null | grep -c '^wayland' || true)"
            echo "PID1: $(cat /proc/1/comm 2>/dev/null)"
            echo "CGROUP: $(cat /proc/self/cgroup)"
            echo "UID: $(id -u)"
        "#;
        let (code, out, err) = run_cmd(&["/bin/sh", "-c", script], &cfg("app", "1", false));
        if !expect_ok(code, &out, &err, "rootfs") {
            return;
        }
        let get = |k: &str| -> String {
            out.lines()
                .find_map(|l| l.strip_prefix(&format!("{k}: ")).map(str::to_owned))
                .unwrap_or_else(|| panic!("missing {k} in output:\n{out}"))
        };

        // The mount table: fstype per target.
        let expect: Vec<(&str, String)> = vec![
            ("/", host_fstype("/")),
            ("/dev", "tmpfs".into()),
            ("/dev/pts", "devpts".into()),
            ("/proc", "proc".into()),
            ("/sys", "tmpfs".into()),
            ("/sys/devices", "sysfs".into()),
            ("/sys/class", "sysfs".into()),
            ("/run", "tmpfs".into()),
            ("/tmp", "tmpfs".into()),
            // The masks: empty tmpfs.
            ("/root", "tmpfs".into()),
            ("/boot", "tmpfs".into()),
            ("/var", "tmpfs".into()),
            ("/srv", "tmpfs".into()),
            ("/media", "tmpfs".into()),
            ("/mnt", "tmpfs".into()),
        ];
        for (m, fstype) in &expect {
            let line = get(&format!("MNT {m}"));
            let got_fs = line.split_whitespace().next().unwrap_or_default();
            assert_eq!(
                got_fs,
                fstype.as_str(),
                "wrong fstype at {m}: {line} (expected {fstype})\n{out}"
            );
        }
        // NOTE: the host-tree binds are not read-only (decision #21 —
        // unattainable on 7.2.11 for foreign superblocks); the
        // read-only *semantics* for the app come from its real uid
        // plus the nono policy (Phase 4), which is verified there.
        // The fresh devpts instance is reachable through /dev/ptmx.
        assert_eq!(get("PTMX"), "pts/ptmx");
        // The /dev nodes are openable by the app (the §3.4 item).
        assert_eq!(
            get("URAND"),
            "8",
            "reading 4 bytes from /dev/urandom must yield 8 hex digits:\n{out}"
        );
        assert_eq!(get("NULL"), "ok", "/dev/null must be writable");
        // Only the per-instance dir is visible under the runtime dir.
        assert_eq!(
            get("RUN"),
            "wlsctx",
            "only the per-instance dir may be visible under the runtime dir:\n{out}"
        );
        // The host Wayland socket must not be visible.
        assert_eq!(
            get("WAYLAND"),
            "0",
            "the host's wayland socket leaked into the sandbox:\n{out}"
        );
        // The namespaced views: the app is PID 1 of a fresh pid ns
        // and sees its own cgroup as the ns root (decision #20;
        // 7.2 renders the ns root as "/").
        assert_eq!(get("PID1"), "sh", "the app must be PID 1:\n{out}");
        assert_eq!(get("CGROUP"), "0::/", "the cgroup ns view:\n{out}");
        // The real uid from the start (decision #10).
        assert_eq!(
            get("UID"),
            nix::unistd::getuid().as_raw().to_string(),
            "the in-ns uid must be the real uid:\n{out}"
        );
        // / is not masked away and the XDG rw self-bind worked: the
        // home dir is writable from the app (the probe uses $HOME
        // from the inherited environment).
        let (code2, out2, err2) = run_cmd(
            &[
                "/bin/sh",
                "-c",
                "touch \"$HOME/wlsctx-write-probe\" && rm -f \"$HOME/wlsctx-write-probe\" && echo ok || echo fail",
            ],
            &cfg("app", "2", false),
        );
        if expect_ok(code2, &out2, &err2, "XDG rw self-bind") {
            assert_eq!(
                out2.trim(),
                "ok",
                "the XDG rw self-bind must make $HOME writable:\n{out2}"
            );
        }
    }

    /// 3.3: the GPU path — in the `render` group, `/dev/dri` is built
    /// and the nodes are openable; otherwise the precheck fails
    /// before the fork with a message naming the group.
    #[test]
    fn the_gpu_path_follows_the_render_group() {
        let name = cstr("render");
        // SAFETY: a valid NUL-terminated name; `getgrnam` returns a
        // static, libc-owned entry (or NULL).
        let grp = unsafe { libc::getgrnam(name.as_ptr().cast()) };
        if grp.is_null() {
            panic!("no `render` group on this host; cannot test the GPU path");
        }
        let gid = unsafe { (*grp).gr_gid }; // SAFETY: non-null from getgrnam
        let in_render = nix::unistd::getgid().as_raw() == gid
            || nix::unistd::getgroups()
                .map(|gs| gs.iter().any(|g| g.as_raw() == gid))
                .unwrap_or(false);

        if in_render {
            let (code, out, err) = run_cmd(
                &[
                    "/bin/sh",
                    "-c",
                    "ls /dev/dri; for f in /dev/dri/renderD*; do [ -r \"$f\" ] && [ -w \"$f\" ] && echo ACCESS-RW; done",
                ],
                &cfg("app", "3", true),
            );
            if !expect_ok(code, &out, &err, "gpu build") {
                return;
            }
            assert!(
                out.contains("renderD"),
                "a render node must be built:\n{out}"
            );
            assert!(
                out.contains("ACCESS-RW"),
                "the render node must be openable r/w by the app:\n{out}"
            );
        } else {
            let (code, _out, err) = run_cmd(&["/bin/sh", "-c", "id"], &cfg("app", "3", true));
            assert_eq!(
                code,
                Some(2),
                "the GPU precheck must fail before the fork (harness exit 2):\n{err}"
            );
            assert!(
                err.contains("render"),
                "the precheck error must name the render group:\n{err}"
            );
        }
    }
}
