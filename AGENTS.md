# AGENTS.md

wlsctx: runs GUI apps (JetBrains IDEs, Librewolf) in an unprivileged
**in-process sandbox** on a wlroots Wayland desktop (sway, Fedora) with
native Wayland + GPU rendering. The Rust binary `wlsctx` creates
namespaces, a private rootfs and landlock+seccomp confinement (`nono`)
and tags the app's Wayland socket with the `wp_security_context_v1`
protocol so the compositor identifies sandboxed clients. The project is
mid-rework away from the old podman/quadlet deployment: **PLAN.md is the
authoritative plan and decisions log — read it before non-trivial
changes** (README.md is stale pending its phase-8 rewrite).

## Layout

- `src/main.rs` — binary entry: logging, CLI parse, pipeline dispatch
- `src/cli.rs` — clap subcommand tree: `run` (the tagged Wayland
  pipeline, `--app`/`--instance`/`--gpu`) and `wayland` (legacy mode)
- `src/wayland/` — the tagged Wayland socket: `listener` (socket
  activation / `--listen`), `roundtrip` (bounded sync), `context`
  (`wp_security_context_v1`), `signals` (signalfd loop)
- `src/sandbox/` — the in-process sandbox: `userns`, `namespaces`
  (mount/pid/cgroup/ipc/uts/net), `mounts` (private rootfs builder),
  `policy` (the nono `CapabilitySet` + three-stage apply, #27),
  `supervise` (notify-fd handoff, app-pid report, verdict pipe, the
  S-side supervisor loop, #23/#25/#26), `mod` (S→A→B pipeline,
  `run_sandboxed`, the S-side signal forwarder / `terminate_app`,
  sd-notify, #33)
- `src/profile/` — per-app TOML profiles (`gpu`, `ro_binds`, `rw_binds`,
  `mask`, `env`; `deny_unknown_fields`)
- `src/testutil.rs` — shared `#[cfg(test)]` helpers (env locking, TmpDir)
- `PLAN.md` — rework plan: architecture, decisions log, phase/task list
- `assets/` — logos/headers

## Facts

- Target: Fedora 45 (upgrade in progress), user-level systemd,
  sway/wlroots desktop. No containers: the sandbox is created by
  `wlsctx` itself (namespaces, private rootfs, landlock+seccomp via
  `nono`) — see PLAN.md.
- The app runs as its **real uid** inside the user namespace: the
  `uid_map` is a **single extent `<uid> <uid> 1`**, written **exactly
  once** (decision #9), because that is all an unprivileged creator may
  write (decision #10). In-ns `0` is therefore **unmapped** — the app
  can never be root or another user, and root-owned trees are simply
  unwritable by it. (The old two-entry `0→uid; uid→uid` map was
  replaced in Phase 3.)
- The private rootfs is **rebuilt, not masked**: the recursive self-bind
  of `/` (never `ro` — see below) is the base; `/dev` and `/sys` are
  **fresh tmpfs** with subpath binds of the nodes the app needs, because
  binding the *mount root* of devtmpfs/sysfs/ext4 is `EINVAL`
  unprivileged (decision #18) and `mknod` is `EPERM` (decision #19).
  `MS_BIND|MS_RDONLY` on those foreign-superblock binds silently drops
  the ro flag and `MS_REMOUNT` is `EPERM` (decision #21) — so ro
  semantics come from the app's real uid plus nono's landlock/seccomp
  policy, not from mount flags. The build scratch lives on
  `/var/tmp/.wlsctx/<inst>` and carries the per-instance runtime dir
  out from under the fresh-`/run` mask (decision #28). The combined
  seccomp-notify + Landlock floor is applied three-stage in B pre-exec
  (decision #27); B blocks on A's verdict before exec (decision #26);
  S services the listener (auto-deny, decision #25).
- The cgroup ns is rooted at the instance sub-cgroup, which must be
  created and entered **before** `unshare(CLONE_NEWCGROUP)` (decision
  #20); the app then sees `0::/`.
- The app only sees the **tagged** Wayland socket, never the host
  socket; the reference pipe ("close" fd) must stay open for the
  process lifetime (ownership note in `wayland/context.rs`).
- Per-instance runtime dir: `$XDG_RUNTIME_DIR/wlsctx/<instance>/`.
- GPU: `/dev/dri/renderD*` nodes are bind-mounted into the sandbox's
  `/dev`; the user must be in the `render` group. `/dev` nodes are
  **bind-mounted, not mknod'd**, so future SELinux modules can use the
  canonical genfs labels.
- SIGHUP exits with status 129 (128+SIGHUP) by design — no restart
  logic in the binary (intentional).
- The app is the **only** process the supervisor arms: it mediates for
  B's pid (decision #25). A *child* of the app issuing a trapped syscall
  is never serviced and deadlocks the handoff (decision #32) — so a
  shell app that spawns subshells (e.g. `$(...)`) will hang; the
  reference app is single-process.
- SIGTERM/SIGINT are **forwarded to the app** (SIGTERM, then SIGKILL
  after 2 s, since pidns-init ignores default-action signals, #13/#33);
  SIGHUP also terminates the app and exits 129. S sends `READY=1` to
  systemd after the handoff and untags the Wayland socket on teardown.
- Rust edition 2024; deps are pinned in Cargo.lock. `nono` is
  Apache-2.0 (compatible with this repo's AGPL-3.0); its docs are thin,
  the crate source is the reference.
- This is a personal WIP repo: the rework is phase-by-phase (PLAN.md),
  each phase committed and working; the README rewrite is phase 8.

## Commit conventions

- Small commits, one per meaningful change, committed as you go.
- Subject: `<emoji> <type>: <summary>` — a conventional type prefix
  (`feat:`, `fix:`, `chore:`, `docs:`, …) and a summary under 72 chars.
  The single emoji is chosen per change to capture what actually changed;
  there is no fixed set of allowed emojis.
- End the message with an `Assisted-by: <agent>:<model>` trailer (no
  "generated with" line).
