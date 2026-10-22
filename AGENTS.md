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
- `src/cli.rs` — clap CLI (currently the single `wayland` mode; becomes
  the subcommand tree per PLAN.md)
- `src/wayland/` — the tagged Wayland socket: `listener` (socket
  activation / `--listen`), `roundtrip` (bounded sync), `context`
  (`wp_security_context_v1`), `signals` (signalfd loop)
- `src/sandbox/`, `src/profile/` — placeholders for the in-process
  sandbox and per-app TOML profiles (PLAN.md phases 1–4)
- `src/testutil.rs` — shared `#[cfg(test)]` helpers (env locking, TmpDir)
- `PLAN.md` — rework plan: architecture, decisions log, phase/task list
- `assets/` — logos/headers

## Facts

- Target: Fedora 45 (upgrade in progress), user-level systemd,
  sway/wlroots desktop. No containers: the sandbox is created by
  `wlsctx` itself (namespaces, private rootfs, landlock+seccomp via
  `nono`) — see PLAN.md.
- The app runs as its **real uid (non-root)** inside the user namespace.
  The `uid_map` maps both `0` (so the mount phase holds CAP_SYS_ADMIN)
  and the real uid (so the app keeps its identity). Modern kernels
  allow **exactly one write** to the map files — there is no
  post-hoc narrowing (PLAN decision #9, pending confirmation).
  Whatever the final design, the `0` entry must be kept inert:
  nono's seccomp denies `setuid`/`setgid`/`setres*`/`sete*` so the app
  can never become ns-0 again (PLAN §3.1).
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
- Rust edition 2024; deps are pinned in Cargo.lock. `nono` is
  Apache-2.0 (compatible with this repo's AGPL-3.0); its docs are thin,
  the crate source is the reference.
- This is a personal WIP repo: the rework is phase-by-phase (PLAN.md),
  each phase committed and working; the README rewrite is phase 8.
