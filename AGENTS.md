# AGENTS.md

wlsctx: runs GUI apps (JetBrains IDEs, Librewolf) in unprivileged Podman
pods on a wlroots Wayland desktop (sway, Fedora) with native Wayland + GPU
rendering. The Rust binary `wlsctx` tags the pod's shared Wayland socket with
the `wp_security_context_v1` protocol so the compositor identifies sandboxed
clients; in the default mode B deployment it additionally runs a
transparent protocol relay (`--proxy`) with an optional global allowlist
and a clipboard/primary-selection receive-gate, plus an optional
host-side broker (`--broker`) that serves both a consent prompt (dropped
*reads*) and a fire-and-forget copy-out notification (app *writes*,
`--notify-copy-out`). **README.md is the full architecture/threat-model
doc — read it before non-trivial changes. TASKS.md tracks deferred
work (next up: rate-limit the Phase 6 copy-out notification; the
selection-audit log, Phase 9, is done).**

## Layout

- `src/main.rs` — the wlsctx binary: CLI parsing, tag-and-park
  lifecycle, and the `--broker` / `--decide` entry points
- `src/lib.rs` — library modules: `proxy/` (the `--proxy` relay: wire
  parser, object bookkeeping, interface tables, global allowlist
  policy, the selection receive-gate — which also *detects* app
  writes/clears via `ClipboardGate::set_selection` — the broker client,
  and `audit.rs`, the Phase 9 selection-audit sink: one size-only
  `key=value` record per `set`/`read`/`clear`/`serve` under the
  `audit` log target),
  `broker.rs` (the broker daemon: N-D-JSON, one consent
  `clipboard-read` request/response *and* one one-way
  `clipboard-write` notification per connection)
- `tests/proxy_integration.rs` — three-party integration tests (fake
  compositor, real wayland-client, the relay): pass-through,
  allowlist, clipboard (incl. the selection-audit records), primary
  selection, broker consent, copy-out notification
- `TASKS.md` — deferred / follow-up tasks (next: rate-limit the Phase
  6 copy-out notification; the gate already records writes via
  `ClipboardGate::set_selection`)
- `scripts/gen_interface_table.py` — generates
  `src/proxy/interfaces.rs` and `src/proxy/wlr_tables.rs` from the
  protocol XMLs; do not hand-edit the generated files
- `containers/systemd/` — quadlets: `wl-app@.pod` + sidecars (`wl-display@`,
  `wl-dbus@`, `wl-xwayland@`), app containers (`app-podman-@`), image/build
  units. Drop-ins: `wl-.container.d/` (pod defaults), `app-podman-.container.d/`
- `containers/apps/` — Containerfiles: `runtime`, `jetbrains`, `librewolf`,
  `xwayland-satellite`, `xdg-dbus-proxy`, `dev/rust`
- `selinux/` — CIL blocks for the sidecar containers
- `systemd/user/` — non-quadlet units (wlsctx socket activation, the
  wlsctx-broker socket+service, dbus-proxy fallback)
- `docker-bake.hcl` — image build matrix (Fedora `DISTRO_RELEASE`)

## Facts

- Target: Fedora 43, user-level systemd, podman quadlet
  (`~/.config/containers/systemd/`), sway/wlroots.
- Quadlet naming: instance `%i` = pod/app instance; `%j` = app product
  (e.g. `rustrover`). Pod runtime dir is `/run/pod` (`POD_RUNTIME_DIR`).
- Pod XDG homes are pod named volumes (`pod_%i_home`, `%j_%i_cache`, …),
  not the real homedir. Apps run read-only with `DropCapability=ALL`.
- `--ipc=host` + `/dev/dri/renderD128…131` (optional, `-` prefix) are
  required for Vulkan/GPU; do not "clean them up".
- `wlsctx` image comes from `ghcr.io/wlsctx/wlsctx`; all other images are
  local (`Policy=never`).
- D-Bus is only reachable via the `wl-dbus@` proxies
  (`/run/pod/session-bus-proxy`, `at-spi-bus-proxy`).
- The `--proxy` relay is convention-adaptive: Rust wayland-backend
  uses display=ID 1, client IDs from 2, server IDs from 0xFF00_0000;
  C libwayland uses display=ID 0, client IDs from 1, server IDs from
  0x80000000. The first message of a connection pins the convention
  for both ends (src/proxy/objects.rs). Events use the raw 0-based
  index in the interface's event list — not `requests.len()+index`.
- The relay's fd sanity check treats only in-memory channels
  (memfd/pipe/socket, via `/proc/self/fd/<n>` readlink) as valid
  `receive` targets; a path is a fatal protocol error.
- The broker is a **host** user service (`systemd/user/`), not a
  quadlet: the scratch wlsctx image has no session bus, so a
  containerized broker could never notify the user.
- The broker speaks N-D-JSON with **two request kinds** (both over the
  same socket, dispatched on the line's `kind` field): `clipboard-read`
  (request/response, the consent prompt — the daemon answers after the
  user decides) and `clipboard-write` (one-way, Phase 6 — the daemon
  fires `notify-send` and closes with no reply). The write notification
  is fire-and-forget and fails open: the relay's `notify_write` uses a
  2 s deadline and never blocks or alters the write.
- Rust edition 2024; deps in Cargo.toml are pinned in Cargo.lock.
  wayland-backend 0.31.11, wayland-scanner 0.31.7,
  wayland-protocols 0.32.9 (features `client, staging, unstable`),
  rustix 1.1.2, nix 0.30.1, serde/serde_json.
- This is a personal WIP repo: several configs are intentionally mid-tuning
  (commented knobs in drop-ins, stub SIGHUP handler, loose at-spi filter).
