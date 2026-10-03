# AGENTS.md

wlsctx: runs GUI apps (JetBrains IDEs, Librewolf) in unprivileged Podman
pods on a wlroots Wayland desktop (sway, Fedora) with native Wayland + GPU
rendering. The Rust binary `wlsctx` tags the pod's shared Wayland socket with
the `wp_security_context_v1` protocol so the compositor identifies sandboxed
clients. **README.md is the full architecture/threat-model doc — read it
before non-trivial changes.**

## Layout

- `src/main.rs` — the wlsctx binary (only Rust code; Dockerfile builds it static)
- `containers/systemd/` — quadlets: `wl-app@.pod` + sidecars (`wl-display@`,
  `wl-dbus@`, `wl-xwayland@`), app containers (`app-podman-@`), image/build
  units. Drop-ins: `wl-.container.d/` (pod defaults), `app-podman-.container.d/`
- `containers/apps/` — Containerfiles: `runtime`, `jetbrains`, `librewolf`,
  `xwayland-satellite`, `xdg-dbus-proxy`, `dev/rust`
- `selinux/` — CIL blocks for the sidecar containers
- `systemd/user/` — non-quadlet units (wlsctx socket activation, dbus-proxy fallback)
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
- Rust edition 2024; deps in Cargo.toml are pinned in Cargo.lock.
- This is a personal WIP repo: several configs are intentionally mid-tuning
  (commented knobs in drop-ins, stub SIGHUP handler, loose at-spi filter).
