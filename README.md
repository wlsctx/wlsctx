# wlsctx

Run GUI applications (JetBrains IDEs, Librewolf) in **unprivileged Podman
containers** on a **wlroots Wayland desktop** (sway, Fedora) while keeping the
UX as close to unconfined as possible: windows are **native Wayland clients**
with **GPU rendering** — no VNC, no RDP, no screen re-encoding, no blurry
text.

The point is blast-radius reduction: a hostile IDE extension (supply-chain
attack) is confined to a pod with a disposable home, a filtered D-Bus, and a
private network, but it still *looks and feels* like a normal local app.

This is a work in progress (personal-dev-laptop target: 1–2 human users).

## How it works

Every app instance runs as a **podman pod** containing four containers:

```
wl-app@<instance>  (pod: shared /run/pod tmpfs, private network ns)
├── wl-display@    → wlsctx:  creates /run/pod/wayland-1 tagged with a
│                     wp_security_context_v1 (sandbox_engine=podman,
│                     app_id, instance_id), held open for the pod's lifetime
├── wl-dbus@       → xdg-dbus-proxy: filtered views of the host session bus
│                     (portals only) and at-spi bus into the pod
├── wl-xwayland@   → xwayland-satellite: in-pod X server (DISPLAY=:0) for
│                     X11-only apps; `xhost SI:localuser` for local access
└── app-podman-@   → the actual app (IDE / browser), read-only rootfs,
                     /dev/dri render nodes, --ipc=host (Vulkan)
```

### The core trick: `wlsctx` (src/main.rs)

wlroots exposes the staging Wayland protocol
[`wp_security_context_v1`](https://wayland.app/protocols/security-context-v1),
intended for apps that want to give a *child process* its own tagged Wayland
socket. wlsctx repurposes it in the other direction:

1. The wlsctx container connects to the host compositor (the host's
   `wayland-1` socket file is passed in via `StandardInput=file:` /
   `StandardOutput=file:` — no extra privileges, no special SELinux label
   needed for the socket itself).
2. It calls `wp_security_context_manager_v1.create_listener()` on a socket
   that will live at `$POD_RUNTIME_DIR/wayland-1` (`/run/pod/wayland-1`)
   inside the pod, and sets `sandbox_engine=podman`, `app_id`, `instance_id`.
3. It holds the protocol's reference pipe open so the tagged socket stays
   valid, sd-notify READY, then sits on a `signalfd(2)` loop (catatonit-style)
   until the pod goes away.

Now every app in the pod connects to `WAYLAND_DISPLAY=/run/pod/wayland-1` —
a **real, unproxied Wayland socket** — but the compositor knows exactly which
sandboxed app/instance every window belongs to. The security context is a
*labelling/policy* mechanism, not the containment boundary itself.

Two input modes: `--listen=<path>` (binds its own socket, default in the
quadlet) or `--socket-activation` (systemd `wlsctx@.socket`, app/instance IDs
derivable from the unit instance name via `LISTEN_FDNAMES`).

### Containment layers

| Layer | What it blocks |
|---|---|
| Podman unprivileged container | kernel escape; `NoNewPrivileges`, `DropCapability=ALL`, read-only rootfs |
| SELinux CIL blocks (`selinux/`) | sidecar containers get their own confined `process` context (connect to host Wayland / D-Bus sockets, send filtered messages) instead of unconfined userspace |
| D-Bus proxy (`wl-dbus@`) | host session bus is unreachable directly: only `org.freedesktop.portal.*` calls (plus per-app names, e.g. `io.gitlab.librewolf.*`) and a loose at-spi passthrough for accessibility |
| Volume layout | `$HOME`, `.cache`, `.config`, `.local` are **pod named volumes** (`pod_%i_home`, …), *not* the real homedir; `~/Downloads` is a separate `noexec` volume; everything else read-only. Deleting the pod's volumes is the recovery procedure |
| Pod network namespace | `wl-app@.network` creates a private podman network per instance shared by the pod's containers (`wl-dbus@` is explicitly `Network=none`); the app reaches the internet through the pod's bridge but has no direct LAN presence |
| `XAUTHORITY` + `xhost SI:localuser` | X access to the in-pod satellite is scoped to the local user |

### GPU / rendering

App and Xwayland containers get the GPU render nodes
(`/dev/dri/renderD128…131`, `-` prefix = optional) and `--ipc=host` (needed
for Vulkan cross-process semaphores). Apps use Mesa/Vulkan/EGL directly, so
sway composites their windows exactly like unconfined clients. If the
render nodes are missing, containers still start and software rendering is
used.

## Images

Built with `docker buildx bake` (see `docker-bake.hcl`, Fedora
`DISTRO_RELEASE=43`):

| Image | Built from | Contents |
|---|---|---|
| `wlsctx` | `Dockerfile` (static, FROM scratch) | the Rust binary; published at `ghcr.io/wlsctx/wlsctx` |
| `shell-runtime` / `shell-devel` / `java-headless-runtime` / `wayland-runtime` / `java-wayland-runtime` | `containers/apps/runtime/Containerfile` | Fedora base; the `wayland-runtime` stage carries Mesa/Vulkan, PipeWire, foot/kitty, Xwayland, fonts |
| `ext-rustrover` | `containers/apps/jetbrains/Containerfile` | latest JetBrains product (`--build-arg JB_CODE=…`), fetched from JetBrains' API, **GPG-verified** (inline or downloaded key), unpacked to `/opt`, and patched with `-Dawt.toolkit.name=WLToolkit` in every `.vmoptions` to force the native Wayland toolkit |
| `librewolf` | `containers/apps/librewolf/Containerfile` | LibreWolf from its own repo (key pinned in-repo) |
| `xwayland-satellite` | `containers/apps/xwayland-satellite/Containerfile` | Rust tool from a `Supreeeme/xwayland-satellite` fork |
| `xdg-dbus-proxy` | `containers/apps/xdg-dbus-proxy/` | alpine or Fedora build of the proxy |

The IDE is distributed as an **image layer**: the app container uses
`Mount=type=image,source=ext-rustrover,destination=/opt`, so the app code is
immutable and the license key is the only per-user file (`Secret=`).

## Deploy

Quadlets live in `containers/systemd/` and install to
`~/.config/containers/systemd/`; the plain user units in `systemd/user/`
go to `~/.config/systemd/user/`.

1. Build/pull the images (`wlsctx` from ghcr, the rest locally; the `.image`
   units define pull policy — local ones are `Policy=never`).
2. Install the SELinux CIL blocks in `selinux/` as local modules
   (compile with the checkpolicy toolchain; needed for the `wl-dbus@` and
   `wlsctx` container labels). *WIP: exact build/load recipe not yet
   documented.*
3. `systemctl --user daemon-reload`
4. `systemctl --user start app-podman-rustrover@rustrover` (or
   `app-podman-librewolf@…`). This pulls in the pod plus the
   `wl-display@` / `wl-dbus@` / `wl-xwayland@` sidecars, which are
   `StopWhenUnneeded` and die with the app.

`app-podman-debug@` is a root `sleep 30d` container (with `SYS_CHROOT` and
cgroup access) for inspecting the pod from inside.

## Known gaps / WIP

- SIGHUP handling in `wlsctx` is a stub (`TODO: SIGHUP restart`).
- at-spi D-Bus filtering is in loose (`--sloppy-names`) mode; the strict
  per-method rule set is commented out in `wl-dbus@.container`.
- The residual-risk surface is `--ipc=host` + raw render-node access (GPU
  escape) — inherent to native GPU rendering, not mitigated by this project.
- The inline JetBrains GPG key in the Containerfile expired 2026-03-15; use
  `JB_KEYS_SOURCE=download` (checksummed) or refresh the inline key.
- No per-container X isolation *within* a pod: every app in a pod can reach
  the shared satellite X display.
- `wl-app@.pod` references `ServiceName=wl-pod@`, a unit that is not in the
  repo.
- Several knobs in the drop-ins (`TMP_SIZE`, per-variable XDG passthrough)
  are commented out mid-tuning.
