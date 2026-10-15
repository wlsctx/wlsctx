<p align="center">
  <img src="assets/wlsctx-header-tagline.svg" alt="wlsctx — Wayland security context wrapper" width="489">
</p>

# wlsctx

Run GUI applications (JetBrains IDEs, Librewolf) in **unprivileged Podman
containers** on a **wlroots Wayland desktop** (sway, Fedora) while keeping
the UX as close to unconfined as possible: windows are **native Wayland
clients** with **GPU rendering** — no VNC, no RDP, no screen
re-encoding, no blurry text.

The threat model is a supply-chain-compromised IDE extension (or a
compromised browser download): the sandbox must not reach host secrets,
home-directory files, or privileged Wayland/D-Bus interfaces — while still
*looking and feeling* like a normal local app.

This is a work in progress (personal-laptop target: 1–2 human users).

## Why `wp_security_context_v1`

[wp_security_context_v1](https://wayland.app/protocols/security-context-v1)
is a Wayland *staging* protocol from wlroots, intended for an app to give a
*child process* its own tagged Wayland socket. wlsctx repurposes it in the
other direction:

1. `wlsctx` connects to the host compositor.
2. It calls `wp_security_context_manager_v1.create_listener()` on a
   listening socket and sets the context's `sandbox_engine=podman`,
   `app_id` and `instance_id`.
3. It holds the protocol's reference pipe open (it keeps the *write* end
   for its whole lifetime), so the tagged socket stays valid; it
   sd-notifies `READY`, then parks on a `signalfd(2)` loop until killed.

**The tagging stays plain in both deployment modes.** In mode B the
`wlsctx` sidecar additionally runs a **transparent relay**
(`--proxy`): the app connects to a second socket (`/run/pod/wayland-1`)
that the app sees as an ordinary Wayland compositor, and the relay
copies the stream byte-for-byte over the tagged connection — the
compositor still sees one plain client per app with its own `render`
fd and direct GPU access, and still enforces per-context policy from
the security context. Mode A does the same standalone: the
socket-activated socket in the host's `XDG_RUNTIME_DIR` is the relay's
public socket, and the tagged socket is bound inside the container.
(Both modes can fall back to the original tag-and-park behaviour: the
client connects to the tagged socket directly and nothing is
intercepted.) The relay is a protocol *interpreter*, not a
re-implementation: it re-parses the messages it relays (the interface
tables are generated from the protocol XML) and applies two optional
policies on the way in from the app — a **global allowlist**
(`--allow-globals`) and a **selection receive-gate** (below) — before
forwarding or dropping them. The security context is the mechanism by
which the *compositor* discriminates; the pod is the mechanism by
which *filesystem, D-Bus and network* are discriminated. Containment
is layered:

| Layer | What it blocks |
|---|---|
| Unprivileged podman container | kernel escape; `NoNewPrivileges`, `DropCapability=ALL`, read-only rootfs |
| SELinux CIL blocks (`selinux/`) | sidecars get their own confined `process` context instead of unconfined userspace (see the [caveat](#selinux-caveat-wl_dbus_proxy) below) |
| D-Bus proxy (`wl-dbus@`) | the host session bus is unreachable directly: only `org.freedesktop.portal.Desktop` calls/broadcasts plus per-app names (e.g. `--own=io.gitlab.librewolf.*`) pass through |
| Volume layout | XDG home dirs are **pod named volumes**, not the real homedir; `~/Downloads` is a separate `noexec` volume; everything else read-only |
| Pod network namespace | one private podman network per instance; the app has outbound connectivity but no direct LAN presence |
| Compositor policy (security context) | privileged globals/operations for sandboxed clients (see [verify your setup](#verify-your-setup)) |
| Wayland relay (`--proxy`, default in both modes) | the selection receive-gate: clipboard *and* primary-selection (middle-click paste) reads of data the app did not itself copy are dropped, optionally after a host-side consent prompt (see [threat model](#threat-model)) |

## Architecture

Every app instance runs as a **podman pod** (quadlet `wl-app@<instance>`)
containing up to four containers, on a per-instance private network
(`wl-app@.network`) and a per-invocation `/run/pod` tmpfs volume
(`pod_%i_run-$INVOCATION_ID`, removed on stop):

```
wl-app@<instance>  (pod)
├── wl-display@     → wlsctx: the tagged socket /run/pod/wlsctx-tagged
│                      (created from the host socket on stdin) plus, in
│                      the default --proxy mode, the relay the app
│                      talks to at /run/pod/wayland-1 (mode B)
├── wl-dbus@        → xdg-dbus-proxy: filtered views of the host
│                      session bus (Desktop portal only) and at-spi bus
├── wl-xwayland@    → xwayland-satellite: in-pod X server (DISPLAY=:0)
└── app-podman-@    → the actual app (IDE / browser)
```

What each container can reach on the **host**:

| Container | Image | Host resources reachable |
|---|---|---|
| `wl-display@` (mode B) | `ghcr.io/wlsctx/wlsctx` | the host's Wayland socket only — passed in via `StandardInput=file:` (`WAYLAND_SOCKET=0`), so no network (`Network=none`), no D-Bus, no home access |
| `wlsctx@` (mode A) | `ghcr.io/wlsctx/wlsctx` | same: the host's Wayland socket bind-mounted read-only; the public socket lives in the *host's* `$XDG_RUNTIME_DIR/wlsctx/%i/`, the tagged one inside the container |
| `wl-dbus@` | `localhost/xdg-dbus-proxy` | the host session bus (bind-mounted to `/run/host/session-bus`) and the at-spi bus; `Network=none` |
| `wl-xwayland@` | `localhost/xwayland-satellite` | GPU render nodes only (`AddDevice=-/dev/dri/renderD128…131`, the `-` prefix makes them optional); the pod network for nothing but X traffic |
| app container | `wayland-runtime` / `librewolf` (+ the app itself as a read-only **image mount**, `Mount=type=image,source=ext-%j`) | GPU render nodes; the pod network (outbound OK); pod volumes including the *shared* `downloads` volume at `~/Downloads` (see [threat model](#what-is-not-protected)) |
| `app-podman-debug@` | `wayland-runtime` | root, `--ipc=host` (intentional — it is the escape hatch), `SYS_CHROOT`, cgroup unmask. Only start it to poke at a running pod |

**Two deployment modes for `wlsctx`** (documented in the unit headers):

- **Mode A — standalone, socket-activated:** the user unit
  `systemd/user/wlsctx@.socket` owns `$XDG_RUNTIME_DIR/wlsctx/%i/wayland-1`
  (the relay's public socket) and socket-activates the quadlet
  `wlsctx@.container`; the relay binds the tagged socket itself,
  inside the container's private runtime dir. Whatever connects to
  the public socket — a pod or a bare host process — is relayed (and
  subject to the allowlist and gate). This mode *requires*
  `WLSCTX_APP_ID` / `WLSCTX_INSTANCE_ID` to be set (the binary no
  longer derives them from the fd name); if they are missing it
  fails with a clear "required argument" error.
- **Mode B — in-pod sidecar (default for `wl-app@` pods):**
  `wl-display@.container` runs inside each pod. It creates the tagged
  socket at `$POD_RUNTIME_DIR/wlsctx-tagged` (`/run/pod/wlsctx-tagged`,
  bound locally and stamped by the compositor during the handshake)
  and, in the default `--proxy` mode, also the relay's public socket
  at `$POD_RUNTIME_DIR/wayland-1` (`/run/pod/wayland-1`) that all the
  pod's containers connect to; the relay relays each app connection
  over the tagged one (see [the binary](#the-wlsctx-binary-srcmainrs)).
  `StandardInput=file:` carries the host socket;
  `StandardOutput=journal` (writing to stdout must never reach the
  compositor). It is `StopWhenUnneeded` and dies with the pod.

### The `wlsctx` binary (`src/main.rs`)

The binary has four operating modes (the relay logic lives in
`src/proxy/`, the broker in `src/broker.rs`):

1. **Tag-and-park** (the fallback in both modes — remove `--proxy`
   from the unit): `--listen=<path>` (binds its own socket) or
   `--socket-activation` (systemd `LISTEN_FDS`); the two are
   mutually exclusive. Requires `--app-id` / `--instance-id` /
   `--sandbox-engine` (or the matching `WLSCTX_*` env vars). Tags the
   listen socket with the security context, sd-notifies, and parks on
   a `signalfd(2)` loop.
2. **Transparent relay** (default in both modes): `--proxy
   --tagged-socket=<path>`: keeps the same tag-and-park lifecycle on
   the *tagged* listener (bound locally, stamped by the compositor
   during the handshake) and relays every connection on the listen
   socket through it. Optional interception:
   - `--allow-globals=<ifaces,…>` hides every other global from the
     app and rejects binds of hidden names;
   - `--clipboard-policy=deny` (default `allow`) enables the
     selection receive-gate: a `receive` request is forwarded only if
     the selection behind it was put on by the app itself (the relay
     infers that from the protocol traffic it sees — an own
     `set_selection`/`start_drag` is attributed to the next echoed
     offer, independently for the clipboard and the primary
     selection); a foreign read is consumed silently (the app's fd
     stays empty) or, with `--broker-socket=<path>`, is *asked about*
     by the broker (mode 3) and forwarded if the user approves, which
     also opens a 1500 ms intent window for further foreign reads.
     Every failure path (broker down, timeout) is a drop. A `receive`
     whose fd is not an in-memory channel (memfd/pipe/socket) is a
     fatal protocol error in both policies.
   - `--notify-copy-out` (requires `--broker-socket=<path>`) fires a
     one-way desktop notification to the broker each time the app
     *writes* to the clipboard or primary selection (a `set_selection`)
     — the copy-*out* signal, since that data is now reachable by every
     client on the desktop. Independent of the policy above (a write is
     always forwarded); fire-and-forget and fail-open (a missing broker
     only loses the notice, it never blocks or alters the write).
   - **The selection audit log** (always on, no flag; Phase 9) writes
     one structured line per selection event the relay is on the path
     of: `set` (the app places data on a selection — the copy-out
     declaration), `read` (a `receive`, with the gate's decision —
     `forward`, `approved` through the prompt broker, or `dropped`),
     `clear` (a NULL `set_selection`, with the origin of the selection
     removed), and `serve` (a `send` event on one of the app's source
     objects — the per-mime byte flow behind a write). Each line
     carries `app`, `instance`, `selection`, `action`, `origin`,
     `mime`, `gate`, `fd_kind`, `payload_bytes` as `key=value` fields
     under the `audit` log target. It records **sizes, never content**
     (the relay only `fstat`s the fd it already holds: a memfd's size
     is settled by a small probe — 250 ms ticks, two stable readings,
     5 s deadline — while a pipe/socket reports no size, and a dropped
     read records 0). The relay's stderr reaches the **host** journal
     in both modes (`LogDriver=passthrough` + `StandardError=journal`),
     so `journalctl -u <relay unit>` shows one line per event;
     `RUST_LOG=warn` silences the stream (the records are then simply
     not retained).
3. **Prompt broker** (host user service, not a container):
   `--broker --socket-activation` (the `wlsctx-broker.socket` /
   `.service` units): each dropped read arrives as one JSON
   `{"kind":"clipboard-read",…}` line; the broker announces it with a
   desktop notification, binds a private decision socket, and waits
   (default 30 s; `--broker-timeout-millis`) for the user's answer — a
   timeout is a deny. It also serves one-way
   `{"kind":"clipboard-write",…}` notifications (Phase 6, from
   `--notify-copy-out`): it fires a desktop notification and closes
   without replying.
4. **One-shot decider**: `--decide --decision allow|deny` sends the
   answer to the most recent pending prompt (the broker's `latest`
   pointer); intended for a keybinding or a notification action.

In the tag-and-park and relay modes it runs its signal loop on
`signalfd(2)` (catatonit-style): `SIGTERM`/`SIGINT` exit cleanly
(releasing the reference pipe, which invalidates the tagged socket);
`SIGHUP` exits with status **129** (no restart is implemented —
in mode A, `Restart=always` brings it back; in mode B the socket dies
with it).

## Images

Built with `docker buildx bake` (`docker-bake.hcl`, Fedora
`DISTRO_RELEASE=43`):

| Image | Built from | Contents |
|---|---|---|
| `wlsctx` | `Dockerfile` (static musl, `FROM scratch`) | the Rust binary; built with `--locked` from a digest-pinned `rust:alpine`; published at `ghcr.io/wlsctx/wlsctx` |
| `shell-runtime`, `wayland-runtime`, `java-wayland-runtime`, `java-headless-runtime`, `shell-devel` | `containers/apps/runtime/Containerfile` | Fedora base; the `wayland-runtime` stage carries Mesa/Vulkan, PipeWire, terminals, Xwayland, fonts |
| `ext-<product>` | `containers/apps/jetbrains/Containerfile` (`--build-arg JB_CODE=…`) | latest JetBrains release fetched from their API and **GPG-verified** (a checksum-pinned `KEYS` file is used to verify the release's `.sha256.asc` before `sha256sum -c`), unpacked to `/opt`, patched with `-Dawt.toolkit.name=WLToolkit` to force the native Wayland toolkit |
| `librewolf` | `containers/apps/librewolf/Containerfile` | LibreWolf from its own repo (GPG key pinned in-repo, `repo_gpgcheck=1`) |
| `xwayland-satellite` | `containers/apps/xwayland-satellite/Containerfile` | the in-pod X server |
| `xdg-dbus-proxy` | `containers/apps/xdg-dbus-proxy/` | the D-Bus filter proxy |

The IDE is distributed as an **image layer**: the app container uses
`Mount=type=image,source=ext-%j,destination=/opt`, so the app code is
immutable. The only per-user file is the license key (`Secret=` in
`app-podman-rustrover@.container`, currently commented out).

## Install

1. **Build or pull the images.**
   - `docker buildx bake` for the runtime/devel matrix (and build the
     `ext-<product>` / `librewolf` / `xwayland-satellite` /
     `xdg-dbus-proxy` images for whatever apps you use).
   - `wlsctx` comes from `ghcr.io/wlsctx/wlsctx` (`Policy=missing` in
     `wlsctx.image`); for reproducibility pin it by digest there (see
     the comment in that file). All other images are local
     (`Policy=never`).
2. **Install the units.** Quadlets from `containers/systemd/` go to
   `~/.config/containers/systemd/`; plain user units from `systemd/user/`
   go to `~/.config/systemd/user/`.
3. **Load the SELinux CIL blocks** in `selinux/` (`wlsctx`,
   `wl_dbus_proxy`) as local modules with the checkpolicy toolchain
   (see the [caveat](#selinux-caveat-wl_dbus_proxy) before relying on
   them). *The exact build/load recipe for local CIL modules is not yet
   documented here — it depends on your checkpolicy setup.*
4. `systemctl --user daemon-reload`
5. `systemctl --user start app-podman-rustrover@rustrover` (or
   `app-podman-librewolf@…`). This pulls in the pod plus the
   `wl-display@` / `wl-dbus@` / `wl-xwayland@` sidecars; the sidecars are
   `StopWhenUnneeded` and die with the app.

## Adding a new app

1. **Image.** For a JetBrains product, build
   `ext-<product>` from the existing
   `containers/apps/jetbrains/Containerfile`
   (`--build-arg JB_CODE=<CODE>`). For anything else, add a
   `containers/apps/<product>/Containerfile` (and a
   `<product>.image` quadlet with `Policy=never`) that leaves the app at
   a known path — by convention `/opt` (image-mounted) or an executable
   on `PATH`.
2. **App unit.** Copy `app-podman-librewolf@.container` and rename to
   `app-podman-<product>@.container`. Set `Exec=`; for a JetBrains
   product set `Image=localhost/wayland-runtime:latest` and
   `Mount=type=image,source=ext-<product>,destination=/opt`. The shared
   drop-ins (`app-podman-.container.d/`) already give it the pod
   volumes, GPU nodes, X/wayland environment and D-Bus addresses — the
   `%j` (product) and `%i` (instance) specifiers drive the volume names.
3. **Per-app extras (optional).** Put them in
   `app-podman-<product>@.container.d/`: e.g. a D-Bus filter addition via
   `Environment=DBUS_PROXY_EXTRA_ARGS=--own=<name>.*` (see
   `app-podman-librewolf@.container.d/dbus-proxy.conf`). Note the caveat
   in `wl-dbus@.container`: systemd does *not* share environment
   variables across units — if the sidecar does not pick up the value,
   set it in a `wl-dbus@.container.d/` drop-in or `environment.d` file
   instead.
4. **Start it:** `systemctl --user start app-podman-<product>@<instance>`.

## Compositor requirements & verify your setup

- The compositor must be **wlroots-based** (e.g. sway) and must provide
  the staging global `wp_security_context_manager_v1`. If it does not,
  `wlsctx` exits with an actionable error pointing at the check below.
- The compositor must be willing to enforce per-context policy on
  security-context clients (that is what makes this more than labelling).

**Verify:** install a Wayland inspector (e.g. `wlsinfo` from
`wayland-utils`) and diff what the sandboxed side sees against the
host:

```sh
# on the host:
wlsinfo            # globals the unconfined client sees
wlsinfo -t         # staging globals — wp_security_context_manager_v1
                   # must be present here

# inside a running pod (mode B), against the relay's public socket:
podman exec wl-app-<product>_<instance> wlsinfo
```

Diff the two global lists. Privileged globals **should be absent** from
the pod's view, notably:

- screencopy (`zwlr_screencopy_manager_v1`)
- data control / screen capture (`zxdg_data_control_v1`)
- virtual keyboard / pointer (`zwp_virtual_keyboard_v1`,
  `zwp_virtual_pointer_v1`)
- foreign-toplevel management (`zwp_foreign_toplevel_manager_v1`)
- input method (`zwp_input_method_manager_v1`)

Exactly which globals your compositor hides for a security-context client
is its policy, not wlsctx's — treat the diff as your own acceptance
checklist, and file upstream if the set is wider than you expected.

## Threat model

**What wlsctx protects:** host home-directory files (XDG dirs are pod
volumes), the host session D-Bus bus (filtered proxy only), privileged
Wayland globals (compositor policy), capabilities and privilege
escalation, the app's own code integrity at *build* time (GPG-verified
JetBrains release, pinned keys/checksums), and — through the relay's
selection receive-gate — **the host desktop's clipboard and
primary selection from sandboxed reads**: an app can only read
selections it put on itself, and every read of data copied on the host
is dropped (the app sees an empty clipboard) or, when the prompt
broker is wired, explicitly approved by the user first.

**What it does NOT protect (residual risk, by design or by necessity):**

- **Outbound network access.** The app container has a private per-pod
  network; egress is *allowed* (the IDE needs it) and nothing here blocks
  it, nor does it guarantee the host's own services (local SOCKS/proxy
  listeners, the host's address on the pod bridge) are unreachable from
  the sandbox. The network configuration is deliberately left as-is.
- **Copy-out via the clipboard.** The receive-gate only protects
  *reads of* host data. An app can still put its own data on the
  clipboard or primary selection (`set_selection`/`start_drag` are
  relayed), and the host desktop can then read it — an exfiltration
  channel into the selection, which anyone on the host can see.
  Blocking it would break the app's own copy-and-paste, so the write is
  **not blocked**; instead it is made *visible*: with
  `--notify-copy-out` (Phase 6) each write fires a desktop notification
  naming the app and the selection, and — always on, in both
  deployment modes — every selection event the relay sees is recorded
  in the **selection audit log** (Phase 9): one structured line per
  `set`/`read`/`clear`/`serve` with the app/instance identity, the
  gate's decision, and the payload *size* (never content), written to
  the host journal (`audit` log target) — see "The selection audit
  log" in the binary section above. The clipboard is treated as shared
  scratch space, not a secret boundary: the notification is a tripwire
  (opt-in, fail-open), the audit log is the persistent record.
- **The shared `downloads` volume.** Every app pod mounts the *same*
  `downloads` volume at `~/Downloads` (`noexec`). A compromised app can
  tamper with files another app will open or download later — apps in
  different pods do not trust each other's downloads.
- **GPU render-node access.** App and Xwayland containers get raw
  `/dev/dri/renderD*` nodes for native rendering. A bug in the GPU stack
  (driver/firmware) is an escape path this project does not mitigate —
  that is the price of "no VNC, no re-encoding".
- **Portal attribution.** D-Bus portal calls from the sandbox are
  proxied to the *host's* portal implementation, which attributes them
  to the **host** desktop (e.g. `org.freedesktop.portal.Desktop.OpenFile`
  appears to come from your desktop environment, not from the sandbox).
  Other users or apps cannot tell the request originated in a container
  — the `sandbox_engine`/`app_id`/`instance_id` context travels only over
  Wayland, not over D-Bus.
- **Within a pod:** all app containers in one pod share the satellite X
  display (`xhost SI:localuser`) and the pod's IPC namespace; they are
  isolated from *other pods*, not from each other.

**SSH / git:** do not mount private keys into the sandbox. Use
`ssh-agent` forwarding instead: keep the agent on the host, run
`ssh-add --constrain usage=sign,confirm=yes <key>` (so even a compromised
agent client cannot ask the key for decryption or use it without
confirmation), and forward the agent into the pod (bind the host's
`$SSH_AUTH_SOCK` into the pod's `/run/pod` and set `SSH_AUTH_SOCK` in
the app container's environment; not yet wired up in the units in this
repo — add it in the app's drop-in).

## SELinux caveat: `wl_dbus_proxy`

`selinux/wl_dbus_proxy.cil` contains the global rule

```
(allow container_t wl_dbus_proxy.process (unix_stream_socket (connectto)))
```

which lets **any** `container_t` process connect to **any**
`wl_dbus_proxy.process` socket — it is not scoped to a specific pod's
proxy. In the current layout this is bounded in practice, because each
pod's proxy sockets live in that pod's private `/run/pod` and each
sidecar runs with its own MCS-constrained label; **MCS separation, not
this rule, is what prevents pod A's containers from talking to pod B's
D-Bus proxies.** The policy does not itself enforce that, so **verify
the MCS separation between pods on your system** (check that sidecar
socket files carry per-pod `s0:cN,cM` suffixes and that a container from
one pod cannot `connect` to another pod's proxy socket). If you ever
expose a proxy socket outside the pod's private runtime dir (e.g. mode A
style, in `$XDG_RUNTIME_DIR`), this rule means *every* container on the
system can reach it.

## Known gaps / WIP

- The broker is wired by default in neither mode: it is opt-in in both
  (a drop-in that bind-mounts the host's `wlsctx-broker` socket into the
  relay container and sets `WLSCTX_BROKER_SOCKET` — see the unit
  headers). Both broker features ride on that one socket: the consent
  prompt (`--clipboard-policy=deny`) and the copy-out notification
  (`--notify-copy-out`, Phase 6) are each enabled independently.
- **Drag-and-drop** selection traffic is only partially covered by the
  audit log: `start_drag` is not audited as a write (the gate still
  attributes drags for the read-gate, and `serve` events fired during a
  drag are recorded under the clipboard label — `wl_data_source` is
  shared by both).
- The at-spi proxy is **intentionally** in allow-nothing mode: its
  `--call`/`--broadcast` rules are commented out in `wl-dbus@.container`
  (marked there) and the `--sloppy-names` filter lets nothing through by
  default. Accessibility inside the sandbox does not work until that is
  re-enabled and narrowed.
- `SIGHUP` in `wlsctx` exits with status 129; there is deliberately no
  restart logic in the binary (mode A's `Restart=always` covers it;
  mode B's tagged socket dies with the process).
- `wl-app@.pod` references `ServiceName=wl-pod@`, a unit that is not in
  this repo.
- The JetBrains `.sha256.asc` GPG chain could not be exercised in the
  authoring environment (the releases API returned empty responses); the
  `TODO` in the Containerfile asks for one real build to confirm it.
- Several knobs in the drop-ins (`TMP_SIZE`, individual `XDG_*`
  passthrough) are commented out mid-tuning.
