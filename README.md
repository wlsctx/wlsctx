<p align="center">
  <img src="assets/wlsctx-header-tagline.svg" alt="wlsctx — Wayland security context wrapper" width="489">
</p>

# wlsctx

Run GUI applications (JetBrains IDEs, LibreWolf, …) in an **unprivileged
in-process sandbox** on a **wlroots Wayland desktop** (sway, Fedora) while
keeping the UX as close to unconfined as possible: windows are **native
Wayland clients** with **GPU rendering** — no VNC, no RDP, no screen
re-encoding, no blurry text.

There are no containers. A single Rust binary (`wlsctx`) creates the
sandbox itself: Linux **user/mount/pid/ipc/uts/cgroup/net namespaces**, a
rebuilt **private rootfs**, and a **Landlock + seccomp** policy applied
via the [`nono`](https://crates.io/crates/nono) crate. The app runs as
**your real uid** (never root, never another user) and looks and feels
like a normal local app.

The threat model is a supply-chain-compromised IDE extension (or a
compromised browser download): the sandbox must not reach host secrets,
other users' files, or privileged Wayland/D-Bus interfaces — while still
*looking and feeling* like a normal local app.

This is a work in progress (personal-laptop target: 1–2 human users).

## Why `wp_security_context_v1`

[wp_security_context_v1](https://wayland.app/protocols/security-context-v1)
is a Wayland *staging* protocol from wlroots, intended for an app to give a
*child process* its own tagged Wayland socket. wlsctx repurposes it in the
other direction: a **host-side** process tags a listening socket so the
*compositor* can identify the clients that connect to it.

1. `wlsctx` connects to the host compositor.
2. It calls `wp_security_context_manager_v1.create_listener()` on a
   listening socket and sets the context's `sandbox_engine` (default
   `wlsctx`), `app_id` and `instance_id`.
3. It holds the protocol's **reference pipe** (the `close_fd`) open for
   the process's whole lifetime, so the tagged socket stays valid; the
   tagged socket is then the only Wayland socket the app is pointed at.

Because the tag travels *over the socket*, the compositor can apply
**per-context policy** to the client without the client having any
capability to opt out: it can hide privileged globals from sandboxed
clients, and it **must not** expose
`wp_security_context_manager_v1` to an already-tagged client (the
*nesting guard* — a tagged client cannot stamp another socket). On sway on
this desktop the host socket advertises 56 globals and the tagged socket
35, and the manager is present on the host (name 34) but **absent** on the
tagged socket — the guard is active.

The tagged socket is one of three ways to use it here:

- **`run --wayland`** — the supervisor creates the tagged socket in the
  per-instance runtime dir and points the app's `WAYLAND_DISPLAY` at it.
  The app reaches *only* the tagged socket, never the host's. This is the
  default, no-interception path.
- **`wayland` (tag-and-park)** — binds a socket, tags it, and parks; the
  compositor accepts connections on that tagged listener directly. The
  original behaviour, kept as a fallback.
- **`wayland --proxy`** — the host-side **transparent relay** (below): the
  app connects to a *public* socket the relay owns, and the relay forwards
  each connection to the compositor over a fresh tagged connection,
  re-parsing the protocol and applying optional policies on the way in.

In all three, the security context is the mechanism by which the
*compositor* discriminates; the sandbox (namespaces + rootfs + nono) is the
mechanism by which *filesystem, D-Bus and network* are discriminated.
Containment is layered:

| Layer | What it blocks |
|---|---|
| Unprivileged user namespace | the app is its **real uid** — never root, never another user. The single-extent self-map (`<uid> <uid> 1`) leaves in-ns `0` *unmapped*, so no `setuid`/`setgid` to a privileged id is possible and there is no privilege escalation path |
| Private rootfs (mount namespace) | other users' homes, `/root`, `/boot`, `/var`, `/srv`, `/media`, `/mnt` are **masked** (empty tmpfs); the app sees its own XDG dirs writable and everything else read-only (a recursive self-bind of `/` is the base) |
| Landlock (nono) | a **default-deny** filesystem floor: even paths the rootfs *shows* (e.g. `/etc`) cannot be opened or written outside the grants; AF_UNIX sockets are restricted to the per-instance dir (plus a profile's explicit sockets) |
| seccomp-notify (nono) | `openat`, `connect`, `bind`, … are routed to the supervisor and **auto-denied** by default — the choke point for both file and network |
| cgroup + cgroup namespace | the app lives in its own per-instance sub-cgroup and sees only `0::/`; scoped under systemd (via D-Bus) for visibility/accounting, or a raw-cgroup fallback |
| pid namespace | the app is **PID 1** of a fresh pidns; it cannot see or signal host processes (signal mode `isolated` by default) |
| ipc namespace | POSIX shared memory only by default (no semaphores) |
| net namespace | the shared host netns by default (**egress is allowed** — see [threat model](#threat-model)) or a bare loopback-only netns with network blocked (`--network=none`) |
| Compositor policy (security context) | privileged Wayland globals/operations for sandboxed clients (see [verify your setup](#compositor-requirements--verify-your-setup)) |
| Wayland relay (`--proxy`, optional) | a **global allowlist** (hide non-allowlisted globals, reject their binds), the **selection receive-gate** (drop clipboard/primary-selection reads of data the app did not itself copy, optionally after a host-side consent prompt), a **copy-out** desktop notification, and the **selection audit log** (see [the relay](#the-transparent-relay-wayland---proxy)) |

## Architecture

### The sandbox: `S → A → B`

`wlsctx run` builds the sandbox with a three-process pipeline (decisions
#12, #23–#26 in [PLAN.md](PLAN.md)):

```
S  wlsctx (the supervisor — outside every namespace)
   │   • GPU precheck; creates the per-instance runtime dir
   │   • optional: registers a transient systemd user SCOPE via D-Bus
   │     (StartTransientUnit, PIDs=[self]) — or a raw-cgroup fallback
   │   • builds the tagged Wayland socket (if --wayland)
   │   • creates the handoff channels; forks A
   │   • receives B's seccomp-notify listener (pidfd_getfd + SCM_RIGHTS)
   │   • forwards SIGTERM/SIGINT/SIGHUP to the app; sd-notifies; waits
   │
   └─fork─► A  the intermediate child
            │   unshare user → mount → pid → cgroup
            │   builds the rootfs (as ns-"root" of its own mountns)
            │   forks B; reaps B; exits with B's status by choice
            │
            └─fork─► B  the app
                      unshare ipc → uts → net (per mode) → fresh /proc
                      nono: prepare landlock → install seccomp-notify →
                            apply the floor (all pre-exec)
                      execve (B is PID 1 of its pid namespace)
```

The supervisor stays *outside* the namespaces on purpose: it needs host
access (the compositor socket, the session bus, the cgroup files) and it
is the process the seccomp-notify fd belongs to. When `B` (PID 1) dies the
kernel's pidns teardown does *not* kill `A` on this kernel, so `A` reaps
`B` and exits with `B`'s status by choice — no orphans, and the exit code
(or `128+signal`) propagates back through both forks to `S`.

### What the sandboxed app sees

The **rootfs is rebuilt, not masked** (the old container-era "bind in
volumes" is gone). Working as the mount namespace's root, `A` assembles:

1. A recursive self-bind of `/` — the read-only base. (The `ro` flag is
   *not* set: it is silently dropped on a bind of a foreign superblock and
   `MS_REMOUNT` is `EPERM` unprivileged; read-only behaviour comes from
   the app's real uid plus the nono policy instead.)
2. `/dev` — a **fresh tmpfs** with the standard nodes (`null`, `zero`,
   `full`, `urandom`, `random`, `tty`) **bind-mounted** (not `mknod`'d, so
   they keep their canonical genfs SELinux labels — important for a future
   SELinux module), a **fresh `devpts` instance** isolated from the host's
   pts, and — with GPU on — `/dev/dri` bound from the host.
3. `/sys` — a fresh tmpfs with read-only binds of `devices/` and `class/`
   (all a GUI app needs for PCI/DRM discovery).
4. `/run` — a fresh tmpfs carrying **only** the per-instance dir
   (`/run/user/<uid>/wlsctx/<app>-<instance>`), whose contents arrive from
   a build scratch on `/var/tmp`. The host's own Wayland sockets sit
   directly under `$XDG_RUNTIME_DIR` and are deliberately *invisible*
   here — the app can reach only the tagged socket.
5. `/tmp` — a fresh tmpfs, sized by the profile (`tmp_size_mib`).
6. The standard **XDG rw self-binds** (`$HOME`, `$XDG_CONFIG_HOME`,
   `$XDG_CACHE_HOME`, `$XDG_STATE_HOME`, `$XDG_DATA_HOME`) plus the
   profile's `rw_binds`.
7. **Masks** — empty tmpfs over `/root`, `/boot`, `/var`, `/srv`,
   `/media`, `/mnt`, every other user's `/home/*`, and `/opt/*` except the
   app's own dir, plus the profile's `mask`.

On top of the filesystem view, the **nono policy** (built identically in
`S` and re-run in `B` from one pure function, so the two cannot disagree)
is a default-deny `CapabilitySet`:

- **Read** on `/`, `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/etc`,
  `/proc`, `/sys`; **read-write** on `/dev`, `/tmp`, the per-instance dir,
  and `$HOME`.
- The profile's `ro_binds` (read), `rw_binds` (read-write), and
  `unix_sockets` (connect).
- **Network**: the shared host netns stays open by default;
  `--network=none` adds `block_network()`.
- **Signal mode** `isolated` (the app may only signal itself and its
  descendants — Landlock V6) or `all`; **IPC mode** `shm` (POSIX shared
  memory only) or `full`.

Applied in three stages pre-exec (decision #22/#27): `prepare_landlock`
(the rule paths are opened *before* any filter exists) → install the
combined seccomp-notify filter → `apply_raw` (builds the Landlock ruleset
from the pre-opened fds, re-asserts `no_new_privs`, and locks the
single-extent identity). `B` blocks on a verdict pipe before `execve`, so
the handoff to the supervisor is deterministic; the supervisor services the
listener and **auto-denies** (decision #25).

### The Wayland side

- **Tagged socket** — created by `S` in the per-instance runtime dir
  (default socket name `wayland-1`). The app's `XDG_RUNTIME_DIR` is set to
  the *in-sandbox* instance dir and `WAYLAND_DISPLAY` to the socket name,
  so the app reaches only the tagged socket.
- **Tag-and-park** (`wayland`, no `--proxy`) — bind, tag, sd-notify, park.
- **Transparent relay** (`wayland --proxy`) — see below.
- **Signal semantics are mode-dependent.** In `run`, `S` forwards
  `SIGTERM`/`SIGINT` to the app (then `SIGKILL` after 2 s, since
  pidns-init ignores default-action signals) and `SIGHUP` terminates the
  app and exits **129** (decision #33 — there is no in-place rebuild of a
  live sandbox). In the `wayland` modes (tag-and-park, proxy), `SIGHUP` is
  a *rebuild*: an in-place re-exec of `/proc/self/exe` in `--listen` mode
  (same pid, fresh compositor connection and tag), or a clean exit for a
  systemd restart when socket-activated.

### The transparent relay (`wayland --proxy`)

The relay owns two sockets: a **public** socket the app connects to
(`--listen`) and a **tagged** socket it holds upstream
(`--tagged-socket`, which must be **unreachable from the app** — a
socket the app can reach that is also a valid tagged socket would let it
bypass the relay; see the [path constraints](#running-the-relay-per-app)
in the deployment recipe). Every connection on the public socket is
relayed to the compositor over a fresh security-context connection to the
tagged socket, so the compositor applies per-context policy to the
sandboxed client while the app believes it is talking to an ordinary
compositor.

It is a protocol *interpreter*, not a byte pipe: it re-parses the messages
it relays (interface tables generated from the protocol XML in
`protocols/`) and is **convention-adaptive** — Rust `wayland-backend` uses
display=ID 1 / client IDs from 2 / server IDs from `0xFF000000`, while C
`libwayland` uses display=ID 0 / client IDs from 1 / server IDs from
`0x80000000`; the first message of a connection pins the convention for
both ends. On the way *in* from the app it can apply:

- **`--allow-globals=<iface,…>`** — hide every other global from the
  registry and reject a bind of any name the app was never shown
  (`wl_display.error` `invalid_object`). When *unset* the relay is a
  pass-through and shows all globals (an empty list is treated as "all",
  not "none").
- **`--clipboard-policy=deny`** (default `allow`) — the **selection
  receive-gate**: a `receive` request is forwarded only if the selection
  behind it was put on by the app itself (inferred from the protocol
  traffic — an own `set_selection`/`start_drag` is attributed to the next
  echoed offer, independently for the clipboard and the primary
  selection). A foreign read is dropped (the app's fd stays empty, so it
  sees an empty clipboard) or, with `--broker-socket=…`, is *asked about*
  by the broker and forwarded if the user approves (which opens a
  1500 ms intent window). Every failure path (broker down, timeout) is a
  drop. A `receive` whose fd is not an in-memory channel (memfd/pipe/
  socket) is a **fatal protocol error** in both policies — compositors do
  not inspect the fd they are handed, so this check is what stops an app
  from steering clipboard data into a file.
- **`--notify-copy-out`** (requires `--broker-socket`) — fires a one-way
  desktop notification to the broker each time the app *writes* to the
  clipboard or primary selection (`set_selection`): the copy-*out* signal,
  since that data is now reachable by every client on the desktop.
  Rate-limited to at most one notification per second per app (a rapid
  copier's burst collapses to that; every write still lands in the audit
  log). Independent of the policy above and fire-and-forget/fail-open: a
  missing broker only loses the notice; the write is never blocked or
  altered.
- **The selection audit log** (always on, no flag) writes one structured
  `key=value` line per selection event the relay is on the path of: `set`
  (the app places data — the copy-out declaration), `read` (a `receive`,
  with the gate's decision — `forward` / `approved` through the broker /
  `dropped`), `clear` (a NULL `set_selection`), and `serve` (a `send`
  event on one of the app's source objects — the per-mime byte flow behind
  a write). Fields: `app`, `instance`, `selection`, `action`, `origin`,
  `mime`, `gate`, `fd_kind`, `payload_bytes`, under the `audit` log
  target. It records **sizes, never content** (the relay only `fstat`s the
  fd it already holds; a pipe/socket reports no size, a dropped read
  records 0).

The relay's stderr reaches the **host** journal in deployment
(`StandardError=journal` / `LogDriver=passthrough` in whatever unit you run
it under), so `journalctl -u <unit>` shows one line per event;
`RUST_LOG=warn` silences the stream (the records are then simply not
retained).

### The prompt broker and the decider

The broker is a **host-side user service** (not in the sandbox): it must
reach the session bus (`notify-send`) and it is the thing that waits for
*you*. It speaks **N-D-JSON** with two request kinds, both over its one
socket (`$XDG_RUNTIME_DIR/wlsctx-broker`):

- **`clipboard-read`** — request/response. The relay's gate dropped a
  foreign read and is asking for consent. The broker announces it with a
  desktop notification (carrying the prompt id and a ready-made reply
  command) and waits — default 30 s (`--broker-timeout-millis`); a timeout
  is a deny. Several prompts can be pending at once.
- **`clipboard-write`** — one-way. The relay fired it because the app
  wrote to a selection; the broker runs `notify-send` and closes with no
  reply. Fire-and-forget; a lost notification never affects the write.

The *user's* answer travels over a **second, session-scoped socket**
(`$XDG_RUNTIME_DIR/wlsctx/decision.sock`, bound once at broker startup):

```sh
wlsctx decide                       # list the pending prompts (oldest first, each with an id)
wlsctx decide --decision allow      # resolve the oldest (or =deny)
wlsctx decide --prompt 3 --decision allow   # resolve a named one
```

If the decision socket cannot be bound, the broker degrades: interactive
prompts are denied at once (`no-decision-socket`) instead of waited on, and
`--auto-decide` mode never binds the socket at all (it answers every
request automatically — a test hook).

## The `wlsctx` binary

Four subcommands (the relay logic lives in `src/proxy/`, the broker in
`src/broker.rs`, the sandbox in `src/sandbox/`):

1. **`run`** — run a command inside the sandbox (the `S → A → B`
   pipeline above).
   - `--app-id` / `--instance-id` (default `app` / `1`): feed the UTS
     hostname (`wlsctx-<app>-<instance>`) and the per-instance cgroup name
     (`<app>-<instance>`); only `[A-Za-z0-9._-]`.
   - `--network shared|none` (default `shared`).
   - `--gpu` / `--no-gpu` — override the profile's GPU setting.
   - `--wayland` — create a tagged socket for the app (default name
     `wayland-1` in the per-instance runtime dir).
   - `--listen <path>` (an absolute path as given, a relative path in the
     per-instance dir; implies `--wayland`) or `--socket-activation`
     (adopt the tagged socket from `LISTEN_FDS`).
   - `--sandbox-engine` (default `wlsctx`).
   - everything after `--` is the command to run, e.g.
     `wlsctx run -- /bin/sh -c 'id'`.

2. **`wayland`** — set up a tagged Wayland socket (tag-and-park), or with
   `--proxy` run the transparent relay.
   - `--app-id` / `--instance-id` / `--sandbox-engine` (required, non-empty;
     `WLSCTX_*` env vars honoured).
   - `--listen <path>` (required unless `--socket-activation`) or
     `--socket-activation`.
   - `--proxy` + `--tagged-socket <path>` — relay mode; the tagged socket
     must be unreachable from the app.
   - `--allow-globals`, `--clipboard-policy allow|deny`,
     `--broker-socket <path>`, `--notify-copy-out` — the relay's policies
     (all proxy-only).

3. **`broker`** — the clipboard prompt broker (host user service).
   `--listen` / `--socket-activation`, `--auto-decide <allow|deny>` (test
   hook), `--broker-timeout-millis` (default 30000).

4. **`decide`** — one-shot client of the broker's decision socket:
   `--decision allow|deny` (without it, lists the pending prompts) and
   `--prompt <id>` (omit: the oldest). Intended for a keybinding or a
   notification action.

## Install

There are no images to build and no container runtime to configure — you
build one binary and (optionally) install one user unit.

1. **Build.** `cargo build --release` → `target/release/wlsctx`. Install
   it wherever you like; the broker unit below expects
   `/usr/local/bin/wlsctx` (override `ExecStart` in a drop-in if yours
   lives elsewhere).
2. **Install the broker unit.** Copy
   `systemd/user/wlsctx-broker.{socket,service}` to
   `~/.config/systemd/user/`.
3. `systemctl --user daemon-reload`
4. **(Optional) enable the broker.**
   `systemctl --user enable --now wlsctx-broker.socket` — it is
   socket-activated and stays dormant until a proxy asks it about a
   dropped read. The broker is only needed for the relay's consent prompt
   and copy-out notification; tag-and-park and plain `run` do not touch
   it.
5. **Add your app profile(s)** (next section) and run.

You need to be in the **`render` group** for GPU access (the `/dev/dri`
nodes are bind-mounted into the sandbox); without it, pass `--no-gpu`.

## Adding an app

An app is described by a **TOML profile** at
`~/.config/wlsctx/apps/<app-id>.toml` (the replacement for the old quadlet
drop-ins). The file is optional: built-in defaults cover the known apps
(`rustrover` → `/opt/rustrover`, `librewolf` →
`/usr/lib64/librewolf`), and a profile-less `run` (an ad-hoc command) falls
back to an ad-hoc default (no GPU). A malformed file is a **hard error** —
it never silently degrades the sandbox. All path fields are absolute
(`~` is not expanded — profiles are data, not shell).

```toml
# ~/.config/wlsctx/apps/rustrover.toml

gpu = true                 # build /dev/dri in the sandbox (CLI --no-gpu overrides)
tmp_size_mib = 2048        # size of the fresh /tmp (0 = kernel default)

# Everything under / is already read-only from the self-bind; ro_binds
# document the app's install dir and exempt it from the /opt/* mask.
ro_binds = ["/opt/rustrover"]

# Extra writable self-binds, on top of the standard XDG set
# ($HOME, config, cache, state, data).
rw_binds = []

# Extra paths to mask (an empty tmpfs over them), on top of the
# defaults (/root, /home/* except ours, /boot, /var, /srv, /media,
# /mnt, /opt/* except the app's).
mask = []

# Environment variables added for the app, on top of the session env.
[env]
# JAVA_TOOL_OPTIONS = "-Dawt.toolkit.name=WLToolkit"

# AF_UNIX socket paths the app may use, on top of the per-instance dir
# (the tagged wayland socket).
unix_sockets = []

ipc = "shm"                # "shm" (POSIX shm only; default) or "full" (also semaphores)
signals = "isolated"       # "isolated" (default; app signals only itself/descendants) or "all"
```

Then run it:

```sh
# a plain command (ad-hoc, no app profile, no Wayland):
wlsctx run -- /bin/sh -c 'id && ls /root'

# a GUI app with a tagged Wayland socket:
wlsctx run --app-id rustrover --instance-id 1 --wayland -- /opt/rustrover/bin/rover

# cut the network:
wlsctx run --app-id rustrover --wayland --network none -- /opt/rustrover/bin/rover
```

## Running the relay (per-app)

Per-app proxies are **documented manual runs, not a systemd template
unit** (decision, [PLAN.md](PLAN.md) §7.1): the public socket's path must
match the socket the app's environment points at (`XDG_RUNTIME_DIR` +
`WAYLAND_DISPLAY`) — per-instance coordination a template instance cannot
derive. Two constraints on the paths:

- the **public** socket must land *inside* the per-instance runtime dir
  (that dir is what the app sees as its `$XDG_RUNTIME_DIR`), so the app
  can reach it;
- the **tagged** socket must sit *outside* the per-instance dir (e.g. as
  a sibling under `$XDG_RUNTIME_DIR/wlsctx/`), so the app cannot reach it
  — a socket the app can reach that is also a valid tagged socket would
  let it bypass the relay.

```sh
# from a terminal, or a one-off `systemd-run --user --scope`:
wlsctx wayland \
  --app-id rustrover --instance-id 1 --sandbox-engine wlsctx \
  --listen "$XDG_RUNTIME_DIR/wlsctx/rustrover-1/wayland-1" \
  --tagged-socket "$XDG_RUNTIME_DIR/wlsctx/rustrover-1.tagged" \
  --clipboard-policy deny \
  --broker-socket "$XDG_RUNTIME_DIR/wlsctx-broker" \
  --notify-copy-out
```

Then point the app at the public socket from its profile and start it
**without** `--wayland` (the relay owns the tagged socket — `run` must not
create a second one). The profile's `[env]` section sets both variables to
the *in-sandbox* instance dir, whose location is fixed at
`/run/user/<uid>/wlsctx/<app>-<instance>` regardless of the host's
`XDG_RUNTIME_DIR`:

```toml
# ~/.config/wlsctx/apps/rustrover.toml — routing the app through the relay
[env]
XDG_RUNTIME_DIR = "/run/user/1000/wlsctx/rustrover-1"
WAYLAND_DISPLAY = "wayland-1"
```

```sh
wlsctx run --app-id rustrover --instance-id 1 -- /opt/rustrover/bin/rover
```

The chain works end-to-end: a sandboxed Wayland client is driven through
the relay into the live compositor (verified with `wayland-info`
enumerating sway's globals and exiting 0). The relay's public socket is
bound inside the per-instance runtime dir, which the rootfs build carries
into the sandbox — so the app's `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY`
resolves to it without any `run --wayland` tag of its own.

**Audit sink.** Run the relay under a unit (or `systemd-run --user`) that
sends its stderr to the host journal, so the selection audit log is
persistent and greppable:

```ini
[Service]
ExecStart=/usr/local/bin/wlsctx wayland --proxy …
StandardError=journal
LogDriver=passthrough
```

`journalctl -u <unit>` then shows one `audit:` line per selection event.

## Compositor requirements & verify your setup

- The compositor must be **wlroots-based** (e.g. sway) and must provide the
  staging global `wp_security_context_manager_v1`. If it does not,
  `wlsctx` exits with an actionable error pointing at the check below.
- The compositor must be willing to enforce per-context policy on
  security-context clients (that is what makes this more than labelling)
  and must not re-expose the manager to a tagged client (the nesting
  guard).

**Verify:** install a Wayland inspector (e.g. `wlsinfo` from
`wayland-utils`, or `wayland-info`) and diff what a sandboxed client sees
against the host:

```sh
# on the host:
wlsinfo          # globals the unconfined client sees
wlsinfo -t       # staging globals — wp_security_context_manager_v1
                 # must be present here

# the sandboxed view (a `run` of the inspector against the tagged socket):
wlsctx run --app-id probe --instance-id 1 --wayland -- /usr/bin/wlsinfo
```

Diff the two global lists. Privileged globals **should be absent** from the
sandboxed view, notably:

- screencopy (`zwlr_screencopy_manager_v1`)
- data control / screen capture (`zxdg_data_control_v1`)
- virtual keyboard / pointer (`zwp_virtual_keyboard_v1`,
  `zwp_virtual_pointer_v1`)
- foreign-toplevel management (`zwp_foreign_toplevel_manager_v1`)
- input method (`zwp_input_method_manager_v1`)

Exactly which globals your compositor hides for a security-context client
is *its* policy, not wlsctx's — treat the diff as your own acceptance
checklist, and file upstream if the set is wider than you expected. On
sway on this desktop the host shows 56 globals, the tagged socket 35, and
`wp_security_context_manager_v1` is present on the host but absent on the
tagged socket.

## Threat model

**What wlsctx protects:** the host filesystem (other users' homes,
`/root`, `/var`, `/srv`, `/media`, `/mnt` are masked; everything else is
read-only by the self-bind *and* default-denied by Landlock; the app keeps
its own real XDG dirs writable, as its real uid); privilege escalation
(the single-extent user-namespace self-map leaves root unmapped); the host
process tree (the app is PID 1 of its own pidns, signals isolated);
privileged Wayland globals (compositor per-context policy via the tagged
socket); and — through the optional relay's **selection receive-gate** —
**the host desktop's clipboard and primary selection from sandboxed
reads**: the app can only read selections it put on itself, and every read
of data copied on the host is dropped (the app sees an empty clipboard) or,
when the broker is wired, explicitly approved by you first. The host
session bus is unreachable by default (its socket is not in the rootfs and
AF_UNIX is Landlock-restricted to the per-instance dir).

**What it does NOT protect (residual risk, by design or by necessity):**

- **Outbound network access.** By default the app shares the host
  netns and egress is *allowed* (the IDE needs it); nothing here blocks
  it, nor does it guarantee the host's own services (local
  SOCKS/proxy listeners, the host's address) are unreachable from the
  sandbox. `--network=none` gives a bare loopback-only netns with network
  blocked; a finer-grained egress filter (Landlock v4 network rules / the
  seccomp `connect` trap) is a later phase. The network configuration is
  deliberately left as-is for now.
- **Copy-out via the clipboard.** The receive-gate only protects *reads of*
  host data. The app can still put its own data on the clipboard or
  primary selection (`set_selection`/`start_drag` are relayed), and the
  host desktop can then read it — an exfiltration channel into the
  selection, which anyone on the host can see. Blocking it would break the
  app's own copy-and-paste, so the write is **not blocked**; instead it is
  made *visible*: with `--notify-copy-out` a write fires a desktop
  notification naming the app and the selection (rate-limited, at most one
  per second per app), and — always on, whenever the relay runs — every
  selection event is recorded in the **selection audit log** (one
  structured line per `set`/`read`/`clear`/`serve`, sizes never content) in
  the host journal. The clipboard is treated as shared scratch space, not a
  secret boundary: the notification is a tripwire (opt-in, fail-open,
  rate-limited), the audit log is the persistent record.
- **GPU render-node access.** With GPU on, the app gets raw
  `/dev/dri/renderD*` nodes (bind-mounted) for native rendering. A bug in
  the GPU stack (driver/firmware) is an escape path this project does not
  mitigate — that is the price of "no VNC, no re-encoding".
- **Your own home directory.** Unlike the container era (where the XDG
  dirs were *pod volumes*, not the real homedir), the sandboxed app is
  your real uid and keeps its **real** XDG dirs writable. A compromised
  app can read and modify your own config, cache and data as you — the
  isolation is from *other* users and the *system*, not from you. This is
  deliberate (apps must persist their own settings), but it means a
  compromised extension can tamper with files another of *your* apps will
  read.
- **Portal attribution.** When the `wlsctx dbus-proxy` sidecar (Phase
  7.2) sits in front of the session bus, portal calls are proxied to
  the *host's* portal, which attributes them to the **host** desktop,
  not the sandbox — the `sandbox_engine`/`app_id`/`instance_id` context
  travels only over Wayland, not over D-Bus. (Without the sidecar there
  is no D-Bus path at all; the session bus is simply unreachable.)
- **Within one app.** All processes of *one* app instance share its
  namespaces and are isolated from *other* instances, not from each
  other; the supervisor nonetheless services the app's *children* as
  well (decision #32), so a multi-process app does not deadlock.

**SSH / git:** do not mount private keys into the sandbox. Use
`ssh-agent` forwarding instead: keep the agent on the host, run
`ssh-add --constrain usage=sign,confirm=yes <key>` (so even a compromised
agent client cannot ask the key for decryption or use it without
confirmation), and — once a D-Bus/socket path exists — allow the host's
`$SSH_AUTH_SOCK` via the profile's `unix_sockets`.

## Known gaps / WIP

- **Multi-process apps work (decision #32).** The supervisor services
  *every* trapped notification on the listener — no pid filter — so a
  child that inherits the seccomp filter is served with the same
  capability set, and a failed verdict answers `EPERM` rather than
  hanging. The Phase 5.5 Firefox e2e (browser + gecko/socket children)
  ran and exited cleanly; the remaining caveat is app-internal pipe
  behaviour, not a supervisor gap.
- **FOOT/PTY: `EACCES` from `devpts` inside the userns.** A fresh
  `devpts` instance is mounted, but opening a *new* pt from inside an
  unprivileged user namespace is rejected by the kernel on this system —
  terminals that allocate a fresh PTY can fail with `EACCES`. It is a
  kernel-level restriction, not a policy one; under test we use a
  pre-allocated path instead.
- **Drag-and-drop `serve` is labelled by its source, not its drag.**
  A `start_drag` is audited as a write (`action=set selection=drag`,
  with its own copy-out notification — Phase 6.5.5), but the `serve`
  records for the bytes it then serves are still labelled
  `selection=clipboard`: `wl_data_source` is shared by the clipboard
  and the drag, and the relay does not yet track which source is in
  an active drag. The write is never missed — only the per-mime byte
  flow behind a drag carries the stable-selection label.
- **The sidecars are opt-in, not on by default.** `wlsctx dbus-proxy`
  (Phase 7.2) and the optional `wlsctx xwayland` host satellite
  (Phase 7.3) are built and run per instance; neither is started by a
  plain `run`, so out of the box the host session bus is simply
  unreachable and there is no in-sandbox X server.
- **SELinux: first-pass module built, not yet installed (needs root).** The container-era CIL blocks are gone; `selinux/` now ships a local module (`wlsctx`) defining `wlsctx_t` (supervisor/pipeline/sidecars) and `wlsctx_app_t` (the sandboxed app), plus the `xserver_t` rules the reconnaissance found missing. Built with `selinux/build.sh` (it is `checkmodule` that compiles modules, not `checkpolicy` — see there); installing is `sudo semodule -i`. Uninstalled, the stack runs unconfined exactly as before; the module is a second containment layer on top of the namespaces + nono, not a replacement for them.
