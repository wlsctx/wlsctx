# wlsctx SELinux module (phase 8.2, first pass)

A local SELinux module that confining the wlsctx stack to its own
domains. It is a **first pass**: the rule sets are deliberately a
little broader than the minimum and meant to be trimmed with audit
denials (below). It has not yet been exercised on an enforcing
system (installing needs root).

## What it defines

- `wlsctx_exec_t` — file type for the installed `wlsctx` binary
  (`/usr/local/bin/wlsctx` or `/usr/bin/wlsctx`, see `wlsctx.fc`).
- `wlsctx_t` — supervisor / S→A→B pipeline / sidecar domain. Reached
  by transition from `unconfined_t` when the binary carries
  `wlsctx_exec_t`. Covers: rootfs mounts (fresh tmpfs / devpts /
  proc, self-bind of `/`, profile binds), the per-instance cgroup,
  the per-instance runtime dir and its sockets (wayland, X, bus,
  broker), the session bus (broker — the `unconfined_dbusd_t`
  dbus-broker variant on this box, and the classic `session_dbusd_t`
  one), spawning `xdg-dbus-proxy` and Xwayland, and the
  `/proc/self/exe` re-exec (SIGHUP rebuild).
- `wlsctx_app_t` — sandboxed-app domain. B execs the app while in
  `wlsctx_t`; the app (and its subprocesses) land here via the
  `bin_t`/`user_home_t` transition. The rule set is a "confined user
  app": instance dir, /tmp, /dev nodes (the §3.3 genfs labels),
  /proc /sys /cgroup /etc, home/cache, system libs (`lib_t` dlopen),
  session bus, loopback network.
- `xserver_t` — the stock policy on this machine **does** transition
  `unconfined_t → xserver_t` on `xserver_exec_t` (verified live
  2026-10-27; an earlier `sesearch` note to the contrary was wrong —
  see LESSONS #20), so Xwayland has run in the real X-server domain
  all along. The module adds the `wlsctx_t → xserver_t` transition
  (needed in confined mode, where the satellite is `wlsctx_t` and
  the stock transition does not fire) plus `xserver_t` access to
  the X socket and MIT auth file the satellite places in the
  per-instance dir (`user_tmp_t`) — precautionary: the Phase 7.3
  e2e (Xwayland as `xserver_t` creating exactly those files, a real
  client connecting) produced no denials, so the stock rule set may
  already cover them; the tuning loop decides whether to keep them.

## How it relates to container-selinux (the podman types)

A permissive-mode probe (2026-10-28) ran wlsctx under the types
podman itself uses, before installing this module. The stock policy
splits podman into **two** domains: `container_runtime_t` (crun —
labeled `container_runtime_exec_t`, the `unconfined_t` exec
transition) and `container_t` (the payload, reached by
setexecfilecon — there is no file `type_transition` into
`container_t` at all). They map onto wlsctx's two sides:

- **The S/A runtime side ≙ `container_runtime_t`**: ran with *zero
  genuine denials* — the rootfs-rebuild `mounton`s over host dirs,
  the fresh `/dev`+`/proc` mounts, the cgroup-scope
  create/enter/teardown, the session-bus connect+send, and the
  transient-scope `system:start` are all covered (crun does the same
  work), including the full `--proxy` chain into a live sway. So
  `wlsctx_t`'s ruleset can borrow the `container_runtime_t` rules as
  a floor.
- **The app side ≙ `container_t`**: also zero denials. The rebuilt
  rootfs' fresh `seclabel` tmpfs (`/tmp`/`/dev`/`/run`) inherit the
  mounting process' exec label → `container_file_t` for free
  (podman's own rootfs mechanism); `/proc` reads, loopback net and
  `/dev/urandom` are covered; `/dev/dri` via
  `container_use_dri_devices` (on by default). So `wlsctx_app_t` can
  stay minimal.
- What `container_t` *alone* does not cover is exactly the
  runtime-side set (it would need, e.g., the session-bus and
  `system:start` allows, plus `container_manage_cgroup` turned on
  for the cgroup-scope writes) — which is why running the whole
  tree as `container_runtime_t` works out of the box while a
  `container_t`-only wlsctx would not. The module (dedicated
  `wlsctx_t`/`wlsctx_app_t`) remains the cleaner confinement; the
  probe is the inventory it must at least match.

## Operating modes

**Unconfined mode (default, no action needed).** The binary keeps
its usual label (`user_home_t` in the dev tree, `bin_t` if installed
without relabeling). Nothing transitions; the whole stack —
supervisor, sidecars, app — runs `unconfined_t` exactly as before,
and the module is inert except for the `xserver_t` rules.

**Confined mode.** Relabel the installed binary so the transition
fires:

```sh
sudo restorecon -v /usr/local/bin/wlsctx   # picks up wlsctx_exec_t
# or explicitly:
sudo chcon -t wlsctx_exec_t /usr/local/bin/wlsctx
```

After that every `wlsctx` subcommand runs as `wlsctx_t`; the
sandboxed app and the `bin_t` helpers it or the pipeline exec
(notify-send, xdg-dbus-proxy, app subprocesses) run as
`wlsctx_app_t`; Xwayland runs as `xserver_t`. The hard boundary of
the sandbox is still the namespaces + nono landlock/seccomp
(decision #27) — the module is a second, compositable layer, and
the S-side supervisor can still see and signal the app across the
domain boundary.

If an app binary carries a type other than `bin_t`/`user_home_t`
(check with `ls -lZ <app>`), add it to the `type_transition
wlsctx_t { ... }` line in `wlsctx.te` and rebuild.

## Per-instance MCS (cross-instance isolation)

In confined mode, each app instance gets its own MCS category
within the user's `s0-s0:c0.c1023` range (a stable hash of
app-id+instance-id), so an instance's files in the per-instance dir
— and everything it creates, e.g. in its home — are unreadable and
unwritable by another instance's category, the same way podman
separates containers (`cNNN,cMMM`). Mechanics:

- at startup, if the process label is `wlsctx_t` (confined) the
  supervisor narrows its own range to `s0-s0:cN` via
  setexecfilecon + a one-time self re-exec (`/proc/self/exe`,
  `dyntransition` on `wlsctx_t` — see the module); every child it
  forks (A, the sidecars) inherits the range, and objects they
  create (the instance dir, scratch, sockets) carry `cN`
- B carries the range into the app exec via setexecfilecon
  (`wlsctx_app_t:s0-s0:cN`, `dyntransition`); the Xwayland satellite
  does the same for its `xserver_t` exec, so the X socket and MIT
  auth file it creates in the instance dir carry `cN`
- s0 (no category) labels stay reachable both ways: the instance
  can read plain host files (its range covers s0) and plain
  processes can read it only if their range covers `cN` — the
  reverse is the isolation
- in unconfined mode (module uninstalled / binary not relabeled)
  the mechanism is off: labels have no category to carry

## Build

```sh
./build.sh        # → build/wlsctx.p, build/wlsctx.pp, build/wlsctx.cil
```

`wlsctx.cil` is a *reference rendering* only: checkpolicy 3.11 can
write CIL (`-C`) but the toolchain has no CIL reader — `semodule`
and `semanage` take only binary module packages, and the old CIL
parser was never merged into upstream checkpolicy (verified against
the 3.11 sources, 2026-10-28). So the install path stays
`.te` → `checkmodule` → `semodule -i wlsctx.pp`.

The build needs only the installed `checkmodule` (from the
`checkpolicy` package) and `semodule_package` (policycoreutils).
Notes on checkpolicy 3.11 (the Fedora 45 "SELinux userspace 3.11"
line), all the hard-won details:

- **module compilation is `checkmodule`, not `checkpolicy`**
  (`checkpolicy` builds the whole base policy; its `-c` flag takes a
  *version number*, not a policy.conf file).
- the module file must start with `module wlsctx 1.0.0;` and contain
  a `require { ... }` block — both are hard errors without them.
- `require` takes **one identifier per `type` line**, and classes
  with their used permissions in **braces**:
  `class process { fork signal ... };`.
- `-M` (MLS/MCS) is needed because this system runs targeted + MCS;
  the module policy version tops out at 24 (module-store versioning,
  unrelated to the kernel policy version 35) — just omit `-c`.
- the output base name must equal the module name
  (`wlsctx.te` → `wlsctx.p`).
- base **type attributes** referenced in rules (here: `file_type`
  for the broad mount grant) are re-declared in the module
  (`attribute file_type;`) — they merge with the same-named base
  attribute at load.

## Install (needs root — the user does this)

```sh
sudo semodule -i build/wlsctx.pp        # registers module + file contexts
sudo restorecon -v /usr/local/bin/wlsctx # confined mode (see above)
```

Remove with `sudo semodule -r wlsctx`. The module package is
self-contained (no dependency on the container-era CIL blocks,
deleted in the plan v2 rework).

## Tuning loop (once it is installed)

1. Use the system normally (run an app, the broker, the xwayland
   satellite).
2. Harvest denials: `sudo ausearch -m avc -ts recent`
   (or `sudo cat /var/log/audit/audit.log | grep avc`).
3. Narrow: `sudo audit2allow -a` (or `-i` per line) → review every
   rule it proposes, port the ones that make sense into `wlsctx.te`
   as explicit rules (no blanket `files_unconfined_type` grants),
   rebuild, `sudo semodule -r wlsctx && sudo semodule -i build/wlsctx.pp`.
4. When the denials stop, the rule set is the trimmed policy.
