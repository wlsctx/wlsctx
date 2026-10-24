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
  broker), the session bus (broker), spawning `xdg-dbus-proxy` and
  Xwayland, and the `/proc/self/exe` re-exec (SIGHUP rebuild).
- `wlsctx_app_t` — sandboxed-app domain. B execs the app while in
  `wlsctx_t`; the app (and its subprocesses) land here via the
  `bin_t`/`user_home_t` transition. The rule set is a "confined user
  app": instance dir, /tmp, /dev nodes (the §3.3 genfs labels),
  /proc /sys /cgroup /etc, home/cache, system libs (`lib_t` dlopen),
  session bus, loopback network.
- `xserver_t` — the stock policy on this machine has **no transition
  into `xserver_t` at all** (verified with `sesearch -T -t
  xserver_t`), so Xwayland has always run `unconfined_t` and the
  stock xserver rules were never exercised. The module adds the
  `wlsctx_t → xserver_t` transition (so the satellite gets a real
  X-server domain in confined mode) and the one gap the
  reconnaissance found: `xserver_t` access to the X socket and MIT
  auth file in the per-instance dir (`user_tmp_t`).

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

## Build

```sh
./build.sh        # → build/wlsctx.p, build/wlsctx.pp
```

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
