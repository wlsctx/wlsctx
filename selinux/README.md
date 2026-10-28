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

- at startup, if the process label is `wlsctx_t` (confined) each
  process narrows its own range to `s0-s0:cN` via setexecfilecon
  (`/proc/self/attr/exec`) + a one-time self re-exec of
  `/proc/self/exe` (the self-`dyntransition` on `wlsctx_t` — see
  the module): the `run` supervisor before it creates the instance
  dir/sockets, and the standalone proxy/satellites before they
  bind their sockets. The narrowing happens **before** any
  binding/creation, so the post-re-exec pass starts clean and the
  sockets carry `cN`. Every forked child (A, the sidecars)
  inherits the range, and objects created with no explicit
  fscreate context take the creator's range — the instance dir,
  scratch and sockets carry `cN` for free
- B carries the range into the app exec via setexecfilecon
  (`wlsctx_app_t:s0-s0:cN`); the Xwayland satellite does the same
  for its `xserver_t` exec, and the dbus-proxy satellite for its
  `wlsctx_app_t` exec, so the X socket, MIT auth file and bus
  socket they create in the instance dir carry `cN`
- the broker never narrows: it is shared by all instances and its
  sockets stay plain `s0`, which every `cN` can still reach
- s0 (no category) labels stay reachable both ways: the instance
  can read plain host files (its range covers s0) and plain
  processes can read it only if their range covers `cN` — the
  reverse is the isolation
- SIGHUP re-execs (`--listen` rebuild) preserve the range via an
  exec-context write (skipping any pending explicit context, so
  the startup narrowing is never clobbered)
- a failed exec-context write (category outside the user's range,
  missing `dyntransition`) degrades to a run **without** MCS:
  logged, the run continues
- in unconfined mode (module uninstalled / binary not relabeled)
  the mechanism is off: labels have no category to carry

## Build

```sh
./build.sh        # → build/wlsctx.p, build/wlsctx.pp, build/wlsctx.cil
```

`wlsctx.cil` is the **primary install artifact**: `semodule -i` on
this toolchain reads CIL directly (libsemanage → libsepol's CIL
reader; the checkpolicy CLI itself has no CIL input mode — that was
the earlier dead end, see LESSONS #24). Install:
`sudo semodule -i build/wlsctx.cil`. The `.pp` (checkmodule +
semodule_package) remains as the classic alternative; the `.te`
stays the source of truth either way.

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
sudo semodule -i build/wlsctx.cil          # policy rules (pure CIL)
sudo semanage fcontext -a -f wlsctx.fc     # file context for the binary
sudo restorecon -v /usr/local/bin/wlsctx   # confined mode (see above)
```

The `.cil` carries no file contexts (the `build.sh` CIL step passes
no `-f`), so the file context lands via `semanage fcontext` — that
path parses the standard `gen_context(...)` form fine; what breaks
on 3.11 is the *store* writer, which serializes a `.pp` filecon's
unresolved `gen_context` placeholder verbatim into CIL and the
reader then rejects it (LESSONS #25). So: pure CIL for the rules,
`semanage fcontext` for the label — not the bundled `.pp`.
(If you do want the `.pp`: `build/wlsctx.nofc.pp` is the policy-only
package, and `wlsctx.fc.resolved` is the colon-form filecontext file
that survives the store conversion.)

Remove with `sudo semodule -r wlsctx`
(and `sudo semanage fcontext -d /usr/local/bin/wlsctx`). The module
is self-contained (no dependency on the container-era CIL blocks,
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
