# wlsctx SELinux module (phase 8.2)

A local SELinux module that confines the wlsctx stack to its own
domains. It is a **first pass**: the rule sets are deliberately a
little broader than the minimum and meant to be trimmed with audit
denials (below). The first confined run is verified: types, the
`xserver_t` fix, and the per-instance MCS narrowing all work (a run
showed `wlsctx_t:s0-s0:cN` / `wlsctx_app_t:s0-s0:cN` live, 2026-10-29).

## The policy is defined directly in CIL

`wlsctx.cil` is the single source of truth — and the install artifact.
There is no `.te`, no `checkmodule`, no build step: on this toolchain
(Fedora 45, policycoreutils 3.11) `semodule -i` accepts CIL directly
(the CIL reader is in libsepol, the library `semodule` links — the
checkpolicy CLI has no CIL input mode; LESSONS #24-25), and the 3.11
module store is CIL-based even for classic `.pp` installs, so the CIL
is the format everything ends up in anyway. Two reasons the old
`.te` → `checkmodule -C` path was dropped:

- **checkmodule -C writes `typetransition` with the raw `.te` class**
  (`file`) and does not normalize it to `process` the way the classic
  checkpolicy pipeline does — the kernel's bprm transition lookup only
  consumes `process`-class avtab entries, so the transition silently
  never fires. Hand-written CIL spells `process` explicitly
  (LESSONS #27).
- a hand-written CIL lets us state the two things the classic
  pipeline gets wrong for a user-spawned type: the **role
  association** (`(roletype unconfined_r wlsctx_t)` — the process
  inherits `unconfined_r` from the shell, and a context is only
  *valid* when the role is associated with the type; without it,
  `setprocattr` of the exec context fails `EINVAL` and the MCS
  narrowing silently degrades, LESSONS #28) and the **`mcs_constrained_type`
  membership** that gives the categories their teeth.

CIL has no comment syntax (the libsepol lexer's comment rule is
empty), so the file is bare statements only.

## What it defines

- `wlsctx_exec_t` — file type for the installed `wlsctx` binary
  (`/usr/local/bin/wlsctx` or `/usr/bin/wlsctx`; the two `(filecon …)`
  statements at the bottom of the CIL, installed in the same command
  as the rules).
- `wlsctx_t` — supervisor / S→A→B pipeline / sidecar domain. Reached
  by transition from `unconfined_t` when the binary carries
  `wlsctx_exec_t`. Covers: rootfs mounts (fresh tmpfs / devpts /
  proc, self-bind of `/`, profile binds), the per-instance cgroup,
  the per-instance runtime dir and its sockets (wayland, X, bus,
  broker), the session bus (dbus-broker as `unconfined_dbusd_t` on
  this box), spawning `xdg-dbus-proxy` and Xwayland, the
  namespace/userns/cap setup, and the `/proc/self/exe` re-execs.
- `wlsctx_app_t` — sandboxed-app domain. B execs the app while in
  `wlsctx_t`; the app (and its subprocesses) land here via the
  `bin_t`/`user_home_t` transition. "Confined user app": instance
  dir, /tmp, /dev nodes, /proc /sys /cgroup /etc, home/cache,
  system libs, session bus, loopback network.
- `xserver_t` — stock policy transitions `unconfined_t → xserver_t`
  on `xserver_exec_t`, but in confined mode the satellite is
  `wlsctx_t`, so the module adds the `wlsctx_t → xserver_t`
  transition plus `xserver_t` access to the X socket and MIT auth
  file it places in the per-instance dir (precautionary — the Phase
  7.3 e2e logged no denials; the tuning loop decides).

**Roles:** both `wlsctx_t` and `wlsctx_app_t` are associated with
`unconfined_r` (the spawner's role, as container-selinux does with
`container_t`/`container_runtime_t`) *and* with `object_r` (so their
file labels are valid). The `unconfined_r` association is load-bearing
— see above.

## Operating modes

**Unconfined mode (default, no action needed).** The binary keeps its
usual label; nothing transitions; the whole stack runs `unconfined_t`
exactly as before, and the module is inert.

**Confined mode.** Relabel the installed binary so the transition
fires:

```sh
sudo restorecon -v /usr/local/bin/wlsctx   # picks up wlsctx_exec_t
```

After that every `wlsctx` subcommand runs as `wlsctx_t`; the
sandboxed app and the helpers it or the pipeline exec run as
`wlsctx_app_t`; Xwayland runs as `xserver_t`. The hard boundary of
the sandbox is still the namespaces + nono landlock/seccomp
(decision #27) — the module is a second, compositable layer.

If an app binary carries a type other than `bin_t`/`user_home_t`
(check with `ls -lZ <app>`), add a `(typetransition wlsctx_t TYPE
process wlsctx_app_t)` line (plus the matching process/file allows)
to `wlsctx.cil` and reinstall.

## Per-instance MCS (cross-instance isolation)

In confined mode, each app instance gets its own MCS category
within the user's `s0-s0:c0.c1023` range (a stable FNV-1a hash of
app-id + instance-id), so an instance's files in the per-instance
dir — and everything it creates, e.g. in its home — are unreadable
and unwritable by another instance's category, the same way podman
separates containers. The isolation is **real, not cosmetic**,
because both types are members of the base policy's
`mcs_constrained_type` attribute: the kernel's MLS constrain then
applies (a file/dir/process object's level must be dominated by the
subject's range *high*), which admits `s0` (plain host files —
dominated by any `cN`) and blocks cross-category access. The socket
and `fd` classes are **not** in the base constrain list, so the
broker's session sockets and inherited fds keep working across
categories.

Mechanics (`src/mcs.rs`):

- at startup, if the process label is `wlsctx_t` (confined) each
  process narrows its own range to `s0-s0:cN` by writing
  `/proc/self/attr/exec` and re-exec'ing `/proc/self/exe` (the
  self-`dyntransition` on `wlsctx_t`). The kernel accepts the write
  only if the target context is *valid* (role associated with type —
  the `unconfined_r` roletypes above) and the new range is a subset
  of the current one (the base `context (contains)` constrain).
  The narrowing happens **before** any binding/creation, so the
  instance dir, scratch and sockets carry `cN` for free (objects
  take the creator's range), and every forked child inherits it.
- B carries the range into the app exec via setexecfilecon
  (`wlsctx_app_t:s0-s0:cN`); the Xwayland and dbus-proxy satellites
  do the same for their execs.
- the broker does not narrow (shared by all instances). **Pending:**
  it currently keeps the full spawn range, which on a fresh machine
  would label a broker-created session dir at that full range — a
  `cN` proxy could then not `add_name` inside it. The planned fix
  narrows the broker to *single-level `s0`* (a subset of any spawn
  range) before it creates anything: it still reads every `cN`
  object and its own files stay plain `s0`.
- SIGHUP re-execs preserve the range (an exec-context write that
  skips any pending explicit context, so the startup narrowing is
  never clobbered).
- a failed exec-context write degrades to a run **without** MCS:
  logged, the run continues. In unconfined mode the mechanism is off
  (labels have no category to carry).

## Install (needs root)

One command for the rules *and* the file context:

```sh
sudo semodule -i selinux/wlsctx.cil
sudo restorecon -v /usr/local/bin/wlsctx     # confined mode (see above)
```

The CIL carries the two `(filecon …)` statements for the binary
(`system_u:object_r:wlsctx_exec_t:s0` — the MCS category is a
*process* label, never a file label). On 3.11 the store reads file
contexts straight out of the module CIL (libsemanage calls
`cil_filecons_to_string` after `cil_compile` and writes them to the
policy's `file_contexts`), so the file context is *in* the module and
`semodule -r wlsctx` removes it too. `restorecon` (or
`chcon -t wlsctx_exec_t`) is what actually relabels the installed
binary — `semodule -i` only registers the context.

**Remove:**

```sh
sudo semodule -r wlsctx
```

## Tuning loop

1. Use the system normally (run an app, the broker, the xwayland
   satellite).
2. Harvest denials: `sudo ausearch -m avc -ts recent`.
3. `sudo audit2allow -C <file>` — since the contexts are valid
   (roles associated), this now parses every record and proposes
   rules; review each one and port the ones that make sense into
   `wlsctx.cil`.
4. Reinstall (`sudo semodule -r wlsctx && sudo semodule -i
   selinux/wlsctx.cil`) and re-run.
