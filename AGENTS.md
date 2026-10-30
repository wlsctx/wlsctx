# AGENTS.md

wlsctx: runs GUI apps (JetBrains IDEs, Librewolf) in an unprivileged
**in-process sandbox** (namespaces, private rootfs, landlock+seccomp
via `nono`) on a wlroots Wayland desktop (sway, Fedora) with native
Wayland + GPU rendering. The Rust binary `wlsctx` is a subcommand CLI:
`run` creates the sandbox and tags the app's Wayland socket with the
`wp_security_context_v1` protocol so the compositor identifies
sandboxed clients; `wayland` is the original tag-and-park mode, which
with `--proxy` additionally runs a transparent protocol relay (an
optional global allowlist, a clipboard/primary-selection receive-gate,
a selection audit log) and, with `--broker-socket`, a host-side broker
(`broker`) that serves a consent prompt (dropped *reads*) and a
fire-and-forget copy-out notification (app *writes*,
`--notify-copy-out`); `decide` lists/resolves the broker's pending
prompts. **PLAN.md is the authoritative plan and decisions log — read
it before non-trivial changes. LESSONS.md is a short, living record of
hard-won lessons — skim it before non-trivial changes (the full
write-ups live in `docs/postmortems/`). README.md is the
architecture/threat-model doc (rewritten for the in-process world in
phase 8.1).**

## Layout

- `src/main.rs` — binary entry: logging, CLI parse, subcommand
  dispatch (`run`/`wayland`/`broker`/`decide`/`dbus-proxy`). SIGHUP
  semantics are
  mode-dependent: `run` terminates the app and exits 129 (decision
  #33); the `wayland` modes rebuild (in-place re-exec in `--listen`
  mode, clean exit for a systemd restart when socket-activated)
- `src/cli.rs` — clap subcommand tree: `run` (sandboxed execution),
  `wayland` (tag-and-park or `--proxy`, incl. `--tagged-socket`,
  `--allow-globals`, `--clipboard-policy`, `--broker-socket`,
  `--notify-copy-out`), `broker` (`--listen`/`--socket-activation`,
  `--auto-decide`, `--broker-timeout-millis`), `decide`
  (`--decision`, `--prompt`), `dbus-proxy` (`--app-id`,
  `--instance-id`, `--bus-address`, `--socket-name`,
  `--see`/`--talk`/`--own`/`--call`/`--broadcast`, `--proxy-bin`);
  cross-field checks live in `validate()`
- `src/lib.rs` — library modules used by the binary:
  - `proxy/` — the `--proxy` relay: wire parser, object bookkeeping
    (convention-adaptive ID layout), interface tables (generated),
    global allowlist policy, the selection receive-gate (detects app
    writes/clears via `ClipboardGate::set_selection` and rate-limits
    the copy-out notification), the broker client, `audit.rs` (one
    size-only `key=value` record per `set`/`read`/`clear`/`serve`
    under the `audit` log target), and the signalfd loop
    (`run_signal_loop`/`re_exec`; SIGHUP → rebuild)
  - `broker.rs` — the broker daemon: N-D-JSON, one consent
    `clipboard-read` request/response *and* one one-way
    `clipboard-write` notification per connection; in interactive mode
    a session decision socket (`decision.sock`, bound once for the
    life of the session) carries `decide`'s list/decide requests over
    a poll(2) main loop
  - `dbus_proxy.rs` — the Phase-7.2 D-Bus sidecar: owns an
    `xdg-dbus-proxy` child (signalfd + pidfd `poll(2)` loop; stops it
    on TERM/INT/HUP); the child's lifetime is a private socketpair
    handed over as `--fd=3` (**non**-CLOEXEC — `execve` closes
    CLOEXEC fds), so even a SIGKILL'd sidecar tears the proxy down
    (decision #36); sync-byte readiness gate; public `bus.sock` in
    the per-instance runtime dir, owner-only
- `mcs.rs` — per-instance MCS categories (phase 8.2, confined mode
    only): one category `cN` of the user's `s0-s0:c0.c1023` range
    per (app-id, instance-id) via a stable FNV-1a hash; the
    one-time self-narrowing re-exec (`self_reexec_with_category`,
    loop-guarded by range equality, degrading to no-MCS on a failed
    exec-context write), the `setexecfilecon` carry-over into the
    app/`xserver_t` execs (`set_exec_context`), and the range-
    preserving re-exec (`preserve_range`, which skips a pending
    explicit exec context so the narrowing is never clobbered).
    No-op when the current label is not `wlsctx_t`
- `xwayland.rs` — the Phase-7.3 Xwayland satellite: owns an
    `Xwayland` child (same signalfd + pidfd `poll(2)` shape;
    TERM→2s→KILL teardown); the sidecar creates, binds **and
    listens** the X socket (the spawner must `listen` — Xwayland's
    `-listenfd` path adopts the fd as-is) and hands it over as
    `-listenfd` (non-CLOEXEC); a socketpair as `-displayfd` is the
    readiness gate (display number cross-checked against
    `--display`); `-auth` (MIT cookie), `-nolisten tcp`, `-rootless`
    by default. The lifetime backstop for a SIGKILL'd satellite is
    `PR_SET_PDEATHSIG` (set in `pre_exec`, re-armed in the child by
    an on-demand-compiled `LD_PRELOAD` shim — the SELinux transition
    into `xserver_t` clears it on exec; decision #37, LESSONS #19-20)
- `src/wayland/` — the tagged Wayland socket for the `run` pipeline:
  `listener` (socket activation / `--listen`), `roundtrip` (bounded
  sync), `context` (the `wp_security_context_v1` exchange)
- `src/sandbox/` — the in-process sandbox: `userns`, `namespaces`
  (mount/pid/cgroup/ipc/uts/net), `mounts` (private rootfs builder),
  `policy` (the nono `CapabilitySet` + three-stage apply, #27),
  `supervise` (notify-fd handoff, app-pid report, verdict pipe, the
  S-side supervisor loop, #23/#25/#26), `mod` (S→A→B pipeline,
  `run_sandboxed`, the S-side signal forwarder / `terminate_app`,
  the `waitpid_retry` + `AppKillGuard` orphan backstop, #41,
  sd-notify, #33)
- `src/profile/` — per-app TOML profiles (`gpu`, `ro_binds`, `rw_binds`,
  `mask`, `env`, …; `deny_unknown_fields`)
- `src/systemd.rs` — the transient session-bus scope (phase 6.1, #35)
- `src/testutil.rs` — shared `#[cfg(test)]` helpers (env locking,
  TmpDir, the LISTEN-FD / sandbox locks)
- `tests/proxy_integration.rs` — three-party integration tests (fake
  compositor, real wayland-client, the relay): pass-through,
  allowlist, clipboard (incl. the selection-audit records), primary
  selection, broker consent, copy-out notification
- `tests/broker_integration.rs` — end-to-end tests of the broker
  daemon as a subprocess: multiple pending prompts on the session
  decision socket (list/resolve by id, timeout, refused decides)
- `tests/phase0_interface_tables.rs` — checks the generated
  interface/wlr tables against the protocol XMLs
- `protocols/` — the protocol XMLs (source of `wlr_tables.rs` and the
  interface-table generator)
- `scripts/gen_interface_table.py` — generates
  `src/proxy/interfaces.rs` (the name → `&'static Interface` lookup
  table) from the protocol XMLs. `src/proxy/wlr_tables.rs` is a
  checked-in `wayland_scanner::generate_interfaces!` table over
  `protocols/*.xml` that expands at compile time. **Do not hand-edit
  either file** (CI regenerates and diffs them).
- `.github/workflows/ci.yml` — protocol-table regeneration check +
  cargo check
- `systemd/user/` — the wlsctx-broker socket+service units: the only
  units in the repo. Per-app proxies are documented manual runs (the
  README), and the phase-7.2/7.3 `dbus-proxy`/`xwayland` sidecars
  would land here
- `PLAN.md` — rework plan: architecture, decisions log, phase/task list
- `LESSONS.md` — a short, living record of hard-won lessons from past
  work; add a line whenever a change teaches something durable, and
  promote long entries to `docs/postmortems/`
- `docs/postmortems/` — full write-ups of significant bugs/fixes (one
  per incident), referenced from `LESSONS.md`; currently the
  fd-misrouting post-mortem
- `assets/` — logos/headers

## Facts

- Target: Fedora 45 (upgrade in progress), user-level systemd,
  sway/wlroots desktop. No containers: the sandbox is created by
  `wlsctx` itself (namespaces, private rootfs, landlock+seccomp via
  `nono`) — see PLAN.md. The container-era deployment is fully
  deleted; the broker units are re-homed to the subcommand CLI
  (phase 7.1).
- The app runs as its **real uid** inside the user namespace: the
  `uid_map` is a **single extent `<uid> <uid> 1`**, written **exactly
  once** (decision #9), because that is all an unprivileged creator may
  write (decision #10). In-ns `0` is therefore **unmapped** — the app
  can never be root or another user, and root-owned trees are simply
  unwritable by it. (The old two-entry `0→uid; uid→uid` map was
  replaced in Phase 3.)
- The private rootfs is **rebuilt, not masked**: the recursive self-bind
  of `/` (never `ro` — see below) is the base; `/dev` and `/sys` are
  **fresh tmpfs** with subpath binds of the nodes the app needs, because
  binding the *mount root* of devtmpfs/sysfs/ext4 is `EINVAL`
  unprivileged (decision #18) and `mknod` is `EPERM` (decision #19).
  `MS_BIND|MS_RDONLY` on those foreign-superblock binds silently drops
  the ro flag and `MS_REMOUNT` is `EPERM` (decision #21) — so ro
  semantics come from the app's real uid plus nono's landlock/seccomp
  policy, not from mount flags. The build scratch lives on
  `/var/tmp/.wlsctx/<inst>` and carries the per-instance runtime dir
  out from under the fresh-`/run` mask (decision #28). The combined
  seccomp-notify + Landlock floor is applied three-stage in B pre-exec
  (decision #27); B blocks on A's verdict before exec (decision #26);
  S services the listener (auto-deny, decision #25).
- The cgroup ns is rooted at the instance sub-cgroup, which must be
  created and entered **before** `unshare(CLONE_NEWCGROUP)` (decision
  #20); the app then sees `0::/`.
- The app only sees the **tagged** Wayland socket, never the host
  socket; the reference pipe ("close" fd) must stay open for the
  process lifetime (ownership note in `wayland/context.rs`).
- Per-instance runtime dir on the host:
  `$XDG_RUNTIME_DIR/wlsctx/<app>-<instance>/`. Inside the sandbox it
  always appears at the systemd-standard
  `/run/user/<uid>/wlsctx/<app>-<instance>/`, regardless of the
  host's `XDG_RUNTIME_DIR` (decision #28) — and that in-sandbox path
  is what the app's env uses: `run --wayland` sets `XDG_RUNTIME_DIR`
  to it and `WAYLAND_DISPLAY` to the socket name (default
  `wayland-1`).
- **Per-instance MCS (phase 8.2, `src/mcs.rs`):** in confined mode
  (module installed + binary relabeled to `wlsctx_exec_t`), each
  instance runs in its own category `cN` of the user's
  `s0-s0:c0.c1023` range (a stable hash of app-id+instance-id — the
  `run` pipeline and the standalone proxy/satellites must agree,
  which they do by construction). Every wlsctx process narrows its
  own range to a single-level `s0:cN` by a `wlsctx_t` self-
  `dyntransition` re-exec **before** it creates or binds anything, so
  every forked child inherits `cN` (a process takes its creator's
  full range); B and the Xwayland/dbus-proxy satellites carry the
  range into their execs via setexecfilecon (`wlsctx_app_t`/
  `xserver_t`). The isolation is **process-level, not object-level**
  (LESSONS #29): both types are in the base `mcs_constrained_type`
  set, so the base mlsconstrain (`h1 dom h2`) lets a `cN` subject
  signal/ptrace/transition only a *same-`cN`* process (a single
  category is incomparable with any other — *stronger* than podman's
  `cNNN,cMMM` model). But `dir`/`file`/`sock_file` created under the
  `s0` runtime parent take the **parent's** low level (`default_range
  … target low`), so the instance dir and everything the app writes
  are `s0` and reachable from every `cN` — file/dir separation comes
  from the namespaces + landlock rootfs, not SELinux. The broker
  narrows to single-level `s0` (`mcs::self_reexec_to_s0`) for
  subject-range hygiene. One known gap: this kernel's `signull`
  (kill 0) is not in the base mlsconstrain and a module CIL can't add
  one, so the `terminate_app` kill -0 probe is not category-scoped
  (LESSONS #33). SIGHUP re-execs preserve the range; a failed
  narrowing degrades to a no-MCS run. In unconfined mode every
  mechanism is a no-op. Details: `selinux/README.md` (the
  "Per-instance MCS" section), decision #38.
- GPU: `/dev/dri/renderD*` nodes are bind-mounted into the sandbox's
  `/dev`; the user must be in the `render` group. `/dev` nodes are
  **bind-mounted, not mknod'd**, so future SELinux modules can use the
  canonical genfs labels.
- **SIGHUP semantics are mode-dependent (merge reconciliation):**
  `run` forwards SIGHUP to the app and exits 129 (decision #33 — there
  is no in-place rebuild of a live sandbox); the `wayland` modes
  (tag-and-park, proxy) treat SIGHUP as a *rebuild*: an in-place
  re-exec in `--listen` mode (`/proc/self/exe`, same pid, fresh
  compositor connection and tag), or a clean exit for a systemd
  restart when socket-activated (the activated fd may not survive an
  `execve`). See `proxy::run_signal_loop` / `proxy::re_exec`.
- The proxy/broker signalfd loops block **every** signal except the
  seven kernel-generated fatal faults. The mask must be built from
  `SigSet::all()` (sigfillset, all 64 bits) minus those seven — never
  by iterating nix's `Signal` enum, which stops at 31 and would leave
  the real-time range (34-64) at its default-terminate disposition,
  letting a same-uid process kill wlsctx with `kill -34` (see
  `proxy::proxy_signal_mask`).
- The supervisor services **every** trapped notification on the
  listener: `handle_notif` dispatches by syscall number with no pid
  filter, so children of the app that inherit the seccomp filter are
  served with the same capability set, and a failed verdict answers
  EPERM rather than hanging (decision #32, resolved — the Firefox e2e
  ran a real multi-process GUI app to a clean SIGTERM shutdown).
- SIGTERM/SIGINT are **forwarded to the app** (SIGTERM, then SIGKILL
  after 2 s, since pidns-init ignores default-action signals, #13/#33);
  SIGHUP also terminates the app and exits 129. S sends `READY=1` to
  systemd after the handoff and untags the Wayland socket on teardown.
- The `--proxy` relay is convention-adaptive: Rust wayland-backend
  uses display=ID 1, client IDs from 2, server IDs from 0xFF00_0000;
  C libwayland uses display=ID 0, client IDs from 1, server IDs from
  0x80000000. The first message of a connection pins the convention
  for both ends (`src/proxy/objects.rs`). Events use the raw 0-based
  index in the interface's event list — not `requests.len()+index`.
- The relay's fd sanity check treats only in-memory channels
  (memfd/pipe/socket, via `/proc/self/fd/<n>` readlink) as valid
  `receive` targets; a path is a fatal protocol error.
- The broker is a **host** user service (`systemd/user/`), not a
  container: it must be able to notify the user.
- The broker speaks N-D-JSON with **two request kinds** (both over the
  same socket, dispatched on the line's `kind` field): `clipboard-read`
  (request/response, the consent prompt — the daemon answers after the
  user decides) and `clipboard-write` (one-way, Phase 6 — the daemon
  fires `notify-send` and closes with no reply). The write notification
  is fire-and-forget and fails open: the relay's `notify_write` uses a
  2 s deadline and never blocks or alters the write. The *user's*
  answer travels over a second, session-scoped socket
  (`$XDG_RUNTIME_DIR/wlsctx/decision.sock`): `wlsctx decide` lists
  the pending prompts (oldest first, each with an id) or resolves the
  oldest — or the one `--prompt <id>` names. A decided prompt leaves
  the queue atomically with its decision; an unbound decision socket
  degrades the broker (prompts deny at once, `no-decision-socket`),
  and `--auto-decide` mode never binds it.
- Rust edition 2024; deps are pinned in Cargo.lock. `nono` is
  Apache-2.0 (compatible with this repo's AGPL-3.0); its docs are thin,
  the crate source is the reference.
- **Run the test suite single-threaded: `cargo test --locked --
  --test-threads=1` (CI already does this).** Several tests mutate the
  process environment (`std::env::set_var`/`remove_var`) and the sandbox
  tests `fork(2)`; both are unsafe with other test threads running —
  the env mutation is UB against any concurrent `getenv` (flaky
  socket-activation failures), and a lingering multi-thread tokio runtime
  across the fork deadlocks on `std`'s global `thread_info` lock (a hung
  whole suite). Single-threading removes both at ~no cost (the suite is
  dominated by the `SANDBOX_LOCK`-serialised sandbox tests). See
  LESSONS.md #15/#16.
- This is a personal WIP repo: the rework is phase-by-phase (PLAN.md),
  each phase committed and working. Phase 5.5 (the Firefox e2e) and
  7.2 (the `dbus-proxy` sidecar), 7.3 (the `xwayland` satellite),
  8.4 (the integration test suite) and 8.5 (the threat-model review)
  are done; phase 8.2 landed the SELinux module (`selinux/` —
  `wlsctx_t`/`wlsctx_app_t`/the xserver_t fix, written directly in
  CIL, installed and tuning-looped to zero denials — see the
  "Per-instance MCS" fact above for what it actually isolates).
  The full chain is verified at probe level (a sandboxed
  `wayland-info` through the `--proxy` relay into live sway) and,
  under **enforcing mode**, with a real GUI app: `foot` rendered
  through the `--proxy` relay into live sway with zero denials
  across the whole boot+render cycle (v2.14 — the enforcing-mode
  tuning closed five gap classes, decisions #39–#40 and LESSONS
  #34–#36: devpts `MS_NODEV`, the `run` teardown sparing live
  sidecar sockets, the relay's receive-side `fd:use`/`file` grants
  for `SCM_RIGHTS` (a dropped fd is silent `MSG_CTRUNC`), the
  fresh-tmpfs symlink label trap, and the `dir` `open`/`read`
  distinction).
  Next up: the `PR_SET_PDEATHSIG` cascade for the SIGKILL-to-S
  boundary decision #41 leaves open (A←S — A never execs, so a
  `pre_exec` set survives — and B←A — B execs, so it needs the
  decision-#37 `LD_PRELOAD` restore shim), then a confined-mode
  run of the `dbus-proxy`/`xwayland` satellites and the broker
  (the relay is now verified confined; they are not), then the
  6.5.5 `serve`-label drag refinement (the audit itself is
  closed); 6.4 (the varlink tier) stays parked until a released
  systemd ships `PIDs` in `StartTransient`.

## Commit conventions

- Small commits, one per meaningful change, committed as you go.
- Subject: `<emoji> <type>: <summary>` — a conventional type prefix
  (`feat:`, `fix:`, `chore:`, `docs:`, …) and a summary under 72 chars.
  The single emoji is chosen per change to capture what actually changed;
  there is no fixed set of allowed emojis.
- End the message with an `Assisted-by: <agent>:<model>` trailer (no
  "generated with" line).
