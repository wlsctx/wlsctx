# LESSONS

Short, living record of hard-won lessons from working on wlsctx, so future
sessions (human or agent) don't have to re-learn them. Each entry is a
takeaway; for full context follow the `source:` link to the relevant
post-mortem (in `docs/postmortems/`) or commit.

**Cultivate this file.** When a change teaches something durable, add one line.
Keep entries to a few sentences; if one grows long, promote it to a post-mortem
under `docs/postmortems/` and link here. This file is a *pointer*, not the
write-up.

## Working with the code

1. **For "first/last N" logic, test the multi-element path, not just the
   one-element path.** The fd-misrouting bug was invisible to every existing
   test because they all used exactly one fd, where `take == len` made the
   wrong `split_off` call accidentally correct. The bug only surfaced with two
   or more fds in a datagram. `VecDeque::split_off(n)` keeps `0..n` and
   *returns* `n..len`; to consume the first N in arrival order the primitive is
   `drain(0..take)`. — *`docs/postmortems/fd-swap-fix-plan.md` §1, §5;
   commit `88d237e`.*

2. **In a security-sensitive path, name the category of the bug before
   fixing or reporting it.** The fd mispairing sat in the clipboard path but
   was a *data-integrity* bug, not a *security* regression: the gate's
   forward/drop decision keys on the object id + origin, never on the fd
   itself. Determining and stating the category up front is what keeps the
   commit message and any disclosure framed correctly. — *post-mortem §4.*

3. **Read the load-bearing lines at the actual line numbers before trusting a
   handoff doc.** The handoff plan was accurate, but the confidence in the fix
   came from reading the real `split_off` call and the `wire::parse_message`
   `pop_front` contract, not from the document alone. Treat a handoff or
   post-mortem as a starting point; verify the lines the fix depends on.
   — *post-mortem §2, §9.*

10. **Anchor a rate-limit window on the last *emitted* event, not on every
    suppressed one.** If every event — including the suppressed ones — reset
    the window, a continuous stream would suppress itself forever: the first
    event fires, and each subsequent event keeps the window fresh so nothing
    ever fires again. Anchoring on the emission instead gives a steady stream
    exactly one event per window, and re-notifies as soon as the stream pauses
    for a window. The copy-out notification rate limit
    (`ClipboardGate::note_copy_out`) does this; the audit log (one record per
    event, no limit) is what keeps the suppressed ones on the record.
    — *commit `3931f52` (the Phase 6 follow-up).*

11. **A daemon that serves a long-lived control channel plus many
    short-lived clients: run the control channel in the main thread and
    the client work on spawned threads — never the reverse.** The
    broker's old per-prompt design parked the *main* loop in the
    30-second consent wait, so a second pending prompt was
    structurally impossible (the accept loop never even got to run).
    The fix inverted it: the main thread owns the session decision
    socket on a `poll(2)` over both listeners (a short read timeout
    bounds a misbehaving decider), and each connection — including a
    prompt waiting for the user — parks on a per-prompt condvar in its
    own thread, so the decision wakes exactly the waiting thread.
    Keeping the decision *and* the queue removal under one lock is
    what makes a double-decide a clean `unknown-prompt` instead of a
    double resolution. — *commits `6365ae5`, `b186c13` (the session
    decision socket).*

## Writing tests

4. **Write the test, watch it fail, then fix (red → green).** Don't add a
   regression test and immediately run it green. First confirm it fails on the
   current buggy code with the *exact* expected symptom (here: the two fds
   arriving swapped — `HTML-SENTINEL` vs `PLAIN-SENTINEL`), then apply the fix
   and confirm it passes. A test that never fails proves it catches nothing.
   — *post-mortem §6–7.*

5. **Prove batching is structural, not a race, before calling a test
   "deterministic".** A test that relies on two messages landing in one
   datagram is trustworthy only if you've traced *why* they must batch: here
   `wayland-client::EventQueue::blocking_dispatch` drains all pending events
   before flushing, so two requests issued in one dispatch pass always
   coalesce into one `sendmsg`. "It ran 10/10" is not the same as "it must".
   Verify the mechanism in the library code, then trust it. — *post-mortem §3.*

6. **Reuse the existing harness; don't reinvent the scaffolding.** The
   regression test reused the existing clipboard harness (`Srv2` /
   `OfferState`) and only added a second data offer plus a client issuing two
   back-to-back `receive` calls. Leveraging proven scaffolding keeps the new
   test small, realistic, and focused on the actual defect. — *post-mortem
   §6.*

## Toolchain and scope

7. **Establish the toolchain baseline before blaming your own diff.** The 44
   `cargo fmt --check` hunks (and a couple of clippy lints) across
   `objects.rs`, `policy.rs`, `wire.rs`, and `phase0_interface_tables.rs` were
   *pre-existing* rustfmt 1.10.0 drift, not caused by the change. When a
   gate fails, determine the baseline — which files, which tool version —
   before attributing it to your edits, and fix only what is in your scope.
   (The pre-existing drift is a separate, deferred cleanup.)

8. **Keep the diff to the defect.** The fix touched exactly `forward()` in
   `src/proxy/mod.rs` and the new test — never the gate, audit, broker, or the
   wire codec, even where adjacent code looked improvable. Related defects
   found in the same review (e.g. the `start_drag` pending-latch, post-mortem
   §10) get their own `TASKS.md` entry and their own commit; they are never
   bundled into an unrelated fix.

## Gotchas

9. **Wayland macros live at `impl` level, not inside `fn event`.** Placing
   `event_created_child!` inside the body of `fn event` produces a confusing
   *runtime* panic — "Missing event_created_child specialization for event
   opcode 0 of `wl_data_device`" — deep in `wayland-client`'s event queue,
   far from the real cause. The macro must be a sibling of `fn event`, inside
   the `impl`. — *`tests/proxy_integration.rs` (Srv4).*
12. **In a mode-based binary, global clap `required*` attributes break the
    modes that don't need the argument.** `--listen` had
    `required_unless_present = "socket_activation"`, so the `--decide`
    one-shot (which never binds a socket) demanded a fake listen path.
    Keep such arguments optional at parse time and enforce presence in
    `validate()` for the specific modes that bind. — *commit `26f54c6`.*
13. **Don't re-exec a socket-activated process to "reload" it.** The
    activated fd may carry `FD_CLOEXEC` (in which case `execve` closes
    it, and the `LISTEN_*` env you restore points at a dead number), and
    where the security context is stamped *on* that very fd
    (tag-and-park), the compositor may refuse to re-stamp it. In
    `wlsctx` the SIGHUP rebuild therefore branches on how the listener
    was obtained: `--listen` re-execs in place (the freed path is
    re-bound and re-tagged); a socket-activated run exits cleanly and
    lets `Restart=always` re-pass a fresh fd. — *commits `e390b32`,
    `6923ea5`.*
14. **`CString::new` and `CString::from_vec_with_nul` have opposite
    conventions about the trailing NUL.** `new` treats a trailing NUL
    as an *interior* NUL and rejects it; `from_vec_with_nul` requires
    the last byte to already be NUL and never appends one. To convert
    NUL-free bytes (argv elements, `NAME=value` pairs for `execve`),
    append the NUL first, then call `from_vec_with_nul`. — *`src/proxy/mod.rs`
    (`osstring_bytes_to_cstring`).*
15. **A forked child must inherit no live OS threads — from any
    runtime, global *or* local.** Two hazards, both `fork(2)`-related:
    (a) `zbus::blocking` (v5) drives futures on a process-global `tokio`
    runtime in a `static OnceLock`; in a forked child the `OnceLock`
    still reports it built while its worker threads are gone, so
    `block_on` hangs forever and *silently*. (b) Even a fresh **local**
    `new_multi_thread()` runtime is unsafe here: `attach_scope` runs in
    `S` *before* the supervisor forks `A`, and dropping a multi-thread
    `Runtime` does **not** join its workers, so they linger for a few ms
    across the fork. The child inherits them and `std`'s process-global
    `thread_info` mutex (locked on every thread start by the
    stack-overflow guard) is left owned by a vanished thread, so the
    first thread the child creates deadlocks on it — the whole binary
    hangs, the forking test's `SANDBOX_LOCK` never released. The fix:
    drive the *async* API on a **current-thread** runtime (no background
    workers → nothing lingers). Rule of thumb: anything that may run in
    or near a forked child must be fork-safe — no live OS threads. —
    *the clipboard-branch merge (Phase 7); `src/systemd.rs`
    (`with_local_runtime`), `src/sandbox/mod.rs` §5.4.*

16. **Env-mutating tests must run single-threaded; a lock only
    against *other* `setenv` callers is not enough.**
    `std::env::set_var`/`remove_var` are C `setenv`/`unsetenv` and are
    undefined behaviour when *any* other thread reads the environment
    concurrently — not just another `with_env`, but plain readers like
    `temp_dir`, xdg, and clap `getenv`. The socket-activation tests
    (which must set `LISTEN_FDS`/`LISTEN_PID`/`LISTEN_FDNAMES` for
    sd-notify to see) race such readers under a parallel run: the two
    separate `env::var` reads inside sd-notify catch a corrupted env
    block between them and mis-report a fd-name count mismatch, so
    `listen_fds_with_names_and_unset_env()` returns `Err` and one test
    fails at random. `ENV_LOCK` serialises `with_env` against itself but
    cannot stop unrelated readers. The fix is `cargo test --
    --test-threads=1` (wired into CI): it costs ~nothing, since the
    suite is dominated by the `SANDBOX_LOCK`-serialised sandbox tests.

17. **A queue filled by concurrent threads is ordered by a sequence
    stamped at the sequential entry point, never by lock order.**
    The broker's prompts were registered by per-connection threads
    (`add_prompt` hands out ids under the queue lock), so *which*
    thread grabbed the lock first decided the order — not which
    connection arrived first — and the
    `multi_prompt_session_is_listed_and_decided` integration test
    flaked whenever the second app's thread won the race. Fixed by
    stamping each connection with a monotonic sequence in the
    broker's `poll(2)` accept loop (the only sequential point) and
    ordering the queue by `(seq, id)`; ids stay unique (so two
    prompts from one connection cannot collide in the order), and
    both the listing and the untargeted decide derive from the
    sequence. Pre-existing from the clipboard branch; its
    integration tests build the queue directly, so nothing exercised
    the thread-race path until the desktop e2e found the sibling
    allowlist bug and the flake was re-run.

18. **When a spawner passes an fd to a child, the argv is half the
    contract — and its absence fails silently.** Phase 7.2's
    socketpair rewrite handed `xdg-dbus-proxy` its lifetime fd on fd 3
    but dropped the *`--fd=3` flag* from the argv: the proxy (told
    nothing) never wrote its sync byte, so the sidecar parked forever
    in its one-byte readiness `read`, and a SIGKILL'd sidecar left the
    proxy alive. Nothing in GLib or the kernel was wrong — the bug was
    invisible in every "it works" smoke test except the SIGKILL one.
    Two tools found it fast: `gdb`-dumping the child's *ppoll
    arguments* (fd 3 absent from the array in the broken run,
    present — with `events=0` — in a control run) and an
    `LD_PRELOAD` ppoll tracer. Related, verified on GLib 2.90: that
    `g_io_add_watch(G_IO_ERR|G_IO_HUP)` is polled with *zero*
    requested events (GLib masks those bits out — an IRIX-era
    workaround) and fires only because the kernel reports `POLLHUP` in
    `revents` even when unrequested; and the fd must be **non**-CLOEXEC
    to survive `execve` (it *closes* CLOEXEC descriptors — the inverse
    of the reflex).

19. **The `-listenfd` contract: the *spawner* must `listen(2)` before the
    handoff.** Xwayland's `-listenfd` path (libXtrans `SocketReopen`)
    adopts the given fd *as-is* and never calls `listen` itself — only
    the create-from-scratch path (`SocketUNIXCreate`) does. Hand over
    an unlistened socket and the server's `accept(2)` fails `EINVAL`
    on every readiness wake: an infinite `accept() failed` flood at
    100% CPU (it also filled our `/tmp` quota with its stderr). sway's
    own spawn is the model: it `listen`s first. The bug was invisible
    in every "it starts" smoke test; an `LD_PRELOAD` `accept` tracer
    (fd number + errno, count-capped) pinned it to fd 4 / `EINVAL` in
    one run.

20. **The kernel clears `PR_SET_PDEATHSIG` on any exec that changes
    the process's *security credentials* — not just setuid, and not
    just `AT_SECURE`.** On this (SELinux-enforcing) machine `Xwayland`
    execs into the `xserver_t` domain; the transition changes
    `cred->security` and the kernel's
    `security_bprm_committing_creds` clears the death signal — while
    `AT_SECURE` stays *unset* (absent from the auxv), so glibc still
    honors `LD_PRELOAD` there. The fix: a 3-line `LD_PRELOAD` shim
    (compiled on demand into the per-instance runtime dir) whose
    constructor re-sets `PR_SET_PDEATHSIG(SIGTERM)` *after* the
    transition — verified: a SIGKILL'd satellite's Xwayland now dies.
    The re-set is a harmless no-op where nothing was cleared. Related
    findings from the same investigation: Xwayland's `-once` flag is
    *XDMCP-session* semantics (terminate on XDMCP retransmission
    timeout) and a no-op for a non-XDMCP rootless Xwayland — it does
    **not** exit when the last X client disconnects; and given
    `-listenfd`, Xwayland does **not** create the conventional
    `/tmp/.X11-unix/X<N>` (the live `X0` on this host was a stale
    leftover of a dead instance, not sway's bind). — *the Phase 7.3
    verification; `src/xwayland.rs` (`ensure_shim`), decision #37.*
21. **checkpolicy 3.11 (Fedora 45 "userspace 3.11"): module compilation is `checkmodule`, not `checkpolicy`** (which builds the base policy; its `-c` takes a *version number*, not a policy.conf file). A module `.te` must start with `module <name> <ver>;` and carry a `require { ... }` block — both hard errors without them; `require` takes one identifier per `type` line and classes with the used permissions in braces; the module policy version tops out at 24 (just omit `-c`); and base *type attributes* referenced in rules (e.g. `file_type`) are re-declared in the module and merge by name at load. — *the phase 8.2 module; `selinux/`.*
22. **Build a capability set against paths that exist *where the set is built*.** S (on the host) builds the supervisor's `CapabilitySet` against the *in-sandbox* instance-dir path (`/run/user/<uid>/wlsctx/<inst>`, decision #28) so it can match the paths the app presents to its trapped syscalls — but nono's `allow_path` validates existence at build time, and that path exists on the host only when the session XDG *is* `/run/user/<uid>`. With a divergent XDG (e.g. a test harness redirecting `XDG_RUNTIME_DIR` to a temp dir) S's build fails, the supervisor disables itself *silently*, and every syscall B's filter traps — including the dynamic loader's `openat` — dies with ENOSYS (the closed listener's default reply). The Phase 8.4 suite pins the standard-XDG topology and skips otherwise; making the divergent-XDG case work (build against the host path, translate at match time) is a product change, not a test one. — *`tests/sandbox_integration.rs` (`session_xdg`), decision #28.*
23. **Podman is not one SELinux domain — it is two, and they map onto wlsctx's two sides.** `crun` is labeled `container_runtime_exec_t` and execs (from `unconfined_t`) into `container_runtime_t`; the in-container payload is `container_t`, reached by *setexecfilecon* (the policy allows `process { dyntransition transition }` from `unconfined_domain_type` to `container_domain` — there is **no** file `type_transition` into `container_t` anywhere). The permissive probe (2026-10-28) ran wlsctx in both: the S/A runtime side as `container_runtime_t` produced **zero genuine denials** (the rootfs-rebuild `mounton`s over host dirs, fresh `/dev`+`/proc` mounts, cgroup scope create/enter, session-bus dbus, the transient-scope `system:start` — all covered, because crun does exactly this work), including the full `--proxy` chain into live sway; the app side as `container_t` also ran clean. Two durable facts: (a) wlsctx's rebuilt rootfs gets `container_file_t` for free — the fresh `seclabel` tmpfs mounts inherit the mounting process' exec label (podman's own rootfs mechanism), so an app tree running in a container-domain type needs almost no policy; (b) the in-sandbox EACCESes on unix-socket `bind` and cgroup writes are nono's (landlock/seccomp), not SELinux — identical in unconfined runs, no `avc` logged for them. The one real policy lever for a `container_t`-family wlsctx: `container_manage_cgroup` (off by default) gates the cgroup-scope writes; the rest of the runtime side is bool-free. — *the container-selinux probe (permissive); PLAN.md 8.2, `selinux/`.*
