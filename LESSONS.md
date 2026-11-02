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
24. **`semodule -i file.cil` *is* a valid install path on this toolchain (Fedora 45, policycoreutils 3.11) — the CIL reader lives in libsepol, not in the checkpolicy CLI.** Verified with a test `.cil`: it installed, committed, and its rules appear in the live policy (libsemanage calls libsepol's `cil_db_init`/`cil_add_file`). The earlier "no CIL path" conclusion tested the wrong tool: the checkpolicy binary has no CIL input mode in this build (a `.cil` fed to it parses as policy.conf and fails; even the live policy needs `-b`, plus `-M` since it is MLS). So install can be a plain `sudo semodule -i wlsctx.cil` — no checkmodule, no semodule_package — with `.te` → checkmodule → `semodule -i .pp` as the classic alternative; the CIL path resolves against the *live* policy's class tables, the same tables the kernel enforces (see #26 for what that catches). Meta-lesson: verify against the actual tool on the machine, not the upstream source tree. Two probe-fed gotchas stand: (a) `mounton` is checked on *file* objects for bind-mounts (fresh-/dev node builds); it is a member of the policy's `file` *common* set (the module's `require` block lists it on `file` explicitly, which is legal — checkpolicy's table has it), so it works in both install paths; (b) on Fedora 45 the *user* session bus is dbus-broker as `unconfined_dbusd_t` with `/run/user/<uid>/bus` labeled `session_dbusd_tmp_t` — not the classic `session_dbusd_t` the stock `dbus_session_bus_client` inlines. — *the CIL verification + module rework; `selinux/`.*
25. **The 3.11 module store is CIL-based, so the CIL reader is the universal install gatekeeper — and it validates against the *live* policy, not checkpolicy's tables.** Every `semodule -i` (even a `.pp`) converts to CIL at commit time and re-parses it with libsepol's CIL reader (`kernel_to_cil.c` → `cil_add_file`/`cil_compile`/`cil_build_policydb`), so the reader's strictness sets the bar for *all* installs: (a) a CIL file has **no** `(module …)` header — that is a checkpolicy *output* convention, not CIL; the reader rejects it (`Unknown keyword module`); bare `(type …)`/`(allow …)`/`(typeattributeset …)` statements are the format (`audit2allow -C` output is exactly that). (b) the resolver validates **every** symbol against the live policy: `require`/`typeattributeset` members must exist (Fedora 45: `cache_home_t` not `user_cache_t`, `unconfined_dbusd_t` not `session_dbusd_t`), and **every (class, permission) pair must exist in the live class table** (class-specific ∪ its `common`) — so permissions that *compile* under checkmodule can still fail at install: `setsockopt` (the policy's socket common is `getopt`/`setopt`) and `node:name_bind` (the policy's `node` class is only the network set — port-bind checks land on the socket classes' `name_bind`). The table to check against: the live dump `checkpolicy -b -M -C /sys/fs/selinux/policy` (the `(class …)` lines are class-specific, `(classcommon …)`/`(common …)` give the rest) or the policy source's `policy/flask/access_vectors`. (c) the `.pp`→CIL store writer serializes an *unresolved* `gen_context(...)` filecon verbatim (the classic linker resolves it via `filecon_expand_context`; the writer skips that) → "Bad filecon declaration" at commit. Three fixes, in preference order: (i) **embed the file context in the module CIL** — the 3.11 store's CIL *reader* handles `(filecon …)` natively: libsemanage calls `cil_filecons_to_string` after `cil_compile` and writes the result into the policy's `file_contexts` (`libsemanage/src/direct_api.c`), and `semodule export` re-emits exactly these statements (byte-for-byte `(filecon "PATH" file (user role type ((s0) (s0))))`), so the format round-trips. `build.sh` appends the statements from `wlsctx.filecon.cil` to the `checkmodule -C` output, so `semodule -i build/wlsctx.cil` is the whole one-command install, with the label removed again by `semodule -r`. Two gotchas: this libsepol CIL lexer has **no comment rule** (`{comment}` is empty, `#` is a symbol char) — `build.sh` greps the `(filecon …)` lines out of the source file rather than appending it verbatim; and the file stays plain `s0`, because the per-instance MCS category is applied to the *process* (the self-narrowing re-exec), never to the file. (ii) **colon-form** `.fc` (`wlsctx.fc.resolved`) packaged into `wlsctx.fcresolved.pp` survives the `.pp`→CIL conversion, so `semodule -i` installs rules + file context in one command — the fallback. (iii) pure `.cil` for the rules plus the label added **per-record** with `semanage fcontext -a -t TYPE -f f -r RANGE -s SEUSER <path>` — note `semanage fcontext` takes per-record flags and a path, it does *not* read a `.fc` file (that's `semodule_package -f` / `checkpolicy`'s `.fc` parser, which do handle `gen_context`); a `semanage fcontext` record is a *local customization* stored apart from the module. — *the CIL install debug; `selinux/`.*
26. **`/proc/self/attr/exec` is consumed by the next exec, so a "preserve state across re-exec" helper must not clobber a pending write.** The MCS self-narrowing writes the exec context and then re-execs through a shared re-exec helper; that helper's own range-preservation write (re-writing the *current* label) would have silently overwritten the just-written target context, sending the process back to `s0` and re-narrowing — an infinite loop. The fix reads the exec attribute first and skips when an explicit context is already pending (`mcs::preserve_range`). Related mechanics: setting the exec context to the *same type* (only the range changes) still needs `dyntransition` on the (type, type) pair — for self-narrowing that is the *self* allow, easy to miss; and a range is carried by fork into children (a process takes its creator's *full* range), so narrowing once before the first fork/bind is all it takes for the *process* side — but note new *objects* do **not** carry the creator's range; they take the parent's low level (`s0`) via `default_range … target low` (see #29). — *the MCS wiring; `src/mcs.rs`.*
27. **`checkmodule -C` (3.11) writes `typetransition` with the raw `.te` class — and the kernel's bprm lookup consumes only `process`.** The classic checkpolicy pipeline turns `type_transition src filetype:file target` into *both* a file-class and a process-class avtab entry (the file/process transition duality); `checkmodule -C` writes only the literal class from the source, so its `(typetransition unconfined_t wlsctx_exec_t file wlsctx_t)` compiled and installed fine but never fired — no AVC, no error, the process just kept the parent type. The kernel's bprm transition lookup keys on class `process`. Fix: hand-written CIL spelling `(typetransition src type process target)`. Recognize it by the symptom: a module that installs, the file relabels correctly (`restorecon` works, the binary carries the exec type), yet the process never changes type. — *the transition-not-firing debug; `selinux/wlsctx.cil`.*
28. **A process context is *valid* only when its role is associated with its type — and `setprocattr` enforces that with a silent `EINVAL`.** `context_is_valid` (libsepol/src/context.c) checks role→type (ebitmap), user→role, and the range inside the user's exp-range; the `/proc/self/attr/exec` write rejects an invalid context with EINVAL — *not* an AVC (a validity check, not an access check). A new module type gets only `(roletype object_r TYPE)` from the classic pipeline, but a shell-spawned process inherits `unconfined_r`, so `unconfined_u:unconfined_r:wlsctx_t:…` was invalid: the MCS narrowing write failed, wlsctx degraded to a full-range run, and `audit2allow -C` rejected every record in those contexts ("invalid security context" ×500) — a denial log that could not even be machine-read. Fix: `(roletype unconfined_r wlsctx_t)` / `(… wlsctx_app_t)` — the container-selinux convention (associate the *spawner's* role: `system_r` for daemons, `unconfined_r` for shell children). Fast oracle before wiring such a mechanism: `runcon user:role:type:level /bin/true`. Second half of the same lesson: adding the types to the base `mcs_constrained_type` attribute is what makes MCS categories *bind* — the base mlsconstrain (`h1 dom h2 or t1 != mcs_constrained_type`) blocks **processes** across categories (a `cN` subject may signal/ptrace/transition only a `cN` process — a single category is incomparable with any other), but it does **not** isolate *files/dirs* across instances, because those objects are all created at `s0` (see #29) and any `cN` dominates plain `s0`, so every wlsctx subject may access them; the socket/`fd` classes are not constrained at all, so a shared daemon still serves per-category clients. — *the MCS no-narrowing debug; `selinux/wlsctx.cil`, `src/mcs.rs`.*

29. **New objects take the *parent's* low level, not the creator's range — so under an `s0` parent, files/dirs/sockets are always `s0`, and there is *no* cross-instance object isolation via MCS.** The live targeted policy sets `default_range dir target low`, `default_range file target low` and `default_range sock_file target low`; in the kernel's `mls_compute_sid` (`security/selinux/ss/mls.c`) the `AVTAB_TRANSITION` path for those classes hits `DEFAULT_TARGET_LOW` → `mls_context_cpy_low(newcontext, tcontext)`, so a fresh object copies the **parent directory's** low level, not the creating process's range. Only classes with *no* `default_range` (process, `unix_stream_socket`, …) fall through to `AVTAB_CHANGE`, where a process/socket gets the creator's **full** range (`mls_context_cpy`) and other classes get its low. Consequence for wlsctx: `/run/user/<uid>` is `s0`, so everything an instance creates beneath it — the instance dir, the build scratch, the per-instance sockets — is `s0` regardless of the creator's `cN`; any `cN` subject dominates plain `s0` (`h1 dom h2` passes), so *every* instance and the `s0` broker may read and write any of them. There is **no** file/dir-level isolation between instances, and the earlier "the first creator pins the session dir to `cN`" caveat was built on the false premise that objects carry the creator's range: the session dir is always `s0`, there is no race to win and no pre-creating needed. What the MCS layer *does* isolate is the **process** level (a process keeps its `cN`; the base mlsconstrain lets only a same-`cN` subject signal/ptrace/transition it — a single category is incomparable with another, which is *stronger* than podman's `cNNN,cMMM` multi-category model); object separation comes from the namespaces + landlock rootfs, not SELinux. The enforcing-mode tuning loop is still the oracle for *allow* gaps; a record that fails an MLS *constrain* (as opposed to a plain allow) carries `mls=1`. — *the default_range investigation; `src/mcs.rs`, `selinux/README.md`, kernel `security/selinux/ss/mls.c`.*

30. **The kernel NUL-terminates the selinuxfs attr strings, and `str::trim` will not strip that — a string-equality re-exec guard read from `/proc/self/attr/current` becomes an infinite loop.** `read_to_string` returns `user:role:type:range\0`; `trim` only strips Unicode whitespace, so the parsed range came back as `s0\0` (later `s0:cN\0`), the `range == target` loop guard in the one-time self re-exec never matched, and wlsctx re-execed itself ~260k times in a single strace session (it "worked" — each re-exec re-narrowed — but never settled). Fix: truncate at the first NUL before parsing (`mcs::parse_label`). A second, related canonical-form trap in the same guard: `mls_sid_to_context` *collapses a low==high range to a single level*, so a narrowed `s0-s0:cN` reads back as `s0:cN` — the guard's target must be written in that single-level form or it never matches either. Two different causes, one symptom (a MCS re-exec that never terminates); the strace line count is the detector. — *the 260k-execve incident; `src/mcs.rs`.*

31. **`std::fs::write` on `/proc/self/attr/exec` carries `O_CREAT`, and on a fresh in-sandbox procfs that first open runs a `may_o_create` probe that SELinux answers with an `add_name` denial on the `attr/` directory.** `std::fs::write` opens `O_CREAT|O_TRUNC`; on a just-mounted procfs `attr/exec` resolves as a first-open race (negative dentry), so `lookup_open` runs `may_o_create` (namei.c) — `inode_permission(MAY_WRITE|MAY_EXEC)` on the parent `attr/` dir plus `security_path_mknod` → `may_create` (`DIR__ADD_NAME|DIR__SEARCH`, `FILE__CREATE`, `FILESYSTEM__ASSOCIATE`). Non-fatal (the kernel clears `O_CREAT` and re-resolves, the open still succeeds) but it logs a denial every run — and granting the full chain does *not* make it work, because the open then proceeds to `i_op->create`, which the procfs attr dir has no handler for (`-EACCES`). The real fix is to not ask to create: `OpenOptions::write(true).truncate(true)` (no `O_CREAT`) hits only the file's own permissions, which the module grants. — *the attr/exec O_CREAT probe; `src/mcs.rs`, `selinux/wlsctx.cil`.*

32. **A confined app that runs shell *pipelines* needs a *self*-`fifo_file` rule — intra-app pipes carry the creator's type, so they are the app's own context, not `unconfined_t`'s.** `sh -c 'a | b'` creates a pipe; the fifo is labeled with the creating process's type (`wlsctx_app_t`), so the pipeline's `fstat` (sh → `getattr`), write (`a`), and read (`b`) are all `wlsctx_app_t → wlsctx_app_t fifo_file` checks. Granting only the *external* pipe rule (`wlsctx_app_t unconfined_t fifo_file`, the host shell's pipes handed across exec) left every intra-app pipeline `EACCES`-denied — the "echo + cat + ls" test never exercised a pipe, so the gap was invisible until a `cat … | head` run logged four self-fifo denials. Fix: `(allow wlsctx_app_t wlsctx_app_t (fifo_file (read write getattr)))`, mirroring the `wlsctx_t` self-fifo rule. General form: any per-type self-object rule set (the app's own dirs/files/sockets) must be checked against the *app* type, not just the host type, or the app's internal IPC silently fails. — *the intra-app pipe gap; `selinux/wlsctx.cil`.*

33. **`signull` (kill 0) is a process permission this kernel's base policy does *not* mlsconstrain — and a module CIL can't add one, so the gap can't be closed at the module level.** The process class splits the classic `signal` into `signull` (kill 0), `sigkill` and `signal`; the base targeted mlsconstrain constrains `ptrace`/`signal`/`sigkill`/`sigstop`/`transition`/`dyntransition` — but **not** `signull`. So a `signull` *allow* grant is unconstrained by MCS: any `cN` wlsctx subject may kill -0 any wlsctx process, including another instance's `cM` (no `h1 dom h2` gate on that permission). It can't be fixed in the module: libsepol's CIL reader rejects `mlsconstrain` in a module CIL (`"Bad constrain declaration"` at `semodule -i`), and a module can only add *type-based* `constrain` (no range/level terms) — so the base `h1 dom h2` expression cannot be mirrored for it. The `signull` grant is needed anyway for `terminate_app`'s kill -0 liveness probe (`wlsctx_t → wlsctx_app_t`) and strace-style tools; the cost is that the probe is not category-scoped. Practical impact is minimal (kill -0 only reveals existence/permission, which `/proc` already does) — a documented limitation, not a fix. Detecting it: a kill -0 you expected to be category-scoped succeeds *across* instances, and the audit shows **no** denial (there is no constraint to fail) — unlike `signal`/`sigkill`, which *are* constrained and log `mls=1` on a cross-category attempt. — *the signull investigation; `selinux/wlsctx.cil`, `src/sandbox/mod.rs` (`terminate_app`).*

34. **A `stat`-based existence check conflates *absent* with *inaccessible* — and `Path::is_file()` is exactly that check, so a SELinux denial on the stat silently degrades the profile lookup.** `profile::load` gates on `Path::is_file()` (a `stat`/`metadata` call) before reading `~/.config/wlsctx/apps/<app-id>.toml`, and falls back to the builtin/ad-hoc profile when it is false. Under SELinux a *denied* `getattr` on the file — or `search` on any ancestor (the confined `wlsctx_t` reader needs `user_home_t`/`config_home_t` `dir search` plus `config_home_t file (getattr open read)`) — makes `is_file()` return false *exactly the same way* as the file genuinely not existing. The fallback is **silent** (no error, no warning), so the visible effect is a sandbox that runs with the *wrong effective configuration*: the user's `gpu = false` and its `XDG_RUNTIME_DIR`/`WAYLAND_DISPLAY` env never apply, the session env leaks into the app, and nothing in the logs points at the cause. Detection: the app *works* but its effective config disagrees with the profile file; the discriminator is `ausearch` for denials against the profile path (they look like ordinary file denials — nothing marks them as hitting an existence probe) or, if you suspect this class, `stat`-ing the same path from the same confined context. Defense: distinguish `NotFound` from every other `metadata` error (fail or at least warn on the rest), and grant the confined reader the full read chain up to the file. — *the profile-not-applied debug; `src/profile/mod.rs`, `selinux/wlsctx.cil`.*

35. **Partial or *wrong-object* grants silently degrade: the permission check can pass everywhere you look while the consumer still loses the capability — a symlink carries the label of the fs it sits on, and `open` is not `read` on a directory.** Two instances from the enforcing-mode tuning, one general class: *the audit records the denials you fix, but the failure is only visible in the consumer's behavior, and the record points at the wrong object.* (a) **The fresh-tmpfs symlink label trap:** the sandbox's `/dev/ptmx` is a relative symlink into the fresh devpts instance (devtmpfs style, step 5 of the rootfs build); the symlink is *on* the fresh tmpfs `/dev`, so it carries the tmpfs's **default** label (`tmpfs_t`), not the `ptmx_t` of what it points at. Following it is `lnk_file:read` against `tmpfs_t` — grants on the target type do nothing until the symlink's *own* type is granted. (b) **`open` vs `read` on a directory:** fontconfig `open()`s each font directory before `getdents`-ing it; `open` and `read` are *separate* permissions of the `dir` class, so a `read`-only grant passes the permission check for the enumeration while the `open(2)` itself is still denied — the directory is never enumerated and the app silently renders without the user's fonts. In both, the audit line is an ordinary denial against an unremarkable object (a `tmpfs_t` lnk_file / a `user_fonts_t` dir) — the `tclass`/`ttype` in the record is the *carrier*, not the capability you were chasing. The discriminating test is always the consumer actually doing the op (the pty opens, the fonts enumerate), not the absence of denials. — *the enforcing-mode pty+font debug; `selinux/wlsctx.cil`, `src/sandbox/mounts.rs`.*

36. **SCM_RIGHTS receive is a *separate* MAC check that runs against the *receiving* process — twice, against two different labels — and a denial drops the fd silently (only `MSG_CTRUNC` flags it), so a relay needs receive-side grants on *both* ends and must check the truncation flag at the point of loss.** The kernel's `security_file_receive` → `__file_has_perm` (`security/selinux/hooks.c`) checks the **receiver** (not the sender) when a file descriptor is delivered over SCM_RIGHTS: first `fd:use` against the file object's SID — for a `memfd_create`'d file that is the **creator's** SID (the app's `wlsctx_app_t`), *not* any filesystem label — and then the file permissions implied by the fd's `f_mode` against the **inode's label**, which for an anonymous inode of a fresh tmpfs is the mount's default (`tmpfs_t`, since `memfd_class=0` — the fs default, again not the creator's type). Both checks must pass, and a failure in either drops the fd from the received cmsg while the message **bytes** arrive intact — silent data loss, `MSG_CTRUNC` the only signal. Consequences. (a) *The grant set must cover every process the relay touches, each against the label the fd carries:* the relay (`wlsctx_t`) receiving the app's wl_shm pixel pool needs `wlsctx_app_t fd:use` **and** `tmpfs_t file (read write)`; the **compositor** (`unconfined_t`) receiving that same pool *forwarded* by the relay is checked too — the forwarder is also a receiver — so `unconfined_t wlsctx_app_t fd:use` is mandatory (the base policy already covers `unconfined_t → tmpfs_t` file read/write, which is why only the app type was new to policy); the reverse direction (the compositor's XKB keymap file — a `/dev/shm` file of an unconfined creator, so `user_tmp_t` — coming down to the relay, and the relay's copy on to the app) needs `fd:use` on `user_tmp_t` for *both* the relay and the app. (b) *The code must fail at the point of loss:* without a check, the relay fails one parse later with a misleading "message references a fd that has not arrived" (`MissingFd`) — the loss point and the failure point are far apart. `ProxySocket::recv` now checks `ReturnFlags::CTRUNC` after every `recvmsg` and errors with the actual cause, and the `MissingFd` error names the message + fd counts, so this whole class is diagnosable from the log. — *the enforcing-mode relay fd debug; `selinux/wlsctx.cil`, `src/proxy/mod.rs`, kernel `security/selinux/hooks.c`.*

37. **A reaper that must live must never die on an interrupt — and supervision that lives only inside a process orphans everything when that process dies.** Two holes, one incident (run #1: S died silently mid-run, A died shortly after, and the app's pidns — B is its PID 1, decision #13: immune to default-action signals from outside the namespace — ran on forever; the only trace was the sub-cgroup `rmdir` failing `ENOTEMPTY`). (a) `EINTR` was fatal in both reapers' blocking `waitpid`s (S's via `?`, A's via a 126 exit). Both reapers block *exactly* the three signals they forward (the signalfd is their sole consumer); every other signal is at its default disposition and reaches them *delivered* — a terminal session's TSTP/TTIN/TTOU, a SIGCHLD, a segfault — and a delivered signal interrupts a blocking `wait4`. A dead A reaps nothing (B reparents to the host init); a dead S takes the forwarder thread — and with it the 2 s KILL escalation, the only thing keeping B finite. On 7.2.11 the empirically reachable set is narrow (a STOP→CONT cycle restarts the wait; a manually sent SIGCHLD is consumed by the wait itself), but the principle is universal: retry `EINTR` in a wait that has to live. (b) There was no backstop for *any* S exit with the app alive — an error `?`, a panic, a dead A reaped by S: the supervision died, but B (the pidns init) and its descendants kept living — and any trapped syscall of theirs would stall anyway, because their seccomp filter has no supervisor left to answer it. The `AppKillGuard` is armed the moment the handoff completes and dropped at the end of the run; its `Drop` reads the instance sub-cgroup's `cgroup.procs` — recursive on cgroup2: A moved in before the unshare (decision #20) and B entered with it, so the list is A + B + every descendant — and SIGKILLs whatever is still there. It does *not* rely on the kernel's zap of a dying pidns init (decision #14: on 7.2.11 strays reparent and survive); on the normal path it is an empty no-op, and it fires — loudly — only when it finds a live process, i.e. exactly the incident. Field-verified by SIGKILL-ing A: the old code orphans (B+child immortal), the new code leaves no process. **Remaining boundary:** a default-terminate signal *to S itself* (SIGKILL, a segfault, …) kills the guard with it — `Drop` runs only on unwinding exits, not on a fatal-signal death — and A and B survive; that is the actual run-#1 shape, and it needs the kernel-level `PR_SET_PDEATHSIG` cascade (A←S — A never execs; B←A — B execs into `wlsctx_app_t`, a credential change, so the kernel clears the pdeathsig and the decision-#37 `LD_PRELOAD` restore shim is needed). — *the run-#1 orphan; `src/sandbox/mod.rs` (`waitpid_retry`, `AppKillGuard`), decisions #13/#14/#41.*

38. **Test tooling can outlive the session that spawned it — and leave *input* state behind.** Two orphans of the previous session's violent teardown, both invisible to normal triage. (a) **The ydotool wedge:** the input-e2e client was killed mid-sequence (a press without its release); the *daemon* (root, nohup'd) survived holding the key pressed, and a pressed key on a wlroots keyboard is auto-repeated by the compositor (sway: 600 ms delay, 25 Hz) — so the user's real terminal behaved as if [enter] were broken (phantom Enters flooding the shell; typed commands sent early, the rest mis-parsed). The stuck state lives in the *virtual* device's per-keyboard state, so the fix is to destroy the device — kill/restart the daemon — not to poke the physical one; a release-only injection (`28:0`) clears it too. A daemon that can inject state into a shared system (input, clipboard, compositor) must be torn down with the test that drives it. (b) **The EOF spin:** a `python3 -` test helper (program from a pipe, IPC over a socketpair) whose coordinator died kept its `while not data: data = sock.recv()` loop — which then got EOF (0 bytes) on every call and "retried": 176k `recvfrom`/2 s, one core at 100% for 3.5 h. `recv() == 0` is the *closed* state, not "empty, try again"; any wait-loop that treats it as retryable never terminates. — *the post-restart incident (2026-10-30); ydotoold, `swaymsg -t get_inputs`.*

39. **Never run a probe that unshares a PID namespace and signals by numeric PID from inside a live desktop session — and never one without `kill()` auditing.** The pdeathsig probe (2026-10-31, session 176) was a C program run via the agent's `bash -c` inside the `foot` scope's cgroup that `fork`/`unshare(CLONE_NEWPID)`/`fork`'d an S→A→B shape and then called `kill(1, …)` from A and `kill(a, SIGKILL)` from S. The same second (09:01:55) the session's own `systemd` — the main process of `user@1000.service` — was SIGKILL'd, so systemd tore down the **entire** session (sway, every terminal, the agent); the user was left at the greeter until they rebooted. Three lessons. (a) **The obvious failure model is wrong, and that is exactly what made it feel low-risk.** The unsharing process A is a *stray*: `unshare(CLONE_NEWPID)` changes only `pid_for_children`, "not the PID namespace of the calling process … because doing so would change the caller's idea of its own PID" (pid_namespaces(7)); so A's `kill(1, …)` operates "using the process ID that is visible in the PID namespace of the caller" — the **host** namespace — i.e. the system **init**, which is un-killable from userspace. The `kill(1)`s were **no-ops**; the death did *not* come from "I signalled PID 1." (b) **The real hazard is that a freshly created pidns inside a session cgroup interacts with systemd's session machinery in a way you cannot safely reason about, and when it misfires it takes the session's *manager* with it** — `user@…` systemd is the process systemd watches as the session main process, and killing it makes logind/sddm cascade into a full teardown. The exact signal path was not recoverable: `auditd` had **no** `kill()`/`tgkill` rule active, so the journal shows only the cascade (`user@1000.service: Main process exited, code=killed, status=9/KILL` → `Session crashed (killed by signal 9)`) and never the sender. (c) **Isolate and audit before you probe.** Run pidns/signal experiments in a context you can afford to lose (a dedicated VM, or a throwaway seat — a re-runnable desktop, not *the* desktop), and arm a `kill()`/`tgkill()` audit rule *beforehand* (`auditctl -a always,exit -F arch=b64 -S kill,tgkill -k pdeath`; read it back with `ausearch -k pdeath`) so the sender is recoverable. In-repo, the pdeathsig cascade is verified through **wlsctx's own** S→A→B pipeline (`run` — supervised, private rootfs, its own cgroup, no raw PID signalling), which has run in-session many times without incident; the unsafe thing is a hand-rolled raw probe in the live desktop. — *the 2026-10-31 desktop-kill; pid_namespaces(7); the pdeathsig cascade (decision #42).*

40. **On 7.2, `PR_SET_PDEATHSIG` is neither inherited nor stable across exec — `fork` *resets* it to 0, `execve` clears it when `bprm->secureexec` is set, and a SELinux *domain transition* sets that bit (the default-denied `noatsecure` check) even at the same uid.** Verified against `v7.2.11` (`~/src/linux`), which also corrects an earlier wrong assumption in this codebase: a same-uid SELinux exec that *changes the domain* (`wlsctx_t` → `wlsctx_app_t`, the confined run) lands in the SID-change branch of `selinux_bprm_committing_creds` (`security/selinux/hooks.c`), where `bprm->secureexec |= !!avc_has_perm(…, PROCESS__NOATSECURE, …)` — the permission is denied by default, so `secureexec` is set and `fs/exec.c` zeroes `pdeath_signal` on the exec. Only a *same-domain* exec (the unconfined run) sets none of the clearing conditions (`secureexec`, the `commit_creds` uid/gid/caps check in `kernel/cred.c`), and the pre-exec belt survives. Consequences, all now encoded in `src/pdeathsig.rs`: (a) every link of a cascade must set its own value *after its own fork* — the value is not inherited (`kernel/fork.c`: `p->pdeath_signal = 0` unconditionally); (b) a process that execs into a different SELinux domain needs the post-exec `LD_PRELOAD` shim to re-arm the signal (decision #42's B←A link, decision #37's satellite) — belt (pre-exec set) and bridle (shim) are both load-bearing, not belt-and-bridle; (c) a signal the process will have *blocked* at delivery time never fires (it stays pending), so a pdeathsig must be one the receiver handles, not one it blocks (A keeps TERM/INT/HUP blocked, hence `SIGUSR1` for A's link). API drift: `PR_GET_PDEATHSIG` writes the value to the pointer in `arg2` and returns 0/`-EFAULT` (`kernel/sys.c`) — the ≤ 6.x convention of returning the value is gone, so a "read it back" test must check the output parameter, not the return. — *the decision-#42 implementation; `src/pdeathsig.rs`, `src/sandbox/mod.rs`, `src/xwayland.rs`.*
