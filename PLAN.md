# wlsctx rework: in-process sandboxing, no containers

Status: **v2.12 — Phase 7.3 is done (2026-10-24): `wlsctx xwayland` — the host-side per-instance Xwayland satellite (sway's spawn pattern: sidecar-created+listened `-listenfd` socket in the per-instance runtime dir, `-displayfd` readiness gate with display-number cross-check, `-auth`, `-nolisten tcp`, `-rootless`). Verified end-to-end (a real X11 client connects to the instance socket) and on both teardown paths (SIGTERM; SIGKILL with the SELinux-pdeathsig restore shim — decision #37). (Previous: v2.11 — Phase 7.2 is done (2026-10-24): `wlsctx dbus-proxy` — the host-side per-instance `xdg-dbus-proxy` sidecar (direct spawn, not a unit; public `bus.sock` in the per-instance runtime dir, owner-only; see/talk/own/call/broadcast rules forwarded verbatim, fail-closed once any is present). The child's lifetime is a *fd*: a private socketpair handed over as `--fd=3` (non-CLOEXEC — `execve` closes CLOEXEC), so even a SIGKILL'd sidecar tears the proxy down (decision #36); verified pass-through + SIGTERM + SIGKILL teardown. (Previous: v2.10 — for the in-process architecture (8.1, 2026-10-24): the S→A→B pipeline, the rebuilt rootfs, the nono policy, the relay/broker/decider, the layered containment table, install/profiles/the per-app relay recipe, verify-your-setup, and the residual-risk list. The zbus 6 migration (`6725560`) landed with it. Phase 5.5 is done (2026-10-24): Firefox ran through the full S→A→B pipeline on this desktop — the window reached the compositor, network egress worked, and a SIGTERM tore it down cleanly; it also confirmed decision #32 (the supervisor services *every* trapped notification, so multi-process apps that inherit the filter don't deadlock). The code-quality sweep is done (2026-10-24): rustfmt/clippy/check clean, the dead `security_context.rs` module removed, the broker's public API tightened, the container-era test fixtures and `Mode A/B` / quadlet comments purged, and the unsafe surface audited (all ownership transfers and the one `transmute` are SAFETY-documented; 192 tests green). The optional 7.3 xwayland satellite and Phase 8's 8.2 and 8.4–8.5 (the SELinux policy, the integration test suite, the threat-model review) remain, plus the full chain (a sandboxed app through the proxy into sway) and the drag-and-drop audit (6.5.5))**

The podman/quadlet layer is deleted (`0c842cf`); the remaining
container-era artifacts (`docker-bake.hcl`, `systemd/`, `selinux/`) are
deleted in the same rework. Containment moves into the `wlsctx` binary
itself: it becomes a CLI tool that, per app, creates Linux namespaces,
builds a private rootfs, applies landlock + seccomp via the
[`nono`](https://docs.rs/nono) library, and `exec()`s the app — with
`wlsctx` itself staying on the host as the **supervisor** (tagged Wayland
socket, seccomp-notify handler, signal forwarding, systemd integration).
systemd integration and SELinux policy are written **from scratch** in
later phases.

---

## 1. Target architecture

```
host user session (uid 1000, sway)
│
├── wlsctx run rustrover          ← supervisor, unsandboxed, host namespaces
│   │   - optional: registers itself in a systemd user SCOPE via D-Bus
│   │     (StartTransientUnit, Delegate=app) — or plain cgroup fallback
│   │   - tagged Wayland socket   (wp_security_context_v1, as today)
│   │   - supervisor IPC listener (nono supervisor socket)
│   │   - sd-notify, signal forwarding, waits on child
│   │
│   └── fork ──► app process      ← the sandbox, runs as UID 1000 (not root)
│       unshare user   (single-extent map: identity stays 1000, full
│                       ns cap set, 0 unmapped — decision #10)
│       unshare mount  → build the rootfs (ns-local CAP_SYS_ADMIN)
│       unshare pid → ipc → uts → cgroup → net
│       nono: landlock + seccomp
│       execve  (app is PID 1 of its pidns)
└── (later phases) wlsctx dbus-proxy / wlsctx xwayland host sidecars
```

Compared to the container era:

- **Gone:** pods, containers, quadlets, Containerfiles, image layers, pod
  networks, SELinux CIL for `container_t` sidecars, MCS, `systemd-run`
  shell-outs.
- **Same in spirit:** unprivileged user namespace; private filesystem view;
  per-instance runtime dir under `$XDG_RUNTIME_DIR/wlsctx/<instance>/`;
  tagged Wayland socket + compositor policy; GPU render nodes by direct
  device access; (later) filtered session bus.
- **Different:** the app runs as **uid 1000, not root**, inside the
  namespace (see §3.2) — stronger than rootless podman, and friendly to
  apps that refuse to run as root; landlock + seccomp via `nono`;
  cgroup ns under a systemd *scope* created over D-Bus (no `systemd-run`).

The supervisor stays *outside* the namespaces deliberately: it needs host
access (compositor socket, session bus, cgroup files) and it is the process
the seccomp-notify fd belongs to.

## 2. nono 0.80.0 — verified API surface

Checked against the published crate source before writing this plan.

- **Linux backend = Landlock LSM** (ABI detection via `Sandbox::detect_abi()`;
  network rules need ABI ≥ v4 → kernel ≥ 6.7; Fedora 45 is fine). Older
  kernels fall back to seccomp-based network filtering
  (`apply_auto()` returns the fallback state).
- **`CapabilitySet`** is the policy object:
  - fs: `allow_path/allow_file(path, Read|ReadWrite|…)`, deny-by-default
  - unix sockets: `allow_unix_socket(_dir/_subtree)` — tagged wayland
    socket, (later) dbus-proxy sockets, ssh-agent, X11
  - network: `block_network()`, `set_network_mode(Blocked|AllowAll|ProxyOnly)`,
    `allow_tcp_connect/bind`, `allow_localhost_port(_range)`, `allow_https()`
  - further knobs: `set_signal_mode()`, `set_process_info_mode()`,
    `set_ipc_mode()`, `with_resource_limits()`
- **`Sandbox::apply_auto(&caps)`** applies to the *calling process*
  (irreversible; inherited across `execve`). `prepare_*`/`install_*`/
  `apply_external()` primitives also support post-fork choreography
  (supervisor prepares the BPF, child installs) — verify which pattern to
  use in Phase 4.
- **seccomp** is built by nono itself (raw BPF, no libseccomp): a static
  filter (network block, arch guard) plus a **SECCOMP_RET_USER_NOTIF**
  filter routing `openat/openat2`, `bind/connect/sendto/sendmsg/sendmmsg`
  to a supervising process.
- **Supervisor IPC** (`nono::supervisor`): length-prefixed messages over a
  Unix socket, `SO_PEERCRED` auth, `SCM_RIGHTS` fd injection; pluggable
  `ApprovalBackend` (we start with an auto-deny `PolicyApproval`).
- License: Apache-2.0 — compatible with this repo's AGPL-3.0.

## 3. Sandbox construction (what the child does)

### 3.1 User namespace + the non-root credential model

Two kernel rules fix the shape of the map (verified in the v7.2.11
source — `kernel/user_namespace.c` — and empirically on this machine):

- `uid_map`/`gid_map` accept **exactly one successful write**
  (decision #9).
- An **unprivileged** creator may write **only a single extent of
  count 1 whose in-ns id equals its own uid/gid**:
  `new_idmap_permitted()`'s fast path requires exactly that (the ns
  owner is the creator's euid, set by `create_user_ns()`); anything
  larger needs `CAP_SETUID`/`CAP_SETGID` in the *parent* ns, which we
  don't have. Two extents sharing a parent id would in any case be
  rejected by `mappings_overlap()` — so the old two-entry
  `0 → self; self → self` map is **EINVAL** on modern kernels
  (decision #10). bwrap reaches multi-extent maps through the setuid
  `newuidmap`/`newgidmap` helpers; we deliberately don't.

So the map is the single extent `<real uid> → <real uid>` (and the
same for gid), and `setgroups=deny` is written first, before the maps:

```
<real uid> → <real uid>   (the app's identity — the in-ns uid from the
                             start; 0 is simply not in the map)
```

Sequence (in the forked child — wlsctx itself stays outside the ns):

1. `unshare(CLONE_NEWUSER)`; write `setgroups=deny`; **one write** of
   `uid_map`/`gid_map` (the single extent above).
2. **Mount phase**: unshare the mount ns and build the whole rootfs
   (§3.3). We hold **the full ns capability set** throughout:
   `set_cred_user_ns()` grants the creator CAP_FULL_SET in the new ns
   and nothing on this path clears it (the 7.0 credential rework moved
   the setuid cap-clearing; empirically CapEff is still
   `000001ffffffffff` after the map write and after a no-op
   `setresuid(self)`). That is safe *by construction of the map*:
   every ns-local capability (dac, kill, ptrace, mount, …) only has
   effect on objects and processes inside our namespaces — and the
   only identity mapped into them is ours — so at exec time we hold no
   privilege beyond running the same command unconfined as the same
   user. The hard privilege boundary is nono's landlock + seccomp
   filter (Phase 4), which additionally denies the
   `setuid`/`setgid`/`setres*`/`sete*` family.
3. The remaining namespaces (§3.2).
4. **nono apply** (landlock + seccomp), then **`execve()` the app**.

The identity is locked **by the map itself**: the in-ns id is the real
uid from the start, in-ns `0` is unmapped, so no `set*uid` call can
ever move it (`setresuid(0)` is EINVAL; the only other mapped value is
the same one), and a second map write is impossible (write-once).
`verify_locked()` asserts exactly this before the exec and aborts
(exit 126) if anything is off.

A subuid range for file *ownership* would need a second extent and
hence a setuid helper (`newuidmap`); deferred (decision #10). Files
the app writes are owned by its real uid on the host — identical to
running unconfined. The app sees itself as its real uid (1000): no
root-in-ns behaviour.

### 3.2 Remaining namespaces (order after the mount phase)

- **PID ns** — the intermediate fork A unshares the pidns, then forks
  once more: the app (B) is **PID 1**. A stays in the *parent* pidns,
  reaps B, and exits with B's status — the teardown we actually rely on
  (7.2's zap is a no-op for surviving members, #13/#14). `wlsctx` stays
  outside both and sees A as a normal child for signalling/reaping.
- **IPC ns** — fresh (private System V + shm view).
- **UTS ns** — `sethostname("wlsctx-<app>-<instance>")`.
- **Cgroup ns** — created and entered **before** unsharing, which
  must happen **before** the rootfs build (the self-bind of `/`
  makes cgroup2 read-only): the instance sub-cgroup is `mkdir`'ed at
  the full path and entered via `cgroup.procs`, *then*
  `unshare(CLONE_NEWCGROUP)` — so the ns root **is** the instance
  cgroup and the app sees `0::/` (#20). The supervisor rmdirs the
  empty sub-cgroup on exit. The cgroup2 fs itself is not re-rooted
  on 7.2 (#12); `/sys/fs` is left empty.
- **Network ns** — per-app mode, decided in §5 (default: *shared* host
  netns + nono filtering; `--network=none` = bare new netns).

### 3.3 Rootfs construction (mount phase, as ns-root)

| Target | How | Notes |
|---|---|---|
| `/` | one-shot recursive self-bind (ro flag unattainable — #21) | new layer under the overlays below; read-only *semantics* for the app come from its real uid + nono (Phase 4); masks last |
| `/dev` | fresh tmpfs + **bind-mount** of the host nodes `null`, `zero`, `full`, `urandom`, `random`, `tty`, `ptmx` | bind-mount, not mknod: nodes keep their canonical genfs SELinux labels (`null_t`, `urandom_t`, …) so future confined domains need plain standard `open/read/write` rules; matches the rootless-runc approach. Clear error if a host node is missing. |
| `/dev/pts` | `mount devpts -o newinstance` | fresh instance, isolated from host pts |
| `/dev/dri` | bind from host | GPU; user must be in `render` group (same requirement as rootless podman); `--no-gpu` skips |
| `/proc` | fresh procfs mount | allowed in an unprivileged user ns (namespaced view); verify on target kernel (Phase 2) |
| `/sys` | fresh tmpfs + binds of `devices/`, `class/` (ro unattainable — #21) | only the sysfs *mount root* is unbindable (#18); these subpaths cover DRM/PCI discovery |
| `/run` | fresh tmpfs | per-instance dir: tagged wayland socket, supervisor socket, (later) dbus-proxy socket, (optionally) ssh-agent socket. Its *content* is the host's per-instance runtime dir, **carried into the step-1 scratch before this mask** and bound in from there — binding the host path directly here would silently hit this fresh tmpfs's own empty stand-in dir (#28) |
| `/tmp` | fresh tmpfs | `size=` from profile |
| `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/etc` | ro-binds | `/etc` as-is; passwd/group map consistently through the uid/gid maps |
| app dir | ro-bind (e.g. `/opt/rustrover`) | path from the app profile |
| XDG dirs | rw-binds | `~/.config`, `~/.cache`, `~/.local`, `~/Documents`, `~/Downloads` — per profile |
| masked | bind empty tmpfs over | `/root`, `/home/*` (except mapped ones), `/boot`, `/var`, `/srv`, `/media`, `/mnt`, `/opt/*` (except the app), anything the profile marks private |

Then `chroot()` to the assembled root. The **host** Wayland socket is
deliberately *not* visible to the app — only the tagged one — so the app
cannot bypass the security context.

All of this happens **before** nono is applied, so seccomp never needs to
permit `mount`/`mknod`/`unshare` for the app.

## 4. systemd integration (least-intrusive: one in-process call, no `systemd-run`)

**Revised 2026-10-23 after hands-on verification on the Fedora 45 target
(#35):** the varlink-first plan is *inverted*. Every released systemd
(≤ v261) lacks a varlink path that can attach PIDs to a scope, so
**D-Bus on the session bus is the primary tier** — and it works on all
distros that have a user systemd, old and new.

`wlsctx run` attempts, in order, and logs which tier it landed on:

1. **D-Bus to the user systemd** (`org.freedesktop.systemd1.Manager`
   `StartTransientUnit` over the session bus; `zbus`, driven on a
   fresh local tokio runtime per call — see `src/systemd.rs`):
   unit `wlsctx-<app>-<instance>.scope`, mode `replace`,
   properties `{ PIDs: [self] }` (**type `au`**, property name
   `PIDs` — that has been the name since scopes exist, v252).
   `systemd` moves **wlsctx itself** into the new scope's cgroup.
   Then the existing #12/#20 flow is unchanged: A captures *its*
   current cgroup before unsharing (now the scope's) and mkdirs the
   instance sub-cgroup below it. **Verified on target:** the scope
   dir is *user-owned* (the user-session subtree
   `user.slice/user-<uid>.slice/user@<uid>.service/` is delegated to
   the user — all dirs/files uid-owned, so no `Delegate=` is needed
   and the user can `mkdir`/write inside the scope freely); the scope
   lands in `app.slice`; a child cgroup created by the user inside it
   accepts the app's pid; the scope **auto-stops and is removed
   recursively** (scope + children) when the last member (the
   supervisor, which exits last) leaves.
   Deliberately **no `StopWhenUnneeded`**: in v261 it is actively
   harmful for scopes (`unit_is_unneeded` stops any active jobless
   scope immediately — verified: scope vanished in the same second,
   member still alive). The empty-cgroup auto-stop already gives the
   desired "dies with the instance" lifecycle, and that has been
   stable forever. Stale-unit handling: on `UnitExists` (a loaded
   unit of the same name) → `StopUnit` best-effort → retry once.
2. **Raw-cgroup fallback (no session bus / no user systemd / call
   failed):** no unit at all. The instance sub-cgroup is created
   under the cgroup wlsctx is currently in (user-slice leaves are
   writable by the user; creating child cgroups under a populated
   cgroup is legal in cgroup v2 — the no-internal-process rule only
   blocks enabling *controllers* there, which we don't need for a
   cgroup ns), and proceed. Documented degradation: no unit
   visibility/accounting.
3. **Future — varlink (when it can do this):** `io.systemd.Unit.StartTransient`
   exists since v261 but only for *services* (`ID`/`Description`/
   `Service{Type,ExecStart,RemainAfterExit}`); `SetUnitProperties`
   takes `Markers` only. A scope *without* PIDs cannot even start
   ("Scope has no PIDs. Refusing" — verified on target). A scope
   context with `PIDs` exists only on `main` (commit abde7e80d0,
   2026-10-16; after v262 — will land in a future release). Revisit
   the tier order then: varlink needs no session bus at all.

`cgroup.subtree_control` writes (resource limits for the `app` sub-cgroup)
are a later optional extension, not required for namespacing to work.
The user-session delegation chain on Fedora 45 permits enabling
`cpu`/`memory`/`pids` in user-owned cgroups (the user manager's
`user@<uid>.service` has them in its `subtree_control`); `io` is not
delegated, so no `io` limits from inside the session.

## 5. CLI design & network decision

```
wlsctx run  [OPTIONS] <app-id> [APP ARGS...]     # full pipeline, execs app
wlsctx run  [OPTIONS] -- <command> [ARGS...]     # ad-hoc (no profile)
wlsctx wayland [OPTIONS]                         # tagged socket only
                                                 # (tag-and-park), or
                                                 # --proxy: the mode A relay
wlsctx broker  [OPTIONS]                         # the prompt broker daemon
wlsctx decide  [OPTIONS]                         # list / resolve pending
                                                 # prompts
# later phases: dbus-proxy, xwayland, profile show, status/stop
```

Key options: `--app-id`, `--instance-id`,
`--network={filter|none|host}`, `--gpu/--no-gpu`, `--config=<dir>`,
`-v/-vv`.

**Network (decided):** default `filter` = *shared* host netns with nono's
network filtering (egress allowed, no bind — matches the old
"egress allowed" behaviour at zero plumbing cost; nono covers it
natively). `--network=none` = new netns, `lo` only. `--network=host` =
no filtering. Private-netns options (veth, pasta/slirp4netns) are a later
hardening phase, out of scope for now.

**App profiles** replace the quadlet drop-ins: TOML in
`~/.config/wlsctx/apps/<app-id>.toml` (ro binds, rw binds, masked paths,
env vars, network mode, gpu, tmp size). New deps: `nono` (pinned),
`toml`, `serde`, and `zbus` (Phase 6, D-Bus tier).

## 6. Decisions log

| # | Question | Decision |
|---|---|---|
| 1 | Network default | Shared host netns + nono filter; `--network=none` for air-gapped; veth/pasta later |
| 2 | UID inside ns | **Non-root (1000)** via a mapping that includes the real uid (§3.1, revised by #9, #10); subuid range deferred (#10) |
| 3 | D-Bus proxy | **Deferred** to a later phase (after namespacing works) |
| 4 | Xwayland | **Deferred** to a later phase |
| 5 | App distribution | *Open* — run host-installed apps (`/opt/<app>` ro-bind) for now; GPG/fetch story undecided |
| 6 | `wlsctx wayland` subcommand | Keep (already tested; no unit file in repo anymore) |
| 7 | Cleanup | Delete `docker-bake.hcl`, `systemd/`, `selinux/` (done this round). **`Dockerfile` still to decide** — it only existed to build the container image; propose deleting it in favour of a plain static build recipe. |
| 8 | systemd integration | In-process unit-start call: **D-Bus session-bus `StartTransientUnit` primary** (`PIDs=[self]`), raw-cgroup last resort, varlink a future tier — §4, #34/#35 |
| 9 | `uid_map` write-once | **Confirmed.** Modern kernels permit exactly one write to `uid_map`/`gid_map` (verified in the v7.2 stable source and current master). The original design (single write of `0 self` + `self self`) turned out to be invalid — superseded by #10, which keeps write-once but makes the map a single extent. |
| 10 | Map shape: single extent | **`<self> <self> 1`** (one extent, uid and gid). Kernel constraints: write-once (#9); an unprivileged creator may only write one extent of count 1 equal to its own uid/gid (`new_idmap_permitted()` fast path); two extents sharing a parent id are rejected by `mappings_overlap()` — so the two-entry `0 self; self self` map is EINVAL (bwrap uses the setuid `newuidmap` helper for more; we don't). Consequences: the identity is the real uid from the start, 0 is unmapped (`setresuid(0)` is EINVAL), the full ns cap set is held at exec — safe by construction of the map (§3.1) — and locked by nono in Phase 4. Subuid range for file ownership deferred (needs a setuid helper). Verified on 7.2.11-300.fc45; §3.1 rewritten; Phase 1 done. |
| 11 | Target release | **Fedora 45** (machine upgraded; running 7.2.11-300.fc45). Kernel series 7.x; Landlock ABI ≥ v4 and unprivileged userns — verified on this machine (Phase 1.4). |
| 12 | Cgroup ns view on 7.2 | The **cgroup2 filesystem is not re-rooted** by the cgroup ns — only `/proc/*/cgroup` is namespaced. So the child captures its full cgroup path *before* unshare, unshares, then `mkdir`s the instance sub-cgroup at that full path and moves in via `cgroup.procs`. The supervisor `rmdir`s the empty sub-cgroup when the instance dies (best-effort). `/proc/self/cgroup` inside shows the clean relative path. |
| 13 | pidns-init is unkillable | The first process of a pidns carries `SIGNAL_UNKILLABLE`: default-action signals are ignored, *except* SIGKILL/SIGSTOP from an ancestor pidns. Our app **is** pidns-init, so the shutdown protocol (Phase 5.4) is **SIGTERM, then SIGKILL fallback** — never wait for a TERM. |
| 14 | pidns teardown on 7.2 | When the ns leader exits, `zap_pid_ns_processes()` **does run** (`disable_pid_allocation()` proven), but on 7.2.11 the SIGKILL to surviving members is empirically a **no-op** — strays reparent, they don't die. We therefore don't rely on it: A (ns leader, in the *parent* pidns) reaps B and **exits by choice**, so nothing is left behind; exit codes propagate through A reliably (verified 5/5 for 0/42/137, incl. `128+sig` for signals). |
| 15 | `/sys/class/net` is global | On 7.2 it lists interfaces of **all** netns (a global sysfs tree) — `unshare --net` still shows the host's. Per-netns verification uses `/proc/net/dev` (per-reader view) and netlink (`ip link`); the network tests do exactly that. |
| 16 | Mount-ns naming/propagation quirks | The mount-ns symlink is `ns/mnt` (not `ns/mount`); `/proc/self/ns/` also contains `pid_for_children`/`time_for_children` entries. In mountinfo the word `private` is **omitted** (it's the default; only `shared:`/`slave:`/`unbindable:` tokens appear — host `/` shows `shared:1`). "View is private" is therefore asserted by *absence* of propagation tokens, gated on a host precondition that `/` is shared. |
| 17 | The mount-ENOENT "flake" | **Not a kernel bug.** The mount test passed a non-NUL-terminated Rust `&str` to `mount()`/`umount()`; the kernel over-reads until a NUL, and the byte after the heap buffer is usually zero (worked) but occasionally not (garbage-suffixed path → ENOENT, sticky, invisible to `stat()`, stale dir left behind). v7.2 dcache/namei audited and exonerated (incl. the 98b6cf102b35 negative-dentry fix — a real but different bug). Fixed `6d255d1`. Rule: **every path handed to a C interface is NUL-terminated** (`dir_c` pattern). |
| 18 | Binding mount roots | Binding the **mount root** of devtmpfs/sysfs/ext4 (e.g. `/dev`, `/sys` themselves) is EINVAL unprivileged on 7.2.11; any **subpath** or file binds fine. Hence `/dev`/`/sys` are rebuilt as fresh tmpfs + subpath binds (the scratch dir carries the node files out of the tree before the self-bind). |
| 19 | `mknod` unprivileged | Unprivileged `mknod` of device nodes is EPERM on 7.2.11 (SELinux enforcing). `/dev` nodes and `/dev/dri` are therefore **bind-mounted** (canonical genfs SELinux labels preserved), never mknod'd. |
| 20 | Cgroup ns root | The ns root is the unsharing task's cgroup **at unshare time**, so the instance sub-cgroup must be entered *before* `unshare(CLONE_NEWCGROUP)`: the app sees `0::/` (its own cgroup is the root; 7.2 renders it with a trailing slash). The Phase-2 order (unshare → move) rooted the ns at the session cgroup (`0::/app-N`) and is corrected; it must still precede the rootfs build (cgroup2 goes ro with the self-bind). |
| 21 | ro-binds are unattainable | On 7.2.11 `MS_BIND\|MS_RDONLY` **silently drops the ro flag** on a bind of a foreign superblock (probed on `/`, on files, and in both one-shot and make-private variants); the two-step bind → `MS_REMOUNT\|MS_RDONLY` is EPERM (the sb's `s_user_ns` is init — we can remount only our *own* fs). §3.3 corrected: `/` and the `/sys` subpaths are plain binds; read-only *semantics* for the app come from its real uid (root-owned trees unwritable) plus the nono landlock/seccomp policy (Phase 4). The test's former `ROOTWR` probe was a false positive (EACCES ≠ EROFS) and the `/proc/mounts` `head -1` read the *bottom* of the mount stack — the topmost entry is the last line. |
| 22 | One notify listener per thread | Linux allows a single `SECCOMP_FILTER_FLAG_NEW_LISTENER` filter per thread, so nono's AF_UNIX mediation filter (traps all `connect`/`bind`/`sendto`/`sendmsg`/`sendmmsg` — the family is checked in userspace, BPF cannot dereference) and the openat-logging filter must be one combined program (`PreparedSeccompNotifyFilter::with_openat_notifications`). Consequence: every `sendmsg` of the app (incl. all wayland/TCP traffic) is a supervisor round-trip — the supervisor must stay a tight, responsive loop or the app stalls. The filter is installed **before** `apply_landlock` (nono's requirement: the supervisor must see paths Landlock would block). |
| 23 | Notify-fd handoff without SCM_RIGHTS from B | B's `sendmsg` is trapped by its own filter, so B cannot hand the listener fd to S via `SCM_RIGHTS` after install. Handoff: B writes the listener's *fd number* to a pre-made B→A pipe; A (unfiltered, B's parent, same uid) does `pidfd_open(B)`+`pidfd_getfd(num)` to take its own copy, then sends it to S over a pre-made S↔A socketpair. All three channels are created in S **before** the first fork and distributed at the forks (A closes the S-side copies, B closes the A-side copies). A dead B (zombie has no fd table) → handoff fails → S falls back to plain `waitpid` (landlock still enforced). |
| 24 | Landlock needs explicit ancestor grants on Linux | A landlock rule is a default-deny floor: to reach a granted subtree the app also needs refer/traverse on every ancestor. nono's `path_metadata_dirs` (ancestor metadata grants) is macOS-only — on Linux the policy itself must grant `/` Read (and any other ancestor chains). Consistent with the current rootfs: the self-bind of `/` already shows the app every top-level directory, so Read-on-`/` adds no visibility. |
| 25 | Supervisor decides (auto-deny), never expands | The supervisor's role in Phase 4 is mediation+logging, not expansion: openat/AF_UNIX notifications are answered continue (allowlisted) or EACCES (denied + logged); there is no fd injection, no approval flow. Abstract/unnamed AF_UNIX sockets are denied (nono's default for pathname mediation) — GUI apps that use abstract-socket IPC (e.g. Chromium-style) may need a per-profile relaxation, to be added if Phase 5's E2E hits it. |
| 26 | Deterministic handoff: the verdict pipe | The seccomp listener is allocated `O_CLOEXEC` in B's table by the kernel (`get_unused_fd_flags(O_CLOEXEC)`, `kernel/seccomp.c`), and `pidfd_getfd` on B succeeds only while B is still dumpable — i.e. *pre-exec* (after exec the credential change fails `task_still_dumpable` → `EPERM`). If B started execing while A was still extracting, the dynamic loader's `openat`s would pile up on the dying listener: `seccomp_notify_free` completes every pending notification with `-ENOSYS` (observed: `Error 38` on `libtinfo.so.6`). Hence B blocks on an A→B **verdict pipe** before exec (`1` = exec, `0` = exit 126 — never an unsupervised exec); A sends it only after the extract + `SCM_RIGHTS` to S have completed. Two close-order invariants: B must *inherit* the verdict read end, so A closes its copy only *after* the second fork (closing it before the fork left B polling a dangling fd number — the "hang" that gdb showed as B-in-poll/A-in-wait4); and A ignores `SIGPIPE` after the fork, because a failure-path verdict can hit a pipe whose reader is already gone and must not kill A before it reaps B. |
| 27 | nono's three-stage prepare/apply — the filter must never precede landlock's *prepare* | nono's `apply_landlock` calls `open_path_rule` → `open(O_PATH)` for every rule path. Installing the seccomp-notify filter *first* traps those opens: B blocks in a notification wait with no supervisor running yet — a hard deadlock (observed: 300 s timeout, zero output). The working order is nono's own prepare/apply split: `prepare_landlock_with_abi` (opens all rule paths, while unfiltered) → install the combined filter → `apply_raw` (consumes the prepared fds; opens nothing). #22's "the filter must precede landlock" survives as *the filter must precede landlock's **apply***. |
| 28 | The rootfs scratch lives on `/var/tmp`; the runtime dir is carried before the `/run` mask | The scratch must stay resolvable through every build step, so it cannot sit under any masked tree. The old location (inside the per-instance runtime dir) is under `/run` for the default `XDG_RUNTIME_DIR=/run/user/<uid>` — and a bind *source* resolved after the fresh-`/run` mask hits the fresh tmpfs's empty stand-in directory: a **silent self-bind no-op** that never crosses to the host (writes "succeed" into the throwaway tmpfs; the app-side socket is invisible). New layout: the scratch is `/var/tmp/.wlsctx/<inst>` (mode 0700, not in the capability set; hidden from the app by the `/var` mask of step 8 *and* the Landlock floor), and the per-instance runtime dir is carried into it in step 1 — the only point where its host path is still resolvable — then bound onto the fresh `/run`'s instance dir in step 5. S removes the scratch (and its parent) on exit. |
| 29 | Raw pidfd syscalls: explicit zero flags; the *host* pid is the right argument | `libc` 0.2 (gnu x86_64) exposes `SYS_pidfd_open`/`SYS_pidfd_getfd` as numbers only, so they are called via `syscall(2)`. The kernel does `if (flags) return -EINVAL` for both, and a short `syscall(2)` call leaves the flags register uninitialised → spurious `EINVAL` (observed on `pidfd_open`). Pass `0` explicitly. Also, `pidfd_open` resolves the pid *globally* (`find_get_pid` → `find_vpid`, the init-namespace hash), so A — inside the fresh pidns — must pass B's **host** pid, which is exactly what `fork()` returns (`clone` returns `pid_vnr` = `level[0].nr`, never the caller-namespace-local pid; B's local pid `1` would be the wrong argument). |
| 34 | Varlink first, D-Bus as fallback | `wlsctx run` starts the scope via **Varlink** `io.systemd.Unit.StartTransient` on the *user* manager socket (`/run/user/<uid>/systemd/io.systemd.Manager`) — JSON over a unix socket, one request/response, no polkit, hand-rolled (~60 lines, no dep on the primary path). Requires **systemd ≥ 261** (`StartTransient` added in commit 913b81735e; the `io.systemd.Unit`/`io.systemd.Manager` skeletons from 258). Distro coverage (pkgs.org check, 2026-10): Ubuntu 26.10, Fedora 45+, Arch, OpenSUSE Tumbleweed, Wolfi. Older stacks (Debian 13, **Ubuntu 26.04 LTS**, RHEL/EPEL) fall back to **D-Bus** `org.freedesktop.systemd1.Manager.StartTransientUnit` on the session bus (`zbus` — chosen over `dbus` 0.9: zbus is the maintained, stable, widely-used crate). Tier order at runtime: varlink → D-Bus → raw-cgroup; the outcome is logged. The `varlink` crate (13.0.0) was considered but not adopted for the one-shot call. |
| 35 | D-Bus primary, varlink deferred (supersedes #34) | Hands-on verification on the Fedora 45 target (systemd 261) overturned the varlink-first plan. (a) `io.systemd.Unit.StartTransient` exists since 261 but is **service-only** (`ID`/`Description`/`Service{Type,ExecStart,RemainAfterExit}`); `SetUnitProperties` accepts `Markers` only; a scope created without PIDs **refuses to start** ("Scope has no PIDs. Refusing"). A scope context with `PIDs` (json pidref) exists only on `main` (abde7e80d0, 2026-10-16 — after v262), so no *released* systemd can do the operation via varlink. (b) D-Bus `StartTransientUnit` works on every user-systemd stack (scopes since v252), needs no polkit on the session bus, and the exact call is: unit `*.scope`, mode `replace`, properties `{ PIDs: <au> [self] }` — property name is `PIDs` (since v252), value an array of uint32; reply type is `(o)`, not `(uo)`. (c) `StopWhenUnneeded=true` is **harmful** on v261 scopes: `unit_is_unneeded()` stops any active, jobless, unpinned scope immediately (verified: scope removed in the same second, member alive, cgroup `(deleted)`). Not needed anyway — a scope auto-stops and is removed **recursively** when its last member leaves (verified: supervisor in scope, app in a user-mkdir'd child; supervisor exits last → whole subtree gone). (d) `Delegate=` is unnecessary: the entire user-session cgroup subtree (`user.slice/user-<uid>.slice/user@<uid>.service/`, incl. manager-created scopes) is **owned by the user** (delegation of `user@.service` chowns it), so the user can `mkdir`/write `cgroup.procs` inside the scope without any unit-level delegation. The user manager also lands transient scopes in `app.slice` (not directly under `user@.service`) — hence the instance sub-cgroup's parent is read from `/proc/self/cgroup` after the call, never assumed. Net: D-Bus (`zbus`, driven on a fresh local tokio runtime per call — never the process-global `OnceLock` runtime, which is dead in a forked child; see `src/systemd.rs`) is the primary tier for all distros (incl. Ubuntu 26.04 LTS, Debian 13 — the very distros that motivated the fallback); varlink becomes a future tier (6.4) once a release ships scope-with-PIDs. The raw-cgroup path remains the last resort (and is what A already does in #12/#20 — the only change is that S's D-Bus call moves S (and thus A's inherited cgroup) into the scope before the forks). |

| 36 | The D-Bus sidecar's lifetime is a *fd*, and that fd must be *non*-CLOEXEC | `wlsctx dbus-proxy` spawns `xdg-dbus-proxy` (0.1.9) as a child it owns (signalfd + pidfd `poll(2)`), and hands the proxy one end of a private **socketpair** as `--fd=3`. Two hard parts. (a) The fd must reach the child **without** CLOEXEC — `execve(2)` *closes* CLOEXEC descriptors (the inverse of the usual "protect the fd" reflex): `pre_exec` dups the end onto 3, *clears* the flag, closes the original (exactly one reference — a second fd for the same end keeps the peer alive). The proxy writes one `x` byte on startup (the sidecar's readiness gate) and exits when its fd sees the peer close (`g_io_add_watch(G_IO_ERR\|G_IO_HUP)`) — so even a SIGKILL'd sidecar tears the proxy down. Socketpair, not pipe: with the installed GLib 2.90 that watch does **not** fire on pipe EOF, but does on a socket peer close (the same thing flatpak passes). (b) GLib 2.90 masks `G_IO_ERR\|G_IO_HUP\|G_IO_NVAL` out of the events it hands `ppoll(2)` (an IRIX-era workaround — see `g_main_context_query_unlocked`), so the watch is polled with *zero* requested events and fires only because the kernel reports `POLLHUP` in `revents` even when unrequested — verified with an `LD_PRELOAD` ppoll tracer dumping the array. The child also resets its signal mask in `pre_exec`: a proxy orphaned with every signal blocked would be killable only by SIGKILL. The long bug of Phase 7.2: a socketpair rewrite dropped `--fd=3` from the *argv* — the proxy (told nothing) never wrote the sync byte, the sidecar parked forever in its readiness `read`, and the child outlived the sidecar; nothing about the GLib/kernel path was wrong. The gdb ppoll-array dump (fd 3 absent) vs a shimmed control run (fd 3 present, `events=0`) exposed it. |
| 37 | Xwayland runs *host-side*, not inside the sandbox; the satellite owns a bound socket and a chosen display number | `wlsctx xwayland` (7.3) gives a sandboxed app an X server by running Xwayland on the host as an ordinary Wayland *client* of the desktop compositor, sharing only its X socket into the sandbox through the per-instance runtime dir. The in-sandbox alternative (Xwayland inside the ns, connected to the tagged socket) was rejected on two counts: (a) the X server is the least-trusted component of the X stack — it can read every client's pixels and inject input — and running it inside the sandbox would hand *that* component the app's full capability set (network, home rw); a host-side satellite is the same documented trust tier as the dbus sidecar and the relay, not a new hole; (b) the private rootfs would need the entire X/GL stack (Xwayland + glamor/EGL/driver + libraries) — a large, version-sensitive surface for a rarely-used feature. Mechanically the satellite mirrors the `dbus-proxy` sidecar, and Xwayland's spawn mirrors sway's own (verified on this machine: `Xwayland :0 -rootless -listenfd N -listenfd M -displayfd K -wm W`): the sidecar creates and binds the socket itself (`-listenfd`, non-CLOEXEC — the #36 fd contract), uses `-displayfd` as the readiness gate (Xwayland writes the display number in use when it can take clients; a mismatch against the requested `--display` is a hard error — Xwayland will not silently renumber, and the app's profile must name a stable display), runs `-rootless` by default (the window integrates with the desktop) and passes `-nolisten tcp` (never a TCP listener). The originally-planned `-once` flag proved to be XDMCP *session* semantics (terminate on XDMCP retransmission timeout) — a no-op for a non-XDMCP rootless Xwayland, which does **not** exit when its last X client disconnects — so it was dropped. The lifetime backstop for a SIGKILL'd satellite is instead `PR_SET_PDEATHSIG`, set in `pre_exec` and *re-armed inside the child* by a small `LD_PRELOAD` restore shim compiled on demand into the instance dir: on this machine the exec is a SELinux domain transition into `xserver_t`, which changes the process's security credentials, and the kernel clears pdeathsig on any exec that does (`security_bprm_committing_creds`) — with **neither** setuid **nor** `AT_SECURE` (both stay unset, which is why glibc still honors `LD_PRELOAD` there; the re-set is a harmless no-op on systems that do not clear it). The instance socket is the *only* host-visible X path: given `-listenfd`, Xwayland does **not** create the conventional `/tmp/.X11-unix/X<N>` (a live `X0` on this host was a stale leftover of a dead instance, not sway's bind). And the sidecar must `listen(2)` the socket it creates before the handoff: Xwayland's `-listenfd` path (libXtrans `SocketReopen`) adopts the fd *as-is* and never calls `listen` itself — a socket handed over unlistened makes the server's `accept(2)` fail `EINVAL` on every poll wake, a 100%-CPU hot spin (sway's spawn, which listens first, is the model). |

## 7. Phases & task list

> Each phase ends with a working, committed state. "Verify" items run on
> the target machine (Fedora 45, sway, unprivileged user).

### Phase 0 — Cleanup & skeleton
- [x] 0.1 Delete `containers/` (`0c842cf`)
- [x] 0.2 Delete `docker-bake.hcl`, `systemd/`, `selinux/`; `Dockerfile` deleted (`42191e9`)
- [x] 0.3 Restructure `src/` into a binary crate with modules:
      `cli.rs`, `wayland/{mod,listener,context,signals}.rs` (move current
      code + all its tests, no behaviour change), `sandbox/`, `profile/`
- [x] 0.4 Add deps: `nono` (pinned at 0.80.0, default-features off to
      drop `keyring`), `toml`, `serde`

### Phase 1 — User namespace, non-root mapping
- [x] 1.1 `sandbox/userns.rs`: fork + `CLONE_NEWUSER`; `setgroups=deny`;
      **single write** of `uid_map`/`gid_map` — one extent each,
      `<self> <self> 1` (decision #10; the old two-entry form is
      EINVAL on modern kernels)
- [x] 1.2 Credential verification (`verify_locked`): ruid/euid/suid =
      the real uid; CapEff is the full ns set (nothing is dropped —
      the map locks the identity); `setresuid(0)`/`setresgid(0)` are
      EINVAL (decision #10)
- [x] 1.3 `wlsctx run -- <cmd>` ad-hoc path to observe results (CLI
      becomes a subcommand tree: `run`, `wayland`)
- [x] 1.4 Verified on this machine (Fedora 45, kernel 7.2.11-300.fc45,
      from the dev container's level-2 user ns — the *stricter* case;
      the plain level-1 session on the same kernel is a subset of the
      permission checks): `id` inside shows the real uid; the
      write-once probe passes (second write EPERM, map unchanged); the
      full ns cap set is held at exec; a rejected map is a hard test
      fail, not a skip
### Phase 2 — Remaining namespaces
- [x] 2.1 Mount ns (unshare right after user ns; rootfs build lands in
      Phase 3 but the unshare slot is here)
- [x] 2.2 PID ns: extra fork so the app is PID 1; death semantics
      (kill app → whole ns gone) — see #14 for the real teardown story
- [x] 2.3 IPC ns + UTS ns (hostname `wlsctx-<app>-<instance>`)
- [x] 2.4 Cgroup ns: unshare in the unit cgroup, then move child to the
      `app` sub-cgroup; verify `/proc/self/cgroup` view — #12 for the
      7.2 dance
- [x] 2.5 Network ns per mode (`none` = bare netns + `lo up`)
- [x] 2.6 Verify full set against a reference
      (`the_full_ns_set_is_fresh`: all 7 ns kinds fresh, `/proc/self/ns`
      names incl. the 7.2 quirks of #16)

### Phase 3 — Rootfs
- [x] 3.1 `sandbox/mounts.rs`: the §3.3 table as code: `/dev` tmpfs +
      node bind-mounts + `devpts -o newinstance`; fresh `/proc`; `/sys`
      ro-binds; `/run`+`/tmp` tmpfs; ro/rw binds; masks; `chroot`
- [x] 3.2 `profile/`: TOML app profiles; defaults for rustrover/librewolf
- [x] 3.3 `/dev/dri` bind + GPU check (render group), `--no-gpu`
- [x] 3.4 Verify: mount table matches the reference; `ls /` minimal;
      host Wayland socket absent; `/dev` nodes openable by the app

### Phase 4 — nono: landlock + seccomp

**Design** (verified against the nono 0.80.0 source, 2026-10-22):
- **B, pre-exec (three-stage apply, #27):** (1) *prepare* the Landlock
  policy (`prepare_landlock_with_abi`) — it opens every rule path, so
  it must run before the filter exists (a filter installed first would
  trap its own `open(O_PATH)`s → deadlock).
  (2) install the *combined* seccomp-notify filter —
  `prepare_seccomp_af_unix_filter().with_openat_notifications()`; Linux
  allows one `NEW_LISTENER` filter per thread, so the AF_UNIX mediation
  (traps `connect`/`bind`/`sendto`/`sendmsg`/`sendmmsg`) and the openat
  logging (traps `openat`/`openat2`) share one listener (#22).
  (3) *apply* the Landlock floor (`apply_raw`) — default-deny fs,
  signal scoping (V6), `no_new_privs` (locks the single-extent
  identity, #10); it uses the prepared fds, no new opens.
  (4) hand the notify-fd *number* to A over a pre-made B→A pipe
  (#23). (5) block on A's *verdict* over a pre-made A→B pipe —
  `1` = the listener is in S's hands, exec now; `0` = the handoff
  failed, exit 126, never an unsupervised exec (#26). The wait is
  mandatory: the listener is `O_CLOEXEC` in B's table (the kernel
  allocates it that way) and `pidfd_getfd` on B succeeds only while B
  is the still-dumpable *pre-exec* process.
- **A:** reads the number, extracts its own listener fd from B's fd
  table via `pidfd_open`+`pidfd_getfd` (A is B's parent, same uid —
  ptrace-permitted; the pid resolves *globally*, so the host pid
  returned by `fork()` is the right argument even from inside A's
  pidns — #29), sends it to S via `SCM_RIGHTS` over a pre-made S↔A
  socketpair, then sends B the verdict (#26). Close ordering: A drops
  its copy of the verdict read end only *after* the second fork (B
  must inherit it), and ignores `SIGPIPE` after the fork — a
  failure-path verdict can hit a pipe whose reader (B) is already
  gone, and that must not kill A before it reaps B and propagates B's
  status. Direct SCM_RIGHTS from B is impossible: its `sendmsg` is
  already trapped (#23). If the handoff fails (B died early) S falls
  back to a plain `waitpid` — landlock still applies.
- **S (the supervisor):** a poll loop over the notify listener and the
  supervisor socket (`SupervisorSocket::pair()`, the
  `CapabilityRequest` channel, auto-deny `ApprovalBackend`). Dispatch by
  syscall number: openat → resolve the path from `/proc/<pid>/mem`
  (`read_notif_path`/`resolve_notif_path`, `read_open_how` for
  openat2), check the capability allowlist → continue or
  EACCES+log; socket syscalls → read the sockaddr, *pathname* AF_UNIX
  must match a granted socket (abstract/unnamed denied — #25),
  non-UNIX families pass through (shared netns is the network
  default). The supervisor never *expands* access in this phase
  (no fd injection); landlock remains the floor. Loop ends when A dies
  (B's death tears down the whole pidns, #14).
- **CapabilitySet** (`policy.rs`): base "app essentials" — `/` Read
  (refer/traverse — required, nono grants no ancestor metadata on
  Linux, #24), `/usr /lib /lib64 /bin /sbin /etc /proc /sys` Read,
  `/dev` RW, `/tmp` RW, the per-instance `/run` dir RW, `$HOME` RW;
  plus profile `ro_binds`→Read, `rw_binds`→ReadWrite, `mask`→no
  grant, `unix_sockets`→`allow_unix_socket`, the instance-dir subtree
  (home of the Phase-5 tagged wayland socket), network
  shared→AllowAll / none→Blocked, `signals`/`ipc` per profile.
  Built identically in S and B from the same pure function (B inherits
  nothing but re-runs it).
- **4.1–4.4 checklist**
- [x] 4.1 Build `CapabilitySet` from profile: fs paths + modes, unix
      socket caps (tagged wayland, later dbus/ssh), network mode, signal /
      process-info / ipc modes (`policy.rs`; the same pure function runs
      in S and B)
- [x] 4.2 Apply after the credential sequence, before `execve` in the
      child; the install path is nono's three-stage
      `prepare_landlock_with_abi` → install combined filter →
      `apply_raw`, plus the notify-fd handoff to the supervisor
      (#23, #26, #27)
- [x] 4.3 Supervisor side: hold the seccomp-notify fd (received by
      `SCM_RIGHTS` from A), a poll loop that mediates
      openat/openat2 (against the same `CapabilitySet` that built the
      floor) and the AF_UNIX socket syscalls (granted pathname sockets
      allowed, abstract/unnamed denied — #25), auto-deny with
      `EACCES`, denials logged; exits when the notification queue
      drains (the app died) or on the stop flag
- [x] 4.4 Verify (the four Phase-4 tests in `supervise::tests`):
      openat write outside every granted subtree → `EACCES` while the
      write into the granted instance subtree crosses the bind to the
      host; read of a base-granted path returns the host file
      verbatim; `connect` to an ungranted AF_UNIX socket → `EACCES`;
      `connect` to a socket in the instance subtree is mediated
      *allow* — the payload reaches the host-side listener. Network-per-
      mode and "a normal GUI app runs" remain with 5.5 (strace-driven
      tuning of the filter, if needed, happens there).

### Phase 5 — Wayland + full pipeline
- [x] 5.1 Tagged-socket creation moves ahead of the fork (supervisor
      side, reusing the existing listener/roundtrip/context code)
- [x] 5.2 Reference pipe handed to the app (socket lives while the app
      lives; app death invalidates it — clean lifecycle)
- [x] 5.3 `wlsctx run <app-id>`: profile → env → `execve`
- [x] 5.4 sd-notify (READY on child spawn), signal forwarding
      (TERM/INT to app; keep SIGHUP→129 semantics), exit-status
      propagation, `/run` dir cleanup
- [x] 5.5 E2E on target: a real GUI app runs through the full S→A→B
      pipeline on this desktop — done with **Firefox** (2026-10-24,
      `--no-gpu`, profile `~/.config/wlsctx/apps/firefox.toml`): the
      window reached the compositor (`org.mozilla.firefox` in sway's
      tree), network egress worked (neqo/Glean uploads in the log), and
      the supervisor forwarded SIGTERM and reaped the app cleanly
      (exit 15). The in-sandbox identity probe (same pipeline, ad-hoc
      `sh`) verified real uid 1000, hostname `wlsctx-probe-1`, `0::/`
      cgroup view, the app as PID 1, and the rebuilt rootfs with the
      expected masks.

**Phase 5 decisions.**
- **30 — In-sandbox path grants.** The `CapabilitySet` and the app's env are
      built from the *in-sandbox* path (`/run/user/<uid>/wlsctx/<inst>`,
      decision #28's carry), not the host path: the app presents sandbox-side
      strings to its trapped syscalls, so the grants must match those strings.
      The wayland socket is granted by its tagged path. CLI: `run` gains
      `--wayland/--listen/--socket-activation/--sandbox-engine`.
- **31 — `open` ≠ `connect` on a unix socket.** `open(2)` on a unix socket
      returns `ENXIO` (bash `exec 3<>` does `open`); the app must `connect(2)`.
- **32 — The supervisor services every trapped notification (original
      per-pid arming resolved, 2026-10-24).** Originally the supervisor
      armed B's pid only, and a *child* of the pidns-init app issuing a
      trapped syscall was never serviced → handoff deadlock (observed: the
      openat-write test hung with the subshell stuck in
      `unix_stream_data_wait`). The supervisor now services *every*
      notification on the listener — `handle_notif` dispatches by syscall
      number with no pid filter, and a failed verdict answers EPERM rather
      than hanging — so children that inherit the seccomp filter are served
      with the same capability set. The Firefox e2e (5.5) confirms a real
      multi-process GUI app (browser + gecko/socket children) runs and exits
      cleanly; the remaining caveat is app-internal pipe behaviour, not a
      supervisor gap.
- **33 — Signal forwarding & shutdown.** S blocks `SIGTERM/SIGINT/SIGHUP`
      before spawning any thread (all threads inherit the block). A forwarder
      reads them from a `signalfd`: TERM/INT → `kill(SIGTERM)` to the app then
      `SIGKILL` after a 2 s grace (decision #13 — pidns-init ignores
      default-action signals); HUP → same, exit status 129. The app's host pid
      is reported A→S over the S↔A socketpair (A is in the parent pidns). After
      the handoff S sends `READY=1` (no-op without `$NOTIFY_SOCKET`). Teardown
      joins both threads, drops the tagged socket (untag), and `remove_dir_all`s
      the per-instance runtime dir (still at its host path — the step-1 carry is
      a bind).

### Phase 6 — systemd integration (revised #35: D-Bus primary)
- [x] 6.1 D-Bus session-bus `StartTransientUnit` scope via `zbus`
      driven on a **fresh local tokio runtime per call** — never
      `zbus::blocking` (v5), whose wrapper hides a *process-global*
      `OnceLock` runtime that is dead in a `fork(2)`-ed child
      (worker threads don't survive the fork; `block_on` on it hangs
      — the test harness forks this path, so the parallel suite
      deadlocked until the call was made runtime-local; the async
      API is the same one 6.0.0 is built on, so the later migration
      is small): `PIDs=[self]` only (no StopWhenUnneeded/Delegate).
      On `UnitExists` the unit is **adopted, not blindly stopped** —
      `StopUnit` on a scope *kills its members* (`scope_enter_dead` →
      `unit_kill_context`, v261 source): already a member → keep;
      empty (`Tasks==0`) → stop, refresh `PIDs`, start; busy (foreign
      tasks) → never touched, the run degrades. The call is async
      (the job is only queued): a ≤3 s poll of `/proc/self/cgroup`
      confirms the move. After the call A's pre-unshare cgroup
      capture lands the instance sub-cgroup inside the scope (no A/B
      change); tier logged. The local runtime's worker threads are
      spawned from the calling thread and inherit its mask, so the
      forwardable-signal block (5.4) stays *ahead of the call*: the
      forwarder stays the sole consumer; A unblocks again before
      forking B, so the app keeps its historical (unblocked) signal
      behavior. Unit
      test: with a session bus — attach self, assert moved + child
      accepts a pid + recursive removal; without — assert raw tier
      (never a silent skip)
- [x] 6.2 Raw-cgroup fallback (no session bus / no user systemd /
      call failed): the #12/#20 path; the degradation's user-visible
      semantics are documented on `ScopeTier::Unavailable` (sandbox
      unchanged; only unit visibility/accounting lost; the instance
      sub-cgroup still created under `S`'s current cgroup and
      cleaned up on exit)
- [x] 6.3 `wlsctx wayland` remains usable standalone (per-app proxy /
      socket-activation units are up to the user; the repo ships only
      the broker units, re-homed in 7.1). Verified on this desktop
      2026-10-23: both the tag-and-park and `--proxy` modes run with
      `--listen` with no units at all (the e2e of the merge session);
      the socket-activation path is unit-tested
- [ ] 6.4 *(future, #35)* varlink tier once a released systemd ships a
      scope context with `PIDs` in `io.systemd.Unit.StartTransient`
      (main only as of 2026-10-16, after v262)

### Phase 6.5 — Wayland proxy & prompt broker (clipboard branch, merged `21b26dd`)

The clipboard branch built the `--proxy` relay and the host-side
broker as its own workstream (its phases 1–9, tracked in its own
TASKS.md); the 2026-10-23 merge folded that work in here. All of it
is integration-tested (`tests/proxy_integration.rs`,
`tests/broker_integration.rs`):

- [x] 6.5.1 Mode A relay (`wayland --proxy`): convention-adaptive
      object bookkeeping between the app's connections and fresh
      tagged security-context connections (`src/proxy/`; the fd
      misrouting defect and its fix:
      `docs/postmortems/fd-swap-fix-plan.md`). SIGHUP is a rebuild,
      not a stub: an in-place re-exec of `/proc/self/exe` in
      `--listen` mode (same pid; re-binds and re-tags the freed
      socket) and a clean exit for a systemd restart when
      socket-activated.
- [x] 6.5.2 Global allow-list (`--allow-globals`): filters the
      `wl_registry` globals and rejects binds of non-allowlisted
      interfaces. **Absent flag = pass-through** (`Policy::all()`).
      The branch-era code mapped *absent* to an *active-but-empty*
      allow-list (hides everything) — the desktop e2e caught it;
      fixed in `1e46e3b`.
- [x] 6.5.3 Clipboard receive-gate (`--clipboard-policy=deny`): a
      dropped read becomes a consent request to the broker (allow =
      a 1500 ms intent window; deny and every failure path fail
      closed); clipboard/primary writes are audited, and
      `--notify-copy-out` fires a one-way `clipboard-write`
      notification (fire-and-forget, fail-open, rate-limited to one
      per selection per second per app — the window is anchored on
      the *fired* notification, so a continuous stream never
      starves).
- [x] 6.5.4 Prompt broker (`wlsctx broker` + `wlsctx decide`):
      N-D-JSON over the broker socket; a session decision socket
      (`$XDG_RUNTIME_DIR/wlsctx/decision.sock`, bound once for the
      life of the session, chmod 0600) so several prompts can be
      pending at once — FIFO, `--prompt <id>` targets — and
      `decide` without `--decision` lists them. `notify-send`
      announces with a ready-made reply command; a timeout is a
      deny; a failed decision-socket bind degrades interactive
      prompts to a deny at once (`no-decision-socket`) while copy-out
      notifications keep working; `--auto-decide` never binds the
      socket.
- [x] 6.5.5 Selection audit log (branch phase 9): one `key=value`
      record per `set`/`read`/`clear`/`serve` event to the **host
      journal** (the relay logs to stderr); payload recorded as
      **size only, never content**; no rate-limiting (a persistent
      record, not a digest). Drag-and-drop closed (2026-10-24): a
      `start_drag` is audited as a write (`action=set selection=drag`,
      its own copy-out notification). Remaining refinement: the
      `serve` records for bytes served *during* a drag still carry the
      `clipboard` label (`wl_data_source` is shared by the clipboard
      and the drag; the relay does not yet track the active drag
      source) — the write is never missed, only the per-mime flow's
      selection label.
- [x] 6.5.6 Protocol-table CI (branch deferred refinement):
      `scripts/gen_interface_table.py` regenerates `interfaces.rs`
      from `protocols/*.xml` and CI diffs the result
      (`git diff --exit-code`); `wlr_tables.rs` is the compiler's
      sync check (the `wayland_scanner::generate_interfaces!` macro
      expands the same XML at build time).
- [x] 6.5.7 Broker arrival order (`9fded8c`): prompts are ordered by
      a sequence stamped in the broker's sequential `poll(2)` accept
      loop, never by the order the per-connection threads happened to
      take the queue lock (LESSONS #17).

**Desktop e2e (this machine, sway; 2026-10-23).** `wayland-info` on
the *tagged* socket sees 35 of the host's 56 globals, and
`wp_security_context_manager_v1` is absent — the nesting guard the
spec requires (a tagged client must not be able to stamp again); on
the host socket the manager is present (name 34). Through the proxy
the same checks hold: after `1e46e3b`, all 35 (before the fix: 0). A
SIGHUP on the proxy re-execs in place (same pid, re-binds and
re-tags, still 35). 5.5 is done (the Firefox e2e, 2026-10-24). The
*full chain* is done (2026-10-24): a sandboxed `wayland-info` is
driven through the `--proxy` relay into the live sway — it enumerates
the compositor's globals and exits 0. The relay's public socket is
bound inside the per-instance runtime dir (the app's in-sandbox
`$XDG_RUNTIME_DIR`), which the rootfs build carries into the sandbox,
so the bare `run` (no `--wayland` tag of its own) resolves
`$WAYLAND_DISPLAY` to the relay. The drag-and-drop audit (6.5.5) is
closed: a `start_drag` is audited as a write (the `serve`-label
refinement is the one remaining drag detail — see 6.5.5 above).

**Branch TASKS.md follow-ups:** the zbus 5→6 migration is done
(`6725560`); the drag-and-drop audit (6.5.5) is done (`start_drag`
audited as a write).

### Phase 7 — Re-homing the deployment units + sidecars
- [x] 7.1 Re-home the broker deployment for the containerless
      world: `systemd/user/wlsctx-broker.{socket,service}` rewritten
      from the branch-era global-flag forms (`wlsctx --broker
      --socket-activation`, `wlsctx --decide`) to the merged
      subcommand CLI (`wlsctx broker --socket-activation`,
      `wlsctx decide`); verified with `systemd-analyze --user
      verify` and by running the exact ExecStart line. *Decision:*
      per-app proxies stay **documented manual runs**, not a unit —
      the proxy's public socket path must match the app profile's
      env (`XDG_RUNTIME_DIR`/`WAYLAND_DISPLAY`), which is
      per-instance coordination a template instance cannot derive.
      The deployment recipe (incl. the audit sink: the relay's
      stderr → journal via `StandardError=journal` /
      `LogDriver=passthrough` in any unit the user writes) lands
      with the README rewrite in 8.1
- [x] 7.2 `wlsctx dbus-proxy <app> <instance>`: host-side
      `xdg-dbus-proxy` (per-instance; **direct spawn**, not a
      socket-unit — the sidecar *is* the unit-equivalent: it blocks
      its signal mask, owns the child via a signalfd+pidfd `poll(2)`
      loop, and stops the child on SIGTERM/SIGINT/SIGHUP). The
      public socket lands in the per-instance runtime dir
      (`bus.sock`), owner-only from birth (umask 0077 + chmod 0600);
      the app profile's `[env]` points
      `DBUS_SESSION_BUS_ADDRESS=unix:path=…` at it. The sidecar's
      `--see/--talk/--own/--call/--broadcast` map 1:1 to the proxy's
      (with `--filter` implied by the first rule — fail-closed once
      any rule is present). Lifetime is by fd: one end of a private
      socketpair is handed to the proxy as `--fd=3` (non-CLOEXEC —
      `execve(2)` *closes* CLOEXEC descriptors), the proxy writes
      its sync byte there and exits on peer close (decision #36).
      Verified: pass-through `busctl --list`, SIGTERM teardown, and
      SIGKILL-teardown of the sidecar (the proxy dies on the HUP).
- [x] 7.3 (optional) `wlsctx xwayland` host-side satellite
      (design: decision #37). Per-instance `Xwayland` for sandboxed
      X clients: a *host* process (the in-sandbox alternative is
      rejected — see #37) mirroring the `dbus-proxy` sidecar's shape:
      direct spawn, signalfd + pidfd `poll(2)` ownership,
      TERM→2 s→KILL teardown, exit with the child's status. The
      sidecar creates the X socket itself (unix stream, bound to
      `<instance-dir>/xwayland.sock`, owner-only from birth) and
      hands it to Xwayland as `-listenfd` — the same pattern sway
      uses to spawn its own Xwayland (verified on this machine:
      `Xwayland :0 -rootless … -listenfd N -displayfd K`) — with the
      fd made *non*-CLOEXEC (the decision-#36 fd contract: `execve`
      closes CLOEXEC descriptors). Readiness is Xwayland's own
      `-displayfd` (a private socketpair): Xwayland writes the
      display number in use when it can take clients; the sidecar
      cross-checks it against `--display` (default 97, kept clear of
      sway's auto-Xwayland) and fails loudly on mismatch — the
      profile's env must name a stable display, so a silent
      renumbering is worse than an error. `-auth <instance-dir>/
      xwayland-auth` gives Xwayland a cookie file (the app points
      `XAUTHORITY` at the in-sandbox copy, decision #28's path);
      `-nolisten tcp` (never a TCP listener); `-once` (the server
      exits when the *last* X client disconnects — an orphaned
      Xwayland self-cleans when the sandbox dies); `-rootless` by
      default (the window integrates with the desktop;
      `--no-rootless` for the framed window). The sidecar prints
      the profile env line: `DISPLAY=unix:<in-sandbox socket>`,
      `XAUTHORITY=<in-sandbox auth>`. Xwayland additionally binds
      the conventional `/tmp/.X11-unix/X<N>` on the host (it always
      does, even with `-listenfd` — sway's instance shows it):
      cookie-gated, owner-reachable, a convenience, not a hole.

### Phase 8 — Docs, SELinux, hardening
- [x] 8.1 Rewrite `README.md`: architecture, threat model (what changed
      vs. containers; residual risks: network, GPU, downloads, portal
      attribution), install, verify-your-setup, adding an app.
      Done: full container-era replacement — the S→A→B pipeline, the
      rebuilt rootfs and the nono policy, the tagged socket's three
      modes, the relay (allowlist / gate / notify / audit), the
      broker/decider, a 10-layer containment table, install, TOML
      profiles, the per-app relay manual-run recipe (public socket
      inside the instance dir, tagged socket outside it; the app's
      `[env]` routes it through, `run` without `--wayland`), the
      audit-sink journal wiring (7.1's deferred deployment recipe),
      verify-your-setup (56 vs 35 globals, nesting guard), and the
      residual-risk list (network egress, copy-out, GPU, own-home
      exposure, portal attribution, multi-process deadlock, FOOT/PTY
      `EACCES`).
- [~] 8.2 New SELinux policy (first pass, 2026-10-24: `selinux/` module built — `wlsctx_t` + `wlsctx_app_t` + the xserver_t fix; not yet installed, that needs root; trimming via audit2allow is the rest). The local module confining the
      supervisor and app domains; the bind-mounted `/dev` nodes keep
      canonical labels, which makes this tractable — see §3.3)
- [x] 8.3 Update `AGENTS.md` (layout, facts): the header points at
      the rewritten README; the `systemd/user/` entry notes the
      broker units are the only units left (proxies are manual runs,
      sidecars would land here); the target fact drops the phase-7
      re-home as pending (7.1 done); the per-instance-dir fact gains
      the in-sandbox path translation and the app-env wiring
      (decision #28); the WIP bullet lists the true next steps.
- [x] 8.4 Integration test suite (`tests/`) (2026-10-24):
      `tests/sandbox_integration.rs` — eight tests driving the *built*
      `wlsctx run` binary as a subprocess with a python3 probe as the
      app (all runnable as a regular user): identity (single-extent
      `uid_map`, PID 1, cgroup-ns root `0::/`, uts hostname,
      `setuid(0)` fails), the rebuilt rootfs (fresh `/dev` with only
      the standard nodes, `/sys` with empty `/sys/fs`, `/run` holding
      only the instance tree, fresh `/tmp`, namespaced `/proc`), the
      Landlock floor (seccomp filter active; a write denied outside
      the granted subtrees, allowed inside them, read-granted trees
      unwritable), the network (`shared` completes a ping/pong with a
      host-side listener; `none` denies `bind` and `connect` before
      the packet leaves — the bare netns per `/proc/net/dev` holds
      only `lo`), the tagged socket (the only one visible in the
      instance dir, the app's `connect(2)` succeeds, and the 5.4
      cleanup removes the per-instance runtime dir after the run),
      and the lifecycle (a forwarded TERM to a handler exits 0; an
      ignored TERM as pidns-init dies by the 2 s SIGKILL escalation,
      exit 137 after ≥1.5 s). The suite skips cleanly when python3,
      unprivileged user namespaces, a live wlroots compositor, or the
      systemd-standard session XDG is absent — the last because the
      supervisor builds its capability set against the *in-sandbox*
      instance-dir path (decision #28), which exists on the host only
      for that XDG (see LESSONS.md #22).
- [x] 8.5 Threat-model review against the old README's list, item by
      item (2026-10-24): reviewed the pre-8.1 README's threat model
      (README @ `1d780d5^`) against the in-process architecture.
      *What it protects:* **home files** — changed shape: the app is
      its real uid and keeps its *real* XDG dirs writable, so the
      protection is from other users and the system, not from you
      (the standard masks — other users' homes, `/root`, `/var`,
      `/srv`, `/media`, `/mnt` — still apply; 8.4 verified the floor
      empirically); **session D-Bus** — stronger: unreachable by
      default (the rebuilt `/run` carries only the instance tree and
      AF_UNIX `connect`/`bind` is trapped to it), with the `dbus-proxy`
      sidecar (7.2) as the opt-in filtered path; **privileged Wayland
      globals** — unchanged (compositor per-context policy via the
      tagged socket, plus the relay's `--allow-globals`); **privilege
      escalation** — stronger: the single-extent self-map leaves uid 0
      *unmapped*, so `setuid(0)` is `EINVAL` rather than merely
      capability-dropped (8.4 verified); **app code integrity at build
      time** — retired: the container-era GPG-verified images are gone;
      the app is whatever command `run` is given, and its integrity is
      the user's as for any local program; **the selection read-gate** —
      unchanged (the relay's opt-in receive-gate, with broker consent
      and the always-on audit log riding on it). *What it does NOT
      protect:* **outbound network** — same stance, with `--network=none`
      as a new explicit knob (8.4: bare netns, `bind`/`connect` denied
      before the packet leaves); **clipboard copy-out** — same
      tripwire + audit-log stance (the `start_drag` write-audit remains
      open as 6.5.5); **the shared downloads volume** — absorbed into
      the new "your own home directory" residual (the same cross-app
      tamper, scoped to your own uid's files); **GPU render nodes** —
      unchanged; **portal attribution** — unchanged, now via the
      *built* `dbus-proxy` (the "planned" wording corrected); **within
      a pod** — now "within one app instance" (all its processes share
      the instance namespaces; the 7.3 xwayland satellite is
      per-instance, so there is no display shared across instances).
      The **SSH/git guidance** survives (mechanism: the profile's
      `unix_sockets`); the container-era **SELinux caveat** (the global
      `container_t → wl_dbus_proxy` connectto rule, MCS-bounded) is
      retired — the 8.2 module scopes every rule to the `wlsctx_t` /
      `wlsctx_app_t` domains. The review retired the container-era
      known gaps (at-spi allow-nothing, the image-frozen SIGHUP
      re-exec, the missing `wl-app@.pod`, the GPG-chain TODO, the
      commented-out drop-in knobs) and fixed three stale entries in
      the current README: the multi-process "deadlock" gap (resolved
      by decision #32 — the supervisor services *every* trapped
      notification, Firefox e2e the proof; the remaining caveat is
      app-internal pipe behaviour), the "sidecars are later" bullet
      (7.2/7.3 are built), and the "full chain … (Phase 5.5)" bullet
      (5.5 is done — what remains is the sandboxed client through the
      `--proxy` relay into the live compositor).

## 8. Risks / things to watch

- **Kernel features on Fedora 45**: unprivileged user+mount+proc+devpts
  from a plain user session — Phase 1/2 verify tasks exist exactly for
  this (Fedora ships unprivileged userns enabled, but verify).
- **`uid_map` is write-once and, for us, single-extent (#9, #10)**:
  confirmed on 7.2.11-300.fc45 — the single-extent self-map works, the
  full ns cap set is held at exec, `setresuid(0)` is EINVAL, and the
  write-once probe (second write EPERM, map unchanged) passes. What
  remains of this risk: a subuid range for file ownership needs a
  setuid helper (`newuidmap`) if we ever want it — a later phase, not
  a blocker.
- **seccomp friction with GUI apps**: JVMs and browsers do exotic
  syscalls; nono's default is allow-everything-except-notified, which
  should keep friction low — but `strace`-driven tuning is expected in
  Phase 4.
- **nono API churn**: pin the version in `Cargo.lock`; the
  supervisor/prepare/apply split needs source-level reading in Phase 4
  (docs are thin; the source is the reference).
- **cgroup corner cases**: no-internal-process rule (we only *create*
  children, never enable controllers under a populated cgroup — safe),
  and how the user-slice delegation behaves in Phase 6.1 — fallback
  path covers any surprise.