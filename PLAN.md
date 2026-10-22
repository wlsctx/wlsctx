# wlsctx rework: in-process sandboxing, no containers

Status: **v2.2 — decision #10 (single-extent map) confirmed on kernel 7.2.11-300.fc45; Phase 1 done; Phase 2 in progress** (2026-10-22)

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

- **PID ns** — the child `fork()`s once more, so the app is **PID 1** of
  the new pidns; when it dies the kernel tears the namespace down and its
  children die with it (no orphans). `wlsctx` stays outside the pidns and
  sees the app as a normal child for signalling/reaping.
- **IPC ns** — fresh (private System V + shm view).
- **UTS ns** — `sethostname("wlsctx-<app>-<instance>")`.
- **Cgroup ns** — unshared while the child is still in the *unit/scope
  cgroup* (inherited from us), then the child moves itself into the
  `app` sub-cgroup (visible inside the ns as `/app`), so
  `/proc/self/cgroup` shows a clean stable path. See §4.
- **Network ns** — per-app mode, decided in §5 (default: *shared* host
  netns + nono filtering; `--network=none` = bare new netns).

### 3.3 Rootfs construction (mount phase, as ns-root)

| Target | How | Notes |
|---|---|---|
| `/` | bind host `/` **ro** | then mask what must not be visible (below) |
| `/dev` | fresh tmpfs + **bind-mount** of the host nodes `null`, `zero`, `full`, `urandom`, `random`, `tty`, `ptmx` | bind-mount, not mknod: nodes keep their canonical genfs SELinux labels (`null_t`, `urandom_t`, …) so future confined domains need plain standard `open/read/write` rules; matches the rootless-runc approach. Clear error if a host node is missing. |
| `/dev/pts` | `mount devpts -o newinstance` | fresh instance, isolated from host pts |
| `/dev/dri` | bind from host | GPU; user must be in `render` group (same requirement as rootless podman); `--no-gpu` skips |
| `/proc` | fresh procfs mount | allowed in an unprivileged user ns (namespaced view); verify on target kernel (Phase 2) |
| `/sys` | ro-binds of `devices/`, `class/` | full `/sys` not mountable unprivileged; these cover DRM/PCI discovery |
| `/run` | fresh tmpfs | per-instance dir: tagged wayland socket, supervisor socket, (later) dbus-proxy socket, (optionally) ssh-agent socket |
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

## 4. systemd integration (least-intrusive: D-Bus, no `systemd-run`)

`wlsctx run` attempts, in order:

1. **D-Bus to the user systemd** (`org.freedesktop.systemd1.Manager`,
   over the session bus; `zbus` or `dbus` crate — pick in Phase 6):
   `StartTransientUnit("wlsctx-<app>-<instance>.scope", "replace",
   { Delegate: "app", StopWhenUnneeded: "yes", Pids: [self] }, {})`.
   `systemd` moves **wlsctx itself** into the new scope's cgroup; we then
   create the delegated `app` sub-cgroup below it. (Same mechanism
   rootless podman uses for its scopes — `Delegate` on a scope is
   supported.) With `StopWhenUnneeded`, the scope dies when both the
   supervisor and the app exit; `systemctl --user status` sees the unit.
2. **Fallback (no systemd / D-Bus call failed):** no unit at all. Create
   the `wlsctx-<app>` and `wlsctx-<app>/app` sub-cgroups with plain file
   writes under the cgroup wlsctx is currently in (user-slice leaves are
   writable by the user; creating child cgroups under a populated cgroup
   is legal in cgroup v2 — the no-internal-process rule only blocks
   enabling *controllers* there, which we don't need for a cgroup ns),
   and proceed. Documented degradation: no unit visibility/accounting.

`cgroup.subtree_control` writes (resource limits for the `app` sub-cgroup)
are a later optional extension, not required for namespacing to work.

## 5. CLI design & network decision

```
wlsctx run  [OPTIONS] <app-id> [APP ARGS...]     # full pipeline, execs app
wlsctx run  [OPTIONS] -- <command> [ARGS...]     # ad-hoc (no profile)
wlsctx wayland [OPTIONS]                         # today's behaviour: tagged
                                                 # socket only (mode A)
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
`toml`, `serde`, and a D-Bus crate in Phase 6.

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
| 8 | systemd integration | In-process D-Bus `StartTransientUnit` scope + raw-cgroup fallback (§4) |
| 9 | `uid_map` write-once | **Confirmed.** Modern kernels permit exactly one write to `uid_map`/`gid_map` (verified in the v7.2 stable source and current master). The original design (single write of `0 self` + `self self`) turned out to be invalid — superseded by #10, which keeps write-once but makes the map a single extent. |
| 10 | Map shape: single extent | **`<self> <self> 1`** (one extent, uid and gid). Kernel constraints: write-once (#9); an unprivileged creator may only write one extent of count 1 equal to its own uid/gid (`new_idmap_permitted()` fast path); two extents sharing a parent id are rejected by `mappings_overlap()` — so the two-entry `0 self; self self` map is EINVAL (bwrap uses the setuid `newuidmap` helper for more; we don't). Consequences: the identity is the real uid from the start, 0 is unmapped (`setresuid(0)` is EINVAL), the full ns cap set is held at exec — safe by construction of the map (§3.1) — and locked by nono in Phase 4. Subuid range for file ownership deferred (needs a setuid helper). Verified on 7.2.11-300.fc45; §3.1 rewritten; Phase 1 done. |
| 11 | Target release | **Fedora 45** (machine upgraded; running 7.2.11-300.fc45). Kernel series 7.x; Landlock ABI ≥ v4 and unprivileged userns — verified on this machine (Phase 1.4). |

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
- [ ] 2.1 Mount ns (unshare right after user ns; rootfs build lands in
      Phase 3 but the unshare slot is here)
- [ ] 2.2 PID ns: extra fork so the app is PID 1; death semantics
      (kill app → whole ns gone)
- [ ] 2.3 IPC ns + UTS ns (hostname `wlsctx-<app>-<instance>`)
- [ ] 2.4 Cgroup ns: unshare in the unit cgroup, then move child to the
      `app` sub-cgroup; verify `/proc/self/cgroup` view
- [ ] 2.5 Network ns per mode (`none` = bare netns + `lo up`)
- [ ] 2.6 Verify full set against a reference:
      `bwrap --unshare-user --uid <self> --unshare-pid …` —
      `mount`/`lsns`/`/proc/self/*` diff

### Phase 3 — Rootfs
- [ ] 3.1 `sandbox/mounts.rs`: the §3.3 table as code: `/dev` tmpfs +
      node bind-mounts + `devpts -o newinstance`; fresh `/proc`; `/sys`
      ro-binds; `/run`+`/tmp` tmpfs; ro/rw binds; masks; `chroot`
- [ ] 3.2 `profile/`: TOML app profiles; defaults for rustrover/librewolf
- [ ] 3.3 `/dev/dri` bind + GPU check (render group), `--no-gpu`
- [ ] 3.4 Verify: mount table matches the reference; `ls /` minimal;
      host Wayland socket absent; `/dev` nodes openable by the app

### Phase 4 — nono: landlock + seccomp
- [ ] 4.1 Build `CapabilitySet` from profile: fs paths + modes, unix
      socket caps (tagged wayland, later dbus/ssh), network mode, signal /
      process-info / ipc modes
- [ ] 4.2 Apply after the credential sequence, before `execve` in the
      child; verify the install path (`apply_auto` vs
      `prepare_*`/`apply_external` + notify-fd handoff to the supervisor)
- [ ] 4.3 Supervisor side: hold the seccomp-notify fd, service the
      supervisor socket with an auto-deny `PolicyApproval`; log denials
      via nono diagnostics
- [ ] 4.4 Verify: blocked path → EACCES; allowed path works; network per
      mode; a normal GUI app *runs* (strace-driven tuning of the static
      filter if needed)

### Phase 5 — Wayland + full pipeline
- [ ] 5.1 Tagged-socket creation moves ahead of the fork (supervisor side,
      reusing the existing listener/roundtrip/context code)
- [ ] 5.2 Reference pipe handed to the app (socket lives while the app
      lives; app death invalidates it — clean lifecycle)
- [ ] 5.3 `wlsctx run <app-id>`: profile → env → `execve`
- [ ] 5.4 sd-notify (READY on child spawn), signal forwarding
      (TERM/INT to app; keep SIGHUP→129 semantics), exit-status
      propagation, `/run` dir cleanup
- [ ] 5.5 E2E on target: RustRover and LibreWolf run; `wlsinfo` diff vs
      host matches the old acceptance checklist

### Phase 6 — systemd integration
- [ ] 6.1 D-Bus `StartTransientUnit` scope (Delegate=app,
      StopWhenUnneeded, Pids=self) — pick `zbus` vs `dbus` crate;
      verify `systemctl --user status` shows the scope, no "unexpected
      process" warnings, scope dies with the instance
- [ ] 6.2 Raw-cgroup fallback (no systemd / call failed): create
      sub-cgroups under the current cgroup, proceed; document degradation
- [ ] 6.3 `wlsctx wayland` remains usable standalone (socket activation
      is up to the user's own units — repo ships none)

### Phase 7 — Sidecars (deferred)
- [ ] 7.1 `wlsctx dbus-proxy <instance>`: host-side `xdg-dbus-proxy`
      (per-instance; decide socket-unit vs direct spawn in this phase)
- [ ] 7.2 (optional) `wlsctx xwayland` host-side satellite

### Phase 8 — Docs, SELinux, hardening
- [ ] 8.1 Rewrite `README.md`: architecture, threat model (what changed
      vs. containers; residual risks: network, GPU, downloads, portal
      attribution), install, verify-your-setup, adding an app
- [ ] 8.2 New SELinux policy from scratch (local module confining the
      supervisor and app domains; the bind-mounted `/dev` nodes keep
      canonical labels, which makes this tractable — see §3.3)
- [ ] 8.3 Update `AGENTS.md` (layout, facts)
- [ ] 8.4 Integration test suite (`tests/`): in-ns assertions (uid is
      non-root, pid 1, mounts, cgroup), landlock deny checks, seccomp
      checks, network checks, wayland tagged-socket check, lifecycle
      (TERM → clean death) — all runnable as a regular user
- [ ] 8.5 Threat-model review against the old README's list, item by item

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
