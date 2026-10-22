# wlsctx rework: in-process sandboxing, no containers

Status: **DRAFT — for discussion before implementation** (2026-10-22)

The podman/quadlet layer is deleted (`0c842cf`). Containment moves into the
`wlsctx` binary itself: it becomes a CLI tool that, per app, creates Linux
namespaces, builds a private rootfs, applies landlock + seccomp via the
[`nono`](https://docs.rs/nono) library, and `exec()`s the app — with `wlsctx`
itself staying on the host as the **supervisor** (tagged Wayland socket,
seccomp-notify handler, signal forwarding, D-Bus proxy sidecar).

---

## 1. Target architecture

```
host user session (uid 1000, sway, host session bus)
│
├── wlsctx run rustrover          ← supervisor, unsandboxed, host namespaces
│   │   - tagged Wayland socket   (wp_security_context_v1, as today)
│   │   - supervisor IPC listener (nono supervisor socket)
│   │   - systemd sd-notify, signal forwarding, waits on child
│   │
│   └── fork ──► app process      ← the sandbox
│       unshare:  user → pid → ipc → uts → cgroup → net → mount
│       mounts:   private /dev, /proc, /sys (subsets), /run, /tmp
│                 binds: /usr /etc /opt/<app> (ro), XDG dirs (rw),
│                        /dev/dri, tagged wayland socket, dbus-proxy socket
│       nono:     landlock (deny-by-default fs + unix sockets + network)
│                 seccomp (static network block / notify filters)
│       exec:     /opt/rustrover/bin/…   (PID 1 of its own pidns)
│
└── wlsctx dbus-proxy <instance>  ← host-side sidecar: xdg-dbus-proxy
                                    filtered view of the host session bus
```

Compared to the container era:

- **Gone:** podman pods, containers, quadlets, Containerfiles, image layers,
  pod networks, SELinux CIL for container sidecars, MCS.
- **Same in spirit:** unprivileged user namespace with uid 0 → 1000 (the app
  is "root" inside, real uid 1000 outside — identical to rootless podman);
  private filesystem view; filtered session bus; per-app private runtime dir
  under `$XDG_RUNTIME_DIR/wlsctx/<instance>/`; tagged Wayland socket +
  compositor policy; GPU render nodes by direct device access.
- **New:** landlock (fs/socket/network baseline) and seccomp via `nono`,
  supervisor pattern with runtime capability requests, cgroup ns +
  systemd `Delegate` for the app's cgroup subtree.

The supervisor stays *outside* the namespaces deliberately: it needs host
access (compositor socket, session bus, cgroup files) and it is the process
the seccomp-notify fd belongs to.

## 2. nono 0.80.0 — verified API surface

Checked against the published crate source before writing this plan.

- **Linux backend = Landlock LSM** (ABI detection via `Sandbox::detect_abi()`;
  network rules require ABI ≥ v4 → kernel ≥ 6.7; Fedora 43 is fine). Older
  kernels fall back to seccomp-based network filtering
  (`apply_auto()` returns the fallback state).
- **`CapabilitySet`** is the policy object:
  - fs: `allow_path/allow_file(path, Read|ReadWrite|…)`, deny-by-default
  - unix sockets: `allow_unix_socket(_dir/_subtree)` — for the tagged
    wayland socket, dbus-proxy sockets, ssh-agent, X11
  - network: `block_network()`, `set_network_mode(Blocked|AllowAll|ProxyOnly)`,
    `allow_tcp_connect/bind`, `allow_localhost_port(_range)`, `allow_https()`
  - further confinement knobs: `set_signal_mode()`, `set_process_info_mode()`,
    `set_ipc_mode()`, `with_resource_limits()`
- **`Sandbox::apply_auto(&caps)`** applies to the *calling process*
  (irreversible; inherited across `execve`). There are also
  `prepare_*`/`install_*`/`apply_external()` primitives that support a
  **post-fork choreography** (supervisor prepares the BPF, child installs
  it) — we will verify exactly which pattern to use in Phase 5.
- **seccomp** is built by nono itself (raw BPF, no libseccomp): a static
  filter for network blocking / arch guard, plus a **SECCOMP_RET_USER_NOTIF**
  filter that routes `openat/openat2`, `bind/connect/sendto/sendmsg/sendmmsg`
  to a supervising process.
- **Supervisor IPC** (`nono::supervisor`): length-prefencoded messages over a
  Unix socket, `SO_PEERCRED` auth, `SCM_RIGHTS` fd injection; pluggable
  `ApprovalBackend` (nono-cli ships Terminal/Webhook/Policy backends; we
  start with an auto-deny `PolicyApproval`).
- License: Apache-2.0 — compatible with this repo's AGPL-3.0.

## 3. Sandbox construction (what the child does, in order)

1. **User ns** — `unshare(CLONE_NEWUSER)`, write `/proc/self/setgroups` =
   `deny`, map uid/gid `0 → <real uid>` (plus optionally the subuid range
   `100000–165536 → 1–65537`, see Q2). Rootless-podman-equivalent mapping is
   *required*: the new mount namespace is owned by this user ns, and
   mounting inside it needs `CAP_SYS_ADMIN` in it.
2. **Mount ns** — built *first* among the non-user ns, because the user ns
   above is what allows it (order in the syscall sequence: user → mount →
   build rootfs → the rest). See §3.1.
3. **PID ns** — the child `fork()`s exactly once *after* unsharing, so the
   grandchild (the app) is **PID 1** of the new pidns; when the app dies,
   the kernel tears the namespace down and its children die with it (no
   orphans). `wlsctx` stays outside the pidns and sees the app as a normal
   child pid for signalling/reaping.
4. **IPC ns** — fresh (private System V + shared-memory view).
5. **UTS ns** — `sethostname("wlsctx-<app>-<instance>")`.
6. **Cgroup ns** — child is moved into a sub-cgroup of the service's cgroup
   *before* unsharing, so the app's `/proc/self/cgroup` shows a clean path
   (e.g. `/app`) and `/sys/fs/cgroup` is rooted at the service. Requires
   systemd delegation, see §4.
7. **Network ns** — mode is per-app, see Q1.
8. **nono apply** — landlock + seccomp on the (soon-to-be-PID 1) process,
   then **`execve()` the app**. The seccomp notify fd is handed to the
   supervisor (wlsctx) which services capability requests for its lifetime.

### 3.1 Rootfs construction (mount namespace)

| Target | How | Notes |
|---|---|---|
| `/` | bind host `/` **ro** | then mask what must not be visible (see below) |
| `/dev` | fresh tmpfs + `mknod` | `null, zero, full, urandom, random, tty, ptmx` + `devpts` at `/dev/pts`; all are on the unprivileged-mknod list |
| `/dev/dri` | bind from host (ro) | GPU; requires user in `render` group (same as rootless podman) |
| `/proc` | fresh procfs mount | allowed in unprivileged user ns (namespaced view); verify on target kernel (task 4.4) |
| `/sys` | ro-binds of `devices/`, `class/` | full `/sys` not mountable unprivileged; these cover DRM/PCI discovery |
| `/run` | fresh tmpfs | holds the per-instance dir: tagged wayland socket, supervisor socket, dbus-proxy socket, (optionally) ssh-agent socket |
| `/tmp` | fresh tmpfs | `size=` from profile |
| `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/etc` | ro-binds | `/etc` as-is (passwd/group map consistently because of the uid map) |
| app dir | ro-bind (e.g. `/opt/rustrover`) | path comes from the app profile |
| XDG dirs | rw-binds | `~/.config`, `~/.cache`, `~/.local`, `~/Documents`, `~/Downloads` — per profile |
| masked | bind empty tmpfs over | `/root`, `/home/*` (except mapped ones), `/boot`, `/var`, `/srv`, `/media`, `/mnt`, `/opt/*` (except the app), anything else the profile marks private |

Then `chroot()`/pivot to the assembled root. The **host** Wayland socket is
deliberately *not* visible to the app — only the tagged one is — so the app
cannot bypass the security context.

## 4. systemd integration (cgroup below a transient unit)

- `wlsctx run` is designed to be started as a **transient user service**:
  `systemd-run --user -p Delegate=…` (a `wlsctx launch` wrapper subcommand)
  or via `StartTransientUnit` over D-Bus. The unit's cgroup then owns both
  `wlsctx` (supervisor) and the app.
- To let the app live in a **sub-cgroup** (`<unit>/app`) that `wlsctx`
  creates and moves itself into:
  - transient unit: pass the property (`-p Delegate=app` / via
    `StartTransientUnit` properties) — this is the "tell systemd" mechanism,
    it suppresses "unexpected processes in cgroup" and grants subtree write
    rights (task 6.1, including verifying the cgroup v2 *no-internal-process*
    rule works out under user-slice delegation);
  - persistent named unit (per-app, optional): a drop-in carrying
    `Delegate=app` in `<unit>.d/`.
- `wlsctx run` also degrades gracefully when started from a plain terminal
  (no systemd): cgroup ns is skipped or falls back to a manually created
  leaf under the user slice; document which (task 6.2).

## 5. CLI design

```
wlsctx run  [OPTIONS] <app-id> [APP ARGS...]     # full pipeline, execs app
wlsctx run  [OPTIONS] -- <command> [ARGS...]     # ad-hoc (no profile)
wlsctx wayland [OPTIONS]                         # today's behaviour:
                                                 # tagged socket only (mode A
                                                 # socket activation stays)
wlsctx dbus-proxy [OPTIONS] <instance>           # host sidecar: xdg-dbus-proxy
wlsctx profile show <app-id>                     # dump resolved policy
                                                 # (mounts/landlock/seccomp)
# later: status/stop, xwayland, list
```

Key options: `--app-id`, `--instance-id`, `--network={none,host,filter}`,
`--gpu/--no-gpu`, `--dbus/--no-dbus`, `--config=<dir>`, `-v/-vv`.

**App profiles** replace the quadlet drop-ins: TOML in
`~/.config/wlsctx/apps/<app-id>.toml` (ro binds, rw binds, masked paths,
env vars, network mode, gpu, dbus filter args, tmp size). New deps:
`nono`, `toml` (+ `serde`).

## 6. Open questions — decide before Phase 2+

1. **Network default.** Old behaviour: private netns, egress allowed, no
   LAN presence. Options:
   - (a) *shared host netns* + nono network filtering (`AllowAll` egress,
     no bind) — simplest; nono covers it natively; keeps IDEs working;
     loses LAN-presence isolation (moot on a 1–2 user laptop?);
   - (b) new netns + veth to host — closest to the old pod network, but
   real plumbing (we'd write the setup in wlsctx);
   - (c) new netns + userspace proxy (pasta/slirp4netns style) — more
   plumbing, most isolation;
   - (d) plain new netns (no connectivity) for `--network=none` apps.
   **Proposal: (a) as default + (d) available now; (b)/(c) as later
   hardening.**
2. **UID mapping.** Single mapping `0 → self` (simplest; other users' files
   show as `nobody`) or rootless-podman-style subuid range (needed if any
   bind-mounted path contains files owned by non-self uids that the app
   must *write*). **Proposal: single mapping now, subuid range as a
   profile option.**
3. **D-Bus proxy shape.** Host-side `wlsctx dbus-proxy <instance>` spawning
   `xdg-dbus-proxy` (external binary, as today's
   `systemd/user/wl-dbus-nocontainer@.service` already does on the host).
   Per-instance unit + on-demand spawn? One shared proxy? **Proposal:
   per-instance, systemd socket-activated, exactly like the existing
   nocontainer unit.**
4. **Xwayland satellite.** Keep as a host-side sidecar (for X apps) or drop
   for now (RustRover uses native Wayland; LibreWolf uses Wayland)?
5. **App distribution.** The GPG-verified JetBrains image build is gone with
   the Containerfiles. For now: run apps installed on the host (bind
   `/opt/<app>`). Do we want a `wlsctx fetch <app>`-style installer
   later? (Probably a separate project.)
6. **`wlsctx wayland` (mode A).** Keep as subcommand (it's already tested
   and useful standalone) — **proposal: keep**; the dangling
   `systemd/user/wlsctx@.socket` is repointed at `wlsctx wayland
   --socket-activation`.
7. **Repo cleanup decisions:** delete `docker-bake.hcl` (all targets gone),
   delete `selinux/` (CIL was for `container_t` sidecars), `Dockerfile` →
   keep only as a static-musl build recipe (no ghcr image) or drop?

## 7. Phases & task list

> Each phase ends with a working, committed state. "Verify" items run on the
> target machine (Fedora 43, sway, unprivileged user).

### Phase 0 — Cleanup & skeleton
- [x] 0.1 Delete `containers/` (`0c842cf`)
- [ ] 0.2 Decide §6 open questions
- [ ] 0.3 Remove `docker-bake.hcl`, `selinux/`; decide `Dockerfile` fate;
      repoint `systemd/user/wlsctx@.socket` (or set aside); keep
      `wl-dbus-nocontainer@.service` (now the relevant D-Bus pattern)
- [ ] 0.4 Restructure `src/` into a binary crate with modules:
      `cli.rs`, `wayland/{mod,listener,context,signals}.rs` (move current
      code + all its tests, no behaviour change), `sandbox/`, `profile/`
- [ ] 0.5 Add deps: `nono` (pinned), `toml`, `serde`

### Phase 1 — User namespace
- [ ] 1.1 `sandbox/userns.rs`: fork + `CLONE_NEWUSER`, `setgroups=deny`,
      write `uid_map`/`gid_map` (single mapping; subuid range behind a
      profile flag)
- [ ] 1.2 `wlsctx run -- id`-style ad-hoc path to observe the result
- [ ] 1.3 Verify: `lsns`, `id` inside, files under `/etc` show the mapped
      uid; kernel's unprivileged-userns is enabled on the target

### Phase 2 — Remaining namespaces
- [ ] 2.1 Mount ns (unshare right after user ns)
- [ ] 2.2 PID ns: single extra fork so the app is PID 1; death semantics
      check (kill app → whole ns gone)
- [ ] 2.3 IPC ns + UTS ns (hostname `wlsctx-<app>-<instance>`)
- [ ] 2.4 Cgroup ns: create `<unit>/app` sub-cgroup, move in, unshare
      (needs Phase 6.1 delegation); verify `/proc/self/cgroup` view
- [ ] 2.5 Network ns per chosen mode (Q1)
- [ ] 2.6 Verify full set against a reference: `bwrap --unshare-user
      --unshare-pid …` `mount`/`lsns`/`cat /proc/self/*` diff

### Phase 3 — Rootfs
- [ ] 3.1 `sandbox/mounts.rs`: the §3.1 table as code (dev nodes, proc,
      sys binds, run/tmp tmpfs, ro/rw binds, masks, chroot)
- [ ] 3.2 `profile/`: TOML app profiles; defaults for rustrover/librewolf
- [ ] 3.3 `/dev/dri` bind + GPU check (render group), optional
      `--no-gpu`
- [ ] 3.4 Verify: mount table matches the reference; `ls /` minimal;
      app files visible; host Wayland socket *absent*

### Phase 4 — nono: landlock + seccomp
- [ ] 4.1 Build `CapabilitySet` from profile: fs paths + modes, unix
      socket caps (tagged wayland, dbus, ssh), network mode, signal /
      process-info / ipc modes
- [ ] 4.2 Apply before `execve` in the child; verify the post-fork
      install path (`apply_auto` vs `prepare_*`/`apply_external`)
- [ ] 4.3 Supervisor side: hold the seccomp-notify fd, service the
      supervisor socket with an auto-deny `PolicyApproval`; log denials
      via nono diagnostics (`audit`/`diagnostic`)
- [ ] 4.4 Verify: blocked path → EACCES; allowed path works; network per
      mode; a blocked syscall doesn't take the app down unexpectedly
      (tune the static filter so a normal GUI app *runs*)

### Phase 5 — Wayland + full pipeline
- [ ] 5.1 Tagged-socket creation moves ahead of the fork (supervisor side,
      reusing the existing listener/roundtrip/context code)
- [ ] 5.2 Reference pipe handed to the app (socket stays live while the
      app lives; app death invalidates it — clean lifecycle)
- [ ] 5.3 `wlsctx run <app-id>`: profile → env → `execve`;
      `wlsctx run -- <cmd>` ad-hoc
- [ ] 5.4 sd-notify (READY on child spawn), signal forwarding
      (TERM/INT to app; keep SIGHUP→129 semantics), exit-status
      propagation, `/run` dir cleanup
- [ ] 5.5 E2E on target: RustRover and LibreWolf run, `wlsinfo` diff vs
      host matches the old acceptance checklist

### Phase 6 — systemd & sidecars
- [ ] 6.1 `wlsctx launch`: `systemd-run --user -p Delegate=…` (or
      `StartTransientUnit` over D-Bus); drop-in variant for named units;
      verify no "unexpected process" warnings, correct `systemctl status`
- [ ] 6.2 `wlsctx dbus-proxy <instance>`: wrap `xdg-dbus-proxy` (reuse
      `wl-dbus-nocontainer@` socket unit as the model); verify portal
      calls succeed, everything else filtered
- [ ] 6.3 Graceful non-systemd invocation (plain terminal): cgroup fallback
      + documented behaviour
- [ ] 6.4 (optional, Q4) `wlsctx xwayland` host-side satellite

### Phase 7 — Docs & hardening
- [ ] 7.1 Rewrite `README.md`: architecture, threat model (what changed
      vs. containers; residual risks: network, GPU, downloads, portal
      attribution), install, verify-your-setup, adding an app
- [ ] 7.2 Update `AGENTS.md` (layout, facts)
- [ ] 7.3 Integration test suite (`tests/`): in-ns assertions (uid/pid/
      mounts/cgroup), landlock deny checks, seccomp checks, network
      checks, wayland tagged-socket check, dbus filter check, lifecycle
      (TERM → clean death) — runs as a regular user
- [ ] 7.4 Threat-model review against the old README's list, item by item

## 8. Risks / things to watch

- **Kernel features on Fedora 43**: unprivileged user+mount+proc+devpts all
  must work from a plain user session — Phase 1/2 verify tasks exist
  exactly for this (Fedora ships unprivileged userns enabled, but verify).
- **seccomp friction with GUI apps**: JVMs and browsers do a lot of exotic
  syscalls; nono's default is allow-everything-except-notified, which
  should keep friction low — but `strace`-driven tuning is expected in
  Phase 4.
- **nono API churn**: pin the version in `Cargo.lock`; the
  supervisor/prepare/apply split needs reading of the crate source in
  Phase 4 (its docs are thin; the source is the reference).
- **cgroup v2 no-internal-process rule**: moving processes into a child of
  a delegated cgroup has corner cases; Phase 6.1 includes a fallback
  decision if delegation behaves differently than expected for user units.
