# wlsctx — deferred / follow-up tasks

This is a personal WIP repo; this file tracks work that is deliberately
deferred to a later phase. Each entry notes where the hook point already
is in the code, so a future phase can pick it up without re-deriving the
design.

---

## Next up

No single next phase is queued: the remaining work is the deferred
refinements below (no fixed phase) — CI regeneration of the protocol
tables, and the SIGHUP reload stub. Most recently done: the broker's
session decision socket, the Phase 9 audit log, and the Phase 6
copy-out rate limit.

---

## Done: broker — a single decision socket for the life of the session

**Status:** implemented (see the commits). The interactive broker
binds one decision socket for the life of the session
(`$XDG_RUNTIME_DIR/wlsctx/decision.sock`, at startup, chmod 0600)
instead of a fresh `broker-<pid>.sock` per prompt; the `latest`
pointer is gone. The run loop is now `poll(2)`-driven over both
listeners: each proxy connection gets its own thread (a prompt
waiting on the user parks that thread on a per-prompt condvar — the
old serial loop parked on the first consent for up to the timeout
and could not even accept the next request), and the main thread
services the decision socket (a short read timeout bounds a stuck
decider). `wlsctx --decide` (no `--decision`) lists the pending
prompts (id, app/instance, selection, mime, time left — oldest
first); `--decide --decision allow|deny` resolves the **oldest**
pending prompt, and `--prompt <id>` targets a specific one (the
consent notification carries the id and a ready-made reply
command). Design decisions taken: the queue is FIFO — an untargeted
decision resolves the oldest, not the most recent, as the old
`latest` pointer implied (with the id in the notification, targeting
is explicit either way); a decided prompt leaves the queue
atomically with its decision (one lock), so a double decide for the
same id is a clean `unknown-prompt` rather than a double resolution,
and an expired prompt is removed by its own waiting thread; a
failed decision-socket bind degrades the broker (interactive prompts
deny at once with `no-decision-socket`, no hang; copy-out
notifications keep working) instead of failing the service;
`--auto-decide` never binds the socket at all.

---

## Done: Phase 6 follow-up — rate-limit the copy-out notification

**Status:** implemented (see the commits). At most one notification
per selection per second, per app: the gate tracks the last *fired*
notification per selection (`ClipboardGate::note_copy_out`, default
window `COPY_OUT_NOTIFY_INTERVAL` = 1 s; the two selections keep
independent windows), so a rapid copier's burst of `set_selection`s
collapses to one per window. Design decisions taken: the window is
anchored on the *fired* notification, not on the suppressed writes (a
continuous stream re-arms once per window and never starves); the
limit lives on the relay side (one thread per app connection — the
per-app, per-selection state; the broker daemon stays a dumb
fire-and-forget announcer); a write is never blocked or delayed
(fail-open unchanged) and a suppression is a `debug!` line; every
write still lands in the audit log (Phase 9), which remains the
persistent record. A `#[cfg(test)]` constructor overrides the window
so the unit tests don't sleep a second; the integration burst tests
(`copy_out_burst_*`) drive two back-to-back `set_selection`s in one
datagram and assert exactly one notification.

---

## Done: Phase 9 — audit log of selection events across the container boundary

**Status:** implemented (see the commits). One structured record per
selection event the relay observes — `set`, `read`, `clear`, and
`serve` (a `send` event on the app's data source: the per-mime byte
flow behind a write) — with `app`, `instance`, `selection`, `action`,
`origin`, `mime`, `gate` (`forward`/`approved`/`dropped` for reads),
`fd_kind`, and `payload_bytes`. Design decisions taken: the sink is
the **host journal** (the relay logs to stderr; `LogDriver=passthrough`
+ `StandardError=journal` in both modes' units), the payload is
recorded as a **size only** (never content — the relay only `fstat`s
the fd it already holds; memfd sizes settle through a small probe,
streams report none, a dropped read records 0), and there is **no
rate-limiting** (one line per event is negligible against the
traffic it guards; `RUST_LOG=warn` silences the stream). Open
follow-ups: the Phase 6 notification debounce (above), and extending
the audit to drag-and-drop (`start_drag` is not audited yet — only
selections).

---

## Deferred refinements (no fixed phase)

* **`wlr_tables.rs` / `interfaces.rs` regeneration** currently depends
  on `scripts/gen_interface_table.py`; wire it into CI so a protocol
  XML change can't silently desync the tables.
* **SIGHUP restart** is a stub (exits 129). Implement an in-place
  config reload or a clean re-exec.
