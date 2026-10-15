# wlsctx — deferred / follow-up tasks

This is a personal WIP repo; this file tracks work that is deliberately
deferred to a later phase. Each entry notes where the hook point already
is in the code, so a future phase can pick it up without re-deriving the
design.

---

## Next up: broker — a single decision socket for the life of the session

**Status:** not started. `decide_interactive` (src/broker.rs) binds a
fresh decision socket per prompt (`broker-<pid>.sock` in the runtime
dir; the path is announced in the consent notification) and the
`--decide` path (src/main.rs) reaches only the most recent prompt via
the `latest` pointer. A single decision socket bound for the life of
the session, with a `wlsctx --decide` that lists the pending prompts,
would make multi-prompt sessions serviceable; the per-prompt bind and
the `latest` pointer are the hook points.

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
