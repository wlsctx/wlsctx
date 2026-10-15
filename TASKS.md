# wlsctx — deferred / follow-up tasks

This is a personal WIP repo; this file tracks work that is deliberately
deferred to a later phase. Each entry notes where the hook point already
is in the code, so a future phase can pick it up without re-deriving the
design.

---

## Next up: Phase 6 follow-up — rate-limit the copy-out notification

**Status:** not started. One `notify-send` per `set_selection` is
noisy for a rapid copier. A per-app, per-selection debounce (at most
one notification per N seconds) would need a small per-relay timer;
the gate already tracks writes (`ClipboardGate::set_selection`), so
the state is there.

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

* **Broker: a single decision socket for the life of the session**
  instead of re-binding per prompt; and a `wlsctx --decide` that lists
  pending prompts rather than relying on the `latest` pointer.
* **`wlr_tables.rs` / `interfaces.rs` regeneration** currently depends
  on `scripts/gen_interface_table.py`; wire it into CI so a protocol
  XML change can't silently desync the tables.
* **SIGHUP restart** is a stub (exits 129). Implement an in-place
  config reload or a clean re-exec.
