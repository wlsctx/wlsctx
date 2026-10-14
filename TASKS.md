# wlsctx — deferred / follow-up tasks

This is a personal WIP repo; this file tracks work that is deliberately
deferred to a later phase. Each entry notes where the hook point already
is in the code, so a future phase can pick it up without re-deriving the
design.

---

## Next up: Phase 9 — audit log of selection events across the container boundary

**Status:** not started. The copy-out *notification* (Phase 6) made a
write *visible in the moment*; this is the **persistent, structured**
record of all selection traffic the relay is on the path of.

### What to record

One structured journal entry (structured-fields, so `journalctl -t
wlsctx` can filter/grep) per selection event the relay observes, with:

| field | value |
|-------|-------|
| `app` | the app ID from the security context (already on `BrokerConfig`) |
| `instance` | the instance ID (same) |
| `selection` | `clipboard` \| `primary` |
| `action` | `set` (write) \| `read` (receive) \| `clear` (set with a NULL source) |
| `origin` | `own` \| `foreign` \| `unknown` — the gate's attribution |
| `mime` | the mime type (from the `receive` request / the source's `offer`s) |
| `gate` | the decision: `forward` \| `dropped` \| `approved` (via broker) |
| `fd_kind` | for a `read`: the receive fd's class (`memfd`/`pipe`/`socket`) |

### Where the hooks already are

* **Write** — `ClipboardGate::writes_selection` is called in
  `Relay::forward` (`src/proxy/mod.rs`, the `Phase 6` block). An audit
  entry goes right there (same call site as the notification).
* **Read** — the `receive` decision in `Relay::forward` (the Phase 3/5
  interceptor block) is where `on_receive` returns a `ForwardAction`;
  the origin is available from the gate, the mime from the request, the
  fd kind from the (existing) sanity check.
* **Clear** — `set_selection` with a NULL source is currently filtered
  *out* of `writes_selection`; a `clear` audit entry needs the gate to
  report clears too (extend the detector to return a three-way
  `write`/`clear`/`none`).

### Open design questions

* **Sink.** The relay runs inside the pod (Mode B) or in a
  socket-activated container (Mode A) — both have a *private* journal.
  Do entries go to the pod's own journal (visible per-pod), or does the
  relay forward them to a host-side audit sink (e.g. the broker socket,
  or a dedicated audit socket) so there is one cross-pod record? The
  host-sink route reuses the existing broker-socket plumbing (a new
  one-way kind, like `clipboard-write`).
* **Redaction / size.** A `mime` of `text/html` can be large; record the
  *name* only, never the payload. Decide whether to record payload
  length (bytes offered) for anomaly detection.
* **Sampling.** Per-`receive` per-mime can be chatty for a power user;
  consider a per-app rate bucket (like the Phase 6 notification, below).

---

## Deferred refinements (no fixed phase)

* **Rate-limit the Phase 6 copy-out notification.** Currently one
  `notify-send` per `set_selection`. A rapid-copier would be noisy. A
  per-app debounce (e.g. at most one notification per N seconds per
  selection) would need a small per-relay timer; the gate already
  tracks writes, so the state is there.
* **Broker: a single decision socket for the life of the session**
  instead of re-binding per prompt; and a `wlsctx --decide` that lists
  pending prompts rather than relying on the `latest` pointer.
* **`wlr_tables.rs` / `interfaces.rs` regeneration** currently depends
  on `scripts/gen_interface_table.py`; wire it into CI so a protocol
  XML change can't silently desync the tables.
* **SIGHUP restart** is a stub (exits 129). Implement an in-place
  config reload or a clean re-exec.
