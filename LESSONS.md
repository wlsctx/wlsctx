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
