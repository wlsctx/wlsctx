//! The selection audit log (Phase 9).
//!
//! The relay is on the path of every selection event a sandboxed app
//! performs, and it keeps a **persistent, structured record** of them
//! — the complement of the Phase 6 copy-out *notification* (visible in
//! the moment, lost if nobody looked): one record per
//!
//! * **`set`** — the app placed data on a selection (`set_selection`
//!   with a non-NULL source). The copy-*out*: from that moment the
//!   data is reachable by every client on the desktop.
//! * **`read`** — the app asked to receive selection data
//!   (`receive`), with the gate's decision: forwarded, dropped, or
//!   approved through the prompt broker.
//! * **`clear`** — the app cleared a selection (`set_selection` with
//!   a NULL source).
//! * **`serve`** — the app is writing its own data into the fd a
//!   requester handed through a `send` event on one of the app's
//!   source objects: the per-mime byte flow behind a `set` (or a
//!   `start_drag`).
//!
//! ## The sink: the host journal
//!
//! The default sink writes one line per record under the `audit` log
//! target. In deployment the relay's stderr reaches the **host**
//! journal in both modes — mode B via the pod's passthrough logging
//! (`LogDriver=passthrough`, `StandardError=journal`), mode A via the
//! unit's `StandardError=journal` — so the record outlives the pod:
//! `journalctl -u <relay unit>` shows one line per event, greppable
//! on the `key=value` fields (the target renders as `audit:` in the
//! line). The audit is *always on* while the relay runs (one formatted
//! line per selection event — negligible against the traffic it
//! guards); a host that does not want the stream sets `RUST_LOG=warn`.
//!
//! ## What a record contains — and what it never does
//!
//! `app`, `instance`, `selection`, `action`, `origin`, `mime`,
//! `gate`, `fd_kind`, `payload_bytes` — see [`AuditRecord`]. The
//! `mime` is the *name* only, and the payload is recorded as a
//! **size** (bytes), never as content: a record is safe to share
//! without revealing what was on the selection. Where a size is
//! measurable depends on the fd's class (a memfd reports a size; a
//! pipe/socket does not — the record then omits the field), and the
//! relay never reads or copies the data: it only `fstat`s the fd it
//! already holds (see the probe in [`super`]).

use std::fmt::Write;
use std::sync::Arc;

use log::info;

/// Where an audit record goes.
///
/// The production sink ([`JournalAuditSink`]) writes one line per
/// record to the process's log stream, which in deployment is the
/// host journal. Tests use a capturing sink to assert on the
/// rendered lines.
pub trait AuditSink: Send + Sync {
    /// Emit one record. `app` and `instance` are the relay's audit
    /// identity (the security-context values it was started with).
    fn audit(&self, app: &str, instance: &str, record: &AuditRecord);
}

/// The default sink: one line per record under the `audit` log
/// target. `RUST_LOG=warn` suppresses the stream (the records are
/// then simply not retained by the journal).
pub struct JournalAuditSink;

impl AuditSink for JournalAuditSink {
    fn audit(&self, app: &str, instance: &str, record: &AuditRecord) {
        let line = format_audit(app, instance, record);
        info!(target: "audit", "{line}");
    }
}

/// The audit identity of the relayed app: the security-context
/// `app_id` / `instance_id` the tagged connection was stamped with
/// (the same values the prompt broker carries).
///
/// Not `Debug` (the sink is a `dyn AuditSink`); the identity fields
/// are logged at startup instead.
#[derive(Clone)]
pub struct AuditConfig {
    pub app: String,
    pub instance: String,
    sink: Arc<dyn AuditSink>,
}

impl Default for AuditConfig {
    /// The journal sink with an unknown identity: a mechanical
    /// default (tests, and any relay started without the security
    /// context values — the records are still emitted, just without
    /// attribution).
    fn default() -> Self {
        Self::new(String::new(), String::new())
    }
}

impl AuditConfig {
    /// The production config: records go to the `audit` log target
    /// (the host journal in deployment).
    pub fn new(app: String, instance: String) -> Self {
        Self {
            app,
            instance,
            sink: Arc::new(JournalAuditSink),
        }
    }

    /// A config that emits through a custom sink (the test hook).
    pub fn with_sink(app: String, instance: String, sink: Arc<dyn AuditSink>) -> Self {
        Self {
            app,
            instance,
            sink,
        }
    }

    /// Emit one record through the configured sink.
    pub fn audit(&self, record: &AuditRecord) {
        self.sink.audit(&self.app, &self.instance, record);
    }
}

/// One audited selection event.
///
/// The fields are rendered in a fixed order; a field that does not
/// apply to the event is omitted rather than given an empty value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    /// The selection the event is about: `clipboard` (the stable
    /// selection) or `primary` (the X-style primary selection).
    pub selection: &'static str,
    /// What happened: `set` (the app placed data on the selection),
    /// `read` (the app received selection data), `clear` (the app
    /// cleared the selection), or `serve` (the app is serving its
    /// own data into a requester's fd — the byte flow behind a
    /// `set`/`start_drag`).
    pub action: &'static str,
    /// The attribution of the data: `own` (the app's), `foreign`
    /// (another client's / the host's), or `unknown` (the gate has
    /// no attribution yet). A `set` is always `own` (the source is
    /// one this client created); a `clear` records the origin of the
    /// selection that was removed; a `read`/`serve` records the
    /// gate's attribution of the data.
    pub origin: Option<&'static str>,
    /// The mime type (a `read`: from the request; a `serve`: from
    /// the event). The *name* only — never the data.
    pub mime: Option<String>,
    /// The decision on a `read`: `forward` (the policy let it
    /// through), `dropped` (the gate, or a broker deny — the app's
    /// fd stays empty), or `approved` (the user approved it through
    /// the prompt broker).
    pub gate: Option<&'static str>,
    /// The class of the fd the data travels through (a `read`: the
    /// app's receive fd; a `serve`: the requester's fd): `memfd`,
    /// `pipe`, or `socket`.
    pub fd_kind: Option<&'static str>,
    /// The payload size in bytes, when measurable: for a `read` the
    /// size of the data written into the app's fd (0 when the read
    /// was dropped — the fd stayed empty), for a `serve` the size of
    /// the data the app wrote into the requester's fd. A memfd
    /// reports a size; a pipe/socket does not (the field is then
    /// omitted), as does a `set`/`clear` (the bytes flow later, per
    /// mime — see the `serve` records).
    pub payload_bytes: Option<u64>,
}

/// Render one record as its `key=value` line. Pure — the same string
/// every sink emits, and what the unit tests assert on.
pub fn format_audit(app: &str, instance: &str, r: &AuditRecord) -> String {
    let mut s = String::new();
    let _ = write!(
        s,
        "app={app} instance={instance} selection={} action={}",
        r.selection, r.action
    );
    if let Some(o) = r.origin {
        let _ = write!(s, " origin={o}");
    }
    if let Some(m) = &r.mime {
        let _ = write!(s, " mime={m}");
    }
    if let Some(g) = r.gate {
        let _ = write!(s, " gate={g}");
    }
    if let Some(k) = r.fd_kind {
        let _ = write!(s, " fd_kind={k}");
    }
    if let Some(b) = r.payload_bytes {
        let _ = write!(s, " payload_bytes={b}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> AuditRecord {
        AuditRecord {
            selection: "clipboard",
            action: "read",
            origin: Some("foreign"),
            mime: Some("text/plain".into()),
            gate: Some("dropped"),
            fd_kind: Some("memfd"),
            payload_bytes: Some(0),
        }
    }

    #[test]
    fn renders_all_fields_in_order() {
        assert_eq!(
            format_audit("rustrover", "work", &record()),
            "app=rustrover instance=work selection=clipboard action=read \
             origin=foreign mime=text/plain gate=dropped fd_kind=memfd payload_bytes=0"
        );
    }

    #[test]
    fn omits_fields_that_do_not_apply() {
        let mut r = record();
        r.action = "set";
        r.origin = Some("own");
        r.mime = None;
        r.gate = None;
        r.fd_kind = None;
        r.payload_bytes = None;
        assert_eq!(
            format_audit("pod", "rustrover", &r),
            "app=pod instance=rustrover selection=clipboard action=set origin=own"
        );
    }

    #[test]
    fn serves_carry_size_and_mime() {
        let mut r = record();
        r.action = "serve";
        r.origin = Some("own");
        r.gate = None;
        r.payload_bytes = Some(4096);
        assert_eq!(
            format_audit("rustrover", "work", &r),
            "app=rustrover instance=work selection=clipboard action=serve \
             origin=own mime=text/plain fd_kind=memfd payload_bytes=4096"
        );
    }
}
