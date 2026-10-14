//! The proxy side of the prompt broker (Phase 4).
//!
//! When the relay's clipboard gate ([`super::clipboard::ClipboardGate`])
//! drops a foreign read under the `deny` policy, the relay consults a
//! [`BrokerConfig`] (if one is configured): a fresh Unix connection to
//! the host broker's socket, one JSON request line, one JSON answer
//! line. An answer of `allow` makes the relay call
//! [`ClipboardGate::unlock`](super::clipboard::ClipboardGate::unlock)
//! with the intent window from the answer (1500 ms by default) and
//! forward the read; anything else — `deny`, a timeout, an
//! unreachable broker, a malformed answer — keeps the drop. The
//! broker is therefore always *optional* and always fails closed: a
//! host without the broker installed behaves exactly like Phase 3.
//!
//! The ask blocks the relay thread for up to [`BrokerConfig::timeout`]
//! (default 30 s, the user's think time): both ends of *this*
//! connection sit idle meanwhile, and other connections have their own
//! threads, so a slow decision never stalls the desktop.
//!
//! A second, one-way use (Phase 6): when `notify_copy_out` is set, the
//! relay also sends a *copy-out* notification (`BrokerConfig::notify_write`)
//! to the same socket each time the app writes to the clipboard or the
//! primary selection. That line gets a desktop notification and no
//! reply; it is fire-and-forget and fails open (a missing broker simply
//! loses the notice, the write is never altered).

use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use log::warn;

use crate::broker::{
    ClipboardRead, ClipboardWrite, Decision, NOTIFY_KIND, PROTOCOL_VERSION, REQUEST_KIND,
    encode_notification, encode_request,
};

/// The broker the relay consults about dropped foreign reads.
#[derive(Clone, Debug)]
pub struct BrokerConfig {
    /// The broker's listening socket (the relay connects to it per
    /// ask). In deployment it is a systemd socket-activated unit on
    /// the host (Mode A) or a socket file bound into the pod (Mode B).
    pub socket: PathBuf,
    /// The app ID from the sandbox's security context (what the
    /// prompt shows).
    pub app: String,
    /// The instance ID from the sandbox's security context.
    pub instance: String,
    /// How long to wait for the broker's answer before failing
    /// closed (the user's think time).
    pub timeout: Duration,
    /// The intent window the relay opens on an approved read: what
    /// it passes to
    /// [`ClipboardGate::unlock`](super::clipboard::ClipboardGate::unlock).
    pub window: Duration,
    /// Phase 6: when set, the relay also fires a one-way *copy-out*
    /// notification ([`Self::notify_write`]) to this broker each time
    /// the app writes to the clipboard or primary selection. Independent
    /// of the consent flow above (which only fires on a *dropped*
    /// read): a write is always forwarded, the notice is fire-and-forget
    /// and fails open.
    pub notify_copy_out: bool,
}

impl BrokerConfig {
    /// The user's default think time: how long the relay waits for
    /// the broker (and through it, the user) to answer.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
    /// The default intent window on an approved read: 1500 ms, the
    /// "this one paste, now" window an approved read opens.
    pub const DEFAULT_WINDOW: Duration = Duration::from_millis(1500);
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            socket: PathBuf::new(),
            app: String::new(),
            instance: String::new(),
            timeout: Self::DEFAULT_TIMEOUT,
            window: Self::DEFAULT_WINDOW,
            notify_copy_out: false,
        }
    }
}

impl BrokerConfig {
    /// Ask the broker whether the dropped read of `mime` from
    /// `selection` (`"clipboard"` or `"primary"`) should be allowed.
    /// `Ok(true)`: the user allowed it (the relay opens the intent
    /// window and forwards); `Ok(false)`: the broker (or the user)
    /// denied it; `Err`: the ask failed (broker missing, timeout,
    /// malformed answer) — the caller must fail closed.
    pub fn ask(&self, selection: &str, mime: &str) -> Result<bool, String> {
        let mut stream = UnixStream::connect(&self.socket)
            .map_err(|e| format!("connecting to the broker socket {:?}: {e}", self.socket))?;
        let _ = stream.set_read_timeout(Some(self.timeout));
        let _ = stream.set_write_timeout(Some(self.timeout));

        let req = ClipboardRead {
            v: PROTOCOL_VERSION,
            kind: REQUEST_KIND.to_string(),
            app: self.app.clone(),
            instance: self.instance.clone(),
            mime: mime.to_string(),
            selection: selection.to_string(),
        };
        stream
            .write_all(encode_request(&req).map_err(|e| e.to_string())?.as_bytes())
            .map_err(|e| format!("writing the request to the broker: {e}"))?;

        let mut line = String::new();
        crate::broker::read_line(&mut stream, &mut line).map_err(|e| match e.kind() {
            // SO_RCVTIMEO expiry on a blocking stream surfaces as
            // WouldBlock: the user (or the broker) did not answer in
            // time.
            io::ErrorKind::WouldBlock => format!(
                "the broker did not answer within {} (fail closed)",
                self.timeout.as_millis()
            ),
            other => format!("reading the broker's answer: {other}"),
        })?;
        let decision: Decision = crate::broker::decode_decision(&line)?;
        match decision {
            Decision::Allow { .. } => Ok(true),
            Decision::Deny { reason } => {
                warn!("broker denied the {selection} read ({reason})");
                Ok(false)
            }
        }
    }

    /// The Phase 6 copy-out notification: the app just wrote to
    /// `selection` (`"clipboard"` or `"primary"`). Fire-and-forget —
    /// one connection, one line, no reply is read. The broker (on the
    /// host) turns it into a desktop notification; the write itself is
    /// never gated or delayed by this.
    ///
    /// A short deadline bounds the relay thread: a missing broker
    /// socket, a full socket buffer, or an unresponsive broker all
    /// surface as an error here, which the caller logs and then
    /// *ignores* (fail-open — the write was already forwarded before
    /// this was called).
    pub fn notify_write(&self, selection: &str) -> Result<(), String> {
        let mut stream = UnixStream::connect(&self.socket).map_err(|e| {
            format!(
                "connecting to the broker socket {:?} for the copy-out note: {e}",
                self.socket
            )
        })?;
        // Bounded by the shorter of a fixed 2 s (enough to enqueue a
        // small line even against a broker busy on a 30 s consent
        // prompt) and the configured consent timeout.
        let deadline = self.timeout.min(NOTIFY_DEADLINE);
        let _ = stream.set_write_timeout(Some(deadline));

        let note = ClipboardWrite {
            v: PROTOCOL_VERSION,
            kind: NOTIFY_KIND.to_string(),
            app: self.app.clone(),
            instance: self.instance.clone(),
            selection: selection.to_string(),
        };
        stream
            .write_all(
                encode_notification(&note)
                    .map_err(|e| e.to_string())?
                    .as_bytes(),
            )
            .map_err(|e| format!("writing the copy-out notification to the broker: {e}"))?;
        // The connection closes here (the OwnedFd/stream drops). No
        // reply is expected or read.
        Ok(())
    }
}

/// The connect+write deadline for the fire-and-forget copy-out
/// notification (kept short so a stuck broker can never hold the
/// relay thread; a dropped notice is acceptable, a blocked app is
/// not).
const NOTIFY_DEADLINE: Duration = Duration::from_millis(2000);
