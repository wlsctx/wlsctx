//! The prompt broker (Phase 4).
//!
//! ## Why the broker
//!
//! Under `--clipboard-policy=deny` the proxy drops every read of a
//! selection the sandboxed app did not create itself (see
//! [`crate::proxy::clipboard`]): the app sees an empty clipboard. That
//! is the safe default, but the user may legitimately want to paste
//! host data into the sandbox — for one read, at the moment it
//! happens, decided by the *user* and not by the app. The broker is
//! where that decision lives: it runs on the **host** (a user service
//! in the desktop session, outside every sandbox), because only the
//! host can see the user and answer for them.
//!
//! ## The protocol
//!
//! Newline-delimited JSON over a Unix stream socket; one request and
//! one response per connection:
//!
//! * The proxy (which hit a foreign read its gate dropped) connects
//!   and sends one request line:
//!   `{"v":1,"kind":"clipboard-read","app":"…","instance":"…","mime":"…"}`.
//! * The broker announces the request to the desktop (`notify-send`),
//!   binds a private **decision socket** (whose path it also records
//!   in a `latest` pointer file in the runtime directory) and waits
//!   for the user's answer on it — one line,
//!   `{"decision":"allow"}` or `{"decision":"deny"}`, sent by
//!   `wlsctx --decide` (a keybinding, a notification action, any
//!   program) or by any writer that can reach the socket.
//! * The broker answers the proxy with one line:
//!   `{"decision":"allow","window_ms":1500}` or
//!   `{"decision":"deny","reason":"…"}` and closes the connection.
//!
//! On an allow, the proxy opens the gate's *intent window*
//! ([`crate::proxy::clipboard::ClipboardGate::unlock`] with the
//! `window_ms` from the response, 1500 ms by default): this read, and
//! any further reads until the window closes, go through without
//! another prompt — an approved paste usually comes in a short burst
//! (one `receive` per mime type, or the app retrying). After the
//! window, the gate is closed again. Every failure path — the broker
//! missing, a timeout, a malformed answer — fails closed on both
//! sides and the read is dropped as if there were no broker.

use std::io::{self, Write};
use std::os::fd::FromRawFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{Duration, Instant};

use log::{info, warn};
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use serde::{Deserialize, Serialize};

/// The broker's default wait for the user's decision.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// The intent window the broker offers on an allow (milliseconds):
/// what the proxy passes to [`crate::proxy::clipboard::ClipboardGate::unlock`].
pub const INTENT_WINDOW_MS: u64 = 1500;
/// The only request kind the proxy sends (room to grow).
pub const REQUEST_KIND: &str = "clipboard-read";
/// The protocol version in every line (both directions).
pub const PROTOCOL_VERSION: u8 = 1;

/// A request from the proxy: the app behind it is trying to read a
/// selection it did not create, and the proxy's gate dropped the read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipboardRead {
    /// The protocol version (currently 1).
    pub v: u8,
    /// The request kind (currently only [`REQUEST_KIND`]).
    pub kind: String,
    /// The app ID from the sandbox's security context.
    pub app: String,
    /// The instance ID from the sandbox's security context.
    pub instance: String,
    /// The mime type the app asked to read.
    pub mime: String,
}

/// The broker's answer to the proxy: allow the read (opening an
/// intent window of `window_ms`) or drop it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    /// Serve the read; the proxy unlocks foreign reads for `window_ms`.
    Allow { window_ms: u64 },
    /// Drop the read; the app sees an empty clipboard.
    Deny { reason: String },
}

/// The user's answer on the decision socket (no window: the broker
/// supplies the intent window from its own configuration).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum UserDecision {
    Allow,
    Deny,
}

/// Encode a wire line (message + trailing newline).
fn encode<T: Serialize>(msg: &T) -> io::Result<String> {
    Ok(format!(
        "{}\n",
        serde_json::to_string(msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
    ))
}

/// Decode one wire line (a newline is optional in input; the
/// `Decision`/`UserDecision` tags must be the given value).
fn decode<T: for<'de> Deserialize<'de>>(line: &str) -> Result<T, String> {
    serde_json::from_str(line.trim())
        .map_err(|e| format!("malformed line {line:?}: {e}"))
}

/// Encode a request line (the proxy → broker direction).
pub fn encode_request(req: &ClipboardRead) -> io::Result<String> {
    encode(req)
}

/// Decode a request line; the version and kind must match.
pub fn decode_request(line: &str) -> Result<ClipboardRead, String> {
    let req = decode::<ClipboardRead>(line)?;
    if req.v != PROTOCOL_VERSION {
        return Err(format!(
            "unsupported protocol version {} (the broker speaks {PROTOCOL_VERSION})",
            req.v
        ));
    }
    if req.kind != REQUEST_KIND {
        return Err(format!("unknown request kind {:?}", req.kind));
    }
    Ok(req)
}

/// Encode a decision line (the broker → proxy direction).
pub fn encode_decision(d: &Decision) -> io::Result<String> {
    encode(d)
}

/// Decode a decision line.
pub fn decode_decision(line: &str) -> Result<Decision, String> {
    decode(line)
}

/// Encode a user-decision line (the `--decide` → broker direction).
pub fn encode_user_decision(d: &UserDecision) -> io::Result<String> {
    encode(d)
}

/// Decode a user-decision line.
pub fn decode_user_decision(line: &str) -> Result<UserDecision, String> {
    decode(line)
}

/// Read one `\n`-terminated line from `r` into `out` (the newline is
/// kept; the line is UTF-8 lossy). Rust 1.99's `BufRead` no longer
/// provides `read_line`/`read_until`, so the reader is manual:
/// chunked `read`s until a newline or EOF. A timeout on a socket with
/// `SO_RCVTIMEO` set surfaces through the underlying `read` as the
/// caller's usual I/O error.
pub fn read_line(r: &mut impl io::Read, out: &mut String) -> io::Result<usize> {
    let mut line = Vec::with_capacity(128);
    let mut chunk = [0u8; 256];
    loop {
        let n = r.read(&mut chunk)?;
        if n == 0 {
            break; // EOF: return whatever was buffered
        }
        match chunk[..n].iter().position(|b| *b == b'\n') {
            Some(rel) => {
                line.extend_from_slice(&chunk[..rel + 1]);
                out.clear();
                out.push_str(&String::from_utf8_lossy(&line));
                return Ok(line.len());
            }
            None => line.extend_from_slice(&chunk[..n]),
        }
    }
    out.clear();
    out.push_str(&String::from_utf8_lossy(&line));
    Ok(out.len())
}

/// Parse a decision keyword (`allow`/`deny`) from the CLI.
pub fn parse_decision(s: &str) -> Result<UserDecision, String> {
    match s {
        "allow" => Ok(UserDecision::Allow),
        "deny" => Ok(UserDecision::Deny),
        other => Err(format!(
            "unknown decision {other:?} (expected `allow` or `deny`)"
        )),
    }
}

/// How the broker decides when no user is in the loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoDecide {
    Allow,
    Deny,
}

/// The broker's configuration (what `main` assembles from the CLI).
pub struct BrokerArgs {
    /// Where the user's decision socket (and the `latest` pointer)
    /// live: `$XDG_RUNTIME_DIR/wlsctx`.
    pub runtime_dir: PathBuf,
    /// Skip prompting entirely (a test hook): decide every request
    /// the given way.
    pub auto_decide: Option<AutoDecide>,
    /// How long to wait for the user's decision.
    pub timeout: Duration,
}

/// Bind the broker's listening socket (the `--listen` path when not
/// socket-activated). Like the proxy's bind, a stale socket file is
/// removed first and the new one is chmod'ed 0600; unlike it, the
/// listener stays *blocking* (the broker blocks on `accept`).
pub fn bind_listener(path: &Path) -> io::Result<UnixListener> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            let _ = std::fs::remove_file(path);
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("{path:?} already exists and is not a socket"),
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    Ok(listener)
}

/// Take the socket handed by systemd socket activation (LISTEN_FDS),
/// if any.
pub fn take_activated_socket() -> Option<UnixListener> {
    sd_notify::listen_fds()
        .ok()
        .and_then(|mut it| it.next())
        .map(|fd| {
            // SAFETY: listen_fds() consumed the LISTEN_* environment
            // variables, so this process is the sole user of the fd.
            unsafe { UnixListener::from_raw_fd(fd) }
        })
}

/// Run the broker until killed: accept app-proxy connections, prompt
/// the user, answer. One request per connection (the proxy opens a
/// fresh one per ask), so the loop is accept → decide → reply.
pub fn run(args: &BrokerArgs, listener: UnixListener) -> io::Result<()> {
    if args.auto_decide.is_none() {
        let _ = std::fs::create_dir_all(&args.runtime_dir);
        // The runtime dir is user-private: the decision sockets and
        // the `latest` pointer inside must stay that way even if the
        // directory pre-existed with a looser mode.
        let _ = std::fs::set_permissions(&args.runtime_dir, std::fs::Permissions::from_mode(0o700));
    }
    info!(
        "prompt broker: deciding {} (waiting up to {} for the user)",
        match args.auto_decide {
            Some(AutoDecide::Allow) => "allow (auto)",
            Some(AutoDecide::Deny) => "deny (auto)",
            None => "by the user",
        },
        args.timeout.as_millis()
    );
    loop {
        let (stream, addr) = listener.accept().map_err(|e| {
            io::Error::other(format!("accepting on the broker socket failed: {e}"))
        })?;
        let _ = stream.set_read_timeout(Some(args.timeout));
        info!("broker request from {addr:?}");
        handle_connection(stream, args);
    }
}

/// Handle one request connection to completion. Never fails the
/// broker: a bad request gets a `deny` answer, a dead proxy a
/// dropped reply, and the loop continues. Public so that tests can
/// drive the daemon's per-connection path without its accept loop.
pub fn handle_connection(mut stream: UnixStream, args: &BrokerArgs) {
    let mut line = String::new();
    if read_line(&mut stream, &mut line).is_err() || line.is_empty() {
        warn!("broker: the request connection closed before a line; ignoring");
        return;
    }
    let req = match decode_request(&line) {
        Ok(req) => req,
        Err(e) => {
            warn!("broker: rejecting the request: {e}");
            if let Ok(answer) =
                encode_decision(&Decision::Deny {
                    reason: "protocol".into(),
                })
            {
                let _ = stream.write_all(answer.as_bytes());
            }
            return;
        }
    };
    info!(
        "clipboard consent request: app {}/{} wants to read `{}` (its own reads were never asked about)",
        req.app, req.instance, req.mime
    );

    let decision = match args.auto_decide {
        Some(AutoDecide::Allow) => Decision::Allow {
            window_ms: INTENT_WINDOW_MS,
        },
        Some(AutoDecide::Deny) => Decision::Deny {
            reason: "auto".into(),
        },
        None => decide_interactive(&req, args),
    };

    let answered = match encode_decision(&decision) {
        Ok(answer) => stream.write_all(answer.as_bytes()).is_ok(),
        Err(_) => false,
    };
    if !answered {
        // The proxy gave up on us (its own deadline expired): the
        // decision is moot, the read was dropped over there.
        warn!("broker: the request connection is gone; the {} decision is moot", decision_reason(&decision));
    } else {
        info!(
            "clipboard consent: {} ({})",
            decision_reason(&decision),
            decision_detail(&decision)
        );
    }
}

fn decision_reason(d: &Decision) -> &'static str {
    match d {
        Decision::Allow { .. } => "allow",
        Decision::Deny { .. } => "deny",
    }
}

fn decision_detail(d: &Decision) -> String {
    match d {
        Decision::Allow { window_ms } => format!("intent window {window_ms} ms"),
        Decision::Deny { reason } => format!("reason: {reason}"),
    }
}

/// The real prompt: announce the request to the desktop, wait for
/// the user's answer on a private decision socket, map it to a
/// [`Decision`] (a timeout is a deny).
fn decide_interactive(req: &ClipboardRead, args: &BrokerArgs) -> Decision {
    let path = args.runtime_dir.join(format!("broker-{}.sock", process::id()));
    let listener = match bind_decision_socket(&path) {
        Ok(l) => l,
        Err(e) => {
            warn!("broker: binding the decision socket {path:?} failed: {e}");
            return Decision::Deny {
                reason: "no-decision-socket".into(),
            };
        }
    };
    // The `latest` pointer: a keybinding that wants "the pending
    // prompt" without knowing pids reads this.
    let _ = std::fs::write(
        args.runtime_dir.join("latest"),
        path.to_string_lossy().as_bytes(),
    );

    announce(req, &path);

    // Wait for the user's answer (one connection, one line) or the
    // deadline.
    let deadline = Instant::now() + args.timeout;
    let answer = loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_default();
        if remaining.is_zero() {
            break None;
        }
        let tick = Timespec {
            tv_sec: i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: i64::from(remaining.subsec_nanos()),
        };
        // Built inside the loop: the poll fd borrows the listener,
        // and the accept below needs it mutably.
        let mut polls = [PollFd::new(&listener, PollFlags::IN)];
        match poll(&mut polls, Some(&tick)) {
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => {
                warn!("broker: polling the decision socket failed: {e}");
                break None;
            }
            Ok(0) => break None, // timeout: the user did not answer
            Ok(_) => break match listener.accept() {
                Err(e) => {
                    warn!("broker: accepting the decision failed: {e}");
                    None
                }
                Ok((mut stream, _)) => {
                    let mut line = String::new();
                    let _ = stream.set_read_timeout(Some(args.timeout));
                    if read_line(&mut stream, &mut line).is_err() || line.is_empty() {
                        warn!("broker: the decision connection closed without a line");
                        None
                    } else {
                        match decode_user_decision(&line) {
                            Ok(d) => Some(d),
                            Err(e) => {
                                warn!("broker: rejecting the decision: {e}");
                                None
                            }
                        }
                    }
                }
            },
        }
    };
    // The decision socket is one-shot; leave the file for the
    // pointer to be re-written by the next prompt (stale files are
    // removed on bind).
    drop(listener);
    match answer {
        Some(UserDecision::Allow) => Decision::Allow {
            window_ms: INTENT_WINDOW_MS,
        },
        Some(UserDecision::Deny) => Decision::Deny {
            reason: "user".into(),
        },
        None => Decision::Deny {
            reason: "timeout".into(),
        },
    }
}

/// Bind the one-shot decision socket, removing a stale file first.
fn bind_decision_socket(path: &Path) -> io::Result<UnixListener> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            let _ = std::fs::remove_file(path);
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("{path:?} exists and is not a socket"),
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    Ok(listener)
}

/// Tell the desktop about the pending request. Fire-and-forget: if
/// `notify-send` is missing or the session bus is unreachable the
/// user can still answer on the decision socket (the path is logged).
fn announce(req: &ClipboardRead, decision_path: &Path) {
    let summary = "wlsctx: clipboard consent";
    let body = format!(
        "The sandboxed app {}/{} wants to read your clipboard (`{}`).\n\
         Reply: wlsctx --decide --decision=allow   (or =deny)",
        req.app, req.instance, req.mime
    );
    info!("waiting for the user's decision on {decision_path:?}");
    match process::Command::new("notify-send")
        .args(["--app-name", "wlsctx", summary, &body])
        .spawn()
    {
        Ok(_) => {}
        Err(e) => warn!(
            "notify-send failed ({e}); the prompt is on the decision socket only"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> ClipboardRead {
        ClipboardRead {
            v: PROTOCOL_VERSION,
            kind: REQUEST_KIND.to_string(),
            app: "jetbrains".into(),
            instance: "rustrover".into(),
            mime: "text/plain".into(),
        }
    }

    #[test]
    fn request_roundtrip() {
        let r = sample_request();
        let line = encode_request(&r).unwrap();
        assert!(line.ends_with('\n'));
        assert_eq!(decode_request(&line).unwrap(), r);
    }

    #[test]
    fn request_rejects_other_versions_and_kinds() {
        let mut r = sample_request();
        r.v = 2;
        assert!(decode_request(&encode_request(&r).unwrap()).is_err());
        let mut r = sample_request();
        r.kind = "something-else".into();
        assert!(decode_request(&encode_request(&r).unwrap()).is_err());
    }

    #[test]
    fn decision_roundtrip() {
        let a = Decision::Allow { window_ms: INTENT_WINDOW_MS };
        let d = Decision::Deny {
            reason: "timeout".into(),
        };
        assert_eq!(decode_decision(&encode_decision(&a).unwrap()).unwrap(), a);
        assert_eq!(decode_decision(&encode_decision(&d).unwrap()).unwrap(), d);
        // The on-the-wire shape: tagged enum, snake_case.
        assert_eq!(
            encode_decision(&a).unwrap().trim(),
            r#"{"decision":"allow","window_ms":1500}"#
        );
    }

    #[test]
    fn user_decision_roundtrip() {
        assert_eq!(
            decode_user_decision(&encode_user_decision(&UserDecision::Allow).unwrap()).unwrap(),
            UserDecision::Allow
        );
        assert_eq!(
            encode_user_decision(&UserDecision::Deny).unwrap().trim(),
            r#"{"decision":"deny"}"#
        );
        assert!(decode_user_decision("nonsense").is_err());
    }

    #[test]
    fn parse_decision_cli() {
        assert_eq!(parse_decision("allow").unwrap(), UserDecision::Allow);
        assert_eq!(parse_decision("deny").unwrap(), UserDecision::Deny);
        assert!(parse_decision("maybe").is_err());
    }
}
