//! End-to-end tests of the broker's session decision socket: the
//! real `wlsctx --broker` binary (interactive mode) bound by a
//! subprocess. These drive the *daemon's* side of the protocol with
//! raw N-D-JSON decider sessions (the `--decide` CLI is a thin
//! wrapper over the same lines) and the *proxy's* side with held
//! open `clipboard-read` connections, so they cover what the
//! per-thread, poll-driven run loop promises:
//!
//! 1. several prompts can be pending at once (the old serial loop
//!    parked on the first consent and could not even accept the
//!    next request);
//! 2. the pending prompts are listed, oldest first, with their ids;
//! 3. a prompt is resolved by id (or the oldest, untargeted), and
//!    the waiting proxy receives the answer;
//! 4. a prompt no one answers expires: the proxy gets a
//!    `deny/timeout` and the prompt leaves the queue;
//! 5. decides with nothing to resolve are refused with a reason.

use std::io::Write as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

use wlsctx::broker::{
    ClipboardRead, Decision, UserDecision, decode_decision, decode_error_reply,
    decode_pending_list, decode_resolution, encode_decide_request, encode_request, read_line,
};

/// A spawned broker the tests can't outlive (killed on drop, even on
/// a panic mid-test).
struct Broker(Option<Child>);

impl Drop for Broker {
    fn drop(&mut self) {
        if let Some(c) = self.0.as_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn broker_socket(xdg: &Path) -> PathBuf {
    xdg.join("broker.sock")
}

fn decision_socket(xdg: &Path) -> PathBuf {
    xdg.join("wlsctx").join(wlsctx::broker::DECISION_SOCKET)
}

fn wait_for_file(path: &Path) {
    let started = Instant::now();
    while !path.exists() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "timed out waiting for {path:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Spawn `wlsctx --broker --listen <xdg>/broker.sock` in a private
/// runtime dir; wait for both sockets (the broker's and the session
/// decision socket, which proves interactive mode bound it).
fn spawn_broker(xdg: &TempDir, timeout_ms: u64) -> Broker {
    let dir = xdg.path();
    std::fs::create_dir_all(dir).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_wlsctx"))
        .args([
            "--broker",
            "--listen",
            broker_socket(dir).to_str().unwrap(),
            "--broker-timeout-millis",
            &timeout_ms.to_string(),
        ])
        .env("XDG_RUNTIME_DIR", dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawning the wlsctx broker failed");
    wait_for_file(&broker_socket(dir));
    wait_for_file(&decision_socket(dir));
    Broker(Some(child))
}

/// One decider session on the decision socket (what
/// `wlsctx --decide` does): one request line, one reply line.
fn decider_request(xdg: &Path, request: &str) -> String {
    let mut stream =
        UnixStream::connect(decision_socket(xdg)).expect("connecting to the decision socket");
    stream
        .write_all(request.as_bytes())
        .expect("writing the decider request");
    let mut line = String::new();
    read_line(&mut stream, &mut line).expect("reading the decider reply");
    line
}

fn pending_prompts(xdg: &Path) -> Vec<wlsctx::broker::PendingPromptView> {
    let reply = decider_request(xdg, &wlsctx::broker::encode_list_request().unwrap());
    decode_pending_list(&reply)
        .expect("the list reply should decode")
        .prompts
}

/// One held-open proxy consent request (the line a relay would send
/// when its gate drops a foreign read).
fn proxy_read_request(stream: &mut UnixStream, app: &str, instance: &str, mime: &str) {
    let req = ClipboardRead {
        v: wlsctx::broker::PROTOCOL_VERSION,
        kind: wlsctx::broker::REQUEST_KIND.to_string(),
        app: app.into(),
        instance: instance.into(),
        mime: mime.into(),
        selection: "clipboard".into(),
    };
    stream
        .write_all(encode_request(&req).unwrap().as_bytes())
        .unwrap();
}

/// Read the broker's answer to a consent request (the connection
/// closes with it).
fn proxy_decision(stream: &mut UnixStream) -> Decision {
    let mut line = String::new();
    read_line(stream, &mut line).expect("reading the broker's answer");
    decode_decision(&line).expect("the answer should decode")
}

fn wait_until(cond: impl Fn() -> bool) {
    let started = Instant::now();
    while !cond() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "timed out waiting for the condition"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The heart of the change: two prompts pending at once, listed in
/// arrival order, resolved by id and untargeted, then the queue
/// empty and further decides refused.
#[test]
fn multi_prompt_session_is_listed_and_decided() {
    let xdg = TempDir::new().unwrap();
    let _broker = spawn_broker(&xdg, 3000);
    let dir = xdg.path();

    // Two dropped reads from two different apps, held open.
    let mut a = UnixStream::connect(broker_socket(dir)).unwrap();
    proxy_read_request(&mut a, "app-a", "inst-a", "text/plain");
    let mut b = UnixStream::connect(broker_socket(dir)).unwrap();
    proxy_read_request(&mut b, "app-b", "inst-b", "text/uri-list");

    // The queue fills as the connections' threads register; wait
    // (bounded) until both prompts are pending.
    wait_until(|| pending_prompts(dir).len() == 2);
    let list = pending_prompts(dir);
    assert_eq!(
        list.iter().map(|p| p.id).collect::<Vec<_>>(),
        vec![1, 2],
        "the listing is in arrival order (oldest first)"
    );
    assert_eq!(
        (list[0].app.as_str(), list[0].mime.as_str()),
        ("app-a", "text/plain")
    );
    assert_eq!(
        (list[1].app.as_str(), list[1].mime.as_str()),
        ("app-b", "text/uri-list")
    );
    // Each prompt has (roughly) its full deadline left.
    assert!(list[0].expires_in_ms >= 2_500);
    assert!(list[1].expires_in_ms >= 2_500);

    // Resolve prompt 1 by id (allow); its proxy gets the answer.
    let reply = decider_request(
        dir,
        &encode_decide_request(&UserDecision::Allow, Some(1)).unwrap(),
    );
    let resolved = decode_resolution(&reply).unwrap();
    assert_eq!((resolved.prompt, resolved.decision.as_str()), (1, "allow"));
    assert_eq!(
        proxy_decision(&mut a),
        Decision::Allow {
            window_ms: wlsctx::broker::INTENT_WINDOW_MS
        }
    );

    // Prompt 2 is still pending: a list now shows just it.
    let list = pending_prompts(dir);
    assert_eq!(list.iter().map(|p| p.id).collect::<Vec<_>>(), vec![2]);

    // Untargeted decide resolves the oldest remaining (deny); its
    // proxy gets the answer too.
    let reply = decider_request(
        dir,
        &encode_decide_request(&UserDecision::Deny, None).unwrap(),
    );
    let resolved = decode_resolution(&reply).unwrap();
    assert_eq!((resolved.prompt, resolved.decision.as_str()), (2, "deny"));
    assert_eq!(
        proxy_decision(&mut b),
        Decision::Deny {
            reason: "user".into()
        }
    );

    // The queue is empty; further decides are refused with reasons.
    wait_until(|| pending_prompts(dir).is_empty());
    let reply = decider_request(
        dir,
        &encode_decide_request(&UserDecision::Allow, None).unwrap(),
    );
    let err = decode_error_reply(&reply).unwrap();
    assert_eq!(err.reason, wlsctx::broker::REASON_NO_PENDING);
    let reply = decider_request(
        dir,
        &encode_decide_request(&UserDecision::Allow, Some(9)).unwrap(),
    );
    let err = decode_error_reply(&reply).unwrap();
    assert_eq!(err.reason, wlsctx::broker::REASON_UNKNOWN_PROMPT);
    assert_eq!(err.prompt, Some(9));
}

/// A prompt no one answers: the proxy gets `deny/timeout` and the
/// prompt leaves the queue (the queue is usable again afterwards).
#[test]
fn an_unanswered_prompt_times_out_and_leaves_the_queue() {
    let xdg = TempDir::new().unwrap();
    let _broker = spawn_broker(&xdg, 300);
    let dir = xdg.path();

    let mut a = UnixStream::connect(broker_socket(dir)).unwrap();
    proxy_read_request(&mut a, "app-a", "inst-a", "text/plain");
    wait_until(|| pending_prompts(dir).len() == 1);

    // The deadline passes without a decision: the proxy is denied.
    a.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(
        proxy_decision(&mut a),
        Decision::Deny {
            reason: "timeout".into()
        }
    );
    wait_until(|| pending_prompts(dir).is_empty());

    // The session socket is still serviceable afterwards.
    assert!(pending_prompts(dir).is_empty());
}

/// Before any prompt exists: the list is empty and decides are
/// refused (no-pending / unknown-prompt) — the socket is bound for
/// the life of the session, not per prompt.
#[test]
fn decides_before_any_prompt_are_refused() {
    let xdg = TempDir::new().unwrap();
    let _broker = spawn_broker(&xdg, 3000);
    let dir = xdg.path();

    assert!(pending_prompts(dir).is_empty());
    let reply = decider_request(
        dir,
        &encode_decide_request(&UserDecision::Allow, None).unwrap(),
    );
    let err = decode_error_reply(&reply).unwrap();
    assert_eq!(err.reason, wlsctx::broker::REASON_NO_PENDING);
    let reply = decider_request(
        dir,
        &encode_decide_request(&UserDecision::Allow, Some(3)).unwrap(),
    );
    let err = decode_error_reply(&reply).unwrap();
    assert_eq!(err.reason, wlsctx::broker::REASON_UNKNOWN_PROMPT);
    assert_eq!(err.prompt, Some(3));
}
