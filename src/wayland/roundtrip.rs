//! A `wl_display.sync` roundtrip that cannot block forever.

use crate::wayland::context::State;
use anyhow::{Context, Result, bail};
use std::io;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use wayland_client::{
    Connection, EventQueue,
    backend::WaylandError,
};

/// How long to wait for the compositor to answer the security-context
/// commit before giving up. Deliberately far below systemd's default
/// `TimeoutStartSec` (90s), so wlsctx itself reports the reason for the
/// failure instead of being SIGKILLed by the service manager.
pub const ROUNDTRIP_TIMEOUT: Duration = Duration::from_secs(10);

/// A `wl_display.sync` roundtrip that cannot block forever.
///
/// `EventQueue::roundtrip()` parks in a plain blocking read(2) until the
/// compositor fires the sync callback: a compositor that accepts the
/// connection and then wedges keeps wlsctx in that read until systemd's
/// `TimeoutStartSec` SIGKILLs it, with no diagnostic. This function does
/// the same protocol exchange (send `wl_display.sync`, wait for its
/// `done` callback, dispatching everything in between) but bounds every
/// wait on the socket with `poll(2)` against `deadline`: a compositor
/// that does not answer fails the service with a clear error well before
/// the manager's kill timer.
///
/// The one remaining unbounded wait is the library-internal registry
/// roundtrip inside `registry_queue_init`, which runs immediately after
/// the connection is established; a compositor dead at that instant is a
/// pathological case that `TimeoutStartSec` still covers.
pub(crate) fn bounded_roundtrip(
    conn: &Connection,
    queue: &mut EventQueue<State>,
    data: &mut State,
    deadline: Instant,
) -> Result<()> {
    let done = Arc::new(AtomicBool::new(false));
    // The generated constructor attaches `done` as the callback's user
    // data; `State`'s `Dispatch<WlCallback, _>` impl flips it on `done`.
    conn.display().sync(&queue.handle(), done.clone());

    let start = Instant::now();
    loop {
        queue
            .dispatch_pending(data)
            .context("dispatching Wayland events")?;
        if done.load(Ordering::Relaxed) {
            return Ok(());
        }
        queue
            .flush()
            .context("flushing the security-context commit to the compositor")?;
        let guard = match queue.prepare_read() {
            Some(guard) => guard,
            // Events are already buffered: go back to dispatching them.
            None => continue,
        };
        let now = Instant::now();
        if now >= deadline {
            return Err(roundtrip_timeout_error(conn, start));
        }
        let mut pfd = libc::pollfd {
            fd: guard.connection_fd().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` is a fully initialised, valid `struct pollfd` and
        // the nfds argument matches it; the borrow on the connection fd
        // lives for the duration of the call.
        let r = unsafe {
            libc::poll(
                &mut pfd,
                1,
                deadline.duration_since(now).as_millis() as libc::c_int,
            )
        };
        let err = io::Error::last_os_error();
        match r {
            0 => return Err(roundtrip_timeout_error(conn, start)),
            -1 if err.raw_os_error() == Some(libc::EINTR) => continue,
            -1 => bail!("polling the Wayland socket failed: {err}"),
            _ => {}
        }
        match guard.read() {
            Ok(_) => {}
            // Spurious readiness: nothing to consume, wait again.
            Err(WaylandError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => {
                let mut err = anyhow::anyhow!(
                    "the Wayland connection failed while waiting for the \
                     security-context commit: {e}"
                );
                if let Some(pe) = conn.protocol_error() {
                    err = err.context(format!("protocol error from the compositor: {pe}"));
                }
                return Err(err);
            }
        }
    }
}

fn roundtrip_timeout_error(conn: &Connection, start: Instant) -> anyhow::Error {
    let waited = (Instant::now() - start).as_secs_f64().max(1.0);
    let mut msg = format!(
        "the compositor did not answer the security-context commit within \
         ~{waited:.0}s: it is unresponsive (check the compositor log); the tagged \
         socket is in an inconsistent state and the app must not start"
    );
    if let Some(pe) = conn.protocol_error() {
        msg = format!("{msg} — last compositor protocol error: {pe}");
    }
    anyhow::anyhow!("{msg}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    /// A `wayland_client` connection whose peer accepts but never sends
    /// anything: the unresponsive-compositor case.
    fn unresponsive_wayland_peer() -> (Connection, UnixStream) {
        let (client, peer) = UnixStream::pair().expect("socketpair");
        (
            Connection::from_socket(client).expect("connection from socket"),
            peer,
        )
    }

    #[test]
    fn roundtrip_times_out_when_the_compositor_is_unresponsive() {
        // Without the poll(2) deadline, `EventQueue::roundtrip` would park
        // in a blocking read(2) forever in this situation.
        let (conn, _peer) = unresponsive_wayland_peer();
        let mut queue = conn.new_event_queue();
        let start = Instant::now();
        let err = bounded_roundtrip(
            &conn,
            &mut queue,
            &mut State {},
            start + Duration::from_millis(250),
        )
        .expect_err("the roundtrip must time out");
        let msg = err.to_string();
        assert!(msg.contains("did not answer"), "unexpected error: {msg}");
        assert!(msg.contains("unresponsive"), "unexpected error: {msg}");
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "timed out too slowly: {elapsed:?}"
        );
    }

    #[test]
    fn roundtrip_completes_when_the_compositor_answers() {
        // A minimal raw-Wayland compositor: read the `wl_display.sync`
        // request (opcode 0, one new-object argument) and answer it with
        // `wl_callback.done(serial)` on the object the client assigned.
        let (client, mut server) = UnixStream::pair().expect("socketpair");
        let conn = Connection::from_socket(client).expect("connection from socket");
        let mut queue = conn.new_event_queue();
        // Blocking read of exactly `buf.len()` bytes; false on peer close.
        fn read_n(server: &mut UnixStream, buf: &mut [u8]) -> bool {
            let mut filled = 0;
            while filled < buf.len() {
                match Read::read(server, &mut buf[filled..]) {
                    Ok(0) => return false, // EOF: the peer closed the connection
                    Ok(n) => filled += n,
                    Err(_) => return false,
                }
            }
            true
        }
        let responder = std::thread::spawn(move || {
            // Minimal raw-Wayland server. Wire format (wayland-backend 0.3):
            // [u32 sender_id][u32 (message_size_in_bytes << 16) | opcode][args...]
            // `sync` is opcode 0 of wl_display with one argument: the id of
            // the callback object the client assigned. The answer is
            // `wl_callback.done(serial)`, opcode 0 of wl_callback. After
            // replying, the loop keeps reading until the client closes its
            // end, so this thread exits when the test drops the client
            // socket — it must not be joined until that happens, or it
            // deadlocks on `recv()`.
            let mut header = [0u8; 8];
            loop {
                if !read_n(&mut server, &mut header) {
                    break;
                }
                let word_2 = u32::from_ne_bytes(header[4..8].try_into().unwrap());
                let size = ((word_2 >> 16) as usize).max(8);
                let opcode = (word_2 & 0xFFFF) as u16;
                let mut args = vec![0u8; size - 8];
                if !read_n(&mut server, &mut args) {
                    break;
                }
                if opcode != 0 {
                    continue; // no reply expected
                }
                let callback_id = u32::from_ne_bytes(args[0..4].try_into().unwrap());
                let mut out = [0u8; 12];
                out[0..4].copy_from_slice(&callback_id.to_ne_bytes());
                // Word 2 = (total_size << 16) | opcode. The done frame is
                // 12 bytes (8-byte header + one u32) with opcode 0.
                out[4..8].copy_from_slice(&(12u32 << 16).to_ne_bytes());
                out[8..12].copy_from_slice(&42u32.to_ne_bytes()); // done(serial=42)
                Write::write_all(&mut server, &out).expect("write the reply");
            }
        });
        bounded_roundtrip(
            &conn,
            &mut queue,
            &mut State {},
            Instant::now() + Duration::from_secs(5),
        )
        .expect("a responsive compositor must complete the roundtrip");
        // Close the client socket so the responder's `recv()` sees EOF and
        // the `join()` below can return. The Wayland backend owns the socket
        // through an `Arc` that is shared between the `Connection` and the
        // `EventQueue`, so the queue must be dropped first to release the
        // last reference; dropping only `conn` would leave the socket open.
        drop(queue);
        drop(conn);
        responder.join().expect("responder");
    }
}
