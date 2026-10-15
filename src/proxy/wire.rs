//! Standalone Wayland wire codec for the transparent proxy.
//!
//! A port of wayland-backend's `rs/wire.rs` (`parse_message` /
//! `write_to_buffers`), kept self-contained because the proxy sits
//! between an app (a Wayland client) and a compositor (a Wayland server)
//! and belongs to neither side, so it cannot use either backend's
//! object map. The signature tables come from [`crate::proxy::interfaces`].
//!
//! Wire format (little-endian):
//! ```text
//! u32  sender_id          // the object the message is addressed to
//! u32  (len << 16) | opcode
//! u32  arg...             // Int/Uint/Fixed/Object/NewId
//! u32  str/array length   // + bytes + NUL (str) + 4-byte padding
//!                          // Fd arguments carry no bytes: they are
//!                          // passed out-of-band as SCM_RIGHTS and
//!                          // consumed in signature order.
//! ```
//! `len` is the total message size in bytes, including this 8-byte
//! header, so a message with no arguments has `len == 8`.

use std::collections::VecDeque;
use std::ffi::CStr;
use std::fmt;
use std::os::fd::OwnedFd;

use wayland_backend::protocol::{Argument, ArgumentType, Message};

/// Size of the message header: `sender_id` + `(len << 16) | opcode`.
pub const HEADER_SIZE: usize = 2 * 4;

/// Error produced while inspecting or serializing Wayland wire data.
#[derive(Debug)]
pub enum Error {
    /// The stream does not contain a complete message yet.
    Incomplete,
    /// A message references a file descriptor that has not arrived yet.
    MissingFd,
    /// A message is malformed, or violates a rule the proxy enforces.
    Malformed(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete => write!(f, "incomplete message on the wire"),
            Self::MissingFd => write!(f, "message references a fd that has not arrived"),
            Self::Malformed(msg) => write!(f, "malformed message: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

/// Length in bytes of the message at the head of `raw`, if the header is
/// complete and well-formed.
///
/// `None` is returned when fewer than [`HEADER_SIZE`] bytes are present,
/// or when the declared length is shorter than a header (a message with
/// no arguments still declares `8`).
pub fn message_len(raw: &[u8]) -> Option<usize> {
    if raw.len() < HEADER_SIZE {
        return None;
    }
    let word2 = u32::from_le_bytes(raw[4..8].try_into().unwrap());
    let len = (word2 >> 16) as usize;
    (len >= HEADER_SIZE).then_some(len)
}

/// Attempt to parse a single Wayland message with the given signature.
///
/// If `raw` contains several messages, only the first one is parsed and
/// the unused tail is returned. Fd arguments are consumed in signature
/// order from `fds` (out-of-band SCM_RIGHTS, see the module docs).
///
/// Ported from `wayland_backend::rs::wire::parse_message`.
pub fn parse_message<'a>(
    raw: &'a [u8],
    signature: &[ArgumentType],
    fds: &mut VecDeque<OwnedFd>,
) -> Result<(Message<u32, OwnedFd>, &'a [u8]), Error> {
    // Helper function to read arrays
    fn read_array_from_payload(array_len: usize, payload: &[u8]) -> Result<(&[u8], &[u8]), Error> {
        let len = next_multiple_of(array_len, 4);
        if len > payload.len() {
            return Err(Error::Incomplete);
        }
        Ok((&payload[..array_len], &payload[len..]))
    }

    let len = match message_len(raw) {
        Some(l) if l <= raw.len() => l,
        _ => return Err(Error::Incomplete),
    };

    let sender_id = u32::from_le_bytes(raw[0..4].try_into().unwrap());
    let word_2 = u32::from_le_bytes(raw[4..8].try_into().unwrap());
    let opcode = (word_2 & 0xFFFF) as u16;

    let (mut payload, rest) = raw.split_at(len);
    payload = &payload[HEADER_SIZE..];

    let arguments = signature
        .iter()
        .map(|argtype| {
            if let ArgumentType::Fd = *argtype {
                // don't consume input but fd
                if let Some(front) = fds.pop_front() {
                    Ok(Argument::Fd(front))
                } else {
                    Err(Error::MissingFd)
                }
            } else if payload.len() >= 4 {
                let (front, mut tail) = payload.split_at(4);
                let front = u32::from_le_bytes(front.try_into().unwrap());
                let arg = match *argtype {
                    ArgumentType::Int => Ok(Argument::Int(front as i32)),
                    ArgumentType::Uint => Ok(Argument::Uint(front)),
                    ArgumentType::Fixed => Ok(Argument::Fixed(front as i32)),
                    ArgumentType::Str(_) => {
                        read_array_from_payload(front as usize, tail).and_then(|(v, r)| {
                            tail = r;
                            if v.is_empty() {
                                Ok(Argument::Str(None))
                            } else {
                                match CStr::from_bytes_with_nul(v) {
                                    Ok(s) => Ok(Argument::Str(Some(Box::new(s.into())))),
                                    Err(_) => Err(Error::Malformed(
                                        "string argument is not NUL-terminated".into(),
                                    )),
                                }
                            }
                        })
                    }
                    ArgumentType::Object(_) => Ok(Argument::Object(front)),
                    ArgumentType::NewId => Ok(Argument::NewId(front)),
                    ArgumentType::Array => {
                        read_array_from_payload(front as usize, tail).map(|(v, r)| {
                            tail = r;
                            Argument::Array(Box::new(v.into()))
                        })
                    }
                    ArgumentType::Fd => unreachable!(),
                };
                payload = tail;
                arg
            } else {
                Err(Error::Incomplete)
            }
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let msg = Message {
        sender_id,
        opcode,
        args: arguments.into(),
    };
    Ok((msg, rest))
}

/// Serialize the contents of a message into `payload`.
///
/// Returns the number of bytes written (including the header). Fd
/// arguments are cloned (dup'd) into `out_fds` in signature order and
/// must be passed to the peer via SCM_RIGHTS (see
/// [`crate::proxy::send_msg`]).
///
/// Ported from `wayland_backend::rs::wire::write_to_buffers` (which dups
/// raw fds; here the owned fds are cloned instead — the dup happens in
/// either case, the fd value never leaves `out_fds` without one).
pub fn write_message(
    msg: &Message<u32, OwnedFd>,
    _signature: &[ArgumentType],
    payload: &mut [u8],
    out_fds: &mut Vec<OwnedFd>,
) -> Result<usize, Error> {
    let orig_payload_len = payload.len();

    // Helper function to write a u32 to its buffer
    fn write_buf(u: u32, payload: &mut [u8]) -> Result<&mut [u8], Error> {
        if payload.len() >= 4 {
            let (head, tail) = payload.split_at_mut(4);
            head.copy_from_slice(&u.to_ne_bytes());
            Ok(tail)
        } else {
            Err(Error::Malformed("write buffer too small".into()))
        }
    }

    // Helper function to write byte arrays in payload
    fn write_array_to_payload<'a>(
        array: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a mut [u8], Error> {
        // size header
        let payload = write_buf(array.len() as u32, payload)?;

        // Handle padding
        let len = next_multiple_of(array.len(), 4);

        if payload.len() < len {
            return Err(Error::Malformed("write buffer too small".into()));
        }

        let (buffer_slice, rest) = payload.split_at_mut(len);
        buffer_slice[..array.len()].copy_from_slice(array);
        Ok(rest)
    }

    if payload.len() < HEADER_SIZE {
        return Err(Error::Malformed("write buffer too small".into()));
    }
    let (header, mut payload) = payload.split_at_mut(HEADER_SIZE);

    for arg in &msg.args {
        payload = match arg {
            Argument::Int(i) => write_buf(*i as u32, payload)?,
            Argument::Uint(u) => write_buf(*u, payload)?,
            Argument::Fixed(f) => write_buf(*f as u32, payload)?,
            Argument::Str(Some(s)) => write_array_to_payload(s.as_bytes_with_nul(), payload)?,
            Argument::Str(None) => write_array_to_payload(&[], payload)?,
            Argument::Object(o) => write_buf(*o, payload)?,
            Argument::NewId(n) => write_buf(*n, payload)?,
            Argument::Array(a) => write_array_to_payload(a, payload)?,
            Argument::Fd(fd) => {
                out_fds.push(
                    fd.try_clone()
                        .map_err(|e| Error::Malformed(e.to_string()))?,
                );
                payload
            }
        };
    }

    let wrote_size = orig_payload_len - payload.len();
    header[..4].copy_from_slice(&msg.sender_id.to_ne_bytes());
    header[4..]
        .copy_from_slice(&(((wrote_size as u32) << 16) | u32::from(msg.opcode)).to_ne_bytes());
    Ok(wrote_size)
}

// Stabilized in Rust 1.73
fn next_multiple_of(lhs: usize, rhs: usize) -> usize {
    match lhs % rhs {
        0 => lhs,
        r => lhs + (rhs - r),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use wayland_backend::protocol::AllowNull;

    fn sig() -> Vec<ArgumentType> {
        vec![
            ArgumentType::Uint,
            ArgumentType::Fixed,
            ArgumentType::Str(AllowNull::No),
            ArgumentType::Array,
            ArgumentType::Object(AllowNull::No),
            ArgumentType::NewId,
            ArgumentType::Int,
            ArgumentType::Fd,
        ]
    }

    #[test]
    fn message_len_roundtrip() {
        // no-arg message: header only
        let mut buf = [0u8; HEADER_SIZE];
        buf[4..8].copy_from_slice(&((8u32) << 16 | 42).to_le_bytes());
        assert_eq!(message_len(&buf), Some(HEADER_SIZE));
        // truncated header
        assert_eq!(message_len(&buf[..7]), None);
        // declared length shorter than a header is malformed
        buf[4..8].copy_from_slice(&((4u32) << 16 | 1).to_le_bytes());
        assert_eq!(message_len(&buf), None);
        // 3-arg message: 8 + 12
        buf[4..8].copy_from_slice(&((20u32) << 16 | 7).to_le_bytes());
        assert_eq!(message_len(&buf), Some(20));
    }

    #[test]
    fn roundtrip_without_fds() {
        let mut bytes = vec![0; 4096];
        let mut fds = Vec::new();
        let msg = Message {
            sender_id: 42,
            opcode: 7,
            args: vec![
                Argument::Uint(3),
                Argument::Fixed(-89),
                Argument::Str(Some(Box::new(CString::new(b"I like trains!").unwrap()))),
                Argument::Array(vec![1, 2, 3, 4, 5, 6, 7, 8, 9].into()),
                Argument::Object(88),
                Argument::NewId(56),
                Argument::Int(-25),
            ]
            .into(),
        };
        let n = write_message(&msg, &sig()[..7], &mut bytes, &mut fds).unwrap();
        assert!(fds.is_empty());
        let mut fdsq = VecDeque::new();
        let (rebuilt, rest) = parse_message(&bytes[..n], &sig()[..7], &mut fdsq).expect("parse");
        assert!(rest.is_empty());
        assert_eq!(rebuilt.sender_id, 42);
        assert_eq!(rebuilt.opcode, 7);
        assert_eq!(rebuilt.args.len(), 7);
        assert_eq!(rebuilt.args[0], Argument::Uint(3));
        assert_eq!(rebuilt.args[1], Argument::Fixed(-89));
        assert_eq!(
            rebuilt.args[2],
            Argument::Str(Some(Box::new(CString::new(b"I like trains!").unwrap())))
        );
        assert_eq!(
            rebuilt.args[3],
            Argument::Array(vec![1, 2, 3, 4, 5, 6, 7, 8, 9].into())
        );
        assert_eq!(rebuilt.args[4], Argument::Object(88));
        assert_eq!(rebuilt.args[5], Argument::NewId(56));
        assert_eq!(rebuilt.args[6], Argument::Int(-25));
    }

    #[test]
    fn roundtrip_with_fd() {
        let (r, w) = pipe();
        let mut bytes = vec![0; 64];
        let mut out = Vec::new();
        // wl_data_source.send(mime, fd)
        let msg = Message {
            sender_id: 11,
            opcode: 1,
            args: vec![
                Argument::Str(Some(Box::new(CString::new(b"text/plain").unwrap()))),
                Argument::Fd(w),
            ]
            .into(),
        };
        let n = write_message(&msg, &sig_of_send(), &mut bytes, &mut out).unwrap();
        assert_eq!(out.len(), 1);
        // parse it back, consuming the fd
        let mut fdsq = VecDeque::new();
        fdsq.push_back(out.pop().unwrap());
        let (rebuilt, rest) = parse_message(&bytes[..n], &sig_of_send(), &mut fdsq).expect("parse");
        assert!(rest.is_empty());
        assert_eq!(
            rebuilt.args[0],
            Argument::Str(Some(Box::new(CString::new(b"text/plain").unwrap())))
        );
        assert!(matches!(rebuilt.args[1], Argument::Fd(_)));
        let _ = r;
    }

    fn sig_of_send() -> Vec<ArgumentType> {
        vec![ArgumentType::Str(AllowNull::No), ArgumentType::Fd]
    }

    #[test]
    fn partial_stream_frames_messages() {
        // Two messages back to back; the second is truncated in the first
        // "recvmsg", completed by the next.
        let mut stream = Vec::new();
        let a = Message {
            sender_id: 1,
            opcode: 0,
            args: vec![Argument::Uint(5)].into(),
        };
        let b = Message {
            sender_id: 2,
            opcode: 3,
            args: vec![].into(),
        };
        let mut tmp = [0u8; 64];
        let mut nofds = Vec::new();
        let na = write_message(&a, &[ArgumentType::Uint], &mut tmp, &mut nofds).unwrap();
        stream.extend_from_slice(&tmp[..na]);
        let nb = write_message(&b, &[], &mut tmp, &mut nofds).unwrap();
        stream.extend_from_slice(&tmp[..nb]);

        // first "recvmsg" delivers everything except the last byte
        let (first, tail) = stream.split_at(stream.len() - 1);
        // message A is complete, B is not
        assert_eq!(message_len(first), Some(na));
        let mut rem = first;
        let (msg, rest) = parse_message(rem, &[ArgumentType::Uint], &mut VecDeque::new()).unwrap();
        assert_eq!(msg.sender_id, 1);
        assert_eq!(msg.args[0], Argument::Uint(5));
        rem = rest;
        // message B: incomplete until the last byte arrives
        let mut combined = rem.to_vec();
        assert_eq!(message_len(&combined), None);
        combined.extend_from_slice(tail);
        assert_eq!(message_len(&combined), Some(nb));
        let (msg, rest) = parse_message(&combined, &[], &mut VecDeque::new()).unwrap();
        assert_eq!(msg.sender_id, 2);
        assert!(rest.is_empty());
    }

    fn pipe() -> (OwnedFd, OwnedFd) {
        let (r, w) = std::io::pipe().unwrap();
        (r.into(), w.into())
    }
}
