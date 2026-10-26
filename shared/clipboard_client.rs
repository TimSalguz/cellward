//! Nonblocking client of an already-scoped private clipboard FD.
//! No socket path, instance selector, host fallback or registration operation.
//! The controller must authenticate/bind the endpoint before handing it here.
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const CONTENT: usize = 64 << 20;
const FRAME: usize = CONTENT + 32 * 1024;
const QUANTUM: usize = 64 << 10;
const TIMEOUT: Duration = Duration::from_secs(5);

pub fn erase_slice(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Selection {
    Clipboard,
    Primary,
}

pub enum Request<'a> {
    Types,
    Set(&'a [(&'a str, &'a [u8])]),
    Read { revision: u64, mime: &'a str },
    Clear,
}

/// Payloads are never printed by Debug and are erased through spare capacity.
#[derive(Default)]
pub struct Bytes(Vec<u8>);
impl Bytes {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    pub fn allocated(&self) -> usize {
        self.0.capacity()
    }
    pub fn append(&mut self, bytes: &[u8], limit: usize) -> io::Result<()> {
        let limit = limit.min(CONTENT);
        if self.0.len().saturating_add(bytes.len()) > limit {
            return Err(invalid());
        }
        self.0
            .try_reserve_exact(bytes.len())
            .map_err(|_| io::Error::other("clipboard allocation limit"))?;
        if self.0.capacity() > limit {
            return Err(invalid());
        }
        self.0.extend_from_slice(bytes);
        Ok(())
    }
    fn clear(&mut self) {
        for at in 0..self.0.capacity() {
            // SAFETY: initialize only this Vec's owned u8 allocation,
            // including spare capacity that may contain truncated payloads.
            unsafe { std::ptr::write_volatile(self.0.as_mut_ptr().add(at), 0) };
        }
        self.0.clear();
    }
}
impl Drop for Bytes {
    fn drop(&mut self) {
        self.clear();
    }
}
impl std::fmt::Debug for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<redacted {} bytes>", self.0.len())
    }
}

#[derive(Debug)]
pub enum Reply {
    Types(Option<(u64, Vec<String>)>),
    Set(u64),
    Data(Bytes),
    Cleared,
    /// Valid protocol refusal, not a reason to consult the host clipboard.
    Rejected(u8),
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid private clipboard frame",
    )
}
fn valid_mime(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && !s.chars().any(char::is_control)
        && !s.starts_with("application/x-cellward-clip-")
}

pub struct Client {
    stream: UnixStream,
    output: Bytes,
    written: usize,
    header: [u8; 4],
    head: usize,
    input: Bytes,
    read: usize,
    opcode: u8,
    deadline: Option<Instant>,
    closed: bool,
}

impl Client {
    pub fn new(stream: UnixStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            output: Bytes::default(),
            written: 0,
            header: [0; 4],
            head: 0,
            input: Bytes::default(),
            read: 0,
            opcode: 0,
            deadline: None,
            closed: false,
        })
    }
    pub fn socket(&self) -> BorrowedFd<'_> {
        self.stream.as_fd()
    }
    pub fn wants_write(&self) -> bool {
        self.deadline.is_some() && self.written < self.output.0.len()
    }
    pub fn next_deadline(&self) -> Option<Instant> {
        self.deadline
    }
    pub fn busy(&self) -> bool {
        self.deadline.is_some()
    }
    pub fn closed(&self) -> bool {
        self.closed
    }

    pub fn start(
        &mut self,
        selection: Selection,
        request: Request<'_>,
        now: Instant,
    ) -> io::Result<()> {
        if self.closed {
            return Err(io::Error::from(io::ErrorKind::NotConnected));
        }
        if self.busy() {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let opcode = match &request {
            Request::Types => 1,
            Request::Set(_) => 2,
            Request::Read { .. } => 3,
            Request::Clear => 4,
        };
        let mut length = 2usize;
        match &request {
            Request::Set(parts) => {
                if !(1..=64).contains(&parts.len()) {
                    return Err(invalid());
                }
                let mut total = 0usize;
                length += 2;
                for (i, (mime, data)) in parts.iter().enumerate() {
                    if !valid_mime(mime) || parts[..i].iter().any(|(m, _)| m == mime) {
                        return Err(invalid());
                    }
                    total = total.checked_add(data.len()).ok_or_else(invalid)?;
                    length = length
                        .checked_add(6 + mime.len())
                        .and_then(|n| n.checked_add(data.len()))
                        .ok_or_else(invalid)?;
                }
                if total > CONTENT {
                    return Err(invalid());
                }
            }
            Request::Read { revision, mime } => {
                if *revision == 0 || !valid_mime(mime) {
                    return Err(invalid());
                }
                length += 10 + mime.len();
            }
            _ => {}
        }
        if length > FRAME {
            return Err(invalid());
        }
        self.output
            .0
            .try_reserve_exact(length + 4)
            .map_err(|_| io::Error::other("clipboard allocation limit"))?;
        if self.output.0.capacity() > FRAME + 4 {
            self.output = Bytes::default();
            return Err(invalid());
        }
        let b = &mut self.output.0;
        b.extend_from_slice(&(length as u32).to_le_bytes());
        b.extend_from_slice(&[
            opcode,
            match selection {
                Selection::Clipboard => 0,
                Selection::Primary => 1,
            },
        ]);
        let mime = |b: &mut Vec<u8>, s: &str| {
            b.extend_from_slice(&(s.len() as u16).to_le_bytes());
            b.extend_from_slice(s.as_bytes());
        };
        match request {
            Request::Set(parts) => {
                b.extend_from_slice(&(parts.len() as u16).to_le_bytes());
                for (m, data) in parts {
                    mime(b, m);
                    b.extend_from_slice(&(data.len() as u32).to_le_bytes());
                    b.extend_from_slice(data);
                }
            }
            Request::Read { revision, mime: m } => {
                b.extend_from_slice(&revision.to_le_bytes());
                mime(b, m);
            }
            _ => {}
        }
        self.opcode = opcode;
        self.deadline = Some(now + TIMEOUT);
        Ok(())
    }

    /// One bounded poll-loop turn. None means wait for readiness/deadline.
    pub fn tick(&mut self, now: Instant) -> Option<io::Result<Reply>> {
        if !self.busy() {
            return None;
        }
        let result = self.step(now);
        match result {
            Ok(None) => None,
            Ok(Some(reply)) => {
                self.reset();
                Some(Ok(reply))
            }
            Err(error) => {
                self.closed = true;
                let _ = self.stream.shutdown(Shutdown::Both);
                self.reset();
                Some(Err(error))
            }
        }
    }

    fn reset(&mut self) {
        self.output = Bytes::default();
        self.input = Bytes::default();
        self.written = 0;
        self.read = 0;
        self.head = 0;
        self.header = [0; 4];
        self.deadline = None;
    }

    fn step(&mut self, now: Instant) -> io::Result<Option<Reply>> {
        if self.deadline.is_some_and(|at| now >= at) {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        let mut budget = QUANTUM;
        while self.written < self.output.0.len() && budget > 0 {
            let end = (self.written + budget).min(self.output.0.len());
            let n = match self.stream.write(&self.output.0[self.written..end]) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(None)
                }
                Err(e) => return Err(e),
            };
            self.written += n;
            budget -= n;
        }
        if self.written < self.output.0.len() || budget == 0 {
            return Ok(None);
        }
        while self.head < 4 && budget > 0 {
            let end = (self.head + budget).min(4);
            let n = read(&mut self.stream, &mut self.header[self.head..end])?;
            if n == 0 {
                return Ok(None);
            }
            self.head += n;
            budget -= n;
        }
        if self.head < 4 || budget == 0 {
            return Ok(None);
        }
        if self.input.0.is_empty() {
            let length = u32::from_le_bytes(self.header) as usize;
            if !(1..=FRAME).contains(&length) {
                return Err(invalid());
            }
            self.input
                .0
                .try_reserve_exact(length)
                .map_err(|_| io::Error::other("clipboard allocation limit"))?;
            if self.input.0.capacity() > FRAME {
                return Err(invalid());
            }
            self.input.0.resize(length, 0);
        }
        while self.read < self.input.0.len() && budget > 0 {
            let end = (self.read + budget).min(self.input.0.len());
            let n = read(&mut self.stream, &mut self.input.0[self.read..end])?;
            if n == 0 {
                return Ok(None);
            }
            self.read += n;
            budget -= n;
        }
        if self.read < self.input.0.len() {
            return Ok(None);
        }
        decode(self.opcode, &self.input.0).map(Some)
    }
}

fn read(stream: &mut UnixStream, target: &mut [u8]) -> io::Result<usize> {
    match stream.read(target) {
        Ok(0) => Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
        Ok(n) => Ok(n),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(0)
        }
        Err(e) => Err(e),
    }
}

struct Decoder<'a>(&'a [u8]);
impl<'a> Decoder<'a> {
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let b = self.0.get(..n).ok_or_else(invalid)?;
        self.0 = &self.0[n..];
        Ok(b)
    }
    fn byte(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn short(&mut self) -> io::Result<usize> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as usize)
    }
    fn revision(&mut self) -> io::Result<u64> {
        let n = u64::from_le_bytes(self.take(8)?.try_into().unwrap());
        if n == 0 {
            Err(invalid())
        } else {
            Ok(n)
        }
    }
}

fn decode(opcode: u8, bytes: &[u8]) -> io::Result<Reply> {
    let mut d = Decoder(bytes);
    let reply = match d.byte()? {
        1 => {
            let code = d.byte()?;
            if !(1..=5).contains(&code) {
                return Err(invalid());
            }
            Reply::Rejected(code)
        }
        0 => match opcode {
            1 => match d.byte()? {
                0 => Reply::Types(None),
                1 => {
                    let revision = d.revision()?;
                    let count = d.short()?;
                    if !(1..=64).contains(&count) {
                        return Err(invalid());
                    }
                    let mut types = Vec::with_capacity(count);
                    for _ in 0..count {
                        let length = d.short()?;
                        if length > 256 {
                            return Err(invalid());
                        }
                        let mime = std::str::from_utf8(d.take(length)?).map_err(|_| invalid())?;
                        if !valid_mime(mime) || types.iter().any(|t| t == mime) {
                            return Err(invalid());
                        }
                        types.push(mime.to_owned());
                    }
                    Reply::Types(Some((revision, types)))
                }
                _ => return Err(invalid()),
            },
            2 => Reply::Set(d.revision()?),
            3 => {
                let n = u32::from_le_bytes(d.take(4)?.try_into().unwrap()) as usize;
                if n > CONTENT {
                    return Err(invalid());
                }
                let data = d.take(n)?;
                let mut payload = Bytes::default();
                payload
                    .0
                    .try_reserve_exact(n)
                    .map_err(|_| io::Error::other("clipboard allocation limit"))?;
                if payload.0.capacity() > CONTENT {
                    return Err(invalid());
                }
                payload.0.extend_from_slice(data);
                Reply::Data(payload)
            }
            4 => Reply::Cleared,
            _ => return Err(invalid()),
        },
        _ => return Err(invalid()),
    };
    if !d.0.is_empty() {
        return Err(invalid());
    }
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(client: &mut Client, peer: &mut UnixStream) -> Vec<u8> {
        peer.set_nonblocking(true).unwrap();
        let mut bytes = Vec::new();
        for _ in 0..100 {
            assert!(client.tick(Instant::now()).is_none());
            let mut part = [0; 4096];
            match peer.read(&mut part) {
                Ok(n) => bytes.extend_from_slice(&part[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                other => panic!("{other:?}"),
            }
            if bytes.len() >= 4
                && bytes.len() == 4 + u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize
            {
                return bytes[4..].to_vec();
            }
        }
        panic!("request did not complete")
    }

    #[test]
    fn fragmented_reply_and_binary_payload_match_the_scoped_protocol() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let mut client = Client::new(a).unwrap();
        let image = b"\x00PNG\xff";
        client
            .start(
                Selection::Primary,
                Request::Set(&[("image/png", image)]),
                Instant::now(),
            )
            .unwrap();
        assert!(client
            .start(Selection::Clipboard, Request::Types, Instant::now())
            .is_err());
        let body = request(&mut client, &mut b);
        assert_eq!(&body[..4], &[2, 1, 1, 0]);
        assert!(body.ends_with(image));
        let mut reply = vec![0];
        reply.extend_from_slice(&7u64.to_le_bytes());
        let mut frame = (reply.len() as u32).to_le_bytes().to_vec();
        frame.extend(reply);
        for byte in &frame[..frame.len() - 1] {
            b.write_all(&[*byte]).unwrap();
            assert!(client.tick(Instant::now()).is_none());
        }
        b.write_all(&frame[frame.len() - 1..]).unwrap();
        assert!(matches!(
            client.tick(Instant::now()).unwrap().unwrap(),
            Reply::Set(7)
        ));
        assert!(!client.busy());
        assert_eq!(client.output.0.capacity() + client.input.0.capacity(), 0);
    }

    #[test]
    fn timeout_and_oversized_header_close_without_any_fallback() {
        for huge in [false, true] {
            let (a, mut b) = UnixStream::pair().unwrap();
            let mut client = Client::new(a).unwrap();
            let now = Instant::now();
            client
                .start(Selection::Clipboard, Request::Types, now)
                .unwrap();
            assert_eq!(request(&mut client, &mut b), [1, 0]);
            let at = if huge {
                b.write_all(&((FRAME + 1) as u32).to_le_bytes()).unwrap();
                now
            } else {
                now + TIMEOUT
            };
            assert!(client.tick(at).unwrap().is_err());
            assert!(client.closed());
            assert_eq!(client.input.0.capacity(), 0);
            assert!(client
                .start(Selection::Clipboard, Request::Clear, at)
                .is_err());
        }
    }

    #[test]
    fn exact_decoding_rejects_stale_shape_and_trailing_data() {
        assert!(matches!(decode(3, &[1, 2]).unwrap(), Reply::Rejected(2)));
        assert!(decode(3, &[1, 2, 0]).is_err());
        assert!(decode(4, &[0, 0]).is_err());
        assert!(decode(2, &[0; 9]).is_err(), "revision zero is invalid");
        assert!(decode(1, &[0, 2]).is_err());
        assert!(decode(3, &[0, 255, 255, 255, 255]).is_err());
        let Reply::Data(data) = decode(3, &[0, 3, 0, 0, 0, 0, 255, 10]).unwrap() else {
            panic!()
        };
        assert_eq!(data.as_slice(), &[0, 255, 10]);
        assert!(!format!("{data:?}").contains("255"));
    }

    #[test]
    fn refused_or_invalid_requests_cannot_silently_replace_an_inflight_selection() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let mut client = Client::new(a).unwrap();
        for parts in [
            vec![("text/plain", &b"a"[..]), ("text/plain", &b"b"[..])],
            vec![("application/x-cellward-clip-forged", &b"a"[..])],
            vec![("bad\n", &b"x"[..])],
        ] {
            assert!(client
                .start(Selection::Clipboard, Request::Set(&parts), Instant::now())
                .is_err());
            assert!(!client.busy());
        }
        client
            .start(Selection::Clipboard, Request::Clear, Instant::now())
            .unwrap();
        assert_eq!(request(&mut client, &mut b), [4, 0]);
        b.write_all(&[2, 0, 0, 0, 1, 4]).unwrap();
        assert!(matches!(
            client.tick(Instant::now()).unwrap().unwrap(),
            Reply::Rejected(4)
        ));
        assert!(!client.closed());
        client
            .start(Selection::Clipboard, Request::Types, Instant::now())
            .unwrap();
    }

    #[test]
    fn erasure_includes_truncated_payload_capacity() {
        let mut bytes = Bytes(vec![91; 1024]);
        bytes.0.truncate(2);
        bytes.clear();
        // SAFETY: clear initialized every byte of the still-owned allocation.
        let allocation =
            unsafe { std::slice::from_raw_parts(bytes.0.as_ptr(), bytes.0.capacity()) };
        assert!(allocation.iter().all(|b| *b == 0));
    }
}
