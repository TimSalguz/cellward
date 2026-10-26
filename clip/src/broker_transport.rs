//! Host-controller-owned socket pairs for independent active selections.
//!
//! Only the trusted controller calls `connect(instance)` and hands that FD
//! to its launch proxy, BEFORE confinement. There is no public listener,
//! path, application-selected instance name, or cross-instance operation.
//! The controller, not an application, controls instance lifetime.
//!
//! Frames are u32 little-endian length + body. Requests start with opcode
//! (1 types, 2 set, 3 read, 4 clear), then selection (0 CLIPBOARD, 1 PRIMARY).
//! Set adds u16 count then repeated (u16 MIME length, MIME, u32 data length,
//! data). Read adds u64 revision and a length-prefixed MIME. Types/clear
//! have no remaining bytes. Trailing bytes are rejected. Responses start
//! with status (0 success, 1 error + code); success carries a present byte
//! and revision/types for types, a revision for set, u32 length/data for
//! read, or nothing for clear. No request can enumerate or select scopes.
//!
//! The FD adapter to Wayland/X11, recorder and explicit host UI transfer is
//! still pending. This module does not change the desktop's active clipboard.

use crate::broker::{Broker, Error, Instance, Limits, Revision, Selection};
use crate::Content;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const MAX_FRAME: usize = crate::MAX_ENTRY + 32 * 1024;
const MAX_IO: usize = 128 << 20;
const MAX_INSTANCE_IO: usize = MAX_FRAME + QUANTUM;
const MAX_PEERS: usize = 512;
const QUANTUM: usize = 64 << 10;
const TIMEOUT: Duration = Duration::from_secs(5);

/// Owns BOTH selections and their scoped server endpoints, independently of
/// the optional history daemon. No daemon/listener is started implicitly.
pub struct Transport {
    broker: Broker,
    peers: Vec<Peer>,
    io_bytes: usize,
}

impl Default for Transport {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

impl Transport {
    pub fn new(limits: Limits) -> Self {
        Self {
            broker: Broker::new(limits),
            peers: Vec::new(),
            io_bytes: 0,
        }
    }

    pub fn register(&mut self) -> Result<Instance, Error> {
        self.broker.register()
    }

    /// Trusted supervisor operation; never a command on the returned FD.
    pub fn connect(&mut self, instance: Instance) -> io::Result<UnixStream> {
        let (server, client) = UnixStream::pair()?;
        self.attach(instance, server)?;
        Ok(client)
    }

    /// Trusted controller only: the stream has completed authenticated binding.
    pub fn attach(&mut self, instance: Instance, server: UnixStream) -> io::Result<()> {
        self.broker
            .types(instance, Selection::Clipboard)
            .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "unknown instance"))?;
        if self.peers.len() >= MAX_PEERS {
            return Err(io::Error::other("too many active-selection peers"));
        }
        server.set_nonblocking(true)?;
        self.peers.push(Peer::new(server, instance));
        Ok(())
    }

    pub fn remove(&mut self, instance: Instance) -> Result<(), Error> {
        self.broker.remove(instance)?;
        self.peers.retain(|peer| {
            if peer.instance == instance {
                self.io_bytes -= peer.buffered();
                false
            } else {
                true
            }
        });
        Ok(())
    }

    /// Readiness sources for the controller's poll loop, together with its
    /// own registration/UI channels. true means wait for writability.
    pub fn sockets(&self) -> impl Iterator<Item = (BorrowedFd<'_>, bool)> {
        self.peers
            .iter()
            .map(|peer| (peer.stream.as_fd(), !peer.output.0.is_empty()))
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.peers.iter().filter_map(|peer| peer.deadline).min()
    }

    pub fn contains_peer(&self, fd: std::os::fd::RawFd) -> bool {
        use std::os::fd::AsRawFd;
        self.peers.iter().any(|peer| peer.stream.as_raw_fd() == fd)
    }

    pub fn revisions(&self, instance: Instance) -> Result<[u64; 2], Error> {
        Ok([
            self.broker
                .types(instance, Selection::Clipboard)?
                .map_or(0, |(r, _)| r.wire()),
            self.broker
                .types(instance, Selection::Primary)?
                .map_or(0, |(r, _)| r.wire()),
        ])
    }

    /// Host UI operation ONLY, after explicit user approval. The wire
    /// protocol intentionally has no corresponding transfer opcode.
    pub fn transfer_explicit(
        &mut self,
        from: Instance,
        to: Instance,
        selection: Selection,
        revision: Revision,
    ) -> Result<Revision, Error> {
        self.broker.transfer_explicit(from, to, selection, revision)
    }

    /// One fair, nonblocking turn, at most QUANTUM bytes in/out per peer.
    /// A slow or malformed peer is closed without stalling other instances.
    pub fn tick(&mut self, now: Instant) {
        let mut scoped = HashMap::<Instance, usize>::new();
        for peer in &self.peers {
            *scoped.entry(peer.instance).or_default() += peer.buffered();
        }
        self.peers.retain_mut(|peer| {
            let used = scoped.entry(peer.instance).or_default();
            let before = peer.buffered();
            let remaining = MAX_INSTANCE_IO.saturating_sub(*used);
            let alive = peer
                .step(&mut self.broker, &mut self.io_bytes, remaining, now)
                .unwrap_or(false);
            *used = *used - before + peer.buffered();
            if alive {
                true
            } else {
                self.io_bytes -= peer.buffered();
                *used -= peer.buffered();
                false
            }
        });
    }
}

/// Overwrite payload-bearing input/output buffers before releasing them.
#[derive(Default)]
struct Bytes(Vec<u8>);
impl Drop for Bytes {
    fn drop(&mut self) {
        crate::broker::erase(&mut self.0);
    }
}

struct Peer {
    stream: UnixStream,
    instance: Instance,
    header: [u8; 4],
    head: usize,
    input: Bytes,
    read: usize,
    output: Bytes,
    written: usize,
    deadline: Option<Instant>,
}

impl Peer {
    fn new(stream: UnixStream, instance: Instance) -> Self {
        Self {
            stream,
            instance,
            header: [0; 4],
            head: 0,
            input: Bytes::default(),
            read: 0,
            output: Bytes::default(),
            written: 0,
            deadline: None,
        }
    }

    fn buffered(&self) -> usize {
        self.input.0.capacity() + self.output.0.capacity()
    }

    fn step(
        &mut self,
        broker: &mut Broker,
        used: &mut usize,
        mut remaining: usize,
        now: Instant,
    ) -> io::Result<bool> {
        if self.deadline.is_some_and(|deadline| now >= deadline) {
            return Ok(false);
        }
        if self.output.0.is_empty() {
            if self.head < 4 {
                let n = match self.stream.read(&mut self.header[self.head..]) {
                    Ok(0) => return Ok(false),
                    Ok(n) => n,
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) =>
                    {
                        return Ok(true)
                    }
                    Err(e) => return Err(e),
                };
                self.deadline.get_or_insert(now + TIMEOUT);
                self.head += n;
                if self.head < 4 {
                    return Ok(true);
                }
                let length = u32::from_le_bytes(self.header) as usize;
                let available = remaining.min(MAX_IO.saturating_sub(*used));
                if !(2..=MAX_FRAME).contains(&length) || length > available {
                    return Ok(false);
                }
                self.input
                    .0
                    .try_reserve_exact(length)
                    .map_err(io::Error::other)?;
                if self.input.0.capacity() > available {
                    self.input = Bytes::default();
                    return Ok(false);
                }
                *used += self.input.0.capacity();
                remaining -= self.input.0.capacity();
                self.input.0.resize(length, 0);
            }
            if self.read < self.input.0.len() {
                let end = self.input.0.len().min(self.read + QUANTUM);
                match self.stream.read(&mut self.input.0[self.read..end]) {
                    Ok(0) => return Ok(false),
                    Ok(n) => self.read += n,
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) =>
                    {
                        return Ok(true)
                    }
                    Err(e) => return Err(e),
                }
                if self.read < self.input.0.len() {
                    return Ok(true);
                }
            }
            self.output = dispatch(
                broker,
                self.instance,
                &self.input.0,
                remaining.min(MAX_IO.saturating_sub(*used)),
            );
            *used += self.output.0.capacity();
            *used -= self.input.0.capacity();
            self.input = Bytes::default();
            if self.output.0.is_empty() {
                return Ok(false);
            }
        }
        let end = self.output.0.len().min(self.written + QUANTUM);
        match self.stream.write(&self.output.0[self.written..end]) {
            Ok(0) => return Ok(false),
            Ok(n) => self.written += n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(true)
            }
            Err(e) => return Err(e),
        }
        if self.written == self.output.0.len() {
            *used -= self.output.0.capacity();
            self.output = Bytes::default();
            self.head = 0;
            self.read = 0;
            self.written = 0;
            self.deadline = None;
        }
        Ok(true)
    }
}

struct Decoder<'a>(&'a [u8]);
impl<'a> Decoder<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let bytes = self.0.get(..n).ok_or(Error::InvalidTypes)?;
        self.0 = &self.0[n..];
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn short(&mut self) -> Result<usize, Error> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as usize)
    }
    fn number(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn mime(&mut self) -> Result<&'a str, Error> {
        let n = self.short()?;
        if !(1..=256).contains(&n) {
            return Err(Error::InvalidTypes);
        }
        std::str::from_utf8(self.take(n)?).map_err(|_| Error::InvalidTypes)
    }
    fn done(&self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidTypes)
        }
    }
}

fn response(body: &[u8], limit: usize) -> Bytes {
    let length = body.len() + 4;
    if length > limit {
        return Bytes::default();
    }
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(length).is_err() || bytes.capacity() > limit {
        return Bytes::default();
    }
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(body);
    Bytes(bytes)
}

fn dispatch(broker: &mut Broker, instance: Instance, bytes: &[u8], limit: usize) -> Bytes {
    if limit < 6 {
        return Bytes::default();
    }
    let mut run = || -> Result<Bytes, Error> {
        let mut d = Decoder(bytes);
        let opcode = d.byte()?;
        let selection = match d.byte()? {
            0 => Selection::Clipboard,
            1 => Selection::Primary,
            _ => return Err(Error::InvalidTypes),
        };
        match opcode {
            1 => {
                d.done()?;
                let mut answer = vec![0];
                if let Some((revision, types)) = broker.types(instance, selection)? {
                    answer.push(1);
                    answer.extend_from_slice(&revision.wire().to_le_bytes());
                    answer.extend_from_slice(&(types.len() as u16).to_le_bytes());
                    for mime in types {
                        answer.extend_from_slice(&(mime.len() as u16).to_le_bytes());
                        answer.extend_from_slice(mime.as_bytes());
                    }
                } else {
                    answer.push(0);
                }
                Ok(response(&answer, limit))
            }
            2 => {
                if limit < 13 {
                    return Err(Error::Limit);
                }
                let count = d.short()?;
                if !(1..=64).contains(&count) {
                    return Err(Error::InvalidTypes);
                }
                let mut slices = Vec::with_capacity(count);
                for _ in 0..count {
                    let mime = d.mime()?;
                    let length = u32::from_le_bytes(d.take(4)?.try_into().unwrap()) as usize;
                    slices.push((mime, d.take(length)?));
                }
                d.done()?;
                let contents = slices
                    .into_iter()
                    .map(|(mime, data)| Content {
                        mime: mime.to_owned(),
                        data: data.to_vec(),
                    })
                    .collect();
                let revision = broker.set(instance, selection, contents)?;
                let mut answer = vec![0];
                answer.extend_from_slice(&revision.wire().to_le_bytes());
                Ok(response(&answer, limit))
            }
            3 => {
                let revision = Revision::from_wire(d.number()?);
                let mime = d.mime()?;
                d.done()?;
                let data = broker.read(instance, selection, revision, mime)?;
                if data.len().saturating_add(9) > limit {
                    return Err(Error::Limit);
                }
                let mut answer = Bytes(vec![0]);
                answer
                    .0
                    .extend_from_slice(&(data.len() as u32).to_le_bytes());
                answer.0.extend_from_slice(data);
                Ok(response(&answer.0, limit))
            }
            4 => {
                d.done()?;
                broker.clear(instance, selection)?;
                Ok(response(&[0], limit))
            }
            _ => Err(Error::InvalidTypes),
        }
    };
    match run() {
        Ok(answer) => answer,
        Err(error) => response(
            &[
                1,
                match error {
                    Error::UnknownInstance => 1,
                    Error::StaleOffer => 2,
                    Error::InvalidTypes => 3,
                    Error::Limit => 4,
                    Error::Exhausted => 5,
                },
            ],
            limit,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_client_interoperates_without_scope_names_or_host_selection() {
        use crate::clipboard_client::{Client, Reply, Request, Selection as Which};
        fn run(
            server: &mut Transport,
            client: &mut Client,
            which: Which,
            request: Request<'_>,
        ) -> Reply {
            client.start(which, request, Instant::now()).unwrap();
            for _ in 0..2000 {
                server.tick(Instant::now());
                if let Some(reply) = client.tick(Instant::now()) {
                    return reply.unwrap();
                }
            }
            panic!("private clipboard exchange stalled")
        }
        let mut server = Transport::default();
        let instance = server.register().unwrap();
        let foreign = server.register().unwrap();
        let mut a = Client::new(server.connect(instance).unwrap()).unwrap();
        let mut b = Client::new(server.connect(instance).unwrap()).unwrap();
        let mut other = Client::new(server.connect(foreign).unwrap()).unwrap();
        let image: Vec<u8> = (0..300_000).map(|n| (n % 251) as u8).collect();
        let Reply::Set(rev) = run(
            &mut server,
            &mut a,
            Which::Clipboard,
            Request::Set(&[("image/png", &image), ("text/plain", b"synthetic text")]),
        ) else {
            panic!()
        };
        let Reply::Types(Some((seen, types))) =
            run(&mut server, &mut b, Which::Clipboard, Request::Types)
        else {
            panic!()
        };
        assert_eq!(seen, rev);
        assert_eq!(types, ["image/png", "text/plain"]);
        let Reply::Data(data) = run(
            &mut server,
            &mut b,
            Which::Clipboard,
            Request::Read {
                revision: rev,
                mime: "image/png",
            },
        ) else {
            panic!()
        };
        assert_eq!(data.as_slice(), image);
        assert!(matches!(
            run(&mut server, &mut other, Which::Clipboard, Request::Types),
            Reply::Types(None)
        ));
        assert!(matches!(
            run(
                &mut server,
                &mut other,
                Which::Clipboard,
                Request::Read {
                    revision: rev,
                    mime: "image/png"
                }
            ),
            Reply::Rejected(2)
        ));
        assert!(matches!(
            run(&mut server, &mut b, Which::Primary, Request::Types),
            Reply::Types(None)
        ));
        assert!(matches!(
            run(
                &mut server,
                &mut a,
                Which::Clipboard,
                Request::Set(&[("text/plain", b"replacement")])
            ),
            Reply::Set(_)
        ));
        assert!(matches!(
            run(
                &mut server,
                &mut b,
                Which::Clipboard,
                Request::Read {
                    revision: rev,
                    mime: "image/png"
                }
            ),
            Reply::Rejected(2)
        ));
        assert!(matches!(
            run(&mut server, &mut b, Which::Clipboard, Request::Clear),
            Reply::Cleared
        ));
        assert!(matches!(
            run(&mut server, &mut a, Which::Clipboard, Request::Types),
            Reply::Types(None)
        ));
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut bytes = (body.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(body);
        bytes
    }

    fn set(which: u8, mime: &str, data: &[u8]) -> Vec<u8> {
        let mut body = vec![2, which];
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&(mime.len() as u16).to_le_bytes());
        body.extend_from_slice(mime.as_bytes());
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(data);
        body
    }

    fn read(which: u8, revision: u64, mime: &str) -> Vec<u8> {
        let mut body = vec![3, which];
        body.extend_from_slice(&revision.to_le_bytes());
        body.extend_from_slice(&(mime.len() as u16).to_le_bytes());
        body.extend_from_slice(mime.as_bytes());
        body
    }

    fn exchange(server: &mut Transport, client: &mut UnixStream, body: &[u8]) -> Vec<u8> {
        client.set_nonblocking(true).unwrap();
        client.write_all(&frame(body)).unwrap();
        let mut bytes = Vec::new();
        for _ in 0..20 {
            server.tick(Instant::now());
            let mut buffer = [0; 1024];
            match client.read(&mut buffer) {
                Ok(0) => panic!("unexpected closed peer"),
                Ok(n) => bytes.extend_from_slice(&buffer[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("{e}"),
            }
            if bytes.len() >= 4 {
                let length = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
                if bytes.len() == length + 4 {
                    return bytes[4..].to_vec();
                }
            }
        }
        panic!("response did not complete")
    }

    fn revision(answer: &[u8]) -> u64 {
        assert_eq!(answer[0], 0);
        u64::from_le_bytes(answer[1..9].try_into().unwrap())
    }

    fn body(answer: &[u8]) -> &[u8] {
        assert_eq!(answer[0], 0);
        assert_eq!(
            u32::from_le_bytes(answer[1..5].try_into().unwrap()) as usize,
            answer.len() - 5
        );
        &answer[5..]
    }

    #[test]
    fn real_socket_peers_share_only_their_immutable_scope() {
        let mut server = Transport::default();
        let one = server.register().unwrap();
        let two = server.register().unwrap();
        let mut a = server.connect(one).unwrap();
        let mut same = server.connect(one).unwrap();
        let mut other = server.connect(two).unwrap();
        let rev = revision(&exchange(
            &mut server,
            &mut a,
            &set(0, "image/png", b"\0synthetic\xff"),
        ));
        assert_eq!(
            body(&exchange(
                &mut server,
                &mut same,
                &read(0, rev, "image/png")
            )),
            b"\0synthetic\xff"
        );
        assert_eq!(exchange(&mut server, &mut other, &[1, 0]), [0, 0]);
        assert_eq!(
            exchange(&mut server, &mut other, &read(0, rev, "image/png")),
            [1, 2]
        );
        // There is no instance-id field; appending one invalidates the request.
        let mut forged = read(0, rev, "image/png");
        forged.extend_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(exchange(&mut server, &mut other, &forged), [1, 3]);
        assert_eq!(server.io_bytes, 0);
    }

    #[test]
    fn clipboard_and_primary_have_independent_revisions_and_clear() {
        let mut server = Transport::default();
        let instance = server.register().unwrap();
        let mut client = server.connect(instance).unwrap();
        let clip = revision(&exchange(
            &mut server,
            &mut client,
            &set(0, "text/plain", b"clipboard"),
        ));
        let primary = revision(&exchange(
            &mut server,
            &mut client,
            &set(1, "text/plain", b"primary"),
        ));
        assert_ne!(clip, primary);
        assert_eq!(
            exchange(&mut server, &mut client, &read(1, clip, "text/plain")),
            [1, 2]
        );
        assert_eq!(exchange(&mut server, &mut client, &[4, 0]), [0]);
        assert_eq!(
            exchange(&mut server, &mut client, &read(0, clip, "text/plain")),
            [1, 2]
        );
        assert_eq!(
            body(&exchange(
                &mut server,
                &mut client,
                &read(1, primary, "text/plain")
            )),
            b"primary"
        );
    }

    #[test]
    fn launch_disconnect_keeps_instance_but_instance_removal_revokes_peers() {
        let mut server = Transport::default();
        let instance = server.register().unwrap();
        let mut client = server.connect(instance).unwrap();
        let rev = revision(&exchange(
            &mut server,
            &mut client,
            &set(0, "text/plain", b"retained"),
        ));
        drop(client);
        server.tick(Instant::now());
        let mut next = server.connect(instance).unwrap();
        assert_eq!(
            body(&exchange(
                &mut server,
                &mut next,
                &read(0, rev, "text/plain")
            )),
            b"retained"
        );
        server.remove(instance).unwrap();
        assert_eq!(next.read(&mut [0; 1]).unwrap(), 0);
        assert!(server.connect(instance).is_err());
        let another = server.register().unwrap();
        assert_ne!(another, instance);
        let mut fresh = server.connect(another).unwrap();
        assert_eq!(
            exchange(&mut server, &mut fresh, &read(0, rev, "text/plain")),
            [1, 2]
        );
    }

    #[test]
    fn old_revision_never_serves_a_replacement_password() {
        let mut server = Transport::default();
        let instance = server.register().unwrap();
        let mut client = server.connect(instance).unwrap();
        let first = revision(&exchange(
            &mut server,
            &mut client,
            &set(0, "text/plain", b"old"),
        ));
        let next = revision(&exchange(
            &mut server,
            &mut client,
            &set(0, "text/plain", b"synthetic password"),
        ));
        assert_ne!(first, next);
        assert_eq!(
            exchange(&mut server, &mut client, &read(0, first, "text/plain")),
            [1, 2]
        );
        assert_eq!(
            body(&exchange(
                &mut server,
                &mut client,
                &read(0, next, "text/plain")
            )),
            b"synthetic password"
        );
    }

    #[test]
    fn slow_peer_does_not_block_other_instance_and_expires() {
        let mut server = Transport::default();
        let one = server.register().unwrap();
        let two = server.register().unwrap();
        let mut slow = server.connect(one).unwrap();
        let mut fast = server.connect(two).unwrap();
        slow.write_all(&[2, 0, 0, 0, 1]).unwrap(); // incomplete types request
        let now = Instant::now();
        server.tick(now);
        assert_eq!(exchange(&mut server, &mut fast, &[1, 0]), [0, 0]);
        server.tick(now + TIMEOUT + Duration::from_secs(1));
        assert_eq!(slow.read(&mut [0; 1]).unwrap(), 0);
        assert_eq!(server.io_bytes, 0);
        assert_eq!(exchange(&mut server, &mut fast, &[1, 0]), [0, 0]);
    }

    #[test]
    fn oversized_header_is_rejected_before_allocating() {
        let mut server = Transport::default();
        let instance = server.register().unwrap();
        let mut client = server.connect(instance).unwrap();
        client.write_all(&u32::MAX.to_le_bytes()).unwrap();
        server.tick(Instant::now());
        assert_eq!(client.read(&mut [0; 1]).unwrap(), 0);
        assert_eq!(server.io_bytes, 0);
        assert!(server.peers.is_empty());
    }

    #[test]
    fn wire_has_no_cross_instance_transfer_but_trusted_controller_can_transfer() {
        let mut server = Transport::default();
        let from = server.register().unwrap();
        let to = server.register().unwrap();
        let mut a = server.connect(from).unwrap();
        let mut b = server.connect(to).unwrap();
        let rev = revision(&exchange(
            &mut server,
            &mut a,
            &set(0, "text/plain", b"explicit only"),
        ));
        assert_eq!(exchange(&mut server, &mut b, &[5, 0]), [1, 3]);
        assert_eq!(exchange(&mut server, &mut b, &[1, 0]), [0, 0]);
        let transferred = server
            .transfer_explicit(from, to, Selection::Clipboard, Revision::from_wire(rev))
            .unwrap();
        assert_ne!(transferred.wire(), rev);
        assert_eq!(
            body(&exchange(
                &mut server,
                &mut b,
                &read(0, transferred.wire(), "text/plain")
            )),
            b"explicit only"
        );
    }

    #[test]
    fn malformed_or_over_budget_set_does_not_replace_existing_selection() {
        let mut server = Transport::new(Limits {
            instances: 1,
            per_instance: 32,
            total: 32,
        });
        let instance = server.register().unwrap();
        let mut client = server.connect(instance).unwrap();
        let rev = revision(&exchange(
            &mut server,
            &mut client,
            &set(0, "text/plain", b"keep"),
        ));
        assert_eq!(
            exchange(&mut server, &mut client, &set(0, "text/plain", &[0; 40])),
            [1, 4]
        );
        let mut trailing = set(0, "text/plain", b"replace");
        trailing.push(0);
        assert_eq!(exchange(&mut server, &mut client, &trailing), [1, 3]);
        assert_eq!(exchange(&mut server, &mut client, &[4, 2]), [1, 3]);
        assert_eq!(
            body(&exchange(
                &mut server,
                &mut client,
                &read(0, rev, "text/plain")
            )),
            b"keep"
        );
    }

    #[test]
    fn insufficient_scope_or_global_io_credit_never_allocates_or_underflows() {
        let mut broker = Broker::default();
        let instance = broker.register().unwrap();
        for (global, scoped) in [(MAX_IO - 1, MAX_INSTANCE_IO), (0, 1)] {
            let (a, mut b) = UnixStream::pair().unwrap();
            a.set_nonblocking(true).unwrap();
            b.write_all(&2u32.to_le_bytes()).unwrap();
            let mut peer = Peer::new(a, instance);
            let mut used = global;
            assert!(!peer
                .step(&mut broker, &mut used, scoped, Instant::now())
                .unwrap());
            assert_eq!(peer.buffered(), 0);
            assert_eq!(used, global);
        }
    }

    #[test]
    fn erasure_covers_truncated_spare_capacity() {
        let mut secret = vec![0x53; 1024];
        secret.truncate(4);
        crate::broker::erase(&mut secret);
        // erase initialized the entire allocation; inspect before dropping it.
        let allocation = unsafe { std::slice::from_raw_parts(secret.as_ptr(), secret.capacity()) };
        assert!(allocation.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn instance_removal_releases_partial_io_and_closes_the_capability() {
        let mut server = Transport::default();
        let instance = server.register().unwrap();
        let mut client = server.connect(instance).unwrap();
        client.write_all(&[32, 0, 0, 0, 2]).unwrap();
        server.tick(Instant::now());
        assert_eq!(server.io_bytes, 32);
        assert!(server.next_deadline().is_some());
        assert_eq!(server.sockets().count(), 1);
        server.remove(instance).unwrap();
        assert_eq!(server.io_bytes, 0);
        assert_eq!(server.next_deadline(), None);
        assert_eq!(server.sockets().count(), 0);
        assert_eq!(client.read(&mut [0; 1]).unwrap(), 0);
    }

    #[test]
    fn malformed_requests_never_read_another_instances_secret() {
        let mut server = Transport::default();
        let source = server.register().unwrap();
        let attacker = server.register().unwrap();
        let secret = b"UNIQUE_SYNTHETIC_PRIVATE_SELECTION";
        server
            .broker
            .set(
                source,
                Selection::Clipboard,
                vec![Content {
                    mime: "text/plain".into(),
                    data: secret.to_vec(),
                }],
            )
            .unwrap();
        let mut seed = 17u64;
        for length in 0..128 {
            let mut input = Vec::new();
            for _ in 0..length {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                input.push((seed >> 32) as u8);
            }
            let answer = dispatch(&mut server.broker, attacker, &input, 64 << 10);
            assert!(!answer.0.windows(secret.len()).any(|part| part == secret));
        }
        assert_eq!(
            server.broker.types(attacker, Selection::Clipboard).unwrap(),
            None
        );
    }
}
