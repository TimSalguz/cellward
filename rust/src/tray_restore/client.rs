//! A bounded, short-lived session-bus connection for scoped tray activation.
use crate::{dbus_wire as wire, sys};
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

const MAX_MESSAGE: usize = 1 << 20;
const MAX_PENDING_FDS: usize = 256;

pub(super) struct Client {
    stream: UnixStream,
    pending: Vec<u8>,
    fds: VecDeque<OwnedFd>,
    serial: u32,
    until: Instant,
}

fn invalid(why: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why.to_string())
}

fn connect(path: &Path) -> io::Result<UnixStream> {
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: sockaddr_un is plain scalar/array data and zero is valid padding.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if !path.is_absolute() || bytes.contains(&0) || bytes.len() >= address.sun_path.len() {
        return Err(invalid("invalid session bus path"));
    }
    address.sun_family = libc::AF_UNIX as _;
    for (to, from) in address.sun_path.iter_mut().zip(bytes) {
        *to = *from as _;
    }
    // A full local socket backlog must not block the picker indefinitely.
    // SAFETY: valid socket constants; a successful fd is adopted immediately.
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socket just returned one new owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let len = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    // SAFETY: address length is checked against sun_path above and includes NUL.
    if unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            len as _,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let stream = UnixStream::from(fd);
    stream.set_nonblocking(false)?;
    Ok(stream)
}

impl Client {
    pub(super) fn open(path: &Path, until: Instant) -> io::Result<Self> {
        let stream = connect(path)?;
        let mut client = Self {
            stream,
            pending: Vec::new(),
            fds: VecDeque::new(),
            serial: 0,
            until,
        };
        client.timeout()?;
        // SAFETY: getuid has no arguments and cannot fail.
        let uid = unsafe { libc::getuid() }.to_string();
        let hex: String = uid.bytes().map(|b| format!("{b:02x}")).collect();
        client
            .stream
            .write_all(format!("\0AUTH EXTERNAL {hex}\r\n").as_bytes())?;
        if !client.line()?.starts_with(b"OK ") {
            return Err(invalid("session bus authentication refused"));
        }
        client.stream.write_all(b"NEGOTIATE_UNIX_FD\r\n")?;
        if client.line()? != b"AGREE_UNIX_FD\r\n" {
            return Err(invalid("session bus cannot carry process references"));
        }
        client.stream.write_all(b"BEGIN\r\n")?;
        let (_, hello) = client.call(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "Hello",
            "",
            &[],
            &[],
        )?;
        if hello.kind != wire::METHOD_RETURN {
            return Err(invalid("session bus Hello failed"));
        }
        Ok(client)
    }

    fn timeout(&self) -> io::Result<()> {
        let remaining = self
            .until
            .checked_duration_since(Instant::now())
            .filter(|t| !t.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
        let timeout = Some(remaining.min(Duration::from_millis(500)));
        self.stream.set_read_timeout(timeout)?;
        self.stream.set_write_timeout(timeout)
    }

    fn line(&mut self) -> io::Result<Vec<u8>> {
        loop {
            if let Some(at) = self.pending.windows(2).position(|w| w == b"\r\n") {
                return Ok(self.pending.drain(..at + 2).collect());
            }
            if self.pending.len() > 16 * 1024 {
                return Err(invalid("oversized bus authentication"));
            }
            self.timeout()?;
            let mut bytes = [0u8; 512];
            let n = self.stream.read(&mut bytes)?;
            if n == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            self.pending.extend_from_slice(&bytes[..n]);
        }
    }

    pub(super) fn call(
        &mut self,
        destination: &str,
        path: &str,
        interface: &str,
        member: &str,
        signature: &str,
        body: &[u8],
        fds: &[RawFd],
    ) -> io::Result<(Vec<u8>, wire::Header)> {
        self.timeout()?;
        if destination != "org.freedesktop.DBus" && !destination.starts_with(':') {
            return Err(invalid("resolve the bus owner before calling it"));
        }
        self.serial = self
            .serial
            .checked_add(1)
            .ok_or_else(|| invalid("bus serial exhausted"))?;
        let serial = self.serial;
        let mut fields = vec![
            wire::Field::Destination(destination),
            wire::Field::Path(path),
            wire::Field::Interface(interface),
            wire::Field::Member(member),
        ];
        if !signature.is_empty() {
            fields.push(wire::Field::Signature(signature));
        }
        if !fds.is_empty() {
            fields.push(wire::Field::UnixFds(fds.len() as u32));
        }
        let packet = wire::message(wire::METHOD_CALL, 0, serial, &fields, body);
        if packet.len() > MAX_MESSAGE || fds.len() > super::MAX_TARGETS {
            return Err(invalid("oversized bus request"));
        }
        sys::send_with_fds(self.stream.as_raw_fd(), &packet, fds)?;
        for _ in 0..128 {
            let (msg, h) = self.message()?;
            if h.reply_serial == Some(serial) {
                if !matches!(h.kind, wire::METHOD_RETURN | wire::ERROR) {
                    return Err(invalid("invalid bus reply kind"));
                }
                let expected = if destination.starts_with(':') {
                    destination
                } else {
                    "org.freedesktop.DBus"
                };
                if h.sender.as_deref() != Some(expected)
                    && !(h.kind == wire::ERROR
                        && h.sender.as_deref() == Some("org.freedesktop.DBus"))
                {
                    return Err(invalid("bus reply came from another owner"));
                }
                return Ok((msg, h));
            }
        }
        Err(invalid("too many unrelated bus messages"))
    }

    fn message(&mut self) -> io::Result<(Vec<u8>, wire::Header)> {
        loop {
            if let Some(size) = wire::message_len(&self.pending).map_err(invalid)? {
                if size > MAX_MESSAGE {
                    return Err(invalid("oversized bus response"));
                }
                if self.pending.len() >= size {
                    let msg: Vec<u8> = self.pending.drain(..size).collect();
                    let h = wire::parse_header(&msg).map_err(invalid)?;
                    if h.unix_fds as usize > self.fds.len() {
                        return Err(invalid("missing bus descriptors"));
                    }
                    // No response of this client needs a descriptor. Still consume
                    // and close them, so they cannot leak or belong to a later reply.
                    drop(self.fds.drain(..h.unix_fds as usize));
                    if h.unix_fds != 0 {
                        return Err(invalid("unexpected bus response descriptors"));
                    }
                    return Ok((msg, h));
                }
            }
            if self.pending.len() >= MAX_MESSAGE {
                return Err(invalid("oversized pending bus response"));
            }
            self.timeout()?;
            let mut bytes = [0u8; 4096];
            let (n, fds, truncated) =
                sys::recv_into_with_fds(self.stream.as_raw_fd(), &mut bytes, 64)?;
            if truncated {
                return Err(invalid("truncated bus descriptors"));
            }
            self.fds.extend(fds);
            if self.fds.len() > MAX_PENDING_FDS {
                return Err(invalid("too many bus descriptors"));
            }
            if n == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            self.pending.extend_from_slice(&bytes[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::thread;

    fn line(stream: &mut UnixStream) -> Vec<u8> {
        let mut out = Vec::new();
        while !out.ends_with(b"\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            out.push(byte[0]);
            assert!(out.len() < 1024);
        }
        out
    }
    fn packet(stream: &UnixStream) -> (Vec<u8>, wire::Header, Vec<OwnedFd>) {
        let mut data = Vec::new();
        let mut fds = Vec::new();
        loop {
            let (bytes, more) = sys::recv_with_fds(stream.as_raw_fd(), 65536, 64).unwrap();
            assert!(!bytes.is_empty());
            data.extend(bytes);
            fds.extend(more);
            if wire::message_len(&data)
                .unwrap()
                .is_some_and(|n| n == data.len())
            {
                let h = wire::parse_header(&data).unwrap();
                return (data, h, fds);
            }
        }
    }
    fn server(mode: &'static str) -> (PathBuf, thread::JoinHandle<()>) {
        let root = std::env::temp_dir().join(format!(
            "cw-tray-client-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("bus");
        let listener = UnixListener::bind(&path).unwrap();
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            assert!(line(&mut stream).starts_with(b"\0AUTH EXTERNAL "));
            stream.write_all(b"OK 0123456789abcdef\r\n").unwrap();
            assert_eq!(line(&mut stream), b"NEGOTIATE_UNIX_FD\r\n");
            if mode == "no-fds" {
                stream.write_all(b"ERROR unsupported\r\n").unwrap();
                return;
            }
            stream.write_all(b"AGREE_UNIX_FD\r\n").unwrap();
            assert_eq!(line(&mut stream), b"BEGIN\r\n");
            for index in 1..=if mode == "good" { 3 } else { 2 } {
                let (_, h, fds) = packet(&stream);
                assert_eq!(h.serial, index);
                let signature = if index == 1 {
                    "s"
                } else if index == 2 {
                    "as"
                } else {
                    ""
                };
                let sender = if index == 3 {
                    ":1.42"
                } else if index == 2 && mode == "wrong-sender" {
                    ":1.999"
                } else {
                    "org.freedesktop.DBus"
                };
                let mut fields = vec![
                    wire::Field::ReplySerial(index),
                    wire::Field::Sender(sender),
                    wire::Field::Destination(":1.200"),
                ];
                if !signature.is_empty() {
                    fields.push(wire::Field::Signature(signature));
                }
                let body = if index == 1 {
                    wire::body::string(":1.200")
                } else if index == 2 {
                    wire::body::strings(&["org.kde.StatusNotifierItem-42-1", ":1.200"])
                } else {
                    Vec::new()
                };
                if index == 3 {
                    assert_eq!(h.member.as_deref(), Some("ActivateIfOwned"));
                    assert_eq!(fds.len(), 1);
                    assert!(super::super::held_pid(&fds[0]).is_some());
                } else {
                    assert!(fds.is_empty());
                }
                let mut response =
                    wire::message(wire::METHOD_RETURN, 0, 100 + index, &fields, &body);
                if index == 2 && mode == "oversized" {
                    response[4..8].copy_from_slice(&((MAX_MESSAGE + 1) as u32).to_le_bytes());
                    response.truncate(16);
                }
                stream.write_all(&response).unwrap();
            }
        });
        (root, thread)
    }
    #[test]
    fn session_handshake_arrays_and_pidfd_transport_work() {
        let (root, server) = server("good");
        let mut bus =
            Client::open(&root.join("bus"), Instant::now() + Duration::from_secs(3)).unwrap();
        let (msg, h) = bus
            .call(
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "ListNames",
                "",
                &[],
                &[],
            )
            .unwrap();
        assert_eq!(wire::string_array(&msg, &h, 4).unwrap().len(), 2);
        let held = sys::pidfd_open(std::process::id() as i32).unwrap();
        let (_, h) = bus
            .call(
                ":1.42",
                "/StatusNotifierItem",
                super::super::INTERFACE,
                "ActivateIfOwned",
                "ah",
                &[4, 0, 0, 0, 0, 0, 0, 0],
                &[held.as_raw_fd()],
            )
            .unwrap();
        assert_eq!(h.kind, wire::METHOD_RETURN);
        server.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn spoofed_sender_and_oversized_responses_are_rejected() {
        for mode in ["wrong-sender", "oversized"] {
            let (root, server) = server(mode);
            let mut bus =
                Client::open(&root.join("bus"), Instant::now() + Duration::from_secs(3)).unwrap();
            assert_eq!(
                bus.call(
                    "org.freedesktop.DBus",
                    "/org/freedesktop/DBus",
                    "org.freedesktop.DBus",
                    "ListNames",
                    "",
                    &[],
                    &[]
                )
                .unwrap_err()
                .kind(),
                io::ErrorKind::InvalidData
            );
            server.join().unwrap();
            fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn transport_without_unix_fds_is_not_used_for_pid_identity() {
        let (root, server) = server("no-fds");
        assert!(Client::open(&root.join("bus"), Instant::now() + Duration::from_secs(3)).is_err());
        server.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
