//! The kernel's socket diagnostics (`NETLINK_SOCK_DIAG`), as a container's
//! live network switch will use them: list the sockets of the container's
//! network namespace, and destroy them (`SOCK_DESTROY`) so that no
//! connection of the old network goes on in the new one (the container
//! design of 2026-09-27, G4).
//!
//! What `ss -K` does, and nothing more: a dump of TCP in every state but
//! `LISTEN` and of UDP in every state, both families, then one destroy per
//! socket, by the id the dump gave — its four-tuple, its interface and its
//! cookie, which the kernel checks, so that a socket that went and a new one
//! on the same ports is not taken for it. A socket with both ends on the
//! loopback ([`loopback_only`]) never leaves the namespace and is left alone.
//!
//! Pure functions over byte buffers: the request a dump or a destroy is,
//! and what the answers say. The socket that carries them is the caller's.
//! Numbers are the host's byte order where the kernel's structures have them
//! so (`nlmsghdr`, the states, the interface, the cookie) and network order
//! where they are `__be` (ports, addresses).
//!
//! **Destroying is not the wall.** The kernel has no destroy for a ping
//! socket, a socket of a `SO_REUSEPORT` group may not be found by its tuple,
//! and an unconnected UDP socket only gets an error once and sends again
//! from the next address. What keeps every pre-switch socket mute is the
//! epoch's firewall rule (`zone::instance_ruleset`); this makes programs
//! notice at once.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// `NETLINK_SOCK_DIAG`, the netlink protocol.
pub const NETLINK_SOCK_DIAG: i32 = 4;
/// `SOCK_DIAG_BY_FAMILY`: a dump request and its answers.
pub const SOCK_DIAG_BY_FAMILY: u16 = 20;
/// `SOCK_DESTROY`.
pub const SOCK_DESTROY: u16 = 21;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
/// `NLM_F_ROOT | NLM_F_MATCH`.
const NLM_F_DUMP: u16 = 0x300;
/// `sizeof(struct nlmsghdr)`.
const NLMSG_HDR: usize = 16;
/// `sizeof(struct inet_diag_sockid)`.
pub const SOCKID_LEN: usize = 48;
/// `sizeof(struct inet_diag_req_v2)`.
const REQ_LEN: usize = 8 + SOCKID_LEN;
/// `sizeof(struct inet_diag_msg)`.
const MSG_LEN: usize = 4 + SOCKID_LEN + 20;

pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
/// `TCP_LISTEN` among the kernel's socket states.
pub const TCP_LISTEN: u8 = 10;
/// Every state but `LISTEN`: a listener carries no connection, and it
/// accepts none from outside a container's namespace anyway.
pub const STATES_BUT_LISTEN: u32 = !(1 << TCP_LISTEN);
/// Every state — for UDP, whose sockets are "established" when connected
/// and "closed" when not, and both kinds send.
pub const ALL_STATES: u32 = !0;

/// One socket of a dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {
    pub family: u8,
    pub state: u8,
    pub src: IpAddr,
    pub sport: u16,
    pub dst: IpAddr,
    pub dport: u16,
    pub interface: u32,
    pub cookie: u64,
    pub uid: u32,
    pub inode: u32,
    /// `inet_diag_sockid` as the kernel wrote it: what a destroy names the
    /// socket by, byte for byte, as `ss -K` does.
    pub id: [u8; SOCKID_LEN],
}

/// One message of an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Socket(Socket),
    /// The end of a dump.
    Done,
    /// An acknowledgement: 0, or the error as a negative errno.
    Ack(i32),
}

/// An answer that cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// A message whose length is shorter than its header, or longer than
    /// what is left of the buffer.
    BadLength,
    /// A socket message shorter than `inet_diag_msg`.
    ShortSocket,
    /// An error message without its errno.
    ShortError,
    /// A family that is neither IPv4 nor IPv6.
    Family(u8),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLength => write!(f, "a netlink message of an impossible length"),
            Self::ShortSocket => write!(f, "a socket message cut short"),
            Self::ShortError => write!(f, "an error message cut short"),
            Self::Family(n) => write!(f, "a socket of family {n}"),
        }
    }
}

impl std::error::Error for ParseError {}

fn header(len: usize, kind: u16, flags: u16, seq: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    // Cannot truncate: a request is a few dozen bytes.
    out.extend_from_slice(&(len as u32).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    // The port id: the kernel's to fill in.
    out.extend_from_slice(&0u32.to_ne_bytes());
    out
}

/// A dump of one family's sockets of one protocol in `states` (a bit per
/// state): `ss -t` or `ss -u` without a filter.
pub fn dump_request(family: u8, protocol: u8, states: u32, seq: u32) -> Vec<u8> {
    let mut out = header(
        NLMSG_HDR + REQ_LEN,
        SOCK_DIAG_BY_FAMILY,
        NLM_F_REQUEST | NLM_F_DUMP,
        seq,
    );
    out.extend_from_slice(&[family, protocol, 0, 0]);
    out.extend_from_slice(&states.to_ne_bytes());
    // No socket named: the whole table.
    out.extend_from_slice(&[0u8; SOCKID_LEN]);
    out
}

/// Destroy the socket a dump listed, named by the id the dump gave it —
/// the request `ss -K` sends. The answer is an [`Message::Ack`].
pub fn destroy_request(socket: &Socket, protocol: u8, seq: u32) -> Vec<u8> {
    let mut out = header(
        NLMSG_HDR + REQ_LEN,
        SOCK_DESTROY,
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
    );
    out.extend_from_slice(&[socket.family, protocol, 0, 0]);
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(&socket.id);
    out
}

fn u16_ne(b: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([b[at], b[at + 1]])
}

fn u32_ne(b: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u16_be(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

/// An address of `inet_diag_sockid`: four `__be32`, of which IPv4 uses the
/// first.
fn address(family: u8, b: &[u8]) -> Result<IpAddr, ParseError> {
    match family {
        AF_INET => Ok(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))),
        AF_INET6 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&b[..16]);
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        other => Err(ParseError::Family(other)),
    }
}

fn socket(body: &[u8]) -> Result<Socket, ParseError> {
    if body.len() < MSG_LEN {
        return Err(ParseError::ShortSocket);
    }
    let family = body[0];
    let id = &body[4..4 + SOCKID_LEN];
    let rest = 4 + SOCKID_LEN;
    let mut raw = [0u8; SOCKID_LEN];
    raw.copy_from_slice(id);
    Ok(Socket {
        family,
        state: body[1],
        sport: u16_be(id, 0),
        dport: u16_be(id, 2),
        src: address(family, &id[4..20])?,
        dst: address(family, &id[20..36])?,
        interface: u32_ne(id, 36),
        cookie: u64::from(u32_ne(id, 40)) | (u64::from(u32_ne(id, 44)) << 32),
        // idiag_expires, idiag_rqueue and idiag_wqueue come first.
        uid: u32_ne(body, rest + 12),
        inode: u32_ne(body, rest + 16),
        id: raw,
    })
}

/// Every message of one `recv` of the diag socket. Attributes after a
/// socket's `inet_diag_msg` are skipped; messages of other types too.
pub fn parse(buf: &[u8]) -> Result<Vec<Message>, ParseError> {
    let mut out = Vec::new();
    let mut at = 0;
    while buf.len() - at >= NLMSG_HDR {
        let len = u32_ne(buf, at) as usize;
        if len < NLMSG_HDR || len > buf.len() - at {
            return Err(ParseError::BadLength);
        }
        let body = &buf[at + NLMSG_HDR..at + len];
        match u16_ne(buf, at + 4) {
            SOCK_DIAG_BY_FAMILY => out.push(Message::Socket(socket(body)?)),
            NLMSG_DONE => out.push(Message::Done),
            NLMSG_ERROR => {
                if body.len() < 4 {
                    return Err(ParseError::ShortError);
                }
                out.push(Message::Ack(u32_ne(body, 0) as i32));
            }
            _ => {}
        }
        // Messages are aligned to four bytes.
        at += (len + 3) & !3;
        if at > buf.len() {
            break;
        }
    }
    Ok(out)
}

/// Does the address never leave the host's loopback: `127/8`, `::1`, or
/// IPv4's loopback mapped into IPv6?
fn is_loopback(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => a.is_loopback(),
        IpAddr::V6(a) => a.is_loopback() || a.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
    }
}

/// A socket that talks to its own namespace's loopback only: its local end
/// on the loopback, and its other end on it too or none at all. Nothing of
/// it reaches the network, before a switch or after, and destroying it
/// would only break a program's talk with itself.
pub fn loopback_only(socket: &Socket) -> bool {
    is_loopback(socket.src) && (is_loopback(socket.dst) || socket.dst.is_unspecified())
}

/// The inode of a socket as `/proc/<pid>/fd/<n>` names it (`socket:[N]`):
/// what a program that still holds a socket of a dump is found by.
pub fn socket_inode(link: &str) -> Option<u32> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// Whether a socket of a dump of `protocol` is destroyed by a switch: not a
/// TCP listener (the dump leaves them out already; a listener carries no
/// connection), and not one that stays on the loopback ([`loopback_only`]).
pub fn to_break(socket: &Socket, protocol: u8) -> bool {
    let listener = protocol == IPPROTO_TCP && socket.state == TCP_LISTEN;
    !(listener || loopback_only(socket))
}

// --- THE I/O HALF (stage 4, 2026-09-27) ---------------------------------------
//
// The netlink socket, in the network namespace of the process that opens it:
// a container instance's, for its relay (`crate::relay`, `--seal` and
// `--probe`), the root of the instance's user namespace — `SOCK_DESTROY`
// wants `CAP_NET_ADMIN` over the namespace's owner.

/// What a switch's break did ([`break_all`]): destroyed TCP and UDP sockets,
/// those the kernel no longer found by their id (`missed`: gone meanwhile,
/// or of a `SO_REUSEPORT` group), those it would not destroy
/// (`unsupported`: no `SOCK_DESTROY` for them), any other refusal
/// (`failed`), the inodes of every UDP socket seen — what the programs that
/// still hold one are found by after the switch: such a socket stays
/// muted by the epoch's wall (`crate::epoch`) —, and what went wrong.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tally {
    pub tcp: u32,
    pub udp: u32,
    pub missed: u32,
    pub unsupported: u32,
    pub failed: u32,
    pub udp_inodes: Vec<u32>,
    pub errors: Vec<String>,
}

impl Tally {
    /// One line of words: `tcp=N udp=N missed=N unsupported=N failed=N
    /// udp-inodes=a,b` — what the relay tells the keeper ([`Tally::parse`]).
    pub fn word(&self) -> String {
        let inodes: Vec<String> = self.udp_inodes.iter().map(u32::to_string).collect();
        format!(
            "tcp={} udp={} missed={} unsupported={} failed={} udp-inodes={}",
            self.tcp,
            self.udp,
            self.missed,
            self.unsupported,
            self.failed,
            inodes.join(",")
        )
    }

    /// [`Tally::word`] read back; words it does not know are skipped, and so
    /// is what `errors` held (said on the relay's stderr, not here).
    pub fn parse(line: &str) -> Self {
        let mut tally = Self::default();
        for word in line.split_whitespace() {
            let Some((key, value)) = word.split_once('=') else {
                continue;
            };
            let count = || value.parse::<u32>().unwrap_or(0);
            match key {
                "tcp" => tally.tcp = count(),
                "udp" => tally.udp = count(),
                "missed" => tally.missed = count(),
                "unsupported" => tally.unsupported = count(),
                "failed" => tally.failed = count(),
                "udp-inodes" => {
                    tally.udp_inodes = value.split(',').filter_map(|n| n.parse().ok()).collect()
                }
                _ => {}
            }
        }
        tally
    }
}

/// A `NETLINK_SOCK_DIAG` socket in this process's network namespace.
fn open() -> io::Result<OwnedFd> {
    // SAFETY: socket(2) takes no pointers and returns a new descriptor or -1.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_SOCK_DIAG,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the descriptor was just returned to us and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// One request to the kernel.
fn send(fd: &OwnedFd, msg: &[u8]) -> io::Result<()> {
    // SAFETY: an all-zero sockaddr_nl is the kernel's address once its
    // family is set.
    let mut to: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    to.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    loop {
        // SAFETY: a buffer of the length passed and an address of the size
        // passed, both alive for the call.
        let n = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                msg.as_ptr().cast(),
                msg.len(),
                0,
                std::ptr::from_ref(&to).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if n >= 0 {
            return if n as usize == msg.len() {
                Ok(())
            } else {
                Err(io::Error::other("a request sent short"))
            };
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// The kernel's next answer, whole: a netlink socket gives one datagram a
/// read.
fn recv(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<Vec<Message>> {
    loop {
        // SAFETY: a buffer of the length passed, alive for the call.
        let n = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Err(io::Error::other("the diag socket was closed"));
        }
        return parse(&buf[..n as usize])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
    }
}

/// Every socket of one family and protocol in `states`.
fn dump(fd: &OwnedFd, family: u8, protocol: u8, states: u32, seq: u32) -> io::Result<Vec<Socket>> {
    send(fd, &dump_request(family, protocol, states, seq))?;
    // A dump comes in datagrams of a few pages; one of 64 KiB takes any.
    let mut buf = vec![0u8; 64 * 1024];
    let mut out = Vec::new();
    loop {
        for message in recv(fd, &mut buf)? {
            match message {
                Message::Socket(socket) => out.push(socket),
                Message::Done => return Ok(out),
                Message::Ack(0) => {}
                Message::Ack(errno) => return Err(io::Error::from_raw_os_error(-errno)),
            }
        }
    }
}

/// Destroy one socket; the kernel's answer: 0, or the error negative.
fn destroy(fd: &OwnedFd, socket: &Socket, protocol: u8, seq: u32) -> io::Result<i32> {
    send(fd, &destroy_request(socket, protocol, seq))?;
    let mut buf = vec![0u8; 8 * 1024];
    loop {
        for message in recv(fd, &mut buf)? {
            if let Message::Ack(code) = message {
                return Ok(code);
            }
        }
    }
}

/// Every socket of this network namespace that may reach out destroyed
/// ([`to_break`]): TCP in every state but `LISTEN`, UDP in every state,
/// both families — what `ss -K` does. What cannot be done is counted and
/// said, never a reason to stop: the epoch's wall holds without it.
pub fn break_all() -> Tally {
    let mut tally = Tally::default();
    let fd = match open() {
        Ok(fd) => fd,
        Err(e) => {
            tally.errors.push(format!("no diag socket ({e})"));
            return tally;
        }
    };
    let mut seq: u32 = 1;
    for (protocol, states) in [(IPPROTO_TCP, STATES_BUT_LISTEN), (IPPROTO_UDP, ALL_STATES)] {
        for family in [AF_INET, AF_INET6] {
            seq = seq.wrapping_add(1);
            let sockets = match dump(&fd, family, protocol, states, seq) {
                Ok(sockets) => sockets,
                Err(e) => {
                    tally.errors.push(format!(
                        "no dump of family {family}, protocol {protocol} ({e})"
                    ));
                    continue;
                }
            };
            for socket in sockets.iter().filter(|s| to_break(s, protocol)) {
                if protocol == IPPROTO_UDP && socket.inode != 0 {
                    tally.udp_inodes.push(socket.inode);
                }
                seq = seq.wrapping_add(1);
                match destroy(&fd, socket, protocol, seq) {
                    Ok(0) if protocol == IPPROTO_TCP => tally.tcp += 1,
                    Ok(0) => tally.udp += 1,
                    Ok(code) if code == -libc::ENOENT => tally.missed += 1,
                    Ok(code) if code == -libc::EOPNOTSUPP => tally.unsupported += 1,
                    Ok(code) => {
                        tally.failed += 1;
                        tally.errors.push(format!(
                            "{}:{} → {}:{}: {}",
                            socket.src,
                            socket.sport,
                            socket.dst,
                            socket.dport,
                            io::Error::from_raw_os_error(-code)
                        ));
                    }
                    Err(e) => {
                        tally.failed += 1;
                        tally.errors.push(format!("a destroy did not go ({e})"));
                    }
                }
            }
        }
    }
    tally
}

/// Whether the kernel destroys sockets here (`CONFIG_INET_DIAG_DESTROY`,
/// default `n` upstream): a destroy of a socket that is not there answers
/// `ENOENT` where it does, `EOPNOTSUPP` where it does not — for TCP and for
/// UDP, whose diag modules the request loads.
pub fn destroy_supported() -> Result<(), String> {
    let fd = open().map_err(|e| format!("no diag socket ({e})"))?;
    let mut cookie = [0u8; 8];
    crate::bridge::random_bytes(&mut cookie).map_err(|e| format!("no random cookie ({e})"))?;
    let mut id = [0u8; SOCKID_LEN];
    id[40..48].copy_from_slice(&cookie);
    let nobody = Socket {
        family: AF_INET,
        state: 0,
        src: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        sport: 0,
        dst: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        dport: 0,
        interface: 0,
        cookie: u64::from_ne_bytes(cookie),
        uid: 0,
        inode: 0,
        id,
    };
    for (seq, protocol) in [(1u32, IPPROTO_TCP), (2, IPPROTO_UDP)] {
        match destroy(&fd, &nobody, protocol, seq) {
            Ok(code) if code == -libc::ENOENT => {}
            Ok(code) if code == -libc::EOPNOTSUPP => {
                return Err(format!(
                    "protocol {protocol}: the kernel destroys no socket (CONFIG_INET_DIAG_DESTROY)"
                ))
            }
            Ok(code) => {
                return Err(format!(
                    "protocol {protocol}: {}",
                    io::Error::from_raw_os_error(-code)
                ))
            }
            Err(e) => return Err(format!("protocol {protocol}: {e}")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A socket message as the kernel writes it, from its fields.
    #[allow(clippy::too_many_arguments)]
    fn message(
        family: u8,
        state: u8,
        src: &[u8],
        sport: u16,
        dst: &[u8],
        dport: u16,
        interface: u32,
        cookie: u64,
    ) -> Vec<u8> {
        let mut body = vec![family, state, 0, 0];
        body.extend_from_slice(&sport.to_be_bytes());
        body.extend_from_slice(&dport.to_be_bytes());
        let mut a = [0u8; 16];
        a[..src.len()].copy_from_slice(src);
        body.extend_from_slice(&a);
        let mut a = [0u8; 16];
        a[..dst.len()].copy_from_slice(dst);
        body.extend_from_slice(&a);
        body.extend_from_slice(&interface.to_ne_bytes());
        body.extend_from_slice(&((cookie & 0xffff_ffff) as u32).to_ne_bytes());
        body.extend_from_slice(&((cookie >> 32) as u32).to_ne_bytes());
        // expires, rqueue, wqueue, uid, inode
        for v in [0u32, 0, 0, 1000, 4242] {
            body.extend_from_slice(&v.to_ne_bytes());
        }
        // An attribute after it, as the kernel may add: skipped.
        body.extend_from_slice(&[8, 0, 1, 0, 9, 9, 9, 9]);
        let mut out = header(NLMSG_HDR + body.len(), SOCK_DIAG_BY_FAMILY, 2, 7);
        out.extend_from_slice(&body);
        out
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn a_dump_request_is_the_bytes_ss_sends() {
        let got = dump_request(AF_INET, IPPROTO_TCP, STATES_BUT_LISTEN, 7);
        let mut want = vec![
            72, 0, 0, 0, // length
            20, 0, // SOCK_DIAG_BY_FAMILY
            0x01, 0x03, // NLM_F_REQUEST | NLM_F_DUMP
            7, 0, 0, 0, // sequence
            0, 0, 0, 0, // port id
            2, 6, 0, 0, // AF_INET, IPPROTO_TCP, no extensions
            0xff, 0xfb, 0xff, 0xff, // every state but LISTEN (bit 10)
        ];
        want.extend_from_slice(&[0u8; 48]);
        assert_eq!(got, want);

        let got = dump_request(AF_INET6, IPPROTO_UDP, ALL_STATES, 8);
        assert_eq!(got[16..24], [10, 17, 0, 0, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(got.len(), 72);
    }

    #[test]
    fn a_dump_is_read_socket_by_socket_to_its_end() {
        let mut buf = message(
            AF_INET,
            1,
            &[10, 254, 1, 2],
            40000,
            &[10, 99, 0, 1],
            8080,
            5,
            0x0000_0001_0000_0002,
        );
        let v6_src = "fd63:656c:6c77::1234".parse::<Ipv6Addr>().unwrap().octets();
        let v6_dst = "fd99::1".parse::<Ipv6Addr>().unwrap().octets();
        buf.extend(message(AF_INET6, 7, &v6_src, 5353, &v6_dst, 0, 0, 99));
        buf.extend(header(20, NLMSG_DONE, 2, 7));
        buf.extend_from_slice(&0u32.to_ne_bytes());
        let got = parse(&buf).unwrap();
        assert_eq!(got.len(), 3);
        let Message::Socket(tcp) = &got[0] else {
            panic!("{got:?}");
        };
        assert_eq!(tcp.family, AF_INET);
        assert_eq!(tcp.state, 1);
        assert_eq!(tcp.src, "10.254.1.2".parse::<IpAddr>().unwrap());
        assert_eq!(tcp.sport, 40000);
        assert_eq!(tcp.dst, "10.99.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(tcp.dport, 8080);
        assert_eq!(tcp.interface, 5);
        assert_eq!(tcp.cookie, 0x0000_0001_0000_0002);
        assert_eq!((tcp.uid, tcp.inode), (1000, 4242));
        let Message::Socket(udp) = &got[1] else {
            panic!("{got:?}");
        };
        assert_eq!(udp.src, IpAddr::V6(Ipv6Addr::from(v6_src)));
        assert_eq!(udp.dst, IpAddr::V6(Ipv6Addr::from(v6_dst)));
        assert_eq!((udp.sport, udp.dport, udp.cookie), (5353, 0, 99));
        assert_eq!(got[2], Message::Done);
    }

    /// The destroy names the socket by the id the dump gave, byte for byte.
    #[cfg(target_endian = "little")]
    #[test]
    fn a_destroy_names_the_socket_as_the_dump_did() {
        let buf = message(
            AF_INET,
            1,
            &[10, 254, 1, 2],
            40000,
            &[10, 99, 0, 1],
            8080,
            5,
            0x0000_0001_0000_0002,
        );
        let Message::Socket(s) = parse(&buf).unwrap().remove(0) else {
            panic!("no socket");
        };
        let got = destroy_request(&s, IPPROTO_TCP, 9);
        let mut want = vec![
            72, 0, 0, 0, // length
            21, 0, // SOCK_DESTROY
            0x05, 0x00, // NLM_F_REQUEST | NLM_F_ACK
            9, 0, 0, 0, // sequence
            0, 0, 0, 0, // port id
            2, 6, 0, 0, // AF_INET, IPPROTO_TCP
            0, 0, 0, 0, // states: not looked at
            0x9c, 0x40, 0x1f, 0x90, // ports 40000 and 8080, network order
            10, 254, 1, 2, // source
        ];
        want.extend_from_slice(&[0u8; 12]);
        want.extend_from_slice(&[10, 99, 0, 1]);
        want.extend_from_slice(&[0u8; 12]);
        want.extend_from_slice(&[5, 0, 0, 0]); // interface
        want.extend_from_slice(&[2, 0, 0, 0, 1, 0, 0, 0]); // cookie
        assert_eq!(got, want);
    }

    #[test]
    fn an_acknowledgement_says_done_or_the_errno() {
        let mut ok = header(36, NLMSG_ERROR, 0x100, 9);
        ok.extend_from_slice(&0i32.to_ne_bytes());
        ok.extend_from_slice(&[0u8; 16]);
        assert_eq!(parse(&ok).unwrap(), [Message::Ack(0)]);
        let mut gone = header(36, NLMSG_ERROR, 0, 9);
        gone.extend_from_slice(&(-2i32).to_ne_bytes());
        gone.extend_from_slice(&[0u8; 16]);
        assert_eq!(parse(&gone).unwrap(), [Message::Ack(-2)]);
    }

    #[test]
    fn a_broken_answer_is_refused() {
        // A length shorter than a header, and one past the buffer.
        assert_eq!(
            parse(&header(8, NLMSG_DONE, 0, 1)),
            Err(ParseError::BadLength)
        );
        assert_eq!(
            parse(&header(64, NLMSG_DONE, 0, 1)),
            Err(ParseError::BadLength)
        );
        // A socket message cut short.
        let mut cut = header(40, SOCK_DIAG_BY_FAMILY, 0, 1);
        cut.extend_from_slice(&[0u8; 24]);
        assert_eq!(parse(&cut), Err(ParseError::ShortSocket));
        // A family nobody asked for.
        let bad = message(1, 1, &[1, 2, 3, 4], 1, &[1, 2, 3, 4], 1, 0, 0);
        assert_eq!(parse(&bad), Err(ParseError::Family(1)));
        // Less than a header is nothing at all.
        assert_eq!(parse(&[1, 2, 3]), Ok(Vec::new()));
    }

    #[test]
    fn only_a_socket_that_stays_on_the_loopback_is_spared() {
        let s = |src: &str, dst: &str| Socket {
            family: AF_INET,
            state: 1,
            src: src.parse().unwrap(),
            sport: 1,
            dst: dst.parse().unwrap(),
            dport: 2,
            interface: 0,
            cookie: 0,
            uid: 0,
            inode: 0,
            id: [0; SOCKID_LEN],
        };
        assert!(loopback_only(&s("127.0.0.1", "127.0.0.1")));
        assert!(loopback_only(&s("127.0.0.53", "0.0.0.0")));
        assert!(loopback_only(&s("::1", "::1")));
        assert!(loopback_only(&s("::ffff:127.0.0.1", "::ffff:127.0.0.1")));
        assert!(loopback_only(&s("::1", "::")));
        // One end out there: destroyed.
        assert!(!loopback_only(&s("127.0.0.1", "10.99.0.1")));
        assert!(!loopback_only(&s("10.254.1.2", "127.0.0.1")));
        assert!(!loopback_only(&s("0.0.0.0", "0.0.0.0")));
        assert!(!loopback_only(&s("10.254.1.2", "0.0.0.0")));
        assert!(!loopback_only(&s("fd63:656c:6c77::1", "::")));
    }

    /// What a switch breaks: every socket that may reach out — not a
    /// listener, not one that stays on the loopback.
    #[test]
    fn a_switch_breaks_what_may_reach_out_and_spares_the_rest() {
        let s = |state: u8, src: &str, dst: &str| Socket {
            family: AF_INET,
            state,
            src: src.parse().unwrap(),
            sport: 1,
            dst: dst.parse().unwrap(),
            dport: 2,
            interface: 0,
            cookie: 0,
            uid: 0,
            inode: 7,
            id: [0; SOCKID_LEN],
        };
        assert!(to_break(&s(1, "10.254.1.2", "10.99.0.1"), IPPROTO_TCP));
        assert!(!to_break(&s(TCP_LISTEN, "0.0.0.0", "0.0.0.0"), IPPROTO_TCP));
        assert!(!to_break(&s(1, "127.0.0.1", "127.0.0.1"), IPPROTO_TCP));
        // An unconnected UDP socket bound to every address: it may send.
        assert!(to_break(&s(7, "0.0.0.0", "0.0.0.0"), IPPROTO_UDP));
        // State 10 is no listener's for UDP.
        assert!(to_break(
            &s(TCP_LISTEN, "10.254.1.2", "0.0.0.0"),
            IPPROTO_UDP
        ));
        assert!(!to_break(&s(7, "127.0.0.53", "0.0.0.0"), IPPROTO_UDP));
    }

    #[test]
    fn a_socket_is_found_by_its_inode_in_a_programs_descriptors() {
        assert_eq!(socket_inode("socket:[4242]"), Some(4242));
        assert_eq!(socket_inode("pipe:[4242]"), None);
        assert_eq!(socket_inode("socket:[x]"), None);
        assert_eq!(socket_inode("/dev/null"), None);
    }

    #[test]
    fn a_tally_is_said_in_one_line_and_read_back() {
        let tally = Tally {
            tcp: 3,
            udp: 2,
            missed: 1,
            unsupported: 0,
            failed: 0,
            udp_inodes: vec![4242, 17],
            errors: vec!["said on stderr".to_owned()],
        };
        let word = tally.word();
        assert_eq!(
            word,
            "tcp=3 udp=2 missed=1 unsupported=0 failed=0 udp-inodes=4242,17"
        );
        assert_eq!(
            Tally::parse(&word),
            Tally {
                errors: Vec::new(),
                ..tally
            }
        );
        assert_eq!(Tally::parse(""), Tally::default());
        assert_eq!(Tally::parse("udp-inodes= odd"), Tally::default());
    }
}
