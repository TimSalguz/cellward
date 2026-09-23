//! The host's names through a zone (`docs/SYSTEM.md` §9c): a DNS forwarder
//! that listens in the host's network and asks in the zone's.
//!
//! A network namespace has no way into another one, and that is the whole
//! point of a zone — so the host's resolver cannot simply "use" a zone. What
//! can be in two namespaces at once is a process: systemd opens the listening
//! sockets (`vpn-zones-dns.socket`, 127.0.0.60:53, UDP and TCP) in the host's
//! namespace and hands them to this service, which itself runs in the zone's
//! (`NetworkNamespacePath=`). A socket stays in the namespace it was made in,
//! so the queries arrive from the host, and every socket this process makes to
//! ask them further is made in the zone. The host's resolver — resolved, nscd,
//! `/etc/resolv.conf` — points here and nowhere else.
//!
//! **Nothing is parsed.** A query is forwarded as bytes and an answer is
//! passed back as bytes; the only field read is the ID, to drop an answer
//! that is not to this query. Each query gets a socket of its own, connected
//! to the resolver, so the kernel picks a fresh source port and drops what
//! comes from anywhere else.
//!
//! **Where it asks.** `--resolv FILE`: the `nameserver` lines of the zone's
//! resolv.conf, bound over `/etc/resolv.conf` by the attaching drop-in and
//! read again for every query — the zone rewrites it in place when its tunnel
//! comes up. `--upstream ADDR[:PORT]`: fixed addresses, what the unit has
//! when vpn-zones are off. No resolver: the query is dropped, and the asker
//! times out — a zone that is not up answers nothing rather than something
//! from elsewhere.

use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{FromRawFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// systemd's first passed descriptor (sd_listen_fds(3)).
const LISTEN_FDS_START: RawFd = 3;
/// How long one resolver gets for an answer before the next is tried.
const UDP_WAIT: Duration = Duration::from_secs(2);
/// A TCP client or resolver that says nothing for this long is dropped.
const TCP_IDLE: Duration = Duration::from_secs(10);
const TCP_CONNECT: Duration = Duration::from_secs(3);
/// Queries in flight at once, per protocol: beyond it new ones are dropped
/// rather than threads made without end.
const MAX_IN_FLIGHT: usize = 128;
/// The largest DNS message there is (TCP's two-byte length).
const MAX_MESSAGE: usize = 65_535;

/// What `vpn-zone-core dns-forward` was asked to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Args {
    pub resolv: Option<PathBuf>,
    pub upstreams: Vec<SocketAddr>,
}

impl Args {
    /// `[--resolv FILE] [--upstream ADDR[:PORT]]…`
    pub fn parse(argv: &[std::ffi::OsString]) -> Result<Self, String> {
        let mut args = Self::default();
        let mut rest = argv.iter();
        while let Some(flag) = rest.next() {
            let flag = flag.to_str().ok_or("the arguments have to be UTF-8")?;
            let value = rest
                .next()
                .and_then(|v| v.to_str())
                .ok_or_else(|| format!("{flag} needs a value"))?;
            match flag {
                "--resolv" => args.resolv = Some(PathBuf::from(value)),
                "--upstream" => args.upstreams.push(
                    parse_upstream(value)
                        .ok_or_else(|| format!("--upstream {value}: not an address"))?,
                ),
                _ => return Err(format!("unknown flag: {flag}")),
            }
        }
        if args.resolv.is_none() && args.upstreams.is_empty() {
            return Err("need --resolv or --upstream".to_owned());
        }
        Ok(args)
    }

    /// The resolvers to ask now, in order.
    fn resolvers(&self) -> Vec<SocketAddr> {
        let mut out = self.upstreams.clone();
        if let Some(path) = &self.resolv {
            out.extend(nameservers(&fs::read_to_string(path).unwrap_or_default()));
        }
        out
    }
}

/// `1.1.1.1`, `1.1.1.1:5353`, `2606:4700::1111`, `[::1]:5353`.
pub fn parse_upstream(text: &str) -> Option<SocketAddr> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Some(addr);
    }
    text.parse::<IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, 53))
}

/// The `nameserver` lines of a resolv.conf, as addresses on port 53. A line
/// that is not an address (a scope suffix, garbage) is skipped.
pub fn nameservers(text: &str) -> Vec<SocketAddr> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some("nameserver")).then_some(())?;
            words.next()?.parse::<IpAddr>().ok()
        })
        .map(|ip| SocketAddr::new(ip, 53))
        .collect()
}

/// Whether an answer is to this query: the same ID, and at least a header.
pub fn answers(query: &[u8], reply: &[u8]) -> bool {
    query.len() >= 2 && reply.len() >= 12 && query[..2] == reply[..2]
}

/// Ask the resolvers in turn over UDP; the first answer to this query wins.
pub fn forward_udp(query: &[u8], resolvers: &[SocketAddr]) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; MAX_MESSAGE];
    for resolver in resolvers {
        let local: SocketAddr = if resolver.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let Ok(sock) = UdpSocket::bind(local) else {
            continue;
        };
        if sock.connect(resolver).is_err()
            || sock.set_read_timeout(Some(UDP_WAIT)).is_err()
            || sock.send(query).is_err()
        {
            continue;
        }
        // A stray datagram with another ID is not an answer; keep waiting
        // for this resolver until its time is up.
        while let Ok(n) = sock.recv(&mut buf) {
            if answers(query, &buf[..n]) {
                return Some(buf[..n].to_vec());
            }
        }
    }
    None
}

fn read_message(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    stream.read_exact(&mut len)?;
    let mut message = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut message)?;
    Ok(message)
}

fn write_message(stream: &mut TcpStream, message: &[u8]) -> io::Result<()> {
    let len = u16::try_from(message.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "message too long"))?;
    let mut framed = Vec::with_capacity(message.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(message);
    stream.write_all(&framed)
}

/// Ask the resolvers in turn over TCP.
pub fn forward_tcp(query: &[u8], resolvers: &[SocketAddr]) -> Option<Vec<u8>> {
    for resolver in resolvers {
        let Ok(mut up) = TcpStream::connect_timeout(resolver, TCP_CONNECT) else {
            continue;
        };
        let _ = up.set_read_timeout(Some(TCP_IDLE));
        let _ = up.set_write_timeout(Some(TCP_IDLE));
        if write_message(&mut up, query).is_err() {
            continue;
        }
        if let Ok(reply) = read_message(&mut up) {
            if answers(query, &reply) {
                return Some(reply);
            }
        }
    }
    None
}

/// One slot of `MAX_IN_FLIGHT`, given back when dropped.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(count: &Arc<AtomicUsize>) -> Option<Self> {
        let taken = count.fetch_add(1, Ordering::SeqCst);
        if taken >= MAX_IN_FLIGHT {
            count.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Self(Arc::clone(count)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn serve_udp(listener: UdpSocket, args: Arc<Args>) {
    let listener = Arc::new(listener);
    let in_flight = Arc::new(AtomicUsize::new(0));
    let mut buf = vec![0u8; MAX_MESSAGE];
    loop {
        let Ok((n, client)) = listener.recv_from(&mut buf) else {
            continue;
        };
        let Some(slot) = Slot::take(&in_flight) else {
            continue;
        };
        let query = buf[..n].to_vec();
        let (listener, args) = (Arc::clone(&listener), Arc::clone(&args));
        thread::spawn(move || {
            let _slot = slot;
            if let Some(reply) = forward_udp(&query, &args.resolvers()) {
                let _ = listener.send_to(&reply, client);
            }
        });
    }
}

fn serve_tcp_client(mut client: TcpStream, args: &Args) {
    let _ = client.set_read_timeout(Some(TCP_IDLE));
    let _ = client.set_write_timeout(Some(TCP_IDLE));
    while let Ok(query) = read_message(&mut client) {
        let Some(reply) = forward_tcp(&query, &args.resolvers()) else {
            return;
        };
        if write_message(&mut client, &reply).is_err() {
            return;
        }
    }
}

fn serve_tcp(listener: TcpListener, args: Arc<Args>) {
    let in_flight = Arc::new(AtomicUsize::new(0));
    for client in listener.incoming() {
        let Ok(client) = client else {
            continue;
        };
        let Some(slot) = Slot::take(&in_flight) else {
            continue;
        };
        let args = Arc::clone(&args);
        thread::spawn(move || {
            let _slot = slot;
            serve_tcp_client(client, &args);
        });
    }
}

/// How many descriptors systemd passed, per sd_listen_fds(3): only when
/// `LISTEN_PID` is this process.
pub fn listen_fds(pid: &str, fds: &str, me: u32) -> usize {
    if pid.trim().parse::<u32>().ok() != Some(me) {
        return 0;
    }
    fds.trim().parse().unwrap_or(0)
}

fn socket_type(fd: RawFd) -> Option<libc::c_int> {
    let mut kind: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `kind`.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&raw mut kind).cast(),
            &raw mut len,
        )
    };
    (rc == 0).then_some(kind)
}

/// Serve the sockets systemd passed until killed. Returns the exit code.
pub fn run(args: Args) -> u8 {
    let count = listen_fds(
        &std::env::var("LISTEN_PID").unwrap_or_default(),
        &std::env::var("LISTEN_FDS").unwrap_or_default(),
        std::process::id(),
    );
    if count == 0 {
        eprintln!("dns-forward: no sockets from systemd (run it from vpn-zones-dns.socket)");
        return 1;
    }
    let args = Arc::new(args);
    let mut workers = Vec::new();
    for fd in LISTEN_FDS_START..LISTEN_FDS_START + count as RawFd {
        let args = Arc::clone(&args);
        match socket_type(fd) {
            // SAFETY: systemd passed this descriptor to us to own.
            Some(libc::SOCK_DGRAM) => {
                let sock = unsafe { UdpSocket::from_raw_fd(fd) };
                workers.push(thread::spawn(move || serve_udp(sock, args)));
            }
            // SAFETY: as above.
            Some(libc::SOCK_STREAM) => {
                let sock = unsafe { TcpListener::from_raw_fd(fd) };
                workers.push(thread::spawn(move || serve_tcp(sock, args)));
            }
            _ => eprintln!("dns-forward: descriptor {fd} is not a UDP or TCP socket, skipped"),
        }
    }
    if workers.is_empty() {
        return 1;
    }
    for worker in workers {
        let _ = worker.join();
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn os(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }

    #[test]
    fn the_resolvers_of_a_resolv_conf() {
        assert_eq!(
            nameservers(
                "# a comment\nnameserver 10.99.0.1\nnameserver fe80::1%eth0\n\
                 nameserver 2606:4700::1111\nsearch corp\nnameserver\nnameserver x\n"
            ),
            vec![
                "10.99.0.1:53".parse::<SocketAddr>().unwrap(),
                "[2606:4700::1111]:53".parse().unwrap(),
            ]
        );
        assert!(nameservers("").is_empty());
    }

    #[test]
    fn upstreams_with_and_without_a_port() {
        assert_eq!(
            parse_upstream("1.1.1.1"),
            Some("1.1.1.1:53".parse().unwrap())
        );
        assert_eq!(
            parse_upstream("1.1.1.1:5353"),
            Some("1.1.1.1:5353".parse().unwrap())
        );
        assert_eq!(
            parse_upstream("[::1]:5353"),
            Some("[::1]:5353".parse().unwrap())
        );
        assert_eq!(
            parse_upstream("2606:4700::1111"),
            Some("[2606:4700::1111]:53".parse().unwrap())
        );
        assert_eq!(parse_upstream("resolver.example"), None);
    }

    #[test]
    fn the_command_line() {
        let args = Args::parse(&os(&["--resolv", "/etc/resolv.conf"])).unwrap();
        assert_eq!(args.resolv, Some(PathBuf::from("/etc/resolv.conf")));
        let args = Args::parse(&os(&["--upstream", "1.1.1.1", "--upstream", "9.9.9.9"])).unwrap();
        assert_eq!(args.upstreams.len(), 2);
        assert!(Args::parse(&os(&[])).is_err());
        assert!(Args::parse(&os(&["--upstream", "x"])).is_err());
        assert!(Args::parse(&os(&["--resolv"])).is_err());
        assert!(Args::parse(&os(&["--bogus", "1"])).is_err());
    }

    #[test]
    fn an_answer_is_to_its_query_by_id() {
        let query = [0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        let mut reply = query;
        reply[2] |= 0x80;
        assert!(answers(&query, &reply));
        reply[0] = 0;
        assert!(!answers(&query, &reply));
        assert!(!answers(&query, &query[..4]));
    }

    #[test]
    fn systemd_passes_sockets_to_the_right_process_only() {
        assert_eq!(listen_fds("42", "2", 42), 2);
        assert_eq!(listen_fds("41", "2", 42), 0);
        assert_eq!(listen_fds("", "2", 42), 0);
        assert_eq!(listen_fds("42", "x", 42), 0);
    }

    /// A resolver on loopback that answers every query with its own ID and
    /// one extra byte, after a stray datagram with another ID.
    fn fake_udp_resolver() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let mut stray = buf[..n].to_vec();
                stray[0] ^= 0xff;
                stray.resize(12, 0);
                let _ = sock.send_to(&stray, from);
                let mut reply = buf[..n].to_vec();
                reply.resize(12, 0);
                reply.push(0x42);
                let _ = sock.send_to(&reply, from);
            }
        });
        addr
    }

    #[test]
    fn udp_skips_a_dead_resolver_and_a_stray_answer() {
        // Nothing listens there: the send may even succeed, the answer never
        // comes, and the next resolver is asked.
        let dead = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let live = fake_udp_resolver();
        let query = [7u8, 9, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        let reply = forward_udp(&query, &[dead, live]).unwrap();
        assert_eq!(&reply[..2], &[7, 9]);
        assert_eq!(reply.last(), Some(&0x42));
        assert!(forward_udp(&query, &[]).is_none());
    }

    #[test]
    fn tcp_is_framed_and_forwarded() {
        let resolver = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = resolver.local_addr().unwrap();
        thread::spawn(move || {
            for stream in resolver.incoming().flatten() {
                let mut stream = stream;
                if let Ok(mut message) = read_message(&mut stream) {
                    message.push(0x43);
                    let _ = write_message(&mut stream, &message);
                }
            }
        });
        let query = [1u8, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        let reply = forward_tcp(&query, &[addr]).unwrap();
        assert_eq!(&reply[..2], &[1, 2]);
        assert_eq!(reply.last(), Some(&0x43));
    }
}
