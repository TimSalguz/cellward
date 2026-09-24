//! `vpn-zone-core bus-filter` — the session bus of a sandbox, with the door
//! for links (`docs/LEAK-MODEL.md` §2).
//!
//! **Why.** A program in a sandbox sees `/.flatpak-info`, and GTK, Qt, Firefox
//! and `xdg-open` itself then open a link through the portal: `OpenURI` on the
//! session bus. The portal lives on the host and hands the link to the default
//! browser there — in the host's network, or in whatever network that browser
//! already runs in, with nobody asked. A link sent to a program in a zone is
//! then a beacon that ties that zone to the home address.
//!
//! Refusing the call is no answer: GLib does not fall back to `xdg-open` when
//! the portal says no, the link simply does not open. So the call is answered
//! HERE, the way the portal would answer it, and the link is opened with
//! `xdg-open` in the sandbox launcher's context — in the zone, outside the
//! sandbox. From there it takes the door every link of a program in a zone
//! takes: the picker, and for another network the broker's question.
//!
//! ```text
//! program in bwrap ──► bus-filter (this) ──► xdg-dbus-proxy ──► session bus
//!                         │ OpenURI/OpenFile/OpenDirectory, ComposeEmail:
//!                         │ answered here; a link → `xdg-open` in the zone
//! ```
//!
//! Everything else passes byte for byte, file descriptors with the message
//! that carries them; the policy — which names the program may see and talk
//! to — stays `xdg-dbus-proxy`'s. The calls are recognised by member and
//! interface, NOT by destination: the portal's unique name reaches it just as
//! well as its well-known one, and a call without an interface field is
//! delivered by member alone.
//!
//! **What is refused, for now.** A `file:` link, `OpenFile`, `OpenDirectory`
//! (a file of the sandbox, opened on the host by the host's program) and
//! `ComposeEmail` (the host's mail client) are answered "cancelled": opening
//! them in the zone needs the file brought along, which is the next step.
//! Better nothing than the host.
//!
//! Every byte comes from the sandboxed program, so the parsing is
//! `crate::dbus_wire`'s, bounds-checked throughout; a message that does not
//! parse ends the connection. The filter dies with the sandbox launcher
//! (`PR_SET_PDEATHSIG`); a link it opened lives on in its own unit.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::dbus_wire::{self as wire, body, Field, Header};
use crate::sys;

/// The portal's well-known name.
const PORTAL: &str = "org.freedesktop.portal.Desktop";
const OPEN_URI: &str = "org.freedesktop.portal.OpenURI";
const EMAIL: &str = "org.freedesktop.portal.Email";
const REQUEST: &str = "org.freedesktop.portal.Request";
/// `Response` codes: done, and "the interaction ended some other way".
const RESPONSE_OK: u32 = 0;
const RESPONSE_OTHER: u32 = 2;
/// Bounds on what one connection may make the filter hold.
const READ_CHUNK: usize = 64 * 1024;
const MAX_FDS_PER_READ: usize = 64;
const MAX_QUEUED_FDS: usize = 256;
const MAX_AUTH_BYTES: usize = 16 * 1024;
const MAX_CONNECTIONS: usize = 64;
/// Links the filter opens: at most this many in a minute.
const MAX_OPENS_PER_MINUTE: usize = 10;
/// The longest link it opens.
const MAX_URI: usize = 8 * 1024;
/// How often a notice about a refusal may be shown.
const NOTICE_EVERY: Duration = Duration::from_secs(30);
/// What a refused file says.
const FILE_NOTICE: &str = "Программа из контейнера попросила открыть файл другой программой. \
     Сейчас это сделала бы программа хоста, в сети хоста, — поэтому файл не открыт. Откройте \
     его из файлового менеджера или из самой программы.";

/// `vpn-zone-core bus-filter --listen <socket> --upstream <socket> --opener <program>
/// [--via-broker <zone>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub listen: PathBuf,
    pub upstream: PathBuf,
    pub opener: PathBuf,
    /// A hermetic zone's own bus: the filter runs in the zone, but not in a
    /// launch with an environment a link could be opened from — so the link
    /// goes to the broker as "run the opener in this very zone", which the
    /// broker starts without a question (it knows the zone by the network
    /// namespace of the one asking), and from there the usual door.
    pub via_broker: Option<String>,
}

impl Args {
    pub fn parse(argv: &[OsString]) -> Result<Self, String> {
        let (mut listen, mut upstream, mut opener, mut via_broker) = (None, None, None, None);
        let mut it = argv.iter();
        while let Some(flag) = it.next() {
            let value = it
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| format!("{} needs a value", flag.to_string_lossy()))?;
            match flag.to_str() {
                Some("--listen") => listen = Some(value),
                Some("--upstream") => upstream = Some(value),
                Some("--opener") => opener = Some(value),
                Some("--via-broker") => via_broker = Some(value.to_string_lossy().into_owned()),
                _ => return Err(format!("unknown argument {}", flag.to_string_lossy())),
            }
        }
        Ok(Self {
            listen: listen.ok_or("--listen is required")?,
            upstream: upstream.ok_or("--upstream is required")?,
            opener: opener.ok_or("--opener is required")?,
            via_broker,
        })
    }
}

/// What the filter answers itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Door {
    /// `OpenURI.OpenURI`: a link.
    Uri,
    /// `OpenURI.OpenFile`, `OpenURI.OpenDirectory`: a file of the sandbox.
    File,
    /// `Email.ComposeEmail`.
    Email,
}

/// Is this call one the filter answers? By member and interface only: the
/// destination does not matter (see the module's notes).
pub fn door(h: &Header) -> Option<Door> {
    if h.kind != wire::METHOD_CALL {
        return None;
    }
    let iface_is = |want: &str| h.interface.as_deref().is_none_or(|i| i == want);
    match h.member.as_deref()? {
        "OpenURI" if iface_is(OPEN_URI) => Some(Door::Uri),
        "OpenFile" | "OpenDirectory" if iface_is(OPEN_URI) => Some(Door::File),
        "ComposeEmail" if iface_is(EMAIL) => Some(Door::Email),
        _ => None,
    }
}

/// Whether a link may be handed to the opener, and why not.
pub fn acceptable(uri: &str) -> Result<(), &'static str> {
    if uri.len() > MAX_URI {
        return Err("too long");
    }
    if uri.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("control characters or spaces");
    }
    let Some((scheme, _)) = uri.split_once(':') else {
        return Err("no scheme");
    };
    let mut chars = scheme.chars();
    let starts = chars.next().is_some_and(|c| c.is_ascii_alphabetic());
    if !starts || !chars.all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) {
        return Err("not a scheme");
    }
    if scheme.eq_ignore_ascii_case("file") {
        return Err("a local file");
    }
    Ok(())
}

/// What of a link goes into the log: the scheme and the host, never the path
/// or the query, which carry tokens.
pub fn loggable(uri: &str) -> String {
    let Some((scheme, rest)) = uri.split_once(':') else {
        return "?".to_owned();
    };
    match rest.strip_prefix("//") {
        Some(rest) => {
            let host = rest.split(['/', '?', '#']).next().unwrap_or("");
            // Credentials in front of the host stay out too.
            let host = host.rsplit('@').next().unwrap_or(host);
            format!("{scheme}://{host}")
        }
        None => format!("{scheme}:…"),
    }
}

/// The object path a portal request lives at: `…/request/<sender>/<token>`,
/// where the sender is the caller's unique name without `:` and with `_` for
/// `.`. A token that is not an object path element is replaced.
pub fn handle_path(unique: Option<&str>, token: Option<&str>, fallback: u32) -> String {
    let sender = unique
        .map(|u| u.trim_start_matches(':').replace('.', "_"))
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        .unwrap_or_else(|| "unknown".to_owned());
    let token = token
        .filter(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        .map(str::to_owned)
        .unwrap_or_else(|| format!("vpnzones{fallback}"));
    format!("/org/freedesktop/portal/desktop/request/{sender}/{token}")
}

/// Shared by every connection.
struct Ctx {
    upstream: PathBuf,
    opener: PathBuf,
    via_broker: Option<String>,
    opens: Mutex<VecDeque<Instant>>,
    last_notice: Mutex<Option<Instant>>,
    serial: AtomicU32,
    connections: AtomicU32,
}

impl Ctx {
    fn serial(&self) -> u32 {
        // Our own serials, far from where a bus starts counting; never 0.
        self.serial.fetch_add(1, Ordering::Relaxed) | 0x4000_0000
    }

    fn may_open(&self) -> bool {
        let mut opens = self.opens.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        while opens
            .front()
            .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60))
        {
            opens.pop_front();
        }
        if opens.len() >= MAX_OPENS_PER_MINUTE {
            return false;
        }
        opens.push_back(now);
        true
    }
}

/// One connection of the program: the client end, written to only under the
/// lock and only in whole messages, and what was learned about it.
struct Conn {
    client: UnixStream,
    write: Mutex<()>,
    unique: Mutex<Option<String>>,
    began: AtomicBool,
}

impl Conn {
    fn send(&self, bytes: &[u8], fds: &[RawFd]) -> io::Result<()> {
        let _guard = self.write.lock().unwrap_or_else(|e| e.into_inner());
        send_all(self.client.as_raw_fd(), bytes, fds)
    }
}

/// All of `data`, the descriptors with its first byte.
fn send_all(sock: RawFd, data: &[u8], fds: &[RawFd]) -> io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let first = data.len().min(READ_CHUNK);
    sys::send_with_fds(sock, &data[..first], fds)?;
    let mut rest = &data[first..];
    while !rest.is_empty() {
        let chunk = rest.len().min(READ_CHUNK);
        sys::send_with_fds(sock, &rest[..chunk], &[])?;
        rest = &rest[chunk..];
    }
    Ok(())
}

/// Serve until the launcher that started us goes.
pub fn run(args: &Args) -> u8 {
    // SAFETY: prctl with these arguments takes no pointers.
    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
    let _ = fs::remove_file(&args.listen);
    let listener = match UnixListener::bind(&args.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "bus-filter: cannot listen on {}: {e}",
                args.listen.display()
            );
            return 1;
        }
    };
    let _ = fs::set_permissions(&args.listen, fs::Permissions::from_mode(0o600));
    let ctx = Arc::new(Ctx {
        upstream: args.upstream.clone(),
        opener: args.opener.clone(),
        via_broker: args.via_broker.clone(),
        opens: Mutex::new(VecDeque::new()),
        last_notice: Mutex::new(None),
        serial: AtomicU32::new(1),
        connections: AtomicU32::new(0),
    });
    for client in listener.incoming() {
        let Ok(client) = client else {
            continue;
        };
        if ctx.connections.load(Ordering::SeqCst) as usize >= MAX_CONNECTIONS {
            eprintln!("bus-filter: too many connections — refused");
            continue;
        }
        let ctx = Arc::clone(&ctx);
        ctx.connections.fetch_add(1, Ordering::SeqCst);
        thread::spawn(move || {
            // A client that goes as soon as it has its answer is the usual
            // end, not news.
            match serve(client, &ctx) {
                Err(e)
                    if !matches!(
                        e.kind(),
                        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    eprintln!("bus-filter: connection closed: {e}");
                }
                _ => {}
            }
            ctx.connections.fetch_sub(1, Ordering::SeqCst);
        });
    }
    0
}

fn serve(client: UnixStream, ctx: &Arc<Ctx>) -> io::Result<()> {
    let upstream = UnixStream::connect(&ctx.upstream)?;
    let conn = Arc::new(Conn {
        client: client.try_clone()?,
        write: Mutex::new(()),
        unique: Mutex::new(None),
        began: AtomicBool::new(false),
    });
    let down = {
        let conn = Arc::clone(&conn);
        let upstream = upstream.try_clone()?;
        thread::spawn(move || {
            let _ = bus_to_client(&upstream, &conn);
            let _ = conn.client.shutdown(std::net::Shutdown::Both);
            let _ = upstream.shutdown(std::net::Shutdown::Both);
        })
    };
    let result = client_to_bus(&client, &upstream, &conn, ctx);
    let _ = client.shutdown(std::net::Shutdown::Both);
    let _ = upstream.shutdown(std::net::Shutdown::Both);
    let _ = down.join();
    result
}

/// Read the next chunk: bytes and descriptors, `None` at the end.
fn read_chunk(
    sock: RawFd,
    buf: &mut [u8],
    fds: &mut VecDeque<OwnedFd>,
) -> io::Result<Option<usize>> {
    let (n, got, truncated) = sys::recv_into_with_fds(sock, buf, MAX_FDS_PER_READ)?;
    if truncated {
        return Err(io::Error::other("descriptors were cut off"));
    }
    fds.extend(got);
    if fds.len() > MAX_QUEUED_FDS {
        return Err(io::Error::other("too many descriptors"));
    }
    Ok((n > 0).then_some(n))
}

/// The complete messages at the front of `pending`, each with its header.
fn next_message(pending: &mut Vec<u8>) -> io::Result<Option<(Vec<u8>, Header)>> {
    let Some(len) = wire::message_len(pending).map_err(io::Error::other)? else {
        return Ok(None);
    };
    if pending.len() < len {
        return Ok(None);
    }
    let msg: Vec<u8> = pending.drain(..len).collect();
    let h = wire::parse_header(&msg).map_err(io::Error::other)?;
    Ok(Some((msg, h)))
}

fn take_fds(fds: &mut VecDeque<OwnedFd>, n: u32) -> io::Result<Vec<OwnedFd>> {
    let n = n as usize;
    if n > fds.len() {
        return Err(io::Error::other(
            "a message names descriptors that did not come",
        ));
    }
    Ok(fds.drain(..n).collect())
}

fn client_to_bus(
    client: &UnixStream,
    upstream: &UnixStream,
    conn: &Conn,
    ctx: &Ctx,
) -> io::Result<()> {
    let mut buf = vec![0u8; READ_CHUNK];
    let mut fds: VecDeque<OwnedFd> = VecDeque::new();
    let mut line: Vec<u8> = Vec::new();
    let mut auth_bytes = 0usize;
    let mut pending: Vec<u8> = Vec::new();
    let up = upstream.as_raw_fd();
    while let Some(n) = read_chunk(client.as_raw_fd(), &mut buf, &mut fds)? {
        let mut data = &buf[..n];
        if !conn.began.load(Ordering::SeqCst) {
            // The authentication, line by line and passed on as it is, up to
            // and including BEGIN; what follows BEGIN is messages.
            let mut split = None;
            for (i, &b) in data.iter().enumerate() {
                line.push(b);
                if line.ends_with(b"\r\n") {
                    if line == b"BEGIN\r\n" {
                        split = Some(i + 1);
                        break;
                    }
                    line.clear();
                }
            }
            auth_bytes += split.unwrap_or(data.len());
            if auth_bytes > MAX_AUTH_BYTES {
                return Err(io::Error::other("authentication too long"));
            }
            let (auth, rest) = data.split_at(split.unwrap_or(data.len()));
            if split.is_some() {
                // Before the bus can answer it, so that the other direction
                // knows to expect messages.
                conn.began.store(true, Ordering::SeqCst);
            }
            send_all(up, auth, &[])?;
            if split.is_none() {
                continue;
            }
            data = rest;
        }
        pending.extend_from_slice(data);
        while let Some((msg, h)) = next_message(&mut pending)? {
            let carried = take_fds(&mut fds, h.unix_fds)?;
            match door(&h) {
                // The descriptors of an answered call are dropped — closed.
                Some(which) => answer(conn, ctx, &msg, &h, which)?,
                None => {
                    let raw: Vec<RawFd> = carried.iter().map(AsRawFd::as_raw_fd).collect();
                    send_all(up, &msg, &raw)?;
                }
            }
        }
    }
    Ok(())
}

fn bus_to_client(upstream: &UnixStream, conn: &Conn) -> io::Result<()> {
    let mut buf = vec![0u8; READ_CHUNK];
    let mut fds: VecDeque<OwnedFd> = VecDeque::new();
    let mut text: Vec<u8> = Vec::new();
    let mut binary = false;
    let mut pending: Vec<u8> = Vec::new();
    while let Some(n) = read_chunk(upstream.as_raw_fd(), &mut buf, &mut fds)? {
        if binary {
            pending.extend_from_slice(&buf[..n]);
        } else {
            text.extend_from_slice(&buf[..n]);
            // The bus's lines (OK, AGREE_UNIX_FD, REJECTED…) go through as
            // they are. Its first message can only follow the client's BEGIN,
            // and a message starts with its endianness byte, which no line
            // does.
            loop {
                let begins_message =
                    conn.began.load(Ordering::SeqCst) && matches!(text.first(), Some(b'l' | b'B'));
                if begins_message {
                    binary = true;
                    pending = std::mem::take(&mut text);
                    break;
                }
                let Some(end) = text.windows(2).position(|w| w == b"\r\n") else {
                    break;
                };
                let line: Vec<u8> = text.drain(..end + 2).collect();
                conn.send(&line, &[])?;
            }
            if text.len() > MAX_AUTH_BYTES {
                return Err(io::Error::other("authentication too long"));
            }
        }
        while let Some((msg, h)) = next_message(&mut pending)? {
            // The bus addresses the connection by its unique name, first in
            // the reply to Hello: what a portal request's path is made of.
            if let Some(dest) = h.destination.as_deref().filter(|d| d.starts_with(':')) {
                let mut unique = conn.unique.lock().unwrap_or_else(|e| e.into_inner());
                if unique.is_none() {
                    *unique = Some(dest.to_owned());
                }
            }
            let carried = take_fds(&mut fds, h.unix_fds)?;
            let raw: Vec<RawFd> = carried.iter().map(AsRawFd::as_raw_fd).collect();
            conn.send(&msg, &raw)?;
        }
    }
    Ok(())
}

/// Answer a call the way the portal would: the request's handle, then its
/// `Response` — done, or cancelled.
fn answer(conn: &Conn, ctx: &Ctx, msg: &[u8], h: &Header, which: Door) -> io::Result<()> {
    let parsed = wire::portal_call(msg, h)
        .map_err(|e| {
            eprintln!(
                "bus-filter: {} does not parse: {e}",
                h.member.as_deref().unwrap_or("?")
            )
        })
        .ok();
    let token = parsed.as_ref().and_then(|(_, t)| t.clone());
    let unique = conn
        .unique
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let handle = handle_path(unique.as_deref(), token.as_deref(), ctx.serial());
    // A client checks that a portal signal comes from the portal's current
    // owner (GLib since 2.80.1): the unique name, asked on a connection of
    // our own. With no portal running, the well-known name is all there is.
    let portal = portal_owner(&ctx.upstream).unwrap_or_else(|| PORTAL.to_owned());
    let dest = unique.as_deref();

    if h.flags & wire::NO_REPLY_EXPECTED == 0 {
        let mut fields = vec![Field::ReplySerial(h.serial), Field::Sender(&portal)];
        if let Some(d) = dest {
            fields.push(Field::Destination(d));
        }
        fields.push(Field::Signature("o"));
        let reply = wire::message(
            wire::METHOD_RETURN,
            wire::NO_REPLY_EXPECTED,
            ctx.serial(),
            &fields,
            &body::string(&handle),
        );
        conn.send(&reply, &[])?;
    }

    let code = match which {
        Door::Uri => match parsed.as_ref().and_then(|(s, _)| s.get(1)) {
            Some(uri) => open_link(ctx, uri),
            None => {
                eprintln!("bus-filter: OpenURI that does not parse — refused");
                RESPONSE_OTHER
            }
        },
        Door::File => {
            eprintln!(
                "bus-filter: {} refused — a file of the sandbox is not opened on the host",
                h.member.as_deref().unwrap_or("?")
            );
            notify(ctx, "Файл не открыт", FILE_NOTICE);
            RESPONSE_OTHER
        }
        Door::Email => {
            eprintln!(
                "bus-filter: ComposeEmail refused — the host's mail client is outside the zone"
            );
            notify(
                ctx,
                "Письмо не создано",
                "Программа из контейнера попросила почтовый клиент хоста — он вне её зоны, \
                 поэтому не открыт.",
            );
            RESPONSE_OTHER
        }
    };

    let mut fields = vec![
        Field::Path(&handle),
        Field::Interface(REQUEST),
        Field::Member("Response"),
        Field::Sender(&portal),
    ];
    if let Some(d) = dest {
        fields.push(Field::Destination(d));
    }
    fields.push(Field::Signature("ua{sv}"));
    let signal = wire::message(
        wire::SIGNAL,
        wire::NO_REPLY_EXPECTED,
        ctx.serial(),
        &fields,
        &body::response(code),
    );
    conn.send(&signal, &[])
}

/// Hand a link to the opener, in this process's context — the zone, outside
/// the sandbox. The response code for the portal answer.
fn open_link(ctx: &Ctx, uri: &str) -> u32 {
    let shown = loggable(uri);
    if let Err(why) = acceptable(uri) {
        eprintln!("bus-filter: link {shown} refused: {why}");
        if why == "a local file" {
            notify(ctx, "Файл не открыт", FILE_NOTICE);
        }
        return RESPONSE_OTHER;
    }
    if !ctx.may_open() {
        eprintln!("bus-filter: link {shown} refused: more than {MAX_OPENS_PER_MINUTE} a minute");
        return RESPONSE_OTHER;
    }
    if let Some(zone) = &ctx.via_broker {
        let argv: Vec<OsString> = vec![
            zone.into(),
            "--".into(),
            ctx.opener.clone().into(),
            uri.into(),
        ];
        return match crate::broker::request(b"", &argv) {
            Some(0) => {
                eprintln!("bus-filter: link {shown} → the broker, into the zone {zone}");
                RESPONSE_OK
            }
            other => {
                eprintln!("bus-filter: link {shown}: the broker did not start it ({other:?})");
                RESPONSE_OTHER
            }
        };
    }
    match Command::new(&ctx.opener)
        .arg(uri)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
    {
        Ok(mut child) => {
            eprintln!(
                "bus-filter: link {shown} → {} in the zone",
                ctx.opener.display()
            );
            thread::spawn(move || {
                let _ = child.wait();
            });
            RESPONSE_OK
        }
        Err(e) => {
            eprintln!(
                "bus-filter: link {shown}: cannot run {}: {e}",
                ctx.opener.display()
            );
            RESPONSE_OTHER
        }
    }
}

/// A short connection of the filter's own through the same filtered bus: the
/// same rules as the program's, nothing the program could not ask itself.
struct OwnConn {
    stream: UnixStream,
    pending: Vec<u8>,
    serial: u32,
}

impl OwnConn {
    fn open(upstream: &Path) -> Option<Self> {
        let mut stream = UnixStream::connect(upstream).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .ok()?;
        // SAFETY: getuid(2) cannot fail and takes no pointers.
        let uid = unsafe { libc::getuid() }.to_string();
        let hex: String = uid.bytes().map(|b| format!("{b:02x}")).collect();
        stream
            .write_all(format!("\0AUTH EXTERNAL {hex}\r\n").as_bytes())
            .ok()?;
        let mut pending = Vec::new();
        let mut chunk = [0u8; 512];
        let line_end = loop {
            if let Some(end) = pending.windows(2).position(|w| w == b"\r\n") {
                break end;
            }
            let n = io::Read::read(&mut stream, &mut chunk).ok()?;
            if n == 0 || pending.len() > MAX_AUTH_BYTES {
                return None;
            }
            pending.extend_from_slice(&chunk[..n]);
        };
        if !pending.starts_with(b"OK ") {
            return None;
        }
        pending.drain(..line_end + 2);
        stream.write_all(b"BEGIN\r\n").ok()?;
        let mut conn = Self {
            stream,
            pending,
            serial: 0,
        };
        conn.call(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "Hello",
            None,
            &[],
        )?;
        Some(conn)
    }

    /// A method call and its reply (or error), within the read timeout.
    fn call(
        &mut self,
        dest: &str,
        path: &str,
        iface: &str,
        member: &str,
        sig: Option<&str>,
        body: &[u8],
    ) -> Option<(Vec<u8>, Header)> {
        self.serial += 1;
        let serial = self.serial;
        let mut fields = vec![
            Field::Path(path),
            Field::Interface(iface),
            Field::Member(member),
            Field::Destination(dest),
        ];
        if let Some(sig) = sig {
            fields.push(Field::Signature(sig));
        }
        self.stream
            .write_all(&wire::message(wire::METHOD_CALL, 0, serial, &fields, body))
            .ok()?;
        let mut chunk = [0u8; 4096];
        loop {
            while let Ok(Some((msg, h))) = next_message(&mut self.pending) {
                if h.reply_serial == Some(serial) {
                    return Some((msg, h));
                }
            }
            let n = io::Read::read(&mut self.stream, &mut chunk).ok()?;
            if n == 0 || self.pending.len() > 1 << 20 {
                return None;
            }
            self.pending.extend_from_slice(&chunk[..n]);
        }
    }
}

/// The portal's unique name, asked on a connection of our own.
fn portal_owner(upstream: &Path) -> Option<String> {
    let mut conn = OwnConn::open(upstream)?;
    let (msg, h) = conn.call(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "GetNameOwner",
        Some("s"),
        &body::string(PORTAL),
    )?;
    (h.kind == wire::METHOD_RETURN)
        .then(|| wire::body_string(&msg, &h).ok())
        .flatten()
}

/// Say why nothing opened: a refusal nobody sees looks like a broken program.
/// At most one notice in [`NOTICE_EVERY`], so that a program cannot flood the
/// desktop with them.
fn notify(ctx: &Ctx, summary: &str, text: &str) {
    {
        let mut last = ctx.last_notice.lock().unwrap_or_else(|e| e.into_inner());
        if last.is_some_and(|t| t.elapsed() < NOTICE_EVERY) {
            return;
        }
        *last = Some(Instant::now());
    }
    let Some(mut conn) = OwnConn::open(&ctx.upstream) else {
        return;
    };
    let _ = conn.call(
        "org.freedesktop.Notifications",
        "/org/freedesktop/Notifications",
        "org.freedesktop.Notifications",
        "Notify",
        Some(body::NOTIFY_SIGNATURE),
        &body::notification("vpn-zones", summary, text),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(member: &str, interface: Option<&str>, dest: &str) -> Header {
        Header {
            kind: wire::METHOD_CALL,
            member: Some(member.to_owned()),
            interface: interface.map(str::to_owned),
            destination: Some(dest.to_owned()),
            ..Header::default()
        }
    }

    /// Recognised by what is called, not by whom: the portal's unique name and
    /// a call with no interface field reach it just the same.
    #[test]
    fn the_doors_are_known_by_member_and_interface() {
        assert_eq!(
            door(&call("OpenURI", Some(OPEN_URI), PORTAL)),
            Some(Door::Uri)
        );
        assert_eq!(
            door(&call("OpenURI", Some(OPEN_URI), ":1.7")),
            Some(Door::Uri)
        );
        assert_eq!(door(&call("OpenURI", None, ":1.7")), Some(Door::Uri));
        assert_eq!(door(&call("OpenFile", None, PORTAL)), Some(Door::File));
        assert_eq!(
            door(&call("OpenDirectory", Some(OPEN_URI), PORTAL)),
            Some(Door::File)
        );
        assert_eq!(
            door(&call("ComposeEmail", Some(EMAIL), PORTAL)),
            Some(Door::Email)
        );
        // The same member on another interface, a query, a signal: passed on.
        assert_eq!(
            door(&call("OpenURI", Some("org.example.Other"), PORTAL)),
            None
        );
        assert_eq!(door(&call("SchemeSupported", Some(OPEN_URI), PORTAL)), None);
        let mut signal = call("OpenURI", Some(OPEN_URI), PORTAL);
        signal.kind = wire::SIGNAL;
        assert_eq!(door(&signal), None);
    }

    #[test]
    fn links_are_checked_and_logged_without_their_secrets() {
        assert!(acceptable("https://example.org/a?b=c").is_ok());
        assert!(acceptable("mailto:someone@example.org").is_ok());
        assert!(acceptable("tg://resolve?domain=x").is_ok());
        assert_eq!(acceptable("file:///etc/passwd"), Err("a local file"));
        assert_eq!(acceptable("FILE:///x"), Err("a local file"));
        assert_eq!(
            acceptable("https://a b"),
            Err("control characters or spaces")
        );
        assert_eq!(
            acceptable("https://a\nb"),
            Err("control characters or spaces")
        );
        assert_eq!(acceptable("-x:y"), Err("not a scheme"));
        assert_eq!(acceptable("no-colon"), Err("no scheme"));
        assert_eq!(
            acceptable(&format!("https://{}", "a".repeat(MAX_URI))),
            Err("too long")
        );
        assert_eq!(
            loggable("https://user:pw@example.org/path?token=secret#x"),
            "https://example.org"
        );
        assert_eq!(loggable("mailto:someone@example.org"), "mailto:…");
    }

    #[test]
    fn a_request_path_is_made_of_the_sender_and_the_token() {
        assert_eq!(
            handle_path(Some(":1.42"), Some("gtk3"), 5),
            "/org/freedesktop/portal/desktop/request/1_42/gtk3"
        );
        assert_eq!(
            handle_path(Some(":1.42"), Some("bad/token"), 5),
            "/org/freedesktop/portal/desktop/request/1_42/vpnzones5"
        );
        assert_eq!(
            handle_path(None, None, 9),
            "/org/freedesktop/portal/desktop/request/unknown/vpnzones9"
        );
    }

    #[test]
    fn at_most_so_many_links_a_minute() {
        let ctx = Ctx {
            upstream: PathBuf::new(),
            opener: PathBuf::new(),
            via_broker: None,
            opens: Mutex::new(VecDeque::new()),
            last_notice: Mutex::new(None),
            serial: AtomicU32::new(1),
            connections: AtomicU32::new(0),
        };
        for _ in 0..MAX_OPENS_PER_MINUTE {
            assert!(ctx.may_open());
        }
        assert!(!ctx.may_open());
        assert_ne!(ctx.serial(), 0);
    }
}
