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
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd, RawFd};
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
const BACKGROUND: &str = "org.freedesktop.portal.Background";
const NETWORK_MONITOR: &str = "org.freedesktop.portal.NetworkMonitor";
const PROXY_RESOLVER: &str = "org.freedesktop.portal.ProxyResolver";
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
    /// `Background.RequestBackground`: with `autostart` the portal writes an
    /// autostart entry ON THE HOST, run at the next login outside every zone.
    Background,
    /// `NetworkMonitor.*`: the HOST's network, as the portal sees it — and
    /// `CanReach` has the host resolve and try any name, in the host's
    /// network (review 2026-09-25). Answered here: the zone's network is up,
    /// not metered, full; any name "reachable" without a packet sent.
    Network,
    /// `ProxyResolver.Lookup`: the host's proxy settings. Answered here: a
    /// zone goes out directly, through its own tunnel.
    Proxy,
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
        "RequestBackground" if iface_is(BACKGROUND) => Some(Door::Background),
        "GetAvailable" | "GetMetered" | "GetConnectivity" | "GetStatus" | "CanReach"
            if iface_is(NETWORK_MONITOR) =>
        {
            Some(Door::Network)
        }
        "Lookup" if iface_is(PROXY_RESOLVER) => Some(Door::Proxy),
        _ => None,
    }
}

/// The portal interfaces a program of a zone or a sandbox may call.
///
/// **The portal takes it for a host application.** xdg-desktop-portal knows a
/// caller by the process on the other end of ITS connection — the proxy, which
/// runs outside the sandbox and outside the zone's mount namespace — and finds
/// no `/.flatpak-info` there (review 2026-09-25). A host application is
/// granted without a dialog what a Flatpak would be asked about: the
/// dynamic launcher installs a `.desktop` entry of the caller's making and
/// starts it ON THE HOST; location, camera, a non-interactive screenshot, the
/// Secret portal's key (one for every "host" caller) come the same way. So
/// the interfaces are named here, and everything else under
/// `org.freedesktop.portal.` is refused — a portal added later included.
pub const PORTAL_ALLOWED: &[&str] = &[
    "org.freedesktop.portal.Request",
    "org.freedesktop.portal.Session",
    "org.freedesktop.portal.FileChooser",
    "org.freedesktop.portal.FileTransfer",
    // Answered by the filter itself (`door`).
    "org.freedesktop.portal.OpenURI",
    "org.freedesktop.portal.Email",
    "org.freedesktop.portal.Background",
    // Read-only, or with a dialog of the portal's own every time.
    // Answered by the filter as well (`Door::Network`, `Door::Proxy`): no
    // call of theirs reaches the host.
    "org.freedesktop.portal.NetworkMonitor",
    "org.freedesktop.portal.ProxyResolver",
    "org.freedesktop.portal.Settings",
    "org.freedesktop.portal.Notification",
    "org.freedesktop.portal.Inhibit",
    "org.freedesktop.portal.MemoryMonitor",
    "org.freedesktop.portal.PowerProfileMonitor",
    "org.freedesktop.portal.Print",
    "org.freedesktop.portal.ScreenCast",
    "org.freedesktop.portal.Account",
];

/// Why a call is not passed on, if it is not: a portal interface not in
/// [`PORTAL_ALLOWED`], or a call that names no interface at all — dispatched
/// by its member alone, it could reach any of them. The bus itself is always
/// asked directly.
pub fn refused(h: &Header) -> Option<String> {
    if h.kind != wire::METHOD_CALL {
        return None;
    }
    match h.interface.as_deref() {
        None if h.destination.as_deref() != Some("org.freedesktop.DBus") => Some(format!(
            "{} without an interface",
            h.member.as_deref().unwrap_or("?")
        )),
        Some(i) if i.starts_with("org.freedesktop.portal.") && !PORTAL_ALLOWED.contains(&i) => {
            Some(format!("{i} is not for programs of a zone"))
        }
        // The portal's host registry (`org.freedesktop.host.portal.Registry`,
        // xdg-desktop-portal 1.19+): an unsandboxed caller names itself with
        // any application id, once, before its first portal call. The portal
        // takes a zone's program for such a caller, so it could name itself
        // after a host program — its dialogs and notifications would say that
        // program asked, and the permissions the portal keeps for that id would
        // be its. By interface, not by destination: a unique name reaches the
        // same object. Anything else of the host's `org.freedesktop.host.`
        // tree goes the same way.
        Some(i) if i.starts_with("org.freedesktop.host.") => {
            Some(format!("{i} is not for programs of a zone"))
        }
        _ => None,
    }
}

/// Answer a call with a value, as its service would, from where it was sent to.
fn reply(conn: &Conn, ctx: &Ctx, h: &Header, signature: &str, body: &[u8]) -> io::Result<()> {
    if h.flags & wire::NO_REPLY_EXPECTED != 0 {
        return Ok(());
    }
    let unique = conn
        .unique
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let from = h.destination.clone().unwrap_or_else(|| PORTAL.to_owned());
    let mut fields = vec![Field::ReplySerial(h.serial), Field::Sender(&from)];
    if let Some(d) = unique.as_deref() {
        fields.push(Field::Destination(d));
    }
    fields.push(Field::Signature(signature));
    let msg = wire::message(
        wire::METHOD_RETURN,
        wire::NO_REPLY_EXPECTED,
        ctx.serial(),
        &fields,
        body,
    );
    conn.send(&msg, &[])
}

/// The answers of `Door::Network` and `Door::Proxy`.
fn answer_value(conn: &Conn, ctx: &Ctx, h: &Header, which: Door) -> io::Result<()> {
    match (which, h.member.as_deref().unwrap_or("")) {
        (Door::Network, "GetStatus") => {
            reply(conn, ctx, h, "a{sv}", &body::network_status(true, false, 4))
        }
        (Door::Network, "GetConnectivity") => reply(conn, ctx, h, "u", &body::uint(4)),
        (Door::Network, "GetMetered") => reply(conn, ctx, h, "b", &body::boolean(false)),
        (Door::Network, _) => reply(conn, ctx, h, "b", &body::boolean(true)),
        _ => reply(conn, ctx, h, "as", &body::strings(&["direct://"])),
    }
}

/// Say no to a call the way the bus would: `AccessDenied`, from where it was
/// sent to. Nothing when no reply is expected.
fn deny(conn: &Conn, ctx: &Ctx, h: &Header, why: &str) -> io::Result<()> {
    eprintln!("bus-filter: refused — {why}");
    if h.flags & wire::NO_REPLY_EXPECTED != 0 {
        return Ok(());
    }
    let unique = conn
        .unique
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let from = h.destination.clone().unwrap_or_else(|| PORTAL.to_owned());
    let mut fields = vec![
        Field::ErrorName("org.freedesktop.DBus.Error.AccessDenied"),
        Field::ReplySerial(h.serial),
        Field::Sender(&from),
    ];
    if let Some(d) = unique.as_deref() {
        fields.push(Field::Destination(d));
    }
    fields.push(Field::Signature("s"));
    let reply = wire::message(
        wire::ERROR,
        wire::NO_REPLY_EXPECTED,
        ctx.serial(),
        &fields,
        &body::string(&format!("{}: {why}", crate::dialog::APP)),
    );
    conn.send(&reply, &[])
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
    // The proxy behind is reached through its directory, held from here on:
    // in a zone that directory is about to be covered (`zone::hide_project_state`),
    // so that no program there can connect past this filter. And nobody of
    // the same uid here may borrow the descriptor through `/proc/<pid>/fd`:
    // not dumpable — its /proc is root's, and reading it takes CAP_SYS_PTRACE
    // over the namespace, which the zone's programs do not have.
    // SAFETY: prctl with these arguments takes no pointers.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    let upstream = match held_upstream(&args.upstream) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("bus-filter: cannot open {}: {e}", args.upstream.display());
            return 1;
        }
    };
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
        upstream,
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

/// The client's side of the authentication, as the proxy behind reads it.
///
/// Where the authentication ends is where this filter starts reading
/// messages — and where xdg-dbus-proxy starts applying its rules. The two
/// must agree to the byte: a client that ends it in a way the proxy takes
/// and this filter does not (`BEGIN` followed by a blank and anything, as
/// dbus-daemon allows; or a first line glued to the credentials byte) would
/// have its calls go past the filter unread, OpenURI among them (review
/// 2026-09-25, third round). So the rules are the proxy's own
/// (`auth_line_is_valid`, `auth_line_is_begin` in flatpak-proxy.c): the first
/// byte apart, whole lines, ASCII without control characters beginning with
/// a capital, and a line the proxy would refuse ends the connection here. The
/// end is passed on as the plain `BEGIN` — then neither side can read it
/// differently.
#[derive(Default)]
struct Auth {
    first: bool,
    line: Vec<u8>,
    bytes: usize,
}

impl Auth {
    /// Take `data`: the lines to pass on, and where the messages start if the
    /// authentication ended in it.
    fn feed(&mut self, data: &[u8]) -> io::Result<(Vec<u8>, Option<usize>)> {
        let mut out = Vec::new();
        for (i, &b) in data.iter().enumerate() {
            self.bytes += 1;
            if self.bytes > MAX_AUTH_BYTES {
                return Err(io::Error::other("authentication too long"));
            }
            if !self.first {
                // The credentials byte, on its own as the proxy reads it.
                self.first = true;
                out.push(b);
                continue;
            }
            self.line.push(b);
            if !self.line.ends_with(b"\r\n") {
                continue;
            }
            let text = &self.line[..self.line.len() - 2];
            if !auth_line_is_valid(text) {
                return Err(io::Error::other(
                    "an authentication line the bus proxy would refuse",
                ));
            }
            if auth_line_is_begin(text) {
                out.extend_from_slice(b"BEGIN\r\n");
                self.line.clear();
                return Ok((out, Some(i + 1)));
            }
            out.extend_from_slice(&self.line);
            self.line.clear();
        }
        Ok((out, None))
    }
}

/// xdg-dbus-proxy's `auth_line_is_valid`: ASCII, no control characters, a
/// capital letter first.
fn auth_line_is_valid(line: &[u8]) -> bool {
    line.first().is_some_and(u8::is_ascii_uppercase)
        && line.iter().all(|&b| b.is_ascii() && b >= b' ')
}

/// xdg-dbus-proxy's `auth_line_is_begin`: `BEGIN`, alone or followed by a
/// blank and anything.
fn auth_line_is_begin(line: &[u8]) -> bool {
    line.strip_prefix(b"BEGIN")
        .is_some_and(|rest| matches!(rest.first(), None | Some(b' ' | b'\t')))
}

/// A call the host may have from a zone only rewritten: a notification
/// (`dbus_wire::sanitized_notify`, `sanitized_portal_notification`) and a
/// screen cast's choice of sources, which is not remembered
/// (`sanitized_screencast_sources`). The message rewritten, an error for one
/// the filter cannot read (refused, not passed on unread), `None` for
/// anything else.
fn rewritten(msg: &[u8], h: &Header) -> Option<Result<Vec<u8>, wire::WireError>> {
    if h.kind != wire::METHOD_CALL {
        return None;
    }
    let body = match (h.interface.as_deref(), h.member.as_deref()) {
        (Some("org.freedesktop.Notifications"), Some("Notify")) => {
            if h.unix_fds != 0 {
                return Some(Err(wire::WireError("a notification with descriptors")));
            }
            wire::sanitized_notify(msg, h)
        }
        (Some("org.freedesktop.portal.Notification"), Some("AddNotification")) => {
            wire::sanitized_portal_notification(msg, h)
        }
        (Some("org.freedesktop.portal.ScreenCast"), Some("SelectSources")) => {
            wire::sanitized_screencast_sources(msg, h)
        }
        _ => return None,
    };
    Some(body.map(|body| {
        let mut fields = Vec::new();
        if let Some(path) = h.path.as_deref() {
            fields.push(Field::Path(path));
        }
        if let Some(interface) = h.interface.as_deref() {
            fields.push(Field::Interface(interface));
        }
        if let Some(member) = h.member.as_deref() {
            fields.push(Field::Member(member));
        }
        if let Some(destination) = h.destination.as_deref() {
            fields.push(Field::Destination(destination));
        }
        if let Some(signature) = h.signature.as_deref() {
            fields.push(Field::Signature(signature));
        }
        if h.unix_fds != 0 {
            fields.push(Field::UnixFds(h.unix_fds));
        }
        wire::message(h.kind, h.flags, h.serial, &fields, &body)
    }))
}

/// `upstream` as `/proc/self/fd/N/<name>`, N a descriptor of its directory
/// kept for the life of the process.
fn held_upstream(upstream: &Path) -> io::Result<PathBuf> {
    let (Some(dir), Some(name)) = (upstream.parent(), upstream.file_name()) else {
        return Err(io::Error::other("not a path to a socket"));
    };
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let fd = sys::open_dir(dir)?.into_raw_fd();
    Ok(Path::new(&format!("/proc/self/fd/{fd}")).join(name))
}

fn client_to_bus(
    client: &UnixStream,
    upstream: &UnixStream,
    conn: &Conn,
    ctx: &Ctx,
) -> io::Result<()> {
    let mut buf = vec![0u8; READ_CHUNK];
    let mut fds: VecDeque<OwnedFd> = VecDeque::new();
    let mut auth = Auth::default();
    let mut pending: Vec<u8> = Vec::new();
    let up = upstream.as_raw_fd();
    while let Some(n) = read_chunk(client.as_raw_fd(), &mut buf, &mut fds)? {
        let mut data = &buf[..n];
        if !conn.began.load(Ordering::SeqCst) {
            // The authentication, whole lines at a time, up to BEGIN; what
            // follows BEGIN is messages.
            let (lines, split) = auth.feed(data)?;
            if split.is_some() {
                // Before the bus can answer it, so that the other direction
                // knows to expect messages.
                conn.began.store(true, Ordering::SeqCst);
            }
            send_all(up, &lines, &[])?;
            let Some(split) = split else {
                continue;
            };
            data = &data[split..];
        }
        pending.extend_from_slice(data);
        while let Some((msg, h)) = next_message(&mut pending)? {
            let carried = take_fds(&mut fds, h.unix_fds)?;
            match door(&h) {
                // The descriptors of an answered call are dropped — closed.
                Some(which @ (Door::Network | Door::Proxy)) => answer_value(conn, ctx, &h, which)?,
                Some(which) => answer(conn, ctx, &msg, &h, which)?,
                // So are those of a refused one.
                None if refused(&h).is_some() => {
                    deny(conn, ctx, &h, &refused(&h).unwrap_or_default())?
                }
                None => {
                    let raw: Vec<RawFd> = carried.iter().map(AsRawFd::as_raw_fd).collect();
                    match rewritten(&msg, &h) {
                        // Passed on without what would point the host's daemon
                        // at the network or at an application, or have the
                        // screen shown again without a question.
                        Some(Ok(message)) => send_all(up, &message, &raw)?,
                        Some(Err(e)) => deny(conn, ctx, &h, &format!("call refused: {e}"))?,
                        None => send_all(up, &msg, &raw)?,
                    }
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
        Door::Background => {
            // No note to the user: programs ask this at every start, and the
            // answer changes nothing they can do while running.
            eprintln!(
                "bus-filter: RequestBackground refused — autostart would be the host's, outside the zone"
            );
            RESPONSE_OTHER
        }
        // Answered with a value, never a Request (`answer_value`): here only
        // if called wrongly, and then refused.
        Door::Network | Door::Proxy => RESPONSE_OTHER,
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
        &body::notification(crate::dialog::APP, summary, text),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Where the authentication ends, the proxy's way: whatever follows a
    /// blank after BEGIN, a first line glued to the credentials byte, a line
    /// cut between two reads. The end goes on as the plain BEGIN.
    #[test]
    fn the_authentication_ends_where_the_proxy_says() {
        let mut auth = Auth::default();
        let (out, split) = auth
            .feed(b"\0AUTH EXTERNAL 31303030\r\nBEGIN now\r\nl\x01")
            .unwrap();
        assert_eq!(out, b"\0AUTH EXTERNAL 31303030\r\nBEGIN\r\n");
        assert_eq!(split, Some(36));

        let mut auth = Auth::default();
        let (out, split) = auth.feed(b"\0BEGIN\r\n").unwrap();
        assert_eq!((out.as_slice(), split), (&b"\0BEGIN\r\n"[..], Some(8)));

        let mut auth = Auth::default();
        assert_eq!(
            auth.feed(b"\0NEGOTIATE_UNIX_FD\r\nBEG").unwrap(),
            (b"\0NEGOTIATE_UNIX_FD\r\n".to_vec(), None)
        );
        assert_eq!(
            auth.feed(b"IN\r\nl").unwrap(),
            (b"BEGIN\r\n".to_vec(), Some(4))
        );
    }

    /// A line the proxy would refuse ends the connection here as well, rather
    /// than being read one way here and another there.
    #[test]
    fn a_line_the_proxy_refuses_is_refused() {
        for line in [
            &b"\0BEGIN\tx\r\n"[..],
            b"\0BEGIN\0x\r\n",
            b"\0begin\r\n",
            b"\0 BEGIN\r\n",
            b"\0\r\n",
            b"\0AUTH \xd0\x96\r\n",
        ] {
            assert!(Auth::default().feed(line).is_err(), "{line:?}");
        }
        // Not the end, and passed on: BEGINNING is another word.
        let mut auth = Auth::default();
        assert_eq!(
            auth.feed(b"\0BEGINNING\r\n").unwrap(),
            (b"\0BEGINNING\r\n".to_vec(), None)
        );
    }

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
        assert_eq!(
            door(&call("RequestBackground", Some(BACKGROUND), PORTAL)),
            Some(Door::Background)
        );
        assert_eq!(
            door(&call("RequestBackground", None, ":1.7")),
            Some(Door::Background)
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

    /// The portal takes a zone's program for a host application: only the
    /// named portal interfaces get through, and no call without an interface.
    #[test]
    fn only_the_named_portal_interfaces_get_through() {
        let on = |iface: Option<&str>, dest: &str| {
            let mut h = call("Anything", iface, dest);
            h.destination = Some(dest.to_owned());
            refused(&h)
        };
        for bad in [
            "org.freedesktop.portal.DynamicLauncher",
            "org.freedesktop.portal.Location",
            "org.freedesktop.portal.Camera",
            "org.freedesktop.portal.Screenshot",
            "org.freedesktop.portal.Secret",
            "org.freedesktop.portal.Realtime",
            "org.freedesktop.portal.Documents",
            "org.freedesktop.portal.SomethingNew",
            "org.freedesktop.host.portal.Registry",
            "org.freedesktop.host.SomethingNew",
        ] {
            assert!(on(Some(bad), PORTAL).is_some(), "{bad}");
            // Not by the portal's well-known name either.
            assert!(on(Some(bad), ":1.42").is_some(), "{bad} by a unique name");
        }
        for good in [
            "org.freedesktop.portal.FileChooser",
            "org.freedesktop.portal.Settings",
            "org.freedesktop.portal.Request",
            "org.freedesktop.DBus.Properties",
            "org.freedesktop.Notifications",
            "org.kde.StatusNotifierWatcher",
        ] {
            assert!(on(Some(good), PORTAL).is_none(), "{good}");
        }
        assert!(on(None, PORTAL).is_some());
        assert!(on(None, "org.freedesktop.DBus").is_none());
        let mut signal = call("Anything", Some("org.freedesktop.portal.Location"), PORTAL);
        signal.kind = wire::SIGNAL;
        assert!(refused(&signal).is_none());
    }

    /// The host's network state is not asked for: the filter answers.
    #[test]
    fn network_and_proxy_questions_are_answered_here() {
        for member in [
            "GetAvailable",
            "GetMetered",
            "GetConnectivity",
            "GetStatus",
            "CanReach",
        ] {
            assert_eq!(
                door(&call(member, Some(NETWORK_MONITOR), PORTAL)),
                Some(Door::Network),
                "{member}"
            );
        }
        assert_eq!(
            door(&call("Lookup", Some(PROXY_RESOLVER), PORTAL)),
            Some(Door::Proxy)
        );
        // The trash is not among what passes any more.
        let mut h = call("TrashFile", Some("org.freedesktop.portal.Trash"), PORTAL);
        h.destination = Some(PORTAL.to_owned());
        assert!(refused(&h).is_some());
        // `as` with one string: length 14, then the string.
        let b = body::strings(&["direct://"]);
        assert_eq!(&b[..4], &14u32.to_le_bytes());
        assert_eq!(&b[4..8], &9u32.to_le_bytes());
        assert_eq!(&b[8..17], b"direct://");
        // `a{sv}` of three entries parses back as one array of the stated length.
        let st = body::network_status(true, false, 4);
        let len = u32::from_le_bytes(st[..4].try_into().unwrap()) as usize;
        assert_eq!(st.len(), 8 + len);
    }
}
