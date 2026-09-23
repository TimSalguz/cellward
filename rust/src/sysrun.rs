//! A user's program in a system zone (ROADMAP M10 stage 4, `docs/SYSTEM.md`
//! §7): `vpn-zone-sys <zone> -- <command>`.
//!
//! ```text
//! vpn-zone-sys (the user)                  vpn-zone-sysrun@N (root, one per launch)
//!  connect /run/vpn-zones/sysrun.sock ───►  who: SO_PEERCRED, from the kernel
//!  a pty of its own; the request           may this user use this zone?
//!    + the pty's slave (or 0, 1, 2)        fork ─ the zone's network
//!  relay: terminal ⇄ pty master                   own mount namespace: the zone's
//!                                                 resolv.conf and nsswitch, the
//!                                                 host's resolvers, system bus and
//!                                                 session sockets hidden
//!                                                 drop to the user, NO_NEW_PRIVS
//!                                                 exec the command
//!  ◄── EXIT <code>                         wait, answer
//! ```
//!
//! **Why a service at all.** A system zone's namespace belongs to the host's
//! user namespace; entering it takes `CAP_SYS_ADMIN` there, which no program of
//! a user has. Something privileged has to do the entering — and then get out
//! of the way before the user's command runs.
//!
//! **What root does, and what it does not.** Root reads who is asking from the
//! kernel, checks the zone's list of users, enters the zone and prepares the
//! mounts: the paths are fixed, and the only part that comes from the request is
//! the zone's name, which is checked like any zone name before it becomes a
//! path. Everything else in the request — the command, its directory, its
//! environment — is applied only after the privileges are gone, as the user,
//! and could not do anything the user cannot do anyway. `NO_NEW_PRIVS` makes
//! that stick: `sudo` inside would be root in the zone's namespace, which can
//! add a route around the tunnel.
//!
//! **The terminal stays the user's business.** The client makes the pty and
//! relays it; the service only gets the slave end, which becomes the command's
//! controlling terminal. Ctrl-C, job control and the window size then work the
//! way they do in any terminal, without a signal ever passing through root.
//! Without a terminal (a pipe, a script) the client's own 0, 1 and 2 are passed.
//!
//! **One unit per launch** (`Accept=yes`): the command lives in the cgroup of
//! its own `vpn-zone-sysrun@…` instance — listed by `systemctl`, stopped with
//! it, and nothing it leaves behind outlives it.
//!
//! **Console programs only, for now.** The session's sockets — its bus, the
//! compositor, pipewire — are hidden: a program that could ask the host's
//! session to open a link would have a way out around the zone. Graphical
//! programs need the sealing user zones do (LEAK-MODEL §13) and come later.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use crate::system::{self, check_name};
use crate::{sys, zone};

/// The socket; the NixOS module makes it `0660 root:vpn-zones`.
pub const SOCKET: &str = "/run/vpn-zones/sysrun.sock";
/// Per zone: `users` (one name per line) and, if present, `system-bus`.
pub const ZONES_DIR: &str = "/etc/vpn-zones/system-zones.d";

const MAGIC: &[u8] = b"VZS1\0";
/// A request is one datagram of a SOCK_SEQPACKET socket, so it has a size.
pub const MAX_REQUEST: usize = 64 * 1024;
const MAX_ITEMS: usize = 4096;
/// Variables that point at the session, which a program here has no access to
/// — or at vpn-zones' own idea of where the program runs.
const DROPPED_ENV: [&[u8]; 6] = [
    b"DBUS_SESSION_BUS_ADDRESS",
    b"WAYLAND_DISPLAY",
    b"DISPLAY",
    b"XDG_RUNTIME_DIR",
    b"SSH_AUTH_SOCK",
    b"VPN_ZONE_CURRENT",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The client's pty: one descriptor, the slave.
    Pty,
    /// No terminal: the client's 0, 1 and 2.
    Pipes,
}

impl Mode {
    fn word(self) -> &'static str {
        match self {
            Self::Pty => "pty",
            Self::Pipes => "pipes",
        }
    }

    fn parse(word: &[u8]) -> Option<Self> {
        match word {
            b"pty" => Some(Self::Pty),
            b"pipes" => Some(Self::Pipes),
            _ => None,
        }
    }

    /// How many descriptors come with the request.
    pub fn fds(self) -> usize {
        match self {
            Self::Pty => 1,
            Self::Pipes => 3,
        }
    }
}

/// What the client asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub zone: String,
    pub mode: Mode,
    pub cwd: OsString,
    pub argv: Vec<OsString>,
    /// `KEY=value`, as the client has them.
    pub env: Vec<OsString>,
}

impl Request {
    /// `VZS1\0`, then zone, mode, cwd, argc, argv…, envc, env…, each ended by a
    /// NUL.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        let mut field = |bytes: &[u8]| {
            out.extend_from_slice(bytes);
            out.push(0);
        };
        field(self.zone.as_bytes());
        field(self.mode.word().as_bytes());
        field(self.cwd.as_bytes());
        field(self.argv.len().to_string().as_bytes());
        for arg in &self.argv {
            field(arg.as_bytes());
        }
        field(self.env.len().to_string().as_bytes());
        for item in &self.env {
            field(item.as_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let body = bytes
            .strip_prefix(MAGIC)
            .ok_or("not a request of vpn-zone-sys")?
            .strip_suffix(&[0])
            .ok_or("the request is cut short")?;
        let mut fields = body.split(|&b| b == 0);
        let mut next = || fields.next().ok_or("the request is cut short");

        let zone = std::str::from_utf8(next()?)
            .map_err(|_| "the zone's name is not UTF-8")?
            .to_owned();
        let mode = Mode::parse(next()?).ok_or("unknown mode")?;
        let cwd = OsString::from_vec(next()?.to_vec());
        let argv = list(&mut next)?;
        if argv.first().is_none_or(|a| a.is_empty()) {
            return Err("no command".to_owned());
        }
        let env = list(&mut next)?;
        if fields.next().is_some() {
            return Err("something follows the request".to_owned());
        }
        Ok(Self {
            zone,
            mode,
            cwd,
            argv,
            env,
        })
    }
}

/// A count, then that many fields.
fn list<'a>(
    next: &mut impl FnMut() -> Result<&'a [u8], &'static str>,
) -> Result<Vec<OsString>, String> {
    let count: usize = std::str::from_utf8(next()?)
        .ok()
        .and_then(|n| n.parse().ok())
        .filter(|&n| n <= MAX_ITEMS)
        .ok_or("a bad count in the request")?;
    (0..count)
        .map(|_| Ok(OsString::from_vec(next()?.to_vec())))
        .collect()
}

/// The service's answer.
pub fn answer_exit(code: u8) -> Vec<u8> {
    format!("EXIT {code}").into_bytes()
}

pub fn answer_refusal(why: &str) -> Vec<u8> {
    format!("ERR {why}").into_bytes()
}

pub fn parse_answer(bytes: &[u8]) -> Result<u8, String> {
    let text = String::from_utf8_lossy(bytes);
    if let Some(code) = text.strip_prefix("EXIT ") {
        return code
            .trim()
            .parse()
            .map_err(|_| format!("a strange answer: {text}"));
    }
    match text.strip_prefix("ERR ") {
        Some(why) => Err(why.to_owned()),
        None => Err(format!("a strange answer: {text}")),
    }
}

/// Adding a zone: `VZA1\0`, the zone, `tunnel` or `plain`, a NUL, then the
/// config's bytes (none for a plain zone).
const ADD_MAGIC: &[u8] = b"VZA1\0";
/// Bringing a zone up: `VZU1\0`, the zone, a NUL.
const UP_MAGIC: &[u8] = b"VZU1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddRequest {
    pub zone: String,
    pub plain: bool,
    pub config: Vec<u8>,
}

impl AddRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = ADD_MAGIC.to_vec();
        out.extend_from_slice(self.zone.as_bytes());
        out.push(0);
        out.extend_from_slice(if self.plain { b"plain" } else { b"tunnel" });
        out.push(0);
        out.extend_from_slice(&self.config);
        out
    }

    pub fn decode(body: &[u8]) -> Result<Self, String> {
        let mut parts = body.splitn(3, |&b| b == 0);
        let zone = std::str::from_utf8(parts.next().unwrap_or_default())
            .map_err(|_| "the zone's name is not UTF-8")?
            .to_owned();
        let plain = match parts.next() {
            Some(b"plain") => true,
            Some(b"tunnel") => false,
            _ => return Err("unknown kind of zone".to_owned()),
        };
        let config = parts.next().ok_or("the request is cut short")?.to_vec();
        check_name(&zone)?;
        Ok(Self {
            zone,
            plain,
            config,
        })
    }
}

pub fn encode_up(zone: &str) -> Vec<u8> {
    let mut out = UP_MAGIC.to_vec();
    out.extend_from_slice(zone.as_bytes());
    out.push(0);
    out
}

pub fn decode_up(body: &[u8]) -> Result<String, String> {
    let zone = body.strip_suffix(&[0]).ok_or("the request is cut short")?;
    let zone = std::str::from_utf8(zone)
        .map_err(|_| "the zone's name is not UTF-8")?
        .to_owned();
    check_name(&zone)?;
    Ok(zone)
}

/// What adding or bringing up a zone came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Done {
    /// Done, in words.
    Ok(String),
    /// This VPN is already that zone: one config, one tunnel — use it.
    Same(String),
}

pub fn answer_done(done: &Done) -> Vec<u8> {
    match done {
        Done::Ok(what) => format!("OK {what}").into_bytes(),
        Done::Same(zone) => format!("SAME {zone}").into_bytes(),
    }
}

pub fn parse_done(bytes: &[u8]) -> Result<Done, String> {
    let text = String::from_utf8_lossy(bytes);
    if let Some(what) = text.strip_prefix("OK ") {
        return Ok(Done::Ok(what.to_owned()));
    }
    if let Some(zone) = text.strip_prefix("SAME ") {
        return Ok(Done::Same(zone.trim().to_owned()));
    }
    match text.strip_prefix("ERR ") {
        Some(why) => Err(why.to_owned()),
        None => Err(format!("a strange answer: {text}")),
    }
}

/// Who may run programs in a zone: the module's list for a declared zone, the
/// one who added it for a zone made on the spot.
pub fn allowed_users(zone: &str) -> Vec<String> {
    system::settings(zone).map(|s| s.users).unwrap_or_default()
}

pub fn parse_users(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|name| {
            name.bytes()
                .next()
                .is_some_and(|b| b.is_ascii_lowercase() || b == b'_')
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-.".contains(&b))
        })
        .map(str::to_owned)
        .collect()
}

/// Does the zone leave the host's system bus reachable?
fn system_bus_allowed(zone: &str) -> bool {
    system::settings(zone).is_some_and(|s| s.system_bus)
}

/// The user the command runs as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
    pub shell: PathBuf,
    pub groups: Vec<u32>,
}

/// The command's environment: the client's, minus what points at the session,
/// with the account's own `HOME`, `USER`, `LOGNAME` and `SHELL`.
pub fn child_env(
    requested: &[OsString],
    user: &User,
    zone: &str,
    runtime: Option<&Path>,
) -> Vec<(OsString, OsString)> {
    let mut forced: Vec<(OsString, OsString)> = vec![
        ("HOME".into(), user.home.clone().into_os_string()),
        ("USER".into(), user.name.clone().into()),
        ("LOGNAME".into(), user.name.clone().into()),
        ("SHELL".into(), user.shell.clone().into_os_string()),
        ("VPN_ZONE_CURRENT".into(), format!("sys:{zone}").into()),
    ];
    if let Some(dir) = runtime {
        forced.push(("XDG_RUNTIME_DIR".into(), dir.as_os_str().to_owned()));
    }
    let mut out: Vec<(OsString, OsString)> = Vec::new();
    for item in requested {
        let bytes = item.as_bytes();
        let Some(eq) = bytes.iter().position(|&b| b == b'=') else {
            continue;
        };
        let (key, value) = (&bytes[..eq], &bytes[eq + 1..]);
        let taken = DROPPED_ENV.contains(&key)
            || forced.iter().any(|(k, _)| k.as_bytes() == key)
            || out.iter().any(|(k, _)| k.as_bytes() == key);
        if key.is_empty() || taken {
            continue;
        }
        out.push((
            OsString::from_vec(key.to_vec()),
            OsString::from_vec(value.to_vec()),
        ));
    }
    out.extend(forced);
    out
}

/// `vpn-zone-sys <zone> [--] <command> [args…]`.
pub fn parse_client_args(args: &[OsString]) -> Result<(String, Vec<OsString>), String> {
    let mut rest = args.iter();
    let zone = rest
        .next()
        .ok_or("need a zone")?
        .to_str()
        .ok_or("the zone's name is not UTF-8")?
        .to_owned();
    check_name(&zone)?;
    let mut cmd: Vec<OsString> = rest.cloned().collect();
    if cmd.first().is_some_and(|first| first == "--") {
        cmd.remove(0);
    }
    if cmd.is_empty() {
        return Err("need a command".to_owned());
    }
    Ok((zone, cmd))
}

// --- THE CLIENT --------------------------------------------------------------

const USAGE: &str = "usage: vpn-zone-sys <zone> [--] <command> [args…]
       vpn-zone-sys --add <zone> <config.conf | ->
       vpn-zone-sys --add <zone> --plain
       vpn-zone-sys --up <zone>";

/// The client. Returns the command's exit code.
pub fn client(args: &[OsString]) -> u8 {
    match args.first().and_then(|a| a.to_str()) {
        Some("--add") => return manage(add_request(&args[1..])),
        Some("--up") => return manage(up_request(&args[1..])),
        _ => {}
    }
    let (zone, cmd) = match parse_client_args(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("vpn-zone-sys: {e}\n{USAGE}");
            return 2;
        }
    };
    match run_client(&zone, cmd) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("vpn-zone-sys: {e}");
            1
        }
    }
}

/// `--add <zone> <file | - | --plain>`.
fn add_request(args: &[OsString]) -> Result<Vec<u8>, String> {
    let zone = args
        .first()
        .and_then(|a| a.to_str())
        .ok_or("need a zone")?
        .to_owned();
    check_name(&zone)?;
    let source = args.get(1).ok_or("need a config file, `-` or --plain")?;
    if args.len() > 2 {
        return Err("too many arguments".to_owned());
    }
    let (plain, config) = if source == "--plain" {
        (true, Vec::new())
    } else if source == "-" {
        let mut bytes = Vec::new();
        io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|e| format!("cannot read the config: {e}"))?;
        (false, bytes)
    } else {
        let bytes = fs::read(source)
            .map_err(|e| format!("cannot read {}: {e}", source.to_string_lossy()))?;
        (false, bytes)
    };
    let request = AddRequest {
        zone,
        plain,
        config,
    }
    .encode();
    if request.len() > MAX_REQUEST {
        return Err("the config is too large".to_owned());
    }
    Ok(request)
}

fn up_request(args: &[OsString]) -> Result<Vec<u8>, String> {
    match args {
        [zone] => {
            let zone = zone.to_str().ok_or("the zone's name is not UTF-8")?;
            check_name(zone)?;
            Ok(encode_up(zone))
        }
        _ => Err("need exactly one zone".to_owned()),
    }
}

/// Send an add or up request and say what came of it.
fn manage(request: Result<Vec<u8>, String>) -> u8 {
    let request = match request {
        Ok(r) => r,
        Err(e) => {
            eprintln!("vpn-zone-sys: {e}\n{USAGE}");
            return 2;
        }
    };
    match exchange(&request) {
        Ok(Done::Ok(what)) => {
            println!("{what}");
            0
        }
        Ok(Done::Same(zone)) => {
            println!(
                "Этот VPN уже есть: системная зона {zone}. Второе подключение не нужно — \
                 программы запускаются в ней: vpn-zone-sys {zone} -- <команда>"
            );
            0
        }
        Err(e) => {
            eprintln!("vpn-zone-sys: {e}");
            1
        }
    }
}

/// Bring a system zone up through the service, as its user: what the TTY
/// console does when the zone is down.
pub fn request_up(zone: &str) -> Result<Done, String> {
    exchange(&encode_up(zone))
}

fn exchange(request: &[u8]) -> Result<Done, String> {
    let sock = connect(SOCKET).map_err(|e| {
        format!(
            "cannot reach {SOCKET}: {e} — is the system tier on, and are you in the group \
             vpn-zones?"
        )
    })?;
    send_with_fds(sock.as_raw_fd(), request, &[])
        .map_err(|e| format!("cannot send the request: {e}"))?;
    let mut buf = [0u8; 4096];
    // SAFETY: a valid descriptor and a buffer of the length given.
    let n = unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
    if n <= 0 {
        return Err("the system-zone service went away without an answer".to_owned());
    }
    parse_done(&buf[..n.unsigned_abs()])
}

fn run_client(zone: &str, argv: Vec<OsString>) -> Result<u8, String> {
    let sock = connect(SOCKET).map_err(|e| {
        format!(
            "cannot reach {SOCKET}: {e} — is the system tier on, and are you in the group \
             vpn-zones?"
        )
    })?;
    let cwd = std::env::current_dir()
        .map(PathBuf::into_os_string)
        .unwrap_or_else(|_| OsString::from("/"));
    let env = std::env::vars_os()
        .map(|(key, value)| {
            let mut item = key;
            item.push("=");
            item.push(value);
            item
        })
        .collect();
    // SAFETY: isatty takes a descriptor number and nothing else.
    let tty = unsafe { libc::isatty(0) == 1 && libc::isatty(1) == 1 };
    let mode = if tty { Mode::Pty } else { Mode::Pipes };
    let request = Request {
        zone: zone.to_owned(),
        mode,
        cwd,
        argv,
        env,
    }
    .encode();
    if request.len() > MAX_REQUEST {
        return Err("the command and its environment are too large".to_owned());
    }
    match mode {
        Mode::Pipes => {
            send_with_fds(sock.as_raw_fd(), &request, &[0, 1, 2])
                .map_err(|e| format!("cannot send the request: {e}"))?;
            wait_answer(sock.as_raw_fd())
        }
        Mode::Pty => pty_session(&sock, &request),
    }
}

/// Relay the terminal to a pty whose slave the command gets.
fn pty_session(sock: &OwnedFd, request: &[u8]) -> Result<u8, String> {
    let (master, slave) = openpty().map_err(|e| format!("cannot make a terminal: {e}"))?;
    let size = window_size(0);
    if let Some(size) = size {
        set_window_size(master.as_raw_fd(), size);
    }
    send_with_fds(sock.as_raw_fd(), request, &[slave.as_raw_fd()])
        .map_err(|e| format!("cannot send the request: {e}"))?;
    drop(slave);

    let raw = RawMode::enable(0);
    let to_master = master
        .try_clone()
        .map_err(|e| format!("cannot relay: {e}"))?;
    let from_master = master
        .try_clone()
        .map_err(|e| format!("cannot relay: {e}"))?;
    thread::spawn(move || {
        let _ = copy(&mut io::stdin().lock(), &mut File::from(to_master));
    });
    let (done_w, done_r) = mpsc::channel();
    thread::spawn(move || {
        let _ = copy(&mut File::from(from_master), &mut io::stdout());
        let _ = done_w.send(());
    });
    let stop = Arc::new(AtomicBool::new(false));
    let watching = Arc::clone(&stop);
    let master_fd = master.as_raw_fd();
    thread::spawn(move || {
        let mut last = size;
        while !watching.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(200));
            let now = window_size(0);
            if now != last {
                if let Some(now) = now {
                    set_window_size(master_fd, now);
                }
                last = now;
            }
        }
    });

    let answer = wait_answer(sock.as_raw_fd());
    // The command's last output is still on its way through the pty: the master
    // reads until every slave is closed, which is when the unit is gone.
    let _ = done_r.recv_timeout(Duration::from_secs(2));
    stop.store(true, Ordering::Relaxed);
    drop(raw);
    drop(master);
    answer
}

fn copy(from: &mut impl Read, to: &mut impl Write) -> io::Result<()> {
    let mut buf = [0u8; 4096];
    loop {
        let n = from.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        to.write_all(&buf[..n])?;
        to.flush()?;
    }
}

fn wait_answer(sock: RawFd) -> Result<u8, String> {
    let mut buf = [0u8; 4096];
    // SAFETY: a valid descriptor and a buffer of the length given.
    let n = unsafe { libc::recv(sock, buf.as_mut_ptr().cast(), buf.len(), 0) };
    if n <= 0 {
        return Err("the system-zone service went away without an answer".to_owned());
    }
    parse_answer(&buf[..n.unsigned_abs()])
}

/// The client's terminal in raw mode while the relay runs; restored on drop.
struct RawMode {
    fd: RawFd,
    saved: libc::termios,
}

impl RawMode {
    fn enable(fd: RawFd) -> Option<Self> {
        // SAFETY: termios is plain data; tcgetattr fills it or fails.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: a descriptor and a termios to fill.
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            return None;
        }
        let mut raw = saved;
        // SAFETY: cfmakeraw only edits the struct it is given.
        unsafe { libc::cfmakeraw(&mut raw) };
        // SAFETY: a descriptor and a filled termios.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return None;
        }
        Some(Self { fd, saved })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // SAFETY: the same descriptor and the termios read from it.
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved) };
    }
}

fn window_size(fd: RawFd) -> Option<(u16, u16)> {
    // SAFETY: winsize is plain data; the ioctl fills it or fails.
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: TIOCGWINSZ writes one winsize.
    let rc = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut size) };
    (rc == 0).then_some((size.ws_row, size.ws_col))
}

fn set_window_size(fd: RawFd, (rows, cols): (u16, u16)) {
    let size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCSWINSZ reads one winsize.
    unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &size) };
}

fn openpty() -> io::Result<(OwnedFd, OwnedFd)> {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: two out-parameters; no name, no termios, no window size.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openpty succeeded, so both are fresh descriptors of ours.
    Ok(unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) })
}

// --- THE SERVICE -------------------------------------------------------------

/// The service: one connection on descriptor 0 (`Accept=yes`), one launch.
pub fn broker() -> u8 {
    let sock: RawFd = 0;
    let answer = match serve_any(sock) {
        Ok(answer) => answer,
        Err(e) => {
            eprintln!("sysrun: refused: {e}");
            answer_refusal(&e)
        }
    };
    // SAFETY: a valid descriptor and a buffer of the length given.
    unsafe {
        libc::send(
            sock,
            answer.as_ptr().cast(),
            answer.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    0
}

/// Everything the child needs, prepared by the parent: after `fork` the child
/// only does syscalls and one `exec`.
struct Launch {
    request: Request,
    fds: Vec<OwnedFd>,
    netns: File,
    user: User,
    runtime: Option<PathBuf>,
    env: Vec<(OsString, OsString)>,
    system_bus: bool,
}

/// Who asks, from the kernel; then what they ask for.
fn serve_any(sock: RawFd) -> Result<Vec<u8>, String> {
    let uid = peer_uid(sock)?;
    let (data, fds) =
        recv_with_fds(sock, MAX_REQUEST, 3).map_err(|e| format!("cannot read the request: {e}"))?;
    if let Some(body) = data.strip_prefix(ADD_MAGIC) {
        return serve_add(uid, &AddRequest::decode(body)?).map(|d| answer_done(&d));
    }
    if let Some(body) = data.strip_prefix(UP_MAGIC) {
        return serve_up(uid, &decode_up(body)?).map(|d| answer_done(&d));
    }
    serve(sock, uid, &data, fds).map(answer_exit)
}

fn systemctl(args: &[&str]) -> Result<(), String> {
    let tool = std::env::var_os("VPN_ZONE_SYSTEMCTL").unwrap_or_else(|| "systemctl".into());
    let status = Command::new(&tool)
        .args(args)
        .status()
        .map_err(|e| format!("cannot run systemctl: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("systemctl {} failed ({status})", args.join(" ")))
    }
}

fn private_key(cfg: &crate::config::WgConfig) -> Option<String> {
    cfg.interface()?.get("PrivateKey").map(str::to_owned)
}

/// Add a VPN as a system zone — or say which zone it already is. One config
/// is one tunnel: the same private key in two tunnels makes the server see
/// two devices with one key, and they knock each other off.
fn serve_add(uid: u32, request: &AddRequest) -> Result<Done, String> {
    let zone = request.zone.as_str();
    if uid == 0 {
        return Err("root adds a zone by declaring it".to_owned());
    }
    let user = user_of(uid)?;
    let existing = system::settings(zone);
    if let Some(s) = &existing {
        if !s.users.contains(&user.name) {
            return Err(format!(
                "the system zone {zone} exists and is not {}'s",
                user.name
            ));
        }
        if s.declared && s.plain != request.plain {
            return Err(format!(
                "{zone} is declared in Nix as {}",
                if s.plain { "plain" } else { "a tunnel" }
            ));
        }
        if s.declared && !s.plain && s.config != system::local_dir(zone).join("config.conf") {
            return Err(format!(
                "the config of {zone} comes from Nix ({})",
                s.config.display()
            ));
        }
    }
    if !request.plain {
        let cfg = crate::config::WgConfig::parse(&request.config)
            .map_err(|e| format!("the config: {e}"))?;
        if let Some(why) = system::refusal(&cfg) {
            return Err(why.to_owned());
        }
        let key = private_key(&cfg).ok_or("the config has no PrivateKey")?;
        for other in system::all_zones() {
            let Some(s) = system::settings(&other).filter(|s| !s.plain && other != zone) else {
                continue;
            };
            let held = fs::read(&s.config)
                .ok()
                .and_then(|raw| crate::config::WgConfig::parse(&raw).ok())
                .and_then(|o| private_key(&o));
            if held.as_deref() == Some(key.as_str()) {
                if s.users.contains(&user.name) {
                    return Ok(Done::Same(other));
                }
                return Err(format!(
                    "this VPN is already the system zone {other}, which is not {}'s",
                    user.name
                ));
            }
        }
    }

    let local = system::local_dir(zone);
    fs::create_dir_all(&local).map_err(|e| format!("cannot create {}: {e}", local.display()))?;
    if !request.plain {
        crate::zone::write_private(&local.join("config.conf"), &request.config)
            .map_err(|e| format!("cannot write the config: {e}"))?;
    }
    if !existing.as_ref().is_some_and(|s| s.declared) {
        let kind = if request.plain { "plain\n" } else { "tunnel\n" };
        fs::write(local.join("kind"), kind).map_err(|e| format!("cannot write: {e}"))?;
        fs::write(local.join("users"), format!("{}\n", user.name))
            .map_err(|e| format!("cannot write: {e}"))?;
    }
    println!("sysrun: {} added the system zone {zone}", user.name);
    systemctl(&["restart", &format!("vpn-zone-system@{zone}.service")])
        .map_err(|e| format!("{zone} is added, but did not come up: {e}"))?;
    Ok(Done::Ok(format!("зона {zone} добавлена и поднята")))
}

/// Bring a zone up for one of its users.
fn serve_up(uid: u32, zone: &str) -> Result<Done, String> {
    let settings =
        system::settings(zone).ok_or_else(|| format!("there is no system zone {zone}"))?;
    let user = user_of(uid)?;
    if uid != 0 && !settings.users.contains(&user.name) {
        return Err(format!("{} may not use the system zone {zone}", user.name));
    }
    systemctl(&["start", &format!("vpn-zone-system@{zone}.service")])
        .map_err(|e| format!("{zone} did not come up: {e}"))?;
    Ok(Done::Ok(format!("зона {zone} поднята")))
}

fn serve(sock: RawFd, uid: u32, data: &[u8], fds: Vec<OwnedFd>) -> Result<u8, String> {
    let request = Request::decode(data)?;
    let zone = request.zone.clone();
    check_name(&zone)?;
    if system::settings(&zone).is_none() {
        return Err(format!("there is no system zone {zone}"));
    }
    if uid == 0 {
        // Root is root in the zone's namespace, and could route around the
        // tunnel; root has `ip netns exec` anyway.
        return Err("root does not go through here — `ip netns exec` is root's".to_owned());
    }
    let user = user_of(uid)?;
    if !allowed_users(&zone).contains(&user.name) {
        return Err(format!(
            "{} may not run programs in the system zone {zone}",
            user.name
        ));
    }
    if fds.len() != request.mode.fds() {
        return Err("the descriptors do not match the mode".to_owned());
    }
    let netns = File::open(system::netns_path(&zone))
        .map_err(|e| format!("the system zone {zone} is not up ({e})"))?;
    let runtime = Path::new("/run/user").join(uid.to_string());
    let runtime = runtime.is_dir().then_some(runtime);
    let env = child_env(&request.env, &user, &zone, runtime.as_deref());
    println!(
        "sysrun: {} runs {} in the system zone {zone}",
        user.name,
        request.argv[0].to_string_lossy()
    );
    let launch = Launch {
        system_bus: system_bus_allowed(&zone),
        request,
        fds,
        netns,
        user,
        runtime,
        env,
    };

    // SAFETY: the service is single-threaded here, so the child may allocate.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork: {}", io::Error::last_os_error()));
    }
    if pid == 0 {
        let why = become_the_command(&launch);
        eprintln!("vpn-zone-sys: {why}");
        // SAFETY: the child ends here, without running the parent's cleanup.
        unsafe { libc::_exit(127) };
    }
    drop(launch);

    // The client gone means nobody wants the command any more.
    thread::spawn(move || {
        let mut byte = [0u8; 1];
        // SAFETY: a valid descriptor and a buffer of the length given.
        let n = unsafe { libc::recv(sock, byte.as_mut_ptr().cast(), 1, 0) };
        if n <= 0 {
            // SAFETY: the child's process group — it made itself a session.
            unsafe {
                libc::kill(-pid, libc::SIGHUP);
                libc::kill(-pid, libc::SIGTERM);
            }
        }
    });
    let mut status = 0;
    loop {
        // SAFETY: our own child and an out-parameter.
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            return Ok(crate::profile::exit_code_of(status));
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(format!("waitpid: {err}"));
        }
    }
}

/// In the child: the caller's terminal, the zone, the mounts, the user, exec.
/// Returns only why it failed.
fn become_the_command(launch: &Launch) -> String {
    // SAFETY: setsid takes no arguments; a new session so the pty can become
    // the controlling terminal.
    unsafe { libc::setsid() };
    match launch.request.mode {
        Mode::Pty => {
            let tty = launch.fds[0].as_raw_fd();
            // SAFETY: a fresh pty slave, controlling no other session.
            if unsafe { libc::ioctl(tty, libc::TIOCSCTTY, 0) } != 0 {
                return format!("cannot take the terminal: {}", io::Error::last_os_error());
            }
            for target in 0..3 {
                // SAFETY: two valid descriptor numbers.
                unsafe { libc::dup2(tty, target) };
            }
        }
        Mode::Pipes => {
            for (target, fd) in (0..3).zip(&launch.fds) {
                // SAFETY: two valid descriptor numbers.
                unsafe { libc::dup2(fd.as_raw_fd(), target) };
            }
        }
    }

    // SAFETY: a descriptor of /run/netns/vz-<zone>.
    if unsafe { libc::setns(launch.netns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
        return format!("cannot enter the zone: {}", io::Error::last_os_error());
    }
    if let Err(e) = seal_mounts(launch) {
        return e;
    }
    if let Err(e) = drop_to(&launch.user) {
        return e;
    }
    if std::env::set_current_dir(&launch.request.cwd).is_err()
        && std::env::set_current_dir(&launch.user.home).is_err()
    {
        let _ = std::env::set_current_dir("/");
    }
    // SAFETY: the child is single-threaded; nothing else reads the environment.
    unsafe { libc::clearenv() };
    for (key, value) in &launch.env {
        std::env::set_var(key, value);
    }
    let e = crate::profile::exec_command(&launch.request.argv);
    format!(
        "cannot run {}: {e}",
        launch.request.argv[0].to_string_lossy()
    )
}

/// A mount namespace of the command's own: what a service in the zone gets
/// from its unit, done by hand.
fn seal_mounts(launch: &Launch) -> Result<(), String> {
    // SAFETY: unshare takes flags only.
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        return Err(format!(
            "cannot make a mount namespace: {}",
            io::Error::last_os_error()
        ));
    }
    sys::mount(
        OsStr::new("none"),
        Path::new("/"),
        "",
        libc::MS_REC | libc::MS_PRIVATE,
        "",
    )
    .map_err(|e| format!("cannot make the mount tree private: {e}"))?;

    // The host's resolvers first: on NixOS /etc/resolv.conf is a chain of links
    // ending INSIDE one of them (see zone.rs, where it bit first).
    for group in zone::RESOLVER_DIRS {
        zone::hide_first(group)?;
    }
    let zone = launch.request.zone.as_str();
    bind_over(
        &system::resolv_path(zone),
        Path::new("/etc/resolv.conf"),
        true,
    )?;
    let nsswitch = system::nsswitch_path(zone);
    if nsswitch.exists() {
        bind_over(&nsswitch, Path::new("/etc/nsswitch.conf"), false)?;
    }
    if !launch.system_bus && Path::new("/run/dbus").is_dir() {
        sys::mount(
            OsStr::new("tmpfs"),
            Path::new("/run/dbus"),
            "tmpfs",
            0,
            "mode=0755,size=64k",
        )
        .map_err(|e| format!("cannot hide the system bus: {e}"))?;
    }
    if let Some(dir) = &launch.runtime {
        let options = format!(
            "mode=0700,uid={},gid={},size=16m",
            launch.user.uid, launch.user.gid
        );
        sys::mount(OsStr::new("tmpfs"), dir, "tmpfs", 0, &options)
            .map_err(|e| format!("cannot hide the session's sockets: {e}"))?;
    }
    Ok(())
}

/// Bind `source` over wherever `link`'s chain of symlinks ends, creating the
/// end when it is missing and `create` says so.
fn bind_over(source: &Path, link: &Path, create: bool) -> Result<(), String> {
    let target = sys::link_target(link);
    if !target.exists() {
        if !create {
            return Ok(());
        }
        if let Some(dir) = target.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }
        File::create(&target).map_err(|e| format!("cannot create {}: {e}", target.display()))?;
    }
    sys::mount(source.as_os_str(), &target, "", libc::MS_BIND, "").map_err(|e| {
        format!(
            "cannot bind {} over {}: {e}",
            source.display(),
            target.display()
        )
    })
}

/// The user's groups, gid and uid, and no way back.
fn drop_to(user: &User) -> Result<(), String> {
    let fail = |what: &str| format!("cannot {what}: {}", io::Error::last_os_error());
    // SAFETY: a list of gids and its length.
    if unsafe { libc::setgroups(user.groups.len(), user.groups.as_ptr()) } != 0 {
        return Err(fail("set the groups"));
    }
    // SAFETY: plain ids.
    if unsafe { libc::setgid(user.gid) } != 0 {
        return Err(fail("set the gid"));
    }
    // SAFETY: plain ids.
    if unsafe { libc::setuid(user.uid) } != 0 {
        return Err(fail("set the uid"));
    }
    // SAFETY: no arguments.
    let still_root = unsafe { libc::getuid() != user.uid || libc::geteuid() != user.uid };
    if still_root {
        return Err("the uid did not change".to_owned());
    }
    // SAFETY: a documented prctl with constant arguments.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(fail("set no_new_privs"));
    }
    Ok(())
}

/// The account behind a uid, with its groups.
fn user_of(uid: u32) -> Result<User, String> {
    // SAFETY: passwd is plain data; getpwuid_r fills it or leaves `found` null.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf: Vec<libc::c_char> = vec![0; 16 * 1024];
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is to a local that outlives the call.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut found) };
    if rc != 0 || found.is_null() {
        return Err(format!("uid {uid} has no account"));
    }
    // SAFETY: getpwuid_r succeeded, so these point into `buf`.
    let (name, home, shell) = unsafe {
        (
            CStr::from_ptr(pwd.pw_name).to_owned(),
            CStr::from_ptr(pwd.pw_dir).to_owned(),
            CStr::from_ptr(pwd.pw_shell).to_owned(),
        )
    };
    let groups = groups_of(&name, pwd.pw_gid)?;
    Ok(User {
        name: name
            .into_string()
            .map_err(|_| format!("the name of uid {uid} is not UTF-8"))?,
        uid,
        gid: pwd.pw_gid,
        home: PathBuf::from(OsString::from_vec(home.into_bytes())),
        shell: PathBuf::from(OsString::from_vec(shell.into_bytes())),
        groups,
    })
}

fn groups_of(name: &CString, gid: u32) -> Result<Vec<u32>, String> {
    let mut size: libc::c_int = 64;
    loop {
        let mut list: Vec<libc::gid_t> = vec![0; usize::try_from(size).unwrap_or(64)];
        let mut count = size;
        // SAFETY: a name, a buffer and its length in `count`.
        let rc = unsafe { libc::getgrouplist(name.as_ptr(), gid, list.as_mut_ptr(), &mut count) };
        if rc >= 0 {
            list.truncate(usize::try_from(count).unwrap_or(0));
            return Ok(list);
        }
        if count <= size || count > 65_536 {
            return Err("cannot list the user's groups".to_owned());
        }
        size = count;
    }
}

// --- SOCKETS -------------------------------------------------------------------

/// Who is on the other end, by the kernel's word.
fn peer_uid(sock: RawFd) -> Result<u32, String> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: a valid descriptor, a correctly sized buffer and its length.
    let rc = unsafe {
        libc::getsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 || cred.pid <= 0 {
        return Err("cannot tell who is asking".to_owned());
    }
    Ok(cred.uid)
}

fn connect(path: &str) -> io::Result<OwnedFd> {
    // SAFETY: plain constants.
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh descriptor of ours.
    let sock = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: sockaddr_un is plain data.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_bytes();
    if bytes.len() >= addr.sun_path.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "path too long"));
    }
    for (slot, byte) in addr.sun_path.iter_mut().zip(bytes) {
        *slot = *byte as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    // SAFETY: a valid descriptor and an address of the length given.
    let rc = unsafe {
        libc::connect(
            sock.as_raw_fd(),
            (&addr as *const libc::sockaddr_un).cast(),
            len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sock)
}

/// Room for `count` descriptors in a control message, in u64s so that the
/// buffer is aligned the way `cmsghdr` wants.
fn control_buffer(count: usize) -> (Vec<u64>, usize) {
    let payload = (count * std::mem::size_of::<libc::c_int>()) as libc::c_uint;
    // SAFETY: CMSG_SPACE is arithmetic.
    let space = unsafe { libc::CMSG_SPACE(payload) } as usize;
    (vec![0u64; space.div_ceil(8)], space)
}

fn send_with_fds(sock: RawFd, data: &[u8], fds: &[RawFd]) -> io::Result<()> {
    let mut iov = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    let (mut control, space) = control_buffer(fds.len());
    // SAFETY: msghdr is plain data; every pointer set below outlives sendmsg.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if !fds.is_empty() {
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        let payload = std::mem::size_of_val(fds) as libc::c_uint;
        // SAFETY: the control buffer has room for one header and `fds`, and is
        // aligned for cmsghdr.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(payload) as _;
            let data = libc::CMSG_DATA(cmsg).cast::<libc::c_int>();
            for (i, fd) in fds.iter().enumerate() {
                data.add(i).write_unaligned(*fd);
            }
        }
    }
    // SAFETY: a valid descriptor and a filled msghdr.
    let sent = unsafe { libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if sent.unsigned_abs() != data.len() {
        return Err(io::Error::other("the request was cut short"));
    }
    Ok(())
}

fn recv_with_fds(sock: RawFd, max: usize, max_fds: usize) -> io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    let mut data = vec![0u8; max];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    let (mut control, space) = control_buffer(max_fds);
    // SAFETY: msghdr is plain data; every pointer set below outlives recvmsg.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    // SAFETY: a valid descriptor and a prepared msghdr.
    let n = unsafe { libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut fds = Vec::new();
    // SAFETY: walking the control messages the kernel wrote into our buffer;
    // every descriptor found is ours from here on.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let payload = (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let base = libc::CMSG_DATA(cmsg).cast::<libc::c_int>();
                for i in 0..payload / std::mem::size_of::<libc::c_int>() {
                    fds.push(OwnedFd::from_raw_fd(base.add(i).read_unaligned()));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(io::Error::other("the request is too large"));
    }
    data.truncate(n.unsigned_abs());
    Ok((data, fds))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }

    fn request() -> Request {
        Request {
            zone: "nl".to_owned(),
            mode: Mode::Pty,
            cwd: OsString::from("/home/alice/проект"),
            argv: os(&["socat", "-", "TCP:10.99.0.1:8080"]),
            env: os(&["PATH=/run/current-system/sw/bin", "TERM=xterm-256color"]),
        }
    }

    #[test]
    fn a_request_survives_the_wire() {
        let r = request();
        assert_eq!(Request::decode(&r.encode()), Ok(r.clone()));
        let pipes = Request {
            mode: Mode::Pipes,
            env: Vec::new(),
            ..r
        };
        assert_eq!(Request::decode(&pipes.encode()), Ok(pipes));
    }

    #[test]
    fn a_broken_request_is_refused() {
        let good = request().encode();
        assert!(Request::decode(b"").is_err());
        assert!(Request::decode(&good[1..]).is_err(), "no magic");
        assert!(
            Request::decode(&good[..good.len() - 1]).is_err(),
            "no final NUL"
        );
        let mut extra = good.clone();
        extra.extend_from_slice(b"more\0");
        assert!(Request::decode(&extra).is_err(), "trailing field");

        let empty_cmd = Request {
            argv: os(&[""]),
            ..request()
        };
        assert!(Request::decode(&empty_cmd.encode()).is_err());
        let no_cmd = Request {
            argv: Vec::new(),
            ..request()
        };
        assert!(Request::decode(&no_cmd.encode()).is_err());

        // Built field by field: a NUL next to a digit would read as an octal
        // escape in a literal.
        let raw = |fields: &[&str]| {
            let mut out = MAGIC.to_vec();
            for field in fields {
                out.extend_from_slice(field.as_bytes());
                out.push(0);
            }
            out
        };
        let huge = raw(&["nl", "pty", "/", "999999"]);
        assert!(Request::decode(&huge).is_err(), "a count past the limit");
        let short = raw(&["nl", "pty", "/", "3", "a", "b"]);
        assert!(
            Request::decode(&short).is_err(),
            "fewer arguments than said"
        );
        let mode = raw(&["nl", "tty", "/", "1", "sh", "0"]);
        assert!(Request::decode(&mode).is_err(), "unknown mode");
        let fine = raw(&["nl", "pipes", "/", "1", "sh", "0"]);
        assert!(Request::decode(&fine).is_ok(), "the same, well-formed");
    }

    #[test]
    fn the_answer_carries_the_exit_code_or_the_reason() {
        assert_eq!(parse_answer(&answer_exit(7)), Ok(7));
        assert_eq!(parse_answer(&answer_exit(0)), Ok(0));
        assert_eq!(
            parse_answer(&answer_refusal("bob may not")),
            Err("bob may not".to_owned())
        );
        assert!(parse_answer(b"garbage").is_err());
        assert!(parse_answer(b"EXIT x").is_err());
    }

    #[test]
    fn the_environment_loses_the_session_and_gets_the_account() {
        let user = User {
            name: "alice".to_owned(),
            uid: 1000,
            gid: 100,
            home: PathBuf::from("/home/alice"),
            shell: PathBuf::from("/run/current-system/sw/bin/zsh"),
            groups: vec![100],
        };
        let env = child_env(
            &os(&[
                "PATH=/bin",
                "TERM=xterm",
                "HOME=/tmp/elsewhere",
                "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
                "WAYLAND_DISPLAY=wayland-1",
                "XDG_RUNTIME_DIR=/run/user/1000",
                "PATH=/second",
                "not a variable",
                "=value",
            ]),
            &user,
            "nl",
            Some(Path::new("/run/user/1000")),
        );
        let get = |k: &str| {
            env.iter()
                .filter(|(key, _)| key == k)
                .map(|(_, v)| v.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(get("PATH"), ["/bin"]);
        assert_eq!(get("TERM"), ["xterm"]);
        assert_eq!(get("HOME"), ["/home/alice"]);
        assert_eq!(get("USER"), ["alice"]);
        assert_eq!(get("SHELL"), ["/run/current-system/sw/bin/zsh"]);
        assert_eq!(get("VPN_ZONE_CURRENT"), ["sys:nl"]);
        assert_eq!(get("XDG_RUNTIME_DIR"), ["/run/user/1000"]);
        assert!(get("DBUS_SESSION_BUS_ADDRESS").is_empty());
        assert!(get("WAYLAND_DISPLAY").is_empty());
        assert!(env.iter().all(|(k, _)| !k.is_empty()));

        let without_runtime = child_env(&os(&["XDG_RUNTIME_DIR=/x"]), &user, "nl", None);
        assert!(without_runtime.iter().all(|(k, _)| k != "XDG_RUNTIME_DIR"));
    }

    #[test]
    fn adding_a_zone_survives_the_wire() {
        let add = AddRequest {
            zone: "nl".to_owned(),
            plain: false,
            config: b"[Interface]\nPrivateKey = x\n".to_vec(),
        };
        let bytes = add.encode();
        assert_eq!(
            AddRequest::decode(bytes.strip_prefix(ADD_MAGIC).unwrap()),
            Ok(add)
        );
        let plain = AddRequest {
            zone: "direct2".to_owned(),
            plain: true,
            config: Vec::new(),
        };
        assert_eq!(
            AddRequest::decode(plain.encode().strip_prefix(ADD_MAGIC).unwrap()),
            Ok(plain)
        );
        assert!(AddRequest::decode(b"Bad_Zone\0tunnel\0").is_err());
        assert!(AddRequest::decode(b"nl\0vpn\0").is_err());
        assert!(AddRequest::decode(b"nl\0tunnel").is_err());

        assert_eq!(
            decode_up(encode_up("nl").strip_prefix(UP_MAGIC).unwrap()),
            Ok("nl".to_owned())
        );
        assert!(decode_up(b"nl").is_err());

        assert_eq!(
            parse_done(&answer_done(&Done::Same("nl".to_owned()))),
            Ok(Done::Same("nl".to_owned()))
        );
        assert_eq!(
            parse_done(&answer_done(&Done::Ok("зона nl поднята".to_owned()))),
            Ok(Done::Ok("зона nl поднята".to_owned()))
        );
        assert_eq!(parse_done(&answer_refusal("no")), Err("no".to_owned()));
    }

    #[test]
    fn the_users_of_a_zone_are_names_and_nothing_else() {
        assert_eq!(
            parse_users("alice\n\n bob \nroot\nBad\n../x\n_svc\nw.x-y\n"),
            ["alice", "bob", "root", "_svc", "w.x-y"]
        );
    }

    #[test]
    fn the_command_line_of_the_client() {
        assert_eq!(
            parse_client_args(&os(&["nl", "--", "bash", "-l"])),
            Ok(("nl".to_owned(), os(&["bash", "-l"])))
        );
        assert_eq!(
            parse_client_args(&os(&["nl", "curl", "--", "x"])),
            Ok(("nl".to_owned(), os(&["curl", "--", "x"])))
        );
        assert!(parse_client_args(&os(&[])).is_err());
        assert!(parse_client_args(&os(&["nl"])).is_err());
        assert!(parse_client_args(&os(&["nl", "--"])).is_err());
        assert!(parse_client_args(&os(&["Bad_Zone", "sh"])).is_err());
    }

    #[test]
    fn descriptors_travel_with_a_request() {
        let mut pair = [0; 2];
        // SAFETY: an out-parameter for two descriptors.
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                pair.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0);
        // SAFETY: both are fresh descriptors of ours.
        let (a, b) = unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) };
        let (r, w) = sys::pipe().unwrap();
        send_with_fds(a.as_raw_fd(), b"hello", &[w.as_raw_fd()]).unwrap();
        drop(w);
        let (data, fds) = recv_with_fds(b.as_raw_fd(), 64, 3).unwrap();
        assert_eq!(data, b"hello");
        assert_eq!(fds.len(), 1);
        File::from(fds.into_iter().next().unwrap())
            .write_all(b"through")
            .unwrap();
        let mut got = String::new();
        File::from(r).read_to_string(&mut got).unwrap();
        assert_eq!(got, "through");
    }
}
