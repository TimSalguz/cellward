//! The frame relay between a container instance and its zone (the container
//! design of 2026-09-27: the container is the unit of isolation, a zone is
//! only transport).
//!
//! A container instance gets a network namespace of its own, and its only way
//! out is a `passt` its zone starts in the zone's app namespace. The two
//! namespaces belong to sibling user namespaces, so neither side can enter the
//! other's: `passt --fd` is handed one end of a stream socket and no handle on
//! any namespace, and this relay, inside the instance, stands between that
//! stream and the instance's tap device, `awg0`. Nothing else joins the two.
//!
//! **The wire is qemu's stream framing**, what `passt --fd` speaks: every
//! Ethernet frame after its length, four bytes big-endian. passt takes no
//! frame shorter than an Ethernet header or longer than `L2_MAX_LEN_PASST`
//! (65535) and resets the connection over one (`tap.c`, `tap_handler_passt`);
//! the relay holds both directions to the same bounds ([`MIN_FRAME`],
//! [`MAX_FRAME`]) and ends at the first frame outside them, whichever side
//! sent it. **Any error ends the pump**, and the relay's end is the tap's:
//! the device is not persistent, it goes with its last descriptor, and the
//! instance is left with `lo` and nothing to leave by — fail-closed.
//!
//! **Back-pressure, never a drop.** Each direction reads only while what it
//! read can be written: a stream that takes no more stops the reading of the
//! tap, a tap that takes no more stops the reading of the stream. Frames
//! wait in a bounded window ([`WINDOW`]), and the kernel's queues behind it
//! fill up and push back on the sender, as a wire would.
//!
//! `poll(2)` and not `epoll`: two descriptors, a set that changes with the
//! back-pressure on every turn, and the way the rest of the crate waits
//! (`bus_filter`, `focus`, `pw_context`).
//!
//! Stage 0 (2026-09-27): the codec, the pump and `vpn-zone-core frame-relay
//! --tap-fd N --stream-fd M` over descriptors it is handed. No launch uses it
//! yet; the VM probe (`tests/vm-probe-container-ns.py`) runs the whole path
//! — a tap in a namespace of its own, the relay, `passt --fd` in a real
//! zone — against the test's server.
//!
//! Stage 2 (2026-09-27): `vpn-zone-core frame-relay --attach …` ([`Attach`]),
//! what an instance's keeper starts for every attach (`bridge::attach`): in
//! the instance's user and network namespaces as their root, exec'd there —
//! its memory that user namespace's own, out of the reach of every zone and
//! every other instance (J3 of the design) —, not dumpable from its first
//! step. It makes the tap itself, **not persistent**, from `/dev/net/tun` of
//! the host's mount namespace (the instance's `/dev` has none), and is its
//! only owner: the device goes with the relay. Then its addresses and routes
//! (`ip`, as the namespace's root) and the instance's rules (`nft`: out by
//! the tap from this attach's own addresses, or not at all; a loud warning
//! when they cannot be loaded — the topology, loopback and one tap, is the
//! wall), and then it seals itself: every capability gone, no new
//! privileges, a seccomp allow-list of what the pump does
//! (`seccomp::Filter::relay`). Only then does it say it is ready (a byte on
//! a pipe its keeper waits on), and pump.
//!
//! Stage 4 (2026-09-27, the live switch — `crate::epoch`): three more
//! things, each as the instance's root in its namespaces, as the attach is.
//!
//! * `--attach … --wall-level L --wall-cgroup P`: the instance's rules
//!   carry the epoch's wall (`socket cgroupv2`), and are loaded before the
//!   tap is made — a relay whose walled rules do not load makes no tap and
//!   ends: no way out without the wall, once there is one. A tap already
//!   there (the old way out not gone) is refused.
//! * `--seal`: a switch's break, between the cut and the next attach, with
//!   the programs frozen — no tap may be there; every socket that may reach
//!   out destroyed (`sockdiag::break_all`, programs hear of it at once); the
//!   rules closed to loopback. The tally on stdout.
//! * `--probe`: what an instance's keeper asks at its start — does nft take
//!   `socket cgroupv2` here, does the kernel destroy sockets here; one line
//!   on stdout ([`crate::epoch::probe_verdict`]). Nothing of the
//!   namespace's is changed: the probe's table is made and deleted in one
//!   transaction.
//!
//! The network monitor (2026-09-28): every frame is counted into the
//! instance's `traffic` file (`--tally-fd`, `crate::traffic`), and noted in
//! its table of flows and names (`--flows-fd`, `crate::flows`) — both shared
//! mappings made before the seal, written with no system call after it
//! ([`Notes`]). A record, not the wall: a file it cannot map, and it relays
//! all the same.

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

/// The length before every frame: four bytes, big-endian.
pub const LEN_BYTES: usize = 4;
/// The shortest frame passt takes: an Ethernet header (`ETH_HLEN`).
pub const MIN_FRAME: usize = 14;
/// The longest: passt's `L2_MAX_LEN_PASST` (`USHRT_MAX`). A tap with the
/// instance's MTU, 65520, never hands over more than 65534.
pub const MAX_FRAME: usize = 65535;
/// How much each direction holds for the other side at most: four frames of
/// the largest size. Enough to keep both sides busy, and bounded, so that a
/// side that stops taking stops the other.
pub const WINDOW: usize = 4 * (LEN_BYTES + MAX_FRAME);

/// A frame whose length passt would refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Shorter than an Ethernet header — no length at all included.
    TooShort(usize),
    /// Longer than passt takes.
    TooLong(usize),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "a frame of {n} bytes, shorter than an Ethernet header"),
            Self::TooLong(n) => write!(f, "a frame of {n} bytes, longer than {MAX_FRAME}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<FrameError> for io::Error {
    fn from(e: FrameError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}

/// Is `len` the length of a frame passt takes?
pub fn check_len(len: usize) -> Result<(), FrameError> {
    if len < MIN_FRAME {
        Err(FrameError::TooShort(len))
    } else if len > MAX_FRAME {
        Err(FrameError::TooLong(len))
    } else {
        Ok(())
    }
}

/// Append `frame` to `out` as the stream carries it: its length, then itself.
/// Nothing is appended for a frame passt would refuse.
pub fn encode(frame: &[u8], out: &mut Vec<u8>) -> Result<(), FrameError> {
    check_len(frame.len())?;
    // Cannot truncate: checked against MAX_FRAME above.
    out.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    out.extend_from_slice(frame);
    Ok(())
}

/// The length of the frame at the front of `buf` once all of it is there:
/// `Ok(None)` while its length or its bytes are still to come. The length
/// is judged as soon as its four bytes are in — an impossible one ends the
/// stream before a byte of its frame is waited for.
pub fn decode(buf: &[u8]) -> Result<Option<usize>, FrameError> {
    let Some(head) = buf.get(..LEN_BYTES) else {
        return Ok(None);
    };
    let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
    check_len(len)?;
    Ok((buf.len() >= LEN_BYTES + len).then_some(len))
}

/// Why [`pump`] came back without an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// The stream ended: the zone's side is gone — its passt ended, the zone
    /// went down, the instance was cut. What was on its way to the tap is
    /// delivered first when the tap takes it at once.
    StreamClosed,
    /// The tap ended; what was read from it went out on the stream first.
    TapClosed,
}

/// Carry frames between `tap` (one frame per `read`/`write`: a tap device,
/// or a `SOCK_SEQPACKET` socket in the tests) and `stream` (qemu's framing
/// on a stream socket) until either ends or anything goes wrong.
///
/// Both descriptors are made non-blocking — their open file descriptions,
/// which the caller should not share with anyone who expects otherwise.
pub fn pump(tap: BorrowedFd<'_>, stream: BorrowedFd<'_>) -> io::Result<End> {
    pump_counted(tap, stream, &mut Notes::default())
}

/// What the relay notes of every frame, each when it has it: its count
/// (`crate::traffic`), its flow and a DNS answer's names (`crate::flows`).
#[derive(Default)]
pub struct Notes<'a> {
    pub tally: Option<&'a crate::traffic::Tally>,
    pub flows: Option<&'a mut crate::flows::Table>,
}

impl Notes<'_> {
    /// A whole frame: `outbound` read from the tap, else taken by it.
    fn frame(&mut self, frame: &[u8], outbound: bool) {
        if let Some(tally) = self.tally {
            if outbound {
                tally.outbound(frame.len());
            } else {
                tally.inbound(frame.len());
            }
        }
        if let Some(flows) = self.flows.as_deref_mut() {
            if let Some(seen) = crate::flows::frame(frame, outbound) {
                flows.note(&seen, crate::flows::now());
            }
        }
    }
}

/// [`pump`], every frame noted (`notes`): out, as it is read from the tap;
/// in, as the tap takes it.
pub fn pump_counted(
    tap: BorrowedFd<'_>,
    stream: BorrowedFd<'_>,
    notes: &mut Notes<'_>,
) -> io::Result<End> {
    let (tap, stream) = (tap.as_raw_fd(), stream.as_raw_fd());
    set_nonblocking(tap)?;
    set_nonblocking(stream)?;
    // Tap → stream: frames read from the tap, framed, waiting for the stream.
    let mut up: Vec<u8> = Vec::with_capacity(2 * WINDOW);
    let mut up_sent = 0;
    // One more than the largest frame: a read that fills it was one too long.
    let mut frame = vec![0u8; MAX_FRAME + 1];
    // Stream → tap: bytes read from the stream, frames taken off its front.
    let mut down = vec![0u8; WINDOW];
    let (mut start, mut end) = (0, 0);
    // A whole frame waits for the tap to take it.
    let mut tap_full = false;
    let mut tap_open = true;
    loop {
        if start > 0 {
            down.copy_within(start..end, 0);
            end -= start;
            start = 0;
        }
        let read_tap = tap_open && up.len() - up_sent < WINDOW;
        // Never full without a whole frame in it: a part of one is shorter
        // than the window.
        let read_stream = !tap_full && end < down.len();
        let mut fds = [
            libc::pollfd {
                // A negative descriptor is skipped: an ended tap would
                // report its hang-up on every turn.
                fd: if tap_open { tap } else { -1 },
                events: interest(read_tap, tap_full),
                revents: 0,
            },
            libc::pollfd {
                fd: stream,
                events: interest(read_stream, up_sent < up.len()),
                revents: 0,
            },
        ];
        // SAFETY: two valid pollfds for the duration of the call.
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        let (at_tap, at_stream) = (fds[0].revents, fds[1].revents);
        if (at_tap | at_stream) & libc::POLLNVAL != 0 {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        let gone = libc::POLLHUP | libc::POLLERR;
        // The stream first: its end is the usual one, and only a read tells
        // it from a write that failed.
        if at_stream & (libc::POLLIN | gone) != 0 {
            if !read_stream {
                // Held back by the tap, and the zone's side is gone: what
                // was on its way goes with it.
                return Ok(End::StreamClosed);
            }
            let open = fill_down(stream, &mut down, &mut end)?;
            tap_full = !deliver(tap, &down, &mut start, end, notes)?;
            if !open {
                return Ok(End::StreamClosed);
            }
        }
        if tap_full && at_tap & (libc::POLLOUT | gone) != 0 {
            tap_full = !deliver(tap, &down, &mut start, end, notes)?;
        }
        if tap_open && at_tap & (libc::POLLIN | gone) != 0 {
            // Not reading it, and it hung up: nothing more comes from it.
            tap_open = read_tap && fill_up(tap, &mut frame, &mut up, up_sent, notes)?;
        }
        if up_sent < up.len() {
            flush(stream, &mut up, &mut up_sent)?;
        }
        if !tap_open && up_sent >= up.len() {
            return Ok(End::TapClosed);
        }
    }
}

/// The poll events for a descriptor read and/or written.
fn interest(read: bool, write: bool) -> libc::c_short {
    let mut events = 0;
    if read {
        events |= libc::POLLIN;
    }
    if write {
        events |= libc::POLLOUT;
    }
    events
}

/// What one `read` brought.
enum Got {
    Bytes(usize),
    WouldBlock,
    Eof,
}

/// One `read(2)`, again when a signal interrupted it. `buf` is never empty.
fn read_some(fd: RawFd, buf: &mut [u8]) -> io::Result<Got> {
    loop {
        // SAFETY: a buffer of that length, alive for the call.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            return Ok(Got::Bytes(n.unsigned_abs()));
        }
        if n == 0 {
            return Ok(Got::Eof);
        }
        let e = io::Error::last_os_error();
        match e.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => return Ok(Got::WouldBlock),
            _ => return Err(e),
        }
    }
}

/// One write: `send(MSG_NOSIGNAL)` on the stream, which is a socket and
/// whose reader may be gone (EPIPE, and no SIGPIPE), `write(2)` on the tap.
/// `None` when it takes nothing now.
fn write_some(fd: RawFd, data: &[u8], socket: bool) -> io::Result<Option<usize>> {
    loop {
        // SAFETY: a buffer of that length, alive for the call.
        let n = unsafe {
            if socket {
                libc::send(fd, data.as_ptr().cast(), data.len(), libc::MSG_NOSIGNAL)
            } else {
                libc::write(fd, data.as_ptr().cast(), data.len())
            }
        };
        if n >= 0 {
            return Ok(Some(n.unsigned_abs()));
        }
        let e = io::Error::last_os_error();
        match e.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => return Ok(None),
            _ => return Err(e),
        }
    }
}

/// Read what the stream has, as far as the window goes. False once it
/// ended.
fn fill_down(stream: RawFd, down: &mut [u8], end: &mut usize) -> io::Result<bool> {
    while *end < down.len() {
        match read_some(stream, &mut down[*end..])? {
            Got::Bytes(n) => *end += n,
            Got::WouldBlock => return Ok(true),
            Got::Eof => return Ok(false),
        }
    }
    Ok(true)
}

/// Write every whole frame at the front of `buf[*start..end]` to the tap,
/// one `write` each. False when the tap takes no more for now; an impossible
/// length or a frame taken in part is an error.
fn deliver(
    tap: RawFd,
    buf: &[u8],
    start: &mut usize,
    end: usize,
    notes: &mut Notes<'_>,
) -> io::Result<bool> {
    while let Some(len) = decode(&buf[*start..end])? {
        let from = *start + LEN_BYTES;
        match write_some(tap, &buf[from..from + len], false)? {
            None => return Ok(false),
            Some(n) if n == len => {
                *start = from + len;
                notes.frame(&buf[from..from + len], false);
            }
            Some(n) => {
                return Err(io::Error::other(format!(
                    "the tap took {n} bytes of a frame of {len}"
                )))
            }
        }
    }
    Ok(true)
}

/// Read frames off the tap while the window has room. False once it ended.
fn fill_up(
    tap: RawFd,
    frame: &mut [u8],
    up: &mut Vec<u8>,
    sent: usize,
    notes: &mut Notes<'_>,
) -> io::Result<bool> {
    while up.len() - sent < WINDOW {
        match read_some(tap, frame)? {
            // A read that filled the buffer was longer than any frame, and
            // is refused as one.
            Got::Bytes(n) => {
                encode(&frame[..n], up)?;
                notes.frame(&frame[..n], true);
            }
            Got::WouldBlock => return Ok(true),
            Got::Eof => return Ok(false),
        }
    }
    Ok(true)
}

/// Send what waits for the stream, as much as it takes now.
fn flush(stream: RawFd, up: &mut Vec<u8>, sent: &mut usize) -> io::Result<()> {
    while *sent < up.len() {
        match write_some(stream, &up[*sent..], true)? {
            Some(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Some(n) => *sent += n,
            None => break,
        }
    }
    if *sent == up.len() {
        up.clear();
        *sent = 0;
    } else if *sent >= WINDOW {
        up.drain(..*sent);
        *sent = 0;
    }
    Ok(())
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl(2) on a descriptor the caller holds, no pointers.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The command line of `vpn-zone-core frame-relay`: `--tap-fd N --stream-fd
/// M`, in either order, both above 2 and not the same.
pub fn parse_args(args: &[OsString]) -> Result<(RawFd, RawFd), String> {
    let (mut tap, mut stream) = (None, None);
    let mut rest = args;
    while let [flag, value, tail @ ..] = rest {
        let slot = match flag.to_str() {
            Some("--tap-fd") => &mut tap,
            Some("--stream-fd") => &mut stream,
            _ => return Err(format!("unknown argument {}", flag.to_string_lossy())),
        };
        let fd = value
            .to_str()
            .and_then(|v| v.parse::<RawFd>().ok())
            .filter(|fd| *fd > 2)
            .ok_or_else(|| {
                format!(
                    "{} takes a descriptor above 2, not {}",
                    flag.to_string_lossy(),
                    value.to_string_lossy()
                )
            })?;
        if slot.replace(fd).is_some() {
            return Err(format!("{} given twice", flag.to_string_lossy()));
        }
        rest = tail;
    }
    if let [odd] = rest {
        return Err(format!("{} without a value", odd.to_string_lossy()));
    }
    match (tap, stream) {
        (Some(tap), Some(stream)) if tap != stream => Ok((tap, stream)),
        (Some(_), Some(_)) => Err("the tap and the stream are one descriptor".to_string()),
        _ => Err("needs --tap-fd N and --stream-fd M".to_string()),
    }
}

/// An inherited descriptor, checked to be open, and ours from here on.
fn adopt(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: fcntl(2) with F_GETFD reads flags only.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: open (checked above), handed to this process to own, and
    // owned by nothing else in it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Nothing a relay does needs a privilege: every capability goes, the
/// bounding set too, and no exec could bring one back (no_new_privs). Not
/// dumpable: nobody attaches to it, and its `/proc` entries are its own.
fn confine() -> io::Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const VERSION_3: u32 = 0x2008_0522;
    // SAFETY: prctl(2) with constants and no pointers. Dropping from the
    // bounding set needs CAP_SETPCAP, which a relay started without it does
    // not have; those that fail were not there to drop, or cannot come back
    // through no_new_privs anyway.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        );
        for cap in 0..64 {
            libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0);
        }
    }
    let mut header = Header {
        version: VERSION_3,
        pid: 0,
    };
    let none = Data {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    };
    let data = [none, none];
    // SAFETY: capset(2) with a version-3 header and its two data structs;
    // lowering every set is always allowed.
    if unsafe { libc::syscall(libc::SYS_capset, &mut header as *mut Header, data.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// What an instance's keeper starts the relay with (`bridge::attach`):
/// `frame-relay --attach --stream-fd N --ready-fd M --a4 A [--a6 A]
/// --ip PATH --nft PATH`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attach {
    /// Its end of the stream to the zone's passt.
    pub stream: RawFd,
    /// Where it says it is ready: one byte, `1`, once its tap is up and it
    /// is sealed.
    pub ready: RawFd,
    /// The instance's addresses of this attach (`bridge::plan`).
    pub a4: Ipv4Addr,
    pub a6: Option<Ipv6Addr>,
    /// What configures the tap and loads the instance's rules.
    pub ip: PathBuf,
    pub nft: PathBuf,
    /// The epoch's wall its rules carry (stage 4, `crate::epoch`): none
    /// before the instance's first switch.
    pub wall: Option<Wall>,
    /// The instance's counters' file (`crate::traffic`), which it counts
    /// every frame into; none, and it counts nothing.
    pub tally: Option<RawFd>,
    /// The instance's flows' file (`crate::flows`), which it notes every
    /// frame's flow in; none, and it notes none.
    pub flows: Option<RawFd>,
}

/// The epoch's wall an instance's rules carry (`crate::epoch`,
/// `zone::instance_ruleset`): only a socket born in this cgroup goes out —
/// `socket cgroupv2 level <level> "<cgroup>"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wall {
    pub level: u32,
    /// Absolute, as `/proc/<pid>/cgroup` has it.
    pub cgroup: String,
}

impl Wall {
    /// The wall of `epoch`, from its second on (`Epoch::wall`).
    pub fn of(epoch: &crate::epoch::Epoch) -> Option<Self> {
        epoch.wall().map(|(level, cgroup)| Self {
            level,
            cgroup: cgroup.to_owned(),
        })
    }

    /// The wall `epoch` would have, whichever it is: what the probe loads.
    pub fn probed(epoch: &crate::epoch::Epoch) -> Self {
        Self {
            level: epoch.level(),
            cgroup: epoch.path.clone(),
        }
    }

    /// `--wall-level L --wall-cgroup P`.
    pub fn args(&self) -> Vec<OsString> {
        vec![
            "--wall-level".into(),
            self.level.to_string().into(),
            "--wall-cgroup".into(),
            self.cgroup.clone().into(),
        ]
    }

    /// The two flags' values, held to what an epoch can be: an absolute
    /// cgroup path of plain components ([`crate::epoch::sane_path`]) whose
    /// depth is the level.
    fn checked(level: &str, cgroup: &str) -> Result<Self, String> {
        let level: u32 = level
            .parse()
            .map_err(|_| "--wall-level takes a number".to_owned())?;
        if !crate::epoch::sane_path(cgroup) {
            return Err("--wall-cgroup is no cgroup's path".to_owned());
        }
        let wall = Self {
            level,
            cgroup: cgroup.to_owned(),
        };
        let depth = cgroup.split('/').filter(|c| !c.is_empty()).count() as u32;
        if depth != level {
            return Err(format!(
                "--wall-level {level} is not the depth of {cgroup} ({depth})"
            ));
        }
        Ok(wall)
    }

    /// `--wall-level` and `--wall-cgroup` from a command line's values:
    /// both or neither.
    fn from_flags(level: Option<String>, cgroup: Option<String>) -> Result<Option<Self>, String> {
        match (level, cgroup) {
            (Some(level), Some(cgroup)) => Self::checked(&level, &cgroup).map(Some),
            (None, None) => Ok(None),
            _ => Err("--wall-level and --wall-cgroup go together".to_owned()),
        }
    }
}

/// Set a flag's value, once.
fn once<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("{flag} given twice"));
    }
    Ok(())
}

/// A tool's path as the keeper passes it: absolute, nothing looked up.
fn absolute(value: &OsString) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(format!("{} is not an absolute path", path.display()))
    }
}

impl Attach {
    /// Its command line after `frame-relay`, as [`Attach::parse`] reads it
    /// back.
    pub fn args(&self) -> Vec<OsString> {
        let mut out: Vec<OsString> = vec![
            "--attach".into(),
            "--stream-fd".into(),
            self.stream.to_string().into(),
            "--ready-fd".into(),
            self.ready.to_string().into(),
            "--a4".into(),
            self.a4.to_string().into(),
        ];
        if let Some(a6) = self.a6 {
            out.push("--a6".into());
            out.push(a6.to_string().into());
        }
        out.push("--ip".into());
        out.push(self.ip.clone().into_os_string());
        out.push("--nft".into());
        out.push(self.nft.clone().into_os_string());
        if let Some(wall) = &self.wall {
            out.extend(wall.args());
        }
        if let Some(tally) = self.tally {
            out.push("--tally-fd".into());
            out.push(tally.to_string().into());
        }
        if let Some(flows) = self.flows {
            out.push("--flows-fd".into());
            out.push(flows.to_string().into());
        }
        out
    }

    /// What follows `--attach`: every flag once, both descriptors above 2
    /// and not the same, the addresses in the instance's own ranges
    /// (`bridge::a4_usable`, `bridge::a6_usable`), the tools by absolute
    /// paths.
    pub fn parse(args: &[OsString]) -> Result<Self, String> {
        let (mut stream, mut ready, mut a4, mut a6, mut ip, mut nft) =
            (None, None, None, None, None, None);
        let (mut tally, mut flows): (Option<RawFd>, Option<RawFd>) = (None, None);
        let (mut wall_level, mut wall_cgroup): (Option<String>, Option<String>) = (None, None);
        let mut rest = args;
        while let [flag, value, tail @ ..] = rest {
            let flag = flag.to_string_lossy();
            let text = value.to_str().unwrap_or("");
            let fd = text.parse::<RawFd>().ok().filter(|fd| *fd > 2);
            match &*flag {
                "--stream-fd" => once(
                    &mut stream,
                    fd.ok_or("--stream-fd takes a descriptor above 2")?,
                    &flag,
                )?,
                "--ready-fd" => once(
                    &mut ready,
                    fd.ok_or("--ready-fd takes a descriptor above 2")?,
                    &flag,
                )?,
                "--a4" => once(
                    &mut a4,
                    text.parse::<Ipv4Addr>()
                        .ok()
                        .filter(|a| crate::bridge::a4_usable(*a, None))
                        .ok_or("--a4 is no address of the instance's network")?,
                    &flag,
                )?,
                "--a6" => once(
                    &mut a6,
                    text.parse::<Ipv6Addr>()
                        .ok()
                        .filter(|a| crate::bridge::a6_usable(*a, None))
                        .ok_or("--a6 is no address of the instance's network")?,
                    &flag,
                )?,
                "--ip" => once(&mut ip, absolute(value)?, &flag)?,
                "--nft" => once(&mut nft, absolute(value)?, &flag)?,
                "--tally-fd" => once(
                    &mut tally,
                    fd.ok_or("--tally-fd takes a descriptor above 2")?,
                    &flag,
                )?,
                "--flows-fd" => once(
                    &mut flows,
                    fd.ok_or("--flows-fd takes a descriptor above 2")?,
                    &flag,
                )?,
                "--wall-level" => once(&mut wall_level, text.to_owned(), &flag)?,
                "--wall-cgroup" => once(&mut wall_cgroup, text.to_owned(), &flag)?,
                _ => return Err(format!("unknown argument {flag}")),
            }
            rest = tail;
        }
        if let [odd] = rest {
            return Err(format!("{} without a value", odd.to_string_lossy()));
        }
        let (Some(stream), Some(ready), Some(a4), Some(ip), Some(nft)) =
            (stream, ready, a4, ip, nft)
        else {
            return Err("needs --stream-fd, --ready-fd, --a4, --ip and --nft".to_owned());
        };
        let fds = [Some(stream), Some(ready), tally, flows];
        let given: Vec<RawFd> = fds.iter().flatten().copied().collect();
        if (1..given.len()).any(|i| given[..i].contains(&given[i])) {
            return Err(
                "the stream, the pipe of its word, the counters and the flows share a descriptor"
                    .to_owned(),
            );
        }
        let wall = Wall::from_flags(wall_level, wall_cgroup)?;
        Ok(Self {
            stream,
            ready,
            a4,
            a6,
            ip,
            nft,
            wall,
            tally,
            flows,
        })
    }
}

/// What `--probe` and `--seal` are given: nft's path, and — for the probe —
/// the wall it tries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Walled {
    pub nft: PathBuf,
    pub wall: Option<Wall>,
}

impl Walled {
    /// Its command line after `--probe` or `--seal`.
    pub fn args(&self) -> Vec<OsString> {
        let mut out: Vec<OsString> = vec!["--nft".into(), self.nft.clone().into_os_string()];
        if let Some(wall) = &self.wall {
            out.extend(wall.args());
        }
        out
    }

    /// [`Walled::args`] read back: every flag once, nft by an absolute path.
    pub fn parse(args: &[OsString]) -> Result<Self, String> {
        let mut nft = None;
        let (mut level, mut cgroup): (Option<String>, Option<String>) = (None, None);
        let mut rest = args;
        while let [flag, value, tail @ ..] = rest {
            let flag = flag.to_string_lossy();
            let text = value.to_str().unwrap_or("").to_owned();
            match &*flag {
                "--nft" => once(&mut nft, absolute(value)?, &flag)?,
                "--wall-level" => once(&mut level, text, &flag)?,
                "--wall-cgroup" => once(&mut cgroup, text, &flag)?,
                _ => return Err(format!("unknown argument {flag}")),
            }
            rest = tail;
        }
        if let [odd] = rest {
            return Err(format!("{} without a value", odd.to_string_lossy()));
        }
        Ok(Self {
            nft: nft.ok_or("needs --nft")?,
            wall: Wall::from_flags(level, cgroup)?,
        })
    }
}

/// Whether the instance's tap is there: the old way out not gone.
fn tap_there() -> bool {
    let Ok(name) = std::ffi::CString::new(crate::zone::TUN_IFACE) else {
        return false;
    };
    // SAFETY: a NUL-terminated name, alive for the call.
    unsafe { libc::if_nametoindex(name.as_ptr()) != 0 }
}

/// The instance's tap, `awg0` as a zone's tunnel is named — the name the
/// instance's rules and the doctor's probe know: made here, not persistent,
/// this process its only owner.
fn make_tap() -> io::Result<OwnedFd> {
    let tun = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;
    // SAFETY: an all-zero ifreq is a valid one: an empty name, no flags.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (to, from) in req.ifr_name.iter_mut().zip(crate::zone::TUN_IFACE.bytes()) {
        *to = from as libc::c_char;
    }
    req.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short;
    // SAFETY: TUNSETIFF reads the ifreq and writes the name back into it; it
    // lives past the call.
    if unsafe {
        libc::ioctl(
            tun.as_raw_fd(),
            libc::TUNSETIFF,
            std::ptr::from_mut(&mut req),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(tun.into())
}

/// The tap's address, MTU and routes, as the instance's root: a random MAC
/// (locally administered, one host's), `a4` in the instance's /16 with the
/// default through passt's gateway, and — IPv6 carried — `a6` with the
/// default through `fe80::1`. Lower than the space's unreachable defaults
/// (`zone::instance_ground`), which answer at once while there is no tap.
fn configure(attach: &Attach) -> Result<(), String> {
    let mut mac = [0u8; 6];
    crate::bridge::random_bytes(&mut mac).map_err(|e| format!("no random MAC ({e})"))?;
    mac[0] = (mac[0] & 0xfe) | 0x02;
    let mac: Vec<String> = mac.iter().map(|b| format!("{b:02x}")).collect();
    let mac = mac.join(":");
    let dev = crate::zone::TUN_IFACE;
    let mtu = crate::bridge::MTU.to_string();
    let a4 = format!("{}/{}", attach.a4, crate::bridge::PREFIX4);
    let g4 = crate::bridge::G4.to_string();
    let ip = |args: &[&str]| crate::zone::run_tool(&attach.ip, args, false);
    ip(&[
        "link",
        "set",
        "dev",
        dev,
        "address",
        mac.as_str(),
        "mtu",
        mtu.as_str(),
        "up",
    ])?;
    ip(&["-4", "addr", "add", a4.as_str(), "dev", dev])?;
    ip(&[
        "-4",
        "route",
        "add",
        "default",
        "via",
        g4.as_str(),
        "dev",
        dev,
    ])?;
    if let Some(a6) = attach.a6 {
        let a6 = format!("{a6}/128");
        let g6 = crate::bridge::G6.to_string();
        ip(&["-6", "addr", "add", a6.as_str(), "dev", dev, "nodad"])?;
        ip(&[
            "-6",
            "route",
            "add",
            "default",
            "via",
            g6.as_str(),
            "dev",
            dev,
        ])?;
    }
    Ok(())
}

/// The instance's rules: out by the tap from this attach's addresses, or
/// not at all (`zone::instance_ruleset`), in place of any an earlier attach
/// left. Without the epoch's wall, not loaded — no nft, a kernel without
/// nf_tables — is said loudly, and the relay goes on: the topology is the
/// wall (stage 2 of the design). With it (stage 4, after the instance's
/// first switch), not loaded is the relay's end: the sockets of the epochs
/// before would go out by the new tap.
fn seal(attach: &Attach) -> Result<(), String> {
    let wall = attach.wall.as_ref().map(|w| (w.level, w.cgroup.as_str()));
    let loaded = crate::zone::instance_ruleset(wall, attach.a4, attach.a6)
        .map(|ruleset| crate::zone::replacing_table(&ruleset))
        .and_then(|ruleset| crate::zone::feed_nft(&attach.nft, &ruleset));
    match loaded {
        Ok(()) => Ok(()),
        Err(e) if attach.wall.is_some() => Err(format!(
            "the instance's rules with the epoch's wall did not load ({e}) — no way out \
             without them"
        )),
        Err(e) => {
            eprintln!(
                "vpn-zone-core frame-relay: the instance's second echelon is OFF ({e}) — its \
                 way out is its tap alone, and nothing insures it against a mistake"
            );
            Ok(())
        }
    }
}

/// `frame-relay --attach …` ([`Attach`]).
fn attach_main(args: &[OsString]) -> u8 {
    // Not dumpable before anything else: the root of the instance's user
    // namespace, exec'd in it — nothing of the instance's may read it.
    // SAFETY: prctl with these arguments takes no pointers.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    let attach = match Attach::parse(args) {
        Ok(attach) => attach,
        Err(e) => {
            eprintln!("vpn-zone-core frame-relay: {e}");
            return 2;
        }
    };
    let (stream, ready) = match (adopt(attach.stream), adopt(attach.ready)) {
        (Ok(stream), Ok(ready)) => (stream, ready),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("vpn-zone-core frame-relay: a descriptor it was given is not open: {e}");
            return 2;
        }
    };
    // One way out at a time: a tap still there is an old one's (G1 of the
    // container design's live switch).
    if tap_there() {
        eprintln!(
            "vpn-zone-core frame-relay: the instance's tap is still there — its old way out is \
             not gone; no second one"
        );
        return 1;
    }
    // The rules before the tap: its first frame meets them.
    if let Err(e) = seal(&attach) {
        eprintln!("vpn-zone-core frame-relay: {e}");
        return 1;
    }
    let tap = match make_tap() {
        Ok(tap) => tap,
        Err(e) => {
            eprintln!(
                "vpn-zone-core frame-relay: cannot make the instance's tap ({e}) — it stays \
                 without a way out"
            );
            return 1;
        }
    };
    if let Err(e) = configure(&attach) {
        eprintln!("vpn-zone-core frame-relay: {e} — the instance stays without a way out");
        return 1;
    }
    // Its counters (`crate::traffic`), mapped while it may still make the
    // call: counting takes none. None, or a file it cannot map: it relays
    // all the same, and counts nothing — the counts are a record, not the
    // wall.
    let tally = attach.tally.and_then(|fd| {
        let file = adopt(fd).ok()?;
        match crate::traffic::Tally::map(file.as_fd(), true) {
            Ok(tally) => Some(tally),
            Err(e) => {
                eprintln!("vpn-zone-core frame-relay: no counters ({e}) — relaying uncounted");
                None
            }
        }
    });
    // Its table of flows (`crate::flows`), the same way; its index grows
    // by the allocator, which the filter lets it (`brk`, `mmap`).
    let mut flows = attach.flows.and_then(|fd| {
        let file = adopt(fd).ok()?;
        match crate::flows::Table::map(file.as_fd(), true) {
            Ok(flows) => Some(flows),
            Err(e) => {
                eprintln!("vpn-zone-core frame-relay: no table of flows ({e}) — relaying unnoted");
                None
            }
        }
    });
    if let Err(e) = confine() {
        eprintln!("vpn-zone-core frame-relay: cannot confine itself ({e}) — not relaying");
        return 1;
    }
    if let Err(e) = crate::seccomp::Filter::relay().and_then(|filter| filter.load()) {
        eprintln!("vpn-zone-core frame-relay: no seccomp filter ({e}) — not relaying");
        return 1;
    }
    // Sealed: its keeper may say the instance has a way out.
    if fs::File::from(ready).write_all(b"1").is_err() {
        return 1;
    }
    let mut notes = Notes {
        tally: tally.as_ref(),
        flows: flows.as_mut(),
    };
    match pump_counted(tap.as_fd(), stream.as_fd(), &mut notes) {
        Ok(End::StreamClosed) => 0,
        Ok(End::TapClosed) => {
            eprintln!("vpn-zone-core frame-relay: the tap ended");
            0
        }
        Err(e) => {
            eprintln!(
                "vpn-zone-core frame-relay: {e} — the relay ends, and the instance's way out \
                 with it"
            );
            1
        }
    }
}

/// The probe's table in the instance's namespace, made and deleted in one
/// transaction: what the kernel and nft take is checked — the expression's
/// module loaded for it, the cgroup's path resolved by nft in this, the
/// host's, mount namespace (J5) —, and nothing stays.
pub fn probe_ruleset(wall: &Wall) -> String {
    let relative = wall.cgroup.trim_start_matches('/');
    format!(
        "table inet vzprobe {{\n\tchain output {{\n\t\ttype filter hook output priority \
         filter; policy accept;\n\t\tsocket cgroupv2 level {} \"{relative}\" accept\n\t}}\n}}\n\
         delete table inet vzprobe\n",
        wall.level
    )
}

/// `frame-relay --probe --nft P --wall-level L --wall-cgroup C`: whether a
/// live switch can be made in this namespace — `nft-socket=<yes|no>
/// destroy=<yes|no>` on stdout, why not on stderr.
fn probe_main(args: &[OsString]) -> u8 {
    // SAFETY: prctl with these arguments takes no pointers.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    let (nft, wall) = match Walled::parse(args) {
        Ok(Walled {
            nft,
            wall: Some(wall),
        }) => (nft, wall),
        Ok(_) => {
            eprintln!("vpn-zone-core frame-relay --probe: needs the wall it tries");
            return 2;
        }
        Err(e) => {
            eprintln!("vpn-zone-core frame-relay --probe: {e}");
            return 2;
        }
    };
    let nft_socket = match crate::zone::feed_nft(&nft, &probe_ruleset(&wall)) {
        Ok(()) => "yes",
        Err(e) => {
            eprintln!(
                "vpn-zone-core frame-relay --probe: nft takes no `socket cgroupv2` here ({e}) — \
                 no epoch's wall, no live switch (the module nft_socket?)"
            );
            "no"
        }
    };
    let destroy = match crate::sockdiag::destroy_supported() {
        Ok(()) => "yes",
        Err(e) => {
            eprintln!("vpn-zone-core frame-relay --probe: no socket destroyed here: {e}");
            "no"
        }
    };
    println!("nft-socket={nft_socket} destroy={destroy}");
    0
}

/// `frame-relay --seal --nft P`: a switch's break (stage 4), between its cut
/// and the next attach, with the instance's programs frozen: no tap may be
/// there; every socket that may reach out destroyed; the rules closed to
/// loopback. The tally on stdout (`sockdiag::Tally::word`). 1 when a tap is
/// there or the closed rules do not load.
fn seal_main(args: &[OsString]) -> u8 {
    // SAFETY: prctl with these arguments takes no pointers.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    let walled = match Walled::parse(args) {
        Ok(walled) => walled,
        Err(e) => {
            eprintln!("vpn-zone-core frame-relay --seal: {e}");
            return 2;
        }
    };
    if tap_there() {
        eprintln!(
            "vpn-zone-core frame-relay --seal: the instance's tap is still there — its old way \
             out is not gone"
        );
        return 1;
    }
    let tally = crate::sockdiag::break_all();
    for e in &tally.errors {
        eprintln!("vpn-zone-core frame-relay --seal: {e}");
    }
    let closed = crate::zone::replacing_table(&crate::zone::instance_closed_ruleset());
    if let Err(e) = crate::zone::feed_nft(&walled.nft, &closed) {
        eprintln!(
            "vpn-zone-core frame-relay --seal: the closed rules did not load ({e}) — not sealed"
        );
        return 1;
    }
    println!("{}", tally.word());
    0
}

/// `vpn-zone-core frame-relay --tap-fd N --stream-fd M`: confine itself,
/// then [`pump`] between the two descriptors it inherited until either
/// ends. 0 when one side ended, 1 on an error, 2 on a bad command line.
/// `--attach …`: an instance's relay ([`Attach`]); `--probe …` and
/// `--seal …`: the live switch's (stage 4, [`Walled`]).
pub fn main(args: &[OsString]) -> u8 {
    match args.first().and_then(|a| a.to_str()) {
        Some("--attach") => return attach_main(&args[1..]),
        Some("--probe") => return probe_main(&args[1..]),
        Some("--seal") => return seal_main(&args[1..]),
        _ => {}
    }
    let (tap, stream) = match parse_args(args) {
        Ok(fds) => fds,
        Err(e) => {
            eprintln!("vpn-zone-core frame-relay: {e}");
            return 2;
        }
    };
    let (tap, stream) = match (adopt(tap), adopt(stream)) {
        (Ok(tap), Ok(stream)) => (tap, stream),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("vpn-zone-core frame-relay: a descriptor it was given is not open: {e}");
            return 2;
        }
    };
    if let Err(e) = confine() {
        eprintln!("vpn-zone-core frame-relay: cannot confine itself ({e}) — not relaying");
        return 1;
    }
    match pump(tap.as_fd(), stream.as_fd()) {
        Ok(End::StreamClosed) => 0,
        Ok(End::TapClosed) => {
            eprintln!("vpn-zone-core frame-relay: the tap ended");
            0
        }
        Err(e) => {
            eprintln!(
                "vpn-zone-core frame-relay: {e} — the relay ends, and the instance's way out \
                 with it"
            );
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    /// A frame of `len` bytes that says which one it is.
    fn frame(n: u32, len: usize) -> Vec<u8> {
        let mut f = vec![0xa5u8; len];
        f[..4].copy_from_slice(&n.to_be_bytes());
        f
    }

    fn seqpacket_pair() -> (OwnedFd, OwnedFd) {
        let mut fds: [libc::c_int; 2] = [0; 2];
        // SAFETY: a valid array of two ints for the duration of the call.
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0, "socketpair: {}", io::Error::last_os_error());
        // SAFETY: just made, owned by nothing else.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    fn send_packet(fd: &OwnedFd, data: &[u8]) -> io::Result<()> {
        // SAFETY: a buffer of that length, alive for the call.
        let n = unsafe {
            libc::send(
                fd.as_raw_fd(),
                data.as_ptr().cast(),
                data.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        assert_eq!(n.unsigned_abs(), data.len());
        Ok(())
    }

    /// One packet, waiting at most ten seconds for it; `None` at its end.
    fn recv_packet(fd: &OwnedFd) -> Option<Vec<u8>> {
        let mut p = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        let ready = unsafe { libc::poll(&mut p, 1, 10_000) };
        assert!(ready > 0, "no packet within ten seconds");
        let mut buf = vec![0u8; MAX_FRAME + 2];
        // SAFETY: a buffer of that length, alive for the call.
        let n = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        assert!(n >= 0, "recv: {}", io::Error::last_os_error());
        if n == 0 {
            return None;
        }
        buf.truncate(n.unsigned_abs());
        Some(buf)
    }

    /// The next whole frame off a stream, `None` at its end.
    fn read_frame(stream: &mut UnixStream) -> Option<Vec<u8>> {
        let mut head = [0u8; LEN_BYTES];
        if stream.read_exact(&mut head).is_err() {
            return None;
        }
        assert!(decode(&head).is_ok(), "a bad length on the stream");
        let len = u32::from_be_bytes(head) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).unwrap();
        Some(body)
    }

    fn framed(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for f in frames {
            encode(f, &mut out).unwrap();
        }
        out
    }

    fn start(tap: OwnedFd, stream: UnixStream) -> std::thread::JoinHandle<io::Result<End>> {
        std::thread::spawn(move || pump(tap.as_fd(), stream.as_fd()))
    }

    #[test]
    fn a_frame_is_its_length_then_itself() {
        let f = frame(1, 60);
        let mut out = Vec::new();
        encode(&f, &mut out).unwrap();
        assert_eq!(out[..4], [0, 0, 0, 60]);
        assert_eq!(out[4..], f[..]);
        assert_eq!(decode(&out), Ok(Some(60)));
    }

    #[test]
    fn lengths_are_held_to_what_passt_takes() {
        assert_eq!(check_len(0), Err(FrameError::TooShort(0)));
        assert_eq!(check_len(13), Err(FrameError::TooShort(13)));
        assert_eq!(check_len(14), Ok(()));
        assert_eq!(check_len(65535), Ok(()));
        assert_eq!(check_len(65536), Err(FrameError::TooLong(65536)));
        let mut out = Vec::new();
        assert_eq!(encode(&[0u8; 13], &mut out), Err(FrameError::TooShort(13)));
        assert_eq!(
            encode(&vec![0u8; 65536], &mut out),
            Err(FrameError::TooLong(65536))
        );
        assert!(out.is_empty(), "a refused frame left bytes behind");
        let mut out = Vec::new();
        encode(&vec![7u8; 65535], &mut out).unwrap();
        assert_eq!(out.len(), 65539);
    }

    #[test]
    fn a_split_frame_waits_for_the_rest() {
        let mut out = Vec::new();
        encode(&frame(2, 100), &mut out).unwrap();
        encode(&frame(3, 20), &mut out).unwrap();
        for cut in 0..104 {
            assert_eq!(decode(&out[..cut]), Ok(None), "at {cut}");
        }
        assert_eq!(decode(&out[..104]), Ok(Some(100)));
        assert_eq!(decode(&out[104..]), Ok(Some(20)));
    }

    #[test]
    fn an_impossible_length_is_refused_before_its_bytes() {
        // Zero, and the largest a length can say: both judged on the four
        // bytes alone.
        assert_eq!(decode(&[0, 0, 0, 0]), Err(FrameError::TooShort(0)));
        assert_eq!(decode(&[0, 1, 0, 0]), Err(FrameError::TooLong(0x0001_0000)));
        assert_eq!(
            decode(&[0xff, 0xff, 0xff, 0xff, 1, 2]),
            Err(FrameError::TooLong(0xffff_ffff))
        );
        assert_eq!(decode(&[0, 0, 0]), Ok(None));
    }

    /// Frames both ways, the stream's in pieces of any size; the stream's
    /// end ends the pump, and the tap sees its end right after.
    #[test]
    fn frames_go_both_ways_and_the_streams_end_ends_it() {
        let (tap, tap_peer) = seqpacket_pair();
        let (stream, mut stream_peer) = UnixStream::pair().unwrap();
        stream_peer
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let pump = start(tap, stream);

        let out: Vec<Vec<u8>> = (0..3).map(|n| frame(n, 60 + n as usize * 700)).collect();
        for f in &out {
            send_packet(&tap_peer, f).unwrap();
        }
        for f in &out {
            assert_eq!(read_frame(&mut stream_peer).as_ref(), Some(f));
        }

        let back: Vec<Vec<u8>> = (10..14).map(|n| frame(n, 14 + n as usize * 300)).collect();
        let bytes = framed(&back);
        // Split reads: a few bytes at a time, across every boundary.
        for piece in bytes.chunks(7) {
            stream_peer.write_all(piece).unwrap();
            stream_peer.flush().unwrap();
        }
        for f in &back {
            assert_eq!(recv_packet(&tap_peer).as_ref(), Some(f));
        }

        drop(stream_peer);
        assert_eq!(pump.join().unwrap().unwrap(), End::StreamClosed);
        assert_eq!(recv_packet(&tap_peer), None, "the tap's end did not follow");
    }

    /// Every frame counted (`crate::traffic`): out as it leaves the tap,
    /// in as the tap takes it, by the frame's own length.
    #[test]
    fn every_frame_is_counted_both_ways() {
        let dir = std::env::temp_dir().join(format!("vz-relay-tally-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file = crate::traffic::create(&dir).unwrap();
        let tally = crate::traffic::Tally::map(file.as_fd(), true).unwrap();
        let (tap, tap_peer) = seqpacket_pair();
        let (stream, mut stream_peer) = UnixStream::pair().unwrap();
        stream_peer
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let pump = std::thread::spawn(move || {
            let mut notes = Notes {
                tally: Some(&tally),
                flows: None,
            };
            let end = pump_counted(tap.as_fd(), stream.as_fd(), &mut notes);
            tally.close();
            end
        });
        let out: Vec<Vec<u8>> = (0..3).map(|n| frame(n, 60 + n as usize * 700)).collect();
        for f in &out {
            send_packet(&tap_peer, f).unwrap();
        }
        for f in &out {
            assert_eq!(read_frame(&mut stream_peer).as_ref(), Some(f));
        }
        let back: Vec<Vec<u8>> = (10..12).map(|n| frame(n, 1500)).collect();
        stream_peer.write_all(&framed(&back)).unwrap();
        for f in &back {
            assert_eq!(recv_packet(&tap_peer).as_ref(), Some(f));
        }
        drop(stream_peer);
        assert_eq!(pump.join().unwrap().unwrap(), End::StreamClosed);
        let counts = crate::traffic::read(&dir).unwrap();
        assert_eq!((counts.out_frames, counts.out_bytes), (3, 60 + 760 + 1460));
        assert_eq!((counts.in_frames, counts.in_bytes), (2, 3000));
        let _ = fs::remove_dir_all(&dir);
    }

    /// Every frame's flow noted (`crate::flows`): by the instance's side of
    /// it, the two ways one flow.
    #[test]
    fn every_frames_flow_is_noted() {
        let dir = std::env::temp_dir().join(format!("vz-relay-flows-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file = crate::flows::create(&dir).unwrap();
        let (tap, tap_peer) = seqpacket_pair();
        let (stream, mut stream_peer) = UnixStream::pair().unwrap();
        stream_peer
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let pump = std::thread::spawn(move || {
            let mut flows = crate::flows::Table::map(file.as_fd(), true).unwrap();
            let mut notes = Notes {
                tally: None,
                flows: Some(&mut flows),
            };
            let end = pump_counted(tap.as_fd(), stream.as_fd(), &mut notes);
            flows.close();
            end
        });
        let tcp = |src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16| {
            let mut f = vec![0u8; 12];
            f.extend_from_slice(&[0x08, 0x00, 0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0]);
            f.extend_from_slice(&src);
            f.extend_from_slice(&dst);
            f.extend_from_slice(&sport.to_be_bytes());
            f.extend_from_slice(&dport.to_be_bytes());
            f.extend_from_slice(&[0; 16]);
            f
        };
        let out = tcp([10, 254, 0, 2], [203, 0, 113, 7], 40000, 443);
        send_packet(&tap_peer, &out).unwrap();
        assert_eq!(read_frame(&mut stream_peer).as_ref(), Some(&out));
        let back = tcp([203, 0, 113, 7], [10, 254, 0, 2], 443, 40000);
        stream_peer
            .write_all(&framed(std::slice::from_ref(&back)))
            .unwrap();
        assert_eq!(recv_packet(&tap_peer).as_ref(), Some(&back));
        drop(stream_peer);
        assert_eq!(pump.join().unwrap().unwrap(), End::StreamClosed);
        let (flows, _) = crate::flows::read(&dir).unwrap();
        assert_eq!(flows.len(), 1, "{flows:?}");
        let f = &flows[0];
        let remote = "203.0.113.7".parse::<std::net::IpAddr>().unwrap();
        assert_eq!(
            (f.key.remote, f.key.rport, f.key.lport),
            (remote, 443, 40000)
        );
        assert_eq!((f.out_packets, f.in_packets), (1, 1));
        assert_eq!(
            (f.out_bytes, f.in_bytes),
            (out.len() as u64, back.len() as u64)
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A stream that takes nothing stops the reading of the tap — the
    /// sender runs into a full queue long before megabytes have gone — and
    /// nothing is lost: every frame arrives, in order, once it is read.
    #[test]
    fn a_stream_that_takes_nothing_holds_the_tap_back() {
        let (tap, tap_peer) = seqpacket_pair();
        let (stream, mut stream_peer) = UnixStream::pair().unwrap();
        stream_peer
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let pump = start(tap, stream);

        const CAP: u32 = 20_000;
        let mut sent = 0;
        while sent < CAP {
            match send_packet(&tap_peer, &frame(sent, 1000)) {
                Ok(()) => sent += 1,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("send: {e}"),
            }
        }
        assert!(
            sent < CAP,
            "20 MB taken with nobody reading: no back-pressure"
        );
        for n in 0..sent {
            assert_eq!(
                read_frame(&mut stream_peer),
                Some(frame(n, 1000)),
                "frame {n}"
            );
        }
        // It flows again.
        send_packet(&tap_peer, &frame(CAP, 1000)).unwrap();
        assert_eq!(read_frame(&mut stream_peer), Some(frame(CAP, 1000)));

        drop(tap_peer);
        assert_eq!(pump.join().unwrap().unwrap(), End::TapClosed);
        assert_eq!(
            read_frame(&mut stream_peer),
            None,
            "the stream's end did not follow"
        );
    }

    /// The other way: a tap that takes nothing stops the reading of the
    /// stream, and nothing is lost either.
    #[test]
    fn a_tap_that_takes_nothing_holds_the_stream_back() {
        let (tap, tap_peer) = seqpacket_pair();
        let (stream, stream_peer) = UnixStream::pair().unwrap();
        let pump = start(tap, stream);
        stream_peer.set_nonblocking(true).unwrap();
        let mut writer = &stream_peer;

        const CAP: u32 = 20_000;
        let mut sent = 0;
        let mut pending: Vec<u8> = Vec::new();
        'fill: while sent < CAP {
            pending.clear();
            encode(&frame(sent, 1000), &mut pending).unwrap();
            let mut at = 0;
            while at < pending.len() {
                match writer.write(&pending[at..]) {
                    Ok(n) => at += n,
                    // A frame that went in only in part stays incomplete
                    // and is not counted: the pump holds it until the end.
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break 'fill,
                    Err(e) => panic!("write: {e}"),
                }
            }
            sent += 1;
        }
        assert!(
            sent < CAP,
            "20 MB taken with nobody reading: no back-pressure"
        );
        for n in 0..sent {
            assert_eq!(recv_packet(&tap_peer), Some(frame(n, 1000)), "frame {n}");
        }
        drop(stream_peer);
        assert_eq!(pump.join().unwrap().unwrap(), End::StreamClosed);
    }

    /// A bad length from the zone's side ends the pump with an error, and
    /// so does a frame from the tap that is longer than passt takes.
    #[test]
    fn any_bad_frame_ends_the_pump() {
        let (tap, _tap_peer) = seqpacket_pair();
        let (stream, mut stream_peer) = UnixStream::pair().unwrap();
        let pump = start(tap, stream);
        stream_peer.write_all(&[0, 0, 0, 5, 1, 2, 3, 4, 5]).unwrap();
        let e = pump.join().unwrap().unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{e}");

        let (tap, tap_peer) = seqpacket_pair();
        let (stream, _stream_peer) = UnixStream::pair().unwrap();
        let pump = start(tap, stream);
        send_packet(&tap_peer, &vec![1u8; MAX_FRAME + 1]).unwrap();
        let e = pump.join().unwrap().unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{e}");

        let (tap, tap_peer) = seqpacket_pair();
        let (stream, _stream_peer) = UnixStream::pair().unwrap();
        let pump = start(tap, stream);
        send_packet(&tap_peer, &[1u8; 13]).unwrap();
        let e = pump.join().unwrap().unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{e}");
    }

    #[test]
    fn the_command_line_names_two_open_descriptors() {
        let args = |a: &[&str]| a.iter().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(
            parse_args(&args(&["--tap-fd", "3", "--stream-fd", "4"])),
            Ok((3, 4))
        );
        assert_eq!(
            parse_args(&args(&["--stream-fd", "9", "--tap-fd", "5"])),
            Ok((5, 9))
        );
        let bad_lines: &[&[&str]] = &[
            &["--tap-fd", "3"],
            &["--tap-fd", "3", "--stream-fd", "3"],
            &["--tap-fd", "2", "--stream-fd", "4"],
            &["--tap-fd", "x", "--stream-fd", "4"],
            &["--tap-fd", "3", "--stream-fd", "4", "--tap-fd", "5"],
            &["--tap-fd", "3", "--stream-fd", "4", "--extra"],
            &["--other", "3", "--stream-fd", "4"],
            &[],
        ];
        for &bad in bad_lines {
            assert!(parse_args(&args(bad)).is_err(), "{bad:?}");
        }
    }

    /// What an instance's keeper starts the relay with is read back as it
    /// was written (stage 2); anything else is refused before a tap is made.
    #[test]
    fn an_attachs_command_line_goes_there_and_back() {
        let attach = Attach {
            stream: 7,
            ready: 8,
            a4: Ipv4Addr::new(10, 254, 3, 4),
            a6: Some(crate::bridge::a6_from(0xabcd_0000_0000_0001)),
            ip: PathBuf::from("/nix/store/x-iproute2/bin/ip"),
            nft: PathBuf::from("/nix/store/x-nftables/bin/nft"),
            wall: None,
            tally: None,
            flows: None,
        };
        let line = attach.args();
        assert_eq!(line[0], "--attach");
        assert_eq!(Attach::parse(&line[1..]), Ok(attach.clone()));
        let four = Attach {
            a6: None,
            ..attach.clone()
        };
        let line = four.args();
        assert!(!line.contains(&OsString::from("--a6")), "{line:?}");
        assert_eq!(Attach::parse(&line[1..]), Ok(four));
        // With the epoch's wall (stage 4): there and back as well.
        let epoch = crate::epoch::Epoch::of(
            "/user.slice/user-1000.slice/user@1000.service/app.slice/\
             vpn-zone-container@work.service",
            2,
        );
        let walled = Attach {
            wall: Wall::of(&epoch),
            ..attach.clone()
        };
        assert_eq!(
            walled.wall,
            Some(Wall {
                level: 6,
                cgroup: epoch.path.clone()
            })
        );
        let line = walled.args();
        assert_eq!(Attach::parse(&line[1..]), Ok(walled));
        // With its counters: there and back; never one of its other
        // descriptors.
        let counted = Attach {
            tally: Some(9),
            ..attach.clone()
        };
        let line = counted.args();
        assert_eq!(Attach::parse(&line[1..]), Ok(counted));
        for fd in [7, 8] {
            let line = Attach {
                tally: Some(fd),
                ..attach.clone()
            }
            .args();
            assert!(Attach::parse(&line[1..]).is_err(), "{fd}");
        }
        // With its flows' table too: there and back; never another of its
        // descriptors.
        let noted = Attach {
            tally: Some(9),
            flows: Some(10),
            ..attach.clone()
        };
        let line = noted.args();
        assert_eq!(Attach::parse(&line[1..]), Ok(noted));
        for fd in [7, 8, 9] {
            let line = Attach {
                tally: Some(9),
                flows: Some(fd),
                ..attach.clone()
            }
            .args();
            assert!(Attach::parse(&line[1..]).is_err(), "{fd}");
        }
        let args = |a: &[&str]| a.iter().map(OsString::from).collect::<Vec<_>>();
        let good = [
            "--stream-fd",
            "7",
            "--ready-fd",
            "8",
            "--a4",
            "10.254.3.4",
            "--ip",
            "/x/ip",
            "--nft",
            "/x/nft",
        ];
        assert!(Attach::parse(&args(&good)).is_ok());
        let bad_lines: &[&[&str]] = &[
            &[],
            &[
                "--stream-fd",
                "7",
                "--ready-fd",
                "7",
                "--a4",
                "10.254.3.4",
                "--ip",
                "/x/ip",
                "--nft",
                "/x/nft",
            ],
            &[
                "--stream-fd",
                "2",
                "--ready-fd",
                "8",
                "--a4",
                "10.254.3.4",
                "--ip",
                "/x/ip",
                "--nft",
                "/x/nft",
            ],
            &[
                "--stream-fd",
                "7",
                "--ready-fd",
                "8",
                "--a4",
                "10.99.0.2",
                "--ip",
                "/x/ip",
                "--nft",
                "/x/nft",
            ],
            &[
                "--stream-fd",
                "7",
                "--ready-fd",
                "8",
                "--a4",
                "10.254.255.254",
                "--ip",
                "/x/ip",
                "--nft",
                "/x/nft",
            ],
            &[
                "--stream-fd",
                "7",
                "--ready-fd",
                "8",
                "--a4",
                "10.254.3.4",
                "--a6",
                "fd99::2",
                "--ip",
                "/x/ip",
                "--nft",
                "/x/nft",
            ],
            &[
                "--stream-fd",
                "7",
                "--ready-fd",
                "8",
                "--a4",
                "10.254.3.4",
                "--ip",
                "ip",
                "--nft",
                "/x/nft",
            ],
            &[
                "--stream-fd",
                "7",
                "--ready-fd",
                "8",
                "--a4",
                "10.254.3.4",
                "--ip",
                "/x/ip",
            ],
            &[
                "--stream-fd",
                "7",
                "--ready-fd",
                "8",
                "--a4",
                "10.254.3.4",
                "--ip",
                "/x/ip",
                "--nft",
                "/x/nft",
                "--a4",
                "10.254.3.5",
            ],
            &[
                "--stream-fd",
                "7",
                "--ready-fd",
                "8",
                "--a4",
                "10.254.3.4",
                "--ip",
                "/x/ip",
                "--nft",
                "/x/nft",
                "--tap-fd",
                "9",
            ],
            &[
                "--stream-fd",
                "7",
                "--ready-fd",
                "8",
                "--a4",
                "10.254.3.4",
                "--ip",
                "/x/ip",
                "--nft",
            ],
        ];
        for &bad in bad_lines {
            assert!(Attach::parse(&args(bad)).is_err(), "{bad:?}");
        }
        // The wall: both flags, a sane path, its depth as the level.
        let with = |extra: &[&str]| {
            let mut line: Vec<&str> = good.to_vec();
            line.extend_from_slice(extra);
            args(&line)
        };
        assert!(Attach::parse(&with(&["--wall-level", "2", "--wall-cgroup", "/a/e2"])).is_ok());
        for bad in [
            &["--wall-level", "2"][..],
            &["--wall-cgroup", "/a/e2"],
            &["--wall-level", "3", "--wall-cgroup", "/a/e2"],
            &["--wall-level", "x", "--wall-cgroup", "/a/e2"],
            &["--wall-level", "2", "--wall-cgroup", "a/e2"],
            &["--wall-level", "2", "--wall-cgroup", "/a\"/e2"],
            &["--wall-level", "3", "--wall-cgroup", "/a/../e2"],
        ] {
            assert!(Attach::parse(&with(bad)).is_err(), "{bad:?}");
        }
    }

    /// `--probe` and `--seal` take nft and, the probe, the wall it tries.
    #[test]
    fn the_probes_and_the_seals_command_lines_go_there_and_back() {
        let walled = Walled {
            nft: PathBuf::from("/x/nft"),
            wall: Some(Wall {
                level: 2,
                cgroup: "/u/e1".to_owned(),
            }),
        };
        assert_eq!(Walled::parse(&walled.args()), Ok(walled.clone()));
        let bare = Walled {
            wall: None,
            ..walled
        };
        assert_eq!(Walled::parse(&bare.args()), Ok(bare));
        let args = |a: &[&str]| a.iter().map(OsString::from).collect::<Vec<_>>();
        for bad in [
            &[][..],
            &["--nft", "nft"],
            &["--nft", "/x/nft", "--nft", "/y/nft"],
            &["--nft", "/x/nft", "--wall-level", "2"],
            &["--nft", "/x/nft", "--other", "1"],
            &["--nft"],
        ] {
            assert!(Walled::parse(&args(bad)).is_err(), "{bad:?}");
        }
    }

    /// The probe's table is made and deleted in one transaction, with the
    /// wall's rule on the output hook.
    #[test]
    fn the_probe_leaves_nothing_behind() {
        let text = probe_ruleset(&Wall {
            level: 6,
            cgroup: "/user.slice/u/x/app.slice/vpn-zone-container@w.service/e1".to_owned(),
        });
        assert!(text.contains(
            "socket cgroupv2 level 6 \"user.slice/u/x/app.slice/vpn-zone-container@w.service/e1\" \
             accept"
        ));
        assert!(text.contains("hook output"), "{text}");
        assert!(
            text.trim_end().ends_with("delete table inet vzprobe"),
            "{text}"
        );
    }
}
