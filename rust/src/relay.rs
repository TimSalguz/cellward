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

use std::ffi::OsString;
use std::fmt;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

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
            tap_full = !deliver(tap, &down, &mut start, end)?;
            if !open {
                return Ok(End::StreamClosed);
            }
        }
        if tap_full && at_tap & (libc::POLLOUT | gone) != 0 {
            tap_full = !deliver(tap, &down, &mut start, end)?;
        }
        if tap_open && at_tap & (libc::POLLIN | gone) != 0 {
            // Not reading it, and it hung up: nothing more comes from it.
            tap_open = read_tap && fill_up(tap, &mut frame, &mut up, up_sent)?;
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
fn deliver(tap: RawFd, buf: &[u8], start: &mut usize, end: usize) -> io::Result<bool> {
    while let Some(len) = decode(&buf[*start..end])? {
        let from = *start + LEN_BYTES;
        match write_some(tap, &buf[from..from + len], false)? {
            None => return Ok(false),
            Some(n) if n == len => *start = from + len,
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
fn fill_up(tap: RawFd, frame: &mut [u8], up: &mut Vec<u8>, sent: usize) -> io::Result<bool> {
    while up.len() - sent < WINDOW {
        match read_some(tap, frame)? {
            // A read that filled the buffer was longer than any frame, and
            // is refused as one.
            Got::Bytes(n) => encode(&frame[..n], up)?,
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

/// `vpn-zone-core frame-relay --tap-fd N --stream-fd M`: confine itself,
/// then [`pump`] between the two descriptors it inherited until either
/// ends. 0 when one side ended, 1 on an error, 2 on a bad command line.
pub fn main(args: &[OsString]) -> u8 {
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
}
