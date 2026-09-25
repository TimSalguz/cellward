//! `pulse-filter` — the PulseAudio socket a zone gets (review 2026-09-25).
//!
//! **Why.** Every zone, the hermetic and the `offline` ones too, got the host's
//! `pulse/native`: the sound server's control socket, where a client may do
//! more than play and record. `LOAD_MODULE` with `module-tunnel-sink`,
//! `module-rtp-send` or `module-native-protocol-tcp` makes the HOST's sound
//! server connect out, or listen, in the host's network — the real address,
//! and data leaving in an audio stream, from a zone that has no network at all.
//! pipewire-pulse allows module loading by default, and a client without
//! `/.flatpak-info` is a client on the host to it.
//!
//! **What.** A filter in front of the socket, started by the zone's holder on
//! the host and bound into the zone as `pulse/native`. It reads the protocol's
//! frames — a 20-byte descriptor (length, channel, offset, flags; big-endian)
//! and a payload — and passes them on, except the commands that change the
//! server rather than use it: `LOAD_MODULE`, `UNLOAD_MODULE` and `KILL_CLIENT`
//! (another program's sound). Those are answered `ERROR` with `ACCESS`, as the
//! server answers a client it does not let.
//!
//! Descriptors (a sound server's shared memory) travel with the frame they
//! came with: on a Unix stream socket a read never runs across the start of a
//! message that carries some, so the frame that begins where such a read
//! began is theirs.
//!
//! Usage: `vpn-zone-core pulse-filter --listen <socket> --upstream <socket>`.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::sys;

/// The descriptor in front of every frame.
const DESCRIPTOR: usize = 20;
/// The largest frame the server accepts (pipewire-pulse `FRAME_SIZE_MAX_ALLOW`).
const FRAME_MAX: usize = 16 * 1024 * 1024;
/// The channel of a command packet; any other is a memory block of a stream.
const COMMAND_CHANNEL: u32 = u32::MAX;
/// `'L'`: the tag of a 32-bit number in a packet.
const TAG_U32: u8 = b'L';

const COMMAND_ERROR: u32 = 0;
const COMMAND_KILL_CLIENT: u32 = 48;
const COMMAND_LOAD_MODULE: u32 = 51;
const COMMAND_UNLOAD_MODULE: u32 = 52;
/// A ring buffer in shared memory for the rest of the connection: after it,
/// commands go through it and past this filter. pipewire-pulse refuses it
/// (`do_error_access`, as `REGISTER_MEMFD_SHMID`); a PulseAudio server offers
/// it — and then the connection is closed rather than filtered no more.
const COMMAND_ENABLE_SRBCHANNEL: u32 = 101;
/// `ERR_ACCESS`.
const ERR_ACCESS: u32 = 1;

const READ_CHUNK: usize = 64 * 1024;
const MAX_FDS_PER_READ: usize = 16;
const MAX_CONNECTIONS: u32 = 128;

/// What the filter was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub listen: PathBuf,
    pub upstream: PathBuf,
}

impl Args {
    pub fn parse(args: &[OsString]) -> Result<Self, String> {
        let mut listen = None;
        let mut upstream = None;
        let mut it = args.iter();
        while let Some(flag) = it.next() {
            let value = it
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| format!("{} needs a value", flag.to_string_lossy()))?;
            match flag.to_str() {
                Some("--listen") => listen = Some(value),
                Some("--upstream") => upstream = Some(value),
                _ => return Err(format!("unknown flag {}", flag.to_string_lossy())),
            }
        }
        Ok(Self {
            listen: listen.ok_or("--listen is required")?,
            upstream: upstream.ok_or("--upstream is required")?,
        })
    }
}

/// The whole length of the frame at the front of `buf`, once its descriptor
/// is there; an error for a length the server would refuse too.
pub fn frame_len(buf: &[u8]) -> io::Result<Option<usize>> {
    if buf.len() < DESCRIPTOR {
        return Ok(None);
    }
    let length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if length == 0 || length > FRAME_MAX {
        return Err(io::Error::other(format!("a frame of {length} bytes")));
    }
    Ok(Some(DESCRIPTOR + length))
}

/// The command and tag of a command packet; `None` for a stream's data.
pub fn command_of(frame: &[u8]) -> Option<(u32, u32)> {
    let channel = u32::from_be_bytes(frame.get(4..8)?.try_into().ok()?);
    if channel != COMMAND_CHANNEL {
        return None;
    }
    let p = frame.get(DESCRIPTOR..)?;
    if p.len() < 10 || p[0] != TAG_U32 || p[5] != TAG_U32 {
        return None;
    }
    Some((
        u32::from_be_bytes(p[1..5].try_into().ok()?),
        u32::from_be_bytes(p[6..10].try_into().ok()?),
    ))
}

/// Why a command is not passed on, if it is not.
pub fn refused(command: u32) -> Option<&'static str> {
    match command {
        COMMAND_LOAD_MODULE => Some("LOAD_MODULE"),
        COMMAND_UNLOAD_MODULE => Some("UNLOAD_MODULE"),
        COMMAND_KILL_CLIENT => Some("KILL_CLIENT"),
        COMMAND_ENABLE_SRBCHANNEL => Some("ENABLE_SRBCHANNEL"),
        _ => None,
    }
}

/// `ERROR` for the command tagged `tag`: access denied.
pub fn error_frame(tag: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(15);
    for value in [COMMAND_ERROR, tag, ERR_ACCESS] {
        payload.push(TAG_U32);
        payload.extend_from_slice(&value.to_be_bytes());
    }
    let mut frame = Vec::with_capacity(DESCRIPTOR + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&COMMAND_CHANNEL.to_be_bytes());
    frame.extend_from_slice(&[0u8; 12]);
    frame.extend_from_slice(&payload);
    frame
}

/// One side's writes, one frame at a time: the frames of the two directions
/// and the filter's own answers never interleave.
struct Out {
    sock: UnixStream,
    lock: Mutex<()>,
}

impl Out {
    fn send(&self, frame: &[u8], fds: &[RawFd]) -> io::Result<()> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let first = frame.len().min(READ_CHUNK);
        sys::send_with_fds(self.sock.as_raw_fd(), &frame[..first], fds)?;
        let mut rest = &frame[first..];
        while !rest.is_empty() {
            let n = rest.len().min(READ_CHUNK);
            sys::send_with_fds(self.sock.as_raw_fd(), &rest[..n], &[])?;
            rest = &rest[n..];
        }
        Ok(())
    }
}

/// Frames from `from` to `to`, whole, each with the descriptors that came with
/// it. With `answer`, a refused command is answered there instead.
fn pump(from: &UnixStream, to: &Out, answer: Option<&Out>) -> io::Result<()> {
    let mut buf = vec![0u8; READ_CHUNK];
    let mut pending: Vec<u8> = Vec::new();
    // Where in the stream each batch of descriptors arrived.
    let mut marks: VecDeque<(u64, Vec<OwnedFd>)> = VecDeque::new();
    let mut read: u64 = 0;
    let mut sent: u64 = 0;
    loop {
        let (n, fds, truncated) =
            sys::recv_into_with_fds(from.as_raw_fd(), &mut buf, MAX_FDS_PER_READ)?;
        if truncated {
            return Err(io::Error::other("descriptors were cut off"));
        }
        if n == 0 {
            return Ok(());
        }
        if !fds.is_empty() {
            marks.push_back((read, fds));
        }
        read += n as u64;
        pending.extend_from_slice(&buf[..n]);
        while let Some(len) = frame_len(&pending)? {
            if pending.len() < len {
                break;
            }
            let frame: Vec<u8> = pending.drain(..len).collect();
            let start = sent;
            sent += len as u64;
            let mut carried: Vec<OwnedFd> = Vec::new();
            while let Some((at, _)) = marks.front() {
                if *at > start {
                    break;
                }
                if *at < start {
                    return Err(io::Error::other("descriptors in the middle of a frame"));
                }
                carried = marks.pop_front().map(|(_, f)| f).unwrap_or_default();
            }
            if answer.is_none()
                && command_of(&frame).is_some_and(|(c, _)| c == COMMAND_ENABLE_SRBCHANNEL)
            {
                return Err(io::Error::other(
                    "the sound server offers a shared ring buffer, which would carry commands \
                     past this filter — the connection is closed",
                ));
            }
            if let (Some(answer), Some((command, tag))) = (answer, command_of(&frame)) {
                if let Some(what) = refused(command) {
                    eprintln!("pulse-filter: {what} refused");
                    answer.send(&error_frame(tag), &[])?;
                    continue;
                }
            }
            let raw: Vec<RawFd> = carried.iter().map(AsRawFd::as_raw_fd).collect();
            to.send(&frame, &raw)?;
        }
    }
}

fn serve(client: UnixStream, upstream: &PathBuf) -> io::Result<()> {
    let server = UnixStream::connect(upstream)?;
    let to_client = Arc::new(Out {
        sock: client.try_clone()?,
        lock: Mutex::new(()),
    });
    let to_server = Out {
        sock: server.try_clone()?,
        lock: Mutex::new(()),
    };
    let down = {
        let to_client = Arc::clone(&to_client);
        let server = server.try_clone()?;
        thread::spawn(move || {
            let _ = pump(&server, &to_client, None);
            let _ = to_client.sock.shutdown(std::net::Shutdown::Both);
            let _ = server.shutdown(std::net::Shutdown::Both);
        })
    };
    let result = pump(&client, &to_server, Some(&to_client));
    let _ = client.shutdown(std::net::Shutdown::Both);
    let _ = server.shutdown(std::net::Shutdown::Both);
    let _ = down.join();
    result
}

/// Serve until the holder that started us goes.
pub fn run(args: &Args) -> u8 {
    // SAFETY: prctl with these arguments takes no pointers.
    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
    let _ = fs::remove_file(&args.listen);
    let listener = match UnixListener::bind(&args.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "pulse-filter: cannot listen on {}: {e}",
                args.listen.display()
            );
            return 1;
        }
    };
    let _ = fs::set_permissions(&args.listen, fs::Permissions::from_mode(0o600));
    let connections = Arc::new(AtomicU32::new(0));
    for client in listener.incoming() {
        let Ok(client) = client else {
            continue;
        };
        if connections.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
            eprintln!("pulse-filter: too many connections — refused");
            continue;
        }
        connections.fetch_add(1, Ordering::SeqCst);
        let upstream = args.upstream.clone();
        let connections = Arc::clone(&connections);
        thread::spawn(move || {
            if let Err(e) = serve(client, &upstream) {
                if !matches!(
                    e.kind(),
                    io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                ) {
                    eprintln!("pulse-filter: {e}");
                }
            }
            connections.fetch_sub(1, Ordering::SeqCst);
        });
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(cmd: u32, tag: u32) -> Vec<u8> {
        let mut payload = vec![TAG_U32];
        payload.extend_from_slice(&cmd.to_be_bytes());
        payload.push(TAG_U32);
        payload.extend_from_slice(&tag.to_be_bytes());
        payload.push(b't');
        payload.extend_from_slice(b"module-tunnel-sink\0");
        let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&COMMAND_CHANNEL.to_be_bytes());
        frame.extend_from_slice(&[0u8; 12]);
        frame.extend_from_slice(&payload);
        frame
    }

    #[test]
    fn a_frame_is_read_the_way_the_server_reads_it() {
        let f = command(COMMAND_LOAD_MODULE, 7);
        assert_eq!(frame_len(&f[..10]).unwrap(), None);
        assert_eq!(frame_len(&f).unwrap(), Some(f.len()));
        assert_eq!(command_of(&f), Some((COMMAND_LOAD_MODULE, 7)));
        // A stream's data is not a command.
        let mut data = f.clone();
        data[4..8].copy_from_slice(&3u32.to_be_bytes());
        assert_eq!(command_of(&data), None);
        // A length the server refuses is an error, not a wait.
        let mut huge = f.clone();
        huge[0..4].copy_from_slice(&(FRAME_MAX as u32 + 1).to_be_bytes());
        assert!(frame_len(&huge).is_err());
        let mut zero = f;
        zero[0..4].copy_from_slice(&0u32.to_be_bytes());
        assert!(frame_len(&zero).is_err());
    }

    #[test]
    fn module_loading_is_refused_and_answered_as_the_server_would() {
        for cmd in [
            COMMAND_LOAD_MODULE,
            COMMAND_UNLOAD_MODULE,
            COMMAND_KILL_CLIENT,
            COMMAND_ENABLE_SRBCHANNEL,
        ] {
            assert!(refused(cmd).is_some(), "{cmd}");
        }
        for cmd in [2, 3, 8, 20, 35, 44, 87] {
            assert!(refused(cmd).is_none(), "{cmd}");
        }
        let e = error_frame(9);
        assert_eq!(frame_len(&e).unwrap(), Some(e.len()));
        assert_eq!(command_of(&e), Some((COMMAND_ERROR, 9)));
        assert_eq!(&e[e.len() - 4..], &ERR_ACCESS.to_be_bytes());
    }

    /// A real conversation through the filter: a harmless command passes, a
    /// module load is answered by the filter and never reaches the server.
    #[test]
    fn only_harmless_commands_reach_the_server() {
        let dir = std::env::temp_dir().join(format!("vz-pulse-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let upstream = dir.join("server");
        let server = UnixListener::bind(&upstream).unwrap();
        let (client, filter_side) = UnixStream::pair().unwrap();
        let path = upstream.clone();
        thread::spawn(move || {
            let _ = serve(filter_side, &path);
        });
        let (mut seen, _) = server.accept().unwrap();
        use std::io::{Read, Write};
        let mut c = client;
        c.write_all(&command(COMMAND_LOAD_MODULE, 1)).unwrap();
        c.write_all(&command(20, 2)).unwrap();
        // The client hears ACCESS for the first…
        let mut answer = vec![0u8; DESCRIPTOR + 15];
        c.read_exact(&mut answer).unwrap();
        assert_eq!(command_of(&answer), Some((COMMAND_ERROR, 1)));
        // …and the server sees only the second.
        let expected = command(20, 2);
        let mut got = vec![0u8; expected.len()];
        seen.read_exact(&mut got).unwrap();
        assert_eq!(command_of(&got), Some((20, 2)));
        let _ = fs::remove_dir_all(&dir);
    }
}
