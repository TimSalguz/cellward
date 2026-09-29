//! `camera-serve` — a camera that is black until the person allows the real
//! one (`docs/PERMISSIONS.md` §3; the owner, 2026-09-29: «систему нагружать
//! не хочется… пустое чёрное окно не должно нагружать ЦП… опциональным… если
//! придумаешь максимально лёгкий режим — давай»). Stage 0: the device alone,
//! seen to work where it has to — a FUSE file in a user namespace that
//! programs take for a V4L2 camera (`tests/vm-camera.nix`).
//!
//! **What it is.** A FUSE filesystem of `video0`-like regular files: a user
//! namespace may mount FUSE (Linux 4.18), not make device nodes. A program
//! opens one as a camera, and its V4L2 ioctls come here as `FUSE_IOCTL` —
//! the kernel copies each one's struct in and out by the size its number
//! encodes (restricted ioctls, `fs/fuse/ioctl.c`), which is how V4L2
//! numbers them. Buffers are ranges of the file that the program maps
//! (`mmap` of the page cache): black in every byte from the first read
//! (YUYV: Y 16, U and V 128), and never written again — a frame is a buffer
//! marked done; no byte moves.
//!
//! **What it costs.** Nothing while no program streams: the server sleeps
//! in `poll(2)`. Streaming, one frame every slowest listed interval
//! ([`INTERVALS`]: 5 a second — above the one a second Chromium waits for
//! before it gives a camera up), a few FUSE round trips each; the program's
//! own work on a frame is the most of it, and so it gets few.
//!
//! **Given to a launch** (a container's camera `black` or `ask`,
//! [`Mode`]): its supervisor (`wl-sandbox`, on the host) starts this server
//! beside itself with one end of a socket pair (`--from`); the launch's
//! `profile-run` opens `/dev/fuse` in the instance's user namespace — the
//! kernel mounts a connection only in the user namespace it was opened in —,
//! mounts it in the launch's mount namespace, sends the connection over the
//! socket and binds its file onto `/dev/video0`
//! (`profile::give_black_camera`). The server is out of the program's
//! reach — the host's pid namespace — and, the connection in hand, in
//! namespaces of its own with an empty root: it keeps nothing of the host's
//! but the connection.
//!
//! **Fail-closed.** What this does not know is refused: buffers other than
//! MMAP, a 32-bit program's ioctls (other sizes, other numbers), controls,
//! any ioctl not listed ([`ENOTTY`]). The server gone, every call on the
//! file fails (the kernel says `ENOTCONN`): no camera, never the real one.
//! Every struct is read at fixed offsets, bounds-checked; nothing in what a
//! program sends is a length or a pointer this follows.

use std::collections::{HashMap, VecDeque};
use std::ffi::OsString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

// --- THE SETTING ------------------------------------------------------------

/// How a container's programs see the host's cameras (`docs/PERMISSIONS.md`
/// §11.15, step 4): a container's own word, else the template's, else
/// [`Mode::DEFAULT`] — asked (the owner, 2026-09-29, once the question was
/// there; the black camera stays optional: `no` gives none, nothing spent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// No camera at all.
    No,
    /// A black camera ([`Server`]), never the real one.
    Black,
    /// A black camera until the person allows the real one: asked when the
    /// program starts streaming (`crate::camask`), the real frames then in
    /// the same stream.
    Ask,
    /// The host's real cameras, bound in (`profile::give_capture`).
    Yes,
}

impl Mode {
    /// Where nobody said: asked, black until allowed — given only where the
    /// host has a camera to ask about ([`Mode::given`]).
    pub const DEFAULT: Self = Self::Ask;

    /// The mode a launch gets on a host with a camera or not
    /// (`host_has_camera`): `ask` on one with none is none — nothing to
    /// ask about, and a program is not shown a camera that is not there;
    /// `black`, said, is given all the same.
    pub fn given(self, host_has_camera: bool) -> Self {
        match self {
            Self::Ask if !host_has_camera => Self::No,
            other => other,
        }
    }

    /// A setting's word: `no|black|ask|yes`, and `on|off|true|false` — a
    /// camera's flag of before — as `yes` and `no`.
    pub fn parse(word: &str) -> Option<Self> {
        match word.trim() {
            "no" | "off" | "false" => Some(Self::No),
            "black" => Some(Self::Black),
            "ask" => Some(Self::Ask),
            "yes" | "on" | "true" => Some(Self::Yes),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::No => "no",
            Self::Black => "black",
            Self::Ask => "ask",
            Self::Yes => "yes",
        }
    }

    /// The word a record keeps: `true`/`false` for the two a camera's flag
    /// had — a build of before reads them, and `black` or `ask` as off, the
    /// closed way.
    pub fn record_word(self) -> &'static str {
        match self {
            Self::No => "false",
            Self::Yes => "true",
            other => other.as_str(),
        }
    }

    /// A black camera is served for it.
    pub fn black(self) -> bool {
        matches!(self, Self::Black | Self::Ask)
    }
}

/// Whether the host has a camera's node at all (`/dev/video<N>`): what a
/// camera `ask` is given by ([`Mode::given`]). Plugged in later: seen by the
/// next launch, as the real ones are.
pub fn host_has_camera() -> bool {
    std::fs::read_dir("/dev").is_ok_and(|entries| {
        entries.flatten().any(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.strip_prefix("video")
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        })
    })
}

// --- THE DEVICE -------------------------------------------------------------

/// `V4L2_PIX_FMT_YUYV`: every UVC camera has it, every program takes it.
pub const YUYV: u32 = u32::from_le_bytes(*b"YUYV");
/// The sizes it offers, logical to the program: width, height.
pub const SIZES: [(u32, u32); 2] = [(640, 480), (1280, 720)];
/// The frame intervals it lists, seconds as fractions, fastest first. Black
/// frames come at the last, the slowest: a program asked for 30 gets 5,
/// which every one takes (a camera's rate is its own to keep).
pub const INTERVALS: [(u32, u32); 3] = [(1, 30), (1, 15), (1, 5)];
/// The most buffers a program gets.
pub const MAX_BUFFERS: u32 = 8;
const PAGE: u64 = 4096;
/// Each buffer's room in the file: the largest frame, in whole pages.
pub const BUFFER_ROOM: u64 = (1280u64 * 720 * 2).div_ceil(PAGE) * PAGE;
/// The file's size: room for every buffer. A mapping past the end of a
/// file is a SIGBUS; within it, pages of black.
pub const FILE_SIZE: u64 = BUFFER_ROOM * MAX_BUFFERS as u64;

// V4L2's numbers (`linux/videodev2.h`).
const BUF_TYPE_CAPTURE: u32 = 1;
const MEMORY_MMAP: u32 = 1;
const FIELD_NONE: u32 = 1;
const COLORSPACE_SRGB: u32 = 8;
const CAP_VIDEO_CAPTURE: u32 = 0x0000_0001;
const CAP_STREAMING: u32 = 0x0400_0000;
const CAP_DEVICE_CAPS: u32 = 0x8000_0000;
const CAP_TIMEPERFRAME: u32 = 0x1000;
const BUF_FLAG_QUEUED: u32 = 0x0002;
const BUF_FLAG_DONE: u32 = 0x0004;
const BUF_FLAG_TIMESTAMP_MONOTONIC: u32 = 0x2000;
const BUF_CAP_SUPPORTS_MMAP: u32 = 1;
const INPUT_TYPE_CAMERA: u32 = 2;
const DISCRETE: u32 = 1;

const fn ioc(dir: u32, nr: u32, size: u32) -> u32 {
    (dir << 30) | (size << 16) | ((b'V' as u32) << 8) | nr
}
const R: u32 = 2;
const W: u32 = 1;
const RW: u32 = R | W;

/// The ioctls answered, by their numbers on a 64-bit program; sizes of the
/// structs as they are there.
pub mod vidioc {
    use super::{ioc, R, RW, W};
    pub const QUERYCAP: u32 = ioc(R, 0, 104);
    pub const ENUM_FMT: u32 = ioc(RW, 2, 64);
    pub const G_FMT: u32 = ioc(RW, 4, 208);
    pub const S_FMT: u32 = ioc(RW, 5, 208);
    pub const REQBUFS: u32 = ioc(RW, 8, 20);
    pub const QUERYBUF: u32 = ioc(RW, 9, 88);
    pub const QBUF: u32 = ioc(RW, 15, 88);
    pub const DQBUF: u32 = ioc(RW, 17, 88);
    pub const STREAMON: u32 = ioc(W, 18, 4);
    pub const STREAMOFF: u32 = ioc(W, 19, 4);
    pub const G_PARM: u32 = ioc(RW, 21, 204);
    pub const S_PARM: u32 = ioc(RW, 22, 204);
    pub const G_CTRL: u32 = ioc(RW, 27, 8);
    pub const S_CTRL: u32 = ioc(RW, 28, 8);
    pub const ENUMINPUT: u32 = ioc(RW, 26, 80);
    pub const QUERYCTRL: u32 = ioc(RW, 36, 68);
    pub const G_INPUT: u32 = ioc(R, 38, 4);
    pub const S_INPUT: u32 = ioc(RW, 39, 4);
    pub const TRY_FMT: u32 = ioc(RW, 64, 208);
    pub const ENUM_FRAMESIZES: u32 = ioc(RW, 74, 44);
    pub const ENUM_FRAMEINTERVALS: u32 = ioc(RW, 75, 52);
    pub const QUERY_EXT_CTRL: u32 = ioc(RW, 103, 232);
}

const EINVAL: i32 = libc::EINVAL;
const EBUSY: i32 = libc::EBUSY;
const EAGAIN: i32 = libc::EAGAIN;
/// What an ioctl this does not know gets: "not a device of this kind".
const ENOTTY: i32 = libc::ENOTTY;

/// A monotonic time: seconds and microseconds, as a V4L2 buffer has it.
pub type Stamp = (i64, i64);

/// Where a buffer is: the program's, queued for a frame, or holding one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    Program,
    Queued,
    Done,
}

/// A frame done: the buffer, its number, when.
#[derive(Debug, Clone, Copy)]
struct Frame {
    index: u32,
    sequence: u32,
    at: Stamp,
}

/// The buffers of the one open file that asked for them.
#[derive(Debug)]
struct Stream {
    owner: u64,
    held: Vec<Held>,
    queued: VecDeque<u32>,
    done: VecDeque<Frame>,
    streaming: bool,
    sequence: u32,
}

/// One camera: its format now, and its buffers.
#[derive(Debug)]
struct Camera {
    width: u32,
    height: u32,
    interval: (u32, u32),
    stream: Option<Stream>,
}

impl Camera {
    fn new() -> Self {
        Self {
            width: SIZES[0].0,
            height: SIZES[0].1,
            interval: INTERVALS[0],
            stream: None,
        }
    }

    fn size_image(&self) -> u32 {
        self.width * self.height * 2
    }
}

/// What an ioctl comes to: the struct back, an error, or a wait for a frame
/// (a blocking `DQBUF`).
#[derive(Debug, PartialEq, Eq)]
enum Answer {
    Struct(Vec<u8>),
    Fail(i32),
    Wait,
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .map_or(0, |s| u32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8).map_or(0, |s| {
        u64::from_ne_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
    })
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    if let Some(s) = b.get_mut(at..at + 4) {
        s.copy_from_slice(&v.to_ne_bytes());
    }
}

fn put64(b: &mut [u8], at: usize, v: u64) {
    if let Some(s) = b.get_mut(at..at + 8) {
        s.copy_from_slice(&v.to_ne_bytes());
    }
}

/// `text` into `b[at..at + len]`, NUL-padded, cut to leave one NUL.
fn put_str(b: &mut [u8], at: usize, len: usize, text: &str) {
    if let Some(s) = b.get_mut(at..at + len) {
        s.fill(0);
        let n = text.len().min(len.saturating_sub(1));
        s[..n].copy_from_slice(&text.as_bytes()[..n]);
    }
}

/// The byte `offset` of the file: black YUYV (Y 16, U and V 128).
pub fn black_at(offset: u64) -> u8 {
    if offset & 1 == 0 {
        0x10
    } else {
        0x80
    }
}

/// The size of a program's ask, as the camera has them: the largest that
/// fits in it, else the smallest.
fn fit(width: u32, height: u32) -> (u32, u32) {
    SIZES
        .iter()
        .rev()
        .find(|&&(w, h)| w <= width && h <= height)
        .copied()
        .unwrap_or(SIZES[0])
}

/// The listed interval nearest `num/den` (seconds).
fn nearest_interval(num: u32, den: u32) -> (u32, u32) {
    if num == 0 || den == 0 {
        return INTERVALS[0];
    }
    let want = f64::from(num) / f64::from(den);
    INTERVALS
        .iter()
        .copied()
        .min_by(|a, b| {
            let da = (f64::from(a.0) / f64::from(a.1) - want).abs();
            let db = (f64::from(b.0) / f64::from(b.1) - want).abs();
            da.total_cmp(&db)
        })
        .unwrap_or(INTERVALS[0])
}

/// How often a black frame comes: the slowest listed interval, in
/// nanoseconds.
pub fn black_interval_ns() -> u64 {
    let (num, den) = INTERVALS[INTERVALS.len() - 1];
    u64::from(num) * 1_000_000_000 / u64::from(den.max(1))
}

impl Camera {
    /// `v4l2_format` of the format now (`G_FMT`), over what was asked.
    fn format(&self, s: &mut [u8]) {
        put32(s, 0, BUF_TYPE_CAPTURE);
        put32(s, 8, self.width);
        put32(s, 12, self.height);
        put32(s, 16, YUYV);
        put32(s, 20, FIELD_NONE);
        put32(s, 24, self.width * 2);
        put32(s, 28, self.size_image());
        put32(s, 32, COLORSPACE_SRGB);
        for at in (36..56).step_by(4) {
            put32(s, at, 0);
        }
    }

    /// `v4l2_buffer` of buffer `index`: where it is in the file, how long,
    /// what it holds.
    fn buffer(&self, s: &mut [u8], index: u32, held: Held, frame: Option<&Frame>) {
        s.fill(0);
        put32(s, 0, index);
        put32(s, 4, BUF_TYPE_CAPTURE);
        let flags = BUF_FLAG_TIMESTAMP_MONOTONIC
            | match held {
                Held::Program => 0,
                Held::Queued => BUF_FLAG_QUEUED,
                Held::Done => BUF_FLAG_DONE,
            };
        put32(s, 12, flags);
        put32(s, 16, FIELD_NONE);
        if let Some(frame) = frame {
            put32(s, 8, self.size_image());
            put64(s, 24, frame.at.0 as u64);
            put64(s, 32, frame.at.1 as u64);
            put32(s, 56, frame.sequence);
        }
        put32(s, 60, MEMORY_MMAP);
        put32(s, 64, (u64::from(index) * BUFFER_ROOM) as u32);
        put32(s, 72, self.size_image());
    }
}

// --- FUSE -------------------------------------------------------------------

/// The FUSE protocol this speaks: 7.31 — nothing of the later ones is used.
const FUSE_MAJOR: u32 = 7;
const FUSE_MINOR: u32 = 31;
/// The root directory's node.
const ROOT: u64 = 1;
const IN_HEADER: usize = 40;
const OUT_HEADER: usize = 16;
/// The most a write from the kernel carries (`max_write`), and so the read
/// buffer: that and the headers.
const MAX_WRITE: u32 = 128 * 1024;
const READ_BUFFER: usize = MAX_WRITE as usize + 4096;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const DT_DIR: u32 = 4;
const DT_REG: u32 = 8;
/// `FUSE_NOTIFY_POLL`: a poll handle has something to report.
const NOTIFY_POLL: i32 = 1;
const POLL_SCHEDULE_NOTIFY: u32 = 1;
/// `FOPEN_KEEP_CACHE`: the pages of black stay between opens.
const KEEP_CACHE: u32 = 2;
/// How long the kernel may keep what it was told (seconds): nothing here
/// changes.
const VALID: u64 = 3600;

mod op {
    pub const LOOKUP: u32 = 1;
    pub const FORGET: u32 = 2;
    pub const GETATTR: u32 = 3;
    pub const SETATTR: u32 = 4;
    pub const OPEN: u32 = 14;
    pub const READ: u32 = 15;
    pub const WRITE: u32 = 16;
    pub const STATFS: u32 = 17;
    pub const RELEASE: u32 = 18;
    pub const FSYNC: u32 = 20;
    pub const FLUSH: u32 = 25;
    pub const INIT: u32 = 26;
    pub const OPENDIR: u32 = 27;
    pub const READDIR: u32 = 28;
    pub const RELEASEDIR: u32 = 29;
    pub const ACCESS: u32 = 34;
    pub const INTERRUPT: u32 = 36;
    pub const DESTROY: u32 = 38;
    pub const IOCTL: u32 = 39;
    pub const POLL: u32 = 40;
    pub const BATCH_FORGET: u32 = 42;
}

/// A reply (or a notice, `unique` 0) to the kernel: the header and `body`.
fn message(unique: u64, error: i32, body: &[u8]) -> Vec<u8> {
    let len = (OUT_HEADER + body.len()) as u32;
    let mut m = Vec::with_capacity(len as usize);
    m.extend_from_slice(&len.to_ne_bytes());
    m.extend_from_slice(&error.to_ne_bytes());
    m.extend_from_slice(&unique.to_ne_bytes());
    m.extend_from_slice(body);
    m
}

fn reply(unique: u64, body: &[u8]) -> Vec<u8> {
    message(unique, 0, body)
}

fn failed(unique: u64, errno: i32) -> Vec<u8> {
    message(unique, -errno, &[])
}

/// A `DQBUF` owed its frame: the request, the open file, the struct's size.
#[derive(Debug, Clone, Copy)]
struct Owed {
    unique: u64,
    fh: u64,
    size: usize,
}

/// An open file: the camera it is, and whether its calls may not wait.
#[derive(Debug, Clone, Copy)]
struct Open {
    node: u64,
    nonblocking: bool,
}

/// The server's state: the cameras (node 2 on), the files open on them,
/// the frames owed, the poll handles to wake.
pub struct Server {
    names: Vec<String>,
    cameras: Vec<Camera>,
    uid: u32,
    gid: u32,
    opens: HashMap<u64, Open>,
    next_fh: u64,
    owed: Vec<Owed>,
    polls: HashMap<u64, u64>,
    /// `FUSE_DESTROY` came: the filesystem is going.
    pub destroyed: bool,
}

impl Server {
    /// Cameras named `names` (each a file of the root), owned by `uid` and
    /// `gid`.
    pub fn new(names: Vec<String>, uid: u32, gid: u32) -> Self {
        let cameras = names.iter().map(|_| Camera::new()).collect();
        Self {
            names,
            cameras,
            uid,
            gid,
            opens: HashMap::new(),
            next_fh: 1,
            owed: Vec::new(),
            polls: HashMap::new(),
            destroyed: false,
        }
    }

    /// Whether a camera streams: the timer runs only then.
    pub fn streaming(&self) -> bool {
        self.cameras
            .iter()
            .any(|c| c.stream.as_ref().is_some_and(|s| s.streaming))
    }

    fn camera_of(&self, node: u64) -> Option<usize> {
        let i = usize::try_from(node.checked_sub(2)?).ok()?;
        (i < self.cameras.len()).then_some(i)
    }

    /// `fuse_attr` of `node`.
    fn attr(&self, node: u64) -> Option<[u8; 88]> {
        let (mode, nlink, size) = if node == ROOT {
            (S_IFDIR | 0o755, 2, 0)
        } else if self.camera_of(node).is_some() {
            (S_IFREG | 0o660, 1, FILE_SIZE)
        } else {
            return None;
        };
        let mut a = [0u8; 88];
        put64(&mut a, 0, node);
        put64(&mut a, 8, size);
        put64(&mut a, 16, size.div_ceil(512));
        put32(&mut a, 60, mode);
        put32(&mut a, 64, nlink);
        put32(&mut a, 68, self.uid);
        put32(&mut a, 72, self.gid);
        put32(&mut a, 80, PAGE as u32);
        Some(a)
    }

    /// One request from the kernel; what goes back to it (replies, and
    /// notices), in order.
    pub fn handle(&mut self, request: &[u8]) -> Vec<Vec<u8>> {
        if request.len() < IN_HEADER {
            return Vec::new();
        }
        let len = (u32_at(request, 0) as usize).min(request.len());
        let opcode = u32_at(request, 4);
        let unique = u64_at(request, 8);
        let node = u64_at(request, 16);
        let body = request.get(IN_HEADER..len).unwrap_or(&[]);
        match opcode {
            op::INIT => {
                let minor = u32_at(body, 4);
                let readahead = u32_at(body, 8);
                let mut out = [0u8; 64];
                put32(&mut out, 0, FUSE_MAJOR);
                put32(&mut out, 4, minor.min(FUSE_MINOR));
                put32(&mut out, 8, readahead);
                // max_background, congestion_threshold.
                out[16..18].copy_from_slice(&16u16.to_ne_bytes());
                out[18..20].copy_from_slice(&12u16.to_ne_bytes());
                put32(&mut out, 20, MAX_WRITE);
                put32(&mut out, 24, 1);
                vec![reply(unique, &out)]
            }
            op::DESTROY => {
                self.destroyed = true;
                vec![reply(unique, &[])]
            }
            op::FORGET | op::BATCH_FORGET => Vec::new(),
            op::LOOKUP => {
                let name = body.split(|&b| b == 0).next().unwrap_or(&[]);
                let found = (node == ROOT)
                    .then(|| self.names.iter().position(|n| n.as_bytes() == name))
                    .flatten();
                match found.and_then(|i| {
                    let node = 2 + i as u64;
                    self.attr(node).map(|a| (node, a))
                }) {
                    Some((node, a)) => {
                        let mut out = [0u8; 128];
                        put64(&mut out, 0, node);
                        put64(&mut out, 8, 1);
                        put64(&mut out, 16, VALID);
                        put64(&mut out, 24, VALID);
                        out[40..].copy_from_slice(&a);
                        vec![reply(unique, &out)]
                    }
                    None => vec![failed(unique, libc::ENOENT)],
                }
            }
            op::GETATTR | op::SETATTR => match self.attr(node) {
                // A change of anything is refused; its attributes are
                // what they are.
                Some(_) if opcode == op::SETATTR => vec![failed(unique, libc::EPERM)],
                Some(a) => {
                    let mut out = [0u8; 104];
                    put64(&mut out, 0, VALID);
                    out[16..].copy_from_slice(&a);
                    vec![reply(unique, &out)]
                }
                None => vec![failed(unique, libc::ENOENT)],
            },
            op::ACCESS | op::FLUSH | op::FSYNC => vec![reply(unique, &[])],
            op::STATFS => {
                let mut out = [0u8; 80];
                put32(&mut out, 40, PAGE as u32);
                put32(&mut out, 44, 255);
                put32(&mut out, 48, PAGE as u32);
                vec![reply(unique, &out)]
            }
            op::OPENDIR => {
                if node != ROOT {
                    return vec![failed(unique, libc::ENOTDIR)];
                }
                vec![reply(unique, &[0u8; 16])]
            }
            op::RELEASEDIR => vec![reply(unique, &[])],
            op::READDIR => {
                let offset = u64_at(body, 8);
                let size = u32_at(body, 16) as usize;
                vec![reply(unique, &self.entries(offset, size))]
            }
            op::OPEN => {
                if self.camera_of(node).is_none() {
                    return vec![failed(unique, libc::EISDIR)];
                }
                let flags = u32_at(body, 0);
                let fh = self.next_fh;
                self.next_fh += 1;
                self.opens.insert(
                    fh,
                    Open {
                        node,
                        nonblocking: flags & libc::O_NONBLOCK as u32 != 0,
                    },
                );
                let mut out = [0u8; 16];
                put64(&mut out, 0, fh);
                put32(&mut out, 8, KEEP_CACHE);
                vec![reply(unique, &out)]
            }
            op::RELEASE => {
                let fh = u64_at(body, 0);
                self.release(fh);
                vec![reply(unique, &[])]
            }
            op::READ => {
                let offset = u64_at(body, 8);
                let size = u64::from(u32_at(body, 16));
                let end = offset.saturating_add(size).min(FILE_SIZE);
                let data: Vec<u8> = (offset.min(end)..end).map(black_at).collect();
                vec![reply(unique, &data)]
            }
            op::WRITE => {
                // The program's own pages, written back: taken and let be —
                // nothing here reads them.
                let mut out = [0u8; 8];
                put32(&mut out, 0, u32_at(body, 16));
                vec![reply(unique, &out)]
            }
            op::INTERRUPT => {
                let gone = u64_at(body, 0);
                match self.owed.iter().position(|o| o.unique == gone) {
                    Some(i) => {
                        self.owed.remove(i);
                        vec![failed(gone, libc::EINTR)]
                    }
                    None => Vec::new(),
                }
            }
            op::POLL => {
                let fh = u64_at(body, 0);
                let kh = u64_at(body, 8);
                let flags = u32_at(body, 16);
                let ready = self.ready(fh);
                if !ready && flags & POLL_SCHEDULE_NOTIFY != 0 {
                    self.polls.insert(fh, kh);
                }
                let revents = if ready {
                    (libc::POLLIN | libc::POLLRDNORM) as u32
                } else {
                    0
                };
                let mut out = [0u8; 8];
                put32(&mut out, 0, revents);
                vec![reply(unique, &out)]
            }
            op::IOCTL => {
                let fh = u64_at(body, 0);
                let cmd = u32_at(body, 12);
                let out_size = u32_at(body, 28) as usize;
                let input = body.get(32..).unwrap_or(&[]);
                match self.ioctl(fh, unique, cmd, input, out_size) {
                    Answer::Struct(s) => vec![reply(unique, &ioctl_out(&s, out_size))],
                    Answer::Fail(errno) => vec![failed(unique, errno)],
                    Answer::Wait => Vec::new(),
                }
            }
            _ => vec![failed(unique, libc::ENOSYS)],
        }
    }

    /// The root's entries from `offset` on, `fuse_dirent`s in `size` bytes.
    fn entries(&self, offset: u64, size: usize) -> Vec<u8> {
        let mut all: Vec<(u64, u32, &str)> = vec![(ROOT, DT_DIR, "."), (ROOT, DT_DIR, "..")];
        for (i, name) in self.names.iter().enumerate() {
            all.push((2 + i as u64, DT_REG, name.as_str()));
        }
        let mut out = Vec::new();
        for (i, (ino, kind, name)) in all.iter().enumerate().skip(offset as usize) {
            let len = 24 + name.len();
            let padded = len.div_ceil(8) * 8;
            if out.len() + padded > size {
                break;
            }
            out.extend_from_slice(&ino.to_ne_bytes());
            out.extend_from_slice(&(i as u64 + 1).to_ne_bytes());
            out.extend_from_slice(&(name.len() as u32).to_ne_bytes());
            out.extend_from_slice(&kind.to_ne_bytes());
            out.extend_from_slice(name.as_bytes());
            out.resize(out.len() + padded - len, 0);
        }
        out
    }

    /// An open file closed: its buffers go, its stream stops.
    fn release(&mut self, fh: u64) {
        if let Some(open) = self.opens.remove(&fh) {
            if let Some(i) = self.camera_of(open.node) {
                let camera = &mut self.cameras[i];
                if camera.stream.as_ref().is_some_and(|s| s.owner == fh) {
                    camera.stream = None;
                }
            }
        }
        self.polls.remove(&fh);
        self.owed.retain(|o| o.fh != fh);
    }

    /// Whether `fh` has a frame to take.
    fn ready(&self, fh: u64) -> bool {
        let Some(i) = self.opens.get(&fh).and_then(|o| self.camera_of(o.node)) else {
            return false;
        };
        self.cameras[i]
            .stream
            .as_ref()
            .is_some_and(|s| s.owner == fh && !s.done.is_empty())
    }

    /// The timer: a black frame into the first queued buffer of every
    /// camera that streams; to a `DQBUF` that waits for it, or a wake to
    /// the poll that does.
    pub fn tick(&mut self, now: Stamp) -> Vec<Vec<u8>> {
        let mut filled = Vec::new();
        for (i, camera) in self.cameras.iter_mut().enumerate() {
            let Some(stream) = camera.stream.as_mut().filter(|s| s.streaming) else {
                continue;
            };
            let sequence = stream.sequence;
            stream.sequence = stream.sequence.wrapping_add(1);
            let Some(index) = stream.queued.pop_front() else {
                continue;
            };
            stream.held[index as usize] = Held::Done;
            stream.done.push_back(Frame {
                index,
                sequence,
                at: now,
            });
            filled.push((i, stream.owner));
        }
        let mut out = Vec::new();
        for (i, owner) in filled {
            out.extend(self.wake(i, owner));
        }
        out
    }

    /// A frame done for `owner`'s stream of camera `i`: to a `DQBUF` that
    /// waits for it, else a wake to its poll.
    fn wake(&mut self, i: usize, owner: u64) -> Vec<Vec<u8>> {
        if let Some(k) = self.owed.iter().position(|o| o.fh == owner) {
            let owed = self.owed.remove(k);
            let camera = &mut self.cameras[i];
            take_frame(camera, owed.size)
                .map(|s| vec![reply(owed.unique, &ioctl_out(&s, owed.size))])
                .unwrap_or_default()
        } else if let Some(kh) = self.polls.remove(&owner) {
            vec![message(0, NOTIFY_POLL, &kh.to_ne_bytes())]
        } else {
            Vec::new()
        }
    }

    /// A frame of the real camera, `data`, into the first queued buffer of
    /// camera `i` — written into the pages of the file the program maps
    /// (`FUSE_NOTIFY_STORE`), no more than the buffer holds —, the buffer
    /// done and the program told as by [`Server::tick`]. With no buffer
    /// queued the frame is dropped, as a camera drops one.
    pub fn deliver(&mut self, i: usize, data: &[u8], now: Stamp) -> Vec<Vec<u8>> {
        let Some(camera) = self.cameras.get_mut(i) else {
            return Vec::new();
        };
        let size = camera.size_image() as usize;
        let Some(stream) = camera.stream.as_mut().filter(|s| s.streaming) else {
            return Vec::new();
        };
        let sequence = stream.sequence;
        stream.sequence = stream.sequence.wrapping_add(1);
        let Some(index) = stream.queued.pop_front() else {
            return Vec::new();
        };
        let mut out = store(
            2 + i as u64,
            u64::from(index) * BUFFER_ROOM,
            &data[..data.len().min(size)],
        );
        stream.held[index as usize] = Held::Done;
        stream.done.push_back(Frame {
            index,
            sequence,
            at: now,
        });
        let owner = stream.owner;
        out.extend(self.wake(i, owner));
        out
    }

    /// Camera `i`'s format while a program streams it: width, height, the
    /// interval it asked for.
    pub fn streaming_format(&self, i: usize) -> Option<(u32, u32, (u32, u32))> {
        self.cameras
            .get(i)
            .filter(|c| c.stream.as_ref().is_some_and(|s| s.streaming))
            .map(|c| (c.width, c.height, c.interval))
    }

    /// A V4L2 ioctl `cmd` on the open file `fh`, its struct `input`.
    fn ioctl(&mut self, fh: u64, unique: u64, cmd: u32, input: &[u8], out_size: usize) -> Answer {
        let Some(open) = self.opens.get(&fh).copied() else {
            return Answer::Fail(libc::EBADF);
        };
        let Some(i) = self.camera_of(open.node) else {
            return Answer::Fail(ENOTTY);
        };
        let size = ((cmd >> 16) & 0x3fff) as usize;
        let reads = (cmd >> 30) & W != 0;
        if reads && input.len() < size {
            return Answer::Fail(EINVAL);
        }
        let mut s = vec![0u8; size];
        if reads {
            s.copy_from_slice(&input[..size]);
        }
        let camera = &mut self.cameras[i];
        let capture = |s: &[u8], at: usize| u32_at(s, at) == BUF_TYPE_CAPTURE;
        match cmd {
            vidioc::QUERYCAP => {
                s.fill(0);
                put_str(&mut s, 0, 16, "cellward");
                put_str(&mut s, 16, 32, "cellward camera");
                put_str(&mut s, 48, 32, "platform:cellward-camera");
                put32(&mut s, 80, 0x0006_0000);
                put32(
                    &mut s,
                    84,
                    CAP_VIDEO_CAPTURE | CAP_STREAMING | CAP_DEVICE_CAPS,
                );
                put32(&mut s, 88, CAP_VIDEO_CAPTURE | CAP_STREAMING);
                Answer::Struct(s)
            }
            vidioc::ENUM_FMT => {
                if !capture(&s, 4) || u32_at(&s, 0) != 0 {
                    return Answer::Fail(EINVAL);
                }
                put32(&mut s, 8, 0);
                put_str(&mut s, 12, 32, "YUYV 4:2:2");
                put32(&mut s, 44, YUYV);
                put32(&mut s, 48, 0);
                s[52..64].fill(0);
                Answer::Struct(s)
            }
            vidioc::G_FMT => {
                if !capture(&s, 0) {
                    return Answer::Fail(EINVAL);
                }
                camera.format(&mut s);
                Answer::Struct(s)
            }
            vidioc::S_FMT | vidioc::TRY_FMT => {
                if !capture(&s, 0) {
                    return Answer::Fail(EINVAL);
                }
                let (w, h) = fit(u32_at(&s, 8), u32_at(&s, 12));
                if cmd == vidioc::S_FMT {
                    if camera.stream.as_ref().is_some_and(|st| !st.held.is_empty()) {
                        return Answer::Fail(EBUSY);
                    }
                    camera.width = w;
                    camera.height = h;
                    camera.format(&mut s);
                } else {
                    let tried = Camera {
                        width: w,
                        height: h,
                        interval: camera.interval,
                        stream: None,
                    };
                    tried.format(&mut s);
                }
                Answer::Struct(s)
            }
            vidioc::REQBUFS => {
                if !capture(&s, 4) || u32_at(&s, 8) != MEMORY_MMAP {
                    return Answer::Fail(EINVAL);
                }
                if let Some(stream) = &camera.stream {
                    if stream.owner != fh && !stream.held.is_empty() {
                        return Answer::Fail(EBUSY);
                    }
                    if stream.streaming {
                        return Answer::Fail(EBUSY);
                    }
                }
                let count = u32_at(&s, 0);
                if count == 0 {
                    camera.stream = None;
                } else {
                    let count = count.clamp(2, MAX_BUFFERS);
                    camera.stream = Some(Stream {
                        owner: fh,
                        held: vec![Held::Program; count as usize],
                        queued: VecDeque::new(),
                        done: VecDeque::new(),
                        streaming: false,
                        sequence: 0,
                    });
                    put32(&mut s, 0, count);
                }
                put32(&mut s, 12, BUF_CAP_SUPPORTS_MMAP);
                s[16..20].fill(0);
                Answer::Struct(s)
            }
            vidioc::QUERYBUF => {
                let index = u32_at(&s, 0);
                let Some(held) = camera
                    .stream
                    .as_ref()
                    .and_then(|st| st.held.get(index as usize).copied())
                else {
                    return Answer::Fail(EINVAL);
                };
                if !capture(&s, 4) {
                    return Answer::Fail(EINVAL);
                }
                camera.buffer(&mut s, index, held, None);
                Answer::Struct(s)
            }
            vidioc::QBUF => {
                let index = u32_at(&s, 0);
                if !capture(&s, 4) || u32_at(&s, 60) != MEMORY_MMAP {
                    return Answer::Fail(EINVAL);
                }
                let Some(stream) = camera.stream.as_mut().filter(|st| st.owner == fh) else {
                    return Answer::Fail(EINVAL);
                };
                match stream.held.get(index as usize) {
                    Some(Held::Program) => {}
                    _ => return Answer::Fail(EINVAL),
                }
                stream.held[index as usize] = Held::Queued;
                stream.queued.push_back(index);
                camera.buffer(&mut s, index, Held::Queued, None);
                Answer::Struct(s)
            }
            vidioc::DQBUF => {
                if !capture(&s, 4) || u32_at(&s, 60) != MEMORY_MMAP {
                    return Answer::Fail(EINVAL);
                }
                let Some(stream) = camera.stream.as_ref().filter(|st| st.owner == fh) else {
                    return Answer::Fail(EINVAL);
                };
                if stream.done.is_empty() {
                    if !stream.streaming {
                        return Answer::Fail(EINVAL);
                    }
                    if open.nonblocking {
                        return Answer::Fail(EAGAIN);
                    }
                    self.owed.push(Owed {
                        unique,
                        fh,
                        size: out_size.min(size),
                    });
                    return Answer::Wait;
                }
                match take_frame(camera, size) {
                    Some(s) => Answer::Struct(s),
                    None => Answer::Fail(EINVAL),
                }
            }
            vidioc::STREAMON | vidioc::STREAMOFF => {
                if !capture(&s, 0) {
                    return Answer::Fail(EINVAL);
                }
                let Some(stream) = camera.stream.as_mut().filter(|st| st.owner == fh) else {
                    return Answer::Fail(EINVAL);
                };
                if cmd == vidioc::STREAMON {
                    stream.streaming = true;
                    return Answer::Struct(Vec::new());
                }
                // Off: every buffer the program's again, a DQBUF that
                // waits refused.
                stream.streaming = false;
                stream.queued.clear();
                stream.done.clear();
                stream.held.fill(Held::Program);
                Answer::Struct(Vec::new())
            }
            vidioc::G_PARM | vidioc::S_PARM => {
                if !capture(&s, 0) {
                    return Answer::Fail(EINVAL);
                }
                if cmd == vidioc::S_PARM {
                    camera.interval = nearest_interval(u32_at(&s, 12), u32_at(&s, 16));
                }
                s[4..].fill(0);
                put32(&mut s, 4, CAP_TIMEPERFRAME);
                put32(&mut s, 12, camera.interval.0);
                put32(&mut s, 16, camera.interval.1);
                Answer::Struct(s)
            }
            vidioc::ENUMINPUT => {
                if u32_at(&s, 0) != 0 {
                    return Answer::Fail(EINVAL);
                }
                s.fill(0);
                put_str(&mut s, 4, 32, "Camera");
                put32(&mut s, 36, INPUT_TYPE_CAMERA);
                Answer::Struct(s)
            }
            vidioc::G_INPUT => Answer::Struct(vec![0; 4]),
            vidioc::S_INPUT => {
                if u32_at(&s, 0) != 0 {
                    return Answer::Fail(EINVAL);
                }
                Answer::Struct(s)
            }
            vidioc::ENUM_FRAMESIZES => {
                let index = u32_at(&s, 0) as usize;
                let Some(&(w, h)) = SIZES.get(index).filter(|_| u32_at(&s, 4) == YUYV) else {
                    return Answer::Fail(EINVAL);
                };
                put32(&mut s, 8, DISCRETE);
                s[12..44].fill(0);
                put32(&mut s, 12, w);
                put32(&mut s, 16, h);
                Answer::Struct(s)
            }
            vidioc::ENUM_FRAMEINTERVALS => {
                let index = u32_at(&s, 0) as usize;
                let asked = (u32_at(&s, 8), u32_at(&s, 12));
                let known = u32_at(&s, 4) == YUYV && SIZES.contains(&asked);
                let Some(&(num, den)) = INTERVALS.get(index).filter(|_| known) else {
                    return Answer::Fail(EINVAL);
                };
                put32(&mut s, 16, DISCRETE);
                s[20..52].fill(0);
                put32(&mut s, 20, num);
                put32(&mut s, 24, den);
                Answer::Struct(s)
            }
            // No controls: none to show, none to change.
            vidioc::QUERYCTRL | vidioc::QUERY_EXT_CTRL | vidioc::G_CTRL | vidioc::S_CTRL => {
                Answer::Fail(EINVAL)
            }
            _ => Answer::Fail(ENOTTY),
        }
    }
}

/// The first frame done of `camera`'s stream, its buffer the program's
/// again: the `v4l2_buffer` of it, `size` bytes.
fn take_frame(camera: &mut Camera, size: usize) -> Option<Vec<u8>> {
    let stream = camera.stream.as_mut()?;
    let frame = stream.done.pop_front()?;
    stream.held[frame.index as usize] = Held::Program;
    let mut s = vec![0u8; size];
    camera.buffer(&mut s, frame.index, Held::Done, Some(&frame));
    Some(s)
}

/// `FUSE_NOTIFY_STORE`: data into the pages of a file the kernel holds.
const NOTIFY_STORE: i32 = 4;
/// The most of a frame one notice carries.
const STORE_CHUNK: usize = 64 * 1024;

/// `data` into the file of `node` at `offset`, in the kernel's pages — the
/// ones a program has mapped, so it reads the frame there: one notice a
/// piece of [`STORE_CHUNK`].
fn store(node: u64, offset: u64, data: &[u8]) -> Vec<Vec<u8>> {
    data.chunks(STORE_CHUNK)
        .enumerate()
        .map(|(k, piece)| {
            let mut body = Vec::with_capacity(24 + piece.len());
            body.extend_from_slice(&node.to_ne_bytes());
            body.extend_from_slice(&(offset + (k * STORE_CHUNK) as u64).to_ne_bytes());
            body.extend_from_slice(&(piece.len() as u32).to_ne_bytes());
            body.extend_from_slice(&0u32.to_ne_bytes());
            body.extend_from_slice(piece);
            message(0, NOTIFY_STORE, &body)
        })
        .collect()
}

/// `fuse_ioctl_out` and the struct after it, `out_size` bytes of it.
fn ioctl_out(s: &[u8], out_size: usize) -> Vec<u8> {
    let mut out = vec![0u8; 16];
    out.extend_from_slice(&s[..s.len().min(out_size)]);
    out
}

// --- THE SERVER -------------------------------------------------------------

/// `vpn-zone-core camera-serve --mount <dir> [--device <name>]…`, or
/// `--from <n>` instead of `--mount`: a FUSE connection someone else opens
/// and mounts — a launch's `profile-run`, in the launch's mount namespace
/// (`profile::give_black_camera`) —, sent over the socket `<n>` once it is
/// mounted, and served then.
#[derive(Debug, PartialEq, Eq)]
pub struct Args {
    pub place: Place,
    pub devices: Vec<String>,
    /// `--ask`: the person asked for the real camera ([`Mode::Ask`],
    /// `crate::camask`), black until then; without it, black for good.
    pub ask: bool,
}

/// Where the cameras are: mounted here, or on a connection sent over a
/// socket.
#[derive(Debug, PartialEq, Eq)]
pub enum Place {
    Mount(PathBuf),
    From(RawFd),
}

impl Args {
    pub fn parse(args: &[OsString]) -> Result<Self, String> {
        let mut mount = None;
        let mut from = None;
        let mut ask = false;
        let mut devices = Vec::new();
        let mut it = args.iter();
        let number = |it: &mut std::slice::Iter<'_, OsString>, what: &str| {
            it.next()
                .and_then(|n| n.to_str())
                .and_then(|n| n.parse::<RawFd>().ok())
                .filter(|&n| n > 2)
                .ok_or_else(|| format!("{what}: a descriptor's number"))
        };
        while let Some(arg) = it.next() {
            match arg.to_str() {
                Some("--mount") => {
                    mount = Some(PathBuf::from(it.next().ok_or("--mount: which directory?")?));
                }
                Some("--from") => from = Some(number(&mut it, "--from")?),
                Some("--ask") => ask = true,
                Some("--device") => {
                    let name = it
                        .next()
                        .and_then(|n| n.to_str())
                        .ok_or("--device: which name?")?;
                    let fits = !name.is_empty()
                        && name.len() <= 32
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
                    if !fits {
                        return Err(format!("--device {name}: a name of letters and digits"));
                    }
                    devices.push(name.to_owned());
                }
                _ => return Err(format!("unknown argument {arg:?}")),
            }
        }
        if devices.is_empty() {
            devices.push("video0".to_owned());
        }
        let place = match (mount, from) {
            (Some(dir), None) => Place::Mount(dir),
            (None, Some(from)) => Place::From(from),
            _ => return Err("--mount <dir>, or --from <n>".to_owned()),
        };
        Ok(Self {
            place,
            devices,
            ask,
        })
    }
}

pub fn run(args: &Args) -> u8 {
    match serve(args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("camera-serve: {e}");
            1
        }
    }
}

fn now() -> Stamp {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes the timespec it is given.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec, ts.tv_nsec / 1000)
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// `/dev/fuse` opened: a connection to mount.
pub fn open_fuse() -> Result<OwnedFd, String> {
    open_fuse_at(std::path::Path::new("/dev/fuse"))
}

/// The FUSE device at `path` opened (the zone's devtmpfs has it where the
/// launch's `/dev` does not): a connection to mount — in the user namespace
/// of this process, the one it is opened in.
pub fn open_fuse_at(path: &std::path::Path) -> Result<OwnedFd, String> {
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| format!("{}: {e}", path.display()))?;
    // SAFETY: a NUL-terminated path; the descriptor is owned below.
    let fd = unsafe { libc::open(name.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(format!(
            "{}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: open has just returned it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The options of a mount of the connection `fuse`: its files are the
/// programs' of `uid` and `gid` alone (no `allow_other`).
pub fn mount_options(fuse: RawFd, uid: u32, gid: u32) -> String {
    format!("fd={fuse},rootmode=40000,user_id={uid},group_id={gid}")
}

/// Mount the connection `fuse` at `dir`: its files a camera's
/// ([`mount_options`]), no set-id, no device, no program run from it.
pub fn mount(fuse: RawFd, dir: &std::path::Path, uid: u32, gid: u32) -> Result<(), String> {
    crate::sys::mount(
        std::ffi::OsStr::new("cellward-camera"),
        dir,
        "fuse",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        &mount_options(fuse, uid, gid),
    )
    .map_err(|e| format!("cannot mount at {}: {e}", dir.display()))
}

/// The kind of file `fd` is (`S_IFCHR`, `S_IFSOCK`, …); `None` where it is
/// no descriptor.
fn kind_of(fd: RawFd) -> Option<libc::mode_t> {
    // SAFETY: fstat of a number that may be no descriptor at all: it fails
    // then, into a zeroed struct of our own.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        (libc::fstat(fd, &mut st) == 0).then_some(st.st_mode & libc::S_IFMT)
    }
}

/// A descriptor this process was handed by number, believed only when it
/// is open and of the kind `mode` (`S_IFCHR`, `S_IFSOCK`), and closed on
/// every exec from here on.
pub fn handed(fd: RawFd, mode: libc::mode_t) -> Option<OwnedFd> {
    if kind_of(fd) != Some(mode) {
        return None;
    }
    // SAFETY: fcntl on that descriptor, open as just seen.
    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    // SAFETY: an open descriptor this process was handed, owned by nobody
    // else here.
    Some(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// An ioctl of V4L2 on the host's camera `fd`, its struct `arg`; retried
/// on a signal.
fn xioctl(fd: RawFd, cmd: u32, arg: &mut [u8]) -> Result<(), String> {
    loop {
        // SAFETY: the struct is `arg`, as long as the number says (the
        // callers give each one its own size).
        let r = unsafe { libc::ioctl(fd, cmd as _, arg.as_mut_ptr()) };
        if r == 0 {
            return Ok(());
        }
        match errno() {
            libc::EINTR => continue,
            e => return Err(std::io::Error::from_raw_os_error(e).to_string()),
        }
    }
}

/// The host's first camera that captures and streams: `/dev/video<N>`,
/// opened non-blocking. Metadata nodes and others that capture nothing are
/// passed over.
fn host_camera() -> Result<OwnedFd, String> {
    for n in 0..64 {
        let Ok(path) = std::ffi::CString::new(format!("/dev/video{n}")) else {
            continue;
        };
        // SAFETY: a NUL-terminated path; the descriptor is owned below.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            continue;
        }
        // SAFETY: open has just returned it.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut cap = [0u8; 104];
        if xioctl(fd.as_raw_fd(), vidioc::QUERYCAP, &mut cap).is_err() {
            continue;
        }
        let caps = if u32_at(&cap, 84) & CAP_DEVICE_CAPS != 0 {
            u32_at(&cap, 88)
        } else {
            u32_at(&cap, 84)
        };
        if caps & CAP_VIDEO_CAPTURE != 0 && caps & CAP_STREAMING != 0 {
            return Ok(fd);
        }
    }
    Err("no camera on the host".to_owned())
}

/// A buffer of the host's camera, mapped.
struct Map {
    ptr: *mut libc::c_void,
    len: usize,
}

impl Drop for Map {
    fn drop(&mut self) {
        // SAFETY: a mapping of ours, of that length, not used after this.
        unsafe { libc::munmap(self.ptr, self.len) };
    }
}

/// The host's camera, streaming for a program the person allowed it:
/// opened, in the program's format, its buffers mapped. Dropped — the
/// program stops, or closes the camera —, it stops streaming and is closed
/// (its light goes off).
struct Real {
    fd: OwnedFd,
    maps: Vec<Map>,
}

impl Drop for Real {
    fn drop(&mut self) {
        let mut off = BUF_TYPE_CAPTURE.to_ne_bytes();
        let _ = xioctl(self.fd.as_raw_fd(), vidioc::STREAMOFF, &mut off);
    }
}

impl Real {
    /// The host's camera streaming `width` × `height` YUYV at `interval`
    /// (as near as it goes): the program's format, which it keeps — a
    /// camera that has not that is none for it (it stays black).
    fn start(width: u32, height: u32, interval: (u32, u32)) -> Result<Self, String> {
        let fd = host_camera()?;
        let raw = fd.as_raw_fd();
        let mut fmt = [0u8; 208];
        put32(&mut fmt, 0, BUF_TYPE_CAPTURE);
        put32(&mut fmt, 8, width);
        put32(&mut fmt, 12, height);
        put32(&mut fmt, 16, YUYV);
        put32(&mut fmt, 20, FIELD_NONE);
        xioctl(raw, vidioc::S_FMT, &mut fmt)?;
        if (u32_at(&fmt, 8), u32_at(&fmt, 12), u32_at(&fmt, 16)) != (width, height, YUYV) {
            return Err(format!("the camera has no {width}×{height} YUYV"));
        }
        let mut parm = [0u8; 204];
        put32(&mut parm, 0, BUF_TYPE_CAPTURE);
        put32(&mut parm, 12, interval.0);
        put32(&mut parm, 16, interval.1);
        // Its own rate where it has not that one: frames as they come.
        let _ = xioctl(raw, vidioc::S_PARM, &mut parm);
        let mut req = [0u8; 20];
        put32(&mut req, 0, 4);
        put32(&mut req, 4, BUF_TYPE_CAPTURE);
        put32(&mut req, 8, MEMORY_MMAP);
        xioctl(raw, vidioc::REQBUFS, &mut req)?;
        let count = u32_at(&req, 0).min(MAX_BUFFERS);
        if count == 0 {
            return Err("the camera gave no buffers".to_owned());
        }
        let mut maps = Vec::new();
        for index in 0..count {
            let mut b = [0u8; 88];
            put32(&mut b, 0, index);
            put32(&mut b, 4, BUF_TYPE_CAPTURE);
            put32(&mut b, 60, MEMORY_MMAP);
            xioctl(raw, vidioc::QUERYBUF, &mut b)?;
            let (offset, len) = (u32_at(&b, 64), u32_at(&b, 72) as usize);
            // SAFETY: a mapping of the camera's buffer as it said it is.
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ,
                    libc::MAP_SHARED,
                    raw,
                    libc::off_t::from(offset),
                )
            };
            if ptr == libc::MAP_FAILED {
                return Err(format!("mmap: {}", std::io::Error::last_os_error()));
            }
            maps.push(Map { ptr, len });
            xioctl(raw, vidioc::QBUF, &mut b)?;
        }
        let mut on = BUF_TYPE_CAPTURE.to_ne_bytes();
        xioctl(raw, vidioc::STREAMON, &mut on)?;
        Ok(Self { fd, maps })
    }

    /// A frame the camera has done: its buffer and how much of it is the
    /// frame. `None` when there is none now.
    fn take(&self) -> Option<(u32, usize)> {
        let mut b = [0u8; 88];
        put32(&mut b, 4, BUF_TYPE_CAPTURE);
        put32(&mut b, 60, MEMORY_MMAP);
        xioctl(self.fd.as_raw_fd(), vidioc::DQBUF, &mut b).ok()?;
        let index = u32_at(&b, 0);
        let map = self.maps.get(index as usize)?;
        Some((index, (u32_at(&b, 8) as usize).min(map.len)))
    }

    /// The frame in buffer `index`, `used` bytes of it.
    fn frame(&self, index: u32, used: usize) -> &[u8] {
        match self.maps.get(index as usize) {
            // SAFETY: the mapping lives as long as `self`, and `used` is no
            // more than its length (`Real::take`).
            Some(map) => unsafe { std::slice::from_raw_parts(map.ptr.cast::<u8>(), used) },
            None => &[],
        }
    }

    /// Buffer `index` back to the camera, for the next frame.
    fn give_back(&self, index: u32) {
        let mut b = [0u8; 88];
        put32(&mut b, 0, index);
        put32(&mut b, 4, BUF_TYPE_CAPTURE);
        put32(&mut b, 60, MEMORY_MMAP);
        let _ = xioctl(self.fd.as_raw_fd(), vidioc::QBUF, &mut b);
    }
}

/// Namespaces of its own but for the files — network, IPC, UTS, in a user
/// namespace whose one uid and gid are the user's, its capabilities there
/// dropped: what a server that asks the person (the launch's socket of
/// questions, the launch window) and opens the host's camera keeps of the
/// host; `--ask`'s, where [`crate::wl_proxy::isolate`] is the black one's.
fn isolate_but_files() -> Result<(), String> {
    // SAFETY: getuid and getgid take nothing and cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNET | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS;
    // SAFETY: unshare takes flags only.
    if unsafe { libc::unshare(flags) } != 0 {
        return Err(format!("unshare: {}", std::io::Error::last_os_error()));
    }
    let write = |file: &str, text: String| {
        std::fs::write(format!("/proc/self/{file}"), text).map_err(|e| format!("{file}: {e}"))
    };
    write("setgroups", "deny".to_owned())?;
    write("uid_map", format!("{uid} {uid} 1"))?;
    write("gid_map", format!("{gid} {gid} 1"))?;
    crate::enter::drop_capabilities();
    Ok(())
}

/// Whether the person lets the program have the real camera.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Consent {
    /// Not asked yet: at the first streaming.
    Unasked,
    /// The question is out.
    Asking,
    Allowed,
    /// No — said, written before, not known whose, or the camera would not.
    Refused,
}

/// Mount the cameras at `args.mount`, or take the connection handed over
/// once it is mounted, and serve them until they are unmounted.
fn serve(args: &Args) -> Result<(), String> {
    // SAFETY: getuid, getgid and getppid take nothing and cannot fail.
    let (uid, gid, supervisor) = unsafe { (libc::getuid(), libc::getgid(), libc::getppid()) };
    let fuse = match &args.place {
        Place::Mount(dir) => {
            let fuse = open_fuse()?;
            mount(fuse.as_raw_fd(), dir, uid, gid)?;
            fuse
        }
        Place::From(socket) => {
            let socket = handed(*socket, libc::S_IFSOCK).ok_or("--from: no socket there")?;
            // Mounted: the connection, sent. The socket's end without it —
            // its other end gone (`profile-run` could not mount it, or never
            // ran): nothing to serve.
            let (_, fds) = crate::sys::recv_with_fds(socket.as_raw_fd(), 1, 1)
                .map_err(|e| format!("the connection not received: {e}"))?;
            let Some(fuse) = fds.into_iter().next() else {
                return Ok(());
            };
            if kind_of(fuse.as_raw_fd()) != Some(libc::S_IFCHR) {
                return Err("what was sent is no /dev/fuse".to_owned());
            }
            // Nothing more of the host's from here than it needs: for the
            // black camera, namespaces of its own with an empty root — as the
            // Wayland proxy (`wl_proxy::isolate`); for the one that asks, the
            // files kept (the question, the host's camera). Where the system
            // gives none, as it is, said.
            if crate::wl_proxy::isolation_given() {
                let isolated = if args.ask {
                    isolate_but_files()
                } else {
                    crate::wl_proxy::isolate()
                };
                isolated.map_err(|e| format!("cannot isolate itself: {e}"))?;
            } else {
                eprintln!("camera-serve: no namespaces of its own here — served as it is");
            }
            fuse
        }
    };
    // SAFETY: flags only; the descriptor is owned below.
    let tfd = unsafe {
        libc::timerfd_create(
            libc::CLOCK_MONOTONIC,
            libc::TFD_NONBLOCK | libc::TFD_CLOEXEC,
        )
    };
    if tfd < 0 {
        return Err(format!("timerfd: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: timerfd_create has just returned it.
    let timer = unsafe { OwnedFd::from_raw_fd(tfd) };
    // The question's answer comes back on a channel, a byte on the pipe
    // saying so.
    let (wake_r, wake_w) = crate::sys::pipe_nonblocking().map_err(|e| format!("pipe: {e}"))?;
    let mut wake_w = Some(wake_w);
    let (tx, rx) = std::sync::mpsc::channel::<crate::camask::Decision>();
    let mut tx = Some(tx);
    let mut consent = if args.ask {
        Consent::Unasked
    } else {
        Consent::Refused
    };
    let mut real: Option<Real> = None;
    let mut server = Server::new(args.devices.clone(), uid, gid);
    let mut buf = vec![0u8; READ_BUFFER];
    let mut armed = false;
    loop {
        let mut fds = vec![
            libc::pollfd {
                fd: fuse.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: timer.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake_r.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        if let Some(r) = &real {
            fds.push(libc::pollfd {
                fd: r.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        // SAFETY: the pollfds of the vector it is given, as many.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return Err(format!("poll: {}", std::io::Error::last_os_error()));
        }
        if fds[1].revents & libc::POLLIN != 0 {
            let mut ticks = [0u8; 8];
            // SAFETY: read(2) into a buffer of that length; non-blocking.
            unsafe { libc::read(timer.as_raw_fd(), ticks.as_mut_ptr().cast(), 8) };
            if real.is_none() {
                write_all(fuse.as_raw_fd(), &server.tick(now()))?;
            }
        }
        if fds[2].revents & libc::POLLIN != 0 {
            let mut drain = [0u8; 8];
            // SAFETY: read(2) into a buffer of that length; non-blocking.
            unsafe { libc::read(wake_r.as_raw_fd(), drain.as_mut_ptr().cast(), 8) };
            if let Ok(decision) = rx.try_recv() {
                consent = match decision {
                    crate::camask::Decision::Once | crate::camask::Decision::Always => {
                        Consent::Allowed
                    }
                    crate::camask::Decision::No => Consent::Refused,
                };
            }
        }
        if let Some(r) = fds.get(3) {
            if r.revents & libc::POLLIN != 0 {
                if let Some(camera) = &real {
                    while let Some((index, used)) = camera.take() {
                        let messages = server.deliver(0, camera.frame(index, used), now());
                        camera.give_back(index);
                        write_all(fuse.as_raw_fd(), &messages)?;
                    }
                }
            } else if r.revents & (libc::POLLERR | libc::POLLHUP) != 0 {
                // The camera gone (unplugged): black from here on.
                eprintln!("camera-serve: the host's camera is gone — black from here on");
                real = None;
                consent = Consent::Refused;
            }
        }
        if fds[0].revents & libc::POLLIN != 0 {
            // SAFETY: read(2) into a buffer of that length.
            let n = unsafe { libc::read(fuse.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                match errno() {
                    // A request gone before it was read; a signal.
                    libc::ENOENT | libc::EINTR | libc::EAGAIN => continue,
                    // Unmounted.
                    libc::ENODEV => return Ok(()),
                    _ => return Err(format!("/dev/fuse: {}", std::io::Error::last_os_error())),
                }
            }
            let messages = server.handle(&buf[..n as usize]);
            write_all(fuse.as_raw_fd(), &messages)?;
            if server.destroyed {
                return Ok(());
            }
        } else if fds[0].revents & (libc::POLLERR | libc::POLLHUP) != 0 {
            return Ok(());
        }
        // The question, at the first streaming: in a thread of its own, the
        // frames black meanwhile.
        if consent == Consent::Unasked && server.streaming() {
            consent = match crate::camask::Asking::find(supervisor) {
                Some(asking) if asking.denied() => {
                    eprintln!(
                        "camera-serve: «{}» was refused the camera before — black",
                        asking.label
                    );
                    Consent::Refused
                }
                Some(asking) => match (tx.take(), wake_w.take()) {
                    (Some(tx), Some(wake)) => {
                        std::thread::spawn(move || {
                            let _ = tx.send(asking.ask());
                            // SAFETY: write(2) of one byte to a pipe we hold.
                            unsafe { libc::write(wake.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
                        });
                        Consent::Asking
                    }
                    _ => Consent::Refused,
                },
                None => {
                    eprintln!(
                        "camera-serve: this launch is not in the registry — nobody to ask, black"
                    );
                    Consent::Refused
                }
            };
        }
        // The real camera while the program streams and may have it.
        let format = server.streaming_format(0);
        match (consent == Consent::Allowed, format, real.is_some()) {
            (true, Some((w, h, interval)), false) => match Real::start(w, h, interval) {
                Ok(camera) => real = Some(camera),
                Err(e) => {
                    eprintln!("camera-serve: the host's camera not started ({e}) — black");
                    consent = Consent::Refused;
                }
            },
            (false, _, true) | (_, None, true) => real = None,
            _ => {}
        }
        // Black frames while it streams and no real one comes.
        let want = server.streaming() && real.is_none();
        if want != armed {
            let ns = if want { black_interval_ns() } else { 0 };
            let every = libc::timespec {
                tv_sec: (ns / 1_000_000_000) as libc::time_t,
                tv_nsec: (ns % 1_000_000_000) as libc::c_long,
            };
            let spec = libc::itimerspec {
                it_interval: every,
                it_value: every,
            };
            // SAFETY: a timer descriptor of this process and a spec that
            // outlives the call.
            unsafe { libc::timerfd_settime(timer.as_raw_fd(), 0, &spec, std::ptr::null_mut()) };
            armed = want;
        }
    }
}

/// Each message in one write, as the kernel takes them. A reply to a
/// request that is gone (the program interrupted) is refused with ENOENT:
/// nothing lost.
fn write_all(fd: RawFd, messages: &[Vec<u8>]) -> Result<(), String> {
    for m in messages {
        // SAFETY: write(2) of a buffer of that length.
        let n = unsafe { libc::write(fd, m.as_ptr().cast(), m.len()) };
        if n < 0 {
            match errno() {
                libc::ENOENT => {}
                // Unmounted: the loop's next read says so.
                libc::ENODEV => return Ok(()),
                _ => eprintln!(
                    "camera-serve: a reply not taken: {}",
                    std::io::Error::last_os_error()
                ),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: Stamp = (100, 500);

    /// A request as the kernel sends it: the header and `body`.
    fn request(opcode: u32, unique: u64, node: u64, body: &[u8]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&((IN_HEADER + body.len()) as u32).to_ne_bytes());
        r.extend_from_slice(&opcode.to_ne_bytes());
        r.extend_from_slice(&unique.to_ne_bytes());
        r.extend_from_slice(&node.to_ne_bytes());
        r.extend_from_slice(&[0u8; 16]);
        r.extend_from_slice(body);
        r
    }

    /// A reply's error and body.
    fn parsed(m: &[u8]) -> (u64, i32, Vec<u8>) {
        assert_eq!(u32_at(m, 0) as usize, m.len(), "length");
        let error = i32::from_ne_bytes(m[4..8].try_into().unwrap());
        (u64_at(m, 8), error, m[OUT_HEADER..].to_vec())
    }

    fn server() -> Server {
        Server::new(vec!["video0".to_owned()], 1000, 100)
    }

    /// An ioctl request: `fuse_ioctl_in` and the struct.
    fn ioctl(s: &mut Server, fh: u64, unique: u64, cmd: u32, arg: &[u8]) -> Vec<Vec<u8>> {
        let size = (cmd >> 16) & 0x3fff;
        let mut body = vec![0u8; 32];
        put64(&mut body, 0, fh);
        put32(&mut body, 12, cmd);
        if (cmd >> 30) & W != 0 {
            put32(&mut body, 24, size);
            body.extend_from_slice(arg);
        }
        if (cmd >> 30) & R != 0 {
            put32(&mut body, 28, size);
        }
        s.handle(&request(op::IOCTL, unique, 2, &body))
    }

    /// An ioctl's struct back, or its error.
    fn answer(out: &[Vec<u8>]) -> Result<Vec<u8>, i32> {
        assert_eq!(out.len(), 1, "{out:?}");
        let (_, error, body) = parsed(&out[0]);
        if error != 0 {
            return Err(-error);
        }
        assert_eq!(body[..16], [0u8; 16], "fuse_ioctl_out");
        Ok(body[16..].to_vec())
    }

    fn open(s: &mut Server, flags: u32) -> u64 {
        let mut body = [0u8; 8];
        put32(&mut body, 0, flags);
        let out = s.handle(&request(op::OPEN, 5, 2, &body));
        let (_, error, body) = parsed(&out[0]);
        assert_eq!(error, 0);
        assert_eq!(u32_at(&body, 8), KEEP_CACHE);
        u64_at(&body, 0)
    }

    /// The numbers are V4L2's own (`videodev2.h`, as `strace` prints them).
    #[test]
    fn the_ioctls_are_v4l2s_numbers() {
        assert_eq!(vidioc::QUERYCAP, 0x8068_5600);
        assert_eq!(vidioc::ENUM_FMT, 0xc040_5602);
        assert_eq!(vidioc::G_FMT, 0xc0d0_5604);
        assert_eq!(vidioc::S_FMT, 0xc0d0_5605);
        assert_eq!(vidioc::REQBUFS, 0xc014_5608);
        assert_eq!(vidioc::QUERYBUF, 0xc058_5609);
        assert_eq!(vidioc::QBUF, 0xc058_560f);
        assert_eq!(vidioc::DQBUF, 0xc058_5611);
        assert_eq!(vidioc::STREAMON, 0x4004_5612);
        assert_eq!(vidioc::STREAMOFF, 0x4004_5613);
        assert_eq!(vidioc::G_PARM, 0xc0cc_5615);
        assert_eq!(vidioc::ENUMINPUT, 0xc050_561a);
        assert_eq!(vidioc::G_INPUT, 0x8004_5626);
        assert_eq!(vidioc::TRY_FMT, 0xc0d0_5640);
        assert_eq!(vidioc::ENUM_FRAMESIZES, 0xc02c_564a);
        assert_eq!(vidioc::ENUM_FRAMEINTERVALS, 0xc034_564b);
        assert_eq!(YUYV, 0x5659_5559);
    }

    /// The filesystem: `INIT` at the version this speaks, the camera found
    /// by its name as a regular file the size of every buffer, the root a
    /// directory that lists it, what is not there not found.
    #[test]
    fn the_filesystem_is_a_directory_of_cameras() {
        let mut s = server();
        let mut init = [0u8; 16];
        put32(&mut init, 0, 7);
        put32(&mut init, 4, 40);
        put32(&mut init, 8, 65536);
        let out = s.handle(&request(op::INIT, 1, 0, &init));
        let (unique, error, body) = parsed(&out[0]);
        assert_eq!((unique, error, body.len()), (1, 0, 64));
        assert_eq!((u32_at(&body, 0), u32_at(&body, 4)), (7, FUSE_MINOR));
        assert_eq!(u32_at(&body, 20), MAX_WRITE);

        let out = s.handle(&request(op::LOOKUP, 2, ROOT, b"video0\0"));
        let (_, error, body) = parsed(&out[0]);
        assert_eq!((error, body.len()), (0, 128));
        assert_eq!(u64_at(&body, 0), 2);
        let attr = &body[40..];
        assert_eq!(u64_at(attr, 8), FILE_SIZE);
        assert_eq!(u32_at(attr, 60), S_IFREG | 0o660);
        assert_eq!((u32_at(attr, 68), u32_at(attr, 72)), (1000, 100));
        for (node, name) in [(ROOT, &b"video1\0"[..]), (2, &b"x\0"[..])] {
            let out = s.handle(&request(op::LOOKUP, 3, node, name));
            assert_eq!(parsed(&out[0]).1, -libc::ENOENT);
        }
        let out = s.handle(&request(op::GETATTR, 4, ROOT, &[0u8; 16]));
        let (_, error, body) = parsed(&out[0]);
        assert_eq!((error, u32_at(&body, 16 + 60)), (0, S_IFDIR | 0o755));
        let out = s.handle(&request(op::SETATTR, 4, 2, &[0u8; 88]));
        assert_eq!(parsed(&out[0]).1, -libc::EPERM);

        let mut read = [0u8; 40];
        put32(&mut read, 16, 4096);
        let out = s.handle(&request(op::READDIR, 6, ROOT, &read));
        let (_, _, dir) = parsed(&out[0]);
        let names: Vec<String> = {
            let mut at = 0;
            let mut names = Vec::new();
            while at + 24 <= dir.len() {
                let len = u32_at(&dir, at + 16) as usize;
                names.push(String::from_utf8(dir[at + 24..at + 24 + len].to_vec()).unwrap());
                at += (24 + len).div_ceil(8) * 8;
            }
            names
        };
        assert_eq!(names, [".", "..", "video0"]);
        // From the third on: the camera alone.
        put64(&mut read, 8, 2);
        let out = s.handle(&request(op::READDIR, 7, ROOT, &read));
        assert_eq!(u32_at(&parsed(&out[0]).2, 16), 6);
        // Anything else (here FUSE_GETXATTR): not here.
        let out = s.handle(&request(22, 8, 2, &[]));
        assert_eq!(parsed(&out[0]).1, -libc::ENOSYS);
    }

    /// Every byte of the file is black, wherever it is read: the pages a
    /// program maps are black before any frame.
    #[test]
    fn the_file_is_black_everywhere() {
        let mut s = server();
        let fh = open(&mut s, 0);
        for offset in [0u64, 1, 4095, BUFFER_ROOM * 3, FILE_SIZE - 10] {
            let mut read = [0u8; 40];
            put64(&mut read, 0, fh);
            put64(&mut read, 8, offset);
            put32(&mut read, 16, 4096);
            let out = s.handle(&request(op::READ, 9, 2, &read));
            let (_, error, data) = parsed(&out[0]);
            assert_eq!(error, 0);
            let want = (FILE_SIZE - offset).min(4096) as usize;
            assert_eq!(data.len(), want, "{offset}");
            for (k, &b) in data.iter().enumerate() {
                assert_eq!(
                    b,
                    if (offset + k as u64) & 1 == 0 {
                        0x10
                    } else {
                        0x80
                    }
                );
            }
        }
    }

    /// A program's way to a black frame, as Chromium and Firefox go: what
    /// it is, its format, buffers, queued, streaming; a frame each tick
    /// into the first queued buffer, taken with `DQBUF` — at once when one
    /// is done, else a blocking one answered by the tick, a non-blocking
    /// one `EAGAIN` and a poll woken.
    #[test]
    fn a_program_streams_black_frames() {
        let mut s = server();
        let fh = open(&mut s, 0);
        let cap = answer(&ioctl(&mut s, fh, 10, vidioc::QUERYCAP, &[])).unwrap();
        assert_eq!(cap.len(), 104);
        assert_eq!(&cap[..9], b"cellward\0");
        assert_eq!(
            u32_at(&cap, 88),
            CAP_VIDEO_CAPTURE | CAP_STREAMING,
            "device caps"
        );
        let mut desc = vec![0u8; 64];
        put32(&mut desc, 4, BUF_TYPE_CAPTURE);
        let d = answer(&ioctl(&mut s, fh, 11, vidioc::ENUM_FMT, &desc)).unwrap();
        assert_eq!(u32_at(&d, 44), YUYV);
        put32(&mut desc, 0, 1);
        assert_eq!(
            answer(&ioctl(&mut s, fh, 11, vidioc::ENUM_FMT, &desc)),
            Err(EINVAL)
        );

        // 1920 × 1080 asked: 1280 × 720 given.
        let mut fmt = vec![0u8; 208];
        put32(&mut fmt, 0, BUF_TYPE_CAPTURE);
        put32(&mut fmt, 8, 1920);
        put32(&mut fmt, 12, 1080);
        put32(&mut fmt, 16, u32::from_le_bytes(*b"MJPG"));
        let f = answer(&ioctl(&mut s, fh, 12, vidioc::S_FMT, &fmt)).unwrap();
        assert_eq!(
            (u32_at(&f, 8), u32_at(&f, 12), u32_at(&f, 16)),
            (1280, 720, YUYV)
        );
        assert_eq!((u32_at(&f, 24), u32_at(&f, 28)), (2560, 1280 * 720 * 2));

        let mut req = vec![0u8; 20];
        put32(&mut req, 0, 4);
        put32(&mut req, 4, BUF_TYPE_CAPTURE);
        put32(&mut req, 8, 2); // USERPTR
        assert_eq!(
            answer(&ioctl(&mut s, fh, 13, vidioc::REQBUFS, &req)),
            Err(EINVAL)
        );
        put32(&mut req, 8, MEMORY_MMAP);
        let r = answer(&ioctl(&mut s, fh, 13, vidioc::REQBUFS, &req)).unwrap();
        assert_eq!((u32_at(&r, 0), u32_at(&r, 12)), (4, BUF_CAP_SUPPORTS_MMAP));
        // No new format with buffers out.
        assert_eq!(
            answer(&ioctl(&mut s, fh, 12, vidioc::S_FMT, &fmt)),
            Err(EBUSY)
        );

        let buffer = |index: u32| {
            let mut b = vec![0u8; 88];
            put32(&mut b, 0, index);
            put32(&mut b, 4, BUF_TYPE_CAPTURE);
            put32(&mut b, 60, MEMORY_MMAP);
            b
        };
        for index in 0..4 {
            let q = answer(&ioctl(&mut s, fh, 14, vidioc::QUERYBUF, &buffer(index))).unwrap();
            assert_eq!(u32_at(&q, 64) as u64, u64::from(index) * BUFFER_ROOM);
            assert_eq!(u32_at(&q, 72), 1280 * 720 * 2);
            assert!(u64::from(u32_at(&q, 64)) + u64::from(u32_at(&q, 72)) <= FILE_SIZE);
            let q = answer(&ioctl(&mut s, fh, 15, vidioc::QBUF, &buffer(index))).unwrap();
            assert_eq!(u32_at(&q, 12) & BUF_FLAG_QUEUED, BUF_FLAG_QUEUED);
        }
        assert_eq!(
            answer(&ioctl(&mut s, fh, 15, vidioc::QBUF, &buffer(0))),
            Err(EINVAL)
        );
        assert_eq!(
            answer(&ioctl(&mut s, fh, 15, vidioc::QBUF, &buffer(9))),
            Err(EINVAL)
        );

        // Not streaming: nothing to wait for, no timer.
        assert_eq!(
            answer(&ioctl(&mut s, fh, 16, vidioc::DQBUF, &buffer(0))),
            Err(EINVAL)
        );
        assert!(!s.streaming());
        assert!(s.tick(NOW).is_empty());
        let mut on = vec![0u8; 4];
        put32(&mut on, 0, BUF_TYPE_CAPTURE);
        assert_eq!(
            answer(&ioctl(&mut s, fh, 17, vidioc::STREAMON, &on)),
            Ok(Vec::new())
        );
        assert!(s.streaming());

        // A blocking DQBUF waits for the tick, which answers it.
        assert!(ioctl(&mut s, fh, 18, vidioc::DQBUF, &buffer(0)).is_empty());
        let out = s.tick((101, 7));
        assert_eq!(out.len(), 1);
        let (unique, error, body) = parsed(&out[0]);
        assert_eq!((unique, error), (18, 0));
        let b = &body[16..];
        assert_eq!(u32_at(b, 0), 0, "the first queued");
        assert_eq!(u32_at(b, 8), 1280 * 720 * 2, "bytes used");
        assert_eq!(u32_at(b, 12) & BUF_FLAG_DONE, BUF_FLAG_DONE);
        assert_eq!((u64_at(b, 24), u64_at(b, 32)), (101, 7));
        assert_eq!(u32_at(b, 56), 0, "sequence");
        // A frame done before it is asked for: taken at once.
        s.tick(NOW);
        let b = answer(&ioctl(&mut s, fh, 19, vidioc::DQBUF, &buffer(0))).unwrap();
        assert_eq!((u32_at(&b, 0), u32_at(&b, 56)), (1, 1));
        // Back in the queue, and round again.
        answer(&ioctl(&mut s, fh, 20, vidioc::QBUF, &buffer(0))).unwrap();

        // An interrupted wait is answered EINTR, and owed nothing more.
        assert!(ioctl(&mut s, fh, 21, vidioc::DQBUF, &buffer(0)).is_empty());
        let out = s.handle(&request(op::INTERRUPT, 22, 0, &21u64.to_ne_bytes()));
        assert_eq!(parsed(&out[0]).0, 21);
        assert_eq!(parsed(&out[0]).1, -libc::EINTR);

        // STREAMOFF: every buffer the program's, no timer.
        let mut off = vec![0u8; 4];
        put32(&mut off, 0, BUF_TYPE_CAPTURE);
        answer(&ioctl(&mut s, fh, 23, vidioc::STREAMOFF, &off)).unwrap();
        assert!(!s.streaming());
        let q = answer(&ioctl(&mut s, fh, 24, vidioc::QUERYBUF, &buffer(2))).unwrap();
        assert_eq!(u32_at(&q, 12) & (BUF_FLAG_QUEUED | BUF_FLAG_DONE), 0);

        // Closed: the buffers go with it.
        s.handle(&request(op::RELEASE, 25, 2, &fh.to_ne_bytes()));
        let other = open(&mut s, 0);
        let r = answer(&ioctl(&mut s, other, 26, vidioc::REQBUFS, &req)).unwrap();
        assert_eq!(u32_at(&r, 0), 4);
    }

    /// A non-blocking program: `EAGAIN` while nothing is done, its poll
    /// told nothing and woken by the frame (`FUSE_NOTIFY_POLL` of its
    /// handle), then told there is one.
    #[test]
    fn a_non_blocking_program_polls() {
        let mut s = server();
        let fh = open(&mut s, libc::O_NONBLOCK as u32);
        let mut req = vec![0u8; 20];
        put32(&mut req, 0, 2);
        put32(&mut req, 4, BUF_TYPE_CAPTURE);
        put32(&mut req, 8, MEMORY_MMAP);
        answer(&ioctl(&mut s, fh, 1, vidioc::REQBUFS, &req)).unwrap();
        let mut b = vec![0u8; 88];
        put32(&mut b, 4, BUF_TYPE_CAPTURE);
        put32(&mut b, 60, MEMORY_MMAP);
        answer(&ioctl(&mut s, fh, 2, vidioc::QBUF, &b)).unwrap();
        let mut on = vec![0u8; 4];
        put32(&mut on, 0, BUF_TYPE_CAPTURE);
        answer(&ioctl(&mut s, fh, 3, vidioc::STREAMON, &on)).unwrap();
        assert_eq!(
            answer(&ioctl(&mut s, fh, 4, vidioc::DQBUF, &b)),
            Err(EAGAIN)
        );

        let poll = |s: &mut Server, unique: u64| {
            let mut body = [0u8; 24];
            put64(&mut body, 0, fh);
            put64(&mut body, 8, 77);
            put32(&mut body, 16, POLL_SCHEDULE_NOTIFY);
            let out = s.handle(&request(op::POLL, unique, 2, &body));
            u32_at(&parsed(&out[0]).2, 0)
        };
        assert_eq!(poll(&mut s, 5), 0);
        let out = s.tick(NOW);
        assert_eq!(out.len(), 1);
        let (unique, code, kh) = parsed(&out[0]);
        assert_eq!((unique, code, u64_at(&kh, 0)), (0, NOTIFY_POLL, 77));
        assert_eq!(poll(&mut s, 6), (libc::POLLIN | libc::POLLRDNORM) as u32);
        let got = answer(&ioctl(&mut s, fh, 7, vidioc::DQBUF, &b)).unwrap();
        assert_eq!(u32_at(&got, 12) & BUF_FLAG_DONE, BUF_FLAG_DONE);
        // Nothing queued: the tick has nothing to fill, nobody to wake.
        assert!(s.tick(NOW).is_empty());
    }

    /// Refused: ioctls not listed (ENOTTY) — a 32-bit program's among them,
    /// its structs of other sizes —, controls (EINVAL), another open file's
    /// buffers (EBUSY), a struct shorter than its number says.
    #[test]
    fn what_is_not_known_is_refused() {
        let mut s = server();
        let fh = open(&mut s, 0);
        // VIDIOC_QUERYBUF of a 32-bit program: 68 bytes.
        assert_eq!(
            answer(&ioctl(&mut s, fh, 1, ioc(RW, 9, 68), &[0u8; 68])),
            Err(ENOTTY)
        );
        // UVCIOC_CTRL_QUERY: an extension unit's, never passed on.
        assert_eq!(
            answer(&ioctl(&mut s, fh, 2, 0xc010_7521, &[0u8; 16])),
            Err(ENOTTY)
        );
        assert_eq!(
            answer(&ioctl(&mut s, fh, 3, vidioc::QUERYCTRL, &[0u8; 68])),
            Err(EINVAL)
        );
        let mut req = vec![0u8; 20];
        put32(&mut req, 0, 2);
        put32(&mut req, 4, BUF_TYPE_CAPTURE);
        put32(&mut req, 8, MEMORY_MMAP);
        answer(&ioctl(&mut s, fh, 4, vidioc::REQBUFS, &req)).unwrap();
        let other = open(&mut s, 0);
        assert_eq!(
            answer(&ioctl(&mut s, other, 5, vidioc::REQBUFS, &req)),
            Err(EBUSY)
        );
        let mut on = vec![0u8; 4];
        put32(&mut on, 0, BUF_TYPE_CAPTURE);
        assert_eq!(
            answer(&ioctl(&mut s, other, 6, vidioc::STREAMON, &on)),
            Err(EINVAL)
        );
        // Short: the kernel copies what the number says; less is nonsense.
        let mut body = vec![0u8; 32];
        put64(&mut body, 0, fh);
        put32(&mut body, 12, vidioc::S_FMT);
        put32(&mut body, 24, 208);
        put32(&mut body, 28, 208);
        body.extend_from_slice(&[0u8; 100]);
        let out = s.handle(&request(op::IOCTL, 7, 2, &body));
        assert_eq!(parsed(&out[0]).1, -EINVAL);
        // A file this never opened.
        assert_eq!(
            answer(&ioctl(&mut s, 999, 8, vidioc::QUERYCAP, &[])),
            Err(libc::EBADF)
        );
    }

    /// A real frame (the person allowed the camera): written into the
    /// pages of the program's first queued buffer in pieces of
    /// `STORE_CHUNK` (`FUSE_NOTIFY_STORE`, no more than the buffer holds),
    /// then the buffer done — the waiting `DQBUF` answered after the data,
    /// never before; with no buffer queued, dropped.
    #[test]
    fn a_real_frame_goes_into_the_programs_buffer_before_it_is_told() {
        let mut s = server();
        let fh = open(&mut s, 0);
        let mut req = vec![0u8; 20];
        put32(&mut req, 0, 2);
        put32(&mut req, 4, BUF_TYPE_CAPTURE);
        put32(&mut req, 8, MEMORY_MMAP);
        answer(&ioctl(&mut s, fh, 1, vidioc::REQBUFS, &req)).unwrap();
        let buffer = |index: u32| {
            let mut b = vec![0u8; 88];
            put32(&mut b, 0, index);
            put32(&mut b, 4, BUF_TYPE_CAPTURE);
            put32(&mut b, 60, MEMORY_MMAP);
            b
        };
        answer(&ioctl(&mut s, fh, 2, vidioc::QBUF, &buffer(1))).unwrap();
        assert_eq!(s.streaming_format(0), None, "not streaming yet");
        let mut on = vec![0u8; 4];
        put32(&mut on, 0, BUF_TYPE_CAPTURE);
        answer(&ioctl(&mut s, fh, 3, vidioc::STREAMON, &on)).unwrap();
        assert_eq!(s.streaming_format(0), Some((640, 480, (1, 30))));
        assert!(ioctl(&mut s, fh, 4, vidioc::DQBUF, &buffer(0)).is_empty());
        // A frame larger than the buffer: cut to it.
        let size: usize = 640 * 480 * 2;
        let frame: Vec<u8> = (0..size + 100).map(|i| (i % 251) as u8).collect();
        let out = s.deliver(0, &frame, (7, 8));
        let pieces = size.div_ceil(STORE_CHUNK);
        assert_eq!(out.len(), pieces + 1, "the pieces, then the answer");
        let mut stored = Vec::new();
        for (k, m) in out[..pieces].iter().enumerate() {
            let (unique, code, body) = parsed(m);
            assert_eq!((unique, code), (0, NOTIFY_STORE));
            assert_eq!(u64_at(&body, 0), 2, "the camera's node");
            assert_eq!(u64_at(&body, 8), BUFFER_ROOM + (k * STORE_CHUNK) as u64);
            assert_eq!(u32_at(&body, 16) as usize, body.len() - 24);
            stored.extend_from_slice(&body[24..]);
        }
        assert_eq!(stored, frame[..size]);
        let (unique, error, body) = parsed(&out[pieces]);
        assert_eq!((unique, error), (4, 0));
        let b = &body[16..];
        assert_eq!((u32_at(b, 0), u32_at(b, 8)), (1, size as u32));
        assert_eq!((u64_at(b, 24), u64_at(b, 32)), (7, 8));
        // Nothing queued now: the next frame is dropped.
        assert!(s.deliver(0, &frame, (7, 9)).is_empty());
        assert!(s.deliver(5, &frame, (7, 9)).is_empty(), "no such camera");
    }

    /// Sizes and rates: the largest size that fits what is asked, the    /// Sizes and rates: the largest size that fits what is asked, the
    /// nearest interval listed; black frames at the slowest.
    #[test]
    fn sizes_and_rates_are_the_listed_ones() {
        assert_eq!(fit(1920, 1080), (1280, 720));
        assert_eq!(fit(800, 600), (640, 480));
        assert_eq!(fit(320, 240), (640, 480));
        assert_eq!(nearest_interval(1, 25), (1, 30));
        assert_eq!(nearest_interval(1, 10), (1, 15));
        assert_eq!(nearest_interval(1, 1), (1, 5));
        assert_eq!(nearest_interval(0, 0), (1, 30));
        assert_eq!(black_interval_ns(), 200_000_000);
    }

    /// The setting's words, the flag's of before among them; kept as a
    /// build of before reads them, the new ones as off there.
    #[test]
    fn the_modes_words() {
        for (word, mode) in [
            ("no", Mode::No),
            ("off", Mode::No),
            ("false", Mode::No),
            (" black\n", Mode::Black),
            ("ask", Mode::Ask),
            ("yes", Mode::Yes),
            ("on", Mode::Yes),
            ("true", Mode::Yes),
        ] {
            assert_eq!(Mode::parse(word), Some(mode), "{word:?}");
        }
        for bad in ["", "maybe", "Black", "1"] {
            assert_eq!(Mode::parse(bad), None, "{bad:?}");
        }
        for mode in [Mode::No, Mode::Black, Mode::Ask, Mode::Yes] {
            assert_eq!(Mode::parse(mode.as_str()), Some(mode));
            assert_eq!(Mode::parse(mode.record_word()), Some(mode));
        }
        assert_eq!(
            (Mode::No.record_word(), Mode::Yes.record_word()),
            ("false", "true")
        );
        assert!(Mode::Black.black() && Mode::Ask.black());
        assert!(!Mode::No.black() && !Mode::Yes.black());
        // On a host with no camera, asking is none; black, said, is black.
        assert_eq!(Mode::Ask.given(false), Mode::No);
        assert_eq!(Mode::Ask.given(true), Mode::Ask);
        assert_eq!(Mode::Black.given(false), Mode::Black);
        assert_eq!(Mode::Yes.given(false), Mode::Yes);
        assert_eq!(Mode::DEFAULT, Mode::Ask);
    }

    #[test]
    fn the_arguments_are_a_mount_point_and_names() {
        let argv = |a: &[&str]| a.iter().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(
            Args::parse(&argv(&["--mount", "/tmp/c"])),
            Ok(Args {
                place: Place::Mount(PathBuf::from("/tmp/c")),
                devices: vec!["video0".to_owned()],
                ask: false,
            })
        );
        assert_eq!(
            Args::parse(&argv(&["--from", "5"])).map(|a| a.place),
            Ok(Place::From(5))
        );
        assert!(Args::parse(&argv(&["--from", "5", "--ask"])).unwrap().ask);
        assert_eq!(
            Args::parse(&argv(&[
                "--mount", "/m", "--device", "video2", "--device", "video3"
            ]))
            .unwrap()
            .devices,
            ["video2", "video3"]
        );
        for bad in [
            &["--device", "video0"][..],
            &["--mount"],
            &["--mount", "/m", "--device", "../x"],
            &["--mount", "/m", "--device", "Video0"],
            &["--mount", "/m", "--other"],
            &["--from"],
            &["--from", "2"],
            &["--mount", "/m", "--from", "5"],
            &["--from", "x"],
        ] {
            assert!(Args::parse(&argv(bad)).is_err(), "{bad:?}");
        }
    }
}
