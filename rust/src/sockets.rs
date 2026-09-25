//! The unix sockets a zone can reach, as a checked invariant
//! (`docs/LEAK-MODEL.md` §15, §17; ROADMAP: the ways out of a zone as an
//! invariant).
//!
//! A socket by path is not a network object. The zone's own network namespace
//! cuts every abstract socket of the host (`@name`), and none of these: what a
//! program connects to by path is a helper outside that acts for whoever
//! connects. An ssh ControlMaster runs a command on a remote machine, a root
//! daemon in `/run` (tailscaled, cups, docker, libvirt) does what its API
//! offers, the Nix daemon fetches in the host's network, an editor's server
//! runs a command on the host. The kernel stops none of it, because the
//! program itself goes nowhere: the helper does, outside the zone.
//!
//! So the probe (`doctor-probe`, INSIDE the zone) walks the places such a
//! socket lives — the home, `/run`, the temporary directories, `/var/lib`,
//! `/nix/var` — and lists every socket a program of the zone could connect to;
//! [`classify`] tells the zone's own from the rest. The rules of the walk are
//! the point of it:
//!
//! * the rights are the program's: the probe sheds the session's groups as
//!   `profile-run` does and holds no capability (`crate::doctor::probe_main`),
//!   and "may connect" is the kernel's own answer (`access(2)` for writing,
//!   ACLs included) — never a reading of mode bits;
//! * directories only are opened, each with `O_DIRECTORY | O_NOFOLLOW |
//!   O_NONBLOCK` from its parent's descriptor: a symlink a program planted
//!   takes the walk nowhere, and a FIFO is never opened, so it cannot hold it;
//! * network and FUSE filesystems and automount points are not entered — a
//!   hung server would hang the probe (the document portal, gvfs, NFS, sshfs,
//!   9p);
//! * bounded: a depth per place, a number of entries, a deadline. What was not
//!   seen is said (`warn`), never taken for "nothing there".
//!
//! A socket in a directory a program may search but not read is found only
//! under a well-known name ([`KNOWN`]): a listing cannot see it, a program
//! that knows the name connects all the same.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::doctor::{Check, Level};

/// A device as `major:minor`, the way `/proc/self/mountinfo` writes it.
pub type Dev = (u32, u32);

/// The places a socket is reached at, and how many directories deep below
/// each the walk goes (the entries of a directory that deep are still read).
/// The home goes in between, at [`HOME_DEPTH`]: after the places that are
/// small and before the ones that may be big, so that a budget spent on
/// `/var/lib` never costs the home.
///
/// `/run` to five: `/run/user/<uid>/vpn-zones/wayland/<zone>/` holds sockets.
/// `/nix/var` only to three: below that are the build logs, tens of thousands
/// of them, and never a socket.
pub const PLACES: [(&str, usize); 7] = [
    ("/run", 5),
    ("/var/run", 5),
    ("/tmp", 3),
    ("/var/tmp", 3),
    ("/dev/shm", 2),
    ("/nix/var", 3),
    ("/var/lib", 3),
];
/// How deep into the home: `~/.ssh/<master>` and
/// `~/.local/share/<program>/<dir>/<socket>` are in reach, a program's caches
/// three levels further are not — a real home has hundreds of thousands of
/// entries at six.
pub const HOME_DEPTH: usize = 3;

/// Sockets by their well-known names, looked at whether or not a listing
/// finds them: a daemon's directory is often `0711` or deeper than the walk
/// goes. The runtime directory's own are added by the probe.
pub const KNOWN: [&str; 16] = [
    "/run/docker.sock",
    "/run/podman/podman.sock",
    "/run/containerd/containerd.sock",
    "/run/libvirt/libvirt-sock",
    "/run/libvirt/virtqemud-sock",
    "/run/libvirt/virtnetworkd-sock",
    "/var/lib/incus/unix.socket",
    "/var/lib/lxd/unix.socket",
    "/run/cups/cups.sock",
    "/run/tailscale/tailscaled.sock",
    "/run/snapd.socket",
    "/run/pcscd/pcscd.comm",
    "/run/dbus/system_bus_socket",
    "/run/systemd/private",
    "/nix/var/nix/daemon-socket/socket",
    crate::sysrun::SOCKET,
];

/// How much the walk may cost, all places together. It runs on every
/// `vpn-zone doctor`.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub entries: usize,
    pub deadline: Duration,
}

pub const LIMITS: Limits = Limits {
    entries: 100_000,
    deadline: Duration::from_secs(3),
};

/// A socket a program here may connect to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub path: Vec<u8>,
    pub dev: Dev,
}

/// What the walk saw.
#[derive(Debug, Default)]
pub struct Walk {
    /// Sorted by path, each socket once (by device and inode: `/var/run` is
    /// usually `/run`).
    pub found: Vec<Found>,
    pub entries: usize,
    /// What was not looked at, said in words; empty when nothing was left.
    pub incomplete: Vec<String>,
}

// --- MOUNTS ---------------------------------------------------------------------

/// One line of `/proc/self/mountinfo`, what the walk needs of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub dev: Dev,
    pub point: Vec<u8>,
    pub fstype: String,
}

/// The mounts of a `mountinfo`. The mount point comes octal-escaped (`\040`
/// for a blank), and is unescaped here.
pub fn mounts(mountinfo: &str) -> Vec<Mount> {
    mountinfo
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let dev = parse_dev(fields.get(2)?)?;
            let point = unescape(fields.get(4)?);
            let dash = fields.iter().position(|f| *f == "-")?;
            let fstype = (*fields.get(dash + 1)?).to_owned();
            Some(Mount { dev, point, fstype })
        })
        .collect()
}

/// `major:minor`.
pub fn parse_dev(text: &str) -> Option<Dev> {
    let (major, minor) = text.split_once(':')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

fn unescape(field: &str) -> Vec<u8> {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let octal = &bytes[i + 1..i + 4];
            if octal.iter().all(|b| (b'0'..=b'7').contains(b)) {
                let value = octal
                    .iter()
                    .fold(0u32, |acc, b| acc * 8 + u32::from(b - b'0'));
                if let Ok(byte) = u8::try_from(value) {
                    out.push(byte);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// A filesystem the walk does not enter: a server that hangs would hang the
/// probe with it (FUSE — the document portal, gvfs, sshfs —, NFS, SMB, 9p,
/// Ceph, AFS), and an automount point mounts one when looked into.
pub fn slow_fs(fstype: &str) -> bool {
    fstype.starts_with("fuse")
        || fstype.starts_with("nfs")
        || matches!(
            fstype,
            "autofs"
                | "cifs"
                | "smb3"
                | "smbfs"
                | "9p"
                | "ceph"
                | "glusterfs"
                | "afs"
                | "davfs"
                | "sshfs"
                | "virtiofs"
                | "lustre"
                | "orangefs"
                | "gfs2"
                | "ocfs2"
        )
}

/// The same, by the magic `statfs(2)` answers for an open directory: the
/// second guard, for a mount the table did not name as it is reached.
fn slow_magic(magic: i64) -> bool {
    const FUSE: i64 = 0x6573_5546;
    const NFS: i64 = 0x6969;
    const SMB: i64 = 0x517b;
    const CIFS: i64 = 0xff53_4d42;
    const SMB2: i64 = 0xfe53_4d42;
    const V9FS: i64 = 0x0102_1997;
    const CEPH: i64 = 0x00c3_6400;
    const AUTOFS: i64 = 0x0187;
    const AFS: i64 = 0x5346_414f;
    [FUSE, NFS, SMB, CIFS, SMB2, V9FS, CEPH, AUTOFS, AFS].contains(&magic)
}

/// The mount points the walk must not enter.
pub fn slow_points(mountinfo: &str) -> HashSet<Vec<u8>> {
    mounts(mountinfo)
        .into_iter()
        .filter(|m| slow_fs(&m.fstype))
        .map(|m| m.point)
        .collect()
}

/// Where a zone covers the host's directory with a tmpfs of its own, besides
/// its runtime directory: the temporary directories of a hermetic zone
/// (`zone::private_tmp`) and every zone's X11 directory (`zone::hide_x11`).
const OWN_PLACES: [&str; 4] = ["/tmp", "/var/tmp", "/dev/shm", crate::x11::X11_DIR];

/// The filesystems the zone made for itself: a tmpfs mounted at the runtime
/// directory or one of [`OWN_PLACES`] that the host does not have. A socket
/// on one of them was bound by a process of the zone — nobody outside can
/// reach that filesystem to listen there.
///
/// `host` is the host's own devices, from its `mountinfo` (the doctor passes
/// them). Without them nothing is the zone's own: a tmpfs is a tmpfs, and the
/// host's `/tmp` looks exactly like the zone's.
pub fn own_devs(mountinfo: &str, runtime: &Path, host: Option<&HashSet<Dev>>) -> HashSet<Dev> {
    let Some(host) = host else {
        return HashSet::new();
    };
    let runtime = runtime.as_os_str().as_bytes();
    mounts(mountinfo)
        .into_iter()
        .filter(|m| {
            m.fstype == "tmpfs"
                && (m.point == runtime || OWN_PLACES.iter().any(|p| m.point == p.as_bytes()))
                && !host.contains(&m.dev)
        })
        .map(|m| m.dev)
        .collect()
}

// --- THE WALK -------------------------------------------------------------------

/// A directory being read, from a descriptor of its own.
struct Dir(*mut libc::DIR);

impl Dir {
    fn from_fd(fd: OwnedFd) -> io::Result<Self> {
        let raw = fd.as_raw_fd();
        // SAFETY: a valid descriptor, whose ownership passes to the stream.
        let dir = unsafe { libc::fdopendir(raw) };
        if dir.is_null() {
            return Err(io::Error::last_os_error());
        }
        std::mem::forget(fd);
        Ok(Self(dir))
    }

    fn fd(&self) -> RawFd {
        // SAFETY: a stream opened by fdopendir and not closed yet.
        unsafe { libc::dirfd(self.0) }
    }

    /// The next entry but `.` and `..`, with its `d_type`. `None` at the end,
    /// and on an error: what could not be read is not there for a program
    /// either.
    fn next_entry(&mut self) -> Option<(CString, u8)> {
        loop {
            // SAFETY: a stream opened by fdopendir and not closed yet; the
            // entry is copied out before the next call can overwrite it.
            let entry = unsafe { libc::readdir(self.0) };
            if entry.is_null() {
                return None;
            }
            // SAFETY: readdir returned a valid entry with a NUL-terminated
            // name.
            let (name, kind) = unsafe {
                (
                    CStr::from_ptr((*entry).d_name.as_ptr()).to_owned(),
                    (*entry).d_type,
                )
            };
            if name.as_bytes() != b"." && name.as_bytes() != b".." {
                return Some((name, kind));
            }
        }
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        // SAFETY: opened by fdopendir, closed once, here.
        unsafe {
            libc::closedir(self.0);
        }
    }
}

/// A directory opened below `parent` (or at an absolute path, `AT_FDCWD`),
/// for reading only. `follow` only for the places themselves: `/var/run` is a
/// link to `/run`, and what a program reaches there is what is behind it.
/// Below them, never.
fn open_dir_at(parent: RawFd, name: &CStr, follow: bool) -> io::Result<OwnedFd> {
    let mut flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NONBLOCK;
    if !follow {
        flags |= libc::O_NOFOLLOW;
    }
    // SAFETY: a NUL-terminated name and constant flags.
    let fd = unsafe { libc::openat(parent, name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a descriptor just opened and owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `fstatat(2)` without following a link.
fn stat_at(dir: RawFd, name: &CStr) -> Option<libc::stat> {
    // SAFETY: stat is plain data filled in by the kernel.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid descriptor (or AT_FDCWD), a NUL-terminated name and a
    // stat to fill.
    let rc = unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    (rc == 0).then_some(st)
}

fn fd_stat(fd: RawFd) -> Option<libc::stat> {
    // SAFETY: as in stat_at.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid descriptor and a stat to fill.
    (unsafe { libc::fstat(fd, &mut st) } == 0).then_some(st)
}

fn dev_of(st: &libc::stat) -> Dev {
    (libc::major(st.st_dev), libc::minor(st.st_dev))
}

/// Is the directory behind `fd` on a filesystem the walk must not read?
fn fd_is_slow(fd: RawFd) -> bool {
    // SAFETY: statfs is plain data filled in by the kernel.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: a valid descriptor and a statfs to fill.
    if unsafe { libc::fstatfs(fd, &mut st) } != 0 {
        return true;
    }
    #[allow(clippy::unnecessary_cast)]
    slow_magic(st.f_type as i64)
}

/// A socket at `name` below `dir` that this process may connect to: its
/// device and inode. Connecting to a unix socket by path takes write
/// permission on it; `faccessat` without flags checks with the real ids and,
/// for a user other than root, without capabilities — the program's case.
fn reachable_socket(dir: RawFd, name: &CStr) -> Option<(Dev, u64)> {
    let st = stat_at(dir, name)?;
    if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return None;
    }
    // SAFETY: a valid descriptor (or AT_FDCWD) and a NUL-terminated name.
    if unsafe { libc::faccessat(dir, name.as_ptr(), libc::W_OK, 0) } != 0 {
        return None;
    }
    Some((dev_of(&st), st.st_ino))
}

fn joined(base: &[u8], name: &[u8]) -> Vec<u8> {
    let mut path = base.to_vec();
    if path.last() != Some(&b'/') {
        path.push(b'/');
    }
    path.extend_from_slice(name);
    path
}

/// Open `rel` below `root`, one component at a time, never through a link.
fn open_below(root: &OwnedFd, rel: &[CString]) -> Option<OwnedFd> {
    let mut current: Option<OwnedFd> = None;
    for name in rel {
        let parent = current
            .as_ref()
            .map_or(root.as_raw_fd(), AsRawFd::as_raw_fd);
        current = Some(open_dir_at(parent, name, false).ok()?);
    }
    current
}

/// Walk `places`, each `(path, depth)`, then look at `known` by name. `slow`
/// are mount points not to enter ([`slow_points`]).
pub fn walk(
    places: &[(PathBuf, usize)],
    known: &[PathBuf],
    slow: &HashSet<Vec<u8>>,
    limits: Limits,
) -> Walk {
    let started = Instant::now();
    let mut out = Walk::default();
    let mut seen_dirs: HashSet<(Dev, u64)> = HashSet::new();
    let mut seen_sockets: HashSet<(Dev, u64)> = HashSet::new();
    let mut stopped = false;

    for (place, depth) in places {
        let place_bytes = place.as_os_str().as_bytes();
        if stopped {
            out.incomplete
                .push(format!("{} не просмотрен", place.display()));
            continue;
        }
        if slow.contains(place_bytes) {
            continue;
        }
        let Ok(c) = CString::new(place_bytes) else {
            continue;
        };
        // Absent or unreadable: a program finds nothing there by listing
        // either (and the known names are looked at below).
        let Ok(root) = open_dir_at(libc::AT_FDCWD, &c, true) else {
            continue;
        };
        if fd_is_slow(root.as_raw_fd()) {
            continue;
        }
        let Some(st) = fd_stat(root.as_raw_fd()) else {
            continue;
        };
        if !seen_dirs.insert((dev_of(&st), st.st_ino)) {
            continue;
        }
        let mut queue: VecDeque<(Vec<CString>, usize)> = VecDeque::new();
        queue.push_back((Vec::new(), 0));
        while let Some((rel, level)) = queue.pop_front() {
            let fd = if rel.is_empty() {
                match root.try_clone() {
                    Ok(fd) => fd,
                    Err(_) => continue,
                }
            } else {
                // Gone, replaced by a link, or not ours to read: skipped, as
                // a program's listing would skip it.
                let Some(fd) = open_below(&root, &rel) else {
                    continue;
                };
                if fd_is_slow(fd.as_raw_fd()) {
                    continue;
                }
                let Some(st) = fd_stat(fd.as_raw_fd()) else {
                    continue;
                };
                if !seen_dirs.insert((dev_of(&st), st.st_ino)) {
                    continue;
                }
                fd
            };
            let Ok(mut dir) = Dir::from_fd(fd) else {
                continue;
            };
            let dir_path = rel.iter().fold(place_bytes.to_vec(), |path, name| {
                joined(&path, name.as_bytes())
            });
            while let Some((name, kind)) = dir.next_entry() {
                out.entries += 1;
                if out.entries > limits.entries || started.elapsed() > limits.deadline {
                    stopped = true;
                    break;
                }
                let kind = if kind == libc::DT_UNKNOWN {
                    match stat_at(dir.fd(), &name).map(|st| st.st_mode & libc::S_IFMT) {
                        Some(libc::S_IFSOCK) => libc::DT_SOCK,
                        Some(libc::S_IFDIR) => libc::DT_DIR,
                        _ => continue,
                    }
                } else {
                    kind
                };
                if kind == libc::DT_SOCK {
                    if let Some((dev, ino)) = reachable_socket(dir.fd(), &name) {
                        if seen_sockets.insert((dev, ino)) {
                            out.found.push(Found {
                                path: joined(&dir_path, name.as_bytes()),
                                dev,
                            });
                        }
                    }
                } else if kind == libc::DT_DIR && level < *depth {
                    let child = joined(&dir_path, name.as_bytes());
                    if !slow.contains(&child) {
                        let mut below = rel.clone();
                        below.push(name);
                        queue.push_back((below, level + 1));
                    }
                }
            }
            if stopped {
                let why = if out.entries > limits.entries {
                    format!("после {} записей", limits.entries)
                } else {
                    format!("через {} с", limits.deadline.as_secs())
                };
                out.incomplete.push(format!(
                    "{} просмотрен не весь: остановлено {why}",
                    place.display()
                ));
                break;
            }
        }
    }

    for path in known {
        let Ok(c) = CString::new(path.as_os_str().as_bytes()) else {
            continue;
        };
        if let Some((dev, ino)) = reachable_socket(libc::AT_FDCWD, &c) {
            if seen_sockets.insert((dev, ino)) {
                out.found.push(Found {
                    path: path.as_os_str().as_bytes().to_vec(),
                    dev,
                });
            }
        }
    }
    out.found.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

// --- WHAT EACH ONE IS -----------------------------------------------------------

/// What a socket found in the zone is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The zone's own: bound by a process of the zone, or one of ours bound
    /// in (the filters, the broker, the restricted Wayland sockets).
    Own(&'static str),
    /// A service of the system that does nothing for the caller beyond
    /// taking what it is given: the journal, sd_notify, user lookups.
    System(&'static str),
    /// A helper outside, in reach: named every time (`warn`).
    Open(&'static str),
    /// In reach although the project promises it is not (`fail`).
    Closed(&'static str),
}

impl Verdict {
    pub fn level(self) -> Level {
        match self {
            Self::Own(_) | Self::System(_) => Level::Ok,
            Self::Open(_) => Level::Warn,
            Self::Closed(_) => Level::Fail,
        }
    }
}

/// What the classification needs to know about the zone.
#[derive(Debug, Clone, Default)]
pub struct Context {
    /// `/run/user/<uid>`.
    pub runtime: PathBuf,
    /// The zone is to be hermetic: the host's session bus and `systemd --user`
    /// are promised out of reach.
    pub hermetic: bool,
    /// The zone is let reach the Nix daemon.
    pub nix_daemon: bool,
    /// The zone's `/proc/self/mountinfo`: which of our sockets is bound where.
    pub mountinfo: String,
    /// [`own_devs`].
    pub own_devs: HashSet<Dev>,
}

/// What `path`, a socket on `dev`, is to a zone described by `ctx`.
pub fn classify(path: &[u8], dev: Dev, ctx: &Context) -> Verdict {
    let p = Path::new(OsStr::from_bytes(path));
    // Made in the zone: a nested compositor's `wayland-1` in the zone's own
    // runtime directory, a tmux server in a hermetic zone's own /tmp, the
    // zone's own X server. Nobody outside listens on a filesystem only the
    // zone has.
    if ctx.own_devs.contains(&dev) {
        return Verdict::Own("сделан в зоне");
    }
    if crate::doctor::RESOLVER_SOCKETS
        .iter()
        .any(|r| p == Path::new(r))
    {
        return Verdict::Closed("резолвер хоста — имена мимо туннеля");
    }
    if p.starts_with(crate::zone::SYSTEM_TIER_DIR) {
        return Verdict::Closed(
            "посредник системного уровня: запуск в системной зоне — мимо туннеля (§14)",
        );
    }
    if p.starts_with(crate::zone::NIX_DAEMON_DIR) {
        return if ctx.nix_daemon {
            Verdict::Open("Nix-демон хоста — зоне разрешён: сборка и загрузка идут в сети хоста")
        } else {
            Verdict::Closed(
                "Nix-демон хоста: производная с фиксированным хешем качает любой адрес \
                 в сети хоста (зоне он не разрешён)",
            )
        };
    }
    if p.starts_with(crate::x11::X11_DIR) {
        return Verdict::Closed("X-сервер хоста: окна, ввод и буфер обмена всей машины (§7)");
    }
    if let Ok(rest) = p.strip_prefix(&ctx.runtime) {
        if let Some(verdict) = runtime_verdict(rest, p, ctx) {
            return verdict;
        }
    }
    if p == Path::new(crate::zone::SYSTEM_BUS) {
        return if crate::doctor::mounted_at(&ctx.mountinfo, crate::zone::SYSTEM_BUS) {
            Verdict::Own("фильтр системной шины")
        } else {
            Verdict::Open("системная шина хоста без фильтра: NetworkManager, hostname1 (§3)")
        };
    }
    if p.starts_with("/run/systemd/journal") {
        return Verdict::System("журнал");
    }
    if p == Path::new("/run/systemd/notify") {
        return Verdict::System("sd_notify");
    }
    if p.starts_with("/run/systemd/userdb") {
        return Verdict::System("userdb");
    }
    if p.starts_with("/nix/var/nix/gc-socket") {
        return Verdict::System("сборщик мусора Nix");
    }
    Verdict::Open(describe(p))
}

/// The runtime directory's entries by name; `None` for what is not one of
/// them.
fn runtime_verdict(rest: &Path, full: &Path, ctx: &Context) -> Option<Verdict> {
    let first = rest
        .components()
        .next()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .unwrap_or_default();
    if crate::zone::compositor_private(&first) {
        return Some(Verdict::Closed(
            "композитор хоста: экран, буфер обмена, ввод — или запуск процесса на хосте (§13)",
        ));
    }
    if first.starts_with("pipewire-") && first.ends_with("-manager") {
        return Some(Verdict::Closed(
            "PipeWire без ограничений: любой клиент и поток (§17)",
        ));
    }
    if rest == Path::new("bus") {
        return Some(if crate::zone::bus_is_zones_filter(&ctx.mountinfo, full) {
            Verdict::Own("фильтр сессионной шины")
        } else if ctx.hermetic {
            Verdict::Closed(
                "сессионная шина хоста в герметичной зоне: systemd --user и порталы — \
                 запуск процесса вне зоны (§1–2)",
            )
        } else {
            Verdict::Open(
                "сессионная шина хоста: порталы и systemd --user — запуск вне зоны (§1–2)",
            )
        });
    }
    if first == "systemd" {
        return Some(if ctx.hermetic {
            Verdict::Closed("systemd --user в герметичной зоне: запуск процесса вне зоны (§1)")
        } else {
            Verdict::Open("systemd --user: запуск процесса вне зоны (§1)")
        });
    }
    if rest == Path::new("pulse/native") {
        return Some(
            if crate::zone::pulse_is_zones_filter(&ctx.mountinfo, full) {
                Verdict::Own("фильтр pulse")
            } else {
                Verdict::Closed(
                    "звуковой сервер хоста без фильтра: модуль, соединяющийся наружу (§17)",
                )
            },
        );
    }
    if rest == Path::new("pipewire-0") {
        return Some(Verdict::Own("pipewire-0"));
    }
    if rest == Path::new(crate::broker::SOCKET) {
        return Some(Verdict::Own("брокер"));
    }
    if rest.starts_with(crate::wl_sandbox::SOCKET_DIR) {
        return Some(Verdict::Own("ограниченный Wayland"));
    }
    if rest.starts_with(crate::fs_sandbox::SCRATCH_SUBDIR) {
        return Some(Verdict::Own("песочницы зоны"));
    }
    None
}

/// What a helper outside probably is, by its path — only words for the
/// report; the level does not depend on them.
fn describe(p: &Path) -> &'static str {
    let s = p.to_string_lossy().to_lowercase();
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let any = |words: &[&str]| words.iter().any(|w| s.contains(w));
    // The first that fits. Order matters where two could: an ssh agent in
    // `~/.ssh` is an agent, `S.gpg-agent.ssh` is one too.
    if name == "S.gpg-agent.ssh" || any(&["/keyring/ssh", "/ssh-agent", "/ssh-auth"]) {
        "ssh-агент: вход на машины вашими ключами"
    } else if s.contains("dhcpcd") {
        "dhcpcd: интерфейсы, адреса и аренды хоста (§3)"
    } else if s.starts_with("/run/ssh-unix-local/") {
        "sshd хоста по unix-сокету (systemd-ssh-generator): вход на хост, если есть ключ или \
         пароль"
    } else if s.contains("/.ssh/") {
        "ssh: мастер-соединение (ControlMaster) — команда на удалённой машине от вашего имени"
    } else if name.starts_with("S.gpg-agent") || name.starts_with("S.keyboxd") {
        "gpg: подпись и расшифровка вашими ключами"
    } else if s.contains("/tmux-") {
        "сервер tmux: `run-shell` исполняет команду на хосте, в его сети (§15)"
    } else if s.contains("vpn-fs-sandbox") {
        "фильтр шины чужой песочницы: шина от имени чужой программы (§15)"
    } else if any(&["docker", "podman", "containerd"]) {
        "контейнерный движок: контейнер в сети хоста"
    } else if any(&["libvirt", "virtqemud", "incus", "lxd"]) {
        "виртуальные машины: машина в сети хоста"
    } else if any(&[
        "tailscale",
        "amnezia",
        "openvpn",
        "mullvad",
        "nordvpn",
        "protonvpn",
    ]) {
        "клиент VPN хоста: включить, выключить, перенастроить VPN хоста (§15)"
    } else if s.contains("cups") {
        "CUPS: печать, в том числе на сетевые принтеры"
    } else if s.contains("/at-spi/") {
        "шина специальных возможностей: чтение и управление окнами других программ"
    } else if s.contains("polkit") {
        "polkit: помощник агента аутентификации"
    } else if name == "SingletonSocket" {
        "«единственный экземпляр» Chromium или Electron: окно в процессе вне зоны (§15)"
    } else if any(&["keepassxc", "bitwarden", "1password"]) {
        "менеджер паролей: интеграция с браузером"
    } else if any(&["emacs", "nvim", "/zed", "vscode"]) {
        "сервер редактора: файл или команда на хосте"
    } else if name == "io.systemd.Hostname" {
        "hostnamed по varlink: имя, модель и id машины — то, что системная шина зоне не \
         отдаёт (§3)"
    } else if name == "io.systemd.Network" {
        "networkd по varlink: интерфейсы и адреса хоста (§3)"
    } else if s.starts_with("/run/systemd/") {
        "служба systemd по varlink: что она сделает для подключившегося, решают она и polkit"
    } else {
        "помощник вне зоны: что он сделает для подключившегося, проверка не знает"
    }
}

/// A path for a report line: printable, a control character or a byte that is
/// not UTF-8 written out, so that no name a program chose can break the
/// probe's line or pass for another path.
pub fn shown(path: &[u8]) -> String {
    let mut out = String::new();
    for chunk in path.utf8_chunks() {
        for c in chunk.valid().chars() {
            if c.is_control() || c == '\\' {
                out.push_str(&c.escape_unicode().to_string());
            } else {
                out.push(c);
            }
        }
        for byte in chunk.invalid() {
            out.push_str(&format!("\\x{byte:02x}"));
        }
    }
    out
}

/// The checks: `sockets`, the summary; `tmp-sockets`, what of it is in the
/// temporary directories (the check of `docs/LEAK-MODEL.md` §15, kept by its
/// name); one `socket` per socket that is not the zone's own or the system's,
/// `<path> — <what it is>`, at its level.
pub fn checks(walk: &Walk, ctx: &Context, groups_shed: bool) -> Vec<Check> {
    let mut own: BTreeMap<&str, usize> = BTreeMap::new();
    let mut system: BTreeMap<&str, usize> = BTreeMap::new();
    let mut lines = Vec::new();
    let mut in_tmp = Vec::new();
    for found in &walk.found {
        let verdict = classify(&found.path, found.dev, ctx);
        match verdict {
            Verdict::Own(label) => *own.entry(label).or_default() += 1,
            Verdict::System(label) => *system.entry(label).or_default() += 1,
            Verdict::Open(what) | Verdict::Closed(what) => {
                let path = Path::new(OsStr::from_bytes(&found.path));
                if crate::doctor::TMP_DIRS.iter().any(|d| path.starts_with(d))
                    && !path.starts_with(crate::x11::X11_DIR)
                {
                    in_tmp.push(shown(&found.path));
                }
                lines.push(Check::new(
                    "socket",
                    verdict.level(),
                    format!("{} — {what}", shown(&found.path)),
                ));
            }
        }
    }
    let counted = |map: &BTreeMap<&str, usize>| {
        map.iter()
            .map(|(label, n)| {
                if *n > 1 {
                    format!("{label} ×{n}")
                } else {
                    (*label).to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let total = |map: &BTreeMap<&str, usize>| map.values().sum::<usize>();
    let mut detail = String::new();
    detail.push_str(&if lines.is_empty() {
        "чужих сокетов в досягаемости нет".to_owned()
    } else {
        format!(
            "чужих сокетов в досягаемости: {} (строки socket)",
            lines.len()
        )
    });
    if !own.is_empty() {
        detail.push_str(&format!("; своих {}: {}", total(&own), counted(&own)));
    }
    if !system.is_empty() {
        detail.push_str(&format!(
            "; системных {}: {}",
            total(&system),
            counted(&system)
        ));
    }
    detail.push_str(&format!("; просмотрено записей: {}", walk.entries));
    if !walk.incomplete.is_empty() {
        detail.push_str(&format!(
            "; перечень НЕПОЛНЫЙ — {}",
            walk.incomplete.join(", ")
        ));
    }
    if !groups_shed {
        detail.push_str("; группы сеанса не сняты — доступ проверен шире, чем у программ зоны");
    }
    let mut level = lines.iter().map(|c| c.level).max().unwrap_or(Level::Ok);
    if !walk.incomplete.is_empty() {
        level = level.max(Level::Warn);
    }
    let mut out = vec![
        Check::new("sockets", level, detail),
        crate::doctor::listed_channel_check(
            "tmp-sockets",
            &in_tmp,
            "сокеты во временных каталогах — где /tmp общий с хостом, это сокеты хоста и \
             других зон: сервер tmux (`run-shell` — команда на хосте, в его сети), IPC \
             клиентов VPN (§15); у герметичной зоны /tmp свой",
        ),
    ];
    out.extend(lines);
    out
}

/// The places for a user whose home is `home`, in the order they are walked.
pub fn places(home: Option<&Path>) -> Vec<(PathBuf, usize)> {
    let mut out: Vec<(PathBuf, usize)> = PLACES[..5]
        .iter()
        .map(|(p, d)| (PathBuf::from(p), *d))
        .collect();
    if let Some(home) = home.filter(|h| h.is_absolute()) {
        out.push((home.to_path_buf(), HOME_DEPTH));
    }
    out.extend(PLACES[5..].iter().map(|(p, d)| (PathBuf::from(p), *d)));
    out
}

/// The well-known names for a user whose runtime directory is `runtime`.
pub fn known(runtime: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = KNOWN.iter().map(PathBuf::from).collect();
    out.extend(crate::doctor::RESOLVER_SOCKETS.iter().map(PathBuf::from));
    // The broker too: in a zone its directory is the holder's, which a
    // program may pass through but not list (seen in the VM, 2026-09-25).
    for name in [
        "bus",
        "systemd/private",
        "pulse/native",
        crate::broker::SOCKET,
    ] {
        out.push(runtime.join(name));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vz-sockinv-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn is_root() -> bool {
        // SAFETY: geteuid(2) takes no arguments and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }

    fn paths(walk: &Walk) -> Vec<String> {
        walk.found
            .iter()
            .map(|f| String::from_utf8_lossy(&f.path).into_owned())
            .collect()
    }

    #[test]
    fn the_walk_finds_what_a_program_may_connect_to_and_nothing_else() {
        let dir = scratch("walk");
        let d = dir.display().to_string();
        for sub in ["a/b/c", "linked", "slow", "closed"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        let _top = UnixListener::bind(dir.join("top.sock")).unwrap();
        let _deep = UnixListener::bind(dir.join("a/b/in-reach")).unwrap();
        let _too_deep = UnixListener::bind(dir.join("a/b/c/too-deep")).unwrap();
        let _behind_link = UnixListener::bind(dir.join("linked/behind")).unwrap();
        let _slow = UnixListener::bind(dir.join("slow/hidden")).unwrap();
        let _mode0 = UnixListener::bind(dir.join("no-write")).unwrap();
        fs::set_permissions(dir.join("no-write"), fs::Permissions::from_mode(0o444)).unwrap();
        let _closed = UnixListener::bind(dir.join("closed/inside")).unwrap();
        fs::set_permissions(dir.join("closed"), fs::Permissions::from_mode(0o000)).unwrap();
        // A link to a directory with a socket, and a FIFO: neither followed
        // nor opened — the walk would hang on the FIFO if it opened it.
        std::os::unix::fs::symlink(dir.join("linked"), dir.join("a/link")).unwrap();
        let fifo = CString::new(dir.join("fifo").as_os_str().as_bytes()).unwrap();
        // SAFETY: a NUL-terminated path and a mode.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        fs::write(dir.join("plain"), "").unwrap();

        let slow: HashSet<Vec<u8>> = [format!("{d}/slow").into_bytes()].into();
        // `linked` is walked where it is itself, never through `a/link`.
        let walk = super::walk(&[(dir.clone(), 2)], &[], &slow, LIMITS);
        let found = paths(&walk);
        assert!(found.contains(&format!("{d}/top.sock")), "{found:?}");
        assert!(found.contains(&format!("{d}/a/b/in-reach")), "{found:?}");
        assert!(found.contains(&format!("{d}/linked/behind")), "{found:?}");
        assert!(!found.iter().any(|p| p.ends_with("too-deep")), "{found:?}");
        assert!(!found.iter().any(|p| p.contains("/a/link/")), "{found:?}");
        assert!(!found.iter().any(|p| p.ends_with("hidden")), "{found:?}");
        if !is_root() {
            assert!(!found.iter().any(|p| p.ends_with("no-write")), "{found:?}");
            assert!(!found.iter().any(|p| p.ends_with("inside")), "{found:?}");
        }
        assert!(walk.incomplete.is_empty(), "{:?}", walk.incomplete);

        // The same place twice (as /var/run and /run) is walked once, and a
        // well-known name already found is not named again.
        let twice = super::walk(
            &[(dir.clone(), 0), (dir.clone(), 0)],
            &[dir.join("top.sock")],
            &HashSet::new(),
            LIMITS,
        );
        assert_eq!(
            paths(&twice)
                .iter()
                .filter(|p| p.ends_with("top.sock"))
                .count(),
            1
        );
        // A well-known name the walk did not reach is found by name.
        let named = super::walk(&[], &[dir.join("a/b/c/too-deep")], &HashSet::new(), LIMITS);
        assert_eq!(paths(&named), [format!("{d}/a/b/c/too-deep")]);

        // Out of budget: said, never silent.
        let tight = Limits {
            entries: 2,
            deadline: LIMITS.deadline,
        };
        let cut = super::walk(
            &[(dir.clone(), 2), (PathBuf::from("/nonexistent-vz"), 1)],
            &[],
            &HashSet::new(),
            tight,
        );
        assert_eq!(cut.incomplete.len(), 2, "{:?}", cut.incomplete);

        fs::set_permissions(dir.join("closed"), fs::Permissions::from_mode(0o700)).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mountinfo_gives_devices_points_and_types() {
        let info = "36 25 0:32 / /run/user/1000 rw,nosuid - tmpfs tmpfs rw\n\
                    37 25 0:40 / /run/user/1000/doc rw shared:9 - fuse.portal portal rw\n\
                    38 25 0:41 / /mnt/with\\040blank rw - nfs4 srv:/x rw\n\
                    39 25 259:2 /@home /home rw - btrfs /dev/x rw\n";
        let all = mounts(info);
        assert_eq!(all.len(), 4);
        assert_eq!(all[0].dev, (0, 32));
        assert_eq!(all[2].point, b"/mnt/with blank");
        assert_eq!(all[1].fstype, "fuse.portal");
        let slow = slow_points(info);
        assert!(slow.contains(b"/run/user/1000/doc".as_slice()));
        assert!(slow.contains(b"/mnt/with blank".as_slice()));
        assert!(!slow.contains(b"/home".as_slice()));
        assert!(slow_fs("autofs") && slow_fs("fuse.sshfs") && slow_fs("9p"));
        assert!(!slow_fs("tmpfs") && !slow_fs("btrfs") && !slow_fs("overlay"));
        assert_eq!(parse_dev("259:2"), Some((259, 2)));
        assert_eq!(parse_dev("x"), None);
    }

    #[test]
    fn only_a_tmpfs_the_host_does_not_have_is_the_zones_own() {
        let runtime = Path::new("/run/user/1000");
        let zone = "1 0 0:30 / /tmp rw - tmpfs tmpfs rw\n\
                    2 0 0:50 / /tmp rw - tmpfs tmpfs rw\n\
                    3 0 0:51 / /run/user/1000 rw - tmpfs tmpfs rw\n\
                    4 0 0:52 / /srv/other rw - tmpfs tmpfs rw\n\
                    5 0 0:31 / /run/user/1000 rw - tmpfs tmpfs rw\n\
                    6 0 0:53 / /tmp/.X11-unix rw - tmpfs tmpfs rw\n";
        let host: HashSet<Dev> = [(0, 30), (0, 31)].into();
        let own = own_devs(zone, runtime, Some(&host));
        assert_eq!(own, [(0, 50), (0, 51), (0, 53)].into());
        // Without the host's devices nothing is the zone's own.
        assert!(own_devs(zone, runtime, None).is_empty());
    }

    fn ctx() -> Context {
        Context {
            runtime: PathBuf::from("/run/user/1000"),
            ..Context::default()
        }
    }

    #[test]
    fn the_zones_own_sockets_are_not_named() {
        let host = (0, 31);
        let mut c = ctx();
        c.mountinfo = "30 29 8:2 /h/.local/state/vpn-zones/nl/session-bus-filter /run/user/1000/bus rw - ext4 /dev/x rw\n\
                       31 29 8:2 /h/.local/state/vpn-zones/nl/pulse-filter /run/user/1000/pulse/native rw - ext4 /dev/x rw\n\
                       32 29 8:2 /h/.local/state/vpn-zones/nl/system-bus /run/dbus/system_bus_socket rw - ext4 /dev/x rw\n"
            .to_owned();
        for path in [
            "/run/user/1000/bus",
            "/run/user/1000/pulse/native",
            "/run/user/1000/pipewire-0",
            "/run/user/1000/vpn-zones/broker",
            "/run/user/1000/vpn-zones/wayland/nl/wayland-0-17",
            "/run/user/1000/vpn-zones/sandbox/x/bus",
            "/run/dbus/system_bus_socket",
        ] {
            assert!(
                matches!(classify(path.as_bytes(), host, &c), Verdict::Own(_)),
                "{path}"
            );
        }
        for path in [
            "/run/systemd/journal/socket",
            "/run/systemd/journal/stdout",
            "/run/systemd/notify",
            "/run/systemd/userdb/io.systemd.DynamicUser",
        ] {
            assert_eq!(
                classify(path.as_bytes(), host, &c).level(),
                Level::Ok,
                "{path}"
            );
        }
        // Made in the zone: its own, even under a name the host's would have.
        c.own_devs = [(0, 50)].into();
        assert!(matches!(
            classify(b"/run/user/1000/wayland-1", (0, 50), &c),
            Verdict::Own(_)
        ));
        assert!(matches!(
            classify(b"/tmp/tmux-1000/default", (0, 50), &c),
            Verdict::Own(_)
        ));
    }

    #[test]
    fn what_the_project_promises_closed_fails_and_the_rest_warns() {
        let host = (0, 31);
        let mut c = ctx();
        let level = |path: &str, c: &Context| classify(path.as_bytes(), host, c).level();
        for path in [
            "/run/user/1000/wayland-1",
            "/run/user/1000/niri.wayland-1.42.sock",
            "/run/user/1000/pipewire-0-manager",
            "/run/user/1000/pulse/native",
            "/run/vpn-zones/sysrun.sock",
            "/nix/var/nix/daemon-socket/socket",
            "/run/systemd/resolve/io.systemd.Resolve",
            "/tmp/.X11-unix/X0",
        ] {
            assert_eq!(level(path, &c), Level::Fail, "{path}");
        }
        // The session bus and systemd --user: open by design in an ordinary
        // zone, promised closed in a hermetic one.
        assert_eq!(level("/run/user/1000/bus", &c), Level::Warn);
        assert_eq!(level("/run/user/1000/systemd/private", &c), Level::Warn);
        c.hermetic = true;
        assert_eq!(level("/run/user/1000/bus", &c), Level::Fail);
        assert_eq!(level("/run/user/1000/systemd/private", &c), Level::Fail);
        // The Nix daemon, once the zone is let: named, not failed.
        c.nix_daemon = true;
        assert_eq!(level("/nix/var/nix/daemon-socket/socket", &c), Level::Warn);
        for path in [
            "/home/alice/.ssh/master-alice@host:22",
            "/run/tailscale/tailscaled.sock",
            "/run/docker.sock",
            "/run/user/1000/gnupg/S.gpg-agent",
            "/run/user/1000/at-spi/bus_0",
            "/run/systemd/io.systemd.Hostname",
            "/tmp/tmux-1000/default",
            "/var/lib/whatever/x.sock",
            "/run/dbus/system_bus_socket",
        ] {
            assert_eq!(level(path, &c), Level::Warn, "{path}");
        }
    }

    #[test]
    fn a_name_a_program_chose_cannot_forge_a_line() {
        assert_eq!(shown(b"/tmp/a b"), "/tmp/a b");
        let forged = shown(b"/tmp/x\tfail\tlinks\nlinks\tok\t\\\xff");
        assert!(!forged.contains('\t') && !forged.contains('\n'), "{forged}");
        assert!(
            forged.contains("\\u{9}") && forged.contains("\\xff"),
            "{forged}"
        );
    }

    #[test]
    fn the_summary_and_the_lines_say_what_is_in_reach() {
        let c = ctx();
        let walk = Walk {
            found: vec![
                Found {
                    path: b"/run/user/1000/pipewire-0".to_vec(),
                    dev: (0, 31),
                },
                Found {
                    path: b"/run/systemd/journal/socket".to_vec(),
                    dev: (0, 25),
                },
                Found {
                    path: b"/tmp/evil.sock".to_vec(),
                    dev: (0, 30),
                },
                Found {
                    path: b"/run/user/1000/wayland-1".to_vec(),
                    dev: (0, 31),
                },
            ],
            entries: 10,
            incomplete: Vec::new(),
        };
        let checks = checks(&walk, &c, true);
        assert_eq!(checks[0].id, "sockets");
        assert_eq!(checks[0].level, Level::Fail);
        assert!(
            checks[0].detail.contains("pipewire-0"),
            "{}",
            checks[0].detail
        );
        assert!(checks[0].detail.contains("журнал"), "{}", checks[0].detail);
        assert_eq!(checks[1].id, "tmp-sockets");
        assert_eq!(checks[1].level, Level::Warn);
        assert!(checks[1].detail.contains("/tmp/evil.sock"));
        let lines: Vec<&Check> = checks.iter().filter(|c| c.id == "socket").collect();
        assert_eq!(lines.len(), 2);
        assert!(
            lines[0].detail.starts_with("/tmp/evil.sock — "),
            "{}",
            lines[0].detail
        );
        assert_eq!(lines[1].level, Level::Fail);

        // Nothing foreign, everything seen: ok. Something unseen: warn.
        let clean = Walk {
            found: walk.found[..2].to_vec(),
            entries: 2,
            incomplete: Vec::new(),
        };
        assert_eq!(checks_level(&clean, &c), Level::Ok);
        let unseen = Walk {
            incomplete: vec!["/var/lib не просмотрен".to_owned()],
            ..clean
        };
        assert_eq!(checks_level(&unseen, &c), Level::Warn);
    }

    fn checks_level(walk: &Walk, c: &Context) -> Level {
        checks(walk, c, true)[0].level
    }

    #[test]
    fn places_put_the_home_between_the_small_and_the_big() {
        let all = places(Some(Path::new("/home/alice")));
        let names: Vec<String> = all.iter().map(|(p, _)| p.display().to_string()).collect();
        assert_eq!(
            names,
            [
                "/run",
                "/var/run",
                "/tmp",
                "/var/tmp",
                "/dev/shm",
                "/home/alice",
                "/nix/var",
                "/var/lib"
            ]
        );
        assert_eq!(places(Some(Path::new("relative"))).len(), PLACES.len());
        assert!(known(Path::new("/run/user/1000")).contains(&PathBuf::from("/run/user/1000/bus")));
    }
}
