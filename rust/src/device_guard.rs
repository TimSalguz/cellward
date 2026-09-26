//! What a zone's holder does about a device it hides once the device is gone
//! (`docs/PERMISSIONS.md` §11.12).
//!
//! A node goes with its device, a reference to its inode does not: a
//! sandbox's bind of it (`fs-sandbox --device`), a descriptor — an `O_PATH`
//! one too, reopened through `/proc/self/fd` — and a bind a program made of
//! it in a namespace of its own. Such a reference opens whatever device the
//! number is given next, and the kernel gives the lowest free one: a keyboard
//! plugged in after a security key is taken out gets the key's `hidraw`.
//!
//! **When it goes** — `/dev/null` over its path wherever the zone's programs
//! still have it bound ([`revoke_everywhere`]), the bind taken away first:
//! nothing mounts over a bind of an unlinked node.
//!
//! **When its number is given again** — every program of the zone that still
//! holds the gone node, by a descriptor on its inode or a bind of it in its
//! namespace, is killed ([`Worker::appeared`]), unless the device given the
//! number is the very same ([`identity`]: the kernel's word on it — the
//! gamepad back after its battery died). What the kernel hands out before the
//! node appears is in such a program's reach until it is killed:
//! milliseconds, the time a device takes to show up in `/dev`.
//!
//! The zone's programs are the processes of its user namespace and of those
//! below it ([`zone_processes`]), whatever network namespace they made. It
//! all runs in a thread of its own ([`start`]), apart from the watch, which
//! covers a device plugged in at once. No clock decides anything: a look
//! into a namespace is waited for by nobody but the one who reports it —
//! a namespace a program made may stall it for good (a FUSE mount over its
//! `/dev`), a loaded machine may make it slow — and it is ended only by the
//! next look for the same node. What the sweep decides by is what is there
//! when the number is given again: a bind still there opens the new device,
//! and then its namespace's programs go, however slow the look was.
//!
//! What this does not hold: a descriptor passed out of the zone (to a
//! program of another zone that takes it); one in flight in a socket at the
//! moment of the sweep.

use std::ffi::CString;
use std::fs::{self, File};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex, MutexGuard};

/// A node as the holder saw it while it was there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// Its file system and inode: what a reference to it holds.
    pub dev: u64,
    pub ino: u64,
    /// Its device number.
    pub rdev: u64,
    /// The device behind it ([`identity`]); `None`: not known.
    pub identity: Option<String>,
}

/// `path` as it is now: a device node, not `/dev/null`.
pub fn seen(path: &Path) -> Option<Seen> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_char_device() {
        return None;
    }
    let rdev = meta.rdev();
    let (major, minor) = (libc::major(rdev), libc::minor(rdev));
    if (major, minor) == (1, 3) {
        return None;
    }
    Some(Seen {
        dev: meta.dev(),
        ino: meta.ino(),
        rdev,
        identity: identity(Path::new("/sys/dev/char"), major, minor),
    })
}

/// Which device the character device `major:minor` is, by what the kernel
/// says of it in sysfs (`sys_char`: `/sys/dev/char`): the USB device it is
/// on (vendor, product, serial), the interface, the HID device (bus, vendor,
/// product), the input device (its ids, its name, what it reports) — each
/// that it hangs off. The same text for the same device plugged in again, in
/// any port; `None` when none of them is there — a number no device has,
/// a device made up.
///
/// Not udev's word: the node appears before udev has looked at the device,
/// and this is read then.
pub fn identity(sys_char: &Path, major: u32, minor: u32) -> Option<String> {
    let node = fs::canonicalize(sys_char.join(format!("{major}:{minor}"))).ok()?;
    let read = |dir: &Path, file: &str| {
        fs::read_to_string(dir.join(file))
            .ok()
            .map(|s| s.trim().to_owned())
    };
    let mut parts: Vec<String> = Vec::new();
    let mut known = false;
    for dir in node.ancestors() {
        let name = dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name == "devices" {
            break;
        }
        if let (Some(vendor), Some(product)) = (read(dir, "idVendor"), read(dir, "idProduct")) {
            let serial = read(dir, "serial").unwrap_or_default();
            parts.push(format!("usb:{vendor}:{product}:{serial}"));
            known = true;
            break;
        }
        if let Some(number) = read(dir, "bInterfaceNumber") {
            parts.push(format!("if:{number}"));
        } else if hid_name(&name) {
            parts.push(format!("hid:{}", &name[..14]));
            known = true;
        } else if let (Some(bus), Some(vendor), Some(product)) = (
            read(dir, "id/bustype"),
            read(dir, "id/vendor"),
            read(dir, "id/product"),
        ) {
            parts.push(format!(
                "input:{bus}:{vendor}:{product}:{}:{}:{}",
                read(dir, "name").unwrap_or_default(),
                read(dir, "capabilities/ev").unwrap_or_default(),
                read(dir, "capabilities/key").unwrap_or_default(),
            ));
            known = true;
        }
    }
    if !known {
        return None;
    }
    // Made through uinput: never the same as a device of the machine.
    let made = node.to_string_lossy().contains("/devices/virtual/input/");
    Some(format!(
        "{}{}",
        if made { "made/" } else { "" },
        parts.join("/")
    ))
}

/// A HID device's directory: `<bus>:<vendor>:<product>.<instance>`, four hex
/// digits each.
fn hid_name(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() == 19
        && b.iter().enumerate().all(|(i, &c)| match i {
            4 | 9 => c == b':',
            14 => c == b'.',
            _ => c.is_ascii_hexdigit(),
        })
}

/// What the watch hands the worker.
#[derive(Debug)]
pub enum Job {
    /// A node gone, and what it was when it was there (`None`: not seen).
    Gone(PathBuf, Option<Seen>),
    /// A node there, new.
    Appeared(PathBuf, Seen),
}

/// The thread that does the looking into the zone's programs, and the way to
/// hand it work.
pub fn start(zone: String) -> mpsc::Sender<Job> {
    let (tx, rx) = mpsc::channel::<Job>();
    std::thread::spawn(move || {
        let mut worker = Worker {
            zone,
            gone: Vec::new(),
            looks: Arc::default(),
        };
        for job in rx {
            match job {
                Job::Gone(path, seen) => worker.gone(path, seen),
                Job::Appeared(path, seen) => worker.appeared(&path, &seen),
            }
        }
    });
    tx
}

struct Worker {
    zone: String,
    /// The nodes gone that a program of the zone may still hold: each until
    /// its number is given again.
    gone: Vec<(PathBuf, Seen)>,
    /// The looks into the zone's mount namespaces still running.
    looks: Looks,
}

/// The looks still running, by the node they are for: each held by a pidfd,
/// so that ending it never hits another process that got its number.
type Looks = Arc<Mutex<Running>>;
type Running = std::collections::HashMap<PathBuf, Vec<Arc<OwnedFd>>>;

fn locked(looks: &Looks) -> MutexGuard<'_, Running> {
    looks.lock().unwrap_or_else(|e| e.into_inner())
}

impl Worker {
    fn gone(&mut self, path: PathBuf, seen: Option<Seen>) {
        // A look for this node from before, still running: stuck in a
        // namespace a program made. This one replaces it.
        for older in locked(&self.looks).remove(&path).unwrap_or_default() {
            crate::sys::pidfd_signal(&older, libc::SIGKILL);
        }
        let (looks, failed) = revoke_everywhere(&path);
        if looks.is_empty() {
            report(&self.zone, &path, 0, &failed);
        } else {
            locked(&self.looks).insert(
                path.clone(),
                looks.iter().filter_map(|l| l.pidfd.clone()).collect(),
            );
            let (zone, at, all) = (self.zone.clone(), path.clone(), Arc::clone(&self.looks));
            std::thread::spawn(move || wait_looks(&zone, &at, looks, failed, &all));
        }
        if let Some(seen) = seen {
            self.gone.push((path, seen));
        }
    }

    /// `path` is there, `now`: if a node gone had its number, kill every
    /// program that holds such a node — unless it is the same device again.
    fn appeared(&mut self, path: &Path, now: &Seen) {
        let before: Vec<Seen> = self
            .gone
            .iter()
            .filter(|(_, s)| s.rdev == now.rdev)
            .map(|(_, s)| s.clone())
            .collect();
        if before.is_empty() {
            return;
        }
        let rel = path.strip_prefix("/dev").unwrap_or(path);
        let found = held(&zone_processes(), &before, rel);
        let foreign = |s: &Seen| s.identity.is_none() || s.identity != now.identity;
        let mut killed: Vec<i32> = Vec::new();
        for (pid, what) in &found.by_descriptor {
            if foreign(what) {
                killed.push(*pid);
            }
        }
        if !found.by_bind.is_empty() && before.iter().any(foreign) {
            killed.extend(&found.by_bind);
        }
        killed.sort_unstable();
        killed.dedup();
        for pid in &killed {
            // SAFETY: a signal to a process of the zone's.
            unsafe { libc::kill(*pid, libc::SIGKILL) };
        }
        if !killed.is_empty() {
            let pids: Vec<String> = killed.iter().map(i32::to_string).collect();
            eprintln!(
                "zone {}: {} is another device now, and these programs still held the one \
                 gone — killed: {}",
                self.zone,
                path.display(),
                pids.join(", ")
            );
        }
        // Kept: the same device's node, still held by a program left alive.
        let still: Vec<u64> = found
            .by_descriptor
            .iter()
            .filter(|(pid, _)| !killed.contains(pid))
            .map(|(_, s)| s.ino)
            .collect();
        let bound = !found.by_bind.is_empty() && !before.iter().any(foreign);
        self.gone.retain(|(_, s)| {
            s.rdev != now.rdev || (!foreign(s) && (bound || still.contains(&s.ino)))
        });
    }
}

/// A process of the zone's, with its mount namespace.
#[derive(Debug, Clone)]
pub struct Proc {
    pub pid: i32,
    pub mnt: Option<PathBuf>,
}

/// The zone's programs: every process — but this one — whose user namespace
/// is this one's, or below it.
pub fn zone_processes() -> Vec<Proc> {
    let Some(own) = ns_key(Path::new("/proc/self/ns/user")) else {
        return Vec::new();
    };
    let me = std::process::id() as i32;
    fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .filter(|&pid| pid != me && below(pid, own))
        .map(|pid| Proc {
            pid,
            mnt: fs::read_link(format!("/proc/{pid}/ns/mnt")).ok(),
        })
        .collect()
}

/// A namespace's file as `(dev, ino)`.
fn ns_key(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(path).ok()?;
    Some((meta.dev(), meta.ino()))
}

/// Whether `pid`'s user namespace is `own` or below it: its parents walked
/// up (`NS_GET_PARENT`), which ends where our view does.
fn below(pid: i32, own: (u64, u64)) -> bool {
    let Ok(file) = File::open(format!("/proc/{pid}/ns/user")) else {
        return false;
    };
    user_ns_below(file.into(), own)
}

/// Whether the mount namespace `mnt` belongs to a user namespace that is
/// `own` or below it: one of the zone's programs made it, or the zone did.
/// A process of the zone may sit in one that is not — the zone's first
/// process, still in the host's — where nothing of a program's is bound.
fn mounts_below(mnt: &File, own: (u64, u64)) -> bool {
    // SAFETY: an ioctl on a namespace descriptor; a new one or -1.
    let user = unsafe { libc::ioctl(mnt.as_raw_fd(), libc::NS_GET_USERNS) };
    if user < 0 {
        return false;
    }
    // SAFETY: the descriptor was just returned to us.
    user_ns_below(unsafe { OwnedFd::from_raw_fd(user) }, own)
}

/// Whether the user namespace `fd` is `own` or below it: its parents walked
/// up (`NS_GET_PARENT`), which ends where our view does.
fn user_ns_below(mut fd: OwnedFd, own: (u64, u64)) -> bool {
    // The kernel nests user namespaces 32 deep at most.
    for _ in 0..40 {
        // SAFETY: fstat of a descriptor we hold, into a zeroed struct.
        let key = unsafe {
            let mut st: libc::stat = std::mem::zeroed();
            (libc::fstat(fd.as_raw_fd(), &mut st) == 0).then_some((st.st_dev, st.st_ino))
        };
        if key == Some(own) {
            return true;
        }
        // SAFETY: an ioctl on a namespace descriptor; a new one or -1.
        let parent = unsafe { libc::ioctl(fd.as_raw_fd(), libc::NS_GET_PARENT) };
        if parent < 0 {
            return false;
        }
        // SAFETY: the descriptor was just returned to us.
        fd = unsafe { OwnedFd::from_raw_fd(parent) };
    }
    false
}

/// Who holds one of the nodes `gone` (all of one number, at `rel` below
/// `/dev`).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Held {
    /// A process with a descriptor on one of them, and which.
    pub by_descriptor: Vec<(i32, Seen)>,
    /// The processes of a mount namespace with a bind of such a node.
    pub by_bind: Vec<i32>,
}

fn held(procs: &[Proc], gone: &[Seen], rel: &Path) -> Held {
    let mut out = Held::default();
    for proc in procs {
        for entry in fs::read_dir(format!("/proc/{}/fd", proc.pid))
            .into_iter()
            .flatten()
            .flatten()
        {
            // Not synced: a descriptor on a FUSE file of the program's own
            // is not asked about — the answer is the inode's, cached.
            let Some(key) = stat_cached(&entry.path()) else {
                continue;
            };
            if let Some(s) = gone.iter().find(|s| (s.dev, s.ino) == key) {
                out.by_descriptor.push((proc.pid, s.clone()));
            }
        }
    }
    let mut looked: Vec<&Path> = Vec::new();
    for proc in procs {
        let Some(mnt) = proc.mnt.as_deref() else {
            continue;
        };
        if looked.contains(&mnt) {
            continue;
        }
        looked.push(mnt);
        let Ok(table) = fs::read_to_string(format!("/proc/{}/mountinfo", proc.pid)) else {
            continue;
        };
        if gone.iter().any(|s| bound_in(&table, s.dev, rel)) {
            out.by_bind.extend(
                procs
                    .iter()
                    .filter(|p| p.mnt.as_deref() == Some(mnt))
                    .map(|p| p.pid),
            );
        }
    }
    out
}

/// `(dev, ino)` of what `path` leads to, from what the kernel has cached.
fn stat_cached(path: &Path) -> Option<(u64, u64)> {
    let c = CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: statx into a zeroed struct, the path NUL-terminated.
    unsafe {
        let mut stx: libc::statx = std::mem::zeroed();
        if libc::statx(
            libc::AT_FDCWD,
            c.as_ptr(),
            libc::AT_STATX_DONT_SYNC,
            libc::STATX_INO,
            &mut stx,
        ) != 0
        {
            return None;
        }
        Some((
            libc::makedev(stx.stx_dev_major, stx.stx_dev_minor),
            stx.stx_ino,
        ))
    }
}

/// Whether a `mountinfo` table has a bind of the unlinked node `rel` of the
/// file system `dev` (devtmpfs): its root reads `/<rel>//deleted`.
pub fn bound_in(table: &str, dev: u64, rel: &Path) -> bool {
    let fs = format!("{}:{}", libc::major(dev), libc::minor(dev));
    let root = format!("/{}//deleted", rel.display());
    table.lines().any(|line| {
        let mut fields = line.split(' ');
        fields.nth(2) == Some(fs.as_str()) && fields.next() == Some(root.as_str())
    })
}

/// A look into one mount namespace, running.
struct Look {
    /// A process of that namespace, for the log.
    of: i32,
    /// The looking process, ours.
    child: i32,
    /// It, held: `None` where it could not be — then no later look ends it.
    pidfd: Option<Arc<OwnedFd>>,
}

/// `/dev/null` over `path` in every mount namespace of the zone's programs
/// but this one's, where `path` still is: a sandbox binds the nodes it is
/// given (`fs-sandbox --device`, `--camera`), and a bind outlives the
/// device. The zone's own namespace, and every launch's copy of it, lose the
/// entry with the device.
///
/// Nothing mounts over such a bind: its dentry is the gone node's, unlinked,
/// and the kernel refuses a mount on an unlinked dentry (ENOENT). So the bind
/// is taken away first, and `/dev/null` goes over what it stood on — the
/// sandbox's empty placeholder. Only a device node is acted on, or what our
/// own taking-away bared: a link or a directory a program put at that path is
/// left alone, and never followed.
///
/// Started, not waited for: the looks running, and what could not be
/// started.
fn revoke_everywhere(path: &Path) -> (Vec<Look>, Vec<String>) {
    let (Ok(target), Ok(null)) = (
        CString::new(path.as_os_str().as_bytes()),
        CString::new("/dev/null"),
    ) else {
        return (Vec::new(), Vec::new());
    };
    let own_mnt = fs::read_link("/proc/self/ns/mnt").ok();
    let Some(own_user) = ns_key(Path::new("/proc/self/ns/user")) else {
        return (Vec::new(), Vec::new());
    };
    let mut seen: Vec<PathBuf> = Vec::new();
    let (mut looks, mut failed) = (Vec::new(), Vec::new());
    let null_dev = libc::makedev(1, 3);
    for proc in zone_processes() {
        let Some(mnt) = proc.mnt else {
            continue;
        };
        if Some(&mnt) == own_mnt.as_ref() || seen.contains(&mnt) {
            continue;
        }
        seen.push(mnt);
        let pid = proc.pid;
        let Ok(handle) = File::open(format!("/proc/{pid}/ns/mnt")) else {
            continue;
        };
        if !mounts_below(&handle, own_user) {
            continue;
        }
        // SAFETY: after fork the child makes only async-signal-safe calls on
        // what was made before it — a descriptor and two C strings — and
        // leaves with _exit.
        let child = unsafe { libc::fork() };
        if child == 0 {
            unsafe {
                if libc::setns(handle.as_raw_fd(), libc::CLONE_NEWNS) != 0 {
                    libc::_exit(1);
                }
                let mut st: libc::stat = std::mem::zeroed();
                let mut bared = false;
                for _ in 0..4 {
                    if libc::lstat(target.as_ptr(), &mut st) != 0 {
                        libc::_exit(if bared { 3 } else { 0 });
                    }
                    let kind = st.st_mode & libc::S_IFMT;
                    if kind == libc::S_IFCHR && st.st_rdev == null_dev {
                        libc::_exit(if bared { 3 } else { 0 });
                    }
                    if !(kind == libc::S_IFCHR || (kind == libc::S_IFREG && bared)) {
                        libc::_exit(if bared { 3 } else { 0 });
                    }
                    let (fstype, data) = (std::ptr::null(), std::ptr::null());
                    let bind = libc::MS_BIND;
                    if libc::mount(null.as_ptr(), target.as_ptr(), fstype, bind, data) == 0 {
                        libc::_exit(3);
                    }
                    let how = libc::MNT_DETACH | libc::UMOUNT_NOFOLLOW;
                    if libc::umount2(target.as_ptr(), how) != 0 {
                        libc::_exit(2);
                    }
                    bared = true;
                }
                libc::_exit(2);
            }
        }
        if child < 0 {
            failed.push(format!("{pid}: cannot fork"));
            continue;
        }
        // Held before anything can reap it: a pidfd of a child not waited
        // for is that child's.
        looks.push(Look {
            of: pid,
            child,
            pidfd: crate::sys::pidfd_open(child).map(Arc::new),
        });
    }
    (looks, failed)
}

/// Wait for each look of `path`, as long as it takes, then say how it went.
fn wait_looks(zone: &str, path: &Path, looks: Vec<Look>, mut failed: Vec<String>, all: &Looks) {
    let mut covered = 0;
    for look in &looks {
        let mut status = 0;
        let got = loop {
            // SAFETY: waiting for our own child.
            let got = unsafe { libc::waitpid(look.child, &mut status, 0) };
            if got >= 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                break got;
            }
        };
        let of = look.of;
        if got != look.child {
            failed.push(format!("{of}: lost"));
        } else if libc::WIFEXITED(status) {
            match libc::WEXITSTATUS(status) {
                0 => {}
                3 => covered += 1,
                1 => failed.push(format!("{of}: cannot enter")),
                _ => failed.push(format!("{of}: cannot cover")),
            }
        } else {
            failed.push(format!("{of}: stuck until the next look"));
        }
    }
    // Done: no longer running — unless a newer look took the node's place.
    {
        let mut running = locked(all);
        let ours = running.get(path).is_some_and(|fds| {
            fds.iter().all(|fd| {
                looks
                    .iter()
                    .any(|l| l.pidfd.as_ref().is_some_and(|p| Arc::ptr_eq(fd, p)))
            })
        });
        if ours {
            running.remove(path);
        }
    }
    report(zone, path, covered, &failed);
}

fn report(zone: &str, path: &Path, covered: usize, failed: &[String]) {
    if !failed.is_empty() {
        eprintln!(
            "zone {zone}: {} gone — covered in {covered} mount namespace(s), not in: {} \
             (a program still holding it is killed when its number is given again)",
            path.display(),
            failed.join(", ")
        );
    } else if covered > 0 {
        println!(
            "zone {zone}: {} gone — its bind covered in {covered} sandbox(es)",
            path.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sysfs of the test's making: `char/<maj>:<min>` links to device
    /// directories below `devices/`.
    struct Sys {
        base: PathBuf,
    }

    impl Sys {
        fn new(tag: &str) -> Self {
            let base = std::env::temp_dir().join(format!("vz-guard-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&base);
            fs::create_dir_all(base.join("char")).unwrap();
            Self { base }
        }

        fn files(&self, dir: &str, files: &[(&str, &str)]) {
            let dir = self.base.join("devices").join(dir);
            fs::create_dir_all(&dir).unwrap();
            for (name, text) in files {
                let file = dir.join(name);
                fs::create_dir_all(file.parent().unwrap()).unwrap();
                fs::write(file, format!("{text}\n")).unwrap();
            }
        }

        fn node(&self, number: &str, dir: &str) {
            let dir = self.base.join("devices").join(dir);
            fs::create_dir_all(&dir).unwrap();
            let link = self.base.join("char").join(number);
            let _ = fs::remove_file(&link);
            std::os::unix::fs::symlink(dir, link).unwrap();
        }

        fn identity(&self, major: u32, minor: u32) -> Option<String> {
            identity(&self.base.join("char"), major, minor)
        }
    }

    impl Drop for Sys {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    const PORT: &str = "pci0000:00/usb1/1-2";

    /// A USB security key's raw node, then a USB keyboard's: another device.
    #[test]
    fn a_key_and_a_keyboard_are_two_devices() {
        let sys = Sys::new("keyboard");
        sys.files(
            PORT,
            &[("idVendor", "1050"), ("idProduct", "0407"), ("serial", "")],
        );
        sys.files(&format!("{PORT}/1-2:1.0"), &[("bInterfaceNumber", "00")]);
        sys.node(
            "240:9",
            &format!("{PORT}/1-2:1.0/0003:1050:0407.0001/hidraw/hidraw9"),
        );
        let key = sys.identity(240, 9).unwrap();
        assert!(key.contains("usb:1050:0407:"), "{key}");
        assert!(key.contains("hid:0003:1050:0407"), "{key}");
        let _ = fs::remove_dir_all(sys.base.join("devices"));
        sys.files(
            PORT,
            &[("idVendor", "046d"), ("idProduct", "c31c"), ("serial", "")],
        );
        sys.files(&format!("{PORT}/1-2:1.0"), &[("bInterfaceNumber", "00")]);
        sys.node(
            "240:9",
            &format!("{PORT}/1-2:1.0/0003:046D:C31C.0002/hidraw/hidraw9"),
        );
        assert_ne!(sys.identity(240, 9), Some(key));
    }

    /// The same gamepad in another port, another HID instance: the same.
    #[test]
    fn the_same_device_replugged_is_the_same() {
        let sys = Sys::new("replug");
        let pad = |port: &str, instance: &str| {
            let _ = fs::remove_dir_all(sys.base.join("devices"));
            sys.files(
                port,
                &[
                    ("idVendor", "045e"),
                    ("idProduct", "028e"),
                    ("serial", "A1"),
                ],
            );
            sys.files(&format!("{port}/x:1.0"), &[("bInterfaceNumber", "00")]);
            let input = format!("{port}/x:1.0/0003:045E:028E.{instance}/input/input7");
            sys.files(
                &input,
                &[
                    ("id/bustype", "0003"),
                    ("id/vendor", "045e"),
                    ("id/product", "028e"),
                    ("name", "Pad"),
                    ("capabilities/ev", "20000b"),
                    ("capabilities/key", "7fdb000000000000 0 0 0 0"),
                ],
            );
            sys.node("13:65", &format!("{input}/event1"));
            sys.identity(13, 65).unwrap()
        };
        assert_eq!(
            pad("pci0000:00/usb1/1-2", "0003"),
            pad("pci0000:00/usb3/3-1", "0009")
        );
    }

    /// One HID device with a keyboard and a gamepad: its two input devices
    /// are two, though the USB device is one.
    #[test]
    fn a_receivers_keyboard_is_not_its_gamepad() {
        let sys = Sys::new("combo");
        sys.files(PORT, &[("idVendor", "046d"), ("idProduct", "c52b")]);
        sys.files(&format!("{PORT}/1-2:1.2"), &[("bInterfaceNumber", "02")]);
        let hid = format!("{PORT}/1-2:1.2/0003:046D:C52B.0004");
        let input = |n: &str, name: &str, key: &str| {
            let dir = format!("{hid}/input/input{n}");
            sys.files(
                &dir,
                &[
                    ("id/bustype", "0003"),
                    ("id/vendor", "046d"),
                    ("id/product", "c52b"),
                    ("name", name),
                    ("capabilities/ev", "120013"),
                    ("capabilities/key", key),
                ],
            );
            sys.node("13:70", &format!("{dir}/event6"));
            sys.identity(13, 70).unwrap()
        };
        let pad = input("8", "Receiver Gamepad", "7fdb000000000000 0 0 0 0");
        let keyboard = input("9", "Receiver Keyboard", "fffffffffffffffe");
        assert_ne!(pad, keyboard);
    }

    /// A number with no device in sysfs, and one made through uinput.
    #[test]
    fn what_the_kernel_does_not_know_is_nothing() {
        let sys = Sys::new("unknown");
        assert_eq!(sys.identity(240, 9), None);
        sys.files(
            "virtual/input/input30",
            &[
                ("id/bustype", "0003"),
                ("id/vendor", "045e"),
                ("id/product", "028e"),
            ],
        );
        sys.node("13:66", "virtual/input/input30/event2");
        let made = sys.identity(13, 66).unwrap();
        assert!(made.starts_with("made/"), "{made}");
        sys.node("240:10", "virtual/misc/foo");
        assert_eq!(sys.identity(240, 10), None);
    }

    #[test]
    fn a_hid_directory_is_told_by_its_name() {
        assert!(hid_name("0005:054C:09CC.0003"));
        assert!(!hid_name("0005:054C:09CC"));
        assert!(!hid_name("input7"));
        assert!(!hid_name("0005-054C:09CC.0003"));
    }

    #[test]
    fn a_bind_of_an_unlinked_node_is_found_by_its_root() {
        let dev = libc::makedev(0, 5);
        let table = "\
36 25 0:5 /hidraw9//deleted /dev/hidraw9 rw,nosuid - devtmpfs devtmpfs rw
37 25 0:5 /null /dev/hidraw8 rw - devtmpfs devtmpfs rw
38 25 0:5 /input/event5//deleted /tmp/x rw - devtmpfs devtmpfs rw
39 25 0:6 /hidraw7//deleted /dev/hidraw7 rw - tmpfs tmpfs rw
";
        assert!(bound_in(table, dev, Path::new("hidraw9")));
        assert!(bound_in(table, dev, Path::new("input/event5")));
        assert!(!bound_in(table, dev, Path::new("hidraw8")));
        // Another file system's.
        assert!(!bound_in(table, dev, Path::new("hidraw7")));
    }

    /// Our own process is in our user namespace; the kernel's first is not
    /// below it unless we are in it ourselves.
    #[test]
    fn a_process_of_our_namespace_is_ours() {
        let own = ns_key(Path::new("/proc/self/ns/user")).unwrap();
        assert!(below(std::process::id() as i32, own));
        // Our mount namespace is our user namespace's, or an ancestor's:
        // below ours only if ours owns it.
        let mnt = File::open("/proc/self/ns/mnt").unwrap();
        // SAFETY: an ioctl on a namespace descriptor.
        let owner = unsafe { libc::ioctl(mnt.as_raw_fd(), libc::NS_GET_USERNS) };
        if owner >= 0 {
            // SAFETY: the descriptor was just returned to us.
            let owner = unsafe { OwnedFd::from_raw_fd(owner) };
            // SAFETY: fstat of a descriptor we hold, into a zeroed struct.
            let owner_key = unsafe {
                let mut st: libc::stat = std::mem::zeroed();
                libc::fstat(owner.as_raw_fd(), &mut st);
                (st.st_dev, st.st_ino)
            };
            assert_eq!(mounts_below(&mnt, own), owner_key == own);
        }
    }

    /// A descriptor on a node gone is found by its inode.
    #[test]
    fn a_descriptor_on_a_gone_node_is_found() {
        use std::os::unix::fs::MetadataExt;
        let dir = std::env::temp_dir().join(format!("vz-guard-fd-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("hidraw9");
        fs::write(&file, "").unwrap();
        let meta = fs::metadata(&file).unwrap();
        let _open = File::open(&file).unwrap();
        fs::remove_file(&file).unwrap();
        let gone = Seen {
            dev: meta.dev(),
            ino: meta.ino(),
            rdev: 0,
            identity: None,
        };
        let me = Proc {
            pid: std::process::id() as i32,
            mnt: None,
        };
        let found = held(&[me], std::slice::from_ref(&gone), Path::new("hidraw9"));
        assert!(found.by_descriptor.iter().any(|(_, s)| *s == gone));
        let _ = fs::remove_dir_all(&dir);
    }
}
