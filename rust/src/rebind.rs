//! A file of a space's own over a name of the host's — `/etc/resolv.conf`,
//! `/etc/nsswitch.conf` — and laid there again when the host replaces that
//! name (`docs/THREAT-MODEL.md` D2, 2026-09-28).
//!
//! A zone and a container's instance read their own `resolv.conf` (the
//! tunnel's resolvers; an instance's constant forwarders) and their own
//! `nsswitch.conf` (`hosts: files dns`) in the host's stead. Both are bind
//! mounts, and a bind mount lives on the directory entry it was made over:
//! NetworkManager, openresolv and resolvconf write the host's file anew and
//! rename it over the old one, and the kernel then detaches every mount on
//! the old entry in every other mount namespace (in its own it answers
//! EBUSY). Until 2026-09-28 the space then read the host's file until it
//! restarted: the tunnel's DNS no longer asked, its names sent through the
//! tunnel to the host's resolvers (a fingerprint of the host's network on
//! the VPN's side), and a resolver on `127.0.0.1` the space's own loopback,
//! where nobody answers. Never around the tunnel: the space has no other way
//! out, and the host's resolver sockets stay covered.
//!
//! **On the name, not at the end of its chain.** The bind used to go where
//! `/etc/resolv.conf` led (`sys::link_target`), because `mount(2)` follows
//! the links of its target: a rename anywhere down the chain — openresolv's
//! in `/run/resolvconf`, NixOS's `/etc/static` replaced by every switch for
//! `nsswitch.conf` — took the file away as well. Attached with
//! `move_mount(2)` without `MOVE_MOUNT_T_SYMLINKS`, the file sits on the
//! name itself, whatever the host has made it, a link or a plain file:
//! nothing the host does further down reaches it, and the one thing that
//! does is a replacement of that very name.
//!
//! **Laid again on that event, by the space.** Its process watches the
//! directory the name is in (`/etc`, inotify: an entry of that name
//! created, moved in, deleted or moved out; the directory itself gone; the
//! queue overflowed) and, woken, looks at what the name leads to now: not
//! its own file — it lays it there again. No clock anywhere. A name the host
//! removed and has not made anew has nothing to be laid on: until the host
//! makes it again, a program finds no `resolv.conf` and glibc asks
//! `127.0.0.1`, the space's own loopback. **The window** is from the host's
//! rename to the re-lay — one wake-up and one mount: a lookup that falls
//! into it asks the host's resolvers, through the tunnel, as every lookup
//! did before this was done; never around the tunnel.
//!
//! **To every launch.** A launch runs in a mount namespace of its own, a
//! slave copy of its instance's (`crate::enter`). The space binds `/etc`
//! onto itself and makes it shared before anything is laid there
//! ([`share`]): what it lays later propagates into every launch's copy, and
//! into a sandbox's `/etc`, which bwrap binds from the launch's — as the
//! space's `/dev` and runtime directory reach them.
//!
//! **Why not a layout the rename cannot touch at all.** The one that would
//! be — the space's own `/etc`, its entries links into the host's and its
//! `resolv.conf` a file of its own — breaks what reads the links of `/etc`
//! (the time zone taken from where `/etc/localtime` points, as ICU and
//! Chromium do), freezes `/etc/static` at the generation the space came up
//! with (every NixOS switch replaces it), and lacks what the host adds to
//! `/etc` later: each of those needs a watch of its own to stay right, and a
//! watch that falls behind there fails in the open for files that have
//! nothing to do with names. A copy of `/etc` made as the space comes up
//! goes stale the same way. Laid on the name, the space's `/etc` is the
//! host's but for the two files, and the window above is the whole price.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::sys;

/// A space's own file and the host's name it is laid over.
pub struct Own {
    name: PathBuf,
    file: OwnedFd,
}

impl Own {
    /// The space's `file`, for the host's `name`: opened without following a
    /// link (`O_PATH | O_NOFOLLOW`), a regular file, and held — the space's
    /// directory is covered once it is set up (`zone::hide_project_state`),
    /// and what is laid later is what was opened and checked here. Written
    /// over in place (an instance's keeper does, with each attach), it stays
    /// the file laid.
    pub fn open(file: &Path, name: &Path) -> io::Result<Self> {
        let file: OwnedFd = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(file)?
            .into();
        if !File::from(file.try_clone()?).metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a regular file",
            ));
        }
        Ok(Self {
            name: name.to_path_buf(),
            file,
        })
    }

    /// The host's name it is laid over.
    pub fn name(&self) -> &Path {
        &self.name
    }

    /// Whether the name leads to this file now — what a program that opens
    /// it reads: through the space's mount on the name, or, with none there,
    /// along the host's links.
    pub fn laid(&self) -> bool {
        let Some(own) = identity(&self.file) else {
            return false;
        };
        fs::metadata(&self.name).is_ok_and(|m| (m.dev(), m.ino()) == own)
    }

    /// Lay the file over the name, unless it is there already: `Ok(true)`
    /// when laid now. On the name itself, a link not followed (`move_mount`
    /// without `MOVE_MOUNT_T_SYMLINKS`), and a bind of what was opened
    /// (`sys::clone_file`), never of what a path names by now. The name
    /// looked up as it is attached: one the host replaced in between is laid
    /// on as it is then. `NotFound`: the host has no such name now — nothing
    /// to lay the file on until it makes one.
    pub fn lay(&self) -> io::Result<bool> {
        if self.laid() {
            return Ok(false);
        }
        sys::attach_tree(&sys::clone_file(&self.file)?, &self.name)?;
        Ok(true)
    }
}

/// `(device, inode)` of what a descriptor names.
fn identity(fd: &OwnedFd) -> Option<(u64, u64)> {
    // SAFETY: stat is plain data filled in by the kernel.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid descriptor and a stat buffer.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return None;
    }
    Some((st.st_dev, st.st_ino))
}

/// `dir` bound onto itself and made a shared mount of its own, in the
/// space's otherwise private tree: every launch is a slave copy of the
/// space's mount namespace (`crate::enter`), and what [`Own::lay`] lays in
/// it later reaches each — a sandbox's `/etc` too, which bwrap binds from
/// the launch's. Recursive: what the host mounted below it stays. Nothing
/// of a launch comes back (a slave), nor goes to the host: the space's tree
/// was made private first, and a private mount made shared is a peer group
/// of its own.
pub fn share(dir: &Path) -> io::Result<()> {
    sys::mount(dir.as_os_str(), dir, "", libc::MS_BIND | libc::MS_REC, "")?;
    sys::mount(OsStr::new("none"), dir, "", libc::MS_SHARED, "")
}

/// What a watch wakes for, in the directory of a name: an entry created,
/// moved in, deleted or moved out; the directory itself deleted or moved.
/// (`IN_Q_OVERFLOW` and `IN_IGNORED` come whether asked or not.)
const MASK: u32 = libc::IN_CREATE
    | libc::IN_MOVED_TO
    | libc::IN_DELETE
    | libc::IN_MOVED_FROM
    | libc::IN_DELETE_SELF
    | libc::IN_MOVE_SELF;

/// An inotify watch on the directory of every name of a set of [`Own`]s.
pub struct Watch {
    fd: OwnedFd,
    dirs: HashMap<i32, PathBuf>,
}

impl Watch {
    /// A watch on the directory of each of `names`, once each.
    pub fn new(names: &[&Path]) -> io::Result<Self> {
        // SAFETY: inotify_init1 takes flags and returns a new descriptor or -1.
        let raw = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the descriptor was just returned to us and nothing else owns it.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut dirs = HashMap::new();
        for name in names {
            let dir = name.parent().unwrap_or(Path::new("/"));
            if dirs.values().any(|d: &PathBuf| d.as_path() == dir) {
                continue;
            }
            let c = std::ffi::CString::new(dir.as_os_str().as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a NUL in a path"))?;
            // SAFETY: a valid inotify descriptor and a NUL-terminated path.
            let wd = unsafe { libc::inotify_add_watch(fd.as_raw_fd(), c.as_ptr(), MASK) };
            if wd < 0 {
                return Err(io::Error::last_os_error());
            }
            dirs.insert(wd, dir.to_path_buf());
        }
        Ok(Self { fd, dirs })
    }

    /// Block until something happens in a watched directory; which of
    /// `names` (as given to [`Watch::new`]) it concerns, and whether a
    /// directory's watch went with it (`IN_IGNORED`: it is not watched any
    /// more). `Err` when the watch cannot be read.
    pub fn next(&self, names: &[&Path]) -> io::Result<(Vec<usize>, bool)> {
        let mut buf = vec![0u8; 16 * 1024];
        // SAFETY: a valid descriptor and a buffer of the length passed.
        let n = unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::Interrupted {
                Ok((Vec::new(), false))
            } else {
                Err(e)
            };
        }
        let events = sys::parse_dir_events(&buf[..n as usize]);
        let gone = events
            .iter()
            .any(|(wd, mask, _)| mask & libc::IN_IGNORED != 0 && self.dirs.contains_key(wd));
        Ok((concerned(names, &self.dirs, &events), gone))
    }
}

/// Which of `names` the inotify `events` concern (`(watch, mask, entry)`,
/// `sys::parse_dir_events`), each once and in order: an event on the entry
/// of that name in its directory; the directory itself gone, moved or no
/// longer watched — every name in it; the queue overflowed — every name,
/// for what happened is not known.
pub fn concerned(
    names: &[&Path],
    dirs: &HashMap<i32, PathBuf>,
    events: &[(i32, u32, Option<String>)],
) -> Vec<usize> {
    let whole = libc::IN_DELETE_SELF | libc::IN_MOVE_SELF | libc::IN_IGNORED;
    let mut hit = vec![false; names.len()];
    for (wd, mask, entry) in events {
        if mask & libc::IN_Q_OVERFLOW != 0 {
            hit.fill(true);
            continue;
        }
        let Some(dir) = dirs.get(wd) else {
            continue;
        };
        for (i, name) in names.iter().enumerate() {
            if name.parent() != Some(dir.as_path()) {
                continue;
            }
            let this = entry
                .as_deref()
                .is_some_and(|e| name.file_name() == Some(OsStr::new(e)));
            if this || mask & whole != 0 {
                hit[i] = true;
            }
        }
    }
    hit.iter()
        .enumerate()
        .filter(|(_, h)| **h)
        .map(|(i, _)| i)
        .collect()
}

/// Keep each of `owns` laid over its name for as long as this process lives
/// (the space's, which parks until the space ends): a thread asleep in a
/// [`Watch`], woken by the host's replacement of a name — no clock. The
/// watch first, then a look at each: nothing the host did since they were
/// laid is missed. `who` names the space in what it says, into its unit's
/// journal. No watch to be had (inotify's limits): said, and the space goes
/// on as it did before this was done — the host's file seen after its
/// rename, until the space restarts; names still only through the tunnel.
pub fn keep(who: String, owns: Vec<Own>) {
    if owns.is_empty() {
        return;
    }
    let listed = owns
        .iter()
        .map(|o| o.name.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let names: Vec<PathBuf> = owns.iter().map(|o| o.name.clone()).collect();
    let refs: Vec<&Path> = names.iter().map(PathBuf::as_path).collect();
    let watch = match Watch::new(&refs) {
        Ok(watch) => watch,
        Err(e) => {
            eprintln!(
                "{who}: no watch on the host's {listed} ({e}) — if the host replaces one, the \
                 space's programs read the host's until it restarts (names still only through \
                 the tunnel)"
            );
            return;
        }
    };
    for own in &owns {
        ensure(&who, own);
    }
    println!("{who}: its own {listed} kept over the host's");
    std::thread::spawn(move || {
        let refs: Vec<&Path> = names.iter().map(PathBuf::as_path).collect();
        loop {
            match watch.next(&refs) {
                Ok((concerned, gone)) => {
                    for i in concerned {
                        ensure(&who, &owns[i]);
                    }
                    if gone {
                        eprintln!(
                            "{who}: a directory of {listed} is no longer watched — a later \
                             replacement by the host is not laid over until the space restarts"
                        );
                    }
                }
                Err(e) => {
                    eprintln!(
                        "{who}: the watch on {listed} ended ({e}) — a later replacement by \
                         the host is not laid over until the space restarts"
                    );
                    return;
                }
            }
        }
    });
}

/// `own` laid over its name, where it is not, and what came of it said.
fn ensure(who: &str, own: &Own) {
    let name = own.name.display();
    match own.lay() {
        Ok(true) => println!("{who}: the host replaced {name} — its own laid over it again"),
        Ok(false) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => println!(
            "{who}: the host has no {name} now — its own is laid again when the host makes one"
        ),
        Err(e) => eprintln!(
            "{who}: cannot lay its own {name} again ({e}) — its programs read the host's \
             (names still only through the tunnel)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vz-rebind-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// What a program reads is the question: the file itself, or a link the
    /// host left that leads to it, is the space's; the host's own file, or
    /// a name that leads nowhere, is not — and then it is laid again.
    #[test]
    fn a_name_is_laid_when_it_leads_to_the_spaces_own_file() {
        let dir = scratch("laid");
        let own = dir.join("own.conf");
        fs::write(&own, "nameserver 10.254.255.253\n").unwrap();
        let name = dir.join("resolv.conf");
        let held = Own::open(&own, &name).unwrap();
        assert_eq!(held.name(), name);
        // No name at all: nothing to lay on.
        assert!(!held.laid());
        // The host's file, renamed into place.
        fs::write(dir.join(".new"), "nameserver 192.168.1.1\n").unwrap();
        fs::rename(dir.join(".new"), &name).unwrap();
        assert!(!held.laid());
        // A link to the space's file (the same inode, followed as a program
        // follows it), and a hard link: laid.
        fs::remove_file(&name).unwrap();
        std::os::unix::fs::symlink(&own, &name).unwrap();
        assert!(held.laid());
        fs::remove_file(&name).unwrap();
        fs::hard_link(&own, &name).unwrap();
        assert!(held.laid());
        // Written over in place, it is still the file laid.
        fs::write(&own, "nameserver 10.254.255.253\nsearch corp.example\n").unwrap();
        assert!(held.laid());
        // A link that leads nowhere: not laid.
        fs::remove_file(&name).unwrap();
        std::os::unix::fs::symlink(dir.join("gone"), &name).unwrap();
        assert!(!held.laid());
        let _ = fs::remove_dir_all(&dir);
    }

    /// The space's own file is taken as it is and only as a file: a link
    /// planted in its place is not followed, a directory is refused.
    #[test]
    fn the_spaces_own_file_is_a_regular_file_and_not_a_link() {
        let dir = scratch("own");
        let target = dir.join("elsewhere");
        fs::write(&target, "nameserver 192.168.1.1\n").unwrap();
        std::os::unix::fs::symlink(&target, dir.join("link.conf")).unwrap();
        let name = dir.join("resolv.conf");
        assert!(Own::open(&dir.join("link.conf"), &name).is_err());
        fs::create_dir(dir.join("adir")).unwrap();
        assert!(Own::open(&dir.join("adir"), &name).is_err());
        assert!(Own::open(&dir.join("missing"), &name).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    /// Which names an event concerns: its own entry in its own directory;
    /// the directory gone; an overflow — all; nothing else.
    #[test]
    fn an_event_concerns_the_name_it_is_about_and_no_other() {
        let resolv = Path::new("/etc/resolv.conf");
        let nss = Path::new("/etc/nsswitch.conf");
        let elsewhere = Path::new("/run/resolvconf/resolv.conf");
        let names = [resolv, nss, elsewhere];
        let dirs: HashMap<i32, PathBuf> =
            [(1, PathBuf::from("/etc")), (2, "/run/resolvconf".into())]
                .into_iter()
                .collect();
        let ev = |wd: i32, mask: u32, name: &str| (wd, mask, Some(name.to_owned()));
        // NetworkManager's rename over it, and resolvconf's delete and create.
        assert_eq!(
            concerned(&names, &dirs, &[ev(1, libc::IN_MOVED_TO, "resolv.conf")]),
            [0]
        );
        assert_eq!(
            concerned(
                &names,
                &dirs,
                &[
                    ev(1, libc::IN_DELETE, "resolv.conf"),
                    ev(1, libc::IN_CREATE, "resolv.conf")
                ]
            ),
            [0]
        );
        // Moved away, and the other name of the same directory.
        assert_eq!(
            concerned(
                &names,
                &dirs,
                &[ev(1, libc::IN_MOVED_FROM, "nsswitch.conf")]
            ),
            [1]
        );
        // An entry of the same name in another directory is that one's.
        assert_eq!(
            concerned(&names, &dirs, &[ev(2, libc::IN_MOVED_TO, "resolv.conf")]),
            [2]
        );
        // Anything else in /etc, or a watch not ours: nothing.
        assert!(concerned(&names, &dirs, &[ev(1, libc::IN_MOVED_TO, "hosts")]).is_empty());
        assert!(concerned(&names, &dirs, &[ev(1, libc::IN_CREATE, "resolv.conf.tmp")]).is_empty());
        assert!(concerned(&names, &dirs, &[ev(9, libc::IN_MOVED_TO, "resolv.conf")]).is_empty());
        // The directory itself gone: every name in it.
        assert_eq!(
            concerned(&names, &dirs, &[(1, libc::IN_DELETE_SELF, None)]),
            [0, 1]
        );
        assert_eq!(
            concerned(&names, &dirs, &[(2, libc::IN_IGNORED, None)]),
            [2]
        );
        // Overflowed: every one, each once.
        assert_eq!(
            concerned(
                &names,
                &dirs,
                &[
                    (-1, libc::IN_Q_OVERFLOW, None),
                    ev(1, libc::IN_MOVED_TO, "resolv.conf")
                ]
            ),
            [0, 1, 2]
        );
    }

    /// The kernel's events, as the host makes them: a file renamed over the
    /// name wakes the watch for it, and so does a delete; a rename of
    /// another entry of the directory does not concern it.
    #[test]
    fn the_hosts_rename_over_the_name_wakes_the_watch() {
        let dir = scratch("watch");
        let name = dir.join("resolv.conf");
        let other = dir.join("hosts");
        fs::write(&name, "nameserver 192.168.1.1\n").unwrap();
        let names = [name.as_path(), other.as_path()];
        let watch = Watch::new(&[name.as_path()]).unwrap();
        let wait = |watch: &Watch| loop {
            let (hit, gone) = watch.next(&names).unwrap();
            assert!(!gone);
            if !hit.is_empty() {
                return hit;
            }
        };
        fs::write(dir.join(".resolv.conf.new"), "nameserver 192.168.1.2\n").unwrap();
        fs::rename(dir.join(".resolv.conf.new"), &name).unwrap();
        assert_eq!(wait(&watch), [0]);
        fs::write(dir.join(".hosts.new"), "127.0.0.1 localhost\n").unwrap();
        fs::rename(dir.join(".hosts.new"), &other).unwrap();
        assert_eq!(wait(&watch), [1]);
        fs::remove_file(&name).unwrap();
        assert_eq!(wait(&watch), [0]);
        let _ = fs::remove_dir_all(&dir);
    }
}
