//! Which container instance a process is of, by the kernel's word: its user
//! namespace (the container design of 2026-09-27, stage 1).
//!
//! **By the user-namespace chain.** An instance's programs are the processes
//! whose user namespace is the instance's own, or below it: a program cannot
//! leave the user namespace it was started into (`setns` into another wants
//! capabilities over it, which no program of an instance has), and one it
//! makes — a browser's sandbox, `bwrap`, `unshare -U` — is a child of it, its
//! parent a fact of the kernel's (`NS_GET_PARENT`). So a double-forked
//! daemon, a sandbox's nested namespaces and a program whose launch is over
//! are still their instance's — where a zone's helpers could tell a program
//! only by the launch it descends from (`crate::origin`), and a nested one
//! not at all.
//!
//! **Which namespace is an instance's.** The one of its space's process
//! (`instance.pid`), believed only while that process is the one that wrote
//! the number (`crate::instance::up`), read through `/proc/<pid>/ns/user`
//! as `(dev, ino)` of the namespace's file — what names a namespace for as
//! long as it lives. Reading another process's namespaces takes the
//! ptrace read check: the user's own processes pass it, the holder's
//! non-dumpable space too for a process of the host's user namespace (the
//! owner of the instance's), and none of a zone's or an instance's own
//! programs do.
//!
//! Who asks: the broker (`crate::broker`), the frame's and the focus's
//! network of a window (`crate::focus`), the keeper counting its programs
//! ([`members`]) and `cellward kill` ([`crate::kill`]).

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

use crate::origin::{Peer, Who};

/// A namespace's file as `(dev, ino)`: what names the namespace while it
/// lives. `None` when it cannot be looked at.
pub fn ns_key(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.dev(), meta.ino()))
}

/// `"<dev>:<ino>"`, as a key is written down and passed on.
pub fn key_text(key: (u64, u64)) -> String {
    format!("{}:{}", key.0, key.1)
}

/// What [`key_text`] wrote.
pub fn parse_key(text: &str) -> Option<(u64, u64)> {
    let (dev, ino) = text.trim().split_once(':')?;
    Some((dev.parse().ok()?, ino.parse().ok()?))
}

/// The user namespace of `pid` and every one above it, nearest first — up
/// to where this process's view ends (`NS_GET_PARENT` refuses to go past
/// the caller's own). Empty when the process's namespace cannot be read:
/// gone, somebody else's, or not dumpable and not below a namespace of
/// ours.
pub fn chain_of(pid: i32) -> Vec<(u64, u64)> {
    let Ok(file) = File::open(format!("/proc/{pid}/ns/user")) else {
        return Vec::new();
    };
    let mut fd: OwnedFd = file.into();
    let mut out = Vec::new();
    // The kernel nests user namespaces 32 deep at most.
    for _ in 0..40 {
        // SAFETY: fstat of a descriptor we hold, into a zeroed struct.
        let key = unsafe {
            let mut st: libc::stat = std::mem::zeroed();
            (libc::fstat(fd.as_raw_fd(), &mut st) == 0).then_some((st.st_dev, st.st_ino))
        };
        let Some(key) = key else {
            break;
        };
        out.push(key);
        // SAFETY: an ioctl on a namespace descriptor; a new one or -1.
        let parent = unsafe { libc::ioctl(fd.as_raw_fd(), libc::NS_GET_PARENT) };
        if parent < 0 {
            break;
        }
        // SAFETY: the descriptor was just returned to us, owned by nobody else.
        fd = unsafe { OwnedFd::from_raw_fd(parent) };
    }
    out
}

/// A running instance a process was found in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub id: String,
    /// The network the instance runs in.
    pub network: String,
    /// Whose programs its are (`crate::instance::who_of`).
    pub who: Who,
}

/// The user namespace of a running instance's space, while the space is
/// the process that wrote its number.
fn space_key(state: &Path, running: &crate::instance::Running) -> Option<(u64, u64)> {
    let key = ns_key(Path::new(&format!("/proc/{}/ns/user", running.pid)))?;
    // Looked at again after: the number was still the space's.
    (crate::instance::up(state, &running.id) == Some(running.pid)).then_some(key)
}

/// The instance the peer is a program of: the running instance whose user
/// namespace the peer's is, or is below. Read while the peer is certainly
/// the process that connected (`Peer::alive` after the look). `None` for
/// every process of the host, of a zone, of nothing we hold.
pub fn of_peer(state: &Path, peer: &Peer) -> Option<Found> {
    let running = crate::instance::running(state);
    if running.is_empty() {
        return None;
    }
    let chain = chain_of(peer.pid);
    if chain.is_empty() || !peer.alive() {
        return None;
    }
    running.into_iter().find_map(|instance| {
        let key = space_key(state, &instance)?;
        chain.contains(&key).then(|| Found {
            who: crate::instance::who_of(&instance.id),
            id: instance.id,
            network: instance.network,
        })
    })
}

/// The network of the running instance whose network namespace is `ns`
/// (`net:[…]`); `None` when it is no instance's.
pub fn network_of_netns(state: &Path, ns: &str) -> Option<String> {
    crate::instance::running(state)
        .into_iter()
        .find(|instance| {
            std::fs::read_link(format!("/proc/{}/ns/net", instance.pid))
                .is_ok_and(|own| own.as_os_str() == ns)
        })
        .map(|instance| instance.network)
}

/// Every process's number in `/proc`.
fn pids() -> Vec<i32> {
    std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .collect()
}

/// The programs of the instance whose user namespace is `key`: every
/// process whose user namespace is it or below it — but this one, and
/// `spare` and what descends from it (the instance's own space) — each held
/// by a pidfd opened while it was one (looked at again with the pidfd
/// held: a number that went to another process in between is not taken).
///
/// What cannot be read is not seen: a launch's waiter (`crate::enter`), not
/// dumpable in the host's user namespace, is nobody's to read — its child,
/// the program, is, from its `exec` on.
pub fn members(key: (u64, u64), spare: Option<i32>) -> Vec<(i32, OwnedFd)> {
    let me = std::process::id() as i32;
    let mut out = Vec::new();
    for pid in pids() {
        if pid == me || !chain_of(pid).contains(&key) {
            continue;
        }
        let Some(fd) = crate::sys::pidfd_open(pid) else {
            continue;
        };
        if !chain_of(pid).contains(&key) {
            continue;
        }
        if spare.is_some_and(|root| crate::sys::descends_from(pid, &fd, root)) {
            continue;
        }
        out.push((pid, fd));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_written_and_read_back() {
        assert_eq!(key_text((4, 4_026_531_837)), "4:4026531837");
        assert_eq!(parse_key("4:4026531837\n"), Some((4, 4_026_531_837)));
        for bad in ["", "4", ":5", "4:", "a:b", "4:5:6"] {
            assert_eq!(parse_key(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn our_own_chain_starts_with_our_namespace() {
        let me = std::process::id() as i32;
        let chain = chain_of(me);
        assert_eq!(
            chain.first().copied(),
            ns_key(Path::new("/proc/self/ns/user"))
        );
        // A process that is not there has none.
        assert!(chain_of(i32::MAX).is_empty());
    }

    #[test]
    fn nobody_is_a_member_of_a_namespace_that_is_not() {
        assert!(members((0, 1), None).is_empty());
    }

    #[test]
    fn with_no_instance_nothing_is_one() {
        let dir = std::env::temp_dir().join(format!("vz-place-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let me = std::process::id() as i32;
        let peer = Peer {
            pid: me,
            pidfd: crate::sys::pidfd_open(me).unwrap(),
            mnt: None,
        };
        assert_eq!(of_peer(&dir, &peer), None);
        assert_eq!(network_of_netns(&dir, "net:[1]"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
