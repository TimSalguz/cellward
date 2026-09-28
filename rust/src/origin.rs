//! Whose program a process is (`docs/PERMISSIONS.md` §11.10) — for the
//! helpers on the host that decide by the container and not by the network:
//! the broker, the sound filter, the PipeWire context, the screen cast.
//!
//! **A container's instance is the container** (`crate::place`, the
//! container design of 2026-09-27): its helpers are told whose its programs
//! are when they start (`--container`, [`Who::from_word`]), and the broker
//! knows the instance of a peer by its user namespace, which no program
//! leaves. Nothing a program says about itself counts.
//!
//! **A zone's own space** — its app namespace and the mount namespace its
//! holder set up — has no container's programs in it since stage 5 of that
//! design (2026-09-28): nothing is launched there any more (`crate::launch`).
//! Its helpers still serve whatever runs there — a program a previous build
//! launched before the update, or a person's `nsenter` —, and they know it
//! as the zone's own ([`Who::Main`]) when it is in the zone's own mount
//! namespace, read while the process is held, and as nobody's
//! ([`Who::Unknown`]) anywhere else. Until stage 5 a zone's program was also
//! the container of the launch it descended from, by the registry of
//! launches (`.running`) and a list of the containers launched into the zone
//! since it came up (`launched-containers`); with no launch into a zone that
//! is gone, and a record of the registry — a launch into an instance, whose
//! network is the zone's name — is never taken for a program of the zone.
//!
//! **Unknown** is everything else: a namespace a launch made of its own and
//! the program left, a process whose namespace could not be read. It is never
//! taken for another container, nor for the zone's own programs: what decides
//! by the container treats it as the least known — no "always".

use std::os::fd::{OwnedFd, RawFd};
use std::path::{Path, PathBuf};

/// Whose program a process is. By default the least known.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Who {
    /// No container: a program of the zone's own, or of the main home's
    /// instance.
    Main,
    /// A program of this container — one that exists.
    Container(String),
    /// Not known (see the module's words).
    #[default]
    Unknown,
}

impl Who {
    /// One word for it, as a helper of a container's instance is told whose
    /// its programs are (`--container`): `main`, `?`, or the container's
    /// name — which is never either (`container::valid_name`).
    pub fn word(&self) -> String {
        match self {
            Who::Main => crate::instance::MAIN.to_owned(),
            Who::Container(name) => name.clone(),
            Who::Unknown => "?".to_owned(),
        }
    }

    /// What [`Who::word`] said; a word that is no container's name is not
    /// known.
    pub fn from_word(word: &str) -> Self {
        match word {
            crate::instance::MAIN => Who::Main,
            name if crate::container::valid_name(name) => Who::Container(name.to_owned()),
            _ => Who::Unknown,
        }
    }
}

/// The peer of a connection as the kernel knows it: its number, held by a
/// pidfd, and its mount namespace when it could be read.
#[derive(Debug)]
pub struct Peer {
    pub pid: i32,
    pub pidfd: OwnedFd,
    /// `None` when its `/proc` is out of reach — a process that made itself
    /// not dumpable (a sandbox's bus filter) is, to a helper without
    /// capabilities: then it is never taken for one of the zone's own.
    pub mnt: Option<PathBuf>,
}

impl Peer {
    /// The process on the other end of the socket `sock`, looked at while it
    /// is certainly the process that connected. `None` when it is gone, or
    /// cannot be held.
    pub fn of(sock: RawFd) -> Option<Self> {
        let pid = crate::sys::peer_pid(sock)?;
        let pidfd = crate::sys::peer_pidfd(sock, pid)?;
        Self::held(pid, pidfd)
    }

    /// The process `pid`, held by a pidfd opened now: for a number the
    /// daemon of a protocol read from the kernel (PipeWire's
    /// `pipewire.sec.pid`), not a connection of ours. `None` when it is gone.
    pub fn of_pid(pid: i32) -> Option<Self> {
        if pid <= 0 {
            return None;
        }
        Self::held(pid, crate::sys::pidfd_open(pid)?)
    }

    fn held(pid: i32, pidfd: OwnedFd) -> Option<Self> {
        let peer = Self {
            pid,
            pidfd,
            mnt: None,
        };
        if !peer.alive() {
            return None;
        }
        let mnt = peer.ns("mnt");
        Some(Self { mnt, ..peer })
    }

    /// Still running: a number read before this is still the peer's.
    pub fn alive(&self) -> bool {
        !crate::sys::pidfd_wait(&self.pidfd, std::time::Duration::ZERO)
    }

    /// A namespace of the peer's (`net`, `user`, `mnt`: the link's text,
    /// `net:[…]`), read while it lives — `None` if it did not.
    pub fn ns(&self, ns: &str) -> Option<PathBuf> {
        let link = std::fs::read_link(format!("/proc/{}/ns/{ns}", self.pid)).ok()?;
        self.alive().then_some(link)
    }
}

/// The zone's own mount namespace: the one its holder is in.
fn zones_own_mounts(state: &Path, zone: &str) -> Option<PathBuf> {
    let pid = crate::cli::zone_pid(state, std::ffi::OsStr::new(zone))?;
    std::fs::read_link(format!("/proc/{pid}/ns/mnt")).ok()
}

/// Whose program the peer is, in `zone` (whose state directory is below
/// `state`): the zone's own in the zone's own mount namespace, else not
/// known.
pub fn of_peer(state: &Path, zone: &str, peer: &Peer) -> Who {
    let own = zones_own_mounts(state, zone);
    of_peer_in(peer, own.as_deref())
}

/// [`of_peer`], the zone's own mount namespace given: a helper that lives in
/// it has it as its own (`/proc/self/ns/mnt`) — the holder's `/proc`, which
/// has capabilities the helper has not, may be out of its reach. Read again
/// now: still the peer's, still that one — a peer read in another namespace
/// than it is in now is not the zone's.
pub fn of_peer_in(peer: &Peer, own_mnt: Option<&Path>) -> Who {
    let still = peer.ns("mnt");
    if own_mnt.is_some() && own_mnt == still.as_deref() && still == peer.mnt {
        Who::Main
    } else {
        Who::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct Dirs(PathBuf);

    impl Dirs {
        fn new(tag: &str) -> Self {
            let base = std::env::temp_dir().join(format!("vz-origin-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&base);
            fs::create_dir_all(base.join("state/.running")).unwrap();
            Self(base)
        }
        fn state(&self) -> PathBuf {
            self.0.join("state")
        }
        /// A launch of `pid` into `zone`, filed under `dir` with `selector`,
        /// its start time on record — as the registry has every launch.
        fn launch(&self, dir: &str, pid: i32, zone: &str, selector: &str) {
            let running = self.0.join("state/.running");
            crate::registry::append(&running.join(dir).join("app"), pid, zone, selector).unwrap();
            crate::registry::note_start(&running, pid, false).unwrap();
        }
    }

    impl Drop for Dirs {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn me() -> Peer {
        let pid = std::process::id() as i32;
        Peer {
            pid,
            pidfd: crate::sys::pidfd_open(pid).unwrap(),
            mnt: Some(fs::read_link("/proc/self/ns/mnt").unwrap()),
        }
    }

    /// Whose programs a helper of an instance is told they are, and reads
    /// back: `main`, a container's name, `?` — nothing else is a name.
    #[test]
    fn whose_is_one_word_and_read_back() {
        for who in [
            Who::Main,
            Who::Container("work".into()),
            Who::Container("Работа".into()),
            Who::Unknown,
        ] {
            assert_eq!(Who::from_word(&who.word()), who);
        }
        assert_eq!(Who::Main.word(), "main");
        assert_eq!(Who::Unknown.word(), "?");
        for not_a_name in ["", "a/b", "a:b", "-x", "ask"] {
            assert_eq!(Who::from_word(not_a_name), Who::Unknown, "{not_a_name:?}");
        }
    }

    /// A child that sleeps: a process in our namespaces that we do not
    /// descend from. Killed on drop.
    struct Sleeper(std::process::Child);

    impl Sleeper {
        fn new() -> Self {
            Self(
                std::process::Command::new("sleep")
                    .arg("60")
                    .spawn()
                    .unwrap(),
            )
        }
        fn pid(&self) -> i32 {
            self.0.id() as i32
        }
    }

    impl Drop for Sleeper {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// In the zone's own namespace, the zone's; anywhere else not known.
    /// A launch in the registry changes nothing (stage 5 of the container
    /// design): no launch goes into a zone's own namespaces, and a record
    /// whose network is the zone's name is a launch into an instance — it
    /// made a process the container of its launch until then, and this
    /// test said so (`a_process_is_the_container_its_launch_was_for`).
    #[test]
    fn a_zones_program_is_known_by_its_namespace_alone() {
        let d = Dirs::new("namespace");
        let peer = me();
        // The zone has no holder: nothing is its own.
        assert_eq!(of_peer(&d.state(), "nl", &peer), Who::Unknown);
        // A launch of `work` in `nl` that we descend from — once taken for
        // `work`'s program — and one of the main profile that is us.
        let parent = crate::sys::parent_of(peer.pid).unwrap();
        d.launch("work", parent, "nl", "work");
        d.launch(crate::registry::MAIN, peer.pid, "nl", "");
        assert_eq!(of_peer(&d.state(), "nl", &peer), Who::Unknown);
        // Our namespace is the zone's own: its holder is in it.
        let zone = d.state().join("nl");
        fs::create_dir_all(&zone).unwrap();
        let holder = Sleeper::new();
        fs::write(zone.join("zone.pid"), holder.pid().to_string()).unwrap();
        let stamp = crate::sys::process_stamp(holder.pid()).unwrap();
        fs::write(zone.join("zone.start"), stamp).unwrap();
        assert_eq!(of_peer(&d.state(), "nl", &peer), Who::Main);
        // Another zone's own is not ours.
        assert_eq!(of_peer(&d.state(), "de", &peer), Who::Unknown);
        // A peer read in another namespace than it is in now is not.
        let moved = Peer {
            mnt: Some(PathBuf::from("mnt:[1]")),
            ..me()
        };
        assert_eq!(of_peer(&d.state(), "nl", &moved), Who::Unknown);
    }

    /// A process whose namespace could not be read (not dumpable, to a
    /// helper without capabilities) is never taken for one of the zone's
    /// own — until stage 5 it was still known by its launch.
    #[test]
    fn a_process_whose_namespace_is_out_of_reach_is_not_known() {
        let blind = Peer { mnt: None, ..me() };
        let own = fs::read_link("/proc/self/ns/mnt").unwrap();
        // In the zone's own namespace, but not known to be: not the zone's.
        assert_eq!(of_peer_in(&blind, Some(&own)), Who::Unknown);
        assert_eq!(of_peer_in(&me(), Some(&own)), Who::Main);
        // No namespace of the zone's known: nobody is its own.
        assert_eq!(of_peer_in(&me(), None), Who::Unknown);
    }
}
