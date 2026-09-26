//! Which container of a zone a process is a program of (`docs/PERMISSIONS.md`
//! §11.10) — for the zone's helpers on the host, which decide by the
//! container and not by the zone: the broker, the sound filter.
//!
//! **By its launch.** The container is the one a launch of which, in that
//! zone, the process descends from: the launcher recorded in the registry
//! (`.running`), taken only with its start time on record and the same
//! (`registry::launched`: a number that went to somebody else is nobody's
//! launch), and the chain of parents read with each held (`sys::ancestors`).
//! The nearest launch wins. Nothing a program says about itself counts.
//!
//! **With no launch known**, a process in the zone's own mount namespace is
//! one of the zone's own programs, with no container: a launch into a
//! container takes a mount namespace of its own, and a program there cannot
//! leave it — `setns` wants capabilities it does not have. A container of the
//! main home runs in the zone's own namespace too: it is told by its launch,
//! not by the namespace, which is why the launch is looked for first.
//!
//! **Unknown** is everything else: a throwaway or temporary container (they
//! have no name to keep a setting under), a name no container has any more,
//! a daemon that left its launch's tree into a namespace of its own. It is
//! never taken for another container, nor for the zone's own programs: what
//! decides by the container treats it as the least known — no "always".
//!
//! What this does NOT hold: the containers of one zone share its user
//! namespace, its `/tmp` and its abstract sockets — a program of one may get
//! a program of another to do the connecting for it. Between containers of
//! one zone this is a setting, not a wall (`docs/PERMISSIONS.md` §11.10).

use std::os::fd::{OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use crate::tools::Tools;

/// Whose program a process is. By default the least known.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Who {
    /// No container: a program of the zone's own, or a launch of the main
    /// profile.
    Main,
    /// A program of this container — one that exists.
    Container(String),
    /// Not known (see the module's words).
    #[default]
    Unknown,
}

/// The directories the answer is read from.
#[derive(Debug, Clone, Copy)]
pub struct Places<'a> {
    /// `~/.local/state/vpn-zones`: the zones and `.running`.
    pub state: &'a Path,
    /// `~/.config/vpn-zones`: the containers' policy, their renames.
    pub config: &'a Path,
    /// `~/.local/state/vpn-profiles`: the containers' data.
    pub profiles: &'a Path,
}

impl<'a> Places<'a> {
    pub fn of(tools: &'a Tools) -> Self {
        Self {
            state: &tools.state,
            config: &tools.config,
            profiles: &tools.profiles,
        }
    }
}

/// The peer of a connection as the kernel knows it: its number, held by a
/// pidfd, and its mount namespace.
#[derive(Debug)]
pub struct Peer {
    pub pid: i32,
    pub pidfd: OwnedFd,
    pub mnt: PathBuf,
}

impl Peer {
    /// The process on the other end of the socket `sock`, looked at while it
    /// is certainly the process that connected. `None` when it is gone, or
    /// cannot be looked at.
    pub fn of(sock: RawFd) -> Option<Self> {
        let pid = crate::sys::peer_pid(sock)?;
        let pidfd = crate::sys::peer_pidfd(sock, pid)?;
        let peer = Self {
            pid,
            pidfd,
            mnt: PathBuf::new(),
        };
        if !peer.alive() {
            return None;
        }
        let mnt = peer.ns("mnt")?;
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

/// Whether the mount namespace `mnt` is the zone's own: the one its holder
/// is in.
pub fn in_zones_own_mounts(state: &Path, zone: &str, mnt: &Path) -> bool {
    let Some(pid) = crate::cli::zone_pid(state, std::ffi::OsStr::new(zone)) else {
        return false;
    };
    std::fs::read_link(format!("/proc/{pid}/ns/mnt")).is_ok_and(|own| own == mnt)
}

/// Whose program the peer is, in `zone`.
pub fn of_peer(places: Places, zone: &str, peer: &Peer) -> Who {
    let running = places.state.join(".running");
    let launched = |pid| crate::registry::launched(&running, pid);
    // The launches of that zone whose owner is known, by their pid: a
    // container's name, or "" for none.
    let mut launches: std::collections::BTreeMap<i32, String> = Default::default();
    for dir in crate::registry::dirs(&running) {
        let dir_name = dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        for (_, record) in crate::registry::live_records(&dir, &launched) {
            if record.zone != zone {
                continue;
            }
            // Whose launch: the directory's container when the record says
            // so itself — a launch of one container writes its name in both
            // places; one from before one container per launch (a layer
            // with a sandbox over it, filed under the layer) is nobody's.
            // Under `__main__`, the main profile (an empty selector) and a
            // sandbox from before one name per container (`sb:<name>`); a
            // throwaway sandbox is nobody's.
            let name = if dir_name == crate::registry::MAIN {
                match record
                    .selector
                    .strip_prefix(crate::container::SANDBOX_PREFIX)
                {
                    Some(_) => crate::container::canonical_in(places.config, &record.selector),
                    None if record.selector.is_empty() => Some(String::new()),
                    None => None,
                }
            } else {
                Some(dir_name.clone())
                    .filter(|n| crate::container::valid_name(n) && record.selector == *n)
            };
            if let Some(name) = name {
                launches.insert(record.pid, name);
            }
        }
    }
    // The nearest launch the peer descends from, its parents read once —
    // before the zone's own namespace: a container of the main home runs in
    // that very namespace, and is its own container all the same.
    let found = crate::sys::ancestors(peer.pid, &peer.pidfd)
        .into_iter()
        .find_map(|pid| launches.get(&pid).cloned());
    match found {
        Some(name) if name.is_empty() => Who::Main,
        // A container that is still one: not a name left by one removed.
        Some(name) if crate::container::exists_in(places.config, places.profiles, &name) => {
            Who::Container(name)
        }
        Some(_) => Who::Unknown,
        // Nothing the registry knows: the zone's own programs are the ones in
        // its own namespace — a link opened by its bus filter, a terminal of
        // the zone's own.
        None if in_zones_own_mounts(places.state, zone, &peer.mnt) => Who::Main,
        None => Who::Unknown,
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
            for dir in ["state/.running", "config", "profiles"] {
                fs::create_dir_all(base.join(dir)).unwrap();
            }
            Self(base)
        }
        fn places(&self) -> (PathBuf, PathBuf, PathBuf) {
            (
                self.0.join("state"),
                self.0.join("config"),
                self.0.join("profiles"),
            )
        }
        /// A launch of `pid` into `zone`, filed under `dir` with `selector`,
        /// its start time on record.
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
            mnt: fs::read_link("/proc/self/ns/mnt").unwrap(),
        }
    }

    fn who(d: &Dirs, zone: &str, peer: &Peer) -> Who {
        let (state, config, profiles) = d.places();
        of_peer(
            Places {
                state: &state,
                config: &config,
                profiles: &profiles,
            },
            zone,
            peer,
        )
    }

    /// A process is its launch's: the container recorded for the launch it
    /// descends from, in that zone — and only while the container is one.
    #[test]
    fn a_process_is_the_container_its_launch_was_for() {
        let d = Dirs::new("launch");
        let peer = me();
        // Nothing launched it, and the zone has no holder: unknown.
        assert_eq!(who(&d, "nl", &peer), Who::Unknown);
        // Our parent is a launch of `work` in nl; `work` is no container yet.
        let parent = crate::sys::parent_of(peer.pid).unwrap();
        d.launch("work", parent, "nl", "work");
        assert_eq!(who(&d, "nl", &peer), Who::Unknown);
        fs::create_dir_all(d.0.join("profiles/work")).unwrap();
        assert_eq!(who(&d, "nl", &peer), Who::Container("work".into()));
        // Another zone's programs are not it.
        assert_eq!(who(&d, "de", &peer), Who::Unknown);
        // The nearest launch wins: we are a launch of the main profile.
        d.launch(crate::registry::MAIN, peer.pid, "nl", "");
        assert_eq!(who(&d, "nl", &peer), Who::Main);
    }

    /// A record that does not say its directory's name, a throwaway sandbox
    /// and a sandbox from before one name per container.
    #[test]
    fn only_a_record_of_a_named_container_names_one() {
        let d = Dirs::new("records");
        let peer = me();
        fs::create_dir_all(d.0.join("profiles/work")).unwrap();
        // Filed under `work`, but a launch of something else.
        d.launch("work", peer.pid, "nl", "__fs__");
        assert_eq!(who(&d, "nl", &peer), Who::Unknown);
        let d = Dirs::new("records-sb");
        fs::create_dir_all(d.0.join("profiles/work")).unwrap();
        d.launch(crate::registry::MAIN, peer.pid, "nl", "sb:work");
        assert_eq!(who(&d, "nl", &peer), Who::Container("work".into()));
        let d = Dirs::new("records-fs");
        d.launch(crate::registry::MAIN, peer.pid, "nl", "__fs__");
        assert_eq!(who(&d, "nl", &peer), Who::Unknown);
    }

    /// A record whose start time is not the process's is somebody else's
    /// number.
    #[test]
    fn a_record_of_a_reused_number_is_nobodys() {
        let d = Dirs::new("reused");
        let peer = me();
        fs::create_dir_all(d.0.join("profiles/work")).unwrap();
        d.launch("work", peer.pid, "nl", "work");
        let note = d.0.join(format!("state/.running/.started/{}", peer.pid));
        assert!(note.exists(), "the start note is not where the test looks");
        fs::write(&note, "1 not-this-boot\n").unwrap();
        assert_eq!(who(&d, "nl", &peer), Who::Unknown);
    }
}
