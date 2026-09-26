//! Which container of a zone a process is a program of (`docs/PERMISSIONS.md`
//! §11.10) — for the zone's helpers on the host, which decide by the
//! container and not by the zone: the broker, the sound filter.
//!
//! **By its launch.** The container is the one a launch of which, in that
//! zone, the process descends from: the launcher recorded in the registry
//! (`.running`), taken only with its start time on record and the same
//! (`registry::launched`: a number that went to somebody else is nobody's
//! launch), and the chain of parents read with each held (`sys::ancestors`).
//! The nearest launch decides, whoever's it is. Nothing a program says about
//! itself counts.
//!
//! **With no launch in its ancestry** — a daemon that forked twice, a
//! program whose launch is over — by its mount namespace, which a program
//! cannot leave (`setns` wants capabilities it does not have). A launch into
//! a container with a home of its own or a layer takes a namespace of its
//! own: a process in the namespace of a live launch is that launch's. A
//! process in the zone's own namespace is one of the zone's own programs,
//! with no container — unless a container of the main home, which runs in
//! that very namespace, has a launch running in the zone: then it may be
//! one that left that container, and the caller says what it is taken for
//! ([`of_peer`]'s `ambiguous`).
//!
//! **Unknown** is everything else: a throwaway or temporary container (they
//! have no name to keep a setting under), a name no container has any more,
//! a namespace no live launch has. It is never taken for another container,
//! nor for the zone's own programs: what decides by the container treats it
//! as the least known — no "always".
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

/// The zone's own mount namespace: the one its holder is in.
fn zones_own_mounts(state: &Path, zone: &str) -> Option<PathBuf> {
    let pid = crate::cli::zone_pid(state, std::ffi::OsStr::new(zone))?;
    std::fs::read_link(format!("/proc/{pid}/ns/mnt")).ok()
}

/// A live launch into a zone, as the registry has it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Launch {
    pid: i32,
    /// Whose: a container's name, `""` for the main profile, `None` for
    /// nobody's (a throwaway or temporary container, a record from before
    /// one container per launch).
    owner: Option<String>,
}

/// Every live launch into `zone`: its record there, its start time on
/// record and the same (`registry::launched`).
fn launches(places: Places, zone: &str) -> Vec<Launch> {
    let running = places.state.join(".running");
    let launched = |pid| crate::registry::launched(&running, pid);
    let mut out = Vec::new();
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
            let owner = if dir_name == crate::registry::MAIN {
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
            out.push(Launch {
                pid: record.pid,
                owner,
            });
        }
    }
    out
}

/// Whose a launch's programs are.
fn owner_of(places: Places, owner: Option<&str>) -> Who {
    match owner {
        Some("") => Who::Main,
        // A container that is still one: not a name left by one removed.
        Some(name) if crate::container::exists_in(places.config, places.profiles, name) => {
            Who::Container(name.to_owned())
        }
        _ => Who::Unknown,
    }
}

/// The mount namespace of a process — the launch's own process: `None` if
/// it cannot be read, or the number is no longer that launch's.
fn mounts_of(running: &Path, pid: i32) -> Option<PathBuf> {
    let mnt = std::fs::read_link(format!("/proc/{pid}/ns/mnt")).ok()?;
    crate::registry::launched(running, pid).then_some(mnt)
}

/// Whose program the peer is, in `zone`.
///
/// `ambiguous`: what a peer in the zone's own namespace with no launch in
/// its ancestry is while a container of the main home has a launch running
/// in that zone — it may be a program of the zone's own, or one that left
/// that container's launch (a container of the main home has no mount
/// namespace of its own yet: `docs/PERMISSIONS.md` §11.11, 8). What decides
/// something a program must not get by leaving its container says
/// [`Who::Unknown`]; the broker, whose question for it would be every link
/// the zone opens, says [`Who::Main`].
pub fn of_peer(places: Places, zone: &str, peer: &Peer, ambiguous: Who) -> Who {
    let live = launches(places, zone);
    // The nearest launch the peer descends from, its parents read once —
    // before the zone's own namespace: a container of the main home runs in
    // that very namespace, and is its own container all the same. The
    // nearest decides, nobody's too: a throwaway sandbox started under a
    // container's program is not that container.
    let nearest = crate::sys::ancestors(peer.pid, &peer.pidfd)
        .into_iter()
        .find_map(|pid| live.iter().find(|l| l.pid == pid));
    if let Some(launch) = nearest {
        return owner_of(places, launch.owner.as_deref());
    }
    // No launch in its ancestry: it left one — a daemon that forked twice, a
    // program whose launch is over — or never had one. By its mount
    // namespace, which a program cannot leave (`setns` wants capabilities it
    // does not have).
    let running = places.state.join(".running");
    let own = zones_own_mounts(places.state, zone);
    if own.as_deref() == Some(peer.mnt.as_path()) {
        // The zone's own programs are the ones in its own namespace — a
        // link opened by its bus filter, a terminal of the zone's own; but
        // so are those of a container of the main home.
        let main_home_running = live.iter().any(|l| {
            l.owner.as_deref().is_some_and(|o| !o.is_empty()) && mounts_of(&running, l.pid) == own
        });
        return if main_home_running {
            ambiguous
        } else {
            Who::Main
        };
    }
    // A namespace a launch made for its container: that launch's.
    let mut owners = live
        .iter()
        .filter(|l| mounts_of(&running, l.pid).as_deref() == Some(peer.mnt.as_path()))
        .map(|l| owner_of(places, l.owner.as_deref()));
    match (owners.next(), owners.next()) {
        (Some(who), None) => who,
        _ => Who::Unknown,
    }
}

/// Whose programs run in `zone` now, as [`of_peer`] names them: the owner
/// of every live launch into it, each once. The zone's own programs, which
/// need no launch, are not in it.
pub fn running(places: Places, zone: &str) -> Vec<Who> {
    let mut out: Vec<Who> = Vec::new();
    for launch in launches(places, zone) {
        let who = owner_of(places, launch.owner.as_deref());
        if !out.contains(&who) {
            out.push(who);
        }
    }
    out
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
            Who::Unknown,
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

    /// The nearest launch decides, nobody's too: a throwaway sandbox under a
    /// container's program is not that container.
    #[test]
    fn the_nearest_launch_decides_whoever_its_is() {
        let d = Dirs::new("nearest");
        let peer = me();
        fs::create_dir_all(d.0.join("profiles/work")).unwrap();
        let parent = crate::sys::parent_of(peer.pid).unwrap();
        d.launch("work", parent, "nl", "work");
        assert_eq!(who(&d, "nl", &peer), Who::Container("work".into()));
        d.launch(crate::registry::MAIN, peer.pid, "nl", "__fs__");
        assert_eq!(who(&d, "nl", &peer), Who::Unknown);
    }

    /// No launch in its ancestry: a process in the namespace of a live launch
    /// is that launch's; in the zone's own, the zone's — unless a container
    /// of the main home runs there, when it is what the caller says.
    #[test]
    fn a_process_that_left_its_launch_is_known_by_its_namespace() {
        let d = Dirs::new("namespace");
        let peer = me();
        fs::create_dir_all(d.0.join("profiles/work")).unwrap();
        // A launch of `work` we do not descend from, in our namespace.
        let launch = Sleeper::new();
        d.launch("work", launch.pid(), "nl", "work");
        assert_eq!(who(&d, "nl", &peer), Who::Container("work".into()));
        // Two launches in it: not known whose.
        let other = Sleeper::new();
        d.launch(crate::registry::MAIN, other.pid(), "nl", "__fs__");
        assert_eq!(who(&d, "nl", &peer), Who::Unknown);

        // Our namespace is the zone's own: its holder is in it.
        let d = Dirs::new("namespace-own");
        let holder = Sleeper::new();
        let zone = d.0.join("state/nl");
        fs::create_dir_all(&zone).unwrap();
        fs::write(zone.join("zone.pid"), holder.pid().to_string()).unwrap();
        let stamp = crate::sys::process_stamp(holder.pid()).unwrap();
        fs::write(zone.join("zone.start"), stamp).unwrap();
        assert_eq!(who(&d, "nl", &peer), Who::Main);
        // A container of the main home runs in it: ambiguous.
        fs::create_dir_all(d.0.join("profiles/main-nl")).unwrap();
        let main_home = Sleeper::new();
        d.launch("main-nl", main_home.pid(), "nl", "main-nl");
        assert_eq!(who(&d, "nl", &peer), Who::Unknown);
        let (state, config, profiles) = d.places();
        let places = Places {
            state: &state,
            config: &config,
            profiles: &profiles,
        };
        assert_eq!(of_peer(places, "nl", &peer, Who::Main), Who::Main);
        // What runs in the zone.
        assert_eq!(
            running(places, "nl"),
            vec![Who::Container("main-nl".into())]
        );
    }
}
