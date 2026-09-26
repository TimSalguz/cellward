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
//! **With no launch in its ancestry**, a process in the zone's own mount
//! namespace is one of the zone's own programs, with no container. Every
//! launch into a container takes a mount namespace of its own — a container
//! of the main home too, with nothing mounted in it (`launch::Entry::
//! own_mounts`) — and a program cannot leave it: `setns` wants capabilities
//! it does not have. So one that left its launch (a daemon that forked
//! twice, a program whose launch is over) is never taken for the zone's own.
//! (The wrapper around a launch — `wl-sandbox` — stays on the host: the
//! namespace of a launch's recorded process is not its programs'.)
//!
//! **Unknown** is everything else: a throwaway or temporary container (they
//! have no name to keep a setting under), a name no container has any more,
//! a program that left its launch, a number two launches claim. It is never
//! taken for another container, nor for the zone's own programs: what
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
/// pidfd, and its mount namespace when it could be read.
#[derive(Debug)]
pub struct Peer {
    pub pid: i32,
    pub pidfd: OwnedFd,
    /// `None` when its `/proc` is out of reach — a process that made itself
    /// not dumpable (a sandbox's bus filter) is, to a helper without
    /// capabilities: then it is known by its launch alone, never taken for
    /// one of the zone's own.
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

/// Below a zone's state directory: the containers launched into the zone
/// since it came up, a name a line (`launch::run` adds, the holder clears
/// it when the zone comes up). Their programs may still be there when the
/// launch is over — for what decides for the whole zone at once
/// ([`containers_in`]). Out of the zones' reach, as the zone's directory is.
pub const LAUNCHED: &str = "launched-containers";

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
    /// one container per launch, a number two launches claim).
    owner: Option<String>,
}

/// Every live launch into `zone`: its record there, its start time on
/// record and the same (`registry::launched`).
fn launches(places: Places, zone: &str) -> Vec<Launch> {
    let running = places.state.join(".running");
    let launched = |pid| crate::registry::launched(&running, pid);
    let mut out: Vec<Launch> = Vec::new();
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
            // The start notes are per number, not per record: a stale record
            // of one container whose number a launch of another took reads
            // as live too. A number two owners claim is nobody's.
            match out.iter_mut().find(|l| l.pid == record.pid) {
                Some(seen) if seen.owner != owner => seen.owner = None,
                Some(_) => {}
                None => out.push(Launch {
                    pid: record.pid,
                    owner,
                }),
            }
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

/// Whose program the peer is, in `zone`.
pub fn of_peer(places: Places, zone: &str, peer: &Peer) -> Who {
    let own = zones_own_mounts(places.state, zone);
    of_peer_in(places, zone, peer, own.as_deref())
}

/// [`of_peer`], the zone's own mount namespace given: a helper that lives in
/// it has it as its own (`/proc/self/ns/mnt`) — the holder's `/proc`, which
/// has capabilities the helper has not, may be out of its reach.
pub fn of_peer_in(places: Places, zone: &str, peer: &Peer, own_mnt: Option<&Path>) -> Who {
    let live = launches(places, zone);
    // The nearest launch the peer descends from, its parents read once —
    // before the zone's own namespace: a program of the main profile runs in
    // that very namespace. The nearest decides, nobody's too: a throwaway
    // sandbox started under a container's program is not that container.
    let nearest = crate::sys::ancestors(peer.pid, &peer.pidfd)
        .into_iter()
        .find_map(|pid| live.iter().find(|l| l.pid == pid));
    if let Some(launch) = nearest {
        return owner_of(places, launch.owner.as_deref());
    }
    // Nothing the registry knows: the zone's own programs are the ones in
    // its own namespace — a link opened by its bus filter, a terminal of the
    // zone's own — read again now: still the peer's, still that one.
    let still = peer.ns("mnt");
    if own_mnt.is_some() && own_mnt == still.as_deref() && still == peer.mnt {
        Who::Main
    } else {
        Who::Unknown
    }
}

/// The containers whose programs may be in `zone` now: every one with a live
/// launch into it, and every one launched into it since it came up
/// ([`LAUNCHED`]) — a daemon may outlive its launch. For what decides for
/// all the zone's programs at once, and so must be as strict as the
/// strictest of them.
pub fn containers_in(places: Places, zone: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |name: &str| {
        if crate::container::valid_name(name) && !out.iter().any(|n| n == name) {
            out.push(name.to_owned());
        }
    };
    for launch in launches(places, zone) {
        if let Some(name) = launch.owner.as_deref() {
            add(name);
        }
    }
    let file = places.state.join(zone).join(LAUNCHED);
    for line in std::fs::read_to_string(file).unwrap_or_default().lines() {
        add(line.trim());
    }
    out
}

/// Note a launch of `container` into `zone` ([`LAUNCHED`]) — not again when
/// it is listed already, so the list does not grow with every launch (two
/// first launches at once may both add it: [`containers_in`] reads each
/// name once).
pub fn note_launched(state: &Path, zone: &str, container: &str) -> std::io::Result<()> {
    use std::io::Write;
    let path = state.join(zone).join(LAUNCHED);
    let listed = std::fs::read_to_string(&path).unwrap_or_default();
    if listed.lines().any(|line| line.trim() == container) {
        return Ok(());
    }
    // One write, the name and its newline together: two launches at once
    // (autostart) must not run their names into one line.
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?
        .write_all(format!("{container}\n").as_bytes())
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
            mnt: Some(fs::read_link("/proc/self/ns/mnt").unwrap()),
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

    /// No launch in its ancestry: in the zone's own namespace, the zone's;
    /// anywhere else — a namespace a launch made for its container, which
    /// the program left — not known.
    #[test]
    fn a_process_that_left_its_launch_is_not_known() {
        let d = Dirs::new("namespace");
        let peer = me();
        fs::create_dir_all(d.0.join("profiles/work")).unwrap();
        // A launch of `work` we do not descend from.
        let launch = Sleeper::new();
        d.launch("work", launch.pid(), "nl", "work");
        assert_eq!(who(&d, "nl", &peer), Who::Unknown);
        // Our namespace is the zone's own: its holder is in it.
        let zone = d.0.join("state/nl");
        fs::create_dir_all(&zone).unwrap();
        let holder = Sleeper::new();
        fs::write(zone.join("zone.pid"), holder.pid().to_string()).unwrap();
        let stamp = crate::sys::process_stamp(holder.pid()).unwrap();
        fs::write(zone.join("zone.start"), stamp).unwrap();
        assert_eq!(who(&d, "nl", &peer), Who::Main);
        // A peer read in another namespace than it is in now is not.
        let moved = Peer {
            mnt: Some(PathBuf::from("mnt:[1]")),
            ..me()
        };
        assert_eq!(who(&d, "nl", &moved), Who::Unknown);
    }

    /// One number, two launches' records: nobody's.
    #[test]
    fn a_number_two_launches_claim_is_nobodys() {
        let d = Dirs::new("claimed");
        let peer = me();
        fs::create_dir_all(d.0.join("profiles/work")).unwrap();
        fs::create_dir_all(d.0.join("profiles/other")).unwrap();
        d.launch("work", peer.pid, "nl", "work");
        assert_eq!(who(&d, "nl", &peer), Who::Container("work".into()));
        d.launch("other", peer.pid, "nl", "other");
        assert_eq!(who(&d, "nl", &peer), Who::Unknown);
    }

    /// What may be in a zone: the live launches' containers and those
    /// launched into it since it came up.
    #[test]
    fn the_containers_in_a_zone_are_the_running_and_the_launched() {
        let d = Dirs::new("containers-in");
        let launch = Sleeper::new();
        d.launch("work", launch.pid(), "nl", "work");
        fs::create_dir_all(d.0.join("state/nl")).unwrap();
        note_launched(&d.0.join("state"), "nl", "gone").unwrap();
        note_launched(&d.0.join("state"), "nl", "work").unwrap();
        let (state, config, profiles) = d.places();
        let places = Places {
            state: &state,
            config: &config,
            profiles: &profiles,
        };
        let mut found = containers_in(places, "nl");
        found.sort();
        assert_eq!(found, ["gone", "work"]);
        assert!(containers_in(places, "de").is_empty());
    }

    /// A process whose namespace could not be read (not dumpable, to a
    /// helper without capabilities) is known by its launch all the same —
    /// and never taken for one of the zone's own without it.
    #[test]
    fn a_process_whose_namespace_is_out_of_reach_is_known_by_its_launch() {
        let d = Dirs::new("unreadable");
        let blind = Peer { mnt: None, ..me() };
        let own = fs::read_link("/proc/self/ns/mnt").unwrap();
        let (state, config, profiles) = d.places();
        let places = Places {
            state: &state,
            config: &config,
            profiles: &profiles,
        };
        // In the zone's own namespace, but not known to be: not the zone's.
        assert_eq!(of_peer_in(places, "nl", &blind, Some(&own)), Who::Unknown);
        assert_eq!(of_peer_in(places, "nl", &me(), Some(&own)), Who::Main);
        fs::create_dir_all(d.0.join("profiles/work")).unwrap();
        let parent = crate::sys::parent_of(blind.pid).unwrap();
        d.launch("work", parent, "nl", "work");
        assert_eq!(
            of_peer_in(places, "nl", &blind, Some(&own)),
            Who::Container("work".into())
        );
    }
}
