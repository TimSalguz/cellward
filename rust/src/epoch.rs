//! The epoch wall of a container's instance: which sockets may still go
//! out after its network changed (the container design of 2026-09-27, stage
//! 4, the live switch — `docs/LEAK-MODEL.md` «Смена сети на ходу»).
//!
//! **A socket's cgroup is fixed at its birth** (`sk_cgrp_data`, set when the
//! socket is made from the maker's cgroup, and never moved with its process).
//! So the programs of an instance live in a cgroup of the current *epoch*,
//! `<unit>/e<N>` below the instance's unit (`Delegate=yes`,
//! `DelegateSubgroup=infra`: the keeper and its own are in `<unit>/infra`), and
//! a switch moves them all into `e<N+1>`: every socket made before is of
//! `e<N>` for good, whatever its process does next. The instance's rules let
//! out only a socket of the current epoch (`socket cgroupv2 level L
//! "<unit>/e<N>"`, `zone::instance_ruleset`) — the wall that holds where
//! destroying sockets cannot (`crate::sockdiag`): an unconnected UDP socket, a
//! `SO_REUSEPORT` group, a ping socket.
//!
//! **Where the epoch is written.** [`FILE`] in the instance's directory:
//! `<N> <the cgroup's path>`, rewritten by the keeper under the instance's
//! lock taken exclusively; a launch reads it under the lock taken shared, and
//! its child puts itself in ([`Epoch::place_self`]) before it enters the
//! instance's mount namespace — `/sys/fs/cgroup` is covered there
//! (`zone::cover_cgroupfs`). A program cannot leave its epoch: it has no
//! cgroupfs to write to, and a cgroup it could make would be below it.
//!
//! **A launch that cannot be placed.** The kernel moves a process only for
//! a writer of the common ancestor's `cgroup.procs`: from a desktop's scope
//! (`user@<uid>.service`, the user's) it can, from a login session's
//! (`session-N.scope` below the root-owned `user-<uid>.slice`) it cannot
//! (stage 1 found it). Such a program stays where it is; before the first
//! switch nothing needs it in (the first epoch's rules have no wall — a
//! program outside has the network as in stage 3), the instance cannot be
//! switched while it runs ([`LiveSwitch`] `outside`), and after a switch
//! the wall is up for good and it has no way out — said to the person.
//!
//! **Whether an instance can be switched live** ([`LIVE_SWITCH`], the
//! keeper's note): its kind (a named container's; not `<c>:<net>`, a
//! throwaway), what its keeper found at its start — its cgroup delegated,
//! nft taking `socket cgroupv2` in its namespace, the kernel destroying
//! sockets (`CONFIG_INET_DIAG_DESTROY`) — and, looked at whenever its
//! programs change, none outside the current epoch.

use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

/// Where the cgroup tree is, in the host's mount namespace.
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// The subgroup systemd puts the instance's keeper in
/// (`DelegateSubgroup=infra` of `vpn-zone-container@.service`).
pub const INFRA: &str = "infra";
/// The instance's current epoch, in its directory: `<N> <cgroup path>`.
pub const FILE: &str = "epoch";
/// Whether the instance can be switched live ([`LiveSwitch`]), in its
/// directory.
pub const LIVE_SWITCH: &str = "live-switch";

/// One epoch of an instance's programs: its number and its cgroup, the path
/// as `/proc/<pid>/cgroup` has it (`/user.slice/…/vpn-zone-container@x.service/e2`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epoch {
    pub n: u32,
    pub path: String,
}

/// A path component nothing of a cgroup's could be: empty, `.`, `..`, or
/// with a quote (nft's string would end there) or a control character.
fn bad_component(c: &str) -> bool {
    c.is_empty() || c == "." || c == ".." || c.contains('"') || c.contains(char::is_control)
}

/// An absolute cgroup path of plain components: what an epoch's is, and
/// what the relay takes for a wall (`relay::Wall`).
pub fn sane_path(path: &str) -> bool {
    path.strip_prefix('/')
        .is_some_and(|rest| !rest.split('/').any(bad_component))
}

impl Epoch {
    /// Epoch `n` of the unit whose cgroup is `unit`.
    pub fn of(unit: &str, n: u32) -> Self {
        Self {
            n,
            path: format!("{unit}/e{n}"),
        }
    }

    /// The unit's cgroup: the path without its last component.
    pub fn unit(&self) -> &str {
        self.path.rsplit_once('/').map_or("", |(unit, _)| unit)
    }

    /// The epoch after this one; `None` past the last number.
    pub fn next(&self) -> Option<Self> {
        Some(Self::of(self.unit(), self.n.checked_add(1)?))
    }

    /// Its depth below the root: what `socket cgroupv2 level` compares at,
    /// for a loader in the initial cgroup namespace (J5 of the design: nft
    /// adds the loader's own depth).
    pub fn level(&self) -> u32 {
        self.path.split('/').filter(|c| !c.is_empty()).count() as u32
    }

    /// Its directory in the host's cgroup tree.
    pub fn dir(&self) -> PathBuf {
        PathBuf::from(format!("{CGROUP_ROOT}{}", self.path))
    }

    /// What the instance's rules wall its way out with: `(level, path)` —
    /// from the second epoch on, the first switch's. The first has no wall:
    /// every program had the network there as before the live switch was, a
    /// launch from a login session included, which no epoch can hold.
    pub fn wall(&self) -> Option<(u32, &str)> {
        (self.n >= 2).then(|| (self.level(), self.path.as_str()))
    }

    /// Whether a process whose `/proc/<pid>/cgroup` is `text` is in this
    /// epoch (or below it, which a program cannot make — cgroupfs is covered
    /// in an instance).
    pub fn holds(&self, text: &str) -> bool {
        crate::kill::cgroup_of(text).is_some_and(|cg| crate::kill::inside(cg, &self.path))
    }

    /// As [`FILE`] has it.
    pub fn text(&self) -> String {
        format!("{} {}\n", self.n, self.path)
    }

    /// [`Epoch::text`] read back — and nothing else: a number from 1, an
    /// absolute path of plain components whose last one is `e<number>`.
    pub fn parse(text: &str) -> Option<Self> {
        let (n, path) = text.trim().split_once(' ')?;
        let n: u32 = n.parse().ok().filter(|n| *n >= 1)?;
        if !sane_path(path) {
            return None;
        }
        let epoch = Self {
            n,
            path: path.to_owned(),
        };
        (epoch.path.ends_with(&format!("/e{n}")) && !epoch.unit().is_empty()).then_some(epoch)
    }

    /// Put the calling process into this epoch: `0` — "myself" — written to
    /// its `cgroup.procs`, as the calling process's user. The kernel's
    /// refusal as it is: a writer that may not write the common ancestor's
    /// `cgroup.procs` (a login session's scope) is refused.
    pub fn place_self(&self) -> io::Result<()> {
        let mut procs = fs::OpenOptions::new()
            .write(true)
            .open(self.dir().join("cgroup.procs"))?;
        procs.write_all(b"0")
    }
}

/// The epoch in the instance's directory `dir`, when there is one that
/// reads as one.
pub fn read(dir: &Path) -> Option<Epoch> {
    Epoch::parse(&fs::read_to_string(dir.join(FILE)).ok()?)
}

/// A small file of the instance's directory replaced whole: a reader sees
/// the old text or the new, never none (the user's alone, 0600).
pub fn write_whole(dir: &Path, name: &str, text: &str) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = dir.join(format!(".{name}.tmp"));
    let _ = fs::remove_file(&tmp);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(text.as_bytes())?;
    drop(file);
    fs::rename(&tmp, dir.join(name))
}

/// The epoch written into the instance's directory.
pub fn write(dir: &Path, epoch: &Epoch) -> io::Result<()> {
    write_whole(dir, FILE, &epoch.text())
}

/// The unit's own cgroup, from this process's `/proc/self/cgroup` text: the
/// keeper is in `<unit>/infra`, and `<unit>` is named `unit_name`. `None`
/// anywhere else — the keeper run by hand, or by a test's stand-in, has no
/// delegated cgroup of the unit's, and its instance no epochs.
pub fn unit_of(text: &str, unit_name: &str) -> Option<String> {
    let own = crate::kill::cgroup_of(text)?;
    let unit = own.strip_suffix(&format!("/{INFRA}"))?;
    let last = unit.rsplit_once('/').map(|(_, last)| last)?;
    (last == unit_name && !unit.split('/').skip(1).any(bad_component)).then(|| unit.to_owned())
}

/// Make the epoch's cgroup. One that is there already is an error: a new
/// epoch is a new cgroup, never one something may have been put in.
pub fn make(epoch: &Epoch) -> io::Result<()> {
    fs::create_dir(epoch.dir())
}

/// Freeze (`true`) or thaw the epoch's cgroup (`cgroup.freeze`).
pub fn freeze(epoch: &Epoch, on: bool) -> io::Result<()> {
    fs::write(
        epoch.dir().join("cgroup.freeze"),
        if on { &b"1"[..] } else { &b"0"[..] },
    )
}

/// Whether anything lives in the epoch's cgroup (`populated` of its
/// `cgroup.events`).
pub fn populated(epoch: &Epoch) -> io::Result<bool> {
    let text = fs::read_to_string(epoch.dir().join("cgroup.events"))?;
    Ok(events_populated(&text))
}

/// `populated 1` in a `cgroup.events` text.
pub fn events_populated(text: &str) -> bool {
    text.lines()
        .filter_map(|l| l.split_once(' '))
        .any(|(key, value)| key == "populated" && value.trim() == "1")
}

/// The pids in a `cgroup.procs` text.
pub fn procs_of(text: &str) -> Vec<i32> {
    text.lines().filter_map(|l| l.trim().parse().ok()).collect()
}

/// Why a wait of the keeper's gave up.
#[derive(Debug)]
pub enum Gave {
    /// The keeper was told to stop meanwhile.
    Stopped,
    /// The cgroup could not be read or written.
    Io(io::Error),
}

impl std::fmt::Display for Gave {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stopped => write!(f, "stopped meanwhile"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

/// Every process of `from` moved into `to`, until `from` has nobody —
/// `populated 0`, looked at again whenever its `cgroup.events` changes
/// (inotify), and pass after pass: a process of `from` made meanwhile is
/// moved by the next one. `from` frozen first ([`freeze`]), nothing in it
/// forks, and it converges; no wait for `frozen 1`: a task on its way to
/// the freeze moves as well. `wake`/`stop`: the keeper's word to give up.
/// No clock: a process that cannot be moved at all (gone meanwhile) is
/// skipped, and one that is there and refused ends the wait with the error.
pub fn move_all(
    from: &Epoch,
    to: &Epoch,
    wake: Option<RawFd>,
    stop: &dyn Fn() -> bool,
) -> Result<(), Gave> {
    let events = from.dir().join("cgroup.events");
    let watch = crate::sys::Inotify::watch_for(&events, libc::IN_MODIFY).ok();
    let into = to.dir().join("cgroup.procs");
    loop {
        if stop() {
            return Err(Gave::Stopped);
        }
        let mut text = String::new();
        fs::File::open(from.dir().join("cgroup.procs"))
            .and_then(|mut f| f.read_to_string(&mut text))
            .map_err(Gave::Io)?;
        let pids = procs_of(&text);
        for pid in &pids {
            // One write per pid: the kernel takes one number a write.
            match fs::write(&into, pid.to_string()) {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
                Err(e) => return Err(Gave::Io(e)),
            }
        }
        if !populated(from).map_err(Gave::Io)? {
            return Ok(());
        }
        if !pids.is_empty() {
            continue;
        }
        wait_for(watch.as_ref(), wake).map_err(Gave::Io)?;
    }
}

/// Wait for the watch (or the keeper's wake-up pipe) to have something; no
/// watch at all is looked at again every `sys::LOOK_AGAIN` — which decides
/// how soon, never what.
fn wait_for(watch: Option<&crate::sys::Inotify>, wake: Option<RawFd>) -> io::Result<()> {
    let mut fds = [
        libc::pollfd {
            fd: watch.map_or(-1, AsRawFd::as_raw_fd),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: wake.unwrap_or(-1),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let ms = if watch.is_some() {
        -1
    } else {
        crate::sys::LOOK_AGAIN.as_millis() as libc::c_int
    };
    // SAFETY: two valid pollfds for the duration of the call; a negative
    // descriptor is skipped.
    let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, ms) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            std::thread::sleep(crate::sys::LOOK_AGAIN);
        }
        return Ok(());
    }
    if fds[0].revents != 0 {
        if let Some(watch) = watch {
            watch.names()?;
        }
    }
    // The keeper's wake-up pipe emptied, as its other waits do: what woke
    // it is in its flags (a stop, a child's end), looked at by the caller.
    if fds[1].revents != 0 {
        if let Some(wake) = wake {
            let mut buf = [0u8; 64];
            // SAFETY: read(2) into a buffer of the length passed; the pipe
            // is non-blocking.
            while unsafe { libc::read(wake, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
        }
    }
    Ok(())
}

/// The epoch's cgroup removed — empty by then ([`move_all`]).
pub fn remove(epoch: &Epoch) -> io::Result<()> {
    fs::remove_dir(epoch.dir())
}

/// Whether an instance can be switched live, as its keeper noted it
/// ([`LIVE_SWITCH`]): yes, or no and why — a word `status --json` and the
/// switch's refusal say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveSwitch {
    Yes,
    /// `kind` (a container of the main home per network, a throwaway), `cgroup`
    /// (no delegated cgroup of the unit's), `nft-socket` (nft cannot load
    /// `socket cgroupv2` in its namespace — the module, `nft_socket`),
    /// `sock-destroy` (the kernel has no `SOCK_DESTROY`), `outside` (a
    /// program runs outside the current epoch — launched from a login
    /// session).
    No(String),
}

impl LiveSwitch {
    pub fn text(&self) -> String {
        match self {
            Self::Yes => "yes\n".to_owned(),
            Self::No(why) => format!("no {why}\n"),
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if text == "yes" {
            return Some(Self::Yes);
        }
        let why = text.strip_prefix("no ")?;
        (!why.is_empty() && why.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'))
            .then(|| Self::No(why.to_owned()))
    }

    /// Why not, or `None` when it can.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Yes => None,
            Self::No(why) => Some(why.as_str()),
        }
    }
}

/// What the instance's keeper found — `ready` for the switch or why not —
/// in the order it is said: its kind first, then what its start found, then
/// its programs.
pub fn live_switch(kind_ok: bool, found: Result<(), &str>, outside: usize) -> LiveSwitch {
    if !kind_ok {
        return LiveSwitch::No("kind".to_owned());
    }
    if let Err(why) = found {
        return LiveSwitch::No(why.to_owned());
    }
    if outside > 0 {
        return LiveSwitch::No("outside".to_owned());
    }
    LiveSwitch::Yes
}

/// The keeper's note, when there is one that reads as one.
pub fn read_live(dir: &Path) -> Option<LiveSwitch> {
    LiveSwitch::parse(&fs::read_to_string(dir.join(LIVE_SWITCH)).ok()?)
}

/// The keeper's note written.
pub fn write_live(dir: &Path, live: &LiveSwitch) -> io::Result<()> {
    write_whole(dir, LIVE_SWITCH, &live.text())
}

/// What `frame-relay --probe` found in an instance's network namespace:
/// `nft-socket=<yes|no> destroy=<yes|no>` — the start's part of
/// [`live_switch`]: `Ok` or the reason's word.
pub fn probe_verdict(line: &str) -> Result<(), &'static str> {
    let said = |key: &str| {
        line.split_whitespace()
            .find_map(|w| w.strip_prefix(key)?.strip_prefix('='))
    };
    if said("nft-socket") != Some("yes") {
        return Err("nft-socket");
    }
    if said("destroy") != Some("yes") {
        return Err("sock-destroy");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNIT: &str = "/user.slice/user-1000.slice/user@1000.service/app.slice/\
                        vpn-zone-container@work.service";

    #[test]
    fn an_epoch_is_a_cgroup_below_its_unit_and_its_level_is_its_depth() {
        let e = Epoch::of(UNIT, 1);
        assert_eq!(e.path, format!("{UNIT}/e1"));
        assert_eq!(e.unit(), UNIT);
        assert_eq!(e.level(), 6);
        assert_eq!(e.dir(), PathBuf::from(format!("/sys/fs/cgroup{UNIT}/e1")));
        let next = e.next().unwrap();
        assert_eq!((next.n, next.path.clone()), (2, format!("{UNIT}/e2")));
        assert_eq!(next.level(), 6);
        assert_eq!(Epoch::of(UNIT, u32::MAX).next(), None);
    }

    /// The first epoch has no wall — every program had the network there as
    /// before, one from a login session included —; from the first switch
    /// on the rules name the epoch's cgroup.
    #[test]
    fn the_wall_stands_from_the_second_epoch_on() {
        assert_eq!(Epoch::of(UNIT, 1).wall(), None);
        let second = Epoch::of(UNIT, 2);
        assert_eq!(second.wall(), Some((6, second.path.as_str())));
    }

    #[test]
    fn an_epoch_is_read_back_and_nothing_else() {
        let e = Epoch::of(UNIT, 3);
        assert_eq!(Epoch::parse(&e.text()), Some(e.clone()));
        // A unit's escaped name as the cgroup has it.
        let odd = Epoch::of("/user.slice/vpn-zone-container@a\\x2db.service", 1);
        assert_eq!(Epoch::parse(&odd.text()), Some(odd));
        for bad in [
            "",
            "1",
            "0 /a/e0",
            "x /a/e1",
            "1 a/e1",
            "1 /a/e2",
            "2 /a/e1",
            "1 /e1",
            "1 /a/../e1",
            "1 /a//e1",
            "1 /a\"b/e1",
            "1 /a\nb/e1",
            "-1 /a/e-1",
        ] {
            assert_eq!(Epoch::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_process_is_in_its_epoch_by_its_cgroup_line() {
        let e = Epoch::of(UNIT, 2);
        assert!(e.holds(&format!("0::{UNIT}/e2\n")));
        assert!(e.holds(&format!("0::{UNIT}/e2/nested\n")));
        assert!(!e.holds(&format!("0::{UNIT}/e1\n")));
        assert!(!e.holds(&format!("0::{UNIT}/e22\n")));
        assert!(!e.holds(&format!("0::{UNIT}/infra\n")));
        assert!(!e.holds("0::/user.slice/user-1000.slice/session-2.scope\n"));
        assert!(!e.holds(""));
    }

    /// The keeper's unit, from its own cgroup: `<unit>/infra`, the unit by
    /// its name — nothing else (a keeper run by hand has none).
    #[test]
    fn the_units_cgroup_is_the_keepers_parent() {
        let name = "vpn-zone-container@work.service";
        assert_eq!(
            unit_of(&format!("0::{UNIT}/infra\n"), name).as_deref(),
            Some(UNIT)
        );
        assert_eq!(unit_of(&format!("0::{UNIT}\n"), name), None);
        assert_eq!(unit_of(&format!("0::{UNIT}/e1\n"), name), None);
        assert_eq!(
            unit_of(
                &format!("0::{UNIT}/infra\n"),
                "vpn-zone-container@other.service"
            ),
            None
        );
        assert_eq!(
            unit_of("0::/user.slice/user-1000.slice/session-2.scope\n", name),
            None
        );
        assert_eq!(unit_of("", name), None);
    }

    #[test]
    fn cgroup_files_are_read_as_the_kernel_writes_them() {
        assert!(events_populated("populated 1\nfrozen 0\n"));
        assert!(!events_populated("populated 0\nfrozen 1\n"));
        assert!(!events_populated(""));
        assert_eq!(procs_of("12\n345\n\n"), vec![12, 345]);
        assert!(procs_of("").is_empty());
    }

    /// Its kind first, then what its start found, then its programs.
    #[test]
    fn whether_it_can_be_switched_says_the_first_reason() {
        assert_eq!(live_switch(true, Ok(()), 0), LiveSwitch::Yes);
        assert_eq!(
            live_switch(false, Err("nft-socket"), 3),
            LiveSwitch::No("kind".to_owned())
        );
        assert_eq!(
            live_switch(true, Err("cgroup"), 3),
            LiveSwitch::No("cgroup".to_owned())
        );
        assert_eq!(
            live_switch(true, Ok(()), 1),
            LiveSwitch::No("outside".to_owned())
        );
        for live in [
            LiveSwitch::Yes,
            LiveSwitch::No("outside".to_owned()),
            LiveSwitch::No("sock-destroy".to_owned()),
        ] {
            assert_eq!(LiveSwitch::parse(&live.text()), Some(live));
        }
        for bad in ["", "no", "no ", "maybe", "no Outside", "no a b"] {
            assert_eq!(LiveSwitch::parse(bad), None, "{bad:?}");
        }
        assert_eq!(LiveSwitch::No("kind".to_owned()).reason(), Some("kind"));
        assert_eq!(LiveSwitch::Yes.reason(), None);
    }

    #[test]
    fn the_probes_line_is_judged_word_by_word() {
        assert_eq!(probe_verdict("nft-socket=yes destroy=yes"), Ok(()));
        assert_eq!(
            probe_verdict("nft-socket=no destroy=yes"),
            Err("nft-socket")
        );
        assert_eq!(
            probe_verdict("nft-socket=yes destroy=no"),
            Err("sock-destroy")
        );
        assert_eq!(probe_verdict(""), Err("nft-socket"));
        assert_eq!(probe_verdict("destroy=yes nft-socket=yes"), Ok(()));
    }
}
