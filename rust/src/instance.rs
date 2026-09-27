//! Container instances: a running container, with network, mount, IPC and
//! (later) pid namespaces of its own — the unit of isolation of the
//! container design of 2026-09-27, where a zone is only transport.
//!
//! Stage 0 (2026-09-27): the names. Which instance a launch runs in
//! ([`id_of`]), the unit that holds it ([`unit_name`]) and where its state
//! lies ([`dir`] and the file names below).
//!
//! Stage 1 (2026-09-27): instances with no way out. Every launch whose
//! network is `offline` runs in its container's instance, held by
//! `vpn-zone-container@<id>.service` (`vpn-zone-core container-holder`,
//! `crate::zone::run_instance`) and entered by `vpn-zone-core
//! container-enter` (`crate::enter`); the `offline` zone itself is never
//! started for a launch any more. What an instance is to be comes from its
//! id alone ([`Plan`]); whether it is up, and where, from its directory
//! ([`up`], [`running`]). Zones, and launches into them, are as they were.
//!
//! **The id.** A container's name can never hold a `:` (`container::
//! valid_name`), so the kinds below cannot be taken for one another:
//!
//! * `<c>` — a named container: one network at a time (`docs/CONTAINERS.md`
//!   I1, I2). One whose network is `ask` takes the network of its first
//!   launch, for as long as the instance runs;
//! * `<c>:<network>` — a container of the main home whose network is
//!   `ask`, and the built-in main (`main:<network>`): the real home in
//!   several networks at once, one instance per network;
//! * `:tmp:<layer>` — a throwaway container, by its layer directory's name;
//! * `:fs:<name>` — a throwaway filesystem sandbox.
//!
//! `unconfined` has no instance: it is the host's network, and its
//! programs are host processes.
//!
//! Stage 2 (2026-09-27): an instance's network may be a zone — its way out
//! through that zone's bridge (`crate::bridge`), fixed for its life. Which
//! network is the id's own for `<c>:<network>` and `main:<network>`, and for
//! the others what the launch that started it asked ([`ask_network`]: a
//! file beside the instance's directory, which an ending instance does not
//! take with it). Its space writes [`SPACE_READY`] once it is set up; its
//! keeper attaches it, rewrites its [`RESOLV`] in place, notes its [`EXIT`]
//! and only then writes [`READY`]: a launch that finds an instance ready
//! finds it with its way out.
//!
//! Stage 3 (2026-09-27, `docs/THREAT-MODEL.md` X4): an instance has a pid
//! namespace of its own. Its holder makes it and forks the instance's pid 1
//! into it (`crate::init`), whose HOST pid is [`PID`] — the process every
//! reader of an instance on the host holds and reads the namespaces of. A
//! program of the instance sees in `/proc` its own container's processes
//! and no one else's; a launch joins the pid namespace with the others
//! (`crate::enter`), and its `profile-run` stays as the launch's subreaper
//! (`crate::profile`).
//!
//! Stage 4 (2026-09-27, the live switch): its programs are in a cgroup of
//! its current epoch below its unit (`crate::epoch`: `epoch` and
//! `live-switch` in its directory), and its network can be changed while
//! they run.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::origin::Who;

/// Below the state directory: one directory per running instance. A dot
/// directory, so that no listing of zones takes it for one. Each is named
/// by [`key`], not by the id: a socket's path is 108 bytes at most, and an
/// id may be a container's name of 128.
pub const INSTANCES_DIR: &str = ".instances";
/// The instance's id in full, in its directory: what [`key`] was made of.
pub const ID: &str = "id";
/// The network it runs in (`offline` in stage 1), as its keeper resolved it.
pub const NETWORK: &str = "network";
/// The zone-level settings of that network as the instance came up with
/// them, frozen for its life (`hermetic::note_applied`'s format): what
/// `status --json` names as changed since.
pub const SETTINGS: &str = crate::hermetic::APPLIED;
/// Its user namespace, `<dev>:<ino>` of the namespace's file: what its
/// programs are known by (`crate::place`).
pub const USERNS: &str = "userns";
/// The instance's space — the process that holds its network, mount and
/// IPC namespaces (stage 1; its pid 1 from stage 3) — writes its host pid
/// here…
pub const PID: &str = "instance.pid";
/// …and that process's start (`crate::sys::process_stamp`), which tells it
/// from whoever has the number later.
pub const START: &str = "instance.start";
/// Written by the instance's keeper once the instance is set up and its way
/// out attached, as a zone's `ready`: what a launch enters by.
pub const READY: &str = "ready";
/// Written by the instance's space once it is set up (stage 2): the keeper
/// attaches its way out then.
pub const SPACE_READY: &str = "space-ready";
/// What the instance's way out is now ([`Exit`]): `through <zone>` or
/// `none <why>`.
pub const EXIT: &str = "exit";
/// Its `resolv.conf`, bound over the system's by its space and rewritten in
/// place by its keeper with each attach (`bridge::resolv_text`): the
/// constant forwarders and the zone's search domains.
pub const RESOLV: &str = "resolv.conf";
/// Left by `cellward container reattach`, taken by the keeper when the
/// doorbell rings: attach a cut instance to its zone as the zone is now.
pub const REATTACH: &str = "reattach";
/// The holder's control socket, for the host's side only.
pub const CONTROL: &str = "control";
/// Taken shared by a launch until its program is in, exclusively by an idle
/// stop and a switch.
pub const LOCK: &str = "lock";
/// Which build started the instance.
pub const BUILD: &str = "build";
/// The instance's user namespace maps its root to this subordinate id —
/// not a zone's (0), nor the OpenConnect client's (1), nor the bridge's
/// passt's (2): a process with the kuid of a zone's holder may attach to it
/// (J3 of the design).
pub const ROOT_ID: u32 = 3;
/// How many subordinate ids a user needs from stage 1 on: 0 to [`ROOT_ID`].
pub const SUBORDINATE_IDS: u64 = ROOT_ID as u64 + 1;

/// The unit template that holds an instance.
pub const UNIT_PREFIX: &str = "vpn-zone-container@";
pub const UNIT_SUFFIX: &str = ".service";
/// systemd's limit on a unit's name (`UNIT_NAME_MAX` less its NUL).
pub const UNIT_NAME_MAX: usize = 255;

pub const TMP_PREFIX: &str = ":tmp:";
pub const FS_PREFIX: &str = ":fs:";
/// The built-in main's name in an id.
pub const MAIN: &str = "main";

/// What a launch runs in, as far as its instance goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Of<'a> {
    /// A named container: its name, its kind of home, and whether its
    /// network is `ask` rather than bound.
    Container {
        name: &'a str,
        home: crate::container::Home,
        asks: bool,
    },
    /// No container: the built-in main, the real home.
    Main,
    /// A throwaway container, by its layer directory's name.
    Throwaway(&'a str),
    /// A throwaway filesystem sandbox, by its name.
    ThrowawaySandbox(&'a str),
}

/// A network an instance can have: a zone's name, or `offline`. Never
/// `unconfined` (or its old name): that is the host's.
pub fn valid_network(name: &str) -> bool {
    name != crate::launch::UNCONFINED
        && name != crate::launch::UNCONFINED_ALIAS
        && !name.is_empty()
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// A throwaway's directory or sandbox name: one path component of letters,
/// digits, `.`, `_` and `-`, not hidden and no option.
fn valid_component(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with(['.', '-'])
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The instance a launch into `network` runs in. `None` for `unconfined`,
/// for a network no instance can have, and for a name that is no
/// container's.
pub fn id_of(of: Of<'_>, network: &str) -> Option<String> {
    if !valid_network(network) {
        return None;
    }
    match of {
        Of::Container { name, home, asks } => {
            if !crate::container::valid_name(name) {
                return None;
            }
            Some(if home == crate::container::Home::Main && asks {
                format!("{name}:{network}")
            } else {
                name.to_string()
            })
        }
        Of::Main => Some(format!("{MAIN}:{network}")),
        Of::Throwaway(layer) => valid_component(layer).then(|| format!("{TMP_PREFIX}{layer}")),
        Of::ThrowawaySandbox(name) => valid_component(name).then(|| format!("{FS_PREFIX}{name}")),
    }
}

/// Could [`id_of`] have given this? What anything read back — a directory
/// name, a word on a socket — is held to.
pub fn valid_id(id: &str) -> bool {
    if let Some(layer) = id.strip_prefix(TMP_PREFIX) {
        return valid_component(layer);
    }
    if let Some(name) = id.strip_prefix(FS_PREFIX) {
        return valid_component(name);
    }
    match id.split_once(':') {
        Some((name, network)) => {
            (name == MAIN || crate::container::valid_name(name)) && valid_network(network)
        }
        None => crate::container::valid_name(id),
    }
}

/// `systemd-escape` of a unit's instance part: every byte but ASCII letters,
/// digits, `:`, `_` and `.` as `\xNN`, `-` included (it would read as a
/// `/`), and a leading `.` too. An id has no `/` to turn into `-`.
pub fn escape(id: &str) -> String {
    let mut out = String::with_capacity(id.len());
    for (i, b) in id.bytes().enumerate() {
        let plain = b.is_ascii_alphanumeric() || matches!(b, b':' | b'_') || (b == b'.' && i > 0);
        if plain {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    out
}

/// The unit that holds instance `id`: `vpn-zone-container@<escaped>.service`.
/// `None` for an id [`valid_id`] refuses, and for one whose escaped name is
/// longer than systemd takes — a long name in a script of many bytes a
/// letter (a container of 128 Cyrillic letters is 1024 characters escaped).
pub fn unit_name(id: &str) -> Option<String> {
    if !valid_id(id) {
        return None;
    }
    let unit = format!("{UNIT_PREFIX}{}{UNIT_SUFFIX}", escape(id));
    (unit.len() <= UNIT_NAME_MAX).then_some(unit)
}

/// The short name of instance `id`'s places: its state directory's and its
/// Wayland sockets' (`wl_sandbox::SOCKET_DIR`). `i-` and the id's FNV-1a
/// hash in sixteen hex digits — never the id itself (stage 1, 2026-09-27):
/// a socket's path is 108 bytes at most, and `$HOME/.local/state/vpn-zones/
/// .instances/<id>/pipewire-context` with a container's name of 128 bytes
/// in it is not a path `bind(2)` takes; a colon in `WAYLAND_DISPLAY` is
/// one no program has seen before. Two ids of one key would share a
/// directory: the keeper writes the id into it ([`ID`]) and refuses one
/// that holds another's.
pub fn key(id: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in id.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("i-{hash:016x}")
}

/// The instance's state directory: `<state>/.instances/<key>`.
pub fn dir(state: &Path, id: &str) -> PathBuf {
    state.join(INSTANCES_DIR).join(key(id))
}

/// A one-line file of an instance's directory, trimmed; `None` when it is
/// not there or empty.
fn read_word(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let word = text.trim();
    (!word.is_empty()).then(|| word.to_owned())
}

/// The space's pid in `dir`, when the process by that number is the one
/// that wrote it: its start on record and the same (as `cli::zone_pid`).
fn space_pid(dir: &Path) -> Option<i32> {
    let pid: i32 = read_word(&dir.join(PID))?.parse().ok().filter(|p| *p > 0)?;
    let stamp = read_word(&dir.join(START))?;
    (crate::sys::process_stamp(pid).as_deref() == Some(stamp.as_str())).then_some(pid)
}

/// The host pid of instance `id`'s space when the instance is up and ready:
/// its directory names this id, `ready` is there, and the process is the
/// one that wrote its number. Nothing else is entered or believed.
pub fn up(state: &Path, id: &str) -> Option<i32> {
    let dir = dir(state, id);
    if read_word(&dir.join(ID)).as_deref() != Some(id) || !dir.join(READY).is_file() {
        return None;
    }
    space_pid(&dir)
}

/// The host pid of instance `id`'s space as [`up`] finds it, ready or not
/// yet: for its keeper, which attaches the space's way out before it says
/// the instance is ready.
pub fn space(state: &Path, id: &str) -> Option<i32> {
    let dir = dir(state, id);
    if read_word(&dir.join(ID)).as_deref() != Some(id) {
        return None;
    }
    space_pid(&dir)
}

/// Where a launch says which network instance `id` is to run in, when its
/// id does not ([`Plan::of`]): `<state>/.instances/<key>.network`, beside
/// the instance's directory — which an instance that ends takes with it,
/// while a launch may be writing this for the next one.
pub fn want_path(state: &Path, id: &str) -> PathBuf {
    state
        .join(INSTANCES_DIR)
        .join(format!("{}.network", key(id)))
}

/// Ask for instance `id` in `network` ([`want_path`]), before its unit is
/// started: whole or not at all (a rename), the user's alone.
pub fn ask_network(state: &Path, id: &str, network: &str) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let path = want_path(state, id);
    if let Some(parent) = path.parent() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    let tmp = path.with_extension("network.tmp");
    fs::write(&tmp, format!("{network}\n"))?;
    fs::rename(&tmp, &path)
}

/// What [`ask_network`] asked, when it is a network an instance can have.
fn wanted_network(state: &Path, id: &str) -> Option<String> {
    read_word(&want_path(state, id)).filter(|network| valid_network(network))
}

/// What an instance's way out is ([`EXIT`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exit {
    /// Out through this zone.
    Through(String),
    /// None, and why: `offline` (none asked for), `zone-down` (cut by the
    /// zone's end, re-attached when it comes back the same), `zone-changed`
    /// (it came back as another zone: cut until `cellward container
    /// reattach`), `attach-failed`.
    Cut(String),
}

impl Exit {
    pub fn text(&self) -> String {
        match self {
            Self::Through(zone) => format!("through {zone}\n"),
            Self::Cut(why) => format!("none {why}\n"),
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        let (word, rest) = text.trim().split_once(' ')?;
        match word {
            "through" if valid_network(rest) => Some(Self::Through(rest.to_owned())),
            "none"
                if !rest.is_empty()
                    && rest.bytes().all(|b| b.is_ascii_lowercase() || b == b'-') =>
            {
                Some(Self::Cut(rest.to_owned()))
            }
            _ => None,
        }
    }
}

/// An instance's way out as its keeper last noted it; `None` when there is
/// no note that reads as one.
pub fn exit_of(dir: &Path) -> Option<Exit> {
    Exit::parse(&fs::read_to_string(dir.join(EXIT)).ok()?)
}

/// A running instance, as its directory says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Running {
    pub id: String,
    pub dir: PathBuf,
    /// Its space's host pid ([`up`]).
    pub pid: i32,
    /// The network it runs in ([`NETWORK`]).
    pub network: String,
}

/// Every instance that is up ([`up`]), by id. A directory whose name is
/// not its id's [`key`] is nobody's.
pub fn running(state: &Path) -> Vec<Running> {
    let Ok(entries) = std::fs::read_dir(state.join(INSTANCES_DIR)) else {
        return Vec::new();
    };
    let mut out: Vec<Running> = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        let Some(id) = read_word(&dir.join(ID)) else {
            continue;
        };
        if !valid_id(&id) || entry.file_name().to_str() != Some(key(&id).as_str()) {
            continue;
        }
        if !dir.join(READY).is_file() {
            continue;
        }
        let Some(pid) = space_pid(&dir) else {
            continue;
        };
        let network = read_word(&dir.join(NETWORK))
            .filter(|n| valid_network(n))
            .unwrap_or_else(|| crate::launch::OFFLINE.to_owned());
        out.push(Running {
            id,
            dir,
            pid,
            network,
        });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

/// Whether the process `pid` — an instance's (`Running::pid`) — has a pid
/// namespace other than this process's: its own (stage 3, `crate::init`).
/// An instance started by an earlier build has none — its programs see
/// every process of the host until it is restarted. False when either
/// cannot be read.
pub fn own_pid_namespace(pid: i32) -> bool {
    let theirs = fs::read_link(format!("/proc/{pid}/ns/pid")).ok();
    let ours = fs::read_link("/proc/self/ns/pid").ok();
    matches!((theirs, ours), (Some(theirs), Some(ours)) if theirs != ours)
}

/// The container an instance is of: its name — `None` for the built-in
/// main and for a throwaway.
pub fn container_of(id: &str) -> Option<&str> {
    if id.starts_with(TMP_PREFIX) || id.starts_with(FS_PREFIX) {
        return None;
    }
    let name = id.split_once(':').map_or(id, |(name, _)| name);
    (name != MAIN).then_some(name)
}

/// Whose programs an instance's are (`crate::origin::Who`): the container's
/// its id names, the main home's for `main:<network>`, not known for a
/// throwaway — as a launch of one is not (`crate::origin`).
pub fn who_of(id: &str) -> Who {
    if id.starts_with(TMP_PREFIX) || id.starts_with(FS_PREFIX) {
        return Who::Unknown;
    }
    match container_of(id) {
        Some(name) => Who::Container(name.to_owned()),
        None => Who::Main,
    }
}

/// `vpn-zone-core container-holder [--inner] [tool flags] <id>`: the keeper
/// of instance `<id>` (`crate::zone::run_instance`), the `ExecStart` of
/// `vpn-zone-container@<id>.service`, with the tool flags of `zone-holder`;
/// `--inner`, its own re-exec inside the instance's user namespace
/// (`crate::zone::run_instance_inner`).
pub fn holder_main(args: &[std::ffi::OsString]) -> u8 {
    let (inner, rest) = match args.first() {
        Some(first) if first == "--inner" => (true, &args[1..]),
        _ => (false, args),
    };
    let parsed = match crate::zone::Args::parse(rest) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("vpn-zone-core container-holder: {e}");
            return 2;
        }
    };
    let Some(id) = parsed
        .name
        .to_str()
        .filter(|id| valid_id(id))
        .map(str::to_owned)
    else {
        eprintln!(
            "vpn-zone-core container-holder: «{}» is no instance's id",
            parsed.name.to_string_lossy()
        );
        return 2;
    };
    let Some(home) = crate::profile::home_dir() else {
        eprintln!("instance {id}: no $HOME and no passwd entry — cannot find its directory");
        return 1;
    };
    let state = home.join(crate::zone::STATE_SUBDIR);
    let plan = match Plan::of(&home, &state, &id) {
        Ok(plan) => plan,
        Err(e) => {
            eprintln!("instance {id}: {e}");
            return 1;
        }
    };
    if inner {
        crate::zone::run_instance_inner(parsed.tools, home, plan)
    } else {
        crate::zone::run_instance(parsed.tools, home, plan)
    }
}

/// What an instance is to be, from its id alone: what its keeper sets it up
/// by, and what it erases when it ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub id: String,
    /// The network it runs in: `offline`, or a zone (stage 2) — fixed for
    /// the instance's life.
    pub network: String,
    /// Whose programs its are ([`who_of`]).
    pub who: Who,
    /// Its container's storage, the one of all containers' kept in its
    /// space (`zone::hide_container_storage`): a data container's
    /// directory, a throwaway's layer. `None`: nothing of the kind.
    pub storage: Option<PathBuf>,
    /// What goes when the instance ends: a throwaway's layer and its
    /// launches' records.
    pub erase: Vec<PathBuf>,
}

impl Plan {
    /// The plan of instance `id`, below `home` and its state directory
    /// `state`. Its network: the id's own for `<c>:<network>` and
    /// `main:<network>`; for the others what the launch asked
    /// ([`ask_network`]), `offline` when nothing was. A network that is no
    /// zone's is refused.
    pub fn of(home: &Path, state: &Path, id: &str) -> Result<Self, String> {
        if !valid_id(id) {
            return Err(format!("«{id}» is no instance's id"));
        }
        let network = match id.split_once(':') {
            Some((_, network)) if !id.starts_with(':') => network.to_owned(),
            _ => wanted_network(state, id).unwrap_or_else(|| crate::launch::OFFLINE.to_owned()),
        };
        if network != crate::launch::OFFLINE && !state.join(&network).join("config.conf").is_file()
        {
            return Err(format!("there is no zone {network} to run in"));
        }
        let who = who_of(id);
        let (storage, erase) = if let Some(layer) = id.strip_prefix(TMP_PREFIX) {
            let layer_dir = state.join(crate::launch::THROWAWAY_DIR).join(layer);
            if !layer_dir.is_dir() {
                return Err(format!(
                    "no throwaway container {} to run",
                    layer_dir.display()
                ));
            }
            let records = state.join(".running").join(layer);
            (Some(layer_dir.clone()), vec![layer_dir, records])
        } else {
            let storage = container_of(id)
                .map(|name| home.join(crate::container::PROFILES_SUBDIR).join(name))
                .filter(|dir| dir.is_dir());
            (storage, Vec::new())
        };
        Ok(Self {
            id: id.to_owned(),
            network,
            who,
            storage,
            erase,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::Home;

    fn named(name: &str, home: Home, asks: bool) -> Of<'_> {
        Of::Container { name, home, asks }
    }

    #[test]
    fn a_named_container_is_one_instance_whatever_its_network() {
        for home in [Home::Private, Home::Layer] {
            for asks in [false, true] {
                assert_eq!(
                    id_of(named("work", home, asks), "nl").as_deref(),
                    Some("work")
                );
                assert_eq!(
                    id_of(named("work", home, asks), "offline").as_deref(),
                    Some("work")
                );
            }
        }
        // Bound to one network, the main home is one instance as well.
        assert_eq!(
            id_of(named("docs", Home::Main, false), "nl").as_deref(),
            Some("docs")
        );
    }

    #[test]
    fn the_main_home_that_asks_is_one_instance_per_network() {
        assert_eq!(
            id_of(named("docs", Home::Main, true), "nl").as_deref(),
            Some("docs:nl")
        );
        assert_eq!(
            id_of(named("docs", Home::Main, true), "de-2").as_deref(),
            Some("docs:de-2")
        );
        assert_eq!(id_of(Of::Main, "nl").as_deref(), Some("main:nl"));
        assert_eq!(id_of(Of::Main, "offline").as_deref(), Some("main:offline"));
    }

    #[test]
    fn throwaways_are_told_apart_from_every_container() {
        assert_eq!(
            id_of(Of::Throwaway("vpn-profile-a1B2c3"), "nl").as_deref(),
            Some(":tmp:vpn-profile-a1B2c3")
        );
        assert_eq!(
            id_of(Of::ThrowawaySandbox("firefox.tmp"), "nl").as_deref(),
            Some(":fs:firefox.tmp")
        );
        for bad in ["", ".", "..", ".hidden", "-opt", "a/b", "a b", "a:b"] {
            assert_eq!(id_of(Of::Throwaway(bad), "nl"), None, "{bad:?}");
            assert_eq!(id_of(Of::ThrowawaySandbox(bad), "nl"), None, "{bad:?}");
        }
    }

    #[test]
    fn unconfined_and_bad_names_have_no_instance() {
        for network in ["unconfined", "direct", "", "-x", "a/b", "a:b", "a b"] {
            assert_eq!(id_of(Of::Main, network), None, "{network:?}");
            assert_eq!(id_of(named("work", Home::Private, false), network), None);
        }
        // Not a container's name: reserved words, a colon, a slash.
        for name in ["main", "ask", "__x", "a:b", "a/b", ".x", "-x", ""] {
            assert_eq!(
                id_of(named(name, Home::Private, false), "nl"),
                None,
                "{name:?}"
            );
        }
    }

    #[test]
    fn every_id_given_is_read_back_and_nothing_else() {
        for id in [
            "work",
            "Работа",
            "docs:nl",
            "main:offline",
            ":tmp:vpn-profile-x",
            ":fs:sb",
        ] {
            assert!(valid_id(id), "{id:?}");
        }
        for id in [
            "",
            ":tmp:",
            ":fs:",
            ":tmp:../x",
            ":x:y",
            "main",
            "docs:",
            "docs:unconfined",
            "docs:nl:x",
            ":nl",
            "a/b",
            ".hidden",
        ] {
            assert!(!valid_id(id), "{id:?}");
        }
    }

    #[test]
    fn a_unit_name_is_systemd_escaped() {
        assert_eq!(
            unit_name("main:nl").as_deref(),
            Some("vpn-zone-container@main:nl.service")
        );
        assert_eq!(
            unit_name("work-2.x").as_deref(),
            Some("vpn-zone-container@work\\x2d2.x.service")
        );
        assert_eq!(
            unit_name(":tmp:vpn-profile-a1").as_deref(),
            Some("vpn-zone-container@:tmp:vpn\\x2dprofile\\x2da1.service")
        );
        assert_eq!(
            unit_name("Раб").as_deref(),
            Some("vpn-zone-container@\\xd0\\xa0\\xd0\\xb0\\xd0\\xb1.service")
        );
        assert_eq!(
            unit_name("a\"b\\c").as_deref(),
            Some("vpn-zone-container@a\\x22b\\x5cc.service")
        );
        assert_eq!(
            unit_name("docs:de_1").as_deref(),
            Some("vpn-zone-container@docs:de_1.service")
        );
        // A name longer than a unit may be, and one that is no id.
        assert_eq!(unit_name(&"Ж".repeat(40)), None);
        assert!(unit_name(&"w".repeat(128)).is_some());
        assert_eq!(unit_name("a/b"), None);
    }

    #[test]
    fn a_leading_dot_is_escaped_as_systemd_does() {
        // No id starts with one, but the escaping is systemd's all the same.
        assert_eq!(escape(".x.y"), "\\x2ex.y");
    }

    #[test]
    fn the_state_lies_in_a_dot_directory() {
        // By the id's key, not the id (stage 1, 2026-09-27): the sockets in
        // the directory must fit in a socket's 108 bytes whatever the id.
        assert_eq!(
            dir(Path::new("/s"), "docs:nl"),
            PathBuf::from("/s/.instances/i-307a07e22d5db1aa")
        );
        assert_eq!(
            dir(Path::new("/s"), "w").join(PID),
            PathBuf::from("/s/.instances/i-af63ea4c86020456/instance.pid")
        );
    }

    #[test]
    fn a_key_is_short_whatever_the_id() {
        // FNV-1a, 64 bits: the empty id is the offset basis itself.
        assert_eq!(key(""), "i-cbf29ce484222325");
        assert_eq!(key("main:offline"), "i-242da5417b1a1e19");
        assert_eq!(key("Работа"), "i-4e6851489e20ed0b");
        assert_eq!(key(":tmp:vpn-profile-x"), "i-03d025104a3cfa69");
        let long = "Ж".repeat(64);
        assert!(valid_id(&long));
        assert_eq!(key(&long).len(), 18);
        assert_ne!(key("a"), key("b"));
    }

    #[test]
    fn whose_an_instance_is_comes_from_its_id() {
        assert_eq!(who_of("work"), Who::Container("work".into()));
        assert_eq!(who_of("docs:offline"), Who::Container("docs".into()));
        assert_eq!(who_of("main:offline"), Who::Main);
        assert_eq!(who_of(":tmp:vpn-profile-x"), Who::Unknown);
        assert_eq!(who_of(":fs:1-2"), Who::Unknown);
        assert_eq!(container_of("work"), Some("work"));
        assert_eq!(container_of("docs:offline"), Some("docs"));
        assert_eq!(container_of("main:offline"), None);
        assert_eq!(container_of(":tmp:x"), None);
    }

    /// A home and its state directory, removed on drop.
    struct Dirs(PathBuf);

    impl Dirs {
        fn new(tag: &str) -> Self {
            let base =
                std::env::temp_dir().join(format!("vz-instance-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(base.join(".local/state/vpn-zones")).unwrap();
            Self(base)
        }
        fn state(&self) -> PathBuf {
            self.0.join(".local/state/vpn-zones")
        }
    }

    impl Drop for Dirs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_plan_keeps_its_own_storage_and_erases_a_throwaways() {
        let h = Dirs::new("plan");
        let state = h.state();
        // A named container: its data directory, where there is one.
        let plan = Plan::of(&h.0, &state, "work").unwrap();
        assert_eq!(plan.network, "offline");
        assert_eq!(plan.who, Who::Container("work".into()));
        assert_eq!(plan.storage, None);
        assert!(plan.erase.is_empty());
        let data = h.0.join(".local/state/vpn-profiles/work");
        std::fs::create_dir_all(&data).unwrap();
        assert_eq!(Plan::of(&h.0, &state, "work").unwrap().storage, Some(data));
        // The main home: nothing of its own to keep.
        let main = Plan::of(&h.0, &state, "main:offline").unwrap();
        assert_eq!((main.who, main.storage), (Who::Main, None));
        // A throwaway: its layer kept, and it and its records erased at the
        // end; one whose layer is gone is not run.
        assert!(Plan::of(&h.0, &state, ":tmp:vpn-profile-x").is_err());
        let layer = state.join(".throwaway/vpn-profile-x");
        std::fs::create_dir_all(&layer).unwrap();
        let tmp = Plan::of(&h.0, &state, ":tmp:vpn-profile-x").unwrap();
        assert_eq!(tmp.who, Who::Unknown);
        assert_eq!(tmp.storage, Some(layer.clone()));
        assert_eq!(tmp.erase, vec![layer, state.join(".running/vpn-profile-x")]);
        // A network that is no zone's is refused (stage 2: a zone's is
        // taken — below), and an id that is none.
        assert!(Plan::of(&h.0, &state, "docs:nl").is_err());
        assert!(Plan::of(&h.0, &state, "docs:offline").is_ok());
        assert!(Plan::of(&h.0, &state, "a/b").is_err());
    }

    /// Stage 2 (2026-09-27): an instance's network is its id's own, or what
    /// the launch asked; a zone's when there is such a zone.
    #[test]
    fn a_plans_network_is_the_ids_or_the_one_asked() {
        let h = Dirs::new("network");
        let state = h.state();
        std::fs::create_dir_all(state.join("nl")).unwrap();
        std::fs::write(state.join("nl/config.conf"), "[Interface]\n").unwrap();
        assert_eq!(Plan::of(&h.0, &state, "docs:nl").unwrap().network, "nl");
        assert_eq!(Plan::of(&h.0, &state, "main:nl").unwrap().network, "nl");
        // Nothing asked: offline.
        assert_eq!(Plan::of(&h.0, &state, "work").unwrap().network, "offline");
        ask_network(&state, "work", "nl").unwrap();
        assert_eq!(Plan::of(&h.0, &state, "work").unwrap().network, "nl");
        assert!(want_path(&state, "work").starts_with(state.join(INSTANCES_DIR)));
        // Asked again, the last word counts; a zone that is gone is refused.
        ask_network(&state, "work", "offline").unwrap();
        assert_eq!(Plan::of(&h.0, &state, "work").unwrap().network, "offline");
        ask_network(&state, "work", "de").unwrap();
        assert!(Plan::of(&h.0, &state, "work").is_err());
        // What is no network is not taken for one.
        ask_network(&state, "work", "unconfined").unwrap();
        assert_eq!(Plan::of(&h.0, &state, "work").unwrap().network, "offline");
        // A throwaway's is asked the same way.
        std::fs::create_dir_all(state.join(".throwaway/vpn-profile-y")).unwrap();
        ask_network(&state, ":tmp:vpn-profile-y", "nl").unwrap();
        assert_eq!(
            Plan::of(&h.0, &state, ":tmp:vpn-profile-y")
                .unwrap()
                .network,
            "nl"
        );
        // The id's own network is not overridden by what was asked.
        ask_network(&state, "docs:nl", "offline").unwrap();
        assert_eq!(Plan::of(&h.0, &state, "docs:nl").unwrap().network, "nl");
    }

    #[test]
    fn an_exit_is_written_and_read_back() {
        for exit in [
            Exit::Through("nl".to_owned()),
            Exit::Cut("offline".to_owned()),
            Exit::Cut("zone-changed".to_owned()),
        ] {
            assert_eq!(Exit::parse(&exit.text()), Some(exit));
        }
        for bad in [
            "",
            "through",
            "through a/b",
            "none",
            "none Why",
            "gone nl",
            "through unconfined",
        ] {
            assert_eq!(Exit::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn an_instance_is_up_only_as_its_directory_and_its_process_say() {
        let h = Dirs::new("up");
        let state = h.state();
        assert_eq!(up(&state, "work"), None);
        assert!(running(&state).is_empty());
        let d = dir(&state, "work");
        std::fs::create_dir_all(&d).unwrap();
        let me = std::process::id() as i32;
        std::fs::write(d.join(PID), format!("{me}\n")).unwrap();
        std::fs::write(
            d.join(START),
            format!("{}\n", crate::sys::process_stamp(me).unwrap()),
        )
        .unwrap();
        std::fs::write(d.join(ID), "work\n").unwrap();
        // Not ready yet — its keeper finds its space all the same.
        assert_eq!(up(&state, "work"), None);
        assert_eq!(space(&state, "work"), Some(me));
        std::fs::write(d.join(READY), "").unwrap();
        assert_eq!(up(&state, "work"), Some(me));
        let found = running(&state);
        assert_eq!(found.len(), 1);
        assert_eq!(
            (
                found[0].id.as_str(),
                found[0].pid,
                found[0].network.as_str()
            ),
            ("work", me, "offline")
        );
        // A directory that holds another id is not this one's.
        std::fs::write(d.join(ID), "other\n").unwrap();
        assert_eq!(up(&state, "work"), None);
        assert!(running(&state).is_empty());
        std::fs::write(d.join(ID), "work\n").unwrap();
        // A number whose process started otherwise is somebody else's.
        std::fs::write(d.join(START), "1 not-this-boot\n").unwrap();
        assert_eq!(up(&state, "work"), None);
    }
}
