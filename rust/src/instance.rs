//! Container instances: a running container, with network, mount, IPC and
//! (later) pid namespaces of its own — the unit of isolation of the
//! container design of 2026-09-27, where a zone is only transport.
//!
//! Stage 0 (2026-09-27): the names only. Which instance a launch runs in
//! ([`id_of`]), the unit that holds it ([`unit_name`]) and where its state
//! lies ([`dir`] and the file names below). Nothing starts an instance yet.
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

use std::path::{Path, PathBuf};

/// Below the state directory: one directory per running instance. A dot
/// directory, so that no listing of zones takes it for one.
pub const INSTANCES_DIR: &str = ".instances";
/// The instance's holder writes its pid 1's host pid here…
pub const PID: &str = "instance.pid";
/// …and that process's start (`crate::sys::process_stamp`), which tells it
/// from whoever has the number later.
pub const START: &str = "instance.start";
/// Written once the instance is set up, as a zone's `ready`.
pub const READY: &str = "ready";
/// What the instance's way out is now: `none` or `through <zone> …`.
pub const EXIT: &str = "exit";
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

/// The instance's state directory: `<state>/.instances/<id>`.
pub fn dir(state: &Path, id: &str) -> PathBuf {
    state.join(INSTANCES_DIR).join(id)
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
        assert_eq!(
            dir(Path::new("/s"), "docs:nl"),
            PathBuf::from("/s/.instances/docs:nl")
        );
        assert_eq!(
            dir(Path::new("/s"), "w").join(PID),
            PathBuf::from("/s/.instances/w/instance.pid")
        );
    }
}
