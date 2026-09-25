//! The screen cast by permission (owner, 2026-09-25; LEAK-MODEL §21,
//! `docs/PERMISSIONS.md` §3д): a zone's programs cast the screen through the
//! portal only as the zone's switch says — `yes`, `no`, or `ask`, the
//! default.
//!
//! * `ask`: the portal's own dialog every time, and the choice is never
//!   remembered: `SelectSources` goes on without `persist_mode` and
//!   `restore_token` (`dbus_wire::sanitized_screencast_sources`) — what every
//!   zone had before the switch.
//! * `no`: every call of `org.freedesktop.portal.ScreenCast` is refused by the
//!   bus filter with the portal's own `NotAllowed` and a text that says why;
//!   the person reads it in `cellward journal`.
//! * `yes`: a choice may be remembered — `persist_mode` and `restore_token`
//!   pass, and with a token the portal starts the next cast WITHOUT its
//!   dialog. Only on a connection the portal knows as the zone (LEAK-MODEL
//!   §23, `bus_filter::register`), and only while the portal that took the id
//!   is the one called: anywhere else `yes` is `ask`, so that a choice is
//!   never kept for the nameless host application every zone shares.
//!
//! **Where it is decided**: in a hermetic zone's session bus filter, for
//! every call, so a change applies at once, to programs already running too.
//! That filter lives in the zone's mount namespace, where the project's state
//! is covered a moment after it starts (`zone::hide_project_state`): it holds
//! descriptors of the zone's directory, the config directory and the state
//! directory (for the journal) from before that ([`Policy::hold`]), and reads
//! through them. One that could not be held is a file that cannot be read:
//! `no`.
//!
//! **Where the setting lives**, as the microphone's (`crate::microphone`):
//! the zone's marker `screencast` in its state directory, hidden from zones
//! (LEAK-MODEL §17), and `declared/screencast` below `~/.config/vpn-zones`
//! (Nix, `programs.cellward.screencast`; read-only in zones). Nix over the
//! marker over `ask`; a value that is none of the three, or a file that is
//! there and cannot be read, is `no`.
//!
//! **What the switch does not reach**: a zone that is not hermetic talks to
//! the portal directly, past any filter; and a file sandbox's own filter does
//! not see the zone's state — in a sandbox `yes` is `ask`, and `no` holds
//! where the zone's filter is behind the sandbox's, in a hermetic zone.

use std::os::fd::IntoRawFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::container::Source;
pub use crate::microphone::Setting;

/// The zone's marker, in its state directory: `yes`, `no` or `ask`.
pub const MARKER: &str = "screencast";
/// The values Nix declared, below `declared/`: `<zone> <value>` per line.
pub const DECLARED: &str = "screencast";
/// The portal's interface the switch is about.
pub const INTERFACE: &str = "org.freedesktop.portal.ScreenCast";
/// At most one journal line per this long: a program that asks in a loop
/// must not wash the journal's history out. stderr gets every one.
const QUIET: Duration = Duration::from_secs(10);

/// The zone's setting and where it comes from.
pub fn setting(zone_dir: &Path, config: &Path, zone: &str) -> (Setting, Source) {
    crate::microphone::zone_switch(Some(zone_dir), config, zone, MARKER, DECLARED)
}

/// What a refused call is told, and the journal says: why.
pub fn refusal(zone: &str, source: Source) -> String {
    match source {
        Source::Nix => format!("трансляция экрана выключена для зоны «{zone}» (задано в Nix)"),
        _ => format!("трансляция экрана выключена для зоны «{zone}»"),
    }
}

/// The switch of one zone as its bus filter reads it.
#[derive(Debug)]
pub struct Policy {
    zone: String,
    /// The zone's directory, the config directory and the state directory,
    /// each as `/proc/self/fd/N` of a descriptor held from the start; `None`
    /// for one that could not be opened.
    zone_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    journal: Option<PathBuf>,
    /// The last journal line.
    last_told: Mutex<Option<Instant>>,
}

impl Policy {
    /// Hold the zone's directories now, before the zone covers them. The
    /// descriptors stay open for the life of the process: the filter is not
    /// dumpable, so nobody else in the zone reaches them through `/proc`.
    pub fn hold(zone: &str, zone_dir: &Path, config: &Path) -> Self {
        let held = |dir: &Path| match crate::sys::open_dir(dir) {
            Ok(fd) => Some(PathBuf::from(format!("/proc/self/fd/{}", fd.into_raw_fd()))),
            Err(e) => {
                eprintln!(
                    "bus-filter: zone {zone}: cannot open {} ({e}) — read as a file that \
                     cannot be read: the screen cast is refused unless Nix says otherwise",
                    dir.display()
                );
                None
            }
        };
        Self {
            zone: zone.to_owned(),
            zone_dir: held(zone_dir),
            config: held(config),
            journal: zone_dir
                .parent()
                .and_then(|state| crate::sys::open_dir(state).ok())
                .map(|fd| PathBuf::from(format!("/proc/self/fd/{}", fd.into_raw_fd()))),
            last_told: Mutex::new(None),
        }
    }

    pub fn zone(&self) -> &str {
        &self.zone
    }

    /// The switch now, and where it comes from.
    pub fn setting(&self) -> (Setting, Source) {
        let Some(config) = &self.config else {
            // Nix may have said "no" there.
            return (Setting::No, Source::Nix);
        };
        crate::microphone::zone_switch(
            self.zone_dir.as_deref(),
            config,
            &self.zone,
            MARKER,
            DECLARED,
        )
    }

    /// A call refused by `no`: said on stderr (the zone's unit journal) and
    /// in `cellward journal`, there at most one line per [`QUIET`]. The text
    /// for the program.
    pub fn refused(&self, source: Source) -> String {
        let why = refusal(&self.zone, source);
        eprintln!("bus-filter: zone {}: screen cast refused: {why}", self.zone);
        let Some(state) = &self.journal else {
            return why;
        };
        {
            let mut last = self.last_told.lock().unwrap_or_else(|e| e.into_inner());
            if last.is_some_and(|t| t.elapsed() < QUIET) {
                return why;
            }
            *last = Some(Instant::now());
        }
        let short = match source {
            Source::Nix => "выключена в Nix",
            _ => "выключена настройкой зоны",
        };
        if let Err(e) = crate::journal::append(
            state,
            "screencast",
            &[
                ("zone", self.zone.as_str()),
                ("decision", "refused"),
                ("why", short),
            ],
        ) {
            eprintln!("bus-filter: journal: {e}");
        }
        why
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dirs {
        base: PathBuf,
    }

    impl Dirs {
        fn new(tag: &str) -> Self {
            let base = std::env::temp_dir()
                .join(format!("vpn-zone-screencast-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(base.join("state/nl")).unwrap();
            std::fs::create_dir_all(base.join("config/declared")).unwrap();
            Self { base }
        }
        fn write(&self, path: &str, text: &str) {
            std::fs::write(self.base.join(path), text).unwrap();
        }
        fn policy(&self) -> Policy {
            Policy::hold("nl", &self.base.join("state/nl"), &self.base.join("config"))
        }
    }

    impl Drop for Dirs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    /// The microphone's rules under the screen cast's names: ask by default,
    /// the zone's marker over it, Nix over both, anything else is no — and
    /// the one does not read the other's files.
    #[test]
    fn nix_wins_over_the_marker_and_the_marker_over_ask() {
        let d = Dirs::new("precedence");
        let read = || setting(&d.base.join("state/nl"), &d.base.join("config"), "nl");
        assert_eq!(read(), (Setting::Ask, Source::Default));
        d.write("state/nl/microphone", "yes");
        d.write("config/declared/microphone", "nl no\n");
        assert_eq!(read(), (Setting::Ask, Source::Default));
        d.write("state/nl/screencast", "yes\n");
        assert_eq!(read(), (Setting::Yes, Source::Local));
        d.write("state/nl/screencast", "sure");
        assert_eq!(read(), (Setting::No, Source::Local));
        d.write("state/nl/screencast", "yes");
        d.write("config/declared/screencast", "de no\nnl ask\n");
        assert_eq!(read(), (Setting::Ask, Source::Nix));
        d.write("config/declared/screencast", "nl maybe\n");
        assert_eq!(read(), (Setting::No, Source::Nix));
    }

    /// The filter reads through what it held at its start: the paths may be
    /// covered afterwards (here: the directory moved away and another put in
    /// its place), and the switch is still the zone's own, read afresh.
    #[test]
    fn the_filter_reads_through_what_it_held() {
        let d = Dirs::new("held");
        let p = d.policy();
        assert_eq!(p.setting(), (Setting::Ask, Source::Default));
        std::fs::rename(d.base.join("state/nl"), d.base.join("state/moved")).unwrap();
        std::fs::create_dir_all(d.base.join("state/nl")).unwrap();
        d.write("state/nl/screencast", "yes");
        d.write("state/moved/screencast", "no");
        assert_eq!(p.setting(), (Setting::No, Source::Local));
        d.write("state/moved/screencast", "yes");
        assert_eq!(p.setting(), (Setting::Yes, Source::Local));
        // What it could not hold is a file that cannot be read: no.
        let lost = Policy::hold("nl", &d.base.join("state/none"), &d.base.join("config"));
        assert_eq!(lost.setting(), (Setting::No, Source::Local));
        d.write("config/declared/screencast", "nl yes\n");
        assert_eq!(lost.setting(), (Setting::Yes, Source::Nix));
        let blind = Policy::hold("nl", &d.base.join("state/moved"), &d.base.join("nowhere"));
        assert_eq!(blind.setting(), (Setting::No, Source::Nix));
    }

    /// A refusal is said in the journal — at most one line per ten seconds.
    #[test]
    fn a_refusal_is_in_the_journal_once_in_a_while() {
        let d = Dirs::new("journal");
        let p = d.policy();
        let why = p.refused(Source::Local);
        assert_eq!(why, "трансляция экрана выключена для зоны «nl»");
        assert!(p.refused(Source::Nix).ends_with("(задано в Nix)"));
        let journal =
            std::fs::read_to_string(d.base.join("state").join(crate::journal::FILE)).unwrap();
        assert_eq!(journal.matches("\"event\":\"screencast\"").count(), 1);
        assert!(
            journal.contains(
                "\"zone\":\"nl\",\"decision\":\"refused\",\"why\":\"выключена настройкой зоны\""
            ),
            "{journal}"
        );
    }
}
