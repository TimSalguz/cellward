//! Whether a zone is hermetic (`docs/HERMETICITY.md` §7 C), and where that
//! comes from.
//!
//! The more specific place wins over the more general one, and Nix over the
//! local one at the same level:
//!
//! 1. the zone is in `hermetic.exceptions` (Nix): the opposite of
//!    `hermetic.default`, which the module only accepts together with it;
//! 2. the zone's own marker (`vpn-zone hermetic <zone> on|off`);
//! 3. `hermetic.default` (Nix);
//! 4. the local default (`vpn-zone hermetic --default on|off`);
//! 5. on — since 2026-09 (off before). A zone in the ordinary mode lets its
//!    programs have the host's session do things for them, `systemd-run
//!    --user` first of all: a process started outside the zone, around its
//!    tunnel. The kernel keeps the zone's own processes in; only hermeticity
//!    keeps them from asking a helper outside (docs/LEAK-MODEL.md §1, §14).
//!
//! Only `off` switches anything off. An empty marker is what the prototype
//! wrote for "on", and a file that says something else, or that is there but
//! cannot be read, is no reason to open a zone.
//!
//! **A container's own** (stage 5 of the container design, 2026-09-28;
//! `docs/PERMISSIONS.md` §11.2): hermeticity, the Nix daemon, the host's
//! files and the audio manager are its container's before they are its
//! network's — `containers.<n>.permissions.*` in Nix, `cellward container
//! set <c> hermetic|nix-daemon|host-files|audio-manager` locally. A
//! container's instance comes up with them ([`start_settings_for`]).
//!
//! **Asked by the container, tolerated by the network** (step 1 of the
//! model the owner took on 2026-09-28, `docs/PERMISSIONS.md` §11.14): three
//! of them are ways around a network, not permissions of a program
//! ([`BYPASS_KEYS`]) — no hermeticity, the Nix daemon, the host's files
//! writable. A container asks for one, its network tolerates it, and only
//! both open it ([`explain`]); a network that does not tolerate one closes
//! it for every container in it, whatever their own word. The old per-zone
//! lists and markers say both at once, for compatibility: that the network
//! tolerates it, and that a container without a word of its own — and the
//! main home — asks for it. `offline` tolerates none; a zone locked by the
//! person, no host session. The audio manager stays the container's, by
//! [`for_container`] as the camera: its container's word, the network's for
//! one without.
//!
//! **Nobody's** (a throwaway container, or a program whose container is not
//! known): the safe values, whatever its network says (review 2026-09-28,
//! [`value_for`]) — a one-off launch is no container anything was given to.

use std::io::ErrorKind;
use std::path::Path;

use crate::cli::{read_setting, DECLARED_DIR};
use crate::container::Source;
use crate::origin::Who;

/// The per-zone marker, in the zone's directory: `on`, `off` or empty (on).
pub const MARKER: &str = "hermetic";
/// The default for zones without a marker, a setting file of the config
/// directory (`on` or `off`), locally or below `declared/`.
pub const DEFAULT_SETTING: &str = "hermetic-default";
/// The zones Nix sets opposite to its default, one name per line, below
/// `declared/`.
pub const DECLARED_EXCEPTIONS: &str = "hermetic-exceptions";

/// A default setting file's text: `None` when it is absent or empty.
fn default_file(text: Option<String>) -> Option<bool> {
    text.filter(|text| !text.trim().is_empty())
        .map(|text| text.trim() != "off")
}

/// The default for zones without a marker: `(on, source)`.
pub fn default_setting(config: &Path) -> (bool, Source) {
    let declared = crate::declared::setting(&config.join(DECLARED_DIR).join(DEFAULT_SETTING));
    if let Some(on) = default_file(declared) {
        return (on, Source::Nix);
    }
    if let Some(on) = default_file(read_setting(&config.join(DEFAULT_SETTING))) {
        return (on, Source::Local);
    }
    (true, Source::Default)
}

/// Whether Nix names this zone an exception.
pub fn declared_exception(config: &Path, zone: &str) -> bool {
    crate::declared::read(&config.join(DECLARED_DIR).join(DECLARED_EXCEPTIONS))
        .is_ok_and(|text| text.lines().map(str::trim).any(|line| line == zone))
}

/// Whether the zone in `zone_dir` is hermetic: `(on, source)`.
pub fn zone_setting(zone_dir: &Path, config: &Path, zone: &str) -> (bool, Source) {
    let default = default_setting(config);
    // An exception is the opposite of a default Nix declared. Without one the
    // file is not the module's, and inverting whatever the default happens to
    // be here could open a zone: it is ignored.
    if default.1 == Source::Nix && declared_exception(config, zone) {
        return (!default.0, Source::Nix);
    }
    match std::fs::read_to_string(zone_dir.join(MARKER)) {
        Ok(text) => (text.trim() != "off", Source::Local),
        Err(e) if e.kind() == ErrorKind::NotFound => default,
        Err(_) => (true, Source::Local),
    }
}

/// Whether a zone's programs reach the host's Nix daemon: a marker in the
/// zone's directory (`on`/`off`, `vpn-zone nix-daemon`), or the zone named in
/// `declared/nix-daemon` (Nix, `programs.cellward.nixDaemon`). Off by default
/// (review 2026-09-25, third round): the daemon builds and fetches in the
/// host's network — a fixed-output derivation fetches any address a program
/// in any zone names, offline included.
pub const NIX_DAEMON: &str = "nix-daemon";

/// Whether a hermetic zone's programs may write what the host runs from the
/// home (autostart, units, launcher entries, shells' and compositors'
/// configs): a marker in the zone's directory (`writable`/`read-only`,
/// `vpn-zone host-files`), or the zone named in `declared/host-files-writable`
/// (Nix, `programs.cellward.hostFilesWritable`). Read-only by default (owner,
/// 2026-09-25).
pub const HOST_FILES: &str = "host-files";
/// The zones Nix lets write the host's files, one name per line.
pub const DECLARED_HOST_FILES_WRITABLE: &str = "host-files-writable";

/// A per-zone switch that is off unless something turns it on: Nix names the
/// zone in `declared/<list>`, or the zone's marker says `on_word`.
fn allowance(
    zone_dir: &Path,
    config: &Path,
    zone: &str,
    list: &str,
    marker: &str,
    on_word: &str,
) -> (bool, Source) {
    let declared = crate::declared::read(&config.join(DECLARED_DIR).join(list))
        .is_ok_and(|text| text.lines().map(str::trim).any(|line| line == zone));
    if declared {
        return (true, Source::Nix);
    }
    match read_setting(&zone_dir.join(marker)) {
        Some(text) if text.trim() == on_word => (true, Source::Local),
        Some(text) if !text.trim().is_empty() => (false, Source::Local),
        _ => (false, Source::Default),
    }
}

/// Whether a zone's programs reach the host's cameras as devices
/// (`/dev/video*`, `/dev/media*`): a marker in the zone's directory
/// (`on`/`off`, `vpn-zone camera`), or the zone named in `declared/camera`
/// (Nix, `programs.cellward.camera`). Off by default (review 2026-09-25):
/// the session's ACL on them is the user's, and a program in a zone is the
/// user — it filmed without a question.
pub const CAMERA: &str = "camera";

/// Whether the zone in `zone_dir` reaches the cameras: `(on, source)`.
pub fn camera(zone_dir: &Path, config: &Path, zone: &str) -> (bool, Source) {
    allowance(zone_dir, config, zone, CAMERA, CAMERA, "on")
}

/// Whether a hermetic zone gets the host's raw `pipewire-0` instead of the
/// restricted one (`crate::pw_context`): a marker in the zone's directory
/// (`on`/`off`, `vpn-zone audio-manager`), or the zone named in
/// `declared/audio-manager` (Nix, `programs.cellward.audioManager`). Off by
/// default (owner, 2026-09-25): the raw socket is every stream and device of
/// the host — for a zone that runs a mixer or a patchbay (pavucontrol,
/// qpwgraph, EasyEffects) and is trusted with the host's sound. An ordinary
/// zone has the raw socket anyway: it has the host's `systemd --user`.
pub const AUDIO_MANAGER: &str = "audio-manager";

/// Whether the zone in `zone_dir` gets the raw PipeWire socket: `(on,
/// source)`.
pub fn audio_manager(zone_dir: &Path, config: &Path, zone: &str) -> (bool, Source) {
    allowance(zone_dir, config, zone, AUDIO_MANAGER, AUDIO_MANAGER, "on")
}

/// Whether the zone in `zone_dir` reaches the Nix daemon: `(on, source)`.
pub fn nix_daemon(zone_dir: &Path, config: &Path, zone: &str) -> (bool, Source) {
    allowance(zone_dir, config, zone, NIX_DAEMON, NIX_DAEMON, "on")
}

/// Whether the zone in `zone_dir` may write the host's files: `(writable,
/// source)`. Only a hermetic zone makes them read-only at all.
pub fn host_files_writable(zone_dir: &Path, config: &Path, zone: &str) -> (bool, Source) {
    allowance(
        zone_dir,
        config,
        zone,
        DECLARED_HOST_FILES_WRITABLE,
        HOST_FILES,
        "writable",
    )
}

/// Below a zone's state directory, and an instance's: the settings it came
/// up with, one `<name>=<true|false>` a line, written by its holder before
/// it is up. They are in force until it comes up again; `status --json`
/// names those that have changed since (`instances[].restart_needed`, and
/// for a network those of the instances running in it:
/// `networks[].restart_needed`, review 2026-09-28).
pub const APPLIED: &str = "zone.settings";

/// The settings a space takes when it comes up that a container may have
/// its own of: by their names in `status --json`, in `container.conf` and in
/// a declared container's file (`<name> = true|false`), each with the value
/// that is safe — what a word that is neither on nor off, or a file that
/// cannot be read, is taken for: never an opening.
pub const CONTAINER_KEYS: [(&str, bool); 4] = [
    ("hermetic", true),
    ("nix_daemon", false),
    ("host_files_writable", false),
    ("audio_manager", false),
];

/// The safe value of the setting `key` ([`CONTAINER_KEYS`]): hermetic on,
/// the others off; a key that is none of them, off.
pub fn safe_value(key: &str) -> bool {
    CONTAINER_KEYS
        .iter()
        .find(|(k, _)| *k == key)
        .is_some_and(|(_, safe)| *safe)
}

/// A container's own word on the setting `key` ([`CONTAINER_KEYS`]), and
/// where it is from: Nix's declaration over its local settings
/// (`container::own_value_in`). `None`: it has none of its own — its
/// network's then.
pub fn container_own(config: &Path, name: &str, key: &str) -> Option<(bool, Source)> {
    let safe = safe_value(key);
    match crate::container::own_value_in(config, name, key) {
        Ok(Some((word, source))) => {
            let on = match word.trim() {
                "true" | "on" | "yes" => true,
                "false" | "off" | "no" => false,
                _ => safe,
            };
            Some((on, source))
        }
        Ok(None) => None,
        Err(source) => Some((safe, source)),
    }
}

/// A setting for a program of a container, from the zone's (`zone`) and the
/// container's own (`own`), whose safe value is `safe` ([`safe_value`]):
/// Nix's word for the container, then Nix's for the zone, then the
/// container's own local word, then the zone's. A local word does not
/// override a declared one to open what it closes — but does to close what
/// it opens: Nix is a frame, and a container that asks for less than its
/// network's declared value is given less (review 2026-09-28; a local
/// `nix-daemon off` was silently ignored while the network was in Nix's
/// `nixDaemon`). Where both say the same, the declared one is named.
pub fn for_container(
    zone: (bool, Source),
    own: Option<(bool, Source)>,
    safe: bool,
) -> (bool, Source) {
    match own {
        Some((on, Source::Nix)) => (on, Source::Nix),
        Some((on, source)) if zone.1 == Source::Nix && on == safe && zone.0 != safe => (on, source),
        _ if zone.1 == Source::Nix => zone,
        Some(own) => own,
        None => zone,
    }
}

/// The zone-level setting `key` ([`CONTAINER_KEYS`]) of the zone in
/// `zone_dir`, by itself.
pub fn zone_value(zone_dir: &Path, config: &Path, zone: &str, key: &str) -> (bool, Source) {
    match key {
        "hermetic" => zone_setting(zone_dir, config, zone),
        "nix_daemon" => nix_daemon(zone_dir, config, zone),
        "host_files_writable" => host_files_writable(zone_dir, config, zone),
        "audio_manager" => audio_manager(zone_dir, config, zone),
        _ => (false, Source::Default),
    }
}

/// The settings of [`CONTAINER_KEYS`] that are ways around a network
/// rather than permissions of a program (review 2026-09-28): not hermetic —
/// the host's `systemd --user` and session start anything outside the zone,
/// around its tunnel; the Nix daemon — it fetches in the host's network
/// whatever a program names; the host's files writable — what is planted
/// there runs on the host later. A network has a say in them ([`tolerance`]).
pub const BYPASS_KEYS: [&str; 3] = ["hermetic", "nix_daemon", "host_files_writable"];

/// Whether the setting `key` is a way around a network ([`BYPASS_KEYS`]).
pub fn is_bypass(key: &str) -> bool {
    BYPASS_KEYS.contains(&key)
}

/// Whether the network whose zone directory is `zone_dir` tolerates the
/// bypass `key` ([`BYPASS_KEYS`]) for its containers, and whence: its own
/// setting ([`zone_value`]) open — the per-zone lists and markers,
/// `programs.cellward.nixDaemon` and the like. `offline` tolerates none,
/// whatever is set for it: a way around no network is a network. A zone
/// the person locked (`cellward lock`) tolerates no host session: the lock
/// is kept by the broker, and a program with the host's `systemd --user`
/// needs no broker. `None`: `key` is no bypass — the network has no say.
pub fn tolerance(zone_dir: &Path, config: &Path, zone: &str, key: &str) -> Option<(bool, Source)> {
    if !is_bypass(key) {
        return None;
    }
    if zone == crate::launch::OFFLINE {
        return Some((false, Source::Default));
    }
    if key == "hermetic" && zone_dir.join(crate::launch::NO_ESCAPE).exists() {
        return Some((false, Source::Local));
    }
    let (on, source) = zone_value(zone_dir, config, zone, key);
    Some((on != safe_value(key), source))
}

/// Whose word a setting asked for is ([`Explained::asked`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asker {
    /// The container's own, from Nix or locally.
    Container,
    /// Its network's list or marker, for a container without a word of its
    /// own and for the main home — step 1's compatibility: what the lists
    /// gave before is still asked for.
    Network,
    /// Nobody's: a throwaway container, or a program whose container is
    /// not known — the safe value.
    Nobody,
}

impl Asker {
    /// Its word in `explain --json`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Container => "container",
            Self::Network => "network",
            Self::Nobody => "nobody",
        }
    }
}

/// How the setting `key` is come to for the programs of someone in a
/// network ([`explain`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Explained {
    pub key: &'static str,
    /// What is asked for, whence, and whose word it is.
    pub asked: (bool, Source, Asker),
    /// What the network tolerates ([`tolerance`]); `None` for a setting
    /// the network has no say in.
    pub tolerated: Option<(bool, Source)>,
    /// What the programs get, and the source of the word that decided it.
    pub value: (bool, Source),
}

/// The name [`CONTAINER_KEYS`] has for `key`, `'static`; `None` for a key
/// that is none of them.
fn known_key(key: &str) -> Option<&'static str> {
    CONTAINER_KEYS.iter().map(|(k, _)| *k).find(|k| *k == key)
}

/// How the setting `key` ([`CONTAINER_KEYS`]) is come to for the programs
/// of `who` in the network whose zone directory is `zone_dir` — what
/// [`value_for`] gives, with the words it is made of.
///
/// - Nobody's (a throwaway container, `:tmp:`, `:fs:`, or a program whose
///   container is not known): the safe value, whatever the network says
///   (review 2026-09-28: a throwaway took the network's, so a one-off
///   launch into a network with the Nix daemon had it too). The
///   microphone's rule for the unknown is the same in spirit: its `yes` is
///   `ask` (`microphone::by_container`).
/// - A way around the network ([`BYPASS_KEYS`]): what is asked for — the
///   container's own word (Nix's over its local one), else its network's,
///   which the main home's always is — and open only where the network
///   tolerates it ([`tolerance`]). A container's own "on" in a network that
///   does not tolerate it is closed (review 2026-09-28: it opened in any
///   network, offline and locked ones too); its own "off" closes whatever
///   the network tolerates.
/// - Else (the audio manager): its container's by [`for_container`], the
///   network's for the main home.
pub fn explain(zone_dir: &Path, config: &Path, zone: &str, who: &Who, key: &str) -> Explained {
    let key = known_key(key).unwrap_or("");
    let safe = safe_value(key);
    let tolerated = tolerance(zone_dir, config, zone, key);
    if *who == Who::Unknown {
        return Explained {
            key,
            asked: (safe, Source::Default, Asker::Nobody),
            tolerated,
            value: (safe, Source::Default),
        };
    }
    let network = zone_value(zone_dir, config, zone, key);
    let own = match who {
        Who::Container(name) => container_own(config, name, key),
        // The main home's own record (§11.15, 2a): its word, as a
        // container's; none — the network's, as before.
        Who::Main => container_own(config, crate::container::MAIN_RECORD, key),
        Who::Unknown => None,
    };
    let asked = match (own, tolerated) {
        (Some((on, source)), Some(_)) => (on, source, Asker::Container),
        (own, None) => {
            let (on, source) = for_container(network, own, safe);
            let whose = if own == Some((on, source)) {
                Asker::Container
            } else {
                Asker::Network
            };
            (on, source, whose)
        }
        (None, Some(_)) => (network.0, network.1, Asker::Network),
    };
    let value = match tolerated {
        Some((false, source)) if asked.0 != safe => (safe, source),
        _ => (asked.0, asked.1),
    };
    Explained {
        key,
        asked,
        tolerated,
        value,
    }
}

/// The setting `key` for the programs of `who` in the network whose zone
/// directory is `zone_dir`, and where the word that decided it is from:
/// [`explain`]'s value.
pub fn value_for(
    zone_dir: &Path,
    config: &Path,
    zone: &str,
    who: &Who,
    key: &str,
) -> (bool, Source) {
    explain(zone_dir, config, zone, who, key).value
}

/// The settings a zone takes when it comes up, by their names in
/// `status --json`.
pub fn start_settings(zone_dir: &Path, config: &Path, zone: &str) -> [(&'static str, bool); 4] {
    start_settings_for(zone_dir, config, zone, &Who::Main)
}

/// The settings a container's instance comes up with for the programs of
/// `who`, in the network whose zone directory is `zone_dir`
/// ([`value_for`]), by their names in `status --json`.
pub fn start_settings_for(
    zone_dir: &Path,
    config: &Path,
    zone: &str,
    who: &Who,
) -> [(&'static str, bool); 4] {
    CONTAINER_KEYS.map(|(key, _)| (key, value_for(zone_dir, config, zone, who, key).0))
}

/// Note what a zone comes up with ([`APPLIED`]), through a temporary.
pub fn note_applied(zone_dir: &Path, settings: &[(&str, bool)]) -> std::io::Result<()> {
    let text: String = settings.iter().map(|(k, v)| format!("{k}={v}\n")).collect();
    let tmp = zone_dir.join(format!("{APPLIED}.new"));
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, zone_dir.join(APPLIED))
}

/// What a note of the settings a space came up with ([`APPLIED`], its
/// text) says of the setting `name`: `None` where it names it not, or in
/// a word that is neither `true` nor `false`.
pub fn applied_in(note: &str, name: &str) -> Option<bool> {
    note.lines()
        .filter_map(|line| line.split_once('='))
        .find(|(key, _)| key.trim() == name)
        .and_then(|(_, value)| match value.trim() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        })
}

/// The settings an instance came up with (`note`, the text of its
/// [`APPLIED`]) that are wider than `target` — what another network would
/// give its container ([`start_settings_for`]): open where the target's is
/// the safe value ([`CONTAINER_KEYS`]). They are frozen for the instance's
/// life (its covers and helpers are made by them once), so a live switch
/// would carry them into a network that gives less (review 2026-09-28,
/// `crate::switch`). One the note does not name, or names in a word that
/// is none, is taken as open: a note that cannot say is no reason to
/// switch.
pub fn wider_than(note: &str, target: &[(&'static str, bool)]) -> Vec<&'static str> {
    target
        .iter()
        .filter(|(name, now)| {
            let safe = safe_value(name);
            *now == safe && applied_in(note, name) != Some(safe)
        })
        .map(|(name, _)| *name)
        .collect()
}

/// Which settings of a running zone's own space differ now from those it
/// came up with, by name. `None`: not known — no note (a zone a build from
/// before it started). A setting the note does not name is not counted.
/// Nothing is launched into that space since stage 5; `status` names the
/// instances' ([`restart_needed_of`]).
pub fn restart_needed(zone_dir: &Path, config: &Path, zone: &str) -> Option<Vec<&'static str>> {
    restart_needed_of(zone_dir, zone_dir, config, zone, &Who::Main)
}

/// [`restart_needed`] of what came up with the note in `applied_dir` by the
/// settings for the programs of `who` in the network whose zone directory
/// is `zone_dir`: a container's instance notes them in its own directory,
/// and they are its container's over its network's ([`start_settings_for`]).
pub fn restart_needed_of(
    applied_dir: &Path,
    zone_dir: &Path,
    config: &Path,
    zone: &str,
    who: &Who,
) -> Option<Vec<&'static str>> {
    let text = std::fs::read_to_string(applied_dir.join(APPLIED)).ok()?;
    let applied = |name: &str| {
        text.lines()
            .filter_map(|line| line.split_once('='))
            .find(|(k, _)| k.trim() == name)
            .map(|(_, v)| v.trim() == "true")
    };
    let mut changed: Vec<&'static str> = start_settings_for(zone_dir, config, zone, who)
        .into_iter()
        .filter(|(name, now)| applied(name).is_some_and(|then| then != *now))
        .map(|(name, _)| name)
        .collect();
    // A note that names the camera is a build's from before the camera was
    // each launch's: that zone neither covers the cameras for all nor
    // shares its /dev — a container's "off" does not hold there until it
    // comes up again.
    if applied("camera").is_some() {
        changed.push("camera");
    }
    Some(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dirs {
        base: std::path::PathBuf,
    }

    impl Dirs {
        fn new(tag: &str) -> Self {
            let base = std::env::temp_dir()
                .join(format!("vpn-zone-hermetic-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(base.join("zone")).unwrap();
            std::fs::create_dir_all(base.join("config/declared")).unwrap();
            Self { base }
        }
        fn zone(&self) -> std::path::PathBuf {
            self.base.join("zone")
        }
        fn config(&self) -> std::path::PathBuf {
            self.base.join("config")
        }
        fn write(&self, path: &str, text: &str) {
            std::fs::write(self.base.join(path), text).unwrap();
        }
        /// What Nix declares, as home-manager puts it there: a link into the
        /// store (`crate::declared`).
        fn declare(&self, name: &str, text: &str) {
            crate::declared::declare(&self.base.join("config/declared").join(name), text);
        }
        fn setting(&self) -> (bool, Source) {
            zone_setting(&self.zone(), &self.config(), "nl")
        }
    }

    impl Drop for Dirs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    /// Off unless Nix names the zone or its marker turns it on; anything else
    /// in the marker keeps it off.
    #[test]
    fn allowances_are_off_unless_given() {
        let d = Dirs::new("allow");
        assert_eq!(
            nix_daemon(&d.zone(), &d.config(), "nl"),
            (false, Source::Default)
        );
        d.write("zone/nix-daemon", "on\n");
        assert_eq!(
            nix_daemon(&d.zone(), &d.config(), "nl"),
            (true, Source::Local)
        );
        d.write("zone/nix-daemon", "yes");
        assert_eq!(
            nix_daemon(&d.zone(), &d.config(), "nl"),
            (false, Source::Local)
        );
        d.declare("nix-daemon", "de\nnl\n");
        assert_eq!(
            nix_daemon(&d.zone(), &d.config(), "nl"),
            (true, Source::Nix)
        );
        assert_eq!(
            host_files_writable(&d.zone(), &d.config(), "nl"),
            (false, Source::Default)
        );
        d.write("zone/host-files", "writable");
        assert_eq!(
            host_files_writable(&d.zone(), &d.config(), "nl"),
            (true, Source::Local)
        );
        d.write("zone/host-files", "read-only");
        assert_eq!(
            host_files_writable(&d.zone(), &d.config(), "nl"),
            (false, Source::Local)
        );
        // The raw PipeWire socket: never by accident.
        assert_eq!(
            audio_manager(&d.zone(), &d.config(), "nl"),
            (false, Source::Default)
        );
        d.write("zone/audio-manager", "yes");
        assert_eq!(
            audio_manager(&d.zone(), &d.config(), "nl"),
            (false, Source::Local)
        );
        d.write("zone/audio-manager", "on");
        assert_eq!(
            audio_manager(&d.zone(), &d.config(), "nl"),
            (true, Source::Local)
        );
        d.write("zone/audio-manager", "off");
        d.declare("audio-manager", "nl\n");
        assert_eq!(
            audio_manager(&d.zone(), &d.config(), "nl"),
            (true, Source::Nix)
        );
    }

    #[test]
    fn nothing_set_is_on_by_default() {
        let d = Dirs::new("none");
        assert_eq!(d.setting(), (true, Source::Default));
        d.write("config/hermetic-default", "");
        assert_eq!(d.setting(), (true, Source::Default));
        // The way back is explicit.
        d.write("config/hermetic-default", "off");
        assert_eq!(d.setting(), (false, Source::Local));
    }

    #[test]
    fn the_marker_of_the_prototype_still_means_on() {
        let d = Dirs::new("marker");
        d.write("zone/hermetic", "");
        assert_eq!(d.setting(), (true, Source::Local));
        d.write("zone/hermetic", "off\n");
        assert_eq!(d.setting(), (false, Source::Local));
        d.write("zone/hermetic", "whatever");
        assert_eq!(d.setting(), (true, Source::Local));
    }

    #[test]
    fn a_default_applies_to_zones_without_a_marker() {
        let d = Dirs::new("default");
        d.write("config/hermetic-default", "on");
        assert_eq!(d.setting(), (true, Source::Local));
        d.declare("hermetic-default", "off");
        assert_eq!(d.setting(), (false, Source::Nix));
        // The zone's own marker is more specific than either default.
        d.write("zone/hermetic", "on");
        assert_eq!(d.setting(), (true, Source::Local));
    }

    #[test]
    fn a_declared_exception_inverts_the_declared_default_over_the_marker() {
        let d = Dirs::new("exception");
        d.declare("hermetic-exceptions", "de\nnl\n");
        d.write("zone/hermetic", "on");
        // No declared default: the exception means nothing.
        assert_eq!(d.setting(), (true, Source::Local));
        d.declare("hermetic-default", "on");
        assert_eq!(d.setting(), (false, Source::Nix));
        d.declare("hermetic-default", "off");
        assert_eq!(d.setting(), (true, Source::Nix));
        assert_eq!(
            zone_setting(&d.zone(), &d.config(), "fr"),
            (true, Source::Local)
        );
    }

    /// What a running zone came up with, against what is set now: a changed
    /// start-time setting is named, an unchanged one is not; no note, not
    /// known.
    #[test]
    fn a_setting_changed_since_the_zone_came_up_is_named() {
        let base = std::env::temp_dir().join(format!("vz-applied-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let zone = base.join("state/nl");
        let config = base.join("config");
        std::fs::create_dir_all(&zone).unwrap();
        std::fs::create_dir_all(&config).unwrap();
        assert_eq!(restart_needed(&zone, &config, "nl"), None);
        let now = start_settings(&zone, &config, "nl");
        note_applied(&zone, &now).unwrap();
        assert_eq!(restart_needed(&zone, &config, "nl"), Some(vec![]));
        std::fs::write(zone.join(NIX_DAEMON), "on").unwrap();
        assert_eq!(
            restart_needed(&zone, &config, "nl"),
            Some(vec!["nix_daemon"])
        );
        // The camera is taken by each launch: no restart for it.
        std::fs::write(zone.join(CAMERA), "on").unwrap();
        assert_eq!(
            restart_needed(&zone, &config, "nl"),
            Some(vec!["nix_daemon"])
        );
        // A note of a build from before, which named the camera: restart.
        let text = std::fs::read_to_string(zone.join(APPLIED)).unwrap();
        std::fs::write(zone.join(APPLIED), format!("{text}camera=false\n")).unwrap();
        assert_eq!(
            restart_needed(&zone, &config, "nl"),
            Some(vec!["nix_daemon", "camera"])
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Stage 5 (2026-09-28): the order a container's own setting is taken
    /// in — Nix's word for the container, then Nix's for the zone, then the
    /// container's local word, then the zone's; and (review 2026-09-28) a
    /// local word that closes what the zone's declared one opens wins.
    /// `true` safe is hermeticity's, `false` safe the others'.
    #[test]
    fn a_containers_own_setting_is_taken_in_the_cameras_order() {
        // Nothing of its own: the zone's, whatever its source.
        assert_eq!(
            for_container((true, Source::Default), None, true),
            (true, Source::Default)
        );
        assert_eq!(
            for_container((false, Source::Nix), None, false),
            (false, Source::Nix)
        );
        // Its own local word over the zone's local or default one…
        assert_eq!(
            for_container((true, Source::Local), Some((false, Source::Local)), true),
            (false, Source::Local)
        );
        assert_eq!(
            for_container((false, Source::Default), Some((true, Source::Local)), false),
            (true, Source::Local)
        );
        // …but not over the zone's declared one to open: not hermetic under
        // a declared "hermetic", the Nix daemon under a declared "none"…
        assert_eq!(
            for_container((true, Source::Nix), Some((false, Source::Local)), true),
            (true, Source::Nix)
        );
        assert_eq!(
            for_container((false, Source::Nix), Some((true, Source::Local)), false),
            (false, Source::Nix)
        );
        // …while to close, it does (changed on purpose, review 2026-09-28:
        // this was the zone's declared "on"): hermetic under a declared
        // "off", no Nix daemon under the network's `nixDaemon` list.
        assert_eq!(
            for_container((false, Source::Nix), Some((true, Source::Local)), true),
            (true, Source::Local)
        );
        assert_eq!(
            for_container((true, Source::Nix), Some((false, Source::Local)), false),
            (false, Source::Local)
        );
        // The same word as the declared one: the declared one is named.
        assert_eq!(
            for_container((true, Source::Nix), Some((true, Source::Local)), true),
            (true, Source::Nix)
        );
        assert_eq!(
            for_container((false, Source::Nix), Some((false, Source::Local)), false),
            (false, Source::Nix)
        );
        // Its own declared word over everything, both ways.
        assert_eq!(
            for_container((true, Source::Nix), Some((false, Source::Nix)), true),
            (false, Source::Nix)
        );
        assert_eq!(
            for_container((false, Source::Default), Some((true, Source::Nix)), false),
            (true, Source::Nix)
        );
        assert_eq!(
            for_container((true, Source::Nix), Some((false, Source::Nix)), false),
            (false, Source::Nix)
        );
    }

    /// Review 2026-09-28, every combination: the zone's value and source,
    /// the container's own (none, or a value from Nix or locally), for a
    /// setting whose safe value is on and for one whose safe value is off.
    #[test]
    fn a_local_word_closes_under_nix_and_never_opens() {
        let sources = [Source::Nix, Source::Local, Source::Default];
        for safe in [true, false] {
            for zone_on in [true, false] {
                for zone_source in sources {
                    let zone = (zone_on, zone_source);
                    let mut owns: Vec<Option<(bool, Source)>> = vec![None];
                    for on in [true, false] {
                        owns.push(Some((on, Source::Nix)));
                        owns.push(Some((on, Source::Local)));
                    }
                    for own in owns {
                        let got = for_container(zone, own, safe);
                        let case = format!("safe {safe}, zone {zone:?}, own {own:?}: {got:?}");
                        match own {
                            // Nothing of its own: the zone's.
                            None => assert_eq!(got, zone, "{case}"),
                            // Its own declared word, both ways.
                            Some((on, Source::Nix)) => assert_eq!(got, (on, Source::Nix), "{case}"),
                            // Under a declared zone: closes, never opens.
                            Some((on, source)) if zone_source == Source::Nix => {
                                if on == safe && zone_on != safe {
                                    assert_eq!(got, (on, source), "{case}");
                                } else {
                                    assert_eq!(got, zone, "{case}");
                                }
                                if zone_on == safe {
                                    assert_eq!(got.0, safe, "a local word opened: {case}");
                                }
                                if on == safe {
                                    assert_eq!(got.0, safe, "a local word did not close: {case}");
                                }
                            }
                            // Over a local or default zone: its own word.
                            Some(own) => assert_eq!(got, own, "{case}"),
                        }
                    }
                }
            }
        }
    }

    /// A container's own word as its files say it: the declared one over the
    /// local one; a word that is neither on nor off the safe value — for
    /// hermeticity on, for the others off.
    #[test]
    fn a_containers_own_word_is_read_safely() {
        let d = Dirs::new("own");
        std::fs::create_dir_all(d.config().join("containers/work")).unwrap();
        std::fs::create_dir_all(d.config().join("declared/containers")).unwrap();
        assert_eq!(container_own(&d.config(), "work", "hermetic"), None);
        d.write(
            "config/containers/work/container.conf",
            "hermetic = false\nnix_daemon = on\naudio_manager = maybe\n",
        );
        assert_eq!(
            container_own(&d.config(), "work", "hermetic"),
            Some((false, Source::Local))
        );
        assert_eq!(
            container_own(&d.config(), "work", "nix_daemon"),
            Some((true, Source::Local))
        );
        assert_eq!(
            container_own(&d.config(), "work", "audio_manager"),
            Some((false, Source::Local))
        );
        d.write(
            "config/containers/work/container.conf",
            "hermetic = maybe\n",
        );
        assert_eq!(
            container_own(&d.config(), "work", "hermetic"),
            Some((true, Source::Local))
        );
        // Declared: a file of the module's kind (with its `home`).
        d.declare(
            "containers/work.conf",
            "home = private\nhermetic = true\nhost_files_writable = true\n",
        );
        assert_eq!(
            container_own(&d.config(), "work", "hermetic"),
            Some((true, Source::Nix))
        );
        assert_eq!(
            container_own(&d.config(), "work", "host_files_writable"),
            Some((true, Source::Nix))
        );
        // And what an instance of it comes up with in a zone that is
        // hermetic by default: hermetic — the zone tolerates no host
        // session (step 1, 2026-09-28) —; in one that does, its own, while
        // the main home's is the zone's.
        d.write("config/containers/work/container.conf", "");
        d.declare("containers/work.conf", "home = private\nhermetic = false\n");
        let work = Who::Container("work".into());
        let settings = start_settings_for(&d.zone(), &d.config(), "nl", &work);
        assert_eq!(settings[0], ("hermetic", true));
        d.declare(
            "containers/work.conf",
            "home = private\nnix_daemon = true\n",
        );
        d.write("zone/hermetic", "off");
        let settings = start_settings_for(&d.zone(), &d.config(), "nl", &work);
        assert_eq!(settings[0], ("hermetic", false));
        assert_eq!(settings[1], ("nix_daemon", false));
        d.declare("containers/work.conf", "home = private\nhermetic = true\n");
        let settings = start_settings_for(&d.zone(), &d.config(), "nl", &work);
        assert_eq!(settings[0], ("hermetic", true));
        let main = start_settings_for(&d.zone(), &d.config(), "nl", &Who::Main);
        assert_eq!(main[0], ("hermetic", false));
        assert_eq!(start_settings(&d.zone(), &d.config(), "nl"), main);
    }

    /// Review 2026-09-28: a throwaway container's instance (nobody's) comes
    /// up with the safe values in a network that gives its containers
    /// everything — declared or local —, and the main home's with the
    /// network's.
    #[test]
    fn a_throwaway_comes_up_safe_whatever_its_network_says() {
        let d = Dirs::new("throwaway");
        let safe = [
            ("hermetic", true),
            ("nix_daemon", false),
            ("host_files_writable", false),
            ("audio_manager", false),
        ];
        let open = [
            ("hermetic", false),
            ("nix_daemon", true),
            ("host_files_writable", true),
            ("audio_manager", true),
        ];
        // Locally.
        d.write("zone/hermetic", "off");
        d.write("zone/nix-daemon", "on");
        d.write("zone/host-files", "writable");
        d.write("zone/audio-manager", "on");
        assert_eq!(
            start_settings_for(&d.zone(), &d.config(), "nl", &Who::Main),
            open
        );
        assert_eq!(
            start_settings_for(&d.zone(), &d.config(), "nl", &Who::Unknown),
            safe
        );
        // Declared in Nix.
        std::fs::remove_file(d.zone().join("hermetic")).unwrap();
        d.declare("hermetic-default", "off");
        d.declare("nix-daemon", "nl\n");
        d.declare("host-files-writable", "nl\n");
        d.declare("audio-manager", "nl\n");
        assert_eq!(
            start_settings_for(&d.zone(), &d.config(), "nl", &Who::Main),
            open
        );
        assert_eq!(
            start_settings_for(&d.zone(), &d.config(), "nl", &Who::Unknown),
            safe
        );
        for (key, value) in safe {
            assert_eq!(
                value_for(&d.zone(), &d.config(), "nl", &Who::Unknown, key),
                (value, Source::Default),
                "{key}"
            );
        }
    }

    /// Step 1 (2026-09-28), every combination for every setting: a
    /// network — an ordinary zone, one the person locked, `offline` —; its
    /// word — none, open or closed, locally or from Nix —; a container's own
    /// word — the same five —; the main home, the container and nobody.
    /// Against step 0's rule ([`for_container`], the network's for the main
    /// home) and the model: nothing wider than before; a way around the
    /// network open only where it is both asked for and tolerated; a
    /// container's closing word always holds, its opening one wherever the
    /// network tolerates it; the main home and a container without a word
    /// of its own get what the lists gave, in a network that is neither
    /// locked nor `offline`; `offline` opens no way around it at all.
    #[test]
    fn a_way_around_the_network_needs_both_words() {
        use std::collections::HashMap;
        use std::path::PathBuf;
        // Declared files as the module's (links into the store), made once
        // for each text: `nix-store --add` is slow.
        let mut stored: HashMap<String, PathBuf> = HashMap::new();
        let mut declare = |path: &Path, text: &str| {
            let target = stored.entry(text.to_owned()).or_insert_with(|| {
                let probe = std::env::temp_dir().join(format!(
                    "vz-both-probe-{}-{}",
                    std::process::id(),
                    text.len()
                ));
                let _ = std::fs::remove_file(&probe);
                crate::declared::declare(&probe, text);
                let target = std::fs::read_link(&probe).unwrap();
                let _ = std::fs::remove_file(&probe);
                target
            });
            let _ = std::fs::remove_file(path);
            std::os::unix::fs::symlink(target, path).unwrap();
        };
        // A word: none, or (open, from Nix).
        let words: [Option<(bool, bool)>; 5] = [
            None,
            Some((true, false)),
            Some((false, false)),
            Some((true, true)),
            Some((false, true)),
        ];
        let base = std::env::temp_dir().join(format!("vz-both-{}", std::process::id()));
        let zone_dir = base.join("zone");
        let config = base.join("config");
        let mut cases = 0;
        for (key, safe) in CONTAINER_KEYS {
            for network in ["zone", "locked", "offline"] {
                let zone = if network == "offline" {
                    "offline"
                } else {
                    "nl"
                };
                for zone_word in words {
                    for own_word in words {
                        let _ = std::fs::remove_dir_all(&base);
                        std::fs::create_dir_all(&zone_dir).unwrap();
                        std::fs::create_dir_all(config.join("declared/containers")).unwrap();
                        std::fs::create_dir_all(config.join("containers/work")).unwrap();
                        if network == "locked" {
                            std::fs::write(zone_dir.join(crate::launch::NO_ESCAPE), "").unwrap();
                        }
                        // The network's word, where each setting has it.
                        let (marker, open_word, closed_word, list) = match key {
                            "hermetic" => (MARKER, "off", "on", DEFAULT_SETTING),
                            "nix_daemon" => (NIX_DAEMON, "on", "off", NIX_DAEMON),
                            "host_files_writable" => (
                                HOST_FILES,
                                "writable",
                                "read-only",
                                DECLARED_HOST_FILES_WRITABLE,
                            ),
                            _ => (AUDIO_MANAGER, "on", "off", AUDIO_MANAGER),
                        };
                        match zone_word {
                            None => {}
                            Some((open, false)) => std::fs::write(
                                zone_dir.join(marker),
                                if open { open_word } else { closed_word },
                            )
                            .unwrap(),
                            Some((open, true)) => {
                                let text = match (key, open) {
                                    ("hermetic", true) => "off\n".to_owned(),
                                    ("hermetic", false) => "on\n".to_owned(),
                                    // A list names the zones it opens:
                                    // "closed" is a list without this one.
                                    (_, true) => format!("de\n{zone}\n"),
                                    (_, false) => "de\n".to_owned(),
                                };
                                declare(&config.join("declared").join(list), &text);
                            }
                        }
                        // The container's own word.
                        match own_word {
                            None => {}
                            Some((open, false)) => std::fs::write(
                                config.join("containers/work/container.conf"),
                                format!("{key} = {}\n", open != safe),
                            )
                            .unwrap(),
                            Some((open, true)) => declare(
                                &config.join("declared/containers/work.conf"),
                                &format!("home = private\n{key} = {}\n", open != safe),
                            ),
                        }
                        let network_word = zone_value(&zone_dir, &config, zone, key);
                        let own = container_own(&config, "work", key);
                        let tolerated = network != "offline"
                            && !(network == "locked" && key == "hermetic")
                            && network_word.0 != safe;
                        for who in [Who::Main, Who::Container("work".into()), Who::Unknown] {
                            cases += 1;
                            let got = value_for(&zone_dir, &config, zone, &who, key);
                            let told = explain(&zone_dir, &config, zone, &who, key);
                            let before = match &who {
                                Who::Container(_) => for_container(network_word, own, safe),
                                Who::Main => network_word,
                                Who::Unknown => (safe, Source::Default),
                            };
                            let case = format!(
                                "{key} in {network} ({zone_word:?}: {network_word:?}), own \
                                 {own_word:?} ({own:?}), {who:?}: {got:?}, before {before:?}, \
                                 {told:?}"
                            );
                            assert_eq!(told.value, got, "{case}");
                            assert_eq!(told.key, key, "{case}");
                            // Nothing wider than step 0 gave.
                            if got.0 != safe {
                                assert_ne!(before.0, safe, "wider than before: {case}");
                            }
                            if who == Who::Unknown {
                                assert_eq!(got, (safe, Source::Default), "{case}");
                                continue;
                            }
                            if !is_bypass(key) {
                                // A program's own permission: as before.
                                assert_eq!(got, before, "{case}");
                                assert_eq!(told.tolerated, None, "{case}");
                                continue;
                            }
                            assert_eq!(told.tolerated.map(|(on, _)| on), Some(tolerated), "{case}");
                            if !tolerated {
                                assert_eq!(got.0, safe, "open, not tolerated: {case}");
                            }
                            match (&who, own) {
                                (Who::Container(_), Some((on, _))) => {
                                    assert_eq!(told.asked.2, Asker::Container, "{case}");
                                    if on == safe {
                                        assert_eq!(got.0, safe, "its closing word: {case}");
                                    } else {
                                        assert_eq!(got.0 != safe, tolerated, "{case}");
                                    }
                                }
                                _ => {
                                    // What the lists gave, for whom they
                                    // spoke: the main home, a container
                                    // with no word of its own.
                                    assert_eq!(told.asked.2, Asker::Network, "{case}");
                                    if network == "zone" {
                                        assert_eq!(got, before, "the lists' word: {case}");
                                    } else {
                                        assert_eq!(
                                            got.0 != safe,
                                            tolerated && network_word.0 != safe,
                                            "{case}"
                                        );
                                    }
                                }
                            }
                            if network == "offline" {
                                assert_eq!(got.0, safe, "a way around offline: {case}");
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(cases, 4 * 3 * 5 * 5 * 3);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Review 2026-09-28: what an instance came up with against what
    /// another network would give it — named where it is open and the
    /// other network's is closed, never where the other is as open or
    /// more; a setting the note does not say, or says in no word, is open.
    #[test]
    fn frozen_settings_wider_than_a_networks_are_named() {
        let closed = [
            ("hermetic", true),
            ("nix_daemon", false),
            ("host_files_writable", false),
            ("audio_manager", false),
        ];
        let open = [
            ("hermetic", false),
            ("nix_daemon", true),
            ("host_files_writable", true),
            ("audio_manager", true),
        ];
        let safe = "hermetic=true\nnix_daemon=false\nhost_files_writable=false\n\
                    audio_manager=false\n";
        let wide = "hermetic=false\nnix_daemon=true\nhost_files_writable=true\n\
                    audio_manager=true\n";
        // Safe settings are wider than nothing.
        assert!(wider_than(safe, &closed).is_empty());
        assert!(wider_than(safe, &open).is_empty());
        // Open ones: wider than a closed target, not than an open one.
        assert_eq!(
            wider_than(wide, &closed),
            vec![
                "hermetic",
                "nix_daemon",
                "host_files_writable",
                "audio_manager"
            ]
        );
        assert!(wider_than(wide, &open).is_empty());
        // Each alone.
        for (i, (name, _)) in closed.iter().enumerate() {
            let mut target = closed;
            let note: String = safe
                .lines()
                .map(|line| {
                    if line.starts_with(&format!("{name}=")) {
                        format!("{name}={}\n", !safe_value(name))
                    } else {
                        format!("{line}\n")
                    }
                })
                .collect();
            assert_eq!(wider_than(&note, &target), vec![*name], "{note}");
            target[i].1 = !target[i].1;
            assert!(wider_than(&note, &target).is_empty(), "{note}");
        }
        // Not said, or said in no word: open.
        assert_eq!(wider_than("", &closed).len(), 4);
        assert_eq!(
            wider_than(
                "hermetic=yes\nnix_daemon=false\nhost_files_writable=false\naudio_manager=false\n",
                &closed
            ),
            vec!["hermetic"]
        );
        assert_eq!(applied_in("hermetic = true\n", "hermetic"), Some(true));
        assert_eq!(applied_in("hermetic=maybe\n", "hermetic"), None);
        assert_eq!(applied_in("", "hermetic"), None);
    }
}
