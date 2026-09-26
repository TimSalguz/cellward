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

use std::io::ErrorKind;
use std::path::Path;

use crate::cli::{read_setting, DECLARED_DIR};
use crate::container::Source;

/// The per-zone marker, in the zone's directory: `on`, `off` or empty (on).
pub const MARKER: &str = "hermetic";
/// The default for zones without a marker, a setting file of the config
/// directory (`on` or `off`), locally or below `declared/`.
pub const DEFAULT_SETTING: &str = "hermetic-default";
/// The zones Nix sets opposite to its default, one name per line, below
/// `declared/`.
pub const DECLARED_EXCEPTIONS: &str = "hermetic-exceptions";

/// A default setting file: `None` when it is absent or empty.
fn default_file(path: &Path) -> Option<bool> {
    read_setting(path)
        .filter(|text| !text.trim().is_empty())
        .map(|text| text.trim() != "off")
}

/// The default for zones without a marker: `(on, source)`.
pub fn default_setting(config: &Path) -> (bool, Source) {
    if let Some(on) = default_file(&config.join(DECLARED_DIR).join(DEFAULT_SETTING)) {
        return (on, Source::Nix);
    }
    if let Some(on) = default_file(&config.join(DEFAULT_SETTING)) {
        return (on, Source::Local);
    }
    (true, Source::Default)
}

/// Whether Nix names this zone an exception.
pub fn declared_exception(config: &Path, zone: &str) -> bool {
    std::fs::read_to_string(config.join(DECLARED_DIR).join(DECLARED_EXCEPTIONS))
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
    let declared = std::fs::read_to_string(config.join(DECLARED_DIR).join(list))
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

/// Below a zone's state directory: the settings it came up with, one
/// `<name>=<true|false>` a line, written by its holder before the zone is
/// up. They are in force until it comes up again; `status --json` names
/// those that have changed since (`networks[].restart_needed`).
pub const APPLIED: &str = "zone.settings";

/// The settings a zone takes when it comes up, by their names in
/// `status --json`.
pub fn start_settings(zone_dir: &Path, config: &Path, zone: &str) -> [(&'static str, bool); 4] {
    [
        ("hermetic", zone_setting(zone_dir, config, zone).0),
        ("nix_daemon", nix_daemon(zone_dir, config, zone).0),
        (
            "host_files_writable",
            host_files_writable(zone_dir, config, zone).0,
        ),
        ("audio_manager", audio_manager(zone_dir, config, zone).0),
    ]
}

/// Note what a zone comes up with ([`APPLIED`]), through a temporary.
pub fn note_applied(zone_dir: &Path, settings: &[(&str, bool)]) -> std::io::Result<()> {
    let text: String = settings.iter().map(|(k, v)| format!("{k}={v}\n")).collect();
    let tmp = zone_dir.join(format!("{APPLIED}.new"));
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, zone_dir.join(APPLIED))
}

/// Which settings of a running zone differ now from those it came up with,
/// by name. `None`: not known — no note (a zone a build from before it
/// started). A setting the note does not name is not counted.
pub fn restart_needed(zone_dir: &Path, config: &Path, zone: &str) -> Option<Vec<&'static str>> {
    let text = std::fs::read_to_string(zone_dir.join(APPLIED)).ok()?;
    let applied = |name: &str| {
        text.lines()
            .filter_map(|line| line.split_once('='))
            .find(|(k, _)| k.trim() == name)
            .map(|(_, v)| v.trim() == "true")
    };
    let mut changed: Vec<&'static str> = start_settings(zone_dir, config, zone)
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
        d.write("config/declared/nix-daemon", "de\nnl\n");
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
        d.write("config/declared/audio-manager", "nl\n");
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
        d.write("config/declared/hermetic-default", "off");
        assert_eq!(d.setting(), (false, Source::Nix));
        // The zone's own marker is more specific than either default.
        d.write("zone/hermetic", "on");
        assert_eq!(d.setting(), (true, Source::Local));
    }

    #[test]
    fn a_declared_exception_inverts_the_declared_default_over_the_marker() {
        let d = Dirs::new("exception");
        d.write("config/declared/hermetic-exceptions", "de\nnl\n");
        d.write("zone/hermetic", "on");
        // No declared default: the exception means nothing.
        assert_eq!(d.setting(), (true, Source::Local));
        d.write("config/declared/hermetic-default", "on");
        assert_eq!(d.setting(), (false, Source::Nix));
        d.write("config/declared/hermetic-default", "off");
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
}
