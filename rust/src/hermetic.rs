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
//! 5. off.
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
    (false, Source::Default)
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

    #[test]
    fn nothing_set_is_off_by_default() {
        let d = Dirs::new("none");
        assert_eq!(d.setting(), (false, Source::Default));
        d.write("config/hermetic-default", "");
        assert_eq!(d.setting(), (false, Source::Default));
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
}
