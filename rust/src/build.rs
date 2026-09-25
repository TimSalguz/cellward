//! Which build of cellward a running zone is on.
//!
//! An update leaves running zones alone (`X-SwitchMethod=keep-old`,
//! `module/default.nix`): their programs keep the network, and a zone takes
//! the new build when it is restarted. Until then the holder's own fixes do
//! not apply to it — and the person should know that, rather than find out.
//! The holder notes the build it runs as ([`FILE`] in the zone's directory,
//! next to `zone.pid`); `status`, `doctor` and the tunnel watch compare it
//! with the build installed now.
//!
//! A build is the store directory of the program (`/nix/store/<hash>-<name>`):
//! a new build of the same version is a new directory too. A holder from
//! before this note wrote none — it is from a previous build as well.

use std::fs;
use std::path::{Path, PathBuf};

use crate::tools::Tools;

/// The note, in a zone's directory.
pub const FILE: &str = "zone.build";

/// Where a running zone stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Age {
    /// The build installed now.
    Current,
    /// An earlier one: restart the zone to take the new.
    Previous,
}

impl Age {
    pub fn as_str(self) -> &'static str {
        match self {
            Age::Current => "current",
            Age::Previous => "previous",
        }
    }
}

/// `age` as a JSON string.
pub fn string(age: Age) -> String {
    format!("\"{}\"", age.as_str())
}

/// The store directory `path` lives in, or the path itself outside the store.
pub fn build_of(path: &Path) -> PathBuf {
    let real = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut parts = real.components();
    let mut out = PathBuf::new();
    // "/", "nix", "store", "<hash>-<name>"
    for _ in 0..4 {
        match parts.next() {
            Some(c) => out.push(c),
            None => return real,
        }
    }
    if out.starts_with("/nix/store") {
        out
    } else {
        real
    }
}

/// Note the build this process runs as, in the zone's directory. Not fatal:
/// without the note the zone reads as "previous", which only asks for a
/// restart.
pub fn record(zone_dir: &Path) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let text = format!("{}\n", build_of(&exe).display());
    let tmp = zone_dir.join(format!("{FILE}.tmp"));
    let _ = fs::write(&tmp, text).and_then(|()| fs::rename(&tmp, zone_dir.join(FILE)));
}

/// The build installed now: the core the manifest names.
pub fn installed(tools: &Tools) -> PathBuf {
    build_of(&tools.core)
}

/// Where a zone whose directory is `zone_dir` stands, compared with
/// `installed`.
pub fn age(zone_dir: &Path, installed: &Path) -> Age {
    match fs::read_to_string(zone_dir.join(FILE)) {
        Ok(text) if Path::new(text.trim()) == installed => Age::Current,
        _ => Age::Previous,
    }
}

/// The running zones on a previous build, by name.
pub fn previous_zones(tools: &Tools) -> Vec<String> {
    let installed = installed(tools);
    let Ok(entries) = fs::read_dir(&tools.state) else {
        return Vec::new();
    };
    let mut out: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(str::to_owned))
        .filter(|name| !name.starts_with('.'))
        .filter(|name| crate::cli::zone_pid(&tools.state, name.as_ref()).is_some())
        .filter(|name| age(&tools.state.join(name), &installed) == Age::Previous)
        .collect();
    out.sort();
    out
}

/// What the person is told, once per update, when zones are left on the
/// previous build.
pub fn notice(zones: &[String]) -> (String, String) {
    let title = if zones.len() == 1 {
        format!("Зона «{}» работает на прошлой сборке cellward", zones[0])
    } else {
        "Зоны работают на прошлой сборке cellward".to_owned()
    };
    let list = zones
        .iter()
        .map(|z| format!("«{z}»"))
        .collect::<Vec<_>>()
        .join(", ");
    let body = format!(
        "{list}: обновление их не тронуло — сеть у программ не прервалась. Новая сборка \
         и её исправления придут в зону, когда вы её перезапустите: cellward down <зона>; \
         cellward up <зона> — в удобный момент, программы зоны на это время потеряют сеть."
    );
    (title, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_build_is_its_store_directory() {
        assert_eq!(
            build_of(Path::new("/nix/store/abc-cellward-0.1/bin/vpn-zone-core")),
            PathBuf::from("/nix/store/abc-cellward-0.1")
        );
        // Outside the store: the path itself.
        assert_eq!(
            build_of(Path::new("/opt/x/bin/core")),
            PathBuf::from("/opt/x/bin/core")
        );
    }

    #[test]
    fn a_zone_without_a_note_is_on_a_previous_build() {
        let dir = std::env::temp_dir().join(format!("cellward-build-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let now = Path::new("/nix/store/new-cellward");
        assert_eq!(age(&dir, now), Age::Previous);
        fs::write(dir.join(FILE), "/nix/store/old-cellward\n").unwrap();
        assert_eq!(age(&dir, now), Age::Previous);
        fs::write(dir.join(FILE), "/nix/store/new-cellward\n").unwrap();
        assert_eq!(age(&dir, now), Age::Current);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_notice_names_the_zones_and_how_to_restart() {
        let (title, body) = notice(&["nl".to_owned()]);
        assert!(title.contains("«nl»"), "{title}");
        assert!(body.contains("cellward down <зона>"), "{body}");
        let (title, body) = notice(&["a".to_owned(), "b".to_owned()]);
        assert!(title.starts_with("Зоны"), "{title}");
        assert!(body.starts_with("«a», «b»"), "{body}");
    }
}
