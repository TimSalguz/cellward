//! A zone's home: a layer over the real one (`docs/HOME-LAYER.md`).
//!
//! The holder mounts, in the zone's mount namespace, an overlay over the
//! home: the real home below, the zone's layer (`<zone>/home/upper`) above.
//! Everything a program in the zone writes stays in the layer; the real home
//! is written only through the paths given back to it ([`passthroughs`]):
//! the project's own state (it is the host's, and hidden from the zone
//! anyway), container storage (a container's data belongs to the container,
//! not to the zone it runs in), mounts below the home (an overlay does not
//! show them), and what the person shares with the zone. This module is the
//! settings and the plan; the mounts are `zone::mount_home_layer`.

use std::path::{Component, Path, PathBuf};

use crate::cli::read_setting;
use crate::container::Source;

/// The zone's layer, in the zone's directory: `upper` and `work` below it.
pub const LAYER_DIR: &str = "home";

/// In the layer's directory when the holder could not put the home under
/// the layer: why, one line. The zone then has the real home.
pub const FAILED: &str = "failed";

/// In the layer's directory: empty the layer before the zone next comes up
/// (`cellward home <zone> reset`). The holder does it — the overlay's own
/// work directory is its, not the user's.
pub const RESET: &str = "reset";

/// The marker of a zone's home: `passthrough` (the real home, the old
/// behaviour) or `layer`. No marker: a layer.
pub const MARKER: &str = "home";

/// Zones given the real home in Nix (`programs.cellward.home.passthrough`),
/// one per line, in `declared/`.
pub const DECLARED_PASSTHROUGH: &str = "home-passthrough";

/// The paths shared with a zone, one per line: `declared/home-shared/<zone>`
/// (Nix, `programs.cellward.home.shared.<zone>`), else `<zone>/home-shared`
/// (`cellward home <zone> share`).
pub const SHARED: &str = "home-shared";

/// What is always the real home's, below the home: the project's state (the
/// host's own, hidden from the zone later), and container storage.
pub const ALWAYS_REAL: [&str; 3] = [
    ".local/state/vpn-zones",
    ".local/state/vpn-profiles",
    ".local/state/vpn-sandboxes",
];

/// Whether the zone in `zone_dir` has the real home: `(passthrough, source)`.
pub fn passthrough(zone_dir: &Path, config: &Path, zone: &str) -> (bool, Source) {
    let declared = std::fs::read_to_string(
        config
            .join(crate::cli::DECLARED_DIR)
            .join(DECLARED_PASSTHROUGH),
    )
    .is_ok_and(|text| text.lines().map(str::trim).any(|line| line == zone));
    if declared {
        return (true, Source::Nix);
    }
    match read_setting(&zone_dir.join(MARKER)) {
        Some(text) if text.trim() == "passthrough" => (true, Source::Local),
        Some(text) if !text.trim().is_empty() => (false, Source::Local),
        _ => (false, Source::Default),
    }
}

/// The paths shared with the zone: `(paths, source)` — the declared list
/// when Nix has one for the zone (it outranks the local one), else the
/// local one. Lines that are no valid path are dropped here, and said by
/// `doctor`.
pub fn shared(zone_dir: &Path, config: &Path, zone: &str) -> (Vec<String>, Source) {
    let declared = config
        .join(crate::cli::DECLARED_DIR)
        .join(SHARED)
        .join(zone);
    let (text, source) = match std::fs::read_to_string(&declared) {
        Ok(text) => (text, Source::Nix),
        Err(_) => match std::fs::read_to_string(zone_dir.join(SHARED)) {
            Ok(text) => (text, Source::Local),
            Err(_) => (String::new(), Source::Default),
        },
    };
    let paths = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter(|l| valid_shared(l).is_ok())
        .map(str::to_owned)
        .collect();
    (paths, source)
}

/// A path that may be shared with a zone: below the home, written as it is
/// (no `.`, no `..`, no leading `/`), and not the project's own — its state
/// is the host's, and its settings and shims are what the host acts on.
pub fn valid_shared(path: &str) -> Result<PathBuf, String> {
    let p = Path::new(path.trim_end_matches('/'));
    if path.is_empty() || p.as_os_str().is_empty() {
        return Err("пустой путь".to_owned());
    }
    if !p.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err(format!(
            "«{path}»: путь от дома, без «/» в начале, «.» и «..»"
        ));
    }
    for own in [
        ".local/state/vpn-zones",
        ".config/vpn-zones",
        ".local/share/vpn-zones",
    ] {
        let own = Path::new(own);
        if p.starts_with(own) || own.starts_with(p) {
            return Err(format!(
                "«{path}»: это настройки и состояние cellward — они хоста"
            ));
        }
    }
    Ok(p.to_path_buf())
}

/// The mount points strictly below `home` in a `mountinfo`, relative to it.
/// An overlay shows none of them: they are bound back on top.
pub fn submounts(mountinfo: &str, home: &Path) -> Vec<PathBuf> {
    mountinfo
        .lines()
        .filter_map(|line| line.split(' ').nth(4))
        .map(unescape)
        .filter_map(|point| {
            PathBuf::from(point)
                .strip_prefix(home)
                .ok()
                .filter(|rel| !rel.as_os_str().is_empty())
                .map(Path::to_path_buf)
        })
        .collect()
}

/// `mountinfo` writes a space, a tab, a line break and a backslash in octal.
fn unescape(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut chars = field.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let digits: String = chars.clone().take(3).collect();
            if digits.len() == 3 && digits.chars().all(|d| ('0'..='7').contains(&d)) {
                if let Ok(byte) = u8::from_str_radix(&digits, 8) {
                    out.push(byte as char);
                    for _ in 0..3 {
                        chars.next();
                    }
                    continue;
                }
            }
        }
        out.push(c);
    }
    out
}

/// What is bound from the real home over the layer, relative to the home, in
/// the order to bind: [`ALWAYS_REAL`], the mounts below the home and the
/// shared paths, each once, and none below another — a recursive bind of the
/// one above brings it along.
pub fn passthroughs(shared: &[String], submounts: &[PathBuf]) -> Vec<PathBuf> {
    let mut all: Vec<PathBuf> = ALWAYS_REAL
        .iter()
        .map(PathBuf::from)
        .chain(submounts.iter().cloned())
        .chain(shared.iter().filter_map(|s| valid_shared(s).ok()))
        .collect();
    all.sort();
    all.dedup();
    let mut out: Vec<PathBuf> = Vec::new();
    for p in all {
        if !out.iter().any(|kept| p.starts_with(kept)) {
            out.push(p);
        }
    }
    out
}

/// The layer's directories in a zone's directory: `(upper, work)`.
pub fn layer_dirs(zone_dir: &Path) -> (PathBuf, PathBuf) {
    let base = zone_dir.join(LAYER_DIR);
    (base.join("upper"), base.join("work"))
}

/// The overlay's options for a home at `home` and a layer at `upper`/`work`,
/// or `None` for a path overlayfs cannot be told (a comma or a colon splits
/// its options and its lower layers; a backslash escapes).
pub fn overlay_options(home: &Path, upper: &Path, work: &Path) -> Option<String> {
    let clean = |p: &Path| {
        let s = p.to_str()?;
        (!s.contains([',', ':', '\\'])).then(|| s.to_owned())
    };
    Some(format!(
        "lowerdir={},upperdir={},workdir={},userxattr",
        clean(home)?,
        clean(upper)?,
        clean(work)?
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_shared_path_is_below_the_home_and_not_the_projects() {
        assert!(valid_shared("Projects").is_ok());
        assert!(valid_shared(".claude.json").is_ok());
        assert!(valid_shared("Projects/").is_ok());
        assert_eq!(valid_shared("a/b").unwrap(), PathBuf::from("a/b"));
        for bad in [
            "",
            "/etc",
            "../x",
            "a/../b",
            "./a",
            ".local/state/vpn-zones",
            ".local/state/vpn-zones/nl",
            ".local/state",
            ".config/vpn-zones",
            ".config",
            ".local/share/vpn-zones/shims",
        ] {
            assert!(valid_shared(bad).is_err(), "{bad} was taken");
        }
    }

    #[test]
    fn mounts_below_the_home_are_found_and_unescaped() {
        let info = "36 1 0:32 / / rw - btrfs /dev/x rw\n\
                    40 36 8:17 / /home/u/Games rw - ext4 /dev/sdb rw\n\
                    41 36 8:18 / /home/u/My\\040Disk rw - ext4 /dev/sdc rw\n\
                    42 36 0:40 / /home/u rw - tmpfs t rw\n\
                    43 36 0:41 / /home/uu/x rw - tmpfs t rw\n";
        assert_eq!(
            submounts(info, Path::new("/home/u")),
            [PathBuf::from("Games"), PathBuf::from("My Disk")]
        );
    }

    #[test]
    fn what_goes_back_is_each_once_and_none_below_another() {
        let shared = vec![
            "Projects".to_owned(),
            "Projects/a".to_owned(),
            "../evil".to_owned(),
            ".local/state/vpn-zones/nl".to_owned(),
        ];
        let subs = vec![PathBuf::from("Games"), PathBuf::from("Games/deep")];
        assert_eq!(
            passthroughs(&shared, &subs),
            [
                ".local/state/vpn-profiles",
                ".local/state/vpn-sandboxes",
                ".local/state/vpn-zones",
                "Games",
                "Projects",
            ]
            .map(PathBuf::from)
        );
    }

    #[test]
    fn the_overlay_is_told_only_paths_it_can_read() {
        assert_eq!(
            overlay_options(
                Path::new("/home/u"),
                Path::new("/home/u/.local/state/vpn-zones/nl/home/upper"),
                Path::new("/home/u/.local/state/vpn-zones/nl/home/work"),
            )
            .as_deref(),
            Some(
                "lowerdir=/home/u,upperdir=/home/u/.local/state/vpn-zones/nl/home/upper,\
                 workdir=/home/u/.local/state/vpn-zones/nl/home/work,userxattr"
            )
        );
        assert!(
            overlay_options(Path::new("/home/a,b"), Path::new("/u"), Path::new("/w")).is_none()
        );
        assert!(
            overlay_options(Path::new("/home/a:b"), Path::new("/u"), Path::new("/w")).is_none()
        );
    }

    #[test]
    fn a_zone_has_a_layer_unless_given_the_real_home() {
        let base = std::env::temp_dir().join(format!("vz-home-layer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let zone = base.join("zone");
        let config = base.join("config");
        std::fs::create_dir_all(&zone).unwrap();
        std::fs::create_dir_all(config.join("declared/home-shared")).unwrap();
        assert_eq!(passthrough(&zone, &config, "nl"), (false, Source::Default));
        std::fs::write(zone.join(MARKER), "passthrough\n").unwrap();
        assert_eq!(passthrough(&zone, &config, "nl"), (true, Source::Local));
        std::fs::write(zone.join(MARKER), "layer\n").unwrap();
        assert_eq!(passthrough(&zone, &config, "nl"), (false, Source::Local));
        std::fs::write(config.join("declared/home-passthrough"), "de\nnl\n").unwrap();
        assert_eq!(passthrough(&zone, &config, "nl"), (true, Source::Nix));
        // Shared: the local list, until Nix has one for the zone.
        std::fs::write(zone.join(SHARED), "Projects\n../x\n\n").unwrap();
        assert_eq!(
            shared(&zone, &config, "nl"),
            (vec!["Projects".to_owned()], Source::Local)
        );
        std::fs::write(config.join("declared/home-shared/nl"), ".claude\n").unwrap();
        assert_eq!(
            shared(&zone, &config, "nl"),
            (vec![".claude".to_owned()], Source::Nix)
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
