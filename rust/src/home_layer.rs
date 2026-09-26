//! A container's home as a layer over the real one (`docs/PERMISSIONS.md`
//! §11.3, `docs/CONTAINERS.md`).
//!
//! `profile-run` mounts, in the launch's own mount namespace, an overlay over
//! the whole home: the real home below, the container's layer above
//! (`<container>/home/upper`). The program sees the home as it is, and
//! everything it writes stays in the layer — a line in `~/.bashrc`, an
//! autostart entry, a git hook are the container's, never the host's. Given
//! back over the layer from the real home, through a descriptor opened before
//! it:
//!
//! * what was mounted below the home before the layer — an overlay shows
//!   none of it: another disk (`~/Games`), and in a zone the zone's own covers
//!   (the project's state hidden, the settings read-only), which must hold in
//!   the layer as they hold outside it; a bind keeps a read-only mount
//!   read-only, its children too;
//! * the paths granted to the container (`container grant`): what it writes
//!   there reaches the real home.
//!
//! Then the other containers' storage is covered: a container is an identity
//! of its own, and its layer is no window into another's data.
//!
//! The plan is here and pure; the mounts are `profile::mount_profile`.

use std::fs;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};

/// The layer's directory in a container's directory: `upper` and `work`
/// below it.
pub const LAYER_DIR: &str = "home";

/// Container storage, below the home: covered in a layer, where it is the
/// other containers' data.
pub const STORAGE: [&str; 2] = [".local/state/vpn-profiles", ".local/state/vpn-sandboxes"];

/// The project's own places below the home: a mount there is the zone's
/// cover (the state hidden, the settings read-only) and keeps its flags.
pub const PROJECT: [&str; 3] = [
    ".local/state/vpn-zones",
    ".config/vpn-zones",
    ".local/share/vpn-zones",
];

/// Whether a mount given back over the layer stays as it is: the project's
/// own covers, and what is granted to the container. Anything else below the
/// home — another disk, a bind of `~/.ssh` from elsewhere — is made read-only:
/// the layer does not cover a mount, and the container must not write the
/// real one unless it was granted.
pub fn keeps_flags(rel: &Path, granted: &[PathBuf]) -> bool {
    PROJECT.iter().any(|p| rel.starts_with(p)) || granted.iter().any(|g| rel.starts_with(g))
}

/// The layer's directories in a container's directory: `(upper, work)`.
pub fn layer_dirs(container_dir: &Path) -> (PathBuf, PathBuf) {
    let base = container_dir.join(LAYER_DIR);
    (base.join("upper"), base.join("work"))
}

/// The mount points strictly below `home` in a `mountinfo`, relative to it,
/// each once, and none below another — a recursive bind of the one above
/// brings it along with its own flags.
pub fn submounts(mountinfo: &str, home: &Path) -> Vec<PathBuf> {
    let mut all: Vec<PathBuf> = mountinfo
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
        .collect();
    all.sort();
    all.dedup();
    let mut top: Vec<PathBuf> = Vec::new();
    for p in all {
        if !top.iter().any(|kept| p.starts_with(kept)) {
            top.push(p);
        }
    }
    top
}

/// `mountinfo` writes a space, a tab, a line break and a backslash in octal.
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = bytes
            .get(i + 1..i + 4)
            .filter(|d| bytes[i] == b'\\' && d.iter().all(|c| (b'0'..=b'7').contains(c)));
        match octal {
            Some(d) => {
                out.push((d[0] - b'0') * 64 + (d[1] - b'0') * 8 + (d[2] - b'0'));
                i += 4;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A path granted to a layer container, relative to the home: below it, and
/// not the home itself. `None` for anything else — a path outside the home is
/// not under the layer, and is the real one anyway.
pub fn relative_share(home: &Path, path: &Path) -> Option<PathBuf> {
    let rel = crate::container::lexical(path)
        .strip_prefix(home)
        .ok()?
        .to_path_buf();
    (!rel.as_os_str().is_empty()).then_some(rel)
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

/// Where a profile's old overlay slots go in the whole-home layer: `(slot's
/// upper, its place in the layer)`. The slots were `<dir>/<slot_name>/upper`
/// over `.config`, `.local/share` and the rest.
pub fn slot_moves(container_dir: &Path) -> Vec<(PathBuf, PathBuf)> {
    let (upper, _) = layer_dirs(container_dir);
    crate::profile::SUBDIRS
        .iter()
        .map(|sub| {
            (
                container_dir
                    .join(crate::profile::slot_name(sub))
                    .join("upper"),
                upper.join(sub),
            )
        })
        .collect()
}

/// Move a profile's old slots into its whole-home layer, where nothing is
/// there yet: its data stays its data. A slot whose place is taken is left
/// where it was, and said.
pub fn migrate_slots(container_dir: &Path) {
    for (from, to) in slot_moves(container_dir) {
        if !from.is_dir() || fs::symlink_metadata(&to).is_ok() {
            continue;
        }
        let moved = to
            .parent()
            .map_or(Ok(()), fs::create_dir_all)
            .and_then(|()| fs::rename(&from, &to));
        if let Err(e) = moved {
            eprintln!(
                "profile: cannot move {} into the layer ({}): {e}",
                from.display(),
                to.display()
            );
        }
    }
}

/// Bind `rel` of the real home (`real`, a descriptor opened before the layer)
/// over the layer: `Ok(false)` when the real home has no such path.
///
/// The target is the layer's view, which the layer shapes: a link left there
/// once (`~/.local` → elsewhere) would take the bind where the container
/// likes. Every part of the path below the home is made a plain directory
/// first — a link is removed, which only whites it out in the layer — and so
/// is the target, of the source's kind. Nothing of the container runs yet:
/// this is its launch, before the program.
pub fn give_back(real: &OwnedFd, home: &Path, rel: &Path) -> Result<bool, String> {
    let from = PathBuf::from(format!("/proc/self/fd/{}", real.as_raw_fd())).join(rel);
    let Ok(meta) = fs::metadata(&from) else {
        return Ok(false);
    };
    let mut at = home.to_path_buf();
    let parts: Vec<_> = rel.components().collect();
    for (i, part) in parts.iter().enumerate() {
        at.push(part);
        let last = i + 1 == parts.len();
        let seen = fs::symlink_metadata(&at);
        let fits = match &seen {
            Ok(m) if m.file_type().is_symlink() => false,
            Ok(m) if !last => m.is_dir(),
            Ok(m) => m.is_dir() == meta.is_dir(),
            Err(_) => false,
        };
        if fits {
            continue;
        }
        if seen.is_ok() {
            let gone = match &seen {
                Ok(m) if m.is_dir() => fs::remove_dir_all(&at),
                _ => fs::remove_file(&at),
            };
            gone.map_err(|e| format!("cannot clear {} in the layer: {e}", at.display()))?;
        }
        let made = if !last || meta.is_dir() {
            fs::create_dir(&at)
        } else {
            fs::File::create(&at).map(drop)
        };
        made.map_err(|e| format!("cannot make {} in the layer: {e}", at.display()))?;
    }
    crate::sys::mount(from.as_os_str(), &at, "", libc::MS_BIND | libc::MS_REC, "")
        .map_err(|e| format!("cannot give {} back: {e}", at.display()))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mounts_below_the_home_are_found_once_and_unescaped() {
        let info = "36 1 0:32 / / rw - btrfs /dev/x rw\n\
                    40 36 8:17 / /home/u/Games rw - ext4 /dev/sdb rw\n\
                    41 36 8:18 / /home/u/My\\040Disk rw - ext4 /dev/sdc rw\n\
                    42 36 0:40 / /home/u rw - tmpfs t rw\n\
                    43 36 0:41 / /home/uu/x rw - tmpfs t rw\n\
                    44 36 0:42 / /home/u/.local/state/vpn-zones rw - tmpfs t rw\n\
                    45 44 0:43 / /home/u/.local/state/vpn-zones/.running ro - btrfs x ro\n\
                    46 36 0:44 / /home/u/Games rw - ext4 /dev/sdb rw\n";
        assert_eq!(
            submounts(info, Path::new("/home/u")),
            [".local/state/vpn-zones", "Games", "My Disk"].map(PathBuf::from)
        );
    }

    #[test]
    fn a_share_is_below_the_home_and_not_the_home() {
        let home = Path::new("/home/u");
        assert_eq!(
            relative_share(home, Path::new("/home/u/Projects")),
            Some(PathBuf::from("Projects"))
        );
        assert_eq!(
            relative_share(home, Path::new("/home/u/a/../Projects")),
            Some(PathBuf::from("Projects"))
        );
        assert_eq!(relative_share(home, Path::new("/home/u")), None);
        assert_eq!(relative_share(home, Path::new("/mnt/games")), None);
        assert_eq!(relative_share(home, Path::new("/home/uu/x")), None);
    }

    #[test]
    fn the_overlay_is_told_only_paths_it_can_read() {
        assert_eq!(
            overlay_options(
                Path::new("/home/u"),
                Path::new("/home/u/.local/state/vpn-profiles/w/home/upper"),
                Path::new("/home/u/.local/state/vpn-profiles/w/home/work"),
            )
            .as_deref(),
            Some(
                "lowerdir=/home/u,upperdir=/home/u/.local/state/vpn-profiles/w/home/upper,\
                 workdir=/home/u/.local/state/vpn-profiles/w/home/work,userxattr"
            )
        );
        assert!(
            overlay_options(Path::new("/home/a,b"), Path::new("/u"), Path::new("/w")).is_none()
        );
        assert!(
            overlay_options(Path::new("/home/a:b"), Path::new("/u"), Path::new("/w")).is_none()
        );
    }

    /// A profile's slots become its layer's `.config` and the rest; a place
    /// taken already keeps what is there.
    #[test]
    fn old_slots_move_into_the_layer() {
        let dir = std::env::temp_dir().join(format!("vz-slots-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join(".config/upper/app")).unwrap();
        fs::write(dir.join(".config/upper/app/settings"), "old").unwrap();
        fs::create_dir_all(dir.join(".local_share/upper")).unwrap();
        fs::write(dir.join(".local_share/upper/history"), "h").unwrap();
        fs::create_dir_all(dir.join(".cache/upper")).unwrap();
        fs::create_dir_all(dir.join("home/upper/.cache")).unwrap();
        fs::write(dir.join("home/upper/.cache/kept"), "k").unwrap();
        migrate_slots(&dir);
        assert_eq!(
            fs::read_to_string(dir.join("home/upper/.config/app/settings")).unwrap(),
            "old"
        );
        assert_eq!(
            fs::read_to_string(dir.join("home/upper/.local/share/history")).unwrap(),
            "h"
        );
        assert!(dir.join("home/upper/.cache/kept").is_file());
        assert!(
            dir.join(".cache/upper").is_dir(),
            "a taken place was overwritten"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod flags_tests {
    use super::*;

    #[test]
    fn only_the_projects_covers_and_grants_keep_their_flags() {
        let granted = vec![PathBuf::from("Games")];
        assert!(keeps_flags(Path::new(".local/state/vpn-zones"), &granted));
        assert!(keeps_flags(Path::new(".config/vpn-zones"), &granted));
        assert!(keeps_flags(Path::new("Games"), &granted));
        assert!(keeps_flags(Path::new("Games/deep"), &granted));
        assert!(!keeps_flags(Path::new(".ssh"), &granted));
        assert!(!keeps_flags(Path::new("Media"), &granted));
    }
}
