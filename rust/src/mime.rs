//! A file's type as the desktop names it (`text/html`, `inode/directory`),
//! by its name, from shared-mime-info's `globs2` — the programs that open it
//! are the entries whose `MimeType` names that type (`crate::links`). No
//! content is read: a file a container offers is named, never parsed here.
//!
//! **Never opened**: what runs — an executable file (any `x` bit) or a type
//! that is a program, a script, a launcher or a package ([`runs`]). Opening
//! one would be starting it, which a request to open a file is not.

use std::fs;
use std::path::{Path, PathBuf};

/// The type of a directory.
pub const DIRECTORY: &str = "inode/directory";
/// The type of a file no glob names.
pub const UNKNOWN: &str = "application/octet-stream";

/// Where `globs2` is: `<data dir>/mime/globs2` for the user's data directory
/// and each of `XDG_DATA_DIRS`.
pub fn globs_files(home: &Path) -> Vec<PathBuf> {
    let mut dirs = vec![std::env::var_os("XDG_DATA_HOME")
        .filter(|v| !v.is_empty())
        .map_or_else(|| home.join(".local/share"), PathBuf::from)];
    let data = std::env::var_os("XDG_DATA_DIRS")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "/usr/local/share:/usr/share".into());
    dirs.extend(std::env::split_paths(&data).filter(|d| !d.as_os_str().is_empty()));
    dirs.into_iter().map(|d| d.join("mime/globs2")).collect()
}

/// Whether `glob` (of `globs2`: `*.ext`, a name, a pattern with `*` and
/// `?`) matches `name`, case left as the glob says unless `fold`.
fn matches(glob: &str, name: &str) -> bool {
    fn go(g: &[u8], n: &[u8]) -> bool {
        match (g.first(), n.first()) {
            (None, None) => true,
            (Some(b'*'), _) => go(&g[1..], n) || (!n.is_empty() && go(g, &n[1..])),
            (Some(b'?'), Some(_)) => go(&g[1..], &n[1..]),
            (Some(a), Some(b)) if a == b => go(&g[1..], &n[1..]),
            _ => false,
        }
    }
    // Character classes (`[...]`) are rare in globs2: such a glob is skipped.
    !glob.contains('[') && go(glob.as_bytes(), name.as_bytes())
}

/// The type of a file named `name` by the `globs2` texts: the match of the
/// greatest weight, then of the longest glob; [`UNKNOWN`] for none.
pub fn of_name(texts: &[String], name: &str) -> String {
    let lower = name.to_lowercase();
    let mut best: Option<(u32, usize, &str)> = None;
    for text in texts {
        for line in text.lines() {
            if line.starts_with('#') {
                continue;
            }
            let mut f = line.split(':');
            let (Some(weight), Some(kind), Some(glob)) = (f.next(), f.next(), f.next()) else {
                continue;
            };
            let flags = f.next().unwrap_or("");
            let Ok(weight) = weight.parse::<u32>() else {
                continue;
            };
            let case_sensitive = flags.split(',').any(|x| x == "cs");
            let hit = if case_sensitive {
                matches(glob, name)
            } else {
                matches(&glob.to_lowercase(), &lower)
            };
            if hit && best.is_none_or(|(w, l, _)| (weight, glob.len()) > (w, l)) {
                best = Some((weight, glob.len(), kind));
            }
        }
    }
    best.map_or(UNKNOWN.to_owned(), |(_, _, k)| k.to_owned())
}

/// The type of the file at `path` (its metadata already looked at: a
/// directory is [`DIRECTORY`]), by the system's `globs2`.
pub fn of_path(home: &Path, path: &Path, is_dir: bool) -> String {
    if is_dir {
        return DIRECTORY.to_owned();
    }
    let texts: Vec<String> = globs_files(home)
        .iter()
        .filter_map(|f| fs::read_to_string(f).ok())
        .collect();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    of_name(&texts, &name)
}

/// Whether a file of type `kind` runs rather than opens: a program, a
/// library, a script, a launcher, a package or an installer.
pub fn runs(kind: &str) -> bool {
    const RUNS: [&str; 22] = [
        "application/x-executable",
        "application/x-pie-executable",
        "application/x-sharedlib",
        "application/x-shellscript",
        "application/x-desktop",
        "application/x-ms-dos-executable",
        "application/x-msdownload",
        "application/x-msi",
        "application/vnd.microsoft.portable-executable",
        "application/vnd.appimage",
        "application/x-iso9660-appimage",
        "application/x-perl",
        "application/x-ruby",
        "application/x-php",
        "text/x-python",
        "text/x-python3",
        "application/x-python-bytecode",
        "application/x-java-archive",
        "application/x-java-jnlp-file",
        "application/vnd.flatpak.ref",
        "application/x-rpm",
        "application/vnd.debian.binary-package",
    ];
    RUNS.contains(&kind)
        || kind.ends_with("-script")
        || kind.starts_with("text/x-") && kind.ends_with("script")
}

#[cfg(test)]
mod tests {
    use super::*;

    const GLOBS: &str = "# comment\n\
        50:text/html:*.html\n\
        50:text/html:*.htm\n\
        50:application/x-shellscript:*.sh\n\
        50:text/plain:*.txt\n\
        55:application/x-compressed-tar:*.tar.gz\n\
        50:application/gzip:*.gz\n\
        50:text/x-readme:README*\n\
        50:application/x-desktop:*.desktop\n\
        60:text/x-makefile:Makefile:cs\n";

    #[test]
    fn a_files_type_is_its_best_glob() {
        let t = [GLOBS.to_owned()];
        assert_eq!(of_name(&t, "index.HTML"), "text/html");
        assert_eq!(of_name(&t, "a.tar.gz"), "application/x-compressed-tar");
        assert_eq!(of_name(&t, "a.gz"), "application/gzip");
        assert_eq!(of_name(&t, "README.md"), "text/x-readme");
        assert_eq!(of_name(&t, "Makefile"), "text/x-makefile");
        assert_eq!(of_name(&t, "makefile"), UNKNOWN, "case-sensitive glob");
        assert_eq!(of_name(&t, "noext"), UNKNOWN);
    }

    #[test]
    fn what_runs_is_never_opened() {
        for kind in [
            "application/x-executable",
            "application/x-shellscript",
            "application/x-desktop",
            "text/x-python",
            "application/x-csh-script",
            "text/x-tclscript",
        ] {
            assert!(runs(kind), "{kind}");
        }
        for kind in [
            "text/html",
            "image/png",
            "application/pdf",
            DIRECTORY,
            UNKNOWN,
        ] {
            assert!(!runs(kind), "{kind}");
        }
    }
}
