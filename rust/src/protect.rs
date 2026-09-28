//! Paths of the real home no container writes (owner, 2026-09-29): what
//! the host runs or trusts — `zone::HOST_RUNS_IN_ZONES` and its startup
//! places, always — and what the person names besides: the repository of the
//! machine's configuration above all, whose next «Применить» (stillconf) is
//! root's (`cellward protect add ~/Configurations/…`, or
//! `programs.cellward.protect` in Nix).
//!
//! **Where it holds.** In every container that sees the real home — the
//! main home's instances and containers of the `main` home kind — and is
//! hermetic: a container with the host's session in reach starts anything on
//! the host anyway (`hermetic`), and one that may write what the host runs
//! (`host-files writable`) was let to. A path is covered read-only where it
//! exists when the container's instance comes up (`zone::protect_host_files`).
//!
//! **Given back.** A container given a path the person protects
//! (`cellward container grant <c> <path>`, or `paths` of its Nix
//! declaration) writes it — the path, a directory above it, or one below it.
//! From its instance's next start: a running one keeps what it came up
//! with. The places the host runs are never given this way.
//!
//! **Where it does not.** A name that does not exist yet is not covered —
//! a mount needs something to cover —, nor a symbolic link: a mount follows
//! it (home-manager's `~/.zshrc` in the home itself; `doctor` names such).

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use crate::container::Source;
use crate::tools::Tools;

/// The setting: a path a line, as the person wrote it (`~/…` or absolute).
pub const SETTING: &str = "protect";

/// A path of the list, below `home` — its home itself, and anything outside
/// it, are no such path — lexically: `..` resolved, nothing followed.
pub fn normalize(home: &Path, text: &str) -> Option<PathBuf> {
    let text = text.trim();
    if text.is_empty() || text.contains(['\n', '\r']) {
        return None;
    }
    let path = crate::container::lexical(&crate::container::expand_home(home, text));
    (path.starts_with(home) && path != home).then_some(path)
}

fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
}

/// The person's list: Nix's (`declared/protect`) and the local one, each
/// once, Nix's first.
pub fn listed(config: &Path, home: &Path) -> Vec<(PathBuf, Source)> {
    let mut out: Vec<(PathBuf, Source)> = Vec::new();
    let declared = config.join(crate::cli::DECLARED_DIR).join(SETTING);
    let sources = [
        (crate::declared::read(&declared).ok(), Source::Nix),
        (fs::read_to_string(config.join(SETTING)).ok(), Source::Local),
    ];
    for (text, source) in sources {
        for line in lines(text.as_deref().unwrap_or_default()) {
            if let Some(path) = normalize(home, line) {
                if !out.iter().any(|(p, _)| *p == path) {
                    out.push((path, source));
                }
            }
        }
    }
    out
}

/// Whether `path` touches what the person protects — at, below or above
/// a listed path: what a container of the real home may be given to write.
/// The places the host runs are not given this way: to a container that
/// sees them, only `host-files writable` does (`crate::hermetic`).
pub fn in_list(config: &Path, home: &Path, path: &Path) -> bool {
    let path = crate::container::lexical(path);
    listed(config, home)
        .iter()
        .any(|(p, _)| path.starts_with(p) || p.starts_with(&path))
}

/// Of the protected places `protected`, those a container given `given`
/// writes: a given path at or above one. And the given paths below one of
/// them, written through its cover.
pub fn lifted(protected: &[PathBuf], given: &[PathBuf]) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let lifted = protected
        .iter()
        .filter(|p| given.iter().any(|g| p.starts_with(g)))
        .cloned()
        .collect();
    let through = given
        .iter()
        .filter(|g| protected.iter().any(|p| g.starts_with(p) && *g != p))
        .cloned()
        .collect();
    (lifted, through)
}

const USAGE: &str = "cellward protect — что из настоящего дома не пишет ни один контейнер\n\
                     cellward protect add <путь> — защитить ещё (репозиторий конфигурации…)\n\
                     cellward protect rm <путь> — снять свою защиту (заданную в Nix — там)";

/// `cellward protect [add|rm <path>]`.
pub fn run(tools: &Tools, args: &[OsString]) -> u8 {
    let args: Vec<&str> = args.iter().map(|a| a.to_str().unwrap_or("")).collect();
    let (add, text) = match args.as_slice() {
        [] => {
            print!("{}", shown(tools));
            return 0;
        }
        ["add", text] => (true, *text),
        ["rm", text] => (false, *text),
        _ => {
            eprintln!("{USAGE}");
            return 1;
        }
    };
    let Some(path) = normalize(&tools.home, text) else {
        eprintln!(
            "cellward protect: «{text}» — не путь внутри дома ({})",
            tools.home.display()
        );
        return 1;
    };
    let now = listed(&tools.config, &tools.home);
    if !add && now.iter().any(|(p, s)| *p == path && *s == Source::Nix) {
        eprintln!(
            "cellward protect: {} защищён в Nix (programs.cellward.protect) — снимается там",
            path.display()
        );
        return 1;
    }
    let file = tools.config.join(SETTING);
    let mut local: Vec<String> = fs::read_to_string(&file)
        .map(|t| lines(&t).map(str::to_owned).collect())
        .unwrap_or_default();
    local.retain(|l| normalize(&tools.home, l).as_ref() != Some(&path));
    if add {
        local.push(path.to_string_lossy().into_owned());
    }
    let text: String = local.iter().map(|l| format!("{l}\n")).collect();
    let written = fs::create_dir_all(&tools.config)
        .and_then(|()| fs::write(&file, text))
        .map_err(|e| format!("{}: {e}", file.display()));
    if let Err(e) = written {
        eprintln!("cellward protect: {e}");
        return 1;
    }
    println!(
        "{} {} — в контейнерах, поднятых после этого",
        path.display(),
        if add {
            "защищён: контейнеры его не пишут"
        } else {
            "больше не защищён"
        }
    );
    0
}

/// What `cellward protect` says.
fn shown(tools: &Tools) -> String {
    let mut out = String::from(
        "Не пишет ни один контейнер с настоящим домом (кроме того, кому выдан путь: \
         cellward container grant):\n",
    );
    for (path, source) in listed(&tools.config, &tools.home) {
        let from = match source {
            Source::Nix => " (Nix)",
            _ => "",
        };
        out.push_str(&format!("  {}{from}\n", path.display()));
    }
    out.push_str(
        "и всегда — то, что исполняет хост: автозапуск и службы, оболочки, git, \
         ~/bin и инструменты, конфигурации панелей, терминалов и редакторов\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_is_one_of_the_home() {
        let home = Path::new("/home/a");
        assert_eq!(
            normalize(home, "~/Configurations/x"),
            Some(PathBuf::from("/home/a/Configurations/x"))
        );
        assert_eq!(
            normalize(home, "/home/a/cfg/../repo"),
            Some(PathBuf::from("/home/a/repo"))
        );
        assert_eq!(normalize(home, "~"), None);
        assert_eq!(normalize(home, "/etc/nixos"), None);
        assert_eq!(normalize(home, "~/../b"), None);
        assert_eq!(normalize(home, ""), None);
    }

    #[test]
    fn a_grant_lifts_what_it_covers() {
        let protected = vec![
            PathBuf::from("/home/a/repo"),
            PathBuf::from("/home/a/.config/noctalia"),
        ];
        let given = vec![
            PathBuf::from("/home/a"),
            PathBuf::from("/home/a/.config/noctalia/colors"),
        ];
        let (lifted_all, through) = lifted(&protected, &given[..1]);
        assert_eq!(lifted_all, protected, "a grant of the home lifts all");
        assert!(through.is_empty());
        let (none, through) = lifted(&protected, &given[1..]);
        assert!(none.is_empty());
        assert_eq!(
            through,
            vec![PathBuf::from("/home/a/.config/noctalia/colors")]
        );
    }

    /// The person's list: a path a line, `~` or absolute, each once; a
    /// note and a path outside the home skipped. (Nix's — a link into the
    /// store — is the CLI test's.)
    #[test]
    fn the_list_is_read_as_written() {
        let root = std::env::temp_dir().join(format!("vz-protect-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let config = root.join("config");
        fs::create_dir_all(&config).unwrap();
        let home = Path::new("/home/a");
        fs::write(
            config.join(SETTING),
            "~/repo\n# a note\n/etc/x\n~/notes\n/home/a/repo\n",
        )
        .unwrap();
        assert_eq!(
            listed(&config, home),
            vec![
                (PathBuf::from("/home/a/repo"), Source::Local),
                (PathBuf::from("/home/a/notes"), Source::Local)
            ]
        );
        assert!(in_list(&config, home, Path::new("/home/a/repo/.git/hooks")));
        assert!(in_list(&config, home, Path::new("/home/a/notes")));
        assert!(!in_list(&config, home, Path::new("/home/a/.gitconfig")));
        assert!(!in_list(&config, home, Path::new("/home/a/Documents")));
        let _ = fs::remove_dir_all(&root);
    }
}
