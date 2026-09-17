//! Containers as identities (`docs/CONTAINERS.md` §3).
//!
//! A container is a home, its permissions, its trusted certificates and ONE
//! network at a time. The homes already exist — a data container
//! (`vpn-profiles/<name>`, an overlay over the XDG directories) and a named
//! sandbox (`vpn-sandboxes/<name>`, a home of its own) — and this module adds
//! what makes them identities: the network a container is bound to, and the
//! programs assigned to it.
//!
//! **Where each value comes from is part of the value.** A setting can be
//! declared in Nix (home-manager writes it under
//! `~/.config/vpn-zones/declared/containers/`, read-only), set locally from the
//! CLI or the GUI (`container.conf` in the container's own directory, the
//! picker's `.pinnedprofile`), or be the default. A declared value wins, and the
//! local tools refuse to change it instead of failing on a read-only file —
//! and a configuration tool reading `vpn-zone status --json` has to know which
//! values it would be fighting the module over.
//!
//! **The file format is ours and flat**: `key = value` lines, `#` comments,
//! repeated keys for lists. Nix writes it, the CLI writes it, a human can read
//! it, and there is no parser to pull in for it.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::cli::{read_setting, visible_entries};
use crate::profile::proc_is_alive;
use crate::registry;
use crate::tools::Tools;

/// The local settings of a container, in its own directory.
pub const FILE: &str = "container.conf";
/// Where home-manager puts the declared containers, below the config dir.
pub const DECLARED: &str = "declared/containers";
/// The prefix of a named sandbox's selector.
pub const SANDBOX_PREFIX: &str = "sb:";
/// The directories granted to a private home, one per line.
pub const PATHS_FILE: &str = "paths";

/// Where a value comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Declared in the home-manager module: read-only here.
    Nix,
    /// Set with the CLI, the GUI or the picker.
    Local,
    /// Nobody set it.
    Default,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nix => "nix",
            Self::Local => "local",
            Self::Default => "default",
        }
    }
}

/// A value and its origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sourced<T> {
    pub value: T,
    pub source: Source,
}

/// What kind of home a container has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Home {
    /// A layer over the XDG directories of the real home: `vpn-profiles`.
    Overlay,
    /// A home of its own: a named sandbox, `vpn-sandboxes`.
    Private,
}

impl Home {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Overlay => "overlay",
            Self::Private => "private",
        }
    }
}

/// The network a container is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Network {
    /// Not bound: the network is asked on every launch, as before containers
    /// had one. What every existing container starts as.
    Ask,
    /// A network by name: a zone, `direct` or `offline`.
    Named(String),
}

impl Network {
    /// `ask`, or a name that could be a network. Anything with a path
    /// separator or whitespace in it cannot be one.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.is_empty() || text.contains(['/', ' ', '\t', '\n']) || text.starts_with(['-', '.'])
        {
            return None;
        }
        Some(if text == "ask" {
            Self::Ask
        } else {
            Self::Named(text.to_owned())
        })
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Ask => "ask",
            Self::Named(name) => name,
        }
    }

    /// May a launch into `zone` use a container bound to this network?
    pub fn accepts(&self, zone: &str) -> bool {
        match self {
            Self::Ask => true,
            Self::Named(name) => name == zone,
        }
    }
}

/// One container, with the origin of every setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    pub name: String,
    pub home: Home,
    pub network: Sourced<Network>,
    pub apps: Vec<Sourced<String>>,
    /// Directories of trusted certificates declared in Nix: built by the module
    /// (one `<sha256>.pem` each, checked for CA:TRUE at build time), read-only.
    pub declared_trust: Vec<PathBuf>,
    /// Directories of the real home granted to a private home
    /// (`docs/CONTAINERS.md` §3.5): declared ones first.
    pub paths: Vec<Sourced<PathBuf>>,
    /// The container's own directory. May not exist yet for a container that
    /// is only declared.
    pub dir: PathBuf,
}

impl Container {
    /// The selector the registry, the pins and `vpn-zone run` use.
    pub fn selector(&self) -> String {
        selector_of(self.home, &self.name)
    }

    pub fn trust_dir(&self) -> PathBuf {
        self.dir.join(crate::trust::DIR)
    }
}

/// `work` for a data container, `sb:work` for a named sandbox.
pub fn selector_of(home: Home, name: &str) -> String {
    match home {
        Home::Overlay => name.to_owned(),
        Home::Private => format!("{SANDBOX_PREFIX}{name}"),
    }
}

/// A selector back into its home and name. `None` for everything that is not a
/// container: the main profile, a throwaway sandbox or container, an empty
/// string.
pub fn parse_selector(selector: &str) -> Option<(Home, &str)> {
    let (home, name) = match selector.strip_prefix(SANDBOX_PREFIX) {
        Some(name) => (Home::Private, name),
        None => (Home::Overlay, selector),
    };
    let reserved = matches!(name, "" | "__main__" | "__fs__" | "__tmp__")
        || name.starts_with("tmpjoin:")
        || name.contains('/')
        || name.starts_with(['-', '.']);
    (!reserved).then_some((home, name))
}

/// `key = value` lines, in order. Comments (`#`) and lines without `=` are
/// skipped; keys and values are trimmed; a key may repeat.
pub fn parse_conf(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

fn values<'a>(conf: &'a [(String, String)], key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    conf.iter()
        .filter(move |(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// The file a declared container lives in: `overlay-<name>.conf` or
/// `private-<name>.conf`.
pub fn declared_file(tools: &Tools, home: Home, name: &str) -> PathBuf {
    tools
        .config
        .join(DECLARED)
        .join(format!("{}-{name}.conf", home.as_str()))
}

fn home_dir_of(tools: &Tools, home: Home, name: &str) -> PathBuf {
    match home {
        Home::Overlay => tools.profiles.join(name),
        Home::Private => tools.sandboxes.join(name),
    }
}

/// Read one container. `None` when it neither exists on disk nor is declared.
pub fn load(tools: &Tools, selector: &str) -> Option<Container> {
    let (home, name) = parse_selector(selector)?;
    let dir = home_dir_of(tools, home, name);
    let declared = fs::read_to_string(declared_file(tools, home, name))
        .map(|t| parse_conf(&t))
        .ok();
    if !dir.is_dir() && declared.is_none() {
        return None;
    }
    let local = fs::read_to_string(dir.join(FILE))
        .map(|t| parse_conf(&t))
        .unwrap_or_default();

    let network = declared
        .as_ref()
        .and_then(|conf| values(conf, "network").last().and_then(Network::parse))
        .map(|value| Sourced {
            value,
            source: Source::Nix,
        })
        .or_else(|| {
            values(&local, "network")
                .last()
                .and_then(Network::parse)
                .map(|value| Sourced {
                    value,
                    source: Source::Local,
                })
        })
        .unwrap_or(Sourced {
            value: Network::Ask,
            source: Source::Default,
        });

    let selector = selector_of(home, name);
    let mut apps: Vec<Sourced<String>> = Vec::new();
    if let Some(conf) = &declared {
        for app in values(conf, "app") {
            apps.push(Sourced {
                value: app.to_owned(),
                source: Source::Nix,
            });
        }
    }
    // The picker's container pins are the local assignments.
    for file in visible_entries(&tools.state.join(".pinnedprofile")) {
        let Some(key) = file.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        if read_setting(&file).as_deref() == Some(selector.as_str())
            && !apps.iter().any(|a| a.value == key)
        {
            apps.push(Sourced {
                value: key,
                source: Source::Local,
            });
        }
    }

    let declared_trust = declared
        .as_ref()
        .map(|conf| values(conf, "trust").map(PathBuf::from).collect())
        .unwrap_or_default();

    let mut paths: Vec<Sourced<PathBuf>> = Vec::new();
    if let Some(conf) = &declared {
        for path in values(conf, "path") {
            paths.push(Sourced {
                value: expand_home(&tools.home, path),
                source: Source::Nix,
            });
        }
    }
    if let Ok(text) = fs::read_to_string(dir.join(PATHS_FILE)) {
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let value = expand_home(&tools.home, line);
            if !paths.iter().any(|p| p.value == value) {
                paths.push(Sourced {
                    value,
                    source: Source::Local,
                });
            }
        }
    }

    Some(Container {
        name: name.to_owned(),
        home,
        network,
        apps,
        declared_trust,
        paths,
        dir,
    })
}

/// Every container: the data containers and named sandboxes on disk, and the
/// declared ones that have no directory yet. Sorted by selector.
pub fn load_all(tools: &Tools) -> Vec<Container> {
    let mut selectors: Vec<String> = Vec::new();
    for (dir, home) in [
        (&tools.profiles, Home::Overlay),
        (&tools.sandboxes, Home::Private),
    ] {
        for entry in visible_entries(dir) {
            if entry.is_dir() {
                let name = entry
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                selectors.push(selector_of(home, &name));
            }
        }
    }
    for file in visible_entries(&tools.config.join(DECLARED)) {
        let name = file
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let Some(stem) = name.strip_suffix(".conf") else {
            continue;
        };
        let parsed = stem
            .strip_prefix("overlay-")
            .map(|n| (Home::Overlay, n))
            .or_else(|| stem.strip_prefix("private-").map(|n| (Home::Private, n)));
        if let Some((home, name)) = parsed {
            selectors.push(selector_of(home, name));
        }
    }
    selectors.sort();
    selectors.dedup();
    selectors.iter().filter_map(|s| load(tools, s)).collect()
}

/// `~/x` against the home; anything else as it is.
pub fn expand_home(home: &Path, path: &str) -> PathBuf {
    match path.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None if path == "~" => home.to_path_buf(),
        None => PathBuf::from(path),
    }
}

/// `.` and `..` folded away without touching the filesystem.
pub fn lexical(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// A path as the filesystem resolves it, including a part that does not exist
/// yet: the deepest existing ancestor canonicalized, the rest appended as
/// written. `None` when not even `/` resolves.
///
/// A grant is checked this way BEFORE its directory is created — creating it
/// first would already have written through a symlink into wherever it
/// points.
pub fn resolved(path: &Path) -> Option<PathBuf> {
    let path = lexical(path);
    let existing = path.ancestors().find(|a| fs::symlink_metadata(a).is_ok())?;
    let rest = path.strip_prefix(existing).ok()?;
    Some(fs::canonicalize(existing).ok()?.join(rest))
}

/// Where a granted directory may be at all, besides the home: the places
/// removable and additional disks are mounted.
pub const GRANT_ROOTS: [&str; 4] = ["/mnt", "/media", "/run/media", "/srv"];

/// Why a directory may not be granted to a private home, if it may not.
///
/// A grant widens what a sandboxed program sees, on purpose — but only to
/// data. So it is an allow-list, not a list of dangers: below the home, or
/// below [`GRANT_ROOTS`]. Everything else is where the walls of the sandbox
/// are — `/run/user` has the D-Bus socket the filter exists for and the
/// compositor's, `/tmp` the X11 sockets, `/etc` the resolver the zone replaces
/// — and a list of those would be one socket short sooner or later.
///
/// Below the home, never the state of this project: `~/.local/state/vpn-zones`
/// holds the private key of every zone, the other three hold every container's
/// data and the pins that decide where programs run. Nor the home itself: that
/// is the `home` permission, asked for in words, not a path grant.
///
/// Lexical: the caller checks the resolved path as well, since a symlink is
/// followed by bwrap.
pub fn forbidden_path(home: &Path, path: &Path) -> Option<String> {
    if !path.is_absolute() {
        return Some("нужен абсолютный путь или ~/…".to_owned());
    }
    let path = lexical(path);
    if home.starts_with(&path) {
        return Some(
            "это весь дом или то, что выше него, — для этого есть разрешение home".to_owned(),
        );
    }
    if !path.starts_with(home) {
        let data_disk = GRANT_ROOTS
            .iter()
            .any(|root| path.starts_with(root) && path.as_path() != Path::new(root));
        return (!data_disk).then(|| {
            format!(
                "выдаются только каталоги дома и дисков ({}): в остальных местах стены песочницы",
                GRANT_ROOTS.join(", ")
            )
        });
    }
    for protected in [
        ".local/state/vpn-zones",
        ".local/state/vpn-profiles",
        ".local/state/vpn-sandboxes",
        ".config/vpn-zones",
    ] {
        let protected = home.join(protected);
        if path.starts_with(&protected) || protected.starts_with(&path) {
            return Some(format!(
                "там состояние vpn-zones ({}): ключи зон и данные контейнеров",
                protected.display()
            ));
        }
    }
    None
}

/// Grant a directory to a private home, or take the grant back.
pub fn set_path(tools: &Tools, selector: &str, path: &str, grant: bool) -> Result<PathBuf, String> {
    let container = load(tools, selector).ok_or_else(|| format!("контейнера {selector} нет"))?;
    if container.home != Home::Private {
        return Err(format!(
            "{selector} — слой над домом: ему и так виден весь настоящий дом, выдавать нечего"
        ));
    }
    let value = expand_home(&tools.home, path);
    if grant {
        // As written and as resolved: fs-sandbox checks both
        // again at every launch, this is only the early, readable refusal.
        let real = resolved(&value);
        let real_home = fs::canonicalize(&tools.home).unwrap_or_else(|_| tools.home.clone());
        let why = forbidden_path(&tools.home, &value)
            .or_else(|| real.as_ref().and_then(|r| forbidden_path(&real_home, r)))
            .or_else(|| {
                // The directories this installation really uses, when they are
                // not the default ones fs-sandbox knows.
                [
                    &tools.state,
                    &tools.profiles,
                    &tools.sandboxes,
                    &tools.config,
                ]
                .into_iter()
                .find(|dir| {
                    let near = |p: &Path| p.starts_with(dir) || dir.starts_with(p);
                    near(lexical(&value).as_path()) || real.as_deref().is_some_and(near)
                })
                .map(|dir| format!("там состояние vpn-zones ({})", dir.display()))
            });
        if let Some(why) = why {
            return Err(format!("{} выдать нельзя: {why}", value.display()));
        }
    } else if container
        .paths
        .iter()
        .any(|p| p.value == value && p.source == Source::Nix)
    {
        return Err(format!("{} выдан в Nix — забирается там", value.display()));
    }
    let file = container.dir.join(PATHS_FILE);
    let mut lines: Vec<String> = fs::read_to_string(&file)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && expand_home(&tools.home, l) != value)
        .map(str::to_owned)
        .collect();
    if grant {
        lines.push(value.to_string_lossy().into_owned());
    }
    fs::create_dir_all(&container.dir)
        .and_then(|()| {
            fs::write(
                &file,
                lines.join("\n") + if lines.is_empty() { "" } else { "\n" },
            )
        })
        .map_err(|e| format!("не записать {}: {e}", file.display()))?;
    Ok(value)
}

/// What a merge did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MergeReport {
    /// Files, links and directories copied into a place that was free.
    pub copied: usize,
    /// Entries that were in both, kept aside under `conflicts_dirs`.
    pub conflicts: usize,
    /// Sockets, pipes, devices — an overlay whiteout is a device too.
    pub skipped: usize,
    /// Where the conflicting entries went: one directory per home, or per
    /// overlay slot.
    pub conflicts_dirs: Vec<PathBuf>,
    /// Programs moved from one container to the other.
    pub apps: usize,
    /// Certificates `<into>` did not have before.
    pub new_certificates: Vec<String>,
}

/// Merge `<from>` into `<into>` (`docs/CONTAINERS.md` §3.4).
///
/// The rules, each for a reason: only containers of one kind (a layer and a
/// home of its own do not merge into each other); nothing declared in Nix (the
/// module would put it back); nothing while either runs (files in use, and
/// I2); a path `<into>` already has is never overwritten — the one from
/// `<from>` goes to `.merged-from-<from>/`, because merging two browser
/// profiles is not a decision a tool can make; certificates new to `<into>`
/// need `allow_new_certificates` (the caller shows the warning); permissions are
/// not copied at all — a wider set is asked for, never inherited; `<from>` is
/// kept, without programs, until it is deleted by hand.
pub fn merge(
    tools: &Tools,
    from: &str,
    into: &str,
    allow_new_certificates: bool,
) -> Result<MergeReport, String> {
    let a = load(tools, from).ok_or_else(|| format!("контейнера {from} нет"))?;
    let b = load(tools, into).ok_or_else(|| format!("контейнера {into} нет"))?;
    if a.selector() == b.selector() {
        return Err("это один и тот же контейнер".to_owned());
    }
    if a.home != b.home {
        return Err(format!(
            "{from} и {into} — разные виды дома (слой над домом и свой дом): такие не объединяются"
        ));
    }
    for c in [&a, &b] {
        if declared_file(tools, c.home, &c.name).exists() {
            return Err(format!(
                "{} объявлен в Nix — объединяй в конфигурации",
                c.selector()
            ));
        }
        if let Some(busy) = running_network(tools, c) {
            return Err(format!(
                "программы контейнера {} работают (в сети {busy}) — закрой их",
                c.selector()
            ));
        }
    }

    let known: Vec<String> = crate::trust::stored(&b.trust_dir())
        .into_iter()
        .map(|c| c.sha256)
        .collect();
    let incoming: Vec<crate::trust::Stored> = crate::trust::stored(&a.trust_dir())
        .into_iter()
        .filter(|c| !known.contains(&c.sha256))
        .collect();
    if !incoming.is_empty() && !allow_new_certificates {
        return Err(format!(
            "у {from} есть корневые сертификаты, которых нет у {into} ({}): объединение сделает их \
             доверенными для программ {into} — подтверди флагом --yes",
            incoming.len()
        ));
    }

    let mut report = MergeReport::default();
    let pairs: Vec<(PathBuf, PathBuf)> = match a.home {
        Home::Private => vec![(a.dir.join("home"), b.dir.join("home"))],
        Home::Overlay => fs::read_dir(&a.dir)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.join("upper").is_dir())
                    .map(|slot| {
                        let name = slot.file_name().unwrap_or_default().to_owned();
                        (slot.join("upper"), b.dir.join(name).join("upper"))
                    })
                    .collect()
            })
            .unwrap_or_default(),
    };
    for (src, dst) in pairs {
        if !src.is_dir() {
            continue;
        }
        fs::create_dir_all(&dst).map_err(|e| format!("не создать {}: {e}", dst.display()))?;
        let conflicts = fresh_aside(&dst, &a.name);
        merge_tree(&src, &dst, &conflicts, &mut report)
            .map_err(|e| format!("не удалось перенести {}: {e}", src.display()))?;
        if fs::symlink_metadata(&conflicts).is_ok() {
            report.conflicts_dirs.push(conflicts);
        }
    }

    for cert in &incoming {
        let dir = b.trust_dir();
        fs::create_dir_all(&dir)
            .and_then(|()| fs::copy(&cert.path, dir.join(format!("{}.pem", cert.sha256))))
            .map_err(|e| format!("не перенести сертификат {}: {e}", cert.sha256))?;
        report.new_certificates.push(cert.sha256.clone());
    }

    // The programs follow: their pins, and the picker's memory of the last
    // choice so that it does not offer the emptied container first.
    for (sub, counts) in [(".pinnedprofile", true), (".lastprofile", false)] {
        for file in visible_entries(&tools.state.join(sub)) {
            if read_setting(&file).as_deref() == Some(a.selector().as_str())
                && fs::write(&file, b.selector()).is_ok()
                && counts
            {
                report.apps += 1;
            }
        }
    }
    Ok(report)
}

/// A name for the conflicts directory that nothing has taken yet.
///
/// Never an existing one: a program of `<into>` can create any name in its own
/// home, a symlink to `~/.ssh` included, and the merge runs outside the
/// sandbox — writing into a planted path would carry files of one container
/// past the walls of the other. A fresh directory has only what the merge
/// itself creates below it.
fn fresh_aside(dst: &Path, from: &str) -> PathBuf {
    let base = format!(".merged-from-{from}");
    let mut candidate = dst.join(&base);
    let mut n = 2;
    while fs::symlink_metadata(&candidate).is_ok() {
        candidate = dst.join(format!("{base}-{n}"));
        n += 1;
    }
    candidate
}

/// Copy `src` into `dst` where `dst` has nothing; what `dst` already has goes
/// to the same relative place under `aside` instead.
///
/// Nothing is followed: a symlink is copied as a symlink, and a symlink in
/// `dst` is a taken name, not a directory to descend into — the two homes
/// belong to programs, and a link planted in one must not lead the merge
/// anywhere else.
pub fn merge_tree(
    src: &Path,
    dst: &Path,
    aside: &Path,
    report: &mut MergeReport,
) -> io::Result<()> {
    let mut names: Vec<PathBuf> = fs::read_dir(src)?.flatten().map(|e| e.path()).collect();
    names.sort();
    for from in names {
        let Some(name) = from.file_name().map(|n| n.to_owned()) else {
            continue;
        };
        let to = dst.join(&name);
        let kind = fs::symlink_metadata(&from)?.file_type();
        let taken = fs::symlink_metadata(&to);
        if kind.is_dir() {
            match taken {
                Err(_) => copy_tree(&from, &to, report)?,
                Ok(meta) if meta.file_type().is_dir() => {
                    merge_tree(&from, &to, &aside.join(&name), report)?
                }
                Ok(_) => {
                    copy_tree(&from, &aside.join(&name), report)?;
                    report.conflicts += 1;
                }
            }
        } else if kind.is_file() || kind.is_symlink() {
            if taken.is_err() {
                copy_one(&from, &to, kind.is_symlink())?;
                report.copied += 1;
            } else {
                fs::create_dir_all(aside)?;
                copy_one(&from, &aside.join(&name), kind.is_symlink())?;
                report.conflicts += 1;
            }
        } else {
            report.skipped += 1;
        }
    }
    Ok(())
}

fn copy_tree(src: &Path, dst: &Path, report: &mut MergeReport) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    report.copied += 1;
    for entry in fs::read_dir(src)?.flatten() {
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let kind = fs::symlink_metadata(&from)?.file_type();
        if kind.is_dir() {
            copy_tree(&from, &to, report)?;
        } else if kind.is_file() || kind.is_symlink() {
            copy_one(&from, &to, kind.is_symlink())?;
            report.copied += 1;
        } else {
            report.skipped += 1;
        }
    }
    Ok(())
}

fn copy_one(from: &Path, to: &Path, symlink: bool) -> io::Result<()> {
    if symlink {
        std::os::unix::fs::symlink(fs::read_link(from)?, to)
    } else {
        fs::copy(from, to).map(|_| ())
    }
}

/// The container a program is assigned to in Nix, if any.
pub fn declared_owner(tools: &Tools, app: &str) -> Option<String> {
    load_all(tools).into_iter().find_map(|c| {
        c.apps
            .iter()
            .any(|a| a.value == app && a.source == Source::Nix)
            .then(|| c.selector())
    })
}

/// Bind a container to a network (or unbind it with `ask`), locally.
///
/// Refused when the network is declared in Nix — the module would put it back
/// on the next switch — and when programs of the container are running in
/// another network right now: a process cannot be moved, and a container in
/// two networks at once is exactly what binding exists to prevent
/// (`docs/CONTAINERS.md` I2).
pub fn set_network(tools: &Tools, selector: &str, network: &Network) -> Result<(), String> {
    let container = load(tools, selector).ok_or_else(|| format!("контейнера {selector} нет"))?;
    if container.network.source == Source::Nix {
        return Err(format!(
            "сеть контейнера {selector} задана в Nix ({}) — меняется там",
            container.network.value.as_str()
        ));
    }
    if let (Network::Named(net), Some(busy)) = (network, running_network(tools, &container)) {
        if &busy != net {
            return Err(format!(
                "программы контейнера {selector} сейчас работают в сети {busy} — закрой их, \
                 потом меняй сеть"
            ));
        }
    }
    fs::create_dir_all(&container.dir)
        .map_err(|e| format!("не создать {}: {e}", container.dir.display()))?;
    let path = container.dir.join(FILE);
    let mut conf: Vec<(String, String)> = fs::read_to_string(&path)
        .map(|t| parse_conf(&t))
        .unwrap_or_default();
    conf.retain(|(k, _)| k != "network");
    if *network != Network::Ask {
        conf.push(("network".to_owned(), network.as_str().to_owned()));
    }
    let mut text = String::from(
        "# Локальные настройки контейнера vpn-zones (docs/CONTAINERS.md).\n\
         # Пишет `vpn-zone container`; значения из Nix лежат в ~/.config/vpn-zones/declared.\n",
    );
    for (k, v) in &conf {
        text.push_str(&format!("{k} = {v}\n"));
    }
    fs::write(&path, text).map_err(|e| format!("не записать {}: {e}", path.display()))
}

/// The network the container's programs run in right now, if any: the first
/// live registry record of any of its programs.
///
/// A data container has a registry directory of its own. A named sandbox
/// launches with no data container, so its records live under `__main__` and
/// are told apart by the selector field.
pub fn running_network(tools: &Tools, container: &Container) -> Option<String> {
    let running = tools.state.join(".running");
    match container.home {
        Home::Overlay => registry::live_zone(&running.join(&container.name), &proc_is_alive),
        Home::Private => registry::live_zone_of_selector(
            &running.join(registry::MAIN),
            &container.selector(),
            &proc_is_alive,
        ),
    }
}

/// The container a launch uses, as a selector: a named sandbox wins (its home is
/// what the program sees), otherwise a named data container.
pub fn selector_of_launch(profile: Option<&str>, sandbox: Option<&str>) -> Option<String> {
    match (sandbox, profile) {
        (Some(sb), _) => Some(selector_of(Home::Private, sb)),
        (None, Some(p)) => Some(selector_of(Home::Overlay, p)),
        (None, None) => None,
    }
}

/// Why a launch into `zone` may not use this container, or `None` when it may.
///
/// The two invariants of `docs/CONTAINERS.md`: a container bound to a network
/// runs in that network only (I1), and a container never runs in two networks
/// at once (I2).
pub fn refusal(container: &Container, zone: &str, running: Option<&str>) -> Option<String> {
    let selector = container.selector();
    if !container.network.value.accepts(zone) {
        let bound = container.network.value.as_str();
        let how = if container.network.source == Source::Nix {
            "сеть задана в Nix и меняется там".to_owned()
        } else {
            format!("сменить сеть контейнера: vpn-zone container set {selector} network {zone}")
        };
        return Some(format!(
            "контейнер «{selector}» работает в сети «{bound}», а запуск просит «{zone}». \
             Одна личность — одна сеть: {how}"
        ));
    }
    match running {
        Some(busy) if busy != zone => Some(format!(
            "программы контейнера «{selector}» уже работают в сети «{busy}», а запуск просит \
             «{zone}». Контейнер не бывает в двух сетях сразу: закрой его программы или запусти \
             в «{busy}»"
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_name_containers_and_nothing_else() {
        assert_eq!(parse_selector("work"), Some((Home::Overlay, "work")));
        assert_eq!(parse_selector("sb:work"), Some((Home::Private, "work")));
        assert_eq!(
            parse_selector("sb:app-firefox"),
            Some((Home::Private, "app-firefox"))
        );
        for not_one in [
            "",
            "__main__",
            "__fs__",
            "__tmp__",
            "tmpjoin:/tmp/x",
            "sb:",
            "a/b",
            "-x",
            ".x",
        ] {
            assert_eq!(parse_selector(not_one), None, "{not_one}");
        }
        assert_eq!(selector_of(Home::Private, "work"), "sb:work");
    }

    #[test]
    fn networks_parse_and_decide() {
        assert_eq!(Network::parse("ask"), Some(Network::Ask));
        assert_eq!(Network::parse(" nl \n"), Some(Network::Named("nl".into())));
        for bad in ["", "a/b", "a b", "-x", ".x"] {
            assert_eq!(Network::parse(bad), None, "{bad}");
        }
        assert!(Network::Ask.accepts("anything"));
        assert!(Network::Named("nl".into()).accepts("nl"));
        assert!(!Network::Named("nl".into()).accepts("direct"));
    }

    #[test]
    fn the_conf_format_is_flat_lines() {
        let conf =
            parse_conf("# comment\nnetwork = nl\n\napp=firefox\napp = tg \nno equals\n = x\n");
        assert_eq!(
            conf,
            vec![
                ("network".to_owned(), "nl".to_owned()),
                ("app".to_owned(), "firefox".to_owned()),
                ("app".to_owned(), "tg".to_owned()),
            ]
        );
        assert_eq!(values(&conf, "app").collect::<Vec<_>>(), ["firefox", "tg"]);
    }

    fn container(network: Network, source: Source) -> Container {
        Container {
            name: "work".into(),
            home: Home::Private,
            network: Sourced {
                value: network,
                source,
            },
            apps: Vec::new(),
            declared_trust: Vec::new(),
            paths: Vec::new(),
            dir: PathBuf::from("/s/work"),
        }
    }

    #[test]
    fn a_bound_container_runs_in_its_network_only() {
        let c = container(Network::Named("nl".into()), Source::Local);
        assert_eq!(refusal(&c, "nl", None), None);
        let why = refusal(&c, "direct", None).unwrap();
        assert!(why.contains("«nl»") && why.contains("«direct»"), "{why}");
        assert!(
            why.contains("vpn-zone container set sb:work network direct"),
            "{why}"
        );
        // Declared in Nix: the way out is the module, not the CLI.
        let c = container(Network::Named("nl".into()), Source::Nix);
        assert!(refusal(&c, "direct", None)
            .unwrap()
            .contains("задана в Nix"));
    }

    #[test]
    fn a_container_is_never_in_two_networks_at_once() {
        let c = container(Network::Ask, Source::Default);
        assert_eq!(refusal(&c, "nl", None), None);
        assert_eq!(refusal(&c, "nl", Some("nl")), None);
        let why = refusal(&c, "de", Some("nl")).unwrap();
        assert!(why.contains("двух сетях"), "{why}");
    }

    #[test]
    fn the_state_of_this_project_is_never_granted() {
        let home = Path::new("/home/u");
        assert_eq!(forbidden_path(home, Path::new("/home/u/.wine")), None);
        assert_eq!(forbidden_path(home, Path::new("/mnt/games")), None);
        assert_eq!(forbidden_path(home, Path::new("/run/media/u/disk")), None);
        for bad in [
            "/home/u",
            "/home",
            "/",
            "/mnt",
            "/run/user/1000",
            "/run/user/1000/bus",
            "/tmp/.X11-unix",
            "/etc",
            "/nix/store",
            "/persist",
            "/mnt/../run/user",
            "/home/u/.local/state/vpn-zones",
            "/home/u/.local/state/vpn-zones/nl",
            "/home/u/.local/state",
            "/home/u/.config/vpn-zones/declared",
            "/home/u/.local/state/vpn-sandboxes/x/home",
            "/home/u/.wine/../.local/state/vpn-zones",
        ] {
            assert!(forbidden_path(home, Path::new(bad)).is_some(), "{bad}");
        }
        assert!(forbidden_path(home, Path::new("relative")).is_some());
        assert_eq!(expand_home(home, "~/.wine"), PathBuf::from("/home/u/.wine"));
        assert_eq!(expand_home(home, "/abs"), PathBuf::from("/abs"));
    }

    #[test]
    fn a_grant_is_resolved_before_anything_is_created() {
        let t = Tmp::new("resolved");
        let real = t.0.join("real");
        fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, t.0.join("link")).unwrap();
        let real = fs::canonicalize(&real).unwrap();
        assert_eq!(
            resolved(&t.0.join("link/not/yet")),
            Some(real.join("not/yet"))
        );
        assert!(!real.join("not").exists(), "resolving creates nothing");
        assert_eq!(resolved(&t.0.join("link/../real")), Some(real));
    }

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p =
                std::env::temp_dir().join(format!("vpn-zone-merge-{}-{tag}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_merge_copies_what_is_free_and_sets_aside_what_is_taken() {
        let t = Tmp::new("tree");
        let (src, dst) = (t.0.join("src"), t.0.join("dst"));
        fs::create_dir_all(src.join(".config/app")).unwrap();
        fs::create_dir_all(dst.join(".config/other")).unwrap();
        fs::write(src.join(".config/app/settings"), "from").unwrap();
        fs::write(src.join("both.txt"), "from").unwrap();
        fs::write(dst.join("both.txt"), "into").unwrap();
        fs::write(src.join("only-from.txt"), "from").unwrap();
        std::os::unix::fs::symlink("only-from.txt", src.join("link")).unwrap();
        // A directory in one and a file in the other is a conflict too.
        fs::create_dir_all(src.join("clash")).unwrap();
        fs::write(src.join("clash/inner"), "x").unwrap();
        fs::write(dst.join("clash"), "file").unwrap();

        let aside = dst.join(".merged-from-a");
        let mut report = MergeReport::default();
        merge_tree(&src, &dst, &aside, &mut report).unwrap();

        assert_eq!(
            fs::read_to_string(dst.join(".config/app/settings")).unwrap(),
            "from"
        );
        assert!(dst.join(".config/other").is_dir(), "what into had is kept");
        assert_eq!(fs::read_to_string(dst.join("both.txt")).unwrap(), "into");
        assert_eq!(fs::read_to_string(aside.join("both.txt")).unwrap(), "from");
        assert_eq!(
            fs::read_to_string(dst.join("only-from.txt")).unwrap(),
            "from"
        );
        assert_eq!(
            fs::read_link(dst.join("link")).unwrap(),
            PathBuf::from("only-from.txt")
        );
        assert_eq!(fs::read_to_string(dst.join("clash")).unwrap(), "file");
        assert_eq!(fs::read_to_string(aside.join("clash/inner")).unwrap(), "x");
        assert_eq!(report.conflicts, 2);
        assert!(report.copied >= 4, "{report:?}");
    }

    #[test]
    fn a_launch_uses_the_sandbox_over_the_data_container() {
        assert_eq!(
            selector_of_launch(Some("work"), Some("dev")).as_deref(),
            Some("sb:dev")
        );
        assert_eq!(
            selector_of_launch(Some("work"), None).as_deref(),
            Some("work")
        );
        assert_eq!(selector_of_launch(None, None), None);
    }
}
