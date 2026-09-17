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
use std::path::PathBuf;

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

    Some(Container {
        name: name.to_owned(),
        home,
        network,
        apps,
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
