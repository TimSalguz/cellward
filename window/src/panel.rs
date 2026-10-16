//! `vpn-zone-window panel --cellward <cellward>
//! [--tab network|tasks|containers|zones|settings] [--dirs <kdialog>]` — the
//! cellward window (2026-09-28): the network monitor, the containers, the
//! zones and the settings, on the toolkit of the launch window, in place of
//! the chains of kdialog menus `cellward-gui` was.
//!
//! It keeps nothing of the project's and decides nothing: every second it
//! reads `cellward _panel` again (the contract is `rust/src/panel.rs` of
//! vpn-zones, repeated in [`parse`]), and it acts through `cellward`'s own
//! verbs — `container set … network`, `container stop`, `container grant`,
//! `container revoke`, `container merge`, `container rm` —, which check and
//! refuse as they do from a terminal; what they say is shown. `--dirs`: the
//! kdialog it chooses a directory to grant, or a zone's config, with — a
//! file dialog, not a menu.
//!
//! **Сеть**: what each running container sends and receives now (the
//! difference of two readings a second apart), since it came up, today and
//! over 30 days (`crate::traffic` of vpn-zones), each by its frame's colour;
//! and their latest connections — which program, to where (the name a DNS
//! answer gave), how much each way, how long ago (`crate::flows`,
//! `crate::owners`) — a tree since 2026-10-15: a program of a container,
//! and under it the sites it talks to, a site's names under it; each to be
//! blocked for that container (`container net <c> block <target>`) once the
//! person confirms, and what is blocked listed with the way back.
//! **Контейнеры**: the list, and for the one chosen its home, network and
//! state, its network to change (live, with a word on what that breaks,
//! when its programs run in another), its granted directories, and what
//! `cellward explain` says of its permissions; a new container.
//! **Зоны**: each zone up or down, its tunnel as the watch last found it,
//! locked or not — to bring up, down, restart, check, lock, cut off, remove;
//! a new zone from its config. **Настройки**: the network and the container
//! a program is first offered, the launchers' mode, the screen's and the
//! input's guard, and the programs pinned to a container, to forget.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

use iced::keyboard::{self, key, Key};
use iced::widget::{button, column, container, row, scrollable, text, text_input, tooltip};
use iced::{Alignment, Color, Element, Length, Size, Subscription, Task};

/// A container, as `cellward _panel` says it.
#[derive(Debug, Clone, Default, PartialEq)]
struct Cont {
    name: String,
    home: String,
    network: String,
    color: Option<Color>,
    /// Granted directories, with when they are taken back (0: never).
    paths: Vec<(String, u64)>,
}

#[derive(Debug, Clone, Default, PartialEq)]
struct Net {
    name: String,
    kind: String,
    up: bool,
    color: Option<Color>,
    locked: bool,
    /// What the tunnel watch last found: `alive`, `idle`, `dead`,
    /// `suspect`, `unknown`; `-` not looked at.
    tunnel: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Inst {
    id: String,
    container: String,
    network: String,
    out: u64,
    inb: u64,
    since: u64,
}

/// A connection of a running instance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Conn {
    instance: String,
    proto: String,
    remote: String,
    port: String,
    /// What a DNS answer said of the address; empty: none.
    name: String,
    /// The program that holds it; empty: none found.
    who: String,
    out: u64,
    inb: u64,
    last: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Use {
    container: String,
    network: String,
    out: u64,
    inb: u64,
}

/// A destination blocked for a container (`container net <c> block`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Block {
    container: String,
    /// A site, a name or an address, as it was blocked.
    target: String,
    /// `local`: blocked here, unblocked here; `nix`: declared in the
    /// configuration, changed there.
    source: String,
}

/// A launch of an instance, by its cgroup (`task`, `crate::tasks` of
/// vpn-zones).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TaskRow {
    instance: String,
    leaf: String,
    /// Its program, for a person; empty: not known.
    name: String,
    frozen: bool,
    rss_kib: u64,
    ticks: u64,
    hz: u64,
}

/// A process of a launch (`tproc`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ProcRow {
    instance: String,
    leaf: String,
    pid: u32,
    comm: String,
    rss_kib: u64,
    ticks: u64,
}

#[derive(Debug, Clone, Default, PartialEq)]
struct Data {
    tasks: Vec<TaskRow>,
    procs: Vec<ProcRow>,
    containers: Vec<Cont>,
    networks: Vec<Net>,
    instances: Vec<Inst>,
    flows: Vec<Conn>,
    /// What each program of each container used today: `(container,
    /// program, out, in)`.
    programs: Vec<(String, String, u64, u64)>,
    today: Vec<Use>,
    month: Vec<Use>,
    /// `(name, value, source)`.
    settings: Vec<(String, String, String)>,
    /// `(key, name, container)`.
    pins: Vec<(String, String, String)>,
    blocks: Vec<Block>,
}

fn color_of(hex: &str) -> Option<Color> {
    let hex = hex.strip_prefix('#')?;
    if hex.len() != 6 {
        return None;
    }
    let byte = |i: usize| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok();
    Some(Color::from_rgb8(byte(0)?, byte(2)?, byte(4)?))
}

/// `cellward _panel`'s lines (`rust/src/panel.rs` of vpn-zones); a line of
/// another shape is skipped.
fn parse(text: &str) -> Data {
    let mut d = Data::default();
    let num = |s: &str| s.parse::<u64>().unwrap_or(0);
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f.as_slice() {
            ["container", name, home, network, color] => d.containers.push(Cont {
                name: (*name).to_owned(),
                home: (*home).to_owned(),
                network: (*network).to_owned(),
                color: color_of(color),
                paths: Vec::new(),
            }),
            ["path", of, path, until] => {
                if let Some(c) = d.containers.iter_mut().find(|c| c.name == *of) {
                    c.paths.push(((*path).to_owned(), num(until)));
                }
            }
            ["network", name, kind, up, color, locked, tunnel] => d.networks.push(Net {
                name: (*name).to_owned(),
                kind: (*kind).to_owned(),
                up: *up == "1",
                color: color_of(color),
                locked: *locked == "1",
                tunnel: (*tunnel).to_owned(),
            }),
            ["setting", name, value, source] => d.settings.push((
                (*name).to_owned(),
                (*value).to_owned(),
                (*source).to_owned(),
            )),
            ["pin", key, name, to] => {
                d.pins
                    .push(((*key).to_owned(), (*name).to_owned(), (*to).to_owned()))
            }
            ["task", id, leaf, name, frozen, rss, ticks, hz] => d.tasks.push(TaskRow {
                instance: (*id).to_owned(),
                leaf: (*leaf).to_owned(),
                name: (*name).to_owned(),
                frozen: *frozen == "1",
                rss_kib: num(rss),
                ticks: num(ticks),
                hz: num(hz).max(1),
            }),
            ["tproc", id, leaf, pid, comm, rss, ticks] => d.procs.push(ProcRow {
                instance: (*id).to_owned(),
                leaf: (*leaf).to_owned(),
                pid: pid.parse().unwrap_or(0),
                comm: (*comm).to_owned(),
                rss_kib: num(rss),
                ticks: num(ticks),
            }),
            ["instance", id, of, network, out, inb, since] => d.instances.push(Inst {
                id: (*id).to_owned(),
                container: (*of).to_owned(),
                network: (*network).to_owned(),
                out: num(out),
                inb: num(inb),
                since: num(since),
            }),
            ["flow", id, proto, remote, port, name, who, out, inb, last] => d.flows.push(Conn {
                instance: (*id).to_owned(),
                proto: (*proto).to_owned(),
                remote: (*remote).to_owned(),
                port: (*port).to_owned(),
                name: (*name).to_owned(),
                who: (*who).to_owned(),
                out: num(out),
                inb: num(inb),
                last: num(last),
            }),
            ["program", of, name, out, inb] => {
                d.programs
                    .push(((*of).to_owned(), (*name).to_owned(), num(out), num(inb)))
            }
            ["block", of, target, source] => d.blocks.push(Block {
                container: (*of).to_owned(),
                target: (*target).to_owned(),
                source: (*source).to_owned(),
            }),
            [kind @ ("today" | "month"), of, network, out, inb] => {
                let u = Use {
                    container: (*of).to_owned(),
                    network: (*network).to_owned(),
                    out: num(out),
                    inb: num(inb),
                };
                if *kind == "today" {
                    d.today.push(u);
                } else {
                    d.month.push(u);
                }
            }
            _ => {}
        }
    }
    d
}

/// A count of bytes for a person: `crate::traffic::bytes_text` of vpn-zones.
fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// How long ago, for a person.
fn ago(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs} с назад"),
        60..=3599 => format!("{} мин назад", secs / 60),
        3600..=86399 => format!("{} ч назад", secs / 3600),
        _ => format!("{} дн назад", secs / 86400),
    }
}

/// Where a connection goes, for a person: the name its address was given,
/// or the address; the port where it has one.
fn destination(c: &Conn) -> String {
    let host = if c.name.is_empty() {
        &c.remote
    } else {
        &c.name
    };
    match c.proto.as_str() {
        "tcp" | "udp" if host.contains(':') => format!("[{host}]:{}", c.port),
        "tcp" | "udp" => format!("{host}:{}", c.port),
        _ => format!("{host} ({})", c.proto),
    }
}

/// Second levels under a country's domain that are no site of their own
/// (`bbc.co.uk`, `example.com.au`, `city.ac.jp`): a short list, not the
/// Public Suffix List — the tree groups by it and nothing else does. A site
/// it gets wrong is shown under a name too short or too long, and its block
/// blocks what the row says, no more.
const SECOND_LEVELS: [&str; 12] = [
    "ac", "co", "com", "edu", "go", "gov", "mil", "ne", "net", "nic", "or", "org",
];

/// The site a name is of — its registrable domain: the last two labels, the
/// last three under a two-letter country's generic second level. An
/// address, or a name of one or two labels, is itself.
fn site_of(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() {
        return host;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let n = labels.len();
    if n < 3 {
        return host;
    }
    let keep = if labels[n - 1].len() == 2 && SECOND_LEVELS.contains(&labels[n - 2]) {
        3
    } else {
        2
    };
    labels[n - keep..].join(".")
}

/// An address of no name, for a person: the address alone on the web's
/// own ports, else as [`destination`] says it.
fn address_text(c: &Conn) -> String {
    let web = matches!(c.proto.as_str(), "tcp" | "udp") && matches!(c.port.as_str(), "80" | "443");
    if web {
        c.remote.clone()
    } else {
        destination(c)
    }
}

/// One destination of a program's connections, summed over them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Dest {
    /// As shown.
    label: String,
    /// What blocking it blocks: the site, the name, the address.
    target: String,
    out: u64,
    inb: u64,
    /// The latest of its connections' last activity.
    last: u64,
    /// A site's names, when it has one other than itself.
    subs: Vec<Dest>,
}

impl Dest {
    fn total(&self) -> u64 {
        self.out.saturating_add(self.inb)
    }

    fn add(&mut self, c: &Conn) {
        self.out = self.out.saturating_add(c.out);
        self.inb = self.inb.saturating_add(c.inb);
        self.last = self.last.max(c.last);
    }
}

/// The entry of `all` shown as `label`, made if there is none.
fn dest_entry<'a>(all: &'a mut Vec<Dest>, label: &str, target: &str) -> &'a mut Dest {
    let at = match all.iter().position(|d| d.label == label) {
        Some(at) => at,
        None => {
            all.push(Dest {
                label: label.to_owned(),
                target: target.to_owned(),
                ..Dest::default()
            });
            all.len() - 1
        }
    };
    &mut all[at]
}

/// The most bytes first; equals by name, so that a reload does not
/// shuffle them.
fn by_bytes(all: &mut [Dest]) {
    all.sort_by(|a, b| {
        b.total()
            .cmp(&a.total())
            .then_with(|| a.label.cmp(&b.label))
    });
}

/// A program of a container, and where its connections go.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Group {
    /// What its fold is kept by across reloads: the container (an
    /// instance of none: its id) and the program.
    key: String,
    /// `-`: an instance of no container.
    container: String,
    /// One of its instances: its colour.
    instance: String,
    /// The program; empty: none found.
    who: String,
    out: u64,
    inb: u64,
    dests: Vec<Dest>,
}

impl Group {
    fn total(&self) -> u64 {
        self.out.saturating_add(self.inb)
    }
}

/// The connections as a tree: by container and program, the most bytes
/// first (one with none yet last), and under each its sites by bytes — a
/// site's names under it when it has others than itself; an address of no
/// name, a row of its own.
fn groups(d: &Data) -> Vec<Group> {
    let mut all: Vec<Group> = Vec::new();
    for c in &d.flows {
        let container = d
            .instances
            .iter()
            .find(|i| i.id == c.instance)
            .map_or("-", |i| i.container.as_str());
        let holder = if container == "-" {
            c.instance.as_str()
        } else {
            container
        };
        let key = format!("{holder}\t{}", c.who);
        let at = match all.iter().position(|g| g.key == key) {
            Some(at) => at,
            None => {
                all.push(Group {
                    key,
                    container: container.to_owned(),
                    instance: c.instance.clone(),
                    who: c.who.clone(),
                    ..Group::default()
                });
                all.len() - 1
            }
        };
        let g = &mut all[at];
        g.out = g.out.saturating_add(c.out);
        g.inb = g.inb.saturating_add(c.inb);
        if c.name.is_empty() {
            dest_entry(&mut g.dests, &address_text(c), &c.remote).add(c);
        } else {
            let name = c.name.trim_end_matches('.').to_ascii_lowercase();
            let site = site_of(&name);
            let s = dest_entry(&mut g.dests, &site, &site);
            s.add(c);
            dest_entry(&mut s.subs, &name, &name).add(c);
        }
    }
    for g in &mut all {
        for s in &mut g.dests {
            if s.subs.len() == 1 && s.subs[0].label == s.label {
                s.subs.clear();
            }
            by_bytes(&mut s.subs);
        }
        by_bytes(&mut g.dests);
    }
    all.sort_by(|a, b| {
        b.total()
            .cmp(&a.total())
            .then_with(|| a.who.is_empty().cmp(&b.who.is_empty()))
            .then_with(|| a.who.cmp(&b.who))
            .then_with(|| a.key.cmp(&b.key))
    });
    all
}

/// The container of the built-in «без изоляции» (`container::OPEN_RECORD`
/// of vpn-zones): nothing of its network is walled, nothing to block in it.
const OPEN: &str = "open";

/// A program's container, in words.
fn container_words(container: &str) -> String {
    match container {
        "-" => "без контейнера".to_owned(),
        OPEN => "без изоляции".to_owned(),
        // `picker::own_name` of vpn-zones.
        c if c.starts_with("app-") => "свой контейнер".to_owned(),
        c => format!("контейнер «{c}»"),
    }
}

/// Whether a destination can be blocked for a container: one with a name,
/// and not «без изоляции».
fn blockable(container: &str) -> bool {
    container != "-" && container != OPEN
}

/// A long name shortened in its middle: its start, and its end — the site.
fn shortened(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max || max < 16 {
        return s.to_owned();
    }
    let head: String = s.chars().take(10).collect();
    let tail: String = s.chars().skip(n - (max - 11)).collect();
    format!("{head}…{tail}")
}

/// Words of less weight — the tree's glyphs, a container in words, how long
/// ago: the text's own colour, fainter, in either theme.
fn dim(theme: &iced::Theme) -> text::Style {
    text::Style {
        color: Some(
            theme
                .extended_palette()
                .background
                .base
                .text
                .scale_alpha(0.6),
        ),
    }
}

fn rate(per_second: f64) -> String {
    format!("{}/с", bytes(per_second.max(0.0).round() as u64))
}

/// A home, for a person.
fn home_text(home: &str) -> &'static str {
    match home {
        "private" => "свой дом",
        "layer" => "слой над настоящим домом",
        "main" => "настоящий дом",
        _ => "?",
    }
}

/// A network, for a person.
fn network_text(network: &str) -> String {
    match network {
        "ask" => "спрашивать при запуске".to_owned(),
        "offline" => "без сети".to_owned(),
        "unconfined" => "без изоляции и без VPN".to_owned(),
        "host" => "сеть хоста (без VPN)".to_owned(),
        zone => format!("VPN: {zone}"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Network,
    Tasks,
    Containers,
    Zones,
    Settings,
}

const TABS: [Tab; 5] = [
    Tab::Network,
    Tab::Tasks,
    Tab::Containers,
    Tab::Zones,
    Tab::Settings,
];

/// A launch's name for the person: its program's, else its cgroup's.
fn task_name(t: &TaskRow) -> String {
    if t.name.is_empty() {
        format!("запуск {}", t.leaf)
    } else {
        t.name.clone()
    }
}

/// KiB as MiB, for a person.
fn mib(kib: u64) -> String {
    format!("{} МБ", kib.div_ceil(1024))
}

/// The name a zone made of this config is offered: the file's without
/// `.conf`, anything but letters, digits, `_` and `-` a dash —
/// `gui::suggested_zone_name` of vpn-zones.
fn zone_name_of(conf: &str) -> String {
    let base = conf.rsplit('/').next().unwrap_or(conf);
    let base = base.strip_suffix(".conf").unwrap_or(base);
    base.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// A tunnel, for a person.
fn tunnel_text(net: &Net) -> String {
    let state = if net.up {
        "поднята"
    } else {
        "опущена"
    };
    let tunnel = match net.tunnel.as_str() {
        "alive" => " · туннель жив",
        "idle" => " · туннель молчит (без трафика)",
        "dead" => " · туннель не отвечает",
        "throttled" => " · похоже, душат",
        "suspect" => " · туннель под сомнением",
        "unknown" => " · туннель ещё не проверен",
        _ => "",
    };
    let lock = if net.locked { " · заперта" } else { "" };
    format!("{state}{tunnel}{lock}")
}

/// What waits for the person's word before it is done.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Pending {
    /// Its programs run in another network: switch now, or with a restart.
    Switch(String),
    /// A directory chosen: for how long.
    Grant(String),
    /// Merge into which one.
    Merge,
    /// Merge into this one, the person agreeing.
    MergeInto(String),
    /// And to the other's root certificates (`container merge --yes`).
    MergeCertificates(String, String),
    Remove,
    /// A zone to cut off: its programs killed at once.
    Kill(String),
    /// Launches to end, every process of each: `(instance, launch, name)`.
    EndTasks(Vec<(String, String, String)>),
    /// A zone to remove, its config's copy with it.
    RemoveZone(String),
    /// A zone to make of this config, by this name.
    AddZone {
        conf: String,
        name: String,
    },
    /// A container to make.
    NewContainer {
        name: String,
        home: &'static str,
    },
    /// Every program's pin forgotten.
    ForgetAll,
    /// A destination blocked for a container: asked on its row first — a
    /// program cut off from a site by a stray click is worse than a click
    /// more.
    Block {
        container: String,
        target: String,
    },
}

#[derive(Debug, Clone)]
enum Msg {
    Tab(Tab),
    Tick,
    Loaded(Result<String, String>),
    Select(String),
    Explained(String, Result<String, String>),
    SetNetwork(String),
    Switch(bool),
    Stop,
    GrantAsk,
    Chosen(Option<String>),
    GrantFor(&'static str),
    Revoke(String),
    MergeAsk,
    MergeInto(String),
    MergeGo,
    MergeCertificatesGo,
    RemoveAsk,
    RemoveGo,
    Cancel,
    Done(Result<String, String>),
    MergeDone(String, Result<String, String>),
    Escape,
    /// ←/→: the tab before or after.
    TabStep(i32),
    /// ↑/↓ in the containers: the one before or after the chosen one.
    Step(i32),
    /// The choice that is already made, pressed: nothing — it is shown
    /// bright, as chosen, and not as a button that cannot be pressed.
    Nothing,
    /// `cellward <verb> <zone>`: up, down, restart, check, lock, unlock.
    ZoneDo(String, &'static str),
    KillAsk(String),
    KillGo,
    RemoveZoneAsk(String),
    RemoveZoneGo,
    AddZoneAsk,
    ConfChosen(Option<String>),
    ZoneName(String),
    AddZoneGo,
    NewContainerAsk,
    NewName(String),
    NewHome(&'static str),
    NewContainerGo,
    /// `cellward <setting> <value>`.
    SetSetting(&'static str, String),
    Forget(String),
    ForgetAllAsk,
    ForgetAllGo,
    /// A program's row in the connections, folded or unfolded (its key).
    Fold(String),
    /// A site's row, its names shown or not (its program's key and the site).
    FoldSite(String),
    /// A program's every destination shown, or the first ones only.
    Whole(String),
    /// `(container, target)`: to block, asked first.
    BlockAsk(String, String),
    BlockGo,
    /// `(container, target)`.
    Unblock(String, String),
    /// A launch clicked: chosen alone, or added to (Ctrl) the chosen.
    TaskPick(String, String),
    /// A launch's processes shown or not.
    TaskOpen(String, String),
    /// `cellward tasks pause|resume` of every chosen launch.
    TasksDo(&'static str),
    TasksEndAsk,
    TasksEndGo,
    /// Space and Delete, outside a field.
    TasksSpace,
    TasksDelete,
    Modifiers(keyboard::Modifiers),
}

struct Panel {
    cellward: PathBuf,
    dirs: Option<PathBuf>,
    tab: Tab,
    data: Data,
    /// The last reading of each instance, and when it was taken.
    last: HashMap<String, (u64, u64, u64, Instant)>,
    /// What each instance sends and receives now, per second.
    rates: HashMap<String, (f64, f64)>,
    selected: Option<String>,
    explained: Option<(String, Result<String, String>)>,
    pending: Option<Pending>,
    /// What the last action said: `Ok` done, `Err` refused.
    said: Option<Result<String, String>>,
    /// An action runs: nothing else is started meanwhile.
    busy: bool,
    /// What reading `cellward _panel` said, when it failed.
    trouble: Option<String>,
    /// The connections' tree as the person left it, by [`Group::key`]
    /// (sites: the key, a tab, the site) — kept across the reloads, which
    /// make the tree anew every second: programs folded, sites unfolded,
    /// programs with every destination shown.
    folded: HashSet<String>,
    unfolded: HashSet<String>,
    whole: HashSet<String>,
    /// The last reading of each launch's and each process's CPU ticks, and
    /// what they used since the one before, in percent of a core.
    task_ticks: HashMap<(String, String), (u64, Instant)>,
    task_cpu: HashMap<(String, String), f64>,
    proc_ticks: HashMap<u32, (u64, Instant)>,
    proc_cpu: HashMap<u32, f64>,
    /// The launches chosen, and those whose processes are shown.
    picked: HashSet<(String, String)>,
    opened: HashSet<(String, String)>,
    ctrl: bool,
}

/// Run `cellward <args>` off the window's threads; its output, or why not.
async fn cellward(path: PathBuf, args: Vec<String>) -> Result<String, String> {
    let (done, over) = iced::futures::channel::oneshot::channel();
    std::thread::spawn(move || {
        let result = match Command::new(&path)
            .args(&args)
            .stdin(Stdio::null())
            .output()
        {
            Ok(out) => {
                let said = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                )
                .trim()
                .to_owned();
                if out.status.success() {
                    Ok(said)
                } else {
                    Err(said)
                }
            }
            Err(e) => Err(format!("cellward не запустился: {e}")),
        };
        let _ = done.send(result);
    });
    over.await
        .unwrap_or_else(|_| Err("cellward не ответил".to_owned()))
}

/// `cellward` once for each command line, in turn, while each is done: what
/// they said, or at the first refusal what it said.
async fn cellward_all(path: PathBuf, all: Vec<Vec<String>>) -> Result<String, String> {
    let mut said = Vec::new();
    for args in all {
        match cellward(path.clone(), args).await {
            Ok(t) => said.push(t),
            Err(t) => {
                said.push(t);
                return Err(said.join("\n").trim().to_owned());
            }
        }
    }
    Ok(said.join("\n").trim().to_owned())
}

/// A zone's config to make a zone of, chosen in the file dialog of `dirs`.
fn choose_conf(dirs: PathBuf) -> Task<Msg> {
    Task::perform(
        async move {
            let (done, over) = iced::futures::channel::oneshot::channel();
            std::thread::spawn(move || {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_owned());
                let chosen = Command::new(&dirs)
                    .args([
                        "--title",
                        "Конфиг VPN",
                        "--getopenfilename",
                        home.as_str(),
                        "*.conf|Конфигурация WireGuard, AmneziaWG, OpenConnect (*.conf)",
                    ])
                    .stdin(Stdio::null())
                    .stderr(Stdio::null())
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
                    .filter(|d| !d.is_empty());
                let _ = done.send(chosen);
            });
            over.await.ok().flatten()
        },
        Msg::ConfChosen,
    )
}

/// `cellward _panel`: its lines — a line of anything else it says is
/// skipped by [`parse`].
fn load(path: PathBuf) -> Task<Msg> {
    Task::perform(cellward(path, vec!["_panel".to_owned()]), Msg::Loaded)
}

/// `Msg::Tick` a second from now: slept on a thread of its own, as the
/// launch window's guard is (`arm_after`) — never on the executor's pool,
/// which carries the input.
fn tick_later() -> Task<Msg> {
    Task::perform(
        async {
            let (done, over) = iced::futures::channel::oneshot::channel();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(1));
                let _ = done.send(());
            });
            let _ = over.await;
        },
        |()| Msg::Tick,
    )
}

/// A directory to grant, chosen in the file dialog of `dirs` (kdialog);
/// `None` when none was.
fn choose_dir(dirs: PathBuf) -> Task<Msg> {
    Task::perform(
        async move {
            let (done, over) = iced::futures::channel::oneshot::channel();
            std::thread::spawn(move || {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_owned());
                let chosen = Command::new(&dirs)
                    .args([
                        "--title",
                        "Какой каталог выдать?",
                        "--getexistingdirectory",
                        home.as_str(),
                    ])
                    .stdin(Stdio::null())
                    .stderr(Stdio::null())
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
                    .filter(|d| !d.is_empty());
                let _ = done.send(chosen);
            });
            over.await.ok().flatten()
        },
        Msg::Chosen,
    )
}

impl Panel {
    fn new(cellward: PathBuf, dirs: Option<PathBuf>, tab: Tab) -> Self {
        Self {
            cellward,
            dirs,
            tab,
            data: Data::default(),
            last: HashMap::new(),
            rates: HashMap::new(),
            selected: None,
            explained: None,
            pending: None,
            said: None,
            busy: false,
            trouble: None,
            folded: HashSet::new(),
            unfolded: HashSet::new(),
            whole: HashSet::new(),
            task_ticks: HashMap::new(),
            task_cpu: HashMap::new(),
            proc_ticks: HashMap::new(),
            proc_cpu: HashMap::new(),
            picked: HashSet::new(),
            opened: HashSet::new(),
            ctrl: false,
        }
    }

    /// CPU use of each launch and process since the reading before, in
    /// percent of a core: the ticks between two readings.
    fn count_cpu(&mut self, data: &Data, now: Instant) {
        let pct = |ticks: u64, was: Option<&(u64, Instant)>, hz: u64| {
            was.and_then(|(t, at)| {
                let dt = now.duration_since(*at).as_secs_f64();
                (dt > 0.2).then(|| ticks.saturating_sub(*t) as f64 / hz as f64 / dt * 100.0)
            })
        };
        let hz = data.tasks.first().map_or(100, |t| t.hz);
        let mut ticks = HashMap::new();
        let mut cpu = HashMap::new();
        for t in &data.tasks {
            let key = (t.instance.clone(), t.leaf.clone());
            if let Some(c) = pct(t.ticks, self.task_ticks.get(&key), t.hz) {
                cpu.insert(key.clone(), c);
            }
            ticks.insert(key, (t.ticks, now));
        }
        self.task_ticks = ticks;
        self.task_cpu = cpu;
        let mut ticks = HashMap::new();
        let mut cpu = HashMap::new();
        for p in &data.procs {
            if let Some(c) = pct(p.ticks, self.proc_ticks.get(&p.pid), hz) {
                cpu.insert(p.pid, c);
            }
            ticks.insert(p.pid, (p.ticks, now));
        }
        self.proc_ticks = ticks;
        self.proc_cpu = cpu;
        // A launch gone: not chosen any more.
        let alive: HashSet<(String, String)> = data
            .tasks
            .iter()
            .map(|t| (t.instance.clone(), t.leaf.clone()))
            .collect();
        self.picked.retain(|k| alive.contains(k));
        self.opened.retain(|k| alive.contains(k));
    }

    /// The launches chosen, in the order they are shown, with their names.
    fn picked_sorted(&self) -> Vec<(String, String, String)> {
        self.data
            .tasks
            .iter()
            .filter(|t| self.picked.contains(&(t.instance.clone(), t.leaf.clone())))
            .map(|t| (t.instance.clone(), t.leaf.clone(), task_name(t)))
            .collect()
    }

    fn chosen(&self) -> Option<&Cont> {
        let name = self.selected.as_deref()?;
        self.data.containers.iter().find(|c| c.name == name)
    }

    /// The instance a container runs in now, if it runs.
    fn running(&self, name: &str) -> Option<&Inst> {
        self.data.instances.iter().find(|i| i.container == name)
    }

    fn act(&mut self, args: Vec<String>) -> Task<Msg> {
        self.busy = true;
        self.said = None;
        self.pending = None;
        Task::perform(cellward(self.cellward.clone(), args), Msg::Done)
    }

    /// What `cellward explain` says of the container `name`: in the
    /// network it runs in, or is bound to; one that asks on every launch and
    /// runs nowhere has none to be explained in — said so.
    fn explain(&self, name: String) -> Task<Msg> {
        let asks = self
            .data
            .containers
            .iter()
            .any(|c| c.name == name && c.network == "ask");
        let mut args = vec!["explain".to_owned(), name.clone()];
        match self.running(&name) {
            Some(i) => args.push(i.network.clone()),
            None if asks => {
                return Task::done(Msg::Explained(
                    name,
                    Ok(
                        "Сеть спрашивают при запуске, а разрешения зависят от сети: выбери сеть \
                        контейнера выше — или запусти его — и они будут здесь."
                            .to_owned(),
                    ),
                ))
            }
            None => {}
        }
        let path = self.cellward.clone();
        Task::perform(cellward(path, args), move |r| {
            Msg::Explained(name.clone(), r)
        })
    }

    fn update(&mut self, msg: Msg) -> Task<Msg> {
        match msg {
            Msg::Tab(tab) => {
                self.tab = tab;
                // A block asked on the network's tab is not left waiting
                // behind another.
                if matches!(self.pending, Some(Pending::Block { .. })) {
                    self.pending = None;
                }
                Task::none()
            }
            Msg::Fold(key) => {
                if !self.folded.remove(&key) {
                    self.folded.insert(key);
                }
                Task::none()
            }
            Msg::FoldSite(key) => {
                if !self.unfolded.remove(&key) {
                    self.unfolded.insert(key);
                }
                Task::none()
            }
            Msg::Whole(key) => {
                if !self.whole.remove(&key) {
                    self.whole.insert(key);
                }
                Task::none()
            }
            Msg::BlockAsk(container, target) => {
                if !self.busy {
                    self.said = None;
                    self.pending = Some(Pending::Block { container, target });
                }
                Task::none()
            }
            Msg::BlockGo => match self.pending.clone() {
                Some(Pending::Block { container, target }) => self.act(vec![
                    "container".into(),
                    "net".into(),
                    container,
                    "block".into(),
                    target,
                ]),
                _ => Task::none(),
            },
            Msg::Unblock(container, target) => self.act(vec![
                "container".into(),
                "net".into(),
                container,
                "unblock".into(),
                target,
            ]),
            Msg::Tick => load(self.cellward.clone()),
            Msg::Loaded(Ok(text)) => {
                let now = Instant::now();
                let data = parse(&text);
                let mut last = HashMap::new();
                let mut rates = HashMap::new();
                for i in &data.instances {
                    if let Some((out, inb, since, at)) = self.last.get(&i.id) {
                        let dt = now.duration_since(*at).as_secs_f64();
                        if *since == i.since && dt > 0.2 {
                            rates.insert(
                                i.id.clone(),
                                (
                                    i.out.saturating_sub(*out) as f64 / dt,
                                    i.inb.saturating_sub(*inb) as f64 / dt,
                                ),
                            );
                        }
                    }
                    last.insert(i.id.clone(), (i.out, i.inb, i.since, now));
                }
                self.last = last;
                self.rates = rates;
                self.count_cpu(&data, now);
                self.data = data;
                self.trouble = None;
                // A container gone: nothing chosen.
                if self.chosen().is_none() {
                    self.selected = None;
                }
                tick_later()
            }
            Msg::Loaded(Err(why)) => {
                self.trouble = Some(why);
                tick_later()
            }
            Msg::Select(name) => {
                self.selected = Some(name.clone());
                self.pending = None;
                self.said = None;
                self.explained = None;
                self.explain(name)
            }
            Msg::Explained(name, result) => {
                if self.selected.as_deref() == Some(name.as_str()) {
                    self.explained = Some((name, result));
                }
                Task::none()
            }
            Msg::SetNetwork(to) => {
                let Some(c) = self.chosen().cloned() else {
                    return Task::none();
                };
                let elsewhere = self
                    .running(&c.name)
                    .is_some_and(|i| i.network != to && to != "ask");
                if elsewhere {
                    self.pending = Some(Pending::Switch(to));
                    Task::none()
                } else {
                    self.act(vec![
                        "container".into(),
                        "set".into(),
                        c.name,
                        "network".into(),
                        to,
                    ])
                }
            }
            Msg::Switch(restart) => {
                let (Some(c), Some(Pending::Switch(to))) =
                    (self.chosen().cloned(), self.pending.clone())
                else {
                    return Task::none();
                };
                let mut args = vec![
                    "container".into(),
                    "set".into(),
                    c.name,
                    "network".into(),
                    to,
                ];
                if restart {
                    args.push("--restart".into());
                }
                args.push("--yes".into());
                self.act(args)
            }
            Msg::Stop => match self.chosen().cloned() {
                Some(c) => self.act(vec!["container".into(), "stop".into(), c.name]),
                None => Task::none(),
            },
            Msg::GrantAsk => match self.dirs.clone() {
                Some(dirs) => choose_dir(dirs),
                None => {
                    self.said = Some(Err(
                        "выбрать каталог нечем — в терминале: cellward container grant <контейнер> \
                         <каталог>"
                            .to_owned(),
                    ));
                    Task::none()
                }
            },
            Msg::Chosen(Some(dir)) => {
                self.pending = Some(Pending::Grant(dir));
                Task::none()
            }
            Msg::Chosen(None) => Task::none(),
            Msg::GrantFor(term) => {
                let (Some(c), Some(Pending::Grant(dir))) =
                    (self.chosen().cloned(), self.pending.clone())
                else {
                    return Task::none();
                };
                let mut args = vec!["container".into(), "grant".into(), c.name, dir];
                if term != "always" {
                    args.push("--for".into());
                    args.push(term.to_owned());
                }
                self.act(args)
            }
            Msg::Revoke(path) => match self.chosen().cloned() {
                Some(c) => self.act(vec!["container".into(), "revoke".into(), c.name, path]),
                None => Task::none(),
            },
            Msg::MergeAsk => {
                self.pending = Some(Pending::Merge);
                Task::none()
            }
            Msg::MergeInto(into) => {
                self.pending = Some(Pending::MergeInto(into));
                Task::none()
            }
            Msg::MergeGo => {
                let (Some(c), Some(Pending::MergeInto(into))) =
                    (self.chosen().cloned(), self.pending.clone())
                else {
                    return Task::none();
                };
                self.busy = true;
                self.said = None;
                self.pending = None;
                let args = vec!["container".into(), "merge".into(), c.name, into.clone()];
                Task::perform(cellward(self.cellward.clone(), args), move |r| {
                    Msg::MergeDone(into.clone(), r)
                })
            }
            Msg::MergeDone(into, Err(said)) if said.contains("--yes") => {
                self.busy = false;
                self.pending = Some(Pending::MergeCertificates(into, said));
                Task::none()
            }
            Msg::MergeDone(_, result) => self.update(Msg::Done(result)),
            Msg::MergeCertificatesGo => {
                let (Some(c), Some(Pending::MergeCertificates(into, _))) =
                    (self.chosen().cloned(), self.pending.clone())
                else {
                    return Task::none();
                };
                self.act(vec![
                    "container".into(),
                    "merge".into(),
                    c.name,
                    into,
                    "--yes".into(),
                ])
            }
            Msg::RemoveAsk => {
                self.pending = Some(Pending::Remove);
                Task::none()
            }
            Msg::RemoveGo => match self.chosen().cloned() {
                Some(c) => {
                    self.selected = None;
                    self.explained = None;
                    self.act(vec!["container".into(), "rm".into(), c.name])
                }
                None => Task::none(),
            },
            Msg::Cancel => {
                self.pending = None;
                Task::none()
            }
            Msg::Nothing => Task::none(),
            Msg::Done(result) => {
                self.busy = false;
                self.said = Some(result);
                let mut tasks = vec![load(self.cellward.clone())];
                if let Some(name) = self.selected.clone() {
                    tasks.push(self.explain(name));
                }
                Task::batch(tasks)
            }
            Msg::TabStep(by) => {
                if self.pending.is_some() {
                    return Task::none();
                }
                let at = TABS.iter().position(|t| *t == self.tab).unwrap_or(0) as i32;
                let next = (at + by).rem_euclid(TABS.len() as i32) as usize;
                self.tab = TABS[next];
                Task::none()
            }
            Msg::ZoneDo(zone, verb) => self.act(vec![verb.to_owned(), zone]),
            Msg::Modifiers(m) => {
                self.ctrl = m.control();
                Task::none()
            }
            Msg::TaskPick(instance, leaf) => {
                let key = (instance, leaf);
                if self.ctrl {
                    if !self.picked.remove(&key) {
                        self.picked.insert(key);
                    }
                } else {
                    self.picked = HashSet::from([key]);
                }
                Task::none()
            }
            Msg::TaskOpen(instance, leaf) => {
                let key = (instance, leaf);
                if !self.opened.remove(&key) {
                    self.opened.insert(key);
                }
                Task::none()
            }
            Msg::TasksDo(verb) => {
                let all: Vec<Vec<String>> = self
                    .picked_sorted()
                    .into_iter()
                    .map(|(i, l, _)| vec!["tasks".into(), verb.into(), i, l])
                    .collect();
                if all.is_empty() {
                    return Task::none();
                }
                self.busy = true;
                self.said = None;
                Task::perform(cellward_all(self.cellward.clone(), all), Msg::Done)
            }
            Msg::TasksEndAsk => {
                let picked = self.picked_sorted();
                if !picked.is_empty() {
                    self.pending = Some(Pending::EndTasks(picked));
                }
                Task::none()
            }
            Msg::TasksEndGo => match self.pending.take() {
                Some(Pending::EndTasks(all)) => {
                    self.busy = true;
                    self.said = None;
                    self.picked.clear();
                    let all = all
                        .into_iter()
                        .map(|(i, l, _)| vec!["tasks".into(), "kill".into(), i, l])
                        .collect();
                    Task::perform(cellward_all(self.cellward.clone(), all), Msg::Done)
                }
                other => {
                    self.pending = other;
                    Task::none()
                }
            },
            Msg::KillAsk(zone) => {
                self.pending = Some(Pending::Kill(zone));
                Task::none()
            }
            Msg::KillGo => match self.pending.clone() {
                Some(Pending::Kill(zone)) => self.act(vec!["kill".into(), zone]),
                _ => Task::none(),
            },
            Msg::RemoveZoneAsk(zone) => {
                self.pending = Some(Pending::RemoveZone(zone));
                Task::none()
            }
            Msg::RemoveZoneGo => match self.pending.clone() {
                Some(Pending::RemoveZone(zone)) => self.act(vec!["rm".into(), zone]),
                _ => Task::none(),
            },
            Msg::AddZoneAsk => match self.dirs.clone() {
                Some(dirs) => choose_conf(dirs),
                None => {
                    self.said = Some(Err(
                        "выбрать файл нечем — в терминале: cellward add <имя> <файл.conf>"
                            .to_owned(),
                    ));
                    Task::none()
                }
            },
            Msg::ConfChosen(Some(conf)) => {
                let name = zone_name_of(&conf);
                self.pending = Some(Pending::AddZone { conf, name });
                Task::none()
            }
            Msg::ConfChosen(None) => Task::none(),
            Msg::ZoneName(typed) => {
                if let Some(Pending::AddZone { name, .. }) = &mut self.pending {
                    *name = typed;
                }
                Task::none()
            }
            Msg::AddZoneGo => {
                let Some(Pending::AddZone { conf, name }) = self.pending.clone() else {
                    return Task::none();
                };
                self.busy = true;
                self.said = None;
                self.pending = None;
                let all = vec![
                    vec!["add".to_owned(), name.clone(), conf],
                    vec!["up".to_owned(), name],
                    vec!["sync".to_owned()],
                ];
                Task::perform(cellward_all(self.cellward.clone(), all), Msg::Done)
            }
            Msg::NewContainerAsk => {
                self.pending = Some(Pending::NewContainer {
                    name: String::new(),
                    home: "private",
                });
                Task::none()
            }
            Msg::NewName(typed) => {
                if let Some(Pending::NewContainer { name, .. }) = &mut self.pending {
                    *name = typed;
                }
                Task::none()
            }
            Msg::NewHome(which) => {
                if let Some(Pending::NewContainer { home, .. }) = &mut self.pending {
                    *home = which;
                }
                Task::none()
            }
            Msg::NewContainerGo => match self.pending.clone() {
                Some(Pending::NewContainer { name, home }) if !name.trim().is_empty() => {
                    self.act(vec![
                        "container".into(),
                        "create".into(),
                        name.trim().to_owned(),
                        "--home".into(),
                        home.to_owned(),
                    ])
                }
                _ => Task::none(),
            },
            Msg::SetSetting(name, value) => self.act(vec![name.to_owned(), value]),
            Msg::Forget(key) => self.act(vec!["forget".into(), key]),
            Msg::ForgetAllAsk => {
                self.pending = Some(Pending::ForgetAll);
                Task::none()
            }
            Msg::ForgetAllGo => self.act(vec!["forget".into(), "--all".into()]),
            Msg::Step(by) if self.tab == Tab::Tasks => {
                if self.pending.is_some() {
                    return Task::none();
                }
                let keys: Vec<(String, String)> = self
                    .data
                    .tasks
                    .iter()
                    .map(|t| (t.instance.clone(), t.leaf.clone()))
                    .collect();
                if keys.is_empty() {
                    return Task::none();
                }
                // From the last chosen, in the order shown.
                let at = keys.iter().rposition(|k| self.picked.contains(k));
                let next = match at {
                    None => 0,
                    Some(i) => (i as i64 + i64::from(by)).clamp(0, keys.len() as i64 - 1) as usize,
                };
                let key = keys[next].clone();
                if self.ctrl {
                    self.picked.insert(key);
                } else {
                    self.picked = HashSet::from([key]);
                }
                Task::none()
            }
            // Space: the chosen paused, or resumed where they all are paused.
            Msg::TasksSpace => {
                if self.tab != Tab::Tasks || self.pending.is_some() || self.busy {
                    return Task::none();
                }
                let all_paused = self
                    .data
                    .tasks
                    .iter()
                    .filter(|t| self.picked.contains(&(t.instance.clone(), t.leaf.clone())))
                    .all(|t| t.frozen);
                self.update(Msg::TasksDo(if all_paused { "resume" } else { "pause" }))
            }
            Msg::TasksDelete => {
                if self.tab != Tab::Tasks || self.busy {
                    return Task::none();
                }
                self.update(Msg::TasksEndAsk)
            }
            Msg::Step(by) => {
                if self.tab != Tab::Containers || self.pending.is_some() {
                    return Task::none();
                }
                let names: Vec<String> = self
                    .data
                    .containers
                    .iter()
                    .map(|c| c.name.clone())
                    .collect();
                if names.is_empty() {
                    return Task::none();
                }
                let at = self
                    .selected
                    .as_ref()
                    .and_then(|s| names.iter().position(|n| n == s));
                let next = match at {
                    None => 0,
                    Some(i) => (i as i64 + i64::from(by)).clamp(0, names.len() as i64 - 1) as usize,
                };
                self.update(Msg::Select(names[next].clone()))
            }
            Msg::Escape => {
                if self.pending.is_some() {
                    self.pending = None;
                    Task::none()
                } else {
                    std::process::exit(0)
                }
            }
        }
    }

    fn color_of_instance(&self, i: &Inst) -> Color {
        self.data
            .containers
            .iter()
            .find(|c| c.name == i.container)
            .and_then(|c| c.color)
            .or_else(|| {
                self.data
                    .networks
                    .iter()
                    .find(|n| n.name == i.network)
                    .and_then(|n| n.color)
            })
            .unwrap_or(Color::from_rgb8(0x88, 0x88, 0x88))
    }

    fn view(&self) -> Element<'_, Msg> {
        let tab = |label: &'static str, which: Tab| {
            button(text(label).size(15))
                .padding([6, 14])
                .style(if self.tab == which {
                    button::primary
                } else {
                    button::secondary
                })
                .on_press(Msg::Tab(which))
        };
        let note = self
            .trouble
            .as_deref()
            .map_or(String::new(), |t| format!("⚠ {t}"));
        let top = row![
            tab("Сеть", Tab::Network),
            tab("Задачи", Tab::Tasks),
            tab("Контейнеры", Tab::Containers),
            tab("Подключения", Tab::Zones),
            tab("Настройки", Tab::Settings),
            container(text(note).size(13)).width(Length::Fill),
            button(text("Закрыть  Esc").size(14))
                .padding([6, 14])
                .style(button::secondary)
                .on_press(Msg::Escape),
        ]
        .spacing(8)
        .align_y(Alignment::Center);
        let body = match self.tab {
            Tab::Network => self.view_network(),
            Tab::Tasks => self.view_tasks(),
            Tab::Containers => self.view_containers(),
            Tab::Zones => self.view_zones(),
            Tab::Settings => self.view_settings(),
        };
        let mut page = column![top].spacing(12).padding(16);
        // What the last action said, whichever tab it was in.
        if let Some(said) = &self.said {
            let (mark, what, color) = match said {
                Ok(t) => ("✓", t.as_str(), Color::from_rgb8(0x2e, 0x9d, 0x55)),
                Err(t) => ("⚠", t.as_str(), Color::from_rgb8(0xd0, 0x3a, 0x3a)),
            };
            let what = if what.is_empty() {
                "готово"
            } else {
                what
            };
            page = page.push(
                text(format!("{mark} {what}"))
                    .size(13)
                    .color(color)
                    .wrapping(iced::widget::text::Wrapping::WordOrGlyph),
            );
        }
        page.push(body).into()
    }

    fn use_rows<'a>(&'a self, title: &'a str, uses: &'a [Use]) -> Element<'a, Msg> {
        let mut block = column![text(title).size(17)].spacing(4);
        if uses.is_empty() {
            block = block.push(text("ничего не записано").size(13));
        }
        for u in uses {
            let color = self
                .data
                .containers
                .iter()
                .find(|c| c.name == u.container)
                .and_then(|c| c.color)
                .unwrap_or(Color::from_rgb8(0x88, 0x88, 0x88));
            block = block.push(
                row![
                    text("●").size(14).color(color),
                    text(u.container.as_str())
                        .size(14)
                        .width(Length::Fixed(260.0)),
                    text(network_text(&u.network))
                        .size(14)
                        .width(Length::Fixed(200.0)),
                    text(format!("↑ {}", bytes(u.out)))
                        .size(14)
                        .width(Length::Fixed(120.0)),
                    text(format!("↓ {}", bytes(u.inb))).size(14),
                ]
                .spacing(8),
            );
        }
        block.into()
    }

    fn view_network(&self) -> Element<'_, Msg> {
        let mut now = column![text("Сейчас").size(17)].spacing(4);
        if self.data.instances.is_empty() {
            now = now.push(text("ни один контейнер сейчас не работает").size(13));
        }
        for i in &self.data.instances {
            let (up, down) = self.rates.get(&i.id).copied().unwrap_or((0.0, 0.0));
            let who = if i.container == "-" {
                i.id.as_str()
            } else {
                i.container.as_str()
            };
            now = now.push(
                row![
                    text("●").size(14).color(self.color_of_instance(i)),
                    text(who).size(14).width(Length::Fixed(260.0)),
                    text(network_text(&i.network))
                        .size(14)
                        .width(Length::Fixed(200.0)),
                    text(format!("↑ {}", rate(up)))
                        .size(14)
                        .width(Length::Fixed(120.0)),
                    text(format!("↓ {}", rate(down)))
                        .size(14)
                        .width(Length::Fixed(120.0)),
                    text(format!("всего ↑ {} ↓ {}", bytes(i.out), bytes(i.inb))).size(13),
                ]
                .spacing(8),
            );
        }
        let page = column![
            now,
            self.view_flows(),
            self.view_programs(),
            self.use_rows("Сегодня", &self.data.today),
            self.use_rows("За 30 дней", &self.data.month),
        ]
        .push(self.view_blocks(None))
        .spacing(18);
        scrollable(page).height(Length::Fill).into()
    }

    /// What each program used today, the most first.
    fn view_programs(&self) -> Element<'_, Msg> {
        const SHOWN: usize = 20;
        let mut block = column![text("Программы сегодня").size(17)].spacing(4);
        if self.data.programs.is_empty() {
            block = block.push(text("ничего не записано").size(13));
        }
        let mut rows: Vec<_> = self.data.programs.iter().collect();
        rows.sort_by_key(|(_, _, o, i)| std::cmp::Reverse(o.saturating_add(*i)));
        for (of, name, out, inb) in rows.into_iter().take(SHOWN) {
            let color = self
                .data
                .containers
                .iter()
                .find(|c| c.name == *of)
                .and_then(|c| c.color)
                .unwrap_or(Color::from_rgb8(0x88, 0x88, 0x88));
            block = block.push(
                row![
                    text("●").size(14).color(color),
                    text(name.as_str()).size(14).width(Length::Fixed(260.0)),
                    text(of.as_str()).size(14).width(Length::Fixed(200.0)),
                    text(format!("↑ {}", bytes(*out)))
                        .size(14)
                        .width(Length::Fixed(120.0)),
                    text(format!("↓ {}", bytes(*inb))).size(14),
                ]
                .spacing(8),
            );
        }
        block.into()
    }

    /// Whether `target` is blocked for `container` already: itself, or a
    /// name it is under (a name's block takes its subdomains, `netrules`
    /// of vpn-zones). A network's block is not looked into: its addresses
    /// keep their ⊘, and the core says what is so.
    fn blocked(&self, container: &str, target: &str) -> bool {
        self.data.blocks.iter().any(|b| {
            b.container == container
                && (b.target == target
                    || target
                        .strip_suffix(b.target.as_str())
                        .is_some_and(|rest| rest.ends_with('.')))
        })
    }

    /// «Блокировать X для контейнера «c»?», on the row it was asked on.
    fn block_question(container_name: &str, target: &str) -> Element<'static, Msg> {
        container(
            row![
                text(format!(
                    "Блокировать {target} для контейнера «{container_name}»? Программы \
                     контейнера перестанут до него доходить."
                ))
                .size(13)
                .width(Length::Fill)
                .wrapping(iced::widget::text::Wrapping::WordOrGlyph),
                button(text("Блокировать").size(13))
                    .padding([4, 10])
                    .style(button::danger)
                    .on_press(Msg::BlockGo),
                button(text("Отмена  Esc").size(13))
                    .padding([4, 10])
                    .style(button::secondary)
                    .on_press(Msg::Cancel),
            ]
            .spacing(6)
            .align_y(Alignment::Center),
        )
        .padding(8)
        .width(Length::Fill)
        .style(container::bordered_box)
        .into()
    }

    /// A destination's row under its program: the tree's glyphs, its bytes
    /// each way, its name — a site's to unfold to its names —, how long ago,
    /// and its block.
    fn dest_row(
        &self,
        glyphs: String,
        fold: Option<(bool, Msg)>,
        d: &Dest,
        of: &str,
        now: u64,
        idle: bool,
    ) -> Element<'static, Msg> {
        let label = text(shortened(&d.label, 56))
            .size(14)
            .wrapping(iced::widget::text::Wrapping::Glyph);
        let name: Element<'static, Msg> = match fold {
            Some((open, msg)) => button(
                row![
                    text(if open { "▼" } else { "▶" })
                        .size(11)
                        .width(Length::Fixed(16.0)),
                    label,
                ]
                .align_y(Alignment::Center),
            )
            .padding(0)
            .width(Length::Fill)
            .style(button::text)
            .on_press(msg)
            .into(),
            None => row![iced::widget::space().width(Length::Fixed(16.0)), label]
                .width(Length::Fill)
                .into(),
        };
        let action: Element<'static, Msg> = if self.blocked(of, &d.target) {
            text("заблокировано").size(12).style(text::danger).into()
        } else if blockable(of) {
            tooltip(
                button(text("⊘").size(14))
                    .padding([0, 8])
                    .style(button::secondary)
                    .on_press_maybe(idle.then(|| Msg::BlockAsk(of.to_owned(), d.target.clone()))),
                container(text("Блокировать").size(12))
                    .padding([2, 6])
                    .style(container::rounded_box),
                tooltip::Position::Left,
            )
            .into()
        } else {
            iced::widget::space().into()
        };
        row![
            text(glyphs).size(14).width(Length::Fixed(44.0)).style(dim),
            text(format!("↓ {}", bytes(d.inb)))
                .size(13)
                .width(Length::Fixed(88.0)),
            text(format!("↑ {}", bytes(d.out)))
                .size(13)
                .width(Length::Fixed(88.0))
                .style(dim),
            name,
            text(ago(now.saturating_sub(d.last)))
                .size(12)
                .width(Length::Fixed(96.0))
                .style(dim),
            container(action)
                .width(Length::Fixed(96.0))
                .align_x(iced::alignment::Horizontal::Right),
        ]
        .spacing(6)
        .align_y(Alignment::Center)
        .into()
    }

    /// The connections of every running container as a tree: a program of
    /// a container — folded by a click on its row, and kept so across the
    /// reloads —, under it where it talks to, the most first, a site's
    /// names under the site; each to be blocked for the container, asked on
    /// its row first.
    fn view_flows(&self) -> Element<'_, Msg> {
        const SHOWN: usize = 15;
        let mut block = column![text("Соединения").size(17)].spacing(2);
        if self.data.flows.is_empty() {
            block = block.push(text("соединений не было").size(13));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let idle = !self.busy && self.pending.is_none();
        let asked = match &self.pending {
            Some(Pending::Block { container, target }) => Some((container, target)),
            _ => None,
        };
        let mut asked_shown = false;
        let mut tree = column![].spacing(4);
        for g in groups(&self.data) {
            let color = self
                .data
                .instances
                .iter()
                .find(|i| i.id == g.instance)
                .map_or(Color::from_rgb8(0x88, 0x88, 0x88), |i| {
                    self.color_of_instance(i)
                });
            let open = !self.folded.contains(&g.key);
            let who = if g.who.is_empty() {
                "неизвестная программа".to_owned()
            } else {
                g.who.clone()
            };
            tree = tree.push(
                row![
                    button(
                        row![
                            text(if open { "▼" } else { "▶" })
                                .size(11)
                                .width(Length::Fixed(14.0)),
                            text("●").size(14).color(color),
                            text(who).size(15),
                            text(format!("({})", container_words(&g.container)))
                                .size(13)
                                .style(dim),
                        ]
                        .spacing(8)
                        .align_y(Alignment::Center),
                    )
                    .padding([3, 4])
                    .width(Length::Fill)
                    .style(button::text)
                    .on_press(Msg::Fold(g.key.clone())),
                    text(format!("↓ {}", bytes(g.inb)))
                        .size(14)
                        .width(Length::Fixed(96.0)),
                    text(format!("↑ {}", bytes(g.out)))
                        .size(14)
                        .width(Length::Fixed(96.0)),
                ]
                .spacing(6)
                .align_y(Alignment::Center),
            );
            if !open {
                continue;
            }
            let whole = self.whole.contains(&g.key);
            let shown = if whole {
                g.dests.len()
            } else {
                g.dests.len().min(SHOWN)
            };
            let more = g.dests.len() > SHOWN;
            let mut children = column![].spacing(3);
            for (n, d) in g.dests.iter().take(shown).enumerate() {
                let last = n + 1 == shown && !more;
                let site_key = format!("{}\t{}", g.key, d.label);
                let unfolded = self.unfolded.contains(&site_key);
                let fold = (!d.subs.is_empty()).then_some((unfolded, Msg::FoldSite(site_key)));
                let glyph = if last { "└─" } else { "├─" };
                children = children.push(self.dest_row(
                    glyph.to_owned(),
                    fold,
                    d,
                    &g.container,
                    now,
                    idle,
                ));
                if !asked_shown && asked == Some((&g.container, &d.target)) {
                    asked_shown = true;
                    children = children.push(Self::block_question(&g.container, &d.target));
                }
                if !unfolded {
                    continue;
                }
                let stem = if last { "   " } else { "│  " };
                for (m, s) in d.subs.iter().enumerate() {
                    let glyph = if m + 1 == d.subs.len() {
                        "└─"
                    } else {
                        "├─"
                    };
                    children = children.push(self.dest_row(
                        format!("{stem}{glyph}"),
                        None,
                        s,
                        &g.container,
                        now,
                        idle,
                    ));
                    if !asked_shown && asked == Some((&g.container, &s.target)) {
                        asked_shown = true;
                        children = children.push(Self::block_question(&g.container, &s.target));
                    }
                }
            }
            if more {
                let label = if whole {
                    "свернуть".to_owned()
                } else {
                    format!("ещё {}…", g.dests.len() - SHOWN)
                };
                children = children.push(
                    row![
                        text("└─").size(14).width(Length::Fixed(44.0)).style(dim),
                        button(text(label).size(13))
                            .padding([1, 6])
                            .style(button::text)
                            .on_press(Msg::Whole(g.key.clone())),
                    ]
                    .spacing(6)
                    .align_y(Alignment::Center),
                );
            }
            tree = tree.push(container(children).padding(iced::Padding {
                left: 22.0,
                ..iced::Padding::ZERO
            }));
        }
        // Its row folded away, or gone with the reload: the question stays,
        // above the tree.
        if let (Some((of, target)), false) = (asked, asked_shown) {
            block = block.push(Self::block_question(of, target));
        }
        block.push(tree).into()
    }

    /// What is blocked: of the container `only`, or of every one with the
    /// container's name; none when nothing is.
    fn view_blocks(&self, only: Option<&str>) -> Option<Element<'_, Msg>> {
        let blocks: Vec<&Block> = self
            .data
            .blocks
            .iter()
            .filter(|b| only.is_none_or(|o| b.container == o))
            .collect();
        if blocks.is_empty() {
            return None;
        }
        let idle = !self.busy && self.pending.is_none();
        let mut block =
            column![text("Заблокировано").size(if only.is_some() { 16 } else { 17 })].spacing(4);
        for b in blocks {
            let mut line = row![].spacing(8).align_y(Alignment::Center);
            if only.is_none() {
                let color = self
                    .data
                    .containers
                    .iter()
                    .find(|c| c.name == b.container)
                    .and_then(|c| c.color)
                    .unwrap_or(Color::from_rgb8(0x88, 0x88, 0x88));
                line = line.push(text("●").size(14).color(color)).push(
                    text(b.container.as_str())
                        .size(14)
                        .width(Length::Fixed(200.0)),
                );
            }
            line = line.push(
                text(b.target.as_str())
                    .size(14)
                    .width(Length::Fill)
                    .wrapping(iced::widget::text::Wrapping::Glyph),
            );
            let undo: Element<'_, Msg> = if b.source == "nix" {
                text("задано в Nix").size(12).style(dim).into()
            } else {
                button(text("Разблокировать").size(13))
                    .padding([3, 8])
                    .style(button::secondary)
                    .on_press_maybe(
                        idle.then(|| Msg::Unblock(b.container.clone(), b.target.clone())),
                    )
                    .into()
            };
            block = block.push(line.push(undo));
        }
        Some(block.into())
    }

    fn view_containers(&self) -> Element<'_, Msg> {
        let mut list = column![].spacing(4);
        if self.data.containers.is_empty() {
            list = list.push(
                text("Контейнеров нет: их заводит окно запуска («Новый контейнер…»)").size(13),
            );
        }
        for c in &self.data.containers {
            let chosen = self.selected.as_deref() == Some(c.name.as_str());
            let running = if self.running(&c.name).is_some() {
                " ▶"
            } else {
                ""
            };
            list = list.push(
                button(
                    row![
                        text("●")
                            .size(14)
                            .color(c.color.unwrap_or(Color::from_rgb8(0x88, 0x88, 0x88))),
                        text(format!("{}{running}", c.name)).size(14),
                    ]
                    .spacing(6),
                )
                .width(Length::Fill)
                .padding([6, 10])
                .style(if chosen {
                    button::primary
                } else {
                    button::text
                })
                .on_press(Msg::Select(c.name.clone())),
            );
        }
        list = list.push(
            button(text("Новый контейнер…").size(13))
                .padding([4, 10])
                .style(button::secondary)
                .on_press_maybe((!self.busy).then_some(Msg::NewContainerAsk)),
        );
        let left = container(scrollable(list).height(Length::Fill)).width(Length::FillPortion(2));
        if let Some(block) = self.pending.as_ref().and_then(|p| self.view_general(p)) {
            return row![left, container(block).width(Length::FillPortion(5))]
                .spacing(16)
                .height(Length::Fill)
                .into();
        }
        let right = container(scrollable(self.view_chosen()).height(Length::Fill))
            .width(Length::FillPortion(5));
        row![left, right].spacing(16).height(Length::Fill).into()
    }

    fn view_chosen(&self) -> Element<'_, Msg> {
        let Some(c) = self.chosen() else {
            return text("Выбери контейнер слева").size(14).into();
        };
        let running = self.running(&c.name);
        let mut page = column![text(c.name.as_str()).size(20)].spacing(10);
        page = page.push(text(format!("Дом: {}", home_text(&c.home))).size(14));
        page = page.push(text(format!("Сеть: {}", network_text(&c.network))).size(14));
        page = page.push(
            text(match running {
                Some(i) => format!(
                    "Работает в сети «{}»: всего ↑ {} ↓ {}",
                    i.network,
                    bytes(i.out),
                    bytes(i.inb)
                ),
                None => "Не работает".to_owned(),
            })
            .size(14),
        );
        if let Some(pending) = &self.pending {
            if let Some(block) = self.view_pending(c, pending) {
                page = page.push(block);
                return page.into();
            }
        }
        let idle = !self.busy;
        // Its network.
        let mut nets = column![].spacing(4);
        let mut choices: Vec<(String, String)> = vec![("ask".into(), "Спрашивать".into())];
        for n in &self.data.networks {
            let label = match n.kind.as_str() {
                "offline" => "Без сети".to_owned(),
                "unconfined" => "Без изоляции и без VPN".to_owned(),
                "host" => "Сеть хоста (без VPN)".to_owned(),
                _ if n.up => n.name.clone(),
                _ => format!("{} (опущена)", n.name),
            };
            choices.push((n.name.clone(), label));
        }
        for (name, label) in choices {
            let current = c.network == name;
            nets = nets.push(
                button(text(label).size(13))
                    .padding([4, 10])
                    .style(if current {
                        button::primary
                    } else {
                        button::secondary
                    })
                    .on_press_maybe(if current {
                        Some(Msg::Nothing)
                    } else {
                        idle.then(|| Msg::SetNetwork(name.clone()))
                    }),
            );
        }
        page = page.push(text("Сеть контейнера").size(16));
        page = page.push(nets);
        // Its granted directories.
        if c.home != "main" {
            page = page.push(text("Выданные каталоги").size(16));
            if c.paths.is_empty() {
                page = page.push(text("нет").size(13));
            }
            for (path, until) in &c.paths {
                let term = if *until == 0 {
                    String::new()
                } else {
                    " (на срок)".to_owned()
                };
                page = page.push(
                    row![
                        text(format!("{path}{term}")).size(13).width(Length::Fill),
                        button(text("Забрать").size(13))
                            .padding([3, 8])
                            .style(button::secondary)
                            .on_press_maybe(idle.then(|| Msg::Revoke(path.clone()))),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                );
            }
            page = page.push(
                button(text("Выдать каталог…").size(13))
                    .padding([4, 10])
                    .style(button::secondary)
                    .on_press_maybe(idle.then_some(Msg::GrantAsk)),
            );
        }
        // What else.
        let mut acts = row![].spacing(6);
        if running.is_some() {
            acts = acts.push(
                button(text("Остановить").size(13))
                    .padding([4, 10])
                    .style(button::secondary)
                    .on_press_maybe(idle.then_some(Msg::Stop)),
            );
        }
        acts = acts.push(
            button(text("Объединить с…").size(13))
                .padding([4, 10])
                .style(button::secondary)
                .on_press_maybe(idle.then_some(Msg::MergeAsk)),
        );
        acts = acts.push(
            button(text("Удалить…").size(13))
                .padding([4, 10])
                .style(button::danger)
                .on_press_maybe(idle.then_some(Msg::RemoveAsk)),
        );
        page = page.push(text("Действия").size(16));
        page = page.push(acts);
        // What is blocked for it (blocked on the network's tab).
        page = page.push(self.view_blocks(Some(&c.name)));
        // Its permissions, as cellward explains them.
        page = page.push(text("Разрешения").size(16));
        let explained = match &self.explained {
            Some((_, Ok(t))) | Some((_, Err(t))) => t.as_str(),
            None => "…",
        };
        page = page.push(
            container(
                text(explained)
                    .size(12)
                    .font(iced::Font::MONOSPACE)
                    .wrapping(iced::widget::text::Wrapping::WordOrGlyph),
            )
            .padding(8)
            .width(Length::Fill)
            .style(container::bordered_box),
        );
        page.into()
    }

    fn view_pending<'a>(&'a self, c: &'a Cont, pending: &'a Pending) -> Option<Element<'a, Msg>> {
        let cancel = button(text("Отмена  Esc").size(13))
            .padding([4, 10])
            .style(button::secondary)
            .on_press(Msg::Cancel);
        let go = |label: String, msg: Msg, danger: bool| {
            button(text(label).size(13))
                .padding([4, 10])
                .style(if danger {
                    button::danger
                } else {
                    button::primary
                })
                .on_press(msg)
        };
        let question = |t: String| {
            text(t)
                .size(14)
                .wrapping(iced::widget::text::Wrapping::WordOrGlyph)
        };
        let block: Element<'a, Msg> = match pending {
            Pending::Switch(to) => column![
                question(format!(
                    "Программы «{}» работают в другой сети. Сменить её на «{to}» на ходу? \
                     Программы останутся, их соединения оборвутся, и ничего из прежней сети \
                     в новой не заговорит. Или закрыть их и открыть уже в новой.",
                    c.name
                )),
                row![
                    go("Сменить сейчас".into(), Msg::Switch(false), false),
                    go(
                        "Сменить и перезапустить программы".into(),
                        Msg::Switch(true),
                        false
                    ),
                    cancel
                ]
                .spacing(6)
            ]
            .spacing(8)
            .into(),
            Pending::Grant(dir) => column![
                question(format!(
                    "Надолго ли выдать «{dir}» контейнеру «{}»? По истечении срока каталог \
                     отмонтируется и у уже запущенных программ.",
                    c.name
                )),
                row![
                    go("Бессрочно".into(), Msg::GrantFor("always"), false),
                    go("На час".into(), Msg::GrantFor("1h"), false),
                    go("На сутки".into(), Msg::GrantFor("1d"), false),
                    go("На неделю".into(), Msg::GrantFor("7d"), false),
                    cancel
                ]
                .spacing(6)
            ]
            .spacing(8)
            .into(),
            Pending::Merge => {
                let mut targets = column![question(format!(
                    "В какой контейнер перенести данные и программы «{}»? Только того же вида.",
                    c.name
                ))]
                .spacing(6);
                let same: Vec<&Cont> = self
                    .data
                    .containers
                    .iter()
                    .filter(|o| o.home == c.home && o.name != c.name)
                    .collect();
                if same.is_empty() {
                    targets = targets.push(text("другого контейнера того же вида нет").size(13));
                }
                for o in same {
                    targets =
                        targets.push(go(o.name.clone(), Msg::MergeInto(o.name.clone()), false));
                }
                targets.push(cancel).into()
            }
            Pending::MergeInto(into) => column![
                question(format!(
                    "Перенести «{0}» в «{into}»? Совпавшие файлы останутся у «{into}», версии из \
                     «{0}» лягут рядом, в .merged-from-{0}. Программы «{0}» перейдут в «{into}». \
                     Сам «{0}» останется — удалишь, когда проверишь.",
                    c.name
                )),
                row![go("Объединить".into(), Msg::MergeGo, true), cancel].spacing(6)
            ]
            .spacing(8)
            .into(),
            Pending::MergeCertificates(into, said) => column![
                question(format!(
                    "{said}\n\n⚠ Программы «{into}» начнут доверять этим корневым сертификатам: \
                     их владелец сможет читать их TLS-трафик. Принять?"
                )),
                row![
                    go("Принять сертификаты".into(), Msg::MergeCertificatesGo, true),
                    cancel
                ]
                .spacing(6)
            ]
            .spacing(8)
            .into(),
            Pending::Remove => column![
                question(format!(
                    "Удалить контейнер «{}» вместе с его данными? Это не отменить.",
                    c.name
                )),
                row![go("Удалить".into(), Msg::RemoveGo, true), cancel].spacing(6)
            ]
            .spacing(8)
            .into(),
            _ => return None,
        };
        Some(
            container(block)
                .padding(10)
                .width(Length::Fill)
                .style(container::bordered_box)
                .into(),
        )
    }

    /// What waits for a word outside one container: a zone's cut or
    /// removal, a new zone, a new container, every pin forgotten.
    fn view_general<'a>(&'a self, pending: &'a Pending) -> Option<Element<'a, Msg>> {
        let cancel = button(text("Отмена  Esc").size(13))
            .padding([4, 10])
            .style(button::secondary)
            .on_press(Msg::Cancel);
        let go = |label: &'static str, msg: Option<Msg>, danger: bool| {
            button(text(label).size(13))
                .padding([4, 10])
                .style(if danger {
                    button::danger
                } else {
                    button::primary
                })
                .on_press_maybe(msg)
        };
        let question = |t: String| {
            text(t)
                .size(14)
                .wrapping(iced::widget::text::Wrapping::WordOrGlyph)
        };
        let block: Element<'a, Msg> = match pending {
            Pending::EndTasks(all) => {
                let names: Vec<&str> = all.iter().map(|(_, _, n)| n.as_str()).collect();
                column![
                    question(format!(
                        "Завершить {}: {}? Каждый запуск — со всеми его процессами сразу, \
                         несохранённое пропадёт.",
                        if all.len() == 1 {
                            "запуск"
                        } else {
                            "запуски"
                        },
                        names.join(", ")
                    )),
                    row![go("Завершить", Some(Msg::TasksEndGo), true), cancel].spacing(6)
                ]
                .spacing(8)
                .into()
            }
            Pending::Kill(zone) => column![
                question(format!(
                    "Оборвать подключение «{zone}»? Все его программы — удалённый доступ, \
                     браузеры, всё, что в нём запущено, — будут заморожены и убиты, \
                     несохранённое пропадёт."
                )),
                row![go("Оборвать", Some(Msg::KillGo), true), cancel].spacing(6)
            ]
            .spacing(8)
            .into(),
            Pending::RemoveZone(zone) => column![
                question(format!(
                    "Удалить подключение «{zone}»? Оно будет остановлено и удалено вместе с \
                     копией конфига — в нём приватный ключ. Программы, закреплённые за ним, \
                     снова начнут спрашивать сеть."
                )),
                row![go("Удалить", Some(Msg::RemoveZoneGo), true), cancel].spacing(6)
            ]
            .spacing(8)
            .into(),
            Pending::AddZone { conf, name } => column![
                question(format!(
                    "Подключение из «{conf}». Как его назвать? Имя попадёт в ярлыки и окна."
                )),
                text_input("имя подключения: буквы, цифры, _ и -", name)
                    .on_input(Msg::ZoneName)
                    .on_submit(Msg::AddZoneGo)
                    .size(14)
                    .padding(6),
                row![
                    go(
                        "Создать и поднять",
                        (!name.trim().is_empty()).then_some(Msg::AddZoneGo),
                        false
                    ),
                    cancel
                ]
                .spacing(6)
            ]
            .spacing(8)
            .into(),
            Pending::NewContainer { name, home } => {
                let kind = |label: &'static str, which: &'static str| {
                    button(text(label).size(13))
                        .padding([4, 10])
                        .style(if *home == which {
                            button::primary
                        } else {
                            button::secondary
                        })
                        .on_press(Msg::NewHome(which))
                };
                column![
                    question(
                        "Новый контейнер: имя и дом. Свой дом — пустой, программа не видит \
                         настоящего; слой — видит настоящий дом, а пишет в свой слой; \
                         настоящий дом — сам дом, со своими сетью и разрешениями."
                            .to_owned()
                    ),
                    text_input("имя: буквы, цифры, дефис", name)
                        .on_input(Msg::NewName)
                        .on_submit(Msg::NewContainerGo)
                        .size(14)
                        .padding(6),
                    row![
                        kind("Свой дом", "private"),
                        kind("Слой над домом", "layer"),
                        kind("Настоящий дом", "main"),
                    ]
                    .spacing(6),
                    row![
                        go(
                            "Создать",
                            (!name.trim().is_empty()).then_some(Msg::NewContainerGo),
                            false
                        ),
                        cancel
                    ]
                    .spacing(6)
                ]
                .spacing(8)
                .into()
            }
            Pending::ForgetAll => column![
                question(
                    "Забыть контейнер у всех закреплённых программ? Он снова будет \
                     спрашиваться при запуске; сети контейнеров останутся их."
                        .to_owned()
                ),
                row![go("Забыть у всех", Some(Msg::ForgetAllGo), true), cancel].spacing(6)
            ]
            .spacing(8)
            .into(),
            _ => return None,
        };
        Some(
            container(block)
                .padding(10)
                .width(Length::Fill)
                .style(container::bordered_box)
                .into(),
        )
    }

    /// **Задачи**: each container's launches by their cgroups, what they
    /// use now, and their processes when unfolded; chosen by a click, more
    /// with Ctrl, paused, resumed, ended (asked first).
    fn view_tasks(&self) -> Element<'_, Msg> {
        let mut page = column![].spacing(8);
        if let Some(block) = self.pending.as_ref().and_then(|p| self.view_general(p)) {
            page = page.push(block);
        }
        let idle = !self.busy && self.pending.is_none();
        let some = !self.picked.is_empty();
        let act = |label: &'static str, msg: Msg, danger: bool| {
            button(text(label).size(13))
                .padding([4, 10])
                .style(if danger {
                    button::danger
                } else {
                    button::secondary
                })
                .on_press_maybe((idle && some).then_some(msg))
        };
        page = page.push(
            row![
                act("Пауза", Msg::TasksDo("pause"), false),
                act("Продолжить", Msg::TasksDo("resume"), false),
                act("Завершить…", Msg::TasksEndAsk, true),
                text(if some {
                    format!("выбрано: {}", self.picked.len())
                } else {
                    "щелчок или ↑/↓ — выбрать запуск, с Ctrl — ещё один; Пробел — пауза, \
                     Delete — завершить"
                        .to_owned()
                })
                .size(12),
            ]
            .spacing(6)
            .align_y(Alignment::Center),
        );
        let mut instances: Vec<&str> = self
            .data
            .tasks
            .iter()
            .map(|t| t.instance.as_str())
            .collect();
        instances.dedup();
        if instances.is_empty() {
            page = page.push(text("Ни одна программа не запущена в контейнере").size(14));
        }
        for id in instances {
            let tasks: Vec<&TaskRow> = self
                .data
                .tasks
                .iter()
                .filter(|t| t.instance == id)
                .collect();
            let network = self
                .data
                .instances
                .iter()
                .find(|i| i.id == id)
                .map(|i| i.network.clone())
                .unwrap_or_default();
            let color = self
                .data
                .containers
                .iter()
                .find(|c| c.name == id.split(':').next().unwrap_or(id))
                .and_then(|c| c.color)
                .unwrap_or(Color::from_rgb8(0x88, 0x88, 0x88));
            let rss: u64 = tasks.iter().map(|t| t.rss_kib).sum();
            let cpu: f64 = tasks
                .iter()
                .filter_map(|t| self.task_cpu.get(&(t.instance.clone(), t.leaf.clone())))
                .sum();
            page = page.push(
                row![
                    text("●").size(14).color(color),
                    text(if network.is_empty() {
                        id.to_owned()
                    } else {
                        format!("{id} · {network}")
                    })
                    .size(15)
                    .width(Length::Fill),
                    text(format!("{} · ЦП {:.0}%", mib(rss), cpu)).size(13),
                ]
                .spacing(8)
                .align_y(Alignment::Center),
            );
            for t in tasks {
                let key = (t.instance.clone(), t.leaf.clone());
                let chosen = self.picked.contains(&key);
                let open = self.opened.contains(&key);
                let procs: Vec<&ProcRow> = self
                    .data
                    .procs
                    .iter()
                    .filter(|p| p.instance == t.instance && p.leaf == t.leaf)
                    .collect();
                let cpu = self
                    .task_cpu
                    .get(&key)
                    .map_or("—".to_owned(), |c| format!("{c:.0}%"));
                let line = row![
                    button(text(if open { "▾" } else { "▸" }).size(13))
                        .padding([0, 4])
                        .style(button::text)
                        .on_press(Msg::TaskOpen(t.instance.clone(), t.leaf.clone())),
                    text(format!(
                        "{}{}",
                        task_name(t),
                        if t.frozen { " — на паузе" } else { "" }
                    ))
                    .size(14)
                    .width(Length::Fill),
                    text(mib(t.rss_kib)).size(13).width(Length::Fixed(80.0)),
                    text(format!("ЦП {cpu}"))
                        .size(13)
                        .width(Length::Fixed(70.0)),
                    text(format!("процессов {}", procs.len())).size(12),
                ]
                .spacing(8)
                .align_y(Alignment::Center);
                page = page.push(
                    button(line)
                        .padding([2, 6])
                        .width(Length::Fill)
                        .style(if chosen {
                            button::primary
                        } else {
                            button::text
                        })
                        .on_press(Msg::TaskPick(t.instance.clone(), t.leaf.clone())),
                );
                if open {
                    for p in procs {
                        let cpu = self
                            .proc_cpu
                            .get(&p.pid)
                            .map_or("—".to_owned(), |c| format!("{c:.0}%"));
                        page = page.push(
                            row![
                                text(format!("{} · {}", p.comm, p.pid))
                                    .size(12)
                                    .width(Length::Fill),
                                text(mib(p.rss_kib)).size(12).width(Length::Fixed(80.0)),
                                text(format!("ЦП {cpu}"))
                                    .size(12)
                                    .width(Length::Fixed(70.0)),
                            ]
                            .spacing(8)
                            .padding(iced::Padding {
                                left: 40.0,
                                ..iced::Padding::ZERO
                            }),
                        );
                    }
                }
            }
        }
        page = page.push(
            text(
                "Память — сумма по процессам: общая между ними считается не раз. Пауза \
                 замораживает все процессы запуска сразу; завершить — убить их все.",
            )
            .size(12),
        );
        scrollable(page).height(Length::Fill).into()
    }

    fn view_zones(&self) -> Element<'_, Msg> {
        let mut page = column![].spacing(10);
        if let Some(block) = self.pending.as_ref().and_then(|p| self.view_general(p)) {
            page = page.push(block);
        }
        let idle = !self.busy && self.pending.is_none();
        page = page.push(
            button(text("Добавить VPN из конфига…").size(13))
                .padding([4, 10])
                .style(button::secondary)
                .on_press_maybe(idle.then_some(Msg::AddZoneAsk)),
        );
        let act = |label: &'static str, msg: Msg, danger: bool| {
            button(text(label).size(13))
                .padding([4, 10])
                .style(if danger {
                    button::danger
                } else {
                    button::secondary
                })
                .on_press_maybe(idle.then_some(msg))
        };
        for n in &self.data.networks {
            if n.kind == "unconfined" {
                continue;
            }
            let color = n.color.unwrap_or(Color::from_rgb8(0x88, 0x88, 0x88));
            let title = match n.kind.as_str() {
                "offline" => "offline (без сети)".to_owned(),
                "host" => "host (сеть хоста, без VPN)".to_owned(),
                _ => n.name.clone(),
            };
            let state = if n.kind == "offline" {
                if n.locked {
                    "заперта".to_owned()
                } else {
                    String::new()
                }
            } else {
                tunnel_text(n)
            };
            let mut buttons = row![].spacing(6);
            if n.kind == "zone" || n.kind == "host" {
                if n.up {
                    buttons = buttons
                        .push(act("Опустить", Msg::ZoneDo(n.name.clone(), "down"), false))
                        .push(act(
                            "Перезапустить",
                            Msg::ZoneDo(n.name.clone(), "restart"),
                            false,
                        ))
                        .push(act(
                            "Проверить туннель",
                            Msg::ZoneDo(n.name.clone(), "check"),
                            false,
                        ));
                } else {
                    buttons =
                        buttons.push(act("Поднять", Msg::ZoneDo(n.name.clone(), "up"), false));
                }
            }
            buttons = buttons.push(if n.locked {
                act("Отпереть", Msg::ZoneDo(n.name.clone(), "unlock"), false)
            } else {
                act("Запереть", Msg::ZoneDo(n.name.clone(), "lock"), false)
            });
            if n.up {
                buttons = buttons.push(act("Оборвать…", Msg::KillAsk(n.name.clone()), true));
            }
            if n.kind == "zone" {
                buttons = buttons.push(act("Удалить…", Msg::RemoveZoneAsk(n.name.clone()), true));
            }
            page = page.push(
                column![
                    row![
                        text("●").size(14).color(color),
                        text(title).size(15).width(Length::Fixed(220.0)),
                        text(state).size(13),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                    buttons,
                ]
                .spacing(4),
            );
        }
        page = page.push(
            text(
                "Запертое подключение не выпускает свои программы в другие сети. Оборвать — \
                 убить все его программы сразу и опустить его.",
            )
            .size(12),
        );
        scrollable(page).height(Length::Fill).into()
    }

    fn setting(&self, name: &str) -> (String, String) {
        self.data
            .settings
            .iter()
            .find(|(n, _, _)| n == name)
            .map(|(_, v, s)| (v.clone(), s.clone()))
            .unwrap_or_default()
    }

    /// One setting's choices, the current one marked; one set in Nix is
    /// changed there — said, and not offered.
    fn setting_row<'a>(
        &'a self,
        title: &'a str,
        name: &'static str,
        choices: Vec<(String, String)>,
    ) -> Element<'a, Msg> {
        let (value, source) = self.setting(name);
        let declared = source == "nix";
        let idle = !self.busy && self.pending.is_none() && !declared;
        let mut buttons = column![].spacing(4);
        for (tag, label) in choices {
            let current = tag == value;
            buttons = buttons.push(
                button(text(label).size(13))
                    .padding([4, 10])
                    .style(if current {
                        button::primary
                    } else {
                        button::secondary
                    })
                    .on_press_maybe(if current {
                        Some(Msg::Nothing)
                    } else {
                        idle.then(|| Msg::SetSetting(name, tag.clone()))
                    }),
            );
        }
        let mut block = column![text(title).size(16)].spacing(6);
        if declared {
            block = block.push(text("задано в Nix — меняется там").size(12));
        }
        block.push(buttons).into()
    }

    fn view_settings(&self) -> Element<'_, Msg> {
        let mut page = column![].spacing(16);
        if let Some(block) = self.pending.as_ref().and_then(|p| self.view_general(p)) {
            page = page.push(block);
        }
        let mut nets = vec![
            (
                "offline".to_owned(),
                "Без сети — безопасно для незнакомой программы".to_owned(),
            ),
            (
                "host".to_owned(),
                "Сеть хоста — без VPN, в своём контейнере".to_owned(),
            ),
            ("unconfined".to_owned(), "Без изоляции и без VPN".to_owned()),
        ];
        for n in self.data.networks.iter().filter(|n| n.kind == "zone") {
            nets.push((n.name.clone(), format!("VPN: {}", n.name)));
        }
        page = page.push(self.setting_row(
            "Сеть, которую предлагать программе, запущенной впервые",
            "default",
            nets,
        ));
        let mut homes = vec![
            ("ask".to_owned(), "Спрашивать каждый раз".to_owned()),
            ("main".to_owned(), "Всегда настоящий дом".to_owned()),
            (
                "own".to_owned(),
                "У каждой программы свой контейнер".to_owned(),
            ),
        ];
        for c in &self.data.containers {
            homes.push((c.name.clone(), format!("Всегда «{}»", c.name)));
        }
        page = page.push(self.setting_row("Контейнер по умолчанию", "default-profile", homes));
        let (mode, _) = self.setting("mode");
        let mut modes = vec![
            (
                "picker".to_owned(),
                "Один ярлык, спрашивает сеть при запуске".to_owned(),
            ),
            ("off".to_owned(), "Не трогать ярлыки".to_owned()),
        ];
        if mode == "per-zone" || mode == "both" {
            modes.push((mode.clone(), format!("{mode} (устарел, будет убран)")));
        }
        page = page.push(self.setting_row("Ярлыки программ", "mode", modes));
        page = page.push(self.setting_row(
            "Экран и ввод: отбирать ли у программ захват экрана, чтение буфера в фоне и \
             эмуляцию ввода",
            "wayland-sandbox",
            vec![
                (
                    "on".to_owned(),
                    "Отбирать — программа видит только свои окна".to_owned(),
                ),
                ("off".to_owned(), "Не отбирать".to_owned()),
            ],
        ));
        let idle = !self.busy && self.pending.is_none();
        let mut pins = column![text("Закреплённые программы").size(16)].spacing(4);
        if self.data.pins.is_empty() {
            pins = pins.push(text("нет — контейнер спрашивается при каждом запуске").size(13));
        }
        for (key, name, to) in &self.data.pins {
            let to = if to.is_empty() { "—" } else { to.as_str() };
            pins = pins.push(
                row![
                    text(format!("{name} → {to}")).size(13).width(Length::Fill),
                    button(text("Забыть").size(13))
                        .padding([3, 8])
                        .style(button::secondary)
                        .on_press_maybe(idle.then(|| Msg::Forget(key.clone()))),
                ]
                .spacing(8)
                .align_y(Alignment::Center),
            );
        }
        if !self.data.pins.is_empty() {
            pins = pins.push(
                button(text("Забыть у всех…").size(13))
                    .padding([4, 10])
                    .style(button::danger)
                    .on_press_maybe(idle.then_some(Msg::ForgetAllAsk)),
            );
        }
        page = page.push(pins);
        scrollable(page).height(Length::Fill).into()
    }

    fn subscription(&self) -> Subscription<Msg> {
        iced::event::listen_with(|event, status, _window| match event {
            iced::Event::Keyboard(keyboard::Event::ModifiersChanged(m)) => Some(Msg::Modifiers(m)),
            iced::Event::Keyboard(keyboard::Event::KeyPressed {
                key: Key::Named(named),
                ..
            }) => {
                // An arrow a field took (a name being typed) is the field's.
                let free = status == iced::event::Status::Ignored;
                match named {
                    key::Named::Escape => Some(Msg::Escape),
                    key::Named::ArrowLeft if free => Some(Msg::TabStep(-1)),
                    key::Named::ArrowRight if free => Some(Msg::TabStep(1)),
                    key::Named::ArrowUp if free => Some(Msg::Step(-1)),
                    key::Named::ArrowDown if free => Some(Msg::Step(1)),
                    key::Named::Space if free => Some(Msg::TasksSpace),
                    key::Named::Delete if free => Some(Msg::TasksDelete),
                    _ => None,
                }
            }
            _ => None,
        })
    }
}

/// `panel …`: the window, until it is closed.
pub fn run(args: &[String]) -> iced::Result {
    let mut cellward: Option<PathBuf> = None;
    let mut dirs: Option<PathBuf> = None;
    let mut tab = Tab::Network;
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        let value = rest.next().cloned().unwrap_or_default();
        match flag.as_str() {
            "--cellward" => cellward = Some(PathBuf::from(value)),
            "--dirs" if !value.is_empty() => dirs = Some(PathBuf::from(value)),
            "--tab" if value == "tasks" => tab = Tab::Tasks,
            "--tab" if value == "containers" => tab = Tab::Containers,
            "--tab" if value == "zones" => tab = Tab::Zones,
            "--tab" if value == "settings" => tab = Tab::Settings,
            _ => {}
        }
    }
    let Some(cellward) = cellward else {
        eprintln!("vpn-zone-window panel: needs --cellward <path>");
        std::process::exit(2);
    };
    iced::application(
        move || {
            let panel = Panel::new(cellward.clone(), dirs.clone(), tab);
            let first = load(panel.cellward.clone());
            (panel, first)
        },
        Panel::update,
        Panel::view,
    )
    .title(|_: &Panel| "cellward".to_owned())
    .theme(|_: &Panel| None::<iced::Theme>)
    .subscription(Panel::subscription)
    .window(iced::window::Settings {
        size: Size::new(980.0, 640.0),
        position: iced::window::Position::Centered,
        #[cfg(target_os = "linux")]
        platform_specific: iced::window::settings::PlatformSpecific {
            application_id: "cellward".to_owned(),
            ..Default::default()
        },
        ..iced::window::Settings::default()
    })
    .run()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &str = "container\twork\tlayer\tnl\t#3366ff\n\
        path\twork\t/home/a/share\t0\n\
        path\tnobody\t/x\t0\n\
        container\tbank\tprivate\task\t#808080\n\
        network\tnl\tzone\t1\t#3366ff\t0\talive\n\
        network\toffline\toffline\t1\t#808080\t1\t-\n\
        network\told\tzone\t1\t#808080\n\
        setting\tdefault\toffline\tdefault\n\
        pin\tfirefox\tFirefox\twork\n\
        instance\twork\twork\tnl\t1500\t3000\t1790000000\n\
        flow\twork\ttcp\t149.154.167.50\t443\tapi.telegram.org\tTelegram\t2048\t10\t1790000100\n\
        flow\twork\ticmpv6\t2001:db8::1\t0\t\t\t64\t64\t1790000050\n\
        program\twork\tTelegram\t4096\t8192\n\
        today\twork\tnl\t1500\t3000\n\
        month\twork\tnl\t9000\t12000\n\
        what\tever\n";

    /// The task lines read, CPU made of two readings' ticks, launches
    /// chosen alone or with Ctrl, and what is ended asked first.
    #[test]
    fn the_tasks_are_read_counted_and_chosen() {
        let reading = |ticks: u64| {
            format!(
                "task\twork\tl10-20\tFirefox\t0\t204800\t{ticks}\t100\n\
                 tproc\twork\tl10-20\t42\tfirefox\t204800\t{ticks}\n\
                 task\twork\tl11-21\t\t1\t1024\t5\t100\n"
            )
        };
        let d = parse(&reading(100));
        assert_eq!(d.tasks.len(), 2);
        assert_eq!(d.procs[0].comm, "firefox");
        assert!(d.tasks[1].frozen && task_name(&d.tasks[1]) == "запуск l11-21");
        assert_eq!(mib(204800), "200 МБ");
        let mut p = Panel::new(PathBuf::from("/nonexistent"), None, Tab::Tasks);
        let then = Instant::now();
        p.count_cpu(&d, then);
        assert!(p.task_cpu.is_empty(), "one reading says no CPU yet");
        p.count_cpu(
            &parse(&reading(150)),
            then + std::time::Duration::from_secs(1),
        );
        let firefox = p.task_cpu[&("work".to_owned(), "l10-20".to_owned())];
        assert!((firefox - 50.0).abs() < 0.5, "{firefox}");
        assert!((p.proc_cpu[&42] - 50.0).abs() < 0.5);
        p.data = parse(&reading(150));
        let _ = p.update(Msg::TaskPick("work".into(), "l10-20".into()));
        let _ = p.update(Msg::TaskPick("work".into(), "l11-21".into()));
        assert_eq!(p.picked.len(), 1, "a click alone chooses one");
        let _ = p.update(Msg::Modifiers(keyboard::Modifiers::CTRL));
        let _ = p.update(Msg::TaskPick("work".into(), "l10-20".into()));
        assert_eq!(p.picked.len(), 2);
        let _ = p.update(Msg::TasksEndAsk);
        assert!(
            matches!(&p.pending, Some(Pending::EndTasks(all)) if all.len() == 2),
            "ended only once asked"
        );
        let _ = p.update(Msg::Cancel);
        assert!(p.pending.is_none());
        // A launch gone: not chosen.
        p.count_cpu(
            &parse("task\twork\tl10-20\tFirefox\t0\t1\t1\t100\n"),
            Instant::now(),
        );
        assert_eq!(p.picked.len(), 1);
    }

    /// The panel's lines read back: each kind in its place, a path of a
    /// container not listed and a line of no kind skipped.
    #[test]
    fn the_panels_lines_are_read() {
        let d = parse(DATA);
        assert_eq!(d.containers.len(), 2);
        assert_eq!(d.containers[0].paths, vec![("/home/a/share".to_owned(), 0)]);
        assert_eq!(
            d.containers[0].color,
            Some(Color::from_rgb8(0x33, 0x66, 0xff))
        );
        // A network line of the old shape is skipped, not misread.
        assert_eq!(d.networks.len(), 2);
        assert!(d.networks[0].up && !d.networks[0].locked);
        assert!(d.networks[1].locked);
        assert_eq!(tunnel_text(&d.networks[0]), "поднята · туннель жив");
        assert_eq!(
            d.settings,
            vec![(
                "default".to_owned(),
                "offline".to_owned(),
                "default".to_owned()
            )]
        );
        assert_eq!(
            d.pins,
            vec![(
                "firefox".to_owned(),
                "Firefox".to_owned(),
                "work".to_owned()
            )]
        );
        assert_eq!(zone_name_of("/home/a/nl de.conf"), "nl-de");
        assert_eq!(zone_name_of("x"), "x");
        assert_eq!(d.instances[0].inb, 3000);
        assert_eq!(d.flows.len(), 2);
        assert_eq!(d.flows[0].who, "Telegram");
        assert_eq!(destination(&d.flows[0]), "api.telegram.org:443");
        assert_eq!(destination(&d.flows[1]), "2001:db8::1 (icmpv6)");
        assert_eq!(d.flows[1].last, 1790000050);
        assert_eq!(
            d.programs,
            vec![("work".to_owned(), "Telegram".to_owned(), 4096, 8192)]
        );
        assert_eq!(d.today.len(), 1);
        assert_eq!(d.month[0].out, 9000);
        assert_eq!(color_of("#12345"), None);
        assert_eq!(color_of("123456"), None);
    }

    /// Two programs of a container, one of another, one of none found, one
    /// with no traffic yet; names of one site, an address on the web's port
    /// and one on another.
    const TREE: &str = "container\twork\tlayer\tnl\t#3366ff\n\
        container\tapp-chat\tprivate\tnl\t#33ff66\n\
        instance\tw1\twork\tnl\t0\t0\t1\n\
        instance\tc1\tapp-chat\tnl\t0\t0\t1\n\
        flow\tw1\ttcp\t10.0.0.1\t443\trr4sn-2o.googlevideo.com\tBrowser\t10\t5000\t100\n\
        flow\tw1\ttcp\t10.0.0.2\t443\trr2.googlevideo.com.\tBrowser\t10\t3000\t300\n\
        flow\tw1\ttcp\t10.0.0.3\t443\tgithub.com\tBrowser\t5\t100\t200\n\
        flow\tw1\ttcp\t10.0.0.4\t443\t\tBrowser\t1\t1\t50\n\
        flow\tw1\tudp\t10.0.0.4\t3478\t\tBrowser\t1\t9000\t60\n\
        flow\tw1\ttcp\t10.0.0.5\t443\t\tEditor\t0\t0\t70\n\
        flow\tc1\tudp\t2001:db8::1\t443\t\tChat\t100\t100\t80\n\
        flow\tc1\ttcp\t10.0.0.6\t443\t\t\t50\t50\t90\n\
        block\twork\tgithub.com\tlocal\n\
        block\twork\tads.example\tnix\n\
        block\tnobody\n";

    /// Programs by container, the most first and the silent last; under
    /// each, sites by bytes, a site's names under it, an address with its
    /// port where it is not the web's.
    #[test]
    fn connections_are_a_tree_by_container_and_program() {
        let g = groups(&parse(TREE));
        let heads: Vec<(&str, &str)> = g
            .iter()
            .map(|g| (g.container.as_str(), g.who.as_str()))
            .collect();
        assert_eq!(
            heads,
            vec![
                ("work", "Browser"),
                ("app-chat", "Chat"),
                ("app-chat", ""),
                ("work", "Editor"),
            ]
        );
        let b = &g[0];
        assert_eq!((b.out, b.inb), (27, 17101));
        let rows: Vec<(&str, &str, u64)> = b
            .dests
            .iter()
            .map(|d| (d.label.as_str(), d.target.as_str(), d.total()))
            .collect();
        assert_eq!(
            rows,
            vec![
                ("10.0.0.4:3478", "10.0.0.4", 9001),
                ("googlevideo.com", "googlevideo.com", 8020),
                ("github.com", "github.com", 105),
                ("10.0.0.4", "10.0.0.4", 2),
            ]
        );
        // The site sums its names and keeps the latest; its names under it,
        // the trailing dot of a DNS name gone.
        let site = &b.dests[1];
        assert_eq!(site.last, 300);
        let names: Vec<&str> = site.subs.iter().map(|s| s.label.as_str()).collect();
        assert_eq!(
            names,
            vec!["rr4sn-2o.googlevideo.com", "rr2.googlevideo.com"]
        );
        // A site that is only itself has nothing to unfold.
        assert!(b.dests[2].subs.is_empty());
        assert_eq!(g[1].dests[0].label, "2001:db8::1");
        assert_eq!(container_words(&g[1].container), "свой контейнер");
        assert_eq!(container_words("work"), "контейнер «work»");
        assert!(!blockable(OPEN) && !blockable("-") && blockable("work"));
        assert_eq!(
            shortened("rr4sn-2oxxxxxxxxxxxxxxxxxxxxxxxxxx.googlevideo.com", 32),
            "rr4sn-2oxx…xxxxx.googlevideo.com"
        );
    }

    #[test]
    fn a_name_is_grouped_by_its_site() {
        assert_eq!(site_of("rr4sn-2o.googlevideo.com"), "googlevideo.com");
        assert_eq!(site_of("www.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(site_of("bbc.co.uk"), "bbc.co.uk");
        assert_eq!(site_of("github.com"), "github.com");
        assert_eq!(site_of("API.GitHub.com."), "github.com");
        assert_eq!(site_of("a.b.example.com.au"), "example.com.au");
        // A three-letter country code is no country's: two labels.
        assert_eq!(site_of("www.example.co.org"), "co.org");
        assert_eq!(site_of("149.154.167.50"), "149.154.167.50");
        assert_eq!(site_of("2001:db8::1"), "2001:db8::1");
        assert_eq!(site_of("localhost"), "localhost");
    }

    /// What the person folded and unfolded stays so when the panel reads
    /// its lines again, as it does every second.
    #[test]
    fn the_tree_stays_as_it_was_left_across_a_reload() {
        let mut p = Panel::new(PathBuf::from("/nonexistent"), None, Tab::Network);
        let _ = p.update(Msg::Loaded(Ok(TREE.to_owned())));
        let g = groups(&p.data);
        let _ = p.update(Msg::Fold(g[1].key.clone()));
        let site = format!("{}\t{}", g[0].key, "googlevideo.com");
        let _ = p.update(Msg::FoldSite(site.clone()));
        let _ = p.update(Msg::Loaded(Ok(TREE.to_owned())));
        assert!(p.folded.contains(&groups(&p.data)[1].key));
        assert!(!p.folded.contains(&groups(&p.data)[0].key));
        assert!(p.unfolded.contains(&site));
        // Folded again: open.
        let _ = p.update(Msg::Fold(g[1].key.clone()));
        assert!(p.folded.is_empty());
        // A block is asked, not done; Esc's cancel and another tab drop it.
        let _ = p.update(Msg::BlockAsk("work".into(), "googlevideo.com".into()));
        assert_eq!(
            p.pending,
            Some(Pending::Block {
                container: "work".into(),
                target: "googlevideo.com".into()
            })
        );
        assert!(!p.busy);
        let _ = p.update(Msg::Tab(Tab::Containers));
        assert_eq!(p.pending, None);
        let _ = p.update(Msg::Tab(Tab::Network));
        let _ = p.update(Msg::BlockAsk("work".into(), "github.com".into()));
        let _ = p.update(Msg::BlockGo);
        assert!(p.busy && p.pending.is_none());
        // The view is drawn, the question's row and all.
        p.busy = false;
        let _ = p.update(Msg::BlockAsk("work".into(), "github.com".into()));
        let _ = p.view();
    }

    #[test]
    fn blocks_are_read() {
        let d = parse(TREE);
        assert_eq!(
            d.blocks,
            vec![
                Block {
                    container: "work".into(),
                    target: "github.com".into(),
                    source: "local".into()
                },
                Block {
                    container: "work".into(),
                    target: "ads.example".into(),
                    source: "nix".into()
                },
            ]
        );
        assert!(parse(DATA).blocks.is_empty());
        // A name's block takes its subdomains, and only them.
        let mut p = Panel::new(PathBuf::from("/nonexistent"), None, Tab::Network);
        p.data = d;
        assert!(p.blocked("work", "github.com"));
        assert!(p.blocked("work", "api.github.com"));
        assert!(!p.blocked("work", "notgithub.com"));
        assert!(!p.blocked("app-chat", "github.com"));
    }

    #[test]
    fn counts_are_said_as_the_cli_says_them() {
        assert_eq!(bytes(1536), "1.5 КБ");
        assert_eq!(rate(2048.4), "2.0 КБ/с");
        assert_eq!(rate(-5.0), "0 Б/с");
        assert_eq!(ago(59), "59 с назад");
        assert_eq!(ago(3600), "1 ч назад");
    }
}
