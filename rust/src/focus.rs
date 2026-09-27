//! Which launch the focused window belongs to: the network and the container
//! of the program in front (`docs/WINDOW-FRAME.md` §7б, §7в) — what the hotkey
//! menu acts on and what a panel shows.
//!
//! The compositor knows the window and the pid that opened its connection
//! (niri: `niri msg --json focused-window`; sway: the focused node of
//! `swaymsg -t get_tree`). vpn-zones knows its launches: the registry
//! (`crate::registry`) records the pid of each, and that pid is an ANCESTOR of
//! the window's — the launch becomes the program through wl-sandbox and
//! profile-run, and a program opens its windows from its own children too. So:
//! up the parent chain from the window's pid to a pid of the registry.
//!
//! **The network is the kernel's word, and only the kernel's.** It is the
//! network namespace of the window's own process, held against the host's (the
//! one this command runs in: a zone has no compositor IPC) and the zones' — a
//! user zone by its holder, checked by its start time (`crate::cli::zone_pid`),
//! a system zone by `/run/netns/vz-<name>`, which only root writes. The
//! registry is on disk: a record outlives its process, its pid comes round to
//! somebody else, and a program with the whole `$HOME` can write it
//! (`docs/LEAK-MODEL.md` §9). So it only ever adds the container and the
//! program — a record of a launch that is certainly still this process
//! (`crate::registry::launched`), and in the network the kernel says. A window
//! in the host's namespace is the host's, whatever any file claims. A namespace
//! that is none of these is not guessed at.
//!
//! A program that detached from its parent (a double fork, reparented to init)
//! is not found in the registry either: its network is known, its container is
//! not, and it is said so.
//!
//! A window cannot lie about its pid (the kernel's `SO_PEERCRED`), but a program
//! can call itself anything in its title and app id: nothing here trusts the
//! title, and the app id is only shown — cut clean — when nothing else names
//! the program.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::process::{Child, Command, Stdio};

use crate::json::{self, Value};
use crate::registry;
use crate::tools::Tools;

/// The focused window as the compositor tells it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Window {
    pub pid: i32,
    pub app_id: String,
    pub title: String,
}

/// The launch a window belongs to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Launch {
    /// The network: a zone, `unconfined`, `offline`.
    pub zone: String,
    /// What was chosen for the container (`sb:<name>`, `__fs__`, a profile,
    /// empty for the main one); `None` when only the network is known.
    pub selector: Option<String>,
    /// The program's key — the registry file, the picker's `--id`.
    pub program: Option<String>,
}

/// The window of `niri msg --json focused-window`.
pub fn window_from_niri(v: &Value) -> Option<Window> {
    Some(Window {
        pid: i32::try_from(v.get("pid")?.as_i64()?).ok()?,
        app_id: v
            .get("app_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        title: v
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
    })
}

/// The focused window of `swaymsg -t get_tree`: the node with `focused`, where
/// a window is a node with a pid.
pub fn window_from_sway(v: &Value) -> Option<Window> {
    if v.get("focused").and_then(Value::as_bool) == Some(true) {
        if let Some(pid) = v.get("pid").and_then(Value::as_i64) {
            return Some(Window {
                pid: i32::try_from(pid).ok()?,
                app_id: v
                    .get("app_id")
                    .and_then(Value::as_str)
                    .or_else(|| {
                        v.get("window_properties")
                            .and_then(|p| p.get("class"))
                            .and_then(Value::as_str)
                    })
                    .unwrap_or("")
                    .to_owned(),
                title: v
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
            });
        }
    }
    ["nodes", "floating_nodes"]
        .iter()
        .filter_map(|k| v.get(k).and_then(Value::as_array))
        .flatten()
        .find_map(window_from_sway)
}

/// Which compositor answers here, by the variable its IPC socket is named in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compositor {
    Niri,
    Sway,
}

pub fn compositor() -> Option<Compositor> {
    let set = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
    if set("NIRI_SOCKET") {
        Some(Compositor::Niri)
    } else if set("SWAYSOCK") {
        Some(Compositor::Sway)
    } else {
        None
    }
}

fn run_json(program: &str, args: &[&str]) -> Result<Value, String> {
    let out = Command::new(program)
        .args(args)
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{program} {} failed", args.join(" ")));
    }
    json::parse(String::from_utf8_lossy(&out.stdout).trim())
}

/// The focused window, or `None` when nothing has the focus.
pub fn focused_window() -> Result<Option<Window>, String> {
    match compositor() {
        Some(Compositor::Niri) => {
            run_json("niri", &["msg", "--json", "focused-window"]).map(|v| window_from_niri(&v))
        }
        Some(Compositor::Sway) => {
            run_json("swaymsg", &["-t", "get_tree", "-r"]).map(|v| window_from_sway(&v))
        }
        None => {
            Err("композитор не отвечает: нужен niri (NIRI_SOCKET) или sway (SWAYSOCK)".to_owned())
        }
    }
}

/// The parent of a process, from `/proc/<pid>/status`.
fn parent(pid: i32) -> Option<i32> {
    crate::sys::parent_of(pid)
}

fn netns(pid: &str) -> Option<String> {
    fs::read_link(format!("/proc/{pid}/ns/net"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Every launch of the registry by its pid: `(container dir, program, record)`.
fn registry_index(running: &Path) -> HashMap<i32, (String, String, registry::Record)> {
    let mut index = HashMap::new();
    for dir in registry::dirs(running) {
        let container = dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        for file in fs::read_dir(&dir).into_iter().flatten().flatten() {
            let program = file.file_name().to_string_lossy().into_owned();
            if program.starts_with('.') {
                continue;
            }
            let Ok(text) = fs::read_to_string(file.path()) else {
                continue;
            };
            for record in text.lines().filter_map(registry::parse_record) {
                index.insert(record.pid, (container.clone(), program.clone(), record));
            }
        }
    }
    index
}

/// Which of our networks the namespace `ns` (`net:[…]`) is: the host's, a user
/// zone's, a container's instance's (the network it runs in), a system
/// zone's. `None` for any other.
fn network_of(state: &Path, ns: &str) -> Option<String> {
    if netns("self").as_deref() == Some(ns) {
        return Some(crate::launch::UNCONFINED.to_owned());
    }
    if let Some(network) = crate::place::network_of_netns(state, ns) {
        return Some(network);
    }
    for entry in fs::read_dir(state).into_iter().flatten().flatten() {
        let name = entry.file_name();
        let Some(zone_pid) = crate::cli::zone_pid(state, &name) else {
            continue;
        };
        if netns(&zone_pid.to_string()).as_deref() == Some(ns) {
            return Some(name.to_string_lossy().into_owned());
        }
    }
    crate::system::zone_of_netns(ns)
}

/// Whether `pid` is the supervisor of a launch behind the Wayland proxy
/// (`crate::wl_proxy`), and if so, the launch's network.
enum Proxied {
    No,
    /// The supervisor's program is in this network.
    Yes(String),
    /// A supervisor whose program's network cannot be told.
    Unknown,
}

/// A window behind the proxy has the SUPERVISOR's pid: upstream, the
/// supervisor (`wl-sandbox`, the pid of the registry record) makes the
/// connection the compositor takes the pid from, for every window of its
/// launch. It runs on the host, so its own namespace says nothing of the
/// program's. The kernel still does: its children are the program and the
/// orphans it adopted — in the program's network — and the proxy (not
/// dumpable, its namespace unread; and not counted). That network, when they
/// all agree on one we know; a nested one (a browser's sandbox) is not
/// counted, and two is not guessed between.
///
/// Known by its name ([`crate::wl_proxy::SUPERVISOR_NAME`]) — and not by
/// that alone, since a name is anybody's (review 2026-09-25): a process in a
/// zone's own namespace is taken by that namespace, whatever it is called;
/// one on the host counts only when the kernel says it runs our own
/// `vpn-zone-core` (`core`) and it is a launch on record. A host process that
/// merely calls itself so — one an ordinary zone started through
/// `systemd --user`, with a child put into that zone — gets no network at all
/// instead of its children's: its windows are its own, and they must not wear
/// the zone's label. A real supervisor passes on only the connections of its
/// own launch (`crate::wl_proxy`), and no process below it in a zone can bring
/// a host process into its subtree — so its children's network is its
/// windows'. After an update of the package a supervisor started before it
/// runs the old file: its windows show no network until the program is
/// started again — the safe way round.
///
/// Nor is the supervisor's own `systemd-run` counted, while it hands a
/// window menu of the frame's buttons to the manager (`crate::wl_proxy`):
/// a child in the host's network running `starter`, the manifest's
/// `systemd-run` (review 2026-09-27: one at a time, a moment long — and the
/// menu it starts looks at this launch at that very moment) — or, with
/// `--wait`, for as long as a notice of a request for the focus is up
/// (`crate::wl_focus`). No process of a zone is in the host's network, so
/// none of the launch's program is taken for it; and leaving a child out
/// never makes a network of none.
fn proxied(state: &Path, core: &Path, starter: Option<&Path>, pid: i32) -> Proxied {
    if comm(pid) != crate::wl_proxy::SUPERVISOR_NAME {
        return Proxied::No;
    }
    let own = netns(&pid.to_string()).and_then(|ns| network_of(state, &ns));
    if own.is_some_and(|zone| zone != crate::launch::UNCONFINED) {
        return Proxied::No;
    }
    if !runs_core(pid, core) || !registry::launched(&state.join(".running"), pid) {
        return Proxied::Unknown;
    }
    let host = netns("self");
    // A launch into a container's instance has its waiter for a child
    // (`crate::enter`): not dumpable, its namespace is nobody's to read —
    // its children, the program, are what counts then (as below it no
    // process can bring a host process in either).
    let programs = children(pid)
        .into_iter()
        .filter(|&child| comm(child) != crate::wl_proxy::PROCESS_NAME)
        .flat_map(|child| match netns(&child.to_string()) {
            Some(_) => vec![child],
            None => children(child),
        });
    let networks = programs
        .filter(|&child| {
            !starter.is_some_and(|starter| {
                netns(&child.to_string()) == host && runs_core(child, starter)
            })
        })
        .filter_map(|child| network_of(state, &netns(&child.to_string())?));
    match one_network(networks) {
        Some(zone) => Proxied::Yes(zone),
        None => Proxied::Unknown,
    }
}

fn comm(pid: i32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|c| c.trim_end().to_owned())
        .unwrap_or_default()
}

/// The one network all of these are in; `None` for none or several.
fn one_network(networks: impl IntoIterator<Item = String>) -> Option<String> {
    let mut networks = networks.into_iter();
    let first = networks.next()?;
    networks.all(|n| n == first).then_some(first)
}

fn children(pid: i32) -> Vec<i32> {
    crate::sys::children_of(pid)
}

/// Whether `pid` runs our own `vpn-zone-core` (`core`, as the tools manifest
/// names it) — or another file of the manifest: the file the kernel
/// executed, which a process cannot rename.
/// Readable for a process of the same user that is dumpable, as the
/// supervisor is.
fn runs_core(pid: i32, core: &Path) -> bool {
    let (Ok(exe), Ok(core)) = (
        fs::read_link(format!("/proc/{pid}/exe")),
        fs::canonicalize(core),
    ) else {
        return false;
    };
    exe == core
}

/// The launch of the process `pid`: its network by its namespace, its
/// container and program by the nearest launch up its parent chain — when that
/// launch is certainly still running and in the same network. A window of a
/// program behind the Wayland proxy has its supervisor's pid, whose network is
/// its children's ([`proxied`]); `core` is our `vpn-zone-core`, the file a
/// supervisor runs.
pub fn launch_of(state: &Path, core: &Path, pid: i32) -> Option<Launch> {
    launch_with(state, core, None, pid)
}

/// [`launch_of`] as the tools manifest has our files: the supervisor's
/// `systemd-run` starting a window menu is not taken for the launch's.
pub fn launch_with_tools(tools: &Tools, pid: i32) -> Option<Launch> {
    launch_with(&tools.state, &tools.core, Some(&tools.systemd_run), pid)
}

fn launch_with(state: &Path, core: &Path, starter: Option<&Path>, pid: i32) -> Option<Launch> {
    let zone = match proxied(state, core, starter, pid) {
        Proxied::No => network_of(state, &netns(&pid.to_string())?)?,
        Proxied::Yes(zone) => zone,
        Proxied::Unknown => return None,
    };
    let running = state.join(".running");
    let index = registry_index(&running);
    let mut at = pid;
    for _ in 0..64 {
        if let Some((_, program, record)) = index.get(&at) {
            // The user's own launch: one a program in a zone asked for runs
            // under an id of that program's choosing, and would get the user's
            // label for it and the "pin" and "restart" entries.
            if registry::launched_here(&running, at) {
                if record.zone == zone {
                    return Some(Launch {
                        zone,
                        selector: Some(record.selector.clone()),
                        program: Some(program.clone()),
                    });
                }
                // The nearest launch is somewhere else than the kernel says —
                // a program entered by hand into another network: its network
                // is known, its container is not.
                break;
            }
        }
        match parent(at) {
            Some(p) if p > 1 => at = p,
            _ => break,
        }
    }
    Some(Launch {
        zone,
        ..Launch::default()
    })
}

/// A name a program gave itself, fit to be shown: no control characters (a
/// line break would start a line of its own in a dialog), not endless.
fn shown(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control() && !reorders(*c))
        .take(80)
        .collect()
}

/// Invisible characters that change the order text is shown in, or hide in
/// it: bidi marks, embeddings, isolates, zero-width joiners and spaces. With
/// them a name can make the network after it read as something else.
pub(crate) fn reorders(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2069}'
            | '\u{3164}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

/// Text for a markup parser: waybar reads `text` and `tooltip` as Pango
/// markup, and a container or a program is named by people and programs.
fn markup(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The network as a person says it.
pub fn zone_words(zone: &str) -> String {
    match zone {
        crate::launch::UNCONFINED => "без ограничений".to_owned(),
        "offline" => "без сети".to_owned(),
        zone => zone.to_owned(),
    }
}

/// "сеть nl", "без сети", "без ограничений" — the network in a sentence.
fn net_phrase(zone: &str) -> String {
    match zone {
        crate::launch::UNCONFINED | "offline" => zone_words(zone),
        zone => format!("сеть {zone}"),
    }
}

/// "в сети nl", "без сети", "без ограничений" — where a program runs.
fn in_net(zone: &str) -> String {
    match zone {
        crate::launch::UNCONFINED | "offline" => zone_words(zone),
        zone => format!("в сети {zone}"),
    }
}

/// The program's name as the picker last showed it, or its key.
fn label(state: &Path, program: &str) -> String {
    crate::cli::read_setting(&state.join(".labels").join(program))
        .unwrap_or_else(|| program.to_owned())
}

/// The program of a window as a person knows it: its label, or else the app
/// id it gave itself, or else its pid.
fn window_name(state: &Path, window: &Window, launch: Option<&Launch>) -> String {
    launch
        .and_then(|l| l.program.as_deref())
        .map(|p| label(state, p))
        .map(|l| shown(&l))
        .unwrap_or_else(|| {
            // The window's own name, in quotes: nothing vouches for it.
            let app_id = shown(&window.app_id);
            if app_id.is_empty() {
                format!("pid {}", window.pid)
            } else {
                format!("«{app_id}»")
            }
        })
}

/// One line for a person.
pub fn describe(state: &Path, window: &Window, launch: Option<&Launch>) -> String {
    let name = window_name(state, window, launch);
    match launch {
        None => format!("{name}: сеть не известна — не хост и не зона cellward"),
        Some(l) => {
            let container = match &l.selector {
                Some(s) => crate::picker::container_label(s),
                None => "контейнер не известен".to_owned(),
            };
            format!("{name}: {}, контейнер: {container}", net_phrase(&l.zone))
        }
    }
}

/// `{"zone":…,"container":…,"program":…,"label":…,"pid":…,"app_id":…}`, or
/// `{"window":null}` with nothing focused.
pub fn to_json(state: &Path, window: Option<&Window>, launch: Option<&Launch>) -> String {
    let Some(w) = window else {
        return "{\"window\":null}".to_owned();
    };
    let opt = |v: Option<&str>| v.map_or("null".to_owned(), json::quote);
    let program = launch.and_then(|l| l.program.as_deref());
    format!(
        "{{\"pid\":{},\"app_id\":{},\"zone\":{},\"container\":{},\"program\":{},\"label\":{}}}",
        w.pid,
        json::quote(&w.app_id),
        opt(launch.map(|l| l.zone.as_str())),
        opt(launch.and_then(|l| l.selector.as_deref())),
        opt(program),
        opt(program.map(|p| label(state, p)).as_deref()),
    )
}

/// One line for a status bar (waybar's `return-type: json`): the text, a
/// tooltip, and a class a style sheet can colour by zone.
pub fn bar_line(state: &Path, window: Option<&Window>, launch: Option<&Launch>) -> String {
    let (text, class) = match launch {
        None if window.is_none() => (String::new(), "none".to_owned()),
        None => ("?".to_owned(), "unknown".to_owned()),
        Some(l) => {
            let container = l
                .selector
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|s| format!(" · {}", crate::picker::container_label(s)))
                .unwrap_or_default();
            (
                format!("{}{container}", zone_words(&l.zone)),
                format!("zone-{}", l.zone),
            )
        }
    };
    let tooltip = window
        .map(|w| describe(state, w, launch))
        .unwrap_or_default();
    format!(
        "{{\"text\":{},\"tooltip\":{},\"class\":{}}}",
        json::quote(&markup(&text)),
        json::quote(&markup(&tooltip)),
        json::quote(&class)
    )
}

/// `vpn-zone focused [--json | --bar | --watch]`.
pub fn run(tools: &Tools, args: &[OsString]) -> u8 {
    let flag = args.first().and_then(|a| a.to_str()).unwrap_or("");
    if flag == "--watch" {
        return watch(tools);
    }
    let window = match focused_window() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("cellward focused: {e}");
            return 1;
        }
    };
    let launch = window
        .as_ref()
        .and_then(|w| launch_with_tools(tools, w.pid));
    match flag {
        "--json" => println!(
            "{}",
            to_json(&tools.state, window.as_ref(), launch.as_ref())
        ),
        "--bar" => println!(
            "{}",
            bar_line(&tools.state, window.as_ref(), launch.as_ref())
        ),
        "" => match &window {
            Some(w) => println!("{}", describe(&tools.state, w, launch.as_ref())),
            None => println!("нет окна в фокусе"),
        },
        other => {
            eprintln!("cellward focused [--json | --bar | --watch], не {other}");
            return 1;
        }
    }
    0
}

/// A bar line every time the focus moves: the compositor's event stream, and
/// a line printed only when it changed.
fn watch(tools: &Tools) -> u8 {
    let (program, args): (&str, &[&str]) = match compositor() {
        Some(Compositor::Niri) => ("niri", &["msg", "--json", "event-stream"]),
        Some(Compositor::Sway) => (
            "swaymsg",
            &["-t", "subscribe", "-m", "[\"window\",\"workspace\"]"],
        ),
        None => {
            eprintln!("cellward focused --watch: нужен niri или sway");
            return 1;
        }
    };
    let mut child = match Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cellward focused --watch: {program}: {e}");
            return 1;
        }
    };
    let Some(stdout) = child.stdout.take() else {
        return 1;
    };
    let mut last = String::new();
    let mut show = || {
        let window = focused_window().ok().flatten();
        let launch = window
            .as_ref()
            .and_then(|w| launch_with_tools(tools, w.pid));
        let line = bar_line(&tools.state, window.as_ref(), launch.as_ref());
        if line != last {
            println!("{line}");
            last = line;
        }
    };
    show();
    for _ in BufReader::new(stdout).lines().map_while(Result::ok) {
        show();
    }
    let _ = child.wait();
    0
}

/// What "always" is for the program of a window: the network is its
/// container's, never the program's (`docs/PERMISSIONS.md` §11.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pin {
    /// A container with no network yet: bind it to the one it runs in.
    Bind(String),
    /// A container bound here (not in Nix): unbind it, and its network is
    /// asked at its next launch.
    Unbind { container: String, network: String },
    /// The main home: the program moves to the container of the main home
    /// bound to the network it runs in (`main-<network>`).
    Main,
    /// Nothing to pin: a throwaway container, a network declared in Nix, a
    /// launch not known.
    Nothing,
}

/// [`Pin`] for a launch.
pub fn pin_of(tools: &Tools, launch: &Launch) -> Pin {
    use crate::container::{Network, Source};
    match launch.selector.as_deref() {
        Some("") => Pin::Main,
        Some(selector) => match crate::container::load(tools, selector) {
            Some(c) => match (&c.network.value, c.network.source) {
                (_, Source::Nix) => Pin::Nothing,
                (Network::Ask, _) => Pin::Bind(c.name),
                (Network::Named(network), _) => Pin::Unbind {
                    network: network.clone(),
                    container: c.name,
                },
            },
            None => Pin::Nothing,
        },
        None => Pin::Nothing,
    }
}

/// The entries of the hotkey menu for the program of a window: `(tag, label,
/// danger)`.
pub fn menu_entries(
    label: &str,
    launch: Option<&Launch>,
    pin: &Pin,
) -> Vec<(String, String, bool)> {
    let mut out = Vec::new();
    let entry = |tag: &str, text: String, danger: bool| (tag.to_owned(), text, danger);
    if let Some(l) = launch.filter(|l| l.program.is_some()) {
        match pin {
            Pin::Unbind { container, network } => out.push(entry(
                "unpin",
                format!(
                    "Спрашивать сеть контейнера «{container}» при запуске (сейчас всегда {})",
                    in_net(network)
                ),
                false,
            )),
            Pin::Bind(container) => out.push(entry(
                "pin",
                format!("Контейнер «{container}» — всегда {}", in_net(&l.zone)),
                false,
            )),
            Pin::Main => out.push(entry(
                "pin",
                format!(
                    "Всегда запускать «{label}» в основном доме {}",
                    in_net(&l.zone)
                ),
                false,
            )),
            Pin::Nothing => {}
        }
        out.push(entry(
            "restart",
            format!("Закрыть «{label}» и запустить снова — выбрать сеть и контейнер…"),
            true,
        ));
    }
    out.push(entry("close", format!("Закрыть «{label}»"), true));
    if let Some(l) = launch.filter(|l| l.zone != crate::launch::UNCONFINED && l.zone != "offline") {
        out.push(entry(
            "kill-zone",
            format!(
                "Оборвать сеть {}: все её программы останутся без сети",
                l.zone
            ),
            true,
        ));
    }
    out
}

/// Ask with the launch window in its menu mode, or with a kdialog menu where
/// the window is missing. The chosen tag.
fn ask_menu(tools: &Tools, menu: &crate::window::Menu) -> Option<String> {
    if !tools.window.as_os_str().is_empty() {
        if let Ok(mut child) = Command::new(&tools.window)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = std::io::Write::write_all(
                    &mut stdin,
                    crate::window::render_menu(menu).as_bytes(),
                );
            }
            let out = child.wait_with_output().ok()?;
            if !out.status.success() {
                return None;
            }
            return crate::window::parse_menu_reply(&String::from_utf8_lossy(&out.stdout));
        }
    }
    let mut argv: Vec<OsString> = vec![
        "--title".into(),
        menu.title.clone().into(),
        "--menu".into(),
        // kdialog shows it in a QLabel, which takes `<` for rich text: a
        // window's own name must not restyle, or hide, what follows it.
        menu.notes
            .join("\n")
            .replace('<', "‹")
            .replace('>', "›")
            .replace('&', "＆")
            .into(),
    ];
    for (tag, label, _) in &menu.actions {
        argv.push(tag.into());
        argv.push(label.into());
    }
    crate::dialog::ask(&tools.kdialog, &argv)
}

/// When a restart asks what to do about a program still closing. Only that:
/// no clock decides — the program closing does, or the person.
const SAY_CLOSING_AFTER: std::time::Duration = std::time::Duration::from_secs(2);

/// A program asked to close for a restart that has not closed yet: the
/// person decides, while it goes on closing (it may be asking whether to
/// save). Asked in the launch window as a guarded question
/// (`crate::window`): nothing is taken until the person has been still with
/// it in view; kdialog only where there is no window — there a "close now"
/// sooner than [`crate::dialog::TOO_FAST`] after its start is taken for a
/// stray key, and the question comes again. Enter — the default — cancels
/// the restart, which is always safe; "close now" kills it, and what is
/// unsaved is lost; Esc (or closing the question) waits for it, and the
/// restart follows. The program closing
/// meanwhile answers the question: it goes. `true`: it closed, and the
/// restart goes on — its launch window asks, and can be closed.
fn closed_after_all(tools: &Tools, label: &str, program: &OwnedFd) -> bool {
    let shown = label.replace('<', "‹").replace('>', "›").replace('&', "＆");
    let text = format!(
        "«{shown}» ещё не закрылась — может быть, спрашивает, сохранить ли. \
         «Ждать» (Esc): перезапуск будет, когда она закроется."
    );
    let pollin = |fd: &OwnedFd| libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // In the launch window first, guarded (`crate::window::question`): a
    // press counts only after the person has been still with the question in
    // view — the dangerous answer too. kdialog where there is no window, and
    // there a press sooner than `dialog::TOO_FAST` after its start is taken
    // for a stray key and asked again.
    let menu = crate::window::Menu {
        title: crate::dialog::APP.to_owned(),
        notes: text.lines().map(str::to_owned).collect(),
        actions: vec![
            ("cancel".to_owned(), "Отменить перезапуск".to_owned(), false),
            ("wait".to_owned(), "Ждать".to_owned(), false),
            ("kill".to_owned(), "Закрыть сразу".to_owned(), true),
        ],
        guard_ms: crate::dialog::TOO_FAST.as_millis() as u64,
        ..Default::default()
    };
    loop {
        let asked = std::time::Instant::now();
        let (dialog, via_window) = match crate::window::spawn_menu(&tools.window, &menu) {
            Some(child) => (Ok(child), true),
            None => (
                Command::new(&tools.kdialog)
                    .args(["--title", crate::dialog::APP, "--warningyesnocancel"])
                    .arg(&text)
                    .args([
                        "--yes-label",
                        "Отменить перезапуск",
                        "--no-label",
                        "Закрыть сразу",
                        "--cancel-label",
                        "Ждать",
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn(),
                false,
            ),
        };
        let (mut dialog, dialog_fd) = match dialog {
            Ok(child) => match crate::sys::pidfd_open(child.id() as i32) {
                Some(fd) => (child, fd),
                None => {
                    let mut child = child;
                    let _ = child.kill();
                    let _ = child.wait();
                    crate::sys::pidfd_wait_end(program);
                    return true;
                }
            },
            // Nowhere to ask: waited for, as the restart asked.
            Err(_) => {
                crate::sys::pidfd_wait_end(program);
                return true;
            }
        };
        let mut fds = [pollin(program), pollin(&dialog_fd)];
        loop {
            // SAFETY: two valid pollfds for the duration of the call.
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
            if rc < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if fds[0].revents != 0 {
            let _ = dialog.kill();
            let _ = dialog.wait();
            return true;
        }
        // 0 cancel, 1 kill, anything else wait — as kdialog's buttons are.
        let answer = if via_window {
            match crate::window::menu_answer(dialog).as_deref() {
                Some("cancel") => Some(0),
                Some("kill") => Some(1),
                _ => Some(2),
            }
        } else {
            dialog.wait().ok().and_then(|s| s.code())
        };
        match answer {
            Some(0) => return false,
            Some(1) if via_window || crate::dialog::not_too_soon(asked).is_ok() => {
                crate::sys::pidfd_signal(program, libc::SIGKILL);
                crate::sys::pidfd_wait_end(program);
                return true;
            }
            // Too soon: asked again.
            Some(1) => continue,
            // "Wait", Esc, the question closed — or the dialog gone some
            // other way: the restart waits for the program.
            _ => {
                crate::sys::pidfd_wait_end(program);
                return true;
            }
        }
    }
}

/// What `window-menu` is asked for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MenuArgs {
    /// The launch of this pid (`--pid`) — a window's pid as the compositor
    /// has it; behind the Wayland proxy, its supervisor's, which is what the
    /// frame's buttons pass (`crate::wl_proxy`). Without it: the focused
    /// window's.
    pub pid: Option<i32>,
    /// Straight to "restart with a network chosen" (`--restart`), with no
    /// menu first: the frame's ⇄, until the network can be switched live.
    pub restart: bool,
}

/// `[--pid <pid>] [--restart]`.
pub fn parse_menu_args(args: &[OsString]) -> Result<MenuArgs, String> {
    let mut out = MenuArgs::default();
    let mut words = args.iter();
    while let Some(word) = words.next() {
        match word.to_str() {
            Some("--pid") => {
                let pid = words
                    .next()
                    .and_then(|p| p.to_str())
                    .and_then(|p| p.parse::<i32>().ok())
                    .filter(|&p| p > 0)
                    .ok_or("--pid: нужен номер процесса")?;
                out.pid = Some(pid);
            }
            Some("--restart") => out.restart = true,
            _ => {
                return Err(format!(
                    "cellward window-menu [--pid <pid>] [--restart], не {}",
                    word.to_string_lossy()
                ))
            }
        }
    }
    Ok(out)
}

/// `vpn-zone window-menu [--pid <pid>] [--restart]`: what can be done with the
/// program of the focused window — for a key binding of the compositor —,
/// or of the launch of `--pid` — for the frame's buttons, whose window may
/// not have the focus.
pub fn menu(tools: &Tools, args: &[OsString]) -> u8 {
    let notify = |title: &str, body: &str| {
        crate::dialog::notify(&tools.notify_send, None, "5000", title, body);
    };
    let args = match parse_menu_args(args) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let window = match args.pid {
        // Nothing of the window but its pid: its launch names the program.
        Some(pid) => Window {
            pid,
            ..Window::default()
        },
        None => match focused_window() {
            Ok(Some(w)) => w,
            Ok(None) => {
                notify(crate::dialog::APP, "Нет окна в фокусе");
                return 0;
            }
            Err(e) => {
                eprintln!("cellward window-menu: {e}");
                notify(crate::dialog::APP, &e);
                return 1;
            }
        },
    };
    // Held from here on: the menu may stay open a while, and a number can
    // change hands in that time — "close" reaches this process or nobody.
    let target = crate::sys::pidfd_open(window.pid);
    if args.pid.is_some() && target.is_none() {
        notify(crate::dialog::APP, "Программа уже закрылась");
        return 0;
    }
    let launch = launch_with_tools(tools, window.pid);
    let program = launch.as_ref().and_then(|l| l.program.clone());
    let label = window_name(&tools.state, &window, launch.as_ref());
    let pin = launch.as_ref().map_or(Pin::Nothing, |l| pin_of(tools, l));
    let menu = crate::window::Menu {
        title: label.clone(),
        notes: vec![describe(&tools.state, &window, launch.as_ref())],
        // Not offered for a system zone's window: see "kill-zone" below.
        actions: menu_entries(&label, launch.as_ref(), &pin)
            .into_iter()
            .filter(|(tag, _, _)| {
                tag != "kill-zone"
                    || !launch
                        .as_ref()
                        .is_some_and(|l| crate::system::run_dir(&l.zone).exists())
            })
            .collect(),
        ..Default::default()
    };
    let choice = if args.restart {
        // The frame's ⇄: the restart with a network chosen — where the menu
        // would offer it (a program of the registry); still confirmed below.
        if !menu.actions.iter().any(|(tag, _, _)| tag == "restart") {
            notify(
                &label,
                "Не известно, какая это программа, — её не перезапустить с выбором сети",
            );
            return 1;
        }
        "restart".to_owned()
    } else {
        let Some(choice) = ask_menu(tools, &menu) else {
            return 0;
        };
        choice
    };
    let confirm = |text: String| {
        crate::dialog::confirm(
            &tools.kdialog,
            [
                "--title",
                crate::dialog::APP,
                "--warningcontinuecancel",
                text.as_str(),
            ],
        )
    };
    match choice.as_str() {
        "pin" => {
            let (Some(p), Some(l)) = (&program, &launch) else {
                return 0;
            };
            let network = crate::container::Network::Named(l.zone.clone());
            let done = match &pin {
                Pin::Bind(container) => crate::container::set_network(tools, container, &network)
                    .map(|()| format!("Контейнер «{container}» теперь всегда {}", in_net(&l.zone))),
                Pin::Main => crate::container::main_for_network(tools, &l.zone).and_then(|name| {
                    let dir = tools.state.join(".pinnedprofile");
                    fs::create_dir_all(&dir)
                        .and_then(|()| fs::write(dir.join(p), &name))
                        .map_err(|e| e.to_string())
                        .map(|()| {
                            format!(
                                "Теперь в контейнере «{name}»: основной дом, всегда {}",
                                in_net(&l.zone)
                            )
                        })
                }),
                _ => return 0,
            };
            match done {
                Ok(text) => notify(&label, &text),
                Err(e) => notify(&label, &e),
            }
        }
        "unpin" => {
            if let Pin::Unbind { container, .. } = &pin {
                match crate::container::set_network(
                    tools,
                    container,
                    &crate::container::Network::Ask,
                ) {
                    Ok(()) => notify(
                        &label,
                        &format!("Сеть контейнера «{container}» спросится при следующем запуске"),
                    ),
                    Err(e) => notify(&label, &e),
                }
            }
        }
        "close" => {
            if !target
                .as_ref()
                .is_some_and(|fd| crate::sys::pidfd_signal(fd, libc::SIGTERM))
            {
                notify(&label, "Программа уже закрылась");
            }
        }
        "restart" => {
            let Some(p) = &program else { return 0 };
            if !confirm(format!(
                "«{label}» закроется и запустится снова с выбором сети и контейнера. \
                 Несохранённое в ней может пропасть."
            )) {
                return 0;
            }
            // No descriptor: the process was gone before the menu came up.
            // Waited for as long as closing takes, no clock of ours: a program
            // asking whether to save, or slow on a loaded machine, is closing
            // all the same, and a deadline would cancel the restart exactly
            // then. When it is not quick, the person decides
            // (`closed_after_all`).
            if let Some(fd) = &target {
                crate::sys::pidfd_signal(fd, libc::SIGTERM);
                if !crate::sys::pidfd_wait(fd, SAY_CLOSING_AFTER)
                    && !closed_after_all(tools, &label, fd)
                {
                    return 0;
                }
            }
            // Through the picker, asked: the launch window with both questions.
            let started = Command::new(&tools.runner)
                .args(["launch", p.as_str()])
                .env(crate::picker::ENV_ASK, "1")
                .stdin(Stdio::null())
                .spawn();
            if let Err(e) = started {
                notify(&label, &format!("Не запустилась: {e}"));
                return 1;
            }
        }
        "kill-zone" => {
            let Some(l) = &launch else { return 0 };
            // A system zone goes by its bare name too, and is no user's to
            // cut: `kill` knows user zones only, and would have cut one of
            // the same name, or nothing at all, without a word (review
            // 2026-09-27).
            if crate::system::run_dir(&l.zone).exists() {
                notify(
                    &label,
                    &format!("{} — системная зона: оборвать её отсюда нельзя", l.zone),
                );
                return 1;
            }
            if !confirm(format!(
                "Оборвать сеть {}? Все её программы сразу останутся без сети, зона опустится.",
                l.zone
            )) {
                return 0;
            }
            let done = Command::new(&tools.runner)
                .args(["kill", l.zone.as_str()])
                .status();
            if !done.as_ref().is_ok_and(|s| s.success()) {
                let why = done.map_or_else(|e| e.to_string(), |s| s.to_string());
                notify(&label, &format!("Сеть {} не оборвана ({why})", l.zone));
                return 1;
            }
        }
        other => eprintln!("cellward window-menu: неизвестный выбор {other}"),
    }
    0
}

/// What `window-focus` is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttentionArgs {
    /// The launch of this pid (`--pid`): its supervisor's, which every window
    /// of a program behind the Wayland proxy has (`crate::wl_proxy`).
    pub pid: i32,
    /// A question (`--ask`) rather than a notification.
    pub ask: bool,
}

/// `--pid <pid> [--ask]`.
pub fn parse_attention_args(args: &[OsString]) -> Result<AttentionArgs, String> {
    const USAGE: &str = "cellward window-focus --pid <pid> [--ask]";
    let mut pid = None;
    let mut ask = false;
    let mut words = args.iter();
    while let Some(word) = words.next() {
        match word.to_str() {
            Some("--pid") => {
                pid = Some(
                    words
                        .next()
                        .and_then(|p| p.to_str())
                        .and_then(|p| p.parse::<i32>().ok())
                        .filter(|&p| p > 0)
                        .ok_or("--pid: нужен номер процесса")?,
                );
            }
            Some("--ask") => ask = true,
            _ => return Err(format!("{USAGE}, не {}", word.to_string_lossy())),
        }
    }
    Ok(AttentionArgs {
        pid: pid.ok_or(USAGE)?,
        ask,
    })
}

/// The windows of the process `pid` in `niri msg --json windows`: their ids.
pub fn windows_of_niri(v: &Value, pid: i32) -> Vec<i64> {
    v.as_array()
        .unwrap_or(&[])
        .iter()
        .filter(|w| w.get("pid").and_then(Value::as_i64) == Some(i64::from(pid)))
        .filter_map(|w| w.get("id").and_then(Value::as_i64))
        .collect()
}

/// The windows of the process `pid` in `swaymsg -t get_tree`: the ids of the
/// nodes with that pid, tiled and floating.
pub fn windows_of_sway(v: &Value, pid: i32) -> Vec<i64> {
    let mut out = Vec::new();
    sway_nodes_of(v, i64::from(pid), &mut out);
    out
}

fn sway_nodes_of(v: &Value, pid: i64, out: &mut Vec<i64>) {
    if v.get("pid").and_then(Value::as_i64) == Some(pid) {
        if let Some(id) = v.get("id").and_then(Value::as_i64) {
            out.push(id);
        }
    }
    for child in ["nodes", "floating_nodes"]
        .iter()
        .filter_map(|k| v.get(k).and_then(Value::as_array))
        .flatten()
    {
        sway_nodes_of(child, pid, out);
    }
}

/// Give the focus to a window of the launch `pid` (a window's pid as the
/// compositor has it) through the compositor's IPC: the newest of them, by
/// the compositor's numbering — niri does not promise to keep its ids in
/// order, and at worst it is another window of the same launch.
pub fn focus_launch(pid: i32) -> Result<(), String> {
    const NONE: &str = "у программы нет окна";
    let (program, args): (&str, Vec<String>) = match compositor() {
        Some(Compositor::Niri) => {
            let windows = run_json("niri", &["msg", "--json", "windows"])?;
            let id = windows_of_niri(&windows, pid)
                .into_iter()
                .max()
                .ok_or(NONE)?;
            (
                "niri",
                vec![
                    "msg".into(),
                    "action".into(),
                    "focus-window".into(),
                    "--id".into(),
                    id.to_string(),
                ],
            )
        }
        Some(Compositor::Sway) => {
            let tree = run_json("swaymsg", &["-t", "get_tree", "-r"])?;
            let id = windows_of_sway(&tree, pid).into_iter().max().ok_or(NONE)?;
            ("swaymsg", vec![format!("[con_id={id}] focus")])
        }
        None => {
            return Err(
                "композитор не отвечает: нужен niri (NIRI_SOCKET) или sway (SWAYSOCK)".to_owned(),
            )
        }
    };
    let done = Command::new(program)
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("{program}: {e}"))?;
    if !done.success() {
        return Err(format!("{program} {} — не вышло", args.join(" ")));
    }
    Ok(())
}

/// `vpn-zone window-focus --pid <pid> [--ask]`: a program of the launch of
/// `pid` asked for the focus, and its container's policy held the request
/// back (`notify`, `ask`; `crate::wl_focus`). The person is told — a
/// notification «<программа> просит внимания» with «Перейти» — or asked
/// («Переключить фокус на <программа>?»), and the focus goes to a window of
/// that launch on their word alone, through the compositor's IPC
/// ([`focus_launch`]).
///
/// Started by the launch's supervisor in a unit of `systemd --user`
/// (`crate::wl_proxy`), one at a time: the manager's environment has the
/// compositor's IPC, where the launch's has none — niri gives the manager
/// its `NIRI_SOCKET` itself, sway's `SWAYSOCK` comes from the module's
/// snippet or home-manager's sway module. The notification goes with the
/// program it is about, and nothing is focused for a program that has
/// ended: the process is held by a pidfd from the start, not by its
/// number.
pub fn attention(tools: &Tools, args: &[OsString]) -> u8 {
    let args = match parse_attention_args(args) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let Some(target) = crate::sys::pidfd_open(args.pid) else {
        return 0;
    };
    let window = Window {
        pid: args.pid,
        ..Window::default()
    };
    let launch = launch_with_tools(tools, args.pid);
    let label = window_name(&tools.state, &window, launch.as_ref());
    let about = describe(&tools.state, &window, launch.as_ref());
    let yes = if args.ask {
        ask_focus(tools, &label, &about)
    } else {
        notify_focus(tools, &target, &label, &about)
    };
    // Signal 0: whether it is still there, as the same process.
    if !yes || !crate::sys::pidfd_signal(&target, 0) {
        return 0;
    }
    match focus_launch(args.pid) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("cellward window-focus: {e}");
            crate::dialog::notify(&tools.notify_send, None, "5000", &label, &e);
            1
        }
    }
}

/// The notification, with «Перейти»: whether the person chose it before it
/// closed — and before the program ended, which ends it.
fn notify_focus(tools: &Tools, target: &OwnedFd, label: &str, about: &str) -> bool {
    // `-A` waits for the answer and prints the action's name.
    let child = Command::new(&tools.notify_send)
        .arg("-a")
        .arg(crate::dialog::APP)
        .arg("--action=focus=Перейти")
        // `--`: a label may start with a dash.
        .arg("--")
        .arg(format!("{label} просит внимания"))
        // The body is markup to most notification daemons.
        .arg(markup(about))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(child) = child else {
        return false;
    };
    while_alive(target, child)
        .and_then(|child| child.wait_with_output().ok())
        .is_some_and(|out| String::from_utf8_lossy(&out.stdout).trim() == "focus")
}

/// The question: whether the person said to switch. In the launch window as
/// a guarded question (`crate::window::question`): nothing is taken until
/// the person has been still with it focused — it takes the focus itself,
/// and keys typed on, meant for another window, must not answer it; Enter,
/// the default, leaves the focus where it was. kdialog where there is no
/// window: its default button leaves it too, and a "switch" sooner than
/// [`crate::dialog::TOO_FAST`] after its start is taken for a stray key.
fn ask_focus(tools: &Tools, label: &str, about: &str) -> bool {
    let question = format!("Переключить фокус на {label}?");
    let answers = [
        ("stay", "Не переключать", false),
        ("focus", "Переключить", false),
    ];
    match crate::window::question(
        &tools.window,
        crate::dialog::APP,
        &format!("{question}\n{about}"),
        None,
        &answers,
        None,
    ) {
        crate::window::Asked::Chose(tag) => return tag == "focus",
        crate::window::Asked::NotShown => {}
        _ => return false,
    }
    let asked = std::time::Instant::now();
    // kdialog shows it in a QLabel, which takes `<` for rich text.
    let text = format!("{question}\n{about}")
        .replace('<', "‹")
        .replace('>', "›")
        .replace('&', "＆");
    let answer = Command::new(&tools.kdialog)
        .args(["--title", crate::dialog::APP, "--yesno"])
        .arg(text)
        .args(["--yes-label", "Не переключать", "--no-label", "Переключить"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    answer.is_ok_and(|s| s.code() == Some(1)) && crate::dialog::not_too_soon(asked).is_ok()
}

/// Wait for `dialog` to end, or for the process `target` to: a notice goes
/// with the program it is about. The dialog, ended, to be read; `None` when
/// the program ended first — the dialog is ended then.
fn while_alive(target: &OwnedFd, mut dialog: Child) -> Option<Child> {
    let Some(ended) = crate::sys::pidfd_open(dialog.id() as i32) else {
        // No descriptor to wait on: the dialog alone decides.
        return Some(dialog);
    };
    let pollin = |fd: &OwnedFd| libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let mut fds = [pollin(target), pollin(&ended)];
    loop {
        // SAFETY: two valid pollfds for the duration of the call.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if rc < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        break;
    }
    if fds[1].revents == 0 && fds[0].revents != 0 {
        let _ = dialog.kill();
        let _ = dialog.wait();
        return None;
    }
    Some(dialog)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_focused_window_is_found_in_what_niri_and_sway_say() {
        let niri =
            json::parse(r#"{"id":3,"title":"t","app_id":"firefox","pid":77,"is_focused":true}"#)
                .unwrap();
        assert_eq!(
            window_from_niri(&niri),
            Some(Window {
                pid: 77,
                app_id: "firefox".to_owned(),
                title: "t".to_owned()
            })
        );
        assert_eq!(window_from_niri(&Value::Null), None);
        let sway = json::parse(
            r#"{"type":"root","focused":false,"nodes":[{"type":"output","focused":false,"nodes":[
                {"type":"workspace","focused":false,"nodes":[
                   {"type":"con","focused":false,"pid":10,"app_id":"foot","name":"a"},
                   {"type":"con","focused":true,"pid":11,"app_id":null,"name":"b",
                    "window_properties":{"class":"Steam"}}]}]}],"floating_nodes":[]}"#,
        )
        .unwrap();
        let w = window_from_sway(&sway).unwrap();
        assert_eq!(
            (w.pid, w.app_id.as_str(), w.title.as_str()),
            (11, "Steam", "b")
        );
    }

    /// What the menu offers follows what is known: a program of the registry
    /// can be pinned or restarted; a real zone can be cut off; the host cannot.
    #[test]
    fn the_menu_offers_what_is_known_of_the_window() {
        let launch = Launch {
            zone: "nl".to_owned(),
            selector: Some(String::new()),
            program: Some("firefox".to_owned()),
        };
        let tags =
            |e: Vec<(String, String, bool)>| e.into_iter().map(|(t, _, _)| t).collect::<Vec<_>>();
        assert_eq!(
            tags(menu_entries("Лис", Some(&launch), &Pin::Main)),
            ["pin", "restart", "close", "kill-zone"]
        );
        assert_eq!(
            tags(menu_entries(
                "Лис",
                Some(&launch),
                &Pin::Bind("work".into())
            )),
            ["pin", "restart", "close", "kill-zone"]
        );
        let unbind = Pin::Unbind {
            container: "work".into(),
            network: "nl".into(),
        };
        let entries = menu_entries("Лис", Some(&launch), &unbind);
        assert_eq!(
            tags(entries.clone()),
            ["unpin", "restart", "close", "kill-zone"]
        );
        assert!(entries[0].1.contains("«work»"), "{entries:?}");
        // A throwaway container, a network from Nix: nothing to pin.
        assert_eq!(
            tags(menu_entries("Лис", Some(&launch), &Pin::Nothing)),
            ["restart", "close", "kill-zone"]
        );
        let host = Launch {
            zone: crate::launch::UNCONFINED.to_owned(),
            ..Launch::default()
        };
        assert_eq!(
            tags(menu_entries("x", Some(&host), &Pin::Nothing)),
            ["close"]
        );
        assert_eq!(tags(menu_entries("x", None, &Pin::Nothing)), ["close"]);
        let entries = menu_entries("Лис", Some(&launch), &Pin::Main);
        assert!(entries[3].2, "cutting a zone off is marked as dangerous");
        assert!(entries[3].1.contains("nl"));
    }

    /// `window-menu`: the focused window's by default, a launch's by
    /// `--pid`, straight to the restart by `--restart`; anything else is
    /// refused, not guessed at.
    #[test]
    fn the_window_menu_takes_a_pid_and_a_restart() {
        let parse =
            |args: &[&str]| parse_menu_args(&args.iter().map(OsString::from).collect::<Vec<_>>());
        assert_eq!(parse(&[]), Ok(MenuArgs::default()));
        assert_eq!(
            parse(&["--pid", "4242"]),
            Ok(MenuArgs {
                pid: Some(4242),
                restart: false
            })
        );
        assert_eq!(
            parse(&["--pid", "4242", "--restart"]),
            Ok(MenuArgs {
                pid: Some(4242),
                restart: true
            })
        );
        assert_eq!(
            parse(&["--restart"]),
            Ok(MenuArgs {
                pid: None,
                restart: true
            })
        );
        for bad in [
            &["--pid"][..],
            &["--pid", "x"],
            &["--pid", "0"],
            &["--pid", "-5"],
            &["--pid", ""],
            &["--menu"],
            &["4242"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn one_network_is_all_of_them_agreeing() {
        let n = |v: &[&str]| one_network(v.iter().map(|s| s.to_string()));
        assert_eq!(n(&["nl", "nl"]).as_deref(), Some("nl"));
        assert_eq!(n(&["nl"]).as_deref(), Some("nl"));
        assert_eq!(n(&["nl", "de"]), None);
        assert_eq!(n(&[]), None);
    }

    /// A window behind the Wayland proxy has the supervisor's pid: its launch is
    /// that pid's record, its network the one of the supervisor's children.
    #[test]
    fn a_window_of_a_proxied_program_is_found_through_the_supervisor() {
        let state = std::env::temp_dir().join(format!("vz-focus-proxy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&state);
        let running = state.join(".running");
        let dir = running.join("sb:work");
        fs::create_dir_all(&dir).unwrap();
        let find = |name: &str| {
            std::env::var_os("PATH")
                .and_then(|p| {
                    std::env::split_paths(&p)
                        .map(|d| d.join(name))
                        .find(|p| p.is_file())
                })
                .unwrap()
        };
        // The supervisor: a shell under the supervisor's name (the kernel
        // takes the name of the file run), with a `sleep` for its program and
        // one more under the proxy's name.
        let supervisor_name = state.join(crate::wl_proxy::SUPERVISOR_NAME);
        let proxy_name = state.join(crate::wl_proxy::PROCESS_NAME);
        std::os::unix::fs::symlink(find("bash"), &supervisor_name).unwrap();
        std::os::unix::fs::symlink(find("sleep"), &proxy_name).unwrap();
        let mut supervisor = Command::new(&supervisor_name)
            .args(["-c", "(exec -a sleep \"$0\" 5) & sleep 5 & wait"])
            .arg(&proxy_name)
            .spawn()
            .unwrap();
        let sup = supervisor.id() as i32;
        for _ in 0..200 {
            if children(sup).len() == 2 && comm(sup) == crate::wl_proxy::SUPERVISOR_NAME {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        fs::write(
            dir.join("foot"),
            format!("{sup} {} sb:work\n", crate::launch::UNCONFINED),
        )
        .unwrap();
        // The file the kernel runs for it: "our vpn-zone-core" in this test.
        let core = find("bash");
        // The name alone is not a supervisor: no launch on record yet, and
        // then a file that is not ours — no network, not the children's.
        assert!(matches!(
            proxied(&state, &core, None, sup),
            Proxied::Unknown
        ));
        registry::note_start(&running, sup, false).unwrap();
        assert!(matches!(
            proxied(&state, &find("sleep"), None, sup),
            Proxied::Unknown
        ));
        assert!(launch_of(&state, &find("sleep"), sup).is_none());
        // Taken for a supervisor, its network is its children's; a child is
        // taken for itself.
        assert!(
            matches!(proxied(&state, &core, None, sup), Proxied::Yes(ref z) if z == crate::launch::UNCONFINED)
        );
        assert!(matches!(
            proxied(&state, &core, None, children(sup)[0]),
            Proxied::No
        ));
        let launch = launch_of(&state, &core, sup).unwrap();
        assert_eq!(launch.zone, crate::launch::UNCONFINED);
        // A child in the host's network running the starter — the
        // supervisor's `systemd-run` of a window menu — is not counted: here
        // the "program" runs `sleep`, and taken for the starter, no child is
        // left to tell the network by.
        assert!(matches!(
            proxied(&state, &core, Some(&find("sleep")), sup),
            Proxied::Unknown
        ));
        assert!(matches!(
            proxied(&state, &core, Some(&find("bash")), sup),
            Proxied::Yes(_)
        ));
        assert_eq!(launch.program.as_deref(), Some("foot"));
        assert_eq!(launch.selector.as_deref(), Some("sb:work"));
        for child in children(sup) {
            // SAFETY: a plain signal to a child of our child, still running.
            unsafe { libc::kill(child, libc::SIGKILL) };
        }
        let _ = supervisor.kill();
        let _ = supervisor.wait();
        let _ = fs::remove_dir_all(&state);
    }

    /// Up the parent chain to the registry: a child of the recorded launch is
    /// that launch — when the record is certainly still that process and in
    /// the network the kernel says.
    #[test]
    fn a_window_of_a_child_is_found_through_its_parents() {
        let state = std::env::temp_dir().join(format!("vz-focus-{}", std::process::id()));
        let _ = fs::remove_dir_all(&state);
        let running = state.join(".running");
        let dir = running.join("sb:work");
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(state.join(".labels")).unwrap();
        fs::write(state.join(".labels").join("firefox"), "Огненный <лис>").unwrap();
        // This test process is "the launch"; a child of it is "the window".
        // Both are in our own namespace — the host's, to this command.
        let me = std::process::id() as i32;
        let record = |zone: &str| {
            fs::write(dir.join("firefox"), format!("{me} {zone} sb:work\n")).unwrap();
        };
        let mut child = Command::new("sleep").arg("5").spawn().unwrap();
        let window = child.id() as i32;

        // A record from before start times were kept: its pid may be anybody's
        // by now. The network is still the kernel's; the container is unknown.
        record(crate::launch::UNCONFINED);
        let bare = launch_of(&state, Path::new(""), window).unwrap();
        assert_eq!(bare.zone, crate::launch::UNCONFINED);
        assert_eq!((bare.selector, bare.program), (None, None));

        // With its start time on record: the launch.
        registry::note_start(&running, me, false).unwrap();
        let launch = launch_of(&state, Path::new(""), window).unwrap();
        assert_eq!(launch.zone, crate::launch::UNCONFINED);
        assert_eq!(launch.selector.as_deref(), Some("sb:work"));
        assert_eq!(launch.program.as_deref(), Some("firefox"));

        // A record that says "nl" of a process in the host's namespace does
        // not make the window a zone's: the kernel says host, and host it is.
        record("nl");
        let host = launch_of(&state, Path::new(""), window).unwrap();
        assert_eq!(host.zone, crate::launch::UNCONFINED);
        assert_eq!(host.program, None);

        // A start time of somebody else: the number was reused.
        record(crate::launch::UNCONFINED);
        fs::write(running.join(registry::STARTED).join(me.to_string()), "1\n").unwrap();
        assert_eq!(
            launch_of(&state, Path::new(""), window).unwrap().program,
            None
        );
        let _ = child.kill();
        let _ = child.wait();

        let w = Window {
            pid: 1,
            app_id: "fire\nfox".to_owned(),
            title: String::new(),
        };
        assert_eq!(
            describe(&state, &w, Some(&launch)),
            "Огненный <лис>: без ограничений, контейнер: песочница work"
        );
        // Markup is escaped for the bar: waybar parses it.
        assert_eq!(
            bar_line(&state, Some(&w), Some(&launch)),
            "{\"text\":\"без ограничений · песочница work\",\"tooltip\":\"Огненный &lt;лис&gt;: без ограничений, контейнер: песочница work\",\"class\":\"zone-unconfined\"}"
        );
        // Nothing but the app id: shown without its line break.
        assert!(describe(&state, &w, None).starts_with("«firefox»: "));
        // Bidi controls are cut: they could make the network read otherwise.
        assert_eq!(shown("a\u{202E}b\u{2066}c"), "abc");
        let _ = fs::remove_dir_all(&state);
    }

    /// `window-focus`: a launch's pid, and a question by `--ask`; anything
    /// else is refused, not guessed at.
    #[test]
    fn the_focus_notice_takes_a_pid_and_a_question() {
        let parse = |args: &[&str]| {
            parse_attention_args(&args.iter().map(OsString::from).collect::<Vec<_>>())
        };
        assert_eq!(
            parse(&["--pid", "4242"]),
            Ok(AttentionArgs {
                pid: 4242,
                ask: false
            })
        );
        assert_eq!(
            parse(&["--ask", "--pid", "7"]),
            Ok(AttentionArgs { pid: 7, ask: true })
        );
        for bad in [
            &[][..],
            &["--ask"],
            &["--pid"],
            &["--pid", "0"],
            &["--pid", "x"],
            &["--pid", "7", "--restart"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    /// The windows of a launch in what niri and sway say: every one with its
    /// pid, tiled or floating, and none of another's.
    #[test]
    fn the_windows_of_a_launch_are_found_by_its_pid() {
        let niri = json::parse(
            r#"[{"id":3,"pid":77,"app_id":"a"},{"id":9,"pid":77,"app_id":"b"},
                {"id":5,"pid":78},{"id":6,"pid":null}]"#,
        )
        .unwrap();
        assert_eq!(windows_of_niri(&niri, 77), [3, 9]);
        assert!(windows_of_niri(&niri, 1).is_empty());
        assert!(windows_of_niri(&Value::Null, 77).is_empty());
        let sway = json::parse(
            r#"{"id":1,"type":"root","nodes":[{"id":2,"type":"output","nodes":[
                {"id":3,"type":"workspace","nodes":[
                   {"id":10,"type":"con","pid":77,"app_id":"a"},
                   {"id":11,"type":"con","pid":78}],
                 "floating_nodes":[{"id":12,"type":"floating_con","pid":77}]}]}],
               "floating_nodes":[]}"#,
        )
        .unwrap();
        assert_eq!(windows_of_sway(&sway, 77), [10, 12]);
        assert_eq!(windows_of_sway(&sway, 78), [11]);
        assert!(windows_of_sway(&sway, 1).is_empty());
    }
}
