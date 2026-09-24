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
//! A program that detached from its parent (a double fork, reparented to init)
//! is not found that way. Its network still is, by its network namespace
//! against the zones' — the container is then unknown, and said so. A window
//! whose namespace is the one this command runs in is the host's own.
//!
//! This reads what the compositor says about a window; a window cannot lie
//! about its pid (the kernel's `SO_PEERCRED`), but a program can pretend to be
//! another in its title — nothing here trusts the title.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};

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
    fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("PPid:"))
        .and_then(|v| v.trim().parse().ok())
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

/// The launch of the process `pid`: up its parent chain to a registry record,
/// or else its network by its namespace.
pub fn launch_of(state: &Path, pid: i32) -> Option<Launch> {
    let index = registry_index(&state.join(".running"));
    let mut at = pid;
    for _ in 0..64 {
        if let Some((_, program, record)) = index.get(&at) {
            return Some(Launch {
                zone: record.zone.clone(),
                selector: Some(record.selector.clone()),
                program: Some(program.clone()),
            });
        }
        match parent(at) {
            Some(p) if p > 1 => at = p,
            _ => break,
        }
    }
    // Detached from its launch: the network by the namespace.
    let ns = netns(&pid.to_string())?;
    if netns("self").as_deref() == Some(ns.as_str()) {
        return Some(Launch {
            zone: crate::launch::UNCONFINED.to_owned(),
            ..Launch::default()
        });
    }
    for entry in fs::read_dir(state).into_iter().flatten().flatten() {
        let name = entry.file_name();
        let Some(zone_pid) = crate::cli::zone_pid(state, &name) else {
            continue;
        };
        if netns(&zone_pid.to_string()).as_deref() == Some(ns.as_str()) {
            return Some(Launch {
                zone: name.to_string_lossy().into_owned(),
                ..Launch::default()
            });
        }
    }
    None
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

/// One line for a person.
pub fn describe(state: &Path, window: &Window, launch: Option<&Launch>) -> String {
    let name = launch
        .and_then(|l| l.program.as_deref())
        .map(|p| label(state, p))
        .unwrap_or_else(|| {
            if window.app_id.is_empty() {
                format!("pid {}", window.pid)
            } else {
                window.app_id.clone()
            }
        });
    match launch {
        None => format!("{name}: не запуск vpn-zones — его сеть не известна"),
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
        json::quote(&text),
        json::quote(&tooltip),
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
            eprintln!("vpn-zone focused: {e}");
            return 1;
        }
    };
    let launch = window.as_ref().and_then(|w| launch_of(&tools.state, w.pid));
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
            eprintln!("vpn-zone focused [--json | --bar | --watch], не {other}");
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
            eprintln!("vpn-zone focused --watch: нужен niri или sway");
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
            eprintln!("vpn-zone focused --watch: {program}: {e}");
            return 1;
        }
    };
    let Some(stdout) = child.stdout.take() else {
        return 1;
    };
    let mut last = String::new();
    let mut show = || {
        let window = focused_window().ok().flatten();
        let launch = window.as_ref().and_then(|w| launch_of(&tools.state, w.pid));
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

/// The entries of the hotkey menu for the program of a window: `(tag, label,
/// danger)`. `pinned` is the network the program is pinned to, if any.
pub fn menu_entries(
    label: &str,
    launch: Option<&Launch>,
    pinned: Option<&str>,
) -> Vec<(String, String, bool)> {
    let mut out = Vec::new();
    let entry = |tag: &str, text: String, danger: bool| (tag.to_owned(), text, danger);
    if let Some(l) = launch.filter(|l| l.program.is_some()) {
        match pinned {
            Some(zone) => out.push(entry(
                "unpin",
                format!(
                    "Спрашивать сеть при запуске «{label}» (сейчас всегда {})",
                    in_net(zone)
                ),
                false,
            )),
            None => out.push(entry(
                "pin",
                format!("Всегда запускать «{label}» {}", in_net(&l.zone)),
                false,
            )),
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
        menu.notes.join("\n").into(),
    ];
    for (tag, label, _) in &menu.actions {
        argv.push(tag.into());
        argv.push(label.into());
    }
    crate::dialog::ask(&tools.kdialog, &argv)
}

/// Is the process still there?
fn alive(pid: i32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// `vpn-zone window-menu`: what can be done with the program of the focused
/// window — for a key binding of the compositor.
pub fn menu(tools: &Tools) -> u8 {
    let notify = |title: &str, body: &str| {
        crate::dialog::notify(&tools.notify_send, None, "5000", title, body);
    };
    let window = match focused_window() {
        Ok(Some(w)) => w,
        Ok(None) => {
            notify(crate::dialog::APP, "Нет окна в фокусе");
            return 0;
        }
        Err(e) => {
            eprintln!("vpn-zone window-menu: {e}");
            notify(crate::dialog::APP, &e);
            return 1;
        }
    };
    let launch = launch_of(&tools.state, window.pid);
    let program = launch.as_ref().and_then(|l| l.program.clone());
    let label = program
        .as_deref()
        .map(|p| label(&tools.state, p))
        .unwrap_or_else(|| {
            if window.app_id.is_empty() {
                format!("pid {}", window.pid)
            } else {
                window.app_id.clone()
            }
        });
    let pinned = program
        .as_deref()
        .and_then(|p| crate::cli::read_setting(&tools.state.join(".pinned").join(p)));
    let menu = crate::window::Menu {
        title: label.clone(),
        notes: vec![describe(&tools.state, &window, launch.as_ref())],
        actions: menu_entries(&label, launch.as_ref(), pinned.as_deref()),
    };
    let Some(choice) = ask_menu(tools, &menu) else {
        return 0;
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
            if let (Some(p), Some(l)) = (&program, &launch) {
                let dir = tools.state.join(".pinned");
                let _ = fs::create_dir_all(&dir);
                let _ = fs::write(dir.join(p), &l.zone);
                notify(&label, &format!("Теперь всегда {}", in_net(&l.zone)));
            }
        }
        "unpin" => {
            if let Some(p) = &program {
                let _ = fs::remove_file(tools.state.join(".pinned").join(p));
                notify(&label, "Сеть будет спрошена при следующем запуске");
            }
        }
        "close" => {
            // SAFETY: kill(2) with a pid the compositor named and a plain signal.
            unsafe { libc::kill(window.pid, libc::SIGTERM) };
        }
        "restart" => {
            let Some(p) = &program else { return 0 };
            if !confirm(format!(
                "«{label}» закроется и запустится снова с выбором сети и контейнера. \
                 Несохранённое в ней может пропасть."
            )) {
                return 0;
            }
            // SAFETY: as above.
            unsafe { libc::kill(window.pid, libc::SIGTERM) };
            for _ in 0..100 {
                if !alive(window.pid) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            if alive(window.pid) {
                notify(
                    &label,
                    "Программа не закрылась за 10 секунд — запуск отменён",
                );
                return 1;
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
            if !confirm(format!(
                "Оборвать сеть {}? Все её программы сразу останутся без сети, зона опустится.",
                l.zone
            )) {
                return 0;
            }
            let _ = Command::new(&tools.runner)
                .args(["kill", l.zone.as_str()])
                .status();
        }
        other => eprintln!("vpn-zone window-menu: неизвестный выбор {other}"),
    }
    0
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
            tags(menu_entries("Лис", Some(&launch), None)),
            ["pin", "restart", "close", "kill-zone"]
        );
        assert_eq!(
            tags(menu_entries("Лис", Some(&launch), Some("nl"))),
            ["unpin", "restart", "close", "kill-zone"]
        );
        let host = Launch {
            zone: crate::launch::UNCONFINED.to_owned(),
            ..Launch::default()
        };
        assert_eq!(tags(menu_entries("x", Some(&host), None)), ["close"]);
        assert_eq!(tags(menu_entries("x", None, None)), ["close"]);
        let entries = menu_entries("Лис", Some(&launch), None);
        assert!(entries[3].2, "cutting a zone off is marked as dangerous");
        assert!(entries[3].1.contains("nl"));
    }

    /// Up the parent chain to the registry: a child of the recorded launch is
    /// that launch; the host's own process is the host.
    #[test]
    fn a_window_of_a_child_is_found_through_its_parents() {
        let state = std::env::temp_dir().join(format!("vz-focus-{}", std::process::id()));
        let _ = fs::remove_dir_all(&state);
        let dir = state.join(".running").join("sb:work");
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(state.join(".labels")).unwrap();
        fs::write(state.join(".labels").join("firefox"), "Огненный лис").unwrap();
        // This test process is "the launch"; a child of it is "the window".
        fs::write(
            dir.join("firefox"),
            format!("{} nl sb:work\n", std::process::id()),
        )
        .unwrap();
        let mut child = Command::new("sleep").arg("5").spawn().unwrap();
        let launch = launch_of(&state, child.id() as i32).unwrap();
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(launch.zone, "nl");
        assert_eq!(launch.selector.as_deref(), Some("sb:work"));
        assert_eq!(launch.program.as_deref(), Some("firefox"));
        let w = Window {
            pid: 1,
            app_id: "firefox".to_owned(),
            title: String::new(),
        };
        assert_eq!(
            describe(&state, &w, Some(&launch)),
            "Огненный лис: сеть nl, контейнер: песочница work"
        );
        assert_eq!(
            bar_line(&state, Some(&w), Some(&launch)),
            "{\"text\":\"nl · песочница work\",\"tooltip\":\"Огненный лис: сеть nl, контейнер: песочница work\",\"class\":\"zone-nl\"}"
        );
        // Not in the registry, in our own namespace: the host.
        fs::remove_file(dir.join("firefox")).unwrap();
        let own = launch_of(&state, std::process::id() as i32).unwrap();
        assert_eq!(own.zone, crate::launch::UNCONFINED);
        assert_eq!(own.selector, None);
        let _ = fs::remove_dir_all(&state);
    }
}
