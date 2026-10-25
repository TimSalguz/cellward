//! The launch window's contract: what the picker tells `vpn-zone-window` on
//! its standard input, and what the window answers on its standard output.
//!
//! The window is a program of its own (`window/`, a crate with a toolkit this
//! one does not need): one window with the network and the container side by
//! side, instead of two kdialog menus in a row with every entry twice ("… —
//! всегда"). The picker keeps every decision; the window only shows the
//! choices and brings back which ones were taken. Without it the picker asks
//! with kdialog, as before.
//!
//! One line per item, fields separated by a tab. Nothing a field carries may
//! contain a tab or a line break — [`clean`] takes them out:
//!
//! ```text
//! title⇥<text>
//! lang⇥en|ru                           (optional; omitted means legacy ru)
//! note⇥<text>                         (any number)
//! net⇥<tag>⇥<label>⇥<flags>
//! container⇥<tag>⇥<label>⇥<flags>
//! pin-net⇥0|1
//! pin-container⇥0|1
//! guard⇥<ms>                          (nothing starts before; optional)
//! pins⇥0                              (no "always"; optional)
//! asker⇥<net>                         (a zone asks: Enter starts only there)
//! program⇥<text>                      (what the command runs, on the host)
//! cmd⇥<word>                          (the zone's command, a word each)
//! rule⇥<text>                         (a checkbox of its own: a container's
//!                                      rule for links, `crate::links`)
//! offer⇥<line>⇥<text>                 (what the program's preset offers its
//!                                      container, `crate::presets`: a
//!                                      checkbox each, unticked)
//! perm⇥<key>⇥<label>⇥<value>:<text>;…  (a permission, its choices: one row
//!                                      of the permissions under the lists)
//! permof⇥<tag>⇥<scope>⇥<key>=<value>[!],…
//!                                     (a container's permissions as they
//!                                      are: whom a change is for, and each
//!                                      value — `!` one that cannot be
//!                                      changed here; none: nothing to set)
//! ```
//!
//! Flags, comma-separated: `selected`; `dead` (the tunnel does not answer);
//! `busy=<zone>` (open in that network, so usable only with it); `bound=<zone>`
//! (the container belongs to that network); `new` (choosing it asks for a
//! name). The answer, exit status 0; a close or Esc is exit status 1 and no
//! answer:
//!
//! ```text
//! net⇥<tag>
//! container⇥<tag>
//! name⇥<text>                         (for a `new` container)
//! pin-net⇥0|1
//! pin-container⇥0|1
//! rule⇥0|1                            (where the request had one)
//! offer⇥<line>                        (each offer ticked)
//! perm⇥<key>⇥<value>                  (each permission changed for the
//!                                      container chosen)
//! ```
//!
//! The same window is the hotkey menu of a running program
//! (`crate::focus`): `mode⇥menu`, a title, notes, and one
//! `action⇥<tag>⇥<label>⇥<flags>` per entry (`danger` for one that breaks
//! something); the answer is `action⇥<tag>`. With `guard⇥<ms>` the menu is a
//! question ([`question`]): the answers are the entries, the safe one first,
//! a command it is about goes as `program⇥`/`cmd⇥`, and the window takes
//! nothing until the person has been still for the guard with it focused.
//! Exit status 3: it could not be shown at all.

use std::path::Path;
use std::process::{Child, Command, Stdio};

/// One row of a column.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Item {
    pub tag: String,
    pub label: String,
    pub selected: bool,
    pub dead: bool,
    pub busy: Option<String>,
    pub bound: Option<String>,
    pub new: bool,
}

/// Everything the window shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Request {
    /// Language of the already-rendered labels and the window chrome.
    pub language: crate::i18n::Language,
    pub title: String,
    pub notes: Vec<String>,
    pub nets: Vec<Item>,
    pub containers: Vec<Item>,
    pub pin_net: bool,
    pub pin_container: bool,
    /// Milliseconds after the window opens during which nothing is started:
    /// the answer to a program in a zone that brought the window up, which
    /// takes the focus from whatever the person was typing into.
    pub guard_ms: u64,
    /// No "always" in the window (`crate::picker` from a zone).
    pub no_pins: bool,
    /// The network of the zone that asks: Enter starts only there, another
    /// takes a click on the button that names it.
    pub asker: Option<String>,
    /// What the command's first word is on the host.
    pub program: String,
    /// The zone's command, one word each, shown apart from the notes.
    pub command: Vec<String>,
    /// A checkbox of its own, unticked: the rule a link's program would be
    /// kept by (`crate::links`) — what it says.
    pub rule: Option<String>,
    /// What the program's preset offers its container (`crate::presets`):
    /// `(line, text)`, a checkbox each, unticked.
    pub offers: Vec<(String, String)>,
    /// The permissions a container can be given here, a row each.
    pub perms: Vec<Perm>,
    /// Each container's, by its tag.
    pub perm_of: Vec<PermOf>,
}

/// A permission's row: its key, its name, and its choices `(value, text)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Perm {
    pub key: String,
    pub label: String,
    pub choices: Vec<(String, String)>,
}

/// A container's permissions as they are: whom a change is for (`scope`,
/// for a person), and `(key, value, fixed)` — fixed: not to be changed
/// here (Nix's, or not this container's to say).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PermOf {
    pub tag: String,
    pub scope: String,
    pub values: Vec<(String, String, bool)>,
}

/// The hotkey menu: entries to choose one of.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Menu {
    pub language: crate::i18n::Language,
    pub title: String,
    pub notes: Vec<String>,
    /// `(tag, label, danger)`.
    pub actions: Vec<(String, String, bool)>,
    /// A guarded menu (`guard⇥<ms>`): nothing is taken until the person has
    /// been still this long with the window focused — a question.
    pub guard_ms: u64,
    /// A command the question is about, one word each, shown apart as the
    /// launch window shows one (`cmd⇥`), with what its first word is on the
    /// host (`program⇥`).
    pub command: Vec<String>,
    pub program: String,
}

/// The tag of a line of a menu that is no entry but the heading of those
/// after it (`action⇥#⇥<text>⇥heading`): not to be chosen, never answered.
pub const HEADING: &str = "#";

/// The menu as the window reads it.
pub fn render_menu(menu: &Menu) -> String {
    let mut out = format!("mode\tmenu\ntitle\t{}\n", clean(&menu.title));
    if menu.language != crate::i18n::Language::default() {
        out.push_str(&format!("lang\t{}\n", menu.language.tag()));
    }
    for note in &menu.notes {
        out.push_str(&format!("note\t{}\n", clean(note)));
    }
    for (tag, label, danger) in &menu.actions {
        let flags = if tag == HEADING {
            "heading"
        } else if *danger {
            "danger"
        } else {
            ""
        };
        out.push_str(&format!(
            "action\t{}\t{}\t{flags}\n",
            clean(tag),
            clean(label),
        ));
    }
    if !menu.program.is_empty() {
        out.push_str(&format!("program\t{}\n", clean(&menu.program)));
    }
    for word in &menu.command {
        out.push_str(&format!("cmd\t{}\n", clean(word)));
    }
    if menu.guard_ms > 0 {
        out.push_str(&format!("guard\t{}\n", menu.guard_ms));
    }
    out
}

/// The window, started with `menu` on its standard input; `None` when there
/// is no window to start.
pub fn spawn_menu(window: &Path, menu: &Menu) -> Option<Child> {
    spawn_menu_on(window, None, menu)
}

/// [`spawn_menu`] on the compositor `display` (`WAYLAND_DISPLAY`; none: the
/// one this process has).
pub fn spawn_menu_on(
    window: &Path,
    display: Option<&std::ffi::OsStr>,
    menu: &Menu,
) -> Option<Child> {
    if window.as_os_str().is_empty() {
        return None;
    }
    let mut command = Command::new(window);
    if let Some(display) = display {
        command.env("WAYLAND_DISPLAY", display);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    // From a thread of its own: a window that does not read would otherwise
    // hold this — and the deadline would never start.
    if let Some(mut stdin) = child.stdin.take() {
        let request = render_menu(menu);
        std::thread::spawn(move || {
            let _ = std::io::Write::write_all(&mut stdin, request.as_bytes());
        });
    }
    Some(child)
}

/// The exit status of a window that could not be shown at all (its
/// `EXIT_NOT_SHOWN`): the caller asks another way.
const EXIT_NOT_SHOWN: i32 = 3;

/// The tag a menu window that has ended chose; `None`: closed, Esc.
pub fn menu_answer(child: Child) -> Option<String> {
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    parse_menu_reply(&String::from_utf8_lossy(&out.stdout))
}

/// How a [`question`] ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asked {
    /// The answer's tag.
    Chose(String),
    /// Closed, Esc, or an answer the window did not give.
    Closed,
    /// Not answered by the deadline: the window is gone, and a late answer
    /// counts for nothing.
    NoAnswer,
    /// No window to ask in (the caller asks another way).
    NotShown,
}

/// A question, in the launch window as a guarded menu: it takes nothing —
/// no key, no click — until the person has been still for
/// [`crate::dialog::TOO_FAST`] with it focused, counted from when they can
/// see it, however long the machine took to show it; a key or a click, or
/// the focus coming back, starts that again. `answers` are `(tag, label,
/// danger)`, the safe one first: Enter gives it. `deadline`: past it the
/// window goes, and the question is not answered.
pub fn question(
    window: &Path,
    title: &str,
    text: &str,
    command: Option<(&str, &[String])>,
    answers: &[(&str, &str, bool)],
    deadline: Option<std::time::Duration>,
) -> Asked {
    question_on(window, None, title, text, command, answers, deadline)
}

/// [`question`] on the compositor `display` (`WAYLAND_DISPLAY`; none: the
/// one this process has) — an instance's keeper asks on its launch's,
/// whatever its unit's environment says (`crate::netask`).
pub fn question_on(
    window: &Path,
    display: Option<&std::ffi::OsStr>,
    title: &str,
    text: &str,
    command: Option<(&str, &[String])>,
    answers: &[(&str, &str, bool)],
    deadline: Option<std::time::Duration>,
) -> Asked {
    question_on_cancellable(
        window,
        display,
        title,
        text,
        command,
        answers,
        (deadline, None),
    )
}

/// As `question_on`, but cancellation ends and reaps only this owned window.
/// Dropping an obsolete UI answer is not enough: its worker/window must end.
pub(crate) fn question_on_cancellable(
    window: &Path,
    display: Option<&std::ffi::OsStr>,
    title: &str,
    text: &str,
    command: Option<(&str, &[String])>,
    answers: &[(&str, &str, bool)],
    control: (
        Option<std::time::Duration>,
        Option<&crate::sys::CancelToken>,
    ),
) -> Asked {
    let (deadline, cancel) = control;
    if cancel.is_some_and(|c| c.cancelled()) {
        return Asked::NoAnswer;
    }
    let (program, command) = command.map_or((String::new(), Vec::new()), |(program, words)| {
        (program.to_owned(), words.to_vec())
    });
    let menu = Menu {
        language: crate::i18n::Language::default(),
        title: title.to_owned(),
        notes: text.lines().map(str::to_owned).collect(),
        actions: answers
            .iter()
            .map(|(tag, label, danger)| ((*tag).to_owned(), (*label).to_owned(), *danger))
            .collect(),
        guard_ms: crate::dialog::TOO_FAST.as_millis() as u64,
        command,
        program,
    };
    let Some(mut child) = spawn_menu_on(window, display, &menu) else {
        return Asked::NotShown;
    };
    if let Some(cancel) = cancel {
        let started = std::time::Instant::now();
        let pidfd = crate::sys::pidfd_open(child.id() as i32);
        loop {
            if cancel.cancelled() || deadline.is_some_and(|d| started.elapsed() >= d) {
                let _ = child.kill();
                let _ = child.wait();
                return Asked::NoAnswer;
            }
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {}
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Asked::NoAnswer;
                }
            }
            use std::os::fd::AsRawFd;
            let mut fds = [
                libc::pollfd {
                    fd: cancel.fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: pidfd.as_ref().map_or(-1, |f| f.as_raw_fd()),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // A short poll also covers kernels without pidfds; a finite
            // deadline is checked above after EINTR or scheduler delays.
            let ms = deadline
                .map_or(crate::sys::LOOK_AGAIN, |d| {
                    d.saturating_sub(started.elapsed())
                        .min(crate::sys::LOOK_AGAIN)
                })
                .as_millis()
                .max(1) as i32;
            // SAFETY: initialized retained descriptors; no borrowed pointers.
            if unsafe { libc::poll(fds.as_mut_ptr(), 2, ms) } < 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                let _ = child.kill();
                let _ = child.wait();
                return Asked::NoAnswer;
            }
        }
    } else if let Some(deadline) = deadline {
        let ended = match crate::sys::pidfd_open(child.id() as i32) {
            Some(fd) => crate::sys::pidfd_wait(&fd, deadline),
            None => {
                let started = std::time::Instant::now();
                loop {
                    if matches!(child.try_wait(), Ok(Some(_))) {
                        break true;
                    }
                    if started.elapsed() >= deadline {
                        break false;
                    }
                    std::thread::sleep(crate::sys::LOOK_AGAIN);
                }
            }
        };
        if !ended {
            let _ = child.kill();
            let _ = child.wait();
            return Asked::NoAnswer;
        }
    }
    let Ok(out) = child.wait_with_output() else {
        return Asked::NoAnswer;
    };
    // Ended by a signal — killed, or it never got to show itself: no answer,
    // as a question not answered in time. Not shown at all: asked another way.
    match out.status.code() {
        None => return Asked::NoAnswer,
        Some(EXIT_NOT_SHOWN) => return Asked::NotShown,
        Some(_) => {}
    }
    match parse_menu_reply(&String::from_utf8_lossy(&out.stdout)) {
        Some(tag) if out.status.success() && answers.iter().any(|(t, _, _)| *t == tag) => {
            Asked::Chose(tag)
        }
        _ => Asked::Closed,
    }
}

/// The chosen entry's tag.
pub fn parse_menu_reply(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.strip_prefix("action\t"))
        .map(str::to_owned)
        .filter(|t| !t.is_empty() && t != HEADING)
}

/// A container's permissions in a window of their own (`mode⇥perms`), from
/// the frame's ☰: the rows of the launch window's ([`Perm`]), the
/// container's as they are (its `permof⇥this⇥…`), a title and notes. The
/// window takes nothing before its guard (a program could have brought it
/// up); the answer is `perm⇥<key>⇥<value>` for each changed — none when
/// nothing was, or it was closed.
pub fn render_perms(title: &str, notes: &[String], perms: &[Perm], of: &PermOf) -> String {
    let mut out = format!("mode\tperms\ntitle\t{}\n", clean(title));
    for note in notes {
        out.push_str(&format!("note\t{}\n", clean(note)));
    }
    let req = Request {
        perms: perms.to_vec(),
        perm_of: vec![PermOf {
            tag: "this".to_owned(),
            ..of.clone()
        }],
        ..Request::default()
    };
    for line in render(&req).lines().filter(|l| l.starts_with("perm")) {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str(&format!("guard\t{}\n", crate::dialog::TOO_FAST.as_millis()));
    out
}

/// The permissions a [`render_perms`] window answered: `None` when it was
/// closed or could not be shown, else the changes (maybe none).
pub fn ask_perms(window: &Path, request: &str) -> Option<Vec<(String, String)>> {
    if window.as_os_str().is_empty() {
        return None;
    }
    let mut child = Command::new(window)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    if let Some(mut stdin) = child.stdin.take() {
        let request = request.to_owned();
        std::thread::spawn(move || {
            let _ = std::io::Write::write_all(&mut stdin, request.as_bytes());
        });
    }
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.strip_prefix("perm\t"))
            .filter_map(|l| l.split_once('\t'))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect(),
    )
}

/// What came back.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reply {
    pub net: String,
    pub container: String,
    pub name: Option<String>,
    pub pin_net: bool,
    pub pin_container: bool,
    /// The request's rule ticked.
    pub rule: bool,
    /// The offers ticked, by their lines.
    pub offers: Vec<String>,
    /// The permissions changed for the container chosen: `(key, value)`.
    pub perms: Vec<(String, String)>,
}

/// A field as the format can carry it: tabs and line breaks become spaces.
pub fn clean(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c == '\t' || c == '\n' || c == '\r' {
                ' '
            } else {
                c
            }
        })
        .collect()
}

fn flags(item: &Item) -> String {
    let mut out = Vec::new();
    if item.selected {
        out.push("selected".to_owned());
    }
    if item.dead {
        out.push("dead".to_owned());
    }
    if let Some(zone) = &item.busy {
        out.push(format!("busy={}", clean(zone).replace(',', " ")));
    }
    if let Some(zone) = &item.bound {
        out.push(format!("bound={}", clean(zone).replace(',', " ")));
    }
    if item.new {
        out.push("new".to_owned());
    }
    out.join(",")
}

/// The request as the window reads it.
pub fn render(req: &Request) -> String {
    let mut out = format!("title\t{}\n", clean(&req.title));
    if req.language != crate::i18n::Language::default() {
        out.push_str(&format!("lang\t{}\n", req.language.tag()));
    }
    for note in &req.notes {
        out.push_str(&format!("note\t{}\n", clean(note)));
    }
    for (kind, items) in [("net", &req.nets), ("container", &req.containers)] {
        for item in items {
            out.push_str(&format!(
                "{kind}\t{}\t{}\t{}\n",
                clean(&item.tag),
                clean(&item.label),
                flags(item)
            ));
        }
    }
    out.push_str(&format!("pin-net\t{}\n", u8::from(req.pin_net)));
    out.push_str(&format!("pin-container\t{}\n", u8::from(req.pin_container)));
    if req.guard_ms > 0 {
        out.push_str(&format!("guard\t{}\n", req.guard_ms));
    }
    if req.no_pins {
        out.push_str("pins\t0\n");
    }
    if let Some(asker) = &req.asker {
        out.push_str(&format!("asker\t{}\n", clean(asker)));
    }
    if !req.program.is_empty() {
        out.push_str(&format!("program\t{}\n", clean(&req.program)));
    }
    for word in &req.command {
        out.push_str(&format!("cmd\t{}\n", clean(word)));
    }
    if let Some(rule) = &req.rule {
        out.push_str(&format!("rule\t{}\n", clean(rule)));
    }
    for (line, text) in &req.offers {
        out.push_str(&format!("offer\t{}\t{}\n", clean(line), clean(text)));
    }
    for perm in &req.perms {
        let choices: Vec<String> = perm
            .choices
            .iter()
            .map(|(value, text)| format!("{}:{}", word(value), clean(text).replace(';', ",")))
            .collect();
        out.push_str(&format!(
            "perm\t{}\t{}\t{}\n",
            word(&perm.key),
            clean(&perm.label),
            choices.join(";")
        ));
    }
    for of in &req.perm_of {
        let values: Vec<String> = of
            .values
            .iter()
            .map(|(key, value, fixed)| {
                format!(
                    "{}={}{}",
                    word(key),
                    word(value),
                    if *fixed { "!" } else { "" }
                )
            })
            .collect();
        out.push_str(&format!(
            "permof\t{}\t{}\t{}\n",
            clean(&of.tag),
            clean(&of.scope),
            values.join(",")
        ));
    }
    out
}

/// A key or a value of a permission: letters, digits, `_` and `-` only — the
/// separators of its line never in it.
fn word(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
        .collect()
}

/// The window's answer. `None` when it is not one: no network or no container
/// chosen — a window that crashed half-way must not start anything.
pub fn parse_reply(text: &str) -> Option<Reply> {
    let mut reply = Reply::default();
    let (mut net, mut container) = (None, None);
    for line in text.lines() {
        let (key, value) = line.split_once('\t').unwrap_or((line, ""));
        match key {
            "net" => net = Some(value.to_owned()),
            "container" => container = Some(value.to_owned()),
            "name" => reply.name = Some(value.to_owned()).filter(|v| !v.is_empty()),
            "pin-net" => reply.pin_net = value == "1",
            "pin-container" => reply.pin_container = value == "1",
            "rule" => reply.rule = value == "1",
            "offer" if !value.is_empty() => reply.offers.push(value.to_owned()),
            "perm" => {
                if let Some((key, value)) = value.split_once('\t') {
                    reply.perms.push((key.to_owned(), value.to_owned()));
                }
            }
            _ => {}
        }
    }
    reply.net = net.filter(|n| !n.is_empty())?;
    reply.container = container?;
    Some(reply)
}

#[cfg(test)]
mod tests {
    #[test]
    fn cancelling_a_question_kills_and_reaps_its_owned_window() {
        let root = std::env::temp_dir().join(format!("vz-window-cancel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let window = root.join("window");
        let seen = root.join("pid");
        crate::dialog::test_program(
            &window,
            &format!(
                "#!/bin/sh\nprintf '%s' \"$$\" > '{}'\nexec sleep 20\n",
                seen.display()
            ),
        );
        let cancel = crate::sys::Cancellation::new().unwrap();
        let token = cancel.token();
        let worker = std::thread::spawn(move || {
            super::question_on_cancellable(
                &window,
                None,
                "network",
                "test",
                None,
                &[("deny", "deny", false)],
                (None, Some(&token)),
            )
        });
        let started = std::time::Instant::now();
        let pid = loop {
            if let Some(pid) = std::fs::read_to_string(&seen)
                .ok()
                .and_then(|s| s.parse::<i32>().ok())
            {
                break pid;
            }
            assert!(started.elapsed() < std::time::Duration::from_secs(3));
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        let pidfd = crate::sys::pidfd_open(pid).unwrap();
        drop(cancel);
        assert_eq!(worker.join().unwrap(), super::Asked::NoAnswer);
        assert!(crate::sys::pidfd_wait(&pidfd, std::time::Duration::ZERO));
        std::fs::remove_dir_all(root).unwrap();
    }
    use super::*;

    #[test]
    fn a_request_is_one_line_per_item_and_nothing_breaks_a_line() {
        let req = Request {
            title: "Запуск: Fire\tfox".to_owned(),
            notes: vec!["уже\nработает".to_owned()],
            nets: vec![
                Item {
                    tag: "nl".to_owned(),
                    label: "VPN: nl".to_owned(),
                    selected: true,
                    ..Item::default()
                },
                Item {
                    tag: "de".to_owned(),
                    label: "VPN: de".to_owned(),
                    dead: true,
                    ..Item::default()
                },
            ],
            containers: vec![Item {
                tag: "work".to_owned(),
                label: "Контейнер «work» — слой над домом".to_owned(),
                busy: Some("nl".to_owned()),
                ..Item::default()
            }],
            pin_net: true,
            pin_container: false,
            ..Request::default()
        };
        assert_eq!(
            render(&req),
            "title\tЗапуск: Fire fox\nnote\tуже работает\n\
             net\tnl\tVPN: nl\tselected\nnet\tde\tVPN: de\tdead\n\
             container\twork\tКонтейнер «work» — слой над домом\tbusy=nl\n\
             pin-net\t1\npin-container\t0\n"
        );
    }

    /// A window a zone's program brought up: the guard and no "always" go
    /// along; an ordinary one says neither.
    #[test]
    fn the_guard_and_no_always_are_said_only_when_set() {
        let req = Request {
            guard_ms: 1500,
            no_pins: true,
            ..Request::default()
        };
        assert!(render(&req).ends_with("guard\t1500\npins\t0\n"));
        let plain = render(&Request::default());
        assert!(!plain.contains("guard") && !plain.contains("pins\t"));
    }

    #[test]
    fn explicit_english_language_is_sent_without_changing_protocol_tags() {
        let req = Request {
            language: crate::i18n::Language::English,
            title: "Launch: Firefox".to_owned(),
            ..Request::default()
        };
        assert!(render(&req).starts_with("title\tLaunch: Firefox\nlang\ten\n"));
        let menu = Menu {
            language: crate::i18n::Language::English,
            ..Menu::default()
        };
        assert!(render_menu(&menu).starts_with("mode\tmenu\ntitle\t\nlang\ten\n"));
    }

    #[test]
    fn the_menu_goes_out_one_line_per_entry_and_one_comes_back() {
        let menu = Menu {
            title: "Firefox".to_owned(),
            notes: vec!["сеть nl".to_owned()],
            actions: vec![
                ("close".to_owned(), "Закрыть".to_owned(), false),
                ("kill-zone".to_owned(), "Оборвать сеть nl".to_owned(), true),
            ],
            ..Default::default()
        };
        assert_eq!(
            render_menu(&menu),
            "mode\tmenu\ntitle\tFirefox\nnote\tсеть nl\n\
             action\tclose\tЗакрыть\t\naction\tkill-zone\tОборвать сеть nl\tdanger\n"
        );
        assert_eq!(
            parse_menu_reply("action\tclose\n").as_deref(),
            Some("close")
        );
        assert_eq!(parse_menu_reply("action\t\n"), None);
        assert_eq!(parse_menu_reply(""), None);
    }

    /// A question is a guarded menu, the safe answer first; the answer is
    /// one of those asked, or none — closed, not in time, or no window.
    #[test]
    fn a_question_is_a_guarded_menu_and_its_answer_one_of_those_asked() {
        let dir = std::env::temp_dir().join(format!("vz-question-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let window = dir.join("window");
        let answers = [("deny", "Отказать", false), ("allow", "Разрешить", false)];
        let ask = |script: &str, deadline| {
            crate::dialog::test_program(&window, &format!("#!/bin/sh\n{script}\n"));
            question(&window, "Запуск", "строка\nещё", None, &answers, deadline)
        };
        let seen = dir.join("request");
        let script = format!("cat > '{}'; printf 'action\\tallow\\n'", seen.display());
        assert_eq!(ask(&script, None), Asked::Chose("allow".to_owned()));
        let request = std::fs::read_to_string(&seen).unwrap();
        assert!(request.starts_with("mode\tmenu\ntitle\tЗапуск\nnote\tстрока\nnote\tещё\n"));
        assert!(
            request.contains("action\tdeny\tОтказать\t\naction\tallow"),
            "{request}"
        );
        assert!(request.ends_with("guard\t1500\n"), "{request}");
        // An answer that was not asked for is none.
        assert_eq!(
            ask("cat >/dev/null; printf 'action\\tother\\n'", None),
            Asked::Closed
        );
        assert_eq!(ask("cat >/dev/null; exit 1", None), Asked::Closed);
        assert_eq!(
            ask(
                "cat >/dev/null; sleep 30",
                Some(std::time::Duration::from_millis(300))
            ),
            Asked::NoAnswer
        );
        // Killed, or never shown: no answer either.
        assert_eq!(ask("cat >/dev/null; kill -9 $$", None), Asked::NoAnswer);
        assert_eq!(
            question(Path::new(""), "t", "q", None, &answers, None),
            Asked::NotShown
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The permissions go a line each, their words kept to what the line's
    /// separators cannot be part of.
    #[test]
    fn the_permissions_go_a_line_each() {
        let req = Request {
            perms: vec![Perm {
                key: "x11".to_owned(),
                label: "Свой\tX".to_owned(),
                choices: vec![
                    (
                        "default".to_owned(),
                        "как у всех (выкл.; сейчас)".to_owned(),
                    ),
                    ("on".to_owned(), "вкл.".to_owned()),
                ],
            }],
            perm_of: vec![PermOf {
                tag: "work".to_owned(),
                scope: "Для всех программ «work»".to_owned(),
                values: vec![
                    ("x11".to_owned(), "on".to_owned(), false),
                    ("camera".to_owned(), "no,=!".to_owned(), true),
                ],
            }],
            ..Request::default()
        };
        let text = render(&req);
        assert!(
            text.contains("perm\tx11\tСвой X\tdefault:как у всех (выкл., сейчас);on:вкл.\n"),
            "{text}"
        );
        assert!(
            text.contains("permof\twork\tДля всех программ «work»\tx11=on,camera=no!\n"),
            "{text}"
        );
    }

    #[test]
    fn an_answer_needs_a_network_and_a_container() {
        let reply = parse_reply(
            "net\tnl\ncontainer\t__newsb__\nname\tобщая\npin-net\t1\npin-container\t0\nrule\t1\n\
             offer\tcamera=on\noffer\t\nperm\tx11\ton\nperm\tbroken\n",
        )
        .unwrap();
        assert_eq!(
            reply,
            Reply {
                net: "nl".to_owned(),
                container: "__newsb__".to_owned(),
                name: Some("общая".to_owned()),
                pin_net: true,
                pin_container: false,
                rule: true,
                offers: vec!["camera=on".to_owned()],
                perms: vec![("x11".to_owned(), "on".to_owned())],
            }
        );
        // The main container is the empty tag — present, and empty.
        assert_eq!(
            parse_reply("net\toffline\ncontainer\t\n")
                .unwrap()
                .container,
            ""
        );
        assert_eq!(parse_reply("container\t\n"), None);
        assert_eq!(parse_reply("net\tnl\n"), None);
        assert_eq!(parse_reply(""), None);
    }
}
