//! Connecting a network (`docs/PERMISSIONS.md` §11.16, the owner,
//! 2026-09-29): a network's «Подключение» — `auto`, it comes up when a
//! program is launched into it, as it always did; `ask`, the person is
//! asked first; `manual`, only the person connects it, and a launch into it
//! while it is down asks whether to connect it now.
//!
//! The question is the launch window's, guarded as every question of it is
//! (`crate::window::question`): nothing is taken until the person has been
//! still with it in view. One question per network at a time: launches that
//! want the same network meanwhile wait for its answer and take it —
//! autostart after the login asks once per network, not once per program.
//! Programs wait with no network while it is open: a network that is down
//! has no route out, so nothing goes anywhere meanwhile. «Не подключать», a
//! closed question, or no way to ask at all: the network stays down, and
//! the launch is refused where the person sees it — never a silent end.

use std::ffi::OsStr;
use std::fs;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use crate::cli::{read_setting, DECLARED_DIR};
use crate::container::Source;
use crate::tools::Tools;
use crate::window::Asked;

/// A network's own setting, in its state directory: `auto`, `ask` or
/// `manual`.
pub const SETTING: &str = "connect";
/// The settings declared in Nix (`programs.cellward.connection`), below
/// `declared/`: `<network> <mode>` per line.
pub const DECLARED: &str = "network-connect";
/// In a network's state directory: the lock of its question, and the last
/// answer — `<number> yes|no`, the number counting the questions.
const LOCK: &str = ".connect-lock";
const ANSWER: &str = ".connect-answer";

/// How a network is connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// When a program is launched into it («сразу»).
    Auto,
    /// When a program is launched into it and the person says yes
    /// («спросить»).
    Ask,
    /// Only by the person («только вручную»): a launch into it while it is
    /// down asks whether to connect it now.
    Manual,
}

impl Mode {
    pub const ALL: [Mode; 3] = [Self::Auto, Self::Ask, Self::Manual];

    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        Self::ALL.into_iter().find(|m| m.as_str() == text)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Ask => "ask",
            Self::Manual => "manual",
        }
    }

    /// The owner's words for it.
    pub fn words(self) -> &'static str {
        match self {
            Self::Auto => "сразу (auto)",
            Self::Ask => "спросить (ask)",
            Self::Manual => "только вручную (manual)",
        }
    }
}

/// A network's own setting file.
fn own_file(state: &Path, zone: &str) -> PathBuf {
    state.join(zone).join(SETTING)
}

/// The mode Nix declares for `zone`, if it does.
fn declared(config: &Path, zone: &str) -> Option<Mode> {
    let text = crate::declared::read(&config.join(DECLARED_DIR).join(DECLARED)).ok()?;
    text.lines().find_map(|line| {
        let (name, mode) = line.trim().split_once(char::is_whitespace)?;
        (name == zone).then(|| Mode::parse(mode)).flatten()
    })
}

/// A network's «Подключение» and where it comes from: Nix, the network's
/// own file (`cellward connection`), else the default ([`default_mode`]).
/// A value that is not a mode is skipped, as if it were not there.
pub fn mode(state: &Path, config: &Path, zone: &str) -> (Mode, Source) {
    if let Some(mode) = declared(config, zone) {
        return (mode, Source::Nix);
    }
    if let Some(mode) = read_setting(&own_file(state, zone))
        .as_deref()
        .and_then(Mode::parse)
    {
        return (mode, Source::Local);
    }
    (default_mode(), Source::Default)
}

/// The default: every network comes up when a program is launched into
/// it, as before. (A network whose login is asked at its start will ask by
/// default: step 2 of §11.16.)
pub fn default_mode() -> Mode {
    Mode::Auto
}

/// Set `zone`'s own setting (`None`: back to the default) — refused where
/// Nix declares it: it is changed there.
pub fn set(state: &Path, config: &Path, zone: &str, mode: Option<Mode>) -> Result<(), String> {
    if declared(config, zone).is_some() {
        return Err(format!(
            "подключение сети {zone} задано в Nix (programs.cellward.connection) и меняется там"
        ));
    }
    let file = own_file(state, zone);
    match mode {
        Some(mode) => crate::desktop::write_atomically(&file, mode.as_str().as_bytes())
            .map_err(|e| format!("не записать {}: {e}", file.display())),
        None => match fs::remove_file(&file) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(format!("не удалить {}: {e}", file.display()))
            }
            _ => Ok(()),
        },
    }
}

/// Who wants a network up.
#[derive(Debug, Clone, Copy)]
pub enum Wants<'a> {
    /// A program being launched into it, by the name the person knows.
    Program(&'a str),
    /// A container being moved there (the ⇄, `cellward container set <c>
    /// network <net>`).
    Container(&'a str),
}

/// The last answer: its number, and whether it was yes.
fn last_answer(dir: &Path) -> Option<(u64, bool)> {
    let text = fs::read_to_string(dir.join(ANSWER)).ok()?;
    let (seq, word) = text.trim().split_once(' ')?;
    let yes = match word {
        "yes" => true,
        "no" => false,
        _ => return None,
    };
    Some((seq.parse().ok()?, yes))
}

fn write_answer(dir: &Path, seq: u64, yes: bool) -> std::io::Result<()> {
    let text = format!("{seq} {}\n", if yes { "yes" } else { "no" });
    crate::desktop::write_atomically(&dir.join(ANSWER), text.as_bytes())
}

/// The network's question lock, held until dropped. Opened close-on-exec
/// (std's way): it never outlives the launch into the program.
fn lock(dir: &Path) -> Result<fs::File, String> {
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(LOCK))
        .map_err(|e| format!("не открыть {}: {e}", dir.join(LOCK).display()))?;
    // SAFETY: a valid open descriptor; LOCK_EX blocks until the lock is ours.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(format!(
            "не взять {}: {}",
            dir.join(LOCK).display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(file)
}

/// `zone` is down and something wants it up: whether it may come up. Its
/// setting says: `auto`, yes; `ask` and `manual`, the person's answer
/// (`ask` — [`question`] in the launch window). One question per network
/// at a time: a launch that waited for another's question takes its answer;
/// one that comes after it asks again. `Err`: why not, for the person.
pub fn consent(tools: &Tools, zone: &str, wants: Wants<'_>) -> Result<(), String> {
    consent_with(tools, zone, wants, |mode| {
        question(tools, zone, mode, wants)
    })
}

/// [`consent`] with the question `ask` (tests ask without a window).
fn consent_with(
    tools: &Tools,
    zone: &str,
    wants: Wants<'_>,
    ask: impl FnOnce(Mode) -> bool,
) -> Result<(), String> {
    let (mode, _) = mode(&tools.state, &tools.config, zone);
    if mode == Mode::Auto {
        return Ok(());
    }
    // The questions answered before this launch began to wait: an answer
    // after them was given while it waited, and is its answer too.
    let seen = last_answer(&tools.state.join(zone)).map_or(0, |(seq, _)| seq);
    decide(tools, zone, (mode, wants), seen, ask)
}

/// Under the network's question lock: up meanwhile — yes; answered since
/// `seen` — that answer; else the person's, written for the launches that
/// wait for it.
fn decide(
    tools: &Tools,
    zone: &str,
    (mode, wants): (Mode, Wants<'_>),
    seen: u64,
    ask: impl FnOnce(Mode) -> bool,
) -> Result<(), String> {
    let dir = tools.state.join(zone);
    let _lock = lock(&dir)?;
    if crate::cli::zone_up(&tools.state, OsStr::new(zone)).is_some() {
        return Ok(());
    }
    let yes = match last_answer(&dir) {
        Some((seq, yes)) if seq > seen => yes,
        last => {
            let yes = ask(mode);
            let seq = last.map_or(0, |(seq, _)| seq).max(seen) + 1;
            if let Err(e) = write_answer(&dir, seq, yes) {
                eprintln!("cellward: ответ о подключении сети {zone} не записан: {e}");
            }
            yes
        }
    };
    if yes {
        Ok(())
    } else {
        Err(refusal(zone, mode, wants))
    }
}

/// What the person is told when the network was not connected.
fn refusal(zone: &str, mode: Mode, wants: Wants<'_>) -> String {
    let what = match wants {
        Wants::Program(program) => format!("«{program}» не запущена"),
        Wants::Container(container) => {
            format!("контейнер «{container}» остался в прежней сети")
        }
    };
    let how = match mode {
        Mode::Manual => {
            format!("сеть {zone} подключается только вручную и не подключена — cellward up {zone}")
        }
        _ => format!("сеть {zone} не подключена — не согласились подключить"),
    };
    format!("{what}: {how}")
}

/// Ask the person whether to connect `zone` now: the launch window's
/// guarded question — «Не подключать», the safe answer, first: Enter gives
/// it —, a kdialog menu where there is no window. No deadline: the programs
/// that want the network wait, with none, until the person answers.
fn question(tools: &Tools, zone: &str, mode: Mode, wants: Wants<'_>) -> bool {
    let (title, text) = question_text(zone, mode, wants);
    let answers = [
        ("cancel", "Не подключать", false),
        ("connect", "Подключить", false),
    ];
    match crate::window::question(&tools.window, &title, &text, None, &answers, None) {
        Asked::Chose(tag) => tag == "connect",
        Asked::Closed | Asked::NoAnswer => false,
        Asked::NotShown => {
            if !crate::launch::has_display() {
                eprintln!("cellward: {text} — спросить негде (нет окна)");
                return false;
            }
            let mut argv: Vec<String> = vec!["--title".into(), title, "--menu".into(), text];
            for (tag, label, _) in answers {
                argv.push(tag.to_owned());
                argv.push(label.to_owned());
            }
            crate::dialog::ask(&tools.kdialog, &argv).as_deref() == Some("connect")
        }
    }
}

/// The question's title and text.
fn question_text(zone: &str, mode: Mode, wants: Wants<'_>) -> (String, String) {
    let who = match wants {
        Wants::Program(program) => format!("«{program}» хочет в сеть {zone}."),
        Wants::Container(container) => {
            format!("Контейнер «{container}» переходит в сеть {zone}.")
        }
    };
    let state = match mode {
        Mode::Manual => "Эта сеть подключается только вручную и сейчас не подключена.",
        _ => "Сеть не подключена.",
    };
    let wait = match wants {
        Wants::Program(_) => " Программа ждёт без сети.",
        Wants::Container(_) => " Пока сеть не подключена, контейнер остаётся в прежней.",
    };
    (
        format!("Подключение к сети {zone}"),
        format!("{who} {state}{wait} Подключить?"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::BTreeMap;

    fn tools(tag: &str) -> Tools {
        let base = std::env::temp_dir().join(format!("vz-connect-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let entries: BTreeMap<String, String> = Tools::keys()
            .iter()
            .map(|k| {
                let dir = match *k {
                    "home" | "state" | "profiles" | "sandboxes" | "config" => base.join(k),
                    other => PathBuf::from(format!("/p/{other}")),
                };
                ((*k).to_owned(), dir.to_string_lossy().into_owned())
            })
            .collect();
        let tools = Tools::from_entries(Path::new("/m.json"), &entries).unwrap();
        fs::create_dir_all(tools.state.join("work")).unwrap();
        fs::create_dir_all(tools.config.join(DECLARED_DIR)).unwrap();
        tools
    }

    #[test]
    fn the_mode_is_nix_then_the_networks_own_then_auto() {
        let t = tools("mode");
        assert_eq!(
            mode(&t.state, &t.config, "work"),
            (Mode::Auto, Source::Default)
        );
        set(&t.state, &t.config, "work", Some(Mode::Manual)).unwrap();
        assert_eq!(
            mode(&t.state, &t.config, "work"),
            (Mode::Manual, Source::Local)
        );
        crate::declared::declare(
            &t.config.join(DECLARED_DIR).join(DECLARED),
            "home auto\nwork ask\n",
        );
        assert_eq!(mode(&t.state, &t.config, "work"), (Mode::Ask, Source::Nix));
        assert!(
            set(&t.state, &t.config, "work", None)
                .unwrap_err()
                .contains("Nix"),
            "Nix's is changed there"
        );
        // Another network's line, or nonsense, is not this one's.
        crate::declared::declare(
            &t.config.join(DECLARED_DIR).join(DECLARED),
            "work sometimes\nworkplace ask\n",
        );
        assert_eq!(
            mode(&t.state, &t.config, "work"),
            (Mode::Manual, Source::Local)
        );
        set(&t.state, &t.config, "work", None).unwrap();
        assert_eq!(mode(&t.state, &t.config, "work").1, Source::Default);
        for m in Mode::ALL {
            assert_eq!(Mode::parse(&format!(" {}\n", m.as_str())), Some(m));
        }
        assert_eq!(Mode::parse("always"), None);
    }

    /// `auto` asks nothing; `ask` and `manual` ask, and the answer decides;
    /// a launch after an answer asks anew.
    #[test]
    fn the_answer_decides_and_the_next_launch_asks_anew() {
        let t = tools("consent");
        let asked = Cell::new(0);
        let answer = |yes: bool| {
            let asked = &asked;
            move |_: Mode| {
                asked.set(asked.get() + 1);
                yes
            }
        };
        let program = Wants::Program("Firefox");
        assert!(consent_with(&t, "work", program, answer(false)).is_ok());
        assert_eq!(asked.get(), 0, "auto asks nothing");
        set(&t.state, &t.config, "work", Some(Mode::Ask)).unwrap();
        let refused = consent_with(&t, "work", program, answer(false)).unwrap_err();
        assert!(refused.contains("«Firefox» не запущена"), "{refused}");
        assert_eq!(asked.get(), 1);
        assert!(consent_with(&t, "work", program, answer(true)).is_ok());
        assert_eq!(asked.get(), 2, "one after an answer asks anew");
        assert_eq!(last_answer(&t.state.join("work")), Some((2, true)));
        // Manual: asked too, and a refusal says how to connect it.
        set(&t.state, &t.config, "work", Some(Mode::Manual)).unwrap();
        let container = Wants::Container("банк");
        let refused = consent_with(&t, "work", container, answer(false)).unwrap_err();
        assert!(
            refused.contains("только вручную") && refused.contains("cellward up work"),
            "{refused}"
        );
        assert!(
            refused.contains("«банк» остался в прежней сети"),
            "{refused}"
        );
        assert_eq!(asked.get(), 3);
    }

    /// One question per network: a launch that waited while another's
    /// question was open takes its answer — written after what it saw —,
    /// and is not asked again.
    #[test]
    fn a_launch_that_waited_takes_the_answer_given_meanwhile() {
        let t = tools("waited");
        let dir = t.state.join("work");
        write_answer(&dir, 4, true).unwrap();
        // It saw answer 4 and waited; meanwhile the other was answered «no».
        write_answer(&dir, 5, false).unwrap();
        let wants = (Mode::Ask, Wants::Program("Telegram"));
        let refused = decide(&t, "work", wants, 4, |_| panic!("asked again")).unwrap_err();
        assert!(refused.contains("«Telegram» не запущена"), "{refused}");
        write_answer(&dir, 6, true).unwrap();
        assert!(decide(&t, "work", wants, 5, |_| panic!("asked again")).is_ok());
        // One that saw the last answer asks.
        let asked = Cell::new(false);
        let _ = decide(&t, "work", wants, 6, |_| {
            asked.set(true);
            false
        });
        assert!(asked.get());
        assert_eq!(last_answer(&dir), Some((7, false)));
    }

    #[test]
    fn the_question_says_who_wants_what() {
        let (title, text) = question_text("work", Mode::Ask, Wants::Program("Firefox"));
        assert_eq!(title, "Подключение к сети work");
        assert!(text.starts_with("«Firefox» хочет в сеть work."), "{text}");
        assert!(text.contains("ждёт без сети") && text.ends_with("Подключить?"));
        let (_, text) = question_text("work", Mode::Manual, Wants::Container("банк"));
        assert!(text.contains("только вручную"), "{text}");
        assert!(text.contains("остаётся в прежней"), "{text}");
    }
}
