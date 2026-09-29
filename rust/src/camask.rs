//! The camera's question (`docs/PERMISSIONS.md` §11.15, step 4; the
//! owner's model: the camera is black until allowed, and a "no" is the
//! program's rule until it is changed in the window's ☰). Asked by a
//! launch's camera server (`crate::camera`, mode `ask`) when its program
//! starts streaming — never when it only looks at what cameras there are —,
//! in the program's black frames meanwhile.
//!
//! The way is the microphone's (`crate::microphone`): on the program's own
//! window first (`crate::onwindow`: a panel under its title, whose one
//! answer is «Отказать»; «Разрешить…» or no window of the program's ask in
//! the launch window, guarded), a "yes" sooner than a question is read taken
//! for a slip (`microphone::considered`), and nothing answered in the
//! question's time (`cellward question-timeout`) is "no" for this launch.
//! Its answers: once — this launch's; always — `camera = yes` in the
//! container's record (its next launches get the real cameras as they are);
//! no — [`DENIED`] in the record, not asked again.
//!
//! Whose program: the launch of the server's supervisor, in the registry
//! (`<state>/.running/<container>/<key>`) — the supervisor is the launch's
//! process itself.

use std::ffi::OsStr;
use std::path::PathBuf;
use std::time::Instant;

use crate::microphone::{considered, shown_program, Answer, TOO_FAST};
use crate::onwindow::OnWindow;
use crate::origin::Who;

/// The key of a container's record under which a program the person said
/// no to the camera is written, a line each.
pub const DENIED: &str = "cam_deny";

/// The panel's answers: «Отказать» the answer there, the other asks in the
/// launch window.
const PANEL: [&str; 2] = ["Отказать", "Разрешить…"];

/// What came of the question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// This launch's.
    Once,
    /// `camera = yes` written for the program's container.
    Always,
    /// No: written as the program's rule where it could be, else for this
    /// launch.
    No,
}

/// Whose camera is asked about, and where things are.
#[derive(Debug, Clone)]
pub struct Asking {
    /// The launch's supervisor: its socket of questions.
    pub supervisor: i32,
    pub who: Who,
    /// The launch's key in its container's registry: what a "no" is
    /// written for.
    pub key: String,
    /// The program as the person knows it (its launcher's name).
    pub label: String,
    /// The network it runs in.
    pub zone: String,
    pub config: PathBuf,
    pub profiles: PathBuf,
    pub state: PathBuf,
    pub window: PathBuf,
}

impl Asking {
    /// The launch of `supervisor`, found in the registry under the manifest
    /// of this process's environment (`crate::tools`). `None`: not a known
    /// launch — nobody is asked, the camera stays black.
    pub fn find(supervisor: i32) -> Option<Self> {
        let tools = crate::tools::Tools::from_env().ok()?;
        let running = tools.state.join(".running");
        for entry in std::fs::read_dir(&running).ok()?.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let dir = entry.path();
            if name.starts_with('.') || !dir.is_dir() {
                continue;
            }
            let Some((key, pid)) = crate::owners::launch_of(&dir, supervisor) else {
                continue;
            };
            if pid != supervisor {
                continue;
            }
            let zone = std::fs::read_to_string(dir.join(&key))
                .unwrap_or_default()
                .lines()
                .filter_map(crate::registry::parse_record)
                .find(|r| r.pid == supervisor)
                .map(|r| r.zone)
                .unwrap_or_default();
            let who = if name == crate::registry::MAIN {
                Who::Main
            } else {
                Who::Container(name)
            };
            let label = crate::launch::pretty_label(&tools.state, OsStr::new(&key))
                .unwrap_or_else(|| key.clone());
            return Some(Self {
                supervisor,
                who,
                key,
                label,
                zone,
                config: tools.config.clone(),
                profiles: tools.profiles.clone(),
                state: tools.state.clone(),
                window: tools.window.clone(),
            });
        }
        None
    }

    /// The record the program's rules are in.
    fn record(&self) -> Option<&str> {
        crate::microphone::record_of(&self.who)
    }

    /// Whether the person said no to this program's camera before.
    pub fn denied(&self) -> bool {
        self.record().is_some_and(|record| {
            crate::microphone::denied_as(&self.config, record, DENIED, &self.key)
        })
    }

    /// Ask the person, and settle it: "always" and "no" written, every
    /// answer in the journal.
    pub fn ask(&self) -> Decision {
        let timeout = crate::timings::QUESTION.read(&self.config).0.duration();
        let text = question(&self.zone, &self.who, &self.label);
        let title = match &self.who {
            Who::Container(name) => {
                format!("Камера — контейнер «{}»", crate::broker::shown_word(name))
            }
            _ => "Камера — настоящий дом".to_owned(),
        };
        let always = crate::microphone::always_label(&self.zone, &self.who);
        let asked = Instant::now();
        // On the program's window first: «Отказать» there is the answer.
        let runtime = crate::onwindow::runtime_dir();
        let short = panel_question(&self.zone, &self.who, &self.label);
        let mut display = None;
        let decided: Option<Answer> =
            match crate::onwindow::ask(&runtime, self.supervisor, &short, &PANEL, timeout) {
                OnWindow::No => Some(Answer::No),
                OnWindow::Unanswered => Some(Answer::Deny("нет ответа".to_owned())),
                OnWindow::Elsewhere(on) => {
                    display = on;
                    None
                }
            };
        let answer = decided.unwrap_or_else(|| {
            let left = timeout.map(|t| t.saturating_sub(asked.elapsed()));
            let answers = [
                ("deny", "Отказать", false),
                ("once", "Разрешить, пока работает", false),
                ("always", always.as_str(), false),
            ];
            match crate::window::question_on(
                &self.window,
                display.as_deref(),
                &title,
                &text,
                None,
                &answers,
                left,
            ) {
                crate::window::Asked::Chose(tag) => match tag.as_str() {
                    "once" => Answer::Once,
                    "always" => Answer::Always,
                    _ => Answer::No,
                },
                crate::window::Asked::Closed => Answer::No,
                crate::window::Asked::NoAnswer => Answer::Deny("нет ответа".to_owned()),
                crate::window::Asked::NotShown => {
                    Answer::Deny("вопрос не показан (нет окна запуска)".to_owned())
                }
            }
        });
        let answer = considered(answer, asked.elapsed(), TOO_FAST);
        self.settle(&answer)
    }

    fn settle(&self, answer: &Answer) -> Decision {
        match answer {
            Answer::Once => {
                self.tell(true, "человек разрешил, пока программа работает");
                Decision::Once
            }
            Answer::Always => match self.remember() {
                Ok(()) => {
                    self.tell(true, "человек разрешил всегда");
                    Decision::Always
                }
                Err(e) => {
                    self.tell(
                        true,
                        &format!(
                            "человек разрешил всегда, но это не записано ({e}) — пока работает"
                        ),
                    );
                    Decision::Once
                }
            },
            Answer::No => {
                let why = match self.refuse() {
                    Ok(()) => "человек отказал — записано; снова спросить можно в меню окна (☰)"
                        .to_owned(),
                    Err(e) => format!("человек отказал ({e}) — до конца запуска"),
                };
                self.tell(false, &why);
                Decision::No
            }
            Answer::Deny(why) => {
                self.tell(false, &format!("{why} — чёрная до конца запуска"));
                Decision::No
            }
        }
    }

    /// `camera = yes` in the container's record: not into a container
    /// removed while the question was open, which would bring it back.
    fn remember(&self) -> Result<(), String> {
        let record = self.record().ok_or("программа не известна")?;
        let file =
            crate::container::policy_dir_in(&self.config, record).join(crate::container::FILE);
        if let Who::Container(name) = &self.who {
            let _lock = crate::registry::lock(&self.config.join(crate::container::POLICY_DIR))
                .map_err(|e| e.to_string())?;
            if !crate::container::exists_in(&self.config, &self.profiles, name) {
                return Err(format!("контейнера {name} больше нет"));
            }
            return crate::container::write_key(&file, "camera", Some("true"), true);
        }
        if let Some(dir) = file.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        crate::container::write_key(&file, "camera", Some("true"), true)
    }

    /// The program's "no" in its container's record, under the same lock.
    fn refuse(&self) -> Result<(), String> {
        let record = self.record().ok_or("программа не известна")?;
        if let Who::Container(name) = &self.who {
            let _lock = crate::registry::lock(&self.config.join(crate::container::POLICY_DIR))
                .map_err(|e| e.to_string())?;
            if !crate::container::exists_in(&self.config, &self.profiles, name) {
                return Err(format!("контейнера {name} больше нет"));
            }
            return crate::microphone::set_denied_as(&self.config, record, DENIED, &self.key, true);
        }
        crate::microphone::set_denied_as(&self.config, record, DENIED, &self.key, true)
    }

    /// Said on stderr and in the journal.
    fn tell(&self, allowed: bool, why: &str) {
        let program = shown_program(&self.label);
        let decision = if allowed { "allowed" } else { "refused" };
        let container = match &self.who {
            Who::Main => String::new(),
            Who::Container(name) => name.clone(),
            Who::Unknown => "?".to_owned(),
        };
        eprintln!(
            "camera-serve: {}: camera for «{program}» {decision}: {why}",
            self.zone
        );
        if let Err(e) = crate::journal::append(
            &self.state,
            "camera",
            &[
                ("zone", self.zone.as_str()),
                ("container", container.as_str()),
                ("program", program.as_str()),
                ("decision", decision),
                ("why", why),
            ],
        ) {
            eprintln!("camera-serve: journal: {e}");
        }
    }
}

/// Whose program it is, for a question: the main home's, a container's.
fn from(zone: &str, who: &Who) -> String {
    match who {
        Who::Main => format!("Программа настоящего дома (сеть «{zone}»)"),
        Who::Container(name) => format!(
            "Программа из контейнера «{}» (сеть «{zone}»)",
            crate::broker::shown_word(name)
        ),
        Who::Unknown => format!("Программа сети «{zone}»"),
    }
}

/// The question's text in the launch window.
pub fn question(zone: &str, who: &Who, program: &str) -> String {
    let always = match who {
        Who::Container(name) => {
            let name = crate::broker::shown_word(name);
            format!(
                "«Всегда» — это настоящие камеры любой программе контейнера «{name}», без \
                 вопросов, с её следующего запуска, пока это не отменить (cellward container \
                 set {name} camera ask).\n\n"
            )
        }
        _ => "«Всегда» — это настоящие камеры любой программе настоящего дома, без вопросов, \
              с её следующего запуска, пока это не отменить (cellward container set main \
              camera ask).\n\n"
            .to_owned(),
    };
    format!(
        "{} хочет снимать камерой. Пока вы не ответили, она получает чёрные кадры.\n\n\
         Она называет себя: «{}» — это слова её ярлыка.\n\n{always}Разрешить?",
        from(zone, who),
        shown_program(program)
    )
}

/// The question as the panel on the program's window says it.
pub fn panel_question(zone: &str, who: &Who, program: &str) -> String {
    format!(
        "{} хочет снимать камерой: «{}». Пока нет ответа — чёрные кадры.",
        from(zone, who),
        shown_program(program)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The question names whose program, what it calls itself, what the
    /// program gets meanwhile, and what "always" is; the panel's is short.
    #[test]
    fn the_question_says_whose_what_and_what_always_is() {
        let who = Who::Container("work".to_owned());
        let text = question("nl", &who, "Firefox");
        assert!(text.contains("контейнера «work» (сеть «nl»)"), "{text}");
        assert!(text.contains("«Firefox»"), "{text}");
        assert!(text.contains("чёрные кадры"), "{text}");
        assert!(
            text.contains("cellward container set work camera ask"),
            "{text}"
        );
        let main = question("offline", &Who::Main, "foot");
        assert!(main.contains("настоящего дома"), "{main}");
        assert!(main.contains("container set main camera ask"), "{main}");
        let short = panel_question("nl", &who, "Firefox");
        assert!(short.len() < text.len());
        assert!(
            short.contains("«Firefox»") && short.contains("чёрные"),
            "{short}"
        );
        // What a program calls itself cannot say more than a name.
        let odd = question("nl", &who, "a\u{202e}b\nc");
        assert!(!odd.contains('\u{202e}'), "{odd:?}");
    }

    /// A "no" is the program's rule in its record, under the camera's own
    /// key — not the microphone's —, and found again.
    #[test]
    fn a_no_is_the_programs_rule_under_the_cameras_key() {
        let base = std::env::temp_dir().join(format!("vz-camask-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let config = base.join("config");
        let profiles = base.join("profiles");
        std::fs::create_dir_all(config.join("containers/work")).unwrap();
        std::fs::create_dir_all(profiles.join("work")).unwrap();
        let asking = Asking {
            supervisor: 1,
            who: Who::Container("work".to_owned()),
            key: "firefox".to_owned(),
            label: "Firefox".to_owned(),
            zone: "nl".to_owned(),
            config: config.clone(),
            profiles,
            state: base.join("state"),
            window: PathBuf::new(),
        };
        assert!(!asking.denied());
        assert_eq!(asking.settle(&Answer::No), Decision::No);
        assert!(asking.denied());
        assert!(!crate::microphone::denied(&config, "work", "firefox"));
        let record = std::fs::read_to_string(config.join("containers/work/container.conf"))
            .unwrap_or_default();
        assert!(record.contains("cam_deny"), "{record}");
        // "Always": the container's camera, yes.
        assert_eq!(asking.settle(&Answer::Always), Decision::Always);
        assert_eq!(
            crate::container::own_camera_in(&config, "work").map(|(m, _)| m),
            Some(crate::camera::Mode::Yes)
        );
        // Nothing answered: no, for this launch only — nothing written.
        crate::microphone::set_denied_as(&config, "work", DENIED, "firefox", false).unwrap();
        assert_eq!(
            asking.settle(&Answer::Deny("нет ответа".to_owned())),
            Decision::No
        );
        assert!(!asking.denied());
        let _ = std::fs::remove_dir_all(&base);
    }
}
