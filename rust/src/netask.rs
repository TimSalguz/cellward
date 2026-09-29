//! The firewall's question (`docs/FIREWALL.md` §4.3, §9, 2026-09-29): a
//! program of a container's instance opens a connection its rules ask
//! about (`crate::netrules::Rule::Ask`) — the person is asked whether it may.
//!
//! **Who asks.** The instance's keeper (`zone::Transport`), which decides
//! every new flow for its relay's gate (`crate::verdicts`), by a thread of
//! its own for each question: the keeper's loop goes on — other programs'
//! flows are decided, the instance cut and carried — and hears the answer
//! on a pipe it polls ([`Asker::fd`]).
//!
//! **Where** (the owner, 2026-09-29: on the program's own window, so that
//! nobody wonders which window asks). First on the window of the program's
//! launch: its supervisor's socket of questions (`crate::wl_proxy::ask_path`)
//! has the Wayland proxy show a panel under the window's title, with
//! «Запретить» and «Разрешить…». «Запретить» there is the answer. Anything
//! else — «Разрешить…», no window to show it on, no such socket (a launch
//! without the proxy, a flow of no launch) — asks in the launch window
//! (`crate::window::question`), on the launch's compositor when its
//! supervisor named it: a "yes" is given only there. The proxy reads the
//! program's messages, and one the program took over must not say "yes"
//! for the person; the worst it can do is say "no", or open the launch
//! window.
//!
//! **What it says.** The program by its label, its container, where it goes
//! (the name a DNS answer gave the address, else the address) and the port.
//! The answers, the safe one first (Enter): «Запретить» — a rule, and it is
//! not asked again until the person changes it (the owner, 2026-09-29);
//! «Разрешить, пока работает» — for the instance's life; «Разрешить всегда»
//! — a rule. A program not found is asked about with no "always": there is
//! no key to write it for.
//!
//! **Closed, not answered, not shown** (no session, no window): "no" for the
//! instance's life — fail-closed, and a program that keeps connecting opens
//! no question after question.
//!
//! **One at a time.** An instance has one question open; the next program's
//! waits for it. Every new flow of a program asked about waits with the
//! first, held by the relay, and the answer is theirs all.

use std::collections::{HashMap, VecDeque};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Arc;

use crate::flows::Key;
use crate::onwindow::OnWindow;
use crate::verdicts::Verdict;

/// The panel's answers on the program's window: the safe one first — the
/// only one that is an answer there (`crate::onwindow`).
const PANEL: [&str; 2] = ["Запретить", "Разрешить…"];

/// What the person said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// A rule: allow.
    Always,
    /// For the instance's life.
    Now,
    /// A rule: deny.
    Deny,
    /// Closed, not answered, not shown: no, for the instance's life.
    Closed,
}

/// A program as the keeper found it: its launch's key, or none.
pub type Program = Option<String>;

/// The instance's asking.
pub struct Asker {
    window: PathBuf,
    config: PathBuf,
    state: PathBuf,
    /// The host's runtime directory: where the launches' sockets of
    /// questions are.
    runtime: PathBuf,
    /// Its record (`crate::netrules`): where an "always" or a "deny" is
    /// written; none for a throwaway.
    record: Option<String>,
    /// Its container as a person reads it.
    shown: String,
    tx: mpsc::Sender<(Program, Answer)>,
    rx: mpsc::Receiver<(Program, Answer)>,
    /// The threads' word on an answer (read end, write end).
    wake: (OwnedFd, Arc<OwnedFd>),
    /// The flows waiting for their program's answer.
    waiting: HashMap<Program, Vec<Key>>,
    /// Where each program's first waiting flow goes, for its question, and
    /// the launch it came from.
    first: HashMap<Program, (String, Option<i32>)>,
    /// The answers for the instance's life.
    session: HashMap<Program, Verdict>,
    /// The program asked about now, and those waiting their turn.
    open: Option<Program>,
    queue: VecDeque<Program>,
}

impl Asker {
    pub fn new(
        window: &Path,
        config: &Path,
        state: &Path,
        runtime: &Path,
        record: Option<String>,
    ) -> std::io::Result<Self> {
        let (r, w) = crate::sys::pipe_nonblocking()?;
        let (tx, rx) = mpsc::channel();
        let shown = match record.as_deref() {
            Some(crate::container::MAIN_RECORD) => "настоящий дом".to_owned(),
            Some(name) => format!("контейнер «{name}»"),
            None => "разовый контейнер".to_owned(),
        };
        Ok(Self {
            window: window.to_path_buf(),
            config: config.to_path_buf(),
            state: state.to_path_buf(),
            runtime: runtime.to_path_buf(),
            record,
            shown,
            tx,
            rx,
            wake: (r, Arc::new(w)),
            waiting: HashMap::new(),
            first: HashMap::new(),
            session: HashMap::new(),
            open: None,
            queue: VecDeque::new(),
        })
    }

    /// The descriptor the keeper polls: readable when an answer came.
    pub fn fd(&self) -> RawFd {
        self.wake.0.as_raw_fd()
    }

    /// A flow of `program` (of the launch `launch`, when one was found) its
    /// rules ask about, going to `to`: its verdict now when the instance's
    /// life has one for the program; else it waits for the answer (`None`),
    /// a question opened for its program when there is none yet.
    pub fn ask(
        &mut self,
        program: Program,
        launch: Option<i32>,
        key: Key,
        to: String,
    ) -> Option<Verdict> {
        if let Some(verdict) = self.session.get(&program) {
            return Some(*verdict);
        }
        let waiting = self.waiting.entry(program.clone()).or_default();
        waiting.push(key);
        if waiting.len() == 1 {
            self.first.insert(program.clone(), (to, launch));
            self.queue.push_back(program);
            self.next();
        }
        None
    }

    /// The next program's question, when none is open.
    fn next(&mut self) {
        if self.open.is_some() {
            return;
        }
        let Some(program) = self.queue.pop_front() else {
            return;
        };
        self.open = Some(program.clone());
        let label = program
            .as_deref()
            .map(|key| label_of(&self.state, key))
            .unwrap_or_else(|| "Неизвестная программа".to_owned());
        let (to, launch) = self.first.get(&program).cloned().unwrap_or_default();
        // "Always" is a rule: a record and a program to write it for.
        let always = self.record.is_some() && program.is_some();
        let (window, shown) = (self.window.clone(), self.shown.clone());
        let at = launch.map(|pid| (self.runtime.clone(), pid));
        let timeout = crate::timings::QUESTION.read(&self.config).0.duration();
        let (tx, wake) = (self.tx.clone(), self.wake.1.clone());
        let spawned = std::thread::Builder::new()
            .name("net-question".to_owned())
            .spawn(move || {
                let asked = Asked {
                    label: &label,
                    shown: &shown,
                    to: &to,
                    always,
                };
                let answer = question(&window, at, timeout, &asked);
                let _ = tx.send((program, answer));
                // SAFETY: one byte from a live buffer; the pipe is
                // non-blocking, and a full one already wakes the keeper.
                unsafe { libc::write(wake.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
            });
        if spawned.is_err() {
            // Nothing to ask in: closed.
            let program = self.open.clone().flatten();
            let _ = self.tx.send((program, Answer::Closed));
            // SAFETY: as in the thread.
            unsafe { libc::write(self.wake.1.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
        }
    }

    /// The answers that came: each written where it is kept — a rule in the
    /// record, or the instance's life — and the verdicts of the flows that
    /// waited for them, to be decided; the next question opened.
    pub fn answered(&mut self) -> Vec<(Key, Verdict)> {
        let mut buf = [0u8; 64];
        // SAFETY: read(2) into a buffer of the length passed; non-blocking.
        while unsafe { libc::read(self.wake.0.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) } > 0
        {
        }
        let mut decided = Vec::new();
        while let Ok((program, answer)) = self.rx.try_recv() {
            let verdict = match answer {
                Answer::Always | Answer::Now => Verdict::Allow,
                Answer::Deny | Answer::Closed => Verdict::Deny,
            };
            let rule = match answer {
                Answer::Always => Some(Verdict::Allow),
                Answer::Deny => Some(Verdict::Deny),
                _ => None,
            };
            let written = match (rule, self.record.as_deref(), program.as_deref()) {
                (Some(rule), Some(record), Some(program)) => {
                    let file = crate::container::policy_dir_in(&self.config, record)
                        .join(crate::container::FILE);
                    crate::netrules::write_line(&file, program, Some(rule))
                        .map_err(|e| eprintln!("the firewall's answer not kept: {e}"))
                        .is_ok()
                }
                _ => false,
            };
            // Not written as a rule: kept for the instance's life.
            if !written {
                self.session.insert(program.clone(), verdict);
            }
            for key in self.waiting.remove(&program).unwrap_or_default() {
                decided.push((key, verdict));
            }
            self.first.remove(&program);
            if self.open.as_ref() == Some(&program) {
                self.open = None;
            }
        }
        self.next();
        decided
    }
}

/// A program's label, as its launcher entry has it, else its key.
fn label_of(state: &Path, key: &str) -> String {
    std::fs::read_to_string(state.join(".labels").join(key))
        .ok()
        .map(|t| t.trim().to_owned())
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| key.to_owned())
}

/// Where a flow goes, as the question says it: the name a DNS answer gave
/// its address, else the address; and the port.
pub fn destination(key: &Key, names: &[crate::flows::Name]) -> String {
    let proto = if key.proto == crate::flows::UDP {
        " (UDP)"
    } else {
        ""
    };
    match crate::flows::name_of(names, &key.remote) {
        Some(name) => format!("{name}:{}{proto}", key.rport),
        None => match key.remote {
            std::net::IpAddr::V6(a) => format!("[{a}]:{}{proto}", key.rport),
            a => format!("{a}:{}{proto}", key.rport),
        },
    }
}

/// A question: the program's label, its container as a person reads it,
/// where it goes, and whether "always" is offered.
struct Asked<'a> {
    label: &'a str,
    shown: &'a str,
    to: &'a str,
    always: bool,
}

/// The question itself: on the program's window when its launch (`at`: the
/// runtime directory and the launch's pid) can show it — "no" there is the
/// answer —, else in the launch window, guarded, the safe answer first. Not
/// shown, closed, not answered in time: [`Answer::Closed`].
fn question(
    window: &Path,
    at: Option<(PathBuf, i32)>,
    timeout: Option<std::time::Duration>,
    asked: &Asked,
) -> Answer {
    let Asked {
        label,
        shown,
        to,
        always,
    } = *asked;
    let title = format!("Сеть — «{label}»");
    let text =
        format!("«{label}» ({shown}) хочет в сеть: {to}.\nПока вы не ответили, у неё сети нет.");
    let started = std::time::Instant::now();
    let mut display = None;
    if let Some((runtime, pid)) = at {
        match crate::onwindow::ask(&runtime, pid, &text, &PANEL, timeout) {
            OnWindow::No => return Answer::Deny,
            OnWindow::Unanswered => return Answer::Closed,
            OnWindow::Elsewhere(on) => display = on,
        }
    }
    // What is left of the time to answer in.
    let timeout = timeout.map(|t| t.saturating_sub(started.elapsed()));
    let mut answers: Vec<(&str, &str, bool)> = vec![
        ("deny", "Запретить", false),
        ("now", "Разрешить, пока работает", false),
    ];
    if always {
        answers.push(("always", "Разрешить всегда", false));
    }
    let asked = crate::window::question_on(
        window,
        display.as_deref(),
        &title,
        &text,
        None,
        &answers,
        timeout,
    );
    match asked {
        crate::window::Asked::Chose(tag) => match tag.as_str() {
            "always" => Answer::Always,
            "now" => Answer::Now,
            _ => Answer::Deny,
        },
        _ => Answer::Closed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(port: u16) -> Key {
        Key {
            proto: crate::flows::TCP,
            lport: port,
            remote: "93.184.216.34".parse().unwrap(),
            rport: 443,
        }
    }

    /// No window to ask in: the question is closed — "no" for the
    /// instance's life, every waiting flow of the program denied, the next
    /// flow decided at once; another program's question waited its turn and
    /// comes next.
    #[test]
    fn a_question_that_cannot_be_shown_is_no_for_the_instances_life() {
        let root = std::env::temp_dir().join(format!("vz-netask-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut asker = Asker::new(
            Path::new(""),
            &root.join("config"),
            &root.join("state"),
            &root,
            Some("work".to_owned()),
        )
        .unwrap();
        let curl = Some("curl".to_owned());
        // A launch with no socket of questions: the launch window, which
        // there is none of either.
        let launch = Some(i32::MAX);
        assert_eq!(
            asker.ask(curl.clone(), launch, key(1), "x:443".into()),
            None
        );
        assert_eq!(
            asker.ask(curl.clone(), launch, key(2), "x:443".into()),
            None
        );
        assert_eq!(
            asker.ask(None, None, key(3), "y:80".into()),
            None,
            "waits its turn"
        );
        let mut decided = Vec::new();
        while decided.len() < 3 {
            let mut fds = [libc::pollfd {
                fd: asker.fd(),
                events: libc::POLLIN,
                revents: 0,
            }];
            // SAFETY: one valid pollfd for the call.
            unsafe { libc::poll(fds.as_mut_ptr(), 1, 10_000) };
            decided.extend(asker.answered());
        }
        decided.sort_by_key(|(k, _)| k.lport);
        assert_eq!(
            decided,
            vec![
                (key(1), Verdict::Deny),
                (key(2), Verdict::Deny),
                (key(3), Verdict::Deny)
            ]
        );
        assert_eq!(
            asker.ask(curl, launch, key(4), "x:443".into()),
            Some(Verdict::Deny)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_destination_is_its_name_else_its_address() {
        let k = key(1);
        assert_eq!(destination(&k, &[]), "93.184.216.34:443");
        let v6 = Key {
            remote: "2001:db8::1".parse().unwrap(),
            proto: crate::flows::UDP,
            ..k
        };
        assert_eq!(destination(&v6, &[]), "[2001:db8::1]:443 (UDP)");
    }
}
