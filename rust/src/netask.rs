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
//! «Запретить всю сеть» and «Разрешить, пока работает». Both are answers there
//! after the panel's input guard. A third choice opens the trusted launch
//! window for a persistent rule, rather than making that high-impact choice
//! on the program's own window. No window to show it on or no such socket (a
//! launch without the proxy, a flow of no launch) asks in the separate
//! launch window (`crate::window::question`) as a fallback.
//!
//! **What it says.** The program by its label, its container, where it goes
//! (the name a DNS answer gave the address, else the address) and the port.
//! The answers, the safe one first (Enter): «Запретить» — a rule, and it is
//! not asked again until the person changes it (the owner, 2026-09-29);
//! «Разрешить, пока работает» — for the instance's life; «Разрешить всю сеть
//! программе всегда» — a rule, not a destination-specific exception. A
//! program not found is asked about with no "always": there is no key to
//! write it for.
//!
//! **Closed, not shown** (no session, no window): "no" for a known program's
//! instance life; an unidentified flow has no stable identity to remember.
//! **Not answered**: it waits, with no time limit
//! (the owner, 2026-10-15: a question is not closed by time) — its flows
//! held, until the person answers, or the program or the instance ends.
//!
//! **One per program.** A known program has one question open; every new flow
//! of it asked about waits with the first, held by the relay, and the
//! answer is theirs all. Another program's question is its own, at once —
//! on its own window: a question nobody answered yet does not hold back
//! every other program of the container. An unidentified flow is its own
//! question: allowing it must not allow unrelated unidentified traffic.
//! Unidentified questions are displayed one at a time within an instance;
//! their authorizations remain independent. Known programs do not wait on
//! this queue.
//! Questions on one window are shown there one after another
//! (`crate::wl_proxy`'s supervisor).

use std::collections::{HashMap, HashSet, VecDeque};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Arc;

use crate::flows::Key;
use crate::onwindow::OnWindow;
use crate::verdicts::Verdict;

/// The panel's answers on the program's window: the safe one first — the
/// only one that is an answer there (`crate::onwindow`).
const PANEL: [&str; 3] = [
    "Запретить всю сеть",
    "Разрешить, пока работает",
    "Разрешить всегда…",
];
const PANEL_TEMP: [&str; 2] = ["Запретить всю сеть", "Разрешить, пока работает"];
const PANEL_UNKNOWN: [&str; 2] = ["Запретить это соединение", "Разрешить это соединение"];
const PANEL_REGISTERED: [&str; 3] = [
    "Запретить всю сеть программе",
    "Разрешить этому запуску",
    "Разрешить всегда…",
];
const PANEL_REGISTERED_TEMP: [&str; 2] =
    ["Запретить всю сеть программе", "Разрешить этому запуску"];

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
type Panel = (i32, Option<u64>);
type First = (String, Option<Panel>, Option<String>);

/// An unknown owner has no stable program identity. In particular, `None`
/// must not be one shared authorization bucket for all unknown traffic.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum QuestionId {
    Known(String),
    Unknown(Key),
    Registered(String, crate::netqueue::Scope),
}

impl QuestionId {
    fn program(&self) -> Option<&str> {
        match self {
            Self::Known(program) | Self::Registered(program, _) => Some(program),
            Self::Unknown(_) => None,
        }
    }
}

/// The instance's asking.
pub struct Asker<T = Key> {
    window: PathBuf,
    attention: Option<PathBuf>,
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
    tx: mpsc::Sender<(u64, QuestionId, Answer)>,
    rx: mpsc::Receiver<(u64, QuestionId, Answer)>,
    /// The threads' word on an answer (read end, write end).
    wake: (OwnedFd, Arc<OwnedFd>),
    /// The flows waiting for their program's answer.
    waiting: HashMap<QuestionId, Vec<T>>,
    /// Where each program's first waiting flow goes, for its question, and
    /// the launch it came from.
    first: HashMap<QuestionId, First>,
    /// The answers for the instance's life.
    session: HashMap<QuestionId, Verdict>,
    /// The programs asked about now, and those to be asked next.
    open: HashSet<QuestionId>,
    queue: VecDeque<QuestionId>,
    round: u64,
    closed: bool,
    cancellation: Option<crate::sys::Cancellation>,
    workers: Arc<std::sync::atomic::AtomicUsize>,
}

struct Worker {
    count: Arc<std::sync::atomic::AtomicUsize>,
    wake: Arc<OwnedFd>,
}

/// A background request must not silently hide beneath another fullscreen
/// app. Alert only: no focus stealing, destination disclosure or grant action.
/// A broken notification daemon must not indefinitely delay the panel.
fn notify_waiting(notify: &Path, label: &str, container: &str) {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let escape = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    let body = format!("{} ({}) ожидает разрешения на сеть. Откройте окно программы. До ответа доступ не разрешён.", escape(label), escape(container));
    let Ok(mut child) = Command::new(notify)
        .args([
            "-a",
            "cellward",
            "-u",
            "critical",
            "-t",
            "10000",
            "--",
            "Cellward: запрос доступа к сети",
            &body,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return;
    };
    let until = Instant::now() + Duration::from_millis(750);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.count.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        // SAFETY: nonblocking wake pipe, retained until this worker exits.
        unsafe { libc::write(self.wake.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
    }
}

impl<T: Copy + Eq> Asker<T> {
    pub(crate) fn with_attention(mut self, notify: &Path) -> Self {
        self.attention = Some(notify.to_owned());
        self
    }

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
            attention: None,
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
            open: HashSet::new(),
            queue: VecDeque::new(),
            round: 0,
            closed: false,
            cancellation: Some(crate::sys::Cancellation::new()?),
            workers: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// The descriptor the keeper polls: readable when an answer came.
    pub fn fd(&self) -> RawFd {
        self.wake.0.as_raw_fd()
    }

    /// A flow of `program` (of the launch `launch`, when one was found) its
    /// rules ask about, going to `to`: its verdict now when the instance's
    /// life has one for the program; else it waits for the answer (`None`),
    /// a question opened for its program when there is none yet. `process`:
    /// the name of the process holding the flow's socket, when it was found
    /// — what the question says of a flow whose launch was not
    /// (`crate::owners`): it is asked about as its container's, by what is
    /// known, never as some program's.
    fn ask_question(
        &mut self,
        question: QuestionId,
        launch: Option<(i32, Option<u64>)>,
        process: Option<String>,
        key: T,
        to: String,
    ) -> Option<Verdict> {
        if self.closed {
            return Some(Verdict::Deny);
        }
        if let Some(verdict) = self.session.get(&question) {
            return Some(*verdict);
        }
        let waiting = self.waiting.entry(question.clone()).or_default();
        if waiting.contains(&key) {
            return None;
        }
        waiting.push(key);
        if waiting.len() == 1 {
            self.first.insert(question.clone(), (to, launch, process));
            self.queue.push_back(question);
            self.next();
        }
        None
    }

    /// The questions of the programs waiting for one, each opened.
    fn next(&mut self) {
        // Unknown connections have independent authorizations, but must not
        // carpet the desktop with one modal window per parallel socket.
        let pending = self.queue.len();
        for _ in 0..pending {
            let Some(program) = self.queue.pop_front() else {
                break;
            };
            if matches!(program, QuestionId::Unknown(_))
                && self
                    .open
                    .iter()
                    .any(|id| matches!(id, QuestionId::Unknown(_)))
            {
                self.queue.push_back(program);
                continue;
            }
            // The strict packet queue is bounded; its UI must be too. A
            // launch token gets one question, not one thread per packet.
            if matches!(program, QuestionId::Registered(..))
                && (self.open.len() >= 8
                    || self.workers.load(std::sync::atomic::Ordering::SeqCst) >= 8)
            {
                self.queue.push_back(program);
                continue;
            }
            if !self.open.contains(&program) {
                self.start(program);
            }
        }
    }

    /// The question of `program`, in a thread of its own.
    fn start(&mut self, question: QuestionId) {
        self.open.insert(question.clone());
        let (to, launch, process) = self.first.get(&question).cloned().unwrap_or_default();
        let label = match question.program() {
            Some(key) => format!("«{}»", label_of(&self.state, key)),
            None => match process {
                Some(process) => format!("Процесс «{process}»"),
                None => "Неизвестный процесс".to_owned(),
            },
        };
        // "Always" is a rule: a record and a program to write it for.
        let always = self.record.is_some() && question.program().is_some();
        let (window, shown) = (self.window.clone(), self.shown.clone());
        let attention = self.attention.clone();
        let at = launch.map(|(pid, start)| (self.runtime.clone(), pid, start));
        // No time to answer in (the owner, 2026-10-15): the flows are held
        // until the person says, and a question open on the program's window
        // waits there. It ends with its program or the instance.
        let timeout = None;
        let (tx, wake) = (self.tx.clone(), self.wake.1.clone());
        let question_of_failed = question.clone();
        let known = question.program().is_some();
        let registered = matches!(question, QuestionId::Registered(..));
        let round = self.round;
        let cancel = self.cancellation.as_ref().map(|cancel| cancel.token());
        self.workers
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let worker = Worker {
            count: self.workers.clone(),
            wake: wake.clone(),
        };
        let spawned = std::thread::Builder::new()
            .name("net-question".to_owned())
            .spawn(move || {
                let _worker = worker;
                if let Some(notify) = attention {
                    notify_waiting(&notify, &label, &shown);
                }
                let asked = Asked {
                    label: &label,
                    shown: &shown,
                    to: &to,
                    always,
                    known,
                    registered,
                };
                let answer = self::question(&window, at, timeout, &asked, cancel.as_ref());
                let _ = tx.send((round, question, answer));
                // SAFETY: one byte from a live buffer; the pipe is
                // non-blocking, and a full one already wakes the keeper.
                unsafe { libc::write(wake.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
            });
        if spawned.is_err() {
            // Nothing to ask in: closed.
            let _ = self.tx.send((round, question_of_failed, Answer::Closed));
            // SAFETY: as in the thread.
            unsafe { libc::write(self.wake.1.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
        }
    }

    /// The answers that came: each written where it is kept — a rule in the
    /// record, or the instance's life — and the verdicts of the flows that
    /// waited for them, to be decided; the next question opened.
    pub fn answered(&mut self) -> Vec<(T, Verdict)> {
        let mut buf = [0u8; 64];
        // SAFETY: read(2) into a buffer of the length passed; non-blocking.
        while unsafe { libc::read(self.wake.0.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) } > 0
        {
        }
        let mut decided = Vec::new();
        while let Ok((round, question, answer)) = self.rx.try_recv() {
            // Cancellation must precede ANY persistence, not only a later
            // queue verdict. Otherwise an obsolete "always" can rewrite a
            // new policy even though its packet ticket is correctly rejected.
            if round != self.round || !self.waiting.contains_key(&question) {
                continue;
            }
            // The question may have been open while the person or Nix
            // tightened the policy. A stale allowing answer must neither
            // release held traffic nor overwrite that newer refusal.
            let rules = match self.record.as_deref() {
                Some(record) => crate::netrules::Rules::load(&self.config, record),
                None => crate::netrules::Rules::template_only(&self.config),
            };
            let refused = rules.decide(question.program()) == crate::netrules::Rule::Deny;
            let mut verdict = match answer {
                Answer::Always | Answer::Now if refused => Verdict::Deny,
                Answer::Always | Answer::Now => Verdict::Allow,
                Answer::Deny | Answer::Closed => Verdict::Deny,
            };
            let rule = match answer {
                Answer::Always if !refused => Some(Verdict::Allow),
                Answer::Deny => Some(Verdict::Deny),
                _ => None,
            };
            let written = match (rule, self.record.as_deref(), question.program()) {
                (Some(rule), Some(record), Some(program)) => {
                    let file = crate::container::policy_dir_in(&self.config, record)
                        .join(crate::container::FILE);
                    crate::netrules::write_line(&file, program, Some(rule))
                        .map_err(|e| eprintln!("the firewall's answer not kept: {e}"))
                        .is_ok()
                }
                _ => false,
            };
            // An "always" answer without its rule on disk is not an
            // allowance. Otherwise the UI promises persistence, but the
            // next launch asks again (and this one gets unrequested access).
            if answer == Answer::Always && !written {
                verdict = Verdict::Deny;
            }
            // Not written as a rule: kept for the instance's life.
            if !written && !refused && question.program().is_some() && answer != Answer::Always {
                self.session.insert(question.clone(), verdict);
            }
            for key in self.waiting.remove(&question).unwrap_or_default() {
                decided.push((key, verdict));
            }
            self.first.remove(&question);
            self.open.remove(&question);
        }
        self.next();
        decided
    }
}

impl Asker<Key> {
    pub fn ask(
        &mut self,
        program: Program,
        launch: Option<i32>,
        process: Option<String>,
        key: Key,
        to: String,
    ) -> Option<Verdict> {
        let question = match program {
            Some(program) => QuestionId::Known(program),
            None => QuestionId::Unknown(key),
        };
        self.ask_question(question, launch.map(|pid| (pid, None)), process, key, to)
    }
}

impl Asker<crate::netqueue::Ticket> {
    /// Trusted queue rotation only: identity, epoch and policy are unchanged.
    /// Cancel pending workers/tickets, preserve only completed launch-scoped
    /// grants. Old callbacks still carry the old round and cannot persist.
    pub(crate) fn rotate_session(&mut self, old: u128, new: u128) {
        let completed = std::mem::take(&mut self.session);
        self.cancel_all();
        if self.closed {
            return;
        }
        for (question, verdict) in completed {
            if let QuestionId::Registered(program, scope) = question {
                if let Some(scope) = scope.rebind_session(old, new) {
                    self.session
                        .insert(QuestionId::Registered(program, scope), verdict);
                }
            }
        }
    }

    /// The destination is display data only. Authorization is returned for
    /// the original ticket, never reconstructed from an address/port tuple.
    pub fn ask_held(
        &mut self,
        held: &crate::netqueue::Held,
        launch: Option<(i32, u64)>,
        to: String,
    ) -> Option<Verdict> {
        let question = QuestionId::Registered(held.launch.program.clone(), held.ticket.scope());
        let already_waiting = self
            .waiting
            .get(&question)
            .is_some_and(|v| v.contains(&held.ticket));
        if !already_waiting
            && !self.session.contains_key(&question)
            && (self.waiting.values().map(Vec::len).sum::<usize>() >= crate::netqueue::MAX_PENDING
                || self
                    .waiting
                    .get(&question)
                    .is_some_and(|v| v.len() >= crate::netqueue::MAX_PENDING_PER_LAUNCH))
        {
            return Some(Verdict::Deny);
        }
        self.ask_question(
            question,
            launch.map(|(pid, start)| (pid, Some(start))),
            None,
            held.ticket,
            to,
        )
    }

    /// Before changing policy/epoch or replacing the bound queue. Late UI
    /// responses cannot persist rules or authorize a successor question.
    pub fn cancel_all(&mut self) {
        // Wake both panel waits and standalone windows. Merely discarding
        // their eventual answers would leave unbounded obsolete UI workers.
        drop(self.cancellation.take());
        self.waiting.clear();
        self.first.clear();
        self.session.clear();
        self.open.clear();
        self.queue.clear();
        match self.round.checked_add(1) {
            Some(round) => self.round = round,
            None => self.closed = true,
        }
        if !self.closed {
            match crate::sys::Cancellation::new() {
                Ok(cancel) => self.cancellation = Some(cancel),
                Err(_) => self.closed = true,
            }
        }
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
    // A ping has no port: its address, and that it is one.
    if key.proto == crate::flows::ICMP || key.proto == crate::flows::ICMP6 {
        let host = crate::flows::name_of(names, &key.remote)
            .map_or_else(|| key.remote.to_string(), str::to_owned);
        return format!("{host} (ping)");
    }
    match crate::flows::name_of(names, &key.remote) {
        Some(name) => format!("{name}:{}{proto}", key.rport),
        None => match key.remote {
            std::net::IpAddr::V6(a) => format!("[{a}]:{}{proto}", key.rport),
            a => format!("{a}:{}{proto}", key.rport),
        },
    }
}

/// A question: the program's label (its process's, quoted, for a flow of
/// no launch found), its container as a person reads it, where it goes,
/// whether "always" is offered, and whether the program is known.
struct Asked<'a> {
    label: &'a str,
    shown: &'a str,
    to: &'a str,
    always: bool,
    known: bool,
    registered: bool,
}

/// The question itself: on the program's window when its launch (`at`: the
/// runtime directory and the launch's pid) can show it — its guarded refusal
/// or session allowance is the answer —, else in the launch window, guarded,
/// the safe answer first. Not shown, closed, not answered in time:
/// [`Answer::Closed`].
fn question(
    window: &Path,
    at: Option<(PathBuf, i32, Option<u64>)>,
    timeout: Option<std::time::Duration>,
    asked: &Asked,
    cancel: Option<&crate::sys::CancelToken>,
) -> Answer {
    if cancel.is_some_and(|c| c.cancelled()) {
        return Answer::Closed;
    }
    let Asked {
        label,
        shown,
        to,
        always,
        known,
        registered,
    } = *asked;
    let title = format!("Сеть — {label}");
    // A flow of no launch found: by its container, and said so.
    let whose = if known {
        shown.to_owned()
    } else {
        format!("{shown}, программа не определена")
    };
    let scope = if registered {
        "Решение касается всей сети, не только этого сайта. «Пока работает» — только этот запуск в текущей сети; постоянное правило — программа в этом контейнере. Пока вы не ответили, сети нет."
    } else if known {
        "Решение касается всей сети программы, не только этого сайта. Пока вы не ответили, сети нет."
    } else {
        "Приложение определить не удалось: разрешение будет только для этого соединения. Пока вы не ответили, сети нет."
    };
    let text = format!("{label} ({whose}) хочет в сеть: {to}.\n{scope}");
    let started = std::time::Instant::now();
    let mut display = None;
    if let Some((runtime, pid, start)) = at {
        // Programs such as browsers open their first connection while their
        // first Wayland window is still being mapped. "No window" at that
        // instant is not a reason to detach the question into a separate
        // launch window: give the program window a brief chance to appear.
        let appear_until = started + std::time::Duration::from_secs(5);
        loop {
            if cancel.is_some_and(|c| c.cancelled()) {
                return Answer::Closed;
            }
            let left = timeout.map(|t| t.saturating_sub(started.elapsed()));
            match crate::onwindow::ask_checked(
                &runtime,
                pid,
                start,
                &text,
                if !known {
                    &PANEL_UNKNOWN
                } else if registered && always {
                    &PANEL_REGISTERED
                } else if registered {
                    &PANEL_REGISTERED_TEMP
                } else if always {
                    &PANEL
                } else {
                    &PANEL_TEMP
                },
                left,
                cancel,
            ) {
                OnWindow::No => return Answer::Deny,
                OnWindow::Yes => return Answer::Now,
                OnWindow::Unanswered => return Answer::Closed,
                OnWindow::More(on) => {
                    display = on;
                    break;
                }
                OnWindow::Elsewhere(on) => {
                    display = on.or(display);
                    if std::time::Instant::now() >= appear_until
                        || left.is_some_and(|left| left.is_zero())
                    {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
    }
    // What is left of the time to answer in.
    let timeout = timeout.map(|t| t.saturating_sub(started.elapsed()));
    let mut answers: Vec<(&str, &str, bool)> = vec![
        (
            "deny",
            if known {
                "Запретить всю сеть программе"
            } else {
                "Запретить это соединение"
            },
            false,
        ),
        (
            "now",
            if registered {
                "Разрешить этому запуску, пока работает"
            } else if known {
                "Разрешить, пока работает"
            } else {
                "Разрешить это соединение"
            },
            false,
        ),
    ];
    if always {
        answers.push(("always", "Разрешить всю сеть программе всегда", false));
    }
    if cancel.is_some_and(|c| c.cancelled()) {
        return Answer::Closed;
    }
    let asked = crate::window::question_on_cancellable(
        window,
        display.as_deref(),
        &title,
        &text,
        None,
        &answers,
        (timeout, cancel),
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

    #[test]
    fn waiting_notification_is_informational_and_bounded() {
        let root = std::env::temp_dir().join(format!("cw-net-notice-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let helper = root.join("notify");
        let seen = root.join("arguments");
        crate::dialog::test_program(
            &helper,
            &format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n", seen.display()),
        );
        notify_waiting(&helper, "<App>", "work");
        let args = std::fs::read_to_string(&seen).unwrap();
        assert!(args.contains("critical") && args.contains("&lt;App&gt;"));
        assert!(
            !args.contains("--action"),
            "a notification cannot grant access"
        );
        crate::dialog::test_program(&helper, "#!/bin/sh\nexec sleep 20\n");
        let started = std::time::Instant::now();
        notify_waiting(&helper, "App", "work");
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
        std::fs::remove_dir_all(root).unwrap();
    }

    fn strict_held(
        s: &mut crate::netqueue::Session,
        token: crate::netqueue::Token,
        id: u32,
    ) -> crate::netqueue::Held {
        let messages = crate::netqueue::wire::parse(
            &crate::netqueue::wire::fixture(7, id, token.mark()),
            0,
            false,
        )
        .unwrap();
        let crate::netqueue::wire::Message::Packet(packet) = &messages[0] else {
            panic!()
        };
        s.hold(123, packet).unwrap()
    }

    fn strict_question(held: &crate::netqueue::Held) -> QuestionId {
        QuestionId::Registered(held.launch.program.clone(), held.ticket.scope())
    }

    #[test]
    fn strict_questions_keep_same_named_launches_and_packet_tickets_separate() {
        let root = std::env::temp_dir().join(format!("vz-netask-strict-{}", std::process::id()));
        let mut asker =
            Asker::<crate::netqueue::Ticket>::new(Path::new(""), &root, &root, &root, None)
                .unwrap();
        let mut session = crate::netqueue::Session::new(123, 7, 1, 1).unwrap();
        let a = session.register("firefox".into(), 10).unwrap();
        let b = session.register("firefox".into(), 11).unwrap();
        session.activate(123, a).unwrap();
        session.activate(123, b).unwrap();
        let first = strict_held(&mut session, a, 1);
        let second = strict_held(&mut session, b, 2);
        let question_a = strict_question(&first);
        let question_b = strict_question(&second);
        assert_ne!(question_a, question_b);
        asker.open.extend([question_a.clone(), question_b.clone()]);
        assert_eq!(
            asker.ask_held(&first, None, "same-address:443".into()),
            None
        );
        assert_eq!(
            asker.ask_held(&first, None, "same-address:443".into()),
            None
        );
        assert_eq!(
            asker.ask_held(&second, None, "same-address:443".into()),
            None
        );
        assert_eq!(asker.waiting[&question_a].len(), 1);
        asker.tx.send((0, question_a, Answer::Now)).unwrap();
        assert_eq!(asker.answered(), [(first.ticket, Verdict::Allow)]);
        assert!(asker.waiting.contains_key(&question_b));
        assert!(!asker.session.contains_key(&question_b));
        session.decide(first.ticket, true).unwrap();
        assert!(session.decide(second.ticket, false).is_ok());
    }

    #[test]
    fn queue_rotation_preserves_only_completed_grants_and_cancels_old_workers() {
        let root = std::env::temp_dir().join(format!("vz-netask-requeue-{}", std::process::id()));
        let mut asker =
            Asker::<crate::netqueue::Ticket>::new(Path::new(""), &root, &root, &root, None)
                .unwrap();
        let mut old = crate::netqueue::Session::new(123, 7, 1, 1).unwrap();
        let a = old.register("firefox".into(), 10).unwrap();
        old.activate(123, a).unwrap();
        let first = strict_held(&mut old, a, 1);
        let question = strict_question(&first);
        asker.session.insert(question.clone(), Verdict::Allow);
        asker
            .tx
            .send((asker.round, question, Answer::Always))
            .unwrap();
        asker.rotate_session(123, 456);
        assert!(
            asker.answered().is_empty(),
            "old queued UI result cannot persist"
        );
        let mut next = crate::netqueue::Session::new(456, 7, 1, 1).unwrap();
        let a = next.register("firefox".into(), 10).unwrap();
        next.activate(456, a).unwrap();
        let messages =
            crate::netqueue::wire::parse(&crate::netqueue::wire::fixture(7, 1, a.mark()), 0, false)
                .unwrap();
        let crate::netqueue::wire::Message::Packet(packet) = &messages[0] else {
            panic!()
        };
        let held = next.hold(456, packet).unwrap();
        assert_eq!(
            asker.ask_held(&held, None, "server".into()),
            Some(Verdict::Allow)
        );
        assert!(asker.waiting.is_empty());
    }

    #[test]
    fn cancelled_strict_answer_cannot_persist_or_consume_a_new_question() {
        let root = std::env::temp_dir().join(format!("vz-netask-cancel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut asker = Asker::<crate::netqueue::Ticket>::new(
            Path::new(""),
            &root,
            &root,
            &root,
            Some("work".into()),
        )
        .unwrap();
        let file = crate::container::policy_dir_in(&root, "work").join(crate::container::FILE);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "net_default = ask\n").unwrap();
        let mut session = crate::netqueue::Session::new(123, 7, 1, 1).unwrap();
        let token = session.register("helium".into(), 10).unwrap();
        session.activate(123, token).unwrap();
        let held = strict_held(&mut session, token, 1);
        let question = strict_question(&held);
        asker.open.insert(question.clone());
        asker.ask_held(&held, None, "one:443".into());
        asker.cancel_all();
        // Even if the exact scope is requested again, the old worker's reply
        // cannot be mistaken for the new invocation's answer.
        asker.open.insert(question.clone());
        asker.ask_held(&held, None, "two:443".into());
        asker
            .tx
            .send((0, question.clone(), Answer::Always))
            .unwrap();
        assert!(asker.answered().is_empty());
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "net_default = ask\n"
        );
        assert!(asker.waiting.contains_key(&question));
        asker.tx.send((1, question, Answer::Now)).unwrap();
        assert_eq!(asker.answered(), [(held.ticket, Verdict::Allow)]);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn strict_question_round_exhaustion_closes_instead_of_reusing_callbacks() {
        let root = Path::new("");
        let mut asker =
            Asker::<crate::netqueue::Ticket>::new(root, root, root, root, None).unwrap();
        asker.round = u64::MAX;
        asker.cancel_all();
        let mut session = crate::netqueue::Session::new(123, 7, 1, 1).unwrap();
        let token = session.register("helium".into(), 10).unwrap();
        session.activate(123, token).unwrap();
        let held = strict_held(&mut session, token, 1);
        assert_eq!(
            asker.ask_held(&held, None, "x:443".into()),
            Some(Verdict::Deny)
        );
        assert!(asker.waiting.is_empty());
    }

    #[test]
    fn strict_worker_limit_includes_cancelled_workers_until_they_exit() {
        let root = Path::new("");
        let mut asker =
            Asker::<crate::netqueue::Ticket>::new(root, root, root, root, None).unwrap();
        let mut session = crate::netqueue::Session::new(123, 7, 1, 1).unwrap();
        let token = session.register("helium".into(), 10).unwrap();
        session.activate(123, token).unwrap();
        let held = strict_held(&mut session, token, 1);
        // Previous workers have received cancellation, but have not exited
        // their poll/child-reaping path. No new batch may exceed the cap.
        asker.workers.store(8, std::sync::atomic::Ordering::SeqCst);
        for _ in 0..20 {
            assert_eq!(asker.ask_held(&held, None, "x:443".into()), None);
            assert!(asker.open.is_empty());
            assert_eq!(asker.queue.len(), 1);
            asker.cancel_all();
            assert_eq!(asker.workers.load(std::sync::atomic::Ordering::SeqCst), 8);
        }
    }

    #[test]
    fn a_new_denial_wins_over_an_open_questions_allowing_answer() {
        let root = std::env::temp_dir().join(format!("vz-netask-stale-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (i, rule) in ["net_deny = browser\n", "net_default = deny\n"]
            .iter()
            .enumerate()
        {
            for answer in [Answer::Now, Answer::Always] {
                let config = root.join(format!("{i}-{answer:?}"));
                let mut asker =
                    Asker::new(Path::new(""), &config, &root, &root, Some("work".into())).unwrap();
                let program = QuestionId::Known("browser".to_owned());
                // A question is already open with two held connections.
                asker.open.insert(program.clone());
                asker.waiting.insert(program.clone(), vec![key(1), key(2)]);
                let file =
                    crate::container::policy_dir_in(&config, "work").join(crate::container::FILE);
                std::fs::create_dir_all(file.parent().unwrap()).unwrap();
                std::fs::write(&file, rule).unwrap();
                asker.tx.send((0, program.clone(), answer)).unwrap();
                assert_eq!(
                    asker.answered(),
                    [(key(1), Verdict::Deny), (key(2), Verdict::Deny)]
                );
                assert_eq!(std::fs::read_to_string(&file).unwrap(), *rule);
                assert!(!asker.session.contains_key(&program));
                assert!(asker.open.is_empty());
            }
        }
        let _ = std::fs::remove_dir_all(root);
    }

    fn key(port: u16) -> Key {
        Key {
            proto: crate::flows::TCP,
            lport: port,
            remote: "93.184.216.34".parse().unwrap(),
            rport: 443,
        }
    }

    #[test]
    fn unidentified_connections_do_not_share_an_allowance() {
        let root = std::env::temp_dir().join(format!("vz-netask-unknown-{}", std::process::id()));
        let mut asker = Asker::new(Path::new(""), &root, &root, &root, None).unwrap();
        let first = QuestionId::Unknown(key(1));
        let other = QuestionId::Unknown(key(2));
        asker.open.extend([first.clone(), other.clone()]);
        asker.waiting.insert(first.clone(), vec![key(1)]);
        asker.waiting.insert(other.clone(), vec![key(2)]);
        asker.tx.send((0, first, Answer::Now)).unwrap();
        assert_eq!(asker.answered(), vec![(key(1), Verdict::Allow)]);
        assert!(asker.waiting.contains_key(&other));
        assert!(asker.session.is_empty());
    }

    #[test]
    fn unidentified_questions_wait_instead_of_opening_parallel_windows() {
        let root = std::env::temp_dir().join("vz-netask-queued");
        let mut asker = Asker::new(Path::new(""), &root, &root, &root, None).unwrap();
        let active = QuestionId::Unknown(key(1));
        asker.open.insert(active.clone());
        for port in 2..8 {
            assert_eq!(asker.ask(None, None, None, key(port), "x:443".into()), None);
        }
        assert_eq!(asker.open.len(), 1);
        assert_eq!(asker.queue.len(), 6);
        assert_eq!(asker.waiting.len(), 6);
        assert!(asker.open.contains(&active));
        assert!(asker.session.is_empty());
    }

    #[test]
    fn a_permanent_allowance_that_cannot_be_saved_does_not_open_the_flow() {
        let root = std::env::temp_dir().join(format!("vz-netask-unsaved-{}", std::process::id()));
        std::fs::write(&root, "not a directory").unwrap();
        let mut asker =
            Asker::new(Path::new(""), &root, &root, &root, Some("work".into())).unwrap();
        let id = QuestionId::Known("helium".into());
        asker.open.insert(id.clone());
        asker.waiting.insert(id.clone(), vec![key(1)]);
        asker.tx.send((0, id, Answer::Always)).unwrap();
        assert_eq!(asker.answered(), vec![(key(1), Verdict::Deny)]);
        assert!(asker.session.is_empty());
        std::fs::remove_file(root).unwrap();
    }

    /// No window to ask in: the question is closed — "no" for the
    /// instance's life, every waiting flow of the program denied, the next
    /// flow decided at once; another program's question is its own, asked
    /// beside it, not after it.
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
            asker.ask(curl.clone(), launch, None, key(1), "x:443".into()),
            None
        );
        assert_eq!(
            asker.ask(curl.clone(), launch, None, key(2), "x:443".into()),
            None
        );
        assert_eq!(
            asker.ask(None, None, Some("helper".into()), key(3), "y:80".into()),
            None,
            "decided before it was asked"
        );
        assert_eq!(asker.open.len(), 2, "one question per program, at once");
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
            asker.ask(curl, launch, None, key(4), "x:443".into()),
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
        let ping = Key {
            proto: crate::flows::ICMP,
            lport: 7,
            remote: "1.1.1.1".parse().unwrap(),
            rport: u16::from(crate::flows::ECHO4),
        };
        assert_eq!(destination(&ping, &[]), "1.1.1.1 (ping)");
    }
}
