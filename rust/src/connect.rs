//! Connecting a network (`docs/PERMISSIONS.md` §11.16, the owner,
//! 2026-09-29): a network's «Подключение» — `auto`, it comes up when a
//! program is launched into it, as it always did; `ask`, the person is
//! asked first; `manual`, only the person connects it, and a launch into it
//! while it is down asks whether to connect it now — and, for a network
//! whose login is asked (an OpenConnect zone without a `PasswordFile`), the
//! connect window's login form, whose answers go to the zone's holder alone.
//!
//! The question is the launch window's, guarded as every question of it is
//! (`crate::window::question`): nothing is taken until the person has been
//! still with it in view; the form is `vpn-zone-window login`, guarded once.
//! One question per network at a time: launches that want the same network
//! meanwhile wait for its outcome and take it — autostart after the login
//! asks once per network, not once per program, and a refusal at an
//! autostart question holds for the session's later autostart launches too
//! ([`autostart_launch`]); a refusal taken so is said in a notification,
//! the person having answered already. Programs wait with no
//! network while it is open: a network that is down has no route out, so
//! nothing goes anywhere meanwhile. «Не подключать», a closed question, or
//! no way to ask at all: the network stays down, and the launch is refused
//! where the person sees it — never a silent end. Connected after the
//! person answered — the question, the form —: a notification says so
//! (step 3), once per network, from the launch that asked; the person who
//! waited for it is told the wait is over, whatever window is in front.
//!
//! **The login** is the gateway's own (§11.17): `cellward-oc-auth` goes
//! through its forms, and each is shown in the connect window as the
//! gateway sent it — its fields, a choice's choices, a «сохранить» box by
//! each but a code. What is typed goes to the helper on its standard input
//! and to the gateway, never to a disk; what comes out is the session's
//! cookie, which goes to the zone's holder on a socket of the user's runtime
//! directory ([`Offer`]), served to that network's holder alone — its
//! peer's cgroup must be the unit `vpn-zone@<network>.service`, so a
//! program of a container of the same user that finds the socket gets
//! nothing —, and from the holder to `openconnect` on its standard input
//! (`crate::zone`). What the person ticks is kept: text and choices in the
//! network's `login` file, a password only in the session's keyring (Secret
//! Service, `secret-tool`, handed it on its standard input). A code never.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::cli::{read_setting, DECLARED_DIR};
use crate::container::Source;
use crate::oc_form::{self, Field, Form, Kind, Said};
use crate::openconnect::OcConfig;
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
/// In a network's state directory: what the person chose to keep of its
/// login ([`Saved`]) — not secret, the forms' prefill.
const LAST_LOGIN: &str = "login";
/// Below `$XDG_RUNTIME_DIR`: the sockets a login is handed over on.
pub const LOGIN_DIR: &str = "vpn-zones/login";

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
    (default_mode(state, zone), Source::Default)
}

/// The default: a network whose login is asked asks (the owner, 2026-09-29);
/// every other one comes up when a program is launched into it, as before.
pub fn default_mode(state: &Path, zone: &str) -> Mode {
    if asks_login(state, zone).is_some() {
        Mode::Ask
    } else {
        Mode::Auto
    }
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

/// The network's OpenConnect section, where its login is asked (no
/// `PasswordFile`, and not `AskLogin = no`).
pub fn asks_login(state: &Path, zone: &str) -> Option<OcConfig> {
    let raw = crate::chain::read_zone_config(state, zone).ok()?;
    let cfg = OcConfig::parse(&raw).ok()?;
    cfg.login.then_some(cfg)
}

/// Who wants a network up.
#[derive(Debug, Clone, Copy)]
pub enum Wants<'a> {
    /// A program being launched into it, by the name the person knows.
    Program(&'a str),
    /// A container being moved there (the ⇄, `cellward container set <c>
    /// network <net>`).
    Container(&'a str),
    /// The person, connecting it (`cellward up`): nothing to ask, but a
    /// login.
    Person,
}

/// The last answer: its number, whether it was yes, and the graphical
/// session of the autostart it was refused at, if it was.
fn last_answer(dir: &Path) -> Option<(u64, bool, Option<String>)> {
    let text = fs::read_to_string(dir.join(ANSWER)).ok()?;
    let mut words = text.split_whitespace();
    let seq = words.next()?.parse().ok()?;
    let yes = match words.next()? {
        "yes" => true,
        "no" => false,
        _ => return None,
    };
    Some((seq, yes, words.next().map(str::to_owned)))
}

fn write_answer(dir: &Path, seq: u64, yes: bool, autostart: Option<&str>) -> std::io::Result<()> {
    let mut text = format!("{seq} {}", if yes { "yes" } else { "no" });
    if let Some(session) = autostart {
        text.push(' ');
        text.push_str(session);
    }
    text.push('\n');
    crate::desktop::write_atomically(&dir.join(ANSWER), text.as_bytes())
}

/// Why a network is not up, for the person.
#[derive(Debug, PartialEq, Eq)]
pub struct NotUp {
    pub why: String,
    /// Refused at another launch's question — one it waited through, or an
    /// autostart question of this session before it: the person saw and
    /// answered that one, and this launch says so without a window of its
    /// own.
    pub taken: bool,
}

impl From<String> for NotUp {
    fn from(why: String) -> Self {
        Self { why, taken: false }
    }
}

impl std::fmt::Display for NotUp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.why)
    }
}

/// The graphical session of this process, when it is a launch of the
/// session's autostart ([`autostart_launch`]).
static AUTOSTART: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// This process is a launch of the session's autostart
/// (`launch::ENV_AUTOSTART`): a network refused at an autostart question of
/// the same graphical session is refused for it too — once per network,
/// however far apart the programs start (the owner, 2026-09-29). Without a
/// display there is no session to tell, and it is asked as any launch.
pub fn autostart_launch() {
    if let Some(session) = display_session() {
        let _ = AUTOSTART.set(session);
    }
}

/// The graphical session by its display socket, made anew with each login:
/// `<device>:<inode>:<mtime>` of `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY`, or of
/// X's socket.
fn display_session() -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let socket = match std::env::var_os("WAYLAND_DISPLAY").filter(|v| !v.is_empty()) {
        Some(name) => Path::new(&std::env::var_os("XDG_RUNTIME_DIR")?).join(name),
        None => {
            let display = std::env::var("DISPLAY").ok()?;
            let number = display.strip_prefix(':')?.split('.').next()?.to_owned();
            PathBuf::from(format!("/tmp/.X11-unix/X{number}"))
        }
    };
    let meta = fs::metadata(socket).ok()?;
    Some(format!("{}:{}:{}", meta.dev(), meta.ino(), meta.mtime()))
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

/// What bringing a network up takes, apart: asking, logging in, starting,
/// whether it is up, and saying it is; the autostart session the launch is
/// of — the real ones ([`Real`]), or a test's.
trait Steps {
    fn ask(&self, zone: &str, mode: Mode, wants: Wants<'_>) -> bool;
    /// Whether the person went through with the login — up or not.
    fn log_in(&self, zone: &str, asked: (Mode, Wants<'_>), cfg: &OcConfig) -> bool;
    fn start(&self, zone: &str, wants: Wants<'_>);
    fn up(&self, zone: &str) -> bool;
    fn connected(&self, zone: &str, wants: Wants<'_>);
    fn autostart(&self) -> Option<String>;
}

struct Real<'a>(&'a Tools);

impl Steps for Real<'_> {
    fn ask(&self, zone: &str, mode: Mode, wants: Wants<'_>) -> bool {
        question(self.0, zone, mode, wants)
    }

    fn log_in(&self, zone: &str, asked: (Mode, Wants<'_>), cfg: &OcConfig) -> bool {
        log_in(self.0, zone, asked, cfg)
    }

    fn start(&self, zone: &str, wants: Wants<'_>) {
        // Returns once the zone is ready or failed (`Type=notify`), and says
        // so while a launch waits (`cli::start_zone`).
        let notify = matches!(wants, Wants::Program(_));
        let _ = crate::cli::start_zone(self.0, OsStr::new(zone), notify);
    }

    fn up(&self, zone: &str) -> bool {
        crate::cli::zone_up(&self.0.state, OsStr::new(zone)).is_some()
    }

    fn connected(&self, zone: &str, wants: Wants<'_>) {
        let (title, body) = connected_text(zone, wants);
        // A unit of its own, not a child: the launch goes on into the
        // program at once — a notification daemon slow to answer holds
        // nothing up, and the instance the launch becomes has no stray
        // child to reap.
        let _ = Command::new(&self.0.systemd_run)
            .args(["--user", "--collect", "--quiet", "--no-block"])
            .arg(format!("--description={}: {title}", crate::dialog::APP))
            .arg("--")
            .arg(&self.0.notify_send)
            .args(["-a", crate::dialog::APP, "-t", "5000"])
            // `--`: a network's name may start with a dash.
            .arg("--")
            .arg(title)
            .arg(body)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    fn autostart(&self) -> Option<String> {
        AUTOSTART.get().cloned()
    }
}

/// `zone` up for `wants`, as its «Подключение» says: `auto` starts it;
/// `ask` and `manual` ask the person first (a launch, a container — the
/// person connecting it asks nothing); a network whose login is asked
/// (no `PasswordFile`) takes it in the connect window's form, asked again with
/// what went wrong until the network is up or the person gives up. One
/// question per network at a time: a launch that waited through another's
/// takes its outcome, one after it asks anew — unless both are of this
/// session's autostart, and it was a refusal. `Err`: why it is not up, for
/// the person.
pub fn bring_up(tools: &Tools, zone: &str, wants: Wants<'_>) -> Result<(), NotUp> {
    if zone != crate::launch::HOST {
        match crate::chain::published_zone(&tools.state, zone) {
            Ok(true) => {}
            Ok(false) => return Err(format!("маршрут {zone} не разрешён в .routes").into()),
            Err(e) => return Err(format!("маршрут {zone}: {e}").into()),
        }
    }
    bring_up_with(tools, zone, wants, &Real(tools))
}

fn bring_up_with(
    tools: &Tools,
    zone: &str,
    wants: Wants<'_>,
    steps: &impl Steps,
) -> Result<(), NotUp> {
    if steps.up(zone) {
        return Ok(());
    }
    let (mode, _) = mode(&tools.state, &tools.config, zone);
    let login = asks_login(&tools.state, zone);
    let asks = login.is_some() || (mode != Mode::Auto && !matches!(wants, Wants::Person));
    if !asks {
        steps.start(zone, wants);
        return if steps.up(zone) {
            Ok(())
        } else {
            Err(failed(zone, wants).into())
        };
    }
    let dir = tools.state.join(zone);
    // The questions answered before this launch began to wait: an answer
    // after them was given while it waited, and is its answer too.
    let seen = last_answer(&dir).map_or(0, |(seq, _, _)| seq);
    decide(tools, zone, (mode, wants), seen, (login.as_ref(), steps))
}

/// Under the network's question lock: up meanwhile — yes; refused since
/// `seen`, or at an autostart question of this launch's autostart session
/// — that refusal, taken; else the person's, written for the launches that
/// wait for it. Connected after the person answered: said so, the lock
/// given back first — the launches that waited go on meanwhile.
fn decide(
    tools: &Tools,
    zone: &str,
    (mode, wants): (Mode, Wants<'_>),
    seen: u64,
    (login, steps): (Option<&OcConfig>, &impl Steps),
) -> Result<(), NotUp> {
    let dir = tools.state.join(zone);
    let held = lock(&dir)?;
    if steps.up(zone) {
        return Ok(());
    }
    let last = last_answer(&dir);
    let autostart = steps.autostart();
    if let Some((seq, false, at)) = &last {
        if *seq > seen || (autostart.is_some() && *at == autostart) {
            return Err(NotUp {
                why: refusal(zone, mode, wants),
                taken: true,
            });
        }
    }
    // Whether the person answered something: the form, the question — not
    // the person connecting a network with nothing to ask, who is told by
    // what they ran.
    let (yes, answered) = match login {
        // The form is the question: «Подключить» there is the yes.
        Some(cfg) => (steps.log_in(zone, (mode, wants), cfg), true),
        None => {
            let person = matches!(wants, Wants::Person);
            let yes = person || steps.ask(zone, mode, wants);
            if yes {
                steps.start(zone, wants);
            }
            (yes, !person)
        }
    };
    let up = yes && steps.up(zone);
    let seq = last.map_or(0, |(seq, _, _)| seq).max(seen) + 1;
    // The session kept with a refusal only: one that failed to come up is
    // tried again by the next.
    let refused_at = autostart.as_deref().filter(|_| !yes);
    if let Err(e) = write_answer(&dir, seq, up, refused_at) {
        eprintln!("cellward: ответ о подключении сети {zone} не записан: {e}");
    }
    drop(held);
    match (up, yes) {
        (true, _) => {
            if answered {
                steps.connected(zone, wants);
            }
            Ok(())
        }
        (false, true) => Err(failed(zone, wants).into()),
        (false, false) => Err(refusal(zone, mode, wants).into()),
    }
}

/// The notification that the network is connected: its title, and what
/// goes on now.
fn connected_text(zone: &str, wants: Wants<'_>) -> (String, String) {
    let body = match wants {
        Wants::Program(program) => format!("«{program}» запускается."),
        Wants::Container(container) => format!("Контейнер «{container}» переходит в неё."),
        Wants::Person => String::new(),
    };
    (format!("Сеть {zone} подключена"), body)
}

/// What the person is told when the network was not connected: refused.
fn refusal(zone: &str, mode: Mode, wants: Wants<'_>) -> String {
    let how = match mode {
        Mode::Manual => {
            format!("сеть {zone} подключается только вручную и не подключена — cellward up {zone}")
        }
        _ => format!("сеть {zone} не подключена — не согласились подключить"),
    };
    format!("{}: {how}", what_failed(wants))
}

/// ... or tried, and it did not come up.
fn failed(zone: &str, wants: Wants<'_>) -> String {
    format!(
        "{}: зона {zone} не поднимается (journalctl --user -u vpn-zone@{zone})",
        what_failed(wants)
    )
}

fn what_failed(wants: Wants<'_>) -> String {
    match wants {
        Wants::Program(program) => format!("«{program}» не запущена"),
        Wants::Container(container) => format!("контейнер «{container}» остался в прежней сети"),
        Wants::Person => "не подключено".to_owned(),
    }
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

/// Who wants the network, for a question or a form.
fn who(zone: &str, wants: Wants<'_>) -> String {
    match wants {
        Wants::Program(program) => format!("«{program}» хочет в сеть {zone}."),
        Wants::Container(container) => {
            format!("Контейнер «{container}» переходит в сеть {zone}.")
        }
        Wants::Person => format!("Подключение сети {zone}."),
    }
}

/// The question's title and text.
fn question_text(zone: &str, mode: Mode, wants: Wants<'_>) -> (String, String) {
    let state = match mode {
        Mode::Manual => "Эта сеть подключается только вручную и сейчас не подключена.",
        _ => "Сеть не подключена.",
    };
    let wait = match wants {
        Wants::Program(_) => " Программа ждёт без сети.",
        Wants::Container(_) => " Пока сеть не подключена, контейнер остаётся в прежней.",
        Wants::Person => "",
    };
    (
        format!("Подключение к сети {zone}"),
        format!("{} {state}{wait} Подключить?", who(zone, wants)),
    )
}

// --- THE LOGIN (§11.16 step 2, §11.17) ---------------------------------------

/// The helper that goes through the gateway's forms (`cellward-oc-auth`,
/// the one binary with libopenconnect), next to our own binaries.
pub const OC_AUTH: &str = "cellward-oc-auth";

/// What a login gave the zone's holder: the gateway's session — never the
/// password, which went to the gateway alone.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Session {
    pub cookie: String,
    /// Where the client connects: the gateway's URL for the session.
    pub connect_url: String,
    /// The certificate the login saw: the client's `--servercert`.
    pub fingerprint: String,
    /// The one address the login went to — and the client goes to.
    pub address: String,
}

/// Never the cookie in a log: it is the session.
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("cookie", &"…")
            .field("connect_url", &self.connect_url)
            .field("fingerprint", &self.fingerprint)
            .field("address", &self.address)
            .finish()
    }
}

/// A value as a line can carry it: no tab, no line break.
fn one_line(value: &str) -> String {
    value
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect()
}

impl Session {
    fn encode(&self) -> String {
        [
            ("cookie", &self.cookie),
            ("url", &self.connect_url),
            ("fingerprint", &self.fingerprint),
            ("address", &self.address),
        ]
        .iter()
        .map(|(key, value)| format!("{key}\t{}\n", one_line(value)))
        .collect()
    }

    /// The lines back; `None` without a cookie.
    fn decode(text: &str) -> Option<Self> {
        let mut session = Self::default();
        for line in text.lines() {
            match line.split_once('\t') {
                Some(("cookie", v)) => session.cookie = v.to_owned(),
                Some(("url", v)) => session.connect_url = v.to_owned(),
                Some(("fingerprint", v)) => session.fingerprint = v.to_owned(),
                Some(("address", v)) => session.address = v.to_owned(),
                _ => {}
            }
        }
        (!session.cookie.is_empty()).then_some(session)
    }
}

/// Where `zone`'s login is handed over.
pub fn login_socket(runtime: &Path, zone: &str) -> PathBuf {
    runtime.join(LOGIN_DIR).join(format!("{zone}.sock"))
}

/// Whether `pid` is in the unit `unit`'s cgroup, or below it.
fn in_unit(pid: i32, unit: &str) -> bool {
    fs::read_to_string(format!("/proc/{pid}/cgroup")).is_ok_and(|text| {
        text.lines().any(|line| {
            line.rsplit_once(':')
                .is_some_and(|(_, path)| path.split('/').any(|part| part == unit))
        })
    })
}

/// A session handed to a network's holder while the network starts: the
/// socket held, served once, to that network's holder alone — anybody else
/// who connects is closed on with nothing said. Taken back when dropped.
pub struct Offer {
    path: PathBuf,
    /// A second descriptor of the listening socket: shut down, it ends the
    /// wait for the holder.
    stop: OwnedFd,
    serving: Option<std::thread::JoinHandle<bool>>,
}

impl Offer {
    pub fn open(runtime: &Path, zone: &str, session: Session) -> Result<Self, String> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let path = login_socket(runtime, zone);
        let dir = path.parent().unwrap_or(runtime);
        let fail = |e: std::io::Error| format!("не открыть {}: {e}", path.display());
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(fail)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(fail)?;
        let _ = fs::remove_file(&path);
        let listener = UnixListener::bind(&path).map_err(fail)?;
        let stop = OwnedFd::from(listener.try_clone().map_err(fail)?);
        let unit = format!("vpn-zone@{zone}.service");
        let serving = std::thread::spawn(move || serve(&listener, &unit, &session));
        Ok(Self {
            path,
            stop,
            serving: Some(serving),
        })
    }

    /// Taken back: whether the holder took it.
    pub fn taken(mut self) -> bool {
        self.close()
    }

    fn close(&mut self) -> bool {
        let _ = fs::remove_file(&self.path);
        // SAFETY: a descriptor this struct owns; shutting a listening socket
        // down wakes an `accept` waiting on it.
        unsafe { libc::shutdown(self.stop.as_raw_fd(), libc::SHUT_RDWR) };
        self.serving
            .take()
            .is_some_and(|serving| serving.join().unwrap_or(false))
    }
}

impl Drop for Offer {
    fn drop(&mut self) {
        self.close();
    }
}

/// Serve the session to the unit's process that asks, once.
fn serve(listener: &UnixListener, unit: &str, session: &Session) -> bool {
    for conn in listener.incoming() {
        let Ok(mut conn) = conn else {
            return false;
        };
        let ours = crate::sys::peer_pid(conn.as_raw_fd()).is_some_and(|pid| in_unit(pid, unit));
        if !ours {
            continue;
        }
        return conn.write_all(session.encode().as_bytes()).is_ok();
    }
    false
}

/// The holder of `zone`, starting: the session handed over by whoever
/// started it ([`Offer`]). `Err`: why there is none, for the journal.
pub fn fetch_session(zone: &str) -> Result<Session, String> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|r| !r.is_empty())
        .ok_or("XDG_RUNTIME_DIR is not set: there is nowhere to take the login from")?;
    let path = login_socket(Path::new(&runtime), zone);
    let mut stream = UnixStream::connect(&path).map_err(|e| {
        format!(
            "no login was given for {zone} ({}: {e}) — it is asked when a program is launched \
             into the zone, or by `cellward up {zone}`; a gateway that asks nothing: \
             AskLogin = no",
            path.display()
        )
    })?;
    let mut text = String::new();
    stream
        .read_to_string(&mut text)
        .map_err(|e| format!("the login for {zone} could not be read: {e}"))?;
    Session::decode(&text).ok_or_else(|| format!("the login for {zone} came without a session"))
}

/// What the person chose to keep of a network's login: the gateway's
/// fields by name — text and choices only; a password is the keyring's, a
/// code nobody's. The file's lines are `field⇥<name>⇥<value>`; a file of
/// before (`user⇥…`, `group⇥…`) is read as what it was, as are the
/// config's `User =` and `AuthGroup =`: the user and the group, for the
/// fields that ask for them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Saved {
    fields: BTreeMap<String, String>,
    user: Option<String>,
    group: Option<String>,
}

fn load_saved(state: &Path, zone: &str, cfg: &OcConfig) -> Saved {
    let text = fs::read_to_string(state.join(zone).join(LAST_LOGIN)).unwrap_or_default();
    let mut saved = Saved {
        user: cfg.user.clone(),
        group: cfg.authgroup.clone(),
        ..Saved::default()
    };
    for line in text.lines() {
        let parts: Vec<&str> = line.splitn(3, '\t').collect();
        match parts.as_slice() {
            ["field", name, value] if !value.is_empty() => {
                saved.fields.insert((*name).to_owned(), (*value).to_owned());
            }
            ["user", value] if !value.is_empty() => saved.user = Some((*value).to_owned()),
            ["group", value] if !value.is_empty() => saved.group = Some((*value).to_owned()),
            _ => {}
        }
    }
    saved
}

fn store_saved(state: &Path, zone: &str, fields: &BTreeMap<String, String>) {
    let text: String = fields
        .iter()
        .map(|(name, value)| format!("field\t{}\t{}\n", one_line(name), one_line(value)))
        .collect();
    if let Err(e) =
        crate::desktop::write_atomically(&state.join(zone).join(LAST_LOGIN), text.as_bytes())
    {
        eprintln!("cellward: сохранённое для входа в сеть {zone} не записано: {e}");
    }
}

/// Does this field ask for the user? By its name or its label.
fn asks_user(field: &Field) -> bool {
    let words = format!("{} {}", field.name, field.label).to_lowercase();
    ["user", "login", "пользовател", "логин"]
        .iter()
        .any(|w| words.contains(w))
}

/// What is known for a field: kept by its name; else the user for a field
/// that asks for it, the group for a choice that offers it.
fn known(saved: &Saved, field: &Field) -> Option<String> {
    if let Some(value) = saved.fields.get(&field.name) {
        return Some(value.clone());
    }
    match field.kind {
        Kind::Text if asks_user(field) => saved.user.clone(),
        Kind::Select => saved.group.as_ref().and_then(|g| {
            field
                .choices
                .iter()
                .find(|c| &c.name == g || &c.label == g)
                .map(|c| c.name.clone())
        }),
        _ => None,
    }
}

/// The keyring's attributes of a network's secret field.
fn keyring_attributes(zone: &str, field: &str) -> [String; 6] {
    [
        "service".into(),
        "cellward".into(),
        "network".into(),
        zone.into(),
        "field".into(),
        field.into(),
    ]
}

/// The secret remembered for `zone`'s field `field`, if there is one.
fn keyring_lookup(tools: &Tools, zone: &str, field: &str) -> Option<String> {
    let out = Command::new(&tools.secret_tool)
        .arg("lookup")
        .args(keyring_attributes(zone, field))
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let secret = String::from_utf8(out.stdout).ok()?;
    let secret = secret.trim_end_matches('\n');
    (out.status.success() && !secret.is_empty()).then(|| secret.to_owned())
}

/// Remember a secret (`keep`) or forget it, in the session's keyring. The
/// secret goes on `secret-tool`'s standard input.
fn keyring_keep(tools: &Tools, zone: &str, field: &str, secret: &str, keep: bool) {
    let attributes = keyring_attributes(zone, field);
    let result = if keep {
        Command::new(&tools.secret_tool)
            .arg("store")
            .arg(format!("--label=cellward: сеть {zone}"))
            .args(attributes)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .and_then(|mut child| {
                if let Some(mut stdin) = child.stdin.take() {
                    stdin.write_all(secret.as_bytes())?;
                }
                child.wait()
            })
    } else {
        Command::new(&tools.secret_tool)
            .arg("clear")
            .args(attributes)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
    };
    match result {
        Ok(status) if status.success() || !keep => {}
        Ok(_) | Err(_) => eprintln!("cellward: пароль сети {zone} не сохранён в связке ключей"),
    }
}

/// A field of a gateway's form as the person answered it, and whether to
/// keep the answer.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Answered {
    field: Field,
    value: String,
    keep: bool,
}

/// The window's request for a form of the gateway's: its words — the
/// banner, the message, what went wrong — as the gateway's, then its
/// fields prefilled (`values`), a choice's choices, and a «сохранить» box
/// for each but a code (`keeps`; a password's only with a keyring).
fn form_request(
    zone: &str,
    (mode, wants): (Mode, Wants<'_>),
    cfg: &OcConfig,
    form: &Form,
    (values, keeps): (&[String], &[bool]),
    (notes, keyring): (&[String], bool),
) -> String {
    let mut req = format!(
        "title\tВход в сеть {zone}\nnote\t{} Шлюз {}.\n",
        crate::window::clean(&who(zone, wants)),
        crate::window::clean(&cfg.server)
    );
    if mode == Mode::Manual && !matches!(wants, Wants::Person) {
        req.push_str("note\tЭта сеть подключается только вручную: вход подключит её сейчас.\n");
    }
    if let Wants::Program(_) = wants {
        req.push_str("note\tПрограмма ждёт без сети.\n");
    }
    for note in notes {
        req.push_str(&format!("note\t{}\n", crate::window::clean(note)));
    }
    for (said, mark) in [(&form.banner, ""), (&form.message, ""), (&form.error, "⚠ ")] {
        for line in said.lines().map(str::trim).filter(|l| !l.is_empty()) {
            req.push_str(&format!(
                "note\t{mark}Шлюз: {}\n",
                crate::window::clean(line)
            ));
        }
    }
    req.push_str(&format!("guard\t{}\n", crate::dialog::TOO_FAST.as_millis()));
    for (i, field) in form.fields.iter().enumerate() {
        let kind = match field.kind {
            Kind::Text => "text",
            Kind::Password => "secret",
            Kind::Select => "select",
            Kind::Token => "token",
        };
        let value = values.get(i).map_or("", String::as_str);
        req.push_str(&format!(
            "field\t{}\t{}\t{kind}\t{}\n",
            one_line(&field.name),
            one_line(&field.label),
            one_line(value)
        ));
        for choice in &field.choices {
            req.push_str(&format!(
                "choice\t{}\t{}\t{}\n",
                one_line(&field.name),
                one_line(&choice.name),
                one_line(&choice.label)
            ));
        }
        let keep = keeps.get(i).copied().unwrap_or(false);
        let label = match field.kind {
            Kind::Token => continue,
            Kind::Password if !keyring => continue,
            Kind::Password => "Сохранить в связке ключей сеанса",
            Kind::Text | Kind::Select => "Сохранить",
        };
        req.push_str(&format!(
            "save\t{}\t{label}\t{}\n",
            one_line(&field.name),
            u8::from(keep)
        ));
    }
    req
}

/// The window's answer to a form: each field's value, in the form's order,
/// and whether to keep it. `None` without every field.
fn parse_form_answer(text: &str, form: &Form) -> Option<(Vec<String>, Vec<bool>)> {
    let mut values: BTreeMap<&str, String> = BTreeMap::new();
    let mut keeps: BTreeMap<&str, bool> = BTreeMap::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.splitn(3, '\t').collect();
        match parts.as_slice() {
            ["field", name, value] => {
                values.insert(name, (*value).to_owned());
            }
            ["save", name, on] => {
                keeps.insert(name, *on == "1");
            }
            _ => {}
        }
    }
    let mut out = (Vec::new(), Vec::new());
    for field in &form.fields {
        out.0.push(values.get(field.name.as_str())?.clone());
        out.1
            .push(keeps.get(field.name.as_str()).copied().unwrap_or(false));
    }
    Some(out)
}

/// Show the form; its answer. Where the window cannot be shown: kdialog,
/// a field at a time, keeping nothing.
fn show_form(tools: &Tools, request: &str, form: &Form) -> Option<(Vec<String>, Vec<bool>)> {
    if let Ok(mut child) = Command::new(&tools.window)
        .arg("login")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(request.as_bytes());
        }
        let out = child.wait_with_output().ok()?;
        if out.status.code() != Some(3) {
            return if out.status.success() {
                parse_form_answer(&String::from_utf8_lossy(&out.stdout), form)
            } else {
                None
            };
        }
    }
    if !crate::launch::has_display() {
        return None;
    }
    let mut values = Vec::new();
    for field in &form.fields {
        let label = crate::window::clean(&field.label);
        let mut cmd = Command::new(&tools.kdialog);
        cmd.arg("--title").arg("Вход в сеть");
        match field.kind {
            Kind::Password => {
                cmd.arg("--password").arg(&label);
            }
            Kind::Select => {
                cmd.arg("--combobox").arg(&label);
                for choice in &field.choices {
                    cmd.arg(&choice.name);
                }
            }
            Kind::Text | Kind::Token => {
                cmd.arg("--inputbox").arg(&label);
            }
        }
        let out = cmd.stderr(Stdio::null()).output().ok()?;
        let value = String::from_utf8(out.stdout).ok()?;
        let value = value.trim_end_matches('\n');
        if !out.status.success() {
            return None;
        }
        values.push(value.to_owned());
    }
    let keeps = vec![false; values.len()];
    Some((values, keeps))
}

/// How one login through the gateway's forms ended.
enum Outcome {
    /// In: the session, and what was answered.
    Done(Session, Vec<Answered>),
    /// The person closed a form.
    Cancelled,
    /// Why not, in words for the person.
    Failed(String),
}

/// One login of `zone` through the gateway's forms (`cellward-oc-auth`):
/// each form in the connect window, prefilled with what was kept; sent by
/// itself when everything it asks is known — not a code, and not after a
/// try that did not bring the network up (`note`).
fn gateway_login(
    tools: &Tools,
    zone: &str,
    asked: (Mode, Wants<'_>),
    cfg: &OcConfig,
    (saved, note): (&Saved, Option<&str>),
) -> Outcome {
    let helper = tools.core.with_file_name(OC_AUTH);
    // Its environment from scratch, as the client's: no proxy of the
    // session's between it and the gateway.
    let env = std::env::vars_os().filter(|(key, _)| {
        crate::openconnect::CLIENT_ENV_KEPT
            .iter()
            .any(|kept| key == OsStr::new(kept))
    });
    let spawned = Command::new(&helper)
        .env_clear()
        .envs(env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => return Outcome::Failed(format!("не запустить {}: {e}", helper.display())),
    };
    let (Some(mut to), Some(from)) = (child.stdin.take(), child.stdout.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return Outcome::Failed("помощник входа без каналов".to_owned());
    };
    // Owning the helper's input: dropped, it is the end of it — a helper
    // waiting for an answer that will not come reads that and stops.
    let mut send = move |line: String| writeln!(to, "{line}").and_then(|()| to.flush()).is_ok();
    if !send(oc_form::Request::of(cfg).encode()) {
        let _ = child.wait();
        return Outcome::Failed("помощник входа не принял запрос".to_owned());
    }
    let keyring = tools.secret_tool.is_file();
    let mut auto = note.is_none();
    let mut first = true;
    let mut answered: BTreeMap<String, Answered> = BTreeMap::new();
    let mut outcome = Outcome::Failed("помощник входа замолчал, не договорив".to_owned());
    for line in BufReader::new(from).lines() {
        let Ok(line) = line else { break };
        let said = match Said::decode(&line) {
            Ok(said) => said,
            Err(e) => {
                outcome = Outcome::Failed(format!("помощник входа сказал непонятное ({e})"));
                break;
            }
        };
        match said {
            Said::Log { text } => eprintln!("cellward: вход в сеть {zone}: {text}"),
            Said::Form(form) => {
                let mut notes: Vec<String> = Vec::new();
                if first {
                    notes.extend(note.map(str::to_owned));
                }
                first = false;
                let mut values = Vec::new();
                let mut keeps = Vec::new();
                for field in &form.fields {
                    let before = answered.get(&field.name);
                    let kept = match field.kind {
                        Kind::Password if keyring => keyring_lookup(tools, zone, &field.name),
                        Kind::Password | Kind::Token => None,
                        Kind::Text | Kind::Select => known(saved, field),
                    };
                    // A choice kept that the gateway offers no more.
                    if field.kind == Kind::Select {
                        if let Some(gone) = saved
                            .fields
                            .get(&field.name)
                            .filter(|v| !field.choices.iter().any(|c| &c.name == *v))
                        {
                            notes.push(format!(
                                "Сохранённого выбора «{gone}» у шлюза больше нет — выбери из тех, \
                                 что есть."
                            ));
                        }
                    }
                    let value = before
                        .filter(|_| field.kind != Kind::Token)
                        .map(|b| b.value.clone())
                        .or_else(|| kept.clone())
                        .unwrap_or_else(|| field.value.clone());
                    // Ticked where it was kept before: in the file, or the keyring.
                    let keep = before.map_or(
                        (kept.is_some() && saved.fields.contains_key(&field.name))
                            || (field.kind == Kind::Password && kept.is_some()),
                        |b| b.keep,
                    );
                    values.push(value);
                    keeps.push(keep);
                }
                let all_known = form.error.is_empty()
                    && form
                        .fields
                        .iter()
                        .zip(&values)
                        .all(|(f, v)| f.kind != Kind::Token && !v.is_empty());
                let answer = if auto && all_known {
                    Some((values, keeps))
                } else {
                    auto = false;
                    let request = form_request(
                        zone,
                        asked,
                        cfg,
                        &form,
                        (&values, &keeps),
                        (&notes, keyring),
                    );
                    show_form(tools, &request, &form)
                };
                let Some((values, keeps)) = answer else {
                    send(oc_form::Answer::Cancel.encode());
                    outcome = Outcome::Cancelled;
                    break;
                };
                let mut given = BTreeMap::new();
                for ((field, value), keep) in form.fields.iter().zip(values).zip(keeps) {
                    given.insert(field.name.clone(), value.clone());
                    answered.insert(
                        field.name.clone(),
                        Answered {
                            field: field.clone(),
                            value,
                            keep,
                        },
                    );
                }
                if !send(oc_form::Answer::Values(given).encode()) {
                    break;
                }
            }
            Said::Done {
                cookie,
                connect_url,
                fingerprint,
                address,
            } => {
                outcome = Outcome::Done(
                    Session {
                        cookie,
                        connect_url,
                        fingerprint,
                        address,
                    },
                    answered.into_values().collect(),
                );
                break;
            }
            Said::Failed { why } => {
                outcome = if why == CANCELLED {
                    Outcome::Cancelled
                } else {
                    Outcome::Failed(why)
                };
                break;
            }
            Said::Probe { .. } => {}
        }
    }
    drop(send);
    let _ = child.wait();
    outcome
}

/// What `cellward-oc-auth` says when a form was closed.
const CANCELLED: &str = "вход отменён";

/// Keep what the person chose to keep of a login that brought the network
/// up, and forget what they unticked.
fn keep_answers(tools: &Tools, zone: &str, saved: &Saved, answered: &[Answered]) {
    let keyring = tools.secret_tool.is_file();
    let mut fields = saved.fields.clone();
    for a in answered {
        match a.field.kind {
            Kind::Text | Kind::Select => {
                if a.keep {
                    fields.insert(a.field.name.clone(), a.value.clone());
                } else {
                    fields.remove(&a.field.name);
                }
            }
            Kind::Password if keyring => keyring_keep(tools, zone, &a.field.name, &a.value, a.keep),
            Kind::Password | Kind::Token => {}
        }
    }
    store_saved(&tools.state, zone, &fields);
}

/// The login of `zone` through its gateway's forms, and the session handed
/// to its holder while it starts; again, with what went wrong, until the
/// network is up or the person gives up. Whether the person went through
/// with it — up or not.
fn log_in(tools: &Tools, zone: &str, (mode, wants): (Mode, Wants<'_>), cfg: &OcConfig) -> bool {
    let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR").filter(|r| !r.is_empty()) else {
        eprintln!("cellward: XDG_RUNTIME_DIR не задан — вход в сеть {zone} передать некуда");
        return false;
    };
    let mut note: Option<String> = None;
    loop {
        let saved = load_saved(&tools.state, zone, cfg);
        let (session, answered) =
            match gateway_login(tools, zone, (mode, wants), cfg, (&saved, note.as_deref())) {
                Outcome::Done(session, answered) => (session, answered),
                Outcome::Cancelled => return false,
                Outcome::Failed(why) => {
                    eprintln!("cellward: вход в сеть {zone}: {why}");
                    crate::dialog::notify(
                        &tools.notify_send,
                        None,
                        "15000",
                        &format!("Вход в сеть {zone} не удался"),
                        &why,
                    );
                    return true;
                }
            };
        let offer = match Offer::open(Path::new(&runtime), zone, session) {
            Ok(offer) => offer,
            Err(e) => {
                eprintln!("cellward: {e}");
                return true;
            }
        };
        Real(tools).start(zone, wants);
        let taken = offer.taken();
        if crate::cli::zone_up(&tools.state, OsStr::new(zone)).is_some() {
            keep_answers(tools, zone, &saved, &answered);
            return true;
        }
        note = Some(if taken {
            format!(
                "Шлюз впустил, но сеть не подключилась (journalctl --user -u vpn-zone@{zone}) — \
                 ещё раз?"
            )
        } else {
            format!(
                "Сеть не подключилась, вход до неё не дошёл (journalctl --user -u \
                 vpn-zone@{zone})."
            )
        });
    }
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

    /// The steps of a test: its answers, and a network that comes up when
    /// started, or never.
    struct Fake {
        answer: bool,
        comes_up: bool,
        up: Cell<bool>,
        asked: Cell<u32>,
        logins: Cell<u32>,
        starts: Cell<u32>,
        told: Cell<u32>,
        session: Option<String>,
    }

    impl Fake {
        fn new(answer: bool, comes_up: bool) -> Self {
            Self {
                answer,
                comes_up,
                up: Cell::new(false),
                asked: Cell::new(0),
                logins: Cell::new(0),
                starts: Cell::new(0),
                told: Cell::new(0),
                session: None,
            }
        }
    }

    impl Steps for Fake {
        fn ask(&self, _: &str, _: Mode, _: Wants<'_>) -> bool {
            self.asked.set(self.asked.get() + 1);
            self.answer
        }

        fn log_in(&self, zone: &str, (_, wants): (Mode, Wants<'_>), _: &OcConfig) -> bool {
            self.logins.set(self.logins.get() + 1);
            if self.answer {
                self.start(zone, wants);
            }
            self.answer
        }

        fn start(&self, _: &str, _: Wants<'_>) {
            self.starts.set(self.starts.get() + 1);
            self.up.set(self.comes_up);
        }

        fn up(&self, _: &str) -> bool {
            self.up.get()
        }

        fn connected(&self, _: &str, _: Wants<'_>) {
            self.told.set(self.told.get() + 1);
        }

        fn autostart(&self) -> Option<String> {
            self.session.clone()
        }
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
        // A network whose login is asked asks by default.
        fs::write(
            t.state.join("work/config.conf"),
            "[OpenConnect]\nServer = vpn.example.org\n",
        )
        .unwrap();
        assert_eq!(
            mode(&t.state, &t.config, "work"),
            (Mode::Ask, Source::Default)
        );
        assert!(asks_login(&t.state, "work").is_some());
        // Its password in a file: nothing to ask, it starts as any other.
        fs::write(
            t.state.join("work/config.conf"),
            "[OpenConnect]\nServer = vpn.example.org\nPasswordFile = /run/x\n",
        )
        .unwrap();
        assert_eq!(
            mode(&t.state, &t.config, "work"),
            (Mode::Auto, Source::Default)
        );
        assert!(asks_login(&t.state, "work").is_none());
    }

    /// `auto` starts; `ask` and `manual` ask, and the answer decides; the
    /// person connecting it is not asked; a launch after an answer asks anew.
    #[test]
    fn the_answer_decides_and_the_next_launch_asks_anew() {
        let t = tools("consent");
        let program = Wants::Program("Firefox");
        let fake = Fake::new(false, true);
        assert!(bring_up_with(&t, "work", program, &fake).is_ok());
        assert_eq!((fake.asked.get(), fake.starts.get()), (0, 1), "auto starts");
        assert_eq!(fake.told.get(), 0, "nobody waited on a question: no notice");
        set(&t.state, &t.config, "work", Some(Mode::Ask)).unwrap();
        let fake = Fake::new(false, true);
        let refused = bring_up_with(&t, "work", program, &fake).unwrap_err();
        assert!(!refused.taken, "its own question");
        let refused = refused.why;
        assert!(refused.contains("«Firefox» не запущена"), "{refused}");
        assert_eq!((fake.asked.get(), fake.starts.get()), (1, 0));
        assert_eq!(fake.told.get(), 0, "refused: no notice");
        let fake = Fake::new(true, true);
        assert!(bring_up_with(&t, "work", program, &fake).is_ok());
        assert_eq!((fake.asked.get(), fake.starts.get()), (1, 1));
        assert_eq!(fake.told.get(), 1, "agreed and up: the person is told");
        assert_eq!(last_answer(&t.state.join("work")), Some((2, true, None)));
        // Agreed, and it did not come up: said so — not "connected".
        let fake = Fake::new(true, false);
        let failed = bring_up_with(&t, "work", program, &fake).unwrap_err().why;
        assert!(failed.contains("зона work не поднимается"), "{failed}");
        assert_eq!(fake.told.get(), 0);
        // The person connecting it: no question, and no notice — what they
        // ran says it.
        let fake = Fake::new(false, true);
        assert!(bring_up_with(&t, "work", Wants::Person, &fake).is_ok());
        assert_eq!((fake.asked.get(), fake.starts.get()), (0, 1));
        assert_eq!(fake.told.get(), 0);
        // Manual: asked too, and a refusal says how to connect it.
        set(&t.state, &t.config, "work", Some(Mode::Manual)).unwrap();
        let fake = Fake::new(false, true);
        let container = Wants::Container("банк");
        let refused = bring_up_with(&t, "work", container, &fake).unwrap_err().why;
        assert!(
            refused.contains("только вручную") && refused.contains("cellward up work"),
            "{refused}"
        );
        assert!(
            refused.contains("«банк» остался в прежней сети"),
            "{refused}"
        );
    }

    /// One question per network: a launch that waited while another's
    /// question was open takes its refusal — written after what it saw —,
    /// and is not asked again; one that saw it asks.
    #[test]
    fn a_launch_that_waited_takes_the_refusal_given_meanwhile() {
        let t = tools("waited");
        let dir = t.state.join("work");
        write_answer(&dir, 4, true, None).unwrap();
        write_answer(&dir, 5, false, None).unwrap();
        let wants = (Mode::Ask, Wants::Program("Telegram"));
        let fake = Fake::new(true, true);
        let refused = decide(&t, "work", wants, 4, (None, &fake)).unwrap_err();
        assert!(
            refused.taken,
            "the answer to the question it waited through"
        );
        assert!(refused.why.contains("«Telegram» не запущена"), "{refused}");
        assert_eq!(fake.asked.get(), 0, "not asked again");
        assert!(decide(&t, "work", wants, 5, (None, &fake)).is_ok());
        assert_eq!(fake.asked.get(), 1);
        assert_eq!(last_answer(&dir), Some((6, true, None)));
        // Up since: the next one takes it, and the notice was the asker's.
        assert!(decide(&t, "work", wants, 6, (None, &fake)).is_ok());
        assert_eq!((fake.asked.get(), fake.told.get()), (1, 1));
    }

    /// A network whose login is asked takes it in the form, whatever its
    /// mode — the form is its question —, the person's `up` too.
    #[test]
    fn a_login_is_asked_in_the_form() {
        let t = tools("login");
        fs::write(
            t.state.join("work/config.conf"),
            "[OpenConnect]\nServer = vpn.example.org\n",
        )
        .unwrap();
        set(&t.state, &t.config, "work", Some(Mode::Auto)).unwrap();
        let fake = Fake::new(true, true);
        assert!(bring_up_with(&t, "work", Wants::Person, &fake).is_ok());
        assert_eq!((fake.asked.get(), fake.logins.get()), (0, 1));
        assert_eq!(fake.told.get(), 1, "the person waited on the form");
        let fake = Fake::new(false, true);
        let refused = bring_up_with(&t, "work", Wants::Program("Wine"), &fake).unwrap_err();
        assert!(refused.why.contains("«Wine» не запущена"), "{refused}");
    }

    /// The autostart asks once per network in its session, however far
    /// apart its programs start: a refusal at an autostart question is the
    /// next autostart launch's too — not another session's, not a launch's
    /// by hand; and a network agreed to that did not come up is tried again.
    #[test]
    fn the_autostart_asks_once_per_network_in_its_session() {
        let t = tools("autostart");
        set(&t.state, &t.config, "work", Some(Mode::Ask)).unwrap();
        let at = |session: &str, answer, comes_up| Fake {
            session: Some(session.to_owned()),
            ..Fake::new(answer, comes_up)
        };
        let first = at("1:2:3", false, true);
        let own = bring_up_with(&t, "work", Wants::Program("Telegram"), &first).unwrap_err();
        assert!(!own.taken);
        assert_eq!(first.asked.get(), 1);
        assert_eq!(
            last_answer(&t.state.join("work")),
            Some((1, false, Some("1:2:3".to_owned())))
        );
        // Later in the same session: taken, not asked.
        let later = at("1:2:3", true, true);
        let taken = bring_up_with(&t, "work", Wants::Program("Signal"), &later).unwrap_err();
        assert!(taken.taken, "{taken:?}");
        assert!(taken.why.contains("«Signal» не запущена"), "{taken:?}");
        assert_eq!(later.asked.get(), 0);
        // The next login: asked.
        let next_login = at("1:2:4", false, true);
        assert!(bring_up_with(&t, "work", Wants::Program("Signal"), &next_login).is_err());
        assert_eq!(next_login.asked.get(), 1);
        // By hand: asked.
        let by_hand = Fake::new(true, false);
        let failed = bring_up_with(&t, "work", Wants::Program("Signal"), &by_hand).unwrap_err();
        assert!(!failed.taken);
        assert_eq!(by_hand.asked.get(), 1);
        // Agreed at an autostart question and not up: no session kept, the
        // next autostart launch asks.
        let agreed = at("1:2:5", true, false);
        assert!(bring_up_with(&t, "work", Wants::Program("Signal"), &agreed).is_err());
        let again = at("1:2:5", false, true);
        assert!(bring_up_with(&t, "work", Wants::Program("Signal"), &again).is_err());
        assert_eq!(again.asked.get(), 1, "a failure is no refusal to take");
    }

    #[test]
    fn the_notice_says_the_network_and_what_goes_on() {
        let (title, body) = connected_text("work", Wants::Program("Firefox"));
        assert_eq!(title, "Сеть work подключена");
        assert_eq!(body, "«Firefox» запускается.");
        let (_, body) = connected_text("work", Wants::Container("банк"));
        assert_eq!(body, "Контейнер «банк» переходит в неё.");
        assert!(connected_text("work", Wants::Person).1.is_empty());
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

    /// The session's lines there and back; never the cookie in a log.
    #[test]
    fn a_session_goes_there_and_back_and_its_cookie_is_not_logged() {
        let session = Session {
            cookie: "webvpn=Xq\t7\nZw".into(),
            connect_url: "https://vpn.example.org/".into(),
            fingerprint: "pin-sha256:abc=".into(),
            address: "192.0.2.10".into(),
        };
        let back = Session::decode(&session.encode()).unwrap();
        assert_eq!(back.cookie, "webvpn=Xq7Zw", "no tab, no line break");
        assert_eq!(
            (
                back.connect_url.as_str(),
                back.fingerprint.as_str(),
                back.address.as_str()
            ),
            ("https://vpn.example.org/", "pin-sha256:abc=", "192.0.2.10")
        );
        assert_eq!(
            Session::decode("url\thttps://x/\n"),
            None,
            "no cookie: none"
        );
        let shown = format!("{session:?}");
        assert!(
            !shown.contains("Xq") && !shown.contains("webvpn"),
            "{shown}"
        );
    }

    fn gateway_form() -> Form {
        let field = |name: &str, label: &str, kind| Field {
            name: name.into(),
            label: label.into(),
            kind,
            value: String::new(),
            choices: vec![],
        };
        let mut group = field("group_list", "GROUP:", Kind::Select);
        group.value = "Employees".into();
        group.choices = vec![
            oc_form::Choice {
                name: "Employees".into(),
                label: "Employees".into(),
            },
            oc_form::Choice {
                name: "Contractors".into(),
                label: "Подрядчики".into(),
            },
        ];
        Form {
            banner: String::new(),
            message: "Please enter your username and password.".into(),
            error: "Login failed.".into(),
            fields: vec![
                group,
                field("username", "Username:", Kind::Text),
                field("password", "Password:", Kind::Password),
            ],
            group: Some("group_list".into()),
        }
    }

    /// The window's request for a gateway's form — its words as the
    /// gateway's, its fields prefilled, a choice's choices, a box to keep
    /// by each (a password's with a keyring only) — and the answer back.
    #[test]
    fn the_gateways_form_is_shown_prefilled_and_read_back() {
        let cfg = OcConfig::parse(b"[OpenConnect]\nServer = vpn.example.org\n").unwrap();
        let form = gateway_form();
        let values = ["Contractors".to_owned(), "ivan".to_owned(), String::new()];
        let keeps = [true, true, false];
        let notes = ["Сеть не подключилась.".to_owned()];
        let req = form_request(
            "work",
            (Mode::Ask, Wants::Program("Wine")),
            &cfg,
            &form,
            (&values, &keeps),
            (&notes, true),
        );
        assert!(req.starts_with("title\tВход в сеть work\n"), "{req}");
        assert!(req.contains("note\t«Wine» хочет в сеть work. Шлюз vpn.example.org.\n"));
        assert!(req.contains("note\tСеть не подключилась.\n"));
        assert!(req.contains("note\tШлюз: Please enter your username and password.\n"));
        assert!(req.contains("note\t⚠ Шлюз: Login failed.\n"));
        assert!(req.contains("field\tgroup_list\tGROUP:\tselect\tContractors\n"));
        assert!(req.contains("choice\tgroup_list\tContractors\tПодрядчики\n"));
        assert!(req.contains("field\tusername\tUsername:\ttext\tivan\n"));
        assert!(req.contains("save\tusername\tСохранить\t1\n"));
        assert!(req.contains("field\tpassword\tPassword:\tsecret\t\n"));
        assert!(req.contains("save\tpassword\tСохранить в связке ключей сеанса\t0\n"));
        let plain = form_request(
            "work",
            (Mode::Manual, Wants::Person),
            &cfg,
            &form,
            (&values, &keeps),
            (&[], false),
        );
        assert!(!plain.contains("save\tpassword"), "no keyring: {plain}");
        assert!(
            !plain.contains("вручную") && !plain.contains("ждёт"),
            "{plain}"
        );
        let (values, keeps) = parse_form_answer(
            "field\tgroup_list\tEmployees\nfield\tusername\tivan\nfield\tpassword\tp w\n\
             save\tusername\t1\nsave\tpassword\t1\n",
            &form,
        )
        .unwrap();
        assert_eq!(values, ["Employees", "ivan", "p w"]);
        assert_eq!(keeps, [false, true, true]);
        assert!(parse_form_answer("field\tusername\tivan\n", &form).is_none());
    }

    /// What was kept is known by the gateway's field name; the file of
    /// before and the config still name the user and the group.
    #[test]
    fn what_was_kept_is_known_by_field_and_the_old_file_still_counts() {
        let t = tools("kept");
        let cfg =
            OcConfig::parse("[OpenConnect]\nServer = a.b\nAuthGroup = Подрядчики\n".as_bytes())
                .unwrap();
        fs::write(
            t.state.join("work").join(LAST_LOGIN),
            "user\tivan\ngroup\t\n",
        )
        .unwrap();
        let saved = load_saved(&t.state, "work", &cfg);
        let form = gateway_form();
        assert_eq!(known(&saved, &form.fields[1]).as_deref(), Some("ivan"));
        assert_eq!(
            known(&saved, &form.fields[0]).as_deref(),
            Some("Contractors"),
            "the config's group, by its label"
        );
        assert_eq!(known(&saved, &form.fields[2]), None, "never a password");
        let mut fields = BTreeMap::new();
        fields.insert("username".to_owned(), "petr".to_owned());
        store_saved(&t.state, "work", &fields);
        let saved = load_saved(&t.state, "work", &cfg);
        assert_eq!(known(&saved, &form.fields[1]).as_deref(), Some("petr"));
        let text = fs::read_to_string(t.state.join("work").join(LAST_LOGIN)).unwrap();
        assert_eq!(text, "field\tusername\tpetr\n");
        assert!(asks_user(&form.fields[1]) && !asks_user(&form.fields[2]));
    }

    /// The session served to the network's holder alone: a process of any
    /// other unit (this test's) is closed on with nothing; the offer taken
    /// back ends the wait.
    #[test]
    fn a_session_is_served_to_the_holder_alone() {
        let runtime = std::env::temp_dir().join(format!("vz-connect-offer-{}", std::process::id()));
        let _ = fs::remove_dir_all(&runtime);
        fs::create_dir_all(&runtime).unwrap();
        let session = Session {
            cookie: "x".into(),
            ..Session::default()
        };
        let offer = Offer::open(&runtime, "work", session).unwrap();
        let path = login_socket(&runtime, "work");
        let mut stream = UnixStream::connect(&path).unwrap();
        let mut got = String::new();
        stream.read_to_string(&mut got).unwrap();
        assert_eq!(got, "", "not the holder: nothing");
        assert!(!offer.taken(), "nobody took it");
        assert!(!path.exists(), "taken back");
        assert!(!in_unit(std::process::id() as i32, "vpn-zone@work.service"));
    }
}
