//! Connecting a network (`docs/PERMISSIONS.md` §11.16, the owner,
//! 2026-09-29): a network's «Подключение» — `auto`, it comes up when a
//! program is launched into it, as it always did; `ask`, the person is
//! asked first; `manual`, only the person connects it, and a launch into it
//! while it is down asks whether to connect it now — and, for a network
//! whose login is asked (`Login = ask` of an OpenConnect zone), the connect
//! window's login form, whose answers go to the zone's holder alone.
//!
//! The question is the launch window's, guarded as every question of it is
//! (`crate::window::question`): nothing is taken until the person has been
//! still with it in view; the form is `vpn-zone-window login`, guarded once.
//! One question per network at a time: launches that want the same network
//! meanwhile wait for its outcome and take it — autostart after the login
//! asks once per network, not once per program. Programs wait with no
//! network while it is open: a network that is down has no route out, so
//! nothing goes anywhere meanwhile. «Не подключать», a closed question, or
//! no way to ask at all: the network stays down, and the launch is refused
//! where the person sees it — never a silent end.
//!
//! **The login** never touches a disk. The form's answers come back on the
//! window's standard output; they go to the zone's holder on a socket of the
//! user's runtime directory ([`Offer`]), served to that network's holder
//! alone — its peer's cgroup must be the unit `vpn-zone@<network>.service`,
//! so a program of a container of the same user that finds the socket gets
//! nothing —, and from the holder to `openconnect` on its standard input
//! (`crate::zone`). The user and the group are remembered for the next form
//! (the network's `login` file); the password only where the person ticks
//! «запомнить», in the session's keyring (Secret Service, `secret-tool`,
//! handed the password on its standard input). A one-time code never.

use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::cli::{read_setting, DECLARED_DIR};
use crate::container::Source;
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
/// In a network's state directory: the user and the group of its last
/// login that brought it up — not secret, the form's prefill.
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

/// The network's OpenConnect section, where its login is asked
/// (`Login = ask`).
pub fn asks_login(state: &Path, zone: &str) -> Option<OcConfig> {
    let raw = fs::read(state.join(zone).join("config.conf")).ok()?;
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

/// What bringing a network up takes, apart: asking, logging in, starting,
/// and whether it is up — the real ones ([`Real`]), or a test's.
trait Steps {
    fn ask(&self, zone: &str, mode: Mode, wants: Wants<'_>) -> bool;
    fn log_in(&self, zone: &str, wants: Wants<'_>, cfg: &OcConfig) -> bool;
    fn start(&self, zone: &str, wants: Wants<'_>);
    fn up(&self, zone: &str) -> bool;
}

struct Real<'a>(&'a Tools);

impl Steps for Real<'_> {
    fn ask(&self, zone: &str, mode: Mode, wants: Wants<'_>) -> bool {
        question(self.0, zone, mode, wants)
    }

    fn log_in(&self, zone: &str, wants: Wants<'_>, cfg: &OcConfig) -> bool {
        log_in(self.0, zone, wants, cfg)
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
}

/// `zone` up for `wants`, as its «Подключение» says: `auto` starts it;
/// `ask` and `manual` ask the person first (a launch, a container — the
/// person connecting it asks nothing); a network whose login is asked
/// (`Login = ask`) takes it in the connect window's form, asked again with
/// what went wrong until the network is up or the person gives up. One
/// question per network at a time: a launch that waited through another's
/// takes its outcome, one after it asks anew. `Err`: why it is not up, for
/// the person.
pub fn bring_up(tools: &Tools, zone: &str, wants: Wants<'_>) -> Result<(), String> {
    bring_up_with(tools, zone, wants, &Real(tools))
}

fn bring_up_with(
    tools: &Tools,
    zone: &str,
    wants: Wants<'_>,
    steps: &impl Steps,
) -> Result<(), String> {
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
            Err(failed(zone, wants))
        };
    }
    let dir = tools.state.join(zone);
    // The questions answered before this launch began to wait: an answer
    // after them was given while it waited, and is its answer too.
    let seen = last_answer(&dir).map_or(0, |(seq, _)| seq);
    decide(tools, zone, (mode, wants), seen, (login.as_ref(), steps))
}

/// Under the network's question lock: up meanwhile — yes; refused since
/// `seen` — that refusal; else the person's, written for the launches that
/// wait for it.
fn decide(
    tools: &Tools,
    zone: &str,
    (mode, wants): (Mode, Wants<'_>),
    seen: u64,
    (login, steps): (Option<&OcConfig>, &impl Steps),
) -> Result<(), String> {
    let dir = tools.state.join(zone);
    let _lock = lock(&dir)?;
    if steps.up(zone) {
        return Ok(());
    }
    let last = last_answer(&dir);
    if let Some((seq, false)) = last {
        if seq > seen {
            return Err(refusal(zone, mode, wants));
        }
    }
    let yes = match login {
        // The form is the question: «Подключить» there is the yes.
        Some(cfg) => steps.log_in(zone, wants, cfg),
        None => {
            let yes = matches!(wants, Wants::Person) || steps.ask(zone, mode, wants);
            if yes {
                steps.start(zone, wants);
            }
            yes
        }
    };
    let up = yes && steps.up(zone);
    let seq = last.map_or(0, |(seq, _)| seq).max(seen) + 1;
    if let Err(e) = write_answer(&dir, seq, up) {
        eprintln!("cellward: ответ о подключении сети {zone} не записан: {e}");
    }
    match (up, yes) {
        (true, _) => Ok(()),
        (false, true) => Err(failed(zone, wants)),
        (false, false) => Err(refusal(zone, mode, wants)),
    }
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

// --- THE LOGIN (step 2 of §11.16) -------------------------------------------

/// A network's login, as its form gave it.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Login {
    pub user: String,
    pub group: String,
    pub password: String,
    /// A one-time code; empty where the gateway asks for none.
    pub code: String,
}

/// Never the password, nor the code, in a log.
impl std::fmt::Debug for Login {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Login")
            .field("user", &self.user)
            .field("group", &self.group)
            .field("password", &"…")
            .field("code", &!self.code.is_empty())
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

impl Login {
    fn encode(&self) -> String {
        [
            ("user", &self.user),
            ("group", &self.group),
            ("password", &self.password),
            ("code", &self.code),
        ]
        .iter()
        .map(|(key, value)| format!("{key}\t{}\n", one_line(value)))
        .collect()
    }

    /// The lines back; `None` without a password.
    fn decode(text: &str) -> Option<Self> {
        let mut login = Self::default();
        for line in text.lines() {
            match line.split_once('\t') {
                Some(("user", v)) => login.user = v.to_owned(),
                Some(("group", v)) => login.group = v.to_owned(),
                Some(("password", v)) => login.password = v.to_owned(),
                Some(("code", v)) => login.code = v.to_owned(),
                _ => {}
            }
        }
        (!login.password.is_empty()).then_some(login)
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

/// A login handed to a network's holder while the network starts: the
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
    pub fn open(runtime: &Path, zone: &str, login: Login) -> Result<Self, String> {
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
        let serving = std::thread::spawn(move || serve(&listener, &unit, &login));
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

/// Serve the login to the unit's process that asks, once.
fn serve(listener: &UnixListener, unit: &str, login: &Login) -> bool {
    for conn in listener.incoming() {
        let Ok(mut conn) = conn else {
            return false;
        };
        let ours = crate::sys::peer_pid(conn.as_raw_fd()).is_some_and(|pid| in_unit(pid, unit));
        if !ours {
            continue;
        }
        return conn.write_all(login.encode().as_bytes()).is_ok();
    }
    false
}

/// The holder of `zone`, starting: the login handed over by whoever
/// started it ([`Offer`]). `Err`: why there is none, for the journal.
pub fn fetch_login(zone: &str) -> Result<Login, String> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|r| !r.is_empty())
        .ok_or("XDG_RUNTIME_DIR is not set: there is nowhere to take the login from")?;
    let path = login_socket(Path::new(&runtime), zone);
    let mut stream = UnixStream::connect(&path).map_err(|e| {
        format!(
            "no login was given for {zone} ({}: {e}) — Login = ask: it is asked when a program \
             is launched into the zone, or by `cellward up {zone}`",
            path.display()
        )
    })?;
    let mut text = String::new();
    stream
        .read_to_string(&mut text)
        .map_err(|e| format!("the login for {zone} could not be read: {e}"))?;
    Login::decode(&text).ok_or_else(|| format!("no login was handed over for {zone}"))
}

/// The user and the group of the network's last login that brought it up.
fn last_login(state: &Path, zone: &str) -> (Option<String>, Option<String>) {
    let text = fs::read_to_string(state.join(zone).join(LAST_LOGIN)).unwrap_or_default();
    let get = |key: &str| {
        text.lines().find_map(|line| {
            line.split_once('\t')
                .filter(|(k, v)| *k == key && !v.is_empty())
                .map(|(_, v)| v.to_owned())
        })
    };
    (get("user"), get("group"))
}

fn save_last_login(state: &Path, zone: &str, login: &Login) {
    let text = format!(
        "user\t{}\ngroup\t{}\n",
        one_line(&login.user),
        one_line(&login.group)
    );
    if let Err(e) =
        crate::desktop::write_atomically(&state.join(zone).join(LAST_LOGIN), text.as_bytes())
    {
        eprintln!("cellward: пользователь сети {zone} не запомнен: {e}");
    }
}

/// The keyring's attributes of a network's password.
fn keyring_attributes(zone: &str, user: &str) -> [String; 6] {
    [
        "service".into(),
        "cellward".into(),
        "network".into(),
        zone.into(),
        "user".into(),
        user.into(),
    ]
}

/// The password remembered for `zone` and `user`, if there is one.
fn keyring_lookup(tools: &Tools, zone: &str, user: &str) -> Option<String> {
    let out = Command::new(&tools.secret_tool)
        .arg("lookup")
        .args(keyring_attributes(zone, user))
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let password = String::from_utf8(out.stdout).ok()?;
    let password = password.trim_end_matches('\n');
    (out.status.success() && !password.is_empty()).then(|| password.to_owned())
}

/// Remember `login`'s password (`true`) or forget it, in the session's
/// keyring. The password goes on `secret-tool`'s standard input.
fn keyring_keep(tools: &Tools, zone: &str, login: &Login, keep: bool) {
    let attributes = keyring_attributes(zone, &login.user);
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
                    stdin.write_all(login.password.as_bytes())?;
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

/// What the form came back with.
struct Answer {
    login: Login,
    remember: bool,
}

/// The connect window's login form for `zone`, prefilled; `error` said above
/// it when a try before did not bring the network up.
fn login_request(
    zone: &str,
    wants: Wants<'_>,
    cfg: &OcConfig,
    prefill: (&str, &str, &str),
    (error, keyring): (Option<&str>, bool),
) -> String {
    let (user, group, password) = prefill;
    let mut req = format!(
        "title\tВход в сеть {zone}\nnote\t{} Шлюз {}.\n",
        crate::window::clean(&who(zone, wants)),
        crate::window::clean(&cfg.server)
    );
    if let Wants::Program(_) = wants {
        req.push_str("note\tПрограмма ждёт без сети.\n");
    }
    if let Some(error) = error {
        req.push_str(&format!("note\t{}\n", crate::window::clean(error)));
    }
    req.push_str(&format!("guard\t{}\n", crate::dialog::TOO_FAST.as_millis()));
    for (tag, label, kind, value) in [
        ("user", "Пользователь", "text", user),
        ("group", "Группа (если шлюз просит)", "optional", group),
        ("password", "Пароль", "secret", password),
        ("code", "Одноразовый код (если шлюз просит)", "code", ""),
    ] {
        req.push_str(&format!(
            "field\t{tag}\t{label}\t{kind}\t{}\n",
            one_line(value)
        ));
    }
    if keyring {
        req.push_str(&format!(
            "remember\tЗапомнить пароль в связке ключей сеанса\t{}\n",
            u8::from(!password.is_empty())
        ));
    }
    req
}

/// The form's answer lines back.
fn parse_answer(text: &str) -> Option<Answer> {
    let mut login = Login::default();
    let mut remember = false;
    for line in text.lines() {
        let fields: Vec<&str> = line.splitn(3, '\t').collect();
        match fields.as_slice() {
            ["field", "user", v] => login.user = (*v).to_owned(),
            ["field", "group", v] => login.group = (*v).to_owned(),
            ["field", "password", v] => login.password = (*v).to_owned(),
            ["field", "code", v] => login.code = (*v).to_owned(),
            ["remember", on] => remember = *on == "1",
            _ => {}
        }
    }
    (!login.password.is_empty()).then_some(Answer { login, remember })
}

/// Show the form; its answer. Where the window cannot be shown: kdialog
/// asks the password alone (no code: a gateway that asks one needs the
/// window).
fn login_form(tools: &Tools, request: &str, user: &str, group: &str) -> Option<Answer> {
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
                parse_answer(&String::from_utf8_lossy(&out.stdout))
            } else {
                None
            };
        }
    }
    if !crate::launch::has_display() {
        return None;
    }
    let out = Command::new(&tools.kdialog)
        .arg("--title")
        .arg("Вход в сеть")
        .arg("--password")
        .arg(format!("Пароль ({user})"))
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let password = String::from_utf8(out.stdout).ok()?;
    let password = password.trim_end_matches('\n');
    (out.status.success() && !password.is_empty()).then(|| Answer {
        login: Login {
            user: user.to_owned(),
            group: group.to_owned(),
            password: password.to_owned(),
            code: String::new(),
        },
        remember: false,
    })
}

/// The login of `zone` taken in the form and handed to its holder while it
/// starts; the form again, with what went wrong, until the network is up or
/// the person gives up. Whether it is up.
fn log_in(tools: &Tools, zone: &str, wants: Wants<'_>, cfg: &OcConfig) -> bool {
    let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR").filter(|r| !r.is_empty()) else {
        eprintln!("cellward: XDG_RUNTIME_DIR не задан — вход в сеть {zone} передать некуда");
        return false;
    };
    let (last_user, last_group) = last_login(&tools.state, zone);
    let mut user = last_user.or_else(|| cfg.user.clone()).unwrap_or_default();
    let mut group = last_group
        .or_else(|| cfg.authgroup.clone())
        .unwrap_or_default();
    let keyring = tools.secret_tool.is_file();
    let mut error: Option<String> = None;
    loop {
        let remembered = keyring
            .then(|| keyring_lookup(tools, zone, &user))
            .flatten()
            .unwrap_or_default();
        let request = login_request(
            zone,
            wants,
            cfg,
            (&user, &group, &remembered),
            (error.as_deref(), keyring),
        );
        let Some(answer) = login_form(tools, &request, &user, &group) else {
            return false;
        };
        let offer = match Offer::open(Path::new(&runtime), zone, answer.login.clone()) {
            Ok(offer) => offer,
            Err(e) => {
                eprintln!("cellward: {e}");
                return false;
            }
        };
        Real(tools).start(zone, wants);
        let taken = offer.taken();
        if crate::cli::zone_up(&tools.state, OsStr::new(zone)).is_some() {
            save_last_login(&tools.state, zone, &answer.login);
            if keyring && (answer.remember || !remembered.is_empty()) {
                keyring_keep(tools, zone, &answer.login, answer.remember);
            }
            return true;
        }
        error = Some(if taken {
            format!(
                "Сеть не подключилась: шлюз не принял вход — проверь пароль и код \
                 (journalctl --user -u vpn-zone@{zone})."
            )
        } else {
            format!(
                "Сеть не подключилась, вход до неё не дошёл (journalctl --user -u \
                 vpn-zone@{zone})."
            )
        });
        user = answer.login.user;
        group = answer.login.group;
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
            }
        }
    }

    impl Steps for Fake {
        fn ask(&self, _: &str, _: Mode, _: Wants<'_>) -> bool {
            self.asked.set(self.asked.get() + 1);
            self.answer
        }

        fn log_in(&self, zone: &str, wants: Wants<'_>, _: &OcConfig) -> bool {
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
            "[OpenConnect]\nServer = vpn.example.org\nLogin = ask\n",
        )
        .unwrap();
        assert_eq!(
            mode(&t.state, &t.config, "work"),
            (Mode::Ask, Source::Default)
        );
        assert!(asks_login(&t.state, "work").is_some());
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
        set(&t.state, &t.config, "work", Some(Mode::Ask)).unwrap();
        let fake = Fake::new(false, true);
        let refused = bring_up_with(&t, "work", program, &fake).unwrap_err();
        assert!(refused.contains("«Firefox» не запущена"), "{refused}");
        assert_eq!((fake.asked.get(), fake.starts.get()), (1, 0));
        let fake = Fake::new(true, true);
        assert!(bring_up_with(&t, "work", program, &fake).is_ok());
        assert_eq!((fake.asked.get(), fake.starts.get()), (1, 1));
        assert_eq!(last_answer(&t.state.join("work")), Some((2, true)));
        // Agreed, and it did not come up: said so.
        let fake = Fake::new(true, false);
        let failed = bring_up_with(&t, "work", program, &fake).unwrap_err();
        assert!(failed.contains("зона work не поднимается"), "{failed}");
        // The person connecting it: no question.
        let fake = Fake::new(false, true);
        assert!(bring_up_with(&t, "work", Wants::Person, &fake).is_ok());
        assert_eq!((fake.asked.get(), fake.starts.get()), (0, 1));
        // Manual: asked too, and a refusal says how to connect it.
        set(&t.state, &t.config, "work", Some(Mode::Manual)).unwrap();
        let fake = Fake::new(false, true);
        let container = Wants::Container("банк");
        let refused = bring_up_with(&t, "work", container, &fake).unwrap_err();
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
        write_answer(&dir, 4, true).unwrap();
        write_answer(&dir, 5, false).unwrap();
        let wants = (Mode::Ask, Wants::Program("Telegram"));
        let fake = Fake::new(true, true);
        let refused = decide(&t, "work", wants, 4, (None, &fake)).unwrap_err();
        assert!(refused.contains("«Telegram» не запущена"), "{refused}");
        assert_eq!(fake.asked.get(), 0, "not asked again");
        assert!(decide(&t, "work", wants, 5, (None, &fake)).is_ok());
        assert_eq!(fake.asked.get(), 1);
        assert_eq!(last_answer(&dir), Some((6, true)));
    }

    /// A network whose login is asked takes it in the form, whatever its
    /// mode — the form is its question —, the person's `up` too.
    #[test]
    fn a_login_is_asked_in_the_form() {
        let t = tools("login");
        fs::write(
            t.state.join("work/config.conf"),
            "[OpenConnect]\nServer = vpn.example.org\nLogin = ask\n",
        )
        .unwrap();
        set(&t.state, &t.config, "work", Some(Mode::Auto)).unwrap();
        let fake = Fake::new(true, true);
        assert!(bring_up_with(&t, "work", Wants::Person, &fake).is_ok());
        assert_eq!((fake.asked.get(), fake.logins.get()), (0, 1));
        let fake = Fake::new(false, true);
        let refused = bring_up_with(&t, "work", Wants::Program("Wine"), &fake).unwrap_err();
        assert!(refused.contains("«Wine» не запущена"), "{refused}");
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

    /// The login's lines there and back; never the password in a log.
    #[test]
    fn a_login_goes_there_and_back_and_is_not_logged() {
        let login = Login {
            user: "ivan".into(),
            group: "staff".into(),
            password: "Xq\t7\nZw".into(),
            code: "123456".into(),
        };
        let back = Login::decode(&login.encode()).unwrap();
        assert_eq!(back.password, "Xq7Zw", "no tab, no line break");
        assert_eq!(
            (back.user.as_str(), back.group.as_str(), back.code.as_str()),
            ("ivan", "staff", "123456")
        );
        assert_eq!(Login::decode("user\tivan\n"), None, "no password: none");
        let shown = format!("{login:?}");
        assert!(
            !shown.contains("Xq") && !shown.contains("Zw") && !shown.contains("123456"),
            "{shown}"
        );
    }

    /// The form's request and its answer: prefilled, the box for the
    /// keyring where there is one, what went wrong said.
    #[test]
    fn the_form_is_prefilled_and_read_back() {
        let cfg =
            OcConfig::parse(b"[OpenConnect]\nServer = vpn.example.org\nLogin = ask\n").unwrap();
        let req = login_request(
            "work",
            Wants::Program("Wine"),
            &cfg,
            ("ivan", "", "secret"),
            (Some("Шлюз не принял вход"), true),
        );
        assert!(req.starts_with("title\tВход в сеть work\n"), "{req}");
        assert!(req.contains("note\t«Wine» хочет в сеть work. Шлюз vpn.example.org.\n"));
        assert!(req.contains("note\tШлюз не принял вход\n"));
        assert!(req.contains("field\tuser\tПользователь\ttext\tivan\n"));
        assert!(req.contains("field\tpassword\tПароль\tsecret\tsecret\n"));
        assert!(req.contains("\tcode\t\n"));
        assert!(req.contains("remember\tЗапомнить пароль в связке ключей сеанса\t1\n"));
        let plain = login_request("work", Wants::Person, &cfg, ("", "", ""), (None, false));
        assert!(
            !plain.contains("remember") && !plain.contains("ждёт"),
            "{plain}"
        );
        let answer = parse_answer(
            "field\tuser\tivan\nfield\tgroup\tstaff\nfield\tpassword\tp w\nfield\tcode\t42\n\
             remember\t1\n",
        )
        .unwrap();
        assert_eq!(answer.login.password, "p w");
        assert_eq!(answer.login.code, "42");
        assert!(answer.remember);
        assert!(parse_answer("field\tuser\tivan\n").is_none());
    }

    /// The last login's user and group, for the next form.
    #[test]
    fn the_last_user_and_group_are_remembered() {
        let t = tools("last");
        assert_eq!(last_login(&t.state, "work"), (None, None));
        let login = Login {
            user: "ivan".into(),
            password: "x".into(),
            ..Login::default()
        };
        save_last_login(&t.state, "work", &login);
        assert_eq!(last_login(&t.state, "work"), (Some("ivan".into()), None));
        let text = fs::read_to_string(t.state.join("work").join(LAST_LOGIN)).unwrap();
        assert!(!text.contains('x'), "no password there: {text}");
    }

    /// The login served to the network's holder alone: a process of any
    /// other unit (this test's) is closed on with nothing; the offer taken
    /// back ends the wait.
    #[test]
    fn a_login_is_served_to_the_holder_alone() {
        let runtime = std::env::temp_dir().join(format!("vz-connect-offer-{}", std::process::id()));
        let _ = fs::remove_dir_all(&runtime);
        fs::create_dir_all(&runtime).unwrap();
        let login = Login {
            password: "x".into(),
            ..Login::default()
        };
        let offer = Offer::open(&runtime, "work", login).unwrap();
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
