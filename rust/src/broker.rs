//! The broker (`docs/HERMETICITY.md` §3, §7 C): the one door out of a hermetic
//! zone.
//!
//! A program in a zone that opens something — a link in a messenger, a file in
//! a mail client — ends in `vpn-zone run`, and a zone cannot enter another
//! network itself (`docs/GOTCHAS.md` §1), so the launch has to happen outside.
//! It used to go through `systemd-run --user`, which is a door with no guard:
//! any program in any zone can start any process on the host with it. A
//! hermetic zone has no `systemd --user` to reach, and this socket instead.
//!
//! The broker is a user service on the host. It learns WHICH zone asks from the
//! kernel — the network namespace of the process that connected — never from
//! the request, and it answers:
//!
//! * the host's own namespace: started — a host program could run `vpn-zone`
//!   itself;
//! * a launch into the very zone that asks: started, no dialog — the program
//!   is in that zone already;
//! * a locked zone asking for another network: refused;
//! * another zone asking — for another zone, for `unconfined`: a person is
//!   asked, with the asking zone and the command in the question; with nobody
//!   to ask (no graphical session), refused;
//! * a namespace that is none of these, or a process that can no longer be
//!   told: refused. It used to be "not a zone, so the host", and started:
//!   a program that asked and exited before the broker looked had its request
//!   run on the host with the host's network, no question asked.
//!
//! **The process is held, not its number.** The peer is pinned when the
//! connection is taken — the kernel's pidfd of the very process that connected
//! (`SO_PEERPIDFD`, Linux 6.5; before that, one opened by its pid at once) —
//! and its namespace is read only while that process is still alive, before
//! and after the read. A pid that went to somebody else is never looked at.
//!
//! The request is `VZB1\0`, the app-id, then the arguments of `vpn-zone run`,
//! each terminated by a NUL; the client closes its writing half, the broker
//! answers one line: `ok` or `refused: <why>`.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::cli::{visible_entries, zone_pid};
use crate::tools::Tools;

/// The magic that starts a request.
const MAGIC: &[u8] = b"VZB1\0";
/// The socket, below the runtime directory.
pub const SOCKET: &str = "vpn-zones/broker";
/// The largest request the broker reads: a command line, not a file.
const MAX_REQUEST: u64 = 64 * 1024;

/// The runtime directory of this user.
pub fn runtime_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        // SAFETY: getuid(2) cannot fail.
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() })))
}

/// A request as bytes.
pub fn encode(app_id: &[u8], argv: &[OsString]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(app_id);
    out.push(0);
    for arg in argv {
        out.extend_from_slice(arg.as_bytes());
        out.push(0);
    }
    out
}

/// A request from bytes: `(app_id, argv)`.
pub fn decode(bytes: &[u8]) -> Option<(OsString, Vec<OsString>)> {
    let rest = bytes.strip_prefix(MAGIC)?;
    let mut parts = rest.split(|b| *b == 0);
    let app_id = OsString::from_vec(parts.next()?.to_vec());
    let mut argv: Vec<OsString> = parts.map(|p| OsString::from_vec(p.to_vec())).collect();
    // The request ends with a NUL, which leaves one empty piece behind it.
    if argv.last().is_some_and(|a| a.is_empty()) {
        argv.pop();
    }
    Some((app_id, argv))
}

/// Where a request comes from, by the kernel's word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// The host's own network namespace, the broker's.
    Host,
    /// A zone of this user.
    Zone(String),
    /// A system zone (`/run/netns/vz-<name>`, root's).
    SystemZone(String),
    /// Anything else: a namespace that is none of ours, or a process gone
    /// before it could be looked at.
    Unknown,
}

impl Origin {
    /// How the journal and "always" name it; a system zone apart from a user
    /// zone of the same name.
    pub fn name(&self) -> String {
        match self {
            Origin::Host => String::new(),
            Origin::Zone(zone) => zone.clone(),
            Origin::SystemZone(zone) => format!("system:{zone}"),
            Origin::Unknown => "?".to_owned(),
        }
    }
}

/// What the broker decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Start,
    /// A person has to say yes.
    Ask,
    Refuse(String),
}

/// The policy, from where the request comes from and the network it asks for.
pub fn decide(origin: &Origin, origin_locked: bool, target: &str) -> Decision {
    match origin {
        // The host itself: it could run `vpn-zone` without us.
        Origin::Host => Decision::Start,
        Origin::Zone(zone) if zone == target => Decision::Start,
        Origin::Zone(zone) if origin_locked => Decision::Refuse(format!(
            "зона «{zone}» заперта: запуск в другой сети ({target}) запрещён"
        )),
        Origin::Zone(_) | Origin::SystemZone(_) => Decision::Ask,
        Origin::Unknown => Decision::Refuse(
            "не понять, откуда запрос: не хост и не зона (или процесс уже вышел)".to_owned(),
        ),
    }
}

/// The zone whose app namespace is `netns` (`net:[…]`), if any.
fn zone_of_netns(state: &Path, netns: &Path) -> Option<String> {
    visible_entries(state).into_iter().find_map(|dir| {
        let name = dir.file_name()?.to_os_string();
        let pid = zone_pid(state, &name)?;
        (std::fs::read_link(format!("/proc/{pid}/ns/net"))
            .ok()?
            .as_path()
            == netns)
            .then(|| name.to_string_lossy().into_owned())
    })
}

/// Which of our networks the namespace `netns` (`net:[…]`) is.
fn classify(state: &Path, netns: &Path) -> Origin {
    if std::fs::read_link("/proc/self/ns/net").ok().as_deref() == Some(netns) {
        return Origin::Host;
    }
    if let Some(zone) = zone_of_netns(state, netns) {
        return Origin::Zone(zone);
    }
    if let Some(zone) = crate::system::zone_of_netns(&netns.to_string_lossy()) {
        return Origin::SystemZone(zone);
    }
    Origin::Unknown
}

/// The process on the other end, pinned: the kernel's pidfd of the very
/// process that connected, or — on a kernel without `SO_PEERPIDFD` — one opened
/// by its pid now.
fn peer_pidfd(stream: &UnixStream, pid: i32) -> Option<OwnedFd> {
    let mut fd: libc::c_int = -1;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: a valid descriptor, a buffer of one int and its length.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&mut fd as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if rc == 0 && fd >= 0 {
        // SAFETY: the kernel just gave us this descriptor to own.
        return Some(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    crate::sys::pidfd_open(pid)
}

/// Where the peer of `stream` is, looked at while it is certainly the process
/// that connected.
fn origin_of(state: &Path, stream: &UnixStream) -> Origin {
    let Some(pid) = peer_pid(stream) else {
        return Origin::Unknown;
    };
    let Some(pidfd) = peer_pidfd(stream, pid) else {
        return Origin::Unknown;
    };
    let alive = || !crate::sys::pidfd_wait(&pidfd, std::time::Duration::ZERO);
    if !alive() {
        return Origin::Unknown;
    }
    let Ok(netns) = std::fs::read_link(format!("/proc/{pid}/ns/net")) else {
        return Origin::Unknown;
    };
    // Still alive after the read: the number was not reused in between, and
    // the namespace read is the peer's own.
    if !alive() {
        return Origin::Unknown;
    }
    classify(state, &netns)
}

/// The pid of the process on the other end of a Unix socket.
fn peer_pid(stream: &UnixStream) -> Option<i32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: a valid descriptor, a correctly sized buffer and its length.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    (rc == 0 && cred.pid > 0).then_some(cred.pid)
}

fn handle(tools: &Tools, mut stream: UnixStream) {
    // First, before the request is read: the peer may leave while it is.
    let origin = origin_of(&tools.state, &stream);
    let mut bytes = Vec::new();
    if (&mut stream)
        .take(MAX_REQUEST)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return;
    }
    let answer = match decode(&bytes) {
        None => "refused: не запрос брокера".to_owned(),
        Some((app_id, argv)) => {
            match crate::launch::Selection::parse(&argv) {
                Err(e) => format!("refused: {e}"),
                Ok(selection) => {
                    let target = selection.zone.to_string_lossy().into_owned();
                    let locked = match &origin {
                        Origin::Zone(zone) => tools
                            .state
                            .join(zone)
                            .join(crate::launch::NO_ESCAPE)
                            .exists(),
                        _ => false,
                    };
                    let allowed = match decide(&origin, locked, &target) {
                        Decision::Start => Ok(()),
                        Decision::Refuse(why) => Err(why),
                        Decision::Ask => ask(tools, &origin, &target, &selection.cmd),
                    };
                    let answer = match &allowed {
                        Ok(()) => start(tools, &app_id, &argv),
                        Err(why) => format!("refused: {why}"),
                    };
                    // Every crossing the broker decides, either way, on the
                    // record: which zone asked, for what, and what came of it.
                    let why = answer.strip_prefix("refused: ").unwrap_or("");
                    let decision = if answer == "ok" { "started" } else { "refused" };
                    if let Err(e) = crate::journal::append(
                        &tools.state,
                        "broker",
                        &[
                            ("origin", origin.name().as_str()),
                            ("target", target.as_str()),
                            ("app", &*app_id.to_string_lossy()),
                            ("decision", decision),
                            ("why", why),
                        ],
                    ) {
                        eprintln!("broker: journal: {e}");
                    }
                    answer
                }
            }
        }
    };
    eprintln!("broker: {answer}");
    let _ = stream.write_all(format!("{answer}\n").as_bytes());
}

/// What "always" is remembered in: one `origin\ttarget\tprogram` per line,
/// below the config directory.
pub const ALWAYS: &str = "broker-always";

/// The program a launch runs, as the host resolves it: the first word of the
/// command, looked up in `PATH` if it is a bare name, its directory's links
/// followed and its own name kept — `touch` and `cat` are links to one
/// coreutils binary, and "always" for one must not be "always" for all.
pub fn program_of(cmd: &[OsString]) -> Option<PathBuf> {
    let first = Path::new(cmd.first()?);
    let path = if first.components().count() > 1 {
        first.to_path_buf()
    } else {
        std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            .map(|dir| dir.join(first))
            .find(|p| p.is_file())?
    };
    let dir = std::fs::canonicalize(path.parent()?).ok()?;
    Some(dir.join(path.file_name()?))
}

/// Whether "always" may be offered for this program: only for one in the
/// store — the name and the file it finally is — where nothing in a zone can
/// write. A program named by a path the user, or a program in a zone with the
/// home in reach, could replace (`~/.local/bin/…`) would make "always" a
/// standing door for whatever is put there next.
pub fn may_remember(program: &Path) -> bool {
    program.starts_with("/nix/store/")
        && std::fs::canonicalize(program).is_ok_and(|real| real.starts_with("/nix/store/"))
}

/// The line "always" writes, and looks for.
pub fn always_line(origin: &str, target: &str, program: &Path) -> String {
    format!("{origin}\t{target}\t{}", program.display())
}

fn remembered(tools: &Tools, line: &str) -> bool {
    std::fs::read_to_string(tools.config.join(ALWAYS))
        .is_ok_and(|text| text.lines().any(|l| l == line))
}

fn remember(tools: &Tools, line: &str) {
    let path = tools.config.join(ALWAYS);
    let _ = std::fs::create_dir_all(&tools.config);
    let appended = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut f| writeln!(f, "{line}"));
    if let Err(e) = appended {
        eprintln!("broker: cannot remember in {}: {e}", path.display());
    }
}

fn ask(tools: &Tools, origin: &Origin, target: &str, cmd: &[OsString]) -> Result<(), String> {
    // Asked before, and "always" said: the same zone, the same network, the
    // very same program from the store.
    let program = program_of(cmd).filter(|p| may_remember(p));
    let line = program
        .as_ref()
        .map(|p| always_line(&origin.name(), target, p));
    if line.as_ref().is_some_and(|l| remembered(tools, l)) {
        return Ok(());
    }
    if !crate::launch::has_display() {
        return Err("спросить некого (нет графической сессии)".to_owned());
    }
    let shown: Vec<String> = cmd
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let network = if target == crate::launch::UNCONFINED {
        "без ограничений (сеть хоста, без VPN и без изоляции зоны)".to_owned()
    } else {
        format!("сети «{target}»")
    };
    let asker = match origin {
        Origin::SystemZone(zone) => format!("системной зоны «{zone}»"),
        other => format!("зоны «{}»", other.name()),
    };
    let question = format!(
        "Программа из {asker} просит запустить в {network}:\n\n{}\n\nРазрешить?",
        shown.join(" ")
    );
    // "Always" only where it can be kept safely (`may_remember`).
    let Some(line) = line else {
        return if crate::dialog::confirm(
            &tools.kdialog,
            [
                "--title",
                "Запуск из зоны",
                "--warningcontinuecancel",
                question.as_str(),
            ],
        ) {
            Ok(())
        } else {
            Err("человек отказал".to_owned())
        };
    };
    match crate::dialog::choose3(
        &tools.kdialog,
        [
            "--title",
            "Запуск из зоны",
            "--yes-label",
            "Разрешить",
            "--no-label",
            "Всегда",
            "--cancel-label",
            "Отказать",
            "--warningyesnocancel",
            question.as_str(),
        ],
    ) {
        Some(0) => Ok(()),
        Some(1) => {
            remember(tools, &line);
            Ok(())
        }
        _ => Err("человек отказал".to_owned()),
    }
}

fn start(tools: &Tools, app_id: &OsString, argv: &[OsString]) -> String {
    let mut command = Command::new(&tools.runner);
    command
        .arg("run")
        .args(argv)
        .env(crate::launch::ENV_DELEGATED, "1")
        .env_remove(crate::launch::ENV_CURRENT)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if !app_id.is_empty() {
        command.env(crate::launch::ENV_APPID, app_id);
    }
    match command.spawn() {
        Ok(mut child) => {
            // Reaped in the background: the program may run for days.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            "ok".to_owned()
        }
        Err(e) => format!("refused: не запустить {}: {e}", tools.runner.display()),
    }
}

/// `vpn-zone _broker`: listen and answer, forever. Normally the socket is
/// systemd's (`vpn-zone-broker.socket`) and handed over at fd 3 — it exists
/// from the moment the user manager or a zone wants it, whether or not this
/// has been started (red in CI: the service, wanted by `default.target`, was
/// never started when home-manager put its unit in place after the manager
/// had reached that target). Run by hand, it listens by itself.
pub fn serve(tools: &Tools) -> u8 {
    let passed = crate::dnsfwd::listen_fds(
        &std::env::var("LISTEN_PID").unwrap_or_default(),
        &std::env::var("LISTEN_FDS").unwrap_or_default(),
        std::process::id(),
    );
    if passed >= 1 {
        use std::os::fd::FromRawFd;
        // SAFETY: systemd passed this descriptor to us to own.
        let listener = unsafe { UnixListener::from_raw_fd(3) };
        eprintln!("broker: listening on the socket systemd passed");
        return accept_forever(tools, &listener);
    }
    let socket = runtime_dir().join(SOCKET);
    if let Some(dir) = socket.parent() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("broker: cannot create {}: {e}", dir.display());
            return 1;
        }
    }
    let _ = std::fs::remove_file(&socket);
    let listener = match UnixListener::bind(&socket) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("broker: cannot listen on {}: {e}", socket.display());
            return 1;
        }
    };
    eprintln!("broker: listening on {}", socket.display());
    accept_forever(tools, &listener)
}

fn accept_forever(tools: &Tools, listener: &UnixListener) -> u8 {
    for stream in listener.incoming().flatten() {
        let tools = tools.clone();
        let _ = std::thread::Builder::new().spawn(move || handle(&tools, stream));
    }
    0
}

/// The client half, for `delegate`: `Some(code)` when a broker answered,
/// `None` when there is none to ask.
pub fn request(app_id: &[u8], argv: &[OsString]) -> Option<u8> {
    let socket = runtime_dir().join(SOCKET);
    let mut stream = UnixStream::connect(&socket).ok()?;
    if stream.write_all(&encode(app_id, argv)).is_err() {
        return Some(crate::profile::EXIT_NOT_STARTED);
    }
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    let answer = answer.trim();
    if answer == "ok" {
        Some(0)
    } else {
        eprintln!(
            "брокер: {}",
            answer.strip_prefix("refused: ").unwrap_or(answer)
        );
        Some(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_is_kept_for_programs_of_the_store_only() {
        // A program of the store: `sh`, as the test's own PATH has it.
        let sh = program_of(&["sh".into()]).unwrap();
        assert!(
            sh.starts_with("/nix/store/") && sh.ends_with("sh"),
            "{}",
            sh.display()
        );
        assert!(may_remember(&sh));
        assert!(!may_remember(Path::new(
            "/nix/store/does-not-exist/bin/zen"
        )));
        assert!(!may_remember(Path::new("/home/u/.local/bin/zen")));
        assert!(!may_remember(Path::new("/tmp/zen")));
        assert_eq!(
            always_line("nl", "unconfined", Path::new("/nix/store/abc-zen/bin/zen")),
            "nl\tunconfined\t/nix/store/abc-zen/bin/zen"
        );
        // The program as the host resolves it: the directory's links followed,
        // the name kept.
        let dir = std::env::temp_dir().join(format!("vpn-zone-broker-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join("real");
        std::fs::write(&real, "").unwrap();
        let link = dir.join("link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(
            program_of(&[link.clone().into_os_string()]),
            Some(std::fs::canonicalize(&dir).unwrap().join("link"))
        );
        // …and a file outside the store is never "always".
        assert!(!may_remember(
            &program_of(&[real.clone().into_os_string()]).unwrap()
        ));
        assert_eq!(program_of(&[]), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_request_survives_the_socket() {
        let argv: Vec<OsString> = ["nl", "--", "firefox", "https://a b"]
            .iter()
            .map(OsString::from)
            .collect();
        let bytes = encode(b"org.mozilla.firefox", &argv);
        let (app_id, back) = decode(&bytes).unwrap();
        assert_eq!(app_id, OsString::from("org.mozilla.firefox"));
        assert_eq!(back, argv);
        assert!(decode(b"junk").is_none());
        let (app_id, back) = decode(&encode(b"", &[])).unwrap();
        assert!(app_id.is_empty() && back.is_empty());
    }

    #[test]
    fn only_the_host_and_the_same_zone_start_without_a_person() {
        let nl = Origin::Zone("nl".to_owned());
        assert_eq!(decide(&nl, false, "nl"), Decision::Start);
        assert_eq!(decide(&nl, false, "de"), Decision::Ask);
        assert_eq!(decide(&nl, false, "unconfined"), Decision::Ask);
        assert!(matches!(
            decide(&nl, true, "unconfined"),
            Decision::Refuse(_)
        ));
        assert_eq!(decide(&nl, true, "nl"), Decision::Start);
        assert_eq!(decide(&Origin::Host, false, "unconfined"), Decision::Start);
        // A system zone is never "the same zone" as a user zone of its name.
        let system = Origin::SystemZone("nl".to_owned());
        assert_eq!(decide(&system, false, "nl"), Decision::Ask);
        assert_eq!(system.name(), "system:nl");
        // Not the host and not a zone — or gone before it was looked at: no.
        assert!(matches!(
            decide(&Origin::Unknown, false, "unconfined"),
            Decision::Refuse(_)
        ));
        assert!(matches!(
            decide(&Origin::Unknown, false, "nl"),
            Decision::Refuse(_)
        ));
    }

    /// The peer of a connection is found while it lives, and a peer that has
    /// left is nobody — not the host.
    #[test]
    fn a_peer_that_left_before_it_was_looked_at_is_unknown() {
        let state = std::env::temp_dir().join(format!("vz-broker-{}", std::process::id()));
        // Ourselves, alive, in our own namespace: the host.
        let (a, b) = UnixStream::pair().unwrap();
        assert_eq!(origin_of(&state, &a), Origin::Host);
        drop((a, b));
        // A child that connects and exits before the broker looks.
        let dir = std::env::temp_dir().join(format!("vz-broker-sock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("s");
        let listener = UnixListener::bind(&socket).unwrap();
        // The address is made before the fork: the child only calls the kernel.
        // SAFETY: sockaddr_un is plain data.
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (dst, src) in addr.sun_path.iter_mut().zip(socket.as_os_str().as_bytes()) {
            *dst = *src as libc::c_char;
        }
        // SAFETY: the child makes three system calls and leaves with _exit.
        let child = unsafe { libc::fork() };
        if child == 0 {
            unsafe {
                let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                libc::connect(
                    fd,
                    (&addr as *const libc::sockaddr_un).cast(),
                    std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
                );
                libc::_exit(0);
            }
        }
        let mut status = 0;
        // SAFETY: waiting for our own child.
        unsafe { libc::waitpid(child, &mut status, 0) };
        let (stream, _) = listener.accept().unwrap();
        assert_eq!(origin_of(&state, &stream), Origin::Unknown);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
