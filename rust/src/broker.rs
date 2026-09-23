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
//! kernel — the network namespace of the peer's pid — never from the request,
//! and it answers:
//!
//! * a launch into the very zone that asks: started, no dialog — the program
//!   is in that zone already;
//! * a locked zone asking for another network: refused;
//! * anything else — another zone, `unconfined`: a person is asked, with the
//!   asking zone and the command in the question; with nobody to ask (no
//!   graphical session), refused.
//!
//! The request is `VZB1\0`, the app-id, then the arguments of `vpn-zone run`,
//! each terminated by a NUL; the client closes its writing half, the broker
//! answers one line: `ok` or `refused: <why>`.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
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

/// What the broker decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Start,
    /// A person has to say yes.
    Ask,
    Refuse(String),
}

/// The policy, from the asking zone and the requested one.
pub fn decide(origin: Option<&str>, origin_locked: bool, target: &str) -> Decision {
    match origin {
        // Not from a zone at all: a host program could run `vpn-zone` itself.
        None => Decision::Start,
        Some(origin) if origin == target => Decision::Start,
        Some(origin) if origin_locked => Decision::Refuse(format!(
            "зона «{origin}» заперта: запуск в другой сети ({target}) запрещён"
        )),
        Some(_) => Decision::Ask,
    }
}

/// The zone whose app namespace has this network namespace, if any.
fn zone_of_netns(tools: &Tools, netns: &Path) -> Option<String> {
    let wanted = std::fs::read_link(netns).ok()?;
    visible_entries(&tools.state).into_iter().find_map(|dir| {
        let name = dir.file_name()?.to_os_string();
        let pid = zone_pid(&tools.state, &name)?;
        (std::fs::read_link(format!("/proc/{pid}/ns/net")).ok()? == wanted)
            .then(|| name.to_string_lossy().into_owned())
    })
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
            let origin = peer_pid(&stream)
                .and_then(|pid| zone_of_netns(tools, Path::new(&format!("/proc/{pid}/ns/net"))));
            match crate::launch::Selection::parse(&argv) {
                Err(e) => format!("refused: {e}"),
                Ok(selection) => {
                    let target = selection.zone.to_string_lossy().into_owned();
                    let locked = origin.as_ref().is_some_and(|o| {
                        tools.state.join(o).join(crate::launch::NO_ESCAPE).exists()
                    });
                    let allowed = match decide(origin.as_deref(), locked, &target) {
                        Decision::Start => Ok(()),
                        Decision::Refuse(why) => Err(why),
                        Decision::Ask => ask(
                            tools,
                            origin.as_deref().unwrap_or("?"),
                            &target,
                            &selection.cmd,
                        ),
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
                            ("origin", origin.as_deref().unwrap_or("")),
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

fn ask(tools: &Tools, origin: &str, target: &str, cmd: &[OsString]) -> Result<(), String> {
    // Asked before, and "always" said: the same zone, the same network, the
    // very same program from the store.
    let program = program_of(cmd).filter(|p| may_remember(p));
    let line = program.as_ref().map(|p| always_line(origin, target, p));
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
    let question = format!(
        "Программа из зоны «{origin}» просит запустить в {network}:\n\n{}\n\nРазрешить?",
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
    fn only_the_same_zone_starts_without_a_person() {
        assert_eq!(decide(Some("nl"), false, "nl"), Decision::Start);
        assert_eq!(decide(Some("nl"), false, "de"), Decision::Ask);
        assert_eq!(decide(Some("nl"), false, "unconfined"), Decision::Ask);
        assert!(matches!(
            decide(Some("nl"), true, "unconfined"),
            Decision::Refuse(_)
        ));
        assert_eq!(decide(Some("nl"), true, "nl"), Decision::Start);
        assert_eq!(decide(None, false, "unconfined"), Decision::Start);
    }
}
