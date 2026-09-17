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
//! * anything else — another zone, `direct`: a person is asked, with the
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
                    match allowed {
                        Ok(()) => start(tools, &app_id, &argv),
                        Err(why) => format!("refused: {why}"),
                    }
                }
            }
        }
    };
    eprintln!("broker: {answer}");
    let _ = stream.write_all(format!("{answer}\n").as_bytes());
}

fn ask(tools: &Tools, origin: &str, target: &str, cmd: &[OsString]) -> Result<(), String> {
    if !crate::launch::has_display() {
        return Err("спросить некого (нет графической сессии)".to_owned());
    }
    let shown: Vec<String> = cmd
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let network = if target == crate::launch::DIRECT {
        "прямом интернете (без VPN)".to_owned()
    } else {
        format!("сети «{target}»")
    };
    let question = format!(
        "Программа из зоны «{origin}» просит запустить в {network}:\n\n{}\n\nРазрешить?",
        shown.join(" ")
    );
    if crate::dialog::confirm(
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

/// `vpn-zone _broker`: listen and answer, forever.
pub fn serve(tools: &Tools) -> u8 {
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
    for stream in listener.incoming().flatten() {
        let tools = tools.clone();
        std::thread::spawn(move || handle(&tools, stream));
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
        assert_eq!(decide(Some("nl"), false, "direct"), Decision::Ask);
        assert!(matches!(
            decide(Some("nl"), true, "direct"),
            Decision::Refuse(_)
        ));
        assert_eq!(decide(Some("nl"), true, "nl"), Decision::Start);
        assert_eq!(decide(None, false, "direct"), Decision::Start);
    }
}
