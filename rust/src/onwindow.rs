//! A question on the program's own window (the owner, 2026-09-29;
//! `docs/FIREWALL.md` §4.3.1): asked on the socket of questions of the
//! program's launch (`crate::wl_proxy::ask_path`), whose supervisor has the
//! Wayland proxy show it as a panel under the window's title. Its only
//! answer is "no" — the first of its labels, the safe one; anything else is
//! "ask in the launch window", on the launch's compositor, which the reply
//! names. The proxy reads the program's messages: a "yes" is never taken
//! from it (`crate::wl_proxy`'s module docs).
//!
//! Who asks: the instance's keeper about a program's network
//! (`crate::netask`), the sound filter about its microphone
//! (`crate::microphone`).

use std::ffi::OsString;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

/// The host's runtime directory, where the launches' sockets of questions
/// are: this process's `XDG_RUNTIME_DIR`, else the user's own.
pub fn runtime_dir() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        // SAFETY: getuid takes nothing and cannot fail.
        None => PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() })),
    }
}

/// The launch process `pid` belongs to, as far as questions go: it, or the
/// nearest of its parents with a socket of questions under `runtime` — the
/// launch's supervisor, of which all its processes are below. A process
/// named so by a program is no launch's supervisor: [`ask`] checks the
/// socket's other end.
pub fn launch_above(runtime: &Path, pid: i32) -> Option<i32> {
    let mut at = pid;
    for _ in 0..64 {
        if at <= 1 {
            return None;
        }
        if std::fs::symlink_metadata(crate::wl_proxy::ask_path(runtime, at)).is_ok() {
            return Some(at);
        }
        at = crate::sys::parent_of(at)?;
    }
    None
}

/// What the launch's supervisor said of a question on the program's window.
#[derive(Debug, PartialEq, Eq)]
pub enum OnWindow {
    /// "No", there.
    No,
    /// Not answered in time.
    Unanswered,
    /// To be asked in the launch window — on the launch's compositor, when
    /// its supervisor named it: «Разрешить…», no window of the program's to
    /// ask on, or no supervisor to ask at all.
    Elsewhere(Option<OsString>),
}

/// `text` asked on the window of the launch whose supervisor is `pid`,
/// through its socket of questions under `runtime`, with the answers
/// `labels` — the safe one first, the only one that is an answer there:
/// what it said ([`OnWindow`]). Its socket is its supervisor's own — the
/// process on the other end is `pid` — or nothing is asked there.
pub fn ask(
    runtime: &Path,
    pid: i32,
    text: &str,
    labels: &[&str],
    timeout: Option<std::time::Duration>,
) -> OnWindow {
    use std::io::{Read, Write};
    let elsewhere = OnWindow::Elsewhere(None);
    let Some(request) = crate::wl_proxy::ask_request(text, labels) else {
        return elsewhere;
    };
    let Ok(stream) = UnixStream::connect(crate::wl_proxy::ask_path(runtime, pid)) else {
        return elsewhere;
    };
    if crate::sys::peer_pid(stream.as_raw_fd()) != Some(pid) {
        return elsewhere;
    }
    if stream.set_read_timeout(timeout).is_err() || (&stream).write_all(&request).is_err() {
        return elsewhere;
    }
    let mut reply = Vec::new();
    match (&stream)
        .take(1 + MAX_DISPLAY as u64)
        .read_to_end(&mut reply)
    {
        Ok(_) => reply_of(&reply),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            OnWindow::Unanswered
        }
        Err(_) => elsewhere,
    }
}

/// The longest compositor's name a supervisor's reply carries.
const MAX_DISPLAY: usize = 256;

/// A supervisor's reply: its answer's byte, then its compositor's name.
fn reply_of(reply: &[u8]) -> OnWindow {
    use std::os::unix::ffi::OsStringExt;
    let display = reply
        .get(1..)
        .filter(|d| !d.is_empty() && d.len() <= MAX_DISPLAY && !d.contains(&0))
        .map(|d| OsString::from_vec(d.to_vec()));
    match reply.first() {
        Some(&crate::wl_proxy::ASK_NO) => OnWindow::No,
        _ => OnWindow::Elsewhere(display),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The supervisor's word: "no" is the answer; anything else, and a
    /// word it never said, asks in the launch window — on its compositor
    /// when it named one.
    #[test]
    fn only_no_is_an_answer_from_the_programs_window() {
        use crate::wl_proxy::{ASK_NO, ASK_NOWHERE, ASK_WINDOW};
        assert_eq!(reply_of(&[ASK_NO]), OnWindow::No);
        assert_eq!(reply_of(b"nwayland-1"), OnWindow::No);
        let on = |d: &str| OnWindow::Elsewhere(Some(OsString::from(d)));
        assert_eq!(reply_of(b"mwayland-1"), on("wayland-1"));
        assert_eq!(reply_of(&[ASK_WINDOW]), OnWindow::Elsewhere(None));
        assert_eq!(reply_of(&[ASK_NOWHERE]), OnWindow::Elsewhere(None));
        assert_eq!(reply_of(b"y"), OnWindow::Elsewhere(None), "never a yes");
        assert_eq!(reply_of(b""), OnWindow::Elsewhere(None), "closed");
        assert_eq!(reply_of(b"mway\0land"), OnWindow::Elsewhere(None));
        assert_eq!(ASK_NO, b'n');
    }

    /// A socket of questions that is not the launch's supervisor's — its
    /// pid another process's — is not asked on.
    #[test]
    fn a_socket_not_the_launchs_is_not_asked_on() {
        let root = std::env::temp_dir().join(format!("vz-onwindow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let path = crate::wl_proxy::ask_path(&root, 1);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let asked = ask(
            &root,
            1,
            "?",
            &["no", "more"],
            Some(std::time::Duration::from_secs(5)),
        );
        assert_eq!(asked, OnWindow::Elsewhere(None));
        drop(listener);
        // No socket at all.
        let none = ask(&root, 2, "?", &["no", "more"], None);
        assert_eq!(none, OnWindow::Elsewhere(None));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A process's launch is the nearest of its parents with a socket of
    /// questions; none: none.
    #[test]
    fn a_launch_is_the_nearest_parent_with_a_socket() {
        let root = std::env::temp_dir().join(format!("vz-onwindow-up-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let me = std::process::id() as i32;
        let parent = crate::sys::parent_of(me).unwrap();
        if parent <= 1 {
            return;
        }
        assert_eq!(launch_above(&root, me), None);
        let path = crate::wl_proxy::ask_path(&root, parent);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert_eq!(launch_above(&root, me), Some(parent));
        drop(listener);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Asked on the launch's own socket (here this process's): the question
    /// goes whole, and what the supervisor says comes back — "no", "ask in
    /// the launch window" with its compositor, or nothing in time.
    #[test]
    fn the_supervisors_word_comes_back() {
        use std::io::{Read, Write};
        let root = std::env::temp_dir().join(format!("vz-onwindow-say-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let me = std::process::id() as i32;
        let path = crate::wl_proxy::ask_path(&root, me);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let supervisor = std::thread::spawn(move || {
            let mut asked = Vec::new();
            for reply in [&b"n"[..], &b"mwayland-9"[..], &b""[..]] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut len = [0u8; 2];
                stream.read_exact(&mut len).unwrap();
                let mut payload = vec![0u8; usize::from(u16::from_le_bytes(len))];
                stream.read_exact(&mut payload).unwrap();
                asked.push(payload);
                if reply.is_empty() {
                    // Held, not answered: the asker gives up first.
                    let mut end = [0u8; 1];
                    let _ = stream.read(&mut end);
                } else {
                    stream.write_all(reply).unwrap();
                }
            }
            asked
        });
        let labels = ["Отказать", "Разрешить…"];
        let long = Some(std::time::Duration::from_secs(10));
        assert_eq!(ask(&root, me, "мик?", &labels, long), OnWindow::No);
        assert_eq!(
            ask(&root, me, "мик?", &labels, long),
            OnWindow::Elsewhere(Some(OsString::from("wayland-9")))
        );
        let short = Some(std::time::Duration::from_millis(300));
        assert_eq!(ask(&root, me, "мик?", &labels, short), OnWindow::Unanswered);
        let asked = supervisor.join().unwrap();
        assert_eq!(asked.len(), 3);
        assert_eq!(asked[0], "мик?\0Отказать\0Разрешить…".as_bytes());
        let _ = std::fs::remove_dir_all(&root);
    }
}
