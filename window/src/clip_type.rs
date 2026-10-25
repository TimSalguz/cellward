//! Host clipboard manager's connection to the selected launch's input proxy.
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::type_input::{Mode, Plan, Request, Timing};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LineBreaks {
    #[default]
    Reject,
    Spaces,
    Enter,
}

impl std::fmt::Display for LineBreaks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Reject => "Переносы: остановить ввод",
            Self::Spaces => "Переносы: заменить пробелами",
            Self::Enter => "Переносы: Enter (может отправить сообщение)",
        })
    }
}

fn typing_text(text: &str, policy: LineBreaks) -> Result<String, String> {
    let text = text.replace("\r\n", "\n");
    match policy {
        LineBreaks::Reject if text.contains('\n') => Err("В записи есть переносы строк. Выберите их обработку: Enter может отправить сообщение или выполнить команду. Обычная вставка безопаснее посимвольного ввода.".into()),
        LineBreaks::Spaces => Ok(text.replace('\n', " ")),
        _ => Ok(text),
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Target {
    pub pid: u32,
    pub token: u64,
}

fn runtime() -> Result<PathBuf, String> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| "Нет каталога сеанса XDG_RUNTIME_DIR".into())
}

fn connect(pid: u32) -> Result<UnixStream, String> {
    let path = runtime()?.join("vpn-zones/ask").join(pid.to_string());
    UnixStream::connect(path).map_err(|_| "Окно выбранной программы уже закрылось".into())
}

fn send(stream: &mut UnixStream, request: &Request) -> Result<(), String> {
    let bytes = request.bytes();
    if Request::parse(&bytes).is_none() {
        return Err("Некорректный запрос ввода".into());
    }
    let length = u16::try_from(bytes.len()).map_err(|_| "Слишком длинный текст")?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&length.to_le_bytes())
        .and_then(|()| stream.write_all(&bytes))
        .map_err(|_| "Не удалось передать запрос ввода".into())
}

/// Each live, updated launch draws its own overlay. The first real click
/// selects one; closing the other sockets retracts their overlays.
pub fn choose(launch: Option<u32>) -> Result<Target, String> {
    let dir = runtime()?.join("vpn-zones/ask");
    let mut nonce = [0u8; 8];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut nonce))
        .map_err(|e| e.to_string())?;
    let token = u64::from_le_bytes(nonce).max(1);
    let mut streams = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .map_err(|_| "Нет открытых окон cellward")?
        .flatten()
    {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if launch.is_some_and(|wanted| wanted != pid) {
            continue;
        }
        // Older supervisors do not understand this protocol. Do not turn a
        // control packet into an empty permission question on an old build.
        if std::fs::read(entry.path().with_extension("typing"))
            .ok()
            .as_deref()
            != Some(b"1")
        {
            continue;
        }
        if streams.len() == 128 {
            break;
        }
        let Ok(mut stream) = connect(pid) else {
            continue;
        };
        if send(&mut stream, &Request::Select { token }).is_ok()
            && stream.set_nonblocking(true).is_ok()
        {
            streams.push((pid, stream));
        }
    }
    if streams.is_empty() {
        return Err(
            "Нет подходящего окна. Перезапустите программу после обновления cellward".into(),
        );
    }
    let until = Instant::now() + Duration::from_secs(125);
    while !streams.is_empty() && Instant::now() < until {
        let mut fds: Vec<_> = streams
            .iter()
            .map(|(_, stream)| libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        // SAFETY: every pollfd refers to one live stream above.
        let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 1000) };
        if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err("Не удалось дождаться выбора окна".into());
        }
        let mut closed = Vec::new();
        for (i, (pid, stream)) in streams.iter_mut().enumerate() {
            if fds[i].revents == 0 {
                continue;
            }
            let mut byte = [0];
            match stream.read(&mut byte) {
                Ok(1) if byte[0] == b'y' => return Ok(Target { pid: *pid, token }),
                Ok(1) if byte[0] == b'n' => return Err("Выбор точки отменён".into()),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                _ => closed.push(i),
            }
        }
        for i in closed.into_iter().rev() {
            streams.remove(i);
        }
    }
    Err("Точка ввода не выбрана".into())
}

/// The entry goes directly from the daemon to the selected launch. No
/// clipboard selection, process argument or environment value contains it.
pub fn type_entry(
    target: Target,
    socket: &Path,
    history: &str,
    id: u64,
    mime: &str,
    timing: Timing,
    mode: Mode,
    lines: LineBreaks,
) -> Result<(), String> {
    if !timing.valid() {
        return Err("Проверьте задержки ввода".into());
    }
    let data = crate::clipd::ask(socket, &crate::clipd::get_request(history, id, mime))
        .map_err(|e| e.text())?;
    let bytes = crate::clipd::read_got(data.as_slice())?;
    let text = String::from_utf8(bytes).map_err(|_| "Выбранный текст не в UTF-8")?;
    let text = typing_text(&text, lines)?;
    let plan = Plan::new(&text, mode).map_err(str::to_owned)?;
    let timeout_ms = u64::from(timing.start_ms)
        + (timing.between_ms as u64 + timing.hold_ms as u64) * plan.keys.len() as u64
        + 10_000;
    drop(plan.keymap);
    let mut stream = connect(target.pid)?;
    send(
        &mut stream,
        &Request::Type {
            token: target.token,
            timing,
            mode,
            text,
        },
    )?;
    stream
        .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .map_err(|e| e.to_string())?;
    let mut answer = [0u8];
    match stream.read_exact(&mut answer) {
        Ok(()) if answer[0] == b'y' => Ok(()),
        Ok(()) if answer[0] == b'n' => Err("Ввод прерван".into()),
        _ => Err("Точка ввода устарела или окно изменилось. Выберите точку снова".into()),
    }
}

pub fn cancel(target: Target) -> Result<(), String> {
    let mut stream = connect(target.pid)?;
    send(
        &mut stream,
        &Request::Cancel {
            token: target.token,
        },
    )?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    let mut answer = [0];
    stream
        .read_exact(&mut answer)
        .map_err(|_| "Не удалось остановить ввод")?;
    if answer[0] == b'y' {
        Ok(())
    } else {
        Err("Не удалось остановить ввод".into())
    }
}

fn settings_path() -> Option<PathBuf> {
    let dir = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(dir.join("cellward/typing.conf"))
}

pub fn load() -> (Timing, Mode, LineBreaks) {
    let mut timing = Timing::default();
    let mut mode = Mode::default();
    let mut lines = LineBreaks::default();
    if let Some(text) = settings_path().and_then(|p| std::fs::read_to_string(p).ok()) {
        for (name, value) in text.lines().filter_map(|l| l.split_once('=')) {
            match name {
                "start" => {
                    if let Ok(n) = value.parse() {
                        timing.start_ms = n;
                    }
                }
                "between" => {
                    if let Ok(n) = value.parse() {
                        timing.between_ms = n;
                    }
                }
                "hold" => {
                    if let Ok(n) = value.parse() {
                        timing.hold_ms = n;
                    }
                }
                "mode" if value == "keycodes" => mode = Mode::Keycodes,
                "newlines" if value == "enter" => lines = LineBreaks::Enter,
                "newlines" if value == "spaces" => lines = LineBreaks::Spaces,
                _ => {}
            }
        }
    }
    if !timing.valid() {
        timing = Timing::default();
    }
    (timing, mode, lines)
}

pub fn save(timing: Timing, mode: Mode, lines: LineBreaks) -> Result<(), String> {
    if !timing.valid() {
        return Err("Некорректные задержки ввода".into());
    }
    let path = settings_path().ok_or("Нет каталога настроек")?;
    let dir = path.parent().expect("settings parent");
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let tmp = dir.join(format!(".typing-{}.tmp", std::process::id()));
    std::fs::write(
        &tmp,
        format!(
            "start={}\nbetween={}\nhold={}\nmode={}\nnewlines={}\n",
            timing.start_ms,
            timing.between_ms,
            timing.hold_ms,
            if mode == Mode::Unicode {
                "unicode"
            } else {
                "keycodes"
            },
            match lines {
                LineBreaks::Reject => "reject",
                LineBreaks::Spaces => "spaces",
                LineBreaks::Enter => "enter",
            }
        ),
    )
    .and_then(|()| std::fs::rename(&tmp, path))
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod newline_tests {
    use super::*;
    #[test]
    fn multiline_typing_requires_an_explicit_policy() {
        assert_eq!(LineBreaks::default(), LineBreaks::Reject);
        assert!(typing_text("one\r\ntwo", LineBreaks::Reject).is_err());
        assert_eq!(
            typing_text("one\r\ntwo\n", LineBreaks::Spaces).unwrap(),
            "one two "
        );
        assert_eq!(
            typing_text("one\r\ntwo", LineBreaks::Enter).unwrap(),
            "one\ntwo"
        );
        assert_eq!(typing_text("single", LineBreaks::Reject).unwrap(), "single");
        assert!(Plan::new(
            &typing_text("x\ry", LineBreaks::Spaces).unwrap(),
            Mode::Unicode
        )
        .is_err());
    }
}
