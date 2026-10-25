//! Re-home an isolated launch from a nondelegated login session into the
//! user's service manager. Pass byte-exact argv/environment/cwd and the
//! picker's window pipe over a private, host-authenticated one-shot socket.
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

const MARKER: &str = "CELLWARD_USER_SERVICE";
const MAX: usize = 2 * 1024 * 1024;

fn managed(cgroup: &str, uid: u32) -> bool {
    let unit = format!("user@{uid}.service");
    crate::kill::cgroup_of(cgroup).is_some_and(|p| p.split('/').any(|part| part == unit))
}

/// Only the host entrypoint calls this, before consuming launch environment.
/// Never route a zone's command around its existing broker/no-escape checks.
pub(crate) fn maybe_delegate(
    tools: &crate::tools::Tools,
    verb: &str,
    args: &[OsString],
) -> Option<u8> {
    if crate::launch::in_zone()
        || !crate::permissions::flag(&tools.config, crate::strict_network::FLAG).0
        || std::env::var_os(crate::launch::ENV_DRYRUN).is_some()
    {
        return None;
    }
    let uid = unsafe { libc::getuid() };
    if uid == 0 || fs::read_to_string("/proc/self/cgroup").is_ok_and(|cg| managed(&cg, uid)) {
        return None;
    }
    let result = (|| -> Result<u8, String> {
        if std::env::var_os(MARKER).is_some() {
            return Err("user service has no delegated cgroup; launch refused".into());
        }
        // Do not launder an inherited host network socket into an AF_UNIX
        // stdio forwarder owned by systemd-run.
        crate::enter::strict_stdio().map_err(|e| e.to_string())?;
        crate::wl_sandbox::take_opened();
        let opened = crate::wl_sandbox::opened_for_proxy();
        let mut command = vec![tools.runner.clone().into_os_string(), verb.into()];
        command.extend_from_slice(args);
        let env: Vec<_> = std::env::vars_os()
            .filter(|(key, _)| !service_variable(key))
            .collect();
        let payload = encode(&command, &env).map_err(|e| e.to_string())?;
        let cwd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(".")
            .map_err(|e| e.to_string())?;
        let mut random = [0; 16];
        crate::bridge::random_bytes(&mut random).map_err(|e| e.to_string())?;
        // Abstract AF_UNIX names are confined to the host netns, do not
        // depend on HOME length, and leave no stale filesystem socket.
        // Random name + same UID + pinned userns guard the one-shot handoff.
        let socket = format!("cellward-user-launch-{:032x}", u128::from_ne_bytes(random));
        let address =
            SocketAddr::from_abstract_name(socket.as_bytes()).map_err(|e| e.to_string())?;
        let listener = UnixListener::bind_addr(&address).map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let cancel = crate::sys::Cancellation::new().map_err(|e| e.to_string())?;
        let token = cancel.token();
        let worker = std::thread::spawn(move || serve(listener, cwd, opened, payload, token));
        // Only trusted ASCII tool/socket paths cross D-Bus. Actual argv,
        // environment and cwd retain arbitrary Unix bytes through the socket.
        let tty = unsafe { libc::isatty(0) == 1 && libc::isatty(1) == 1 };
        let status = Command::new(&tools.systemd_run)
            .args([
                "--user",
                "--quiet",
                "--collect",
                "--wait",
                "--service-type=exec",
                if tty { "--pty" } else { "--pipe" },
                "--",
            ])
            .arg(&tools.core)
            .arg("user-launch-handoff")
            .arg(&socket)
            .status();
        drop(cancel);
        let handed = worker
            .join()
            .map_err(|_| "launch handoff worker failed".to_owned())?;
        let status = status.map_err(|e| format!("cannot start delegated user service: {e}"))?;
        if !handed && status.success() {
            return Err("user service did not receive the launch".into());
        }
        Ok(u8::try_from(
            status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)),
        )
        .unwrap_or(1))
    })();
    crate::wl_sandbox::no_word();
    Some(match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("cellward: delegated launch failed: {e}; no unregistered fallback");
            127
        }
    })
}

fn service_variable(key: &std::ffi::OsStr) -> bool {
    matches!(
        key.as_bytes(),
        b"INVOCATION_ID"
            | b"JOURNAL_STREAM"
            | b"NOTIFY_SOCKET"
            | b"WATCHDOG_PID"
            | b"WATCHDOG_USEC"
            | b"LISTEN_FDS"
            | b"LISTEN_PID"
            | b"LISTEN_FDNAMES"
    ) || key == MARKER
        || key == crate::wl_sandbox::ENV_OPENED_FD
}

fn serve(
    listener: UnixListener,
    cwd: File,
    opened: Option<OwnedFd>,
    payload: Vec<u8>,
    cancel: crate::sys::CancelToken,
) -> bool {
    let deadline = Instant::now() + Duration::from_secs(30);
    let ours = fs::read_link("/proc/self/ns/user").ok();
    loop {
        if cancel.cancelled() || Instant::now() >= deadline {
            return false;
        }
        let mut fds = [
            libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: cancel.fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(i32::MAX as u128) as i32;
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, remaining) };
        if ready < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if ready <= 0 || fds[1].revents != 0 {
            return false;
        }
        let Ok((mut conn, _)) = listener.accept() else {
            continue;
        };
        let peer = crate::origin::Peer::of(conn.as_raw_fd());
        if crate::bridge::peer_uid(conn.as_raw_fd()) != Some(unsafe { libc::getuid() })
            || ours.is_none()
            || peer.as_ref().and_then(|p| p.ns("user")) != ours
            || !peer.is_some_and(|p| p.alive())
        {
            continue;
        }
        let _ = conn.set_write_timeout(Some(Duration::from_secs(2)));
        let sent = (|| -> io::Result<()> {
            conn.write_all(&(payload.len() as u32).to_le_bytes())?;
            conn.write_all(&payload)?;
            let mut fds = vec![cwd.as_raw_fd()];
            if let Some(fd) = &opened {
                fds.push(fd.as_raw_fd());
            }
            crate::sys::send_with_fds(conn.as_raw_fd(), b"h", &fds)
        })();
        return sent.is_ok();
    }
}

fn encode(command: &[OsString], env: &[(OsString, OsString)]) -> io::Result<Vec<u8>> {
    let mut bytes = b"cwscope1".to_vec();
    bytes.extend_from_slice(&(command.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(env.len() as u32).to_le_bytes());
    for arg in command {
        bytes.extend_from_slice(arg.as_bytes());
        bytes.push(0);
    }
    for (key, value) in env {
        bytes.extend_from_slice(key.as_bytes());
        bytes.push(b'=');
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0);
    }
    if bytes.len() > MAX {
        return Err(io::Error::other(
            "delegated launch exceeds argument/environment budget",
        ));
    }
    Ok(bytes)
}

type Request = (Vec<OsString>, Vec<(OsString, OsString)>);
fn decode(bytes: &[u8]) -> io::Result<Request> {
    let bad = || io::Error::other("invalid delegated launch payload");
    if bytes.len() < 17
        || bytes.len() > MAX
        || bytes[..8] != *b"cwscope1"
        || bytes.last() != Some(&0)
    {
        return Err(bad());
    }
    let argc = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let envc = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    if argc == 0 || argc.saturating_add(envc) > MAX / 8 {
        return Err(bad());
    }
    let mut fields = bytes[16..bytes.len() - 1].split(|b| *b == 0);
    let command: Vec<_> = (0..argc)
        .map(|_| {
            fields
                .next()
                .map(|p| OsString::from_vec(p.to_vec()))
                .ok_or_else(bad)
        })
        .collect::<io::Result<_>>()?;
    if command[0].is_empty() || !Path::new(&command[0]).is_absolute() {
        return Err(bad());
    }
    let env = (0..envc)
        .map(|_| {
            let field = fields.next().ok_or_else(bad)?;
            let at = field
                .iter()
                .position(|b| *b == b'=')
                .filter(|n| *n != 0)
                .ok_or_else(bad)?;
            Ok((
                OsString::from_vec(field[..at].to_vec()),
                OsString::from_vec(field[at + 1..].to_vec()),
            ))
        })
        .collect::<io::Result<_>>()?;
    if fields.next().is_some() {
        return Err(bad());
    }
    Ok((command, env))
}

pub fn handoff_main(args: &[OsString]) -> u8 {
    let result = (|| -> io::Result<()> {
        if args.len() != 1 {
            return Err(io::Error::other("expected private handoff socket"));
        }
        let address = SocketAddr::from_abstract_name(args[0].as_bytes())?;
        let mut conn = UnixStream::connect_addr(&address)?;
        conn.set_read_timeout(Some(Duration::from_secs(10)))?;
        // The server independently pins our host peer; also reject foreign
        // users at the receiving end before accepting any command/fd.
        if crate::bridge::peer_uid(conn.as_raw_fd()) != Some(unsafe { libc::getuid() }) {
            return Err(io::Error::other("foreign handoff server"));
        }
        let mut size = [0; 4];
        conn.read_exact(&mut size)?;
        let size = u32::from_le_bytes(size) as usize;
        if size > MAX {
            return Err(io::Error::other("handoff payload too large"));
        }
        let mut bytes = vec![0; size];
        conn.read_exact(&mut bytes)?;
        let (command, env) = decode(&bytes)?;
        let (tag, mut fds) = crate::sys::recv_with_fds(conn.as_raw_fd(), 1, 2)?;
        if tag != b"h" || !(1..=2).contains(&fds.len()) {
            return Err(io::Error::other("invalid handoff descriptors"));
        }
        let cwd = fds.remove(0);
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(cwd.as_raw_fd(), &mut stat) } != 0
            || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
            || unsafe { libc::fchdir(cwd.as_raw_fd()) } != 0
        {
            return Err(io::Error::other("invalid handoff working directory"));
        }
        for (key, _) in std::env::vars_os() {
            std::env::remove_var(key);
        }
        for (key, value) in env {
            if !service_variable(&key) {
                std::env::set_var(key, value);
            }
        }
        std::env::set_var(MARKER, "1");
        let opened = fds.pop();
        if let Some(fd) = &opened {
            if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0
                || stat.st_mode & libc::S_IFMT != libc::S_IFIFO
                || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, 0) } != 0
            {
                return Err(io::Error::other("invalid handoff window pipe"));
            }
            std::env::set_var(crate::wl_sandbox::ENV_OPENED_FD, fd.as_raw_fd().to_string());
        }
        Err(crate::profile::exec_command(&command))
    })();
    if let Err(e) = result {
        eprintln!("cellward user launch: {e}; program not executed");
    }
    127
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn delegation_uses_real_manager_component_not_a_substring() {
        assert!(managed(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/term.scope\n",
            1000
        ));
        assert!(!managed(
            "0::/user.slice/user-1000.slice/session-4.scope\n",
            1000
        ));
        assert!(!managed("0::/fake-user@1000.service/unit\n", 1000));
        assert!(!managed("0::/user@1001.service/unit\n", 1000));
    }
    #[test]
    fn handoff_preserves_non_utf8_empty_arguments_and_environment() {
        let command = vec![
            OsString::from("/bin/test"),
            OsString::new(),
            OsString::from_vec(vec![0xff, b' ', b'\n']),
        ];
        let env = vec![("TEST".into(), OsString::from_vec(vec![b'=', 0xff]))];
        let encoded = encode(&command, &env).unwrap();
        assert_eq!(decode(&encoded).unwrap(), (command, env));
        for cut in 0..encoded.len() {
            assert!(decode(&encoded[..cut]).is_err(), "cut {cut}");
        }
        let mut extra = encoded;
        extra.extend_from_slice(b"extra\0");
        assert!(decode(&extra).is_err());
    }

    #[test]
    fn real_handoff_transfers_cwd_and_window_pipe_without_losing_raw_arguments() {
        let address =
            SocketAddr::from_abstract_name(format!("cw-scope-test-{}", std::process::id()))
                .unwrap();
        let listener = UnixListener::bind_addr(&address).unwrap();
        listener.set_nonblocking(true).unwrap();
        let cwd = File::open(".").unwrap();
        let (read, write) = crate::sys::pipe().unwrap();
        let command = vec!["/bin/test".into(), OsString::from_vec(vec![0xff])];
        let payload = encode(&command, &[]).unwrap();
        let cancel = crate::sys::Cancellation::new().unwrap();
        let token = cancel.token();
        let worker = std::thread::spawn(move || serve(listener, cwd, Some(write), payload, token));
        let mut conn = UnixStream::connect_addr(&address).unwrap();
        conn.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut size = [0; 4];
        conn.read_exact(&mut size).unwrap();
        let mut payload = vec![0; u32::from_le_bytes(size) as usize];
        conn.read_exact(&mut payload).unwrap();
        assert_eq!(decode(&payload).unwrap().0, command);
        let (tag, fds) = crate::sys::recv_with_fds(conn.as_raw_fd(), 1, 2).unwrap();
        assert_eq!(tag, b"h");
        assert_eq!(fds.len(), 2);
        let mut write = File::from(fds.into_iter().nth(1).unwrap());
        write.write_all(b"w").unwrap();
        let mut read = File::from(read);
        let mut byte = [0];
        read.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"w");
        assert!(worker.join().unwrap());
        drop(cancel);
    }
}
