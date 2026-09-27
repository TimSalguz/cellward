//! `vpn-zone-core x11-run`: an X server of the launch's own, for a program in a
//! zone whose container has the `x11` permission (`docs/HERMETICITY.md` §7, A).
//!
//! The host's X server is out of reach in a zone: `/tmp/.X11-unix` is a tmpfs
//! there and `DISPLAY` is dropped from the launch, because one X server shows
//! every client the windows, the keyboard and the clipboard of all the others.
//! A container that needs X gets an `xwayland-satellite` instead — on the
//! Wayland socket the launch already has, which `wl-sandbox` has restricted —
//! and only its own programs are its clients.
//!
//! Unlike the sandbox's launcher (`fs-sandbox-x11`), nothing here dies with a
//! pid namespace, so this one supervises: it starts the satellite (which is
//! told to die with it), starts the program, waits for it, and takes the
//! satellite down.
//!
//! The display's socket is this process's own (review 2026-09-27): bound
//! here, in the launch's own `/tmp/.X11-unix` (`profile-run --own-x11`), and
//! handed to the satellite (`-listenfd`) — a name no other program of the
//! zone took first, where no other can reach it, and no socket in the
//! abstract namespace, which the zone's network namespace shows every
//! program of the zone. An X server takes no password from its clients:
//! whoever reaches it sees everything its clients show and type.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::profile::EXIT_NOT_STARTED;

/// The marker of a zone whose programs get an X server of their own, in the
/// zone's directory.
pub const ZONE_FLAG: &str = "x11";
/// The zones declared to have one, one name per line, below the config dir.
pub const DECLARED_ZONES: &str = "declared/zone-x11";

/// Where the per-zone setting comes from, if the zone has one:
/// `(on, source)`. Declared in Nix wins over the local marker.
pub fn zone_setting(state: &Path, config: &Path, zone: &str) -> (bool, crate::container::Source) {
    use crate::container::Source;
    if let Ok(text) = std::fs::read_to_string(config.join(DECLARED_ZONES)) {
        if text.lines().map(str::trim).any(|l| l == zone) {
            return (true, Source::Nix);
        }
    }
    if state.join(zone).join(ZONE_FLAG).exists() {
        (true, Source::Local)
    } else {
        (false, Source::Default)
    }
}

/// Where X servers put their sockets.
pub const X11_DIR: &str = "/tmp/.X11-unix";
/// The displays a satellite may take: `:100`…`:499`, like the sandbox's.
const FIRST: u32 = 100;
const LAST: u32 = 499;

/// What `x11-run` was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub xwayland: PathBuf,
    pub cmd: Vec<OsString>,
}

impl Args {
    /// Parse `[--xwayland P] -- cmd...`.
    pub fn parse(argv: &[OsString]) -> Result<Self, String> {
        let split = argv
            .iter()
            .position(|a| a == "--")
            .ok_or("need -- before the command")?;
        let cmd = argv[split + 1..].to_vec();
        if cmd.is_empty() {
            return Err("nothing to run".to_owned());
        }
        let mut xwayland = PathBuf::from("xwayland-satellite");
        let mut rest = argv[..split].iter();
        while let Some(arg) = rest.next() {
            match arg.as_bytes() {
                b"--xwayland" => {
                    xwayland = rest
                        .next()
                        .map(PathBuf::from)
                        .ok_or("--xwayland needs a path")?;
                }
                _ => return Err(format!("unknown argument: {}", arg.to_string_lossy())),
            }
        }
        Ok(Self { xwayland, cmd })
    }
}

/// A display of this process's own: the first number with no lock file
/// whose socket this process could bind — a name nobody holds, bound before
/// anyone else could take it. The socket, listening.
pub fn own_display(dir: &Path, lock_dir: &Path) -> Option<(u32, UnixListener)> {
    (FIRST..=LAST).find_map(|n| {
        if std::fs::symlink_metadata(lock_dir.join(format!(".X{n}-lock"))).is_ok() {
            return None;
        }
        // Clients try the abstract name first (libxcb): one somebody holds
        // is a display whose clients would go there (see [`run`]).
        if abstract_name_taken(n) {
            return None;
        }
        UnixListener::bind(dir.join(format!("X{n}")))
            .ok()
            .map(|listener| (n, listener))
    })
}

/// Whether `@/tmp/.X11-unix/X<n>` is bound by somebody in this network
/// namespace: a bind of our own fails. Ours, if it succeeds, goes at once.
pub(crate) fn abstract_name_taken(n: u32) -> bool {
    use std::os::linux::net::SocketAddrExt;
    let Ok(addr) =
        std::os::unix::net::SocketAddr::from_abstract_name(format!("/tmp/.X11-unix/X{n}"))
    else {
        return true;
    };
    UnixListener::bind_addr(&addr).is_err()
}

/// Whether an X server answers on `socket`: a connection of our own, and
/// the first byte of the server's answer to its setup. Waited for as long
/// as it takes — no clock: on a loaded machine the server comes up late,
/// and a deadline would start the program without X exactly there. A
/// server that ends first ends the wait: the listening socket goes with it,
/// and the connection waiting in it is cut.
pub fn x_answers(socket: &Path) -> bool {
    let Ok(mut stream) = UnixStream::connect(socket) else {
        return false;
    };
    // Little-endian, protocol 11.0, no authorisation.
    let setup = [b'l', 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    if stream.write_all(&setup).is_err() {
        return false;
    }
    let mut answer = [0u8; 1];
    matches!(stream.read(&mut answer), Ok(1))
}

/// Start the satellite, run the program on it, take the satellite down.
pub fn run(args: Args) -> u8 {
    // The server's clients try the abstract name `@/tmp/.X11-unix/X<n>`
    // before the socket's path (libxcb), and fall back only when there is
    // none: a program of the zone that took the name after the display was
    // chosen would be the server this launch's programs talk to — and relay
    // them to the real one, seeing everything. Under a Landlock scope the
    // launch reaches no abstract socket of the outside: a name taken is a
    // display that does not open, never a server in between.
    match crate::sys::abstract_socket_scope() {
        Some(scope) => {
            if let Err(e) = crate::sys::enter_scope(scope.as_raw_fd()) {
                eprintln!("x11-run: cannot keep off the zone's abstract sockets ({e}) — the program starts without X");
                return exec(&args.cmd);
            }
        }
        None => eprintln!(
            "x11-run: this kernel cannot keep the X clients off the zone's abstract sockets \
             (Landlock scopes, Linux 6.12)"
        ),
    }
    let dir = Path::new(X11_DIR);
    let Some((number, listener)) = own_display(dir, Path::new("/tmp")) else {
        eprintln!("x11-run: no free X display — the program starts without X");
        return exec(&args.cmd);
    };
    let display = format!(":{number}");
    let socket = dir.join(format!("X{number}"));
    let gone = || {
        let _ = std::fs::remove_file(&socket);
    };
    let fd = listener.as_raw_fd();
    let mut satellite = Command::new(&args.xwayland);
    satellite
        .arg(&display)
        .arg("-listenfd")
        .arg(fd.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // The satellite is a compositor to Xwayland, on a socket it makes in
    // its runtime directory — the zone's is every program of the zone's, and
    // one there first would be the one it serves. A runtime directory of its
    // own, in the launch's own X11 directory; the host compositor's socket
    // by its whole path.
    let runtime = dir.join(format!(".run-{number}"));
    if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(&runtime) {
        // The zone's instead would be the interception this is here against.
        eprintln!(
            "x11-run: no runtime directory of the satellite's own ({}: {e}) — the program \
             starts without X",
            runtime.display()
        );
        gone();
        return exec(&args.cmd);
    }
    if let (Some(wayland), Some(old)) = (
        std::env::var_os("WAYLAND_DISPLAY").filter(|d| !d.is_empty()),
        std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()),
    ) {
        satellite.env("WAYLAND_DISPLAY", Path::new(&old).join(wayland));
    }
    satellite.env("XDG_RUNTIME_DIR", &runtime);
    // SAFETY: prctl and fcntl in the child before exec, async-signal-safe:
    // the satellite dies with this process, whatever kills it, and gets the
    // display's socket.
    unsafe {
        satellite.pre_exec(move || {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut satellite = match satellite.spawn() {
        Ok(child) => child,
        Err(e) => {
            eprintln!(
                "x11-run: cannot start {} ({e}) — the program starts without X",
                args.xwayland.display()
            );
            gone();
            return exec(&args.cmd);
        }
    };
    // The satellite's copy is the only one: if it ends, the socket closes.
    drop(listener);
    if !x_answers(&socket) {
        eprintln!("x11-run: the X server ended before it answered — the program starts without it");
        let _ = satellite.kill();
        let _ = satellite.wait();
        gone();
        return exec(&args.cmd);
    }

    let status = Command::new(&args.cmd[0])
        .args(&args.cmd[1..])
        .env("DISPLAY", &display)
        .env_remove("XAUTHORITY")
        .status();
    let _ = satellite.kill();
    let _ = satellite.wait();
    gone();
    let _ = std::fs::remove_dir_all(&runtime);
    match status {
        Ok(status) => {
            use std::os::unix::process::ExitStatusExt;
            crate::profile::exit_code_of(status.into_raw())
        }
        Err(e) => {
            eprintln!(
                "x11-run: cannot start {}: {e}",
                args.cmd[0].to_string_lossy()
            );
            EXIT_NOT_STARTED
        }
    }
}

fn exec(cmd: &[OsString]) -> u8 {
    let e = crate::profile::exec_command(cmd);
    eprintln!("x11-run: cannot start {}: {e}", cmd[0].to_string_lossy());
    EXIT_NOT_STARTED
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn the_command_follows_the_separator() {
        let a = Args::parse(&argv(&["--xwayland", "/s/xw", "--", "steam", "-silent"])).unwrap();
        assert_eq!(a.xwayland, PathBuf::from("/s/xw"));
        assert_eq!(a.cmd, argv(&["steam", "-silent"]));
        assert!(Args::parse(&argv(&["steam"])).is_err());
        assert!(Args::parse(&argv(&["--"])).is_err());
        assert!(Args::parse(&argv(&["--weird", "--", "x"])).is_err());
    }

    #[test]
    fn a_display_with_a_socket_or_a_lock_is_taken() {
        let base = std::env::temp_dir().join(format!("vpn-zone-x11-{}", std::process::id()));
        let sockets = base.join("sockets");
        std::fs::create_dir_all(&sockets).unwrap();
        // The first free one: on a machine with X servers of its own, the
        // abstract names below it may be somebody's.
        let (first, _held) = own_display(&sockets, &base).unwrap();
        assert!(sockets.join(format!("X{first}")).exists());
        // Taken: by a socket (ours, still held, or anybody's file), or a lock.
        std::fs::write(sockets.join(format!("X{}", first + 1)), "").unwrap();
        std::fs::write(base.join(format!(".X{}-lock", first + 2)), "").unwrap();
        let second = own_display(&sockets, &base).unwrap().0;
        assert!(second > first + 2, "{first} {second}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// No answer from a socket nobody serves: the wait ends when the
    /// listening socket does, not by a clock.
    #[test]
    fn a_server_that_ends_first_ends_the_wait() {
        let base = std::env::temp_dir().join(format!("vpn-zone-x11-gone-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let socket = base.join("X100");
        let listener = UnixListener::bind(&socket).unwrap();
        let closer = std::thread::spawn(move || drop(listener));
        closer.join().unwrap();
        assert!(!x_answers(&socket));
        let listener = UnixListener::bind(base.join("X101")).unwrap();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut setup = [0u8; 12];
            conn.read_exact(&mut setup).unwrap();
            conn.write_all(&[1]).unwrap();
        });
        assert!(x_answers(&base.join("X101")));
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }
}
