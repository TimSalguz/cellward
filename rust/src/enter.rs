//! `vpn-zone-core container-enter --instance <id> [--systemctl P] -- cmd…`:
//! a launch into a container's instance (`crate::instance`, the container
//! design of 2026-09-27, stage 1) — what `nsenter` is to a zone's.
//!
//! **Two processes, two views.** This process — the launch's *waiter*, the
//! one its supervisor (`wl-sandbox`) started and waits for — joins the
//! instance's user, network and IPC namespaces and never its mount
//! namespace (J8 of the design): it stays in the host's, where `/proc` is
//! the host's and every number it holds means what it says. Its child joins
//! the mount namespace, takes a copy of it of its own (a slave: what the
//! instance binds into its runtime directory later still comes in, nothing
//! the launch mounts goes back), raises the capabilities of the instance's
//! user namespace into its ambient set — what `nsenter --keep-caps` did,
//! for `profile-run` to mount the container's layer with — and becomes the
//! command.
//!
//! **Which instance.** By its id, again here and not by a number handed
//! down: the space's process is read from the instance's directory, held
//! by a pidfd, and believed only while it is the one that wrote the number
//! (`instance::up`, before and after the pidfd). Every namespace is joined
//! through that pidfd. The network it has is what `profile-run` checks from
//! inside ([`crate::profile::ENV_EXPECT_NETNS`]).
//!
//! **The lock.** Shared, from the look at the instance until the child has
//! exec'd — until its program is in, where the keeper's look finds it. The
//! keeper ends an instance only with the lock taken exclusively and nobody
//! in (`zone::keep`); this one then finds it gone, and starts it again
//! (`--systemctl`). And then the doorbell: the keeper looks again.
//!
//! **The waiter itself.** Not dumpable from its first step: it is in the
//! instance's user namespace with the host's files around it, and a
//! program of the instance that could trace it would reach them. Its
//! capabilities go once the child is on its way. It passes the signals a
//! launch is ended with on to the child, and ends with its status.
//!
//! **It does not stop when the child stops**, as `nsenter` did. A terminal's
//! job control needs no mirror here — the waiter, its child and the
//! supervisor are one process group, and `^Z` and `fg` reach them all —,
//! and a mirror would hang: `cellward container kill` freezes the
//! instance's programs with SIGSTOP, the waiter would stop itself for good
//! (it is not in sight of that scan to be killed — not dumpable), and its
//! child killed a moment later would stay its unreaped zombie under a
//! stopped parent. (`nsenter`, dumpable, was frozen and killed with a
//! zone's programs.)

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};

use crate::profile::{exec_command, exit_code_of, EXIT_NOT_STARTED};

/// What `container-enter` was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub instance: String,
    /// `systemctl`, to start an instance that stopped between the launch's
    /// look and this one's. Without it such a launch is not started.
    pub systemctl: Option<PathBuf>,
    pub cmd: Vec<OsString>,
}

impl Args {
    /// `--instance <id> [--systemctl <path>] -- cmd…`.
    pub fn parse(argv: &[OsString]) -> Result<Self, String> {
        let mut instance = None;
        let mut systemctl = None;
        let mut rest = argv.iter();
        while let Some(flag) = rest.next() {
            if flag == "--" {
                let cmd: Vec<OsString> = rest.cloned().collect();
                if cmd.is_empty() {
                    return Err("nothing to run after `--`".to_owned());
                }
                let instance = instance.ok_or("--instance is required")?;
                return Ok(Self {
                    instance,
                    systemctl,
                    cmd,
                });
            }
            let value = rest
                .next()
                .ok_or_else(|| format!("{} needs a value", flag.to_string_lossy()))?;
            match flag.to_str() {
                Some("--instance") => {
                    instance = Some(
                        value
                            .to_str()
                            .filter(|id| crate::instance::valid_id(id))
                            .ok_or("--instance is not an instance's id")?
                            .to_owned(),
                    )
                }
                Some("--systemctl") => systemctl = Some(PathBuf::from(value)),
                _ => return Err(format!("unknown flag {}", flag.to_string_lossy())),
            }
        }
        Err("no `--` before the command".to_owned())
    }
}

/// The launch's child, for the signals passed on to it.
static CHILD: AtomicI32 = AtomicI32::new(0);

extern "C" fn pass_on(sig: libc::c_int) {
    let pid = CHILD.load(Ordering::SeqCst);
    if pid > 0 {
        // SAFETY: kill(2) is async-signal-safe and takes no pointers.
        unsafe { libc::kill(pid, sig) };
    }
}

/// The signals a launch is ended or told something with.
const PASSED_ON: [libc::c_int; 6] = [
    libc::SIGTERM,
    libc::SIGINT,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGUSR1,
    libc::SIGUSR2,
];

/// The instance's lock file, opened — `None` when its directory is not
/// there (the instance is not up).
fn open_lock(dir: &Path) -> Option<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(dir.join(crate::instance::LOCK))
        .ok()
}

/// `flock(2)`, shared, as long as that takes.
fn lock_shared(lock: &File) -> bool {
    loop {
        // SAFETY: flock(2) on a descriptor we hold.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_SH) } == 0 {
            return true;
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return false;
        }
    }
}

/// The keeper's doorbell (`instance::CONTROL`): a connection, closed at
/// once, is the word "look again". Through the directory's descriptor —
/// the path may be longer than a socket's. Nobody answers: an instance
/// whose keeper is gone is looked at by nobody.
fn ring(dir: &Path) {
    let Ok(held) = crate::sys::open_dir(dir) else {
        return;
    };
    let path = format!(
        "/proc/self/fd/{}/{}",
        held.as_raw_fd(),
        crate::instance::CONTROL
    );
    let _ = std::os::unix::net::UnixStream::connect(path);
}

/// The instance up, held: its lock taken shared, its space's pid and a pidfd
/// of it — started when it is not up and `systemctl` is there.
fn held_instance(state: &Path, args: &Args) -> Result<(File, libc::pid_t, OwnedFd), String> {
    let dir = crate::instance::dir(state, &args.instance);
    for attempt in 0..2 {
        if attempt > 0 {
            let Some(systemctl) = &args.systemctl else {
                break;
            };
            let unit = crate::instance::unit_name(&args.instance)
                .ok_or("the instance has no unit's name (its id is too long)")?;
            let _ = std::process::Command::new(systemctl)
                .args(["--user", "start"])
                .arg(unit)
                .status();
        }
        let Some(lock) = open_lock(&dir) else {
            continue;
        };
        if !lock_shared(&lock) {
            continue;
        }
        if let Some(pid) = crate::instance::up(state, &args.instance) {
            if let Some(fd) = crate::sys::pidfd_open(pid) {
                // Held now: still the process that wrote the number.
                if crate::instance::up(state, &args.instance) == Some(pid) {
                    return Ok((lock, pid, fd));
                }
            }
        }
        drop(lock);
    }
    Err(format!(
        "контейнер {} не поднят — запуск остановлен",
        args.instance
    ))
}

/// `setns(2)` through a pidfd, into the namespaces of `flags`.
fn setns(pidfd: &OwnedFd, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: setns(2) with a pidfd we hold and constant flags.
    if unsafe { libc::setns(pidfd.as_raw_fd(), flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `capget`/`capset`'s header and data (`_LINUX_CAPABILITY_VERSION_3`).
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const CAP_VERSION_3: u32 = 0x2008_0522;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_RAISE: libc::c_int = 2;
const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_int = 4;

/// Every capability permitted now raised into the ambient set: kept across
/// the `exec` of a program that is not uid 0 in the instance's namespace —
/// what `nsenter --keep-caps` did for a zone. The inheritable set first:
/// the kernel raises only what is permitted and inheritable both.
fn raise_ambient() -> io::Result<()> {
    let mut header = CapHeader {
        version: CAP_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: capget/capset with a version 3 header and two data words.
    unsafe {
        if libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        for word in &mut data {
            word.inheritable = word.permitted;
        }
        if libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    for (word, bits) in data.iter().enumerate() {
        for bit in 0..32usize {
            if bits.permitted & (1u32 << bit) != 0 {
                let cap = (word * 32 + bit) as libc::c_ulong;
                // SAFETY: prctl with these arguments takes no pointers. A
                // capability this kernel does not know is refused: skipped.
                unsafe { libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0) };
            }
        }
    }
    Ok(())
}

/// Every capability dropped, and none kept for an exec.
fn drop_capabilities() {
    let mut header = CapHeader {
        version: CAP_VERSION_3,
        pid: 0,
    };
    let data = [CapData::default(); 2];
    // SAFETY: prctl and capset with a version 3 header and two zeroed data
    // words: nothing is left.
    unsafe {
        libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
        libc::syscall(libc::SYS_capset, &mut header, data.as_ptr());
    }
}

/// The child: the instance's mount namespace, a copy of it of its own, the
/// capabilities kept, the command. Returns only when something failed —
/// what, for the waiter to say.
fn become_the_launch(space: &OwnedFd, cmd: &[OsString]) -> String {
    if let Err(e) = setns(space, libc::CLONE_NEWNS) {
        return format!("cannot join the instance's mount namespace: {e}");
    }
    // SAFETY: unshare(2) takes no pointers.
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        return format!(
            "cannot take a mount namespace of the launch's own: {}",
            io::Error::last_os_error()
        );
    }
    if let Err(e) = crate::sys::mount(
        std::ffi::OsStr::new("none"),
        Path::new("/"),
        "",
        libc::MS_REC | libc::MS_SLAVE,
        "",
    ) {
        return format!("cannot make the launch's mounts a slave of the instance's: {e}");
    }
    if let Err(e) = raise_ambient() {
        return format!("cannot keep the instance's capabilities: {e}");
    }
    let e = exec_command(cmd);
    format!("cannot start {}: {e}", cmd[0].to_string_lossy())
}

/// Wait for the child's end — not its stops (the module's words) — and give
/// its status as a shell reports it.
fn wait_for_end(child: libc::pid_t) -> u8 {
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: `status` is a valid pointer for the duration of the call.
        let r = unsafe { libc::waitpid(child, &mut status, 0) };
        if r < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return 1;
        }
        return exit_code_of(status);
    }
}

pub fn run(args: &Args) -> u8 {
    // SAFETY: prctl with these arguments takes no pointers.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    let Some(home) = crate::profile::home_dir() else {
        eprintln!("container-enter: no $HOME and no passwd entry — no instance to find");
        return EXIT_NOT_STARTED;
    };
    let state = home.join(crate::zone::STATE_SUBDIR);
    let dir = crate::instance::dir(&state, &args.instance);
    let (lock, pid, space) = match held_instance(&state, args) {
        Ok(held) => held,
        Err(why) => {
            eprintln!("{why}");
            ring(&dir);
            return EXIT_NOT_STARTED;
        }
    };
    // Its network as it is now: what `profile-run` checks from inside. Not
    // ours: a space in the host's network would be no instance's.
    let netns = std::fs::read_link(format!("/proc/{pid}/ns/net")).ok();
    let own = std::fs::read_link("/proc/self/ns/net").ok();
    let Some(netns) = netns.filter(|ns| Some(ns) != own.as_ref()) else {
        eprintln!(
            "контейнер {}: его пространство в сети хоста или не читается — запуск остановлен",
            args.instance
        );
        drop(lock);
        ring(&dir);
        return EXIT_NOT_STARTED;
    };
    std::env::set_var(crate::profile::ENV_EXPECT_NETNS, &netns);
    if let Err(e) = setns(
        &space,
        libc::CLONE_NEWUSER | libc::CLONE_NEWNET | libc::CLONE_NEWIPC,
    ) {
        eprintln!(
            "контейнер {}: не войти в его пространство ({e}) — запуск остановлен",
            args.instance
        );
        drop(lock);
        ring(&dir);
        return EXIT_NOT_STARTED;
    }
    // The child's word: nothing (its exec closed the pipe) or why it could
    // not become the launch.
    let (said_r, said_w) = match crate::sys::pipe() {
        Ok(pipe) => pipe,
        Err(e) => {
            eprintln!("container-enter: cannot create a pipe ({e})");
            drop(lock);
            ring(&dir);
            return EXIT_NOT_STARTED;
        }
    };
    // SAFETY: single-threaded, so the child may allocate before its exec.
    let child = unsafe { libc::fork() };
    if child < 0 {
        eprintln!(
            "container-enter: cannot fork ({})",
            io::Error::last_os_error()
        );
        drop(lock);
        ring(&dir);
        return EXIT_NOT_STARTED;
    }
    if child == 0 {
        drop(said_r);
        drop(lock);
        let why = become_the_launch(&space, &args.cmd);
        let _ = File::from(said_w).write_all(why.as_bytes());
        // SAFETY: _exit never returns and touches nothing of ours.
        unsafe { libc::_exit(libc::c_int::from(EXIT_NOT_STARTED)) };
    }
    drop(said_w);
    drop(space);
    CHILD.store(child, Ordering::SeqCst);
    for sig in PASSED_ON {
        // SAFETY: signal(2) with a plain function pointer; the handler only
        // reads an atomic and calls kill(2).
        unsafe {
            libc::signal(
                sig,
                pass_on as extern "C" fn(libc::c_int) as libc::sighandler_t,
            )
        };
    }
    // Nothing left to do in the instance's namespace that needs them.
    drop_capabilities();
    let mut said = String::new();
    let _ = File::from(said_r).read_to_string(&mut said);
    // The program is in, or will not be: the lock goes, the keeper looks.
    drop(lock);
    ring(&dir);
    if !said.is_empty() {
        eprintln!("контейнер {}: {said}", args.instance);
    }
    wait_for_end(child)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn the_instance_and_the_command_are_taken_apart_at_the_separator() {
        let a = Args::parse(&argv(&["--instance", "work", "--", "foot", "--", "-x"])).unwrap();
        assert_eq!(a.instance, "work");
        assert_eq!(a.systemctl, None);
        assert_eq!(a.cmd, argv(&["foot", "--", "-x"]));
        let a = Args::parse(&argv(&[
            "--systemctl",
            "/bin/systemctl",
            "--instance",
            "main:offline",
            "--",
            "true",
        ]))
        .unwrap();
        assert_eq!(a.instance, "main:offline");
        assert_eq!(a.systemctl, Some(PathBuf::from("/bin/systemctl")));
    }

    #[test]
    fn a_broken_command_line_is_refused() {
        for bad in [
            &[][..],
            &["--instance", "work"],
            &["--instance", "work", "--"],
            &["--", "true"],
            &["--instance", "a/b", "--", "true"],
            &["--instance", "work", "--other", "x", "--", "true"],
            &["--instance"],
        ] {
            assert!(Args::parse(&argv(bad)).is_err(), "{bad:?}");
        }
    }
}
