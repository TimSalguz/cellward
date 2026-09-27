//! Pid 1 of a container's instance (stage 3 of the container design of
//! 2026-09-27, `docs/THREAT-MODEL.md` X4): the process the instance's pid
//! namespace is made with, and ends with.
//!
//! ```text
//! H  container-holder --inner      uid 0 of the instance's user namespace,
//!  │                               unshare(NEWPID), fork
//!  └─ I  pid 1 — this module: unshare(NET|NS|IPC), its own /proc
//!      └─ K  the space: covers, /dev and its guard, the bus filter (`zone`)
//! ```
//!
//! **Why a pid namespace.** Without one a program of the instance saw every
//! process of the host in `/proc`: the command lines of the user's other
//! programs (the containers and zones in use, the URLs and paths they were
//! given), and `/proc/<pid>/net` of any of them — their network's sockets
//! and addresses, which no ptrace check guards. A `/proc` of the instance's
//! own lists its own processes and nobody else's.
//!
//! **Why this process does so little.** Pid 1 of a namespace is the one
//! whose end ends it — the kernel kills everything in it then — and the one
//! every orphan of the namespace is handed to. So it is small, single-
//! threaded and never `exec`s: it mounts the namespace's `/proc`, forks the
//! space, reaps, and ends the space when it is told to stop.
//!
//! **Its signals.** The kernel does not deliver to pid 1 of a namespace a
//! signal it has no handler for — TERM included, from outside too (only
//! KILL and STOP from an ancestor namespace are forced). The stop signals
//! and SIGCHLD are therefore BLOCKED before the fork, by its parent, and
//! the child starts with them blocked: a blocked signal is never ignored,
//! it waits, and this process takes it with `sigwaitinfo`. Nothing arrives
//! in a window of SIG_DFL, because there is none. A stop counts only from
//! outside the namespace (`si_pid` 0: the sender has no number here) — the
//! holder passing on systemd's TERM, or its own death (`PR_SET_PDEATHSIG`);
//! the instance's programs could not signal it anyway (another uid, and
//! their Landlock signal scope).
//!
//! **Its `/proc`.** Mounted by this process, a member of the namespace, in
//! its mount namespace (copied from the host's and made private first). The
//! kernel lets a user namespace mount a procfs only where the host's
//! `/proc` is fully visible (`mount_too_revealing`): a `/proc` with a part
//! of it covered by a mount of the host's refuses (EPERM), and the instance
//! does not come up — named, never quietly with the host's. The space is
//! forked after it, so every `/proc/self` and `/proc/<getpid()>` the space
//! builds is of one view (`crate::sys`, the pid view).

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::path::Path;

/// The signals an instance is stopped with.
pub const STOP_SIGNALS: [libc::c_int; 3] = [libc::SIGTERM, libc::SIGINT, libc::SIGHUP];

/// The lowest and the highest the namespace's first pid is drawn from
/// (below the smallest `pid_max`, 32768): a program's pid says nothing of
/// how many processes the instance has started.
const FIRST_PID_FROM: u32 = 300;
const FIRST_PID_SPAN: u32 = 30_000;

/// What pid 1 is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A stop signal; `outside`: from outside the namespace (`si_pid` 0).
    Stop { outside: bool },
    /// A child of pid 1 reaped.
    Reaped(libc::pid_t),
}

/// What pid 1 does about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Act {
    Nothing,
    /// Ask the space to end: TERM (and CONT, should it be stopped).
    EndSpace(libc::pid_t),
    /// End, with this code — and the namespace with it.
    Exit(u8),
}

/// Pid 1's whole state: the space it forked, and whether it was told to
/// stop. The space's end ends it — cleanly after a stop, as a failure
/// without one (a space that ended by itself holds no covers any more).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Init {
    space: libc::pid_t,
    stopping: bool,
}

impl Init {
    pub fn new(space: libc::pid_t) -> Self {
        Self {
            space,
            stopping: false,
        }
    }

    pub fn on(&mut self, event: Event) -> Act {
        match event {
            // From inside: nobody there may stop the instance.
            Event::Stop { outside: false } => Act::Nothing,
            Event::Stop { outside: true } if self.stopping => Act::Nothing,
            Event::Stop { outside: true } => {
                self.stopping = true;
                Act::EndSpace(self.space)
            }
            Event::Reaped(pid) if pid == self.space => Act::Exit(u8::from(!self.stopping)),
            // An orphan of a program, handed to pid 1 and reaped: nothing.
            Event::Reaped(_) => Act::Nothing,
        }
    }
}

/// The signals pid 1 takes with `sigwaitinfo`: [`STOP_SIGNALS`] and
/// SIGCHLD. Blocked by its parent before the fork ([`block`]).
pub fn waited_set() -> libc::sigset_t {
    // SAFETY: sigemptyset and sigaddset fill a sigset_t of our own.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for sig in STOP_SIGNALS {
            libc::sigaddset(&mut set, sig);
        }
        libc::sigaddset(&mut set, libc::SIGCHLD);
        set
    }
}

/// Block `set`; the mask as it was before.
pub fn block(set: &libc::sigset_t) -> io::Result<libc::sigset_t> {
    // SAFETY: sigprocmask with two sigset_t of our own.
    unsafe {
        let mut old: libc::sigset_t = std::mem::zeroed();
        if libc::sigprocmask(libc::SIG_BLOCK, set, &mut old) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(old)
    }
}

/// The signal mask set to `mask`.
pub fn set_mask(mask: &libc::sigset_t) {
    // SAFETY: sigprocmask with a sigset_t of our own and no old one asked.
    unsafe { libc::sigprocmask(libc::SIG_SETMASK, mask, std::ptr::null_mut()) };
}

/// The instance's network, mount and IPC namespaces; its mount tree
/// private, then a `/proc` of the pid namespace's own over the host's:
/// `nosuid`, `nodev`, `noexec`, as the host's is. (An IPC namespace too: an
/// X client's MIT-SHM segment of the host is one `shmat` away without one,
/// `zone_setup`.)
fn own_proc() -> Result<(), String> {
    // SAFETY: unshare(2) takes no pointers.
    if unsafe { libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWNS | libc::CLONE_NEWIPC) } != 0 {
        return Err(format!(
            "cannot create the net+mount+IPC namespace: {}",
            io::Error::last_os_error()
        ));
    }
    crate::sys::mount(
        OsStr::new("none"),
        Path::new("/"),
        "",
        libc::MS_REC | libc::MS_PRIVATE,
        "",
    )
    .map_err(|e| format!("cannot make the mount tree private: {e}"))?;
    crate::sys::mount(
        OsStr::new("proc"),
        Path::new("/proc"),
        "proc",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "",
    )
    .map_err(|e| {
        if e.raw_os_error() == Some(libc::EPERM) {
            format!(
                "cannot mount a /proc of its own ({e}): the kernel refuses one where the \
                 host's /proc is not fully visible (mount_too_revealing — a part of it is \
                 covered by a mount of the host's). Without it the instance would show its \
                 programs every process of the host: it does not come up"
            )
        } else {
            format!("cannot mount a /proc of its own: {e}")
        }
    })
}

/// The namespace's next pid drawn at random: a program's own number says
/// nothing of how many processes came before it. Best effort — a kernel
/// that refuses leaves them counted from 1, which says little.
fn random_first_pid(id: &str) {
    let mut bytes = [0u8; 4];
    if crate::bridge::random_bytes(&mut bytes).is_err() {
        return;
    }
    let first = FIRST_PID_FROM + u32::from_le_bytes(bytes) % FIRST_PID_SPAN;
    if let Err(e) = std::fs::write("/proc/sys/kernel/ns_last_pid", first.to_string()) {
        eprintln!("instance {id}: its pids are counted from 1 ({e})");
    }
}

/// Every descriptor from 3 up closed: the space is forked with nothing of
/// its parent's but its standard ones.
fn close_the_rest() {
    // SAFETY: close_range takes two numbers and flags; it closes only.
    unsafe { libc::close_range(3, libc::c_uint::MAX, 0) };
}

/// Pid 1 of instance `id`: its `/proc`, its first pid, the holder's word
/// (`go`: a byte once the holder has written down this process's host pid;
/// the end of the pipe without one — the holder gone — is an end here too),
/// then `space` forked and reaped, and every orphan with it. Returns the
/// code to end with; the namespace ends with this process.
///
/// Called in the holder's child, pid 1 of the pid namespace the holder
/// made, with [`waited_set`] blocked.
pub fn run(id: &str, go: OwnedFd, space: impl FnOnce() -> u8) -> u8 {
    // SAFETY: prctl with these arguments takes no pointers. Nothing of the
    // instance's may read this process; its parent's end is a stop.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0);
    }
    if let Err(e) = own_proc() {
        eprintln!("instance {id}: {e}");
        return 1;
    }
    random_first_pid(id);
    let mut byte = [0u8; 1];
    if File::from(go).read_exact(&mut byte).is_err() {
        eprintln!("instance {id}: its holder is gone before it said the instance's pid");
        return 1;
    }
    close_the_rest();
    let set = waited_set();
    // SAFETY: single-threaded, so the child may allocate before it goes on.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        eprintln!(
            "instance {id}: cannot fork its space: {}",
            io::Error::last_os_error()
        );
        return 1;
    }
    if pid == 0 {
        // The space's signals are an ordinary process's.
        // SAFETY: an empty sigset_t of our own.
        let empty = unsafe {
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut empty);
            empty
        };
        set_mask(&empty);
        let code = space();
        // SAFETY: _exit never returns and touches nothing of ours.
        unsafe { libc::_exit(libc::c_int::from(code)) };
    }
    let mut init = Init::new(pid);
    loop {
        // SAFETY: an all-zero siginfo_t is a valid one to be filled.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: a sigset_t and a siginfo_t of our own.
        let sig = unsafe { libc::sigwaitinfo(&set, &mut info) };
        if sig < 0 {
            continue;
        }
        let mut acts = Vec::new();
        if sig == libc::SIGCHLD {
            loop {
                let mut status: libc::c_int = 0;
                // SAFETY: `status` is a valid pointer for the duration of the call.
                let dead = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
                if dead <= 0 {
                    break;
                }
                acts.push(init.on(Event::Reaped(dead)));
            }
        } else {
            // SAFETY: the siginfo_t of a signal sent by kill(2) or the
            // kernel carries a sender's pid (0 from outside the namespace).
            let from = unsafe { info.si_pid() };
            acts.push(init.on(Event::Stop { outside: from == 0 }));
        }
        for act in acts {
            match act {
                Act::Nothing => {}
                Act::EndSpace(space) => {
                    // SAFETY: kill(2) of our own child, not reaped yet.
                    unsafe {
                        libc::kill(space, libc::SIGTERM);
                        libc::kill(space, libc::SIGCONT);
                    }
                }
                Act::Exit(code) => return code,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stop from outside ends the space, its end ends pid 1 cleanly;
    /// orphans reaped meanwhile change nothing.
    #[test]
    fn a_stop_from_outside_ends_the_space_then_pid_1() {
        let mut init = Init::new(7);
        assert_eq!(init.on(Event::Reaped(40)), Act::Nothing);
        assert_eq!(init.on(Event::Stop { outside: true }), Act::EndSpace(7));
        // Said again: once is enough.
        assert_eq!(init.on(Event::Stop { outside: true }), Act::Nothing);
        assert_eq!(init.on(Event::Reaped(41)), Act::Nothing);
        assert_eq!(init.on(Event::Reaped(7)), Act::Exit(0));
    }

    /// Nobody inside may stop the instance: a signal with a sender's number
    /// in the namespace is nothing.
    #[test]
    fn a_stop_from_inside_is_nothing() {
        let mut init = Init::new(7);
        for _ in 0..3 {
            assert_eq!(init.on(Event::Stop { outside: false }), Act::Nothing);
        }
        // Still not stopping: the space's end is a failure.
        assert_eq!(init.on(Event::Reaped(7)), Act::Exit(1));
    }

    /// The space ending by itself ends pid 1, as a failure: nothing holds
    /// the instance's covers any more.
    #[test]
    fn the_space_ending_by_itself_is_a_failure() {
        let mut init = Init::new(9);
        assert_eq!(init.on(Event::Reaped(10)), Act::Nothing);
        assert_eq!(init.on(Event::Reaped(9)), Act::Exit(1));
    }

    #[test]
    fn the_stop_signals_and_sigchld_are_waited_for() {
        let set = waited_set();
        for sig in STOP_SIGNALS.into_iter().chain([libc::SIGCHLD]) {
            // SAFETY: a sigset_t of our own.
            assert_eq!(unsafe { libc::sigismember(&set, sig) }, 1, "{sig}");
        }
        for sig in [libc::SIGKILL, libc::SIGSTOP, libc::SIGUSR1, libc::SIGQUIT] {
            // SAFETY: as above.
            assert_eq!(unsafe { libc::sigismember(&set, sig) }, 0, "{sig}");
        }
    }
}
