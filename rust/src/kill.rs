//! `vpn-zone kill <zone>`: cut a zone off, now.
//!
//! For the moment something in a zone must stop at once — a remote-access
//! session that should not go on, a program that turned out to be something
//! else. `vpn-zone down` is not that: it takes the network away, but the
//! programs started into the zone live on in their own cgroups, and a program
//! that is still running is a program that keeps whatever it already has.
//!
//! In three steps, in this order:
//!
//! 1. every process in the zone's network namespace is FROZEN (`SIGSTOP`,
//!    which cannot be caught), again and again until a pass finds nothing
//!    new — a fork between two passes is frozen by the next one;
//! 2. the zone goes down (`systemctl --user stop`), taking the tunnel, the
//!    uplink and pasta with it;
//! 3. the frozen processes are killed (`SIGKILL`), and so is anything that
//!    entered the namespace while the zone was going down — a launch that
//!    was already on its way in.
//!
//! Frozen first, so that nothing gets to act on the teardown it sees. The
//! zone's own processes — the holder, pasta, the proxies, the app namespace's
//! placeholder — are in the unit's cgroup and are left to `systemctl stop`: a
//! stopped holder would hold the stop up until systemd's timeout.
//!
//! Every signal goes through a pidfd opened while the process was verified to
//! be in the zone, so a pid that is reused in between is never signalled.

use std::ffi::OsString;
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use crate::cli::zone_pid;
use crate::tools::Tools;

/// Exit codes, a contract for the tools that put a button on this:
/// 0 — cut off: programs killed, zone down;
pub const EXIT_CUT: u8 = 0;
/// 1 — programs killed, but the zone could not be taken down;
pub const EXIT_NOT_DOWN: u8 = 1;
/// 2 — the zone is not up: nothing of it has a network any more;
pub const EXIT_NOT_UP: u8 = 2;
/// 3 — refused: not a zone of its own (`unconfined`, the host's namespace), a
/// namespace that cannot be read, a bad command line. Nothing was touched.
pub const EXIT_REFUSED: u8 = 3;

/// How many freezing passes before giving up on a zone that forks faster than
/// it is frozen.
const PASSES: usize = 20;

/// A process of the zone, held by a pidfd.
struct Target {
    pid: i32,
    name: String,
    fd: OwnedFd,
}

fn pidfd_open(pid: i32) -> Option<OwnedFd> {
    // SAFETY: pidfd_open(2) takes a pid and flags and returns a new descriptor
    // or -1; the descriptor is owned by nobody else.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

fn pidfd_signal(fd: &OwnedFd, signal: i32) -> bool {
    // SAFETY: a valid pidfd, a signal number, no siginfo, no flags.
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        ) == 0
    }
}

/// The cgroup of a process, from `/proc/<pid>/cgroup` (the v2 line).
pub fn cgroup_of(text: &str) -> Option<&str> {
    text.lines().find_map(|l| l.strip_prefix("0::"))
}

/// Is `cgroup` the unit's own cgroup or one below it?
pub fn inside(cgroup: &str, unit: &str) -> bool {
    cgroup == unit
        || cgroup
            .strip_prefix(unit)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The processes below `proc` whose network namespace is `netns` and whose
/// cgroup is not below `unit`, never one of `spare`.
fn scan(proc: &Path, netns: &Path, unit: Option<&str>, spare: &[i32]) -> Vec<(i32, PathBuf)> {
    let Ok(entries) = fs::read_dir(proc) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .filter(|pid| !spare.contains(pid))
        .filter_map(|pid| {
            let dir = proc.join(pid.to_string());
            (fs::read_link(dir.join("ns/net")).ok()? == netns).then_some((pid, dir))
        })
        .filter(|(_, dir)| {
            let own = fs::read_to_string(dir.join("cgroup")).ok();
            match (unit, own.as_deref().and_then(cgroup_of)) {
                (Some(unit), Some(cgroup)) => !inside(cgroup, unit),
                // A process whose cgroup cannot be read is not spared.
                _ => true,
            }
        })
        .collect()
}

/// Freeze everything in the zone, pass after pass, holding each by a pidfd.
/// What was frozen comes back even when the passes ran out — it is to be
/// killed all the same, not left stopped.
fn freeze(netns: &Path, unit: Option<&str>, spare: &[i32]) -> (Vec<Target>, Option<String>) {
    let proc = Path::new("/proc");
    let mut held: Vec<Target> = Vec::new();
    for _ in 0..PASSES {
        let mut fresh = 0;
        for (pid, dir) in scan(proc, netns, unit, spare) {
            if held.iter().any(|t| t.pid == pid) {
                continue;
            }
            let Some(fd) = pidfd_open(pid) else {
                continue;
            };
            // Checked again with the process held: the pid may have been
            // reused between the scan and the pidfd.
            if fs::read_link(dir.join("ns/net")).ok().as_deref() != Some(netns) {
                continue;
            }
            let name = fs::read_to_string(dir.join("comm"))
                .map(|c| c.trim().to_owned())
                .unwrap_or_default();
            if pidfd_signal(&fd, libc::SIGSTOP) {
                fresh += 1;
                held.push(Target { pid, name, fd });
            }
        }
        if fresh == 0 {
            return (held, None);
        }
    }
    let why = format!(
        "зона порождает процессы быстрее, чем их удаётся заморозить ({} заморожено)",
        held.len()
    );
    (held, Some(why))
}

/// `vpn-zone kill <zone>`.
pub fn run(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(name) = args.first().filter(|n| !n.is_empty()) else {
        eprintln!("vpn-zone kill <зона>");
        return EXIT_REFUSED;
    };
    let text = name.to_string_lossy();
    if crate::launch::is_unconfined_name(&text) {
        eprintln!(
            "у {} нет зоны: это сеть хоста, обрывать нечего — программы там обычные процессы хоста",
            crate::launch::UNCONFINED
        );
        return EXIT_REFUSED;
    }
    let Some(zone) = zone_pid(&tools.state, name) else {
        eprintln!("зона {text} не поднята: сети у её программ уже нет");
        return EXIT_NOT_UP;
    };
    let Ok(netns) = fs::read_link(format!("/proc/{zone}/ns/net")) else {
        eprintln!("не прочитать сетевой namespace зоны {text}");
        return EXIT_REFUSED;
    };
    // A zone whose namespace is the host's is no zone, and "every process in
    // it" would be every process of the session.
    if fs::read_link("/proc/self/ns/net").ok().as_deref() == Some(netns.as_path()) {
        eprintln!("у зоны {text} сеть хоста, а не своя — обрывать отказываюсь");
        return EXIT_REFUSED;
    }
    let unit = fs::read_to_string(format!("/proc/{zone}/cgroup"))
        .ok()
        .and_then(|t| cgroup_of(&t).map(str::to_owned));

    // The zone's placeholder is spared by name too: frozen, it would hold the
    // stop up even when its cgroup could not be read.
    let spare = [std::process::id() as i32, zone];
    let (frozen, overrun) = freeze(&netns, unit.as_deref(), &spare);
    if let Some(why) = overrun {
        // Down and kill anyway: what is frozen is killed, and the network is
        // gone for the rest.
        eprintln!("{why}");
    }
    let stopped = crate::cli::systemctl(tools, "stop", name);
    // The namespace outlives the zone while anything is in it: one more
    // round for whoever got in between the passes and the stop.
    let (late, _) = freeze(&netns, unit.as_deref(), &spare);
    let killed: Vec<&Target> = frozen
        .iter()
        .chain(
            late.iter()
                .filter(|l| !frozen.iter().any(|f| f.pid == l.pid)),
        )
        .filter(|t| pidfd_signal(&t.fd, libc::SIGKILL))
        .collect();
    let names: Vec<String> = killed
        .iter()
        .map(|t| format!("{} ({})", t.name, t.pid))
        .collect();
    if let Err(e) = crate::journal::append(
        &tools.state,
        "kill",
        &[
            ("zone", &*text),
            ("killed", killed.len().to_string().as_str()),
            ("programs", names.join(", ").as_str()),
            ("down", if stopped == 0 { "yes" } else { "no" }),
        ],
    ) {
        eprintln!("журнал: {e}");
    }
    if stopped != 0 {
        eprintln!("зону {text} не удалось опустить (systemctl: {stopped}) — её программы убиты");
    }
    if killed.is_empty() {
        println!("зона {text} оборвана: опущена, программ в ней не было");
    } else {
        println!(
            "зона {text} оборвана: опущена, убито программ — {}: {}",
            killed.len(),
            names.join(", ")
        );
    }
    if stopped == 0 {
        EXIT_CUT
    } else {
        EXIT_NOT_DOWN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unit_cgroup_and_below_are_spared_nothing_else() {
        let text =
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/vpn-zone@nl.service\n";
        let unit = cgroup_of(text).unwrap();
        assert!(inside(unit, unit));
        assert!(inside(&format!("{unit}/sub"), unit));
        assert!(!inside(
            "/user.slice/user-1000.slice/user@1000.service/app.slice/vpn-zone@nl.service-x",
            unit
        ));
        assert!(!inside(
            "/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox.scope",
            unit
        ));
        assert_eq!(cgroup_of("1:name=systemd:/x\n"), None);
    }

    #[test]
    fn a_scan_of_another_namespace_finds_nobody_here() {
        // The test runs in one namespace; nothing in /proc is in a made-up one.
        assert!(scan(Path::new("/proc"), Path::new("net:[1]"), None, &[]).is_empty());
    }
}
