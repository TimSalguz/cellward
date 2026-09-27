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
//!
//! **A container's instance** (`crate::instance`, stage 1 of the container
//! design of 2026-09-27) — `cellward kill <container>`, `cellward container
//! kill <container>`, and `cellward kill offline` for every instance with
//! no network: its programs are the processes of its user namespace
//! (`crate::place::members`), frozen pass after pass and killed; then the
//! instance is stopped, and finds nobody left to end. `cellward container
//! stop` only stops it: its keeper ends its programs with TERM, as a logout
//! does ([`instances`]).

use std::ffi::OsString;
use std::fs;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use crate::cli::zone_pid;
use crate::sys::{pidfd_open, pidfd_signal};
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
        eprintln!("cellward kill <зона>");
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
        // No zone of that name up: a container's instances, or — `offline`
        // — every instance with no network.
        if !instances_named(&tools.state, &text).is_empty() {
            return instances(tools, &text, true);
        }
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

/// The running instances `name` names: the instance of that id, a
/// container's (its own, and one per network of a container of the main
/// home), or — a network's name — every instance in that network: `offline`
/// every one with no network, a zone's every one it carries (stage 2).
pub fn instances_named(state: &Path, name: &str) -> Vec<crate::instance::Running> {
    crate::instance::running(state)
        .into_iter()
        .filter(|i| {
            i.id == name || crate::instance::container_of(&i.id) == Some(name) || i.network == name
        })
        .collect()
}

/// Freeze every program of the instance whose user namespace is `userns`
/// but its own (`spare`, its keeper, and below: its space, its relay), pass
/// after pass, as [`freeze`] does a zone's.
fn freeze_members(userns: (u64, u64), spare: i32) -> (Vec<Target>, Option<String>) {
    let mut held: Vec<Target> = Vec::new();
    for _ in 0..PASSES {
        let mut fresh = 0;
        for (pid, fd) in crate::place::members(userns, Some(spare)) {
            if held.iter().any(|t| t.pid == pid) {
                continue;
            }
            let name = fs::read_to_string(format!("/proc/{pid}/comm"))
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
        "контейнер порождает процессы быстрее, чем их удаётся заморозить ({} заморожено)",
        held.len()
    );
    (held, Some(why))
}

/// `cellward container stop|kill <name>` (and `cellward kill <name>` for
/// one that is no zone up): the instances `name` names
/// ([`instances_named`]) stopped — with `kill`, their programs frozen and
/// killed first, all at once, rather than asked to end.
pub fn instances(tools: &Tools, name: &str, kill: bool) -> u8 {
    let found = instances_named(&tools.state, name);
    if found.is_empty() {
        eprintln!("у «{name}» нет запущенного экземпляра контейнера — останавливать нечего");
        return EXIT_NOT_UP;
    }
    let mut killed: Vec<Target> = Vec::new();
    let mut all_stopped = true;
    for instance in &found {
        if kill {
            // Its user namespace, looked at while its space is still the
            // process that wrote its number; its keeper spared, and what it
            // started — the space's holder, the relay (stage 2) — with it.
            let key = crate::place::ns_key(Path::new(&format!("/proc/{}/ns/user", instance.pid)));
            let keeper = crate::sys::parent_of(instance.pid)
                .filter(|&h| h > 1)
                .and_then(crate::sys::parent_of)
                .filter(|&k| k > 1);
            let still = crate::instance::up(&tools.state, &instance.id) == Some(instance.pid);
            if let (Some(key), Some(keeper), true) = (key, keeper, still) {
                let (frozen, overrun) = freeze_members(key, keeper);
                if let Some(why) = overrun {
                    eprintln!("{why}");
                }
                killed.extend(
                    frozen
                        .into_iter()
                        .filter(|t| pidfd_signal(&t.fd, libc::SIGKILL)),
                );
            }
        }
        let unit = crate::instance::unit_name(&instance.id).unwrap_or_default();
        if crate::cli::systemctl_unit(tools, "stop", std::ffi::OsStr::new(&unit)) != 0 {
            all_stopped = false;
            eprintln!(
                "контейнер {}: не остановлен (systemctl stop {unit})",
                instance.id
            );
        }
    }
    let ids: Vec<&str> = found.iter().map(|i| i.id.as_str()).collect();
    let names: Vec<String> = killed
        .iter()
        .map(|t| format!("{} ({})", t.name, t.pid))
        .collect();
    // A stop is on the record by the keeper's own `instance-stop`.
    if kill {
        if let Err(e) = crate::journal::append(
            &tools.state,
            "kill",
            &[
                ("container", name),
                ("instances", ids.join(", ").as_str()),
                ("killed", killed.len().to_string().as_str()),
                ("programs", names.join(", ").as_str()),
                ("down", if all_stopped { "yes" } else { "no" }),
            ],
        ) {
            eprintln!("журнал: {e}");
        }
    }
    match (kill, killed.is_empty()) {
        (true, false) => println!(
            "{name}: остановлен, убито программ — {}: {}",
            killed.len(),
            names.join(", ")
        ),
        (true, true) => println!("{name}: остановлен, программ в нём не было"),
        (false, _) => println!("{name}: остановлен, его программы закрыты"),
    }
    if all_stopped {
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
