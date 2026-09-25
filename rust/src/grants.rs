//! Granted directories with a term, and taking a grant away from programs that
//! are already running (`docs/CONTAINERS.md` §3.5).
//!
//! `vpn-zone container grant sb:<name> <dir> --for 2h` writes the end of the
//! term next to the path. From that moment on a grant whose term is over is
//! simply not there for any launch — `container::load` skips it — so nothing
//! has to happen on time for a NEW launch to be refused it.
//!
//! A program that was started while the grant was in force has the directory
//! bound into its mount namespace, and that bind does not care about a line in
//! a file. So the term is also enforced where it matters: a transient user
//! timer runs `vpn-zone container expire` when the term ends, and a revoke does
//! the same at once — the bind is detached (`umount2(MNT_DETACH)`) inside every
//! mount namespace of the sandbox's running programs, entered with `setns` as
//! the owner of their user namespaces. What survives a detach is only what was
//! already open: a file descriptor, a working directory inside. For a hard end
//! there is `vpn-zone kill`.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{self, File};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::tools::Tools;

/// The longest term: a grant for longer than this is a permanent grant and
/// should say so.
const MAX_TERM: u64 = 366 * 86_400;

/// How long a refused permission is not asked about again
/// (`vpn-zone ask-again`): a setting file below the config directory, and
/// below `declared/` from Nix (`askAgainAfter`), which wins.
pub const ASK_AGAIN_SETTING: &str = "ask-again";
/// The pause when nothing sets it: three minutes.
pub const ASK_AGAIN_DEFAULT: u64 = 180;
/// The shortest pause: longer than one question waits for its answer
/// (`microphone::TIMEOUT`) — a shorter one would let a program that
/// reconnects after every "no" keep a dialog up all the time, waiting for a
/// stray Enter.
pub const ASK_AGAIN_MIN: u64 = 30;
/// The longest: a day. Longer is "no", and the zone's switch says that.
pub const ASK_AGAIN_MAX: u64 = 86_400;

/// A pause as `vpn-zone ask-again` takes it: a term within the bounds.
pub fn ask_again_term(text: &str) -> Option<u64> {
    parse_term(text.trim()).filter(|secs| (ASK_AGAIN_MIN..=ASK_AGAIN_MAX).contains(secs))
}

/// The pause after a refusal, and where it comes from: Nix, the local
/// setting, or the default. A file that does not hold a pause within the
/// bounds is passed over — never read as no pause.
pub fn ask_again(config: &Path) -> (u64, crate::container::Source) {
    use crate::container::Source;
    let declared = config
        .join(crate::cli::DECLARED_DIR)
        .join(ASK_AGAIN_SETTING);
    for (path, source) in [
        (declared, Source::Nix),
        (config.join(ASK_AGAIN_SETTING), Source::Local),
    ] {
        if let Some(secs) = fs::read_to_string(&path)
            .ok()
            .and_then(|t| ask_again_term(&t))
        {
            return (secs, source);
        }
    }
    (ASK_AGAIN_DEFAULT, Source::Default)
}

/// Seconds as the shortest term that says them: 180 → `3m`, 90 → `90s`.
pub fn term_text(secs: u64) -> String {
    match secs {
        0 => "0s".to_owned(),
        s if s % 86_400 == 0 => format!("{}d", s / 86_400),
        s if s % 3_600 == 0 => format!("{}h", s / 3_600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

/// `30s`, `15m`, `2h`, `7d` in seconds.
pub fn parse_term(text: &str) -> Option<u64> {
    let unit = match text.chars().last()? {
        's' => 1,
        'm' => 60,
        'h' => 3_600,
        'd' => 86_400,
        _ => return None,
    };
    let number: u64 = text[..text.len() - 1].parse().ok()?;
    let secs = number.checked_mul(unit)?;
    (secs > 0 && secs <= MAX_TERM).then_some(secs)
}

/// Run `vpn-zone container expire` when `secs` have passed. `false` when no
/// timer could be set: the grant still ends for every new launch, only the
/// programs already running keep it until the next expire or revoke.
pub fn schedule_expiry(tools: &Tools, secs: u64) -> bool {
    Command::new(&tools.systemd_run)
        .arg("--user")
        .arg("--collect")
        .arg("--quiet")
        .arg(format!("--on-active={}s", secs + 1))
        .arg("--timer-property=AccuracySec=1s")
        .arg("--")
        .arg(&tools.runner)
        .args(["container", "expire"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The parent pid from the text of `/proc/<pid>/stat`.
pub fn ppid_of(stat: &str) -> Option<i32> {
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// A mount point field of `/proc/<pid>/mountinfo`, octal escapes undone.
pub fn unescape(field: &str) -> Vec<u8> {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = bytes
            .get(i + 1..i + 4)
            .filter(|d| d.iter().all(|b| (b'0'..=b'7').contains(b)));
        match (bytes[i], octal) {
            (b'\\', Some(d)) => {
                let value = d.iter().fold(0u32, |acc, b| acc * 8 + u32::from(b - b'0'));
                out.push(value as u8);
                i += 4;
            }
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

/// Is `dest` a mount point in this mountinfo?
pub fn mounted_at(mountinfo: &str, dest: &Path) -> bool {
    let wanted = dest.as_os_str().as_bytes();
    mountinfo
        .lines()
        .filter_map(|l| l.split(' ').nth(4))
        .any(|point| unescape(point) == wanted)
}

/// The live pids of a sandbox's programs and all their descendants.
fn sandbox_processes(tools: &Tools, selector: &str) -> BTreeSet<i32> {
    let mut roots: Vec<i32> = Vec::new();
    let running = tools.state.join(".running");
    for dir in crate::registry::dirs(&running) {
        for (_, record) in
            crate::registry::live_records(&dir, &|pid| crate::registry::alive(&running, pid))
        {
            if record.selector == selector {
                roots.push(record.pid);
            }
        }
    }
    let mut children: BTreeMap<i32, Vec<i32>> = BTreeMap::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<i32>().ok())
            else {
                continue;
            };
            if let Some(ppid) = fs::read_to_string(entry.path().join("stat"))
                .ok()
                .as_deref()
                .and_then(ppid_of)
            {
                children.entry(ppid).or_default().push(pid);
            }
        }
    }
    let mut seen = BTreeSet::new();
    while let Some(pid) = roots.pop() {
        if seen.insert(pid) {
            roots.extend(children.get(&pid).into_iter().flatten().copied());
        }
    }
    seen
}

/// `NS_GET_USERNS` from `<linux/nsfs.h>`: the user namespace that owns a
/// namespace, as a new descriptor.
const NS_GET_USERNS: u64 = 0xb701;

/// Detach `dest` inside the mount namespace of `pid`, from a forked child that
/// enters the user namespace OWNING that mount namespace, then the mount
/// namespace itself.
///
/// The owner, not the process's own user namespace: bwrap sets its mounts up
/// in a first user namespace and then moves the program into a second one,
/// nested, to map the sandbox's uid. Capabilities in the nested one say
/// nothing about the mounts, and `setns` into the mount namespace is refused.
fn detach_in(pid: i32, dest: &Path) -> Result<(), String> {
    let mnt = File::open(format!("/proc/{pid}/ns/mnt")).map_err(|e| e.to_string())?;
    // SAFETY: an ioctl on a namespace descriptor we own; it returns a new
    // descriptor or -1.
    let owner_fd = unsafe { libc::ioctl(mnt.as_raw_fd(), NS_GET_USERNS as _) };
    if owner_fd < 0 {
        return Err(format!(
            "не узнать владельца mount namespace: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: the descriptor was just returned to us and is owned by nobody else.
    let owner = unsafe { File::from_raw_fd(owner_fd) };
    let same_user = fs::read_link("/proc/self/ns/user").ok()
        == fs::read_link(format!("/proc/self/fd/{owner_fd}")).ok();
    let target = CString::new(dest.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    // SAFETY: fork in a process that is single-threaded here; the child only
    // makes async-signal-safe system calls on descriptors and a C string that
    // were prepared before the fork, and leaves with _exit.
    match unsafe { libc::fork() } {
        -1 => Err(std::io::Error::last_os_error().to_string()),
        0 => unsafe {
            if !same_user && libc::setns(owner.as_raw_fd(), libc::CLONE_NEWUSER) != 0 {
                libc::_exit(2);
            }
            if libc::setns(mnt.as_raw_fd(), libc::CLONE_NEWNS) != 0 {
                libc::_exit(3);
            }
            // Until nothing is mounted there any more: a bind can sit on top
            // of another bind of the same directory.
            let mut detached = 0;
            while detached < 16 && libc::umount2(target.as_ptr(), libc::MNT_DETACH) == 0 {
                detached += 1;
            }
            libc::_exit(if detached > 0 { 0 } else { 4 })
        },
        child => {
            let mut status = 0;
            // SAFETY: waiting for our own child with a valid status pointer.
            unsafe { libc::waitpid(child, &mut status, 0) };
            match libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status)) {
                Some(0) => Ok(()),
                Some(2) => Err("не войти в user namespace-владелец".to_owned()),
                Some(3) => Err("не войти в mount namespace программы".to_owned()),
                Some(4) => Err("отмонтировать не вышло".to_owned()),
                _ => Err("помощник завершился аварийно".to_owned()),
            }
        }
    }
}

/// Take `dest` away from every running program of the sandbox `selector`:
/// `(detached, failed)` — mount namespaces, not processes.
pub fn detach_live(tools: &Tools, selector: &str, dest: &Path) -> (usize, Vec<String>) {
    let mut namespaces: BTreeMap<PathBuf, i32> = BTreeMap::new();
    for pid in sandbox_processes(tools, selector) {
        let Ok(ns) = fs::read_link(format!("/proc/{pid}/ns/mnt")) else {
            continue;
        };
        if namespaces.contains_key(&ns) {
            continue;
        }
        let mounted = fs::read_to_string(format!("/proc/{pid}/mountinfo"))
            .is_ok_and(|info| mounted_at(&info, dest));
        if mounted {
            namespaces.insert(ns, pid);
        }
    }
    let mut detached = 0;
    let mut failed = Vec::new();
    for (_, pid) in namespaces {
        match detach_in(pid, dest) {
            Ok(()) => detached += 1,
            Err(why) => failed.push(format!("pid {pid}: {why}")),
        }
    }
    (detached, failed)
}

/// `vpn-zone container expire`: end every grant whose term is over, for the
/// programs already running too.
pub fn expire(tools: &Tools) -> u8 {
    let taken = crate::container::expire_grants(tools);
    let mut code = 0;
    for (selector, path) in &taken {
        let (detached, failed) = detach_live(tools, selector, path);
        let shown = path.to_string_lossy();
        if let Err(e) = crate::journal::append(
            &tools.state,
            "grant-expired",
            &[
                ("container", selector.as_str()),
                ("path", &*shown),
                ("detached", detached.to_string().as_str()),
                ("failed", failed.join("; ").as_str()),
            ],
        ) {
            eprintln!("журнал: {e}");
        }
        let mut text = format!("срок доступа {selector} к {shown} истёк");
        if detached > 0 {
            text.push_str(&format!(
                ", у запущенных программ каталог отмонтирован ({detached})"
            ));
        }
        if !failed.is_empty() {
            code = 1;
            text.push_str(&format!(
                "; у части запущенных программ отмонтировать не удалось ({}) — \
                 завершите их или оборвите зону: vpn-zone kill",
                failed.join("; ")
            ));
        }
        println!("{text}");
        crate::dialog::notify(
            &tools.notify_send,
            None,
            "10000",
            "Доступ к каталогу истёк",
            &text,
        );
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_term_is_a_number_and_a_unit() {
        assert_eq!(parse_term("30s"), Some(30));
        assert_eq!(parse_term("15m"), Some(900));
        assert_eq!(parse_term("2h"), Some(7_200));
        assert_eq!(parse_term("7d"), Some(604_800));
        for bad in [
            "",
            "h",
            "0h",
            "2",
            "2w",
            "-1h",
            "1.5h",
            "367d",
            "99999999999999999999d",
        ] {
            assert_eq!(parse_term(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_parent_is_read_past_a_name_with_brackets() {
        assert_eq!(ppid_of("42 (a) b) S 7 42 42 0"), Some(7));
        assert_eq!(ppid_of("garbage"), None);
    }

    #[test]
    fn a_mount_point_with_a_space_is_found() {
        let info = "36 35 0:31 / /home/u/My\\040Games rw,relatime - ext4 /dev/x rw\n\
                    37 35 0:32 / /mnt/games rw - ext4 /dev/y rw\n";
        assert!(mounted_at(info, Path::new("/home/u/My Games")));
        assert!(mounted_at(info, Path::new("/mnt/games")));
        assert!(!mounted_at(info, Path::new("/mnt")));
    }
}
