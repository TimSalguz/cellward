//! The launch registry: which program runs in which network, right now.
//!
//! One directory per container (`__main__` for "no container"), one file per
//! program, one line per launch:
//!
//! ```text
//! ~/.local/state/vpn-zones/.running/<container>/<program>
//!   1234 nl sb:work
//!   ^pid ^zone ^selector
//! ```
//!
//! Four readers depend on that shape, so it is a contract and not an internal
//! detail: `vpn-zone run` (is this program already running in ANOTHER network?),
//! the picker (a click on a running program means "raise the window", so it must
//! be started into the same network and the same container), `vpn-zone gc`
//! (dead records, abandoned throwaway containers) and `vpn-zone-core
//! profile-run` (is the last tenant of a throwaway container gone?).
//!
//! **The pid is the launcher's own.** It survives the `execvp` at the end of
//! `vpn-zone run` — the process becomes the program and keeps its pid — so the
//! record stays true for as long as the program lives, and dead ones are swept
//! lazily by the next launch. (`docs/GOTCHAS.md` §5)
//!
//! **The third field is what was CHOSEN**, not what was mounted: `sb:<name>` for
//! a named sandbox, `__fs__` for a throwaway one, the container name otherwise,
//! empty for the plain main profile. Without it a second click on a running
//! program brought it back "bare": the network was read from the registry while
//! the sandbox was lost, because a sandboxed launch has no container and always
//! lands in `__main__`. (`docs/GOTCHAS.md` §5)
//!
//! **Every rewrite is under `flock`.** Two launches of one program used to do
//! read → rewrite → rename with no lock and lose each other's records, and `gc`
//! could erase the record of a program that had just started. The lock is a
//! separate `.lock` file in the container's directory, exactly where the bash
//! version's `9>>"$regdir/.lock"` put it — an old and a new `vpn-zone` running
//! side by side during a home-manager switch still exclude each other.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

/// Name of the lock file inside a container's registry directory. Hidden on
/// purpose: the shell globs that walk the registry (`*/*`) skip dot-files, and
/// so does everything here.
pub const LOCK: &str = ".lock";

/// A subdirectory of every container's registry directory: the same records,
/// filed under the program's BINARY name rather than the launcher's id.
///
/// Answers one question only — "is this binary already running in another
/// network?" — because two launcher entries for one single-instance program
/// (a Steam game and Steam, firefox and its private-window entry) have
/// different ids and used to be invisible to each other. A dot-directory on
/// purpose: every walk of the registry skips dot-names, so none of the four
/// readers mistakes it for a program. `vpn-zone gc` sweeps it too.
pub const BY_BINARY: &str = ".by-binary";

/// The container key of "no container at all". A real profile name can never
/// collide with it: `profile create` refuses `/`, spaces and a leading dot or
/// dash, and nobody would name a container `__main__` by accident.
pub const MAIN: &str = "__main__";

/// One line of a registry file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub pid: i32,
    /// Zone the program was started into. `unconfined` and `offline` are zones here
    /// like any other.
    pub zone: String,
    /// What was chosen: `sb:<name>`, `__fs__`, a container name, or empty.
    pub selector: String,
}

/// Parse one line the way `read -r pid zone selector` did.
///
/// Fields are split on runs of whitespace and the selector takes the whole
/// remainder — which is what the third variable in that `read` was for. With
/// only two variables the selector used to be glued onto the zone name, so
/// "same zone, but sandboxed" looked like a different network and the launch
/// asked "already running in another network?" for no reason at all.
/// (`docs/GOTCHAS.md` §5)
///
/// A line whose first field is not a decimal pid is skipped, as `[ -d /proc/$p ]`
/// skipped it before: blank lines, and anything a crash left half-written.
pub fn parse_record(line: &str) -> Option<Record> {
    let mut fields = line.split_whitespace();
    let pid: i32 = fields.next()?.parse().ok()?;
    // Records written before the rename say `direct`.
    let zone = crate::launch::network_name(fields.next().unwrap_or_default()).to_owned();
    let selector = fields.collect::<Vec<_>>().join(" ");
    Some(Record {
        pid,
        zone,
        selector,
    })
}

/// A held `flock`, released when it goes out of scope.
///
/// The lock lives on a descriptor, so closing the file is what unlocks it —
/// which is exactly what the shell's `9>>file` subshell did on exit.
#[derive(Debug)]
pub struct Lock(File);

impl Drop for Lock {
    fn drop(&mut self) {
        // SAFETY: the descriptor is owned by `self.0` and still open.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Take the exclusive lock of one container's registry directory.
///
/// Blocking, like `flock 9` without `-n`: the critical sections are a couple of
/// file reads, and a launch that waited a millisecond is better than one that
/// silently skipped the bookkeeping.
pub fn lock(dir: &Path) -> io::Result<Lock> {
    fs::create_dir_all(dir)?;
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(LOCK))?;
    // SAFETY: a valid open descriptor; LOCK_EX blocks until the lock is ours.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Lock(file))
}

/// Drop the dead records of one program and report where a LIVE one is running
/// somewhere other than `zone`.
///
/// Caller holds [`lock`] for the directory. The file is rewritten through a
/// temporary and renamed, so a reader without the lock — the picker — sees
/// either the old file or the new one, never half of one.
///
/// Returns the zone of the last live record that names a different zone, which
/// is what the "already running in another network" warning is about. Several
/// such records mean the program is open in several networks at once; the last
/// one wins, as it did in the shell loop.
pub fn rewrite_live<F>(reg: &Path, zone: &str, is_alive: F) -> io::Result<Option<String>>
where
    F: Fn(i32) -> bool,
{
    let text = match fs::read_to_string(reg) {
        Ok(text) => text,
        // No file means nobody has ever launched this program: not an error,
        // and nothing to clean.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };

    let mut kept = String::new();
    let mut busy = None;
    for line in text.lines() {
        let Some(record) = parse_record(line) else {
            continue;
        };
        if !is_alive(record.pid) {
            continue;
        }
        // Reassembled with single spaces, exactly as the shell's `printf '%s %s
        // %s\n'` did — including the trailing space of a record with no
        // selector.
        kept.push_str(&format!(
            "{} {} {}\n",
            record.pid, record.zone, record.selector
        ));
        if record.zone != zone {
            busy = Some(record.zone);
        }
    }

    let tmp = tmp_path(reg);
    fs::write(&tmp, kept)?;
    fs::rename(&tmp, reg)?;
    Ok(busy)
}

/// Add our own record. Caller holds [`lock`].
pub fn append(reg: &Path, pid: i32, zone: &str, selector: &str) -> io::Result<()> {
    if let Some(dir) = reg.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(reg)?;
    writeln!(file, "{pid} {zone} {selector}")
}

/// Below the registry: when each launch started, `.started/<pid>` holding the
/// start time of the process ([`crate::sys::start_time`]).
///
/// **A pid alone does not name a process for long.** The registry is on disk
/// and outlives a reboot, and records are only swept by the next launch of the
/// same program: after a reboot every pid in it is soon somebody else's, and in
/// a long session the numbers come round too. A record whose pid now belongs to
/// another process says a program runs when it does not — and the picker
/// starts a click on a "running" program into its network WITHOUT asking,
/// `unconfined` included. The start time tells the launch from its successor.
///
/// A side file rather than a fourth field: the record's shape is a contract
/// (the selector takes the rest of the line), and a `vpn-zone` from before
/// this, still running during a home-manager switch, reads records it can
/// parse. A dot-directory: no walk of the registry takes it for a container.
pub const STARTED: &str = ".started";

/// Note when the launch `pid` started — ours, just before the record. Swept on
/// the way: what is left of launches that are over.
pub fn note_start(running: &Path, pid: i32) -> io::Result<()> {
    let dir = running.join(STARTED);
    fs::create_dir_all(&dir)?;
    sweep_started(running);
    let start = crate::sys::start_time(pid)
        .ok_or_else(|| io::Error::other(format!("no start time of pid {pid}")))?;
    // Through a temporary: a reader never sees half a number.
    let tmp = dir.join(format!(".{pid}.tmp"));
    fs::write(&tmp, format!("{start}\n"))?;
    fs::rename(&tmp, dir.join(pid.to_string()))
}

/// Drop the start times of launches that are over. How many went.
pub fn sweep_started(running: &Path) -> usize {
    let mut swept = 0;
    for entry in fs::read_dir(running.join(STARTED))
        .into_iter()
        .flatten()
        .flatten()
    {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<i32>().ok())
        else {
            continue;
        };
        if !launched(running, pid) && fs::remove_file(entry.path()).is_ok() {
            swept += 1;
        }
    }
    swept
}

fn recorded_start(running: &Path, pid: i32) -> Option<u64> {
    fs::read_to_string(running.join(STARTED).join(pid.to_string()))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Is the process `pid` the launch recorded under that pid — its start time on
/// record and the same? For what a record makes happen WITHOUT a question: the
/// picker's "already running, start it there", the zone of a window. A record
/// from before start times were kept is not trusted with that.
pub fn launched(running: &Path, pid: i32) -> bool {
    recorded_start(running, pid).is_some_and(|start| crate::sys::start_time(pid) == Some(start))
}

/// May the launch recorded under `pid` still be running? The same as
/// [`launched`], except that a record from before start times were kept counts
/// by its pid alone, as it always did. For the decisions that are the safe
/// ones when a program is taken for running: a container refused a second
/// network, a throwaway container kept, a record not swept.
pub fn alive(running: &Path, pid: i32) -> bool {
    match recorded_start(running, pid) {
        Some(start) => crate::sys::start_time(pid) == Some(start),
        None => crate::profile::proc_is_alive(pid),
    }
}

/// Where is this container open? The zone of the first live record found.
///
/// Used by `vpn-zone profile list` and by the picker's idea of "busy". A live
/// record with an empty zone does not count as an answer — the shell's
/// `[ -n "$where" ]` moved on to the next file, and a container shown as busy in
/// no network would be worse than one shown as free.
pub fn live_zone<F>(dir: &Path, is_alive: &F) -> Option<String>
where
    F: Fn(i32) -> bool,
{
    for file in files(dir) {
        let Ok(text) = fs::read_to_string(&file) else {
            continue;
        };
        if let Some(record) = text
            .lines()
            .filter_map(parse_record)
            .find(|r| is_alive(r.pid))
        {
            if !record.zone.is_empty() {
                return Some(record.zone);
            }
        }
    }
    None
}

/// Where does anything launched with this selector run? The zone of the first
/// live record, in any program's file of one registry directory, whose third
/// field is `selector`.
///
/// A named sandbox has no data container of its own, so its launches are filed
/// under `__main__` together with everything else, and only the selector tells
/// them apart. (`docs/CONTAINERS.md` I2)
pub fn live_zone_of_selector<F>(dir: &Path, selector: &str, is_alive: &F) -> Option<String>
where
    F: Fn(i32) -> bool,
{
    files(dir).iter().find_map(|file| {
        fs::read_to_string(file)
            .ok()?
            .lines()
            .filter_map(parse_record)
            .find(|r| r.selector == selector && !r.zone.is_empty() && is_alive(r.pid))
            .map(|r| r.zone)
    })
}

/// Every live record of one registry directory, with the program each belongs
/// to (the file name). What `vpn-zone status --json` lists as "running".
pub fn live_records<F>(dir: &Path, is_alive: &F) -> Vec<(String, Record)>
where
    F: Fn(i32) -> bool,
{
    let mut out = Vec::new();
    for file in files(dir) {
        let Some(app) = file.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        let Ok(text) = fs::read_to_string(&file) else {
            continue;
        };
        for record in text.lines().filter_map(parse_record) {
            if is_alive(record.pid) {
                out.push((app.clone(), record));
            }
        }
    }
    out
}

/// Is anything at all still running in this container?
///
/// Unlike [`live_zone`] this does not care which zone the record names: `gc`
/// asks it before taking a throwaway container's directory away.
pub fn any_live<F>(dir: &Path, is_alive: &F) -> bool
where
    F: Fn(i32) -> bool,
{
    files(dir).iter().any(|file| {
        fs::read_to_string(file)
            .map(|text| {
                text.lines()
                    .filter_map(parse_record)
                    .any(|r| is_alive(r.pid))
            })
            .unwrap_or(false)
    })
}

/// Remove the registry files that have no live record left, and say how many
/// went. Each file under the lock of its own directory.
///
/// This is the second half of `vpn-zone gc`. Nothing here kills anything: a file
/// with one live record is left alone even if every other record in it is dead —
/// those are swept by the next launch of that program, which rewrites the file
/// anyway.
pub fn sweep_dead<F>(running: &Path, is_alive: &F) -> usize
where
    F: Fn(i32) -> bool,
{
    let mut cleaned = 0;
    for dir in dirs(running) {
        let Ok(_guard) = lock(&dir) else {
            continue;
        };
        for file in files(&dir).into_iter().chain(files(&dir.join(BY_BINARY))) {
            let Ok(text) = fs::read_to_string(&file) else {
                continue;
            };
            if text
                .lines()
                .filter_map(parse_record)
                .any(|r| is_alive(r.pid))
            {
                continue;
            }
            if fs::remove_file(&file).is_ok() {
                cleaned += 1;
            }
        }
    }
    cleaned
}

/// Regular files of a registry directory, dot-files skipped, in name order —
/// the set and the order of the shell glob `"$dir"/*`.
fn files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.as_encoded_bytes().starts_with(b".") {
            continue;
        }
        if entry.path().is_file() {
            out.push(entry.path());
        }
    }
    out.sort();
    out
}

/// Container directories of the registry, same rules.
pub fn dirs(running: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(running) else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.as_encoded_bytes().starts_with(b".") {
            continue;
        }
        if entry.path().is_dir() {
            out.push(entry.path());
        }
    }
    out.sort();
    out
}

/// `<file>.new`, the name the shell version rewrote through. Appended to the
/// whole file name rather than replacing an extension: a program called
/// `org.kde.dolphin` must not become `org.kde.new`.
fn tmp_path(reg: &Path) -> PathBuf {
    let mut name = OsString::from(reg.as_os_str());
    name.push(".new");
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// A registry directory under the system temporary directory, removed on
    /// drop. Named by test so that a parallel run cannot collide.
    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "vpn-zone-registry-test-{}-{tag}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn file(&self, name: &str, body: &str) -> PathBuf {
            let path = self.0.join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&path, body).unwrap();
            path
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn alive(pids: &[i32]) -> impl Fn(i32) -> bool + '_ {
        let set: HashSet<i32> = pids.iter().copied().collect();
        move |pid| set.contains(&pid)
    }

    #[test]
    fn a_record_keeps_its_three_fields_apart() {
        assert_eq!(
            parse_record("1234 nl sb:work"),
            Some(Record {
                pid: 1234,
                zone: "nl".into(),
                selector: "sb:work".into()
            })
        );
        // No selector: the zone must not swallow anything.
        assert_eq!(
            parse_record("7 nl"),
            Some(Record {
                pid: 7,
                zone: "nl".into(),
                selector: String::new()
            })
        );
        // Extra whitespace is a separator, as it was for `read`.
        assert_eq!(
            parse_record("  7   nl   __fs__  ").unwrap().selector,
            "__fs__"
        );
        for junk in ["", "   ", "not-a-pid nl", "1x2 nl", "-", "nl 7"] {
            assert!(parse_record(junk).is_none(), "«{junk}» приняли за запись");
        }
    }

    #[test]
    fn rewriting_keeps_the_living_and_reports_another_network() {
        let dir = Dir::new("rewrite");
        let reg = dir.file("firefox", "1 nl\n2 de sb:work\n3 nl prof\n4 bad\n");
        let busy = rewrite_live(&reg, "nl", alive(&[2, 3])).unwrap();
        assert_eq!(busy.as_deref(), Some("de"));
        // The dead ones are gone and the shape is the shell's, trailing space
        // and all.
        assert_eq!(
            fs::read_to_string(&reg).unwrap(),
            "2 de sb:work\n3 nl prof\n"
        );
        // Nothing left alive in another zone — no warning.
        assert_eq!(rewrite_live(&reg, "nl", alive(&[3])).unwrap(), None);
        assert_eq!(fs::read_to_string(&reg).unwrap(), "3 nl prof\n");
        // Everything dead: an empty file, not a missing one.
        assert_eq!(rewrite_live(&reg, "nl", alive(&[])).unwrap(), None);
        assert_eq!(fs::read_to_string(&reg).unwrap(), "");
        // And no file at all is simply "nobody has run this yet".
        assert_eq!(
            rewrite_live(&dir.0.join("never-run"), "nl", alive(&[1])).unwrap(),
            None
        );
    }

    #[test]
    fn the_last_live_stranger_wins() {
        let dir = Dir::new("last");
        let reg = dir.file("firefox", "1 de\n2 fr\n");
        assert_eq!(
            rewrite_live(&reg, "nl", alive(&[1, 2])).unwrap().as_deref(),
            Some("fr")
        );
    }

    #[test]
    fn our_own_record_is_appended_under_the_same_shape() {
        let dir = Dir::new("append");
        let reg = dir.0.join("firefox");
        append(&reg, 42, "nl", "sb:work").unwrap();
        append(&reg, 43, "nl", "").unwrap();
        assert_eq!(fs::read_to_string(&reg).unwrap(), "42 nl sb:work\n43 nl \n");
        // …and it parses back to what was written.
        let records: Vec<_> = fs::read_to_string(&reg)
            .unwrap()
            .lines()
            .filter_map(parse_record)
            .collect();
        assert_eq!(records[0].selector, "sb:work");
        assert_eq!(records[1].selector, "");
    }

    #[test]
    fn the_lock_is_a_dot_file_and_is_never_taken_for_a_record() {
        let dir = Dir::new("lock");
        {
            let _guard = lock(&dir.0).unwrap();
            assert!(dir.0.join(LOCK).is_file());
        }
        dir.file("firefox", "1 nl\n");
        assert!(any_live(&dir.0, &alive(&[1])));
        // The lock file is not a record file, whatever ends up inside it.
        assert_eq!(files(&dir.0).len(), 1);
    }

    #[test]
    fn a_container_is_busy_where_its_first_live_record_says() {
        let dir = Dir::new("busy");
        dir.file("aaa", "1 de\n");
        dir.file("bbb", "2 nl\n");
        assert_eq!(live_zone(&dir.0, &alive(&[1, 2])).as_deref(), Some("de"));
        assert_eq!(live_zone(&dir.0, &alive(&[2])).as_deref(), Some("nl"));
        assert_eq!(live_zone(&dir.0, &alive(&[])), None);
        assert!(!any_live(&dir.0, &alive(&[])));
        assert!(any_live(&dir.0, &alive(&[2])));
    }

    #[test]
    fn a_sandbox_is_found_by_its_selector_among_everything_else() {
        let dir = Dir::new("selector");
        dir.file("firefox", "1 nl sb:work\n2 de \n");
        dir.file("telegram", "3 fr sb:other\n");
        assert_eq!(
            live_zone_of_selector(&dir.0, "sb:work", &alive(&[1, 2, 3])).as_deref(),
            Some("nl")
        );
        assert_eq!(
            live_zone_of_selector(&dir.0, "sb:work", &alive(&[2, 3])),
            None
        );
        assert_eq!(
            live_zone_of_selector(&dir.0, "sb:other", &alive(&[3])).as_deref(),
            Some("fr")
        );
    }

    #[test]
    fn gc_removes_only_the_files_where_nobody_is_left() {
        let dir = Dir::new("sweep");
        let running = dir.0.join("running");
        fs::create_dir_all(running.join("__main__")).unwrap();
        fs::create_dir_all(running.join("work")).unwrap();
        fs::write(running.join("__main__/firefox"), "1 nl\n").unwrap();
        fs::write(running.join("__main__/telegram"), "2 nl\n3 nl\n").unwrap();
        fs::write(running.join("work/chromium"), "4 de\n").unwrap();
        // A dot-directory is not a container and a dot-file is not a record.
        fs::create_dir_all(running.join(".hidden")).unwrap();
        fs::write(running.join(".hidden/x"), "5 nl\n").unwrap();

        assert_eq!(sweep_dead(&running, &alive(&[2])), 2);
        assert!(!running.join("__main__/firefox").exists());
        assert!(running.join("__main__/telegram").exists());
        assert!(!running.join("work/chromium").exists());
        assert!(running.join(".hidden/x").exists());
        // Nothing left to do the second time round.
        assert_eq!(sweep_dead(&running, &alive(&[2])), 0);
    }

    #[test]
    fn the_binary_index_is_swept_and_never_read_as_a_program() {
        let dir = Dir::new("by-binary");
        let running = dir.0.join("running");
        let main = running.join("__main__");
        fs::create_dir_all(main.join(BY_BINARY)).unwrap();
        fs::write(main.join("PEAK"), "1 nl\n").unwrap();
        fs::write(main.join(BY_BINARY).join("steam"), "1 nl\n").unwrap();
        fs::write(main.join(BY_BINARY).join("firefox"), "2 de\n").unwrap();

        // Not a program of the container: the walks skip the dot-directory.
        assert_eq!(files(&main), vec![main.join("PEAK")]);
        assert_eq!(live_zone(&main, &alive(&[1, 2])).as_deref(), Some("nl"));

        // gc takes the dead records from the index as well.
        assert_eq!(sweep_dead(&running, &alive(&[1])), 1);
        assert!(main.join(BY_BINARY).join("steam").exists());
        assert!(!main.join(BY_BINARY).join("firefox").exists());
    }

    #[test]
    fn the_temporary_file_does_not_eat_a_dotted_program_name() {
        assert_eq!(
            tmp_path(Path::new("/r/.running/__main__/org.kde.dolphin")),
            PathBuf::from("/r/.running/__main__/org.kde.dolphin.new")
        );
    }

    /// A pid with its start time names one process; without the note a
    /// record counts by its pid only where that is the safe side.
    #[test]
    fn a_launch_is_known_by_its_start_time_and_not_by_its_number() {
        let dir = Dir::new("started");
        let running = dir.0.join(".running");
        let me = std::process::id() as i32;
        // No note: not certainly a launch, but maybe alive.
        assert!(!launched(&running, me));
        assert!(super::alive(&running, me));
        note_start(&running, me).unwrap();
        assert!(launched(&running, me));
        assert!(super::alive(&running, me));
        // A note of another start: the number went to somebody else.
        fs::write(running.join(STARTED).join(me.to_string()), "1\n").unwrap();
        assert!(!launched(&running, me));
        assert!(!super::alive(&running, me));
        // Swept as a launch that is over; a new note replaces it.
        assert_eq!(sweep_started(&running), 1);
        note_start(&running, me).unwrap();
        assert!(launched(&running, me));
        // The note is not a container.
        assert!(dirs(&running).is_empty());
    }
}
