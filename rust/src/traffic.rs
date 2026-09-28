//! What a container's instance sent and received through its zone — stage 1
//! of the network monitor (`docs/FIREWALL.md` §3, §9): the counters of the
//! frame relay, per instance, and `cellward traffic`.
//!
//! **Where it is counted.** Every frame of an instance passes the relay
//! (`crate::relay`), between its tap and its zone's passt; nothing of the
//! instance's reaches its zone another way. The relay counts each frame's
//! bytes (the Ethernet frame, as passt takes it) and the frames, out (from
//! the instance) and in.
//!
//! **Where it is kept.** A file of the instance's directory, [`FILE`], of a
//! fixed layout ([`LEN`] bytes, little-endian): [`MAGIC`], then the out
//! bytes and frames, the in bytes and frames, and when the counting began
//! (Unix seconds) — all `u64`. The instance's keeper makes it anew as the
//! instance comes up and hands each relay a descriptor of it
//! (`frame-relay --tally-fd`); the relay maps it before it seals itself and
//! adds to it with atomic operations on the shared mapping, so that counting
//! takes no system call — its seccomp filter allows none it does not need.
//! A reader maps it too and reads the same cells atomically: a count is
//! never seen half written. The counts are the instance's life, across its
//! attaches and switches: what it did in each network is the monitor's next
//! stage (the history of `docs/FIREWALL.md` §7).
//!
//! No count, no harm: an instance whose file cannot be made or mapped has
//! its way out all the same, and no counts (said once, by its keeper). The
//! counts are a record, not a wall.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::status::string;
use crate::tools::Tools;

/// The counters' file in an instance's directory.
pub const FILE: &str = "traffic";
/// Its first eight bytes: which layout it has.
pub const MAGIC: [u8; 8] = *b"cwtally1";
/// Its length: the magic, five counts, and room.
pub const LEN: usize = 64;

/// The cells after the magic, each a `u64`.
const OUT_BYTES: usize = 1;
const OUT_FRAMES: usize = 2;
const IN_BYTES: usize = 3;
const IN_FRAMES: usize = 4;
const SINCE: usize = 5;

/// What an instance sent and received, and since when.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub out_bytes: u64,
    pub out_frames: u64,
    pub in_bytes: u64,
    pub in_frames: u64,
    /// Unix seconds.
    pub since: u64,
}

/// Make the counters' file of an instance anew in `dir`: zero counts, the
/// counting beginning now. Readable by the user, written by the relay.
pub fn create(dir: &Path) -> io::Result<File> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir.join(FILE))?;
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut bytes = [0u8; LEN];
    bytes[..8].copy_from_slice(&MAGIC);
    bytes[SINCE * 8..SINCE * 8 + 8].copy_from_slice(&since.to_le_bytes());
    file.write_all(&bytes)?;
    file.flush()?;
    Ok(file)
}

/// A counters' file mapped: its cells, shared with every other mapping of
/// it. Not unmapped by dropping it — the relay, which may make no system
/// call it was not let, keeps its mapping to its end; a reader lets it go
/// with [`Tally::close`].
pub struct Tally {
    base: NonNull<u8>,
}

// SAFETY: the mapping is only ever touched through atomic operations on its
// cells, which any thread may do.
unsafe impl Send for Tally {}
// SAFETY: as above.
unsafe impl Sync for Tally {}

impl Tally {
    /// Map the counters' file open at `fd`, to add to it (`write`) or to
    /// read it. A file of another layout, or shorter, is refused.
    pub fn map(fd: BorrowedFd<'_>, write: bool) -> io::Result<Tally> {
        let prot = if write {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };
        // SAFETY: a new mapping of LEN bytes of a descriptor of ours; the
        // kernel checks the rest.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                LEN,
                prot,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let base =
            NonNull::new(ptr.cast::<u8>()).ok_or_else(|| io::Error::other("null mapping"))?;
        let tally = Tally { base };
        // A file shorter than the mapping faults on its first touch past
        // the end: its length is looked at first.
        // SAFETY: an all-zero stat is a valid one to fill.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid descriptor and a stat to fill.
        let short = unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0
            || usize::try_from(st.st_size).ok().is_none_or(|len| len < LEN);
        // SAFETY: the mapping's first 8 bytes, inside it, read as bytes.
        let magic = !short && unsafe { std::slice::from_raw_parts(base.as_ptr(), 8) } == MAGIC;
        if !magic {
            tally.close();
            return Err(io::Error::other("not a counters' file of this layout"));
        }
        Ok(tally)
    }

    fn cell(&self, i: usize) -> &AtomicU64 {
        debug_assert!(i > 0 && i * 8 + 8 <= LEN);
        // SAFETY: an 8-aligned cell inside the mapping (mmap is page
        // aligned), alive as long as `self`, touched only atomically.
        unsafe { &*self.base.as_ptr().add(i * 8).cast::<AtomicU64>() }
    }

    /// A frame of `bytes` out of the instance.
    pub fn outbound(&self, bytes: usize) {
        self.cell(OUT_BYTES)
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.cell(OUT_FRAMES).fetch_add(1, Ordering::Relaxed);
    }

    /// A frame of `bytes` into the instance.
    pub fn inbound(&self, bytes: usize) {
        self.cell(IN_BYTES)
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.cell(IN_FRAMES).fetch_add(1, Ordering::Relaxed);
    }

    /// The counts as they are now.
    pub fn counts(&self) -> Counts {
        Counts {
            out_bytes: self.cell(OUT_BYTES).load(Ordering::Relaxed),
            out_frames: self.cell(OUT_FRAMES).load(Ordering::Relaxed),
            in_bytes: self.cell(IN_BYTES).load(Ordering::Relaxed),
            in_frames: self.cell(IN_FRAMES).load(Ordering::Relaxed),
            since: self.cell(SINCE).load(Ordering::Relaxed),
        }
    }

    /// Let the mapping go.
    pub fn close(self) {
        // SAFETY: our own mapping of LEN bytes, not touched after this.
        unsafe { libc::munmap(self.base.as_ptr().cast(), LEN) };
    }
}

/// The counts in the counters' file of the instance directory `dir`, if it
/// has one of this layout.
pub fn read(dir: &Path) -> Option<Counts> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir.join(FILE))
        .ok()?;
    let tally = Tally::map(file.as_fd(), false).ok()?;
    let counts = tally.counts();
    tally.close();
    Some(counts)
}

// --- HISTORY ----------------------------------------------------------------

/// Below the state directory (out of every zone's reach, as the rest of
/// it): the history of what the containers sent and received
/// (`docs/FIREWALL.md` §7).
pub const NETLOG: &str = "netlog";
/// One file a day in it, `<YYYY-MM-DD>` by the local calendar: a line per
/// container and network — `<container>\t<network>\t<out>\t<in>`, bytes.
const DAYS: &str = "days";
/// The counts seen at the last record, a line per instance:
/// `<id>\t<since>\t<out>\t<in>`.
const LAST: &str = "last";
/// How many days of summaries are kept (the owner, 2026-09-28: a year).
pub const KEEP_DAYS: u64 = 365;

/// What an instance did since the counts `last` of the same counting
/// (`since`): its counts less them — all of them, the counting begun anew
/// (the instance came up again) or never seen before.
pub fn delta(last: Option<(u64, u64, u64)>, now: Counts) -> (u64, u64) {
    match last {
        Some((since, out, inb)) if since == now.since => (
            now.out_bytes.saturating_sub(out),
            now.in_bytes.saturating_sub(inb),
        ),
        _ => (now.out_bytes, now.in_bytes),
    }
}

/// The local calendar's date of Unix time `secs`, `YYYY-MM-DD`.
pub fn local_date(secs: u64) -> String {
    let t = libc::time_t::try_from(secs).unwrap_or(0);
    // SAFETY: an all-zero tm is a valid one to fill.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: valid pointers to a time and a tm of ours.
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return "1970-01-01".to_owned();
    }
    format!(
        "{:04}-{:02}-{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday
    )
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Lines of tab-separated fields, each with `n` of them; others skipped.
fn lines_of(text: &str, n: usize) -> Vec<Vec<&str>> {
    text.lines()
        .map(|l| l.split('\t').collect::<Vec<&str>>())
        .filter(|f| f.len() == n)
        .collect()
}

/// A day's summary: `(container, network) → (out, in)`.
type Day = std::collections::BTreeMap<(String, String), (u64, u64)>;

fn read_day(path: &Path) -> Day {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut day = Day::new();
    for f in lines_of(&text, 4) {
        if let (Ok(out), Ok(inb)) = (f[2].parse::<u64>(), f[3].parse::<u64>()) {
            let e = day.entry((f[0].to_owned(), f[1].to_owned())).or_default();
            e.0 = e.0.saturating_add(out);
            e.1 = e.1.saturating_add(inb);
        }
    }
    day
}

fn write_atomically(path: &Path, text: &str) -> io::Result<()> {
    let tmp = path.with_extension("new");
    std::fs::write(&tmp, text).and_then(|()| std::fs::rename(&tmp, path))
}

/// Add what the running instances did since the last record to today's
/// summary (`state/netlog/days/<today>`), by container and network — the
/// network each runs in now —, and drop the days older than [`KEEP_DAYS`].
/// Run with the tunnel watch, every minute (`crate::watch`): an instance
/// that ends between two records takes its last minute with it.
pub fn record(tools: &Tools) -> io::Result<()> {
    let rows = rows(tools);
    record_rows(&tools.state, &rows, now_secs())
}

fn record_rows(state: &Path, rows: &[Row], now: u64) -> io::Result<()> {
    let base = state.join(NETLOG);
    let days = base.join(DAYS);
    std::fs::create_dir_all(&days)?;
    let last_text = std::fs::read_to_string(base.join(LAST)).unwrap_or_default();
    let last: std::collections::HashMap<&str, (u64, u64, u64)> = lines_of(&last_text, 4)
        .into_iter()
        .filter_map(|f| {
            Some((
                f[0],
                (f[1].parse().ok()?, f[2].parse().ok()?, f[3].parse().ok()?),
            ))
        })
        .collect();
    let today = days.join(local_date(now));
    let mut day = read_day(&today);
    let mut seen = String::new();
    for r in rows {
        let Some(c) = r.counts else { continue };
        let (out, inb) = delta(last.get(r.id.as_str()).copied(), c);
        if out > 0 || inb > 0 {
            let who = r.container.clone().unwrap_or_else(|| r.id.clone());
            let e = day.entry((who, r.network.clone())).or_default();
            e.0 = e.0.saturating_add(out);
            e.1 = e.1.saturating_add(inb);
        }
        seen.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            r.id, c.since, c.out_bytes, c.in_bytes
        ));
    }
    let text: String = day
        .iter()
        .map(|((who, net), (out, inb))| format!("{who}\t{net}\t{out}\t{inb}\n"))
        .collect();
    write_atomically(&today, &text)?;
    write_atomically(&base.join(LAST), &seen)?;
    // The summaries past their keep.
    let oldest = local_date(now.saturating_sub(KEEP_DAYS * 86_400));
    for entry in std::fs::read_dir(&days)?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.len() == 10 && name.as_str() < oldest.as_str() {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    Ok(())
}

/// What each container sent and received in each network over the last
/// `n` days, today included, from the summaries.
fn over_days(state: &Path, n: u64, now: u64) -> (String, Day) {
    let days = state.join(NETLOG).join(DAYS);
    let from = local_date(now.saturating_sub(n.saturating_sub(1) * 86_400));
    let mut total = Day::new();
    for entry in std::fs::read_dir(&days).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.len() != 10 || name.as_str() < from.as_str() {
            continue;
        }
        for (k, (out, inb)) in read_day(&entry.path()) {
            let e = total.entry(k).or_default();
            e.0 = e.0.saturating_add(out);
            e.1 = e.1.saturating_add(inb);
        }
    }
    (from, total)
}

fn days_json(n: u64, from: &str, total: &Day) -> String {
    let items: Vec<String> = total
        .iter()
        .map(|((who, net), (out, inb))| {
            format!(
                "{{\"container\":{},\"network\":{},\"out_bytes\":{out},\"in_bytes\":{inb}}}",
                string(who),
                string(net)
            )
        })
        .collect();
    format!(
        "{{\"schema_version\":{},\"days\":{n},\"from\":{},\"containers\":[{}]}}",
        crate::status::SCHEMA_VERSION,
        string(from),
        items.join(",")
    )
}

fn days_text(n: u64, from: &str, total: &Day) -> String {
    if total.is_empty() {
        return format!("с {from} ({n} дн.) ничего не записано\n");
    }
    let mut out = format!("с {from} ({n} дн.):\n");
    for ((who, net), (o, i)) in total {
        out.push_str(&format!(
            "{who} · {net}: ↑ {} · ↓ {}\n",
            bytes_text(*o),
            bytes_text(*i)
        ));
    }
    out
}

/// One running instance's line of `cellward traffic`.
struct Row {
    id: String,
    container: Option<String>,
    network: String,
    counts: Option<Counts>,
}

fn rows(tools: &Tools) -> Vec<Row> {
    let mut rows: Vec<Row> = crate::instance::running(&tools.state)
        .into_iter()
        .map(|i| Row {
            container: crate::instance::container_of(&i.id).map(str::to_owned),
            counts: read(&i.dir),
            network: i.network,
            id: i.id,
        })
        .collect();
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    rows
}

/// A count of bytes for a person.
pub fn bytes_text(n: u64) -> String {
    const UNITS: [&str; 5] = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn counts_json(counts: Option<Counts>) -> String {
    match counts {
        Some(c) => format!(
            "{{\"out_bytes\":{},\"out_frames\":{},\"in_bytes\":{},\"in_frames\":{},\"since\":{}}}",
            c.out_bytes, c.out_frames, c.in_bytes, c.in_frames, c.since
        ),
        None => "null".to_owned(),
    }
}

/// `status --json`'s `instances[].traffic` of the instance in `dir`: its
/// counts, `null` without them (an instance of an earlier build, or one
/// whose file could not be made).
pub fn status_json(dir: &Path) -> String {
    counts_json(read(dir))
}

fn json(rows: &[Row]) -> String {
    let items: Vec<String> = rows
        .iter()
        .map(|r| {
            format!(
                "{{\"id\":{},\"container\":{},\"network\":{},\"traffic\":{}}}",
                string(&r.id),
                r.container.as_deref().map_or("null".to_owned(), string),
                string(&r.network),
                counts_json(r.counts)
            )
        })
        .collect();
    format!(
        "{{\"schema_version\":{},\"instances\":[{}]}}",
        crate::status::SCHEMA_VERSION,
        items.join(",")
    )
}

fn text(rows: &[Row]) -> String {
    if rows.is_empty() {
        return "ни один экземпляр контейнера не работает\n".to_owned();
    }
    let mut out = String::new();
    for r in rows {
        let who = r.container.as_deref().unwrap_or(r.id.as_str());
        let counts = match r.counts {
            Some(c) => format!(
                "↑ {} · ↓ {}",
                bytes_text(c.out_bytes),
                bytes_text(c.in_bytes)
            ),
            None => "не считается (экземпляр прошлой сборки)".to_owned(),
        };
        out.push_str(&format!("{who} · {}: {counts}\n", r.network));
    }
    out
}

const USAGE: &str = "cellward traffic [--json] [--watch]\n\
                     cellward traffic --days <N> [--json]\n\
                     cellward traffic --record";

/// `cellward traffic [--json] [--watch]`: what each running instance sent
/// and received since it came up; with `--watch`, again every second — a
/// look at it, which decides nothing — until stopped.
pub fn run(tools: &Tools, args: &[OsString]) -> u8 {
    let mut json_out = false;
    let mut watch = false;
    let mut days: Option<u64> = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.to_str() {
            Some("--json") => json_out = true,
            Some("--watch") => watch = true,
            Some("--record") => {
                return match record(tools) {
                    Ok(()) => 0,
                    Err(e) => {
                        eprintln!("cellward traffic: не записать итоги ({e})");
                        1
                    }
                }
            }
            Some("--days") => {
                match rest
                    .next()
                    .and_then(|v| v.to_str())
                    .and_then(|v| v.parse::<u64>().ok())
                    .filter(|n| (1..=KEEP_DAYS).contains(n))
                {
                    Some(n) => days = Some(n),
                    None => {
                        eprintln!("--days: от 1 до {KEEP_DAYS}");
                        return 1;
                    }
                }
            }
            _ => {
                eprintln!("{USAGE}");
                return 1;
            }
        }
    }
    if let Some(n) = days {
        let (from, total) = over_days(&tools.state, n, now_secs());
        if json_out {
            println!("{}", days_json(n, &from, &total));
        } else {
            print!("{}", days_text(n, &from, &total));
        }
        return 0;
    }
    loop {
        let rows = rows(tools);
        let out = if json_out {
            format!("{}\n", json(&rows))
        } else {
            text(&rows)
        };
        let mut stdout = io::stdout().lock();
        if stdout
            .write_all(out.as_bytes())
            .and_then(|()| stdout.flush())
            .is_err()
        {
            return 0;
        }
        drop(stdout);
        if !watch {
            return 0;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
        if !json_out {
            println!();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("vz-traffic-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Made anew, counted into through one mapping, read through another —
    /// as the relay and a reader do.
    #[test]
    fn counts_go_from_the_relays_mapping_to_a_readers() {
        let d = dir("counts");
        let file = create(&d).unwrap();
        let before = read(&d).unwrap();
        assert_eq!((before.out_bytes, before.in_frames), (0, 0));
        assert!(before.since > 0);
        let tally = Tally::map(file.as_fd(), true).unwrap();
        tally.outbound(1500);
        tally.outbound(60);
        tally.inbound(9000);
        let now = read(&d).unwrap();
        assert_eq!(
            now,
            Counts {
                out_bytes: 1560,
                out_frames: 2,
                in_bytes: 9000,
                in_frames: 1,
                since: before.since,
            }
        );
        tally.close();
        // Made anew: counting from zero again.
        drop(file);
        let _file = create(&d).unwrap();
        assert_eq!(read(&d).unwrap().out_bytes, 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A file of another layout, or a short one, is no counters' file.
    #[test]
    fn a_file_of_another_layout_is_refused() {
        let d = dir("layout");
        std::fs::write(d.join(FILE), [0u8; LEN]).unwrap();
        assert!(read(&d).is_none());
        std::fs::write(d.join(FILE), MAGIC).unwrap();
        assert!(read(&d).is_none());
        assert!(read(&d.join("nowhere")).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Recorded twice a minute apart: the second adds only what was done
    /// since; an instance come up again counts from its new start; days
    /// past the keep go; `--days` sums the days it covers.
    #[test]
    fn a_record_adds_what_was_done_since_the_last() {
        let state = dir("record");
        let row = |id: &str, net: &str, since: u64, out: u64, inb: u64| Row {
            id: id.to_owned(),
            container: Some(id.to_owned()),
            network: net.to_owned(),
            counts: Some(Counts {
                out_bytes: out,
                in_bytes: inb,
                since,
                ..Counts::default()
            }),
        };
        let noon = 1_790_000_000; // a day in 2026
        let today = local_date(noon);
        record_rows(&state, &[row("work", "nl", 100, 1000, 5000)], noon).unwrap();
        record_rows(&state, &[row("work", "nl", 100, 1500, 9000)], noon + 60).unwrap();
        let day = read_day(&state.join(NETLOG).join(DAYS).join(&today));
        assert_eq!(day.get(&("work".into(), "nl".into())), Some(&(1500, 9000)));
        // Came up again: its counts from zero, all of them new.
        record_rows(&state, &[row("work", "de", 200, 300, 400)], noon + 120).unwrap();
        let day = read_day(&state.join(NETLOG).join(DAYS).join(&today));
        assert_eq!(day.get(&("work".into(), "de".into())), Some(&(300, 400)));
        assert_eq!(day.get(&("work".into(), "nl".into())), Some(&(1500, 9000)));
        // An old day goes; a recent one stays and is summed.
        let days = state.join(NETLOG).join(DAYS);
        std::fs::write(days.join("2000-01-01"), "work\tnl\t1\t1\n").unwrap();
        let yesterday = local_date(noon - 86_400);
        std::fs::write(days.join(&yesterday), "work\tnl\t7\t3\n").unwrap();
        record_rows(&state, &[], noon + 180).unwrap();
        assert!(!days.join("2000-01-01").exists());
        let (from, total) = over_days(&state, 2, noon);
        assert_eq!(from, yesterday);
        assert_eq!(
            total.get(&("work".into(), "nl".into())),
            Some(&(1507, 9003))
        );
        let (_, one) = over_days(&state, 1, noon);
        assert_eq!(one.get(&("work".into(), "nl".into())), Some(&(1500, 9000)));
        assert!(days_json(2, &from, &total).contains(
            "{\"container\":\"work\",\"network\":\"nl\",\"out_bytes\":1507,\"in_bytes\":9003}"
        ));
        crate::json::parse(&days_json(2, &from, &total)).unwrap();
        assert_eq!(
            delta(
                Some((5, 10, 10)),
                Counts {
                    since: 5,
                    out_bytes: 4,
                    in_bytes: 20,
                    ..Counts::default()
                }
            ),
            (0, 10)
        );
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn bytes_are_said_in_their_unit() {
        assert_eq!(bytes_text(0), "0 Б");
        assert_eq!(bytes_text(1023), "1023 Б");
        assert_eq!(bytes_text(1536), "1.5 КБ");
        assert_eq!(bytes_text(5 * 1024 * 1024), "5.0 МБ");
    }
}
