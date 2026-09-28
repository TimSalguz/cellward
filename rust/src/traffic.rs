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

const USAGE: &str = "cellward traffic [--json] [--watch]";

/// `cellward traffic [--json] [--watch]`: what each running instance sent
/// and received since it came up; with `--watch`, again every second — a
/// look at it, which decides nothing — until stopped.
pub fn run(tools: &Tools, args: &[OsString]) -> u8 {
    let mut json_out = false;
    let mut watch = false;
    for arg in args {
        match arg.to_str() {
            Some("--json") => json_out = true,
            Some("--watch") => watch = true,
            _ => {
                eprintln!("{USAGE}");
                return 1;
            }
        }
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

    #[test]
    fn bytes_are_said_in_their_unit() {
        assert_eq!(bytes_text(0), "0 Б");
        assert_eq!(bytes_text(1023), "1023 Б");
        assert_eq!(bytes_text(1536), "1.5 КБ");
        assert_eq!(bytes_text(5 * 1024 * 1024), "5.0 МБ");
    }
}
