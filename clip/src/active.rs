//! The active segment: an append-only log of what happened since the last
//! seal, mirrored in memory (its postings, dedup hashes, events,
//! tombstones) so it is searched like a sealed segment.
//!
//! The file: `b"CWCL"`, u32 version 1, then frames — u32 payload length,
//! u32 CRC-32 of the payload, the payload, whose first byte says what it is:
//!
//! * `1` an entry: varint count of its terms, the terms (u64 each — keyed
//!   hashes, the same the sealed index holds, so opening the log rebuilds
//!   its postings without the key), then its blob (`record`);
//! * `2` an event: u8 kind (copied, pasted), u64 id, i64 unix ms — a copy
//!   again of what is already there, a paste of it: an entry is never
//!   rewritten;
//! * `3` a tombstone: u64 id.
//!
//! A crash may leave a frame half written. Opening reads frames until the
//! first that is short or fails its checksum and cuts the file there: what
//! was cut was never acknowledged as written when `sync` is on (each append
//! is `fdatasync`ed before it returns).

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::codec::{put_i64, put_u32, put_u64, put_varint, Reader};
use super::Error;

const MAGIC: &[u8; 4] = b"CWCL";
const VERSION: u32 = 1;
const HEADER: u64 = 8;
/// No frame is longer: an entry's cap, its terms (a few per byte of text
/// at most) and the AEAD's overhead fit well under it.
const MAX_FRAME: u32 = 1 << 30;

const R_ENTRY: u8 = 1;
const R_EVENT: u8 = 2;
const R_DELETE: u8 = 3;

/// Event kinds, in the log and in a sealed segment's events.
pub(super) const COPIED: u8 = 1;
pub(super) const PASTED: u8 = 2;

pub(super) struct Active {
    pub number: u64,
    pub path: PathBuf,
    file: File,
    /// Bytes of good frames: where the next one is written.
    pub len: u64,
    /// The entries' ids, ascending, and where each one's blob is.
    pub ids: Vec<u64>,
    pub locs: Vec<(u64, u64)>,
    pub postings: HashMap<u64, Vec<u64>>,
    pub dedup: HashMap<u64, Vec<u64>>,
    /// (id, unix ms, kind), in the order they came.
    pub events: Vec<(u64, i64, u8)>,
    pub tombstones: HashSet<u64>,
    pub records: usize,
}

impl Active {
    /// A new empty log (the name must not exist).
    pub fn create(path: &Path, number: u64) -> io::Result<Active> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let mut h = Vec::with_capacity(8);
        h.extend_from_slice(MAGIC);
        put_u32(&mut h, VERSION);
        file.write_all_at(&h, 0)?;
        file.sync_all()?;
        Ok(Active::empty(path, number, file))
    }

    fn empty(path: &Path, number: u64, file: File) -> Active {
        Active {
            number,
            path: path.to_owned(),
            file,
            len: HEADER,
            ids: Vec::new(),
            locs: Vec::new(),
            postings: HashMap::new(),
            dedup: HashMap::new(),
            events: Vec::new(),
            tombstones: HashSet::new(),
            records: 0,
        }
    }

    /// The log at `path`, its torn tail (if any) cut off.
    pub fn open(path: &Path, number: u64) -> Result<Active, Error> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        if data.len() < HEADER as usize || &data[..4] != MAGIC {
            return Err(Error::Corrupt(format!(
                "{}: не журнал истории",
                path.display()
            )));
        }
        if u32::from_le_bytes(data[4..8].try_into().expect("4 bytes")) != VERSION {
            return Err(Error::Corrupt(format!("{}: другая версия", path.display())));
        }
        let mut a = Active::empty(path, number, file);
        let mut at = HEADER as usize;
        while let Some((payload, next)) = frame(&data, at) {
            if a.apply(payload, (at + 8) as u64).is_none() {
                break;
            }
            at = next;
        }
        a.len = at as u64;
        if (at as u64) < data.len() as u64 {
            a.file.set_len(a.len)?;
            a.file.sync_all()?;
        }
        Ok(a)
    }

    /// Mirror one record in memory; `None` if it does not parse (and is
    /// treated as the torn tail).
    fn apply(&mut self, payload: &[u8], payload_at: u64) -> Option<()> {
        let mut r = Reader::new(payload);
        match r.u8()? {
            R_ENTRY => {
                let n = usize::try_from(r.varint()?).ok()?;
                let mut terms = Vec::with_capacity(n.min(1 << 16));
                for _ in 0..n {
                    terms.push(r.u64()?);
                }
                let blob = &payload[r.at..];
                let b = super::record::parse(blob)?;
                if self.ids.last().is_some_and(|&last| last >= b.id) {
                    return None;
                }
                self.ids.push(b.id);
                self.locs
                    .push((payload_at + r.at as u64, blob.len() as u64));
                for t in terms {
                    self.postings.entry(t).or_default().push(b.id);
                }
                self.dedup.entry(b.dedup).or_default().push(b.id);
                self.events.push((b.id, b.copied_at, COPIED));
            }
            R_EVENT => {
                let kind = r.u8()?;
                let id = r.u64()?;
                let t = r.i64()?;
                if kind != COPIED && kind != PASTED {
                    return None;
                }
                self.events.push((id, t, kind));
            }
            R_DELETE => {
                self.tombstones.insert(r.u64()?);
            }
            _ => return None,
        }
        self.records += 1;
        Some(())
    }

    fn write(&mut self, payload: &[u8], sync: bool) -> io::Result<u64> {
        let mut f = Vec::with_capacity(8 + payload.len());
        put_u32(&mut f, payload.len() as u32);
        put_u32(&mut f, crc32fast::hash(payload));
        f.extend_from_slice(payload);
        if let Err(e) = self.file.write_all_at(&f, self.len) {
            // Whatever part of it got there is a torn tail: cut it now.
            let _ = self.file.set_len(self.len);
            return Err(e);
        }
        if sync {
            self.file.sync_data()?;
        }
        let at = self.len + 8;
        self.len += f.len() as u64;
        Ok(at)
    }

    pub fn append_entry(&mut self, terms: &[u64], blob: &[u8], sync: bool) -> Result<(), Error> {
        if blob.len() + terms.len() * 8 + 16 > MAX_FRAME as usize {
            return Err(Error::TooLarge(blob.len()));
        }
        let mut p = Vec::with_capacity(16 + terms.len() * 8 + blob.len());
        p.push(R_ENTRY);
        put_varint(&mut p, terms.len() as u64);
        for &t in terms {
            put_u64(&mut p, t);
        }
        let blob_off = p.len() as u64;
        p.extend_from_slice(blob);
        let at = self.write(&p, sync)?;
        // The blob was made by us: it parses.
        if self.apply(&p, at).is_none() {
            return Err(Error::Corrupt("запись не разбирается".into()));
        }
        debug_assert_eq!(self.locs.last().map(|l| l.0), Some(at + blob_off));
        Ok(())
    }

    pub fn append_event(&mut self, kind: u8, id: u64, t: i64, sync: bool) -> Result<(), Error> {
        let mut p = Vec::with_capacity(18);
        p.push(R_EVENT);
        p.push(kind);
        put_u64(&mut p, id);
        put_i64(&mut p, t);
        self.write(&p, sync)?;
        self.events.push((id, t, kind));
        self.records += 1;
        Ok(())
    }

    pub fn append_tombstone(&mut self, id: u64, sync: bool) -> Result<(), Error> {
        let mut p = Vec::with_capacity(9);
        p.push(R_DELETE);
        put_u64(&mut p, id);
        self.write(&p, sync)?;
        self.tombstones.insert(id);
        self.records += 1;
        Ok(())
    }

    pub fn contains(&self, id: u64) -> bool {
        self.ids.binary_search(&id).is_ok()
    }

    /// The blob of an entry of this log.
    pub fn blob(&self, id: u64) -> io::Result<Option<Vec<u8>>> {
        let Ok(i) = self.ids.binary_search(&id) else {
            return Ok(None);
        };
        let (off, len) = self.locs[i];
        let mut b = vec![0u8; len as usize];
        self.file.read_exact_at(&mut b, off)?;
        Ok(Some(b))
    }

    pub fn sync(&self) -> io::Result<()> {
        self.file.sync_data()
    }

    /// The log mapped, for a seal to copy blobs out of.
    pub fn map(&self) -> io::Result<memmap2::Mmap> {
        // SAFETY: the log is ours, under the history's lock, and only ever
        // appended to: the bytes mapped do not change while mapped.
        unsafe { memmap2::Mmap::map(&self.file) }
    }
}

/// The payload of the frame at `at` and where the next one starts, if the
/// frame is whole and its checksum agrees.
fn frame(data: &[u8], at: usize) -> Option<(&[u8], usize)> {
    let mut r = Reader::new(data);
    r.at = at;
    let len = r.u32()?;
    if len > MAX_FRAME || len == 0 {
        return None;
    }
    let crc = r.u32()?;
    let payload = r.take(len as usize)?;
    (crc32fast::hash(payload) == crc).then_some((payload, r.at))
}
