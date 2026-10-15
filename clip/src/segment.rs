//! A sealed segment: one immutable file, memory-mapped, opened by reading
//! its header — nothing in it is parsed until a query or a lookup touches
//! it, so opening a history costs the same with ten entries or ten million.
//!
//! The file (little-endian throughout):
//!
//! ```text
//! b"CWCS" | u32 version 1
//! u64 entries | u64 least id | u64 greatest id
//! 9 × (u64 offset, u64 length)      the sections, below
//! u32 CRC-32 of all the above
//! ```
//!
//! | # | section    | rows                                                    |
//! |---|------------|---------------------------------------------------------|
//! | 0 | records    | the entries' blobs (`record`), as the log had them      |
//! | 1 | locations  | 24 B: id, offset into records, length — by id           |
//! | 2 | postings   | one list per term (below)                               |
//! | 3 | fst        | term (8 bytes, big-endian) → offset of its list         |
//! | 4 | copied     | 16 B: unix ms, id — by time: every copy, first or again |
//! | 5 | pasted     | 16 B: unix ms, id — by time                             |
//! | 6 | events     | 17 B: id, unix ms, kind — by id: an entry's history     |
//! | 7 | dedup      | 16 B: dedup hash, id — by hash                          |
//! | 8 | tombstones | 8 B: id — sorted                                        |
//!
//! A posting list: varint count, varint blocks, per block a u64 first id
//! and a u32 offset of its data (12 B, fixed: a binary search over them),
//! then the blocks — [`BLOCK`] ids each, the first in the table, the rest
//! varint deltas. A query walks a list newest first and skips by block.
//!
//! The entries of a segment are a contiguous run of ids: segments are only
//! ever merged with their neighbours, and the log's ids are greater than
//! every sealed one. Events and tombstones are about any id, older
//! segments' included — a paste of an old entry is recorded where the
//! paste happened, not in the entry's segment.
//!
//! Only the header is checksummed — checking the whole file would make
//! opening linear. The blobs are authenticated by their AEAD; every read
//! of the index is bounds-checked, so a damaged segment gives errors or
//! missing results, not a crash.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fst::Streamer;
use memmap2::Mmap;

use super::active::{Active, COPIED, PASTED};
use super::codec::{put_u32, put_u64, put_varint, u32_at, u64_at, Reader, Table};
use super::Error;

const MAGIC: &[u8; 4] = b"CWCS";
const VERSION: u32 = 1;
const SECTIONS: usize = 9;
const HEADER: usize = 32 + SECTIONS * 16 + 4;

pub(super) const S_RECORDS: usize = 0;
pub(super) const S_LOCS: usize = 1;
pub(super) const S_POSTINGS: usize = 2;
pub(super) const S_FST: usize = 3;
pub(super) const S_COPIED: usize = 4;
pub(super) const S_PASTED: usize = 5;
pub(super) const S_EVENTS: usize = 6;
pub(super) const S_DEDUP: usize = 7;
pub(super) const S_TOMBS: usize = 8;

const WIDTH: [usize; SECTIONS] = [1, 24, 1, 1, 16, 16, 17, 16, 8];

/// Ids per postings block.
pub(super) const BLOCK: usize = 128;

/// A section of the map, for `fst` to read in place.
#[derive(Clone)]
pub(super) struct Slice {
    map: Arc<Mmap>,
    start: usize,
    end: usize,
}

impl AsRef<[u8]> for Slice {
    fn as_ref(&self) -> &[u8] {
        &self.map[self.start..self.end]
    }
}

pub(super) struct Segment {
    pub number: u64,
    pub path: PathBuf,
    map: Arc<Mmap>,
    pub entries: u64,
    pub min_id: u64,
    pub max_id: u64,
    sec: [(usize, usize); SECTIONS],
    fst: fst::Map<Slice>,
    pub size: u64,
}

impl Segment {
    pub fn open(path: &Path, number: u64) -> Result<Segment, Error> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        // SAFETY: sealed segments are never written after the rename that
        // publishes them, and the history's lock keeps other writers of
        // this store away; a file changed under the map by someone else
        // with our uid is outside what the store defends against.
        let map = Arc::new(unsafe { Mmap::map(&file)? });
        let bad = |why: &str| Error::Corrupt(format!("{}: {why}", path.display()));
        if map.len() < HEADER || &map[..4] != MAGIC {
            return Err(bad("не сегмент истории"));
        }
        if u32_at(&map, 4) != Some(VERSION) {
            return Err(bad("другая версия"));
        }
        if u32_at(&map, HEADER - 4) != Some(crc32fast::hash(&map[..HEADER - 4])) {
            return Err(bad("заголовок повреждён"));
        }
        let h = |at| u64_at(&map, at).unwrap_or(0);
        let mut sec = [(0usize, 0usize); SECTIONS];
        for (i, s) in sec.iter_mut().enumerate() {
            let off = usize::try_from(h(32 + i * 16)).map_err(|_| bad("раздел"))?;
            let len = usize::try_from(h(40 + i * 16)).map_err(|_| bad("раздел"))?;
            let end = off.checked_add(len).ok_or_else(|| bad("раздел"))?;
            if off < HEADER || end > map.len() || len % WIDTH[i] != 0 {
                return Err(bad("раздел за пределами файла"));
            }
            *s = (off, end);
        }
        let fst = fst::Map::new(Slice {
            map: map.clone(),
            start: sec[S_FST].0,
            end: sec[S_FST].1,
        })
        .map_err(|e| bad(&format!("fst: {e}")))?;
        Ok(Segment {
            number,
            path: path.to_owned(),
            entries: h(8),
            min_id: h(16),
            max_id: h(24),
            sec,
            fst,
            size: map.len() as u64,
            map,
        })
    }

    fn section(&self, i: usize) -> &[u8] {
        &self.map[self.sec[i].0..self.sec[i].1]
    }

    pub fn table(&self, i: usize) -> Table<'_> {
        Table {
            b: self.section(i),
            width: WIDTH[i],
        }
    }

    /// The blob of entry `id`, if it is in this segment.
    pub fn blob(&self, id: u64) -> Option<&[u8]> {
        if self.entries == 0 || id < self.min_id || id > self.max_id {
            return None;
        }
        let t = self.table(S_LOCS);
        let i = t.partition_point(|i| t.u64(i, 0) < id);
        if i == t.len() || t.u64(i, 0) != id {
            return None;
        }
        let (off, len) = (t.u64(i, 8), t.u64(i, 16));
        let rec = self.section(S_RECORDS);
        let start = usize::try_from(off).ok()?;
        rec.get(start..start.checked_add(usize::try_from(len).ok()?)?)
    }

    pub fn postings(&self, term: u64) -> Option<Postings<'_>> {
        let off = self.fst.get(term.to_be_bytes())?;
        Postings::parse(self.section(S_POSTINGS), usize::try_from(off).ok()?)
    }

    /// Every term of the segment and the offset of its list, by term.
    fn terms(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::with_capacity(self.fst.len());
        let mut s = self.fst.stream();
        while let Some((k, v)) = s.next() {
            if let Ok(k) = <[u8; 8]>::try_from(k) {
                out.push((u64::from_be_bytes(k), v));
            }
        }
        out
    }

    pub fn is_tomb(&self, id: u64) -> bool {
        let t = self.table(S_TOMBS);
        let i = t.partition_point(|i| t.u64(i, 0) < id);
        i < t.len() && t.u64(i, 0) == id
    }

    /// Whether any tombstone is kept here.
    pub fn is_tomb_any(&self) -> bool {
        self.table(S_TOMBS).len() > 0
    }

    /// Entry `id`'s events recorded here: (unix ms, kind).
    pub fn events_of(&self, id: u64, out: &mut Vec<(i64, u8)>) {
        let t = self.table(S_EVENTS);
        let mut i = t.partition_point(|i| t.u64(i, 0) < id);
        while i < t.len() && t.u64(i, 0) == id {
            out.push((t.i64(i, 8), t.row(i)[16]));
            i += 1;
        }
    }

    pub fn dedup_ids(&self, hash: u64, out: &mut Vec<u64>) {
        let t = self.table(S_DEDUP);
        let mut i = t.partition_point(|i| t.u64(i, 0) < hash);
        while i < t.len() && t.u64(i, 0) == hash {
            out.push(t.u64(i, 8));
            i += 1;
        }
    }

    /// How many events of `kind` are in `[from, to)`.
    pub fn time_count(&self, kind: u8, from: i64, to: i64) -> usize {
        let t = self.table(if kind == COPIED { S_COPIED } else { S_PASTED });
        let lo = t.partition_point(|i| t.i64(i, 0) < from);
        let hi = t.partition_point(|i| t.i64(i, 0) < to);
        hi.saturating_sub(lo)
    }

    /// The ids of the events of `kind` in `[from, to)`.
    pub fn time_range(&self, kind: u8, from: i64, to: i64, out: &mut Vec<u64>) {
        let t = self.table(if kind == COPIED { S_COPIED } else { S_PASTED });
        let mut i = t.partition_point(|i| t.i64(i, 0) < from);
        while i < t.len() && t.i64(i, 0) < to {
            out.push(t.u64(i, 8));
            i += 1;
        }
    }
}

/// A posting list read in place, one block decoded at a time.
pub(super) struct Postings<'a> {
    pub n: usize,
    nblocks: usize,
    table: &'a [u8],
    data: &'a [u8],
    cached: usize,
    pub buf: Vec<u64>,
}

impl<'a> Postings<'a> {
    fn parse(section: &'a [u8], off: usize) -> Option<Postings<'a>> {
        let mut r = Reader::new(section);
        r.at = off;
        let n = usize::try_from(r.varint()?).ok()?;
        let nblocks = usize::try_from(r.varint()?).ok()?;
        if nblocks != n.div_ceil(BLOCK) {
            return None;
        }
        let table = r.take(nblocks.checked_mul(12)?)?;
        Some(Postings {
            n,
            nblocks,
            table,
            data: &section[r.at..],
            cached: usize::MAX,
            buf: Vec::with_capacity(BLOCK),
        })
    }

    pub fn first_of(&self, block: usize) -> u64 {
        u64_at(self.table, block * 12).unwrap_or(u64::MAX)
    }

    /// Decode block `i` into `buf` (a damaged block decodes short).
    pub fn load(&mut self, i: usize) {
        if self.cached == i {
            return;
        }
        self.cached = i;
        self.buf.clear();
        let count = (self.n - i * BLOCK).min(BLOCK);
        let mut id = self.first_of(i);
        let off = u32_at(self.table, i * 12 + 8).unwrap_or(u32::MAX) as usize;
        let mut r = Reader::new(self.data);
        r.at = off;
        self.buf.push(id);
        for _ in 1..count {
            match r.varint() {
                Some(d) if d > 0 => id = id.saturating_add(d),
                _ => break,
            }
            self.buf.push(id);
        }
    }

    /// The greatest id of the list below `below`: the block decoded last
    /// is tried first (a walk down a list, or a leapfrog over it, mostly
    /// stays in one), else a binary search over the blocks' first ids.
    pub fn prev(&mut self, below: u64) -> Option<u64> {
        if self.n == 0 {
            return None;
        }
        let c = self.cached;
        let b = if c != usize::MAX
            && self.buf.first().is_some_and(|&f| f < below)
            && (c + 1 == self.nblocks || self.first_of(c + 1) >= below)
        {
            c
        } else {
            let (mut lo, mut hi) = (0, self.nblocks);
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                if self.first_of(mid) < below {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            lo.checked_sub(1)?
        };
        self.load(b);
        let k = self.buf.partition_point(|&x| x < below);
        k.checked_sub(1).map(|k| self.buf[k])
    }

    /// Every id of the list, ascending.
    pub fn all(&mut self) -> Vec<u64> {
        let mut out = Vec::with_capacity(self.n);
        for i in 0..self.nblocks {
            self.load(i);
            out.extend_from_slice(&self.buf);
        }
        out
    }
}

pub(super) fn encode_postings(ids: &[u64], out: &mut Vec<u8>) {
    let nblocks = ids.len().div_ceil(BLOCK);
    put_varint(out, ids.len() as u64);
    put_varint(out, nblocks as u64);
    let mut data = Vec::new();
    let mut table = Vec::with_capacity(nblocks * 12);
    for block in ids.chunks(BLOCK) {
        put_u64(&mut table, block[0]);
        put_u32(&mut table, data.len() as u32);
        for w in block.windows(2) {
            put_varint(&mut data, w[1] - w[0]);
        }
    }
    out.extend_from_slice(&table);
    out.extend_from_slice(&data);
}

/// What a new segment is made of: sealed segments and the log, oldest
/// first — the order their entries' ids go in.
pub(super) enum Part<'a> {
    Sealed(&'a Segment),
    Active(&'a Active, &'a [u8]),
}

type Iter<'a, T> = Box<dyn Iterator<Item = T> + 'a>;

impl<'a> Part<'a> {
    fn entries(&self) -> Iter<'a, (u64, &'a [u8])> {
        match *self {
            Part::Sealed(s) => {
                let t = s.table(S_LOCS);
                let rec = s.section(S_RECORDS);
                Box::new((0..t.len()).filter_map(move |i| {
                    let (off, len) = (t.u64(i, 8) as usize, t.u64(i, 16) as usize);
                    Some((t.u64(i, 0), rec.get(off..off.checked_add(len)?)?))
                }))
            }
            Part::Active(a, map) => Box::new(a.ids.iter().zip(&a.locs).filter_map(
                move |(&id, &(off, len))| Some((id, map.get(off as usize..(off + len) as usize)?)),
            )),
        }
    }

    fn times(&self, kind: u8) -> Iter<'a, (i64, u64)> {
        match *self {
            Part::Sealed(s) => {
                let t = s.table(if kind == COPIED { S_COPIED } else { S_PASTED });
                Box::new((0..t.len()).map(move |i| (t.i64(i, 0), t.u64(i, 8))))
            }
            Part::Active(a, _) => {
                let mut v: Vec<(i64, u64)> = a
                    .events
                    .iter()
                    .filter(|e| e.2 == kind)
                    .map(|e| (e.1, e.0))
                    .collect();
                v.sort_unstable();
                Box::new(v.into_iter())
            }
        }
    }

    fn events(&self) -> Iter<'a, (u64, i64, u8)> {
        match *self {
            Part::Sealed(s) => {
                let t = s.table(S_EVENTS);
                Box::new((0..t.len()).map(move |i| (t.u64(i, 0), t.i64(i, 8), t.row(i)[16])))
            }
            Part::Active(a, _) => {
                let mut v = a.events.clone();
                v.sort_unstable();
                Box::new(v.into_iter())
            }
        }
    }

    fn dedup(&self) -> Iter<'a, (u64, u64)> {
        match *self {
            Part::Sealed(s) => {
                let t = s.table(S_DEDUP);
                Box::new((0..t.len()).map(move |i| (t.u64(i, 0), t.u64(i, 8))))
            }
            Part::Active(a, _) => {
                let mut v: Vec<(u64, u64)> = a
                    .dedup
                    .iter()
                    .flat_map(|(&h, ids)| ids.iter().map(move |&id| (h, id)))
                    .collect();
                v.sort_unstable();
                Box::new(v.into_iter())
            }
        }
    }

    fn tombs(&self) -> Iter<'a, u64> {
        match *self {
            Part::Sealed(s) => {
                let t = s.table(S_TOMBS);
                Box::new((0..t.len()).map(move |i| t.u64(i, 0)))
            }
            Part::Active(a, _) => {
                let mut v: Vec<u64> = a.tombstones.iter().copied().collect();
                v.sort_unstable();
                Box::new(v.into_iter())
            }
        }
    }
}

/// Sorted iterators merged into one sorted iterator.
fn kmerge<'a, T: Ord + Copy + 'a>(mut its: Vec<Iter<'a, T>>) -> impl Iterator<Item = T> + 'a {
    let mut heap = BinaryHeap::new();
    for (i, it) in its.iter_mut().enumerate() {
        if let Some(x) = it.next() {
            heap.push(Reverse((x, i)));
        }
    }
    std::iter::from_fn(move || {
        let Reverse((x, i)) = heap.pop()?;
        if let Some(y) = its[i].next() {
            heap.push(Reverse((y, i)));
        }
        Some(x)
    })
}

/// A file being written, and where in it we are.
struct Out {
    w: BufWriter<File>,
    pos: u64,
}

impl Out {
    fn put(&mut self, b: &[u8]) -> io::Result<()> {
        self.w.write_all(b)?;
        self.pos += b.len() as u64;
        Ok(())
    }
}

/// Write the segment made of `parts` to `path` (a temporary name the caller
/// renames), keeping the entries, events and dedup rows of the ids `live`
/// says are, and the tombstones `keep_tomb` says still matter. Streams: the
/// memory it takes is that of the longest posting list and the terms'
/// table, not of the segment.
pub(super) fn write(
    path: &Path,
    parts: &[Part],
    live: &dyn Fn(u64) -> bool,
    keep_tomb: &dyn Fn(u64) -> bool,
) -> Result<(), Error> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let mut o = Out {
        w: BufWriter::with_capacity(1 << 20, file),
        pos: 0,
    };
    o.put(&[0u8; HEADER])?;
    let mut sec = [(0u64, 0u64); SECTIONS];
    let mut row = Vec::with_capacity(32);

    // Locations first (their offsets are known from the blobs' lengths
    // alone), then the blobs: two passes over the inputs, none held.
    let (mut entries, mut min_id, mut max_id, mut rel) = (0u64, 0u64, 0u64, 0u64);
    let start = o.pos;
    for p in parts {
        for (id, blob) in p.entries() {
            if !live(id) {
                continue;
            }
            row.clear();
            put_u64(&mut row, id);
            put_u64(&mut row, rel);
            put_u64(&mut row, blob.len() as u64);
            o.put(&row)?;
            rel += blob.len() as u64;
            if entries == 0 {
                min_id = id;
            }
            max_id = id;
            entries += 1;
        }
    }
    sec[S_LOCS] = (start, o.pos - start);
    let start = o.pos;
    for p in parts {
        for (id, blob) in p.entries() {
            if live(id) {
                o.put(blob)?;
            }
        }
    }
    sec[S_RECORDS] = (start, o.pos - start);

    // Postings, by term across the parts; the FST over them after.
    let mut terms: Vec<(u64, usize, u64)> = Vec::new();
    for (pi, p) in parts.iter().enumerate() {
        match *p {
            Part::Sealed(s) => terms.extend(s.terms().into_iter().map(|(t, off)| (t, pi, off))),
            Part::Active(a, _) => terms.extend(a.postings.keys().map(|&t| (t, pi, 0))),
        }
    }
    terms.sort_unstable();
    let start = o.pos;
    let mut fst = fst::MapBuilder::memory();
    let mut ids = Vec::new();
    let mut buf = Vec::new();
    let mut i = 0;
    while i < terms.len() {
        let term = terms[i].0;
        ids.clear();
        while i < terms.len() && terms[i].0 == term {
            let (_, pi, off) = terms[i];
            match parts[pi] {
                Part::Sealed(s) => {
                    if let Some(mut p) = Postings::parse(s.section(S_POSTINGS), off as usize) {
                        ids.extend(p.all().into_iter().filter(|&id| live(id)));
                    }
                }
                Part::Active(a, _) => {
                    ids.extend(a.postings[&term].iter().copied().filter(|&id| live(id)));
                }
            }
            i += 1;
        }
        if ids.is_empty() {
            continue;
        }
        buf.clear();
        encode_postings(&ids, &mut buf);
        fst.insert(term.to_be_bytes(), o.pos - start)
            .map_err(|e| Error::Corrupt(format!("fst: {e}")))?;
        o.put(&buf)?;
    }
    sec[S_POSTINGS] = (start, o.pos - start);
    let fst = fst
        .into_inner()
        .map_err(|e| Error::Corrupt(format!("fst: {e}")))?;
    let start = o.pos;
    o.put(&fst)?;
    sec[S_FST] = (start, o.pos - start);

    for (s, kind) in [(S_COPIED, COPIED), (S_PASTED, PASTED)] {
        let start = o.pos;
        for (t, id) in kmerge(parts.iter().map(|p| p.times(kind)).collect()) {
            if live(id) {
                row.clear();
                put_u64(&mut row, t as u64);
                put_u64(&mut row, id);
                o.put(&row)?;
            }
        }
        sec[s] = (start, o.pos - start);
    }
    let start = o.pos;
    for (id, t, kind) in kmerge(parts.iter().map(|p| p.events()).collect()) {
        if live(id) {
            row.clear();
            put_u64(&mut row, id);
            put_u64(&mut row, t as u64);
            row.push(kind);
            o.put(&row)?;
        }
    }
    sec[S_EVENTS] = (start, o.pos - start);
    let start = o.pos;
    for (h, id) in kmerge(parts.iter().map(|p| p.dedup()).collect()) {
        if live(id) {
            row.clear();
            put_u64(&mut row, h);
            put_u64(&mut row, id);
            o.put(&row)?;
        }
    }
    sec[S_DEDUP] = (start, o.pos - start);
    let start = o.pos;
    let mut last = None;
    for id in kmerge(parts.iter().map(|p| p.tombs()).collect()) {
        if last != Some(id) && keep_tomb(id) {
            o.put(&id.to_le_bytes())?;
        }
        last = Some(id);
    }
    sec[S_TOMBS] = (start, o.pos - start);

    let mut h = Vec::with_capacity(HEADER);
    h.extend_from_slice(MAGIC);
    put_u32(&mut h, VERSION);
    put_u64(&mut h, entries);
    put_u64(&mut h, min_id);
    put_u64(&mut h, max_id);
    for (off, len) in sec {
        put_u64(&mut h, off);
        put_u64(&mut h, len);
    }
    let crc = crc32fast::hash(&h);
    put_u32(&mut h, crc);
    let mut file = o.w.into_inner().map_err(|e| e.into_error())?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&h)?;
    file.sync_all()?;
    Ok(())
}
