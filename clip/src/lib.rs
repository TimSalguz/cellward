//! The clipboard history's store and its search (`docs/CLIPBOARD.md`, «The
//! history»): one [`History`] per directory — one per container, one for
//! the host. No Wayland and no window here: the daemon that records copies
//! and the window that shows them are built on this API.
//!
//! **What an entry is.** An id (a `u64`, growing, never reused — not even
//! after the newest entries are deleted and merged away), when it was first
//! copied (unix ms), the types it was offered in and the contents of each
//! ([`Content`]: text as UTF-8 bytes, images and the rest as they came; one
//! entry holds at most [`MAX_ENTRY`] bytes), a short preview, and its
//! events: every time it was copied again and every time it was pasted.
//! An event is a record of its own, appended — an entry is never rewritten.
//! Copying again what is already there (the same types with the same
//! contents, found by a keyed hash and then compared) adds a copy event to
//! the entry that has it ([`Appended::Again`]) instead of a second entry.
//!
//! **On disk** (each part's format is in its module):
//!
//! * `manifest` — which segments are live, the log, the next id, and a
//!   known text sealed with the key: a wrong key is told at open
//!   ([`Error::WrongKey`]), not as garbage later. Replaced by `rename`.
//! * `log-<n>.cwl` — the active segment (`active`): an append-only log of
//!   entries, events and tombstones, each frame checksummed; a torn tail
//!   left by a crash is cut off at open.
//! * `seg-<n>.cws` — sealed segments (`segment`), immutable and
//!   memory-mapped: the entries' sealed blobs, an FST from hashed trigram
//!   to a posting list, the copy and paste times sorted (a date range is a
//!   binary search), the events by id, the dedup hashes, the tombstones.
//! * `lock` — `flock`ed while a history is open: one writer.
//!
//! When the log passes [`Options::seal_bytes`] it is sealed into a segment
//! and a new log begun; when [`Options::fanout`] neighbouring segments are
//! of a size they are merged into one (tiered, LSM-style: an entry is
//! rewritten about log_fanout(history ÷ seal) times in its life). A merge
//! copies the sealed blobs as they are — it needs no decryption — and
//! drops what was deleted.
//!
//! **Encrypted at rest.** The caller's 32-byte [`Key`] (`Key::load_or_create`
//! makes the 0600 file, never through a link) gives three keys
//! (HMAC-SHA256 of labels): contents, previews and types are sealed with
//! XChaCha20-Poly1305 under random 192-bit nonces, the id bound in as
//! associated data. Nothing of the plain text is on disk: the index's terms
//! are HMAC-SHA256(term key, trigram) truncated to 64 bits, the dedup hash
//! HMAC-SHA256(dedup key, contents) truncated likewise.
//!
//! **What the index still tells** whoever reads the files without the key —
//! keyed hashes hide *what* a trigram is, not *that* it recurs:
//!
//! * how many entries there are, when each was copied and pasted (times are
//!   in the clear: a date range must be searchable without decrypting
//!   everything), and roughly how large each is;
//! * for each hashed trigram, which entries contain it: its frequency, and
//!   which entries share trigrams (co-occurrence) — so which entries are
//!   alike, and, against a known corpus or language statistics, frequency
//!   analysis may guess the commonest trigrams and from them words of short,
//!   common texts;
//! * which entries were offered in the same types (a type is a hashed term
//!   too), and which entries are copies again of one another (events).
//!
//! It does not tell a single trigram, type or text without the key. A
//! deleted entry stays on disk, sealed, until a merge drops its segment.
//!
//! **Search** ([`Query`]): words (each must occur, case-insensitively), a
//! pattern (a regex), types, and time ranges of copies or pastes. Words and
//! the literal runs a pattern requires become trigrams; each segment's
//! posting lists for them are intersected newest first, by leapfrogging,
//! with the time ranges' ids; each candidate is decrypted and checked
//! exactly, so a hash collision costs time, never a wrong answer. Results
//! are ids, newest first, a page at a time ([`History::query`]'s `before`
//! and `limit`): the first page of a common word decrypts a page's worth
//! of entries, not every match. A word shorter than three characters, and
//! a pattern requiring no literal run of three, have no trigram: they are
//! checked by decrypting entry after entry (narrowed by the other
//! conditions, if any) — slow on a large history. So is a pattern whose
//! literal is common and whose matches are rare (`word\s+\d{4}$` over ten
//! million entries: seconds): every entry with the word is decrypted until
//! a page is found. A wide time range with words is checked on each
//! candidate ([`Options::time_set_max`]) rather than gathered first.
//!
//! Measured (`tests::bench_ten_million`, ten million short texts, 4.2 GB
//! after a full merge): ~36k appends a second including seals and merges;
//! open under a millisecond; a first page from warm pages in 0.05–0.7 ms
//! for a rare word, a common word, two words, a day, a rare word in a
//! month; from a cold page cache, tens to hundreds of milliseconds.

mod active;
mod codec;
mod crypto;
mod query;
mod record;
mod segment;

/// Volatile active-selection model; Wayland/X11 transport is not wired yet.
pub mod broker;
/// Scoped socket-pair transport for the active-selection model (not wired to UI yet).
pub mod broker_transport;
/// Nonblocking FD client; graphic adapters are still a separate integration step.
#[path = "../../shared/clipboard_client.rs"]
pub mod clipboard_client;
/// What the recorder decides of a selection (`cellward-clip daemon`).
pub mod recorder;
/// History paths protected by the container mount boundary and their migration.
pub mod storage;

/// The daemon's socket of questions: requests and answers.
pub mod protocol;

#[cfg(test)]
mod tests;

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::ops::Range;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub use crypto::Key;

use active::{Active, COPIED, PASTED};
use codec::{put_bytes, put_u32, put_u64, Reader};
use crypto::{Keys, TERM_TRIGRAM, TERM_TYPE};
use query::{leapfrog, lower, trigrams, IdSet, Locs, Sorted, Union};
use segment::{Part, Segment};

/// The most one entry may hold: its types' names and contents together.
pub const MAX_ENTRY: usize = 64 << 20;

/// The types searched as the entry's text, in this order of preference; if
/// none is there, the first `text/*` type that is valid UTF-8.
const TEXT_TYPES: [&str; 5] = [
    "text/plain;charset=utf-8",
    "utf8_string",
    "text/plain",
    "string",
    "text",
];

/// Characters of a preview made from the text.
const PREVIEW: usize = 200;

/// What the manifest's known text is (sealed with the key).
const KEYCHECK: &[u8] = b"cellward clipboard history v1";

/// The trigram hashes `append` remembers (cleared when full): hashing is
/// most of an append's work, and a history's texts share their trigrams.
const TERM_CACHE: usize = 1 << 20;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// The key is not the history's.
    WrongKey,
    /// The key file is not one to trust (a link, someone else's, readable
    /// by others, the wrong size).
    KeyFile(String),
    /// A file of the history does not read as one.
    Corrupt(String),
    /// An entry that does not decrypt (altered on disk).
    Undecryptable(u64),
    /// An entry over [`MAX_ENTRY`].
    TooLarge(usize),
    /// Another process has the history open.
    Busy,
    /// The query's pattern does not compile.
    BadPattern(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "история буфера обмена: {e}"),
            Error::WrongKey => f.write_str("история буфера обмена: ключ не от этой истории"),
            Error::KeyFile(why) => write!(f, "ключ истории буфера обмена не принят: {why}"),
            Error::Corrupt(why) => write!(f, "история буфера обмена повреждена: {why}"),
            Error::Undecryptable(id) => {
                write!(f, "запись {id} истории буфера обмена не расшифровывается")
            }
            Error::TooLarge(n) => write!(
                f,
                "скопировано слишком много для истории: {n} байт (не больше {MAX_ENTRY})"
            ),
            Error::Busy => f.write_str("история буфера обмена уже открыта другим процессом"),
            Error::BadPattern(e) => write!(f, "шаблон поиска не разобран: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// One type an entry was offered in, and its contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Content {
    pub mime: String,
    pub data: Vec<u8>,
}

/// What [`History::append`] takes.
#[derive(Debug, Clone)]
pub struct NewEntry {
    /// Unix ms.
    pub copied_at: i64,
    pub contents: Vec<Content>,
    /// Made from the text when `None` (the first [`PREVIEW`] characters,
    /// spaces collapsed); empty for an entry without text.
    pub preview: Option<String>,
}

/// An entry, whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub id: u64,
    /// When it was first copied (unix ms).
    pub copied_at: i64,
    /// Every time it was copied, the first included; ascending.
    pub copies: Vec<i64>,
    /// Every time it was pasted; ascending.
    pub pastes: Vec<i64>,
    pub contents: Vec<Content>,
    pub preview: String,
}

/// An entry without its contents: what a list shows (the contents are
/// not decrypted unless they are small enough to lie with the preview).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub id: u64,
    pub copied_at: i64,
    pub copies: Vec<i64>,
    pub pastes: Vec<i64>,
    /// Each type and the size of its contents.
    pub types: Vec<(String, u64)>,
    pub preview: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Appended {
    /// A new entry, of this id.
    New(u64),
    /// The same contents were there: a copy event added to this entry.
    Again(u64),
}

impl Appended {
    pub fn id(self) -> u64 {
        match self {
            Appended::New(id) | Appended::Again(id) => id,
        }
    }
}

/// A search. Every condition given must hold; none given matches all.
/// Times are unix-ms half-open ranges — a day or an hour in the local zone
/// is the caller's to turn into one.
#[derive(Debug, Clone, Default)]
pub struct Query {
    /// Words that must all occur in the text, case-insensitively (simple
    /// per-character lowercase).
    pub text_terms: Vec<String>,
    /// A regex (the `regex` crate's syntax) the text must match; case
    /// matters unless it says `(?i)`.
    pub pattern: Option<String>,
    /// Offered in any of these types; `image/*` stands for every image
    /// type. Case-insensitive.
    pub types: Option<Vec<String>>,
    /// Copied (first or again) within.
    pub copied: Option<Range<i64>>,
    /// Pasted within.
    pub pasted: Option<Range<i64>>,
    /// Copied or pasted within `window` ms of `time`, either side.
    pub around: Option<(i64, i64)>,
}

/// How a history behaves.
#[derive(Debug, Clone)]
pub struct Options {
    /// Seal the log when it is this large.
    pub seal_bytes: u64,
    /// Merge this many neighbouring segments of a size into one.
    pub fanout: usize,
    /// `fdatasync` each append before it returns. Off only for bulk loads
    /// (a test's): a crash may then lose the last appends — never more,
    /// and never the history.
    pub sync: bool,
    /// Merge after a seal when segments pile up (else only [`History::compact`]).
    pub auto_merge: bool,
    /// A time range of more events than this, in a query that has words or
    /// types too, is checked on each candidate instead of being made a set
    /// of ids first.
    pub time_set_max: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            seal_bytes: 8 << 20,
            fanout: 8,
            sync: true,
            auto_merge: true,
            time_set_max: 1 << 16,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub segments: usize,
    pub sealed_entries: u64,
    pub active_entries: usize,
    pub bytes: u64,
}

pub struct History {
    dir: PathBuf,
    keys: Keys,
    opts: Options,
    _lock: File,
    keycheck: Vec<u8>,
    next_file: u64,
    next_id: u64,
    /// Oldest first; their entries' ids ascend in that order.
    segments: Vec<Segment>,
    active: Active,
    term_cache: HashMap<String, u64>,
}

struct Manifest {
    next_file: u64,
    next_id: u64,
    keycheck: Vec<u8>,
    active: u64,
    segments: Vec<u64>,
}

const MANIFEST_MAGIC: &[u8; 4] = b"CWCM";
const MANIFEST_VERSION: u32 = 1;

impl Manifest {
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(MANIFEST_MAGIC);
        put_u32(&mut v, MANIFEST_VERSION);
        put_u64(&mut v, self.next_file);
        put_u64(&mut v, self.next_id);
        put_bytes(&mut v, &self.keycheck);
        put_u64(&mut v, self.active);
        put_u32(&mut v, self.segments.len() as u32);
        for &s in &self.segments {
            put_u64(&mut v, s);
        }
        let crc = crc32fast::hash(&v);
        put_u32(&mut v, crc);
        v
    }

    fn decode(b: &[u8]) -> Option<Manifest> {
        let body = b.get(..b.len().checked_sub(4)?)?;
        if codec::u32_at(b, body.len())? != crc32fast::hash(body) {
            return None;
        }
        let mut r = Reader::new(body);
        if r.take(4)? != MANIFEST_MAGIC || r.u32()? != MANIFEST_VERSION {
            return None;
        }
        let next_file = r.u64()?;
        let next_id = r.u64()?;
        let keycheck = r.bytes()?.to_vec();
        let active = r.u64()?;
        let n = r.u32()?;
        let mut segments = Vec::new();
        for _ in 0..n {
            segments.push(r.u64()?);
        }
        r.done().then_some(Manifest {
            next_file,
            next_id,
            keycheck,
            active,
            segments,
        })
    }
}

fn seg_name(n: u64) -> String {
    format!("seg-{n:016x}.cws")
}

fn log_name(n: u64) -> String {
    format!("log-{n:016x}.cwl")
}

/// Write `data` to `dir/name` atomically: a temporary file, synced, renamed
/// over, the directory synced.
fn replace_file(dir: &Path, name: &str, data: &[u8]) -> io::Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, dir.join(name))?;
    sync_dir(dir)
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// The text an entry is searched by.
fn primary_text(contents: &[Content]) -> Option<&str> {
    for t in TEXT_TYPES {
        if let Some(c) = contents
            .iter()
            .find(|c| c.mime.replace(' ', "").eq_ignore_ascii_case(t))
        {
            if let Ok(s) = std::str::from_utf8(&c.data) {
                return Some(s);
            }
        }
    }
    contents
        .iter()
        .filter(|c| c.mime.to_ascii_lowercase().starts_with("text/"))
        .find_map(|c| std::str::from_utf8(&c.data).ok())
}

fn make_preview(text: &str) -> String {
    let mut out = String::new();
    let mut n = 0;
    for word in text.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
            n += 1;
        }
        for c in word.chars() {
            if n >= PREVIEW {
                out.push('…');
                return out;
            }
            out.push(c);
            n += 1;
        }
    }
    out
}

/// The contents in a form that is the same for the same contents offered
/// in another order: what the dedup hash is of.
fn canonical(contents: &[Content]) -> Vec<u8> {
    let mut sorted: Vec<&Content> = contents.iter().collect();
    sorted.sort_by(|a, b| (&a.mime, &a.data).cmp(&(&b.mime, &b.data)));
    let mut v = Vec::new();
    for c in sorted {
        put_bytes(&mut v, c.mime.as_bytes());
        put_bytes(&mut v, &c.data);
    }
    v
}

/// The type terms of a type: itself, and `major/*`.
fn type_terms(mime: &str) -> Vec<String> {
    let m = mime.to_ascii_lowercase();
    let mut out = Vec::with_capacity(2);
    if let Some((major, _)) = m.split_once('/') {
        out.push(format!("{major}/*"));
    }
    out.push(m);
    out
}

impl History {
    /// Open the history in `dir` (made, 0700, if missing), or begin one.
    pub fn open(dir: &Path, key: &Key) -> Result<History> {
        History::open_with(dir, key, Options::default())
    }

    pub fn open_with(dir: &Path, key: &Key, opts: Options) -> Result<History> {
        DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(dir.join("lock"))?;
        // SAFETY: a descriptor of ours.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let e = io::Error::last_os_error();
            return Err(if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
                Error::Busy
            } else {
                Error::Io(e)
            });
        }
        let keys = Keys::derive(key);
        let m = match fs::read(dir.join("manifest")) {
            Ok(b) => Manifest::decode(&b)
                .ok_or_else(|| Error::Corrupt("manifest не разбирается".into()))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let m = Manifest {
                    next_file: 2,
                    next_id: 1,
                    keycheck: keys.seal(b"keycheck", KEYCHECK)?,
                    active: 1,
                    segments: Vec::new(),
                };
                let p = dir.join(log_name(1));
                crypto_remove(&p);
                Active::create(&p, 1)?;
                replace_file(dir, "manifest", &m.encode())?;
                m
            }
            Err(e) => return Err(e.into()),
        };
        if keys.open(b"keycheck", &m.keycheck).as_deref() != Some(KEYCHECK) {
            return Err(Error::WrongKey);
        }
        let mut segments = Vec::with_capacity(m.segments.len());
        for &n in &m.segments {
            segments.push(Segment::open(&dir.join(seg_name(n)), n)?);
        }
        let active = Active::open(&dir.join(log_name(m.active)), m.active)?;
        // What a crash left between writing a file and the manifest naming
        // it (or between the manifest and removing what it no longer
        // names) is not part of the history.
        let mut keep: BTreeSet<String> = m.segments.iter().map(|&n| seg_name(n)).collect();
        keep.insert(log_name(m.active));
        for e in fs::read_dir(dir)?.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let ours =
                name.starts_with("seg-") || name.starts_with("log-") || name.ends_with(".tmp");
            if ours && !keep.contains(&name) {
                crypto_remove(&e.path());
            }
        }
        let mut next_id = m.next_id.max(1);
        if let Some(&last) = active.ids.last() {
            next_id = next_id.max(last + 1);
        }
        for s in &segments {
            if s.entries > 0 {
                next_id = next_id.max(s.max_id + 1);
            }
        }
        Ok(History {
            dir: dir.to_owned(),
            keys,
            opts,
            _lock: lock,
            keycheck: m.keycheck,
            next_file: m.next_file,
            next_id,
            segments,
            active,
            term_cache: HashMap::new(),
        })
    }

    pub fn stats(&self) -> Stats {
        Stats {
            segments: self.segments.len(),
            sealed_entries: self.segments.iter().map(|s| s.entries).sum(),
            active_entries: self.active.ids.len(),
            bytes: self.segments.iter().map(|s| s.size).sum::<u64>() + self.active.len,
        }
    }

    /// Record a copy. The same contents copied before (and not deleted)
    /// get a copy event instead of a new entry.
    ///
    /// See `contains_contents` for a lookup which records no copy event.
    pub fn append(&mut self, e: NewEntry) -> Result<Appended> {
        let size: usize = e.contents.iter().map(|c| c.mime.len() + c.data.len()).sum();
        if size > MAX_ENTRY {
            return Err(Error::TooLarge(size));
        }
        let hash = self.keys.dedup(&canonical(&e.contents));
        let mut same = Vec::new();
        if let Some(ids) = self.active.dedup.get(&hash) {
            same.extend_from_slice(ids);
        }
        for s in &self.segments {
            s.dedup_ids(hash, &mut same);
        }
        same.sort_unstable_by(|a, b| b.cmp(a));
        for id in same {
            if self.is_deleted(id) {
                continue;
            }
            if let Some(old) = self.contents(id)? {
                if canonical(&old) == canonical(&e.contents) {
                    self.event(COPIED, id, e.copied_at)?;
                    return Ok(Appended::Again(id));
                }
            }
        }

        self.append_new(e)
    }

    fn append_new(&mut self, e: NewEntry) -> Result<Appended> {
        let size: usize = e.contents.iter().map(|c| c.mime.len() + c.data.len()).sum();
        if size > MAX_ENTRY {
            return Err(Error::TooLarge(size));
        }
        let hash = self.keys.dedup(&canonical(&e.contents));
        let id = self.next_id;
        let text = primary_text(&e.contents);
        let preview = e
            .preview
            .clone()
            .unwrap_or_else(|| text.map(make_preview).unwrap_or_default());
        let mut terms = Vec::new();
        if let Some(text) = text {
            let lc = lower(text);
            let (keys, cache) = (&self.keys, &mut self.term_cache);
            trigrams(&lc, |g| {
                let h = match cache.get(g) {
                    Some(&h) => h,
                    None => {
                        if cache.len() >= TERM_CACHE {
                            cache.clear();
                        }
                        let h = keys.term(TERM_TRIGRAM, g.as_bytes());
                        cache.insert(g.to_owned(), h);
                        h
                    }
                };
                terms.push(h);
            });
        }
        for c in &e.contents {
            for t in type_terms(&c.mime) {
                terms.push(self.keys.term(TERM_TYPE, t.as_bytes()));
            }
        }
        terms.sort_unstable();
        terms.dedup();
        let blob = record::seal(&self.keys, id, e.copied_at, hash, &e.contents, &preview)?;
        self.active.append_entry(&terms, &blob, self.opts.sync)?;
        self.next_id += 1;
        self.maybe_seal()?;
        Ok(Appended::New(id))
    }

    /// Whether these exact contents are present without changing copy counts
    /// or allocating an id. Used to omit already-marked passwords from the
    /// ordinary recorder without exposing a match to the copying program.
    pub fn contains_contents(&self, contents: &[Content]) -> Result<bool> {
        let wanted = canonical(contents);
        let hash = self.keys.dedup(&wanted);
        let mut ids = self.active.dedup.get(&hash).cloned().unwrap_or_default();
        for segment in &self.segments {
            segment.dedup_ids(hash, &mut ids);
        }
        for id in ids {
            if !self.is_deleted(id) {
                if let Some(old) = self.contents(id)? {
                    if canonical(&old) == wanted {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    /// Append an entry of another history (a move between containers: `get`
    /// there, `import` here, `delete` there): its contents, its preview, its
    /// copies and its pastes. Its id here is a new one.
    pub fn import(&mut self, e: &Entry) -> Result<Appended> {
        let first = e.copies.first().copied().unwrap_or(e.copied_at);
        let a = self.append(NewEntry {
            copied_at: first,
            contents: e.contents.clone(),
            preview: Some(e.preview.clone()),
        })?;
        let id = a.id();
        let skip = usize::from(matches!(a, Appended::New(_)) && !e.copies.is_empty());
        for &t in &e.copies[skip..] {
            self.event(COPIED, id, t)?;
        }
        for &t in &e.pastes {
            self.event(PASTED, id, t)?;
        }
        Ok(a)
    }

    /// Replace contents/preview without deduplicating away an edited label.
    /// A fresh id preserves the immutable log format. The replacement and its
    /// original copy/paste times are durable before the old id is deleted.
    pub fn replace(
        &mut self,
        id: u64,
        contents: Vec<Content>,
        preview: String,
    ) -> Result<Option<u64>> {
        let Some(old) = self.get(id)? else {
            return Ok(None);
        };
        let new = self
            .append_new(NewEntry {
                copied_at: old.copied_at,
                contents,
                preview: Some(preview),
            })?
            .id();
        for &at in old.copies.iter().skip(1) {
            self.event(COPIED, new, at)?;
        }
        for &at in &old.pastes {
            self.event(PASTED, new, at)?;
        }
        self.sync()?;
        self.delete(id)?;
        self.sync()?;
        Ok(Some(new))
    }

    /// Record that entry `id` was copied again at `at` (false: no such
    /// entry).
    pub fn record_copy(&mut self, id: u64, at: i64) -> Result<bool> {
        if !self.exists(id) {
            return Ok(false);
        }
        self.event(COPIED, id, at)?;
        Ok(true)
    }

    /// Record that entry `id` was pasted at `at` (false: no such entry).
    pub fn record_paste(&mut self, id: u64, at: i64) -> Result<bool> {
        if !self.exists(id) {
            return Ok(false);
        }
        self.event(PASTED, id, at)?;
        Ok(true)
    }

    fn event(&mut self, kind: u8, id: u64, at: i64) -> Result<()> {
        self.active.append_event(kind, id, at, self.opts.sync)?;
        self.maybe_seal()
    }

    /// Delete entry `id` (false: no such entry). It is gone from every
    /// answer at once, and from the disk at the next merge of its segment.
    pub fn delete(&mut self, id: u64) -> Result<bool> {
        if !self.exists(id) {
            return Ok(false);
        }
        self.active.append_tombstone(id, self.opts.sync)?;
        self.maybe_seal()?;
        Ok(true)
    }

    /// Flush the log to the disk (what `Options::sync` does per append).
    pub fn sync(&self) -> Result<()> {
        Ok(self.active.sync()?)
    }

    fn exists(&self, id: u64) -> bool {
        !self.is_deleted(id) && (self.active.contains(id) || self.segment_of(id).is_some())
    }

    fn is_deleted(&self, id: u64) -> bool {
        self.active.tombstones.contains(&id) || self.segments.iter().any(|s| s.is_tomb(id))
    }

    fn segment_of(&self, id: u64) -> Option<&Segment> {
        self.segments
            .iter()
            .rev()
            .find(|s| s.entries > 0 && s.min_id <= id && id <= s.max_id)
            .filter(|s| s.blob(id).is_some())
    }

    /// The blob of entry `id`, wherever it is.
    fn blob(&self, id: u64) -> Result<Option<Vec<u8>>> {
        if self.active.contains(id) {
            return Ok(self.active.blob(id)?);
        }
        Ok(self
            .segment_of(id)
            .and_then(|s| s.blob(id))
            .map(<[u8]>::to_vec))
    }

    fn contents(&self, id: u64) -> Result<Option<Vec<Content>>> {
        let Some(b) = self.blob(id)? else {
            return Ok(None);
        };
        let blob = record::parse(&b).ok_or_else(|| Error::Corrupt(format!("запись {id}")))?;
        let head = record::open_head(&self.keys, &blob)?;
        Ok(Some(record::open_contents(&self.keys, &blob, head)?))
    }

    /// Entry `id`'s copies and pastes, ascending.
    fn events_of(&self, id: u64) -> (Vec<i64>, Vec<i64>) {
        let mut ev = Vec::new();
        for s in &self.segments {
            s.events_of(id, &mut ev);
        }
        ev.extend(
            self.active
                .events
                .iter()
                .filter(|e| e.0 == id)
                .map(|e| (e.1, e.2)),
        );
        ev.sort_unstable();
        let pick = |k| ev.iter().filter(|e| e.1 == k).map(|e| e.0).collect();
        (pick(COPIED), pick(PASTED))
    }

    /// Entry `id`, decrypted (None: no such entry, or deleted).
    pub fn get(&self, id: u64) -> Result<Option<Entry>> {
        if self.is_deleted(id) {
            return Ok(None);
        }
        let Some(b) = self.blob(id)? else {
            return Ok(None);
        };
        let blob = record::parse(&b).ok_or_else(|| Error::Corrupt(format!("запись {id}")))?;
        let head = record::open_head(&self.keys, &blob)?;
        let preview = head.preview.clone();
        let contents = record::open_contents(&self.keys, &blob, head)?;
        let (copies, pastes) = self.events_of(id);
        Ok(Some(Entry {
            id,
            copied_at: blob.copied_at,
            copies,
            pastes,
            contents,
            preview,
        }))
    }

    /// Entry `id` without its contents.
    pub fn summary(&self, id: u64) -> Result<Option<Summary>> {
        if self.is_deleted(id) {
            return Ok(None);
        }
        let Some(b) = self.blob(id)? else {
            return Ok(None);
        };
        let blob = record::parse(&b).ok_or_else(|| Error::Corrupt(format!("запись {id}")))?;
        let head = record::open_head(&self.keys, &blob)?;
        let (copies, pastes) = self.events_of(id);
        Ok(Some(Summary {
            id,
            copied_at: blob.copied_at,
            copies,
            pastes,
            types: head.types,
            preview: head.preview,
        }))
    }

    /// How many events of `kind` are in `[from, to)` (two binary searches a
    /// segment).
    fn time_count(&self, kind: u8, from: i64, to: i64) -> usize {
        let sealed: usize = self
            .segments
            .iter()
            .map(|s| s.time_count(kind, from, to))
            .sum();
        sealed
            + self
                .active
                .events
                .iter()
                .filter(|e| e.2 == kind && from <= e.1 && e.1 < to)
                .count()
    }

    /// The ids of the events of `kind` in `[from, to)`.
    fn time_ids(&self, kind: u8, from: i64, to: i64, out: &mut Vec<u64>) {
        for s in &self.segments {
            s.time_range(kind, from, to, out);
        }
        out.extend(
            self.active
                .events
                .iter()
                .filter(|e| e.2 == kind && from <= e.1 && e.1 < to)
                .map(|e| e.0),
        );
    }

    /// The ids matching `q`, newest (greatest id) first: at most `limit` of
    /// them, all below `before` when given — the next page is asked for with
    /// `before` set to the last id of this one.
    pub fn query(&self, q: &Query, before: Option<u64>, limit: usize) -> Result<Vec<u64>> {
        let mut out = Vec::new();
        if limit == 0 {
            return Ok(out);
        }
        let re = match &q.pattern {
            Some(p) => Some(
                regex::RegexBuilder::new(p)
                    .size_limit(1 << 24)
                    .build()
                    .map_err(|e| Error::BadPattern(e.to_string()))?,
            ),
            None => None,
        };
        let words: Vec<String> = q
            .text_terms
            .iter()
            .map(|t| lower(t))
            .filter(|t| !t.is_empty())
            .collect();
        let mut runs = words.clone();
        if let Some(p) = &q.pattern {
            runs.extend(query::required_literals(p));
        }
        let mut hashes = BTreeSet::new();
        for r in &runs {
            trigrams(r, |g| {
                hashes.insert(self.keys.term(TERM_TRIGRAM, g.as_bytes()));
            });
        }
        let types: Option<Vec<u64>> = q.types.as_ref().map(|ts| {
            ts.iter()
                .map(|t| self.keys.term(TERM_TYPE, t.to_ascii_lowercase().as_bytes()))
                .collect()
        });
        // A time condition: the kinds of event, and the range. Turned into a
        // set of ids when that set is small or nothing else narrows the
        // search; else (a month of a large history and a rare word) checked
        // on each candidate by its own events, which costs a lookup per
        // candidate instead of collecting and sorting the range's every id.
        let mut conds: Vec<(&[u8], i64, i64)> = Vec::new();
        if let Some(r) = &q.copied {
            conds.push((&[COPIED], r.start, r.end));
        }
        if let Some(r) = &q.pasted {
            conds.push((&[PASTED], r.start, r.end));
        }
        if let Some((t, w)) = q.around {
            let w = w.abs();
            conds.push((
                &[COPIED, PASTED],
                t.saturating_sub(w),
                t.saturating_add(w).saturating_add(1),
            ));
        }
        let narrowed = !hashes.is_empty() || types.is_some();
        let mut times: Vec<Vec<u64>> = Vec::new();
        let mut deferred: Vec<(&[u8], i64, i64)> = Vec::new();
        for (kinds, from, to) in conds {
            let count: usize = kinds.iter().map(|&k| self.time_count(k, from, to)).sum();
            if narrowed && count > self.opts.time_set_max {
                deferred.push((kinds, from, to));
                continue;
            }
            let mut v = Vec::with_capacity(count);
            for &k in kinds {
                self.time_ids(k, from, to, &mut v);
            }
            v.sort_unstable();
            v.dedup();
            times.push(v);
        }
        let need_text = !words.is_empty() || re.is_some();
        let below = before.unwrap_or(u64::MAX);

        // The log first (its ids are the newest), then the segments, newest
        // first: each holds a run of ids below the one before it.
        let parts = std::iter::once(None).chain(self.segments.iter().rev().map(Some));
        for part in parts {
            let (min, max) = match part {
                None => match (self.active.ids.first(), self.active.ids.last()) {
                    (Some(&a), Some(&b)) => (a, b),
                    _ => continue,
                },
                Some(s) if s.entries > 0 => (s.min_id, s.max_id),
                Some(_) => continue,
            };
            let upper = below.min(max.saturating_add(1));
            if upper <= min {
                continue;
            }
            let mut sets: Vec<Box<dyn IdSet + '_>> = Vec::new();
            let mut missing = false;
            for &h in &hashes {
                match part {
                    None => match self.active.postings.get(&h) {
                        Some(v) => sets.push(Box::new(Sorted(v))),
                        None => missing = true,
                    },
                    Some(s) => match s.postings(h) {
                        Some(p) => sets.push(Box::new(p)),
                        None => missing = true,
                    },
                }
            }
            if missing {
                continue;
            }
            if let Some(types) = &types {
                let mut any: Vec<Box<dyn IdSet + '_>> = Vec::new();
                for &h in types {
                    match part {
                        None => {
                            if let Some(v) = self.active.postings.get(&h) {
                                any.push(Box::new(Sorted(v)));
                            }
                        }
                        Some(s) => {
                            if let Some(p) = s.postings(h) {
                                any.push(Box::new(p));
                            }
                        }
                    }
                }
                if any.is_empty() {
                    continue;
                }
                sets.push(Box::new(Union(any)));
            }
            for t in &times {
                sets.push(Box::new(Sorted(t)));
            }
            if sets.is_empty() {
                match part {
                    None => sets.push(Box::new(Sorted(&self.active.ids))),
                    Some(s) => sets.push(Box::new(Locs(s.table(segment::S_LOCS)))),
                }
            }
            sets.sort_by_key(|s| s.len());
            let mut at = upper;
            while let Some(id) = leapfrog(&mut sets, at, min) {
                at = id;
                if self.is_deleted(id) {
                    continue;
                }
                if !deferred.is_empty() {
                    let (copies, pastes) = self.events_of(id);
                    let within = |&(kinds, from, to): &(&[u8], i64, i64)| {
                        kinds.iter().any(|&k| {
                            let ev = if k == COPIED { &copies } else { &pastes };
                            ev.iter().any(|&t| from <= t && t < to)
                        })
                    };
                    if !deferred.iter().all(within) {
                        continue;
                    }
                }
                if need_text {
                    let blob = match part {
                        None => self.active.blob(id)?.map(std::borrow::Cow::Owned),
                        Some(s) => s.blob(id).map(std::borrow::Cow::Borrowed),
                    };
                    let Some(blob) = blob else { continue };
                    if !self.matches(&blob, &words, re.as_ref()) {
                        continue;
                    }
                } else if !time_only_exists(part, &self.active, id) {
                    continue;
                }
                out.push(id);
                if out.len() >= limit {
                    return Ok(out);
                }
            }
        }
        Ok(out)
    }

    /// Whether the entry's text has every word and matches the pattern. An
    /// entry that does not open (damaged) does not match.
    fn matches(&self, b: &[u8], words: &[String], re: Option<&regex::Regex>) -> bool {
        let Some(blob) = record::parse(b) else {
            return false;
        };
        let Ok(head) = record::open_head(&self.keys, &blob) else {
            return false;
        };
        let Ok(contents) = record::open_contents(&self.keys, &blob, head) else {
            return false;
        };
        let Some(text) = primary_text(&contents) else {
            return false;
        };
        if !words.is_empty() {
            let lc = lower(text);
            if !words.iter().all(|w| lc.contains(w.as_str())) {
                return false;
            }
        }
        re.is_none_or(|re| re.is_match(text))
    }

    /// Seal the log into a segment now (nothing if it is empty).
    pub fn seal(&mut self) -> Result<()> {
        if self.active.records == 0 {
            return Ok(());
        }
        let n = self.next_file;
        let name = seg_name(n);
        let tmp = self.dir.join(format!("{name}.tmp"));
        {
            let map = self.active.map()?;
            let parts = [Part::Active(&self.active, &map)];
            // A tombstone of an entry of the log goes with the entry; one of
            // an entry of a segment stays until that segment is merged.
            segment::write(&tmp, &parts, &|id| !self.is_deleted(id), &|id| {
                self.segment_of(id).is_some()
            })?;
        }
        fs::rename(&tmp, self.dir.join(&name))?;
        let seg = Segment::open(&self.dir.join(&name), n)?;
        let log = Active::create(&self.dir.join(log_name(n + 1)), n + 1)?;
        let mut numbers: Vec<u64> = self.segments.iter().map(|s| s.number).collect();
        numbers.push(n);
        self.write_manifest(n + 2, &numbers, n + 1)?;
        let old = std::mem::replace(&mut self.active, log);
        crypto_remove(&old.path);
        self.next_file = n + 2;
        self.segments.push(seg);
        if self.opts.auto_merge {
            self.merge_tiers()?;
        }
        Ok(())
    }

    fn maybe_seal(&mut self) -> Result<()> {
        if self.active.len >= self.opts.seal_bytes {
            self.seal()?;
        }
        Ok(())
    }

    fn write_manifest(&self, next_file: u64, segments: &[u64], active: u64) -> Result<()> {
        let m = Manifest {
            next_file,
            next_id: self.next_id,
            keycheck: self.keycheck.clone(),
            active,
            segments: segments.to_vec(),
        };
        Ok(replace_file(&self.dir, "manifest", &m.encode())?)
    }

    fn tier(&self, size: u64) -> u32 {
        let unit = (self.opts.seal_bytes / 2).max(1);
        let f = self.opts.fanout.max(2) as u64;
        let mut s = size / unit;
        let mut t = 0;
        while s >= f {
            s /= f;
            t += 1;
        }
        t
    }

    /// Merge the newest run of segments of one tier while it is `fanout`
    /// long.
    fn merge_tiers(&mut self) -> Result<()> {
        loop {
            let n = self.segments.len();
            let f = self.opts.fanout.max(2);
            if n < f {
                return Ok(());
            }
            let t = self.tier(self.segments[n - 1].size);
            let mut lo = n - 1;
            while lo > 0 && self.tier(self.segments[lo - 1].size) == t {
                lo -= 1;
            }
            if n - lo < f {
                return Ok(());
            }
            self.merge(lo..n)?;
        }
    }

    /// Seal the log and merge every segment into one: a history at its
    /// smallest, its deleted entries gone from the disk.
    pub fn compact(&mut self) -> Result<()> {
        self.seal()?;
        if self.segments.len() > 1 || self.segments.iter().any(|s| s.is_tomb_any()) {
            self.merge(0..self.segments.len())?;
        }
        Ok(())
    }

    /// Merge the segments of `range` (neighbours) into one.
    fn merge(&mut self, range: Range<usize>) -> Result<()> {
        if range.is_empty() {
            return Ok(());
        }
        let n = self.next_file;
        let name = seg_name(n);
        let tmp = self.dir.join(format!("{name}.tmp"));
        {
            let parts: Vec<Part> = self.segments[range.clone()]
                .iter()
                .map(Part::Sealed)
                .collect();
            let outside = |id: u64| {
                self.active.contains(id)
                    || self
                        .segments
                        .iter()
                        .enumerate()
                        .any(|(i, s)| !range.contains(&i) && s.blob(id).is_some())
            };
            segment::write(&tmp, &parts, &|id| !self.is_deleted(id), &outside)?;
        }
        fs::rename(&tmp, self.dir.join(&name))?;
        let seg = Segment::open(&self.dir.join(&name), n)?;
        let mut numbers: Vec<u64> = Vec::new();
        for (i, s) in self.segments.iter().enumerate() {
            if i == range.start {
                numbers.push(n);
            }
            if !range.contains(&i) {
                numbers.push(s.number);
            }
        }
        self.write_manifest(n + 1, &numbers, self.active.number)?;
        self.next_file = n + 1;
        let old: Vec<Segment> = self.segments.splice(range, [seg]).collect();
        for s in old {
            let path = s.path.clone();
            drop(s);
            crypto_remove(&path);
        }
        Ok(())
    }
}

/// Without a text to check, an id from the time index is an answer if its
/// entry is in this part (an event may outlive its entry's merge).
fn time_only_exists(part: Option<&Segment>, active: &Active, id: u64) -> bool {
    match part {
        None => active.contains(id),
        Some(s) => s.blob(id).is_some(),
    }
}

fn crypto_remove(path: &Path) {
    let _ = fs::remove_file(path);
}
