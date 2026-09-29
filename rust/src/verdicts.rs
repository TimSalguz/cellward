//! The firewall's decisions for an instance's flows (`docs/FIREWALL.md` §9,
//! stages 4 and 5, 2026-09-29): whether a new flow of a program of the
//! instance may go — written by the instance's keeper, read by its relay.
//!
//! **Why a table of its own.** The relay holds the first frames of a flow
//! it has no decision for (`crate::relay`, the gate) and wakes the keeper;
//! the keeper finds the flow's program (`crate::owners`), decides by the
//! container's rules (`crate::netrules`) — or asks the person — and writes
//! the decision here, then wakes the relay back. The relay reads the file
//! through a mapping made before its filter was sealed: no system call, as
//! for the flows it writes (`crate::flows`). One writer — the keeper — and
//! one reader.
//!
//! **Layout.** A header ([`MAGIC`]) and [`SLOTS`] slots of [`SLOT`] bytes: a
//! sequence number (odd while the slot is being written), the protocol, the
//! family and the decision, the two ports, the other end's address. A
//! reader that finds the sequence odd, or changed by the time it has read
//! the slot, reads again: a slot is never taken half written. A full table
//! gives the oldest slot to the new decision; the relay keeps what it has
//! read of a live flow, and a flow whose decision is gone from both is asked
//! about again — decided again by the rules, not guessed.
//!
//! **A decision is the flow's**, by its whole key — protocol, the instance's
//! port, the other end's address and port —, never its port's alone: a port
//! freed and taken by another program inherits nothing.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::ptr::NonNull;
use std::sync::atomic::{fence, AtomicU32, AtomicU64, Ordering};

use crate::flows::Key;

/// The decisions' file in an instance's directory.
pub const FILE: &str = "verdicts";
/// Its first eight bytes: which layout it has.
pub const MAGIC: [u8; 8] = *b"cwverdi1";
/// How many decisions it keeps; past these, the oldest goes.
pub const SLOTS: usize = 2048;
const HEADER: usize = 64;
const SLOT: usize = 32;
/// Its length.
pub const LEN: usize = HEADER + SLOTS * SLOT;

/// A slot's cells: seq, meta (protocol, IPv6, decision), ports (the
/// instance's in the high half), the address (two u64).
mod cell {
    pub const SEQ: usize = 0;
    pub const META: usize = 4;
    pub const PORTS: usize = 8;
    pub const ADDR: usize = 16;
}

const V6: u32 = 1 << 8;

/// What a flow may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
}

impl Verdict {
    fn code(self) -> u32 {
        match self {
            Self::Allow => 1,
            Self::Deny => 2,
        }
    }

    fn of(code: u32) -> Option<Self> {
        match code {
            1 => Some(Self::Allow),
            2 => Some(Self::Deny),
            _ => None,
        }
    }
}

/// Make the decisions' file of an instance anew (the keeper's, before its
/// relay starts): the right size, the magic in, nothing decided.
pub fn create(dir: &Path) -> io::Result<std::fs::File> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir.join(FILE))?;
    file.set_len(LEN as u64)?;
    file.write_all(&MAGIC)?;
    file.flush()?;
    Ok(file)
}

/// The mapped table: the keeper's to write ([`Table::put`]), the relay's to
/// read ([`Table::get`]).
pub struct Table {
    base: NonNull<u8>,
    /// The writer's: where each decision is, and the slot written next.
    index: HashMap<Key, usize>,
    keys: Vec<Option<Key>>,
    next: usize,
}

// SAFETY: the mapping is touched only through atomic operations on its
// cells.
unsafe impl Send for Table {}

impl Table {
    /// Map the decisions' file open at `fd`; to write, with what is in it
    /// indexed. A file of another layout, or shorter, is refused.
    pub fn map(fd: BorrowedFd<'_>, write: bool) -> io::Result<Table> {
        // SAFETY: an all-zero stat is a valid one to fill.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid descriptor and a stat to fill.
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0
            || usize::try_from(st.st_size).ok().is_none_or(|len| len < LEN)
        {
            return Err(io::Error::other("not a decisions' file of this size"));
        }
        let prot = if write {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };
        // SAFETY: a new mapping of LEN bytes of a descriptor of ours, whose
        // file is at least that long.
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
        let base = NonNull::new(ptr.cast::<u8>()).ok_or_else(io::Error::last_os_error)?;
        let mut table = Table {
            base,
            index: HashMap::new(),
            keys: vec![None; SLOTS],
            next: 0,
        };
        // SAFETY: the first eight bytes of our mapping, read-only here.
        let magic = unsafe { std::slice::from_raw_parts(base.as_ptr(), MAGIC.len()) };
        if magic != MAGIC {
            table.close();
            return Err(io::Error::other("not a decisions' file"));
        }
        if write {
            table.take_over();
        }
        Ok(table)
    }

    fn u32_cell(&self, at: usize) -> &AtomicU32 {
        // SAFETY: `at` is a 4-aligned offset inside the mapping (the header
        // and the slots are multiples of 8), which lives as long as `self`.
        unsafe { &*self.base.as_ptr().add(at).cast::<AtomicU32>() }
    }

    fn u64_cell(&self, at: usize) -> &AtomicU64 {
        // SAFETY: as `u32_cell`, 8-aligned.
        unsafe { &*self.base.as_ptr().add(at).cast::<AtomicU64>() }
    }

    fn slot(i: usize) -> usize {
        HEADER + i * SLOT
    }

    /// A writer's start on a file a keeper before it wrote: a slot being
    /// written when it died is emptied, the rest indexed.
    fn take_over(&mut self) {
        for i in 0..SLOTS {
            let s = Self::slot(i);
            let seq = self.u32_cell(s + cell::SEQ);
            if !seq.load(Ordering::Acquire).is_multiple_of(2) {
                self.u32_cell(s + cell::META).store(0, Ordering::Relaxed);
                seq.fetch_add(1, Ordering::Release);
            }
            if let Some((key, _)) = self.read_slot(i) {
                self.index.insert(key, i);
                self.keys[i] = Some(key);
                self.next = (i + 1) % SLOTS;
            }
        }
    }

    /// The decision in slot `i`, read whole.
    fn read_slot(&self, i: usize) -> Option<(Key, Verdict)> {
        let s = Self::slot(i);
        let seq = self.u32_cell(s + cell::SEQ);
        loop {
            let before = seq.load(Ordering::Acquire);
            if !before.is_multiple_of(2) {
                std::hint::spin_loop();
                continue;
            }
            let meta = self.u32_cell(s + cell::META).load(Ordering::Relaxed);
            let ports = self.u32_cell(s + cell::PORTS).load(Ordering::Relaxed);
            let hi = self.u64_cell(s + cell::ADDR).load(Ordering::Relaxed);
            let lo = self.u64_cell(s + cell::ADDR + 8).load(Ordering::Relaxed);
            fence(Ordering::Acquire);
            if seq.load(Ordering::Relaxed) != before {
                continue;
            }
            let verdict = Verdict::of((meta >> 16) & 0xff)?;
            let remote = if meta & V6 != 0 {
                IpAddr::V6(Ipv6Addr::from((u128::from(hi) << 64) | u128::from(lo)))
            } else {
                IpAddr::V4(Ipv4Addr::from(lo as u32))
            };
            let key = Key {
                proto: (meta & 0xff) as u8,
                lport: (ports >> 16) as u16,
                remote,
                rport: (ports & 0xffff) as u16,
            };
            return Some((key, verdict));
        }
    }

    /// The decision for `key`, if there is one (the relay's).
    pub fn get(&self, key: &Key) -> Option<Verdict> {
        (0..SLOTS)
            .filter_map(|i| self.read_slot(i))
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    /// Decide `key` (the keeper's): its slot, or the oldest.
    pub fn put(&mut self, key: Key, verdict: Verdict) {
        let i = match self.index.get(&key) {
            Some(&i) => i,
            None => {
                let i = self.next;
                self.next = (i + 1) % SLOTS;
                if let Some(old) = self.keys[i].replace(key) {
                    self.index.remove(&old);
                }
                self.index.insert(key, i);
                i
            }
        };
        let s = Self::slot(i);
        let (v6, hi, lo) = match key.remote {
            IpAddr::V4(a) => (0, 0, u64::from(u32::from(a))),
            IpAddr::V6(a) => {
                let n = u128::from(a);
                (V6, (n >> 64) as u64, n as u64)
            }
        };
        let seq = self.u32_cell(s + cell::SEQ);
        seq.fetch_add(1, Ordering::Relaxed);
        fence(Ordering::Release);
        self.u32_cell(s + cell::META).store(
            u32::from(key.proto) | v6 | (verdict.code() << 16),
            Ordering::Relaxed,
        );
        self.u32_cell(s + cell::PORTS).store(
            (u32::from(key.lport) << 16) | u32::from(key.rport),
            Ordering::Relaxed,
        );
        self.u64_cell(s + cell::ADDR).store(hi, Ordering::Relaxed);
        self.u64_cell(s + cell::ADDR + 8)
            .store(lo, Ordering::Relaxed);
        seq.fetch_add(1, Ordering::Release);
    }

    pub fn close(self) {
        // SAFETY: our own mapping of LEN bytes, not touched after this.
        unsafe { libc::munmap(self.base.as_ptr().cast(), LEN) };
    }
}

/// Open the decisions' file of the instance directory `dir` for its keeper.
pub fn open_writer(dir: &Path) -> io::Result<Table> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir.join(FILE))?;
    Table::map(file.as_fd(), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(lport: u16, remote: &str, rport: u16) -> Key {
        Key {
            proto: crate::flows::TCP,
            lport,
            remote: remote.parse().unwrap(),
            rport,
        }
    }

    /// Decided by the whole key, both families; a decision changes in
    /// place; a full table gives its oldest slot to the next; another
    /// mapping — the relay's — reads what the keeper wrote, and a keeper of
    /// later takes over what is there.
    #[test]
    fn a_decision_is_the_flows_and_read_as_written() {
        let dir = std::env::temp_dir().join(format!("vz-verdicts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = create(&dir).unwrap();
        let mut w = Table::map(file.as_fd(), true).unwrap();
        let reader = Table::map(file.as_fd(), false).unwrap();
        let a = key(40000, "93.184.216.34", 443);
        let b = key(40000, "93.184.216.35", 443);
        let c = key(40001, "2001:db8::1", 80);
        w.put(a, Verdict::Allow);
        w.put(c, Verdict::Deny);
        assert_eq!(reader.get(&a), Some(Verdict::Allow));
        assert_eq!(reader.get(&b), None, "the port alone decides nothing");
        assert_eq!(reader.get(&c), Some(Verdict::Deny));
        w.put(a, Verdict::Deny);
        assert_eq!(reader.get(&a), Some(Verdict::Deny));
        w.close();
        let mut again = open_writer(&dir).unwrap();
        assert_eq!(again.index.len(), 2, "taken over");
        for p in 0..SLOTS as u16 {
            again.put(key(1000 + p, "10.0.0.1", 53), Verdict::Allow);
        }
        assert_eq!(reader.get(&c), None, "the oldest gave its slot");
        assert_eq!(
            reader.get(&key(1000 + SLOTS as u16 - 1, "10.0.0.1", 53)),
            Some(Verdict::Allow)
        );
        again.close();
        reader.close();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
