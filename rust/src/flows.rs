//! The connections of a container's instance, as its frame relay sees them —
//! stage 2 of the network monitor (`docs/FIREWALL.md` §2, §3, 2026-09-28).
//!
//! **Where.** Every frame of an instance passes its relay (`crate::relay`),
//! between its tap and its zone's passt. The relay reads each frame's headers
//! — Ethernet, IPv4 or IPv6, TCP or UDP ([`frame`]) — and keeps a table of
//! flows: the protocol, the instance's own port, the other end's address and
//! port, the bytes and packets each way, when it was first and last seen. A
//! DNS answer that passes (UDP from port 53, to the instance's constant
//! forwarder or anywhere else) is read too ([`dns`]): each address it gives
//! is noted with the name asked, so that a flow to `149.154.167.50` can be
//! said to be `api.telegram.org`.
//!
//! **What is kept, and where.** A file of the instance's directory, [`FILE`],
//! of a fixed layout and size ([`LEN`]): a header, [`SLOTS`] flow slots and
//! [`NAMES`] name slots, the relay's writes and a reader's reads all through
//! shared mappings of it, with no system call on the relay's side — its
//! seccomp filter lets none it does not need (`crate::traffic` counts the
//! same way). Each slot has a sequence number, odd while it is being
//! written: a reader that finds it odd, or changed by the time it has read
//! the slot, reads it again — a slot is never seen half written. A full table
//! gives the slot of the flow seen longest ago to the new one. The file is the
//! user's alone (0600): which names a container asked is nobody else's.
//!
//! **Nothing here decides.** The table is a record; the wall is the
//! instance's rules. Which program a flow is is looked up by the reader, by
//! the instance's own port (`crate::sockdiag` in the instance's network,
//! `/proc` of its programs) — the relay knows no processes.
//!
//! **Parsing untrusted frames.** A frame is the instance's programs' own, and
//! every length and offset in it is checked against the frame before it is
//! read; a frame that does not read is simply not noted (it is relayed all
//! the same — the relay's bounds are its own, `relay::check_len`).

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::ptr::NonNull;
use std::sync::atomic::{fence, AtomicU32, AtomicU64, Ordering};

/// The flows' file in an instance's directory.
pub const FILE: &str = "flows";
/// Its first eight bytes: which layout it has.
pub const MAGIC: [u8; 8] = *b"cwflows1";
/// How many flows it keeps; past these, the one seen longest ago goes.
pub const SLOTS: usize = 4096;
/// How many names it keeps, in turn.
pub const NAMES: usize = 1024;
const HEADER: usize = 64;
const SLOT: usize = 64;
const NAME_SLOT: usize = 288;
/// The longest name kept (a DNS name is at most 253 characters).
pub const NAME_MAX: usize = 256;
/// Its length.
pub const LEN: usize = HEADER + SLOTS * SLOT + NAMES * NAME_SLOT;

pub const TCP: u8 = 6;
pub const UDP: u8 = 17;
pub const ICMP: u8 = 1;
pub const ICMP6: u8 = 58;

/// A flow, by the instance's side of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key {
    pub proto: u8,
    /// The instance's own port (0 where the protocol has none).
    pub lport: u16,
    pub remote: IpAddr,
    pub rport: u16,
}

/// What one frame is, for the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen<'a> {
    pub key: Key,
    /// From the instance (read off its tap).
    pub outbound: bool,
    /// The whole frame's length.
    pub len: usize,
    /// The payload of a UDP datagram to or from port 53.
    pub dns: Option<&'a [u8]>,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// An Ethernet frame's flow; `None` for one that is not IPv4 or IPv6, or
/// does not read.
pub fn frame(buf: &[u8], outbound: bool) -> Option<Seen<'_>> {
    let (proto, src, dst, payload, whole) = match u16_at(buf, 12)? {
        0x0800 => {
            let ip = buf.get(14..)?;
            let ihl = usize::from(*ip.first()? & 0x0f) * 4;
            if ihl < 20 || ip.len() < ihl {
                return None;
            }
            let src = IpAddr::V4(Ipv4Addr::from(u32_at(ip, 12)?));
            let dst = IpAddr::V4(Ipv4Addr::from(u32_at(ip, 16)?));
            // A fragment after the first has no ports.
            let first = u16_at(ip, 6)? & 0x1fff == 0;
            (ip[9], src, dst, ip.get(ihl..)?, first)
        }
        0x86dd => {
            let ip = buf.get(14..)?;
            let src: [u8; 16] = ip.get(8..24)?.try_into().ok()?;
            let dst: [u8; 16] = ip.get(24..40)?.try_into().ok()?;
            (
                ip[6],
                IpAddr::V6(Ipv6Addr::from(src)),
                IpAddr::V6(Ipv6Addr::from(dst)),
                ip.get(40..)?,
                true,
            )
        }
        _ => return None,
    };
    let remote = if outbound { dst } else { src };
    let (sport, dport, dns) = match proto {
        TCP | UDP if whole => {
            let sport = u16_at(payload, 0)?;
            let dport = u16_at(payload, 2)?;
            let dns = (proto == UDP && (sport == 53 || dport == 53))
                .then(|| payload.get(8..))
                .flatten();
            (sport, dport, dns)
        }
        _ => (0, 0, None),
    };
    let (lport, rport) = if outbound {
        (sport, dport)
    } else {
        (dport, sport)
    };
    Some(Seen {
        key: Key {
            proto,
            lport,
            remote,
            rport,
        },
        outbound,
        len: buf.len(),
        dns,
    })
}

/// A DNS name at `at` in `msg`: its labels, following compression pointers
/// (at most a few, and never forward into a loop); the offset after it at
/// its first place.
fn dns_name(msg: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = usize::from(*msg.get(at)?);
        if len == 0 {
            return Some((name, end.unwrap_or(at + 1)));
        }
        if len & 0xc0 == 0xc0 {
            let to = usize::from(u16_at(msg, at)? & 0x3fff);
            jumps += 1;
            if jumps > 8 || to >= at {
                return None;
            }
            end.get_or_insert(at + 2);
            at = to;
            continue;
        }
        if len > 63 {
            return None;
        }
        let label = msg.get(at + 1..at + 1 + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        for &c in label {
            // What a name may be; anything else as `?`.
            let c = if c.is_ascii_alphanumeric() || c == b'-' || c == b'_' {
                c.to_ascii_lowercase() as char
            } else {
                '?'
            };
            name.push(c);
        }
        if name.len() > NAME_MAX {
            return None;
        }
        at += 1 + len;
    }
}

/// A DNS answer's question name and the addresses it gives for it (A,
/// AAAA); `None` for a query, or a message that does not read.
pub fn dns(msg: &[u8]) -> Option<(String, Vec<IpAddr>)> {
    let flags = u16_at(msg, 2)?;
    let (questions, answers) = (u16_at(msg, 4)?, u16_at(msg, 6)?);
    if flags & 0x8000 == 0 || questions != 1 {
        return None;
    }
    let (qname, mut at) = dns_name(msg, 12)?;
    at += 4;
    let mut addrs = Vec::new();
    for _ in 0..answers.min(64) {
        let (_, after) = dns_name(msg, at)?;
        let kind = u16_at(msg, after)?;
        let len = usize::from(u16_at(msg, after + 8)?);
        let data = msg.get(after + 10..after + 10 + len)?;
        match (kind, len) {
            (1, 4) => addrs.push(IpAddr::V4(Ipv4Addr::from(u32_at(data, 0)?))),
            (28, 16) => {
                let a: [u8; 16] = data.try_into().ok()?;
                addrs.push(IpAddr::V6(Ipv6Addr::from(a)));
            }
            _ => {}
        }
        at = after + 10 + len;
    }
    Some((qname, addrs))
}

/// Seconds since the Unix epoch, as the table keeps them.
pub fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX))
}

/// Make the flows' file of an instance anew in `dir`: empty. The user's
/// alone.
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

/// A flow as a reader finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    pub key: Key,
    pub first: u32,
    pub last: u32,
    pub out_bytes: u64,
    pub in_bytes: u64,
    pub out_packets: u32,
    pub in_packets: u32,
}

/// A name as a reader finds it: the address a DNS answer gave for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    pub addr: IpAddr,
    pub name: String,
    pub at: u32,
}

/// The file mapped: the relay writes it, a reader reads it. Not unmapped by
/// dropping it (the relay keeps its mapping to its end; a reader lets it go
/// with [`Table::close`]).
pub struct Table {
    base: NonNull<u8>,
    /// Where each flow is, and what each slot holds (the writer's).
    index: HashMap<Key, usize>,
    keys: Vec<Option<Key>>,
    /// The slots holding nothing, the lowest last.
    free: Vec<usize>,
    /// The name slot written next.
    next_name: usize,
}

// SAFETY: the mapping is touched only through atomic operations on its
// cells.
unsafe impl Send for Table {}

/// A flow slot's cells ([`SLOT`] bytes): seq, meta (protocol, IPv6, used),
/// ports, first, remote (two u64), out bytes, in bytes, packets (out, in),
/// last.
mod cell {
    pub const SEQ: usize = 0;
    pub const META: usize = 4;
    pub const PORTS: usize = 8;
    pub const FIRST: usize = 12;
    pub const ADDR: usize = 16;
    pub const OUT: usize = 32;
    pub const IN: usize = 40;
    pub const OUT_PKT: usize = 48;
    pub const IN_PKT: usize = 52;
    pub const LAST: usize = 56;
}

const USED: u32 = 1 << 9;
const V6: u32 = 1 << 8;

fn addr_words(a: IpAddr) -> (u64, u64, bool) {
    let (bytes, v6) = match a {
        IpAddr::V4(v4) => (v4.to_ipv6_mapped().octets(), false),
        IpAddr::V6(v6) => (v6.octets(), true),
    };
    let hi = u64::from_be_bytes(bytes[..8].try_into().unwrap_or([0; 8]));
    let lo = u64::from_be_bytes(bytes[8..].try_into().unwrap_or([0; 8]));
    (hi, lo, v6)
}

fn addr_of(hi: u64, lo: u64, v6: bool) -> IpAddr {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&hi.to_be_bytes());
    bytes[8..].copy_from_slice(&lo.to_be_bytes());
    let a = Ipv6Addr::from(bytes);
    match (v6, a.to_ipv4_mapped()) {
        (false, Some(v4)) => IpAddr::V4(v4),
        _ => IpAddr::V6(a),
    }
}

impl Table {
    /// Map the flows' file open at `fd`; to write, with the flows already
    /// in it indexed (a relay of a later attach goes on with them). A file
    /// of another layout, or shorter, is refused.
    pub fn map(fd: BorrowedFd<'_>, write: bool) -> io::Result<Table> {
        // SAFETY: an all-zero stat is a valid one to fill.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid descriptor and a stat to fill.
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0
            || usize::try_from(st.st_size).ok().is_none_or(|len| len < LEN)
        {
            return Err(io::Error::other("not a flows' file of this size"));
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
        let base =
            NonNull::new(ptr.cast::<u8>()).ok_or_else(|| io::Error::other("null mapping"))?;
        let mut table = Table {
            base,
            // A writer's index at its full size now: it never grows after the
            // relay's seal.
            index: HashMap::with_capacity(if write { SLOTS } else { 0 }),
            keys: Vec::new(),
            free: Vec::new(),
            next_name: 0,
        };
        // SAFETY: the mapping's first 8 bytes, inside it.
        if unsafe { std::slice::from_raw_parts(base.as_ptr(), 8) } != MAGIC {
            table.close();
            return Err(io::Error::other("not a flows' file of this layout"));
        }
        if write {
            table.take_over();
        }
        Ok(table)
    }

    fn u32_cell(&self, at: usize) -> &AtomicU32 {
        debug_assert!(at.is_multiple_of(4) && at + 4 <= LEN);
        // SAFETY: a 4-aligned cell inside the mapping, touched only
        // atomically, alive as long as `self`.
        unsafe { &*self.base.as_ptr().add(at).cast::<AtomicU32>() }
    }

    fn u64_cell(&self, at: usize) -> &AtomicU64 {
        debug_assert!(at.is_multiple_of(8) && at + 8 <= LEN);
        // SAFETY: as above, 8-aligned.
        unsafe { &*self.base.as_ptr().add(at).cast::<AtomicU64>() }
    }

    fn slot(i: usize) -> usize {
        HEADER + i * SLOT
    }

    fn name_slot(i: usize) -> usize {
        HEADER + SLOTS * SLOT + i * NAME_SLOT
    }

    /// A writer's start on a file a relay before it wrote (a later attach
    /// of the same instance; the one before was killed and reaped first,
    /// `bridge::Link::close`): a slot it was writing when it died is
    /// emptied, its sequence made even again; the flows in it are indexed,
    /// and the names go on after the newest.
    fn take_over(&mut self) {
        for s in (0..SLOTS)
            .map(Self::slot)
            .chain((0..NAMES).map(Self::name_slot))
        {
            let seq = self.u32_cell(s);
            if !seq.load(Ordering::Acquire).is_multiple_of(2) {
                self.u32_cell(s + cell::META).store(0, Ordering::Relaxed);
                seq.fetch_add(1, Ordering::Release);
            }
        }
        self.keys = vec![None; SLOTS];
        for (i, flow) in self.flows_at() {
            self.index.insert(flow.key, i);
            self.keys[i] = Some(flow.key);
        }
        self.free = (0..SLOTS)
            .rev()
            .filter(|&i| self.keys[i].is_none())
            .collect();
        let names = self.names_at();
        self.next_name = if names.len() < NAMES {
            let mut taken = vec![false; NAMES];
            for (i, _) in &names {
                taken[*i] = true;
            }
            taken.iter().position(|t| !t).unwrap_or(0)
        } else {
            names
                .iter()
                .min_by_key(|(_, n)| n.at)
                .map_or(0, |(i, _)| *i)
        };
    }

    /// The slot for `key`: its own, a free one, or the one seen longest ago
    /// (whose flow leaves the index).
    fn slot_for(&mut self, key: Key) -> usize {
        if let Some(&i) = self.index.get(&key) {
            return i;
        }
        let i = self.free.pop().unwrap_or_else(|| {
            (0..SLOTS)
                .min_by_key(|&i| {
                    self.u32_cell(Self::slot(i) + cell::LAST)
                        .load(Ordering::Relaxed)
                })
                .unwrap_or(0)
        });
        if let Some(old) = self.keys[i].replace(key) {
            self.index.remove(&old);
        }
        self.index.insert(key, i);
        i
    }

    /// A frame seen, at `now`: its flow's slot made or brought up to date,
    /// and a DNS answer's names noted.
    pub fn note(&mut self, seen: &Seen<'_>, now: u32) {
        let fresh = !self.index.contains_key(&seen.key);
        let i = self.slot_for(seen.key);
        let s = Self::slot(i);
        let seq = self.u32_cell(s + cell::SEQ);
        seq.fetch_add(1, Ordering::Relaxed);
        fence(Ordering::Release);
        if fresh {
            let (hi, lo, v6) = addr_words(seen.key.remote);
            let meta = USED | u32::from(seen.key.proto) | if v6 { V6 } else { 0 };
            self.u32_cell(s + cell::META).store(meta, Ordering::Relaxed);
            self.u32_cell(s + cell::PORTS).store(
                (u32::from(seen.key.lport) << 16) | u32::from(seen.key.rport),
                Ordering::Relaxed,
            );
            self.u64_cell(s + cell::ADDR).store(hi, Ordering::Relaxed);
            self.u64_cell(s + cell::ADDR + 8)
                .store(lo, Ordering::Relaxed);
            self.u32_cell(s + cell::FIRST).store(now, Ordering::Relaxed);
            for c in [cell::OUT, cell::IN] {
                self.u64_cell(s + c).store(0, Ordering::Relaxed);
            }
            for c in [cell::OUT_PKT, cell::IN_PKT] {
                self.u32_cell(s + c).store(0, Ordering::Relaxed);
            }
        }
        let (bytes, packets) = if seen.outbound {
            (cell::OUT, cell::OUT_PKT)
        } else {
            (cell::IN, cell::IN_PKT)
        };
        self.u64_cell(s + bytes)
            .fetch_add(seen.len as u64, Ordering::Relaxed);
        self.u32_cell(s + packets).fetch_add(1, Ordering::Relaxed);
        self.u32_cell(s + cell::LAST).store(now, Ordering::Relaxed);
        seq.fetch_add(1, Ordering::Release);
        if let Some((name, addrs)) = seen.dns.filter(|_| !seen.outbound).and_then(dns) {
            for addr in addrs.into_iter().take(16) {
                self.note_name(addr, &name, now);
            }
        }
    }

    fn note_name(&mut self, addr: IpAddr, name: &str, now: u32) {
        let i = self.next_name;
        self.next_name = (i + 1) % NAMES;
        let s = Self::name_slot(i);
        let seq = self.u32_cell(s);
        seq.fetch_add(1, Ordering::Relaxed);
        fence(Ordering::Release);
        let bytes = name.as_bytes();
        let len = bytes.len().min(NAME_MAX);
        let (hi, lo, v6) = addr_words(addr);
        let meta = USED | if v6 { V6 } else { 0 } | ((len as u32) << 16);
        self.u32_cell(s + cell::META).store(meta, Ordering::Relaxed);
        self.u32_cell(s + 8).store(now, Ordering::Relaxed);
        self.u64_cell(s + 16).store(hi, Ordering::Relaxed);
        self.u64_cell(s + 24).store(lo, Ordering::Relaxed);
        for w in 0..NAME_MAX / 8 {
            let mut word = [0u8; 8];
            for (j, b) in word.iter_mut().enumerate() {
                if let Some(&c) = bytes.get(w * 8 + j).filter(|_| w * 8 + j < len) {
                    *b = c;
                }
            }
            self.u64_cell(s + 32 + w * 8)
                .store(u64::from_le_bytes(word), Ordering::Relaxed);
        }
        seq.fetch_add(1, Ordering::Release);
    }

    /// Read a slot at `s` with `read`, again while it is being written or
    /// changed meanwhile; `None` after a few tries (the writer is busy
    /// with it), or for an unused one.
    fn stable<T>(&self, s: usize, read: impl Fn() -> Option<T>) -> Option<T> {
        let seq = self.u32_cell(s);
        for _ in 0..16 {
            let before = seq.load(Ordering::Acquire);
            if !before.is_multiple_of(2) {
                std::hint::spin_loop();
                continue;
            }
            let got = read();
            fence(Ordering::Acquire);
            if seq.load(Ordering::Relaxed) == before {
                return got;
            }
        }
        None
    }

    fn flows_at(&self) -> Vec<(usize, Flow)> {
        (0..SLOTS)
            .filter_map(|i| {
                let s = Self::slot(i);
                self.stable(s, || {
                    let meta = self.u32_cell(s + cell::META).load(Ordering::Relaxed);
                    if meta & USED == 0 {
                        return None;
                    }
                    let ports = self.u32_cell(s + cell::PORTS).load(Ordering::Relaxed);
                    let remote = addr_of(
                        self.u64_cell(s + cell::ADDR).load(Ordering::Relaxed),
                        self.u64_cell(s + cell::ADDR + 8).load(Ordering::Relaxed),
                        meta & V6 != 0,
                    );
                    Some(Flow {
                        key: Key {
                            proto: (meta & 0xff) as u8,
                            lport: (ports >> 16) as u16,
                            remote,
                            rport: (ports & 0xffff) as u16,
                        },
                        first: self.u32_cell(s + cell::FIRST).load(Ordering::Relaxed),
                        last: self.u32_cell(s + cell::LAST).load(Ordering::Relaxed),
                        out_bytes: self.u64_cell(s + cell::OUT).load(Ordering::Relaxed),
                        in_bytes: self.u64_cell(s + cell::IN).load(Ordering::Relaxed),
                        out_packets: self.u32_cell(s + cell::OUT_PKT).load(Ordering::Relaxed),
                        in_packets: self.u32_cell(s + cell::IN_PKT).load(Ordering::Relaxed),
                    })
                })
                .map(|f| (i, f))
            })
            .collect()
    }

    /// Every flow in the table.
    pub fn flows(&self) -> Vec<Flow> {
        self.flows_at().into_iter().map(|(_, f)| f).collect()
    }

    /// Every name in the table.
    pub fn names(&self) -> Vec<Name> {
        self.names_at().into_iter().map(|(_, n)| n).collect()
    }

    fn names_at(&self) -> Vec<(usize, Name)> {
        (0..NAMES)
            .filter_map(|i| {
                let s = Self::name_slot(i);
                self.stable(s, || {
                    let meta = self.u32_cell(s + cell::META).load(Ordering::Relaxed);
                    if meta & USED == 0 {
                        return None;
                    }
                    let len = ((meta >> 16) as usize).min(NAME_MAX);
                    let mut bytes = Vec::with_capacity(NAME_MAX);
                    for w in 0..NAME_MAX / 8 {
                        bytes.extend_from_slice(
                            &self
                                .u64_cell(s + 32 + w * 8)
                                .load(Ordering::Relaxed)
                                .to_le_bytes(),
                        );
                    }
                    bytes.truncate(len);
                    Some(Name {
                        addr: addr_of(
                            self.u64_cell(s + 16).load(Ordering::Relaxed),
                            self.u64_cell(s + 24).load(Ordering::Relaxed),
                            meta & V6 != 0,
                        ),
                        name: String::from_utf8_lossy(&bytes).into_owned(),
                        at: self.u32_cell(s + 8).load(Ordering::Relaxed),
                    })
                })
                .map(|n| (i, n))
            })
            .collect()
    }

    /// Let the mapping go.
    pub fn close(self) {
        // SAFETY: our own mapping of LEN bytes, not touched after this.
        unsafe { libc::munmap(self.base.as_ptr().cast(), LEN) };
    }
}

/// The flows and names in the flows' file of the instance directory `dir`.
pub fn read(dir: &Path) -> Option<(Vec<Flow>, Vec<Name>)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir.join(FILE))
        .ok()?;
    let table = Table::map(file.as_fd(), false).ok()?;
    let got = (table.flows(), table.names());
    table.close();
    Some(got)
}

/// The latest name noted for `addr`.
pub fn name_of<'a>(names: &'a [Name], addr: &IpAddr) -> Option<&'a str> {
    names
        .iter()
        .filter(|n| n.addr == *addr)
        .max_by_key(|n| n.at)
        .map(|n| n.name.as_str())
}

// --- THE REPORT -------------------------------------------------------------

/// A protocol, as the report names it.
pub fn proto_name(proto: u8) -> String {
    match proto {
        TCP => "tcp".to_owned(),
        UDP => "udp".to_owned(),
        ICMP => "icmp".to_owned(),
        ICMP6 => "icmpv6".to_owned(),
        2 => "igmp".to_owned(),
        n => n.to_string(),
    }
}

/// An address and port, as a person reads them.
fn endpoint(addr: &IpAddr, port: u16, proto: u8) -> String {
    match (addr, proto) {
        (IpAddr::V6(a), TCP | UDP) => format!("[{a}]:{port}"),
        (IpAddr::V4(a), TCP | UDP) => format!("{a}:{port}"),
        _ => addr.to_string(),
    }
}

/// A running instance's flows and names; `None` for one without a table
/// (of an earlier build, or whose file could not be made).
struct Listed {
    id: String,
    container: Option<String>,
    network: String,
    table: Option<(Vec<Flow>, Vec<Name>)>,
}

fn listed(tools: &crate::tools::Tools) -> Vec<Listed> {
    let mut out: Vec<Listed> = crate::instance::running(&tools.state)
        .into_iter()
        .map(|i| Listed {
            container: crate::instance::container_of(&i.id).map(str::to_owned),
            table: read(&i.dir).map(|(mut flows, names)| {
                flows.sort_by(|a, b| {
                    (b.last, b.out_bytes.saturating_add(b.in_bytes))
                        .cmp(&(a.last, a.out_bytes.saturating_add(a.in_bytes)))
                });
                (flows, names)
            }),
            network: i.network,
            id: i.id,
        })
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

/// The instance's own DNS forwarder (`crate::bridge`): what every name of a
/// container is asked of.
fn forwarder(addr: &IpAddr) -> bool {
    *addr == IpAddr::V4(crate::bridge::D4) || *addr == IpAddr::V6(crate::bridge::D6)
}

fn flows_json(flows: &[Flow], names: &[Name]) -> String {
    use crate::status::string;
    let items: Vec<String> = flows
        .iter()
        .map(|f| {
            format!(
                "{{\"proto\":{},\"local_port\":{},\"remote\":{},\"remote_port\":{},\
                 \"name\":{},\"first\":{},\"last\":{},\"out_bytes\":{},\"in_bytes\":{},\
                 \"out_packets\":{},\"in_packets\":{}}}",
                string(&proto_name(f.key.proto)),
                f.key.lport,
                string(&f.key.remote.to_string()),
                f.key.rport,
                name_of(names, &f.key.remote).map_or("null".to_owned(), string),
                f.first,
                f.last,
                f.out_bytes,
                f.in_bytes,
                f.out_packets,
                f.in_packets
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

fn json(rows: &[Listed]) -> String {
    use crate::status::string;
    let items: Vec<String> = rows
        .iter()
        .map(|r| {
            format!(
                "{{\"id\":{},\"container\":{},\"network\":{},\"connections\":{}}}",
                string(&r.id),
                r.container.as_deref().map_or("null".to_owned(), string),
                string(&r.network),
                r.table
                    .as_ref()
                    .map_or("null".to_owned(), |(f, n)| flows_json(f, n))
            )
        })
        .collect();
    format!(
        "{{\"schema_version\":{},\"instances\":[{}]}}",
        crate::status::SCHEMA_VERSION,
        items.join(",")
    )
}

/// How long ago, for a person.
fn ago(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs} с назад"),
        60..=3599 => format!("{} мин назад", secs / 60),
        3600..=86399 => format!("{} ч назад", secs / 3600),
        _ => format!("{} дн назад", secs / 86400),
    }
}

fn text(rows: &[Listed], now: u32) -> String {
    use crate::traffic::bytes_text;
    if rows.is_empty() {
        return "ни один экземпляр контейнера не работает\n".to_owned();
    }
    let mut out = String::new();
    for r in rows {
        let who = r.container.as_deref().unwrap_or(r.id.as_str());
        out.push_str(&format!("{who} · {}:\n", r.network));
        let Some((flows, names)) = &r.table else {
            out.push_str("  соединения не видны (экземпляр прошлой сборки)\n");
            continue;
        };
        if flows.is_empty() {
            out.push_str("  соединений не было\n");
        }
        for f in flows {
            let name = if forwarder(&f.key.remote) {
                Some("DNS контейнера")
            } else {
                name_of(names, &f.key.remote)
            };
            out.push_str(&format!(
                "  {} {}{} · ↑ {} · ↓ {} · {}\n",
                proto_name(f.key.proto),
                endpoint(&f.key.remote, f.key.rport, f.key.proto),
                name.map_or(String::new(), |n| format!(" ({n})")),
                bytes_text(f.out_bytes),
                bytes_text(f.in_bytes),
                ago(u64::from(now.saturating_sub(f.last)))
            ));
        }
    }
    out
}

/// `cellward traffic --connections [--json]`: each running instance's
/// connections, the latest first, with the names its DNS answers gave for
/// their addresses.
pub fn run(tools: &crate::tools::Tools, json_out: bool) -> u8 {
    let rows = listed(tools);
    if json_out {
        println!("{}", json(&rows));
    } else {
        print!("{}", text(&rows, now()));
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth(kind: u16, ip: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&kind.to_be_bytes());
        f.extend_from_slice(ip);
        f
    }

    fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, proto, 0, 0];
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(payload);
        eth(0x0800, &ip)
    }

    fn ports(sport: u16, dport: u16, rest: &[u8]) -> Vec<u8> {
        let mut p = sport.to_be_bytes().to_vec();
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&[0; 4]);
        p.extend_from_slice(rest);
        p
    }

    /// An answer for `name` with the given addresses (the second by a
    /// compression pointer to the question).
    fn answer(name: &str, a: [u8; 4], aaaa: [u8; 16]) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0, 1, 0, 1]);
        m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        m.extend_from_slice(&a);
        m.extend_from_slice(&[0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
        m.extend_from_slice(&aaaa);
        m
    }

    #[test]
    fn a_frames_flow_is_read_from_its_headers() {
        let out = ipv4(
            TCP,
            [10, 254, 0, 2],
            [93, 184, 216, 34],
            &ports(40000, 443, &[0; 12]),
        );
        let s = frame(&out, true).unwrap();
        assert_eq!(
            s.key,
            Key {
                proto: TCP,
                lport: 40000,
                remote: "93.184.216.34".parse().unwrap(),
                rport: 443
            }
        );
        assert_eq!(s.len, out.len());
        let back = ipv4(
            TCP,
            [93, 184, 216, 34],
            [10, 254, 0, 2],
            &ports(443, 40000, &[0; 12]),
        );
        assert_eq!(frame(&back, false).unwrap().key, s.key);
        // IPv6 UDP.
        let mut ip6 = vec![0x60, 0, 0, 0, 0, 16, UDP, 64];
        ip6.extend_from_slice(&"fd63::2".parse::<Ipv6Addr>().unwrap().octets());
        ip6.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        ip6.extend_from_slice(&ports(5000, 4433, &[]));
        let v6 = eth(0x86dd, &ip6);
        let s6 = frame(&v6, true).unwrap();
        assert_eq!((s6.key.proto, s6.key.rport), (UDP, 4433));
        // Not IP, or cut short: nothing.
        assert!(frame(&eth(0x0806, &[0; 28]), true).is_none());
        assert!(frame(&out[..20], true).is_none());
        assert!(frame(&[], true).is_none());
        // A later fragment: no ports.
        let mut frag = ipv4(UDP, [10, 254, 0, 2], [1, 1, 1, 1], &ports(1, 2, &[]));
        frag[14 + 6] = 0x00;
        frag[14 + 7] = 0x10;
        assert_eq!(frame(&frag, true).unwrap().key.lport, 0);
    }

    #[test]
    fn a_dns_answer_gives_its_name_and_addresses() {
        let m = answer("API.telegram.org", [149, 154, 167, 50], [0x20; 16]);
        let (name, addrs) = dns(&m).unwrap();
        assert_eq!(name, "api.telegram.org");
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], "149.154.167.50".parse::<IpAddr>().unwrap());
        // A query is no answer; one cut short does not read.
        let mut q = m.clone();
        q[2] = 0x01;
        assert!(dns(&q).is_none());
        assert!(dns(&m[..m.len() - 3]).is_none());
        // A pointer that loops, or points forward: refused.
        let mut looped = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        looped.extend_from_slice(&[0xc0, 12]);
        assert!(dns(&looped).is_none());
    }

    #[test]
    fn the_table_keeps_flows_and_names_a_reader_can_read() {
        let dir = std::env::temp_dir().join(format!("vz-flows-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = create(&dir).unwrap();
        let mut table = Table::map(file.as_fd(), true).unwrap();
        let out = ipv4(
            TCP,
            [10, 254, 0, 2],
            [149, 154, 167, 50],
            &ports(40000, 443, &[0; 12]),
        );
        table.note(&frame(&out, true).unwrap(), 100);
        table.note(&frame(&out, true).unwrap(), 101);
        let back = ipv4(
            TCP,
            [149, 154, 167, 50],
            [10, 254, 0, 2],
            &ports(443, 40000, &[0; 32]),
        );
        table.note(&frame(&back, false).unwrap(), 102);
        // A DNS answer from the forwarder.
        let dnsm = answer("api.telegram.org", [149, 154, 167, 50], [0x20; 16]);
        let reply = ipv4(
            UDP,
            [10, 254, 255, 253],
            [10, 254, 0, 2],
            &ports(53, 5353, &dnsm),
        );
        table.note(&frame(&reply, false).unwrap(), 99);
        let (flows, names) = read(&dir).unwrap();
        let tcp = flows.iter().find(|f| f.key.proto == TCP).unwrap();
        assert_eq!((tcp.first, tcp.last), (100, 102));
        assert_eq!((tcp.out_packets, tcp.in_packets), (2, 1));
        assert_eq!(tcp.out_bytes, 2 * out.len() as u64);
        assert_eq!(tcp.in_bytes, back.len() as u64);
        assert_eq!(
            name_of(&names, &"149.154.167.50".parse().unwrap()),
            Some("api.telegram.org")
        );
        // A relay of a later attach goes on with the same flows — after one
        // killed while it wrote a slot: that slot emptied, and even again.
        let last = Table::slot(SLOTS - 1);
        table
            .u32_cell(last + cell::META)
            .store(USED | u32::from(UDP), Ordering::Relaxed);
        table.u32_cell(last).store(7, Ordering::Relaxed);
        let mut again = Table::map(file.as_fd(), true).unwrap();
        assert_eq!(again.u32_cell(last).load(Ordering::Relaxed), 8);
        assert_eq!(again.u32_cell(last + cell::META).load(Ordering::Relaxed), 0);
        assert_eq!(again.next_name, 2, "the names go on after the two there");
        again.note(&frame(&out, true).unwrap(), 110);
        let (flows, _) = read(&dir).unwrap();
        assert_eq!(flows.iter().filter(|f| f.key.proto == TCP).count(), 1);
        assert_eq!(flows.iter().find(|f| f.key.proto == TCP).unwrap().last, 110);
        again.close();
        table.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The report: the latest first, a name where a DNS answer gave one,
    /// the forwarder said as what it is; JSON with every field.
    #[test]
    fn the_report_says_what_was_reached() {
        let flow = |remote: &str, rport, last| Flow {
            key: Key {
                proto: TCP,
                lport: 40000,
                remote: remote.parse().unwrap(),
                rport,
            },
            first: 90,
            last,
            out_bytes: 2048,
            in_bytes: 10,
            out_packets: 2,
            in_packets: 1,
        };
        let names = vec![Name {
            addr: "149.154.167.50".parse().unwrap(),
            name: "api.telegram.org".to_owned(),
            at: 80,
        }];
        let rows = vec![Listed {
            id: "work".to_owned(),
            container: Some("work".to_owned()),
            network: "zone".to_owned(),
            table: Some((
                vec![
                    flow("149.154.167.50", 443, 100),
                    flow("10.254.255.253", 53, 95),
                    flow("2001:db8::1", 8443, 20),
                ],
                names,
            )),
        }];
        let t = text(&rows, 160);
        assert!(
            t.contains(
                "tcp 149.154.167.50:443 (api.telegram.org) · ↑ 2.0 КБ · ↓ 10 Б · 1 мин назад"
            ),
            "{t}"
        );
        assert!(t.contains("10.254.255.253:53 (DNS контейнера)"), "{t}");
        assert!(t.contains("[2001:db8::1]:8443 · "), "{t}");
        let j = json(&rows);
        assert!(j.contains("\"name\":\"api.telegram.org\""), "{j}");
        assert!(
            j.contains("\"remote\":\"2001:db8::1\",\"remote_port\":8443,\"name\":null"),
            "{j}"
        );
        assert!(j.contains("\"out_packets\":2,\"in_packets\":1"), "{j}");
        let none = vec![Listed {
            table: None,
            ..rows.into_iter().next().unwrap()
        }];
        assert!(json(&none).contains("\"connections\":null"));
        assert!(text(&none, 0).contains("прошлой сборки"));
    }

    /// A full table gives the slot seen longest ago.
    #[test]
    fn a_full_table_gives_up_the_oldest_flow() {
        let dir = std::env::temp_dir().join(format!("vz-flows-full-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = create(&dir).unwrap();
        let mut table = Table::map(file.as_fd(), true).unwrap();
        for i in 0..SLOTS as u32 {
            let f = ipv4(
                UDP,
                [10, 254, 0, 2],
                [1, 1, 1, 1],
                &ports((i % 60000) as u16 + 1, (i / 60000) as u16 + 1, &[]),
            );
            table.note(&frame(&f, true).unwrap(), 1000 + i);
        }
        let new = ipv4(UDP, [10, 254, 0, 2], [9, 9, 9, 9], &ports(7, 7, &[]));
        table.note(&frame(&new, true).unwrap(), 9999);
        let (flows, _) = read(&dir).unwrap();
        assert_eq!(flows.len(), SLOTS);
        assert!(flows
            .iter()
            .any(|f| f.key.remote == "9.9.9.9".parse::<IpAddr>().unwrap()));
        assert!(!flows.iter().any(|f| f.first == 1000), "the oldest stayed");
        table.close();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
