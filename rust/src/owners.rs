//! Which program holds each connection of a container's instance — stage 2
//! of the network monitor (`docs/FIREWALL.md` §9), beside the relay's table
//! of flows (`crate::flows`), which knows no processes.
//!
//! **How.** From the host, as the user, nothing entered: the sockets of the
//! instance's network namespace as `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` of
//! its space lists them — each with its ends and its inode —; the
//! instance's processes, those whose `/proc/<pid>/ns/net` is the space's;
//! which of them holds each inode (`/proc/<pid>/fd`); and, up its parents,
//! which of the container's launches it belongs to (`crate::registry`), the
//! program's own name for the person (`.labels/<key>`). A flow is matched by
//! its protocol and the instance's port, and by the other end where the
//! socket has one (an unconnected UDP socket has none).
//!
//! **What it cannot say.** A socket closed by the time it is looked at, and a
//! process gone, leave their flow without an owner: the record says so, and
//! guesses nothing. ICMP (a ping socket) is not matched. Nothing here
//! decides — the wall is the instance's rules.
//!
//! **At the first packet** ([`Keeper`]). The relay says a word on a pipe
//! for every new flow it notes (`frame-relay --news-fd`); the instance's
//! keeper wakes on it, looks the new flows' owners up while their sockets
//! are fresh — a short connection too, gone a moment later —, and appends
//! them to the instance's [`FILE`]. A reader takes an owner from there
//! first, and looks up now only the flows it has none for.

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::flows::{Flow, Key, TCP, UDP};

/// A socket of the instance's network namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sock {
    pub proto: u8,
    pub lport: u16,
    pub remote: IpAddr,
    pub rport: u16,
    pub inode: u64,
}

/// Who holds a flow: the process with its socket, and the launch it
/// belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    pub pid: i32,
    /// Its `comm`.
    pub process: String,
    /// The program's key in the registry (`crate::registry`), when a
    /// launch of the container's is among its parents.
    pub program: Option<String>,
}

/// An address as `/proc/net/*` prints it: the bytes of the kernel's
/// `__be32` words, each printed as a number of the machine's order.
fn hex_addr(text: &str) -> Option<IpAddr> {
    let word = |w: &str| u32::from_str_radix(w, 16).ok().map(u32::to_ne_bytes);
    match text.len() {
        8 => Some(IpAddr::V4(Ipv4Addr::from(word(text)?))),
        32 => {
            let mut bytes = [0u8; 16];
            for (i, chunk) in bytes.chunks_mut(4).enumerate() {
                chunk.copy_from_slice(&word(text.get(i * 8..i * 8 + 8)?)?);
            }
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

/// `<address>:<port>` of `/proc/net/*`.
fn hex_end(text: &str) -> Option<(IpAddr, u16)> {
    let (addr, port) = text.split_once(':')?;
    Some((hex_addr(addr)?, u16::from_str_radix(port, 16).ok()?))
}

/// An IPv4 address a dual-stack socket names as `::ffff:a.b.c.d`, as it is.
fn plain(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(addr, IpAddr::V4),
        v4 => v4,
    }
}

/// The sockets in one of `/proc/<pid>/net/{tcp,tcp6,udp,udp6}`; a line that
/// does not read is skipped.
pub fn parse_net(text: &str, proto: u8) -> Vec<Sock> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (_, lport) = hex_end(f.get(1)?)?;
            let (remote, rport) = hex_end(f.get(2)?)?;
            Some(Sock {
                proto,
                lport,
                remote: plain(remote),
                rport,
                inode: f.get(9)?.parse().ok()?,
            })
        })
        .collect()
}

/// The sockets of the network namespace of process `space`.
fn sockets(space: i32) -> Vec<Sock> {
    [("tcp", TCP), ("tcp6", TCP), ("udp", UDP), ("udp6", UDP)]
        .iter()
        .flat_map(|(file, proto)| {
            fs::read_to_string(format!("/proc/{space}/net/{file}"))
                .map(|text| parse_net(&text, *proto))
                .unwrap_or_default()
        })
        .collect()
}

/// The socket of `flow`: its protocol and the instance's port, and its other
/// end — or, for UDP, none: an unconnected socket sends anywhere. A
/// connected one first; a TCP listener is never one (its connections are
/// sockets of their own).
pub fn socket_of<'a>(socks: &'a [Sock], flow: &Flow) -> Option<&'a Sock> {
    let k = &flow.key;
    let ours = |s: &&Sock| s.proto == k.proto && s.lport == k.lport && k.lport != 0;
    socks
        .iter()
        .filter(ours)
        .find(|s| s.remote == plain(k.remote) && s.rport == k.rport)
        .or_else(|| {
            socks
                .iter()
                .filter(ours)
                .find(|s| s.proto == UDP && s.remote.is_unspecified() && s.rport == 0)
        })
}

/// The processes the user may look at, each with its network namespace:
/// looked at once for every instance asked of.
#[derive(Default)]
pub struct Procs(Vec<(i32, PathBuf)>);

impl Procs {
    pub fn scan() -> Self {
        let Ok(entries) = fs::read_dir("/proc") else {
            return Self(Vec::new());
        };
        Self(
            entries
                .flatten()
                .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
                .filter_map(|pid| Some((pid, fs::read_link(format!("/proc/{pid}/ns/net")).ok()?)))
                .collect(),
        )
    }

    /// Those in the network namespace of process `space`.
    fn in_netns(&self, space: i32) -> Vec<i32> {
        let Some(ns) = self
            .0
            .iter()
            .find(|(pid, _)| *pid == space)
            .map(|(_, ns)| ns)
        else {
            return Vec::new();
        };
        self.0
            .iter()
            .filter(|(_, n)| n == ns)
            .map(|(pid, _)| *pid)
            .collect()
    }
}

/// The inode of a socket as `/proc/<pid>/fd/<n>` names it (`socket:[N]`).
fn socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// Which of `pids` holds each socket: its inode → the pid (the first found).
fn holders_of(pids: &[i32]) -> HashMap<u64, i32> {
    let mut out = HashMap::new();
    for pid in pids {
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Some(inode) = fs::read_link(fd.path())
                .ok()
                .and_then(|l| socket_inode(&l.to_string_lossy()))
            {
                out.entry(inode).or_insert(*pid);
            }
        }
    }
    out
}

/// The parent of a process, from its `stat` (after its name, which may have
/// anything in it, a `)` too).
pub fn parent_in(stat: &str) -> Option<i32> {
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(1)?.parse().ok()
}

/// The launches of a container: each launch's pid → its program's key.
fn launches(registry: &Path) -> HashMap<i32, String> {
    let mut out = HashMap::new();
    let Ok(entries) = fs::read_dir(registry) else {
        return out;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let text = fs::read_to_string(e.path()).unwrap_or_default();
        for r in text.lines().filter_map(crate::registry::parse_record) {
            out.insert(r.pid, name.clone());
        }
    }
    out
}

/// The program of process `pid`: it or the nearest of its parents that is a
/// launch.
fn program_of(pid: i32, launches: &HashMap<i32, String>) -> Option<String> {
    let mut at = pid;
    for _ in 0..64 {
        if let Some(key) = launches.get(&at) {
            return Some(key.clone());
        }
        let stat = fs::read_to_string(format!("/proc/{at}/stat")).ok()?;
        at = parent_in(&stat).filter(|p| *p > 1)?;
    }
    None
}

/// The owner of each of `flows` of the instance whose space is process
/// `space`, among `procs`, by the launches in `registry`: `None` where none
/// is found.
pub fn of(space: i32, registry: &Path, flows: &[Flow], procs: &Procs) -> Vec<Option<Owner>> {
    let socks = sockets(space);
    if socks.is_empty() {
        return vec![None; flows.len()];
    }
    let holders = holders_of(&procs.in_netns(space));
    owned(&socks, &holders, registry, flows)
}

/// [`of`], its sockets and their holders looked at already.
fn owned(
    socks: &[Sock],
    holders: &HashMap<u64, i32>,
    registry: &Path,
    flows: &[Flow],
) -> Vec<Option<Owner>> {
    let launches = launches(registry);
    flows
        .iter()
        .map(|f| {
            let pid = *holders.get(&socket_of(socks, f)?.inode)?;
            // The container's own word: nothing of it said to a terminal as
            // a control character.
            let process = fs::read_to_string(format!("/proc/{pid}/comm"))
                .map(|c| {
                    c.trim()
                        .chars()
                        .map(|ch| if ch.is_control() { '?' } else { ch })
                        .collect()
                })
                .unwrap_or_default();
            Some(Owner {
                pid,
                process,
                program: program_of(pid, &launches),
            })
        })
        .collect()
}

// --- AT THE FIRST PACKET ----------------------------------------------------

/// The owners' file in an instance's directory: a line per flow whose owner
/// its keeper found — `<proto>⇥<own port>⇥<remote>⇥<remote port>⇥<first
/// seen>⇥<pid>⇥<process>⇥<program or ->`.
pub const FILE: &str = "owners";

/// A flow as the owners' file names it: its key, and when it was first seen
/// (ports are used again).
pub type Seen = (Key, u32);

fn line_of(seen: &Seen, o: &Owner) -> String {
    let (k, first) = seen;
    format!(
        "{}\t{}\t{}\t{}\t{first}\t{}\t{}\t{}\n",
        k.proto,
        k.lport,
        k.remote,
        k.rport,
        o.pid,
        o.process.replace(['\t', '\n'], "?"),
        o.program.as_deref().unwrap_or("-")
    )
}

/// The owners' file read: each flow's owner (a later line over an earlier).
pub fn read(dir: &Path) -> HashMap<Seen, Owner> {
    let text = fs::read_to_string(dir.join(FILE)).unwrap_or_default();
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            let [proto, lport, remote, rport, first, pid, process, program] = f.as_slice() else {
                return None;
            };
            let key = Key {
                proto: proto.parse().ok()?,
                lport: lport.parse().ok()?,
                remote: remote.parse().ok()?,
                rport: rport.parse().ok()?,
            };
            let owner = Owner {
                pid: pid.parse().ok()?,
                process: (*process).to_owned(),
                program: (*program != "-").then(|| (*program).to_owned()),
            };
            Some(((key, first.parse().ok()?), owner))
        })
        .collect()
}

/// An instance's keeper's part: the owners of its new flows, looked up as
/// the relay says it saw them.
#[derive(Default)]
pub struct Keeper {
    /// The flows' table, mapped to read (the keeper made the file).
    table: Option<crate::flows::Table>,
    /// The flows already looked at, found or not.
    known: HashSet<Seen>,
    /// Those found, as the file has them.
    found: HashMap<Seen, Owner>,
    /// The lines in the file.
    lines: usize,
    procs: Procs,
}

impl Keeper {
    /// The relay said it saw new flows: those not looked at yet looked up
    /// now, in the instance's directory `dir`, of its space `space`, by
    /// the launches in `registry`; what is found appended to [`FILE`].
    pub fn heard(&mut self, dir: &Path, space: i32, registry: &Path) {
        let fresh = self.fresh(dir);
        self.resolve(dir, space, registry, &fresh);
    }

    /// The flows of the table not looked at yet (the firewall decides them
    /// first where their program does not matter, `crate::netrules`).
    pub fn fresh(&mut self, dir: &Path) -> Vec<Flow> {
        if self.table.is_none() {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(dir.join(crate::flows::FILE));
            self.table = file
                .ok()
                .and_then(|f| crate::flows::Table::map(std::os::fd::AsFd::as_fd(&f), false).ok());
        }
        let Some(table) = &self.table else {
            return Vec::new();
        };
        table
            .flows()
            .into_iter()
            .filter(|f| !self.known.contains(&(f.key, f.first)))
            .collect()
    }

    /// The owners of `fresh` ([`Keeper::fresh`]) looked up and written down:
    /// each flow's, in order — `None` where none was found.
    pub fn resolve(
        &mut self,
        dir: &Path,
        space: i32,
        registry: &Path,
        fresh: &[Flow],
    ) -> Vec<Option<Owner>> {
        if fresh.is_empty() {
            return Vec::new();
        }
        let socks = sockets(space);
        let mut holders = holders_of(&self.procs.in_netns(space));
        // A socket no process known to hold: a process new since the last
        // look — every process looked at again, once.
        let unheld = fresh
            .iter()
            .any(|f| socket_of(&socks, f).is_some_and(|s| !holders.contains_key(&s.inode)));
        if unheld {
            self.procs = Procs::scan();
            holders = holders_of(&self.procs.in_netns(space));
        }
        let owners = owned(&socks, &holders, registry, fresh);
        let mut text = String::new();
        for (f, owner) in fresh.iter().zip(&owners) {
            let seen = (f.key, f.first);
            self.known.insert(seen);
            if let Some(o) = owner {
                text.push_str(&line_of(&seen, o));
                self.found.insert(seen, o.clone());
            }
        }
        // Past twice what the table holds: what left it is forgotten, and
        // the file written anew with the rest — at most a table's worth, so
        // the next time is a table's worth of lines away.
        self.lines += text.lines().count();
        let most = 2 * crate::flows::SLOTS;
        if self.lines > most || self.known.len() > most {
            let flows = self.table.as_ref().map(|t| t.flows()).unwrap_or_default();
            let now: HashSet<Seen> = flows.iter().map(|f| (f.key, f.first)).collect();
            self.known.retain(|s| now.contains(s));
            self.found.retain(|s, _| now.contains(s));
            self.rewrite(dir);
        } else if !text.is_empty() {
            let _ = append(dir, &text);
        }
        owners
    }

    fn rewrite(&mut self, dir: &Path) {
        let text: String = self.found.iter().map(|(s, o)| line_of(s, o)).collect();
        let tmp = dir.join(format!(".{FILE}.new"));
        let _ = fs::remove_file(&tmp);
        let written = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)
            .and_then(|mut f| f.write_all(text.as_bytes()))
            .and_then(|()| fs::rename(&tmp, dir.join(FILE)));
        if written.is_ok() {
            self.lines = self.found.len();
        }
    }
}

fn append(dir: &Path, text: &str) -> std::io::Result<()> {
    OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir.join(FILE))?
        .write_all(text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flows::Key;

    #[test]
    fn proc_net_lines_are_read() {
        // 10.254.0.2:40000 → 149.154.167.50:443, established; a dual-stack
        // one to 1.1.1.1:53; a listener; a line cut short.
        let lo = u32::from_ne_bytes([10, 254, 0, 2]);
        let far = u32::from_ne_bytes([149, 154, 167, 50]);
        let tcp = format!(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
             \x20  0: {lo:08X}:9C40 {far:08X}:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 424242 1 0 20 4 30 10 -1\n\
             \x20  1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 7 1\n\
             \x20  2: {lo:08X}:9C40\n"
        );
        let socks = parse_net(&tcp, TCP);
        assert_eq!(socks.len(), 2, "{socks:?}");
        assert_eq!(
            socks[0],
            Sock {
                proto: TCP,
                lport: 40000,
                remote: "149.154.167.50".parse().unwrap(),
                rport: 443,
                inode: 424242,
            }
        );
        let mapped: [u8; 16] = "::ffff:1.1.1.1".parse::<Ipv6Addr>().unwrap().octets();
        let words: String = mapped
            .chunks(4)
            .map(|c| format!("{:08X}", u32::from_ne_bytes(c.try_into().unwrap())))
            .collect();
        let udp6 = format!(
            "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
             \x20 10: 00000000000000000000000000000000:D431 {words}:0035 01 00000000:00000000 00:00000000 00000000  1000        0 99 2 0000000000000000 0\n"
        );
        let socks6 = parse_net(&udp6, UDP);
        assert_eq!(socks6[0].remote, "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(
            (socks6[0].lport, socks6[0].rport, socks6[0].inode),
            (54321, 53, 99)
        );
    }

    #[test]
    fn a_flow_finds_its_socket() {
        let sock = |lport, remote: &str, rport, inode| Sock {
            proto: UDP,
            lport,
            remote: remote.parse().unwrap(),
            rport,
            inode,
        };
        let socks = vec![
            sock(5000, "0.0.0.0", 0, 1),
            sock(5000, "9.9.9.9", 53, 2),
            sock(6000, "::", 0, 3),
        ];
        let flow = |lport, remote: &str, rport| Flow {
            key: Key {
                proto: UDP,
                lport,
                remote: remote.parse().unwrap(),
                rport,
            },
            first: 0,
            last: 0,
            out_bytes: 0,
            in_bytes: 0,
            out_packets: 0,
            in_packets: 0,
        };
        let inode = |f: &Flow| socket_of(&socks, f).map(|s| s.inode);
        // The connected one first; else the unconnected one on its port.
        assert_eq!(inode(&flow(5000, "9.9.9.9", 53)), Some(2));
        assert_eq!(inode(&flow(5000, "8.8.8.8", 53)), Some(1));
        assert_eq!(inode(&flow(6000, "2001:db8::1", 443)), Some(3));
        assert_eq!(inode(&flow(7000, "8.8.8.8", 53)), None);
        // No port, no socket.
        assert_eq!(inode(&flow(0, "8.8.8.8", 0)), None);
        // A TCP listener holds no connection of its own.
        let listening = [Sock {
            proto: TCP,
            ..sock(8000, "0.0.0.0", 0, 4)
        }];
        let outbound = Flow {
            key: Key {
                proto: TCP,
                ..flow(8000, "8.8.8.8", 443).key
            },
            ..flow(8000, "8.8.8.8", 443)
        };
        assert_eq!(socket_of(&listening, &outbound), None);
    }

    #[test]
    fn a_parent_is_read_past_any_name() {
        assert_eq!(parent_in("1234 (a) b) c) S 77 1234 1234 0"), Some(77));
        assert_eq!(parent_in("1 (init) S 0 1 1"), Some(0));
        assert_eq!(parent_in("garbage"), None);
    }

    /// The keeper, told of a new flow, finds its owner — a process it did
    /// not know yet — and writes it down; a reader takes it from there. Told
    /// again, it writes nothing twice.
    #[test]
    fn the_keeper_writes_down_a_new_flows_owner() {
        use std::os::fd::AsFd;
        let me = std::process::id() as i32;
        let dir = std::env::temp_dir().join(format!("vz-keeper-{me}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("registry")).unwrap();
        fs::write(dir.join("registry/tester"), format!("{me} offline work\n")).unwrap();
        let file = crate::flows::create(&dir).unwrap();
        let mut table = crate::flows::Table::map(file.as_fd(), true).unwrap();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let key = Key {
            proto: UDP,
            lport: socket.local_addr().unwrap().port(),
            remote: "127.0.0.2".parse().unwrap(),
            rport: 9,
        };
        let seen = crate::flows::Seen {
            key,
            outbound: true,
            len: 60,
            dns: None,
        };
        assert!(table.note(&seen, 100), "a new flow");
        assert!(!table.note(&seen, 101), "the same flow again");
        let mut keeper = Keeper::default();
        keeper.heard(&dir, me, &dir.join("registry"));
        let kept = read(&dir);
        let owner = kept
            .get(&(key, 100))
            .expect("the new flow's owner written down");
        assert_eq!(owner.pid, me);
        assert_eq!(owner.program.as_deref(), Some("tester"));
        keeper.heard(&dir, me, &dir.join("registry"));
        let text = fs::read_to_string(dir.join(FILE)).unwrap();
        assert_eq!(text.lines().count(), 1, "{text}");
        drop(socket);
        table.close();
        let _ = fs::remove_dir_all(&dir);
    }

    /// This test's own process: its sockets found, its socket's holder is
    /// itself, and a launch among its parents names its program.
    #[test]
    fn our_own_socket_is_ours() {
        let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let me = std::process::id() as i32;
        let flow = Flow {
            key: Key {
                proto: UDP,
                lport: port,
                remote: "127.0.0.2".parse().unwrap(),
                rport: 9,
            },
            first: 0,
            last: 0,
            out_bytes: 0,
            in_bytes: 0,
            out_packets: 0,
            in_packets: 0,
        };
        let reg = std::env::temp_dir().join(format!("vz-owners-{me}"));
        let _ = fs::remove_dir_all(&reg);
        fs::create_dir_all(&reg).unwrap();
        fs::write(reg.join("tester"), format!("{me} offline work\n")).unwrap();
        let owners = of(me, &reg, std::slice::from_ref(&flow), &Procs::scan());
        let owner = owners[0].as_ref().expect("our own socket has an owner");
        assert_eq!(owner.pid, me);
        assert_eq!(owner.program.as_deref(), Some("tester"));
        drop(listener);
        let _ = fs::remove_dir_all(&reg);
    }

    /// A line of the owners' file there and back; one of another shape
    /// skipped.
    #[test]
    fn an_owners_line_reads_back() {
        let seen = (
            Key {
                proto: TCP,
                lport: 40000,
                remote: "2001:db8::1".parse().unwrap(),
                rport: 443,
            },
            1790000000,
        );
        let owner = Owner {
            pid: 42,
            process: "tab\there".to_owned(),
            program: None,
        };
        let me = std::process::id();
        let dir = std::env::temp_dir().join(format!("vz-owners-line-{me}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let text = format!("{}what\tever\n", line_of(&seen, &owner));
        fs::write(dir.join(FILE), text).unwrap();
        let kept = read(&dir);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[&seen].process, "tab?here");
        assert_eq!(kept[&seen].program, None);
        let _ = fs::remove_dir_all(&dir);
    }
}
