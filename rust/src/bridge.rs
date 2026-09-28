//! The bridge: how a zone carries a container instance (the container design
//! of 2026-09-27, §3).
//!
//! An instance's network namespace belongs to the instance's user namespace,
//! a zone's app namespace to the zone's, and the two are siblings: no process
//! holds the capabilities over both that `setns` would want. So the zone runs
//! a `passt --fd` in its app namespace for each instance it carries, handed
//! one end of a stream socket and no handle on any namespace, and the
//! instance's relay (`crate::relay`) pumps the frames of its tap into the
//! other end. passt's sockets are the zone's: the instance's traffic leaves
//! by the zone's routes — its tunnel, its interface, its system zone — and
//! by nothing else.
//!
//! Stage 0 (2026-09-27): the pure parts, which nothing calls yet.
//!
//! * The addresses. The instance's side of the link is its own, the same in
//!   every zone: IPv4 `10.254.0.0/16` with the gateway [`G4`] and the DNS
//!   forwarder [`D4`] at its top, and a /64 of the project's unique local
//!   prefix ([`ULA6`]) with the forwarder [`D6`] and the gateway `fe80::1`.
//!   The instance's own addresses are drawn anew for every attach
//!   ([`pick_a4`], [`pick_a6`]) — never the previous one, so that nothing of
//!   the old link can be taken for the new one. None of them is a
//!   host-interface zone's (`zone::HOSTIF_*`, `10.255.255.252/30`).
//! * **DNS by a constant.** The instance's `resolv.conf` names [`D4`] (and
//!   [`D6`]) and never a real resolver; passt forwards what is sent there to
//!   the zone's first resolver of that family (`--dns-forward`,
//!   `--dns-host`). A new network is a new passt behind the same address:
//!   nothing a program cached — c-ares, Go, glibc — names the old resolver.
//!   One upstream per family: no failover inside a zone.
//! * The request an instance's holder sends the zone ([`Request`], `VZA1`)
//!   and the zone's answers ([`Answer`]).
//! * passt's command line ([`passt_argv`]) with every door it does not need
//!   shut: no DHCP, DHCPv6 or router advertisements (the relay configures the
//!   tap itself), no forwarded ports either way, no address of passt's that
//!   stands for the zone's loopback (`--no-map-gw`) or for the instance's own
//!   address (`--map-guest-addr none`).
//!
//! Stage 2 (2026-09-27): the two ends in use.
//!
//! * **The zone's end** ([`serve`], a thread of the zone's app namespace
//!   process, `zone::zone_setup`). Its socket, [`SOCKET`], is bound in the
//!   zone's directory before `ready`, so that a zone found ready is found
//!   carrying instances; a zone of a previous build has none, and a launch
//!   into it takes the old way ([`carries`]). A request is taken from the
//!   user alone (`SO_PEERCRED`; the path is under the state every zone and
//!   instance covers — the trust `nsenter` had), and only by a zone whose
//!   refusal of its own local addresses to passt is loaded ([`RULE_MARK`]):
//!   without it a program of the instance could reach what listens in the
//!   zone itself. passt runs as [`BRIDGE_ID`] with the group of its own
//!   ([`bridge_gid`]), with no supplementary group, no way to new privileges
//!   and the parent-death signal of the thread that holds it; it is ready
//!   when its pid file has its pid (`-P`, as pasta's word), and the answer
//!   comes then. The requester's end of the connection is the instance's
//!   hold on it: gone, passt is killed; passt gone, the requester is told
//!   ([`Answer::Exited`]).
//! * **The instance's end** ([`attach`], the instance's keeper,
//!   `zone::hold_instance`). The keeper asks with one end of a fresh
//!   socketpair and gives the other to the relay (`crate::relay`), which it
//!   starts in the instance's user and network namespaces as their root;
//!   the relay makes the tap, its addresses and routes and its rules, seals
//!   itself, and says so on a pipe. A zone that ends takes its passts with
//!   it: the relay sees its stream end and ends too, the tap goes with it,
//!   and the instance is left with loopback and unreachable defaults — its
//!   programs live on with no way out. The zone's fingerprint ([`fingerprint`])
//!   says whether a zone that came back is the one the instance was carried
//!   by: only then is it re-attached by itself.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// The uid passt runs as in a zone, mapped from the user's subordinate range
/// like the zone's root (0) and the OpenConnect client (1). The zone's
/// refusal of its local addresses is keyed on it (`zone::bridge_refusal_rules`).
/// Its group is not 2 but the subordinate id itself, mapped onto itself
/// ([`bridge_gid`], `zone::map_args`): the ping range is one range of the
/// namespace's gids whose two ends the kernel keeps as the host's, and it
/// has to take the user's group and passt's both (`zone::ping_range`).
pub const BRIDGE_ID: u32 = 2;
/// The instance's tap's MTU, as a system zone's bridge has it: passt carries
/// what the tunnel behind it can.
pub const MTU: u32 = 65520;
/// The instance's IPv4 network…
pub const NET4: Ipv4Addr = Ipv4Addr::new(10, 254, 0, 0);
pub const PREFIX4: u8 = 16;
/// …its gateway, passt…
pub const G4: Ipv4Addr = Ipv4Addr::new(10, 254, 255, 254);
/// …and the address its DNS goes to, forwarded by passt to the zone's
/// resolver.
pub const D4: Ipv4Addr = Ipv4Addr::new(10, 254, 255, 253);
/// The project's unique local /64 (`fd` + "cellw" as the global id): the
/// instance's IPv6 addresses.
pub const ULA6: Ipv6Addr = Ipv6Addr::new(0xfd63, 0x656c, 0x6c77, 0, 0, 0, 0, 0);
pub const PREFIX6: u8 = 64;
/// The IPv6 DNS forwarder, in that /64.
pub const D6: Ipv6Addr = Ipv6Addr::new(0xfd63, 0x656c, 0x6c77, 0, 0, 0, 0, 0x53);
/// The IPv6 gateway: link-local, as a tunnel's side has none of its own and
/// passt takes its link-local address from the gateway named.
pub const G6: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
/// The zone's socket instances attach through, in its state directory.
pub const SOCKET: &str = "bridge.sock";
/// Written by the zone once its refusal of local addresses to the bridge is
/// loaded: without it the zone carries no instance.
pub const RULE_MARK: &str = "bridge-rule";
/// The first word of a request.
pub const MAGIC: &[u8; 4] = b"VZA1";
/// How many draws an address gets before the plan takes the first one free.
const TRIES: usize = 64;
/// The bottom of the instance's IPv4 network: where a plan starts counting
/// when no draw would do.
const FIRST4: Ipv4Addr = Ipv4Addr::new(10, 254, 0, 1);

/// The instance's addresses on its side of one attach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestPlan {
    pub a4: Ipv4Addr,
    /// None: the instance asks for no IPv6, or the zone carries none.
    pub a6: Option<Ipv6Addr>,
}

/// `10.254.<high>.<low>`.
pub fn a4_from(bits: u16) -> Ipv4Addr {
    let [high, low] = bits.to_be_bytes();
    Ipv4Addr::new(10, 254, high, low)
}

/// The project's /64 with this interface id.
pub fn a6_from(iid: u64) -> Ipv6Addr {
    Ipv6Addr::from(u128::from_be_bytes(ULA6.octets()) | u128::from(iid))
}

/// May the instance take this IPv4 address: in the network, not its first
/// or last, not the gateway's or the forwarder's, not the previous attach's.
pub fn a4_usable(a: Ipv4Addr, previous: Option<Ipv4Addr>) -> bool {
    let [ten, net, high, low] = a.octets();
    ten == 10
        && net == 254
        && !(high == 0 && low == 0)
        && !(high == 255 && low == 255)
        && a != G4
        && a != D4
        && Some(a) != previous
}

/// The interface ids an instance never takes: the low ones (the subnet's
/// anycast `::`, the forwarder's `::53`, anything that looks like a
/// service's) and the reserved top of the range (RFC 5453).
const IID_LOW: u64 = 0x1_0000;
const IID_RESERVED: u64 = 0xfdff_ffff_ffff_ff80;

/// May the instance take this IPv6 address: in the project's /64, not a
/// reserved interface id, not the previous attach's.
pub fn a6_usable(a: Ipv6Addr, previous: Option<Ipv6Addr>) -> bool {
    let bits = u128::from_be_bytes(a.octets());
    let iid = (bits & u128::from(u64::MAX)) as u64;
    (bits >> 64) == (u128::from_be_bytes(ULA6.octets()) >> 64)
        && (IID_LOW..IID_RESERVED).contains(&iid)
        && Some(a) != previous
}

/// The instance's IPv4 address for an attach: the first usable one of the
/// draws, and when [`TRIES`] of them were not, the first free one counted
/// from the bottom — never one [`a4_usable`] refuses.
pub fn pick_a4(previous: Option<Ipv4Addr>, draws: impl IntoIterator<Item = u16>) -> Ipv4Addr {
    draws
        .into_iter()
        .take(TRIES)
        .map(a4_from)
        .find(|a| a4_usable(*a, previous))
        .or_else(|| {
            (1..=u16::MAX)
                .map(a4_from)
                .find(|a| a4_usable(*a, previous))
        })
        // Three addresses of 65534 are ever refused: one is always free.
        .unwrap_or(FIRST4)
}

/// The same for IPv6, from draws of an interface id.
pub fn pick_a6(previous: Option<Ipv6Addr>, draws: impl IntoIterator<Item = u64>) -> Ipv6Addr {
    draws
        .into_iter()
        .take(TRIES)
        .map(a6_from)
        .find(|a| a6_usable(*a, previous))
        .unwrap_or_else(|| {
            let first = a6_from(IID_LOW);
            if Some(first) == previous {
                a6_from(IID_LOW + 1)
            } else {
                first
            }
        })
}

/// `getrandom(2)` into the whole buffer.
pub(crate) fn random_bytes(buf: &mut [u8]) -> io::Result<()> {
    let mut at = 0;
    while at < buf.len() {
        let rest = &mut buf[at..];
        // SAFETY: the rest of the buffer, alive for the call.
        let n = unsafe { libc::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        at += n.unsigned_abs();
    }
    Ok(())
}

/// A new plan for an attach: fresh random addresses, none of them the
/// previous plan's; an IPv6 one when `v6`.
pub fn plan(previous: Option<GuestPlan>, v6: bool) -> io::Result<GuestPlan> {
    let mut random = [0u8; TRIES * (2 + 8)];
    random_bytes(&mut random)?;
    let (four, six) = random.split_at(TRIES * 2);
    let a4 = pick_a4(
        previous.map(|p| p.a4),
        four.chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]])),
    );
    let a6 = v6.then(|| {
        pick_a6(
            previous.and_then(|p| p.a6),
            six.chunks_exact(8).map(|c| {
                let mut b = [0u8; 8];
                b.copy_from_slice(c);
                u64::from_be_bytes(b)
            }),
        )
    });
    Ok(GuestPlan { a4, a6 })
}

/// What an instance's holder asks a zone for: a passt for this instance,
/// with the instance's side as in `plan`. The stream's end comes with it
/// (`SCM_RIGHTS`).
///
/// On the wire, NUL-terminated words:
/// `VZA1 \0 <instance id> \0 <IPv6 wanted: 0|1> \0 <a4> \0 <a6 or nothing> \0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub instance: String,
    pub plan: GuestPlan,
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.push(0);
        for word in [
            self.instance.clone(),
            u8::from(self.plan.a6.is_some()).to_string(),
            self.plan.a4.to_string(),
            self.plan.a6.map(|a| a.to_string()).unwrap_or_default(),
        ] {
            out.extend_from_slice(word.as_bytes());
            out.push(0);
        }
        out
    }

    /// A request as the zone reads it — from a peer it has checked, but
    /// held to every word all the same: an instance id the grammar takes
    /// (`instance::valid_id`), addresses in the instance's ranges only.
    pub fn decode(buf: &[u8]) -> Result<Self, String> {
        let Some(body) = buf.strip_suffix(b"\0") else {
            return Err("a request not ended by NUL".to_string());
        };
        let words: Vec<&[u8]> = body.split(|b| *b == 0).collect();
        let [magic, instance, v6, a4, a6] = words[..] else {
            return Err(format!("a request of {} words, not 5", words.len()));
        };
        if magic != MAGIC {
            return Err("not a VZA1 request".to_string());
        }
        let text = |w: &[u8]| {
            std::str::from_utf8(w)
                .map(str::to_string)
                .map_err(|_| "a word that is not UTF-8".to_string())
        };
        let instance = text(instance)?;
        if !crate::instance::valid_id(&instance) {
            return Err(format!("no instance is called {instance:?}"));
        }
        let a4 = text(a4)?
            .parse::<Ipv4Addr>()
            .ok()
            .filter(|a| a4_usable(*a, None))
            .ok_or("an IPv4 address outside the instance's network")?;
        let a6 = match (v6, a6) {
            (b"0", b"") => None,
            (b"1", word) => Some(
                text(word)?
                    .parse::<Ipv6Addr>()
                    .ok()
                    .filter(|a| a6_usable(*a, None))
                    .ok_or("an IPv6 address outside the instance's network")?,
            ),
            _ => {
                return Err("IPv6 asked for and not given an address, or the other way".to_string())
            }
        };
        Ok(Self {
            instance,
            plan: GuestPlan { a4, a6 },
        })
    }
}

/// What a zone answers a request with, one line each: first whether the
/// instance is attached, later — on the same stream — how its passt ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// passt is up for the instance (its pid file written): whether it
    /// carries IPv6, the zone's search domains for the instance's
    /// `resolv.conf`, and the zone's fingerprint ([`fingerprint`]).
    /// `OK v6=<0|1> search=<domain,…> fp=<16 hex digits>`.
    Attached {
        v6: bool,
        search: Vec<String>,
        fp: u64,
    },
    /// Not attached, and why, for the person. `ERR <why>`.
    Refused(String),
    /// The instance's passt ended with this status: its way out is gone.
    /// `EXIT <code>`.
    Exited(i32),
}

/// A domain that may go into a `search` line and on this one: letters,
/// digits, `-` and `.`.
fn is_domain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

impl Answer {
    pub fn encode(&self) -> String {
        match self {
            Self::Attached { v6, search, fp } => format!(
                "OK v6={} search={} fp={fp:016x}\n",
                u8::from(*v6),
                search.join(",")
            ),
            // One line of it, whatever it said.
            Self::Refused(why) => {
                let why: String = why
                    .chars()
                    .map(|c| if c.is_control() { ' ' } else { c })
                    .collect();
                format!("ERR {why}\n")
            }
            Self::Exited(code) => format!("EXIT {code}\n"),
        }
    }

    pub fn decode(line: &str) -> Result<Self, String> {
        let line = line.strip_suffix('\n').unwrap_or(line);
        if line.contains(['\n', '\0']) {
            return Err("an answer of more than one line".to_string());
        }
        if let Some(rest) = line.strip_prefix("OK ") {
            let fields: Vec<&str> = rest.split(' ').collect();
            let [v6, search, fp] = fields[..] else {
                return Err(format!("an OK of {} fields, not 3", fields.len()));
            };
            let v6 = match v6 {
                "v6=0" => false,
                "v6=1" => true,
                _ => return Err(format!("an OK that says {v6:?} of IPv6")),
            };
            let search = search
                .strip_prefix("search=")
                .ok_or("an OK without its search domains")?;
            let search: Vec<String> = if search.is_empty() {
                Vec::new()
            } else {
                search.split(',').map(str::to_string).collect()
            };
            if let Some(bad) = search.iter().find(|d| !is_domain(d)) {
                return Err(format!("a search domain that is none: {bad:?}"));
            }
            let fp = fp
                .strip_prefix("fp=")
                .filter(|hex| hex.len() == 16 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
                .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                .ok_or("an OK without the zone's fingerprint")?;
            return Ok(Self::Attached { v6, search, fp });
        }
        if let Some(why) = line.strip_prefix("ERR ") {
            return Ok(Self::Refused(why.to_string()));
        }
        if let Some(code) = line.strip_prefix("EXIT ") {
            return code
                .parse()
                .map(Self::Exited)
                .map_err(|_| format!("an exit status that is none: {code:?}"));
        }
        Err(format!("not an answer: {line:?}"))
    }
}

/// What a zone starts passt with for one instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasstPlan {
    /// The instance's side.
    pub guest: GuestPlan,
    /// The zone's first resolver of each family: where `D4` and `D6` are
    /// forwarded. A family without one is not forwarded at all — never to
    /// whatever passt would read from a `resolv.conf` of its own.
    pub resolver4: Option<Ipv4Addr>,
    pub resolver6: Option<Ipv6Addr>,
}

/// passt's command line for one instance: `--fd <fd>`, in the foreground,
/// its pid file as its word that it is ready (as pasta's, `zone::PastaWord`),
/// and every door shut that the instance does not need.
///
/// **One-off** by `--fd`: passt ends when the stream does. The descriptor
/// by the number it has in the zone's process, made inheritable between
/// fork and exec ([`serve`]) — never moved to a number of its own choosing,
/// which `std`'s own descriptors of the spawn may hold then. Above 2: stdin,
/// stdout and stderr are the spawn's. passt closes every other descriptor
/// first thing (its `isolate_initial`). Its IPv6 when the instance has an
/// address for it, else `-4`. No path but the binary and the pid file: no
/// socket, capture or log file of passt's, no namespace to open.
pub fn passt_argv(passt: &Path, pid_file: &Path, fd: RawFd, plan: &PasstPlan) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec![
        passt.into(),
        "--fd".into(),
        fd.to_string().into(),
        "-f".into(),
        "-q".into(),
        "-P".into(),
        pid_file.into(),
        // The relay configures the tap itself: nothing is offered.
        "--no-dhcp".into(),
        "--no-dhcpv6".into(),
        "--no-ra".into(),
        // No address that stands for the zone's loopback…
        "--no-map-gw".into(),
        // …or for the instance's own address as the zone sees it.
        "--map-guest-addr".into(),
        "none".into(),
        // Nothing comes in from the zone's side.
        "-t".into(),
        "none".into(),
        "-u".into(),
        "none".into(),
        "-a".into(),
        plan.guest.a4.to_string().into(),
        "-n".into(),
        PREFIX4.to_string().into(),
        "-g".into(),
        G4.to_string().into(),
    ];
    match plan.guest.a6 {
        Some(a6) => argv.extend(
            [
                "-a".to_string(),
                a6.to_string(),
                "-g".to_string(),
                G6.to_string(),
            ]
            .map(OsString::from),
        ),
        None => argv.push("-4".into()),
    }
    let forwards = [
        plan.resolver4.map(|r| (IpAddr::V4(D4), IpAddr::V4(r))),
        plan.resolver6
            .filter(|_| plan.guest.a6.is_some())
            .map(|r| (IpAddr::V6(D6), IpAddr::V6(r))),
    ];
    for (forward, host) in forwards.into_iter().flatten() {
        argv.extend(
            [
                "--dns-forward".to_string(),
                forward.to_string(),
                "--dns-host".to_string(),
                host.to_string(),
            ]
            .map(OsString::from),
        );
    }
    argv
}

// --- WHAT A ZONE IS TO AN INSTANCE --------------------------------------------

/// FNV-1a, 64 bits: `bytes` hashed on from `hash`.
fn fnv(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// The first half of a zone's fingerprint: the config it came up with, as
/// its holder read it (`zone::prepare`) — the very bytes, not the file as it
/// may read later.
pub fn config_seed(config: &[u8]) -> u64 {
    fnv(0xcbf2_9ce4_8422_2325, config)
}

/// A zone's fingerprint: its config ([`config_seed`]), the resolvers its
/// passts forward DNS to and its search domains. What an instance takes a
/// zone that came back by (O3 of the design): the same, and it is the exit
/// the instance was carried by — re-attached by itself; another (the config
/// edited, a gateway that named other resolvers), and it is another exit,
/// which is never taken as a side effect: the instance stays cut until the
/// person says (`cellward container reattach`). Not a secret and no proof
/// against the user: a change of the user's own is what it tells.
pub fn fingerprint(
    seed: u64,
    resolver4: Option<Ipv4Addr>,
    resolver6: Option<Ipv6Addr>,
    search: &[String],
) -> u64 {
    let mut hash = fnv(seed, b"\0resolvers\0");
    for resolver in [resolver4.map(IpAddr::V4), resolver6.map(IpAddr::V6)] {
        let text = resolver.map(|r| r.to_string()).unwrap_or_default();
        hash = fnv(fnv(hash, text.as_bytes()), b"\0");
    }
    hash = fnv(hash, b"search\0");
    for domain in search {
        hash = fnv(fnv(hash, domain.as_bytes()), b"\0");
    }
    hash
}

/// The group passt runs with in a zone: the zone's root's subordinate gid
/// with [`BRIDGE_ID`] added, mapped onto itself (`zone::map_args`) — read
/// from the zone's `gid_map`. `None`: the zone was not mapped for it, and
/// carries nothing.
pub fn bridge_gid(gid_map: &str) -> Option<u32> {
    let lines: Vec<(u64, u64, u64)> = gid_map
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace().map(str::parse::<u64>);
            Some((
                fields.next()?.ok()?,
                fields.next()?.ok()?,
                fields.next()?.ok()?,
            ))
        })
        .collect();
    let root = lines
        .iter()
        .find(|(inside, _, count)| *inside == 0 && *count > 0)
        .map(|(_, outside, _)| *outside)?;
    let want = root + u64::from(BRIDGE_ID);
    let mapped = lines
        .iter()
        .any(|(inside, outside, count)| *inside == want && *outside == want && *count > 0);
    mapped.then(|| u32::try_from(want).ok()).flatten()
}

/// Every address `ip -j addr show` names, both families: a namespace's own
/// addresses, which the bridge's passt is refused
/// (`zone::bridge_refusal_rules`). `None` when the text is not the list `ip`
/// gives — never an empty list for one that was not read.
pub fn local_addresses(json: &str) -> Option<Vec<IpAddr>> {
    let value = crate::json::parse(json).ok()?;
    let mut out = Vec::new();
    for link in value.as_array()? {
        let Some(infos) = link.get("addr_info").and_then(|a| a.as_array()) else {
            continue;
        };
        for info in infos {
            if let Some(address) = info.get("local").and_then(|l| l.as_str()) {
                out.push(address.parse().ok()?);
            }
        }
    }
    Some(out)
}

/// Whether a zone that is up carries container instances: its socket is
/// there. A zone of a previous build — one an update left running — has
/// none, and a launch into it is refused with its restart (`launch::
/// no_bridge_refusal`; into the zone's own namespaces until stage 5): the
/// socket's presence says so, never a build's name.
pub fn carries(zone_dir: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    fs::symlink_metadata(zone_dir.join(SOCKET)).is_ok_and(|m| m.file_type().is_socket())
}

/// The `resolv.conf` of an instance a zone carries: the constant forwarders
/// ([`D4`], and [`D6`] when the zone carries IPv6) and the zone's search
/// domains. Never a real resolver: what a program cached stays right when
/// the passt behind the address is another.
pub fn resolv_text(v6: bool, search: &[String]) -> String {
    let mut text = format!("nameserver {D4}\n");
    if v6 {
        text.push_str(&format!("nameserver {D6}\n"));
    }
    if !search.is_empty() {
        text.push_str(&format!("search {}\n", search.join(" ")));
    }
    text
}

/// The search domains of a `resolv.conf` text: the words of its last
/// `search` line — what a zone's bridge answers with (`Carrier::search`, the
/// same line split the same way), read by an instance's keeper before a live
/// switch (stage 4, O8 of the design).
pub fn search_in(resolv: &str) -> Vec<String> {
    resolv
        .lines()
        .filter_map(|line| line.trim().strip_prefix("search"))
        .rfind(|rest| rest.starts_with([' ', '\t']))
        .map(|rest| rest.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default()
}

// --- THE ZONE'S END -----------------------------------------------------------

/// What a zone carries instances with ([`serve`]), fixed as it came up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carrier {
    /// The zone's name, for its journal.
    pub zone: String,
    pub passt: PathBuf,
    /// The one uid that may ask: the user's, as the zone's user namespace
    /// sees it (the owner of the zone's directory).
    pub owner: u32,
    /// passt's group ([`bridge_gid`]). `None`: nothing is carried.
    pub gid: Option<u32>,
    /// Whether the zone's refusal of its own addresses to passt is loaded
    /// ([`RULE_MARK`]). Without it nothing is carried.
    pub ruled: bool,
    /// Whether the zone carries IPv6: an instance gets it only then.
    pub v6: bool,
    pub resolver4: Option<Ipv4Addr>,
    pub resolver6: Option<Ipv6Addr>,
    pub search: Vec<String>,
    pub fp: u64,
}

/// The most a request takes: the word, an id of 128 letters of four bytes,
/// two addresses.
const REQUEST_MAX: usize = 1024;

/// The zone's end of the bridge: every connection to its socket in a thread
/// of its own, for as long as the zone lives. A thread and not a process:
/// the passt it starts dies with the thread (`PR_SET_PDEATHSIG`), the thread
/// with the zone's process, and the zone's unit takes what is left.
pub fn serve(listener: UnixListener, carrier: Carrier) {
    let carrier = std::sync::Arc::new(carrier);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let mine = std::sync::Arc::clone(&carrier);
                let spawned = std::thread::Builder::new()
                    .name("bridge".to_owned())
                    .spawn(move || attend(stream, &mine));
                if let Err(e) = spawned {
                    eprintln!(
                        "zone {}: the bridge cannot take a request ({e})",
                        carrier.zone
                    );
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                // Out of descriptors, for one: looked at again in a moment,
                // which decides how soon and nothing else.
                eprintln!("zone {}: the bridge cannot accept ({e})", carrier.zone);
                std::thread::sleep(crate::sys::LOOK_AGAIN);
            }
        }
    }
}

/// The uid of the process on the other end, as this process's user
/// namespace sees it (`SO_PEERCRED`).
pub(crate) fn peer_uid(fd: RawFd) -> Option<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: a descriptor, a correctly sized buffer and its length.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    (rc == 0).then_some(cred.uid)
}

/// A socket's type (`SO_TYPE`); `None` for a descriptor that is no socket.
fn socket_type(fd: RawFd) -> Option<libc::c_int> {
    let mut kind: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: a descriptor, a buffer of one int and its length.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    (rc == 0).then_some(kind)
}

/// A request as the zone takes it — or why not: from the zone's user
/// ([`Carrier::owner`]; `peer` as `SO_PEERCRED` says it), to a zone that
/// has its refusal loaded and passt's group mapped, with one descriptor — a
/// stream socket, above 2 — and words the grammar takes ([`Request::decode`]).
/// The descriptor and passt's group come with it.
pub fn admit(
    c: &Carrier,
    peer: Option<u32>,
    bytes: &[u8],
    mut fds: Vec<OwnedFd>,
) -> Result<(Request, OwnedFd, u32), String> {
    if peer != Some(c.owner) {
        return Err("only the zone's user may ask it for a way out".to_owned());
    }
    if !c.ruled {
        return Err(format!(
            "zone {} has not loaded its refusal of its own addresses to the bridge \
             (nftables) — it carries no container",
            c.zone
        ));
    }
    let Some(gid) = c.gid else {
        return Err(format!(
            "zone {} was mapped without the bridge's ids — restart it",
            c.zone
        ));
    };
    if fds.len() != 1 {
        return Err(format!(
            "a request comes with one descriptor, not {}",
            fds.len()
        ));
    }
    let fd = fds.pop().ok_or("a request without its descriptor")?;
    if fd.as_raw_fd() <= 2 || socket_type(fd.as_raw_fd()) != Some(libc::SOCK_STREAM) {
        return Err("the descriptor that came is not a stream socket".to_owned());
    }
    let request = Request::decode(bytes)?;
    Ok((request, fd, gid))
}

/// One line to the requester; one gone meanwhile is nobody to tell.
fn answer(stream: &UnixStream, answer: &Answer) {
    let mut writer = stream;
    let _ = writer.write_all(answer.encode().as_bytes());
}

/// A status as a shell reports it: the exit code, or the signal negative.
fn status_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| -status.signal().unwrap_or(0))
}

/// One request: taken, answered, and held for as long as both sides live.
fn attend(stream: UnixStream, c: &Carrier) {
    let fd = stream.as_raw_fd();
    let admitted = crate::sys::recv_with_fds(fd, REQUEST_MAX, 1)
        .map_err(|e| format!("the request could not be read ({e})"))
        .and_then(|(bytes, fds)| admit(c, peer_uid(fd), &bytes, fds));
    let (request, relay_end, gid) = match admitted {
        Ok(admitted) => admitted,
        Err(why) => {
            eprintln!("zone {}: a way out refused: {why}", c.zone);
            answer(&stream, &Answer::Refused(why));
            return;
        }
    };
    let plan = PasstPlan {
        guest: GuestPlan {
            a4: request.plan.a4,
            // IPv6 for the instance only where the zone has it to give.
            a6: request.plan.a6.filter(|_| c.v6),
        },
        resolver4: c.resolver4,
        resolver6: c.resolver6,
    };
    let refuse = |why: String| {
        eprintln!(
            "zone {}: no way out for instance {}: {why}",
            c.zone, request.instance
        );
        answer(&stream, &Answer::Refused(why));
    };
    let word = match Word::new(BRIDGE_ID, gid) {
        Ok(word) => word,
        Err(e) => return refuse(format!("no pid file for passt ({e})")),
    };
    let mut child = match spawn_passt(&c.passt, &word.path(), &relay_end, gid, &plan) {
        Ok(child) => child,
        Err(e) => return refuse(format!("cannot start passt ({e})")),
    };
    // passt has its end now: ours would keep the stream open past it.
    drop(relay_end);
    let Some(pidfd) = crate::sys::pidfd_open(child.id() as i32) else {
        let _ = child.kill();
        let _ = child.wait();
        return refuse("no pidfd of passt".to_owned());
    };
    match crate::sys::wait_for_entry_or(&word.path(), Some(&pidfd), Some(fd), crate::sys::written) {
        crate::sys::Waited::There => {}
        crate::sys::Waited::MakerGone => {
            let status = child.wait().map_or(-1, status_code);
            return refuse(format!("passt ended before it was ready (status {status})"));
        }
        crate::sys::Waited::PeerGone => {
            crate::sys::pidfd_signal(&pidfd, libc::SIGKILL);
            let _ = child.wait();
            return;
        }
    }
    drop(word);
    println!(
        "zone {}: carries instance {} ({}{})",
        c.zone,
        request.instance,
        plan.guest.a4,
        plan.guest.a6.map(|a| format!(", {a}")).unwrap_or_default()
    );
    answer(
        &stream,
        &Answer::Attached {
            v6: plan.guest.a6.is_some(),
            search: c.search.clone(),
            fp: c.fp,
        },
    );
    match hold_passt(&stream, &pidfd, &mut child) {
        Some(code) => {
            eprintln!(
                "zone {}: the way out of instance {} ended (passt: {code})",
                c.zone, request.instance
            );
            answer(&stream, &Answer::Exited(code));
        }
        None => println!(
            "zone {}: instance {} let go of its way out",
            c.zone, request.instance
        ),
    }
}

/// Wait for passt's end or the requester's, whichever comes first — as long
/// as that takes: passt ended, its status; the requester gone (or saying
/// anything, which a requester has no reason to), passt killed and `None`.
fn hold_passt(stream: &UnixStream, pidfd: &OwnedFd, child: &mut Child) -> Option<i32> {
    let gone = libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR;
    loop {
        let mut fds = [
            libc::pollfd {
                fd: pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLIN | libc::POLLRDHUP,
                revents: 0,
            },
        ];
        // SAFETY: two valid pollfds for the duration of the call.
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                std::thread::sleep(crate::sys::LOOK_AGAIN);
            }
            continue;
        }
        if fds[0].revents != 0 {
            return Some(child.wait().map_or(-1, status_code));
        }
        if fds[1].revents & (libc::POLLIN | gone) != 0 {
            crate::sys::pidfd_signal(pidfd, libc::SIGKILL);
            let _ = child.wait();
            return None;
        }
    }
}

/// passt's word that it is ready: its pid file, made for its user in a
/// directory of its own under `/tmp` that it may pass through (0711) — the
/// zone's directory is out of its reach, as out of pasta's
/// (`zone::PastaWord`). Gone with this.
struct Word {
    dir: PathBuf,
}

impl Word {
    fn new(uid: u32, gid: u32) -> io::Result<Self> {
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::PermissionsExt;
        let mut template = b"/tmp/vpn-zone-bridge.XXXXXX\0".to_vec();
        // SAFETY: a writable NUL-terminated template ending in six Xs.
        let made = unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) };
        if made.is_null() {
            return Err(io::Error::last_os_error());
        }
        template.pop();
        let word = Self {
            dir: PathBuf::from(OsString::from_vec(template)),
        };
        fs::set_permissions(&word.dir, fs::Permissions::from_mode(0o711))?;
        crate::sys::pid_file_for(&word.path(), uid, gid)?;
        Ok(word)
    }

    fn path(&self) -> PathBuf {
        self.dir.join("passt.pid")
    }
}

impl Drop for Word {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// passt for one instance ([`passt_argv`]), as [`BRIDGE_ID`] and `gid`, with
/// no supplementary group, no way to new privileges, and killed with the
/// thread that holds it (`PR_SET_PDEATHSIG`, set after the ids change,
/// which clears it; a parent gone before it was set is a refusal). An empty
/// environment: nothing of the zone's holder's is passt's business.
fn spawn_passt(
    passt: &Path,
    pid_file: &Path,
    stream: &OwnedFd,
    gid: u32,
    plan: &PasstPlan,
) -> io::Result<Child> {
    let fd = stream.as_raw_fd();
    let argv = passt_argv(passt, pid_file, fd, plan);
    // SAFETY: getpid(2) takes no arguments and cannot fail.
    let parent = unsafe { libc::getpid() };
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]).env_clear().stdin(Stdio::null());
    // SAFETY: between fork and exec only async-signal-safe calls, with plain
    // integers or a null pointer.
    unsafe {
        cmd.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setresgid(gid, gid, gid) != 0
                || libc::setresuid(BRIDGE_ID, BRIDGE_ID, BRIDGE_ID) != 0
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }
    cmd.spawn()
}

// --- THE INSTANCE'S END -------------------------------------------------------

/// Why an instance got no way out ([`attach`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoLink {
    /// Its keeper was asked to stop meanwhile.
    Stopped,
    /// The zone is not the one that carried the instance: its fingerprint
    /// is this other one ([`fingerprint`]).
    Changed(u64),
    /// Anything else, as the journal says it.
    Failed(String),
}

impl std::fmt::Display for NoLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stopped => write!(f, "stopped meanwhile"),
            Self::Changed(fp) => write!(f, "the zone is another one now ({fp:016x})"),
            Self::Failed(why) => write!(f, "{why}"),
        }
    }
}

/// What the relay is started with besides its stream: our own binary, and
/// the tools it configures its tap with.
pub struct RelayTools<'a> {
    pub core: &'a Path,
    pub ip: &'a Path,
    pub nft: &'a Path,
    /// The instance's counters' file (`crate::traffic`), which the relay
    /// counts every frame into; none, and it counts nothing.
    pub tally: Option<RawFd>,
}

/// A container instance's way out through a zone.
pub struct Link {
    /// The request, open: the zone's hold on its passt, and the zone's word
    /// when that passt ends.
    pub control: UnixStream,
    /// The relay (`crate::relay`), in the instance's namespaces as their root.
    pub relay: Child,
    pub relay_fd: OwnedFd,
    /// The instance's side of this attach.
    pub plan: GuestPlan,
    /// Whether the instance got IPv6: the zone carries it.
    pub v6: bool,
    pub search: Vec<String>,
    pub fp: u64,
}

impl Link {
    /// Whether the zone's side has ended, looked at when the request's
    /// connection has something: its end, or the zone's `EXIT` — whatever
    /// comes after the `OK` says the passt is gone.
    pub fn zone_ended(&self) -> bool {
        let mut buf = [0u8; 256];
        loop {
            // SAFETY: a buffer of the length passed, alive for the call.
            let n = unsafe {
                libc::recv(
                    self.control.as_raw_fd(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if n >= 0 {
                return true;
            }
            match io::Error::last_os_error().kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => return false,
                _ => return true,
            }
        }
    }

    /// Cut: the request dropped — the zone kills its passt —, the relay
    /// killed and waited for; its tap goes with its last descriptor.
    pub fn close(mut self) {
        let _ = self.control.shutdown(std::net::Shutdown::Both);
        crate::sys::pidfd_signal(&self.relay_fd, libc::SIGKILL);
        let _ = self.relay.wait();
    }
}

/// Empty a non-blocking pipe.
fn drain(fd: RawFd) {
    let mut buf = [0u8; 64];
    // SAFETY: read(2) into a buffer of the length passed.
    while unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
}

/// Poll `fd` and the keeper's wake-up pipe: `Ok` once `fd` has something,
/// `Err(Stopped)` when the keeper was told to stop meanwhile.
fn wait_readable(fd: RawFd, wake: Option<RawFd>, stop: &dyn Fn() -> bool) -> Result<(), NoLink> {
    loop {
        let mut fds = [
            libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                // A negative descriptor is skipped.
                fd: wake.unwrap_or(-1),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: two valid pollfds for the duration of the call.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if rc < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            std::thread::sleep(crate::sys::LOOK_AGAIN);
        }
        if fds[1].revents != 0 {
            if let Some(wake) = wake {
                drain(wake);
            }
        }
        if stop() {
            return Err(NoLink::Stopped);
        }
        if rc > 0 && fds[0].revents != 0 {
            return Ok(());
        }
    }
}

/// The zone's first line, a byte at a time — what follows it is the zone's
/// later word and stays on the connection —, as long as it takes, or until
/// the keeper is told to stop.
fn read_line(
    stream: &UnixStream,
    wake: Option<RawFd>,
    stop: &dyn Fn() -> bool,
) -> Result<String, NoLink> {
    let mut line: Vec<u8> = Vec::new();
    loop {
        wait_readable(stream.as_raw_fd(), wake, stop)?;
        let mut byte = [0u8; 1];
        // SAFETY: a buffer of one byte, alive for the call.
        let n = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                byte.as_mut_ptr().cast(),
                1,
                libc::MSG_DONTWAIT,
            )
        };
        if n == 0 {
            return Err(NoLink::Failed(
                "the zone hung up without an answer".to_owned(),
            ));
        }
        if n < 0 {
            let e = io::Error::last_os_error();
            if matches!(
                e.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(NoLink::Failed(format!("the zone's answer: {e}")));
        }
        if byte[0] == b'\n' {
            return String::from_utf8(line)
                .map_err(|_| NoLink::Failed("an answer that is not UTF-8".to_owned()));
        }
        line.push(byte[0]);
        if line.len() > REQUEST_MAX * 4 {
            return Err(NoLink::Failed("an answer longer than any".to_owned()));
        }
    }
}

/// The relay's word that its tap is up and it is sealed — or its end first.
fn relay_ready(
    ready: &OwnedFd,
    relay: &OwnedFd,
    wake: Option<RawFd>,
    stop: &dyn Fn() -> bool,
) -> Result<(), NoLink> {
    let early = || NoLink::Failed("the relay ended before its tap was up".to_owned());
    loop {
        let mut fds = [
            libc::pollfd {
                fd: ready.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: relay.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake.unwrap_or(-1),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: three valid pollfds for the duration of the call.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 3, -1) };
        if rc < 0 {
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                std::thread::sleep(crate::sys::LOOK_AGAIN);
            }
            continue;
        }
        if fds[2].revents != 0 {
            if let Some(wake) = wake {
                drain(wake);
            }
        }
        if stop() {
            return Err(NoLink::Stopped);
        }
        if fds[0].revents != 0 {
            let mut byte = [0u8; 1];
            // SAFETY: a buffer of one byte, alive for the call.
            let n = unsafe { libc::read(ready.as_raw_fd(), byte.as_mut_ptr().cast(), 1) };
            if n == 1 && byte[0] == b'1' {
                return Ok(());
            }
            if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(early());
        }
        if fds[1].revents != 0 {
            return Err(early());
        }
    }
}

/// The relay, started into the instance's user and network namespaces as
/// their root: joined through the space's pidfd, uid and gid 0 there, no
/// group of the user's — and then an `exec`, which makes its memory the
/// instance's user namespace's own (J3 of the design): only the user, that
/// namespace's owner, may read it, and it makes itself not dumpable first
/// thing (`crate::relay`). Its stream and its word's pipe by their numbers,
/// made inheritable between fork and exec; the instance's counters' file
/// (`crate::traffic`) too, when it has one.
fn spawn_relay(
    tools: &RelayTools<'_>,
    space: &OwnedFd,
    stream: &UnixStream,
    ready: &OwnedFd,
    plan: &GuestPlan,
    wall: Option<crate::relay::Wall>,
) -> io::Result<Child> {
    let (stream_fd, ready_fd) = (stream.as_raw_fd(), ready.as_raw_fd());
    let tally = tools.tally;
    let args = crate::relay::Attach {
        stream: stream_fd,
        ready: ready_fd,
        a4: plan.a4,
        a6: plan.a6,
        ip: tools.ip.to_path_buf(),
        nft: tools.nft.to_path_buf(),
        wall,
        tally,
    }
    .args();
    let mut keep = vec![stream_fd, ready_fd];
    keep.extend(tally);
    let mut cmd = in_instance(tools.core, space, &keep);
    cmd.arg("frame-relay").args(args).stdin(Stdio::null());
    cmd.spawn()
}

/// Our own binary, to be run in the instance's user and network namespaces
/// as their root (the relay, and stage 4's probe and seal): joined through
/// the space's pidfd, uid and gid 0 there, no group of the user's — and
/// then its `exec`, which makes its memory the instance's user namespace's
/// own (J3 of the design). `keep`: descriptors made inheritable between
/// fork and exec. Its mount namespace stays the host's, where
/// `/dev/net/tun` and `/sys/fs/cgroup` are the host's (J5).
pub fn in_instance(core: &Path, space: &OwnedFd, keep: &[RawFd]) -> Command {
    let space_fd = space.as_raw_fd();
    let mut keep_fds: [RawFd; 4] = [-1; 4];
    for (slot, fd) in keep_fds.iter_mut().zip(keep) {
        *slot = *fd;
    }
    let mut cmd = Command::new(core);
    // SAFETY: between fork and exec only async-signal-safe calls, with plain
    // integers or a null pointer. The child is single-threaded, as joining a
    // user namespace wants.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setns(space_fd, libc::CLONE_NEWUSER | libc::CLONE_NEWNET) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setresgid(0, 0, 0) != 0
                || libc::setresuid(0, 0, 0) != 0
            {
                return Err(io::Error::last_os_error());
            }
            for fd in keep_fds.into_iter().filter(|fd| *fd >= 0) {
                if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    cmd
}

/// `frame-relay --probe` in the instance whose space `space` holds its
/// namespaces (stage 4, `crate::epoch`): its line, or why there is none.
pub fn probe(core: &Path, nft: &Path, space: &OwnedFd, wall: crate::relay::Wall) -> String {
    let walled = crate::relay::Walled {
        nft: nft.to_path_buf(),
        wall: Some(wall),
    };
    let out = in_instance(core, space, &[])
        .arg("frame-relay")
        .arg("--probe")
        .args(walled.args())
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output();
    match out {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_owned(),
        Ok(out) => format!("probe-failed status={}", out.status),
        Err(e) => format!("probe-failed {e}"),
    }
}

/// `frame-relay --seal` in the instance (stage 4, a switch's break): the
/// tally of what it destroyed, or why it did not seal.
pub fn seal(core: &Path, nft: &Path, space: &OwnedFd) -> Result<crate::sockdiag::Tally, String> {
    let walled = crate::relay::Walled {
        nft: nft.to_path_buf(),
        wall: None,
    };
    let out = in_instance(core, space, &[])
        .arg("frame-relay")
        .arg("--seal")
        .args(walled.args())
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("the seal did not start ({e})"))?;
    if !out.status.success() {
        return Err(format!("the seal failed ({})", out.status));
    }
    Ok(crate::sockdiag::Tally::parse(&String::from_utf8_lossy(
        &out.stdout,
    )))
}

/// An attach that failed at `what`, for the journal.
fn failed(what: &str, e: impl std::fmt::Display) -> NoLink {
    NoLink::Failed(format!("{what}: {e}"))
}

/// Ask the zone in `zone_dir` for a way out for instance `id`, whose space
/// `space` (a pidfd) holds its namespaces, and start the relay into it.
/// `previous`: the last attach's plan, whose addresses are not taken again.
/// `expect`: the fingerprint the instance was carried by — a return, not the
/// person's own ask; another one is [`NoLink::Changed`], and nothing is
/// started. `wall`: the epoch's wall the relay loads the instance's rules
/// with (stage 4, `crate::epoch`; none before the instance's first switch).
/// `wake` and `stop`: the keeper's word to give up, heard while it waits
/// (no clock: the zone answers once its passt is up, or refuses).
#[allow(clippy::too_many_arguments)]
pub fn attach(
    zone_dir: &Path,
    id: &str,
    space: &OwnedFd,
    previous: Option<GuestPlan>,
    expect: Option<u64>,
    wall: Option<crate::relay::Wall>,
    tools: &RelayTools<'_>,
    wake: Option<RawFd>,
    stop: &dyn Fn() -> bool,
) -> Result<Link, NoLink> {
    let asked = plan(previous, true).map_err(|e| failed("no addresses for the attach", e))?;
    let (ours, theirs) = UnixStream::pair().map_err(|e| failed("no socket pair", e))?;
    let held = crate::sys::open_dir(zone_dir).map_err(|e| failed("the zone's directory", e))?;
    let control = UnixStream::connect(format!("/proc/self/fd/{}/{SOCKET}", held.as_raw_fd()))
        .map_err(|e| failed("the zone's bridge does not answer", e))?;
    drop(held);
    let request = Request {
        instance: id.to_owned(),
        plan: asked,
    };
    crate::sys::send_with_fds(
        control.as_raw_fd(),
        &request.encode(),
        &[theirs.as_raw_fd()],
    )
    .map_err(|e| failed("the request did not go", e))?;
    drop(theirs);
    let line = read_line(&control, wake, stop)?;
    let (v6, search, fp) =
        match Answer::decode(&line).map_err(|e| failed("the zone's answer", e))? {
            Answer::Attached { v6, search, fp } => (v6, search, fp),
            Answer::Refused(why) => return Err(NoLink::Failed(format!("the zone refused: {why}"))),
            Answer::Exited(code) => {
                return Err(NoLink::Failed(format!(
                    "the zone's passt ended at once ({code})"
                )))
            }
        };
    if expect.is_some_and(|expected| expected != fp) {
        return Err(NoLink::Changed(fp));
    }
    let plan = GuestPlan {
        a4: asked.a4,
        a6: asked.a6.filter(|_| v6),
    };
    let (ready_r, ready_w) = crate::sys::pipe().map_err(|e| failed("no pipe", e))?;
    let mut relay = spawn_relay(tools, space, &ours, &ready_w, &plan, wall)
        .map_err(|e| failed("the relay did not start", e))?;
    // The relay's now: a copy here would keep its stream and its word open
    // past it.
    drop(ours);
    drop(ready_w);
    let Some(relay_fd) = crate::sys::pidfd_open(relay.id() as i32) else {
        let _ = relay.kill();
        let _ = relay.wait();
        return Err(NoLink::Failed("no pidfd of the relay".to_owned()));
    };
    if let Err(e) = relay_ready(&ready_r, &relay_fd, wake, stop) {
        crate::sys::pidfd_signal(&relay_fd, libc::SIGKILL);
        let _ = relay.wait();
        return Err(e);
    }
    Ok(Link {
        control,
        relay,
        relay_fd,
        plan,
        v6,
        search,
        fp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hostif() -> [Ipv4Addr; 2] {
        [
            crate::zone::HOSTIF_GUEST4.parse().unwrap(),
            crate::zone::HOSTIF_GATEWAY4.parse().unwrap(),
        ]
    }

    #[test]
    fn the_constants_are_where_the_design_puts_them() {
        assert_eq!(G4.to_string(), "10.254.255.254");
        assert_eq!(D4.to_string(), "10.254.255.253");
        assert_eq!(D6.to_string(), "fd63:656c:6c77::53");
        assert_eq!(G6.to_string(), "fe80::1");
        assert_eq!(a4_from(0x0102), Ipv4Addr::new(10, 254, 1, 2));
        assert_eq!(a6_from(0x1234).to_string(), "fd63:656c:6c77::1234");
        // The forwarders are in their networks and taken by nobody.
        assert!(!a4_usable(D4, None) && !a4_usable(G4, None));
        assert!(!a6_usable(D6, None));
    }

    /// Whatever the draw, the address is in the network and none of the
    /// ones it must not be — the gateway, the forwarder, a host-interface
    /// zone's, the network's ends, the previous attach's.
    #[test]
    fn no_draw_gives_a_forbidden_ipv4_address() {
        let previous = Ipv4Addr::new(10, 254, 7, 7);
        let mut forbidden = vec![
            G4,
            D4,
            previous,
            Ipv4Addr::new(10, 254, 0, 0),
            Ipv4Addr::new(10, 254, 255, 255),
        ];
        forbidden.extend(hostif());
        for bits in 0..=u16::MAX {
            let a = pick_a4(Some(previous), [bits]);
            assert!(!forbidden.contains(&a), "{bits:#x} gave {a}");
            assert_eq!(a.octets()[..2], [10, 254], "{bits:#x} gave {a}");
            assert!(a4_usable(a, Some(previous)));
        }
        // A draw that is usable is taken as it is.
        assert_eq!(pick_a4(None, [0x0707]), previous);
        // Draws that are all refused: the first free one from the bottom.
        assert_eq!(
            pick_a4(Some(Ipv4Addr::new(10, 254, 0, 1)), [0xfffe; 100]),
            Ipv4Addr::new(10, 254, 0, 2)
        );
        assert_eq!(pick_a4(None, []), Ipv4Addr::new(10, 254, 0, 1));
    }

    #[test]
    fn no_draw_gives_a_forbidden_ipv6_address() {
        let previous = a6_from(0x1234_5678_9abc_def0);
        for iid in [
            0,
            1,
            0x53,
            0xffff,
            0x1_0000,
            0x1234_5678_9abc_def0,
            IID_RESERVED - 1,
            IID_RESERVED,
            u64::MAX,
        ] {
            let a = pick_a6(Some(previous), [iid]);
            assert_ne!(a, previous, "{iid:#x}");
            assert_ne!(a, D6, "{iid:#x}");
            assert!(a6_usable(a, Some(previous)), "{iid:#x} gave {a}");
            assert_eq!(a.segments()[..4], ULA6.segments()[..4], "{iid:#x} gave {a}");
        }
        assert_eq!(pick_a6(None, [0x1_0000]), a6_from(0x1_0000));
        assert_eq!(pick_a6(Some(a6_from(IID_LOW)), []), a6_from(IID_LOW + 1));
        // Outside the /64: never usable.
        assert!(!a6_usable("fd63:656c:6c78::1:0".parse().unwrap(), None));
    }

    #[test]
    fn a_plan_is_new_every_time() {
        let first = plan(None, true).unwrap();
        assert!(a4_usable(first.a4, None));
        assert!(first.a6.is_some_and(|a| a6_usable(a, None)));
        let next = plan(Some(first), true).unwrap();
        assert_ne!(next.a4, first.a4);
        assert_ne!(next.a6, first.a6);
        assert_eq!(plan(Some(first), false).unwrap().a6, None);
    }

    fn request(v6: bool) -> Request {
        Request {
            instance: "docs:nl".to_string(),
            plan: GuestPlan {
                a4: Ipv4Addr::new(10, 254, 3, 4),
                a6: v6.then(|| a6_from(0xabcd_0000_0000_0001)),
            },
        }
    }

    #[test]
    fn a_request_goes_there_and_back() {
        for v6 in [false, true] {
            let r = request(v6);
            assert_eq!(Request::decode(&r.encode()), Ok(r));
        }
        assert_eq!(
            request(false).encode(),
            b"VZA1\x00docs:nl\x000\x0010.254.3.4\x00\x00".to_vec()
        );
    }

    #[test]
    fn a_malformed_request_is_refused() {
        let good = request(true).encode();
        let bad = [
            Vec::new(),
            b"VZA1\x00".to_vec(),
            good[..good.len() - 1].to_vec(),
            [&good[..], &b"x\x00"[..]].concat(),
            [&b"VZA2"[..], &good[4..]].concat(),
            b"VZA1\x00../x\x000\x0010.254.3.4\x00\x00".to_vec(),
            b"VZA1\x00work:unconfined\x000\x0010.254.3.4\x00\x00".to_vec(),
            b"VZA1\x00work\x000\x0010.99.0.2\x00\x00".to_vec(),
            b"VZA1\x00work\x000\x0010.254.255.253\x00\x00".to_vec(),
            b"VZA1\x00work\x001\x0010.254.3.4\x00\x00".to_vec(),
            b"VZA1\x00work\x000\x0010.254.3.4\x00fd63:656c:6c77::1:0\x00".to_vec(),
            b"VZA1\x00work\x001\x0010.254.3.4\x00fd99::2\x00".to_vec(),
            b"VZA1\x00work\x001\x0010.254.3.4\x00fd63:656c:6c77::53\x00".to_vec(),
            b"VZA1\x00work\x002\x0010.254.3.4\x00\x00".to_vec(),
            b"VZA1\x00w\xffrk\x000\x0010.254.3.4\x00\x00".to_vec(),
        ];
        for b in &bad {
            assert!(
                Request::decode(b).is_err(),
                "{:?}",
                String::from_utf8_lossy(b)
            );
        }
    }

    #[test]
    fn answers_go_there_and_back() {
        for a in [
            Answer::Attached {
                v6: true,
                search: vec!["corp.example".to_string(), "lab.example".to_string()],
                fp: 0x0123_4567_89ab_cdef,
            },
            Answer::Attached {
                v6: false,
                search: Vec::new(),
                fp: 0,
            },
            Answer::Attached {
                v6: false,
                search: Vec::new(),
                fp: u64::MAX,
            },
            Answer::Refused("the zone is not ready".to_string()),
            Answer::Exited(1),
            Answer::Exited(-9),
        ] {
            let line = a.encode();
            assert!(
                line.ends_with('\n') && line.matches('\n').count() == 1,
                "{line:?}"
            );
            assert_eq!(Answer::decode(&line), Ok(a));
        }
        assert_eq!(
            Answer::Attached {
                v6: true,
                search: vec!["corp.example".to_string()],
                fp: 0xab,
            }
            .encode(),
            "OK v6=1 search=corp.example fp=00000000000000ab\n"
        );
        // A reason is one line, whatever it held.
        assert_eq!(
            Answer::Refused("two\nlines".to_string()).encode(),
            "ERR two lines\n"
        );
        // Stage 2 (2026-09-27): an OK carries the zone's fingerprint; one
        // without it — or with anything but sixteen hex digits — is none.
        for bad in [
            "",
            "OK",
            "OK v6=2 search= fp=0000000000000000",
            "OK v6=1",
            "OK v6=1 search=",
            "OK v6=1 search=a b fp=0000000000000000",
            "OK v6=1 search=a,,b fp=0000000000000000",
            "OK v6=1 search=a;b fp=0000000000000000",
            "OK v6=1 search= fp=",
            "OK v6=1 search= fp=123",
            "OK v6=1 search= fp=+123456789abcdef",
            "OK v6=1 search= fp=0123456789abcdefg",
            "OK v6=1 search= fp=0000000000000000 x",
            "EXIT x",
            "HELLO",
            "OK v6=1 search= fp=0000000000000000\nEXIT 0",
        ] {
            assert!(Answer::decode(bad).is_err(), "{bad:?}");
        }
    }

    /// The fingerprint tells a zone's config, resolvers and search domains
    /// apart, and the same ones give the same one every time.
    #[test]
    fn a_zones_fingerprint_is_its_config_resolvers_and_search() {
        let seed = config_seed(b"[Interface]\nPrivateKey = x\n");
        let r4 = Some(Ipv4Addr::new(10, 99, 0, 1));
        let r6: Option<Ipv6Addr> = Some("fd99::1".parse().unwrap());
        let search = vec!["corp.example".to_string()];
        let fp = fingerprint(seed, r4, r6, &search);
        assert_eq!(fp, fingerprint(seed, r4, r6, &search));
        for other in [
            fingerprint(
                config_seed(b"[Interface]\nPrivateKey = y\n"),
                r4,
                r6,
                &search,
            ),
            fingerprint(seed, Some(Ipv4Addr::new(10, 99, 0, 2)), r6, &search),
            fingerprint(seed, r4, None, &search),
            fingerprint(seed, None, r6, &search),
            fingerprint(seed, r4, r6, &[]),
            fingerprint(seed, r4, r6, &["lab.example".to_string()]),
            fingerprint(
                seed,
                r4,
                r6,
                &["corp.example".to_string(), "lab.example".to_string()],
            ),
        ] {
            assert_ne!(fp, other);
        }
        // Words cannot run into one another.
        assert_ne!(
            fingerprint(seed, None, None, &["ab".to_string(), "c".to_string()]),
            fingerprint(seed, None, None, &["a".to_string(), "bc".to_string()])
        );
    }

    /// passt's group is the root's subordinate gid plus two, mapped onto
    /// itself; a zone mapped otherwise has none.
    #[test]
    fn the_bridges_group_is_read_from_the_zones_map() {
        let map = "         0     100000          1\n      1000       1000          1\n    100002     100002          1\n";
        assert_eq!(bridge_gid(map), Some(100_002));
        // An OpenConnect zone's client's line changes nothing.
        let with_client = "0 100000 1\n1000 1000 1\n1 100001 1\n100002 100002 1\n";
        assert_eq!(bridge_gid(with_client), Some(100_002));
        // Mapped as 2, not onto itself; not mapped at all; no root.
        assert_eq!(bridge_gid("0 100000 1\n1000 1000 1\n2 100002 1\n"), None);
        assert_eq!(bridge_gid("0 100000 1\n1000 1000 1\n"), None);
        assert_eq!(bridge_gid("1000 1000 1\n100002 100002 1\n"), None);
        assert_eq!(bridge_gid(""), None);
    }

    /// What `ip -j addr show` of a zone's app namespace says: every address
    /// of every link; text that is not its list is nothing read.
    #[test]
    fn a_namespaces_own_addresses_from_ip_json() {
        let json = r#"[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP"],"addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"},{"family":"inet6","local":"::1","prefixlen":128,"scope":"host"}]},{"ifindex":3,"ifname":"awg0","flags":["POINTOPOINT","UP"],"addr_info":[{"family":"inet","local":"10.99.0.2","prefixlen":32,"scope":"global"},{"family":"inet6","local":"fd99::2","prefixlen":128,"scope":"global"},{"family":"inet6","local":"fe80::1c2d","prefixlen":64,"scope":"link"}]},{"ifindex":4,"ifname":"down0","addr_info":[]}]"#;
        let got = local_addresses(json).unwrap();
        let want: Vec<IpAddr> = ["127.0.0.1", "::1", "10.99.0.2", "fd99::2", "fe80::1c2d"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        assert_eq!(got, want);
        // Into the refusal they go (the zone's side of it).
        let rules = crate::zone::bridge_refusal_rules(BRIDGE_ID, &got);
        assert!(rules[0].contains("10.99.0.2"), "{rules:?}");
        assert!(rules[1].contains("fd99::2"), "{rules:?}");
        assert_eq!(local_addresses("[]"), Some(Vec::new()));
        assert_eq!(local_addresses("not json"), None);
        assert_eq!(local_addresses("{}"), None);
        assert_eq!(
            local_addresses(r#"[{"addr_info":[{"local":"not an address"}]}]"#),
            None
        );
    }

    #[test]
    fn an_instances_resolv_conf_names_the_forwarders_only() {
        assert_eq!(resolv_text(false, &[]), "nameserver 10.254.255.253\n");
        assert_eq!(
            resolv_text(
                true,
                &["corp.example".to_string(), "lab.example".to_string()]
            ),
            "nameserver 10.254.255.253\nnameserver fd63:656c:6c77::53\nsearch corp.example lab.example\n"
        );
    }

    /// A zone's search domains as its `resolv.conf` has them — the same list
    /// its bridge answers with, what a live switch compares (stage 4).
    #[test]
    fn a_zones_search_domains_are_its_last_search_line() {
        assert!(search_in("nameserver 10.99.0.1\n").is_empty());
        assert_eq!(
            search_in("nameserver 10.99.0.1\nsearch corp.example  lab.example\n"),
            vec!["corp.example".to_owned(), "lab.example".to_owned()]
        );
        assert_eq!(
            search_in("search a.example\nsearch b.example\n"),
            vec!["b.example".to_owned()]
        );
        assert!(search_in("searching x\n").is_empty());
        let text = resolv_text(false, &["corp.example".to_owned()]);
        assert_eq!(search_in(&text), vec!["corp.example".to_owned()]);
    }

    fn carrier() -> Carrier {
        Carrier {
            zone: "nl".to_string(),
            passt: PathBuf::from("/nix/store/x-passt/bin/passt"),
            owner: 1000,
            gid: Some(100_002),
            ruled: true,
            v6: true,
            resolver4: Some(Ipv4Addr::new(10, 99, 0, 1)),
            resolver6: None,
            search: Vec::new(),
            fp: 7,
        }
    }

    /// A stream socket's end, as the relay's would come.
    fn stream_end() -> OwnedFd {
        let (a, _b) = UnixStream::pair().unwrap();
        a.into()
    }

    /// The zone takes a request only from its user, only with its refusal
    /// loaded and passt's group mapped, only with one stream socket, and
    /// only in words the grammar takes.
    #[test]
    fn the_zone_takes_a_request_only_as_it_should_come() {
        let c = carrier();
        let good = request(true).encode();
        let (taken, fd, gid) = admit(&c, Some(1000), &good, vec![stream_end()]).unwrap();
        assert_eq!(taken, request(true));
        assert_eq!(gid, 100_002);
        assert!(fd.as_raw_fd() > 2);
        // Somebody else, or nobody known.
        assert!(admit(&c, Some(1001), &good, vec![stream_end()]).is_err());
        assert!(admit(&c, Some(0), &good, vec![stream_end()]).is_err());
        assert!(admit(&c, None, &good, vec![stream_end()]).is_err());
        // A zone without its refusal, or without passt's group.
        let unruled = Carrier {
            ruled: false,
            ..carrier()
        };
        assert!(admit(&unruled, Some(1000), &good, vec![stream_end()]).is_err());
        let unmapped = Carrier {
            gid: None,
            ..carrier()
        };
        assert!(admit(&unmapped, Some(1000), &good, vec![stream_end()]).is_err());
        // No descriptor, two, one that is no stream socket.
        assert!(admit(&c, Some(1000), &good, Vec::new()).is_err());
        assert!(admit(&c, Some(1000), &good, vec![stream_end(), stream_end()]).is_err());
        let (datagram, _other) = std::os::unix::net::UnixDatagram::pair().unwrap();
        assert!(admit(&c, Some(1000), &good, vec![datagram.into()]).is_err());
        let file: OwnedFd = fs::File::open("/dev/null").unwrap().into();
        assert!(admit(&c, Some(1000), &good, vec![file]).is_err());
        // Words that are none.
        assert!(admit(&c, Some(1000), b"VZA1\0../x\0", vec![stream_end()]).is_err());
    }

    /// A zone carries instances when its socket is there — a socket, not a
    /// file of that name.
    #[test]
    fn a_zone_carries_when_its_socket_is_there() {
        let dir = std::env::temp_dir().join(format!("vz-bridge-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        assert!(!carries(&dir));
        fs::write(dir.join(SOCKET), "").unwrap();
        assert!(!carries(&dir));
        fs::remove_file(dir.join(SOCKET)).unwrap();
        let listener = UnixListener::bind(dir.join(SOCKET)).unwrap();
        assert!(carries(&dir));
        drop(listener);
        let _ = fs::remove_dir_all(&dir);
    }

    fn passt_plan(v6: bool, r4: bool, r6: bool) -> PasstPlan {
        PasstPlan {
            guest: request(v6).plan,
            resolver4: r4.then(|| Ipv4Addr::new(10, 99, 0, 1)),
            resolver6: r6.then(|| "fd99::1".parse().unwrap()),
        }
    }

    fn words(argv: &[OsString]) -> Vec<String> {
        argv.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    /// Every plan shuts every door, names no path but its binary and its
    /// pid file, and forwards DNS of a family only to a resolver of that
    /// family.
    #[test]
    fn passt_always_runs_with_its_doors_shut() {
        let passt = Path::new("/nix/store/x-passt/bin/passt");
        let pid = Path::new("/tmp/vpn-zone-bridge.a1/passt.pid");
        for v6 in [false, true] {
            for r4 in [false, true] {
                for r6 in [false, true] {
                    let argv = words(&passt_argv(passt, pid, 9, &passt_plan(v6, r4, r6)));
                    let has = |pair: &[&str]| argv.windows(pair.len()).any(|w| w == pair);
                    let doors: &[&[&str]] = &[
                        &["--fd", "9"],
                        &["-f"],
                        &["--no-dhcp"],
                        &["--no-dhcpv6"],
                        &["--no-ra"],
                        &["--no-map-gw"],
                        &["--map-guest-addr", "none"],
                        &["-t", "none"],
                        &["-u", "none"],
                        &["-a", "10.254.3.4", "-n", "16", "-g", "10.254.255.254"],
                    ];
                    for &door in doors {
                        assert!(has(door), "{door:?} missing: {argv:?}");
                    }
                    for never in [
                        "-s",
                        "--socket",
                        "-p",
                        "--pcap",
                        "-l",
                        "--log-file",
                        "--netns",
                        "--userns",
                        "--runas",
                        "-T",
                        "-U",
                        "-D",
                        "--dns",
                        "-i",
                        "-o",
                    ] {
                        assert!(!argv.iter().any(|w| w == never), "{never} in {argv:?}");
                    }
                    let paths: Vec<&String> = argv.iter().filter(|w| w.starts_with('/')).collect();
                    assert_eq!(paths, [&argv[0], &argv[6]], "{argv:?}");
                    assert_eq!(argv[5], "-P");
                    assert_eq!(v6, !argv.iter().any(|w| w == "-4"), "{argv:?}");
                    assert_eq!(v6, has(&["-g", "fe80::1"]), "{argv:?}");
                    assert_eq!(
                        r4,
                        has(&["--dns-forward", "10.254.255.253", "--dns-host", "10.99.0.1"])
                    );
                    assert_eq!(
                        v6 && r6,
                        has(&[
                            "--dns-forward",
                            "fd63:656c:6c77::53",
                            "--dns-host",
                            "fd99::1"
                        ]),
                        "{argv:?}"
                    );
                    let forwards = argv.iter().filter(|w| *w == "--dns-forward").count();
                    let hosts = argv.iter().filter(|w| *w == "--dns-host").count();
                    assert_eq!(forwards, hosts, "{argv:?}");
                }
            }
        }
    }
}
