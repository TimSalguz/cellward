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

use std::ffi::OsString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// The id passt runs as in a zone, mapped from the user's subordinate range
/// like the zone's root (0) and the OpenConnect client (1). The zone's
/// refusal of its local addresses is keyed on it (`zone::bridge_refusal_rules`).
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
/// The descriptor passt is handed its end of the stream on.
pub const PASST_FD: i32 = 3;
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
fn random_bytes(buf: &mut [u8]) -> io::Result<()> {
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
    /// carries IPv6, and the zone's search domains for the instance's
    /// `resolv.conf`. `OK v6=<0|1> search=<domain,…>`.
    Attached { v6: bool, search: Vec<String> },
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
            Self::Attached { v6, search } => {
                format!("OK v6={} search={}\n", u8::from(*v6), search.join(","))
            }
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
            let (v6, search) = rest
                .split_once(' ')
                .ok_or("an OK without its search domains")?;
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
            return Ok(Self::Attached { v6, search });
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

/// passt's command line for one instance: `--fd 3`, in the foreground, its
/// pid file as its word that it is ready (as pasta's, `zone::PastaWord`),
/// and every door shut that the instance does not need.
///
/// **One-off** by `--fd`: passt ends when the stream does. Its IPv6 when
/// the instance has an address for it, else `-4`. No path but the binary
/// and the pid file: no socket, capture or log file of passt's, no
/// namespace to open.
pub fn passt_argv(passt: &Path, pid_file: &Path, plan: &PasstPlan) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec![
        passt.into(),
        "--fd".into(),
        PASST_FD.to_string().into(),
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
            b"VZA1\x00unconfined:x\x000\x0010.254.3.4\x00\x00".to_vec(),
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
            },
            Answer::Attached {
                v6: false,
                search: Vec::new(),
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
                search: vec!["corp.example".to_string()]
            }
            .encode(),
            "OK v6=1 search=corp.example\n"
        );
        // A reason is one line, whatever it held.
        assert_eq!(
            Answer::Refused("two\nlines".to_string()).encode(),
            "ERR two lines\n"
        );
        for bad in [
            "",
            "OK",
            "OK v6=2 search=",
            "OK v6=1",
            "OK v6=1 search=a b",
            "OK v6=1 search=a,,b",
            "OK v6=1 search=a;b",
            "EXIT x",
            "HELLO",
            "OK v6=1 search=\nEXIT 0",
        ] {
            assert!(Answer::decode(bad).is_err(), "{bad:?}");
        }
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
                    let argv = words(&passt_argv(passt, pid, &passt_plan(v6, r4, r6)));
                    let has = |pair: &[&str]| argv.windows(pair.len()).any(|w| w == pair);
                    let doors: &[&[&str]] = &[
                        &["--fd", "3"],
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
