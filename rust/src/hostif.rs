//! Zones that go out through an interface of the host (`docs/CONTAINERS.md`
//! §3.3): a second uplink, a modem, a VPN the system itself brought up.
//!
//! No tunnel of ours and no uplink namespace: pasta attaches straight to the
//! app namespace, names its interface `awg0` — the one name the zone's filter,
//! `doctor` and `vpn-zone check` know — and binds every socket it opens on the
//! host to the chosen interface (`--outbound-if4/-if6`, i.e. `SO_BINDTODEVICE`).
//! A packet from the zone therefore leaves by that interface or not at all:
//! when the interface goes down, the zone is offline, not rerouted.
//!
//! **When it goes AWAY, pasta alone is not enough.** Binding a socket to an
//! interface that no longer exists fails (ENODEV), and pasta takes that for
//! a note in its debug log and connects the TCP socket unbound — by the host's
//! routes, with the host's address (review 2026-09-24, passt's
//! `tcp_bind_outbound`). So the holder watches the interface over rtnetlink
//! ([`watch_interface`]) and kills pasta the moment the interface is deleted or
//! renamed: the zone goes down, as for any dead uplink.
//!
//! What such a zone does NOT do is encrypt, and it is named for that everywhere
//! it is shown.
//!
//! The config is a file like the others, so that `vpn-zone add` stays one verb:
//!
//! ```ini
//! [HostInterface]
//! Interface = enp4s0
//! DNS = 192.168.1.1, 9.9.9.9
//! ```

use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::config::WgConfig;

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const IFLA_IFNAME: u16 = 3;
/// `struct nlmsghdr`, `struct ifinfomsg`.
const NLMSG_HDR: usize = 16;
const IFINFO: usize = 16;

/// The index of a host interface, from sysfs.
fn ifindex(name: &str) -> Option<i32> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Does this batch of rtnetlink messages say interface `index` is gone — deleted,
/// or renamed away from `name`?
pub fn link_gone(messages: &[u8], index: i32, name: &str) -> bool {
    let mut at = 0;
    while at + NLMSG_HDR <= messages.len() {
        let u32_at = |i: usize| u32::from_ne_bytes(messages[i..i + 4].try_into().unwrap_or([0; 4]));
        let len = u32_at(at) as usize;
        if len < NLMSG_HDR || at + len > messages.len() {
            break;
        }
        let kind = u16::from_ne_bytes([messages[at + 4], messages[at + 5]]);
        let body = &messages[at + NLMSG_HDR..at + len];
        if (kind == RTM_NEWLINK || kind == RTM_DELLINK) && body.len() >= IFINFO {
            let this = i32::from_ne_bytes(body[4..8].try_into().unwrap_or([0; 4]));
            if this == index {
                if kind == RTM_DELLINK {
                    return true;
                }
                // Attributes: a name other than ours is a rename.
                let mut a = IFINFO;
                while a + 4 <= body.len() {
                    let alen = u16::from_ne_bytes([body[a], body[a + 1]]) as usize;
                    let atype = u16::from_ne_bytes([body[a + 2], body[a + 3]]) & 0x3fff;
                    if alen < 4 || a + alen > body.len() {
                        break;
                    }
                    if atype == IFLA_IFNAME {
                        let value = &body[a + 4..a + alen];
                        let value = value.split(|b| *b == 0).next().unwrap_or(value);
                        if value != name.as_bytes() {
                            return true;
                        }
                    }
                    a += (alen + 3) & !3;
                }
            }
        }
        at += (len + 3) & !3;
    }
    false
}

/// Watch the host interface `name` from the namespace we are in, and call
/// `gone` once, the moment it is deleted or renamed (see the module's notes).
/// An error when it cannot be watched — the caller does not start then: a
/// zone bound to an interface nobody watches would leak the day it goes.
pub fn watch_interface<F>(name: &str, gone: F) -> io::Result<()>
where
    F: FnOnce() + Send + 'static,
{
    // SAFETY: socket(2) with constant arguments.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a descriptor we just opened and own.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: sockaddr_nl is plain data.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr.nl_groups = libc::RTMGRP_LINK as u32;
    // SAFETY: a valid descriptor and an address of the size given.
    let bound = unsafe {
        libc::bind(
            sock.as_raw_fd(),
            (&addr as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bound != 0 {
        return Err(io::Error::last_os_error());
    }
    // Looked up AFTER subscribing: a deletion in between is either seen here
    // or arrives as a message.
    let index = ifindex(name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no interface {name}")))?;
    let name = name.to_owned();
    std::thread::Builder::new()
        .name("watch-interface".to_owned())
        .spawn(move || {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                // SAFETY: a valid descriptor and a buffer of the length given.
                let n =
                    unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
                if n < 0 {
                    match io::Error::last_os_error().raw_os_error() {
                        Some(libc::EINTR) => continue,
                        // Messages lost to an overflow: look again ourselves.
                        Some(libc::ENOBUFS) => {
                            if ifindex(&name) != Some(index) {
                                break;
                            }
                            continue;
                        }
                        // Cannot watch any more: as good as gone.
                        _ => break,
                    }
                }
                if n == 0 || link_gone(&buf[..n.unsigned_abs()], index, &name) {
                    break;
                }
            }
            gone();
        })?;
    Ok(())
}

/// The section that makes a config a host-interface zone.
pub const SECTION: &str = "HostInterface";

/// A parsed `[HostInterface]` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostIfConfig {
    /// The host's interface every packet leaves by.
    pub interface: String,
    /// Resolvers for the zone's resolv.conf — literal addresses only: the zone
    /// has no resolver to look a name up with before it has these.
    pub dns: Vec<IpAddr>,
}

/// Is this a host-interface config?
pub fn is_host_interface(ini: &WgConfig) -> bool {
    ini.section(SECTION).is_some()
}

/// A Linux interface name: 1–15 bytes, no `/`, no whitespace, not `.`/`..`.
pub fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name != "."
        && name != ".."
        && !name
            .bytes()
            .any(|b| b == b'/' || b == b':' || b.is_ascii_whitespace() || b < 0x20)
}

/// Can the zone use IPv6 through this interface: a global address on it
/// (`/proc/net/if_inet6`, scope `00`) and a default route through it
/// (`/proc/net/ipv6_route`, not the kernel's unreachable one)?
///
/// Without both, pasta refuses to start when told to bind IPv6 to the
/// interface — and NOT binding it while leaving IPv6 on would let IPv6 go out
/// by whatever interface the host routes it through. So the answer decides
/// between binding IPv6 and switching it off in the zone altogether.
pub fn ipv6_usable(interface: &str, if_inet6: &str, ipv6_route: &str) -> bool {
    let global_address = if_inet6.lines().any(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        f.len() >= 6 && f[5] == interface && f[3] == "00"
    });
    global_address
        && crate::doctor::default_routes6(ipv6_route)
            .iter()
            .any(|dev| dev == interface)
}

impl HostIfConfig {
    pub fn from_ini(ini: &WgConfig) -> Result<Self, String> {
        let section = ini
            .section(SECTION)
            .ok_or_else(|| format!("нет секции [{SECTION}]"))?;
        let interface = section
            .get("Interface")
            .map(str::trim)
            .filter(|i| !i.is_empty())
            .ok_or_else(|| format!("[{SECTION}]: нужен Interface = <интерфейс хоста>"))?;
        if !valid_interface_name(interface) {
            return Err(format!("[{SECTION}]: «{interface}» — не имя интерфейса"));
        }
        // Loopback leads nowhere but the host itself, and `awg0` is the name
        // the zone's own end has: neither is a way out.
        if interface == "lo" || interface == "awg0" {
            return Err(format!(
                "[{SECTION}]: через «{interface}» зона выйти не может — нужен внешний интерфейс"
            ));
        }
        let mut dns = Vec::new();
        if let Some(list) = section.get("DNS") {
            for item in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let addr: IpAddr = item.parse().map_err(|_| {
                    format!(
                        "[{SECTION}]: DNS «{item}» — нужен адрес, не имя: резолвить его зоне ещё нечем"
                    )
                })?;
                dns.push(addr);
            }
        }
        Ok(Self {
            interface: interface.to_owned(),
            dns,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<HostIfConfig, String> {
        let ini = WgConfig::parse(text.as_bytes()).map_err(|e| e.to_string())?;
        HostIfConfig::from_ini(&ini)
    }

    #[test]
    fn a_host_interface_config_names_an_interface_and_literal_resolvers() {
        let cfg =
            parse("[HostInterface]\nInterface = enp4s0\nDNS = 192.168.1.1, 2001:db8::1\n").unwrap();
        assert_eq!(cfg.interface, "enp4s0");
        assert_eq!(cfg.dns.len(), 2);
        assert!(parse("[HostInterface]\nInterface = wg-home\n")
            .unwrap()
            .dns
            .is_empty());

        for bad in [
            "[HostInterface]\n",
            "[HostInterface]\nInterface = lo\n",
            "[HostInterface]\nInterface = awg0\n",
            "[HostInterface]\nInterface = a/b\n",
            "[HostInterface]\nInterface = averyveryverylongname\n",
            "[HostInterface]\nInterface = eth0\nDNS = dns.example\n",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        let inet6 = "fe800000000000000000000000000001 04 40 20 80 vmdummy\n\
                     20010db8000100000000000000000001 03 40 00 80 eth1\n";
        let zero = "00000000000000000000000000000000";
        let routes = format!("{zero} 00 {zero} 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth1\n");
        assert!(ipv6_usable("eth1", inet6, &routes));
        assert!(!ipv6_usable("vmdummy", inet6, &routes), "link-local only");
        assert!(!ipv6_usable("eth1", inet6, ""), "no default route");

        let ini = WgConfig::parse(b"[HostInterface]\nInterface = eth0\n").unwrap();
        assert!(is_host_interface(&ini));
        let wg = WgConfig::parse(b"[Interface]\nPrivateKey = x\n").unwrap();
        assert!(!is_host_interface(&wg));
    }

    /// A deletion of our interface, a rename of it, and anything else.
    #[test]
    fn a_link_deleted_or_renamed_is_gone() {
        fn msg(kind: u16, index: i32, name: Option<&str>) -> Vec<u8> {
            let mut body = vec![0u8; IFINFO];
            body[4..8].copy_from_slice(&index.to_ne_bytes());
            if let Some(name) = name {
                let mut attr = name.as_bytes().to_vec();
                attr.push(0);
                let alen = (4 + attr.len()) as u16;
                body.extend_from_slice(&alen.to_ne_bytes());
                body.extend_from_slice(&IFLA_IFNAME.to_ne_bytes());
                body.extend_from_slice(&attr);
                while !body.len().is_multiple_of(4) {
                    body.push(0);
                }
            }
            let len = (NLMSG_HDR + body.len()) as u32;
            let mut out = len.to_ne_bytes().to_vec();
            out.extend_from_slice(&kind.to_ne_bytes());
            out.extend_from_slice(&[0u8; 10]);
            out.extend_from_slice(&body);
            out
        }
        assert!(link_gone(&msg(RTM_DELLINK, 7, None), 7, "wg-corp"));
        assert!(!link_gone(&msg(RTM_DELLINK, 8, None), 7, "wg-corp"));
        assert!(link_gone(
            &msg(RTM_NEWLINK, 7, Some("wg-old")),
            7,
            "wg-corp"
        ));
        assert!(!link_gone(
            &msg(RTM_NEWLINK, 7, Some("wg-corp")),
            7,
            "wg-corp"
        ));
        let mut two = msg(RTM_NEWLINK, 3, Some("eth0"));
        two.extend(msg(RTM_DELLINK, 7, None));
        assert!(link_gone(&two, 7, "wg-corp"));
        assert!(!link_gone(&[1, 2, 3], 7, "wg-corp"));
    }
}
