//! What the cellward window's scheme draws of the host (`_panel`'s `iface`
//! and `endpoint` lines): the host's interfaces, each with its kind — a
//! cable, a radio, a virtual one —, and for each zone its tunnel and its
//! server, with the interface and the gateway the host reaches that server
//! by. Read, never changed: the scheme is to see where a zone is linked and
//! where it is not.

use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::process::{Command, Stdio};

/// A host's interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iface {
    pub name: String,
    /// `ethernet`, `wifi`, `loopback`, `virtual`.
    pub kind: &'static str,
    pub up: bool,
    pub addrs: Vec<String>,
}

/// The kind of interface `name`, from sysfs: a radio has `wireless` (or its
/// `uevent` says `wlan`), a device behind a bus (`device`) is a cable's,
/// anything else — a tunnel, a bridge, a veth — is virtual.
pub fn kind_of(sys: &Path, name: &str) -> &'static str {
    let dir = sys.join(name);
    if name == "lo" {
        return "loopback";
    }
    let uevent = fs::read_to_string(dir.join("uevent")).unwrap_or_default();
    if dir.join("wireless").exists()
        || dir.join("phy80211").exists()
        || uevent.lines().any(|l| l == "DEVTYPE=wlan")
    {
        return "wifi";
    }
    if uevent.lines().any(|l| l.starts_with("DEVTYPE=")) {
        return "virtual";
    }
    if dir.join("device").exists() {
        "ethernet"
    } else {
        "virtual"
    }
}

/// The host's interfaces and their addresses (`ip -o addr show`).
pub fn ifaces(ip: &Path) -> Vec<Iface> {
    let sys = Path::new("/sys/class/net");
    let addrs = Command::new(ip)
        .args(["-o", "addr", "show"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let mut names: Vec<String> = fs::read_dir(sys)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let up = fs::read_to_string(sys.join(&name).join("operstate"))
                .is_ok_and(|s| s.trim() == "up" || s.trim() == "unknown");
            Iface {
                kind: kind_of(sys, &name),
                up,
                addrs: addrs_of(&addrs, &name),
                name,
            }
        })
        .collect()
}

/// The addresses of `name` in `ip -o addr show`'s lines (`2: eth0    inet
/// 192.0.2.5/24 …`).
pub fn addrs_of(text: &str, name: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            let _index = w.next()?;
            (w.next()? == name).then_some(())?;
            let family = w.next()?;
            (family == "inet" || family == "inet6").then_some(())?;
            w.next().map(str::to_owned)
        })
        .collect()
}

/// The interface and the gateway the host reaches `addr` by (`ip -o route
/// get`): `(dev, via)`.
pub fn route_to(ip: &Path, addr: IpAddr) -> Option<(String, Option<String>)> {
    let out = Command::new(ip)
        .args(["-o", "route", "get", &addr.to_string()])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    parse_route(&String::from_utf8_lossy(&out.stdout))
}

/// The interface and gateway `addr` is reached by in the network namespace of
/// process `pid` — a zone's app namespace —, entered as the user
/// (`nsenter -U -n`, read only): what a packet there really takes, not what
/// it is meant to.
pub fn route_in(
    nsenter: &Path,
    ip: &Path,
    pid: i32,
    addr: IpAddr,
) -> Option<(String, Option<String>)> {
    let out = Command::new(nsenter)
        .args([
            "--preserve-credentials",
            "-U",
            "-n",
            "-t",
            &pid.to_string(),
            "--",
        ])
        .arg(ip)
        .args(["-o", "route", "get", &addr.to_string()])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    parse_route(&String::from_utf8_lossy(&out.stdout))
}

/// `dev` and `via` of a `route get` line.
pub fn parse_route(text: &str) -> Option<(String, Option<String>)> {
    let words: Vec<&str> = text.split_whitespace().collect();
    let after = |key: &str| {
        words
            .iter()
            .position(|w| *w == key)
            .and_then(|i| words.get(i + 1))
            .map(|w| (*w).to_owned())
    };
    Some((after("dev")?, after("via")))
}

/// A zone's tunnel as its config says: its kind, and each server (`raw`,
/// the address the zone goes to, whether it was a name).
pub struct Tunnel {
    /// `amneziawg`, `wireguard`, `openconnect`, `host`, `system`.
    pub kind: &'static str,
    pub servers: Vec<(String, Option<IpAddr>, bool)>,
}

/// [`Tunnel`] of the zone whose directory is `dir`; its servers' addresses
/// a literal's, or the kept one of a name (`zone::ENDPOINT_CACHE`).
pub fn tunnel_of(dir: &Path) -> Option<Tunnel> {
    let raw = fs::read(dir.join("config.conf")).ok()?;
    let cfg = crate::config::WgConfig::parse(&raw).ok()?;
    let kind = if crate::openconnect::is_openconnect(&cfg) {
        "openconnect"
    } else if crate::hostif::is_host_network(&cfg) || crate::hostif::is_host_interface(&cfg) {
        "host"
    } else if crate::sysuplink::is_system_zone(&cfg) {
        "system"
    } else if cfg.sections.iter().flat_map(|s| s.entries.iter()).any(|e| {
        ["Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"]
            .iter()
            .any(|k| e.key.eq_ignore_ascii_case(k))
    }) {
        "amneziawg"
    } else {
        "wireguard"
    };
    let kept = crate::zone::read_endpoint_cache(&dir.join(crate::zone::ENDPOINT_CACHE));
    let servers = cfg
        .sections
        .iter()
        .flat_map(|s| s.entries.iter())
        .filter(|e| e.key.eq_ignore_ascii_case("Endpoint"))
        .filter_map(|e| crate::config::Endpoint::parse(&e.value))
        .map(|ep| match &ep.host {
            crate::config::EndpointHost::V4(a) => (ep.raw.clone(), Some(IpAddr::V4(*a)), false),
            crate::config::EndpointHost::V6(a) => (ep.raw.clone(), Some(IpAddr::V6(*a)), false),
            crate::config::EndpointHost::Name(n) => (ep.raw.clone(), kept.get(n).copied(), true),
        })
        .collect();
    Some(Tunnel { kind, servers })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hosts_side_is_read() {
        let addrs = "1: lo    inet 127.0.0.1/8 scope host lo\n\
                     2: wlp2s0    inet 192.168.1.5/24 brd 192.168.1.255 scope global wlp2s0\n\
                     2: wlp2s0    inet6 fe80::1/64 scope link\n\
                     3: enp3s0    link/ether 00:11:22:33:44:55\n";
        assert_eq!(addrs_of(addrs, "wlp2s0"), ["192.168.1.5/24", "fe80::1/64"]);
        assert!(addrs_of(addrs, "enp3s0").is_empty());
        assert_eq!(
            parse_route("203.0.113.5 via 192.168.1.1 dev wlp2s0 src 192.168.1.5 uid 1000"),
            Some(("wlp2s0".to_owned(), Some("192.168.1.1".to_owned())))
        );
        assert_eq!(
            parse_route("192.168.1.9 dev wlp2s0 src 192.168.1.5"),
            Some(("wlp2s0".to_owned(), None))
        );
        assert_eq!(
            parse_route("RTNETLINK answers: Network is unreachable"),
            None
        );
        assert_eq!(kind_of(Path::new("/sys/class/net"), "lo"), "loopback");
    }
}
