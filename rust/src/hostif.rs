//! Zones that go out through an interface of the host (`docs/CONTAINERS.md`
//! §3.3): a second uplink, a modem, a VPN the system itself brought up.
//!
//! No tunnel of ours and no uplink namespace: pasta attaches straight to the
//! app namespace, names its interface `awg0` — the one name the zone's filter,
//! `doctor` and `vpn-zone check` know — and binds every socket it opens on the
//! host to the chosen interface (`--outbound-if4/-if6`, i.e. `SO_BINDTODEVICE`).
//! A packet from the zone therefore leaves by that interface or not at all:
//! when the interface goes down or away, the zone is offline, not rerouted.
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

use std::net::IpAddr;

use crate::config::WgConfig;

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
}
