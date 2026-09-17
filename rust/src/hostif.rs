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
        let ini = WgConfig::parse(b"[HostInterface]\nInterface = eth0\n").unwrap();
        assert!(is_host_interface(&ini));
        let wg = WgConfig::parse(b"[Interface]\nPrivateKey = x\n").unwrap();
        assert!(!is_host_interface(&wg));
    }
}
