//! Where a zone's DNS goes past its tunnel, for the person to see
//! (`docs/LEAK-MODEL.md` §6): a resolver of the VPN's own side — an address
//! of a private, shared or link-local range, reached inside the tunnel and
//! answered by the VPN's server or its network — or a public one, which the
//! VPN's server asks for the zone across the internet, in clear: its
//! operator and everything on the way read the names. Told by the address
//! alone; nothing is asked.

use std::net::IpAddr;
use std::path::Path;

/// Where a resolver is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// On the VPN's side: the tunnel's end and its network.
    Vpn,
    /// A public address: past the VPN's server, in clear.
    Public,
}

impl Side {
    pub fn word(self) -> &'static str {
        match self {
            Self::Vpn => "vpn",
            Self::Public => "public",
        }
    }
}

/// The side of resolver `addr`.
pub fn side_of(addr: IpAddr) -> Side {
    let vpn = match addr {
        IpAddr::V4(a) => {
            let o = a.octets();
            a.is_private()
                || a.is_link_local()
                || a.is_loopback()
                // Shared address space, 100.64.0.0/10 (carriers', Tailscale's).
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            // Unique local fc00::/7, link-local fe80::/10.
            (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80 || a.is_loopback()
        }
    };
    if vpn {
        Side::Vpn
    } else {
        Side::Public
    }
}

/// The resolvers of the zone whose directory is `dir`, from its config's
/// `DNS =`, each with its side. None for a config with none (an OpenConnect
/// zone's come from its server; a host zone's are the host's).
pub fn of_zone(dir: &Path) -> Vec<(IpAddr, Side)> {
    let Ok(raw) = std::fs::read(dir.join("config.conf")) else {
        return Vec::new();
    };
    let Ok(cfg) = crate::config::WgConfig::parse(&raw) else {
        return Vec::new();
    };
    cfg.dns()
        .iter()
        .filter_map(|d| d.parse::<IpAddr>().ok())
        .map(|a| (a, side_of(a)))
        .collect()
}

/// For a person: where the names its programs ask go.
pub fn words(found: &[(IpAddr, Side)]) -> String {
    if found.is_empty() {
        return "DNS — от сервера VPN или хоста (в конфиге не задан)".to_owned();
    }
    let public: Vec<String> = found
        .iter()
        .filter(|(_, s)| *s == Side::Public)
        .map(|(a, _)| a.to_string())
        .collect();
    if public.is_empty() {
        let all: Vec<String> = found.iter().map(|(a, _)| a.to_string()).collect();
        format!(
            "DNS {} — на стороне VPN: зашифрован до сервера VPN, дальше — у провайдера VPN",
            all.join(", ")
        )
    } else {
        format!(
            "DNS {} — публичный резолвер: от сервера VPN до него имена идут открытым текстом — \
             их видят оператор сервера и всё по пути",
            public.join(", ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_resolvers_side_is_its_address() {
        for vpn in [
            "10.8.1.1",
            "172.16.0.1",
            "192.168.1.1",
            "100.100.100.100",
            "fd00::1",
            "fe80::1",
        ] {
            assert_eq!(side_of(vpn.parse().unwrap()), Side::Vpn, "{vpn}");
        }
        for public in ["1.1.1.1", "8.8.8.8", "9.9.9.9", "2606:4700:4700::1111"] {
            assert_eq!(side_of(public.parse().unwrap()), Side::Public, "{public}");
        }
        let mixed = [
            ("10.8.1.1".parse().unwrap(), Side::Vpn),
            ("1.1.1.1".parse().unwrap(), Side::Public),
        ];
        assert!(words(&mixed).contains("1.1.1.1 — публичный"));
        assert!(words(&mixed[..1]).contains("на стороне VPN"));
        assert!(words(&[]).contains("не задан"));
    }
}
