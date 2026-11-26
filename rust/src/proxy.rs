//! A SOCKS5 or HTTP CONNECT proxy as a full-tunnel zone, carried by sing-box.

use std::net::IpAddr;

use crate::config::WgConfig;
use crate::openconnect::Plan;

pub const SECTION: &str = "Proxy";
pub const CONFIG_FILE: &str = "sing-box.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Socks5,
    Http,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub kind: Kind,
    pub server: IpAddr,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub adapter: Option<String>,
    pub addresses: Vec<String>,
    pub plan: Plan,
}

pub fn is_proxy(ini: &WgConfig) -> bool {
    ini.section(SECTION).is_some()
}

impl Config {
    pub fn from_ini(ini: &WgConfig, iface: &str) -> Result<Self, String> {
        let section = ini.section(SECTION).ok_or("no [Proxy] section")?;
        const KEYS: &[&str] = &["Type", "Server", "Port", "Username", "Password", "Adapter"];
        if let Some(key) = section
            .entries
            .iter()
            .find(|entry| !KEYS.iter().any(|key| entry.key.eq_ignore_ascii_case(key)))
            .map(|entry| entry.key.as_str())
        {
            return Err(format!("[Proxy]: unknown key {key}"));
        }
        let kind = match required(section, "Type")?.as_str() {
            "socks5" => Kind::Socks5,
            "http" => Kind::Http,
            other => return Err(format!("[Proxy] Type = {other}: expected socks5 or http")),
        };
        let server = required(section, "Server")?
            .parse::<IpAddr>()
            .map_err(|_| "[Proxy] Server must be a literal IPv4 or IPv6 address".to_owned())?;
        if server.is_unspecified() || server.is_multicast() {
            return Err("[Proxy] Server must be a unicast address".to_owned());
        }
        let port = required(section, "Port")?
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or("[Proxy] Port must be a number 1..65535")?;
        let interface = ini.interface().ok_or("a proxy zone needs [Interface]")?;
        const INTERFACE_KEYS: &[&str] = &["Address", "DNS", "MTU"];
        if let Some(key) = interface
            .entries
            .iter()
            .find(|entry| {
                !INTERFACE_KEYS
                    .iter()
                    .any(|key| entry.key.eq_ignore_ascii_case(key))
            })
            .map(|entry| entry.key.as_str())
        {
            return Err(format!(
                "a proxy zone's [Interface] accepts only Address, DNS and MTU, not {key}"
            ));
        }
        if ini.section("Peer").is_some() {
            return Err("a proxy zone has no [Peer]".to_owned());
        }
        let addresses = ini.addresses();
        if addresses.is_empty()
            || addresses
                .iter()
                .any(|address| address.ip.is_none() || address.prefix_len.is_none())
        {
            return Err(
                "[Interface] Address must contain literal addresses with prefixes".to_owned(),
            );
        }
        let mut address4 = None;
        let mut address6 = None;
        for address in &addresses {
            match address.ip {
                Some(IpAddr::V4(ip)) if address4.is_none() => address4 = Some(ip),
                Some(IpAddr::V6(ip)) if address6.is_none() => address6 = Some(ip),
                Some(IpAddr::V4(_)) => {
                    return Err("a proxy zone accepts one IPv4 address".to_owned())
                }
                Some(IpAddr::V6(_)) => {
                    return Err("a proxy zone accepts one IPv6 address".to_owned())
                }
                None => unreachable!(),
            }
        }
        let address =
            address4.ok_or("a proxy zone needs one IPv4 address in [Interface] Address")?;
        let dns = ini
            .dns()
            .into_iter()
            .map(|value| {
                value
                    .parse::<IpAddr>()
                    .map_err(|_| format!("[Interface] DNS is not an address: {value}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mtu = ini.mtu().unwrap_or(crate::zone::DEFAULT_MTU);
        if !(576..=65535).contains(&mtu) {
            return Err("[Interface] MTU must be 576–65535".to_owned());
        }
        Ok(Self {
            kind,
            server,
            port,
            username: section.get("Username").map(str::to_owned),
            password: section.get("Password").map(str::to_owned),
            adapter: section.get("Adapter").map(str::to_owned),
            addresses: addresses.into_iter().map(|address| address.raw).collect(),
            plan: Plan {
                iface: iface.to_owned(),
                address,
                ipv6_offered: false,
                address6,
                mtu,
                dns,
                search: None,
                ignored_splits: 0,
            },
        })
    }

    pub fn sing_box_config(&self) -> String {
        use crate::status::string;
        let (kind, extra) = match self.kind {
            Kind::Socks5 => ("socks", "".to_owned()),
            Kind::Http => ("http", ",\"network\":\"tcp\"".to_owned()),
        };
        let username = self
            .username
            .as_ref()
            .map(|value| format!(",\"username\":{}", string(value)))
            .unwrap_or_default();
        let password = self
            .password
            .as_ref()
            .map(|value| format!(",\"password\":{}", string(value)))
            .unwrap_or_default();
        let addresses = self
            .addresses
            .iter()
            .map(|address| string(address))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"log\":{{\"level\":\"warn\"}},\"inbounds\":[{{\"type\":\"tun\",\"tag\":\"zone\",\"interface_name\":{},\"address\":[{}],\"mtu\":{},\"stack\":\"gvisor\",\"auto_route\":false,\"strict_route\":false}}],\"outbounds\":[{{\"type\":{},\"tag\":\"proxy\",\"server\":{},\"server_port\":{}{}{}{}}}],\"route\":{{\"final\":\"proxy\",\"rules\":[{{\"action\":\"sniff\"}}]}}}}",
            string(&self.plan.iface),
            addresses,
            self.plan.mtu,
            string(kind),
            string(&self.server.to_string()),
            self.port,
            username,
            password,
            extra,
        )
    }
}

pub fn attached_adapter(
    config: &std::path::Path,
    proxy: &Config,
) -> Result<Option<crate::transport::Adapter>, String> {
    let Some(name) = proxy.adapter.as_deref() else {
        return Ok(None);
    };
    if !proxy.server.is_loopback() {
        return Err("an application adapter requires a loopback [Proxy] Server".to_owned());
    }
    let adapter = crate::transport::inventory(config)?
        .into_iter()
        .find(|adapter| adapter.name == name && adapter.kind == crate::transport::Kind::Plugin)
        .ok_or_else(|| format!("no external application transport {name}"))?;
    let published = adapter
        .publication
        .as_ref()
        .ok_or_else(|| format!("transport {name} publishes no proxy"))?;
    if published.kind != proxy.kind || published.port != proxy.port {
        return Err(format!(
            "transport {name} and [Proxy] disagree about the proxy type or port"
        ));
    }
    Ok(Some(adapter))
}

fn required(section: &crate::config::Section, key: &str) -> Result<String, String> {
    section
        .get(key)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("[Proxy] needs {key}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn config() -> Config {
        Config::from_ini(
            &WgConfig::parse(
                b"[Interface]\nAddress = 10.200.0.2/32, fd00:200::2/128\nDNS = 1.1.1.1\nMTU = 1380\n[Proxy]\nType = socks5\nServer = 192.0.2.10\nPort = 1080\n",
            )
            .unwrap(),
            "awg0",
        )
        .unwrap()
    }

    #[test]
    fn a_proxy_becomes_a_tun_and_one_pinned_outbound() {
        let cfg = config();
        let json = cfg.sing_box_config();
        let parsed = crate::json::parse(&json).unwrap();
        assert_eq!(
            parsed.get("route").unwrap().get("final").unwrap().as_str(),
            Some("proxy")
        );
        assert_eq!(
            parsed.get("outbounds").unwrap().as_array().unwrap()[0]
                .get("server")
                .unwrap()
                .as_str(),
            Some("192.0.2.10")
        );
        assert_eq!(
            parsed.get("inbounds").unwrap().as_array().unwrap()[0]
                .get("auto_route")
                .unwrap()
                .as_bool(),
            Some(false)
        );
        assert_eq!(Plan::parse(&cfg.plan.to_text()).unwrap(), cfg.plan);
    }

    #[test]
    fn an_attached_adapter_must_publish_the_same_loopback_endpoint() {
        let root =
            std::env::temp_dir().join(format!("cellward-proxy-adapter-{}", std::process::id()));
        let manifests = root.join(crate::transport::DIRECTORY);
        fs::create_dir_all(&manifests).unwrap();
        fs::write(
            manifests.join("vendor.conf"),
            b"[Transport]\nName = vendor\nRun = /does/not/run\nChannel = application\nProxy = socks5\nProxyPort = 1080\n",
        )
        .unwrap();
        let ini = WgConfig::parse(
            b"[Interface]\nAddress = 10.200.0.2/32\n[Proxy]\nType = socks5\nServer = 127.0.0.1\nPort = 1080\nAdapter = vendor\n",
        )
        .unwrap();
        let config = Config::from_ini(&ini, "awg0").unwrap();
        assert_eq!(
            attached_adapter(&root, &config).unwrap().unwrap().name,
            "vendor"
        );
        let mut wrong = config.clone();
        wrong.port = 1081;
        assert!(attached_adapter(&root, &wrong).is_err());
        wrong.port = 1080;
        wrong.server = "192.0.2.1".parse().unwrap();
        assert!(attached_adapter(&root, &wrong).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn http_connect_is_explicitly_tcp_only() {
        let ini = WgConfig::parse(b"[Interface]\nAddress = 10.200.0.2/32\n[Proxy]\nType = http\nServer = 192.0.2.10\nPort = 8080\n").unwrap();
        let cfg = Config::from_ini(&ini, "awg0").unwrap();
        assert!(cfg.sing_box_config().contains("\"network\":\"tcp\""));
    }

    #[test]
    fn hostnames_and_wireguard_keys_are_not_accepted() {
        let ini = WgConfig::parse(b"[Interface]\nAddress = 10.200.0.2/32\nPrivateKey = secret\n[Proxy]\nType = socks5\nServer = proxy.example\nPort = 1080\n").unwrap();
        assert!(Config::from_ini(&ini, "awg0").is_err());
        let ini = WgConfig::parse(b"[Interface]\nAddress = 10.200.0.2/32\nPrivateKey = secret\n[Proxy]\nType = socks5\nServer = 192.0.2.10\nPort = 1080\n").unwrap();
        assert!(Config::from_ini(&ini, "awg0").is_err());
    }
}
