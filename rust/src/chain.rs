//! A tunnel whose transport goes through another network.
//!
//! The first supported upstream is a system zone: its privileged bridge starts
//! pasta inside that zone and attaches it to the inner tunnel's uplink
//! namespace.  The inner tunnel therefore sees the outer tunnel as its only
//! route; if either hop dies, the inner zone dies too.

use crate::config::{Endpoint, EndpointHost, WgConfig};
use crate::openconnect::{self, OcConfig};

pub const SECTION: &str = "Chain";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainConfig {
    /// The system zone carrying the inner tunnel's encrypted transport.
    pub via: String,
}

impl ChainConfig {
    pub fn from_ini(ini: &WgConfig) -> Result<Option<Self>, String> {
        let Some(section) = ini.section(SECTION) else {
            return Ok(None);
        };
        let via = section
            .get("Via")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("[{SECTION}] needs Via = <system zone>"))?;
        crate::system::check_name(via)?;
        Ok(Some(Self {
            via: via.to_owned(),
        }))
    }

    pub fn text(&self) -> String {
        format!("[{SECTION}]\nVia = {}\n", self.via)
    }

    /// Nothing used to establish an inner tunnel may reach the host network.
    /// The gateway login helper currently connects there before the tunnel
    /// exists, so interactive OpenConnect login cannot be chained yet.
    pub fn validate_transport(ini: &WgConfig) -> Result<(), String> {
        if openconnect::is_openconnect(ini) {
            let oc = OcConfig::from_ini(ini).map_err(|e| e.to_string())?;
            if oc.server_literal().is_none() {
                return Err("a chained OpenConnect Server must be a literal IP address; resolving its name through the host would bypass the outer zone".to_owned());
            }
            if oc.login {
                return Err("a chained OpenConnect zone cannot ask for gateway login yet: the login helper connects before the outer tunnel and would expose the inner server to the host network; use PasswordFile or AskLogin = no".to_owned());
            }
        } else {
            for entry in ini.sections.iter().flat_map(|s| &s.entries) {
                if entry.key.eq_ignore_ascii_case("Endpoint")
                    && Endpoint::parse(&entry.value)
                        .is_some_and(|e| matches!(e.host, EndpointHost::Name(_)))
                {
                    return Err(format!(
                        "chained Endpoint on line {} must be a literal IP address; resolving its name through the host would bypass the outer zone",
                        entry.line
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Option<ChainConfig>, String> {
        ChainConfig::from_ini(&WgConfig::parse(text.as_bytes()).unwrap())
    }

    #[test]
    fn chain_names_its_outer_system_zone() {
        let cfg = parse("[Interface]\nPrivateKey = x\n[Chain]\nVia = outer\n")
            .unwrap()
            .unwrap();
        assert_eq!(cfg.via, "outer");
        assert_eq!(cfg.text(), "[Chain]\nVia = outer\n");
        assert!(parse("[Chain]\nVia = ../host\n").is_err());
        assert_eq!(parse("[Interface]\nPrivateKey = x\n").unwrap(), None);
    }

    #[test]
    fn chained_gateways_cannot_use_host_dns_or_host_login() {
        let ini = WgConfig::parse(b"[Peer]\nEndpoint = vpn.example:51820\n").unwrap();
        assert!(ChainConfig::validate_transport(&ini).is_err());
        let ini = WgConfig::parse(b"[Peer]\nEndpoint = 192.0.2.1:51820\n").unwrap();
        assert!(ChainConfig::validate_transport(&ini).is_ok());
        let ini = WgConfig::parse(b"[OpenConnect]\nServer = 192.0.2.2\n").unwrap();
        assert!(ChainConfig::validate_transport(&ini)
            .unwrap_err()
            .contains("gateway login"));
        let ini = WgConfig::parse(b"[OpenConnect]\nServer = 192.0.2.2\nAskLogin = no\n").unwrap();
        assert!(ChainConfig::validate_transport(&ini).is_ok());
    }
}
