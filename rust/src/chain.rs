//! A tunnel whose transport goes through another network.
//!
//! The first supported upstream is a system zone: its privileged bridge starts
//! pasta inside that zone and attaches it to the inner tunnel's uplink
//! namespace.  The inner tunnel therefore sees the outer tunnel as its only
//! route; if either hop dies, the inner zone dies too.

use crate::config::WgConfig;

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
}
