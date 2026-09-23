//! User zones whose way out is a system zone (`docs/SYSTEM.md` §7b): one VPN,
//! one tunnel, for the host's services and the user's programs alike.
//!
//! A user zone is a user namespace with an app namespace in it, and its way
//! out is pasta. Here there is no tunnel of the zone's own and no uplink: the
//! system-zone service starts pasta INSIDE the system zone's network namespace,
//! as the user, and attaches it to the app namespace — so a packet from the
//! user zone reaches pasta, pasta sends it on from the system zone, and the
//! system zone has lo and its tunnel and nothing else. pasta names its
//! interface `awg0` in the app namespace, the one name the zone's filter,
//! `doctor` and `vpn-zone check` know, exactly as for a host-interface zone.
//!
//! Everything a user zone has — the sealed runtime directory, the compositor
//! restriction, the picker, containers, hermeticity — is unchanged: that is
//! the point of taking the tunnel from the system zone rather than taking the
//! programs there.
//!
//! The config is a file like the others, so that `vpn-zone add` stays one verb,
//! and it holds no key — the key is the system zone's:
//!
//! ```ini
//! [SystemZone]
//! Name = nl
//! ```

use crate::config::WgConfig;

/// The section that makes a config a zone through a system zone.
pub const SECTION: &str = "SystemZone";

/// A parsed `[SystemZone]` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysUplinkConfig {
    /// The system zone whose tunnel the user zone goes out by.
    pub zone: String,
}

/// Is this a config of a zone through a system zone?
pub fn is_system_zone(ini: &WgConfig) -> bool {
    ini.section(SECTION).is_some()
}

impl SysUplinkConfig {
    pub fn from_ini(ini: &WgConfig) -> Result<Self, String> {
        let section = ini
            .section(SECTION)
            .ok_or_else(|| format!("no [{SECTION}] section"))?;
        let zone = section
            .get("Name")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("[{SECTION}] needs Name = <system zone>"))?;
        crate::system::check_name(zone)?;
        Ok(Self {
            zone: zone.to_owned(),
        })
    }

    /// The file `vpn-zone add` writes for such a zone.
    pub fn text(&self) -> String {
        format!("[{SECTION}]\nName = {}\n", self.zone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<SysUplinkConfig, String> {
        SysUplinkConfig::from_ini(&WgConfig::parse(text.as_bytes()).unwrap())
    }

    #[test]
    fn a_system_zone_config_names_the_zone_and_nothing_else() {
        let cfg = parse("[SystemZone]\nName = nl\n").unwrap();
        assert_eq!(cfg.zone, "nl");
        assert_eq!(cfg.text(), "[SystemZone]\nName = nl\n");
        assert_eq!(parse(&cfg.text()).unwrap(), cfg);
        assert!(is_system_zone(
            &WgConfig::parse(b"[SystemZone]\nName = nl\n").unwrap()
        ));
        assert!(!is_system_zone(
            &WgConfig::parse(b"[Interface]\nPrivateKey = x\n").unwrap()
        ));
    }

    #[test]
    fn the_name_is_checked_like_a_system_zones() {
        assert!(parse("[SystemZone]\n").is_err());
        assert!(parse("[SystemZone]\nName =\n").is_err());
        assert!(parse("[SystemZone]\nName = ../etc\n").is_err());
        assert!(parse("[SystemZone]\nName = direct\n").is_err());
        assert!(parse("[SystemZone]\nName = waytoolongname0\n").is_err());
    }
}
