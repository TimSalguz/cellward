//! Read-only MTU diagnostics for every hop of a published route.
//!
//! The configured value and the effective interface value are deliberately
//! different fields. Nothing is changed and no packets are sent: a down route
//! has no effective value, while a live tunnel is inspected in its own
//! namespace.

use std::ffi::{OsStr, OsString};
use std::process::Command;

use crate::config::WgConfig;
use crate::tools::Tools;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub zone: String,
    pub interface: Option<String>,
    pub up: bool,
    pub configured_mtu: Option<u32>,
    pub effective_mtu: Option<u32>,
    pub note: Option<String>,
}

impl Report {
    fn json(&self) -> String {
        use crate::status::string;
        format!(
            "{{\"zone\":{},\"interface\":{},\"up\":{},\"configured_mtu\":{},\"effective_mtu\":{},\"note\":{}}}",
            string(&self.zone),
            self.interface.as_deref().map_or("null".to_owned(), string),
            self.up,
            self.configured_mtu.map_or("null".to_owned(), |mtu| mtu.to_string()),
            self.effective_mtu.map_or("null".to_owned(), |mtu| mtu.to_string()),
            self.note.as_deref().map_or("null".to_owned(), string),
        )
    }
}

fn ip_link_mtu(text: &str) -> Option<u32> {
    let mut words = text.split_whitespace();
    while let Some(word) = words.next() {
        if word == "mtu" {
            return words.next()?.parse().ok();
        }
    }
    None
}

fn effective(tools: &Tools, zone: &str, interface: &str) -> Result<Option<u32>, String> {
    let Some(pid) = crate::cli::zone_up(&tools.state, OsStr::new(zone)) else {
        return Ok(None);
    };
    let output = Command::new(&tools.nsenter)
        .env_clear()
        .env("HOME", &tools.home)
        .args(["--preserve-credentials", "-U", "-n", "-m", "-t"])
        .arg(pid.to_string())
        .arg("--")
        .arg(&tools.ip)
        .args(["-o", "link", "show", "dev", interface])
        .output()
        .map_err(|e| format!("cannot inspect {interface} in {zone}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "cannot inspect {interface} in {zone}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    ip_link_mtu(&text)
        .ok_or_else(|| format!("no MTU in ip link for {interface} in {zone}"))
        .map(Some)
}

fn report(tools: &Tools, zone: &str) -> Result<Report, String> {
    let raw = crate::chain::read_zone_config(&tools.state, zone)?;
    let ini = WgConfig::parse(&crate::cli::strip_cr(&raw)).map_err(|e| e.to_string())?;
    if crate::sysuplink::is_system_zone(&ini) {
        return Ok(Report {
            zone: zone.to_owned(),
            interface: None,
            up: crate::cli::zone_up(&tools.state, OsStr::new(zone)).is_some(),
            configured_mtu: None,
            effective_mtu: None,
            note: Some("borrowed namespace; inspect the following hop".to_owned()),
        });
    }
    if crate::hostif::is_host_network(&ini) {
        return Ok(Report {
            zone: zone.to_owned(),
            interface: None,
            up: true,
            configured_mtu: None,
            effective_mtu: None,
            note: Some("host network; inspect the physical interface separately".to_owned()),
        });
    }
    let (interface, configured_mtu) = if crate::hostif::is_host_interface(&ini) {
        let host = crate::hostif::HostIfConfig::from_ini(&ini)?;
        (host.interface, ini.mtu())
    } else {
        let default = if crate::proxy::is_proxy(&ini) {
            crate::zone::DEFAULT_MTU
        } else if crate::openconnect::is_openconnect(&ini) {
            crate::openconnect::DEFAULT_MTU
        } else {
            crate::zone::DEFAULT_MTU
        };
        (
            crate::zone::TUN_IFACE.to_owned(),
            Some(ini.mtu().unwrap_or(default)),
        )
    };
    let effective_mtu = effective(tools, zone, &interface)?;
    Ok(Report {
        zone: zone.to_owned(),
        interface: Some(interface),
        up: crate::cli::zone_up(&tools.state, OsStr::new(zone)).is_some(),
        configured_mtu,
        effective_mtu,
        note: None,
    })
}

pub fn reports(tools: &Tools, zone: &str) -> Result<Vec<Report>, String> {
    let raw = crate::chain::read_zone_config(&tools.state, zone)?;
    let ini = WgConfig::parse(&crate::cli::strip_cr(&raw)).map_err(|e| e.to_string())?;
    let route = crate::chain::Route::from_ini_in(&tools.state, zone, &ini)?;
    let mut zones = vec![zone.to_owned()];
    zones.extend(route.prefix);
    zones.iter().map(|zone| report(tools, zone)).collect()
}

/// `cellward mtu [<zone>…] [--json]`: inspect, never change, every hop.
pub fn run(tools: &Tools, args: &[OsString]) -> u8 {
    const USAGE: &str = "cellward mtu [<зона>…] [--json]";
    let mut json = false;
    let mut zones = Vec::new();
    for arg in args {
        if arg == "--json" {
            json = true;
        } else if let Some(zone) = arg.to_str() {
            zones.push(zone.to_owned());
        } else {
            eprintln!("{USAGE}");
            return 1;
        }
    }
    if zones.is_empty() {
        zones = crate::panel::zones(&tools.state);
    }
    let mut rows = Vec::new();
    for zone in zones {
        match reports(tools, &zone) {
            Ok(reports) => rows.extend(reports),
            Err(error) => {
                eprintln!("{zone}: {error}");
                return 1;
            }
        }
    }
    if json {
        let rows: Vec<String> = rows.iter().map(Report::json).collect();
        println!("[{}]", rows.join(","));
    } else {
        for row in rows {
            println!(
                "{}\t{}\tup={}\tconfigured={}\teffective={}{}",
                row.zone,
                row.interface.as_deref().unwrap_or("-"),
                row.up,
                row.configured_mtu
                    .map_or("unknown".to_owned(), |mtu| mtu.to_string()),
                row.effective_mtu
                    .map_or("down".to_owned(), |mtu| mtu.to_string()),
                row.note.map_or(String::new(), |note| format!("\t{note}"))
            );
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn an_ip_link_line_yields_its_mtu() {
        assert_eq!(
            ip_link_mtu(
                "5: awg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1412 qdisc noqueue state UNKNOWN"
            ),
            Some(1412)
        );
        assert_eq!(ip_link_mtu("5: awg0: no MTU here"), None);
    }

    #[test]
    fn a_down_nested_route_reports_each_configured_hop() {
        let state = std::env::temp_dir().join(format!("cellward-mtu-{}", std::process::id()));
        let nodes = state.join(crate::chain::NODES_DIR).join("inner-tunnel");
        fs::create_dir_all(&nodes).unwrap();
        let config = |mtu| {
            format!(
                "[Interface]\nPrivateKey = QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg=\nAddress = 10.99.0.2/32\nMTU = {mtu}\n[Peer]\nPublicKey = MDEyMzQ1Njc4OUFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFk=\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n"
            )
        };
        fs::write(
            nodes.join("config.conf"),
            config(1400).replace(
                "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg=",
                "MDEyMzQ1Njc4OUFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFk=",
            ),
        )
        .unwrap();
        fs::create_dir_all(state.join("outer")).unwrap();
        fs::write(state.join("outer/config.conf"), config(1400)).unwrap();
        fs::create_dir_all(state.join("inner")).unwrap();
        fs::write(
            state.join("inner/config.conf"),
            "[Node]\nName = inner-tunnel\n[Chain]\nViaUser = outer\n",
        )
        .unwrap();
        let entries: std::collections::BTreeMap<String, String> = Tools::keys()
            .iter()
            .map(|key| {
                let dir = match *key {
                    "home" => state.join("home"),
                    "state" => state.clone(),
                    "profiles" => state.join("profiles"),
                    "sandboxes" => state.join("sandboxes"),
                    "config" => state.join("config"),
                    other => std::path::PathBuf::from(format!("/p/{other}")),
                };
                ((*key).to_owned(), dir.to_string_lossy().into_owned())
            })
            .collect();
        let tools = Tools::from_entries(Path::new("/m.json"), &entries).unwrap();
        let rows = reports(&tools, "inner").unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].zone, "inner");
        assert_eq!(rows[0].configured_mtu, Some(1400));
        assert_eq!(rows[0].effective_mtu, None);
        assert_eq!(rows[1].zone, "outer");
        assert_eq!(rows[1].configured_mtu, Some(1400));
        fs::remove_dir_all(state).unwrap();
    }
}
