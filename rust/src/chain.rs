//! A tunnel whose transport goes through another network.
//!
//! The first supported upstream is a system zone: its privileged bridge starts
//! pasta inside that zone and attaches it to the inner tunnel's uplink
//! namespace.  The inner tunnel therefore sees the outer tunnel as its only
//! route; if either hop dies, the inner zone dies too.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::config::{Endpoint, EndpointHost, WgConfig};
use crate::openconnect::{self, OcConfig};

pub const SECTION: &str = "Chain";
/// Optional, strict publication policy. Configs are nodes; only entries in
/// this file are launchable routes. An absent file preserves pre-policy
/// installations. A present but unreadable/invalid file refuses all routes.
pub const ROUTES: &str = ".routes";
const ROUTES_ENABLED: &str = ".routes-enabled";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Route {
    pub zone: String,
    pub via: Option<String>,
    pub borrowed: bool,
}

impl Route {
    fn parse(line: &str) -> Result<Self, String> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let route = match parts.as_slice() {
            [zone] => Self {
                zone: (*zone).to_owned(),
                via: None,
                borrowed: false,
            },
            [via, ">", zone] => Self {
                zone: (*zone).to_owned(),
                via: Some((*via).to_owned()),
                borrowed: false,
            },
            [via, "=>", zone] => Self {
                zone: (*zone).to_owned(),
                via: Some((*via).to_owned()),
                borrowed: true,
            },
            _ => {
                return Err(format!(
                    "invalid route {line:?}: use 'zone', 'outer > inner' or 'system => user-zone'"
                ))
            }
        };
        if !crate::cli::safe_zone_name(std::ffi::OsStr::new(&route.zone))
            || route
                .via
                .as_deref()
                .is_some_and(|v| crate::system::check_name(v).is_err())
            || route.via.as_deref() == Some(route.zone.as_str())
        {
            return Err(format!("invalid route {line:?}"));
        }
        Ok(route)
    }

    pub fn text(&self) -> String {
        match &self.via {
            Some(via) if self.borrowed => format!("{via} => {}", self.zone),
            Some(via) => format!("{via} > {}", self.zone),
            None => self.zone.clone(),
        }
    }

    pub fn from_ini(zone: &str, ini: &WgConfig) -> Result<Self, String> {
        let chain = ChainConfig::from_ini(ini)?;
        let system = if crate::sysuplink::is_system_zone(ini) {
            Some(crate::sysuplink::SysUplinkConfig::from_ini(ini)?.zone)
        } else {
            None
        };
        if chain.is_some() && system.is_some() {
            return Err("[Chain] and [SystemZone] cannot describe one route".to_owned());
        }
        Ok(Self {
            zone: zone.to_owned(),
            via: chain.map(|c| c.via).or_else(|| system.clone()),
            borrowed: system.is_some(),
        })
    }
}

/// `None` means the legacy, unrestricted user-zone publication mode. Once
/// enabled, even a zero-line file means no route is published.
pub fn routes(state: &Path) -> Result<Option<BTreeSet<Route>>, String> {
    let raw = match fs::read_to_string(state.join(ROUTES)) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if state.join(ROUTES_ENABLED).exists() {
                return Err(format!(
                    "{ROUTES} is missing although strict route policy was enabled"
                ));
            }
            return Ok(None);
        }
        Err(e) => return Err(format!("cannot read {ROUTES}: {e}")),
    };
    let mut out = BTreeSet::new();
    for (n, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let route = Route::parse(line).map_err(|e| format!("{ROUTES}:{}: {e}", n + 1))?;
        if !out.insert(route) {
            return Err(format!("{ROUTES}:{}: duplicate route", n + 1));
        }
    }
    Ok(Some(out))
}

pub fn published(state: &Path, zone: &str, ini: &WgConfig) -> Result<bool, String> {
    match routes(state)? {
        None => Ok(true),
        Some(allowed) => Ok(allowed.contains(&Route::from_ini(zone, ini)?)),
    }
}

pub fn published_zone(state: &Path, zone: &str) -> Result<bool, String> {
    if routes(state)?.is_none() {
        return Ok(true);
    }
    let path = state.join(zone).join("config.conf");
    let raw = fs::read(&path).map_err(|e| format!("cannot inspect {}: {e}", path.display()))?;
    let ini =
        WgConfig::parse(&raw).map_err(|e| format!("cannot inspect {}: {e}", path.display()))?;
    published(state, zone, &ini)
}

/// Atomic rewrite of the user's publication list. `routes enable` first
/// creates an empty list; later allow/deny operations change it without
/// silently publishing other installed VPN configs.
pub fn write_routes(state: &Path, allowed: &BTreeSet<Route>) -> Result<(), String> {
    fs::create_dir_all(state).map_err(|e| e.to_string())?;
    // The marker is committed first. If the process dies before the list is
    // renamed into place, the next reader refuses rather than reverting to
    // legacy allow-all behavior.
    let marker = state.join(ROUTES_ENABLED);
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&marker)
        .or_else(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                fs::OpenOptions::new().read(true).open(&marker)
            } else {
                Err(e)
            }
        })
        .map_err(|e| format!("cannot enable strict route policy: {e}"))?;
    file.sync_all().map_err(|e| e.to_string())?;
    let target = state.join(ROUTES);
    let temp = state.join(format!(".routes.{}.tmp", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|e| format!("cannot write {}: {e}", temp.display()))?;
    for route in allowed {
        writeln!(file, "{}", route.text()).map_err(|e| e.to_string())?;
    }
    file.sync_all().map_err(|e| e.to_string())?;
    fs::rename(&temp, &target).map_err(|e| e.to_string())
}

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

    /// A key already installed as a system zone could be started directly at
    /// boot, independently of this route's `Via`. Do not claim the inner hop
    /// is protected while that direct system route still exists. Failure to
    /// ask the system tier is a refusal too, not permission by silence.
    pub fn refuse_system_duplicate(
        ini: &WgConfig,
        lookup: impl FnOnce(&str) -> Result<Option<String>, String>,
    ) -> Result<(), String> {
        let Some(key) = ini
            .interface()
            .and_then(|section| section.get("PrivateKey"))
        else {
            return Ok(()); // OpenConnect has no WireGuard key to compare.
        };
        match lookup(key.trim()).map_err(|e| {
            format!(
                "cannot verify that the inner VPN is absent from system zones ({e}) — \
                 a chain is not safe to publish without that check"
            )
        })? {
            Some(zone) => Err(format!(
                "this inner VPN is also the system zone {zone}; that zone may connect directly \
                 at boot, bypassing [Chain] — remove the direct system zone first"
            )),
            None => Ok(()),
        }
    }
}

/// The identity of a tunnel, not its zone name. An OpenConnect gateway has
/// no WireGuard key, so its address and port are the strongest local identity
/// available here. Different accounts on one gateway intentionally conflict:
/// either direct connection would still reveal that gateway to the provider.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TunnelIdentity {
    WireGuard(String),
    OpenConnect(String, u16),
}

fn identity(ini: &WgConfig) -> Result<Option<TunnelIdentity>, String> {
    if openconnect::is_openconnect(ini) {
        let oc = OcConfig::from_ini(ini).map_err(|e| e.to_string())?;
        let server = oc
            .server_literal()
            .map_or_else(|| oc.server.to_ascii_lowercase(), |ip| ip.to_string());
        return Ok(Some(TunnelIdentity::OpenConnect(
            server,
            oc.port.unwrap_or(443),
        )));
    }
    Ok(ini
        .interface()
        .and_then(|section| section.get("PrivateKey"))
        .map(|key| TunnelIdentity::WireGuard(key.trim().to_owned())))
}

/// A user zone with the same tunnel must not offer a shorter route than a
/// chain. Check both when adding a zone and when starting it: either config
/// might have been added or changed since the other was created. A malformed
/// peer config is not silently treated as evidence of safety.
pub fn refuse_user_shortcut(state: &Path, name: &str, ini: &WgConfig) -> Result<(), String> {
    let policy = routes(state)?;
    refuse_user_shortcut_with(state, name, ini, policy.as_ref())
}

/// Preflight a proposed publication before writing it, as well as checking
/// the current one at zone startup.
pub fn refuse_user_shortcut_with(
    state: &Path,
    name: &str,
    ini: &WgConfig,
    policy: Option<&BTreeSet<Route>>,
) -> Result<(), String> {
    let Some(ours) = identity(ini)? else {
        return Ok(());
    };
    if let Some(allowed) = policy {
        if !allowed.contains(&Route::from_ini(name, ini)?) {
            // A node in the pool, not a published route. It cannot dial yet.
            return Ok(());
        }
    }
    let chained = ChainConfig::from_ini(ini)?.is_some();
    let entries = match fs::read_dir(state) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("cannot inspect user zones for shorter routes: {e}")),
    };
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot inspect user zones: {e}"))?;
        let other = entry.file_name();
        let Some(other_name) = other.to_str() else {
            continue;
        };
        if other_name == name || !crate::cli::safe_zone_name(&other) {
            continue;
        }
        let path = entry.path().join("config.conf");
        if !path.exists() {
            continue;
        }
        let raw = fs::read(&path).map_err(|e| format!("cannot inspect {}: {e}", path.display()))?;
        let peer =
            WgConfig::parse(&raw).map_err(|e| format!("cannot inspect {}: {e}", path.display()))?;
        if let Some(allowed) = policy {
            if !allowed.contains(&Route::from_ini(other_name, &peer)?) {
                continue;
            }
        }
        if identity(&peer).map_err(|e| format!("cannot inspect {}: {e}", path.display()))?
            == Some(ours.clone())
            && chained != ChainConfig::from_ini(&peer)?.is_some()
        {
            return Err(format!(
                "the same VPN is also user zone {other_name} with a different route; \
                 its direct connection could bypass [Chain] — remove that shorter route first"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(tag: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "cellward-chain-shortcut-{tag}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn installed(state: &Path, name: &str, text: &str) {
        let dir = state.join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("config.conf"), text).unwrap();
    }

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

    #[test]
    fn inner_key_cannot_also_be_a_direct_system_zone() {
        let ini = WgConfig::parse(b"[Interface]\nPrivateKey = inner-secret\n[Chain]\nVia = nl\n")
            .unwrap();
        assert!(ChainConfig::refuse_system_duplicate(&ini, |key| {
            assert_eq!(key, "inner-secret");
            Ok(Some("ch-direct".into()))
        })
        .unwrap_err()
        .contains("ch-direct"));
        assert!(ChainConfig::refuse_system_duplicate(&ini, |_| Ok(None)).is_ok());
        assert!(
            ChainConfig::refuse_system_duplicate(&ini, |_| Err("no socket".into()))
                .unwrap_err()
                .contains("no socket")
        );
    }

    #[test]
    fn same_user_wireguard_key_cannot_have_a_direct_shortcut_in_either_order() {
        let state = state("wg");
        let direct = "[Interface]\nPrivateKey = inner-secret\n";
        let chain = "[Interface]\nPrivateKey = inner-secret\n[Chain]\nVia = nl\n";
        installed(&state, "direct", direct);
        assert!(
            refuse_user_shortcut(&state, "inner", &WgConfig::parse(chain.as_bytes()).unwrap())
                .unwrap_err()
                .contains("direct")
        );
        fs::remove_dir_all(state.join("direct")).unwrap();
        installed(&state, "inner", chain);
        assert!(refuse_user_shortcut(
            &state,
            "direct",
            &WgConfig::parse(direct.as_bytes()).unwrap()
        )
        .unwrap_err()
        .contains("inner"));
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn same_openconnect_gateway_cannot_have_a_direct_shortcut() {
        let state = state("oc");
        let chain = "[OpenConnect]\nServer = 192.0.2.5\nAskLogin = no\n[Chain]\nVia = nl\n";
        installed(&state, "inner", chain);
        let direct = "[OpenConnect]\nServer = 192.0.2.5:443\nAskLogin = no\n";
        assert!(refuse_user_shortcut(
            &state,
            "direct",
            &WgConfig::parse(direct.as_bytes()).unwrap()
        )
        .unwrap_err()
        .contains("inner"));
        let other = "[OpenConnect]\nServer = 192.0.2.6\nAskLogin = no\n";
        assert!(
            refuse_user_shortcut(&state, "other", &WgConfig::parse(other.as_bytes()).unwrap())
                .is_ok()
        );
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn independent_and_equally_chained_zones_are_allowed() {
        let state = state("allowed");
        installed(
            &state,
            "first",
            "[Interface]\nPrivateKey = shared\n[Chain]\nVia = nl\n",
        );
        let same_route =
            WgConfig::parse(b"[Interface]\nPrivateKey = shared\n[Chain]\nVia = nl\n").unwrap();
        assert!(refuse_user_shortcut(&state, "second", &same_route).is_ok());
        let other = WgConfig::parse(b"[Interface]\nPrivateKey = distinct\n").unwrap();
        assert!(refuse_user_shortcut(&state, "other", &other).is_ok());
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn publication_is_exact_and_fails_closed_on_bad_policy() {
        let state = state("routes");
        let direct = WgConfig::parse(b"[Interface]\nPrivateKey = direct\n").unwrap();
        let inner =
            WgConfig::parse(b"[Interface]\nPrivateKey = inner\n[Chain]\nVia = nl\n").unwrap();
        assert!(published(&state, "ch", &inner).unwrap()); // legacy installations
        write_routes(&state, &BTreeSet::new()).unwrap();
        assert!(!published(&state, "ch", &inner).unwrap());
        let mut allow = BTreeSet::new();
        allow.insert(Route::parse("nl > ch").unwrap());
        write_routes(&state, &allow).unwrap();
        assert!(published(&state, "ch", &inner).unwrap());
        assert!(!published(&state, "ch", &direct).unwrap());
        assert!(!published(&state, "nl", &direct).unwrap());
        let borrowed = WgConfig::parse(b"[SystemZone]\nName = nl\n").unwrap();
        assert_eq!(
            Route::from_ini("apps", &borrowed).unwrap().text(),
            "nl => apps"
        );
        assert!(!published(&state, "apps", &borrowed).unwrap());
        fs::write(state.join(ROUTES), "nl > ch\nch\n../escape\n").unwrap();
        assert!(published(&state, "ch", &inner).is_err());
        fs::remove_file(state.join(ROUTES)).unwrap();
        assert!(published(&state, "ch", &inner).is_err());
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn unpublished_direct_config_is_only_a_pool_node() {
        let state = state("pool");
        let direct = "[Interface]\nPrivateKey = shared\n";
        let chain = "[Interface]\nPrivateKey = shared\n[Chain]\nVia = nl\n";
        installed(&state, "direct", direct);
        let mut allow = BTreeSet::new();
        allow.insert(Route::parse("nl > inner").unwrap());
        write_routes(&state, &allow).unwrap();
        let ini = WgConfig::parse(chain.as_bytes()).unwrap();
        assert!(refuse_user_shortcut(&state, "inner", &ini).is_ok());
        allow.insert(Route::parse("direct").unwrap());
        assert!(refuse_user_shortcut_with(&state, "inner", &ini, Some(&allow)).is_err());
        // Legacy allow-all mode still refuses the very same files.
        fs::remove_file(state.join(ROUTES)).unwrap();
        fs::remove_file(state.join(ROUTES_ENABLED)).unwrap();
        assert!(refuse_user_shortcut(&state, "inner", &ini).is_err());
        fs::remove_dir_all(state).unwrap();
    }
}
