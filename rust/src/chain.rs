//! A tunnel whose transport goes through another network.
//!
//! The upstream is a system VPN or another user VPN route. The broker starts
//! pasta inside its network namespace and attaches it to the inner tunnel's
//! uplink namespace. Every user hop can itself have an upstream; the inner
//! tunnel sees the preceding hop as its only route, never the host network.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::config::{Endpoint, EndpointHost, WgConfig};
use crate::openconnect::{self, OcConfig};

pub const SECTION: &str = "Chain";
pub const NODE_SECTION: &str = "Node";
pub const NODES_DIR: &str = ".nodes";

/// A route config may name one pooled tunnel config. The route contains no
/// secret; the node file is the single source of its key and endpoint.
pub fn node_of(ini: &WgConfig) -> Result<Option<String>, String> {
    let Some(section) = ini.section(NODE_SECTION) else {
        return Ok(None);
    };
    let name = section
        .get("Name")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or("[Node] needs Name = <node>")?;
    if !crate::cli::safe_zone_name(std::ffi::OsStr::new(name)) {
        return Err("[Node] has an invalid name".to_owned());
    }
    if section.entries.len() != 1 {
        return Err("[Node] accepts only Name".to_owned());
    }
    Ok(Some(name.to_owned()))
}

pub fn validate_node(ini: &WgConfig) -> Result<(), String> {
    if ini.section(NODE_SECTION).is_some()
        || ini.section(SECTION).is_some()
        || crate::sysuplink::is_system_zone(ini)
        || crate::hostif::is_host_interface(ini)
        || crate::hostif::is_host_network(ini)
    {
        return Err(
            "a pooled node must be a tunnel config, not a route or host interface".to_owned(),
        );
    }
    if openconnect::is_openconnect(ini) {
        OcConfig::from_ini(ini).map_err(|e| e.to_string())?;
    } else if ini
        .interface()
        .and_then(|i| i.get("PrivateKey"))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_none()
    {
        return Err("a pooled WireGuard node needs PrivateKey".to_owned());
    }
    Ok(())
}

/// Resolve one route's node without following another route or a nested node.
/// A missing node is an error, never a fallback to the host's network.
pub fn read_zone_config(state: &Path, zone: &str) -> Result<Vec<u8>, String> {
    let path = state.join(zone).join("config.conf");
    let route = fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    resolve_route_config(state, &route).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn resolve_route_config(state: &Path, route: &[u8]) -> Result<Vec<u8>, String> {
    let route_ini = WgConfig::parse(route).map_err(|e| e.to_string())?;
    let Some(node) = node_of(&route_ini)? else {
        return Ok(route.to_vec());
    };
    // No config directives besides Node and Chain may be smuggled into a
    // reference: the transport identity comes from one node file alone.
    if route_ini.sections.iter().any(|s| {
        !s.name.eq_ignore_ascii_case(NODE_SECTION) && !s.name.eq_ignore_ascii_case(SECTION)
    }) {
        return Err("a node route may contain only [Node] and [Chain]".to_owned());
    }
    if route_ini
        .sections
        .iter()
        .filter(|s| s.name.eq_ignore_ascii_case(NODE_SECTION))
        .count()
        != 1
        || route_ini
            .sections
            .iter()
            .filter(|s| s.name.eq_ignore_ascii_case(SECTION))
            .count()
            > 1
        || route_ini
            .section(SECTION)
            .is_some_and(|s| s.entries.len() != 1)
    {
        return Err("a node route needs one [Node] and at most one [Chain] Via".to_owned());
    }
    let node_path = state.join(NODES_DIR).join(&node).join("config.conf");
    let mut raw =
        fs::read(&node_path).map_err(|e| format!("cannot read pooled node {node}: {e}"))?;
    let node_ini = WgConfig::parse(&raw).map_err(|e| format!("pooled node {node}: {e}"))?;
    validate_node(&node_ini).map_err(|e| format!("pooled node {node}: {e}"))?;
    if let Some(chain) = ChainConfig::from_ini(&route_ini)? {
        if !raw.ends_with(b"\n") {
            raw.push(b'\n');
        }
        raw.extend_from_slice(chain.text().as_bytes());
    }
    Ok(raw)
}

pub fn read_zone_config_dir(dir: &Path) -> Result<Vec<u8>, String> {
    let state = dir.parent().ok_or("zone has no state directory")?;
    let zone = dir
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("zone has no name")?;
    read_zone_config(state, zone)
}
/// Optional, strict publication policy. Configs are nodes; only entries in
/// this file are launchable routes. An absent file preserves pre-policy
/// installations. A present but unreadable/invalid file refuses all routes.
pub const ROUTES: &str = ".routes";
const ROUTES_ENABLED: &str = ".routes-enabled";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Route {
    pub zone: String,
    pub prefix: Vec<String>,
    /// One edge per prefix: false is a system VPN, true a user VPN route.
    pub user_edges: Vec<bool>,
    pub borrowed: bool,
}

impl Route {
    fn parse(line: &str) -> Result<Self, String> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let borrowed = parts.len() == 3 && parts[1] == "=>";
        if parts.is_empty()
            || parts.len().is_multiple_of(2)
            || (!borrowed
                && parts
                    .iter()
                    .skip(1)
                    .step_by(2)
                    .any(|op| ![">", ">>"].contains(op)))
            || (!borrowed && parts.iter().skip(3).step_by(2).any(|op| *op != ">>"))
        {
            return Err(format!("invalid route {line:?}: use 'zone', 'system > user', 'user >> user' or 'system => user-zone'"));
        }
        let route = Self {
            zone: parts[parts.len() - 1].to_owned(),
            prefix: parts
                .iter()
                .step_by(2)
                .take(parts.len() / 2)
                .map(|s| (*s).to_owned())
                .collect(),
            user_edges: parts
                .iter()
                .skip(1)
                .step_by(2)
                .map(|op| *op == ">>")
                .collect(),
            borrowed,
        };
        if !crate::cli::safe_zone_name(std::ffi::OsStr::new(&route.zone))
            || route
                .prefix
                .iter()
                .any(|v| !crate::cli::safe_zone_name(std::ffi::OsStr::new(v)))
            || route.prefix.iter().any(|v| v == &route.zone)
            || route.prefix.iter().collect::<BTreeSet<_>>().len() != route.prefix.len()
        {
            return Err(format!("invalid route {line:?}"));
        }
        Ok(route)
    }

    pub fn text(&self) -> String {
        if self.borrowed {
            format!("{} => {}", self.prefix[0], self.zone)
        } else if self.prefix.is_empty() {
            self.zone.clone()
        } else {
            let mut path = self.prefix[0].clone();
            for (index, user) in self.user_edges.iter().enumerate() {
                path.push_str(if *user { " >> " } else { " > " });
                path.push_str(if index + 1 == self.prefix.len() {
                    &self.zone
                } else {
                    &self.prefix[index + 1]
                });
            }
            path
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
            user_edges: chain
                .as_ref()
                .map(|c| vec![c.user])
                .or_else(|| system.as_ref().map(|_| vec![false]))
                .unwrap_or_default(),
            prefix: chain
                .map(|c| vec![c.via])
                .or_else(|| system.clone().map(|s| vec![s]))
                .unwrap_or_default(),
            borrowed: system.is_some(),
        })
    }

    pub fn from_ini_in(state: &Path, zone: &str, ini: &WgConfig) -> Result<Self, String> {
        Self::from_ini_in_inner(state, zone, ini, &mut BTreeSet::new(), &mut BTreeSet::new())
    }

    fn from_ini_in_inner(
        state: &Path,
        zone: &str,
        ini: &WgConfig,
        seen: &mut BTreeSet<String>,
        identities: &mut BTreeSet<TunnelIdentity>,
    ) -> Result<Self, String> {
        if !seen.insert(zone.to_owned()) {
            return Err(format!("cycle in VPN route at {zone}"));
        }
        if identity(ini)?.is_some_and(|id| !identities.insert(id)) {
            return Err(format!("the same VPN appears twice in the route to {zone}"));
        }
        let mut route = Self::from_ini(zone, ini)?;
        if let Some(chain) = ChainConfig::from_ini(ini)?.filter(|c| c.user) {
            let raw = read_zone_config(state, &chain.via)?;
            let upstream = WgConfig::parse(&raw).map_err(|e| e.to_string())?;
            if identity(&upstream)?.is_none() {
                return Err(format!(
                    "upstream user zone {} has no VPN tunnel",
                    chain.via
                ));
            }
            let parent = Self::from_ini_in_inner(state, &chain.via, &upstream, seen, identities)?;
            route.prefix = parent.prefix;
            route.prefix.push(parent.zone);
            route.user_edges = parent.user_edges;
            route.user_edges.push(true);
        }
        seen.remove(zone);
        Ok(route)
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
        Some(allowed) => Ok(allowed.contains(&Route::from_ini_in(state, zone, ini)?)),
    }
}

pub fn published_zone(state: &Path, zone: &str) -> Result<bool, String> {
    let strict = routes(state)?.is_some();
    let path = state.join(zone).join("config.conf");
    let raw = read_zone_config(state, zone)
        .map_err(|e| format!("cannot inspect {}: {e}", path.display()))?;
    let ini =
        WgConfig::parse(&raw).map_err(|e| format!("cannot inspect {}: {e}", path.display()))?;
    if strict && !published(state, zone, &ini)? {
        return Ok(false);
    }
    user_upstreams(state, zone, &ini)?;
    Ok(true)
}

/// Every user-owned prefix required by a route, from the outermost one inward.
/// A missing, unpublished, non-tunnel or cyclic prefix is a refusal before
/// any new inner transport can connect.
pub fn user_upstreams(state: &Path, zone: &str, ini: &WgConfig) -> Result<Vec<String>, String> {
    let mut seen = BTreeSet::new();
    let mut current = zone.to_owned();
    let mut config = ini.clone();
    let mut reverse = Vec::new();
    loop {
        if !seen.insert(current.clone()) {
            return Err(format!("cycle in VPN route at {current}"));
        }
        let Some(chain) = ChainConfig::from_ini(&config)?.filter(|c| c.user) else {
            break;
        };
        let raw = read_zone_config(state, &chain.via)?;
        let upstream = WgConfig::parse(&raw).map_err(|e| e.to_string())?;
        if identity(&upstream)?.is_none() {
            return Err(format!(
                "upstream user zone {} has no VPN tunnel",
                chain.via
            ));
        }
        if !published(state, &chain.via, &upstream)? {
            return Err(format!(
                "upstream user route {} is not published",
                chain.via
            ));
        }
        reverse.push(chain.via.clone());
        current = chain.via;
        config = upstream;
    }
    reverse.reverse();
    Ok(reverse)
}

/// Recheck the actual immediate source after systemd reported it ready. The
/// route may have been edited while an outer zone was starting; a plain zone
/// must never be accepted as the carrier of an inner VPN.
pub fn validate_user_source(state: &Path, zone: &str) -> Result<(), String> {
    let raw = read_zone_config(state, zone)?;
    let ini = WgConfig::parse(&raw).map_err(|e| e.to_string())?;
    if identity(&ini)?.is_none() || !published_zone(state, zone)? {
        return Err(format!(
            "upstream user route {zone} is not a published VPN tunnel"
        ));
    }
    Ok(())
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
    /// The zone carrying the inner tunnel's encrypted transport.
    pub via: String,
    /// True for a user VPN route; false for a system VPN zone.
    pub user: bool,
}

impl ChainConfig {
    pub fn from_ini(ini: &WgConfig) -> Result<Option<Self>, String> {
        let Some(section) = ini.section(SECTION) else {
            return Ok(None);
        };
        if ini
            .sections
            .iter()
            .filter(|s| s.name.eq_ignore_ascii_case(SECTION))
            .count()
            != 1
        {
            return Err(format!("[{SECTION}] may occur only once"));
        }
        let system = section.get("Via").map(str::trim).filter(|s| !s.is_empty());
        let user = section
            .get("ViaUser")
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if system.is_some() == user.is_some() || section.entries.len() != 1 {
            return Err(format!("[{SECTION}] needs exactly one Via or ViaUser"));
        }
        let via = system
            .or(user)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("[{SECTION}] needs Via or ViaUser"))?;
        if user.is_some() {
            if !crate::cli::safe_zone_name(std::ffi::OsStr::new(via)) {
                return Err("ViaUser must name a user zone".to_owned());
            }
        } else {
            crate::system::check_name(via)?;
        }
        Ok(Some(Self {
            via: via.to_owned(),
            user: user.is_some(),
        }))
    }

    pub fn text(&self) -> String {
        format!(
            "[{SECTION}]\n{} = {}\n",
            if self.user { "ViaUser" } else { "Via" },
            self.via
        )
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
                if entry.key.eq_ignore_ascii_case("Endpoint") {
                    let endpoint = Endpoint::parse(&entry.value).ok_or_else(|| {
                        format!("invalid chained Endpoint on line {}", entry.line)
                    })?;
                    if matches!(endpoint.host, EndpointHost::Name(_)) {
                        return Err(format!(
                            "chained Endpoint on line {} must be a literal IP address; resolving its name through the host would bypass the outer zone",
                            entry.line
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// An IPv6 endpoint cannot be reached over an IPv4-only preceding hop.
    /// The broker reports what the pinned source namespace really carries.
    pub fn needs_ipv6_transport(ini: &WgConfig) -> Result<bool, String> {
        if openconnect::is_openconnect(ini) {
            return Ok(OcConfig::from_ini(ini)
                .map_err(|e| e.to_string())?
                .server_literal()
                .is_some_and(|addr| addr.is_ipv6()));
        }
        Ok(ini.sections.iter().flat_map(|s| &s.entries).any(|e| {
            e.key.eq_ignore_ascii_case("Endpoint")
                && Endpoint::parse(&e.value)
                    .is_some_and(|ep| matches!(ep.host, EndpointHost::V6(_)))
        }))
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum TunnelIdentity {
    WireGuard(String),
    OpenConnect(String, u16),
}

fn identity(ini: &WgConfig) -> Result<Option<TunnelIdentity>, String> {
    if crate::hostif::is_host_interface(ini)
        || crate::hostif::is_host_network(ini)
        || crate::sysuplink::is_system_zone(ini)
    {
        return Ok(None);
    }
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
        .map(str::trim)
        .filter(|key| !key.is_empty())
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
        if !allowed.contains(&Route::from_ini_in(state, name, ini)?) {
            // A node in the pool, not a published route. It cannot dial yet.
            return Ok(());
        }
    }
    let ours_route = Route::from_ini_in(state, name, ini)?;
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
        let raw = read_zone_config(state, other_name)
            .map_err(|e| format!("cannot inspect {}: {e}", path.display()))?;
        let peer =
            WgConfig::parse(&raw).map_err(|e| format!("cannot inspect {}: {e}", path.display()))?;
        if let Some(allowed) = policy {
            if !allowed.contains(&Route::from_ini_in(state, other_name, &peer)?) {
                continue;
            }
        }
        if identity(&peer).map_err(|e| format!("cannot inspect {}: {e}", path.display()))?
            == Some(ours.clone())
            && {
                let peer_route = Route::from_ini_in(state, other_name, &peer)?;
                ours_route.prefix != peer_route.prefix
                    || ours_route.user_edges != peer_route.user_edges
            }
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

    #[test]
    fn pooled_node_is_resolved_without_copying_its_secret_into_routes() {
        let state = state("node");
        let pool = state.join(NODES_DIR).join("ch");
        fs::create_dir_all(&pool).unwrap();
        fs::write(
            pool.join("config.conf"),
            b"[Interface]\nPrivateKey = one-secret\n[Peer]\nEndpoint = 192.0.2.7:51820\n",
        )
        .unwrap();
        installed(&state, "direct", "[Node]\nName = ch\n");
        installed(&state, "inner", "[Node]\nName = ch\n[Chain]\nVia = nl\n");
        let stub = fs::read_to_string(state.join("inner/config.conf")).unwrap();
        assert!(!stub.contains("one-secret"));
        let raw = read_zone_config(&state, "inner").unwrap();
        let ini = WgConfig::parse(&raw).unwrap();
        assert_eq!(
            ini.interface().unwrap().get("PrivateKey"),
            Some("one-secret")
        );
        assert_eq!(ChainConfig::from_ini(&ini).unwrap().unwrap().via, "nl");
        let mut allow = BTreeSet::new();
        allow.insert(Route::parse("nl > inner").unwrap());
        write_routes(&state, &allow).unwrap();
        assert!(published_zone(&state, "inner").unwrap());
        assert!(!published_zone(&state, "direct").unwrap());
        assert!(refuse_user_shortcut(&state, "inner", &ini).is_ok());
        allow.insert(Route::parse("direct").unwrap());
        assert!(refuse_user_shortcut_with(&state, "inner", &ini, Some(&allow)).is_err());
        fs::remove_file(pool.join("config.conf")).unwrap();
        assert!(read_zone_config(&state, "inner").is_err());
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn a_pool_reference_cannot_override_or_nest_a_tunnel_config() {
        let state = state("node-invalid");
        let pool = state.join(NODES_DIR).join("ch");
        fs::create_dir_all(&pool).unwrap();
        fs::write(
            pool.join("config.conf"),
            "[Interface]\nPrivateKey = k\n[Node]\nName = other\n",
        )
        .unwrap();
        assert!(resolve_route_config(&state, b"[Node]\nName = ch\n").is_err());
        fs::write(pool.join("config.conf"), "[Interface]\nPrivateKey = k\n").unwrap();
        assert!(resolve_route_config(
            &state,
            b"[Node]\nName = ch\n[Peer]\nEndpoint = 192.0.2.1:1\n"
        )
        .is_err());
        assert!(resolve_route_config(
            &state,
            b"[Node]\nName = ch\n[Chain]\nVia = nl\nEndpoint = 192.0.2.1:1\n"
        )
        .is_err());
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn three_hops_need_exact_publication_of_every_user_prefix() {
        let state = state("three-hops");
        installed(
            &state,
            "middle",
            "[Interface]\nPrivateKey = middle\n[Chain]\nVia = nl\n",
        );
        installed(
            &state,
            "last",
            "[Interface]\nPrivateKey = last\n[Chain]\nViaUser = middle\n",
        );
        let raw = read_zone_config(&state, "last").unwrap();
        let ini = WgConfig::parse(&raw).unwrap();
        let route = Route::from_ini_in(&state, "last", &ini).unwrap();
        assert_eq!(route.text(), "nl > middle >> last");
        let mut allow = BTreeSet::new();
        allow.insert(route);
        write_routes(&state, &allow).unwrap();
        assert!(user_upstreams(&state, "last", &ini).is_err());
        allow.insert(Route::parse("nl > middle").unwrap());
        write_routes(&state, &allow).unwrap();
        assert_eq!(
            user_upstreams(&state, "last", &ini).unwrap(),
            vec!["middle"]
        );
        assert!(published(&state, "last", &ini).unwrap());
        assert!(!allow.contains(&Route::parse("last").unwrap()));
        assert!(Route::parse("nl > middle >> last").is_ok());
        assert!(Route::parse("nl > middle > last").is_err());
        assert!(Route::parse("nl > middle >> nl").is_err());
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn user_route_cycles_are_refused_before_transport_starts() {
        let state = state("cycle");
        installed(
            &state,
            "a",
            "[Interface]\nPrivateKey = a\n[Chain]\nViaUser = b\n",
        );
        installed(
            &state,
            "b",
            "[Interface]\nPrivateKey = b\n[Chain]\nViaUser = a\n",
        );
        let ini = WgConfig::parse(&read_zone_config(&state, "a").unwrap()).unwrap();
        assert!(Route::from_ini_in(&state, "a", &ini)
            .unwrap_err()
            .contains("cycle"));
        assert!(user_upstreams(&state, "a", &ini).is_err());
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn one_vpn_identity_cannot_repeat_inside_a_chain() {
        let state = state("repeat-key");
        installed(&state, "outer", "[Interface]\nPrivateKey = shared\n");
        installed(
            &state,
            "inner",
            "[Interface]\nPrivateKey = shared\n[Chain]\nViaUser = outer\n",
        );
        let ini = WgConfig::parse(&read_zone_config(&state, "inner").unwrap()).unwrap();
        assert!(Route::from_ini_in(&state, "inner", &ini)
            .unwrap_err()
            .contains("twice"));
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn user_routes_can_start_from_a_user_vpn_without_a_system_hop() {
        let state = state("user-root");
        installed(&state, "home-vpn-long", "[Interface]\nPrivateKey = home\n");
        installed(
            &state,
            "office",
            "[Interface]\nPrivateKey = office\n[Chain]\nViaUser = home-vpn-long\n",
        );
        let ini = WgConfig::parse(&read_zone_config(&state, "office").unwrap()).unwrap();
        assert_eq!(
            Route::from_ini_in(&state, "office", &ini).unwrap().text(),
            "home-vpn-long >> office"
        );
        let mut allow = BTreeSet::new();
        allow.insert(Route::parse("home-vpn-long").unwrap());
        allow.insert(Route::parse("home-vpn-long >> office").unwrap());
        write_routes(&state, &allow).unwrap();
        assert_eq!(
            user_upstreams(&state, "office", &ini).unwrap(),
            vec!["home-vpn-long"]
        );
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn an_ipv6_endpoint_requires_ipv6_in_the_preceding_user_vpn() {
        let ipv4 = WgConfig::parse(b"[Peer]\nEndpoint = 192.0.2.1:51820\n").unwrap();
        let ipv6 = WgConfig::parse(b"[Peer]\nEndpoint = [2001:db8::1]:51820\n").unwrap();
        assert!(!ChainConfig::needs_ipv6_transport(&ipv4).unwrap());
        assert!(ChainConfig::needs_ipv6_transport(&ipv6).unwrap());
    }

    #[test]
    fn changing_a_system_hop_to_a_user_hop_does_not_inherit_publication() {
        let state = state("hop-kind");
        installed(&state, "nl", "[Interface]\nPrivateKey = outer\n");
        let ini =
            WgConfig::parse(b"[Interface]\nPrivateKey = inner\n[Chain]\nViaUser = nl\n").unwrap();
        let mut allow = BTreeSet::new();
        allow.insert(Route::parse("nl > inner").unwrap());
        allow.insert(Route::parse("nl").unwrap());
        write_routes(&state, &allow).unwrap();
        assert!(!published(&state, "inner", &ini).unwrap());
        allow.insert(Route::parse("nl >> inner").unwrap());
        write_routes(&state, &allow).unwrap();
        assert!(published(&state, "inner", &ini).unwrap());
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn a_plain_user_zone_cannot_carry_an_inner_vpn_even_with_a_key_field() {
        let state = state("plain-upstream");
        installed(
            &state,
            "plain",
            "[Interface]\nPrivateKey = decoy\n[HostNetwork]\n",
        );
        let ini = WgConfig::parse(b"[Interface]\nPrivateKey = inner\n[Chain]\nViaUser = plain\n")
            .unwrap();
        assert!(Route::from_ini_in(&state, "inner", &ini).is_err());
        fs::remove_dir_all(state).unwrap();
    }
}
