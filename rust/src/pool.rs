//! Ordered alternatives for one published VPN route.
//!
//! The route's `[Chain]` is shared by every alternative. Only the selected
//! pooled node changes; a failed last alternative closes the route rather than
//! falling back to a direct connection. Health is an actual DNS answer and a
//! numeric TCP connection made from the route's own namespace, never a WG
//! handshake or the holder's mirror alone.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::config::WgConfig;
use crate::tools::Tools;

pub const SECTION: &str = "Pool";
pub const ACTIVE: &str = ".pool-active";
pub const HEALTH: &str = ".pool-health";
const DNS_WAIT: Duration = Duration::from_secs(2);
const TCP_WAIT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolConfig {
    pub nodes: Vec<String>,
    pub dns_name: String,
    pub egress: SocketAddr,
}

impl PoolConfig {
    pub fn from_ini(ini: &WgConfig) -> Result<Option<Self>, String> {
        let nodes = crate::chain::nodes_of(ini)?.unwrap_or_default();
        let section = ini.section(SECTION);
        if nodes.len() < 2 {
            if section.is_some() {
                return Err("[Pool] requires at least two nodes in [Node] Name".to_owned());
            }
            return Ok(None);
        }
        let section = section
            .ok_or("an ordered node pool needs [Pool] ProbeDNS and ProbeEgress".to_owned())?;
        if section.entries.len() != 2
            || ini
                .sections
                .iter()
                .filter(|s| s.name.eq_ignore_ascii_case(SECTION))
                .count()
                != 1
        {
            return Err("[Pool] needs exactly ProbeDNS and ProbeEgress".to_owned());
        }
        let dns_name = section
            .get("ProbeDNS")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or("[Pool] needs ProbeDNS")?;
        validate_dns_name(dns_name)?;
        let egress = section
            .get("ProbeEgress")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or("[Pool] needs ProbeEgress")?
            .parse::<SocketAddr>()
            .map_err(|_| "[Pool] ProbeEgress must be a numeric IP:port".to_owned())?;
        if egress.port() == 0 {
            return Err("[Pool] ProbeEgress must have a nonzero port".to_owned());
        }
        Ok(Some(Self {
            nodes,
            dns_name: dns_name.to_owned(),
            egress,
        }))
    }

    pub fn load(state: &Path, zone: &str) -> Result<Option<Self>, String> {
        let path = state.join(zone).join("config.conf");
        let raw = fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let ini = WgConfig::parse(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::from_ini(&ini).map_err(|e| format!("{}: {e}", path.display()))
    }
}

pub fn validate_dns_name(name: &str) -> Result<(), String> {
    let plain = name.strip_suffix('.').unwrap_or(name);
    if plain.is_empty()
        || plain.len() > 253
        || plain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    {
        return Err("[Pool] ProbeDNS must be a plain DNS name".to_owned());
    }
    Ok(())
}

pub fn active(dir: &Path, nodes: &[String]) -> Result<String, String> {
    let first = nodes.first().ok_or("an ordered pool has no nodes")?;
    match fs::read_to_string(dir.join(ACTIVE)) {
        Ok(raw) => {
            let selected = raw.trim();
            if nodes.iter().any(|node| node == selected) {
                Ok(selected.to_owned())
            } else {
                Err(format!(
                    "{} does not name a member of this ordered pool",
                    dir.join(ACTIVE).display()
                ))
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(first.clone()),
        Err(e) => Err(format!("cannot read {}: {e}", dir.join(ACTIVE).display())),
    }
}

fn write_state(path: &Path, text: &str) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("cannot replace {}: {e}", path.display()))
}

fn write_active(dir: &Path, node: &str) -> Result<(), String> {
    write_state(&dir.join(ACTIVE), &format!("{node}\n"))
}

fn write_health(dir: &Path, state: &str, node: &str, reason: Option<&str>) -> Result<(), String> {
    let reason = reason.unwrap_or("").replace(['\n', '\r'], " ");
    write_state(&dir.join(HEALTH), &format!("{state}\n{node}\n{reason}\n"))
}

fn reset_preference(dir: &Path, nodes: &[String]) -> Result<(), String> {
    let first = nodes.first().ok_or("an ordered pool has no nodes")?;
    write_active(dir, first)?;
    match fs::remove_file(dir.join(HEALTH)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("cannot clear {}: {e}", dir.join(HEALTH).display())),
    }
}

/// A fresh explicit start tries the preferred order from its beginning.
/// Automatic restarts during failover do not pass through here and therefore
/// retain the next selected node.
pub fn prepare_start(tools: &Tools, zone: &str) -> Result<bool, String> {
    let Some(pool) = PoolConfig::load(&tools.state, zone)? else {
        return Ok(false);
    };
    let dir = tools.state.join(zone);
    let _lock = crate::registry::lock(&dir).map_err(|e| format!("cannot lock pool {zone}: {e}"))?;
    reset_preference(&dir, &pool.nodes)?;
    Ok(true)
}

struct Hooks<'a> {
    probe: &'a mut dyn FnMut(&str) -> Result<(), String>,
    restart: &'a mut dyn FnMut() -> u8,
    stop: &'a mut dyn FnMut() -> u8,
    up: &'a mut dyn FnMut() -> bool,
}

fn stop_after_error(hooks: &mut Hooks<'_>, zone: &str, error: String) -> String {
    let code = (hooks.stop)();
    if code == 0 {
        error
    } else {
        format!("{error}; stopping route {zone} also failed (systemctl status {code})")
    }
}

fn maintain_with(
    dir: &Path,
    zone: &str,
    pool: &PoolConfig,
    hooks: &mut Hooks<'_>,
) -> Result<bool, String> {
    let result = (|| {
        let mut pending_failure = None;
        loop {
            let current = active(dir, &pool.nodes)?;
            if pending_failure.is_none() && !(hooks.up)() {
                return Err(format!("ordered pool {zone} is not up"));
            }
            let outcome = match pending_failure.take() {
                Some(why) => Err(why),
                None => (hooks.probe)(&current),
            };
            match outcome {
                Ok(()) => {
                    write_health(dir, "healthy", &current, None)?;
                    return Ok(true);
                }
                Err(why) => {
                    eprintln!(
                        "pool {zone}: {current} failed its DNS + numeric egress probe: {why}"
                    );
                    let index = pool
                        .nodes
                        .iter()
                        .position(|node| node == &current)
                        .ok_or("active pool node disappeared")?;
                    if let Some(next) = pool.nodes.get(index + 1) {
                        write_active(dir, next)?;
                        write_health(dir, "switching", next, Some(&why))?;
                        eprintln!(
                            "pool {zone}: switching from {current} to {next}; its chain is unchanged"
                        );
                        let code = (hooks.restart)();
                        if code != 0 || !(hooks.up)() {
                            pending_failure = Some(format!(
                                "replacement route did not come up (systemctl status {code})"
                            ));
                        }
                        continue;
                    }
                    write_health(dir, "exhausted", &current, Some(&why))?;
                    return Err(format!(
                        "pool {zone}: every alternative failed DNS + numeric egress; route stopped without direct fallback"
                    ));
                }
            }
        }
    })();
    result.map_err(|error| stop_after_error(hooks, zone, error))
}

/// Probe the active path and advance in configuration order after a failure.
/// Returns false for an ordinary, single-node route. The caller starts the
/// route first; this function never starts a route that is down by itself.
pub fn maintain(tools: &Tools, zone: &str) -> Result<bool, String> {
    let pool = match PoolConfig::load(&tools.state, zone) {
        Ok(Some(pool)) => pool,
        Ok(None) => return Ok(false),
        Err(error) => {
            let stop = || crate::cli::systemctl(tools, "stop", std::ffi::OsStr::new(zone));
            let code = stop();
            return Err(if code == 0 {
                error
            } else {
                format!("{error}; stopping route {zone} also failed (systemctl status {code})")
            });
        }
    };
    let dir = tools.state.join(zone);
    let _lock = match crate::registry::lock(&dir) {
        Ok(lock) => lock,
        Err(e) => {
            let code = crate::cli::systemctl(tools, "stop", std::ffi::OsStr::new(zone));
            let error = format!("cannot lock pool {zone}: {e}");
            return Err(if code == 0 {
                error
            } else {
                format!("{error}; stopping route {zone} also failed (systemctl status {code})")
            });
        }
    };
    let mut probe = |_current: &str| probe_in_zone(tools, zone, &pool);
    let mut restart = || crate::cli::systemctl(tools, "restart", std::ffi::OsStr::new(zone));
    let mut stop = || crate::cli::systemctl(tools, "stop", std::ffi::OsStr::new(zone));
    let mut up = || crate::cli::zone_up(&tools.state, std::ffi::OsStr::new(zone)).is_some();
    let mut hooks = Hooks {
        probe: &mut probe,
        restart: &mut restart,
        stop: &mut stop,
        up: &mut up,
    };
    maintain_with(&dir, zone, &pool, &mut hooks)
}

fn probe_in_zone(tools: &Tools, zone: &str, pool: &PoolConfig) -> Result<(), String> {
    let pid = crate::cli::zone_up(&tools.state, std::ffi::OsStr::new(zone))
        .ok_or_else(|| format!("route {zone} went down before its health probe"))?;
    let output = Command::new(&tools.nsenter)
        .env_clear()
        .env("HOME", &tools.home)
        .args(["--preserve-credentials", "-U", "-n", "-m", "-t"])
        .arg(pid.to_string())
        .arg("--")
        .arg(&tools.core)
        .arg("pool-probe")
        .arg(&pool.dns_name)
        .arg(pool.egress.to_string())
        .output()
        .map_err(|e| format!("cannot start the in-zone health probe: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let error = String::from_utf8_lossy(&output.stderr);
        let error = error.trim();
        Err(if error.is_empty() {
            "the in-zone health probe failed".to_owned()
        } else {
            error.to_owned()
        })
    }
}

fn dns_query(name: &str, id: u16) -> Result<Vec<u8>, String> {
    validate_dns_name(name)?;
    let mut query = Vec::new();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    for label in name.strip_suffix('.').unwrap_or(name).split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    Ok(query)
}

fn dns_name_end(message: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *message.get(at)?;
        if len & 0xc0 == 0xc0 {
            message.get(at + 1)?;
            return Some(at + 2);
        }
        if len == 0 {
            return Some(at + 1);
        }
        if len & 0xc0 != 0 || len > 63 {
            return None;
        }
        at = at.checked_add(usize::from(len) + 1)?;
        if at > message.len() {
            return None;
        }
    }
}

fn dns_answer_ok(query: &[u8], answer: &[u8]) -> bool {
    if query.len() < 12 || answer.len() < query.len() || query[..2] != answer[..2] {
        return false;
    }
    let flags = u16::from_be_bytes([answer[2], answer[3]]);
    let questions = u16::from_be_bytes([answer[4], answer[5]]);
    let answers = u16::from_be_bytes([answer[6], answer[7]]);
    let authorities = u16::from_be_bytes([answer[8], answer[9]]);
    let additional = u16::from_be_bytes([answer[10], answer[11]]);
    if flags & 0x8000 == 0
        || flags & 0x0200 != 0
        || flags & 0x000f != 0
        || questions != 1
        || answers == 0
        || query[12..] != answer[12..query.len()]
    {
        return false;
    }
    let Some(question_end) = dns_name_end(query, 12).and_then(|at| at.checked_add(4)) else {
        return false;
    };
    if question_end != query.len() {
        return false;
    }
    let mut at = query.len();
    for _ in 0..u32::from(answers) + u32::from(authorities) + u32::from(additional) {
        let Some(name_end) = dns_name_end(answer, at) else {
            return false;
        };
        let Some(record_end) = name_end.checked_add(10) else {
            return false;
        };
        if record_end > answer.len() {
            return false;
        }
        let data_len = usize::from(u16::from_be_bytes([
            answer[record_end - 2],
            answer[record_end - 1],
        ]));
        let Some(next) = record_end.checked_add(data_len) else {
            return false;
        };
        if next > answer.len() {
            return false;
        }
        at = next;
    }
    at == answer.len()
}

fn dns_probe(name: &str, resolv: &str) -> Result<(), String> {
    let resolvers = crate::dnsfwd::nameservers(resolv);
    if resolvers.is_empty() {
        return Err("the route has no numeric nameserver in /etc/resolv.conf".to_owned());
    }
    dns_probe_to(name, &resolvers)
}

fn dns_probe_to(name: &str, resolvers: &[SocketAddr]) -> Result<(), String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let query = dns_query(name, (nanos as u16) ^ std::process::id() as u16)?;
    for resolver in resolvers {
        let local: SocketAddr = if resolver.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let Ok(socket) = UdpSocket::bind(local) else {
            continue;
        };
        if socket.connect(resolver).is_err()
            || socket.set_read_timeout(Some(DNS_WAIT)).is_err()
            || socket.send(&query).is_err()
        {
            continue;
        }
        let mut answer = vec![0u8; 65_535];
        if let Ok(size) = socket.recv(&mut answer) {
            if dns_answer_ok(&query, &answer[..size]) {
                return Ok(());
            }
        }
    }
    Err(format!("no valid DNS answer for {name} through the route"))
}

fn probe_with_resolv(name: &str, egress: SocketAddr, resolv: &str) -> Result<(), String> {
    dns_probe(name, resolv)?;
    tcp_probe(egress)
}

fn tcp_probe(egress: SocketAddr) -> Result<(), String> {
    TcpStream::connect_timeout(&egress, TCP_WAIT)
        .map(|_| ())
        .map_err(|e| format!("numeric egress connect to {egress} failed: {e}"))
}

#[cfg(test)]
fn probe_with_resolver(name: &str, egress: SocketAddr, resolver: SocketAddr) -> Result<(), String> {
    dns_probe_to(name, &[resolver])?;
    tcp_probe(egress)
}

fn probe_here(name: &str, egress: SocketAddr) -> Result<(), String> {
    let resolv = fs::read_to_string("/etc/resolv.conf")
        .map_err(|e| format!("cannot read the route's /etc/resolv.conf: {e}"))?;
    probe_with_resolv(name, egress, &resolv)
}

pub fn probe_main(args: &[OsString]) -> u8 {
    let [name, egress] = args else {
        eprintln!("vpn-zone-core pool-probe: need <DNS name> <numeric IP:port>");
        return 2;
    };
    let Some(name) = name.to_str() else {
        return 2;
    };
    let Ok(egress) = egress.to_string_lossy().parse::<SocketAddr>() else {
        eprintln!("vpn-zone-core pool-probe: egress must be a numeric IP:port");
        return 2;
    };
    if egress.port() == 0 {
        eprintln!("vpn-zone-core pool-probe: egress must have a nonzero port");
        return 2;
    }
    match probe_here(name, egress) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

/// `networks[].route_pool`: ordered configuration and current runtime choice.
pub fn status_json(state: &Path, zone: &str) -> String {
    let result = (|| -> Result<String, String> {
        let Some(pool) = PoolConfig::load(state, zone)? else {
            return Ok("null".to_owned());
        };
        let dir = state.join(zone);
        let current = active(&dir, &pool.nodes)?;
        let note = fs::read_to_string(dir.join(HEALTH)).ok().and_then(|text| {
            let mut lines = text.lines();
            let state = lines.next()?.to_owned();
            let node = lines.next()?;
            let reason = lines.next().unwrap_or("").to_owned();
            (node == current).then_some((state, reason))
        });
        let (health, reason) = note.unwrap_or_else(|| ("unknown".to_owned(), String::new()));
        let nodes = pool
            .nodes
            .iter()
            .map(|node| crate::status::string(node))
            .collect::<Vec<_>>()
            .join(",");
        Ok(format!(
            "{{\"policy\":\"ordered\",\"nodes\":{{\"value\":[{nodes}],\"source\":\"local\"}},\"active\":{},\"health\":{},\"reason\":{}}}",
            crate::status::string(&current),
            crate::status::string(&health),
            if reason.is_empty() {
                "null".to_owned()
            } else {
                crate::status::string(&reason)
            }
        ))
    })();
    result.unwrap_or_else(|e| format!("{{\"error\":{}}}", crate::status::string(&e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::rc::Rc;

    fn pool() -> PoolConfig {
        PoolConfig {
            nodes: vec!["first".into(), "second".into(), "third".into()],
            dns_name: "probe.test".into(),
            egress: "192.0.2.10:80".parse().unwrap(),
        }
    }

    fn dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cellward-pool-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn ordered_pool_reuses_node_names_and_requires_explicit_probes() {
        let ini = WgConfig::parse(
            b"[Node]\nName = first, second, third\n[Chain]\nViaUser = nl\n[Pool]\nProbeDNS = probe.test\nProbeEgress = 192.0.2.10:80\n",
        )
        .unwrap();
        let pool = PoolConfig::from_ini(&ini).unwrap().unwrap();
        assert_eq!(pool.nodes, ["first", "second", "third"]);
        assert_eq!(pool.dns_name, "probe.test");
        assert_eq!(pool.egress, "192.0.2.10:80".parse().unwrap());
        assert!(
            PoolConfig::from_ini(&WgConfig::parse(b"[Node]\nName = one\n").unwrap())
                .unwrap()
                .is_none()
        );
        for bad in [
            "[Node]\nName = one, two\n",
            "[Node]\nName = one, one\n[Pool]\nProbeDNS = probe.test\nProbeEgress = 192.0.2.10:80\n",
            "[Node]\nName = one, two\n[Pool]\nProbeDNS = probe.test\nProbeEgress = localhost:80\n",
            "[Node]\nName = one, two\n[Pool]\nProbeDNS = probe.test\nProbeEgress = 192.0.2.10:0\n",
            "[Node]\nName = one, two\n[Pool]\nProbeDNS = bad name\nProbeEgress = 192.0.2.10:80\n",
            "[Pool]\nProbeDNS = probe.test\nProbeEgress = 192.0.2.10:80\n",
        ] {
            assert!(PoolConfig::from_ini(&WgConfig::parse(bad.as_bytes()).unwrap()).is_err());
        }
    }

    #[test]
    fn active_node_must_be_a_member_and_defaults_to_the_first() {
        let dir = dir("active");
        let nodes = vec!["first".to_owned(), "second".to_owned()];
        assert_eq!(active(&dir, &nodes).unwrap(), "first");
        write_active(&dir, "second").unwrap();
        assert_eq!(active(&dir, &nodes).unwrap(), "second");
        fs::write(dir.join(ACTIVE), "not-a-secret-but-malformed\n").unwrap();
        let error = active(&dir, &nodes).unwrap_err();
        assert!(!error.contains("not-a-secret-but-malformed"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn status_exposes_order_active_node_and_health_without_config_values() {
        let state = dir("status");
        let zone = state.join("route");
        fs::create_dir_all(&zone).unwrap();
        fs::write(
            zone.join("config.conf"),
            "[Node]\nName = first, second, third\n[Pool]\nProbeDNS = probe.test\nProbeEgress = 192.0.2.10:80\n",
        )
        .unwrap();
        write_active(&zone, "second").unwrap();
        write_health(&zone, "switching", "second", Some("synthetic failure")).unwrap();
        let json = status_json(&state, "route");
        assert!(json.contains("\"nodes\":{\"value\":[\"first\",\"second\",\"third\"]"));
        assert!(json.contains("\"active\":\"second\""));
        assert!(json.contains("\"health\":\"switching\""));
        assert!(!json.contains("probe.test"));
        assert!(!json.contains("192.0.2.10"));
        fs::remove_dir_all(state).unwrap();
    }

    fn successful_answer(query: &[u8]) -> Vec<u8> {
        let mut answer = query.to_vec();
        answer[2] = 0x81;
        answer[3] = 0x80;
        answer[7] = 1;
        answer.extend_from_slice(&[0xc0, 0x0c]);
        answer.extend_from_slice(&1u16.to_be_bytes());
        answer.extend_from_slice(&1u16.to_be_bytes());
        answer.extend_from_slice(&0u32.to_be_bytes());
        answer.extend_from_slice(&4u16.to_be_bytes());
        answer.extend_from_slice(&[192, 0, 2, 1]);
        answer
    }

    #[test]
    fn dns_health_requires_a_real_matching_successful_answer() {
        let query = dns_query("probe.test", 0x1234).unwrap();
        let answer = successful_answer(&query);
        assert!(dns_answer_ok(&query, &answer));
        let mut missing_record = query.clone();
        missing_record[2] = 0x81;
        missing_record[3] = 0x80;
        missing_record[7] = 1;
        assert!(!dns_answer_ok(&query, &missing_record));
        let mut refused = answer.clone();
        refused[3] = 0x83;
        assert!(!dns_answer_ok(&query, &refused));
        let mut no_answers = answer.clone();
        no_answers[7] = 0;
        assert!(!dns_answer_ok(&query, &no_answers));
        let mut wrong_id = answer;
        wrong_id[0] = 0;
        assert!(!dns_answer_ok(&query, &wrong_id));
        assert!(dns_query("bad name", 1).is_err());
    }

    #[test]
    fn health_does_real_dns_and_numeric_tcp_io() {
        let dns = UdpSocket::bind("127.0.0.1:0").unwrap();
        let resolver = dns.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut query = [0u8; 512];
            let (size, peer) = dns.recv_from(&mut query).unwrap();
            let answer = successful_answer(&query[..size]);
            dns.send_to(&answer, peer).unwrap();
        });
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let egress = tcp.local_addr().unwrap();
        let accept = std::thread::spawn(move || tcp.accept().unwrap());
        probe_with_resolver("probe.test", egress, resolver).unwrap();
        server.join().unwrap();
        accept.join().unwrap();

        let dns = UdpSocket::bind("127.0.0.1:0").unwrap();
        let resolver = dns.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut query = [0u8; 512];
            let (size, peer) = dns.recv_from(&mut query).unwrap();
            let answer = successful_answer(&query[..size]);
            dns.send_to(&answer, peer).unwrap();
        });
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let refused = tcp.local_addr().unwrap();
        drop(tcp);
        assert!(probe_with_resolver("probe.test", refused, resolver)
            .unwrap_err()
            .contains("numeric egress"));
        server.join().unwrap();
    }

    #[test]
    fn failover_uses_order_persists_choice_and_only_explicit_start_resets() {
        let dir = dir("order");
        let pool = pool();
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut probe = |node: &str| {
            events.borrow_mut().push(format!("probe:{node}"));
            if node == "third" {
                Ok(())
            } else {
                Err("synthetic failure".into())
            }
        };
        let mut restart = || {
            let node = active(&dir, &pool.nodes).unwrap();
            events.borrow_mut().push(format!("restart:{node}"));
            0
        };
        let mut stop = || {
            events.borrow_mut().push("stop".into());
            0
        };
        let mut up = || true;
        let mut hooks = Hooks {
            probe: &mut probe,
            restart: &mut restart,
            stop: &mut stop,
            up: &mut up,
        };
        assert!(maintain_with(&dir, "route", &pool, &mut hooks).unwrap());
        assert_eq!(active(&dir, &pool.nodes).unwrap(), "third");
        assert_eq!(
            events.borrow().as_slice(),
            [
                "probe:first",
                "restart:second",
                "probe:second",
                "restart:third",
                "probe:third"
            ]
        );

        reset_preference(&dir, &pool.nodes).unwrap();
        assert_eq!(active(&dir, &pool.nodes).unwrap(), "first");
        write_active(&dir, "third").unwrap();
        assert_eq!(active(&dir, &pool.nodes).unwrap(), "third");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_last_alternative_stops_without_any_direct_fallback() {
        let dir = dir("exhausted");
        let mut pool = pool();
        pool.nodes.truncate(2);
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut probe = |node: &str| {
            events.borrow_mut().push(format!("probe:{node}"));
            Err("synthetic failure".into())
        };
        let mut restart = || {
            events.borrow_mut().push("restart:same-route".into());
            0
        };
        let mut stop = || {
            events.borrow_mut().push("stop:closed".into());
            0
        };
        let mut up = || true;
        let mut hooks = Hooks {
            probe: &mut probe,
            restart: &mut restart,
            stop: &mut stop,
            up: &mut up,
        };
        let error = maintain_with(&dir, "route", &pool, &mut hooks).unwrap_err();
        assert!(error.contains("without direct fallback"));
        assert_eq!(active(&dir, &pool.nodes).unwrap(), "second");
        assert_eq!(
            events.borrow().as_slice(),
            [
                "probe:first",
                "restart:same-route",
                "probe:second",
                "stop:closed"
            ]
        );
        assert!(fs::read_to_string(dir.join(HEALTH))
            .unwrap()
            .starts_with("exhausted\nsecond\n"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_replacement_that_does_not_start_is_also_a_failed_alternative() {
        let dir = dir("restart-failed");
        let pool = pool();
        let probed = Rc::new(RefCell::new(Vec::new()));
        let restarts = Rc::new(RefCell::new(0));
        let mut probe = |node: &str| {
            probed.borrow_mut().push(node.to_owned());
            if node == "third" {
                Ok(())
            } else {
                Err("synthetic failure".into())
            }
        };
        let mut restart = || {
            *restarts.borrow_mut() += 1;
            if *restarts.borrow() == 1 {
                1
            } else {
                0
            }
        };
        let mut stop = || 0;
        let mut up = || true;
        let mut hooks = Hooks {
            probe: &mut probe,
            restart: &mut restart,
            stop: &mut stop,
            up: &mut up,
        };
        assert!(maintain_with(&dir, "route", &pool, &mut hooks).unwrap());
        assert_eq!(probed.borrow().as_slice(), ["first", "third"]);
        assert_eq!(active(&dir, &pool.nodes).unwrap(), "third");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn malformed_saved_choice_fails_closed_before_probing() {
        let dir = dir("malformed-active");
        let pool = pool();
        fs::write(dir.join(ACTIVE), "unknown\n").unwrap();
        let stopped = Rc::new(RefCell::new(false));
        let mut probe = |_node: &str| panic!("a malformed choice must not be probed");
        let mut restart = || panic!("a malformed choice must not be restarted");
        let mut stop = || {
            *stopped.borrow_mut() = true;
            0
        };
        let mut up = || true;
        let mut hooks = Hooks {
            probe: &mut probe,
            restart: &mut restart,
            stop: &mut stop,
            up: &mut up,
        };
        assert!(maintain_with(&dir, "route", &pool, &mut hooks).is_err());
        assert!(*stopped.borrow());
        fs::remove_dir_all(dir).unwrap();
    }
}
