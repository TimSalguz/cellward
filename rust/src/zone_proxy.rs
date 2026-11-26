//! Explicit, loopback-only access to a zone through SOCKS5 or HTTP CONNECT.
//!
//! Matched connections are made by a helper inside the zone's network and mount
//! namespaces. `default = host` is the only mode that can use the host network;
//! a missing or broken zone never turns a matched connection into a direct one.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use crate::config::WgConfig;
use crate::tools::Tools;

pub const FILE: &str = "zone-proxy.conf";
pub const SECTION: &str = "ZoneProxy";
const CONNECT_WAIT: Duration = Duration::from_secs(10);
const HEADER_LIMIT: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultRoute {
    Zone,
    Deny,
    Host,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Rule {
    Exact(String),
    Suffix(String),
    Address(IpAddr, u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub listen: SocketAddr,
    pub default: DefaultRoute,
    rules: Vec<Rule>,
}

impl Config {
    pub fn new(port: u16, default: DefaultRoute, rules: &[String]) -> Result<Self, String> {
        if port == 0 {
            return Err("proxy port must be nonzero".to_owned());
        }
        Ok(Self {
            listen: SocketAddr::from(([127, 0, 0, 1], port)),
            default,
            rules: rules
                .iter()
                .map(|value| rule(value))
                .collect::<Result<_, _>>()?,
        })
    }

    fn from_ini(ini: &WgConfig) -> Result<Self, String> {
        let section = ini.section(SECTION).ok_or("missing [ZoneProxy]")?;
        if ini.sections.len() != 1 {
            return Err("zone-proxy.conf accepts one [ZoneProxy] section".to_owned());
        }
        for key in ["Listen", "Default"] {
            if section
                .entries
                .iter()
                .filter(|entry| entry.key.eq_ignore_ascii_case(key))
                .count()
                != 1
            {
                return Err(format!("[ZoneProxy] needs exactly one {key}"));
            }
        }
        let listen = required(section, "Listen")?
            .parse::<SocketAddr>()
            .map_err(|_| "Listen must be a numeric IP:port".to_owned())?;
        if !listen.ip().is_loopback() || listen.port() == 0 {
            return Err("Listen must be a loopback address with a nonzero port".to_owned());
        }
        let default = match required(section, "Default")?.as_str() {
            "zone" => DefaultRoute::Zone,
            "deny" => DefaultRoute::Deny,
            "host" => DefaultRoute::Host,
            _ => return Err("Default must be zone, deny or host".to_owned()),
        };
        let mut rules = Vec::new();
        for entry in &section.entries {
            if entry.key.eq_ignore_ascii_case("Listen") || entry.key.eq_ignore_ascii_case("Default")
            {
                continue;
            }
            if !entry.key.eq_ignore_ascii_case("Rule") {
                return Err(format!("unknown [ZoneProxy] key {}", entry.key));
            }
            rules.push(rule(entry.value.trim())?);
        }
        Ok(Self {
            listen,
            default,
            rules,
        })
    }

    pub fn load(state: &Path, zone: &str) -> Result<Option<Self>, String> {
        let path = state.join(zone).join(FILE);
        let raw = match fs::read(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        let ini = WgConfig::parse(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::from_ini(&ini)
            .map(Some)
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn to_text(&self) -> String {
        let mut text = format!(
            "[ZoneProxy]\nListen = {}\nDefault = {}\n",
            self.listen,
            match self.default {
                DefaultRoute::Zone => "zone",
                DefaultRoute::Deny => "deny",
                DefaultRoute::Host => "host",
            }
        );
        for rule in &self.rules {
            match rule {
                Rule::Exact(name) => text.push_str(&format!("Rule = {name}\n")),
                Rule::Suffix(name) => text.push_str(&format!("Rule = .{name}\n")),
                Rule::Address(ip, prefix) => text.push_str(&format!("Rule = {ip}/{prefix}\n")),
            }
        }
        text
    }

    fn decision(&self, host: &str) -> DefaultRoute {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if self.rules.iter().any(|rule| match rule {
            Rule::Exact(name) => host == *name,
            Rule::Suffix(name) => {
                host.len() > name.len() + 1 && host.ends_with(&format!(".{name}"))
            }
            Rule::Address(network, prefix) => host
                .parse::<IpAddr>()
                .is_ok_and(|ip| same_network(ip, *network, *prefix)),
        }) {
            DefaultRoute::Zone
        } else {
            self.default
        }
    }
}

fn required(section: &crate::config::Section, key: &str) -> Result<String, String> {
    section
        .get(key)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("[ZoneProxy] needs {key}"))
}

fn rule(value: &str) -> Result<Rule, String> {
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return Err("Rule must be a domain or IP[/prefix] without spaces".to_owned());
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(Rule::Address(ip, if ip.is_ipv4() { 32 } else { 128 }));
    }
    if let Some((network, prefix)) = value.split_once('/') {
        let ip = network
            .parse::<IpAddr>()
            .map_err(|_| "Rule has an invalid IP network".to_owned())?;
        let prefix = prefix
            .parse::<u8>()
            .ok()
            .filter(|prefix| *prefix <= if ip.is_ipv4() { 32 } else { 128 })
            .ok_or("Rule has an invalid IP prefix")?;
        return Ok(Rule::Address(ip, prefix));
    }
    let (suffix, name) = value
        .strip_prefix('.')
        .map_or((false, value), |name| (true, name));
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    crate::pool::validate_dns_name(&name).map_err(|_| "Rule has an invalid domain".to_owned())?;
    if name == "localhost" {
        return Err("Rule must not route the proxy's own loopback address".to_owned());
    }
    Ok(if suffix {
        Rule::Suffix(name)
    } else {
        Rule::Exact(name)
    })
}

fn same_network(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
    let (ip, network, bits) = match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(network)) => (
            u128::from(u32::from(ip)),
            u128::from(u32::from(network)),
            32u8,
        ),
        (IpAddr::V6(ip), IpAddr::V6(network)) => (u128::from(ip), u128::from(network), 128u8),
        _ => return false,
    };
    let shift = bits.saturating_sub(prefix);
    (ip >> shift) == (network >> shift)
}

fn unit(zone: &str) -> String {
    format!("vpn-zone-proxy@{zone}.service")
}

pub fn ensure_started(tools: &Tools, zone: &str) -> Result<(), String> {
    if Config::load(&tools.state, zone)?.is_none() {
        return Ok(());
    }
    let unit = unit(zone);
    let active = Command::new(&tools.systemctl)
        .args(["--user", "is-active", "--quiet"])
        .arg(&unit)
        .status()
        .map_err(|e| format!("cannot inspect scoped proxy: {e}"))?;
    if active.success() {
        return Ok(());
    }
    let zone_unit = format!("vpn-zone@{zone}.service");
    let status = Command::new(&tools.systemd_run)
        .args([
            "--user",
            "--quiet",
            "--unit",
            &unit,
            "--service-type=exec",
            "-p",
            &format!("BindsTo={zone_unit}"),
            "-p",
            &format!("After={zone_unit}"),
            "--setenv",
            &format!("HOME={}", tools.home.display()),
            "--",
        ])
        .arg(&tools.core)
        .arg("zone-proxy-host")
        .arg("--state")
        .arg(&tools.state)
        .arg("--zone")
        .arg(zone)
        .arg("--nsenter")
        .arg(&tools.nsenter)
        .status()
        .map_err(|e| format!("cannot start scoped proxy: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "scoped proxy did not start (systemd status {status})"
        ))
    }
}

pub fn stop(tools: &Tools, zone: &str) {
    let _ = crate::cli::systemctl_unit(tools, "stop", std::ffi::OsStr::new(&unit(zone)));
}

pub fn restart(tools: &Tools, zone: &str) -> Result<(), String> {
    if Config::load(&tools.state, zone)?.is_none() {
        stop(tools, zone);
        return Ok(());
    }
    if crate::cli::zone_up(&tools.state, std::ffi::OsStr::new(zone)).is_none() {
        return Ok(());
    }
    stop(tools, zone);
    ensure_started(tools, zone)
}

pub fn cli(tools: &Tools, args: &[std::ffi::OsString]) -> u8 {
    let Some(action) = args.first().and_then(|arg| arg.to_str()) else {
        eprintln!("cellward zone-proxy set <зона> <порт> <zone|deny|host> [домен|IP[/prefix]…]\n  cellward zone-proxy show <зона>\n  cellward zone-proxy off <зона>");
        return 2;
    };
    match action {
        "show" if args.len() == 2 => {
            let Some(zone) = args[1].to_str() else {
                return 2;
            };
            match Config::load(&tools.state, zone) {
                Ok(Some(config)) => {
                    print!("{}", config.to_text());
                    0
                }
                Ok(None) => {
                    println!("scoped proxy для {zone} не настроен");
                    0
                }
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        "set" if args.len() >= 4 => {
            let Some(zone) = args[1]
                .to_str()
                .filter(|zone| crate::cli::safe_zone_name(std::ffi::OsStr::new(zone)))
            else {
                eprintln!("некорректное имя зоны");
                return 2;
            };
            if !tools.state.join(zone).join("config.conf").is_file() {
                eprintln!("нет зоны {zone}");
                return 1;
            }
            let Some(port) = args[2].to_str().and_then(|port| port.parse::<u16>().ok()) else {
                eprintln!("порт должен быть числом 1..65535");
                return 2;
            };
            let default = match args[3].to_str() {
                Some("zone") => DefaultRoute::Zone,
                Some("deny") => DefaultRoute::Deny,
                Some("host") => DefaultRoute::Host,
                _ => {
                    eprintln!("default должен быть zone, deny или host");
                    return 2;
                }
            };
            let rules: Vec<String> = args[4..]
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
            let config = match Config::new(port, default, &rules) {
                Ok(config) => config,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            };
            let path = tools.state.join(zone).join(FILE);
            let tmp = path.with_extension("tmp");
            let written = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .and_then(|mut file| {
                    file.write_all(config.to_text().as_bytes())?;
                    file.sync_all()
                })
                .and_then(|()| fs::rename(&tmp, &path));
            if let Err(e) = written {
                eprintln!("cannot write {}: {e}", path.display());
                return 1;
            }
            println!(
                "scoped proxy {zone}: SOCKS5 и HTTP CONNECT на 127.0.0.1:{port}, только TCP; поднимется вместе с зоной"
            );
            if default == DefaultRoute::Host {
                println!("ВНИМАНИЕ: несовпавшие правила идут напрямую через хост. Совпавшие — только через {zone}, без fallback.");
            } else if default == DefaultRoute::Deny {
                println!("Несовпавшие правила будут отклонены, не через хост.");
            }
            if let Err(e) = restart(tools, zone) {
                eprintln!("{e}");
                return 1;
            }
            0
        }
        "off" if args.len() == 2 => {
            let Some(zone) = args[1].to_str() else {
                return 2;
            };
            stop(tools, zone);
            let path = tools.state.join(zone).join(FILE);
            match fs::remove_file(&path) {
                Ok(()) => {
                    println!("scoped proxy {zone} выключен");
                    0
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
                Err(e) => {
                    eprintln!("cannot remove {}: {e}", path.display());
                    1
                }
            }
        }
        _ => 2,
    }
}

pub fn host_main(args: &[std::ffi::OsString]) -> u8 {
    let [state_flag, state, zone_flag, zone, nsenter_flag, nsenter] = args else {
        eprintln!("zone-proxy-host: need --state <dir> --zone <name> --nsenter <path>");
        return 2;
    };
    if state_flag != "--state" || zone_flag != "--zone" || nsenter_flag != "--nsenter" {
        return 2;
    }
    let Some(zone) = zone.to_str() else {
        return 2;
    };
    if !crate::cli::safe_zone_name(std::ffi::OsStr::new(zone)) {
        return 2;
    }
    let state = PathBuf::from(state);
    let config = match Config::load(&state, zone) {
        Ok(Some(config)) => config,
        Ok(None) => {
            eprintln!("zone proxy {zone}: no configuration");
            return 1;
        }
        Err(e) => {
            eprintln!("zone proxy {zone}: {e}");
            return 1;
        }
    };
    let listener = match TcpListener::bind(config.listen) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("zone proxy {zone}: cannot listen on {}: {e}", config.listen);
            return 1;
        }
    };
    eprintln!(
        "zone proxy {zone}: SOCKS5 and HTTP CONNECT on {} (default {:?})",
        config.listen, config.default
    );
    serve(
        listener,
        config,
        state,
        zone.to_owned(),
        PathBuf::from(nsenter),
    );
    0
}

fn serve(listener: TcpListener, config: Config, state: PathBuf, zone: String, nsenter: PathBuf) {
    for client in listener.incoming() {
        let Ok(client) = client else {
            continue;
        };
        let config = config.clone();
        let state = state.clone();
        let zone = zone.clone();
        let nsenter = nsenter.clone();
        std::thread::spawn(move || {
            let _ = client.set_nodelay(true);
            let _ = client.set_read_timeout(Some(CONNECT_WAIT));
            let _ = client.set_write_timeout(Some(CONNECT_WAIT));
            if let Err(e) = handle(client, &config, &state, &zone, &nsenter) {
                eprintln!("zone proxy {zone}: connection closed: {e}");
            }
        });
    }
}

fn handle(
    client: TcpStream,
    config: &Config,
    state: &Path,
    zone: &str,
    nsenter: &Path,
) -> Result<(), String> {
    let mut reader = BufReader::new(client.try_clone().map_err(|e| e.to_string())?);
    let protocol = reader
        .fill_buf()
        .map_err(|e| e.to_string())?
        .first()
        .copied()
        .ok_or("empty connection")?;
    let target = if protocol == 5 {
        socks5_request(&mut reader)?
    } else {
        http_connect(&mut reader)?
    };
    let (host, port) = split_target(&target)?;
    match config.decision(&host) {
        DefaultRoute::Deny => {
            if protocol == 5 {
                reader.get_mut().write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0])
            } else {
                reader
                    .get_mut()
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            }
            .map_err(|e| e.to_string())?;
            Ok(())
        }
        DefaultRoute::Zone => {
            let mut child = match spawn_zone(state, zone, nsenter, &host, port, reader.get_mut()) {
                Ok(child) => child,
                Err(_) => {
                    if protocol == 5 {
                        reader.get_mut().write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0])
                    } else {
                        reader
                            .get_mut()
                            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    }
                    .map_err(|e| e.to_string())?;
                    return Ok(());
                }
            };
            let mut answer = [0u8; 1];
            let status = child
                .stderr
                .as_mut()
                .ok_or("zone connector has no status channel")?
                .read_exact(&mut answer);
            if status.is_err() {
                let _ = child.kill();
                let _ = child.wait();
                return Err("zone connector did not answer".to_owned());
            }
            if answer[0] != b'y' {
                let _ = child.wait();
                if protocol == 5 {
                    reader.get_mut().write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0])
                } else {
                    reader
                        .get_mut()
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                }
                .map_err(|e| e.to_string())?;
                return Ok(());
            }
            if protocol == 5 {
                reader.get_mut().write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            } else {
                reader
                    .get_mut()
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            }
            .map_err(|e| e.to_string())?;
            let _ = child.wait();
            Ok(())
        }
        DefaultRoute::Host => {
            let mut upstream = match connect((&*host, port)) {
                Ok(upstream) => upstream,
                Err(_) => {
                    if protocol == 5 {
                        reader.get_mut().write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0])
                    } else {
                        reader
                            .get_mut()
                            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    }
                    .map_err(|e| e.to_string())?;
                    return Ok(());
                }
            };
            if protocol == 5 {
                reader.get_mut().write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            } else {
                reader
                    .get_mut()
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            }
            .map_err(|e| e.to_string())?;
            relay(&mut reader, &mut upstream)
        }
    }
}

fn socks5_request(reader: &mut BufReader<TcpStream>) -> Result<String, String> {
    let mut header = [0u8; 2];
    reader.read_exact(&mut header).map_err(|e| e.to_string())?;
    if header[0] != 5 {
        return Err("not SOCKS5".to_owned());
    }
    let mut methods = vec![0u8; usize::from(header[1])];
    reader.read_exact(&mut methods).map_err(|e| e.to_string())?;
    if !methods.contains(&0) {
        return Err("SOCKS5 client requires authentication".to_owned());
    }
    reader
        .get_mut()
        .write_all(&[5, 0])
        .map_err(|e| e.to_string())?;
    let mut request = [0u8; 4];
    reader.read_exact(&mut request).map_err(|e| e.to_string())?;
    if request[0] != 5 || request[1] != 1 || request[2] != 0 {
        return Err("only SOCKS5 CONNECT is supported".to_owned());
    }
    let host = match request[3] {
        1 => {
            let mut octets = [0u8; 4];
            reader.read_exact(&mut octets).map_err(|e| e.to_string())?;
            IpAddr::from(octets).to_string()
        }
        4 => {
            let mut octets = [0u8; 16];
            reader.read_exact(&mut octets).map_err(|e| e.to_string())?;
            IpAddr::from(octets).to_string()
        }
        3 => {
            let mut length = [0u8; 1];
            reader.read_exact(&mut length).map_err(|e| e.to_string())?;
            if length[0] == 0 {
                return Err("empty SOCKS5 domain".to_owned());
            }
            let mut name = vec![0u8; usize::from(length[0])];
            reader.read_exact(&mut name).map_err(|e| e.to_string())?;
            String::from_utf8(name).map_err(|_| "SOCKS5 domain is not UTF-8")?
        }
        _ => return Err("unknown SOCKS5 address type".to_owned()),
    };
    let mut port = [0u8; 2];
    reader.read_exact(&mut port).map_err(|e| e.to_string())?;
    Ok(format_target(&host, u16::from_be_bytes(port)))
}

fn http_connect(reader: &mut BufReader<TcpStream>) -> Result<String, String> {
    let mut first = String::new();
    let read = reader.read_line(&mut first).map_err(|e| e.to_string())?;
    if read == 0 || read > HEADER_LIMIT || !first.starts_with("CONNECT ") {
        return Err("only HTTP CONNECT is supported".to_owned());
    }
    let mut words = first.split_whitespace();
    let target = words.nth(1).ok_or("CONNECT has no target")?.to_owned();
    let version = words.next().unwrap_or_default();
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || words.next().is_some() {
        return Err("invalid CONNECT request".to_owned());
    }
    let mut bytes = first.len();
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).map_err(|e| e.to_string())?;
        bytes += read;
        if bytes > HEADER_LIMIT {
            return Err("HTTP headers are too large".to_owned());
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        if read == 0 {
            return Err("truncated HTTP headers".to_owned());
        }
    }
    Ok(target)
}

fn split_target(target: &str) -> Result<(String, u16), String> {
    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        let (host, port) = rest.split_once("]:").ok_or("invalid bracketed target")?;
        (host, port)
    } else {
        target.rsplit_once(':').ok_or("target has no port")?
    };
    if host.is_empty() || host.contains(['\r', '\n', '\0']) {
        return Err("invalid target host".to_owned());
    }
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or("target has an invalid port")?;
    Ok((host.to_owned(), port))
}

fn format_target(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn spawn_zone(
    state: &Path,
    zone: &str,
    nsenter: &Path,
    host: &str,
    port: u16,
    client: &mut TcpStream,
) -> Result<Child, String> {
    let pid = crate::cli::zone_up(state, std::ffi::OsStr::new(zone)).ok_or("zone is down")?;
    let core = std::env::current_exe().map_err(|e| e.to_string())?;
    let input = client.try_clone().map_err(|e| e.to_string())?;
    let output = client.try_clone().map_err(|e| e.to_string())?;
    let mut command = Command::new(nsenter);
    command
        .env_clear()
        .env("HOME", std::env::var_os("HOME").unwrap_or_default())
        .args(["--preserve-credentials", "-U", "-n", "-m", "-t"])
        .arg(pid.to_string())
        .arg("--")
        .arg(core)
        .arg("zone-proxy-connect")
        .arg(format_target(host, port))
        // SAFETY: each owned client descriptor is transferred to exactly one File.
        .stdin(Stdio::from(unsafe {
            std::fs::File::from_raw_fd(input.into_raw_fd())
        }))
        .stdout(Stdio::from(unsafe {
            std::fs::File::from_raw_fd(output.into_raw_fd())
        }))
        .stderr(Stdio::piped());
    command
        .spawn()
        .map_err(|e| format!("cannot enter zone: {e}"))
}

fn connect<A: ToSocketAddrs>(target: A) -> Result<TcpStream, String> {
    let addresses = target
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve target: {e}"))?;
    let mut last = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, CONNECT_WAIT) {
            Ok(stream) => return Ok(stream),
            Err(e) => last = Some(e),
        }
    }
    Err(last
        .map(|e| format!("target connection failed: {e}"))
        .unwrap_or_else(|| "target resolved to no addresses".to_owned()))
}

fn relay(reader: &mut BufReader<TcpStream>, upstream: &mut TcpStream) -> Result<(), String> {
    let buffered = reader.buffer().to_vec();
    if !buffered.is_empty() {
        upstream.write_all(&buffered).map_err(|e| e.to_string())?;
    }
    let mut client_read = reader.get_mut().try_clone().map_err(|e| e.to_string())?;
    let mut client_write = reader.get_mut().try_clone().map_err(|e| e.to_string())?;
    let mut upstream_read = upstream.try_clone().map_err(|e| e.to_string())?;
    let mut upstream_write = upstream.try_clone().map_err(|e| e.to_string())?;
    let worker = std::thread::spawn(move || {
        let result = std::io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
        result
    });
    let _ = std::io::copy(&mut upstream_read, &mut client_write);
    let _ = client_write.shutdown(Shutdown::Write);
    let _ = worker.join();
    Ok(())
}

pub fn connect_main(args: &[std::ffi::OsString]) -> u8 {
    let [target] = args else {
        return 2;
    };
    let Some(target) = target.to_str() else {
        return 2;
    };
    let Ok((host, port)) = split_target(target) else {
        return 2;
    };
    match connect((&*host, port)) {
        Ok(upstream) => {
            let _ = std::io::stderr().write_all(b"y");
            // SAFETY: this helper is started with the accepted socket as stdin/stdout;
            // duplicating the descriptors before either relay thread finishes keeps
            // them alive for the whole transfer.
            let input = unsafe { std::fs::File::from_raw_fd(0) };
            let output = unsafe { std::fs::File::from_raw_fd(1) };
            let mut reader = input.try_clone().expect("stdin descriptor");
            let mut writer = output.try_clone().expect("stdout descriptor");
            let mut upstream_read = upstream.try_clone().expect("upstream descriptor");
            let mut upstream_write = upstream;
            let worker = std::thread::spawn(move || {
                let result = std::io::copy(&mut reader, &mut upstream_write);
                let _ = upstream_write.shutdown(Shutdown::Write);
                result
            });
            let result = std::io::copy(&mut upstream_read, &mut writer);
            // SAFETY: fd 1 is the accepted socket; this only disables its write half.
            unsafe { libc::shutdown(1, libc::SHUT_WR) };
            let _ = worker.join();
            if result.is_ok() {
                0
            } else {
                1
            }
        }
        Err(_) => {
            let _ = std::io::stderr().write_all(b"n");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(default: DefaultRoute, rules: &[&str]) -> Config {
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            default,
            rules: rules.iter().map(|value| rule(value).unwrap()).collect(),
        }
    }

    #[test]
    fn configuration_is_loopback_only_and_round_trips() {
        let ini = WgConfig::parse(
            b"[ZoneProxy]\nListen = 127.0.0.1:1080\nDefault = host\nRule = example.com\nRule = .googlevideo.com\nRule = 192.0.2.0/24\n",
        )
        .unwrap();
        let config = Config::from_ini(&ini).unwrap();
        assert_eq!(config.to_text(), "[ZoneProxy]\nListen = 127.0.0.1:1080\nDefault = host\nRule = example.com\nRule = .googlevideo.com\nRule = 192.0.2.0/24\n");
        assert_eq!(config.decision("example.com"), DefaultRoute::Zone);
        assert_eq!(config.decision("www.example.com"), DefaultRoute::Host);
        assert_eq!(config.decision("www.googlevideo.com"), DefaultRoute::Zone);
        assert_eq!(config.decision("192.0.2.4"), DefaultRoute::Zone);
        assert_eq!(config.decision("198.51.100.1"), DefaultRoute::Host);
        for bad in [
            "[ZoneProxy]\nListen = 0.0.0.0:1080\nDefault = zone\n",
            "[ZoneProxy]\nListen = 127.0.0.1:0\nDefault = zone\n",
            "[ZoneProxy]\nListen = 127.0.0.1:1080\nDefault = direct\n",
            "[ZoneProxy]\nListen = 127.0.0.1:1080\nDefault = zone\nRule = bad name\n",
        ] {
            assert!(Config::from_ini(&WgConfig::parse(bad.as_bytes()).unwrap()).is_err());
        }
    }

    #[test]
    fn targets_and_networks_are_parsed_without_hostname_resolution() {
        assert_eq!(
            split_target("example.com:443").unwrap(),
            ("example.com".into(), 443)
        );
        assert_eq!(
            split_target("[2001:db8::1]:443").unwrap(),
            ("2001:db8::1".into(), 443)
        );
        assert!(split_target("example.com").is_err());
        assert!(same_network(
            "192.0.2.4".parse().unwrap(),
            "192.0.2.0".parse().unwrap(),
            24
        ));
        assert!(!same_network(
            "192.0.3.4".parse().unwrap(),
            "192.0.2.0".parse().unwrap(),
            24
        ));
    }

    fn echo_server() -> (SocketAddr, std::thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).unwrap();
            received
        });
        (address, worker)
    }

    #[test]
    fn socks5_uses_explicit_host_mode_without_a_zone() {
        let (address, worker) = echo_server();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = listener.local_addr().unwrap();
        let config = config(DefaultRoute::Host, &[]);
        std::thread::spawn(move || {
            serve(
                listener,
                config,
                PathBuf::new(),
                "missing".into(),
                PathBuf::new(),
            )
        });
        let mut client = TcpStream::connect(proxy).unwrap();
        client.write_all(&[5, 1, 0, 5, 1, 0, 3]).unwrap();
        let host = address.ip().to_string();
        client.write_all(&[host.len() as u8]).unwrap();
        client.write_all(host.as_bytes()).unwrap();
        client.write_all(&address.port().to_be_bytes()).unwrap();
        let mut response = [0u8; 12];
        client.read_exact(&mut response).unwrap();
        assert_eq!(response, [5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        client.write_all(b"synthetic").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        assert_eq!(worker.join().unwrap(), b"synthetic");
    }

    #[test]
    fn default_deny_and_missing_zone_never_fall_back_to_host() {
        for default in [DefaultRoute::Deny, DefaultRoute::Zone] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let proxy = listener.local_addr().unwrap();
            let config = config(default, &[]);
            std::thread::spawn(move || {
                serve(
                    listener,
                    config,
                    PathBuf::new(),
                    "missing".into(),
                    PathBuf::new(),
                )
            });
            let mut client = TcpStream::connect(proxy).unwrap();
            client
                .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .unwrap();
            let mut response = String::new();
            BufReader::new(client).read_line(&mut response).unwrap();
            assert!(response.contains(if default == DefaultRoute::Deny {
                "403"
            } else {
                "502"
            }));
        }
    }
}
