//! Transport discovery and the frame boundary between Cellward and adapters.
//!
//! Built-in WG/AWG/OpenConnect and external manifests share one description.
//! Reading a manifest never executes its `Run` path. Process isolation and
//! lifecycle are deliberately separate from this read-only inventory.

use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use crate::config::WgConfig;
use crate::tools::Tools;

pub const SECTION: &str = "Transport";
pub const DIRECTORY: &str = "transports";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    WireGuard,
    AmneziaWg,
    OpenConnect,
    Plugin,
}

impl Kind {
    fn text(self) -> &'static str {
        match self {
            Self::WireGuard => "wg",
            Self::AmneziaWg => "awg",
            Self::OpenConnect => "openconnect",
            Self::Plugin => "plugin",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Datagram,
    Stream,
    Application,
}

impl Channel {
    fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "datagram" => Some(Self::Datagram),
            "stream" => Some(Self::Stream),
            "application" => Some(Self::Application),
            _ => None,
        }
    }

    fn text(self) -> &'static str {
        match self {
            Self::Datagram => "datagram",
            Self::Stream => "stream",
            Self::Application => "application",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    pub ipv4: bool,
    pub ipv6: bool,
    pub asymmetric: bool,
    pub multiplex: bool,
    /// Declared by the adapter, not measured by Cellward.
    pub mtu: Option<u32>,
}

impl Capabilities {
    fn new(ipv6: bool) -> Self {
        Self {
            ipv4: true,
            ipv6,
            asymmetric: false,
            multiplex: true,
            mtu: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adapter {
    pub name: String,
    pub kind: Kind,
    pub channel: Channel,
    pub capabilities: Capabilities,
    pub run: Option<PathBuf>,
    /// Run the deterministic lifecycle adapter instead of the normal protocol.
    pub fake: bool,
}

impl Adapter {
    fn builtin(name: &str, kind: Kind, channel: Channel, ipv6: bool) -> Self {
        Self {
            name: name.to_owned(),
            kind,
            channel,
            capabilities: Capabilities::new(ipv6),
            run: None,
            fake: false,
        }
    }

    pub fn builtins() -> Vec<Self> {
        vec![
            Self::builtin("wireguard", Kind::WireGuard, Channel::Datagram, true),
            Self::builtin("amneziawg", Kind::AmneziaWg, Channel::Datagram, true),
            Self::builtin("openconnect", Kind::OpenConnect, Channel::Stream, true),
        ]
    }

    pub fn from_manifest(raw: &[u8]) -> Result<Self, String> {
        let ini = WgConfig::parse(raw).map_err(|e| e.to_string())?;
        if ini.sections.len() != 1 || !ini.sections[0].name.eq_ignore_ascii_case(SECTION) {
            return Err("a transport manifest needs exactly one [Transport]".to_owned());
        }
        let section = &ini.sections[0];
        const KEYS: &[&str] = &[
            "Name",
            "Run",
            "Channel",
            "IPv4",
            "IPv6",
            "Asymmetric",
            "Multiplex",
            "MTU",
            "Fake",
        ];
        if let Some(key) = section
            .entries
            .iter()
            .find(|entry| !KEYS.iter().any(|key| entry.key.eq_ignore_ascii_case(key)))
            .map(|entry| entry.key.as_str())
        {
            return Err(format!("unknown [Transport] key {key}"));
        }
        let name = required(section, "Name")?;
        if !valid_name(&name) {
            return Err(
                "transport Name must be 1–64 ASCII letters, digits, '.', '_' or '-'".to_owned(),
            );
        }
        if Self::builtins().iter().any(|adapter| adapter.name == name) {
            return Err(format!("transport name {name} is built in"));
        }
        let run = PathBuf::from(required(section, "Run")?);
        if !run.is_absolute() {
            return Err("transport Run must be an absolute path".to_owned());
        }
        let channel = Channel::parse(&required(section, "Channel")?)
            .ok_or("transport Channel must be datagram, stream or application")?;
        let capabilities = Capabilities {
            ipv4: boolean(section, "IPv4", true)?,
            ipv6: boolean(section, "IPv6", false)?,
            asymmetric: boolean(section, "Asymmetric", false)?,
            multiplex: boolean(section, "Multiplex", true)?,
            mtu: match section.get("MTU") {
                Some(value) => {
                    let mtu = value
                        .trim()
                        .parse::<u32>()
                        .map_err(|_| "transport MTU must be 576–65535".to_owned())?;
                    if !(576..=65535).contains(&mtu) {
                        return Err("transport MTU must be 576–65535".to_owned());
                    }
                    Some(mtu)
                }
                None => None,
            },
        };
        if !capabilities.ipv4 && !capabilities.ipv6 {
            return Err("a transport needs IPv4 or IPv6".to_owned());
        }
        Ok(Self {
            name,
            kind: Kind::Plugin,
            channel,
            capabilities,
            run: Some(run),
            fake: boolean(section, "Fake", false)?,
        })
    }

    fn json(&self) -> String {
        use crate::status::string;
        format!(
            "{{\"name\":{},\"kind\":{},\"channel\":{},\"capabilities\":{{\"ipv4\":{},\"ipv6\":{},\"asymmetric\":{},\"multiplex\":{},\"mtu\":{}}},\"run\":{}}}",
            string(&self.name),
            string(self.kind.text()),
            string(self.channel.text()),
            self.capabilities.ipv4,
            self.capabilities.ipv6,
            self.capabilities.asymmetric,
            self.capabilities.multiplex,
            self.capabilities
                .mtu
                .map_or("null".to_owned(), |mtu| mtu.to_string()),
            self.run.as_ref().map_or("null".to_owned(), |path| {
                string(&path.as_os_str().to_string_lossy())
            })
        )
    }
}

fn required(section: &crate::config::Section, key: &str) -> Result<String, String> {
    section
        .get(key)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("[Transport] needs {key}"))
}

fn boolean(section: &crate::config::Section, key: &str, default: bool) -> Result<bool, String> {
    match section.get(key).map(str::trim) {
        None => Ok(default),
        Some("yes" | "true" | "on" | "1") => Ok(true),
        Some("no" | "false" | "off" | "0") => Ok(false),
        _ => Err(format!("transport {key} must be yes or no")),
    }
}

fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

pub fn inventory(config: &Path) -> Result<Vec<Adapter>, String> {
    let mut adapters = Adapter::builtins();
    let directory = config.join(DIRECTORY);
    let mut files = Vec::new();
    if directory.is_dir() {
        for entry in fs::read_dir(&directory)
            .map_err(|e| format!("cannot read {}: {e}", directory.display()))?
        {
            let path = entry
                .map_err(|e| format!("cannot read {}: {e}", directory.display()))?
                .path();
            if path
                .extension()
                .is_some_and(|extension| extension == "conf")
            {
                files.push(path);
            }
        }
    }
    files.sort();
    let mut names = BTreeMap::new();
    for path in files {
        let raw = fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let adapter =
            Adapter::from_manifest(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
        if names.insert(adapter.name.clone(), ()).is_some() {
            return Err(format!("duplicate transport {}", adapter.name));
        }
        adapters.push(adapter);
    }
    Ok(adapters)
}

/// One frame on the adapter boundary. Ordering, replay checks and congestion
/// control belong to the session protocol, not to an untrusted payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub session_id: u64,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

pub trait AdapterSession {
    fn capabilities(&self) -> &Capabilities;
    fn send(&mut self, frame: Frame) -> Result<(), String>;
    fn recv(&mut self) -> Option<Frame>;
}

/// A deterministic fake adapter for VM and scheduler tests.
pub struct LoopbackSession {
    capabilities: Capabilities,
    incoming: VecDeque<Frame>,
    outgoing: VecDeque<Frame>,
}

impl LoopbackSession {
    pub fn new(capabilities: Capabilities) -> Self {
        Self {
            capabilities,
            incoming: VecDeque::new(),
            outgoing: VecDeque::new(),
        }
    }

    pub fn peer_send(&mut self, frame: Frame) {
        self.incoming.push_back(frame);
    }

    pub fn take_sent(&mut self) -> Option<Frame> {
        self.outgoing.pop_front()
    }
}

impl AdapterSession for LoopbackSession {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    fn send(&mut self, frame: Frame) -> Result<(), String> {
        if let Some(mtu) = self.capabilities.mtu {
            if frame.payload.len() > mtu as usize {
                return Err(format!("frame exceeds declared MTU {mtu}"));
            }
        }
        self.outgoing.push_back(frame);
        Ok(())
    }

    fn recv(&mut self) -> Option<Frame> {
        self.incoming.pop_front()
    }
}

/// `cellward transport list [--json]` and `transport check <manifest>`.
pub fn run(tools: &Tools, args: &[OsString]) -> u8 {
    const USAGE: &str = "cellward transport list [--json]\n\
                         cellward transport check <manifest.conf>\n\
                         cellward transport selftest <имя>";
    let words: Vec<&str> = match args.iter().map(|arg| arg.to_str()).collect::<Option<_>>() {
        Some(words) => words,
        None => {
            eprintln!("{USAGE}");
            return 1;
        }
    };
    match words.as_slice() {
        ["list"] | ["list", "--json"] => match inventory(&tools.config) {
            Ok(adapters) => {
                if words == ["list", "--json"] {
                    let rows: Vec<String> = adapters.iter().map(Adapter::json).collect();
                    println!("[{}]", rows.join(","));
                } else {
                    for adapter in adapters {
                        println!(
                            "{}\t{}\t{}\tipv4={} ipv6={} asymmetric={} multiplex={} mtu={}{}",
                            adapter.name,
                            adapter.kind.text(),
                            adapter.channel.text(),
                            adapter.capabilities.ipv4,
                            adapter.capabilities.ipv6,
                            adapter.capabilities.asymmetric,
                            adapter.capabilities.multiplex,
                            adapter
                                .capabilities
                                .mtu
                                .map_or("unknown".to_owned(), |mtu| mtu.to_string()),
                            adapter.run.as_ref().map_or(String::new(), |run| {
                                format!(" run={}", run.as_os_str().to_string_lossy())
                            })
                        );
                    }
                }
                0
            }
            Err(error) => {
                eprintln!("{error}");
                1
            }
        },
        ["selftest", name] => match crate::adapter_process::selftest(tools, name) {
            Ok(frame) => {
                println!(
                    "ok\t{}\tsession={} sequence={} bytes={}",
                    name,
                    frame.session_id,
                    frame.sequence,
                    frame.payload.len()
                );
                0
            }
            Err(error) => {
                eprintln!("{error}");
                1
            }
        },
        ["check", path] => match fs::read(path) {
            Ok(raw) => match Adapter::from_manifest(&raw) {
                Ok(adapter) => {
                    println!(
                        "{}\t{}\t{}",
                        adapter.name,
                        adapter.kind.text(),
                        adapter.channel.text()
                    );
                    0
                }
                Err(error) => {
                    eprintln!("{error}");
                    1
                }
            },
            Err(error) => {
                eprintln!("cannot read {path}: {error}");
                1
            }
        },
        _ => {
            eprintln!("{USAGE}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_and_external_adapters_share_one_inventory() {
        let root = std::env::temp_dir().join(format!("cellward-transports-{}", std::process::id()));
        let directory = root.join(DIRECTORY);
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("reticulum.conf"),
            b"[Transport]\nName = reticulum\nRun = /run/current-system/sw/bin/true\nChannel = datagram\nIPv6 = yes\nAsymmetric = yes\nMTU = 1200\n",
        )
        .unwrap();
        let adapters = inventory(&root).unwrap();
        assert_eq!(adapters.len(), 4);
        assert_eq!(adapters[0].kind, Kind::WireGuard);
        assert_eq!(adapters[3].name, "reticulum");
        assert!(adapters[3].capabilities.asymmetric);
        assert_eq!(adapters[3].capabilities.mtu, Some(1200));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_manifest_is_validated_without_executing_its_program() {
        let good = Adapter::from_manifest(
            b"[Transport]\nName = game\nRun = /does/not/exist\nChannel = application\nIPv4 = yes\n",
        )
        .unwrap();
        assert_eq!(good.channel, Channel::Application);
        for bad in [
            &b"[Transport]\nRun = /bin/true\nChannel = datagram\n"[..],
            &b"[Transport]\nName = x\nRun = relative\nChannel = datagram\n"[..],
            &b"[Transport]\nName = wireguard\nRun = /bin/true\nChannel = datagram\n"[..],
            &b"[Transport]\nName = x\nRun = /bin/true\nChannel = datagram\nMTU = 2\n"[..],
            &b"[Transport]\nName = x\nRun = /bin/true\nChannel = datagram\nIPv4 = no\nIPv6 = no\n"
                [..],
        ] {
            assert!(Adapter::from_manifest(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_fake_session_exercises_frames_and_the_declared_mtu() {
        let capabilities = Capabilities {
            ipv4: true,
            ipv6: false,
            asymmetric: true,
            multiplex: true,
            mtu: Some(4),
        };
        let mut session = LoopbackSession::new(capabilities);
        let frame = Frame {
            session_id: 7,
            sequence: 11,
            payload: vec![1, 2, 3, 4],
        };
        session.send(frame.clone()).unwrap();
        assert_eq!(session.take_sent(), Some(frame.clone()));
        session.peer_send(frame.clone());
        assert_eq!(session.recv(), Some(frame.clone()));
        assert!(session
            .send(Frame {
                payload: vec![0; 5],
                ..frame
            })
            .is_err());
    }
}
