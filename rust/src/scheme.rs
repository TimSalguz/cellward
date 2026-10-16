//! The network scheme as data (`cellward scheme [--json]`): every place a
//! container's packet passes — its program, its container's network and
//! gate, its zone's way in, tunnel and way out, the host's interface, the
//! gateway, what is past it, the VPN's server, where it goes — and every flow
//! through them, hop by hop: what goes, in what it is wrapped, who can read
//! it, and where the flow ends — arrived, denied, answered on the way, or
//! cut. What the window draws and a person reads in a terminal, from one
//! source; drawn by nothing here.
//!
//! **Facts, then the scheme.** [`facts`] reads what is: the zones (their
//! tunnels, servers, resolvers, the host's way to each server), the host's
//! interfaces, the running instances and their flows with each one's
//! program and the gate's decision. [`build`] makes the scheme of them and
//! looks at nothing else: what a scheme says of a set of facts is tested
//! with no network at all.
//!
//! **A flow is a row**, but not one per connection: a container's programs
//! open hundreds. A row is a program's flows of one kind — its connections,
//! its names asked, those the gate denied, its talk with the gateway —, with
//! their count, their bytes and the destinations most used. A zone adds its
//! tunnel's handshake and the lookup of its server's name; the host, its own
//! programs, which go around every zone.
//!
//! **Who can read a hop** ([`Sees`]): the machine alone; nobody (encrypted);
//! the VPN's server, as any site's way out; a stranger, in clear — the LAN,
//! the networks past the gateway, a public resolver. Told by the zone's kind
//! and its resolvers' side (`crate::dnspath`), never by guessing what is
//! unknown: the host knows its route's next hop — a gateway, or none, the
//! destination on its own link —, not whether it is a router or a provider's;
//! what is past it is a place of its own, marked unknown.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::dnspath::Side;
use crate::flows::{ICMP6, TCP, UDP};
use crate::tools::Tools;

// --- FACTS ------------------------------------------------------------------

/// A zone, as its directory and the host say.
#[derive(Debug, Clone, PartialEq)]
pub struct Zone {
    pub name: String,
    pub up: bool,
    /// `amneziawg`, `wireguard`, `openconnect`, `host`, `system`
    /// (`crate::netmap::Tunnel`).
    pub kind: &'static str,
    pub servers: Vec<Server>,
    /// Its config's `DNS =`, each by its side.
    pub dns: Vec<(IpAddr, Side)>,
    /// What its app namespace really routes (`netmap::route_in`): none, not
    /// looked at (down, or a kind with no tunnel of its own).
    pub inside: Option<Inside>,
}

/// A zone's routes as its app namespace has them: the interface the
/// internet is reached by, and each resolver's — `None`, no route at all.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Inside {
    pub data: Option<String>,
    pub dns: Vec<(IpAddr, Option<String>)>,
}

/// A zone's server, and the host's way to it.
#[derive(Debug, Clone, PartialEq)]
pub struct Server {
    /// As the config writes it.
    pub raw: String,
    /// Its address: a literal, or the one kept for its name.
    pub addr: Option<IpAddr>,
    /// The config names it (looked up through the host's resolver).
    pub named: bool,
    /// The host's interface to it, and the gateway on the way.
    pub dev: Option<String>,
    pub via: Option<String>,
}

/// A running instance and its flows.
#[derive(Debug, Clone, PartialEq)]
pub struct Instance {
    pub id: String,
    /// Its container; none for a throwaway.
    pub container: Option<String>,
    pub network: String,
    pub flows: Vec<Flow>,
    /// Its rules' named counters (`zone::INSTANCE_COUNTERS`): packets each
    /// drop rule dropped; none, not read.
    pub counters: Vec<(String, u64)>,
}

/// The named counters of `nft list counters` text: each one's name and its
/// packets.
pub fn parse_counters(text: &str) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    let mut name = None;
    for line in text.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("counter ") {
            name = rest.split_whitespace().next().map(str::to_owned);
        } else if let (Some(n), Some(rest)) = (&name, line.strip_prefix("packets ")) {
            if let Some(p) = rest.split_whitespace().next().and_then(|p| p.parse().ok()) {
                out.push((n.clone(), p));
            }
            name = None;
        }
    }
    out
}

/// The counters of the instance whose space is process `pid`: its rules
/// listed in its network namespace, entered as the user (read only).
fn counters_of(tools: &Tools, pid: i32) -> Vec<(String, u64)> {
    // `--keep-caps`, as `doctor` enters: what the user namespace gives kept
    // across the exec — nft lists nothing without ("you must be root").
    std::process::Command::new(&tools.nsenter)
        .args([
            "--preserve-credentials",
            "--keep-caps",
            "-U",
            "-n",
            "-t",
            &pid.to_string(),
            "--",
        ])
        .arg(&tools.nft)
        .args(["list", "counters", "table", "inet", crate::zone::NFT_TABLE])
        .stdin(std::process::Stdio::null())
        .output()
        .map(|o| {
            if !o.status.success() {
                // Said, not hidden: no counters is not "nothing dropped".
                eprintln!(
                    "scheme: the counters of instance {pid} not read ({}): {}",
                    o.status,
                    String::from_utf8_lossy(&o.stderr).trim()
                );
            }
            parse_counters(&String::from_utf8_lossy(&o.stdout))
        })
        .unwrap_or_else(|e| {
            eprintln!("scheme: the counters of instance {pid} not read: {e}");
            Vec::new()
        })
}

/// A flow of an instance's.
#[derive(Debug, Clone, PartialEq)]
pub struct Flow {
    pub proto: u8,
    pub lport: u16,
    pub remote: IpAddr,
    pub rport: u16,
    /// What a DNS answer named the address.
    pub name: Option<String>,
    /// Its program, for a person; none where none was found.
    pub program: Option<String>,
    pub out_bytes: u64,
    pub in_bytes: u64,
    /// The gate's decision; none, not decided (or not the gate's).
    pub verdict: Option<crate::verdicts::Verdict>,
}

/// What the scheme is made of.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Facts {
    pub zones: Vec<Zone>,
    pub ifaces: Vec<crate::netmap::Iface>,
    pub instances: Vec<Instance>,
    /// The host's own way out: its default route's interface and gateway.
    pub default: Option<(String, Option<String>)>,
}

/// An address on the internet the host's default route is asked about.
const SOMEWHERE: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));

/// The facts as they are now.
pub fn facts(tools: &Tools) -> Facts {
    // The host's own network is a zone too, when it was brought up once.
    let mut names = crate::panel::zones(&tools.state);
    if tools
        .state
        .join(crate::launch::HOST)
        .join("config.conf")
        .is_file()
    {
        names.push(crate::launch::HOST.to_owned());
    }
    let zones = names
        .into_iter()
        .map(|name| {
            let dir = tools.state.join(&name);
            let up = crate::cli::zone_pid(&tools.state, std::ffi::OsStr::new(&name)).is_some();
            let tunnel = crate::netmap::tunnel_of(&dir);
            let servers = tunnel
                .as_ref()
                .map(|t| {
                    t.servers
                        .iter()
                        .map(|(raw, addr, named)| {
                            let route = addr.and_then(|a| crate::netmap::route_to(&tools.ip, a));
                            Server {
                                raw: raw.clone(),
                                addr: *addr,
                                named: *named,
                                dev: route.as_ref().map(|(d, _)| d.clone()),
                                via: route.and_then(|(_, v)| v),
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
            let kind = tunnel.map_or("wireguard", |t| t.kind);
            let dns = crate::dnspath::of_zone(&dir);
            // What the zone's app namespace really routes: a tunnel zone's,
            // up.
            let pid = crate::cli::zone_pid(&tools.state, std::ffi::OsStr::new(&name));
            let inside = pid
                .filter(|_| matches!(kind, "amneziawg" | "wireguard" | "openconnect"))
                .map(|pid| {
                    let route = |a| crate::netmap::route_in(&tools.nsenter, &tools.ip, pid, a);
                    Inside {
                        data: route(SOMEWHERE).map(|(dev, _)| dev),
                        dns: dns
                            .iter()
                            .map(|(a, _)| (*a, route(*a).map(|(d, _)| d)))
                            .collect(),
                    }
                });
            Zone {
                kind,
                dns,
                name,
                up,
                servers,
                inside,
            }
        })
        .collect();
    let instances = crate::flows::listed(tools)
        .into_iter()
        .map(|l| {
            let dir = crate::instance::running(&tools.state)
                .into_iter()
                .find(|i| i.id == l.id)
                .map(|i| i.dir);
            let decisions = dir.and_then(|d| {
                let file = std::fs::File::open(d.join(crate::verdicts::FILE)).ok()?;
                crate::verdicts::Table::map(std::os::fd::AsFd::as_fd(&file), false).ok()
            });
            let flows = l
                .table
                .as_ref()
                .map(|(flows, names)| {
                    flows
                        .iter()
                        .zip(&l.owners)
                        .map(|(f, owner)| Flow {
                            proto: f.key.proto,
                            lport: f.key.lport,
                            remote: f.key.remote,
                            rport: f.key.rport,
                            name: crate::flows::name_of(names, &f.key.remote).map(str::to_owned),
                            program: crate::flows::holder_name(owner.as_ref(), &l.labels),
                            out_bytes: f.out_bytes,
                            in_bytes: f.in_bytes,
                            verdict: decisions.as_ref().and_then(|t| t.get(&f.key)),
                        })
                        .collect()
                })
                .unwrap_or_default();
            if let Some(t) = decisions {
                t.close();
            }
            let counters = crate::instance::running(&tools.state)
                .into_iter()
                .find(|i| i.id == l.id)
                .map(|i| counters_of(tools, i.pid))
                .unwrap_or_default();
            Instance {
                id: l.id,
                container: l.container,
                network: l.network,
                flows,
                counters,
            }
        })
        .collect();
    Facts {
        zones,
        ifaces: crate::netmap::ifaces(&tools.ip),
        instances,
        default: crate::netmap::route_to(&tools.ip, SOMEWHERE),
    }
}

// --- THE SCHEME -------------------------------------------------------------

/// Where a place is, outside in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    Program,
    Container,
    /// A zone's app namespace: its way in and its tunnel.
    Zone,
    /// A zone's uplink namespace: its way out.
    Uplink,
    Host,
    Outside,
}

impl Layer {
    pub fn word(self) -> &'static str {
        match self {
            Self::Program => "program",
            Self::Container => "container",
            Self::Zone => "zone",
            Self::Uplink => "uplink",
            Self::Host => "host",
            Self::Outside => "outside",
        }
    }
}

/// A place a packet passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Place {
    pub id: String,
    pub layer: Layer,
    /// For a person.
    pub name: String,
    /// What it is, technically.
    pub tech: String,
    /// The firewall decides here.
    pub gate: bool,
    /// What is inside is not known (the networks past the gateway).
    pub unknown: bool,
}

/// Who can read a hop's contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sees {
    /// The machine alone: it never leaves.
    Machine,
    /// Nobody: encrypted.
    Nobody,
    /// The VPN's server, and the way from it — as any site's way out.
    Server,
    /// A stranger, in clear.
    Stranger,
}

impl Sees {
    pub fn word(self) -> &'static str {
        match self {
            Self::Machine => "machine",
            Self::Nobody => "nobody",
            Self::Server => "server",
            Self::Stranger => "stranger",
        }
    }
}

/// A hop: from the place before to `to`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hop {
    pub to: String,
    pub what: String,
    pub wrap: String,
    pub sees: Sees,
    /// Who sees what of it, for a person.
    pub seen_by: String,
}

/// Where a row ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// At its destination.
    Arrives(String),
    /// Stopped by a gate.
    Denied(String),
    /// Answered on the way, and no further.
    Answered(String),
    /// Nothing goes past its last place.
    Cut(String),
    /// Out around the tunnel: what the zone's own routes say, against what
    /// it is meant to do.
    Leak(String),
}

impl End {
    pub fn word(&self) -> &'static str {
        match self {
            Self::Arrives(_) => "arrives",
            Self::Denied(_) => "denied",
            Self::Answered(_) => "answered",
            Self::Cut(_) => "cut",
            Self::Leak(_) => "leak",
        }
    }

    pub fn text(&self) -> &str {
        match self {
            Self::Arrives(t)
            | Self::Denied(t)
            | Self::Answered(t)
            | Self::Cut(t)
            | Self::Leak(t) => t,
        }
    }
}

/// What a row is of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Data,
    /// ICMP echo.
    Ping,
    Dns,
    Denied,
    /// With the gateway (ARP, neighbour discovery): answered by passt.
    Local,
    Handshake,
    /// The VPN's server's name, through the host's resolver.
    ServerName,
    /// The host's own programs, outside cellward.
    Host,
    /// An instance with no network.
    Offline,
    /// ARP with the gateway: answered by passt.
    Arp,
    /// Dropped by the instance's rules (`zone::INSTANCE_COUNTERS`) or its
    /// gate, never relayed: broadcast, multicast, a frame of no IP.
    Dropped,
    /// Come from outside, unasked.
    Inbound,
    /// The host's or a zone's own upkeep with its link: ARP, DHCP, ND.
    Service,
}

impl Kind {
    pub fn word(self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::Ping => "ping",
            Self::Dns => "dns",
            Self::Denied => "denied",
            Self::Local => "local",
            Self::Handshake => "handshake",
            Self::ServerName => "server-name",
            Self::Host => "host",
            Self::Offline => "offline",
            Self::Arp => "arp",
            Self::Dropped => "dropped",
            Self::Inbound => "inbound",
            Self::Service => "service",
        }
    }
}

/// A flow, or a program's flows of one kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub id: String,
    /// What it is under: an instance, a zone, the host.
    pub group: String,
    pub name: String,
    pub kind: Kind,
    /// Its first place.
    pub from: String,
    pub hops: Vec<Hop>,
    pub end: End,
    /// The connections it stands for — or, a counter's, its packets.
    pub count: usize,
    pub out_bytes: u64,
    pub in_bytes: u64,
    /// Seen — a flow the relay noted, a counter of the rules —; else what
    /// the design says happens, drawn as such.
    pub observed: bool,
}

/// The scheme.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Scheme {
    pub places: Vec<Place>,
    pub rows: Vec<Row>,
    /// Each group's title, in order.
    pub groups: Vec<(String, String)>,
}

impl Scheme {
    fn place(&mut self, id: &str, layer: Layer, name: &str, tech: &str) -> String {
        if !self.places.iter().any(|p| p.id == id) {
            self.places.push(Place {
                id: id.to_owned(),
                layer,
                name: name.to_owned(),
                tech: tech.to_owned(),
                gate: false,
                unknown: false,
            });
        }
        id.to_owned()
    }

    fn gate(&mut self, id: &str, layer: Layer, name: &str, tech: &str) -> String {
        let id = self.place(id, layer, name, tech);
        if let Some(p) = self.places.iter_mut().find(|p| p.id == id) {
            p.gate = true;
        }
        id
    }

    fn group(&mut self, id: &str, title: String) {
        if !self.groups.iter().any(|(g, _)| g == id) {
            self.groups.push((id.to_owned(), title));
        }
    }
}

fn hop(to: &str, what: &str, wrap: &str, sees: Sees, seen_by: &str) -> Hop {
    Hop {
        to: to.to_owned(),
        what: what.to_owned(),
        wrap: wrap.to_owned(),
        sees,
        seen_by: seen_by.to_owned(),
    }
}

/// An interface's kind, for a person.
fn iface_word(kind: &str) -> &'static str {
    match kind {
        "wifi" => "Wi-Fi",
        "ethernet" => "кабель",
        "loopback" => "петля",
        _ => "виртуальный",
    }
}

/// A tunnel's kind, for a person.
fn kind_word(kind: &str) -> &'static str {
    match kind {
        "amneziawg" => "AmneziaWG",
        "wireguard" => "WireGuard",
        "openconnect" => "OpenConnect",
        "host" => "сеть хоста",
        "system" => "системная зона",
        _ => "?",
    }
}

/// The host's way out by `route` — its interface and gateway: its places
/// (the interface, the gateway, what is past it) and the hops onto them, each
/// carrying `what` and read as `sees`.
fn host_way(
    s: &mut Scheme,
    facts: &Facts,
    (dev, via): (&str, Option<&str>),
    what: &str,
    sees: Sees,
    lan_sees: &str,
    isp_sees: &str,
) -> Vec<Hop> {
    let iface = facts.ifaces.iter().find(|i| i.name == dev);
    let kind = iface.map_or("virtual", |i| i.kind);
    let tech = match iface.and_then(|i| i.addrs.first()) {
        Some(a) => format!("{} · {}", iface_word(kind), a),
        None => iface_word(kind).to_owned(),
    };
    let ifc = s.place(&format!("if:{dev}"), Layer::Host, dev, &tech);
    let frame = if kind == "wifi" {
        "кадр Wi-Fi (802.11)"
    } else {
        "кадр Ethernet"
    };
    // No gateway: what it goes to is on the link itself — nothing between.
    let Some(via) = via else {
        let lan = s.place(
            &format!("link:{dev}"),
            Layer::Outside,
            "Локальная сеть",
            "без шлюза: адресат в ней",
        );
        return vec![
            hop(&ifc, what, "IP-пакет хоста", Sees::Machine, "только машина"),
            hop(&lan, what, frame, sees, lan_sees),
        ];
    };
    // The gateway is what the host knows: the next hop of its route. A
    // router, a provider's box, a phone sharing its network — not known.
    let lan = s.place(&format!("lan:{dev}"), Layer::Outside, "Шлюз", via);
    let isp = s.place(
        &format!("isp:{dev}"),
        Layer::Outside,
        "⋯ дальше не известно ⋯",
        "сети за шлюзом",
    );
    if let Some(p) = s.places.iter_mut().find(|p| p.id == isp) {
        p.unknown = true;
    }
    vec![
        hop(&ifc, what, "IP-пакет хоста", Sees::Machine, "только машина"),
        hop(&lan, what, frame, sees, lan_sees),
        hop(&isp, what, "IP", sees, isp_sees),
    ]
}

/// The rows a zone carries for an instance's flows of one kind, from the
/// zone's way in (`passt`) on: its places and hops to its server, and how
/// it ends there — or before.
struct Way {
    hops: Vec<Hop>,
    /// The last place reached; its server, when the way gets there.
    server: Option<String>,
    cut: Option<String>,
}

/// A flow's way around the zone's tunnel, as the zone's app namespace
/// routes it ([`Inside`]): the internet's — or, `dns`, its resolver's — by
/// another interface than the tunnel. `None`: by the tunnel, or not looked
/// at. No route at all is no leak: nothing goes (the way says it cut).
fn leak_of(s: &mut Scheme, zone: &Zone, dns: bool, what: &str) -> Option<(Hop, End)> {
    let inside = zone.inside.as_ref()?;
    let dev = if dns {
        let addr = zone.dns.first()?.0;
        inside.dns.iter().find(|(a, _)| *a == addr)?.1.clone()?
    } else {
        inside.data.clone()?
    };
    if dev == crate::zone::TUN_IFACE {
        return None;
    }
    let z = &zone.name;
    let to = s.place(
        &format!("leak:{z}:{dev}"),
        Layer::Zone,
        "⚠ Мимо туннеля",
        &dev,
    );
    let h = hop(
        &to,
        what,
        "открытым текстом, мимо шифратора",
        Sees::Stranger,
        &format!("⚠ любой в сети за {dev}: маршрут зоны ведёт туда, а не в туннель"),
    );
    Some((
        h,
        End::Leak(format!(
            "утечка: маршрут зоны ведёт через {dev}, мимо туннеля"
        )),
    ))
}

fn zone_way(s: &mut Scheme, facts: &Facts, zone: &Zone, what: &str) -> Way {
    let z = &zone.name;
    let server = zone
        .servers
        .iter()
        .find(|v| v.addr.is_some())
        .or(zone.servers.first());
    let mut hops = Vec::new();
    match zone.kind {
        "host" => {
            // No tunnel: the zone's sockets are the host's network's.
            let out = s.place(
                &format!("out:{z}"),
                Layer::Uplink,
                "Выход зоны",
                "pasta, без шифрования",
            );
            hops.push(hop(
                &out,
                what,
                "соединение зоны",
                Sees::Machine,
                "только машина",
            ));
            if !zone.up {
                return Way {
                    hops,
                    server: None,
                    cut: Some("зона опущена — наружу не уходит".into()),
                };
            }
            let Some((dev, via)) = facts.default.clone() else {
                return Way {
                    hops,
                    server: None,
                    cut: Some("у хоста нет маршрута наружу".into()),
                };
            };
            hops.extend(host_way(
                s,
                facts,
                (&dev, via.as_deref()),
                what,
                Sees::Stranger,
                "⚠ локальная сеть и шлюз: куда и что, если не TLS",
                "⚠ сети за шлюзом: куда и что, если не TLS",
            ));
            return Way {
                hops,
                server: None,
                cut: None,
            };
        }
        "system" => {
            let tun = s.gate(
                &format!("tun:{z}"),
                Layer::Zone,
                "Шифратор",
                "туннель системной зоны",
            );
            hops.push(hop(
                &tun,
                what,
                "IP-пакет зоны",
                Sees::Machine,
                "только машина",
            ));
            if !zone.up {
                return Way {
                    hops,
                    server: None,
                    cut: Some("зона опущена — наружу не уходит".into()),
                };
            }
            let vpn = s.place(
                &format!("vpn:{z}"),
                Layer::Outside,
                "Сервер системной зоны",
                "его настраивает root",
            );
            hops.push(hop(
                &vpn,
                what,
                "туннель системной зоны",
                Sees::Nobody,
                "что по пути — как у любого туннеля",
            ));
            return Way {
                hops,
                server: Some(vpn),
                cut: None,
            };
        }
        _ => {}
    }
    let tech = match zone.kind {
        "openconnect" => "tun · OpenConnect".to_owned(),
        k => format!("awg0 · {}", kind_word(k)),
    };
    let tun = s.gate(&format!("tun:{z}"), Layer::Zone, "Шифратор", &tech);
    hops.push(hop(
        &tun,
        what,
        "IP-пакет зоны",
        Sees::Machine,
        "только машина",
    ));
    if !zone.up {
        return Way {
            hops,
            server: None,
            cut: Some("зона опущена — наружу не уходит".into()),
        };
    }
    let (wrap, port_text) = match zone.kind {
        "openconnect" => ("зашифровано: TLS/DTLS к шлюзу", "к шлюзу"),
        _ => ("зашифровано: UDP к серверу", "к серверу"),
    };
    let out = s.gate(
        &format!("out:{z}"),
        Layer::Uplink,
        "Выход зоны",
        "сокет туннеля + pasta",
    );
    hops.push(hop(&out, what, wrap, Sees::Nobody, "никто"));
    let Some(server) = server else {
        return Way {
            hops,
            server: None,
            cut: Some("у зоны нет сервера".into()),
        };
    };
    let Some(addr) = server.addr else {
        return Way {
            hops,
            server: None,
            cut: Some(format!("адрес {} ещё не известен", server.raw)),
        };
    };
    let Some(dev) = server.dev.clone() else {
        return Way {
            hops,
            server: None,
            cut: Some(format!("у хоста нет маршрута к {addr}")),
        };
    };
    let carried = format!("{what} — внутри туннеля");
    let mut way = host_way(
        s,
        facts,
        (&dev, server.via.as_deref()),
        &carried,
        Sees::Nobody,
        &format!("локальная сеть и шлюз: что есть поток {port_text} {addr}, размер, время"),
        &format!("сети за шлюзом: что есть поток {port_text} {addr}, размер, время"),
    );
    // The way out's first hop is the zone's socket in the host's: by uid
    // of the zone, the host's routes choosing the interface.
    if let Some(first) = way.first_mut() {
        first.wrap = "UDP-сокет хоста от имени зоны".into();
        first.sees = Sees::Nobody;
        first.seen_by = "никто".into();
    }
    hops.extend(way);
    let vpn = s.place(
        &format!("vpn:{z}"),
        Layer::Outside,
        &format!("Сервер VPN {z}"),
        &addr.to_string(),
    );
    hops.push(hop(
        &vpn,
        &carried,
        wrap,
        Sees::Nobody,
        "сети до сервера: то же",
    ));
    Way {
        hops,
        server: Some(vpn),
        cut: None,
    }
}

/// What a flow of an instance's is, for its row.
fn kind_of(f: &Flow) -> Kind {
    let key = crate::flows::Key {
        proto: f.proto,
        lport: f.lport,
        remote: f.remote,
        rport: f.rport,
    };
    if f.proto == crate::flows::NOT_IP {
        return if f.rport == crate::flows::ETHER_ARP {
            Kind::Arp
        } else {
            Kind::Dropped
        };
    }
    if f.proto == ICMP6 && f.lport == 0 && [133, 135, 136].contains(&f.rport) {
        return Kind::Local;
    }
    // Not the gate's, and nothing sent: what came in to the instance's
    // kernel — an ICMP error from passt, an unreachable resolver's —, no
    // program's and nothing denied.
    if !crate::relay::gated(&key) && f.out_bytes == 0 {
        return Kind::Local;
    }
    // Not the gate's to pass: dropped by it — another protocol, an ICMP
    // message of no ping, a fragment.
    if !crate::relay::gated(&key) {
        return Kind::Dropped;
    }
    if f.verdict == Some(crate::verdicts::Verdict::Deny) {
        return Kind::Denied;
    }
    if crate::relay::to_forwarder(&key) {
        return Kind::Dns;
    }
    if f.proto == crate::flows::ICMP || f.proto == ICMP6 {
        return Kind::Ping;
    }
    Kind::Data
}

/// The destinations most used of `flows`, for a person.
fn destinations(flows: &[&Flow]) -> String {
    let mut by: HashMap<String, u64> = HashMap::new();
    for f in flows {
        let name = f.name.clone().unwrap_or_else(|| match (f.remote, f.proto) {
            (IpAddr::V6(a), TCP | UDP) => format!("[{a}]:{}", f.rport),
            (a, TCP | UDP) => format!("{a}:{}", f.rport),
            (a, _) => a.to_string(),
        });
        *by.entry(name).or_default() += f.out_bytes + f.in_bytes;
    }
    let mut list: Vec<(String, u64)> = by.into_iter().collect();
    list.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let shown: Vec<&str> = list.iter().take(3).map(|(n, _)| n.as_str()).collect();
    match list.len() {
        0 => String::new(),
        n if n <= 3 => shown.join(", "),
        n => format!("{} и ещё {}", shown.join(", "), n - 3),
    }
}

/// The scheme of `facts`.
pub fn build(facts: &Facts) -> Scheme {
    let mut s = Scheme::default();
    for inst in &facts.instances {
        let group = format!("instance:{}", inst.id);
        let title = match (&inst.container, crate::instance::who_of(&inst.id)) {
            (Some(c), _) => format!("Контейнер {c} · сеть {}", inst.network),
            (None, crate::origin::Who::Main) => format!("Настоящий дом · сеть {}", inst.network),
            (None, _) => format!("Одноразовый {} · сеть {}", inst.id, inst.network),
        };
        s.group(&group, title);
        let zone = facts.zones.iter().find(|z| z.name == inst.network);
        if zone.is_none() {
            let from = s.place(
                &format!("prog:{}:*", inst.id),
                Layer::Program,
                "Программы",
                "контейнера",
            );
            let (text, kind) = if inst.network == crate::launch::OFFLINE {
                ("без сети: у контейнера только lo", Kind::Offline)
            } else {
                ("не контейнер: как программа хоста", Kind::Host)
            };
            s.rows.push(Row {
                id: format!("{}:offline", inst.id),
                group: group.clone(),
                name: "Программы".into(),
                kind,
                from,
                hops: Vec::new(),
                end: End::Cut(text.into()),
                count: 0,
                out_bytes: 0,
                in_bytes: 0,
                observed: true,
            });
            continue;
        }
        let zone = zone.expect("found");
        let tap = s.place(
            &format!("tap:{}", inst.id),
            Layer::Container,
            "Сеть контейнера",
            "tap · 10.254.0.0/16",
        );
        let relay = s.gate(
            &format!("relay:{}", inst.id),
            Layer::Container,
            "Привратник",
            "пересылка: правила, счётчики",
        );
        let passt = s.place(
            &format!("passt:{}", inst.id),
            Layer::Zone,
            "Вход в зону",
            "passt",
        );
        // A program's flows, by kind: one row each.
        let mut by: Vec<((String, Kind), Vec<&Flow>)> = Vec::new();
        for f in &inst.flows {
            let kind = kind_of(f);
            // ARP and neighbour discovery are the instance's kernel's own:
            // no socket, no program — said as what they are.
            let who = match (kind, &f.program) {
                (Kind::Local | Kind::Arp, _) => "ядро контейнера".to_owned(),
                (Kind::Dropped, None) if f.proto == crate::flows::NOT_IP => {
                    "кадры не IP".to_owned()
                }
                (_, Some(p)) => p.clone(),
                (_, None) => "неизвестная программа".to_owned(),
            };
            let k = (who, kind);
            match by.iter_mut().find(|(key, _)| *key == k) {
                Some((_, list)) => list.push(f),
                None => by.push((k, vec![f])),
            }
        }
        for ((who, kind), flows) in by {
            let from = s.place(
                &format!("prog:{}:{who}", inst.id),
                Layer::Program,
                &who,
                "программа",
            );
            let what = match kind {
                Kind::Dns => "DNS-запрос к 10.254.255.253",
                Kind::Local => "служебное ядра: соседи IPv6, ICMP",
                Kind::Arp => "ARP: «у кого адрес шлюза?»",
                Kind::Dropped => "то, что привратник не пропускает",
                Kind::Ping => "ping",
                _ => "соединение программы",
            };
            let mut hops = vec![
                hop(&tap, what, "IP-пакет", Sees::Machine, "только контейнер"),
                hop(
                    &relay,
                    what,
                    "пакет в кадре Ethernet",
                    Sees::Machine,
                    "только контейнер",
                ),
            ];
            let end = match kind {
                Kind::Denied => End::Denied("привратник: запрещено правилом контейнера".into()),
                Kind::Dropped => End::Denied(
                    "привратник отбрасывает: не TCP, не UDP, не ping, фрагмент или не IP".into(),
                ),
                Kind::Arp => {
                    hops.push(hop(
                        &passt,
                        what,
                        "кадр по unix-сокету (не сеть)",
                        Sees::Machine,
                        "только машина",
                    ));
                    End::Answered("отвечает вход в зону — он и есть шлюз; дальше не идёт".into())
                }
                Kind::Local => {
                    hops.push(hop(
                        &passt,
                        what,
                        "кадр по unix-сокету (не сеть)",
                        Sees::Machine,
                        "только машина",
                    ));
                    End::Answered("отвечает вход в зону; дальше не идёт".into())
                }
                _ => {
                    hops.push(hop(
                        &passt,
                        what,
                        "кадр по unix-сокету (не сеть)",
                        Sees::Machine,
                        "только машина",
                    ));
                    // Where the zone's own routes take it, first: a way
                    // around its tunnel is a leak, whatever it is meant to do.
                    let leak = leak_of(&mut s, zone, kind == Kind::Dns, what);
                    let way = match leak {
                        Some(_) => Way {
                            hops: Vec::new(),
                            server: None,
                            cut: None,
                        },
                        None => zone_way(&mut s, facts, zone, what),
                    };
                    hops.extend(way.hops);
                    match (leak, way.cut, way.server, kind) {
                        (Some((h, end)), ..) => {
                            hops.push(h);
                            end
                        }
                        (None, Some(cut), _, _) => End::Cut(cut),
                        (None, None, server, Kind::Dns) => {
                            dns_end(&mut s, facts, zone, server.as_deref(), &mut hops)
                        }
                        (None, None, Some(_), _) => {
                            let dest = destinations(&flows);
                            let to = s.place(
                                &format!("dst:{}:{who}", inst.id),
                                Layer::Outside,
                                "Куда",
                                &dest,
                            );
                            hops.push(hop(
                                &to,
                                "соединение программы",
                                "IP от адреса сервера",
                                Sees::Server,
                                "сервер VPN: куда; сайт — адрес сервера, не твой",
                            ));
                            End::Arrives(dest)
                        }
                        // A host zone: no server; the destination is the internet itself.
                        (None, None, None, _) => End::Arrives(destinations(&flows)),
                    }
                }
            };
            s.rows.push(Row {
                id: format!("{}:{who}:{}", inst.id, kind.word()),
                group: group.clone(),
                name: who.clone(),
                kind,
                from,
                hops,
                end,
                count: flows.len(),
                out_bytes: flows.iter().map(|f| f.out_bytes).sum(),
                in_bytes: flows.iter().map(|f| f.in_bytes).sum(),
                observed: true,
            });
        }
        // What the instance's rules dropped, by why — counted, never
        // relayed (`zone::INSTANCE_COUNTERS`).
        let wall = s.gate(
            &format!("wall:{}", inst.id),
            Layer::Container,
            "Стена контейнера",
            "nft: что не уходит",
        );
        let senders = s.place(
            &format!("prog:{}:*", inst.id),
            Layer::Program,
            "программы и ядро",
            "контейнера",
        );
        for (name, packets) in &inst.counters {
            let (title, why) = match name.as_str() {
                "bcast4" => ("broadcast IPv4", "широковещательные — в туннель не уходят"),
                "mcast4" => ("multicast IPv4: mDNS, SSDP…", "групповые — не уходят"),
                "mcast6" => ("multicast IPv6", "групповые — не уходят"),
                "denied" => ("запрещённые программы", "ядро отклоняет их отправку"),
                "rest" => (
                    "прочее",
                    "не с адреса контейнера или не в туннель — отброшено",
                ),
                _ => continue,
            };
            s.rows.push(Row {
                id: format!("{}:wall:{name}", inst.id),
                group: group.clone(),
                name: title.into(),
                kind: Kind::Dropped,
                from: senders.clone(),
                hops: vec![hop(
                    &wall,
                    title,
                    "IP-пакет",
                    Sees::Machine,
                    "только контейнер",
                )],
                end: End::Denied(format!("стена контейнера: {why} — {packets} пакет(ов)")),
                count: usize::try_from(*packets).unwrap_or(usize::MAX),
                out_bytes: 0,
                in_bytes: 0,
                observed: true,
            });
        }
        // What is not there by design, said: no DHCP.
        s.rows.push(Row {
            id: format!("{}:dhcp", inst.id),
            group: group.clone(),
            name: "DHCP".into(),
            kind: Kind::Service,
            from: senders.clone(),
            hops: vec![hop(&tap, "DHCP", "—", Sees::Machine, "только контейнер")],
            end: End::Cut("DHCP нет: адрес и маршрут ставит пересылка".into()),
            count: 0,
            out_bytes: 0,
            in_bytes: 0,
            observed: false,
        });
    }
    // The zones' own rows: the tunnel's handshake, the server's name.
    for zone in &facts.zones {
        if !matches!(zone.kind, "amneziawg" | "wireguard" | "openconnect") {
            continue;
        }
        let group = format!("zone:{}", zone.name);
        s.group(
            &group,
            format!("Зона {} · {}", zone.name, kind_word(zone.kind)),
        );
        let way = zone_way(&mut s, facts, zone, "рукопожатие и keepalive");
        // From its way out on: the tunnel's own packets are born there.
        let at = way.hops.iter().position(|h| h.to.starts_with("out:"));
        if let (Some(at), None) = (at, &way.cut) {
            let from = way.hops[at].to.clone();
            s.rows.push(Row {
                id: format!("{}:handshake", zone.name),
                group: group.clone(),
                name: "Туннель держит связь".into(),
                kind: Kind::Handshake,
                from,
                hops: way.hops[at + 1..].to_vec(),
                end: End::Arrives("сервер VPN".into()),
                count: 0,
                out_bytes: 0,
                in_bytes: 0,
                observed: true,
            });
        }
        // By design: the way out's own upkeep with pasta, and what comes in
        // unasked through the tunnel.
        let out = s.place(
            &format!("out:{}", zone.name),
            Layer::Uplink,
            "Выход зоны",
            "сокет туннеля + pasta",
        );
        s.rows.push(Row {
            id: format!("{}:uplink-nd", zone.name),
            group: group.clone(),
            name: "ND/ARP выхода с pasta".into(),
            kind: Kind::Service,
            from: out.clone(),
            hops: Vec::new(),
            end: End::Answered("отвечает pasta сама; дальше не идёт".into()),
            count: 0,
            out_bytes: 0,
            in_bytes: 0,
            observed: false,
        });
        if zone.up {
            let vpn = format!("vpn:{}", zone.name);
            let tun = format!("tun:{}", zone.name);
            if s.places.iter().any(|p| p.id == vpn) {
                s.rows.push(Row {
                    id: format!("{}:inbound", zone.name),
                    group: group.clone(),
                    name: "Входящее из интернета".into(),
                    kind: Kind::Inbound,
                    from: vpn,
                    hops: vec![
                        hop(
                            &out,
                            "подключение к программе",
                            "внутри туннеля",
                            Sees::Nobody,
                            "никто",
                        ),
                        hop(
                            &tun,
                            "то же",
                            "IP-пакет зоны",
                            Sees::Machine,
                            "только машина",
                        ),
                    ],
                    end: End::Denied(
                        "вход в зону не пробрасывает портов — ни до одной программы".into(),
                    ),
                    count: 0,
                    out_bytes: 0,
                    in_bytes: 0,
                    observed: false,
                });
            }
        }
        for server in zone.servers.iter().filter(|v| v.named) {
            let from = s.place("hostdns", Layer::Host, "DNS хоста", "как его настроил хост");
            let route = facts.default.clone();
            let mut hops = Vec::new();
            if let Some((dev, via)) = route {
                let name = server
                    .raw
                    .rsplit_once(':')
                    .map_or(server.raw.as_str(), |(h, _)| h);
                hops = host_way(
                    &mut s,
                    facts,
                    (&dev, via.as_deref()),
                    &format!("«{name}?»"),
                    Sees::Stranger,
                    "⚠ локальная сеть и шлюз: имя сервера VPN",
                    "⚠ сети за шлюзом и резолвер хоста: какой VPN и когда",
                );
            }
            let end = if server.addr.is_some() {
                End::Answered("один раз: адрес запомнен, дальше не спрашивается".into())
            } else {
                End::Answered("при подъёме зоны".into())
            };
            s.rows.push(Row {
                id: format!("{}:name:{}", zone.name, server.raw),
                group: group.clone(),
                name: format!("Имя сервера {}", server.raw),
                kind: Kind::ServerName,
                from,
                hops,
                end,
                count: 0,
                out_bytes: 0,
                in_bytes: 0,
                observed: true,
            });
        }
    }
    // The host's own programs: around every zone.
    if let Some((dev, via)) = facts.default.clone() {
        s.group("host", "Сам хост".into());
        let from = s.place("hostapps", Layer::Host, "Программы хоста", "вне cellward");
        let hops = host_way(
            &mut s,
            facts,
            (&dev, via.as_deref()),
            "их трафик, DHCP, ARP, mDNS",
            Sees::Stranger,
            "локальная сеть и шлюз",
            "сети за шлюзом — мимо VPN",
        );
        s.rows.push(Row {
            id: "host".into(),
            group: "host".into(),
            name: "Программы хоста".into(),
            kind: Kind::Host,
            from,
            hops,
            end: End::Arrives("интернет: видит твой адрес".into()),
            count: 0,
            out_bytes: 0,
            in_bytes: 0,
            observed: true,
        });
    }
    // By design, around every zone: the host's own talk with its link, and
    // what comes in from it unasked. Not seen without the system's observer.
    if let Some((dev, via)) = facts.default.clone() {
        let lan_id = if via.is_some() {
            format!("lan:{dev}")
        } else {
            format!("link:{dev}")
        };
        let ifc = format!("if:{dev}");
        if s.places.iter().any(|p| p.id == lan_id) {
            let service = |id: &str, name: &str, what: &str, end: End, from: &str, to: &str| Row {
                id: id.into(),
                group: "host".into(),
                name: name.into(),
                kind: Kind::Service,
                from: from.into(),
                hops: vec![hop(
                    to,
                    what,
                    "кадры локальной сети",
                    Sees::Stranger,
                    "локальная сеть и шлюз",
                )],
                end,
                count: 0,
                out_bytes: 0,
                in_bytes: 0,
                observed: false,
            };
            s.rows.push(service(
                "host:arp",
                "ARP, ND с соседями",
                "«у кого этот адрес?»",
                End::Answered("соседи знают MAC и адрес машины".into()),
                &ifc,
                &lan_id,
            ));
            s.rows.push(service(
                "host:dhcp",
                "DHCP, RA",
                "аренда адреса, маршрутизатор",
                End::Answered("шлюз выдаёт адрес и DNS хоста".into()),
                &ifc,
                &lan_id,
            ));
            s.rows.push(service(
                "host:mcast",
                "mDNS, SSDP, LLMNR, broadcast",
                "«кто тут есть?», имя машины",
                End::Arrives("слышат все в локальной сети".into()),
                &ifc,
                &lan_id,
            ));
            let mut inbound = service(
                "host:inbound",
                "Входящее из локальной сети",
                "подключение к машине",
                End::Denied("в контейнеры маршрута нет; хосту — по его фаерволу".into()),
                &lan_id,
                &ifc,
            );
            inbound.kind = Kind::Inbound;
            s.rows.push(inbound);
        }
    }
    // The host's interfaces no way uses: there, and said.
    for i in facts.ifaces.iter().filter(|i| i.kind != "loopback") {
        let tech = if i.up {
            format!("{} · не используется", iface_word(i.kind))
        } else {
            format!("{} · не подключён", iface_word(i.kind))
        };
        s.place(&format!("if:{}", i.name), Layer::Host, &i.name, &tech);
    }
    s
}

/// Where a zone's names end past its server: at a public resolver, in
/// clear; else answered on the VPN's side.
/// Whether `addr` is in a network of one of the host's interfaces
/// (`192.168.1.5/24` has 192.168.1.1).
fn on_hosts_link(facts: &Facts, addr: &IpAddr) -> Option<String> {
    let bits = |a: &IpAddr| -> u128 {
        match a {
            IpAddr::V4(v) => u128::from(u32::from(*v)) << 96,
            IpAddr::V6(v) => u128::from(*v),
        }
    };
    facts
        .ifaces
        .iter()
        .filter(|i| i.kind != "loopback")
        .find_map(|i| {
            i.addrs.iter().find_map(|cidr| {
                let (a, len) = cidr.split_once('/')?;
                let (a, len): (IpAddr, u32) = (a.parse().ok()?, len.parse().ok()?);
                let len = if a.is_ipv4() {
                    len.min(32)
                } else {
                    len.min(128)
                };
                if a.is_ipv4() != addr.is_ipv4() || len == 0 {
                    return None;
                }
                let shift = if a.is_ipv4() {
                    32 - len + 96
                } else {
                    128 - len
                };
                let mask = if shift >= 128 { 0 } else { u128::MAX << shift };
                (bits(&a) & mask == bits(addr) & mask).then(|| i.name.clone())
            })
        })
}

fn dns_end(
    s: &mut Scheme,
    facts: &Facts,
    zone: &Zone,
    server: Option<&str>,
    hops: &mut Vec<Hop>,
) -> End {
    if server.is_none() {
        return End::Arrives(crate::dnspath::words(&zone.dns));
    }
    match zone.dns.iter().find(|(_, side)| *side == Side::Public) {
        Some((addr, _)) => {
            let to = s.place(
                &format!("dns:{addr}"),
                Layer::Outside,
                "Резолвер",
                &addr.to_string(),
            );
            hops.push(hop(
                &to,
                "DNS-запрос",
                "⚠ UDP 53 открытым текстом",
                Sees::Stranger,
                &format!("⚠ сервер VPN, путь до {addr}, сам {addr}"),
            ));
            End::Arrives(format!("{addr}: имена открытым текстом"))
        }
        None if zone.dns.is_empty() => End::Answered("резолвер даёт сервер VPN".into()),
        None => {
            // An address of the person's own network: asked on the VPN's
            // side all the same — not their router, whatever it is called.
            if let Some((addr, dev)) = zone
                .dns
                .iter()
                .find_map(|(a, _)| on_hosts_link(facts, a).map(|d| (a, d)))
            {
                return End::Answered(format!(
                    "⚠ {addr} — адрес твоей сети ({dev}), но спросят его на стороне VPN, \
                     не твой роутер; не отвечают имена — причина здесь"
                ));
            }
            let all: Vec<String> = zone.dns.iter().map(|(a, _)| a.to_string()).collect();
            End::Answered(format!(
                "резолвер {} на стороне VPN: имена видит только она",
                all.join(", ")
            ))
        }
    }
}

// --- OUTPUT -----------------------------------------------------------------

/// The scheme as JSON.
pub fn json(s: &Scheme) -> String {
    use crate::status::string;
    let places: Vec<String> = s
        .places
        .iter()
        .map(|p| {
            format!(
                "{{\"id\":{},\"layer\":{},\"name\":{},\"tech\":{},\"gate\":{},\"unknown\":{}}}",
                string(&p.id),
                string(p.layer.word()),
                string(&p.name),
                string(&p.tech),
                p.gate,
                p.unknown
            )
        })
        .collect();
    let rows: Vec<String> = s
        .rows
        .iter()
        .map(|r| {
            let hops: Vec<String> = r
                .hops
                .iter()
                .map(|h| {
                    format!(
                        "{{\"to\":{},\"what\":{},\"wrap\":{},\"sees\":{},\"seen_by\":{}}}",
                        string(&h.to),
                        string(&h.what),
                        string(&h.wrap),
                        string(h.sees.word()),
                        string(&h.seen_by)
                    )
                })
                .collect();
            format!(
                "{{\"id\":{},\"group\":{},\"name\":{},\"kind\":{},\"from\":{},\"hops\":[{}],\
                 \"end\":{{\"kind\":{},\"text\":{}}},\"count\":{},\"out_bytes\":{},\"in_bytes\":{},\"observed\":{}}}",
                string(&r.id),
                string(&r.group),
                string(&r.name),
                string(r.kind.word()),
                string(&r.from),
                hops.join(","),
                string(r.end.word()),
                string(r.end.text()),
                r.count,
                r.out_bytes,
                r.in_bytes,
                r.observed
            )
        })
        .collect();
    let groups: Vec<String> = s
        .groups
        .iter()
        .map(|(id, title)| format!("{{\"id\":{},\"title\":{}}}", string(id), string(title)))
        .collect();
    format!(
        "{{\"places\":[{}],\"groups\":[{}],\"rows\":[{}]}}",
        places.join(","),
        groups.join(","),
        rows.join(",")
    )
}

/// The scheme as a person reads it in a terminal: each group, each row a
/// line of its places and how it ends.
pub fn text(s: &Scheme) -> String {
    let name = |id: &str| {
        s.places
            .iter()
            .find(|p| p.id == id)
            .map_or(id.to_owned(), |p| {
                let gate = if p.gate { " ⛨" } else { "" };
                if p.tech.is_empty() || p.layer == Layer::Program {
                    format!("{}{gate}", p.name)
                } else {
                    format!("{} ({}){gate}", p.name, p.tech)
                }
            })
    };
    let mark = |sees: Sees| match sees {
        Sees::Machine => "→",
        Sees::Nobody => "⇒",
        Sees::Server => "→",
        Sees::Stranger => "⚠→",
    };
    let mut out = String::new();
    for (group, title) in &s.groups {
        out.push_str(title);
        out.push('\n');
        for r in s.rows.iter().filter(|r| &r.group == group) {
            out.push_str("  ");
            out.push_str(&r.name);
            if r.count > 0 {
                out.push_str(&format!(
                    " — {}: {}, ↑ {} ↓ {}",
                    r.kind.word(),
                    r.count,
                    crate::traffic::bytes_text(r.out_bytes),
                    crate::traffic::bytes_text(r.in_bytes)
                ));
            }
            out.push_str("\n    ");
            out.push_str(&name(&r.from));
            for h in &r.hops {
                out.push_str(&format!(" {} {}", mark(h.sees), name(&h.to)));
            }
            // Arrived where its last place says: nothing to add.
            let at_place = r.hops.last().is_some_and(|h| h.to.starts_with("dst:"));
            match r.end {
                End::Arrives(_) if at_place => out.push_str(" ✓\n"),
                End::Arrives(_) => out.push_str(&format!(" → {}\n", r.end.text())),
                End::Denied(_) | End::Cut(_) => out.push_str(&format!(" ✕ {}\n", r.end.text())),
                End::Answered(_) => out.push_str(&format!(" ↩ {}\n", r.end.text())),
                End::Leak(_) => out.push_str(&format!(" ⚠ {}\n", r.end.text())),
            }
        }
    }
    out.push_str(
        "\n→ внутри машины или от сервера VPN, ⇒ зашифровано, ⚠→ видит посторонний; ⛨ заслон\n",
    );
    out
}

/// Whether `facts` are an instance's own: its way out the gateway every
/// instance has (`crate::bridge::G4`), no zone in sight.
fn inside_instance(facts: &Facts) -> bool {
    let gateway = crate::bridge::G4.to_string();
    facts.zones.is_empty()
        && facts
            .default
            .as_ref()
            .is_some_and(|(_, via)| via.as_deref() == Some(gateway.as_str()))
}

/// `cellward scheme [--json]`.
pub fn run(tools: &Tools, args: &[std::ffi::OsString]) -> u8 {
    let as_json = match args
        .iter()
        .map(|a| a.to_str())
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => false,
        [Some("--json")] => true,
        _ => {
            eprintln!("cellward scheme [--json]");
            return 2;
        }
    };
    let facts = facts(tools);
    // Run in a container, its "host" is the container's own network: what
    // it would draw is not the machine's.
    if inside_instance(&facts) {
        eprintln!(
            "это контейнер cellward: его сеть — только туннель зоны, а зоны и сеть хоста \
             отсюда не видны; схема — с хоста"
        );
        return 1;
    }
    let s = build(&facts);
    if as_json {
        println!("{}", json(&s));
    } else {
        print!("{}", text(&s));
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdicts::Verdict;

    fn wifi() -> crate::netmap::Iface {
        crate::netmap::Iface {
            name: "wlp2s0".into(),
            kind: "wifi",
            up: true,
            addrs: vec!["192.168.1.5/24".into()],
        }
    }

    fn zone(kind: &'static str, dns: &str, named: bool) -> Zone {
        let addr: IpAddr = "203.0.113.5".parse().unwrap();
        Zone {
            name: "nl".into(),
            up: true,
            kind,
            servers: vec![Server {
                raw: if named {
                    "vpn.example.org:51820".into()
                } else {
                    "203.0.113.5:51820".into()
                },
                addr: Some(addr),
                named,
                dev: Some("wlp2s0".into()),
                via: Some("192.168.1.1".into()),
            }],
            dns: vec![{
                let a: IpAddr = dns.parse().unwrap();
                (a, crate::dnspath::side_of(a))
            }],
            inside: None,
        }
    }

    fn flow(proto: u8, remote: &str, rport: u16, program: &str, verdict: Option<Verdict>) -> Flow {
        Flow {
            proto,
            lport: 40000,
            remote: remote.parse().unwrap(),
            rport,
            name: None,
            program: Some(program.into()),
            out_bytes: 100,
            in_bytes: 200,
            verdict,
        }
    }

    fn facts(zone: Zone, flows: Vec<Flow>) -> Facts {
        Facts {
            zones: vec![zone],
            ifaces: vec![
                wifi(),
                crate::netmap::Iface {
                    name: "eth0".into(),
                    kind: "ethernet",
                    up: false,
                    addrs: vec![],
                },
            ],
            instances: vec![Instance {
                id: "work-1".into(),
                container: Some("work".into()),
                network: "nl".into(),
                flows,
                counters: vec![("bcast4".into(), 3), ("mcast6".into(), 0)],
            }],
            default: Some(("wlp2s0".into(), Some("192.168.1.1".into()))),
        }
    }

    fn row<'a>(s: &'a Scheme, id: &str) -> &'a Row {
        s.rows
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("no row {id}: {:#?}", s.rows))
    }

    /// A program's connections go through its container, its zone's tunnel
    /// and the host's Wi-Fi to the server, encrypted from the tunnel on, and
    /// past the server as the server's; one row for all of them.
    #[test]
    fn a_programs_connections_are_one_row_through_the_tunnel() {
        let ok = Some(Verdict::Allow);
        let s = build(&facts(
            zone("amneziawg", "10.8.1.1", false),
            vec![
                flow(TCP, "198.51.100.1", 443, "Firefox", ok),
                flow(UDP, "198.51.100.2", 443, "Firefox", ok),
            ],
        ));
        let r = row(&s, "work-1:Firefox:data");
        assert_eq!(r.count, 2);
        let to: Vec<&str> = r.hops.iter().map(|h| h.to.as_str()).collect();
        assert_eq!(
            to,
            [
                "tap:work-1",
                "relay:work-1",
                "passt:work-1",
                "tun:nl",
                "out:nl",
                "if:wlp2s0",
                "lan:wlp2s0",
                "isp:wlp2s0",
                "vpn:nl",
                "dst:work-1:Firefox"
            ]
        );
        let sees: Vec<Sees> = r.hops.iter().map(|h| h.sees).collect();
        assert_eq!(&sees[..4], [Sees::Machine; 4]);
        assert!(sees[4..9].iter().all(|s| *s == Sees::Nobody), "{sees:?}");
        assert_eq!(sees[9], Sees::Server);
        assert!(matches!(r.end, End::Arrives(_)));
        assert!(s.places.iter().any(|p| p.id == "isp:wlp2s0" && p.unknown));
        assert!(s.places.iter().any(|p| p.id == "relay:work-1" && p.gate));
        // The cable not plugged in is there, and says so.
        assert!(s
            .places
            .iter()
            .any(|p| p.id == "if:eth0" && p.tech.contains("не подключён")));
    }

    /// A server on the host's own link, no gateway: nothing between.
    #[test]
    fn a_server_on_the_link_has_nothing_between() {
        let mut z = zone("wireguard", "10.8.1.1", false);
        z.servers[0].via = None;
        let s = build(&facts(z, vec![]));
        let to: Vec<&str> = row(&s, "nl:handshake")
            .hops
            .iter()
            .map(|h| h.to.as_str())
            .collect();
        assert_eq!(to, ["if:wlp2s0", "link:wlp2s0", "vpn:nl"]);
        assert!(s
            .places
            .iter()
            .any(|p| p.id == "link:wlp2s0" && p.name == "Локальная сеть"));
    }

    /// A denied program ends at the gate; so does what the gate drops.
    #[test]
    fn what_the_gate_denies_ends_there() {
        let s = build(&facts(
            zone("wireguard", "10.8.1.1", false),
            vec![
                flow(TCP, "198.51.100.1", 443, "Терминал", Some(Verdict::Deny)),
                flow(132, "198.51.100.1", 0, "Терминал", None),
            ],
        ));
        // Denied by its rule; dropped by the gate (another protocol): each
        // its row, both at the gate.
        for id in ["work-1:Терминал:denied", "work-1:Терминал:dropped"] {
            let r = row(&s, id);
            assert_eq!(r.count, 1, "{id}");
            assert_eq!(r.hops.last().unwrap().to, "relay:work-1");
            assert!(matches!(r.end, End::Denied(_)));
        }
    }

    /// Names asked of a public resolver: past the server, in clear — a
    /// stranger's to read; of the VPN's own, answered at the server.
    #[test]
    fn names_end_by_their_resolvers_side() {
        let dns = || {
            vec![flow(
                UDP,
                "10.254.255.253",
                53,
                "Firefox",
                Some(Verdict::Allow),
            )]
        };
        let public = build(&facts(zone("amneziawg", "1.1.1.1", false), dns()));
        let r = row(&public, "work-1:Firefox:dns");
        let last = r.hops.last().unwrap();
        assert_eq!(
            (last.to.as_str(), last.sees),
            ("dns:1.1.1.1", Sees::Stranger)
        );
        let own = build(&facts(zone("amneziawg", "10.8.1.1", false), dns()));
        let r = row(&own, "work-1:Firefox:dns");
        assert_eq!(r.hops.last().unwrap().to, "vpn:nl");
        assert!(
            matches!(&r.end, End::Answered(t) if t.contains("10.8.1.1")),
            "{:?}",
            r.end
        );
    }

    /// The zone's own routes taking a flow around its tunnel: a leak,
    /// shown as one — the data's and the names' each by their own route;
    /// through the tunnel, none.
    #[test]
    fn a_way_around_the_tunnel_is_a_leak() {
        let flows = || {
            vec![
                flow(TCP, "198.51.100.1", 443, "Firefox", Some(Verdict::Allow)),
                flow(UDP, "10.254.255.253", 53, "Firefox", Some(Verdict::Allow)),
            ]
        };
        let dns: IpAddr = "10.8.1.1".parse().unwrap();
        let mut z = zone("amneziawg", "10.8.1.1", false);
        z.inside = Some(Inside {
            data: Some("awg0".into()),
            dns: vec![(dns, Some("awg0".into()))],
        });
        let s = build(&facts(z.clone(), flows()));
        assert!(
            !s.rows.iter().any(|r| matches!(r.end, End::Leak(_))),
            "{:#?}",
            s.rows
        );
        z.inside = Some(Inside {
            data: Some("awg0".into()),
            dns: vec![(dns, Some("eth0".into()))],
        });
        let s = build(&facts(z.clone(), flows()));
        let r = row(&s, "work-1:Firefox:dns");
        assert!(
            matches!(&r.end, End::Leak(t) if t.contains("eth0")),
            "{:?}",
            r.end
        );
        let last = r.hops.last().unwrap();
        assert_eq!(
            (last.to.as_str(), last.sees),
            ("leak:nl:eth0", Sees::Stranger)
        );
        assert!(matches!(
            row(&s, "work-1:Firefox:data").end,
            End::Arrives(_)
        ));
        z.inside = Some(Inside {
            data: Some("wlp2s0".into()),
            dns: vec![(dns, Some("awg0".into()))],
        });
        let s = build(&facts(z, flows()));
        assert!(matches!(row(&s, "work-1:Firefox:data").end, End::Leak(_)));
        assert!(text(&s).contains("⚠ утечка"));
    }

    /// A resolver at an address of the host's own network: said as such.
    #[test]
    fn a_resolver_of_the_persons_own_network_is_said() {
        let s = build(&facts(
            zone("wireguard", "192.168.1.1", false),
            vec![flow(
                UDP,
                "10.254.255.253",
                53,
                "Firefox",
                Some(Verdict::Allow),
            )],
        ));
        let r = row(&s, "work-1:Firefox:dns");
        assert!(
            matches!(&r.end, End::Answered(t) if t.contains("wlp2s0") && t.contains("не твой роутер")),
            "{:?}",
            r.end
        );
        assert_eq!(
            on_hosts_link(
                &facts(zone("wireguard", "10.8.1.1", false), vec![]),
                &"10.8.1.1".parse().unwrap()
            ),
            None
        );
    }

    /// A zone that is down cuts its rows at its tunnel: nothing past it.
    #[test]
    fn a_zone_down_cuts_at_its_tunnel() {
        let mut z = zone("amneziawg", "10.8.1.1", false);
        z.up = false;
        let s = build(&facts(
            z,
            vec![flow(TCP, "198.51.100.1", 443, "Firefox", None)],
        ));
        let r = row(&s, "work-1:Firefox:data");
        assert_eq!(r.hops.last().unwrap().to, "tun:nl");
        assert!(matches!(r.end, End::Cut(_)));
        assert!(!s.rows.iter().any(|r| r.kind == Kind::Handshake));
    }

    /// A server by name: looked up through the host's resolver, in clear —
    /// once, its address kept.
    #[test]
    fn a_named_server_is_looked_up_by_the_host() {
        let s = build(&facts(zone("wireguard", "10.8.1.1", true), vec![]));
        let r = row(&s, "nl:name:vpn.example.org:51820");
        assert_eq!(r.from, "hostdns");
        assert!(r.hops.iter().skip(1).all(|h| h.sees == Sees::Stranger));
        assert!(r.hops[1].what.contains("vpn.example.org"));
        assert!(matches!(&r.end, End::Answered(t) if t.contains("запомнен")));
        let hs = row(&s, "nl:handshake");
        assert_eq!(hs.from, "out:nl");
        assert_eq!(hs.hops.last().unwrap().to, "vpn:nl");
    }

    /// A zone of the host's network has no tunnel: past its way out, what a
    /// program sends is a stranger's to read.
    #[test]
    fn a_host_network_zone_is_in_clear() {
        let s = build(&facts(
            zone("host", "192.168.1.1", false),
            vec![flow(
                TCP,
                "198.51.100.1",
                443,
                "Firefox",
                Some(Verdict::Allow),
            )],
        ));
        let r = row(&s, "work-1:Firefox:data");
        assert!(!r
            .hops
            .iter()
            .any(|h| h.to.starts_with("vpn:") || h.to.starts_with("tun:")));
        assert_eq!(r.hops.last().unwrap().sees, Sees::Stranger);
    }

    /// Every kind of packet has its row: ARP answered by passt, what the
    /// gate drops, the rules' counters with their packets, and what the
    /// design says — drawn as not seen.
    #[test]
    fn every_kind_of_packet_has_its_row() {
        let mut arp = flow(
            crate::flows::NOT_IP,
            "10.254.255.254",
            crate::flows::ETHER_ARP,
            "?",
            None,
        );
        (arp.lport, arp.program) = (0, None);
        let mut lldp = flow(crate::flows::NOT_IP, "0.0.0.0", 0x88cc, "?", None);
        (lldp.lport, lldp.program) = (0, None);
        let sctp = flow(132, "198.51.100.1", 0, "Firefox", None);
        let s = build(&facts(
            zone("amneziawg", "10.8.1.1", false),
            vec![arp, lldp, sctp],
        ));
        let a = row(&s, "work-1:ядро контейнера:arp");
        assert!(matches!(a.end, End::Answered(_)));
        assert_eq!(a.hops.last().unwrap().to, "passt:work-1");
        assert!(matches!(
            row(&s, "work-1:кадры не IP:dropped").end,
            End::Denied(_)
        ));
        assert!(matches!(
            row(&s, "work-1:Firefox:dropped").end,
            End::Denied(_)
        ));
        let b = row(&s, "work-1:wall:bcast4");
        assert_eq!((b.count, b.observed), (3, true));
        assert!(matches!(&b.end, End::Denied(t) if t.contains("3 пакет")));
        assert_eq!(b.hops[0].to, "wall:work-1");
        assert_eq!(row(&s, "work-1:wall:mcast6").count, 0);
        for id in [
            "work-1:dhcp",
            "nl:uplink-nd",
            "nl:inbound",
            "host:arp",
            "host:dhcp",
            "host:mcast",
            "host:inbound",
        ] {
            assert!(!row(&s, id).observed, "{id}");
        }
        assert!(json(&s).contains("\"observed\":false"));
    }

    /// `nft list counters`, read back.
    #[test]
    fn a_rulesets_counters_are_read() {
        let text = "table inet vpnzone {\n\tcounter bcast4 {\n\t\tpackets 7 bytes 420\n\t}\n\
                    \tcounter rest {\n\t\tpackets 0 bytes 0\n\t}\n}\n";
        assert_eq!(
            parse_counters(text),
            [("bcast4".to_owned(), 7), ("rest".to_owned(), 0)]
        );
        assert!(parse_counters("").is_empty());
    }

    /// Facts read in an instance are told from the machine's.
    #[test]
    fn an_instances_own_view_is_told() {
        let mut f = Facts {
            default: Some(("awg0".into(), Some("10.254.255.254".into()))),
            ..Facts::default()
        };
        assert!(inside_instance(&f));
        f.default = Some(("wlp2s0".into(), Some("192.168.1.1".into())));
        assert!(!inside_instance(&f));
    }

    /// The gateway's talk is answered by passt; the JSON and the text say
    /// every row.
    #[test]
    fn the_gateways_talk_is_answered_and_everything_is_written() {
        let mut rs = flow(ICMP6, "ff02::2", 133, "Firefox", None);
        rs.lport = 0;
        let s = build(&facts(
            zone("amneziawg", "1.1.1.1", true),
            vec![
                rs,
                flow(TCP, "198.51.100.1", 443, "Firefox", Some(Verdict::Allow)),
            ],
        ));
        let r = row(&s, "work-1:ядро контейнера:local");
        // An ICMP error that came in, nothing sent: the kernel's too.
        let mut err = flow(ICMP6, "fd63::1", 1, "?", None);
        (err.lport, err.out_bytes, err.program) = (0, 0, None);
        let e = build(&facts(zone("amneziawg", "1.1.1.1", false), vec![err]));
        assert_eq!(row(&e, "work-1:ядро контейнера:local").count, 1);
        assert_eq!(r.hops.last().unwrap().to, "passt:work-1");
        assert!(matches!(r.end, End::Answered(_)));
        let j = json(&s);
        for r in &s.rows {
            assert!(j.contains(&crate::status::string(&r.id)), "{}", r.id);
        }
        let t = text(&s);
        assert!(
            t.contains("Контейнер work · сеть nl") && t.contains("Сам хост"),
            "{t}"
        );
        assert!(t.contains("⚠→"), "{t}");
    }
}
