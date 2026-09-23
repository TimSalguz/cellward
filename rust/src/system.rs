//! System zones (ROADMAP M10, `docs/SYSTEM.md`): the same zone as a user one,
//! held by systemd from boot instead of by a session.
//!
//! ```text
//! vpn-zone-system-ns-<name>.service   vpn-zone-core system-zone ns-up <name>
//!   /run/netns/vz-<name>: lo, the app ruleset, an empty resolv.conf
//!
//! vpn-zone-system-<name>.service      vpn-zone-core system-zone up <name>
//!   the host's namespace: vz-<name> is CREATED here, its UDP socket stays here
//!                         └─ moves ↓ and is renamed awg0
//!   vz-<name>:            lo and awg0 and NOTHING ELSE, the routes into the
//!                         tunnel, the zone's resolv.conf
//! ```
//!
//! **The same zone, another holder.** A user zone needs two namespaces because
//! it has no network of its own to leave from: its uplink is a namespace behind
//! pasta. Root has one — the host's — so here the host's namespace IS the
//! uplink: the interface is created in it, keeps its encrypted socket in it,
//! and is moved into the zone. Inside, a system zone is indistinguishable from
//! a user zone's app namespace — `lo` and `awg0`, the same ruleset, the same
//! routes — which is what lets one leak model and one smoke assertion cover
//! both tiers (`docs/ARCHITECTURE.md` §3).
//!
//! **Why the namespace has a unit of its own.** Services and containers join
//! the namespace by its path. A namespace that came and went with the tunnel
//! would take every one of them down with it — and the tunnel unit is
//! restarted by every update of this package. So the namespace unit is never
//! restarted by a switch, and the tunnel can come and go inside it: without the
//! tunnel the namespace holds `lo` alone, which is the kill switch.
//!
//! **What is shared with user zones**, on purpose and by calling the same code:
//! the config parser, resolving endpoints in the host's network before
//! anything is configured, the amneziawg/wireguard choice, the IPv6 plan, the
//! resolv.conf text and the second-echelon ruleset.
//!
//! **What is not here yet.** OpenConnect and host-interface configs: they need
//! an uplink namespace of their own and are refused for now.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

use crate::config::{Family, WgConfig};
use crate::zone::{self, V6Plan};

/// Where the configs of system zones live when the module names no other file.
pub const STATE_DIR: &str = "/var/lib/vpn-zones/system";
/// The run directory of every system zone: `ready`, `status`, `setconf.conf`.
/// The module makes each one `2750 root:vpn-zones`, so the group reads the
/// status and new files inherit the group.
pub const RUN_DIR: &str = "/run/vpn-zones/system";
/// The declared zones, one name per line, written by the NixOS module. What
/// `vpn-zone status --json` lists.
pub const DECLARED: &str = "/etc/vpn-zones/system-zones";
/// Namespaces are `vz-<name>`: apart from anybody else's `ip netns add`.
pub const NETNS_PREFIX: &str = "vz-";
/// `vz-` + 12 = 15, the longest interface name the kernel takes — and the
/// interface is born in the host's namespace under that very name.
pub const NAME_MAX: usize = 12;

/// The mark a system zone's tunnel puts on its encrypted packets. Its UDP
/// socket is the kernel's own — no file, so no owner for the host egress
/// policy to recognise (`crate::egress`) — and the mark is what lets it out.
/// 0x767a is "vz"; a DPI bypass's marks sit in the high bits.
pub const TUNNEL_MARK: u32 = 0x767a;

/// Set by `vpn-zones-off`, removed by `vpn-zones-on`: vpn-zones are off, the
/// host has its own network, and no zone comes up — the module's units check
/// the same path.
pub const OFF_FLAG: &str = "/var/lib/vpn-zones/off";

/// Whether vpn-zones are off (`vpn-zones-off`).
pub fn is_off() -> bool {
    Path::new(OFF_FLAG).exists()
}

/// Names that already mean a built-in network.
const RESERVED: [&str; 3] = ["unconfined", "direct", "offline"];
const CONFIG: &str = "config.conf";
const SETCONF: &str = "setconf.conf";
const READY: &str = "ready";
const STATUS: &str = "status";
const STATUS_TMP: &str = "status.tmp";
/// The tunnel's name inside the zone — the one user zones use, so the app
/// ruleset applies unchanged.
const TUN: &str = zone::TUN_IFACE;

/// Is this a name a system zone may have?
pub fn check_name(name: &str) -> Result<(), String> {
    let first = name
        .as_bytes()
        .first()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let rest = name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !first || !rest || name.len() > NAME_MAX {
        return Err(format!(
            "a system zone is named by 1 to {NAME_MAX} of a-z, 0-9 and '-', not starting \
             with '-': {name:?}"
        ));
    }
    if RESERVED.contains(&name) {
        return Err(format!("{name} is a built-in network, not a zone"));
    }
    Ok(())
}

/// `vz-<name>`: the namespace, and the interface's name until it is inside.
pub fn netns(name: &str) -> String {
    format!("{NETNS_PREFIX}{name}")
}

/// `/run/netns/vz-<name>`: what services and containers are given.
pub fn netns_path(name: &str) -> PathBuf {
    Path::new("/run/netns").join(netns(name))
}

/// `/etc/netns/vz-<name>/resolv.conf`: what consumers bind over their own.
/// Under `/etc/netns` because that is where `ip netns exec` looks as well.
pub fn resolv_path(name: &str) -> PathBuf {
    Path::new("/etc/netns")
        .join(netns(name))
        .join("resolv.conf")
}

/// `/etc/netns/vz-<name>/nsswitch.conf`: the host's, with `hosts: files dns`
/// (`zone::zone_nsswitch`) — the class-wide insurance a user zone has too: no
/// NSS module but the plain resolver is ever asked for a name.
pub fn nsswitch_path(name: &str) -> PathBuf {
    Path::new("/etc/netns")
        .join(netns(name))
        .join("nsswitch.conf")
}

pub fn run_dir(name: &str) -> PathBuf {
    Path::new(RUN_DIR).join(name)
}

/// `-n vz-<name>` in front of an `ip` command line: the same command, run on
/// the zone's namespace.
pub fn in_zone_args(ns: &str, args: &[&str]) -> Vec<String> {
    let mut all = vec!["-n".to_owned(), ns.to_owned()];
    all.extend(args.iter().map(|a| (*a).to_owned()));
    all
}

/// Why this config can't be a system zone yet, if it can't.
pub fn refusal(cfg: &WgConfig) -> Option<&'static str> {
    if crate::openconnect::is_openconnect(cfg) {
        return Some(
            "an [OpenConnect] zone needs an uplink namespace of its own; system zones carry \
             WireGuard/AmneziaWG only for now",
        );
    }
    if crate::hostif::is_host_interface(cfg) {
        return Some(
            "a [HostInterface] zone needs an uplink namespace of its own; system zones carry \
             WireGuard/AmneziaWG only for now",
        );
    }
    if cfg.interface().is_none() {
        return Some("no [Interface] section — this is not a WireGuard/AmneziaWG config");
    }
    None
}

/// The text `setconf` gets, with the tunnel's mark as the interface's
/// `FwMark` — replacing any the config had: in a system zone the socket lives
/// in the host's namespace, and the host's policy has to know it.
pub fn with_tunnel_mark(setconf: &str) -> String {
    let mut out = String::new();
    let mut in_interface = false;
    for line in setconf.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_interface = trimmed.eq_ignore_ascii_case("[interface]");
            out.push_str(line);
            out.push('\n');
            if in_interface {
                out.push_str(&format!("FwMark = {TUNNEL_MARK:#x}\n"));
            }
            continue;
        }
        let is_mark = trimmed
            .split_once('=')
            .is_some_and(|(key, _)| key.trim().eq_ignore_ascii_case("fwmark"));
        if in_interface && is_mark {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// The declared zones: the module's list, with anything that isn't a valid
/// name dropped rather than trusted.
pub fn declared() -> Vec<String> {
    fs::read_to_string(DECLARED)
        .map(|text| parse_declared(&text))
        .unwrap_or_default()
}

pub fn parse_declared(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| check_name(line).is_ok())
        .map(str::to_owned)
        .collect()
}

/// What a reader without root can know about a system zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunState {
    /// The run directory is closed to the reader: not in the group `vpn-zones`.
    Closed,
    Down,
    /// Up, with the status mirror once the holder has written one.
    Up(Option<String>),
}

pub fn run_state(name: &str) -> RunState {
    let run = run_dir(name);
    match fs::read_dir(&run) {
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => RunState::Closed,
        Err(_) => RunState::Down,
        Ok(_) if run.join(READY).exists() => {
            RunState::Up(fs::read_to_string(run.join(STATUS)).ok())
        }
        Ok(_) => RunState::Down,
    }
}

/// Absolute paths of the tools; Nix puts them into the units' command lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tools {
    pub ip: PathBuf,
    pub awg: PathBuf,
    pub wg: PathBuf,
    pub nft: PathBuf,
    /// The way out of a plain zone.
    pub pasta: PathBuf,
}

impl Default for Tools {
    /// Bare names, i.e. "find them on `PATH`" — running a verb by hand.
    fn default() -> Self {
        Self {
            ip: PathBuf::from("ip"),
            awg: PathBuf::from("awg"),
            wg: PathBuf::from("wg"),
            nft: PathBuf::from("nft"),
            pasta: PathBuf::from("pasta"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// The namespace, `lo`, the ruleset, an empty resolv.conf.
    NsUp,
    /// The namespace gone.
    NsDown,
    /// The tunnel moved in, then the status mirror until stopped.
    Up,
    /// The tunnel gone, the namespace left with `lo`.
    Down,
}

impl Verb {
    fn parse(word: &str) -> Option<Self> {
        match word {
            "ns-up" => Some(Self::NsUp),
            "ns-down" => Some(Self::NsDown),
            "up" => Some(Self::Up),
            "down" => Some(Self::Down),
            _ => None,
        }
    }
}

/// What `vpn-zone-core system-zone` was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub verb: Verb,
    pub name: String,
    pub tools: Tools,
    /// The config, when it is not `STATE_DIR/<name>/config.conf` — a secret
    /// decrypted at boot, typically.
    pub config: Option<PathBuf>,
    /// A plain zone (§1a of `docs/SYSTEM.md`): no tunnel, out through the
    /// host's network by pasta, which runs as this system user.
    pub plain: Option<String>,
}

impl Args {
    /// Parse `<verb> [--ip P] [--awg P] [--wg P] [--nft P] [--pasta P]
    /// [--config P] [--plain USER] <name>`.
    pub fn parse(argv: &[OsString]) -> Result<Self, String> {
        let mut rest = argv.iter();
        let word = rest
            .next()
            .ok_or("need a verb: ns-up, ns-down, up or down")?
            .to_string_lossy()
            .into_owned();
        let verb = Verb::parse(&word).ok_or_else(|| format!("unknown verb: {word}"))?;

        let mut tools = Tools::default();
        let mut config = None;
        let mut plain = None;
        let mut name: Option<String> = None;
        while let Some(arg) = rest.next() {
            let arg = arg.to_str().ok_or("the arguments have to be UTF-8")?;
            if let Some(flag) = arg.strip_prefix("--") {
                let value = PathBuf::from(
                    rest.next()
                        .ok_or_else(|| format!("--{flag} needs a path"))?,
                );
                match flag {
                    "ip" => tools.ip = value,
                    "awg" => tools.awg = value,
                    "wg" => tools.wg = value,
                    "nft" => tools.nft = value,
                    "pasta" => tools.pasta = value,
                    "config" => config = Some(value),
                    "plain" => plain = Some(value.to_string_lossy().into_owned()),
                    _ => return Err(format!("unknown flag: --{flag}")),
                }
                continue;
            }
            if name.is_some() {
                return Err("only one zone name is accepted".to_owned());
            }
            name = Some(arg.to_owned());
        }
        let name = name.ok_or("need a zone name")?;
        check_name(&name)?;
        Ok(Self {
            verb,
            name,
            tools,
            config,
            plain,
        })
    }
}

/// Run one verb. Returns the exit code for the process.
pub fn run(args: &Args) -> u8 {
    let result = match args.verb {
        Verb::NsUp => ns_up(args),
        Verb::NsDown => {
            ns_down(args);
            Ok(())
        }
        Verb::Up => up(args),
        Verb::Down => {
            down(args);
            Ok(())
        }
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("system zone {}: {e}", args.name);
            1
        }
    }
}

// --- THE NAMESPACE -----------------------------------------------------------

fn ns_up(args: &Args) -> Result<(), String> {
    let (tools, name) = (&args.tools, args.name.as_str());
    let ns = netns(name);
    if !netns_path(name).exists() {
        ip(tools, &["netns", "add", ns.as_str()])?;
    }
    ip_in(tools, name, &["link", "set", "lo", "up"], false)?;

    // The second echelon, before there is anything to filter — as in a user
    // zone, and never fatal for the same reason: it insures the topology, the
    // topology does not lean on it.
    if let Err(e) = feed_ruleset(tools, name, &zone::app_ruleset()) {
        eprintln!(
            "system zone {name}: nftables second echelon is OFF ({e}) — the zone is still \
             hermetic by construction, but nothing insures it against a mistake"
        );
    }

    // Empty until the tunnel says otherwise: glibc then asks 127.0.0.1, and
    // this namespace's loopback has nobody on it. A consumer that starts before
    // the tunnel resolves nothing — rather than anything through the host.
    let resolv = resolv_path(name);
    if !resolv.exists() {
        if let Some(dir) = resolv.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }
        fs::write(&resolv, "").map_err(|e| format!("cannot create {}: {e}", resolv.display()))?;
    }
    // Written every time: the host's nsswitch.conf changes with the system.
    if let Ok(host) = fs::read_to_string(crate::sys::link_target(Path::new("/etc/nsswitch.conf"))) {
        let path = nsswitch_path(name);
        fs::write(&path, zone::zone_nsswitch(&host))
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }
    println!("system zone {name}: namespace {ns} is ready");
    Ok(())
}

fn ns_down(args: &Args) {
    let (tools, name) = (&args.tools, args.name.as_str());
    let ns = netns(name);
    if netns_path(name).exists() {
        let _ = ip_in(tools, name, &["link", "del", TUN], true);
        if let Err(e) = ip(tools, &["netns", "del", ns.as_str()]) {
            eprintln!("system zone {name}: {e}");
        }
    }
    let resolv = resolv_path(name);
    let _ = fs::remove_file(&resolv);
    let _ = fs::remove_file(nsswitch_path(name));
    if let Some(dir) = resolv.parent() {
        let _ = fs::remove_dir(dir);
    }
    println!("system zone {name}: namespace {ns} is gone");
}

// --- THE TUNNEL --------------------------------------------------------------

fn up(args: &Args) -> Result<(), String> {
    // The flags win (running a verb by hand); the unit passes none, and the
    // zone's own settings say what it is.
    let found = settings(&args.name);
    let own_dns = found.as_ref().map(|s| s.dns.clone()).unwrap_or_default();
    let plain = args.plain.clone().or_else(|| {
        found
            .as_ref()
            .filter(|s| s.plain)
            .map(|_| PLAIN_USER.to_owned())
    });
    if let Some(runas) = &plain {
        return up_plain(args, runas);
    }
    let (tools, name) = (&args.tools, args.name.as_str());
    let ns = netns(name);

    let config = args
        .config
        .clone()
        .or_else(|| found.map(|s| s.config))
        .unwrap_or_else(|| local_dir(name).join(CONFIG));
    let raw = fs::read(&config).map_err(|e| format!("cannot read {}: {e}", config.display()))?;
    let mut cfg = WgConfig::parse(&raw).map_err(|e| format!("{}: {e}", config.display()))?;
    if let Some(why) = refusal(&cfg) {
        return Err(why.to_owned());
    }
    if !cfg.dropped_empty.is_empty() {
        let keys: Vec<&str> = cfg.dropped_empty.iter().map(|d| d.key.as_str()).collect();
        println!(
            "system zone {name}: dropped empty config lines: {}",
            keys.join(", ")
        );
    }

    // --- THE ENDPOINT, RESOLVED HERE, IN THE HOST'S NETWORK ---
    // `setconf` runs inside the zone, where there is no DNS until the tunnel
    // it configures is up; a name there would hang it. The same rewrite a user
    // zone does, by the same function.
    let endpoints = cfg.resolve_endpoints(zone::resolve_endpoint);
    if endpoints.is_empty() {
        eprintln!("system zone {name}: no Endpoint in the config — the tunnel has nowhere to go");
    }
    if let Some(bad) = endpoints.iter().find(|e| e.addr.is_none()) {
        // Not fatal forever: at boot the host's network may not be there yet,
        // and the unit retries.
        return Err(format!(
            "cannot resolve the endpoint {} (line {}) yet",
            bad.raw, bad.line
        ));
    }

    if !netns_path(name).exists() {
        return Err(format!(
            "{} is missing — vpn-zone-system-ns-{name} has to run first",
            netns_path(name).display()
        ));
    }
    let run = run_dir(name);
    make_run_dir(&run)?;
    let _ = fs::remove_file(run.join(READY));
    let _ = fs::remove_file(run.join(STATUS));
    // 0600, root: it carries the private key.
    let setconf = run.join(SETCONF);
    zone::write_private(&setconf, with_tunnel_mark(&cfg.to_setconf()).as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", setconf.display()))?;

    // Leftovers of a run that died halfway: an interface still in the host's
    // namespace (died before the move), or one already inside.
    let _ = ip_quiet(tools, &["link", "del", ns.as_str()]);
    let _ = ip_in(tools, name, &["link", "del", TUN], true);

    // --- THE TUNNEL IS BORN IN THE HOST'S NAMESPACE ---
    // Its UDP socket stays in the namespace it was created in, wherever the
    // interface goes: the encrypted packets leave by the host's routes, and the
    // zone never sees the endpoint at all.
    let wgtool = create_tunnel(tools, ns.as_str(), &cfg)?;
    if let Err(e) = move_in(tools, name, ns.as_str()) {
        let _ = ip_quiet(tools, &["link", "del", ns.as_str()]);
        return Err(e);
    }
    if let Err(e) = configure(tools, name, &cfg, &wgtool, &setconf) {
        let _ = ip_in(tools, name, &["link", "del", TUN], true);
        return Err(e);
    }
    if own_dns.is_empty() {
        write_resolv(name, &cfg)?;
    } else {
        println!("system zone {name}: its own resolvers, not the config's DNS=");
        write_resolv_text(name, &zone::resolv_conf(&own_dns).0, false)?;
    }

    write_group_readable(&run.join(READY), b"")
        .map_err(|e| format!("cannot write {READY}: {e}"))?;
    println!("system zone {name} is up in {}", netns_path(name).display());
    notify_ready();
    mirror(tools, name, &wgtool, &run)
}

/// A plain zone: pasta attached to the zone's namespace, as a system user of
/// its own. No tunnel and no encryption — the zone's own namespace, its own
/// resolvers and nothing of the host's: pasta's port forwarding and its
/// mapping of the gateway to the host's loopback are shut (`PASTA_CLOSED`), as
/// in every zone. What it is for: a network for the TTY console when the VPN
/// cannot come up, and for programs that have to go out directly once the
/// host has no network of its own (§9).
fn up_plain(args: &Args, runas: &str) -> Result<(), String> {
    let (tools, name) = (&args.tools, args.name.as_str());
    if !netns_path(name).exists() {
        return Err(format!(
            "{} is missing — vpn-zone-system-ns-{name} has to run first",
            netns_path(name).display()
        ));
    }
    let run = run_dir(name);
    make_run_dir(&run)?;
    let _ = fs::remove_file(run.join(READY));
    let _ = fs::remove_file(run.join(STATUS));
    let _ = ip_in(tools, name, &["link", "del", TUN], true);

    // As a system user, not as root and not as pasta's default `nobody`: the
    // host's egress policy lets system users out, and knows this one by name.
    let (uid, gid) = user_ids(runas).ok_or_else(|| format!("there is no user {runas}"))?;
    let mut pasta = Command::new(&tools.pasta);
    pasta
        .arg("--netns")
        .arg(netns_path(name))
        .args(["--config-net", "-q", "-I", TUN, "-f"])
        .args(zone::PASTA_CLOSED);
    // SAFETY: between fork and exec the closure only makes syscalls.
    unsafe {
        pasta.pre_exec(move || become_with_ns_caps(uid, gid));
    }
    let mut pasta = pasta
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}", tools.pasta.display()))?;
    let link = || {
        let args = in_zone_args(&netns(name), &["-o", "link", "show", TUN]);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        zone::tool_output(&tools.ip, &args).unwrap_or_default()
    };
    let mut there = false;
    for _ in 0..50 {
        if !link().trim().is_empty() {
            there = true;
            break;
        }
        if let Ok(Some(status)) = pasta.try_wait() {
            return Err(format!("pasta exited ({status}) — the zone has no way out"));
        }
        thread::sleep(std::time::Duration::from_millis(100));
    }
    if !there {
        let _ = pasta.kill();
        let _ = pasta.wait();
        return Err("pasta gave the zone no interface".to_owned());
    }
    let own_dns = settings(name).map(|s| s.dns).unwrap_or_default();
    let (text, defaulted) = zone::resolv_conf(&own_dns);
    write_resolv_text(name, &text, defaulted)?;
    write_group_readable(&run.join(READY), b"")
        .map_err(|e| format!("cannot write {READY}: {e}"))?;
    println!(
        "system zone {name} is up in {}: plain, out through the host's network (not encrypted \
         by this zone)",
        netns_path(name).display()
    );
    notify_ready();

    let status = run.join(STATUS);
    let tmp = run.join(STATUS_TMP);
    loop {
        if let Ok(Some(exit)) = pasta.try_wait() {
            return Err(format!("pasta exited ({exit}) — the zone has no way out"));
        }
        let addr = {
            let args = in_zone_args(&netns(name), &["-br", "-4", "addr", "show", TUN]);
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            zone::tool_output(&tools.ip, &args).unwrap_or_default()
        };
        let text = zone::link_mirror("plain", &link(), &addr);
        if write_group_readable(&tmp, text.as_bytes()).is_ok() {
            let _ = fs::rename(&tmp, &status);
        }
        thread::sleep(zone::STATUS_PERIOD);
    }
}

fn user_ids(name: &str) -> Option<(u32, u32)> {
    let name = std::ffi::CString::new(name).ok()?;
    // SAFETY: getpwnam returns a pointer into a static buffer, read at once.
    unsafe {
        let pw = libc::getpwnam(name.as_ptr());
        if pw.is_null() {
            None
        } else {
            Some(((*pw).pw_uid, (*pw).pw_gid))
        }
    }
}

/// In pasta's child, before exec: become `uid`/`gid` and keep exactly
/// CAP_SYS_ADMIN and CAP_NET_ADMIN, as ambient capabilities — what pasta needs
/// to enter a namespace the host's user namespace owns and configure its
/// interface there. `--runas` cannot do it: pasta changes its uid first, which
/// clears every capability, and then fails to enter the namespace ("Couldn't
/// switch to pasta namespaces", found by the VM test). Started as a non-root
/// user, pasta keeps its uid and these two.
fn become_with_ns_caps(uid: u32, gid: u32) -> io::Result<()> {
    const CAP_NET_ADMIN: u32 = 12;
    const CAP_SYS_ADMIN: u32 = 21;
    /// `_LINUX_CAPABILITY_VERSION_3`: two 32-bit words per set.
    const VERSION_3: u32 = 0x2008_0522;
    #[repr(C)]
    struct Header {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let check = |rc: libc::c_int| {
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    };
    let bits = (1u32 << CAP_NET_ADMIN) | (1u32 << CAP_SYS_ADMIN);
    let mut header = Header {
        version: VERSION_3,
        pid: 0,
    };
    let data = [
        Data {
            effective: bits,
            permitted: bits,
            inheritable: bits,
        },
        Data {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    // SAFETY: plain syscalls with constants, ids and the two structs above.
    unsafe {
        // Keep the permitted set across the change of uid…
        check(libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0))?;
        check(libc::setgroups(0, std::ptr::null()))?;
        check(libc::setresgid(gid, gid, gid))?;
        check(libc::setresuid(uid, uid, uid))?;
        // …then narrow it to the two, and make them survive exec.
        if libc::syscall(libc::SYS_capset, &mut header as *mut Header, data.as_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        for cap in [CAP_NET_ADMIN, CAP_SYS_ADMIN] {
            check(libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_RAISE,
                libc::c_ulong::from(cap),
                0,
                0,
            ))?;
        }
    }
    Ok(())
}

/// The zone's run directory, `2750 root:vpn-zones`: the group reads the
/// status, new files inherit the group. Made here and not only by tmpfiles,
/// because a zone added on the spot has no tmpfiles line.
fn make_run_dir(run: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(run).map_err(|e| format!("cannot create {}: {e}", run.display()))?;
    if let Some(gid) = crate::egress::group_id("vpn-zones") {
        let path = std::ffi::CString::new(run.as_os_str().as_encoded_bytes())
            .map_err(|_| "a NUL in the run directory's path".to_owned())?;
        // SAFETY: a valid path; uid 0 and the group's gid.
        unsafe { libc::chown(path.as_ptr(), 0, gid) };
    }
    fs::set_permissions(run, fs::Permissions::from_mode(0o2750))
        .map_err(|e| format!("cannot set the mode of {}: {e}", run.display()))
}

/// The system user pasta of plain zones runs as; the module creates it.
pub const PLAIN_USER: &str = "vpn-zones-plain";

/// A system zone's settings. Two sources, as with user zones: declared in Nix
/// (`/etc/vpn-zones/system-zones.d/<name>/`, written by the module) and made
/// on the spot (`/var/lib/vpn-zones/system/<name>/`, written by the
/// system-zone service when a user adds a VPN). Nix is stronger: a declared
/// zone takes nothing from the local directory but its config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub declared: bool,
    pub plain: bool,
    /// Where the tunnel's config is; unused by a plain zone.
    pub config: PathBuf,
    pub users: Vec<String>,
    pub system_bus: bool,
    /// The zone's own resolvers, instead of the config's `DNS =` (or, for a
    /// plain zone, the public ones): `zones.<name>.dns` in the module.
    pub dns: Vec<String>,
}

pub fn declared_dir(name: &str) -> PathBuf {
    Path::new(crate::sysrun::ZONES_DIR).join(name)
}

pub fn local_dir(name: &str) -> PathBuf {
    Path::new(STATE_DIR).join(name)
}

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|t| t.trim().to_owned())
        .filter(|t| !t.is_empty())
}

/// The settings of a zone, or `None` when there is no such zone.
pub fn settings(name: &str) -> Option<Settings> {
    check_name(name).ok()?;
    let local = local_dir(name);
    let declared = declared().iter().any(|z| z == name);
    let dir = if declared {
        declared_dir(name)
    } else if local.join("kind").exists() {
        local.clone()
    } else {
        return None;
    };
    let config = read_trimmed(&dir.join("config"))
        .map(PathBuf::from)
        .unwrap_or_else(|| local.join(CONFIG));
    Some(Settings {
        declared,
        plain: read_trimmed(&dir.join("kind")).as_deref() == Some("plain"),
        config,
        users: fs::read_to_string(dir.join("users"))
            .map(|t| crate::sysrun::parse_users(&t))
            .unwrap_or_default(),
        system_bus: dir.join("system-bus").exists(),
        dns: fs::read_to_string(dir.join("dns"))
            .map(|t| parse_dns(&t))
            .unwrap_or_default(),
    })
}

/// The addresses of a zone's `dns` file, one per line. Anything that is not
/// an address is left out: the lines end up in a resolv.conf, and a line of
/// its own there would be an option, not a resolver.
pub fn parse_dns(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.trim().parse::<std::net::IpAddr>().ok())
        .map(|ip| ip.to_string())
        .collect()
}

/// Every system zone: the declared ones and the ones made on the spot.
pub fn all_zones() -> Vec<String> {
    let mut zones = declared();
    if let Ok(entries) = fs::read_dir(STATE_DIR) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if check_name(&name).is_ok() && entry.path().join("kind").exists() {
                zones.push(name);
            }
        }
    }
    zones.sort();
    zones.dedup();
    zones
}

/// What a zone is, in `status --json`'s words.
pub fn declared_kind(name: &str) -> &'static str {
    if settings(name).is_some_and(|s| s.plain) {
        "plain"
    } else {
        "wireguard"
    }
}

fn down(args: &Args) {
    let (tools, name) = (&args.tools, args.name.as_str());
    let ns = netns(name);
    let run = run_dir(name);
    let _ = fs::remove_file(run.join(READY));
    if netns_path(name).exists() {
        let _ = ip_in(tools, name, &["link", "del", TUN], true);
    }
    // A run that died between `link add` and the move leaves it here.
    let _ = ip_quiet(tools, &["link", "del", ns.as_str()]);
    let _ = fs::remove_file(run.join(STATUS));
    let _ = fs::remove_file(run.join(SETCONF));
    println!("system zone {name}: the tunnel is gone, the namespace keeps lo alone");
}

/// The amneziawg module when there is one, the in-tree wireguard for a config
/// without obfuscation — the choice a user zone makes. Returns the tool that
/// speaks to what was built.
fn create_tunnel(tools: &Tools, link: &str, cfg: &WgConfig) -> Result<PathBuf, String> {
    if ip_quiet(tools, &["link", "add", link, "type", "amneziawg"]).is_ok() {
        return Ok(tools.awg.clone());
    }
    if cfg.is_obfuscated() {
        return Err(
            "the amneziawg module is unavailable and an obfuscated config cannot be carried \
             without it"
                .to_owned(),
        );
    }
    ip(tools, &["link", "add", link, "type", "wireguard"])?;
    println!("no amneziawg module — using the in-tree wireguard");
    Ok(tools.wg.clone())
}

/// Into the zone, where it becomes `awg0`. The namespace and the interface
/// share the name `vz-<name>`, which is why `link` is both.
fn move_in(tools: &Tools, name: &str, link: &str) -> Result<(), String> {
    ip(tools, &["link", "set", link, "netns", link])?;
    ip_in(tools, name, &["link", "set", link, "name", TUN], false)
}

/// Everything a user zone's app namespace does to its interface, from the
/// outside: `setconf`, the addresses, MTU, up, the routes.
fn configure(
    tools: &Tools,
    name: &str,
    cfg: &WgConfig,
    wgtool: &Path,
    setconf: &Path,
) -> Result<(), String> {
    let status = exec_in(tools, name, wgtool)
        .arg("setconf")
        .arg(TUN)
        .arg(setconf)
        .status()
        .map_err(|e| format!("cannot run {}: {e}", wgtool.display()))?;
    if !status.success() {
        return Err(format!("{} setconf failed ({status})", wgtool.display()));
    }

    // Every address, both families — a v6 address dropped silently is an IPv6
    // leak in any layout that has another interface; here it would only be a
    // dead family, and it is said all the same.
    let mut tunnel_v6 = false;
    for addr in cfg.addresses() {
        let raw = addr.raw.as_str();
        match addr.family {
            Family::V6 => {
                if ip_in(tools, name, &["-6", "addr", "add", raw, "dev", TUN], true).is_ok() {
                    tunnel_v6 = true;
                } else {
                    eprintln!(
                        "system zone {name}: the v6 address {raw} did not apply — IPv6 will be \
                         closed here"
                    );
                }
            }
            Family::V4 => ip_in(tools, name, &["-4", "addr", "add", raw, "dev", TUN], false)?,
        }
    }
    let mtu = cfg.mtu().unwrap_or(zone::DEFAULT_MTU).to_string();
    ip_in(
        tools,
        name,
        &["link", "set", TUN, "mtu", mtu.as_str(), "up"],
        false,
    )?;
    ip_in(
        tools,
        name,
        &["route", "replace", "default", "dev", TUN],
        false,
    )?;
    match zone::v6_plan(Path::new("/proc/net/if_inet6").exists(), tunnel_v6) {
        V6Plan::NoKernel => {}
        V6Plan::IntoTunnel => ip_in(
            tools,
            name,
            &["-6", "route", "replace", "default", "dev", TUN],
            false,
        )?,
        V6Plan::CloseDefault => {
            // The type before the prefix — see `zone::close_or_tunnel_v6`.
            let _ = ip_in(
                tools,
                name,
                &["-6", "route", "replace", "unreachable", "default"],
                true,
            );
        }
    }
    Ok(())
}

/// The zone's resolv.conf, from `DNS =` or the public resolvers through the
/// tunnel.
fn write_resolv(name: &str, cfg: &WgConfig) -> Result<(), String> {
    let (text, defaulted) = zone::resolv_conf(&cfg.dns());
    write_resolv_text(name, &text, defaulted)
}

fn write_resolv_text(name: &str, text: &str, defaulted: bool) -> Result<(), String> {
    if defaulted {
        println!("system zone {name}: no DNS= in the config — public resolvers through the tunnel");
    }
    let path = resolv_path(name);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    // IN PLACE, not by rename: consumers bind this file over their own
    // /etc/resolv.conf, and a bind mount keeps the inode it was made with — a
    // renamed file would leave every one of them reading the old text.
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(&path)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    file.write_all(text.as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Say the first handshake in the journal, then mirror `show` into the run
/// directory until the unit is stopped. `show` needs netlink privileges in the
/// zone; the group `vpn-zones` reads the file instead.
fn mirror(tools: &Tools, name: &str, wgtool: &Path, run: &Path) -> Result<(), String> {
    thread::sleep(zone::HANDSHAKE_AFTER);
    let handshakes = show(tools, name, wgtool, &["latest-handshakes"]).unwrap_or_default();
    if zone::handshake_seen(&handshakes) {
        println!("system zone {name}: handshake done — the tunnel is alive");
    } else {
        eprintln!(
            "system zone {name}: no handshake. Either the config is dead or the server is \
             unreachable"
        );
    }
    let status = run.join(STATUS);
    let tmp = run.join(STATUS_TMP);
    loop {
        if let Ok(text) = show(tools, name, wgtool, &[]) {
            if write_group_readable(&tmp, text.as_bytes()).is_ok() {
                let _ = fs::rename(&tmp, &status);
            }
        }
        thread::sleep(zone::STATUS_PERIOD);
    }
}

/// Tell systemd the zone is up (`Type=notify`): whatever is ordered after the
/// holder then starts with the tunnel and the zone's resolv.conf already in
/// place, instead of with a namespace that holds `lo` alone. Run by hand, with
/// no `NOTIFY_SOCKET`, there is nobody to tell.
fn notify_ready() {
    let Some(socket) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let sock = match UnixDatagram::unbound() {
        Ok(sock) => sock,
        Err(e) => {
            eprintln!("cannot tell systemd the zone is up: {e}");
            return;
        }
    };
    // `@name` is an abstract socket; anything else is a path.
    let sent = match socket.as_bytes().strip_prefix(b"@") {
        Some(name) => SocketAddr::from_abstract_name(name)
            .and_then(|addr| sock.send_to_addr(b"READY=1", &addr)),
        None => sock.send_to(b"READY=1", Path::new(&socket)),
    };
    if let Err(e) = sent {
        eprintln!("cannot tell systemd the zone is up: {e}");
    }
}

// --- SMALL PLUMBING ----------------------------------------------------------

fn ip(tools: &Tools, args: &[&str]) -> Result<(), String> {
    zone::run_tool(&tools.ip, args, false)
}

fn ip_quiet(tools: &Tools, args: &[&str]) -> Result<(), String> {
    zone::run_tool(&tools.ip, args, true)
}

/// `ip -n vz-<name> …`.
fn ip_in(tools: &Tools, name: &str, args: &[&str], quiet: bool) -> Result<(), String> {
    let all = in_zone_args(&netns(name), args);
    let all: Vec<&str> = all.iter().map(String::as_str).collect();
    zone::run_tool(&tools.ip, &all, quiet)
}

/// `ip netns exec vz-<name> <tool>`: for the tools that only speak to the
/// namespace they run in (`awg`, `wg`, `nft`).
fn exec_in(tools: &Tools, name: &str, tool: &Path) -> Command {
    let mut cmd = Command::new(&tools.ip);
    cmd.arg("netns").arg("exec").arg(netns(name)).arg(tool);
    cmd
}

fn show(tools: &Tools, name: &str, wgtool: &Path, extra: &[&str]) -> Result<String, String> {
    let out = exec_in(tools, name, wgtool)
        .arg("show")
        .arg(TUN)
        .args(extra)
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {}: {e}", wgtool.display()))?;
    if !out.status.success() {
        return Err(format!("{} show failed ({})", wgtool.display(), out.status));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `nft -f -` inside the zone, the ruleset on stdin (see `zone::feed_nft`).
fn feed_ruleset(tools: &Tools, name: &str, ruleset: &str) -> Result<(), String> {
    let mut child = exec_in(tools, name, &tools.nft)
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", tools.nft.display()))?;
    let fed = match child.stdin.take() {
        Some(mut pipe) => pipe
            .write_all(ruleset.as_bytes())
            .map_err(|e| format!("cannot hand the ruleset to nft: {e}")),
        None => Err("nft was given no stdin".to_owned()),
    };
    let status = child
        .wait()
        .map_err(|e| format!("cannot wait for {}: {e}", tools.nft.display()))?;
    fed?;
    if !status.success() {
        return Err(format!("{} -f - failed ({status})", tools.nft.display()));
    }
    Ok(())
}

/// A file the group of its directory may read: 0640, created anew so the mode
/// is the one asked for.
fn write_group_readable(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let _ = fs::remove_file(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }

    #[test]
    fn a_zones_own_resolvers_are_addresses_only() {
        assert_eq!(
            parse_dns(
                "192.168.1.1\n  2606:4700::1111 \n\noptions ndots:9\nnameserver 1.1.1.1\nx\n"
            ),
            ["192.168.1.1", "2606:4700::1111"]
        );
        assert!(parse_dns("").is_empty());
    }

    #[test]
    fn names_fit_an_interface_and_mean_nothing_else() {
        for good in ["vpn1", "a", "nl-home", "0", "abcdefghijkl"] {
            assert!(check_name(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "-x",
            "Nl",
            "nl_home",
            "nl home",
            "abcdefghijklm",
            "unconfined",
            "direct",
            "offline",
            "../x",
        ] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
        // The longest name still makes a legal interface name.
        assert_eq!(netns("abcdefghijkl").len(), 15);
    }

    #[test]
    fn the_paths_of_a_zone() {
        assert_eq!(netns_path("nl"), PathBuf::from("/run/netns/vz-nl"));
        assert_eq!(
            resolv_path("nl"),
            PathBuf::from("/etc/netns/vz-nl/resolv.conf")
        );
        assert_eq!(run_dir("nl"), PathBuf::from("/run/vpn-zones/system/nl"));
        assert_eq!(
            nsswitch_path("nl"),
            PathBuf::from("/etc/netns/vz-nl/nsswitch.conf")
        );
        assert_eq!(
            in_zone_args("vz-nl", &["link", "set", "lo", "up"]),
            vec!["-n", "vz-nl", "link", "set", "lo", "up"]
        );
    }

    #[test]
    fn the_command_line() {
        let args = Args::parse(&os(&[
            "up",
            "--ip",
            "/x/ip",
            "--awg",
            "/x/awg",
            "--config",
            "/run/secrets/nl",
            "nl",
        ]))
        .unwrap();
        assert_eq!(args.verb, Verb::Up);
        assert_eq!(args.name, "nl");
        assert_eq!(args.tools.ip, PathBuf::from("/x/ip"));
        assert_eq!(args.tools.awg, PathBuf::from("/x/awg"));
        assert_eq!(args.tools.wg, PathBuf::from("wg"));
        assert_eq!(args.config, Some(PathBuf::from("/run/secrets/nl")));
        assert_eq!(args.plain, None);
        let plain = Args::parse(&os(&[
            "up",
            "--pasta",
            "/x/pasta",
            "--plain",
            "vpn-zones-plain",
            "pl",
        ]))
        .unwrap();
        assert_eq!(plain.plain.as_deref(), Some("vpn-zones-plain"));
        assert_eq!(plain.tools.pasta, PathBuf::from("/x/pasta"));

        assert_eq!(Args::parse(&os(&["ns-up", "nl"])).unwrap().verb, Verb::NsUp);
        assert_eq!(
            Args::parse(&os(&["ns-down", "nl"])).unwrap().verb,
            Verb::NsDown
        );
        assert_eq!(Args::parse(&os(&["down", "nl"])).unwrap().verb, Verb::Down);

        assert!(Args::parse(&os(&[])).is_err());
        assert!(Args::parse(&os(&["start", "nl"])).is_err());
        assert!(Args::parse(&os(&["up"])).is_err());
        assert!(Args::parse(&os(&["up", "nl", "de"])).is_err());
        assert!(Args::parse(&os(&["up", "--ip"])).is_err());
        assert!(Args::parse(&os(&["up", "--openconnect", "/x", "nl"])).is_err());
        assert!(Args::parse(&os(&["up", "Bad_Name"])).is_err());
    }

    #[test]
    fn only_wireguard_configs_for_now() {
        let wg = WgConfig::parse_str(
            "[Interface]\nPrivateKey = x\n[Peer]\nPublicKey = y\nEndpoint = 192.0.2.1:51820\n",
        )
        .unwrap();
        assert_eq!(refusal(&wg), None);

        let oc = WgConfig::parse_str("[OpenConnect]\nServer = vpn.example.org\n").unwrap();
        assert!(refusal(&oc).unwrap().contains("OpenConnect"));

        let hostif = WgConfig::parse_str("[HostInterface]\nInterface = enp4s0\n").unwrap();
        assert!(refusal(&hostif).unwrap().contains("HostInterface"));

        let nothing = WgConfig::parse_str("[Peer]\nPublicKey = y\n").unwrap();
        assert!(refusal(&nothing).is_some());
    }

    #[test]
    fn the_tunnel_carries_the_mark_the_host_lets_out() {
        let text = "[Interface]\nPrivateKey = x\nFwMark = 0x1\nJc = 4\n[Peer]\nPublicKey = y\n\
                    FwMark = 7\n";
        let marked = with_tunnel_mark(text);
        assert_eq!(
            marked,
            "[Interface]\nFwMark = 0x767a\nPrivateKey = x\nJc = 4\n[Peer]\nPublicKey = y\n\
             FwMark = 7\n"
        );
        // A config without one gets it all the same.
        assert!(with_tunnel_mark("[Interface]\nPrivateKey = x\n").contains("FwMark = 0x767a"));
    }

    #[test]
    fn the_declared_list_trusts_no_name() {
        assert_eq!(
            parse_declared("nl\n\n  de  \nBad\nunconfined\n../etc\n"),
            vec!["nl".to_owned(), "de".to_owned()]
        );
    }
}
