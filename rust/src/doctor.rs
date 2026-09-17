//! `vpn-zone doctor` (ROADMAP M5): what is really in place, checked from where
//! a program would see it.
//!
//! The rule this command exists for is in `docs/LEAK-MODEL.md`: a channel is
//! closed when something shows it closed, not when reasoning says there is
//! nowhere to go. The DNS leak through nss-resolve was found by a browser leak
//! test on a live machine while every document said "closed". So the zone
//! checks run INSIDE the zone — `nsenter` into its namespaces and a probe
//! (`vpn-zone-core doctor-probe`) that reads what a program there would read —
//! and the host only compares.
//!
//! Four levels, and the difference between the middle two is the point:
//!
//! * `ok` — the property holds;
//! * `warn` — a channel the project KNOWS is open and names in
//!   `docs/LEAK-MODEL.md` ("open channels"): the session bus, `systemd --user`,
//!   the system bus, X11. Reported every time, so that nobody reads the absence
//!   of a failure as the absence of a way out;
//! * `fail` — a property the project promises does not hold: a second way out
//!   of the zone, a host resolver in reach, the host's `nsswitch.conf`;
//! * `skip` — could not be checked, and says why.
//!
//! The probe prints one line per check, `id<TAB>level<TAB>detail`: a stable,
//! trivial format across a namespace boundary, where the two sides may even be
//! different builds for a moment after an update.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cli::{liveness_line, visible_entries, zone_pid};
use crate::status::string as json_string;
use crate::tools::Tools;

/// The one link a zone's app namespace may have besides loopback: every
/// backend brings its tunnel up under this name (`crate::zone`).
pub const TUNNEL: &str = "awg0";

/// How a check came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Ok,
    Skip,
    Warn,
    Fail,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Skip => "skip",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "ok" => Some(Self::Ok),
            "skip" => Some(Self::Skip),
            "warn" => Some(Self::Warn),
            "fail" => Some(Self::Fail),
            _ => None,
        }
    }

    fn mark(self) -> &'static str {
        match self {
            Self::Ok => "✓",
            Self::Skip => "·",
            Self::Warn => "⚠",
            Self::Fail => "✗",
        }
    }
}

/// One check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub id: String,
    pub level: Level,
    pub detail: String,
}

impl Check {
    pub fn new(id: &str, level: Level, detail: impl Into<String>) -> Self {
        Self {
            id: id.to_owned(),
            level,
            detail: detail.into(),
        }
    }

    /// The probe's line: tabs and newlines in the detail become spaces.
    pub fn line(&self) -> String {
        let detail: String = self
            .detail
            .chars()
            .map(|c| if c == '\t' || c == '\n' { ' ' } else { c })
            .collect();
        format!("{}\t{}\t{detail}", self.id, self.level.as_str())
    }

    pub fn parse_line(line: &str) -> Option<Self> {
        let mut parts = line.splitn(3, '\t');
        let id = parts.next()?;
        let level = Level::parse(parts.next()?)?;
        Some(Self::new(id, level, parts.next().unwrap_or("")))
    }

    fn json(&self) -> String {
        format!(
            "{{\"id\":{},\"level\":{},\"detail\":{}}}",
            json_string(&self.id),
            json_string(self.level.as_str()),
            json_string(&self.detail)
        )
    }
}

// --- PURE EVALUATORS -----------------------------------------------------------

/// The interface names of a `/proc/net/dev`.
pub fn interfaces(net_dev: &str) -> Vec<String> {
    net_dev
        .lines()
        .skip(2)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, _)| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .collect()
}

/// A zone has loopback and at most its tunnel: anything else is a second way
/// out, around the tunnel.
pub fn links_check(links: &[String]) -> Check {
    let others: Vec<&str> = links
        .iter()
        .map(String::as_str)
        .filter(|l| *l != "lo" && *l != TUNNEL)
        .collect();
    if !others.is_empty() {
        return Check::new(
            "links",
            Level::Fail,
            format!("в зоне есть выход мимо туннеля: {}", others.join(", ")),
        );
    }
    if links.iter().any(|l| l == TUNNEL) {
        Check::new("links", Level::Ok, format!("lo и {TUNNEL}, больше ничего"))
    } else {
        Check::new("links", Level::Ok, "только lo: сети нет вовсе")
    }
}

/// The interfaces of the IPv4 default routes in a `/proc/net/route`.
pub fn default_routes4(route: &str) -> Vec<String> {
    route
        .lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            (f.len() >= 8 && f[1] == "00000000" && f[7] == "00000000").then(|| f[0].to_owned())
        })
        .collect()
}

/// The interfaces of the IPv6 default routes in a `/proc/net/ipv6_route`,
/// without the kernel's own unreachable ones (`RTF_REJECT` on `lo`).
pub fn default_routes6(route: &str) -> Vec<String> {
    const RTF_REJECT: u32 = 0x0200;
    route
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 || f[0].bytes().any(|b| b != b'0') || f[1] != "00" {
                return None;
            }
            let flags = u32::from_str_radix(f[8], 16).unwrap_or(0);
            (flags & RTF_REJECT == 0).then(|| f[9].to_owned())
        })
        .collect()
}

/// Every default route goes into the tunnel, or there is none.
pub fn routes_check(id: &str, family: &str, routes: &[String]) -> Check {
    let around: Vec<&str> = routes
        .iter()
        .map(String::as_str)
        .filter(|r| *r != TUNNEL)
        .collect();
    if !around.is_empty() {
        Check::new(
            id,
            Level::Fail,
            format!(
                "маршрут {family} по умолчанию мимо туннеля: {}",
                around.join(", ")
            ),
        )
    } else if routes.is_empty() {
        Check::new(id, Level::Ok, format!("маршрута {family} наружу нет"))
    } else {
        Check::new(id, Level::Ok, format!("{family} по умолчанию — в {TUNNEL}"))
    }
}

/// The zone's own `nsswitch.conf` says `hosts: files dns`, and nothing else
/// that could ask a daemon of the host.
pub fn nsswitch_check(text: Option<&str>) -> Check {
    let Some(text) = text else {
        return Check::new(
            "nsswitch",
            Level::Ok,
            "nsswitch.conf нет: встроенный порядок glibc без демонов",
        );
    };
    let hosts = text.lines().find_map(|line| {
        let line = line.split('#').next().unwrap_or("").trim();
        line.strip_prefix("hosts:").map(|rest| {
            rest.split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<String>>()
        })
    });
    match hosts {
        Some(words) if words == ["files", "dns"] => {
            Check::new("nsswitch", Level::Ok, "hosts: files dns")
        }
        Some(words) => Check::new(
            "nsswitch",
            Level::Fail,
            format!(
                "hosts: {} — модули кроме files и dns могут спросить демона хоста; \
                 зона поднята без своего nsswitch.conf (перезапусти её)",
                words.join(" ")
            ),
        ),
        None => Check::new("nsswitch", Level::Ok, "строки hosts: нет — files dns"),
    }
}

/// The nameservers of a `resolv.conf`.
pub fn nameservers(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            match (words.next(), words.next()) {
                (Some("nameserver"), Some(address)) => Some(address.to_owned()),
                _ => None,
            }
        })
        .collect()
}

pub fn resolv_check(text: Option<&str>) -> Check {
    match text.map(nameservers) {
        None => Check::new(
            "resolv",
            Level::Warn,
            "resolv.conf не читается: имена не резолвятся",
        ),
        Some(servers) if servers.is_empty() => Check::new(
            "resolv",
            Level::Warn,
            "в resolv.conf нет серверов: имена не резолвятся",
        ),
        Some(servers) => Check::new(
            "resolv",
            Level::Ok,
            format!("серверы имён: {}", servers.join(", ")),
        ),
    }
}

/// Sockets of the host's resolvers: must not be visible in a zone.
pub const RESOLVER_SOCKETS: [&str; 5] = [
    "/run/nscd/socket",
    "/var/run/nscd/socket",
    "/run/systemd/resolve/io.systemd.Resolve",
    "/run/systemd/resolve/io.systemd.Resolve.Monitor",
    "/run/avahi-daemon/socket",
];

pub fn resolver_sockets_check(present: &[&str]) -> Check {
    if present.is_empty() {
        Check::new(
            "resolvers",
            Level::Ok,
            "сокетов резолверов хоста (nscd, systemd-resolved, avahi) не видно",
        )
    } else {
        Check::new(
            "resolvers",
            Level::Fail,
            format!(
                "виден резолвер хоста — имена уйдут мимо туннеля: {}",
                present.join(", ")
            ),
        )
    }
}

/// The channels `docs/LEAK-MODEL.md` lists as open, as they are seen in this
/// namespace: `(id, path, what it is)`.
pub fn open_channels(uid: u32) -> Vec<(&'static str, PathBuf, &'static str)> {
    vec![
        (
            "session-bus",
            PathBuf::from(format!("/run/user/{uid}/bus")),
            "сессионная шина: порталы и systemd --user — запуск процесса вне зоны \
             (LEAK-MODEL, открытые каналы §1–2)",
        ),
        (
            "systemd-user",
            PathBuf::from(format!("/run/user/{uid}/systemd/private")),
            "сокет systemd --user: запуск процесса вне зоны (§1)",
        ),
        (
            "system-bus",
            PathBuf::from("/run/dbus/system_bus_socket"),
            "системная шина: NetworkManager, hostname1, resolve1 (§3)",
        ),
        (
            "x11",
            PathBuf::from("/tmp/.X11-unix"),
            "сокеты X-сервера хоста: окна, ввод и буфер обмена всей машины (§7)",
        ),
    ]
}

/// A known open channel: `warn` while it is there.
pub fn open_channel_check(id: &str, what: &str, open: bool) -> Check {
    if open {
        Check::new(id, Level::Warn, format!("открыт — {what}"))
    } else {
        Check::new(id, Level::Ok, "не виден")
    }
}

/// Is there a socket or anything else at this path (an X11 directory counts
/// only with a socket in it)?
fn reachable(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::read_dir(path)
            .map(|entries| entries.flatten().next().is_some())
            .unwrap_or(false),
        Ok(_) => true,
        Err(_) => false,
    }
}

// --- THE PROBE (inside a zone) -------------------------------------------------

/// Every check a program in this namespace can answer.
pub fn probe(uid: u32) -> Vec<Check> {
    let read = |path: &str| fs::read_to_string(path).ok();
    let mut checks = Vec::new();
    match read("/proc/net/dev") {
        Some(dev) => checks.push(links_check(&interfaces(&dev))),
        None => checks.push(Check::new(
            "links",
            Level::Skip,
            "/proc/net/dev не читается",
        )),
    }
    match read("/proc/net/route") {
        Some(route) => checks.push(routes_check("route4", "IPv4", &default_routes4(&route))),
        None => checks.push(Check::new(
            "route4",
            Level::Skip,
            "/proc/net/route не читается",
        )),
    }
    match read("/proc/net/ipv6_route") {
        Some(route) => checks.push(routes_check("route6", "IPv6", &default_routes6(&route))),
        // IPv6 switched off in the zone: nothing to route.
        None => checks.push(Check::new("route6", Level::Ok, "IPv6 в зоне нет")),
    }
    checks.push(nsswitch_check(read("/etc/nsswitch.conf").as_deref()));
    checks.push(resolv_check(read("/etc/resolv.conf").as_deref()));
    let present: Vec<&str> = RESOLVER_SOCKETS
        .iter()
        .copied()
        .filter(|p| fs::symlink_metadata(p).is_ok())
        .collect();
    checks.push(resolver_sockets_check(&present));
    let mountinfo = read("/proc/self/mountinfo").unwrap_or_default();
    for (id, path, what) in open_channels(uid) {
        if id == "system-bus" {
            checks.push(system_bus_check(&mountinfo, reachable(&path), what));
            continue;
        }
        if id == "session-bus" && mounted_at(&mountinfo, &path.to_string_lossy()) {
            checks.push(Check::new(
                "session-bus",
                Level::Ok,
                "фильтруется (герметичная зона): порталы, уведомления, трей, MPRIS, методы ввода",
            ));
            continue;
        }
        if id == "x11" && mounted_at(&mountinfo, crate::x11::X11_DIR) {
            checks.push(Check::new(
                "x11",
                Level::Ok,
                "X-сервер хоста скрыт; видны только свои X-серверы контейнеров",
            ));
            continue;
        }
        checks.push(open_channel_check(id, what, reachable(&path)));
    }
    checks
}

/// The system bus in a zone: filtered (the zone's proxy bound over the socket)
/// or closed (a tmpfs over `/run/dbus`) is what the zone promises; the host's
/// bus as it is, a warning.
/// Is something mounted at this point, per `/proc/self/mountinfo`?
pub fn mounted_at(mountinfo: &str, point: &str) -> bool {
    mountinfo
        .lines()
        .any(|line| line.split_whitespace().nth(4) == Some(point))
}

pub fn system_bus_check(mountinfo: &str, reachable: bool, what: &str) -> Check {
    let mounted_at = |point: &str| mounted_at(mountinfo, point);
    if mounted_at("/run/dbus/system_bus_socket") {
        Check::new(
            "system-bus",
            Level::Ok,
            "фильтруется: UPower, login1 только Inhibit и чтение",
        )
    } else if mounted_at("/run/dbus") || !reachable {
        Check::new("system-bus", Level::Ok, "закрыта")
    } else {
        Check::new("system-bus", Level::Warn, format!("открыта — {what}"))
    }
}

/// `vpn-zone-core doctor-probe <uid>`.
pub fn probe_main(args: &[OsString]) -> u8 {
    let Some(uid) = args
        .first()
        .and_then(|a| a.to_str())
        .and_then(|a| a.parse::<u32>().ok())
    else {
        eprintln!("vpn-zone-core doctor-probe: need <uid>");
        return 2;
    };
    for check in probe(uid) {
        println!("{}", check.line());
    }
    0
}

// --- THE HOST SIDE -------------------------------------------------------------

/// Where this command itself runs: a terminal started in a zone or a sandbox
/// breaks system operations in ways that do not say why (ROADMAP M5).
pub fn context_check(current_zone: Option<&str>, in_sandbox: bool) -> Check {
    match (current_zone, in_sandbox) {
        (Some(zone), true) => Check::new(
            "context",
            Level::Warn,
            format!("эта команда запущена в зоне «{zone}» и в песочнице: сеть и файлы — не хоста"),
        ),
        (Some(zone), false) => Check::new(
            "context",
            Level::Warn,
            format!("эта команда запущена в зоне «{zone}»: её сеть — не сеть хоста"),
        ),
        (None, true) => Check::new(
            "context",
            Level::Warn,
            "эта команда запущена в песочнице: файлы хоста ей не видны",
        ),
        (None, false) => Check::new("context", Level::Ok, "запущено на хосте"),
    }
}

/// The user namespace switches of the kernel, from their `/proc/sys` values.
pub fn userns_check(
    max_user_namespaces: Option<&str>,
    unprivileged_clone: Option<&str>,
    apparmor_restrict: Option<&str>,
) -> Check {
    let value = |v: Option<&str>| v.and_then(|t| t.trim().parse::<i64>().ok());
    if value(max_user_namespaces) == Some(0) {
        return Check::new(
            "userns",
            Level::Fail,
            "user.max_user_namespaces = 0: зоны без root невозможны",
        );
    }
    if value(unprivileged_clone) == Some(0) {
        return Check::new(
            "userns",
            Level::Fail,
            "kernel.unprivileged_userns_clone = 0: непривилегированные userns запрещены",
        );
    }
    if value(apparmor_restrict) == Some(1) {
        return Check::new(
            "userns",
            Level::Fail,
            "kernel.apparmor_restrict_unprivileged_userns = 1: AppArmor запрещает userns \
             (sysctl kernel.apparmor_restrict_unprivileged_userns=0)",
        );
    }
    Check::new(
        "userns",
        Level::Ok,
        "непривилегированные user namespaces разрешены",
    )
}

/// A line of `/etc/subuid` (or `subgid`) for this user, by name or by uid.
pub fn has_subid_range(text: &str, user: &str, uid: u32) -> bool {
    let uid = uid.to_string();
    text.lines().any(|line| {
        let mut fields = line.split(':');
        let owner = fields.next().unwrap_or("");
        (owner == user || owner == uid)
            && fields.nth(1).and_then(|n| n.trim().parse::<u64>().ok()) >= Some(65536)
    })
}

fn file_check(id: &str, path: &Path, what: &str) -> Check {
    let executable = fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false);
    if executable {
        Check::new(id, Level::Ok, format!("{what}: {}", path.display()))
    } else {
        Check::new(
            id,
            Level::Fail,
            format!("{what} не найден или не исполняемый: {}", path.display()),
        )
    }
}

/// `newuidmap` with the setuid bit, where NixOS and the distributions put it.
fn newuidmap_check() -> Check {
    for dir in ["/run/wrappers/bin", "/usr/bin", "/bin"] {
        let path = Path::new(dir).join("newuidmap");
        if let Ok(meta) = fs::metadata(&path) {
            return if meta.mode() & 0o4000 != 0 {
                Check::new(
                    "newuidmap",
                    Level::Ok,
                    format!("{} (setuid)", path.display()),
                )
            } else {
                Check::new(
                    "newuidmap",
                    Level::Warn,
                    format!(
                        "{} без setuid-бита: второй диапазон uid в зоне не отобразится \
                         (file capabilities этой проверкой не видны)",
                        path.display()
                    ),
                )
            };
        }
    }
    Check::new(
        "newuidmap",
        Level::Fail,
        "newuidmap не найден (shadow / uidmap): зоне нечем отобразить uid",
    )
}

pub fn system_checks(tools: &Tools, uid: u32) -> Vec<Check> {
    let read = |path: &str| fs::read_to_string(path).ok();
    let mut checks = vec![context_check(
        std::env::var(crate::launch::ENV_CURRENT)
            .ok()
            .filter(|z| !z.is_empty())
            .as_deref(),
        Path::new("/.flatpak-info").exists(),
    )];
    checks.push(userns_check(
        read("/proc/sys/user/max_user_namespaces").as_deref(),
        read("/proc/sys/kernel/unprivileged_userns_clone").as_deref(),
        read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").as_deref(),
    ));
    checks.push(newuidmap_check());
    let user = std::env::var("USER").unwrap_or_default();
    for (id, file) in [("subuid", "/etc/subuid"), ("subgid", "/etc/subgid")] {
        checks.push(match read(file) {
            Some(text) if has_subid_range(&text, &user, uid) => {
                Check::new(id, Level::Ok, format!("диапазон для {user} есть в {file}"))
            }
            Some(_) => Check::new(
                id,
                Level::Fail,
                format!("в {file} нет диапазона на 65536 для {user}"),
            ),
            None => Check::new(id, Level::Fail, format!("{file} не читается")),
        });
    }
    // A zone that kept the name `unconfined` from before it meant the host's
    // network: no longer offered, and refused when named.
    if tools.state.join(crate::launch::UNCONFINED).is_dir() {
        checks.push(Check::new(
            "zone-name-unconfined",
            Level::Fail,
            format!(
                "есть зона с именем «{}» — теперь это имя сети хоста без ограничений; \
                 запуск в неё отказывается, переименуй её каталог в {}",
                crate::launch::UNCONFINED,
                tools.state.display()
            ),
        ));
    }
    checks.push(if Path::new("/dev/net/tun").exists() {
        Check::new("tun", Level::Ok, "/dev/net/tun есть")
    } else {
        Check::new(
            "tun",
            Level::Fail,
            "/dev/net/tun нет: pasta не поднимет аплинк",
        )
    });
    for (id, path, what) in [
        ("tool-nsenter", &tools.nsenter, "nsenter"),
        ("tool-ip", &tools.ip, "ip"),
        ("tool-systemctl", &tools.systemctl, "systemctl"),
        ("tool-bwrap", &tools.bwrap, "bwrap"),
        ("tool-dbus-proxy", &tools.dbus_proxy, "xdg-dbus-proxy"),
        ("tool-core", &tools.core, "vpn-zone-core"),
    ] {
        checks.push(file_check(id, path, what));
    }
    checks
}

/// The zone's own checks: the probe inside it, and the tunnel from outside.
pub fn zone_checks(tools: &Tools, name: &str, uid: u32) -> (bool, Vec<Check>) {
    let Some(pid) = zone_pid(&tools.state, name.as_ref()) else {
        return (
            false,
            vec![Check::new(
                "up",
                Level::Skip,
                "зона не поднята — проверяется только поднятая",
            )],
        );
    };
    let dir = tools.state.join(name);
    let offline = dir.join("offline").exists();
    let mut checks = Vec::new();
    let output = Command::new(&tools.nsenter)
        .args(["--preserve-credentials", "-U", "-n", "-m", "-t"])
        .arg(pid.to_string())
        .arg("--")
        .arg(&tools.core)
        .arg("doctor-probe")
        .arg(uid.to_string())
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            let parsed: Vec<Check> = text.lines().filter_map(Check::parse_line).collect();
            if parsed.is_empty() {
                checks.push(Check::new(
                    "probe",
                    Level::Fail,
                    "проба в зоне ничего не ответила",
                ));
            }
            checks.extend(parsed);
        }
        Ok(out) => checks.push(Check::new(
            "probe",
            Level::Fail,
            format!(
                "проба в зоне не запустилась: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        )),
        Err(e) => checks.push(Check::new(
            "probe",
            Level::Fail,
            format!("не запустить {}: {e}", tools.nsenter.display()),
        )),
    }
    if !offline {
        checks.push(match fs::read_to_string(dir.join("status")) {
            Ok(mirror) => match liveness_line(&mirror) {
                Some(line) => Check::new("tunnel", Level::Ok, format!("туннель живой ({line})")),
                None => Check::new(
                    "tunnel",
                    Level::Warn,
                    "рукопожатия нет: программы зоны без сети (утечки нет — выход закрыт)",
                ),
            },
            Err(_) => Check::new(
                "tunnel",
                Level::Skip,
                "состояние туннеля неизвестно: зона поднята старой версией",
            ),
        });
    }
    (true, checks)
}

/// The names of every zone on disk, `offline` included.
fn all_zones(tools: &Tools) -> Vec<String> {
    let mut names: Vec<String> = visible_entries(&tools.state)
        .into_iter()
        .filter(|d| d.join("config.conf").is_file() || d.join("offline").exists())
        .filter_map(|d| d.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect();
    names.sort();
    names
}

/// `vpn-zone doctor [<zone>…] [--json]`. Exit code 1 when anything failed.
pub fn run(tools: &Tools, args: &[OsString]) -> u8 {
    let json = args.iter().any(|a| a == "--json");
    let asked: Vec<String> = args
        .iter()
        .filter(|a| *a != "--json")
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    let system = system_checks(tools, uid);
    let names = if asked.is_empty() {
        all_zones(tools)
    } else {
        asked
    };
    let zones: Vec<(String, bool, Vec<Check>)> = names
        .into_iter()
        .map(|name| {
            if !tools.state.join(&name).is_dir() {
                let missing = Check::new("exists", Level::Fail, "такой зоны нет");
                return (name, false, vec![missing]);
            }
            let (up, checks) = zone_checks(tools, &name, uid);
            (name, up, checks)
        })
        .collect();

    let worst = system
        .iter()
        .chain(zones.iter().flat_map(|(_, _, c)| c.iter()))
        .map(|c| c.level)
        .max()
        .unwrap_or(Level::Ok);

    if json {
        let list = |checks: &[Check]| {
            format!(
                "[{}]",
                checks.iter().map(Check::json).collect::<Vec<_>>().join(",")
            )
        };
        let zones_json: Vec<String> = zones
            .iter()
            .map(|(name, up, checks)| {
                format!(
                    "{{\"name\":{},\"up\":{up},\"checks\":{}}}",
                    json_string(name),
                    list(checks)
                )
            })
            .collect();
        println!(
            "{{\"schema_version\":{},\"worst\":{},\"system\":{},\"zones\":[{}]}}",
            crate::status::SCHEMA_VERSION,
            json_string(worst.as_str()),
            list(&system),
            zones_json.join(",")
        );
    } else {
        let print = |checks: &[Check]| {
            for check in checks {
                println!("  {} {:<14} {}", check.level.mark(), check.id, check.detail);
            }
        };
        println!("система:");
        print(&system);
        for (name, _, checks) in &zones {
            println!("зона {name}:");
            print(checks);
        }
        match worst {
            Level::Fail => println!("\n✗ есть нарушения — см. строки с ✗"),
            Level::Warn => println!(
                "\n⚠ нарушений нет; ⚠ — известные открытые каналы и предупреждения \
                 (docs/LEAK-MODEL.md, «Открытые каналы»)"
            ),
            _ => println!("\n✓ всё в порядке"),
        }
    }
    u8::from(worst == Level::Fail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zone_has_loopback_and_its_tunnel_and_nothing_else() {
        let dev = "Inter-|   Receive\n face |bytes\n    lo: 1 2 3\n  awg0: 4 5 6\n";
        assert_eq!(interfaces(dev), ["lo", "awg0"]);
        assert_eq!(links_check(&interfaces(dev)).level, Level::Ok);
        assert_eq!(links_check(&["lo".to_owned()]).level, Level::Ok);
        let host = ["lo".to_owned(), "eth0".to_owned(), "awg0".to_owned()];
        let check = links_check(&host);
        assert_eq!(check.level, Level::Fail);
        assert!(check.detail.contains("eth0"), "{}", check.detail);
    }

    #[test]
    fn default_routes_are_read_from_proc() {
        let v4 =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                  awg0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n\
                  eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(default_routes4(v4), ["awg0"]);
        assert_eq!(
            routes_check("route4", "IPv4", &default_routes4(v4)).level,
            Level::Ok
        );
        let leak =
            "Iface\tDestination\n eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n";
        assert_eq!(
            routes_check("route4", "IPv4", &default_routes4(leak)).level,
            Level::Fail
        );

        let zero = "00000000000000000000000000000000";
        let v6 = format!(
            "{zero} 00 {zero} 00 {zero} 00000400 00000001 00000000 00000001     awg0\n\
             {zero} 00 {zero} 00 {zero} ffffffff 00000001 00000000 00200200       lo\n\
             fe800000000000000000000000000000 40 {zero} 00 {zero} 00000100 00000001 00000000 00000001     eth0\n"
        );
        assert_eq!(default_routes6(&v6), ["awg0"]);
        let unreachable_only =
            format!("{zero} 00 {zero} 00 {zero} ffffffff 00000001 00000000 00200200       lo\n");
        assert!(default_routes6(&unreachable_only).is_empty());
    }

    #[test]
    fn only_files_and_dns_resolve_hosts() {
        let own = "passwd: files systemd\nhosts: files dns # zone\n";
        assert_eq!(nsswitch_check(Some(own)).level, Level::Ok);
        let host = "hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns\n";
        let check = nsswitch_check(Some(host));
        assert_eq!(check.level, Level::Fail);
        assert!(check.detail.contains("mymachines"), "{}", check.detail);
        assert_eq!(nsswitch_check(None).level, Level::Ok);
    }

    #[test]
    fn resolvers_fail_and_open_channels_warn() {
        assert_eq!(resolver_sockets_check(&[]).level, Level::Ok);
        assert_eq!(
            resolver_sockets_check(&["/run/systemd/resolve/io.systemd.Resolve"]).level,
            Level::Fail
        );
        assert_eq!(open_channel_check("x11", "X", true).level, Level::Warn);
        assert_eq!(open_channel_check("x11", "X", false).level, Level::Ok);
        assert_eq!(
            nameservers("# c\nnameserver 10.0.0.1\nnameserver  ::1\nsearch x\n"),
            ["10.0.0.1", "::1"]
        );
        assert_eq!(resolv_check(Some("search x\n")).level, Level::Warn);
    }

    #[test]
    fn the_system_bus_is_ok_when_filtered_or_closed() {
        let bound = "36 25 0:5 /x /run/dbus/system_bus_socket rw - tmpfs x rw\n";
        let closed = "36 25 0:5 / /run/dbus rw - tmpfs tmpfs rw\n";
        assert_eq!(system_bus_check(bound, true, "w").level, Level::Ok);
        assert_eq!(system_bus_check(closed, false, "w").level, Level::Ok);
        assert_eq!(system_bus_check("", true, "w").level, Level::Warn);
    }

    #[test]
    fn the_probe_line_survives_the_namespace_boundary() {
        let check = Check::new("links", Level::Fail, "a\tb\nc");
        assert_eq!(check.line(), "links\tfail\ta b c");
        assert_eq!(
            Check::parse_line(&check.line()),
            Some(Check::new("links", Level::Fail, "a b c"))
        );
        assert_eq!(Check::parse_line("junk"), None);
        assert_eq!(Check::parse_line("id\tweird\tx"), None);
        assert!(Level::Fail > Level::Warn && Level::Warn > Level::Skip && Level::Skip > Level::Ok);
    }

    #[test]
    fn system_readiness_is_read_from_proc_and_etc() {
        assert_eq!(userns_check(Some("63000\n"), None, None).level, Level::Ok);
        assert_eq!(userns_check(Some("0\n"), None, None).level, Level::Fail);
        assert_eq!(userns_check(Some("1"), Some("0"), None).level, Level::Fail);
        assert_eq!(
            userns_check(Some("1"), Some("1"), Some("1\n")).level,
            Level::Fail
        );
        assert_eq!(userns_check(Some("1"), None, Some("0")).level, Level::Ok);

        let subuid = "root:100000:65536\nalice:165536:65536\n1001:231072:1000\n";
        assert!(has_subid_range(subuid, "alice", 1000));
        assert!(!has_subid_range(subuid, "bob", 1001), "too small a range");
        assert!(has_subid_range("1000:100000:65536\n", "alice", 1000));

        assert_eq!(context_check(None, false).level, Level::Ok);
        assert_eq!(context_check(Some("nl"), false).level, Level::Warn);
        assert_eq!(context_check(None, true).level, Level::Warn);
    }
}
