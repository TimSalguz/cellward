//! Scoped tray activation: kernel process references, never application titles.
mod client;
use crate::{dbus_wire as wire, origin::Peer};
use std::fs;
use std::os::fd::{AsRawFd, OwnedFd};

pub const INTERFACE: &str = "org.cellward.Tray";
pub const MAX_TARGETS: usize = 64;

/// fdinfo numbers both references in the namespace of the same procfs mount,
/// which need not equal SO_PEERCRED's namespace. Never compare those numbers
/// to peer.pid or use them in pidfd_open while namespaces may differ.
fn pid_number(fd: &OwnedFd) -> Option<i32> {
    let text = fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).ok()?;
    text.lines()
        .find_map(|s| s.strip_prefix("Pid:"))?
        .trim()
        .parse()
        .ok()
}

pub(crate) fn held_pid(fd: &OwnedFd) -> Option<i32> {
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one owned descriptor; zero timeout. Errors are not liveness.
    if unsafe { libc::poll(&mut poll, 1, 0) } != 0 {
        return None;
    }
    let pid = pid_number(fd)?;
    (pid > 0).then_some(pid)
}

/// None means an ordinary message. Private methods are never forwarded as-is:
/// only a verified owner becomes ordinary Activate, and no received fd reaches
/// the application. The caller owns/closes the descriptor collection.
pub fn rewrite(
    msg: &[u8],
    h: &wire::Header,
    fds: &[OwnedFd],
    peer: Option<&Peer>,
) -> Result<Option<Vec<u8>>, &'static str> {
    if h.interface.as_deref() != Some(INTERFACE) {
        return Ok(None);
    }
    let interface = match (h.kind, h.member.as_deref()) {
        (wire::METHOD_CALL, Some("ActivateIfOwned")) => "org.kde.StatusNotifierItem",
        (wire::METHOD_CALL, Some("ActivateFreedesktopIfOwned")) => {
            "org.freedesktop.StatusNotifierItem"
        }
        _ => return Err("unsupported private tray method"),
    };
    if fds.is_empty() || fds.len() > MAX_TARGETS || h.unix_fds as usize != fds.len() {
        return Err("invalid tray process references");
    }
    let indexes =
        wire::fd_array(msg, h, MAX_TARGETS).map_err(|_| "invalid tray process indexes")?;
    let mut seen = [false; MAX_TARGETS];
    if indexes.len() != fds.len() {
        return Err("missing tray process indexes");
    }
    for i in indexes {
        let i = i as usize;
        if i >= fds.len() || std::mem::replace(&mut seen[i], true) {
            return Err("invalid or duplicate tray process index");
        }
    }
    if fds.iter().any(|fd| pid_number(fd).is_none()) {
        return Err("tray process reference is not a pidfd");
    }
    let peer = peer.ok_or("tray connection has no live process owner")?;
    let peer_pid = held_pid(&peer.pidfd).ok_or("tray connection owner exited")?;
    let matches = fds
        .iter()
        .any(|fd| held_pid(fd) == Some(peer_pid) && held_pid(&peer.pidfd) == Some(peer_pid));
    if !matches {
        return Err("tray item belongs to another launch");
    }
    let path = h.path.as_deref().ok_or("tray object path missing")?;
    let mut fields = vec![
        wire::Field::Path(path),
        wire::Field::Interface(interface),
        wire::Field::Member("Activate"),
        wire::Field::Signature("ii"),
    ];
    if let Some(sender) = h.sender.as_deref() {
        fields.push(wire::Field::Sender(sender));
    }
    if let Some(destination) = h.destination.as_deref() {
        fields.push(wire::Field::Destination(destination));
    }
    Ok(Some(wire::message(
        wire::METHOD_CALL,
        h.flags,
        h.serial,
        &fields,
        &[0; 8],
    )))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Item {
    service: String,
    path: String,
    freedesktop: bool,
}

fn bus_path() -> Result<std::path::PathBuf, String> {
    use std::os::unix::ffi::OsStringExt;
    let Some(address) = std::env::var_os("DBUS_SESSION_BUS_ADDRESS") else {
        return Ok(crate::broker::runtime_dir().join("bus"));
    };
    let address = address.to_str().ok_or("адрес шины сеанса не UTF-8")?;
    let encoded = address
        .split(';')
        .filter_map(|a| a.strip_prefix("unix:"))
        .find_map(|a| a.split(',').find_map(|p| p.strip_prefix("path=")))
        .ok_or("поддерживается только файловый Unix-адрес шины сеанса")?;
    let mut bytes = Vec::new();
    let mut chars = encoded.bytes();
    while let Some(c) = chars.next() {
        if c == b'%' {
            let a = chars
                .next()
                .and_then(|c| (c as char).to_digit(16))
                .ok_or("неверное экранирование адреса шины")?;
            let b = chars
                .next()
                .and_then(|c| (c as char).to_digit(16))
                .ok_or("неверное экранирование адреса шины")?;
            bytes.push((a * 16 + b) as u8);
        } else {
            bytes.push(c);
        }
    }
    Ok(std::path::PathBuf::from(std::ffi::OsString::from_vec(
        bytes,
    )))
}

fn owner(bus: &mut client::Client, service: &str) -> Option<String> {
    if service.starts_with(':') {
        return Some(service.to_owned());
    }
    let (msg, h) = bus
        .call(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "GetNameOwner",
            "s",
            &wire::body::string(service),
            &[],
        )
        .ok()?;
    if h.kind != wire::METHOD_RETURN {
        return None;
    }
    let unique = wire::body_string(&msg, &h).ok()?;
    (unique.starts_with(':') && unique.len() <= 255).then_some(unique)
}

fn item(value: &str, freedesktop: bool) -> Option<Item> {
    let (service, suffix) = value
        .split_once('/')
        .unwrap_or((value, "StatusNotifierItem"));
    if service.is_empty() || service.len() > 255 || service.contains(['\0', ' ', '\t', '\n']) {
        return None;
    }
    let path = format!("/{suffix}");
    if path.len() > 1024
        || !path
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'/' || c == b'_')
    {
        return None;
    }
    Some(Item {
        service: service.to_owned(),
        path,
        freedesktop,
    })
}

fn inventory(bus: &mut client::Client) -> Result<Vec<Item>, String> {
    let mut items = Vec::new();
    for (service, interface, freedesktop) in [
        (
            "org.kde.StatusNotifierWatcher",
            "org.kde.StatusNotifierWatcher",
            false,
        ),
        (
            "org.freedesktop.StatusNotifierWatcher",
            "org.freedesktop.StatusNotifierWatcher",
            true,
        ),
    ] {
        let Some(unique) = owner(bus, service) else {
            continue;
        };
        let body = wire::plain_body(&[
            wire::Arg::Str(interface.into()),
            wire::Arg::Str("RegisteredStatusNotifierItems".into()),
        ]);
        let Ok((msg, h)) = bus.call(
            &unique,
            "/StatusNotifierWatcher",
            "org.freedesktop.DBus.Properties",
            "Get",
            "ss",
            &body,
            &[],
        ) else {
            continue;
        };
        if h.kind == wire::METHOD_RETURN {
            if let Ok(values) = wire::string_array(&msg, &h, 128) {
                for value in values {
                    if let Some(item) = item(&value, freedesktop) {
                        if !items.contains(&item) && items.len() < 128 {
                            items.push(item);
                        }
                    }
                }
            }
        }
    }
    // A watcher may be absent while an item still owns its standard name.
    let (msg, h) = bus
        .call(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "ListNames",
            "",
            &[],
            &[],
        )
        .map_err(|e| format!("не получить значки трея: {e}"))?;
    if h.kind == wire::METHOD_RETURN {
        for name in wire::string_array(&msg, &h, 4096).map_err(|e| e.to_string())? {
            if wire::is_tray_name(&name) {
                if let Some(item) = item(&name, name.starts_with("org.freedesktop.")) {
                    if !items.contains(&item) && items.len() < 128 {
                        items.push(item);
                    }
                }
            }
        }
    }
    Ok(items)
}

fn targets(root: i32, until: std::time::Instant) -> Result<Vec<Peer>, String> {
    use std::collections::{HashMap, VecDeque};
    let root_peer = Peer::of_pid(root).ok_or("запущенный экземпляр завершился")?;
    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
    for entry in fs::read_dir("/proc")
        .map_err(|e| e.to_string())?
        .take(65536)
        .flatten()
    {
        if std::time::Instant::now() >= until {
            return Err("истекло время поиска процесса трея".into());
        }
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
        else {
            continue;
        };
        if let Some(parent) = crate::sys::parent_of(pid) {
            children.entry(parent).or_default().push(pid);
        }
    }
    let mut out = Vec::new();
    let mut pending = VecDeque::from([root]);
    while let Some(pid) = pending.pop_front() {
        if out.len() >= MAX_TARGETS || std::time::Instant::now() >= until {
            break;
        }
        let Some(peer) = Peer::of_pid(pid) else {
            continue;
        };
        if !crate::sys::descends_from(pid, &peer.pidfd, root) {
            continue;
        }
        if let Some(kids) = children.remove(&pid) {
            pending.extend(kids);
        }
        out.push(peer);
    }
    if !root_peer.alive() {
        return Err("запущенный экземпляр завершился".into());
    }
    Ok(out)
}

/// Ask a matching filtered SNI connection to show its window. The caller must
/// still focus only the pinned launch's compositor window after it remaps.
pub(crate) fn activate(root: i32, held: &OwnedFd) -> Result<(), String> {
    use std::time::{Duration, Instant};
    if held_pid(held) != Some(root) {
        return Err("экземпляр завершился".into());
    }
    let until = Instant::now() + Duration::from_secs(3);
    let peers = targets(root, until)?;
    let path = bus_path()?;
    let mut bus =
        client::Client::open(&path, until).map_err(|e| format!("шина сеанса недоступна: {e}"))?;
    let items = inventory(&mut bus)?;
    let fds: Vec<_> = peers
        .iter()
        .filter(|p| p.alive())
        .map(|p| p.pidfd.as_raw_fd())
        .collect();
    if fds.is_empty() {
        return Err("запущенный экземпляр завершился".into());
    }
    let mut body = ((fds.len() * 4) as u32).to_le_bytes().to_vec();
    for n in 0..fds.len() {
        body.extend_from_slice(&(n as u32).to_le_bytes());
    }
    for item in items {
        if held_pid(held) != Some(root) {
            return Err("экземпляр завершился".into());
        }
        if Instant::now() >= until {
            break;
        }
        let Some(unique) = owner(&mut bus, &item.service) else {
            continue;
        };
        if held_pid(held) != Some(root) {
            return Err("экземпляр завершился".into());
        }
        let method = if item.freedesktop {
            "ActivateFreedesktopIfOwned"
        } else {
            "ActivateIfOwned"
        };
        match bus.call(&unique, &item.path, INTERFACE, method, "ah", &body, &fds) {
            Ok((_, h)) if h.kind == wire::METHOD_RETURN => return Ok(()),
            // A matching application can be slow to answer Activate yet already
            // remapping. Let the caller check only its own pinned window.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Ok(())
            }
            _ => (),
        }
    }
    Err("значок этого экземпляра не найден или не поддерживает безопасное восстановление; после обновления cellward остановите и заново запустите контейнер".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    fn request(indexes: &[u32], count: u32) -> (Vec<u8>, wire::Header) {
        let mut body = ((indexes.len() * 4) as u32).to_le_bytes().to_vec();
        for i in indexes {
            body.extend_from_slice(&i.to_le_bytes());
        }
        let msg = wire::message(
            wire::METHOD_CALL,
            0,
            9,
            &[
                wire::Field::Path("/StatusNotifierItem"),
                wire::Field::Interface(INTERFACE),
                wire::Field::Member("ActivateIfOwned"),
                wire::Field::Signature("ah"),
                wire::Field::UnixFds(count),
                wire::Field::Sender(":1.7"),
                wire::Field::Destination(":1.8"),
            ],
            &body,
        );
        let h = wire::parse_header(&msg).unwrap();
        (msg, h)
    }
    #[test]
    fn only_kernel_owners_restore_and_no_pidfd_reaches_the_app() {
        let (socket, _other) = UnixStream::pair().unwrap();
        let peer = Peer::of(socket.as_raw_fd()).unwrap();
        let own = crate::sys::pidfd_open(peer.pid).unwrap();
        let (msg, h) = request(&[0], 1);
        let out = rewrite(&msg, &h, &[own], Some(&peer)).unwrap().unwrap();
        let h = wire::parse_header(&out).unwrap();
        assert_eq!(h.member.as_deref(), Some("Activate"));
        assert_eq!(h.interface.as_deref(), Some("org.kde.StatusNotifierItem"));
        assert_eq!(h.signature.as_deref(), Some("ii"));
        assert_eq!(h.unix_fds, 0);
        assert_eq!(h.serial, 9);
        assert_eq!(&out[h.body_offset..], &[0; 8]);
        let (msg, h) = request(&[0], 1);
        let arbitrary: OwnedFd = fs::File::open("/dev/null").unwrap().into();
        assert!(rewrite(&msg, &h, &[arbitrary], Some(&peer)).is_err());
        assert!(rewrite(&msg, &h, &[], Some(&peer)).is_err());
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let foreign = crate::sys::pidfd_open(child.id() as i32).unwrap();
        assert!(rewrite(&msg, &h, &[foreign], Some(&peer)).is_err());
        child.kill().unwrap();
        child.wait().unwrap();
    }
    #[test]
    fn duplicate_indexes_and_unknown_owners_are_rejected() {
        let (socket, _other) = UnixStream::pair().unwrap();
        let peer = Peer::of(socket.as_raw_fd()).unwrap();
        let fds = vec![
            crate::sys::pidfd_open(peer.pid).unwrap(),
            crate::sys::pidfd_open(peer.pid).unwrap(),
        ];
        let (msg, h) = request(&[0, 0], 2);
        assert!(rewrite(&msg, &h, &fds, Some(&peer)).is_err());
        let (msg, h) = request(&[0, 1], 2);
        assert!(rewrite(&msg, &h, &fds, None).is_err());
    }
}
