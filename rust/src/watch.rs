//! `vpn-zone watch` (ROADMAP M5): a tunnel that died is said out loud.
//!
//! A zone whose tunnel stopped working does not leak — its programs simply
//! have no network, and that is the fail-closed half of the design. The other
//! half is that nobody tells the person: the browser spins, the messenger says
//! "connecting…", and the zone looks exactly like a working one. A user timer
//! runs this every minute and sends one notification when a tunnel dies and
//! one when it comes back.
//!
//! **What "dead" means for WireGuard is not "no handshake lately".** WireGuard
//! handshakes only when there is something to send: an idle tunnel has an old
//! handshake and is perfectly fine. Dead is SENDING and getting nothing back:
//! the transmitted counter grew since the last look, the received one did not,
//! and the last handshake is older than the protocol's own limit for a session
//! (180 s) — or there never was one. For OpenConnect and host-interface zones
//! the mirror already says `connected` or `disconnected`.
//!
//! The state between two runs is one small file per zone in `.watch/`: the
//! counters and the last verdict, so that a notification is sent on a change
//! and not every minute.

use std::ffi::OsString;
use std::fs;
use std::path::Path;

use crate::cli::{visible_entries, zone_pid};
use crate::status::string as json_string;
use crate::tools::Tools;

/// The directory of the watcher's memory, below the state directory.
pub const WATCH_DIR: &str = ".watch";
/// WireGuard's `REJECT_AFTER_TIME`: a session older than this carries nothing.
pub const SESSION_LIMIT_S: u64 = 180;

/// What a status mirror says, parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reading {
    /// Seconds since the latest handshake; `None` when there never was one.
    pub handshake_age_s: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// For backends whose mirror says it in words: `Some(true)` for
    /// `connected:`, `Some(false)` for `disconnected:`.
    pub connected: Option<bool>,
}

/// `1 day, 2 hours, 3 minutes, 4 seconds ago` → seconds; `Now` → 0.
pub fn parse_age(text: &str) -> Option<u64> {
    let text = text.trim().trim_end_matches("ago").trim();
    if text.eq_ignore_ascii_case("now") {
        return Some(0);
    }
    let mut total = 0u64;
    let mut any = false;
    for part in text.split(',') {
        let mut words = part.split_whitespace();
        let (Some(n), Some(unit)) = (words.next(), words.next()) else {
            continue;
        };
        let n: u64 = n.parse().ok()?;
        let seconds = match unit.trim_end_matches('s') {
            "year" => 365 * 86_400,
            "day" => 86_400,
            "hour" => 3_600,
            "minute" => 60,
            "second" => 1,
            _ => return None,
        };
        total += n * seconds;
        any = true;
    }
    any.then_some(total)
}

/// `1.23 MiB` → bytes.
pub fn parse_size(text: &str) -> Option<u64> {
    let mut words = text.split_whitespace();
    let number: f64 = words.next()?.parse().ok()?;
    let factor: f64 = match words.next()? {
        "B" => 1.0,
        "KiB" => 1024.0,
        "MiB" => 1024.0 * 1024.0,
        "GiB" => 1024.0 * 1024.0 * 1024.0,
        "TiB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some((number * factor) as u64)
}

/// Read a status mirror: `wg show`/`awg show` text, or the link mirror of the
/// other backends.
pub fn parse_mirror(mirror: &str) -> Reading {
    let mut reading = Reading::default();
    for line in mirror.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("latest handshake:") {
            let age = parse_age(rest);
            // Several peers: the freshest handshake is the one that counts.
            reading.handshake_age_s = match (reading.handshake_age_s, age) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        } else if let Some(rest) = line.strip_prefix("transfer:") {
            for part in rest.split(',') {
                let part = part.trim();
                if let Some(size) = part.strip_suffix("received") {
                    reading.rx_bytes += parse_size(size).unwrap_or(0);
                } else if let Some(size) = part.strip_suffix("sent") {
                    reading.tx_bytes += parse_size(size).unwrap_or(0);
                }
            }
        } else if line.starts_with("connected:") {
            reading.connected = Some(true);
        } else if line.starts_with("disconnected:") {
            reading.connected = Some(false);
        }
    }
    reading
}

/// What the watcher concludes about one tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Alive,
    /// Nothing sent since the last look: nothing can be said, nothing is wrong.
    Idle,
    Dead,
    /// Dead at one look only. A single look can fall between a packet and its
    /// answer; a death is announced when two looks in a row agree.
    Suspect,
    /// First look, or no mirror: no counters to compare yet.
    Unknown,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Alive => "alive",
            Self::Idle => "idle",
            Self::Dead => "dead",
            Self::Suspect => "suspect",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "alive" => Some(Self::Alive),
            "idle" => Some(Self::Idle),
            "dead" => Some(Self::Dead),
            "suspect" => Some(Self::Suspect),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// The decision, from this reading and the previous one.
pub fn verdict(previous: Option<&Reading>, now: &Reading) -> Verdict {
    if let Some(connected) = now.connected {
        return if connected {
            Verdict::Alive
        } else {
            Verdict::Dead
        };
    }
    let Some(previous) = previous else {
        return Verdict::Unknown;
    };
    // Counters that went down: the interface was recreated (the zone was
    // restarted between two looks). Nothing to compare.
    if now.tx_bytes < previous.tx_bytes || now.rx_bytes < previous.rx_bytes {
        return Verdict::Unknown;
    }
    let sending = now.tx_bytes > previous.tx_bytes;
    let receiving = now.rx_bytes > previous.rx_bytes;
    let stale = now.handshake_age_s.is_none_or(|age| age > SESSION_LIMIT_S);
    match (sending, receiving) {
        (_, true) => Verdict::Alive,
        (true, false) if stale => Verdict::Dead,
        (true, false) => Verdict::Alive,
        (false, false) => Verdict::Idle,
    }
}

/// The watcher's memory of one zone: `rx tx verdict`.
pub fn render_memory(reading: &Reading, verdict: Verdict) -> String {
    format!(
        "{} {} {}\n",
        reading.rx_bytes,
        reading.tx_bytes,
        verdict.as_str()
    )
}

pub fn parse_memory(text: &str) -> Option<(Reading, Verdict)> {
    let mut words = text.split_whitespace();
    let rx_bytes = words.next()?.parse().ok()?;
    let tx_bytes = words.next()?.parse().ok()?;
    let verdict = Verdict::parse(words.next()?)?;
    Some((
        Reading {
            rx_bytes,
            tx_bytes,
            ..Reading::default()
        },
        verdict,
    ))
}

/// The state to keep after a look: a death needs two looks in a row, and a
/// quiet look (`Idle`, `Unknown`) keeps what was known — a tunnel that died
/// and then went quiet is still dead as far as the person knows.
pub fn next_state(last: Option<Verdict>, fresh: Verdict) -> Verdict {
    match (fresh, last) {
        (Verdict::Dead, Some(Verdict::Dead | Verdict::Suspect)) => Verdict::Dead,
        (Verdict::Dead, _) => Verdict::Suspect,
        (Verdict::Idle | Verdict::Unknown, Some(last)) => last,
        _ => fresh,
    }
}

/// Which notification a change of the kept state deserves, if any:
/// `(title, body)`. A death that was not announced yet, and a recovery from an
/// announced one.
pub fn announcement(zone: &str, last: Option<Verdict>, now: Verdict) -> Option<(String, String)> {
    match (last, now) {
        (Some(Verdict::Dead), Verdict::Dead) => None,
        (_, Verdict::Dead) => Some((
            format!("Зона «{zone}»: туннель не отвечает"),
            "Программы зоны отправляют данные и ничего не получают: сети у них нет. Утечки нет — \
             выход закрыт. Проверь сервер или конфиг: cellward check, cellward doctor."
                .to_owned(),
        )),
        (Some(Verdict::Dead), Verdict::Alive) => Some((
            format!("Зона «{zone}»: туннель снова работает"),
            "Трафик через туннель снова ходит в обе стороны.".to_owned(),
        )),
        _ => None,
    }
}

/// `vpn-zone watch [--json]`: look at every zone that is up, remember, and
/// announce the changes.
pub fn run(tools: &Tools, args: &[OsString]) -> u8 {
    let json = args.iter().any(|a| a == "--json");
    let memory_dir = tools.state.join(WATCH_DIR);
    let mut rows = Vec::new();
    for dir in visible_entries(&tools.state) {
        let Some(name) = dir.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        if !dir.join("config.conf").is_file() || dir.join("offline").exists() {
            continue;
        }
        let memory_file = memory_dir.join(&name);
        if zone_pid(&tools.state, name.as_ref()).is_none() {
            // A zone that is down is nobody's alarm, and its old counters mean
            // nothing to the next start.
            let _ = fs::remove_file(&memory_file);
            continue;
        }
        let Ok(mirror) = fs::read_to_string(dir.join("status")) else {
            rows.push((name, Reading::default(), Verdict::Unknown, false));
            continue;
        };
        let now = parse_mirror(&mirror);
        // A verdict about a previous run of the zone — it was restarted between
        // two looks, faster than a look found it down — is not carried over:
        // an idle tunnel just brought up would inherit "dead" (review
        // 2026-09-25).
        let modified = |p: &std::path::Path| fs::metadata(p).and_then(|m| m.modified()).ok();
        let this_run = match (modified(&memory_file), modified(&dir.join("zone.pid"))) {
            (Some(verdict), Some(started)) => verdict >= started,
            _ => false,
        };
        let remembered = fs::read_to_string(&memory_file)
            .ok()
            .filter(|_| this_run)
            .and_then(|t| parse_memory(&t));
        let fresh = verdict(remembered.as_ref().map(|(r, _)| r), &now);
        let last = remembered.as_ref().map(|(_, v)| *v);
        let kept = next_state(last, fresh);
        let mut notified = false;
        if let Some((title, body)) = announcement(&name, last, kept) {
            crate::dialog::notify(&tools.notify_send, Some("critical"), "0", &title, &body);
            eprintln!("{title}");
            notified = true;
        }
        if fs::create_dir_all(&memory_dir).is_ok() {
            let _ = write_memory(&memory_file, &render_memory(&now, kept));
        }
        rows.push((name, now, kept, notified));
    }

    if json {
        let items: Vec<String> = rows
            .iter()
            .map(|(name, reading, verdict, notified)| {
                format!(
                    "{{\"name\":{},\"verdict\":{},\"handshake_age_s\":{},\"rx_bytes\":{},\
                     \"tx_bytes\":{},\"notified\":{notified}}}",
                    json_string(name),
                    json_string(verdict.as_str()),
                    reading
                        .handshake_age_s
                        .map_or("null".to_owned(), |a| a.to_string()),
                    reading.rx_bytes,
                    reading.tx_bytes
                )
            })
            .collect();
        println!(
            "{{\"schema_version\":{},\"zones\":[{}]}}",
            crate::status::SCHEMA_VERSION,
            items.join(",")
        );
    } else {
        for (name, _, verdict, _) in &rows {
            println!("{name}: {}", verdict.as_str());
        }
    }
    0
}

fn write_memory(path: &Path, text: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, text).and_then(|()| fs::rename(&tmp, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WG: &str = "interface: awg0\n  public key: x\n\npeer: y\n  endpoint: 192.0.2.1:51820\n  \
                      allowed ips: 0.0.0.0/0\n  latest handshake: 3 minutes, 5 seconds ago\n  \
                      transfer: 1.50 MiB received, 512 KiB sent\n";

    #[test]
    fn a_wg_mirror_is_read_into_numbers() {
        let r = parse_mirror(WG);
        assert_eq!(r.handshake_age_s, Some(185));
        assert_eq!(r.rx_bytes, 1_572_864);
        assert_eq!(r.tx_bytes, 524_288);
        assert_eq!(r.connected, None);
        assert_eq!(parse_age("Now"), Some(0));
        assert_eq!(
            parse_age("1 day, 1 hour, 1 minute, 1 second ago"),
            Some(90_061)
        );
        assert_eq!(parse_age("soon"), None);
        assert_eq!(parse_size("92 B"), Some(92));
        assert_eq!(parse_size("1.00 GiB"), Some(1 << 30));
        let oc = "interface: awg0\n  backend: openconnect\n  connected: yes\n";
        assert_eq!(parse_mirror(oc).connected, Some(true));
        let gone = "interface: awg0\n  backend: x\n  disconnected: gone\n";
        assert_eq!(parse_mirror(gone).connected, Some(false));
    }

    fn reading(rx: u64, tx: u64, age: Option<u64>) -> Reading {
        Reading {
            handshake_age_s: age,
            rx_bytes: rx,
            tx_bytes: tx,
            connected: None,
        }
    }

    #[test]
    fn dead_is_sending_into_silence_not_an_old_handshake() {
        let before = reading(1000, 1000, Some(30));
        // An idle tunnel with an old handshake is fine.
        assert_eq!(
            verdict(Some(&before), &reading(1000, 1000, Some(900))),
            Verdict::Idle
        );
        // Sending and receiving: alive whatever the handshake says.
        assert_eq!(
            verdict(Some(&before), &reading(2000, 2000, Some(900))),
            Verdict::Alive
        );
        // Sending into silence with a fresh session: rekeying, not dead yet.
        assert_eq!(
            verdict(Some(&before), &reading(1000, 5000, Some(60))),
            Verdict::Alive
        );
        // Sending into silence past the session limit, or with no handshake ever.
        assert_eq!(
            verdict(Some(&before), &reading(1000, 5000, Some(181))),
            Verdict::Dead
        );
        assert_eq!(
            verdict(Some(&before), &reading(1000, 5000, None)),
            Verdict::Dead
        );
        // First look, or counters that restarted: nothing to say.
        assert_eq!(verdict(None, &reading(0, 5000, None)), Verdict::Unknown);
        assert_eq!(
            verdict(Some(&before), &reading(0, 10, None)),
            Verdict::Unknown
        );
    }

    #[test]
    fn a_death_takes_two_looks_and_quiet_looks_keep_what_was_known() {
        assert_eq!(
            next_state(Some(Verdict::Alive), Verdict::Dead),
            Verdict::Suspect
        );
        assert_eq!(
            next_state(Some(Verdict::Suspect), Verdict::Dead),
            Verdict::Dead
        );
        assert_eq!(
            next_state(Some(Verdict::Suspect), Verdict::Alive),
            Verdict::Alive
        );
        assert_eq!(
            next_state(Some(Verdict::Dead), Verdict::Idle),
            Verdict::Dead
        );
        assert_eq!(next_state(None, Verdict::Unknown), Verdict::Unknown);
        // A suspect is not announced; the second look is.
        assert!(announcement("nl", Some(Verdict::Alive), Verdict::Suspect).is_none());
        assert!(announcement("nl", Some(Verdict::Suspect), Verdict::Dead).is_some());
    }

    #[test]
    fn a_death_is_announced_once_and_so_is_the_recovery() {
        assert!(announcement("nl", Some(Verdict::Alive), Verdict::Dead).is_some());
        assert!(announcement("nl", None, Verdict::Dead).is_some());
        assert!(announcement("nl", Some(Verdict::Dead), Verdict::Dead).is_none());
        assert!(announcement("nl", Some(Verdict::Dead), Verdict::Alive).is_some());
        assert!(announcement("nl", Some(Verdict::Alive), Verdict::Alive).is_none());
        assert!(announcement("nl", Some(Verdict::Dead), Verdict::Idle).is_none());

        let r = reading(10, 20, Some(5));
        let text = render_memory(&r, Verdict::Dead);
        let (back, v) = parse_memory(&text).unwrap();
        assert_eq!((back.rx_bytes, back.tx_bytes, v), (10, 20, Verdict::Dead));
    }
}
