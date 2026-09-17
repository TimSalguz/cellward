//! The journal: what was let out of containment, to whom, and when.
//!
//! A launch into `unconfined` has nothing of a zone around it, and a request
//! the broker lets through crosses from one network into another. Both are
//! legitimate, both are exactly what should be answerable afterwards — "which
//! programs ran without containment yesterday, and who let them out" — so each
//! leaves a line here. Nothing in the journal is a boundary: it is the record
//! of the moments a boundary was not applied.
//!
//! One JSON object per line in `~/.local/state/vpn-zones/.journal`, flat, every
//! value a string: `time` (UTC, RFC 3339), `event`, and the fields of that
//! event. At [`ROTATE_AT`] the file becomes `.journal.1`, so the journal keeps
//! between one and two megabytes of history. Readable by the user only.
//!
//! Events:
//! * `launch-unconfined` — `app`, `container`, `program`, `pid`;
//! * `broker` — `origin`, `target`, `app`, `decision` (`started`, `refused`),
//!   `why` when refused;
//! * `kill` — `zone`, `killed` (how many), `programs`, `down` (`yes`, `no`).

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::status::string;

/// The journal, below the state directory.
pub const FILE: &str = ".journal";
/// The previous one.
pub const PREVIOUS: &str = ".journal.1";
/// Where the journal starts over.
const ROTATE_AT: u64 = 1024 * 1024;
/// The lock the rotation and the append share.
const LOCK: &str = ".journal.lock";

/// `secs` since the epoch as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn utc(secs: u64) -> String {
    // Days to a civil date, after Howard Hinnant's `civil_from_days`.
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        rem / 60 % 60,
        rem % 60
    )
}

/// One line of the journal.
pub fn line(time: &str, event: &str, fields: &[(&str, &str)]) -> String {
    let mut out = format!("{{\"time\":{},\"event\":{}", string(time), string(event));
    for (key, value) in fields {
        out.push(',');
        out.push_str(&string(key));
        out.push(':');
        out.push_str(&string(value));
    }
    out.push('}');
    out
}

/// Append an event. A journal that cannot be written is said on stderr by the
/// caller and stops nothing: the launch it records has already been decided.
pub fn append(state: &Path, event: &str, fields: &[(&str, &str)]) -> io::Result<()> {
    fs::create_dir_all(state)?;
    let lock = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(state.join(LOCK))?;
    // SAFETY: a valid open descriptor; LOCK_EX blocks until the lock is ours,
    // and closing `lock` at the end of the function releases it.
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let path = state.join(FILE);
    if fs::metadata(&path).is_ok_and(|m| m.len() >= ROTATE_AT) {
        fs::rename(&path, state.join(PREVIOUS))?;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut text = line(&utc(now), event, fields);
    text.push('\n');
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)?
        .write_all(text.as_bytes())
}

/// A journal line back as its fields, in order. `None` for anything that is
/// not a flat object of strings — a line cut short by a full disk, say.
pub fn parse(text: &str) -> Option<Vec<(String, String)>> {
    let mut chars = text.trim().chars().peekable();
    let mut out = Vec::new();
    if chars.next()? != '{' {
        return None;
    }
    fn read_string(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<String> {
        if chars.next()? != '"' {
            return None;
        }
        let mut s = String::new();
        loop {
            match chars.next()? {
                '"' => return Some(s),
                '\\' => match chars.next()? {
                    'n' => s.push('\n'),
                    'r' => s.push('\r'),
                    't' => s.push('\t'),
                    'u' => {
                        let hex: String = (0..4).map(|_| chars.next()).collect::<Option<_>>()?;
                        s.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                    }
                    c => s.push(c),
                },
                c => s.push(c),
            }
        }
    }
    if chars.peek() == Some(&'}') {
        chars.next();
        return chars.next().is_none().then_some(out);
    }
    loop {
        let key = read_string(&mut chars)?;
        if chars.next()? != ':' {
            return None;
        }
        let value = read_string(&mut chars)?;
        out.push((key, value));
        match chars.next()? {
            ',' => continue,
            '}' => return chars.next().is_none().then_some(out),
            _ => return None,
        }
    }
}

/// The last `count` lines of the journal, oldest first, over the rotation.
pub fn tail(state: &Path, count: usize) -> Vec<String> {
    let mut lines: Vec<String> = [PREVIOUS, FILE]
        .iter()
        .filter_map(|name| fs::read_to_string(state.join(name)).ok())
        .flat_map(|text| text.lines().map(str::to_owned).collect::<Vec<_>>())
        .filter(|l| !l.trim().is_empty())
        .collect();
    let skip = lines.len().saturating_sub(count);
    lines.drain(..skip);
    lines
}

/// How an event reads for a person.
fn human(fields: &[(String, String)]) -> String {
    let get = |key: &str| {
        fields
            .iter()
            .find(|(k, _)| k == key)
            .map_or("", |(_, v)| v.as_str())
    };
    let time = get("time").replace('T', " ").replace('Z', " UTC");
    let what = match get("event") {
        "launch-unconfined" => {
            let container = match get("container") {
                "" => "основной профиль".to_owned(),
                "__fs__" => "одноразовая песочница".to_owned(),
                c => format!("контейнер {c}"),
            };
            format!(
                "без ограничений: {} ({}, {container}), pid {}",
                get("app"),
                get("program"),
                get("pid")
            )
        }
        "broker" => {
            let verdict = match get("decision") {
                "started" => "запущено".to_owned(),
                _ => format!("отказано: {}", get("why")),
            };
            let origin = match get("origin") {
                "" => "с хоста".to_owned(),
                zone => format!("из зоны «{zone}»"),
            };
            format!(
                "брокер: {origin} в «{}» — {} — {verdict}",
                get("target"),
                get("app")
            )
        }
        "kill" => format!(
            "зона «{}» оборвана: убито {}{}{}",
            get("zone"),
            get("killed"),
            match get("programs") {
                "" => String::new(),
                p => format!(" — {p}"),
            },
            if get("down") == "yes" {
                ""
            } else {
                ", опустить не удалось"
            }
        ),
        other => {
            let rest: Vec<String> = fields
                .iter()
                .filter(|(k, _)| k != "time" && k != "event")
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            format!("{other}: {}", rest.join(" "))
        }
    };
    format!("{time}  {what}")
}

/// `vpn-zone journal [--json] [<count>]`.
pub fn run(tools: &crate::tools::Tools, args: &[std::ffi::OsString]) -> u8 {
    let mut json = false;
    let mut count = 50;
    for arg in args {
        match arg.to_str() {
            Some("--json") => json = true,
            Some(n) if n.parse::<usize>().is_ok_and(|n| n > 0) => {
                count = n.parse().unwrap_or(count)
            }
            _ => {
                eprintln!("vpn-zone journal [--json] [<сколько последних>]");
                return 1;
            }
        }
    }
    let lines = tail(&tools.state, count);
    if json {
        let events: Vec<&str> = lines
            .iter()
            .map(String::as_str)
            .filter(|l| parse(l).is_some())
            .collect();
        println!(
            "{{\"schema_version\":{},\"events\":[{}]}}",
            crate::status::SCHEMA_VERSION,
            events.join(",")
        );
    } else if lines.is_empty() {
        println!("журнал пуст: запусков без ограничений и решений брокера не было");
    } else {
        for l in &lines {
            match parse(l) {
                Some(fields) => println!("{}", human(&fields)),
                None => println!("(повреждённая строка) {l}"),
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clock_reads_as_utc() {
        assert_eq!(utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc(951_868_799), "2000-02-29T23:59:59Z");
        assert_eq!(utc(1_789_650_309), "2026-09-17T13:05:09Z");
    }

    #[test]
    fn a_line_survives_the_round_trip() {
        let l = line(
            "2026-09-17T13:05:09Z",
            "launch-unconfined",
            &[("app", "a \"b\"\\c\u{1}"), ("container", "")],
        );
        assert_eq!(
            parse(&l).unwrap(),
            vec![
                ("time".to_owned(), "2026-09-17T13:05:09Z".to_owned()),
                ("event".to_owned(), "launch-unconfined".to_owned()),
                ("app".to_owned(), "a \"b\"\\c\u{1}".to_owned()),
                ("container".to_owned(), String::new()),
            ]
        );
        assert!(parse("{\"time\":\"x\"").is_none());
        assert!(parse("{\"time\":1}").is_none());
        assert!(parse("{\"a\":\"b\"} junk").is_none());
        assert_eq!(parse("{}"), Some(Vec::new()));
    }

    #[test]
    fn the_journal_rotates_and_the_tail_spans_both_files() {
        let state = std::env::temp_dir().join(format!("vpn-zone-journal-{}", std::process::id()));
        let _ = fs::remove_dir_all(&state);
        fs::create_dir_all(&state).unwrap();
        fs::write(
            state.join(FILE),
            format!("{}\n", "x".repeat(ROTATE_AT as usize)),
        )
        .unwrap();
        append(&state, "broker", &[("decision", "started")]).unwrap();
        assert!(state.join(PREVIOUS).is_file());
        let tail = tail(&state, 2);
        assert_eq!(tail.len(), 2);
        assert!(tail[1].contains("\"event\":\"broker\""), "{tail:?}");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(state.join(FILE)).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(&state);
    }
}
