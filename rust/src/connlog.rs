//! The connections' journal — stage 2 of the network monitor
//! (`docs/FIREWALL.md` §7): what each running container's connections did,
//! minute by minute, and what each program used, day by day.
//!
//! **When.** With the counts' summaries (`crate::traffic::record`), every
//! minute the tunnel watch runs (`crate::watch`): each connection of every
//! running instance (`crate::flows`) that sent or received anything since
//! the last record gets a line in the day's raw journal, with the name its
//! address was given and the program that holds it (`crate::owners`), and
//! its bytes go to the day's summary of its container and program.
//!
//! **Where.** Below the state directory, out of every zone's reach, in
//! [`crate::traffic::NETLOG`]:
//!
//! ```text
//! raw/<YYYY-MM-DD>       <unix time>⇥<container>⇥<network>⇥<proto>⇥<remote>⇥<remote port>⇥<name>⇥<program>⇥<out>⇥<in>
//! programs/<YYYY-MM-DD>  <container>⇥<program>⇥<out>⇥<in>
//! last-flows             <instance>⇥<proto>⇥<own port>⇥<remote>⇥<remote port>⇥<first seen>⇥<out>⇥<in>
//! ```
//!
//! `<program>`: the launch's key (`crate::registry`), `~<process>` for a
//! process of no launch of the container's, `?` for none found; `<name>`
//! what a DNS answer said of the address, empty for none. Bytes are those
//! since the record before.
//!
//! **How long.** The raw journal: [`KEEP_RAW_DAYS`] days, or what the person
//! chose (`cellward netlog keep`, `programs.cellward.netlog.keepDays`), and
//! no more than [`RAW_CAP`] bytes, or the person's (`cellward netlog cap`,
//! `netlog.maxSize`) — whichever comes first, the oldest day going first;
//! a day that alone reaches the cap stops being written. The programs'
//! summaries: a year, as the containers' (`crate::traffic::KEEP_DAYS`).

use std::collections::{BTreeMap, HashMap};
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::flows::Flow;
use crate::tools::Tools;
use crate::traffic::{local_date, NETLOG};

/// The raw journal's directory in [`NETLOG`].
pub const RAW: &str = "raw";
/// The programs' summaries' directory in [`NETLOG`].
pub const PROGRAMS: &str = "programs";
/// Each connection's bytes at the last record.
const LAST: &str = "last-flows";
/// How many days of the raw journal are kept (the owner, 2026-09-28).
pub const KEEP_RAW_DAYS: u64 = 30;
/// How large the raw journal may grow (the owner, 2026-09-28: 1 GiB).
pub const RAW_CAP: u64 = 1 << 30;
/// The settings: days, and a size (`crate::cli::setting`).
pub const KEEP_SETTING: &str = "netlog-keep";
pub const CAP_SETTING: &str = "netlog-cap";

/// A day of programs: `(container, program) → (out, in)`.
pub type Programs = BTreeMap<(String, String), (u64, u64)>;

/// One connection of a running instance, as a record takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub instance: String,
    pub container: String,
    pub network: String,
    pub flow: Flow,
    pub name: String,
    pub program: String,
}

/// A size as the person says it: bytes, or a number with `K`, `M`, `G` or
/// `T` (binary).
pub fn parse_size(text: &str) -> Option<u64> {
    let text = text.trim();
    let (num, unit) = match text.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((at, _)) => text.split_at(at),
        None => (text, ""),
    };
    let shift = match unit.trim().to_ascii_uppercase().as_str() {
        "" | "B" => 0,
        "K" | "KB" | "KIB" => 10,
        "M" | "MB" | "MIB" => 20,
        "G" | "GB" | "GIB" => 30,
        "T" | "TB" | "TIB" => 40,
        _ => return None,
    };
    num.parse::<u64>().ok()?.checked_mul(1 << shift)
}

/// The days of the raw journal kept, and where that was said.
pub fn keep_days(tools: &Tools) -> (u64, crate::container::Source) {
    crate::cli::setting(tools, KEEP_SETTING)
        .and_then(|(v, s)| {
            Some((
                v.trim()
                    .parse::<u64>()
                    .ok()
                    .filter(|d| (1..=3650).contains(d))?,
                s,
            ))
        })
        .unwrap_or((KEEP_RAW_DAYS, crate::container::Source::Default))
}

/// The raw journal's cap in bytes, and where that was said.
pub fn cap(tools: &Tools) -> (u64, crate::container::Source) {
    crate::cli::setting(tools, CAP_SETTING)
        .and_then(|(v, s)| Some((parse_size(&v).filter(|n| *n >= 1 << 20)?, s)))
        .unwrap_or((RAW_CAP, crate::container::Source::Default))
}

/// Every running instance's connections now (`crate::flows::listed`).
fn entries(tools: &Tools) -> Vec<Entry> {
    let mut out = Vec::new();
    for l in crate::flows::listed(tools) {
        let Some((flows, names)) = &l.table else {
            continue;
        };
        let container = l.container.clone().unwrap_or_else(|| l.id.clone());
        for (f, owner) in flows.iter().zip(&l.owners) {
            let name = if crate::flows::forwarder(&f.key.remote) {
                "dns".to_owned()
            } else {
                crate::flows::name_of(names, &f.key.remote)
                    .unwrap_or_default()
                    .to_owned()
            };
            let program = match owner {
                Some(o) => o
                    .program
                    .clone()
                    .unwrap_or_else(|| format!("~{}", o.process)),
                None => "?".to_owned(),
            };
            out.push(Entry {
                instance: l.id.clone(),
                container: container.clone(),
                network: l.network.clone(),
                flow: f.clone(),
                name,
                program,
            });
        }
    }
    out
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Record what the running instances' connections did since the last
/// record (see the module's words). Run with the tunnel watch.
pub fn record(tools: &Tools) -> io::Result<()> {
    record_entries(
        &tools.state,
        &entries(tools),
        now_secs(),
        keep_days(tools).0,
        cap(tools).0,
    )
}

/// A connection by its instance and its own ends, and when it was first
/// seen (ports are used again).
type Seen = (String, u8, u16, String, u16, u32);

fn seen_of(e: &Entry) -> Seen {
    let k = &e.flow.key;
    (
        e.instance.clone(),
        k.proto,
        k.lport,
        k.remote.to_string(),
        k.rport,
        e.flow.first,
    )
}

/// A field of the container's own words, on one line of its own.
fn field(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn read_programs(path: &Path) -> Programs {
    let text = fs::read_to_string(path).unwrap_or_default();
    let mut day = Programs::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let [who, program, out, inb] = f.as_slice() else {
            continue;
        };
        if let (Ok(out), Ok(inb)) = (out.parse::<u64>(), inb.parse::<u64>()) {
            let e = day
                .entry(((*who).to_owned(), (*program).to_owned()))
                .or_default();
            e.0 = e.0.saturating_add(out);
            e.1 = e.1.saturating_add(inb);
        }
    }
    day
}

fn write_atomically(path: &Path, text: &str) -> io::Result<()> {
    let tmp = path.with_extension("new");
    fs::write(&tmp, text).and_then(|()| fs::rename(&tmp, path))
}

/// The day files of `dir` (`YYYY-MM-DD`), oldest first, with their sizes.
fn days_in(dir: &Path) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_str()?.to_owned();
            (name.len() == 10 && name.as_bytes()[4] == b'-')
                .then(|| (name, e.metadata().map_or(0, |m| m.len())))
        })
        .collect();
    out.sort();
    out
}

fn record_entries(
    state: &Path,
    entries: &[Entry],
    now: u64,
    keep: u64,
    cap: u64,
) -> io::Result<()> {
    let base = state.join(NETLOG);
    let (raw, programs) = (base.join(RAW), base.join(PROGRAMS));
    fs::create_dir_all(&raw)?;
    fs::create_dir_all(&programs)?;
    let last_text = fs::read_to_string(base.join(LAST)).unwrap_or_default();
    let last: HashMap<Seen, (u64, u64)> = last_text
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            let [id, proto, lport, remote, rport, first, out, inb] = f.as_slice() else {
                return None;
            };
            Some((
                (
                    (*id).to_owned(),
                    proto.parse().ok()?,
                    lport.parse().ok()?,
                    (*remote).to_owned(),
                    rport.parse().ok()?,
                    first.parse().ok()?,
                ),
                (out.parse().ok()?, inb.parse().ok()?),
            ))
        })
        .collect();
    let date = local_date(now);
    let today = programs.join(&date);
    let mut day = read_programs(&today);
    let (mut lines, mut seen) = (String::new(), String::new());
    for e in entries {
        let s = seen_of(e);
        let f = &e.flow;
        let (out, inb) = match last.get(&s) {
            Some((o, i)) => (
                f.out_bytes.saturating_sub(*o),
                f.in_bytes.saturating_sub(*i),
            ),
            None => (f.out_bytes, f.in_bytes),
        };
        seen.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            s.0, s.1, s.2, s.3, s.4, s.5, f.out_bytes, f.in_bytes
        ));
        if out == 0 && inb == 0 {
            continue;
        }
        let (container, program) = (field(&e.container), field(&e.program));
        lines.push_str(&format!(
            "{now}\t{container}\t{}\t{}\t{}\t{}\t{}\t{program}\t{out}\t{inb}\n",
            field(&e.network),
            crate::flows::proto_name(f.key.proto),
            f.key.remote,
            f.key.rport,
            field(&e.name),
        ));
        let d = day.entry((container, program)).or_default();
        d.0 = d.0.saturating_add(out);
        d.1 = d.1.saturating_add(inb);
    }
    let text: String = day
        .iter()
        .map(|((who, program), (out, inb))| format!("{who}\t{program}\t{out}\t{inb}\n"))
        .collect();
    write_atomically(&today, &text)?;
    write_atomically(&base.join(LAST), &seen)?;
    // The raw journal: the days past their keep; then the oldest, while it
    // is over its cap; today's is written only while under it.
    let oldest = local_date(now.saturating_sub(keep.saturating_sub(1) * 86_400));
    let mut days = days_in(&raw);
    for (name, _) in days.iter().filter(|(n, _)| n.as_str() < oldest.as_str()) {
        let _ = fs::remove_file(raw.join(name));
    }
    days.retain(|(n, _)| n.as_str() >= oldest.as_str());
    let mut total: u64 = days.iter().map(|(_, n)| n).sum();
    let mut at = 0;
    while total.saturating_add(lines.len() as u64) > cap && at < days.len() && days[at].0 != date {
        let _ = fs::remove_file(raw.join(&days[at].0));
        total = total.saturating_sub(days[at].1);
        at += 1;
    }
    if !lines.is_empty() && total.saturating_add(lines.len() as u64) <= cap {
        OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(raw.join(&date))?
            .write_all(lines.as_bytes())?;
    }
    // The programs' summaries past their keep.
    let oldest = local_date(now.saturating_sub(crate::traffic::KEEP_DAYS * 86_400));
    for (name, _) in days_in(&programs) {
        if name.as_str() < oldest.as_str() {
            let _ = fs::remove_file(programs.join(name));
        }
    }
    Ok(())
}

/// What each program of each container used over the last `n` days,
/// today included, and from which day.
pub fn programs_over(state: &Path, n: u64, now: u64) -> (String, Programs) {
    let dir = state.join(NETLOG).join(PROGRAMS);
    let from = local_date(now.saturating_sub(n.saturating_sub(1) * 86_400));
    let mut total = Programs::new();
    for (name, _) in days_in(&dir) {
        if name.as_str() < from.as_str() {
            continue;
        }
        for (k, (out, inb)) in read_programs(&dir.join(&name)) {
            let e = total.entry(k).or_default();
            e.0 = e.0.saturating_add(out);
            e.1 = e.1.saturating_add(inb);
        }
    }
    (from, total)
}

/// What each program of each container used today.
pub fn used_today(state: &Path) -> Programs {
    programs_over(state, 1, now_secs()).1
}

/// A program as the summaries name it, for a person: its label, its key, a
/// process's name, or «не найдена».
pub fn program_text(state: &Path, program: &str) -> String {
    if program == "?" {
        return "программа не найдена".to_owned();
    }
    if let Some(process) = program.strip_prefix('~') {
        return format!("процесс {process}");
    }
    crate::cli::read_setting(&state.join(".labels").join(program))
        .unwrap_or_else(|| program.to_owned())
}

fn programs_json(n: u64, from: &str, total: &Programs) -> String {
    use crate::status::string;
    let items: Vec<String> = total
        .iter()
        .map(|((who, program), (out, inb))| {
            format!(
                "{{\"container\":{},\"program\":{},\"out_bytes\":{out},\"in_bytes\":{inb}}}",
                string(who),
                string(program)
            )
        })
        .collect();
    format!(
        "{{\"schema_version\":{},\"days\":{n},\"from\":{},\"programs\":[{}]}}",
        crate::status::SCHEMA_VERSION,
        string(from),
        items.join(",")
    )
}

fn programs_text(state: &Path, n: u64, from: &str, total: &Programs) -> String {
    use crate::traffic::bytes_text;
    if total.is_empty() {
        return format!("с {from} ({n} дн.) ничего не записано\n");
    }
    let mut rows: Vec<_> = total.iter().collect();
    rows.sort_by_key(|(_, (o, i))| std::cmp::Reverse(o.saturating_add(*i)));
    let mut out = format!("с {from} ({n} дн.):\n");
    for ((who, program), (o, i)) in rows {
        out.push_str(&format!(
            "{who} · {}: ↑ {} · ↓ {}\n",
            program_text(state, program),
            bytes_text(*o),
            bytes_text(*i)
        ));
    }
    out
}

/// `cellward traffic --programs [--days N] [--json]`.
pub fn report_programs(tools: &Tools, days: u64, json: bool) -> u8 {
    let (from, total) = programs_over(&tools.state, days, now_secs());
    if json {
        println!("{}", programs_json(days, &from, &total));
    } else {
        print!("{}", programs_text(&tools.state, days, &from, &total));
    }
    0
}

const USAGE: &str = "cellward netlog                  сколько хранится журнал соединений\n\
                     cellward netlog keep <дни>|default   сколько дней (1–3650; по умолчанию 30)\n\
                     cellward netlog cap <размер>|default сколько места (512M, 2G; по умолчанию 1G)";

/// `cellward netlog [keep <days>|cap <size>]`: how long, and how large, the
/// connections' journal is kept.
pub fn run(tools: &Tools, args: &[OsString]) -> u8 {
    use crate::container::Source;
    let from = |s: Source, nix: &str| match s {
        Source::Local => String::new(),
        Source::Nix => format!(" (задано в Nix: programs.cellward.netlog.{nix})"),
        Source::Default => " (умолчание)".to_owned(),
    };
    let args: Vec<&str> = args.iter().map(|a| a.to_str().unwrap_or("")).collect();
    let (setting, value) = match args.as_slice() {
        [] => {
            let (days, ks) = keep_days(tools);
            let (bytes, cs) = cap(tools);
            let used: u64 = days_in(&tools.state.join(NETLOG).join(RAW))
                .iter()
                .map(|(_, n)| n)
                .sum();
            println!(
                "журнал соединений хранится {days} дн.{}",
                from(ks, "keepDays")
            );
            println!(
                "и занимает не больше {}{} — сейчас {}",
                crate::traffic::bytes_text(bytes),
                from(cs, "maxSize"),
                crate::traffic::bytes_text(used)
            );
            return 0;
        }
        ["keep", v] => (KEEP_SETTING, *v),
        ["cap", v] => (CAP_SETTING, *v),
        _ => {
            eprintln!("{USAGE}");
            return 1;
        }
    };
    let valid = match setting {
        KEEP_SETTING => value
            .parse::<u64>()
            .ok()
            .filter(|d| (1..=3650).contains(d))
            .map(|d| d.to_string()),
        _ => parse_size(value)
            .filter(|n| *n >= 1 << 20)
            .map(|_| value.trim().to_owned()),
    };
    let written = if value == "default" {
        crate::cli::reset_setting(tools, setting)
    } else if let Some(v) = valid {
        crate::cli::write_setting(tools, setting, OsStr::new(&v))
    } else {
        Err(format!("«{value}»: {USAGE}"))
    };
    match written {
        Ok(()) => run(tools, &[]),
        Err(e) => {
            eprintln!("cellward netlog: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flows::{Key, TCP, UDP};

    fn entry(lport: u16, remote: &str, first: u32, out: u64, inb: u64, program: &str) -> Entry {
        Entry {
            instance: "work".to_owned(),
            container: "work".to_owned(),
            network: "nl".to_owned(),
            flow: Flow {
                key: Key {
                    proto: TCP,
                    lport,
                    remote: remote.parse().unwrap(),
                    rport: 443,
                },
                first,
                last: first,
                out_bytes: out,
                in_bytes: inb,
                out_packets: 1,
                in_packets: 1,
            },
            name: "example.org".to_owned(),
            program: program.to_owned(),
        }
    }

    fn state(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("vz-connlog-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn sizes_are_read_as_a_person_says_them() {
        assert_eq!(parse_size("1G"), Some(1 << 30));
        assert_eq!(parse_size("512M"), Some(512 << 20));
        assert_eq!(parse_size("2 GiB"), Some(2 << 30));
        assert_eq!(parse_size("4096"), Some(4096));
        assert_eq!(parse_size("1X"), None);
        assert_eq!(parse_size(""), None);
        assert_eq!(parse_size("99999999999T"), None);
    }

    /// A connection's bytes since the record before, once; its program's
    /// day summed; a connection that did nothing since, no line.
    #[test]
    fn a_record_writes_what_each_connection_did_since() {
        let st = state("rec");
        let now = 1_790_000_000;
        let a = entry(40000, "192.0.2.1", 100, 1000, 5000, "firefox");
        let b = entry(40001, "192.0.2.2", 100, 10, 20, "~curl");
        record_entries(&st, &[a.clone(), b.clone()], now, 30, RAW_CAP).unwrap();
        let mut a2 = a.clone();
        a2.flow.out_bytes = 1500;
        record_entries(&st, &[a2, b], now + 60, 30, RAW_CAP).unwrap();
        let date = local_date(now);
        let raw = fs::read_to_string(st.join(NETLOG).join(RAW).join(&date)).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 3, "{raw}");
        assert_eq!(
            lines[2],
            format!(
                "{}\twork\tnl\ttcp\t192.0.2.1\t443\texample.org\tfirefox\t500\t0",
                now + 60
            )
        );
        let (_, total) = programs_over(&st, 1, now + 60);
        assert_eq!(
            total[&("work".to_owned(), "firefox".to_owned())],
            (1500, 5000)
        );
        assert_eq!(total[&("work".to_owned(), "~curl".to_owned())], (10, 20));
        // A port used again later is another connection.
        let again = entry(40000, "192.0.2.1", 900, 7, 7, "firefox");
        record_entries(&st, &[again], now + 120, 30, RAW_CAP).unwrap();
        let (_, total) = programs_over(&st, 1, now + 120);
        assert_eq!(
            total[&("work".to_owned(), "firefox".to_owned())],
            (1507, 5007)
        );
        let _ = fs::remove_dir_all(&st);
    }

    /// Days past the keep go; over the cap, the oldest go first, and today
    /// is written only while under it.
    #[test]
    fn the_journal_keeps_its_days_and_its_size() {
        let st = state("keep");
        let raw = st.join(NETLOG).join(RAW);
        fs::create_dir_all(&raw).unwrap();
        let now = 1_790_000_000;
        let day = |ago: u64| local_date(now - ago * 86_400);
        for ago in [40, 10, 5] {
            fs::write(raw.join(day(ago)), vec![b'x'; 3000]).unwrap();
        }
        let mut e = entry(40000, "192.0.2.1", 100, 10, 10, "firefox");
        e.flow.key.proto = UDP;
        record_entries(&st, &[e.clone()], now, 30, 6000).unwrap();
        let names: Vec<String> = days_in(&raw).into_iter().map(|(n, _)| n).collect();
        // The 40-day-old one past the keep; the 10-day-old over the cap.
        assert_eq!(names, vec![day(5), day(0)], "{names:?}");
        // A cap today alone reaches: today not written further.
        e.flow.out_bytes = 20;
        let before = fs::read_to_string(raw.join(day(0))).unwrap();
        record_entries(&st, &[e], now + 60, 30, before.len() as u64 + 10).unwrap();
        assert_eq!(fs::read_to_string(raw.join(day(0))).unwrap(), before);
        let _ = fs::remove_dir_all(&st);
    }
}
