//! The host without a network of its own (ROADMAP M10 stage 5,
//! `docs/SYSTEM.md` §9): a user's program that runs outside every zone does
//! not reach the network.
//!
//! **Who is let out, and why by owner.** The threat is a user's program on the
//! host — something started past the launcher, a script, a terminal. Root and
//! the system's own users (below 1000, and systemd's dynamic range) are the
//! administration and keep their network; which of those services may go out,
//! and where, is a per-service switch, not this. What the policy looks at is
//! the owner of the socket a packet leaves from:
//!
//! * root and system users — out;
//! * a user zone's uplink — pasta, started by the zone holder as uid 0 of the
//!   zone's user namespace, i.e. the first uid of the user's `/etc/subuid`
//!   range on the host (`zone::uplink_owner`) — out;
//! * a system zone's tunnel — its UDP socket is the kernel's own and has no
//!   owner, so the tunnel marks its packets (`system::TUNNEL_MARK`) — out;
//! * programs in any zone — they are in the zone's namespace and never pass
//!   this hook at all;
//! * the users and groups named in the module (`nixbld` for builds; a person
//!   who is moving over gradually) — out;
//! * anybody else: logged, and in `enforce` refused.
//!
//! Owners and not cgroups on purpose: a cgroup set (`NFTSet=`) is filled by
//! systemd when a unit starts and emptied by every firewall reload that flushes
//! the ruleset, and a policy that silently stops recognising what it allows
//! breaks the machine or lets everything through. A uid does not change.
//!
//! `audit` is the default: the same rules, logged and let through, so that a
//! machine can be watched before it is locked.
//!
//! **`strict`: the host itself, too.** Root and the system's users keep only
//! the local network (`--local`: private, link-local and multicast ranges by
//! default) and DHCP. What of the system has to reach further goes through a
//! zone like everything else — the Nix daemon and the clock through a plain
//! zone ("directly") or a VPN one, attached by the module; a plain zone's
//! pasta is let out by its owner (`--user vpn-zones-plain`). What is left on
//! the host and wants the internet is refused and logged, root included.
//! Against a program that does not know, not against root: root can load a
//! ruleset of its own.
//!
//! **Our binary cannot open the host.** The restriction is printed once, when
//! the system is built (`print`), and loaded by `nft` from that file; this
//! binary only ADDS allowances to it afterwards (`allow`). If it crashes, the
//! allowances are missing and the host is more closed than meant — user zones
//! lose their way out, as with a dropped tunnel — never open. The emergency key
//! closes the host again from the same file.

use std::ffi::{CString, OsString};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The table; the policy lives in it and nowhere else.
pub const TABLE: &str = "vpnzones_egress";
/// The prefix of every log line — what a tool reads the journal for.
pub const LOG_PREFIX: &str = "vpn-zones-egress: ";
/// systemd's range for `DynamicUser=` (systemd.exec(5)).
const DYNAMIC_UIDS: (u32, u32) = (61_184, 65_519);

/// What the ruleset is made of.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// Refuse, or only log.
    pub enforce: bool,
    /// Root and the system's users too: the local network only.
    pub strict: bool,
    /// The local network, for `strict`: prefixes, checked (`parse_prefix`).
    pub local: Vec<String>,
    /// The emergency key: the table stays, the restriction does not.
    pub open: bool,
    /// Owners let out besides root and system users.
    pub uids: Vec<u32>,
    pub gids: Vec<u32>,
}

/// The ruleset, as `nft -f` takes it: the old table destroyed and the new one
/// made in one transaction, so there is no moment without either.
pub fn ruleset(policy: &Policy) -> String {
    // `add` then `delete`: the table gone whether it was there or not, in any
    // nft and kernel — `destroy` needs nft 1.0.8 and Linux 6.3, and a file
    // that does not load leaves the host with no policy at all (review).
    let mut out =
        format!("add table inet {TABLE}\ndelete table inet {TABLE}\ntable inet {TABLE} {{\n");
    let set = |out: &mut String, name: &str, kind: &str, ids: &[u32]| {
        out.push_str(&format!("\tset {name} {{\n\t\ttype {kind}\n"));
        if !ids.is_empty() {
            let list: Vec<String> = ids.iter().map(u32::to_string).collect();
            out.push_str(&format!("\t\telements = {{ {} }}\n", list.join(", ")));
        }
        out.push_str("\t}\n");
    };
    set(&mut out, "users", "uid", &policy.uids);
    set(&mut out, "groups", "gid", &policy.gids);
    if policy.strict {
        for (name, kind, v6) in [
            ("local4", "ipv4_addr", false),
            ("local6", "ipv6_addr", true),
        ] {
            let list: Vec<&str> = policy
                .local
                .iter()
                .filter(|p| p.contains(':') == v6)
                .map(String::as_str)
                .collect();
            out.push_str(&format!(
                "\tset {name} {{\n\t\ttype {kind}\n\t\tflags interval\n\t\tauto-merge\n"
            ));
            if !list.is_empty() {
                out.push_str(&format!("\t\telements = {{ {} }}\n", list.join(", ")));
            }
            out.push_str("\t}\n");
        }
    }
    out.push_str("\tchain output {\n");
    // After conntrack (-200), before mangle (-150): a DPI bypass steering
    // packets there sees only what was let through here.
    out.push_str("\t\ttype filter hook output priority -160; policy accept;\n");
    if policy.open {
        out.push_str(&format!(
            "\t\tlimit rate 1/minute log prefix \"{LOG_PREFIX}OPEN \"\n"
        ));
        out.push_str("\t}\n}\n");
        return out;
    }
    let system_owners = [
        "meta skuid < 1000".to_owned(),
        format!("meta skuid {}-{}", DYNAMIC_UIDS.0, DYNAMIC_UIDS.1),
    ];
    let system_rules: Vec<String> = if policy.strict {
        // DHCP by port: a renewal goes to the server's own address, which
        // need not be a private one.
        let mut rules = vec![
            // The DHCP clients are the system's: a service able to bind
            // port 68 would otherwise have a way to anywhere (review).
            "meta skuid < 1000 udp sport 68 udp dport 67 accept".to_owned(),
            "meta skuid < 1000 udp sport 546 udp dport 547 accept".to_owned(),
        ];
        for owner in &system_owners {
            rules.push(format!("{owner} ip daddr @local4 accept"));
            rules.push(format!("{owner} ip6 daddr @local6 accept"));
        }
        rules
    } else {
        system_owners
            .iter()
            .map(|o| format!("{o} accept"))
            .collect()
    };
    for rule in [
        "ct state established,related accept".to_owned(),
        "oifname \"lo\" accept".to_owned(),
    ]
    .into_iter()
    .chain(system_rules)
    .chain([
        "meta skuid @users accept".to_owned(),
        "meta skgid @groups accept".to_owned(),
        // A system zone's tunnel: the kernel's own UDP socket has no owner,
        // so its packets carry a mark instead (`system::TUNNEL_MARK`).
        format!("meta mark {:#x} accept", crate::system::TUNNEL_MARK),
        // The kernel's own, with no socket and so no owner: neighbour
        // discovery and group membership.
        "icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, \
         mld-listener-report, mld2-listener-report } accept"
            .to_owned(),
        "ip protocol igmp accept".to_owned(),
        format!("limit rate 10/second burst 20 packets log prefix \"{LOG_PREFIX}\" flags skuid"),
    ]) {
        out.push_str("\t\t");
        out.push_str(&rule);
        out.push('\n');
    }
    if policy.enforce || policy.strict {
        // Refused at once rather than dropped: a program fails in a moment
        // instead of hanging until its own timeout.
        out.push_str("\t\treject with icmpx admin-prohibited\n");
    }
    out.push_str("\t}\n}\n");
    out
}

/// Allowances added to a loaded policy: the elements of its two sets. Empty
/// when there is nothing to add. What this cannot do is lift the restriction —
/// the policy's own rules come from a file `nft` loads by itself, so our
/// binary failing leaves the host MORE closed, never open.
pub fn allow_text(uids: &[u32], gids: &[u32]) -> String {
    let mut out = String::new();
    for (set, ids) in [("users", uids), ("groups", gids)] {
        if ids.is_empty() {
            continue;
        }
        let list: Vec<String> = ids.iter().map(u32::to_string).collect();
        out.push_str(&format!(
            "add element inet {TABLE} {set} {{ {} }}\n",
            list.join(", ")
        ));
    }
    out
}

/// The first uid of every range in `/etc/subuid` (or gid in `/etc/subgid`):
/// the owners of user zones' uplinks.
pub fn subid_starts(text: &str) -> Vec<u32> {
    let mut out: Vec<u32> = text
        .lines()
        .filter_map(|line| {
            let mut fields = line.trim().split(':');
            let (_name, start) = (fields.next()?, fields.next()?);
            fields.next()?.parse::<u32>().ok()?;
            start.parse().ok()
        })
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// A prefix of the local network as nft takes it — `10.0.0.0/8`, `fe80::/10`,
/// or a single address. Checked here, when the system is built: a ruleset
/// `nft` refuses at boot would leave the host with no policy at all.
pub fn parse_prefix(text: &str) -> Result<String, String> {
    let (addr, len) = match text.split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (text, None),
    };
    let addr: std::net::IpAddr = addr
        .parse()
        .map_err(|_| format!("{text}: not an address or a prefix"))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let len = match len {
        None => max,
        Some(l) => l
            .parse::<u8>()
            .ok()
            .filter(|l| *l <= max)
            .ok_or_else(|| format!("{text}: the prefix length is 0 to {max}"))?,
    };
    // The host bits cleared: `10.1.2.3/8` is `10.0.0.0/8`, which nft takes
    // as it is.
    let addr = match addr {
        std::net::IpAddr::V4(a) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            std::net::IpAddr::V4((u32::from(a) & mask).into())
        }
        std::net::IpAddr::V6(a) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            std::net::IpAddr::V6((u128::from(a) & mask).into())
        }
    };
    Ok(format!("{addr}/{len}"))
}

/// What `vpn-zone-core egress` was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub verb: Verb,
    pub nft: PathBuf,
    pub enforce: bool,
    pub strict: bool,
    pub local: Vec<String>,
    pub users: Vec<String>,
    pub groups: Vec<String>,
    /// Groups by number, for `print`: known when the system is built.
    pub gids: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// Print the restriction, with only the ids given as flags — what the
    /// module loads with `nft` alone, from a file built with the system.
    Print,
    /// Add the allowances that need the running system — the uplinks of
    /// user zones, named users and groups — to a loaded policy.
    Allow,
    /// Load the policy (again), restriction and allowances at once: by hand.
    Apply,
    /// Keep the table, lift the restriction: the emergency key.
    Open,
    /// The table gone.
    Remove,
}

impl Args {
    /// `<verb> [--nft P] [--enforce|--strict] [--local PREFIX]… [--user NAME]…
    /// [--group NAME]… [--gid N]…`
    pub fn parse(argv: &[OsString]) -> Result<Self, String> {
        let mut rest = argv.iter();
        let verb = match rest.next().and_then(|v| v.to_str()) {
            Some("apply") => Verb::Apply,
            Some("open") => Verb::Open,
            Some("print") => Verb::Print,
            Some("allow") => Verb::Allow,
            Some("remove") => Verb::Remove,
            _ => return Err("need a verb: print, allow, apply, open or remove".to_owned()),
        };
        let mut args = Self {
            verb,
            nft: PathBuf::from("nft"),
            enforce: false,
            strict: false,
            local: Vec::new(),
            users: Vec::new(),
            groups: Vec::new(),
            gids: Vec::new(),
        };
        while let Some(arg) = rest.next() {
            let arg = arg.to_str().ok_or("the arguments have to be UTF-8")?;
            if arg == "--enforce" {
                args.enforce = true;
                continue;
            }
            if arg == "--strict" {
                args.strict = true;
                continue;
            }
            let value = rest
                .next()
                .and_then(|v| v.to_str())
                .ok_or_else(|| format!("{arg} needs a value"))?
                .to_owned();
            match arg {
                "--nft" => args.nft = PathBuf::from(value),
                "--user" => args.users.push(value),
                "--group" => args.groups.push(value),
                "--local" => args.local.push(parse_prefix(&value)?),
                "--gid" => args.gids.push(
                    value
                        .parse()
                        .map_err(|_| format!("--gid {value}: not a number"))?,
                ),
                _ => return Err(format!("unknown flag: {arg}")),
            }
        }
        Ok(args)
    }
}

/// Run one verb. Returns the exit code for the process.
pub fn run(args: &Args) -> u8 {
    if args.verb == Verb::Print {
        print!(
            "{}",
            ruleset(&Policy {
                enforce: args.enforce,
                strict: args.strict,
                local: args.local.clone(),
                open: false,
                uids: Vec::new(),
                gids: args.gids.clone(),
            })
        );
        return 0;
    }
    let text = match args.verb {
        Verb::Remove => format!("add table inet {TABLE}\ndelete table inet {TABLE}\n"),
        Verb::Allow => {
            let policy = policy_of(args);
            allow_text(&policy.uids, &policy.gids)
        }
        Verb::Apply | Verb::Open | Verb::Print => ruleset(&policy_of(args)),
    };
    if text.is_empty() {
        println!("host egress policy: nothing to allow besides root and system users");
        return 0;
    }
    match feed(&args.nft, &text) {
        Ok(()) => {
            println!(
                "{}",
                match (args.verb, args.enforce || args.strict) {
                    (Verb::Remove, _) => "host egress policy removed".to_owned(),
                    (Verb::Allow, _) => "host egress policy: user zones' uplinks and the \
                                         named owners allowed"
                        .to_owned(),
                    (Verb::Print, _) => String::new(),
                    (Verb::Open, _) => "host egress policy OPEN: programs of users outside \
                                        zones reach the network until it is applied again"
                        .to_owned(),
                    (Verb::Apply, true) if args.strict => {
                        "host egress policy strict: the host keeps its local network only"
                            .to_owned()
                    }
                    (Verb::Apply, true) => "host egress policy enforced".to_owned(),
                    (Verb::Apply, false) =>
                        "host egress policy auditing (logs, lets through)".to_owned(),
                }
            );
            0
        }
        Err(e) => {
            eprintln!("host egress policy: {e}");
            1
        }
    }
}

/// The owners from the arguments and the system: named users and groups that
/// exist (a missing one is said, not fatal — a policy that fails to load lets
/// everything through), and the first ids of every subordinate range.
fn policy_of(args: &Args) -> Policy {
    let mut uids: Vec<u32> = fs::read_to_string("/etc/subuid")
        .map(|t| subid_starts(&t))
        .unwrap_or_default();
    for name in &args.users {
        match user_id(name) {
            Some(uid) => uids.push(uid),
            None => eprintln!("host egress policy: no user {name}, skipped"),
        }
    }
    let mut gids: Vec<u32> = fs::read_to_string("/etc/subgid")
        .map(|t| subid_starts(&t))
        .unwrap_or_default();
    for name in &args.groups {
        match group_id(name) {
            Some(gid) => gids.push(gid),
            None => eprintln!("host egress policy: no group {name}, skipped"),
        }
    }
    uids.sort_unstable();
    uids.dedup();
    gids.sort_unstable();
    gids.dedup();
    Policy {
        enforce: args.enforce,
        strict: args.strict,
        local: args.local.clone(),
        open: args.verb == Verb::Open,
        uids,
        gids,
    }
}

pub(crate) fn user_id(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;
    // SAFETY: getpwnam returns a pointer into a static buffer, read at once.
    unsafe {
        let pw = libc::getpwnam(name.as_ptr());
        if pw.is_null() {
            None
        } else {
            Some((*pw).pw_uid)
        }
    }
}

pub(crate) fn group_id(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;
    // SAFETY: getgrnam returns a pointer into a static buffer, read at once.
    unsafe {
        let gr = libc::getgrnam(name.as_ptr());
        if gr.is_null() {
            None
        } else {
            Some((*gr).gr_gid)
        }
    }
}

/// `nft -f -`, the ruleset on stdin.
fn feed(nft: &Path, text: &str) -> Result<(), String> {
    let mut child = Command::new(nft)
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", nft.display()))?;
    let fed = match child.stdin.take() {
        Some(mut pipe) => pipe
            .write_all(text.as_bytes())
            .map_err(|e| format!("cannot hand the ruleset to nft: {e}")),
        None => Err("nft was given no stdin".to_owned()),
    };
    let status = child
        .wait()
        .map_err(|e| format!("cannot wait for {}: {e}", nft.display()))?;
    fed?;
    if !status.success() {
        return Err(format!("{} -f - failed ({status})", nft.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }

    #[test]
    fn audit_logs_and_lets_through() {
        let text = ruleset(&Policy {
            uids: vec![100_000],
            gids: vec![30_000],
            ..Policy::default()
        });
        assert!(
            text.starts_with("add table inet vpnzones_egress\ndelete table inet vpnzones_egress\n")
        );
        assert!(!text.contains("destroy"), "{text}");
        assert!(text.contains("priority -160; policy accept;"));
        assert!(text.contains("elements = { 100000 }"));
        assert!(text.contains("elements = { 30000 }"));
        assert!(text.contains("meta skuid < 1000 accept"));
        assert!(text.contains("meta skuid 61184-65519 accept"));
        assert!(text.contains("meta mark 0x767a accept"));
        assert!(text.contains("log prefix \"vpn-zones-egress: \" flags skuid"));
        assert!(!text.contains("reject"), "{text}");
    }

    #[test]
    fn enforce_refuses_what_it_logs() {
        let text = ruleset(&Policy {
            enforce: true,
            ..Policy::default()
        });
        let log = text.find("flags skuid").unwrap();
        let reject = text.find("reject with icmpx admin-prohibited").unwrap();
        assert!(log < reject, "the log comes first:\n{text}");
        // Nothing but the chain's own lines follows the refusal.
        assert!(text[reject..].lines().skip(1).all(|l| l.trim() == "}"));
        // Empty sets are declared without elements.
        assert!(!text.contains("elements = {  }"));
    }

    #[test]
    fn strict_keeps_the_host_to_its_local_network() {
        let text = ruleset(&Policy {
            strict: true,
            local: vec![
                "10.0.0.0/8".into(),
                "fe80::/10".into(),
                "192.168.0.0/16".into(),
            ],
            ..Policy::default()
        });
        // Root and system users: no blanket allowance any more.
        assert!(!text.contains("meta skuid < 1000 accept"), "{text}");
        assert!(!text.contains("meta skuid 61184-65519 accept"), "{text}");
        assert!(text.contains("meta skuid < 1000 ip daddr @local4 accept"));
        assert!(text.contains("meta skuid < 1000 ip6 daddr @local6 accept"));
        assert!(text.contains("meta skuid 61184-65519 ip daddr @local4 accept"));
        assert!(text.contains("elements = { 10.0.0.0/8, 192.168.0.0/16 }"));
        assert!(text.contains("elements = { fe80::/10 }"));
        assert!(text.contains("flags interval"));
        assert!(text.contains("meta skuid < 1000 udp sport 68 udp dport 67 accept"));
        // The ways out that are not the host's own stay as they are.
        assert!(text.contains("meta mark 0x767a accept"));
        assert!(text.contains("meta skuid @users accept"));
        // Strict refuses, whatever `enforce` says.
        assert!(text.contains("reject with icmpx admin-prohibited"));
        // No local sets outside strict.
        let enforce = ruleset(&Policy {
            enforce: true,
            local: vec!["10.0.0.0/8".into()],
            ..Policy::default()
        });
        assert!(!enforce.contains("local4"), "{enforce}");
    }

    #[test]
    fn local_prefixes_are_checked_when_built() {
        assert_eq!(parse_prefix("10.0.0.0/8").unwrap(), "10.0.0.0/8");
        assert_eq!(parse_prefix("192.168.1.1").unwrap(), "192.168.1.1/32");
        assert_eq!(parse_prefix("fe80::/10").unwrap(), "fe80::/10");
        assert_eq!(parse_prefix("ff02::1:2").unwrap(), "ff02::1:2/128");
        assert_eq!(parse_prefix("10.1.2.3/8").unwrap(), "10.0.0.0/8");
        assert_eq!(parse_prefix("0.0.0.0/0").unwrap(), "0.0.0.0/0");
        assert_eq!(parse_prefix("fe80::1/10").unwrap(), "fe80::/10");
        for bad in [
            "10.0.0.0/33",
            "fe80::/129",
            "10.0.0/8",
            "x",
            "10.0.0.0/",
            "10.0.0.0/8; flush ruleset",
        ] {
            assert!(parse_prefix(bad).is_err(), "{bad}");
        }
        let args = Args::parse(&os(&["print", "--strict", "--local", "10.0.0.0/8"])).unwrap();
        assert!(args.strict);
        assert_eq!(args.local, ["10.0.0.0/8"]);
        assert!(Args::parse(&os(&["print", "--local", "nope"])).is_err());
    }

    #[test]
    fn the_emergency_key_keeps_the_table_and_lifts_the_rest() {
        let text = ruleset(&Policy {
            enforce: true,
            open: true,
            uids: vec![100_000],
            ..Policy::default()
        });
        assert!(text.contains("table inet vpnzones_egress"));
        assert!(text.contains("OPEN"));
        assert!(!text.contains("reject"), "{text}");
        assert!(!text.contains("meta skuid"), "{text}");
    }

    #[test]
    fn allowances_only_add_elements() {
        assert_eq!(
            allow_text(&[100_000, 1000], &[30_000]),
            "add element inet vpnzones_egress users { 100000, 1000 }\n\
             add element inet vpnzones_egress groups { 30000 }\n"
        );
        assert_eq!(allow_text(&[], &[]), "");
        assert!(!allow_text(&[1], &[2]).contains("delete"));
        assert!(!allow_text(&[1], &[2]).contains("destroy"));
    }

    #[test]
    fn subordinate_ranges_give_their_first_ids() {
        assert_eq!(
            subid_starts(
                "alice:100000:65536\nbob:165536:65536\nbroken\nx:y:1\nalice:100000:65536\n"
            ),
            vec![100_000, 165_536]
        );
        assert!(subid_starts("").is_empty());
    }

    #[test]
    fn the_command_line() {
        let args = Args::parse(&os(&[
            "apply",
            "--nft",
            "/x/nft",
            "--enforce",
            "--user",
            "alice",
            "--group",
            "nixbld",
        ]))
        .unwrap();
        assert_eq!(args.verb, Verb::Apply);
        assert!(args.enforce);
        assert_eq!(args.nft, PathBuf::from("/x/nft"));
        assert_eq!(args.users, ["alice"]);
        assert_eq!(args.groups, ["nixbld"]);
        assert_eq!(Args::parse(&os(&["open"])).unwrap().verb, Verb::Open);
        assert_eq!(Args::parse(&os(&["remove"])).unwrap().verb, Verb::Remove);
        let print = Args::parse(&os(&["print", "--enforce", "--gid", "30000"])).unwrap();
        assert_eq!((print.verb, print.gids), (Verb::Print, vec![30_000]));
        assert!(Args::parse(&os(&["print", "--gid", "x"])).is_err());
        assert_eq!(Args::parse(&os(&["allow"])).unwrap().verb, Verb::Allow);
        assert!(Args::parse(&os(&[])).is_err());
        assert!(Args::parse(&os(&["apply", "--user"])).is_err());
        assert!(Args::parse(&os(&["apply", "--other", "x"])).is_err());
    }
}
