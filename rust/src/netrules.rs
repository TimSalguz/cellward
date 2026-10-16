//! A container's network rules by program (`docs/FIREWALL.md` §4, §9 stage
//! 4, 2026-09-29): whether a program of it may open connections at all.
//!
//! **Where.** The container's record (`crate::container`): `net_allow =
//! <program>` and `net_deny = <program>` lines, a program each — by its
//! launcher key, as the registry of launches knows it —, and `net_default =
//! allow|deny` for a program with no line. Nix's declaration
//! (`containers.<c>.firewall`, `declared/containers/<c>.conf`) and the local
//! record (`cellward container net`) both: a program Nix names is Nix's; a
//! local "deny" narrows a Nix "allow" (step 0 of the permission model: a
//! local word closes under Nix, never opens). The main home's record
//! (`container::MAIN_RECORD`) has them as any container.
//!
//! **What decides.** The instance's keeper, for each new flow, by the flow's
//! program (`crate::owners`): the verdict goes to its relay
//! (`crate::verdicts`), which holds the flow's first frames until then. A
//! flow whose program is not found gets the container's default. The
//! default without a word of the record's is the permissions' template's
//! (`network`: `yes|no|ask`, `crate::permissions`), "ask" without one
//! (the owner, 2026-09-28): the keeper asks the person (§4.3). «Без
//! изоляции» (`container::OPEN_RECORD`) always has the network.
//!
//! What this is not: a way around the network. A rule only narrows what the
//! container's network carries; it opens nothing the network does not.

use std::path::Path;

use crate::container::Source;
use crate::verdicts::Verdict;

const ALLOW: &str = "net_allow";
const DENY: &str = "net_deny";
const DEFAULT: &str = "net_default";
/// A destination none of the container's programs reaches ([`Block`]).
const BLOCK: &str = "net_block";

/// A destination blocked for a container (the owner, 2026-10-15): a name,
/// with every name below it; an address; a network. Decided by the keeper
/// for every new flow before its program's rule (`zone`): a flow to a
/// blocked address, or to an address a DNS answer gave for a blocked name,
/// is denied, whoever's it is.
///
/// What it cannot see: a name resolved where the relay reads no answer —
/// DNS over HTTPS or TLS of a browser's own — reaches its address
/// unblocked unless the address is blocked too; and an address shared by
/// many names (a CDN) is blocked by its name only on a flow the answer for
/// that name led to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    Name(String),
    Addr(std::net::IpAddr),
    Net(std::net::IpAddr, u8),
}

impl Block {
    /// A word of a person's or a record's: `example.com`, `1.2.3.4`,
    /// `2001:db8::/32`. A name in lower case, of letters, digits, `-` and
    /// dots, a dot inside it; no scheme, path or port.
    pub fn parse(word: &str) -> Option<Self> {
        let word = word.trim();
        if let Some((addr, len)) = word.split_once('/') {
            let addr: std::net::IpAddr = addr.parse().ok()?;
            let len: u8 = len.parse().ok()?;
            let max = if addr.is_ipv4() { 32 } else { 128 };
            return (len <= max).then_some(Self::Net(addr, len));
        }
        if let Ok(addr) = word.parse() {
            return Some(Self::Addr(addr));
        }
        let name = word.trim_end_matches('.').to_ascii_lowercase();
        let ok = name.len() <= 253
            && name.contains('.')
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });
        ok.then_some(Self::Name(name))
    }

    /// How it is written in a record.
    pub fn word(&self) -> String {
        match self {
            Self::Name(name) => name.clone(),
            Self::Addr(addr) => addr.to_string(),
            Self::Net(addr, len) => format!("{addr}/{len}"),
        }
    }

    /// Whether a flow to `addr`, which a DNS answer named `name` (none: no
    /// answer seen), goes where this blocks.
    pub fn covers(&self, name: Option<&str>, addr: &std::net::IpAddr) -> bool {
        match self {
            Self::Addr(blocked) => blocked == addr,
            Self::Net(net, len) => in_net(addr, net, *len),
            Self::Name(blocked) => name.is_some_and(|n| {
                let n = n.trim_end_matches('.').to_ascii_lowercase();
                n == *blocked || n.ends_with(&format!(".{blocked}"))
            }),
        }
    }
}

fn in_net(addr: &std::net::IpAddr, net: &std::net::IpAddr, len: u8) -> bool {
    use std::net::IpAddr;
    let (a, n, bits): (u128, u128, u32) = match (addr, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => (u32::from(*a).into(), u32::from(*n).into(), 32),
        (IpAddr::V6(a), IpAddr::V6(n)) => (u128::from(*a), u128::from(*n), 128),
        _ => return false,
    };
    let len = u32::from(len).min(bits);
    if len == 0 {
        return true;
    }
    let shift = bits - len;
    (a >> shift) == (n >> shift)
}

/// A launcher key as a rule names it: one word, nothing that would read as
/// another line or another setting.
pub fn valid_program(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 255
        && !key.starts_with('-')
        && !key
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '=' | '/' | '#' | '?'))
}

/// What a program's network is: there, not, or asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    Allow,
    Deny,
    Ask,
}

impl Rule {
    /// The verdict it is without asking.
    pub fn verdict(self) -> Option<Verdict> {
        match self {
            Self::Allow => Some(Verdict::Allow),
            Self::Deny => Some(Verdict::Deny),
            Self::Ask => None,
        }
    }

    fn of(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Allow => Self::Allow,
            Verdict::Deny => Self::Deny,
        }
    }
}

/// The template's key of the network's default ([`crate::permissions`]).
pub const TEMPLATE_KEY: &str = "network";

/// The template's default for a record with none of its own.
pub fn template(config: &Path) -> (Rule, Source) {
    use crate::microphone::Setting;
    let (setting, source) = crate::permissions::switch(config, TEMPLATE_KEY);
    let rule = match setting {
        Setting::Yes => Rule::Allow,
        Setting::No => Rule::Deny,
        Setting::Ask => Rule::Ask,
    };
    (rule, source)
}

/// A container's rules, read once: what the keeper decides a round of new
/// flows by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rules {
    /// `(program, verdict, source)`, Nix's first.
    pub programs: Vec<(String, Verdict, Source)>,
    pub default: Option<(Verdict, Source)>,
    /// The template's, for no default of the record's.
    pub template: (Rule, Source),
    /// «Без изоляции»: the network, always.
    pub open: bool,
    /// The destinations blocked ([`Block`]), Nix's first.
    pub blocks: Vec<(Block, Source)>,
}

impl Default for Rules {
    /// No record's — a throwaway's: the built-in template's.
    fn default() -> Self {
        Self {
            programs: Vec::new(),
            default: None,
            template: (Rule::Ask, Source::Default),
            open: false,
            blocks: Vec::new(),
        }
    }
}

fn verdict_of(word: &str) -> Option<Verdict> {
    match word.trim() {
        "allow" | "yes" | "on" => Some(Verdict::Allow),
        "deny" | "no" | "off" => Some(Verdict::Deny),
        _ => None,
    }
}

fn values<'a>(conf: &'a [(String, String)], key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    conf.iter()
        .filter(move |(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

impl Rules {
    /// No record's (a throwaway container's): the template's alone.
    pub fn template_only(config: &Path) -> Self {
        Self {
            template: template(config),
            ..Self::default()
        }
    }

    /// The rules of the record `name` in `config`.
    pub fn load(config: &Path, name: &str) -> Self {
        let declared = crate::declared::read(&crate::container::declared_file_in(config, name))
            .map(|t| crate::container::parse_conf(&t))
            .unwrap_or_default();
        let local = std::fs::read_to_string(
            crate::container::policy_dir_in(config, name).join(crate::container::FILE),
        )
        .map(|t| crate::container::parse_conf(&t))
        .unwrap_or_default();
        let mut rules = Rules {
            template: template(config),
            open: name == crate::container::OPEN_RECORD,
            ..Rules::default()
        };
        for (conf, source) in [(&declared, Source::Nix), (&local, Source::Local)] {
            for block in values(conf, BLOCK).filter_map(Block::parse) {
                if !rules.blocks.iter().any(|(b, _)| *b == block) {
                    rules.blocks.push((block, source));
                }
            }
            for (key, verdict) in [(ALLOW, Verdict::Allow), (DENY, Verdict::Deny)] {
                for program in values(conf, key)
                    .map(str::trim)
                    .filter(|p| valid_program(p))
                {
                    rules.add(program, verdict, source);
                }
            }
        }
        let default = |conf: &[(String, String)]| values(conf, DEFAULT).last().and_then(verdict_of);
        rules.default = match (default(&declared), default(&local)) {
            // A local word closes under Nix, never opens.
            (Some(Verdict::Allow), Some(Verdict::Deny)) => Some((Verdict::Deny, Source::Local)),
            (Some(nix), _) => Some((nix, Source::Nix)),
            (None, Some(local)) => Some((local, Source::Local)),
            (None, None) => None,
        };
        rules
    }

    fn add(&mut self, program: &str, verdict: Verdict, source: Source) {
        match self.programs.iter_mut().find(|(p, _, _)| p == program) {
            // Nix's first; a local "deny" narrows it.
            Some(had) => {
                if had.2 == Source::Nix && source == Source::Local && verdict == Verdict::Deny {
                    *had = (program.to_owned(), Verdict::Deny, Source::Local);
                } else if had.2 == source {
                    // The last line of one source counts.
                    had.1 = verdict;
                }
            }
            None => self.programs.push((program.to_owned(), verdict, source)),
        }
    }

    /// The default for a program with no line of its own: the record's,
    /// else the template's; «без изоляции» — the network.
    pub fn default_rule(&self) -> Rule {
        if self.open {
            return Rule::Allow;
        }
        self.default.map_or(self.template.0, |(v, _)| Rule::of(v))
    }

    /// One verdict for every program, when no program has a line of its
    /// own and the default asks nothing: the keeper decides a round of new
    /// flows without looking up whose they are.
    pub fn uniform(&self) -> Option<Verdict> {
        if self.open {
            return Some(Verdict::Allow);
        }
        // A destination blocked: each flow is looked at.
        if !self.blocks.is_empty() {
            return None;
        }
        self.programs
            .is_empty()
            .then(|| self.default_rule().verdict())
            .flatten()
    }

    /// Whether a flow to `addr`, named `name` by a DNS answer, is blocked —
    /// whoever's it is. Never for «без изоляции».
    pub fn blocked(&self, name: Option<&str>, addr: &std::net::IpAddr) -> bool {
        !self.open && self.blocks.iter().any(|(b, _)| b.covers(name, addr))
    }

    /// A new flow's verdict, `key` to the address a DNS answer named `name`,
    /// of `program` (`None`: not found): what the keeper writes for the
    /// relay's gate — `None`, the person is asked. A flow the gate does not
    /// hold went already. DNS to the instance's forwarder is its program's
    /// rule's, "ask" let — the question is the connection's that follows —;
    /// a program denied the network asks no names either (the gate's
    /// holes, 2026-10-16: names are a way out too). A destination blocked
    /// for the container: no, whoever's it is, before the program's rule.
    pub fn of_flow(
        &self,
        key: &crate::flows::Key,
        name: Option<&str>,
        program: Option<&str>,
    ) -> Option<Verdict> {
        if !crate::relay::gated(key) {
            return Some(Verdict::Allow);
        }
        if crate::relay::to_forwarder(key) {
            return Some(match self.decide(program) {
                Rule::Deny => Verdict::Deny,
                Rule::Allow | Rule::Ask => Verdict::Allow,
            });
        }
        if self.blocked(name, &key.remote) {
            return Some(Verdict::Deny);
        }
        self.decide(program).verdict()
    }

    /// The rule for a flow whose program was not found — a socket gone by
    /// the time it was looked for (a datagram sent, the program ended), a
    /// raw one, a process of no launch: the default, but never "yes" where
    /// a program is denied — that one may be it (the owner, 2026-10-16: a
    /// program too short to be found must not be a way past its rule).
    pub fn unknown(&self) -> Rule {
        let rule = self.default_rule();
        let denied = self.programs.iter().any(|(_, v, _)| *v == Verdict::Deny);
        if rule == Rule::Allow && denied {
            Rule::Deny
        } else {
            rule
        }
    }

    /// The rule for `program` (`None`: not found — [`Rules::unknown`]).
    pub fn decide(&self, program: Option<&str>) -> Rule {
        if self.open {
            return Rule::Allow;
        }
        let Some(program) = program else {
            return self.unknown();
        };
        self.programs
            .iter()
            .find(|(q, _, _)| q == program)
            .map_or_else(|| self.default_rule(), |(_, v, _)| Rule::of(*v))
    }
}

/// Set `program`'s rule in the record of `container`, locally (`None`: its
/// line taken away — the default then). A program Nix names is changed
/// there, but for a "deny", which narrows it.
pub fn set(
    tools: &crate::tools::Tools,
    container: &str,
    program: &str,
    verdict: Option<Verdict>,
) -> Result<(), String> {
    if !valid_program(program) {
        return Err(format!("«{program}» — не ключ программы (id ярлыка)"));
    }
    let record = crate::container::load(tools, container)
        .ok_or_else(|| format!("контейнера {container} нет"))?;
    let rules = Rules::load(&tools.config, &record.name);
    if let Some((_, nix, _)) = rules
        .programs
        .iter()
        .find(|(p, _, s)| p == program && *s == Source::Nix)
    {
        if verdict != Some(Verdict::Deny) || *nix == Verdict::Deny {
            return Err(format!(
                "сеть программы {program} в контейнере {container} задана в Nix — меняется там \
                 (местно можно только запретить)"
            ));
        }
    }
    write_line(
        &record.policy.join(crate::container::FILE),
        program,
        verdict,
    )
}

/// Block `target` for `container`, or take a local block back (`add`
/// false), locally. Nix's blocks are taken back there.
pub fn set_block(
    tools: &crate::tools::Tools,
    container: &str,
    target: &str,
    add: bool,
) -> Result<Block, String> {
    let block = Block::parse(target).ok_or_else(|| {
        format!("«{target}» — не имя, не адрес и не сеть (example.com, 1.2.3.4, 10.0.0.0/8)")
    })?;
    let record = crate::container::load(tools, container)
        .ok_or_else(|| format!("контейнера {container} нет"))?;
    if record.name == crate::container::OPEN_RECORD {
        return Err("«без изоляции» не настраивается: сеть у его программ есть".to_owned());
    }
    let rules = Rules::load(&tools.config, &record.name);
    if !add
        && rules
            .blocks
            .iter()
            .any(|(b, s)| *b == block && *s == Source::Nix)
    {
        return Err(format!(
            "{} для контейнера {container} заблокировано в Nix — снимается там",
            block.word()
        ));
    }
    let file = record.policy.join(crate::container::FILE);
    let local = std::fs::read_to_string(&file)
        .map(|t| crate::container::parse_conf(&t))
        .unwrap_or_default();
    let mut kept: Vec<String> = values(&local, BLOCK)
        .filter_map(Block::parse)
        .filter(|b| *b != block)
        .map(|b| b.word())
        .collect();
    if add {
        kept.push(block.word());
    }
    crate::container::write_values(&file, BLOCK, &kept)?;
    Ok(block)
}

/// `program`'s line in the record's local file `file`: allow, deny, or
/// none. What `set` and the keeper's answers write.
pub fn write_line(file: &Path, program: &str, verdict: Option<Verdict>) -> Result<(), String> {
    if !valid_program(program) {
        return Err(format!("«{program}» — не ключ программы (id ярлыка)"));
    }
    let local = std::fs::read_to_string(file)
        .map(|t| crate::container::parse_conf(&t))
        .unwrap_or_default();
    for key in [ALLOW, DENY] {
        let kept: Vec<String> = values(&local, key)
            .map(str::trim)
            .filter(|p| *p != program)
            .map(str::to_owned)
            .collect();
        let mut kept = kept;
        let wanted = match verdict {
            Some(Verdict::Allow) => key == ALLOW,
            Some(Verdict::Deny) => key == DENY,
            None => false,
        };
        if wanted {
            kept.push(program.to_owned());
        }
        crate::container::write_values(file, key, &kept)?;
    }
    Ok(())
}

/// Whether the local record `record` says no to `program`: what the
/// window's ☰ may take back (Nix's words are Nix's).
pub fn denied_locally(config: &Path, record: &str, program: &str) -> bool {
    let file = crate::container::policy_dir_in(config, record).join(crate::container::FILE);
    std::fs::read_to_string(file).is_ok_and(|text| {
        values(&crate::container::parse_conf(&text), DENY).any(|p| p.trim() == program)
    })
}

/// The mark, in the config directory, that [`grandfather`] was done.
pub const GRANDFATHERED: &str = ".net-grandfathered";

/// Once: every program that already went out — the programs' journal
/// (`crate::connlog`, `netlog/programs`) — gets `net_allow` in its record,
/// where it has no line: "ask" by default asks about new programs, not the
/// person's usual ones (`docs/FIREWALL.md` §9). The mark first, made
/// exclusively: one keeper does it. A record that is not there any more
/// is not made for it; a process of no launch (`~…`) and none found (`?`)
/// are nobody to write for.
pub fn grandfather(config: &Path, state: &Path) {
    let mark = config.join(GRANDFATHERED);
    let made = std::fs::create_dir_all(config).and_then(|()| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&mark)
    });
    if made.is_err() {
        return;
    }
    let dir = state
        .join(crate::traffic::NETLOG)
        .join(crate::connlog::PROGRAMS);
    let mut seen = std::collections::BTreeSet::new();
    for day in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        let text = std::fs::read_to_string(day.path()).unwrap_or_default();
        for line in text.lines() {
            let fields: Vec<&str> = line.split('\t').collect();
            let [who, program, ..] = fields.as_slice() else {
                continue;
            };
            if program.starts_with('~') || *program == "?" || !valid_program(program) {
                continue;
            }
            let record = if who.starts_with("main:") {
                crate::container::MAIN_RECORD.to_owned()
            } else if crate::container::valid_name(who) {
                (*who).to_owned()
            } else {
                continue;
            };
            seen.insert((record, (*program).to_owned()));
        }
    }
    for (record, program) in seen {
        let policy = crate::container::policy_dir_in(config, &record);
        let there = record == crate::container::MAIN_RECORD
            || policy.is_dir()
            || crate::container::declared_file_in(config, &record).exists();
        if !there || record == crate::container::OPEN_RECORD {
            continue;
        }
        let rules = Rules::load(config, &record);
        if rules.programs.iter().any(|(p, _, _)| *p == program) {
            continue;
        }
        let _ = write_line(
            &policy.join(crate::container::FILE),
            &program,
            Some(Verdict::Allow),
        );
    }
}

/// Set the record's default, locally (`None`: none of its own).
pub fn set_default(
    tools: &crate::tools::Tools,
    container: &str,
    verdict: Option<Verdict>,
) -> Result<(), String> {
    let record = crate::container::load(tools, container)
        .ok_or_else(|| format!("контейнера {container} нет"))?;
    let rules = Rules::load(&tools.config, &record.name);
    if let Some((nix, Source::Nix)) = rules.default {
        if verdict != Some(Verdict::Deny) || nix == Verdict::Deny {
            return Err(format!(
                "сеть программ контейнера {container} по умолчанию задана в Nix — меняется там \
                 (местно можно только запретить)"
            ));
        }
    }
    crate::container::write_key(
        &record.policy.join(crate::container::FILE),
        DEFAULT,
        verdict.map(|v| match v {
            Verdict::Allow => "allow",
            Verdict::Deny => "deny",
        }),
        true,
    )
}

#[cfg(test)]
mod tests {

    /// A blocked name covers itself and every name below it, never a name
    /// that only ends the same way; an address and a network by their bits.
    #[test]
    fn a_block_covers_its_name_its_address_its_network() {
        let addr = |a: &str| -> std::net::IpAddr { a.parse().unwrap() };
        let yt = Block::parse("YouTube.com.").unwrap();
        assert_eq!(yt, Block::Name("youtube.com".to_owned()));
        assert!(yt.covers(Some("youtube.com"), &addr("1.1.1.1")));
        assert!(yt.covers(Some("www.youtube.com"), &addr("1.1.1.1")));
        assert!(!yt.covers(Some("notyoutube.com"), &addr("1.1.1.1")));
        assert!(!yt.covers(None, &addr("1.1.1.1")));
        let one = Block::parse("149.154.167.41").unwrap();
        assert!(one.covers(None, &addr("149.154.167.41")));
        assert!(!one.covers(None, &addr("149.154.167.42")));
        let net = Block::parse("149.154.160.0/20").unwrap();
        assert!(net.covers(None, &addr("149.154.167.41")));
        assert!(!net.covers(None, &addr("149.154.176.1")));
        assert!(!net.covers(None, &addr("2001:db8::1")));
        let six = Block::parse("2001:db8::/32").unwrap();
        assert!(six.covers(None, &addr("2001:db8:1::5")));
        for bad in [
            "",
            "youtube",
            "http://youtube.com",
            "a b.com",
            "-x.com",
            "1.2.3.4/33",
            "x.com:443",
        ] {
            assert_eq!(Block::parse(bad), None, "{bad}");
        }
        let rules = Rules {
            blocks: vec![(yt, Source::Local)],
            ..Rules::default()
        };
        assert!(
            rules.uniform().is_none(),
            "a block makes each flow looked at"
        );
        assert!(rules.blocked(Some("m.youtube.com"), &addr("1.1.1.1")));
        let open = Rules {
            open: true,
            ..rules
        };
        assert!(!open.blocked(Some("m.youtube.com"), &addr("1.1.1.1")));
    }

    use super::*;

    fn rules(nix: &str, local: &str) -> Rules {
        let root = std::env::temp_dir().join(format!(
            "vz-netrules-{}-{}",
            std::process::id(),
            nix.len() * 1000 + local.len()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let config = root.join("config");
        let policy = crate::container::policy_dir_in(&config, "c");
        std::fs::create_dir_all(&policy).unwrap();
        std::fs::write(policy.join(crate::container::FILE), local).unwrap();
        if !nix.is_empty() {
            let declared = crate::container::declared_file_in(&config, "c");
            std::fs::create_dir_all(declared.parent().unwrap()).unwrap();
            crate::declared::declare(&declared, nix);
        }
        let rules = Rules::load(&config, "c");
        let _ = std::fs::remove_dir_all(&root);
        rules
    }

    /// A new flow: DNS to the forwarder by its program's rule, "ask" let
    /// and "deny" not; a ping as any flow; a blocked destination no,
    /// whoever's; what the gate does not hold, yes.
    #[test]
    fn a_flows_verdict_is_its_programs_and_its_destinations() {
        use crate::flows::{Key, ECHO4, ICMP, ICMP6, TCP, UDP};
        let r = rules(
            "",
            "net_deny = curl\nnet_allow = firefox\nnet_block = datadoghq.com\n",
        );
        let key = |proto, remote: &str, rport| Key {
            proto,
            lport: 40000,
            remote: remote.parse().unwrap(),
            rport,
        };
        let dns = key(UDP, "10.254.255.253", 53);
        let dns6 = key(TCP, &crate::bridge::D6.to_string(), 53);
        assert_eq!(r.of_flow(&dns, None, Some("curl")), Some(Verdict::Deny));
        assert_eq!(r.of_flow(&dns6, None, Some("curl")), Some(Verdict::Deny));
        assert_eq!(r.of_flow(&dns, None, Some("firefox")), Some(Verdict::Allow));
        // Not found, the default asks: its names are let, its connections asked.
        assert_eq!(r.decide(None), Rule::Ask);
        assert_eq!(r.of_flow(&dns, None, None), Some(Verdict::Allow));
        let ping = key(ICMP, "1.1.1.1", u16::from(ECHO4));
        assert_eq!(r.of_flow(&ping, None, Some("curl")), Some(Verdict::Deny));
        assert_eq!(
            r.of_flow(&ping, None, Some("firefox")),
            Some(Verdict::Allow)
        );
        assert_eq!(r.of_flow(&ping, None, None), None);
        // DNS elsewhere is a connection like any.
        assert_eq!(r.of_flow(&key(UDP, "9.9.9.9", 53), None, None), None);
        let tcp = key(TCP, "203.0.113.7", 443);
        assert_eq!(
            r.of_flow(&tcp, Some("api.datadoghq.com"), Some("firefox")),
            Some(Verdict::Deny)
        );
        assert_eq!(
            r.of_flow(&tcp, Some("example.org"), Some("firefox")),
            Some(Verdict::Allow)
        );
        // A router solicitation is not the gate's.
        let rs = Key {
            lport: 0,
            ..key(ICMP6, "ff02::2", 133)
        };
        assert_eq!(r.of_flow(&rs, None, Some("curl")), Some(Verdict::Allow));
    }

    /// A flow of no program found: the default, but "no" where a program
    /// is denied and the default is "yes" — the denied one may be it.
    #[test]
    fn an_unknown_program_is_never_let_past_a_denial() {
        let r = rules("", "# unknown, its own directory\nnet_default = allow\n");
        assert_eq!(r.decide(None), Rule::Allow);
        let r = rules(
            "",
            "# unknown, its own directory\nnet_default = allow\nnet_deny = curl\n",
        );
        assert_eq!(r.decide(None), Rule::Deny);
        assert_eq!(r.decide(Some("firefox")), Rule::Allow);
        let r = rules(
            "",
            "# unknown, its own directory\nnet_default = allow\nnet_allow = firefox\n",
        );
        assert_eq!(r.decide(None), Rule::Allow);
        // "Ask" still asks: about a program it cannot name.
        let r = rules("", "# unknown, its own directory\nnet_deny = curl\n");
        assert_eq!(r.decide(None), Rule::Ask);
    }

    /// A program's line, the record's default without one, the template's
    /// without that — "ask" built in; a local "deny" narrows Nix, a local
    /// "allow" does not widen it; one verdict for all only with no program
    /// lines and a default that asks nothing; «без изоляции» always has it.
    #[test]
    fn a_programs_line_then_the_default_then_the_template() {
        let r = rules("", "net_deny = curl\nnet_allow = firefox\n");
        assert_eq!(r.decide(Some("curl")), Rule::Deny);
        assert_eq!(r.decide(Some("firefox")), Rule::Allow);
        assert_eq!(
            r.decide(Some("other")),
            Rule::Ask,
            "the template's, built in"
        );
        assert_eq!(r.decide(None), Rule::Ask);
        assert_eq!(r.uniform(), None);

        let r = rules("", "net_default = deny\n");
        assert_eq!(r.uniform(), Some(Verdict::Deny));
        let r = rules("", "net_default = allow\n");
        assert_eq!(r.uniform(), Some(Verdict::Allow));
        assert_eq!(rules("", "").uniform(), None, "asks");

        let r = rules(
            "home = private\nnet_allow = steam\nnet_default = allow\n",
            "net_deny = steam\nnet_allow = telegram\nnet_default = deny\n",
        );
        assert_eq!(r.decide(Some("steam")), Rule::Deny, "a local deny narrows");
        assert_eq!(r.decide(Some("telegram")), Rule::Allow);
        assert_eq!(r.default, Some((Verdict::Deny, Source::Local)));

        let r = rules(
            "home = private\nnet_deny = steam\nnet_default = deny\n",
            "net_allow = steam\nnet_default = allow\n",
        );
        assert_eq!(
            r.decide(Some("steam")),
            Rule::Deny,
            "a local allow does not widen"
        );
        assert_eq!(r.default_rule(), Rule::Deny);

        let open = Rules {
            open: true,
            ..rules("", "net_default = deny\n")
        };
        assert_eq!(open.decide(Some("x")), Rule::Allow);
        assert_eq!(open.uniform(), Some(Verdict::Allow));
    }

    /// Once, the programs of the journal get "allow" in their records —
    /// the main home's by `main:<network>`, a container's that is there —;
    /// a line of their own stays, a record gone is not made, `~` and `?`
    /// are nobody's; the second time does nothing.
    #[test]
    fn the_programs_that_went_out_are_let_once() {
        let root = std::env::temp_dir().join(format!("vz-grandfather-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (config, state) = (root.join("config"), root.join("state"));
        let journal = state
            .join(crate::traffic::NETLOG)
            .join(crate::connlog::PROGRAMS);
        std::fs::create_dir_all(&journal).unwrap();
        std::fs::write(
            journal.join("2026-09-28"),
            "main:nl\tfirefox\t10\t20\nwork\ttelegram\t1\t2\nwork\tcurl\t1\t2\n\
             gone\tsteam\t1\t1\nwork\t~bash\t1\t1\nwork\t?\t1\t1\n",
        )
        .unwrap();
        let work = crate::container::policy_dir_in(&config, "work");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::write(
            work.join(crate::container::FILE),
            "home = layer\nnet_deny = curl\n",
        )
        .unwrap();
        grandfather(&config, &state);
        let main = Rules::load(&config, crate::container::MAIN_RECORD);
        assert_eq!(main.decide(Some("firefox")), Rule::Allow);
        let w = Rules::load(&config, "work");
        assert_eq!(w.decide(Some("telegram")), Rule::Allow);
        assert_eq!(w.decide(Some("curl")), Rule::Deny, "its own line stays");
        assert_eq!(w.programs.len(), 2, "{w:?}");
        assert!(!crate::container::policy_dir_in(&config, "gone").exists());
        // Once.
        std::fs::write(journal.join("2026-09-29"), "work\tobs\t1\t1\n").unwrap();
        grandfather(&config, &state);
        assert_eq!(Rules::load(&config, "work").decide(Some("obs")), Rule::Ask);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_program_is_one_word() {
        for ok in ["firefox", "org.telegram.desktop", "app_x-1"] {
            assert!(valid_program(ok), "{ok}");
        }
        for bad in ["", "a b", "a=b", "../x", "-x", "a\nb", "#x", "?"] {
            assert!(!valid_program(bad), "{bad:?}");
        }
    }

    /// A local "no" is what the window's ☰ may take back: written, found;
    /// taken out, gone — and an "allow" is no "no".
    #[test]
    fn a_local_no_is_found_and_taken_back() {
        let config = std::env::temp_dir().join(format!("vz-netrules-no-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&config);
        let file = crate::container::policy_dir_in(&config, "work").join(crate::container::FILE);
        assert!(!denied_locally(&config, "work", "curl"));
        write_line(&file, "curl", Some(Verdict::Deny)).unwrap();
        write_line(&file, "steam", Some(Verdict::Allow)).unwrap();
        assert!(denied_locally(&config, "work", "curl"));
        assert!(!denied_locally(&config, "work", "steam"));
        write_line(&file, "curl", None).unwrap();
        assert!(!denied_locally(&config, "work", "curl"));
        let _ = std::fs::remove_dir_all(&config);
    }
}
