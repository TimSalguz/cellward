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
}

impl Default for Rules {
    /// No record's — a throwaway's: the built-in template's.
    fn default() -> Self {
        Self {
            programs: Vec::new(),
            default: None,
            template: (Rule::Ask, Source::Default),
            open: false,
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
        self.programs
            .is_empty()
            .then(|| self.default_rule().verdict())
            .flatten()
    }

    /// The rule for `program` (`None`: not found — the default).
    pub fn decide(&self, program: Option<&str>) -> Rule {
        if self.open {
            return Rule::Allow;
        }
        program
            .and_then(|p| self.programs.iter().find(|(q, _, _)| q == p))
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
