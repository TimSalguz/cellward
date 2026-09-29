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
//! default without a word is "allow" for now — the question comes next
//! (§4.3).
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
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '=' | '/' | '#'))
}

/// A container's rules, read once: what the keeper decides a round of new
/// flows by.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rules {
    /// `(program, verdict, source)`, Nix's first.
    pub programs: Vec<(String, Verdict, Source)>,
    pub default: Option<(Verdict, Source)>,
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
        let mut rules = Rules::default();
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

    /// The default for a program with no line of its own.
    pub fn default_verdict(&self) -> Verdict {
        self.default.map_or(Verdict::Allow, |(v, _)| v)
    }

    /// One verdict for every program, when no program has a line of its
    /// own: the keeper decides a round of new flows without looking up whose
    /// they are.
    pub fn uniform(&self) -> Option<Verdict> {
        self.programs.is_empty().then(|| self.default_verdict())
    }

    /// The verdict for `program` (`None`: not found — the default).
    pub fn decide(&self, program: Option<&str>) -> Verdict {
        program
            .and_then(|p| self.programs.iter().find(|(q, _, _)| q == p))
            .map_or_else(|| self.default_verdict(), |(_, v, _)| *v)
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
    let file = record.policy.join(crate::container::FILE);
    let local = std::fs::read_to_string(&file)
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
        crate::container::write_values(&file, key, &kept)?;
    }
    Ok(())
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

    /// A program's line, the default without one, "allow" without a
    /// default; a local "deny" narrows Nix, a local "allow" does not widen
    /// it; one verdict for all only with no program lines.
    #[test]
    fn a_programs_line_then_the_default() {
        let r = rules("", "net_deny = curl\nnet_allow = firefox\n");
        assert_eq!(r.decide(Some("curl")), Verdict::Deny);
        assert_eq!(r.decide(Some("firefox")), Verdict::Allow);
        assert_eq!(r.decide(Some("other")), Verdict::Allow);
        assert_eq!(r.decide(None), Verdict::Allow);
        assert_eq!(r.uniform(), None);

        let r = rules("", "net_default = deny\n");
        assert_eq!(r.uniform(), Some(Verdict::Deny));
        assert_eq!(rules("", "").uniform(), Some(Verdict::Allow));

        let r = rules(
            "home = private\nnet_allow = steam\nnet_default = allow\n",
            "net_deny = steam\nnet_allow = telegram\nnet_default = deny\n",
        );
        assert_eq!(
            r.decide(Some("steam")),
            Verdict::Deny,
            "a local deny narrows"
        );
        assert_eq!(r.decide(Some("telegram")), Verdict::Allow);
        assert_eq!(r.default, Some((Verdict::Deny, Source::Local)));

        let r = rules(
            "home = private\nnet_deny = steam\nnet_default = deny\n",
            "net_allow = steam\nnet_default = allow\n",
        );
        assert_eq!(
            r.decide(Some("steam")),
            Verdict::Deny,
            "a local allow does not widen"
        );
        assert_eq!(r.default_verdict(), Verdict::Deny);
    }

    #[test]
    fn a_program_is_one_word() {
        for ok in ["firefox", "org.telegram.desktop", "app_x-1"] {
            assert!(valid_program(ok), "{ok}");
        }
        for bad in ["", "a b", "a=b", "../x", "-x", "a\nb", "#x"] {
            assert!(!valid_program(bad), "{bad:?}");
        }
    }
}
