//! A container's live network switch (the container design of 2026-09-27,
//! stage 4, §5; `docs/LEAK-MODEL.md` «Смена сети на ходу»): what may start
//! one, and where each step leaves the instance when it fails. Pure: the
//! keeper (`zone::Transport::switch`) gathers the facts and does the steps.
//!
//! **Only the person, only from the host, never as a side effect (G6).** A
//! switch is asked on the instance's control socket (`instance::CONTROL`) by
//! a peer of the host's user namespace, as the user — `cellward container
//! set <c> network <net>`; the socket's path is covered in every zone and
//! instance, and nothing else (the broker, the filters, a launch, a zone's
//! return, a change of Nix) has a verb for it.
//!
//! **A refusal touches nothing.** Every precondition is looked at before the
//! cut ([`refusal`]): the instance stays on its network, attached, with its
//! sockets as they were; the person is told why and the way out — to close
//! the programs and start them in the other network (`--restart`).
//!
//! **Failure is offline, never the old network (G7).** From the cut on, the
//! instance is bound to the new network ([`Phase`], [`after`]): a step that
//! fails leaves it cut — loopback and unreachable defaults — and its next
//! way out is the new network's, through a new epoch.

use crate::epoch::LiveSwitch;

/// The request's word on the control socket: `SWITCH <network>`.
pub const VERB: &str = "SWITCH";

/// What the network asked for is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// No way out: the instance keeps loopback alone.
    Offline,
    /// A zone of the user's: whether it is up, whether it carries instances
    /// (its bridge's socket — a zone of a previous build has none), and its
    /// search domains (its `resolv.conf`).
    Zone {
        up: bool,
        carries: bool,
        search: Vec<String>,
    },
    /// The host's network: no instance has it.
    Unconfined,
    /// No network of this name.
    Unknown,
}

/// What the keeper knows when a switch is asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts<'a> {
    /// P1: the peer is the user in the host's user namespace.
    pub from_host: bool,
    /// P2: the container's network is declared in Nix.
    pub declared: bool,
    /// P7: a named container's instance — not `<c>:<net>`, `main:<net>` or a
    /// throwaway.
    pub named: bool,
    /// P8, P4: the keeper's note ([`crate::epoch::LIVE_SWITCH`]); `None` for
    /// an instance of a previous build.
    pub live: Option<&'a LiveSwitch>,
    /// P4: programs of the instance outside its current epoch, looked at now.
    pub outside: usize,
    /// P3: its current network is a zone locked by the person (`cellward
    /// lock`): its programs may not go to another network.
    pub locked: bool,
    /// P6: what the network asked for is.
    pub target: &'a Target,
    /// P5: the search domains its programs have now.
    pub search_now: &'a [String],
    /// P9 (review 2026-09-28): the settings the instance came up with that
    /// are wider than those the network asked for would give its container
    /// (`hermetic::wider_than`). They are frozen for its life — its covers
    /// and helpers are made by them once —, and would go with it into a
    /// network that gives less: a container with the Nix daemon of one
    /// network's would keep it in one whose containers have none.
    pub wider: &'a [&'static str],
    /// P10 (review 2026-09-28): the network asked for is a zone locked by
    /// the person (`cellward lock`) — which holds a hermetic instance only.
    pub target_locked: bool,
    /// P10: the instance came up hermetic (its note says so).
    pub hermetic: bool,
}

/// Why a switch was refused: a word for the journal and the command line,
/// and the person's text with the way out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: &'static str,
    pub text: String,
}

/// The way out every refusal offers.
pub const RESTART: &str = "закрыть программы контейнера и открыть их в новой сети: \
                           cellward container set <контейнер> network <сеть> --restart";

fn refused(code: &'static str, why: impl Into<String>) -> Option<Refusal> {
    Some(Refusal {
        code,
        text: format!("{} — {RESTART}", why.into()),
    })
}

/// A setting an instance came up with (`hermetic::CONTAINER_KEYS`), open,
/// for a person — and what the network asked for would give instead.
pub fn wider_text(name: &str) -> &'static str {
    match name {
        "hermetic" => "не герметичен (там был бы герметичен)",
        "nix_daemon" => "с Nix-демоном хоста (там — без него)",
        "host_files_writable" => "пишет файлы хоста (там — только чтение)",
        "audio_manager" => "с PipeWire хоста без ограничений (там — с ограниченным)",
        _ => "с настройкой, которой там нет",
    }
}

/// Why this switch may not be made, or `None` when it may — P1 to P8 of the
/// design, the first that holds. Nothing is touched for any of them.
pub fn refusal(f: &Facts<'_>) -> Option<Refusal> {
    if !f.from_host {
        return Some(Refusal {
            code: "from-host",
            text: "сеть контейнера меняет только человек, с хоста".to_owned(),
        });
    }
    if f.declared {
        return Some(Refusal {
            code: "declared",
            text: "сеть контейнера задана в Nix — меняется там".to_owned(),
        });
    }
    if !f.named {
        return refused(
            "kind",
            "экземпляр на одну сеть (настоящий дом с выбором сети, разовый контейнер, \
             временный слой) сеть не меняет",
        );
    }
    let Some(live) = f.live else {
        return refused(
            "previous-build",
            "контейнер поднят прошлой сборкой — сеть на ходу у него не меняется",
        );
    };
    match f.target {
        Target::Offline => {}
        Target::Zone {
            up: true,
            carries: true,
            ..
        } => {}
        Target::Zone { up: false, .. } => {
            return refused("zone-down", "зона не поднята");
        }
        Target::Zone { .. } => {
            return refused(
                "zone-previous-build",
                "зона поднята прошлой сборкой и контейнеры не везёт — перезапусти её \
                 (cellward down, cellward up)",
            );
        }
        Target::Unconfined => {
            return refused(
                "unconfined",
                "unconfined — сеть хоста, у экземпляра её не бывает",
            );
        }
        Target::Unknown => {
            return Some(Refusal {
                code: "unknown",
                text: "такой сети нет — есть offline и зоны из cellward list".to_owned(),
            });
        }
    }
    if f.locked {
        return refused(
            "locked",
            "его сеть заперта (cellward lock): программам из неё в другие сети нельзя",
        );
    }
    if f.target_locked && !f.hermetic {
        return refused(
            "locked-target",
            "новая сеть заперта (cellward lock), а экземпляр контейнера поднят не \
             герметичным: замок держится только в герметичном — включи герметичность \
             (cellward container set <контейнер> hermetic on)",
        );
    }
    if !f.wider.is_empty() {
        let named: Vec<&str> = f.wider.iter().copied().map(wider_text).collect();
        return refused(
            "settings",
            format!(
                "экземпляр контейнера поднят с настройками шире, чем дала бы ему новая сеть: \
                 {} — их берут при подъёме, на ходу они не сужаются",
                named.join(", ")
            ),
        );
    }
    match live.reason() {
        None if f.outside > 0 => {
            return refused(
                "outside",
                "программа контейнера запущена из сеанса входа (tty, ssh) и не в его группе: \
                 её сокеты стена эпох не удержит",
            );
        }
        None => {}
        Some("outside") if f.outside > 0 => {
            return refused(
                "outside",
                "программа контейнера запущена из сеанса входа (tty, ssh) и не в его группе: \
                 её сокеты стена эпох не удержит",
            );
        }
        // Noted before the program ended; the look now is what counts.
        Some("outside") => {}
        Some("kind") => {
            return refused("kind", "экземпляр на одну сеть сеть не меняет");
        }
        Some(why) => {
            return refused(
                "cannot",
                format!(
                    "на этом хосте сеть на ходу не меняется ({why}: cellward doctor скажет, \
                     чего нет)"
                ),
            );
        }
    }
    if let Target::Zone { search, .. } = f.target {
        // O8: another zone's search domains would send the programs' short
        // names — which they took from the old list, and may keep — to the
        // new network's resolver.
        if search.as_slice() != f.search_now {
            return refused(
                "search",
                "у зон разные домены поиска (search): короткие имена прежней сети ушли бы \
                 резолверу новой",
            );
        }
    }
    None
}

/// The steps of a switch, in their order (§5.3 of the design).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// The preconditions; nothing touched yet.
    Check,
    /// The old way out closed: its relay killed and reaped, its tap gone.
    /// From here on the instance is bound to the new network.
    Cut,
    /// Its programs frozen and moved into the next epoch's cgroup.
    Epoch,
    /// Every socket that may reach out destroyed, the rules closed.
    Seal,
    /// The new way out attached, its relay's rules walled by the new epoch.
    Attach,
    /// Written down.
    Commit,
}

impl Phase {
    /// Its word on the control socket and in the journal.
    pub fn word(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Cut => "cut",
            Self::Epoch => "epoch",
            Self::Seal => "seal",
            Self::Attach => "attach",
            Self::Commit => "commit",
        }
    }
}

/// Where the instance is when a switch from `from` to `to` failed at
/// `phase` (`None`: it did not fail): the network it is bound to and whether
/// it has a way out — never `from` once the cut was made, and never a way out
/// that did not attach. The table the keeper is held to.
pub fn after(phase: Option<Phase>, from: &str, to: &str) -> (String, bool) {
    let has_way = |network: &str| network != crate::launch::OFFLINE;
    match phase {
        Some(Phase::Check) => (from.to_owned(), has_way(from)),
        Some(_) => (to.to_owned(), false),
        None => (to.to_owned(), has_way(to)),
    }
}

/// What the person is told before a switch (§5.4 of the design): what it
/// breaks, and what it cannot.
pub fn warning(container: &str, from: &str, to: &str) -> String {
    format!(
        "Сменить сеть контейнера «{container}»: «{from}» → «{to}».\n\n\
         Программы продолжат работу, их соединения будут разорваны: сначала «{from}» \
         отключится совсем, потом подключится «{to}». Смена сети не делает контейнер другим: \
         сайты и сервисы, где он уже вошёл или оставил cookies, узнают его и в «{to}» и смогут \
         связать «{from}» с «{to}». Чтобы в «{to}» быть другим — другой контейнер."
    )
}

/// A line of the keeper's answer to a switch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Said {
    /// Switched: the network, its epoch, and what the break destroyed.
    Done {
        network: String,
        epoch: u32,
        tcp: u32,
        udp: u32,
        missed: u32,
    },
    /// A program that still holds a UDP socket of the network before.
    Muted { pid: i32, name: String },
    /// Not switched; nothing touched.
    Refused { code: String, text: String },
    /// Failed from the cut on, at this step: cut, in the new network.
    Failed { phase: String, text: String },
}

/// One line of the keeper's answer (`zone::answer_request`).
pub fn parse_answer(line: &str) -> Option<Said> {
    let (word, rest) = line.trim_end().split_once(' ')?;
    let (first, text) = rest.split_once(' ').unwrap_or((rest, ""));
    match word {
        "DONE" => {
            let tally = crate::sockdiag::Tally::parse(text);
            let epoch = text
                .split_whitespace()
                .find_map(|w| w.strip_prefix("epoch="))?
                .parse()
                .ok()?;
            Some(Said::Done {
                network: first.to_owned(),
                epoch,
                tcp: tally.tcp,
                udp: tally.udp,
                missed: tally.missed,
            })
        }
        "MUTED" => Some(Said::Muted {
            pid: first.parse().ok()?,
            name: text.to_owned(),
        }),
        "REFUSED" => Some(Said::Refused {
            code: first.to_owned(),
            text: text.to_owned(),
        }),
        "FAILED" => Some(Said::Failed {
            phase: first.to_owned(),
            text: text.to_owned(),
        }),
        _ => None,
    }
}

/// A request line: `SWITCH <network>`, the network a word a network can be
/// (`instance::valid_network`, `unconfined` refused later with its reason).
pub fn parse_request(line: &str) -> Option<&str> {
    let network = line
        .trim_end_matches(['\n', '\r'])
        .strip_prefix(VERB)?
        .strip_prefix(' ')?;
    let plain = !network.is_empty()
        && network
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'));
    plain.then_some(network)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(search: &[&str]) -> Target {
        Target::Zone {
            up: true,
            carries: true,
            search: search.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn facts<'a>(target: &'a Target, live: Option<&'a LiveSwitch>) -> Facts<'a> {
        Facts {
            from_host: true,
            declared: false,
            named: true,
            live,
            outside: 0,
            locked: false,
            target,
            search_now: &[],
            wider: &[],
            target_locked: false,
            hermetic: true,
        }
    }

    /// Each precondition, alone, refuses — with its word and the way out —
    /// and the switch that meets them all is not refused.
    #[test]
    fn every_precondition_refuses_alone() {
        let yes = LiveSwitch::Yes;
        let b = zone(&[]);
        assert_eq!(refusal(&facts(&b, Some(&yes))), None);
        assert_eq!(refusal(&facts(&Target::Offline, Some(&yes))), None);
        let code = |f: Facts<'_>| refusal(&f).map(|r| r.code);
        assert_eq!(
            code(Facts {
                from_host: false,
                ..facts(&b, Some(&yes))
            }),
            Some("from-host")
        );
        assert_eq!(
            code(Facts {
                declared: true,
                ..facts(&b, Some(&yes))
            }),
            Some("declared")
        );
        assert_eq!(
            code(Facts {
                named: false,
                ..facts(&b, Some(&yes))
            }),
            Some("kind")
        );
        assert_eq!(code(facts(&b, None)), Some("previous-build"));
        let down = Target::Zone {
            up: false,
            carries: false,
            search: Vec::new(),
        };
        assert_eq!(code(facts(&down, Some(&yes))), Some("zone-down"));
        let old = Target::Zone {
            up: true,
            carries: false,
            search: Vec::new(),
        };
        assert_eq!(code(facts(&old, Some(&yes))), Some("zone-previous-build"));
        assert_eq!(
            code(facts(&Target::Unconfined, Some(&yes))),
            Some("unconfined")
        );
        assert_eq!(code(facts(&Target::Unknown, Some(&yes))), Some("unknown"));
        assert_eq!(
            code(Facts {
                locked: true,
                ..facts(&b, Some(&yes))
            }),
            Some("locked")
        );
        assert_eq!(
            code(Facts {
                outside: 1,
                ..facts(&b, Some(&yes))
            }),
            Some("outside")
        );
        let nft = LiveSwitch::No("nft-socket".to_owned());
        assert_eq!(code(facts(&b, Some(&nft))), Some("cannot"));
        let kind = LiveSwitch::No("kind".to_owned());
        assert_eq!(code(facts(&b, Some(&kind))), Some("kind"));
        // P9: settings frozen wider than the target's; P10: a locked target
        // and an instance that is not hermetic — a hermetic one goes in.
        assert_eq!(
            code(Facts {
                wider: &["nix_daemon"],
                ..facts(&b, Some(&yes))
            }),
            Some("settings")
        );
        assert_eq!(
            code(Facts {
                wider: &["hermetic"],
                ..facts(&Target::Offline, Some(&yes))
            }),
            Some("settings")
        );
        assert_eq!(
            code(Facts {
                target_locked: true,
                hermetic: false,
                ..facts(&b, Some(&yes))
            }),
            Some("locked-target")
        );
        assert_eq!(
            code(Facts {
                target_locked: true,
                ..facts(&b, Some(&yes))
            }),
            None
        );
        assert_eq!(
            code(Facts {
                hermetic: false,
                ..facts(&b, Some(&yes))
            }),
            None
        );
        let with_search = zone(&["corp.example"]);
        assert_eq!(code(facts(&with_search, Some(&yes))), Some("search"));
        // The same search lists: taken.
        let now = vec!["corp.example".to_owned()];
        assert_eq!(
            code(Facts {
                search_now: &now,
                ..facts(&with_search, Some(&yes))
            }),
            None
        );
        // Every refusal but the host's own words offers the way out.
        let r = refusal(&Facts {
            locked: true,
            ..facts(&b, Some(&yes))
        })
        .unwrap();
        assert!(r.text.contains("--restart"), "{}", r.text);
        // Each wider setting named for the person, with the way out.
        let r = refusal(&Facts {
            wider: &[
                "hermetic",
                "nix_daemon",
                "host_files_writable",
                "audio_manager",
            ],
            ..facts(&b, Some(&yes))
        })
        .unwrap();
        for part in [
            "не герметичен",
            "Nix-демоном",
            "файлы хоста",
            "PipeWire",
            "--restart",
        ] {
            assert!(r.text.contains(part), "{part}: {}", r.text);
        }
        let r = refusal(&Facts {
            target_locked: true,
            hermetic: false,
            ..facts(&b, Some(&yes))
        })
        .unwrap();
        assert!(r.text.contains("hermetic on"), "{}", r.text);
    }

    /// A program noted outside that has ended since is not held against the
    /// switch; one outside now is, whatever the note says.
    #[test]
    fn the_look_now_decides_whether_a_program_is_outside() {
        let noted = LiveSwitch::No("outside".to_owned());
        let b = zone(&[]);
        assert_eq!(refusal(&facts(&b, Some(&noted))), None);
        assert_eq!(
            refusal(&Facts {
                outside: 2,
                ..facts(&b, Some(&noted))
            })
            .map(|r| r.code),
            Some("outside")
        );
    }

    /// Checked in order: the host's word first, the search lists last.
    #[test]
    fn the_first_refusal_is_said() {
        let with_search = zone(&["x"]);
        let f = Facts {
            from_host: false,
            declared: true,
            named: false,
            live: None,
            outside: 3,
            locked: true,
            target: &with_search,
            search_now: &[],
            wider: &["nix_daemon"],
            target_locked: true,
            hermetic: false,
        };
        assert_eq!(refusal(&f).map(|r| r.code), Some("from-host"));
    }

    /// Failure before the cut: where it was. From the cut on: bound to the
    /// new network, and no way out — never the old one (G7).
    #[test]
    fn every_failure_after_the_cut_ends_offline_and_never_on_the_old_network() {
        assert_eq!(
            after(Some(Phase::Check), "nl", "de"),
            ("nl".to_owned(), true)
        );
        for phase in [
            Phase::Cut,
            Phase::Epoch,
            Phase::Seal,
            Phase::Attach,
            Phase::Commit,
        ] {
            let (network, way) = after(Some(phase), "nl", "de");
            assert_eq!(network, "de", "{phase:?}");
            assert!(!way, "{phase:?}");
            assert!(phase > Phase::Check);
        }
        assert_eq!(after(None, "nl", "de"), ("de".to_owned(), true));
        assert_eq!(after(None, "nl", "offline"), ("offline".to_owned(), false));
        assert_eq!(
            after(Some(Phase::Check), "offline", "de"),
            ("offline".to_owned(), false)
        );
    }

    /// The keeper's answer as `zone::answer_request` writes it.
    #[test]
    fn the_keepers_answer_is_read_line_by_line() {
        assert_eq!(
            parse_answer(
                "DONE de epoch=3 tcp=2 udp=1 missed=0 unsupported=0 failed=0 udp-inodes=77\n"
            ),
            Some(Said::Done {
                network: "de".to_owned(),
                epoch: 3,
                tcp: 2,
                udp: 1,
                missed: 0
            })
        );
        assert_eq!(
            parse_answer("MUTED 42 firefox\n"),
            Some(Said::Muted {
                pid: 42,
                name: "firefox".to_owned()
            })
        );
        assert_eq!(
            parse_answer("REFUSED locked его сеть заперта\n"),
            Some(Said::Refused {
                code: "locked".to_owned(),
                text: "его сеть заперта".to_owned()
            })
        );
        assert_eq!(
            parse_answer("FAILED attach the zone refused"),
            Some(Said::Failed {
                phase: "attach".to_owned(),
                text: "the zone refused".to_owned()
            })
        );
        for bad in ["", "DONE", "DONE de", "MUTED x y", "HELLO there"] {
            assert_eq!(parse_answer(bad), None, "{bad:?}");
        }
        let w = warning("work", "nl", "de");
        assert!(w.contains("«nl» → «de»") && w.contains("cookies"), "{w}");
    }

    #[test]
    fn a_request_is_its_word_and_a_network() {
        assert_eq!(parse_request("SWITCH nl\n"), Some("nl"));
        assert_eq!(parse_request("SWITCH offline"), Some("offline"));
        assert_eq!(parse_request("SWITCH de-2\r\n"), Some("de-2"));
        for bad in [
            "",
            "SWITCH",
            "SWITCH ",
            "SWITCH  nl",
            "switch nl",
            "SWITCH nl x",
            "SWITCH ../x",
            "SWITCHnl",
        ] {
            assert_eq!(parse_request(bad), None, "{bad:?}");
        }
    }
}
