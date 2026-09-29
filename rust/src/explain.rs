//! `cellward explain <container|program|main> [<network>] [--json]`: what
//! the programs of a container get in a network, and whose word decided
//! each (step 1 of the permission model the owner took on 2026-09-28,
//! `docs/PERMISSIONS.md` §11.14). Made of the functions a launch and an
//! instance's start take them from — `hermetic::explain` for the settings
//! an instance comes up with, `x11::effective`'s order for X11,
//! `hermetic::for_container` for the cameras, `microphone::setting_for` and
//! `microphone::by_container` for the microphone and the screen cast —, so
//! what it says is what is done.

use std::ffi::OsString;

use crate::container::{Home, Source};
use crate::hermetic::Asker;
use crate::origin::Who;
use crate::status::string;
use crate::tools::Tools;

/// A setting's value: on or off, a word (`yes`, `no`, `ask`), or the
/// camera's mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    Flag(bool),
    Word(crate::microphone::Setting),
    Camera(crate::camera::Mode),
}

/// One setting, as `explain` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// Its name in `status --json` and in a container's settings.
    pub key: &'static str,
    pub value: Value,
    /// The source of the word that decided it.
    pub source: Source,
    /// What is asked for, whence, and whose word it is
    /// (`hermetic::Explained::asked`); for X11 and the cameras, whose word
    /// the value is. `None` where it is not told apart.
    pub asked: Option<(Value, Source, Asker)>,
    /// What the network tolerates (`hermetic::tolerance`); `None` for a
    /// permission of a program, which the network has no say in.
    pub tolerated: Option<(bool, Source)>,
    /// Why the network does not tolerate it, where it does not: `offline`
    /// (it tolerates none), `lock` (a zone the person locked tolerates no
    /// host session) or `network` (its own setting).
    pub refused_by: Option<&'static str>,
    /// Why it changes nothing for this container, where it does not.
    pub moot: Option<&'static str>,
}

/// Every setting of the programs of `who` (a container's home `home`) in
/// the network `zone`.
pub fn rows(tools: &Tools, zone: &str, who: &Who, home: Option<Home>) -> Vec<Row> {
    let dir = tools.state.join(zone);
    let config = &tools.config;
    let mut rows = Vec::new();
    let mut hermetic = true;
    for (key, _) in crate::hermetic::CONTAINER_KEYS {
        let told = crate::hermetic::explain(&dir, config, zone, who, key);
        if key == "hermetic" {
            hermetic = told.value.0;
        }
        let moot = match key {
            // A home of its own is a sandbox that binds the store alone.
            "nix_daemon" if home == Some(Home::Private) => {
                Some("личному дому Nix-демон не виден: в его песочнице только /nix/store")
            }
            "host_files_writable" if !matches!(home, None | Some(Home::Main)) => {
                Some("файлы хоста — в настоящем доме, а дом контейнера не настоящий")
            }
            "host_files_writable" if !hermetic => Some("не герметичен: файлы хоста пишутся и так"),
            _ => None,
        };
        let refused_by = match told.tolerated {
            Some((false, _)) if zone == crate::launch::OFFLINE => Some("offline"),
            Some((false, _))
                if key == "hermetic" && dir.join(crate::launch::NO_ESCAPE).exists() =>
            {
                Some("lock")
            }
            Some((false, _)) => Some("network"),
            _ => None,
        };
        rows.push(Row {
            key: told.key,
            value: Value::Flag(told.value.0),
            source: told.value.1,
            asked: Some((Value::Flag(told.asked.0), told.asked.1, told.asked.2)),
            tolerated: told.tolerated,
            refused_by,
            moot,
        });
    }
    // Whose record: a container's, or the main home's own
    // (`container::MAIN_RECORD`, 2a of `docs/PERMISSIONS.md` §11.15).
    let record = match who {
        Who::Container(name) => Some(name.as_str()),
        Who::Main => Some(crate::container::MAIN_RECORD),
        Who::Unknown => None,
    };
    // X11: the container's own word, both ways, else its network's
    // (`x11::effective`), as a launch reads them.
    let zone_x11 = crate::x11::zone_setting(&tools.state, config, zone);
    let own_x11 = record
        .and_then(|name| crate::container::load(tools, name))
        .and_then(|c| c.x11)
        .map(|x11| (x11.value, x11.source));
    let (x11, x11_whose) = match own_x11 {
        Some(own) => (own, Asker::Container),
        None => (zone_x11, Asker::Network),
    };
    rows.push(Row {
        key: "x11",
        value: Value::Flag(x11.0),
        source: x11.1,
        asked: Some((Value::Flag(x11.0), x11.1, x11_whose)),
        tolerated: None,
        refused_by: None,
        moot: None,
    });
    // The cameras: a container's by the camera's order, the network's for
    // a launch of no container (`launch`, THE CAMERAS).
    let camera = crate::hermetic::camera(&dir, config, zone);
    let own_camera = record.and_then(|name| crate::container::own_camera_in(config, name));
    // Its own word over the template both ways (§11.15, 2b).
    let (camera, camera_whose) = match (record, own_camera) {
        (Some(_), Some(own)) => (own, Asker::Container),
        (Some(_), None) => (camera, Asker::Template),
        (None, _) => (camera, Asker::Nobody),
    };
    rows.push(Row {
        key: "camera",
        value: Value::Camera(camera.0),
        source: camera.1,
        asked: Some((Value::Camera(camera.0), camera.1, camera_whose)),
        tolerated: None,
        refused_by: None,
        moot: None,
    });
    let microphone = crate::microphone::setting_for(&dir, config, zone, who);
    rows.push(Row {
        key: "microphone",
        value: Value::Word(microphone.0),
        source: microphone.1,
        asked: None,
        tolerated: None,
        refused_by: None,
        moot: None,
    });
    let screencast = crate::microphone::by_container(
        crate::screencast::setting(&dir, config, zone),
        config,
        "screencast",
        who,
    );
    rows.push(Row {
        key: "screencast",
        value: Value::Word(screencast.0),
        source: screencast.1,
        asked: None,
        tolerated: None,
        refused_by: None,
        moot: None,
    });
    rows
}

/// Whom `explain` was asked about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    /// A container, by name, and its home.
    Container(String, Home),
    /// The built-in main home: `main:<network>`.
    Main,
    /// A program no container has (by its id): a throwaway container's.
    Program(String),
}

impl Subject {
    fn who(&self) -> Who {
        match self {
            Self::Container(name, _) => Who::Container(name.clone()),
            Self::Main => Who::Main,
            Self::Program(_) => Who::Unknown,
        }
    }

    fn home(&self) -> Option<Home> {
        match self {
            Self::Container(_, home) => Some(*home),
            _ => None,
        }
    }
}

/// A setting's name for a person, said of what opens it: for hermeticity,
/// what its absence gives.
fn name(key: &str) -> &'static str {
    match key {
        "hermetic" => "сессия хоста (не герметичен)",
        "nix_daemon" => "Nix-демон хоста",
        "host_files_writable" => "запись файлов хоста",
        "audio_manager" => "PipeWire хоста без ограничений",
        "x11" => "свой X-сервер (X11)",
        "camera" => "камеры",
        "microphone" => "микрофон",
        "screencast" => "трансляция экрана",
        _ => "?",
    }
}

/// Whether `value` of the setting `key` opens it: for hermeticity, its
/// absence.
fn opens(key: &str, value: Value) -> bool {
    match value {
        Value::Flag(on) => on != (key == "hermetic"),
        Value::Word(word) => word == crate::microphone::Setting::Yes,
        Value::Camera(mode) => mode == crate::camera::Mode::Yes,
    }
}

fn word(key: &str, value: Value) -> &'static str {
    match value {
        Value::Word(crate::microphone::Setting::Ask) => "спросить",
        Value::Camera(crate::camera::Mode::Ask) => "спросить, до ответа чёрная",
        Value::Camera(crate::camera::Mode::Black) => "чёрная",
        value if opens(key, value) => "да",
        _ => "нет",
    }
}

fn from(source: Source) -> &'static str {
    match source {
        Source::Nix => "Nix",
        Source::Local => "местно",
        Source::Default => "по умолчанию",
    }
}

/// Why a row is what it is, for a person.
fn why(row: &Row) -> String {
    let Some((asked, asked_source, whose)) = row.asked else {
        return format!("{} ({})", whose_word(None), from(row.source));
    };
    let key = row.key;
    let src = from(asked_source);
    let Some((tolerated, tolerated_source)) = row.tolerated else {
        return format!("{} ({src})", whose_word(Some(whose)));
    };
    let asking = opens(key, asked);
    let asker = match whose {
        Asker::Nobody => return "разовый или незнакомый запуск — всегда нет".to_owned(),
        Asker::Container => {
            if asking {
                format!("контейнер просит ({src})")
            } else {
                format!("контейнер не просит ({src})")
            }
        }
        Asker::Network => {
            if asking {
                format!("сеть даёт тем, у кого нет своего слова ({src})")
            } else {
                format!("своего слова нет, сеть не даёт ({src})")
            }
        }
        Asker::Template => {
            if asking {
                format!("своего слова нет, по умолчанию — да ({src})")
            } else {
                format!("своего слова нет, по умолчанию — нет ({src})")
            }
        }
    };
    if !asking {
        return asker;
    }
    let tolerance = match row.refused_by {
        _ if tolerated => format!("сеть допускает ({})", from(tolerated_source)),
        Some("offline") => "но offline не допускает обходов сети никогда".to_owned(),
        Some("lock") => "но зона заперта (cellward lock) и держит только герметичных".to_owned(),
        _ => format!("но сеть не допускает ({})", from(tolerated_source)),
    };
    format!("{asker}, {tolerance}")
}

fn whose_word(whose: Option<Asker>) -> &'static str {
    match whose {
        Some(Asker::Container) => "своё у контейнера",
        Some(Asker::Network) => "как у сети",
        Some(Asker::Nobody) => "ничьё",
        Some(Asker::Template) => "по умолчанию (cellward defaults)",
        None => "по контейнеру и сети",
    }
}

/// The rows for a person.
pub fn text(subject: &Subject, zone: &str, rows: &[Row]) -> String {
    let head = match subject {
        Subject::Container(name, home) => {
            let home = match home {
                Home::Private => "свой дом",
                Home::Layer => "слой над настоящим домом",
                Home::Main => "настоящий дом",
            };
            format!("Контейнер «{name}» ({home}) в сети {zone}:")
        }
        Subject::Main => format!("Настоящий дом (без контейнера) в сети {zone}:"),
        Subject::Program(id) => format!(
            "Программа {id} ни в одном контейнере: её запускают в разовом контейнере — в сети \
             {zone} так:"
        ),
    };
    let width = rows
        .iter()
        .map(|r| name(r.key).chars().count())
        .max()
        .unwrap_or(0);
    let mut out = head;
    out.push('\n');
    for row in rows {
        let label = name(row.key);
        let pad = " ".repeat(width - label.chars().count());
        let moot = row
            .moot
            .map_or(String::new(), |m| format!(" · не действует: {m}"));
        out.push_str(&format!(
            "  {label}{pad}  {:<8} {}{moot}\n",
            word(row.key, row.value),
            why(row)
        ));
    }
    out.push_str(
        "Обходы сети (сессия хоста, Nix-демон, запись файлов хоста) открыты, только если их \
         просит контейнер и допускает сеть: cellward container set <к> hermetic|nix-daemon|\
         host-files …; cellward hermetic|nix-daemon|host-files <сеть> ….\n",
    );
    out
}

fn value_json(value: Value) -> String {
    match value {
        Value::Flag(on) => on.to_string(),
        Value::Word(word) => string(word.as_str()),
        Value::Camera(mode) => string(mode.as_str()),
    }
}

/// The rows for a program: `{"subject":…,"network":…,"settings":[…]}`.
/// Each setting's `value` is in its own sense, as `status --json` has it
/// (`hermetic`: `true` is hermetic); `asked.by` is `container`, `network`
/// or `nobody`; `tolerated.value` is whether the network tolerates the way
/// around it that the setting opens (for `hermetic`: no hermeticity), and
/// `refused_by` why not (`offline`, `lock`, `network`), `null` for a
/// program's permission.
pub fn json(subject: &Subject, zone: &str, rows: &[Row]) -> String {
    let subject = match subject {
        Subject::Container(name, home) => format!(
            "{{\"kind\":\"container\",\"name\":{},\"home\":{}}}",
            string(name),
            string(home.as_str())
        ),
        Subject::Main => "{\"kind\":\"main\",\"name\":null,\"home\":\"main\"}".to_owned(),
        Subject::Program(id) => format!(
            "{{\"kind\":\"program\",\"name\":{},\"home\":null}}",
            string(id)
        ),
    };
    let settings: Vec<String> = rows
        .iter()
        .map(|row| {
            let asked = row.asked.map_or("null".to_owned(), |(value, source, whose)| {
                format!(
                    "{{\"value\":{},\"source\":{},\"by\":{}}}",
                    value_json(value),
                    string(source.as_str()),
                    string(whose.as_str())
                )
            });
            let tolerated = row.tolerated.map_or("null".to_owned(), |(on, source)| {
                format!(
                    "{{\"value\":{on},\"source\":{},\"refused_by\":{}}}",
                    string(source.as_str()),
                    row.refused_by.map_or("null".to_owned(), string)
                )
            });
            format!(
                "{{\"key\":{},\"value\":{},\"source\":{},\"asked\":{asked},\"tolerated\":{tolerated},\"moot\":{}}}",
                string(row.key),
                value_json(row.value),
                string(row.source.as_str()),
                row.moot.map_or("null".to_owned(), string)
            )
        })
        .collect();
    format!(
        "{{\"subject\":{subject},\"network\":{},\"settings\":[{}]}}",
        string(zone),
        settings.join(",")
    )
}

/// The network a container's programs are in: the one it is bound to,
/// else the one its instance runs in, else the one a launch of it runs in;
/// `None` for one that asks on every launch and runs nowhere.
pub fn network_of(tools: &Tools, c: &crate::container::Container) -> Option<String> {
    if let crate::container::Network::Named(network) = &c.network.value {
        return Some(network.clone());
    }
    crate::instance::running(&tools.state)
        .into_iter()
        .find(|i| crate::instance::container_of(&i.id) == Some(c.name.as_str()))
        .map(|i| i.network)
        .or_else(|| crate::container::running_network(tools, c))
}

const USAGE: &str = "cellward explain <контейнер|программа|main> [<сеть>] [--json]";

/// `cellward explain …`.
pub fn run(tools: &Tools, args: &[OsString]) -> u8 {
    let json_out = args.iter().any(|a| a == "--json");
    let words: Vec<String> = args
        .iter()
        .filter(|a| *a != "--json")
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let (what, network) = match words.as_slice() {
        [what] => (what.as_str(), None),
        [what, network] => (what.as_str(), Some(network.as_str())),
        _ => {
            eprintln!("{USAGE}");
            return 1;
        }
    };
    let (subject, bound) = if what == crate::instance::MAIN {
        (Subject::Main, None)
    } else if let Some(c) = crate::container::load(tools, what).or_else(|| {
        crate::container::load_all(tools)
            .into_iter()
            .find(|c| c.apps.iter().any(|a| a.value == what))
    }) {
        (
            Subject::Container(c.name.clone(), c.home),
            network_of(tools, &c),
        )
    } else {
        (
            Subject::Program(what.to_owned()),
            Some(crate::launch::OFFLINE.to_owned()),
        )
    };
    let Some(zone) = network.map(str::to_owned).or(bound) else {
        eprintln!(
            "{what}: сеть спрашивают при запуске — назови её: cellward explain {what} <сеть>"
        );
        return 1;
    };
    let zone = crate::launch::network_name(&zone).to_owned();
    if !crate::container::network_exists(tools, &zone) {
        eprintln!("сети {zone} нет");
        return 1;
    }
    if zone == crate::launch::UNCONFINED {
        if json_out {
            println!(
                "{{\"network\":{},\"settings\":null}}",
                string(crate::launch::UNCONFINED)
            );
        } else {
            println!(
                "unconfined — сеть хоста без экземпляра: программы там видят хост целиком, и \
                 разрешения контейнера там не действуют (кроме вида дома)"
            );
        }
        return 0;
    }
    let rows = rows(tools, &zone, &subject.who(), subject.home());
    if json_out {
        println!("{}", json(&subject, &zone, &rows));
    } else {
        print!("{}", text(&subject, &zone, &rows));
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(key: &'static str, value: bool, asked: (bool, Asker), tolerated: Option<bool>) -> Row {
        Row {
            key,
            value: Value::Flag(value),
            source: Source::Default,
            asked: Some((Value::Flag(asked.0), Source::Local, asked.1)),
            tolerated: tolerated.map(|t| (t, Source::Nix)),
            refused_by: (tolerated == Some(false)).then_some("network"),
            moot: None,
        }
    }

    /// Each reason a way around the network is open or closed is said, in
    /// the terms of what opens it (hermeticity by its absence).
    #[test]
    fn reasons_are_said_by_what_opens() {
        let asked_not_tolerated = row("nix_daemon", false, (true, Asker::Container), Some(false));
        assert_eq!(
            why(&asked_not_tolerated),
            "контейнер просит (местно), но сеть не допускает (Nix)"
        );
        let offline = Row {
            refused_by: Some("offline"),
            ..asked_not_tolerated.clone()
        };
        assert_eq!(
            why(&offline),
            "контейнер просит (местно), но offline не допускает обходов сети никогда"
        );
        let locked = Row {
            key: "hermetic",
            value: Value::Flag(true),
            asked: Some((Value::Flag(false), Source::Local, Asker::Container)),
            refused_by: Some("lock"),
            ..asked_not_tolerated.clone()
        };
        assert_eq!(
            why(&locked),
            "контейнер просит (местно), но зона заперта (cellward lock) и держит только \
             герметичных"
        );
        let both = row("hermetic", false, (false, Asker::Network), Some(true));
        assert_eq!(
            why(&both),
            "сеть даёт тем, у кого нет своего слова (местно), сеть допускает (Nix)"
        );
        assert_eq!(word("hermetic", both.value), "да");
        let closed = row("hermetic", true, (true, Asker::Container), Some(true));
        assert_eq!(why(&closed), "контейнер не просит (местно)");
        assert_eq!(word("hermetic", closed.value), "нет");
        let nobody = row("nix_daemon", false, (false, Asker::Nobody), Some(true));
        assert_eq!(why(&nobody), "разовый или незнакомый запуск — всегда нет");
        let own = row("audio_manager", true, (true, Asker::Container), None);
        assert_eq!(why(&own), "своё у контейнера (местно)");
        let mic = Row {
            key: "microphone",
            value: Value::Word(crate::microphone::Setting::Ask),
            source: Source::Default,
            asked: None,
            tolerated: None,
            refused_by: None,
            moot: None,
        };
        assert_eq!(word("microphone", mic.value), "спросить");
        assert_eq!(why(&mic), "по контейнеру и сети (по умолчанию)");
    }

    /// The JSON has each setting's value in its own sense, and says who
    /// asked and what the network tolerates.
    #[test]
    fn json_names_the_words() {
        let rows = vec![row(
            "hermetic",
            true,
            (false, Asker::Container),
            Some(false),
        )];
        let out = json(
            &Subject::Container("work".into(), Home::Private),
            "nl",
            &rows,
        );
        assert_eq!(
            out,
            "{\"subject\":{\"kind\":\"container\",\"name\":\"work\",\"home\":\"private\"},\
             \"network\":\"nl\",\"settings\":[{\"key\":\"hermetic\",\"value\":true,\
             \"source\":\"default\",\"asked\":{\"value\":false,\"source\":\"local\",\
             \"by\":\"container\"},\"tolerated\":{\"value\":false,\"source\":\"nix\",\
             \"refused_by\":\"network\"},\"moot\":null}]}"
        );
        crate::json::parse(&out).unwrap();
    }
}
