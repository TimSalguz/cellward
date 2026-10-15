//! The permissions in the launch window (the owner, 2026-10-15): every time
//! a program is started from the window, what its container may do is in
//! front of the person, as it is now, and can be changed right there — an X
//! server of its own, the cameras, the microphone, the screen, the network
//! of a program with no rule, the focus.
//!
//! **Kept where they always are.** A change is written to the container's
//! record, as `cellward container set` writes it: the next launch reads it
//! from there and the window shows it as it is then — nothing in the window
//! is remembered apart. A container's record is every program's of it: the
//! window says so ([`scope`]). A throwaway container has no record: what
//! the launch decides itself — the X server and the cameras — is this
//! launch's alone (`run --with`), the rest is the template's, shown and
//! not changed here.
//!
//! **Never past Nix.** A value Nix set is shown fixed; [`apply`] refuses it
//! again, as the setters do.

use std::ffi::OsString;

use crate::container::Source;
use crate::tools::Tools;
use crate::window::{Perm, PermOf};

/// The keys, in the window's order.
pub const KEYS: [&str; 6] = [
    "x11",
    "camera",
    "microphone",
    "screencast",
    "network",
    "focus",
];

/// "Не задано у контейнера": the template's, whatever it says.
pub const DEFAULT: &str = "default";

/// The words a key takes besides [`DEFAULT`], each with its text.
fn choices(key: &str) -> &'static [(&'static str, &'static str)] {
    match key {
        "x11" => &[("on", "вкл."), ("off", "выкл.")],
        "camera" => &[
            ("no", "нет"),
            ("black", "чёрная"),
            ("ask", "спрашивать"),
            ("yes", "да"),
        ],
        "microphone" | "screencast" => &[("ask", "спрашивать"), ("yes", "да"), ("no", "нет")],
        "network" => &[("allow", "разрешать"), ("deny", "запрещать")],
        "focus" => &[
            ("input", "по щелчку"),
            ("notify", "уведомлять"),
            ("ask", "спрашивать"),
            ("allow", "всегда"),
        ],
        _ => &[],
    }
}

fn label(key: &str) -> &'static str {
    match key {
        "x11" => "Свой X-сервер (для X11-программ)",
        "camera" => "Камера",
        "microphone" => "Микрофон",
        "screencast" => "Захват экрана",
        "network" => "Сеть программ без своего правила",
        "focus" => "Окна забирают фокус",
        _ => "",
    }
}

/// The text of a word of `key` — and of `ask`, the template's network
/// default, which a record does not keep (only `allow` or `deny`).
fn text_of(key: &str, word: &str) -> String {
    match choices(key).iter().find(|(w, _)| *w == word) {
        Some((_, text)) => (*text).to_owned(),
        None if word == "ask" => "спрашивать".to_owned(),
        None => word.to_owned(),
    }
}

/// The template's word for `key`: what [`DEFAULT`] is.
fn template_word(tools: &Tools, key: &str) -> String {
    let config = &tools.config;
    match key {
        "x11" => if crate::permissions::flag(config, "x11").0 {
            "on"
        } else {
            "off"
        }
        .to_owned(),
        "camera" => crate::permissions::camera(config).0.as_str().to_owned(),
        "microphone" | "screencast" => crate::permissions::switch(config, key)
            .0
            .as_str()
            .to_owned(),
        "network" => match crate::netrules::template(config).0 {
            crate::netrules::Rule::Allow => "allow",
            crate::netrules::Rule::Deny => "deny",
            crate::netrules::Rule::Ask => "ask",
        }
        .to_owned(),
        "focus" => crate::wl_focus::FocusPolicy::default().as_str().to_owned(),
        _ => String::new(),
    }
}

/// The rows of the window: each key, its choices — [`DEFAULT`] first, with
/// what the template says.
pub fn rows(tools: &Tools) -> Vec<Perm> {
    KEYS.iter()
        .map(|key| {
            let mut out = vec![(
                DEFAULT.to_owned(),
                format!("как у всех ({})", text_of(key, &template_word(tools, key))),
            )];
            out.extend(
                choices(key)
                    .iter()
                    .map(|(w, t)| ((*w).to_owned(), (*t).to_owned())),
            );
            Perm {
                key: (*key).to_owned(),
                label: label(key).to_owned(),
                choices: out,
            }
        })
        .collect()
}

/// A record's own words, as the window shows them: `(key, word, fixed)` —
/// [`DEFAULT`] where it has none, fixed where Nix said.
pub fn of_record(tools: &Tools, record: &str) -> Vec<(String, String, bool)> {
    let Some(c) = crate::container::load(tools, record) else {
        return of_new();
    };
    let own = |word: Option<(&str, Source)>| match word {
        Some((w, source)) => (w.to_owned(), source == Source::Nix),
        None => (DEFAULT.to_owned(), false),
    };
    let rules = crate::netrules::Rules::load(&tools.config, &c.name);
    KEYS.iter()
        .map(|key| {
            let (word, fixed) = match *key {
                "x11" => own(c
                    .x11
                    .as_ref()
                    .map(|x| (if x.value { "on" } else { "off" }, x.source))),
                "camera" => own(c.camera.as_ref().map(|m| (m.value.as_str(), m.source))),
                "microphone" => own(c.microphone.as_ref().map(|m| (m.value.as_str(), m.source))),
                "screencast" => own(c.screencast.as_ref().map(|m| (m.value.as_str(), m.source))),
                "network" => own(rules.default.map(|(v, source)| {
                    (
                        match v {
                            crate::verdicts::Verdict::Allow => "allow",
                            crate::verdicts::Verdict::Deny => "deny",
                        },
                        source,
                    )
                })),
                "focus" => match c.focus.source {
                    Source::Default => (DEFAULT.to_owned(), false),
                    source => (c.focus.value.as_str().to_owned(), source == Source::Nix),
                },
                _ => (DEFAULT.to_owned(), true),
            };
            ((*key).to_owned(), word, fixed)
        })
        .collect()
}

/// A container still to be made: nothing of its own yet, all of it to say.
pub fn of_new() -> Vec<(String, String, bool)> {
    KEYS.iter()
        .map(|key| ((*key).to_owned(), DEFAULT.to_owned(), false))
        .collect()
}

/// A launch with no record (a throwaway's): its own X server and cameras
/// to say ([`crate::launch::WITH_KEYS`]), the rest the template's — or, in
/// one open already (`joined`), nothing: what it was opened with.
pub fn of_launch(joined: bool) -> Vec<(String, String, bool)> {
    KEYS.iter()
        .map(|key| {
            let own = !joined && crate::launch::WITH_KEYS.iter().any(|(k, _)| k == key);
            ((*key).to_owned(), DEFAULT.to_owned(), !own)
        })
        .collect()
}

/// Whom a change in the window is for — a container's every program, or
/// this launch alone.
pub fn scope(kind: Scope<'_>) -> String {
    match kind {
        Scope::Main => {
            "Для всех программ настоящего дома, в любой сети — хранится в его записи".to_owned()
        }
        Scope::Own(name, made) => format!(
            "Для этой программы: её свой контейнер «{name}»{} — хранится в нём",
            if made {
                ""
            } else {
                ", будет создан"
            }
        ),
        Scope::Named(name, []) => {
            format!("Для всех программ контейнера «{name}» — хранится в нём")
        }
        Scope::Named(name, open) => format!(
            "Для всех программ контейнера «{name}» (сейчас открыты: {}) — хранится в нём",
            open.join(", ")
        ),
        Scope::New => "Для нового контейнера — хранится в нём".to_owned(),
        Scope::Launch => {
            "Только для этого запуска: у разового контейнера записи нет; остальное — как у всех \
             (cellward defaults)"
                .to_owned()
        }
        Scope::Joined => {
            "Как у открытого разового контейнера: его разрешения заданы, когда он открылся"
                .to_owned()
        }
        Scope::Open => {
            "Без изоляции: у программы всё, что у хоста, — здесь нечего выбирать".to_owned()
        }
    }
}

/// Whose permissions a container row shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope<'a> {
    Main,
    /// The program's own container, made already or not.
    Own(&'a str, bool),
    /// A named one, with the programs open in it.
    Named(&'a str, &'a [String]),
    New,
    Launch,
    Joined,
    Open,
}

/// The row of `tag` for the window.
pub fn perm_of(tag: &str, scope_text: String, values: Vec<(String, String, bool)>) -> PermOf {
    PermOf {
        tag: tag.to_owned(),
        scope: scope_text,
        values,
    }
}

/// The changes the window brought back, each one a word its key takes.
pub fn valid(changes: &[(String, String)]) -> Vec<(String, String)> {
    changes
        .iter()
        .filter(|(key, word)| {
            KEYS.contains(&key.as_str())
                && (word == DEFAULT || choices(key).iter().any(|(w, _)| w == word))
        })
        .cloned()
        .collect()
}

/// Write the changes to the record of `record`, each by its setter (Nix's
/// refused there): what came of each, for the person — a refusal as such.
pub fn apply(
    tools: &Tools,
    record: &str,
    changes: &[(String, String)],
) -> Vec<Result<String, String>> {
    let mut out = Vec::new();
    for (key, word) in valid(changes) {
        let default = word == DEFAULT;
        let done = match key.as_str() {
            "x11" => crate::container::set_x11(tools, record, (!default).then(|| word == "on")),
            "camera" => crate::container::set_camera(
                tools,
                record,
                crate::camera::Mode::parse(&word).filter(|_| !default),
            ),
            "microphone" => crate::container::set_microphone(
                tools,
                record,
                crate::microphone::Setting::parse(&word).filter(|_| !default),
            ),
            "screencast" => crate::container::set_screencast(
                tools,
                record,
                crate::microphone::Setting::parse(&word).filter(|_| !default),
            ),
            "network" => crate::netrules::set_default(
                tools,
                record,
                match word.as_str() {
                    "allow" => Some(crate::verdicts::Verdict::Allow),
                    "deny" => Some(crate::verdicts::Verdict::Deny),
                    _ => None,
                },
            ),
            "focus" => crate::container::set_focus(
                tools,
                record,
                crate::wl_focus::FocusPolicy::parse(&word).filter(|_| !default),
            ),
            _ => continue,
        };
        out.push(done.map(|()| format!("{}: {}", label(&key), text_of(&key, &word))));
    }
    out
}

/// The changes of a launch with no record, as `run` takes them: `--with
/// <key>=<word>` for what it decides itself; the template's words are no
/// flag at all.
pub fn with_args(changes: &[(String, String)]) -> Vec<OsString> {
    let mut out = Vec::new();
    for (key, word) in valid(changes) {
        let takes = crate::launch::WITH_KEYS
            .iter()
            .any(|(k, words)| *k == key && words.contains(&word.as_str()));
        if takes {
            out.push("--with".into());
            out.push(format!("{key}={word}").into());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whatever the window says back, only a key of the list and a word it
    /// takes are kept — and a launch's flags only what `run` takes there.
    #[test]
    fn only_the_words_each_key_takes_come_through() {
        let said = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect()
        };
        let changes = said(&[
            ("x11", "on"),
            ("camera", "default"),
            ("camera", "maybe"),
            ("hermetic", "off"),
            ("network", "ask"),
            ("focus", "notify"),
        ]);
        assert_eq!(
            valid(&changes),
            said(&[("x11", "on"), ("camera", "default"), ("focus", "notify")])
        );
        let args: Vec<String> = with_args(&changes)
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, ["--with", "x11=on"]);
        // Every word of the window's that `run` takes for a launch is one
        // `--with` takes.
        for (key, words) in crate::launch::WITH_KEYS {
            for word in words {
                assert!(choices(key).iter().any(|(w, _)| w == word), "{key}={word}");
            }
        }
    }

    /// A throwaway's launch says its X server and cameras; one joined, and
    /// everything else, is shown fixed.
    #[test]
    fn a_launch_with_no_record_says_only_what_it_decides() {
        let launch = of_launch(false);
        let free: Vec<&str> = launch
            .iter()
            .filter(|(_, _, fixed)| !fixed)
            .map(|(k, _, _)| k.as_str())
            .collect();
        assert_eq!(free, ["x11", "camera"]);
        assert!(of_launch(true).iter().all(|(_, _, fixed)| *fixed));
        assert!(of_new().iter().all(|(_, w, fixed)| w == DEFAULT && !fixed));
        assert_eq!(text_of("network", "ask"), "спрашивать");
    }
}
