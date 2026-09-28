//! Program permissions without the network (2b of `docs/PERMISSIONS.md`
//! §11.15, 2026-09-29): what a program gets is its container's word — or
//! the main home's own record's (`container::MAIN_RECORD`) —, else the
//! **template** here, else the built-in safe value. The network it runs in
//! has no say: it only says where packets go.
//!
//! **The template.** `~/.config/vpn-zones/defaults.conf` (`key = value`,
//! `cellward defaults set <key> <value>`), and `declared/defaults.conf` over
//! it (`programs.cellward.defaults.permissions`). A container's own word
//! is taken over it both ways: the template is a default, not a ceiling.
//! A program whose container is not known gets it, but never `yes`.
//!
//! **The move** ([`migrate`]): the networks' own words of before — a zone's
//! marker and Nix's list — become containers' own, once, and never wider
//! than before: a container bound to a network takes that network's word
//! where it differs from the template; the main home and the containers of
//! no network take the narrowest of all networks' where it is narrower than
//! the template. Whatever narrows is written to the journal.

use std::ffi::OsString;
use std::fs;
use std::path::Path;

use crate::container::Source;
use crate::microphone::Setting;
use crate::tools::Tools;

/// The template's local file, in the config directory.
pub const FILE: &str = "defaults.conf";
/// The switches (`yes|no|ask`), built-in `ask`.
pub const SWITCHES: [&str; 2] = ["microphone", "screencast"];
/// The flags (`on|off`, kept `true|false` as a container's), built-in off:
/// the cameras, and the host's raw PipeWire (the audio manager).
pub const FLAGS: [&str; 2] = ["camera", "audio_manager"];

/// The template's word for `key` and whose: Nix's over the local one;
/// `Err(source)`: a file there that cannot be read (the strictest, then).
fn word(config: &Path, key: &str) -> Result<Option<(String, Source)>, Source> {
    let declared = config.join(crate::cli::DECLARED_DIR).join(FILE);
    match crate::declared::read(&declared) {
        Ok(text) => {
            let conf = crate::container::parse_conf(&text);
            if let Some((_, v)) = conf.iter().rev().find(|(k, _)| k == key) {
                return Ok(Some((v.clone(), Source::Nix)));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Source::Nix),
    }
    match fs::read_to_string(config.join(FILE)) {
        Ok(text) => Ok(crate::container::parse_conf(&text)
            .into_iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| (v, Source::Local))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(Source::Local),
    }
}

/// The template's `yes|no|ask` switch `key`: `ask` where nobody said; a
/// word that is none of the three, or a file that cannot be read, `no`.
pub fn switch(config: &Path, key: &str) -> (Setting, Source) {
    match word(config, key) {
        Ok(Some((w, source))) => (Setting::parse(&w).unwrap_or(Setting::No), source),
        Ok(None) => (Setting::Ask, Source::Default),
        Err(source) => (Setting::No, source),
    }
}

/// The template's on/off flag `key`: off where nobody said, and for a word
/// that is neither, or a file that cannot be read.
pub fn flag(config: &Path, key: &str) -> (bool, Source) {
    match word(config, key) {
        Ok(Some((w, source))) => (matches!(w.as_str(), "true" | "on"), source),
        Ok(None) => (false, Source::Default),
        Err(source) => (false, source),
    }
}

/// How much a switch lets through.
fn openness(setting: Setting) -> u8 {
    match setting {
        Setting::No => 0,
        Setting::Ask => 1,
        Setting::Yes => 2,
    }
}

const USAGE: &str = "cellward defaults — разрешения контейнеров без своего слова\n\
                     cellward defaults set microphone|screencast yes|no|ask|default\n\
                     cellward defaults set camera|audio-manager on|off|default";

/// `cellward defaults [set <key> <value>|default]`.
pub fn run(tools: &Tools, args: &[OsString]) -> u8 {
    let args: Vec<&str> = args.iter().map(|a| a.to_str().unwrap_or("")).collect();
    match args.as_slice() {
        [] => {
            print!("{}", shown(&tools.config));
            0
        }
        ["set", key, value]
            if SWITCHES.contains(key) || FLAGS.contains(&key.replace('-', "_").as_str()) =>
        {
            let flag = FLAGS.contains(&key.replace('-', "_").as_str());
            let key = &key.replace('-', "_");
            let value = match (*value, flag) {
                ("default", _) => None,
                ("on", true) => Some("true"),
                ("off", true) => Some("false"),
                (v, false) => match Setting::parse(v) {
                    Some(s) => Some(s.as_str()),
                    None => {
                        eprintln!("{USAGE}");
                        return 1;
                    }
                },
                _ => {
                    eprintln!("{USAGE}");
                    return 1;
                }
            };
            if matches!(
                word(&tools.config, key),
                Ok(Some((_, Source::Nix))) | Err(Source::Nix)
            ) {
                eprintln!(
                    "cellward defaults: {key} задан в Nix (programs.cellward.defaults.permissions) \
                     — меняется там"
                );
                return 1;
            }
            let file = tools.config.join(FILE);
            let written = fs::create_dir_all(&tools.config)
                .map_err(|e| e.to_string())
                .and_then(|()| crate::container::write_key(&file, key, value, true));
            match written {
                Ok(()) => {
                    print!("{}", shown(&tools.config));
                    0
                }
                Err(e) => {
                    eprintln!("cellward defaults: {e}");
                    1
                }
            }
        }
        _ => {
            eprintln!("{USAGE}");
            1
        }
    }
}

fn shown(config: &Path) -> String {
    let mut out = String::from("Контейнерам без своего слова (и настоящему дому без своего):\n");
    for key in SWITCHES {
        let (setting, source) = switch(config, key);
        let from = match source {
            Source::Nix => " (Nix)",
            Source::Local => "",
            Source::Default => " (умолчание)",
        };
        out.push_str(&format!("  {key}: {}{from}\n", setting.as_str()));
    }
    for key in FLAGS {
        let (on, source) = flag(config, key);
        let from = match source {
            Source::Nix => " (Nix)",
            Source::Local => "",
            Source::Default => " (умолчание)",
        };
        let key = key.replace('_', "-");
        out.push_str(&format!(
            "  {key}: {}{from}\n",
            if on { "on" } else { "off" }
        ));
    }
    out
}

// --- THE MOVE ------------------------------------------------------------------

/// The marker of the move, in the containers' policy directory.
const MOVED: &str = ".permissions-by-container";

/// The networks' own words of before for a switch: `(network, setting)`,
/// the zone's marker (`marker` in its state directory) and Nix's list
/// (`declared/<declared>`, `<zone> <value>` lines) over it; the template's
/// value is no word.
fn network_words(tools: &Tools, marker: &str, declared: &str) -> Vec<(String, Setting)> {
    let mut out: Vec<(String, Setting)> = Vec::new();
    if let Ok(text) =
        crate::declared::read(&tools.config.join(crate::cli::DECLARED_DIR).join(declared))
    {
        for line in text.lines() {
            if let Some((zone, value)) = line.trim().split_once(char::is_whitespace) {
                let value = Setting::parse(value.trim()).unwrap_or(Setting::No);
                out.push((zone.to_owned(), value));
            }
        }
    }
    for entry in fs::read_dir(&tools.state).into_iter().flatten().flatten() {
        let zone = entry.file_name().to_string_lossy().into_owned();
        if zone.starts_with('.') || out.iter().any(|(z, _)| *z == zone) {
            continue;
        }
        if let Ok(text) = fs::read_to_string(entry.path().join(marker)) {
            if !text.trim().is_empty() {
                let value = Setting::parse(text.trim()).unwrap_or(Setting::No);
                out.push((zone, value));
            }
        }
    }
    out
}

/// The networks' own words of before for a flag: the zones named in Nix's
/// list (`declared/<list>`) on, and each zone's marker (`marker`: `on`, or
/// any other word off).
fn network_flags(tools: &Tools, marker: &str, list: &str) -> Vec<(String, Setting)> {
    let mut out: Vec<(String, Setting)> = Vec::new();
    if let Ok(text) = crate::declared::read(&tools.config.join(crate::cli::DECLARED_DIR).join(list))
    {
        for zone in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            out.push((zone.to_owned(), Setting::Yes));
        }
    }
    for entry in fs::read_dir(&tools.state).into_iter().flatten().flatten() {
        let zone = entry.file_name().to_string_lossy().into_owned();
        if zone.starts_with('.') || out.iter().any(|(z, _)| *z == zone) {
            continue;
        }
        if let Ok(text) = fs::read_to_string(entry.path().join(marker)) {
            let word = text.trim();
            if !word.is_empty() {
                let on = if word == "on" {
                    Setting::Yes
                } else {
                    Setting::No
                };
                out.push((zone, on));
            }
        }
    }
    out
}

/// What the move writes for switch `key`: `(record, value)`, each a
/// container's (or the main home's) own word it did not have.
pub fn moves(
    template: Setting,
    words: &[(String, Setting)],
    records: &[(String, Option<String>, bool)],
) -> Vec<(String, Setting)> {
    let narrowest = words
        .iter()
        .map(|(_, s)| *s)
        .min_by_key(|s| openness(*s))
        .filter(|s| openness(*s) < openness(template));
    let mut out = Vec::new();
    for (record, network, has_own) in records {
        if *has_own {
            continue;
        }
        let value = match network {
            Some(net) => words
                .iter()
                .find(|(z, _)| z == net)
                .map(|(_, s)| *s)
                .filter(|s| *s != template),
            None => narrowest,
        };
        if let Some(value) = value {
            out.push((record.clone(), value));
        }
    }
    out
}

/// The move, once (see the module's words). Run with the containers' own
/// move (`container::migrate`).
pub fn migrate(tools: &Tools) {
    let marker = tools.config.join(crate::container::POLICY_DIR).join(MOVED);
    if marker.exists() {
        return;
    }
    // Marked first: whatever becomes of it, it is not tried at every start.
    let _ = fs::create_dir_all(marker.parent().unwrap_or(&tools.config));
    if fs::write(&marker, "").is_err() {
        return;
    }
    let mut records: Vec<(String, Option<String>)> = crate::container::load_all_quiet(tools)
        .into_iter()
        .map(|c| {
            let net = match &c.network.value {
                crate::container::Network::Named(n) => Some(n.clone()),
                crate::container::Network::Ask => None,
            };
            (c.name, net)
        })
        .collect();
    records.push((crate::container::MAIN_RECORD.to_owned(), None));
    let mut said = Vec::new();
    // The flags as switches of two words: on is `yes`, off is `no` — the
    // same rule, never wider.
    for (key, marker_name) in [
        ("camera", crate::hermetic::CAMERA),
        ("audio_manager", crate::hermetic::AUDIO_MANAGER),
    ] {
        let words = network_flags(tools, marker_name, marker_name);
        if words.is_empty() {
            continue;
        }
        let template = if flag(&tools.config, key).0 {
            Setting::Yes
        } else {
            Setting::No
        };
        let with_own: Vec<(String, Option<String>, bool)> = records
            .iter()
            .map(|(name, net)| {
                // A file that cannot be read is a word not known: kept.
                let own = !matches!(
                    crate::container::own_value_in(&tools.config, name, key),
                    Ok(None)
                );
                (name.clone(), net.clone(), own)
            })
            .collect();
        for (record, value) in moves(template, &words, &with_own) {
            let word = if value == Setting::Yes {
                "true"
            } else {
                "false"
            };
            let file = crate::container::policy_dir(tools, &record).join(crate::container::FILE);
            if let Some(dir) = file.parent() {
                let _ = fs::create_dir_all(dir);
            }
            if crate::container::write_key(&file, key, Some(word), true).is_ok() {
                said.push(format!("{record}: {key} = {word}"));
            }
        }
    }
    for (key, marker_name, declared) in [
        (
            "microphone",
            crate::microphone::MARKER,
            crate::microphone::DECLARED,
        ),
        (
            "screencast",
            crate::screencast::MARKER,
            crate::screencast::DECLARED,
        ),
    ] {
        let words = network_words(tools, marker_name, declared);
        if words.is_empty() {
            continue;
        }
        let template = switch(&tools.config, key).0;
        let with_own: Vec<(String, Option<String>, bool)> = records
            .iter()
            .map(|(name, net)| {
                let own = crate::microphone::container_switch(&tools.config, name, key).is_some();
                (name.clone(), net.clone(), own)
            })
            .collect();
        for (record, value) in moves(template, &words, &with_own) {
            let file = crate::container::policy_dir(tools, &record).join(crate::container::FILE);
            if let Some(dir) = file.parent() {
                let _ = fs::create_dir_all(dir);
            }
            if crate::container::write_key(&file, key, Some(value.as_str()), true).is_ok() {
                said.push(format!("{record}: {key} = {}", value.as_str()));
            }
        }
    }
    let _ = fs::write(&marker, said.join("\n"));
    if !said.is_empty() {
        let text = said.join("; ");
        let _ = crate::journal::append(
            &tools.state,
            "permissions-moved",
            &[("words", text.as_str())],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The move never widens: a bound container takes its network's word
    /// where it differs from the template; the main home and the unbound
    /// the narrowest, only where it is narrower; a record with a word of
    /// its own is left as it is.
    #[test]
    fn the_move_never_widens() {
        let words = vec![
            ("nl".to_owned(), Setting::Yes),
            ("de".to_owned(), Setting::No),
        ];
        let records = vec![
            ("work".to_owned(), Some("nl".to_owned()), false),
            ("bank".to_owned(), Some("de".to_owned()), false),
            ("chat".to_owned(), Some("fr".to_owned()), false),
            ("main".to_owned(), None, false),
            ("own".to_owned(), Some("nl".to_owned()), true),
        ];
        let got = moves(Setting::Ask, &words, &records);
        assert_eq!(
            got,
            vec![
                ("work".to_owned(), Setting::Yes),
                ("bank".to_owned(), Setting::No),
                ("main".to_owned(), Setting::No),
            ]
        );
        // All networks as open as the template or more: nothing for main.
        let words = vec![("nl".to_owned(), Setting::Yes)];
        let got = moves(Setting::Ask, &words, &records[3..4]);
        assert!(got.is_empty(), "{got:?}");
    }

    #[test]
    fn the_template_is_read_nix_over_local() {
        let root = std::env::temp_dir().join(format!("vz-perm-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        assert_eq!(switch(&root, "microphone"), (Setting::Ask, Source::Default));
        fs::write(root.join(FILE), "microphone = no\nscreencast = sometimes\n").unwrap();
        assert_eq!(switch(&root, "microphone"), (Setting::No, Source::Local));
        assert_eq!(switch(&root, "screencast"), (Setting::No, Source::Local));
        let _ = fs::remove_dir_all(&root);
    }
}
