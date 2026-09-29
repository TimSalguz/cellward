//! What a program is known to need (step 3 of `docs/PERMISSIONS.md` §11.15,
//! owner 2026-09-29): a catalog of presets by launcher key, so that every
//! program can run in a container of its own from the first launch — and
//! keep working after a reboot — without the person working out, program by
//! program, what to give it.
//!
//! **Safe and not.** A preset's items are of two kinds:
//!
//! * **safe** ones are taken by themselves — written as the program's own
//!   container's words when that container is made ([`seed`]): asking for the
//!   microphone and the screen (asking is the default anyway; said here, it
//!   is the program's), an X server of its container's own, gamepads,
//!   security keys (a key signs nothing without a touch);
//! * **the rest are offered**, never given: the cameras (they have no
//!   "ask" yet), the microphone or the screen without asking, a folder of
//!   the real home, a device with a network of its own or every device, the
//!   host's session, the Nix daemon, the places the host runs, the raw
//!   PipeWire, a home that sees the real one. The launch window shows them
//!   unticked, with the preset's reason ([`offered`]).
//!
//! **Whose word.** The person's first: a program declared in Nix
//! (`programs.cellward.programs.<id>`, `declared/programs/<id>.conf`)
//! replaces the built-in preset whole; `cellward presets` shows which is in
//! force. A container's own word is never overwritten by a preset: seeding
//! writes only what it has no word of.

use std::fs;
use std::path::Path;

use crate::container::Source;
use crate::microphone::Setting;
use crate::tools::Tools;

/// Where Nix's presets are, below the config dir: `<id>.conf` each.
pub const DECLARED: &str = "programs";

/// One thing a preset gives or offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// The microphone: `ask` is safe, `yes` is offered.
    Microphone(Setting),
    /// The screen cast portal: `ask` is safe, `yes` is offered.
    Screencast(Setting),
    /// The host's cameras (no "ask" yet: step 4): offered.
    Camera,
    /// An X server of the container's own: safe — it is nobody else's.
    X11,
    /// A device grant (`devices::Grant`): gamepads and security keys are
    /// safe, the rest offered.
    Device(String),
    /// A folder of the real home, `~/…`: offered (written, until folders
    /// can be given read-only: step 5).
    Folder(String),
    /// The host's session — `systemd --user`, the whole bus: offered.
    Session,
    /// The Nix daemon: offered.
    NixDaemon,
    /// The places the host runs, writable: offered.
    HostFilesWritable,
    /// The host's raw PipeWire: offered.
    AudioManager,
    /// A home that sees the real one (`layer`, `main`): offered.
    Home(crate::container::Home),
}

impl Item {
    /// Taken by itself ([`seed`]), or only offered.
    pub fn safe(&self) -> bool {
        match self {
            Self::Microphone(s) | Self::Screencast(s) => *s != Setting::Yes,
            Self::X11 => true,
            Self::Device(word) => matches!(word.as_str(), "games" | "security-keys"),
            Self::Home(home) => *home == crate::container::Home::Private,
            Self::Camera
            | Self::Folder(_)
            | Self::Session
            | Self::NixDaemon
            | Self::HostFilesWritable
            | Self::AudioManager => false,
        }
    }

    /// As a preset file line (`key=value`), the form Nix writes and
    /// `cellward presets` shows.
    pub fn line(&self) -> String {
        match self {
            Self::Microphone(s) => format!("microphone={}", s.as_str()),
            Self::Screencast(s) => format!("screencast={}", s.as_str()),
            Self::Camera => "camera=on".to_owned(),
            Self::X11 => "x11=on".to_owned(),
            Self::Device(word) => format!("device={word}"),
            Self::Folder(path) => format!("folder={path}"),
            Self::Session => "session=on".to_owned(),
            Self::NixDaemon => "nix_daemon=on".to_owned(),
            Self::HostFilesWritable => "host_files_writable=on".to_owned(),
            Self::AudioManager => "audio_manager=on".to_owned(),
            Self::Home(home) => format!("home={}", home.setting()),
        }
    }

    /// One line of a preset file; anything else is none.
    pub fn parse(line: &str) -> Option<Self> {
        let (key, value) = line.split_once('=')?;
        let (key, value) = (key.trim(), value.trim());
        let on = matches!(value, "on" | "true" | "yes");
        Some(match key {
            "microphone" => Self::Microphone(Setting::parse(value)?),
            "screencast" => Self::Screencast(Setting::parse(value)?),
            "camera" if on => Self::Camera,
            "x11" if on => Self::X11,
            "device" => Self::Device(crate::devices::Grant::parse(value)?.word()),
            "folder" if value.starts_with("~/") && !value.contains(['\n', '\r']) => {
                Self::Folder(value.to_owned())
            }
            "session" if on => Self::Session,
            "nix_daemon" if on => Self::NixDaemon,
            "host_files_writable" if on => Self::HostFilesWritable,
            "audio_manager" if on => Self::AudioManager,
            "home" => Self::Home(crate::container::Home::parse(value)?),
            _ => return None,
        })
    }

    /// What it is, for a person.
    pub fn text(&self) -> String {
        match self {
            Self::Microphone(Setting::Yes) => "микрофон без вопроса".to_owned(),
            Self::Microphone(_) => "микрофон — спрашивать".to_owned(),
            Self::Screencast(Setting::Yes) => "показ экрана без вопроса".to_owned(),
            Self::Screencast(_) => "показ экрана — спрашивать".to_owned(),
            Self::Camera => "камеры".to_owned(),
            Self::X11 => "свой X-сервер".to_owned(),
            Self::Device(word) => match word.as_str() {
                "games" => "геймпады".to_owned(),
                "security-keys" => "ключи безопасности".to_owned(),
                "phone" => "телефон (может дать свою сеть)".to_owned(),
                "serial" => "последовательные порты".to_owned(),
                "vm" => "виртуальные машины (kvm, tun)".to_owned(),
                crate::devices::ALL => "все устройства".to_owned(),
                other => format!("устройство {other}"),
            },
            Self::Folder(path) => format!("папка {path}"),
            Self::Session => "сеанс хоста (systemd --user, вся шина)".to_owned(),
            Self::NixDaemon => "Nix-демон".to_owned(),
            Self::HostFilesWritable => "запись того, что исполняет хост".to_owned(),
            Self::AudioManager => "PipeWire хоста без ограничений".to_owned(),
            Self::Home(home) => format!("дом: {}", home.label()),
        }
    }
}

/// A preset: the launcher keys it is for, its items, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preset {
    pub items: Vec<Item>,
    pub why: String,
    pub source: Source,
}

use Item::{
    AudioManager as Am, Camera as Cam, Device as Dev, Folder as Dir, HostFilesWritable as Hfw,
    Microphone as Mic, NixDaemon as Nix, Screencast as Cast, Session as Ses, X11,
};

/// A built-in entry: the keys, the items, why.
type Entry = (&'static [&'static str], fn() -> Vec<Item>, &'static str);

fn dev(word: &str) -> Item {
    Dev(word.to_owned())
}

fn dir(path: &str) -> Item {
    Dir(path.to_owned())
}

/// The built-in catalog, by launcher key (the desktop entry's id).
const CATALOG: &[Entry] = &[
    (
        &[
            "firefox",
            "librewolf",
            "zen",
            "zen-browser",
            "chromium",
            "chromium-browser",
            "google-chrome",
            "com.google.Chrome",
            "helium",
            "brave-browser",
            "org.qutebrowser.qutebrowser",
            "vivaldi-stable",
        ],
        || {
            vec![
                Mic(Setting::Ask),
                Cast(Setting::Ask),
                dev("security-keys"),
                Cam,
                dir("~/Downloads"),
            ]
        },
        "браузер: звонки и показ экрана по вопросу, ключи для входа; камера и загрузки — по выбору",
    ),
    (
        &[
            "vesktop",
            "discord",
            "com.discordapp.Discord",
            "webcord",
            "TeamSpeak",
            "teamspeak",
            "com.slack.Slack",
            "slack",
            "zoom",
            "us.zoom.Zoom",
            "element-desktop",
            "im.riot.Riot",
            "signal-desktop",
            "org.signal.Signal",
        ],
        || vec![Mic(Setting::Ask), Cast(Setting::Ask), Cam],
        "звонки: микрофон и показ экрана по вопросу; камера — по выбору",
    ),
    (
        &[
            "org.telegram.desktop",
            "telegram-desktop",
            "com.ayugram.desktop",
            "io.github.kotatogram",
        ],
        || vec![Mic(Setting::Ask), Cast(Setting::Ask), Cam, dir("~/Downloads")],
        "мессенджер: голосовые и звонки по вопросу; камера и загрузки — по выбору",
    ),
    (
        &["com.obsproject.Studio", "obs"],
        || {
            vec![
                Cast(Setting::Ask),
                Mic(Setting::Ask),
                Cam,
                Am,
                dir("~/Videos"),
            ]
        },
        "запись экрана: показ экрана и микрофон по вопросу; камеры, звук всей системы и папка записей — по выбору",
    ),
    (
        &["steam", "com.valvesoftware.Steam"],
        || vec![X11, dev("games"), Mic(Setting::Ask)],
        "игры: свой X, геймпады, голосовой чат по вопросу",
    ),
    (
        &[
            "net.lutris.Lutris",
            "net.lutris.Lutris1",
            "lutris",
            "com.heroicgameslauncher.hgl",
            "com.usebottles.bottles",
            "protontricks",
            "wine",
            "winetricks",
            "proton-run",
        ],
        || vec![X11, dev("games")],
        "игры и Wine: свой X, геймпады",
    ),
    (
        &[
            "mpv",
            "umpv",
            "vlc",
            "org.kde.haruna",
            "io.github.celluloid_player.Celluloid",
        ],
        || vec![dir("~/Videos"), dir("~/Music")],
        "плеер: папки видео и музыки — по выбору",
    ),
    (
        &["imv", "imv-dir", "org.kde.gwenview", "gimp", "org.gimp.GIMP", "swappy"],
        || vec![dir("~/Pictures")],
        "изображения: папка картинок — по выбору",
    ),
    (
        &["org.kde.okular", "okularApplication_pdf", "org.gnome.Evince"],
        || vec![dir("~/Documents")],
        "документы: папка документов — по выбору",
    ),
    (
        &["org.keepassxc.KeePassXC", "keepassxc"],
        || vec![dev("security-keys"), dir("~/Documents")],
        "менеджер паролей: ключи безопасности; папка с базой — по выбору",
    ),
    (
        &["org.qbittorrent.qBittorrent", "qbittorrent", "transmission-gtk"],
        || vec![dir("~/Downloads")],
        "торрент: папка загрузок — по выбору",
    ),
    (
        &["com.anthropic.Claude"],
        || vec![Mic(Setting::Ask), dir("~/Documents")],
        "ассистент: голос по вопросу; папка документов — по выбору",
    ),
    (
        &["org.pulseaudio.pavucontrol", "pavucontrol", "com.saivert.pwvucontrol"],
        || vec![Am],
        "микшер: управлять звуком всей системы можно только с PipeWire хоста — по выбору",
    ),
    (
        &["codium", "code", "dev.zed.Zed", "org.kde.kate", "org.kde.kwrite"],
        || vec![dir("~/Projects"), Nix],
        "редактор: папка проектов и Nix-демон (сборка) — по выбору",
    ),
    (
        &[
            "Alacritty",
            "foot",
            "footclient",
            "org.wezfurlong.wezterm",
            "kitty",
            "com.mitchellh.ghostty",
            "org.kde.konsole",
        ],
        || {
            vec![
                Item::Home(crate::container::Home::Main),
                Nix,
                Ses,
                Hfw,
            ]
        },
        "терминал: всё это — по выбору; без выбора — свой дом, как у любой программы",
    ),
    (
        &["virt-manager", "remote-viewer"],
        || vec![dev("vm"), Ses],
        "виртуальные машины: kvm и tun, сеанс хоста (libvirt) — по выбору",
    ),
    (
        &["opendeck", "GalaxyBudsClient"],
        || vec![dev(crate::devices::ALL)],
        "работает с устройством напрямую — все устройства по выбору",
    ),
];

/// The built-in preset for `key`, if the catalog has one.
pub fn built_in(key: &str) -> Option<Preset> {
    CATALOG
        .iter()
        .find(|(keys, _, _)| keys.contains(&key))
        .map(|(_, items, why)| Preset {
            items: items(),
            why: (*why).to_owned(),
            source: Source::Default,
        })
}

/// Nix's preset for `key` (`declared/programs/<key>.conf`), whole: a line
/// each, `why=…` its reason.
fn declared(config: &Path, key: &str) -> Option<Preset> {
    if key.is_empty() || key.contains('/') || key.starts_with('.') {
        return None;
    }
    let file = config
        .join(crate::cli::DECLARED_DIR)
        .join(DECLARED)
        .join(format!("{key}.conf"));
    let text = crate::declared::read(&file).ok()?;
    let mut why = String::new();
    let mut items = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(text) = line.strip_prefix("why=") {
            why = text.trim().to_owned();
        } else if let Some(item) = Item::parse(line) {
            if !items.contains(&item) {
                items.push(item);
            }
        }
    }
    Some(Preset {
        items,
        why,
        source: Source::Nix,
    })
}

/// The preset in force for `key`: Nix's, else the catalog's.
pub fn for_key(config: &Path, key: &str) -> Option<Preset> {
    declared(config, key).or_else(|| built_in(key))
}

/// What a preset only offers: the items that are not [`Item::safe`].
pub fn offered(preset: &Preset) -> Vec<Item> {
    preset.items.iter().filter(|i| !i.safe()).cloned().collect()
}

/// A new container of `key`'s own (`picker::own_name`) takes the safe items
/// of the preset in force — each where it has no word of its own. What was
/// written, as lines.
pub fn seed(tools: &Tools, container: &str, key: &str) -> Vec<String> {
    let Some(preset) = for_key(&tools.config, key) else {
        return Vec::new();
    };
    let mut written = Vec::new();
    for item in preset.items.iter().filter(|i| i.safe()) {
        let done = match item {
            Item::Microphone(s) => {
                (crate::container::own_value_in(&tools.config, container, "microphone")
                    .ok()
                    .flatten()
                    .is_none())
                .then(|| crate::container::set_microphone(tools, container, Some(*s)))
            }
            Item::Screencast(s) => {
                (crate::container::own_value_in(&tools.config, container, "screencast")
                    .ok()
                    .flatten()
                    .is_none())
                .then(|| crate::container::set_screencast(tools, container, Some(*s)))
            }
            Item::X11 => crate::container::load(tools, container)
                .is_some_and(|c| c.x11.is_none())
                .then(|| crate::container::set_x11(tools, container, Some(true))),
            Item::Device(word) => crate::container::load(tools, container)
                .is_some_and(|c| !c.devices.iter().any(|d| d.value == *word))
                .then(|| crate::container::set_device(tools, container, word, true)),
            _ => None,
        };
        if let Some(Ok(())) = done {
            written.push(item.line());
        }
    }
    written
}

const USAGE: &str = "cellward presets [<программа>] [--json] — что программе нужно по заготовке";

/// `cellward presets [<key>] [--json]`.
pub fn run(tools: &Tools, args: &[std::ffi::OsString]) -> u8 {
    let args: Vec<&str> = args.iter().map(|a| a.to_str().unwrap_or("")).collect();
    let json = args.contains(&"--json");
    let keys: Vec<&str> = args.iter().copied().filter(|a| *a != "--json").collect();
    let keys: Vec<String> = match keys.as_slice() {
        [] => {
            let mut all: Vec<String> = CATALOG
                .iter()
                .flat_map(|(keys, _, _)| keys.iter().map(|k| (*k).to_owned()))
                .collect();
            let dir = tools.config.join(crate::cli::DECLARED_DIR).join(DECLARED);
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if let Some(key) = name.strip_suffix(".conf") {
                        all.push(key.to_owned());
                    }
                }
            }
            all.sort();
            all.dedup();
            all
        }
        [key] => vec![(*key).to_owned()],
        _ => {
            eprintln!("{USAGE}");
            return 1;
        }
    };
    let found: Vec<(String, Preset)> = keys
        .iter()
        .filter_map(|k| for_key(&tools.config, k).map(|p| (k.clone(), p)))
        .collect();
    if json {
        let items = |preset: &Preset, safe: bool| {
            let lines: Vec<String> = preset
                .items
                .iter()
                .filter(|i| i.safe() == safe)
                .map(|i| crate::json::quote(&i.line()))
                .collect();
            format!("[{}]", lines.join(","))
        };
        let rows: Vec<String> = found
            .iter()
            .map(|(key, p)| {
                format!(
                    "{{\"id\":{},\"source\":\"{}\",\"why\":{},\"given\":{},\"offered\":{}}}",
                    crate::json::quote(key),
                    p.source.as_str(),
                    crate::json::quote(&p.why),
                    items(p, true),
                    items(p, false)
                )
            })
            .collect();
        println!("[{}]", rows.join(","));
        return 0;
    }
    if found.is_empty() {
        println!("заготовки нет — программа получает то же, что любая: свой дом и вопросы");
        return 0;
    }
    for (key, preset) in &found {
        let from = if preset.source == Source::Nix {
            " (Nix)"
        } else {
            ""
        };
        println!("{key}{from}: {}", preset.why);
        for item in &preset.items {
            let how = if item.safe() {
                "само"
            } else {
                "по выбору"
            };
            println!("  {} — {how}", item.text());
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Asking is safe, giving is not; gamepads and keys are, a device with a
    /// network of its own is not; a folder, the host's session, a home that
    /// sees the real one never are.
    #[test]
    fn what_is_taken_by_itself_and_what_is_only_offered() {
        assert!(Mic(Setting::Ask).safe() && !Mic(Setting::Yes).safe());
        assert!(Cast(Setting::Ask).safe() && !Cast(Setting::Yes).safe());
        assert!(X11.safe() && dev("games").safe() && dev("security-keys").safe());
        for item in [
            Cam,
            dev("phone"),
            dev("vm"),
            dev("all"),
            dir("~/Downloads"),
            Ses,
            Nix,
            Hfw,
            Am,
            Item::Home(crate::container::Home::Main),
            Item::Home(crate::container::Home::Layer),
        ] {
            assert!(!item.safe(), "{item:?}");
        }
    }

    /// Every item reads back from its line; a line that is none is none.
    #[test]
    fn an_item_is_its_line() {
        for (_, items, why) in CATALOG {
            assert!(!why.is_empty());
            for item in items() {
                assert_eq!(Item::parse(&item.line()), Some(item.clone()), "{item:?}");
            }
        }
        for bad in [
            "camera=off",
            "folder=/etc",
            "device=everything",
            "microphone=maybe",
            "session",
            "whatever=on",
        ] {
            assert_eq!(Item::parse(bad), None, "{bad}");
        }
    }

    /// A key is in the catalog once.
    #[test]
    fn a_key_has_one_built_in_preset() {
        let mut keys: Vec<&str> = CATALOG
            .iter()
            .flat_map(|(k, _, _)| k.iter().copied())
            .collect();
        let n = keys.len();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), n);
        assert!(built_in("firefox").is_some_and(|p| p.items.contains(&Mic(Setting::Ask))));
        assert!(built_in("no-such-program").is_none());
    }

    /// Nix's preset replaces the built-in one whole.
    #[test]
    fn nix_replaces_the_built_in_preset() {
        let root = std::env::temp_dir().join(format!("vz-presets-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let config = root.join("config");
        let file = config
            .join(crate::cli::DECLARED_DIR)
            .join(DECLARED)
            .join("firefox.conf");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        crate::declared::declare(&file, "why=мой\nx11=on\nfolder=~/Work\nnonsense\n");
        let preset = for_key(&config, "firefox").unwrap();
        assert_eq!(preset.source, Source::Nix);
        assert_eq!(preset.why, "мой");
        assert_eq!(preset.items, vec![X11, dir("~/Work")]);
        assert_eq!(offered(&preset), vec![dir("~/Work")]);
        let _ = fs::remove_dir_all(&root);
    }
}
