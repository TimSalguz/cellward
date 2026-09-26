//! `.desktop` generation for VPN zones. Two modes, switched with
//! `vpn-zone mode`.
//!
//! **picker mode** (the default) is what this exists for. The application keeps
//! its single launcher entry, but that entry is intercepted: instead of the
//! program it starts the picker, which asks "which network?" and calls the
//! program itself. The launcher does not grow a row of duplicates, and the
//! network is chosen at the moment of starting. The interception is the plain
//! XDG trick — a file of the same name in `~/.local/share/applications`
//! shadows the system one. The originals in `/nix/store` are never touched;
//! undoing it is deleting our files (`vpn-zone mode off`).
//!
//! **per-zone mode** is the older behaviour: one entry per zone, "Firefox
//! (nl)". Useful for starting into a specific zone with one click and no
//! dialog. `both` does both.
//!
//! **Self-eating protection** (in both modes):
//!
//! * files carrying the `X-VPNZone` key are never taken as input;
//! * in per-zone mode clones are additionally filtered out by name prefix;
//! * foreign files in `~/.local/share/applications` (home-manager symlinks,
//!   hand-written entries) are NEVER overwritten — only our own, the ones
//!   carrying the marker. Without that the very first sync would have erased
//!   the entries Nix puts there.
//!
//! Why a parser and not `sed`: a `.desktop` file is an ini with localised keys
//! and escaping, and taking it apart line by line means one day producing an
//! entry with a mangled `Exec`. (`docs/GOTCHAS.md` §10)

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

/// Prefix of every file this module writes itself, and of the module's own
/// menu entries. Files starting with it are never taken as input.
pub const PREFIX: &str = "vpn-zone-";
/// Where the original bytes of taken-over entries are kept, below the state
/// directory: one file per entry, under the entry's own name.
pub const ADOPTED_DIR: &str = ".adopted";
/// Where the lock of the whole sync pass lives, below the state directory.
pub const SYNC_LOCK_DIR: &str = ".sync";
/// Backups of the autostart entries taken over, below the state directory.
/// Apart from [`ADOPTED_DIR`]: an autostart entry and a launcher entry often
/// share a file name (`org.telegram.desktop.desktop`) and differ in content.
pub const AUTOSTART_ADOPTED_DIR: &str = ".adopted-autostart";
/// Where shadow D-Bus service files go, below the home: the session bus reads
/// this directory before the system ones (`docs/CONTAINERS.md` §5.3).
pub const DBUS_SERVICES: &str = ".local/share/dbus-1/services";
/// The marker of our service files. A comment: a key the bus does not know
/// might make it reject the file.
const DBUS_MARK: &str = "# X-VPNZone=dbus";
/// The picker's flag for a launch from XDG autostart: no dialog, ever.
pub const AUTOSTART_FLAG: &str = "--autostart";
/// The marker value of an entry taken over in place: `X-VPNZone=adopted`.
const ADOPTED: &str = "adopted";
/// The marker that says "this file is ours". Present in the file we write and
/// checked before overwriting or deleting anything.
pub const MARK: &str = "X-VPNZone";

/// What gets carried into a per-zone clone.
///
/// `MimeType` is deliberately **not** here: otherwise the clones would start
/// claiming file associations, and one day "open this image" would silently
/// travel into a VPN zone. In picker mode it is the other way round — there is
/// only one entry and it MUST keep the associations, or the program stops
/// being a handler. (`docs/GOTCHAS.md` §10)
const CLONE_KEYS: [&str; 7] = [
    "Icon",
    "Terminal",
    "Categories",
    "Keywords",
    "StartupNotify",
    "StartupWMClass",
    "Path",
];

/// Keys that must never be copied into a picker entry: `Exec` is rewritten,
/// and the other two would let the launcher reach the program around it.
const PICKER_DROPPED_KEYS: [&str; 3] = ["Exec", "DBusActivatable", "TryExec"];

/// Localised label keys. `Name` is the only one a zone suffix is appended to.
const LABEL_KEYS: [&str; 3] = ["Name", "GenericName", "Comment"];

/// The `%f`, `%U`… field codes of the desktop entry specification.
const FIELD_CODES: &str = "fFuUdDnNickvm";

/// Our own menu entries. home-manager puts them there as symlinks, so `ours()`
/// would leave them alone anyway — they are listed to make the intent visible.
const OWN_ENTRIES: [&str; 3] = [
    "vpn-zone-add.desktop",
    "vpn-zone-remove.desktop",
    "vpn-zone-forget.desktop",
];

/// How the launcher entries are generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Picker,
    PerZone,
    Both,
    Off,
}

impl Mode {
    /// Anything unknown in the mode file means the default, never a failure:
    /// this runs from a path unit and a timer, where an error is invisible.
    pub fn parse(text: &str) -> Self {
        match text.trim() {
            "per-zone" => Self::PerZone,
            "both" => Self::Both,
            "off" => Self::Off,
            _ => Self::Picker,
        }
    }

    /// What to say about a mode that is on its way out, if anything.
    ///
    /// Per-zone clones are deprecated (`docs/LAUNCHERS.md` §4): their purpose
    /// is "this program, in that network" on every click, which is exactly how
    /// one identity ends up in two networks, and they grow as programs × zones.
    /// Nothing is removed yet; the notice says why and what replaces them.
    pub fn deprecation(self) -> Option<&'static str> {
        self.clones().then_some(
            "режим ярлыков per-zone/both устарел и будет убран: ярлык на каждую зону — это выбор \
             сети на каждый клик, так одна программа оказывается в двух сетях. Замена — один \
             ярлык с пикером (cellward mode picker), а позже ярлыки контейнеров \
             (docs/LAUNCHERS.ru.md §4)",
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Picker => "picker",
            Self::PerZone => "per-zone",
            Self::Both => "both",
            Self::Off => "off",
        }
    }

    fn intercepts(self) -> bool {
        matches!(self, Self::Picker | Self::Both)
    }

    fn clones(self) -> bool {
        matches!(self, Self::PerZone | Self::Both)
    }
}

/// One `[Group]` of a desktop file with its keys, in file order.
///
/// A `Vec` and not a map on purpose: the output has to keep the order of the
/// input, so that a rewritten entry stays diff-able against the original.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Group {
    pub name: String,
    entries: Vec<(String, String)>,
}

impl Group {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.0 == key)
            .map(|e| e.1.as_str())
    }

    /// Keys and values in file order.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Last value wins, first position wins — the same thing a Python dict did.
    fn set(&mut self, key: &str, value: &str) {
        match self.entries.iter_mut().find(|e| e.0 == key) {
            Some(e) => e.1 = value.to_string(),
            None => self.entries.push((key.to_string(), value.to_string())),
        }
    }

    /// Is `key` present, either plain or in any localised form (`Name[ru]`)?
    fn has(&self, key: &str) -> bool {
        self.entries
            .iter()
            .any(|(k, _)| k == key || k.starts_with(&format!("{key}[")))
    }
}

/// Read a whole desktop file: `[(group name, keys)]`.
///
/// Invalid UTF-8 is replaced rather than rejected (Python read these with
/// `errors="replace"`): a broken byte in some translated `Comment` must not
/// cost the user their launcher entry.
pub fn parse_desktop(text: &str) -> Vec<Group> {
    let mut groups: Vec<Group> = Vec::new();
    for raw in text.lines() {
        let s = raw.trim();
        if s.len() >= 2 && s.starts_with('[') && s.ends_with(']') {
            groups.push(Group {
                name: s[1..s.len() - 1].to_string(),
                entries: Vec::new(),
            });
            continue;
        }
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        let Some((key, value)) = s.split_once('=') else {
            continue;
        };
        // Keys before the first group header belong to nothing and are
        // dropped, as the specification says.
        let Some(current) = groups.last_mut() else {
            continue;
        };
        current.set(key.trim(), value.trim());
    }
    groups
}

/// Same, from a file. An unreadable file yields no groups, which makes it a
/// non-candidate — never an error.
pub fn parse_desktop_file(path: &Path) -> Vec<Group> {
    match fs::read(path) {
        Ok(bytes) => parse_desktop(&String::from_utf8_lossy(&bytes)),
        Err(_) => Vec::new(),
    }
}

/// The `[Desktop Entry]` group.
pub fn desktop_entry(groups: &[Group]) -> Option<&Group> {
    groups.iter().find(|g| g.name == "Desktop Entry")
}

/// Can this file be intercepted or cloned?
pub fn is_candidate(file_name: &str, entry: Option<&Group>) -> bool {
    if file_name.starts_with(PREFIX) {
        return false;
    }
    let Some(entry) = entry else {
        return false;
    };
    // Ours already — taking it as input is how a generator eats itself.
    if entry.has(MARK) {
        return false;
    }
    if entry.get("Type").unwrap_or("Application") != "Application" {
        return false;
    }
    for hidden in ["NoDisplay", "Hidden"] {
        if entry
            .get(hidden)
            .unwrap_or("false")
            .eq_ignore_ascii_case("true")
        {
            return false;
        }
    }
    entry.get("Exec").is_some_and(|e| !e.is_empty())
}

/// A hidden handler: an application entry kept out of menus (`NoDisplay=true`)
/// that exists to open files or links (`MimeType` is set).
///
/// These are exactly the entries links and "open with" go through —
/// `okularApplication_pdf`, `codium-url-handler`, `imv-dir` — and they used to
/// be skipped as non-candidates, so a PDF or a link opened through one started
/// the program around the picker, without its container and in the host's
/// network. They are intercepted now, but only under the id of a VISIBLE entry
/// of the same program (see [`sync`]): a hidden system helper with no program
/// of its own in the menu (an OAuth callback, a settings URL handler) is left
/// alone rather than turned into a network dialog. `Hidden=true` means
/// "deleted" and is never a handler. (`docs/LAUNCHERS.md` L6)
pub fn is_hidden_handler(file_name: &str, entry: Option<&Group>) -> bool {
    if file_name.starts_with(PREFIX) {
        return false;
    }
    let Some(entry) = entry else {
        return false;
    };
    let flag = |key: &str| {
        entry
            .get(key)
            .unwrap_or("false")
            .eq_ignore_ascii_case("true")
    };
    !entry.has(MARK)
        && entry.get("Type").unwrap_or("Application") == "Application"
        && flag("NoDisplay")
        && !flag("Hidden")
        && entry.get("Exec").is_some_and(|e| !e.is_empty())
        && entry.get("MimeType").is_some_and(|m| !m.trim().is_empty())
}

/// The words of an `Exec` line, the way the desktop entry specification quotes
/// them: whitespace separates, double quotes group, a backslash inside quotes
/// escapes the next character.
///
/// Used only to recognise WHICH PROGRAM an entry starts and what it hands over
/// — never to build a command line: `Exec` is always passed on verbatim.
pub fn exec_words(exec: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_word = false;
    let mut quoted = false;
    let mut chars = exec.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                quoted = !quoted;
                in_word = true;
            }
            '\\' if quoted => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            c if c.is_whitespace() && !quoted => {
                if in_word {
                    words.push(std::mem::take(&mut current));
                    in_word = false;
                }
            }
            c => {
                current.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(current);
    }
    words
}

/// The program an `Exec` line starts: wrappers and assignments skipped, by the
/// same rule `vpn-zone run` names the program with.
pub fn exec_program(exec: &str) -> Option<String> {
    let words: Vec<OsString> = exec_words(exec).into_iter().map(OsString::from).collect();
    crate::launch::app_word(&words).map(|w| w.to_string_lossy().into_owned())
}

/// The URL schemes an `Exec` line hands to its program: `steam` for
/// `steam steam://rungameid/1`. Field codes are not URLs.
pub fn exec_url_schemes(exec: &str) -> Vec<String> {
    exec_words(exec)
        .iter()
        .skip(1)
        .filter_map(|word| {
            let (scheme, _) = word.split_once("://")?;
            let mut chars = scheme.chars();
            let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
                && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'));
            valid.then(|| scheme.to_ascii_lowercase())
        })
        .collect()
}

/// The URL schemes an entry claims: `x-scheme-handler/<scheme>` in `MimeType`.
pub fn claimed_schemes(entry: &Group) -> Vec<String> {
    entry
        .get("MimeType")
        .unwrap_or("")
        .split(';')
        .filter_map(|mime| mime.trim().strip_prefix("x-scheme-handler/"))
        .filter(|scheme| !scheme.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

/// A hidden application entry of the user's own directory, with or without a
/// `MimeType`: not ours, with a command. Deleted ones (`Hidden=true`, what a
/// menu editor writes to "remove" an entry) count too: menus skip them, but
/// xdg-open does not, and a `mimeapps.list` default naming such a file ran
/// its command as it was — around the picker, on the host.
fn is_hidden_user_entry(file_name: &str, entry: Option<&Group>) -> bool {
    let Some(entry) = entry else {
        return false;
    };
    let flag = |key: &str| {
        entry
            .get(key)
            .unwrap_or("false")
            .eq_ignore_ascii_case("true")
    };
    !file_name.starts_with(PREFIX)
        && !entry.has(MARK)
        && entry.get("Type").unwrap_or("Application") == "Application"
        && (flag("NoDisplay") || flag("Hidden"))
        && entry.get("Exec").is_some_and(|e| !e.is_empty())
}

/// The memory key of a launcher id: [`sanitize`] when that lost nothing,
/// otherwise with the first eight hex digits of an FNV-1a hash of the id
/// appended (`docs/LAUNCHERS.md` §3.4, L8).
///
/// `sanitize` alone maps every character it does not keep to `_`, so two ids
/// of the same length that differ only there — `Игра` and `Мама`, `a b` and
/// `a_b` — got ONE key: one pin, one container, one network for two programs,
/// and the second went where the first was sent without a word. Idempotent:
/// a key is all kept characters, so it maps to itself — the picker gets the key
/// on its command line and derives it again.
pub fn stable_key(raw: &str) -> String {
    let kept = sanitize(raw);
    if kept == raw {
        return kept;
    }
    format!("{kept}-{:08x}", fnv1a(raw))
}

/// 32-bit FNV-1a: what a name that had to be changed keeps of what it was.
fn fnv1a(raw: &str) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in raw.bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

// --- THE ZONE'S NAME FOR THE PORTAL ------------------------------------------

/// The first elements of every zone's application id.
pub const ZONE_APP_PREFIX: &str = "cellward.zone.";
/// The marker value of a zone's entry for the portal: `X-VPNZone=portal`.
const PORTAL_ENTRY: &str = "portal";
/// What the entry is drawn with in the portal's dialogs: the module's own
/// launcher entries have it too.
const ZONE_ICON: &str = "network-vpn";
/// The longest application id D-Bus and GLib take.
const MAX_APP_ID: usize = 255;

/// The application id a zone's programs have for the portal (LEAK-MODEL §23):
/// `cellward.zone.<id>`, which the zone's bus filter registers for each of
/// their connections with the portal's host registry before any call of
/// theirs passes (`crate::bus_filter`).
///
/// `<id>` is the zone's name with every character but `[A-Za-z0-9_]` turned
/// into `_`, and a `_` in front of a leading digit — one element of an
/// application id. A name that changed on the way (`work-vpn`, `1st`) gets
/// the first eight hex digits of its FNV-1a hash appended, as a launcher key
/// does (`stable_key`): `work-vpn` and `work_vpn` are two zones, and one id
/// for both would give the portal one application for two zones — one
/// permission store, one remembered screen cast, one name in its dialogs, and
/// one entry file the two would overwrite and `rm` of either would take. A
/// name that is too long is cut, and hashed for the same reason.
pub fn zone_app_id(zone: &str) -> String {
    let mut id: String = zone
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if id.is_empty() || id.starts_with(|c: char| c.is_ascii_digit()) {
        id.insert(0, '_');
    }
    let room = MAX_APP_ID - ZONE_APP_PREFIX.len();
    if id != zone || id.len() > room {
        // All ASCII by now: cutting at a byte is cutting at a character.
        id.truncate(room - 9);
        id = format!("{id}_{:08x}", fnv1a(zone));
    }
    format!("{ZONE_APP_PREFIX}{id}")
}

/// The file of a zone's entry for the portal, in the applications directory:
/// the portal finds an application by `<id>.desktop` and nothing else.
pub fn zone_entry_file(zone: &str) -> String {
    format!("{}.desktop", zone_app_id(zone))
}

/// A string value of a desktop entry: the specification's escapes, so that a
/// name can neither end the line nor start a key of its own.
fn desktop_value(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (i, c) in text.chars().enumerate() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            ' ' if i == 0 => out.push_str("\\s"),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// One argument of an `Exec` line, quoted the specification's way when it
/// has to be (a reserved character in it), a `%` doubled so that it is no
/// field code. The line then goes through [`desktop_value`] like any string.
fn exec_argument(arg: &str) -> String {
    let arg = arg.replace('%', "%%");
    let reserved = |c: char| c.is_whitespace() || "\"'\\><~|&;$*?#()`".contains(c);
    if !arg.is_empty() && !arg.chars().any(reserved) {
        return arg;
    }
    let mut out = String::from("\"");
    for c in arg.chars() {
        if matches!(c, '"' | '`' | '$' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// A zone's entry for the portal: what its dialogs name the zone's programs
/// by. Never shown in a menu (`NoDisplay`), never started — but GLib loads an
/// entry only when its `Exec` names a program it can find, so the command is
/// a real one and harmless: `cellward status <zone>`, by the profile's path
/// (`runner`), which the portal's own `PATH` need not have. Ours by the
/// marker: sync neither takes it over nor clones it, and keeps it while the
/// zone exists (`sync_from`).
pub fn render_zone_entry(zone: &str, runner: &str) -> String {
    let exec = format!("{} status {}", exec_argument(runner), exec_argument(zone));
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name={}\n\
         Comment={}\n\
         Exec={}\n\
         Icon={ZONE_ICON}\n\
         NoDisplay=true\n\
         {MARK}={PORTAL_ENTRY}\n",
        desktop_value(&format!("cellward · {zone}")),
        desktop_value(&format!("Программы зоны «{zone}»")),
        desktop_value(&exec),
    )
}

/// Write a zone's entry for the portal into `home`'s applications directory
/// when it is not there as it should be. Whether it was written; an error
/// for a place taken by a file that is not ours, which stays as it is.
pub fn write_zone_entry(home: &Path, zone: &str, runner: &str) -> std::io::Result<bool> {
    let dir = home.join(".local/share/applications");
    fs::create_dir_all(&dir)?;
    let target = dir.join(zone_entry_file(zone));
    if occupied(&target) && !ours(&target) {
        return Err(std::io::Error::other(format!(
            "{} is not ours",
            target.display()
        )));
    }
    let text = render_zone_entry(zone, runner);
    if fs::read(&target).is_ok_and(|existing| existing == text.as_bytes()) {
        return Ok(false);
    }
    write_atomically(&target, text.as_bytes()).map(|()| true)
}

/// Take a zone's entry for the portal away, if it is ours.
pub fn remove_zone_entry(home: &Path, zone: &str) {
    let target = home
        .join(".local/share/applications")
        .join(zone_entry_file(zone));
    if ours(&target) {
        let _ = fs::remove_file(target);
    }
}

/// The zones whose entries for the portal sync keeps: every zone directory,
/// the offline zone's included — its programs register as well.
fn portal_zones(state_dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(state_dir) else {
        return Vec::new();
    };
    let mut zones: Vec<String> = entries
        .flatten()
        .filter(|e| {
            let path = e.path();
            !e.file_name().as_encoded_bytes().starts_with(b".")
                && (path.join("config.conf").is_file() || path.join("offline").exists())
        })
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    zones.sort();
    zones
}

/// A key without spaces or quotes, so that `Exec` parses for anybody.
pub fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// `Name`, `Name[ru]`, `GenericName`, `Comment[de]` → the base key.
fn label_key(key: &str) -> Option<&'static str> {
    for base in LABEL_KEYS {
        let Some(rest) = key.strip_prefix(base) else {
            continue;
        };
        if rest.is_empty() {
            return Some(base);
        }
        // `[…]` with a non-empty locale and no nested bracket.
        if rest.len() > 2
            && rest.starts_with('[')
            && rest.ends_with(']')
            && !rest[1..rest.len() - 1].contains(']')
        {
            return Some(base);
        }
    }
    None
}

/// Drop `%U` and friends. Used for per-zone clones only: there the command
/// goes through `vpn-zone run`, which does not carry file arguments.
fn strip_field_codes(exec: &str) -> String {
    let mut out = String::with_capacity(exec.len());
    // A `%` is held back for one character: only `%` + a code is dropped, a
    // literal `%%` and a `%` before anything else stay as they are.
    let mut pending_percent = false;
    for c in exec.chars() {
        if pending_percent {
            pending_percent = false;
            if FIELD_CODES.contains(c) {
                continue;
            }
            out.push('%');
        }
        if c == '%' {
            pending_percent = true;
            continue;
        }
        out.push(c);
    }
    if pending_percent {
        out.push('%');
    }
    out
}

/// per-zone: "Firefox (nl)" — a separate entry per zone.
pub fn render_clone(entry: &Group, zone: &str, runner: &str) -> String {
    let exec_line = strip_field_codes(entry.get("Exec").unwrap_or(""))
        .trim()
        .to_string();
    let mut lines = vec![
        "[Desktop Entry]".to_string(),
        "Type=Application".to_string(),
    ];
    for (key, value) in entry.entries() {
        match label_key(key) {
            // Only the name gets the zone appended: a translated Comment with
            // "(nl)" glued to it reads like a mistake.
            Some("Name") => lines.push(format!("{key}={value} ({zone})")),
            Some(_) => lines.push(format!("{key}={value}")),
            None if CLONE_KEYS.contains(&key) => lines.push(format!("{key}={value}")),
            None => {}
        }
    }
    lines.push(format!("Exec={runner} run {zone} -- {exec_line}"));
    lines.push(format!("{MARK}={zone}"));
    lines.join("\n") + "\n"
}

/// picker: the same entry, with `Exec` leading into the network dialog.
///
/// `app_key` is the identifier of the entry (its file name without the
/// extension). It is handed to the picker as `--id` and is the memory key for
/// "which network and which container was chosen for this program". It used to
/// be derived from the first word of the command, and for entries shaped like
/// `Exec=env DESKTOPINTEGRATION=1 AyuGram` that produced "env" — so every such
/// program shared one memory slot, and the reset list showed a mysterious
/// "env".
///
/// **There must be NO QUOTES in `Exec`**, and that is not a matter of taste.
/// The program's display name ("Zen Browser") used to be passed here quoted,
/// by the letter of the desktop specification. But Telegram (and it is not
/// alone) splits `Exec` naively on spaces without removing quotes: the
/// argument fell apart into `Zen` and `Browser"`, the picker took the rubbish
/// for a command, and the launch died with «невозможно выполнить Browser"».
/// So the command line carries single words only, and the human-readable name
/// is taken by the picker from the label file written next to it.
/// (`docs/GOTCHAS.md` §10)
pub fn render_picker(groups: &[Group], picker: &str, app_key: &str) -> String {
    render_intercepted(groups, picker, app_key, "picker")
}

/// The same entry, taken over in place in the user's own directory: only the
/// marker differs, and it is what tells [`cleanup`] to RESTORE the original
/// rather than delete the file. (`docs/LAUNCHERS.md` §3.2)
pub fn render_adopted(groups: &[Group], picker: &str, app_key: &str) -> String {
    render_intercepted(groups, picker, app_key, ADOPTED)
}

/// An XDG autostart entry, taken over in place (`docs/CONTAINERS.md` §5): the
/// picker is started with [`AUTOSTART_FLAG`], so that a program nobody chose a
/// network for starts offline at login instead of asking a person who is not
/// looking yet — or starting uncontained, as it did.
///
/// Two differences from a launcher entry. `TryExec` is kept: it is how an
/// autostart entry of an uninstalled program stays silent, and without it the
/// picker would be started at every login for nothing. And a copy of one of
/// our own picker entries (desktop settings "add to autostart" copy the entry
/// the menu shows, which is ours) is unwrapped first — wrapped twice, the
/// inner picker would ask at login after all.
pub fn render_autostart(groups: &[Group], picker: &str, app_key: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for group in groups {
        if group.name != "Desktop Entry" {
            continue;
        }
        out.push(format!("[{}]", group.name));
        for (key, value) in group.entries() {
            // `Exec[ru]` is Exec too for whoever reads localised keys.
            let base = key.split('[').next().unwrap_or(key);
            if matches!(base, "Exec" | "DBusActivatable") || base == MARK {
                continue;
            }
            out.push(format!("{key}={value}"));
        }
        if let Some(exec) = group.get("Exec").filter(|e| !e.is_empty()) {
            let inner = unwrap_picker_exec(exec).map_or(exec, |(_, inner)| inner);
            out.push(format!(
                "Exec={picker} {AUTOSTART_FLAG} --id {} -- {inner}",
                stable_key(app_key)
            ));
        }
        out.push("DBusActivatable=false".to_string());
        out.push(format!("{MARK}={ADOPTED}"));
        out.push(String::new());
    }
    out.join("\n")
}

/// A shadow D-Bus service file: the same bus name, started through the picker.
///
/// A `DBusActivatable=true` program is started by the session bus whenever
/// somebody calls its name — `gapplication launch`, a notification's action,
/// another program — and the bus reads the service file, not the launcher
/// entry. Without a shadow the interception covered clicks only.
pub fn render_dbus_shadow(name: &str, picker: &str, app_key: &str, exec: &str) -> String {
    format!(
        "{DBUS_MARK}\n[D-BUS Service]\nName={name}\nExec={picker} --id {} -- {exec}\n",
        stable_key(app_key)
    )
}

/// The `Exec` of the service file that activates `name`, from the data
/// directories next to the launcher directories `sync` reads — never from our
/// own service directory.
fn dbus_service_exec(dirs: &[PathBuf], home: &Path, name: &str) -> Option<String> {
    let resolved = |p: &Path| fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let own = resolved(&home.join(DBUS_SERVICES));
    for dir in dirs {
        let Some(data) = dir.parent() else {
            continue;
        };
        let services = data.join("dbus-1/services");
        if resolved(&services) == own {
            continue;
        }
        let groups = parse_desktop_file(&services.join(format!("{name}.service")));
        let Some(group) = groups.iter().find(|g| g.name == "D-BUS Service") else {
            continue;
        };
        if group.get("Name") != Some(name) {
            continue;
        }
        if let Some(exec) = group.get("Exec").filter(|e| !e.is_empty()) {
            return Some(exec.to_owned());
        }
    }
    None
}

/// A well-formed D-Bus name a launcher entry may be activated under: the
/// specification requires `DBusActivatable` entries to be named by it.
fn is_bus_name(name: &str) -> bool {
    name.contains('.')
        && !name.starts_with('.')
        && !name.ends_with('.')
        && name
            .split('.')
            .all(|part| !part.is_empty() && !part.starts_with(|c: char| c.is_ascii_digit()))
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Remove our service files that are not wanted any more. Returns how many.
fn cleanup_dbus(dir: &Path, wanted: &BTreeSet<String>) -> u32 {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(String::from) else {
            continue;
        };
        if !name.ends_with(".service") || wanted.contains(&name) {
            continue;
        }
        if ours(&entry.path()) && fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// `vpn-zone-pick [--autostart] --id <key> -- <command>` → the key and the
/// command, for an `Exec` line one of our entries wrote. Anything else: `None`.
///
/// By the program's file name, not its path: a copy made months ago names a
/// store path of an older generation.
pub fn unwrap_picker_exec(exec: &str) -> Option<(Option<String>, &str)> {
    let (head, inner) = exec.split_once(" -- ")?;
    let mut words = head.split_whitespace();
    let program = words.next()?;
    if program.rsplit('/').next() != Some("vpn-zone-pick") {
        return None;
    }
    let mut id = None;
    while let Some(word) = words.next() {
        match word {
            "--id" => id = words.next().map(str::to_owned),
            AUTOSTART_FLAG => {}
            _ => return None,
        }
    }
    Some((id, inner))
}

fn render_intercepted(groups: &[Group], picker: &str, app_key: &str, marker: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for group in groups {
        if group.name != "Desktop Entry" && !group.name.starts_with("Desktop Action ") {
            continue;
        }
        out.push(format!("[{}]", group.name));
        for (key, value) in group.entries() {
            // `Exec[ru]` is Exec too for whoever reads localised keys.
            let base = key.split('[').next().unwrap_or(key);
            if PICKER_DROPPED_KEYS.contains(&base) || base == MARK {
                continue;
            }
            out.push(format!("{key}={value}"));
        }
        if let Some(exec) = group.get("Exec").filter(|e| !e.is_empty()) {
            // Field codes (%U, %f) are KEPT: the entry stays a file handler,
            // and the path reaches the program through the picker as an
            // ordinary argument.
            out.push(format!(
                "Exec={picker} --id {} -- {exec}",
                stable_key(app_key)
            ));
        }
        // Without this the launcher activates the program over D-Bus, around
        // `Exec` — and the whole interception would be pointless.
        out.push("DBusActivatable=false".to_string());
        if group.name == "Desktop Entry" {
            out.push(format!("{MARK}={marker}"));
        }
        out.push(String::new());
    }
    out.join("\n")
}

/// A user entry that starts nothing itself: no `[Desktop Entry]`, or no
/// `Exec` in it — a menu editor's "deleted" stub.
fn is_stub(path: &Path) -> bool {
    let Ok(bytes) = fs::read(path) else {
        return false;
    };
    let groups = parse_desktop(&String::from_utf8_lossy(&bytes));
    desktop_entry(&groups).is_none_or(|e| e.get("Exec").is_none_or(|x| x.trim().is_empty()))
}

/// The flags of a stub that decide what menus show: `Hidden`, `NoDisplay`.
fn stub_flags(text: &str) -> Vec<String> {
    let groups = parse_desktop(text);
    let Some(entry) = desktop_entry(&groups) else {
        return vec!["Hidden=true".to_owned()];
    };
    ["Hidden", "NoDisplay"]
        .iter()
        .filter_map(|k| entry.get(k).map(|v| format!("{k}={v}")))
        .collect()
}

/// A rendered entry with `flags` set in its `[Desktop Entry]`, replacing any
/// of the same keys.
fn with_flags(text: &str, flags: &[String]) -> String {
    let keys: Vec<&str> = flags.iter().filter_map(|f| f.split('=').next()).collect();
    let mut out: Vec<String> = Vec::new();
    let mut in_entry = false;
    for line in text.lines() {
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            out.push(line.to_owned());
            if in_entry {
                out.extend(flags.iter().cloned());
            }
            continue;
        }
        let key = line.split('=').next().unwrap_or("");
        if in_entry && keys.contains(&key) {
            continue;
        }
        out.push(line.to_owned());
    }
    let mut joined = out.join("\n");
    if text.ends_with('\n') {
        joined.push('\n');
    }
    joined
}

/// Is this file ours — may it be overwritten or deleted?
///
/// A symlink is never ours: home-manager and the user put those there.
pub fn ours(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_symlink() && meta.is_file() => {}
        _ => return false,
    }
    match fs::read(path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).contains(&format!("{MARK}=")),
        Err(_) => false,
    }
}

/// Whether CellWard takes the entry `id` over: the user's directory has our
/// entry in its place (the picker's, or the adopted one). A symlink there —
/// home-manager's, the user's — is left alone, and a program started from it
/// runs where it was asked for, as `xdg-open` would run it.
pub fn intercepted(home: &Path, id: &str) -> bool {
    ours(
        &home
            .join(".local/share/applications")
            .join(format!("{id}.desktop")),
    )
}

/// Is this an entry taken over in place — ours, with the `adopted` marker?
pub fn adopted(path: &Path) -> bool {
    ours(path)
        && fs::read(path)
            .is_ok_and(|b| String::from_utf8_lossy(&b).contains(&format!("{MARK}={ADOPTED}")))
}

/// A regular file, not a symlink: the only kind of foreign entry that may ever
/// be taken over. home-manager's and Nix's entries are symlinks into the store
/// and stay untouched whatever happens.
fn regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
}

/// Is there anything at this path at all — INCLUDING a broken symlink?
///
/// A plain "does it exist" follows symlinks and answers `false` for one
/// pointing nowhere. Without this distinction sync would write THROUGH such a
/// symlink, into somebody else's target — with home-manager that is the
/// read-only `/nix/store`, and the whole pass died on the write. Observed
/// exactly like that. (`docs/GOTCHAS.md` §10)
pub fn occupied(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// Write only when the content changed; returns 1 if it did.
///
/// The comparison is mandatory: a path unit watches this directory, so without
/// it the unit would wake sync, sync would rewrite the files, and the loop
/// would never end. (`docs/GOTCHAS.md` §10)
///
/// The comparison is over bytes, not text: a file that is not valid UTF-8 is
/// simply "different", it does not abort the pass.
pub fn write_if_changed(target: &Path, content: &str) -> u32 {
    if fs::read(target).is_ok_and(|existing| existing == content.as_bytes()) {
        return 0;
    }
    match write_atomically(target, content.as_bytes()) {
        Ok(()) => 1,
        Err(e) => {
            eprintln!(
                "skipping {}: {e}",
                target
                    .file_name()
                    .unwrap_or(target.as_os_str())
                    .to_string_lossy()
            );
            0
        }
    }
}

/// Write through a temporary in the same directory and rename it over the
/// target, so that nobody ever reads half a file.
///
/// Not a nicety for the entries taken over in place: a pass that read one of
/// them half-written would see a foreign file without the marker and keep THAT
/// as the original, over the real backup — and `mode off` would then "restore"
/// a fragment. Two passes do run at once: the path unit reacts to the very
/// write a manual `vpn-zone sync` makes. The temporary does not end in
/// `.desktop`, so no pass ever collects it.
pub fn write_atomically(target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let name = target.file_name().unwrap_or_default().to_string_lossy();
    let tmp = target.with_file_name(format!(".{name}.vpn-zone-tmp"));
    fs::write(&tmp, bytes)
        .and_then(|()| fs::rename(&tmp, target))
        .inspect_err(|_| {
            let _ = fs::remove_file(&tmp);
        })
}

/// The human-readable name next to the key: dialogs and reset lists show
/// "Zen Browser" while the command line carries the id only.
fn write_label(state_dir: &Path, key: &str, label: &str) {
    let dir = state_dir.join(".labels");
    if fs::create_dir_all(&dir).is_ok() {
        let _ = fs::write(dir.join(stable_key(key)), label);
    }
}

/// Where launcher entries are read from, in priority order and deduplicated.
///
/// The environment is read by the caller and passed in, so that a test can
/// describe a whole system of directories without touching the process
/// environment other threads are reading from.
pub fn source_dirs(home: &Path) -> Vec<PathBuf> {
    let user = std::env::var("USER").unwrap_or_default();
    let mut dirs = vec![
        home.join(".local/share/applications"),
        PathBuf::from(format!("/etc/profiles/per-user/{user}/share/applications")),
        PathBuf::from("/run/current-system/sw/share/applications"),
    ];
    if let Some(data_dirs) = std::env::var_os("XDG_DATA_DIRS") {
        for dir in std::env::split_paths(&data_dirs) {
            if !dir.as_os_str().is_empty() {
                dirs.push(dir.join("applications"));
            }
        }
    }
    let mut seen = BTreeSet::new();
    dirs.into_iter()
        .filter(|d| seen.insert(d.clone()) && d.is_dir())
        .collect()
}

/// One launcher entry found in the sources.
struct App {
    /// The desktop-file ID, e.g. `firefox.desktop`: the file name, or for an
    /// entry in a subdirectory its path with `-` for `/`
    /// (`wine/Programs/X.desktop` is `wine-Programs-X.desktop`) — what a menu
    /// knows it by and what an entry of a higher directory shadows.
    name: String,
    /// Where the file is below its directory: the name itself at the top,
    /// `wine/Programs/X.desktop` below it.
    rel: PathBuf,
    groups: Vec<Group>,
    /// Found in our own output directory. Such files are never intercepted:
    /// they are either ours or the user's.
    own_dir: bool,
    /// A [`is_hidden_handler`] entry rather than a visible one.
    hidden: bool,
}

/// Where the PATH shims go, below the home (`docs/CONTAINERS.md` §5).
pub const SHIM_DIR: &str = ".local/share/vpn-zones/bin";
/// The marker line of a shim.
const SHIM_MARK: &str = "# X-VPNZone=shim";

/// Whether PATH shims are wanted: the declared setting, then the local one,
/// off by default — a shim changes what a word typed in a terminal does, and
/// that is the person's call.
fn wants_shims(home: &Path) -> bool {
    let config = home.join(".config/vpn-zones");
    fs::read_to_string(config.join("declared/path-shims"))
        .or_else(|_| fs::read_to_string(config.join("path-shims")))
        .is_ok_and(|v| v.trim() == "on")
}

/// A shim: the program typed in a terminal goes through the picker like a
/// click on its entry. `real` is the program as found outside the shim
/// directory, so a shim never calls itself.
pub fn render_shim(picker: &str, key: &str, real: &Path) -> String {
    format!(
        "#!/bin/sh\n{SHIM_MARK}\n# Written by cellward sync; `pathShims.enable = false` removes it.\n\
         exec {picker} --id {} -- {} \"$@\"\n",
        stable_key(key),
        shell_quote(&real.to_string_lossy())
    )
}

fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// The first `name` on the search path that is not in the shim directory and
/// not a shim.
pub fn real_program(name: &str, search: &[PathBuf], shim_dir: &Path) -> Option<PathBuf> {
    let resolved = |p: &Path| fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let shims = resolved(shim_dir);
    search
        .iter()
        .filter(|dir| resolved(dir) != shims)
        .map(|dir| dir.join(name))
        .find(|path| {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                && !fs::read(path).is_ok_and(|b| String::from_utf8_lossy(&b).contains(SHIM_MARK))
        })
}

/// Our own commands, by every name they have (`cellward`, `cw`, the old
/// `vpn-zone` and the helpers): never shimmed — a shim of that name, first on
/// `PATH`, would stand in for the command itself.
pub fn is_ours(program: &str) -> bool {
    program.starts_with("vpn-zone") || program.starts_with("cellward") || program == "cw"
}

/// Write a shim for every program assigned to a container, remove the ones
/// no longer wanted. Returns (written, removed).
///
/// Only assigned programs: a shim for a program nobody chose anything for
/// would put a dialog in front of every use in a terminal. The shim name is the
/// program's name from its entry's `Exec`; the first entry wins a name.
fn sync_shims(
    home: &Path,
    state_dir: &Path,
    picker: &str,
    apps: &[App],
    parents: &BTreeMap<String, String>,
    search: Option<&[PathBuf]>,
) -> (u32, u32) {
    let dir = home.join(SHIM_DIR);
    let mut wanted: BTreeSet<String> = BTreeSet::new();
    let mut written = 0;
    if let Some(search) = search {
        let declared = home.join(".config/vpn-zones/declared/containers");
        let declared_apps: BTreeSet<String> = fs::read_dir(&declared)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|f| fs::read_to_string(f.path()).ok())
            .flat_map(|text| {
                text.lines()
                    .filter_map(|l| l.split_once('='))
                    .filter(|(k, _)| k.trim() == "app")
                    .map(|(_, v)| stable_key(v.trim()))
                    .collect::<Vec<_>>()
            })
            .collect();
        for app in apps
            .iter()
            .filter(|a| !a.hidden && !parents.contains_key(&a.name))
        {
            let key = stable_key(app.key());
            let assigned = state_dir.join(".pinnedprofile").join(&key).is_file()
                || declared_apps.contains(&key);
            if !assigned {
                continue;
            }
            let Some(program) = desktop_entry(&app.groups)
                .and_then(|e| e.get("Exec"))
                .and_then(exec_program)
            else {
                continue;
            };
            if program.contains('/') || is_ours(&program) || wanted.contains(&program) {
                continue;
            }
            let Some(real) = real_program(&program, search, &dir) else {
                continue;
            };
            if fs::create_dir_all(&dir).is_err() {
                break;
            }
            let target = dir.join(&program);
            // Somebody else's file of that name is left alone.
            if occupied(&target)
                && !fs::read(&target).is_ok_and(|b| String::from_utf8_lossy(&b).contains(SHIM_MARK))
            {
                continue;
            }
            written += write_if_changed(&target, &render_shim(picker, &key, &real));
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&target, fs::Permissions::from_mode(0o755));
            wanted.insert(program);
        }
    }
    let mut removed = 0;
    for entry in fs::read_dir(&dir).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if wanted.contains(&name) || name.starts_with('.') {
            continue;
        }
        let ours =
            fs::read(entry.path()).is_ok_and(|b| String::from_utf8_lossy(&b).contains(SHIM_MARK));
        if ours && fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    (written, removed)
}

/// Whether XDG autostart entries of the user are taken over: the declared
/// setting (`autostart.unassigned`), then the local one — `ask` by default
/// since 2026-09-24, `offline` before; both take over. `as-is` leaves them, and
/// gives back the ones taken over.
fn takes_over_autostart(home: &Path) -> bool {
    let config = home.join(".config/vpn-zones");
    let value = fs::read_to_string(config.join("declared/autostart"))
        .or_else(|_| fs::read_to_string(config.join("autostart")))
        .unwrap_or_default();
    value.trim() != "as-is"
}

/// Whether foreign entries in the user's directory are taken over: the
/// declared setting, then the local one, `take-over` by default
/// (`docs/LAUNCHERS.md` §3.2, the owner's decision of 2026-09-17).
fn takes_over_user_entries(home: &Path) -> bool {
    let config = home.join(".config/vpn-zones");
    let value = fs::read_to_string(config.join("declared/user-entries"))
        .or_else(|_| fs::read_to_string(config.join("user-entries")))
        .unwrap_or_default();
    value.trim() != "leave"
}

impl App {
    /// The memory key of the entry: its file name without the extension.
    fn key(&self) -> &str {
        self.name.strip_suffix(".desktop").unwrap_or(&self.name)
    }
}

/// Does this `Exec` open a web app of a Chromium-family browser
/// (`--app-id=<id>` for an installed one, `--app=<url>` for a site as a
/// window)? Such an entry is the browser: the running browser process takes
/// the request and opens the window in ITS network and profile, whatever a
/// pin of the web app's own said. (`docs/CONTAINERS.md` §5)
pub fn is_web_app_exec(exec: &str) -> bool {
    exec_words(exec)
        .iter()
        .any(|w| w.starts_with("--app-id=") || w.starts_with("--app="))
}

/// Whose id an entry is launched under, when it is not its own.
///
/// Two kinds of entries are not programs of their own and must not get a
/// memory, a registry key and — in per-zone mode — a row of clones:
///
/// * a **child**: its command hands a URL to a program that another visible
///   entry starts and whose scheme that entry claims — `Exec=steam
///   steam://rungameid/<id>` next to `steam.desktop` with
///   `x-scheme-handler/steam`. The running client decides where the game runs;
///   the game is its child and has its network. A clone per game per zone
///   promised a choice nobody could honour, and the conflict check did not see
///   the game and the client as one program. (`docs/GOTCHAS.md` §10)
/// * a **hidden handler** of a program that has a visible entry — see
///   [`is_hidden_handler`];
/// * a **web app** of a browser that has a visible entry — see
///   [`is_web_app_exec`].
///
/// With several visible entries for one program the one whose key IS the
/// program's name wins, then the first by name — stable across passes.
fn parents(apps: &[App]) -> BTreeMap<String, String> {
    let visible = || apps.iter().filter(|a| !a.hidden);
    let program_of = |app: &App| {
        desktop_entry(&app.groups)
            .and_then(|e| e.get("Exec"))
            .and_then(exec_program)
    };
    let web_app = |app: &App| {
        desktop_entry(&app.groups)
            .and_then(|e| e.get("Exec"))
            .is_some_and(is_web_app_exec)
    };
    let mut by_program: BTreeMap<String, &App> = BTreeMap::new();
    // A web app is never the entry of its browser, even when it is the only
    // entry of that program the scan has seen so far.
    for app in visible().filter(|a| !web_app(a)) {
        let Some(program) = program_of(app) else {
            continue;
        };
        let better = match by_program.get(&program) {
            None => true,
            Some(current) => current.key() != program && app.key() == program,
        };
        if better {
            by_program.insert(program, app);
        }
    }

    let mut out = BTreeMap::new();
    for app in apps {
        let Some(entry) = desktop_entry(&app.groups) else {
            continue;
        };
        let Some(program) = entry.get("Exec").and_then(exec_program) else {
            continue;
        };
        let parent = if app.hidden || web_app(app) {
            by_program
                .get(&program)
                .filter(|p| p.name != app.name)
                .map(|p| p.key().to_owned())
        } else {
            let schemes = exec_url_schemes(entry.get("Exec").unwrap_or(""));
            visible()
                .filter(|p| p.name != app.name)
                .filter(|p| program_of(p).as_deref() == Some(program.as_str()))
                .find(|p| {
                    desktop_entry(&p.groups)
                        .map(claimed_schemes)
                        .is_some_and(|claimed| schemes.iter().any(|s| claimed.contains(s)))
                })
                .map(|p| p.key().to_owned())
        };
        if let Some(parent) = parent {
            out.insert(app.name.clone(), parent);
        }
    }
    out
}

/// How deep below an applications directory entries are looked for: Wine's are
/// at `wine/Programs/<program>/<entry>.desktop`.
/// Wine nests them deeper when an installer makes folders of its own
/// (`wine/Programs/<vendor>/<product>/<entry>.desktop`), and menus look
/// without a limit — an entry below ours would start around the picker.
const ENTRY_DEPTH: usize = 16;

/// The `.desktop` files of an applications directory and of its subdirectories,
/// as `(path below it, desktop-file ID)`, sorted by ID — so that two runs over
/// the same directory produce the same result, which the "first one found wins"
/// rule depends on.
///
/// Subdirectories count (the XDG menu specification): Wine puts every program
/// it installs at `wine/Programs/…`, and an entry read only from the top would
/// start its program in the host's network, around the picker
/// (`docs/LEAK-MODEL.md` §11). Hidden directories and symlinked ones are not
/// entered — a link could lead anywhere, round in a circle included.
fn desktop_files(dir: &Path) -> Vec<(PathBuf, String)> {
    fn walk(dir: &Path, rel: &Path, depth: usize, out: &mut Vec<(PathBuf, String)>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(String::from) else {
                continue;
            };
            let here = rel.join(&name);
            let is_real_dir = entry.file_type().is_ok_and(|t| t.is_dir());
            if is_real_dir {
                if depth < ENTRY_DEPTH && !name.starts_with('.') {
                    walk(&entry.path(), &here, depth + 1, out);
                }
            } else if name.ends_with(".desktop") {
                let id = here
                    .iter()
                    .map(|part| part.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("-");
                out.push((here, id));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, Path::new(""), 1, &mut out);
    out.sort_by(|a, b| a.1.cmp(&b.1));
    out
}

fn collect_apps(dirs: &[PathBuf], out_dir: &Path, adopted_dir: &Path) -> Vec<App> {
    let resolved = |p: &Path| fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let out_resolved = resolved(out_dir);

    let mut apps: Vec<App> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for dir in dirs {
        let own_dir = resolved(dir) == out_resolved;
        for (rel, name) in desktop_files(dir) {
            if seen.contains(&name) {
                continue;
            }
            let path = dir.join(&rel);
            // An entry taken over in place is read from the original it
            // replaced, not from what we wrote: the original is the program's
            // entry, ours is only its interception.
            let source = if own_dir && adopted(&path) {
                let backup = adopted_dir.join(&name);
                if !backup.is_file() {
                    continue;
                }
                backup
            } else {
                path
            };
            let groups = parse_desktop_file(&source);
            if groups.is_empty() {
                continue;
            }
            let entry = desktop_entry(&groups);
            let hidden = if is_candidate(&name, entry) {
                false
            } else if is_hidden_handler(&name, entry) {
                true
            } else if own_dir && is_hidden_user_entry(&name, entry) {
                // In the user's own directory a hidden entry needs no MimeType
                // to matter: `mimeapps.list` names these files directly — the
                // `userapp-*` entries programs write when they make themselves
                // the default handler are exactly this.
                true
            } else {
                continue;
            };
            seen.insert(name.clone());
            apps.push(App {
                name,
                rel,
                groups,
                own_dir,
                hidden,
            });
        }
    }
    apps
}

/// Names of the zones that have a config — the ones a per-zone clone can be
/// made for. An offline zone has no config and is a picker option, not a zone.
fn zone_names(state_dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(state_dir) else {
        return Vec::new();
    };
    let mut zones: Vec<String> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_str().map(String::from)?;
            if name.starts_with('.') || !e.path().join("config.conf").is_file() {
                return None;
            }
            Some(name)
        })
        .collect();
    zones.sort();
    zones
}

/// Remove our own files that are not wanted any more: the mode changed, a zone
/// was deleted, a program disappeared. Foreign files are left alone —
/// [`ours`] checks both the marker and that it is not a symlink.
///
/// An entry taken over in place is never deleted: it was the user's (or a
/// program's) file. Its original bytes are written back and the backup goes;
/// without a backup the file is left as it is.
pub fn cleanup(out_dir: &Path, wanted: &BTreeSet<String>, adopted_dir: &Path) -> u32 {
    let mut removed = 0;
    // Subdirectories too: an entry of Wine's is taken over where it lies.
    for (rel, name) in desktop_files(out_dir) {
        if OWN_ENTRIES.contains(&name.as_str()) || wanted.contains(&name) {
            continue;
        }
        let path = out_dir.join(&rel);
        if adopted(&path) {
            let backup = adopted_dir.join(&name);
            if let Ok(original) = fs::read(&backup) {
                if write_atomically(&path, &original).is_ok() {
                    let _ = fs::remove_file(&backup);
                    removed += 1;
                }
            }
            continue;
        }
        if ours(&path) && fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// The key an autostart entry is launched under — the one its program's pins
/// and container assignment are kept under.
///
/// Autostart files are named by whoever wrote them, and often not like the
/// launcher entry (`telegramdesktop.desktop` next to
/// `org.telegram.desktop.desktop`): a key taken from the file name alone would
/// miss the pins and start a pinned program offline. So, in order: the id of a
/// copied picker entry; a launcher entry of the same file name; a launcher
/// entry of the same program (the one named like the program first); the file
/// name.
fn autostart_key(name: &str, exec: &str, apps: &[App]) -> String {
    if let Some((Some(id), _)) = unwrap_picker_exec(exec) {
        return stable_key(&id);
    }
    if let Some(app) = apps.iter().find(|a| a.name == name && !a.hidden) {
        return stable_key(app.key());
    }
    let inner = unwrap_picker_exec(exec).map_or(exec, |(_, inner)| inner);
    if let Some(program) = exec_program(inner) {
        let same = |a: &&App| {
            !a.hidden
                && desktop_entry(&a.groups)
                    .and_then(|e| e.get("Exec"))
                    .and_then(exec_program)
                    .as_deref()
                    == Some(program.as_str())
        };
        if let Some(app) = apps
            .iter()
            .filter(same)
            .find(|a| a.key() == program)
            .or_else(|| apps.iter().find(same))
        {
            return stable_key(app.key());
        }
    }
    stable_key(name.strip_suffix(".desktop").unwrap_or(name))
}

/// The picker's memory directories below the state directory, by key.
const MEMORY_DIRS: [&str; 5] = [
    ".pinned",
    ".pinnedprofile",
    ".last",
    ".lastprofile",
    ".labels",
];

/// Move what was remembered under the old, lossy keys to the stable ones
/// ([`stable_key`]), once, under the sync lock.
///
/// For every old key: if some entry still owns it losslessly (its id needed no
/// replacement), it stays that entry's and nothing moves. If exactly one entry
/// maps to it, its pins, last choices, label, file permissions and own sandbox
/// (`app-<key>`, and the selectors naming it) move to the new key — only where
/// the new key has nothing yet. If several entries shared it, nobody can tell
/// whose memory it was: it is dropped, and those programs are asked again —
/// the closed choice. Returns what it did, for the log.
fn migrate_keys(state_dir: &Path, home: &Path, apps: &[App]) -> Vec<String> {
    let mut by_old: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for app in apps {
        by_old
            .entry(sanitize(app.key()))
            .or_default()
            .insert(stable_key(app.key()));
    }
    let move_absent = |from: &Path, to: &Path| -> bool {
        occupied(from) && !occupied(to) && fs::rename(from, to).is_ok()
    };
    // The own container's data: in the one data directory, or where the
    // layout before one name per container kept a sandbox; its policy, in
    // either layout.
    let data_roots = [
        home.join(".local/state/vpn-profiles"),
        home.join(".local/state/vpn-sandboxes"),
    ];
    let policy_roots = [
        home.join(".config/vpn-zones/containers"),
        home.join(".config/vpn-zones/containers/sandboxes"),
    ];
    let perms = home.join(".config/vpn-zones/fs-perms");
    let mut log = Vec::new();
    for (old, news) in by_old {
        if news.contains(&old) {
            continue;
        }
        let memory = MEMORY_DIRS
            .iter()
            .any(|d| occupied(&state_dir.join(d).join(&old)));
        if news.len() > 1 {
            // A shared own sandbox is data and stays where it is; only the
            // choices go.
            if !memory {
                continue;
            }
            for dir in MEMORY_DIRS {
                let _ = fs::remove_file(state_dir.join(dir).join(&old));
            }
            log.push(format!(
                "key {old} was shared by {}: its memory is dropped, they will be asked again",
                news.iter().cloned().collect::<Vec<_>>().join(", ")
            ));
            continue;
        }
        let remembered = memory
            || occupied(&perms.join(&old))
            || data_roots
                .iter()
                .any(|root| occupied(&root.join(format!("app-{old}"))));
        let Some(new) = news.into_iter().next().filter(|_| remembered) else {
            continue;
        };
        for dir in MEMORY_DIRS {
            move_absent(
                &state_dir.join(dir).join(&old),
                &state_dir.join(dir).join(&new),
            );
        }
        move_absent(&perms.join(&old), &perms.join(&new));
        let mut moved = false;
        for root in data_roots.iter().chain(&policy_roots) {
            moved |= move_absent(
                &root.join(format!("app-{old}")),
                &root.join(format!("app-{new}")),
            );
        }
        if moved {
            // A pinned or last-chosen own container names it, in either
            // spelling.
            let to = format!("app-{new}");
            for dir in [".pinnedprofile", ".lastprofile"] {
                for file in fs::read_dir(state_dir.join(dir))
                    .into_iter()
                    .flatten()
                    .flatten()
                {
                    let named = fs::read_to_string(file.path()).is_ok_and(|v| {
                        let v = v.trim();
                        v == format!("sb:app-{old}") || v == format!("app-{old}")
                    });
                    if named {
                        let _ = fs::write(file.path(), &to);
                    }
                }
            }
        }
        log.push(format!("key {old} → {new}"));
    }
    log
}

/// Take over the user's XDG autostart entries in place, or give them back.
///
/// The same rules as for the user's launcher entries (`docs/LAUNCHERS.md`
/// §3.2): a symlink is never touched (home-manager's `xdg.autostart`); the
/// original bytes are kept aside BEFORE anything is written, and no backup
/// means no take-over; a program that rewrites its entry has its new bytes
/// taken as the original. Beyond them:
///
/// * an entry that starts nothing (`Hidden=true`, disabled, no `Exec`) is left
///   alone, and given back if it was taken;
/// * a per-zone clone copied here (its marker names a zone) is an explicit
///   choice of a network and stays as it is; a copied picker entry is taken
///   over like a foreign one;
/// * a backup whose entry is gone is dropped: the program switched its own
///   autostart off.
///
/// `/etc/xdg/autostart` is not touched at all: it is the desktop's own
/// components, and an entry of the user's own directory with the same name
/// would override — disable — them.
///
/// Returns (written, given back).
fn sync_autostart(
    dir: &Path,
    backups: &Path,
    state_dir: &Path,
    picker: &str,
    take: bool,
    apps: &[App],
) -> (u32, u32) {
    let Ok(entries) = fs::read_dir(dir) else {
        return (0, 0);
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(String::from))
        .filter(|n| n.ends_with(".desktop") && !n.starts_with('.'))
        .collect();
    names.sort();

    let (mut written, mut given_back) = (0, 0);
    let give_back = |path: &Path, name: &str| -> u32 {
        let backup = backups.join(name);
        match fs::read(&backup) {
            Ok(original) if write_atomically(path, &original).is_ok() => {
                let _ = fs::remove_file(&backup);
                1
            }
            _ => 0,
        }
    };
    for name in &names {
        let path = dir.join(name);
        if !regular_file(&path) {
            continue;
        }
        let taken = adopted(&path);
        if !take {
            if taken {
                given_back += give_back(&path, name);
            }
            continue;
        }
        let original = if taken {
            fs::read(backups.join(name))
        } else {
            fs::read(&path)
        };
        let Ok(original) = original else {
            continue;
        };
        let groups = parse_desktop(&String::from_utf8_lossy(&original));
        let Some(entry) = desktop_entry(&groups) else {
            continue;
        };
        let exec = entry.get("Exec").unwrap_or("");
        // What systemd's autostart generator — the one that starts these under
        // niri and sway — does not start: Hidden or X-systemd-skip, read the
        // way it reads booleans. Not X-GNOME-Autostart-enabled=false, which it
        // does not know: such an entry ran around the picker (review
        // 2026-09-25). It is taken over, the key kept for GNOME.
        let yes = |key: &str| {
            entry.get(key).is_some_and(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "true" | "yes" | "1" | "on"
                )
            })
        };
        let starts_nothing = exec.is_empty() || yes("Hidden") || yes("X-systemd-skip");
        if starts_nothing {
            if taken {
                given_back += give_back(&path, name);
            }
            continue;
        }
        // Somebody's copy of one of our entries: a picker entry is unwrapped
        // and taken over below; a clone names its network already.
        if !taken && entry.get(MARK).is_some_and(|m| m != "picker") {
            continue;
        }
        if !taken {
            let kept = fs::create_dir_all(backups).is_ok()
                && write_atomically(&backups.join(name), &original).is_ok();
            if !kept {
                continue;
            }
        }
        let key = autostart_key(name, exec, apps);
        if !state_dir.join(".labels").join(&key).exists() {
            write_label(state_dir, &key, entry.get("Name").unwrap_or(&key));
        }
        written += write_if_changed(&path, &render_autostart(&groups, picker, &key));
    }

    // Backups of entries that are gone.
    if let Ok(entries) = fs::read_dir(backups) {
        for backup in entries.flatten() {
            if !occupied(&dir.join(backup.file_name())) {
                let _ = fs::remove_file(backup.path());
            }
        }
    }
    (written, given_back)
}

/// The entry a launcher id names, as its program wrote it: `(file, groups)`.
///
/// Searched in the directories `sync` reads, in their order. In the user's own
/// directory an entry taken over in place is read from its backup, and one of
/// our picker entries is skipped — the original it shadows is further down the
/// list. (`docs/CONTAINERS.md` §5.1)
pub fn find_entry(
    dirs: &[PathBuf],
    home: &Path,
    state_dir: &Path,
    id: &str,
) -> Option<(PathBuf, Vec<Group>)> {
    let name = format!("{id}.desktop");
    let own = home.join(".local/share/applications");
    let resolved = |p: &Path| fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    for dir in dirs {
        let path = dir.join(&name);
        if !path.is_file() {
            continue;
        }
        let source = if resolved(dir) == resolved(&own) && adopted(&path) {
            state_dir.join(ADOPTED_DIR).join(&name)
        } else if ours(&path) {
            continue;
        } else {
            path
        };
        let groups = parse_desktop_file(&source);
        if desktop_entry(&groups).is_some() {
            return Some((source, groups));
        }
    }
    None
}

/// An entry's `Exec` as a command, its field codes filled from `args` the way a
/// launcher fills them (the desktop entry specification, "The Exec key").
///
/// `%u`/`%f` take the first argument, `%U`/`%F` all of them, `%i` becomes
/// `--icon <Icon>`, `%c` the name, `%k` the entry's file, `%%` a percent sign;
/// the deprecated codes vanish. Arguments with no field code to take them are
/// not appended: the program did not say it accepts any. Returns the words and
/// whether the arguments were used.
pub fn expand_exec(entry: &Group, file: &Path, args: &[OsString]) -> (Vec<OsString>, bool) {
    let exec = entry.get("Exec").unwrap_or("");
    let mut out: Vec<OsString> = Vec::new();
    let mut used = false;
    for word in exec_words(exec) {
        match word.as_str() {
            "%U" | "%F" => {
                out.extend(args.iter().cloned());
                used = true;
                continue;
            }
            "%u" | "%f" => {
                out.extend(args.first().cloned());
                used = true;
                continue;
            }
            "%i" => {
                if let Some(icon) = entry.get("Icon").filter(|i| !i.is_empty()) {
                    out.push("--icon".into());
                    out.push(icon.into());
                }
                continue;
            }
            _ => {}
        }
        // A code inside a word (`--url=%u`): filled in place, lossy for a
        // file name that is not UTF-8 — the same as every launcher does it.
        let mut filled = String::new();
        let mut coded = false;
        let mut chars = word.chars();
        while let Some(c) = chars.next() {
            if c != '%' {
                filled.push(c);
                continue;
            }
            coded = true;
            match chars.next() {
                Some('%') => filled.push('%'),
                Some('u' | 'f' | 'U' | 'F') => {
                    if let Some(first) = args.first() {
                        filled.push_str(&first.to_string_lossy());
                    }
                    used = true;
                }
                Some('c') => filled.push_str(entry.get("Name").unwrap_or("")),
                Some('k') => filled.push_str(&file.to_string_lossy()),
                Some(code) if FIELD_CODES.contains(code) => {}
                Some(other) => {
                    filled.push('%');
                    filled.push(other);
                }
                None => filled.push('%'),
            }
        }
        // A word that was nothing but a code with nothing to fill it with is
        // gone, not an empty argument.
        if !(coded && filled.is_empty()) {
            out.push(filled.into());
        }
    }
    (out, used)
}

/// The whole pass. Returns the process exit code.
pub fn sync(
    state_dir: &Path,
    home: &Path,
    runner: &str,
    picker: &str,
    systemctl: Option<&Path>,
) -> u8 {
    let (code, dbus_changed) = sync_from(state_dir, home, runner, picker, &source_dirs(home));
    // dbus-broker does not watch its service directories: a shadow nobody
    // told it about would not exist for it until the next login. dbus-daemon
    // does watch, and a reload costs it nothing. No-block: this pass may be
    // running inside a unit itself.
    if dbus_changed {
        if let Some(systemctl) = systemctl {
            let _ = std::process::Command::new(systemctl)
                .args(["--user", "--no-block", "reload", "dbus.service"])
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
    code
}

/// [`sync`] over an explicit list of source directories. Returns the exit code
/// and whether a D-Bus service file changed.
fn sync_from(
    state_dir: &Path,
    home: &Path,
    runner: &str,
    picker: &str,
    dirs: &[PathBuf],
) -> (u8, bool) {
    let out_dir = home.join(".local/share/applications");
    if let Err(e) = fs::create_dir_all(&out_dir) {
        eprintln!("cannot create {}: {e}", out_dir.display());
        return (1, false);
    }

    // One pass at a time, and the mode read under the lock: the path unit
    // starts a pass for every write into the applications directory, the
    // manual `vpn-zone sync` and `mode` start theirs, and two passes
    // interleaved can each take the other's rewrite for an original, or
    // rewrite an entry the other has just given back. Without the lock only
    // this pass's own atomicity is left, which is not enough for that.
    let _lock = match crate::registry::lock(&state_dir.join(SYNC_LOCK_DIR)) {
        Ok(lock) => Some(lock),
        Err(e) => {
            eprintln!("sync lock unavailable ({e}): running unlocked");
            None
        }
    };

    // The mode declared in Nix, when there is one, wins over the local file.
    let declared_mode = home.join(".config/vpn-zones/declared/mode");
    let mode_file = if declared_mode.exists() {
        declared_mode
    } else {
        home.join(".config/vpn-zones/mode")
    };
    let mode = match fs::read_to_string(mode_file) {
        Ok(text) => Mode::parse(&text),
        Err(_) => Mode::Picker,
    };
    let zones = zone_names(state_dir);
    let adopted_dir = state_dir.join(ADOPTED_DIR);
    let take_over = takes_over_user_entries(home);
    let apps = if mode == Mode::Off {
        Vec::new()
    } else {
        collect_apps(dirs, &out_dir, &adopted_dir)
    };
    for line in migrate_keys(state_dir, home, &apps) {
        println!("{line}");
    }

    let mut wanted: BTreeSet<String> = BTreeSet::new();
    let mut written = 0u32;
    let parents = parents(&apps);
    let dbus_dir = home.join(DBUS_SERVICES);
    let mut dbus_wanted: BTreeSet<String> = BTreeSet::new();
    let mut dbus_written = 0u32;
    // The shadow service of an intercepted, D-Bus-activatable entry.
    let mut shadow_dbus = |app: &App, entry: &Group, app_key: &str| {
        let name = app.key();
        if entry.get("DBusActivatable") != Some("true") || !is_bus_name(name) {
            return;
        }
        let Some(exec) = dbus_service_exec(dirs, home, name) else {
            return;
        };
        let file = format!("{name}.service");
        let target = dbus_dir.join(&file);
        // A service file of the user's own is theirs, as an entry would be.
        if occupied(&target) && !ours(&target) {
            return;
        }
        if fs::create_dir_all(&dbus_dir).is_err() {
            return;
        }
        dbus_wanted.insert(file);
        dbus_written +=
            write_if_changed(&target, &render_dbus_shadow(name, picker, app_key, &exec));
    };

    for app in &apps {
        let Some(entry) = desktop_entry(&app.groups) else {
            continue;
        };
        let parent = parents.get(&app.name);
        // A hidden handler with no visible entry of its program is a system
        // helper, not a program somebody launches: left alone entirely. The
        // user's own directory holds no system helpers — what is there, the
        // user or a program they installed put there.
        if app.hidden && parent.is_none() && !app.own_dir {
            continue;
        }

        // The picker intercepts an entry under its own name, so only entries
        // that came from the system directories may be touched. Files already
        // sitting in ~/.local/share/applications (ours, or home-manager's) are
        // left as they are.
        if mode.intercepts() && !app.own_dir {
            let target = out_dir.join(&app.name);
            // A stub of the user's under this name — a menu editor's "delete",
            // `Hidden=true` and little else — masks the system entry in menus
            // but not for xdg-open and GLib, which go past it to the system
            // entry, around the picker (review 2026-09-25). It is taken over
            // like a foreign entry: kept aside, and in its place the system
            // entry through the picker, with the stub's own flags.
            let stub = take_over && regular_file(&target) && !ours(&target) && is_stub(&target);
            let masked = stub || adopted(&target);
            let kept = !stub
                || (fs::create_dir_all(&adopted_dir).is_ok()
                    && fs::read(&target)
                        .and_then(|bytes| write_atomically(&adopted_dir.join(&app.name), &bytes))
                        .is_ok());
            if kept && (!occupied(&target) || ours(&target) || stub) {
                wanted.insert(app.name.clone());
                // A child or a hidden handler is launched under its parent's
                // id and leaves the parent's label alone.
                let app_key = match parent {
                    Some(parent) => parent.as_str(),
                    None => {
                        write_label(state_dir, app.key(), entry.get("Name").unwrap_or(app.key()));
                        app.key()
                    }
                };
                let text = if masked {
                    let flags = fs::read(adopted_dir.join(&app.name))
                        .map(|b| stub_flags(&String::from_utf8_lossy(&b)))
                        .unwrap_or_default();
                    with_flags(&render_adopted(&app.groups, picker, app_key), &flags)
                } else {
                    render_picker(&app.groups, picker, app_key)
                };
                written += write_if_changed(&target, &text);
                shadow_dbus(app, entry, app_key);
            }
        }

        // A foreign entry of the user's own directory: taken over IN PLACE,
        // with its original bytes kept aside (`docs/LAUNCHERS.md` §3.2). There
        // is no directory with a higher precedence to shadow it from, and these
        // are the entries `mimeapps.list` sends links to — a browser or a
        // messenger made the default handler writes one. A symlink is never
        // touched (home-manager, Nix); a regular file that is not ours yet is
        // either new, or ours rewritten by its program — either way its current
        // bytes are the original now.
        if mode.intercepts() && app.own_dir && take_over {
            // In place: in its subdirectory, where the menu finds it.
            let target = out_dir.join(&app.rel);
            if regular_file(&target) {
                let mut kept = true;
                if !ours(&target) {
                    kept = fs::create_dir_all(&adopted_dir).is_ok()
                        && fs::read(&target)
                            .and_then(|bytes| {
                                write_atomically(&adopted_dir.join(&app.name), &bytes)
                            })
                            .is_ok();
                }
                // No backup, no take-over: a file we could not restore is not
                // ours to rewrite.
                if kept {
                    wanted.insert(app.name.clone());
                    let app_key = match parent {
                        Some(parent) => parent.as_str(),
                        None => {
                            write_label(
                                state_dir,
                                app.key(),
                                entry.get("Name").unwrap_or(app.key()),
                            );
                            app.key()
                        }
                    };
                    written +=
                        write_if_changed(&target, &render_adopted(&app.groups, picker, app_key));
                    shadow_dbus(app, entry, app_key);
                }
            }
        }

        // Clones are for programs: not for a game of Steam's, and not for a
        // handler nobody sees in a menu.
        if mode.clones() && parent.is_none() && !app.hidden {
            for zone in &zones {
                let name = format!("{PREFIX}{zone}-{}", app.name);
                let target = out_dir.join(&name);
                if occupied(&target) && !ours(&target) {
                    continue;
                }
                wanted.insert(name);
                written += write_if_changed(&target, &render_clone(entry, zone, runner));
            }
        }
    }

    // Each zone's entry for the portal (`zone_app_id`): the zone's holder
    // writes it as the zone comes up; kept while the zone is there, in every
    // mode — it is no launcher entry — and taken with the zone.
    let mut kept = wanted.clone();
    kept.extend(portal_zones(state_dir).iter().map(|z| zone_entry_file(z)));
    let removed = cleanup(&out_dir, &kept, &adopted_dir);
    let dbus_removed = cleanup_dbus(&dbus_dir, &dbus_wanted);
    // Where a shim looks for the real program: the search path of this pass,
    // and the profiles, which a unit's PATH may not have.
    let shim_search: Option<Vec<PathBuf>> = (mode.intercepts() && wants_shims(home)).then(|| {
        let mut search: Vec<PathBuf> = std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default();
        let user = std::env::var("USER").unwrap_or_default();
        search.push(PathBuf::from(format!("/etc/profiles/per-user/{user}/bin")));
        search.push(home.join(".nix-profile/bin"));
        search.push(PathBuf::from("/run/current-system/sw/bin"));
        search
    });
    let (shims_written, shims_removed) = sync_shims(
        home,
        state_dir,
        picker,
        &apps,
        &parents,
        shim_search.as_deref(),
    );
    let (autostart_written, autostart_given_back) = sync_autostart(
        &home.join(".config/autostart"),
        &state_dir.join(AUTOSTART_ADOPTED_DIR),
        state_dir,
        picker,
        mode.intercepts() && takes_over_autostart(home),
        &apps,
    );
    if let Some(note) = mode.deprecation() {
        eprintln!("{note}");
    }
    let zone_list = if zones.is_empty() {
        "none".to_string()
    } else {
        zones.join(", ")
    };
    println!(
        "mode {}: {} entries ({written} updated, {removed} removed); autostart: \
         {autostart_written} updated, {autostart_given_back} given back; D-Bus services: {} \
         ({dbus_written} updated, {dbus_removed} removed); shims: {shims_written} updated, \
         {shims_removed} removed; zones: {zone_list}",
        mode.as_str(),
        wanted.len(),
        dbus_wanted.len()
    );
    (0, dbus_written + dbus_removed > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// A directory under the system temp dir, removed on drop. No dependency
    /// for this: the crate's dependencies are libc and libseccomp, and a test
    /// helper is not a reason to add a third.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "vpn-zone-desktop-test-{}-{tag}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }

        fn write(&self, name: &str, body: &str) -> PathBuf {
            let p = self.join(name);
            fs::write(&p, body).unwrap();
            p
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    const FIREFOX: &str = "\
[Desktop Entry]
# a comment
Type=Application
Name=Firefox
Name[ru]=Огненный лис
GenericName=Web Browser
Comment=Browse the web
Exec=firefox %U
Icon=firefox
Terminal=false
MimeType=text/html;x-scheme-handler/https;
Categories=Network;WebBrowser;
StartupWMClass=firefox
DBusActivatable=true
TryExec=firefox

[Desktop Action new-private-window]
Name=New Private Window
Exec=firefox --private-window %U

[X-Something-Else]
Name=not carried over
";

    fn groups() -> Vec<Group> {
        parse_desktop(FIREFOX)
    }

    #[test]
    fn the_parser_keeps_order_and_drops_noise() {
        let g = groups();
        assert_eq!(g.len(), 3);
        assert_eq!(g[0].name, "Desktop Entry");
        assert_eq!(g[1].name, "Desktop Action new-private-window");
        assert_eq!(g[0].get("Exec"), Some("firefox %U"));
        assert_eq!(g[0].get("Name[ru]"), Some("Огненный лис"));
        assert_eq!(g[0].get("nothing"), None);
        // Comments, blank lines and lines without `=` are gone; order is kept.
        let keys: Vec<&str> = g[0].entries().map(|(k, _)| k).collect();
        assert_eq!(keys[0], "Type");
        assert_eq!(keys[1], "Name");
        assert!(!keys.contains(&"# a comment"));
    }

    #[test]
    fn the_parser_handles_the_awkward_lines() {
        let g = parse_desktop(
            "Stray=key before any group\n\
             [Desktop Entry]\n\
             \n\
             ; an ini comment style we do not know, and no key either\n\
             Exec = env FOO=bar app --flag=1 \n\
             Name=First\n\
             Name=Second\n\
             []\n\
             Empty=group name\n",
        );
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].get("Stray"), None);
        // Values keep their inner `=`, and both sides are trimmed.
        assert_eq!(g[0].get("Exec"), Some("env FOO=bar app --flag=1"));
        // Last value wins, first position wins.
        assert_eq!(g[0].get("Name"), Some("Second"));
        assert_eq!(g[0].entries().filter(|(k, _)| *k == "Name").count(), 1);
        assert_eq!(g[1].name, "");
    }

    #[test]
    fn candidates_are_visible_applications_that_are_not_ours() {
        let g = groups();
        assert!(is_candidate("firefox.desktop", desktop_entry(&g)));
        // Our own files, by name and by marker.
        assert!(!is_candidate("vpn-zone-add.desktop", desktop_entry(&g)));
        for marker in ["X-VPNZone=picker", "X-VPNZone[ru]=picker"] {
            let marked = parse_desktop(&format!("[Desktop Entry]\nExec=x\n{marker}\n"));
            assert!(
                !is_candidate("x.desktop", desktop_entry(&marked)),
                "{marker} must not be taken as input"
            );
        }
        for skip in [
            "Type=Link\nExec=x",
            "NoDisplay=true\nExec=x",
            "NoDisplay=TRUE\nExec=x",
            "Hidden=true\nExec=x",
            "Name=no exec line",
        ] {
            let g = parse_desktop(&format!("[Desktop Entry]\n{skip}\n"));
            assert!(!is_candidate("x.desktop", desktop_entry(&g)), "{skip}");
        }
        assert!(!is_candidate("x.desktop", None));
    }

    #[test]
    fn the_picker_entry_carries_no_quotes_and_keeps_the_field_codes() {
        let out = render_picker(
            &groups(),
            "/home/u/.nix-profile/bin/vpn-zone-pick",
            "firefox",
        );

        assert!(
            !out.contains('"'),
            "quotes in Exec break naive parsers:\n{out}"
        );
        assert!(
            !out.contains('\''),
            "quotes in Exec break naive parsers:\n{out}"
        );
        assert!(out
            .contains("Exec=/home/u/.nix-profile/bin/vpn-zone-pick --id firefox -- firefox %U\n"));
        // The entry must stay a file handler.
        assert!(out.contains("MimeType=text/html;x-scheme-handler/https;"));
        // D-Bus activation would go around Exec.
        assert_eq!(out.matches("DBusActivatable=false").count(), 2);
        assert!(!out.contains("DBusActivatable=true"));
        assert!(!out.contains("TryExec="));
        // The marker belongs to the main group only, or the actions would look
        // like entries of their own.
        assert_eq!(out.matches("X-VPNZone=picker").count(), 1);
        assert!(out.starts_with("[Desktop Entry]\n"));
        // Actions are carried over, foreign groups are not.
        assert!(out.contains("[Desktop Action new-private-window]"));
        assert!(out.contains(
            "Exec=/home/u/.nix-profile/bin/vpn-zone-pick --id firefox -- firefox --private-window %U"
        ));
        assert!(!out.contains("X-Something-Else"));
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn the_picker_id_is_sanitised_not_quoted() {
        let g = parse_desktop("[Desktop Entry]\nType=Application\nExec=AyuGram\n");
        let out = render_picker(&g, "pick", "com.ayugram.desktop with space");
        let key = stable_key("com.ayugram.desktop with space");
        assert!(key.starts_with("com.ayugram.desktop_with_space-"), "{key}");
        assert!(
            out.contains(&format!("Exec=pick --id {key} -- AyuGram")),
            "{out}"
        );
        assert_eq!(sanitize("Zen Browser"), "Zen_Browser");
        assert_eq!(sanitize("Огненный"), "________");
        assert_eq!(sanitize("a-b_c.d"), "a-b_c.d");
    }

    #[test]
    fn a_clone_is_named_after_its_zone_and_claims_no_mime_types() {
        let g = groups();
        let out = render_clone(desktop_entry(&g).unwrap(), "nl", "/bin/vpn-zone");
        assert!(out.contains("Name=Firefox (nl)\n"));
        assert!(out.contains("Name[ru]=Огненный лис (nl)\n"));
        // Only the name gets the suffix.
        assert!(out.contains("GenericName=Web Browser\n"));
        assert!(out.contains("Comment=Browse the web\n"));
        // Associations must not be hijacked by a clone.
        assert!(!out.contains("MimeType"));
        // Field codes make no sense here: the file argument would be lost.
        assert!(out.contains("Exec=/bin/vpn-zone run nl -- firefox\n"));
        assert!(out.contains("X-VPNZone=nl\n"));
        assert!(!out.contains("TryExec"));
        assert!(!out.contains("DBusActivatable"));
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn field_codes_are_removed_one_by_one() {
        assert_eq!(strip_field_codes("app %U %f --x"), "app   --x");
        // A literal percent is not a field code.
        assert_eq!(strip_field_codes("app 50%% %i"), "app 50%% ");
        assert_eq!(strip_field_codes("app %Z"), "app %Z");
        // A `%` at the very end is kept, and `%%U` loses only the `%U`.
        assert_eq!(strip_field_codes("app %"), "app %");
        assert_eq!(strip_field_codes("%%U"), "%");
    }

    #[test]
    fn ours_and_occupied_tell_symlinks_apart() {
        let tmp = TempDir::new("ours");
        let mine = tmp.write("mine.desktop", "[Desktop Entry]\nX-VPNZone=picker\n");
        let theirs = tmp.write("theirs.desktop", "[Desktop Entry]\nExec=x\n");
        let link = tmp.join("link.desktop");
        symlink(&mine, &link).unwrap();
        let broken = tmp.join("broken.desktop");
        symlink(tmp.join("gone-for-good"), &broken).unwrap();

        assert!(ours(&mine));
        assert!(!ours(&theirs), "a file without the marker is not ours");
        assert!(!ours(&link), "a symlink is never ours, marker or not");
        assert!(!ours(&broken));
        assert!(!ours(&tmp.join("absent.desktop")));

        assert!(occupied(&mine));
        assert!(occupied(&link));
        // The whole point: a symlink pointing nowhere still occupies the path,
        // and writing to it would write into somebody else's target.
        assert!(occupied(&broken));
        assert!(!occupied(&tmp.join("absent.desktop")));
    }

    #[test]
    fn an_atomic_write_leaves_no_temporary_behind() {
        let tmp = TempDir::new("atomic");
        let target = tmp.join("userapp-x.desktop");
        fs::write(&target, "old\n").unwrap();
        write_atomically(&target, b"new\n").unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "new\n");
        let names: Vec<String> = fs::read_dir(&tmp.path)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["userapp-x.desktop"]);
        // A failed write removes its temporary and leaves the target alone.
        let missing = tmp.join("no-such-dir").join("y.desktop");
        assert!(write_atomically(&missing, b"x").is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "new\n");
    }

    #[test]
    fn write_if_changed_is_idempotent() {
        let tmp = TempDir::new("write");
        let target = tmp.join("x.desktop");
        assert_eq!(write_if_changed(&target, "one\n"), 1);
        assert_eq!(write_if_changed(&target, "one\n"), 0);
        assert_eq!(write_if_changed(&target, "two\n"), 1);
        assert_eq!(fs::read_to_string(&target).unwrap(), "two\n");
        // Not valid UTF-8 on disk: still just "different", never a failure.
        fs::write(&target, b"\xff\xfe").unwrap();
        assert_eq!(write_if_changed(&target, "two\n"), 1);
    }

    #[test]
    fn cleanup_removes_only_our_own_leftovers() {
        let tmp = TempDir::new("cleanup");
        let stale = tmp.write(
            "vpn-zone-nl-firefox.desktop",
            "[Desktop Entry]\nX-VPNZone=nl\n",
        );
        let kept = tmp.write(
            "vpn-zone-de-firefox.desktop",
            "[Desktop Entry]\nX-VPNZone=de\n",
        );
        let foreign = tmp.write("handmade.desktop", "[Desktop Entry]\nExec=x\n");
        let own_menu = tmp.write("vpn-zone-add.desktop", "[Desktop Entry]\nX-VPNZone=menu\n");
        let target = tmp.write("target.desktop", "[Desktop Entry]\nX-VPNZone=picker\n");
        let link = tmp.join("linked.desktop");
        symlink(&target, &link).unwrap();
        let not_desktop = tmp.write("notes.txt", "X-VPNZone=\n");

        let wanted: BTreeSet<String> = ["vpn-zone-de-firefox.desktop", "target.desktop"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(cleanup(&tmp.path, &wanted, &tmp.join("adopted")), 1);

        assert!(!stale.exists(), "our stale clone must go");
        assert!(kept.exists());
        assert!(foreign.exists(), "a file without the marker is not ours");
        assert!(own_menu.exists(), "our own menu entries are never swept");
        assert!(
            fs::symlink_metadata(&link).is_ok(),
            "a symlink is never ours, even if its target carries the marker"
        );
        assert!(target.exists());
        assert!(not_desktop.exists());
    }

    #[test]
    fn modes_are_read_leniently() {
        assert_eq!(Mode::parse("per-zone\n"), Mode::PerZone);
        assert_eq!(Mode::parse(" both "), Mode::Both);
        assert_eq!(Mode::parse("off"), Mode::Off);
        assert_eq!(Mode::parse("picker"), Mode::Picker);
        assert_eq!(Mode::parse("nonsense"), Mode::Picker);
        assert_eq!(Mode::parse(""), Mode::Picker);
        assert!(Mode::Both.intercepts() && Mode::Both.clones());
        assert!(Mode::Picker.intercepts() && !Mode::Picker.clones());
        assert!(!Mode::PerZone.intercepts() && Mode::PerZone.clones());
        assert!(!Mode::Off.intercepts() && !Mode::Off.clones());
        // The modes that make clones say they are deprecated; the others do not.
        assert!(Mode::PerZone.deprecation().is_some());
        assert!(Mode::Both.deprecation().is_some());
        assert!(Mode::Picker.deprecation().is_none());
        assert!(Mode::Off.deprecation().is_none());
    }

    #[test]
    fn exec_lines_are_split_the_way_the_specification_quotes_them() {
        assert_eq!(
            exec_words(r#"env "WINEPREFIX=/home/u/My Games" wine start %u"#),
            ["env", "WINEPREFIX=/home/u/My Games", "wine", "start", "%u"]
        );
        assert_eq!(exec_words(r#""/opt/a b/app" --x"#), ["/opt/a b/app", "--x"]);
        assert_eq!(
            exec_words(r#"sh -c "echo \"hi\"""#),
            ["sh", "-c", "echo \"hi\""]
        );
        assert_eq!(
            exec_words("  steam   steam://rungameid/1 "),
            ["steam", "steam://rungameid/1"]
        );
        assert_eq!(exec_words(r#"app """#), ["app", ""]);
        assert!(exec_words("").is_empty());
    }

    #[test]
    fn the_program_of_an_entry_is_named_past_its_wrappers() {
        assert_eq!(
            exec_program("steam steam://rungameid/1").as_deref(),
            Some("steam")
        );
        assert_eq!(
            exec_program(r#"env "WINEPREFIX=/w" /nix/store/x/bin/wine start %u"#).as_deref(),
            Some("wine")
        );
        assert_eq!(
            exec_program("/usr/bin/okular %U").as_deref(),
            Some("okular")
        );
        assert_eq!(exec_program(""), None);
    }

    #[test]
    fn urls_handed_over_and_schemes_claimed_are_read_apart() {
        assert_eq!(exec_url_schemes("steam steam://rungameid/1"), ["steam"]);
        assert_eq!(exec_url_schemes("app HTTPS://x %U"), ["https"]);
        // The program word is not an argument, field codes are not URLs, and
        // something that only looks like a scheme is not one.
        assert!(exec_url_schemes("x://odd %U").is_empty());
        assert!(exec_url_schemes("app 1abc://x --flag=a://b").is_empty());

        let g = parse_desktop(
            "[Desktop Entry]\nMimeType=text/html;x-scheme-handler/Steam;x-scheme-handler/steamlink;\n",
        );
        assert_eq!(
            claimed_schemes(desktop_entry(&g).unwrap()),
            ["steam", "steamlink"]
        );
    }

    #[test]
    fn a_hidden_handler_is_a_hidden_application_that_opens_something() {
        let entry = |body: &str| parse_desktop(&format!("[Desktop Entry]\n{body}\n"));
        let yes = entry("NoDisplay=true\nExec=okular %U\nMimeType=application/pdf;");
        assert!(is_hidden_handler(
            "okularApplication_pdf.desktop",
            desktop_entry(&yes)
        ));
        assert!(!is_candidate(
            "okularApplication_pdf.desktop",
            desktop_entry(&yes)
        ));
        for no in [
            // Visible: an ordinary candidate, not a hidden handler.
            "Exec=okular %U\nMimeType=application/pdf;",
            // Hidden but opens nothing.
            "NoDisplay=true\nExec=helper",
            "NoDisplay=true\nExec=helper\nMimeType=",
            // Deleted.
            "NoDisplay=true\nHidden=true\nExec=x\nMimeType=a/b;",
            // Ours.
            "NoDisplay=true\nExec=x\nMimeType=a/b;\nX-VPNZone=picker",
            "Type=Link\nNoDisplay=true\nExec=x\nMimeType=a/b;",
        ] {
            let g = entry(no);
            assert!(!is_hidden_handler("x.desktop", desktop_entry(&g)), "{no}");
        }
        assert!(!is_hidden_handler(
            "vpn-zone-x.desktop",
            desktop_entry(&yes)
        ));
    }

    #[test]
    fn children_and_hidden_handlers_go_under_the_program_they_belong_to() {
        let tmp = TempDir::new("parents");
        let home = tmp.join("home");
        let state = tmp.join("state");
        let apps = home.join(".local/share/applications");
        let system = tmp.join("system/applications");
        fs::create_dir_all(&apps).unwrap();
        fs::create_dir_all(&system).unwrap();
        fs::create_dir_all(state.join("nl")).unwrap();
        fs::write(state.join("nl/config.conf"), "[Interface]\n").unwrap();
        fs::create_dir_all(home.join(".config/vpn-zones")).unwrap();
        fs::write(home.join(".config/vpn-zones/mode"), "both").unwrap();

        let write = |dir: &Path, name: &str, body: &str| {
            fs::write(
                dir.join(name),
                format!("[Desktop Entry]\nType=Application\n{body}\n"),
            )
            .unwrap()
        };
        write(
            &system,
            "steam.desktop",
            "Name=Steam\nExec=steam %U\nMimeType=x-scheme-handler/steam;",
        );
        // A game in the system directory (interceptable) and one written by
        // the client into the user directory (foreign: never rewritten).
        write(
            &system,
            "PEAK.desktop",
            "Name=PEAK\nExec=steam steam://rungameid/1",
        );
        write(
            &apps,
            "Some Game.desktop",
            "Name=Some Game\nExec=steam steam://rungameid/2",
        );
        write(
            &system,
            "org.kde.okular.desktop",
            "Name=Okular\nExec=okular %U\nMimeType=application/pdf;",
        );
        write(
            &system,
            "okularApplication_pdf.desktop",
            "Name=Okular PDF\nNoDisplay=true\nExec=okular %U\nMimeType=application/pdf;",
        );
        // A hidden helper with no program of its own in the menu.
        write(
            &system,
            "oauth-helper.desktop",
            "Name=OAuth\nNoDisplay=true\nExec=goa-oauth2-handler %u\nMimeType=x-scheme-handler/goa;",
        );
        // A link that is NOT a child: nobody claims the scheme.
        write(
            &system,
            "site.desktop",
            "Name=Site\nExec=firefox https://example.org",
        );

        let dirs = vec![apps.clone(), system.clone()];
        assert_eq!(
            sync_from(&state, &home, "/bin/vpn-zone", "/bin/vpn-zone-pick", &dirs).0,
            0
        );
        let read = |name: &str| fs::read_to_string(apps.join(name)).unwrap_or_default();

        // The child is launched as Steam, and the client keeps its own label.
        assert!(read("PEAK.desktop").contains("--id steam -- steam steam://rungameid/1"));
        assert_eq!(
            fs::read_to_string(state.join(".labels/steam")).unwrap(),
            "Steam"
        );
        assert!(!state.join(".labels/PEAK").exists());
        // No clones for either game. The one the client wrote into the user
        // directory is taken over in place, under the client's id too.
        assert!(!apps.join("vpn-zone-nl-PEAK.desktop").exists());
        assert!(!apps.join("vpn-zone-nl-Some Game.desktop").exists());
        assert!(read("Some Game.desktop").contains("X-VPNZone=adopted"));
        assert!(read("Some Game.desktop").contains("--id steam -- steam steam://rungameid/2"));
        // The client itself is a program: intercepted and cloned as before.
        assert!(read("steam.desktop").contains("--id steam -- steam %U"));
        assert!(apps.join("vpn-zone-nl-steam.desktop").exists());

        // The hidden handler goes under Okular's id and stays hidden.
        let pdf = read("okularApplication_pdf.desktop");
        assert!(pdf.contains("--id org.kde.okular -- okular %U"), "{pdf}");
        assert!(pdf.contains("NoDisplay=true"), "{pdf}");
        assert!(pdf.contains("MimeType=application/pdf;"), "{pdf}");
        assert!(!apps
            .join("vpn-zone-nl-okularApplication_pdf.desktop")
            .exists());

        // A helper with no program behind it is left alone entirely.
        assert!(!apps.join("oauth-helper.desktop").exists());
        assert!(!apps.join("vpn-zone-nl-oauth-helper.desktop").exists());

        // An ordinary entry with a URL of an unclaimed scheme is its own program.
        assert!(read("site.desktop").contains("--id site --"));
        assert!(apps.join("vpn-zone-nl-site.desktop").exists());
    }

    /// A home, a state dir and a system dir for a full sync pass.
    struct Desk {
        _tmp: TempDir,
        home: PathBuf,
        state: PathBuf,
        apps: PathBuf,
        system: PathBuf,
    }

    impl Desk {
        fn new(tag: &str) -> Self {
            let tmp = TempDir::new(tag);
            let home = tmp.join("home");
            let state = tmp.join("state");
            let apps = home.join(".local/share/applications");
            let system = tmp.join("system/applications");
            fs::create_dir_all(&apps).unwrap();
            fs::create_dir_all(&system).unwrap();
            fs::create_dir_all(&state).unwrap();
            Self {
                _tmp: tmp,
                home,
                state,
                apps,
                system,
            }
        }

        fn sync(&self) {
            let dirs = vec![self.apps.clone(), self.system.clone()];
            assert_eq!(
                sync_from(&self.state, &self.home, "/bin/vpn-zone", "/bin/pick", &dirs).0,
                0
            );
        }

        fn setting(&self, name: &str, value: &str) {
            let dir = self.home.join(".config/vpn-zones");
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(name), value).unwrap();
        }

        fn read(&self, name: &str) -> String {
            fs::read_to_string(self.apps.join(name)).unwrap_or_default()
        }
    }

    #[test]
    fn a_foreign_user_entry_is_taken_over_in_place_and_given_back() {
        let d = Desk::new("adopt");
        let original = "[Desktop Entry]\nType=Application\nName=Handler\nExec=myapp --open %u\nMimeType=x-scheme-handler/my;\n";
        fs::write(d.apps.join("userapp-My.desktop"), original).unwrap();
        d.sync();
        let taken = d.read("userapp-My.desktop");
        assert!(taken.contains("X-VPNZone=adopted"), "{taken}");
        assert!(
            taken.contains("Exec=/bin/pick --id userapp-My -- myapp --open %u"),
            "{taken}"
        );
        assert!(taken.contains("MimeType=x-scheme-handler/my;"), "{taken}");
        assert_eq!(
            fs::read_to_string(d.state.join(ADOPTED_DIR).join("userapp-My.desktop")).unwrap(),
            original
        );
        // Idempotent: the second pass reads the original from the backup and
        // writes nothing.
        d.sync();
        assert_eq!(d.read("userapp-My.desktop"), taken);

        // The program writes its entry again: the new bytes are the original
        // now, and the entry is taken over again.
        let rewritten = original.replace("--open", "--open-new");
        fs::write(d.apps.join("userapp-My.desktop"), &rewritten).unwrap();
        d.sync();
        assert!(d
            .read("userapp-My.desktop")
            .contains("-- myapp --open-new %u"));
        assert_eq!(
            fs::read_to_string(d.state.join(ADOPTED_DIR).join("userapp-My.desktop")).unwrap(),
            rewritten
        );

        // "leave" gives it back byte for byte, and the backup goes.
        d.setting("user-entries", "leave");
        d.sync();
        assert_eq!(d.read("userapp-My.desktop"), rewritten);
        assert!(!d
            .state
            .join(ADOPTED_DIR)
            .join("userapp-My.desktop")
            .exists());
    }

    /// Wine puts every program it installs below the user's directory, at
    /// `wine/Programs/<program>/`: read only from the top, such an entry ran
    /// its program in the host's network, with no picker (owner, 2026-09-24;
    /// `docs/LEAK-MODEL.md` §11). Taken over where it lies, under its
    /// desktop-file ID, and given back there.
    #[test]
    fn an_entry_in_a_subdirectory_is_taken_over_where_it_lies() {
        let d = Desk::new("adopt-nested");
        let dir = d.apps.join("wine/Programs/Game");
        fs::create_dir_all(&dir).unwrap();
        let original = "[Desktop Entry]\nName=Game\nExec=env \"WINEPREFIX=/home/u/.wine\" wine \"C:\\\\Game.lnk\"\nType=Application\nPath=/home/u/.wine/drive_c/Game/\n";
        fs::write(dir.join("Game.desktop"), original).unwrap();
        d.sync();
        let taken = d.read("wine/Programs/Game/Game.desktop");
        assert!(taken.contains("X-VPNZone=adopted"), "{taken}");
        assert!(
            taken.contains("Exec=/bin/pick --id wine-Programs-Game-Game -- env \"WINEPREFIX=/home/u/.wine\" wine \"C:\\\\Game.lnk\""),
            "{taken}"
        );
        assert!(
            taken.contains("Path=/home/u/.wine/drive_c/Game/"),
            "{taken}"
        );
        // Not a second copy at the top: the menu would show the program twice.
        assert!(!d.apps.join("wine-Programs-Game-Game.desktop").exists());
        assert_eq!(
            fs::read_to_string(
                d.state
                    .join(ADOPTED_DIR)
                    .join("wine-Programs-Game-Game.desktop")
            )
            .unwrap(),
            original
        );
        d.sync();
        assert_eq!(d.read("wine/Programs/Game/Game.desktop"), taken);
        d.setting("mode", "off");
        d.sync();
        assert_eq!(d.read("wine/Programs/Game/Game.desktop"), original);
    }

    /// A system entry in a subdirectory is shadowed by its desktop-file ID from
    /// the top of the user's directory — the one place with a higher precedence.
    #[test]
    fn a_system_entry_in_a_subdirectory_is_shadowed_by_its_id() {
        let d = Desk::new("nested-system");
        fs::create_dir_all(d.system.join("kde")).unwrap();
        fs::write(
            d.system.join("kde/viewer.desktop"),
            "[Desktop Entry]\nType=Application\nName=Viewer\nExec=viewer %f\n",
        )
        .unwrap();
        // A symlinked directory is not entered: it could lead anywhere.
        symlink(d.system.join("kde"), d.system.join("loop")).unwrap();
        d.sync();
        let out = d.read("kde-viewer.desktop");
        assert!(
            out.contains("Exec=/bin/pick --id kde-viewer -- viewer %f"),
            "{out}"
        );
        assert!(!d.apps.join("loop-viewer.desktop").exists());
    }

    #[test]
    fn mode_off_gives_every_taken_over_entry_back() {
        let d = Desk::new("adopt-off");
        let original = "[Desktop Entry]\nType=Application\nName=X\nExec=x\n";
        fs::write(d.apps.join("x.desktop"), original).unwrap();
        d.sync();
        assert!(d.read("x.desktop").contains("X-VPNZone=adopted"));
        d.setting("mode", "off");
        d.sync();
        assert_eq!(d.read("x.desktop"), original);
    }

    #[test]
    fn a_symlinked_user_entry_is_never_taken_over() {
        // home-manager and Nix put their entries there as symlinks.
        let d = Desk::new("adopt-symlink");
        let target = d.system.join("../hm-entry.desktop");
        fs::write(
            &target,
            "[Desktop Entry]\nType=Application\nName=H\nExec=h\n",
        )
        .unwrap();
        symlink(&target, d.apps.join("hm.desktop")).unwrap();
        d.sync();
        assert!(fs::symlink_metadata(d.apps.join("hm.desktop"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!d.state.join(ADOPTED_DIR).join("hm.desktop").exists());
    }

    #[test]
    fn a_hidden_default_handler_goes_under_its_program() {
        // What a browser made the default writes: hidden, no MimeType, named
        // by mimeapps.list directly.
        let d = Desk::new("adopt-userapp");
        fs::write(
            d.system.join("zen.desktop"),
            "[Desktop Entry]\nType=Application\nName=Zen\nExec=zen --name zen %U\n",
        )
        .unwrap();
        fs::write(
            d.apps.join("userapp-Zen-ABC.desktop"),
            "[Desktop Entry]\nType=Application\nName=Zen\nNoDisplay=true\nExec=/etc/profiles/per-user/u/bin/zen %u\n",
        )
        .unwrap();
        d.setting("mode", "both");
        d.sync();
        let taken = d.read("userapp-Zen-ABC.desktop");
        assert!(
            taken.contains("--id zen -- /etc/profiles/per-user/u/bin/zen %u"),
            "{taken}"
        );
        assert!(taken.contains("NoDisplay=true"), "{taken}");
        // A hidden entry gets no clones.
        assert!(!d.apps.join("vpn-zone-nl-userapp-Zen-ABC.desktop").exists());
    }

    /// A "deleted" entry (Hidden=true) that mimeapps.list names is taken
    /// over too; a localised Exec is dropped like Exec itself; entries deep in
    /// Wine's folders are found.
    /// A menu editor's "deleted" stub under a system entry's name hides it
    /// from menus, not from xdg-open: taken over with its flags, given back
    /// as it was.
    #[test]
    fn a_stub_masking_a_system_entry_is_taken_over_and_given_back() {
        let d = Desk::new("stub");
        fs::write(
            d.system.join("zen.desktop"),
            "[Desktop Entry]\nType=Application\nName=Zen\nExec=zen %U\n",
        )
        .unwrap();
        let stub = "[Desktop Entry]\nHidden=true\n";
        fs::write(d.apps.join("zen.desktop"), stub).unwrap();
        d.setting("mode", "picker");
        d.sync();
        let taken = d.read("zen.desktop");
        assert!(taken.contains("--id zen -- zen %U"), "{taken}");
        assert!(taken.contains("Hidden=true"), "{taken}");
        assert!(taken.contains("X-VPNZone=adopted"), "{taken}");
        // A second pass keeps it so.
        d.sync();
        assert_eq!(d.read("zen.desktop"), taken);
        // Interception off: the stub comes back byte for byte.
        d.setting("mode", "off");
        d.sync();
        assert_eq!(d.read("zen.desktop"), stub);
    }

    #[test]
    fn deleted_entries_localised_commands_and_deep_folders_are_covered() {
        let d = Desk::new("hidden-localised");
        fs::write(
            d.system.join("zen.desktop"),
            "[Desktop Entry]\nType=Application\nName=Zen\nExec=zen %U\n",
        )
        .unwrap();
        fs::write(
            d.apps.join("userapp-Zen-DEL.desktop"),
            "[Desktop Entry]\nType=Application\nName=Zen\nHidden=true\nExec=/bin/zen %u\nExec[ru]=/bin/zen %u\n",
        )
        .unwrap();
        let deep = d.apps.join("wine/Programs/Vendor/Product");
        fs::create_dir_all(&deep).unwrap();
        fs::write(
            deep.join("Game.desktop"),
            "[Desktop Entry]\nType=Application\nName=Game\nExec=env WINEPREFIX=/w wine game.exe\n",
        )
        .unwrap();
        d.setting("mode", "picker");
        d.sync();
        let taken = d.read("userapp-Zen-DEL.desktop");
        assert!(taken.contains("-- /bin/zen %u"), "{taken}");
        assert!(!taken.contains("Exec[ru]"), "{taken}");
        let game = d.read("wine/Programs/Vendor/Product/Game.desktop");
        assert!(game.contains("--id "), "{game}");
    }

    #[test]
    fn a_full_pass_writes_a_picker_entry_and_sweeps_the_old_one() {
        let tmp = TempDir::new("sync");
        let home = tmp.join("home");
        let state = tmp.join("state");
        let apps = home.join(".local/share/applications");
        let system = tmp.join("system/applications");
        fs::create_dir_all(&apps).unwrap();
        fs::create_dir_all(&system).unwrap();
        fs::create_dir_all(state.join("nl")).unwrap();
        fs::write(state.join("nl/config.conf"), "[Interface]\n").unwrap();
        fs::write(system.join("firefox.desktop"), FIREFOX).unwrap();
        // A leftover of a zone that no longer exists.
        fs::write(
            apps.join("vpn-zone-gone-firefox.desktop"),
            "[Desktop Entry]\nX-VPNZone=gone\n",
        )
        .unwrap();

        // The source list is passed in rather than taken from XDG_DATA_DIRS:
        // tests share one process, and rewriting the environment under the
        // other threads is not worth a fixture.
        let dirs = vec![apps.clone(), system.clone()];
        let run = || sync_from(&state, &home, "/bin/vpn-zone", "/bin/vpn-zone-pick", &dirs).0;
        assert_eq!(run(), 0);

        let written = fs::read_to_string(apps.join("firefox.desktop")).unwrap();
        assert!(written.contains("--id firefox --"));
        assert!(written.contains("X-VPNZone=picker"));
        assert!(!apps.join("vpn-zone-gone-firefox.desktop").exists());
        // The label file is what the dialogs show instead of the id.
        assert_eq!(
            fs::read_to_string(state.join(".labels/firefox")).unwrap(),
            "Firefox"
        );

        // Second pass changes nothing, and the entry we wrote ourselves is not
        // taken as input on the way (it now sits in the output directory).
        assert_eq!(run(), 0);
        assert_eq!(
            fs::read_to_string(apps.join("firefox.desktop")).unwrap(),
            written
        );
    }

    // --- AUTOSTART ---------------------------------------------------------

    impl Desk {
        fn autostart(&self, name: &str, text: &str) -> PathBuf {
            let dir = self.home.join(".config/autostart");
            fs::create_dir_all(&dir).unwrap();
            let path = dir.join(name);
            fs::write(&path, text).unwrap();
            path
        }
    }

    #[test]
    fn an_autostart_entry_goes_through_the_picker_and_comes_back() {
        let d = Desk::new("autostart");
        // The launcher entry and the autostart entry are named differently, as
        // Telegram names them: the autostart one must still get the pins of
        // the program.
        fs::write(
            d.system.join("org.telegram.desktop.desktop"),
            "[Desktop Entry]\nType=Application\nName=Telegram\nExec=telegram-desktop -- %u\n",
        )
        .unwrap();
        let original = "[Desktop Entry]\nType=Application\nName=Telegram\n\
                        TryExec=/nix/store/x-telegram/bin/telegram-desktop\n\
                        Exec=/nix/store/x-telegram/bin/telegram-desktop -workdir /tmp/t -autostart\n\
                        X-GNOME-Autostart-enabled=true\n";
        let path = d.autostart("telegramdesktop.desktop", original);
        d.sync();
        let taken = fs::read_to_string(&path).unwrap();
        assert!(
            taken.contains(
                "Exec=/bin/pick --autostart --id org.telegram.desktop -- \
                 /nix/store/x-telegram/bin/telegram-desktop -workdir /tmp/t -autostart"
            ),
            "{taken}"
        );
        assert!(taken.contains("TryExec=/nix/store/x-telegram"), "{taken}");
        assert!(taken.contains("X-VPNZone=adopted"), "{taken}");
        assert!(taken.contains("DBusActivatable=false"), "{taken}");
        assert_eq!(
            fs::read_to_string(
                d.state
                    .join(AUTOSTART_ADOPTED_DIR)
                    .join("telegramdesktop.desktop")
            )
            .unwrap(),
            original
        );

        // Idempotent, and a rewrite by the program is taken over again.
        d.sync();
        assert_eq!(fs::read_to_string(&path).unwrap(), taken);
        let rewritten = original.replace("-autostart", "-startintray");
        fs::write(&path, &rewritten).unwrap();
        d.sync();
        assert!(fs::read_to_string(&path).unwrap().contains("-startintray"));
        assert_eq!(
            fs::read_to_string(
                d.state
                    .join(AUTOSTART_ADOPTED_DIR)
                    .join("telegramdesktop.desktop")
            )
            .unwrap(),
            rewritten
        );

        // `as-is` gives it back byte for byte, and so does `mode off`.
        d.setting("autostart", "as-is");
        d.sync();
        assert_eq!(fs::read_to_string(&path).unwrap(), rewritten);
        assert!(!d
            .state
            .join(AUTOSTART_ADOPTED_DIR)
            .join("telegramdesktop.desktop")
            .exists());
        d.setting("autostart", "offline");
        d.sync();
        assert!(fs::read_to_string(&path).unwrap().contains("--autostart"));
        d.setting("mode", "off");
        d.sync();
        assert_eq!(fs::read_to_string(&path).unwrap(), rewritten);
    }

    #[test]
    fn autostart_leaves_what_starts_nothing_symlinks_and_clones() {
        let d = Desk::new("autostart-leave");
        let hidden = "[Desktop Entry]\nType=Application\nName=Off\nExec=off\nHidden=true\n";
        let disabled =
            "[Desktop Entry]\nType=Application\nName=Off2\nExec=off2\nX-GNOME-Autostart-enabled=false\n";
        let clone = "[Desktop Entry]\nType=Application\nName=In nl\nExec=/bin/vpn-zone run nl -- x\nX-VPNZone=nl\n";
        let hidden_path = d.autostart("off.desktop", hidden);
        let disabled_path = d.autostart("off2.desktop", disabled);
        let clone_path = d.autostart("vpn-zone-nl-x.desktop", clone);
        let target = d.home.join("hm-target.desktop");
        fs::write(
            &target,
            "[Desktop Entry]\nType=Application\nName=HM\nExec=hm\n",
        )
        .unwrap();
        let link = d.home.join(".config/autostart/hm.desktop");
        symlink(&target, &link).unwrap();
        d.sync();
        assert_eq!(fs::read_to_string(&hidden_path).unwrap(), hidden);
        // X-GNOME-Autostart-enabled=false is started by systemd's generator
        // anyway: taken over, the key kept.
        let taken = fs::read_to_string(&disabled_path).unwrap();
        assert!(taken.contains("-- off2"), "{taken}");
        assert!(taken.contains("X-GNOME-Autostart-enabled=false"), "{taken}");
        assert_eq!(fs::read_to_string(&clone_path).unwrap(), clone);
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!fs::read_to_string(&target).unwrap().contains("X-VPNZone"));
    }

    #[test]
    fn a_copied_picker_entry_is_unwrapped_not_wrapped_twice() {
        let d = Desk::new("autostart-copy");
        // "Add to autostart" in desktop settings copies the menu entry — ours.
        let copy = "[Desktop Entry]\nType=Application\nName=Firefox\n\
                    Exec=/old/generation/bin/vpn-zone-pick --id firefox -- firefox %u\n\
                    DBusActivatable=false\nX-VPNZone=picker\n";
        let path = d.autostart("firefox.desktop", copy);
        d.sync();
        let taken = fs::read_to_string(&path).unwrap();
        assert!(
            taken.contains("Exec=/bin/pick --autostart --id firefox -- firefox %u"),
            "{taken}"
        );
        assert_eq!(taken.matches("vpn-zone-pick").count(), 0, "{taken}");
        assert_eq!(taken.matches("X-VPNZone=").count(), 1, "{taken}");
        // Given back as the copy it was.
        d.setting("autostart", "as-is");
        d.sync();
        assert_eq!(fs::read_to_string(&path).unwrap(), copy);
    }

    #[test]
    fn a_backup_goes_when_the_program_switches_its_autostart_off() {
        let d = Desk::new("autostart-gone");
        let path = d.autostart(
            "x.desktop",
            "[Desktop Entry]\nType=Application\nName=X\nExec=x\n",
        );
        d.sync();
        assert!(d
            .state
            .join(AUTOSTART_ADOPTED_DIR)
            .join("x.desktop")
            .exists());
        fs::remove_file(&path).unwrap();
        d.sync();
        assert!(!d
            .state
            .join(AUTOSTART_ADOPTED_DIR)
            .join("x.desktop")
            .exists());
    }

    #[test]
    fn picker_exec_lines_are_recognised_by_the_program_name() {
        assert_eq!(
            unwrap_picker_exec("/a/b/vpn-zone-pick --id tg -- telegram %u"),
            Some((Some("tg".to_owned()), "telegram %u"))
        );
        assert_eq!(
            unwrap_picker_exec("vpn-zone-pick --autostart --id tg -- telegram"),
            Some((Some("tg".to_owned()), "telegram"))
        );
        assert_eq!(unwrap_picker_exec("telegram -- x"), None);
        assert_eq!(unwrap_picker_exec("/bin/vpn-zone run nl -- x"), None);
        assert_eq!(unwrap_picker_exec("vpn-zone-pick --weird -- x"), None);
    }

    // --- vpn-zone launch -----------------------------------------------------

    #[test]
    fn field_codes_are_filled_like_a_launcher_fills_them() {
        let groups = parse_desktop(
            "[Desktop Entry]\nName=Fox\nIcon=fox\nExec=fox --name \"Fox Box\" %i --url=%u %U %% %d\n",
        );
        let entry = desktop_entry(&groups).unwrap();
        let args: Vec<OsString> = vec!["https://a".into(), "https://b".into()];
        let (words, used) = expand_exec(entry, Path::new("/x/fox.desktop"), &args);
        assert!(used);
        assert_eq!(
            words,
            [
                "fox",
                "--name",
                "Fox Box",
                "--icon",
                "fox",
                "--url=https://a",
                "https://a",
                "https://b",
                "%",
            ]
            .map(OsString::from)
        );
        let (words, used) = expand_exec(entry, Path::new("/x/fox.desktop"), &[]);
        assert!(used);
        assert_eq!(
            words,
            ["fox", "--name", "Fox Box", "--icon", "fox", "--url=", "%"].map(OsString::from)
        );
    }

    #[test]
    fn a_launch_finds_the_original_not_our_shadow() {
        let d = Desk::new("find");
        fs::write(
            d.system.join("fox.desktop"),
            "[Desktop Entry]\nType=Application\nName=Fox\nExec=fox %u\n",
        )
        .unwrap();
        d.sync();
        assert!(d.read("fox.desktop").contains("X-VPNZone=picker"));
        let dirs = vec![d.apps.clone(), d.system.clone()];
        let (file, groups) = find_entry(&dirs, &d.home, &d.state, "fox").unwrap();
        assert_eq!(file, d.system.join("fox.desktop"));
        assert_eq!(desktop_entry(&groups).unwrap().get("Exec"), Some("fox %u"));

        // Taken over in place: read from the backup.
        fs::write(
            d.apps.join("userapp-Fox.desktop"),
            "[Desktop Entry]\nType=Application\nName=Fox link\nNoDisplay=true\nExec=fox --open %u\n",
        )
        .unwrap();
        d.sync();
        let (file, groups) = find_entry(&dirs, &d.home, &d.state, "userapp-Fox").unwrap();
        assert_eq!(file, d.state.join(ADOPTED_DIR).join("userapp-Fox.desktop"));
        assert_eq!(
            desktop_entry(&groups).unwrap().get("Exec"),
            Some("fox --open %u")
        );

        assert!(find_entry(&dirs, &d.home, &d.state, "nope").is_none());
    }

    // --- D-Bus activation ----------------------------------------------------

    #[test]
    fn a_dbus_activatable_entry_gets_a_shadow_service_and_loses_it() {
        let d = Desk::new("dbus");
        fs::write(
            d.system.join("org.example.Notes.desktop"),
            "[Desktop Entry]\nType=Application\nName=Notes\nExec=notes %U\nDBusActivatable=true\n",
        )
        .unwrap();
        // Not activatable: no shadow, even with a service file next to it.
        fs::write(
            d.system.join("org.example.Plain.desktop"),
            "[Desktop Entry]\nType=Application\nName=Plain\nExec=plain\n",
        )
        .unwrap();
        let services = d.system.parent().unwrap().join("dbus-1/services");
        fs::create_dir_all(&services).unwrap();
        fs::write(
            services.join("org.example.Notes.service"),
            "[D-BUS Service]\nName=org.example.Notes\nExec=/store/notes --gapplication-service\nSystemdService=app-notes.service\n",
        )
        .unwrap();
        fs::write(
            services.join("org.example.Plain.service"),
            "[D-BUS Service]\nName=org.example.Plain\nExec=/store/plain\n",
        )
        .unwrap();
        let dirs = vec![d.apps.clone(), d.system.clone()];
        let (_, changed) = sync_from(&d.state, &d.home, "/bin/vpn-zone", "/bin/pick", &dirs);
        assert!(changed);
        let shadow = d.home.join(DBUS_SERVICES).join("org.example.Notes.service");
        let text = fs::read_to_string(&shadow).unwrap();
        assert_eq!(
            text,
            "# X-VPNZone=dbus\n[D-BUS Service]\nName=org.example.Notes\n\
             Exec=/bin/pick --id org.example.Notes -- /store/notes --gapplication-service\n"
        );
        assert!(!d
            .home
            .join(DBUS_SERVICES)
            .join("org.example.Plain.service")
            .exists());

        // Nothing changed: the bus is not reloaded for nothing.
        let (_, changed) = sync_from(&d.state, &d.home, "/bin/vpn-zone", "/bin/pick", &dirs);
        assert!(!changed);

        // A service file of the user's own is never overwritten or removed.
        let mine = d.home.join(DBUS_SERVICES).join("org.example.Mine.service");
        fs::write(&mine, "[D-BUS Service]\nName=org.example.Mine\nExec=mine\n").unwrap();

        // Mode off: our shadow goes, theirs stays.
        d.setting("mode", "off");
        let (_, changed) = sync_from(&d.state, &d.home, "/bin/vpn-zone", "/bin/pick", &dirs);
        assert!(changed);
        assert!(!shadow.exists());
        assert!(mine.exists());
    }

    #[test]
    fn only_well_formed_bus_names_are_shadowed() {
        assert!(is_bus_name("org.example.Notes"));
        assert!(is_bus_name("org.gnome.Nautilus"));
        for bad in [
            "firefox", ".org.x", "org.x.", "org..x", "org.1x", "org.x/y", "org.x y",
        ] {
            assert!(!is_bus_name(bad), "{bad}");
        }
    }

    // --- Web apps ------------------------------------------------------------

    #[test]
    fn a_web_app_is_launched_as_its_browser() {
        let d = Desk::new("webapp");
        fs::write(
            d.system.join("chromium-browser.desktop"),
            "[Desktop Entry]\nType=Application\nName=Chromium\nExec=chromium %U\n",
        )
        .unwrap();
        // What Chromium writes into the user directory when a site is
        // installed as an app — and a plain site shortcut.
        fs::write(
            d.apps.join("chrome-abcdef-Default.desktop"),
            "[Desktop Entry]\nType=Application\nName=Mail\n\
             Exec=/nix/store/x-chromium/bin/chromium --profile-directory=Default --app-id=abcdef\n",
        )
        .unwrap();
        fs::write(
            d.system.join("site-window.desktop"),
            "[Desktop Entry]\nType=Application\nName=Site\nExec=chromium --app=https://example.org\n",
        )
        .unwrap();
        d.sync();
        let web = d.read("chrome-abcdef-Default.desktop");
        assert!(web.contains("X-VPNZone=adopted"), "{web}");
        assert!(
            web.contains("--id chromium-browser -- /nix/store/x-chromium/bin/chromium"),
            "{web}"
        );
        assert!(d
            .read("site-window.desktop")
            .contains("--id chromium-browser -- chromium --app="));
        // The browser keeps its label; the web apps get none of their own.
        assert!(!d.state.join(".labels/chrome-abcdef-Default").exists());
        assert!(!d.state.join(".labels/site-window").exists());

        assert!(is_web_app_exec(
            "brave --profile-directory=Default --app-id=x"
        ));
        assert!(!is_web_app_exec("firefox --new-window https://example.org"));
    }

    #[test]
    fn a_web_app_without_its_browser_entry_is_its_own_program() {
        let d = Desk::new("webapp-alone");
        fs::write(
            d.apps.join("chrome-abcdef-Default.desktop"),
            "[Desktop Entry]\nType=Application\nName=Mail\nExec=chromium --app-id=abcdef\n",
        )
        .unwrap();
        d.sync();
        assert!(d
            .read("chrome-abcdef-Default.desktop")
            .contains("--id chrome-abcdef-Default --"));
    }

    // --- Lossless keys (L8) --------------------------------------------------

    #[test]
    fn keys_that_lost_something_carry_a_hash_and_keys_are_fixed_points() {
        assert_eq!(stable_key("firefox"), "firefox");
        assert_eq!(stable_key("org.kde.dolphin"), "org.kde.dolphin");
        let a = stable_key("Игра");
        let b = stable_key("Мама");
        assert!(a.starts_with("____-"), "{a}");
        assert_ne!(a, b);
        assert_ne!(stable_key("a b"), stable_key("a_b"));
        assert_eq!(stable_key("a_b"), "a_b");
        for raw in ["Игра", "a b", "Zen Browser", "x"] {
            let key = stable_key(raw);
            assert_eq!(stable_key(&key), key, "{raw}");
        }
        // Stable across versions: the hash is part of the state format.
        assert_eq!(stable_key("Zen Browser"), "Zen_Browser-a5ffb3fa");
    }

    #[test]
    fn memory_moves_to_the_new_key_or_is_dropped_when_it_was_shared() {
        let d = Desk::new("migrate");
        let entry = |name: &str| {
            fs::write(
                d.system.join(format!("{name}.desktop")),
                format!(
                    "[Desktop Entry]\nType=Application\nName={name}\nExec=x-{}\n",
                    name.len()
                ),
            )
            .unwrap()
        };
        entry("Zen Browser");
        entry("Игра");
        entry("Мама");
        let mem = |dir: &str, key: &str, value: &str| {
            fs::create_dir_all(d.state.join(dir)).unwrap();
            fs::write(d.state.join(dir).join(key), value).unwrap();
        };
        // The one entry behind `Zen_Browser`: everything moves.
        mem(".pinned", "Zen_Browser", "nl");
        mem(".pinnedprofile", "Zen_Browser", "sb:app-Zen_Browser");
        let sandboxes = d.home.join(".local/state/vpn-sandboxes");
        fs::create_dir_all(sandboxes.join("app-Zen_Browser/home")).unwrap();
        // Two entries behind `____`: nobody knows whose it was.
        mem(".pinned", "____", "direct");

        d.sync();
        let zen = stable_key("Zen Browser");
        assert_eq!(
            fs::read_to_string(d.state.join(".pinned").join(&zen)).unwrap(),
            "nl"
        );
        assert!(!d.state.join(".pinned/Zen_Browser").exists());
        assert!(sandboxes.join(format!("app-{zen}/home")).is_dir());
        assert_eq!(
            fs::read_to_string(d.state.join(".pinnedprofile").join(&zen)).unwrap(),
            format!("app-{zen}")
        );
        assert!(
            !d.state.join(".pinned/____").exists(),
            "shared memory is dropped"
        );
        assert!(!d.state.join(".pinned").join(stable_key("Игра")).exists());
        // The entries carry the new keys.
        assert!(d
            .read("Zen Browser.desktop")
            .contains(&format!("--id {zen} --")));
    }

    // --- PATH shims ----------------------------------------------------------

    #[test]
    fn an_assigned_program_gets_a_shim_that_never_calls_itself() {
        let d = Desk::new("shims");
        let bin = d.home.join("realbin");
        fs::create_dir_all(&bin).unwrap();
        let real = bin.join("tgapp");
        fs::write(&real, "#!/bin/sh\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(
            d.system.join("org.example.Tg.desktop"),
            "[Desktop Entry]\nType=Application\nName=Tg\nExec=tgapp -- %u\n",
        )
        .unwrap();
        fs::write(
            d.system.join("other.desktop"),
            "[Desktop Entry]\nType=Application\nName=Other\nExec=tgapp --other\n",
        )
        .unwrap();
        fs::create_dir_all(d.state.join(".pinnedprofile")).unwrap();
        fs::write(d.state.join(".pinnedprofile/org.example.Tg"), "work").unwrap();

        let shims = d.home.join(SHIM_DIR);
        let search = vec![shims.clone(), bin.clone()];
        assert_eq!(real_program("tgapp", &search, &shims), Some(real.clone()));

        // Off by default: nothing written.
        d.sync();
        assert!(!shims.join("tgapp").exists());

        d.setting("path-shims", "on");
        let apps = collect_apps(
            &[d.apps.clone(), d.system.clone()],
            &d.apps,
            &d.state.join(ADOPTED_DIR),
        );
        let parents = parents(&apps);
        let search = vec![shims.clone(), bin.clone()];
        let (written, _) = sync_shims(
            &d.home,
            &d.state,
            "/bin/pick",
            &apps,
            &parents,
            Some(&search),
        );
        assert_eq!(written, 1);
        let text = fs::read_to_string(shims.join("tgapp")).unwrap();
        assert!(
            text.contains(&format!(
                "exec /bin/pick --id org.example.Tg -- '{}' \"$@\"",
                real.display()
            )),
            "{text}"
        );
        // The shim itself is never taken for the real program.
        let search = vec![shims.clone()];
        assert_eq!(
            real_program("tgapp", &search, &d.home.join("elsewhere")),
            None
        );

        // Unassigned: the shim goes.
        fs::remove_file(d.state.join(".pinnedprofile/org.example.Tg")).unwrap();
        let search = vec![shims.clone(), bin.clone()];
        let (_, removed) = sync_shims(
            &d.home,
            &d.state,
            "/bin/pick",
            &apps,
            &parents,
            Some(&search),
        );
        assert_eq!(removed, 1);
        assert!(!shims.join("tgapp").exists());
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }

    /// Our own command under any of its names is never shimmed, even when an
    /// entry that runs it is assigned to a container: the shim would stand in
    /// for the command first on `PATH`.
    #[test]
    fn our_own_commands_are_never_shimmed() {
        let d = Desk::new("shims-ours");
        let bin = d.home.join("realbin");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(d.state.join(".pinnedprofile")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let names = ["cellward", "cw", "vpn-zone", "cellward-gui", "vpn-zone-gui"];
        for name in names {
            let real = bin.join(name);
            fs::write(&real, "#!/bin/sh\n").unwrap();
            fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).unwrap();
            fs::write(
                d.system.join(format!("org.example.{name}.desktop")),
                format!("[Desktop Entry]\nType=Application\nName={name}\nExec={name} list\n"),
            )
            .unwrap();
            fs::write(
                d.state.join(format!(".pinnedprofile/org.example.{name}")),
                "work",
            )
            .unwrap();
            assert!(is_ours(name), "{name}");
        }
        assert!(!is_ours("cwm") && !is_ours("firefox"));
        d.setting("path-shims", "on");
        let apps = collect_apps(
            &[d.apps.clone(), d.system.clone()],
            &d.apps,
            &d.state.join(ADOPTED_DIR),
        );
        let parents = parents(&apps);
        let shims = d.home.join(SHIM_DIR);
        let search = vec![shims.clone(), bin.clone()];
        let (written, _) = sync_shims(
            &d.home,
            &d.state,
            "/bin/pick",
            &apps,
            &parents,
            Some(&search),
        );
        assert_eq!(written, 0);
        for name in names {
            assert!(!shims.join(name).exists(), "{name}");
        }
    }

    // --- THE ZONE'S NAME FOR THE PORTAL -------------------------------------

    /// One element of an application id: `[A-Za-z0-9_]`, no leading digit;
    /// a name that changed on the way keeps a hash of what it was, so that
    /// two zones never share one id.
    #[test]
    fn a_zones_app_id_is_one_valid_element_and_its_own() {
        assert_eq!(zone_app_id("nl"), "cellward.zone.nl");
        assert_eq!(zone_app_id("Work_2"), "cellward.zone.Work_2");
        assert_eq!(zone_app_id("_1x"), "cellward.zone._1x");
        let dash = zone_app_id("work-vpn");
        let under = zone_app_id("work_vpn");
        assert_eq!(under, "cellward.zone.work_vpn");
        assert!(dash.starts_with("cellward.zone.work_vpn_"), "{dash}");
        assert_ne!(dash, under);
        let digit = zone_app_id("1x");
        assert!(digit.starts_with("cellward.zone._1x_"), "{digit}");
        assert_ne!(digit, zone_app_id("_1x"));
        // Stable: the holder, sync and `rm` derive the same file name.
        assert_eq!(zone_app_id("work-vpn"), dash);
        for zone in [
            "nl",
            "work-vpn",
            "1x",
            "зона",
            "a b",
            "",
            "x.y",
            &"z".repeat(400),
            &"-".repeat(400),
        ] {
            let id = zone_app_id(zone);
            let element = id.strip_prefix(ZONE_APP_PREFIX).unwrap();
            assert!(id.len() <= MAX_APP_ID, "{zone:?}: {}", id.len());
            assert!(!element.is_empty(), "{zone:?}");
            assert!(
                element
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "{zone:?}: {id}"
            );
            assert!(!element.starts_with(|c: char| c.is_ascii_digit()), "{id}");
            assert_eq!(zone_entry_file(zone), format!("{id}.desktop"));
        }
        // Cut to fit, and still two ids for two long names.
        assert_ne!(
            zone_app_id(&format!("{}a", "z".repeat(300))),
            zone_app_id(&format!("{}b", "z".repeat(300)))
        );
    }

    /// A string value as GLib's key file reads it back.
    fn unescaped(value: &str) -> String {
        let mut out = String::new();
        let mut chars = value.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('s') => out.push(' '),
                Some(other) => out.push(other),
                None => {}
            }
        }
        out
    }

    /// The entry names the zone and starts nothing it should not: an odd
    /// name cannot end a line, add a key or split the command, and the
    /// command reads back as `<runner> status <zone>`.
    #[test]
    fn a_zones_entry_is_escaped_and_starts_only_its_status() {
        let text = render_zone_entry("nl", "/home/u/.nix-profile/bin/cellward");
        assert_eq!(
            text,
            "[Desktop Entry]\nType=Application\nName=cellward · nl\n\
             Comment=Программы зоны «nl»\n\
             Exec=/home/u/.nix-profile/bin/cellward status nl\nIcon=network-vpn\n\
             NoDisplay=true\nX-VPNZone=portal\n"
        );
        let groups = parse_desktop(&text);
        assert_eq!(groups.len(), 1);
        let entry = desktop_entry(&groups).unwrap();
        // Ours: sync neither intercepts, clones nor takes it over.
        assert!(!is_candidate(&zone_entry_file("nl"), Some(entry)));
        assert!(!is_hidden_handler(&zone_entry_file("nl"), Some(entry)));
        assert!(!is_hidden_user_entry(&zone_entry_file("nl"), Some(entry)));

        let odd = " a\"b$c`d\\e\nExec=evil %u\tf";
        let runner = "/home/John Doe/bin/cellward";
        let text = render_zone_entry(odd, runner);
        assert_eq!(text.lines().count(), 8, "{text}");
        let groups = parse_desktop(&text);
        let entry = desktop_entry(&groups).unwrap();
        assert_eq!(entry.entries().count(), 7, "{text}");
        assert_eq!(
            unescaped(entry.get("Name").unwrap()),
            format!("cellward · {odd}")
        );
        let exec = unescaped(entry.get("Exec").unwrap());
        let words: Vec<String> = exec_words(&exec)
            .into_iter()
            .map(|w| w.replace("%%", "%"))
            .collect();
        assert_eq!(words, [runner, "status", odd]);
        // No field code left for a launcher to fill.
        assert!(!exec.replace("%%", "").contains('%'), "{exec}");
    }

    /// The holder writes it, sync keeps it while the zone is there — in every
    /// mode — and takes it with the zone; a file of somebody else's under the
    /// name is left as it is.
    #[test]
    fn a_zones_entry_lives_as_long_as_the_zone() {
        let d = Desk::new("portal");
        fs::create_dir_all(d.state.join("nl")).unwrap();
        fs::write(d.state.join("nl/config.conf"), "[Interface]\n").unwrap();
        fs::create_dir_all(d.state.join("offline")).unwrap();
        fs::write(d.state.join("offline/offline"), "").unwrap();
        for zone in ["nl", "offline", "gone"] {
            assert!(write_zone_entry(&d.home, zone, "/bin/cellward").unwrap());
        }
        // Unchanged: not written again (a path unit watches the directory).
        assert!(!write_zone_entry(&d.home, "nl", "/bin/cellward").unwrap());
        for mode in ["picker", "off", "per-zone"] {
            d.setting("mode", mode);
            d.sync();
            let nl = d.read(&zone_entry_file("nl"));
            assert_eq!(nl, render_zone_entry("nl", "/bin/cellward"), "{mode}");
            assert!(d.apps.join(zone_entry_file("offline")).exists(), "{mode}");
            assert!(!d.apps.join(zone_entry_file("gone")).exists(), "{mode}");
            // Not taken for a program: no clone, no picker entry of it.
            assert!(
                !d.apps
                    .join(format!("{PREFIX}nl-{}", zone_entry_file("nl")))
                    .exists(),
                "{mode}"
            );
        }
        // `rm`: the entry goes with the zone.
        remove_zone_entry(&d.home, "nl");
        assert!(!d.apps.join(zone_entry_file("nl")).exists());
        // Somebody else's file under the name: neither overwritten nor taken.
        let theirs = d.apps.join(zone_entry_file("nl"));
        fs::write(&theirs, "[Desktop Entry]\nType=Application\nExec=x\n").unwrap();
        assert!(write_zone_entry(&d.home, "nl", "/bin/cellward").is_err());
        remove_zone_entry(&d.home, "nl");
        assert!(theirs.exists());
    }
}
