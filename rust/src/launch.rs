//! `vpn-zone run` — everything that happens between a click on a shortcut and
//! the program starting inside a zone.
//!
//! The order of the steps is the interesting part, and every one of them is
//! there because something went wrong without it:
//!
//!  1. **a launch coming FROM a zone is delegated outwards.** A process that is
//!     already in a user+net namespace cannot enter another one ("nsenter:
//!     reassociate to namespaces failed"), so a link clicked in a messenger
//!     inside a zone opened the picker and then no browser at all — and "direct
//!     internet" silently inherited the zone's network instead of being direct.
//!     `systemd --user` lives in the root namespace and its socket is visible
//!     from inside the zone, so the launch is handed to it and starts outside;
//!  2. **a locked zone keeps its launches**, because a quarantine zone must not
//!     be able to open a program in another network. Not by re-entering the zone
//!     (the kernel forbids that too) but by dropping the selection arguments and
//!     running the command where we already are;
//!  3. the container and sandbox flags are parsed, and a throwaway container is
//!     created;
//!  4. the command is wrapped in the compositor restriction (`wl-sandbox`) and,
//!     if asked for, the filesystem sandbox (`fs-sandbox`);
//!  5. the launch registry says whether this program is already running in
//!     ANOTHER network — the "I thought I was on the VPN" warning;
//!  6. the zone is started if it was down, we write ourselves into the registry
//!     and `execvp` into the container's instance (`crate::instance`, the
//!     container design of 2026-09-27): its unit is started if it was down,
//!     and the last word is `container-enter`, which finds it again by its
//!     id. Never into the zone's own namespaces (stage 5, 2026-09-28): a zone
//!     is transport, and one that cannot carry the instance — of a previous
//!     build — is refused with the way out, its restart.
//!
//! **`direct` takes the same road**, minus the zone. It used to be a special
//! case of the picker, which simply became the command — and with that the
//! container or sandbox the user had chosen, the compositor restriction and the
//! registry record were all dropped without a word: "🔒 Своя песочница" plus
//! "Прямой интернет" started the program with the whole `$HOME` in reach.
//! Now only the NAMESPACE step differs: there is no zone to enter, so a
//! container gets a user+mount namespace of its own from `unshare` (see
//! [`entry_argv`]) and everything else is exactly what a zone launch gets.
//!
//! **The last step must be an `exec`.** The pid does not change, so the registry
//! record written just before it stays true for as long as the program runs —
//! the picker, the conflict warning and the throwaway-container cleanup all read
//! that pid. Anything that forked here instead would leave a record naming a
//! process that exits immediately. (`docs/GOTCHAS.md` §5)

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::cli;
use crate::profile::{exec_command, EXIT_NOT_STARTED};
use crate::registry;
use crate::tools::Tools;

/// Marks the descendants of a zone. Its presence is what step 1 keys on.
pub const ENV_CURRENT: &str = "VPN_ZONE_CURRENT";
/// Set on the delegated launch so that it does not delegate itself again.
pub const ENV_DELEGATED: &str = "VPN_ZONE_DELEGATED";
/// The launcher's stable key for the program, put there by the picker.
pub const ENV_APPID: &str = "VPN_ZONE_APPID";
/// On a delegated launch: the zone it was asked for from. A zone's lock is
/// out of its own sight (`zone::hide_project_state`), so the host looks it up.
const ENV_FROM: &str = "VPN_ZONE_FROM";
/// Print the resulting command and start nothing.
pub const ENV_DRYRUN: &str = "VPN_ZONE_DRYRUN";
/// On a launch the broker started without a question (the same container
/// asking for itself): what the program's name would relax — no Wayland
/// proxy, no compositor restriction — is not relaxed. The requester chose
/// the command's first word, and so the name the lists are read by.
pub const ENV_UNASKED: &str = "VPN_ZONE_UNASKED";

/// Environment variables that name a compositor's IPC socket — a way to have
/// the compositor spawn a process on the host. Dropped from launches into a
/// zone, where the sockets are not either (`docs/LEAK-MODEL.md` §13).
///
/// Wayfire's (`docs/THREAT-MODEL.md` W7, 2026-09-28): `WAYFIRE_SOCKET`, where
/// its IPC plugin listens — by default in `/tmp`, which an ordinary zone
/// shares with the host (LEAK-MODEL §9, §15): its programs are no longer told
/// where it is, and a hermetic zone's `/tmp` is its own. `_WAYFIRE_SOCKET` is
/// the path Wayfire is told to make it at, and names it as well.
pub const COMPOSITOR_IPC_VARS: [&str; 6] = [
    "NIRI_SOCKET",
    "SWAYSOCK",
    "I3SOCK",
    "HYPRLAND_INSTANCE_SIGNATURE",
    "WAYFIRE_SOCKET",
    "_WAYFIRE_SOCKET",
];

/// Marker file of a locked ("no escape") zone.
pub const NO_ESCAPE: &str = "no-escape";

/// The built-in "network" that is the host's own: no zone, no tunnel, and none
/// of a zone's containment — the host's resolver, its session bus, its
/// `systemd --user`, its X server. Named for exactly that, so that it is never
/// taken for a harmless default. Not a directory in the state dir and never
/// one: `vpn-zone add` refuses the name, and a launch refuses it while a zone
/// of that name survives from before the name was taken.
pub const UNCONFINED: &str = "unconfined";
/// Its name until 2026-09. Accepted wherever a network name comes in — the
/// command line, pins, settings, containers, Nix, the registry — and never
/// written again.
pub const UNCONFINED_ALIAS: &str = "direct";

/// A network name as the rest of the code knows it: the old name of
/// [`UNCONFINED`] becomes the new one, everything else stays.
pub fn network_name(name: &str) -> &str {
    if name == UNCONFINED_ALIAS {
        UNCONFINED
    } else {
        name
    }
}

/// Whether this process is a zone's: a program started into a zone carries
/// [`ENV_CURRENT`]. A program that drops the variable only loses what the
/// host would do for it; the zone's walls are the kernel's.
pub fn in_zone() -> bool {
    std::env::var_os(ENV_CURRENT).is_some_and(|v| !v.is_empty())
}

/// Names a zone directory cannot be entered by: they mean [`UNCONFINED`].
pub fn is_unconfined_name(name: &str) -> bool {
    matches!(name, UNCONFINED | UNCONFINED_ALIAS)
}
/// The other built-in choice: a zone with loopback only, created on demand.
pub const OFFLINE: &str = "offline";

/// Programs that keep the full set of compositor protocols.
///
/// They are the ones that live off exactly those protocols: screenshot tools,
/// the clipboard manager, screen recording, the compositor's own shell. The
/// sandboxes at the end (flatpak, bwrap, podman, distrobox) are here NOT by
/// oversight: they create a security context of their own, and a restricted
/// client has that protocol taken away — one sandbox cannot be nested in
/// another. Their own isolation is stricter than ours, so they get to use it.
/// (`docs/GOTCHAS.md` §7)
pub const WAYLAND_ALLOWED: [&str; 27] = [
    "grim",
    "slurp",
    "swappy",
    "wl-copy",
    "wl-paste",
    "copyq",
    "wf-recorder",
    "obs",
    "obs-studio",
    "spectacle",
    "ksnip",
    "wtype",
    "ydotool",
    "niri",
    "noctalia",
    "noctalia-shell",
    "waybar",
    "wayland-info",
    "wlr-randr",
    "kanshi",
    "gammastep",
    "wlsunset",
    "wdisplays",
    "flatpak",
    "bwrap",
    "podman",
    "distrobox",
];

/// The warning shown when the same program is already running somewhere else.
/// Verbatim from the shell version: it is the one message in the project a user
/// reads under time pressure.
const CONFLICT_MESSAGE: &str = "«{app}» уже запущена в сети «{busy}», а ты открываешь её в «{zone}».\n\nОсторожно: у программ с одним процессом на профиль (браузеры, Telegram, Discord) окно ОТКРОЕТСЯ и будет выглядеть обычно — но нарисует его старый процесс, и трафик в нём пойдёт через «{busy}», а не через «{zone}». Со стороны неотличимо, поэтому и предупреждаем.\n\nЕсли у программы каждое окно своё (терминалы, редакторы), всё в порядке — отметь «не спрашивать снова».";

/// The same warning when what is being handed over is a LINK (`steam://…`,
/// `tg://…`, `https://…`). A single-instance program hands it to the process
/// that is already up, so the link — or the game a Steam shortcut starts — is
/// opened in THAT process's network; "the window will open" is the wrong
/// picture for it. (`docs/GOTCHAS.md` §5)
const CONFLICT_URL_MESSAGE: &str = "«{app}» уже запущена в сети «{busy}», а ссылку ты открываешь в «{zone}».\n\nОсторожно: ссылку, скорее всего, примет уже запущенный процесс — и откроет её в сети «{busy}», а не «{zone}». Так ведут себя браузеры, мессенджеры и Steam: игра с ярлыка запускается в сети клиента. Со стороны неотличимо, поэтому и предупреждаем.\n\nЕсли программа на каждую ссылку запускает свой процесс, всё в порядке — отметь «не спрашивать снова».";

/// What the user asked for, before anything was created or checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub zone: OsString,
    pub container: Container,
    pub sandbox: Sandbox,
    /// The program and its arguments. May be empty: the shell version passed
    /// nothing to `nsenter` in that case, and `nsenter` with no command starts a
    /// shell inside the zone — which is a perfectly good thing to want.
    pub cmd: Vec<OsString>,
}

/// The data container of a launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Container {
    /// No layers: `~/` as it is.
    Main,
    /// A container with a layer over the home (`--profile`, `--container`).
    /// Before [`resolve_selection`], any named container: its kind is not
    /// known yet.
    Named(OsString),
    /// A named container of the main home: `~/` as it is, under the
    /// container's name, network and permissions.
    MainNamed(OsString),
    /// `--tmp-profile`: a fresh layer in `/tmp`, erased when the last program
    /// living in it exits.
    TmpNew,
    /// `--tmp-profile --join <dir>`: put this program into a throwaway
    /// container that is already open, so that two programs share one session.
    TmpJoin(PathBuf),
}

/// The filesystem sandbox of a launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sandbox {
    None,
    /// `--fs-sandbox`: an empty home that dies with the program.
    Throwaway,
    /// `--sandbox <name>`: a persistent home shared by everything started into
    /// that sandbox.
    Named(OsString),
}

/// Everything that can be wrong with `vpn-zone run`'s arguments.
///
/// The texts are the shell's `${1:?…}` messages word for word — they are what
/// the user sees in a terminal, and translating them is a step of its own
/// (ROADMAP M6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgError {
    MissingZone,
    MissingProfile,
    MissingJoinDir,
    MissingSandbox,
    MissingContainer,
}

impl fmt::Display for ArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingZone => write!(f, "нужно имя"),
            Self::MissingProfile => write!(f, "нужно имя контейнера (--profile)"),
            Self::MissingJoinDir => write!(f, "нужен каталог временного контейнера"),
            Self::MissingSandbox => write!(f, "нужно имя контейнера (--sandbox)"),
            Self::MissingContainer => write!(f, "нужно имя контейнера"),
        }
    }
}

impl std::error::Error for ArgError {}

impl Selection {
    /// Parse `<zone> [--container C | --profile P | -p P | --tmp-profile
    /// [--join DIR]] [--fs-sandbox | --sandbox NAME] [--] cmd…`.
    ///
    /// Positional, exactly as the shell version: the container flag may only
    /// come first and the sandbox flag second, and everything after the
    /// optional `--` is the command even when it looks like a flag. The picker
    /// builds the line in that order, and a `-p` that arrives later belongs to
    /// the program, not to us.
    pub fn parse(argv: &[OsString]) -> Result<Self, ArgError> {
        let mut rest = argv.iter();
        let zone = rest
            .next()
            .filter(|z| !z.is_empty())
            .ok_or(ArgError::MissingZone)?;
        let zone = if zone == UNCONFINED_ALIAS {
            OsString::from(UNCONFINED)
        } else {
            zone.clone()
        };
        let mut rest: Vec<OsString> = rest.cloned().collect();

        let container = match rest.first().map(OsString::as_os_str) {
            Some(f) if f == "--container" => {
                let name = rest.get(1).filter(|n| !n.is_empty()).cloned();
                let name = name.ok_or(ArgError::MissingContainer)?;
                rest.drain(..2.min(rest.len()));
                Container::Named(name)
            }
            Some(f) if f == "--profile" || f == "-p" => {
                let name = rest.get(1).filter(|n| !n.is_empty()).cloned();
                let name = name.ok_or(ArgError::MissingProfile)?;
                rest.drain(..2.min(rest.len()));
                Container::Named(name)
            }
            Some(f) if f == "--tmp-profile" => {
                rest.remove(0);
                if rest.first().is_some_and(|f| f == "--join") {
                    let dir = rest.get(1).filter(|d| !d.is_empty()).cloned();
                    let dir = dir.ok_or(ArgError::MissingJoinDir)?;
                    rest.drain(..2.min(rest.len()));
                    Container::TmpJoin(PathBuf::from(dir))
                } else {
                    Container::TmpNew
                }
            }
            _ => Container::Main,
        };

        let sandbox = match rest.first().map(OsString::as_os_str) {
            Some(f) if f == "--fs-sandbox" => {
                rest.remove(0);
                Sandbox::Throwaway
            }
            Some(f) if f == "--sandbox" => {
                let name = rest.get(1).filter(|n| !n.is_empty()).cloned();
                let name = name.ok_or(ArgError::MissingSandbox)?;
                rest.drain(..2.min(rest.len()));
                Sandbox::Named(name)
            }
            _ => Sandbox::None,
        };

        if rest.first().is_some_and(|f| f == "--") {
            rest.remove(0);
        }

        Ok(Self {
            zone,
            container,
            sandbox,
            cmd: rest,
        })
    }
}

/// Drop the selection arguments of a `run` line and leave the command.
///
/// This is what a LOCKED zone does with a launch: we are already inside that
/// zone, entering it a second time is impossible, and mounting a container
/// layer from in here is impossible too (the capabilities are gone), so the
/// choice is simply thrown away and the command runs where it is.
///
/// The sandbox flags have to be dropped as well, and that is not cosmetic:
/// while they were left in the line, `--` was no longer found where it was
/// expected and the shell tried to execute the flag itself — "--sandbox: not
/// found". The program did not open at all, and the message went to a
/// shortcut's stderr, where nobody reads it.
pub fn strip_selection(argv: &[OsString]) -> Vec<OsString> {
    let mut rest: Vec<OsString> = argv.iter().skip(1).cloned().collect();
    match rest.first().map(OsString::as_os_str) {
        Some(f) if f == "--profile" || f == "-p" || f == "--container" => {
            rest.drain(..2.min(rest.len()));
        }
        Some(f) if f == "--tmp-profile" => {
            rest.remove(0);
            if rest.first().is_some_and(|f| f == "--join") {
                rest.drain(..2.min(rest.len()));
            }
        }
        _ => {}
    }
    match rest.first().map(OsString::as_os_str) {
        Some(f) if f == "--fs-sandbox" => {
            rest.remove(0);
        }
        Some(f) if f == "--sandbox" => {
            rest.drain(..2.min(rest.len()));
        }
        _ => {}
    }
    if rest.first().is_some_and(|f| f == "--") {
        rest.remove(0);
    }
    rest
}

/// The word of a command line that names the program.
///
/// Wrappers and variable assignments are skipped: for `env DESKTOPINTEGRATION=1
/// AyuGram` the answer is `AyuGram` and not `env`. Two traps here, both paid
/// for (`docs/GOTCHAS.md` §7):
///
/// * only a REAL assignment is skipped. The pattern used to be `*=*`, which
///   also threw away ordinary arguments with an equals sign in them — the
///   script text after `sh -c`, for instance — and the app-id came out empty;
/// * an argument with a space in it is taken as the program name (through
///   `basename`) rather than skipped, because that is the `sh -c '…'` case and
///   an empty app-id would mean no compositor restriction at all.
pub fn app_word(cmd: &[OsString]) -> Option<&OsStr> {
    program_word(cmd).map(basename)
}

/// The word of a command line that names the program, whole — a path stays
/// a path ([`app_word`] is its last component). What the compositor's list
/// asks the origin of (`wayland_sandbox_wanted`).
fn program_word(cmd: &[OsString]) -> Option<&OsStr> {
    for word in cmd {
        let bytes = word.as_bytes();
        // A wrapper by its name, bare or where the system keeps it: the
        // broker pins a program by its path (`/nix/store/…/bin/env`, review
        // 2026-09-27) — but a `~/.local/bin/env` of a zone's is a program of
        // its own, not a wrapper to see past.
        let system = !bytes.contains(&b'/')
            || [
                &b"/nix/store/"[..],
                b"/run/current-system/",
                b"/usr/",
                b"/bin/",
            ]
            .iter()
            .any(|place| bytes.starts_with(place));
        if (system
            && matches!(
                basename(word).as_bytes(),
                b"env" | b"sh" | b"bash" | b"setsid" | b"nohup"
            ))
            || bytes.starts_with(b"-")
        {
            continue;
        }
        if bytes.contains(&b' ') {
            return Some(word.as_os_str());
        }
        if is_assignment(bytes) {
            continue;
        }
        return Some(word.as_os_str());
    }
    None
}

/// Does this command hand a LINK to its program (`steam://rungameid/…`,
/// `tg://resolve?…`, `https://…`)?
///
/// Only the warning text depends on it, so a rough test is the right one: any
/// argument with `://` in it that is not the program itself.
pub fn hands_over_a_link(cmd: &[OsString]) -> bool {
    cmd.iter()
        .skip(1)
        .any(|arg| arg.as_bytes().windows(3).any(|w| w == b"://"))
}

/// `[A-Za-z_]*=*` as a shell glob: a name-looking word with an equals sign
/// somewhere after the first character.
///
/// Public because the picker derives its memory key the same way when a launch
/// did not come from a shortcut (`crate::picker::fallback_key`), and the two
/// must not drift apart.
pub fn is_assignment(word: &[u8]) -> bool {
    matches!(word.first(), Some(b) if b.is_ascii_alphabetic() || *b == b'_')
        && word[1..].contains(&b'=')
}

/// `basename`: the last path component, trailing slashes ignored.
pub fn basename(path: &OsStr) -> &OsStr {
    let bytes = path.as_bytes();
    let trimmed = bytes.trim_ascii_end_matches_slash();
    if trimmed.is_empty() {
        // "/" and "//" answer "/", "" answers "" — what basename(1) prints.
        return OsStr::from_bytes(&bytes[..bytes.len().min(1)]);
    }
    let start = trimmed
        .iter()
        .rposition(|b| *b == b'/')
        .map_or(0, |i| i + 1);
    OsStr::from_bytes(&trimmed[start..])
}

/// The private half of [`basename`]: `${x%%/}` for bytes.
trait TrimSlash {
    fn trim_ascii_end_matches_slash(&self) -> &Self;
}

impl TrimSlash for [u8] {
    fn trim_ascii_end_matches_slash(&self) -> &[u8] {
        let mut end = self.len();
        while end > 0 && self[end - 1] == b'/' {
            end -= 1;
        }
        &self[..end]
    }
}

/// Reduce an identifier to one word of `[A-Za-z0-9_.-]`, at most 64 bytes.
///
/// It goes into an argument of `wl-sandbox`, so it MUST be a single word: a
/// space split the argument in two and the wrong program was started (measured
/// on `sh -c 'echo …'`). Newlines are removed rather than replaced because the
/// first line of a multi-line command is empty — `cut` then returned nothing at
/// all and the launch died with "need an app-id".
///
/// Byte-wise on purpose, like the `tr` it replaces: a non-ASCII name becomes a
/// row of underscores, which is ugly and stable, and the shell version has been
/// answering that way for as long as the permission files have existed.
/// The registry's file name for a program: the picker's keys as they are
/// (`desktop::stable_key` makes them of these characters already), anything
/// else reduced to them — never a path, never `.` or `..`, never empty.
pub fn registry_key(raw: &OsStr) -> OsString {
    let kept: Vec<u8> = raw
        .as_bytes()
        .iter()
        .take(200)
        .map(|&b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-') {
                b
            } else {
                b'_'
            }
        })
        .collect();
    if kept.is_empty() || kept.iter().all(|&b| b == b'.') {
        return OsString::from("программа");
    }
    OsString::from_vec(kept)
}

pub fn sanitize_app_id(raw: &OsStr) -> OsString {
    let mut out: Vec<u8> = Vec::with_capacity(raw.as_bytes().len());
    for &b in raw.as_bytes() {
        if b == b'\n' {
            continue;
        }
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-') {
            out.push(b);
        } else {
            out.push(b'_');
        }
        if out.len() == 64 {
            break;
        }
    }
    OsString::from_vec(out)
}

/// `$VAR`, or `None` when it is unset or empty — the shell's `${VAR:-}` test.
fn env_nonempty(name: &str) -> Option<OsString> {
    std::env::var_os(name).filter(|v| !v.is_empty())
}

/// The human-readable name the picker remembered for this key
/// (`.labels/<key>`), if any.
///
/// Dialogs should say «Telegram», not "org.telegram.desktop": the raw id is
/// the PERMISSION KEY, not a name for humans. A launch that never went through
/// the picker has no label — callers fall back to the id, which is still
/// better than naming no program at all.
fn pretty_label(state: &Path, key: &OsStr) -> Option<String> {
    if key.is_empty() {
        return None;
    }
    let text = std::fs::read_to_string(state.join(".labels").join(key)).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// Is there a graphical session to show a dialog on?
///
/// Without one `kdialog` dies immediately, and treating that as "the user
/// cancelled" turned a launch from a terminal into silence. The picker and the
/// filesystem sandbox make the same test, and this is the one they make.
/// (`docs/GOTCHAS.md` §5, §6)
pub fn has_display() -> bool {
    env_nonempty("WAYLAND_DISPLAY").is_some() || env_nonempty("DISPLAY").is_some()
}

/// Run a program inside a zone. Returns only when something went wrong: the
/// successful path ends in `execvp`.
pub fn run(tools: &Tools, argv: &[OsString]) -> u8 {
    // The picker's pipe, when it watches this launch for a hand-over
    // (`crate::picker`): taken at once — nothing this starts on the way
    // (a dialog, systemctl) inherits it —, given on to `wl-sandbox` just
    // before its exec, and on every other way out told that no word will
    // come: a launch cancelled or only shown (`--dry-run`) that ends with
    // success is no hand-over.
    struct NoWord;
    impl Drop for NoWord {
        fn drop(&mut self) {
            crate::wl_sandbox::no_word();
        }
    }
    crate::wl_sandbox::take_opened();
    let _no_word = NoWord;
    // --- 1. FROM INSIDE A ZONE: DELEGATE OR STAY ---
    if let Some(current) = env_nonempty(ENV_CURRENT) {
        if env_nonempty(ENV_DELEGATED).is_none() {
            return if tools.state.join(&current).join(NO_ESCAPE).exists() {
                run_locked(&current, argv)
            } else {
                delegate(tools, argv)
            };
        }
    }
    // The guard has done its job for THIS launch and must not travel into the
    // program. It used to: a browser opened from a messenger inside a zone
    // carried `VPN_ZONE_DELEGATED=1` for the rest of its life, so a link
    // clicked in THAT browser skipped the delegation above and died in
    // `nsenter` with "reassociate to namespaces failed" — the very failure the
    // delegation exists to avoid. Whether it was there is kept for the
    // registry: a launch asked for from inside a zone is marked so.
    let from_zone = env_nonempty(ENV_DELEGATED).is_some();
    std::env::remove_var(ENV_DELEGATED);
    let unasked = env_nonempty(ENV_UNASKED).is_some();
    std::env::remove_var(ENV_UNASKED);
    let asked_from = env_nonempty(ENV_FROM).filter(|_| from_zone);
    std::env::remove_var(ENV_FROM);
    // A locked zone's own launches stay in it (`run_locked`), which the zone
    // can no longer see for itself: its lock is hidden from it with the rest
    // of the state. The name comes from the zone and may be a lie — a zone
    // with `systemd --user` has other ways out anyway, which is what the lock
    // of such a zone says of itself (`vpn-zone lock`); a hermetic zone has no
    // way here but the broker, which judges by the kernel.
    let argv: Vec<OsString> = match asked_from {
        Some(origin)
            if argv.first().map(OsString::as_os_str) != Some(origin.as_os_str())
                && !origin.is_empty()
                && !origin.to_string_lossy().contains('/')
                && tools.state.join(&origin).join(NO_ESCAPE).exists() =>
        {
            eprintln!(
                "зона {} заперта: запускаем в ней же",
                origin.to_string_lossy()
            );
            std::iter::once(origin)
                .chain(argv.iter().skip(1).cloned())
                .collect()
        }
        _ => argv.to_vec(),
    };
    let argv = argv.as_slice();

    let selection = match Selection::parse(argv) {
        Ok(selection) => selection,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    // One launch, one container, whatever words named it.
    let selection = match resolve_selection(tools, selection) {
        Ok(selection) => selection,
        Err(why) => {
            refuse(tools, &why);
            return 1;
        }
    };
    let zone = selection.zone.clone();
    let zone_name = zone.to_string_lossy().into_owned();

    // A zone that was called `unconfined` before the name meant the host's
    // network: a launch "into" it would now leave its VPN behind without a
    // word. Refused until the zone is renamed.
    if zone == UNCONFINED && tools.state.join(UNCONFINED).is_dir() {
        refuse(
            tools,
            &format!(
                "«{UNCONFINED}» теперь значит «без ограничений» (сеть хоста, без VPN и изоляции зоны), \
                 а у тебя есть зона с таким именем — запуск остановлен, чтобы не уйти мимо её VPN. \
                 Переименуй зону: cellward down {UNCONFINED}, переименуй каталог \
                 {} и снова cellward up",
                tools.state.join(UNCONFINED).display()
            ),
        );
        return 1;
    }

    // The network with no network has a directory of its own, made on demand
    // here as in the picker: where its settings are kept, and its instances
    // read them (`zone::InstanceInfo::network_dir`). Never started as a zone
    // since stage 1 of the container design: nothing is launched into a
    // zone's own namespaces.
    if zone == OFFLINE {
        ensure_offline_zone(&tools.state);
    }

    // --- 1a. ONE IDENTITY, ONE NETWORK ---
    // Before anything is created: a container bound to a network runs in that
    // network only, and a container never runs in two networks at once
    // (`docs/CONTAINERS.md` I1, I2). The picker does not offer anything else;
    // this is where a command line, a stale shortcut or a script is stopped.
    if let Some(why) = identity_refusal(tools, &selection, &zone_name) {
        refuse(tools, &why);
        return 1;
    }
    // Only now anything is made or moved for it — never for a launch that is
    // refused, never in a dry run.
    if env_nonempty(ENV_DRYRUN).is_none() {
        if let Err(why) = prepare_selection(tools, &selection) {
            refuse(tools, &why);
            return 1;
        }
    }

    // --- 2. THE CONTAINER ---
    let Some(container) = resolve_container(tools, &selection) else {
        return 1;
    };
    // Offline, the launch runs in its container's instance (`crate::
    // instance`, stage 1 of the container design of 2026-09-27): namespaces
    // of the container's own, no way out — and the `offline` zone is not
    // started for it any more.
    // Stage 2 (2026-09-27): into a zone too — its instance's way out is a
    // passt the zone runs for it, and nothing of the zone's own namespaces is
    // the program's. Stage 5 (2026-09-28): ONLY so. A zone of a previous
    // build (no bridge: an update left it running) used to be entered as
    // before, into its own namespaces; now no launch goes there at all, and
    // one into such a zone is refused with the way out — its restart
    // (`up_instance`). Every network but `unconfined` is an instance's.
    let instance_id: Option<String> = if zone == UNCONFINED {
        None
    } else {
        match instance_of(tools, &selection, &container, &zone_name) {
            Ok(id) => Some(id),
            Err(why) => {
                refuse(tools, &why);
                return 1;
            }
        }
    };
    // A container whose launches still run in the zone's own namespaces —
    // started there by a previous build, before the update — is not started
    // in its instance beside them: two worlds of one home and one profile
    // (`docs/CONTAINERS.md` I2, stage 2's form of it).
    if let (Some(_), Some(name)) = (&instance_id, container_name(&selection)) {
        if let Some(why) = zone_launches_refusal(tools, &name, &zone_name) {
            refuse(tools, &why);
            return 1;
        }
    }
    // A locked zone takes a hermetic instance only (review 2026-09-28,
    // `lock_refusal`): before anything is started — in a dry run too —,
    // and again once the instance is up (`up_instance`).
    if let Some(why) = instance_id
        .as_deref()
        .and_then(|id| lock_refusal(tools, id, &zone_name))
    {
        refuse(tools, &why);
        return 1;
    }

    // --- 3. THE WRAPPERS ---
    // The app-id is worked out BEFORE anything is prepended to the command:
    // afterwards the first word is `vpn-zone-core`, and taking the name from
    // there made the conflict warning name the wrapper, gave every sandboxed
    // program one shared "do not ask again" key, and merged them all into a
    // single registry entry. (`docs/GOTCHAS.md` §5, §6)
    let appid_env = env_nonempty(ENV_APPID);
    let appbin = sanitize_app_id(
        appid_env
            .as_deref()
            .or_else(|| app_word(&selection.cmd))
            .unwrap_or(OsStr::new("")),
    );
    // The human-readable name for every dialog below: the label the picker
    // remembered for this key, when there is one. Two programs starting at
    // once each ask their own questions, and a dialog that names its program
    // with a raw id (or not at all) is how the answers get swapped.
    // A file name, whoever set the variable (`registry_key`).
    let label = pretty_label(
        &tools.state,
        &registry_key(appid_env.as_deref().unwrap_or(appbin.as_os_str())),
    );
    let mut cmd = selection.cmd.clone();

    // --- THE CAMERAS ---
    // The host's cameras for this launch (`docs/PERMISSIONS.md` §11.10): the
    // zone's `/dev` has none, and a launch they are let gets them bound in,
    // in its own mount namespace (`profile::give_capture`)
    // — by its container's setting, the zone's for a launch with none.
    let camera = zone != UNCONFINED && {
        let zone_dir = tools.state.join(&zone_name);
        match container_name(&selection) {
            Some(name) => crate::container::camera_for(&zone_dir, &tools.config, &zone_name, &name),
            None => crate::hermetic::camera(&zone_dir, &tools.config, &zone_name).0,
        }
    };

    // --- THE DEVICES ---
    // The devices given to its container (`docs/PERMISSIONS.md` §11.12): the
    // zone's `/dev` has none, and this launch gets the given ones bound in,
    // in its own mount namespace (`profile-run --device`), checking each
    // once more there. None for a launch with no container.
    let devices: Vec<crate::devices::Pass> = match container_name(&selection) {
        Some(name) if zone != UNCONFINED => {
            let grants: Vec<crate::devices::Grant> = crate::container::load(tools, &name)
                .map(|c| {
                    c.devices
                        .iter()
                        .filter_map(|d| crate::devices::Grant::parse(&d.value))
                        .collect()
                })
                .unwrap_or_default();
            if grants.is_empty() {
                Vec::new()
            } else {
                let nodes = crate::devices::host_nodes();
                crate::devices::granted(&nodes, &grants)
                    .into_iter()
                    .map(crate::devices::Node::pass)
                    .collect()
            }
        }
        _ => Vec::new(),
    };
    let device_args: Vec<String> = devices.iter().map(crate::devices::Pass::arg).collect();

    // --- X11 (docs/HERMETICITY.md §7, A) ---
    // The host's X server is out of reach in a zone. A container with the x11
    // permission gets a satellite of its own, started INSIDE wl-sandbox (the
    // wrapping below goes around this one), so it speaks to the compositor
    // through the restricted socket like the program does. A sandbox starts
    // its own satellite and is told about the permission instead.
    // Or the zone itself has x11: for someone who runs zones without
    // containers, Steam in a zone must open all the same. The container's
    // own word first, both ways (`x11::effective`, 2026-09-28): its `off`
    // refuses the zone's X server, which it could not before.
    let container_x11 = crate::x11::effective(
        container_name(&selection)
            .and_then(|name| crate::container::load(tools, &name))
            .and_then(|c| c.x11.map(|x11| x11.value)),
        zone != UNCONFINED && crate::x11::zone_setting(&tools.state, &tools.config, &zone_name).0,
    );
    let own_x11 = container_x11
        && zone != UNCONFINED
        && selection.sandbox == Sandbox::None
        && !cmd.is_empty();
    if own_x11 {
        let mut wrapped: Vec<OsString> = vec![
            tools.core.clone().into(),
            "x11-run".into(),
            "--xwayland".into(),
            tools.xwayland.clone().into(),
            "--".into(),
        ];
        wrapped.extend(cmd);
        cmd = wrapped;
    }

    // --- THE COMPOSITOR (docs/LEAK-MODEL.md §13) ---
    // Around everything, on the host: a zone has no compositor socket of its
    // own to make the restricted one from, and a sandbox would otherwise be
    // handed the unrestricted one. Into a zone always — the allowlist and
    // `wayland-sandbox off` are for unconfined launches only, where the
    // compositor's own socket is there anyway.
    let compositor_wrap: Option<Vec<OsString>> = (zone != UNCONFINED
        || wayland_sandbox_wanted(tools, &appbin, program_word(&selection.cmd), unasked))
    .then(|| {
        let app = if appbin.is_empty() {
            OsString::from("shell")
        } else {
            appbin.clone()
        };
        // An instance's sockets go by its key (`instance::key`): the one
        // directory of them its space has bound.
        let dir = match &instance_id {
            Some(id) => crate::instance::key(id),
            None if zone == UNCONFINED => crate::wl_sandbox::NO_ZONE.to_owned(),
            None => zone_name.clone(),
        };
        let mut wrap: Vec<OsString> = vec![
            tools.core.clone().into(),
            "wl-sandbox".into(),
            app,
            "--zone".into(),
            dir.into(),
        ];
        if !wayland_proxy_wanted(tools, &appbin, unasked) {
            wrap.push("--no-proxy".into());
        } else if zone != UNCONFINED {
            // The zone's frame around its windows (docs/WINDOW-FRAME.md
            // §0а): the colour, width and title mode as they are now, and
            // the title's text — the zone and the container as this
            // launch knows them; the switch that hides it is read by the
            // supervisor for each connection.
            // The container's colour, the zone's when it has none.
            let color = container_name(&selection)
                .and_then(|name| crate::container::load(tools, &name))
                .and_then(|c| c.frame_color.map(|c| c.value));
            let frame = crate::frame::Frame::of_launch(
                &tools.state,
                &tools.config,
                &zone_name,
                color.as_deref(),
            );
            wrap.push("--frame".into());
            wrap.push(frame.to_arg().into());
            let selector = selector_of(&selection, &container.profile);
            let shown = if container.ephemeral && selection.sandbox == Sandbox::None {
                // Its name is a random directory's: what it IS is what
                // the owner needs to read.
                "временный".to_owned()
            } else {
                crate::picker::container_label_in(tools, &selector.to_string_lossy())
            };
            wrap.push("--frame-title".into());
            wrap.push(crate::frame::title_text(&zone_name, &shown).into());
            wrap.push("--frame-switch".into());
            wrap.push(tools.config.clone().into());
        }
        // What becomes of the program's asking for the focus
        // (`crate::wl_focus`): its container's policy. `input`, the
        // default, is wl-sandbox's own and not said.
        let focus = crate::wl_focus::of_launch(tools, container_name(&selection).as_deref());
        if focus != crate::wl_focus::FocusPolicy::Input {
            wrap.push("--focus".into());
            wrap.push(focus.as_str().into());
        }
        wrap.push("--".into());
        wrap
    });

    if selection.sandbox != Sandbox::None {
        // The permissions belong to the launcher's id when there is one: the
        // shortcut says "discord" while the binary is called "Discord", and two
        // independent permission sets for one program is what taking the binary
        // name gave us. (`docs/GOTCHAS.md` §6)
        // Cleaned (`appbin` is the variable's value, sanitized): it becomes a
        // directory of the sandbox's permissions and the portals' app id.
        let fsid = appbin.clone();
        // Asked here, on the host: in the zone the answers are read-only.
        if env_nonempty(ENV_DRYRUN).is_none() {
            let named = match &selection.sandbox {
                Sandbox::Named(name) => Some(name.to_string_lossy().into_owned()),
                _ => None,
            };
            crate::fs_sandbox::settle_permissions(
                &tools.home,
                &fsid.to_string_lossy(),
                named.as_deref(),
                label.as_deref(),
                &tools.kdialog,
                &tools.window,
            );
        }
        let mut wrapped: Vec<OsString> = vec![
            tools.core.clone().into(),
            "fs-sandbox".into(),
            "--bwrap".into(),
            tools.bwrap.clone().into(),
            "--dbus-proxy".into(),
            tools.dbus_proxy.clone().into(),
            "--kdialog".into(),
            tools.kdialog.clone().into(),
            "--xwayland".into(),
            tools.xwayland.clone().into(),
            "--opener".into(),
            tools.opener.clone().into(),
            fsid,
        ];
        if let Sandbox::Named(name) = &selection.sandbox {
            wrapped.push("--name".into());
            wrapped.push(name.clone());
            // Directories of the real home granted to this sandbox
            // (`docs/CONTAINERS.md` §3.5); fs-sandbox checks them once more.
            if let Some(container) = crate::container::load(tools, &name.to_string_lossy()) {
                for path in container.paths {
                    wrapped.push("--bind-path".into());
                    wrapped.push(path.value.into());
                }
            }
        }
        if let Some(label) = &label {
            wrapped.push("--label".into());
            wrapped.push(label.clone().into());
        }
        if container_x11 {
            wrapped.push("--x11".into());
            wrapped.push("on".into());
        }
        // The cameras into its own /dev, where they are let.
        if camera {
            wrapped.push("--camera".into());
            wrapped.push("on".into());
        }
        // And the devices its container is given.
        for pass in &devices {
            wrapped.push("--device".into());
            wrapped.push(pass.path.clone().into());
        }
        // The network it runs in: to the portal its programs are the zone
        // (LEAK-MODEL §23). None for an unconfined launch — the host's own.
        if zone != UNCONFINED {
            wrapped.push("--zone".into());
            wrapped.push(zone.clone());
        }
        // In its container's instance, the container's /tmp — shared by its
        // launches, so that a single-instance program started again finds
        // the first copy (`fs_sandbox::Layout::share_tmp`). Never outside
        // one: an unconfined launch's /tmp is the host's.
        if instance_id.is_some() {
            wrapped.push("--share-tmp".into());
            wrapped.push("on".into());
        }
        wrapped.push("--".into());
        wrapped.extend(cmd);
        cmd = wrapped;
    }

    // --- 4. IS IT ALREADY RUNNING SOMEWHERE ELSE? ---
    // A file name in the registry, whoever set the variable: the broker
    // passes on what a zone asked for, and `/run/user/…` or `../..` would have
    // been a path to rewrite on the host.
    let appname = registry_key(appid_env.as_deref().unwrap_or(&appbin));
    let running = tools.state.join(".running");
    let regdir = running.join(container.key.as_os_str());
    let reg = regdir.join(&appname);
    // The same program under its BINARY name as well. The key above is the
    // launcher's id when there is one, and two ids for one single-instance
    // binary did not see each other: a Steam game's shortcut and Steam itself,
    // firefox and a firefox private-window entry, two Telegram variants. The
    // second launch handed its work to the process already up — in ITS network
    // — and the warning stayed silent. The binary index answers only "is it
    // running elsewhere"; which network a click on a running program goes to is
    // still decided by the id, because a multi-window program (a terminal) must
    // not be dragged into another's network by name. (`docs/GOTCHAS.md` §5)
    let binary = sanitize_app_id(app_word(&selection.cmd).unwrap_or(OsStr::new("")));
    let binreg = (!binary.is_empty() && binary != appname)
        .then(|| regdir.join(registry::BY_BINARY).join(&binary));
    let dryrun = env_nonempty(ENV_DRYRUN).is_some();

    let busy = match registry::lock(&regdir) {
        Ok(_guard) => {
            let live = |file: &Path| {
                registry::rewrite_live(file, &zone_name, |pid| registry::alive(&running, pid))
                    .unwrap_or_else(|e| {
                        eprintln!("реестр запусков {}: {e}", file.display());
                        None
                    })
            };
            let by_id = live(reg.as_path());
            let by_binary = binreg.as_deref().and_then(live);
            by_id.or(by_binary)
        }
        Err(e) => {
            eprintln!("реестр запусков {}: {e}", regdir.display());
            None
        }
    };

    if let Some(busy) = busy.filter(|_| !dryrun) {
        // Both `{busy}` and both `{zone}` get the same value, so a plain
        // replace does what the shell's five `%s` did.
        // The pretty label again: the warning is about a PROGRAM, and with two
        // of them launching the raw key does not say which one.
        let shown = label
            .clone()
            .unwrap_or_else(|| appname.to_string_lossy().into_owned());
        let template = if hands_over_a_link(&selection.cmd) {
            CONFLICT_URL_MESSAGE
        } else {
            CONFLICT_MESSAGE
        };
        let message = template
            .replace("{app}", &shown)
            .replace("{busy}", &busy)
            .replace("{zone}", &zone_name);
        if has_display() {
            let answer = Command::new(&tools.kdialog)
                .arg("--title")
                .arg("Программа уже запущена в другой сети")
                .arg("--dontagain")
                .arg(format!(
                    "vpn-zonesrc:conflict-{}",
                    appname.to_string_lossy()
                ))
                .arg("--warningcontinuecancel")
                .arg(&message)
                .stderr(Stdio::null())
                .status();
            match answer {
                Ok(status) if status.success() => {}
                // Cancelled: the person said no — over, and quietly.
                Ok(status) if status.code() == Some(KDIALOG_CANCEL) => return 0,
                // Not asked at all: kdialog could not be started, or ended
                // without an answer. The launch does not go on unasked — and
                // says so where it is seen: a launch from a menu has no
                // terminal, and "nothing happened" was all it showed.
                other => {
                    let why = match other {
                        Ok(status) => format!("окно вопроса закрылось без ответа ({status})"),
                        Err(e) => format!("окно вопроса не открылось ({e})"),
                    };
                    return not_started(
                        tools,
                        &shown,
                        &format!(
                            "{shown} уже запущена в сети «{busy}», а спросить не вышло: {why}"
                        ),
                    );
                }
            }
        } else {
            // No dialog to show from a terminal: warn and go on. Cancelling the
            // launch silently would be worse than warning about it.
            eprintln!("{message}");
        }
    }

    // Into a zone, the container's storage: the zone covers it, and
    // `profile-run` gives this one directory back in the launch's own mount
    // namespace. Made here first, on the host: a sandbox's before its first
    // launch, which the zone could not make.
    // (Before the zone or the instance is up: an instance keeps its
    // container's storage in reach only when it is there as it comes up.)
    let in_space = zone != UNCONFINED;
    let storage_dir: Option<PathBuf> = match (in_space, &selection.sandbox, &selection.container) {
        (true, Sandbox::Named(name), _) => {
            Some(crate::container::data_dir(tools, &name.to_string_lossy()))
        }
        (true, Sandbox::None, Container::Named(_)) if !container.ephemeral => {
            Some(container.dir.clone())
        }
        // A throwaway one's too — the zone covers them all, and gives back
        // only this launch's (`home_layer::THROWAWAY_STORAGE`). By its path
        // below the state directory as the zone knows it; one left in /tmp
        // from before the move is no zone's to keep.
        (true, Sandbox::None, Container::TmpNew | Container::TmpJoin(_)) => {
            let base = tools.state.join(THROWAWAY_DIR);
            let in_base = fs::canonicalize(&base)
                .is_ok_and(|b| container.dir.parent() == Some(b.as_path()))
                || container.dir.parent() == Some(base.as_path());
            container
                .dir
                .file_name()
                .filter(|_| in_base)
                .map(|name| base.join(name))
        }
        _ => None,
    };
    if let Some(dir) = storage_dir.as_ref().filter(|_| !dryrun) {
        if let Err(e) = fs::create_dir_all(dir) {
            eprintln!("не создать хранилище контейнера {}: {e}", dir.display());
            return EXIT_NOT_STARTED;
        }
    }

    // The real home in a pid namespace of the instance's own (stage 3,
    // `docs/THREAT-MODEL.md` X4): an application of the main home that runs
    // elsewhere already is not started beside it (`main_home_rival`).
    let main_home = matches!(
        (&selection.sandbox, &selection.container),
        (Sandbox::None, Container::Main | Container::MainNamed(_))
    );
    if let Some(id) = instance_id
        .as_deref()
        .filter(|_| main_home && appid_env.is_some() && !dryrun)
    {
        if let Some(word) = program_word(&selection.cmd) {
            if let Some(pid) = main_home_rival(&tools.state, id, word) {
                refuse(
                    tools,
                    &format!(
                        "«{}» уже работает с основным домом вне контейнера «{id}» (pid {pid}). \
                         У контейнера своё пространство процессов, и замок профиля, которым \
                         программа вроде браузера не даёт открыть его дважды, сквозь него не \
                         виден: второй процесс открыл бы тот же профиль. Закрой ту программу — \
                         или запусти эту в контейнере со своим домом",
                        basename(word).to_string_lossy()
                    ),
                );
                return 1;
            }
        }
    }
    // And the other way round (review 2026-09-28): the main home unconfined
    // is a host process, and the copy of the application in an instance of
    // the real home keeps a lock that names a pid of the instance's
    // namespace — on the host nobody, or somebody else: Chromium takes it for
    // a stale lock, deletes it and opens the profile the other copy has open
    // (`main_home_in_instance`). Only the host's side of cellward can see
    // both; a program started on the host past cellward is not seen here
    // (LEAK-MODEL §28).
    if instance_id.is_none() && main_home && appid_env.is_some() && !dryrun {
        if let Some(word) = program_word(&selection.cmd) {
            if let Some((pid, id, network)) = main_home_in_instance(tools, word) {
                refuse(
                    tools,
                    &format!(
                        "«{}» уже работает с основным домом в контейнере «{id}» (pid {pid}). \
                         У контейнера своё пространство процессов, и замок профиля, которым \
                         программа вроде браузера не даёт открыть его дважды, с хоста не \
                         виден: эта программа открыла бы тот же профиль. Закрой ту программу — \
                         или запусти эту там же, в сети «{network}»",
                        basename(word).to_string_lossy()
                    ),
                );
                return 1;
            }
        }
    }

    // --- 5. THE ZONE AND THE INSTANCE ---
    let network = match &instance_id {
        // Nothing to start and nothing to enter: the host's own network.
        None => Network::Unconfined,
        // The container's instance, up and ready in this network — its zone
        // and it started when they are not (`Type=notify`: `systemctl start`
        // returns when it is ready or failed; no clock of ours). Not in a dry
        // run: nothing is started for one. Refused where the person sees it
        // (stage 5): a zone of a previous build is no longer entered in its
        // stead, and a shortcut's stderr is read by nobody.
        Some(id) => {
            if !dryrun {
                if let Err(why) = up_instance(tools, id, &zone, &zone_name) {
                    refuse(tools, &why);
                    return 1;
                }
            }
            Network::Instance
        }
    };

    if dryrun {
        let shown: Vec<String> = compositor_wrap
            .iter()
            .flatten()
            .chain(cmd.iter())
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let shown_container = if container.profile.is_empty() {
            "основной".to_owned()
        } else {
            container.profile.to_string_lossy().into_owned()
        };
        println!(
            "зона {zone_name}, контейнер {shown_container}: {}",
            shown.join(" ")
        );
        return 0;
    }

    // --- 6. INTO THE REGISTRY AND INTO THE ZONE ---
    let selector = selector_of(&selection, &container.profile);
    // The start first, outside any directory's lock: a number that came
    // round again takes the dead launch's records out, under each lock.
    if let Err(e) = registry::note_start(&running, std::process::id() as i32, from_zone) {
        eprintln!("реестр запусков {}: {e}", running.display());
    }
    match registry::lock(&regdir) {
        Ok(_guard) => {
            for file in std::iter::once(&reg).chain(binreg.as_ref()) {
                if let Err(e) = registry::append(
                    file,
                    std::process::id() as i32,
                    &zone_name,
                    &selector.to_string_lossy(),
                ) {
                    eprintln!("реестр запусков {}: {e}", file.display());
                }
            }
        }
        Err(e) => eprintln!("реестр запусков {}: {e}", regdir.display()),
    }
    // Nothing of a zone around this one: on the record, with who and what.
    if network == Network::Unconfined {
        let program = selection
            .cmd
            .first()
            .map(|c| c.to_string_lossy().into_owned())
            .unwrap_or_default();
        if let Err(e) = crate::journal::append(
            &tools.state,
            "launch-unconfined",
            &[
                ("app", &*appname.to_string_lossy()),
                ("container", &*selector.to_string_lossy()),
                ("program", program.as_str()),
                ("pid", std::process::id().to_string().as_str()),
            ],
        ) {
            eprintln!(
                "журнал {}: {e}",
                tools.state.join(crate::journal::FILE).display()
            );
        }
    }

    // The mark descendants are recognised by: a program started in a zone that
    // tries to open something else has that launch delegated outwards (step 1).
    //
    // An unconfined launch is marked only when it ends up in a namespace of its
    // own — a container's user namespace or a sandbox. From there `nsenter`
    // into a zone fails exactly as it does from inside a zone, so the
    // descendants have to delegate too. A plain unconfined launch is an ordinary
    // host process and must stay unmarked, or everything it starts would take
    // a detour through systemd for nothing.
    let namespaced = !container.dir.as_os_str().is_empty() || selection.sandbox != Sandbox::None;
    if network != Network::Unconfined || namespaced {
        std::env::set_var(ENV_CURRENT, &zone);
    }
    // No host X server in a zone, and no name of one either: toolkits that see
    // DISPLAY try X first and fail instead of using Wayland. A container with
    // the permission gets its own display from x11-run.
    if network != Network::Unconfined {
        std::env::remove_var("DISPLAY");
        std::env::remove_var("XAUTHORITY");
        // The compositors' IPC is not in a zone (LEAK-MODEL §13); its names
        // are not either.
        for var in COMPOSITOR_IPC_VARS {
            std::env::remove_var(var);
        }
        // Input methods through their portals only (review 2026-09-25): the
        // daemons' own interfaces run and fetch things on the host, and the
        // zone's bus and mount namespace keep them out
        // (`zone::SESSION_BUS_RULES`, `zone::hide_input_methods`). libibus
        // takes its portal only in Flatpak or when told so; fcitx5's clients
        // fall back to theirs by themselves.
        std::env::set_var("IBUS_USE_PORTAL", "1");
    }

    // The caller's working directory, which entering a space would lose. A
    // directory that has been removed under us is no reason not to start:
    // `profile-run` falls back to `$HOME` anyway.
    let cwd = std::env::current_dir().unwrap_or_else(|_| tools.home.clone());
    // No command at all is a shell inside the zone — what `nsenter` used to
    // start by itself, before `profile-run` stood between it and the program.
    let cmd = if cmd.is_empty() && network != Network::Unconfined {
        vec![std::env::var_os("SHELL")
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| OsString::from("/bin/sh"))]
    } else {
        cmd
    };
    let (trust, nss_home, trust_extra) = trust_of(tools, &selection);
    // A layer container's grants: the paths it writes into the real home.
    let shares: Vec<PathBuf> = match (&selection.sandbox, &selection.container) {
        (Sandbox::None, Container::Named(name)) => {
            crate::container::load(tools, &name.to_string_lossy())
                .map(|c| c.paths.into_iter().map(|p| p.value).collect())
                .unwrap_or_default()
        }
        _ => Vec::new(),
    };
    let exec = entry_argv(
        &Entry {
            unshare: &tools.unshare,
            core: &tools.core,
            systemctl: &tools.systemctl,
            zone: &zone,
            network,
            instance: instance_id.as_deref(),
            dir: &container.dir,
            ephemeral: container.ephemeral,
            regdir: &regdir,
            // The record written above: this process's pid, which the
            // `exec` below keeps, and its start time.
            registered: {
                let pid = std::process::id() as i32;
                crate::sys::start_time(pid).map(|start| crate::profile::Registered { pid, start })
            },
            cwd: &cwd,
            trust: trust.as_deref(),
            nss_home: nss_home.as_deref(),
            trust_extra: &trust_extra,
            certutil: &tools.certutil,
            bwrap: &tools.bwrap,
            shares: &shares,
            own_x11,
            camera,
            devices: &device_args,
            storage: storage_dir.as_deref(),
        },
        cmd,
    );
    // Only `direct` with no container can get here with nothing at all: into a
    // space an empty command is a shell there, which is a perfectly good
    // thing to want, but the host has no such fallback.
    if exec.is_empty() {
        eprintln!("нечего запускать");
        return 1;
    }
    let through_wl_sandbox = compositor_wrap.is_some();
    let exec = match compositor_wrap {
        Some(mut wrapped) => {
            wrapped.extend(exec);
            wrapped
        }
        None => {
            // No `wl-sandbox` on the way to say the program opened a window:
            // told that no word will come — the picker learns nothing.
            crate::wl_sandbox::no_word();
            exec
        }
    };

    // A launch into a zone's own namespaces used to be checked here, as close
    // to the `exec` as it gets: its zone process in OUR network namespace was
    // not the zone. No launch goes there since stage 5; an instance's network
    // is checked by `container-enter`, from its pid 1, and by `profile-run`
    // from inside (`profile::ENV_EXPECT_NETNS`).

    // The picker's pipe, given on to `wl-sandbox` alone, as the very last
    // thing before its exec (`wl_sandbox::pass_opened_on`): nothing this
    // process starts on the way has it.
    if through_wl_sandbox {
        crate::wl_sandbox::pass_opened_on();
    }
    let e = exec_command(&exec);
    eprintln!("не удалось запустить {}: {e}", exec[0].to_string_lossy());
    EXIT_NOT_STARTED
}

/// Where a launch runs, as far as its command line is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// A container's instance that is up (`crate::instance`), entered by
    /// `container-enter`, which finds it again by its id
    /// (`Entry::instance`) — never by a number handed down.
    Instance,
    /// The host's own network: there is no namespace to enter.
    Unconfined,
}

/// Everything the last command line of a launch depends on.
#[derive(Debug, Clone, Copy)]
pub struct Entry<'a> {
    pub unshare: &'a Path,
    pub core: &'a Path,
    /// What starts an instance that stopped between this launch's look and
    /// `container-enter`'s (`Network::Instance`).
    pub systemctl: &'a Path,
    pub zone: &'a OsStr,
    pub network: Network,
    /// The instance's id, for `Network::Instance`.
    pub instance: Option<&'a str>,
    /// The container's layer directory; empty for the main profile.
    pub dir: &'a Path,
    pub ephemeral: bool,
    pub regdir: &'a Path,
    /// This launch's own record in `regdir`: its pid and its start time.
    /// Passed to a throwaway container's `profile-run --registered`, which
    /// tells it from the other tenants when its program exits (J9).
    pub registered: Option<crate::profile::Registered>,
    /// The directory the program is to start in: the caller's.
    pub cwd: &'a Path,
    /// The container's directory of trusted certificates, when it has one
    /// (`docs/CERTIFICATES.md`). Like a layer, it needs a mount namespace.
    pub trust: Option<&'a Path>,
    /// The home the program will see when that is not `$HOME`: a named
    /// sandbox's, on disk. Only meaningful together with `trust`.
    pub nss_home: Option<&'a Path>,
    /// Directories of certificates declared in Nix, besides `trust`.
    pub trust_extra: &'a [PathBuf],
    pub certutil: &'a Path,
    pub bwrap: &'a Path,
    /// Paths of the real home granted to a layer container
    /// (`container grant`): written through its layer (`--share`).
    pub shares: &'a [PathBuf],
    /// The container's storage directory, for a launch into an instance:
    /// the instance covers container storage, and `profile-run --storage`
    /// gives this one directory back in the launch's own mount namespace,
    /// from the instance's keep (`home_layer::KEPT_STORAGE`).
    pub storage: Option<&'a Path>,
    /// An X server of the launch's own (`x11-run`): its sockets' directory
    /// too (`profile-run --own-x11`).
    pub own_x11: bool,
    /// The host's cameras let this launch in an instance: bound into its
    /// own mount namespace (`profile-run --camera`).
    pub camera: bool,
    /// The devices its container is given, as `profile-run --device` takes
    /// them (`devices::Pass::arg`): bound into its own mount namespace.
    pub devices: &'a [String],
}

/// The command line `run` finally `exec`s: the namespaces, the container, then
/// the (already wrapped) command.
///
/// A pure function, because every word of it was paid for:
///
/// * **into a container's instance** (every network but `unconfined`, since
///   stage 5 of the container design of 2026-09-27): `vpn-zone-core
///   container-enter --instance <id>` (`crate::enter`), which joins the
///   instance's namespaces from its pid 1 and gives the launch a mount
///   namespace of its own, a slave of the instance's, with the capabilities
///   `profile-run` mounts the container with and sheds the session's groups
///   with (`docs/GOTCHAS.md` §1). Never a zone's own namespaces any more:
///   `nsenter` into a zone's app namespace was the way until stage 5, and a
///   zone of a previous build is now refused instead (`run`);
/// * **`direct` with a container**: there is no zone to borrow a user namespace
///   from, so `unshare` makes one — `--map-current-user` maps the user onto
///   itself (the program keeps its uid and sees `$HOME` as usual) and
///   `--keep-caps` carries the capabilities of that namespace across the exec,
///   for the same reason as above: `profile-run` needs CAP_SYS_ADMIN over the
///   new mount namespace to stack the layers, and drops it before the program
///   starts. No network namespace is created: `direct` IS the host's network;
/// * **`direct` without a container**: nothing at all. The program is a host
///   process like any other, and the command is exec'd as it is (still wrapped
///   in `wl-sandbox`/`fs-sandbox`, which are part of `cmd`).
///
/// **Everything that enters a namespace ends in `profile-run --cwd`**, the
/// main profile included (with an empty layer directory, which stacks
/// nothing). Joining a mount namespace leaves a process in `/` — a terminal
/// started into a zone opened in `/` when `nsenter` did it — and a chdir
/// before the mounts is no cure: with a container the overlay is mounted over
/// `$HOME` afterwards, so the chdir has to come after the mounts, and a
/// directory that does not exist in the space's mount tree must not stop the
/// launch. `profile-run` makes the chdir after mounting and falls back to
/// `$HOME` and `/`. (`docs/GOTCHAS.md` §1)
pub fn entry_argv(entry: &Entry<'_>, cmd: Vec<OsString>) -> Vec<OsString> {
    // Something has to be mounted for this launch: a container's layer, or
    // the trust layer's bundle.
    let container =
        !entry.dir.as_os_str().is_empty() || entry.trust.is_some() || entry.storage.is_some();
    let mut exec: Vec<OsString> = Vec::new();
    // Into a space of ours — an instance's —, with its own `/dev` and
    // covers: what `profile-run` gives the launch from there.
    let in_space = entry.network == Network::Instance;
    // Does the program end up in a mount namespace other than ours?
    let entered = container || in_space;
    // A throwaway container's instance erases it when its last program ends
    // (`zone::keep`): `profile-run` outlives nothing then, and asks nobody.
    let ephemeral = entry.ephemeral && entry.network != Network::Instance;
    match entry.network {
        // Into a container's instance: by its id, and `container-enter`
        // gives the launch a mount namespace of its own, a slave of the
        // instance's, whatever it mounts (`crate::enter`).
        Network::Instance => {
            exec.push(entry.core.into());
            exec.push("container-enter".into());
            exec.push("--instance".into());
            exec.push(entry.instance.unwrap_or_default().into());
            // The network asked for: an instance started meanwhile in
            // another one is not entered (stage 2).
            exec.push("--network".into());
            exec.push(entry.zone.into());
            exec.push("--systemctl".into());
            exec.push(entry.systemctl.into());
            exec.push("--".into());
        }
        Network::Unconfined if container => {
            exec.push(entry.unshare.into());
            exec.extend([
                "--user".into(),
                "--map-current-user".into(),
                "--keep-caps".into(),
                "--mount".into(),
                "--propagation".into(),
                "private".into(),
                "--".into(),
            ]);
        }
        Network::Unconfined => {}
    }
    if entered {
        exec.push(entry.core.into());
        exec.push("profile-run".into());
        exec.push("--cwd".into());
        exec.push(entry.cwd.into());
        // Only a throwaway container asks who else is in it.
        if let Some(me) = entry.registered.filter(|_| ephemeral) {
            exec.push("--registered".into());
            exec.push(me.arg().into());
        }
        if entry.camera && in_space {
            exec.push("--camera".into());
        }
        if entry.own_x11 && in_space {
            exec.push("--own-x11".into());
        }
        if in_space {
            for device in entry.devices {
                exec.push("--device".into());
                exec.push(device.into());
            }
        }
        if let Some(path) = entry.storage {
            exec.push("--storage".into());
            exec.push(path.into());
        }
        if let Some(trust) = entry.trust {
            exec.push("--trust".into());
            exec.push(trust.into());
            exec.push("--certutil".into());
            exec.push(entry.certutil.into());
            exec.push("--bwrap".into());
            exec.push(entry.bwrap.into());
            if let Some(home) = entry.nss_home {
                exec.push("--nss-home".into());
                exec.push(home.into());
            }
            for extra in entry.trust_extra {
                exec.push("--trust-extra".into());
                exec.push(extra.into());
            }
        }
        // Only with a layer: the main profile has the real home anyway.
        if !entry.dir.as_os_str().is_empty() {
            for share in entry.shares {
                exec.push("--share".into());
                exec.push(share.into());
            }
        }
        exec.push(entry.dir.into());
        exec.push(entry.zone.into());
        exec.push(if ephemeral { "1" } else { "0" }.into());
        exec.push(entry.regdir.into());
        exec.push("--".into());
    }
    exec.extend(cmd);
    exec
}

/// The instance an offline launch runs in (`crate::instance::id_of`): its
/// container's, the main home's, a throwaway's — a throwaway sandbox gets
/// one of its own, named by this launch. Refused: an id that has no unit's
/// name (a container's name too long for systemd).
fn instance_of(
    tools: &Tools,
    selection: &Selection,
    container: &ResolvedContainer,
    network: &str,
) -> Result<String, String> {
    use crate::container::Home;
    use crate::instance::Of;
    let none = || "у этого запуска не может быть экземпляра контейнера".to_owned();
    let named = |name: &OsString, home: Home| -> Result<String, String> {
        let name = name.to_str().ok_or_else(none)?;
        let asks = crate::container::load(tools, name)
            .is_some_and(|c| c.network.value == crate::container::Network::Ask);
        crate::instance::id_of(Of::Container { name, home, asks }, network).ok_or_else(none)
    };
    let id = match (&selection.sandbox, &selection.container) {
        (Sandbox::Named(name), _) => named(name, Home::Private)?,
        (Sandbox::None, Container::Named(name)) => named(name, Home::Layer)?,
        (Sandbox::None, Container::MainNamed(name)) => named(name, Home::Main)?,
        (Sandbox::None, Container::TmpNew | Container::TmpJoin(_)) => {
            let layer = container
                .dir
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or_default();
            crate::instance::id_of(Of::Throwaway(layer), network).ok_or_else(none)?
        }
        (Sandbox::Throwaway, _) => {
            let pid = std::process::id() as i32;
            let unique = format!("{pid}-{}", crate::sys::start_time(pid).unwrap_or(0));
            crate::instance::id_of(Of::ThrowawaySandbox(&unique), network).ok_or_else(none)?
        }
        (Sandbox::None, Container::Main) => {
            crate::instance::id_of(Of::Main, network).ok_or_else(none)?
        }
    };
    if crate::instance::unit_name(&id).is_none() {
        return Err(format!(
            "у контейнера «{id}» слишком длинное имя для юнита systemd — переименуй контейнер"
        ));
    }
    Ok(id)
}

/// Why a launch cannot run in an instance through `zone`, which is up: it
/// carries none — no bridge (`bridge::carries`: by the socket's presence,
/// never by a build's name). Its holder of a previous build, which an update
/// left running (`X-SwitchMethod=keep-old`), or one whose bridge did not
/// open. Until stage 5 of the container design (2026-09-28) such a zone was
/// entered in the instance's stead, into its own namespaces; now nothing is
/// launched there at all, and the person is told the way out — the zone's
/// restart, which this build's holder comes up from. `None`: it carries.
pub fn no_bridge_refusal(state: &Path, zone: &OsStr) -> Option<String> {
    if crate::bridge::carries(&state.join(zone)) {
        return None;
    }
    let zone = zone.to_string_lossy();
    Some(format!(
        "зона {zone} не везёт контейнеры: она поднята прошлой сборкой или её мост не \
         открылся (journalctl --user -u 'vpn-zone@{zone}.service'). В пространство самой \
         зоны программы больше не запускаются — перезапусти её: cellward restart {zone}"
    ))
}

/// Instance `id`, for a person: its container's name, the id itself for
/// the main home's and a throwaway's.
fn instance_shown(id: &str) -> String {
    crate::instance::container_of(id).unwrap_or(id).to_owned()
}

/// Whether instance `id` came up hermetic: its note says so
/// (`instance::SETTINGS`); a note that does not say, or none, is not.
fn came_up_hermetic(state: &Path, id: &str) -> bool {
    let note = fs::read_to_string(crate::instance::dir(state, id).join(crate::instance::SETTINGS))
        .unwrap_or_default();
    crate::hermetic::applied_in(&note, "hermetic") == Some(true)
}

/// The network instance `id` runs in now, where it is up.
fn instance_network(state: &Path, id: &str) -> Option<String> {
    crate::instance::up(state, id)?;
    fs::read_to_string(crate::instance::dir(state, id).join(crate::instance::NETWORK))
        .ok()
        .map(|text| text.trim().to_owned())
}

/// Why instance `id` may not take a launch into `zone`, which the person
/// locked (`cellward lock`), if it may not (review 2026-09-28). The lock is
/// kept by the broker, the one door out of a hermetic space; an instance
/// that is not hermetic has `systemd --user` in reach, and a program there
/// starts anything anywhere without asking — the lock would say what it
/// does not hold. Judged by what the instance came up with where it runs in
/// that zone now, by what it would come up with there otherwise.
pub fn lock_refusal(tools: &Tools, id: &str, zone: &str) -> Option<String> {
    let dir = tools.state.join(zone);
    if zone == UNCONFINED || !dir.join(NO_ESCAPE).exists() {
        return None;
    }
    let running = instance_network(&tools.state, id).as_deref() == Some(zone);
    let hermetic = if running {
        came_up_hermetic(&tools.state, id)
    } else {
        crate::hermetic::value_for(
            &dir,
            &tools.config,
            zone,
            &crate::instance::who_of(id),
            "hermetic",
        )
        .0
    };
    if hermetic {
        return None;
    }
    let shown = instance_shown(id);
    let how = match crate::instance::who_of(id) {
        crate::origin::Who::Container(name) => {
            format!("включи его герметичность: cellward container set {name} hermetic on")
        }
        _ => format!("включи герметичность сети: cellward hermetic {zone} on"),
    };
    let restart = if running {
        format!(
            "; работающий экземпляр держит свою, пока его программы не закрыты: cellward \
             container stop {id}"
        )
    } else {
        String::new()
    };
    Some(format!(
        "зона {zone} заперта (cellward lock), а контейнер «{shown}» в ней не герметичен: замок \
         держится только в герметичном — с systemd --user программа запустила бы что угодно \
         мимо него. Отопри зону (cellward unlock {zone}) или {how}{restart}"
    ))
}

/// What a locked zone's lock does not hold (review 2026-09-28,
/// [`lock_refusal`]): the instances running in `zone` that came up not
/// hermetic, then the containers bound to it that would come up so there —
/// each by name, once, with whether it runs. Its own programs launched
/// there are refused; what runs is named by `cellward lock`, `status`
/// (`networks[].lock_not_held_by`) and `doctor` (`lock`).
pub fn lock_not_held_by(tools: &Tools, zone: &str) -> Vec<(String, bool)> {
    let mut out: Vec<(String, bool)> = Vec::new();
    if zone == UNCONFINED {
        return out;
    }
    for i in crate::instance::running(&tools.state) {
        if i.network == zone && !came_up_hermetic(&tools.state, &i.id) {
            let name = instance_shown(&i.id);
            if !out.iter().any(|(n, _)| *n == name) {
                out.push((name, true));
            }
        }
    }
    let dir = tools.state.join(zone);
    let bound = crate::container::Network::Named(zone.to_owned());
    for c in crate::container::load_all(tools) {
        if c.network.value != bound || out.iter().any(|(n, _)| *n == c.name) {
            continue;
        }
        let who = crate::origin::Who::Container(c.name.clone());
        if !crate::hermetic::value_for(&dir, &tools.config, zone, &who, "hermetic").0 {
            out.push((c.name.clone(), false));
        }
    }
    out
}

/// Every process's children, by their `PPid`, read once.
fn process_children() -> std::collections::HashMap<i32, Vec<i32>> {
    let mut children: std::collections::HashMap<i32, Vec<i32>> = Default::default();
    for entry in fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<i32>().ok())
        else {
            continue;
        };
        if let Some(parent) = crate::sys::parent_of(pid) {
            children.entry(parent).or_default().push(pid);
        }
    }
    children
}

/// Whether `root` or a process below it is in the user namespace `userns`
/// (`user:[…]`, as `/proc/<pid>/ns/user` reads).
fn tree_in_userns(
    children: &std::collections::HashMap<i32, Vec<i32>>,
    root: i32,
    userns: &Path,
) -> bool {
    let mut todo = vec![root];
    let mut seen = std::collections::HashSet::new();
    while let Some(at) = todo.pop() {
        if !seen.insert(at) {
            continue;
        }
        if fs::read_link(format!("/proc/{at}/ns/user")).ok().as_deref() == Some(userns) {
            return true;
        }
        if let Some(below) = children.get(&at) {
            todo.extend(below);
        }
    }
    false
}

/// Why container `name` may not start in its instance in `zone` (stage 2):
/// live launches of it run in the zone's own namespaces — from before the
/// switch-over, or into this zone when it was of a previous build. Beside
/// them its instance would be a second world of one home and one profile,
/// whose programs' locks and sockets do not see each other's.
fn zone_launches_refusal(tools: &Tools, name: &str, zone: &str) -> Option<String> {
    if zone == OFFLINE {
        return None;
    }
    let container = crate::container::load(tools, name)?;
    let records: Vec<(String, registry::Record)> =
        crate::container::live_records(tools, &container)
            .into_iter()
            .filter(|(_, record)| record.zone == zone)
            .collect();
    if records.is_empty() {
        return None;
    }
    let pid = cli::zone_pid(&tools.state, OsStr::new(zone))?;
    let userns = fs::read_link(format!("/proc/{pid}/ns/user")).ok()?;
    let children = process_children();
    let apps: Vec<String> = records
        .iter()
        .filter(|(_, record)| tree_in_userns(&children, record.pid, &userns))
        .map(|(app, _)| app.clone())
        .collect();
    if apps.is_empty() {
        return None;
    }
    Some(format!(
        "программы контейнера «{name}» ({}) работают в пространстве самой зоны {zone} — \
         запущены до обновления или в зону прошлой сборки. Рядом с ними контейнер в своём \
         пространстве не запускается: закрой их и запусти снова",
        apps.join(", ")
    ))
}

/// The launch's instance `id` up and ready in `zone` (stage 2): its zone up
/// first — started when it is down, as a launch into a zone always did —
/// and carrying instances; the instance started when it is not up, asked
/// for this network (`instance::ask_network`); one that runs in another
/// network refused (`docs/CONTAINERS.md` I2) — before its start and after,
/// for a launch that asked otherwise meanwhile.
fn up_instance(tools: &Tools, id: &str, zone: &OsStr, zone_name: &str) -> Result<(), String> {
    let running_in = || {
        fs::read_to_string(crate::instance::dir(&tools.state, id).join(crate::instance::NETWORK))
            .map(|text| text.trim().to_owned())
            .unwrap_or_default()
    };
    let elsewhere = |running: String| {
        format!(
            "контейнер {id} уже работает в сети «{running}», а запуск просит «{zone_name}»: \
             контейнер не бывает в двух сетях сразу — закрой его программы \
             (cellward container stop {id}) или запусти в «{running}»"
        )
    };
    if crate::instance::up(&tools.state, id).is_some() {
        let running = running_in();
        if running != zone_name {
            return Err(elsewhere(running));
        }
    }
    if zone_name != OFFLINE {
        let mut pid = cli::zone_up(&tools.state, zone);
        if pid.is_none() {
            // Returns once the zone is ready or failed (`Type=notify`), and
            // says so while it waits (`cli::start_zone`).
            let _ = cli::start_zone(tools, zone, true);
            pid = cli::zone_up(&tools.state, zone);
        }
        if pid.is_none() {
            return Err(format!("зона {zone_name} не поднимается"));
        }
        if let Some(why) = no_bridge_refusal(&tools.state, zone) {
            return Err(why);
        }
    }
    if crate::instance::up(&tools.state, id).is_none() {
        crate::instance::ask_network(&tools.state, id, zone_name)
            .map_err(|e| format!("контейнер {id}: не попросить сеть {zone_name} ({e})"))?;
        let unit = crate::instance::unit_name(id).unwrap_or_default();
        let _ = cli::systemctl_unit(tools, "start", OsStr::new(&unit));
        if crate::instance::up(&tools.state, id).is_none() {
            return Err(format!(
                "контейнер {id} не поднимается (journalctl --user -u '{unit}')"
            ));
        }
    }
    let running = running_in();
    if running != zone_name {
        return Err(elsewhere(running));
    }
    // Once more by what it came up with (review 2026-09-28): it may have
    // come up meanwhile, by another launch, with settings of before.
    if let Some(why) = lock_refusal(tools, id, zone_name) {
        return Err(why);
    }
    Ok(())
}

/// Why this launch may not use its container in `zone`, if it may not.
fn identity_refusal(tools: &Tools, selection: &Selection, zone: &str) -> Option<String> {
    if let (Sandbox::None, Container::TmpJoin(dir)) = (&selection.sandbox, &selection.container) {
        return throwaway_join_refusal(tools, dir, zone);
    }
    let container = crate::container::load(tools, &container_name(selection)?)?;
    let running = crate::container::running_network(tools, &container);
    crate::container::refusal(&container, zone, running.as_deref())
}

/// A throwaway container is joined while it runs, and in the network it
/// runs in, only. Its name is in `.running`, which every zone reads: a
/// request naming another zone's would carry that session — its cookies,
/// its logins — into another network, and one whose programs are gone
/// holds what a launch that did not end cleanly left, nobody's to join.
fn throwaway_join_refusal(tools: &Tools, dir: &Path, zone: &str) -> Option<String> {
    let closed = || {
        Some(format!(
            "временного контейнера {} больше нет: присоединиться нельзя",
            dir.display()
        ))
    };
    let Some(real) = fs::canonicalize(dir).ok() else {
        return closed();
    };
    // Not one of ours at all: `resolve_container` says so, in its words.
    if !our_throwaway(tools, &real) {
        return None;
    }
    let Some(name) = real.file_name().map(OsStr::to_owned) else {
        return closed();
    };
    let running = tools.state.join(".running");
    let records =
        registry::live_records(&running.join(&name), &|pid| registry::alive(&running, pid));
    if records.is_empty() {
        return closed();
    }
    records
        .into_iter()
        .map(|(_, r)| r.zone)
        .find(|busy| busy != zone)
        .map(|busy| {
            format!(
                "временный контейнер {} работает в сети «{busy}», а запуск просит «{zone}»: \
                 контейнер не бывает в двух сетях сразу",
                name.to_string_lossy()
            )
        })
}

/// The name of the container a resolved launch runs in, whatever its home;
/// `None` for the main profile, a throwaway one and a temporary one.
pub fn container_name(selection: &Selection) -> Option<String> {
    match (&selection.sandbox, &selection.container) {
        (Sandbox::Named(name), _)
        | (Sandbox::None, Container::Named(name) | Container::MainNamed(name)) => {
            Some(name.to_string_lossy().into_owned())
        }
        _ => None,
    }
}

/// One launch, one container (`docs/PERMISSIONS.md` §11.7): the name —
/// `--container`, and the words from before, `--profile` and `--sandbox` —
/// read as the container it is now, its kind of home deciding how it is
/// mounted. Nothing is made or moved here: that is [`prepare_selection`],
/// after the network is checked.
///
/// A layer and a home of its own together, or a named container with a
/// throwaway one, are two containers: refused. `--sandbox` (and `sb:`) asks
/// for a home of its own and gets nothing else: a name that is a layer or the
/// main home is refused, not given the real home without a word; a missing
/// one is made at the launch, as a sandbox always was. The others refuse a
/// container that is not there, and one whose move to this layout has not
/// finished (its data are not where the launch would look).
pub fn resolve_selection(tools: &Tools, selection: Selection) -> Result<Selection, String> {
    use crate::container::Home;
    let (asked, sandbox_asked) = match (&selection.container, &selection.sandbox) {
        (Container::Main, Sandbox::None | Sandbox::Throwaway)
        | (Container::TmpNew | Container::TmpJoin(_), Sandbox::None) => return Ok(selection),
        (Container::Named(name) | Container::MainNamed(name), Sandbox::None) => {
            (name.to_string_lossy().into_owned(), false)
        }
        (Container::Main, Sandbox::Named(name)) => {
            // A stale `--sandbox work` is the sandbox that became `work-sb`.
            let name = crate::container::sandbox_name(tools, &name.to_string_lossy())
                .unwrap_or_else(|| name.to_string_lossy().into_owned());
            (name, true)
        }
        _ => {
            return Err(
                "один запуск — один контейнер: слой над домом (--profile, --tmp-profile) и \
                 свой дом (--sandbox, --fs-sandbox) вместе больше не собираются"
                    .to_owned(),
            )
        }
    };
    let Some(name) = crate::container::canonical(tools, &asked) else {
        return Err(format!("«{asked}» не может быть именем контейнера"));
    };
    if crate::container::move_pending(tools, &name) {
        return Err(format!(
            "данные контейнера {name} ещё не перенесены в новый каталог (см. сообщение \
             переноса выше) — запуск остановлен, чтобы не открыть его с пустым домом"
        ));
    }
    let home = match crate::container::load(tools, &name) {
        Some(c) if sandbox_asked && c.home != Home::Private => {
            return Err(format!(
                "«{name}» — не контейнер со своим домом, а {}: запуск со своим домом \
                 (--sandbox) в нём остановлен. Запустить в нём: --container {name}",
                c.home.label()
            ))
        }
        Some(c) => c.home,
        None if sandbox_asked => Home::Private,
        None => {
            return Err(format!(
                "контейнера {name} нет — создай: cellward container create {name}"
            ))
        }
    };
    let name = OsString::from(&name);
    let (container_axis, sandbox) = match home {
        Home::Layer => (Container::Named(name), Sandbox::None),
        Home::Private => (Container::Main, Sandbox::Named(name)),
        Home::Main => (Container::MainNamed(name), Sandbox::None),
    };
    Ok(Selection {
        container: container_axis,
        sandbox,
        ..selection
    })
}

/// Make a resolved launch's container ready, once the launch may go: a home
/// of its own asked for and not there yet is made; the data are made the kind
/// the settings say, the other kind's set aside — never under programs of
/// the container that run, whose home would change under them (a change of
/// kind in Nix does not ask).
pub fn prepare_selection(tools: &Tools, selection: &Selection) -> Result<(), String> {
    let Some(name) = container_name(selection) else {
        return Ok(());
    };
    let container = match crate::container::load(tools, &name) {
        Some(c) => c,
        None => crate::container::create(tools, &name, crate::container::Home::Private)?,
    };
    if !crate::container::data_ready(&container) {
        if let Some(busy) = crate::container::running_network(tools, &container) {
            return Err(format!(
                "у контейнера {name} сменился вид дома, а его программы работают (в сети \
                 {busy}) — закрой их: дом сменится при следующем запуске"
            ));
        }
    }
    crate::container::prepare_data(&container)
}

/// Say no, where the person can see it: a dialog when there is a graphical
/// session (a launcher entry's stderr is read by nobody), and stderr always.
/// What kdialog's `--warningcontinuecancel` and its kin say for "cancel"
/// (and for the window closed).
const KDIALOG_CANCEL: i32 = 2;

/// A launch that ends before its program started, for a reason the person
/// should see ([`EXIT_NOT_STARTED`]): said on stderr, and — a launch from a
/// menu has no terminal to say it on — to the picker that watches it
/// (`wl_sandbox::not_started_word`), or, with none, in a notification that
/// stays until it is read, in a graphical session.
fn not_started(tools: &Tools, program: &str, why: &str) -> u8 {
    eprintln!("{why}");
    if !crate::wl_sandbox::not_started_word(why) && has_display() {
        crate::dialog::notify(
            &tools.notify_send,
            Some("critical"),
            "0",
            &format!("{program} не запущена"),
            why,
        );
    }
    EXIT_NOT_STARTED
}

fn refuse(tools: &Tools, why: &str) {
    eprintln!("{why}");
    if has_display() {
        let _ = Command::new(&tools.kdialog)
            .arg("--title")
            .arg("Запуск остановлен")
            .arg("--sorry")
            .arg(why)
            .stderr(Stdio::null())
            .status();
    }
}

/// The trusted certificates of a launch: the container's own directory, the
/// directories declared in Nix, and the home they belong to.
///
/// They follow the home the program SEES (`docs/CERTIFICATES.md` §3.1): a
/// named sandbox's (its home on disk is where its NSS databases are), otherwise
/// the data container's. A throwaway sandbox has no identity to trust anything
/// with, and the main profile is the host's — neither ever gets a layer. The
/// layer is switched on by the directory existing, even empty: an emptied one
/// still takes stale entries out of the container's NSS databases.
fn trust_of(
    tools: &Tools,
    selection: &Selection,
) -> (Option<PathBuf>, Option<PathBuf>, Vec<PathBuf>) {
    let (selector, nss_home) = match (&selection.sandbox, &selection.container) {
        (Sandbox::Named(name), _) => {
            let name = name.to_string_lossy().into_owned();
            let home = crate::container::data_dir(tools, &name).join("home");
            (name, Some(home))
        }
        (Sandbox::Throwaway, _) => return (None, None, Vec::new()),
        (Sandbox::None, Container::Named(name)) => (name.to_string_lossy().into_owned(), None),
        // The main home's certificates are the host's: none of its own.
        (Sandbox::None, _) => return (None, None, Vec::new()),
    };
    let Some(container) = crate::container::load(tools, &selector) else {
        return (None, None, Vec::new());
    };
    let dir = container.trust_dir();
    if !container.declared_trust.is_empty() {
        // Declared certificates still need the container's own directory: the
        // bundle is written to a tmpfs laid over it.
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!("не создать {}: {e}", dir.display());
        }
    }
    let active = dir.is_dir();
    (active.then_some(dir), nss_home, container.declared_trust)
}

/// A locked zone: run the command here, without the network the caller asked
/// for.
fn run_locked(current: &OsStr, argv: &[OsString]) -> u8 {
    let asked = argv
        .first()
        .map(|z| z.to_string_lossy().into_owned())
        .unwrap_or_else(|| "?".to_owned());
    eprintln!(
        "зона {} заперта: запускаем в ней же, а не в «{asked}»",
        current.to_string_lossy()
    );
    let cmd = strip_selection(argv);
    if cmd.is_empty() {
        eprintln!("нечего запускать");
        return 1;
    }
    let e = exec_command(&cmd);
    eprintln!("не удалось запустить {}: {e}", cmd[0].to_string_lossy());
    EXIT_NOT_STARTED
}

/// The network with no network: a directory with the `offline` marker and
/// nothing else — there is no config to keep (`docs/GOTCHAS.md` §2). It
/// holds the network's settings (hermetic, microphone, …), which its
/// instances come up with; since stage 1 of the container design no zone is
/// started from it for a launch.
pub fn ensure_offline_zone(state: &Path) {
    let dir = state.join(OFFLINE);
    if !dir.is_dir() {
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join(OFFLINE), b"");
    }
}

/// Hand the launch to `systemd --user`, which lives outside every zone.
fn delegate(tools: &Tools, argv: &[OsString]) -> u8 {
    // The app-id is passed explicitly: systemd-run starts the unit with the
    // MANAGER's environment, not ours, and VPN_ZONE_APPID never reached it — so
    // a link opened from a messenger inside a zone built a separate set of file
    // permissions and a separate registry entry, and the same program stopped
    // being recognised as itself.
    let appid = env_nonempty(ENV_APPID).unwrap_or_default();

    // A hermetic zone has no systemd --user to reach, and the broker instead:
    // the door with a guard (`crate::broker`). Checked by the manager's socket
    // being gone rather than by a variable a program could set.
    let runtime = crate::broker::runtime_dir();
    if !runtime.join("systemd/private").exists() {
        if let Some(code) = crate::broker::request(appid.as_bytes(), argv) {
            return code;
        }
    }
    let mut setenv = OsString::from("--setenv=VPN_ZONE_APPID=");
    setenv.push(&appid);

    let mut exec: Vec<OsString> = vec![tools.systemd_run.clone().into()];
    exec.extend([
        "--user".into(),
        "--quiet".into(),
        "--collect".into(),
        "--setenv=VPN_ZONE_DELEGATED=1".into(),
    ]);
    exec.push(setenv);
    if let Some(current) = env_nonempty(ENV_CURRENT) {
        let mut from = OsString::from(format!("--setenv={ENV_FROM}="));
        from.push(&current);
        exec.push(from);
    }
    exec.push("--".into());
    exec.push(tools.runner.clone().into());
    exec.push("run".into());
    exec.extend(argv.iter().cloned());

    let e = exec_command(&exec);
    eprintln!("не удалось запустить {}: {e}", tools.systemd_run.display());
    EXIT_NOT_STARTED
}

/// What was chosen for the container, as the registry records it (the third
/// field): the container's name, `__fs__` for a throwaway sandbox, the
/// temporary container's directory name, empty for the main profile.
fn selector_of(selection: &Selection, profile: &OsStr) -> OsString {
    match (&selection.sandbox, &selection.container) {
        (Sandbox::Named(name), _) | (Sandbox::None, Container::MainNamed(name)) => name.clone(),
        (Sandbox::Throwaway, _) => OsString::from("__fs__"),
        (Sandbox::None, _) => profile.to_owned(),
    }
}

/// A container as the rest of `run` needs it.
struct ResolvedContainer {
    /// Name of the container, empty for the main profile. Also the third field
    /// of the registry record.
    profile: OsString,
    /// Where the layers live, empty for the main profile.
    dir: PathBuf,
    ephemeral: bool,
    /// Registry directory key: the container name, or `__main__`.
    key: OsString,
}

/// Where throwaway containers live, below the state directory.
pub const THROWAWAY_DIR: &str = ".throwaway";

/// Where a throwaway container named `name` is, if it still exists: below the
/// state directory, or in `/tmp`, where a launch from before the move put it.
pub fn throwaway_path(state: &Path, name: &OsStr) -> Option<PathBuf> {
    throwaway_bases(state)
        .into_iter()
        .map(|base| base.join(name))
        .find(|dir| dir.is_dir())
}

/// The directories throwaway containers are looked for in, the current one
/// first.
pub fn throwaway_bases(state: &Path) -> [PathBuf; 2] {
    [state.join(THROWAWAY_DIR), PathBuf::from("/tmp")]
}

/// Is `real` (links resolved) a throwaway container of ours: `vpn-profile-…`
/// right in one of [`throwaway_bases`]?
fn our_throwaway(tools: &Tools, real: &Path) -> bool {
    real.file_name()
        .is_some_and(|n| n.as_bytes().starts_with(b"vpn-profile-"))
        && throwaway_bases(&tools.state)
            .iter()
            .any(|base| fs::canonicalize(base).is_ok_and(|b| real.parent() == Some(b.as_path())))
}

/// Turn the parsed container into directories, creating a throwaway one.
///
/// `None` means the message has been printed and the launch is over.
fn resolve_container(tools: &Tools, selection: &Selection) -> Option<ResolvedContainer> {
    let (profile, dir, ephemeral) = match &selection.container {
        Container::Main | Container::MainNamed(_) => (OsString::new(), PathBuf::new(), false),
        Container::Named(name) => {
            let dir = crate::container::data_dir(tools, &name.to_string_lossy());
            if !dir.is_dir() {
                let name = name.to_string_lossy();
                eprintln!("контейнера {name} нет — создай: cellward container create {name}");
                return None;
            }
            (name.clone(), dir, false)
        }
        Container::TmpNew => {
            // On a disk rather than a tmpfs, so a browser cache does not eat the
            // RAM (`docs/GOTCHAS.md` §5) — and no longer in /tmp: a hermetic
            // zone has a /tmp of its own, where a layer made on the host would
            // not be (`docs/LEAK-MODEL.md` §15).
            let base = tools.state.join(THROWAWAY_DIR);
            let made = fs::create_dir_all(&base)
                .and_then(|()| fs::set_permissions(&base, fs::Permissions::from_mode(0o700)))
                .and_then(|()| mkdtemp(&format!("{}/vpn-profile-XXXXXXXX", base.display())));
            let dir = match made {
                Ok(dir) => dir,
                Err(e) => {
                    eprintln!("не создать временный контейнер в {}: {e}", base.display());
                    return None;
                }
            };
            (basename(dir.as_os_str()).to_owned(), dir, true)
        }
        Container::TmpJoin(dir) => {
            if !dir.is_dir() {
                eprintln!("временного контейнера {} уже нет", dir.display());
                return None;
            }
            // Only a throwaway container of ours: its layer is ERASED behind the
            // last tenant, and a directory named here — by a request that came
            // through the broker, or by a slip of the hand — would go with it.
            let real = fs::canonicalize(dir).ok()?;
            if !our_throwaway(tools, &real) {
                eprintln!(
                    "{} — не временный контейнер cellward: присоединиться нельзя",
                    dir.display()
                );
                return None;
            }
            (basename(real.as_os_str()).to_owned(), real, true)
        }
    };
    // Every named container has a registry directory of its own, whatever
    // its home: what runs in it is found there (`docs/PERMISSIONS.md` §11.8).
    let key = match container_name(selection) {
        Some(name) => OsString::from(name),
        None if profile.is_empty() => OsString::from(registry::MAIN),
        None => profile.clone(),
    };
    Some(ResolvedContainer {
        profile,
        dir,
        ephemeral,
        key,
    })
}

/// `mktemp -d <template>`.
fn mkdtemp(template: &str) -> std::io::Result<PathBuf> {
    let mut buf = template.as_bytes().to_vec();
    buf.push(0);
    // SAFETY: a NUL-terminated, writable buffer that outlives the call; mkdtemp
    // edits the six trailing X's in place.
    let ptr = unsafe { libc::mkdtemp(buf.as_mut_ptr().cast()) };
    if ptr.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    buf.pop();
    Ok(PathBuf::from(OsString::from_vec(buf)))
}

/// Should this program be put on a restricted Wayland socket? Reads the two
/// files the answer depends on and asks [`restrict_compositor`].
/// `unasked` ([`ENV_UNASKED`]): the list by program is not read.
fn wayland_sandbox_wanted(
    tools: &Tools,
    appbin: &OsStr,
    program: Option<&OsStr>,
    unasked: bool,
) -> bool {
    let mode = cli::setting(tools, "wayland-sandbox").map(|(value, _)| value);
    let allowlist = std::fs::read_to_string(tools.config.join("wayland-allow"))
        .ok()
        .filter(|_| !unasked);
    let launched =
        program.and_then(|word| resolve_program(word, std::env::var_os("PATH").as_deref()));
    let dirs = trusted_bin_dirs();
    let origin = |entry: &str| {
        launched
            .as_deref()
            .is_some_and(|p| names_program(entry, p, &dirs))
    };
    restrict_compositor(mode.as_deref(), appbin, allowlist.as_deref(), &origin)
}

/// Where a program let the compositor's full protocols BY NAME has to come
/// from: the system's profile and the user's as NixOS keeps it, and the
/// directories a distribution installs programs into — all of them root's.
/// Not `~/.nix-profile` (a link in the home a program may re-point) and
/// nothing else in the home.
fn trusted_bin_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = [
        "/run/current-system/sw/bin",
        "/nix/var/nix/profiles/default/bin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    if let Some(user) = std::env::var_os("USER").filter(|u| !u.is_empty()) {
        let mut dir = PathBuf::from("/etc/profiles/per-user");
        dir.push(user);
        dir.push("bin");
        dirs.push(dir);
    }
    dirs
}

/// A process as the main-home guard sees it ([`rival`]): its real uid, the
/// file it runs (`dev`, `ino` of `/proc/<pid>/exe`, when it may be read) and
/// its `argv[0]`'s last component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub pid: i32,
    pub uid: u32,
    pub exe: Option<(u64, u64)>,
    pub name: Option<OsString>,
}

/// The first process of `seen` that runs the launch's program as the user
/// (`uid`) outside the instance the launch goes to — by the file (`exe`,
/// what the command resolves to) or by its name (`name`: wrappers exec the
/// real binary with the name they were called by, `exec -a "$0"`) —, never
/// one of `skip` (this launch and its parents) nor one `inside` says is in
/// the target instance.
pub fn rival(
    seen: &[Seen],
    uid: u32,
    exe: Option<(u64, u64)>,
    name: &OsStr,
    skip: &[i32],
    inside: &dyn Fn(i32) -> bool,
) -> Option<i32> {
    seen.iter()
        .filter(|s| s.uid == uid && !skip.contains(&s.pid))
        .filter(|s| {
            (exe.is_some() && s.exe == exe) || (!name.is_empty() && s.name.as_deref() == Some(name))
        })
        .find(|s| !inside(s.pid))
        .map(|s| s.pid)
}

/// A process of the user's running the program `word` starts, outside
/// instance `id` — its pid (the main-home guard, stage 3 of the container
/// design). Two pid namespaces sharing the real home cannot see each other's
/// pid lock files: Chromium's `SingletonLock`, Firefox's `lock`, wineserver's
/// name a pid, and a pid of another namespace is nobody (or somebody else)
/// in this one — a second browser would take the profile the first one has
/// open. So a launch of the main home into an instance is refused while the
/// program runs outside it: on the host, in a zone's own namespaces, in
/// another instance. Asked for applications only (a launch with an app's
/// id): a terminal's `cellward run nl -- sh` is no single-instance program,
/// and the user's shells are everywhere.
fn main_home_rival(state: &Path, id: &str, word: &OsStr) -> Option<i32> {
    let (exe, uid, skip) = rival_marks(word);
    // The target instance's user namespace, while it is up: what is in it
    // or below it shares its pid namespace.
    let target = crate::instance::up(state, id)
        .and_then(|pid| crate::place::ns_key(Path::new(&format!("/proc/{pid}/ns/user"))));
    let inside = |pid: i32| target.is_some_and(|key| crate::place::chain_of(pid).contains(&key));
    rival(&seen_processes(), uid, exe, basename(word), &skip, &inside)
}

/// The main-home guard the other way round (review 2026-09-28): a process
/// of the user's running the program `word` starts, in the pid namespace of
/// a running instance that has the real home ([`shares_main_home`]) — its
/// host pid, the instance's id and its network. An unconfined launch of the
/// main home is a host process, and the copy in the instance keeps a lock
/// that names a pid of the instance's namespace: on the host nobody, or
/// somebody else — Chromium takes it for a stale lock, deletes it and opens
/// the profile the other copy has open. Instances with a home of their own
/// run their own profile; one of an earlier build, with no pid namespace of
/// its own, writes host pids into its locks.
fn main_home_in_instance(tools: &Tools, word: &OsStr) -> Option<(i32, String, String)> {
    let home_of = |name: &str| crate::container::load(tools, name).map(|c| c.home);
    let targets: Vec<((u64, u64), crate::instance::Running)> =
        crate::instance::running(&tools.state)
            .into_iter()
            .filter(|i| crate::instance::own_pid_namespace(i.pid))
            .filter(|i| shares_main_home(&i.id, &home_of))
            .filter_map(|i| {
                let key = crate::place::ns_key(Path::new(&format!("/proc/{}/ns/user", i.pid)))?;
                Some((key, i))
            })
            .collect();
    if targets.is_empty() {
        return None;
    }
    let (exe, uid, skip) = rival_marks(word);
    let within = |pid: i32| {
        let chain = crate::place::chain_of(pid);
        targets.iter().find(|(key, _)| chain.contains(key))
    };
    // `rival` finds one outside what it is told is inside: here, outside
    // every other place than these instances.
    let pid = rival(&seen_processes(), uid, exe, basename(word), &skip, &|pid| {
        within(pid).is_none()
    })?;
    let (_, instance) = within(pid)?;
    Some((pid, instance.id.clone(), instance.network.clone()))
}

/// Whether instance `id` has the real home: the built-in main's
/// (`main:<network>`), a main-home container's that asks its network
/// (`<c>:<network>`: no other container's id has one), or a named
/// container's whose home is the main one (`home_of`). One that cannot be
/// read any more — removed while its instance runs — is taken for one that
/// has it: a refusal is undone by closing a program, a profile opened twice
/// is not. A throwaway's is a layer or a sandbox of its own.
fn shares_main_home(id: &str, home_of: &dyn Fn(&str) -> Option<crate::container::Home>) -> bool {
    if id.starts_with(crate::instance::TMP_PREFIX) || id.starts_with(crate::instance::FS_PREFIX) {
        return false;
    }
    match id.split_once(':') {
        Some(_) => true,
        None => home_of(id).is_none_or(|home| home == crate::container::Home::Main),
    }
}

/// What the main-home guards know the program `word` by, and whom they
/// never take for it: its file — only when the file is the program's own: a
/// name that resolves to a file of another name is a multicall binary's
/// (coreutils, busybox), which every other command of it runs too —, the
/// user's uid, and this launch with its parents.
fn rival_marks(word: &OsStr) -> (Option<(u64, u64)>, u32, Vec<i32>) {
    use std::os::unix::fs::MetadataExt;
    let exe = resolve_program(word, std::env::var_os("PATH").as_deref())
        .filter(|path| path.file_name() == Some(basename(word)))
        .and_then(|path| fs::metadata(path).ok())
        .map(|m| (m.dev(), m.ino()));
    // SAFETY: getuid(2) takes no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
    let me = std::process::id() as i32;
    let skip = crate::sys::pidfd_open(me)
        .map(|fd| crate::sys::ancestors(me, &fd))
        .unwrap_or_else(|| vec![me]);
    (exe, uid, skip)
}

/// Every process of the host's `/proc`, as [`rival`] reads them.
fn seen_processes() -> Vec<Seen> {
    use std::os::unix::fs::MetadataExt;
    fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .filter_map(|pid| {
            let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
            let uid = status
                .lines()
                .find_map(|l| l.strip_prefix("Uid:"))?
                .split_whitespace()
                .next()?
                .parse()
                .ok()?;
            let exe = fs::metadata(format!("/proc/{pid}/exe"))
                .ok()
                .map(|m| (m.dev(), m.ino()));
            let name = fs::read(format!("/proc/{pid}/cmdline"))
                .ok()
                .and_then(|line| {
                    let first = line.split(|b| *b == 0).next()?.to_vec();
                    (!first.is_empty()).then(|| basename(&OsString::from_vec(first)).to_owned())
                });
            Some(Seen {
                pid,
                uid,
                exe,
                name,
            })
        })
        .collect()
}

/// The real path of the program a command word starts: the word itself when
/// it names a path, else the first executable file of that name on `path`.
fn resolve_program(word: &OsStr, path: Option<&OsStr>) -> Option<PathBuf> {
    let found = if word.as_bytes().contains(&b'/') {
        PathBuf::from(word)
    } else {
        std::env::split_paths(path?)
            .map(|dir| dir.join(word))
            .find(|candidate| {
                std::fs::metadata(candidate)
                    .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            })?
    };
    std::fs::canonicalize(found).ok()
}

/// Is `launched` (a real path) the program an allow-list entry names: an
/// absolute path, that file; a name, what one of `dirs` gives under it.
pub fn names_program(entry: &str, launched: &Path, dirs: &[PathBuf]) -> bool {
    let same = |p: &Path| std::fs::canonicalize(p).is_ok_and(|real| real == launched);
    if entry.starts_with('/') {
        return same(Path::new(entry));
    }
    !entry.is_empty() && !entry.contains('/') && dirs.iter().any(|dir| same(&dir.join(entry)))
}

/// Whether the Wayland proxy stands between this program and the compositor
/// (`crate::wl_proxy`): on unless switched off — for all programs
/// (`vpn-zone wayland-proxy off`, `programs.cellward.waylandProxy.enable`)
/// or for this one (`~/.config/vpn-zones/wayland-no-proxy`, one program per
/// line, and its declared twin). Off, the compositor listens on the zone's
/// path itself, as before there was a proxy: still the restricted socket.
/// `unasked` ([`ENV_UNASKED`]): the lists by program are not read.
fn wayland_proxy_wanted(tools: &Tools, appbin: &OsStr, unasked: bool) -> bool {
    let mode = cli::setting(tools, "wayland-proxy").map(|(value, _)| value);
    let lists = [
        std::fs::read_to_string(tools.config.join("wayland-no-proxy")),
        crate::declared::read(
            &tools
                .config
                .join(cli::DECLARED_DIR)
                .join("wayland-no-proxy"),
        ),
    ];
    let listed = !unasked
        && appbin.to_str().is_some_and(|name| {
            lists
                .iter()
                .flatten()
                .any(|text| text.lines().map(str::trim).any(|line| line == name))
        });
    proxy_wanted(mode.as_deref(), listed)
}

/// The decision itself: no setting means on, and only `off` switches it off.
pub fn proxy_wanted(mode: Option<&str>, listed: bool) -> bool {
    mode.map(str::trim) != Some("off") && !listed
}

/// The decision itself, without the filesystem.
///
/// **No setting file means ON.** That is the default the project promises, and
/// getting it wrong is invisible: the program starts, everything works, and the
/// screen capture, the background clipboard reads and the input emulation are
/// all quietly back. The shell version said `cat … || echo on` for exactly this
/// reason. (`docs/GOTCHAS.md` §7)
///
/// Two ways out of the restriction: the built-in [`WAYLAND_ALLOWED`] list, and
/// `~/.config/vpn-zones/wayland-allow`, one program per line and matched whole
/// (the shell's `grep -qxF`) — a name, or an absolute path.
///
/// **A name is not enough (2026-09-27, `docs/LEAK-MODEL.md` §8):** it is the
/// program's own word, and anything called `obs` — a script in `~/.local/bin`,
/// something downloaded — would have had screen capture, input emulation and
/// the clipboard in the background. `origin` answers whether the program of
/// this launch IS the one an entry names: under a name, the one the system's
/// and the user's profiles give ([`names_program`]); under a path, that file.
/// Only for launches outside every zone: a launch into a zone is restricted
/// whatever its program.
pub fn restrict_compositor(
    mode: Option<&str>,
    appbin: &OsStr,
    allowlist: Option<&str>,
    origin: &dyn Fn(&str) -> bool,
) -> bool {
    if appbin.is_empty() {
        return false;
    }
    if mode.unwrap_or("on") != "on" {
        return false;
    }
    let Some(name) = appbin.to_str() else {
        // Sanitisation leaves only ASCII, so this cannot happen — and if it ever
        // does, restricting is the safe answer.
        return true;
    };
    if WAYLAND_ALLOWED.contains(&name) && origin(name) {
        return false;
    }
    !allowlist.is_some_and(|text| {
        text.lines()
            .any(|line| (line == name || line.starts_with('/')) && origin(line))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A manifest whose home, state, containers and config are below `base`.
    fn tools_in(base: &Path) -> Tools {
        let entries: std::collections::BTreeMap<String, String> = Tools::keys()
            .iter()
            .map(|k| {
                let dir = match *k {
                    "home" => base.join("home"),
                    "state" => base.join("state"),
                    "profiles" => base.join("profiles"),
                    "sandboxes" => base.join("sandboxes"),
                    "config" => base.join("config"),
                    other => PathBuf::from(format!("/p/{other}")),
                };
                ((*k).to_owned(), dir.to_string_lossy().into_owned())
            })
            .collect();
        Tools::from_entries(Path::new("/m.json"), &entries).unwrap()
    }

    /// One launch, one container (`docs/PERMISSIONS.md` §11.7): the name,
    /// whichever word carries it, is the container, and its home decides how
    /// it is mounted; two containers at once are refused; `--sandbox` makes a
    /// missing one with a home of its own, as it always made a sandbox.
    #[test]
    fn one_launch_is_one_container_by_its_name() {
        use crate::container::{self, Home};
        let base = std::env::temp_dir().join(format!("vz-one-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let tools = tools_in(&base);
        container::create(&tools, "work", Home::Layer).unwrap();
        container::create(&tools, "dev", Home::Private).unwrap();
        container::create(&tools, "files", Home::Main).unwrap();
        let resolve = |line: &[&str]| {
            let argv: Vec<OsString> = line.iter().map(OsString::from).collect();
            resolve_selection(&tools, Selection::parse(&argv).unwrap())
                .map(|s| (s.container, s.sandbox))
        };
        let name = |n: &str| OsString::from(n);

        assert_eq!(
            resolve(&["nl", "--container", "work", "--", "x"]),
            Ok((Container::Named(name("work")), Sandbox::None))
        );
        for flag in ["--container", "--profile"] {
            assert_eq!(
                resolve(&["nl", flag, "dev", "--", "x"]),
                Ok((Container::Main, Sandbox::Named(name("dev")))),
                "{flag}"
            );
        }
        // A sandbox asked for gets a home of its own or nothing: never the
        // real home through a layer or the main home by that name.
        for layer_or_main in ["work", "files"] {
            assert!(resolve(&["nl", "--sandbox", layer_or_main, "--", "x"])
                .unwrap_err()
                .contains("не контейнер со своим домом"));
        }
        assert_eq!(
            resolve(&["nl", "--container", "files", "--", "x"]),
            Ok((Container::MainNamed(name("files")), Sandbox::None))
        );
        // A missing one is made — at the launch, after its network is
        // checked, not while it is resolved.
        let new = Selection::parse(&[
            OsString::from("nl"),
            OsString::from("--sandbox"),
            OsString::from("new"),
            OsString::from("x"),
        ])
        .unwrap();
        let new = resolve_selection(&tools, new).unwrap();
        assert_eq!(
            (&new.container, &new.sandbox),
            (&Container::Main, &Sandbox::Named(name("new")))
        );
        assert!(container::load(&tools, "new").is_none());
        prepare_selection(&tools, &new).unwrap();
        assert_eq!(
            container::load(&tools, "new").map(|c| c.home),
            Some(Home::Private)
        );
        assert!(resolve(&["nl", "--container", "gone", "--", "x"])
            .unwrap_err()
            .contains("нет"));
        assert!(resolve(&["nl", "--container", "main", "--", "x"]).is_err());
        for two in [
            &["nl", "--profile", "work", "--sandbox", "dev", "--", "x"][..],
            &["nl", "--profile", "work", "--fs-sandbox", "--", "x"],
            &["nl", "--tmp-profile", "--fs-sandbox", "--", "x"],
        ] {
            assert!(
                resolve(two).unwrap_err().contains("один контейнер"),
                "{two:?}"
            );
        }
        // A sandbox of that very name is itself; one the move renamed (a
        // layer had the name) is found by its old one.
        container::create(&tools, "a-sb", Home::Private).unwrap();
        container::create(&tools, "a-sb2", Home::Private).unwrap();
        fs::write(base.join("config/containers/.renamed"), "sb:a\ta-sb2\n").unwrap();
        assert_eq!(
            resolve(&["nl", "--sandbox", "a", "--", "x"]),
            Ok((Container::Main, Sandbox::Named(name("a-sb2"))))
        );
        assert_eq!(
            resolve(&["nl", "--sandbox", "a-sb", "--", "x"]),
            Ok((Container::Main, Sandbox::Named(name("a-sb"))))
        );
        container::create(&tools, "a", Home::Private).unwrap();
        assert_eq!(
            resolve(&["nl", "--sandbox", "a", "--", "x"]),
            Ok((Container::Main, Sandbox::Named(name("a"))))
        );
        // Nothing named: nothing to resolve.
        assert_eq!(
            resolve(&["nl", "--fs-sandbox", "--", "x"]),
            Ok((Container::Main, Sandbox::Throwaway))
        );
        assert_eq!(
            resolve(&["nl", "--", "x"]),
            Ok((Container::Main, Sandbox::None))
        );
        let _ = fs::remove_dir_all(&base);
    }

    /// The proxy is on unless said off, for all or for one program.
    #[test]
    fn the_wayland_proxy_is_on_unless_said_off() {
        assert!(proxy_wanted(None, false));
        assert!(proxy_wanted(Some("on"), false));
        assert!(proxy_wanted(Some("whatever"), false));
        assert!(!proxy_wanted(Some("off"), false));
        assert!(!proxy_wanted(Some("off\n"), false));
        assert!(!proxy_wanted(None, true));
    }

    /// Throwaway containers live below the state directory, not in /tmp: a
    /// hermetic zone's /tmp is its own (`docs/LEAK-MODEL.md` §15). One from
    /// before the move is still found where it was.
    #[test]
    fn a_throwaway_container_is_found_in_the_state_directory_first() {
        let state = std::env::temp_dir().join(format!("vz-throwaway-{}", std::process::id()));
        let _ = fs::remove_dir_all(&state);
        let name = OsStr::new("vpn-profile-vzunit01");
        assert_eq!(throwaway_path(&state, name), None);
        let dir = state.join(THROWAWAY_DIR).join(name);
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(throwaway_path(&state, name), Some(dir));
        assert_eq!(throwaway_bases(&state)[1], Path::new("/tmp"));
        let _ = fs::remove_dir_all(&state);
    }

    fn argv(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    #[test]
    fn pretty_label_reads_trims_and_ignores_junk() {
        let state = mkdtemp("/tmp/vpn-launch-test-XXXXXXXX").unwrap();
        std::fs::create_dir_all(state.join(".labels")).unwrap();
        std::fs::write(state.join(".labels").join("app"), "Телеграм\n").unwrap();
        std::fs::write(state.join(".labels").join("blank"), "  \n").unwrap();
        assert_eq!(
            pretty_label(&state, OsStr::new("app")).as_deref(),
            Some("Телеграм")
        );
        // Whitespace-only, missing and empty keys are all "no label": the
        // dialog falls back to the id rather than showing «».
        assert_eq!(pretty_label(&state, OsStr::new("blank")), None);
        assert_eq!(pretty_label(&state, OsStr::new("missing")), None);
        assert_eq!(pretty_label(&state, OsStr::new("")), None);
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn a_bare_zone_and_a_command() {
        let s = Selection::parse(&argv(&["nl", "--", "firefox", "--new-window"])).unwrap();
        assert_eq!(s.zone, os("nl"));
        assert_eq!(s.container, Container::Main);
        assert_eq!(s.sandbox, Sandbox::None);
        assert_eq!(s.cmd, argv(&["firefox", "--new-window"]));
    }

    #[test]
    fn the_old_name_of_unconfined_is_read_as_it() {
        let s = Selection::parse(&argv(&["direct", "--", "firefox"])).unwrap();
        assert_eq!(s.zone, os(UNCONFINED));
        assert_eq!(network_name("direct"), "unconfined");
        assert_eq!(network_name("nl"), "nl");
        assert!(is_unconfined_name("direct") && is_unconfined_name("unconfined"));
        assert!(!is_unconfined_name("offline"));
    }

    #[test]
    fn the_separator_is_optional_and_only_the_first_one_counts() {
        assert_eq!(
            Selection::parse(&argv(&["nl", "firefox"])).unwrap().cmd,
            argv(&["firefox"])
        );
        assert_eq!(
            Selection::parse(&argv(&["nl", "--", "sh", "-c", "echo -- hi"]))
                .unwrap()
                .cmd,
            argv(&["sh", "-c", "echo -- hi"])
        );
    }

    #[test]
    fn every_container_shape_is_recognised() {
        for flag in ["--profile", "-p"] {
            let s = Selection::parse(&argv(&["nl", flag, "work", "--", "x"])).unwrap();
            assert_eq!(s.container, Container::Named(os("work")));
            assert_eq!(s.cmd, argv(&["x"]));
        }
        let s = Selection::parse(&argv(&["nl", "--tmp-profile", "--", "x"])).unwrap();
        assert_eq!(s.container, Container::TmpNew);
        let s = Selection::parse(&argv(&[
            "nl",
            "--tmp-profile",
            "--join",
            "/tmp/p",
            "--",
            "x",
        ]))
        .unwrap();
        assert_eq!(s.container, Container::TmpJoin(PathBuf::from("/tmp/p")));
        assert_eq!(s.cmd, argv(&["x"]));
    }

    #[test]
    fn every_sandbox_shape_is_recognised() {
        let s = Selection::parse(&argv(&["nl", "--fs-sandbox", "--", "x"])).unwrap();
        assert_eq!(s.sandbox, Sandbox::Throwaway);
        let s = Selection::parse(&argv(&["nl", "--sandbox", "work", "--", "x"])).unwrap();
        assert_eq!(s.sandbox, Sandbox::Named(os("work")));
        assert_eq!(s.cmd, argv(&["x"]));
    }

    #[test]
    fn a_container_and_a_sandbox_together_the_way_the_picker_writes_them() {
        let s = Selection::parse(&argv(&[
            "nl",
            "--tmp-profile",
            "--join",
            "/tmp/vpn-profile-abc",
            "--sandbox",
            "work",
            "--",
            "firefox",
        ]))
        .unwrap();
        assert_eq!(
            s.container,
            Container::TmpJoin(PathBuf::from("/tmp/vpn-profile-abc"))
        );
        assert_eq!(s.sandbox, Sandbox::Named(os("work")));
        assert_eq!(s.cmd, argv(&["firefox"]));
    }

    #[test]
    fn flags_after_the_command_belong_to_the_program() {
        let s = Selection::parse(&argv(&["nl", "--", "code", "--profile", "mine"])).unwrap();
        assert_eq!(s.container, Container::Main);
        assert_eq!(s.cmd, argv(&["code", "--profile", "mine"]));
    }

    #[test]
    fn a_missing_value_is_the_shell_message() {
        assert_eq!(Selection::parse(&[]), Err(ArgError::MissingZone));
        assert_eq!(Selection::parse(&argv(&[""])), Err(ArgError::MissingZone));
        assert_eq!(
            Selection::parse(&argv(&["nl", "--profile"])),
            Err(ArgError::MissingProfile)
        );
        assert_eq!(
            Selection::parse(&argv(&["nl", "--tmp-profile", "--join"])),
            Err(ArgError::MissingJoinDir)
        );
        assert_eq!(
            Selection::parse(&argv(&["nl", "--sandbox"])),
            Err(ArgError::MissingSandbox)
        );
        assert_eq!(
            Selection::parse(&argv(&["nl", "--sandbox", ""])),
            Err(ArgError::MissingSandbox)
        );
    }

    #[test]
    fn a_locked_zone_drops_the_whole_selection() {
        assert_eq!(
            strip_selection(&argv(&["nl", "--", "firefox"])),
            argv(&["firefox"])
        );
        assert_eq!(
            strip_selection(&argv(&["nl", "firefox"])),
            argv(&["firefox"])
        );
        assert_eq!(
            strip_selection(&argv(&["nl", "--profile", "work", "--", "firefox"])),
            argv(&["firefox"])
        );
        assert_eq!(
            strip_selection(&argv(&["nl", "-p", "work", "--fs-sandbox", "--", "a", "b"])),
            argv(&["a", "b"])
        );
        assert_eq!(
            strip_selection(&argv(&["nl", "--tmp-profile", "--sandbox", "s", "--", "x"])),
            argv(&["x"])
        );
        assert_eq!(
            strip_selection(&argv(&[
                "nl",
                "--tmp-profile",
                "--join",
                "/tmp/p",
                "--sandbox",
                "s",
                "--",
                "x"
            ])),
            argv(&["x"])
        );
        // Nothing left to run: the caller says so instead of exec'ing a flag.
        assert!(strip_selection(&argv(&["nl"])).is_empty());
        assert!(strip_selection(&argv(&["nl", "--fs-sandbox", "--"])).is_empty());
    }

    #[test]
    fn the_program_name_survives_wrappers_and_assignments() {
        assert_eq!(
            app_word(&argv(&["env", "DESKTOPINTEGRATION=1", "AyuGram"])),
            Some(OsStr::new("AyuGram"))
        );
        assert_eq!(
            app_word(&argv(&["/nix/store/xxx/bin/firefox"])),
            Some(OsStr::new("firefox"))
        );
        assert_eq!(
            app_word(&argv(&["nohup", "setsid", "-f", "telegram-desktop"])),
            Some(OsStr::new("telegram-desktop"))
        );
        assert_eq!(app_word(&argv(&["env"])), None);
        // A wrapper pinned by its path is one; one in the home is a program.
        assert_eq!(
            app_word(&argv(&["/nix/store/x-coreutils/bin/env", "firefox"])),
            Some(OsStr::new("firefox"))
        );
        assert_eq!(
            app_word(&argv(&["/home/u/.local/bin/env", "firefox"])),
            Some(OsStr::new("env"))
        );
        assert_eq!(app_word(&[]), None);
    }

    #[test]
    fn an_argument_with_an_equals_sign_in_it_is_not_an_assignment() {
        // The `*=*` pattern threw this away and the app-id came out empty.
        // What comes back is `basename` of the whole word, exactly as the shell
        // took it — an odd name, but a non-empty one, and the sanitiser makes it
        // a single word afterwards.
        assert_eq!(
            app_word(&argv(&["sh", "-c", "exec foo --url=https://x"])),
            Some(OsStr::new("x"))
        );
        assert_eq!(
            app_word(&argv(&["sh", "-c", "echo hello=world"])),
            Some(OsStr::new("echo hello=world"))
        );
        // A real assignment still is one.
        assert_eq!(
            app_word(&argv(&["FOO=bar", "_X=1", "chromium"])),
            Some(OsStr::new("chromium"))
        );
    }

    #[test]
    fn an_app_id_is_one_word_of_at_most_sixty_four_bytes() {
        assert_eq!(sanitize_app_id(OsStr::new("firefox")), os("firefox"));
        assert_eq!(
            sanitize_app_id(OsStr::new("org.kde.dolphin")),
            os("org.kde.dolphin")
        );
        // Spaces used to split the wl-sandbox argument in two.
        assert_eq!(sanitize_app_id(OsStr::new("echo -- hi")), os("echo_--_hi"));
        // The first line of a multi-line command is empty: without dropping the
        // newlines the id came out empty and the launch died.
        assert_eq!(sanitize_app_id(OsStr::new("\necho hi")), os("echo_hi"));
        assert_eq!(sanitize_app_id(OsStr::new("")), os(""));
        let long = "a".repeat(100);
        assert_eq!(sanitize_app_id(OsStr::new(&long)).len(), 64);
        // Byte-wise, exactly as `tr -c` was: one underscore per byte.
        assert_eq!(sanitize_app_id(OsStr::new("зона")), os("________"));
    }

    #[test]
    fn the_main_home_guard_finds_the_program_outside_the_instance() {
        let seen = |pid, uid, exe: Option<(u64, u64)>, name: Option<&str>| Seen {
            pid,
            uid,
            exe,
            name: name.map(OsString::from),
        };
        let table = [
            // This launch's own parent (the picker) and itself.
            seen(10, 1000, Some((1, 5)), Some("vpn-zone-pick")),
            seen(11, 1000, Some((1, 6)), Some("vpn-zone")),
            // Another user's firefox: not ours to mind.
            seen(20, 1001, Some((1, 7)), Some("firefox")),
            // The user's firefox in the target instance itself.
            seen(30, 1000, Some((1, 7)), Some("firefox")),
            // A shell of the user's, and an unreadable process.
            seen(40, 1000, Some((1, 8)), Some("bash")),
            seen(41, 1000, None, None),
        ];
        let inside = |pid: i32| pid == 30;
        let skip = [11, 10];
        let firefox = OsStr::new("firefox");
        assert_eq!(
            rival(&table, 1000, Some((1, 7)), firefox, &skip, &inside),
            None
        );
        // The same file on the host: refused.
        let mut host = table.to_vec();
        host.push(seen(50, 1000, Some((1, 7)), None));
        assert_eq!(
            rival(&host, 1000, Some((1, 7)), firefox, &skip, &inside),
            Some(50)
        );
        // A wrapper's real binary, by the name it was called by.
        let mut wrapped = table.to_vec();
        wrapped.push(seen(60, 1000, Some((9, 9)), Some("firefox")));
        assert_eq!(
            rival(&wrapped, 1000, Some((1, 7)), firefox, &skip, &inside),
            Some(60)
        );
        assert_eq!(
            rival(&wrapped, 1000, None, firefox, &skip, &inside),
            Some(60)
        );
        // Nothing to go by: nothing found.
        assert_eq!(
            rival(&wrapped, 1000, None, OsStr::new(""), &skip, &inside),
            None
        );
        // Its own parent is not its rival, whatever it runs.
        let firefox_picker = [seen(10, 1000, Some((1, 7)), Some("firefox"))];
        assert_eq!(
            rival(&firefox_picker, 1000, Some((1, 7)), firefox, &skip, &inside),
            None
        );
        // The other way round (review 2026-09-28): an unconfined launch
        // finds the copy in an instance of the real home, and nothing on
        // the host.
        let in_instance = |pid: i32| pid != 30;
        assert_eq!(
            rival(&host, 1000, Some((1, 7)), firefox, &skip, &in_instance),
            Some(30)
        );
        let on_host_only: Vec<Seen> = host.iter().filter(|s| s.pid != 30).cloned().collect();
        assert_eq!(
            rival(
                &on_host_only,
                1000,
                Some((1, 7)),
                firefox,
                &skip,
                &in_instance
            ),
            None
        );
    }

    /// Which instances have the real home (review 2026-09-28): the main's,
    /// a main-home container's by its id or its home, and one whose
    /// container cannot be read; not a private or a layered home's, nor a
    /// throwaway's.
    #[test]
    fn an_instance_of_the_real_home_is_known_by_its_id_or_its_container() {
        use crate::container::Home;
        let home_of = |name: &str| match name {
            "work" => Some(Home::Private),
            "layered" => Some(Home::Layer),
            "shared" => Some(Home::Main),
            _ => None,
        };
        for id in ["main:nl", "main:offline", "shared:nl", "shared", "gone"] {
            assert!(shares_main_home(id, &home_of), "{id}");
        }
        for id in ["work", "layered", ":tmp:vpn-profile-x", ":fs:box"] {
            assert!(!shares_main_home(id, &home_of), "{id}");
        }
    }

    #[test]
    fn basenames_match_the_tool_of_the_same_name() {
        assert_eq!(basename(OsStr::new("/a/b/c")), OsStr::new("c"));
        assert_eq!(basename(OsStr::new("c")), OsStr::new("c"));
        assert_eq!(basename(OsStr::new("/a/b/")), OsStr::new("b"));
        assert_eq!(
            basename(OsStr::new("/tmp/vpn-profile-abc")),
            OsStr::new("vpn-profile-abc")
        );
        assert_eq!(basename(OsStr::new("/")), OsStr::new("/"));
        assert_eq!(basename(OsStr::new("")), OsStr::new(""));
    }

    /// An origin that always agrees: the name logic alone.
    fn yes(_: &str) -> bool {
        true
    }

    /// A name on a list is not enough: the program has to be the one the
    /// system's profiles give under it, or the file a path entry names
    /// (2026-09-27, LEAK-MODEL §8).
    #[test]
    fn a_name_on_the_list_is_only_the_program_the_system_gives_under_it() {
        let no = |_: &str| false;
        assert!(restrict_compositor(None, OsStr::new("obs"), None, &no));
        assert!(!restrict_compositor(None, OsStr::new("obs"), None, &yes));
        assert!(restrict_compositor(
            None,
            OsStr::new("my-rec"),
            Some("my-rec\n"),
            &no
        ));
        // A path entry lets the file it names, whatever the program is called.
        let only_path = |e: &str| e == "/opt/rec/bin/rec";
        assert!(!restrict_compositor(
            None,
            OsStr::new("rec"),
            Some("/opt/rec/bin/rec\n"),
            &only_path
        ));

        let base = std::env::temp_dir().join(format!("wl-origin-{}", std::process::id()));
        let store = base.join("store/obs-1/bin");
        let profile = base.join("profile/bin");
        let home = base.join("home/.local/bin");
        for dir in [&store, &profile, &home] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let real = store.join("obs");
        let fake = home.join("obs");
        for file in [&real, &fake] {
            std::fs::write(file, b"").unwrap();
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::os::unix::fs::symlink(&real, profile.join("obs")).unwrap();
        let dirs = vec![profile.clone()];
        let real_c = std::fs::canonicalize(&real).unwrap();
        let fake_c = std::fs::canonicalize(&fake).unwrap();
        let in_profile = names_program("obs", &real_c, &dirs);
        let in_home = names_program("obs", &fake_c, &dirs);
        let by_path = names_program(fake.to_str().unwrap(), &fake_c, &dirs);
        // Found on PATH: the home's first, as a user's PATH may have it.
        let path = std::env::join_paths([&home, &profile]).unwrap();
        let resolved = resolve_program(OsStr::new("obs"), Some(path.as_os_str()));
        let _ = std::fs::remove_dir_all(&base);
        assert!(in_profile);
        assert!(!in_home, "a program in the home passed for the system's");
        assert!(by_path);
        assert_eq!(resolved, Some(fake_c));
        assert!(!names_program("", &real_c, &dirs));
        assert!(!names_program("../obs", &real_c, &dirs));
    }

    #[test]
    fn no_setting_file_means_the_compositor_restriction_is_on() {
        // The default the project promises. Getting it wrong is invisible from
        // the outside: the program starts and works, only the spying is back.
        assert!(restrict_compositor(None, OsStr::new("firefox"), None, &yes));
        assert!(restrict_compositor(
            Some("on"),
            OsStr::new("firefox"),
            None,
            &yes
        ));
        assert!(!restrict_compositor(
            Some("off"),
            OsStr::new("firefox"),
            None,
            &yes
        ));
        // Anything that is not "on" is off, as the shell comparison was.
        assert!(!restrict_compositor(
            Some(""),
            OsStr::new("firefox"),
            None,
            &yes
        ));
    }

    #[test]
    fn the_exceptions_are_the_built_in_list_and_the_allow_file() {
        assert!(!restrict_compositor(None, OsStr::new("grim"), None, &yes));
        assert!(!restrict_compositor(
            None,
            OsStr::new("flatpak"),
            None,
            &yes
        ));
        // One program per line, matched whole — `grep -qxF`.
        let allow = "copyq\nmy-recorder\n";
        assert!(!restrict_compositor(
            None,
            OsStr::new("my-recorder"),
            Some(allow),
            &yes
        ));
        assert!(restrict_compositor(
            None,
            OsStr::new("my-recorder-2"),
            Some(allow),
            &yes
        ));
        assert!(restrict_compositor(
            None,
            OsStr::new("record"),
            Some(allow),
            &yes
        ));
        // No app-id at all: there is nothing to name the sandbox after, and the
        // shell version skipped the wrapper too.
        assert!(!restrict_compositor(None, OsStr::new(""), None, &yes));
    }

    #[test]
    fn the_exception_list_holds_the_tools_that_live_off_those_protocols() {
        for name in ["grim", "wl-paste", "copyq", "obs", "niri", "waybar"] {
            assert!(
                WAYLAND_ALLOWED.contains(&name),
                "{name} пропал из исключений"
            );
        }
        // Nested sandboxes: they build a security context themselves.
        for name in ["flatpak", "bwrap", "podman", "distrobox"] {
            assert!(
                WAYLAND_ALLOWED.contains(&name),
                "{name} пропал из исключений"
            );
        }
        assert!(!WAYLAND_ALLOWED.contains(&"firefox"));
    }

    #[test]
    fn a_link_is_told_apart_from_a_file_argument() {
        assert!(hands_over_a_link(&argv(&["steam", "steam://rungameid/1"])));
        assert!(hands_over_a_link(&argv(&[
            "firefox",
            "https://example.org"
        ])));
        assert!(!hands_over_a_link(&argv(&["firefox", "/home/u/page.html"])));
        assert!(!hands_over_a_link(&argv(&["firefox"])));
        // The program word itself does not count.
        assert!(!hands_over_a_link(&argv(&["x://odd"])));
    }

    fn entry<'a>(network: Network, dir: &'a Path, ephemeral: bool) -> Entry<'a> {
        Entry {
            unshare: Path::new("/t/unshare"),
            core: Path::new("/t/core"),
            systemctl: Path::new("/t/systemctl"),
            zone: OsStr::new(match network {
                Network::Instance => OFFLINE,
                Network::Unconfined => UNCONFINED,
            }),
            network,
            instance: (network == Network::Instance).then_some("work"),
            dir,
            ephemeral,
            regdir: Path::new("/r/.running/work"),
            registered: None,
            cwd: Path::new("/home/u/src"),
            trust: None,
            nss_home: None,
            trust_extra: &[],
            certutil: Path::new("/t/certutil"),
            bwrap: Path::new("/t/bwrap"),
            shares: &[],
            storage: None,
            own_x11: false,
            camera: false,
            devices: &[],
        }
    }

    /// A container of the main home: nothing to mount, and a mount
    /// namespace of its own all the same. Into a zone it used to be asked
    /// for (`own_mounts`, `unshare --mount`), so that its programs were told
    /// from the zone's own; an instance's launch has one from
    /// `container-enter` whatever it mounts, and nothing goes into a zone's
    /// namespaces since stage 5 — the flag went with them. Outside any
    /// space it takes none.
    #[test]
    fn a_container_of_the_main_home_takes_a_mount_namespace_in_an_instance() {
        let e = entry(Network::Instance, Path::new(""), false);
        let line = entry_argv(&e, argv(&["dolphin"]));
        let at = |w: &str| line.iter().position(|a| a == w).unwrap();
        assert_eq!(line[0], os("/t/core"));
        assert!(at("container-enter") < at("profile-run"), "{line:?}");
        assert!(!line.contains(&os("/t/unshare")), "{line:?}");
        let e = entry(Network::Unconfined, Path::new(""), false);
        assert_eq!(entry_argv(&e, argv(&["dolphin"])), argv(&["dolphin"]));
    }

    /// An X server of the launch's own in an instance: its sockets'
    /// directory too, in a mount namespace of the launch's own (`x11-run`,
    /// `profile-run --own-x11`) — the instance's is every program of the
    /// instance's. (Into a zone until stage 5, the same through `unshare`.)
    #[test]
    fn an_x_server_of_its_own_has_a_directory_of_its_own() {
        let mut e = entry(Network::Instance, Path::new(""), false);
        e.own_x11 = true;
        let line = entry_argv(&e, argv(&["steam"]));
        let at = |w: &str| line.iter().position(|a| a == w).unwrap();
        assert!(at("container-enter") < at("profile-run"), "{line:?}");
        assert!(at("profile-run") < at("--own-x11"), "{line:?}");
        assert!(at("--own-x11") < at("steam"), "{line:?}");
    }

    /// A sandbox into an instance: the instance covers container storage,
    /// and the launch gets its own directory back — in a mount namespace of
    /// its own, never in the instance's. (Into a zone until stage 5, where
    /// every other program of the zone would have seen it.)
    #[test]
    fn a_containers_storage_comes_back_in_its_own_namespace() {
        let mut e = entry(Network::Instance, Path::new(""), false);
        e.storage = Some(Path::new("/home/u/.local/state/vpn-sandboxes/work"));
        let line = entry_argv(&e, argv(&["firefox"]));
        let at = |w: &str| line.iter().position(|a| a == w).unwrap();
        assert!(at("container-enter") < at("profile-run"), "{line:?}");
        let s = at("--storage");
        assert_eq!(line[s + 1], "/home/u/.local/state/vpn-sandboxes/work");
    }

    #[test]
    fn trust_alone_is_enough_to_take_a_mount_namespace() {
        // A named sandbox has no overlay directory, but its certificates still
        // need a bundle bound in a namespace of this launch's own — never in
        // the space's, where the next launch would see it. An instance's
        // launch has one from `container-enter` (a zone's took `unshare`
        // until stage 5).
        let mut e = entry(Network::Instance, Path::new(""), false);
        e.trust = Some(Path::new("/s/sb/work/trust"));
        e.nss_home = Some(Path::new("/s/sb/work/home"));
        let line = entry_argv(&e, argv(&["firefox"]));
        assert_eq!(
            line,
            argv(&[
                "/t/core",
                "container-enter",
                "--instance",
                "work",
                "--network",
                "offline",
                "--systemctl",
                "/t/systemctl",
                "--",
                "/t/core",
                "profile-run",
                "--cwd",
                "/home/u/src",
                "--trust",
                "/s/sb/work/trust",
                "--certutil",
                "/t/certutil",
                "--bwrap",
                "/t/bwrap",
                "--nss-home",
                "/s/sb/work/home",
                "",
                "offline",
                "0",
                "/r/.running/work",
                "--",
                "firefox"
            ])
        );

        // In direct the same takes a user namespace of its own.
        let mut e = entry(Network::Unconfined, Path::new(""), false);
        e.trust = Some(Path::new("/p/work/trust"));
        let line = entry_argv(&e, argv(&["firefox"]));
        assert_eq!(line[0], os("/t/unshare"));
        assert!(line.contains(&os("--map-current-user")));
        assert!(line.contains(&os("--trust")));
        // The home is $HOME there: no --nss-home without one.
        assert!(!line.contains(&os("--nss-home")));
    }

    #[test]
    fn into_an_instance_without_a_container_still_restores_the_working_directory() {
        // No layer to stack, but joining a mount namespace has left us in
        // `/`: `profile-run` with an empty directory stacks nothing and makes
        // the chdir. (Into a zone's own namespaces until stage 5, through
        // `nsenter`, which did the same.)
        let line = entry_argv(
            &entry(Network::Instance, Path::new(""), false),
            argv(&["firefox", "%u"]),
        );
        assert_eq!(
            line,
            argv(&[
                "/t/core",
                "container-enter",
                "--instance",
                "work",
                "--network",
                "offline",
                "--systemctl",
                "/t/systemctl",
                "--",
                "/t/core",
                "profile-run",
                "--cwd",
                "/home/u/src",
                "",
                "offline",
                "0",
                "/r/.running/work",
                "--",
                "firefox",
                "%u"
            ])
        );
        // No chdir before the mounts: a directory missing from the space's
        // mount tree would stop the launch.
        assert!(!line.iter().any(|a| a.to_string_lossy().starts_with("--wd")));
    }

    /// Stage 5 of the container design (2026-09-28): a network is never
    /// entered through a zone's own namespaces — no `nsenter` into its app
    /// namespace and no `unshare` below it, a container or not; only
    /// `container-enter`, by the instance's id. (What this test was, "into a
    /// zone with a container keeps the caps and takes a mount namespace",
    /// `container-enter` does now: `enter.rs` raises the capabilities for
    /// `profile-run`, in a mount namespace of the launch's own.)
    #[test]
    fn a_launch_never_enters_a_zones_own_namespaces() {
        for dir in ["", "/p/work"] {
            let line = entry_argv(
                &entry(Network::Instance, Path::new(dir), false),
                argv(&["firefox"]),
            );
            assert_eq!(line[0], os("/t/core"), "{line:?}");
            assert_eq!(line[1], os("container-enter"), "{line:?}");
            for word in ["nsenter", "/t/unshare", "-t"] {
                assert!(!line.contains(&os(word)), "{word}: {line:?}");
            }
            let at = |w: &str| line.iter().position(|a| a == w).unwrap();
            assert!(at("container-enter") < at("profile-run"), "{line:?}");
            assert_eq!(line[at("profile-run") + 3], os(dir), "{line:?}");
        }
    }

    #[test]
    fn direct_without_a_container_is_the_command_itself() {
        // Still whatever wrappers `run` put in front of it — they are part of
        // the command by then — but no namespace of any kind, and no chdir:
        // the working directory survives an exec by itself.
        let cmd = argv(&["/t/core", "wl-sandbox", "firefox", "--", "firefox"]);
        assert_eq!(
            entry_argv(
                &entry(Network::Unconfined, Path::new(""), false),
                cmd.clone()
            ),
            cmd
        );
        assert!(entry_argv(
            &entry(Network::Unconfined, Path::new(""), false),
            Vec::new()
        )
        .is_empty());
    }

    #[test]
    fn direct_with_a_container_makes_its_own_user_namespace_and_no_network_one() {
        // The container must not be dropped just because there is no zone to
        // borrow a user namespace from — that was a silent loss of isolation.
        let line = entry_argv(
            &entry(Network::Unconfined, Path::new("/tmp/vpn-profile-x"), true),
            argv(&["firefox"]),
        );
        assert_eq!(
            line,
            argv(&[
                "/t/unshare",
                "--user",
                "--map-current-user",
                "--keep-caps",
                "--mount",
                "--propagation",
                "private",
                "--",
                "/t/core",
                "profile-run",
                "--cwd",
                "/home/u/src",
                "/tmp/vpn-profile-x",
                "unconfined",
                "1",
                "/r/.running/work",
                "--",
                "firefox"
            ])
        );
        assert!(
            !line.contains(&os("--net")),
            "unconfined is the host's network"
        );
        assert!(!line.contains(&os("/t/nsenter")));
    }

    /// A throwaway container's `profile-run` is told the launch's own record
    /// (J9): with `wl-sandbox` in between, its own pid is in no record, and
    /// the launcher's record kept the container forever. A container that
    /// is kept asks nobody, and its command line stays as it was.
    #[test]
    fn a_throwaway_launch_names_its_own_record() {
        let me = crate::profile::Registered {
            pid: 4242,
            start: 777,
        };
        // Into `unconfined`, the one network with no instance to erase it
        // (a zone's until stage 5).
        let mut e = entry(Network::Unconfined, Path::new("/tmp/vpn-profile-x"), true);
        e.registered = Some(me);
        let line = entry_argv(&e, argv(&["firefox"]));
        let at = |w: &str| line.iter().position(|a| a == w).unwrap();
        assert!(at("profile-run") < at("--registered"), "{line:?}");
        assert_eq!(line[at("--registered") + 1], "4242:777");
        assert!(at("--registered") < at("/tmp/vpn-profile-x"), "{line:?}");
        let parsed = crate::profile::Args::parse(&line[at("profile-run") + 1..]).unwrap();
        assert_eq!(parsed.registered, Some(me));
        assert!(parsed.ephemeral);

        let mut e = entry(Network::Unconfined, Path::new("/p/work"), false);
        e.registered = Some(me);
        let line = entry_argv(&e, argv(&["firefox"]));
        assert!(!line.contains(&os("--registered")), "{line:?}");
    }

    /// Into a container's instance (stage 1, 2026-09-27): `container-enter`
    /// by the instance's id — no `nsenter`, no `unshare` (it gives the launch
    /// a mount namespace of its own itself) —, then `profile-run` as into a
    /// zone.
    #[test]
    fn into_an_instance_by_its_id_and_container_enter() {
        let line = entry_argv(
            &entry(Network::Instance, Path::new("/p/work"), false),
            argv(&["firefox"]),
        );
        assert_eq!(
            line,
            argv(&[
                "/t/core",
                "container-enter",
                "--instance",
                "work",
                "--network",
                "offline",
                "--systemctl",
                "/t/systemctl",
                "--",
                "/t/core",
                "profile-run",
                "--cwd",
                "/home/u/src",
                "/p/work",
                "offline",
                "0",
                "/r/.running/work",
                "--",
                "firefox"
            ])
        );
        let parsed = crate::enter::Args::parse(&line[2..]).unwrap();
        assert_eq!(parsed.instance, "work");
        // The network asked for goes with it (stage 2).
        assert_eq!(parsed.network.as_deref(), Some("offline"));
        assert_eq!(parsed.cmd[1], "profile-run");
    }

    /// Stage 2 (2026-09-27): a zone that is up and has no bridge — of a
    /// previous build — was entered as before, into its own namespaces.
    /// Stage 5 (2026-09-28): it is refused, and the refusal says the way out,
    /// its restart; one with its socket carries the launch's instance. By
    /// the socket's presence, as before: a file of that name is no bridge.
    #[test]
    fn a_zone_of_a_previous_build_is_refused_with_its_restart() {
        let state = std::env::temp_dir().join(format!("vz-legacy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&state);
        let zone = state.join("nl");
        fs::create_dir_all(&zone).unwrap();
        let why = no_bridge_refusal(&state, OsStr::new("nl")).unwrap();
        assert!(why.contains("не везёт контейнеры"), "{why}");
        assert!(why.contains("cellward restart nl"), "{why}");
        // A file of that name is no bridge.
        fs::write(zone.join(crate::bridge::SOCKET), "").unwrap();
        assert!(no_bridge_refusal(&state, OsStr::new("nl")).is_some());
        fs::remove_file(zone.join(crate::bridge::SOCKET)).unwrap();
        let bridge =
            std::os::unix::net::UnixListener::bind(zone.join(crate::bridge::SOCKET)).unwrap();
        assert_eq!(no_bridge_refusal(&state, OsStr::new("nl")), None);
        drop(bridge);
        let _ = fs::remove_dir_all(&state);
    }

    /// A launch's tree is looked through for a program in a zone's own
    /// user namespace: this process, in its own, is found; in another, not.
    #[test]
    fn a_launch_in_a_zones_own_namespaces_is_found() {
        let me = std::process::id() as i32;
        let children = process_children();
        let own = fs::read_link("/proc/self/ns/user").unwrap();
        assert!(tree_in_userns(&children, me, &own));
        assert!(!tree_in_userns(&children, me, Path::new("user:[1]")));
        assert!(!tree_in_userns(&children, i32::MAX, &own));
    }

    /// A throwaway container's instance erases it when its last program
    /// ends: `profile-run` is not told it is a throwaway one, and asks
    /// nobody who else is in it. The cameras and the devices come in as
    /// into a zone: an instance has a `/dev` of its own too.
    #[test]
    fn a_throwaway_in_an_instance_is_the_instances_to_erase() {
        let mut e = entry(
            Network::Instance,
            Path::new("/s/.throwaway/vpn-profile-x"),
            true,
        );
        e.registered = Some(crate::profile::Registered {
            pid: 4242,
            start: 777,
        });
        e.camera = true;
        let devices = ["/dev/hidraw3=241:3:1050:0407".to_owned()];
        e.devices = &devices;
        let line = entry_argv(&e, argv(&["firefox"]));
        assert!(!line.contains(&os("--registered")), "{line:?}");
        assert!(line.contains(&os("--camera")), "{line:?}");
        assert!(
            line.contains(&os("/dev/hidraw3=241:3:1050:0407")),
            "{line:?}"
        );
        let at = line.iter().position(|a| a == "profile-run").unwrap();
        let parsed = crate::profile::Args::parse(&line[at + 1..]).unwrap();
        assert!(!parsed.ephemeral);
        assert!(parsed.camera);
    }

    /// What a zone asked the broker for is a file name in the registry, not
    /// a path on the host.
    #[test]
    fn a_registry_key_is_never_a_path() {
        for (raw, key) in [
            ("firefox", "firefox"),
            ("org.telegram.desktop", "org.telegram.desktop"),
            ("/run/user/1000/x", "_run_user_1000_x"),
            ("../../.bashrc", ".._.._.bashrc"),
            ("..", "программа"),
            (".", "программа"),
            ("", "программа"),
        ] {
            assert_eq!(registry_key(OsStr::new(raw)), OsString::from(key), "{raw}");
        }
    }

    /// Cameras let a launch into an instance: a mount namespace of its own,
    /// and `profile-run --camera` binds them in there. Outside any space
    /// they are the host's anyway. (Into a zone until stage 5, the same
    /// through `unshare`.)
    #[test]
    fn a_launch_let_the_cameras_uncovers_them_in_its_own_namespace() {
        let mut e = entry(Network::Instance, Path::new(""), false);
        e.camera = true;
        let line = entry_argv(&e, argv(&["cheese"]));
        let at = |w: &str| line.iter().position(|a| a == w).unwrap();
        assert!(at("container-enter") < at("profile-run"), "{line:?}");
        assert!(at("profile-run") < at("--camera"), "{line:?}");
        let mut e = entry(Network::Unconfined, Path::new(""), false);
        e.camera = true;
        assert_eq!(entry_argv(&e, argv(&["cheese"])), argv(&["cheese"]));
    }
}
