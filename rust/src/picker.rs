//! `vpn-zone-pick` — the dialog that asks where a program is allowed to go.
//!
//! This is what an intercepted launcher entry starts instead of the program
//! (`crate::desktop`, picker mode): it asks which network and which container,
//! remembers the answer, and becomes `vpn-zone run`. It was the last shell
//! script of the project, and every branch of it is here because something went
//! wrong without it.
//!
//! **The network is the container's** (`docs/PERMISSIONS.md` §11.8): a
//! container bound to a network is started there with no question; one with
//! no network yet — and the main home, and a throwaway one — has it asked.
//! A named container keeps its network; "always" in the built-in main home
//! pins only that program's network, without creating another container.
//!
//! **What the question starts on** (`docs/GOTCHAS.md` §11):
//!
//!  1. where the program runs, when it does;
//!  2. the LAST CHOICE (`.last/<program>`);
//!  3. the GLOBAL DEFAULT (`~/.config/vpn-zones/default`, `offline` unless set).
//!     That is the "an unknown program gets no internet" policy: until a
//!     network is picked explicitly, the one without any is offered.
//!
//! The container is the program's pin (`.pinnedprofile/<program>`), the
//! global default, or the last choice; "↺ Спрашивать снова" drops the pin.
//!
//! Two environment variables drive the second pass:
//!
//! * `VPN_ZONE_ASK=1` forces the dialog for a program whose container is
//!   bound;
//! * `VPN_ZONE_PROFILE` is how the picker hands ITSELF the container that was
//!   just chosen in "⚙ Сменить контейнер" — it re-execs itself with both set.
//!   It is read once and removed from the environment immediately, or it would
//!   travel into the program, and a link opened from there would inherit
//!   somebody else's container.
//!
//! The decision itself is a pure function of a snapshot ([`Memory`]) so that
//! every branch of that machine is a test case and not a mouse click:
//! [`net_step`], [`container_without_dialog`], [`Container::from_selector`].

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use crate::cli::{read_setting, visible_entries, EXIT_TOOLS};
use crate::desktop::sanitize;
use crate::dialog;
use crate::launch::{self, basename, is_assignment};
use crate::profile::{exec_command, EXIT_NOT_STARTED};
use crate::registry;
use crate::tools::Tools;
use crate::window;

/// Force the dialog even for a pinned program.
pub const ENV_ASK: &str = "VPN_ZONE_ASK";
/// The container chosen in "⚙ Сменить контейнер", carried across the re-exec.
/// Internal: setting it by hand does nothing useful.
pub const ENV_PROFILE: &str = "VPN_ZONE_PROFILE";
/// The picker's per-program lock across its deliberate self-exec.
const ENV_LOCK_FD: &str = "VPN_ZONE_PICK_LOCK_FD";

struct PickerLock(File);

impl PickerLock {
    fn take(state: &Path, key: &str) -> std::io::Result<Option<Self>> {
        if let Some(raw) = std::env::var_os(ENV_LOCK_FD) {
            std::env::remove_var(ENV_LOCK_FD);
            if let Ok(fd) = raw.to_string_lossy().parse::<i32>() {
                if fd > 2 {
                    // SAFETY: this descriptor was deliberately inherited by
                    // our immediately preceding self-exec.
                    let file = unsafe { File::from_raw_fd(fd) };
                    // The launched application must never inherit it.
                    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
                    return Ok(Some(Self(file)));
                }
            }
        }
        let dir = state.join(".picker-locks");
        fs::create_dir_all(&dir)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(dir.join(key))?;
        // SAFETY: flock on our live file descriptor.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            Ok(Some(Self(file)))
        } else if std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn inherit_once(&self) {
        let fd = self.0.as_raw_fd();
        // SAFETY: keep our lock only over the immediate self-exec. The next
        // pass restores CLOEXEC before it can launch the application.
        unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
        std::env::set_var(ENV_LOCK_FD, fd.to_string());
    }
}

/// Sentinel for "the main profile" where an empty string would not do: in
/// `.pinnedprofile` and in `VPN_ZONE_PROFILE` an empty value cannot be told
/// apart from "not set at all". (`docs/GOTCHAS.md` §11)
pub const MAIN: &str = "__main__";
/// Selector of a throwaway filesystem sandbox.
pub const THROWAWAY: &str = "__fs__";
/// Prefix of a named sandbox selector: `sb:<name>`.
pub const SANDBOX_PREFIX: &str = "sb:";
/// Selector of a fresh throwaway container.
pub const TMP: &str = "__tmp__";
/// Prefix of "join the throwaway container that is already open at <dir>".
pub const TMPJOIN_PREFIX: &str = "tmpjoin:";

/// The wrappers and shell built-ins the fallback key derivation walks past.
///
/// One more than [`crate::launch::app_word`] has (`systemd-run`), and the
/// difference is deliberate: this list is the picker's own, and a launch
/// delegated through `systemd-run` must be keyed by the program, not by the
/// tool that started it.
const WRAPPERS: [&[u8]; 6] = [b"env", b"sh", b"bash", b"setsid", b"nohup", b"systemd-run"];

// --- ARGUMENTS ---------------------------------------------------------------

/// `[<label>] [--id K] [--label L] [--] cmd…`
///
/// The program's DISPLAY NAME is no longer an argument: it contains spaces, and
/// Telegram (and it is not alone) splits `Exec` naively without removing
/// quotes, so "Zen Browser" fell apart into two arguments and the launch died.
/// The name is read from the label file the shortcut generator writes instead.
/// (`docs/GOTCHAS.md` §10)
///
/// A leading positional label is still ACCEPTED, because shortcuts and the
/// picker are not updated atomically: during one rebuild `sync` ran before the
/// profile was swapped, and the new picker was handed shortcuts in the old
/// format — AyuGram stopped starting at all. Parsing both shapes is cheaper
/// than depending on the order of an update. Such a label is only taken when a
/// `--` follows somewhere, or the command itself would be eaten.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Args {
    /// `--id`: the stable identifier of the launcher entry (its file name
    /// without the extension). Without it the memory key would have to be
    /// derived from the command, and those are full of wrappers: AyuGram's
    /// `Exec` starts with `env DESKTOPINTEGRATION=1 …`, and the key came out as
    /// "env". (`docs/GOTCHAS.md` §10)
    pub id: Option<OsString>,
    pub label: Option<OsString>,
    /// `--autostart`: started by XDG autostart at login, where nobody is
    /// looking at a dialog yet. Never asks (`docs/CONTAINERS.md` §5).
    pub autostart: bool,
    /// `--from-zone <zone>`: the broker asks on behalf of a program in that
    /// zone ([`pick_for_zone`]); `--locked`: that zone is locked.
    pub from_zone: Option<String>,
    /// Broker-provided source identity, used only to propose an existing row.
    pub from_container: Option<String>,
    pub locked: bool,
    /// `--offer-rule <text>`: with `--from-zone`, a checkbox of its own in
    /// the window — a container's rule for links (`crate::links`); ticked,
    /// the answer starts with the word `--rule`.
    pub offer_rule: Option<String>,
    pub cmd: Vec<OsString>,
}

impl Args {
    pub fn parse(argv: &[OsString]) -> Self {
        let mut rest = argv;
        let mut label = None;

        let legacy = rest
            .first()
            .filter(|a| !a.is_empty() && !a.as_bytes().starts_with(b"-"))
            .is_some()
            && rest.iter().any(|a| a == "--");
        if legacy {
            label = Some(rest[0].clone());
            rest = &rest[1..];
        }

        let mut id = None;
        let mut autostart = false;
        let mut from_zone = None;
        let mut from_container = None;
        let mut locked = false;
        let mut offer_rule = None;
        let mut at = 0;
        while at < rest.len() {
            match rest[at].as_bytes() {
                b"--id" => {
                    id = rest.get(at + 1).cloned();
                    at += 2;
                }
                b"--label" => {
                    label = rest.get(at + 1).cloned();
                    at += 2;
                }
                b"--autostart" => {
                    autostart = true;
                    at += 1;
                }
                b"--from-zone" => {
                    from_zone = rest
                        .get(at + 1)
                        .map(|z| z.to_string_lossy().into_owned())
                        .filter(|z| !z.is_empty());
                    at += 2;
                }
                b"--from-container" => {
                    from_container = rest.get(at + 1).map(|c| c.to_string_lossy().into_owned());
                    at += 2;
                }
                b"--locked" => {
                    locked = true;
                    at += 1;
                }
                b"--offer-rule" => {
                    offer_rule = rest
                        .get(at + 1)
                        .map(|r| r.to_string_lossy().into_owned())
                        .filter(|r| !r.is_empty());
                    at += 2;
                }
                b"--" => {
                    at += 1;
                    break;
                }
                _ => break,
            }
        }

        Self {
            id: id.filter(|v| !v.is_empty()),
            label: label.filter(|v| !v.is_empty()),
            autostart,
            from_zone,
            from_container,
            locked,
            offer_rule,
            cmd: rest.get(at..).unwrap_or(&[]).to_vec(),
        }
    }
}

/// The memory key of a launch that did not come from a shortcut (a compositor
/// binding, a terminal): skip the wrappers and the variable assignments and
/// take the first real command.
///
/// The two traps are the ones [`crate::launch::app_word`] documents: only a
/// REAL assignment is skipped (`FOO=bar`, not `--url=https://x`), and an
/// argument with a space in it is the `sh -c '…'` case, where the whole word is
/// taken through `basename` rather than skipped.
pub fn fallback_key(cmd: &[OsString]) -> OsString {
    for word in cmd {
        let bytes = word.as_bytes();
        if WRAPPERS.contains(&bytes) || bytes.starts_with(b"-") {
            continue;
        }
        if bytes.contains(&b' ') {
            return basename(word).to_owned();
        }
        if is_assignment(bytes) {
            continue;
        }
        return basename(word).to_owned();
    }
    OsString::from("программа")
}

/// A name a person typed into a dialog, cleaned of exactly what would break —
/// path separators, quotes, spaces, line breaks and the invisible characters
/// that reorder text — and of the leading dash or dot kdialog takes for an
/// option. Cyrillic stays Cyrillic. (`docs/GOTCHAS.md` §11)
pub fn sanitize_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() && !crate::focus::reorders(*c))
        .map(|c| match c {
            '/' | '"' | '\'' | '`' | '\\' | ' ' | ':' => '_',
            other => other,
        })
        .collect();
    let name = cleaned.trim_start_matches(['-', '.']).to_owned();
    if reserved_name(&name) {
        String::new()
    } else {
        name
    }
}

/// A container name the menus use as a tag of their own: a profile called
/// `pinmain` or `__fs__` would be read as that command, not as itself. Never
/// created, by the picker or by `cellward container create`.
pub fn reserved_name(name: &str) -> bool {
    name.contains(':') || crate::container::reserved_name(name)
}

/// A selector from memory as it is now: a container's name after the move to
/// one name per container (`sb:work` → `work`, or `work-sb` when a layer had
/// the name); the words of the menus and the settings as they are.
///
/// `sb:<name>` keeps its prefix, with the name as it is now: what was a
/// sandbox is asked for as one ([`Container::from_selector`]). A temporary
/// container of a running program (its directory's name) is joined while it
/// is there, and a new one is made when it is gone — never a container of
/// that name.
fn canon(tools: &Tools, selector: &str) -> String {
    match selector {
        "" | MAIN | THROWAWAY | TMP | "ask" | "main" | "own" => selector.to_owned(),
        s if s.starts_with(TMPJOIN_PREFIX) => s.to_owned(),
        s if s.starts_with(crate::container::TEMPORARY_PREFIX) => {
            match launch::throwaway_path(&tools.state, std::ffi::OsStr::new(s)) {
                Some(dir) => format!("{TMPJOIN_PREFIX}{}", dir.display()),
                None => TMP.to_owned(),
            }
        }
        // Resolved here once; `run --sandbox` takes a home of its own of
        // that very name as it is, and renames nothing twice.
        s if s.starts_with(SANDBOX_PREFIX) => match crate::container::sandbox_name(tools, s) {
            Some(name) => format!("{SANDBOX_PREFIX}{name}"),
            None => s.to_owned(),
        },
        s => crate::container::canonical(tools, s).unwrap_or_else(|| s.to_owned()),
    }
}

/// Is there a container by this name — its data, its policy or its
/// declaration?
fn container_exists(tools: &Tools, name: &str) -> bool {
    crate::container::load(tools, name).is_some()
}

// --- THE STATE THE DECISION IS MADE FROM -------------------------------------

/// One live record of the launch registry, as the picker cares about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Running {
    pub zone: String,
    /// The third registry field: what was CHOSEN (`sb:<name>`, `__fs__`, a
    /// container name, or empty). (`docs/GOTCHAS.md` §5)
    pub selector: String,
}

/// Everything the first decision depends on, read from disk and nothing else.
///
/// The pins are the VALIDATED ones: a pin naming a zone or a container that no
/// longer exists has already been dropped by the caller
/// ([`pin_is_valid`], [`profile_pin_is_valid`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Memory {
    /// A live registry record for this program, if it is running somewhere.
    pub running: Option<Running>,
    /// `.handover/<key>`: the program was seen handing a launch over to the
    /// copy already running ([`HANDOVER`]) — a click on it while it runs
    /// raises that copy's window, with no question.
    pub hands_over: bool,
    /// `.pinnedprofile/<key>`, empty when the container is not pinned.
    pub pinned_profile: String,
    /// `.last/<key>`.
    pub last: String,
    /// `.lastprofile/<key>`.
    pub last_profile: String,
    /// `.lastprofile/<key>` is there at all: a container was chosen for this
    /// program before. The main home is an EMPTY file, so an empty
    /// `last_profile` alone cannot tell "the main home" from "never" — and
    /// the two are answered differently ([`Memory::last_choice`]).
    pub container_chosen: bool,
    /// `~/.config/vpn-zones/default`, `offline` when the file is absent.
    pub fallback: String,
    /// `~/.config/vpn-zones/default-profile`, `ask` when the file is absent.
    pub default_profile: String,
    /// `VPN_ZONE_ASK` is set.
    pub ask: bool,
    /// The network the container this launch would use is bound to, empty
    /// when it is not bound (`ask`) or there is no container at all.
    pub bound: String,
}

impl Memory {
    /// The container chosen for this program last time, or `None` for a
    /// program nobody ever chose one for — seen for the first time.
    ///
    /// Such a program is given ITS OWN HOME, preselected in the window and
    /// taken without one (2026-09-27, the owner's model of 2026-09-17: every
    /// program a home of its own; `docs/CONTAINERS.md` §12): the main home, the
    /// whole real one with nothing between it and the program, is a choice
    /// somebody makes, not what a new program falls into. What was chosen
    /// before — the main home included — stays chosen.
    pub fn last_choice(&self) -> Option<&str> {
        (self.container_chosen || !self.last_profile.is_empty())
            .then_some(self.last_profile.as_str())
    }
}

/// What the first (network) question resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetStep {
    /// A live launch exists. The person may focus it, open another window
    /// in its home, or pick a different home for an independent copy. This
    /// does not guess from an application-specific browser/terminal list.
    Running { zone: String, selector: String },
    /// The container this launch uses without a question is bound to a
    /// network: that is where it goes (`docs/PERMISSIONS.md` §11.8).
    Bound { zone: String },
    /// Show the network dialog, with this entry selected.
    Ask { default: String },
}

/// The first decision, without touching anything.
pub fn net_step(memory: &Memory) -> NetStep {
    if !memory.ask {
        if let Some(running) = memory.running.as_ref() {
            return NetStep::Running {
                zone: running.zone.clone(),
                selector: running.selector.clone(),
            };
        }
        // A container bound to a network answers the network question itself:
        // the network is part of the container's identity, and asking would
        // only offer the way to break it (`docs/CONTAINERS.md` I1). The
        // container itself is the one the pin or the default chose, so there
        // is nothing left to ask. The network is the container's and never a
        // program's: a program's pin is gone (`docs/PERMISSIONS.md` §11.8).
        if !memory.bound.is_empty() {
            return NetStep::Bound {
                zone: memory.bound.clone(),
            };
        }
    }
    NetStep::Ask {
        // Running already: where it runs is what Enter keeps; then the
        // container's own network (asked anyway with VPN_ZONE_ASK).
        default: match &memory.running {
            Some(running) => crate::launch::network_name(&running.zone).to_owned(),
            None if !memory.bound.is_empty() => memory.bound.clone(),
            None if memory.last.is_empty() => memory.fallback.clone(),
            None => memory.last.clone(),
        },
    }
}

/// Where [`Memory::hands_over`] is kept, one empty file per program.
pub const HANDOVER: &str = ".handover";

/// Whether a launch is watched for a hand-over ([`launch_asked`]): the
/// program runs, it is not known to hand over yet, and it is started into
/// the network it runs in — the one case where the new process ending with
/// success without a window of its own can mean nothing else. Another network is not watched: there `run`
/// warns first, and a cancel there exits with success too. Not from inside
/// a zone either (`in_zone`): the launch is delegated to the host and the
/// launcher returns at once.
pub fn watch_handover(memory: &Memory, zone: &str, in_zone: bool) -> bool {
    !in_zone
        && !memory.hands_over
        && memory.running.as_ref().is_some_and(|running| {
            crate::launch::network_name(&running.zone) == crate::launch::network_name(zone)
        })
}

/// The container of a launch: exactly the three variables the shell carried
/// (`profile`, `fssand`, `sandbox`) — and now never two of them at once
/// (`docs/PERMISSIONS.md` §11.7).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Container {
    /// A container that exists, by name, whatever its home — `run
    /// --container`; `__tmp__` or `tmpjoin:<dir>`; empty for the main
    /// profile.
    pub profile: String,
    /// `--fs-sandbox`, or with `sandbox` set a home of its own.
    pub fs_sandbox: bool,
    /// `--sandbox <name>`: a container made with a home of its own at its
    /// first launch — the program's own, a new one, or one that is gone.
    pub sandbox: String,
    /// With `fs_sandbox`: the open throwaway sandbox joined (`--fs-sandbox
    /// --join`), by its name; empty for a new one.
    pub join: String,
    /// This launch's own permissions (`run --with`), for a container with
    /// no record to keep them in (`crate::launch_perms`).
    pub with: Vec<OsString>,
}

impl Container {
    /// A stored selector turned back into a choice.
    ///
    /// For a selector from the launch registry, a pin or `VPN_ZONE_PROFILE`,
    /// all validated when they were written: a container that is not there
    /// (any more) is made again with a home of its own — the program's own
    /// home, never the whole real one.
    pub fn from_selector(selector: &str, exists: impl Fn(&str) -> bool) -> Self {
        Self::resolve(selector, &exists).unwrap_or_else(|| {
            let name = selector
                .strip_prefix(SANDBOX_PREFIX)
                .unwrap_or(selector)
                .to_owned();
            Self {
                fs_sandbox: true,
                sandbox: name,
                ..Self::default()
            }
        })
    }

    /// The same, for what nothing revalidates on the way in — `.lastprofile`:
    /// `None` for a container that is gone, and the caller decides.
    pub fn from_selector_checked(selector: &str, exists: impl Fn(&str) -> bool) -> Option<Self> {
        Self::resolve(selector, &exists)
    }

    fn resolve(selector: &str, exists: &impl Fn(&str) -> bool) -> Option<Self> {
        match selector {
            "" | MAIN => Some(Self::default()),
            THROWAWAY => Some(Self {
                fs_sandbox: true,
                ..Self::default()
            }),
            // An open one, as its programs' records name it.
            other if launch::throwaway_of(other).is_some() => {
                let join = launch::throwaway_of(other).flatten().unwrap_or_default();
                Some(Self {
                    fs_sandbox: true,
                    join: join.to_owned(),
                    ..Self::default()
                })
            }
            TMP => Some(Self {
                profile: TMP.to_owned(),
                ..Self::default()
            }),
            other if other.starts_with(TMPJOIN_PREFIX) => Some(Self {
                profile: other.to_owned(),
                ..Self::default()
            }),
            // `sb:<name>` — a stale pin, a default from Nix, a record of a
            // program started before one name per container — asked for a
            // home of its own and gets nothing else: `run --sandbox` refuses
            // a layer or the main home by that name, and makes a missing one.
            other => match other.strip_prefix(SANDBOX_PREFIX) {
                Some("") => None,
                Some(name) => Some(Self {
                    fs_sandbox: true,
                    sandbox: name.to_owned(),
                    ..Self::default()
                }),
                None if exists(other) => Some(Self {
                    profile: other.to_owned(),
                    ..Self::default()
                }),
                None => None,
            },
        }
    }

    /// What goes into `.lastprofile`: the CHOICE, a container's name
    /// whatever flag carries it. (`docs/GOTCHAS.md` §11)
    pub fn selector(&self) -> String {
        if !self.sandbox.is_empty() {
            return self.sandbox.clone();
        }
        if self.fs_sandbox && !self.join.is_empty() {
            return launch::throwaway_selector(&self.join);
        }
        if self.fs_sandbox {
            return THROWAWAY.to_owned();
        }
        self.profile.clone()
    }

    /// Is this a one-off container that must not be remembered? Remembering it
    /// would make a throwaway permanent.
    pub fn is_throwaway_container(&self) -> bool {
        self.profile == TMP || self.profile.starts_with(TMPJOIN_PREFIX) || !self.join.is_empty()
    }

    fn own_sandbox(key: &str) -> Self {
        Self {
            fs_sandbox: true,
            sandbox: own_name(key),
            ..Self::default()
        }
    }
}

/// The name of a program's own container, with a home of its own.
pub fn own_name(key: &str) -> String {
    format!("app-{key}")
}

/// The container when there is no dialog to ask it in, in priority order.
///
/// 1. `VPN_ZONE_PROFILE` — chosen in "⚙ Сменить контейнер" a second ago, so it
///    beats everything, the pin included;
/// 2. `.pinnedprofile` — and with no `VPN_ZONE_ASK` check in front of it: the
///    fresh choice arrives in the variable above, and testing for ASK here made
///    "↺ Спрашивать сеть снова" drop a pinned container into "main", because
///    `.lastprofile` is usually empty for somebody who pinned one;
/// 3. the global `default-profile` setting when it is an answer (`main`,
///    `own`, an existing container);
/// 4. the container a copy of it runs in already, as the launch window
///    preselects it: a program that runs somewhere was put there;
/// 5. `.lastprofile`; one that is gone is the program's own container, not
///    the whole real home — and so is none at all ([`Memory::last_choice`]).
///
/// Whole containers, never a part of one laid over another: the shell's
/// partial overlay (a default container with the sandbox remembered from
/// the last time) made one launch of two containers.
pub fn container_without_dialog(
    memory: &Memory,
    key: &str,
    exists: impl Fn(&str) -> bool,
    reprofile: Option<&str>,
) -> Container {
    if let Some(selector) = reprofile.filter(|s| !s.is_empty()) {
        return Container::from_selector(selector, &exists);
    }
    if !memory.pinned_profile.is_empty() {
        return Container::from_selector(&memory.pinned_profile, &exists);
    }
    match memory.default_profile.as_str() {
        "main" => return Container::default(),
        "own" => return Container::own_sandbox(key),
        "ask" => {}
        name if exists(name) => return Container::from_selector(name, &exists),
        _ => {}
    }
    if let Some(running) = memory
        .running
        .as_ref()
        .and_then(|running| Container::from_selector_checked(&running.selector, &exists))
    {
        return running;
    }
    memory
        .last_choice()
        .and_then(|last| Container::from_selector_checked(last, &exists))
        .unwrap_or_else(|| Container::own_sandbox(key))
}

/// Where a program started by XDG autostart goes, and what had to be guessed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutostartPlan {
    pub zone: String,
    pub container: Container,
    /// No network was chosen for the program: it starts in `offline`.
    pub network_guessed: bool,
    /// No container was chosen and the default is `ask`: it starts in a home
    /// of its own.
    pub container_guessed: bool,
}

/// The decision for an autostart launch — never a dialog.
///
/// What was chosen for the program is honoured without a dialog. What was not
/// chosen is, with `autostart.unassigned = "ask"` (the default since
/// 2026-09-24, the owner's word), the picker's question — see
/// [`autostart_asks`]; with `offline` (2026-09-17 to 2026-09-24), or with no
/// screen to ask on, the closed variant below: a stray click on a dialog drawn
/// at login is a choice nobody made, and the old default started the program
/// uncontained in the host's network.
///
/// * running already — where it runs, like a click would;
/// * the container: the pinned or assigned one; otherwise the global default
///   when it is an answer (`main`, `own`, an existing container); otherwise —
///   `ask` — a home of its own;
/// * the network: the one that container is bound to; otherwise `offline`.
///   Not the last choice and not the global default: those
///   are what a dialog preselects, not a consent to go online unasked.
///
/// `bound_of` is the network a container is bound to, if any.
pub fn autostart_plan(
    memory: &Memory,
    key: &str,
    exists: impl Fn(&str) -> bool,
    bound_of: impl Fn(&Container) -> Option<String>,
) -> AutostartPlan {
    if let Some(running) = &memory.running {
        return AutostartPlan {
            zone: running.zone.clone(),
            container: Container::from_selector(&running.selector, &exists),
            network_guessed: false,
            container_guessed: false,
        };
    }
    let (container, container_guessed) = if !memory.pinned_profile.is_empty() {
        (
            Container::from_selector(&memory.pinned_profile, &exists),
            false,
        )
    } else {
        match memory.default_profile.as_str() {
            "main" => (Container::default(), false),
            "own" => (Container::own_sandbox(key), false),
            name if name != "ask" && exists(name) => {
                (Container::from_selector(name, &exists), false)
            }
            _ => (Container::own_sandbox(key), true),
        }
    };
    // The network of the global default container is not a choice for this
    // program: nobody made one.
    let via_default = memory.pinned_profile.is_empty() && is_default(memory, &container);
    let bound = if container.selector().is_empty() {
        (!memory.bound.is_empty()).then(|| memory.bound.clone())
    } else {
        bound_of(&container).filter(|_| !via_default)
    };
    let (zone, network_guessed) = match bound {
        Some(network) => (network, false),
        None => ("offline".to_owned(), true),
    };
    AutostartPlan {
        zone,
        container,
        network_guessed,
        container_guessed,
    }
}

/// Is this network pin still worth honouring?
///
/// `unconfined` (and its old name `direct`) and `offline` are built-in choices
/// rather than zones, so they are always valid; anything else has to still
/// have a config. A dead pin is
/// removed rather than ignored, or the program would stay bound to a network
/// that does not exist and fail silently on every launch.
/// (`docs/GOTCHAS.md` §11)
pub fn pin_is_valid(pinned: &str, zone_exists: impl Fn(&str) -> bool) -> bool {
    matches!(pinned, "" | "offline")
        || crate::launch::is_unconfined_name(pinned)
        || zone_exists(pinned)
}

/// Is this container pin still worth honouring?
///
/// A container that exists; and the program's own one even before its first
/// launch, which makes it — it used to be checked as something that had to
/// exist, and the pin was erased on the very next click: "🔒 Своя песочница
/// — всегда" did not work at all. (`docs/GOTCHAS.md` §11)
/// A pinned sandbox (`sb:<name>`) likewise: a home of its own is made when it
/// is not there, as it always was.
pub fn profile_pin_is_valid(pinned: &str, profile_exists: impl Fn(&str) -> bool) -> bool {
    match pinned {
        "" | MAIN | THROWAWAY => true,
        other if other.starts_with(SANDBOX_PREFIX) => true,
        other => other.starts_with("app-") || profile_exists(other),
    }
}

// --- THE MENUS ---------------------------------------------------------------

/// One row of a kdialog `--menu`: the tag that comes back on stdout, and the
/// text shown next to it.
pub type Row = (String, String);

/// The unconfined choice, said the way it is: nothing stands between the
/// program and the host — no VPN, and none of its container's settings
/// (review 2026-09-28: the camera, the microphone, the devices, X are the
/// host's there).
pub const UNCONFINED_ROW: (&str, &str) = (
    crate::launch::UNCONFINED,
    "Без изоляции и без VPN — у программы всё, что у хоста: файлы, камера, микрофон, устройства",
);

/// «Без изоляции» (2e of `docs/PERMISSIONS.md` §11.15,
/// `container::OPEN_RECORD`): everything the host has, in the network chosen
/// — a VPN's too. Said as what it opens.
pub const OPEN_ROW: (&str, &str) = (
    crate::container::OPEN_RECORD,
    "⚠ Без изоляции: у программы всё, что у хоста — устройства, сеанс, все файлы; сеть — выбранная",
);

/// The host's own network (2e of `docs/PERMISSIONS.md` §11.15): no VPN, and
/// the program in its container all the same.
pub const HOST_ROW: (&str, &str) = (
    crate::launch::HOST,
    "Сеть хоста — без VPN, программа в своём контейнере",
);

fn row(tag: &str, text: impl Into<String>) -> Row {
    (tag.to_owned(), text.into())
}

/// The network menu: each choice once "for this launch", then bindable
/// choices again as "Всегда: …". Full-host mode has nothing to bind.
///
/// One dialog rather than two steps, because pinning is worth exactly one
/// click. `current_container` is the label of the container that WOULD be used
/// — see [`container_label`].
pub fn net_menu(zones: &[MenuZone], pinned: &str, current_container: &str) -> Vec<Row> {
    let mut nets = vec![
        row(UNCONFINED_ROW.0, UNCONFINED_ROW.1),
        row("offline", "Без сети"),
        row(HOST_ROW.0, HOST_ROW.1),
    ];
    for zone in zones {
        let name = &zone.name;
        // A network through an interface of the host is not a VPN, and the
        // menu must not call it one: nothing about it is encrypted.
        let mut text = if zone.host_interface {
            format!("Через интерфейс: {name} (без шифрования)")
        } else if let Some(path) = &zone.chain_path {
            format!("VPN-цепочка: {path}")
        } else if let Some(system) = &zone.system_zone {
            format!("VPN: {name} (через системное подключение {system})")
        } else {
            format!("VPN: {name}")
        };
        // What `vpn-zone watch` last concluded: choosing a network whose
        // tunnel does not answer should not be a surprise.
        if zone.dead {
            text.push_str(" — туннель не отвечает");
        }
        nets.push(row(name, text));
    }

    let mut menu = nets.clone();
    for (tag, text) in &nets {
        // The full-host launch has no container/network binding to pin.
        // Showing an "always" row here would promise a setting we cannot
        // actually keep without silently reusing a different container.
        if tag == launch::UNCONFINED {
            continue;
        }
        menu.push((format!("pin:{tag}"), format!("Всегда: {text}")));
    }
    menu.push(row(
        "__chooseprofile__",
        format!("⚙ Сменить контейнер (сейчас: {current_container})…"),
    ));
    if !pinned.is_empty() {
        menu.push(row(
            "unpin",
            format!("↺ Спрашивать снова (программа закреплена за контейнером {pinned})"),
        ));
    }
    menu
}

/// A zone as the network menu shows it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MenuZone {
    pub name: String,
    /// Outer-to-inner route as shown to a person, without secrets.
    pub chain_path: Option<String>,
    /// `[HostInterface]`: no tunnel, no encryption.
    pub host_interface: bool,
    /// `[SystemZone]`: the tunnel is this system zone's (`docs/SYSTEM.md` §7b).
    pub system_zone: Option<String>,
    /// `vpn-zone watch` found the tunnel dead at its last look.
    pub dead: bool,
}

/// Resolve only the route's names for display. Read and validation of the
/// route before connection remain the backend's responsibility.
fn chain_path(state: &Path, name: &str) -> Option<String> {
    let mut names = vec![name.to_owned()];
    let mut current = name.to_owned();
    let mut seen = std::collections::BTreeSet::new();
    loop {
        if !seen.insert(current.clone()) {
            return Some("недоступна (цикл)".to_owned());
        }
        let raw = crate::chain::read_zone_config(state, &current).ok()?;
        let ini = crate::config::WgConfig::parse(&raw).ok()?;
        let Some(via) = crate::chain::ChainConfig::from_ini(&ini).ok()? else {
            break;
        };
        names.push(via.via.clone());
        if !via.user {
            break;
        }
        current = via.via;
    }
    (names.len() > 1).then(|| {
        names.reverse();
        names.join(" → ")
    })
}

/// The zones of the state directory with what the menu says about them.
fn menu_zones(state: &Path) -> Vec<MenuZone> {
    zone_names(state)
        .into_iter()
        .map(|name| {
            let ini = crate::chain::read_zone_config(state, &name)
                .ok()
                .and_then(|raw| crate::config::WgConfig::parse(&crate::cli::strip_cr(&raw)).ok());
            let host_interface = ini.as_ref().is_some_and(crate::hostif::is_host_interface);
            let system_zone = ini
                .as_ref()
                .and_then(|ini| crate::sysuplink::SysUplinkConfig::from_ini(ini).ok())
                .map(|s| s.zone);
            let dead = crate::cli::zone_pid(state, name.as_ref()).is_some()
                && fs::read_to_string(state.join(crate::watch::WATCH_DIR).join(&name))
                    .ok()
                    .and_then(|t| crate::watch::parse_memory(&t))
                    .is_some_and(|(_, v)| v == crate::watch::Verdict::Dead);
            let chain_path = chain_path(state, &name);
            MenuZone {
                name,
                chain_path,
                host_interface,
                system_zone,
                dead,
            }
        })
        .collect()
}

/// How the container that is in force right now is described in that entry.
///
/// A PINNED container outranks the last choice here, and that is a fix: without
/// it the entry promised "сейчас: основной" while the program opened in the
/// pinned one — the menu disagreed with what actually happened.
///
/// By the selector alone; [`container_label_in`] knows the kind of its home.
///
/// The word "контейнер" is the one every place that shows this puts in front
/// of it ("контейнер: …", "сеть · …"), so the label is what is left: the
/// launch window's words without it — «основной», «свой», «разовый», or a
/// name with the kind of its home.
pub fn container_label(selector: &str) -> String {
    label_of(selector, None)
}

/// [`container_label`], with the kind of the container's home read.
pub fn container_label_in(tools: &Tools, selector: &str) -> String {
    let home = crate::container::load(tools, selector).map(|c| c.home);
    label_of(selector, home)
}

fn label_of(selector: &str, home: Option<crate::container::Home>) -> String {
    use crate::container::Home;
    match selector {
        "" | MAIN => "настоящий дом".to_owned(),
        crate::container::OPEN_RECORD => "без изоляции".to_owned(),
        other if launch::throwaway_of(other).is_some() => "разовый".to_owned(),
        other => {
            let (name, home) = match other.strip_prefix(SANDBOX_PREFIX) {
                Some(name) => (name, Some(Home::Private)),
                None => (other, home),
            };
            match home {
                Some(Home::Private) | None if name.starts_with("app-") => "свой".to_owned(),
                Some(home) => format!("{name} — {}", home.label()),
                None => name.to_owned(),
            }
        }
    }
}

/// A container as the menu shows it: its name, and the zone it is open in
/// (empty when it is free). `main`: a container of the main home.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileRow {
    pub name: String,
    pub busy_in: String,
    pub main: bool,
    /// The network the container is bound to, empty when it has none yet:
    /// the window does not offer it with another.
    pub bound: String,
    /// The programs open in it now, by their names for a person.
    pub open: Vec<String>,
}

/// A throwaway sandbox that is open: its name (`launch::throwaway_name`),
/// the network its instance is in, and its programs, by their names for a
/// person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenThrowaway {
    pub name: String,
    pub zone: String,
    pub who: Vec<String>,
}

/// A throwaway container that is already open: the directory to join, and the
/// programs living in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TmpJoinRow {
    pub dir: String,
    /// The program names, each with the leading space the shell's
    /// `who="$who $(basename …)"` produced.
    pub who: String,
}

/// The container menu.
///
/// The filesystem sandbox is not a container but a separate property of a
/// launch — it is here because asking about it in a third dialog would be
/// tiring, and because "an isolated home" is what people are actually choosing
/// between when they think about containers.
///
/// The question is asked EVEN WHEN THERE ARE NO CONTAINERS YET. It used to be
/// shown only when one existed, and then there was no way to learn the feature
/// existed without reading the manual: the system quietly decided for you that
/// no container was needed. (`docs/GOTCHAS.md` §11)
pub fn profile_menu(
    sandboxes: &[String],
    profiles: &[ProfileRow],
    tmp_joins: &[TmpJoinRow],
    pinned_profile: &str,
    current_zone: &str,
) -> Vec<Row> {
    use crate::container::Home;
    let mut menu = vec![
        row(
            "",
            "Настоящий дом: все ваши файлы — ключи ssh, пароли браузера, токены",
        ),
        row("pinmain", "Настоящий дом — всегда"),
        row(OPEN_ROW.0, OPEN_ROW.1),
        (
            format!("pin:{}", OPEN_ROW.0),
            format!("{} — всегда", OPEN_ROW.1),
        ),
        // A home of the program's own: permanent, but nobody else's. It differs
        // from a named container with a home of its own only in that the name
        // is picked automatically — it is "an isolated home by default", which
        // can later be merged with another program by choosing a shared one.
        row(
            "__ownsb__",
            "🔒 Свой контейнер: постоянный дом только этой программы",
        ),
        row("pin:__ownsb__", "🔒 Свой контейнер — всегда"),
        row(
            THROWAWAY,
            "🔒 Разовый контейнер: пустой дом, стирается при выходе",
        ),
        row("pin:__fs__", "🔒 Разовый контейнер — всегда"),
    ];
    // Containers with a home of their own: shared by everything started into
    // the same one, so two programs can work together without seeing your
    // files.
    for name in sandboxes {
        let shown = format!("🔒 Контейнер «{name}»: {}", Home::Private.label());
        menu.push((name.clone(), shown.clone()));
        menu.push((format!("pin:{name}"), format!("{shown} — всегда")));
    }
    menu.push(row("__newsb__", "🔒➕ Новый контейнер со своим домом…"));

    // «Без изоляции» has its row above.
    for profile in profiles
        .iter()
        .filter(|p| p.name != crate::container::OPEN_RECORD)
    {
        let name = &profile.name;
        let shown = if profile.main {
            format!("⚠ Контейнер «{name}»: {}", Home::Main.label())
        } else {
            format!("Контейнер «{name}»: {}", Home::Layer.label())
        };
        if !profile.busy_in.is_empty() && profile.busy_in != current_zone && !profile.main {
            menu.push((
                name.clone(),
                format!("{shown} — занят сетью {}", profile.busy_in),
            ));
        } else {
            menu.push((name.clone(), shown.clone()));
        }
        menu.push((format!("pin:{name}"), format!("{shown} — всегда")));
    }

    // Temporary layers that are open right now — so a program can be put
    // into one that is already running (a shared one-off session) instead of
    // starting yet another.
    for join in tmp_joins {
        menu.push((
            format!("{TMPJOIN_PREFIX}{}", join.dir),
            format!("🗑 К открытому временному слою:{}", join.who),
        ));
    }
    menu.push(row(
        TMP,
        "🗑 Временный слой над домом: видит ваш дом, изменения сотрутся, когда выйдет \
         последняя программа",
    ));
    menu.push(row("__new__", "➕ Новый контейнер — слой над домом…"));
    if !pinned_profile.is_empty() {
        menu.push(row("unpinprof", "↺ Спрашивать контейнер снова"));
    }
    menu
}

// --- THE LAUNCH WINDOW (`crate::window`) -------------------------------------

/// The network column: the menu's choices, once — "always" is a checkbox now.
pub fn window_nets(zones: &[MenuZone], selected: &str) -> Vec<window::Item> {
    let mut items = net_menu(zones, "", "")
        .into_iter()
        .take_while(|(tag, _)| !tag.starts_with("pin:"))
        .map(|(tag, label)| {
            let dead = zones.iter().any(|z| z.name == tag && z.dead);
            let label = label
                .strip_suffix(" — туннель не отвечает")
                .map(str::to_owned)
                .unwrap_or(label);
            window::Item {
                selected: tag == selected,
                dead,
                tag,
                label,
                ..window::Item::default()
            }
        })
        .collect::<Vec<_>>();
    // Nothing remembered is offered: `offline`, not the first row.
    if !items.iter().any(|i| i.selected) {
        for it in &mut items {
            it.selected = it.tag == "offline";
        }
    }
    items
}

/// The container column: what the container menu offers, once each.
/// `current` is the selector in force (pinned, set, or the last one).
pub fn window_containers(
    key: &str,
    sandboxes: &[ProfileRow],
    profiles: &[ProfileRow],
    tmp_joins: &[TmpJoinRow],
    fs_open: &[OpenThrowaway],
    current: &str,
) -> Vec<window::Item> {
    use crate::container::Home;
    let item = |tag: &str, label: &str| window::Item {
        tag: tag.to_owned(),
        label: label.to_owned(),
        ..window::Item::default()
    };
    let own = own_name(key);
    let mut items = vec![
        item(
            "",
            "Настоящий дом — все ваши файлы: ключи ssh, пароли браузера, токены",
        ),
        item(
            OPEN_ROW.0,
            "Без изоляции — у программы всё, что у хоста: устройства, сеанс, все файлы",
        ),
        item(
            "__ownsb__",
            "Свой контейнер — постоянный дом только этой программы; будет создан",
        ),
        item(
            THROWAWAY,
            "Новый разовый контейнер — пустой дом, стирается, когда выйдет последняя программа",
        ),
    ];
    // The open ones, right below: one more program into the same empty home,
    // in the network it is in.
    for (n, open) in fs_open.iter().enumerate() {
        let mut it = item(
            &launch::throwaway_selector(&open.name),
            &format!(
                "Открытый разовый контейнер{} — {}",
                if fs_open.len() > 1 {
                    format!(" {}", n + 1)
                } else {
                    String::new()
                },
                open_now(&open.who)
            ),
        );
        it.bound = Some(open.zone.clone());
        items.push(it);
    }
    for row in sandboxes {
        if row.name == own {
            // The program's own: the row above — made already, with its
            // network when it has one.
            if let Some(it) = items.iter_mut().find(|i| i.tag == "__ownsb__") {
                it.label = format!(
                    "Свой контейнер «{}» — постоянный дом только этой программы; создан{}",
                    row.name,
                    open_suffix(&row.open)
                );
                it.bound = Some(row.bound.clone()).filter(|z| !z.is_empty());
            }
            continue;
        }
        let label = format!(
            "Контейнер «{}» — {}{}",
            row.name,
            Home::Private.label(),
            open_suffix(&row.open)
        );
        let mut it = item(&row.name, &label);
        it.busy = Some(row.busy_in.clone()).filter(|z| !z.is_empty());
        it.bound = Some(row.bound.clone()).filter(|z| !z.is_empty());
        items.push(it);
    }
    // «Без изоляции» has its row above.
    for profile in profiles
        .iter()
        .filter(|p| p.name != crate::container::OPEN_RECORD)
    {
        let home = if profile.main {
            Home::Main
        } else {
            Home::Layer
        };
        let label = format!(
            "Контейнер «{}» — {}{}",
            profile.name,
            home.label(),
            open_suffix(&profile.open)
        );
        let mut it = item(&profile.name, &label);
        // The main home is one identity in every network: never "busy".
        it.busy = Some(profile.busy_in.clone()).filter(|z| !z.is_empty() && !profile.main);
        it.bound = Some(profile.bound.clone()).filter(|z| !z.is_empty());
        items.push(it);
    }
    for join in tmp_joins {
        items.push(item(
            &format!("{TMPJOIN_PREFIX}{}", join.dir),
            &format!("К открытому временному слою:{}", join.who),
        ));
    }
    items.push(item(
        TMP,
        "Временный слой над домом — видит ваш дом, изменения сотрутся, когда выйдет \
         последняя программа",
    ));
    let mut new_sandbox = item("__newsb__", "Новый контейнер со своим домом…");
    new_sandbox.new = true;
    items.push(new_sandbox);
    let mut new_profile = item("__new__", "Новый контейнер — слой над домом…");
    new_profile.new = true;
    items.push(new_profile);

    let current = current.strip_prefix(SANDBOX_PREFIX).unwrap_or(current);
    let selected = match current {
        "" | MAIN => "",
        c if c == own => "__ownsb__",
        c => c,
    };
    let mut found = false;
    for it in &mut items {
        it.selected = !found && it.tag == selected;
        found |= it.selected;
    }
    // What was remembered is gone (a sandbox removed, a profile renamed): the
    // program's own sandbox, not the main profile with the whole home.
    if !found {
        for it in &mut items {
            it.selected = it.tag == "__ownsb__";
        }
    }
    items
}

/// "открыт: firefox, foot" — what runs in a container now, for its row.
fn open_now(who: &[String]) -> String {
    format!("открыт: {}", who.join(", "))
}

/// [`open_now`] after a row's text, or nothing when nothing runs there.
fn open_suffix(who: &[String]) -> String {
    if who.is_empty() {
        String::new()
    } else {
        format!("; {}", open_now(who))
    }
}

/// A container answer of the window as the menu would have said it, with its
/// pin: the menu had an "— всегда" row where the window has a checkbox.
pub fn window_container_choice(tag: &str, pin: bool) -> ProfileChoice {
    match tag {
        _ if !pin => parse_profile_choice(tag),
        "" => parse_profile_choice("pinmain"),
        TMP | "__newsb__" | "__new__" => parse_profile_choice(tag),
        // An open one is no choice for always: it ends with its programs.
        t if t.starts_with(TMPJOIN_PREFIX) || launch::throwaway_of(t).is_some() => {
            parse_profile_choice(t)
        }
        t => parse_profile_choice(&format!("pin:{t}")),
    }
}

/// The launch window instead of the two menus. `None`: there is no window to
/// show — none installed, or it would not start — and kdialog asks.
/// `Some(None)`: the window was closed, and the launch is over. Otherwise the
/// network and the container, with their pins already written.
fn ask_window(
    tools: &Tools,
    key: &str,
    label: &str,
    default_net: &str,
    memory: &Memory,
    avoid: Option<&Container>,
) -> Option<Option<(String, Container)>> {
    let startup = StartupTrace::new();
    if tools.window.as_os_str().is_empty() {
        return None;
    }
    let mut req = window_request(tools, key, label, default_net, memory);
    startup.mark("dialog request prepared");
    if avoid.is_some() {
        req.notes.push("Отдельный запуск: выбери другой контейнер/дом. Одна только смена сети не отделяет профиль браузера от уже открытого процесса.".to_owned());
    }
    let reply = match show_window(tools, &req)? {
        Some(reply) => reply,
        None => return Some(None),
    };

    // A single-profile application would pass this launch to the already
    // running copy. Reject that choice before writing pins, permissions or
    // presets: merely trying another container must not change settings.
    if let Some(old) = avoid {
        let same = if reply.net == launch::UNCONFINED {
            old.profile == crate::container::OPEN_RECORD
        } else {
            same_home_choice(tools, key, &reply, old)
        };
        if same {
            return Some(Some((reply.net, old.clone())));
        }
    }

    remember(&tools.state, ".last", key, &reply.net);

    // This is a top-level launch mode, not a network to combine with the
    // previous container. In particular, do not turn a stale container pin
    // or its preset offers into a second, hidden choice.
    if reply.net == launch::UNCONFINED {
        let _ = fs::remove_file(tools.state.join(".pinnedprofile").join(key));
        let _ = fs::remove_file(tools.state.join(".pinned").join(key));
        let container = Container {
            profile: crate::container::OPEN_RECORD.to_owned(),
            ..Container::default()
        };
        return Some(Some((reply.net, container)));
    }

    if !reply.pin_container && !memory.pinned_profile.is_empty() {
        let _ = fs::remove_file(tools.state.join(".pinnedprofile").join(key));
    }
    let is_new = matches!(reply.container.as_str(), "__newsb__" | "__new__");
    let choice = window_container_choice(&reply.container, reply.pin_container);
    let Some(container) = apply_profile_choice(tools, key, choice, reply.name.clone()) else {
        return Some(None);
    };
    let container = match with_files(tools, key, &reply, container) {
        Ok(container) => container,
        Err(why) => {
            let _ = window::navigation_question(
                &tools.window,
                "Запуск остановлен",
                &why,
                &[("close", "Закрыть", false)],
            );
            eprintln!("vpn-zone-pick: запуск остановлен при сохранении файловой политики: {why}");
            return Some(None);
        }
    };
    let selector = container.selector();
    if is_new && reply.pin_container {
        remember(&tools.state, ".pinnedprofile", key, &selector);
    }
    if !container.is_throwaway_container() {
        remember(&tools.state, ".lastprofile", key, &selector);
    }
    let container = with_permissions(tools, key, &reply, container);
    let shared = !reply.pin_container && shared_default(memory, &container, None);
    let _ = fs::remove_file(tools.state.join(".pinned").join(key));
    let container = settle_network(tools, key, container, &reply.net, reply.pin_net, shared);
    // The preset's offers ticked: the chosen container's words — one that
    // keeps words, named or the program's own.
    let keeps = container.selector();
    if !reply.offers.is_empty()
        && !container.is_throwaway_container()
        && crate::container::valid_name(&keeps)
        && keeps != crate::container::OPEN_RECORD
    {
        for line in crate::presets::apply(tools, &keeps, key, &reply.offers) {
            eprintln!("vpn-zone-pick: {line}");
        }
    }
    Some(Some((reply.net, container)))
}

/// The permissions the window changed, where they are kept: the record of
/// the container chosen (made first, for the program's own one not made
/// yet), or this launch's own (`run --with`) for one with no record. What
/// came of each to the journal of the picker, a refusal (Nix's) to the
/// person too.
fn with_permissions(
    tools: &Tools,
    key: &str,
    reply: &window::Reply,
    mut container: Container,
) -> Container {
    let changes = crate::launch_perms::valid(&reply.perms);
    if changes.is_empty() {
        return container;
    }
    let record = match reply.container.as_str() {
        "" => Some(crate::container::MAIN_RECORD.to_owned()),
        "__ownsb__" => {
            let own = own_name(key);
            if !container_exists(tools, &own) {
                if let Err(e) =
                    crate::container::create(tools, &own, crate::container::Home::Private)
                {
                    eprintln!("vpn-zone-pick: свой контейнер «{own}» не создан: {e}");
                }
            }
            Some(own)
        }
        THROWAWAY | TMP => {
            container.with = crate::launch_perms::with_args(&changes);
            None
        }
        "__newsb__" | "__new__" => Some(container.profile.clone()).filter(|p| !p.is_empty()),
        tag if launch::throwaway_of(tag).is_some()
            || tag.starts_with(TMPJOIN_PREFIX)
            || tag == OPEN_ROW.0 =>
        {
            None
        }
        tag => Some(tag.to_owned()),
    };
    if let Some(record) = record {
        for done in crate::launch_perms::apply(tools, &record, &changes) {
            match done {
                Ok(line) => eprintln!("vpn-zone-pick: «{record}»: {line}"),
                Err(why) => {
                    eprintln!("vpn-zone-pick: «{record}»: {why}");
                    dialog::notify(
                        &tools.notify_send,
                        None,
                        "8000",
                        "Разрешение не изменено",
                        &why,
                    );
                }
            }
        }
    }
    container
}

/// Is this container the program's by the global default alone — a named
/// container nobody pinned this program to? Its network is shared by every
/// program that goes there unasked, and is not bound from one of them.
fn shared_default(memory: &Memory, container: &Container, reprofile: Option<&str>) -> bool {
    reprofile.is_none() && memory.pinned_profile.is_empty() && is_default(memory, container)
}

/// Is this container the named global default (`sb:` or not)?
fn is_default(memory: &Memory, container: &Container) -> bool {
    let default = memory.default_profile.as_str();
    !matches!(default, "" | "ask" | "main" | "own")
        && container.selector() == default.strip_prefix(SANDBOX_PREFIX).unwrap_or(default)
}

/// "Always" for a network (`docs/PERMISSIONS.md` §11.8): the network is
/// made the container's — a named container with no network yet is bound to
/// it, the program's own one is made with it, and in the main home the
/// program keeps its own network pin in the built-in main home. Without
/// "always" nothing is bound: a binding is an
/// action of its own, never a side effect of one launch (I1). A throwaway
/// container keeps nothing, and a container that is the program's only by
/// the global default is not bound from it (`shared_default`). A sandbox
/// asked for by name is bound only when it is a home of its own. Returns the
/// container to launch.
fn settle_network(
    tools: &Tools,
    key: &str,
    container: Container,
    net: &str,
    always: bool,
    shared: bool,
) -> Container {
    use crate::container::{Home, Network, Source};
    if net == launch::UNCONFINED {
        return container;
    }
    if !always
        || container.is_throwaway_container()
        || (container.fs_sandbox && container.sandbox.is_empty())
    {
        return container;
    }
    let network = Network::Named(launch::network_name(net).to_owned());
    if container.profile.is_empty() && container.sandbox.is_empty() {
        remember(&tools.state, ".pinned", key, launch::network_name(net));
        remember(&tools.state, ".pinnedprofile", key, MAIN);
        return container;
    }
    if shared {
        let name = container.selector();
        dialog::notify(
            &tools.notify_send,
            None,
            "8000",
            "Сеть не закреплена",
            &format!(
                "«{name}» — контейнер по умолчанию для всех программ: его сеть меняется в его \
                 настройках (cellward container set {name} network …), не одним запуском."
            ),
        );
        return container;
    }
    let (name, private_only) = if container.sandbox.is_empty() {
        (container.profile.clone(), false)
    } else {
        (
            crate::container::sandbox_name(tools, &container.sandbox)
                .unwrap_or_else(|| container.sandbox.clone()),
            true,
        )
    };
    let bound = match crate::container::load(tools, &name) {
        // `run --sandbox` refuses a layer or the main home by that name: its
        // network is not touched either.
        Some(c) if private_only && c.home != Home::Private => Ok(()),
        Some(c) if c.network.value == Network::Ask && c.network.source != Source::Nix => {
            crate::container::set_network(tools, &c.name, &network)
        }
        Some(_) => Ok(()),
        // The program's own, or a new one, made at its first launch: made now,
        // with its network.
        None if private_only => crate::container::create(tools, &name, Home::Private)
            .and_then(|c| crate::container::set_network(tools, &c.name, &network)),
        None => Ok(()),
    };
    if let Err(why) = bound {
        eprintln!("vpn-zone-pick: сеть контейнера {name}: {why}");
    }
    container
}

/// The containers the menus offer: those with a home of their own, and the
/// rest (a layer, the main home) with the network each is open in.
fn container_rows(tools: &Tools) -> (Vec<ProfileRow>, Vec<ProfileRow>) {
    use crate::container::{Home, Network};
    let running = tools.state.join(".running");
    let mut sandboxes = Vec::new();
    let mut profiles = Vec::new();
    for c in crate::container::load_all(tools) {
        // A name a menu takes for a command of its own is not shown.
        if reserved_name(&c.name) {
            continue;
        }
        let bound = match &c.network.value {
            Network::Named(net) => net.clone(),
            Network::Ask => String::new(),
        };
        let busy_in = live_tenant(&running, &c.dir.join("inuse"))
            .or_else(|| crate::container::running_network(tools, &c))
            .unwrap_or_default();
        let row = ProfileRow {
            main: c.home == Home::Main,
            name: c.name.clone(),
            busy_in,
            bound,
            open: open_programs(&tools.state, &running.join(&c.name), |_| true),
        };
        if c.home == Home::Private {
            sandboxes.push(row);
        } else {
            profiles.push(row);
        }
    }
    (sandboxes, profiles)
}

/// The programs with a live record in the registry directory `dir` whose
/// selector `takes`, by their names for a person (`.labels`), each once.
fn open_programs(state: &Path, dir: &Path, takes: impl Fn(&str) -> bool) -> Vec<String> {
    let running = state.join(".running");
    let alive = |pid| registry::alive(&running, pid);
    let mut who: Vec<String> = Vec::new();
    for (key, record) in registry::live_records(dir, &alive) {
        if !takes(&record.selector) {
            continue;
        }
        let name = read_setting(&state.join(".labels").join(&key)).unwrap_or(key);
        if !who.contains(&name) {
            who.push(name);
        }
    }
    who.sort();
    who
}

/// The throwaway sandboxes open now, from the registry: the records whose
/// selector names one (`launch::throwaway_selector`), in a network an
/// instance has — a throwaway sandbox of the host's network has none to
/// join, its home is its program's alone.
fn open_throwaway_sandboxes(state: &Path) -> Vec<OpenThrowaway> {
    let running = state.join(".running");
    let alive = |pid| registry::alive(&running, pid);
    let mut out: Vec<OpenThrowaway> = Vec::new();
    for dir in registry::dirs(&running) {
        for (_, record) in registry::live_records(&dir, &alive) {
            let Some(Some(name)) = launch::throwaway_of(&record.selector) else {
                continue;
            };
            let zone = launch::network_name(&record.zone);
            if launch::is_unconfined_name(zone) || out.iter().any(|o| o.name == name) {
                continue;
            }
            let selector = record.selector.clone();
            out.push(OpenThrowaway {
                name: name.to_owned(),
                zone: zone.to_owned(),
                who: open_programs(state, &dir, |s| s == selector),
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// What the launch window is asked: both columns as the memory has them.
fn window_request(
    tools: &Tools,
    key: &str,
    label: &str,
    default_net: &str,
    memory: &Memory,
) -> window::Request {
    let running = tools.state.join(".running");
    let (sandboxes, profiles) = container_rows(tools);
    // In force: the pin, then the global setting, then the running copy's,
    // then the last choice.
    let current = if !memory.pinned_profile.is_empty() {
        memory.pinned_profile.clone()
    } else {
        match memory.default_profile.as_str() {
            "ask" => match &memory.running {
                Some(running) => running.selector.clone(),
                None => memory
                    .last_choice()
                    .map_or_else(|| own_name(key), str::to_owned),
            },
            "main" => String::new(),
            "own" => own_name(key),
            name => name.to_owned(),
        }
    };
    let mut req = window::Request {
        host_home: tools.home.display().to_string(),
        folder_protected: crate::container::grant_protected_paths(tools)
            .into_iter()
            .map(|p| p.display().to_string())
            .collect(),
        title: format!("Запуск: {label}"),
        notes: Vec::new(),
        nets: window_nets(&menu_zones(&tools.state), default_net),
        containers: window_containers(
            key,
            &sandboxes,
            &profiles,
            &open_throwaways(&running),
            &open_throwaway_sandboxes(&tools.state),
            &current,
        ),
        // "Always" for the network is for the main home only: a container's
        // network is its own once chosen.
        pin_net: false,
        pin_container: !memory.pinned_profile.is_empty(),
        // What the program's preset only offers its container (step 3 of
        // `docs/PERMISSIONS.md` §11.15): a checkbox each, unticked.
        offers: crate::presets::for_key(&tools.config, key)
            .map(|preset| {
                crate::presets::launch_offered(&preset)
                    .iter()
                    .map(|item| (item.line(), item.text()))
                    .collect()
            })
            .unwrap_or_default(),
        ..window::Request::default()
    };
    if let Some(running) = &memory.running {
        let zone = launch::network_name(&running.zone);
        let shown = req
            .nets
            .iter()
            .find(|n| n.tag == zone)
            .map_or(zone, |n| n.label.as_str());
        req.notes.push(format!("Уже открыта: {shown}"));
    }
    // What each container may do, as it is now, to change right there.
    req.perms = crate::launch_perms::rows(tools);
    let open: Vec<(&str, &[String])> = sandboxes
        .iter()
        .chain(&profiles)
        .map(|r| (r.name.as_str(), r.open.as_slice()))
        .collect();
    let own = own_name(key);
    let own_made = sandboxes.iter().any(|r| r.name == own);
    req.perm_of = req
        .containers
        .iter()
        .filter_map(|item| {
            let scope = perm_scope(&item.tag, &own, own_made, &open)?;
            let values = match scope {
                PermScope::Record(record) => crate::launch_perms::of_record(tools, record),
                PermScope::New => crate::launch_perms::of_new(),
                PermScope::Launch => crate::launch_perms::of_launch(false),
                PermScope::Joined | PermScope::Open => crate::launch_perms::of_launch(true),
            };
            Some(crate::launch_perms::perm_of(
                &item.tag,
                crate::launch_perms::scope(scope.kind(&item.tag, &own, own_made, &open)),
                if scope == PermScope::Open {
                    Vec::new()
                } else {
                    values
                },
            ))
        })
        .collect();
    req.files = req
        .containers
        .iter()
        .map(|c| launch_files(tools, key, &c.tag))
        .collect();
    req
}

/// Filesystem state is computed by the host, never inferred by the GUI from a
/// container's friendly label. In particular legacy `home` remains visible.
fn launch_files(tools: &Tools, key: &str, tag: &str) -> window::FileAccess {
    let record = match tag {
        "" => crate::container::MAIN_RECORD.to_owned(),
        "__ownsb__" => own_name(key),
        "__new__" | "__newsb__" => String::new(),
        other => other.to_owned(),
    };
    let loaded = crate::container::load(tools, &record);
    let sandbox =
        (!record.is_empty() && record != crate::container::MAIN_RECORD).then_some(record.as_str());
    let legacy = crate::fs_sandbox::saved_permissions(&tools.home, key, sandbox);
    let mut paths = Vec::new();
    for (yes, path) in [
        (legacy.downloads, "~/Downloads"),
        (legacy.documents, "~/Documents"),
        (legacy.pictures, "~/Pictures"),
    ] {
        if yes {
            paths.push((path.to_owned(), "legacy · чтение и запись".to_owned()));
        }
    }
    if legacy.home {
        paths.push((
            "~ (весь настоящий дом)".to_owned(),
            "legacy · чтение и запись".to_owned(),
        ));
    }
    if let Some(c) = &loaded {
        for p in &c.paths {
            paths.push((
                p.value.display().to_string(),
                format!("{} · чтение и запись", p.source.as_str()),
            ));
        }
    }
    match crate::folder_rules::load(tools, &record) {
        Ok(rules) => {
            for rule in rules {
                paths.push((
                    rule.path.display().to_string(),
                    format!("rule:{}", rule.mode.word()),
                ));
            }
        }
        Err(why) => paths.push(("Политика папок не прочитана".into(), why)),
    }
    let persistent = tag == ""
        || tag == "__ownsb__"
        || tag == "__new__"
        || tag == "__newsb__"
        || loaded.is_some();
    window::FileAccess {
        tag: tag.to_owned(),
        home: if legacy.home {
            "main".to_owned()
        } else {
            loaded
                .as_ref()
                .map(|c| c.home.setting().to_owned())
                .unwrap_or_else(|| {
                    if tag == "__new__" {
                        "layer".into()
                    } else {
                        "private".into()
                    }
                })
        },
        editable: persistent
            && tag != ""
            && !legacy.home
            && loaded
                .as_ref()
                .is_none_or(|c| c.home_source != crate::container::Source::Nix),
        paths,
    }
}

/// Apply only the policy explicitly returned by the integrated host dialog.
/// Any refusal stops the launch; it must not silently use broader access.
fn with_files(
    tools: &Tools,
    key: &str,
    reply: &window::Reply,
    mut selected: Container,
) -> Result<Container, String> {
    if !reply.files_reviewed {
        return Ok(selected);
    } // older GUI / CLI fallback
    let own = own_name(key);
    let record = if reply.container.is_empty() {
        crate::container::MAIN_RECORD.to_owned()
    } else if reply.container == "__ownsb__" {
        own
    } else {
        selected.selector()
    };
    let persistent = reply.container.is_empty()
        || reply.container == "__ownsb__"
        || crate::container::load(tools, &record).is_some();
    if !persistent {
        if !reply.grants.is_empty() || reply.home.is_some() {
            return Err("Изменения папок для временного контейнера пока недоступны; выберите постоянный контейнер".into());
        }
        return Ok(selected);
    }
    if crate::container::load(tools, &record).is_none() {
        crate::container::create(tools, &record, crate::container::Home::Private)?;
    }
    // Reject invalid drafts before changing the base home. Launch is one
    // confirmation, not a sequence of broader partially-applied choices.
    let current = crate::container::load(tools, &record).ok_or("контейнер не найден")?;
    let target_home = reply
        .home
        .as_deref()
        .and_then(crate::container::Home::parse)
        .unwrap_or(current.home);
    for grant in &reply.grants {
        let (mode, path) = grant
            .split_once('\t')
            .ok_or("неверный формат доступа к папке")?;
        if mode == "inherit" {
            continue;
        }
        if target_home == crate::container::Home::Main {
            return Err(
                "Для правил папок выберите свой дом или слой; настоящий дом уже доступен напрямую"
                    .into(),
            );
        }
        crate::folder_rules::Mode::parse(mode).ok_or("неизвестный режим папки")?;
        let path = path
            .strip_prefix("~/")
            .map(|p| tools.home.join(p))
            .unwrap_or_else(|| std::path::PathBuf::from(path));
        let real = crate::folder_rules::validate(&tools.home, &path)?;
        for protected in [
            &tools.config,
            &tools.state,
            &tools.profiles,
            &tools.sandboxes,
        ] {
            let canonical = fs::canonicalize(protected).unwrap_or_else(|_| protected.clone());
            if [&path, &real].iter().any(|p| {
                p.starts_with(protected)
                    || protected.starts_with(p)
                    || p.starts_with(&canonical)
                    || canonical.starts_with(p)
            }) {
                return Err("состояние Cellward не выдаётся".into());
            }
        }
        if current.paths.iter().any(|p| {
            p.source == crate::container::Source::Nix
                && (p.value.starts_with(&path) || path.starts_with(&p.value))
        }) {
            return Err("пересекающийся доступ задан в Nix — измените его там".into());
        }
    }
    if let Some(home) = &reply.home {
        let shown = launch_files(tools, key, &reply.container);
        if !shown.editable {
            return Err("Вид дома задан в Nix, унаследован из старых разрешений или принадлежит настоящему дому".into());
        }
        let home = crate::container::Home::parse(home).ok_or("неизвестный вид дома")?;
        crate::container::set_home(tools, &record, home)?;
        selected = Container::from_selector(&record, |n| container_exists(tools, n));
    }
    if record != crate::container::MAIN_RECORD {
        selected = Container::from_selector(&record, |n| container_exists(tools, n));
    }
    for grant in &reply.grants {
        let (mode, path) = grant
            .split_once('\t')
            .ok_or("неверный формат доступа к папке")?;
        crate::folder_rules::set(tools, &record, mode, path)?;
    }
    let sandbox = (record != crate::container::MAIN_RECORD).then_some(record.as_str());
    crate::fs_sandbox::confirm_permissions(&tools.home, key, sandbox)?;
    Ok(selected)
}

/// Where the permissions of a container row of the window are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PermScope<'a> {
    /// Its record: the real home's, the program's own, a named one's.
    Record(&'a str),
    /// One to be made: nothing of its own yet.
    New,
    /// None to keep them: this launch's alone (a new throwaway one).
    Launch,
    /// An open throwaway one: what it was opened with.
    Joined,
    /// «Без изоляции»: everything, nothing to say.
    Open,
}

impl<'a> PermScope<'a> {
    fn kind(
        self,
        tag: &'a str,
        own: &'a str,
        own_made: bool,
        open: &[(&'a str, &'a [String])],
    ) -> crate::launch_perms::Scope<'a> {
        use crate::launch_perms::Scope;
        match self {
            PermScope::Record(crate::container::MAIN_RECORD) => Scope::Main,
            PermScope::Record(name) if name == own => Scope::Own(own, own_made),
            PermScope::Record(name) => Scope::Named(
                name,
                open.iter()
                    .find(|(n, _)| *n == name)
                    .map_or(&[][..], |(_, o)| *o),
            ),
            PermScope::New if tag == "__ownsb__" => Scope::Own(own, false),
            PermScope::New => Scope::New,
            PermScope::Launch => Scope::Launch,
            PermScope::Joined => Scope::Joined,
            PermScope::Open => Scope::Open,
        }
    }
}

/// The permissions of the window's container row `tag`: whose they are.
/// `None` for a row it does not know.
fn perm_scope<'a>(
    tag: &'a str,
    own: &'a str,
    own_made: bool,
    open: &[(&'a str, &'a [String])],
) -> Option<PermScope<'a>> {
    Some(match tag {
        "" => PermScope::Record(crate::container::MAIN_RECORD),
        t if t == OPEN_ROW.0 => PermScope::Open,
        "__ownsb__" if own_made => PermScope::Record(own),
        "__ownsb__" | "__newsb__" | "__new__" => PermScope::New,
        THROWAWAY | TMP => PermScope::Launch,
        t if launch::throwaway_of(t).is_some() || t.starts_with(TMPJOIN_PREFIX) => {
            PermScope::Joined
        }
        t => PermScope::Record(open.iter().find(|(n, _)| *n == t)?.0),
    })
}

/// Show the launch window. `None`: it would not start. `Some(None)`: closed,
/// or an answer that is none — the launch is over. Only what was offered
/// comes back: an answer from outside the lists starts nothing.
fn restrict_reply_offers(req: &window::Request, reply: &mut window::Reply) {
    // A stale/foreign window must not add a preset grant which was not
    // actually shown, particularly one superseded by a permission row.
    reply
        .offers
        .retain(|line| req.offers.iter().any(|(allowed, _)| allowed == line));
}

fn show_window(tools: &Tools, req: &window::Request) -> Option<Option<window::Reply>> {
    let startup = StartupTrace::new();
    let mut child = Command::new(&tools.window)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(
            if std::env::var_os("CELLWARD_TRACE_STARTUP").as_deref()
                == Some(std::ffi::OsStr::new("1"))
            {
                Stdio::inherit()
            } else {
                Stdio::null()
            },
        )
        .spawn()
        .ok()?;
    startup.mark("dialog process spawned (not first frame)");
    if let Some(mut stdin) = child.stdin.take() {
        let _ = std::io::Write::write_all(&mut stdin, window::render(req).as_bytes());
    }
    startup.mark("dialog request delivered (not first frame)");
    // From here on a failure is a close, never the menus on top of a window
    // the person has already answered.
    let Ok(out) = child.wait_with_output() else {
        return Some(None);
    };
    if !out.status.success() {
        return Some(None);
    }
    let Some(mut reply) = window::parse_reply(&String::from_utf8_lossy(&out.stdout)) else {
        return Some(None);
    };
    // Only what was offered: an answer from outside the list starts nothing.
    let offered_net = req.nets.iter().any(|n| n.tag == reply.net);
    let offered_container = req.containers.iter().any(|c| c.tag == reply.container);
    if !offered_net || !offered_container {
        eprintln!("vpn-zone-pick: окно запуска ответило тем, чего не предлагали — не запускаю");
        return Some(None);
    }
    restrict_reply_offers(req, &mut reply);
    Some(Some(reply))
}

// --- WHAT CAME BACK ----------------------------------------------------------

/// The answer to the network dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetChoice {
    /// An empty answer. kdialog exits 0 with nothing on stdout when the menu
    /// was dismissed, and the shell checked for it separately.
    Nothing,
    ChooseContainer,
    Unpin,
    Pin(String),
    Zone(String),
}

pub fn parse_net_choice(tag: &str) -> NetChoice {
    match tag {
        "" => NetChoice::Nothing,
        "__chooseprofile__" => NetChoice::ChooseContainer,
        "unpin" => NetChoice::Unpin,
        other => match other.strip_prefix("pin:") {
            Some(zone) => NetChoice::Pin(zone.to_owned()),
            None => NetChoice::Zone(other.to_owned()),
        },
    }
}

/// The answer to the container dialog. `pin` means the choice is also written
/// to `.pinnedprofile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileChoice {
    Main {
        pin: bool,
    },
    OwnSandbox {
        pin: bool,
    },
    Throwaway {
        pin: bool,
    },
    /// The open throwaway sandbox of this name: one more program in it.
    ThrowawayJoin(String),
    Sandbox {
        name: String,
        pin: bool,
    },
    NewSandbox,
    Tmp,
    TmpJoin(String),
    NewProfile,
    Unpin,
    Profile {
        name: String,
        pin: bool,
    },
}

/// Order matters and is the shell's `case` order: `pin:__ownsb__`,
/// `pin:sb:<name>` and `pin:__fs__` all have to be recognised before the plain
/// `pin:<container>` pattern would swallow them.
pub fn parse_profile_choice(tag: &str) -> ProfileChoice {
    match tag {
        "" => ProfileChoice::Main { pin: false },
        "pinmain" => ProfileChoice::Main { pin: true },
        "__ownsb__" => ProfileChoice::OwnSandbox { pin: false },
        "pin:__ownsb__" => ProfileChoice::OwnSandbox { pin: true },
        THROWAWAY => ProfileChoice::Throwaway { pin: false },
        "pin:__fs__" => ProfileChoice::Throwaway { pin: true },
        "__newsb__" => ProfileChoice::NewSandbox,
        TMP => ProfileChoice::Tmp,
        "__new__" => ProfileChoice::NewProfile,
        "unpinprof" => ProfileChoice::Unpin,
        other => {
            if let Some(Some(name)) = launch::throwaway_of(other) {
                return ProfileChoice::ThrowawayJoin(name.to_owned());
            }
            if let Some(name) = other.strip_prefix(SANDBOX_PREFIX) {
                return ProfileChoice::Sandbox {
                    name: name.to_owned(),
                    pin: false,
                };
            }
            if let Some(dir) = other.strip_prefix(TMPJOIN_PREFIX) {
                return ProfileChoice::TmpJoin(dir.to_owned());
            }
            match other.strip_prefix("pin:") {
                Some(rest) => match rest.strip_prefix(SANDBOX_PREFIX) {
                    Some(name) => ProfileChoice::Sandbox {
                        name: name.to_owned(),
                        pin: true,
                    },
                    None => ProfileChoice::Profile {
                        name: rest.to_owned(),
                        pin: true,
                    },
                },
                None => ProfileChoice::Profile {
                    name: other.to_owned(),
                    pin: false,
                },
            }
        }
    }
}

// --- THE COMMAND LINE THAT COMES OUT -----------------------------------------

/// `vpn-zone run <zone> [container flags] [sandbox flags] -- cmd…`
///
/// The order is the one [`crate::launch::Selection::parse`] expects: the
/// container flag first, the sandbox flag second, `--` and then the command.
pub fn run_argv(
    runner: &Path,
    zone: &str,
    container: &Container,
    cmd: &[OsString],
) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec![runner.into(), "run".into(), zone.into()];
    if let Some(dir) = container.profile.strip_prefix(TMPJOIN_PREFIX) {
        argv.push("--tmp-profile".into());
        argv.push("--join".into());
        argv.push(dir.into());
    } else if container.profile == TMP {
        argv.push("--tmp-profile".into());
    } else if !container.profile.is_empty() {
        argv.push("--container".into());
        argv.push(container.profile.as_str().into());
    }
    if !container.sandbox.is_empty() {
        argv.push("--sandbox".into());
        argv.push(container.sandbox.as_str().into());
    } else if container.fs_sandbox {
        argv.push("--fs-sandbox".into());
        if !container.join.is_empty() {
            argv.push("--join".into());
            argv.push(container.join.as_str().into());
        }
    }
    argv.extend(container.with.iter().cloned());
    argv.push("--".into());
    argv.extend(cmd.iter().cloned());
    argv
}

// --- THE PROGRAM -------------------------------------------------------------

/// Entry point of the `vpn-zone-pick` binary.
/// Opt-in startup milestones. Never log argv, clipboard contents or destinations.
/// Times end before waiting for a person's reply; that wait is not UI startup.
struct StartupTrace(Option<std::time::Instant>);

impl StartupTrace {
    fn new() -> Self {
        Self(
            (std::env::var_os("CELLWARD_TRACE_STARTUP").as_deref()
                == Some(std::ffi::OsStr::new("1")))
            .then(std::time::Instant::now),
        )
    }

    fn mark(&self, stage: &str) {
        if let Some(started) = self.0 {
            eprintln!(
                "cellward startup [{}]: {stage}: {} ms",
                std::process::id(),
                started.elapsed().as_millis()
            );
        }
    }
}

pub fn main() -> ExitCode {
    let startup = StartupTrace::new();
    // From a program of another launch: the session's compositor, for the
    // window and the launch (`wl_sandbox::session_compositor`).
    crate::wl_sandbox::session_compositor();
    // `args_os`: a launcher hands file names through `%U` field codes, and file
    // names are bytes.
    let argv: Vec<OsString> = std::env::args_os().skip(1).collect();
    let args = Args::parse(&argv);
    if args.cmd.is_empty() {
        eprintln!("нечего запускать");
        return ExitCode::from(1);
    }

    let tools = match Tools::from_env() {
        Ok(tools) => tools,
        Err(e) => {
            eprintln!("vpn-zone-pick: {e}");
            return ExitCode::from(EXIT_TOOLS);
        }
    };
    startup.mark("tools loaded");
    for dir in [".last", ".lastprofile", ".pinnedprofile", ".labels"] {
        let _ = fs::create_dir_all(tools.state.join(dir));
    }
    let _ = fs::create_dir_all(&tools.config);

    let key = match &args.id {
        Some(id) => crate::desktop::stable_key(&id.to_string_lossy()),
        None => sanitize(&fallback_key(&args.cmd).to_string_lossy()),
    };

    // From inside a zone the question is the host's: the zone sees none of
    // the zones (`zone::hide_project_state`), and a window the zone draws is
    // one its programs could draw as well. The broker shows it
    // (`broker::pick`). No broker to ask — a zone from before it — and the
    // picker asks here, as before; `run` still goes through the broker.
    // Not for a container of the host's network (`unconfined` in the
    // variable): it sees the state, and the broker knows no zone of it.
    let in_zone = std::env::var(launch::ENV_CURRENT)
        .is_ok_and(|z| !z.is_empty() && !launch::is_unconfined_name(&z));
    if args.from_zone.is_none() && in_zone {
        if let Some(code) = crate::broker::pick(key.as_bytes(), &args.cmd) {
            return ExitCode::from(code);
        }
    }

    let picker_lock = match PickerLock::take(&tools.state, &key) {
        Ok(Some(lock)) => lock,
        Ok(None) => {
            eprintln!("vpn-zone-pick: выбор для «{key}» уже открыт");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("vpn-zone-pick: не защитить единственный выбор для «{key}»: {e}");
            return ExitCode::from(EXIT_NOT_STARTED);
        }
    };

    // The name for the dialogs: from the label the shortcut generator left, or
    // from `--label`, or the key itself.
    let label = match &args.label {
        Some(label) => {
            let text = label.to_string_lossy().into_owned();
            let _ = fs::write(tools.state.join(".labels").join(&key), &text);
            text
        }
        None => {
            read_setting(&tools.state.join(".labels").join(&key)).unwrap_or_else(|| key.clone())
        }
    };

    // Read the hand-over variable AT ONCE and take it out of the environment:
    // otherwise it would travel into the program itself, and a link opened from
    // there would inherit somebody else's container.
    let reprofile = std::env::var(ENV_PROFILE).ok().filter(|v| !v.is_empty());
    std::env::remove_var(ENV_PROFILE);

    if let Some(zone) = &args.from_zone {
        let memory = read_memory_with(&tools, &key, false);
        return pick_for_zone(
            &tools,
            &key,
            &memory,
            &args.cmd,
            zone,
            args.locked,
            args.offer_rule.as_deref(),
            args.from_container.as_deref(),
        );
    }
    let memory = read_memory(&tools, &key);
    startup.mark("launch state loaded (before any container startup)");
    if args.autostart {
        // For the launch: a network refused at an autostart question of this
        // session is not asked again (`connect::autostart_launch`).
        std::env::set_var(launch::ENV_AUTOSTART, "1");
        if let Some(code) = autostart(&tools, &key, &label, &memory, &args.cmd) {
            return code;
        }
        // Nothing chosen for it, and the setting says ask (owner, 2026-09-24):
        // the same picker a click shows, with its "always".
        eprintln!("vpn-zone-pick: автозапуск «{label}»: для неё ничего не выбрано — спрашиваю");
    }
    let zone_choice: String;
    // The network was chosen here, "always" or not: made the container's
    // once the container is known (`settle_network`).
    let mut chosen: Option<bool> = None;

    match net_step(&memory) {
        // Watched as an asked launch is (`launch_asked`): a hand-over ends
        // without a window of its own, and the window of the copy that runs
        // is then raised for the person's click.
        NetStep::Running { zone, selector } => {
            let mut container =
                Container::from_selector(&selector, |n| container_exists(&tools, n));
            let choice = if !container.join.is_empty() {
                again_in_throwaway(&tools, &label)
            } else {
                again_running(&tools, &label, &zone, &selector)
            };
            match choice {
                Again::There => {
                    if let Err(why) = raise_running(&tools, &key, &zone, &selector) {
                        tell_not_raised(&tools, &label, &why);
                        return ExitCode::from(1);
                    }
                    return ExitCode::SUCCESS;
                }
                Again::Same => {}
                Again::New if !container.join.is_empty() => container.join.clear(),
                Again::New => {
                    // A second browser with the same home would hand its
                    // command to the old process. Only a different home is
                    // offered as a separate instance, regardless of network.
                    if launch::has_display() {
                        // This is one unfinished launch, not a fresh picker
                        // invocation. Keep its network across validation
                        // failures without writing a last choice or a pin.
                        let mut draft_zone = zone.clone();
                        loop {
                            match ask_window(
                                &tools,
                                &key,
                                &label,
                                &draft_zone,
                                &memory,
                                Some(&container),
                            ) {
                                Some(Some((chosen_zone, chosen_container)))
                                    if separate_home(&container, &chosen_container) =>
                                {
                                    return launch_asked(
                                        &tools,
                                        &key,
                                        &label,
                                        &chosen_zone,
                                        &chosen_container,
                                        &args.cmd,
                                        &memory,
                                    );
                                }
                                Some(Some((chosen_zone, _))) => {
                                    draft_zone = chosen_zone;
                                    let answers = [
                                        ("again", "Выбрать другой контейнер", false),
                                        ("cancel", "Отмена", false),
                                    ];
                                    let text = "Это тот же контейнер и дом, что у открытого браузера. Новый запуск может передать команду старому процессу в прежней сети. Для отдельной копии выбери другой контейнер.";
                                    if !matches!(crate::window::question(&tools.window, "Не отдельная копия", text, None, &answers, None), crate::window::Asked::Chose(tag) if tag == "again")
                                    {
                                        return ExitCode::SUCCESS;
                                    }
                                }
                                _ => return ExitCode::SUCCESS,
                            }
                        }
                    }
                    return ExitCode::SUCCESS;
                }
                Again::Nothing => return ExitCode::SUCCESS,
            }
            return launch_asked(&tools, &key, &label, &zone, &container, &args.cmd, &memory);
        }
        NetStep::Bound { zone } => zone_choice = zone,
        NetStep::Ask { default } => {
            // The row the question starts on: the remembered one while it is
            // still offered, else `offline` — never whatever comes first, which
            // is the host's network. A zone removed after `vpn-zone default`
            // named it (or after it was last chosen) is not offered.
            let default = if default == "offline"
                || default == launch::UNCONFINED
                || menu_zones(&tools.state).iter().any(|z| z.name == default)
            {
                default
            } else {
                "offline".to_owned()
            };
            // One window for both questions, where there is one.
            if launch::has_display() {
                match ask_window(&tools, &key, &label, &default, &memory, None) {
                    Some(Some((zone, container))) => {
                        return launch_asked(
                            &tools, &key, &label, &zone, &container, &args.cmd, &memory,
                        )
                    }
                    Some(None) => return ExitCode::SUCCESS,
                    None => {}
                }
            }
            let current = if memory.pinned_profile.is_empty() {
                &memory.last_profile
            } else {
                &memory.pinned_profile
            };
            // "↺" only for a pin of the picker's own: one declared in Nix is
            // not undone here.
            let local_pin = tools.state.join(".pinnedprofile").join(&key).is_file();
            let menu = net_menu(
                &menu_zones(&tools.state),
                if local_pin {
                    &memory.pinned_profile
                } else {
                    ""
                },
                &container_label_in(&tools, current),
            );

            let answer = if launch::has_display() {
                let mut argv: Vec<OsString> = vec![
                    "--title".into(),
                    format!("Куда пустить «{label}»?").into(),
                    "--default".into(),
                    default.as_str().into(),
                    "--menu".into(),
                    "Выбери сеть для запуска".into(),
                ];
                push_rows(&mut argv, &menu);
                match dialog::ask(&tools.kdialog, &argv) {
                    Some(answer) => answer,
                    // Cancelled: the launch is over, and quietly.
                    None => return ExitCode::SUCCESS,
                }
            } else {
                // Nowhere to show a dialog: kdialog dies immediately, and
                // taking that for a cancel turned a click (or a launch from a
                // terminal) into silence. Take what WOULD have been selected —
                // the last choice, or the global default.
                // (`docs/GOTCHAS.md` §5)
                eprintln!("vpn-zone-pick: спросить негде (нет графики) — беру «{default}»");
                default.clone()
            };

            let choice = parse_net_choice(&answer);
            // "↺ Спрашивать снова": the program's container pin goes — the
            // network is the container's — and the container is asked right
            // away, as "⚙ Сменить контейнер" does. Not a pass that falls back
            // to whatever the memory had, the main home with nothing.
            if choice == NetChoice::Unpin {
                let _ = fs::remove_file(tools.state.join(".pinnedprofile").join(&key));
            }
            match choice {
                NetChoice::Nothing => return ExitCode::SUCCESS,
                NetChoice::ChooseContainer | NetChoice::Unpin => {
                    // The container is asked here and the network question is
                    // then asked again by a second pass of this same binary.
                    let Some(container) = ask_profile(
                        &tools,
                        &key,
                        &label,
                        "__chooseprofile__",
                        // After "↺" the pin is gone: the menu does not
                        // offer to drop it again.
                        &Memory {
                            pinned_profile: if choice == NetChoice::Unpin {
                                String::new()
                            } else {
                                memory.pinned_profile.clone()
                            },
                            ..memory.clone()
                        },
                    ) else {
                        return ExitCode::SUCCESS;
                    };
                    let selector = container.selector();
                    if !container.is_throwaway_container() {
                        remember(&tools.state, ".lastprofile", &key, &selector);
                    }
                    // The choice is handed over in a VARIABLE as well as in the
                    // file. A one-off container is not written to `.lastprofile`
                    // (that would make it permanent) and used to be lost
                    // completely across the re-exec: the user chose "🗑 Новый
                    // временный" and the program quietly opened in the previous,
                    // permanent container. For a sandbox that is a loss of
                    // isolation, not a detail. An empty choice ("Основной")
                    // travels as `__main__`: an empty string cannot be told
                    // apart from "not set".
                    let handover = if selector.is_empty() {
                        MAIN.to_owned()
                    } else {
                        selector
                    };
                    return reexec(&tools, &picker_lock, &key, &args.cmd, Some(&handover));
                }
                NetChoice::Pin(zone) => {
                    chosen = Some(true);
                    zone_choice = zone;
                }
                NetChoice::Zone(zone) => {
                    chosen = Some(false);
                    zone_choice = zone;
                }
            }
            remember(&tools.state, ".last", &key, &zone_choice);
        }
    }

    // The container: the one pinned, set globally, or remembered — the
    // network question above was about it.
    let container = container_without_dialog(
        &memory,
        &key,
        |name| container_exists(&tools, name),
        reprofile.as_deref(),
    );
    let container = match chosen {
        Some(always) => {
            if zone_choice == launch::UNCONFINED && launch::has_display() {
                // The person selected the top-level "no isolation" action.
                // Older saved pins and autostart bindings still retain their
                // container: changing them silently on upgrade would expose
                // a previously isolated program to the real home.
                let open = Container {
                    profile: crate::container::OPEN_RECORD.to_owned(),
                    ..Container::default()
                };
                return launch_asked(
                    &tools,
                    &key,
                    &label,
                    &zone_choice,
                    &open,
                    &args.cmd,
                    &memory,
                );
            }
            let shared = shared_default(&memory, &container, reprofile.as_deref());
            settle_network(&tools, &key, container, &zone_choice, always, shared)
        }
        None => container,
    };

    launch_asked(
        &tools,
        &key,
        &label,
        &zone_choice,
        &container,
        &args.cmd,
        &memory,
    )
}

/// The answer to [`again_in_throwaway`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Again {
    There,
    Same,
    New,
    Nothing,
}

/// A different network alone is not a second instance of a single-profile
/// browser. It needs a different home/container identity.
fn separate_home(old: &Container, new: &Container) -> bool {
    old.profile != new.profile
        || old.fs_sandbox != new.fs_sandbox
        || old.sandbox != new.sandbox
        || old.join != new.join
}

fn same_home_choice(tools: &Tools, key: &str, reply: &window::Reply, old: &Container) -> bool {
    if reply.container == crate::container::OPEN_RECORD {
        return old.profile == crate::container::OPEN_RECORD;
    }
    match window_container_choice(&reply.container, reply.pin_container) {
        ProfileChoice::Main { .. } => !separate_home(old, &Container::default()),
        ProfileChoice::OwnSandbox { .. } => !separate_home(old, &Container::own_sandbox(key)),
        ProfileChoice::Sandbox { name, .. } => {
            let name = canon(tools, &format!("{SANDBOX_PREFIX}{name}"));
            !separate_home(
                old,
                &Container::from_selector(&name, |n| container_exists(tools, n)),
            )
        }
        ProfileChoice::Profile { name, .. } => !separate_home(
            old,
            &Container::from_selector(&name, |n| container_exists(tools, n)),
        ),
        ProfileChoice::ThrowawayJoin(name) => old.fs_sandbox && old.join == name,
        ProfileChoice::TmpJoin(name) => old.profile == name,
        _ => false,
    }
}

fn again_running(tools: &Tools, label: &str, zone: &str, selector: &str) -> Again {
    let text = format!(
        "«{label}» уже открыта в сети «{zone}» (контейнер: {}).\n\
         Можно перейти к открытому окну, открыть ещё одно в том же контейнере или выбрать другой контейнер для отдельной копии. \
         Один и тот же дом браузера может передать новый запуск старому процессу.",
        if selector.is_empty() { "настоящий дом" } else { selector }
    );
    let answers = [
        ("cancel", "Отмена", false),
        ("new", "Открыть отдельно — другая сеть/контейнер…", false),
        ("same", "Ещё одно окно здесь", false),
        ("there", "Переключиться к открытой", false),
    ];
    match crate::window::navigation_question(
        &tools.window,
        "Программа уже открыта",
        &text,
        &answers,
    ) {
        crate::window::Asked::Chose(tag) if tag == "there" => Again::There,
        crate::window::Asked::Chose(tag) if tag == "same" => Again::Same,
        crate::window::Asked::Chose(tag) if tag == "new" => Again::New,
        crate::window::Asked::NotShown => Again::Same,
        _ => Again::Nothing,
    }
}

/// A program that hands a launch over is open in a throwaway sandbox: to
/// its window there, or into a new one, with an empty home of its own? With
/// nowhere to ask, its window — what a click on a running program always
/// was.
fn again_in_throwaway(tools: &Tools, label: &str) -> Again {
    let text = format!(
        "«{label}» уже открыта в разовом контейнере.\n\
         Переключиться к её окну там — или открыть ещё одну, в новом разовом контейнере \
         с пустым домом?"
    );
    let answers = [
        ("cancel", "Отмена", false),
        ("new", "Открыть в новом разовом", false),
        ("there", "Переключиться к открытой", false),
    ];
    match crate::window::navigation_question(&tools.window, "Уже открыта", &text, &answers)
    {
        crate::window::Asked::Chose(tag) if tag == "there" => Again::There,
        crate::window::Asked::Chose(tag) if tag == "new" => Again::New,
        crate::window::Asked::NotShown => Again::There,
        _ => Again::Nothing,
    }
}

/// Below the state directory: the networks each program has gone out to
/// from the real home (`LEAK-MODEL.md` §4), a file per program's key, a
/// network a line.
const MAIN_NETWORKS: &str = ".mainnets";

/// Whether `container` is the real home: the main profile, or a container
/// whose home is it (`--home main`) — one identity either way.
fn is_real_home(tools: &Tools, container: &Container) -> bool {
    if container.fs_sandbox || !container.sandbox.is_empty() {
        return false;
    }
    container.profile.is_empty()
        || crate::container::load(tools, &container.profile)
            .is_some_and(|c| c.home == crate::container::Home::Main)
}

/// The networks the program of `key` has gone out to from the real home,
/// the latest last.
fn main_networks(state: &Path, key: &str) -> Vec<String> {
    fs::read_to_string(state.join(MAIN_NETWORKS).join(key))
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

/// `zone` written down as the latest the program has gone out to.
fn note_main_network(state: &Path, key: &str, zone: &str) {
    let mut nets = main_networks(state, key);
    nets.retain(|n| n != zone);
    nets.push(zone.to_owned());
    let dir = state.join(MAIN_NETWORKS);
    if fs::create_dir_all(&dir).is_ok() {
        let _ = fs::write(dir.join(key), nets.join("\n") + "\n");
    }
}

/// The network to start the real home's program in (§4 of the leak model:
/// one identity on both sides — cookies, logins, the fingerprint): `zone`
/// where it has gone out to it before, or never anywhere, or `zone` has no
/// network (`offline`); else the person is asked — the one before, `zone`
/// all the same, or nothing. `None`: nothing started. With nowhere to ask,
/// nothing either: never moved to another network unsaid.
fn real_home_network(
    tools: &Tools,
    key: &str,
    label: &str,
    zone: &str,
    container: &Container,
) -> Option<String> {
    if zone == "offline" || !is_real_home(tools, container) {
        return Some(zone.to_owned());
    }
    let before = main_networks(&tools.state, key);
    let Some(last) = before.last().filter(|_| !before.iter().any(|n| n == zone)) else {
        note_main_network(&tools.state, key, zone);
        return Some(zone.to_owned());
    };
    let name = |z: &str| match z {
        launch::UNCONFINED => "без изоляции".to_owned(),
        launch::HOST => "сеть хоста".to_owned(),
        z => format!("«{z}»"),
    };
    let text = format!(
        "«{label}» в настоящем доме уже выходила в сеть {}. В {} она будет той же: \
         cookies, входы на сайтах и отпечаток у неё одни, и сайт свяжет обе сети.\n\
         Чтобы быть в {} другой, нужен свой контейнер.",
        name(last),
        name(zone),
        name(zone)
    );
    let back = format!("Запустить в {}", name(last));
    let anyway = format!("Всё равно в {}", name(zone));
    let answers = [
        ("cancel", "Отмена", false),
        ("back", back.as_str(), false),
        ("anyway", anyway.as_str(), true),
    ];
    match crate::window::question(&tools.window, "Другая сеть", &text, None, &answers, None)
    {
        crate::window::Asked::Chose(tag) if tag == "back" => Some(last.clone()),
        crate::window::Asked::Chose(tag) if tag == "anyway" => {
            note_main_network(&tools.state, key, zone);
            Some(zone.to_owned())
        }
        crate::window::Asked::NotShown => {
            eprintln!(
                "vpn-zone-pick: «{label}» настоящего дома не запущена в {}: она выходила в {}, \
                 а спросить негде",
                name(zone),
                name(last)
            );
            None
        }
        _ => None,
    }
}

/// How long the window a zone's program brought up starts nothing: the
/// question's own `dialog::TOO_FAST`.
const FROM_ZONE_GUARD: std::time::Duration = crate::dialog::TOO_FAST;

/// The picker for a program in a zone (`--from-zone`, run by the broker on
/// the host, `broker::pick`): the window, and the answer on stdout — the
/// arguments of `run`, each ended by a NUL — for the broker to check and
/// start. Nothing is started here and nothing is remembered.
///
/// Nothing is decided without the window either: a pin, a container's
/// network, a running copy only choose what the window starts on. The program
/// in the zone chose which launcher's name this is, and a pin of that name
/// must not start the zone's command anywhere unasked; for the same reason
/// the window has no "always" (a pin of that name would decide the menu's
/// next launch of the real program), and the title says who asks and the
/// notes what, word by word — not the launcher's name. Starting is off for
/// its first moments ([`FROM_ZONE_GUARD`], in the window and checked here
/// again): it takes the focus, and a key meant for something else must not
/// answer it. A locked zone is offered only itself. What the window shows is
/// [`zone_request`]; what it may answer is a container that exists, with no
/// pin.
fn pick_for_zone(
    tools: &Tools,
    key: &str,
    memory: &Memory,
    cmd: &[OsString],
    zone: &str,
    locked: bool,
    offer_rule: Option<&str>,
    source_container: Option<&str>,
) -> ExitCode {
    let refuse = |why: &str| {
        eprintln!("vpn-zone-pick: {why}");
        ExitCode::from(1)
    };
    if cmd.is_empty() {
        return refuse("нечего запускать");
    }
    if tools.window.as_os_str().is_empty() {
        return refuse("окна запуска нет");
    }
    let Some(shown) = crate::broker::shown_words(cmd) else {
        return refuse("команда слишком длинная, чтобы показать её целиком");
    };
    let mut req = zone_request(tools, key, memory, cmd, &shown, zone, locked);
    req.rule = offer_rule.map(str::to_owned);
    if let Some(source) = source_container {
        propose_source_container(&mut req, key, source);
    }

    let asked = std::time::Instant::now();
    let reply = match show_window(tools, &req) {
        Some(Some(reply)) => reply,
        Some(None) => return ExitCode::from(1),
        None => return refuse("окно запуска не открылось"),
    };
    if let Err(why) = crate::dialog::not_too_soon(asked) {
        return refuse(&why);
    }
    // Only a container that exists and no pin: the window offers nothing
    // else, and a row named like a command is refused all the same.
    let choice = window_container_choice(&reply.container, false);
    match &choice {
        ProfileChoice::Main { pin: false }
        | ProfileChoice::OwnSandbox { pin: false }
        | ProfileChoice::Throwaway { pin: false }
        | ProfileChoice::Sandbox { pin: false, .. }
        | ProfileChoice::Profile { pin: false, .. }
        | ProfileChoice::Tmp
        | ProfileChoice::TmpJoin(_) => {}
        _ => return refuse("окно ответило выбором, которого в запросе из зоны нет"),
    }
    let Some(container) = apply_profile_choice(tools, key, choice, None) else {
        return ExitCode::from(1);
    };
    let net = launch::network_name(&reply.net);
    if net == "offline" {
        launch::ensure_offline_zone(&tools.state);
    }
    let argv = run_argv(Path::new(""), net, &container, cmd);
    let mut out = Vec::new();
    // The rule ticked: said first, apart from the arguments of `run`.
    if offer_rule.is_some() && reply.rule {
        out.extend_from_slice(b"--rule\0");
    }
    for word in &argv[2..] {
        out.extend_from_slice(word.as_bytes());
        out.push(0);
    }
    if std::io::Write::write_all(&mut std::io::stdout(), &out).is_err() {
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// Source metadata never creates a container or bypasses confirmation. Only an
/// existing row compatible with the source network may become the proposal.
fn propose_source_container(req: &mut window::Request, key: &str, source: &str) {
    let tag = if source == own_name(key) {
        "__ownsb__"
    } else {
        source
    };
    let Some(index) = req.containers.iter().position(|c| {
        c.tag == tag
            && !c.new
            && c.bound
                .as_deref()
                .is_none_or(|n| Some(n) == req.asker.as_deref())
            && c.busy
                .as_deref()
                .is_none_or(|n| Some(n) == req.asker.as_deref())
    }) else {
        return;
    };
    for (i, c) in req.containers.iter_mut().enumerate() {
        c.selected = i == index;
    }
    req.notes.push(format!("Исходный контейнер: {source}. Запуск здесь даст программе доступ к его данным и общим каналам; назначение программы не сохраняется."));
}

/// What the window of [`pick_for_zone`] is asked: the zone's command in a
/// block of its own and the program as the host finds it; the asking
/// network chosen, and the only one Enter starts in (`offline` for a
/// system zone's program); the host's network last, away from where a
/// habit would click; no new container (a name typed into a window that
/// came up by itself), no "always", no note of the memory of a name the
/// zone chose; a sandbox named by its name, not "its own".
fn zone_request(
    tools: &Tools,
    key: &str,
    memory: &Memory,
    cmd: &[OsString],
    shown: &[String],
    zone: &str,
    locked: bool,
) -> window::Request {
    let mut req = window_request(tools, key, "", zone, memory);
    req.title = match zone.strip_prefix("system:") {
        Some(system) => format!("Запрос из системного подключения «{system}»"),
        None => format!("Запрос из сети «{zone}»"),
    };
    req.notes.clear();
    // A zone-origin request selects an existing environment only. Its reply
    // cannot edit host filesystem policy, so never offer editable file grants.
    req.offers.clear();
    req.files.clear();
    req.host_home.clear();
    req.folder_protected.clear();
    let asker = if req.nets.iter().any(|n| n.tag == zone) {
        zone
    } else {
        "offline"
    };
    for net in &mut req.nets {
        net.selected = net.tag == asker;
    }
    if locked {
        req.nets.retain(|n| n.tag == zone);
        req.notes
            .push("Подключение заперто: запустить можно только в нём самом.".to_owned());
    }
    if let Some(at) = req
        .nets
        .iter()
        .position(|n| launch::is_unconfined_name(&n.tag))
    {
        let host = req.nets.remove(at);
        req.nets.push(host);
    }
    req.containers.retain(|c| !c.new);
    for c in &mut req.containers {
        if c.tag == "__ownsb__" {
            c.label = format!(
                "🔒 Контейнер «app-{key}» — {}",
                crate::container::Home::Private.label()
            );
        }
    }
    req.asker = Some(asker.to_owned());
    req.command = shown.to_vec();
    // The broker hands the program over found already (an absolute path):
    // what is shown is what runs.
    let path = Path::new(&cmd[0]);
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let shown_path = crate::broker::shown_word(&path.display().to_string());
    req.program = if crate::broker::runs_anything(name) {
        format!("⚠ {shown_path} — запускает любую команду: смотри, что идёт следом")
    } else if crate::broker::may_remember(path) {
        shown_path
    } else {
        format!(
            "⚠ {shown_path} — не из системы: этот файл может подменить программа, у которой есть дом"
        )
    };
    req.pin_net = false;
    req.pin_container = false;
    req.no_pins = true;
    req.guard_ms = FROM_ZONE_GUARD.as_millis() as u64;
    req
}

/// `autostart.unassigned`: the declared setting, then the local one; `ask` by
/// default (owner, 2026-09-24 — `offline` before).
fn autostart_setting(tools: &Tools) -> String {
    crate::declared::setting(&tools.config.join("declared/autostart"))
        .or_else(|| read_setting(&tools.config.join("autostart")))
        .map(|v| v.trim().to_owned())
        .unwrap_or_else(|| "ask".to_owned())
}

/// Whether an autostart launch shows the picker instead of guessing: with
/// `ask`, when something had to be guessed, and when there is a screen to ask
/// on — a login on a text console gets the closed variant as before.
pub fn autostart_asks(setting: &str, plan: &AutostartPlan, screen: bool) -> bool {
    setting == "ask" && (plan.network_guessed || plan.container_guessed) && screen
}

/// A launch from XDG autostart: [`autostart_plan`], a notification for what
/// was guessed, and the launch itself. `None`: the picker asks instead
/// ([`autostart_asks`]).
fn autostart(
    tools: &Tools,
    key: &str,
    label: &str,
    memory: &Memory,
    cmd: &[OsString],
) -> Option<ExitCode> {
    let plan = autostart_plan(
        memory,
        key,
        |name| container_exists(tools, name),
        |container| {
            crate::container::load(tools, &container.selector()).and_then(|c| {
                match c.network.value {
                    crate::container::Network::Named(network) => Some(network),
                    crate::container::Network::Ask => None,
                }
            })
        },
    );
    let screen = std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty())
        || std::env::var_os("DISPLAY").is_some_and(|v| !v.is_empty());
    if autostart_asks(&autostart_setting(tools), &plan, screen) {
        return None;
    }
    let mut lines = Vec::new();
    if plan.network_guessed {
        lines.push(
            "сеть для неё не выбрана — запущена без сети. Чтобы выбрать: закрой программу, \
             запусти из меню и закрепи сеть"
                .to_owned(),
        );
    }
    if plan.container_guessed {
        lines.push(format!(
            "контейнер не выбран — запущена в своём контейнере «{}». Назначить: cellward \
             container assign {key} <контейнер>",
            plan.container.selector()
        ));
    }
    // A home of its own that has never been started asks for file access in
    // a dialog — the one thing an autostart must not do. It gets the closed
    // answer instead, the one given when there is no screen to ask on.
    if !plan.container.sandbox.is_empty() {
        let dir = crate::container::policy_dir(tools, &plan.container.sandbox);
        let perms = dir.join("perms");
        if !perms.exists()
            && fs::create_dir_all(&dir)
                .and_then(|()| fs::write(&perms, crate::fs_sandbox::Perms::default().render()))
                .is_ok()
        {
            lines.push("доступа к файлам хоста у неё нет".to_owned());
        }
    }
    if !lines.is_empty() {
        eprintln!("vpn-zone-pick: автозапуск «{label}»: {}", lines.join("; "));
        dialog::notify(
            &tools.notify_send,
            None,
            "15000",
            &format!("Автозапуск: «{label}»"),
            &lines.join("\n"),
        );
    }
    Some(launch(tools, key, &plan.zone, &plan.container, cmd))
}

/// Read the three levels of memory, dropping the pins that have gone stale.
fn read_memory(tools: &Tools, key: &str) -> Memory {
    read_memory_with(tools, key, true)
}

/// [`read_memory`]; `tidy` false leaves every file as it is — for a window a
/// zone's program asks for, under a launcher's name the zone chose: a pin
/// is not dropped because the zone moved a container away for a moment.
fn read_memory_with(tools: &Tools, key: &str, tidy: bool) -> Memory {
    // The memory as the layout of one name per container has it: the move
    // rewrites the pins it renames, and makes the programs' network pins
    // their containers' networks (`container::migrate_pins`), before they
    // are read.
    crate::container::migrate(tools);
    let state = &tools.state;

    let profile_pin_path = state.join(".pinnedprofile").join(key);
    let mut pinned_profile = canon(tools, &read_setting(&profile_pin_path).unwrap_or_default());
    // An assignment declared in Nix outranks the picker's own pin: it is the
    // configuration, the pin only a memory. (`docs/CONTAINERS.md` §4)
    if let Some(declared) = crate::container::declared_owner(tools, key) {
        pinned_profile = declared;
    }
    if !profile_pin_is_valid(&pinned_profile, |name| container_exists(tools, name)) {
        if tidy {
            let _ = fs::remove_file(&profile_pin_path);
        }
        pinned_profile.clear();
    }

    let running: Vec<Running> = running_records(state, key)
        .into_iter()
        .map(|r| Running {
            selector: canon(tools, &r.selector),
            ..r
        })
        .collect();
    // Two copies alive at once: whatever handed over once, this program runs
    // side by side (two containers of one browser, or a wrong guess) — ask
    // again.
    let handover_path = state.join(HANDOVER).join(key);
    let mut hands_over = handover_path.is_file();
    if hands_over && running.len() > 1 {
        if tidy {
            let _ = fs::remove_file(&handover_path);
        }
        hands_over = false;
    }
    let mut memory = Memory {
        running: running.into_iter().next(),
        hands_over,
        pinned_profile,
        last: crate::launch::network_name(
            &read_setting(&state.join(".last").join(key)).unwrap_or_default(),
        )
        .to_owned(),
        last_profile: canon(
            tools,
            &read_setting(&state.join(".lastprofile").join(key)).unwrap_or_default(),
        ),
        container_chosen: state.join(".lastprofile").join(key).is_file(),
        fallback: crate::cli::setting(tools, "default").map_or_else(
            || "offline".to_owned(),
            |(value, _)| crate::launch::network_name(&value).to_owned(),
        ),
        default_profile: crate::cli::setting(tools, "default-profile")
            .map_or_else(|| "ask".to_owned(), |(value, _)| canon(tools, &value)),
        ask: std::env::var_os(ENV_ASK).is_some_and(|v| !v.is_empty()),
        bound: String::new(),
    };
    // The container this launch would use without a dialog, and its network.
    let would_use = container_without_dialog(&memory, key, |n| container_exists(tools, n), None);
    // A program that reaches the global default container with nothing
    // pinned is a program nobody chose a network for: its network is asked,
    // the container's own preselected — never taken unasked, or every new
    // program would go there (`docs/PERMISSIONS.md` §11.8).
    if !(memory.pinned_profile.is_empty() && is_default(&memory, &would_use)) {
        if let Some(container) = crate::container::load(tools, &would_use.selector()) {
            if let crate::container::Network::Named(network) = container.network.value {
                memory.bound = network;
            }
        }
    }
    if would_use.selector().is_empty() {
        let path = state.join(".pinned").join(key);
        let pinned =
            crate::launch::network_name(&read_setting(&path).unwrap_or_default()).to_owned();
        if !pinned.is_empty() && crate::container::network_exists(tools, &pinned) {
            memory.bound = pinned;
        } else if tidy && path.exists() {
            let _ = fs::remove_file(path);
        }
    }
    memory
}

/// Where is this program running right now? Every live record, over every
/// container's registry directory; the first one is where a click goes.
fn running_records(state: &Path, key: &str) -> Vec<Running> {
    let running = state.join(".running");
    let mut out = Vec::new();
    for dir in registry::dirs(&running) {
        let Ok(text) = fs::read_to_string(dir.join(key)) else {
            continue;
        };
        out.extend(
            text.lines()
                .filter_map(registry::parse_record)
                // This one starts a click into that network without a
                // question: only a launch that is certainly still this
                // process counts (`registry::STARTED`), not whatever holds its
                // number now — and only one the user started, not one a
                // program in a zone asked for under an id of its choosing.
                .filter(|r| registry::launched_here(&running, r.pid))
                .map(|record| Running {
                    zone: record.zone,
                    selector: record.selector,
                }),
        );
    }
    out
}

/// The zones that can be started into: a directory with a config in it.
/// `offline` is skipped even though it has no config — it is a built-in choice
/// of the menu, listed above the zones. (`docs/GOTCHAS.md` §2)
fn zone_names(state: &Path) -> Vec<String> {
    visible_entries(state)
        .into_iter()
        .filter(|dir| dir.join("config.conf").is_file())
        .filter_map(|dir| dir.file_name().map(|n| n.to_string_lossy().into_owned()))
        .filter(|name| name != "offline" && name != crate::launch::HOST)
        // A zone left with a name that now means the host's network is not
        // offered: choosing it would launch unconfined. (`vpn-zone doctor`
        // names it.)
        .filter(|name| !crate::launch::is_unconfined_name(name))
        .filter(|name| crate::chain::published_zone(state, name).unwrap_or(false))
        .collect()
}

/// The second dialog: which container (or sandbox) to open the program in.
///
/// `None` means the user cancelled and the launch is over. `current_zone` is
/// what a container being open in ANOTHER network is compared against.
fn ask_profile(
    tools: &Tools,
    key: &str,
    label: &str,
    current_zone: &str,
    memory: &Memory,
) -> Option<Container> {
    // The global "do not ask" setting: `main` is always the main profile, a
    // name is always that container. Set by the settings shortcut or by
    // `vpn-zone default-profile`.
    match memory.default_profile.as_str() {
        "ask" => {}
        "main" => return Some(Container::default()),
        "own" => return Some(Container::own_sandbox(key)),
        name => {
            if container_exists(tools, name) {
                return Some(Container::from_selector(name, |n| {
                    container_exists(tools, n)
                }));
            }
        }
    }

    if !launch::has_display() {
        // Same reason as the network dialog above: without a graphical session
        // kdialog dies and `|| exit 0` took that for a cancel, so a launch from
        // a terminal or from a unit ended in nothing at all. Take the last
        // choice and let the program start — its own home when that is gone.
        return Some(
            memory
                .last_choice()
                .and_then(|last| {
                    Container::from_selector_checked(last, |n| container_exists(tools, n))
                })
                .unwrap_or_else(|| Container::own_sandbox(key)),
        );
    }

    let (sandboxes, profiles) = container_rows(tools);
    let sandboxes: Vec<String> = sandboxes.into_iter().map(|r| r.name).collect();
    let running = tools.state.join(".running");
    let tmp_joins = open_throwaways(&running);

    let mut argv: Vec<OsString> = vec![
        "--title".into(),
        format!("Контейнер для «{label}»").into(),
        "--default".into(),
        memory.last_choice().unwrap_or("__ownsb__").into(),
        "--menu".into(),
        "В каком контейнере открыть? Контейнер хранит настройки, сессии и логины отдельно от \
         настоящего дома"
            .into(),
    ];
    push_rows(
        &mut argv,
        &profile_menu(
            &sandboxes,
            &profiles,
            &tmp_joins,
            &memory.pinned_profile,
            current_zone,
        ),
    );
    let answer = dialog::ask(&tools.kdialog, &argv)?;
    apply_profile_choice(tools, key, parse_profile_choice(&answer), None)
}

/// A container choice made real: its pin written, a new sandbox or profile
/// created. `new_name` is the new one's name when the launch window already
/// asked for it; without it kdialog asks, as the menu always did.
fn apply_profile_choice(
    tools: &Tools,
    key: &str,
    choice: ProfileChoice,
    new_name: Option<String>,
) -> Option<Container> {
    let pin = |selector: &str| remember(&tools.state, ".pinnedprofile", key, selector);
    match choice {
        ProfileChoice::Main { pin: false } => Some(Container::default()),
        ProfileChoice::Main { pin: true } => {
            // "Основной — всегда": pinned separately from the network.
            pin(MAIN);
            Some(Container::default())
        }
        ProfileChoice::OwnSandbox { pin: want } => {
            if want {
                pin(&own_name(key));
            }
            Some(Container::own_sandbox(key))
        }
        ProfileChoice::Throwaway { pin: want } => {
            if want {
                pin(THROWAWAY);
            }
            Some(Container {
                fs_sandbox: true,
                ..Container::default()
            })
        }
        ProfileChoice::ThrowawayJoin(name) => Some(Container {
            fs_sandbox: true,
            join: name,
            ..Container::default()
        }),
        // `sb:<name>` of an older menu or window: the container by its name.
        ProfileChoice::Sandbox { name, pin: want } => {
            let name = canon(tools, &format!("{SANDBOX_PREFIX}{name}"));
            if want {
                pin(&name);
            }
            Some(Container::from_selector(&name, |n| {
                container_exists(tools, n)
            }))
        }
        ProfileChoice::NewSandbox => {
            let name = match new_name {
                Some(name) => name,
                None => dialog::ask(
                    &tools.kdialog,
                    [
                        "--title",
                        "Новый контейнер со своим домом",
                        "--inputbox",
                        "Название контейнера. У него будет свой пустой дом, общий для всех программ, которые ты в нём запустишь.",
                        "",
                    ],
                )?,
            };
            // A creation that fails (a name that cleans down to nothing, no
            // space, no permission) must not kill the picker: that used to
            // happen silently, AFTER every dialog had been answered. But what
            // was asked for is a sandbox, so it is the program's own sandbox —
            // not the main profile with the whole home —, and said so.
            let name = sanitize_name(&name);
            let made = crate::container::create(tools, &name, crate::container::Home::Private);
            if let Err(why) = made {
                dialog::notify(
                    &tools.notify_send,
                    None,
                    "8000",
                    "Контейнер не создан",
                    &format!("{why}. Программа запущена в своём контейнере — без дома системы."),
                );
                return apply_profile_choice(
                    tools,
                    key,
                    ProfileChoice::OwnSandbox { pin: false },
                    None,
                );
            }
            Some(Container {
                profile: name,
                ..Container::default()
            })
        }
        ProfileChoice::Tmp => Some(Container {
            profile: TMP.to_owned(),
            ..Container::default()
        }),
        ProfileChoice::TmpJoin(dir) => Some(Container {
            profile: format!("{TMPJOIN_PREFIX}{dir}"),
            ..Container::default()
        }),
        // The pin goes, and the program's own container follows — not the
        // main home with the whole of it.
        ProfileChoice::Unpin => {
            let _ = fs::remove_file(tools.state.join(".pinnedprofile").join(key));
            Some(Container::own_sandbox(key))
        }
        ProfileChoice::NewProfile => {
            let name = match new_name {
                Some(name) => name,
                None => dialog::ask(
                    &tools.kdialog,
                    [
                        "--title",
                        "Новый контейнер — слой над домом",
                        "--inputbox",
                        "Название контейнера (буквы, цифры, дефис):",
                        "",
                    ],
                )?,
            };
            // Only what actually gets in the way is cleaned (paths, spaces,
            // quotes) and a leading dash is cut off — Cyrillic stays Cyrillic.
            let name = sanitize_name(&name);
            // The same trap as the sandbox above: without swallowing the error
            // the picker died after all the dialogs, and with a container that
            // does not exist `vpn-zone run` would honestly refuse to start.
            let made = crate::container::create(tools, &name, crate::container::Home::Layer);
            if let Err(why) = made {
                // A container was asked for: the program's own sandbox, not the
                // main profile with the whole home (review 2026-09-25).
                dialog::notify(
                    &tools.notify_send,
                    None,
                    "8000",
                    "Контейнер не создан",
                    &format!("{why}. Программа запущена в своём контейнере — без дома системы."),
                );
                return apply_profile_choice(
                    tools,
                    key,
                    ProfileChoice::OwnSandbox { pin: false },
                    None,
                );
            }
            Some(Container {
                profile: name,
                ..Container::default()
            })
        }
        ProfileChoice::Profile { name, pin: want } => {
            if want {
                pin(&name);
            }
            Some(Container {
                profile: name,
                ..Container::default()
            })
        }
    }
}

/// The zone named by the first live line of a container's `inuse` file.
///
/// That file is a leftover of an older version and nothing writes it any more,
/// which is why "занят сетью …" never actually appeared in this menu. It is
/// still read (a container from that era may carry one), and the launch
/// registry — the same source `vpn-zone profile list` and the container removal
/// dialog use — answers the question for everything else.
fn live_tenant(running: &Path, inuse: &Path) -> Option<String> {
    let text = fs::read_to_string(inuse).ok()?;
    text.lines()
        .filter_map(registry::parse_record)
        .find(|record| registry::alive(running, record.pid))
        .map(|record| record.zone)
        .filter(|zone| !zone.is_empty())
}

/// The throwaway containers that are open right now: a registry directory named
/// `vpn-profile-*` whose directory still exists (below the state directory, or
/// in `/tmp` from before the move) and which has at least one live tenant.
fn open_throwaways(running: &Path) -> Vec<TmpJoinRow> {
    let mut out = Vec::new();
    for dir in registry::dirs(running) {
        let Some(name) = dir.file_name() else {
            continue;
        };
        if !name.as_bytes().starts_with(b"vpn-profile-") {
            continue;
        }
        let state = running.parent().unwrap_or(running);
        let Some(tmp) = crate::launch::throwaway_path(state, name) else {
            continue;
        };
        let mut who = String::new();
        for file in visible_entries(&dir) {
            if !file.is_file() {
                continue;
            }
            // Only the FIRST line of each file is looked at, as the shell's
            // `while read … break` did: one program, one answer.
            let Ok(text) = fs::read_to_string(&file) else {
                continue;
            };
            let alive = text
                .lines()
                .next()
                .and_then(registry::parse_record)
                .is_some_and(|record| registry::alive(running, record.pid));
            if alive {
                who.push(' ');
                who.push_str(&file.file_name().unwrap_or_default().to_string_lossy());
            }
        }
        if !who.is_empty() {
            out.push(TmpJoinRow {
                dir: tmp.to_string_lossy().into_owned(),
                who,
            });
        }
    }
    out
}

/// Append a menu to a kdialog command line: tag, text, tag, text…
fn push_rows(argv: &mut Vec<OsString>, rows: &[Row]) {
    for (tag, text) in rows {
        argv.push(tag.as_str().into());
        argv.push(text.as_str().into());
    }
}

/// Write one of the memory files (`printf '%s'`: no trailing newline).
///
/// A failure is reported and stepped over rather than fatal: the launch matters
/// more than the memory of it, and this runs after every dialog has been
/// answered.
fn remember(state: &Path, sub: &str, key: &str, value: &str) {
    let path = state.join(sub).join(key);
    if let Err(e) = fs::write(&path, value) {
        eprintln!("vpn-zone-pick: не записать {}: {e}", path.display());
    }
}

/// Start the second pass of the picker: the same binary, with the answer
/// already given carried in the environment.
///
/// `/proc/self/exe` rather than the profile path on purpose — this is the same
/// binary asking itself a second question, and during a home-manager switch the
/// profile path may already point at the next generation. The environment
/// (including `VPN_ZONE_TOOLS`) is inherited as it is.
fn reexec(
    tools: &Tools,
    picker_lock: &PickerLock,
    key: &str,
    cmd: &[OsString],
    handover: Option<&str>,
) -> ExitCode {
    std::env::set_var(ENV_ASK, "1");
    match handover {
        Some(selector) => std::env::set_var(ENV_PROFILE, selector),
        // Already removed at startup; make sure a second pass cannot inherit a
        // stale one.
        None => std::env::remove_var(ENV_PROFILE),
    }
    let me = fs::read_link("/proc/self/exe")
        .ok()
        .filter(|path| path.is_file())
        .unwrap_or_else(|| tools.picker.clone());
    let mut argv: Vec<OsString> = vec![me.clone().into(), "--id".into(), key.into(), "--".into()];
    argv.extend(cmd.iter().cloned());
    picker_lock.inherit_once();
    let e = exec_command(&argv);
    std::env::remove_var(ENV_LOCK_FD);
    eprintln!("не удалось запустить {}: {e}", me.display());
    ExitCode::from(EXIT_NOT_STARTED)
}

/// Become the launch. Returns only when the `execvp` failed.
fn launch(
    tools: &Tools,
    key: &str,
    zone_choice: &str,
    container: &Container,
    cmd: &[OsString],
) -> ExitCode {
    let argv = launch_argv(tools, key, zone_choice, container, cmd);
    let e = exec_command(&argv);
    eprintln!("не удалось запустить {}: {e}", tools.runner.display());
    ExitCode::from(EXIT_NOT_STARTED)
}

/// [`launch`] of an answer the person gave, watched for a hand-over when
/// [`watch_handover`] says so, and in a graphical session for a launch that
/// does not start (2026-09-28: one from a menu that ended before its
/// program showed nothing at all — the error was in the session's log): the
/// program is then started as a child instead of in place. Gone with
/// success without ever opening a window (the Wayland proxy's word,
/// [`opened_or_ended`]) — however long that took: it handed the launch to
/// the copy that runs, and [`HANDOVER`] remembers that — the next click on
/// it while it runs raises that copy with no question, as every click on a
/// running program did before. Not started ([`EXIT_NOT_STARTED`], or the
/// launch's word of it with why), or gone with a failure before any window:
/// the person is told. A window of its own:
/// the picker leaves, and the program goes on without it. No proxy on the
/// way (no word to come): the picker leaves, and learns nothing.
fn launch_asked(
    tools: &Tools,
    key: &str,
    label: &str,
    zone_choice: &str,
    container: &Container,
    cmd: &[OsString],
    memory: &Memory,
) -> ExitCode {
    // The real home in a network it has not gone out to: asked first.
    let zone_choice = match real_home_network(tools, key, label, zone_choice, container) {
        Some(zone) => zone,
        None => return ExitCode::SUCCESS,
    };
    let zone_choice = zone_choice.as_str();
    let in_zone = std::env::var_os(launch::ENV_CURRENT).is_some_and(|v| !v.is_empty());
    let handover = watch_handover(memory, zone_choice, in_zone);
    if !handover && (in_zone || !launch::has_display()) {
        return launch(tools, key, zone_choice, container, cmd);
    }
    let argv = launch_argv(tools, key, zone_choice, container, cmd);
    // The program's first window, told by the Wayland proxy through a pipe of
    // ours (`wl_proxy::window_opened`, taken by `wl-sandbox`). No pipe: the
    // launch goes on as any other, and nothing is learned.
    let Ok((heard, told)) = crate::sys::pipe() else {
        return launch(tools, key, zone_choice, container, cmd);
    };
    let told_raw = told.as_raw_fd();
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]).env(
        crate::wl_sandbox::ENV_OPENED_FD,
        crate::wl_sandbox::OPENED_FD.to_string(),
    );
    // SAFETY: between fork and exec: dup2/fcntl on descriptors of ours.
    unsafe {
        command.pre_exec(move || {
            let fd = crate::wl_sandbox::OPENED_FD;
            let done = if told_raw == fd {
                libc::fcntl(fd, libc::F_SETFD, 0)
            } else {
                libc::dup2(told_raw, fd)
            };
            if done < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let spawned = command.spawn();
    drop(told);
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => {
            eprintln!("не удалось запустить {}: {e}", tools.runner.display());
            return ExitCode::from(EXIT_NOT_STARTED);
        }
    };
    let status = match opened_or_ended(&heard, &mut child) {
        // A window of its own: no hand-over. The picker leaves, the program
        // goes on without it.
        Heard::Opened | Heard::Nothing => return ExitCode::SUCCESS,
        Heard::NotStarted(why) => {
            tell_not_started(tools, label, &why);
            return ExitCode::from(EXIT_NOT_STARTED);
        }
        Heard::Ended(status) => status,
    };
    // Gone without ever opening a window, with success: it handed the launch
    // over to the copy that runs — remembered, however long that took.
    if handover && status.success() {
        let dir = tools.state.join(HANDOVER);
        let _ = fs::create_dir_all(&dir).and_then(|()| fs::write(dir.join(key), ""));
    }
    // And the person clicked for that copy's window: raised for them.
    if (handover || memory.hands_over) && status.success() && !in_zone {
        if let Err(why) = raise_running(tools, key, zone_choice, &container.selector()) {
            tell_not_raised(tools, label, &why);
            return ExitCode::from(1);
        }
    }
    if status.code() == Some(i32::from(EXIT_NOT_STARTED)) {
        tell_not_started(tools, label, NOT_STARTED_UNSAID);
    } else if !status.success() {
        // Gone with a failure before any window: a program of a home of its
        // own that is not there (bwrap's own failure is 1), one that fell
        // over at its start — nothing on the screen said so either.
        use std::os::unix::process::ExitStatusExt;
        let how = match (status.code(), status.signal()) {
            (Some(code), _) => format!("код {code}"),
            (None, Some(signal)) => format!("сигнал {signal}"),
            (None, None) => status.to_string(),
        };
        tell_not_started(
            tools,
            label,
            &format!(
                "закрылась, не открыв окна ({how}) — причина в журнале сеанса (journalctl \
                 --user -e)"
            ),
        );
    }
    ExitCode::from(status.code().map_or(1, |c| c as u8))
}

/// Focus only the selected network/container launch. If hidden, activate its
/// verified tray item before waiting for its window; never relaunch a copy.
fn raise_running(tools: &Tools, key: &str, zone: &str, selector: &str) -> Result<(), String> {
    let running = tools.state.join(".running");
    let mut candidates: Vec<i32> = registry::dirs(&running)
        .into_iter()
        .filter_map(|dir| fs::read_to_string(dir.join(key)).ok())
        .flat_map(|text| {
            text.lines()
                .filter_map(registry::parse_record)
                .filter(|r| r.zone == zone && canon(tools, &r.selector) == canon(tools, selector))
                .map(|r| r.pid)
                .collect::<Vec<_>>()
        })
        .collect();
    candidates.sort_unstable();
    candidates.dedup();
    for pid in candidates.into_iter().rev() {
        let Some(held) = crate::sys::pidfd_open(pid) else {
            continue;
        };
        // Check the registry identity after pinning, never pin a reused PID
        // after treating an earlier record check as permission to focus it.
        if !registry::launched_here(&running, pid)
            || crate::tray_restore::held_pid(&held) != Some(pid)
        {
            continue;
        }
        return crate::focus::restore_launch(pid, &held);
    }
    Err(format!(
        "открытый экземпляр «{key}» в выбранном контейнере уже завершился"
    ))
}

fn tell_not_raised(tools: &Tools, label: &str, why: &str) {
    eprintln!("vpn-zone-pick: окно «{label}» не показано: {why}");
    crate::dialog::notify(
        &tools.notify_send,
        None,
        "5000",
        &format!("Не удалось показать окно «{label}»"),
        why,
    );
}

/// Why a launch did not start, when nothing on the way said it.
const NOT_STARTED_UNSAID: &str = "запуск закончился, не начав программу (код 127) — причина в \
                                  журнале сеанса (journalctl --user -e)";

/// A launch the person asked for that did not start, said to them: a
/// notification that stays until it is read.
fn tell_not_started(tools: &Tools, label: &str, why: &str) {
    eprintln!("vpn-zone-pick: «{label}» не запущена: {why}");
    crate::dialog::notify(
        &tools.notify_send,
        Some("critical"),
        "0",
        &format!("«{label}» не запущена"),
        why,
    );
}

/// What [`opened_or_ended`] heard first.
enum Heard {
    /// The program opened a window.
    Opened,
    /// Nobody will say: the launch went without the Wayland proxy
    /// ([`crate::wl_sandbox::WORD_NONE`]).
    Nothing,
    /// The launch ended before its program started, and said why
    /// ([`crate::wl_sandbox::WORD_NOT_STARTED`]).
    NotStarted(String),
    /// The launch ended, no window opened.
    Ended(std::process::ExitStatus),
}

/// Whichever comes first, as long as it takes: the word that the program
/// opened a window, or the launch's end. No clock: a hand-over that takes
/// long on a loaded machine is a hand-over all the same, and a window that
/// comes late is a window.
fn opened_or_ended(heard: &OwnedFd, child: &mut std::process::Child) -> Heard {
    let pidfd = crate::sys::pidfd_open(child.id() as i32);
    loop {
        let mut fds = vec![libc::pollfd {
            fd: heard.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        if let Some(fd) = &pidfd {
            fds.push(libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        // SAFETY: a valid array of pollfd and its length.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if rc < 0 {
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                std::thread::sleep(crate::sys::LOOK_AGAIN);
            }
            continue;
        }
        if fds[0].revents != 0 {
            let mut byte = [0u8; 1];
            // SAFETY: a valid descriptor and a buffer of one byte.
            let n = unsafe { libc::read(heard.as_raw_fd(), byte.as_mut_ptr().cast(), 1) };
            return match (n, byte[0]) {
                (1, crate::wl_sandbox::WORD_OPENED) => Heard::Opened,
                (1, crate::wl_sandbox::WORD_NOT_STARTED) => Heard::NotStarted(why_of(heard)),
                (1, _) => Heard::Nothing,
                // The end of the pipe with no word: nobody holds it any more
                // — the launch is ending (its descriptors close a moment
                // before it can be waited for; waited for, then).
                _ => match child.wait() {
                    Ok(status) => Heard::Ended(status),
                    Err(_) => Heard::Nothing,
                },
            };
        }
        // Ended, and nothing in the pipe (a word said on the way would have
        // been heard above, first).
        if fds.get(1).is_some_and(|f| f.revents != 0) {
            return match child.wait() {
                Ok(status) => Heard::Ended(status),
                Err(_) => Heard::Nothing,
            };
        }
    }
}

/// The rest of a [`crate::wl_sandbox::WORD_NOT_STARTED`]: written with the
/// word in one write, so all there now — read without waiting, since other
/// holders of the pipe (the Wayland proxy) may keep it open.
fn why_of(heard: &OwnedFd) -> String {
    let fd = heard.as_raw_fd();
    // SAFETY: fcntl on our own descriptor.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
    let mut why = vec![0u8; crate::wl_sandbox::WHY_MAX];
    // SAFETY: a valid descriptor and a buffer of ours of this length.
    let n = unsafe { libc::read(fd, why.as_mut_ptr().cast(), why.len()) };
    why.truncate(usize::try_from(n).unwrap_or(0));
    let why = String::from_utf8_lossy(&why).trim().to_owned();
    if why.is_empty() {
        NOT_STARTED_UNSAID.to_owned()
    } else {
        why
    }
}

/// The `run` command line of a launch, with the environment it needs.
fn launch_argv(
    tools: &Tools,
    key: &str,
    zone_choice: &str,
    container: &Container,
    cmd: &[OsString],
) -> Vec<OsString> {
    // The shortcut's key is also the app-id the compositor restriction and the
    // sandbox permissions are keyed by. (`docs/GOTCHAS.md` §6, §7)
    std::env::set_var(launch::ENV_APPID, key);

    // Keep `vpn-zone run` in charge even without isolation: it records the
    // launch and enforces the locked-zone guard. Saved pre-existing
    // unconfined+container bindings retain their home on upgrade; an explicit
    // top-level choice is normalized by the picker before it gets here.
    let zone = match crate::launch::network_name(zone_choice) {
        "offline" => {
            launch::ensure_offline_zone(&tools.state);
            "offline"
        }
        other => other,
    };

    run_argv(&tools.runner, zone, container, cmd)
}

#[cfg(test)]
mod tests {

    #[test]
    fn integrated_file_confirmation_creates_policy_once_and_reports_legacy_real_home() {
        let root = std::env::temp_dir().join(format!("cw-picker-files-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let home = root.join("home");
        let entries = Tools::keys()
            .iter()
            .map(|key| {
                let path = match *key {
                    "home" => home.clone(),
                    "config" => home.join(".config/vpn-zones"),
                    "state" => home.join(".local/state/vpn-zones"),
                    "profiles" | "sandboxes" => home.join(".local/state/vpn-profiles"),
                    other => root.join("tools").join(other),
                };
                ((*key).to_owned(), path.display().to_string())
            })
            .collect();
        let tools = Tools::from_entries(Path::new("/test/manifest"), &entries).unwrap();
        let key = "synthetic-app";
        let own = own_name(key);
        let mut reply = window::Reply {
            container: "__ownsb__".into(),
            ..window::Reply::default()
        };
        let selected = Container::own_sandbox(key);
        with_files(&tools, key, &reply, selected.clone()).unwrap();
        assert!(
            crate::container::load(&tools, &own).is_none(),
            "old GUI silently acknowledged file permissions"
        );
        let project = home.join("Projects");
        fs::create_dir_all(&project).unwrap();
        reply.files_reviewed = true;
        reply.grants.push(format!("overlay\t{}", project.display()));
        let got = with_files(&tools, key, &reply, selected).unwrap();
        assert_eq!(got.selector(), own);
        assert_eq!(crate::folder_rules::load(&tools, &own).unwrap().len(), 1);
        let policy = crate::container::policy_dir(&tools, &own).join("perms");
        assert_eq!(fs::read_to_string(&policy).unwrap(), "");
        fs::write(&policy, "home\ndownloads\n").unwrap();
        let shown = launch_files(&tools, key, "__ownsb__");
        assert_eq!(shown.home, "main");
        assert!(!shown.editable);
        reply.home = Some("private".into());
        assert!(with_files(&tools, key, &reply, got).is_err());
        assert_eq!(fs::read_to_string(policy).unwrap(), "home\ndownloads\n");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn hidden_preset_grants_cannot_override_the_main_permission_answer() {
        let req = window::Request {
            offers: vec![("folder=~/Downloads".into(), "Downloads".into())],
            ..window::Request::default()
        };
        let mut reply = window::Reply {
            offers: vec![
                "camera=on".into(),
                "folder=~/Downloads".into(),
                "session=on".into(),
            ],
            perms: vec![("camera".into(), "no".into())],
            ..window::Reply::default()
        };
        restrict_reply_offers(&req, &mut reply);
        assert_eq!(reply.offers, ["folder=~/Downloads"]);
        assert_eq!(reply.perms, [("camera".into(), "no".into())]);
        restrict_reply_offers(&window::Request::default(), &mut reply);
        assert!(reply.offers.is_empty());
    }

    /// The networks a program went out to from the real home, the latest
    /// last, each once.
    #[test]
    fn the_real_homes_networks_are_remembered() {
        let base = std::env::temp_dir().join(format!("vz-mainnets-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        assert!(main_networks(&base, "firefox").is_empty());
        note_main_network(&base, "firefox", "nl");
        note_main_network(&base, "firefox", "de");
        note_main_network(&base, "firefox", "nl");
        assert_eq!(main_networks(&base, "firefox"), ["de", "nl"]);
        assert!(main_networks(&base, "other").is_empty());
        let _ = fs::remove_dir_all(&base);
    }
    use super::*;
    use std::ffi::OsStr;

    fn argv(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn tags(rows: &[Row]) -> Vec<&str> {
        rows.iter().map(|(tag, _)| tag.as_str()).collect()
    }

    fn text_of<'a>(rows: &'a [Row], tag: &str) -> &'a str {
        rows.iter()
            .find(|(t, _)| t == tag)
            .map(|(_, text)| text.as_str())
            .unwrap_or_else(|| panic!("нет пункта «{tag}»"))
    }

    fn nothing(_: &str) -> bool {
        false
    }

    fn anything(_: &str) -> bool {
        true
    }

    // --- ARGUMENTS -----------------------------------------------------------

    /// 2026-09-28: what the picker hears of a launch it watches — its word
    /// that it did not start, with the whole of why, while another holder
    /// (the Wayland proxy) keeps the pipe open; its end with nothing said;
    /// a window.
    #[test]
    fn a_launch_that_did_not_start_is_heard_with_why() {
        let say = |told: &OwnedFd, word: &[u8]| {
            // SAFETY: a valid descriptor and a buffer of ours.
            let n = unsafe { libc::write(told.as_raw_fd(), word.as_ptr().cast(), word.len()) };
            assert_eq!(usize::try_from(n).unwrap(), word.len());
        };
        let (heard, told) = crate::sys::pipe().unwrap();
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let mut word = vec![crate::wl_sandbox::WORD_NOT_STARTED];
        word.extend_from_slice("в контейнере нет программы steam".as_bytes());
        say(&told, &word);
        match opened_or_ended(&heard, &mut child) {
            Heard::NotStarted(why) => assert_eq!(why, "в контейнере нет программы steam"),
            _ => panic!("not heard as not started"),
        }
        drop(told);
        let _ = child.kill();
        let _ = child.wait();
        // Ended, nothing said: its status.
        let (heard, told) = crate::sys::pipe().unwrap();
        let mut child = std::process::Command::new("sh")
            .args(["-c", "exit 127"])
            .spawn()
            .unwrap();
        drop(told);
        match opened_or_ended(&heard, &mut child) {
            Heard::Ended(status) => assert_eq!(status.code(), Some(127)),
            _ => panic!("not heard as ended"),
        }
        // A window.
        let (heard, told) = crate::sys::pipe().unwrap();
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        say(&told, &[crate::wl_sandbox::WORD_OPENED]);
        assert!(matches!(opened_or_ended(&heard, &mut child), Heard::Opened));
        let _ = child.kill();
        let _ = child.wait();
        // A word with nothing after it: why is the unsaid one.
        let (heard, told) = crate::sys::pipe().unwrap();
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        say(&told, &[crate::wl_sandbox::WORD_NOT_STARTED]);
        match opened_or_ended(&heard, &mut child) {
            Heard::NotStarted(why) => assert_eq!(why, NOT_STARTED_UNSAID),
            _ => panic!("not heard as not started"),
        }
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn the_autostart_flag_is_taken_before_the_command() {
        let a = Args::parse(&argv(&[
            "--autostart",
            "--id",
            "tg",
            "--",
            "telegram",
            "-autostart",
        ]));
        assert!(a.autostart);
        assert_eq!(a.id.as_deref(), Some(OsStr::new("tg")));
        assert_eq!(a.cmd, argv(&["telegram", "-autostart"]));
        // After `--` it belongs to the program.
        let a = Args::parse(&argv(&["--id", "x", "--", "x", "--autostart"]));
        assert!(!a.autostart);
    }

    // --- AUTOSTART -----------------------------------------------------------

    fn unbound(_: &Container) -> Option<String> {
        None
    }

    #[test]
    fn an_unassigned_program_starts_offline_in_a_home_of_its_own() {
        let memory = Memory {
            // What a dialog would preselect is not a consent to go online.
            last: "nl".into(),
            last_profile: "work".into(),
            fallback: "unconfined".into(),
            default_profile: "ask".into(),
            ..Memory::default()
        };
        let plan = autostart_plan(&memory, "tg", anything, unbound);
        assert_eq!(plan.zone, "offline");
        assert_eq!(plan.container.selector(), "app-tg");
        assert!(plan.network_guessed && plan.container_guessed);
    }

    #[test]
    fn what_was_chosen_for_a_program_is_honoured_at_login() {
        let memory = Memory {
            pinned_profile: "work".into(),
            default_profile: "ask".into(),
            ..Memory::default()
        };
        // The container's network: the program's own is gone.
        let bound = |c: &Container| (c.selector() == "work").then(|| "de".to_owned());
        let plan = autostart_plan(&memory, "tg", anything, bound);
        assert_eq!(
            (plan.zone.as_str(), plan.container.selector()),
            ("de", "work".to_owned())
        );
        assert!(!plan.network_guessed && !plan.container_guessed);
        // A container with no network yet: offline, and said.
        let plan = autostart_plan(&memory, "tg", anything, unbound);
        assert_eq!(plan.zone, "offline");
        assert!(plan.network_guessed && !plan.container_guessed);
        // The global default container's network is nobody's choice for an
        // unassigned program: offline at login, bound or not.
        let by_default = Memory {
            default_profile: "work".into(),
            ..Memory::default()
        };
        let plan = autostart_plan(&by_default, "tg", anything, bound);
        assert_eq!(plan.zone, "offline");
        assert!(plan.network_guessed);

        // The global container default is an answer, `ask` is not.
        for (default, selector) in [("main", ""), ("own", "app-tg"), ("work", "work")] {
            let memory = Memory {
                default_profile: default.into(),
                ..Memory::default()
            };
            let plan = autostart_plan(&memory, "tg", anything, unbound);
            assert_eq!(plan.container.selector(), selector, "{default}");
            assert!(!plan.container_guessed, "{default}");
            assert!(plan.network_guessed, "{default}");
        }
        // A default naming a container that is gone is no answer either.
        let memory = Memory {
            default_profile: "gone".into(),
            ..Memory::default()
        };
        let plan = autostart_plan(&memory, "tg", nothing, unbound);
        assert_eq!(plan.container.selector(), "app-tg");
        assert!(plan.container_guessed);

        // Running already: where it runs.
        let memory = Memory {
            running: Some(Running {
                zone: "nl".into(),
                selector: "sb:x".into(),
            }),
            ..Memory::default()
        };
        let plan = autostart_plan(&memory, "tg", anything, unbound);
        assert_eq!(
            (plan.zone.as_str(), plan.container.selector()),
            ("nl", "x".to_owned())
        );
    }

    #[test]
    fn the_shortcut_form_is_id_then_command() {
        let a = Args::parse(&argv(&["--id", "org.kde.dolphin", "--", "dolphin", "%u"]));
        assert_eq!(a.id.as_deref(), Some(OsStr::new("org.kde.dolphin")));
        assert_eq!(a.label, None);
        assert_eq!(a.cmd, argv(&["dolphin", "%u"]));

        let a = Args::parse(&argv(&["--id", "x", "--label", "Зен", "--", "zen"]));
        assert_eq!(a.label.as_deref(), Some(OsStr::new("Зен")));
        assert_eq!(a.cmd, argv(&["zen"]));
    }

    #[test]
    fn a_leading_label_is_only_taken_when_a_separator_follows() {
        // The old shortcut format: shortcuts and the picker do not update
        // atomically, so both shapes have to parse.
        let a = Args::parse(&argv(&["AyuGram Desktop", "--", "env", "X=1", "AyuGram"]));
        assert_eq!(a.label.as_deref(), Some(OsStr::new("AyuGram Desktop")));
        assert_eq!(a.cmd, argv(&["env", "X=1", "AyuGram"]));

        // No `--` anywhere: the first word is the COMMAND and must not be eaten.
        let a = Args::parse(&argv(&["firefox", "--new-window"]));
        assert_eq!(a.label, None);
        assert_eq!(a.cmd, argv(&["firefox", "--new-window"]));

        // `--label` still wins over a positional one.
        let a = Args::parse(&argv(&["Старое", "--label", "Новое", "--", "x"]));
        assert_eq!(a.label.as_deref(), Some(OsStr::new("Новое")));
    }

    #[test]
    fn a_command_can_be_given_without_the_separator() {
        let a = Args::parse(&argv(&["--id", "x", "firefox"]));
        assert_eq!(a.cmd, argv(&["firefox"]));
        // Nothing at all is the "нечего запускать" case.
        assert!(Args::parse(&[]).cmd.is_empty());
        assert!(Args::parse(&argv(&["--id", "x", "--"])).cmd.is_empty());
        // A flag with no value is not a crash and not a key.
        assert_eq!(Args::parse(&argv(&["--id"])).id, None);
    }

    #[test]
    fn the_fallback_key_walks_past_wrappers_and_assignments() {
        assert_eq!(
            fallback_key(&argv(&["env", "DESKTOPINTEGRATION=1", "AyuGram"])),
            OsString::from("AyuGram")
        );
        assert_eq!(
            fallback_key(&argv(&["/nix/store/x/bin/firefox", "--new-window"])),
            OsString::from("firefox")
        );
        // One more wrapper than `launch::app_word` knows: a delegated launch is
        // keyed by the program, not by systemd-run.
        assert_eq!(
            fallback_key(&argv(&["systemd-run", "--user", "telegram-desktop"])),
            OsString::from("telegram-desktop")
        );
        // `sh -c '…'`: the whole word, not skipped, or the key would be empty.
        assert_eq!(
            fallback_key(&argv(&["sh", "-c", "exec foo --url=https://x"])),
            OsString::from("x")
        );
        // Nothing recognisable at all still yields a key.
        assert_eq!(fallback_key(&argv(&["env"])), OsString::from("программа"));
        assert_eq!(fallback_key(&[]), OsString::from("программа"));
    }

    #[test]
    fn a_typed_name_keeps_its_cyrillic_and_loses_what_breaks_a_dialog() {
        assert_eq!(sanitize_name("личное"), "личное");
        assert_eq!(sanitize_name("два слова"), "два_слова");
        assert_eq!(sanitize_name("a/b\"c'd`e\\f"), "a_b_c_d_e_f");
        // A leading dash makes kdialog take the argument for an option and
        // close without a word.
        assert_eq!(sanitize_name("-x"), "x");
        assert_eq!(sanitize_name("..-.-a"), "a");
        assert_eq!(sanitize_name("---"), "");
        assert_eq!(sanitize_name(""), "");
    }

    // --- THE DECISION MACHINE ------------------------------------------------

    fn memory() -> Memory {
        Memory {
            fallback: "offline".to_owned(),
            default_profile: "ask".to_owned(),
            ..Memory::default()
        }
    }

    #[test]
    fn the_builtin_main_home_keeps_a_programs_network_without_a_named_container() {
        let mut m = memory();
        m.pinned_profile = MAIN.to_owned();
        m.bound = "host".to_owned();
        assert_eq!(
            net_step(&m),
            NetStep::Bound {
                zone: "host".into()
            }
        );
        let plan = autostart_plan(&m, "terminal", |_| false, |_| None);
        assert_eq!(plan.zone, "host");
        assert!(plan.container.selector().is_empty());
        assert!(!plan.network_guessed);
    }

    /// `ask` shows the picker at login only when something had to be guessed
    /// and there is a screen; what is chosen starts without a question, and
    /// `offline` or a text console keep the closed variant.
    #[test]
    fn autostart_asks_only_for_what_was_not_chosen_and_only_on_a_screen() {
        let plan = |network_guessed, container_guessed| AutostartPlan {
            zone: "offline".to_owned(),
            container: Container::default(),
            network_guessed,
            container_guessed,
        };
        assert!(autostart_asks("ask", &plan(true, true), true));
        assert!(autostart_asks("ask", &plan(true, false), true));
        assert!(autostart_asks("ask", &plan(false, true), true));
        assert!(
            !autostart_asks("ask", &plan(false, false), true),
            "all chosen: no question"
        );
        assert!(
            !autostart_asks("ask", &plan(true, true), false),
            "a text console: nobody to ask"
        );
        assert!(
            !autostart_asks("offline", &plan(true, true), true),
            "the closed variant, when set"
        );
    }

    #[test]
    fn a_running_program_that_hands_over_is_started_where_it_already_runs() {
        let mut m = memory();
        m.running = Some(Running {
            zone: "nl".to_owned(),
            selector: "sb:work".to_owned(),
        });
        m.hands_over = true;
        // Even a bound container does not get a say: the window is going to be
        // raised by the process that is already up.
        m.bound = "de".to_owned();
        assert_eq!(
            net_step(&m),
            NetStep::Running {
                zone: "nl".to_owned(),
                selector: "sb:work".to_owned()
            }
        );
        // VPN_ZONE_ASK is the way past it — that is what the re-exec sets.
        m.ask = true;
        assert_eq!(
            net_step(&m),
            NetStep::Ask {
                default: "nl".to_owned()
            }
        );
    }

    /// A running terminal also gets the choice to focus it, open another
    /// window there, or choose a different home/network. No browser list.
    #[test]
    fn a_running_program_not_known_to_hand_over_gets_running_menu() {
        let mut m = memory();
        m.last = "de".to_owned();
        m.running = Some(Running {
            zone: "nl".to_owned(),
            selector: String::new(),
        });
        assert_eq!(
            net_step(&m),
            NetStep::Running {
                zone: "nl".to_owned(),
                selector: String::new()
            }
        );
        // The host's network under its old name is chosen as the new one.
        m.running = Some(Running {
            zone: "direct".to_owned(),
            selector: String::new(),
        });
        assert_eq!(
            net_step(&m),
            NetStep::Running {
                zone: "direct".to_owned(),
                selector: String::new()
            }
        );
        m.bound = "de".to_owned();
        assert!(matches!(net_step(&m), NetStep::Running { .. }));
    }

    /// Only a launch into the network the program runs in is watched, only
    /// while it is not known to hand over, and never from inside a zone.
    #[test]
    fn a_hand_over_is_watched_for_only_where_it_can_be_told() {
        let mut m = memory();
        assert!(!watch_handover(&m, "nl", false), "not running");
        m.running = Some(Running {
            zone: "nl".to_owned(),
            selector: String::new(),
        });
        assert!(watch_handover(&m, "nl", false));
        assert!(
            !watch_handover(&m, "de", false),
            "another network: run warns"
        );
        assert!(!watch_handover(&m, "nl", true), "delegated from a zone");
        m.running = Some(Running {
            zone: "direct".to_owned(),
            selector: String::new(),
        });
        assert!(watch_handover(&m, "unconfined", false));
        m.hands_over = true;
        assert!(!watch_handover(&m, "unconfined", false), "known already");
    }

    #[test]
    fn a_container_bound_to_a_network_answers_the_network_question() {
        let mut m = memory();
        m.bound = "nl".to_owned();
        // The last choice is only where a question would start.
        m.last = "de".to_owned();
        assert_eq!(
            net_step(&m),
            NetStep::Bound {
                zone: "nl".to_owned()
            }
        );
        // A running instance that hands over still wins: its window is
        // raised where it is.
        m.running = Some(Running {
            zone: "nl".to_owned(),
            selector: "work".to_owned(),
        });
        m.hands_over = true;
        assert!(matches!(net_step(&m), NetStep::Running { .. }));
        // One that does not: the running menu still appears.
        m.hands_over = false;
        assert!(matches!(net_step(&m), NetStep::Running { .. }));
        // And VPN_ZONE_ASK still opens the dialog.
        m.running = None;
        m.ask = true;
        assert!(matches!(net_step(&m), NetStep::Ask { .. }));
    }

    /// A container not bound to a network yet — and the main home, and a
    /// throwaway one — have it asked (`docs/PERMISSIONS.md` §11.8): a
    /// program has no network of its own to skip the question with.
    #[test]
    fn a_container_with_no_network_has_it_asked() {
        let mut m = memory();
        m.last = "nl".to_owned();
        for pinned in ["work", "", THROWAWAY] {
            m.pinned_profile = pinned.to_owned();
            assert_eq!(
                net_step(&m),
                NetStep::Ask {
                    default: "nl".to_owned()
                },
                "{pinned}"
            );
        }
    }

    #[test]
    fn without_a_pin_the_dialog_opens_on_the_last_choice_then_the_default() {
        let mut m = memory();
        assert_eq!(
            net_step(&m),
            NetStep::Ask {
                default: "offline".to_owned()
            }
        );
        m.fallback = "unconfined".to_owned();
        assert_eq!(
            net_step(&m),
            NetStep::Ask {
                default: "unconfined".to_owned()
            }
        );
        m.last = "nl".to_owned();
        assert_eq!(
            net_step(&m),
            NetStep::Ask {
                default: "nl".to_owned()
            }
        );
    }

    #[test]
    fn a_selector_is_read_back_into_the_three_variables() {
        assert_eq!(Container::from_selector("", nothing), Container::default());
        assert_eq!(
            Container::from_selector(MAIN, nothing),
            Container::default()
        );
        assert_eq!(
            Container::from_selector("__fs__", nothing),
            Container {
                fs_sandbox: true,
                ..Container::default()
            }
        );
        // A container that exists, by its name, whatever its home.
        assert_eq!(
            Container::from_selector("work", anything),
            Container {
                profile: "work".to_owned(),
                ..Container::default()
            }
        );
        // The old prefix asks for a home of its own and nothing else: `run
        // --sandbox` refuses a layer or the main home by that name.
        assert_eq!(
            Container::from_selector("sb:work", anything),
            Container {
                fs_sandbox: true,
                sandbox: "work".to_owned(),
                ..Container::default()
            }
        );
        // One that is gone is made again with a home of its own: the
        // program's own home, never the whole real one.
        assert_eq!(
            Container::from_selector("sb:app-firefox", nothing),
            Container {
                fs_sandbox: true,
                sandbox: "app-firefox".to_owned(),
                ..Container::default()
            }
        );
        // Checked: a container that has been deleted is no answer, and the
        // caller decides.
        assert_eq!(Container::from_selector_checked("work", nothing), None);
        assert_eq!(
            Container::from_selector_checked("work", anything).map(|c| c.profile),
            Some("work".to_owned())
        );
        assert_eq!(
            Container::from_selector_checked(TMP, nothing).map(|c| c.profile),
            Some(TMP.to_owned())
        );
    }

    #[test]
    fn the_selector_that_is_written_back_is_the_choice_not_the_variable() {
        let sandbox = Container {
            fs_sandbox: true,
            sandbox: "work".to_owned(),
            ..Container::default()
        };
        assert_eq!(sandbox.selector(), "work");
        assert_eq!(
            Container {
                fs_sandbox: true,
                ..Container::default()
            }
            .selector(),
            "__fs__"
        );
        assert_eq!(Container::default().selector(), "");
        assert_eq!(
            Container {
                profile: "work".to_owned(),
                ..Container::default()
            }
            .selector(),
            "work"
        );
        // And it round-trips, which is what makes the re-exec faithful: once
        // made, the container is found by its name.
        assert_eq!(
            Container::from_selector(&sandbox.selector(), anything).selector(),
            "work"
        );
        assert_eq!(
            Container::from_selector(&sandbox.selector(), nothing),
            sandbox
        );
        // One-off containers are never remembered.
        for profile in [TMP, "tmpjoin:/tmp/vpn-profile-abc"] {
            let c = Container {
                profile: profile.to_owned(),
                ..Container::default()
            };
            assert!(c.is_throwaway_container(), "{profile}");
        }
        assert!(!Container::default().is_throwaway_container());
        assert!(!sandbox.is_throwaway_container());
    }

    #[test]
    fn the_fresh_choice_outranks_the_pin_and_the_pin_outranks_the_memory() {
        let mut m = memory();
        m.pinned_profile = "pinned".to_owned();
        m.last_profile = "last".to_owned();

        // 1. What "⚙ Сменить контейнер" just answered. Including a throwaway
        //    one, which is exactly what used to be lost across the re-exec.
        assert_eq!(
            container_without_dialog(&m, "k", anything, Some(TMP)).profile,
            TMP
        );
        assert_eq!(
            container_without_dialog(&m, "k", anything, Some(MAIN)),
            Container::default()
        );
        // An empty variable is "not set", not "main".
        assert_eq!(
            container_without_dialog(&m, "k", anything, Some("")).profile,
            "pinned"
        );

        // 2. The pin — and with ASK set, too: that is the fix for "↺ Спрашивать
        //    сеть снова" dropping a pinned container into the main profile.
        m.ask = true;
        assert_eq!(
            container_without_dialog(&m, "k", anything, None).profile,
            "pinned"
        );
        m.ask = false;

        // 3. The last choice, when nothing is pinned.
        m.pinned_profile.clear();
        assert_eq!(
            container_without_dialog(&m, "k", anything, None).profile,
            "last"
        );
    }

    /// A program nobody ever chose a container for gets a home of its own —
    /// not the main home, which is somebody's choice (2026-09-27). A main
    /// home chosen before stays chosen: an empty `.lastprofile` file.
    #[test]
    fn a_program_seen_for_the_first_time_gets_a_home_of_its_own() {
        let own = Container {
            fs_sandbox: true,
            sandbox: "app-tg".to_owned(),
            ..Container::default()
        };
        let mut m = memory();
        m.default_profile = "ask".to_owned();
        assert_eq!(m.last_choice(), None);
        assert_eq!(container_without_dialog(&m, "tg", anything, None), own);

        m.container_chosen = true;
        assert_eq!(m.last_choice(), Some(""));
        assert_eq!(
            container_without_dialog(&m, "tg", anything, None),
            Container::default()
        );

        // A name read from the file is a choice, whatever the flag says.
        m.container_chosen = false;
        m.last_profile = "work".to_owned();
        assert_eq!(m.last_choice(), Some("work"));
    }

    #[test]
    fn the_global_default_container_outranks_the_last_choice() {
        let mut m = memory();
        m.last_profile = "last".to_owned();

        m.default_profile = "main".to_owned();
        assert_eq!(
            container_without_dialog(&m, "k", anything, None),
            Container::default()
        );

        m.default_profile = "own".to_owned();
        assert_eq!(
            container_without_dialog(&m, "firefox", anything, None),
            Container {
                fs_sandbox: true,
                sandbox: "app-firefox".to_owned(),
                ..Container::default()
            }
        );

        m.default_profile = "work".to_owned();
        assert_eq!(
            container_without_dialog(&m, "k", anything, None).profile,
            "work"
        );
        // A default naming a container that is gone leaves the last choice
        // alone, as the shell's `[ -d … ] && profile=$defp` did.
        m.default_profile = "gone".to_owned();
        assert_eq!(
            container_without_dialog(&m, "k", |name| name == "last", None).profile,
            "last"
        );
        // And a last choice that is gone is the program's own home, not the
        // whole real one.
        assert_eq!(
            container_without_dialog(&m, "k", nothing, None).selector(),
            "app-k"
        );
    }

    /// One launch, one container: a default is a whole container, never laid
    /// over a part of the last choice — the shell's partial overlay made one
    /// launch of a layer and a sandbox at once.
    #[test]
    fn a_default_container_is_whole() {
        let mut m = memory();
        m.last_profile = "work".to_owned();
        m.default_profile = "main".to_owned();
        assert_eq!(
            container_without_dialog(&m, "k", anything, None),
            Container::default()
        );
        m.default_profile = "other".to_owned();
        let c = container_without_dialog(&m, "k", anything, None);
        assert_eq!((c.profile.as_str(), c.sandbox.as_str()), ("other", ""));
    }

    #[test]
    fn a_pin_is_dropped_only_when_what_it_names_is_gone() {
        assert!(pin_is_valid("", nothing));
        // Built-in choices are not zones and are always valid.
        assert!(pin_is_valid("unconfined", nothing));
        assert!(pin_is_valid("direct", nothing));
        assert!(pin_is_valid("offline", nothing));
        assert!(pin_is_valid("nl", |z| z == "nl"));
        assert!(!pin_is_valid("nl", nothing));

        // The program's own container is valid before its first launch makes
        // it: checking it as one that must exist erased the pin on the next
        // click, and "🔒 Своя песочница — всегда" never worked at all.
        assert!(profile_pin_is_valid("app-firefox", nothing));
        assert!(profile_pin_is_valid("sb:app-firefox", nothing));
        // A pinned sandbox is made again when it is gone, as it always was.
        assert!(profile_pin_is_valid("sb:work", nothing));
        assert!(!profile_pin_is_valid("work", nothing));
        assert!(profile_pin_is_valid(THROWAWAY, nothing));
        assert!(profile_pin_is_valid(MAIN, nothing));
        assert!(profile_pin_is_valid("", nothing));
        assert!(profile_pin_is_valid("work", |p| p == "work"));
        assert!(!profile_pin_is_valid("work", nothing));
    }

    // --- THE MENUS -----------------------------------------------------------

    #[test]
    fn the_network_menu_does_not_offer_an_illusory_full_host_pin() {
        let zone = |name: &str| MenuZone {
            name: name.to_owned(),
            ..MenuZone::default()
        };
        let menu = net_menu(&[zone("de"), zone("nl")], "", "настоящий дом");
        assert_eq!(
            tags(&menu),
            [
                "unconfined",
                "offline",
                "host",
                "de",
                "nl",
                "pin:offline",
                "pin:host",
                "pin:de",
                "pin:nl",
                "__chooseprofile__",
            ]
        );
        assert_eq!(
            text_of(&menu, "host"),
            "Сеть хоста — без VPN, программа в своём контейнере"
        );
        assert_eq!(text_of(&menu, "nl"), "VPN: nl");
        assert_eq!(text_of(&menu, "pin:nl"), "Всегда: VPN: nl");
        let chain = MenuZone {
            name: "ch".to_owned(),
            chain_path: Some("home → nl → ch".to_owned()),
            ..MenuZone::default()
        };
        let menu = net_menu(&[chain], "", "настоящий дом");
        assert_eq!(text_of(&menu, "ch"), "VPN-цепочка: home → nl → ch");
        assert_eq!(
            text_of(&menu, "__chooseprofile__"),
            "⚙ Сменить контейнер (сейчас: настоящий дом)…"
        );
        // The way back out of a pin is only offered when there is one — of
        // the program's container: the network is the container's.
        let menu = net_menu(&[], "work", "work");
        assert_eq!(
            text_of(&menu, "unpin"),
            "↺ Спрашивать снова (программа закреплена за контейнером work)"
        );
        // A host interface is not called a VPN, and a dead tunnel says so.
        let menu = net_menu(
            &[
                MenuZone {
                    name: "lan".to_owned(),
                    host_interface: true,
                    dead: false,
                    ..MenuZone::default()
                },
                MenuZone {
                    name: "nl".to_owned(),
                    host_interface: false,
                    dead: true,
                    ..MenuZone::default()
                },
                MenuZone {
                    name: "mz".to_owned(),
                    system_zone: Some("sz".to_owned()),
                    ..MenuZone::default()
                },
            ],
            "",
            "настоящий дом",
        );
        assert_eq!(
            text_of(&menu, "lan"),
            "Через интерфейс: lan (без шифрования)"
        );
        assert_eq!(text_of(&menu, "nl"), "VPN: nl — туннель не отвечает");
        // A zone through a system zone is a VPN, and says whose tunnel it is.
        assert_eq!(
            text_of(&menu, "mz"),
            "VPN: mz (через системное подключение sz)"
        );
    }

    #[test]
    fn the_container_in_force_is_named_the_way_the_user_chose_it() {
        assert_eq!(container_label(""), "настоящий дом");
        assert_eq!(container_label(MAIN), "настоящий дом");
        assert_eq!(container_label(THROWAWAY), "разовый");
        assert_eq!(container_label("__fs__:7-9"), "разовый");
        assert_eq!(container_label("sb:app-firefox"), "свой");
        assert_eq!(container_label("sb:work"), "work — свой дом");
        assert_eq!(container_label("work"), "work");
        // A program's own container is one by its name, whatever the prefix.
        assert_eq!(container_label("app-firefox"), "свой");
        // A named one by its name and the kind of its home — the launch
        // window's words.
        use crate::container::Home;
        assert_eq!(label_of("dev", Some(Home::Private)), "dev — свой дом");
        assert_eq!(label_of("files", Some(Home::Main)), "files — настоящий дом");
        assert_eq!(label_of("work", Some(Home::Layer)), "work — слой над домом");
    }

    #[test]
    fn the_container_menu_lists_the_ways_to_split_data_and_the_ways_to_pin_them() {
        let profiles = vec![
            ProfileRow {
                name: "work".to_owned(),
                busy_in: "de".to_owned(),
                main: false,
                bound: String::new(),
                open: Vec::new(),
            },
            ProfileRow {
                name: "личное".to_owned(),
                busy_in: String::new(),
                main: false,
                bound: String::new(),
                open: Vec::new(),
            },
            ProfileRow {
                name: "files".to_owned(),
                busy_in: "de".to_owned(),
                main: true,
                bound: String::new(),
                open: Vec::new(),
            },
        ];
        let joins = vec![TmpJoinRow {
            dir: "/tmp/vpn-profile-abc".to_owned(),
            who: " firefox telegram".to_owned(),
        }];
        let menu = profile_menu(&["общая".to_owned()], &profiles, &joins, "", "nl");
        assert_eq!(
            tags(&menu),
            [
                "",
                "pinmain",
                "open",
                "pin:open",
                "__ownsb__",
                "pin:__ownsb__",
                "__fs__",
                "pin:__fs__",
                "общая",
                "pin:общая",
                "__newsb__",
                "work",
                "pin:work",
                "личное",
                "pin:личное",
                "files",
                "pin:files",
                "tmpjoin:/tmp/vpn-profile-abc",
                "__tmp__",
                "__new__",
            ]
        );
        // One vocabulary with the launch window: a container, by its name
        // and the kind of its home; the two throwaway kinds by what the
        // program sees.
        assert_eq!(
            text_of(&menu, ""),
            "Настоящий дом: все ваши файлы — ключи ssh, пароли браузера, токены"
        );
        assert_eq!(text_of(&menu, "pinmain"), "Настоящий дом — всегда");
        assert_eq!(
            text_of(&menu, "__ownsb__"),
            "🔒 Свой контейнер: постоянный дом только этой программы"
        );
        assert_eq!(
            text_of(&menu, "pin:__ownsb__"),
            "🔒 Свой контейнер — всегда"
        );
        assert_eq!(
            text_of(&menu, "__fs__"),
            "🔒 Разовый контейнер: пустой дом, стирается при выходе"
        );
        assert_eq!(
            text_of(&menu, "pin:__fs__"),
            "🔒 Разовый контейнер — всегда"
        );
        assert_eq!(text_of(&menu, "общая"), "🔒 Контейнер «общая»: свой дом");
        assert_eq!(
            text_of(&menu, "pin:общая"),
            "🔒 Контейнер «общая»: свой дом — всегда"
        );
        assert_eq!(
            text_of(&menu, "__newsb__"),
            "🔒➕ Новый контейнер со своим домом…"
        );
        // The main home says what it is, and is never "busy": it is one
        // identity in every network.
        assert_eq!(
            text_of(&menu, "files"),
            "⚠ Контейнер «files»: настоящий дом"
        );
        assert_eq!(
            text_of(&menu, "pin:files"),
            "⚠ Контейнер «files»: настоящий дом — всегда"
        );
        assert_eq!(
            text_of(&menu, "work"),
            "Контейнер «work»: слой над домом — занят сетью de"
        );
        assert_eq!(
            text_of(&menu, "pin:work"),
            "Контейнер «work»: слой над домом — всегда"
        );
        assert_eq!(
            text_of(&menu, "личное"),
            "Контейнер «личное»: слой над домом"
        );
        assert_eq!(
            text_of(&menu, "tmpjoin:/tmp/vpn-profile-abc"),
            "🗑 К открытому временному слою: firefox telegram"
        );
        assert_eq!(
            text_of(&menu, "__tmp__"),
            "🗑 Временный слой над домом: видит ваш дом, изменения сотрутся, когда выйдет \
             последняя программа"
        );
        assert_eq!(
            text_of(&menu, "__new__"),
            "➕ Новый контейнер — слой над домом…"
        );
        // Busy in the network we are about to use is not "busy" at all.
        let menu = profile_menu(&[], &profiles, &[], "", "de");
        assert_eq!(text_of(&menu, "work"), "Контейнер «work»: слой над домом");
        // The way back out of a container pin, when there is one.
        let menu = profile_menu(&[], &[], &[], "work", "nl");
        assert_eq!(text_of(&menu, "unpinprof"), "↺ Спрашивать контейнер снова");
    }

    // --- WHAT CAME BACK ------------------------------------------------------

    #[test]
    fn the_network_answers_are_told_apart() {
        assert_eq!(parse_net_choice(""), NetChoice::Nothing);
        assert_eq!(parse_net_choice("nl"), NetChoice::Zone("nl".to_owned()));
        assert_eq!(
            parse_net_choice("pin:offline"),
            NetChoice::Pin("offline".to_owned())
        );
        assert_eq!(parse_net_choice("unpin"), NetChoice::Unpin);
        assert_eq!(
            parse_net_choice("__chooseprofile__"),
            NetChoice::ChooseContainer
        );
    }

    #[test]
    fn the_container_answers_are_told_apart_pins_first() {
        use ProfileChoice as P;
        assert_eq!(parse_profile_choice(""), P::Main { pin: false });
        assert_eq!(parse_profile_choice("pinmain"), P::Main { pin: true });
        assert_eq!(
            parse_profile_choice("__ownsb__"),
            P::OwnSandbox { pin: false }
        );
        assert_eq!(
            parse_profile_choice("pin:__ownsb__"),
            P::OwnSandbox { pin: true }
        );
        assert_eq!(parse_profile_choice("__fs__"), P::Throwaway { pin: false });
        assert_eq!(
            parse_profile_choice("pin:__fs__"),
            P::Throwaway { pin: true }
        );
        assert_eq!(
            parse_profile_choice("sb:work"),
            P::Sandbox {
                name: "work".to_owned(),
                pin: false
            }
        );
        // The trap: `pin:sb:work` must not be read as a container called
        // `sb:work`.
        assert_eq!(
            parse_profile_choice("pin:sb:work"),
            P::Sandbox {
                name: "work".to_owned(),
                pin: true
            }
        );
        assert_eq!(parse_profile_choice("__newsb__"), P::NewSandbox);
        assert_eq!(parse_profile_choice("__new__"), P::NewProfile);
        assert_eq!(parse_profile_choice("__tmp__"), P::Tmp);
        assert_eq!(
            parse_profile_choice("tmpjoin:/tmp/vpn-profile-abc"),
            P::TmpJoin("/tmp/vpn-profile-abc".to_owned())
        );
        assert_eq!(parse_profile_choice("unpinprof"), P::Unpin);
        assert_eq!(
            parse_profile_choice("work"),
            P::Profile {
                name: "work".to_owned(),
                pin: false
            }
        );
        assert_eq!(
            parse_profile_choice("pin:work"),
            P::Profile {
                name: "work".to_owned(),
                pin: true
            }
        );
    }

    // --- THE COMMAND LINE ----------------------------------------------------

    #[test]
    fn the_launch_line_is_built_in_the_order_run_parses_it() {
        let runner = Path::new("/p/bin/vpn-zone");
        let cmd = argv(&["firefox", "%U"]);

        assert_eq!(
            run_argv(runner, "nl", &Container::default(), &cmd),
            argv(&["/p/bin/vpn-zone", "run", "nl", "--", "firefox", "%U"])
        );
        assert_eq!(
            run_argv(
                runner,
                "nl",
                &Container {
                    profile: "work".to_owned(),
                    ..Container::default()
                },
                &cmd
            ),
            argv(&[
                "/p/bin/vpn-zone",
                "run",
                "nl",
                "--container",
                "work",
                "--",
                "firefox",
                "%U"
            ])
        );
        assert_eq!(
            run_argv(
                runner,
                "offline",
                &Container {
                    fs_sandbox: true,
                    ..Container::default()
                },
                &cmd
            ),
            argv(&[
                "/p/bin/vpn-zone",
                "run",
                "offline",
                "--fs-sandbox",
                "--",
                "firefox",
                "%U"
            ])
        );
        // A named sandbox replaces the throwaway flag rather than joining it.
        assert_eq!(
            run_argv(
                runner,
                "nl",
                &Container {
                    fs_sandbox: true,
                    sandbox: "work".to_owned(),
                    ..Container::default()
                },
                &cmd
            ),
            argv(&[
                "/p/bin/vpn-zone",
                "run",
                "nl",
                "--sandbox",
                "work",
                "--",
                "firefox",
                "%U"
            ])
        );
        assert_eq!(
            run_argv(
                runner,
                "nl",
                &Container {
                    profile: TMP.to_owned(),
                    ..Container::default()
                },
                &cmd
            ),
            argv(&[
                "/p/bin/vpn-zone",
                "run",
                "nl",
                "--tmp-profile",
                "--",
                "firefox",
                "%U"
            ])
        );
        assert_eq!(
            run_argv(
                runner,
                "nl",
                &Container {
                    profile: "tmpjoin:/tmp/vpn-profile-abc".to_owned(),
                    ..Container::default()
                },
                &cmd
            ),
            argv(&[
                "/p/bin/vpn-zone",
                "run",
                "nl",
                "--tmp-profile",
                "--join",
                "/tmp/vpn-profile-abc",
                "--",
                "firefox",
                "%U"
            ])
        );
    }

    #[test]
    fn what_the_picker_writes_is_what_run_parses() {
        // The two halves of one contract: whatever menu row was chosen, the
        // line that comes out has to be understood by `vpn-zone run`.
        use crate::launch::{Sandbox, Selection};
        for tag in [
            "",
            "__fs__",
            "__fs__:7-9",
            "sb:work",
            "work",
            "__tmp__",
            "tmpjoin:/tmp/p",
        ] {
            // `sb:work` of an older window: here, before anything resolves
            // it, the name as a sandbox.
            let container = match parse_profile_choice(tag) {
                ProfileChoice::Main { .. } => Container::default(),
                ProfileChoice::Throwaway { .. } => Container {
                    fs_sandbox: true,
                    ..Container::default()
                },
                ProfileChoice::ThrowawayJoin(join) => Container {
                    fs_sandbox: true,
                    join,
                    ..Container::default()
                },
                ProfileChoice::Sandbox { name, .. } => Container {
                    fs_sandbox: true,
                    sandbox: name,
                    ..Container::default()
                },
                ProfileChoice::Tmp => Container {
                    profile: TMP.to_owned(),
                    ..Container::default()
                },
                ProfileChoice::TmpJoin(dir) => Container {
                    profile: format!("{TMPJOIN_PREFIX}{dir}"),
                    ..Container::default()
                },
                ProfileChoice::Profile { name, .. } => Container {
                    profile: name,
                    ..Container::default()
                },
                other => panic!("неожиданный разбор «{tag}»: {other:?}"),
            };
            let line = run_argv(Path::new("/p/vpn-zone"), "nl", &container, &argv(&["x"]));
            let parsed = Selection::parse(&line[2..]).unwrap_or_else(|e| panic!("«{tag}»: {e}"));
            assert_eq!(parsed.zone, OsString::from("nl"), "«{tag}»");
            assert_eq!(parsed.cmd, argv(&["x"]), "«{tag}»");
            if !container.sandbox.is_empty() {
                assert_eq!(
                    parsed.sandbox,
                    Sandbox::Named(container.sandbox.as_str().into()),
                    "«{tag}»"
                );
            } else if container.fs_sandbox {
                let join = (!container.join.is_empty()).then(|| container.join.as_str().into());
                assert_eq!(parsed.sandbox, Sandbox::Throwaway(join), "«{tag}»");
            }
        }
    }

    /// The launch window's container column in the menu's words: a
    /// container by its name and the kind of its home, the two throwaway
    /// kinds by what the program sees.
    #[test]
    fn the_window_names_a_container_by_the_kind_of_its_home() {
        let row = |name: &str, main: bool| ProfileRow {
            name: name.to_owned(),
            main,
            ..ProfileRow::default()
        };
        let joins = vec![TmpJoinRow {
            dir: "/tmp/vpn-profile-abc".to_owned(),
            who: " firefox".to_owned(),
        }];
        let fs_open = vec![OpenThrowaway {
            name: "7-9".to_owned(),
            zone: "nl".to_owned(),
            who: vec!["Firefox".to_owned(), "foot".to_owned()],
        }];
        let mut bank = row("банк", false);
        bank.open = vec!["Firefox".to_owned()];
        let items = window_containers(
            "firefox",
            &[row("общая", false)],
            &[bank, row("files", true)],
            &joins,
            &fs_open,
            "",
        );
        let labels: Vec<(&str, &str)> = items
            .iter()
            .map(|i| (i.tag.as_str(), i.label.as_str()))
            .collect();
        assert_eq!(
            labels,
            [
                (
                    "",
                    "Настоящий дом — все ваши файлы: ключи ssh, пароли браузера, токены"
                ),
                (
                    "open",
                    "Без изоляции — у программы всё, что у хоста: устройства, сеанс, все файлы"
                ),
                (
                    "__ownsb__",
                    "Свой контейнер — постоянный дом только этой программы; будет создан"
                ),
                (
                    "__fs__",
                    "Новый разовый контейнер — пустой дом, стирается, когда выйдет \
                     последняя программа"
                ),
                (
                    "__fs__:7-9",
                    "Открытый разовый контейнер — открыт: Firefox, foot"
                ),
                ("общая", "Контейнер «общая» — свой дом"),
                ("банк", "Контейнер «банк» — слой над домом; открыт: Firefox"),
                ("files", "Контейнер «files» — настоящий дом"),
                (
                    "tmpjoin:/tmp/vpn-profile-abc",
                    "К открытому временному слою: firefox"
                ),
                (
                    "__tmp__",
                    "Временный слой над домом — видит ваш дом, изменения сотрутся, когда \
                     выйдет последняя программа"
                ),
                ("__newsb__", "Новый контейнер со своим домом…"),
                ("__new__", "Новый контейнер — слой над домом…"),
            ]
        );
    }

    /// Each row of the window shows the permissions of where they are kept:
    /// a record, a container to be made, this launch alone, or nothing to
    /// say.
    #[test]
    fn each_container_row_shows_whose_permissions_it_has() {
        let open = [("work", &[][..]), ("app-firefox", &[][..])];
        let of = |tag, made| perm_scope(tag, "app-firefox", made, &open);
        assert_eq!(of("", true), Some(PermScope::Record("main")));
        assert_eq!(of("open", true), Some(PermScope::Open));
        assert_eq!(
            of("__ownsb__", true),
            Some(PermScope::Record("app-firefox"))
        );
        assert_eq!(of("__ownsb__", false), Some(PermScope::New));
        assert_eq!(of("__newsb__", true), Some(PermScope::New));
        assert_eq!(of("__fs__", true), Some(PermScope::Launch));
        assert_eq!(of("__tmp__", true), Some(PermScope::Launch));
        assert_eq!(of("__fs__:7-9", true), Some(PermScope::Joined));
        assert_eq!(of("tmpjoin:/x", true), Some(PermScope::Joined));
        assert_eq!(of("work", true), Some(PermScope::Record("work")));
        assert_eq!(of("gone", true), None);
    }

    /// A remembered choice that is no longer offered starts the question on
    /// the safe rows — never the first one, which is the host's network, nor
    /// the main profile with the whole home.
    #[test]
    fn a_choice_that_is_gone_is_not_replaced_by_the_first_row() {
        let zones = vec![MenuZone {
            name: "de".to_owned(),
            host_interface: false,
            system_zone: None,
            dead: false,
            chain_path: None,
        }];
        let nets = window_nets(&zones, "nl-removed");
        let chosen: Vec<&str> = nets
            .iter()
            .filter(|i| i.selected)
            .map(|i| i.tag.as_str())
            .collect();
        assert_eq!(chosen, ["offline"]);
        assert!(window_nets(&zones, "de")
            .iter()
            .any(|i| i.selected && i.tag == "de"));
        // A retry's explicit draft choice must win over the presence of
        // the VPN used by the running copy; the host network is not the
        // unconfined launch mode.
        let host = window_nets(&zones, "host");
        let selected: Vec<_> = host
            .iter()
            .filter(|i| i.selected)
            .map(|i| i.tag.as_str())
            .collect();
        assert_eq!(selected, ["host"]);
        // A container's network goes with its row: the window does not
        // offer it with another.
        let row = |name: &str, bound: &str| ProfileRow {
            name: name.to_owned(),
            bound: bound.to_owned(),
            ..ProfileRow::default()
        };
        let items = window_containers(
            "firefox",
            &[row("app-firefox", "nl"), row("dev", "de")],
            &[row("work", "")],
            &[],
            &[],
            "",
        );
        let bound_of = |tag: &str| items.iter().find(|i| i.tag == tag).unwrap().bound.clone();
        assert_eq!(bound_of("__ownsb__").as_deref(), Some("nl"));
        assert_eq!(bound_of("dev").as_deref(), Some("de"));
        assert_eq!(bound_of("work"), None);

        let containers = window_containers("firefox", &[], &[], &[], &[], "sb:removed");
        let chosen: Vec<&str> = containers
            .iter()
            .filter(|i| i.selected)
            .map(|i| i.tag.as_str())
            .collect();
        assert_eq!(chosen, ["__ownsb__"]);
    }
}

#[cfg(test)]
mod source_context_tests {
    use super::*;

    fn request() -> window::Request {
        window::Request {
            asker: Some("host".into()),
            containers: ["app-browser", "work", "other"]
                .into_iter()
                .map(|tag| window::Item {
                    tag: tag.into(),
                    selected: tag == "app-browser",
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn source_proposes_existing_identity_without_changing_network_or_creating_rows() {
        let mut req = request();
        propose_source_container(&mut req, "browser", "work");
        assert_eq!(
            req.containers
                .iter()
                .filter(|c| c.selected)
                .map(|c| c.tag.as_str())
                .collect::<Vec<_>>(),
            ["work"]
        );
        assert_eq!(req.asker.as_deref(), Some("host"));
        assert_eq!(req.containers.len(), 3);
        assert_eq!(req.notes.len(), 1);
    }

    #[test]
    fn absent_new_and_other_network_sources_do_not_replace_the_proposal() {
        for mode in 0..4 {
            let mut req = request();
            let source = if mode == 0 { "missing" } else { "work" };
            if mode == 1 {
                req.containers[1].new = true;
            }
            if mode == 2 {
                req.containers[1].bound = Some("vpn".into());
            }
            if mode == 3 {
                req.containers[1].busy = Some("vpn".into());
            }
            propose_source_container(&mut req, "browser", source);
            assert!(req.containers[0].selected);
            assert!(!req.containers[1].selected);
            assert!(req.notes.is_empty());
        }
    }
}
