//! The clipboard by container (the owner, 2026-10-15): what is copied in a
//! container is read freely by its programs; what was copied elsewhere — in
//! another container, on the host — only when the person pastes it.
//!
//! **Whose a selection is.** What a program of a launch copies
//! (`wl_data_source`, the primary selection's source) is offered by the
//! Wayland proxy with one more type, the mark of its container's instance
//! ([`MARK_PREFIX`] and a secret of the instance's, [`token_for`]): a type
//! nobody reads — the proxy answers no request for it — and that no
//! program sees, as the proxy passes no mark on to its program. A program
//! cannot say a mark of its own either: its sources' marks are dropped.
//! An offer that came with the mark of the launch's instance is its own;
//! one with another mark, or none — the host's, another container's — is
//! foreign.
//!
//! **When a foreign one is read.** Its contents go to the program only
//! within [`PASTE_WINDOW`] after a paste of the person's — Ctrl+V, Ctrl+Shift+V,
//! Shift+Insert ([`is_paste`]), a middle click for the primary selection — as
//! the compositor delivered it to the program, or when it was dragged onto
//! the program: a program reading the clipboard each time it gets the focus
//! gets nothing of another container's. The types offered are seen as
//! before: a program knows that there is something to paste.
//!
//! **What it does not cover.** A paste from a program's own menu of a
//! foreign selection gives nothing (a button of the frame for it is next).
//! The instance's own secret is known to its proxies alone, on the host;
//! a program of the host, which is not proxied, reads every mark — and
//! could do anything else anyway.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The type a launch's copy is marked with, before its instance's secret.
pub const MARK_PREFIX: &str = "application/x-cellward-clip-";

/// How long after a paste of the person's a foreign selection may be read.
pub const PASTE_WINDOW: Duration = Duration::from_secs(2);

/// What the clipboard history offers beside an entry it made the selection
/// for a paste (`cellward-clip`'s `select`): a mark of nobody's instance.
pub const HISTORY_MARK: &str = "application/x-cellward-clip-recorder";

/// Below the runtime directory: an instance's secret, one file each.
pub const DIR: &str = "vpn-zones/clip";

/// evdev's middle button.
pub const BTN_MIDDLE: u32 = 0x112;
const KEY_V: u32 = 47;
const KEY_INSERT: u32 = 110;
/// xkb's modifier masks, in the order every keymap of a compositor has them.
const SHIFT: u32 = 1 << 0;
const CONTROL: u32 = 1 << 2;

/// Which selection a paste is of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Which {
    Clipboard,
    Primary,
}

#[derive(Default)]
struct State {
    mark: RefCell<Option<String>>,
    /// A paste of the history's to press for the person, until then.
    inject: Cell<Option<Instant>>,
    /// Offers that came with [`HISTORY_MARK`], the last few by id; and
    /// whether the selection the program was told of last is one.
    history_offers: RefCell<VecDeque<u64>>,
    history_selected: Cell<bool>,
    clipboard: Cell<Option<Instant>>,
    primary: Cell<Option<Instant>>,
    dragged: RefCell<VecDeque<u64>>,
    said: Cell<Option<Instant>>,
}

thread_local! {
    // The proxy is one thread: its connections share what the person did.
    static STATE: State = State::default();
}

/// The launch's mark, set once in the proxy before it serves.
pub fn set_mark(token: Option<&str>) {
    STATE.with(|s| *s.mark.borrow_mut() = token.map(|t| format!("{MARK_PREFIX}{t}")));
}

/// The type this launch's copies are marked with.
pub fn mark() -> Option<String> {
    STATE.with(|s| s.mark.borrow().clone())
}

/// Whether a type is a mark — anybody's.
pub fn is_mark(mime_type: &str) -> bool {
    mime_type.starts_with(MARK_PREFIX)
}

/// Whether a type is this launch's instance's mark.
pub fn is_own(mime_type: &str) -> bool {
    STATE.with(|s| s.mark.borrow().as_deref() == Some(mime_type))
}

/// The keys a paste is on, as evdev codes: those that give `v` or `V` in
/// any group of the keymap (a shortcut is the Latin letter's in a second
/// layout too), and those that give `Insert`. The physical V and Insert of a
/// US keyboard where the keymap could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasteKeys {
    pub v: Vec<u32>,
    pub insert: Vec<u32>,
}

impl Default for PasteKeys {
    fn default() -> Self {
        Self {
            v: vec![KEY_V],
            insert: vec![KEY_INSERT],
        }
    }
}

/// [`PasteKeys`] of an XKB keymap as the compositor sends it (text, v1): the
/// codes of its `xkb_keycodes` (less 8, the X offset), aliases followed, and
/// the keys of its `xkb_symbols` with those symbols among theirs.
pub fn paste_keys(keymap: &str) -> PasteKeys {
    use std::collections::HashMap;
    let section = |name: &str| -> Option<&str> {
        let start = keymap.find(name)?;
        let body = &keymap[start..];
        let open = body.find('{')?;
        let mut depth = 0;
        for (i, c) in body[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&body[open + 1..open + i]);
                    }
                }
                _ => {}
            }
        }
        None
    };
    let (Some(keycodes), Some(symbols)) = (section("xkb_keycodes"), section("xkb_symbols")) else {
        return PasteKeys::default();
    };
    let mut codes: HashMap<&str, u32> = HashMap::new();
    let mut aliases: Vec<(&str, &str)> = Vec::new();
    for statement in keycodes.split(';').map(str::trim) {
        if let Some(rest) = statement.strip_prefix("alias") {
            if let Some((a, b)) = rest.split_once('=') {
                aliases.push((a.trim(), b.trim()));
            }
        } else if let Some((name, code)) = statement.split_once('=') {
            let name = name.trim();
            if name.starts_with('<') {
                if let Ok(code) = code.trim().parse::<u32>() {
                    codes.insert(name, code);
                }
            }
        }
    }
    for (alias, real) in aliases {
        if let Some(code) = codes.get(real).copied() {
            codes.entry(alias).or_insert(code);
        }
    }
    let mut out = PasteKeys {
        v: Vec::new(),
        insert: Vec::new(),
    };
    let mut rest = symbols;
    while let Some(at) = rest.find("key ") {
        rest = &rest[at + 4..];
        let Some(name_end) = rest.find('>') else {
            break;
        };
        let name = rest[..=name_end].trim();
        let Some(body_start) = rest.find('{') else {
            break;
        };
        let Some(body_len) = rest[body_start..].find("};") else {
            break;
        };
        let body = &rest[body_start..body_start + body_len];
        rest = &rest[body_start + body_len..];
        let Some(code) = codes.get(name).and_then(|c| c.checked_sub(8)) else {
            continue;
        };
        let words = body
            .split(|c: char| matches!(c, '[' | ']' | ',' | '{' | '}' | '=') || c.is_whitespace())
            .filter(|w| !w.is_empty());
        let mut v = false;
        let mut insert = false;
        // By name, or by number as a keymap of a virtual keyboard has it
        // (`0x76`, `U0076`).
        for word in words {
            let word = word.to_ascii_lowercase();
            v |= matches!(word.as_str(), "v" | "0x76" | "0x56" | "u0076" | "u0056");
            insert |= matches!(word.as_str(), "insert" | "0xff63");
        }
        if v && !out.v.contains(&code) {
            out.v.push(code);
        }
        if insert && !out.insert.contains(&code) {
            out.insert.push(code);
        }
    }
    if out.v.is_empty() && out.insert.is_empty() {
        return PasteKeys::default();
    }
    out
}

/// A keyboard's keymap as the compositor sends it: `size` bytes of `fd`,
/// read at their offsets — never moving the file's position, which may be
/// shared with every other client of the compositor. `None` past 4 MiB or
/// unread.
pub fn read_keymap(fd: &std::os::fd::OwnedFd, size: u32) -> Option<String> {
    use std::os::fd::AsRawFd;
    if size > 4 << 20 {
        return None;
    }
    let mut text = vec![0u8; size as usize];
    let mut at = 0usize;
    while at < text.len() {
        // SAFETY: into the buffer's unread part, of its length.
        let n = unsafe {
            libc::pread(
                fd.as_raw_fd(),
                text[at..].as_mut_ptr().cast(),
                text.len() - at,
                at as libc::off_t,
            )
        };
        if n <= 0 {
            break;
        }
        at += n as usize;
    }
    if at == 0 {
        return None;
    }
    text.truncate(at);
    Some(
        String::from_utf8_lossy(&text)
            .trim_end_matches('\0')
            .to_owned(),
    )
}

/// Whether a key pressed with modifiers `depressed` is a paste, by the
/// keyboard's own keymap.
pub fn is_paste(keys: &PasteKeys, key: u32, depressed: u32) -> bool {
    (keys.v.contains(&key) && depressed & CONTROL != 0)
        || (keys.insert.contains(&key) && depressed & SHIFT != 0)
}

/// The person pastes now: a foreign selection may be read for a moment. A
/// key pastes either selection (Shift+Insert is the primary one in some
/// programs).
pub fn pasting(which: Which) {
    STATE.with(|s| {
        let until = Some(Instant::now() + PASTE_WINDOW);
        s.primary.set(until);
        if which == Which::Clipboard {
            s.clipboard.set(until);
        }
    });
}

/// The person chose an entry of the clipboard history to paste into this
/// launch (`cellward clip-window`): the history made it the selection, and
/// the proxy presses Shift+Insert for the program — now, where a keyboard of it
/// has the focus, or when one gets it, within [`PASTE_WINDOW`].
pub fn want_paste() {
    STATE.with(|s| s.inject.set(Some(Instant::now() + PASTE_WINDOW)));
    pasting(Which::Clipboard);
}

/// Whether a paste is to be pressed now: true once, within its time, and
/// only on the history's selection — the program told of it, so that the
/// paste reads what the person chose, not what was there before.
pub fn take_paste() -> bool {
    STATE.with(|s| {
        if !s.history_selected.get() {
            return false;
        }
        s.inject.take().is_some_and(|until| Instant::now() < until)
    })
}

/// An offer came with [`HISTORY_MARK`].
pub fn history_offer(offer: u64) {
    STATE.with(|s| {
        let mut o = s.history_offers.borrow_mut();
        o.push_back(offer);
        while o.len() > 16 {
            o.pop_front();
        }
    });
}

/// The program is told of a new selection (`None`: none).
pub fn selection(offer: Option<u64>) {
    STATE.with(|s| {
        let history = offer.is_some_and(|o| s.history_offers.borrow().contains(&o));
        s.history_selected.set(history);
    });
}

/// The time of an event pressed by the proxy, in a key event's
/// milliseconds: the monotonic clock's, as compositors give theirs.
pub fn now_ms() -> u32 {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: one timespec, written by the kernel.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) };
    (t.tv_sec as u64 * 1000 + t.tv_nsec as u64 / 1_000_000) as u32
}

/// The modifier's mask and the key of a paste pressed by the proxy:
/// Shift+Insert. Ctrl+V is no paste in a terminal (it quotes the next key
/// there); Shift+Insert is one nearly everywhere — GTK, Qt, Chromium,
/// Firefox, LibreOffice — and in terminals of the primary selection, which
/// the history sets too.
pub fn paste_chord(keys: &PasteKeys) -> (u32, u32) {
    (SHIFT, keys.insert.first().copied().unwrap_or(KEY_INSERT))
}

/// An offer the person drags onto the program: read as dropped.
pub fn dragged(offer: u64) {
    STATE.with(|s| {
        let mut d = s.dragged.borrow_mut();
        d.push_back(offer);
        while d.len() > 16 {
            d.pop_front();
        }
    });
}

/// Whether the program may read `mime_type` of an offer (`own`: of its
/// instance; `offer`: its id, for a drag).
pub fn may_read(own: bool, which: Which, mime_type: &str, offer: u64) -> bool {
    if is_mark(mime_type) {
        return false;
    }
    if own {
        return true;
    }
    STATE.with(|s| {
        if s.dragged.borrow().contains(&offer) {
            return true;
        }
        let until = match which {
            Which::Clipboard => s.clipboard.get(),
            Which::Primary => s.primary.get(),
        };
        let now = Instant::now();
        let pasting = until.is_some_and(|u| now < u);
        if !pasting && s.said.get().is_none_or(|t| now >= t) {
            s.said.set(Some(now + Duration::from_secs(10)));
            eprintln!(
                "wl-sandbox: the {} of another container not read — read when the person pastes",
                match which {
                    Which::Clipboard => "clipboard",
                    Which::Primary => "selection",
                }
            );
        }
        pasting
    })
}

/// What a launch tells the clipboard history (`cellward-clipd`) of whose its
/// copies are: the history they go to, by its container's record (a
/// container's name, `main` for the real home), or [`NO_HISTORY`] — a
/// throwaway container's copies are not kept past it.
pub const NO_HISTORY: &str = "-";

/// Whether `name` may name a history: a record's name, or [`NO_HISTORY`].
pub fn valid_history(name: &str) -> bool {
    name == NO_HISTORY
        || (!name.is_empty()
            && name.len() <= 128
            && !name.starts_with(['.', '-'])
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')))
}

/// A history an explicit host-side entry selection may name. The reserved
/// favourites scope is never a launch's recording destination.
pub fn valid_entry_history(name: &str) -> bool {
    let real = name.strip_prefix("@favorites:").unwrap_or(name);
    valid_history(real) && real != NO_HISTORY
}

/// The secret of the instance whose restricted sockets are `key`
/// (`wl_sandbox`'s zone), with the history its copies go to: read, or made
/// at its first launch — sixteen random bytes as hex, then the history on a
/// line of its own, in a file only its user reads, never through a link.
/// The history daemon reads the same file to know whose a marked copy is.
/// `None` when it can be neither: every copy foreign then, which is the
/// closed way.
pub fn token_for(runtime: &Path, key: &str, history: &str) -> Option<String> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    if key.is_empty() || key.contains('/') || key.starts_with('.') || !valid_history(history) {
        return None;
    }
    let dir: PathBuf = runtime.join(DIR);
    let _ = fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir);
    let path = dir.join(key);
    let valid = |t: &str| t.len() == 32 && t.bytes().all(|b| b.is_ascii_hexdigit());
    let mut text = String::new();
    let mut token = None;
    if let Ok(mut f) = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        if f.read_to_string(&mut text).is_ok() {
            let mut lines = text.lines();
            let had = lines.next().unwrap_or_default().trim();
            if valid(had) {
                if lines.next().map(str::trim) == Some(history) {
                    return Some(had.to_owned());
                }
                token = Some(had.to_owned());
            }
        }
    }
    let token = match token {
        Some(token) => token,
        None => {
            let mut bytes = [0u8; 16];
            fs::File::open("/dev/urandom")
                .and_then(|mut r| r.read_exact(&mut bytes))
                .ok()?;
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }
    };
    // Written new beside it and renamed over: a reader never sees half.
    let tmp = dir.join(format!(".{key}.tmp"));
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .ok()?;
    f.write_all(format!("{token}\n{history}\n").as_bytes())
        .ok()?;
    fs::rename(&tmp, &path).ok()?;
    Some(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn favourites_can_be_selected_but_not_used_as_a_recording_history() {
        assert!(valid_entry_history("@favorites:app-helium"));
        assert!(!valid_history("@favorites:app-helium"));
        assert!(!valid_entry_history("@favorites:../host"));
        assert!(!valid_entry_history("@favorites:-"));
    }

    /// A foreign selection is read only within a paste or a drag; the own
    /// one always; a mark never.
    #[test]
    fn a_foreign_selection_is_read_only_when_pasted() {
        set_mark(Some("00ff"));
        let mark = mark().unwrap();
        assert!(is_own(&mark));
        assert!(is_mark(&format!("{MARK_PREFIX}abcd")) && !is_own(&format!("{MARK_PREFIX}abcd")));
        assert!(may_read(true, Which::Clipboard, "text/plain", 1));
        assert!(!may_read(true, Which::Clipboard, &mark, 1));
        assert!(!may_read(false, Which::Clipboard, "text/plain", 1));
        dragged(2);
        assert!(may_read(false, Which::Clipboard, "text/plain", 2));
        pasting(Which::Primary);
        assert!(may_read(false, Which::Primary, "text/plain", 3));
        assert!(!may_read(false, Which::Clipboard, "text/plain", 3));
        pasting(Which::Clipboard);
        assert!(may_read(false, Which::Clipboard, "text/plain", 3));
    }

    /// A paste of the history's is pressed once, and only once the program
    /// was told of the history's selection.
    #[test]
    fn a_paste_of_the_history_waits_for_its_selection() {
        selection(None);
        want_paste();
        assert!(!take_paste(), "the selection before is not what was chosen");
        selection(Some(41));
        assert!(
            !take_paste(),
            "an offer without the mark is not the history's"
        );
        history_offer(42);
        selection(Some(42));
        assert!(take_paste());
        assert!(!take_paste(), "pressed once");
        assert!(may_read(false, Which::Clipboard, "text/plain", 42));
        assert!(!may_read(false, Which::Clipboard, HISTORY_MARK, 42));
        assert!(is_mark(HISTORY_MARK) && !is_own(HISTORY_MARK));
    }

    #[test]
    fn a_paste_is_ctrl_v_or_shift_insert() {
        let keys = PasteKeys::default();
        assert!(is_paste(&keys, KEY_V, CONTROL));
        assert!(is_paste(&keys, KEY_V, CONTROL | SHIFT));
        assert!(is_paste(&keys, KEY_INSERT, SHIFT));
        assert!(!is_paste(&keys, KEY_V, 0));
        assert!(!is_paste(&keys, KEY_V, SHIFT));
        assert!(!is_paste(&keys, KEY_INSERT, CONTROL));
    }

    /// The paste keys are the keymap's: V wherever a layout has it — a
    /// second group's included —, an alias followed, another keymap's codes
    /// (a virtual keyboard's) as they are.
    #[test]
    fn the_paste_keys_are_read_from_the_keymap() {
        let keymap = r#"xkb_keymap {
xkb_keycodes "evdev" { minimum = 8; maximum = 255; <AB04> = 55; <INS> = 118; <K9> = 17; alias <ALT1> = <AB04>; };
xkb_types "complete" { virtual_modifiers NumLock; };
xkb_symbols "pc+us+ru" {
    key <AB04> { type= "ALPHABETIC", symbols[Group1]= [ v, V ], symbols[Group2]= [ Cyrillic_em, Cyrillic_EM ] };
    key <INS> { [ Insert ] };
    key <K9> { [ x ] };
};
};"#;
        let keys = paste_keys(keymap);
        assert_eq!(keys.v, [47]);
        assert_eq!(keys.insert, [110]);
        // wtype's: a code of its own for each symbol, and the symbol by its
        // number.
        let virtual_keymap = "xkb_keymap { xkb_keycodes \"(unnamed)\" { minimum = 8; maximum = 255; <K1> = 9; <K2> = 10; indicator 1 = \"Caps Lock\"; }; xkb_symbols \"(unnamed)\" { key <K1> {      [ 0x76 ] }; key <K2> { [ v ] }; }; };";
        assert_eq!(paste_keys(virtual_keymap).v, [1, 2]);
        assert_eq!(paste_keys("garbage"), PasteKeys::default());
    }

    /// An instance's secret is made once and read back, never through a
    /// link; a key that is no plain name has none.
    #[test]
    fn an_instances_secret_is_its_own_and_kept() {
        let base = std::env::temp_dir().join(format!("vz-clip-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let one = token_for(&base, "i-1", "work").unwrap();
        assert_eq!(token_for(&base, "i-1", "work").unwrap(), one);
        assert_ne!(token_for(&base, "i-2", "work").unwrap(), one);
        assert_eq!(token_for(&base, "../x", "work"), None);
        assert_eq!(token_for(&base, "i-4", "../x"), None);
        // Its history said beside it, for the daemon; the secret kept.
        assert_eq!(
            fs::read_to_string(base.join(DIR).join("i-1")).unwrap(),
            format!("{one}\nwork\n")
        );
        assert_eq!(token_for(&base, "i-1", NO_HISTORY).unwrap(), one);
        assert!(fs::read_to_string(base.join(DIR).join("i-1"))
            .unwrap()
            .ends_with("\n-\n"));
        let link = base.join(DIR).join("i-3");
        std::os::unix::fs::symlink(base.join("elsewhere"), &link).unwrap();
        let three = token_for(&base, "i-3", "main").unwrap();
        assert!(!base.join("elsewhere").exists(), "written through the link");
        assert_eq!(three.len(), 32);
        let _ = fs::remove_dir_all(&base);
    }
}
