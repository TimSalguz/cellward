//! What the recorder (`cellward-clip daemon`) decides about a selection,
//! apart from Wayland: whose it is, whether it is kept, which of its types
//! are read and what its preview says. The daemon only fetches and stores.
//!
//! **Whose.** A launch of cellward marks what its program copies with its
//! instance's secret (`application/x-cellward-clip-<secret>`, the core's
//! `clip` module), and keeps the secret in `$XDG_RUNTIME_DIR/vpn-zones/clip/
//! <instance key>` with the history its copies go to on the line after it.
//! A selection with a mark found there is that history's; with a mark found
//! nowhere — a launch gone, a mark made up — it is kept nowhere; with none,
//! it is the host's ([`HOST`]): a program not started through cellward.
//!
//! **Not kept.** A copy whose launch said no history (a throwaway
//! container's, [`NO_HISTORY`]); a copy a password manager says is secret
//! (`x-kde-passwordManagerHint` = `secret`, KeePassXC and others); a
//! selection that offers nothing readable.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// The type a launch's copy is marked with, before its instance's secret.
pub const MARK_PREFIX: &str = "application/x-cellward-clip-";
/// Below the runtime directory: the instances' secrets and histories.
pub const MARKS_DIR: &str = "vpn-zones/clip";
/// The history of a copy no launch of cellward made.
pub const HOST: &str = "host";
/// A launch's word for "keep none".
pub const NO_HISTORY: &str = "-";
/// What a password manager offers beside a secret it copies.
pub const SECRET_HINT: &str = "x-kde-passwordManagerHint";

/// The texts, best first: what a person would paste.
const TEXTS: [&str; 5] = [
    "text/plain;charset=utf-8",
    "UTF8_STRING",
    "text/plain",
    "TEXT",
    "STRING",
];

/// Where a selection goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Whose {
    /// Into this history.
    History(String),
    /// Nowhere: a throwaway container's, an unknown mark's, a secret.
    Nobody,
}

/// The instances' secrets as their files say: secret → history.
#[derive(Debug, Default)]
pub struct Marks {
    dir: PathBuf,
    by_secret: HashMap<String, String>,
}

impl Marks {
    pub fn new(runtime: &Path) -> Self {
        Self {
            dir: runtime.join(MARKS_DIR),
            by_secret: HashMap::new(),
        }
    }

    /// Read the files again: a launch since the last look made one.
    pub fn reload(&mut self) {
        self.by_secret.clear();
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().starts_with('.') {
                continue;
            }
            // Never through a link: a file of the user's own directory.
            if !entry.file_type().is_ok_and(|t| t.is_file()) {
                continue;
            }
            let Ok(text) = fs::read_to_string(entry.path()) else {
                continue;
            };
            let mut lines = text.lines();
            let (Some(secret), Some(history)) = (lines.next(), lines.next()) else {
                continue;
            };
            let (secret, history) = (secret.trim(), history.trim());
            if secret.len() == 32
                && secret.bytes().all(|b| b.is_ascii_hexdigit())
                && valid_history(history)
            {
                self.by_secret.insert(secret.to_owned(), history.to_owned());
            }
        }
    }

    /// The history of a secret, the files read again once when it is not
    /// known.
    pub fn history_of(&mut self, secret: &str) -> Option<String> {
        if !self.by_secret.contains_key(secret) {
            self.reload();
        }
        self.by_secret.get(secret).cloned()
    }

    /// Whose a selection offering `types` is.
    pub fn whose(&mut self, types: &[String]) -> Whose {
        let marks: Vec<&str> = types
            .iter()
            .filter_map(|t| t.strip_prefix(MARK_PREFIX))
            .collect();
        match marks.as_slice() {
            [] => Whose::History(HOST.to_owned()),
            [secret] => match self.history_of(secret) {
                Some(history) if history != NO_HISTORY => Whose::History(history),
                _ => Whose::Nobody,
            },
            // Two marks: not one launch's copy — kept nowhere.
            _ => Whose::Nobody,
        }
    }
}

/// Whether `name` may name a history.
pub fn valid_history(name: &str) -> bool {
    name == NO_HISTORY
        || (!name.is_empty()
            && name.len() <= 128
            && !name.starts_with(['.', '-'])
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')))
}

/// Whether the selection may carry a secret: its hint offered at all. Its
/// value (`secret`) is not even read — the hint alone keeps it out.
pub fn is_secret(types: &[String]) -> bool {
    types.iter().any(|t| t == SECRET_HINT)
}

/// The types of a selection read to keep it: its best text, its first
/// image, its files' list; never a mark, never the hint. Empty: nothing
/// readable to keep.
pub fn to_read(types: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(text) = TEXTS.iter().find(|t| types.iter().any(|o| o == *t)) {
        out.push((*text).to_owned());
    }
    if let Some(image) = types
        .iter()
        .find(|t| t.as_str() == "image/png")
        .or_else(|| types.iter().find(|t| t.starts_with("image/")))
    {
        out.push(image.clone());
    }
    if types.iter().any(|t| t == "text/uri-list") {
        out.push("text/uri-list".to_owned());
    }
    out
}

/// A copy's preview: its text's first line, cut to 200 characters; an
/// image by its type and size.
pub fn preview(contents: &[(String, Vec<u8>)]) -> Option<String> {
    if let Some((_, text)) = contents.iter().find(|(t, _)| TEXTS.contains(&t.as_str())) {
        let text = String::from_utf8_lossy(text);
        let line = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
        let mut cut: String = line.trim().chars().take(200).collect();
        if line.trim().chars().count() > 200 {
            cut.push('…');
        }
        return Some(cut);
    }
    contents
        .iter()
        .find(|(t, _)| t.starts_with("image/"))
        .map(|(t, data)| {
            format!(
                "картинка {} · {} КБ",
                t.trim_start_matches("image/"),
                data.len().div_ceil(1024)
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn types(list: &[&str]) -> Vec<String> {
        list.iter().map(|t| (*t).to_owned()).collect()
    }

    #[test]
    fn a_selection_is_its_marks_history_or_the_hosts() {
        let base = std::env::temp_dir().join(format!("clip-marks-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let dir = base.join(MARKS_DIR);
        fs::create_dir_all(&dir).unwrap();
        let work = "0123456789abcdef0123456789abcdef";
        let gone = "ffffffffffffffffffffffffffffffff";
        let throwaway = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        fs::write(dir.join("i-1"), format!("{work}\nwork\n")).unwrap();
        fs::write(dir.join("i-2"), format!("{throwaway}\n-\n")).unwrap();
        fs::write(dir.join("i-3"), format!("{gone}\n../x\n")).unwrap();
        let mut marks = Marks::new(&base);
        let mark = |s: &str| format!("{MARK_PREFIX}{s}");
        assert_eq!(
            marks.whose(&types(&["text/plain", &mark(work)])),
            Whose::History("work".to_owned())
        );
        assert_eq!(
            marks.whose(&types(&["text/plain"])),
            Whose::History(HOST.to_owned())
        );
        assert_eq!(
            marks.whose(&types(&["text/plain", &mark(throwaway)])),
            Whose::Nobody
        );
        // A mark no file says, or a history no name: nobody's.
        assert_eq!(
            marks.whose(&types(&["text/plain", &mark(gone)])),
            Whose::Nobody
        );
        assert_eq!(
            marks.whose(&types(&[&mark(work), &mark(throwaway)])),
            Whose::Nobody
        );
        // A launch since: found on the second look.
        let late = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        fs::write(dir.join("i-4"), format!("{late}\nmain\n")).unwrap();
        assert_eq!(
            marks.whose(&types(&[&mark(late)])),
            Whose::History("main".to_owned())
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn what_is_read_and_what_is_said_of_it() {
        let offered = types(&[
            "TEXT",
            "text/plain;charset=utf-8",
            "image/jpeg",
            "image/png",
            "text/uri-list",
            "application/x-cellward-clip-00",
        ]);
        assert_eq!(
            to_read(&offered),
            ["text/plain;charset=utf-8", "image/png", "text/uri-list"]
        );
        assert!(to_read(&types(&["application/x-foo"])).is_empty());
        assert!(is_secret(&types(&["text/plain", SECRET_HINT])));
        assert!(!is_secret(&offered));
        let long = format!("\n  {}  \nsecond", "я".repeat(250));
        let said = preview(&[("text/plain".to_owned(), long.into_bytes())]).unwrap();
        assert_eq!(said.chars().count(), 201);
        assert!(said.ends_with('…'));
        assert_eq!(
            preview(&[("image/png".to_owned(), vec![0; 3000])]).unwrap(),
            "картинка png · 3 КБ"
        );
    }
}
