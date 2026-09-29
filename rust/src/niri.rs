//! niri's own round corners, for the frame to follow (the owner, 2026-09-29:
//! "в идеале расчёт закругления автоматическим по закруглению niri").
//!
//! niri says nothing of a window's radius over its IPC (26.04): it is its
//! config's, a `window-rule`'s `geometry-corner-radius` — one value, or four
//! (top left, top right, bottom right, bottom left), logical pixels. Rules
//! apply in the file's order, the last that sets it wins; a rule with a
//! `match` applies only to windows it matches. What is read here is the
//! radius of the rules that match every window — no `match` line —, the
//! larger of a rule's four where it gives four. A rule for some programs
//! only is not followed (said in `docs/WINDOW-FRAME.md`); nor is an
//! `include`d file.
//!
//! Where the config is, as niri looks for it: `NIRI_CONFIG`, then
//! `$XDG_CONFIG_HOME/niri/config.kdl` (`~/.config/niri/config.kdl`), then
//! `/etc/niri/config.kdl`.

use std::path::{Path, PathBuf};

/// Where niri reads its config from, as it looks for it; the first that is
/// there.
pub fn config_path() -> Option<PathBuf> {
    let home_config = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|h| !h.is_empty())
                .map(|h| PathBuf::from(h).join(".config"))
        });
    let candidates = [
        std::env::var_os("NIRI_CONFIG")
            .filter(|p| !p.is_empty())
            .map(PathBuf::from),
        home_config.map(|c| c.join("niri").join("config.kdl")),
        Some(PathBuf::from("/etc/niri/config.kdl")),
    ];
    candidates.into_iter().flatten().find(|p| p.is_file())
}

/// niri's radius for every window, logical pixels, from its config at
/// `path`; `None` when no rule for every window sets one (niri's is 0 then)
/// or the file cannot be read.
pub fn corner_radius_at(path: &Path) -> Option<f64> {
    corner_radius(&std::fs::read_to_string(path).ok()?)
}

/// [`corner_radius_at`] of niri's config where niri looks for it.
pub fn corner_radius_now() -> Option<f64> {
    corner_radius_at(&config_path()?)
}

/// The radius the rules without a `match` set, the last one's: the text of
/// a niri config (KDL). Comments (`//` lines, `/* */`, `/-` slashdashed
/// nodes are taken as the lines they start) and strings are minded where
/// they could hide a brace.
pub fn corner_radius(text: &str) -> Option<f64> {
    let text = strip_comments(text);
    let mut found = None;
    let mut rest = text.as_str();
    while let Some(at) = find_node(rest, "window-rule") {
        let after = &rest[at + "window-rule".len()..];
        let Some(open) = after.find('{') else {
            break;
        };
        // Arguments or properties before the brace belong to the node.
        if after[..open].contains(['\n', ';']) {
            rest = &after[open..];
            continue;
        }
        let body_start = open + 1;
        let Some(len) = block_len(&after[body_start..]) else {
            break;
        };
        let body = &after[body_start..body_start + len];
        let for_every_window = !body_nodes(body).any(|(name, _)| name == "match");
        if for_every_window {
            if let Some(value) = body_nodes(body)
                .filter(|(name, _)| *name == "geometry-corner-radius")
                .filter_map(|(_, args)| radius_of(args))
                .last()
            {
                found = Some(value);
            }
        }
        rest = &after[body_start + len..];
    }
    found
}

/// A radius node's arguments: one number, or four — the largest of them.
fn radius_of(args: &str) -> Option<f64> {
    let values: Vec<f64> = args
        .split_whitespace()
        .map(|w| w.trim_end_matches(';').parse::<f64>())
        .collect::<Result<_, _>>()
        .ok()?;
    match values.as_slice() {
        [one] => Some(*one),
        [a, b, c, d] => Some(a.max(*b).max(*c).max(*d)),
        _ => None,
    }
    .filter(|r| r.is_finite() && *r >= 0.0)
}

/// Where the node `name` starts in `text`: at the start of a line (after
/// blanks), followed by a blank or a brace.
fn find_node(text: &str, name: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(i) = text[from..].find(name) {
        let at = from + i;
        let line_start = text[..at].rfind('\n').map_or(0, |n| n + 1);
        let before_blank = text[line_start..at].trim().is_empty();
        let next = text[at + name.len()..].chars().next();
        if before_blank && next.is_some_and(|c| c.is_whitespace() || c == '{') {
            return Some(at);
        }
        from = at + name.len();
    }
    None
}

/// The length of a block's body, `text` starting right after its `{`, up
/// to its `}` — braces in strings aside.
fn block_len(text: &str) -> Option<usize> {
    let mut depth = 1usize;
    let mut in_string = false;
    let mut escaped = false;
    for (i, c) in text.char_indices() {
        if in_string {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// The nodes of a block's body at its own level: each its name and the
/// rest of its line (its arguments).
fn body_nodes(body: &str) -> impl Iterator<Item = (&str, &str)> {
    let mut depth = 0usize;
    body.lines().filter_map(move |line| {
        let at = depth;
        let (opens, closes) = braces(line);
        depth = (depth + opens).saturating_sub(closes);
        if at > 0 {
            return None;
        }
        let line = line.trim();
        let name = line.split_whitespace().next()?;
        Some((name, line[name.len()..].trim()))
    })
}

/// The braces of a line that open and close blocks: not those in strings.
fn braces(line: &str) -> (usize, usize) {
    let (mut opens, mut closes) = (0, 0);
    let (mut in_string, mut escaped) = (false, false);
    for c in line.chars() {
        if in_string {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '{' => opens += 1,
            '}' => closes += 1,
            _ => {}
        }
    }
    (opens, closes)
}

/// `text` without its comments: `//` to the end of a line, `/* */` blocks,
/// and a slashdashed node's line (`/-`) — strings minded.
fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match (c, chars.peek()) {
            ('"', _) => {
                in_string = true;
                out.push(c);
            }
            ('/', Some('/')) | ('/', Some('-')) => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            ('/', Some('*')) => {
                chars.next();
                let mut last = ' ';
                for c in chars.by_ref() {
                    if last == '*' && c == '/' {
                        break;
                    }
                    if c == '\n' {
                        out.push('\n');
                    }
                    last = c;
                }
            }
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A usual config: one rule for every window; others for
    /// some programs, not followed; the last rule for every window wins;
    /// four values give the largest; comments hide nothing.
    #[test]
    fn the_radius_of_the_rules_for_every_window() {
        let config = r#"
layout {
    gaps 8
    border { width 4; }
}
// window-rule { geometry-corner-radius 99; }
window-rule {
    geometry-corner-radius 12
    clip-to-geometry true
}
/* window-rule { geometry-corner-radius 50 } */
window-rule {
    match app-id="^firefox$" title="a { brace"
    geometry-corner-radius 3
}
window-rule {
    geometry-corner-radius 20
    clip-to-geometry true
}
/-window-rule {
    geometry-corner-radius 77
}
"#;
        assert_eq!(corner_radius(config), Some(20.0));
        assert_eq!(
            corner_radius("window-rule {\n geometry-corner-radius 8 4 8 6\n}\n"),
            Some(8.0)
        );
        assert_eq!(corner_radius("layout { gaps 8; }\n"), None);
        assert_eq!(
            corner_radius("window-rule {\n match is-floating=true\n geometry-corner-radius 9\n}\n"),
            None,
            "a rule with a match is some windows'"
        );
        assert_eq!(
            corner_radius("window-rule {\n geometry-corner-radius x\n}\n"),
            None
        );
        // A brace in a string of a rule's line is no block.
        assert_eq!(
            corner_radius("window-rule {\n exclude title=\"{\"\n geometry-corner-radius 6\n}\n"),
            Some(6.0)
        );
        assert_eq!(
            corner_radius("window-rule {\n geometry-corner-radius -3\n}\n"),
            None
        );
        // A nested block in a rule does not end it early.
        assert_eq!(
            corner_radius(
                "window-rule {\n    border {\n        width 2\n    }\n    geometry-corner-radius 14\n}\n"
            ),
            Some(14.0)
        );
    }

    #[test]
    fn the_config_is_read_where_it_is() {
        let dir = std::env::temp_dir().join(format!("vz-niri-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("config.kdl");
        std::fs::write(&file, "window-rule {\n    geometry-corner-radius 16\n}\n").unwrap();
        assert_eq!(corner_radius_at(&file), Some(16.0));
        assert_eq!(corner_radius_at(&dir.join("none.kdl")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
