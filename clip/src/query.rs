//! What a query is made of: the text's trigrams, the literal runs a
//! pattern cannot match without, and sets of ids walked newest first and
//! intersected by leapfrogging.

use regex_syntax::hir::{Class, Hir, HirKind};

use super::codec::Table;
use super::segment::Postings;

/// Lowercase one character at a time ("simple" lowercase: no context, so
/// the lowercase of a part of a text is a part of the text's lowercase —
/// what the index of trigrams needs, and what `str::to_lowercase`, with its
/// final sigma, does not promise).
pub(super) fn lower(s: &str) -> String {
    s.chars().flat_map(char::to_lowercase).collect()
}

/// Each window of three characters of `s`, as a `&str`.
pub(super) fn trigrams(s: &str, mut f: impl FnMut(&str)) {
    let mut idx = s
        .char_indices()
        .map(|(i, _)| i)
        .chain(std::iter::once(s.len()));
    let (Some(mut a), Some(mut b), Some(mut c)) = (idx.next(), idx.next(), idx.next()) else {
        return;
    };
    for d in idx {
        f(&s[a..d]);
        (a, b, c) = (b, c, d);
    }
}

/// The runs of text every match of `pattern` contains, lowercased. Only
/// what is certain: a literal, a case-insensitive letter (a class of one
/// letter's cases), a concatenation of those; a group or a repetition of
/// at least one is looked into; an alternation, a class or an optional
/// part is not — it requires nothing. Empty for a pattern that does not
/// parse (the regex crate will say why).
pub(super) fn required_literals(pattern: &str) -> Vec<String> {
    let Ok(hir) = regex_syntax::Parser::new().parse(pattern) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect(&hir, &mut out);
    out.retain(|s| !s.is_empty());
    out
}

fn collect(h: &Hir, out: &mut Vec<String>) {
    if let Some(s) = literal(h) {
        out.push(s);
        return;
    }
    match h.kind() {
        HirKind::Capture(c) => collect(&c.sub, out),
        HirKind::Repetition(r) if r.min >= 1 => collect(&r.sub, out),
        HirKind::Concat(parts) => {
            let mut run = String::new();
            for p in parts {
                match literal(p) {
                    Some(s) => run.push_str(&s),
                    None => {
                        out.push(std::mem::take(&mut run));
                        collect(p, out);
                    }
                }
            }
            out.push(run);
        }
        _ => {}
    }
}

/// The text `h` matches exactly (lowercased), if it matches one text only
/// up to case.
fn literal(h: &Hir) -> Option<String> {
    match h.kind() {
        HirKind::Literal(l) => std::str::from_utf8(&l.0).ok().map(lower),
        HirKind::Capture(c) => literal(&c.sub),
        HirKind::Class(Class::Unicode(c)) => {
            let mut chars = Vec::new();
            for r in c.ranges() {
                for ch in r.start()..=r.end() {
                    chars.push(ch);
                    if chars.len() > 4 {
                        return None;
                    }
                }
            }
            one_letter(&chars)
        }
        HirKind::Class(Class::Bytes(c)) => {
            let mut chars = Vec::new();
            for r in c.ranges() {
                for b in r.start()..=r.end() {
                    if !b.is_ascii() {
                        return None;
                    }
                    chars.push(b as char);
                    if chars.len() > 4 {
                        return None;
                    }
                }
            }
            one_letter(&chars)
        }
        HirKind::Concat(parts) => parts.iter().map(literal).collect(),
        _ => None,
    }
}

/// `[kK]` (and `[kKK]`, the Kelvin sign): one letter in its cases.
fn one_letter(chars: &[char]) -> Option<String> {
    let first = lower(&chars.first()?.to_string());
    chars
        .iter()
        .all(|c| lower(&c.to_string()) == first)
        .then_some(first)
}

/// A set of ids, walked down.
pub(super) trait IdSet {
    /// How many ids (an estimate is enough: it orders the leapfrog).
    fn len(&self) -> usize;
    /// The greatest id of the set below `below`.
    fn prev(&mut self, below: u64) -> Option<u64>;
}

impl IdSet for Postings<'_> {
    fn len(&self) -> usize {
        self.n
    }
    fn prev(&mut self, below: u64) -> Option<u64> {
        Postings::prev(self, below)
    }
}

/// Ascending ids in memory.
pub(super) struct Sorted<'a>(pub &'a [u64]);

impl IdSet for Sorted<'_> {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn prev(&mut self, below: u64) -> Option<u64> {
        let k = self.0.partition_point(|&x| x < below);
        k.checked_sub(1).map(|k| self.0[k])
    }
}

/// A segment's every entry, from its locations.
pub(super) struct Locs<'a>(pub Table<'a>);

impl IdSet for Locs<'_> {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn prev(&mut self, below: u64) -> Option<u64> {
        let t = self.0;
        let k = t.partition_point(|i| t.u64(i, 0) < below);
        k.checked_sub(1).map(|k| t.u64(k, 0))
    }
}

/// Ids in any of several sets.
pub(super) struct Union<'a>(pub Vec<Box<dyn IdSet + 'a>>);

impl IdSet for Union<'_> {
    fn len(&self) -> usize {
        self.0.iter().map(|s| s.len()).sum()
    }
    fn prev(&mut self, below: u64) -> Option<u64> {
        self.0.iter_mut().filter_map(|s| s.prev(below)).max()
    }
}

/// The greatest id below `below`, not below `floor`, that is in every one
/// of `sets` (at least one): each set in turn is asked for its greatest id
/// not above the candidate, which falls until they all agree — a list that
/// shares little with the others is skipped over a block at a time.
pub(super) fn leapfrog(sets: &mut [Box<dyn IdSet + '_>], below: u64, floor: u64) -> Option<u64> {
    let k = sets.len();
    let mut c = sets.first_mut()?.prev(below)?;
    let mut agree = 1;
    let mut i = 1 % k;
    while agree < k {
        if c < floor {
            return None;
        }
        let x = sets[i].prev(c.saturating_add(1))?;
        if x == c {
            agree += 1;
        } else {
            c = x;
            agree = 1;
        }
        i = (i + 1) % k;
    }
    (c >= floor).then_some(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trigrams_are_of_characters() {
        let mut v = Vec::new();
        trigrams("приве", |t| v.push(t.to_owned()));
        assert_eq!(v, ["при", "рив", "иве"]);
        let mut v = Vec::new();
        trigrams("ab", |t| v.push(t.to_owned()));
        assert!(v.is_empty());
        let mut v = Vec::new();
        trigrams("abc", |t| v.push(t.to_owned()));
        assert_eq!(v, ["abc"]);
    }

    #[test]
    fn literals_a_pattern_requires() {
        assert_eq!(required_literals(r"foo\d+bar"), ["foo", "bar"]);
        assert_eq!(required_literals(r"(?i)Hello world"), ["hello world"]);
        assert_eq!(required_literals(r"a(bc)d"), ["abcd"]);
        assert_eq!(required_literals(r"(xyz)+q"), ["xyz", "q"]);
        assert!(required_literals(r"foo|bar").is_empty());
        assert!(required_literals(r"(foo)?").is_empty());
        assert_eq!(required_literals(r"Ключ-\d{4}"), ["ключ-"]);
        assert!(required_literals(r"[0-9]+").is_empty());
    }

    #[test]
    fn leapfrog_intersects() {
        let a = [1u64, 3, 5, 7, 9, 11];
        let b = [2u64, 3, 4, 9, 10];
        let c = [3u64, 9, 12];
        let mut sets: Vec<Box<dyn IdSet>> = vec![
            Box::new(Sorted(&a)),
            Box::new(Sorted(&b)),
            Box::new(Sorted(&c)),
        ];
        assert_eq!(leapfrog(&mut sets, 100, 0), Some(9));
        assert_eq!(leapfrog(&mut sets, 9, 0), Some(3));
        assert_eq!(leapfrog(&mut sets, 3, 0), None);
        assert_eq!(leapfrog(&mut sets, 9, 4), None);
    }
}
