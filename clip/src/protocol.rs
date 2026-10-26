//! The daemon's socket of questions (`cellward-clip daemon`): one request
//! line, its answer, the connection closed. What the history window and
//! `cellward clip-window` ask.
//!
//! ```text
//! histories                                  a name a line
//! list⇥<history>⇥<n>                          as search with no condition
//! search⇥<history>⇥<key=value>…              an entry a line (below)
//! get⇥<history>⇥<id>⇥<type>                   ok⇥<length>, then the bytes
//! move⇥<from>⇥<id>⇥<to>                       ok⇥<new id>
//! favorite⇥<history>⇥<id>                    ok⇥<favorite id>
//! secret⇥<history>⇥<id>⇥<label>             ok⇥<secret id>; source removed
//! secret-edit⇥<history>⇥<id>⇥<label>⇥<text>  ok⇥<replacement id>; empty text keeps the password
//! secret-move⇥<from>⇥<id>⇥<to>             ok⇥<target id>; secret-only transfer, source removed
//! search/get/delete/select with `@favorites:<history>` address that
//! history's encrypted favourites, kept under `.favorites/` and never
//! listed as a container history.
//! `@secrets:<history>` addresses encrypted passwords under `.secrets/`;
//! text/regex searching and ordinary moves of passwords are refused.
//! delete⇥<history>⇥<id>                       ok
//! select⇥<history>⇥<id>                       ok: it is the selection now
//! copy⇥<history>⇥<id>                         same, without recording a paste
//! ```
//!
//! Values are percent-encoded: `%`, tab, line feed and `=` as `%25`, `%09`,
//! `%0A`, `%3D`. A search's keys, each optional: `q` words, `re` a pattern,
//! `type` (repeated), `copied` and `pasted` `<from ms>-<to ms>`, `around`
//! `<ms>:<window ms>`, `before` an id, `limit` (at most 200). An entry's
//! line: `<id>⇥<copied ms>⇥<last copied ms>⇥<copies>⇥<pastes>⇥<last pasted
//! ms or 0>⇥<type:size,…>⇥<preview>`. Anything that fails: `error⇥<why>`.

use crate::{Query, Summary};

/// At most this many entries an answer.
pub const MAX_LIMIT: usize = 200;
/// Includes a percent-encoded password (at most 32 KiB) and its label.
pub const MAX_REQUEST: usize = 128 * 1024;

/// `%`, tab, line feed and `=` written as `%xx`.
pub fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '%' => out.push_str("%25"),
            '\t' => out.push_str("%09"),
            '\n' => out.push_str("%0A"),
            '\r' => out.push_str("%0D"),
            '=' => out.push_str("%3D"),
            c => out.push(c),
        }
    }
    out
}

/// Every `%xx` read back; `None` for one that is not two hex digits, or
/// bytes that are not UTF-8.
pub fn decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// A search's conditions, its page's start and its size.
#[derive(Debug, Default)]
pub struct Search {
    pub query: Query,
    pub before: Option<u64>,
    pub limit: usize,
}

fn range(value: &str) -> Option<std::ops::Range<i64>> {
    let (from, to) = value.split_once('-')?;
    Some(from.parse().ok()?..to.parse().ok()?)
}

/// A search from its `key=value` words; `Err` names the first that does
/// not read.
pub fn search(words: &[&str]) -> Result<Search, String> {
    let mut s = Search {
        limit: 50,
        ..Search::default()
    };
    for word in words {
        let (key, value) = word
            .split_once('=')
            .ok_or_else(|| format!("«{word}» — не ключ=значение"))?;
        let value = decode(value).ok_or_else(|| format!("{key}: не читается"))?;
        let bad = || format!("{key}: «{value}» не читается");
        match key {
            "q" => s
                .query
                .text_terms
                .extend(value.split_whitespace().map(str::to_owned)),
            "re" if !value.is_empty() => s.query.pattern = Some(value),
            "re" => {}
            "type" => s.query.types.get_or_insert_with(Vec::new).push(value),
            "copied" => s.query.copied = Some(range(&value).ok_or_else(bad)?),
            "pasted" => s.query.pasted = Some(range(&value).ok_or_else(bad)?),
            "around" => {
                let (at, window) = value.split_once(':').ok_or_else(bad)?;
                s.query.around = Some((
                    at.parse().map_err(|_| bad())?,
                    window.parse().map_err(|_| bad())?,
                ));
            }
            "before" => s.before = Some(value.parse().map_err(|_| bad())?),
            "limit" => s.limit = value.parse::<usize>().map_err(|_| bad())?.min(MAX_LIMIT),
            other => return Err(format!("неизвестный ключ {other}")),
        }
    }
    Ok(s)
}

/// An entry's line of an answer.
pub fn line(s: &Summary) -> String {
    let types: Vec<String> = s
        .types
        .iter()
        .map(|(t, size)| format!("{}:{size}", encode(t).replace(',', "%2C")))
        .collect();
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
        s.id,
        s.copied_at,
        s.copies.last().copied().unwrap_or(s.copied_at),
        s.copies.len().max(1),
        s.pastes.len(),
        s.pastes.last().copied().unwrap_or(0),
        types.join(","),
        encode(&s.preview)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_round_trip() {
        for text in ["a=b\tc\nd%e", "", "простой", "100%"] {
            assert_eq!(decode(&encode(text)).as_deref(), Some(text));
        }
        assert_eq!(decode("%zz"), None);
        assert_eq!(decode("%4"), None);
    }

    #[test]
    fn a_search_reads_its_keys() {
        let s = search(&[
            "q=hello%20world",
            "re=%5Cd%7B4%7D",
            "type=image%2F*",
            "type=text/plain",
            "copied=10-20",
            "around=100:5",
            "before=7",
            "limit=1000",
        ])
        .unwrap();
        assert_eq!(s.query.text_terms, ["hello", "world"]);
        assert_eq!(s.query.pattern.as_deref(), Some("\\d{4}"));
        assert_eq!(s.query.types.as_ref().unwrap().len(), 2);
        assert_eq!(s.query.copied, Some(10..20));
        assert_eq!(s.query.around, Some((100, 5)));
        assert_eq!((s.before, s.limit), (Some(7), MAX_LIMIT));
        assert!(search(&["copied=x"]).is_err());
        assert!(search(&["nope=1"]).is_err());
        assert_eq!(search(&[]).unwrap().limit, 50);
    }

    #[test]
    fn an_entry_is_one_line() {
        let s = Summary {
            id: 3,
            copied_at: 10,
            copies: vec![10, 30],
            pastes: vec![40],
            types: vec![("text/plain".to_owned(), 5)],
            preview: "a\tb".to_owned(),
        };
        assert_eq!(line(&s), "3\t10\t30\t2\t1\t40\ttext/plain:5\ta%09b\n");
    }
}
