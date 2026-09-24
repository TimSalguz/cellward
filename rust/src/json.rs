//! A small JSON reader, for what compositors answer on their IPC (`niri msg
//! --json`, `swaymsg -t get_tree`): objects, arrays, strings, numbers, booleans
//! and null. The manifest reader in `crate::tools` takes only a flat object of
//! strings; a window list has numbers, nulls and nesting.
//!
//! Input comes from a compositor, not from a stranger, but it is still bounded:
//! nesting deeper than [`MAX_DEPTH`] is an error, not a stack overflow.

use std::collections::BTreeMap;

/// How deep arrays and objects may nest.
const MAX_DEPTH: usize = 128;

/// A JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl Value {
    /// A member of an object.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(map) => map.get(key),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// A whole number that fits an `i64`.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Number(n) if n.fract() == 0.0 && n.abs() < 9.0e15 => Some(*n as i64),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }
}

/// Read one JSON document; anything but whitespace after it is an error.
pub fn parse(text: &str) -> Result<Value, String> {
    let bytes = text.as_bytes();
    let mut at = 0;
    let value = value(bytes, &mut at, 0)?;
    skip_ws(bytes, &mut at);
    if at != bytes.len() {
        return Err(format!("trailing characters at {at}"));
    }
    Ok(value)
}

fn skip_ws(bytes: &[u8], at: &mut usize) {
    while bytes.get(*at).is_some_and(|b| b" \t\r\n".contains(b)) {
        *at += 1;
    }
}

fn expect(bytes: &[u8], at: &mut usize, word: &[u8]) -> Result<(), String> {
    if bytes[*at..].starts_with(word) {
        *at += word.len();
        Ok(())
    } else {
        Err(format!("unexpected token at {at}"))
    }
}

fn value(bytes: &[u8], at: &mut usize, depth: usize) -> Result<Value, String> {
    if depth > MAX_DEPTH {
        return Err("nested too deep".to_owned());
    }
    skip_ws(bytes, at);
    match bytes.get(*at) {
        None => Err("unexpected end".to_owned()),
        Some(b'n') => expect(bytes, at, b"null").map(|()| Value::Null),
        Some(b't') => expect(bytes, at, b"true").map(|()| Value::Bool(true)),
        Some(b'f') => expect(bytes, at, b"false").map(|()| Value::Bool(false)),
        Some(b'"') => string(bytes, at).map(Value::String),
        Some(b'[') => {
            *at += 1;
            let mut items = Vec::new();
            skip_ws(bytes, at);
            if bytes.get(*at) == Some(&b']') {
                *at += 1;
                return Ok(Value::Array(items));
            }
            loop {
                items.push(value(bytes, at, depth + 1)?);
                skip_ws(bytes, at);
                match bytes.get(*at) {
                    Some(b',') => *at += 1,
                    Some(b']') => {
                        *at += 1;
                        return Ok(Value::Array(items));
                    }
                    _ => return Err(format!("expected , or ] at {at}")),
                }
            }
        }
        Some(b'{') => {
            *at += 1;
            let mut map = BTreeMap::new();
            skip_ws(bytes, at);
            if bytes.get(*at) == Some(&b'}') {
                *at += 1;
                return Ok(Value::Object(map));
            }
            loop {
                skip_ws(bytes, at);
                if bytes.get(*at) != Some(&b'"') {
                    return Err(format!("expected a key at {at}"));
                }
                let key = string(bytes, at)?;
                skip_ws(bytes, at);
                if bytes.get(*at) != Some(&b':') {
                    return Err(format!("expected : at {at}"));
                }
                *at += 1;
                map.insert(key, value(bytes, at, depth + 1)?);
                skip_ws(bytes, at);
                match bytes.get(*at) {
                    Some(b',') => *at += 1,
                    Some(b'}') => {
                        *at += 1;
                        return Ok(Value::Object(map));
                    }
                    _ => return Err(format!("expected , or }} at {at}")),
                }
            }
        }
        Some(_) => number(bytes, at).map(Value::Number),
    }
}

fn number(bytes: &[u8], at: &mut usize) -> Result<f64, String> {
    let start = *at;
    while bytes
        .get(*at)
        .is_some_and(|b| b.is_ascii_digit() || b"+-.eE".contains(b))
    {
        *at += 1;
    }
    std::str::from_utf8(&bytes[start..*at])
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|n| n.is_finite())
        .ok_or_else(|| format!("not a number at {start}"))
}

fn string(bytes: &[u8], at: &mut usize) -> Result<String, String> {
    *at += 1; // the opening quote
    let mut out = String::new();
    loop {
        let start = *at;
        while bytes.get(*at).is_some_and(|b| *b != b'"' && *b != b'\\') {
            *at += 1;
        }
        out.push_str(std::str::from_utf8(&bytes[start..*at]).map_err(|_| "not UTF-8".to_owned())?);
        match bytes.get(*at) {
            None => return Err("unterminated string".to_owned()),
            Some(b'"') => {
                *at += 1;
                return Ok(out);
            }
            Some(_) => {
                *at += 1;
                let esc = *bytes.get(*at).ok_or("unterminated escape")?;
                *at += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{8}'),
                    b'f' => out.push('\u{c}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let hi = hex4(bytes, at)?;
                        let c = if (0xD800..0xDC00).contains(&hi) {
                            // A surrogate pair: the low half must follow.
                            expect(bytes, at, b"\\u")?;
                            let lo = hex4(bytes, at)?;
                            if !(0xDC00..0xE000).contains(&lo) {
                                return Err("broken surrogate pair".to_owned());
                            }
                            0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                        } else {
                            hi
                        };
                        out.push(char::from_u32(c).unwrap_or('\u{fffd}'));
                    }
                    _ => return Err(format!("bad escape at {at}")),
                }
            }
        }
    }
}

fn hex4(bytes: &[u8], at: &mut usize) -> Result<u32, String> {
    let digits = bytes
        .get(*at..*at + 4)
        .and_then(|d| std::str::from_utf8(d).ok())
        .ok_or("short \\u escape")?;
    *at += 4;
    u32::from_str_radix(digits, 16).map_err(|_| "bad \\u escape".to_owned())
}

/// A JSON string literal: quotes and every character JSON demands escaped.
pub fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `niri msg --json focused-window` prints, trimmed.
    #[test]
    fn a_compositors_answer_is_read() {
        let v = parse(
            r#"{"id":12,"title":"Мой \"сайт\" — Firefox","app_id":"firefox","pid":4242,
               "workspace_id":1,"is_focused":true,"is_floating":false,
               "layout":{"pos_in_scrolling_layout":[1,1],"tile_size":[960.0,1080.5]},
               "emoji":"\ud83d\ude00","nothing":null,"list":[]}"#,
        )
        .unwrap();
        assert_eq!(v.get("pid").and_then(Value::as_i64), Some(4242));
        assert_eq!(
            v.get("title").and_then(Value::as_str),
            Some("Мой \"сайт\" — Firefox")
        );
        assert_eq!(v.get("is_focused").and_then(Value::as_bool), Some(true));
        assert_eq!(v.get("emoji").and_then(Value::as_str), Some("😀"));
        assert_eq!(v.get("nothing"), Some(&Value::Null));
        assert_eq!(
            v.get("list").and_then(Value::as_array).map(<[_]>::len),
            Some(0)
        );
        assert_eq!(parse("null").unwrap(), Value::Null);
    }

    #[test]
    fn broken_input_is_an_error_not_a_panic() {
        for bad in [
            "",
            "{",
            "[1,",
            "{\"a\"}",
            "\"x",
            "tru",
            "{\"a\":1}x",
            "\"\\u12\"",
            "1e999",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        let deep = "[".repeat(1000);
        assert!(parse(&deep).is_err());
    }

    #[test]
    fn a_string_goes_out_quoted_and_comes_back_the_same() {
        let text = "зона \"nl\" \\ tab\t\u{1}";
        assert_eq!(parse(&quote(text)).unwrap().as_str(), Some(text));
    }
}
