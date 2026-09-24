//! The D-Bus wire format, as much of it as the bus filter needs
//! (`crate::bus_filter`): where a message ends, its header fields, the options
//! of a portal call, and the messages the filter answers with itself.
//!
//! Everything here reads input a sandboxed program wrote, so every read is
//! bounds-checked and every length is checked against what is left: a lie in a
//! length field is an error, never an allocation or a panic. Nesting is bounded
//! as the specification bounds it (32 levels of arrays, 32 of structs). What is
//! written is always little-endian; what is read may be either.

use std::fmt;

/// Message types.
pub const METHOD_CALL: u8 = 1;
pub const METHOD_RETURN: u8 = 2;
pub const SIGNAL: u8 = 4;
/// Header flag: the caller does not want a reply.
pub const NO_REPLY_EXPECTED: u8 = 0x1;
/// The largest message the specification allows: 128 MiB.
pub const MAX_MESSAGE: usize = 1 << 27;
/// How deep a signature may nest (32 arrays and 32 structs).
const MAX_DEPTH: usize = 64;

/// Header field codes.
const FIELD_PATH: u8 = 1;
const FIELD_INTERFACE: u8 = 2;
const FIELD_MEMBER: u8 = 3;
const FIELD_REPLY_SERIAL: u8 = 5;
const FIELD_DESTINATION: u8 = 6;
const FIELD_SENDER: u8 = 7;
const FIELD_SIGNATURE: u8 = 8;
const FIELD_UNIX_FDS: u8 = 9;

/// Why bytes are not a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError(pub &'static str);

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for WireError {}

type Result<T> = std::result::Result<T, WireError>;

fn pad(pos: usize, align: usize) -> usize {
    (align - pos % align) % align
}

/// How long the message at the start of `buf` is, once 16 bytes are there to
/// tell: `None` while fewer have arrived.
pub fn message_len(buf: &[u8]) -> Result<Option<usize>> {
    if buf.len() < 16 {
        return Ok(None);
    }
    let little = match buf[0] {
        b'l' => true,
        b'B' => false,
        _ => return Err(WireError("not a D-Bus message (endianness byte)")),
    };
    let body = u32_at(buf, 4, little) as usize;
    let fields = u32_at(buf, 12, little) as usize;
    let header = 16usize
        .checked_add(fields)
        .ok_or(WireError("header length overflows"))?;
    let total = header
        .checked_add(pad(header, 8))
        .and_then(|h| h.checked_add(body))
        .ok_or(WireError("message length overflows"))?;
    if total > MAX_MESSAGE {
        return Err(WireError("message larger than D-Bus allows"));
    }
    Ok(Some(total))
}

fn u32_at(buf: &[u8], at: usize, little: bool) -> u32 {
    let b = [buf[at], buf[at + 1], buf[at + 2], buf[at + 3]];
    if little {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    }
}

/// A message's fixed header and the fields the filter looks at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Header {
    pub little: bool,
    pub kind: u8,
    pub flags: u8,
    pub serial: u32,
    pub path: Option<String>,
    pub interface: Option<String>,
    pub member: Option<String>,
    pub reply_serial: Option<u32>,
    pub destination: Option<String>,
    pub sender: Option<String>,
    pub signature: Option<String>,
    pub unix_fds: u32,
    /// Where the body starts.
    pub body_offset: usize,
}

/// Read a whole message's header. `msg` is exactly one message, as
/// [`message_len`] measured it.
pub fn parse_header(msg: &[u8]) -> Result<Header> {
    let len = message_len(msg)?.ok_or(WireError("message shorter than its header"))?;
    if len != msg.len() {
        return Err(WireError("message length does not match"));
    }
    let little = msg[0] == b'l';
    let mut h = Header {
        little,
        kind: msg[1],
        flags: msg[2],
        serial: u32_at(msg, 8, little),
        ..Header::default()
    };
    if msg[3] != 1 {
        return Err(WireError("unknown protocol version"));
    }
    let fields_end = 16 + u32_at(msg, 12, little) as usize;
    let mut r = Reader {
        buf: &msg[..fields_end],
        pos: 16,
        little,
    };
    while r.pos < fields_end {
        r.align(8)?;
        if r.pos >= fields_end {
            break;
        }
        let code = r.byte()?;
        let sig = r.signature()?;
        match (code, sig.as_str()) {
            (FIELD_PATH, "o") => h.path = Some(r.string()?),
            (FIELD_INTERFACE, "s") => h.interface = Some(r.string()?),
            (FIELD_MEMBER, "s") => h.member = Some(r.string()?),
            (FIELD_DESTINATION, "s") => h.destination = Some(r.string()?),
            (FIELD_SENDER, "s") => h.sender = Some(r.string()?),
            (FIELD_SIGNATURE, "g") => h.signature = Some(r.signature()?),
            (FIELD_REPLY_SERIAL, "u") => h.reply_serial = Some(r.u32()?),
            (FIELD_UNIX_FDS, "u") => h.unix_fds = r.u32()?,
            _ => {
                let used = r.skip(sig.as_bytes(), 0)?;
                if used != sig.len() {
                    return Err(WireError("header field is not one complete type"));
                }
            }
        }
    }
    h.body_offset = fields_end + pad(fields_end, 8);
    Ok(h)
}

/// A cursor over a message. Offsets are from the start of the message, which is
/// what alignment is relative to.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    little: bool,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or(WireError("value runs past the end"))?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn align(&mut self, n: usize) -> Result<()> {
        let skip = pad(self.pos, n);
        self.take(skip).map(|_| ())
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        self.align(4)?;
        let b = self.take(4)?;
        let b = [b[0], b[1], b[2], b[3]];
        Ok(if self.little {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }

    /// `s` or `o`.
    fn string(&mut self) -> Result<String> {
        let len = self.u32()? as usize;
        let bytes = self.take(len)?.to_vec();
        if self.byte()? != 0 {
            return Err(WireError("string without its NUL"));
        }
        String::from_utf8(bytes).map_err(|_| WireError("string is not UTF-8"))
    }

    /// `g`.
    fn signature(&mut self) -> Result<String> {
        let len = self.byte()? as usize;
        let bytes = self.take(len)?.to_vec();
        if self.byte()? != 0 {
            return Err(WireError("signature without its NUL"));
        }
        String::from_utf8(bytes).map_err(|_| WireError("signature is not ASCII"))
    }

    /// Step over one complete type's value; returns how many characters of
    /// `sig` that type took.
    fn skip(&mut self, sig: &[u8], depth: usize) -> Result<usize> {
        if depth > MAX_DEPTH {
            return Err(WireError("nested too deep"));
        }
        let first = *sig.first().ok_or(WireError("empty signature"))?;
        match first {
            b'y' => self.take(1).map(|_| 1),
            b'n' | b'q' => {
                self.align(2)?;
                self.take(2).map(|_| 1)
            }
            b'b' | b'i' | b'u' | b'h' => {
                self.align(4)?;
                self.take(4).map(|_| 1)
            }
            b'x' | b't' | b'd' => {
                self.align(8)?;
                self.take(8).map(|_| 1)
            }
            b's' | b'o' => self.string().map(|_| 1),
            b'g' => self.signature().map(|_| 1),
            b'v' => {
                let inner = self.signature()?;
                let used = self.skip(inner.as_bytes(), depth + 1)?;
                if used != inner.len() {
                    return Err(WireError("variant holds more than one type"));
                }
                Ok(1)
            }
            b'a' => {
                let len = self.u32()? as usize;
                let elem = complete_type_len(&sig[1..], depth + 1)?;
                self.align(alignment(sig[1]))?;
                self.take(len)?;
                Ok(1 + elem)
            }
            b'(' | b'{' => {
                let close = if first == b'(' { b')' } else { b'}' };
                self.align(8)?;
                let mut i = 1;
                while *sig.get(i).ok_or(WireError("unclosed struct"))? != close {
                    i += self.skip(&sig[i..], depth + 1)?;
                }
                Ok(i + 1)
            }
            _ => Err(WireError("unknown type in signature")),
        }
    }
}

/// The alignment of a type by its first character.
fn alignment(code: u8) -> usize {
    match code {
        b'n' | b'q' => 2,
        b'b' | b'i' | b'u' | b'h' | b's' | b'o' | b'a' => 4,
        b'x' | b't' | b'd' | b'(' | b'{' => 8,
        _ => 1,
    }
}

/// How many characters one complete type at the start of `sig` takes.
fn complete_type_len(sig: &[u8], depth: usize) -> Result<usize> {
    if depth > MAX_DEPTH {
        return Err(WireError("nested too deep"));
    }
    match *sig
        .first()
        .ok_or(WireError("array without an element type"))?
    {
        b'a' => Ok(1 + complete_type_len(&sig[1..], depth + 1)?),
        open @ (b'(' | b'{') => {
            let close = if open == b'(' { b')' } else { b'}' };
            let mut i = 1;
            while *sig.get(i).ok_or(WireError("unclosed struct"))? != close {
                i += complete_type_len(&sig[i..], depth + 1)?;
            }
            Ok(i + 1)
        }
        b'y' | b'b' | b'n' | b'q' | b'i' | b'u' | b'x' | b't' | b'd' | b'h' | b's' | b'o'
        | b'g' | b'v' => Ok(1),
        _ => Err(WireError("unknown type in signature")),
    }
}

/// The body of a portal call, read up to its `a{sv}` of options: the string
/// arguments before it (in order) and `handle_token` from the options, if it is
/// a string. `sig` is the body's signature; everything before the options must
/// be `s` or `h` (the window handle, the URI, a file descriptor's index).
pub fn portal_call(msg: &[u8], h: &Header) -> Result<(Vec<String>, Option<String>)> {
    let sig = h.signature.as_deref().unwrap_or("");
    let Some(before) = sig.strip_suffix("a{sv}") else {
        return Err(WireError("not a portal call (no options at the end)"));
    };
    let mut r = Reader {
        buf: msg,
        pos: h.body_offset,
        little: h.little,
    };
    let mut strings = Vec::new();
    for code in before.bytes() {
        match code {
            b's' => strings.push(r.string()?),
            b'h' => {
                r.u32()?;
            }
            _ => return Err(WireError("unexpected argument before the options")),
        }
    }
    let len = r.u32()? as usize;
    r.align(8)?;
    let end = r
        .pos
        .checked_add(len)
        .filter(|&e| e <= msg.len())
        .ok_or(WireError("options run past the end"))?;
    let mut token = None;
    while r.pos < end {
        r.align(8)?;
        let key = r.string()?;
        let vsig = r.signature()?;
        if key == "handle_token" && vsig == "s" {
            token = Some(r.string()?);
        } else if r.skip(vsig.as_bytes(), 0)? != vsig.len() {
            return Err(WireError("option holds more than one type"));
        }
    }
    Ok((strings, token))
}

/// A body that is one string (`s`), as the bus answers `GetNameOwner`.
pub fn body_string(msg: &[u8], h: &Header) -> Result<String> {
    if h.signature.as_deref() != Some("s") {
        return Err(WireError("the body is not one string"));
    }
    Reader {
        buf: msg,
        pos: h.body_offset,
        little: h.little,
    }
    .string()
}

// --- WRITING ------------------------------------------------------------------

/// A little-endian message under construction.
struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn align(&mut self, n: usize) {
        let skip = pad(self.buf.len(), n);
        self.buf.extend(std::iter::repeat_n(0, skip));
    }
    fn u32(&mut self, v: u32) {
        self.align(4);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn string(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
    }
    fn signature(&mut self, s: &str) {
        self.buf.push(s.len() as u8);
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
    }
    fn field_str(&mut self, code: u8, sig: &str, value: &str) {
        self.align(8);
        self.buf.push(code);
        self.signature(sig);
        if sig == "g" {
            self.signature(value);
        } else {
            self.string(value);
        }
    }
    fn field_u32(&mut self, code: u8, value: u32) {
        self.align(8);
        self.buf.push(code);
        self.signature("u");
        self.u32(value);
    }
}

/// A header field to write.
pub enum Field<'a> {
    Path(&'a str),
    Interface(&'a str),
    Member(&'a str),
    ReplySerial(u32),
    Destination(&'a str),
    Sender(&'a str),
    Signature(&'a str),
}

/// A complete message: header with `fields`, then `body` (already marshalled
/// from offset 0 of an 8-aligned start, which is what [`body`] produces).
pub fn message(kind: u8, flags: u8, serial: u32, fields: &[Field<'_>], body: &[u8]) -> Vec<u8> {
    let mut w = Writer { buf: Vec::new() };
    w.buf.extend_from_slice(&[b'l', kind, flags, 1]);
    w.u32(body.len() as u32);
    w.u32(serial);
    w.u32(0); // the fields' length, filled in below
    for field in fields {
        match field {
            Field::Path(v) => w.field_str(FIELD_PATH, "o", v),
            Field::Interface(v) => w.field_str(FIELD_INTERFACE, "s", v),
            Field::Member(v) => w.field_str(FIELD_MEMBER, "s", v),
            Field::ReplySerial(v) => w.field_u32(FIELD_REPLY_SERIAL, *v),
            Field::Destination(v) => w.field_str(FIELD_DESTINATION, "s", v),
            Field::Sender(v) => w.field_str(FIELD_SENDER, "s", v),
            Field::Signature(v) => w.field_str(FIELD_SIGNATURE, "g", v),
        }
    }
    let fields_len = (w.buf.len() - 16) as u32;
    w.buf[12..16].copy_from_slice(&fields_len.to_le_bytes());
    w.align(8);
    w.buf.extend_from_slice(body);
    w.buf
}

/// Bodies the filter writes.
pub mod body {
    use super::Writer;

    /// One string (`s`, or an object path `o`).
    pub fn string(s: &str) -> Vec<u8> {
        let mut w = Writer { buf: Vec::new() };
        w.string(s);
        w.buf
    }

    /// A portal's `Response`: `(u response, a{sv} results)` with no results.
    pub fn response(code: u32) -> Vec<u8> {
        let mut w = Writer { buf: Vec::new() };
        w.u32(code);
        w.u32(0);
        // An empty array is still padded to its elements' alignment.
        w.align(8);
        w.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An OpenURI call the way GLib writes it: parent window, URI, options with
    /// a handle token and a boolean next to it.
    fn open_uri(uri: &str, token: Option<&str>) -> Vec<u8> {
        let mut w = Writer { buf: Vec::new() };
        w.string("");
        w.string(uri);
        w.u32(0); // the options' length, patched below
        let at = w.buf.len() - 4;
        w.align(8);
        let start = w.buf.len();
        w.align(8);
        w.string("writable");
        w.signature("b");
        w.u32(1);
        if let Some(t) = token {
            w.align(8);
            w.string("handle_token");
            w.signature("s");
            w.string(t);
        }
        let len = (w.buf.len() - start) as u32;
        w.buf[at..at + 4].copy_from_slice(&len.to_le_bytes());
        message(
            METHOD_CALL,
            0,
            7,
            &[
                Field::Path("/org/freedesktop/portal/desktop"),
                Field::Interface("org.freedesktop.portal.OpenURI"),
                Field::Member("OpenURI"),
                Field::Destination("org.freedesktop.portal.Desktop"),
                Field::Signature("ssa{sv}"),
            ],
            &w.buf,
        )
    }

    #[test]
    fn a_call_is_measured_parsed_and_its_options_read() {
        let msg = open_uri("https://example.org/x", Some("gtk123"));
        assert_eq!(message_len(&msg).unwrap(), Some(msg.len()));
        assert_eq!(message_len(&msg[..10]).unwrap(), None);
        let h = parse_header(&msg).unwrap();
        assert_eq!(h.kind, METHOD_CALL);
        assert_eq!(h.serial, 7);
        assert_eq!(h.member.as_deref(), Some("OpenURI"));
        assert_eq!(
            h.interface.as_deref(),
            Some("org.freedesktop.portal.OpenURI")
        );
        assert_eq!(h.signature.as_deref(), Some("ssa{sv}"));
        let (strings, token) = portal_call(&msg, &h).unwrap();
        assert_eq!(strings, ["", "https://example.org/x"]);
        assert_eq!(token.as_deref(), Some("gtk123"));
        let (_, none) = portal_call(&open_uri("https://e.org", None), &h).unwrap();
        assert_eq!(none, None);
    }

    #[test]
    fn what_the_filter_writes_reads_back() {
        let ret = message(
            METHOD_RETURN,
            0,
            1,
            &[
                Field::ReplySerial(7),
                Field::Destination(":1.42"),
                Field::Sender(":1.5"),
                Field::Signature("o"),
            ],
            &body::string("/org/freedesktop/portal/desktop/request/1_42/t"),
        );
        let h = parse_header(&ret).unwrap();
        assert_eq!(h.reply_serial, Some(7));
        assert_eq!(h.destination.as_deref(), Some(":1.42"));
        assert_eq!(h.sender.as_deref(), Some(":1.5"));
        assert_eq!(h.body_offset % 8, 0);
        let sig = message(
            SIGNAL,
            0,
            2,
            &[
                Field::Path("/org/freedesktop/portal/desktop/request/1_42/t"),
                Field::Interface("org.freedesktop.portal.Request"),
                Field::Member("Response"),
                Field::Signature("ua{sv}"),
            ],
            &body::response(2),
        );
        let h = parse_header(&sig).unwrap();
        assert_eq!(h.member.as_deref(), Some("Response"));
        assert_eq!(&sig[h.body_offset..], [2, 0, 0, 0, 0, 0, 0, 0]);
    }

    /// Lies in lengths are errors, not panics or allocations.
    #[test]
    fn lying_lengths_are_refused() {
        let mut msg = open_uri("https://example.org", Some("t"));
        assert!(message_len(b"XXXXXXXXXXXXXXXXXXXX").is_err());
        let mut huge = msg.clone();
        huge[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(message_len(&huge).is_err());
        // The URI's length points past the end of the message.
        let h = parse_header(&msg).unwrap();
        let at = h.body_offset + 4;
        msg[at..at + 4].copy_from_slice(&1_000_000u32.to_le_bytes());
        assert!(portal_call(&msg, &h).is_err());
        // Every prefix and every single-byte corruption: an error or a value,
        // never a panic.
        let good = open_uri("https://example.org/p", Some("tok"));
        for cut in 0..good.len() {
            let _ = message_len(&good[..cut]);
            let _ = parse_header(&good[..cut]);
        }
        for i in 0..good.len() {
            for v in [0u8, 0xff, 0x7f, b'a'] {
                let mut bad = good.clone();
                bad[i] = v;
                if let Ok(h) = parse_header(&bad) {
                    let _ = portal_call(&bad, &h);
                }
            }
        }
    }

    #[test]
    fn nesting_is_bounded_and_types_are_skipped() {
        assert!(complete_type_len(&[b'a'; 100], 0).is_err());
        assert_eq!(complete_type_len(b"a{sv}x", 0).unwrap(), 5);
        assert_eq!(complete_type_len(b"(ia(s))", 0).unwrap(), 7);
        assert!(complete_type_len(b"(ii", 0).is_err());
    }
}
