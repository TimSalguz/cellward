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
pub const ERROR: u8 = 3;
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
const FIELD_ERROR_NAME: u8 = 4;
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

// --- NOTIFICATIONS -------------------------------------------------------------

/// The hints a notification keeps on its way to the host's daemon: how it
/// looks and sounds, nothing it can be told to fetch, open or start. Dropped
/// among others: `desktop-entry` (a click activates that application on the
/// host), `x-kde-urls` (links the daemon opens), `sound-file` (a path the host
/// plays). `image-path` stays when it is a path or a `file://` URI.
const NOTIFY_HINTS: [&str; 11] = [
    "urgency",
    "category",
    "transient",
    "resident",
    "image-data",
    "image_data",
    "icon_data",
    "suppress-sound",
    "sound-name",
    "action-icons",
    "x-kde-display-appname",
];

/// A path, or a URI of a local file: nothing the host would fetch.
fn local(uri: &str) -> bool {
    !uri.contains("://") || uri.starts_with("file://")
}

/// Notification markup without what points anywhere: `b`, `i` and `u` stay,
/// every other tag goes (its text stays) — `<a href>` a click opens on the
/// host, `<img src>` a daemon may fetch.
pub fn plain_markup(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('<') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('>') else {
            out.push_str("&lt;");
            rest = after;
            continue;
        };
        let tag = &after[..close];
        if matches!(tag, "b" | "/b" | "i" | "/i" | "u" | "/u") {
            out.push('<');
            out.push_str(tag);
            out.push('>');
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

/// One `a{sv}` read entry by entry: each kept as it was — its bytes, which
/// start 8-aligned wherever they land — or dropped, or (`image-path`)
/// rewritten.
fn filtered_options(
    r: &mut Reader<'_>,
    w: &mut Writer,
    keep: &dyn Fn(&str) -> bool,
    path_keys: &[&str],
) -> Result<()> {
    let len = r.u32()? as usize;
    r.align(8)?;
    let end = r
        .pos
        .checked_add(len)
        .filter(|&e| e <= r.buf.len())
        .ok_or(WireError("options run past the end"))?;
    w.u32(0);
    let len_at = w.buf.len() - 4;
    w.align(8);
    let start = w.buf.len();
    while r.pos < end {
        r.align(8)?;
        let entry = r.pos;
        let key = r.string()?;
        let vsig = r.signature()?;
        if path_keys.contains(&key.as_str()) && vsig == "s" {
            let value = r.string()?;
            if local(&value) {
                w.align(8);
                w.string(&key);
                w.signature("s");
                w.string(&value);
            }
            continue;
        }
        if r.skip(vsig.as_bytes(), 0)? != vsig.len() {
            return Err(WireError("option holds more than one type"));
        }
        if keep(&key) {
            w.align(8);
            w.buf.extend_from_slice(&r.buf[entry..r.pos]);
        }
    }
    let len = (w.buf.len() - start) as u32;
    w.buf[len_at..len_at + 4].copy_from_slice(&len.to_le_bytes());
    Ok(())
}

/// `org.freedesktop.Notifications.Notify` as the host's daemon may have it
/// from a zone (review 2026-09-25, third round): it runs on the host, and a
/// link in the text, an icon by URL or a hint that names an application is
/// the host's network or a host launch — past the door OpenURI is. The new
/// body, little-endian; a big-endian message is refused by the caller.
pub fn sanitized_notify(msg: &[u8], h: &Header) -> Result<Vec<u8>> {
    if h.signature.as_deref() != Some(body::NOTIFY_SIGNATURE) || !h.little {
        return Err(WireError("not a notification the filter reads"));
    }
    let mut r = Reader {
        buf: msg,
        pos: h.body_offset,
        little: true,
    };
    let mut w = Writer { buf: Vec::new() };
    let app = r.string()?;
    let replaces = r.u32()?;
    let icon = r.string()?;
    let summary = r.string()?;
    let text = r.string()?;
    w.string(&app);
    w.u32(replaces);
    w.string(if local(&icon) { &icon } else { "" });
    w.string(&summary);
    w.string(&plain_markup(&text));
    // The actions: their keys go back to the program, which acts on them.
    let len = r.u32()? as usize;
    let end = r
        .pos
        .checked_add(len)
        .filter(|&e| e <= msg.len())
        .ok_or(WireError("actions run past the end"))?;
    let mut actions = Vec::new();
    while r.pos < end {
        actions.push(r.string()?);
    }
    w.u32(0);
    let len_at = w.buf.len() - 4;
    let start = w.buf.len();
    for action in &actions {
        w.string(action);
    }
    let len = (w.buf.len() - start) as u32;
    w.buf[len_at..len_at + 4].copy_from_slice(&len.to_le_bytes());
    filtered_options(
        &mut r,
        &mut w,
        &|key| NOTIFY_HINTS.contains(&key),
        &["image-path", "image_path"],
    )?;
    let timeout = r.u32()?;
    w.u32(timeout);
    if r.pos != msg.len() {
        return Err(WireError("more after the notification"));
    }
    Ok(w.buf)
}

/// The notification portal's `AddNotification(s id, a{sv})` without
/// `markup-body`, whose links the host's daemon would open.
pub fn sanitized_portal_notification(msg: &[u8], h: &Header) -> Result<Vec<u8>> {
    if h.signature.as_deref() != Some("sa{sv}") || !h.little {
        return Err(WireError("not a notification the filter reads"));
    }
    let mut r = Reader {
        buf: msg,
        pos: h.body_offset,
        little: true,
    };
    let mut w = Writer { buf: Vec::new() };
    w.string(&r.string()?);
    filtered_options(&mut r, &mut w, &|key| key != "markup-body", &[])?;
    if r.pos != msg.len() {
        return Err(WireError("more after the notification"));
    }
    Ok(w.buf)
}

/// The options of `ScreenCast.SelectSources` passed on: what to show and how.
/// Not `persist_mode` and `restore_token` — and nothing a later portal adds.
pub const SCREENCAST_OPTIONS: &[&str] = &["handle_token", "types", "multiple", "cursor_mode"];

/// The screen cast portal's `SelectSources(o session, a{sv})` that asks every
/// time. A remembered choice (`persist_mode`) comes back as a token, and with
/// it the portal starts the next cast WITHOUT its dialog: the program could
/// show the screen again whenever it likes, and in niri nothing says so. The
/// portal keeps the choice for "host applications" — which a zone's program
/// is to it (`bus_filter::PORTAL_ALLOWED`) — so the person could not even
/// tell which zone it was given to.
pub fn sanitized_screencast_sources(msg: &[u8], h: &Header) -> Result<Vec<u8>> {
    if h.signature.as_deref() != Some("oa{sv}") || !h.little {
        return Err(WireError("not a screen cast selection the filter reads"));
    }
    let mut r = Reader {
        buf: msg,
        pos: h.body_offset,
        little: true,
    };
    let mut w = Writer { buf: Vec::new() };
    w.string(&r.string()?);
    filtered_options(
        &mut r,
        &mut w,
        &|key| SCREENCAST_OPTIONS.contains(&key),
        &[],
    )?;
    if r.pos != msg.len() {
        return Err(WireError("more after the screen cast selection"));
    }
    Ok(w.buf)
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
    ErrorName(&'a str),
    ReplySerial(u32),
    Destination(&'a str),
    Sender(&'a str),
    Signature(&'a str),
    UnixFds(u32),
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
            Field::ErrorName(v) => w.field_str(FIELD_ERROR_NAME, "s", v),
            Field::ReplySerial(v) => w.field_u32(FIELD_REPLY_SERIAL, *v),
            Field::Destination(v) => w.field_str(FIELD_DESTINATION, "s", v),
            Field::Sender(v) => w.field_str(FIELD_SENDER, "s", v),
            Field::Signature(v) => w.field_str(FIELD_SIGNATURE, "g", v),
            Field::UnixFds(v) => w.field_u32(FIELD_UNIX_FDS, *v),
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

    /// `org.freedesktop.Notifications.Notify`'s arguments.
    pub const NOTIFY_SIGNATURE: &str = "susssasa{sv}i";

    /// A notification: no replaced id, no actions, no hints, the server's
    /// default timeout.
    pub fn notification(app: &str, summary: &str, text: &str) -> Vec<u8> {
        let mut w = Writer { buf: Vec::new() };
        w.string(app);
        w.u32(0);
        w.string("dialog-information");
        w.string(summary);
        w.string(text);
        // `as`: empty.
        w.u32(0);
        // `a{sv}`: empty, padded to its elements' alignment.
        w.u32(0);
        w.align(8);
        // `i`: -1, the server's default.
        w.u32(u32::MAX);
        w.buf
    }

    /// A portal's `Response`: `(u response, a{sv} results)` with no results.
    /// A boolean (`b`).
    pub fn boolean(v: bool) -> Vec<u8> {
        let mut w = Writer { buf: Vec::new() };
        w.u32(u32::from(v));
        w.buf
    }

    /// An unsigned 32-bit number (`u`).
    pub fn uint(v: u32) -> Vec<u8> {
        let mut w = Writer { buf: Vec::new() };
        w.u32(v);
        w.buf
    }

    /// An array of strings (`as`).
    pub fn strings(items: &[&str]) -> Vec<u8> {
        let mut w = Writer { buf: Vec::new() };
        w.u32(0);
        let start = w.buf.len();
        for s in items {
            w.string(s);
        }
        let len = (w.buf.len() - start) as u32;
        w.buf[start - 4..start].copy_from_slice(&len.to_le_bytes());
        w.buf
    }

    /// `NetworkMonitor.GetStatus`'s `a{sv}`: available, metered, connectivity.
    pub fn network_status(available: bool, metered: bool, connectivity: u32) -> Vec<u8> {
        let mut w = Writer { buf: Vec::new() };
        w.u32(0);
        let len_at = w.buf.len() - 4;
        w.align(8);
        let start = w.buf.len();
        for (key, sig, value) in [
            ("available", "b", u32::from(available)),
            ("metered", "b", u32::from(metered)),
            ("connectivity", "u", connectivity),
        ] {
            w.align(8);
            w.string(key);
            w.signature(sig);
            w.u32(value);
        }
        let len = (w.buf.len() - start) as u32;
        w.buf[len_at..len_at + 4].copy_from_slice(&len.to_le_bytes());
        w.buf
    }

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

    /// A notification as a program in a zone might send it, with everything
    /// that points the host's daemon at the network or at an application.
    fn hostile_notify() -> Vec<u8> {
        let mut w = Writer { buf: Vec::new() };
        w.string("app");
        w.u32(7);
        w.string("https://evil.test/icon.png");
        w.string("summary");
        w.string(
            "<a href=\"https://x.test\">click</a> <b>bold</b><img src=\"http://y.test\"/> 1 < 2",
        );
        // actions
        w.u32(0);
        let at = w.buf.len();
        for a in ["default", "Open"] {
            w.string(a);
        }
        let len = (w.buf.len() - at) as u32;
        w.buf[at - 4..at].copy_from_slice(&len.to_le_bytes());
        // hints
        w.u32(0);
        let len_at = w.buf.len() - 4;
        w.align(8);
        let start = w.buf.len();
        for (key, value) in [
            ("desktop-entry", "firefox"),
            ("image-path", "https://evil.test/i.png"),
            ("image_path", "/tmp/a.png"),
            ("sound-file", "/tmp/s.oga"),
        ] {
            w.align(8);
            w.string(key);
            w.signature("s");
            w.string(value);
        }
        w.align(8);
        w.string("urgency");
        w.signature("y");
        w.buf.push(2);
        w.align(8);
        w.string("x-kde-urls");
        w.signature("as");
        w.u32(0);
        let at = w.buf.len();
        w.string("https://z.test");
        let n = (w.buf.len() - at) as u32;
        w.buf[at - 4..at].copy_from_slice(&n.to_le_bytes());
        let len = (w.buf.len() - start) as u32;
        w.buf[len_at..len_at + 4].copy_from_slice(&len.to_le_bytes());
        w.u32(u32::MAX);
        message(
            METHOD_CALL,
            0,
            5,
            &[
                Field::Path("/org/freedesktop/Notifications"),
                Field::Interface("org.freedesktop.Notifications"),
                Field::Member("Notify"),
                Field::Destination("org.freedesktop.Notifications"),
                Field::Signature(body::NOTIFY_SIGNATURE),
            ],
            &w.buf,
        )
    }

    /// What reaches the daemon: the text without links and images, no icon by
    /// URL, the hints of the allow-list and a local image path — and a
    /// message the bus can read.
    #[test]
    fn a_notification_loses_what_points_anywhere() {
        let msg = hostile_notify();
        let h = parse_header(&msg).unwrap();
        let body = sanitized_notify(&msg, &h).unwrap();
        let out = message(
            METHOD_CALL,
            0,
            5,
            &[Field::Signature(body::NOTIFY_SIGNATURE)],
            &body,
        );
        let h2 = parse_header(&out).unwrap();
        let mut r = Reader {
            buf: &out,
            pos: h2.body_offset,
            little: true,
        };
        assert_eq!(r.string().unwrap(), "app");
        assert_eq!(r.u32().unwrap(), 7);
        assert_eq!(r.string().unwrap(), "");
        assert_eq!(r.string().unwrap(), "summary");
        assert_eq!(r.string().unwrap(), "click <b>bold</b> 1 &lt; 2");
        let len = r.u32().unwrap() as usize;
        let end = r.pos + len;
        let mut actions = Vec::new();
        while r.pos < end {
            actions.push(r.string().unwrap());
        }
        assert_eq!(actions, ["default", "Open"]);
        let len = r.u32().unwrap() as usize;
        r.align(8).unwrap();
        let end = r.pos + len;
        let mut keys = Vec::new();
        while r.pos < end {
            r.align(8).unwrap();
            let key = r.string().unwrap();
            let sig = r.signature().unwrap();
            if key == "image_path" {
                assert_eq!(r.string().unwrap(), "/tmp/a.png");
            } else {
                r.skip(sig.as_bytes(), 0).unwrap();
            }
            keys.push(key);
        }
        assert_eq!(keys, ["image_path", "urgency"]);
        assert_eq!(r.u32().unwrap(), u32::MAX);
        assert_eq!(r.pos, out.len());
    }

    #[test]
    fn markup_keeps_bold_italic_underline_only() {
        assert_eq!(
            plain_markup("<i>a</i><u>b</u><span color='x'>c</span>"),
            "<i>a</i><u>b</u>c"
        );
        assert_eq!(plain_markup("a <A HREF=x>b</A>"), "a b");
        assert_eq!(plain_markup("no tag < here"), "no tag &lt; here");
    }

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

    /// The notification body is exactly its signature: a reader stepping over
    /// every argument ends where the body ends.
    #[test]
    fn a_notification_is_its_signature() {
        let b = body::notification("vpn-zones", "Файл не открыт", "текст");
        let mut r = Reader {
            buf: &b,
            pos: 0,
            little: true,
        };
        let mut sig: &[u8] = body::NOTIFY_SIGNATURE.as_bytes();
        while !sig.is_empty() {
            let used = r.skip(sig, 0).unwrap();
            sig = &sig[used..];
        }
        assert_eq!(r.pos, b.len());
    }

    /// A screen cast's choice of sources reaches the portal without what
    /// would have it remembered, and without an option nobody has read.
    #[test]
    fn a_screen_cast_is_not_remembered() {
        let session = "/org/freedesktop/portal/desktop/session/1_42/s";
        let mut w = Writer { buf: Vec::new() };
        w.string(session);
        w.u32(0);
        let at = w.buf.len() - 4;
        w.align(8);
        let start = w.buf.len();
        for (key, sig, value) in [
            ("handle_token", "s", Some("t1")),
            ("persist_mode", "u", None),
            ("types", "u", None),
            ("restore_token", "s", Some("0b2c…")),
            ("multiple", "b", None),
            ("cursor_mode", "u", None),
            ("later_option", "s", Some("x")),
        ] {
            w.align(8);
            w.string(key);
            w.signature(sig);
            match value {
                Some(v) => w.string(v),
                None => w.u32(2),
            }
        }
        let len = (w.buf.len() - start) as u32;
        w.buf[at..at + 4].copy_from_slice(&len.to_le_bytes());
        let fields = [
            Field::Path("/org/freedesktop/portal/desktop"),
            Field::Interface("org.freedesktop.portal.ScreenCast"),
            Field::Member("SelectSources"),
            Field::Destination("org.freedesktop.portal.Desktop"),
            Field::Signature("oa{sv}"),
        ];
        let msg = message(METHOD_CALL, 0, 9, &fields, &w.buf);
        let h = parse_header(&msg).unwrap();
        let body = sanitized_screencast_sources(&msg, &h).unwrap();
        let out = message(METHOD_CALL, 0, 9, &fields, &body);
        let h2 = parse_header(&out).unwrap();
        let mut r = Reader {
            buf: &out,
            pos: h2.body_offset,
            little: true,
        };
        assert_eq!(r.string().unwrap(), session);
        let len = r.u32().unwrap() as usize;
        r.align(8).unwrap();
        let end = r.pos + len;
        let mut keys = Vec::new();
        while r.pos < end {
            r.align(8).unwrap();
            let key = r.string().unwrap();
            let sig = r.signature().unwrap();
            r.skip(sig.as_bytes(), 0).unwrap();
            keys.push(key);
        }
        assert_eq!(r.pos, out.len());
        assert_eq!(keys, ["handle_token", "types", "multiple", "cursor_mode"]);
        // Not read, not passed on: another signature is refused.
        let mut odd = h.clone();
        odd.signature = Some("oa{ss}".to_owned());
        assert!(sanitized_screencast_sources(&msg, &odd).is_err());
    }

    #[test]
    fn nesting_is_bounded_and_types_are_skipped() {
        assert!(complete_type_len(&[b'a'; 100], 0).is_err());
        assert_eq!(complete_type_len(b"a{sv}x", 0).unwrap(), 5);
        assert_eq!(complete_type_len(b"(ia(s))", 0).unwrap(), 7);
        assert!(complete_type_len(b"(ii", 0).is_err());
    }
}
