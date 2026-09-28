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
    /// An `ERROR`'s name.
    pub error_name: Option<String>,
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
            (FIELD_ERROR_NAME, "s") => h.error_name = Some(r.string()?),
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

/// What a remembered choice adds to them: the zone's `screencast yes`, on a
/// connection the portal knows by the zone's own id
/// (`bus_filter::screencast_verdict`).
pub const SCREENCAST_REMEMBERED: &[&str] = &["persist_mode", "restore_token"];

/// The screen cast portal's `SelectSources(o session, a{sv})` as it may go on.
///
/// Asking every time (`remember` false — the zone's `ask`, and `yes` without
/// an id of the zone's): a remembered choice (`persist_mode`) comes back as a
/// token, and with it the portal starts the next cast WITHOUT its dialog —
/// the program could show the screen again whenever it likes, and in niri
/// nothing says so. The portal keeps the choice under the caller's
/// application id, and a zone's program without one is a nameless "host
/// application" to it, the one every zone shares
/// (`bus_filter::PORTAL_ALLOWED`): the person could not even tell which zone
/// it was given to.
///
/// `remember` (`yes`, and the connection registered as the zone — LEAK-MODEL
/// §23): `persist_mode` and `restore_token` pass as well, and the choice is
/// kept under the zone's own id. Anything on neither list goes either way.
pub fn sanitized_screencast_sources(msg: &[u8], h: &Header, remember: bool) -> Result<Vec<u8>> {
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
        &|key| {
            SCREENCAST_OPTIONS.contains(&key) || (remember && SCREENCAST_REMEMBERED.contains(&key))
        },
        &[],
    )?;
    if r.pos != msg.len() {
        return Err(WireError("more after the screen cast selection"));
    }
    Ok(w.buf)
}

// --- TRAY ICONS ----------------------------------------------------------------

/// A tray icon's interface: the KDE spelling and the freedesktop one.
pub const ITEM_INTERFACES: [&str; 2] = [
    "org.kde.StatusNotifierItem",
    "org.freedesktop.StatusNotifierItem",
];

/// The most pictures one property carries that the filter reads.
const MAX_PICTURES: usize = 64;

/// What a tray host asked a program's icon for: all its properties, or one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemAsk {
    All,
    One(String),
}

/// A call from the bus asking a tray icon's properties
/// (`org.freedesktop.DBus.Properties.Get`/`GetAll` on [`ITEM_INTERFACES`]),
/// and which. Anything else, or a call that does not read: `None`.
pub fn item_properties_call(msg: &[u8], h: &Header) -> Option<ItemAsk> {
    if h.kind != METHOD_CALL || h.interface.as_deref() != Some("org.freedesktop.DBus.Properties") {
        return None;
    }
    let mut r = Reader {
        buf: msg,
        pos: h.body_offset,
        little: h.little,
    };
    let ask = match (h.member.as_deref()?, h.signature.as_deref()?) {
        ("GetAll", "s") => ItemAsk::All,
        ("Get", "ss") => {
            let interface = r.string().ok()?;
            let property = r.string().ok()?;
            return ITEM_INTERFACES
                .contains(&interface.as_str())
                .then_some(ItemAsk::One(property));
        }
        _ => return None,
    };
    let interface = r.string().ok()?;
    ITEM_INTERFACES.contains(&interface.as_str()).then_some(ask)
}

/// A picture of a tray icon: width, height, ARGB32 in network byte order.
pub type Picture = (i32, i32, Vec<u8>);

/// What the filter does to a tray icon's answer (`crate::tray`): draws on
/// each picture, gives an icon with no pictures of its own an overlay, and
/// adds to the tooltip's text.
pub struct ItemMarks<'a> {
    pub picture: &'a dyn Fn(i32, i32, &mut [u8]),
    pub overlay: Option<Picture>,
    pub tooltip: &'a dyn Fn(&str) -> String,
}

fn read_pictures(r: &mut Reader<'_>) -> Result<Vec<Picture>> {
    let len = r.u32()? as usize;
    r.align(8)?;
    let end = r
        .pos
        .checked_add(len)
        .filter(|&e| e <= r.buf.len())
        .ok_or(WireError("pictures run past the end"))?;
    let mut out = Vec::new();
    while r.pos < end {
        if out.len() == MAX_PICTURES {
            return Err(WireError("too many pictures"));
        }
        r.align(8)?;
        let width = r.u32()? as i32;
        let height = r.u32()? as i32;
        let n = r.u32()? as usize;
        let bytes = r.take(n)?.to_vec();
        out.push((width, height, bytes));
    }
    if r.pos != end {
        return Err(WireError("pictures end inside a picture"));
    }
    Ok(out)
}

fn write_pictures(w: &mut Writer, pictures: &[Picture]) {
    w.u32(0);
    let len_at = w.buf.len() - 4;
    // An array of structs is padded to its elements' alignment, empty or not.
    w.align(8);
    let start = w.buf.len();
    for (width, height, bytes) in pictures {
        w.align(8);
        w.u32(*width as u32);
        w.u32(*height as u32);
        w.u32(bytes.len() as u32);
        w.buf.extend_from_slice(bytes);
    }
    let len = (w.buf.len() - start) as u32;
    w.buf[len_at..len_at + 4].copy_from_slice(&len.to_le_bytes());
}

fn marked_pictures(mut pictures: Vec<Picture>, marks: &ItemMarks<'_>) -> Vec<Picture> {
    for (width, height, bytes) in &mut pictures {
        (marks.picture)(*width, *height, bytes);
    }
    pictures
}

/// A property the filter writes again, read and marked.
enum Marked {
    Pictures(Vec<Picture>),
    /// `(sa(iiay)ss)`: icon name, pictures, title, text.
    Tip(String, Vec<Picture>, String, String),
}

/// One property's value marked, or `None` for one left as it is. `r` is at
/// the value, and past it after the call either way.
fn marked_value(
    name: &str,
    sig: &str,
    r: &mut Reader<'_>,
    marks: &ItemMarks<'_>,
    has_pictures: bool,
) -> Result<Option<Marked>> {
    match (name, sig) {
        ("IconPixmap" | "AttentionIconPixmap", "a(iiay)") => {
            let pictures = read_pictures(r)?;
            if pictures.is_empty() {
                return Ok(None);
            }
            Ok(Some(Marked::Pictures(marked_pictures(pictures, marks))))
        }
        ("OverlayIconPixmap", "a(iiay)") => {
            let pictures = read_pictures(r)?;
            // The program's own overlay stays; an icon with pictures of its
            // own is marked on them.
            match marks.overlay.as_ref() {
                Some(overlay) if pictures.is_empty() && !has_pictures => {
                    Ok(Some(Marked::Pictures(vec![overlay.clone()])))
                }
                _ => Ok(None),
            }
        }
        ("ToolTip", "(sa(iiay)ss)") => {
            r.align(8)?;
            let icon = r.string()?;
            let pictures = read_pictures(r)?;
            let title = r.string()?;
            let text = r.string()?;
            Ok(Some(Marked::Tip(
                icon,
                marked_pictures(pictures, marks),
                title,
                (marks.tooltip)(&text),
            )))
        }
        _ => {
            let used = r.skip(sig.as_bytes(), 1)?;
            if used != sig.len() {
                return Err(WireError("a property holds more than one type"));
            }
            Ok(None)
        }
    }
}

/// Write a marked value where `w` is: its alignment is relative to the
/// body, which starts 8-aligned in the message, so it is right in the
/// message too.
fn write_marked(w: &mut Writer, m: &Marked) {
    match m {
        Marked::Pictures(pictures) => write_pictures(w, pictures),
        Marked::Tip(icon, pictures, title, text) => {
            w.align(8);
            w.string(icon);
            write_pictures(w, pictures);
            w.string(title);
            w.string(text);
        }
    }
}

/// A program's answer to a tray host's [`ItemAsk`] with the zone's mark on
/// it (`crate::tray`): the new body, little-endian, or `None` when there is
/// nothing to mark. An answer the filter cannot mark — big-endian (its
/// untouched properties could not be copied into a little-endian body), or
/// one that does not read — is an error: the caller refuses it rather than
/// pass an icon without its mark (independent review 2026-09-28: a
/// big-endian answer was a way to drop the mark).
pub fn marked_item_reply(
    msg: &[u8],
    h: &Header,
    ask: &ItemAsk,
    marks: &ItemMarks<'_>,
) -> Result<Option<Vec<u8>>> {
    if h.kind != METHOD_RETURN {
        return Ok(None);
    }
    if !h.little {
        return Err(WireError("a big-endian answer is not marked"));
    }
    let mut r = Reader {
        buf: msg,
        pos: h.body_offset,
        little: true,
    };
    match ask {
        ItemAsk::One(name) => {
            if h.signature.as_deref() != Some("v") {
                return Ok(None);
            }
            let sig = r.signature()?;
            // Alone, an overlay cannot tell whether the icon has pictures
            // of its own: the mark goes on both — the same colour on the
            // same corner, one mark to the eye.
            let Some(value) = marked_value(name, &sig, &mut r, marks, false)? else {
                return Ok(None);
            };
            if r.pos != msg.len() {
                return Err(WireError("more after the property"));
            }
            let mut w = Writer { buf: Vec::new() };
            w.signature(&sig);
            write_marked(&mut w, &value);
            Ok(Some(w.buf))
        }
        ItemAsk::All => {
            if h.signature.as_deref() != Some("a{sv}") {
                return Ok(None);
            }
            let len = r.u32()? as usize;
            r.align(8)?;
            let end = r
                .pos
                .checked_add(len)
                .filter(|&e| e <= msg.len())
                .ok_or(WireError("properties run past the end"))?;
            // First every entry: where it is, its name and signature, and
            // whether the icon has pictures of its own.
            struct Entry {
                start: usize,
                value: usize,
                end: usize,
                name: String,
                sig: String,
            }
            let mut entries = Vec::new();
            let mut has_pictures = false;
            while r.pos < end {
                r.align(8)?;
                let start = r.pos;
                let name = r.string()?;
                let sig = r.signature()?;
                let value = r.pos;
                if name == "IconPixmap" && sig == "a(iiay)" {
                    has_pictures = !read_pictures(&mut r)?.is_empty();
                } else {
                    let used = r.skip(sig.as_bytes(), 1)?;
                    if used != sig.len() {
                        return Err(WireError("a property holds more than one type"));
                    }
                }
                entries.push(Entry {
                    start,
                    value,
                    end: r.pos,
                    name,
                    sig,
                });
            }
            if r.pos != end || end != msg.len() {
                return Err(WireError("more after the properties"));
            }
            let mut w = Writer { buf: Vec::new() };
            w.u32(0);
            let len_at = w.buf.len() - 4;
            w.align(8);
            let start = w.buf.len();
            let mut changed = false;
            for e in &entries {
                let mut v = Reader {
                    buf: msg,
                    pos: e.value,
                    little: true,
                };
                w.align(8);
                match marked_value(&e.name, &e.sig, &mut v, marks, has_pictures)? {
                    Some(value) => {
                        changed = true;
                        w.string(&e.name);
                        w.signature(&e.sig);
                        write_marked(&mut w, &value);
                    }
                    // Copied as it came: it starts 8-aligned here as there,
                    // so everything in it keeps its alignment.
                    None => w.buf.extend_from_slice(&msg[e.start..e.end]),
                }
            }
            if !changed {
                return Ok(None);
            }
            let len = (w.buf.len() - start) as u32;
            w.buf[len_at..len_at + 4].copy_from_slice(&len.to_le_bytes());
            Ok(Some(w.buf))
        }
    }
}

// --- TRAY ICONS' NAMES --------------------------------------------------------

/// A well-known name a tray icon owns: `org.kde.StatusNotifierItem-<pid>-<n>`
/// or `org.freedesktop.StatusNotifierItem-…` (`crate::zone::TRAY_ITEM_NAMES`).
pub fn is_tray_name(name: &str) -> bool {
    name.starts_with("org.kde.StatusNotifierItem-")
        || name.starts_with("org.freedesktop.StatusNotifierItem-")
}

/// An argument of a body of strings and numbers only ([`plain_args`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    Str(String),
    U32(u32),
}

/// The arguments of a body of strings (`s`) and uint32s (`u`) only, at most
/// four: the bus's name calls and signals (`RequestName` `su`,
/// `NameOwnerChanged` `sss`) and a tray watcher's `RegisterStatusNotifierItem`
/// (`s`). Anything else, or a body that does not read, is an error.
pub fn plain_args(msg: &[u8], h: &Header) -> Result<Vec<Arg>> {
    let sig = h.signature.as_deref().unwrap_or("");
    if sig.is_empty() || sig.len() > 4 || !sig.bytes().all(|c| c == b's' || c == b'u') {
        return Err(WireError("not a body of strings and numbers"));
    }
    let mut r = Reader {
        buf: msg,
        pos: h.body_offset,
        little: h.little,
    };
    sig.bytes()
        .map(|c| {
            if c == b's' {
                r.string().map(Arg::Str)
            } else {
                r.u32().map(Arg::U32)
            }
        })
        .collect()
}

/// The body of [`plain_args`], written back.
pub fn plain_body(args: &[Arg]) -> Vec<u8> {
    let mut w = Writer { buf: Vec::new() };
    for arg in args {
        match arg {
            Arg::Str(s) => w.string(s),
            Arg::U32(v) => w.u32(*v),
        }
    }
    w.buf
}

/// The message of `h` again with `body` (of the same signature) for its
/// body: every field of its header kept, written little-endian.
pub fn with_body(h: &Header, body: &[u8]) -> Vec<u8> {
    let mut fields = Vec::new();
    if let Some(v) = h.path.as_deref() {
        fields.push(Field::Path(v));
    }
    if let Some(v) = h.interface.as_deref() {
        fields.push(Field::Interface(v));
    }
    if let Some(v) = h.member.as_deref() {
        fields.push(Field::Member(v));
    }
    if let Some(v) = h.error_name.as_deref() {
        fields.push(Field::ErrorName(v));
    }
    if let Some(v) = h.reply_serial {
        fields.push(Field::ReplySerial(v));
    }
    if let Some(v) = h.destination.as_deref() {
        fields.push(Field::Destination(v));
    }
    if let Some(v) = h.sender.as_deref() {
        fields.push(Field::Sender(v));
    }
    if let Some(v) = h.signature.as_deref() {
        fields.push(Field::Signature(v));
    }
    if h.unix_fds != 0 {
        fields.push(Field::UnixFds(h.unix_fds));
    }
    message(h.kind, h.flags, h.serial, &fields, body)
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

    /// `org.freedesktop.host.portal.Registry.Register`'s `(s app_id, a{sv}
    /// options)`, with no options.
    pub fn register(app_id: &str) -> Vec<u8> {
        let mut w = Writer { buf: Vec::new() };
        w.string(app_id);
        w.u32(0);
        // An empty array is still padded to its elements' alignment.
        w.align(8);
        w.buf
    }

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
        // The sender's pid (KDE's `sender-pid`): a number of the program's
        // pid namespace, which means somebody else's on the host — a
        // daemon that acted on it would act on another process (stage 3 of
        // the container design). Not in the allow-list: dropped.
        w.align(8);
        w.string("sender-pid");
        w.signature("x");
        w.align(8);
        w.buf.extend_from_slice(&4242i64.to_le_bytes());
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

    /// No hint that carries a pid reaches the host's daemon: a pid of an
    /// instance's namespace names another process there.
    #[test]
    fn no_hint_carries_a_pid() {
        assert!(!NOTIFY_HINTS.iter().any(|h| h.contains("pid")));
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
        let keys = |remember: bool| {
            let body = sanitized_screencast_sources(&msg, &h, remember).unwrap();
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
                if key == "restore_token" {
                    assert_eq!(r.string().unwrap(), "0b2c…");
                } else {
                    r.skip(sig.as_bytes(), 0).unwrap();
                }
                keys.push(key);
            }
            assert_eq!(r.pos, out.len());
            keys
        };
        assert_eq!(
            keys(false),
            ["handle_token", "types", "multiple", "cursor_mode"]
        );
        // Remembered (`screencast yes` under the zone's own id): the choice
        // and its token pass as well — and still nothing nobody has read.
        assert_eq!(
            keys(true),
            [
                "handle_token",
                "persist_mode",
                "types",
                "restore_token",
                "multiple",
                "cursor_mode"
            ]
        );
        // Not read, not passed on: another signature is refused.
        let mut odd = h.clone();
        odd.signature = Some("oa{ss}".to_owned());
        assert!(sanitized_screencast_sources(&msg, &odd, false).is_err());
        assert!(sanitized_screencast_sources(&msg, &odd, true).is_err());
    }

    #[test]
    fn nesting_is_bounded_and_types_are_skipped() {
        assert!(complete_type_len(&[b'a'; 100], 0).is_err());
        assert_eq!(complete_type_len(b"a{sv}x", 0).unwrap(), 5);
        assert_eq!(complete_type_len(b"(ia(s))", 0).unwrap(), 7);
        assert!(complete_type_len(b"(ii", 0).is_err());
    }

    // --- tray icons ------------------------------------------------------

    /// A 2×2 picture, every pixel `px`.
    fn picture(px: [u8; 4]) -> Picture {
        (2, 2, px.repeat(4))
    }

    /// A host's `GetAll`/`Get` on an item.
    fn item_call(member: &str, args: &[&str]) -> (Vec<u8>, Header) {
        let mut w = Writer { buf: Vec::new() };
        for a in args {
            w.string(a);
        }
        let sig = "s".repeat(args.len());
        let msg = message(
            METHOD_CALL,
            0,
            7,
            &[
                Field::Path("/StatusNotifierItem"),
                Field::Interface("org.freedesktop.DBus.Properties"),
                Field::Member(member),
                Field::Signature(&sig),
            ],
            &w.buf,
        );
        let h = parse_header(&msg).unwrap();
        (msg, h)
    }

    fn reply(sig: &str, body: &[u8]) -> (Vec<u8>, Header) {
        let msg = message(
            METHOD_RETURN,
            0,
            9,
            &[
                Field::ReplySerial(7),
                Field::Destination(":1.44"),
                Field::Signature(sig),
            ],
            body,
        );
        let h = parse_header(&msg).unwrap();
        (msg, h)
    }

    /// An item's `GetAll` answer as Electron gives it: an odd-length name
    /// first, so that the entries after it test the alignment.
    fn all_properties(pictures: &[Picture], tip: &str) -> Vec<u8> {
        let mut w = Writer { buf: Vec::new() };
        w.u32(0);
        let len_at = w.buf.len() - 4;
        w.align(8);
        let start = w.buf.len();
        for (key, value) in [
            ("Category", "ApplicationStatus"),
            ("Id", "chrome_status_icon_1"),
        ] {
            w.align(8);
            w.string(key);
            w.signature("s");
            w.string(value);
        }
        w.align(8);
        w.string("IconPixmap");
        w.signature("a(iiay)");
        write_pictures(&mut w, pictures);
        w.align(8);
        w.string("OverlayIconPixmap");
        w.signature("a(iiay)");
        write_pictures(&mut w, &[]);
        w.align(8);
        w.string("ToolTip");
        w.signature("(sa(iiay)ss)");
        w.align(8);
        w.string("");
        write_pictures(&mut w, &[]);
        w.string("Claude");
        w.string(tip);
        let len = (w.buf.len() - start) as u32;
        w.buf[len_at..len_at + 4].copy_from_slice(&len.to_le_bytes());
        w.buf
    }

    /// Read a rewritten `a{sv}` back: each name with its pictures (for
    /// `a(iiay)`) or its tooltip text.
    fn read_back(msg: &[u8]) -> Vec<(String, Vec<Picture>, Option<String>)> {
        let h = parse_header(msg).unwrap();
        let mut r = Reader {
            buf: msg,
            pos: h.body_offset,
            little: true,
        };
        let len = r.u32().unwrap() as usize;
        r.align(8).unwrap();
        let end = r.pos + len;
        let mut out = Vec::new();
        while r.pos < end {
            r.align(8).unwrap();
            let name = r.string().unwrap();
            let sig = r.signature().unwrap();
            match sig.as_str() {
                "a(iiay)" => out.push((name, read_pictures(&mut r).unwrap(), None)),
                "(sa(iiay)ss)" => {
                    r.align(8).unwrap();
                    r.string().unwrap();
                    read_pictures(&mut r).unwrap();
                    r.string().unwrap();
                    out.push((name, Vec::new(), Some(r.string().unwrap())));
                }
                other => {
                    r.skip(other.as_bytes(), 1).unwrap();
                    out.push((name, Vec::new(), None));
                }
            }
        }
        assert_eq!(r.pos, msg.len());
        out
    }

    fn mark_first_pixel(_: i32, _: i32, px: &mut [u8]) {
        px[..4].copy_from_slice(&[0xff, 1, 2, 3]);
    }

    fn zone_line(own: &str) -> String {
        format!("{own}|zone · box")
    }

    fn marks(overlay: Option<Picture>) -> ItemMarks<'static> {
        ItemMarks {
            picture: &mark_first_pixel,
            overlay,
            tooltip: &zone_line,
        }
    }

    /// A body of strings and numbers read, written back, and put in the
    /// message with every field of its header; a big-endian one read as
    /// well; any other body refused.
    #[test]
    fn a_plain_body_is_read_and_written_back() {
        let args = vec![
            Arg::Str("org.kde.StatusNotifierItem-2-1".into()),
            Arg::U32(4),
        ];
        let msg = message(
            METHOD_CALL,
            0,
            9,
            &[
                Field::Path("/org/freedesktop/DBus"),
                Field::Interface("org.freedesktop.DBus"),
                Field::Member("RequestName"),
                Field::Destination("org.freedesktop.DBus"),
                Field::Sender(":1.3"),
                Field::Signature("su"),
            ],
            &plain_body(&args),
        );
        let h = parse_header(&msg).unwrap();
        assert_eq!(plain_args(&msg, &h).unwrap(), args);
        let longer = vec![
            Arg::Str("org.kde.StatusNotifierItem-2-1-c1_77".into()),
            Arg::U32(4),
        ];
        let again = with_body(&h, &plain_body(&longer));
        let h2 = parse_header(&again).unwrap();
        assert_eq!(plain_args(&again, &h2).unwrap(), longer);
        assert_eq!(
            (
                h2.serial,
                h2.member.as_deref(),
                h2.sender.as_deref(),
                h2.destination.as_deref()
            ),
            (
                9,
                Some("RequestName"),
                Some(":1.3"),
                Some("org.freedesktop.DBus")
            )
        );
        assert_eq!(message_len(&again).unwrap(), Some(again.len()));
        // Big-endian: the same arguments.
        let mut big = vec![b'B', METHOD_CALL, 0, 1];
        let body_be = {
            let mut b = Vec::new();
            b.extend_from_slice(&3u32.to_be_bytes());
            b.extend_from_slice(b"abc\0");
            b.extend_from_slice(&7u32.to_be_bytes());
            b
        };
        big.extend_from_slice(&(body_be.len() as u32).to_be_bytes());
        big.extend_from_slice(&5u32.to_be_bytes());
        let mut fields = Vec::new();
        fields.extend_from_slice(&[8, 1, b'g', 0, 2, b's', b'u', 0]);
        big.extend_from_slice(&(fields.len() as u32).to_be_bytes());
        big.extend_from_slice(&fields);
        while big.len() % 8 != 0 {
            big.push(0);
        }
        big.extend_from_slice(&body_be);
        let h = parse_header(&big).unwrap();
        assert_eq!(
            plain_args(&big, &h).unwrap(),
            vec![Arg::Str("abc".into()), Arg::U32(7)]
        );
        // Not strings and numbers only.
        let h = Header {
            signature: Some("a{sv}".into()),
            ..h
        };
        assert!(plain_args(&big, &h).is_err());
        assert!(is_tray_name("org.freedesktop.StatusNotifierItem-5-1"));
        assert!(!is_tray_name("org.kde.StatusNotifierWatcher"));
    }

    #[test]
    fn a_hosts_question_to_an_icon_is_known() {
        let (msg, h) = item_call("GetAll", &["org.kde.StatusNotifierItem"]);
        assert_eq!(item_properties_call(&msg, &h), Some(ItemAsk::All));
        let (msg, h) = item_call("Get", &["org.freedesktop.StatusNotifierItem", "IconPixmap"]);
        assert_eq!(
            item_properties_call(&msg, &h),
            Some(ItemAsk::One("IconPixmap".into()))
        );
        let (msg, h) = item_call("GetAll", &["org.mpris.MediaPlayer2"]);
        assert_eq!(item_properties_call(&msg, &h), None);
        let (msg, h) = item_call("Set", &["org.kde.StatusNotifierItem", "x"]);
        assert_eq!(item_properties_call(&msg, &h), None);
    }

    #[test]
    fn every_picture_of_an_icon_is_marked_and_the_rest_kept() {
        let body = all_properties(
            &[picture([0xff, 9, 9, 9]), picture([0x80, 7, 7, 7])],
            "3 new",
        );
        let (msg, h) = reply("a{sv}", &body);
        let new = marked_item_reply(&msg, &h, &ItemAsk::All, &marks(Some(picture([1, 1, 1, 1]))))
            .unwrap()
            .expect("marked");
        let out = message(
            METHOD_RETURN,
            0,
            9,
            &[Field::ReplySerial(7), Field::Signature("a{sv}")],
            &new,
        );
        let props = read_back(&out);
        let names: Vec<&str> = props.iter().map(|(n, _, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "Category",
                "Id",
                "IconPixmap",
                "OverlayIconPixmap",
                "ToolTip"
            ]
        );
        let icon = &props[2].1;
        assert_eq!(icon.len(), 2);
        for (w, h, px) in icon {
            assert_eq!((*w, *h), (2, 2));
            assert_eq!(&px[..4], &[0xff, 1, 2, 3], "the mark");
            assert_eq!(px.len(), 16);
        }
        assert_eq!(
            &icon[1].2[4..8],
            &[0x80, 7, 7, 7],
            "the rest of the picture"
        );
        // Pictures of its own: no overlay made for it.
        assert!(props[3].1.is_empty());
        assert_eq!(props[4].2.as_deref(), Some("3 new|zone · box"));
    }

    #[test]
    fn an_icon_by_name_gets_the_overlay() {
        let body = all_properties(&[], "");
        let (msg, h) = reply("a{sv}", &body);
        let overlay = picture([0xff, 5, 5, 5]);
        let new = marked_item_reply(&msg, &h, &ItemAsk::All, &marks(Some(overlay.clone())))
            .unwrap()
            .expect("marked");
        let out = message(METHOD_RETURN, 0, 9, &[Field::Signature("a{sv}")], &new);
        let props = read_back(&out);
        assert!(props[2].1.is_empty(), "no pictures made up");
        assert_eq!(props[3].1, vec![overlay]);
    }

    #[test]
    fn one_property_is_marked_as_a_variant() {
        let mut w = Writer { buf: Vec::new() };
        w.signature("a(iiay)");
        write_pictures(&mut w, &[picture([0xff, 9, 9, 9])]);
        let (msg, h) = reply("v", &w.buf);
        let ask = ItemAsk::One("IconPixmap".into());
        let new = marked_item_reply(&msg, &h, &ask, &marks(None))
            .unwrap()
            .expect("marked");
        let out = message(METHOD_RETURN, 0, 9, &[Field::Signature("v")], &new);
        let h = parse_header(&out).unwrap();
        let mut r = Reader {
            buf: &out,
            pos: h.body_offset,
            little: true,
        };
        assert_eq!(r.signature().unwrap(), "a(iiay)");
        let pictures = read_pictures(&mut r).unwrap();
        assert_eq!(&pictures[0].2[..4], &[0xff, 1, 2, 3]);
        assert_eq!(r.pos, out.len());
        // Another property, or another answer, passes as it is.
        let ask = ItemAsk::One("Title".into());
        let mut w = Writer { buf: Vec::new() };
        w.signature("s");
        w.string("Claude");
        let (msg, h) = reply("v", &w.buf);
        assert_eq!(
            marked_item_reply(&msg, &h, &ask, &marks(None)).unwrap(),
            None
        );
    }

    #[test]
    fn a_big_endian_icon_answer_is_refused_not_passed() {
        let body = all_properties(&[picture([0xff, 9, 9, 9])], "x");
        let (mut msg, _) = reply("a{sv}", &body);
        // Only the endianness byte: the parse of the header reads it first.
        msg[0] = b'B';
        let h = Header {
            little: false,
            ..parse_header(&reply("a{sv}", &body).0).unwrap()
        };
        assert!(marked_item_reply(&msg, &h, &ItemAsk::All, &marks(None)).is_err());
    }

    #[test]
    fn a_lying_icon_answer_is_an_error_not_a_panic() {
        let mut body = all_properties(&[picture([0xff, 9, 9, 9])], "x");
        // The array says it is longer than the message.
        body[0] = 0xff;
        body[1] = 0xff;
        let (msg, h) = reply("a{sv}", &body);
        assert!(marked_item_reply(&msg, &h, &ItemAsk::All, &marks(None)).is_err());
        // A picture that says it has more bytes than there are.
        let mut w = Writer { buf: Vec::new() };
        w.signature("a(iiay)");
        w.u32(20);
        w.align(8);
        w.u32(2);
        w.u32(2);
        w.u32(4096);
        let (msg, h) = reply("v", &w.buf);
        let ask = ItemAsk::One("IconPixmap".into());
        assert!(marked_item_reply(&msg, &h, &ask, &marks(None)).is_err());
    }
}
