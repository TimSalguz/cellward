//! An entry as it lies on disk — the same bytes in the active log and in a
//! sealed segment, so sealing and merging copy them without decrypting:
//!
//! ```text
//! u64 id | i64 copied-at | u64 dedup hash
//! u32 head length | head: nonce(24) ‖ AEAD(head plain text) ‖ tag(16)
//! u64 body length | body: nonce ‖ AEAD(contents) ‖ tag   (0: inline)
//! ```
//!
//! The head's plain text: a flags byte (bit 0: the contents are inline,
//! after the preview — an entry up to [`INLINE`] bytes pays for one AEAD,
//! not two), the types (varint count; per type its name and its size), the
//! preview. The body holds the contents of every type, one after another,
//! in the order of the types. The id is the AEAD's associated data (with
//! `h` or `b` before it): a sealed head or body moved to another id, or the
//! head swapped with the body, no longer opens.

use super::codec::{put_bytes, put_i64, put_u32, put_u64, put_varint, Reader};
use super::crypto::Keys;
use super::{Content, Error};

/// Contents up to this many bytes are sealed with the head.
pub(super) const INLINE: usize = 4096;

pub(super) struct Blob<'a> {
    pub id: u64,
    pub copied_at: i64,
    pub dedup: u64,
    pub head: &'a [u8],
    pub body: &'a [u8],
}

pub(super) fn parse(b: &[u8]) -> Option<Blob<'_>> {
    let mut r = Reader::new(b);
    let id = r.u64()?;
    let copied_at = r.i64()?;
    let dedup = r.u64()?;
    let hl = r.u32()? as usize;
    let head = r.take(hl)?;
    let bl = usize::try_from(r.u64()?).ok()?;
    let body = r.take(bl)?;
    r.done().then_some(Blob {
        id,
        copied_at,
        dedup,
        head,
        body,
    })
}

fn aad(part: u8, id: u64) -> [u8; 9] {
    let mut a = [0u8; 9];
    a[0] = part;
    a[1..].copy_from_slice(&id.to_le_bytes());
    a
}

/// Seal an entry's contents and preview into its blob.
pub(super) fn seal(
    keys: &Keys,
    id: u64,
    copied_at: i64,
    dedup: u64,
    contents: &[Content],
    preview: &str,
) -> Result<Vec<u8>, Error> {
    let total: usize = contents.iter().map(|c| c.data.len()).sum();
    let inline = total <= INLINE;
    let mut head = Vec::with_capacity(64 + preview.len() + if inline { total } else { 0 });
    head.push(u8::from(inline));
    put_varint(&mut head, contents.len() as u64);
    for c in contents {
        put_bytes(&mut head, c.mime.as_bytes());
        put_varint(&mut head, c.data.len() as u64);
    }
    put_bytes(&mut head, preview.as_bytes());
    let mut body_plain = Vec::new();
    {
        let dst = if inline { &mut head } else { &mut body_plain };
        dst.reserve(total);
        for c in contents {
            dst.extend_from_slice(&c.data);
        }
    }
    let head = keys.seal(&aad(b'h', id), &head)?;
    let body = if inline {
        Vec::new()
    } else {
        keys.seal(&aad(b'b', id), &body_plain)?
    };
    let mut out = Vec::with_capacity(40 + head.len() + body.len());
    put_u64(&mut out, id);
    put_i64(&mut out, copied_at);
    put_u64(&mut out, dedup);
    put_u32(&mut out, head.len() as u32);
    out.extend_from_slice(&head);
    put_u64(&mut out, body.len() as u64);
    out.extend_from_slice(&body);
    Ok(out)
}

/// An entry's head, opened.
pub(super) struct Head {
    pub types: Vec<(String, u64)>,
    pub preview: String,
    /// The contents, when they were sealed with the head.
    pub inline: Option<Vec<u8>>,
}

pub(super) fn open_head(keys: &Keys, blob: &Blob) -> Result<Head, Error> {
    let plain = keys
        .open(&aad(b'h', blob.id), blob.head)
        .ok_or(Error::Undecryptable(blob.id))?;
    let corrupt = || Error::Corrupt(format!("запись {}: заголовок", blob.id));
    let mut r = Reader::new(&plain);
    let flags = r.u8().ok_or_else(corrupt)?;
    let n = r.varint().ok_or_else(corrupt)?;
    let mut types = Vec::new();
    for _ in 0..n {
        let mime = r.bytes().ok_or_else(corrupt)?;
        let size = r.varint().ok_or_else(corrupt)?;
        types.push((String::from_utf8_lossy(mime).into_owned(), size));
    }
    let preview = String::from_utf8_lossy(r.bytes().ok_or_else(corrupt)?).into_owned();
    let inline = if flags & 1 != 0 {
        Some(plain[r.at..].to_vec())
    } else {
        None
    };
    Ok(Head {
        types,
        preview,
        inline,
    })
}

/// The contents of every type: from the head when inline, else the body
/// opened.
pub(super) fn open_contents(keys: &Keys, blob: &Blob, head: Head) -> Result<Vec<Content>, Error> {
    let all = match head.inline {
        Some(b) => b,
        None => keys
            .open(&aad(b'b', blob.id), blob.body)
            .ok_or(Error::Undecryptable(blob.id))?,
    };
    let mut out = Vec::with_capacity(head.types.len());
    let mut at = 0usize;
    for (mime, size) in head.types {
        let end = usize::try_from(size)
            .ok()
            .and_then(|s| at.checked_add(s))
            .filter(|&e| e <= all.len())
            .ok_or_else(|| Error::Corrupt(format!("запись {}: размеры", blob.id)))?;
        out.push(Content {
            mime,
            data: all[at..end].to_vec(),
        });
        at = end;
    }
    Ok(out)
}
