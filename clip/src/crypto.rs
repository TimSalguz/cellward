//! The history's key, and the three keys derived from it: the AEAD key
//! that seals contents and previews, the key of the index's terms, the key
//! of the dedup hashes. One secret on disk; a term hash and a dedup hash are
//! never comparable with each other or with another history's.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::Error;

type HmacSha256 = Hmac<Sha256>;

/// Bytes of a nonce (XChaCha20: 192 bits, so a random one never repeats in
/// practice) and of a tag.
pub(super) const NONCE: usize = 24;
pub(super) const TAG: usize = 16;

/// A history's 32-byte secret. Zeroed when dropped; never printed.
pub struct Key([u8; 32]);

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(..)")
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        for b in &mut self.0 {
            // SAFETY: a byte of our own array; volatile so the zeroing is
            // not optimized away as a dead store.
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
}

impl Key {
    /// A key from bytes the caller holds (a TPM-unsealed one, a test's).
    pub fn from_bytes(bytes: [u8; 32]) -> Key {
        Key(bytes)
    }

    /// A fresh random key.
    pub fn generate() -> io::Result<Key> {
        let mut k = [0u8; 32];
        random(&mut k)?;
        Ok(Key(k))
    }

    /// The key in the file at `path`, made (32 random bytes, mode 0600) when
    /// there is none. The file is never reached through a link: it is
    /// opened with `O_NOFOLLOW` and created with `O_CREAT|O_EXCL` (which
    /// fails on any name that exists, a dangling link included), and a
    /// file found there must be a regular file of ours, 32 bytes, readable
    /// by nobody else — a key someone else could have read or planted is
    /// refused, not used. `O_NONBLOCK` keeps a FIFO put in its place from
    /// hanging the open.
    pub fn load_or_create(path: &Path) -> Result<Key, Error> {
        loop {
            match OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
                .open(path)
            {
                Ok(f) => return read_key(f, path),
                Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
                    return Err(Error::KeyFile(format!(
                        "{}: это ссылка, а не файл ключа",
                        path.display()
                    )));
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(Error::Io(e)),
            }
            let mut f = match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
            {
                Ok(f) => f,
                // Made by someone else between the two opens: read that one
                // (and check it like any other).
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(Error::Io(e)),
            };
            let key = Key::generate()?;
            f.write_all(&key.0)?;
            f.sync_all()?;
            if let Some(dir) = path.parent() {
                if let Ok(d) = File::open(if dir.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    dir
                }) {
                    let _ = d.sync_all();
                }
            }
            return Ok(key);
        }
    }

    pub(super) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn read_key(mut f: File, path: &Path) -> Result<Key, Error> {
    let meta = f.metadata()?;
    let bad = |why: &str| Err(Error::KeyFile(format!("{}: {why}", path.display())));
    if !meta.file_type().is_file() {
        return bad("не обычный файл");
    }
    // SAFETY: geteuid cannot fail.
    if meta.uid() != unsafe { libc::geteuid() } {
        return bad("файл чужого пользователя");
    }
    if meta.mode() & 0o077 != 0 {
        return bad("доступен не только владельцу (нужно 0600)");
    }
    if meta.len() != 32 {
        return bad("не 32 байта");
    }
    let mut k = [0u8; 32];
    f.read_exact(&mut k)?;
    Ok(Key(k))
}

/// `getrandom(2)` into the whole buffer.
pub(super) fn random(buf: &mut [u8]) -> io::Result<()> {
    let mut at = 0;
    while at < buf.len() {
        let rest = &mut buf[at..];
        // SAFETY: the rest of the buffer, alive for the call.
        let n = unsafe { libc::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        at += n.unsigned_abs();
    }
    Ok(())
}

/// The keys a history works with, derived from its [`Key`] by
/// HMAC-SHA256(key, label).
pub(super) struct Keys {
    aead: XChaCha20Poly1305,
    /// Initialized MACs, cloned per hash: the key schedule is paid once.
    term: HmacSha256,
    dedup: HmacSha256,
}

/// What a term hash is of: the two kinds never collide by construction.
pub(super) const TERM_TRIGRAM: u8 = 0;
pub(super) const TERM_TYPE: u8 = 1;

impl Keys {
    pub fn derive(key: &Key) -> Keys {
        let sub = |label: &[u8]| -> [u8; 32] {
            let mut m = <HmacSha256 as Mac>::new_from_slice(key.bytes()).expect("any key length");
            m.update(b"cellward-clipstore/v1/");
            m.update(label);
            m.finalize().into_bytes().into()
        };
        let mut a = sub(b"aead");
        let mut t = sub(b"term");
        let mut d = sub(b"dedup");
        let keys = Keys {
            aead: XChaCha20Poly1305::new_from_slice(&a).expect("32 bytes"),
            term: <HmacSha256 as Mac>::new_from_slice(&t).expect("any key length"),
            dedup: <HmacSha256 as Mac>::new_from_slice(&d).expect("any key length"),
        };
        a.fill(0);
        t.fill(0);
        d.fill(0);
        keys
    }

    /// The index term of a trigram or a type: HMAC-SHA256 truncated to 64
    /// bits. A false match costs one decryption that then fails the exact
    /// check — never a wrong result.
    pub fn term(&self, kind: u8, bytes: &[u8]) -> u64 {
        let mut m = self.term.clone();
        m.update(&[kind]);
        m.update(bytes);
        let out = m.finalize().into_bytes();
        u64::from_be_bytes(out[..8].try_into().expect("32 bytes"))
    }

    /// The dedup hash of a canonical encoding of contents. 64 bits: a match
    /// is confirmed by decrypting and comparing before it counts.
    pub fn dedup(&self, canonical: &[u8]) -> u64 {
        let mut m = self.dedup.clone();
        m.update(canonical);
        let out = m.finalize().into_bytes();
        u64::from_be_bytes(out[..8].try_into().expect("32 bytes"))
    }

    /// `nonce || ciphertext || tag`, the nonce fresh from the kernel.
    pub fn seal(&self, aad: &[u8], plain: &[u8]) -> io::Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE];
        random(&mut nonce)?;
        let ct = self
            .aead
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plain, aad })
            .map_err(|_| io::Error::other("aead"))?;
        let mut out = Vec::with_capacity(NONCE + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// The plain text of [`Keys::seal`]'s output, or `None`: another key,
    /// another `aad` (a record moved to another id), or altered bytes.
    pub fn open(&self, aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < NONCE + TAG {
            return None;
        }
        let (nonce, ct) = sealed.split_at(NONCE);
        self.aead
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
            .ok()
    }
}
