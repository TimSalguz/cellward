//! The bytes under the store: little-endian integers, LEB128 varints, and a
//! reader that never panics on what it reads — a sealed segment is mapped
//! from disk, and a corrupt one must give an error, not an out-of-bounds
//! index.

pub(super) fn put_u32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}

pub(super) fn put_u64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}

pub(super) fn put_i64(v: &mut Vec<u8>, x: i64) {
    v.extend_from_slice(&x.to_le_bytes());
}

pub(super) fn put_varint(v: &mut Vec<u8>, mut x: u64) {
    while x >= 0x80 {
        v.push(x as u8 | 0x80);
        x >>= 7;
    }
    v.push(x as u8);
}

/// A varint, then the bytes.
pub(super) fn put_bytes(v: &mut Vec<u8>, b: &[u8]) {
    put_varint(v, b.len() as u64);
    v.extend_from_slice(b);
}

pub(super) fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

pub(super) fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        b.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

/// A cursor over bytes; every read is checked and `None` past the end.
pub(super) struct Reader<'a> {
    pub b: &'a [u8],
    pub at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Reader { b, at: 0 }
    }

    pub fn done(&self) -> bool {
        self.at >= self.b.len()
    }

    pub fn u8(&mut self) -> Option<u8> {
        let x = *self.b.get(self.at)?;
        self.at += 1;
        Some(x)
    }

    pub fn u32(&mut self) -> Option<u32> {
        let x = u32_at(self.b, self.at)?;
        self.at += 4;
        Some(x)
    }

    pub fn u64(&mut self) -> Option<u64> {
        let x = u64_at(self.b, self.at)?;
        self.at += 8;
        Some(x)
    }

    pub fn i64(&mut self) -> Option<i64> {
        self.u64().map(|x| x as i64)
    }

    pub fn varint(&mut self) -> Option<u64> {
        let mut x = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.u8()?;
            x |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(x);
            }
        }
        None
    }

    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(s)
    }

    /// A varint length, then that many bytes.
    pub fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = usize::try_from(self.varint()?).ok()?;
        self.take(n)
    }
}

/// A section of fixed-width records, each starting with a sort key; read
/// in place from the map.
#[derive(Clone, Copy)]
pub(super) struct Table<'a> {
    pub b: &'a [u8],
    pub width: usize,
}

impl<'a> Table<'a> {
    pub fn len(&self) -> usize {
        self.b.len() / self.width
    }

    pub fn row(&self, i: usize) -> &'a [u8] {
        &self.b[i * self.width..(i + 1) * self.width]
    }

    /// The u64 at `off` of row `i` (in bounds: a table's length is checked
    /// to be a multiple of its width when its segment is opened).
    pub fn u64(&self, i: usize, off: usize) -> u64 {
        u64::from_le_bytes(self.row(i)[off..off + 8].try_into().unwrap_or([0; 8]))
    }

    pub fn i64(&self, i: usize, off: usize) -> i64 {
        self.u64(i, off) as i64
    }

    /// The first row for which `pred` is false, `pred` being true for a
    /// prefix of the rows.
    pub fn partition_point(&self, mut pred: impl FnMut(usize) -> bool) -> usize {
        let (mut lo, mut hi) = (0, self.len());
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if pred(mid) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }
}
