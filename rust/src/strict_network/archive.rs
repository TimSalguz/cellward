//! Private, append-only fixed records. Cache eviction never erases ownership.
//! Checksums detect torn/corrupt records; they are not authentication. Access
//! control is the covered instance state directory and its private file.
use super::Mapping;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};

const ROW: usize = 512;
pub(super) struct Archive {
    file: File,
    session: u128,
    count: AtomicU32,
}

impl Archive {
    pub fn create(dir: &Path, session: u128) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(dir.join(format!("strict-launches.{session:032x}")))?;
        Ok(Self {
            file,
            session,
            count: AtomicU32::new(0),
        })
    }

    pub fn count(&self) -> u32 {
        self.count.load(Ordering::Acquire)
    }

    pub fn append(&self, mapping: &Mapping) -> io::Result<()> {
        let expected = self.count().checked_add(1).ok_or_else(corrupt)?;
        if mapping.token.mark() != expected {
            return Err(corrupt());
        }
        let bytes = encode(mapping, self.session)?;
        self.file
            .write_all_at(&bytes, u64::from(expected - 1) * ROW as u64)?;
        self.file.sync_data()?;
        // Publish only the complete record, before its kernel mapping/exec.
        self.count.store(expected, Ordering::Release);
        Ok(())
    }

    pub fn read(&self, token: u32) -> io::Result<Option<Mapping>> {
        if token == 0 || token > self.count() {
            return Ok(None);
        }
        let mut row = [0; ROW];
        self.file
            .read_exact_at(&mut row, u64::from(token - 1) * ROW as u64)?;
        decode(&row, self.session, token).map(Some)
    }

    pub fn contains_cgroup(&self, id: u64) -> io::Result<bool> {
        // Sequential, bounded-memory archive scan at launch registration,
        // NEVER on the packet hot path. Token lookups are direct offsets.
        let count = self.count();
        let mut buffer = [0u8; ROW * 128];
        let mut at = 0u32;
        while at < count {
            let rows = (count - at).min(128) as usize;
            self.file
                .read_exact_at(&mut buffer[..rows * ROW], u64::from(at) * ROW as u64)?;
            for (i, row) in buffer[..rows * ROW].chunks_exact(ROW).enumerate() {
                let mapping = decode(row.try_into().unwrap(), self.session, at + i as u32 + 1)?;
                if mapping.cgroup == id {
                    return Ok(true);
                }
            }
            at += rows as u32;
        }
        Ok(false)
    }
}

fn corrupt() -> io::Error {
    io::Error::other("invalid strict launch archive record")
}

fn checksum(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325u64, |hash, b| {
        (hash ^ u64::from(*b)).wrapping_mul(0x100000001b3)
    })
}

fn encode(m: &Mapping, session: u128) -> io::Result<[u8; ROW]> {
    if m.program.is_empty()
        || m.program.len() > 255
        || m.leaf.len() > 128
        || m.epoch == 0
        || m.cgroup == 0
        || m.level == 0
        || m.generation == 0
        || crate::epoch::leaf_of(&m.leaf).is_none()
    {
        return Err(corrupt());
    }
    let mut row = [0u8; ROW];
    row[..8].copy_from_slice(b"cwlnch01");
    row[8..24].copy_from_slice(&session.to_le_bytes());
    row[24..28].copy_from_slice(&m.token.mark().to_le_bytes());
    row[28..36].copy_from_slice(&m.epoch.to_le_bytes());
    row[36..44].copy_from_slice(&m.cgroup.to_le_bytes());
    row[44..60].copy_from_slice(&m.generation.to_le_bytes());
    let (pid, start) = m.panel.unwrap_or((0, 0));
    row[60..64].copy_from_slice(&pid.to_le_bytes());
    row[64..72].copy_from_slice(&start.to_le_bytes());
    row[72] = m.level;
    row[74..76].copy_from_slice(&(m.program.len() as u16).to_le_bytes());
    row[76..78].copy_from_slice(&(m.leaf.len() as u16).to_le_bytes());
    row[78..78 + m.program.len()].copy_from_slice(m.program.as_bytes());
    row[333..333 + m.leaf.len()].copy_from_slice(m.leaf.as_bytes());
    let hash = checksum(&row[..504]);
    row[504..].copy_from_slice(&hash.to_le_bytes());
    Ok(row)
}

fn decode(row: &[u8; ROW], session: u128, token: u32) -> io::Result<Mapping> {
    if row[..8] != *b"cwlnch01"
        || row[8..24] != session.to_le_bytes()
        || row[24..28] != token.to_le_bytes()
        || row[504..] != checksum(&row[..504]).to_le_bytes()
    {
        return Err(corrupt());
    }
    let program_len = usize::from(u16::from_le_bytes(row[74..76].try_into().unwrap()));
    let leaf_len = usize::from(u16::from_le_bytes(row[76..78].try_into().unwrap()));
    if program_len == 0 || program_len > 255 || leaf_len > 128 {
        return Err(corrupt());
    }
    let panel = (
        i32::from_le_bytes(row[60..64].try_into().unwrap()),
        u64::from_le_bytes(row[64..72].try_into().unwrap()),
    );
    let mapping = Mapping {
        path: String::new(),
        token: crate::netqueue::Token::archived(token).ok_or_else(corrupt)?,
        epoch: u64::from_le_bytes(row[28..36].try_into().unwrap()),
        cgroup: u64::from_le_bytes(row[36..44].try_into().unwrap()),
        generation: u128::from_le_bytes(row[44..60].try_into().unwrap()),
        level: row[72],
        panel: match panel {
            (0, 0) => None,
            (pid, start) if pid > 0 && start > 0 => Some((pid, start)),
            _ => return Err(corrupt()),
        },
        program: std::str::from_utf8(&row[78..78 + program_len])
            .map_err(|_| corrupt())?
            .to_owned(),
        leaf: std::str::from_utf8(&row[333..333 + leaf_len])
            .map_err(|_| corrupt())?
            .to_owned(),
    };
    // One canonical encoding also validates bounds, reserved bytes and keys.
    if encode(&mapping, session)? != *row {
        return Err(corrupt());
    }
    Ok(mapping)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn mapping() -> Mapping {
        Mapping {
            path: "/unit/e1/l42-7".into(),
            token: crate::netqueue::Token::archived(1).unwrap(),
            epoch: 1,
            cgroup: 0x1_0000_0001,
            generation: 55,
            level: 7,
            panel: Some((42, 7)),
            program: "firefox".into(),
            leaf: "l42-7".into(),
        }
    }
    #[test]
    fn record_keeps_full_cgroup_id_and_rejects_corruption_and_foreign_identity() {
        let row = encode(&mapping(), 77).unwrap();
        assert_eq!(decode(&row, 77, 1).unwrap().cgroup, 0x1_0000_0001);
        assert!(decode(&row, 78, 1).is_err());
        assert!(decode(&row, 77, 2).is_err());
        for i in 0..ROW {
            let mut damaged = row;
            damaged[i] ^= 1;
            assert!(decode(&damaged, 77, 1).is_err(), "byte {i}");
        }
    }
    #[test]
    fn archive_is_private_append_only_and_supports_direct_old_token_lookup() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("cw-strict-archive-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let archive = Archive::create(&dir, 77).unwrap();
        assert_eq!(
            archive.file.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(Archive::create(&dir, 77).is_err());
        archive.append(&mapping()).unwrap();
        assert!(archive.append(&mapping()).is_err());
        assert_eq!(archive.read(1).unwrap().unwrap().program, "firefox");
        assert!(archive.read(2).unwrap().is_none());
        assert!(archive.contains_cgroup(0x1_0000_0001).unwrap());
        assert!(!archive.contains_cgroup(0x2_0000_0001).unwrap());
        archive.file.write_all_at(&[0xff], 78).unwrap();
        assert!(archive.read(1).is_err());
        drop(archive);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
