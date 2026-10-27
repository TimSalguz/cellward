//! Host-only history storage, inside the state hidden by Cellward's mount
//! namespaces. Encryption alone is not an access boundary when the key and
//! ciphertext are both in a real-home container's readable home.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub const PROTECTED_STATE: &str = ".local/state/vpn-zones";
pub const STORE: &str = ".clipboard";

/// The lock stays held for the daemon's lifetime. A second updated daemon
/// must not migrate, open the key, or replace the first daemon's socket.
pub struct Prepared {
    pub dir: PathBuf,
    _lock: File,
}

impl Drop for Prepared {
    fn drop(&mut self) {
        // A concurrently spawned child can briefly inherit the same open file
        // description before CLOEXEC. End this daemon's lock explicitly;
        // merely closing its fd would keep that lock until the child execs.
        // SAFETY: the guard still owns its open regular lock file.
        unsafe {
            libc::flock(self._lock.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

pub fn directory(home: &Path) -> PathBuf {
    home.join(PROTECTED_STATE).join(STORE)
}

pub fn legacy_directory(home: &Path, state_home: Option<&Path>) -> PathBuf {
    state_home
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| home.join(".local/state"))
        .join("cellward-clip")
}

fn owned_directory(path: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no arguments and cannot fail.
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{}: need an owned directory, not a symlink or writable by others",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Prepare only on the host. The canonical protected state path is
/// intentional: arbitrary XDG_STATE_HOME locations are not covered by the
/// container mount policy. The old XDG path is used only for migration.
pub fn prepare(home: &Path, legacy: &Path) -> io::Result<Prepared> {
    let home = home.canonicalize()?;
    let state = home.join(PROTECTED_STATE);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&state)?;
    owned_directory(&state)?;
    if state.canonicalize()? != state {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "clipboard state must not escape the container-masked path through symlinks",
        ));
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(state.join(".clipboard.lock"))?;
    let meta = lock.metadata()?;
    // SAFETY: geteuid has no arguments and cannot fail.
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe clipboard lock",
        ));
    }
    // SAFETY: flock operates on our open regular file, without pointers.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "another clipboard daemon holds the store",
        ));
    }
    let dir = state.join(STORE);
    let old = match fs::symlink_metadata(legacy) {
        Ok(_) => true,
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(e) => return Err(e),
    };
    let new = match fs::symlink_metadata(&dir) {
        Ok(_) => true,
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(e) => return Err(e),
    };
    match (old, new) {
        (true, true) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "both old and protected clipboard stores exist; no automatic merge or overwrite",
            ))
        }
        (true, false) => {
            owned_directory(legacy)?;
            let from = std::ffi::CString::new(legacy.as_os_str().as_bytes())?;
            let to = std::ffi::CString::new(dir.as_os_str().as_bytes())?;
            // SAFETY: both NUL-terminated paths outlive renameat2. NOREPLACE
            // is atomic: a destination created after the check is never lost.
            if unsafe {
                libc::renameat2(
                    libc::AT_FDCWD,
                    from.as_ptr(),
                    libc::AT_FDCWD,
                    to.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            // No cross-filesystem copy fallback: leaving a readable copy of
            // the key behind would defeat this migration's purpose.
            File::open(&state)?.sync_all()?;
            if let Some(parent) = legacy.parent() {
                File::open(parent)?.sync_all()?;
            }
        }
        (false, false) => fs::DirBuilder::new().mode(0o700).create(&dir)?,
        (false, true) => {}
    }
    owned_directory(&dir)?;
    // The migrated top-level directory may have been 0755; descendants
    // cannot be reached by another host user through this 0700 parent.
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    Ok(Prepared { dir, _lock: lock })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let mut random = [0; 16];
            crate::crypto::random(&mut random).unwrap();
            let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
            let path = std::env::temp_dir().join(format!("cellward-clip-storage-{name}"));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn ending_store_ownership_unlocks_even_with_a_transient_inherited_description() {
        let t = Temp::new();
        let old = legacy_directory(&t.0, None);
        let prepared = prepare(&t.0, &old).unwrap();
        // Dup and a fork inheritance hold the same flock file description.
        let inherited = prepared._lock.try_clone().unwrap();
        drop(prepared);
        let restarted = prepare(&t.0, &old)
            .expect("transient child descriptor must not retain ended ownership");
        drop(inherited);
        assert!(
            prepare(&t.0, &old).is_err(),
            "the new daemon still owns its lock"
        );
        drop(restarted);
        assert!(prepare(&t.0, &old).is_ok());
    }

    #[test]
    fn migrates_whole_store_without_copying_or_replacing_key() {
        let t = Temp::new();
        let old = legacy_directory(&t.0, None);
        fs::create_dir_all(old.join(".secrets/work")).unwrap();
        fs::write(old.join("key"), b"test key, not a real secret").unwrap();
        fs::write(old.join(".secrets/work/manifest"), b"encrypted fixture").unwrap();
        let inode = fs::metadata(old.join("key")).unwrap().ino();
        let p = prepare(&t.0, &old).unwrap();
        assert_eq!(p.dir, directory(&t.0));
        assert!(!old.exists());
        assert_eq!(fs::metadata(p.dir.join("key")).unwrap().ino(), inode);
        assert_eq!(
            fs::read(p.dir.join(".secrets/work/manifest")).unwrap(),
            b"encrypted fixture"
        );
        assert_eq!(fs::metadata(&p.dir).unwrap().mode() & 0o777, 0o700);
        assert!(
            prepare(&t.0, &old).is_err(),
            "second daemon must not open the store"
        );
        drop(p);
        assert!(
            prepare(&t.0, &old).is_ok(),
            "normal restart after migration"
        );
    }

    #[test]
    fn refuses_conflicting_stores_without_touching_either() {
        let t = Temp::new();
        let old = legacy_directory(&t.0, None);
        fs::create_dir_all(&old).unwrap();
        fs::write(old.join("key"), b"old").unwrap();
        fs::create_dir_all(directory(&t.0)).unwrap();
        fs::write(directory(&t.0).join("key"), b"new").unwrap();
        assert_eq!(
            prepare(&t.0, &old).err().unwrap().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(old.join("key")).unwrap(), b"old");
        assert_eq!(fs::read(directory(&t.0).join("key")).unwrap(), b"new");
    }

    #[test]
    fn rejects_symlinks_and_other_writable_protected_state() {
        let t = Temp::new();
        let old = legacy_directory(&t.0, None);
        fs::create_dir_all(t.0.join(".local/state")).unwrap();
        let elsewhere = t.0.join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        symlink(&elsewhere, t.0.join(PROTECTED_STATE)).unwrap();
        assert!(prepare(&t.0, &old).is_err());
        fs::remove_file(t.0.join(PROTECTED_STATE)).unwrap();
        fs::create_dir(t.0.join(PROTECTED_STATE)).unwrap();
        fs::set_permissions(t.0.join(PROTECTED_STATE), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(prepare(&t.0, &old).is_err());
    }

    #[test]
    fn custom_xdg_is_only_a_migration_source() {
        let t = Temp::new();
        let old = legacy_directory(&t.0, Some(&t.0.join("custom-state")));
        fs::create_dir_all(&old).unwrap();
        let p = prepare(&t.0, &old).unwrap();
        assert_eq!(p.dir, directory(&t.0));
        assert!(!old.exists());
    }
}
