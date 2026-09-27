//! What Nix declared: `~/.config/vpn-zones/declared/`, believed only when it
//! is what home-manager makes of it.
//!
//! The home-manager module writes each declared setting with `home.file`
//! (`module/default.nix`), and home-manager puts every such file in place as
//! a symlink into its `home-manager-files` tree in the Nix store, which links
//! on to the file's own store path. A declared value wins over the local one,
//! and the CLI refuses to change it ("задано в Nix"). Until 2026-09-27 any
//! file that sat in `declared/` was taken for Nix's word, so anything that
//! writes the home could speak in Nix's name: a program of the host, or a
//! file chooser saving where a zone's program proposed —
//! `declared/hermetic-default` with `off` in it, and every zone started after
//! that is not hermetic.
//!
//! So a declared file counts only when, every link followed, it is in the
//! store ([`STORE`]): written by a build, read-only, nobody's program's. A
//! plain file, a link out of the store, a link to nowhere: ignored, with a
//! warning once per path and process, and the local value or the default
//! applies as if nothing were declared. The check is in [`hold`], and
//! every reader of `declared/` goes through it.
//!
//! Where the file is, is asked of the kernel about the file itself: the
//! path is opened `O_PATH` — every link followed, nothing opened for reading,
//! so a FIFO or a device put there is neither waited on nor touched — and
//! the descriptor's own link in `/proc/self/fd` names the file it holds; the
//! text is then read through that descriptor, not through the path again.
//! Not `realpath`: the filters read the config directory through a
//! descriptor they held at their start (`/proc/self/fd/<n>/declared/…`,
//! `crate::screencast::Policy::hold`), and `realpath` would follow that
//! link's text — the path as it is named now, possibly covered since — and
//! not the directory held.
//!
//! The store is a constant. Not an environment variable and not a key of
//! the tools manifest: whatever a program can set, it could point at a
//! directory of its own and take the check away. The tests put their
//! declarations into the real store, as home-manager does ([`declare`]).
//!
//! What this does not stop: whoever writes the home can still remove Nix's
//! link — the local value or the default then applies, as with nothing
//! declared — or point it at another file of the store, which a build made
//! but not necessarily one that says what the owner wants. A program that
//! can do that outside every zone is the host, trusted anyway
//! (`docs/THREAT-MODEL.md` §5); in a zone the config directory is read-only.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Where home-manager's files end up, and so where a declaration has to.
pub const STORE: &str = "/nix/store";

/// The paths already warned about in this process: a filter reads its
/// switch for every call, and one word is enough.
static WARNED: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// The file a declared path leads to, held (`O_PATH`), when it is the
/// store's. `NotFound` both when there is nothing there and when what is
/// there is not Nix's (said once on stderr); other errors as they come, so
/// that a declaration that cannot be read is not taken for none.
pub fn hold(path: &Path) -> io::Result<File> {
    let held = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH)
        .open(path)?;
    let real = fs::read_link(fd_path(&held)).map_err(|e| {
        io::Error::other(format!(
            "{}: where it leads is not known ({e})",
            path.display()
        ))
    })?;
    if in_store(&real) {
        return Ok(held);
    }
    warn(path);
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "not a link into the Nix store",
    ))
}

/// Whether `path` is declared: there, and the store's.
pub fn is_declared(path: &Path) -> bool {
    hold(path).is_ok()
}

/// Whether the setting `name` of the config directory `config` is declared
/// ([`is_declared`] of `declared/<name>`): the CLI's refusal to change it.
pub fn declares(config: &Path, name: &str) -> bool {
    is_declared(&config.join(crate::cli::DECLARED_DIR).join(name))
}

/// The text of a declared file ([`hold`]'s errors), read through the
/// descriptor that was checked, not through the path again: a link changed
/// in between is not followed.
pub fn read(path: &Path) -> io::Result<String> {
    fs::read_to_string(fd_path(&hold(path)?))
}

/// A declared one-line setting, as [`crate::cli::read_setting`] reads a
/// local one: trailing newlines dropped. `None` when there is none, or none
/// of Nix's.
pub fn setting(path: &Path) -> Option<String> {
    crate::cli::read_setting(&fd_path(&hold(path).ok()?))
}

/// A held file's own name in `/proc`: read, it is the file; as a link, it
/// says where the file is.
fn fd_path(held: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", held.as_raw_fd()))
}

/// Inside the store, below its root. The store's own path is resolved too:
/// `/nix` may be a link to another disk.
fn in_store(real: &Path) -> bool {
    let store = fs::canonicalize(STORE).unwrap_or_else(|_| PathBuf::from(STORE));
    real != store && real.starts_with(&store)
}

fn warn(path: &Path) {
    let mut warned = WARNED.lock().unwrap_or_else(|e| e.into_inner());
    if warned.iter().any(|p| p == path) {
        return;
    }
    warned.push(path.to_path_buf());
    eprintln!(
        "cellward: {} — не ссылка в {STORE}, то есть не от Nix: не учитывается, действует \
         локальное значение или умолчание",
        path.display()
    );
}

/// Declare `text` at `path` the way home-manager does: the text into the
/// Nix store (`nix-store --add`), `path` a link to it, in place of whatever
/// was there. The tests need Nix, as they need its libseccomp.
#[cfg(test)]
pub(crate) fn declare(path: &Path, text: &str) {
    let source = test_source();
    fs::write(&source, text).unwrap();
    link_into_store(&source, path);
}

/// A declaration that is Nix's and cannot be read as a file: a directory of
/// the store.
#[cfg(test)]
pub(crate) fn declare_unreadable(path: &Path) {
    let source = test_source();
    fs::create_dir(&source).unwrap();
    link_into_store(&source, path);
}

/// A new place to put a declaration together before it goes into the store.
#[cfg(test)]
fn test_source() -> PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "cellward-declare-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir.join("cellward-test-declared")
}

#[cfg(test)]
fn link_into_store(source: &Path, path: &Path) {
    let out = std::process::Command::new("nix-store")
        .arg("--add")
        .arg(source)
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "nix-store: {e} — what Nix declares lives in the Nix store, and so do the \
                 tests' declarations: run them where Nix is (nix-shell ../tests/harness.nix \
                 -A rustShell)"
            )
        });
    assert!(
        out.status.success(),
        "nix-store --add: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stored = PathBuf::from(String::from_utf8(out.stdout).unwrap().trim());
    if let Some(dir) = source.parent() {
        let _ = fs::remove_dir_all(dir);
    }
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).unwrap();
    }
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => panic!("{}: {e}", path.display()),
    }
    std::os::unix::fs::symlink(stored, path).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("cellward-declared-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(dir.join("declared")).unwrap();
            Self(dir)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// What home-manager makes — a link into the store, through a link as
    /// its `home-manager-files` is one — is Nix's word, read from the store.
    #[test]
    fn a_link_into_the_store_is_declared() {
        let d = Dir::new("store");
        let path = d.0.join("declared/hermetic-default");
        declare(&path, "on\n");
        assert!(is_declared(&path));
        let held = hold(&path).unwrap();
        assert!(fs::read_link(fd_path(&held)).unwrap().starts_with(STORE));
        assert_eq!(read(&path).unwrap(), "on\n");
        assert_eq!(setting(&path).as_deref(), Some("on"));
        // One more link on the way, as home-manager's files tree is.
        let hop = d.0.join("hop");
        std::os::unix::fs::symlink(fs::read_link(&path).unwrap(), &hop).unwrap();
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&hop, &path).unwrap();
        assert_eq!(setting(&path).as_deref(), Some("on"));
    }

    /// A plain file in `declared/`, or a link anywhere but the store, is
    /// nobody's declaration: as if there were none, not an error.
    #[test]
    fn a_plain_file_or_a_link_elsewhere_is_not_declared() {
        let d = Dir::new("plain");
        let plain = d.0.join("declared/hermetic-default");
        fs::write(&plain, "off\n").unwrap();
        assert!(!is_declared(&plain));
        assert_eq!(setting(&plain), None);
        assert_eq!(read(&plain).unwrap_err().kind(), io::ErrorKind::NotFound);

        let elsewhere = d.0.join("declared/mode");
        std::os::unix::fs::symlink(&plain, &elsewhere).unwrap();
        assert!(!is_declared(&elsewhere));
        assert_eq!(
            read(&elsewhere).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );

        // A link that goes nowhere, and nothing at all.
        let nowhere = d.0.join("declared/autostart");
        std::os::unix::fs::symlink(d.0.join("gone"), &nowhere).unwrap();
        assert!(!is_declared(&nowhere));
        assert!(!is_declared(&d.0.join("declared/absent")));
        // A link to the store's root is not a file of the store.
        let root = d.0.join("declared/user-entries");
        std::os::unix::fs::symlink(STORE, &root).unwrap();
        assert!(!is_declared(&root));
        // A FIFO is not waited on: it is refused, not opened.
        let fifo = d.0.join("declared/frame-title");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a NUL-terminated path of this test's own directory.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(!is_declared(&fifo));
        assert_eq!(setting(&fifo), None);
    }

    /// Read through a directory held at the start, as the filters read the
    /// config directory (`/proc/self/fd/<n>/declared/…`): the file of the
    /// directory held, not of whatever has the name now.
    #[test]
    fn a_held_directory_is_read_as_held() {
        let d = Dir::new("held");
        declare(&d.0.join("declared/screencast"), "nl no\n");
        let dir = File::open(d.0.join("declared")).unwrap();
        let through = fd_path(&dir).join("screencast");
        fs::rename(d.0.join("declared"), d.0.join("moved")).unwrap();
        fs::create_dir(d.0.join("declared")).unwrap();
        fs::write(d.0.join("declared/screencast"), "nl yes\n").unwrap();
        assert_eq!(read(&through).unwrap(), "nl no\n");
        assert_eq!(read(&d.0.join("declared/screencast")).ok(), None);
    }

    /// Nix's, and not readable as a file: an error of its own, so that a
    /// caller that must be safe can take the strictest value.
    #[test]
    fn a_declaration_that_cannot_be_read_is_not_taken_for_none() {
        let d = Dir::new("unreadable");
        let path = d.0.join("declared/microphone");
        declare_unreadable(&path);
        assert!(is_declared(&path));
        let e = read(&path).unwrap_err();
        assert_ne!(e.kind(), io::ErrorKind::NotFound, "{e}");
    }
}
