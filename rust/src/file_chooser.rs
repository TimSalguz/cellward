//! The capability layer below a future trusted FileChooser backend.
//!
//! Views are authorized before a path is resolved. A file grant is an fd opened
//! below that view's pinned directory, never a host path returned to the caller.
//! This module has no GUI, D-Bus service, Document Portal calls, or mount setup.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::origin::Who;

#[derive(Debug)]
pub enum Error {
    UnknownIdentity,
    HostHomeNotAllowed,
    OtherContainerNotAllowed,
    ViewUnavailable,
    InvalidPath,
    Symlink,
    NotARegularFile,
    ChangedDuringOpen,
    WrongRequester,
    Revoked,
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownIdentity => write!(f, "broker could not identify the requester"),
            Self::HostHomeNotAllowed => write!(f, "host home was not explicitly allowed"),
            Self::OtherContainerNotAllowed => {
                write!(f, "the other container was not explicitly selected")
            }
            Self::ViewUnavailable => write!(f, "the authorized view has no trusted root"),
            Self::InvalidPath => write!(f, "a relative file path without `..` is required"),
            Self::Symlink => write!(f, "symbolic links are not followed"),
            Self::NotARegularFile => write!(f, "only a regular file can be granted"),
            Self::ChangedDuringOpen => write!(f, "the file changed while it was opened"),
            Self::WrongRequester => write!(f, "the grant belongs to another requester"),
            Self::Revoked => write!(f, "the grant was revoked"),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// The container identity established by the broker, never by request fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerIdentity {
    who: Who,
}

impl BrokerIdentity {
    pub fn from_broker(who: &Who) -> Result<Self, Error> {
        match who {
            Who::Unknown => Err(Error::UnknownIdentity),
            known => Ok(Self { who: known.clone() }),
        }
    }
}

/// Filesystem namespaces are distinct even when their displayed paths agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum View {
    AppFs,
    HostHome,
    OtherContainer(String),
}

/// Explicit, per-request permission to show views beyond the requester's own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    host_home: bool,
    other_containers: BTreeSet<String>,
}

impl Policy {
    pub fn allow_host_home(&mut self) {
        self.host_home = true;
    }

    pub fn allow_other_container(&mut self, name: &str) -> Result<(), Error> {
        if !crate::container::valid_name(name) {
            return Err(Error::InvalidPath);
        }
        self.other_containers.insert(name.to_owned());
        Ok(())
    }
}

/// Directory descriptors opened and mapped by the trusted host backend.
pub struct ViewRoots {
    app_fs: OwnedFd,
    host_home: Option<OwnedFd>,
    other_containers: BTreeMap<String, OwnedFd>,
}

impl ViewRoots {
    pub fn new(app_fs: OwnedFd) -> Self {
        Self {
            app_fs,
            host_home: None,
            other_containers: BTreeMap::new(),
        }
    }

    pub fn set_host_home(&mut self, root: OwnedFd) {
        self.host_home = Some(root);
    }

    pub fn set_other_container(&mut self, name: &str, root: OwnedFd) -> Result<(), Error> {
        if !crate::container::valid_name(name) {
            return Err(Error::InvalidPath);
        }
        self.other_containers.insert(name.to_owned(), root);
        Ok(())
    }

    pub fn authorize<'a>(
        &'a self,
        identity: &BrokerIdentity,
        view: View,
        policy: &Policy,
    ) -> Result<AuthorizedView<'a>, Error> {
        let root = match &view {
            View::AppFs => &self.app_fs,
            View::HostHome if !policy.host_home => return Err(Error::HostHomeNotAllowed),
            View::HostHome => self.host_home.as_ref().ok_or(Error::ViewUnavailable)?,
            View::OtherContainer(name) if !policy.other_containers.contains(name) => {
                return Err(Error::OtherContainerNotAllowed);
            }
            View::OtherContainer(name) => self
                .other_containers
                .get(name)
                .ok_or(Error::ViewUnavailable)?,
        };
        if fd_stat(root.as_raw_fd())?.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(Error::ViewUnavailable);
        }
        Ok(AuthorizedView {
            identity: identity.clone(),
            view,
            root,
        })
    }
}

/// A view authorized for one broker identity and pinned to one root dirfd.
pub struct AuthorizedView<'a> {
    identity: BrokerIdentity,
    view: View,
    root: &'a OwnedFd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    ReadOnly,
    ReadWrite,
}

impl AuthorizedView<'_> {
    /// Open one regular file without following any symlink and issue a scoped grant.
    pub fn grant_file(
        &self,
        relative: &Path,
        access: Access,
    ) -> Result<(FdGrant, GrantRevocation), Error> {
        let fd = open_regular_below(self.root, relative, access)?;
        let revoked = Arc::new(AtomicBool::new(false));
        Ok((
            FdGrant {
                identity: self.identity.clone(),
                view: self.view.clone(),
                access,
                fd,
                revoked: Arc::clone(&revoked),
            },
            GrantRevocation { revoked },
        ))
    }
}

/// A regular-file capability. Raw directory fds are deliberately not issued:
/// their owner could follow a later symlink below the directory by itself.
pub struct FdGrant {
    identity: BrokerIdentity,
    view: View,
    access: Access,
    fd: OwnedFd,
    revoked: Arc<AtomicBool>,
}

impl FdGrant {
    pub fn view(&self) -> &View {
        &self.view
    }

    pub fn access(&self) -> Access {
        self.access
    }

    /// Duplicate for SCM_RIGHTS or another trusted handoff to the same requester.
    /// Revocation stops later duplicates; Unix cannot retract fds already sent.
    pub fn duplicate_for(&self, requester: &BrokerIdentity) -> Result<OwnedFd, Error> {
        if requester != &self.identity {
            return Err(Error::WrongRequester);
        }
        if self.revoked.load(Ordering::Acquire) {
            return Err(Error::Revoked);
        }
        Ok(self.fd.try_clone()?)
    }
}

/// The backend's revocable half of a grant, retained when the fd is handed off.
#[derive(Clone)]
pub struct GrantRevocation {
    revoked: Arc<AtomicBool>,
}

impl GrantRevocation {
    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
    }
}

fn open_at(parent: RawFd, name: &CStr, flags: libc::c_int) -> Result<OwnedFd, Error> {
    // SAFETY: a valid parent descriptor and a NUL-terminated single component.
    let fd = unsafe { libc::openat(parent, name.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        let error = io::Error::last_os_error();
        return Err(
            if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) {
                Error::Symlink
            } else {
                Error::Io(error)
            },
        );
    }
    // SAFETY: the descriptor was just returned and is owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn stat_at(dir: RawFd, name: &CStr) -> io::Result<libc::stat> {
    // SAFETY: stat is plain output storage filled by the kernel.
    let mut stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid descriptor and name; never follow the final component.
    if unsafe { libc::fstatat(dir, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat)
}

fn fd_stat(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: stat is plain output storage filled by the kernel.
    let mut stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid descriptor and a valid output pointer.
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat)
}

fn open_regular_below(root: &OwnedFd, path: &Path, access: Access) -> Result<OwnedFd, Error> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => {
                components.push(CString::new(name.as_bytes()).map_err(|_| Error::InvalidPath)?)
            }
            Component::CurDir => {}
            Component::RootDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(Error::InvalidPath);
            }
        }
    }
    let Some((last, parents)) = components.split_last() else {
        return Err(Error::InvalidPath);
    };

    let mut current: Option<OwnedFd> = None;
    for name in parents {
        let parent = current
            .as_ref()
            .map_or(root.as_raw_fd(), AsRawFd::as_raw_fd);
        current = Some(open_at(
            parent,
            name,
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )?);
    }
    let parent = current
        .as_ref()
        .map_or(root.as_raw_fd(), AsRawFd::as_raw_fd);
    let before = stat_at(parent, last)?;
    if before.st_mode & libc::S_IFMT == libc::S_IFLNK {
        return Err(Error::Symlink);
    }
    if before.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(Error::NotARegularFile);
    }
    let access = match access {
        Access::ReadOnly => libc::O_RDONLY,
        Access::ReadWrite => libc::O_RDWR,
    };
    let fd = open_at(parent, last, access | libc::O_NONBLOCK | libc::O_NOFOLLOW)?;
    let after = fd_stat(fd.as_raw_fd())?;
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || after.st_mode & libc::S_IFMT != libc::S_IFREG
    {
        return Err(Error::ChangedDuringOpen);
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Synthetic(PathBuf);

    impl Synthetic {
        fn new() -> Self {
            let base = std::env::temp_dir().join(format!(
                "cw-file-chooser-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            for dir in ["app", "host", "other", "outside"] {
                fs::create_dir_all(base.join(dir)).unwrap();
            }
            fs::write(base.join("app/note"), b"app data").unwrap();
            fs::write(base.join("host/note"), b"host data").unwrap();
            fs::write(base.join("other/note"), b"other data").unwrap();
            fs::write(base.join("outside/secret"), b"synthetic outside data").unwrap();
            Self(base)
        }

        fn root(&self, name: &str) -> OwnedFd {
            fs::File::open(self.0.join(name)).unwrap().into()
        }
    }

    impl Drop for Synthetic {
        fn drop(&mut self) {
            for file in [
                "app/note",
                "app/dir-link",
                "app/file-link",
                "host/note",
                "other/note",
                "outside/secret",
            ] {
                let _ = fs::remove_file(self.0.join(file));
            }
            for dir in ["app", "host", "other", "outside"] {
                let _ = fs::remove_dir(self.0.join(dir));
            }
            let _ = fs::remove_dir(&self.0);
        }
    }

    fn identity(name: &str) -> BrokerIdentity {
        BrokerIdentity::from_broker(&Who::Container(name.to_owned())).unwrap()
    }

    #[test]
    fn unknown_broker_identity_gets_no_view() {
        assert!(matches!(
            BrokerIdentity::from_broker(&Who::Unknown),
            Err(Error::UnknownIdentity)
        ));
    }

    #[test]
    fn host_home_requires_explicit_policy() {
        let synthetic = Synthetic::new();
        let caller = identity("app");
        let mut roots = ViewRoots::new(synthetic.root("app"));
        roots.set_host_home(synthetic.root("host"));
        let policy = Policy::default();
        assert!(matches!(
            roots.authorize(&caller, View::HostHome, &policy),
            Err(Error::HostHomeNotAllowed)
        ));
        let mut allowed = Policy::default();
        allowed.allow_host_home();
        let view = roots.authorize(&caller, View::HostHome, &allowed).unwrap();
        let (grant, _revocation) = view
            .grant_file(Path::new("note"), Access::ReadOnly)
            .unwrap();
        assert_eq!(grant.view(), &View::HostHome);
    }

    #[test]
    fn other_container_requires_that_trusted_choice() {
        let synthetic = Synthetic::new();
        let caller = identity("app");
        let mut roots = ViewRoots::new(synthetic.root("app"));
        roots
            .set_other_container("work", synthetic.root("other"))
            .unwrap();
        let requested = View::OtherContainer("work".to_owned());
        assert!(matches!(
            roots.authorize(&caller, requested.clone(), &Policy::default()),
            Err(Error::OtherContainerNotAllowed)
        ));
        let mut policy = Policy::default();
        policy.allow_other_container("work").unwrap();
        assert!(roots.authorize(&caller, requested, &policy).is_ok());
        assert!(matches!(
            roots.authorize(
                &caller,
                View::OtherContainer("different".to_owned()),
                &policy
            ),
            Err(Error::OtherContainerNotAllowed)
        ));
    }

    #[test]
    fn symlink_escape_is_rejected_for_intermediate_and_final_components() {
        let synthetic = Synthetic::new();
        symlink("../outside", synthetic.0.join("app/dir-link")).unwrap();
        symlink("../outside/secret", synthetic.0.join("app/file-link")).unwrap();
        let roots = ViewRoots::new(synthetic.root("app"));
        let view = roots
            .authorize(&identity("app"), View::AppFs, &Policy::default())
            .unwrap();
        for path in ["dir-link/secret", "file-link"] {
            assert!(matches!(
                view.grant_file(Path::new(path), Access::ReadOnly),
                Err(Error::Symlink)
            ));
        }
        assert!(matches!(
            view.grant_file(Path::new("../outside/secret"), Access::ReadOnly),
            Err(Error::InvalidPath)
        ));
    }

    #[test]
    fn fd_grant_is_scoped_and_revocation_stops_new_duplicates() {
        let synthetic = Synthetic::new();
        let caller = identity("app");
        let roots = ViewRoots::new(synthetic.root("app"));
        let view = roots
            .authorize(&caller, View::AppFs, &Policy::default())
            .unwrap();
        let (grant, revocation) = view
            .grant_file(Path::new("note"), Access::ReadOnly)
            .unwrap();
        assert_eq!(grant.access(), Access::ReadOnly);
        assert!(matches!(
            grant.duplicate_for(&identity("other")),
            Err(Error::WrongRequester)
        ));
        let already_sent = grant.duplicate_for(&caller).unwrap();
        revocation.revoke();
        assert!(matches!(grant.duplicate_for(&caller), Err(Error::Revoked)));
        let mut file = fs::File::from(already_sent);
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "app data");
    }

    #[test]
    fn a_directory_is_not_silently_turned_into_a_file_grant() {
        let synthetic = Synthetic::new();
        let roots = ViewRoots::new(synthetic.root("app"));
        let view = roots
            .authorize(&identity("app"), View::AppFs, &Policy::default())
            .unwrap();
        assert!(matches!(
            view.grant_file(Path::new(""), Access::ReadOnly),
            Err(Error::InvalidPath)
        ));
        assert!(matches!(
            view.grant_file(Path::new("."), Access::ReadOnly),
            Err(Error::InvalidPath)
        ));
    }
}
