//! Minimal, persistent document grants for explicitly selected host files.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedFd, OwnedValue};

use super::{file_uri, Access, DocumentBackend};

const NAME: &str = "org.freedesktop.portal.Documents";
const PATH: &str = "/org/freedesktop/portal/documents";
const INTERFACE: &str = "org.freedesktop.portal.Documents";
const REUSE_AND_PERSIST: u32 = 3;
type Extra = HashMap<String, OwnedValue>;

pub struct Documents {
    connection: Connection,
}

impl Documents {
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }

    fn proxy(&self) -> io::Result<Proxy<'_>> {
        Proxy::new(&self.connection, NAME, PATH, INTERFACE)
            .map_err(|error| io::Error::other(error.to_string()))
    }

    fn mountpoint(&self, extra: Option<&Extra>) -> io::Result<PathBuf> {
        let bytes = if let Some(value) = extra.and_then(|extra| extra.get("mountpoint")) {
            Vec::<u8>::try_from(zbus::zvariant::Value::from(value.clone()))
                .map_err(|_| io::Error::other("document portal returned an invalid mountpoint"))?
        } else {
            self.proxy()?
                .call("GetMountPoint", &())
                .map_err(|error| io::Error::other(error.to_string()))?
        };
        let bytes = bytes.strip_suffix(&[0]).unwrap_or(&bytes);
        let path = PathBuf::from(OsStr::from_bytes(bytes));
        if path.is_absolute() {
            Ok(path)
        } else {
            Err(io::Error::other(
                "document portal returned a relative mountpoint",
            ))
        }
    }

    fn document_uri(&self, mountpoint: PathBuf, id: &str, name: &Path) -> io::Result<String> {
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(io::Error::other(
                "document portal returned an invalid document id",
            ));
        }
        if name.components().count() != 1
            || !matches!(name.components().next(), Some(Component::Normal(_)))
        {
            return Err(io::Error::other("invalid document basename"));
        }
        Ok(file_uri(&mountpoint.join(id).join(name)))
    }

    fn existing_id(&self, path: &Path) -> Option<String> {
        self.proxy()
            .ok()?
            .call("Lookup", &path.as_os_str().as_bytes().to_vec())
            .ok()
    }
}

impl DocumentBackend for Documents {
    fn resolve_folder(&self, folder: &Path) -> io::Result<Option<PathBuf>> {
        let mountpoint = self.mountpoint(None)?;
        let mut suffix = PathBuf::new();
        let id = if let Ok(relative) = folder.strip_prefix(&mountpoint) {
            let mut components = relative.components();
            let Some(Component::Normal(id)) = components.next() else {
                return Ok(None);
            };
            let Some(id) = id.to_str() else {
                return Ok(None);
            };
            for component in components {
                if let Component::Normal(part) = component {
                    suffix.push(part);
                } else {
                    return Ok(None);
                }
            }
            Some(id.to_owned())
        } else {
            self.existing_id(folder)
        };
        let Some(id) = id else {
            return Ok(None);
        };
        let (actual, _apps): (Vec<u8>, HashMap<String, Vec<String>>) = self
            .proxy()?
            .call("Info", &id)
            .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(Some(PathBuf::from(OsStr::from_bytes(&actual)).join(suffix)))
    }

    fn existing_grant(
        &self,
        app_id: &str,
        path: &Path,
        access: Access,
    ) -> io::Result<Option<String>> {
        let Some(id) = self.existing_id(path) else {
            return Ok(None);
        };
        let (actual, apps): (Vec<u8>, HashMap<String, Vec<String>>) = self
            .proxy()?
            .call("Info", &id)
            .map_err(|error| io::Error::other(error.to_string()))?;
        if Path::new(OsStr::from_bytes(&actual)) != path {
            return Ok(None);
        }
        let Some(permissions) = apps.get(app_id) else {
            return Ok(None);
        };
        if !access
            .permissions()
            .iter()
            .all(|needed| permissions.iter().any(|held| held == needed))
        {
            return Ok(None);
        }
        let name = path
            .file_name()
            .map(Path::new)
            .ok_or_else(|| io::Error::other("selected document has no basename"))?;
        self.document_uri(self.mountpoint(None)?, &id, name)
            .map(Some)
    }

    fn export(&self, app_id: &str, paths: &[PathBuf], access: Access) -> io::Result<Vec<String>> {
        let mut fds = Vec::with_capacity(paths.len());
        for path in paths {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)?;
            let fd: std::os::fd::OwnedFd = file.into();
            fds.push(OwnedFd::from(fd));
        }
        let (ids, extra): (Vec<String>, Extra) = self
            .proxy()?
            .call(
                "AddFull",
                &(
                    fds,
                    REUSE_AND_PERSIST,
                    app_id,
                    access.permissions().to_vec(),
                ),
            )
            .map_err(|error| io::Error::other(error.to_string()))?;
        if ids.len() != paths.len() {
            return Err(io::Error::other(
                "document portal returned the wrong grant count",
            ));
        }
        let mountpoint = self.mountpoint(Some(&extra))?;
        ids.iter()
            .zip(paths)
            .map(|(id, path)| {
                let name = path
                    .file_name()
                    .map(Path::new)
                    .ok_or_else(|| io::Error::other("selected document has no basename"))?;
                self.document_uri(mountpoint.clone(), id, name)
            })
            .collect()
    }

    fn export_named(
        &self,
        app_id: &str,
        parent: &Path,
        name: &Path,
        access: Access,
    ) -> io::Result<String> {
        if name.components().count() != 1
            || !matches!(name.components().next(), Some(Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid save basename",
            ));
        }
        let parent = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(parent)?;
        let fd: std::os::fd::OwnedFd = parent.into();
        let (id, extra): (String, Extra) = self
            .proxy()?
            .call(
                "AddNamedFull",
                &(
                    OwnedFd::from(fd),
                    name.as_os_str().as_bytes().to_vec(),
                    REUSE_AND_PERSIST,
                    app_id,
                    access.permissions().to_vec(),
                ),
            )
            .map_err(|error| io::Error::other(error.to_string()))?;
        self.document_uri(self.mountpoint(Some(&extra))?, &id, name)
    }
}
