//! Scoped FileChooser decisions, independent of D-Bus and the host dialogs.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::container::{Container, Home};
use crate::sys::{CancelToken, Cancellation};
use crate::tools::Tools;

pub mod dbus;
pub mod documents;
pub mod gui;

pub const RESPONSE_OK: u32 = 0;
pub const RESPONSE_CANCELLED: u32 = 1;
pub const RESPONSE_FAILED: u32 = 2;
const MAX_REQUESTS: usize = 64;
const REQUEST_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    ReadWrite,
}

impl Access {
    pub fn permissions(self) -> &'static [&'static str] {
        match self {
            Self::Read => &["read"],
            Self::ReadWrite => &["read", "write"],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    pub label: String,
    pub rules: Vec<(u32, String)>,
}

impl Filter {
    pub fn validate(&self) -> Result<(), String> {
        if self.label.is_empty() || self.rules.is_empty() || self.rules.len() > 128 {
            return Err("invalid filter".into());
        }
        for (kind, rule) in &self.rules {
            if rule.is_empty() || rule.as_bytes().contains(&0) {
                return Err("invalid filter rule".into());
            }
            match kind {
                0 => {}
                1 if valid_mime(rule) => {}
                _ => return Err("invalid filter rule".into()),
            }
        }
        Ok(())
    }
}

fn valid_mime(rule: &str) -> bool {
    let Some((major, minor)) = rule.split_once('/') else {
        return false;
    };
    let valid = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'+' | b'.' | b'*'))
    };
    valid(major) && valid(minor) && !major.contains('*') && (!minor.contains('*') || minor == "*")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    pub id: String,
    pub label: String,
    pub options: Vec<(String, String)>,
    pub initial: String,
}

impl Choice {
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty()
            || self.label.is_empty()
            || self.options.len() > 64
            || self.options.iter().any(|(id, label)| {
                id.is_empty()
                    || label.is_empty()
                    || self.options.iter().filter(|(o, _)| o == id).count() > 1
            })
        {
            return Err("invalid choice".into());
        }
        if self.options.is_empty() {
            if self.initial.is_empty() || matches!(self.initial.as_str(), "true" | "false") {
                return Ok(());
            }
            return Err("invalid boolean choice".into());
        }
        if self.initial.is_empty() || self.options.iter().any(|(id, _)| id == &self.initial) {
            Ok(())
        } else {
            Err("invalid initial choice".into())
        }
    }

    pub fn defaults(&self) -> (String, String) {
        let selected = if self.options.is_empty() {
            if self.initial.is_empty() {
                "false"
            } else {
                self.initial.as_str()
            }
        } else if self.initial.is_empty() {
            self.options[0].0.as_str()
        } else {
            self.initial.as_str()
        };
        (self.id.clone(), selected.to_owned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    Open { multiple: bool, directory: bool },
    Save { current_name: Option<String> },
    SaveMany { files: Vec<PathBuf> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub app_id: String,
    pub parent_window: String,
    pub title: String,
    pub accept_label: Option<String>,
    pub modal: bool,
    pub operation: Operation,
    pub filters: Vec<Filter>,
    pub current_filter: Option<Filter>,
    pub choices: Vec<Choice>,
    pub current_folder: Option<PathBuf>,
    pub current_file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub paths: Vec<PathBuf>,
    pub choices: Vec<(String, String)>,
    pub current_filter: Option<Filter>,
    pub confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub code: u32,
    pub uris: Vec<String>,
    pub choices: Vec<(String, String)>,
    pub current_filter: Option<Filter>,
    pub writable: bool,
}

impl Response {
    fn empty(code: u32) -> Self {
        Self {
            code,
            uris: Vec::new(),
            choices: Vec::new(),
            current_filter: None,
            writable: false,
        }
    }
}

#[derive(Debug, Clone)]
enum DirectHome {
    Real,
    Private(Container),
    Layer(Container),
}

#[derive(Debug, Clone)]
pub struct Source {
    pub app_id: String,
    pub label: String,
    direct: Option<DirectHome>,
}

impl Source {
    pub fn resolve(tools: &Tools, app_id: &str) -> Option<Self> {
        for container in crate::container::load_all_quiet(tools) {
            if crate::desktop::container_app_id(&container.name) == app_id {
                let direct = match container.home {
                    Home::Main => DirectHome::Real,
                    Home::Private => DirectHome::Private(container.clone()),
                    Home::Layer => DirectHome::Layer(container.clone()),
                };
                return Some(Self {
                    app_id: app_id.to_owned(),
                    label: format!("контейнер «{}»", container.name),
                    direct: Some(direct),
                });
            }
        }
        if app_id.starts_with("vpnzone.app.")
            && app_id.len() <= 255
            && app_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Some(Self {
                app_id: app_id.to_owned(),
                label: "изолированная программа Cellward".into(),
                direct: None,
            });
        }
        None
    }

    fn chooser_folder(&self, tools: &Tools, folder: &Path) -> PathBuf {
        match self.direct.as_ref() {
            Some(DirectHome::Private(container)) if folder.starts_with(&tools.home) => {
                let relative = folder
                    .strip_prefix(&tools.home)
                    .unwrap_or_else(|_| Path::new(""));
                container
                    .dir
                    .join(crate::home_layer::LAYER_DIR)
                    .join(relative)
            }
            Some(DirectHome::Layer(container)) if folder.starts_with(&tools.home) => {
                let relative = folder
                    .strip_prefix(&tools.home)
                    .unwrap_or_else(|_| Path::new(""));
                let (upper, _) = crate::home_layer::layer_dirs(&container.dir);
                let layered = upper.join(relative);
                if layered.is_dir() {
                    layered
                } else {
                    folder.to_path_buf()
                }
            }
            _ => folder.to_path_buf(),
        }
    }

    fn direct_path(&self, tools: &Tools, selected: &Path) -> Option<PathBuf> {
        let direct = self.direct.as_ref()?;
        match direct {
            DirectHome::Real if selected.starts_with(&tools.home) => (!selected
                .starts_with(&tools.profiles)
                && !selected.starts_with(&tools.sandboxes)
                && !selected.starts_with(&tools.state))
            .then(|| selected.to_path_buf()),
            DirectHome::Layer(container) => {
                let (upper, _) = crate::home_layer::layer_dirs(&container.dir);
                if let Ok(relative) = selected.strip_prefix(upper) {
                    return Some(tools.home.join(relative));
                }
                if !selected.starts_with(&tools.home)
                    || selected.starts_with(&tools.profiles)
                    || selected.starts_with(&tools.sandboxes)
                    || selected.starts_with(&tools.state)
                {
                    return None;
                }
                Some(selected.to_path_buf())
            }
            DirectHome::Private(container) => {
                let home = container.dir.join(crate::home_layer::LAYER_DIR);
                if let Ok(relative) = selected.strip_prefix(home) {
                    return Some(tools.home.join(relative));
                }
                container
                    .paths
                    .iter()
                    .any(|grant| selected.starts_with(&grant.value))
                    .then(|| selected.to_path_buf())
            }
            _ => None,
        }
    }
}

pub trait DocumentBackend: Send + Sync {
    fn resolve_folder(&self, folder: &Path) -> io::Result<Option<PathBuf>> {
        let _ = folder;
        Ok(None)
    }

    fn existing_grant(
        &self,
        app_id: &str,
        path: &Path,
        access: Access,
    ) -> io::Result<Option<String>>;

    fn export(&self, app_id: &str, paths: &[PathBuf], access: Access) -> io::Result<Vec<String>>;

    fn export_named(
        &self,
        app_id: &str,
        parent: &Path,
        name: &Path,
        access: Access,
    ) -> io::Result<String>;
}

pub trait Chooser: Send + Sync {
    fn select(&self, request: &Request, cancel: &CancelToken) -> Option<Selection>;

    fn preview(&self, request: &Request, text: &str, cancel: &CancelToken) -> bool;
}

impl<T: DocumentBackend + ?Sized> DocumentBackend for Arc<T> {
    fn resolve_folder(&self, folder: &Path) -> io::Result<Option<PathBuf>> {
        (**self).resolve_folder(folder)
    }

    fn existing_grant(
        &self,
        app_id: &str,
        path: &Path,
        access: Access,
    ) -> io::Result<Option<String>> {
        (**self).existing_grant(app_id, path, access)
    }

    fn export(&self, app_id: &str, paths: &[PathBuf], access: Access) -> io::Result<Vec<String>> {
        (**self).export(app_id, paths, access)
    }

    fn export_named(
        &self,
        app_id: &str,
        parent: &Path,
        name: &Path,
        access: Access,
    ) -> io::Result<String> {
        (**self).export_named(app_id, parent, name, access)
    }
}

impl<T: Chooser + ?Sized> Chooser for Arc<T> {
    fn select(&self, request: &Request, cancel: &CancelToken) -> Option<Selection> {
        (**self).select(request, cancel)
    }

    fn preview(&self, request: &Request, text: &str, cancel: &CancelToken) -> bool {
        (**self).preview(request, text, cancel)
    }
}

pub struct Backend<C, D> {
    pub tools: Tools,
    pub chooser: C,
    pub documents: D,
}

impl<C: Chooser, D: DocumentBackend> Backend<C, D> {
    pub fn process(&self, request: &Request, cancel: &CancelToken) -> Response {
        let Some(source) = Source::resolve(&self.tools, &request.app_id) else {
            return Response::empty(RESPONSE_FAILED);
        };
        let mut effective = request.clone();
        if let Some(folder) = &request.current_folder {
            match self.documents.resolve_folder(folder) {
                Ok(resolved) => {
                    let folder = resolved.as_deref().unwrap_or(folder);
                    effective.current_folder = Some(source.chooser_folder(&self.tools, folder));
                }
                Err(_) => return Response::empty(RESPONSE_FAILED),
            }
        }
        let Some(selection) = self.chooser.select(&effective, cancel) else {
            return Response::empty(RESPONSE_CANCELLED);
        };
        if cancel.cancelled() || !selection.confirmed {
            return Response::empty(if cancel.cancelled() {
                RESPONSE_CANCELLED
            } else {
                RESPONSE_FAILED
            });
        }
        if !self.valid_selection(request, &selection) {
            return Response::empty(RESPONSE_FAILED);
        }
        let access = match request.operation {
            Operation::Open { .. } => Access::Read,
            Operation::Save { .. } | Operation::SaveMany { .. } => Access::ReadWrite,
        };
        let paths = match &request.operation {
            Operation::SaveMany { files } => files
                .iter()
                .map(|name| selection.paths[0].join(name))
                .collect::<Vec<_>>(),
            _ => selection.paths.clone(),
        };
        let saving = matches!(
            request.operation,
            Operation::Save { .. } | Operation::SaveMany { .. }
        );
        let mut uris = vec![None; paths.len()];
        let mut pending = Vec::new();
        for (index, path) in paths.iter().enumerate() {
            if let Some(direct) = source.direct_path(&self.tools, path) {
                uris[index] = Some(file_uri(&direct));
                continue;
            }
            if !saving && source.direct.is_some() {
                match self.documents.existing_grant(&source.app_id, path, access) {
                    Ok(Some(uri)) => {
                        uris[index] = Some(uri);
                        continue;
                    }
                    Ok(None) => {}
                    Err(_) => return Response::empty(RESPONSE_FAILED),
                }
            }
            pending.push((index, path.clone()));
        }
        if (saving || !pending.is_empty())
            && !self.confirmed_scope(request, &source, &paths, cancel)
        {
            return Response::empty(RESPONSE_CANCELLED);
        }
        for (index, path) in pending {
            let granted = if saving {
                let Some(parent) = path.parent() else {
                    return Response::empty(RESPONSE_FAILED);
                };
                let Some(name) = path.file_name() else {
                    return Response::empty(RESPONSE_FAILED);
                };
                self.documents
                    .export_named(&source.app_id, parent, Path::new(name), access)
            } else {
                self.documents
                    .export(&source.app_id, std::slice::from_ref(&path), access)
                    .and_then(|mut granted| {
                        if granted.len() == 1 {
                            Ok(granted.remove(0))
                        } else {
                            Err(io::Error::other("wrong document grant count"))
                        }
                    })
            };
            match granted {
                Ok(uri) => uris[index] = Some(uri),
                Err(_) => return Response::empty(RESPONSE_FAILED),
            }
        }
        Response {
            code: RESPONSE_OK,
            uris: uris
                .into_iter()
                .collect::<Option<Vec<_>>>()
                .unwrap_or_default(),
            choices: selection.choices,
            current_filter: selection.current_filter,
            writable: false,
        }
    }

    fn valid_selection(&self, request: &Request, selection: &Selection) -> bool {
        if selection.paths.is_empty()
            || selection.paths.iter().any(|path| {
                !path.is_absolute()
                    || path
                        .components()
                        .any(|part| matches!(part, Component::ParentDir))
            })
        {
            return false;
        }
        if let Some(filter) = &selection.current_filter {
            if filter.validate().is_err()
                || (!request.filters.is_empty() && !request.filters.contains(filter))
            {
                return false;
            }
        }
        match &request.operation {
            Operation::Open {
                multiple,
                directory,
            } => {
                (*multiple || selection.paths.len() == 1)
                    && selection.paths.iter().all(|path| {
                        std::fs::metadata(path).is_ok_and(|meta| meta.is_dir() == *directory)
                    })
            }
            Operation::Save { .. } => selection.paths.len() == 1,
            Operation::SaveMany { files } => {
                selection.paths.len() == 1
                    && std::fs::metadata(&selection.paths[0]).is_ok_and(|meta| meta.is_dir())
                    && !files.is_empty()
            }
        }
    }

    fn confirmed_scope(
        &self,
        request: &Request,
        source: &Source,
        paths: &[PathBuf],
        cancel: &CancelToken,
    ) -> bool {
        let action = match request.operation {
            Operation::Open { .. } => "получить доступ на чтение к",
            Operation::Save { .. } | Operation::SaveMany { .. } => "сохранить",
        };
        let names: Vec<String> = paths
            .iter()
            .filter_map(|path| path.file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .take(16)
            .collect();
        let overwrite = matches!(
            request.operation,
            Operation::Save { .. } | Operation::SaveMany { .. }
        ) && paths.iter().any(|path| path.exists());
        let text = format!(
            "{} просит {} выбранные на хосте файлы:\n{}\n{}",
            source.label,
            action,
            names.join(", "),
            if overwrite {
                "Существующий файл будет перезаписан только после вашего подтверждения."
            } else {
                "Доступ выдаётся только к явно выбранным файлам, не к каталогу хоста целиком."
            }
        );
        self.chooser.preview(request, &text, cancel)
    }
}

pub fn file_uri(path: &Path) -> String {
    let mut out = String::from("file://");
    for byte in std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str()) {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(*byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

struct LiveRequest {
    owner: String,
    _cancellation: Cancellation,
    started: Instant,
}

#[derive(Default)]
pub struct Requests {
    live: HashMap<String, LiveRequest>,
    used: HashSet<String>,
    used_order: VecDeque<String>,
}

impl Requests {
    pub fn begin(&mut self, handle: &str, owner: &str) -> Option<CancelToken> {
        if !handle.starts_with('/')
            || handle.len() > 256
            || !owner.starts_with(':')
            || self.used.contains(handle)
        {
            return None;
        }
        let stale: Vec<String> = self
            .live
            .iter()
            .filter(|(_, request)| request.started.elapsed() >= REQUEST_TTL)
            .map(|(handle, _)| handle.clone())
            .collect();
        for handle in stale {
            self.live.remove(&handle);
        }
        if self.live.len() >= MAX_REQUESTS {
            return None;
        }
        if self.used_order.len() >= 4096 {
            let expired = self
                .used_order
                .iter()
                .position(|handle| !self.live.contains_key(handle))
                .and_then(|position| self.used_order.remove(position));
            if let Some(expired) = expired {
                self.used.remove(&expired);
            }
        }
        let cancellation = Cancellation::new().ok()?;
        let token = cancellation.token();
        self.used.insert(handle.to_owned());
        self.used_order.push_back(handle.to_owned());
        self.live.insert(
            handle.to_owned(),
            LiveRequest {
                owner: owner.to_owned(),
                _cancellation: cancellation,
                started: Instant::now(),
            },
        );
        Some(token)
    }

    pub fn finish(&mut self, handle: &str) {
        self.live.remove(handle);
    }

    pub fn close(&mut self, handle: &str, owner: &str) -> bool {
        if self
            .live
            .get(handle)
            .is_some_and(|request| request.owner == owner)
        {
            self.live.remove(handle);
            true
        } else {
            false
        }
    }

    pub fn caller_disappeared(&mut self, owner: &str) {
        self.live.retain(|_, request| request.owner != owner);
    }

    pub fn contains(&self, handle: &str) -> bool {
        self.live.contains_key(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tools(home: &Path, base: &Path) -> Tools {
        let entries = [
            ("home", home.to_path_buf()),
            ("state", base.join("state")),
            ("profiles", base.join("profiles")),
            ("sandboxes", base.join("sandboxes")),
            ("config", base.join("config")),
        ]
        .into_iter()
        .map(|(key, path)| (key.to_owned(), path.to_string_lossy().into_owned()))
        .chain(
            [
                "runner",
                "picker",
                "core",
                "systemctl",
                "systemd-run",
                "nsenter",
                "unshare",
                "ip",
                "kdialog",
                "notify-send",
                "bwrap",
                "dbus-proxy",
                "xwayland",
                "openssl",
                "certutil",
                "opener",
                "window",
                "busctl",
                "secret-tool",
                "nft",
            ]
            .into_iter()
            .map(|key| (key.to_owned(), "/bin/false".to_owned())),
        )
        .collect();
        Tools::from_entries(Path::new("/manifest"), &entries).unwrap()
    }

    #[test]
    fn png_mime_and_globs_match_only_the_selected_files() {
        let filter = Filter {
            label: "PNG".into(),
            rules: vec![(1, "image/png".into())],
        };
        assert_eq!(filter.rules[0].0, 1);
        assert!(valid_mime("image/png"));
        assert!(valid_mime("image/*"));
        assert!(!valid_mime("*/png"));
    }

    #[test]
    fn choices_are_validated_and_boolean_defaults_are_safe() {
        let boolean = Choice {
            id: "overwrite".into(),
            label: "Overwrite".into(),
            options: vec![],
            initial: "false".into(),
        };
        assert_eq!(boolean.defaults(), ("overwrite".into(), "false".into()));
        assert!(boolean.validate().is_ok());
        assert!(Choice {
            initial: "yes".into(),
            ..boolean.clone()
        }
        .validate()
        .is_err());
        assert!(Choice {
            id: "encoding".into(),
            label: "Encoding".into(),
            options: vec![("utf8".into(), "UTF-8".into())],
            initial: "other".into(),
        }
        .validate()
        .is_err());
    }

    #[test]
    fn request_handles_are_scoped_to_the_caller_and_never_reused() {
        let mut requests = Requests::default();
        let token = requests.begin("/request/one", ":1.1").unwrap();
        assert!(!requests.close("/request/one", ":1.2"));
        assert!(!token.cancelled());
        assert!(requests.close("/request/one", ":1.1"));
        assert!(token.cancelled());
        assert!(requests.begin("/request/one", ":1.1").is_none());
        let token = requests.begin("/request/two", ":1.2").unwrap();
        requests.caller_disappeared(":1.2");
        assert!(token.cancelled());
        assert!(!requests.contains("/request/two"));
    }

    #[derive(Default)]
    struct NoDocuments;
    impl DocumentBackend for NoDocuments {
        fn existing_grant(&self, _: &str, _: &Path, _: Access) -> io::Result<Option<String>> {
            panic!("a same-container file must not become a host document")
        }
        fn export(&self, _: &str, _: &[PathBuf], _: Access) -> io::Result<Vec<String>> {
            panic!("a same-container file must not become a host document")
        }
        fn export_named(&self, _: &str, _: &Path, _: &Path, _: Access) -> io::Result<String> {
            panic!("a same-container file must not become a host document")
        }
    }

    struct Selected(PathBuf);
    impl Chooser for Selected {
        fn select(&self, _: &Request, _: &CancelToken) -> Option<Selection> {
            Some(Selection {
                paths: vec![self.0.clone()],
                choices: vec![],
                current_filter: None,
                confirmed: true,
            })
        }
        fn preview(&self, _: &Request, _: &str, _: &CancelToken) -> bool {
            panic!("a same-container file needs no host-scope preview")
        }
    }

    #[test]
    fn private_container_file_maps_back_to_its_visible_home_without_export() {
        let base = std::env::temp_dir().join(format!(
            "cw-file-chooser-direct-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let home = base.join("home");
        let data = base.join("profiles/work");
        let selected = data.join("home/Pictures/picture.png");
        std::fs::create_dir_all(selected.parent().unwrap()).unwrap();
        std::fs::create_dir_all(base.join("config/containers/work")).unwrap();
        std::fs::create_dir_all(base.join("state")).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(&selected, b"png").unwrap();
        std::fs::write(
            base.join("config/containers/work/container.conf"),
            "home = private\n",
        )
        .unwrap();
        let tools = test_tools(&home, &base);
        let backend = Backend {
            tools,
            chooser: Selected(selected.clone()),
            documents: NoDocuments,
        };
        let cancellation = Cancellation::new().unwrap();
        let response = backend.process(
            &Request {
                app_id: crate::desktop::container_app_id("work"),
                parent_window: String::new(),
                title: "Open".into(),
                accept_label: None,
                modal: true,
                operation: Operation::Open {
                    multiple: false,
                    directory: false,
                },
                filters: vec![],
                current_filter: None,
                choices: vec![],
                current_folder: None,
                current_file: None,
            },
            &cancellation.token(),
        );
        assert_eq!(response.code, RESPONSE_OK);
        assert_eq!(
            response.uris,
            [file_uri(&home.join("Pictures/picture.png"))]
        );
        let _ = std::fs::remove_file(selected);
        let _ = std::fs::remove_file(base.join("config/containers/work/container.conf"));
        for dir in [
            data.join("home/Pictures"),
            data.join("home"),
            data,
            base.join("profiles"),
            base.join("config/containers/work"),
            base.join("config/containers"),
            base.join("config"),
            base.join("state"),
            home,
            base,
        ] {
            let _ = std::fs::remove_dir(dir);
        }
    }

    #[test]
    fn hidden_container_storage_is_not_direct_for_a_layer_home() {
        let base = std::env::temp_dir().join(format!(
            "cw-file-chooser-layer-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(base.join("config/containers/work")).unwrap();
        std::fs::create_dir_all(base.join("profiles/other/home")).unwrap();
        std::fs::write(
            base.join("config/containers/work/container.conf"),
            "home = layer\n",
        )
        .unwrap();
        let home = base.join("home");
        let tools = test_tools(&home, &base);
        let source = Source::resolve(&tools, &crate::desktop::container_app_id("work")).unwrap();
        assert!(source
            .direct_path(&tools, &base.join("profiles/other/home/secret"))
            .is_none());
        let _ = std::fs::remove_file(base.join("config/containers/work/container.conf"));
        for dir in [
            base.join("profiles/other/home"),
            base.join("profiles/other"),
            base.join("profiles"),
            base.join("config/containers/work"),
            base.join("config/containers"),
            base.join("config"),
            base,
        ] {
            let _ = std::fs::remove_dir(dir);
        }
    }

    #[test]
    fn file_uris_percent_encode_non_utf8_and_spaces() {
        use std::os::unix::ffi::OsStrExt;
        let path = PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/a b-\xff"));
        assert_eq!(file_uri(&path), "file:///tmp/a%20b-%FF");
    }

    #[test]
    fn an_unconfirmed_save_selection_is_never_exported() {
        struct Unconfirmed;
        impl Chooser for Unconfirmed {
            fn select(&self, _: &Request, _: &CancelToken) -> Option<Selection> {
                Some(Selection {
                    paths: vec![PathBuf::from("/not-confirmed")],
                    choices: vec![],
                    current_filter: None,
                    confirmed: false,
                })
            }
            fn preview(&self, _: &Request, _: &str, _: &CancelToken) -> bool {
                panic!("unconfirmed path reached preview")
            }
        }
        let cancellation = Cancellation::new().unwrap();
        let backend = Backend {
            tools: test_tools(Path::new("/home/test"), Path::new("/tmp/cw-unconfirmed")),
            chooser: Unconfirmed,
            documents: NoDocuments,
        };
        let response = backend.process(
            &Request {
                app_id: "vpnzone.app.test".into(),
                parent_window: String::new(),
                title: "Save".into(),
                accept_label: None,
                modal: true,
                operation: Operation::Save {
                    current_name: Some("report.txt".into()),
                },
                filters: vec![],
                current_filter: None,
                choices: vec![],
                current_folder: None,
                current_file: Some(PathBuf::from("/must-not-be-exported")),
            },
            &cancellation.token(),
        );
        assert_eq!(response.code, RESPONSE_FAILED);
    }
}
