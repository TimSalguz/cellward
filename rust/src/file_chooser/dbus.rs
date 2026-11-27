//! `org.freedesktop.impl.portal.FileChooser` and its request lifecycle.

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use zbus::message::Header;
use zbus::zvariant::{ObjectPath, Value};
use zbus::{fdo, interface, Connection};

use super::documents::Documents;
use super::gui::HostChooser;
use super::{
    Backend, Choice, Chooser, DocumentBackend, Filter, Operation, Request, Requests, Response,
};
use crate::tools::Tools;

pub const DESKTOP: &str = "/org/freedesktop/portal/desktop";
pub const DEFAULT_NAME: &str = "org.freedesktop.impl.portal.desktop.cellward.filechooser";
type Options<'a> = HashMap<String, Value<'a>>;
type DynChooser = Arc<dyn Chooser>;
type DynDocuments = Arc<dyn DocumentBackend>;

fn failed(error: impl std::fmt::Display) -> fdo::Error {
    fdo::Error::Failed(error.to_string())
}

fn invalid(message: impl Into<String>) -> fdo::Error {
    fdo::Error::InvalidArgs(message.into())
}

fn text_option<'a>(options: &Options<'a>, name: &str) -> fdo::Result<Option<String>> {
    options
        .get(name)
        .map(|value| {
            String::try_from(value).map_err(|_| invalid(format!("{name} must be a string")))
        })
        .transpose()
}

fn bool_option(options: &Options<'_>, name: &str, default: bool) -> fdo::Result<bool> {
    options.get(name).map_or(Ok(default), |value| {
        bool::try_from(value).map_err(|_| invalid(format!("{name} must be boolean")))
    })
}

fn path_bytes(value: &Value<'_>, name: &str) -> fdo::Result<Vec<u8>> {
    let bytes =
        Vec::<u8>::try_from(value.clone()).map_err(|_| invalid(format!("{name} must be ay")))?;
    if bytes.len() < 2 || bytes.last() != Some(&0) || bytes[..bytes.len() - 1].contains(&0) {
        return Err(invalid(format!(
            "{name} must contain one path and a trailing NUL"
        )));
    }
    Ok(bytes[..bytes.len() - 1].to_vec())
}

fn path_option(options: &Options<'_>, name: &str) -> fdo::Result<Option<PathBuf>> {
    let Some(value) = options.get(name) else {
        return Ok(None);
    };
    let path = PathBuf::from(OsString::from_vec(path_bytes(value, name)?));
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(invalid(format!(
            "{name} must be an absolute path without .."
        )));
    }
    Ok(Some(path))
}

fn filter(value: &Value<'_>) -> fdo::Result<Filter> {
    let (label, rules) = <(String, Vec<(u32, String)>)>::try_from(value.clone())
        .map_err(|_| invalid("filter must have signature (sa(us))"))?;
    let filter = Filter { label, rules };
    filter.validate().map_err(invalid)?;
    Ok(filter)
}

fn filters(options: &Options<'_>) -> fdo::Result<Vec<Filter>> {
    let Some(value) = options.get("filters") else {
        return Ok(Vec::new());
    };
    let raw = Vec::<(String, Vec<(u32, String)>)>::try_from(value.clone())
        .map_err(|_| invalid("filters must have signature a(sa(us))"))?;
    if raw.len() > 64 {
        return Err(invalid("too many filters"));
    }
    raw.into_iter()
        .map(|(label, rules)| {
            let filter = Filter { label, rules };
            filter.validate().map_err(invalid)?;
            Ok(filter)
        })
        .collect()
}

fn choices(options: &Options<'_>) -> fdo::Result<Vec<Choice>> {
    let Some(value) = options.get("choices") else {
        return Ok(Vec::new());
    };
    let raw = Vec::<(String, String, Vec<(String, String)>, String)>::try_from(value.clone())
        .map_err(|_| invalid("choices must have signature a(ssa(ss)s)"))?;
    if raw.len() > 32 {
        return Err(invalid("too many choices"));
    }
    let mut ids = std::collections::HashSet::new();
    raw.into_iter()
        .map(|(id, label, options, initial)| {
            if !ids.insert(id.clone()) {
                return Err(invalid("duplicate choice id"));
            }
            let choice = Choice {
                id,
                label,
                options,
                initial,
            };
            choice.validate().map_err(invalid)?;
            Ok(choice)
        })
        .collect()
}

fn short_text(value: String, name: &str, maximum: usize, empty: bool) -> fdo::Result<String> {
    if value.len() > maximum
        || (!empty && value.is_empty())
        || value
            .bytes()
            .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r')
    {
        Err(invalid(format!("invalid {name}")))
    } else {
        Ok(value)
    }
}

enum Method {
    Open,
    Save,
    SaveMany,
}

fn parse_request(
    method: Method,
    app_id: String,
    parent_window: String,
    title: String,
    options: &Options<'_>,
) -> fdo::Result<Request> {
    short_text(app_id.clone(), "app_id", 255, false)?;
    short_text(parent_window.clone(), "parent_window", 256, true)?;
    short_text(title.clone(), "title", 1024, true)?;
    let operation = match method {
        Method::Open => Operation::Open {
            multiple: bool_option(options, "multiple", false)?,
            directory: bool_option(options, "directory", false)?,
        },
        Method::Save => {
            let current_name = match text_option(options, "current_name")? {
                Some(name) => {
                    let name = short_text(name, "current_name", 255, false)?;
                    if name.contains('/') || matches!(name.as_str(), "." | "..") {
                        return Err(invalid("current_name must be a basename"));
                    }
                    Some(name)
                }
                None => None,
            };
            Operation::Save { current_name }
        }
        Method::SaveMany => {
            let raw = options
                .get("files")
                .map(|value| {
                    Vec::<Vec<u8>>::try_from(value.clone())
                        .map_err(|_| invalid("files must have signature aay"))
                })
                .transpose()?
                .ok_or_else(|| invalid("SaveFiles requires files"))?;
            if raw.is_empty() || raw.len() > 128 {
                return Err(invalid("SaveFiles requires between 1 and 128 names"));
            }
            let mut names = Vec::with_capacity(raw.len());
            for bytes in raw {
                if bytes.last() != Some(&0) || bytes[..bytes.len().saturating_sub(1)].contains(&0) {
                    return Err(invalid("every SaveFiles name must end with one NUL"));
                }
                let name = PathBuf::from(OsString::from_vec(bytes[..bytes.len() - 1].to_vec()));
                if name.components().count() != 1
                    || !matches!(name.components().next(), Some(Component::Normal(_)))
                    || name.as_os_str().len() > 255
                {
                    return Err(invalid("SaveFiles names must be plain basenames"));
                }
                names.push(name);
            }
            Operation::SaveMany { files: names }
        }
    };
    let filters = filters(options)?;
    let current_filter = options.get("current_filter").map(filter).transpose()?;
    if current_filter
        .as_ref()
        .is_some_and(|current| !filters.is_empty() && !filters.contains(current))
    {
        return Err(invalid("current_filter is not in filters"));
    }
    Ok(Request {
        app_id,
        parent_window,
        title,
        accept_label: text_option(options, "accept_label")?
            .map(|label| short_text(label, "accept_label", 256, false))
            .transpose()?,
        modal: bool_option(options, "modal", true)?,
        operation,
        filters,
        current_filter,
        choices: choices(options)?,
        current_folder: path_option(options, "current_folder")?,
        current_file: path_option(options, "current_file")?,
    })
}

fn result(response: Response) -> (u32, Options<'static>) {
    let mut results = Options::new();
    if response.code == super::RESPONSE_OK {
        results.insert("uris".into(), Value::new(response.uris));
        results.insert("choices".into(), Value::new(response.choices));
        if let Some(filter) = response.current_filter {
            results.insert(
                "current_filter".into(),
                Value::new((filter.label, filter.rules)),
            );
        }
        results.insert("writable".into(), Value::Bool(response.writable));
    }
    (response.code, results)
}

struct ImplRequest {
    requests: Arc<Mutex<Requests>>,
    handle: String,
}

#[interface(name = "org.freedesktop.impl.portal.Request")]
impl ImplRequest {
    fn close(&self, #[zbus(header)] header: Header<'_>) -> fdo::Result<()> {
        let owner = header
            .sender()
            .ok_or_else(|| failed("missing D-Bus sender"))?
            .to_string();
        if self
            .requests
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .close(&self.handle, &owner)
        {
            Ok(())
        } else {
            Err(fdo::Error::AccessDenied(
                "request handle is stale or belongs to another caller".into(),
            ))
        }
    }
}

pub struct Portal {
    backend: Arc<Backend<DynChooser, DynDocuments>>,
    requests: Arc<Mutex<Requests>>,
}

impl Portal {
    pub fn new(tools: Tools, chooser: DynChooser, documents: DynDocuments) -> Self {
        Self {
            backend: Arc::new(Backend {
                tools,
                chooser,
                documents,
            }),
            requests: Arc::new(Mutex::new(Requests::default())),
        }
    }

    fn watch_caller(
        connection: &Connection,
        requests: Arc<Mutex<Requests>>,
        handle: String,
        owner: String,
    ) {
        let connection = zbus::blocking::Connection::from(connection.clone());
        std::thread::spawn(move || {
            let Ok(proxy) = zbus::blocking::Proxy::new(
                &connection,
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
            ) else {
                requests
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .caller_disappeared(&owner);
                return;
            };
            loop {
                std::thread::sleep(std::time::Duration::from_millis(100));
                let alive = proxy.call::<_, _, String>("GetNameOwner", &owner).is_ok();
                let mut requests = requests.lock().unwrap_or_else(|error| error.into_inner());
                if !alive {
                    requests.caller_disappeared(&owner);
                    break;
                }
                if !requests.contains(&handle) {
                    break;
                }
            }
        });
    }

    async fn execute(
        &self,
        connection: &Connection,
        header: Header<'_>,
        handle: ObjectPath<'_>,
        request: Request,
    ) -> fdo::Result<(u32, Options<'static>)> {
        let owner = header
            .sender()
            .ok_or_else(|| failed("missing D-Bus sender"))?
            .to_string();
        let frontend: String = zbus::Proxy::new(
            connection,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )
        .await
        .map_err(failed)?
        .call::<_, _, String>("GetNameOwner", &"org.freedesktop.portal.Desktop")
        .await
        .map_err(failed)?;
        if frontend != owner {
            return Ok((super::RESPONSE_FAILED, Options::new()));
        }
        let handle = handle.to_string();
        let token = self
            .requests
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .begin(&handle, &owner)
            .ok_or_else(|| invalid("request handle is stale, duplicated, or invalid"))?;
        connection
            .object_server()
            .at(
                handle.clone(),
                ImplRequest {
                    requests: self.requests.clone(),
                    handle: handle.clone(),
                },
            )
            .await
            .map_err(failed)?;
        Self::watch_caller(connection, self.requests.clone(), handle.clone(), owner);
        let backend = self.backend.clone();
        let response = blocking::unblock(move || backend.process(&request, &token)).await;
        self.requests
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .finish(&handle);
        Ok(result(response))
    }
}

#[allow(clippy::too_many_arguments)]
#[interface(name = "org.freedesktop.impl.portal.FileChooser")]
impl Portal {
    async fn open_file(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        handle: ObjectPath<'_>,
        app_id: String,
        parent_window: String,
        title: String,
        options: Options<'_>,
    ) -> fdo::Result<(u32, Options<'static>)> {
        let request = parse_request(Method::Open, app_id, parent_window, title, &options)?;
        self.execute(connection, header, handle, request).await
    }

    async fn save_file(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        handle: ObjectPath<'_>,
        app_id: String,
        parent_window: String,
        title: String,
        options: Options<'_>,
    ) -> fdo::Result<(u32, Options<'static>)> {
        let request = parse_request(Method::Save, app_id, parent_window, title, &options)?;
        self.execute(connection, header, handle, request).await
    }

    async fn save_files(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        handle: ObjectPath<'_>,
        app_id: String,
        parent_window: String,
        title: String,
        options: Options<'_>,
    ) -> fdo::Result<(u32, Options<'static>)> {
        let request = parse_request(Method::SaveMany, app_id, parent_window, title, &options)?;
        self.execute(connection, header, handle, request).await
    }
}

fn builder(address: Option<&str>) -> zbus::Result<zbus::blocking::connection::Builder<'_>> {
    match address {
        Some(address) => zbus::blocking::connection::Builder::address(address),
        None => zbus::blocking::connection::Builder::session(),
    }
}

pub fn run(args: &[OsString]) -> u8 {
    let mut address = None;
    let mut name = None;
    let mut words = args.iter();
    while let Some(word) = words.next() {
        let Some(value) = words.next() else {
            eprintln!("cellward-file-chooser: {word:?} needs a value");
            return 2;
        };
        match word.to_str() {
            Some("--address") => {
                let Some(value) = value.to_str() else {
                    eprintln!("cellward-file-chooser: --address must be UTF-8");
                    return 2;
                };
                address = Some(value.to_owned());
            }
            Some("--name") => {
                let Some(value) = value.to_str().filter(|value| !value.is_empty()) else {
                    eprintln!("cellward-file-chooser: --name must be non-empty UTF-8");
                    return 2;
                };
                name = Some(value.to_owned());
            }
            _ => {
                eprintln!("cellward-file-chooser: unknown option {word:?}");
                return 2;
            }
        }
    }
    let tools = match Tools::from_env() {
        Ok(tools) => tools,
        Err(error) => {
            eprintln!("cellward-file-chooser: {error}");
            return 2;
        }
    };
    let documents = match builder(address.as_deref()).and_then(|builder| builder.build()) {
        Ok(connection) => Documents::new(connection),
        Err(error) => {
            eprintln!("cellward-file-chooser: cannot connect to the document portal: {error}");
            return 1;
        }
    };
    let portal = Portal::new(
        tools.clone(),
        Arc::new(HostChooser { tools }),
        Arc::new(documents),
    );
    let name = name.unwrap_or_else(|| DEFAULT_NAME.to_owned());
    let connection = builder(address.as_deref()).and_then(|builder| {
        builder
            .name(name.as_str())?
            .serve_at(DESKTOP, portal)?
            .build()
    });
    let _connection = match connection {
        Ok(connection) => connection,
        Err(error) => {
            eprintln!("cellward-file-chooser: cannot start D-Bus backend: {error}");
            return 1;
        }
    };
    eprintln!("cellward-file-chooser: {name} is ready");
    loop {
        std::thread::park();
    }
}

pub fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ExitCode::from(run(&args))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_chooser::Access;

    #[test]
    fn malformed_filters_choices_and_save_paths_are_rejected() {
        let options = Options::from([(
            "filters".into(),
            Value::new(vec![(
                "PNG".to_owned(),
                vec![(1u32, "image/png".to_owned())],
            )]),
        )]);
        assert_eq!(filters(&options).unwrap().len(), 1);
        let options = Options::from([(
            "current_filter".into(),
            Value::new(("PNG".to_owned(), vec![(9u32, "bad".to_owned())])),
        )]);
        assert!(filter(options.get("current_filter").unwrap()).is_err());
        let options = Options::from([("files".into(), Value::new(vec![b"../outside\0".to_vec()]))]);
        assert!(parse_request(
            Method::SaveMany,
            "vpnzone.app.test".into(),
            String::new(),
            "Save".into(),
            &options,
        )
        .is_err());
    }

    #[test]
    fn save_file_current_file_is_only_a_gui_suggestion() {
        let options = Options::from([(
            "current_file".into(),
            Value::new(b"/host/existing.txt\0".to_vec()),
        )]);
        let request = parse_request(
            Method::Save,
            "vpnzone.app.test".into(),
            String::new(),
            "Save".into(),
            &options,
        )
        .unwrap();
        assert_eq!(
            request.current_file,
            Some(PathBuf::from("/host/existing.txt"))
        );
        assert!(request.accept_label.is_none());
    }

    #[test]
    fn access_rights_never_include_grant_or_delete() {
        assert_eq!(Access::Read.permissions(), ["read"]);
        assert_eq!(Access::ReadWrite.permissions(), ["read", "write"]);
    }
}

#[cfg(test)]
mod smoke {
    use super::*;
    use crate::file_chooser::{Selection, RESPONSE_CANCELLED, RESPONSE_FAILED, RESPONSE_OK};
    use crate::sys::CancelToken;
    use std::io::{BufRead, BufReader};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use zbus::blocking::Proxy;
    use zbus::zvariant::{OwnedFd, OwnedValue};

    const DOCUMENTS_PATH: &str = "/org/freedesktop/portal/documents";
    const DOCUMENTS_NAME: &str = "org.freedesktop.portal.Documents";
    const MOUNT: &str = "/run/cellward-test/doc";
    type DocumentInfo = (Vec<u8>, HashMap<String, Vec<String>>);

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        Full {
            app_id: String,
            permissions: Vec<String>,
            paths: Vec<PathBuf>,
        },
        Named {
            app_id: String,
            permissions: Vec<String>,
            parent: PathBuf,
            name: PathBuf,
        },
    }

    #[derive(Debug, Clone)]
    struct Grant {
        id: String,
        app_id: String,
        permissions: Vec<String>,
    }

    #[derive(Default)]
    struct FakeState {
        next: usize,
        calls: Vec<Call>,
        grants: HashMap<PathBuf, Grant>,
    }

    struct FakeDocuments {
        state: Arc<Mutex<FakeState>>,
    }

    impl FakeDocuments {
        fn add(&self, path: PathBuf, app_id: String, permissions: Vec<String>) -> String {
            let mut state = self.state.lock().unwrap();
            state.next += 1;
            let id = format!("doc{}", state.next);
            state.grants.insert(
                path,
                Grant {
                    id: id.clone(),
                    app_id,
                    permissions,
                },
            );
            id
        }

        fn extra() -> Options<'static> {
            Options::from([(
                "mountpoint".to_owned(),
                Value::new(format!("{MOUNT}\0").into_bytes()),
            )])
        }
    }

    fn fd_path(fd: &OwnedFd) -> PathBuf {
        std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap()
    }

    #[interface(name = "org.freedesktop.portal.Documents")]
    impl FakeDocuments {
        fn get_mount_point(&self) -> Vec<u8> {
            format!("{MOUNT}\0").into_bytes()
        }

        fn add_full(
            &self,
            fds: Vec<OwnedFd>,
            flags: u32,
            app_id: String,
            permissions: Vec<String>,
        ) -> fdo::Result<(Vec<String>, Options<'static>)> {
            if flags != 3 {
                return Err(fdo::Error::InvalidArgs(
                    "grant must be reused and persistent".into(),
                ));
            }
            let paths: Vec<PathBuf> = fds.iter().map(fd_path).collect();
            self.state.lock().unwrap().calls.push(Call::Full {
                app_id: app_id.clone(),
                permissions: permissions.clone(),
                paths: paths.clone(),
            });
            let ids = paths
                .into_iter()
                .map(|path| self.add(path, app_id.clone(), permissions.clone()))
                .collect();
            Ok((ids, Self::extra()))
        }

        fn add_named_full(
            &self,
            fd: OwnedFd,
            filename: Vec<u8>,
            flags: u32,
            app_id: String,
            permissions: Vec<String>,
        ) -> fdo::Result<(String, Options<'static>)> {
            if flags != 3 {
                return Err(fdo::Error::InvalidArgs(
                    "grant must be reused and persistent".into(),
                ));
            }
            let parent = fd_path(&fd);
            let name = PathBuf::from(OsString::from_vec(filename));
            self.state.lock().unwrap().calls.push(Call::Named {
                app_id: app_id.clone(),
                permissions: permissions.clone(),
                parent: parent.clone(),
                name: name.clone(),
            });
            let id = self.add(parent.join(name), app_id, permissions);
            Ok((id, Self::extra()))
        }

        fn lookup(&self, filename: Vec<u8>) -> fdo::Result<String> {
            let path = PathBuf::from(OsString::from_vec(filename));
            self.state
                .lock()
                .unwrap()
                .grants
                .get(&path)
                .map(|grant| grant.id.clone())
                .ok_or_else(|| fdo::Error::Failed("not a document".into()))
        }

        fn info(&self, id: String) -> fdo::Result<DocumentInfo> {
            let state = self.state.lock().unwrap();
            let (path, grant) = state
                .grants
                .iter()
                .find(|(_, grant)| grant.id == id)
                .ok_or_else(|| fdo::Error::Failed("not a document".into()))?;
            Ok((
                path.as_os_str().as_bytes().to_vec(),
                HashMap::from([(grant.app_id.clone(), grant.permissions.clone())]),
            ))
        }
    }

    struct FakeChooser {
        paths: Mutex<Vec<PathBuf>>,
        confirmed: Mutex<bool>,
        allow_preview: Mutex<bool>,
        previews: Mutex<usize>,
        wait_for_close: Mutex<bool>,
        started: Mutex<usize>,
        folders: Mutex<Vec<Option<PathBuf>>>,
    }

    impl FakeChooser {
        fn new() -> Self {
            Self {
                paths: Mutex::new(Vec::new()),
                confirmed: Mutex::new(true),
                allow_preview: Mutex::new(true),
                previews: Mutex::new(0),
                wait_for_close: Mutex::new(false),
                started: Mutex::new(0),
                folders: Mutex::new(Vec::new()),
            }
        }

        fn set(&self, paths: Vec<PathBuf>, confirmed: bool, preview: bool) {
            *self.paths.lock().unwrap() = paths;
            *self.confirmed.lock().unwrap() = confirmed;
            *self.allow_preview.lock().unwrap() = preview;
        }
    }

    impl Chooser for FakeChooser {
        fn select(&self, request: &Request, cancel: &CancelToken) -> Option<Selection> {
            *self.started.lock().unwrap() += 1;
            self.folders
                .lock()
                .unwrap()
                .push(request.current_folder.clone());
            if *self.wait_for_close.lock().unwrap() {
                while !cancel.cancelled() {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                return None;
            }
            let paths = self.paths.lock().unwrap().clone();
            if paths.is_empty() {
                return None;
            }
            Some(Selection {
                paths,
                choices: request.choices.iter().map(Choice::defaults).collect(),
                current_filter: request
                    .current_filter
                    .clone()
                    .or_else(|| request.filters.first().cloned()),
                confirmed: *self.confirmed.lock().unwrap(),
            })
        }

        fn preview(&self, _: &Request, _: &str, _: &CancelToken) -> bool {
            *self.previews.lock().unwrap() += 1;
            *self.allow_preview.lock().unwrap()
        }
    }

    struct Bus(Child);

    impl Drop for Bus {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn private_bus() -> (Bus, String) {
        let config = std::env::var("CELLWARD_TEST_DBUS_CONFIG")
            .map(|path| format!("--config-file={path}"))
            .unwrap_or_else(|_| "--session".to_owned());
        let mut bus = Bus(Command::new("dbus-daemon")
            .args([config.as_str(), "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap());
        let mut address = String::new();
        BufReader::new(bus.0.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        let address = address.trim().split(';').next().unwrap().to_owned();
        (bus, address)
    }

    fn connect(address: &str) -> zbus::blocking::Connection {
        zbus::blocking::connection::Builder::address(address)
            .unwrap()
            .build()
            .unwrap()
    }

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "cellward-file-chooser-smoke-{}-{nonce}",
                std::process::id()
            ));
            for dir in ["host", "home", "state", "profiles", "sandboxes", "config"] {
                std::fs::create_dir_all(root.join(dir)).unwrap();
            }
            std::fs::write(root.join("host/picture.png"), b"synthetic png").unwrap();
            std::fs::write(root.join("host/second.png"), b"synthetic png 2").unwrap();
            std::fs::create_dir_all(root.join("config/containers/work")).unwrap();
            std::fs::create_dir_all(root.join("profiles/work/home")).unwrap();
            std::fs::write(
                root.join("config/containers/work/container.conf"),
                "home = private\n",
            )
            .unwrap();
            Self { root }
        }

        fn tools(&self) -> Tools {
            let entries = [
                ("home", self.root.join("home")),
                ("state", self.root.join("state")),
                ("profiles", self.root.join("profiles")),
                ("sandboxes", self.root.join("sandboxes")),
                ("config", self.root.join("config")),
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
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            for file in [
                "host/picture.png",
                "host/second.png",
                "config/containers/work/container.conf",
            ] {
                let _ = std::fs::remove_file(self.root.join(file));
            }
            for dir in [
                "profiles/work/home",
                "profiles/work",
                "config/containers/work",
                "config/containers",
                "host",
                "home",
                "state",
                "profiles",
                "sandboxes",
                "config",
            ] {
                let _ = std::fs::remove_dir(self.root.join(dir));
            }
            let _ = std::fs::remove_dir(&self.root);
        }
    }

    fn handle(name: &str) -> ObjectPath<'static> {
        ObjectPath::try_from(format!("/org/cellward/file/request/{name}")).unwrap()
    }

    fn owned_results(
        proxy: &Proxy<'_>,
        method: &str,
        handle: &ObjectPath<'_>,
        app_id: &str,
        options: Options<'_>,
    ) -> zbus::Result<(u32, HashMap<String, OwnedValue>)> {
        proxy.call(
            method,
            &(handle.clone(), app_id, "", "File chooser", options),
        )
    }

    fn uris(results: &HashMap<String, OwnedValue>) -> Vec<String> {
        Vec::<String>::try_from(Value::from(results["uris"].clone())).unwrap()
    }

    #[test]
    fn isolated_open_save_cancel_foreign_stale_and_unconfirmed_paths() {
        let fixture = Fixture::new();
        let (_bus, address) = private_bus();
        let fake_state = Arc::new(Mutex::new(FakeState::default()));
        let _documents_server = zbus::blocking::connection::Builder::address(address.as_str())
            .unwrap()
            .name(DOCUMENTS_NAME)
            .unwrap()
            .serve_at(
                DOCUMENTS_PATH,
                FakeDocuments {
                    state: fake_state.clone(),
                },
            )
            .unwrap()
            .build()
            .unwrap();
        let chooser = Arc::new(FakeChooser::new());
        let documents = Documents::new(connect(&address));
        let portal = Portal::new(fixture.tools(), chooser.clone(), Arc::new(documents));
        let _portal_server = zbus::blocking::connection::Builder::address(address.as_str())
            .unwrap()
            .name(DEFAULT_NAME)
            .unwrap()
            .serve_at(DESKTOP, portal)
            .unwrap()
            .build()
            .unwrap();
        let client = connect(&address);
        client
            .request_name("org.freedesktop.portal.Desktop")
            .unwrap();
        let portal = Proxy::new(
            &client,
            DEFAULT_NAME,
            DESKTOP,
            "org.freedesktop.impl.portal.FileChooser",
        )
        .unwrap();
        let picture = fixture.root.join("host/picture.png");
        chooser.set(vec![picture.clone()], true, true);
        let png = Filter {
            label: "PNG images".into(),
            rules: vec![(1, "image/png".into())],
        };
        let options = Options::from([
            (
                "filters".into(),
                Value::new(vec![(png.label.clone(), png.rules.clone())]),
            ),
            (
                "current_filter".into(),
                Value::new((png.label.clone(), png.rules.clone())),
            ),
            (
                "choices".into(),
                Value::new(vec![(
                    "readonly".to_owned(),
                    "Read only".to_owned(),
                    Vec::<(String, String)>::new(),
                    "true".to_owned(),
                )]),
            ),
        ]);
        let container_app = crate::desktop::container_app_id("work");
        let (code, results) = owned_results(
            &portal,
            "OpenFile",
            &handle("open"),
            &container_app,
            options,
        )
        .unwrap();
        assert_eq!(code, RESPONSE_OK);
        assert_eq!(uris(&results), [format!("file://{MOUNT}/doc1/picture.png")]);
        assert_eq!(
            Vec::<(String, String)>::try_from(Value::from(results["choices"].clone())).unwrap(),
            [("readonly".to_owned(), "true".to_owned())]
        );
        let returned_filter = <(String, Vec<(u32, String)>)>::try_from(Value::from(
            results["current_filter"].clone(),
        ))
        .unwrap();
        assert_eq!(returned_filter, (png.label.clone(), png.rules.clone()));
        let calls = fake_state.lock().unwrap().calls.clone();
        assert_eq!(
            calls,
            [Call::Full {
                app_id: container_app.clone(),
                permissions: vec!["read".into()],
                paths: vec![picture.clone()],
            }]
        );

        let output = fixture.root.join("host/output.txt");
        chooser.set(vec![output.clone()], true, true);
        let save_options = Options::from([(
            "current_file".into(),
            Value::new(b"/must/not/be/silently/overwritten\0".to_vec()),
        )]);
        let (code, results) = owned_results(
            &portal,
            "SaveFile",
            &handle("save"),
            "vpnzone.app.test",
            save_options,
        )
        .unwrap();
        assert_eq!(code, RESPONSE_OK);
        assert_eq!(uris(&results), [format!("file://{MOUNT}/doc2/output.txt")]);
        assert!(fake_state.lock().unwrap().calls.iter().any(|call| {
            call == &Call::Named {
                app_id: "vpnzone.app.test".into(),
                permissions: vec!["read".into(), "write".into()],
                parent: fixture.root.join("host"),
                name: PathBuf::from("output.txt"),
            }
        }));

        chooser.set(Vec::new(), true, true);
        let before = fake_state.lock().unwrap().calls.len();
        let (code, _) = owned_results(
            &portal,
            "OpenFile",
            &handle("cancel"),
            "vpnzone.app.test",
            Options::new(),
        )
        .unwrap();
        assert_eq!(code, RESPONSE_CANCELLED);
        assert_eq!(fake_state.lock().unwrap().calls.len(), before);

        chooser.set(vec![picture.clone()], true, true);
        let (code, _) = owned_results(
            &portal,
            "OpenFile",
            &handle("foreign"),
            "org.example.foreign",
            Options::new(),
        )
        .unwrap();
        assert_eq!(code, RESPONSE_FAILED);
        assert_eq!(fake_state.lock().unwrap().calls.len(), before);

        let foreign_client = connect(&address);
        let foreign_portal = Proxy::new(
            &foreign_client,
            DEFAULT_NAME,
            DESKTOP,
            "org.freedesktop.impl.portal.FileChooser",
        )
        .unwrap();
        let (code, _) = owned_results(
            &foreign_portal,
            "OpenFile",
            &handle("not_frontend"),
            &container_app,
            Options::new(),
        )
        .unwrap();
        assert_eq!(code, RESPONSE_FAILED);
        assert_eq!(fake_state.lock().unwrap().calls.len(), before);

        chooser.set(vec![picture.clone()], false, true);
        let (code, _) = owned_results(
            &portal,
            "SaveFile",
            &handle("unconfirmed"),
            "vpnzone.app.test",
            Options::new(),
        )
        .unwrap();
        assert_eq!(code, RESPONSE_FAILED);
        assert_eq!(fake_state.lock().unwrap().calls.len(), before);

        assert!(owned_results(
            &portal,
            "OpenFile",
            &handle("open"),
            "vpnzone.app.test",
            Options::new()
        )
        .is_err());
        let open_handle = handle("open");
        let stale = Proxy::new(
            &foreign_client,
            DEFAULT_NAME,
            open_handle.as_str(),
            "org.freedesktop.impl.portal.Request",
        )
        .unwrap();
        let close: zbus::Result<()> = stale.call("Close", &());
        assert!(close.is_err());

        chooser.set(vec![picture.clone()], true, false);
        let previews = *chooser.previews.lock().unwrap();
        let before = fake_state.lock().unwrap().calls.len();
        let (code, results) = owned_results(
            &portal,
            "OpenFile",
            &handle("existing"),
            &container_app,
            Options::new(),
        )
        .unwrap();
        assert_eq!(code, RESPONSE_OK);
        assert_eq!(uris(&results), [format!("file://{MOUNT}/doc1/picture.png")]);
        assert_eq!(fake_state.lock().unwrap().calls.len(), before);
        assert_eq!(*chooser.previews.lock().unwrap(), previews);

        chooser.set(vec![fixture.root.join("host")], true, true);
        let directory = Options::from([("directory".into(), Value::Bool(true))]);
        let (code, results) = owned_results(
            &portal,
            "OpenFile",
            &handle("directory"),
            &container_app,
            directory,
        )
        .unwrap();
        assert_eq!(code, RESPONSE_OK);
        assert_eq!(uris(&results), [format!("file://{MOUNT}/doc3/host")]);
        chooser.set(vec![fixture.root.join("host")], true, false);
        let before = fake_state.lock().unwrap().calls.len();
        let previews = *chooser.previews.lock().unwrap();
        let directory = Options::from([
            ("directory".into(), Value::Bool(true)),
            (
                "current_folder".into(),
                Value::new(format!("{MOUNT}/doc3\0").into_bytes()),
            ),
        ]);
        let (code, results) = owned_results(
            &portal,
            "OpenFile",
            &handle("directory_existing"),
            &container_app,
            directory,
        )
        .unwrap();
        assert_eq!(code, RESPONSE_OK);
        assert_eq!(uris(&results), [format!("file://{MOUNT}/doc3/host")]);
        assert_eq!(fake_state.lock().unwrap().calls.len(), before);
        assert_eq!(*chooser.previews.lock().unwrap(), previews);
        assert_eq!(
            chooser.folders.lock().unwrap().last().unwrap().clone(),
            Some(fixture.root.join("host"))
        );

        chooser.set(
            vec![picture.clone(), fixture.root.join("host/second.png")],
            true,
            true,
        );
        let multiple = Options::from([("multiple".into(), Value::Bool(true))]);
        let (code, results) = owned_results(
            &portal,
            "OpenFile",
            &handle("multiple"),
            &container_app,
            multiple,
        )
        .unwrap();
        assert_eq!(code, RESPONSE_OK);
        assert_eq!(uris(&results).len(), 2);

        chooser.set(vec![picture.clone()], true, true);
        *chooser.wait_for_close.lock().unwrap() = true;
        let started = *chooser.started.lock().unwrap();
        let worker_client = client.clone();
        let worker = std::thread::spawn(move || {
            let portal = Proxy::new(
                &worker_client,
                DEFAULT_NAME,
                DESKTOP,
                "org.freedesktop.impl.portal.FileChooser",
            )
            .unwrap();
            owned_results(
                &portal,
                "OpenFile",
                &handle("live_close"),
                "vpnzone.app.test",
                Options::new(),
            )
            .unwrap()
        });
        while *chooser.started.lock().unwrap() == started {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let live_handle = handle("live_close");
        let foreign_close = Proxy::new(
            &foreign_client,
            DEFAULT_NAME,
            live_handle.as_str(),
            "org.freedesktop.impl.portal.Request",
        )
        .unwrap();
        let refused: zbus::Result<()> = foreign_close.call("Close", &());
        assert!(refused.is_err());
        let owner_close = Proxy::new(
            &client,
            DEFAULT_NAME,
            live_handle.as_str(),
            "org.freedesktop.impl.portal.Request",
        )
        .unwrap();
        let closed: zbus::Result<()> = owner_close.call("Close", &());
        assert!(closed.is_ok());
        let (code, _) = worker.join().unwrap();
        assert_eq!(code, RESPONSE_CANCELLED);
        *chooser.wait_for_close.lock().unwrap() = false;

        chooser.set(vec![fixture.root.join("host")], true, true);
        let save_many = Options::from([(
            "files".into(),
            Value::new(vec![b"one.txt\0".to_vec(), b"two.txt\0".to_vec()]),
        )]);
        let (code, results) = owned_results(
            &portal,
            "SaveFiles",
            &handle("save_many"),
            "vpnzone.app.test",
            save_many,
        )
        .unwrap();
        assert_eq!(code, RESPONSE_OK);
        assert_eq!(uris(&results).len(), 2);
        assert!(uris(&results)[0].ends_with("/one.txt"));
        assert!(uris(&results)[1].ends_with("/two.txt"));
        assert!(fake_state.lock().unwrap().calls.iter().all(|call| {
            match call {
                Call::Full { permissions, .. } | Call::Named { permissions, .. } => {
                    permissions == &["read"] || permissions == &["read", "write"]
                }
            }
        }));

        chooser.set(vec![picture.clone()], true, true);
        *chooser.wait_for_close.lock().unwrap() = true;
        let started = *chooser.started.lock().unwrap();
        let dying_client = client.clone();
        let worker = std::thread::spawn(move || {
            let portal = Proxy::new(
                &dying_client,
                DEFAULT_NAME,
                DESKTOP,
                "org.freedesktop.impl.portal.FileChooser",
            )
            .unwrap();
            owned_results(
                &portal,
                "OpenFile",
                &handle("caller_disappears"),
                "vpnzone.app.test",
                Options::new(),
            )
        });
        while *chooser.started.lock().unwrap() == started {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        client.clone().close().unwrap();
        assert!(worker.join().unwrap().is_err());
    }
}
