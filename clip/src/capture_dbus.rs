//! D-Bus ScreenCast v6 adapter for the transport-independent session registry.

use crate::capture_portal::{Error, Registry, Source, Status};
use std::collections::HashMap;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
#[allow(dead_code)]
#[path = "../../shared/json.rs"]
mod json;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{ObjectPath, OwnedFd, Value};
use zbus::{fdo, interface, Connection};

const DESKTOP: &str = "/org/freedesktop/portal/desktop";
type Options<'a> = HashMap<String, Value<'a>>;
type Provider = dyn Fn() -> Vec<Source> + Send + Sync;

fn failed(error: impl std::fmt::Display) -> fdo::Error {
    fdo::Error::Failed(error.to_string())
}

fn transition(error: Error) -> u32 {
    match error {
        Error::UnknownSession | Error::InvalidTransition => 2,
        Error::NoSources | Error::AmbiguousSource => 1,
    }
}

fn choose_capture_id_with(
    available: &[Source],
    multiple: bool,
    capture_id: Option<&str>,
    kdialog: Option<&Path>,
    choose: impl FnOnce() -> io::Result<String>,
) -> Result<Option<String>, Error> {
    if available.is_empty() {
        return Err(Error::NoSources);
    }
    if capture_id.is_some() || multiple || available.len() == 1 {
        return Ok(capture_id.map(str::to_owned));
    }
    if available.len() > 64 {
        return Err(Error::AmbiguousSource);
    }
    if kdialog.is_none() {
        return Err(Error::AmbiguousSource);
    }
    let selected = choose()
        .map_err(|_| Error::AmbiguousSource)?
        .trim()
        .to_owned();
    if selected.is_empty() || !available.iter().any(|source| source.capture_id == selected) {
        return Err(Error::AmbiguousSource);
    }
    Ok(Some(selected))
}

fn choose_capture_id(
    available: &[Source],
    multiple: bool,
    capture_id: Option<&str>,
    kdialog: Option<&Path>,
) -> Result<Option<String>, Error> {
    let Some(program) = kdialog else {
        return choose_capture_id_with(available, multiple, capture_id, None, || unreachable!());
    };
    let mut command = Command::new(program);
    command
        .arg("--menu")
        .arg("Choose a Cellward capture source");
    for source in available {
        command.arg(&source.capture_id).arg(&source.capture_id);
    }
    choose_capture_id_with(available, multiple, capture_id, kdialog, || {
        let output = command.output()?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        } else {
            Err(io::Error::other("capture chooser was cancelled"))
        }
    })
}

#[derive(Clone)]
struct Recorder {
    cellward: PathBuf,
    transition: Arc<Mutex<()>>,
}

impl Recorder {
    fn new(cellward: PathBuf) -> Self {
        Self {
            cellward,
            transition: Arc::new(Mutex::new(())),
        }
    }
}

type Recording = Arc<Mutex<Option<i32>>>;
type Recordings = Arc<Mutex<HashMap<String, Recording>>>;

impl Recorder {
    fn start_focused(&self) -> Option<i32> {
        let output = Command::new(&self.cellward)
            .args(["focused", "--json"])
            .output()
            .ok()?;
        if !output.status.success() {
            eprintln!(
                "cellward-capture-portal: cannot find the focused window: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
            return None;
        }
        let focused = json::parse(String::from_utf8_lossy(&output.stdout).trim()).ok()?;
        let pid = i32::try_from(focused.get("pid")?.as_i64()?).ok()?;
        let status = Command::new(&self.cellward)
            .arg("window-record")
            .arg("--pid")
            .arg(pid.to_string())
            .stdout(Stdio::null())
            .status()
            .ok()?;
        if !status.success() {
            eprintln!("cellward-capture-portal: cannot start the focused PipeWire source");
        }
        status.success().then_some(pid)
    }

    fn stop(&self, pid: i32) {
        let _ = Command::new(&self.cellward)
            .arg("window-record")
            .arg("--pid")
            .arg(pid.to_string())
            .arg("--stop")
            .stdout(Stdio::null())
            .status();
    }

    fn available(
        &self,
        available: &Provider,
        recordings: &Recordings,
        handle: &str,
    ) -> (Vec<Source>, Option<i32>) {
        let _transition = self
            .transition
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let existing = (available)();
        let already_recording = recordings
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(handle)
            .and_then(|recording| *recording.lock().unwrap_or_else(|error| error.into_inner()))
            .is_some();
        if !existing.is_empty() || already_recording {
            return (existing, None);
        }
        let Some(pid) = self.start_focused() else {
            return (existing, None);
        };
        for _ in 0..50 {
            let sources = (available)();
            if !sources.is_empty() {
                return (sources, Some(pid));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        self.stop(pid);
        (Vec::new(), None)
    }
}

fn close_session(recorder: &Option<Recorder>, recordings: &Recordings, handle: &str) {
    let recording = recordings
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .remove(handle);
    let pid = recording.and_then(|recording| {
        recording
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
    });
    if let (Some(recorder), Some(pid)) = (recorder, pid) {
        recorder.stop(pid);
    }
}

fn token(options: &Options<'_>, name: &str) -> fdo::Result<String> {
    let token = options
        .get(name)
        .and_then(|value| String::try_from(value).ok())
        .unwrap_or_else(|| "request".to_owned());
    if token.is_empty()
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(fdo::Error::InvalidArgs("invalid handle token".into()));
    }
    Ok(token)
}

fn request_path(options: &Options<'_>) -> fdo::Result<ObjectPath<'static>> {
    ObjectPath::try_from(format!(
        "/org/cellward/capture/request/{}",
        token(options, "handle_token")?
    ))
    .map_err(failed)
}

fn emitter_for(connection: &Connection, path: ObjectPath<'static>) -> SignalEmitter<'static> {
    SignalEmitter::from_parts(connection.clone(), path)
}

async fn empty_response(emitter: &SignalEmitter<'_>, code: u32) -> fdo::Result<()> {
    Request::response(emitter, code, Options::new())
        .await
        .map_err(failed)
}

struct Request;

#[interface(name = "org.freedesktop.portal.Request")]
impl Request {
    fn close(&self) {}

    #[zbus(signal)]
    async fn response(
        emitter: &SignalEmitter<'_>,
        response: u32,
        results: Options<'_>,
    ) -> zbus::Result<()>;
}

struct Session {
    registry: Arc<Mutex<Registry>>,
    handle: String,
    recorder: Option<Recorder>,
    recordings: Recordings,
}

#[interface(name = "org.freedesktop.portal.Session")]
impl Session {
    fn close(&self) {
        self.registry
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .close(&self.handle);
        close_session(&self.recorder, &self.recordings, &self.handle);
    }

    #[zbus(property)]
    fn version(&self) -> u32 {
        6
    }

    #[zbus(signal)]
    async fn closed(emitter: &SignalEmitter<'_>, details: Options<'_>) -> zbus::Result<()>;
}

pub struct Portal {
    registry: Arc<Mutex<Registry>>,
    available: Arc<Provider>,
    pipewire: PathBuf,
    kdialog: Option<PathBuf>,
    recorder: Option<Recorder>,
    recordings: Recordings,
}

impl Portal {
    pub fn new(
        registry: Arc<Mutex<Registry>>,
        available: Arc<Provider>,
        pipewire: PathBuf,
    ) -> Self {
        Self {
            registry,
            available,
            pipewire,
            kdialog: None,
            recorder: None,
            recordings: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_kdialog(mut self, path: PathBuf) -> Self {
        self.kdialog = Some(path);
        self
    }

    pub fn with_recorder(mut self, cellward: PathBuf) -> Self {
        self.recorder = Some(Recorder::new(cellward));
        self
    }

    pub fn pipewire(&self) -> &Path {
        &self.pipewire
    }
}

#[interface(name = "org.freedesktop.portal.ScreenCast")]
impl Portal {
    async fn create_session(
        &self,
        #[zbus(connection)] connection: &Connection,
        options: Options<'_>,
    ) -> fdo::Result<ObjectPath<'static>> {
        let request = request_path(&options)?;
        let handle = self
            .registry
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .create_session();
        if self.recorder.is_some() {
            self.recordings
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .insert(handle.clone(), Arc::new(Mutex::new(None)));
        }
        let session = Session {
            registry: self.registry.clone(),
            handle: handle.clone(),
            recorder: self.recorder.clone(),
            recordings: self.recordings.clone(),
        };
        connection
            .object_server()
            .at(handle.as_str(), session)
            .await
            .map_err(failed)?;
        connection
            .object_server()
            .at(request.clone(), Request)
            .await
            .map_err(failed)?;
        let emitter = emitter_for(connection, request.clone());
        let results = Options::from([("session_handle".to_owned(), Value::Str(handle.into()))]);
        Request::response(&emitter, 0, results)
            .await
            .map_err(failed)?;
        Ok(request)
    }

    async fn select_sources(
        &self,
        #[zbus(connection)] connection: &Connection,
        session_handle: ObjectPath<'_>,
        options: Options<'_>,
    ) -> fdo::Result<ObjectPath<'static>> {
        let request = request_path(&options)?;
        connection
            .object_server()
            .at(request.clone(), Request)
            .await
            .map_err(failed)?;
        let multiple = options
            .get("multiple")
            .and_then(|value| bool::try_from(value).ok())
            .unwrap_or(false);
        let result = self
            .registry
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .select_sources(session_handle.as_str(), multiple);
        let emitter = emitter_for(connection, request.clone());
        empty_response(&emitter, result.map_or_else(transition, |()| 0)).await?;
        Ok(request)
    }

    async fn start(
        &self,
        #[zbus(connection)] connection: &Connection,
        session_handle: ObjectPath<'_>,
        _parent_window: String,
        options: Options<'_>,
    ) -> fdo::Result<ObjectPath<'static>> {
        let request = request_path(&options)?;
        connection
            .object_server()
            .at(request.clone(), Request)
            .await
            .map_err(failed)?;
        let capture_id = options
            .get("cellward_capture_id")
            .and_then(|value| String::try_from(value).ok());
        let (available, recording_pid) = match &self.recorder {
            Some(recorder) => recorder.available(
                self.available.as_ref(),
                &self.recordings,
                session_handle.as_str(),
            ),
            None => ((self.available)(), None),
        };
        let selected = choose_capture_id(
            &available,
            self.registry
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .multiple(session_handle.as_str())
                .unwrap_or(false),
            capture_id.as_deref(),
            self.kdialog.as_deref(),
        );
        let result = selected.and_then(|capture_id| {
            self.registry
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .start(session_handle.as_str(), &available, capture_id.as_deref())
        });
        if let Some(pid) = recording_pid {
            if result.is_ok() {
                if let Some(recording) = self
                    .recordings
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .get(session_handle.as_str())
                {
                    *recording.lock().unwrap_or_else(|error| error.into_inner()) = Some(pid);
                }
            } else if let Some(recorder) = &self.recorder {
                recorder.stop(pid);
            }
        }
        let emitter = emitter_for(connection, request.clone());
        match result {
            Ok(sources) => {
                let streams: Vec<(u32, Options<'static>)> = sources
                    .into_iter()
                    .map(|source| {
                        (
                            source.node_id,
                            Options::from([
                                ("id".to_owned(), Value::Str(source.capture_id.into())),
                                ("source_type".to_owned(), Value::U32(2)),
                                ("pipewire-serial".to_owned(), Value::U64(source.serial)),
                            ]),
                        )
                    })
                    .collect();
                let results = Options::from([("streams".to_owned(), Value::new(streams))]);
                Request::response(&emitter, 0, results)
                    .await
                    .map_err(failed)?;
            }
            Err(error) => empty_response(&emitter, transition(error)).await?,
        }
        Ok(request)
    }

    #[zbus(name = "OpenPipeWireRemote")]
    fn open_pipewire_remote(
        &self,
        session_handle: ObjectPath<'_>,
        _options: Options<'_>,
    ) -> fdo::Result<OwnedFd> {
        if self
            .registry
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .status(session_handle.as_str())
            != Some(Status::Started)
        {
            return Err(fdo::Error::InvalidArgs(
                "the capture session has not started".into(),
            ));
        }
        let stream = std::os::unix::net::UnixStream::connect(&self.pipewire).map_err(failed)?;
        let fd: std::os::fd::OwnedFd = stream.into();
        Ok(fd.into())
    }

    #[zbus(property)]
    fn available_source_types(&self) -> u32 {
        2
    }

    #[zbus(property)]
    fn available_cursor_modes(&self) -> u32 {
        1
    }

    #[zbus(property)]
    fn version(&self) -> u32 {
        6
    }
}

struct ImplRequest;

#[interface(name = "org.freedesktop.impl.portal.Request")]
impl ImplRequest {
    fn close(&self) {}
}

struct ImplSession {
    registry: Arc<Mutex<Registry>>,
    handle: String,
    recorder: Option<Recorder>,
    recordings: Recordings,
}

#[interface(name = "org.freedesktop.impl.portal.Session")]
impl ImplSession {
    fn close(&self) {
        self.registry
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .close(&self.handle);
        close_session(&self.recorder, &self.recordings, &self.handle);
    }

    #[zbus(property)]
    fn version(&self) -> u32 {
        6
    }

    #[zbus(signal)]
    async fn closed(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
}

pub struct ImplPortal {
    registry: Arc<Mutex<Registry>>,
    available: Arc<Provider>,
    kdialog: Option<PathBuf>,
    recorder: Option<Recorder>,
    recordings: Recordings,
}

impl ImplPortal {
    pub fn new(registry: Arc<Mutex<Registry>>, available: Arc<Provider>) -> Self {
        Self {
            registry,
            available,
            kdialog: None,
            recorder: None,
            recordings: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_kdialog(mut self, path: PathBuf) -> Self {
        self.kdialog = Some(path);
        self
    }

    pub fn with_recorder(mut self, cellward: PathBuf) -> Self {
        self.recorder = Some(Recorder::new(cellward));
        self
    }
}

#[interface(name = "org.freedesktop.impl.portal.ScreenCast")]
impl ImplPortal {
    async fn create_session(
        &self,
        #[zbus(connection)] connection: &Connection,
        handle: ObjectPath<'_>,
        session_handle: ObjectPath<'_>,
        _app_id: String,
        _options: Options<'_>,
    ) -> fdo::Result<(u32, Options<'static>)> {
        connection
            .object_server()
            .at(handle, ImplRequest)
            .await
            .map_err(failed)?;
        let result = self
            .registry
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .create_session_with_handle(session_handle.as_str());
        let code = result.map_or_else(transition, |()| 0);
        if code == 0 {
            if self.recorder.is_some() {
                self.recordings
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .insert(session_handle.to_string(), Arc::new(Mutex::new(None)));
            }
            let session = ImplSession {
                registry: self.registry.clone(),
                handle: session_handle.to_string(),
                recorder: self.recorder.clone(),
                recordings: self.recordings.clone(),
            };
            connection
                .object_server()
                .at(session_handle.clone(), session)
                .await
                .map_err(failed)?;
        }
        Ok((
            code,
            Options::from([(
                "session_id".to_owned(),
                Value::Str(session_handle.to_string().into()),
            )]),
        ))
    }

    fn select_sources(
        &self,
        _handle: ObjectPath<'_>,
        session_handle: ObjectPath<'_>,
        _app_id: String,
        options: Options<'_>,
    ) -> (u32, Options<'static>) {
        let multiple = options
            .get("multiple")
            .and_then(|value| bool::try_from(value).ok())
            .unwrap_or(false);
        let result = self
            .registry
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .select_sources(session_handle.as_str(), multiple);
        (result.map_or_else(transition, |()| 0), Options::new())
    }

    fn start(
        &self,
        _handle: ObjectPath<'_>,
        session_handle: ObjectPath<'_>,
        _app_id: String,
        _parent_window: String,
        options: Options<'_>,
    ) -> (u32, Options<'static>) {
        let capture_id = options
            .get("cellward_capture_id")
            .and_then(|value| String::try_from(value).ok());
        let (available, recording_pid) = match &self.recorder {
            Some(recorder) => recorder.available(
                self.available.as_ref(),
                &self.recordings,
                session_handle.as_str(),
            ),
            None => ((self.available)(), None),
        };
        let selected = choose_capture_id(
            &available,
            self.registry
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .multiple(session_handle.as_str())
                .unwrap_or(false),
            capture_id.as_deref(),
            self.kdialog.as_deref(),
        );
        let result = selected.and_then(|capture_id| {
            self.registry
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .start(session_handle.as_str(), &available, capture_id.as_deref())
        });
        if let Some(pid) = recording_pid {
            if result.is_ok() {
                if let Some(recording) = self
                    .recordings
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .get(session_handle.as_str())
                {
                    *recording.lock().unwrap_or_else(|error| error.into_inner()) = Some(pid);
                }
            } else if let Some(recorder) = &self.recorder {
                recorder.stop(pid);
            }
        }
        match result {
            Ok(sources) => {
                let streams: Vec<(u32, Options<'static>)> = sources
                    .into_iter()
                    .map(|source| {
                        (
                            source.node_id,
                            Options::from([
                                ("id".to_owned(), Value::Str(source.capture_id.into())),
                                ("source_type".to_owned(), Value::U32(2)),
                                ("pipewire-serial".to_owned(), Value::U64(source.serial)),
                            ]),
                        )
                    })
                    .collect();
                (
                    0,
                    Options::from([("streams".to_owned(), Value::new(streams))]),
                )
            }
            Err(error) => (transition(error), Options::new()),
        }
    }

    #[zbus(property)]
    fn available_source_types(&self) -> u32 {
        2
    }

    #[zbus(property)]
    fn available_cursor_modes(&self) -> u32 {
        1
    }

    #[zbus(property)]
    fn version(&self) -> u32 {
        6
    }
}

const MAX_DUMP: usize = 4 << 20;

fn sources_from_json(text: &str) -> io::Result<Vec<Source>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid pw-dump response");
    let root =
        json::parse(text).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    root.as_array()
        .ok_or_else(invalid)?
        .iter()
        .filter(|item| {
            item.get("type").and_then(json::Value::as_str) == Some("PipeWire:Interface:Node")
        })
        .filter_map(|item| {
            let info = item.get("info")?;
            let props = info.get("props")?;
            let node_id = u32::try_from(item.get("id")?.as_i64()?).ok()?;
            let serial = u64::try_from(props.get("object.serial")?.as_i64()?).ok()?;
            let capture_id = props.get("cellward.capture.id")?.as_str()?;
            Source::new(node_id, serial, capture_id)
        })
        .map(Ok)
        .collect()
}

pub fn sources(program: &Path) -> io::Result<Vec<Source>> {
    if !program.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pw-dump must have an absolute path",
        ));
    }
    let mut child = Command::new(program)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut bytes = Vec::new();
    child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("pw-dump has no stdout"))?
        .take((MAX_DUMP + 1) as u64)
        .read_to_end(&mut bytes)?;
    let status = child.wait()?;
    if bytes.len() > MAX_DUMP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pw-dump response is too large",
        ));
    }
    if !status.success() {
        return Err(io::Error::other(format!("pw-dump exited with {status}")));
    }
    sources_from_json(&String::from_utf8_lossy(&bytes))
}

pub fn desktop_path() -> &'static str {
    DESKTOP
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;
    use std::process::{Child, Command, Stdio};
    use zbus::blocking::proxy::SignalIterator;
    use zbus::blocking::{Connection, Proxy};
    use zbus::zvariant::OwnedObjectPath;

    struct Bus(Child);
    impl Drop for Bus {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn fixture_path(name: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("cellward-{name}-{}-{nonce}", std::process::id()))
    }

    fn options(token: &str) -> Options<'static> {
        Options::from([(
            "handle_token".to_owned(),
            Value::Str(token.to_owned().into()),
        )])
    }

    fn response_proxy<'a>(
        connection: &'a Connection,
        token: &str,
    ) -> zbus::Result<(Proxy<'a>, SignalIterator<'static>)> {
        let proxy = Proxy::new(
            connection,
            "org.cellward.CaptureTest",
            format!("/org/cellward/capture/request/{token}"),
            "org.freedesktop.portal.Request",
        )?;
        let stream = proxy.receive_signal("Response")?;
        Ok((proxy, stream))
    }

    #[test]
    fn chooser_selects_only_an_advertised_container_and_cancel_is_closed() {
        let available = [
            Source::new(1, 1, "one").unwrap(),
            Source::new(2, 2, "two").unwrap(),
        ];
        let program = Path::new("/chooser");
        assert_eq!(
            choose_capture_id_with(&available, false, None, Some(program), || {
                Ok("two\n".to_owned())
            })
            .unwrap(),
            Some("two".to_owned())
        );
        assert_eq!(
            choose_capture_id(&available, false, None, None),
            Err(Error::AmbiguousSource)
        );
        assert_eq!(
            choose_capture_id(&[], false, None, Some(program)),
            Err(Error::NoSources)
        );
        assert_eq!(
            choose_capture_id(&available, false, Some("missing"), Some(program)),
            Ok(Some("missing".to_owned()))
        );
    }

    #[test]
    fn pw_dump_keeps_only_complete_capture_sources() {
        let dump = r#"[
            {"id":7,"type":"PipeWire:Interface:Node","info":{"props":{"object.serial":41,"cellward.capture.id":"work"}}},
            {"id":8,"type":"PipeWire:Interface:Node","info":{"props":{"object.serial":42,"node.name":"other"}}},
            {"id":9,"type":"PipeWire:Interface:Client","info":{"props":{"object.serial":43,"cellward.capture.id":"not-a-node"}}}
        ]"#;
        assert_eq!(
            sources_from_json(dump).unwrap(),
            [Source::new(7, 41, "work").unwrap()]
        );
        assert!(sources_from_json("not json").is_err());
        assert!(sources(Path::new("pw-dump")).is_err());
    }

    #[test]
    fn screencast_v6_round_trip_uses_serial_and_closes_the_session() {
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
        let address = address.trim().to_owned();
        let socket = fixture_path("capture-test");
        let listener = UnixListener::bind(&socket).unwrap();
        {
            let registry = Arc::new(Mutex::new(Registry::default()));
            let portal = Portal::new(
                registry.clone(),
                Arc::new(|| vec![Source::new(7, 41, "work").unwrap()]),
                socket.clone(),
            );
            let _server = zbus::blocking::connection::Builder::address(address.as_str())
                .unwrap()
                .name("org.cellward.CaptureTest")
                .unwrap()
                .serve_at(DESKTOP, portal)
                .unwrap()
                .build()
                .unwrap();
            let client = zbus::blocking::connection::Builder::address(address.as_str())
                .unwrap()
                .build()
                .unwrap();
            let portal = Proxy::new(
                &client,
                "org.cellward.CaptureTest",
                DESKTOP,
                "org.freedesktop.portal.ScreenCast",
            )
            .unwrap();

            let (_request, mut responses) = response_proxy(&client, "create").unwrap();
            let request: OwnedObjectPath =
                portal.call("CreateSession", &options("create")).unwrap();
            assert_eq!(request.as_str(), "/org/cellward/capture/request/create");
            let message = responses.next().unwrap();
            let body = message.body();
            let (code, results) = body.deserialize::<(u32, Options)>().unwrap();
            assert_eq!(code, 0);
            let session = String::try_from(&results["session_handle"]).unwrap();
            let session_path = ObjectPath::try_from(session.clone()).unwrap();

            let (_request, mut responses) = response_proxy(&client, "select").unwrap();
            portal
                .call_method("SelectSources", &(session_path.clone(), options("select")))
                .unwrap();
            let message = responses.next().unwrap();
            let body = message.body();
            let (code, _) = body.deserialize::<(u32, Options)>().unwrap();
            assert_eq!(code, 0);

            let (_request, mut responses) = response_proxy(&client, "start").unwrap();
            let start = Options::from([
                ("handle_token".to_owned(), Value::Str("start".into())),
                ("cellward_capture_id".to_owned(), Value::Str("work".into())),
            ]);
            portal
                .call_method("Start", &(session_path.clone(), "", start))
                .unwrap();
            let message = responses.next().unwrap();
            let body = message.body();
            let (code, results) = body.deserialize::<(u32, Options)>().unwrap();
            assert_eq!(code, 0);
            let streams = Vec::<(u32, Options)>::try_from(results["streams"].clone()).unwrap();
            assert_eq!(streams.len(), 1);
            assert_eq!(streams[0].0, 7);
            assert_eq!(u64::try_from(&streams[0].1["pipewire-serial"]).unwrap(), 41);
            assert_eq!(String::try_from(&streams[0].1["id"]).unwrap(), "work");

            let fd: OwnedFd = portal
                .call("OpenPipeWireRemote", &(session_path, Options::new()))
                .unwrap();
            assert!(std::os::fd::AsRawFd::as_raw_fd(&fd) >= 0);
            let session_proxy = Proxy::new(
                &client,
                "org.cellward.CaptureTest",
                session.as_str(),
                "org.freedesktop.portal.Session",
            )
            .unwrap();
            let _: () = session_proxy.call("Close", &()).unwrap();
            assert_eq!(registry.lock().unwrap().status(&session), None);
        }
        drop(listener);
    }

    #[test]
    fn impl_screencast_backend_returns_streams_without_request_signals() {
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
        let address = address.trim().to_owned();
        let registry = Arc::new(Mutex::new(Registry::default()));
        let portal = ImplPortal::new(
            registry.clone(),
            Arc::new(|| {
                vec![
                    Source::new(7, 41, "work").unwrap(),
                    Source::new(8, 42, "two").unwrap(),
                ]
            }),
        );
        let _server = zbus::blocking::connection::Builder::address(address.as_str())
            .unwrap()
            .name("org.freedesktop.impl.portal.desktop.cellward")
            .unwrap()
            .serve_at(DESKTOP, portal)
            .unwrap()
            .build()
            .unwrap();
        let client = zbus::blocking::connection::Builder::address(address.as_str())
            .unwrap()
            .build()
            .unwrap();
        let portal = Proxy::new(
            &client,
            "org.freedesktop.impl.portal.desktop.cellward",
            DESKTOP,
            "org.freedesktop.impl.portal.ScreenCast",
        )
        .unwrap();
        let request = ObjectPath::try_from("/org/cellward/capture/request/impl").unwrap();
        let session = ObjectPath::try_from("/org/cellward/capture/session/impl").unwrap();
        let (code, results): (u32, HashMap<String, zbus::zvariant::OwnedValue>) = portal
            .call(
                "CreateSession",
                &(request.clone(), session.clone(), "test.app", Options::new()),
            )
            .unwrap();
        assert_eq!(code, 0);
        assert_eq!(
            String::try_from(Value::from(results["session_id"].clone())).unwrap(),
            session.as_str()
        );
        let (code, _): (u32, HashMap<String, zbus::zvariant::OwnedValue>) = portal
            .call(
                "SelectSources",
                &(request.clone(), session.clone(), "test.app", Options::new()),
            )
            .unwrap();
        assert_eq!(code, 0);
        let start = Options::from([("cellward_capture_id".to_owned(), Value::Str("two".into()))]);
        let (code, results): (u32, HashMap<String, zbus::zvariant::OwnedValue>) = portal
            .call("Start", &(request, session.clone(), "test.app", "", start))
            .unwrap();
        assert_eq!(code, 0);
        let streams =
            Vec::<(u32, Options)>::try_from(Value::from(results["streams"].clone())).unwrap();
        assert_eq!(streams.len(), 1);
        assert_eq!(u64::try_from(&streams[0].1["pipewire-serial"]).unwrap(), 42);
        assert_eq!(String::try_from(&streams[0].1["id"]).unwrap(), "two");
        let session_proxy = Proxy::new(
            &client,
            "org.freedesktop.impl.portal.desktop.cellward",
            session.as_str(),
            "org.freedesktop.impl.portal.Session",
        )
        .unwrap();
        let _: () = session_proxy.call("Close", &()).unwrap();
        assert_eq!(registry.lock().unwrap().status(session.as_str()), None);
    }
}
