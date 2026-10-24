//! `cellward-clip` — the clipboard history by container.
//!
//! ```text
//! cellward-clip daemon                  record every copy into its history
//! cellward-clip histories               the histories there are
//! cellward-clip list <history> [N]      its last N entries (20)
//! ```
//!
//! The histories live below `$XDG_STATE_HOME/cellward-clip` (one directory
//! each, `clipstore`), with the key that seals them, `key`, beside them.
//!
//! **The recorder** follows the compositor's selection through data-control
//! (ext-data-control-v1, else wlr-data-control) — a protocol of the host's
//! programs only: cellward's Wayland proxy gives it to no container. At each
//! new selection it asks whose it is (`clipstore::recorder`), reads the types
//! worth keeping straight from the program that offers them, and appends them
//! to that history. The primary selection (what is only selected) is not
//! kept. What it reads it keeps nowhere but in its histories, sealed.

use std::collections::HashMap;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clipstore::recorder::{self, Marks, Whose};
use clipstore::{Content, History, Key, NewEntry, MAX_ENTRY};
use wayland_client::backend::ObjectId;
use wayland_client::protocol::{wl_registry, wl_seat};
use wayland_client::{Connection, Dispatch, Proxy, QueueHandle};
use wayland_protocols::ext::data_control::v1::client::{
    ext_data_control_device_v1 as ext_device, ext_data_control_manager_v1 as ext_manager,
    ext_data_control_offer_v1 as ext_offer, ext_data_control_source_v1 as ext_source,
};
use wayland_protocols_wlr::data_control::v1::client::{
    zwlr_data_control_device_v1 as wlr_device, zwlr_data_control_manager_v1 as wlr_manager,
    zwlr_data_control_offer_v1 as wlr_offer, zwlr_data_control_source_v1 as wlr_source,
};

#[path = "../tray.rs"]
mod tray;

/// What the daemon offers beside an entry it makes the selection
/// (`select`): a mark of nobody's — no file names it —, so that what it
/// sets is not kept again, and no program sees it (proxies drop marks).
const OWN_MARK: &str = "application/x-cellward-clip-recorder";

/// How long a program has to hand over what it copied.
const READ_WITHIN: Duration = Duration::from_secs(3);

fn state_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))?;
    Some(base.join("cellward-clip"))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(dir) = state_dir() else {
        eprintln!("cellward-clip: нет $HOME");
        return ExitCode::from(1);
    };
    match args.first().map(String::as_str) {
        Some("daemon") => daemon(&dir),
        Some("histories") => histories(&dir),
        Some("list") => match args.get(1) {
            Some(history)
                if recorder::valid_history(history) && history != recorder::NO_HISTORY =>
            {
                let n = args.get(2).and_then(|n| n.parse().ok()).unwrap_or(20);
                list(&dir, history, n)
            }
            _ => usage(),
        },
        // Any request of the protocol (`clipstore::protocol`), its words as
        // arguments: for scripts, and for the tests.
        Some("ask") if args.len() > 1 && args[1..].iter().all(|w| !w.contains(['\t', '\n'])) => {
            ask(&args[1..].join("\t"))
        }
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!("cellward-clip daemon | histories | list <история> [сколько] | ask <запрос>…");
    ExitCode::from(2)
}

fn key(dir: &Path) -> Option<Key> {
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("cellward-clip: не создать {}: {e}", dir.display());
        return None;
    }
    match Key::load_or_create(&dir.join("key")) {
        Ok(key) => Some(key),
        Err(e) => {
            eprintln!("cellward-clip: ключ: {e}");
            None
        }
    }
}

/// The daemon's socket of questions, in the session's runtime directory:
/// its user's alone (the directory is 0700, the socket 0600, and the peer's
/// uid is checked). The histories are opened by the daemon alone — it holds
/// the key —, and everything else asks it.
fn socket_path() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/nonexistent"))
        .join("cellward-clip.sock")
}

/// Ask the daemon `request` (one line) and print its answer.
fn ask(request: &str) -> ExitCode {
    use std::io::Write;
    let mut stream = match std::os::unix::net::UnixStream::connect(socket_path()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cellward-clip: служба истории не отвечает ({e}) — она включена? (programs.cellward.clipboard.history)");
            return ExitCode::from(1);
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    if stream.write_all(format!("{request}\n").as_bytes()).is_err() {
        return ExitCode::from(1);
    }
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    match answer.strip_prefix("error\t") {
        Some(why) => {
            eprintln!("cellward-clip: {}", why.trim());
            ExitCode::from(1)
        }
        None => {
            print!("{answer}");
            ExitCode::SUCCESS
        }
    }
}

fn histories(_dir: &Path) -> ExitCode {
    ask("histories")
}

fn list(_dir: &Path, history: &str, n: usize) -> ExitCode {
    ask(&format!("list\t{history}\t{n}"))
}

/// The histories, opened by the daemon as they are needed.
struct Store {
    dir: PathBuf,
    key: Key,
    open: HashMap<String, History>,
}

impl Store {
    fn history(&mut self, name: &str) -> Result<&mut History, String> {
        let (dir, real) = if let Some(real) = name.strip_prefix("@favorites:") {
            (self.dir.join(".favorites"), real)
        } else if let Some(real) = name.strip_prefix("@secrets:") {
            (self.dir.join(".secrets"), real)
        } else {
            (self.dir.clone(), name)
        };
        if !recorder::valid_history(real) || real == recorder::NO_HISTORY {
            return Err(format!("«{name}» — не имя истории"));
        }
        if !self.open.contains_key(name) {
            let h =
                History::open(&dir.join(real), &self.key).map_err(|e| format!("{name}: {e}"))?;
            self.open.insert(name.to_owned(), h);
        }
        Ok(self.open.get_mut(name).expect("just opened"))
    }

    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| recorder::valid_history(n) && n != recorder::NO_HISTORY)
            .collect();
        names.sort();
        names
    }

    /// The answer to one request line (`clipstore::protocol`).
    fn answer(&mut self, request: &str) -> Reply {
        use clipstore::protocol;
        let words: Vec<&str> = request.trim_end_matches(['\n', '\r']).split('\t').collect();
        let error = |e: &dyn std::fmt::Display| Reply::Text(format!("error\t{e}\n"));
        let lines = |h: &mut History, q: &clipstore::Query, before, limit| -> Reply {
            match h.query(q, before, limit) {
                Ok(ids) => Reply::Text(
                    ids.into_iter()
                        .filter_map(|id| h.summary(id).ok().flatten())
                        .map(|s| protocol::line(&s))
                        .collect(),
                ),
                Err(e) => Reply::Text(format!("error\t{e}\n")),
            }
        };
        match words.as_slice() {
            ["histories"] => Reply::Text(self.names().iter().map(|n| format!("{n}\n")).collect()),
            ["list", name, n] => {
                let n = n.parse().unwrap_or(20).min(protocol::MAX_LIMIT);
                match self.history(name) {
                    Ok(h) => lines(h, &clipstore::Query::default(), None, n),
                    Err(e) => error(&e),
                }
            }
            ["search", name, rest @ ..] => match protocol::search(rest) {
                Ok(search) => match self.history(name) {
                    Ok(_)
                        if name.starts_with("@secrets:")
                            && (!search.query.text_terms.is_empty()
                                || search.query.pattern.is_some()) =>
                    {
                        error(&"поиск по тексту паролей отключён")
                    }
                    Ok(h) => lines(h, &search.query, search.before, search.limit),
                    Err(e) => error(&e),
                },
                Err(e) => error(&e),
            },
            ["get", name, id, mime] => {
                let (Ok(id), Some(mime)) = (id.parse::<u64>(), protocol::decode(mime)) else {
                    return error(&"не номер или не тип");
                };
                match self.history(name).map(|h| h.get(id)) {
                    Ok(Ok(Some(entry))) => {
                        match entry.contents.into_iter().find(|c| c.mime == mime) {
                            Some(c) => {
                                let mut out = format!("ok\t{}\n", c.data.len()).into_bytes();
                                out.extend_from_slice(&c.data);
                                Reply::Bytes(out)
                            }
                            None => error(&"такого типа у записи нет"),
                        }
                    }
                    Ok(Ok(None)) => error(&"записи нет"),
                    Ok(Err(e)) => error(&e),
                    Err(e) => error(&e),
                }
            }
            ["move", from, id, to] => {
                if from.starts_with("@secrets:") || to.starts_with("@secrets:") {
                    return error(&"пароли нельзя переносить как обычные записи");
                }
                let Ok(id) = id.parse::<u64>() else {
                    return error(&"не номер");
                };
                if from == to {
                    return error(&"это та же история");
                }
                let entry = match self.history(from).map(|h| h.get(id)) {
                    Ok(Ok(Some(entry))) => entry,
                    Ok(Ok(None)) => return error(&"записи нет"),
                    Ok(Err(e)) => return error(&e),
                    Err(e) => return error(&e),
                };
                match self.history(to).map(|h| h.import(&entry)) {
                    Ok(Ok(added)) => Reply::Text(format!("ok\t{}\n", added.id())),
                    Ok(Err(e)) => error(&e),
                    Err(e) => error(&e),
                }
            }
            ["favorite", name, id] => {
                let Ok(id) = id.parse::<u64>() else {
                    return error(&"не номер");
                };
                if name.starts_with("@favorites:") || name.starts_with("@secrets:") {
                    return error(&"запись уже из избранного");
                }
                let entry = match self.history(name).map(|h| h.get(id)) {
                    Ok(Ok(Some(entry))) => entry,
                    Ok(Ok(None)) => return error(&"записи нет"),
                    Ok(Err(e)) => return error(&e),
                    Err(e) => return error(&e),
                };
                let favorites = format!("@favorites:{name}");
                match self.history(&favorites).map(|h| h.import(&entry)) {
                    Ok(Ok(added)) => Reply::Text(format!("ok\t{}\n", added.id())),
                    Ok(Err(e)) => error(&e),
                    Err(e) => error(&e),
                }
            }
            ["secret", name, id, label] => {
                let Ok(id) = id.parse::<u64>() else {
                    return error(&"не номер");
                };
                if name.starts_with('@') {
                    return error(&"паролем можно отметить только запись истории");
                }
                let Some(label) = protocol::decode(label) else {
                    return error(&"метка пароля не читается");
                };
                if label.chars().count() > 80 || label.chars().any(char::is_control) {
                    return error(&"метка пароля слишком длинная или содержит управляющие символы");
                }
                let entry = match self.history(name).map(|h| h.get(id)) {
                    Ok(Ok(Some(entry))) => entry,
                    Ok(Ok(None)) => return error(&"записи нет"),
                    Ok(Err(e)) => return error(&e),
                    Err(e) => return error(&e),
                };
                let Some(content) = password_content(&entry.contents) else {
                    return error(&"паролем можно отметить только текст");
                };
                let secrets = format!("@secrets:{name}");
                let added = match self.history(&secrets).map(|h| {
                    h.append(NewEntry {
                        copied_at: entry.copied_at,
                        contents: vec![content],
                        preview: Some(if label.trim().is_empty() {
                            "Пароль".to_owned()
                        } else {
                            format!("Пароль: {}", label.trim())
                        }),
                    })
                }) {
                    Ok(Ok(added)) => added,
                    Ok(Err(e)) => return error(&e),
                    Err(e) => return error(&e),
                };
                match self.history(name).map(|h| h.delete(id)) {
                    Ok(Ok(true)) => Reply::Text(format!("ok\t{}\n", added.id())),
                    Ok(Ok(false)) => error(&"запись исчезла до удаления"),
                    Ok(Err(e)) => error(&e),
                    Err(e) => error(&e),
                }
            }
            ["delete", name, id] => {
                let Ok(id) = id.parse::<u64>() else {
                    return error(&"не номер");
                };
                match self.history(name).map(|h| h.delete(id)) {
                    Ok(Ok(true)) => Reply::Text("ok\n".to_owned()),
                    Ok(Ok(false)) => error(&"записи нет"),
                    Ok(Err(e)) => error(&e),
                    Err(e) => error(&e),
                }
            }
            ["select", name, id] => {
                let Ok(id) = id.parse::<u64>() else {
                    return error(&"не номер");
                };
                match self.history(name) {
                    Ok(h) => match h.get(id) {
                        Ok(Some(entry)) => {
                            let _ = h.record_paste(id, now_ms());
                            let mut contents = entry.contents;
                            if name.starts_with("@secrets:") {
                                contents.push(Content {
                                    mime: recorder::SECRET_HINT.to_owned(),
                                    data: b"secret".to_vec(),
                                });
                            }
                            Reply::Select(contents)
                        }
                        Ok(None) => error(&"записи нет"),
                        Err(e) => error(&e),
                    },
                    Err(e) => error(&e),
                }
            }
            _ => Reply::Text("error\tнепонятный запрос\n".to_owned()),
        }
    }

    fn keep(&mut self, history: &str, entry: NewEntry) {
        if self.dir.join(".secrets").join(history).is_dir() {
            if let Some(content) = password_content(&entry.contents) {
                let secret = format!("@secrets:{history}");
                match self
                    .history(&secret)
                    .map(|h| h.contains_contents(&[content]))
                {
                    Ok(Ok(false)) => {}
                    Ok(Ok(true)) => return,
                    _ => {
                        eprintln!("cellward-clip: пароли {history} не читаются — запись истории пропущена");
                        return;
                    }
                }
            }
        }
        match self.history(history) {
            Ok(h) => {
                if let Err(e) = h.append(entry) {
                    eprintln!("cellward-clip: история {history}: {e}");
                }
            }
            Err(e) => eprintln!("cellward-clip: история {e}"),
        }
    }
}

/// One canonical representation makes a marked password recognizable when
/// the next copy offers a different set of clipboard MIME representations.
fn password_content(contents: &[Content]) -> Option<Content> {
    for mime in [
        "text/plain;charset=utf-8",
        "UTF8_STRING",
        "text/plain",
        "TEXT",
        "STRING",
    ] {
        if let Some(c) = contents.iter().find(|c| c.mime == mime) {
            std::str::from_utf8(&c.data).ok()?;
            return Some(Content {
                mime: "text/plain;charset=utf-8".into(),
                data: c.data.clone(),
            });
        }
    }
    None
}

/// What a request is answered with.
enum Reply {
    Text(String),
    Bytes(Vec<u8>),
    /// `ok`, and the daemon makes these contents the selection.
    Select(Vec<Content>),
}

/// One question on the socket: from this user only, one line, answered. A
/// `select` hands back the contents to make the selection.
fn serve(store: &mut Store, mut stream: std::os::unix::net::UnixStream) -> Option<Vec<Content>> {
    use std::io::{BufRead, Write};
    let mut cred = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: a ucred of the length given.
    let got = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    // SAFETY: getuid takes nothing.
    if got != 0 || cred.uid != unsafe { libc::getuid() } {
        return None;
    }
    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
    let mut line = String::new();
    let Ok(clone) = stream.try_clone() else {
        return None;
    };
    let mut reader = std::io::BufReader::new(clone);
    if reader.read_line(&mut line).is_err() || line.len() > 4096 {
        return None;
    }
    match store.answer(&line) {
        Reply::Text(text) => {
            let _ = stream.write_all(text.as_bytes());
            None
        }
        Reply::Bytes(bytes) => {
            let _ = stream.write_all(&bytes);
            None
        }
        Reply::Select(contents) => {
            let _ = stream.write_all(b"ok\n");
            Some(contents)
        }
    }
}

// --- THE RECORDER --------------------------------------------------------------

/// A selection's offer, of either protocol.
#[derive(Clone)]
enum Offer {
    Ext(ext_offer::ExtDataControlOfferV1),
    Wlr(wlr_offer::ZwlrDataControlOfferV1),
}

impl Offer {
    fn id(&self) -> ObjectId {
        match self {
            Offer::Ext(o) => o.id(),
            Offer::Wlr(o) => o.id(),
        }
    }

    fn receive(&self, mime: &str, fd: std::os::fd::BorrowedFd<'_>) {
        match self {
            Offer::Ext(o) => o.receive(mime.to_owned(), fd),
            Offer::Wlr(o) => o.receive(mime.to_owned(), fd),
        }
    }

    fn destroy(&self) {
        match self {
            Offer::Ext(o) => o.destroy(),
            Offer::Wlr(o) => o.destroy(),
        }
    }
}

#[derive(Default)]
struct App {
    seat: Option<wl_seat::WlSeat>,
    ext: Option<ext_manager::ExtDataControlManagerV1>,
    wlr: Option<wlr_manager::ZwlrDataControlManagerV1>,
    /// The offers announced, and their types.
    types: HashMap<ObjectId, Vec<String>>,
    /// The selection to keep, once the round is over.
    selection: Option<Offer>,
    /// An offer no longer the selection: destroyed after the round.
    gone: Vec<Offer>,
    finished: bool,
    ext_device: Option<ext_device::ExtDataControlDeviceV1>,
    wlr_device: Option<wlr_device::ZwlrDataControlDeviceV1>,
    /// What the daemon's own selection offers (`select`), by type.
    own: HashMap<String, std::sync::Arc<Vec<u8>>>,
}

impl Dispatch<wl_registry::WlRegistry, ()> for App {
    fn event(
        app: &mut Self,
        registry: &wl_registry::WlRegistry,
        event: wl_registry::Event,
        _: &(),
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        if let wl_registry::Event::Global {
            name,
            interface,
            version,
        } = event
        {
            match interface.as_str() {
                "wl_seat" if app.seat.is_none() => {
                    app.seat = Some(registry.bind(name, version.min(5), qh, ()));
                }
                "ext_data_control_manager_v1" => {
                    app.ext = Some(registry.bind(name, 1, qh, ()));
                }
                "zwlr_data_control_manager_v1" => {
                    app.wlr = Some(registry.bind(name, version.min(2), qh, ()));
                }
                _ => {}
            }
        }
    }
}

impl Dispatch<wl_seat::WlSeat, ()> for App {
    fn event(
        _: &mut Self,
        _: &wl_seat::WlSeat,
        _: wl_seat::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ext_manager::ExtDataControlManagerV1, ()> for App {
    fn event(
        _: &mut Self,
        _: &ext_manager::ExtDataControlManagerV1,
        _: ext_manager::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<wlr_manager::ZwlrDataControlManagerV1, ()> for App {
    fn event(
        _: &mut Self,
        _: &wlr_manager::ZwlrDataControlManagerV1,
        _: wlr_manager::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ext_device::ExtDataControlDeviceV1, ()> for App {
    fn event(
        app: &mut Self,
        _: &ext_device::ExtDataControlDeviceV1,
        event: ext_device::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            ext_device::Event::DataOffer { id } => {
                app.types.insert(id.id(), Vec::new());
            }
            ext_device::Event::Selection { id } => app.selected(id.map(Offer::Ext)),
            ext_device::Event::PrimarySelection { id: Some(o) } => app.gone.push(Offer::Ext(o)),
            ext_device::Event::Finished => app.finished = true,
            _ => {}
        }
    }

    wayland_client::event_created_child!(App, ext_device::ExtDataControlDeviceV1, [
        ext_device::EVT_DATA_OFFER_OPCODE => (ext_offer::ExtDataControlOfferV1, ()),
    ]);
}

impl Dispatch<wlr_device::ZwlrDataControlDeviceV1, ()> for App {
    fn event(
        app: &mut Self,
        _: &wlr_device::ZwlrDataControlDeviceV1,
        event: wlr_device::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            wlr_device::Event::DataOffer { id } => {
                app.types.insert(id.id(), Vec::new());
            }
            wlr_device::Event::Selection { id } => app.selected(id.map(Offer::Wlr)),
            wlr_device::Event::PrimarySelection { id: Some(o) } => app.gone.push(Offer::Wlr(o)),
            wlr_device::Event::Finished => app.finished = true,
            _ => {}
        }
    }

    wayland_client::event_created_child!(App, wlr_device::ZwlrDataControlDeviceV1, [
        wlr_device::EVT_DATA_OFFER_OPCODE => (wlr_offer::ZwlrDataControlOfferV1, ()),
    ]);
}

impl Dispatch<ext_source::ExtDataControlSourceV1, ()> for App {
    fn event(
        app: &mut Self,
        source: &ext_source::ExtDataControlSourceV1,
        event: ext_source::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            ext_source::Event::Send { mime_type, fd } => app.send(&mime_type, fd),
            ext_source::Event::Cancelled => source.destroy(),
            _ => {}
        }
    }
}

impl Dispatch<wlr_source::ZwlrDataControlSourceV1, ()> for App {
    fn event(
        app: &mut Self,
        source: &wlr_source::ZwlrDataControlSourceV1,
        event: wlr_source::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            wlr_source::Event::Send { mime_type, fd } => app.send(&mime_type, fd),
            wlr_source::Event::Cancelled => source.destroy(),
            _ => {}
        }
    }
}

impl Dispatch<ext_offer::ExtDataControlOfferV1, ()> for App {
    fn event(
        app: &mut Self,
        offer: &ext_offer::ExtDataControlOfferV1,
        event: ext_offer::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let ext_offer::Event::Offer { mime_type } = event {
            app.offered(offer.id(), mime_type);
        }
    }
}

impl Dispatch<wlr_offer::ZwlrDataControlOfferV1, ()> for App {
    fn event(
        app: &mut Self,
        offer: &wlr_offer::ZwlrDataControlOfferV1,
        event: wlr_offer::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let wlr_offer::Event::Offer { mime_type } = event {
            app.offered(offer.id(), mime_type);
        }
    }
}

impl App {
    /// Make `contents` the selection: a source of the daemon's own, which
    /// answers every type it offers from memory until another selection
    /// takes its place.
    fn select(&mut self, qh: &QueueHandle<Self>, contents: Vec<Content>) {
        self.own = contents
            .into_iter()
            .map(|c| (c.mime, std::sync::Arc::new(c.data)))
            .collect();
        let mut types: Vec<String> = self.own.keys().cloned().collect();
        types.push(OWN_MARK.to_owned());
        // Both selections, the primary one first: the paste a launch's proxy
        // presses is Shift+Insert, which terminals take as a paste of the
        // primary selection, and it is pressed once the clipboard's arrives
        // (`crate::clip::take_paste` of the core) — the primary one there by
        // then.
        if let (Some(manager), Some(device)) = (&self.ext, &self.ext_device) {
            let source = |qh| {
                let source = manager.create_data_source(qh, ());
                for t in &types {
                    source.offer(t.clone());
                }
                source
            };
            device.set_primary_selection(Some(&source(qh)));
            device.set_selection(Some(&source(qh)));
        } else if let (Some(manager), Some(device)) = (&self.wlr, &self.wlr_device) {
            let source = |qh| {
                let source = manager.create_data_source(qh, ());
                for t in &types {
                    source.offer(t.clone());
                }
                source
            };
            if device.version() >= 2 {
                device.set_primary_selection(Some(&source(qh)));
            }
            device.set_selection(Some(&source(qh)));
        }
    }

    /// A program asks the daemon's own selection for `mime`: written from a
    /// thread of its own, the daemon's loop not waiting on the reader.
    fn send(&self, mime: &str, fd: OwnedFd) {
        if let Some(data) = self.own.get(mime).cloned() {
            std::thread::spawn(move || {
                use std::io::Write;
                let _ = std::fs::File::from(fd).write_all(&data);
            });
        }
    }

    fn offered(&mut self, id: ObjectId, mime: String) {
        if let Some(types) = self.types.get_mut(&id) {
            // Bounded: a program offering types without end is not kept
            // in memory without end.
            if types.len() < 64 && mime.len() <= 256 {
                types.push(mime);
            }
        }
    }

    fn selected(&mut self, offer: Option<Offer>) {
        if let Some(old) = self.selection.take() {
            self.gone.push(old);
        }
        self.selection = offer;
    }
}

/// Read `mime` of `offer`: the program writes it into a pipe of ours. At
/// most [`MAX_ENTRY`] bytes and [`READ_WITHIN`]; `None` past either, or
/// when nothing came.
fn read(conn: &Connection, offer: &Offer, mime: &str) -> Option<Vec<u8>> {
    let mut fds = [0; 2];
    // SAFETY: two descriptors' room; O_CLOEXEC.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return None;
    }
    // SAFETY: both just made, ours alone.
    let (r, w) = unsafe {
        use std::os::fd::FromRawFd;
        (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))
    };
    offer.receive(mime, w.as_fd());
    conn.flush().ok()?;
    drop(w);
    let mut file = std::fs::File::from(r);
    let until = Instant::now() + READ_WITHIN;
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        let mut poll = libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one pollfd.
        if unsafe { libc::poll(&mut poll, 1, left.as_millis() as i32) } <= 0 {
            return None;
        }
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.len() > MAX_ENTRY {
                    return None;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    (!out.is_empty()).then_some(out)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

fn daemon(dir: &Path) -> ExitCode {
    let Some(key) = key(dir) else {
        return ExitCode::from(1);
    };
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/nonexistent"));
    let mut marks = Marks::new(&runtime);
    let conn = match Connection::connect_to_env() {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("cellward-clip: нет композитора: {e}");
            return ExitCode::from(1);
        }
    };
    let mut queue = conn.new_event_queue();
    let qh = queue.handle();
    let _registry = conn.display().get_registry(&qh, ());
    let mut app = App::default();
    if queue.roundtrip(&mut app).is_err() {
        eprintln!("cellward-clip: композитор не ответил");
        return ExitCode::from(1);
    }
    let Some(seat) = app.seat.clone() else {
        eprintln!("cellward-clip: у композитора нет места ввода (wl_seat)");
        return ExitCode::from(1);
    };
    if let Some(ext) = &app.ext {
        app.ext_device = Some(ext.get_data_device(&seat, &qh, ()));
    } else if let Some(wlr) = &app.wlr {
        app.wlr_device = Some(wlr.get_data_device(&seat, &qh, ()));
    } else {
        eprintln!("cellward-clip: композитор не даёт data-control — истории не будет");
        return ExitCode::from(1);
    }
    // The socket of questions: a leftover of an earlier run replaced.
    let socket = socket_path();
    let _ = std::fs::remove_file(&socket);
    let listener = match std::os::unix::net::UnixListener::bind(&socket) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cellward-clip: не открыть {}: {e}", socket.display());
            return ExitCode::from(1);
        }
    };
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600));
    let _ = listener.set_nonblocking(true);
    let mut store = Store {
        dir: dir.to_path_buf(),
        key,
        open: HashMap::new(),
    };
    tray::start();
    eprintln!("cellward-clip: пишу историю в {}", dir.display());
    loop {
        // The compositor's events and the questions, whichever comes.
        if conn.flush().is_err() || queue.dispatch_pending(&mut app).is_err() {
            eprintln!("cellward-clip: композитор закрыл соединение");
            return ExitCode::from(1);
        }
        if let Some(guard) = queue.prepare_read() {
            let mut fds = [
                libc::pollfd {
                    fd: guard.connection_fd().as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: listener.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: two pollfds.
            unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
            if fds[0].revents != 0 {
                if guard.read().is_err() {
                    eprintln!("cellward-clip: композитор закрыл соединение");
                    return ExitCode::from(1);
                }
            } else {
                drop(guard);
            }
            if fds[1].revents != 0 {
                while let Ok((stream, _)) = listener.accept() {
                    let _ = stream.set_nonblocking(false);
                    if let Some(contents) = serve(&mut store, stream) {
                        app.select(&qh, contents);
                    }
                }
            }
            if queue.dispatch_pending(&mut app).is_err() {
                return ExitCode::from(1);
            }
        }
        if app.finished {
            eprintln!("cellward-clip: композитор закрыл соединение");
            return ExitCode::from(1);
        }
        for offer in std::mem::take(&mut app.gone) {
            app.types.remove(&offer.id());
            offer.destroy();
        }
        let Some(offer) = app.selection.clone() else {
            continue;
        };
        let types = app.types.get(&offer.id()).cloned().unwrap_or_default();
        // Read once: the next round finds it taken.
        app.types.insert(offer.id(), Vec::new());
        if types.is_empty() {
            continue;
        }
        let history = match marks.whose(&types) {
            Whose::History(h) => h,
            Whose::Nobody => continue,
        };
        if recorder::is_secret(&types) {
            continue;
        }
        let mut contents = Vec::new();
        for mime in recorder::to_read(&types) {
            if let Some(data) = read(&conn, &offer, &mime) {
                contents.push((mime, data));
            }
        }
        if contents.is_empty() {
            continue;
        }
        let preview = recorder::preview(&contents);
        store.keep(
            &history,
            NewEntry {
                copied_at: now_ms(),
                contents: contents
                    .into_iter()
                    .map(|(mime, data)| Content { mime, data })
                    .collect(),
                preview,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_favourite_is_encrypted_separate_and_survives_deleting_its_source() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("cw-clip-favourite-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = Key::load_or_create(&dir.join("key")).unwrap();
        let mut store = Store {
            dir: dir.clone(),
            key,
            open: HashMap::new(),
        };
        let id = store
            .history("host")
            .unwrap()
            .append(NewEntry {
                copied_at: 100,
                contents: vec![Content {
                    mime: "text/plain".into(),
                    data: b"private note".to_vec(),
                }],
                preview: None,
            })
            .unwrap()
            .id();
        let reply = store.answer(&format!("favorite\thost\t{id}"));
        assert!(matches!(reply, Reply::Text(ref s) if s.starts_with("ok\t")));
        assert_eq!(store.names(), ["host"]);
        assert!(store.history("host").unwrap().delete(id).unwrap());
        let ids = store
            .history("@favorites:host")
            .unwrap()
            .query(&clipstore::Query::default(), None, 10)
            .unwrap();
        assert_eq!(ids.len(), 1);
        let saved = store
            .history("@favorites:host")
            .unwrap()
            .get(ids[0])
            .unwrap()
            .unwrap();
        assert_eq!(saved.contents[0].data, b"private note");
        assert!(store.history("@favorites:../host").is_err());
        drop(store);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_password_moves_out_of_history_without_searching_its_text() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("cw-clip-secret-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = Key::load_or_create(&dir.join("key")).unwrap();
        let mut store = Store {
            dir: dir.clone(),
            key,
            open: HashMap::new(),
        };
        let id = store
            .history("host")
            .unwrap()
            .append(NewEntry {
                copied_at: 100,
                contents: vec![Content {
                    mime: "text/plain".into(),
                    data: b"hidden-password".to_vec(),
                }],
                preview: None,
            })
            .unwrap()
            .id();
        assert!(
            matches!(store.answer(&format!("secret\thost\t{id}\tMail")), Reply::Text(ref s) if s.starts_with("ok\t"))
        );
        assert!(store.history("host").unwrap().get(id).unwrap().is_none());
        assert_eq!(store.names(), ["host"]);
        let listed = store.answer("search\t@secrets:host\tlimit=10");
        assert!(
            matches!(listed, Reply::Text(ref s) if s.contains("Пароль: Mail") && !s.contains("hidden-password"))
        );
        assert!(
            matches!(store.answer("search\t@secrets:host\tq=hidden-password"), Reply::Text(ref s) if s.starts_with("error\t"))
        );
        assert!(
            matches!(store.answer("move\t@secrets:host\t1\thost"), Reply::Text(ref s) if s.starts_with("error\t"))
        );
        assert!(store.history("@secrets:../host").is_err());
        store.keep(
            "host",
            NewEntry {
                copied_at: 200,
                contents: vec![Content {
                    mime: "UTF8_STRING".into(),
                    data: b"hidden-password".to_vec(),
                }],
                preview: None,
            },
        );
        assert!(store
            .history("host")
            .unwrap()
            .query(&clipstore::Query::default(), None, 10)
            .unwrap()
            .is_empty());
        let secret = store
            .history("@secrets:host")
            .unwrap()
            .get(1)
            .unwrap()
            .unwrap();
        assert_eq!(secret.copies, [100]);
        store.keep(
            "host",
            NewEntry {
                copied_at: 300,
                contents: vec![Content {
                    mime: "text/plain".into(),
                    data: b"ordinary note".to_vec(),
                }],
                preview: None,
            },
        );
        let kept = store
            .history("host")
            .unwrap()
            .query(&clipstore::Query::default(), None, 10)
            .unwrap();
        assert_eq!(
            kept,
            [id + 1],
            "a suppressed password must not consume an ordinary-history id"
        );
        assert!(
            matches!(store.answer("select\t@secrets:host\t1"), Reply::Select(ref c) if c.iter().any(|c| c.mime == recorder::SECRET_HINT && c.data == b"secret"))
        );
        drop(store);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
