//! Instance-private Wayland selections. Enabled only with a host-bound FD.
//! Never publishes a selection upstream or imports one on focus/paste.
use super::*;
use crate::clipboard_client::{Bytes, Client as BrokerClient, Reply, Request, Selection};
use crate::clipboard_endpoint::Bound;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};

mod capture;
use capture::{CaptureData, Payload};
mod metadata;
use metadata::Metadata;

const LIMIT: usize = 64 << 20;
const QUANTUM: usize = 64 << 10;
const PENDING: usize = 64;
/// Explicit opt-in for initialized windowless clients, never clipboard data.
pub(super) const READY_MIME: &str = "application/x-cellward-private-ready";

thread_local! { static STATE: RefCell<Option<State>> = const { RefCell::new(None) }; }
fn index(which: Selection) -> usize {
    match which {
        Selection::Clipboard => 0,
        Selection::Primary => 1,
    }
}
fn choice(at: usize) -> Selection {
    if at == 0 {
        Selection::Clipboard
    } else {
        Selection::Primary
    }
}

pub(crate) fn enabled() -> bool {
    STATE.with(|s| s.borrow().is_some())
}
pub(crate) fn initialize(bound: Bound) -> io::Result<()> {
    let client = BrokerClient::new(bound.data)?;
    STATE.with(|s| {
        *s.borrow_mut() = Some(State {
            client: Some(client),
            metadata: bound.captures.map(Metadata::new).transpose()?,
            local: [0; 2],
            changing: [None; 2],
            epochs: [None; 2],
            changed: File::from(bound.changed),
            operation: None,
            selections: [None, None],
            devices: Vec::new(),
            primary: Vec::new(),
            refresh: [true; 2],
            clear: [false; 2],
            capture: [None, None],
            waiting: VecDeque::new(),
            publish: VecDeque::new(),
            reads: VecDeque::new(),
            writes: VecDeque::new(),
        });
        Ok::<_, io::Error>(())
    })?;
    Ok(())
}

pub(crate) fn keep_fds() -> Vec<RawFd> {
    STATE.with(|s| {
        s.borrow().as_ref().map_or(Vec::new(), |s| {
            let mut fds = vec![s.changed.as_raw_fd()];
            if let Some(client) = &s.client {
                fds.push(client.socket().as_raw_fd());
            }
            if let Some(meta) = &s.metadata {
                fds.push(meta.fd());
            }
            fds
        })
    })
}
pub(crate) fn data_fd() -> Option<RawFd> {
    STATE.with(|s| {
        s.borrow()
            .as_ref()
            .and_then(|s| s.client.as_ref().map(|c| c.socket().as_raw_fd()))
    })
}

pub(crate) fn socket_fds() -> Vec<RawFd> {
    let mut fds: Vec<_> = data_fd().into_iter().collect();
    STATE.with(|s| {
        if let Some(meta) = s.borrow().as_ref().and_then(|s| s.metadata.as_ref()) {
            fds.push(meta.fd());
        }
    });
    fds
}

pub(crate) fn smart_enabled() -> bool {
    STATE.with(|s| {
        s.borrow().as_ref().is_some_and(|s| {
            s.client.is_some()
                && s.metadata
                    .as_ref()
                    .and_then(|m| m.caps)
                    .is_some_and(|caps| caps & 2 != 0)
        })
    })
}

pub(crate) fn revision() -> Option<u64> {
    STATE.with(|s| {
        s.borrow().as_ref().and_then(|s| {
            (s.client.is_some()
                && s.changing[0].is_none()
                && !s.refresh[0]
                && !matches!(s.operation, Some(Operation::Types(Selection::Clipboard))))
            .then(|| s.selections[0].as_ref().map_or(0, |s| s.revision))
        })
    })
}

pub(crate) fn pollfds() -> Vec<libc::pollfd> {
    STATE.with(|s| {
        s.borrow().as_ref().map_or(Vec::new(), |s| {
            let p = |fd, write| libc::pollfd {
                fd,
                events: if write { libc::POLLOUT } else { libc::POLLIN },
                revents: 0,
            };
            let mut fds = Vec::new();
            if let Some(client) = &s.client {
                fds.push(p(client.socket().as_raw_fd(), client.wants_write()));
                fds.push(p(s.changed.as_raw_fd(), false));
            }
            for capture in s.capture.iter().flatten() {
                if let Some(fd) = capture.data.fd() {
                    fds.push(p(fd, false));
                }
            }
            fds.extend(s.writes.iter().map(|w| p(w.file.as_raw_fd(), true)));
            if let Some(meta) = &s.metadata {
                fds.push(meta.pollfd());
            }
            fds
        })
    })
}
pub(crate) fn wake_at() -> Option<Instant> {
    STATE.with(|s| {
        s.borrow().as_ref().and_then(|s| {
            s.client
                .as_ref()
                .and_then(BrokerClient::next_deadline)
                .into_iter()
                .chain(s.capture.iter().flatten().map(|c| c.data.wake_at()))
                .chain(s.metadata.as_ref().and_then(Metadata::deadline))
                .chain(s.writes.iter().map(|w| w.deadline))
                .min()
        })
    })
}
pub(crate) fn tick(now: Instant) {
    STATE.with(|s| {
        if let Some(s) = &mut *s.borrow_mut() {
            s.tick(now);
        }
    });
}

pub(super) fn register(device: &Rc<WlDataDevice>) {
    STATE.with(|s| {
        if let Some(s) = &mut *s.borrow_mut() {
            s.devices
                .retain(|(d, _)| d.upgrade().is_some_and(|d| !d.state().is_destroyed()));
            if s.devices.len() < 128 {
                s.devices.push((Rc::downgrade(device), false));
            }
        }
    });
}
pub(super) fn register_primary(device: &Rc<ZwpPrimarySelectionDeviceV1>) {
    STATE.with(|s| {
        if let Some(s) = &mut *s.borrow_mut() {
            s.primary
                .retain(|(d, _)| d.upgrade().is_some_and(|d| !d.state().is_destroyed()));
            if s.primary.len() < 128 {
                s.primary.push((Rc::downgrade(device), false));
            }
        }
    });
}

pub(super) fn ready(device: &Rc<WlDataDevice>) {
    STATE.with(|s| {
        if let Some(s) = &mut *s.borrow_mut() {
            if let Some((_, ready)) = s
                .devices
                .iter_mut()
                .find(|(d, _)| d.upgrade().is_some_and(|d| Rc::ptr_eq(&d, device)))
            {
                if !*ready {
                    *ready = true;
                    if s.changing[0].is_none() {
                        announce(device, s.selections[0].as_ref());
                    }
                }
            }
        }
    });
}
pub(super) fn ready_primary(device: &Rc<ZwpPrimarySelectionDeviceV1>) {
    STATE.with(|s| {
        if let Some(s) = &mut *s.borrow_mut() {
            if let Some((_, ready)) = s
                .primary
                .iter_mut()
                .find(|(d, _)| d.upgrade().is_some_and(|d| Rc::ptr_eq(&d, device)))
            {
                if !*ready {
                    *ready = true;
                    if s.changing[1].is_none() {
                        announce_primary(device, s.selections[1].as_ref());
                    }
                }
            }
        }
    });
}

#[derive(Clone)]
pub(super) enum SourceRef {
    Clipboard(Rc<WlDataSource>, Rc<Cell<bool>>),
    Primary(Rc<ZwpPrimarySelectionSourceV1>, Rc<Cell<bool>>),
}
impl SourceRef {
    fn alive(&self) -> bool {
        match self {
            Self::Clipboard(s, a) => a.get() && !s.state().is_destroyed(),
            Self::Primary(s, a) => a.get() && !s.state().is_destroyed(),
        }
    }
    fn send(&self, mime: &str, fd: &Rc<OwnedFd>) {
        match self {
            Self::Clipboard(s, _) => s.send_send(mime, fd),
            Self::Primary(s, _) => s.send_send(mime, fd),
        }
    }
}
pub(super) fn set(
    which: Selection,
    source: Option<SourceRef>,
    mut types: Vec<String>,
    overflow: bool,
) {
    types.retain(|mime| mime != READY_MIME);
    STATE.with(|s| {
        if let Some(s) = &mut *s.borrow_mut() {
            if s.client.is_none() {
                return;
            }
            let at = index(which);
            let Some(local) = s.local[at].checked_add(1) else {
                s.disable();
                return;
            };
            s.local[at] = local;
            s.changing[at] = Some(local);
            if let Some(meta) = &mut s.metadata {
                meta.forget(which);
                if let Some((_, epoch)) = s.epochs[at].take() {
                    meta.abort(which, epoch);
                }
            }
            s.waiting.retain(|(w, _, _)| index(*w) != at);
            s.publish.retain(|p| index(p.which) != at);
            s.capture[at] = None;
            if let Some(source) = source {
                s.clear[at] = false;
                if let Some(meta) = &mut s.metadata {
                    let user_copy =
                        at == 0 && !types.iter().any(|t| t == "application/x-cellward-restored");
                    meta.begin(which, local, user_copy);
                }
                if !overflow && !types.is_empty() {
                    s.waiting.push_back((which, source, types));
                } else {
                    s.changing[at] = None;
                }
            } else {
                s.clear[at] = true;
            }
        }
    });
}

#[derive(Clone)]
struct Snapshot {
    revision: u64,
    types: Rc<Vec<String>>,
    which: Selection,
}
struct Publication {
    which: Selection,
    contents: Vec<Payload>,
    local: u64,
}
struct Capture {
    which: Selection,
    source: SourceRef,
    data: CaptureData,
    local: u64,
}
struct ReadRequest {
    revision: u64,
    which: Selection,
    mime: String,
    file: File,
}
struct Transfer {
    file: File,
    bytes: Bytes,
    written: usize,
    deadline: Instant,
}
enum Operation {
    Types(Selection),
    Clear(Selection, u64),
    Set(Selection, Rc<Vec<String>>, u64),
    Read(ReadRequest),
}
struct State {
    client: Option<BrokerClient>,
    metadata: Option<Metadata>,
    local: [u64; 2],
    changing: [Option<u64>; 2],
    epochs: [Option<(u64, u64)>; 2],
    changed: File,
    operation: Option<Operation>,
    selections: [Option<Snapshot>; 2],
    devices: Vec<(Weak<WlDataDevice>, bool)>,
    primary: Vec<(Weak<ZwpPrimarySelectionDeviceV1>, bool)>,
    refresh: [bool; 2],
    clear: [bool; 2],
    capture: [Option<Capture>; 2],
    waiting: VecDeque<(Selection, SourceRef, Vec<String>)>,
    publish: VecDeque<Publication>,
    reads: VecDeque<ReadRequest>,
    writes: VecDeque<Transfer>,
}

impl State {
    fn disable(&mut self) {
        self.client = None;
        self.metadata = None;
        self.changing = [None; 2];
        self.operation = None;
        self.capture = [None, None];
        self.waiting.clear();
        self.publish.clear();
        self.reads.clear();
        self.writes.clear();
        self.selected(Selection::Clipboard, None);
        self.selected(Selection::Primary, None);
    }
    fn selected(&mut self, which: Selection, value: Option<(u64, Vec<String>)>) {
        let at = index(which);
        let revision = value.as_ref().map(|(r, _)| *r);
        if self.selections[at].as_ref().map(|s| s.revision) == revision {
            return;
        }
        self.selections[at] = value.map(|(revision, types)| Snapshot {
            revision,
            types: Rc::new(types),
            which,
        });
        if self.changing[at].is_none() {
            self.announce(which);
        }
    }

    fn announce(&self, which: Selection) {
        let at = index(which);
        if at == 0 {
            for device in self
                .devices
                .iter()
                .filter(|(_, ready)| *ready)
                .filter_map(|(d, _)| d.upgrade())
                .filter(|d| !d.state().is_destroyed())
            {
                announce(&device, self.selections[at].as_ref());
            }
        } else {
            for device in self
                .primary
                .iter()
                .filter(|(_, ready)| *ready)
                .filter_map(|(d, _)| d.upgrade())
                .filter(|d| !d.state().is_destroyed())
            {
                announce_primary(&device, self.selections[at].as_ref());
            }
        }
    }

    fn release_local(&mut self, which: Selection, local: u64, failed: bool) {
        let at = index(which);
        if self.changing[at] == Some(local) {
            self.changing[at] = None;
            if let Some((generation, epoch)) = self.epochs[at].take() {
                if failed && generation == local {
                    if let Some(meta) = &mut self.metadata {
                        meta.abort(which, epoch);
                    }
                }
            }
            self.announce(which);
        }
    }
    fn tick(&mut self, now: Instant) {
        if let Some(meta) = &mut self.metadata {
            match meta.tick(now) {
                Ok(Some(begun)) => {
                    let at = index(begun.which);
                    if self.changing[at] == Some(begun.local) {
                        self.epochs[at] = Some((begun.local, begun.epoch));
                    } else {
                        meta.abort(begun.which, begun.epoch);
                    }
                }
                Ok(None) => {}
                Err(()) => {
                    eprintln!("wl-sandbox: private clipboard metadata unavailable");
                    self.metadata = None;
                    self.epochs = [None; 2];
                }
            }
        }
        let Some(client) = &mut self.client else {
            return;
        };
        if crate::sys::poll_events_now(client.socket().as_raw_fd(), libc::POLLIN)
            .is_ok_and(|events| events & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0)
        {
            self.disable();
            return;
        }
        let mut changed = [0; 8];
        if self.changed.read(&mut changed).is_ok_and(|n| n == 8) {
            self.refresh = [true; 2];
        }
        if let Some(result) = client.tick(now) {
            let Ok(reply) = result else {
                self.disable();
                return;
            };
            match (self.operation.take(), reply) {
                (Some(Operation::Types(which)), Reply::Types(value)) => self.selected(which, value),
                (Some(Operation::Set(which, types, local)), Reply::Set(revision)) => {
                    self.selected(which, Some((revision, types.as_ref().clone())));
                    self.release_local(which, local, false);
                    self.refresh[index(which)] = true;
                }
                (Some(Operation::Clear(which, local)), Reply::Cleared) => {
                    self.selected(which, None);
                    self.release_local(which, local, false);
                }
                (Some(Operation::Read(read)), Reply::Data(bytes)) => {
                    let allocated: usize = self.writes.iter().map(|w| w.bytes.allocated()).sum();
                    if allocated.saturating_add(bytes.allocated()) <= LIMIT {
                        self.writes.push_back(Transfer {
                            file: read.file,
                            bytes,
                            written: 0,
                            deadline: now + Duration::from_secs(3),
                        });
                    }
                }
                (
                    Some(Operation::Set(which, _, local) | Operation::Clear(which, local)),
                    Reply::Rejected(_),
                ) => {
                    self.release_local(which, local, true);
                    self.refresh[index(which)] = true;
                }
                (Some(_), Reply::Rejected(_)) => {}
                _ => {
                    self.disable();
                    return;
                }
            }
        }
        let mut budget = QUANTUM;
        self.writes.retain_mut(|w| {
            if now >= w.deadline {
                return false;
            }
            let end = w.bytes.as_slice().len().min(w.written + budget);
            if end > w.written {
                match w.file.write(&w.bytes.as_slice()[w.written..end]) {
                    Ok(0) => return false,
                    Ok(n) => {
                        w.written += n;
                        budget -= n;
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => return false,
                }
            }
            w.written < w.bytes.as_slice().len()
        });
        // PRIMARY must never hold a new explicit copy behind a stalled
        // selection. Both captures share one read quantum and payload budget.
        let mut budget = QUANTUM;
        for at in 0..2 {
            if self.capture[at].is_none() {
                if let Some(pos) = self.waiting.iter().position(|(w, _, _)| index(*w) == at) {
                    let (which, source, types) = self.waiting.remove(pos).unwrap();
                    self.capture[at] = Some(Capture {
                        which,
                        source,
                        data: CaptureData::new(types, now),
                        local: self.local[at],
                    });
                }
            }
            let other = self.capture[1 - at]
                .as_ref()
                .map_or(0, |c| c.data.allocated());
            let queued: usize = self
                .publish
                .iter()
                .flat_map(|p| &p.contents)
                .map(Payload::allocated)
                .sum();
            if let Some(capture) = &mut self.capture[at] {
                let source = &capture.source;
                if capture.data.tick(
                    now,
                    source.alive(),
                    &mut budget,
                    LIMIT.saturating_sub(other + queued),
                    |mime, fd| source.send(mime, fd),
                ) {
                    let c = self.capture[at].take().unwrap();
                    if c.data.failures() != 0 {
                        // Counts only: no MIME strings or clipboard contents.
                        eprintln!("wl-sandbox: private {} capture: {} completed formats, {} failed formats",
                            if at == 0 { "CLIPBOARD" } else { "PRIMARY" },
                            c.data.contents.len(), c.data.failures());
                    }
                    if !c.data.contents.is_empty() {
                        self.publish.push_back(Publication {
                            which: c.which,
                            contents: c.data.contents,
                            local: c.local,
                        });
                    } else {
                        self.release_local(c.which, c.local, true);
                    }
                }
            }
        }
        let Some(client) = &mut self.client else {
            return;
        };
        if client.busy() {
            return;
        }
        let operation = if let Some(at) = self.clear.iter().position(|v| *v) {
            self.clear[at] = false;
            let which = choice(at);
            if client.start(which, Request::Clear, now).is_err() {
                self.disable();
                return;
            }
            Some(Operation::Clear(which, self.local[at]))
        } else if self.publish.front().is_some_and(|p| {
            self.metadata.is_none()
                || self.epochs[index(p.which)].is_some_and(|(local, _)| local == p.local)
        }) {
            let publish = self.publish.pop_front().unwrap();
            let parts: Vec<_> = publish
                .contents
                .iter()
                .map(|p| (p.mime.as_str(), p.bytes.as_slice()))
                .collect();
            let request = if self.metadata.is_some() {
                Request::FinishCapture {
                    epoch: self.epochs[index(publish.which)].unwrap().1,
                    parts: &parts,
                }
            } else {
                Request::Set(&parts)
            };
            if client.start(publish.which, request, now).is_err() {
                self.release_local(publish.which, publish.local, true);
                return;
            }
            Some(Operation::Set(
                publish.which,
                Rc::new(publish.contents.iter().map(|p| p.mime.clone()).collect()),
                publish.local,
            ))
        } else if let Some(at) = self.refresh.iter().position(|v| *v) {
            self.refresh[at] = false;
            let which = choice(at);
            if client.start(which, Request::Types, now).is_err() {
                self.disable();
                return;
            }
            Some(Operation::Types(which))
        } else if let Some(read) = self.reads.pop_front() {
            if client
                .start(
                    read.which,
                    Request::Read {
                        revision: read.revision,
                        mime: &read.mime,
                    },
                    now,
                )
                .is_err()
            {
                return;
            }
            Some(Operation::Read(read))
        } else {
            None
        };
        self.operation = operation;
    }
}

fn nonblocking(fd: RawFd) -> io::Result<()> {
    crate::sys::set_nonblocking(fd)
}

fn receive(snapshot: &Snapshot, mime: &str, fd: &Rc<OwnedFd>) {
    if !snapshot.types.iter().any(|s| s == mime) {
        return;
    }
    STATE.with(|s| {
        if let Some(s) = &mut *s.borrow_mut() {
            if s.client.is_none() || s.reads.len() + s.writes.len() >= PENDING {
                return;
            }
            let Ok(fd) = fd.try_clone() else { return };
            if nonblocking(fd.as_raw_fd()).is_err() {
                return;
            }
            s.reads.push_back(ReadRequest {
                revision: snapshot.revision,
                which: snapshot.which,
                mime: mime.to_owned(),
                file: File::from(fd),
            });
        }
    });
}
fn announce(device: &Rc<WlDataDevice>, snapshot: Option<&Snapshot>) {
    let Some(snapshot) = snapshot else {
        device.send_selection(None);
        return;
    };
    let offer = device.create_child::<WlDataOffer>();
    offer.set_handler(PrivateOffer(snapshot.clone()));
    device.send_data_offer(&offer);
    for mime in snapshot.types.iter() {
        offer.send_offer(mime);
    }
    device.send_selection(Some(&offer));
}
fn announce_primary(device: &Rc<ZwpPrimarySelectionDeviceV1>, snapshot: Option<&Snapshot>) {
    let Some(snapshot) = snapshot else {
        device.send_selection(None);
        return;
    };
    let offer = device.create_child::<ZwpPrimarySelectionOfferV1>();
    offer.set_handler(PrivatePrimaryOffer(snapshot.clone()));
    device.send_data_offer(&offer);
    for mime in snapshot.types.iter() {
        offer.send_offer(mime);
    }
    device.send_selection(Some(&offer));
}
struct PrivateOffer(Snapshot);
impl WlDataOfferHandler for PrivateOffer {
    fn handle_receive(&mut self, _: &Rc<WlDataOffer>, mime: &str, fd: &Rc<OwnedFd>) {
        receive(&self.0, mime, fd);
    }
    fn handle_destroy(&mut self, slf: &Rc<WlDataOffer>) {
        slf.delete_id();
    }
    fn handle_accept(&mut self, _: &Rc<WlDataOffer>, _: u32, _: Option<&str>) {}
    fn handle_finish(&mut self, _: &Rc<WlDataOffer>) {}
    fn handle_set_actions(
        &mut self,
        _: &Rc<WlDataOffer>,
        _: wl_proxy::protocols::wayland::wl_data_device_manager::WlDataDeviceManagerDndAction,
        _: wl_proxy::protocols::wayland::wl_data_device_manager::WlDataDeviceManagerDndAction,
    ) {
    }
}
struct PrivatePrimaryOffer(Snapshot);
impl ZwpPrimarySelectionOfferV1Handler for PrivatePrimaryOffer {
    fn handle_receive(&mut self, _: &Rc<ZwpPrimarySelectionOfferV1>, mime: &str, fd: &Rc<OwnedFd>) {
        receive(&self.0, mime, fd);
    }
    fn handle_destroy(&mut self, slf: &Rc<ZwpPrimarySelectionOfferV1>) {
        slf.delete_id();
    }
}
