//! Instance-private Wayland selections. Enabled only with a host-bound FD.
//! Never publishes a selection upstream or imports one on focus/paste.
use super::*;
use crate::clipboard_client::{Bytes, Client as BrokerClient, Reply, Request, Selection};
use crate::clipboard_endpoint::Bound;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};

const LIMIT: usize = 64 << 20;
const QUANTUM: usize = 64 << 10;
const PENDING: usize = 64;

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
            changed: File::from(bound.changed),
            operation: None,
            selections: [None, None],
            devices: Vec::new(),
            primary: Vec::new(),
            refresh: [true; 2],
            clear: [false; 2],
            capture: None,
            waiting: VecDeque::new(),
            publish: VecDeque::new(),
            reads: VecDeque::new(),
            writes: VecDeque::new(),
        })
    });
    Ok(())
}

pub(crate) fn keep_fds() -> Vec<RawFd> {
    STATE.with(|s| {
        s.borrow().as_ref().map_or(Vec::new(), |s| {
            let mut fds = vec![s.changed.as_raw_fd()];
            if let Some(client) = &s.client {
                fds.push(client.socket().as_raw_fd());
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
            if let Some(capture) = &s.capture {
                if let Some((file, _)) = &capture.pipe {
                    fds.push(p(file.as_raw_fd(), false));
                }
            }
            fds.extend(s.writes.iter().map(|w| p(w.file.as_raw_fd(), true)));
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
                .chain(s.capture.as_ref().map(|c| c.deadline))
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
                .retain(|d| d.upgrade().is_some_and(|d| !d.state().is_destroyed()));
            if s.devices.len() < 128 {
                s.devices.push(Rc::downgrade(device));
                announce(device, s.selections[0].as_ref());
            }
        }
    });
}
pub(super) fn register_primary(device: &Rc<ZwpPrimarySelectionDeviceV1>) {
    STATE.with(|s| {
        if let Some(s) = &mut *s.borrow_mut() {
            s.primary
                .retain(|d| d.upgrade().is_some_and(|d| !d.state().is_destroyed()));
            if s.primary.len() < 128 {
                s.primary.push(Rc::downgrade(device));
                announce_primary(device, s.selections[1].as_ref());
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
pub(super) fn set(which: Selection, source: Option<SourceRef>, types: Vec<String>, overflow: bool) {
    STATE.with(|s| {
        if let Some(s) = &mut *s.borrow_mut() {
            if s.client.is_none() {
                return;
            }
            let at = index(which);
            s.waiting.retain(|(w, _, _)| index(*w) != at);
            s.publish.retain(|p| index(p.which) != at);
            if s.capture.as_ref().is_some_and(|c| index(c.which) == at) {
                s.capture = None;
            }
            if let Some(source) = source {
                s.clear[at] = false;
                if !overflow && !types.is_empty() {
                    s.waiting.push_back((which, source, types));
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
struct Payload {
    mime: String,
    bytes: Bytes,
}
struct Publication {
    which: Selection,
    contents: Vec<Payload>,
}
struct Capture {
    which: Selection,
    source: SourceRef,
    types: VecDeque<String>,
    contents: Vec<Payload>,
    pipe: Option<(File, Payload)>,
    deadline: Instant,
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
    Clear(Selection),
    Set(Selection, Rc<Vec<String>>),
    Read(ReadRequest),
}
struct State {
    client: Option<BrokerClient>,
    changed: File,
    operation: Option<Operation>,
    selections: [Option<Snapshot>; 2],
    devices: Vec<Weak<WlDataDevice>>,
    primary: Vec<Weak<ZwpPrimarySelectionDeviceV1>>,
    refresh: [bool; 2],
    clear: [bool; 2],
    capture: Option<Capture>,
    waiting: VecDeque<(Selection, SourceRef, Vec<String>)>,
    publish: VecDeque<Publication>,
    reads: VecDeque<ReadRequest>,
    writes: VecDeque<Transfer>,
}

impl State {
    fn disable(&mut self) {
        self.client = None;
        self.operation = None;
        self.capture = None;
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
        if at == 0 {
            for device in self
                .devices
                .iter()
                .filter_map(Weak::upgrade)
                .filter(|d| !d.state().is_destroyed())
            {
                announce(&device, self.selections[at].as_ref());
            }
        } else {
            for device in self
                .primary
                .iter()
                .filter_map(Weak::upgrade)
                .filter(|d| !d.state().is_destroyed())
            {
                announce_primary(&device, self.selections[at].as_ref());
            }
        }
    }
    fn tick(&mut self, now: Instant) {
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
                (Some(Operation::Set(which, types)), Reply::Set(revision)) => {
                    self.selected(which, Some((revision, types.as_ref().clone())));
                    self.refresh[index(which)] = true;
                }
                (Some(Operation::Clear(which)), Reply::Cleared) => self.selected(which, None),
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
        if self.capture.is_none() {
            if let Some((which, source, types)) = self.waiting.pop_front() {
                self.capture = Some(Capture {
                    which,
                    source,
                    types: types.into(),
                    contents: Vec::new(),
                    pipe: None,
                    deadline: now + Duration::from_secs(3),
                });
            }
        }
        if let Some(capture) = &mut self.capture {
            match capture.tick(now) {
                Ok(true) => {
                    let c = self.capture.take().unwrap();
                    self.publish.push_back(Publication {
                        which: c.which,
                        contents: c.contents,
                    });
                }
                Ok(false) => {}
                Err(_) => self.capture = None,
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
            Some(Operation::Clear(which))
        } else if let Some(publish) = self.publish.pop_front() {
            let parts: Vec<_> = publish
                .contents
                .iter()
                .map(|p| (p.mime.as_str(), p.bytes.as_slice()))
                .collect();
            if client
                .start(publish.which, Request::Set(&parts), now)
                .is_err()
            {
                return;
            }
            Some(Operation::Set(
                publish.which,
                Rc::new(publish.contents.iter().map(|p| p.mime.clone()).collect()),
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
impl Capture {
    fn tick(&mut self, now: Instant) -> io::Result<bool> {
        if now >= self.deadline || !self.source.alive() {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        let mut budget = QUANTUM;
        while budget > 0 {
            if self.pipe.is_none() {
                let Some(mime) = self.types.pop_front() else {
                    return Ok(true);
                };
                let (read, write) = crate::sys::pipe()?;
                let write = Rc::new(write);
                nonblocking(read.as_raw_fd())?;
                self.source.send(&mime, &write);
                self.pipe = Some((
                    File::from(read),
                    Payload {
                        mime,
                        bytes: Bytes::default(),
                    },
                ));
            }
            let remaining =
                LIMIT.saturating_sub(self.contents.iter().map(|p| p.bytes.allocated()).sum());
            let (file, payload) = self.pipe.as_mut().unwrap();
            let mut buffer = [0; 8192];
            let n = match file.read(&mut buffer[..budget.min(8192)]) {
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(false)
                }
                Err(e) => return Err(e),
            };
            if n == 0 {
                self.contents.push(self.pipe.take().unwrap().1);
                continue;
            }
            let result = payload.bytes.append(&buffer[..n], remaining);
            crate::clipboard_client::erase_slice(&mut buffer);
            result?;
            budget -= n;
        }
        Ok(false)
    }
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
