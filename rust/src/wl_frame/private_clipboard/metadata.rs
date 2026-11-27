//! Small copy-epoch and drag-registration messages on a separate pre-bound
//! socket. Large payloads cannot delay the identity of the next operation.
use super::*;

#[derive(Clone, Copy)]
struct Note {
    which: Selection,
    local: u64,
    user_copy: bool,
}
enum Operation {
    Probe,
    Begin(Note),
    Abort(Selection, u64),
    BeginDrag(u64),
    AbortDrag(u64),
}

pub(super) struct Metadata {
    client: BrokerClient,
    operation: Option<Operation>,
    pending: VecDeque<Operation>,
    pub caps: Option<u8>,
}
pub(super) struct Begun {
    pub which: Selection,
    pub local: u64,
    pub epoch: u64,
}

pub(super) enum Event {
    Capture(Begun),
    Drag,
}

impl Metadata {
    pub fn new(socket: std::os::unix::net::UnixStream) -> io::Result<Self> {
        Ok(Self {
            client: BrokerClient::new(socket)?,
            operation: None,
            pending: VecDeque::from([Operation::Probe]),
            caps: None,
        })
    }
    pub fn fd(&self) -> RawFd {
        self.client.socket().as_raw_fd()
    }
    pub fn pollfd(&self) -> libc::pollfd {
        libc::pollfd {
            fd: self.fd(),
            events: if self.client.wants_write() {
                libc::POLLOUT
            } else {
                libc::POLLIN
            },
            revents: 0,
        }
    }
    pub fn deadline(&self) -> Option<Instant> {
        self.client.next_deadline()
    }
    pub fn disconnect(&mut self) {
        self.client.disconnect();
        self.operation = None;
        self.pending = VecDeque::from([Operation::Probe]);
        self.caps = None;
    }
    pub fn reconnect(&mut self, socket: std::os::unix::net::UnixStream) -> io::Result<()> {
        self.client.reconnect(socket)?;
        self.operation = None;
        self.pending = VecDeque::from([Operation::Probe]);
        self.caps = None;
        Ok(())
    }
    pub fn forget(&mut self, which: Selection) {
        self.pending
            .retain(|op| !matches!(op, Operation::Begin(n) if index(n.which) == index(which)));
    }
    pub fn begin(&mut self, which: Selection, local: u64, user_copy: bool) {
        self.forget(which);
        self.pending.push_back(Operation::Begin(Note {
            which,
            local,
            user_copy,
        }));
    }
    pub fn abort(&mut self, which: Selection, epoch: u64) {
        if self.pending.len() < 16 {
            self.pending.push_back(Operation::Abort(which, epoch));
        }
    }
    pub fn begin_drag(&mut self, drag_id: u64) {
        if self.pending.len() < 16 {
            self.pending.push_back(Operation::BeginDrag(drag_id));
        }
    }
    pub fn abort_drag(&mut self, drag_id: u64) {
        if self.pending.len() < 16 {
            self.pending.push_back(Operation::AbortDrag(drag_id));
        }
    }
    pub fn tick(&mut self, now: Instant) -> Result<Option<Event>, ()> {
        if crate::sys::poll_events_now(self.fd(), libc::POLLIN)
            .is_ok_and(|events| events & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0)
        {
            return Err(());
        }
        let mut event = None;
        if let Some(reply) = self.client.tick(now) {
            match (self.operation.take(), reply.map_err(|_| ())?) {
                (Some(Operation::Probe), Reply::Capabilities(caps)) if caps & 1 != 0 => {
                    self.caps = Some(caps)
                }
                (Some(Operation::Begin(n)), Reply::Begun(epoch)) => {
                    event = Some(Event::Capture(Begun {
                        which: n.which,
                        local: n.local,
                        epoch,
                    }))
                }
                (Some(Operation::BeginDrag(expected)), Reply::Begun(drag_id))
                    if expected == drag_id =>
                {
                    event = Some(Event::Drag);
                }
                (Some(Operation::Abort(_, _) | Operation::AbortDrag(_)), Reply::Cleared) => {}
                _ => return Err(()),
            }
        }
        if !self.client.busy() {
            if let Some(operation) = self.pending.pop_front() {
                let (which, request) = match &operation {
                    Operation::Probe => (Selection::Clipboard, Request::Capabilities),
                    Operation::Begin(n) => (
                        n.which,
                        Request::BeginCapture {
                            user_copy: n.user_copy,
                        },
                    ),
                    Operation::Abort(which, epoch) => {
                        (*which, Request::AbortCapture { epoch: *epoch })
                    }
                    Operation::BeginDrag(drag_id) => (
                        Selection::Clipboard,
                        Request::BeginDrag { drag_id: *drag_id },
                    ),
                    Operation::AbortDrag(drag_id) => (
                        Selection::Clipboard,
                        Request::AbortDrag { drag_id: *drag_id },
                    ),
                };
                self.client.start(which, request, now).map_err(|_| ())?;
                self.operation = Some(operation);
            }
        }
        Ok(event)
    }
}
