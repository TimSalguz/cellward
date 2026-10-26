//! Trusted host recorder of private selections. Never publishes to Wayland.
use crate::clipboard_client::{Client, Reply, Request, Selection};
use crate::clipboard_endpoint;
use crate::recorder;
use std::collections::HashMap;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::sync::mpsc::{self, Receiver};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

pub const RESTORED: &str = "application/x-cellward-restored";
pub struct Entry {
    pub history: String,
    pub contents: Vec<(String, crate::clipboard_client::Bytes)>,
}
struct Tap {
    client: Client,
    changed: OwnedFd,
    history: String,
    seen: Option<u64>,
}
pub struct Recorder {
    entries: Receiver<Entry>,
    stopped: Arc<AtomicBool>,
}
impl Recorder {
    pub fn try_recv(&self) -> Result<Entry, mpsc::TryRecvError> {
        self.entries.try_recv()
    }
}
impl Drop for Recorder {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Relaxed);
    }
}

/// Blocking only in the dedicated recorder worker, with bounded protocol I/O.
pub fn exchange(client: &mut Client, request: Request<'_>) -> io::Result<Reply> {
    client.start(Selection::Clipboard, request, Instant::now())?;
    loop {
        if let Some(reply) = client.tick(Instant::now()) {
            return reply;
        }
        let mut fd = libc::pollfd {
            fd: client.socket().as_raw_fd(),
            events: if client.wants_write() {
                libc::POLLOUT
            } else {
                libc::POLLIN
            },
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut fd, 1, 50) };
        if rc < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
    }
}

pub fn start(runtime: &Path) -> Recorder {
    // At most one queued selection; the controller and active buffers keep
    // working even while history is busy encrypting or compacting its store.
    let (send, receive) = mpsc::sync_channel(1);
    let stopped = Arc::new(AtomicBool::new(false));
    let stop = stopped.clone();
    let runtime = runtime.to_owned();
    std::thread::spawn(move || {
        let mut taps: HashMap<String, Tap> = HashMap::new();
        let mut discover = Instant::now();
        loop {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            if Instant::now() >= discover {
                if let Ok(scopes) = clipboard_endpoint::list(&runtime) {
                    taps.retain(|id, _| scopes.iter().any(|(live, _)| live == id));
                    for (id, history) in scopes {
                        if history == recorder::NO_HISTORY || taps.contains_key(&id) {
                            continue;
                        }
                        if let Ok(bound) = clipboard_endpoint::lookup(&runtime, &id) {
                            if let Ok(client) = Client::new(bound.data) {
                                taps.insert(
                                    id,
                                    Tap {
                                        client,
                                        changed: bound.changed,
                                        history,
                                        seen: None,
                                    },
                                );
                            }
                        }
                    }
                } else {
                    taps.clear();
                }
                discover = Instant::now() + Duration::from_secs(1);
            }
            let mut dead = Vec::new();
            for (id, tap) in &mut taps {
                let mut changed = 0u64;
                let n = unsafe {
                    libc::read(
                        tap.changed.as_raw_fd(),
                        (&mut changed as *mut u64).cast(),
                        8,
                    )
                };
                if n != 8 && tap.seen.is_some() {
                    continue;
                }
                let Ok(Reply::Types(selection)) = exchange(&mut tap.client, Request::Types) else {
                    dead.push(id.clone());
                    continue;
                };
                let Some((revision, types)) = selection else {
                    // Revisions start at one; zero means an observed empty
                    // selection. Wait for its eventfd instead of polling it.
                    tap.seen = Some(0);
                    continue;
                };
                if tap.seen == Some(revision) {
                    continue;
                }
                tap.seen = Some(revision);
                if recorder::is_secret(&types) || types.iter().any(|t| t == RESTORED) {
                    continue;
                }
                let mut contents = Vec::new();
                let mut complete = true;
                for mime in recorder::to_read(&types) {
                    match exchange(
                        &mut tap.client,
                        Request::Read {
                            revision,
                            mime: &mime,
                        },
                    ) {
                        Ok(Reply::Data(bytes)) => contents.push((mime, bytes)),
                        _ => {
                            complete = false;
                            break;
                        }
                    }
                }
                if complete && !contents.is_empty() {
                    match send.try_send(Entry {
                        history: tap.history.clone(),
                        contents,
                    }) {
                        Ok(()) => {}
                        Err(mpsc::TrySendError::Full(_)) => {
                            // Retry this revision after the consumer catches up.
                            tap.seen = None;
                        }
                        Err(mpsc::TrySendError::Disconnected(_)) => return,
                    }
                }
            }
            for id in dead {
                taps.remove(&id);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
    Recorder {
        entries: receive,
        stopped,
    }
}
