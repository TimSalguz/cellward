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

#[derive(Debug, Eq, PartialEq)]
enum TapState {
    Live,
    Dead,
    Stop,
}

fn record(tap: &mut Tap, send: &mpsc::SyncSender<Entry>) -> TapState {
    let mut changed = 0u64;
    let n = unsafe {
        libc::read(
            tap.changed.as_raw_fd(),
            (&mut changed as *mut u64).cast(),
            8,
        )
    };
    if n != 8 && tap.seen.is_some() {
        return TapState::Live;
    }
    let selection = match exchange(&mut tap.client, Request::Types) {
        Ok(Reply::Types(selection)) => selection,
        Ok(Reply::Rejected(_)) => return TapState::Live,
        Ok(_) | Err(_) => return TapState::Dead,
    };
    let Some((revision, types)) = selection else {
        // Revisions start at one; zero means an observed empty selection.
        // Wait for its eventfd instead of polling it.
        tap.seen = Some(0);
        return TapState::Live;
    };
    if tap.seen == Some(revision) {
        return TapState::Live;
    }
    if recorder::is_secret(&types) || types.iter().any(|t| t == RESTORED) {
        tap.seen = Some(revision);
        return TapState::Live;
    }
    let mut contents = Vec::new();
    for mime in recorder::to_read(&types) {
        match exchange(
            &mut tap.client,
            Request::Read {
                revision,
                mime: &mime,
            },
        ) {
            Ok(Reply::Data(bytes)) => contents.push((mime, bytes)),
            Ok(Reply::Rejected(_)) => {
                tap.seen = Some(revision);
                return TapState::Live;
            }
            Ok(_) | Err(_) => return TapState::Dead,
        }
    }
    if contents.is_empty() {
        tap.seen = Some(revision);
        return TapState::Live;
    }
    match send.try_send(Entry {
        history: tap.history.clone(),
        contents,
    }) {
        Ok(()) => {
            tap.seen = Some(revision);
            TapState::Live
        }
        Err(mpsc::TrySendError::Full(_)) => {
            // Retry this revision after the consumer catches up.
            tap.seen = None;
            TapState::Live
        }
        Err(mpsc::TrySendError::Disconnected(_)) => TapState::Stop,
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
                        if history == recorder::NO_HISTORY {
                            taps.remove(&id);
                            continue;
                        }
                        if taps.get(&id).is_some_and(|tap| tap.history != history) {
                            taps.remove(&id);
                        }
                        if let Some(tap) = taps.get_mut(&id) {
                            if !matches!(
                                exchange(&mut tap.client, Request::Types),
                                Ok(Reply::Types(_) | Reply::Rejected(_))
                            ) {
                                taps.remove(&id);
                            }
                        }
                        if taps.contains_key(&id) {
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
                match record(tap, &send) {
                    TapState::Live => {}
                    TapState::Dead => dead.push(id.clone()),
                    TapState::Stop => return,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixStream;

    fn tap(stream: UnixStream) -> Tap {
        let changed = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        assert!(changed >= 0);
        Tap {
            client: Client::new(stream).unwrap(),
            changed: unsafe { OwnedFd::from_raw_fd(changed) },
            history: "test".to_owned(),
            seen: None,
        }
    }

    fn request(stream: &mut UnixStream) -> Vec<u8> {
        let mut header = [0; 4];
        stream.read_exact(&mut header).unwrap();
        let mut body = vec![0; u32::from_le_bytes(header) as usize];
        stream.read_exact(&mut body).unwrap();
        body
    }

    fn reply(stream: &mut UnixStream, body: &[u8]) {
        stream
            .write_all(&(body.len() as u32).to_le_bytes())
            .unwrap();
        stream.write_all(body).unwrap();
    }

    fn types(stream: &mut UnixStream, revision: u64) {
        assert_eq!(request(stream), [1, 0]);
        let mut body = vec![0, 1];
        body.extend_from_slice(&revision.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&10u16.to_le_bytes());
        body.extend_from_slice(b"text/plain");
        reply(stream, &body);
    }

    #[test]
    fn read_disconnect_retries_the_current_revision_without_another_event() {
        let (send, receive) = mpsc::sync_channel(1);
        let (first, mut first_server) = UnixStream::pair().unwrap();
        let failed = std::thread::spawn(move || {
            types(&mut first_server, 7);
            let read = request(&mut first_server);
            assert_eq!(read[0], 3);
            assert_eq!(&read[2..10], &7u64.to_le_bytes());
        });
        assert_eq!(record(&mut tap(first), &send), TapState::Dead);
        failed.join().unwrap();
        assert!(receive.try_recv().is_err());

        let (second, mut second_server) = UnixStream::pair().unwrap();
        let retried = std::thread::spawn(move || {
            types(&mut second_server, 7);
            let read = request(&mut second_server);
            assert_eq!(read[0], 3);
            assert_eq!(&read[2..10], &7u64.to_le_bytes());
            let mut body = vec![0];
            body.extend_from_slice(&4u32.to_le_bytes());
            body.extend_from_slice(b"data");
            reply(&mut second_server, &body);
        });
        assert_eq!(record(&mut tap(second), &send), TapState::Live);
        retried.join().unwrap();
        let entry = receive.try_recv().unwrap();
        assert_eq!(entry.contents[0].1.as_slice(), b"data");
    }

    #[test]
    fn read_rejection_finishes_the_revision_without_reconnecting() {
        let (send, receive) = mpsc::sync_channel(1);
        let (stream, mut server) = UnixStream::pair().unwrap();
        let rejected = std::thread::spawn(move || {
            types(&mut server, 9);
            assert_eq!(request(&mut server)[0], 3);
            reply(&mut server, &[1, 2]);
        });
        let mut tap = tap(stream);
        assert_eq!(record(&mut tap, &send), TapState::Live);
        rejected.join().unwrap();
        assert_eq!(tap.seen, Some(9));
        assert_eq!(record(&mut tap, &send), TapState::Live);
        assert!(receive.try_recv().is_err());
    }
}
