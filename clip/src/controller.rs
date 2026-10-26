//! Host-only scope binding. After the acknowledgment the same FD speaks only
//! the immutable-scope broker protocol; an application cannot rebind it.
use crate::broker::Instance;
use crate::broker_transport::Transport;
use crate::clipboard_endpoint as endpoint;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

struct Scope {
    instance: Instance,
    owner: OwnedFd,
    history: String,
    revisions: [u64; 2],
    watchers: Vec<(RawFd, OwnedFd)>,
}
struct Pending {
    stream: UnixStream,
    header: [u8; 4],
    head: usize,
    body: Vec<u8>,
    read: usize,
    owner: Option<OwnedFd>,
    answer: Vec<u8>,
    written: usize,
    attach: Option<Instance>,
    notifier: Option<OwnedFd>,
    ready: bool,
    deadline: Instant,
}
pub struct Controller {
    listener: UnixListener,
    socket: PathBuf,
    _lock: File,
    scopes: BTreeMap<String, Scope>,
    transport: Transport,
    pending: Vec<Pending>,
}

impl Controller {
    pub fn open(runtime: &Path) -> io::Result<Self> {
        if !runtime.is_absolute() {
            return Err(endpoint::invalid());
        }
        let directory = runtime.join(endpoint::DIRECTORY);
        match fs::create_dir(&directory) {
            Ok(()) => fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        let meta = fs::symlink_metadata(&directory)?;
        if !meta.is_dir() || meta.uid() != unsafe { libc::getuid() } || meta.mode() & 0o077 != 0 {
            return Err(endpoint::invalid());
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join("lock"))?;
        let meta = lock.metadata()?;
        if !meta.is_file() || meta.uid() != unsafe { libc::getuid() } || meta.mode() & 0o077 != 0 {
            return Err(endpoint::invalid());
        }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let socket = endpoint::path(runtime);
        match fs::symlink_metadata(&socket) {
            Ok(meta) if meta.file_type().is_socket() && meta.uid() == unsafe { libc::getuid() } => {
                fs::remove_file(&socket)?
            }
            Ok(_) => return Err(endpoint::invalid()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            socket,
            _lock: lock,
            scopes: BTreeMap::new(),
            transport: Transport::default(),
            pending: Vec::new(),
        })
    }
    pub fn pollfds(&self) -> Vec<libc::pollfd> {
        let p = |fd, write| libc::pollfd {
            fd,
            events: if write { libc::POLLOUT } else { libc::POLLIN },
            revents: 0,
        };
        let mut fds = vec![p(self.listener.as_raw_fd(), false)];
        fds.extend(
            self.pending
                .iter()
                .map(|s| p(s.stream.as_raw_fd(), s.ready)),
        );
        fds.extend(
            self.transport
                .sockets()
                .map(|(fd, write)| p(fd.as_raw_fd(), write)),
        );
        fds.extend(self.scopes.values().map(|s| p(s.owner.as_raw_fd(), false)));
        fds
    }
    pub fn deadline(&self) -> Option<Instant> {
        self.pending
            .iter()
            .map(|p| p.deadline)
            .chain(self.transport.next_deadline())
            .min()
    }
    pub fn tick(&mut self, now: Instant) {
        for scope in self.scopes.values_mut() {
            scope
                .watchers
                .retain(|(fd, _)| self.transport.contains_peer(*fd));
        }
        self.scopes.retain(|_, scope| {
            if endpoint::alive(scope.owner.as_fd()) {
                true
            } else {
                let _ = self.transport.remove(scope.instance);
                false
            }
        });
        for _ in 0..16 {
            let Ok((stream, _)) = self.listener.accept() else {
                break;
            };
            if self.pending.len() >= 128 || !endpoint::host_peer(&stream) {
                continue;
            }
            if stream.set_nonblocking(true).is_err() {
                continue;
            }
            self.pending.push(Pending {
                stream,
                header: [0; 4],
                head: 0,
                body: Vec::new(),
                read: 0,
                owner: None,
                answer: Vec::new(),
                written: 0,
                attach: None,
                notifier: None,
                ready: false,
                deadline: now + Duration::from_secs(3),
            });
        }
        let mut pending = std::mem::take(&mut self.pending);
        for mut p in pending.drain(..) {
            if now >= p.deadline {
                continue;
            }
            match p.step(self) {
                Ok(false) => self.pending.push(p),
                Ok(true) => {
                    if let Some(scope) = p.attach {
                        let fd = p.stream.as_raw_fd();
                        if self.transport.attach(scope, p.stream).is_ok() {
                            if let Some(notifier) = p.notifier {
                                if let Some(scope) =
                                    self.scopes.values_mut().find(|s| s.instance == scope)
                                {
                                    scope.watchers.push((fd, notifier));
                                }
                            }
                        }
                    }
                }
                Err(_) => {}
            }
        }
        self.transport.tick(now);
        for scope in self.scopes.values_mut() {
            let Ok(revisions) = self.transport.revisions(scope.instance) else {
                continue;
            };
            if revisions != scope.revisions {
                scope.revisions = revisions;
                for (_, fd) in &scope.watchers {
                    let one = 1u64.to_ne_bytes();
                    unsafe {
                        libc::write(fd.as_raw_fd(), one.as_ptr().cast(), 8);
                    }
                }
            }
        }
    }
    fn bind(&mut self, id: &str, history: &str, owner: OwnedFd) -> io::Result<Instance> {
        if id.len() > 512 || !crate::recorder::valid_history(history) {
            return Err(endpoint::invalid());
        }
        let pid = endpoint::owner_pid(owner.as_fd()).ok_or_else(endpoint::invalid)?;
        if let Some(old) = self.scopes.get(id) {
            if endpoint::owner_pid(old.owner.as_fd()) != Some(pid) || old.history != history {
                return Err(endpoint::invalid());
            }
            return Ok(old.instance);
        }
        let instance = self
            .transport
            .register()
            .map_err(|_| io::Error::other("clipboard scope limit"))?;
        self.scopes.insert(
            id.to_owned(),
            Scope {
                instance,
                owner,
                history: history.to_owned(),
                revisions: [0; 2],
                watchers: Vec::new(),
            },
        );
        Ok(instance)
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket);
    }
}

impl Pending {
    fn step(&mut self, controller: &mut Controller) -> io::Result<bool> {
        if !self.ready {
            while self.head < 4 {
                let (n, fd) =
                    match endpoint::recv_header(&self.stream, &mut self.header[self.head..]) {
                        Ok(result) => result,
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
                    return Err(endpoint::invalid());
                }
                if let Some(fd) = fd {
                    if self.owner.replace(fd).is_some() {
                        return Err(endpoint::invalid());
                    }
                }
                self.head += n;
            }
            if self.body.is_empty() {
                let length = u32::from_le_bytes(self.header) as usize;
                if !(1..=endpoint::MAX_CONTROL).contains(&length) {
                    return Err(endpoint::invalid());
                }
                self.body.resize(length, 0);
            }
            while self.read < self.body.len() {
                match self.stream.read(&mut self.body[self.read..]) {
                    Ok(0) => return Err(endpoint::invalid()),
                    Ok(n) => self.read += n,
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) =>
                    {
                        return Ok(false)
                    }
                    Err(e) => return Err(e),
                }
            }
            let result = self.dispatch(controller);
            let body = result.unwrap_or_else(|_| {
                self.attach = None;
                vec![1]
            });
            if self.attach.is_some() {
                let fd = unsafe { libc::eventfd(1, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                self.notifier = Some(unsafe { OwnedFd::from_raw_fd(fd) });
            }
            self.answer
                .extend_from_slice(&(body.len() as u32).to_le_bytes());
            self.answer.extend(body);
            self.ready = true;
        }
        let sent = if self.written == 0 && self.notifier.is_some() {
            endpoint::send_header(
                &self.stream,
                self.answer[..4].try_into().unwrap(),
                self.notifier.as_ref().map(AsFd::as_fd),
            )
        } else {
            self.stream.write(&self.answer[self.written..])
        };
        match sent {
            Ok(0) => Err(endpoint::invalid()),
            Ok(n) => {
                self.written += n;
                Ok(self.written == self.answer.len())
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }
    fn dispatch(&mut self, controller: &mut Controller) -> io::Result<Vec<u8>> {
        let mut bytes = &self.body[1..];
        match self.body[0] {
            b'B' => {
                let id = endpoint::take_string(&mut bytes)?;
                let history = endpoint::take_string(&mut bytes)?;
                if !bytes.is_empty() {
                    return Err(endpoint::invalid());
                }
                let owner = self.owner.take().ok_or_else(endpoint::invalid)?;
                self.attach = Some(controller.bind(id, history, owner)?);
                Ok(vec![0])
            }
            b'L' => {
                let id = endpoint::take_string(&mut bytes)?;
                if !bytes.is_empty() || self.owner.is_some() {
                    return Err(endpoint::invalid());
                }
                self.attach = Some(
                    controller
                        .scopes
                        .get(id)
                        .ok_or_else(endpoint::invalid)?
                        .instance,
                );
                Ok(vec![0])
            }
            b'E' if bytes.is_empty() && self.owner.is_none() => {
                let mut answer = vec![0];
                answer.extend_from_slice(&(controller.scopes.len() as u16).to_le_bytes());
                for (id, s) in &controller.scopes {
                    endpoint::put_string(&mut answer, id);
                    endpoint::put_string(&mut answer, &s.history);
                }
                Ok(answer)
            }
            _ => Err(endpoint::invalid()),
        }
    }
}

pub fn run(runtime: &Path) -> io::Result<()> {
    let mut controller = Controller::open(runtime)?;
    STOP.store(false, Ordering::Relaxed);
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = stop as *const () as usize;
    unsafe { libc::sigemptyset(&mut action.sa_mask) };
    for signal in [libc::SIGTERM, libc::SIGINT] {
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    while !STOP.load(Ordering::Relaxed) {
        controller.tick(Instant::now());
        let mut fds = controller.pollfds();
        let wait = controller.deadline().map_or(-1, |at| {
            at.saturating_duration_since(Instant::now())
                .as_millis()
                .min(i32::MAX as u128) as i32
        });
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, wait) };
        if n < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
    }
    // Dropping Transport wipes retained payloads and closes every endpoint.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clipboard_client::{Client, Reply, Request, Selection};
    use std::os::fd::FromRawFd;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    struct Lease {
        child: std::process::Child,
        fd: OwnedFd,
    }
    impl Lease {
        fn new() -> Self {
            let child = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap();
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) } as i32;
            assert!(fd >= 0);
            Self {
                child,
                fd: unsafe { OwnedFd::from_raw_fd(fd) },
            }
        }
    }
    impl Drop for Lease {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
    struct Harness {
        runtime: PathBuf,
        stop: Arc<AtomicBool>,
        worker: Option<std::thread::JoinHandle<()>>,
    }
    impl Harness {
        fn new() -> Self {
            let runtime = std::env::temp_dir().join(format!(
                "cw-controller-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&runtime).unwrap();
            let mut controller = Controller::open(&runtime).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let running = stop.clone();
            let worker = std::thread::spawn(move || {
                while !running.load(Ordering::SeqCst) {
                    controller.tick(Instant::now());
                    std::thread::sleep(Duration::from_millis(1));
                }
            });
            Self {
                runtime,
                stop,
                worker: Some(worker),
            }
        }
    }
    impl Drop for Harness {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            self.worker.take().unwrap().join().unwrap();
            fs::remove_dir_all(&self.runtime).unwrap();
        }
    }
    fn exchange(client: &mut Client, request: Request<'_>) -> io::Result<Reply> {
        client.start(Selection::Clipboard, request, Instant::now())?;
        for _ in 0..2000 {
            if let Some(reply) = client.tick(Instant::now()) {
                return reply;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Err(io::Error::from(io::ErrorKind::TimedOut))
    }

    #[test]
    fn private_registration_namespace_probe() {
        let Some(runtime) = std::env::var_os("CELLWARD_TEST_FOREIGN_CLIPBOARD") else {
            return;
        };
        let mut stream = UnixStream::connect(endpoint::path(Path::new(&runtime))).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut request = 1u32.to_le_bytes().to_vec();
        request.push(b'E');
        // The controller may reject before the valid request is written.
        if stream.write_all(&request).is_err() {
            return;
        }
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                ) => {}
            other => {
                panic!("foreign namespace got an admin response or was left pending: {other:?}")
            }
        }
    }

    #[test]
    fn same_user_in_a_foreign_namespace_cannot_enumerate_or_register() {
        let h = Harness::new();
        let result = std::process::Command::new("unshare")
            .args(["--user", "--map-root-user", "--mount"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "controller::tests::private_registration_namespace_probe",
                "--nocapture",
            ])
            .env("CELLWARD_TEST_FOREIGN_CLIPBOARD", &h.runtime)
            .output();
        let result = match result {
            Ok(result) => result,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                eprintln!("namespace authentication probe skipped: unshare is unavailable");
                return;
            }
            Err(e) => panic!("unshare: {e}"),
        };
        let stderr = String::from_utf8_lossy(&result.stderr);
        if !result.status.success() && stderr.contains("unshare failed: Operation not permitted") {
            eprintln!("namespace authentication probe skipped: user namespaces are denied");
            return;
        }
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            stderr
        );
    }

    #[test]
    fn private_recording_never_needs_a_host_selection_and_skips_secrets_and_restores() {
        let h = Harness::new();
        let owner = Lease::new();
        let mut client = Client::new(
            endpoint::bind(&h.runtime, "work", "work", owner.fd.as_fd())
                .unwrap()
                .data,
        )
        .unwrap();
        let recorder = crate::private_history::start(&h.runtime);
        exchange(
            &mut client,
            Request::Set(&[("text/plain", b"private history only")]),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let entry = loop {
            if let Ok(entry) = recorder.try_recv() {
                break entry;
            }
            assert!(
                Instant::now() < deadline,
                "private recorder did not receive selection"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(entry.history, "work");
        assert_eq!(entry.contents[0].1.as_slice(), b"private history only");
        exchange(
            &mut client,
            Request::Set(&[
                ("text/plain", b"secret"),
                (crate::recorder::SECRET_HINT, b"secret"),
            ]),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(200));
        assert!(recorder.try_recv().is_err());
        exchange(
            &mut client,
            Request::Set(&[
                ("text/plain", b"restored"),
                (crate::private_history::RESTORED, b""),
            ]),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(200));
        assert!(recorder.try_recv().is_err());
    }

    #[test]
    fn lifetime_bound_scopes_share_only_with_their_own_launches() {
        let h = Harness::new();
        let mut owner = Lease::new();
        let other = Lease::new();
        let a = endpoint::bind(&h.runtime, "work", "work", owner.fd.as_fd()).unwrap();
        let changes = a.changed;
        let mut signal = [0u8; 8];
        assert_eq!(
            unsafe { libc::read(changes.as_raw_fd(), signal.as_mut_ptr().cast(), 8) },
            8
        );
        let mut a = Client::new(a.data).unwrap();
        let mut b = Client::new(endpoint::lookup(&h.runtime, "work").unwrap().data).unwrap();
        let mut foreign = Client::new(
            endpoint::bind(&h.runtime, "other", "-", other.fd.as_fd())
                .unwrap()
                .data,
        )
        .unwrap();
        let Reply::Set(revision) = exchange(
            &mut a,
            Request::Set(&[("text/plain", b"private synthetic text")]),
        )
        .unwrap() else {
            panic!()
        };
        let mut notified = false;
        for _ in 0..1000 {
            if unsafe { libc::read(changes.as_raw_fd(), signal.as_mut_ptr().cast(), 8) } == 8 {
                notified = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            notified,
            "selection changes wake their own proxies without polling"
        );
        let Reply::Data(data) = exchange(
            &mut b,
            Request::Read {
                revision,
                mime: "text/plain",
            },
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(data.as_slice(), b"private synthetic text");
        assert!(matches!(
            exchange(
                &mut foreign,
                Request::Read {
                    revision,
                    mime: "text/plain"
                }
            )
            .unwrap(),
            Reply::Rejected(2)
        ));
        assert!(
            endpoint::bind(&h.runtime, "work", "work", other.fd.as_fd()).is_err(),
            "live scope cannot be rebound to another owner"
        );
        assert!(endpoint::bind(&h.runtime, "work", "wrong-history", owner.fd.as_fd()).is_err());
        assert_eq!(
            endpoint::list(&h.runtime).unwrap(),
            [("other".into(), "-".into()), ("work".into(), "work".into())]
        );
        owner.child.kill().unwrap();
        owner.child.wait().unwrap();
        for _ in 0..1000 {
            if endpoint::list(&h.runtime).unwrap().len() == 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(endpoint::lookup(&h.runtime, "work").is_err());
        assert!(exchange(&mut a, Request::Types).is_err());
        let mut fresh = Client::new(
            endpoint::bind(&h.runtime, "work", "work", other.fd.as_fd())
                .unwrap()
                .data,
        )
        .unwrap();
        assert!(matches!(
            exchange(&mut fresh, Request::Types).unwrap(),
            Reply::Types(None)
        ));
        assert!(matches!(
            exchange(
                &mut fresh,
                Request::Read {
                    revision,
                    mime: "text/plain"
                }
            )
            .unwrap(),
            Reply::Rejected(2)
        ));
    }

    #[test]
    fn a_bound_stream_cannot_enumerate_or_rebind_and_non_pidfds_are_rejected() {
        let h = Harness::new();
        let owner = Lease::new();
        let file = File::open("/dev/null").unwrap();
        assert!(endpoint::bind(&h.runtime, "bad", "work", file.as_fd()).is_err());
        let mut stream = endpoint::bind(&h.runtime, "work", "work", owner.fd.as_fd())
            .unwrap()
            .data;
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(&[2, 0, 0, 0, b'E', 0]).unwrap();
        let mut header = [0; 4];
        stream.read_exact(&mut header).unwrap();
        assert_eq!(u32::from_le_bytes(header), 2);
        let mut body = [0; 2];
        stream.read_exact(&mut body).unwrap();
        assert_eq!(
            body,
            [1, 3],
            "application FD only speaks the scoped data protocol"
        );
        assert!(endpoint::lookup(&h.runtime, "not-running").is_err());
    }
}
