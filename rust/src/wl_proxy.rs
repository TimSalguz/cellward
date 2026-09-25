//! The Wayland proxy of `wl-sandbox`: a process of its own between a program
//! and the compositor (`docs/WINDOW-FRAME.md` §8, stage 1).
//!
//! **Why.** A frame the program cannot remove has to be drawn by someone who
//! sits on its connection, and a party that adds objects to a connection must
//! translate every object id in both directions — the compositor's table is
//! dense (§2). That needs the signature of every message of every protocol
//! passed on; `wl-proxy` has them and keeps the two id spaces apart (§3.2).
//! This stage is the TRANSPARENT proxy: the same connection the program had,
//! minus what is hidden below, nothing added. The frame comes on top of it.
//!
//! ```text
//!  wl-sandbox (supervisor, host)                                     zone
//!   │ listener of the security context: $XDG_RUNTIME_DIR/vpn-zones/wl-up/<pid>
//!   │   (0700, never bound into a zone; the compositor listens there)
//!   │ connects to it on request ──fd──┐
//!   └ fork ─► proxy (this, seccomp)   ▼
//!               accept() on vpn-zones/wayland/<zone>/wl-sandbox-<pid> ◄── program
//!               one wl-proxy State per accepted connection, upstream = the fd
//! ```
//!
//! **What the program sees.** Only the globals of the protocols compiled into
//! `wl-proxy` (`rust/Cargo.toml` names them — the list IS the policy), at most
//! at the versions of its pinned baseline. The rest is hidden: what the crate
//! does not know is dropped by the crate itself, and a bind to a name this
//! connection was never shown is refused here, so a hidden global cannot be
//! bound by guessing its number (the compositor would have taken it: a name is
//! just a number). [`HIDDEN`] lists what that means, and a test holds the build
//! to it. No global is ever added.
//!
//! **The proxy is hostile input's first reader**, so it is kept small in what
//! it can do (§10):
//!
//! * a process of its own, not dumpable — nobody of the same uid reads its
//!   memory or borrows its descriptors through `/proc`;
//! * an allow-list seccomp filter ([`filter`]): no `open`, no `socket`, no
//!   `connect`, no `exec`, no `fork`, no executable memory. It cannot reach the
//!   compositor's own socket or anything else by name: a connection upstream is
//!   made by the SUPERVISOR, which connects to the security context's listener
//!   and nothing else, and hands the descriptor over. A proxy taken over by its
//!   client gets what the client already had — restricted connections;
//! * limits, so that a client cannot make it hold unbounded memory or
//!   descriptors: connections, connections waiting for their upstream, objects
//!   per connection, globals per registry, the bytes waiting for a client that
//!   does not read (its requests are not read meanwhile — back-pressure, as on
//!   a direct connection), and `RLIMIT_NOFILE`/`RLIMIT_DATA` for the process.
//!   `wl-proxy` bounds a message (4096 bytes) and the descriptors of one read
//!   (28, the rest the kernel closes); descriptors a client sends ahead and
//!   never uses stay queued until the process limit — which starves this
//!   launch's own connections only (§3.2);
//!
//! **Fail-closed.** The proxy dying takes the program's display with it; the
//! program is never handed the compositor's socket instead. When it cannot
//! START, `wl-sandbox` falls back to exactly what it did before the proxy: the
//! compositor listens on the zone's path itself (§8, the fallback ladder).
//!
//! **Lifetime.** Until the main program exits, the proxy accepts. Then the
//! supervisor closes the channel between them, and the proxy stops accepting —
//! a new connection after the program is gone is refused, as it was when the
//! compositor stopped listening — but serves the connections it has: a
//! terminal's child keeps its window. It exits with the last of them, and the
//! supervisor, which adopted the program's orphans (`PR_SET_CHILD_SUBREAPER`)
//! so that a window of one of them still leads to its launch
//! (`crate::focus`), exits after it.
//!
//! **Whose pid a window has.** The compositor takes a client's pid from the
//! connection (`SO_PEERCRED`: whoever called `connect`), and upstream it is the
//! supervisor that connects. Every window of the launch therefore has the
//! supervisor's pid — the very pid of the launch's registry record — whichever
//! process of the program opened it; the supervisor goes by
//! [`SUPERVISOR_NAME`] meanwhile, so that `crate::focus` knows to ask its
//! children for the network.

use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use libseccomp::{ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};
use wl_proxy::baseline::Baseline;
use wl_proxy::client::{Client, ClientHandler};
use wl_proxy::object::{Object, ObjectCoreApi};
use wl_proxy::protocols::wayland::wl_display::{WlDisplay, WlDisplayHandler};
use wl_proxy::protocols::wayland::wl_registry::{WlRegistry, WlRegistryHandler};
use wl_proxy::protocols::ObjectInterface;
use wl_proxy::state::{State, StateHandler};

use crate::sys;

/// The proxy's process name (`/proc/<pid>/comm`, 15 bytes at most).
pub const PROCESS_NAME: &str = "vz-wl-proxy";

/// The supervisor's process name while it runs a proxy. A window of a proxied
/// program has the SUPERVISOR's pid (it made the connection upstream), and
/// [`crate::focus`] knows it by this name: the network is not the
/// supervisor's own (the host's) but its children's.
pub const SUPERVISOR_NAME: &str = "vz-wl-sandbox";

/// Below the runtime directory: the listeners of the security contexts, one
/// per launch. `crate::zone` keeps nothing of `vpn-zones/` in a zone but the
/// zone's own `wayland/<zone>`, so this directory is never seen from one.
pub const UPSTREAM_DIR: &str = "vpn-zones/wl-up";

/// The baseline: the highest version of each interface the program is shown.
/// Pinned, like the crate: a newer one is a reviewed change.
const BASELINE: Baseline = Baseline::V5;

/// Globals a program behind the proxy never sees, though a compositor may
/// offer them to a restricted client: their protocols are left out of the
/// build (`rust/Cargo.toml`). `wp_drm_lease_device_v1` hands out a DRM
/// descriptor (§4.3, the decision of §11); the rest is what security-context
/// exists to hide — kept out here too, so that a compositor that forgets one
/// does not decide for us — and names the crate does not know at all
/// (NVIDIA's EGLStream, mutter's interop). Not exhaustive for the unknown:
/// anything not compiled in is hidden.
pub const HIDDEN: &[&str] = &[
    "wp_drm_lease_device_v1",
    "ext_data_control_manager_v1",
    "zwlr_data_control_manager_v1",
    "ext_foreign_toplevel_list_v1",
    "zwlr_foreign_toplevel_manager_v1",
    "ext_image_copy_capture_manager_v1",
    "ext_output_image_capture_source_manager_v1",
    "ext_foreign_toplevel_image_capture_source_manager_v1",
    "zwlr_screencopy_manager_v1",
    "zwlr_export_dmabuf_manager_v1",
    "ext_session_lock_manager_v1",
    "ext_idle_notifier_v1",
    "ext_transient_seat_manager_v1",
    "ext_workspace_manager_v1",
    "zwp_input_method_manager_v2",
    "zwp_input_method_v1",
    "zwp_input_panel_v1",
    "zwp_virtual_keyboard_manager_v1",
    "zwlr_virtual_pointer_manager_v1",
    "xwayland_shell_v1",
    "zwp_xwayland_keyboard_grab_manager_v1",
    "wp_security_context_manager_v1",
    "zwp_fullscreen_shell_v1",
    "zwlr_layer_shell_v1",
    "zwlr_output_manager_v1",
    "zwlr_output_power_manager_v1",
    "zwlr_gamma_control_manager_v1",
    "zwlr_input_inhibit_manager_v1",
    // Unknown to wl-proxy 0.1.4 altogether. xdg-foreign v1 is GTK3's: a
    // portal dialog of a GTK3 program comes up unparented (v2 passes).
    "zxdg_exporter_v1",
    "zxdg_importer_v1",
    "gtk_shell1",
    "wl_eglstream_display",
    "mutter_x11_interop",
];

// --- LIMITS -----------------------------------------------------------------

/// Connections of one launch at once. A browser opens a handful; a hundred is
/// a program trying something.
const MAX_CONNECTIONS: usize = 64;
/// Accepted connections still waiting for the supervisor to connect upstream.
const MAX_WAITING: usize = 16;
/// Objects of one connection. libwayland has no such limit, but a big program
/// holds a few thousand; the proxy's share of each is a few hundred bytes.
const MAX_OBJECTS: usize = 100_000;
/// How often (in dispatches of a connection) its objects are counted: the
/// count walks all of them, and one read of 8 KiB creates at most ~700.
const COUNT_OBJECTS_EVERY: u32 = 64;
/// Globals remembered per registry. The compositor's to fill, not the
/// program's, but an output plugged in and out forever must not grow it.
const MAX_GLOBALS: usize = 4096;
/// Bytes a client has not read yet (`TIOCOUTQ`) at which its requests stop
/// being read, and at which they are read again. The kernel's own buffer is
/// ~200 KiB; above the high mark the client is not keeping up.
const OUTQ_HIGH: libc::c_int = 128 * 1024;
const OUTQ_LOW: libc::c_int = 32 * 1024;
/// How often a stopped client is looked at again.
const RECHECK_MS: libc::c_int = 50;
/// The process limits.
const MAX_FDS: libc::rlim_t = 1024;
const MAX_DATA: libc::rlim_t = 512 << 20;
/// How long the supervisor waits for the proxy to say it is ready.
const READY_TIMEOUT: Duration = Duration::from_secs(5);
/// The longest compositor error text passed on to the program.
const MAX_ERROR_TEXT: usize = 1024;

// --- THE CHANNEL -------------------------------------------------------------
// One byte per message on a stream socketpair; the upstream descriptor rides
// on its byte. The supervisor closing its end is "the program has exited".

/// Proxy → supervisor: hardened, filter loaded, serving.
const READY: u8 = b'r';
/// Proxy → supervisor: one more connection upstream, please.
const CONNECT: u8 = b'c';
/// Supervisor → proxy: here it is (with the descriptor).
const UPSTREAM: u8 = b'u';
/// Supervisor → proxy: the security context no longer accepts.
const REFUSED: u8 = b'n';

/// `wl_display` error codes.
const INVALID_OBJECT: u32 = 0;
const NO_MEMORY: u32 = 2;

// --- THE SUPERVISOR'S SIDE ----------------------------------------------------

/// The security context's listener, before the proxy is started: made first,
/// because the compositor has to be listening on it when the program starts.
pub struct Upstream {
    pub listener: UnixListener,
    pub path: PathBuf,
}

impl Upstream {
    /// `$XDG_RUNTIME_DIR/vpn-zones/wl-up/<pid>`, in a directory only the user
    /// enters. A leftover of an earlier run with this pid is replaced.
    pub fn bind(runtime_dir: &Path, pid: u32) -> io::Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let dir = runtime_dir.join(UPSTREAM_DIR);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;
        // An existing directory keeps whatever mode it was made with.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        let path = dir.join(pid.to_string());
        let _ = fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        Ok(Self { listener, path })
    }
}

/// A running proxy, as its supervisor holds it.
pub struct Proxy {
    pid: libc::pid_t,
    pidfd: Option<OwnedFd>,
    channel: Option<UnixStream>,
    upstream: PathBuf,
    adopting: bool,
}

/// Start the proxy on `zone_listener`, the socket the program will be told
/// about. Returns once the proxy has confined itself; on any failure nothing
/// is left running and the caller falls back.
///
/// Called with the compositor's (unrestricted) connection already closed: the
/// child inherits nothing of it. It closes every descriptor it did not ask for
/// all the same, first thing.
pub fn start(zone_listener: &UnixListener, upstream: &Path) -> Result<Proxy, String> {
    let (ours, theirs) = UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;
    let listener = zone_listener.try_clone().map_err(|e| format!("dup: {e}"))?;
    // SAFETY: single-threaded here (wl-sandbox has no threads), so the child
    // may allocate before it confines itself.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork: {}", io::Error::last_os_error()));
    }
    if pid == 0 {
        drop(ours);
        // A panic ends the proxy here: unwinding further would run the
        // supervisor's code (`wl_sandbox::run`) in this child.
        let code =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| child(listener, theirs)))
                .unwrap_or(101);
        // _exit: the parent's atexit handlers and buffers are not ours.
        // SAFETY: always sound.
        unsafe { libc::_exit(code) };
    }
    drop(listener);
    drop(theirs);
    let proxy = Proxy {
        pid,
        pidfd: sys::pidfd_open(pid),
        channel: Some(ours),
        upstream: upstream.to_path_buf(),
        adopting: false,
    };
    match proxy.await_ready() {
        Ok(()) => Ok(proxy),
        Err(e) => {
            proxy.kill();
            Err(e)
        }
    }
}

impl Proxy {
    fn await_ready(&self) -> Result<(), String> {
        let channel = self.channel.as_ref().ok_or("no channel")?;
        let mut pfd = [pollfd(channel.as_raw_fd())];
        let ms = READY_TIMEOUT.as_millis() as libc::c_int;
        match poll(&mut pfd, ms) {
            Ok(0) => return Err("it did not report ready".to_owned()),
            Ok(_) => {}
            Err(e) => return Err(format!("poll: {e}")),
        }
        let mut byte = [0u8; 1];
        match sys::recv_into_with_fds(channel.as_raw_fd(), &mut byte, 0) {
            Ok((1, _, _)) if byte[0] == READY => Ok(()),
            Ok(_) => Err("it exited before it was ready".to_owned()),
            Err(e) => Err(format!("recv: {e}")),
        }
    }

    /// Become the supervisor, just before the program is started: the name
    /// `crate::focus` knows the windows by ([`SUPERVISOR_NAME`]), and the
    /// program's orphans come here — a window of a process whose parent has
    /// gone still leads to its launch, and to its network. Only once the proxy
    /// is certainly running: the subreaper flag survives `execve`, and a
    /// fallback that runs the program in this very process must not keep it
    /// ([`Proxy::kill`] takes it back; the name goes with the `execve`).
    pub fn take_over(&mut self) {
        if let Ok(name) = std::ffi::CString::new(SUPERVISOR_NAME) {
            // SAFETY: PR_SET_NAME reads a NUL-terminated string that outlives
            // the call.
            unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr(), 0, 0, 0) };
        }
        // SAFETY: prctl with these arguments takes no pointers.
        self.adopting = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } == 0;
    }

    /// Stop it at once, on a path that will not start the program behind it.
    pub fn kill(mut self) {
        if self.adopting {
            // SAFETY: as in `take_over`.
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0) };
        }
        self.channel = None;
        match &self.pidfd {
            Some(fd) => {
                sys::pidfd_signal(fd, libc::SIGKILL);
            }
            // SAFETY: our own child, not reaped yet, so the pid is still ours.
            None => unsafe {
                libc::kill(self.pid, libc::SIGKILL);
            },
        }
        let mut status = 0;
        wait(self.pid, &mut status, 0);
    }

    /// Answer the proxy's requests until the program `main` exits, call
    /// `on_main_exit`, stop the proxy accepting and wait for it to finish
    /// with the connections it has. Returns `main`'s wait status.
    pub fn supervise(mut self, main: libc::pid_t, on_main_exit: impl FnOnce()) -> libc::c_int {
        let main_fd = sys::pidfd_open(main);
        let mut main_status = None;
        let mut proxy_alive = true;
        loop {
            self.reap(main, &mut main_status, &mut proxy_alive);
            if main_status.is_some() {
                break;
            }
            let mut fds = Vec::with_capacity(3);
            if let Some(fd) = &main_fd {
                fds.push(pollfd(fd.as_raw_fd()));
            }
            let channel_at = self.channel.as_ref().map(|c| {
                fds.push(pollfd(c.as_raw_fd()));
                fds.len() - 1
            });
            if proxy_alive {
                if let Some(fd) = &self.pidfd {
                    fds.push(pollfd(fd.as_raw_fd()));
                }
            }
            // Orphans are reaped on every wake-up; without a pidfd for the
            // program its exit is only noticed on this timeout.
            let timeout = if main_fd.is_some() { 2000 } else { 200 };
            if let Err(e) = poll(&mut fds, timeout) {
                if e.kind() != io::ErrorKind::Interrupted {
                    eprintln!("wl-sandbox: poll: {e}");
                    std::thread::sleep(Duration::from_millis(100));
                }
                continue;
            }
            if let Some(at) = channel_at {
                if fds[at].revents != 0 && !self.answer() {
                    self.channel = None;
                }
            }
        }
        on_main_exit();
        // The proxy stops accepting when this closes, and exits with its
        // last connection.
        self.channel = None;
        while proxy_alive {
            let mut status = 0;
            match wait(-1, &mut status, 0) {
                Some(pid) if pid == self.pid => proxy_alive = false,
                Some(_) => {}
                None => break,
            }
        }
        main_status.unwrap_or(0)
    }

    /// Reap whatever has exited: the program, the proxy, adopted orphans.
    fn reap(
        &self,
        main: libc::pid_t,
        main_status: &mut Option<libc::c_int>,
        proxy_alive: &mut bool,
    ) {
        loop {
            let mut status = 0;
            match wait(-1, &mut status, libc::WNOHANG) {
                Some(0) | None => return,
                Some(pid) if pid == main => *main_status = Some(status),
                Some(pid) if pid == self.pid => {
                    *proxy_alive = false;
                    // Fail-closed: the program's connections died with the
                    // proxy, and it is not given another way to the compositor.
                    eprintln!(
                        "wl-sandbox: the Wayland proxy exited ({}) — the program has no display now",
                        describe(status)
                    );
                }
                Some(_) => {}
            }
        }
    }

    /// One request of the proxy. False when the channel is gone.
    fn answer(&self) -> bool {
        let Some(channel) = &self.channel else {
            return false;
        };
        let mut byte = [0u8; 1];
        // No descriptors are expected from the proxy; any it sends are closed
        // by the kernel (`MSG_CTRUNC`).
        match sys::recv_into_with_fds(channel.as_raw_fd(), &mut byte, 0) {
            Ok((1, _, _)) if byte[0] == CONNECT => {}
            Ok((1, _, _)) => return true,
            Ok(_) => return false,
            Err(e) => return e.kind() == io::ErrorKind::Interrupted,
        }
        // The one place a connection upstream is made: to the security
        // context's listener, never to anything the proxy names.
        let sent = match UnixStream::connect(&self.upstream) {
            Ok(up) => sys::send_with_fds(channel.as_raw_fd(), &[UPSTREAM], &[up.as_raw_fd()]),
            Err(_) => sys::send_with_fds(channel.as_raw_fd(), &[REFUSED], &[]),
        };
        sent.is_ok()
    }
}

/// `waitpid`, retried on EINTR. `None` when there is nothing (left) to wait for.
fn wait(pid: libc::pid_t, status: &mut libc::c_int, flags: libc::c_int) -> Option<libc::pid_t> {
    loop {
        // SAFETY: `status` is a valid pointer for the duration of the call.
        let r = unsafe { libc::waitpid(pid, status, flags) };
        if r >= 0 {
            return Some(r);
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return None;
        }
    }
}

fn describe(status: libc::c_int) -> String {
    if libc::WIFSIGNALED(status) {
        format!("signal {}", libc::WTERMSIG(status))
    } else {
        format!("code {}", libc::WEXITSTATUS(status))
    }
}

// --- THE PROXY'S SIDE -------------------------------------------------------

/// The forked proxy: confine, report ready, serve.
fn child(listener: UnixListener, channel: UnixStream) -> libc::c_int {
    if let Err(e) = confine(&listener, &channel) {
        eprintln!("wl-sandbox: the Wayland proxy cannot confine itself: {e}");
        return 1;
    }
    if sys::send_with_fds(channel.as_raw_fd(), &[READY], &[]).is_err() {
        return 1;
    }
    serve(listener, channel)
}

/// Everything that makes the process what [`filter`] assumes, in an order
/// that leaves it no moment to be anything else: a name, not dumpable, no
/// descriptor but its own and the standard three, the limits, the filter.
fn confine(listener: &UnixListener, channel: &UnixStream) -> Result<(), String> {
    let name = std::ffi::CString::new(PROCESS_NAME).map_err(|e| e.to_string())?;
    // SAFETY: PR_SET_NAME reads a NUL-terminated string that outlives the call.
    unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr(), 0, 0, 0) };
    // SAFETY: prctl with these arguments takes no pointers.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(format!("PR_SET_DUMPABLE: {}", io::Error::last_os_error()));
    }
    close_all_but(&mut [0, 1, 2, listener.as_raw_fd(), channel.as_raw_fd()])?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("O_NONBLOCK: {e}"))?;
    limit(libc::RLIMIT_NOFILE, MAX_FDS)?;
    limit(libc::RLIMIT_DATA, MAX_DATA)?;
    filter(ScmpAction::KillProcess)
        .and_then(|f| f.load())
        .map_err(|e| format!("seccomp: {e}"))
}

/// Close every descriptor but `keep`. `close_range(2)`: one call per gap,
/// and nothing to enumerate — the proxy must not start with a descriptor it
/// does not know about (an inherited `WAYLAND_SOCKET` is the compositor's
/// unrestricted connection). Sorts `keep` in place and allocates nothing:
/// it runs in a fresh child.
fn close_all_but(keep: &mut [RawFd]) -> Result<(), String> {
    keep.sort_unstable();
    let mut from: libc::c_uint = 0;
    for &fd in keep.iter() {
        let Ok(fd) = libc::c_uint::try_from(fd) else {
            continue;
        };
        if fd > from {
            // SAFETY: close_range takes two numbers and flags; it closes
            // descriptors nobody in this (single-threaded) child still uses.
            if unsafe { libc::close_range(from, fd - 1, 0) } != 0 {
                return Err(format!("close_range: {}", io::Error::last_os_error()));
            }
        }
        from = from.max(fd.saturating_add(1));
    }
    // SAFETY: as above, to the end of the table.
    if unsafe { libc::close_range(from, libc::c_uint::MAX, 0) } != 0 {
        return Err(format!("close_range: {}", io::Error::last_os_error()));
    }
    Ok(())
}

/// Lower a resource limit (soft and hard) to `max`, never raise it.
fn limit(resource: libc::__rlimit_resource_t, max: libc::rlim_t) -> Result<(), String> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid pointer for the duration of each call.
    unsafe {
        if libc::getrlimit(resource, &mut lim) != 0 {
            return Err(format!("getrlimit: {}", io::Error::last_os_error()));
        }
        lim.rlim_max = lim.rlim_max.min(max);
        lim.rlim_cur = lim.rlim_max;
        if libc::setrlimit(resource, &lim) != 0 {
            return Err(format!("setrlimit: {}", io::Error::last_os_error()));
        }
    }
    Ok(())
}

/// The proxy's seccomp filter: an ALLOW-list, `default` for everything else
/// (the proxy is started with `KillProcess`: a call outside this list means
/// it is broken or taken over, and neither should go on forwarding).
///
/// What it needs and nothing more: its descriptors (read, write, close,
/// recvmsg, sendmsg, accept4 on the listener it has), waiting (poll, epoll —
/// each wl-proxy State polls its own epoll), the eventfd and pipe a State
/// makes, memory (anonymous and never executable), futex, the clock and
/// random numbers the runtime reads, and leaving. `ioctl` only for
/// `TIOCOUTQ`. Not there: open*, socket, connect, bind, exec*, clone/fork,
/// ptrace, kill, prctl, setrlimit, mount, anything with a path.
pub fn filter(default: ScmpAction) -> Result<ScmpFilterContext, libseccomp::error::SeccompError> {
    let mut ctx = ScmpFilterContext::new(default)?;
    ctx.set_ctl_nnp(true)?;
    // A foreign architecture's table (int 0x80 on x86_64) is not in the
    // filter at all: whatever comes through it gets the same answer.
    ctx.set_act_badarch(default)?;
    let allow = [
        "read",
        "write",
        "close",
        "recvmsg",
        "sendmsg",
        "accept4",
        "poll",
        "ppoll",
        "epoll_create1",
        "epoll_ctl",
        "epoll_wait",
        "epoll_pwait",
        "epoll_pwait2",
        "eventfd2",
        "pipe2",
        "munmap",
        "mremap",
        "brk",
        "madvise",
        "futex",
        "getrandom",
        "clock_gettime",
        "gettimeofday",
        "sched_yield",
        "getpid",
        "gettid",
        "rt_sigreturn",
        "rt_sigprocmask",
        "sigaltstack",
        "restart_syscall",
        "exit",
        "exit_group",
    ];
    for name in allow {
        // A name this architecture does not have (`poll`, `epoll_wait` on
        // arm64) is simply not there to allow.
        if let Ok(call) = ScmpSyscall::from_name(name) {
            ctx.add_rule(ScmpAction::Allow, call)?;
        }
    }
    let exec = libc::PROT_EXEC as u64;
    let no_exec = ScmpArgCompare::new(2, ScmpCompareOp::MaskedEqual(exec), 0);
    // Anonymous memory only: the descriptor argument is -1. Masked to 32
    // bits: an `int` -1 may reach the register sign-extended or not.
    let anonymous = ScmpArgCompare::new(4, ScmpCompareOp::MaskedEqual(0xffff_ffff), 0xffff_ffff);
    ctx.add_rule_conditional(
        ScmpAction::Allow,
        ScmpSyscall::from_name("mmap")?,
        &[no_exec, anonymous],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Allow,
        ScmpSyscall::from_name("mprotect")?,
        &[no_exec],
    )?;
    // `F_GETFD` only: std asks it of every descriptor it closes when built
    // with debug assertions (an `OwnedFd` that is not open is a bug).
    ctx.add_rule_conditional(
        ScmpAction::Allow,
        ScmpSyscall::from_name("fcntl")?,
        &[ScmpArgCompare::new(
            1,
            ScmpCompareOp::MaskedEqual(0xffff_ffff),
            libc::F_GETFD as u64,
        )],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Allow,
        ScmpSyscall::from_name("ioctl")?,
        &[ScmpArgCompare::new(
            1,
            ScmpCompareOp::MaskedEqual(0xffff_ffff),
            libc::TIOCOUTQ,
        )],
    )?;
    Ok(ctx)
}

/// Serve until the supervisor has said the program is gone and the last
/// connection has closed. Runs confined; see [`filter`] for what it may call.
fn serve(listener: UnixListener, channel: UnixStream) -> libc::c_int {
    let mut listener = Some(listener);
    let mut channel = Some(channel);
    // Accepted, their upstream asked for, in the order asked.
    let mut waiting: VecDeque<OwnedFd> = VecDeque::new();
    let mut conns: Vec<Conn> = Vec::new();
    loop {
        if channel.is_none() && conns.is_empty() {
            return 0;
        }
        conns.retain_mut(Conn::flush);
        let mut fds = Vec::with_capacity(2 + conns.len());
        if let Some(l) = &listener {
            fds.push(pollfd(l.as_raw_fd()));
        }
        if let Some(c) = &channel {
            fds.push(pollfd(c.as_raw_fd()));
        }
        let first_conn = fds.len();
        fds.extend(conns.iter().map(|c| pollfd(c.state.poll_fd().as_raw_fd())));
        let timeout = if conns.iter().any(|c| c.stopped) {
            RECHECK_MS
        } else {
            -1
        };
        match poll(&mut fds, timeout) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                eprintln!("wl-sandbox: the Wayland proxy cannot wait: {e}");
                return 1;
            }
        }
        let mut at = 0;
        if let Some(l) = &listener {
            if fds[at].revents != 0 {
                let busy = conns.len();
                if !accept(l, channel.as_ref(), &mut waiting, busy) {
                    // Out of descriptors: this launch holds too many. It keeps
                    // what it has; new connections are refused from here on.
                    eprintln!(
                        "wl-sandbox: the Wayland proxy is out of descriptors — no new connections"
                    );
                    listener = None;
                }
            }
            at += 1;
        }
        if let Some(c) = &channel {
            if fds[at].revents != 0 {
                match answer(c) {
                    Answer::Upstream(up) => {
                        if let Some(client) = waiting.pop_front() {
                            match Conn::open(client, up) {
                                Ok(conn) => conns.push(conn),
                                Err(e) => eprintln!("wl-sandbox: the Wayland proxy: {e}"),
                            }
                        }
                    }
                    Answer::Refused => {
                        waiting.pop_front();
                    }
                    Answer::Nothing => {}
                    Answer::Closed => {
                        // The program has exited (or the supervisor is gone):
                        // no new connections, those waiting are dropped.
                        channel = None;
                        listener = None;
                        waiting.clear();
                    }
                }
            }
        }
        // Those opened just now were not polled: their turn is the next round.
        let polled = &fds[first_conn..];
        for (conn, pfd) in conns.iter_mut().zip(polled) {
            if pfd.revents != 0 || conn.stopped {
                conn.dispatch();
            }
        }
        conns.retain(Conn::alive);
    }
}

/// Take what is waiting on the listener. False when out of descriptors.
fn accept(
    listener: &UnixListener,
    channel: Option<&UnixStream>,
    waiting: &mut VecDeque<OwnedFd>,
    busy: usize,
) -> bool {
    for _ in 0..MAX_WAITING {
        let sock = match accept_nonblocking(listener.as_raw_fd()) {
            Ok(sock) => sock,
            Err(e) => return !matches!(e.raw_os_error(), Some(libc::EMFILE | libc::ENFILE)),
        };
        // Over the limits, or nobody to ask for an upstream: closed at once,
        // so that the client fails now instead of hanging.
        let Some(channel) = channel else {
            continue;
        };
        if busy + waiting.len() >= MAX_CONNECTIONS || waiting.len() >= MAX_WAITING {
            continue;
        }
        if sys::send_with_fds(channel.as_raw_fd(), &[CONNECT], &[]).is_ok() {
            waiting.push_back(sock);
        }
    }
    true
}

enum Answer {
    Upstream(OwnedFd),
    Refused,
    Nothing,
    Closed,
}

fn answer(channel: &UnixStream) -> Answer {
    let mut byte = [0u8; 1];
    match sys::recv_into_with_fds(channel.as_raw_fd(), &mut byte, 1) {
        // Without its descriptor (out of descriptors here: the kernel closed
        // it) the answer is as good as a refusal — for this one client.
        Ok((1, mut fds, _)) if byte[0] == UPSTREAM => match fds.pop() {
            Some(up) => Answer::Upstream(up),
            None => Answer::Refused,
        },
        Ok((1, _, _)) if byte[0] == REFUSED => Answer::Refused,
        Ok((0, _, _)) => Answer::Closed,
        Err(e) if e.kind() == io::ErrorKind::Interrupted => Answer::Nothing,
        // The supervisor never sends anything else: a broken channel.
        _ => Answer::Closed,
    }
}

/// One program connection and its own connection upstream.
struct Conn {
    state: Rc<State>,
    client: Rc<Client>,
    socket: Rc<OwnedFd>,
    /// Set by the handlers: the client is gone or refused.
    closing: Rc<Cell<bool>>,
    /// Its requests are not being read: it is not reading its events.
    stopped: bool,
    dispatches: u32,
    scratch: Vec<Rc<dyn Object>>,
}

impl Conn {
    fn open(client: OwnedFd, upstream: OwnedFd) -> Result<Self, String> {
        let upstream = Rc::new(upstream);
        let state = State::builder(BASELINE)
            .with_server_fd(&upstream)
            .build()
            .map_err(|e| format!("cannot start a connection: {e}"))?;
        let socket = Rc::new(client);
        let client = match state.add_client(&socket) {
            Ok(client) => client,
            Err(e) => {
                state.destroy();
                return Err(format!("cannot take a connection: {e}"));
            }
        };
        let closing = Rc::new(Cell::new(false));
        state.set_handler(Relay {
            socket: socket.clone(),
        });
        client.set_handler(Gone {
            closing: closing.clone(),
        });
        client.display().set_handler(Display {
            closing: closing.clone(),
        });
        Ok(Self {
            state,
            client,
            socket,
            closing,
            stopped: false,
            dispatches: 0,
            scratch: Vec::new(),
        })
    }

    fn alive(&self) -> bool {
        !self.closing.get() && self.state.is_not_destroyed()
    }

    /// Write out what is queued, before going to sleep. False when dead.
    fn flush(&mut self) -> bool {
        self.alive() && self.state.before_poll().is_ok()
    }

    fn dispatch(&mut self) {
        if self.state.dispatch_available().is_err() {
            return;
        }
        self.dispatches = self.dispatches.wrapping_add(1);
        // Back-pressure: a client that does not read is not read either.
        let queued = outq(self.socket.as_raw_fd());
        if !self.stopped && queued >= OUTQ_HIGH {
            self.stopped = true;
            self.client.set_suspended(true);
        } else if self.stopped && queued <= OUTQ_LOW {
            self.stopped = false;
            self.client.set_suspended(false);
        }
        if self.dispatches.is_multiple_of(COUNT_OBJECTS_EVERY) {
            self.scratch.clear();
            self.client.objects(&mut self.scratch);
            let count = self.scratch.len();
            self.scratch.clear();
            if count > MAX_OBJECTS {
                refuse(&self.client, &self.closing, NO_MEMORY, "too many objects");
                let _ = self.state.before_poll();
            }
        }
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        // The State's objects and handlers point at each other: without this
        // the connection upstream would outlive the program's, and its
        // windows with it.
        self.state.destroy();
    }
}

/// Tell the client why, and end it. Like libwayland: an error event, then
/// the connection is closed (after this dispatch has written it out).
fn refuse(client: &Rc<Client>, closing: &Cell<bool>, code: u32, why: &str) {
    let display = client.display().clone();
    display.send_error(display.clone(), code, why);
    // Nothing more of it is read.
    client.set_suspended(true);
    closing.set(true);
}

struct Gone {
    closing: Rc<Cell<bool>>,
}

impl ClientHandler for Gone {
    fn disconnected(self: Box<Self>) {
        self.closing.set(true);
    }
}

/// A protocol error from the compositor ends the connection (wl-proxy
/// destroys the State at once); the program gets the error itself, written
/// straight to its socket, so that it can say what went wrong.
struct Relay {
    socket: Rc<OwnedFd>,
}

impl StateHandler for Relay {
    fn display_error(
        self: Box<Self>,
        object: Option<&Rc<dyn Object>>,
        _server_id: u32,
        error: u32,
        msg: &str,
    ) {
        let id = object.and_then(|o| o.client_id()).unwrap_or(1);
        // Non-blocking socket: a client that does not read loses the text,
        // not the proxy its time. If an earlier message was cut short, the
        // client reads garbage instead — it is being disconnected either way.
        let _ = sys::send_with_fds(
            self.socket.as_raw_fd(),
            &display_error_message(id, error, msg),
            &[],
        );
    }
}

struct Display {
    closing: Rc<Cell<bool>>,
}

impl WlDisplayHandler for Display {
    fn handle_get_registry(&mut self, slf: &Rc<WlDisplay>, registry: &Rc<WlRegistry>) {
        registry.set_handler(Registry {
            closing: self.closing.clone(),
            shown: HashMap::new(),
        });
        slf.send_get_registry(registry);
    }
}

/// A global this registry was shown.
struct Shown {
    interface: ObjectInterface,
    version: u32,
    removed: bool,
}

/// Every global wl-proxy passes (it has already dropped the ones it does not
/// know and capped the versions) is passed on and remembered; a bind must name
/// one of them, with its interface and at most its version. A global removed
/// stays bindable here: a bind racing the removal is the compositor's to
/// answer, as without the proxy.
struct Registry {
    closing: Rc<Cell<bool>>,
    shown: HashMap<u32, Shown>,
}

impl WlRegistryHandler for Registry {
    fn handle_global(
        &mut self,
        slf: &Rc<WlRegistry>,
        name: u32,
        interface: ObjectInterface,
        version: u32,
    ) {
        if self.shown.len() >= MAX_GLOBALS {
            self.shown.retain(|_, g| !g.removed);
            if self.shown.len() >= MAX_GLOBALS {
                return;
            }
        }
        self.shown.insert(
            name,
            Shown {
                interface,
                version,
                removed: false,
            },
        );
        slf.send_global(name, interface, version);
    }

    fn handle_global_remove(&mut self, slf: &Rc<WlRegistry>, name: u32) {
        if let Some(g) = self.shown.get_mut(&name) {
            if !g.removed {
                g.removed = true;
                slf.send_global_remove(name);
            }
        }
    }

    fn handle_bind(&mut self, slf: &Rc<WlRegistry>, name: u32, id: Rc<dyn Object>) {
        let fits = self
            .shown
            .get(&name)
            .is_some_and(|g| g.interface == id.interface() && id.version() <= g.version);
        if fits {
            slf.send_bind(name, id);
            return;
        }
        // What libwayland answers a bind to a name it does not have.
        if let Some(client) = slf.client() {
            let why = format!("invalid global {} ({name})", id.interface().name());
            refuse(&client, &self.closing, INVALID_OBJECT, &why);
        } else {
            self.closing.set(true);
        }
    }
}

/// `wl_display.error(object, code, message)` on the wire (host byte order).
fn display_error_message(object: u32, code: u32, message: &str) -> Vec<u8> {
    let mut end = message.len().min(MAX_ERROR_TEXT);
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    let text = &message.as_bytes()[..end];
    let len = text.len() + 1;
    let padded = len.div_ceil(4) * 4;
    let size = 8 + 4 + 4 + 4 + padded;
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&1u32.to_ne_bytes());
    out.extend_from_slice(&((size as u32) << 16).to_ne_bytes());
    out.extend_from_slice(&object.to_ne_bytes());
    out.extend_from_slice(&code.to_ne_bytes());
    out.extend_from_slice(&(len as u32).to_ne_bytes());
    out.extend_from_slice(text);
    out.resize(size, 0);
    out
}

// --- SMALL SYSCALL HELPERS ----------------------------------------------------

fn pollfd(fd: RawFd) -> libc::pollfd {
    libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }
}

/// `poll(2)`: how many descriptors are ready.
fn poll(fds: &mut [libc::pollfd], timeout_ms: libc::c_int) -> io::Result<usize> {
    // SAFETY: `fds` is a valid, exclusively borrowed array of `fds.len()`
    // pollfds for the duration of the call.
    let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

/// `accept4(SOCK_NONBLOCK | SOCK_CLOEXEC)`: wl-proxy never blocks on a
/// client, and neither does the error relay.
fn accept_nonblocking(listener: RawFd) -> io::Result<OwnedFd> {
    loop {
        // SAFETY: no address is asked for, so both pointers may be null.
        let fd = unsafe {
            libc::accept4(
                listener,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            )
        };
        if fd >= 0 {
            // SAFETY: accept4 has just returned this descriptor; nobody else
            // owns it.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        let e = io::Error::last_os_error();
        if !matches!(e.raw_os_error(), Some(libc::EINTR | libc::ECONNABORTED)) {
            return Err(e);
        }
    }
}

/// Bytes sent on a socket that its peer has not read (`TIOCOUTQ`, which is
/// `SIOCOUTQ` for a socket). 0 when it cannot be told.
fn outq(fd: RawFd) -> libc::c_int {
    let mut n: libc::c_int = 0;
    // SAFETY: TIOCOUTQ writes one int through the pointer, valid for the call.
    let r = unsafe { libc::ioctl(fd, libc::TIOCOUTQ, &mut n) };
    if r == 0 {
        n
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::mpsc;

    #[test]
    fn hidden_protocols_are_not_in_the_build() {
        for name in HIDDEN {
            assert!(
                ObjectInterface::from_str(name).is_none(),
                "{name} is compiled into wl-proxy, so it would be passed on"
            );
        }
        // And what an ordinary program needs is.
        for name in [
            "wl_compositor",
            "wl_subcompositor",
            "wl_shm",
            "wl_seat",
            "wl_output",
            "wl_data_device_manager",
            "xdg_wm_base",
            "zxdg_decoration_manager_v1",
            "org_kde_kwin_server_decoration_manager",
            "zwp_linux_dmabuf_v1",
            "wl_drm",
            "wp_viewporter",
            "wp_fractional_scale_manager_v1",
            "wp_cursor_shape_manager_v1",
            "zwp_primary_selection_device_manager_v1",
            "zwp_text_input_manager_v3",
            "xdg_activation_v1",
            "zxdg_output_manager_v1",
            "wp_presentation",
            "zwp_pointer_constraints_v1",
            "zwp_relative_pointer_manager_v1",
            "zwp_idle_inhibit_manager_v1",
            "wp_linux_drm_syncobj_manager_v1",
            "zwp_tablet_manager_v2",
            "zxdg_exporter_v2",
        ] {
            assert!(
                ObjectInterface::from_str(name).is_some(),
                "{name} is not compiled in"
            );
        }
    }

    #[test]
    fn the_filter_builds_and_its_default_is_kill() {
        let path = std::env::temp_dir().join(format!("vz-wl-proxy-bpf-{}", std::process::id()));
        let file = fs::File::create(&path).unwrap();
        filter(ScmpAction::KillProcess)
            .unwrap()
            .export_bpf(&file)
            .unwrap();
        let bpf = fs::read(&path).unwrap();
        let _ = fs::remove_file(&path);
        assert!(!bpf.is_empty() && bpf.len().is_multiple_of(8));
        // SECCOMP_RET_KILL_PROCESS is 0x80000000: some return carries it.
        let kills = bpf.chunks(8).any(|insn| {
            u16::from_ne_bytes([insn[0], insn[1]]) & 0x07 == 0x06
                && u32::from_ne_bytes([insn[4], insn[5], insn[6], insn[7]]) == 0x8000_0000
        });
        assert!(kills, "no kill in the program");
    }

    #[test]
    fn the_error_message_is_a_wire_message() {
        let m = display_error_message(7, 2, "bad");
        let word = |i: usize| u32::from_ne_bytes(m[i * 4..i * 4 + 4].try_into().unwrap());
        assert_eq!(m.len() % 4, 0);
        assert_eq!(word(0), 1, "sent by wl_display");
        assert_eq!(word(1) >> 16, m.len() as u32);
        assert_eq!(word(1) & 0xffff, 0, "opcode error");
        assert_eq!((word(2), word(3), word(4)), (7, 2, 4));
        assert_eq!(&m[20..24], b"bad\0");
        // Cut at a character, never in one, and never longer than allowed.
        let long = "й".repeat(MAX_ERROR_TEXT);
        let m = display_error_message(1, 0, &long);
        let len = u32::from_ne_bytes(m[16..20].try_into().unwrap()) as usize;
        assert!(len - 1 <= MAX_ERROR_TEXT);
        assert!(std::str::from_utf8(&m[20..20 + len - 1]).is_ok());
    }

    #[test]
    fn close_all_but_keeps_what_it_is_told() {
        // In a child: closing descriptors of the test harness is not ours to do.
        let (mut a, b) = UnixStream::pair().unwrap();
        let (c, _d) = UnixStream::pair().unwrap();
        // SAFETY: the child of this multi-threaded process allocates nothing:
        // close_range, fcntl, write, _exit.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let ok = close_all_but(&mut [2, b.as_raw_fd()]).is_ok();
            // SAFETY: fcntl on a number only asks.
            let c_open = unsafe { libc::fcntl(c.as_raw_fd(), libc::F_GETFD) } >= 0;
            let b_open = unsafe { libc::fcntl(b.as_raw_fd(), libc::F_GETFD) } >= 0;
            let byte = [u8::from(ok && b_open && !c_open)];
            // SAFETY: a valid descriptor and buffer.
            unsafe { libc::write(b.as_raw_fd(), byte.as_ptr().cast(), 1) };
            unsafe { libc::_exit(0) };
        }
        let mut got = [0u8];
        a.read_exact(&mut got).unwrap();
        let mut status = 0;
        wait(pid, &mut status, 0);
        assert_eq!(got[0], 1, "kept the wrong descriptors");
    }

    // --- a proxy between a real client and a fake compositor ----------------

    /// A compositor that knows two requests: `wl_display.get_registry` (it
    /// announces `globals` on the new registry) and `wl_display.sync` (done,
    /// then delete_id). Every bind is remembered.
    fn fake_compositor(
        mut sock: UnixStream,
        globals: &'static [(&'static str, u32)],
        binds: mpsc::Sender<u32>,
    ) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let word = |b: &[u8], i: usize| u32::from_ne_bytes(b[i * 4..i * 4 + 4].try_into().unwrap());
        loop {
            let n = match sock.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            buf.extend_from_slice(&chunk[..n]);
            while buf.len() >= 8 {
                let size = (word(&buf, 1) >> 16) as usize;
                if buf.len() < size {
                    break;
                }
                let msg: Vec<u8> = buf.drain(..size).collect();
                let (object, opcode) = (word(&msg, 0), word(&msg, 1) & 0xffff);
                let mut out = Vec::new();
                match (object, opcode) {
                    (1, 1) => {
                        let registry = word(&msg, 2);
                        for (name, (iface, version)) in globals.iter().enumerate() {
                            event(&mut out, registry, 0, |a| {
                                a.extend_from_slice(&(name as u32 + 1).to_ne_bytes());
                                string(a, iface);
                                a.extend_from_slice(&version.to_ne_bytes());
                            });
                        }
                    }
                    (1, 0) => {
                        let callback = word(&msg, 2);
                        event(&mut out, callback, 0, |a| {
                            a.extend_from_slice(&7u32.to_ne_bytes())
                        });
                        event(&mut out, 1, 1, |a| {
                            a.extend_from_slice(&callback.to_ne_bytes())
                        });
                    }
                    (_, 0) if size > 12 => {
                        // wl_registry.bind(name, interface, version, id)
                        let _ = binds.send(word(&msg, 2));
                    }
                    _ => {}
                }
                if sock.write_all(&out).is_err() {
                    return;
                }
            }
        }
    }

    fn event(out: &mut Vec<u8>, object: u32, opcode: u32, args: impl FnOnce(&mut Vec<u8>)) {
        let mut a = Vec::new();
        args(&mut a);
        let size = 8 + a.len() as u32;
        out.extend_from_slice(&object.to_ne_bytes());
        out.extend_from_slice(&((size << 16) | opcode).to_ne_bytes());
        out.extend_from_slice(&a);
    }

    fn string(out: &mut Vec<u8>, s: &str) {
        let len = s.len() + 1;
        out.extend_from_slice(&(len as u32).to_ne_bytes());
        out.extend_from_slice(s.as_bytes());
        out.resize(out.len() + len.div_ceil(4) * 4 - s.len(), 0);
    }

    const GLOBALS: &[(&str, u32)] = &[
        ("wl_compositor", 6),
        ("wp_drm_lease_device_v1", 1),
        ("xdg_wm_base", 99),
        ("mutter_x11_interop", 1),
        ("zwlr_screencopy_manager_v1", 3),
        ("wl_shm", 1),
    ];

    /// The proxy's own loop, under its own filter (answering EPERM instead of
    /// killing, so that a missing call fails this test rather than the whole
    /// run), in a thread: the filter is loaded into that thread only. The
    /// test plays the supervisor and the compositor.
    struct Rig {
        dir: PathBuf,
        path: PathBuf,
        channel: Option<UnixStream>,
        proxy: Option<std::thread::JoinHandle<libc::c_int>>,
        binds: mpsc::Receiver<u32>,
        binds_tx: mpsc::Sender<u32>,
    }

    impl Rig {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("vz-wl-proxy-test-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            let path = dir.join("sock");
            let listener = UnixListener::bind(&path).unwrap();
            listener.set_nonblocking(true).unwrap();
            let (ours, theirs) = UnixStream::pair().unwrap();
            let proxy = std::thread::spawn(move || {
                filter(ScmpAction::Errno(libc::EPERM))
                    .unwrap()
                    .load()
                    .unwrap();
                serve(listener, theirs)
            });
            let (binds_tx, binds) = mpsc::channel();
            Self {
                dir,
                path,
                channel: Some(ours),
                proxy: Some(proxy),
                binds,
                binds_tx,
            }
        }

        /// A client connects; the proxy asks for an upstream; the test hands
        /// it one to a fake compositor.
        fn connect(&self) -> UnixStream {
            let client = UnixStream::connect(&self.path).unwrap();
            let channel = self.channel.as_ref().unwrap();
            let mut byte = [0u8];
            (&*channel).read_exact(&mut byte).unwrap();
            assert_eq!(byte[0], CONNECT);
            let (up, compositor) = UnixStream::pair().unwrap();
            let binds = self.binds_tx.clone();
            std::thread::spawn(move || fake_compositor(compositor, GLOBALS, binds));
            sys::send_with_fds(channel.as_raw_fd(), &[UPSTREAM], &[up.as_raw_fd()]).unwrap();
            client
        }

        fn finish(mut self) -> libc::c_int {
            self.channel = None;
            let code = self.proxy.take().unwrap().join().unwrap();
            let _ = fs::remove_dir_all(&self.dir);
            code
        }
    }

    /// Globals the client sees through the proxy, by a real client library.
    fn globals_of(client: UnixStream) -> Vec<(String, u32)> {
        use wayland_client::globals::registry_queue_init;
        let conn = wayland_client::Connection::from_socket(client).unwrap();
        let (globals, _queue) = registry_queue_init::<NoState>(&conn).unwrap();
        globals
            .contents()
            .clone_list()
            .into_iter()
            .map(|g| (g.interface, g.version))
            .collect()
    }

    struct NoState;
    impl
        wayland_client::Dispatch<
            wayland_client::protocol::wl_registry::WlRegistry,
            wayland_client::globals::GlobalListContents,
        > for NoState
    {
        fn event(
            _: &mut Self,
            _: &wayland_client::protocol::wl_registry::WlRegistry,
            _: wayland_client::protocol::wl_registry::Event,
            _: &wayland_client::globals::GlobalListContents,
            _: &wayland_client::Connection,
            _: &wayland_client::QueueHandle<Self>,
        ) {
        }
    }

    #[test]
    fn a_client_sees_the_known_globals_and_nothing_else() {
        let rig = Rig::new("globals");
        let seen = globals_of(rig.connect());
        let names: Vec<&str> = seen.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            ["wl_compositor", "xdg_wm_base", "wl_shm"],
            "{seen:?}"
        );
        // Capped at the baseline, not the compositor's 99.
        let wm = seen.iter().find(|(n, _)| n == "xdg_wm_base").unwrap().1;
        assert!(wm < 99, "xdg_wm_base at {wm}");
        assert_eq!(rig.finish(), 0);
    }

    /// Raw requests, to bind what the library would not.
    fn request(sock: &mut UnixStream, object: u32, opcode: u32, args: &[u8]) {
        let mut out = Vec::new();
        event(&mut out, object, opcode, |a| a.extend_from_slice(args));
        sock.write_all(&out).unwrap();
    }

    fn bind_args(name: u32, iface: &str, version: u32, id: u32) -> Vec<u8> {
        let mut a = name.to_ne_bytes().to_vec();
        string(&mut a, iface);
        a.extend_from_slice(&version.to_ne_bytes());
        a.extend_from_slice(&id.to_ne_bytes());
        a
    }

    /// Read events until one for `object` has come.
    fn await_event(sock: &mut UnixStream, object: u32) {
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut buf = Vec::new();
        loop {
            while buf.len() >= 8 {
                let size = (u32::from_ne_bytes(buf[4..8].try_into().unwrap()) >> 16) as usize;
                if buf.len() < size {
                    break;
                }
                let msg: Vec<u8> = buf.drain(..size).collect();
                if u32::from_ne_bytes(msg[..4].try_into().unwrap()) == object {
                    return;
                }
            }
            let mut chunk = [0u8; 4096];
            let n = sock.read(&mut chunk).unwrap();
            assert!(n > 0, "closed before an event for {object}");
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Read until EOF; the bytes that came.
    fn drain(sock: &mut UnixStream) -> Vec<u8> {
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut all = Vec::new();
        let _ = sock.read_to_end(&mut all);
        all
    }

    #[test]
    fn a_hidden_global_cannot_be_bound_by_its_number() {
        let rig = Rig::new("bind");
        let mut client = rig.connect();
        request(&mut client, 1, 1, &2u32.to_ne_bytes()); // get_registry → 2
                                                         // Name 2 is the DRM lease device: never shown. Asked for as a
                                                         // wl_compositor, the only way to name it at all.
        request(&mut client, 2, 0, &bind_args(2, "wl_compositor", 1, 3));
        let got = drain(&mut client);
        let text = String::from_utf8_lossy(&got);
        assert!(text.contains("invalid global"), "no error: {text:?}");
        // Name 1 is wl_compositor, shown: bound, and the compositor got it.
        let mut client = rig.connect();
        request(&mut client, 1, 1, &2u32.to_ne_bytes());
        request(&mut client, 1, 0, &3u32.to_ne_bytes());
        // As a real client does: bind once the globals are in, which the
        // sync's `done` says.
        await_event(&mut client, 3);
        request(&mut client, 2, 0, &bind_args(1, "wl_compositor", 4, 4));
        assert_eq!(rig.binds.recv_timeout(Duration::from_secs(10)), Ok(1));
        // A version above the one shown is refused too.
        request(&mut client, 2, 0, &bind_args(1, "wl_compositor", 7, 6));
        let text = String::from_utf8_lossy(&drain(&mut client)).into_owned();
        assert!(text.contains("invalid global"), "{text:?}");
        assert!(
            rig.binds.try_recv().is_err(),
            "a refused bind reached the compositor"
        );
        assert_eq!(rig.finish(), 0);
    }

    #[test]
    fn after_the_program_exits_nothing_new_is_accepted_but_old_connections_live() {
        let rig = Rig::new("life");
        let old = rig.connect();
        let path = rig.path.clone();
        let Rig {
            dir,
            channel,
            proxy,
            ..
        } = rig;
        drop(channel);
        // The listener is closed: a new connection is refused (the path is
        // the supervisor's to remove).
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            match UnixStream::connect(&path) {
                Err(_) => break,
                Ok(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Ok(_) => panic!("still accepting"),
            }
        }
        // The old one still works.
        assert_eq!(globals_of(old).len(), 3);
        // And the proxy is done when the last connection is.
        assert_eq!(proxy.unwrap().join().unwrap(), 0);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn when_the_client_goes_its_upstream_goes_too() {
        let rig = Rig::new("updown");
        let client = UnixStream::connect(&rig.path).unwrap();
        let channel = rig.channel.as_ref().unwrap();
        let mut byte = [0u8];
        (&*channel).read_exact(&mut byte).unwrap();
        let (up, mut compositor) = UnixStream::pair().unwrap();
        sys::send_with_fds(channel.as_raw_fd(), &[UPSTREAM], &[up.as_raw_fd()]).unwrap();
        drop(up);
        drop(client);
        // The compositor sees its end close: no window outlives its program.
        compositor
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut rest = Vec::new();
        assert!(
            compositor.read_to_end(&mut rest).is_ok(),
            "upstream still open"
        );
        assert_eq!(rig.finish(), 0);
    }

    #[test]
    fn when_the_compositor_goes_the_client_loses_its_display() {
        let rig = Rig::new("down");
        let mut client = UnixStream::connect(&rig.path).unwrap();
        let channel = rig.channel.as_ref().unwrap();
        let mut byte = [0u8];
        (&*channel).read_exact(&mut byte).unwrap();
        let (up, compositor) = UnixStream::pair().unwrap();
        sys::send_with_fds(channel.as_raw_fd(), &[UPSTREAM], &[up.as_raw_fd()]).unwrap();
        drop(up);
        drop(compositor);
        request(&mut client, 1, 0, &2u32.to_ne_bytes());
        assert!(drain(&mut client).is_empty());
        assert_eq!(rig.finish(), 0);
    }

    #[test]
    fn a_refused_upstream_closes_the_client() {
        let rig = Rig::new("refused");
        let mut client = UnixStream::connect(&rig.path).unwrap();
        let channel = rig.channel.as_ref().unwrap();
        let mut byte = [0u8];
        (&*channel).read_exact(&mut byte).unwrap();
        sys::send_with_fds(channel.as_raw_fd(), &[REFUSED], &[]).unwrap();
        assert!(drain(&mut client).is_empty());
        assert_eq!(rig.finish(), 0);
    }

    /// `start` forks, and a fork of the multi-threaded test harness is no
    /// place to confine a process in: the test runs itself again, alone.
    #[test]
    fn the_proxy_starts_confined_serves_and_ends_with_its_last_connection() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "wl_proxy::tests::supervised",
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success() && text.contains("1 passed"), "{text}");
    }

    #[test]
    #[ignore = "run by the_proxy_starts_confined_serves_and_ends_with_its_last_connection"]
    fn supervised() {
        let dir = std::env::temp_dir().join(format!("vz-wl-proxy-sup-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // The security context's listener, played by a fake compositor.
        let up = Upstream::bind(&dir, 42).unwrap();
        assert!(up.path.starts_with(dir.join(UPSTREAM_DIR)));
        let zone_path = dir.join("zone-sock");
        let zone = UnixListener::bind(&zone_path).unwrap();
        // Before any thread: the fork in `start` has to be the only thing.
        let mut proxy = start(&zone, &up.path).unwrap();
        drop(zone);
        let pid = proxy.pid;
        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        let field = |k: &str| {
            status
                .lines()
                .find_map(|l| l.strip_prefix(k))
                .map(str::trim)
                .unwrap_or("")
                .to_owned()
        };
        assert_eq!(field("Name:"), PROCESS_NAME);
        assert_eq!(field("Seccomp:"), "2", "no filter");
        assert_eq!(field("NoNewPrivs:"), "1");
        // Not dumpable: its descriptors are root's to look at.
        assert!(fs::read_dir(format!("/proc/{pid}/fd")).is_err());

        let (binds, _) = mpsc::channel();
        let (peers_tx, peers) = mpsc::channel();
        let listener = up.listener;
        std::thread::spawn(move || {
            for sock in listener.incoming().flatten() {
                // Whose pid the compositor sees: whoever connected.
                let mut cred = libc::ucred {
                    pid: 0,
                    uid: 0,
                    gid: 0,
                };
                let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
                // SAFETY: SO_PEERCRED fills one ucred, whose size is passed.
                unsafe {
                    libc::getsockopt(
                        sock.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_PEERCRED,
                        (&mut cred as *mut libc::ucred).cast(),
                        &mut len,
                    )
                };
                let _ = peers_tx.send(cred.pid);
                let binds = binds.clone();
                std::thread::spawn(move || fake_compositor(sock, GLOBALS, binds));
            }
        });
        // The "program": lives a second, and a client of it opens a
        // connection that outlives it by another. Reaped by `supervise`.
        #[allow(clippy::zombie_processes)]
        let main = std::process::Command::new("sleep")
            .arg("1")
            .spawn()
            .unwrap();
        let (seen_tx, seen_rx) = mpsc::channel();
        let client_path = zone_path.clone();
        std::thread::spawn(move || {
            seen_tx
                .send(globals_of(UnixStream::connect(&client_path).unwrap()).len())
                .unwrap();
            let mut client = UnixStream::connect(&client_path).unwrap();
            request(&mut client, 1, 0, &2u32.to_ne_bytes());
            await_event(&mut client, 2);
            std::thread::sleep(Duration::from_secs(2));
            // Still served after the program is gone.
            request(&mut client, 1, 0, &3u32.to_ne_bytes());
            await_event(&mut client, 3);
            seen_tx.send(0).unwrap();
        });
        proxy.take_over();
        let exited = Rc::new(Cell::new(false));
        let flag = exited.clone();
        let started = std::time::Instant::now();
        let status = proxy.supervise(main.id() as libc::pid_t, move || flag.set(true));
        assert!(exited.get());
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        assert_eq!(seen_rx.recv().unwrap(), 3);
        // Every connection upstream is the supervisor's: its windows have the
        // pid of the launch's record (`crate::focus`).
        let me = std::process::id() as libc::pid_t;
        assert_eq!(peers.try_iter().collect::<Vec<_>>(), [me, me]);
        assert_eq!(
            seen_rx.recv().unwrap(),
            0,
            "the late connection was not served"
        );
        // Not before the connection that outlived the program was closed.
        assert!(
            started.elapsed() >= Duration::from_millis(1800),
            "{:?}",
            started.elapsed()
        );
        // And after the program, nothing new is taken.
        assert!(UnixStream::connect(&zone_path).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_filter_refuses_what_the_proxy_must_not_do() {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (a, _b) = UnixStream::pair().unwrap();
            filter(ScmpAction::Errno(libc::EPERM))
                .unwrap()
                .load()
                .unwrap();
            let eperm = |r: libc::c_long| {
                r == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
            };
            // SAFETY: every call below either fails under the filter or acts
            // on memory/descriptors of this thread only.
            let results = unsafe {
                vec![
                    (
                        "socket",
                        eperm(libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) as _),
                    ),
                    (
                        "openat",
                        eperm(libc::open(c"/etc/hostname".as_ptr(), libc::O_RDONLY) as _),
                    ),
                    (
                        "fcntl F_DUPFD",
                        eperm(libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 100) as _),
                    ),
                    (
                        "mmap exec",
                        libc::mmap(
                            std::ptr::null_mut(),
                            4096,
                            libc::PROT_READ | libc::PROT_EXEC,
                            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                            -1,
                            0,
                        ) == libc::MAP_FAILED,
                    ),
                    (
                        "mmap of a descriptor",
                        libc::mmap(
                            std::ptr::null_mut(),
                            4096,
                            libc::PROT_READ,
                            libc::MAP_PRIVATE,
                            0,
                            0,
                        ) == libc::MAP_FAILED,
                    ),
                    (
                        "ioctl other",
                        eperm(libc::ioctl(0, libc::FIONREAD, &mut 0i32) as _),
                    ),
                    ("kill", eperm(libc::kill(1, 0) as _)),
                ]
            };
            // And what it needs still works.
            let v: Vec<u8> = vec![1; 1 << 20];
            let fine = v.len() == 1 << 20 && outq(a.as_raw_fd()) == 0;
            tx.send((results, fine)).unwrap();
        });
        let (results, fine) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        for (what, refused) in results {
            assert!(refused, "{what} was allowed");
        }
        assert!(fine, "memory or TIOCOUTQ was refused");
    }
}
