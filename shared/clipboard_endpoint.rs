//! Host-only registration/lookup of scoped clipboard descriptors.
//! Never give an unbound connection to a confined program or proxy.
use std::io::{self, Read, Write};
use std::mem;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const MAX_CONTROL: usize = 4096;
pub const DIRECTORY: &str = "cellward-clipboard";
pub struct Bound {
    pub data: UnixStream,
    pub changed: OwnedFd,
    /// Separate bounded metadata traffic: a large payload/read must not
    /// delay announcing a newly started copy to the host broker.
    pub captures: Option<UnixStream>,
}
pub fn path(runtime: &Path) -> PathBuf {
    runtime.join(DIRECTORY).join("control.sock")
}
pub fn valid_label(s: &str) -> bool {
    !s.is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control) && !s.contains('/')
}
pub fn put_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}
pub fn take_string<'a>(bytes: &mut &'a [u8]) -> io::Result<&'a str> {
    if bytes.len() < 2 {
        return Err(invalid());
    }
    let n = u16::from_le_bytes(bytes[..2].try_into().unwrap()) as usize;
    let text =
        std::str::from_utf8(bytes.get(2..2 + n).ok_or_else(invalid)?).map_err(|_| invalid())?;
    if !valid_label(text) {
        return Err(invalid());
    }
    *bytes = &bytes[2 + n..];
    Ok(text)
}
pub fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid clipboard control message",
    )
}

fn exchange(
    runtime: &Path,
    body: &[u8],
    owner: Option<BorrowedFd<'_>>,
) -> io::Result<(UnixStream, Vec<u8>, Option<OwnedFd>)> {
    if !runtime.is_absolute() || body.len() > MAX_CONTROL {
        return Err(invalid());
    }
    let mut stream = UnixStream::connect(path(runtime))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let header = (body.len() as u32).to_le_bytes();
    let sent = send_header(&stream, &header, owner)?;
    stream.write_all(&header[sent..])?;
    stream.write_all(body)?;
    let mut header = [0; 4];
    let mut head = 0;
    let mut changed = None;
    while head < 4 {
        let (n, fd) = recv_header(&stream, &mut header[head..])?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        if let Some(fd) = fd {
            if changed.replace(fd).is_some() {
                return Err(invalid());
            }
        }
        head += n;
    }
    let n = u32::from_le_bytes(header) as usize;
    if !(1..=64 * 1024).contains(&n) {
        return Err(invalid());
    }
    let mut answer = vec![0; n];
    stream.read_exact(&mut answer)?;
    if answer[0] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private clipboard scope refused",
        ));
    }
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    Ok((stream, answer, changed))
}

pub fn bind(runtime: &Path, id: &str, history: &str, owner: BorrowedFd<'_>) -> io::Result<Bound> {
    if !valid_label(id) || !valid_label(history) {
        return Err(invalid());
    }
    let mut body = vec![b'B'];
    put_string(&mut body, id);
    put_string(&mut body, history);
    let (stream, answer, changed) = exchange(runtime, &body, Some(owner))?;
    if answer != [0] {
        return Err(invalid());
    }
    Ok(Bound {
        data: stream,
        changed: changed.ok_or_else(invalid)?,
        captures: None,
    })
}
pub fn lookup(runtime: &Path, id: &str) -> io::Result<Bound> {
    if !valid_label(id) {
        return Err(invalid());
    }
    let mut body = vec![b'L'];
    put_string(&mut body, id);
    let (stream, answer, changed) = exchange(runtime, &body, None)?;
    if answer != [0] {
        return Err(invalid());
    }
    Ok(Bound {
        data: stream,
        changed: changed.ok_or_else(invalid)?,
        captures: None,
    })
}

pub fn bind_capture(
    runtime: &Path,
    id: &str,
    history: &str,
    owner: BorrowedFd<'_>,
) -> io::Result<Bound> {
    let mut bound = bind(runtime, id, history, owner)?;
    let metadata = lookup(runtime, id)?;
    bound.captures = Some(metadata.data);
    Ok(bound)
}

pub struct PastePreview {
    pub epoch: u64,
    pub source_revision: u64,
    pub target_revision: u64,
    pub source: String,
    pub source_history: String,
    pub target_history: String,
    pub secret: bool,
    pub preview: String,
    pub types: Vec<(String, u64)>,
}
impl std::fmt::Debug for PastePreview {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PastePreview")
            .field("epoch", &self.epoch)
            .field("secret", &self.secret)
            .field("preview", &"<redacted>")
            .finish_non_exhaustive()
    }
}
#[derive(Debug)]
pub enum PastePlan {
    Current(u64),
    Pending(u64),
    Transfer(PastePreview),
}

pub fn put_text(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(&(text.len() as u16).to_le_bytes());
    out.extend_from_slice(text.as_bytes());
}
pub fn take_text<'a>(bytes: &mut &'a [u8], limit: usize) -> io::Result<&'a str> {
    let n = u16::from_le_bytes(bytes.get(..2).ok_or_else(invalid)?.try_into().unwrap()) as usize;
    if n > limit {
        return Err(invalid());
    }
    let text =
        std::str::from_utf8(bytes.get(2..2 + n).ok_or_else(invalid)?).map_err(|_| invalid())?;
    if text.chars().any(char::is_control) {
        return Err(invalid());
    }
    *bytes = &bytes[2 + n..];
    Ok(text)
}
pub fn take_number(bytes: &mut &[u8]) -> io::Result<u64> {
    let n = u64::from_le_bytes(bytes.get(..8).ok_or_else(invalid)?.try_into().unwrap());
    *bytes = &bytes[8..];
    Ok(n)
}

pub fn prepare_paste(runtime: &Path, target: &str, revision: u64) -> io::Result<PastePlan> {
    if !valid_label(target) {
        return Err(invalid());
    }
    let mut body = vec![b'P', 1];
    put_string(&mut body, target);
    body.extend_from_slice(&revision.to_le_bytes());
    let (_, answer, fd) = exchange(runtime, &body, None)?;
    if fd.is_some() || answer.len() < 2 {
        return Err(invalid());
    }
    let mut bytes = &answer[2..];
    let plan = match answer[1] {
        0 => PastePlan::Current(take_number(&mut bytes)?),
        1 => PastePlan::Pending(take_number(&mut bytes)?),
        2 => {
            let epoch = take_number(&mut bytes)?;
            let source_revision = take_number(&mut bytes)?;
            let target_revision = take_number(&mut bytes)?;
            let secret = match bytes.first() {
                Some(0) => false,
                Some(1) => true,
                _ => return Err(invalid()),
            };
            bytes = &bytes[1..];
            let source = take_string(&mut bytes)?.to_owned();
            let source_history = take_string(&mut bytes)?.to_owned();
            let target_history = take_string(&mut bytes)?.to_owned();
            let preview = take_text(&mut bytes, 2048)?.to_owned();
            let count = u16::from_le_bytes(bytes.get(..2).ok_or_else(invalid)?.try_into().unwrap())
                as usize;
            bytes = &bytes[2..];
            if !(1..=64).contains(&count)
                || epoch == 0
                || source_revision == 0
                || (secret && !preview.is_empty())
            {
                return Err(invalid());
            }
            let mut types = Vec::with_capacity(count);
            for _ in 0..count {
                let mime = take_text(&mut bytes, 256)?.to_owned();
                let size = take_number(&mut bytes)?;
                types.push((mime, size));
            }
            PastePlan::Transfer(PastePreview {
                epoch,
                source_revision,
                target_revision,
                source,
                source_history,
                target_history,
                secret,
                preview,
                types,
            })
        }
        _ => return Err(invalid()),
    };
    if !bytes.is_empty() {
        return Err(invalid());
    }
    Ok(plan)
}

pub fn commit_paste(
    runtime: &Path,
    target: &str,
    candidate: &PastePreview,
    allow_secret: bool,
) -> io::Result<u64> {
    if !valid_label(target) {
        return Err(invalid());
    }
    let mut body = vec![b'J', 1];
    put_string(&mut body, target);
    for n in [
        candidate.epoch,
        candidate.source_revision,
        candidate.target_revision,
    ] {
        body.extend_from_slice(&n.to_le_bytes());
    }
    body.push(u8::from(allow_secret));
    let (_, answer, fd) = exchange(runtime, &body, None)?;
    if fd.is_some() || answer.len() != 9 {
        return Err(invalid());
    }
    Ok(u64::from_le_bytes(answer[1..].try_into().unwrap()))
}
pub fn list(runtime: &Path) -> io::Result<Vec<(String, String)>> {
    let (_, answer, changed) = exchange(runtime, b"E", None)?;
    if changed.is_some() {
        return Err(invalid());
    }
    let mut bytes = &answer[1..];
    if bytes.len() < 2 {
        return Err(invalid());
    }
    let n = u16::from_le_bytes(bytes[..2].try_into().unwrap()) as usize;
    bytes = &bytes[2..];
    if n > 64 {
        return Err(invalid());
    }
    let mut scopes = Vec::with_capacity(n);
    for _ in 0..n {
        scopes.push((
            take_string(&mut bytes)?.to_owned(),
            take_string(&mut bytes)?.to_owned(),
        ));
    }
    if !bytes.is_empty() {
        return Err(invalid());
    }
    Ok(scopes)
}

/// Versioned input-selection validation. `subject` is the actual peer pidfd
/// captured by the target supervisor; capability bytes alone are insufficient.
pub fn verify_selection(
    runtime: &Path,
    capability: &[u8; 32],
    subject: BorrowedFd<'_>,
) -> io::Result<()> {
    let mut body = vec![b'V', 1];
    body.extend_from_slice(capability);
    let (_, answer, fd) = exchange(runtime, &body, Some(subject))?;
    if answer != [0] || fd.is_some() {
        return Err(invalid());
    }
    Ok(())
}

/// Only the issuing process, taken from this socket's peer, may revoke it.
pub fn revoke_selection(runtime: &Path, capability: &[u8; 32]) -> io::Result<()> {
    let mut body = vec![b'X', 1];
    body.extend_from_slice(capability);
    let (_, answer, fd) = exchange(runtime, &body, None)?;
    if answer != [0] || fd.is_some() {
        return Err(invalid());
    }
    Ok(())
}

pub fn send_header(
    stream: &UnixStream,
    header: &[u8; 4],
    fd: Option<BorrowedFd<'_>>,
) -> io::Result<usize> {
    let mut iov = libc::iovec {
        iov_base: header.as_ptr().cast_mut().cast(),
        iov_len: 4,
    };
    // usize alignment is sufficient for cmsghdr, and the buffer outlives sendmsg.
    let mut control = [0usize; 8];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if let Some(fd) = fd {
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = unsafe { libc::CMSG_SPACE(mem::size_of::<i32>() as u32) } as usize;
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(mem::size_of::<i32>() as u32) as usize;
            std::ptr::write_unaligned(libc::CMSG_DATA(c).cast::<i32>(), fd.as_raw_fd());
        }
    }
    let n = unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else if n == 0 {
        Err(io::Error::from(io::ErrorKind::WriteZero))
    } else {
        Ok(n as usize)
    }
}

/// Receive only control-header bytes, retaining at most one transferred FD.
pub fn recv_header(stream: &UnixStream, bytes: &mut [u8]) -> io::Result<(usize, Option<OwnedFd>)> {
    let mut control = [0usize; 8];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = mem::size_of_val(&control);
    let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut fds = Vec::new();
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let base = libc::CMSG_LEN(0) as usize;
                if (*c).cmsg_len >= base {
                    for at in 0..((*c).cmsg_len - base) / mem::size_of::<i32>() {
                        let fd = std::ptr::read_unaligned(libc::CMSG_DATA(c).cast::<i32>().add(at));
                        if fd >= 0 {
                            fds.push(OwnedFd::from_raw_fd(fd));
                        }
                    }
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 || fds.len() > 1 {
        return Err(invalid());
    }
    Ok((n as usize, fds.pop()))
}

pub fn alive(fd: BorrowedFd<'_>) -> bool {
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&mut p, 1, 0) == 0 }
}
pub fn owner_pid(fd: BorrowedFd<'_>) -> Option<i32> {
    if std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
        .ok()?
        .as_os_str()
        != "anon_inode:[pidfd]"
        || !alive(fd)
    {
        return None;
    }
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).ok()?;
    let pid = info.lines().find_map(|l| {
        l.strip_prefix("Pid:")
            .and_then(|p| p.trim().parse::<i32>().ok())
    })?;
    (pid > 0 && alive(fd)).then_some(pid)
}

/// A live connecting host process, not merely a matching numeric uid.
pub fn host_peer(stream: &UnixStream) -> bool {
    host_owner(stream).is_some()
}

/// Pin the actual host socket principal for a later authorization decision.
pub fn host_owner(stream: &UnixStream) -> Option<OwnedFd> {
    use std::os::fd::AsFd;
    let mut cred: libc::ucred = unsafe { mem::zeroed() };
    let mut len = mem::size_of_val(&cred) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    } != 0
        || cred.pid <= 0
        || cred.uid != unsafe { libc::getuid() }
    {
        return None;
    }
    let mut fd = -1i32;
    let mut len = mem::size_of_val(&fd) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&mut fd as *mut i32).cast(),
            &mut len,
        )
    } != 0
        || fd < 0
    {
        return None;
    }
    let held = unsafe { OwnedFd::from_raw_fd(fd) };
    if !alive(held.as_fd()) {
        return None;
    }
    for name in ["user", "pid", "mnt"] {
        let own = std::fs::read_link(format!("/proc/self/ns/{name}")).ok();
        let other = std::fs::read_link(format!("/proc/{}/ns/{name}", cred.pid)).ok();
        if own.is_none() || own != other || !alive(held.as_fd()) {
            return None;
        }
    }
    Some(held)
}
