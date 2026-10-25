//! Kernel-only, nonblocking NFNETLINK transport. Opening this socket does
//! not install a firewall or enable the experimental strict backend.
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use super::wire;

pub struct Socket {
    fd: OwnedFd,
}

impl Socket {
    /// Only for a descriptor handed back by the trusted namespace helper.
    pub fn from_owned(fd: OwnedFd) -> io::Result<Self> {
        for (option, expected) in [
            (libc::SO_DOMAIN, libc::AF_NETLINK),
            (libc::SO_PROTOCOL, libc::NETLINK_NETFILTER),
            (libc::SO_TYPE, libc::SOCK_RAW),
        ] {
            let mut value = 0i32;
            let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    std::ptr::from_mut(&mut value).cast(),
                    &mut len,
                )
            } != 0
                || value != expected
            {
                return Err(io::Error::other("not an NFNETLINK queue socket"));
            }
        }
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    pub fn open_here() -> io::Result<Self> {
        // SAFETY: socket takes integers; ownership is taken exactly once.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::NETLINK_NETFILTER,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: zeroed sockaddr_nl with family/pid/groups initialized.
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        if unsafe {
            libc::bind(
                fd.as_raw_fd(),
                std::ptr::from_ref(&address).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Trusted controller only. The adapter, not a GUI, chooses messages.
    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        if data.len() > wire::MAX_DATAGRAM {
            return Err(io::Error::other("netqueue message too large"));
        }
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        loop {
            // SAFETY: live buffer and kernel sockaddr_nl (port/groups zero).
            let n = unsafe {
                libc::sendto(
                    self.fd(),
                    data.as_ptr().cast(),
                    data.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    std::ptr::from_ref(&address).cast(),
                    std::mem::size_of_val(&address) as libc::socklen_t,
                )
            };
            if n == data.len() as isize {
                return Ok(());
            }
            if n >= 0 {
                return Err(io::Error::other("short netqueue send"));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    pub fn receive(&self) -> io::Result<Option<Vec<wire::Message>>> {
        let mut data = vec![0u8; wire::MAX_DATAGRAM];
        let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_name = std::ptr::from_mut(&mut sender).cast();
        message.msg_namelen = std::mem::size_of_val(&sender) as libc::socklen_t;
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        // SAFETY: all recvmsg buffers live for the call; no borrowed fd or
        // sender identity comes from application-controlled protocol fields.
        let n = unsafe { libc::recvmsg(self.fd(), &mut message, libc::MSG_DONTWAIT) };
        if n < 0 {
            let error = io::Error::last_os_error();
            return match error.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(None),
                _ => Err(error),
            };
        }
        if message.msg_namelen as usize != std::mem::size_of_val(&sender)
            || sender.nl_family != libc::AF_NETLINK as u16
            || sender.nl_groups != 0
        {
            return Err(io::Error::other("not a unicast netlink kernel peer"));
        }
        let truncated = message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0;
        wire::parse(
            &data[..(n as usize).min(data.len())],
            sender.nl_pid,
            truncated,
        )
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("netqueue: {e:?}")))
    }

    pub fn wait(&self, timeout: Duration) -> io::Result<()> {
        let mut fd = libc::pollfd {
            fd: self.fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized pollfd, timeout clamped to libc::poll's range.
        let result =
            unsafe { libc::poll(&mut fd, 1, timeout.as_millis().min(i32::MAX as u128) as i32) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if result == 0 {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "netqueue timeout"));
        }
        if fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(io::Error::other("netqueue transport failed"));
        }
        Ok(())
    }
}
