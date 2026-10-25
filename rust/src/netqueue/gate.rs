//! Inherited pre-exec barrier. No public pathname or application-selected
//! identifier. Create before fork; immediately drop the opposite endpoint in
//! each process. The supervisor must verify dedicated placement and acknowledge
//! the nft mapping before calling release. This module does not prove either.
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const READY: u8 = 0x52;
const EXEC: u8 = 0x45;

pub struct Supervisor(UnixStream);
pub struct Child(UnixStream);
pub struct Prepared(UnixStream);

pub fn pair(timeout: Duration) -> io::Result<(Supervisor, Child)> {
    if timeout.is_zero() || timeout > Duration::from_secs(30) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid launch barrier timeout",
        ));
    }
    // UnixStream::pair creates CLOEXEC descriptors. A supervisor crash/EOF is
    // denial; there is no permissive token, retry or execute-on-timeout path.
    let (parent, child) = UnixStream::pair()?;
    for socket in [&parent, &child] {
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;
    }
    Ok((Supervisor(parent), Child(child)))
}

impl Supervisor {
    /// Consuming transition prevents approval before the child's placement
    /// attempt. READY itself is not proof of placement: pin/recheck the fork's
    /// host PID/start/cgroup from the trusted supervisor before registration.
    pub fn prepared(mut self) -> io::Result<Prepared> {
        expect(&mut self.0, READY)?;
        Ok(Prepared(self.0))
    }
}

impl Prepared {
    /// Only after the trusted controller's exact mapping ACK. Consumes the
    /// endpoint: it cannot accidentally release a second launch later.
    pub fn release(mut self) -> io::Result<()> {
        self.0.write_all(&[EXEC])
    }
}

impl Child {
    /// Call after successful dedicated-cgroup placement and before exec or
    /// creation of any network socket. Any error MUST abort the child.
    pub fn placed_then_wait(mut self) -> io::Result<()> {
        self.0.write_all(&[READY])?;
        expect(&mut self.0, EXEC)
    }
}

fn expect(socket: &mut UnixStream, expected: u8) -> io::Result<()> {
    let mut byte = [0];
    socket.read_exact(&mut byte)?;
    if byte != [expected] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid launch barrier message",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn child_cannot_continue_before_registration_release() {
        let (supervisor, child) = pair(Duration::from_secs(2)).unwrap();
        let (sent, received) = mpsc::channel();
        let worker = thread::spawn(move || {
            sent.send(child.placed_then_wait()).unwrap();
        });
        let prepared = supervisor.prepared().unwrap();
        assert!(received.try_recv().is_err());
        prepared.release().unwrap();
        received
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn supervisor_failure_never_releases_exec() {
        let (supervisor, child) = pair(Duration::from_secs(2)).unwrap();
        let worker = thread::spawn(move || child.placed_then_wait());
        drop(supervisor.prepared().unwrap());
        assert!(worker.join().unwrap().is_err());
    }

    #[test]
    fn child_failure_cannot_be_treated_as_ready() {
        let (supervisor, child) = pair(Duration::from_secs(2)).unwrap();
        drop(child);
        assert!(supervisor.prepared().is_err());
    }

    #[test]
    fn missing_supervisor_times_out_instead_of_executing() {
        let (_supervisor, child) = pair(Duration::from_millis(20)).unwrap();
        assert!(child.placed_then_wait().is_err());
    }

    #[test]
    fn corrupted_release_is_denial() {
        let (supervisor, child) = pair(Duration::from_secs(2)).unwrap();
        let worker = thread::spawn(move || child.placed_then_wait());
        let mut prepared = supervisor.prepared().unwrap();
        prepared.0.write_all(b"X").unwrap();
        assert!(worker.join().unwrap().is_err());
    }

    #[test]
    fn barrier_descriptors_cannot_leak_across_exec() {
        let (supervisor, child) = pair(Duration::from_secs(2)).unwrap();
        for fd in [supervisor.0.as_raw_fd(), child.0.as_raw_fd()] {
            // SAFETY: live descriptors, F_GETFD takes no pointer arguments.
            assert_ne!(
                unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
        }
        assert!(pair(Duration::ZERO).is_err());
        assert!(pair(Duration::from_secs(31)).is_err());
    }
}
