//! Process-bound, short-lived authority for one broadcast target selection.
//!
//! This is the lease store, not human consent or a public control endpoint.
//! The controller must call `issue` only after its trusted consent flow and
//! pass the actual requesting socket's pidfd, never a client-supplied PID.
use crate::clipboard_endpoint;
use std::collections::HashMap;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::time::{Duration, Instant};

pub const MAX_LEASES: usize = 64;
pub const SELECTION_LIFETIME: Duration = Duration::from_secs(120);

/// Never log the operation capability, even in a debug representation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Capability([u8; 32]);
impl std::fmt::Debug for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Capability([redacted])")
    }
}
impl Capability {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

struct Lease {
    owner: OwnedFd,
    expires: Instant,
}

#[derive(Default)]
pub struct Authority {
    leases: HashMap<Capability, Lease>,
}
impl Authority {
    /// Only a trusted completed consent operation may issue a selection lease.
    /// Possession of the capability alone never authorizes another process.
    pub fn issue(&mut self, owner: OwnedFd, now: Instant) -> io::Result<Capability> {
        self.purge(now);
        if clipboard_endpoint::owner_pid(owner.as_fd()).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "selection owner is not a live process",
            ));
        }
        if self.leases.len() >= MAX_LEASES {
            return Err(io::Error::other("selection authority limit"));
        }
        for _ in 0..4 {
            let mut random = [0u8; 32];
            crate::crypto::random(&mut random)?;
            let key = Capability(random);
            if let std::collections::hash_map::Entry::Vacant(slot) = self.leases.entry(key) {
                slot.insert(Lease {
                    owner,
                    expires: now + SELECTION_LIFETIME,
                });
                return Ok(key);
            }
        }
        Err(io::Error::other("selection capability collision"))
    }

    /// `subject` is captured from the actual input-request socket by the
    /// supervisor. Both held pidfds are compared in the controller's procfs
    /// view. Do not reopen a numeric PID received through the wire.
    pub fn permits(&mut self, key: Capability, subject: BorrowedFd<'_>, now: Instant) -> bool {
        self.purge(now);
        let Some(lease) = self.leases.get(&key) else {
            return false;
        };
        let Some(pid) = clipboard_endpoint::owner_pid(subject) else {
            return false;
        };
        clipboard_endpoint::owner_pid(lease.owner.as_fd()) == Some(pid)
    }

    /// Broadcast validation is repeatable while selecting. Revocation ends
    /// that operation; it does not revoke another manager or revive a token.
    pub fn revoke(&mut self, key: Capability, subject: BorrowedFd<'_>, now: Instant) -> bool {
        if !self.permits(key, subject, now) {
            return false;
        }
        self.leases.remove(&key).is_some()
    }

    pub fn purge(&mut self, now: Instant) {
        self.leases.retain(|_, lease| {
            now < lease.expires && clipboard_endpoint::owner_pid(lease.owner.as_fd()).is_some()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn process(pid: u32) -> OwnedFd {
        use std::os::fd::FromRawFd;
        // SAFETY: pidfd_open returns an owned fd for a test-owned live process.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
        assert!(fd >= 0, "{}", io::Error::last_os_error());
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    #[test]
    fn known_capability_cannot_be_used_or_revoked_by_a_different_process() {
        let now = Instant::now();
        let mut authority = Authority::default();
        let subject = process(std::process::id());
        let key = authority.issue(process(std::process::id()), now).unwrap();
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let foreign = process(child.id());
        assert!(!authority.permits(key, foreign.as_fd(), now));
        assert!(!authority.revoke(key, foreign.as_fd(), now));
        assert!(authority.permits(key, subject.as_fd(), now));
        assert!(authority.permits(key, subject.as_fd(), now));
        assert!(authority.revoke(key, subject.as_fd(), now));
        assert!(!authority.permits(key, subject.as_fd(), now));
        assert!(!authority.revoke(key, subject.as_fd(), now));
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn owner_death_expiry_and_controller_restart_revoke_authority() {
        let now = Instant::now();
        let mut authority = Authority::default();
        let subject = process(std::process::id());
        let key = authority.issue(process(std::process::id()), now).unwrap();
        assert!(!Authority::default().permits(key, subject.as_fd(), now));
        assert!(!authority.permits(key, subject.as_fd(), now + SELECTION_LIFETIME));
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let dead = process(child.id());
        let key = authority.issue(process(child.id()), now).unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!authority.permits(key, dead.as_fd(), now));
        let not_a_process: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
        assert!(authority.issue(not_a_process, now).is_err());
        assert!(authority.leases.is_empty());
    }
}
