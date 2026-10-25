//! Strict egress-identity foundation, not yet a live firewall backend.
//!
//! A trusted controller must register a launch, install and acknowledge its
//! socket-cgroup -> mark rule, and only then release its child to execute.
//! The OUTPUT chain must clear app-provided marks before classifying. Only
//! kernel NFQUEUE messages on that controller's bound socket may enter here.
//! No identity is inferred from PID, tuple, DNS name or process liveness.
//! The state machine performs no syscalls or policy writes. Its explicit
//! socket adapter is separate and never installs a firewall automatically.

#[path = "netqueue/driver.rs"]
pub mod driver;
#[path = "netqueue/gate.rs"]
pub mod gate;
#[path = "netqueue/socket.rs"]
pub mod socket;
#[path = "netqueue/wire.rs"]
pub mod wire;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub const MAX_LAUNCHES: usize = 4096;
pub const MAX_PENDING: usize = 1024;
pub const MAX_PENDING_PER_LAUNCH: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Token(u32);

impl Token {
    pub fn mark(self) -> u32 {
        self.0
    }
}

/// Trusted, immutable launch record. A generation is not a numeric PID.
#[derive(Debug, PartialEq, Eq)]
pub struct Launch {
    pub program: String,
    pub generation: u128,
    pub epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket {
    session: u128,
    epoch: u64,
    revision: u64,
    packet: u32,
    nonce: u64,
    token: Token,
}

/// Opaque permission scope: neither a tuple nor a numeric process ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Scope {
    session: u128,
    epoch: u64,
    revision: u64,
    token: Token,
}

impl Ticket {
    pub fn packet_id(self) -> u32 {
        self.packet
    }

    pub fn scope(self) -> Scope {
        Scope {
            session: self.session,
            epoch: self.epoch,
            revision: self.revision,
            token: self.token,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Held {
    pub ticket: Ticket,
    pub launch: Arc<Launch>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidIdentity,
    Capacity,
    UnknownToken,
    UnarmedToken,
    ForeignSession,
    WrongQueue,
    OldEpoch,
    StaleTicket,
    InvalidRevision,
    Closed,
    /// Fatal: close the queue socket so the kernel drops its backlog.
    PacketReplayOrWrap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Accept(Ticket),
    Drop(Ticket),
}

/// One queue binding in one instance generation. The controller must mint
/// a fresh nonzero session ID and must never route old replies to its successor.
pub struct Session {
    id: u128,
    queue: u16,
    epoch: u64,
    revision: u64,
    next_token: u64,
    next_nonce: u64,
    last_packet: Option<u32>,
    launches: HashMap<Token, Arc<Launch>>,
    armed: HashSet<Token>,
    pending: HashMap<u32, (Held, Token)>,
    per_launch: HashMap<Token, usize>,
    closed: bool,
}

impl Session {
    pub fn new(id: u128, queue: u16, epoch: u64, revision: u64) -> Result<Self, Error> {
        if id == 0 || epoch == 0 {
            return Err(Error::InvalidIdentity);
        }
        Ok(Self {
            id,
            queue,
            epoch,
            revision,
            next_token: 1,
            next_nonce: 1,
            last_packet: None,
            launches: HashMap::new(),
            armed: HashSet::new(),
            pending: HashMap::new(),
            per_launch: HashMap::new(),
            closed: false,
        })
    }

    /// Does not install a rule or authorize startup. Integration must wait
    /// for the kernel rule ACK and validate generation before releasing exec.
    pub fn register(&mut self, program: String, generation: u128) -> Result<Token, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if generation == 0
            || program.is_empty()
            || program.len() > 255
            || program.starts_with('-')
            || program
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '=' | '/' | '#' | '?'))
        {
            return Err(Error::InvalidIdentity);
        }
        if self.launches.len() >= MAX_LAUNCHES || self.next_token > u64::from(u32::MAX) {
            return Err(Error::Capacity);
        }
        let token = Token(self.next_token as u32);
        self.next_token += 1;
        self.launches.insert(
            token,
            Arc::new(Launch {
                program,
                generation,
                epoch: self.epoch,
            }),
        );
        Ok(token)
    }

    /// Call only after matching the trusted kernel's rule-install ACK for
    /// this session/token, before releasing exec. A merely reserved token
    /// cannot authorize a packet. This method does not manufacture that ACK.
    pub fn activate(&mut self, observed_session: u128, token: Token) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if observed_session != self.id {
            return Err(Error::ForeignSession);
        }
        let launch = self.launches.get(&token).ok_or(Error::UnknownToken)?;
        if launch.epoch != self.epoch {
            return Err(Error::OldEpoch);
        }
        self.armed.insert(token);
        Ok(())
    }

    /// A failed intake never authorizes traffic. For recoverable errors the
    /// adapter must issue DROP for this packet; for replay/wrap/closed state
    /// it must close the queue. No queue-bypass or FAIL_OPEN is permitted.
    pub fn hold(&mut self, observed_session: u128, packet: &wire::Packet) -> Result<Held, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if observed_session != self.id {
            return Err(Error::ForeignSession);
        }
        if packet.queue() != self.queue {
            return Err(Error::WrongQueue);
        }
        // A single bound queue serializes ID allocation and unicast. Stop
        // before wrap rather than allowing old numeric IDs to be reused.
        if self.last_packet.is_some_and(|last| packet.id() <= last) {
            self.fail();
            return Err(Error::PacketReplayOrWrap);
        }
        self.last_packet = Some(packet.id());
        let launch = self
            .launches
            .get(&Token(packet.mark()))
            .ok_or(Error::UnknownToken)?;
        if !self.armed.contains(&Token(packet.mark())) {
            return Err(Error::UnarmedToken);
        }
        if launch.epoch != self.epoch {
            return Err(Error::OldEpoch);
        }
        let token = Token(packet.mark());
        if self.pending.len() >= MAX_PENDING
            || self.per_launch.get(&token).copied().unwrap_or(0) >= MAX_PENDING_PER_LAUNCH
            || self.next_nonce == u64::MAX
        {
            return Err(Error::Capacity);
        }
        let held = Held {
            ticket: Ticket {
                session: self.id,
                epoch: self.epoch,
                revision: self.revision,
                packet: packet.id(),
                nonce: self.next_nonce,
                token,
            },
            launch: Arc::clone(launch),
        };
        self.next_nonce += 1;
        self.pending.insert(packet.id(), (held.clone(), token));
        *self.per_launch.entry(token).or_default() += 1;
        Ok(held)
    }

    /// Preliminary decision only; the runtime adapter must revalidate its
    /// live queue binding and current policy before emitting/ACKing a verdict.
    pub fn decide(&mut self, ticket: Ticket, allow: bool) -> Result<Decision, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        let (pending, token) = self.pending.get(&ticket.packet).ok_or(Error::StaleTicket)?;
        if pending.ticket != ticket
            || ticket.session != self.id
            || ticket.epoch != self.epoch
            || ticket.revision != self.revision
        {
            return Err(Error::StaleTicket);
        }
        let token = *token;
        self.pending.remove(&ticket.packet);
        if let Some(count) = self.per_launch.get_mut(&token) {
            *count -= 1;
            if *count == 0 {
                self.per_launch.remove(&token);
            }
        }
        Ok(if allow {
            Decision::Accept(ticket)
        } else {
            Decision::Drop(ticket)
        })
    }

    /// All held packets must be dropped before applying the new policy.
    pub fn change_policy(&mut self, revision: u64) -> Result<Vec<Ticket>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if revision <= self.revision {
            return Err(Error::InvalidRevision);
        }
        self.revision = revision;
        Ok(self.drain())
    }

    /// Drain before switching routes. Old birth-cgroup tokens stay as
    /// tombstones and cannot authorize old sockets in the new epoch.
    pub fn change_epoch(&mut self, epoch: u64) -> Result<Vec<Ticket>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if epoch <= self.epoch {
            return Err(Error::InvalidRevision);
        }
        self.epoch = epoch;
        Ok(self.drain())
    }

    fn drain(&mut self) -> Vec<Ticket> {
        self.per_launch.clear();
        self.pending
            .drain()
            .map(|(_, (held, _))| held.ticket)
            .collect()
    }

    /// Adapter must close the underlying NFQUEUE socket on loss, malformed
    /// input, failed verdict delivery, invalid ACK or transport failure.
    /// Closing it, not this Rust method alone, drops the kernel backlog.
    pub fn fail(&mut self) {
        self.closed = true;
        self.pending.clear();
        self.per_launch.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(id: u32, token: u32) -> wire::Packet {
        let data = wire::fixture(7, id, token);
        let wire::Message::Packet(p) = wire::parse(&data, 0, false).unwrap().remove(0) else {
            panic!()
        };
        p
    }
    fn session() -> Session {
        Session::new(123, 7, 1, 1).unwrap()
    }

    fn ready(s: &mut Session, name: &str, generation: u128) -> Token {
        let token = s.register(name.into(), generation).unwrap();
        s.activate(123, token).unwrap();
        token
    }

    #[test]
    fn launch_identity_is_retained_without_a_process_or_socket_lookup() {
        let mut s = session();
        let token = ready(&mut s, "helium", 10);
        let held = s.hold(123, &packet(1, token.mark())).unwrap();
        assert_eq!(held.launch.program, "helium");
        assert_eq!(held.launch.generation, 10);
        assert_eq!(
            s.decide(held.ticket, true),
            Ok(Decision::Accept(held.ticket))
        );
        assert_eq!(s.decide(held.ticket, true), Err(Error::StaleTicket));
    }

    #[test]
    fn no_unknown_token_or_zero_mark_can_be_allowed() {
        let mut s = session();
        for (id, mark) in [(1, 0), (2, 88)] {
            assert_eq!(s.hold(123, &packet(id, mark)), Err(Error::UnknownToken));
        }
        assert!(s.pending.is_empty());
    }

    #[test]
    fn repeated_program_names_receive_distinct_nonreused_tokens() {
        let mut s = session();
        let old = ready(&mut s, "firefox", 10);
        let new = ready(&mut s, "firefox", 11);
        assert_ne!(old, new);
        assert_eq!(
            s.hold(123, &packet(1, old.mark()))
                .unwrap()
                .launch
                .generation,
            10
        );
        assert_eq!(
            s.hold(123, &packet(2, new.mark()))
                .unwrap()
                .launch
                .generation,
            11
        );
    }

    #[test]
    fn replay_and_id_wrap_poison_the_session_instead_of_reusing_a_verdict() {
        for (first, next) in [(1, 1), (u32::MAX, 0)] {
            let mut s = session();
            let token = ready(&mut s, "terminal", 10);
            let held = s.hold(123, &packet(first, token.mark())).unwrap();
            assert_eq!(
                s.hold(123, &packet(next, token.mark())),
                Err(Error::PacketReplayOrWrap)
            );
            assert_eq!(s.decide(held.ticket, true), Err(Error::Closed));
            assert_eq!(s.register("other".into(), 11), Err(Error::Closed));
        }
    }

    #[test]
    fn source_session_and_queue_must_match() {
        let mut s = session();
        let token = ready(&mut s, "firefox", 10);
        assert_eq!(
            s.hold(124, &packet(1, token.mark())),
            Err(Error::ForeignSession)
        );
        let mut wrong = packet(1, token.mark());
        wrong.queue = 8;
        assert_eq!(s.hold(123, &wrong), Err(Error::WrongQueue));
        assert!(s.pending.is_empty());
    }

    #[test]
    fn new_policy_invalidates_all_pending_approval_tickets() {
        let mut s = session();
        let token = ready(&mut s, "firefox", 10);
        let held = s.hold(123, &packet(1, token.mark())).unwrap();
        assert_eq!(s.change_policy(2).unwrap(), [held.ticket]);
        assert_eq!(s.decide(held.ticket, true), Err(Error::StaleTicket));
        assert_eq!(s.change_policy(1), Err(Error::InvalidRevision));
    }

    #[test]
    fn network_switch_drops_pending_and_blocks_old_birth_tokens() {
        let mut s = session();
        let old = ready(&mut s, "firefox", 10);
        let held = s.hold(123, &packet(1, old.mark())).unwrap();
        assert_eq!(s.change_epoch(2).unwrap(), [held.ticket]);
        assert_eq!(s.decide(held.ticket, true), Err(Error::StaleTicket));
        assert_eq!(s.hold(123, &packet(2, old.mark())), Err(Error::OldEpoch));
        let new = ready(&mut s, "firefox", 10);
        assert_ne!(new, old);
        assert!(s.hold(123, &packet(3, new.mark())).is_ok());
    }

    #[test]
    fn bounded_registry_and_pending_queue_do_not_evict_identity_or_allow() {
        let mut s = session();
        let first = ready(&mut s, "terminal", 10);
        let mut tokens = vec![first];
        for i in 1..MAX_PENDING / MAX_PENDING_PER_LAUNCH {
            tokens.push(ready(&mut s, "terminal", 10 + i as u128));
        }
        for id in 1..=MAX_PENDING as u32 {
            let token = tokens[(id as usize - 1) / MAX_PENDING_PER_LAUNCH];
            s.hold(123, &packet(id, token.mark())).unwrap();
        }
        assert_eq!(
            s.hold(123, &packet(MAX_PENDING as u32 + 1, first.mark())),
            Err(Error::Capacity)
        );
        assert_eq!(s.pending.len(), MAX_PENDING);
        for id in tokens.len()..MAX_LAUNCHES {
            s.register("terminal".into(), id as u128 + 10).unwrap();
        }
        assert_eq!(s.register("terminal".into(), 9999), Err(Error::Capacity));
        assert_eq!(s.launches[&first].generation, 10);
    }

    #[test]
    fn an_unanswered_launch_cannot_fill_the_whole_queue() {
        let mut s = session();
        let noisy = ready(&mut s, "noisy", 10);
        let quiet = ready(&mut s, "quiet", 11);
        let mut first = None;
        for id in 1..=MAX_PENDING_PER_LAUNCH as u32 {
            let held = s.hold(123, &packet(id, noisy.mark())).unwrap();
            first.get_or_insert(held);
        }
        let next = MAX_PENDING_PER_LAUNCH as u32 + 1;
        assert_eq!(
            s.hold(123, &packet(next, noisy.mark())),
            Err(Error::Capacity)
        );
        assert!(s.hold(123, &packet(next + 1, quiet.mark())).is_ok());
        s.decide(first.unwrap().ticket, false).unwrap();
        assert!(s.hold(123, &packet(next + 2, noisy.mark())).is_ok());
        s.change_policy(2).unwrap();
        assert!(s.per_launch.is_empty());
        assert!(s.hold(123, &packet(next + 3, noisy.mark())).is_ok());
    }

    #[test]
    fn untrusted_program_text_and_missing_generations_are_refused() {
        let mut s = session();
        for name in ["", "browser\nallow", "../firefox", "x=y", "-x"] {
            assert_eq!(s.register(name.into(), 10), Err(Error::InvalidIdentity));
        }
        assert_eq!(s.register("firefox".into(), 0), Err(Error::InvalidIdentity));
        assert!(Session::new(0, 7, 1, 1).is_err());
    }

    #[test]
    fn registration_alone_is_not_permission_to_execute_or_send() {
        let mut s = session();
        let token = s.register("firefox".into(), 10).unwrap();
        assert_eq!(
            s.hold(123, &packet(1, token.mark())),
            Err(Error::UnarmedToken)
        );
        assert_eq!(s.activate(124, token), Err(Error::ForeignSession));
        s.activate(123, token).unwrap();
        assert!(s.hold(123, &packet(2, token.mark())).is_ok());
    }

    #[test]
    fn a_forged_ticket_cannot_consume_or_allow_a_held_packet() {
        let mut s = session();
        let token = ready(&mut s, "firefox", 10);
        let held = s.hold(123, &packet(1, token.mark())).unwrap();
        let wrong = Ticket {
            nonce: held.ticket.nonce + 1,
            ..held.ticket
        };
        assert_eq!(s.decide(wrong, true), Err(Error::StaleTicket));
        assert_eq!(
            s.decide(held.ticket, false),
            Ok(Decision::Drop(held.ticket))
        );
    }

    #[test]
    fn a_new_session_cannot_inherit_old_replies_even_with_same_packet_numbers() {
        let mut old = session();
        let token = ready(&mut old, "firefox", 10);
        let previous = old.hold(123, &packet(1, token.mark())).unwrap();
        let mut new = Session::new(124, 7, 1, 1).unwrap();
        let token = new.register("firefox".into(), 11).unwrap();
        new.activate(124, token).unwrap();
        let current = new.hold(124, &packet(1, token.mark())).unwrap();
        assert_eq!(new.decide(previous.ticket, true), Err(Error::StaleTicket));
        assert_eq!(
            new.decide(current.ticket, false),
            Ok(Decision::Drop(current.ticket))
        );
    }
}
