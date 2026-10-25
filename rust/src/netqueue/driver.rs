//! Fail-closed queue lifetime and ACK handling. This is not launch registration
//! IPC and does not install cgroup rules. A failed driver drops its socket,
//! rather than leaving an apparently closed model with a live kernel queue.
use std::collections::{HashSet, VecDeque};
use std::io;
use std::time::{Duration, Instant};

use super::{socket::Socket, wire, Decision, Held, Session, Ticket, Token, MAX_PENDING};

pub trait Transport {
    fn send(&self, message: &[u8]) -> io::Result<()>;
    fn receive(&self) -> io::Result<Option<Vec<wire::Message>>>;
    fn wait(&self, timeout: Duration) -> io::Result<()>;
}

impl Transport for Socket {
    fn send(&self, message: &[u8]) -> io::Result<()> {
        self.send(message)
    }
    fn receive(&self) -> io::Result<Option<Vec<wire::Message>>> {
        self.receive()
    }
    fn wait(&self, timeout: Duration) -> io::Result<()> {
        self.wait(timeout)
    }
}

pub struct Driver<T: Transport> {
    transport: Option<T>,
    session: Session,
    id: u128,
    queue: u16,
    sequence: u32,
    acknowledgements: HashSet<u32>,
    ready: VecDeque<Held>,
}

impl<T: Transport> Driver<T> {
    pub fn has_ready(&self) -> bool {
        !self.ready.is_empty()
    }
    /// Bind is acknowledged before this constructor succeeds. Ownership of
    /// the socket transfers even on failure, so a half-bound queue is closed.
    pub fn bind(transport: T, id: u128, queue: u16, epoch: u64, revision: u64) -> io::Result<Self> {
        let session = Session::new(id, queue, epoch, revision).map_err(model_error)?;
        let mut driver = Self {
            transport: Some(transport),
            session,
            id,
            queue,
            sequence: 0,
            acknowledgements: HashSet::new(),
            ready: VecDeque::new(),
        };
        let result = (|| {
            let sequence = driver.next_sequence()?;
            let binding = wire::bind_headers(queue, sequence, MAX_PENDING as u32)
                .map_err(|e| io::Error::other(format!("network queue binding: {e:?}")))?;
            driver.send(sequence, &binding)?;
            driver.flush()?;
            Ok(())
        })();
        driver.checked(result)?;
        Ok(driver)
    }

    pub fn register(&mut self, program: String, generation: u128) -> Result<Token, super::Error> {
        self.session.register(program, generation)
    }

    /// Caller must have independently acknowledged the nft mapping for this
    /// exact session/token/cgroup. The queue ACK is NOT proof of that mapping.
    pub fn activate_after_mapping_ack(&mut self, token: Token) -> Result<(), super::Error> {
        self.session.activate(self.id, token)
    }

    /// Bounded nonblocking intake. No application-provided identity is used.
    /// Returned tickets still require a current policy decision.
    pub fn receive(&mut self) -> io::Result<Vec<Held>> {
        let result = (|| {
            for _ in 0..MAX_PENDING {
                let Some(messages) = self.socket()?.receive()? else {
                    break;
                };
                self.messages(messages)?;
            }
            self.flush()?;
            Ok(self.ready.drain(..).collect())
        })();
        self.checked(result)
    }

    pub fn wait(&mut self, timeout: Duration) -> io::Result<()> {
        let result = self.socket()?.wait(timeout);
        // An ordinary caller poll timeout is not transport loss.
        if result
            .as_ref()
            .is_err_and(|e| e.kind() == io::ErrorKind::TimedOut)
        {
            return result;
        }
        self.checked(result)
    }

    pub fn decide(&mut self, ticket: Ticket, allow: bool) -> io::Result<()> {
        // Stale UI callbacks must not close a healthy successor session.
        let decision = self.session.decide(ticket, allow).map_err(model_error)?;
        self.ready.retain(|held| held.ticket != ticket);
        let result = (|| {
            self.verdict(ticket.packet_id(), matches!(decision, Decision::Accept(_)))?;
            self.flush()
        })();
        self.checked(result)
    }

    /// Call before changing the external firewall. No previous ticket remains
    /// usable, and all previously held packets are acknowledged DROP first.
    pub fn change_policy(&mut self, revision: u64) -> io::Result<()> {
        let tickets = self.session.change_policy(revision).map_err(model_error)?;
        self.drop_tickets(tickets)
    }

    /// Call with egress fenced before changing routes or releasing launches.
    pub fn change_epoch(&mut self, epoch: u64) -> io::Result<()> {
        let tickets = self.session.change_epoch(epoch).map_err(model_error)?;
        self.drop_tickets(tickets)
    }

    fn drop_tickets(&mut self, tickets: Vec<Ticket>) -> io::Result<()> {
        self.ready.clear();
        let result = (|| {
            for ticket in tickets {
                self.verdict(ticket.packet_id(), false)?;
            }
            self.flush()
        })();
        self.checked(result)
    }

    pub fn close(&mut self) {
        self.session.fail();
        self.ready.clear();
        self.acknowledgements.clear();
        drop(self.transport.take());
    }

    fn checked<R>(&mut self, result: io::Result<R>) -> io::Result<R> {
        if result.is_err() {
            self.close();
        }
        result
    }

    fn socket(&self) -> io::Result<&T> {
        self.transport
            .as_ref()
            .ok_or_else(|| io::Error::other("network ownership queue closed"))
    }

    fn next_sequence(&mut self) -> io::Result<u32> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("network queue sequence exhausted"))?;
        Ok(self.sequence)
    }

    fn send(&mut self, sequence: u32, message: &[u8]) -> io::Result<()> {
        if self.acknowledgements.len() >= MAX_PENDING {
            return Err(io::Error::other("network queue ACK capacity"));
        }
        self.socket()?.send(message)?;
        self.acknowledgements.insert(sequence);
        Ok(())
    }

    fn verdict(&mut self, packet: u32, allow: bool) -> io::Result<()> {
        let sequence = self.next_sequence()?;
        self.send(
            sequence,
            &wire::verdict(self.queue, packet, allow, sequence),
        )
    }

    fn messages(&mut self, messages: Vec<wire::Message>) -> io::Result<()> {
        for message in messages {
            match message {
                wire::Message::Ack { sequence, errno } => {
                    if !self.acknowledgements.remove(&sequence) {
                        return Err(io::Error::other("unexpected network queue ACK"));
                    }
                    if errno != 0 {
                        return Err(io::Error::from_raw_os_error(-errno));
                    }
                }
                wire::Message::Packet(packet) => match self.session.hold(self.id, &packet) {
                    Ok(held) => self.ready.push_back(held),
                    Err(
                        super::Error::UnknownToken
                        | super::Error::UnarmedToken
                        | super::Error::OldEpoch
                        | super::Error::Capacity,
                    ) => {
                        self.verdict(packet.id(), false)?;
                    }
                    Err(error) => return Err(model_error(error)),
                },
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !self.acknowledgements.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "network queue ACK timeout",
                ));
            }
            self.socket()?.wait(remaining)?;
            if let Some(messages) = self.socket()?.receive()? {
                self.messages(messages)?;
            }
        }
        Ok(())
    }
}

impl Driver<Socket> {
    pub fn fd(&self) -> Option<std::os::fd::RawFd> {
        self.transport.as_ref().map(Socket::fd)
    }
}

fn model_error(error: super::Error) -> io::Error {
    io::Error::other(format!("network ownership: {error:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    #[derive(Default)]
    struct State {
        incoming: RefCell<VecDeque<Vec<wire::Message>>>,
        sent: RefCell<Vec<Vec<u8>>>,
        closed: Cell<bool>,
        auto_ack: Cell<bool>,
    }
    struct Fake(Rc<State>);
    impl Drop for Fake {
        fn drop(&mut self) {
            self.0.closed.set(true);
        }
    }
    impl Transport for Fake {
        fn send(&self, data: &[u8]) -> io::Result<()> {
            self.0.sent.borrow_mut().push(data.to_vec());
            if self.0.auto_ack.get() {
                let sequence = u32::from_ne_bytes(data[8..12].try_into().unwrap());
                self.0
                    .incoming
                    .borrow_mut()
                    .push_back(vec![wire::Message::Ack { sequence, errno: 0 }]);
            }
            Ok(())
        }
        fn receive(&self) -> io::Result<Option<Vec<wire::Message>>> {
            Ok(self.0.incoming.borrow_mut().pop_front())
        }
        fn wait(&self, _: Duration) -> io::Result<()> {
            if self.0.incoming.borrow().is_empty() {
                Err(io::Error::new(io::ErrorKind::TimedOut, "fake timeout"))
            } else {
                Ok(())
            }
        }
    }
    fn driver() -> (Driver<Fake>, Rc<State>, Token) {
        let state = Rc::new(State::default());
        state.auto_ack.set(true);
        let mut driver = Driver::bind(Fake(state.clone()), 123, 7, 1, 1).unwrap();
        let token = driver.register("helium".into(), 55).unwrap();
        driver.activate_after_mapping_ack(token).unwrap();
        (driver, state, token)
    }
    fn packet(state: &State, id: u32, token: u32) {
        state
            .incoming
            .borrow_mut()
            .push_back(wire::parse(&wire::fixture(7, id, token), 0, false).unwrap());
    }
    #[test]
    fn binding_timeout_destroys_transport() {
        let state = Rc::new(State::default());
        assert!(Driver::bind(Fake(state.clone()), 123, 7, 1, 1).is_err());
        assert!(state.closed.get());
    }
    #[test]
    fn unknown_identity_is_dropped_without_a_question() {
        let (mut driver, state, _) = driver();
        packet(&state, 1, 999);
        assert!(driver.receive().unwrap().is_empty());
        assert_eq!(state.sent.borrow().len(), 2);
        assert!(!state.closed.get());
    }
    #[test]
    fn verdict_ack_failure_closes_actual_transport() {
        let (mut driver, state, token) = driver();
        packet(&state, 1, token.mark());
        let held = driver.receive().unwrap().remove(0);
        state.auto_ack.set(false);
        assert!(driver.decide(held.ticket, true).is_err());
        assert!(state.closed.get());
        assert_eq!(
            driver.register("x".into(), 2),
            Err(super::super::Error::Closed)
        );
    }
    #[test]
    fn unsolicited_ack_is_fatal() {
        let (mut driver, state, _) = driver();
        state
            .incoming
            .borrow_mut()
            .push_back(vec![wire::Message::Ack {
                sequence: 999,
                errno: 0,
            }]);
        assert!(driver.receive().is_err());
        assert!(state.closed.get());
    }
    #[test]
    fn policy_change_invalidates_ui_ticket_without_killing_new_session() {
        let (mut driver, state, token) = driver();
        packet(&state, 1, token.mark());
        let old = driver.receive().unwrap().remove(0);
        driver.change_policy(2).unwrap();
        assert!(driver.decide(old.ticket, true).is_err());
        assert!(!state.closed.get());
        packet(&state, 2, token.mark());
        let new = driver.receive().unwrap().remove(0);
        driver.decide(new.ticket, true).unwrap();
    }
    #[test]
    fn packets_arriving_before_verdict_ack_are_not_lost() {
        let (mut driver, state, token) = driver();
        packet(&state, 1, token.mark());
        let first = driver.receive().unwrap().remove(0);
        packet(&state, 2, token.mark());
        driver.decide(first.ticket, true).unwrap();
        let second = driver.receive().unwrap().remove(0);
        assert_eq!(second.ticket.packet_id(), 2);
        driver.decide(second.ticket, false).unwrap();
    }
    #[test]
    fn duplicate_packet_closes_queue_instead_of_reusing_identity() {
        let (mut driver, state, token) = driver();
        packet(&state, 1, token.mark());
        packet(&state, 1, token.mark());
        assert!(driver.receive().is_err());
        assert!(state.closed.get());
    }
}
