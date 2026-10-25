//! Bounded NFNETLINK_QUEUE codec. No sockets or firewall changes here.
//! The future recvmsg adapter must obtain sender/truncation from the kernel,
//! not from a UI message. Parsing is not itself an authorization boundary.

pub const MAX_DATAGRAM: usize = 256 * 1024;
const MAX_MESSAGES: usize = 256;
const HEADER: usize = 16;
const NFGEN: usize = 4;
const PACKET: u16 = 3 << 8; // NFNL_SUBSYS_QUEUE | NFQNL_MSG_PACKET
const VERDICT: u16 = PACKET | 1;
const CONFIG: u16 = PACKET | 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub(super) queue: u16,
    pub(super) id: u32,
    pub(super) mark: u32,
    pub(super) family: u8,
}

impl Packet {
    pub fn queue(&self) -> u16 {
        self.queue
    }
    pub fn id(&self) -> u32 {
        self.id
    }
    pub fn mark(&self) -> u32 {
        self.mark
    }
    pub fn family(&self) -> u8 {
        self.family
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Message {
    Packet(Packet),
    Ack { sequence: u32, errno: i32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NotKernel,
    Truncated,
    TooLarge,
    Length,
    Overrun,
    Type,
    Family,
    Version,
    Hook,
    Attribute,
    Duplicate,
    MissingHeader,
    BadAck,
}

fn align(n: usize) -> usize {
    (n + 3) & !3
}
fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes(b.try_into().expect("checked four bytes"))
}

/// Atomic parse: no partial list of accepted packets on a malformed tail.
/// `sender_port` must be recvmsg's sockaddr_nl.nl_pid, not nlmsghdr.nlmsg_pid.
pub fn parse(data: &[u8], sender_port: u32, truncated: bool) -> Result<Vec<Message>, Error> {
    if sender_port != 0 {
        return Err(Error::NotKernel);
    }
    if truncated {
        return Err(Error::Truncated);
    }
    if data.len() > MAX_DATAGRAM {
        return Err(Error::TooLarge);
    }
    if data.is_empty() {
        return Err(Error::Length);
    }
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        if rest.len() < HEADER || out.len() >= MAX_MESSAGES {
            return Err(Error::Length);
        }
        let len = u32::from_ne_bytes(rest[..4].try_into().unwrap()) as usize;
        if len < HEADER || len > rest.len() || align(len) > rest.len() {
            return Err(Error::Length);
        }
        let kind = u16::from_ne_bytes(rest[4..6].try_into().unwrap());
        let sequence = u32::from_ne_bytes(rest[8..12].try_into().unwrap());
        // Kernel packet notifications use zero in both port fields. ACK
        // headers may echo the receiving port, so only inspect it for PACKET.
        let body = &rest[HEADER..len];
        match kind {
            PACKET => {
                if rest[12..16] != [0; 4] {
                    return Err(Error::NotKernel);
                }
                out.push(Message::Packet(packet(body)?));
            }
            2 => {
                if body.len() < 20 {
                    return Err(Error::BadAck);
                }
                let errno = i32::from_ne_bytes(body[..4].try_into().unwrap());
                if !(-4095..=0).contains(&errno) {
                    return Err(Error::BadAck);
                }
                out.push(Message::Ack { sequence, errno });
            }
            4 => return Err(Error::Overrun),
            _ => return Err(Error::Type),
        }
        rest = &rest[align(len)..];
    }
    Ok(out)
}

fn packet(body: &[u8]) -> Result<Packet, Error> {
    if body.len() < NFGEN {
        return Err(Error::Length);
    }
    let family = body[0];
    if !matches!(family, 2 | 10) {
        return Err(Error::Family);
    }
    if body[1] != 0 {
        return Err(Error::Version);
    }
    let queue = u16::from_be_bytes(body[2..4].try_into().unwrap());
    let mut attrs = &body[NFGEN..];
    let (mut id, mut mark) = (None, None);
    while !attrs.is_empty() {
        if attrs.len() < 4 {
            return Err(Error::Attribute);
        }
        let len = usize::from(u16::from_ne_bytes(attrs[..2].try_into().unwrap()));
        let raw_kind = u16::from_ne_bytes(attrs[2..4].try_into().unwrap());
        if len < 4 || len > attrs.len() || align(len) > attrs.len() {
            return Err(Error::Attribute);
        }
        let kind = raw_kind & 0x3fff;
        let value = &attrs[4..len];
        match kind {
            1 => {
                if id.is_some() {
                    return Err(Error::Duplicate);
                }
                if value.len() != 7 || raw_kind & 0x8000 != 0 {
                    return Err(Error::Attribute);
                }
                if value[6] != 3 {
                    return Err(Error::Hook);
                } // NF_INET_LOCAL_OUT
                let protocol = u16::from_be_bytes(value[4..6].try_into().unwrap());
                if protocol != if family == 2 { 0x0800 } else { 0x86dd } {
                    return Err(Error::Family);
                }
                id = Some(be32(&value[..4]));
            }
            3 => {
                if mark.is_some() {
                    return Err(Error::Duplicate);
                }
                if value.len() != 4 || raw_kind & 0x8000 != 0 {
                    return Err(Error::Attribute);
                }
                mark = Some(be32(value));
            }
            // Payload and other metadata are deliberately not retained.
            _ => {}
        }
        attrs = &attrs[align(len)..];
    }
    Ok(Packet {
        queue,
        id: id.ok_or(Error::MissingHeader)?,
        mark: mark.unwrap_or(0),
        family,
    })
}

fn attr(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let len = 4 + value.len();
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(value);
    out.resize(align(out.len()), 0);
}

fn request(kind: u16, queue: u16, sequence: u32, attrs: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + NFGEN + attrs.len());
    out.extend_from_slice(&((HEADER + NFGEN + attrs.len()) as u32).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&5u16.to_ne_bytes()); // REQUEST | ACK
    out.extend_from_slice(&sequence.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(&[0, 0]); // AF_UNSPEC, NFNETLINK_V0
    out.extend_from_slice(&queue.to_be_bytes());
    out.extend_from_slice(&attrs);
    out
}

/// Queue bind/configuration with bounded kernel backlog, metadata only,
/// and FAIL_OPEN explicitly cleared. Requires matching ACKs before nft
/// routing/launch activation. Does not perform any system call.
pub fn bind(queue: u16, sequence: u32, max_pending: u32) -> Result<Vec<u8>, Error> {
    if max_pending == 0 || max_pending > 1024 {
        return Err(Error::TooLarge);
    }
    let mut attrs = Vec::new();
    attr(&mut attrs, 1, &[1, 0, 0, 0]); // BIND
    let mut params = 0u32.to_be_bytes().to_vec();
    params.push(1); // COPY_META, no payload collection
    attr(&mut attrs, 2, &params);
    attr(&mut attrs, 3, &max_pending.to_be_bytes());
    attr(&mut attrs, 4, &1u32.to_be_bytes()); // mask FAIL_OPEN
    attr(&mut attrs, 5, &0u32.to_be_bytes()); // no FAIL_OPEN
    Ok(request(CONFIG, queue, sequence, attrs))
}

/// Only individual ACCEPT/DROP verdicts; never batch-approve, repeat the
/// hook, edit payloads, or leave an attribution mark in routing metadata.
pub fn verdict(queue: u16, id: u32, allow: bool, sequence: u32) -> Vec<u8> {
    let mut attrs = Vec::new();
    let mut value = u32::from(allow).to_be_bytes().to_vec();
    value.extend_from_slice(&id.to_be_bytes());
    attr(&mut attrs, 2, &value);
    attr(&mut attrs, 3, &0u32.to_be_bytes()); // clear private attribution mark
    request(VERDICT, queue, sequence, attrs)
}

#[cfg(test)]
pub(super) fn fixture(queue: u16, id: u32, mark: u32) -> Vec<u8> {
    let mut attrs = Vec::new();
    let mut header = id.to_be_bytes().to_vec();
    header.extend_from_slice(&[0x08, 0x00, 3]);
    attr(&mut attrs, 1, &header);
    if mark != 0 {
        attr(&mut attrs, 3, &mark.to_be_bytes());
    }
    let mut out = request(PACKET, queue, 0, attrs);
    out[6..8].fill(0);
    out[16] = 2;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_packet_id_mark_and_queue_have_the_correct_byte_orders() {
        let out = parse(&fixture(0x1234, 0x11223344, 0x55667788), 0, false).unwrap();
        assert_eq!(
            out,
            [Message::Packet(Packet {
                queue: 0x1234,
                id: 0x11223344,
                mark: 0x55667788,
                family: 2
            })]
        );
    }

    #[test]
    fn missing_mark_is_zero_not_an_inferred_program() {
        let out = parse(&fixture(4, 2, 0), 0, false).unwrap();
        let Message::Packet(p) = &out[0] else {
            panic!()
        };
        assert_eq!(p.mark(), 0);
    }

    #[test]
    fn sender_and_truncation_are_checked_before_parsing() {
        let good = fixture(4, 2, 3);
        assert_eq!(parse(&good, 123, false), Err(Error::NotKernel));
        assert_eq!(parse(&good, 0, true), Err(Error::Truncated));
        assert_eq!(
            parse(&vec![0; MAX_DATAGRAM + 1], 0, false),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn malformed_lengths_never_produce_a_partial_packet_list() {
        let good = fixture(4, 2, 3);
        for cut in 0..good.len() {
            assert!(parse(&good[..cut], 0, false).is_err());
        }
        let mut tail = good;
        tail.extend_from_slice(&[1, 2, 3]);
        assert_eq!(parse(&tail, 0, false), Err(Error::Length));
    }

    #[test]
    fn duplicates_bad_hook_and_nested_critical_attributes_are_refused() {
        let mut bad = fixture(4, 2, 3);
        bad[30] = 1;
        assert_eq!(parse(&bad, 0, false), Err(Error::Hook));
        let mut duplicate = fixture(4, 2, 3);
        attr(&mut duplicate, 3, &8u32.to_be_bytes());
        let n = duplicate.len() as u32;
        duplicate[..4].copy_from_slice(&n.to_ne_bytes());
        assert_eq!(parse(&duplicate, 0, false), Err(Error::Duplicate));
        let mut nested = fixture(4, 2, 3);
        nested[22..24].copy_from_slice(&0x8001u16.to_ne_bytes());
        assert_eq!(parse(&nested, 0, false), Err(Error::Attribute));
    }

    #[test]
    fn queue_configuration_is_bounded_and_cannot_request_fail_open() {
        assert!(bind(2, 1, 0).is_err());
        assert!(bind(2, 1, 1025).is_err());
        let request = bind(2, 0x12345678, 1024).unwrap();
        assert_eq!(request[4..6], CONFIG.to_ne_bytes());
        assert_eq!(request[8..12], 0x12345678u32.to_ne_bytes());
        let mut expected = Vec::new();
        attr(&mut expected, 5, &0u32.to_be_bytes());
        assert!(request.ends_with(&expected));
    }

    #[test]
    fn only_individual_verdicts_are_built_and_the_mark_is_cleared() {
        for allow in [false, true] {
            let message = verdict(0x1234, 0x11223344, allow, 7);
            assert_eq!(message[4..6], VERDICT.to_ne_bytes());
            assert_eq!(message[18..20], [0x12, 0x34]);
            assert_eq!(message[24..28], u32::from(allow).to_be_bytes());
            assert_eq!(message[28..32], 0x11223344u32.to_be_bytes());
            assert_eq!(&message[message.len() - 4..], &[0; 4]);
        }
    }

    #[test]
    fn family_version_missing_header_and_overrun_are_failures() {
        let mut bad = fixture(7, 1, 8);
        bad[16] = 10;
        assert_eq!(parse(&bad, 0, false), Err(Error::Family));
        bad[28..30].copy_from_slice(&0x86ddu16.to_be_bytes());
        assert!(parse(&bad, 0, false).is_ok());
        bad[17] = 1;
        assert_eq!(parse(&bad, 0, false), Err(Error::Version));
        let mut missing = fixture(7, 1, 8);
        missing[22..24].copy_from_slice(&100u16.to_ne_bytes());
        assert_eq!(parse(&missing, 0, false), Err(Error::MissingHeader));
        let mut overrun = fixture(7, 1, 8);
        overrun[4..6].copy_from_slice(&4u16.to_ne_bytes());
        assert_eq!(parse(&overrun, 0, false), Err(Error::Overrun));
    }

    #[test]
    fn ack_errors_and_sequence_are_decoded_without_accepting_positive_errno() {
        for errno in [0i32, -1, -95, 1, i32::MIN] {
            let mut msg = vec![0; 40];
            msg[..4].copy_from_slice(&40u32.to_ne_bytes());
            msg[4..6].copy_from_slice(&2u16.to_ne_bytes());
            msg[8..12].copy_from_slice(&123u32.to_ne_bytes());
            msg[16..20].copy_from_slice(&errno.to_ne_bytes());
            if (-4095..=0).contains(&errno) {
                assert_eq!(
                    parse(&msg, 0, false),
                    Ok(vec![Message::Ack {
                        sequence: 123,
                        errno
                    }])
                );
            } else {
                assert_eq!(parse(&msg, 0, false), Err(Error::BadAck));
            }
        }
    }
}
