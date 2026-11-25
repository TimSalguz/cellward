//! A small positive DNS cache for one forwarder.
//!
//! Entries are keyed by the complete question and the ordered resolver list.
//! There are no background queries and no answers from another route's
//! resolvers. A cached packet gets the current query's ID and every ordinary
//! resource record's TTL is capped by the time left in the cache entry.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_ENTRIES: usize = 256;
const OPT: u16 = 41;

#[derive(Clone, Hash, PartialEq, Eq)]
struct Key {
    resolvers: Vec<SocketAddr>,
    question: Vec<u8>,
}

impl Key {
    fn new(query: &[u8], resolvers: &[SocketAddr]) -> Option<Self> {
        (query.len() >= 2).then(|| Self {
            resolvers: resolvers.to_vec(),
            question: query[2..].to_vec(),
        })
    }
}

struct Entry {
    response: Vec<u8>,
    expires: Instant,
    ttls: Vec<(usize, u32)>,
}

#[derive(Default)]
pub struct Cache {
    entries: Mutex<HashMap<Key, Entry>>,
}

impl Cache {
    pub fn get(&self, query: &[u8], resolvers: &[SocketAddr]) -> Option<Vec<u8>> {
        let key = Key::new(query, resolvers)?;
        let mut entries = self.entries.lock().ok()?;
        let now = Instant::now();
        if entries.get(&key).is_some_and(|entry| entry.expires <= now) {
            entries.remove(&key);
            return None;
        }
        let entry = entries.get(&key)?;
        let left = entry
            .expires
            .saturating_duration_since(now)
            .as_secs()
            .min(u64::from(u32::MAX)) as u32;
        let mut response = entry.response.clone();
        response[..2].copy_from_slice(&query[..2]);
        for &(offset, original) in &entry.ttls {
            response[offset..offset + 4].copy_from_slice(&original.min(left).to_be_bytes());
        }
        Some(response)
    }

    pub fn put(&self, query: &[u8], resolvers: &[SocketAddr], response: &[u8]) {
        let Some(key) = Key::new(query, resolvers) else {
            return;
        };
        let Some((lifetime, ttls)) = cacheable(query, response) else {
            return;
        };
        let now = Instant::now();
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        entries.retain(|_, entry| entry.expires > now);
        if entries.len() >= MAX_ENTRIES && !entries.contains_key(&key) {
            let oldest = entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                entries.remove(&oldest);
            }
        }
        entries.insert(
            key,
            Entry {
                response: response.to_vec(),
                expires: now + lifetime,
                ttls,
            },
        );
    }
}

fn number(message: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        message.get(at..at + 2)?.try_into().ok()?,
    ))
}

fn name_end(message: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *message.get(at)?;
        if len & 0xc0 == 0xc0 {
            message.get(at + 1)?;
            return Some(at + 2);
        }
        if len & 0xc0 != 0 || len > 63 {
            return None;
        }
        at += 1;
        if len == 0 {
            return Some(at);
        }
        at = at.checked_add(usize::from(len))?;
        if at > message.len() {
            return None;
        }
    }
}

fn question_end(message: &[u8]) -> Option<usize> {
    if message.len() < 12 || number(message, 4)? != 1 {
        return None;
    }
    let end = name_end(message, 12)?.checked_add(4)?;
    (end <= message.len()).then_some(end)
}

fn cacheable(query: &[u8], response: &[u8]) -> Option<(Duration, Vec<(usize, u32)>)> {
    if response.len() < 12
        || response[2] & 0x80 == 0
        || (response[2] >> 3) & 0x0f != 0
        || response[2] & 0x02 != 0
        || response[3] & 0x0f != 0
        || number(response, 6)? == 0
    {
        return None;
    }
    let query_end = question_end(query)?;
    let response_question_end = question_end(response)?;
    if query.get(12..query_end)? != response.get(12..response_question_end)? {
        return None;
    }
    let records = number(response, 6)? as usize
        + number(response, 8)? as usize
        + number(response, 10)? as usize;
    let mut at = response_question_end;
    let mut shortest = u32::MAX;
    let mut ttls = Vec::new();
    for _ in 0..records {
        at = name_end(response, at)?;
        let kind = number(response, at)?;
        let ttl_at = at.checked_add(4)?;
        let ttl = u32::from_be_bytes(response.get(ttl_at..ttl_at + 4)?.try_into().ok()?);
        let data_len = usize::from(number(response, at + 8)?);
        at = at.checked_add(10)?.checked_add(data_len)?;
        if at > response.len() {
            return None;
        }
        if kind != OPT {
            shortest = shortest.min(ttl);
            ttls.push((ttl_at, ttl));
        }
    }
    if shortest == 0 || shortest == u32::MAX {
        return None;
    }
    Some((Duration::from_secs(u64::from(shortest)), ttls))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn question(id: u16) -> Vec<u8> {
        let mut message = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        message[..2].copy_from_slice(&id.to_be_bytes());
        message.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        message
    }

    fn response(query: &[u8], ttl: u32) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2] = 0x81;
        response[3] = 0x80;
        response[7] = 1;
        response.extend_from_slice(b"\xc0\x0c\x00\x01\x00\x01");
        response.extend_from_slice(&ttl.to_be_bytes());
        response.extend_from_slice(b"\x00\x04");
        response.extend_from_slice(&[192, 0, 2, 1]);
        response
    }

    fn resolver(last: u8) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, last], 53))
    }

    #[test]
    fn hits_have_the_current_id_and_only_the_time_left_as_ttl() {
        let cache = Cache::default();
        let query = question(0x1234);
        let resolvers = [resolver(1)];
        cache.put(&query, &resolvers, &response(&query, 30));
        let other = question(0xabcd);
        let key = Key::new(&query, &resolvers).unwrap();
        cache.entries.lock().unwrap().get_mut(&key).unwrap().expires =
            Instant::now() + Duration::from_secs(7);
        let hit = cache.get(&other, &resolvers).unwrap();
        assert_eq!(&hit[..2], &0xabcd_u16.to_be_bytes());
        let left = u32::from_be_bytes(hit[hit.len() - 10..hit.len() - 6].try_into().unwrap());
        assert!((6..=7).contains(&left), "TTL was not reduced: {left}");
        cache.entries.lock().unwrap().get_mut(&key).unwrap().expires =
            Instant::now() - Duration::from_secs(1);
        assert!(cache.get(&other, &resolvers).is_none());
    }

    #[test]
    fn another_route_or_question_cannot_reuse_an_answer() {
        let cache = Cache::default();
        let query = question(1);
        cache.put(&query, &[resolver(1)], &response(&query, 30));
        assert!(cache.get(&query, &[resolver(2)]).is_none());
        assert!(cache.get(&query, &[resolver(1), resolver(2)]).is_none());
        let mut wrong = response(&query, 30);
        wrong[12] = 3;
        cache.put(&query, &[resolver(1)], &wrong);
        let mut nxdomain = response(&query, 30);
        nxdomain[3] = 3;
        cache.put(&query, &[resolver(1)], &nxdomain);
        let mut truncated = response(&query, 30);
        truncated[2] |= 2;
        cache.put(&query, &[resolver(1)], &truncated);
        for end in 0..response(&query, 30).len() {
            cache.put(&query, &[resolver(1)], &response(&query, 30)[..end]);
        }
    }
}
