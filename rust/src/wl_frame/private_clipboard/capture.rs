//! Bounded, best-effort capture of one selection, independent of Wayland objects.
//! Only EOF completes a format. A stalled or oversized format never publishes
//! its prefix and never discards other completed formats.
use crate::clipboard_client::{erase_slice, Bytes};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::rc::Rc;
use std::time::{Duration, Instant};

const TOTAL_TIMEOUT: Duration = Duration::from_secs(3);
const IDLE_TIMEOUT: Duration = Duration::from_secs(1);
// History treats the presence of these types as policy, independently of
// their payload. Losing a hint with a failed format must not record a secret
// or re-record a restored history entry (clip/src/private_history.rs).
const HISTORY_HINTS: [&str; 2] = [
    "x-kde-passwordManagerHint",
    "application/x-cellward-restored",
];

pub(super) struct Payload {
    pub mime: String,
    pub bytes: Bytes,
}

impl Payload {
    pub fn allocated(&self) -> usize {
        self.mime.capacity() + self.bytes.allocated()
    }
}

struct Pending {
    file: File,
    payload: Payload,
    idle: Instant,
}

pub(super) struct CaptureData {
    types: VecDeque<String>,
    pub contents: Vec<Payload>,
    hints: Vec<String>,
    pipe: Option<Pending>,
    deadline: Instant,
    failures: usize,
}

// Read portable payloads before legacy aliases such as TEXT. Firefox/GTK can
// advertise aliases it cannot deliver; their order must not starve plain text.
fn priority(mime: &str) -> u8 {
    match mime {
        "text/plain;charset=utf-8" => 0,
        "text/plain" => 1,
        "image/png" => 2,
        "text/uri-list" => 3,
        "text/html" => 4,
        "UTF8_STRING" => 5,
        "TEXT" | "STRING" => 7,
        _ => 6,
    }
}

impl CaptureData {
    pub fn new(mut types: Vec<String>, now: Instant) -> Self {
        let mut failures = 0;
        // The source handler already bounds length/count and removes private
        // marks. A control character is also forbidden by the broker wire;
        // do not let one malformed format poison otherwise usable payloads.
        types.retain(|mime| {
            let valid = !mime.chars().any(char::is_control);
            failures += usize::from(!valid);
            valid
        });
        types.sort_by_key(|t| priority(t));
        let hints = types
            .iter()
            .filter(|t| HISTORY_HINTS.contains(&t.as_str()))
            .cloned()
            .collect();
        Self {
            types: types.into(),
            contents: Vec::new(),
            hints,
            pipe: None,
            deadline: now + TOTAL_TIMEOUT,
            failures,
        }
    }

    pub fn fd(&self) -> Option<RawFd> {
        self.pipe.as_ref().map(|p| p.file.as_raw_fd())
    }

    pub fn wake_at(&self) -> Instant {
        self.pipe
            .as_ref()
            .map_or(self.deadline, |p| p.idle.min(self.deadline))
    }

    pub fn allocated(&self) -> usize {
        self.contents.iter().map(Payload::allocated).sum::<usize>()
            + self.pipe.as_ref().map_or(0, |p| p.payload.allocated())
            + self.hints.iter().map(String::capacity).sum::<usize>()
    }

    pub fn failures(&self) -> usize {
        self.failures
    }

    fn finish(&mut self) -> bool {
        self.failures += self.types.len() + usize::from(self.pipe.is_some());
        self.types.clear();
        self.pipe = None;
        // Retain policy even if the source disappeared before delivering its
        // hint. Do not invent text/image contents or turn a failed copy into
        // an empty selection replacing the previous working clipboard.
        if !self.contents.is_empty() {
            for mime in self.hints.drain(..) {
                if !self.contents.iter().any(|p| p.mime == mime) {
                    self.contents.push(Payload {
                        mime,
                        bytes: Bytes::default(),
                    });
                }
            }
        }
        true
    }

    pub fn tick(
        &mut self,
        now: Instant,
        alive: bool,
        budget: &mut usize,
        limit: usize,
        mut send: impl FnMut(&str, &Rc<OwnedFd>),
    ) -> bool {
        if now >= self.deadline || !alive {
            return self.finish();
        }
        while *budget > 0 {
            if self.pipe.is_none() {
                let Some(mime) = self.types.pop_front() else {
                    return self.finish();
                };
                if self.allocated().saturating_add(mime.capacity()) > limit {
                    self.failures += 1;
                    continue;
                }
                let pipes = crate::sys::pipe().and_then(|(read, write)| {
                    crate::sys::set_nonblocking(read.as_raw_fd())?;
                    Ok((read, write))
                });
                let Ok((read, write)) = pipes else {
                    self.failures += 1;
                    continue;
                };
                send(&mime, &Rc::new(write));
                self.pipe = Some(Pending {
                    file: File::from(read),
                    payload: Payload {
                        mime,
                        bytes: Bytes::default(),
                    },
                    idle: now + IDLE_TIMEOUT,
                });
            }
            let remaining = limit.saturating_sub(
                self.contents.iter().map(Payload::allocated).sum::<usize>()
                    + self.hints.iter().map(String::capacity).sum::<usize>()
                    + self.pipe.as_ref().unwrap().payload.mime.capacity(),
            );
            let pending = self.pipe.as_mut().unwrap();
            let mut buffer = [0; 8192];
            let n = match pending.file.read(&mut buffer[..(*budget).min(8192)]) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // A busy event loop may run after the idle deadline even
                    // though data is already queued. Drain available bytes
                    // before deciding the producer stopped making progress.
                    if now >= pending.idle {
                        self.pipe = None;
                        self.failures += 1;
                        continue;
                    }
                    return false;
                }
                // Let the event loop retry without spinning on signals.
                Err(e) if e.kind() == io::ErrorKind::Interrupted => return false,
                Err(_) => {
                    self.pipe = None;
                    self.failures += 1;
                    continue;
                }
            };
            if n == 0 {
                self.contents.push(self.pipe.take().unwrap().payload);
                continue;
            }
            *budget -= n;
            let result = pending.payload.bytes.append(&buffer[..n], remaining);
            erase_slice(&mut buffer);
            if result.is_err() {
                self.pipe = None;
                self.failures += 1;
            } else {
                pending.idle = now + IDLE_TIMEOUT;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const LIMIT: usize = 1 << 20;
    fn capture(types: &[&str], now: Instant) -> CaptureData {
        CaptureData::new(types.iter().map(|t| (*t).to_owned()).collect(), now)
    }
    fn write(fd: &Rc<OwnedFd>, bytes: &[u8]) {
        File::from(fd.try_clone().unwrap())
            .write_all(bytes)
            .unwrap();
    }
    fn payload(c: &CaptureData, mime: &str) -> Option<Vec<u8>> {
        c.contents
            .iter()
            .find(|p| p.mime == mime)
            .map(|p| p.bytes.as_slice().to_vec())
    }

    #[test]
    fn stalled_alias_keeps_text_and_next_format_and_never_publishes_its_prefix() {
        let now = Instant::now();
        let mut c = capture(&["TEXT", "application/x-later", "text/plain"], now);
        let mut held = None;
        assert!(!c.tick(now, true, &mut { LIMIT }, LIMIT, |mime, fd| {
            match mime {
                "text/plain" => write(fd, b"complete text"),
                "application/x-later" => {
                    write(fd, b"incomplete");
                    held = Some(fd.try_clone().unwrap());
                }
                _ => panic!("alias must wait for the previous format"),
            }
        }));
        assert_eq!(payload(&c, "text/plain"), Some(b"complete text".to_vec()));
        assert_eq!(c.wake_at(), now + IDLE_TIMEOUT);
        assert!(c.tick(
            now + IDLE_TIMEOUT,
            true,
            &mut { LIMIT },
            LIMIT,
            |mime, fd| {
                assert_eq!(mime, "TEXT");
                write(fd, b"legacy text");
            }
        ));
        assert_eq!(payload(&c, "application/x-later"), None);
        assert_eq!(payload(&c, "TEXT"), Some(b"legacy text".to_vec()));
        assert_eq!(c.failures(), 1);
        drop(held);
    }

    #[test]
    fn stalled_preferred_text_does_not_prevent_plain_text_fallback() {
        let now = Instant::now();
        let mut c = capture(&["text/plain", "text/plain;charset=utf-8"], now);
        let mut held = None;
        assert!(!c.tick(now, true, &mut { LIMIT }, LIMIT, |_, fd| held =
            Some(fd.try_clone().unwrap())));
        assert!(c.tick(
            now + IDLE_TIMEOUT,
            true,
            &mut { LIMIT },
            LIMIT,
            |mime, fd| {
                assert_eq!(mime, "text/plain");
                write(fd, b"fallback");
            }
        ));
        assert_eq!(payload(&c, "text/plain"), Some(b"fallback".to_vec()));
        assert_eq!(payload(&c, "text/plain;charset=utf-8"), None);
        drop(held);
    }

    #[test]
    fn total_timeout_and_source_exit_keep_completed_formats_and_policy_hints() {
        for alive in [false, true] {
            let now = Instant::now();
            let mut c = capture(&["text/plain", HISTORY_HINTS[0], HISTORY_HINTS[1]], now);
            let mut held = None;
            assert!(!c.tick(now, true, &mut { LIMIT }, LIMIT, |mime, fd| {
                if mime == "text/plain" {
                    write(fd, b"synthetic secret");
                } else {
                    held = Some(fd.try_clone().unwrap());
                }
            }));
            assert!(c.tick(
                if alive { now + TOTAL_TIMEOUT } else { now },
                alive,
                &mut { LIMIT },
                LIMIT,
                |_, _| panic!("source must not be read")
            ));
            assert_eq!(
                payload(&c, "text/plain"),
                Some(b"synthetic secret".to_vec())
            );
            for hint in HISTORY_HINTS {
                assert_eq!(payload(&c, hint), Some(Vec::new()));
            }
            assert_eq!(c.failures(), 2);
            assert!(c.fd().is_none());
            drop(held);
        }
    }

    #[test]
    fn completely_failed_capture_does_not_replace_previous_selection() {
        let now = Instant::now();
        let mut c = capture(&["TEXT"], now);
        let mut held = None;
        assert!(!c.tick(now, true, &mut { LIMIT }, LIMIT, |_, fd| {
            write(fd, b"partial");
            held = Some(fd.try_clone().unwrap());
        }));
        assert!(c.tick(
            now + TOTAL_TIMEOUT,
            true,
            &mut { LIMIT },
            LIMIT,
            |_, _| unreachable!()
        ));
        assert!(c.contents.is_empty());
        assert_eq!(c.allocated(), 0);
        drop(held);
    }

    #[test]
    fn oversized_format_does_not_discard_text_or_prevent_later_formats() {
        let now = Instant::now();
        let mut c = capture(&["text/plain", "image/png", "text/html"], now);
        assert!(c.tick(now, true, &mut { LIMIT }, 128, |mime, fd| {
            write(
                fd,
                match mime {
                    "text/plain" => b"plain",
                    "image/png" => &[42; 256],
                    _ => b"<b>plain</b>",
                },
            );
        }));
        assert_eq!(payload(&c, "text/plain"), Some(b"plain".to_vec()));
        assert_eq!(payload(&c, "text/html"), Some(b"<b>plain</b>".to_vec()));
        assert_eq!(payload(&c, "image/png"), None);
        assert_eq!(c.failures(), 1);
        assert!(c.allocated() <= 128);
    }

    #[test]
    fn empty_binary_and_non_text_formats_are_preserved_without_conversion() {
        let now = Instant::now();
        let mut c = capture(&["application/x-binary", "text/plain"], now);
        assert!(c.tick(now, true, &mut { LIMIT }, LIMIT, |mime, fd| {
            write(
                fd,
                if mime == "text/plain" {
                    b""
                } else {
                    b"\0\xff\r\n"
                },
            );
        }));
        assert_eq!(payload(&c, "text/plain"), Some(Vec::new()));
        assert_eq!(
            payload(&c, "application/x-binary"),
            Some(b"\0\xff\r\n".to_vec())
        );
        assert_eq!(c.failures(), 0);
    }

    #[test]
    fn invalid_mime_does_not_poison_a_valid_copy() {
        let now = Instant::now();
        let mut c = capture(&["text/plain", "application/x-invalid\n"], now);
        assert!(c.tick(now, true, &mut { LIMIT }, LIMIT, |mime, fd| {
            assert_eq!(mime, "text/plain");
            write(fd, b"valid text");
        }));
        assert_eq!(payload(&c, "text/plain"), Some(b"valid text".to_vec()));
        assert_eq!(c.failures(), 1);
    }

    #[test]
    fn read_quantum_yields_and_progress_extends_only_idle_deadline() {
        let now = Instant::now();
        let mut c = capture(&["text/plain"], now);
        let mut held = None;
        assert!(!c.tick(now, true, &mut 2, LIMIT, |_, fd| {
            write(fd, b"four");
            held = Some(fd.try_clone().unwrap());
        }));
        assert!(c.contents.is_empty());
        assert_eq!(c.pipe.as_ref().unwrap().payload.bytes.allocated(), 2);
        assert!(!c.tick(
            now + Duration::from_millis(500),
            true,
            &mut 2,
            LIMIT,
            |_, _| unreachable!()
        ));
        assert_eq!(c.wake_at(), now + Duration::from_millis(1500));
        drop(held);
        assert!(c.tick(
            now + Duration::from_millis(600),
            true,
            &mut { LIMIT },
            LIMIT,
            |_, _| unreachable!()
        ));
        assert_eq!(payload(&c, "text/plain"), Some(b"four".to_vec()));
    }

    #[test]
    fn delayed_event_loop_drains_ready_data_before_declaring_idle() {
        let now = Instant::now();
        let mut c = capture(&["text/plain"], now);
        let mut held = None;
        assert!(!c.tick(now, true, &mut { LIMIT }, LIMIT, |_, fd| held =
            Some(fd.try_clone().unwrap())));
        let fd = Rc::new(held.take().unwrap());
        write(&fd, b"queued before the event loop resumed");
        drop(fd);
        assert!(c.tick(
            now + IDLE_TIMEOUT,
            true,
            &mut { LIMIT },
            LIMIT,
            |_, _| unreachable!()
        ));
        assert_eq!(
            payload(&c, "text/plain"),
            Some(b"queued before the event loop resumed".to_vec())
        );
        assert_eq!(c.failures(), 0);
    }

    #[test]
    fn total_deadline_bounds_a_producer_that_keeps_streaming() {
        let now = Instant::now();
        let mut c = capture(&["text/plain"], now);
        let mut held = None;
        assert!(!c.tick(now, true, &mut 1, LIMIT, |_, fd| {
            write(fd, b"never complete");
            held = Some(fd.try_clone().unwrap());
        }));
        assert!(c.tick(
            now + TOTAL_TIMEOUT,
            true,
            &mut { LIMIT },
            LIMIT,
            |_, _| unreachable!()
        ));
        assert!(c.contents.is_empty());
        assert_eq!(c.allocated(), 0);
        drop(held);
    }
}
