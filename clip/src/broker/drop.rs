//! Frozen drag-and-drop snapshots, independent of either clipboard selection.
use super::*;
use std::time::{Duration, Instant};

const DROP_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_DRAGS: usize = 64;

struct Drag {
    source: Instance,
}

struct Candidate {
    source: Instance,
    target: Instance,
    revision: Revision,
    target_revision: u64,
    contents: Vec<Content>,
    bytes: usize,
    until: Instant,
    approved: bool,
}

impl Drop for Candidate {
    fn drop(&mut self) {
        for content in &mut self.contents {
            erase(&mut content.data);
        }
    }
}

#[derive(Default)]
pub(super) struct DropState {
    drags: HashMap<u64, Drag>,
    candidates: HashMap<u64, Candidate>,
    bytes: usize,
}

impl DropState {
    fn remove_candidate(&mut self, drag_id: u64) {
        if let Some(candidate) = self.candidates.remove(&drag_id) {
            self.bytes -= candidate.bytes;
        }
    }

    pub(super) fn remove_instance(&mut self, instance: Instance) {
        self.drags.retain(|_, drag| drag.source != instance);
        let stale: Vec<u64> = self
            .candidates
            .iter()
            .filter(|(_, candidate)| candidate.source == instance || candidate.target == instance)
            .map(|(drag_id, _)| *drag_id)
            .collect();
        for drag_id in stale {
            self.remove_candidate(drag_id);
        }
    }
}

impl Broker {
    pub fn next_drop_deadline(&self) -> Option<Instant> {
        self.drops
            .candidates
            .values()
            .map(|candidate| candidate.until)
            .min()
    }

    pub fn expire_drops(&mut self, now: Instant) {
        let expired: Vec<u64> = self
            .drops
            .candidates
            .iter()
            .filter(|(_, candidate)| now >= candidate.until)
            .map(|(drag_id, _)| *drag_id)
            .collect();
        for drag_id in expired {
            self.drops.remove_candidate(drag_id);
            self.drops.drags.remove(&drag_id);
        }
    }

    pub fn begin_drag(&mut self, source: Instance, drag_id: u64) -> Result<(), Error> {
        if drag_id == 0
            || !self.instances.contains_key(&source)
            || self.drops.drags.contains_key(&drag_id)
            || self.drops.candidates.contains_key(&drag_id)
            || self.drops.drags.len() >= MAX_DRAGS
        {
            return Err(Error::StaleOffer);
        }
        self.drops.drags.insert(drag_id, Drag { source });
        Ok(())
    }

    pub fn abort_drag(&mut self, source: Instance, drag_id: u64) {
        if self
            .drops
            .drags
            .get(&drag_id)
            .is_some_and(|drag| drag.source == source)
        {
            self.drops.drags.remove(&drag_id);
            self.drops.remove_candidate(drag_id);
        }
    }

    pub fn finish_drop(
        &mut self,
        target: Instance,
        drag_id: u64,
        target_revision: u64,
        mut contents: Vec<Content>,
        now: Instant,
    ) -> Result<Revision, Error> {
        let revision = self.clipboard_revision(target)?;
        let source = self
            .drops
            .drags
            .get(&drag_id)
            .filter(|_| self.instances.contains_key(&target))
            .map(|drag| drag.source)
            .ok_or(Error::StaleOffer)?;
        if !self.instances.contains_key(&source) || revision != target_revision {
            for content in &mut contents {
                erase(&mut content.data);
            }
            return Err(Error::StaleOffer);
        }
        let result = (|| {
            let mut types = HashSet::new();
            if contents.is_empty() || contents.len() > 64 {
                return Err(Error::InvalidTypes);
            }
            contents.shrink_to_fit();
            let mut bytes = 0usize;
            for content in &contents {
                if content.mime.is_empty()
                    || content.mime.len() > 256
                    || content.mime.chars().any(char::is_control)
                    || content.mime.starts_with("application/x-cellward-clip-")
                    || !types.insert(content.mime.as_str())
                {
                    return Err(Error::InvalidTypes);
                }
                bytes = bytes
                    .checked_add(content.mime.capacity())
                    .and_then(|n| n.checked_add(content.data.capacity()))
                    .ok_or(Error::Limit)?;
            }
            if bytes > self.limits.per_instance
                || bytes > self.limits.total.saturating_sub(self.drops.bytes)
            {
                return Err(Error::Limit);
            }
            Ok(bytes)
        })();
        let bytes = match result {
            Ok(bytes) => bytes,
            Err(error) => {
                for content in &mut contents {
                    erase(&mut content.data);
                }
                return Err(error);
            }
        };
        let drop_revision = match self.serial() {
            Ok(revision) => Revision(revision),
            Err(error) => {
                for content in &mut contents {
                    erase(&mut content.data);
                }
                return Err(error);
            }
        };
        if let Some(old) = self
            .drops
            .candidates
            .iter()
            .find(|(_, candidate)| candidate.target == target)
            .map(|(id, _)| *id)
        {
            self.drops.remove_candidate(old);
            self.drops.drags.remove(&old);
        }
        self.drops.candidates.insert(
            drag_id,
            Candidate {
                source,
                target,
                revision: drop_revision,
                target_revision,
                contents,
                bytes,
                until: now + DROP_TIMEOUT,
                approved: false,
            },
        );
        self.drops.bytes += bytes;
        Ok(drop_revision)
    }

    pub fn prepare_drop(
        &self,
        target: Instance,
        drag_id: u64,
        expected_target_revision: u64,
        now: Instant,
    ) -> Result<PasteDecision, Error> {
        if self.clipboard_revision(target)? != expected_target_revision {
            return Err(Error::StaleOffer);
        }
        let Some(candidate) = self.drops.candidates.get(&drag_id) else {
            if self
                .drops
                .drags
                .get(&drag_id)
                .is_some_and(|drag| self.instances.contains_key(&drag.source))
            {
                return Ok(PasteDecision::Pending(drag_id));
            }
            return Err(Error::StaleOffer);
        };
        if candidate.target != target
            || candidate.target_revision != expected_target_revision
            || candidate.approved
            || now >= candidate.until
            || !self.instances.contains_key(&candidate.source)
            || !self.instances.contains_key(&candidate.target)
        {
            return Err(Error::StaleOffer);
        }
        Ok(PasteDecision::Transfer(super::paste::preview(
            drag_id,
            candidate.source,
            candidate.revision,
            candidate.target_revision,
            &candidate.contents,
        )))
    }

    pub fn commit_drop(
        &mut self,
        target: Instance,
        drag_id: u64,
        drop_revision: Revision,
        expected_target_revision: u64,
        allow_secret: bool,
        now: Instant,
    ) -> Result<Revision, Error> {
        let PasteDecision::Transfer(candidate) =
            self.prepare_drop(target, drag_id, expected_target_revision, now)?
        else {
            return Err(Error::StaleOffer);
        };
        if candidate.epoch != drag_id
            || candidate.revision != drop_revision
            || (candidate.secret && !allow_secret)
        {
            return Err(Error::StaleOffer);
        }
        let stored = self
            .drops
            .candidates
            .get_mut(&drag_id)
            .ok_or(Error::StaleOffer)?;
        stored.approved = true;
        Ok(stored.revision)
    }

    pub fn read_drop(
        &self,
        target: Instance,
        drag_id: u64,
        drop_revision: Revision,
        mime: &str,
        now: Instant,
    ) -> Result<&[u8], Error> {
        if !self.instances.contains_key(&target) {
            return Err(Error::UnknownInstance);
        }
        let candidate = self
            .drops
            .candidates
            .get(&drag_id)
            .filter(|candidate| {
                candidate.target == target
                    && candidate.revision == drop_revision
                    && candidate.approved
                    && now < candidate.until
                    && self.instances.contains_key(&candidate.source)
            })
            .ok_or(Error::StaleOffer)?;
        candidate
            .contents
            .iter()
            .find(|content| content.mime == mime)
            .map(|content| content.data.as_slice())
            .ok_or(Error::InvalidTypes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn content(mime: &str, data: &[u8]) -> Content {
        Content {
            mime: mime.into(),
            data: data.to_vec(),
        }
    }

    fn clipboard_copy(b: &mut Broker, source: Instance, data: &[u8], now: Instant) {
        let epoch = b
            .begin_capture(source, Selection::Clipboard, true, now)
            .unwrap();
        b.finish_capture(
            source,
            Selection::Clipboard,
            epoch,
            vec![content("text/plain", data)],
            now,
        )
        .unwrap();
    }

    #[test]
    fn preview_and_replay_use_the_dragged_snapshot_not_the_latest_copy() {
        let now = Instant::now();
        let mut b = Broker::default();
        let source = b.register().unwrap();
        let target = b.register().unwrap();
        let old = b
            .set(
                target,
                Selection::Clipboard,
                vec![content("text/plain", b"target clipboard")],
            )
            .unwrap();
        clipboard_copy(&mut b, source, b"newer clipboard copy", now);
        b.begin_drag(source, 41).unwrap();
        let dropped = b
            .finish_drop(
                target,
                41,
                old.wire(),
                vec![content("text/plain", b"dragged text")],
                now,
            )
            .unwrap();
        let PasteDecision::Transfer(candidate) =
            b.prepare_drop(target, 41, old.wire(), now).unwrap()
        else {
            panic!()
        };
        assert_eq!(candidate.preview, "dragged text");
        assert_eq!(candidate.epoch, 41);
        assert_eq!(candidate.revision, dropped);
        assert_eq!(
            b.commit_drop(target, 41, dropped, old.wire(), false, now),
            Ok(dropped)
        );
        assert_eq!(
            b.read_drop(target, 41, dropped, "text/plain", now).unwrap(),
            b"dragged text"
        );
        let PasteDecision::Transfer(paste) = b.prepare_paste(target, old.wire(), now).unwrap()
        else {
            panic!()
        };
        assert_eq!(paste.preview, "newer clipboard copy");
        assert_eq!(
            b.types(target, Selection::Clipboard).unwrap().unwrap().0,
            old
        );
        assert!(b.types(target, Selection::Primary).unwrap().is_none());
        assert_eq!(
            b.read(target, Selection::Clipboard, old, "text/plain")
                .unwrap(),
            b"target clipboard"
        );
    }

    #[test]
    fn uri_png_and_arbitrary_binary_formats_survive_frozen_replay() {
        let now = Instant::now();
        let mut b = Broker::default();
        let source = b.register().unwrap();
        let target = b.register().unwrap();
        b.begin_drag(source, 42).unwrap();
        let png = b"\x89PNG\r\n\x1a\n\x00\xffSYNTHETIC";
        let binary = b"\x00\xff\x10\x00binary";
        let uri = b"file:///tmp/synthetic%20file\r\nhttps://example.test/\r\n";
        let dropped = b
            .finish_drop(
                target,
                42,
                0,
                vec![
                    content("text/uri-list", uri),
                    content("image/png", png),
                    content("application/x-synthetic-binary", binary),
                ],
                now,
            )
            .unwrap();
        let PasteDecision::Transfer(candidate) = b.prepare_drop(target, 42, 0, now).unwrap() else {
            panic!()
        };
        assert!(candidate.preview.is_empty());
        assert_eq!(candidate.image.as_deref(), Some(png.as_slice()));
        b.commit_drop(target, 42, dropped, 0, false, now).unwrap();
        for (mime, expected) in [
            ("text/uri-list", uri.as_slice()),
            ("image/png", png.as_slice()),
            ("application/x-synthetic-binary", binary.as_slice()),
        ] {
            assert_eq!(
                b.read_drop(target, 42, dropped, mime, now).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn secret_has_no_preview_and_requires_the_second_consent() {
        let now = Instant::now();
        let mut b = Broker::default();
        let source = b.register().unwrap();
        let target = b.register().unwrap();
        b.begin_drag(source, 43).unwrap();
        let dropped = b
            .finish_drop(
                target,
                43,
                0,
                vec![
                    content("text/plain", b"SYNTHETIC_SECRET"),
                    content("image/png", b"\x89PNG\r\n\x1a\nSYNTHETIC"),
                    content("x-kde-passwordManagerHint", b"secret"),
                ],
                now,
            )
            .unwrap();
        let PasteDecision::Transfer(candidate) = b.prepare_drop(target, 43, 0, now).unwrap() else {
            panic!()
        };
        assert!(candidate.secret);
        assert!(candidate.preview.is_empty());
        assert!(candidate.image.is_none());
        assert_eq!(
            b.commit_drop(target, 43, dropped, 0, false, now),
            Err(Error::StaleOffer)
        );
        b.commit_drop(target, 43, dropped, 0, true, now).unwrap();
        assert_eq!(
            b.read_drop(target, 43, dropped, "x-kde-passwordManagerHint", now)
                .unwrap(),
            b"secret"
        );
    }

    #[test]
    fn stale_revision_target_expiry_and_duplicate_commit_never_fall_back() {
        let now = Instant::now();
        let mut b = Broker::default();
        let source = b.register().unwrap();
        let target = b.register().unwrap();
        let other = b.register().unwrap();
        b.begin_drag(source, 44).unwrap();
        let dropped = b
            .finish_drop(target, 44, 0, vec![content("text/plain", b"frozen")], now)
            .unwrap();
        assert!(matches!(
            b.prepare_drop(other, 44, 0, now),
            Err(Error::StaleOffer)
        ));
        assert_eq!(
            b.commit_drop(
                target,
                44,
                Revision::from_wire(dropped.wire() + 1),
                0,
                false,
                now
            ),
            Err(Error::StaleOffer)
        );
        let changed = b
            .set(
                target,
                Selection::Clipboard,
                vec![content("text/plain", b"changed")],
            )
            .unwrap();
        assert!(matches!(
            b.prepare_drop(target, 44, 0, now),
            Err(Error::StaleOffer)
        ));
        assert!(matches!(
            b.prepare_drop(target, 44, changed.wire(), now + DROP_TIMEOUT),
            Err(Error::StaleOffer)
        ));
        assert_eq!(
            b.commit_drop(
                target,
                44,
                dropped,
                changed.wire(),
                false,
                now + DROP_TIMEOUT
            ),
            Err(Error::StaleOffer)
        );
    }

    #[test]
    fn commit_is_one_shot_and_closed_registrations_revoke_snapshot() {
        for close_source in [false, true] {
            let now = Instant::now();
            let mut b = Broker::default();
            let source = b.register().unwrap();
            let target = b.register().unwrap();
            b.begin_drag(source, 45).unwrap();
            let dropped = b
                .finish_drop(
                    target,
                    45,
                    0,
                    vec![content("application/x-binary", b"\x00\xff")],
                    now,
                )
                .unwrap();
            b.commit_drop(target, 45, dropped, 0, false, now).unwrap();
            assert_eq!(
                b.commit_drop(target, 45, dropped, 0, false, now),
                Err(Error::StaleOffer)
            );
            if close_source {
                b.remove(source).unwrap();
                assert_eq!(
                    b.read_drop(target, 45, dropped, "application/x-binary", now),
                    Err(Error::StaleOffer)
                );
            } else {
                b.remove(target).unwrap();
                assert_eq!(
                    b.read_drop(target, 45, dropped, "application/x-binary", now),
                    Err(Error::UnknownInstance)
                );
            }
        }
    }

    #[test]
    fn failed_or_aborted_capture_has_no_candidate_and_no_clipboard_side_effect() {
        let now = Instant::now();
        let mut b = Broker::default();
        let source = b.register().unwrap();
        let target = b.register().unwrap();
        b.begin_drag(source, 46).unwrap();
        assert!(matches!(
            b.prepare_drop(target, 46, 0, now).unwrap(),
            PasteDecision::Pending(46)
        ));
        assert_eq!(
            b.finish_drop(target, 46, 0, Vec::new(), now),
            Err(Error::InvalidTypes)
        );
        assert!(matches!(
            b.prepare_drop(target, 46, 0, now).unwrap(),
            PasteDecision::Pending(46)
        ));
        b.abort_drag(source, 46);
        assert_eq!(
            b.finish_drop(target, 46, 0, vec![content("text/plain", b"late")], now),
            Err(Error::StaleOffer)
        );
        assert!(b.types(target, Selection::Clipboard).unwrap().is_none());
    }

    #[test]
    fn a_new_drop_to_the_target_revokes_the_previous_pending_result() {
        let now = Instant::now();
        let mut b = Broker::default();
        let source = b.register().unwrap();
        let target = b.register().unwrap();
        b.begin_drag(source, 47).unwrap();
        let first = b
            .finish_drop(target, 47, 0, vec![content("text/plain", b"first")], now)
            .unwrap();
        b.begin_drag(source, 48).unwrap();
        let second = b
            .finish_drop(target, 48, 0, vec![content("text/plain", b"second")], now)
            .unwrap();
        assert!(matches!(
            b.prepare_drop(target, 47, 0, now),
            Err(Error::StaleOffer)
        ));
        assert_eq!(
            b.commit_drop(target, 47, first, 0, false, now),
            Err(Error::StaleOffer)
        );
        b.commit_drop(target, 48, second, 0, false, now).unwrap();
        assert_eq!(
            b.read_drop(target, 48, second, "text/plain", now).unwrap(),
            b"second"
        );
    }
}
