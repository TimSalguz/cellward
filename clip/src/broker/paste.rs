//! Explicit keyboard transfers, separate from the immutable-scope data wire.
//! A copy is announced before reading its payload: a fast paste must wait for
//! that copy instead of silently inserting the previous completed selection.
use super::*;
use std::time::{Duration, Instant};

// Allow the bounded three-second source capture and five-second data-wire
// transaction to finish before treating an announced copy as unavailable.
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(9);

struct Capture {
    epoch: u64,
    until: Instant,
}
struct LastCopy {
    epoch: u64,
    source: Instance,
    ready: Option<Revision>,
    until: Instant,
    failed: bool,
}
#[derive(Default)]
pub(super) struct PasteState {
    captures: HashMap<(Instance, usize), Capture>,
    last: Option<LastCopy>,
    seen: HashMap<Instance, u64>,
}
impl PasteState {
    pub fn remove(&mut self, instance: Instance) {
        self.captures.retain(|(id, _), _| *id != instance);
        self.seen.remove(&instance);
        // Keep the epoch, never its data: a closed latest source must not
        // make a different, older copy become the user's latest copy.
        if let Some(last) = self.last.as_mut().filter(|l| l.source == instance) {
            last.failed = true;
        }
    }
    pub fn explicit_selection(&mut self, instance: Instance) {
        if let Some(last) = &self.last {
            self.seen.insert(instance, last.epoch);
        }
    }
}

pub struct PasteCandidate {
    pub epoch: u64,
    pub source: Instance,
    pub revision: Revision,
    pub target_revision: u64,
    pub secret: bool,
    pub preview: String,
    pub types: Vec<(String, u64)>,
}
pub enum PasteDecision {
    Current(u64),
    Pending(u64),
    Transfer(PasteCandidate),
}

impl Broker {
    pub(super) fn cancel_capture(&mut self, instance: Instance, selection: Selection) {
        if let Some(epoch) = self
            .paste
            .captures
            .get(&(instance, selection.index()))
            .map(|c| c.epoch)
        {
            self.abort_capture(instance, selection, epoch);
        }
    }
    pub fn begin_capture(
        &mut self,
        instance: Instance,
        selection: Selection,
        user_copy: bool,
        now: Instant,
    ) -> Result<u64, Error> {
        if !self.instances.contains_key(&instance) {
            return Err(Error::UnknownInstance);
        }
        if user_copy && selection != Selection::Clipboard {
            return Err(Error::InvalidTypes);
        }
        let epoch = self.serial()?;
        let until = now + CAPTURE_TIMEOUT;
        self.paste
            .captures
            .insert((instance, selection.index()), Capture { epoch, until });
        if user_copy {
            self.paste.last = Some(LastCopy {
                epoch,
                source: instance,
                ready: None,
                until,
                failed: false,
            });
            self.paste.seen.insert(instance, epoch);
        } else if selection == Selection::Clipboard {
            if let Some(last) = self
                .paste
                .last
                .as_mut()
                .filter(|l| l.source == instance && l.ready.is_none())
            {
                last.failed = true;
            }
        }
        Ok(epoch)
    }

    pub fn abort_capture(&mut self, instance: Instance, selection: Selection, epoch: u64) {
        let key = (instance, selection.index());
        if self
            .paste
            .captures
            .get(&key)
            .is_some_and(|c| c.epoch == epoch)
        {
            self.paste.captures.remove(&key);
        }
        if let Some(last) = self
            .paste
            .last
            .as_mut()
            .filter(|l| l.source == instance && l.epoch == epoch)
        {
            last.failed = true;
        }
    }

    pub fn finish_capture(
        &mut self,
        instance: Instance,
        selection: Selection,
        epoch: u64,
        mut contents: Vec<Content>,
        now: Instant,
    ) -> Result<Revision, Error> {
        if !self
            .paste
            .captures
            .get(&(instance, selection.index()))
            .is_some_and(|c| c.epoch == epoch && now < c.until)
        {
            for content in &mut contents {
                erase(&mut content.data);
            }
            return Err(Error::StaleOffer);
        }
        self.paste.captures.remove(&(instance, selection.index()));
        let revision = match self.set(instance, selection, contents) {
            Ok(revision) => revision,
            Err(error) => {
                self.abort_capture(instance, selection, epoch);
                return Err(error);
            }
        };
        if let Some(last) = self
            .paste
            .last
            .as_mut()
            .filter(|l| l.source == instance && l.epoch == epoch)
        {
            last.ready = Some(revision);
            last.failed = false;
        }
        Ok(revision)
    }

    fn clipboard_revision(&self, instance: Instance) -> Result<u64, Error> {
        Ok(self
            .types(instance, Selection::Clipboard)?
            .map_or(0, |(r, _)| r.wire()))
    }

    /// Trusted host operation only. Scoped application endpoints cannot
    /// enumerate candidates or transfer between instances.
    pub fn prepare_paste(
        &self,
        target: Instance,
        expected: u64,
        now: Instant,
    ) -> Result<PasteDecision, Error> {
        let revision = self.clipboard_revision(target)?;
        let Some(last) = &self.paste.last else {
            return Ok(PasteDecision::Current(revision));
        };
        if last.failed || (last.ready.is_none() && now >= last.until) {
            // A previously imported snapshot remains independent of its source.
            if last.ready.is_some()
                && last.source != target
                && self.paste.seen.get(&target).copied().unwrap_or(0) >= last.epoch
            {
                return Ok(PasteDecision::Current(revision));
            }
            return Err(Error::StaleOffer);
        }
        if last.ready.is_none() {
            // The source may share this instance with another launch. Wait
            // before pasting there too, otherwise it would see an old offer.
            if last.source == target
                || self.paste.seen.get(&target).copied().unwrap_or(0) < last.epoch
            {
                return Ok(PasteDecision::Pending(last.epoch));
            }
        }
        if last.source == target || self.paste.seen.get(&target).copied().unwrap_or(0) >= last.epoch
        {
            return Ok(PasteDecision::Current(revision));
        }
        if last.failed || last.ready.is_none() || revision != expected {
            return Err(Error::StaleOffer);
        }
        let source_revision = last.ready.unwrap();
        let offers = self
            .instances
            .get(&last.source)
            .ok_or(Error::UnknownInstance)?;
        let offer = offers[0]
            .as_ref()
            .filter(|o| o.revision == source_revision)
            .ok_or(Error::StaleOffer)?;
        let secret = offer
            .contents
            .iter()
            .any(|c| c.mime == "x-kde-passwordManagerHint");
        let preferred = [
            "text/plain;charset=utf-8",
            "text/plain",
            "UTF8_STRING",
            "TEXT",
            "STRING",
        ]
        .iter()
        .find_map(|mime| offer.contents.iter().find(|c| c.mime == *mime));
        let preview = if secret {
            String::new()
        } else {
            preferred
                .map(|c| {
                    let sample = String::from_utf8_lossy(&c.data[..c.data.len().min(2048)]);
                    let mut preview: String = sample
                        .chars()
                        .take(200)
                        .map(|c| if c.is_control() { ' ' } else { c })
                        .collect();
                    if c.data.len() > 2048 || sample.chars().take(201).count() > 200 {
                        preview.push('…');
                    }
                    preview
                })
                .unwrap_or_default()
        };
        Ok(PasteDecision::Transfer(PasteCandidate {
            epoch: last.epoch,
            source: last.source,
            revision: source_revision,
            target_revision: revision,
            secret,
            preview,
            types: offer
                .contents
                .iter()
                .map(|c| (c.mime.clone(), c.data.len() as u64))
                .collect(),
        }))
    }

    pub fn commit_paste(
        &mut self,
        target: Instance,
        epoch: u64,
        source_revision: Revision,
        target_revision: u64,
        allow_secret: bool,
        now: Instant,
    ) -> Result<Revision, Error> {
        let PasteDecision::Transfer(candidate) =
            self.prepare_paste(target, target_revision, now)?
        else {
            return Err(Error::StaleOffer);
        };
        if candidate.epoch != epoch
            || candidate.revision != source_revision
            || candidate.target_revision != target_revision
            || (candidate.secret && !allow_secret)
        {
            return Err(Error::StaleOffer);
        }
        let revision = self.transfer_explicit(
            candidate.source,
            target,
            Selection::Clipboard,
            source_revision,
        )?;
        self.paste.seen.insert(target, epoch);
        Ok(revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn text(body: &[u8]) -> Vec<Content> {
        vec![Content {
            mime: "text/plain".into(),
            data: body.to_vec(),
        }]
    }
    fn copy(b: &mut Broker, from: Instance, body: &[u8], now: Instant) -> (u64, Revision) {
        let epoch = b
            .begin_capture(from, Selection::Clipboard, true, now)
            .unwrap();
        let rev = b
            .finish_capture(from, Selection::Clipboard, epoch, text(body), now)
            .unwrap();
        (epoch, rev)
    }
    #[test]
    fn fast_paste_waits_for_the_announced_copy_and_transfers_once() {
        let now = Instant::now();
        let mut b = Broker::default();
        let a = b.register().unwrap();
        let target = b.register().unwrap();
        let old = b.set(target, Selection::Clipboard, text(b"old")).unwrap();
        let epoch = b.begin_capture(a, Selection::Clipboard, true, now).unwrap();
        assert!(
            matches!(b.prepare_paste(target, old.wire(), now).unwrap(), PasteDecision::Pending(e) if e == epoch)
        );
        let copied = b
            .finish_capture(a, Selection::Clipboard, epoch, text(b"fresh"), now)
            .unwrap();
        let imported = b
            .commit_paste(target, epoch, copied, old.wire(), false, now)
            .unwrap();
        assert_eq!(
            b.read(target, Selection::Clipboard, imported, "text/plain")
                .unwrap(),
            b"fresh"
        );
        assert!(
            matches!(b.prepare_paste(target, imported.wire(), now).unwrap(), PasteDecision::Current(r) if r == imported.wire())
        );
        assert!(b.types(target, Selection::Primary).unwrap().is_none());
    }
    #[test]
    fn failed_or_closed_latest_copy_never_falls_back_to_an_older_source() {
        for close in [false, true] {
            let now = Instant::now();
            let mut b = Broker::default();
            let a = b.register().unwrap();
            let target = b.register().unwrap();
            copy(&mut b, a, b"older", now);
            let epoch = b.begin_capture(a, Selection::Clipboard, true, now).unwrap();
            if close {
                b.remove(a).unwrap();
            } else {
                b.abort_capture(a, Selection::Clipboard, epoch);
            }
            assert!(matches!(
                b.prepare_paste(target, 0, now),
                Err(Error::StaleOffer | Error::UnknownInstance)
            ));
            assert!(b.types(target, Selection::Clipboard).unwrap().is_none());
        }
    }
    #[test]
    fn stale_capture_cannot_overwrite_a_newer_copy_from_the_same_instance() {
        let now = Instant::now();
        let mut b = Broker::default();
        let a = b.register().unwrap();
        let old = b.begin_capture(a, Selection::Clipboard, true, now).unwrap();
        let (_, current) = copy(&mut b, a, b"newer", now);
        assert_eq!(
            b.finish_capture(a, Selection::Clipboard, old, text(b"old"), now),
            Err(Error::StaleOffer)
        );
        assert_eq!(
            b.read(a, Selection::Clipboard, current, "text/plain")
                .unwrap(),
            b"newer"
        );
    }
    #[test]
    fn changed_source_or_destination_invalidates_the_prepared_transfer() {
        for change_source in [false, true] {
            let now = Instant::now();
            let mut b = Broker::default();
            let a = b.register().unwrap();
            let target = b.register().unwrap();
            let (epoch, source) = copy(&mut b, a, b"first", now);
            if change_source {
                copy(&mut b, a, b"second", now);
            } else {
                b.set(target, Selection::Clipboard, text(b"local selection"))
                    .unwrap();
            }
            assert_eq!(
                b.commit_paste(target, epoch, source, 0, false, now),
                Err(Error::StaleOffer)
            );
        }
    }
    #[test]
    fn secret_has_no_preview_and_needs_separate_consent_without_losing_its_hint() {
        let now = Instant::now();
        let mut b = Broker::default();
        let a = b.register().unwrap();
        let target = b.register().unwrap();
        let epoch = b.begin_capture(a, Selection::Clipboard, true, now).unwrap();
        let mut contents = text(b"SYNTHETIC_SECRET");
        contents.push(Content {
            mime: "x-kde-passwordManagerHint".into(),
            data: b"secret".to_vec(),
        });
        let rev = b
            .finish_capture(a, Selection::Clipboard, epoch, contents, now)
            .unwrap();
        let PasteDecision::Transfer(candidate) = b.prepare_paste(target, 0, now).unwrap() else {
            panic!()
        };
        assert!(candidate.secret);
        assert!(candidate.preview.is_empty());
        assert_eq!(
            b.commit_paste(target, epoch, rev, 0, false, now),
            Err(Error::StaleOffer)
        );
        let imported = b.commit_paste(target, epoch, rev, 0, true, now).unwrap();
        assert_eq!(
            b.read(
                target,
                Selection::Clipboard,
                imported,
                "x-kde-passwordManagerHint"
            )
            .unwrap(),
            b"secret"
        );
    }
    #[test]
    fn background_selections_are_not_globally_announced_copies() {
        let now = Instant::now();
        let mut b = Broker::default();
        let a = b.register().unwrap();
        let target = b.register().unwrap();
        let epoch = b
            .begin_capture(a, Selection::Clipboard, false, now)
            .unwrap();
        b.finish_capture(a, Selection::Clipboard, epoch, text(b"background"), now)
            .unwrap();
        assert!(matches!(
            b.prepare_paste(target, 0, now).unwrap(),
            PasteDecision::Current(0)
        ));
    }
    #[test]
    fn expired_capture_is_not_a_successful_empty_copy() {
        let now = Instant::now();
        let mut b = Broker::default();
        let a = b.register().unwrap();
        let target = b.register().unwrap();
        let epoch = b.begin_capture(a, Selection::Clipboard, true, now).unwrap();
        assert!(matches!(
            b.prepare_paste(target, 0, now + CAPTURE_TIMEOUT),
            Err(Error::StaleOffer)
        ));
        assert_eq!(
            b.finish_capture(
                a,
                Selection::Clipboard,
                epoch,
                text(b"late"),
                now + CAPTURE_TIMEOUT
            ),
            Err(Error::StaleOffer)
        );
    }

    #[test]
    fn completion_order_cannot_reorder_copies_between_scopes() {
        let now = Instant::now();
        let mut b = Broker::default();
        let slow = b.register().unwrap();
        let fast = b.register().unwrap();
        let target = b.register().unwrap();
        let old = b
            .begin_capture(slow, Selection::Clipboard, true, now)
            .unwrap();
        let (new, revision) = copy(&mut b, fast, b"newer", now);
        b.finish_capture(slow, Selection::Clipboard, old, text(b"older"), now)
            .unwrap();
        let PasteDecision::Transfer(candidate) = b.prepare_paste(target, 0, now).unwrap() else {
            panic!()
        };
        assert_eq!((candidate.epoch, candidate.revision), (new, revision));
        assert_eq!(candidate.preview, "newer");
    }

    #[test]
    fn failed_own_copy_is_not_a_successful_paste_of_the_previous_offer() {
        let now = Instant::now();
        let mut b = Broker::default();
        let source = b.register().unwrap();
        let (_, old) = copy(&mut b, source, b"older", now);
        let epoch = b
            .begin_capture(source, Selection::Clipboard, true, now)
            .unwrap();
        b.abort_capture(source, Selection::Clipboard, epoch);
        assert!(matches!(
            b.prepare_paste(source, old.wire(), now),
            Err(Error::StaleOffer)
        ));
    }

    #[test]
    fn imported_snapshot_survives_source_exit_without_reexporting_a_stale_source() {
        let now = Instant::now();
        let mut b = Broker::default();
        let source = b.register().unwrap();
        let target = b.register().unwrap();
        let other = b.register().unwrap();
        let (epoch, revision) = copy(&mut b, source, b"snapshot", now);
        let imported = b
            .commit_paste(target, epoch, revision, 0, false, now)
            .unwrap();
        b.remove(source).unwrap();
        assert!(
            matches!(b.prepare_paste(target, imported.wire(), now).unwrap(), PasteDecision::Current(r) if r == imported.wire())
        );
        assert!(matches!(
            b.prepare_paste(other, 0, now),
            Err(Error::StaleOffer)
        ));
    }
}
