//! Volatile, bounded active selections for the host-side instance broker.
//!
//! This is independent of history: recording can be disabled without losing
//! an instance's current clipboard. A transport must bind each connection to
//! its supervisor's Instance once, never accept a destination instance from
//! an application request. This module is not the Wayland/X11 adapter yet.

use std::collections::{HashMap, HashSet};

use crate::Content;

/// Opaque connection scope, allocated only by the trusted host supervisor.
/// Not a wire authentication token: the transport owns the mapping to peers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Instance(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Selection {
    Clipboard,
    Primary,
}

impl Selection {
    fn index(self) -> usize {
        match self {
            Self::Clipboard => 0,
            Self::Primary => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Revision(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnknownInstance,
    StaleOffer,
    InvalidTypes,
    Limit,
    Exhausted,
}

/// Budgets apply before replacing an existing selection. No eviction of
/// another instance's buffer, and no fallback to the host selection.
#[derive(Clone, Copy)]
pub struct Limits {
    pub instances: usize,
    pub per_instance: usize,
    pub total: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            instances: 64,
            per_instance: crate::MAX_ENTRY,
            total: 128 << 20,
        }
    }
}

struct Offer {
    revision: Revision,
    contents: Vec<Content>,
    bytes: usize,
}

impl Drop for Offer {
    fn drop(&mut self) {
        for content in &mut self.contents {
            for byte in &mut content.data {
                // SAFETY: a byte of our owned buffer; volatile so dropping
                // a password selection does not optimize the erasure away.
                unsafe {
                    std::ptr::write_volatile(byte, 0);
                }
            }
        }
    }
}

/// No compositor globals, paths, history keys, or implicit host buffer here.
pub struct Broker {
    limits: Limits,
    next: u64,
    bytes: usize,
    instances: HashMap<Instance, [Option<Offer>; 2]>,
}

impl Default for Broker {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

impl Broker {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            next: 0,
            bytes: 0,
            instances: HashMap::new(),
        }
    }

    fn serial(&mut self) -> Result<u64, Error> {
        self.next = self.next.checked_add(1).ok_or(Error::Exhausted)?;
        Ok(self.next)
    }

    pub fn register(&mut self) -> Result<Instance, Error> {
        if self.instances.len() >= self.limits.instances {
            return Err(Error::Limit);
        }
        let id = Instance(self.serial()?);
        self.instances.insert(id, [None, None]);
        Ok(id)
    }

    /// Called when the actual instance ends, not when one of its windows
    /// loses focus or one of several launches exits.
    pub fn remove(&mut self, instance: Instance) -> Result<(), Error> {
        let offers = self
            .instances
            .remove(&instance)
            .ok_or(Error::UnknownInstance)?;
        self.bytes -= offers.iter().flatten().map(|o| o.bytes).sum::<usize>();
        Ok(())
    }

    pub fn set(
        &mut self,
        instance: Instance,
        selection: Selection,
        contents: Vec<Content>,
    ) -> Result<Revision, Error> {
        let mut candidate = Offer {
            revision: Revision(0),
            contents,
            bytes: 0,
        };
        let offers = self
            .instances
            .get(&instance)
            .ok_or(Error::UnknownInstance)?;
        let mut types = HashSet::new();
        if candidate.contents.is_empty() || candidate.contents.len() > 64 {
            return Err(Error::InvalidTypes);
        }
        candidate.contents.shrink_to_fit();
        let mut bytes = 0usize;
        for content in &candidate.contents {
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
        let previous = offers[selection.index()].as_ref().map_or(0, |o| o.bytes);
        let instance_bytes = offers.iter().flatten().map(|o| o.bytes).sum::<usize>() - previous;
        if bytes > self.limits.per_instance.saturating_sub(instance_bytes)
            || bytes > self.limits.total.saturating_sub(self.bytes - previous)
        {
            return Err(Error::Limit);
        }
        let revision = Revision(self.serial()?);
        candidate.revision = revision;
        candidate.bytes = bytes;
        self.instances.get_mut(&instance).unwrap()[selection.index()] = Some(candidate);
        self.bytes = self.bytes - previous + bytes;
        Ok(revision)
    }

    pub fn clear(&mut self, instance: Instance, selection: Selection) -> Result<(), Error> {
        let offers = self
            .instances
            .get_mut(&instance)
            .ok_or(Error::UnknownInstance)?;
        if let Some(old) = offers[selection.index()].take() {
            self.bytes -= old.bytes;
        }
        Ok(())
    }

    pub fn types(
        &self,
        instance: Instance,
        selection: Selection,
    ) -> Result<Option<(Revision, Vec<&str>)>, Error> {
        let offers = self
            .instances
            .get(&instance)
            .ok_or(Error::UnknownInstance)?;
        Ok(offers[selection.index()].as_ref().map(|o| {
            (
                o.revision,
                o.contents.iter().map(|c| c.mime.as_str()).collect(),
            )
        }))
    }

    /// A stale offer is rejected, never silently served from a newer copy
    /// (particularly important if a password replaced the previous text).
    pub fn read(
        &self,
        instance: Instance,
        selection: Selection,
        revision: Revision,
        mime: &str,
    ) -> Result<&[u8], Error> {
        let offers = self
            .instances
            .get(&instance)
            .ok_or(Error::UnknownInstance)?;
        let offer = offers[selection.index()]
            .as_ref()
            .filter(|o| o.revision == revision)
            .ok_or(Error::StaleOffer)?;
        offer
            .contents
            .iter()
            .find(|c| c.mime == mime)
            .map(|c| c.data.as_slice())
            .ok_or(Error::InvalidTypes)
    }

    /// Host UI/supervisor operation only, after explicit user confirmation.
    /// This is intentionally not an operation available to scoped app peers.
    pub fn transfer_explicit(
        &mut self,
        from: Instance,
        to: Instance,
        selection: Selection,
        revision: Revision,
    ) -> Result<Revision, Error> {
        let offers = self.instances.get(&from).ok_or(Error::UnknownInstance)?;
        let offer = offers[selection.index()]
            .as_ref()
            .filter(|o| o.revision == revision)
            .ok_or(Error::StaleOffer)?;
        let contents = offer.contents.clone();
        self.set(to, selection, contents)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn text(s: &[u8]) -> Vec<Content> {
        vec![Content {
            mime: "text/plain".into(),
            data: s.to_vec(),
        }]
    }

    #[test]
    fn instances_and_primary_are_separate_until_explicit_transfer() {
        let mut b = Broker::default();
        let a = b.register().unwrap();
        let other = b.register().unwrap();
        let r = b.set(a, Selection::Clipboard, text(b"private")).unwrap();
        assert!(b.types(other, Selection::Clipboard).unwrap().is_none());
        assert!(b.types(a, Selection::Primary).unwrap().is_none());
        assert_eq!(
            b.read(other, Selection::Clipboard, r, "text/plain"),
            Err(Error::StaleOffer)
        );
        let copied = b
            .transfer_explicit(a, other, Selection::Clipboard, r)
            .unwrap();
        assert_ne!(r, copied);
        assert_eq!(
            b.read(other, Selection::Clipboard, copied, "text/plain")
                .unwrap(),
            b"private"
        );
        b.clear(a, Selection::Clipboard).unwrap();
        assert_eq!(
            b.read(other, Selection::Clipboard, copied, "text/plain")
                .unwrap(),
            b"private"
        );
    }

    #[test]
    fn replacement_invalidates_old_offers_and_instance_end_drops_buffers() {
        let mut b = Broker::default();
        let a = b.register().unwrap();
        let old = b.set(a, Selection::Clipboard, text(b"old")).unwrap();
        let new = b.set(a, Selection::Clipboard, text(b"password")).unwrap();
        assert_eq!(
            b.read(a, Selection::Clipboard, old, "text/plain"),
            Err(Error::StaleOffer)
        );
        assert_eq!(
            b.read(a, Selection::Clipboard, new, "text/plain").unwrap(),
            b"password"
        );
        b.remove(a).unwrap();
        assert_eq!(b.bytes, 0);
        assert_eq!(
            b.types(a, Selection::Clipboard),
            Err(Error::UnknownInstance)
        );
    }

    #[test]
    fn budgets_preserve_current_buffers_on_rejection() {
        let mut b = Broker::new(Limits {
            instances: 2,
            per_instance: 24,
            total: 36,
        });
        let a = b.register().unwrap();
        let other = b.register().unwrap();
        assert_eq!(b.register(), Err(Error::Limit));
        let r = b.set(a, Selection::Clipboard, text(b"1234")).unwrap();
        assert_eq!(
            b.set(a, Selection::Primary, text(b"1234")),
            Err(Error::Limit)
        );
        b.set(other, Selection::Clipboard, text(b"1234")).unwrap();
        assert_eq!(
            b.set(a, Selection::Clipboard, text(b"01234567890123")),
            Err(Error::Limit)
        );
        assert_eq!(
            b.read(a, Selection::Clipboard, r, "text/plain").unwrap(),
            b"1234"
        );
        assert_eq!(b.bytes, 28);
    }

    #[test]
    fn images_and_text_are_kept_without_conversion_or_disk_storage() {
        let mut b = Broker::default();
        let a = b.register().unwrap();
        let r = b
            .set(
                a,
                Selection::Clipboard,
                vec![Content {
                    mime: "image/png".into(),
                    data: vec![0, 255, 0, 10],
                }],
            )
            .unwrap();
        assert_eq!(
            b.read(a, Selection::Clipboard, r, "image/png").unwrap(),
            &[0, 255, 0, 10]
        );
        assert_eq!(
            b.read(a, Selection::Clipboard, r, "text/plain"),
            Err(Error::InvalidTypes)
        );
    }

    #[test]
    fn reserved_payload_memory_is_charged_not_just_its_visible_length() {
        let mut b = Broker::new(Limits {
            instances: 1,
            per_instance: 32,
            total: 32,
        });
        let a = b.register().unwrap();
        let mut data = Vec::with_capacity(1024);
        data.push(1);
        assert_eq!(
            b.set(
                a,
                Selection::Clipboard,
                vec![Content {
                    mime: "image/png".into(),
                    data
                }]
            ),
            Err(Error::Limit)
        );
        assert!(b.types(a, Selection::Clipboard).unwrap().is_none());
        assert_eq!(b.bytes, 0);
    }

    #[test]
    fn private_marks_duplicate_types_and_control_characters_are_rejected() {
        let mut b = Broker::default();
        let a = b.register().unwrap();
        for mime in ["", "text/plain\n", "application/x-cellward-clip-forged"] {
            assert_eq!(
                b.set(
                    a,
                    Selection::Clipboard,
                    vec![Content {
                        mime: mime.into(),
                        data: vec![]
                    }]
                ),
                Err(Error::InvalidTypes)
            );
        }
        let mut duplicate = text(b"one");
        duplicate.extend(text(b"two"));
        assert_eq!(
            b.set(a, Selection::Clipboard, duplicate),
            Err(Error::InvalidTypes)
        );
        assert_eq!(b.bytes, 0);
    }
}
