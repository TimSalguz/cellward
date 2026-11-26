//! ScreenCast session lifecycle, independent of D-Bus and PipeWire transports.
//! A source is never selected implicitly when more than one container is live.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub node_id: u32,
    pub serial: u64,
    pub capture_id: String,
}

impl Source {
    pub fn new(node_id: u32, serial: u64, capture_id: &str) -> Option<Self> {
        (node_id > 0
            && serial > 0
            && !capture_id.is_empty()
            && capture_id.len() <= 128
            && capture_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-')))
        .then(|| Self {
            node_id,
            serial,
            capture_id: capture_id.to_owned(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Created,
    SourcesSelected,
    Started,
}

#[derive(Debug)]
struct Session {
    status: Status,
    multiple: bool,
    streams: Vec<Source>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    UnknownSession,
    InvalidTransition,
    NoSources,
    AmbiguousSource,
}

#[derive(Debug, Default)]
pub struct Registry {
    next: u64,
    sessions: BTreeMap<String, Session>,
}

impl Registry {
    pub fn create_session(&mut self) -> String {
        self.next = self
            .next
            .checked_add(1)
            .expect("capture sessions exhausted");
        let handle = format!("/org/cellward/capture/session/{}", self.next);
        self.sessions.insert(
            handle.clone(),
            Session {
                status: Status::Created,
                multiple: false,
                streams: Vec::new(),
            },
        );
        handle
    }

    pub fn select_sources(&mut self, handle: &str, multiple: bool) -> Result<(), Error> {
        let session = self.sessions.get_mut(handle).ok_or(Error::UnknownSession)?;
        if session.status != Status::Created {
            return Err(Error::InvalidTransition);
        }
        session.multiple = multiple;
        session.status = Status::SourcesSelected;
        Ok(())
    }

    pub fn start(
        &mut self,
        handle: &str,
        available: &[Source],
        capture_id: Option<&str>,
    ) -> Result<Vec<Source>, Error> {
        let session = self.sessions.get_mut(handle).ok_or(Error::UnknownSession)?;
        if session.status != Status::SourcesSelected {
            return Err(Error::InvalidTransition);
        }
        let mut selected: Vec<Source> = available
            .iter()
            .filter(|source| capture_id.is_none_or(|id| source.capture_id == id))
            .cloned()
            .collect();
        if selected.is_empty() {
            return Err(Error::NoSources);
        }
        if capture_id.is_none() && !session.multiple && selected.len() != 1 {
            return Err(Error::AmbiguousSource);
        }
        if !session.multiple {
            selected.truncate(1);
        }
        session.streams = selected.clone();
        session.status = Status::Started;
        Ok(selected)
    }

    pub fn status(&self, handle: &str) -> Option<Status> {
        self.sessions.get(handle).map(|session| session.status)
    }

    pub fn streams(&self, handle: &str) -> Option<&[Source]> {
        self.sessions
            .get(handle)
            .filter(|session| session.status == Status::Started)
            .map(|session| session.streams.as_slice())
    }

    pub fn close(&mut self, handle: &str) -> bool {
        self.sessions.remove(handle).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(serial: u64, id: &str) -> Source {
        Source::new(serial as u32, serial, id).unwrap()
    }

    #[test]
    fn one_explicitly_started_source_keeps_its_serial_and_capture_id() {
        let mut registry = Registry::default();
        let handle = registry.create_session();
        registry.select_sources(&handle, false).unwrap();
        let streams = registry
            .start(&handle, &[source(41, "work")], None)
            .unwrap();
        assert_eq!(streams, [source(41, "work")]);
        assert_eq!(registry.status(&handle), Some(Status::Started));
        assert_eq!(registry.streams(&handle).unwrap(), streams);
    }

    #[test]
    fn several_containers_are_never_narrowed_to_the_first_one() {
        let mut registry = Registry::default();
        let handle = registry.create_session();
        registry.select_sources(&handle, false).unwrap();
        let available = [source(1, "one"), source(2, "two")];
        assert_eq!(
            registry.start(&handle, &available, None),
            Err(Error::AmbiguousSource)
        );
        let chosen = registry.start(&handle, &available, Some("two")).unwrap();
        assert_eq!(chosen, [source(2, "two")]);
        assert_eq!(
            registry.start(&handle, &available, Some("two")),
            Err(Error::InvalidTransition)
        );
    }

    #[test]
    fn multiple_requires_an_explicit_selection_and_never_invents_a_source() {
        let mut registry = Registry::default();
        let handle = registry.create_session();
        registry.select_sources(&handle, true).unwrap();
        let available = [source(1, "one"), source(2, "two")];
        assert_eq!(
            registry.start(&handle, &available, None).unwrap(),
            available
        );
        assert_eq!(
            registry.start(&handle, &available, None),
            Err(Error::InvalidTransition)
        );
        let other = registry.create_session();
        registry.select_sources(&other, true).unwrap();
        assert_eq!(registry.start(&other, &[], None), Err(Error::NoSources));
        assert_eq!(
            registry.start(&other, &available, Some("missing")),
            Err(Error::NoSources)
        );
    }

    #[test]
    fn close_is_scoped_and_handles_are_not_reused() {
        let mut registry = Registry::default();
        let first = registry.create_session();
        let second = registry.create_session();
        assert_ne!(first, second);
        assert!(registry.close(&first));
        assert!(!registry.close(&first));
        assert_eq!(registry.status(&second), Some(Status::Created));
        assert_eq!(registry.status(&first), None);
        assert!(registry.streams(&first).is_none());
    }

    #[test]
    fn invalid_source_metadata_is_rejected() {
        for invalid in ["", "with space", "comma,id", "line\nbreak", "ё"] {
            assert!(Source::new(1, 1, invalid).is_none());
        }
        assert!(Source::new(0, 1, "work").is_none());
        assert!(Source::new(1, 0, "work").is_none());
        assert!(Source::new(1, 1, "main:offline").is_some());
    }
}
