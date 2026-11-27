//! A single foreign drop, captured and replayed only after host confirmation.
use super::*;
use private_clipboard::CaptureData;
use std::os::fd::RawFd;

const LIMIT: usize = 64 << 20;
const QUANTUM: usize = 64 << 10;

struct Capture {
    offer: Rc<WlDataOffer>,
    data: CaptureData,
}

struct Pending {
    ticket: u64,
    drag_id: u64,
    target_revision: u64,
    device: Weak<WlDataDevice>,
    surface: Weak<WlSurface>,
    offer: Weak<WlDataOffer>,
    offer_id: u64,
    capture: Option<Capture>,
    until: Instant,
    send: bool,
    confirmed: Option<u64>,
}

#[derive(Default)]
struct State {
    serial: u64,
    pending: Option<Pending>,
}

thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }

pub(super) fn begin(
    device: &Rc<WlDataDevice>,
    surface: &Rc<WlSurface>,
    offer: &Rc<WlDataOffer>,
    drag_id: u64,
    target_revision: u64,
) -> bool {
    if !private_clipboard::drop_enabled() {
        return false;
    }
    let Ok(info) = offer.try_get_handler_ref::<Offer>() else {
        return false;
    };
    if info.drag_id != Some(drag_id) || info.own_drag || info.drag_invalid {
        return false;
    }
    let capture = CaptureData::new(info.types.clone(), Instant::now());
    let offer_id = info.id;
    drop(info);
    STATE.with_borrow_mut(|state| {
        let Some(ticket) = state.serial.checked_add(1) else {
            state.pending = None;
            return false;
        };
        state.serial = ticket;
        state.pending = Some(Pending {
            ticket,
            drag_id,
            target_revision,
            device: Rc::downgrade(device),
            surface: Rc::downgrade(surface),
            offer: Rc::downgrade(offer),
            offer_id,
            capture: Some(Capture {
                offer: offer.clone(),
                data: capture,
            }),
            until: Instant::now() + Duration::from_secs(60),
            send: true,
            confirmed: None,
        });
        true
    })
}

pub(super) fn cancel() {
    STATE.with_borrow_mut(|state| state.pending = None);
}

pub(crate) fn request() -> Option<(u64, u64, u64)> {
    STATE.with_borrow_mut(|state| {
        let pending = state.pending.as_mut()?;
        if !pending.send || pending.confirmed.is_some() {
            return None;
        }
        pending.send = false;
        Some((pending.ticket, pending.drag_id, pending.target_revision))
    })
}

pub(crate) fn finish(ticket: u64, drop_revision: Option<u64>) {
    STATE.with_borrow_mut(|state| {
        if let Some(pending) = state
            .pending
            .as_mut()
            .filter(|pending| pending.ticket == ticket)
        {
            if let Some(revision) = drop_revision.filter(|revision| *revision > 0) {
                pending.confirmed = Some(revision);
                pending.until = pending.until.min(Instant::now() + Duration::from_secs(2));
            } else {
                state.pending = None;
            }
        }
    });
}

fn alive(pending: &Pending) -> bool {
    pending
        .device
        .upgrade()
        .is_some_and(|device| !device.state().is_destroyed())
        && pending
            .surface
            .upgrade()
            .is_some_and(|surface| !surface.state().is_destroyed())
        && pending
            .offer
            .upgrade()
            .is_some_and(|offer| !offer.state().is_destroyed())
}

pub(crate) fn tick(now: Instant) {
    STATE.with_borrow_mut(|state| {
        let Some(pending) = state.pending.as_mut() else {
            return;
        };
        if now >= pending.until || !alive(pending) {
            eprintln!("smart-drop: cancelled (expired-or-target-ended)");
            state.pending = None;
            return;
        }
        if let Some(capture) = &mut pending.capture {
            let mut budget = QUANTUM;
            let alive = !capture.offer.state().is_destroyed();
            if capture
                .data
                .tick(now, alive, &mut budget, LIMIT, |mime, fd| {
                    capture.offer.send_receive(mime, fd)
                })
            {
                let capture = pending.capture.take().unwrap();
                if !capture.data.contents.is_empty() {
                    private_clipboard::finish_drop(
                        pending.drag_id,
                        pending.target_revision,
                        capture.data.contents,
                    );
                }
            }
            return;
        }
        let Some(drop_revision) = pending.confirmed else {
            return;
        };
        let current = private_clipboard::revision();
        if current != Some(pending.target_revision) {
            if current.is_some_and(|revision| revision != pending.target_revision) {
                eprintln!("smart-drop: cancelled (selection-changed)");
                state.pending = None;
            }
            return;
        }
        let Some(offer) = pending.offer.upgrade() else {
            state.pending = None;
            return;
        };
        let Ok(mut info) = offer.try_get_handler_mut::<Offer>() else {
            state.pending = None;
            return;
        };
        if info.id != pending.offer_id || info.drag_id != Some(pending.drag_id) {
            state.pending = None;
            return;
        }
        info.approved = Some((pending.drag_id, drop_revision));
        drop(info);
        let Some(device) = pending.device.upgrade() else {
            state.pending = None;
            return;
        };
        state.pending = None;
        device.send_drop();
    });
}

pub(crate) fn pollfds() -> Vec<libc::pollfd> {
    STATE.with_borrow(|state| {
        state
            .pending
            .as_ref()
            .and_then(|pending| pending.capture.as_ref())
            .and_then(|capture| capture.data.fd())
            .map(|fd: RawFd| {
                vec![libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                }]
            })
            .unwrap_or_default()
    })
}

pub(crate) fn wake_at() -> Option<Instant> {
    STATE.with_borrow(|state| {
        state.pending.as_ref().map(|pending| {
            let capture = pending
                .capture
                .as_ref()
                .map(|capture| capture.data.wake_at());
            let replay = pending
                .confirmed
                .is_some()
                .then(|| Instant::now() + Duration::from_millis(25));
            pending
                .until
                .min(capture.unwrap_or(pending.until))
                .min(replay.unwrap_or(pending.until))
        })
    })
}
