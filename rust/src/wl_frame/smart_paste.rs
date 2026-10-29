//! A single physical paste, bound to its original keyboard and surface.
use super::*;

struct Pending {
    ticket: u64,
    revision: u64,
    keyboard: Weak<WlKeyboard>,
    state: Rc<RefCell<typing::KeyboardState>>,
    surface: Weak<WlSurface>,
    chord: (u32, u32),
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
    keyboard: &Rc<WlKeyboard>,
    state: &Rc<RefCell<typing::KeyboardState>>,
    key: u32,
    modifiers: u32,
) {
    STATE.with_borrow_mut(|s| {
        if s.pending.is_some() || !state.borrow().on {
            return;
        }
        let Some(ticket) = s.serial.checked_add(1) else {
            return;
        };
        s.serial = ticket;
        s.pending = Some(Pending {
            ticket,
            revision: private_clipboard::revision().unwrap_or(0),
            keyboard: Rc::downgrade(keyboard),
            state: state.clone(),
            surface: state.borrow().surface.clone(),
            chord: (modifiers, key),
            until: Instant::now() + Duration::from_secs(60),
            send: true,
            confirmed: None,
        });
    });
}

pub(crate) fn request() -> Option<(u64, u64)> {
    STATE.with_borrow_mut(|s| {
        let p = s.pending.as_mut()?;
        if !p.send {
            return None;
        }
        p.send = false;
        Some((p.ticket, p.revision))
    })
}

pub(crate) fn finish(ticket: u64, revision: Option<u64>) {
    STATE.with_borrow_mut(|s| {
        if let Some(p) = s.pending.as_mut().filter(|p| p.ticket == ticket) {
            if let Some(revision) = revision {
                p.confirmed = Some(revision);
                p.until = p.until.min(Instant::now() + Duration::from_secs(2));
            } else {
                s.pending = None;
            }
        }
    });
}

pub(crate) fn tick(now: Instant) {
    STATE.with_borrow_mut(|s| {
        let Some(p) = s.pending.as_ref() else { return };
        if now >= p.until
            || p.keyboard
                .upgrade()
                .is_none_or(|k| k.state().is_destroyed())
            || p.surface
                .upgrade()
                .is_none_or(|surface| surface.state().is_destroyed())
        {
            eprintln!("smart-paste: cancelled (expired-or-target-ended)");
            s.pending = None;
            return;
        }
        let Some(revision) = p.confirmed else { return };
        let state = p.state.borrow();
        if !state.on || !Weak::ptr_eq(&state.surface, &p.surface) {
            return;
        }
        let Some(current) = private_clipboard::revision() else {
            return;
        };
        if current != revision {
            // A new copy after confirmation must never be substituted.
            if current > revision {
                eprintln!("smart-paste: cancelled (selection-changed)");
                drop(state);
                s.pending = None;
            }
            return;
        }
        let keyboard = p.keyboard.upgrade().unwrap();
        let focus = Focus {
            on: true,
            serial: state.serial,
            mods: state.mods,
            chord: p.chord,
        };
        drop(state);
        s.pending = None;
        press_paste(&keyboard, focus);
    });
}

pub(crate) fn wake_at() -> Option<Instant> {
    STATE.with_borrow(|s| {
        s.pending.as_ref().map(|p| {
            if p.confirmed.is_some() {
                p.until.min(Instant::now() + Duration::from_millis(25))
            } else {
                p.until
            }
        })
    })
}
