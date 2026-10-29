//! Hover capture is a transparent-to-input shade on only its originating window.
//! Real motion reaches the application. Both halves of the freezing click stay
//! here; the host capture starts after the shade's removal is processed upstream.
use super::*;
use std::os::fd::{AsRawFd, RawFd};

#[derive(Default)]
struct State {
    shade: Option<Rc<OwnedFd>>,
    requested: Option<(Weak<WlSurface>, Instant)>,
    active: Option<Overlay>,
    consumed: Vec<u32>,
}
struct Overlay {
    root: Weak<WlSurface>,
    frames: Rc<Frames>,
    strip: Strip,
    buffer: Rc<WlBuffer>,
    until: Instant,
}
impl Drop for Overlay {
    fn drop(&mut self) {
        self.strip.surface.send_attach(None, 0, 0);
        self.strip.surface.send_commit();
        self.strip.viewport.send_destroy();
        self.strip.sub.send_destroy();
        self.strip.surface.send_destroy();
        self.buffer.send_destroy();
    }
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }

pub(crate) fn initialize(shade: OwnedFd) {
    STATE.with_borrow_mut(|s| s.shade = Some(Rc::new(shade)));
}
pub(crate) fn keep_fds() -> Vec<RawFd> {
    STATE.with_borrow(|s| s.shade.iter().map(|fd| fd.as_raw_fd()).collect())
}
pub(super) fn arm(root: Weak<WlSurface>) {
    STATE.with_borrow_mut(|s| {
        s.active = None;
        s.requested = Some((root, Instant::now() + Duration::from_secs(30)));
    });
}
pub(super) fn cancel(surface: &Weak<WlSurface>) -> bool {
    STATE.with_borrow_mut(|s| {
        let root = s
            .active
            .as_ref()
            .map(|a| &a.root)
            .or_else(|| s.requested.as_ref().map(|(r, _)| r));
        let same = root
            .and_then(Weak::upgrade)
            .and_then(|r| spot(&r))
            .zip(surface.upgrade().and_then(|r| spot(&r)))
            .is_some_and(|((a, _), (b, _))| Rc::ptr_eq(&a, &b));
        if !same {
            return false;
        }

        s.active.take().is_some() | s.requested.take().is_some()
    })
}
pub(crate) fn wake_at() -> Option<Instant> {
    STATE.with_borrow(|s| {
        s.active
            .as_ref()
            .map(|a| a.until)
            .into_iter()
            .chain(s.requested.as_ref().map(|(_, until)| *until))
            .min()
    })
}

pub(crate) fn tick(frames: &Rc<Frames>, now: Instant) {
    STATE.with_borrow_mut(|s| {
        if s.active
            .as_ref()
            .is_some_and(|a| now >= a.until || a.root.upgrade().is_none_or(|r| !programs(&r)))
        {
            s.active = None;
        }
        let Some((root, until)) = &s.requested else {
            return;
        };
        if now >= *until || root.strong_count() == 0 {
            s.requested = None;
            return;
        }
        let Some(root) = root.upgrade() else { return };
        let Some((window, _)) = spot(&root) else {
            return;
        };
        if !frames
            .windows
            .borrow()
            .iter()
            .any(|w| Weak::ptr_eq(w, &Rc::downgrade(&window)))
        {
            return;
        }
        let Some(shade) = &s.shade else {
            s.requested = None;
            return;
        };
        let Ok(mut w) = window.try_borrow_mut() else {
            return;
        };
        let Some(area) = w.area().filter(|a| a.w > 0 && a.h > 0) else {
            s.requested = None;
            return;
        };
        let own = frames.own.borrow();
        let (Some(compositor), Some(subcompositor), Some(shm), Some(viewporter)) = (
            &own.compositor,
            &own.subcompositor,
            &own.shm,
            &own.viewporter,
        ) else {
            s.requested = None;
            return;
        };
        w.close_menu();
        let surface = compositor.new_send_create_surface();
        quiet(&*surface);
        let empty = compositor.new_send_create_region();
        quiet(&*empty);
        surface.send_set_input_region(Some(&empty));
        empty.send_destroy();
        let sub = subcompositor.new_send_get_subsurface(&surface, &root);
        quiet(&*sub);
        let viewport = viewporter.new_send_get_viewport(&surface);
        quiet(&*viewport);
        viewport.send_set_destination(
            area.w.saturating_add(area.x.max(0)),
            area.h.saturating_add(area.y.max(0)),
        );
        let pool = shm.new_send_create_pool(shade, 4);
        quiet(&*pool);
        let buffer = pool.new_send_create_buffer(0, 1, 1, 4, WlShmFormat::ARGB8888);
        quiet(&*buffer);
        pool.send_destroy();
        attach_whole(&surface, &buffer, 1, 1);
        sub.send_set_desync();
        surface.send_commit();
        w.reconfigure(frames);
        let until = *until;
        s.requested = None;
        s.active = Some(Overlay {
            root: Rc::downgrade(&root),
            frames: frames.clone(),
            strip: Strip {
                surface,
                sub,
                viewport,
            },
            buffer,
            until,
        });
    });
}

/// Also run when the connection which owned the overlay has disappeared.
/// Otherwise an expired wake-up with no remaining frame would spin the loop.
pub(crate) fn expire(now: Instant) {
    STATE.with_borrow_mut(|s| {
        if s.active.as_ref().is_some_and(|a| {
            now >= a.until
                || a.root
                    .upgrade()
                    .is_none_or(|r| r.state().is_destroyed() || !programs(&r))
        }) {
            s.active = None;
        }
        if s.requested.as_ref().is_some_and(|(root, until)| {
            now >= *until
                || root
                    .upgrade()
                    .is_none_or(|r| r.state().is_destroyed() || !programs(&r))
        }) {
            s.requested = None;
        }
    });
}

struct Removed {
    frames: Rc<Frames>,
    root: Weak<WlSurface>,
}
impl WlCallbackHandler for Removed {
    fn handle_done(&mut self, _slf: &Rc<WlCallback>, _: u32) {
        if self
            .root
            .upgrade()
            .is_some_and(|root| !root.state().is_destroyed() && programs(&root))
        {
            self.frames.asks.push(Ask::ScreenshotHover);
        }
    }
}

pub(super) fn click(surface: &Weak<WlSurface>, button: u32, down: bool) -> bool {
    STATE.with_borrow_mut(|s| {
        if let Some(index) = s.consumed.iter().position(|b| *b == button) {
            if !down {
                s.consumed.swap_remove(index);
            }
            return true;
        }
        let Some(active) = &s.active else {
            return false;
        };
        let same_window = surface
            .upgrade()
            .and_then(|r| spot(&r))
            .zip(active.root.upgrade().and_then(|r| spot(&r)))
            .is_some_and(|((a, _), (b, _))| Rc::ptr_eq(&a, &b));
        if !same_window || !down {
            return false;
        }
        if s.consumed.len() < 16 {
            s.consumed.push(button);
        }
        if button == 0x110 {
            let active = s.active.take().unwrap();
            let frames = active.frames.clone();
            let root = active.root.clone();
            drop(active);
            if let Some(display) = frames.display.upgrade() {
                let sync = display.new_send_sync();
                quiet(&*sync);
                sync.set_handler(Removed { frames, root });
            }
        }
        true
    })
}
