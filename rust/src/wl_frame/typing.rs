//! A host-selected point and keystrokes sent only to its program connection.
use super::*;
use crate::type_input::{Mode, Plan, Timing};

#[derive(Default)]
pub(super) struct KeyboardState {
    pub surface: Weak<WlSurface>,
    pub on: bool,
    pub serial: u32,
    pub mods: (u32, u32, u32, u32),
    pub keymap: Option<(Rc<OwnedFd>, u32)>,
}

#[derive(Default)]
pub(super) struct PointerState {
    pub surface: Weak<WlSurface>,
    pub on: bool,
    pub serial: u32,
    pub x: f64,
    pub y: f64,
}

type TypeKeyboard = (
    Weak<WlKeyboard>,
    Weak<Frames>,
    Weak<WlSeat>,
    Rc<RefCell<KeyboardState>>,
);

#[derive(Default)]
struct Typer {
    keyboards: Vec<TypeKeyboard>,
    selection: Option<Selection>,
    target: Option<Target>,
    run: Option<Run>,
    replies: VecDeque<Reply>,
}

struct Selection {
    seq: u8,
    token: u64,
    overlays: Vec<Overlay>,
    until: Instant,
}

struct Overlay {
    window: Weak<RefCell<Window>>,
    strip: Strip,
    buffer: Rc<WlBuffer>,
    area: Rect,
    pressed: bool,
}

impl Drop for Overlay {
    fn drop(&mut self) {
        self.strip.viewport.send_destroy();
        self.strip.sub.send_destroy();
        self.strip.surface.send_destroy();
        self.buffer.send_destroy();
    }
}

#[derive(Clone)]
struct Target {
    token: u64,
    window: Weak<RefCell<Window>>,
    root: Weak<WlSurface>,
    area: Rect,
    pointer: Weak<WlPointer>,
    pointer_state: Rc<RefCell<PointerState>>,
    keyboard: Weak<WlKeyboard>,
    keyboard_state: Rc<RefCell<KeyboardState>>,
    x: f64,
    y: f64,
    serial: u32,
    until: Instant,
}

struct Run {
    seq: u8,
    target: Target,
    plan: Plan,
    keymap: Option<Rc<OwnedFd>>,
    timing: Timing,
    at: usize,
    down: bool,
    began: bool,
    next: Instant,
}

thread_local! { static TYPER: RefCell<Typer> = RefCell::new(Typer::default()); }

pub(super) fn register_keyboard(
    kb: &Rc<WlKeyboard>,
    f: &Rc<Frames>,
    seat: &Rc<WlSeat>,
) -> Rc<RefCell<KeyboardState>> {
    let state = Rc::new(RefCell::new(KeyboardState::default()));
    TYPER.with_borrow_mut(|t| {
        t.keyboards.retain(|(k, _, _, _)| k.strong_count() > 0);
        t.keyboards.push((
            Rc::downgrade(kb),
            Rc::downgrade(f),
            Rc::downgrade(seat),
            state.clone(),
        ));
    });
    state
}

fn overlay(window: &Rc<RefCell<Window>>, f: &Rc<Frames>, white: &Rc<OwnedFd>) -> Option<Overlay> {
    let mut w = window.try_borrow_mut().ok()?;
    let area = w.area()?;
    if area.w <= 0 || area.h <= 0 {
        return None;
    }
    let root = w.root.upgrade().filter(programs)?;
    let own = f.own.borrow();
    let (Some(compositor), Some(subcompositor), Some(shm), Some(viewporter)) = (
        &own.compositor,
        &own.subcompositor,
        &own.shm,
        &own.viewporter,
    ) else {
        return None;
    };
    w.close_menu();
    let surface = compositor.new_send_create_surface();
    quiet(&*surface);
    surface.set_handler(Mine {
        window: Rc::downgrade(window),
        part: Part::TypeTarget,
    });
    let sub = subcompositor.new_send_get_subsurface(&surface, &root);
    quiet(&*sub);
    let viewport = viewporter.new_send_get_viewport(&surface);
    quiet(&*viewport);
    viewport.send_set_destination(
        area.w.saturating_add(area.x.max(0)),
        area.h.saturating_add(area.y.max(0)),
    );
    let pool = shm.new_send_create_pool(white, 4);
    quiet(&*pool);
    let buffer = pool.new_send_create_buffer(0, 1, 1, 4, WlShmFormat::XRGB8888);
    quiet(&*buffer);
    pool.send_destroy();
    attach_whole(&surface, &buffer, 1, 1);
    sub.send_set_desync();
    surface.send_commit();
    // A newly created subsurface joins the parent's stack at its next
    // commit. Ask the application to commit without committing its pending
    // buffer state on its behalf.
    w.reconfigure(f);
    Some(Overlay {
        window: Rc::downgrade(window),
        strip: Strip {
            surface,
            sub,
            viewport,
        },
        buffer,
        area,
        pressed: false,
    })
}

pub(crate) fn select(seq: u8, token: u64, white: OwnedFd, frames: &[Rc<Frames>]) {
    TYPER.with_borrow_mut(|t| {
        t.cancel();
        t.target = None;
        let white = Rc::new(white);
        let overlays: Vec<_> = frames
            .iter()
            .flat_map(|f| {
                f.windows
                    .borrow()
                    .iter()
                    .filter_map(Weak::upgrade)
                    .filter_map(|w| overlay(&w, f, &white))
                    .collect::<Vec<_>>()
            })
            .collect();
        if overlays.is_empty() {
            t.replies.push_back(Reply::Nowhere(seq));
        } else {
            t.selection = Some(Selection {
                seq,
                token,
                overlays,
                until: Instant::now() + Duration::from_secs(120),
            });
        }
    });
}

pub(super) fn choose(
    window: &Rc<RefCell<Window>>,
    f: &Rc<Frames>,
    seat: &Rc<WlSeat>,
    pointer: &Rc<WlPointer>,
    state: &Rc<RefCell<PointerState>>,
    x: f64,
    y: f64,
    serial: u32,
    down: bool,
) {
    TYPER.with_borrow_mut(|t| {
        let Some(selection) = &mut t.selection else {
            return;
        };
        let Some(overlay) = selection
            .overlays
            .iter_mut()
            .find(|o| Weak::ptr_eq(&o.window, &Rc::downgrade(window)))
        else {
            return;
        };
        if down {
            overlay.pressed = true;
            return;
        }
        if !overlay.pressed || !x.is_finite() || !y.is_finite() {
            return;
        }
        if x < 0.0
            || y < 0.0
            || x >= f64::from(overlay.area.x.max(0) + overlay.area.w)
            || y >= f64::from(overlay.area.y.max(0) + overlay.area.h)
        {
            return;
        }
        let Some((kb, _, _, kb_state)) = t.keyboards.iter().find(|(kb, frame, s, state)| {
            kb.strong_count() > 0
                && Weak::ptr_eq(frame, &Rc::downgrade(f))
                && Weak::ptr_eq(s, &Rc::downgrade(seat))
                && state.borrow().keymap.is_some()
        }) else {
            let seq = selection.seq;
            t.selection = None;
            t.replies.push_back(Reply::Nowhere(seq));
            return;
        };
        let Some(root) = window
            .try_borrow()
            .ok()
            .and_then(|w| w.root.upgrade())
            .filter(programs)
        else {
            return;
        };
        t.target = Some(Target {
            token: selection.token,
            window: Rc::downgrade(window),
            root: Rc::downgrade(&root),
            area: overlay.area,
            pointer: Rc::downgrade(pointer),
            pointer_state: state.clone(),
            keyboard: kb.clone(),
            keyboard_state: kb_state.clone(),
            x,
            y,
            serial,
            until: Instant::now() + Duration::from_secs(300),
        });
        let seq = selection.seq;
        t.selection = None;
        t.replies.push_back(Reply::Chose(seq, 1));
    });
}

pub(crate) fn start(
    seq: u8,
    token: u64,
    timing: Timing,
    mode: Mode,
    text: &str,
    keymap: Option<OwnedFd>,
) {
    TYPER.with_borrow_mut(|t| {
        if t.target.as_ref().is_none_or(|v| v.token != token) {
            t.replies.push_back(Reply::Nowhere(seq));
            return;
        }
        let target = t
            .target
            .clone()
            .filter(|v| v.token == token && v.until > Instant::now() && target_alive(v));
        let plan = Plan::new(text, mode);
        match (target, plan) {
            (Some(target), Ok(plan))
                if timing.valid() && (plan.keymap.is_some() == keymap.is_some()) =>
            {
                t.run = Some(Run {
                    seq,
                    target,
                    plan,
                    keymap: keymap.map(Rc::new),
                    timing,
                    at: 0,
                    down: false,
                    began: false,
                    next: Instant::now() + Duration::from_millis(u64::from(timing.start_ms)),
                });
            }
            _ => t.replies.push_back(Reply::Nowhere(seq)),
        }
    });
}

fn target_alive(target: &Target) -> bool {
    target.root.upgrade().is_some_and(|s| programs(&s))
        && target.keyboard.strong_count() > 0
        && target.pointer.strong_count() > 0
        && target
            .window
            .upgrade()
            .is_some_and(|w| w.try_borrow().is_ok_and(|w| w.area() == Some(target.area)))
}

impl Run {
    fn begin(&mut self) -> bool {
        let (Some(kb), Some(pointer), Some(root)) = (
            self.target.keyboard.upgrade(),
            self.target.pointer.upgrade(),
            self.target.root.upgrade(),
        ) else {
            return false;
        };
        let p = self.target.pointer_state.borrow();
        if let Some(old) = p.surface.upgrade().filter(programs) {
            pointer.send_leave(self.target.serial, &old);
        }
        let x = Fixed::from_f64_lossy(self.target.x);
        let y = Fixed::from_f64_lossy(self.target.y);
        pointer.send_enter(self.target.serial, &root, x, y);
        pointer.send_motion(crate::clip::now_ms(), x, y);
        pointer.send_button(
            self.target.serial,
            crate::clip::now_ms(),
            BTN_LEFT,
            WlPointerButtonState::PRESSED,
        );
        pointer.send_button(
            self.target.serial,
            crate::clip::now_ms(),
            BTN_LEFT,
            WlPointerButtonState::RELEASED,
        );
        pointer.send_leave(self.target.serial, &root);
        if p.on {
            if let Some(old) = p.surface.upgrade().filter(programs) {
                pointer.send_enter(
                    p.serial,
                    &old,
                    Fixed::from_f64_lossy(p.x),
                    Fixed::from_f64_lossy(p.y),
                );
            }
        }
        if pointer.version() >= 5 {
            pointer.send_frame();
        }
        let state = self.target.keyboard_state.borrow();
        if state.on {
            if let Some(old) = state.surface.upgrade().filter(programs) {
                kb.send_leave(self.target.serial, &old);
            }
        }
        if let (Some(fd), Some(map)) = (&self.keymap, &self.plan.keymap) {
            kb.send_keymap(WlKeyboardKeymapFormat::XKB_V1, fd, map.len() as u32);
        }
        kb.send_enter(self.target.serial, &root, &[]);
        kb.send_modifiers(self.target.serial, 0, 0, 0, 0);
        self.began = true;
        true
    }

    fn restore(&mut self) {
        if !self.began {
            return;
        }
        let Some(kb) = self.target.keyboard.upgrade() else {
            return;
        };
        if self.down {
            if let Some(stroke) = self.plan.keys.get(self.at) {
                kb.send_key(
                    self.target.serial,
                    crate::clip::now_ms(),
                    stroke.key,
                    WlKeyboardKeyState::RELEASED,
                );
            }
        }
        let state = self.target.keyboard_state.borrow();
        if self.keymap.is_some() {
            if let Some((fd, size)) = &state.keymap {
                kb.send_keymap(WlKeyboardKeymapFormat::XKB_V1, fd, *size);
            }
        }
        if let Some(root) = self.target.root.upgrade().filter(programs) {
            kb.send_leave(self.target.serial, &root);
        }
        if state.on {
            if let Some(surface) = state.surface.upgrade().filter(programs) {
                kb.send_enter(state.serial, &surface, &[]);
            }
        }
        let (d, l, locked, g) = state.mods;
        kb.send_modifiers(state.serial, d, l, locked, g);
        self.began = false;
    }
}

impl Typer {
    fn cancel(&mut self) {
        if let Some(selection) = self.selection.take() {
            self.replies.push_back(Reply::Chose(selection.seq, 0));
        }
        if let Some(mut run) = self.run.take() {
            run.restore();
            self.replies.push_back(Reply::Chose(run.seq, 0));
        }
    }
}

pub(crate) fn retract(seq: u8) {
    TYPER.with_borrow_mut(|t| {
        if t.selection.as_ref().is_some_and(|s| s.seq == seq)
            || t.run.as_ref().is_some_and(|r| r.seq == seq)
        {
            t.cancel();
        }
    });
}

pub(crate) fn cancel_token(token: u64) {
    TYPER.with_borrow_mut(|t| {
        if t.selection.as_ref().is_some_and(|s| s.token == token)
            || t.run.as_ref().is_some_and(|r| r.target.token == token)
        {
            t.cancel();
        }
        if t.target.as_ref().is_some_and(|v| v.token == token) {
            t.target = None;
        }
    });
}

pub(super) fn key(kb: &Rc<WlKeyboard>, key: u32, pressed: bool) -> bool {
    TYPER.with_borrow_mut(|t| {
        if t.selection.is_some() {
            if key == KEY_ESC && pressed {
                t.cancel();
            }
            return true;
        }
        if t.run
            .as_ref()
            .is_some_and(|r| Weak::ptr_eq(&r.target.keyboard, &Rc::downgrade(kb)))
        {
            if pressed {
                t.cancel();
            }
            return true;
        }
        false
    })
}

pub(super) fn keyboard_changed(kb: &Rc<WlKeyboard>) -> bool {
    TYPER.with_borrow_mut(|t| {
        if t.run
            .as_ref()
            .is_some_and(|r| r.began && Weak::ptr_eq(&r.target.keyboard, &Rc::downgrade(kb)))
        {
            t.cancel();
            true
        } else {
            false
        }
    })
}

pub(super) fn suppress_modifiers(kb: &Rc<WlKeyboard>) -> bool {
    TYPER.with_borrow(|t| {
        t.run
            .as_ref()
            .is_some_and(|r| r.began && Weak::ptr_eq(&r.target.keyboard, &Rc::downgrade(kb)))
    })
}

pub(crate) fn wake_at() -> Option<Instant> {
    TYPER.with_borrow(|t| {
        [
            t.selection.as_ref().map(|s| s.until),
            t.run.as_ref().map(|r| r.next),
        ]
        .into_iter()
        .flatten()
        .min()
    })
}

pub(crate) fn tick(now: Instant) {
    TYPER.with_borrow_mut(|t| {
        if t.selection.as_ref().is_some_and(|s| {
            s.until <= now || s.overlays.iter().all(|o| o.window.strong_count() == 0)
        }) {
            t.cancel();
        }
        let Some(run) = &mut t.run else {
            return;
        };
        if !target_alive(&run.target) {
            t.cancel();
            return;
        }
        if run.next > now {
            return;
        }
        if !run.began && !run.begin() {
            t.cancel();
            return;
        }
        let Some(kb) = run.target.keyboard.upgrade() else {
            t.cancel();
            return;
        };
        let stroke = run.plan.keys[run.at];
        if !run.down {
            kb.send_modifiers(run.target.serial, u32::from(stroke.shift), 0, 0, 0);
            kb.send_key(
                run.target.serial,
                crate::clip::now_ms(),
                stroke.key,
                WlKeyboardKeyState::PRESSED,
            );
            run.down = true;
            run.next = now + Duration::from_millis(u64::from(run.timing.hold_ms));
        } else {
            kb.send_key(
                run.target.serial,
                crate::clip::now_ms(),
                stroke.key,
                WlKeyboardKeyState::RELEASED,
            );
            kb.send_modifiers(run.target.serial, 0, 0, 0, 0);
            run.down = false;
            run.at += 1;
            if run.at == run.plan.keys.len() {
                let mut run = t.run.take().expect("running above");
                run.restore();
                t.replies.push_back(Reply::Chose(run.seq, 1));
            } else {
                run.next = now + Duration::from_millis(u64::from(run.timing.between_ms));
            }
        }
    });
}

pub(crate) fn take() -> Vec<Reply> {
    TYPER.with_borrow_mut(|t| t.replies.drain(..).collect())
}

pub(crate) fn unavailable(seq: u8) {
    TYPER.with_borrow_mut(|t| t.replies.push_back(Reply::Nowhere(seq)));
}
