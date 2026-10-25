//! Keep a launch's native Wayland terminal and its Satellite on the same
//! clipboard offer, even while only the terminal has keyboard focus.
//!
//! Metadata is relayed only within this confined proxy process. Payloads
//! remain lazy and use the existing instance/paste-gesture check. This is
//! not host data-control and not the future cross-launch private broker.

use super::*;
use wl_proxy::protocols::wayland::wl_data_device_manager::WlDataDeviceManagerDndAction;

const MAX_DEVICES: usize = 128;
const MAX_TYPES: usize = 64;
const MAX_TYPE_BYTES: usize = 256;

#[derive(Clone)]
struct Selection {
    id: u64,
    device: Weak<WlDataDevice>,
    source: Rc<WlDataOffer>,
    own: bool,
    types: Rc<Vec<String>>,
}

impl Selection {
    fn alive(&self) -> bool {
        self.source.server_id().is_some() && !self.source.state().is_destroyed()
    }
}

#[derive(Default)]
struct Relay {
    devices: Vec<Weak<WlDataDevice>>,
    selection: Option<Selection>,
}

thread_local! {
    static RELAY: RefCell<Relay> = RefCell::new(Relay::default());
}

pub(super) fn register(device: &Rc<WlDataDevice>) {
    RELAY.with(|r| {
        let mut r = r.borrow_mut();
        r.devices
            .retain(|d| d.upgrade().is_some_and(|d| !d.state().is_destroyed()));
        if r.devices.len() < MAX_DEVICES {
            r.devices.push(Rc::downgrade(device));
            if let Some(s) = r.selection.as_ref().filter(|s| s.alive()) {
                announce(device, s);
            }
        }
    });
}

/// True when the upstream None was replaced by the current offer from a
/// different connection. A background Satellite receiving None must not
/// undo the offer just announced from the focused native terminal.
pub(super) fn selected(device: &Rc<WlDataDevice>, source: Option<&Rc<WlDataOffer>>) -> bool {
    let offered = source.and_then(|source| {
        let handler = source.get_handler_any_ref().ok()?;
        let handler = handler.downcast_ref::<Offer>()?;
        (!handler.relay_overflow).then(|| Selection {
            id: handler.id,
            device: Rc::downgrade(device),
            source: source.clone(),
            own: handler.own,
            types: Rc::new(handler.types.clone()),
        })
    });
    RELAY.with(|r| {
        let mut r = r.borrow_mut();
        if source.is_none() {
            if let Some(s) = r.selection.as_ref().filter(|s| s.alive()) {
                if s.device.upgrade().is_some_and(|d| !Rc::ptr_eq(&d, device)) {
                    announce(device, s);
                    return true;
                }
            }
        }
        r.selection = offered;
        r.devices
            .retain(|d| d.upgrade().is_some_and(|d| !d.state().is_destroyed()));
        for other in r.devices.iter().filter_map(Weak::upgrade) {
            if !Rc::ptr_eq(&other, device) {
                if let Some(s) = &r.selection {
                    announce(&other, s);
                } else {
                    other.send_selection(None);
                }
            }
        }
        false
    })
}

fn announce(device: &Rc<WlDataDevice>, selection: &Selection) {
    let offer = device.create_child::<WlDataOffer>();
    offer.set_handler(RelayedOffer {
        selection: selection.clone(),
    });
    device.send_data_offer(&offer);
    for mime in selection.types.iter() {
        offer.send_offer(mime);
    }
    device.send_selection(Some(&offer));
}

struct RelayedOffer {
    selection: Selection,
}

impl WlDataOfferHandler for RelayedOffer {
    fn handle_receive(&mut self, _: &Rc<WlDataOffer>, mime: &str, fd: &Rc<OwnedFd>) {
        let s = &self.selection;
        if s.alive()
            && s.types.iter().any(|t| t == mime)
            && crate::clip::may_read(s.own, crate::clip::Which::Clipboard, mime, s.id)
        {
            s.source.send_receive(mime, fd);
        }
    }

    // Synthetic offers have no upstream id. Their destructor is local,
    // never a destroy of the original offer another connection still uses.
    fn handle_destroy(&mut self, slf: &Rc<WlDataOffer>) {
        slf.delete_id();
    }
    fn handle_accept(&mut self, _: &Rc<WlDataOffer>, _: u32, _: Option<&str>) {}
    fn handle_finish(&mut self, _: &Rc<WlDataOffer>) {}
    fn handle_set_actions(
        &mut self,
        _: &Rc<WlDataOffer>,
        _: WlDataDeviceManagerDndAction,
        _: WlDataDeviceManagerDndAction,
    ) {
    }
}

pub(super) fn keep_type(types: &mut Vec<String>, overflow: &mut bool, mime: &str) {
    if *overflow || types.iter().any(|t| t == mime) {
        return;
    }
    if types.len() >= MAX_TYPES || mime.len() > MAX_TYPE_BYTES || mime.is_empty() {
        *overflow = true;
        types.clear();
    } else {
        types.push(mime.to_owned());
    }
}

/// A cosmetic frame is not required for the paste authorization boundary.
pub(super) fn watch_unframed(id: &Rc<dyn Object>) {
    if let Some(seat) = id.try_downcast::<WlSeat>() {
        seat.set_handler(UnframedSeat);
    }
}

struct UnframedSeat;

impl WlSeatHandler for UnframedSeat {
    fn handle_get_keyboard(&mut self, slf: &Rc<WlSeat>, id: &Rc<WlKeyboard>) {
        slf.send_get_keyboard(id);
        id.set_handler(UnframedKeyboard {
            paste: crate::clip::PasteKeys::default(),
            depressed: 0,
        });
    }
    fn handle_get_pointer(&mut self, slf: &Rc<WlSeat>, id: &Rc<WlPointer>) {
        slf.send_get_pointer(id);
        id.set_handler(UnframedPointer);
    }
}

struct UnframedKeyboard {
    paste: crate::clip::PasteKeys,
    depressed: u32,
}

impl WlKeyboardHandler for UnframedKeyboard {
    fn handle_keymap(
        &mut self,
        slf: &Rc<WlKeyboard>,
        format: WlKeyboardKeymapFormat,
        fd: &Rc<OwnedFd>,
        size: u32,
    ) {
        if format == WlKeyboardKeymapFormat::XKB_V1 {
            if let Some(text) = crate::clip::read_keymap(fd, size) {
                self.paste = crate::clip::paste_keys(&text);
            }
        }
        slf.send_keymap(format, fd, size);
    }
    fn handle_modifiers(
        &mut self,
        slf: &Rc<WlKeyboard>,
        serial: u32,
        depressed: u32,
        latched: u32,
        locked: u32,
        group: u32,
    ) {
        self.depressed = depressed;
        slf.send_modifiers(serial, depressed, latched, locked, group);
    }
    fn handle_key(
        &mut self,
        slf: &Rc<WlKeyboard>,
        serial: u32,
        time: u32,
        key: u32,
        state: WlKeyboardKeyState,
    ) {
        if state == WlKeyboardKeyState::PRESSED
            && crate::clip::is_paste(&self.paste, key, self.depressed)
        {
            crate::clip::pasting(crate::clip::Which::Clipboard);
        }
        slf.send_key(serial, time, key, state);
    }
}

struct UnframedPointer;

impl WlPointerHandler for UnframedPointer {
    fn handle_button(
        &mut self,
        slf: &Rc<WlPointer>,
        serial: u32,
        time: u32,
        button: u32,
        state: WlPointerButtonState,
    ) {
        if button == crate::clip::BTN_MIDDLE && state == WlPointerButtonState::PRESSED {
            crate::clip::pasting(crate::clip::Which::Primary);
        }
        slf.send_button(serial, time, button, state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_local_object_numbers_cannot_alias_clipboard_authorization() {
        // Each of these handlers can belong to a different wl-proxy State,
        // whose local unique_id counters can have the same numeric value.
        let first = Offer::default();
        let other = Offer::default();
        let primary = PrimaryOffer::default();
        assert_ne!(first.id, other.id);
        assert_ne!(first.id, primary.id);
        crate::clip::dragged(first.id);
        assert!(crate::clip::may_read(
            false,
            crate::clip::Which::Clipboard,
            "image/png",
            first.id
        ));
        assert!(!crate::clip::may_read(
            false,
            crate::clip::Which::Clipboard,
            "image/png",
            other.id
        ));
        assert!(!crate::clip::may_read(
            false,
            crate::clip::Which::Primary,
            "text/plain",
            primary.id
        ));
        crate::clip::history_offer(first.id);
        crate::clip::selection(Some(other.id));
        crate::clip::want_paste();
        assert!(
            !crate::clip::take_paste(),
            "history selection must not match another connection's offer"
        );
    }

    #[test]
    fn metadata_is_bounded_and_duplicate_types_do_not_consume_the_budget() {
        let (mut types, mut overflow) = (Vec::new(), false);
        for _ in 0..1000 {
            keep_type(&mut types, &mut overflow, "image/png");
        }
        assert_eq!(types, ["image/png"]);
        assert!(!overflow);
        for n in 0..MAX_TYPES {
            keep_type(
                &mut types,
                &mut overflow,
                &format!("application/x-test-{n}"),
            );
        }
        assert!(overflow);
        assert!(types.is_empty());
        keep_type(&mut types, &mut overflow, "text/plain");
        assert!(types.is_empty(), "overflow is sticky for this offer");
        let (mut types, mut overflow) = (Vec::new(), false);
        keep_type(&mut types, &mut overflow, &"x".repeat(MAX_TYPE_BYTES + 1));
        assert!(overflow);
        assert!(types.is_empty());
    }
}
