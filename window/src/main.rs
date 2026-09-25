//! `vpn-zone-window` — the launch window of vpn-zones: the network and the
//! container of a program, side by side, in one window.
//!
//! The picker (`vpn-zone-pick`) keeps every decision; this program only shows
//! the choices and brings back which ones were taken. It reads the request on
//! standard input and writes the answer on standard output — the contract is
//! `rust/src/window.rs` of vpn-zones, repeated here in `parse_request` and
//! `answer`. Exit status 0 is an answer; 1 is a close, Esc or Cancel, and
//! nothing is started.
//!
//! Keyboard: ←/→ or Tab switch the column, ↑/↓ or a digit choose in it, Space
//! ticks "always" of that column, Enter starts, Esc closes.
//!
//! A window a program in a zone brought up (`guard`, `pins`) takes no key and
//! starts nothing until the keyboard has been still for the guard's time — it
//! takes the focus, and a person still typing into something else would pick
//! a row with a digit and say yes with Enter — and has no "always": a program
//! there picks which launcher's name the window carries, and "always" for
//! that name would decide later launches from the menu. A container that is
//! open in another network (or belongs to one) cannot go with a different
//! network: it is shown greyed out with the reason, and the choice skips it.

use std::io::Read;

use iced::keyboard::{self, key, Key};
use iced::widget::{button, checkbox, column, container, row, scrollable, text, text_input};
use iced::{Alignment, Element, Length, Subscription, Task};

/// One row of a column, as the picker sent it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Item {
    tag: String,
    label: String,
    selected: bool,
    dead: bool,
    busy: Option<String>,
    bound: Option<String>,
    new: bool,
}

/// Everything the window shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Request {
    /// `menu`: the hotkey menu of a running program — entries, one of which
    /// is chosen. Anything else: the launch window.
    mode: String,
    /// The menu's entries: `(tag, label, danger)`.
    actions: Vec<(String, String, bool)>,
    title: String,
    notes: Vec<String>,
    nets: Vec<Item>,
    containers: Vec<Item>,
    pin_net: bool,
    pin_container: bool,
    /// For how long, in milliseconds, nothing is started (`guard⇥<ms>`).
    guard: u64,
    /// `pins⇥0`: no "always" checkboxes, and none ticked.
    no_pins: bool,
}

fn parse_item(fields: &[&str]) -> Option<Item> {
    let tag = (*fields.first()?).to_owned();
    let label = (*fields.get(1)?).to_owned();
    let mut item = Item {
        tag,
        label,
        ..Item::default()
    };
    for flag in fields.get(2).unwrap_or(&"").split(',') {
        match flag.split_once('=') {
            Some(("busy", zone)) => item.busy = Some(zone.to_owned()),
            Some(("bound", zone)) => item.bound = Some(zone.to_owned()),
            _ => match flag {
                "selected" => item.selected = true,
                "dead" => item.dead = true,
                "new" => item.new = true,
                _ => {}
            },
        }
    }
    Some(item)
}

/// The request: one line per item, fields separated by tabs.
fn parse_request(text: &str) -> Request {
    let mut req = Request::default();
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        match fields[0] {
            "mode" => req.mode = fields.get(1).unwrap_or(&"").to_string(),
            "action" if fields.len() >= 3 => req.actions.push((
                fields[1].to_owned(),
                fields[2].to_owned(),
                fields
                    .get(3)
                    .is_some_and(|f| f.split(',').any(|f| f == "danger")),
            )),
            "title" => req.title = fields.get(1).unwrap_or(&"").to_string(),
            "note" => req.notes.push(fields.get(1).unwrap_or(&"").to_string()),
            "net" => req.nets.extend(parse_item(&fields[1..])),
            "container" => req.containers.extend(parse_item(&fields[1..])),
            "pin-net" => req.pin_net = fields.get(1) == Some(&"1"),
            "pin-container" => req.pin_container = fields.get(1) == Some(&"1"),
            "guard" => req.guard = fields.get(1).and_then(|v| v.parse().ok()).unwrap_or(0),
            "pins" => req.no_pins = fields.get(1) == Some(&"0"),
            _ => {}
        }
    }
    if req.no_pins {
        req.pin_net = false;
        req.pin_container = false;
    }
    req
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pane {
    Net,
    Container,
}

#[derive(Debug, Clone)]
enum Msg {
    /// A menu entry, by its index.
    Action(usize),
    Net(usize),
    Container(usize),
    PinNet(bool),
    PinContainer(bool),
    Name(String),
    Launch,
    Cancel,
    Key(Key, keyboard::Modifiers),
    /// The guard's time is over, if no key came since this count of them:
    /// starting is possible.
    Armed(u64),
}

struct Window {
    req: Request,
    /// The highlighted menu entry.
    entry: usize,
    pane: Pane,
    net: usize,
    container: usize,
    pin_net: bool,
    pin_container: bool,
    name: String,
    /// False while the request's guard runs.
    armed: bool,
    /// Keys pressed while the guard ran: each one starts it again.
    held_keys: u64,
}

/// Why a container cannot go with this network, if it cannot.
fn blocked(item: &Item, net: &str) -> Option<String> {
    if let Some(zone) = item.busy.as_deref().filter(|z| *z != net) {
        return Some(format!("открыт в сети {zone}"));
    }
    if let Some(zone) = item.bound.as_deref().filter(|z| *z != net) {
        return Some(format!("привязан к сети {zone}"));
    }
    None
}

const NAME_FIELD: &str = "new-container-name";

impl Window {
    fn new(req: Request) -> Self {
        // Nothing marked: `offline`, never the first row (the host's network).
        let net = req
            .nets
            .iter()
            .position(|i| i.selected)
            .or_else(|| req.nets.iter().position(|i| i.tag == "offline"))
            .unwrap_or(0);
        let container = req.containers.iter().position(|i| i.selected).unwrap_or(0);
        Self {
            pin_net: req.pin_net,
            pin_container: req.pin_container,
            pane: Pane::Net,
            net,
            container,
            name: String::new(),
            entry: 0,
            armed: req.guard == 0,
            held_keys: 0,
            req,
        }
    }

    fn menu(&self) -> bool {
        self.req.mode == "menu"
    }

    fn net_tag(&self) -> &str {
        self.req.nets.get(self.net).map_or("", |i| i.tag.as_str())
    }

    fn container_ok(&self, i: usize) -> bool {
        self.req
            .containers
            .get(i)
            .is_some_and(|c| blocked(c, self.net_tag()).is_none())
    }

    /// Everything needed to start: a container that goes with the network, a
    /// name for a new one, and the guard's time over.
    fn ready(&self) -> bool {
        let Some(c) = self.req.containers.get(self.container) else {
            return false;
        };
        self.armed && self.container_ok(self.container) && (!c.new || !self.name.trim().is_empty())
    }

    fn naming(&self) -> bool {
        self.req
            .containers
            .get(self.container)
            .is_some_and(|c| c.new)
    }

    /// Move the choice in the focused column by `step`, skipping containers
    /// that cannot go with the network.
    fn step(&mut self, step: isize) {
        match self.pane {
            Pane::Net => {
                let n = self.req.nets.len() as isize;
                if n > 0 {
                    self.net = (self.net as isize + step).rem_euclid(n) as usize;
                }
            }
            Pane::Container => {
                let n = self.req.containers.len() as isize;
                let mut at = self.container as isize;
                for _ in 0..n {
                    at = (at + step).rem_euclid(n);
                    if self.container_ok(at as usize) {
                        self.container = at as usize;
                        break;
                    }
                }
            }
        }
    }

    fn pick(&mut self, index: usize) {
        match self.pane {
            Pane::Net if index < self.req.nets.len() => self.net = index,
            Pane::Container if self.container_ok(index) => self.container = index,
            _ => {}
        }
    }

    /// The answer, as the picker reads it.
    fn answer(&self) -> String {
        let mut out = format!("net\t{}\n", self.net_tag());
        let c = &self.req.containers[self.container];
        out.push_str(&format!("container\t{}\n", c.tag));
        if c.new {
            out.push_str(&format!(
                "name\t{}\n",
                self.name.trim().replace(['\t', '\n'], " ")
            ));
        }
        out.push_str(&format!("pin-net\t{}\n", u8::from(self.pin_net)));
        out.push_str(&format!(
            "pin-container\t{}\n",
            u8::from(self.pin_container)
        ));
        out
    }

    fn update(&mut self, msg: Msg) -> Task<Msg> {
        match msg {
            Msg::Action(i) => {
                if let Some((tag, _, _)) = self.req.actions.get(i) {
                    println!("action\t{tag}");
                    std::process::exit(0);
                }
            }
            Msg::Net(i) => {
                self.pane = Pane::Net;
                self.net = i;
            }
            Msg::Container(i) => {
                self.pane = Pane::Container;
                if self.container_ok(i) {
                    self.container = i;
                    if self.naming() {
                        return iced::widget::operation::focus(NAME_FIELD);
                    }
                }
            }
            Msg::PinNet(v) => self.pin_net = v && !self.req.no_pins,
            Msg::PinContainer(v) => self.pin_container = v && !self.req.no_pins,
            Msg::Armed(keys) => self.armed |= keys == self.held_keys,
            Msg::Name(name) => self.name = name,
            Msg::Launch => {
                if self.naming() && self.name.trim().is_empty() {
                    return iced::widget::operation::focus(NAME_FIELD);
                }
                if self.ready() {
                    print!("{}", self.answer());
                    std::process::exit(0);
                }
            }
            Msg::Cancel => std::process::exit(1),
            Msg::Key(key, modifiers) => return self.key(key, modifiers),
        }
        Task::none()
    }

    fn key(&mut self, key: Key, modifiers: keyboard::Modifiers) -> Task<Msg> {
        // Guarded: a key is somebody typing elsewhere — nothing, and the
        // guard from the start. Esc still closes.
        if !self.armed && key.as_ref() != Key::Named(key::Named::Escape) {
            self.held_keys += 1;
            return arm_after(self.req.guard, self.held_keys);
        }
        if self.menu() {
            let n = self.req.actions.len();
            match key.as_ref() {
                Key::Named(key::Named::Escape) => return self.update(Msg::Cancel),
                Key::Named(key::Named::Enter) => return self.update(Msg::Action(self.entry)),
                Key::Named(key::Named::ArrowUp) if n > 0 => self.entry = (self.entry + n - 1) % n,
                Key::Named(key::Named::ArrowDown) if n > 0 => self.entry = (self.entry + 1) % n,
                Key::Character(c) => {
                    if let Some(d) = c
                        .chars()
                        .next()
                        .and_then(|c| c.to_digit(10))
                        .filter(|d| *d > 0)
                    {
                        if (d as usize) <= n {
                            self.entry = d as usize - 1;
                        }
                    }
                }
                _ => {}
            }
            return Task::none();
        }
        match key.as_ref() {
            Key::Named(key::Named::Escape) => return self.update(Msg::Cancel),
            Key::Named(key::Named::Enter) => return self.update(Msg::Launch),
            Key::Named(key::Named::ArrowLeft) => self.pane = Pane::Net,
            Key::Named(key::Named::ArrowRight) => self.pane = Pane::Container,
            Key::Named(key::Named::Tab) => {
                self.pane = match (self.pane, modifiers.shift()) {
                    (Pane::Net, false) | (Pane::Container, true) => Pane::Container,
                    _ => Pane::Net,
                }
            }
            Key::Named(key::Named::ArrowUp) => self.step(-1),
            Key::Named(key::Named::ArrowDown) => self.step(1),
            Key::Named(key::Named::Space) if !self.req.no_pins => match self.pane {
                Pane::Net => self.pin_net = !self.pin_net,
                Pane::Container => self.pin_container = !self.pin_container,
            },
            Key::Character(c) => {
                if let Some(d) = c
                    .chars()
                    .next()
                    .and_then(|c| c.to_digit(10))
                    .filter(|d| *d > 0)
                {
                    self.pick(d as usize - 1);
                    if self.pane == Pane::Container && self.naming() {
                        return iced::widget::operation::focus(NAME_FIELD);
                    }
                }
            }
            _ => {}
        }
        Task::none()
    }

    fn column_view<'a>(
        &'a self,
        heading: &'a str,
        pane: Pane,
        items: &'a [Item],
        chosen: usize,
        on_pick: fn(usize) -> Msg,
    ) -> Element<'a, Msg> {
        let focused = self.pane == pane;
        let mut list = column![].spacing(2);
        for (i, item) in items.iter().enumerate() {
            let why = (pane == Pane::Container)
                .then(|| blocked(item, self.net_tag()))
                .flatten();
            let mark = if i == chosen { "●" } else { "○" };
            let number = if i < 9 {
                format!("{} ", i + 1)
            } else {
                "  ".to_owned()
            };
            let mut label = format!("{number}{mark} {}", item.label);
            if item.dead {
                label.push_str(" — туннель молчит");
            }
            if let Some(why) = &why {
                label.push_str(&format!(" — {why}"));
            }
            let style = if i == chosen && focused {
                button::primary
            } else if i == chosen {
                button::secondary
            } else {
                button::text
            };
            let b = button(text(label).size(14))
                .width(Length::Fill)
                .padding([4, 8])
                .style(style)
                .on_press_maybe(why.is_none().then(|| on_pick(i)));
            list = list.push(b);
        }
        let title = text(if focused {
            format!("▸ {heading}")
        } else {
            heading.to_owned()
        })
        .size(16);
        column![title, scrollable(list).height(Length::Fill)]
            .spacing(6)
            .width(Length::FillPortion(1))
            .into()
    }

    /// The hotkey menu: the program, what is known of it, the entries.
    fn view_menu(&self) -> Element<'_, Msg> {
        let mut page = column![text(&self.req.title).size(20)]
            .spacing(10)
            .padding(16);
        for note in &self.req.notes {
            page = page.push(text(note.as_str()).size(14));
        }
        let mut list = column![].spacing(4);
        for (i, (_, label, danger)) in self.req.actions.iter().enumerate() {
            let style = match (i == self.entry, *danger) {
                (true, true) => button::danger,
                (true, false) => button::primary,
                _ => button::text,
            };
            let mark = if *danger { "⚠ " } else { "" };
            list = list.push(
                button(text(format!("{} {mark}{label}", i + 1)).size(15))
                    .width(Length::Fill)
                    .padding([6, 10])
                    .style(style)
                    .on_press(Msg::Action(i)),
            );
        }
        page = page.push(list);
        page = page.push(
            row![
                container(text("")).width(Length::Fill),
                button(text("Закрыть меню  Esc").size(14))
                    .padding([6, 14])
                    .style(button::secondary)
                    .on_press(Msg::Cancel)
            ]
            .align_y(Alignment::Center),
        );
        page.into()
    }

    fn view(&self) -> Element<'_, Msg> {
        if self.menu() {
            return self.view_menu();
        }
        let nets = self.column_view("Сеть", Pane::Net, &self.req.nets, self.net, Msg::Net);
        let containers = self.column_view(
            "Контейнер",
            Pane::Container,
            &self.req.containers,
            self.container,
            Msg::Container,
        );
        let mut right = column![containers].spacing(8).width(Length::FillPortion(1));
        if self.naming() {
            right = right.push(
                text_input("Название (буквы, цифры, дефис)", &self.name)
                    .id(NAME_FIELD)
                    .on_input(Msg::Name)
                    .on_submit(Msg::Launch)
                    .padding(6),
            );
        }
        let mut left = column![nets].spacing(8).width(Length::FillPortion(1));
        if !self.req.no_pins {
            right = right.push(
                checkbox(self.pin_container)
                    .label("Всегда этот контейнер")
                    .on_toggle(Msg::PinContainer),
            );
            left = left.push(
                checkbox(self.pin_net)
                    .label("Всегда эту сеть")
                    .on_toggle(Msg::PinNet),
            );
        }

        // The program's name inside the window too: niri draws no title bars.
        let mut page = column![text(&self.req.title).size(20)]
            .spacing(12)
            .padding(16);
        for note in &self.req.notes {
            page = page.push(text(format!("ⓘ {note}")).size(14));
        }
        page = page.push(row![left, right].spacing(16).height(Length::Fill));
        let launch = button(
            text(if self.armed {
                "Запустить  Enter"
            } else {
                "Секунду…"
            })
            .size(14),
        )
        .padding([6, 14])
        .style(button::primary)
        .on_press_maybe(self.ready().then_some(Msg::Launch));
        let cancel = button(text("Отмена  Esc").size(14))
            .padding([6, 14])
            .style(button::secondary)
            .on_press(Msg::Cancel);
        page = page.push(
            row![container(text("")).width(Length::Fill), launch, cancel]
                .spacing(10)
                .align_y(Alignment::Center),
        );
        page.into()
    }

    fn subscription(&self) -> Subscription<Msg> {
        keyboard::listen().filter_map(|event| match event {
            keyboard::Event::KeyPressed { key, modifiers, .. } => Some(Msg::Key(key, modifiers)),
            _ => None,
        })
    }
}

/// `Msg::Armed(keys)` after `guard` milliseconds: a plain sleep on the
/// executor's pool — no timer backend in this build, and the pool has threads
/// to spare for it.
fn arm_after(guard: u64, keys: u64) -> Task<Msg> {
    let guard = std::time::Duration::from_millis(guard);
    Task::perform(async move { std::thread::sleep(guard) }, move |()| {
        Msg::Armed(keys)
    })
}

fn main() -> iced::Result {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        std::process::exit(1);
    }
    let req = parse_request(&input);
    // Nothing to choose from is not a window: the caller falls back.
    let empty = if req.mode == "menu" {
        req.actions.is_empty()
    } else {
        req.nets.is_empty() || req.containers.is_empty()
    };
    if empty {
        std::process::exit(1);
    }
    let size = if req.mode == "menu" {
        iced::Size::new(520.0, 380.0)
    } else {
        iced::Size::new(760.0, 460.0)
    };
    let title = if req.title.is_empty() {
        "Запуск".to_owned()
    } else {
        req.title.clone()
    };
    let boot = std::sync::Mutex::new(Some(req));
    iced::application(
        move || {
            let req = boot
                .lock()
                .ok()
                .and_then(|mut r| r.take())
                .unwrap_or_default();
            let window = Window::new(req);
            let arm = if window.armed {
                Task::none()
            } else {
                arm_after(window.req.guard, 0)
            };
            (window, arm)
        },
        Window::update,
        Window::view,
    )
    .title(move |_: &Window| title.clone())
    // None: the system's colour scheme decides, light or dark.
    .theme(|_: &Window| None::<iced::Theme>)
    .subscription(Window::subscription)
    .window(iced::window::Settings {
        size,
        position: iced::window::Position::Centered,
        // The name a compositor's window rule matches — to float it in a
        // tiling one, say. Without it the window has no app id at all.
        #[cfg(target_os = "linux")]
        platform_specific: iced::window::settings::PlatformSpecific {
            application_id: "vpn-zone-window".to_owned(),
            ..Default::default()
        },
        ..iced::window::Settings::default()
    })
    .run()
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST: &str = "title\tЗапуск: Firefox\nnote\tуже работает\n\
        net\tunconfined\tБез ограничений\t\nnet\toffline\tБез сети\t\nnet\tnl\tVPN: nl\tselected\n\
        net\tde\tVPN: de\tdead\n\
        container\t\tОсновной\t\ncontainer\t__ownsb__\tСвоя песочница\tselected\n\
        container\twork\tПрофиль work\tbusy=de\ncontainer\t__newsb__\tНовая песочница…\tnew\n\
        pin-net\t1\npin-container\t0\n";

    #[test]
    fn the_request_is_read_as_the_picker_writes_it() {
        let req = parse_request(REQUEST);
        assert_eq!(req.title, "Запуск: Firefox");
        assert_eq!(req.notes, ["уже работает"]);
        assert_eq!(req.nets.len(), 4);
        assert!(req.nets[2].selected && req.nets[3].dead);
        assert_eq!(req.containers[0].tag, "");
        assert_eq!(req.containers[2].busy.as_deref(), Some("de"));
        assert!(req.containers[3].new);
        assert!(req.pin_net && !req.pin_container);
    }

    #[test]
    fn the_keyboard_chooses_and_the_answer_is_what_was_chosen() {
        let mut w = Window::new(parse_request(REQUEST));
        assert_eq!((w.net, w.container), (2, 1));
        // A container open in another network is skipped while nl is chosen.
        w.pane = Pane::Container;
        w.step(1);
        assert_eq!(w.container, 3, "work (busy in de) is skipped");
        // ...and becomes reachable when its network is chosen.
        w.pane = Pane::Net;
        w.pick(3);
        w.pane = Pane::Container;
        w.pick(2);
        assert_eq!(w.container, 2);
        let _ = w.key(
            Key::Named(key::Named::Space),
            keyboard::Modifiers::default(),
        );
        assert_eq!(
            w.answer(),
            "net\tde\ncontainer\twork\npin-net\t1\npin-container\t1\n"
        );
    }

    #[test]
    fn the_menu_is_read_and_walked_with_the_keyboard() {
        let req = parse_request(
            "mode\tmenu\ntitle\tFirefox\nnote\tсеть nl\n\
             action\tpin\tВсегда в nl\t\naction\tkill-zone\tОборвать nl\tdanger\n",
        );
        assert_eq!(req.mode, "menu");
        assert_eq!(
            req.actions,
            [
                ("pin".to_owned(), "Всегда в nl".to_owned(), false),
                ("kill-zone".to_owned(), "Оборвать nl".to_owned(), true)
            ]
        );
        let mut w = Window::new(req);
        assert!(w.menu());
        let _ = w.key(
            Key::Named(key::Named::ArrowDown),
            keyboard::Modifiers::default(),
        );
        assert_eq!(w.entry, 1);
        let _ = w.key(
            Key::Named(key::Named::ArrowDown),
            keyboard::Modifiers::default(),
        );
        assert_eq!(w.entry, 0, "round");
        let _ = w.key(Key::Character("2".into()), keyboard::Modifiers::default());
        assert_eq!(w.entry, 1);
    }

    /// A window a zone's program brought up: nothing starts during the guard,
    /// and there is no "always" to tick.
    #[test]
    fn a_guarded_window_starts_nothing_at_first_and_has_no_always() {
        let req = parse_request(&format!("{REQUEST}guard\t1500\npins\t0\n"));
        assert_eq!(req.guard, 1500);
        assert!(req.no_pins && !req.pin_net, "a pin sent along is dropped");
        let mut w = Window::new(req);
        assert!(!w.armed && !w.ready());
        let _ = w.key(
            Key::Named(key::Named::Space),
            keyboard::Modifiers::default(),
        );
        let _ = w.update(Msg::PinContainer(true));
        assert!(!w.pin_net && !w.pin_container);
        // Somebody still typing: a digit picks nothing, Enter starts nothing,
        // and the guard that was running no longer arms the window.
        let _ = w.key(Key::Character("1".into()), keyboard::Modifiers::default());
        assert_eq!(w.net, 2, "a digit during the guard picked a row");
        let _ = w.key(
            Key::Named(key::Named::Enter),
            keyboard::Modifiers::default(),
        );
        let _ = w.update(Msg::Armed(0));
        assert!(!w.armed, "a key came after that guard began");
        let _ = w.update(Msg::Armed(w.held_keys));
        assert!(w.ready());
        assert!(w.answer().ends_with("pin-net\t0\npin-container\t0\n"));
    }

    #[test]
    fn a_new_container_needs_a_name_before_anything_starts() {
        let mut w = Window::new(parse_request(REQUEST));
        w.pane = Pane::Container;
        w.pick(3);
        assert!(w.naming() && !w.ready());
        w.name = "  общая  ".to_owned();
        assert!(w.ready());
        assert!(w.answer().contains("container\t__newsb__\nname\tобщая\n"));
    }
}
