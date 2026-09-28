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
//! A window a program in a zone brought up (`guard`, `pins`, `asker`) takes
//! nothing — no key, no click, no choice — until the person has been still
//! for the guard's time with the window focused: it takes the focus when the
//! program likes, and somebody still typing or clicking into something else
//! must not pick a row and say yes. Every key and every press starts the
//! guard again, captured by a widget or not, and so does the focus coming
//! back. There, Enter starts only in the network that asks; another network
//! takes a click on the button that names it, after the guard once more (a
//! changed choice restarts it); digits choose nothing. And it has no
//! "always": a program there picks which launcher's name the window carries,
//! and "always" for that name would decide later launches from the menu.
//! The command it asks to run is its own block, word by word and numbered,
//! apart from the window's notes. A container that is
//! open in another network (or belongs to one) cannot go with a different
//! network: it is shown greyed out with the reason, and the choice skips it.
//!
//! The window's height fits what it shows. It opens at a guess, measures
//! its lists once they are laid out — what is in view of each and all of it
//! — and asks once for the height that shows them whole, no taller than
//! most of its screen: no empty band under a short list, no scroll bar on a
//! list that would fit (`Window::measured`). Nothing it shows changes height
//! afterwards: the name of a new container is typed next to the buttons,
//! and "Секунду…" of a menu stands beside its close button.

use std::io::Read;

use iced::keyboard::{self, key, Key};
use iced::widget::{
    button, checkbox, column, container, row, scrollable, sensor, text, text_input,
};
use iced::{Alignment, Element, Length, Size, Subscription, Task};

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
    /// is chosen; with a `guard` it is a question (the broker's, the
    /// microphone's): nothing is taken until the person has been still with
    /// it focused, Enter gives the highlighted entry, any other key starts
    /// the guard again, digits choose nothing. Anything else: the launch
    /// window.
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
    /// `asker⇥<net>`: the network of the zone that asks — Enter starts only
    /// there.
    asker: Option<String>,
    /// `program⇥<text>`: what the command's first word is on the host.
    program: String,
    /// `cmd⇥<word>`: the command, one word each.
    command: Vec<String>,
    /// `rule⇥<text>`: a checkbox of its own, unticked — a container's rule
    /// for links; answered `rule⇥0|1`.
    rule: Option<String>,
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
            "asker" => req.asker = fields.get(1).map(|v| v.to_string()),
            "program" => req.program = fields.get(1).unwrap_or(&"").to_string(),
            "cmd" => req.command.push(fields.get(1).unwrap_or(&"").to_string()),
            "rule" => {
                req.rule = fields
                    .get(1)
                    .map(|v| v.to_string())
                    .filter(|v| !v.is_empty())
            }
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

/// A list of the window that scrolls when it is longer than its place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum List {
    /// The menu's notes.
    Notes,
    /// The launch window's columns.
    Nets,
    Containers,
}

impl List {
    fn of(pane: Pane) -> Self {
        match pane {
            Pane::Net => Self::Nets,
            Pane::Container => Self::Containers,
        }
    }
}

/// What the window measures of itself to fit its height (`Window::measured`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Measure {
    /// The whole page: the window's inside, as it was laid out.
    Page,
    /// As much of a list as its place shows…
    View(List),
    /// …and all of it.
    Content(List),
}

/// The height the window never fits below, and the one it does not grow past
/// by itself (less where the screen is smaller: `resize_to`).
const MIN_HEIGHT: f32 = 160.0;
const MAX_HEIGHT: f32 = 760.0;

#[derive(Debug, Clone)]
enum Msg {
    /// A menu entry, by its index.
    Action(usize),
    Net(usize),
    Container(usize),
    PinNet(bool),
    PinContainer(bool),
    Rule(bool),
    Name(String),
    Launch,
    Cancel,
    /// A key, and whether a widget took it already.
    Key(Key, keyboard::Modifiers, bool),
    /// A mouse button pressed anywhere in the window.
    Press,
    /// The window got (`true`) or lost the focus.
    Focus(bool),
    /// The guard's time is over, if nothing came since this count of
    /// holds: taking a choice is possible.
    Armed(u64),
    /// A part of the window as it came out laid out.
    Measured(Measure, Size),
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
    /// The request's rule ticked.
    rule: bool,
    name: String,
    /// False while the request's guard runs.
    armed: bool,
    /// How many times the guard was started: only the last one arms.
    holds: u64,
    /// The window has the keyboard's focus: a guarded window arms only
    /// then — its guard is counted from when the person can see it, and a
    /// window that never gets the focus never takes a choice.
    focused: bool,
    /// What was measured for the fit: the page, and each list's place and
    /// length (by `List as usize`).
    page: Option<Size>,
    views: [Option<f32>; 3],
    contents: [Option<f32>; 3],
    /// The fit was asked for: it is asked once.
    fitted: bool,
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
            rule: false,
            pane: Pane::Net,
            net,
            container,
            name: String::new(),
            entry: 0,
            armed: req.guard == 0,
            holds: 0,
            focused: false,
            page: None,
            views: [None; 3],
            contents: [None; 3],
            fitted: false,
            req,
        }
    }

    fn menu(&self) -> bool {
        self.req.mode == "menu"
    }

    /// The lists this window shows.
    fn lists(&self) -> &'static [List] {
        if self.menu() {
            &[List::Notes]
        } else {
            &[List::Nets, List::Containers]
        }
    }

    /// A measure taken; the size that shows every list whole once all of
    /// them are in. The page grows by what its longest list lacks, or
    /// shrinks by what it leaves over — as laid out, not guessed from the
    /// fonts. Asked once: `None` before and after.
    fn measured(&mut self, what: Measure, size: Size) -> Option<Size> {
        match what {
            Measure::Page => self.page = Some(size),
            Measure::View(list) => self.views[list as usize] = Some(size.height),
            Measure::Content(list) => self.contents[list as usize] = Some(size.height),
        }
        if self.fitted {
            return None;
        }
        let page = self.page?;
        let mut lack = f32::NEG_INFINITY;
        for list in self.lists() {
            let i = *list as usize;
            lack = lack.max(self.contents[i]? - self.views[i]?);
        }
        self.fitted = true;
        let height = (page.height + lack).ceil().clamp(MIN_HEIGHT, MAX_HEIGHT);
        ((height - page.height).abs() >= 1.0).then_some(Size::new(page.width, height))
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
        if self.req.rule.is_some() {
            out.push_str(&format!("rule\t{}\n", u8::from(self.rule)));
        }
        out
    }

    fn guarded(&self) -> bool {
        self.req.guard > 0
    }

    /// The guard, from the start: nothing is taken until it is over.
    fn hold(&mut self) -> Task<Msg> {
        self.armed = false;
        self.holds += 1;
        arm_after(self.req.guard, self.holds)
    }

    /// Whether Enter may start: anywhere in an ordinary window, only in the
    /// asking network in a zone's.
    fn enter_starts(&self) -> bool {
        self.req
            .asker
            .as_deref()
            .is_none_or(|a| a == self.net_tag())
    }

    fn update(&mut self, msg: Msg) -> Task<Msg> {
        // A guarded window takes no choice before the guard is over: the
        // input is somebody's elsewhere, and the guard starts again.
        if self.guarded() && !self.armed {
            match msg {
                Msg::Net(_)
                | Msg::Container(_)
                | Msg::PinNet(_)
                | Msg::PinContainer(_)
                | Msg::Name(_)
                | Msg::Launch
                | Msg::Action(_)
                | Msg::Press => return self.hold(),
                Msg::Key(ref key, _, _) if key.as_ref() != Key::Named(key::Named::Escape) => {
                    return self.hold()
                }
                _ => {}
            }
        }
        match msg {
            Msg::Action(i) => {
                if let Some((tag, _, _)) = self.req.actions.get(i) {
                    println!("action\t{tag}");
                    std::process::exit(0);
                }
            }
            Msg::Net(i) => {
                self.pane = Pane::Net;
                let changed = self.net != i;
                self.net = i;
                if changed && self.guarded() {
                    return self.hold();
                }
            }
            Msg::Container(i) => {
                self.pane = Pane::Container;
                if self.container_ok(i) {
                    let changed = self.container != i;
                    self.container = i;
                    if changed && self.guarded() {
                        return self.hold();
                    }
                    if self.naming() {
                        return iced::widget::operation::focus(NAME_FIELD);
                    }
                }
            }
            Msg::PinNet(v) => self.pin_net = v && !self.req.no_pins,
            Msg::PinContainer(v) => self.pin_container = v && !self.req.no_pins,
            Msg::Rule(v) => self.rule = v && self.req.rule.is_some(),
            // Armed by the last guard started, and only with the focus.
            Msg::Armed(holds) => self.armed |= holds == self.holds && self.focused,
            Msg::Measured(what, size) => {
                if let Some(fit) = self.measured(what, size) {
                    return resize_to(fit);
                }
            }
            Msg::Press => {}
            // Losing the focus disarms; getting it starts the guard — the
            // first time too: nothing counts from the window's start.
            Msg::Focus(focused) if self.guarded() => {
                self.focused = focused;
                if focused {
                    return self.hold();
                }
                self.armed = false;
                self.holds += 1;
            }
            Msg::Focus(focused) => self.focused = focused,
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
            // A key a widget took (the name field) is the widget's.
            Msg::Key(key, _, true) if key.as_ref() != Key::Named(key::Named::Escape) => {}
            Msg::Key(key, modifiers, _) => return self.key(key, modifiers),
        }
        Task::none()
    }

    fn key(&mut self, key: Key, modifiers: keyboard::Modifiers) -> Task<Msg> {
        if self.menu() && self.guarded() {
            // A question: Enter gives the highlighted answer, Esc refuses;
            // any other key — typing meant for something else, or a move of
            // the highlight — starts the guard again, so no key typed on can
            // pick an answer. Digits choose nothing.
            let n = self.req.actions.len();
            return match key.as_ref() {
                Key::Named(key::Named::Escape) => self.update(Msg::Cancel),
                Key::Named(key::Named::Enter) => self.update(Msg::Action(self.entry)),
                Key::Named(key::Named::ArrowUp) if n > 0 => {
                    self.entry = (self.entry + n - 1) % n;
                    self.hold()
                }
                Key::Named(key::Named::ArrowDown) if n > 0 => {
                    self.entry = (self.entry + 1) % n;
                    self.hold()
                }
                _ => self.hold(),
            };
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
        let before = (self.net, self.container);
        let typing = matches!(key.as_ref(), Key::Character(_));
        let task = self.key_choose(key, modifiers);
        // A choice changed by the keyboard in a zone's window, or typing
        // meant for something else: the guard again.
        if self.guarded() && ((self.net, self.container) != before || typing) {
            return self.hold();
        }
        task
    }

    fn key_choose(&mut self, key: Key, modifiers: keyboard::Modifiers) -> Task<Msg> {
        match key.as_ref() {
            Key::Named(key::Named::Escape) => return self.update(Msg::Cancel),
            Key::Named(key::Named::Enter) if self.enter_starts() => {
                return self.update(Msg::Launch)
            }
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
            // Digits choose nothing in a zone's window.
            Key::Character(c) if self.req.asker.is_none() => {
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
        column![title, list_view(List::of(pane), list)]
            .spacing(6)
            .width(Length::FillPortion(1))
            .into()
    }

    /// The hotkey menu, or a question (guarded): the title, what is known
    /// (in a block that scrolls and breaks any word, so that nothing of it is
    /// cut off out of sight), the command apart where there is one, and the
    /// entries — always in view.
    fn view_menu(&self) -> Element<'_, Msg> {
        let mut page = column![text(&self.req.title).size(20)]
            .spacing(10)
            .padding(16);
        let mut notes = column![].spacing(4);
        for note in &self.req.notes {
            notes = notes.push(
                text(note.as_str())
                    .size(14)
                    .wrapping(iced::widget::text::Wrapping::WordOrGlyph),
            );
        }
        page = page.push(list_view(List::Notes, notes));
        if !self.req.command.is_empty() {
            page = page.push(self.command_view());
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
        // "Секунду…" beside the close button, not a line of its own: the
        // notes above keep the height the window was fitted to.
        let wait = if self.armed { "" } else { "Секунду…" };
        page = page.push(
            row![
                container(text(wait).size(13)).width(Length::Fill),
                button(text("Закрыть меню  Esc").size(14))
                    .padding([6, 14])
                    .style(button::secondary)
                    .on_press(Msg::Cancel)
            ]
            .align_y(Alignment::Center),
        );
        measured_page(page)
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
        // The containers' words are the longer ones: their column is wider.
        let mut right = column![containers].spacing(8).width(Length::FillPortion(3));
        let mut left = column![nets].spacing(8).width(Length::FillPortion(2));
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
        if !self.req.command.is_empty() {
            page = page.push(self.command_view());
        }
        page = page.push(row![left, right].spacing(16).height(Length::Fill));
        if let Some(rule) = &self.req.rule {
            page = page.push(checkbox(self.rule).label(rule).on_toggle(Msg::Rule));
        }
        let label = if !self.armed {
            "Секунду…".to_owned()
        } else if self.enter_starts() {
            "Запустить  Enter".to_owned()
        } else {
            let net = self.req.nets.get(self.net).map_or("", |n| n.label.as_str());
            format!("Запустить: {net}")
        };
        let launch = button(text(label).size(14))
            .padding([6, 14])
            .style(button::primary)
            .on_press_maybe(self.ready().then_some(Msg::Launch));
        let cancel = button(text("Отмена  Esc").size(14))
            .padding([6, 14])
            .style(button::secondary)
            .on_press(Msg::Cancel);
        // The name of a new container beside the buttons that start it: the
        // same height as they are, so the lists above keep their place.
        let lead: Element<'_, Msg> = if self.naming() {
            text_input("Название контейнера (буквы, цифры, дефис)", &self.name)
                .id(NAME_FIELD)
                .on_input(Msg::Name)
                .on_submit(Msg::Launch)
                .size(14)
                .padding(6)
                .width(Length::Fill)
                .into()
        } else {
            container(text("")).width(Length::Fill).into()
        };
        page = page.push(
            row![lead, launch, cancel]
                .spacing(10)
                .align_y(Alignment::Center),
        );
        measured_page(page)
    }

    /// The command a zone's program asks to run: apart from the notes, the
    /// program as the host finds it, then every word numbered, in a block of
    /// its own height that scrolls — the lists and the buttons stay in view
    /// however long it is, and a long word breaks instead of running off.
    fn command_view(&self) -> Element<'_, Msg> {
        let mut words = column![].spacing(2);
        for (i, word) in self.req.command.iter().enumerate() {
            words = words.push(
                text(format!("{:>2}. {word}", i + 1))
                    .size(13)
                    .wrapping(iced::widget::text::Wrapping::WordOrGlyph),
            );
        }
        let mut block = column![text("Команда").size(15)].spacing(4);
        if !self.req.program.is_empty() {
            block = block.push(
                text(format!("Программа: {}", self.req.program))
                    .size(13)
                    .wrapping(iced::widget::text::Wrapping::WordOrGlyph),
            );
        }
        block = block.push(scrollable(words).height(Length::Fixed(110.0)));
        container(block)
            .padding(8)
            .width(Length::Fill)
            .style(container::bordered_box)
            .into()
    }

    fn subscription(&self) -> Subscription<Msg> {
        iced::event::listen_with(|event, status, _window| match event {
            iced::Event::Keyboard(keyboard::Event::KeyPressed { key, modifiers, .. }) => Some(
                Msg::Key(key, modifiers, status == iced::event::Status::Captured),
            ),
            iced::Event::Mouse(iced::mouse::Event::ButtonPressed(_)) => Some(Msg::Press),
            iced::Event::Window(iced::window::Event::Focused) => Some(Msg::Focus(true)),
            iced::Event::Window(iced::window::Event::Unfocused) => Some(Msg::Focus(false)),
            _ => None,
        })
    }
}

/// A list in a place of its own that scrolls when it is longer, measured for
/// the fit: the place as it is, and the list whole — the container between
/// them lays the list out loose, at its own height rather than the place's.
fn list_view<'a>(list: List, rows: impl Into<Element<'a, Msg>>) -> Element<'a, Msg> {
    let rows: Element<'a, Msg> = sensor(rows)
        .on_show(move |size| Msg::Measured(Measure::Content(list), size))
        .into();
    sensor(scrollable(container(rows)).height(Length::Fill))
        .on_show(move |size| Msg::Measured(Measure::View(list), size))
        .into()
}

/// The page, measured for the fit: the window's inside as it was laid out.
fn measured_page<'a>(page: impl Into<Element<'a, Msg>>) -> Element<'a, Msg> {
    sensor(page)
        .on_show(|size| Msg::Measured(Measure::Page, size))
        .into()
}

/// The window resized to `size` — no taller than most of its screen, where
/// the screen is known.
fn resize_to(size: Size) -> Task<Msg> {
    iced::window::latest().and_then(move |id| {
        iced::window::monitor_size(id).then(move |screen| {
            let height = screen.map_or(size.height, |s| size.height.min(s.height * 0.9));
            iced::window::resize(id, Size::new(size.width, height.max(MIN_HEIGHT)))
        })
    })
}

/// `Msg::Armed(holds)` after `guard` milliseconds: slept on a thread of its
/// own, awaited on the executor — never on the executor's pool, which also
/// carries the input events: a sleep there would hold keys typed during the
/// guard until after it, and they would count as typed when armed.
fn arm_after(guard: u64, holds: u64) -> Task<Msg> {
    let guard = std::time::Duration::from_millis(guard);
    Task::perform(
        async move {
            let (done, over) = iced::futures::channel::oneshot::channel();
            std::thread::spawn(move || {
                std::thread::sleep(guard);
                let _ = done.send(());
            });
            let _ = over.await;
        },
        move |()| Msg::Armed(holds),
    )
}

/// The size the window opens at, before it measures itself: the width of its
/// kind, and a height guessed from what it shows — lines of text at about
/// the width they wrap at, at the sizes they are drawn (a line is 1.3 of its
/// size in iced), with the paddings and the spaces between. The fit corrects
/// the guess (`Window::measured`); a close one only keeps the window from
/// jumping away from the middle of the screen, where it was placed.
fn first_size(req: &Request) -> Size {
    let lines = |text: &str, per_line: usize| text.chars().count().div_ceil(per_line).max(1) as f32;
    let command = if req.command.is_empty() { 0.0 } else { 180.0 };
    let (width, height) = if req.mode == "menu" {
        let notes: f32 = req.notes.iter().map(|n| lines(n, 64) * 18.2 + 4.0).sum();
        let entries: f32 = req
            .actions
            .iter()
            .map(|(_, label, _)| lines(label, 56) * 19.5 + 16.0)
            .sum();
        let width = if req.command.is_empty() { 560.0 } else { 640.0 };
        // Padding, title, notes, command, entries, the close button, and
        // the spaces between them.
        (width, 32.0 + 26.0 + notes + command + entries + 30.0 + 40.0)
    } else {
        let rows = |items: &[Item], per_line: usize| -> f32 {
            items
                .iter()
                .map(|i| lines(&i.label, per_line) * 18.2 + 10.0)
                .sum()
        };
        let list = rows(&req.nets, 36).max(rows(&req.containers, 55));
        let notes = req.notes.len() as f32 * 31.0;
        let rule = if req.rule.is_some() { 33.0 } else { 0.0 };
        // Padding, title, notes, command, the columns' headings and
        // checkboxes, the longer list, the rule, the buttons, the spaces.
        (
            840.0,
            32.0 + 26.0 + notes + command + 56.0 + list + rule + 30.0 + 24.0,
        )
    };
    Size::new(width, height.clamp(MIN_HEIGHT, 640.0))
}

/// The exit status of a window that could not be shown at all: the caller
/// asks another way (kdialog) — not a "no".
const EXIT_NOT_SHOWN: i32 = 3;

fn main() -> iced::Result {
    // The fonts of this window: a short list of its own (package.nix), not
    // every font of the system — iced reads all it is given at each start,
    // over a thousand on a desktop, seconds under load. Set before anything
    // starts a thread.
    if let Some(fonts) = option_env!("VPN_ZONE_WINDOW_FONTS") {
        std::env::set_var("FONTCONFIG_FILE", fonts);
    }
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
    let size = first_size(&req);
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
            // A guarded window arms from its focus, not from its start
            // (`Msg::Focus`).
            (Window::new(req), Task::none())
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
    .map_err(|e| {
        eprintln!("vpn-zone-window: {e}");
        std::process::exit(EXIT_NOT_SHOWN)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST: &str = "title\tЗапуск: Firefox\nnote\tуже работает\n\
        net\tunconfined\tБез ограничений\t\nnet\toffline\tБез сети\t\nnet\tnl\tVPN: nl\tselected\n\
        net\tde\tVPN: de\tdead\n\
        container\t\tОсновной дом\t\ncontainer\t__ownsb__\tСвой контейнер\tselected\n\
        container\twork\tКонтейнер «work» — слой над домом\tbusy=de\n\
        container\t__newsb__\tНовый контейнер со своим домом…\tnew\n\
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
    fn press(w: &mut Window, key: Key) {
        let _ = w.update(Msg::Key(key, keyboard::Modifiers::default(), false));
    }

    /// The guard over with the window focused: focused first where it is
    /// not — a guard arms only with the focus.
    fn arm(w: &mut Window) {
        if !w.focused {
            let _ = w.update(Msg::Focus(true));
        }
        let _ = w.update(Msg::Armed(w.holds));
    }

    /// A window a zone's program brought up takes nothing until the guard is
    /// over — no key, no click, no choice — and every one of them, captured
    /// by a widget or not, and the focus coming back start it again. There is
    /// no "always" to tick.
    #[test]
    fn a_guarded_window_takes_nothing_until_the_person_is_still() {
        let req = parse_request(&format!("{REQUEST}guard\t1500\npins\t0\n"));
        assert_eq!(req.guard, 1500);
        assert!(req.no_pins && !req.pin_net, "a pin sent along is dropped");
        let mut w = Window::new(req);
        assert!(!w.armed && !w.ready());
        // Never focused: its guard over arms nothing — nothing counts from
        // the window's start.
        let _ = w.update(Msg::Armed(w.holds));
        assert!(!w.armed, "armed without the focus");
        // Somebody still typing or clicking: nothing is chosen or started,
        // and the guard that was running no longer arms the window.
        press(&mut w, Key::Character("1".into()));
        let _ = w.update(Msg::Net(0));
        let _ = w.update(Msg::Container(0));
        let _ = w.update(Msg::Launch);
        let _ = w.update(Msg::PinContainer(true));
        assert_eq!(
            (w.net, w.container),
            (2, 1),
            "a choice was taken during the guard"
        );
        assert!(!w.pin_container);
        let stale = w.holds;
        let _ = w.update(Msg::Key(
            Key::Character("x".into()),
            keyboard::Modifiers::default(),
            true,
        ));
        let _ = w.update(Msg::Armed(stale));
        assert!(
            !w.armed,
            "a key a widget took did not start the guard again"
        );
        let stale = w.holds;
        let _ = w.update(Msg::Press);
        let _ = w.update(Msg::Armed(stale));
        assert!(!w.armed, "a click did not start the guard again");
        arm(&mut w);
        assert!(w.ready());
        // The focus goes and comes back: disarmed, and the guard again.
        let _ = w.update(Msg::Focus(false));
        assert!(!w.armed);
        let _ = w.update(Msg::Focus(true));
        assert!(!w.armed);
        arm(&mut w);
        press(&mut w, Key::Named(key::Named::Space));
        assert!(!w.pin_net && !w.pin_container);
        assert!(w.answer().ends_with("pin-net\t0\npin-container\t0\n"));
    }

    /// A link's rule: offered unticked, answered as ticked or not, and never
    /// ticked where it was not offered.
    #[test]
    fn a_rule_is_offered_unticked_and_answered() {
        let text = "title\tt\nnet\tnl\tnl\tselected\ncontainer\t\tОсновной\t\n\
                    pins\t0\nrule\tВсегда открывать ссылки https: из контейнера tg в Firefox\n";
        let req = parse_request(text);
        assert_eq!(
            req.rule.as_deref(),
            Some("Всегда открывать ссылки https: из контейнера tg в Firefox")
        );
        let mut w = Window::new(req);
        assert!(w.answer().ends_with("rule\t0\n"));
        let _ = w.update(Msg::Rule(true));
        assert!(w.answer().ends_with("rule\t1\n"));
        let mut plain = Window::new(parse_request(
            "title\tt\nnet\tnl\tnl\ncontainer\t\tОсновной\t\n",
        ));
        let _ = plain.update(Msg::Rule(true));
        assert!(!plain.answer().contains("rule"));
    }

    /// In a zone's window Enter starts only in the network that asks; digits
    /// choose nothing; a choice changed by the keyboard or a click takes the
    /// guard again before anything starts.
    #[test]
    fn in_a_zones_window_enter_starts_only_where_it_asks() {
        let req = parse_request(&format!(
            "{REQUEST}guard\t1500\npins\t0\nasker\tnl\nprogram\t/nix/store/x/bin/firefox\n\
             cmd\tfirefox\ncmd\thttps://a\n"
        ));
        assert_eq!(req.asker.as_deref(), Some("nl"));
        assert_eq!(req.command, ["firefox", "https://a"]);
        let mut w = Window::new(req);
        arm(&mut w);
        assert_eq!(w.net_tag(), "nl");
        // A digit — typing meant for something else — chooses nothing, and
        // starts the guard again.
        press(&mut w, Key::Character("1".into()));
        assert_eq!(w.net_tag(), "nl", "a digit chose a network");
        assert!(!w.armed, "typing did not start the guard again");
        arm(&mut w);
        // Up to another network: the guard again, and Enter does not start.
        press(&mut w, Key::Named(key::Named::ArrowUp));
        assert_eq!(w.net_tag(), "offline");
        assert!(!w.armed);
        arm(&mut w);
        assert!(!w.enter_starts());
        // A click on another row: the guard again as well.
        let _ = w.update(Msg::Net(0));
        assert!(!w.armed && w.net_tag() == "unconfined");
        arm(&mut w);
        assert!(w.ready(), "the button that names it starts");
        let _ = w.update(Msg::Net(2));
        arm(&mut w);
        assert!(w.enter_starts());
    }

    /// A question (a guarded menu): Enter gives the highlighted answer — the
    /// safe one first — only once armed; digits choose nothing; a moved
    /// highlight and any other key start the guard again.
    #[test]
    fn a_question_takes_no_answer_typed_on() {
        let req = parse_request(
            "mode\tmenu\ntitle\tЗапуск из зоны\nnote\tРазрешить?\n\
             action\tdeny\tОтказать\t\naction\tallow\tРазрешить\t\n\
             action\talways\tВсегда\t\nguard\t1500\n",
        );
        let mut w = Window::new(req);
        assert!(w.menu() && w.guarded() && !w.armed);
        arm(&mut w);
        assert!(w.armed);
        // "3⏎" typed on: the digit chooses nothing and starts the guard, and
        // the Enter after it only starts it again.
        press(&mut w, Key::Character("3".into()));
        assert_eq!(w.entry, 0, "a digit chose an answer");
        assert!(!w.armed);
        arm(&mut w);
        // A move of the highlight: the guard again, so a quick Enter after
        // it takes nothing.
        press(&mut w, Key::Named(key::Named::ArrowDown));
        assert_eq!(w.entry, 1);
        assert!(!w.armed, "a moved highlight did not start the guard again");
        // A letter: the guard again too.
        arm(&mut w);
        press(&mut w, Key::Character("a".into()));
        assert!(!w.armed);
    }

    /// The height fits what the window shows once every list is measured: a
    /// menu gives back what its notes leave over, the launch window takes
    /// what its longer list lacks — and it is asked for once.
    #[test]
    fn the_height_fits_the_lists_once_they_are_measured() {
        let mut menu = Window::new(parse_request(
            "mode\tmenu\ntitle\tFoot\nnote\tFoot: без сети\naction\tclose\tЗакрыть\tdanger\n",
        ));
        let notes = List::Notes;
        assert_eq!(menu.measured(Measure::Page, Size::new(560.0, 420.0)), None);
        assert_eq!(
            menu.measured(Measure::View(notes), Size::new(528.0, 190.0)),
            None
        );
        // 420 − 190 + 18.5, up to a whole pixel.
        assert_eq!(
            menu.measured(Measure::Content(notes), Size::new(120.0, 18.5)),
            Some(Size::new(560.0, 249.0))
        );
        assert_eq!(
            menu.measured(Measure::Page, Size::new(560.0, 249.0)),
            None,
            "asked once"
        );

        let mut launch = Window::new(parse_request(REQUEST));
        let (nets, containers) = (List::Nets, List::Containers);
        for (what, height) in [
            (Measure::Page, 400.0),
            (Measure::View(nets), 200.0),
            (Measure::View(containers), 200.0),
            (Measure::Content(nets), 120.0),
        ] {
            assert_eq!(launch.measured(what, Size::new(840.0, height)), None);
        }
        assert_eq!(
            launch.measured(Measure::Content(containers), Size::new(460.0, 260.0)),
            Some(Size::new(840.0, 460.0))
        );

        // Lists that fit as they are: nothing to ask. One longer than any
        // screen: no taller than the most the window grows to — it scrolls.
        let mut fits = Window::new(parse_request(REQUEST));
        let mut long = Window::new(parse_request(REQUEST));
        for (what, height) in [
            (Measure::Page, 400.0),
            (Measure::View(nets), 200.0),
            (Measure::View(containers), 200.0),
            (Measure::Content(nets), 150.0),
        ] {
            let _ = fits.measured(what, Size::new(840.0, height));
            let _ = long.measured(what, Size::new(840.0, height));
        }
        assert_eq!(
            fits.measured(Measure::Content(containers), Size::new(460.0, 200.0)),
            None
        );
        assert!(fits.fitted);
        assert_eq!(
            long.measured(Measure::Content(containers), Size::new(460.0, 5000.0)),
            Some(Size::new(840.0, MAX_HEIGHT))
        );
    }

    /// The size it opens at is a guess from what it shows: a short menu
    /// opens short, a list longer than a screen no taller than 640.
    #[test]
    fn the_first_size_is_guessed_from_what_is_shown() {
        let menu = parse_request(
            "mode\tmenu\ntitle\tFoot\nnote\tFoot: без сети, контейнер: основной\n\
             action\tpin\tВсегда запускать «Foot» в основном доме без сети\t\n\
             action\trestart\tЗакрыть «Foot» и запустить снова — выбрать сеть и контейнер…\tdanger\n\
             action\tclose\tЗакрыть «Foot»\tdanger\n",
        );
        let size = first_size(&menu);
        assert!(
            size.width > 559.0 && size.width < 561.0 && (230.0..300.0).contains(&size.height),
            "{size:?}"
        );
        let rows: String = (0..60)
            .map(|i| format!("container\tc{i}\tКонтейнер «c{i}» — свой дом\t\n"))
            .collect();
        let long = parse_request(&format!("title\tt\nnet\tnl\tnl\t\n{rows}"));
        assert_eq!(first_size(&long), Size::new(840.0, 640.0));
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
