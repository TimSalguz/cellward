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
//! The window opens at the height of what it shows (`fitted_size`): its page
//! laid out by iced itself, with the fonts it draws in, before the window
//! is made — no empty band under a short list, no scroll bar on a list that
//! fits, up to a height most screens have (a longer list scrolls). Nothing
//! it shows changes that height afterwards: the name of a new container is
//! typed beside the buttons, and a question's "Секунду…" stands beside its
//! close button. A window is not resized once open: on Wayland iced goes on
//! drawing at the size it had, and the compositor scales that to the new one.

use std::io::Read;

mod appearance;
mod checklist;
mod clip;
mod clip_type;
mod clipd;
mod days;
#[path = "../../shared/i18n.rs"]
mod i18n;
mod login;
mod metro;
mod panel;
mod pattern;
mod syscolors;
mod thumb;
#[path = "../../shared/type_input.rs"]
mod type_input;

use i18n::{text as tr, Key as UiKey, Language};
use iced::keyboard::{self, key, Key};
use iced::widget::{button, checkbox, column, container, row, scrollable, text, text_input};
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
    language: Language,
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
    /// `offer⇥<line>⇥<text>`: what the program's preset offers its
    /// container, each a checkbox, unticked (step 3 of vpn-zones'
    /// `docs/PERMISSIONS.md` §11.15); a ticked one answered `offer⇥<line>`.
    offers: Vec<(String, String)>,
    /// `perm⇥<key>⇥<label>⇥<value>:<text>;…`: a permission a container can
    /// be given here, a row each under the lists.
    perms: Vec<Perm>,
    /// `permof⇥<tag>⇥<scope>⇥<key>=<value>[!],…`: a container's
    /// permissions as they are, and whom a change is for.
    perm_of: Vec<PermOf>,
    /// The permissions block's heading (`block`): «Разрешения» unless said
    /// — the frame's settings are shown as the same rows.
    block: Option<String>,
    frame_preview: bool,
    frame_sliders: std::collections::HashMap<String, (u32, u32)>,
}

/// A permission's row: its key, its name, its choices `(value, text)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Perm {
    key: String,
    label: String,
    choices: Vec<(String, String)>,
}

/// A container's permissions: whom a change is for, and `(key, value,
/// fixed)` — fixed: not to be changed here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PermOf {
    tag: String,
    scope: String,
    values: Vec<(String, String, bool)>,
}

fn parse_perm(fields: &[&str]) -> Option<Perm> {
    let key = (*fields.first()?).to_owned();
    let label = (*fields.get(1)?).to_owned();
    let choices: Vec<(String, String)> = fields
        .get(2)?
        .split(';')
        .filter_map(|c| c.split_once(':'))
        .map(|(v, t)| (v.to_owned(), t.to_owned()))
        .collect();
    (!key.is_empty() && !choices.is_empty()).then_some(Perm {
        key,
        label,
        choices,
    })
}

fn parse_perm_of(fields: &[&str]) -> Option<PermOf> {
    let tag = (*fields.first()?).to_owned();
    let scope = (*fields.get(1)?).to_owned();
    let values = fields
        .get(2)
        .unwrap_or(&"")
        .split(',')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| match v.strip_suffix('!') {
            Some(v) => (k.to_owned(), v.to_owned(), true),
            None => (k.to_owned(), v.to_owned(), false),
        })
        .collect();
    Some(PermOf { tag, scope, values })
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
            "lang" => req.language = Language::from_wire_tag(fields.get(1).copied().unwrap_or("")),
            "mode" => req.mode = fields.get(1).unwrap_or(&"").to_string(),
            "frame-preview" => req.frame_preview = fields.get(1) == Some(&"1"),
            "slider" if fields.len() == 4 => {
                if let (Ok(max), Ok(now)) = (fields[2].parse::<u32>(), fields[3].parse::<u32>()) {
                    if max > 0 && max <= 64 {
                        req.frame_sliders
                            .insert(fields[1].to_owned(), (max, now.min(max)));
                    }
                }
            }
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
            "offer" if fields.len() >= 3 && !fields[1].is_empty() => req
                .offers
                .push((fields[1].to_owned(), fields[2].to_owned())),
            "perm" => req.perms.extend(parse_perm(&fields[1..])),
            "permof" => req.perm_of.extend(parse_perm_of(&fields[1..])),
            "block" if fields.len() >= 2 && !fields[1].is_empty() => {
                req.block = Some(fields[1].to_string())
            }
            _ => {}
        }
    }
    if req.no_pins {
        req.pin_net = false;
        req.pin_container = false;
    }
    // Compatibility with older cores: an optional preset checkbox must
    // not become a second control for an existing permission or home row.
    req.offers.retain(|(line, _)| {
        !line.split_once('=').is_some_and(|(key, _)| {
            req.perms.iter().any(|p| p.key == key) || (key == "home" && !req.containers.is_empty())
        })
    });
    req
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pane {
    Net,
    Container,
}

#[derive(Debug, Clone)]
enum Msg {
    Appearance,
    /// A menu entry, by its index.
    Action(usize),
    Net(usize),
    Container(usize),
    PinNet(bool),
    PinContainer(bool),
    Rule(bool),
    /// An offer of the preset, by its index, ticked or not.
    Offer(usize, bool),
    ShowOffers(bool),
    /// A permission's choice for the container chosen: the row, the choice.
    Perm(usize, usize),
    FrameNumber(usize, u32),
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
    GuardTick(u64, u64),
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
    /// The request's offers ticked, one each.
    offered: Vec<bool>,
    show_offers: bool,
    /// The permissions changed: `(container tag, key) → value`.
    changed: std::collections::HashMap<(String, String), String>,
    name: String,
    /// False while the request's guard runs.
    armed: bool,
    /// How many times the guard was started: only the last one arms.
    holds: u64,
    guard_seconds: u64,
    /// The window has the keyboard's focus: a guarded window arms only
    /// then — its guard is counted from when the person can see it, and a
    /// window that never gets the focus never takes a choice.
    focused: bool,
    /// Laid out to be measured (`fitted_size`): every list whole, at its own
    /// height, rather than in a place that scrolls.
    measuring: bool,
}

/// Why a container cannot go with this network, if it cannot.
fn blocked(item: &Item, net: &str, language: Language) -> Option<String> {
    if let Some(zone) = item.busy.as_deref().filter(|z| *z != net) {
        return Some(format!("{} {zone}", tr(language, UiKey::BusyInNetwork)));
    }
    if let Some(zone) = item.bound.as_deref().filter(|z| *z != net) {
        return Some(format!("{} {zone}", tr(language, UiKey::BoundToNetwork)));
    }
    None
}

const NAME_FIELD: &str = "new-container-name";

/// The tag of a menu's heading (vpn-zones' `window::HEADING`): a line, not
/// a choice.
const HEADING: &str = "#";

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
        let unconfined = req.nets.get(net).is_some_and(|n| n.tag == "unconfined");
        Self {
            pin_net: req.pin_net && !unconfined,
            pin_container: req.pin_container && !unconfined,
            rule: false,
            offered: vec![false; req.offers.len()],
            show_offers: false,
            changed: std::collections::HashMap::new(),
            pane: Pane::Net,
            net,
            container,
            name: String::new(),
            entry: req
                .actions
                .iter()
                .position(|(tag, _, _)| tag != HEADING)
                .unwrap_or(0),
            armed: req.guard == 0,
            holds: 0,
            guard_seconds: req.guard.div_ceil(1000),
            focused: false,
            measuring: false,
            req,
        }
    }

    /// A list in a place of its own that scrolls when it is longer — or,
    /// measuring, the list whole.
    fn list_view<'a>(&self, rows: impl Into<Element<'a, Msg>>) -> Element<'a, Msg> {
        if self.measuring {
            rows.into()
        } else {
            scrollable(rows).height(Length::Fill).into()
        }
    }

    fn menu(&self) -> bool {
        self.req.mode == "menu"
    }

    /// A window of a container's permissions alone (`mode⇥perms`, the
    /// frame's ☰): its rows, «Сохранить» and «Отмена».
    fn perms_only(&self) -> bool {
        self.req.mode == "perms"
    }

    /// Whether entry `i` of the menu is a heading: a line, not a choice.
    fn heading(&self, i: usize) -> bool {
        self.req
            .actions
            .get(i)
            .is_some_and(|(tag, _, _)| tag == HEADING)
    }

    /// The menu's choices, by their places among its lines.
    fn choices(&self) -> Vec<usize> {
        (0..self.req.actions.len())
            .filter(|i| !self.heading(*i))
            .collect()
    }

    /// The highlight moved by `step` among the choices, headings passed over.
    fn step_entry(&mut self, step: isize) {
        let choices = self.choices();
        if choices.is_empty() {
            return;
        }
        let at = choices.iter().position(|i| *i == self.entry).unwrap_or(0) as isize;
        let n = choices.len() as isize;
        self.entry = choices[(at + step).rem_euclid(n) as usize];
    }

    fn net_tag(&self) -> &str {
        self.req.nets.get(self.net).map_or("", |i| i.tag.as_str())
    }

    fn container_ok(&self, i: usize) -> bool {
        if self.net_tag() == "unconfined" {
            return false;
        }
        self.req
            .containers
            .get(i)
            .is_some_and(|c| blocked(c, self.net_tag(), self.req.language).is_none())
    }

    /// Everything needed to start: a container that goes with the network, a
    /// name for a new one, and the guard's time over.
    fn ready(&self) -> bool {
        if self.net_tag() == "unconfined" {
            return self.armed;
        }
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
            Pane::Net if index < self.req.nets.len() => {
                self.net = index;
                if self.net_tag() == "unconfined" {
                    self.pin_net = false;
                    self.pin_container = false;
                }
            }
            Pane::Container if self.container_ok(index) => self.container = index,
            _ => {}
        }
    }

    fn container_tag(&self) -> &str {
        if self.perms_only() {
            return "this";
        }
        self.req
            .containers
            .get(self.container)
            .map_or("", |c| c.tag.as_str())
    }

    /// The permissions of the container chosen, as the request has them.
    fn perm_of(&self) -> Option<&PermOf> {
        let tag = self.container_tag();
        self.req.perm_of.iter().find(|p| p.tag == tag)
    }

    /// A permission of the container chosen: its value now (changed or as
    /// it was), and whether it is fixed — every one is where the request
    /// says nothing of the container.
    fn perm_value(&self, key: &str) -> (String, bool) {
        let tag = self.container_tag();
        let had = self
            .perm_of()
            .and_then(|p| p.values.iter().find(|(k, _, _)| k == key));
        let Some((_, value, fixed)) = had else {
            return ("default".to_owned(), true);
        };
        match self.changed.get(&(tag.to_owned(), key.to_owned())) {
            Some(changed) if !fixed => (changed.clone(), false),
            _ => (value.clone(), *fixed),
        }
    }

    /// The answer, as the picker reads it.
    fn answer(&self) -> String {
        let mut out = format!("net\t{}\n", self.net_tag());
        if self.net_tag() == "unconfined" {
            out.push_str("container\topen\npin-net\t0\npin-container\t0\n");
            return out;
        }
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
        for ((line, _), ticked) in self.req.offers.iter().zip(&self.offered) {
            if *ticked {
                out.push_str(&format!("offer\t{line}\n"));
            }
        }
        out.push_str(&self.perms_answer());
        out
    }

    /// The permissions changed for the container chosen, and only what
    /// differs from what it had: `perm⇥<key>⇥<value>` each.
    fn perms_answer(&self) -> String {
        let mut out = String::new();
        if let Some(of) = self.perm_of() {
            for (key, value, fixed) in &of.values {
                let (now, _) = self.perm_value(key);
                if !fixed && now != *value {
                    out.push_str(&format!("perm\t{key}\t{now}\n"));
                }
            }
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
        self.guard_seconds = self.req.guard.div_ceil(1000);
        arm_after(self.req.guard, self.holds)
    }

    fn wait_label(&self) -> String {
        if self.armed {
            String::new()
        } else {
            format!(
                "{} {}",
                tr(self.req.language, UiKey::Wait),
                self.guard_seconds
            )
        }
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
                | Msg::Rule(_)
                | Msg::Offer(_, _)
                | Msg::ShowOffers(_)
                | Msg::Perm(_, _)
                | Msg::FrameNumber(_, _)
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
            Msg::Appearance => {}
            Msg::Action(i) => {
                if let Some((tag, _, _)) = self.req.actions.get(i).filter(|_| !self.heading(i)) {
                    println!("action\t{tag}");
                    std::process::exit(0);
                }
            }
            Msg::Net(i) => {
                self.pane = Pane::Net;
                let changed = self.net != i;
                self.net = i;
                if self.net_tag() == "unconfined" {
                    self.pin_net = false;
                    self.pin_container = false;
                }
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
            Msg::PinNet(v) => {
                self.pin_net = v && !self.req.no_pins && self.net_tag() != "unconfined"
            }
            Msg::PinContainer(v) => {
                self.pin_container = v && !self.req.no_pins && self.net_tag() != "unconfined"
            }
            Msg::Rule(v) => self.rule = v && self.req.rule.is_some(),
            Msg::Offer(i, v) => {
                if let Some(ticked) = self.offered.get_mut(i) {
                    *ticked = v;
                }
            }
            Msg::ShowOffers(show) => self.show_offers = show && !self.req.offers.is_empty(),
            Msg::Perm(row, choice) => {
                let Some(perm) = self.req.perms.get(row) else {
                    return Task::none();
                };
                let Some((value, _)) = perm.choices.get(choice) else {
                    return Task::none();
                };
                if !self.perm_value(&perm.key).1 {
                    let tag = self.container_tag().to_owned();
                    let (key, value) = (perm.key.clone(), value.clone());
                    self.changed.insert((tag, key.clone()), value.clone());
                    self.preview_number(&key, &value);
                }
            }
            Msg::FrameNumber(row, number) => {
                if !self.req.frame_preview || !self.perms_only() {
                    return Task::none();
                }
                let Some(perm) = self.req.perms.get(row) else {
                    return Task::none();
                };
                let key = perm.key.clone();
                let Some((max, _)) = self.req.frame_sliders.get(&key) else {
                    return Task::none();
                };
                if number > *max || self.perm_value(&key).1 {
                    return Task::none();
                }
                let value = number.to_string();
                self.changed.insert(
                    (self.container_tag().to_owned(), key.clone()),
                    value.clone(),
                );
                self.preview_number(&key, &value);
            }
            // Armed by the last guard started, and only with the focus.
            Msg::Armed(holds) => self.armed |= holds == self.holds && self.focused,
            Msg::GuardTick(holds, seconds) => {
                if holds == self.holds && self.focused {
                    self.guard_seconds = seconds;
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
            Msg::Launch if self.perms_only() => {
                if self.armed {
                    print!("{}", self.perms_answer());
                    std::process::exit(0);
                }
            }
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
                    self.step_entry(-1);
                    self.hold()
                }
                Key::Named(key::Named::ArrowDown) if n > 0 => {
                    self.step_entry(1);
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
                Key::Named(key::Named::ArrowUp) if n > 0 => self.step_entry(-1),
                Key::Named(key::Named::ArrowDown) if n > 0 => self.step_entry(1),
                // A digit: that choice, headings not counted.
                Key::Character(c) => {
                    if let Some(d) = c
                        .chars()
                        .next()
                        .and_then(|c| c.to_digit(10))
                        .filter(|d| *d > 0)
                    {
                        if let Some(i) = self.choices().get(d as usize - 1) {
                            self.entry = *i;
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
        if self.show_offers {
            if matches!(
                key.as_ref(),
                Key::Named(key::Named::Escape | key::Named::ArrowLeft)
            ) {
                return self.update(Msg::ShowOffers(false));
            }
            return Task::none();
        }
        match key.as_ref() {
            Key::Named(key::Named::Escape) => return self.update(Msg::Cancel),
            Key::Named(key::Named::Enter) if self.enter_starts() => {
                return self.update(Msg::Launch)
            }
            Key::Named(key::Named::ArrowLeft) => self.pane = Pane::Net,
            Key::Named(key::Named::ArrowRight) if self.net_tag() != "unconfined" => {
                self.pane = Pane::Container
            }
            Key::Named(key::Named::Tab) => {
                self.pane = match (self.pane, modifiers.shift()) {
                    (Pane::Net, false) | (Pane::Container, true) => Pane::Container,
                    _ => Pane::Net,
                };
                if self.net_tag() == "unconfined" {
                    self.pane = Pane::Net;
                }
            }
            Key::Named(key::Named::ArrowUp) => self.step(-1),
            Key::Named(key::Named::ArrowDown) => self.step(1),
            Key::Named(key::Named::Space) if !self.req.no_pins => match self.pane {
                Pane::Net if self.net_tag() != "unconfined" => self.pin_net = !self.pin_net,
                Pane::Net => {}
                Pane::Container if self.net_tag() != "unconfined" => {
                    self.pin_container = !self.pin_container
                }
                Pane::Container => {}
            },
            // Digits choose nothing in a zone's window.
            Key::Character(c) if self.req.asker.is_none() => {
                if let Some(d) = c.chars().next().and_then(|c| c.to_digit(10)) {
                    let index = if self.pane == Pane::Net {
                        if d == 0 {
                            self.req.nets.iter().position(|n| n.tag == "unconfined")
                        } else {
                            self.req
                                .nets
                                .iter()
                                .enumerate()
                                .filter(|(_, n)| n.tag != "unconfined")
                                .nth(d as usize - 1)
                                .map(|(i, _)| i)
                        }
                    } else {
                        (d > 0).then_some(d as usize - 1)
                    };
                    if let Some(index) = index {
                        self.pick(index);
                    }
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
            if pane == Pane::Net && item.tag == "unconfined" {
                continue;
            }
            let why = (pane == Pane::Container)
                .then(|| blocked(item, self.net_tag(), self.req.language))
                .flatten();
            let mark = if i == chosen { "●" } else { "○" };
            let display_number = if pane == Pane::Net {
                items[..i].iter().filter(|n| n.tag != "unconfined").count() + 1
            } else {
                i + 1
            };
            let number = if display_number < 10 {
                format!("{display_number} ")
            } else {
                "  ".to_owned()
            };
            let mut label = format!("{number}{mark} {}", item.label);
            if item.dead {
                label.push_str(tr(self.req.language, UiKey::TunnelSilent));
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
        column![title, self.list_view(list)]
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
        page = page.push(self.list_view(notes));
        if !self.req.command.is_empty() {
            page = page.push(self.command_view());
        }
        let mut list = column![].spacing(4);
        let mut number = 0;
        for (i, (_, label, danger)) in self.req.actions.iter().enumerate() {
            if self.heading(i) {
                list = list.push(
                    container(text(label.as_str()).size(13))
                        .padding(iced::Padding::from([0, 4]).top(if i == 0 { 0 } else { 6 })),
                );
                continue;
            }
            number += 1;
            let style = match (i == self.entry, *danger) {
                (true, true) => button::danger,
                (true, false) => button::primary,
                _ => button::text,
            };
            let mark = if *danger { "⚠ " } else { "" };
            list = list.push(
                button(text(format!("{number} {mark}{label}")).size(15))
                    .width(Length::Fill)
                    .padding([6, 10])
                    .style(style)
                    .on_press(Msg::Action(i)),
            );
        }
        page = page.push(list);
        // "Секунду…" beside the close button, not a line of its own: the
        // window keeps the height it opened at.
        let wait = self.wait_label();
        page = page.push(
            row![
                container(text(wait).size(13)).width(Length::Fill),
                button(text(tr(self.req.language, UiKey::CloseMenu)).size(14))
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
        if self.perms_only() {
            return self.view_perms();
        }
        if self.show_offers {
            return self.view_offers();
        }
        let nets = self.column_view(
            tr(self.req.language, UiKey::Network),
            Pane::Net,
            &self.req.nets,
            self.net,
            Msg::Net,
        );
        let unconfined = self.net_tag() == "unconfined";
        let mut left = column![nets].spacing(8).width(Length::FillPortion(2));
        if !self.req.no_pins && !unconfined {
            left = left.push(
                checkbox(self.pin_net)
                    .label(tr(self.req.language, UiKey::AlwaysNetwork))
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
        if self.req.nets.iter().any(|n| n.tag == "unconfined") {
            let style = if unconfined {
                button::danger
            } else {
                button::secondary
            };
            if let Some(index) = self.req.nets.iter().position(|n| n.tag == "unconfined") {
                page = page.push(
                    button(text(tr(self.req.language, UiKey::UnconfinedWarning)).size(15))
                        .width(Length::Fill)
                        .style(style)
                        .on_press(Msg::Net(index)),
                );
            }
        }
        if !self.req.command.is_empty() {
            page = page.push(self.command_view());
        }
        let lists = if self.measuring {
            Length::Shrink
        } else {
            Length::Fill
        };
        if unconfined {
            page = page.push(text(tr(self.req.language, UiKey::NoContainer)).size(14));
            page = page.push(left.height(lists));
        } else {
            let containers = self.column_view(
                tr(self.req.language, UiKey::Container),
                Pane::Container,
                &self.req.containers,
                self.container,
                Msg::Container,
            );
            let mut right = column![containers].spacing(8).width(Length::FillPortion(3));
            if !self.req.no_pins {
                right = right.push(
                    checkbox(self.pin_container)
                        .label(tr(self.req.language, UiKey::AlwaysContainer))
                        .on_toggle(Msg::PinContainer),
                );
            }
            page = page.push(row![left, right].spacing(16).height(lists));
        }
        if !unconfined {
            if !self.req.perms.is_empty() {
                page = page.push(self.perms_view());
            }
            if let Some(rule) = &self.req.rule {
                page = page.push(checkbox(self.rule).label(rule).on_toggle(Msg::Rule));
            }
            if !self.req.offers.is_empty() {
                page = page.push(
                    button(text(tr(self.req.language, UiKey::OptionalAccess)).size(13))
                        .padding([3, 8])
                        .style(button::text)
                        .on_press(Msg::ShowOffers(true)),
                );
            }
        }
        let label = if !self.armed {
            self.wait_label()
        } else if self.enter_starts() {
            tr(self.req.language, UiKey::Start).to_owned()
        } else {
            let net = self.req.nets.get(self.net).map_or("", |n| n.label.as_str());
            format!("{} {net}", tr(self.req.language, UiKey::StartIn))
        };
        let launch = button(text(label).size(14))
            .padding([6, 14])
            .style(button::primary)
            .on_press_maybe(self.ready().then_some(Msg::Launch));
        let cancel = button(text(tr(self.req.language, UiKey::Cancel)).size(14))
            .padding([6, 14])
            .style(button::secondary)
            .on_press(Msg::Cancel);
        // The name of a new container beside the buttons that start it, at
        // their height: the lists above keep their place.
        let lead: Element<'_, Msg> = if self.naming() {
            text_input(tr(self.req.language, UiKey::ContainerName), &self.name)
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
        page.into()
    }

    fn view_offers(&self) -> Element<'_, Msg> {
        let mut offers = column![].spacing(8);
        for (i, (_, label)) in self.req.offers.iter().enumerate() {
            offers = offers.push(
                checkbox(self.offered.get(i).copied().unwrap_or(false))
                    .label(label.as_str())
                    .on_toggle(move |v| Msg::Offer(i, v)),
            );
        }
        column![
            text(tr(self.req.language, UiKey::PresetOffer)).size(18),
            scrollable(offers).height(Length::Fill),
            button(text(tr(self.req.language, UiKey::Back)).size(14))
                .padding([6, 14])
                .style(button::secondary)
                .on_press(Msg::ShowOffers(false)),
        ]
        .spacing(12)
        .padding(16)
        .into()
    }

    /// The permissions of one container (`mode⇥perms`): the title, the
    /// notes, its rows, and «Сохранить» once the guard is over.
    fn view_perms(&self) -> Element<'_, Msg> {
        let mut page = column![text(&self.req.title).size(20)]
            .spacing(12)
            .padding(16);
        for note in &self.req.notes {
            page = page.push(text(format!("ⓘ {note}")).size(14));
        }
        page = page.push(self.perms_view());
        let wait = self.wait_label();
        page = page.push(
            row![
                container(text(wait).size(13)).width(Length::Fill),
                button(text(tr(self.req.language, UiKey::Save)).size(14))
                    .padding([6, 14])
                    .style(button::primary)
                    .on_press_maybe(self.armed.then_some(Msg::Launch)),
                button(text(tr(self.req.language, UiKey::Cancel)).size(14))
                    .padding([6, 14])
                    .style(button::secondary)
                    .on_press(Msg::Cancel)
            ]
            .spacing(10)
            .align_y(Alignment::Center),
        );
        page.into()
    }

    /// The permissions of the container chosen, a row each: its name and
    /// its choices, the one in force marked. The same rows for every
    /// container — the window keeps the height it opened at —, those that
    /// cannot be changed here not pressable. Above them, whom a change is
    /// for: every program of the container, or this launch alone.
    fn preview_number(&self, key: &str, value: &str) {
        if self.req.frame_preview
            && self.perms_only()
            && matches!(
                key,
                "width" | "radius" | "outer-radius" | "hover-edge" | "resize-corner"
            )
        {
            use std::io::Write;
            println!("preview\t{key}\t{value}");
            let _ = std::io::stdout().flush();
        }
    }

    fn perms_view(&self) -> Element<'_, Msg> {
        let scope = self
            .perm_of()
            .map_or(tr(self.req.language, UiKey::NothingToChoose), |p| {
                p.scope.as_str()
            });
        let mut block = column![
            text(
                self.req
                    .block
                    .as_deref()
                    .unwrap_or(tr(self.req.language, UiKey::Permissions))
            )
            .size(15),
            text(scope)
                .size(13)
                .wrapping(iced::widget::text::Wrapping::WordOrGlyph)
        ]
        .spacing(4);
        for (row_at, perm) in self.req.perms.iter().enumerate() {
            let (now, fixed) = self.perm_value(&perm.key);
            let mut choices = row![].spacing(4);
            for (choice_at, (value, label)) in perm.choices.iter().enumerate() {
                let style = if *value == now {
                    if fixed {
                        button::secondary
                    } else {
                        button::primary
                    }
                } else {
                    button::text
                };
                choices = choices.push(
                    button(text(label.as_str()).size(12))
                        .padding([2, 6])
                        .style(style)
                        .on_press_maybe((!fixed).then_some(Msg::Perm(row_at, choice_at))),
                );
            }
            block = block.push(
                row![
                    text(perm.label.as_str())
                        .size(13)
                        .width(Length::Fixed(230.0)),
                    // Many choices (the frame's colours) go on below.
                    choices.wrap().vertical_spacing(2)
                ]
                .spacing(8)
                .align_y(Alignment::Center),
            );
            if self.req.frame_preview {
                if let Some(&(max, initial)) = self.req.frame_sliders.get(&perm.key) {
                    let number = now.parse::<u32>().unwrap_or(initial).min(max);
                    block = block.push(
                        row![
                            container(text("")).width(Length::Fixed(230.0)),
                            iced::widget::slider(0..=max, number, move |n| Msg::FrameNumber(
                                row_at, n
                            ))
                            .step(1u32)
                            .on_release(Msg::Press),
                            text(number.to_string()).size(12).width(Length::Fixed(30.0)),
                        ]
                        .spacing(8)
                        .align_y(Alignment::Center),
                    );
                }
            }
        }
        container(block)
            .padding(8)
            .width(Length::Fill)
            .style(container::bordered_box)
            .into()
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
        let mut block = column![text(tr(self.req.language, UiKey::Command)).size(15)].spacing(4);
        if !self.req.program.is_empty() {
            block = block.push(
                text(format!(
                    "{} {}",
                    tr(self.req.language, UiKey::Program),
                    self.req.program
                ))
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
        Subscription::batch([
            iced::event::listen_with(|event, status, _window| match event {
                iced::Event::Keyboard(keyboard::Event::KeyPressed { key, modifiers, .. }) => Some(
                    Msg::Key(key, modifiers, status == iced::event::Status::Captured),
                ),
                iced::Event::Mouse(iced::mouse::Event::ButtonPressed(_)) => Some(Msg::Press),
                iced::Event::Window(iced::window::Event::Focused) => Some(Msg::Focus(true)),
                iced::Event::Window(iced::window::Event::Unfocused) => Some(Msg::Focus(false)),
                _ => None,
            }),
            appearance::watch().map(|_| Msg::Appearance),
        ])
    }
}

/// `Msg::Armed(holds)` after `guard` milliseconds: slept on a thread of its
/// own, awaited on the executor — never on the executor's pool, which also
/// carries the input events: a sleep there would hold keys typed during the
/// guard until after it, and they would count as typed when armed.
fn arm_after(guard: u64, holds: u64) -> Task<Msg> {
    let (sender, receiver) = iced::futures::channel::mpsc::unbounded();
    std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(guard);
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                let _ = sender.unbounded_send(Msg::Armed(holds));
                break;
            }
            if sender
                .unbounded_send(Msg::GuardTick(
                    holds,
                    left.as_millis().div_ceil(1000) as u64,
                ))
                .is_err()
            {
                break;
            }
            std::thread::sleep(left.min(std::time::Duration::from_millis(250)));
        }
    });
    Task::run(receiver, |msg| msg)
}

/// The heights a window opens at no lower than, and no higher than: most
/// screens have the latter free under a panel. A longer list scrolls.
const MIN_HEIGHT: f32 = 160.0;
const MAX_HEIGHT: f32 = 760.0;

/// The size the window opens at: the width of its kind, and the height of
/// its page laid out by iced — every list whole, at its own height, with
/// the renderer and the fonts the window draws with (the font system is one
/// for the process, set up once) — within `MIN_HEIGHT` and `MAX_HEIGHT`.
fn fitted_size(req: &Request) -> Size {
    let width = match (req.mode == "menu", req.command.is_empty()) {
        (true, true) => 560.0,
        (true, false) => 640.0,
        (false, _) => 840.0,
    };
    let mut window = Window::new(req.clone());
    window.measuring = true;
    let mut page = window.view();
    let mut tree = iced::advanced::widget::Tree::new(&page);
    let renderer = iced::Renderer::new(iced::Font::default(), iced::Pixels(16.0));
    let limits = iced::advanced::layout::Limits::new(Size::ZERO, Size::new(width, f32::INFINITY));
    let height = page
        .as_widget_mut()
        .layout(&mut tree, &renderer, &limits)
        .size()
        .height;
    Size::new(width, height.ceil().clamp(MIN_HEIGHT, MAX_HEIGHT))
}

/// The exit status of a window that could not be shown at all: the caller
/// asks another way (kdialog) — not a "no".
const EXIT_NOT_SHOWN: i32 = 3;

fn main() -> iced::Result {
    let started = std::time::Instant::now();
    let trace =
        std::env::var_os("CELLWARD_TRACE_STARTUP").as_deref() == Some(std::ffi::OsStr::new("1"));
    let milestone = |stage: &str| {
        if trace {
            eprintln!(
                "cellward window startup: {stage}: {} ms",
                started.elapsed().as_millis()
            );
        }
    };
    // The fonts of this window: a short list of its own (package.nix), not
    // every font of the system — iced reads all it is given at each start,
    // over a thousand on a desktop, seconds under load. Set before anything
    // starts a thread.
    if let Some(fonts) = option_env!("VPN_ZONE_WINDOW_FONTS") {
        std::env::set_var("FONTCONFIG_FILE", fonts);
    }
    // The cellward window (`panel.rs`): the containers and the network
    // monitor, which `cellward-gui` opens.
    let args: Vec<String> = std::env::args().skip(1).collect();
    // A question with boxes to tick (`checklist.rs`): what a program with a
    // home of its own may see, asked at its first launch.
    if args.first().map(String::as_str) == Some("checklist") {
        return checklist::run().map_err(|e| {
            eprintln!("vpn-zone-window checklist: {e}");
            std::process::exit(EXIT_NOT_SHOWN)
        });
    }
    // The connect window's login form (`login.rs`): what a network's
    // gateway asks for before the network comes up.
    if args.first().map(String::as_str) == Some("login") {
        return login::run().map_err(|e| {
            eprintln!("vpn-zone-window login: {e}");
            std::process::exit(EXIT_NOT_SHOWN)
        });
    }
    // The clipboard history of a container (`clip.rs`): its entries, a
    // search, and one to paste into the window it was opened from.
    if args.first().map(String::as_str) == Some("clip") {
        return clip::run(&args[1..]).map_err(|e| {
            eprintln!("vpn-zone-window clip: {e}");
            std::process::exit(EXIT_NOT_SHOWN)
        });
    }
    if args.first().map(String::as_str) == Some("panel") {
        // One that cannot be shown says so as the launch window does: the
        // caller asks the old way.
        return panel::run(&args[1..]).map_err(|e| {
            eprintln!("vpn-zone-window panel: {e}");
            std::process::exit(EXIT_NOT_SHOWN)
        });
    }
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        std::process::exit(1);
    }
    let req = parse_request(&input);
    milestone("request read and parsed");
    // Nothing to choose from is not a window: the caller falls back.
    let empty = match req.mode.as_str() {
        "menu" => req.actions.is_empty(),
        "perms" => req.perms.is_empty(),
        _ => req.nets.is_empty() || req.containers.is_empty(),
    };
    if empty {
        std::process::exit(1);
    }
    let size = fitted_size(&req);
    milestone("fonts and initial layout ready");
    let title = if req.title.is_empty() {
        tr(req.language, UiKey::Launch).to_owned()
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
    .theme(|_: &Window| appearance::load().theme())
    .subscription(Window::subscription)
    .window(iced::window::Settings {
        size,
        position: iced::window::Position::Centered,
        // Its size is its own (it is never resized once open): a fixed size
        // — the minimum the maximum — is what niri and sway float by
        // themselves, no window rule needed (docs/PERMISSIONS.md §11.15,
        // step 6).
        resizable: false,
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
        assert_eq!(req.language, Language::Russian);
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
    fn the_window_chrome_uses_the_language_of_its_request() {
        let req = parse_request(
            "lang\ten\ntitle\tLaunch: Firefox\nnet\toffline\tOffline\t\ncontainer\tmain\tHome\t\n",
        );
        assert_eq!(req.language, Language::English);
        assert_eq!(
            tr(req.language, UiKey::UnconfinedWarning),
            "⚠ No isolation or VPN — full access to host files, devices and session"
        );
        let mut item = Item {
            tag: "main".to_owned(),
            ..Item::default()
        };
        item.busy = Some("nl".to_owned());
        assert_eq!(
            blocked(&item, "offline", req.language).as_deref(),
            Some("open in network nl")
        );
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
    fn no_isolation_is_a_whole_launch_mode_not_a_container_combination() {
        let mut w = Window::new(parse_request(
            "title\tFirefox\nnet\tunconfined\tБез изоляции\t\nnet\toffline\tБез сети\tselected\n\
             container\t\tНастоящий дом\t\ncontainer\twork\tКонтейнер work\tselected\n\
             pin-net\t0\npin-container\t1\noffer\tcamera=on\tкамера\n",
        ));
        w.pane = Pane::Net;
        w.pick(0);
        assert!(w.ready(), "скрытый контейнер не должен блокировать запуск");
        assert!(!w.pin_container);
        assert_eq!(
            w.answer(),
            "net\tunconfined\ncontainer\topen\npin-net\t0\npin-container\t0\n"
        );
        w.pick(1);
        assert_eq!(
            w.container, 1,
            "выбор контейнера сохраняется для обычной сети"
        );
        assert!(w.answer().contains("container\twork\n"));
        assert!(!w.pin_container);
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

    #[test]
    fn countdown_is_visible_and_stale_ticks_cannot_change_a_new_guard() {
        let mut w = Window::new(parse_request(&format!("{REQUEST}guard\t2500\n")));
        assert!(w.wait_label().ends_with(" 3"));
        let _ = w.update(Msg::Focus(true));
        let previous = w.holds;
        let _ = w.update(Msg::GuardTick(previous, 1));
        assert!(w.wait_label().ends_with(" 1"));
        let _ = w.update(Msg::Press);
        assert!(w.wait_label().ends_with(" 3"));
        let _ = w.update(Msg::GuardTick(previous, 1));
        let _ = w.update(Msg::Armed(previous));
        assert!(w.wait_label().ends_with(" 3"));
        assert!(!w.armed);
        let _ = w.update(Msg::Armed(w.holds));
        assert_eq!(w.wait_label(), "");
    }

    /// A window a zone's program brought up takes nothing until the guard is
    /// over — no key, no click, no choice — and every one of them, captured
    /// by a widget or not, and the focus coming back start it again. There is
    /// no "always" to tick.
    #[test]
    fn a_guarded_window_takes_nothing_until_the_person_is_still() {
        let req = parse_request(&format!(
            "{REQUEST}guard\t1500\npins\t0\nrule\tссылки https — сюда\noffer\tcam\tкамеры\n"
        ));
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
        let _ = w.update(Msg::Rule(true));
        let _ = w.update(Msg::Offer(0, true));
        assert!(!w.rule, "the link rule ticked during the guard");
        assert!(
            w.offered.iter().all(|t| !t),
            "an offer ticked during the guard"
        );
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
        // Armed, the boxes are the person's to tick.
        let _ = w.update(Msg::Rule(true));
        assert!(w.rule);
        let _ = w.update(Msg::Rule(false));
        // The focus goes and comes back: disarmed, and the guard again.
        let _ = w.update(Msg::Focus(false));
        assert!(!w.armed);
        let _ = w.update(Msg::Focus(true));
        assert!(!w.armed);
        arm(&mut w);
        press(&mut w, Key::Named(key::Named::Space));
        assert!(!w.pin_net && !w.pin_container);
        assert!(w.answer().contains("pin-net\t0\npin-container\t0\n"));
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

    #[test]
    fn optional_preset_access_has_a_separate_page_and_keeps_its_choice() {
        let req = parse_request(
            "title\tFirefox\nnet\toffline\tOffline\tselected\ncontainer\tmain\tHome\tselected\n\
             offer\tcamera=on\tCamera\n",
        );
        let mut window = Window::new(req);
        assert!(!window.show_offers);
        let _ = window.update(Msg::ShowOffers(true));
        assert!(window.show_offers);
        let _ = window.update(Msg::Offer(0, true));
        let _ = window.update(Msg::ShowOffers(false));
        assert!(!window.show_offers);
        assert!(window.answer().contains("offer\tcamera=on\n"));
        let mut no_offers = Window::new(parse_request(
            "net\toffline\tOffline\tselected\ncontainer\tmain\tHome\tselected\n",
        ));
        let _ = no_offers.update(Msg::ShowOffers(true));
        assert!(!no_offers.show_offers);
    }

    /// A preset's offers: unticked, each answered only when ticked; a line
    /// with no text is none.
    #[test]
    fn a_presets_offers_are_unticked_and_answered_when_ticked() {
        let text = "title\tt\nnet\tnl\tnl\tselected\ncontainer\t__ownsb__\tСвой\tselected\n\
                    offer\tcamera=on\tкамеры\noffer\tfolder=~/Downloads\tпапка ~/Downloads\n\
                    offer\t\tничего\n";
        let req = parse_request(text);
        assert_eq!(req.offers.len(), 2);
        let mut w = Window::new(req);
        assert!(!w.answer().contains("offer"));
        let _ = w.update(Msg::Offer(1, true));
        let _ = w.update(Msg::Offer(7, true));
        assert!(
            w.answer().ends_with("offer\tfolder=~/Downloads\n"),
            "{}",
            w.answer()
        );
        assert!(!w.answer().contains("camera"));
    }

    #[test]
    fn optional_resources_do_not_repeat_the_launch_permission_rows() {
        let request = "title\tt\nnet\thost\tHost\tselected\ncontainer\twork\tWork\tselected\n\
            perm\tcamera\tCamera\tno:No;yes:Yes\n\
            perm\tmicrophone\tMicrophone\tno:No;yes:Yes\n\
            offer\tcamera=on\tCamera\noffer\tmicrophone=yes\tMicrophone\n\
            offer\thome=main\tReal home\noffer\tfolder=~/Downloads\tDownloads\n";
        let req = parse_request(request);
        assert_eq!(req.perms.len(), 2);
        assert_eq!(
            req.offers,
            [("folder=~/Downloads".into(), "Downloads".into())]
        );
        let mut window = Window::new(req);
        let _ = window.update(Msg::Offer(0, true));
        assert!(window.answer().contains("offer\tfolder=~/Downloads\n"));
        assert!(!window.answer().contains("offer\tcamera"));
        let only_camera =
            parse_request("perm\tcamera\tCamera\tno:No;yes:Yes\noffer\tcamera=on\tCamera\n");
        assert!(only_camera.offers.is_empty(), "no empty extra-access page");
    }

    /// The permissions: each container's own shown, a change answered only
    /// for the container chosen and only where it differs; a fixed one is
    /// not changed; a container the request says nothing of has every one
    /// fixed.
    #[test]
    fn a_permission_changed_is_answered_for_the_container_chosen() {
        let text = "title\tt\nnet\tnl\tnl\tselected\n\
                    container\twork\tWork\tselected\ncontainer\topen\tOpen\n\
                    perm\tx11\tX\tdefault:как у всех (выкл.);on:вкл.;off:выкл.\n\
                    perm\tcamera\tКамера\tdefault:как у всех;no:нет;yes:да\n\
                    permof\twork\tДля всех программ «work»\tx11=default,camera=no!\n";
        let req = parse_request(text);
        assert_eq!(req.perms.len(), 2);
        assert_eq!(
            req.perm_of[0].values,
            [
                ("x11".to_owned(), "default".to_owned(), false),
                ("camera".to_owned(), "no".to_owned(), true)
            ]
        );
        let mut w = Window::new(req);
        assert!(!w.answer().contains("perm"));
        let _ = w.update(Msg::Perm(0, 1));
        // Fixed (Nix's): nothing.
        let _ = w.update(Msg::Perm(1, 2));
        assert_eq!(w.perm_value("x11"), ("on".to_owned(), false));
        assert_eq!(w.perm_value("camera"), ("no".to_owned(), true));
        assert!(w.answer().ends_with("perm\tx11\ton\n"), "{}", w.answer());
        // Back to what it had: nothing to say.
        let _ = w.update(Msg::Perm(0, 0));
        assert!(!w.answer().contains("perm"));
        // A container the request has nothing for: every one fixed, and
        // nothing of another container's goes with it.
        let _ = w.update(Msg::Perm(0, 1));
        let _ = w.update(Msg::Container(1));
        assert_eq!(w.perm_value("x11"), ("default".to_owned(), true));
        let _ = w.update(Msg::Perm(0, 2));
        assert!(!w.answer().contains("perm"), "{}", w.answer());
    }

    #[test]
    fn frame_sliders_change_numeric_values_but_never_permission_rows() {
        let request = "mode\tperms\nframe-preview\t1\nslider\twidth\t32\t4\nperm\twidth\tWidth\t0:0;4:4;default:Nix\npermof\tthis\tFrame\twidth=4\n";
        let mut w = Window::new(parse_request(request));
        assert_eq!(w.req.frame_sliders.get("width"), Some(&(32, 4)));
        let _ = w.update(Msg::FrameNumber(0, 7));
        assert_eq!(w.perms_answer(), "perm\twidth\t7\n");
        let _ = w.update(Msg::FrameNumber(0, 33));
        assert_eq!(w.perms_answer(), "perm\twidth\t7\n");
        let _ = w.update(Msg::Perm(0, 2));
        assert_eq!(w.perms_answer(), "perm\twidth\tdefault\n");
        let mut permissions =
            Window::new(parse_request(&request.replace("frame-preview\t1\n", "")));
        let _ = permissions.update(Msg::FrameNumber(0, 7));
        assert!(permissions.perms_answer().is_empty());
    }

    /// A menu's headings are lines, not choices: the highlight starts on the
    /// first choice and passes over them, digits count the choices alone,
    /// and a heading is never answered.
    #[test]
    fn a_menus_headings_are_not_choices() {
        let text = "mode\tmenu\ntitle\tt\naction\t#\tПрограмма\theading\n\
                    action\trestart\tЗанова\t\naction\tclose\tЗакрыть\tdanger\n\
                    action\t#\tКонтейнер\theading\naction\tperms\tРазрешения\t\n";
        let mut w = Window::new(parse_request(text));
        assert_eq!(w.entry, 1);
        w.step_entry(1);
        w.step_entry(1);
        assert_eq!(w.entry, 4, "the heading passed over");
        w.step_entry(1);
        assert_eq!(w.entry, 1, "round to the first choice");
        press(&mut w, Key::Character("3".into()));
        assert_eq!(w.entry, 4);
        assert_eq!(w.choices(), [1, 2, 4]);
        assert!(w.heading(3));
    }

    /// A container's permissions alone: its rows, guarded, and the changes
    /// answered — nothing before the guard.
    #[test]
    fn the_permissions_window_answers_its_changes() {
        let text = "mode\tperms\ntitle\tРазрешения\n\
                    perm\tx11\tX\tdefault:как у всех;on:вкл.;off:выкл.\n\
                    permof\tthis\tДля всех\tx11=default\nguard\t1500\n";
        let mut w = Window::new(parse_request(text));
        assert!(w.perms_only());
        let _ = w.update(Msg::Perm(0, 1));
        assert_eq!(w.perms_answer(), "", "taken before the guard");
        arm(&mut w);
        let _ = w.update(Msg::Perm(0, 2));
        assert_eq!(w.perms_answer(), "perm\tx11\toff\n");
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

    /// The window opens at the height of what it shows: every entry and row
    /// counts, a new container's name adds none, and a list longer than a
    /// screen stops at the most a window opens at — it scrolls.
    #[test]
    fn the_window_opens_at_the_height_of_what_it_shows() {
        let menu = |entries: usize| {
            let actions: String = (0..entries)
                .map(|i| format!("action\ta{i}\tЗакрыть «Foot»\tdanger\n"))
                .collect();
            parse_request(&format!(
                "mode\tmenu\ntitle\tFoot\nnote\tFoot: без сети, контейнер: основной\n{actions}"
            ))
        };
        let (one, three) = (fitted_size(&menu(1)), fitted_size(&menu(3)));
        assert!(one.height < three.height, "{one:?} {three:?}");
        assert!(three.height < 420.0, "the old fixed height: {three:?}");
        assert!(one.width > 559.0 && one.width < 561.0, "{one:?}");

        let launch = fitted_size(&parse_request(REQUEST));
        let naming = REQUEST
            .replace("\tselected\n", "\t\n")
            .replace("\tnew\n", "\tnew,selected\n");
        let named = fitted_size(&parse_request(&naming));
        assert!(Window::new(parse_request(&naming)).naming());
        // Up to the rounding to a whole pixel.
        assert!(
            (launch.height - named.height).abs() < 1.5,
            "the name's field changes the height: {launch:?} {named:?}"
        );

        let rows: String = (0..60)
            .map(|i| format!("container\tc{i}\tКонтейнер «c{i}» — свой дом\t\n"))
            .collect();
        let long = parse_request(&format!("title\tt\nnet\tnl\tnl\t\n{rows}"));
        assert_eq!(fitted_size(&long), Size::new(840.0, MAX_HEIGHT));
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
