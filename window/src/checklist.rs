//! `vpn-zone-window checklist` — a question with boxes to tick (2026-09-28):
//! what a program with a home of its own may see of the real one, asked at
//! its first launch (`fs_sandbox::settle_permissions` of vpn-zones), in
//! place of kdialog's checklist.
//!
//! The request on standard input, a line per item, tab-separated:
//!
//! ```text
//! title⇥<text>
//! note⇥<text>                      (any number)
//! guard⇥<ms>                       (nothing is taken before; optional)
//! check⇥<tag>⇥<label>⇥<flags>      (`danger`: said to open much)
//! ```
//!
//! The answer, exit status 0: `check⇥<tag>` for each box ticked. Exit
//! status 1: closed, Esc, or «ничего» — nothing allowed, the safe answer;
//! 3: it could not be shown.
//!
//! **The guard**, as the launch window's questions have it: the window
//! takes nothing — no tick, no button, no key but Esc — until the person
//! has been still for the guard's time with it focused; every key and every
//! press starts that again, and so does the focus coming back. It opens
//! when a launch asks, and takes the focus: somebody typing into something
//! else must not tick "the whole home" and say yes.

use std::io::Read;

use iced::keyboard::{self, key, Key};
use iced::widget::{button, checkbox, column, container, row, text};
use iced::{Alignment, Element, Length, Size, Subscription, Task};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Request {
    title: String,
    notes: Vec<String>,
    guard: u64,
    /// `(tag, label, danger)`.
    items: Vec<(String, String, bool)>,
}

fn parse(text: &str) -> Request {
    let mut req = Request::default();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f.as_slice() {
            ["title", t, ..] => req.title = (*t).to_owned(),
            ["note", t, ..] => req.notes.push((*t).to_owned()),
            ["guard", ms, ..] => req.guard = ms.parse().unwrap_or(0),
            ["check", tag, label, rest @ ..] => req.items.push((
                (*tag).to_owned(),
                (*label).to_owned(),
                rest.first()
                    .is_some_and(|flags| flags.split(',').any(|f| f == "danger")),
            )),
            _ => {}
        }
    }
    req
}

/// The answer's lines: the ticked boxes' tags.
fn answer(req: &Request, ticked: &[bool]) -> String {
    req.items
        .iter()
        .zip(ticked)
        .filter(|(_, t)| **t)
        .map(|((tag, _, _), _)| format!("check\t{tag}\n"))
        .collect()
}

#[derive(Debug, Clone)]
enum Msg {
    Toggle(usize, bool),
    Allow,
    Cancel,
    /// A key other than Esc, and whether a widget took it.
    Key(Key),
    Press,
    Focus(bool),
    Armed(u64),
}

struct List {
    req: Request,
    ticked: Vec<bool>,
    armed: bool,
    holds: u64,
    focused: bool,
}

/// `Msg::Armed(holds)` after `ms`: slept on a thread of its own, never on
/// the executor's pool, which carries the input (the launch window's
/// `arm_after`).
fn arm_after(ms: u64, holds: u64) -> Task<Msg> {
    Task::perform(
        async move {
            let (done, over) = iced::futures::channel::oneshot::channel();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(ms));
                let _ = done.send(());
            });
            let _ = over.await;
        },
        move |()| Msg::Armed(holds),
    )
}

impl List {
    fn new(req: Request) -> Self {
        Self {
            ticked: vec![false; req.items.len()],
            armed: req.guard == 0,
            holds: 0,
            focused: false,
            req,
        }
    }

    /// The guard again: nothing is taken until it is over, with the focus.
    fn hold(&mut self) -> Task<Msg> {
        if self.req.guard == 0 {
            return Task::none();
        }
        self.armed = false;
        self.holds += 1;
        if self.focused {
            arm_after(self.req.guard, self.holds)
        } else {
            Task::none()
        }
    }

    fn update(&mut self, msg: Msg) -> Task<Msg> {
        if !self.armed {
            match msg {
                Msg::Toggle(..) | Msg::Allow | Msg::Press | Msg::Key(_) => return self.hold(),
                _ => {}
            }
        }
        match msg {
            Msg::Toggle(i, v) => {
                if let Some(t) = self.ticked.get_mut(i) {
                    *t = v;
                }
            }
            Msg::Allow => {
                print!("{}", answer(&self.req, &self.ticked));
                std::process::exit(0);
            }
            Msg::Cancel => std::process::exit(1),
            Msg::Key(key) => {
                if key.as_ref() == Key::Named(key::Named::Enter) {
                    return self.update(Msg::Allow);
                }
            }
            Msg::Press => {}
            Msg::Focus(focused) => {
                self.focused = focused;
                if focused {
                    return self.hold();
                }
                if self.req.guard != 0 {
                    self.armed = false;
                    self.holds += 1;
                }
            }
            Msg::Armed(holds) => self.armed |= holds == self.holds && self.focused,
        }
        Task::none()
    }

    fn view(&self) -> Element<'_, Msg> {
        let mut page = column![text(self.req.title.as_str()).size(18)]
            .spacing(10)
            .padding(16);
        for note in &self.req.notes {
            page = page.push(
                text(note.as_str())
                    .size(14)
                    .wrapping(iced::widget::text::Wrapping::WordOrGlyph),
            );
        }
        let mut boxes = column![].spacing(6);
        for (i, (_, label, danger)) in self.req.items.iter().enumerate() {
            let label = if *danger {
                format!("⚠ {label}")
            } else {
                label.clone()
            };
            boxes = boxes.push(
                checkbox(self.ticked[i])
                    .label(label)
                    .on_toggle(move |v| Msg::Toggle(i, v)),
            );
        }
        page = page.push(boxes);
        let wait = if self.armed { "" } else { "Секунду…" };
        page = page.push(
            row![
                container(text(wait).size(13)).width(Length::Fill),
                button(text("Разрешить отмеченное  Enter").size(14))
                    .padding([6, 14])
                    .style(button::primary)
                    .on_press_maybe(self.armed.then_some(Msg::Allow)),
                button(text("Ничего  Esc").size(14))
                    .padding([6, 14])
                    .style(button::secondary)
                    .on_press(Msg::Cancel),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
        );
        page.into()
    }

    fn subscription(&self) -> Subscription<Msg> {
        iced::event::listen_with(|event, _status, _window| match event {
            iced::Event::Keyboard(keyboard::Event::KeyPressed { key, .. }) => {
                if key.as_ref() == Key::Named(key::Named::Escape) {
                    Some(Msg::Cancel)
                } else {
                    Some(Msg::Key(key))
                }
            }
            iced::Event::Mouse(iced::mouse::Event::ButtonPressed(_)) => Some(Msg::Press),
            iced::Event::Window(iced::window::Event::Focused) => Some(Msg::Focus(true)),
            iced::Event::Window(iced::window::Event::Unfocused) => Some(Msg::Focus(false)),
            _ => None,
        })
    }
}

/// `checklist`: the question read from standard input, until it is answered.
pub fn run() -> iced::Result {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        std::process::exit(1);
    }
    let req = parse(&input);
    // Nothing to tick is no question: the caller asks another way.
    if req.items.is_empty() {
        std::process::exit(3);
    }
    let title = if req.title.is_empty() {
        "Доступ к файлам".to_owned()
    } else {
        req.title.clone()
    };
    let height = 200.0 + 30.0 * req.items.len() as f32 + 22.0 * req.notes.len() as f32;
    let boot = std::sync::Mutex::new(Some(req));
    iced::application(
        move || {
            let req = boot
                .lock()
                .ok()
                .and_then(|mut r| r.take())
                .unwrap_or_default();
            (List::new(req), Task::none())
        },
        List::update,
        List::view,
    )
    .title(move |_: &List| title.clone())
    .theme(|_: &List| None::<iced::Theme>)
    .subscription(List::subscription)
    .window(iced::window::Settings {
        size: Size::new(600.0, height.clamp(260.0, 600.0)),
        position: iced::window::Position::Centered,
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

    /// The request read, the ticked boxes answered by their tags, a
    /// danger flag kept, a line of no kind skipped.
    #[test]
    fn a_checklist_is_read_and_answered() {
        let req = parse(
            "title\tДоступ к файлам: Firefox\nnote\tЧто показать?\nguard\t1500\n\
             check\tdownloads\tЗагрузки\t\ncheck\thome\tВесь дом\tdanger\nwhat\n",
        );
        assert_eq!(req.guard, 1500);
        assert_eq!(req.items.len(), 2);
        assert!(!req.items[0].2 && req.items[1].2);
        assert_eq!(answer(&req, &[true, false]), "check\tdownloads\n");
        assert_eq!(answer(&req, &[false, false]), "");
        let list = List::new(req);
        assert!(!list.armed, "a guarded list takes nothing at first");
    }
}
