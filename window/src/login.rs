//! `vpn-zone-window login` — the connect window's login form (2026-09-29,
//! vpn-zones' `docs/PERMISSIONS.md` §11.16): the fields a network's gateway
//! asks for before it lets a tunnel up — the user, the group, the password,
//! a one-time code —, and whether to remember the password in the
//! session's keyring.
//!
//! The request on standard input, a line per item, tab-separated:
//!
//! ```text
//! title⇥<text>
//! note⇥<text>                          (any number)
//! guard⇥<ms>                           (nothing is taken before; optional)
//! field⇥<tag>⇥<label>⇥<kind>⇥<value>   kind: `text`, `optional` (may stay
//!                                      empty), `secret` (shown as dots) or
//!                                      `code` (a one-time code, may stay
//!                                      empty); the value prefilled
//! remember⇥<label>⇥0|1                 a box for the password (optional)
//! ```
//!
//! The answer, exit status 0: `field⇥<tag>⇥<value>` for each field, and
//! `remember⇥0|1` where there was a box. Exit status 1: closed, Esc or
//! «Отмена» — not connected; 3: it could not be shown. What is typed goes
//! to the caller alone, on this process's standard output — never a file,
//! never an argument.
//!
//! **The guard**, as the launch window's questions have it, but once: the
//! form takes nothing — no key, no click — until the person has been still
//! for the guard's time with it focused; a key or a press before that, or
//! the focus leaving, starts it again. After that it stays open for typing
//! (a question's guard comes back with every key; a form is typed into).
//! It opens when a launch asks, and takes the focus: the rest of a password
//! somebody is typing into another program must not land here, nor its
//! Enter send it to a gateway.

use std::io::Read;

use iced::keyboard::{self, key, Key};
use iced::widget::{button, checkbox, column, container, row, text, text_input};
use iced::{Alignment, Element, Length, Size, Subscription, Task};

/// How a field is typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Text,
    /// Plain text that may stay empty (a group the gateway may not ask
    /// for).
    Optional,
    Secret,
    /// A one-time code: may stay empty (the gateway may not ask for one).
    Code,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Field {
    tag: String,
    label: String,
    kind: Kind,
    value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Request {
    title: String,
    notes: Vec<String>,
    guard: u64,
    fields: Vec<Field>,
    /// The box for the password, and whether it is ticked.
    remember: Option<(String, bool)>,
}

fn parse(text: &str) -> Request {
    let mut req = Request::default();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f.as_slice() {
            ["title", t, ..] => req.title = (*t).to_owned(),
            ["note", t, ..] => req.notes.push((*t).to_owned()),
            ["guard", ms, ..] => req.guard = ms.parse().unwrap_or(0),
            ["field", tag, label, kind, rest @ ..] => {
                let kind = match *kind {
                    "secret" => Kind::Secret,
                    "code" => Kind::Code,
                    "optional" => Kind::Optional,
                    _ => Kind::Text,
                };
                req.fields.push(Field {
                    tag: (*tag).to_owned(),
                    label: (*label).to_owned(),
                    kind,
                    value: rest.first().map_or_else(String::new, |v| (*v).to_owned()),
                });
            }
            ["remember", label, on, ..] => req.remember = Some(((*label).to_owned(), *on == "1")),
            _ => {}
        }
    }
    req
}

/// A value as the answer can carry it: no tab, no line break.
fn clean(value: &str) -> String {
    value
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect()
}

/// The answer's lines.
fn answer(req: &Request) -> String {
    let mut out: String = req
        .fields
        .iter()
        .map(|f| format!("field\t{}\t{}\n", f.tag, clean(&f.value)))
        .collect();
    if let Some((_, on)) = &req.remember {
        out.push_str(&format!("remember\t{}\n", u8::from(*on)));
    }
    out
}

/// Whether the form can be sent: every field that may not stay empty
/// filled.
fn complete(req: &Request) -> bool {
    req.fields
        .iter()
        .all(|f| matches!(f.kind, Kind::Code | Kind::Optional) || !f.value.is_empty())
}

#[derive(Debug, Clone)]
enum Msg {
    Input(usize, String),
    Remember(bool),
    Connect,
    Cancel,
    Key(Key),
    Press,
    Focus(bool),
    Armed(u64),
}

struct Form {
    req: Request,
    armed: bool,
    holds: u64,
    focused: bool,
}

/// `Msg::Armed(holds)` after `ms`, slept on a thread of its own (the launch
/// window's `arm_after`).
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

/// The id of the first field to type into: the first one empty.
fn first_empty(req: &Request) -> Option<usize> {
    req.fields.iter().position(|f| f.value.is_empty())
}

fn field_id(i: usize) -> iced::widget::Id {
    iced::widget::Id::from(format!("field-{i}"))
}

impl Form {
    fn new(req: Request) -> Self {
        Self {
            armed: req.guard == 0,
            holds: 0,
            focused: false,
            req,
        }
    }

    /// The guard again, while it is not over.
    fn hold(&mut self) -> Task<Msg> {
        if self.armed || self.req.guard == 0 {
            return Task::none();
        }
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
                Msg::Input(..) | Msg::Remember(_) | Msg::Connect | Msg::Press | Msg::Key(_) => {
                    return self.hold()
                }
                _ => {}
            }
        }
        match msg {
            Msg::Input(i, value) => {
                if let Some(f) = self.req.fields.get_mut(i) {
                    f.value = value;
                }
            }
            Msg::Remember(on) => {
                if let Some((_, r)) = &mut self.req.remember {
                    *r = on;
                }
            }
            Msg::Connect => {
                if complete(&self.req) {
                    print!("{}", answer(&self.req));
                    std::process::exit(0);
                }
            }
            Msg::Cancel => std::process::exit(1),
            Msg::Key(_) | Msg::Press => {}
            Msg::Focus(focused) => {
                self.focused = focused;
                if !self.armed {
                    return self.hold();
                }
            }
            Msg::Armed(holds) => {
                if holds == self.holds && self.focused && !self.armed {
                    self.armed = true;
                    return match first_empty(&self.req) {
                        Some(i) => iced::widget::operation::focus(field_id(i)),
                        None => Task::none(),
                    };
                }
            }
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
        for (i, f) in self.req.fields.iter().enumerate() {
            let mut input = text_input("", &f.value)
                .id(field_id(i))
                .secure(f.kind == Kind::Secret)
                .padding(6)
                .size(14);
            if self.armed {
                input = input
                    .on_input(move |v| Msg::Input(i, v))
                    .on_submit(Msg::Connect);
            }
            page = page.push(
                row![
                    container(text(f.label.as_str()).size(14)).width(Length::Fixed(170.0)),
                    input,
                ]
                .spacing(8)
                .align_y(Alignment::Center),
            );
        }
        if let Some((label, on)) = &self.req.remember {
            let mut boxed = checkbox(*on).label(label.as_str());
            if self.armed {
                boxed = boxed.on_toggle(Msg::Remember);
            }
            page = page.push(boxed);
        }
        let wait = if self.armed { "" } else { "Секунду…" };
        let ready = self.armed && complete(&self.req);
        page = page.push(
            row![
                container(text(wait).size(13)).width(Length::Fill),
                button(text("Подключить  Enter").size(14))
                    .padding([6, 14])
                    .style(button::primary)
                    .on_press_maybe(ready.then_some(Msg::Connect)),
                button(text("Отмена  Esc").size(14))
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

/// `login`: the form read from standard input, until it is sent or closed.
pub fn run() -> iced::Result {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        std::process::exit(1);
    }
    let req = parse(&input);
    // Nothing to fill in is no form: the caller asks another way.
    if req.fields.is_empty() {
        std::process::exit(3);
    }
    let title = if req.title.is_empty() {
        "Подключение".to_owned()
    } else {
        req.title.clone()
    };
    let height = 170.0
        + 42.0 * req.fields.len() as f32
        + 22.0 * req.notes.len() as f32
        + if req.remember.is_some() { 30.0 } else { 0.0 };
    let boot = std::sync::Mutex::new(Some(req));
    iced::application(
        move || {
            let req = boot
                .lock()
                .ok()
                .and_then(|mut r| r.take())
                .unwrap_or_default();
            (Form::new(req), Task::none())
        },
        Form::update,
        Form::view,
    )
    .title(move |_: &Form| title.clone())
    .theme(|_: &Form| None::<iced::Theme>)
    .subscription(Form::subscription)
    .window(iced::window::Settings {
        size: Size::new(560.0, height.clamp(240.0, 600.0)),
        position: iced::window::Position::Centered,
        // A fixed size: floated by the compositor itself, as a dialog.
        resizable: false,
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

    const REQUEST: &str = "title\tВход в сеть work\nnote\tШлюз vpn.example\nguard\t1500\n\
        field\tuser\tПользователь\ttext\tivan\n\
        field\tgroup\tГруппа\toptional\t\n\
        field\tpassword\tПароль\tsecret\t\n\
        field\tcode\tОдноразовый код\tcode\t\n\
        remember\tЗапомнить пароль\t0\nwhat\n";

    #[test]
    fn a_form_is_read_filled_and_answered() {
        let req = parse(REQUEST);
        assert_eq!(req.title, "Вход в сеть work");
        assert_eq!(req.guard, 1500);
        assert_eq!(req.fields.len(), 4);
        assert_eq!(req.fields[0].value, "ivan");
        assert_eq!(req.fields[2].kind, Kind::Secret);
        assert_eq!(req.fields[3].kind, Kind::Code);
        assert_eq!(req.remember, Some(("Запомнить пароль".to_owned(), false)));
        assert_eq!(first_empty(&req), Some(1));
        let mut form = Form::new(req);
        assert!(!form.armed, "a guarded form takes nothing at first");
        let _ = form.update(Msg::Input(2, "x".into()));
        assert_eq!(form.req.fields[2].value, "", "typed before the guard");
        form.armed = true;
        assert!(!complete(&form.req), "the password is empty");
        assert_eq!(form.req.fields[1].kind, Kind::Optional);
        let _ = form.update(Msg::Input(1, "staff".into()));
        let _ = form.update(Msg::Input(2, "pa\tss\nword".into()));
        let _ = form.update(Msg::Remember(true));
        assert!(complete(&form.req), "a code may stay empty");
        assert_eq!(
            answer(&form.req),
            "field\tuser\tivan\nfield\tgroup\tstaff\nfield\tpassword\tpassword\n\
             field\tcode\t\nremember\t1\n"
        );
    }
}
