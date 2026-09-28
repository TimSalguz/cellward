//! `vpn-zone-window panel --cellward <cellward> [--tab network|containers]
//! [--dirs <kdialog>]` — the cellward window (2026-09-28): the network
//! monitor and the containers, on the toolkit of the launch window, in
//! place of the chains of kdialog menus `cellward-gui` was.
//!
//! It keeps nothing of the project's and decides nothing: every second it
//! reads `cellward _panel` again (the contract is `rust/src/panel.rs` of
//! vpn-zones, repeated in [`parse`]), and it acts through `cellward`'s own
//! verbs — `container set … network`, `container stop`, `container grant`,
//! `container revoke`, `container merge`, `container rm` —, which check and
//! refuse as they do from a terminal; what they say is shown. `--dirs`: the
//! kdialog it chooses a directory to grant with — a file dialog, not a menu.
//!
//! **Сеть**: what each running container sends and receives now (the
//! difference of two readings a second apart), since it came up, today and
//! over 30 days (`crate::traffic` of vpn-zones), each by its frame's colour.
//! **Контейнеры**: the list, and for the one chosen its home, network and
//! state, its network to change (live, with a word on what that breaks,
//! when its programs run in another), its granted directories, and what
//! `cellward explain` says of its permissions.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

use iced::keyboard::{self, key, Key};
use iced::widget::{button, column, container, row, scrollable, text};
use iced::{Alignment, Color, Element, Length, Size, Subscription, Task};

/// A container, as `cellward _panel` says it.
#[derive(Debug, Clone, Default, PartialEq)]
struct Cont {
    name: String,
    home: String,
    network: String,
    color: Option<Color>,
    /// Granted directories, with when they are taken back (0: never).
    paths: Vec<(String, u64)>,
}

#[derive(Debug, Clone, Default, PartialEq)]
struct Net {
    name: String,
    kind: String,
    up: bool,
    color: Option<Color>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Inst {
    id: String,
    container: String,
    network: String,
    out: u64,
    inb: u64,
    since: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Use {
    container: String,
    network: String,
    out: u64,
    inb: u64,
}

#[derive(Debug, Clone, Default, PartialEq)]
struct Data {
    containers: Vec<Cont>,
    networks: Vec<Net>,
    instances: Vec<Inst>,
    today: Vec<Use>,
    month: Vec<Use>,
}

fn color_of(hex: &str) -> Option<Color> {
    let hex = hex.strip_prefix('#')?;
    if hex.len() != 6 {
        return None;
    }
    let byte = |i: usize| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok();
    Some(Color::from_rgb8(byte(0)?, byte(2)?, byte(4)?))
}

/// `cellward _panel`'s lines (`rust/src/panel.rs` of vpn-zones); a line of
/// another shape is skipped.
fn parse(text: &str) -> Data {
    let mut d = Data::default();
    let num = |s: &str| s.parse::<u64>().unwrap_or(0);
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f.as_slice() {
            ["container", name, home, network, color] => d.containers.push(Cont {
                name: (*name).to_owned(),
                home: (*home).to_owned(),
                network: (*network).to_owned(),
                color: color_of(color),
                paths: Vec::new(),
            }),
            ["path", of, path, until] => {
                if let Some(c) = d.containers.iter_mut().find(|c| c.name == *of) {
                    c.paths.push(((*path).to_owned(), num(until)));
                }
            }
            ["network", name, kind, up, color] => d.networks.push(Net {
                name: (*name).to_owned(),
                kind: (*kind).to_owned(),
                up: *up == "1",
                color: color_of(color),
            }),
            ["instance", id, of, network, out, inb, since] => d.instances.push(Inst {
                id: (*id).to_owned(),
                container: (*of).to_owned(),
                network: (*network).to_owned(),
                out: num(out),
                inb: num(inb),
                since: num(since),
            }),
            [kind @ ("today" | "month"), of, network, out, inb] => {
                let u = Use {
                    container: (*of).to_owned(),
                    network: (*network).to_owned(),
                    out: num(out),
                    inb: num(inb),
                };
                if *kind == "today" {
                    d.today.push(u);
                } else {
                    d.month.push(u);
                }
            }
            _ => {}
        }
    }
    d
}

/// A count of bytes for a person: `crate::traffic::bytes_text` of vpn-zones.
fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn rate(per_second: f64) -> String {
    format!("{}/с", bytes(per_second.max(0.0).round() as u64))
}

/// A home, for a person.
fn home_text(home: &str) -> &'static str {
    match home {
        "private" => "свой дом",
        "layer" => "слой над настоящим домом",
        "main" => "настоящий дом",
        _ => "?",
    }
}

/// A network, for a person.
fn network_text(network: &str) -> String {
    match network {
        "ask" => "спрашивать при запуске".to_owned(),
        "offline" => "без сети".to_owned(),
        "unconfined" => "без ограничений (сеть хоста)".to_owned(),
        zone => format!("VPN: {zone}"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Network,
    Containers,
}

/// What waits for the person's word before it is done.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Pending {
    /// Its programs run in another network: switch now, or with a restart.
    Switch(String),
    /// A directory chosen: for how long.
    Grant(String),
    /// Merge into which one.
    Merge,
    /// Merge into this one, the person agreeing.
    MergeInto(String),
    /// And to the other's root certificates (`container merge --yes`).
    MergeCertificates(String, String),
    Remove,
}

#[derive(Debug, Clone)]
enum Msg {
    Tab(Tab),
    Tick,
    Loaded(Result<String, String>),
    Select(String),
    Explained(String, Result<String, String>),
    SetNetwork(String),
    Switch(bool),
    Stop,
    GrantAsk,
    Chosen(Option<String>),
    GrantFor(&'static str),
    Revoke(String),
    MergeAsk,
    MergeInto(String),
    MergeGo,
    MergeCertificatesGo,
    RemoveAsk,
    RemoveGo,
    Cancel,
    Done(Result<String, String>),
    MergeDone(String, Result<String, String>),
    Escape,
    /// ←/→: the other tab.
    OtherTab,
    /// ↑/↓ in the containers: the one before or after the chosen one.
    Step(i32),
}

struct Panel {
    cellward: PathBuf,
    dirs: Option<PathBuf>,
    tab: Tab,
    data: Data,
    /// The last reading of each instance, and when it was taken.
    last: HashMap<String, (u64, u64, u64, Instant)>,
    /// What each instance sends and receives now, per second.
    rates: HashMap<String, (f64, f64)>,
    selected: Option<String>,
    explained: Option<(String, Result<String, String>)>,
    pending: Option<Pending>,
    /// What the last action said: `Ok` done, `Err` refused.
    said: Option<Result<String, String>>,
    /// An action runs: nothing else is started meanwhile.
    busy: bool,
    /// What reading `cellward _panel` said, when it failed.
    trouble: Option<String>,
}

/// Run `cellward <args>` off the window's threads; its output, or why not.
fn cellward(
    path: PathBuf,
    args: Vec<String>,
) -> impl std::future::Future<Output = Result<String, String>> {
    async move {
        let (done, over) = iced::futures::channel::oneshot::channel();
        std::thread::spawn(move || {
            let result = match Command::new(&path)
                .args(&args)
                .stdin(Stdio::null())
                .output()
            {
                Ok(out) => {
                    let said = format!(
                        "{}{}",
                        String::from_utf8_lossy(&out.stdout),
                        String::from_utf8_lossy(&out.stderr)
                    )
                    .trim()
                    .to_owned();
                    if out.status.success() {
                        Ok(said)
                    } else {
                        Err(said)
                    }
                }
                Err(e) => Err(format!("cellward не запустился: {e}")),
            };
            let _ = done.send(result);
        });
        over.await
            .unwrap_or_else(|_| Err("cellward не ответил".to_owned()))
    }
}

/// `cellward _panel`, without its stderr in the way: the lines alone.
fn load(path: PathBuf) -> Task<Msg> {
    Task::perform(cellward(path, vec!["_panel".to_owned()]), Msg::Loaded)
}

/// `Msg::Tick` a second from now: slept on a thread of its own, as the
/// launch window's guard is (`arm_after`) — never on the executor's pool,
/// which carries the input.
fn tick_later() -> Task<Msg> {
    Task::perform(
        async {
            let (done, over) = iced::futures::channel::oneshot::channel();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(1));
                let _ = done.send(());
            });
            let _ = over.await;
        },
        |()| Msg::Tick,
    )
}

/// A directory to grant, chosen in the file dialog of `dirs` (kdialog);
/// `None` when none was.
fn choose_dir(dirs: PathBuf) -> Task<Msg> {
    Task::perform(
        async move {
            let (done, over) = iced::futures::channel::oneshot::channel();
            std::thread::spawn(move || {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_owned());
                let chosen = Command::new(&dirs)
                    .args([
                        "--title",
                        "Какой каталог выдать?",
                        "--getexistingdirectory",
                        home.as_str(),
                    ])
                    .stdin(Stdio::null())
                    .stderr(Stdio::null())
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
                    .filter(|d| !d.is_empty());
                let _ = done.send(chosen);
            });
            over.await.ok().flatten()
        },
        Msg::Chosen,
    )
}

impl Panel {
    fn new(cellward: PathBuf, dirs: Option<PathBuf>, tab: Tab) -> Self {
        Self {
            cellward,
            dirs,
            tab,
            data: Data::default(),
            last: HashMap::new(),
            rates: HashMap::new(),
            selected: None,
            explained: None,
            pending: None,
            said: None,
            busy: false,
            trouble: None,
        }
    }

    fn chosen(&self) -> Option<&Cont> {
        let name = self.selected.as_deref()?;
        self.data.containers.iter().find(|c| c.name == name)
    }

    /// The instance a container runs in now, if it runs.
    fn running(&self, name: &str) -> Option<&Inst> {
        self.data.instances.iter().find(|i| i.container == name)
    }

    fn act(&mut self, args: Vec<String>) -> Task<Msg> {
        self.busy = true;
        self.said = None;
        self.pending = None;
        Task::perform(cellward(self.cellward.clone(), args), Msg::Done)
    }

    fn explain(&self, name: String) -> Task<Msg> {
        let path = self.cellward.clone();
        Task::perform(
            cellward(path, vec!["explain".to_owned(), name.clone()]),
            move |r| Msg::Explained(name.clone(), r),
        )
    }

    fn update(&mut self, msg: Msg) -> Task<Msg> {
        match msg {
            Msg::Tab(tab) => {
                self.tab = tab;
                Task::none()
            }
            Msg::Tick => load(self.cellward.clone()),
            Msg::Loaded(Ok(text)) => {
                let now = Instant::now();
                let data = parse(&text);
                let mut last = HashMap::new();
                let mut rates = HashMap::new();
                for i in &data.instances {
                    if let Some((out, inb, since, at)) = self.last.get(&i.id) {
                        let dt = now.duration_since(*at).as_secs_f64();
                        if *since == i.since && dt > 0.2 {
                            rates.insert(
                                i.id.clone(),
                                (
                                    i.out.saturating_sub(*out) as f64 / dt,
                                    i.inb.saturating_sub(*inb) as f64 / dt,
                                ),
                            );
                        }
                    }
                    last.insert(i.id.clone(), (i.out, i.inb, i.since, now));
                }
                self.last = last;
                self.rates = rates;
                self.data = data;
                self.trouble = None;
                // A container gone: nothing chosen.
                if self.chosen().is_none() {
                    self.selected = None;
                }
                tick_later()
            }
            Msg::Loaded(Err(why)) => {
                self.trouble = Some(why);
                tick_later()
            }
            Msg::Select(name) => {
                self.selected = Some(name.clone());
                self.pending = None;
                self.said = None;
                self.explained = None;
                self.explain(name)
            }
            Msg::Explained(name, result) => {
                if self.selected.as_deref() == Some(name.as_str()) {
                    self.explained = Some((name, result));
                }
                Task::none()
            }
            Msg::SetNetwork(to) => {
                let Some(c) = self.chosen().cloned() else {
                    return Task::none();
                };
                let elsewhere = self
                    .running(&c.name)
                    .is_some_and(|i| i.network != to && to != "ask");
                if elsewhere {
                    self.pending = Some(Pending::Switch(to));
                    Task::none()
                } else {
                    self.act(vec![
                        "container".into(),
                        "set".into(),
                        c.name,
                        "network".into(),
                        to,
                    ])
                }
            }
            Msg::Switch(restart) => {
                let (Some(c), Some(Pending::Switch(to))) =
                    (self.chosen().cloned(), self.pending.clone())
                else {
                    return Task::none();
                };
                let mut args = vec![
                    "container".into(),
                    "set".into(),
                    c.name,
                    "network".into(),
                    to,
                ];
                if restart {
                    args.push("--restart".into());
                }
                args.push("--yes".into());
                self.act(args)
            }
            Msg::Stop => match self.chosen().cloned() {
                Some(c) => self.act(vec!["container".into(), "stop".into(), c.name]),
                None => Task::none(),
            },
            Msg::GrantAsk => match self.dirs.clone() {
                Some(dirs) => choose_dir(dirs),
                None => {
                    self.said = Some(Err(
                        "выбрать каталог нечем — в терминале: cellward container grant <контейнер> \
                         <каталог>"
                            .to_owned(),
                    ));
                    Task::none()
                }
            },
            Msg::Chosen(Some(dir)) => {
                self.pending = Some(Pending::Grant(dir));
                Task::none()
            }
            Msg::Chosen(None) => Task::none(),
            Msg::GrantFor(term) => {
                let (Some(c), Some(Pending::Grant(dir))) =
                    (self.chosen().cloned(), self.pending.clone())
                else {
                    return Task::none();
                };
                let mut args = vec!["container".into(), "grant".into(), c.name, dir];
                if term != "always" {
                    args.push("--for".into());
                    args.push(term.to_owned());
                }
                self.act(args)
            }
            Msg::Revoke(path) => match self.chosen().cloned() {
                Some(c) => self.act(vec!["container".into(), "revoke".into(), c.name, path]),
                None => Task::none(),
            },
            Msg::MergeAsk => {
                self.pending = Some(Pending::Merge);
                Task::none()
            }
            Msg::MergeInto(into) => {
                self.pending = Some(Pending::MergeInto(into));
                Task::none()
            }
            Msg::MergeGo => {
                let (Some(c), Some(Pending::MergeInto(into))) =
                    (self.chosen().cloned(), self.pending.clone())
                else {
                    return Task::none();
                };
                self.busy = true;
                self.said = None;
                self.pending = None;
                let args = vec!["container".into(), "merge".into(), c.name, into.clone()];
                Task::perform(cellward(self.cellward.clone(), args), move |r| {
                    Msg::MergeDone(into.clone(), r)
                })
            }
            Msg::MergeDone(into, Err(said)) if said.contains("--yes") => {
                self.busy = false;
                self.pending = Some(Pending::MergeCertificates(into, said));
                Task::none()
            }
            Msg::MergeDone(_, result) => self.update(Msg::Done(result)),
            Msg::MergeCertificatesGo => {
                let (Some(c), Some(Pending::MergeCertificates(into, _))) =
                    (self.chosen().cloned(), self.pending.clone())
                else {
                    return Task::none();
                };
                self.act(vec![
                    "container".into(),
                    "merge".into(),
                    c.name,
                    into,
                    "--yes".into(),
                ])
            }
            Msg::RemoveAsk => {
                self.pending = Some(Pending::Remove);
                Task::none()
            }
            Msg::RemoveGo => match self.chosen().cloned() {
                Some(c) => {
                    self.selected = None;
                    self.explained = None;
                    self.act(vec!["container".into(), "rm".into(), c.name])
                }
                None => Task::none(),
            },
            Msg::Cancel => {
                self.pending = None;
                Task::none()
            }
            Msg::Done(result) => {
                self.busy = false;
                self.said = Some(result);
                let mut tasks = vec![load(self.cellward.clone())];
                if let Some(name) = self.selected.clone() {
                    tasks.push(self.explain(name));
                }
                Task::batch(tasks)
            }
            Msg::OtherTab => {
                self.tab = match self.tab {
                    Tab::Network => Tab::Containers,
                    Tab::Containers => Tab::Network,
                };
                Task::none()
            }
            Msg::Step(by) => {
                if self.tab != Tab::Containers || self.pending.is_some() {
                    return Task::none();
                }
                let names: Vec<String> = self
                    .data
                    .containers
                    .iter()
                    .map(|c| c.name.clone())
                    .collect();
                if names.is_empty() {
                    return Task::none();
                }
                let at = self
                    .selected
                    .as_ref()
                    .and_then(|s| names.iter().position(|n| n == s));
                let next = match at {
                    None => 0,
                    Some(i) => (i as i64 + i64::from(by)).clamp(0, names.len() as i64 - 1) as usize,
                };
                self.update(Msg::Select(names[next].clone()))
            }
            Msg::Escape => {
                if self.pending.is_some() {
                    self.pending = None;
                    Task::none()
                } else {
                    std::process::exit(0)
                }
            }
        }
    }

    fn color_of_instance(&self, i: &Inst) -> Color {
        self.data
            .containers
            .iter()
            .find(|c| c.name == i.container)
            .and_then(|c| c.color)
            .or_else(|| {
                self.data
                    .networks
                    .iter()
                    .find(|n| n.name == i.network)
                    .and_then(|n| n.color)
            })
            .unwrap_or(Color::from_rgb8(0x88, 0x88, 0x88))
    }

    fn view(&self) -> Element<'_, Msg> {
        let tab = |label: &'static str, which: Tab| {
            button(text(label).size(15))
                .padding([6, 14])
                .style(if self.tab == which {
                    button::primary
                } else {
                    button::secondary
                })
                .on_press(Msg::Tab(which))
        };
        let note = self
            .trouble
            .as_deref()
            .map_or(String::new(), |t| format!("⚠ {t}"));
        let top = row![
            tab("Сеть", Tab::Network),
            tab("Контейнеры", Tab::Containers),
            container(text(note).size(13)).width(Length::Fill),
            button(text("Закрыть  Esc").size(14))
                .padding([6, 14])
                .style(button::secondary)
                .on_press(Msg::Escape),
        ]
        .spacing(8)
        .align_y(Alignment::Center);
        let body = match self.tab {
            Tab::Network => self.view_network(),
            Tab::Containers => self.view_containers(),
        };
        column![top, body].spacing(12).padding(16).into()
    }

    fn use_rows<'a>(&'a self, title: &'a str, uses: &'a [Use]) -> Element<'a, Msg> {
        let mut block = column![text(title).size(17)].spacing(4);
        if uses.is_empty() {
            block = block.push(text("ничего не записано").size(13));
        }
        for u in uses {
            let color = self
                .data
                .containers
                .iter()
                .find(|c| c.name == u.container)
                .and_then(|c| c.color)
                .unwrap_or(Color::from_rgb8(0x88, 0x88, 0x88));
            block = block.push(
                row![
                    text("●").size(14).color(color),
                    text(u.container.as_str())
                        .size(14)
                        .width(Length::Fixed(260.0)),
                    text(network_text(&u.network))
                        .size(14)
                        .width(Length::Fixed(200.0)),
                    text(format!("↑ {}", bytes(u.out)))
                        .size(14)
                        .width(Length::Fixed(120.0)),
                    text(format!("↓ {}", bytes(u.inb))).size(14),
                ]
                .spacing(8),
            );
        }
        block.into()
    }

    fn view_network(&self) -> Element<'_, Msg> {
        let mut now = column![text("Сейчас").size(17)].spacing(4);
        if self.data.instances.is_empty() {
            now = now.push(text("ни один контейнер сейчас не работает").size(13));
        }
        for i in &self.data.instances {
            let (up, down) = self.rates.get(&i.id).copied().unwrap_or((0.0, 0.0));
            let who = if i.container == "-" {
                i.id.as_str()
            } else {
                i.container.as_str()
            };
            now = now.push(
                row![
                    text("●").size(14).color(self.color_of_instance(i)),
                    text(who).size(14).width(Length::Fixed(260.0)),
                    text(network_text(&i.network))
                        .size(14)
                        .width(Length::Fixed(200.0)),
                    text(format!("↑ {}", rate(up)))
                        .size(14)
                        .width(Length::Fixed(120.0)),
                    text(format!("↓ {}", rate(down)))
                        .size(14)
                        .width(Length::Fixed(120.0)),
                    text(format!("всего ↑ {} ↓ {}", bytes(i.out), bytes(i.inb))).size(13),
                ]
                .spacing(8),
            );
        }
        let page = column![
            now,
            self.use_rows("Сегодня", &self.data.today),
            self.use_rows("За 30 дней", &self.data.month),
        ]
        .spacing(18);
        scrollable(page).height(Length::Fill).into()
    }

    fn view_containers(&self) -> Element<'_, Msg> {
        let mut list = column![].spacing(4);
        if self.data.containers.is_empty() {
            list = list.push(
                text("Контейнеров нет: их заводит окно запуска («Новый контейнер…»)").size(13),
            );
        }
        for c in &self.data.containers {
            let chosen = self.selected.as_deref() == Some(c.name.as_str());
            let running = if self.running(&c.name).is_some() {
                " ▶"
            } else {
                ""
            };
            list = list.push(
                button(
                    row![
                        text("●")
                            .size(14)
                            .color(c.color.unwrap_or(Color::from_rgb8(0x88, 0x88, 0x88))),
                        text(format!("{}{running}", c.name)).size(14),
                    ]
                    .spacing(6),
                )
                .width(Length::Fill)
                .padding([6, 10])
                .style(if chosen {
                    button::primary
                } else {
                    button::text
                })
                .on_press(Msg::Select(c.name.clone())),
            );
        }
        let left = container(scrollable(list).height(Length::Fill)).width(Length::FillPortion(2));
        let right = container(scrollable(self.view_chosen()).height(Length::Fill))
            .width(Length::FillPortion(5));
        row![left, right].spacing(16).height(Length::Fill).into()
    }

    fn view_chosen(&self) -> Element<'_, Msg> {
        let Some(c) = self.chosen() else {
            return text("Выбери контейнер слева").size(14).into();
        };
        let running = self.running(&c.name);
        let mut page = column![text(c.name.as_str()).size(20)].spacing(10);
        page = page.push(text(format!("Дом: {}", home_text(&c.home))).size(14));
        page = page.push(text(format!("Сеть: {}", network_text(&c.network))).size(14));
        page = page.push(
            text(match running {
                Some(i) => format!(
                    "Работает в сети «{}»: всего ↑ {} ↓ {}",
                    i.network,
                    bytes(i.out),
                    bytes(i.inb)
                ),
                None => "Не работает".to_owned(),
            })
            .size(14),
        );
        if let Some(said) = &self.said {
            let (mark, what, color) = match said {
                Ok(t) => ("✓", t.as_str(), Color::from_rgb8(0x2e, 0x9d, 0x55)),
                Err(t) => ("⚠", t.as_str(), Color::from_rgb8(0xd0, 0x3a, 0x3a)),
            };
            page = page.push(
                text(format!("{mark} {what}"))
                    .size(13)
                    .color(color)
                    .wrapping(iced::widget::text::Wrapping::WordOrGlyph),
            );
        }
        if let Some(pending) = &self.pending {
            page = page.push(self.view_pending(c, pending));
            return page.into();
        }
        let idle = !self.busy;
        // Its network.
        let mut nets = column![].spacing(4);
        let mut choices: Vec<(String, String)> = vec![("ask".into(), "Спрашивать".into())];
        for n in &self.data.networks {
            let label = match n.kind.as_str() {
                "offline" => "Без сети".to_owned(),
                "unconfined" => "Хоста".to_owned(),
                _ if n.up => n.name.clone(),
                _ => format!("{} (опущена)", n.name),
            };
            choices.push((n.name.clone(), label));
        }
        for (name, label) in choices {
            let current = c.network == name;
            nets = nets.push(
                button(text(label).size(13))
                    .padding([4, 10])
                    .style(if current {
                        button::primary
                    } else {
                        button::secondary
                    })
                    .on_press_maybe((idle && !current).then(|| Msg::SetNetwork(name.clone()))),
            );
        }
        page = page.push(text("Сеть контейнера").size(16));
        page = page.push(nets);
        // Its granted directories.
        if c.home != "main" {
            page = page.push(text("Выданные каталоги").size(16));
            if c.paths.is_empty() {
                page = page.push(text("нет").size(13));
            }
            for (path, until) in &c.paths {
                let term = if *until == 0 {
                    String::new()
                } else {
                    " (на срок)".to_owned()
                };
                page = page.push(
                    row![
                        text(format!("{path}{term}")).size(13).width(Length::Fill),
                        button(text("Забрать").size(13))
                            .padding([3, 8])
                            .style(button::secondary)
                            .on_press_maybe(idle.then(|| Msg::Revoke(path.clone()))),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                );
            }
            page = page.push(
                button(text("Выдать каталог…").size(13))
                    .padding([4, 10])
                    .style(button::secondary)
                    .on_press_maybe(idle.then_some(Msg::GrantAsk)),
            );
        }
        // What else.
        let mut acts = row![].spacing(6);
        if running.is_some() {
            acts = acts.push(
                button(text("Остановить").size(13))
                    .padding([4, 10])
                    .style(button::secondary)
                    .on_press_maybe(idle.then_some(Msg::Stop)),
            );
        }
        acts = acts.push(
            button(text("Объединить с…").size(13))
                .padding([4, 10])
                .style(button::secondary)
                .on_press_maybe(idle.then_some(Msg::MergeAsk)),
        );
        acts = acts.push(
            button(text("Удалить…").size(13))
                .padding([4, 10])
                .style(button::danger)
                .on_press_maybe(idle.then_some(Msg::RemoveAsk)),
        );
        page = page.push(text("Действия").size(16));
        page = page.push(acts);
        // Its permissions, as cellward explains them.
        page = page.push(text("Разрешения").size(16));
        let explained = match &self.explained {
            Some((_, Ok(t))) | Some((_, Err(t))) => t.as_str(),
            None => "…",
        };
        page = page.push(
            container(
                text(explained)
                    .size(12)
                    .font(iced::Font::MONOSPACE)
                    .wrapping(iced::widget::text::Wrapping::WordOrGlyph),
            )
            .padding(8)
            .width(Length::Fill)
            .style(container::bordered_box),
        );
        page.into()
    }

    fn view_pending<'a>(&'a self, c: &'a Cont, pending: &'a Pending) -> Element<'a, Msg> {
        let cancel = button(text("Отмена  Esc").size(13))
            .padding([4, 10])
            .style(button::secondary)
            .on_press(Msg::Cancel);
        let go = |label: String, msg: Msg, danger: bool| {
            button(text(label).size(13))
                .padding([4, 10])
                .style(if danger {
                    button::danger
                } else {
                    button::primary
                })
                .on_press(msg)
        };
        let question = |t: String| {
            text(t)
                .size(14)
                .wrapping(iced::widget::text::Wrapping::WordOrGlyph)
        };
        let block: Element<'a, Msg> = match pending {
            Pending::Switch(to) => column![
                question(format!(
                    "Программы «{}» работают в другой сети. Сменить её на «{to}» на ходу? \
                     Программы останутся, их соединения оборвутся, и ничего из прежней сети \
                     в новой не заговорит. Или закрыть их и открыть уже в новой.",
                    c.name
                )),
                row![
                    go("Сменить сейчас".into(), Msg::Switch(false), false),
                    go(
                        "Сменить и перезапустить программы".into(),
                        Msg::Switch(true),
                        false
                    ),
                    cancel
                ]
                .spacing(6)
            ]
            .spacing(8)
            .into(),
            Pending::Grant(dir) => column![
                question(format!(
                    "Надолго ли выдать «{dir}» контейнеру «{}»? По истечении срока каталог \
                     отмонтируется и у уже запущенных программ.",
                    c.name
                )),
                row![
                    go("Бессрочно".into(), Msg::GrantFor("always"), false),
                    go("На час".into(), Msg::GrantFor("1h"), false),
                    go("На сутки".into(), Msg::GrantFor("1d"), false),
                    go("На неделю".into(), Msg::GrantFor("7d"), false),
                    cancel
                ]
                .spacing(6)
            ]
            .spacing(8)
            .into(),
            Pending::Merge => {
                let mut targets = column![question(format!(
                    "В какой контейнер перенести данные и программы «{}»? Только того же вида.",
                    c.name
                ))]
                .spacing(6);
                let same: Vec<&Cont> = self
                    .data
                    .containers
                    .iter()
                    .filter(|o| o.home == c.home && o.name != c.name)
                    .collect();
                if same.is_empty() {
                    targets = targets.push(text("другого контейнера того же вида нет").size(13));
                }
                for o in same {
                    targets =
                        targets.push(go(o.name.clone(), Msg::MergeInto(o.name.clone()), false));
                }
                targets.push(cancel).into()
            }
            Pending::MergeInto(into) => column![
                question(format!(
                    "Перенести «{0}» в «{into}»? Совпавшие файлы останутся у «{into}», версии из \
                     «{0}» лягут рядом, в .merged-from-{0}. Программы «{0}» перейдут в «{into}». \
                     Сам «{0}» останется — удалишь, когда проверишь.",
                    c.name
                )),
                row![go("Объединить".into(), Msg::MergeGo, true), cancel].spacing(6)
            ]
            .spacing(8)
            .into(),
            Pending::MergeCertificates(into, said) => column![
                question(format!(
                    "{said}\n\n⚠ Программы «{into}» начнут доверять этим корневым сертификатам: \
                     их владелец сможет читать их TLS-трафик. Принять?"
                )),
                row![
                    go("Принять сертификаты".into(), Msg::MergeCertificatesGo, true),
                    cancel
                ]
                .spacing(6)
            ]
            .spacing(8)
            .into(),
            Pending::Remove => column![
                question(format!(
                    "Удалить контейнер «{}» вместе с его данными? Это не отменить.",
                    c.name
                )),
                row![go("Удалить".into(), Msg::RemoveGo, true), cancel].spacing(6)
            ]
            .spacing(8)
            .into(),
        };
        container(block)
            .padding(10)
            .width(Length::Fill)
            .style(container::bordered_box)
            .into()
    }

    fn subscription(&self) -> Subscription<Msg> {
        iced::event::listen_with(|event, _status, _window| match event {
            iced::Event::Keyboard(keyboard::Event::KeyPressed {
                key: Key::Named(named),
                ..
            }) => match named {
                key::Named::Escape => Some(Msg::Escape),
                key::Named::ArrowLeft | key::Named::ArrowRight => Some(Msg::OtherTab),
                key::Named::ArrowUp => Some(Msg::Step(-1)),
                key::Named::ArrowDown => Some(Msg::Step(1)),
                _ => None,
            },
            _ => None,
        })
    }
}

/// `panel …`: the window, until it is closed.
pub fn run(args: &[String]) -> iced::Result {
    let mut cellward: Option<PathBuf> = None;
    let mut dirs: Option<PathBuf> = None;
    let mut tab = Tab::Network;
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        let value = rest.next().cloned().unwrap_or_default();
        match flag.as_str() {
            "--cellward" => cellward = Some(PathBuf::from(value)),
            "--dirs" if !value.is_empty() => dirs = Some(PathBuf::from(value)),
            "--tab" if value == "containers" => tab = Tab::Containers,
            _ => {}
        }
    }
    let Some(cellward) = cellward else {
        eprintln!("vpn-zone-window panel: needs --cellward <path>");
        std::process::exit(2);
    };
    iced::application(
        move || {
            let panel = Panel::new(cellward.clone(), dirs.clone(), tab);
            let first = load(panel.cellward.clone());
            (panel, first)
        },
        Panel::update,
        Panel::view,
    )
    .title(|_: &Panel| "cellward".to_owned())
    .theme(|_: &Panel| None::<iced::Theme>)
    .subscription(Panel::subscription)
    .window(iced::window::Settings {
        size: Size::new(980.0, 640.0),
        position: iced::window::Position::Centered,
        #[cfg(target_os = "linux")]
        platform_specific: iced::window::settings::PlatformSpecific {
            application_id: "cellward".to_owned(),
            ..Default::default()
        },
        ..iced::window::Settings::default()
    })
    .run()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &str = "container\twork\tlayer\tnl\t#3366ff\n\
        path\twork\t/home/a/share\t0\n\
        path\tnobody\t/x\t0\n\
        container\tbank\tprivate\task\t#808080\n\
        network\tnl\tzone\t1\t#3366ff\n\
        network\toffline\toffline\t1\t#808080\n\
        instance\twork\twork\tnl\t1500\t3000\t1790000000\n\
        today\twork\tnl\t1500\t3000\n\
        month\twork\tnl\t9000\t12000\n\
        what\tever\n";

    /// The panel's lines read back: each kind in its place, a path of a
    /// container not listed and a line of no kind skipped.
    #[test]
    fn the_panels_lines_are_read() {
        let d = parse(DATA);
        assert_eq!(d.containers.len(), 2);
        assert_eq!(d.containers[0].paths, vec![("/home/a/share".to_owned(), 0)]);
        assert_eq!(
            d.containers[0].color,
            Some(Color::from_rgb8(0x33, 0x66, 0xff))
        );
        assert_eq!(d.networks.len(), 2);
        assert!(d.networks[0].up);
        assert_eq!(d.instances[0].inb, 3000);
        assert_eq!(d.today.len(), 1);
        assert_eq!(d.month[0].out, 9000);
        assert_eq!(color_of("#12345"), None);
        assert_eq!(color_of("123456"), None);
    }

    #[test]
    fn counts_are_said_as_the_cli_says_them() {
        assert_eq!(bytes(1536), "1.5 КБ");
        assert_eq!(rate(2048.4), "2.0 КБ/с");
        assert_eq!(rate(-5.0), "0 Б/с");
    }
}
