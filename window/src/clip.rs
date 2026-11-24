//! `vpn-zone-window clip --history <name> [--launch <pid>] [--title <text>]`
//! — the clipboard history of one container (cellward's `docs/CLIPBOARD.md`),
//! as a messenger shows its messages: the oldest at the top, the newest at
//! the bottom where the window opens, a date between days, older copies
//! loaded as the person scrolls up.
//!
//! It holds nothing: every entry, every content comes from the daemon
//! (`clipd.rs`), asked off the window's threads. It pastes nothing either:
//! with `--launch` (the launch of the window it was opened from) Enter or
//! «Вставить» prints `paste⇥<history>⇥<id>` and exits 0 — the command that
//! opened it (`cellward clip-window`) has the daemon set that entry as the
//! selection, with the container's mark, and the program's proxy press
//! Ctrl+V. Without `--launch` there is nothing to paste into: the history is
//! browsed, an entry moved to another history or deleted. Esc, or closing
//! the window: exit 1, nothing printed.
//!
//! The search bar at the bottom, as a message is typed: words, live. «⋯» the
//! pattern builder (`pattern.rs`); 📅 what was copied or pasted when, in
//! local time (`days.rs`), and which kind of content.
//!
//! Keyboard: ↑/↓ the entry, Enter pastes it, / or Ctrl+F the search, Esc
//! closes what is open — a question, the builder, the dates — and then the
//! window.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use iced::keyboard::{self, key, Key};
use iced::widget::scrollable::{AbsoluteOffset, Viewport};
use iced::widget::{
    button, checkbox, column, container, mouse_area, operation, pick_list, rich_text, row,
    scrollable, span, text, text_editor, text_input,
};
use iced::{Alignment, Color, Element, Font, Length, Size, Subscription, Task};

use crate::clip_type;
use crate::clipd::{self, Entry, Filter, PAGE};
use crate::days;
use crate::i18n::{self, Key as UiKey, Language};
use crate::pattern::{self, Alphabet, Builder, Kind, Tag, Times, Tried};
use crate::type_input::{Mode as TypeMode, Timing};

const FEED: &str = "clip-feed";
const SEARCH: &str = "clip-search";

fn ui(key: UiKey) -> &'static str {
    i18n::text(Language::default(), key)
}

/// How long typing rests before the search is asked.
const DEBOUNCE_MS: u64 = 150;

/// A preview shows at most this many lines and characters.
const PREVIEW_LINES: usize = 3;
const PREVIEW_CHARS: usize = 180;
/// An image's thumbnail, in lines of text high, unless `--image-lines`.
const IMAGE_LINES: u32 = 3;
/// A line of a bubble's text (size 15), in pixels.
const LINE: f32 = 20.0;
/// An image larger than this is named, not fetched for a thumbnail.
const MAX_THUMB_SOURCE: u64 = 32 << 20;
const TYPE_MODES: [TypeMode; 2] = [TypeMode::Unicode, TypeMode::Keycodes];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardTarget {
    Host,
    Instance(String),
}
impl std::fmt::Display for ClipboardTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Host => f.write_str("Рабочий стол (хост, общий буфер)"),
            Self::Instance(id) => write!(f, "Контейнер: {id}"),
        }
    }
}

/// Which moments a date filter is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DateOf {
    Copied,
    Pasted,
}

/// A date filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum When {
    All,
    Today,
    Yesterday,
    Week,
    /// The day typed in `Dates::day`.
    Day,
    /// Around the moment typed in `Dates::at`, ± `Dates::hours`.
    Around,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dates {
    of: DateOf,
    when: When,
    day: String,
    at: String,
    hours: String,
}

impl Default for Dates {
    fn default() -> Self {
        Self {
            of: DateOf::Copied,
            when: When::All,
            day: String::new(),
            at: String::new(),
            hours: "2".to_owned(),
        }
    }
}

/// A search's dates: `(copied, pasted, around)`.
type Bounds = (Option<(i64, i64)>, Option<(i64, i64)>, Option<(i64, i64)>);

impl Dates {
    /// The filter's bounds in ms, local days; `Err` says what does not read.
    fn bounds(&self, now: i64) -> Result<Bounds, String> {
        let range = match self.when {
            When::All => return Ok((None, None, None)),
            When::Today => (days::day_start(now), days::day_shift(now, 1)),
            When::Yesterday => (days::day_shift(now, -1), days::day_start(now)),
            When::Week => (days::day_shift(now, -6), days::day_shift(now, 1)),
            When::Day => {
                let day = days::parse_date(&self.day, now, false)
                    .ok_or("Дата не читается: ДД.ММ или ДД.ММ.ГГГГ")?;
                (day, days::day_shift(day, 1))
            }
            When::Around => {
                let at = days::parse_date(&self.at, now, true)
                    .ok_or("Дата не читается: ДД.ММ.ГГГГ ЧЧ:ММ")?;
                let hours: f64 = self
                    .hours
                    .trim()
                    .replace(',', ".")
                    .parse()
                    .ok()
                    .filter(|h: &f64| *h > 0.0 && *h <= 24.0 * 366.0)
                    .ok_or("Часы не читаются: число больше нуля")?;
                let window = (hours * 3_600_000.0) as i64;
                return Ok(match self.of {
                    // The daemon's own "around" is a copy's.
                    DateOf::Copied => (None, None, Some((at, window))),
                    DateOf::Pasted => (None, Some((at - window, at + window)), None),
                });
            }
        };
        Ok(match self.of {
            DateOf::Copied => (Some(range), None, None),
            DateOf::Pasted => (None, Some(range), None),
        })
    }

    /// The filter in words, for the line of what is filtered.
    fn words(&self) -> Option<String> {
        let of = match self.of {
            DateOf::Copied => "скопировано",
            DateOf::Pasted => "вставлено",
        };
        let when = match self.when {
            When::All => return None,
            When::Today => "сегодня".to_owned(),
            When::Yesterday => "вчера".to_owned(),
            When::Week => "за неделю".to_owned(),
            When::Day => self.day.trim().to_owned(),
            When::Around => format!("около {} ± {} ч", self.at.trim(), self.hours.trim()),
        };
        Some(format!("{of} {when}"))
    }
}

/// The kinds of content to filter by: `(type, word)`.
const KINDS: [(&str, &str); 3] = [
    ("text/plain", "текст"),
    ("image/*", "картинки"),
    ("text/uri-list", "файлы и ссылки"),
];

/// A key the window acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Press {
    Up,
    Down,
    Enter,
    Search,
    Escape,
}

#[derive(Debug, Clone)]
pub enum Msg {
    Appearance,
    LivePoll,
    LiveLoaded {
        gen: u64,
        result: Result<Vec<Entry>, String>,
    },
    Preview(u64),
    PreviewLoaded(
        String,
        u64,
        Result<(Arc<crate::thumb::Source>, crate::thumb::Thumb, u32), String>,
    ),
    FitLoaded(String, u64, u32, Result<crate::thumb::Thumb, String>),
    NativeLoaded(String, u64, Result<crate::thumb::Thumb, String>),
    PreviewNative(bool),
    PreviewExpand,
    PreviewMaximize,
    PreviewClose,
    Resized(f32),
    Opened(iced::window::Id),
    Loaded {
        gen: u64,
        older: bool,
        result: Result<Vec<Entry>, String>,
    },
    Scrolled(Viewport),
    Words(String),
    Rested(u64),
    Select(usize),
    Paste(u64),
    CopyForPaste(u64),
    CopyToAsk(u64),
    LocalTarget(ClipboardTarget),
    CopyTo(u64),
    CopiedForPaste(ClipboardTarget, Result<String, String>),
    Got(String, u64, Result<String, String>),
    Thumb(String, u64, Result<crate::thumb::Thumb, String>),
    MoveAsk(u64),
    Histories(String, Result<Vec<String>, String>),
    Tabs(Result<Vec<String>, String>),
    Targets(Result<Vec<ClipboardTarget>, String>),
    Target(ClipboardTarget),
    Switch(String),
    Shelf(bool),
    Secrets,
    Favorite(u64),
    Favorited(String, Result<String, String>),
    SecretAsk(u64),
    SecretLabel(String),
    SecretYes(u64),
    Secreted(String, u64, Result<String, String>),
    CopySecretAsk(u64),
    CopySecretYes(u64),
    CopiedSecret(ClipboardTarget, Result<String, String>),
    EditSecret(u64),
    EditedLabel(String),
    EditedPassword(String),
    SaveSecret(u64),
    SavedSecret(String, Result<String, String>),
    TransferSecret(u64, String),
    TransferSecretYes(u64),
    TransferredSecret(String, Result<String, String>),
    Typing(bool),
    TypeMode(TypeMode),
    TypeLines(clip_type::LineBreaks),
    TypeDelay(&'static str, String),
    TypePick,
    TypePickWindow(Option<iced::window::Id>),
    TypeChosen(iced::window::Id, Result<clip_type::Target, String>),
    TypeSend(u64),
    TypeSendWindow(Option<iced::window::Id>, u64),
    Typed(iced::window::Id, Result<(), String>),
    TypeCancel,
    TypeCanceled(Result<(), String>),
    MoveTo(u64, String),
    Moved(Result<String, String>),
    DeleteAsk(u64),
    DeleteYes(u64),
    Deleted(String, u64, Result<String, String>),
    Cancel,
    Close,
    Key(Press),
    Dismiss,
    // The filters.
    DatesOpen,
    DateOf(DateOf),
    When(When),
    Day(String),
    At(String),
    Hours(String),
    Kind(usize, bool),
    ClearAll,
    // The pattern builder.
    BuilderOpen,
    Add(Tag),
    Remove(usize),
    Shift(usize, isize),
    Chars(usize, String),
    From(usize, String),
    To(usize, String),
    Alone(usize, bool),
    Letters(usize, Alphabet),
    Times(usize, Times),
    N(usize, String),
    M(usize, String),
    Lazy(usize, bool),
    Flag(usize, bool),
    Sample(text_editor::Action),
    Apply,
    Unapply,
}

struct LiveRefresh {
    gen: u64,
    history: String,
    filter: Filter,
    oldest: Option<u64>,
    before: Option<u64>,
    entries: Vec<Entry>,
}

type FullImage = Result<(iced::widget::image::Handle, u32, u32), String>;

struct CachedImage {
    source: Arc<crate::thumb::Source>,
    fit: iced::widget::image::Handle,
    fit_width: u32,
    full: Option<iced::widget::image::Handle>,
}

struct ImagePreview {
    id: u64,
    history: String,
    image: Option<FullImage>,
    native: bool,
    expanded: bool,
}

pub struct Clip {
    history: String,
    /// The host manager shows histories as tabs; a frame-opened history stays
    /// scoped to its launch and cannot silently browse another container.
    manager: bool,
    tabs: Vec<String>,
    tabs_loading: bool,
    tabs_error: Option<String>,
    targets: Vec<ClipboardTarget>,
    available_targets: Vec<ClipboardTarget>,
    targets_loading: bool,
    targets_error: Option<String>,
    target: ClipboardTarget,
    target_available: bool,
    favorites: bool,
    secrets: bool,
    /// A text's lines shown before «показать целиком», and an image's
    /// thumbnail's height in lines.
    lines: usize,
    image_lines: u32,
    /// Thumbnails made, or why not.
    thumbs: HashMap<u64, Result<iced::widget::image::Handle, String>>,
    can_paste: bool,
    socket: PathBuf,
    now: i64,
    /// Oldest first, as shown.
    entries: Vec<Entry>,
    /// Older entries than the first are left to load.
    older: bool,
    loading: bool,
    live: Option<LiveRefresh>,
    image_preview: Option<ImagePreview>,
    full_images: HashMap<(String, u64), Result<CachedImage, String>>,
    window_width: f32,
    /// The search's generation: an answer to an older one is dropped.
    gen: u64,
    /// The typing's: a rest of an older one asks nothing.
    typed: u64,
    selected: Option<usize>,
    words: String,
    kinds: [bool; 3],
    dates: Dates,
    dates_open: bool,
    /// The pattern searched by, once applied from the builder.
    re: Option<String>,
    builder: Builder,
    builder_open: bool,
    sample: text_editor::Content,
    /// Whole texts fetched for the selected entry's detail pane.
    whole: HashMap<u64, String>,
    whole_loading: HashSet<u64>,
    /// Moving an entry: the histories to move it to, once known.
    moving: Option<(u64, Option<Vec<String>>)>,
    deleting: Option<u64>,
    secreting: Option<u64>,
    secret_label: String,
    copying: Option<(u64, ClipboardTarget)>,
    copying_secret: Option<(u64, ClipboardTarget)>,
    editing_secret: Option<u64>,
    edited_label: String,
    edited_password: String,
    transferring_secret: Option<(u64, String)>,
    launch: Option<u32>,
    type_enabled: bool,
    type_busy: bool,
    type_target: Option<clip_type::Target>,
    type_active: Option<clip_type::Target>,
    type_mode: TypeMode,
    type_lines: clip_type::LineBreaks,
    type_start: String,
    type_between: String,
    type_hold: String,
    error: Option<String>,
    notice: Option<String>,
    /// The feed's offset from its bottom, and its height.
    view: (f32, f32),
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

/// What is printed for the caller to paste.
pub fn paste_line(history: &str, id: u64) -> String {
    format!("paste\t{history}\t{id}\n")
}

/// A size, for a person.
fn size_words(bytes: u64) -> String {
    match bytes {
        0..=1023 => format!("{bytes} Б"),
        1024..=1_048_575 => format!("{} КБ", (bytes + 512) / 1024),
        _ => format!("{:.1} МБ", bytes as f64 / 1_048_576.0).replace('.', ","),
    }
}

/// «раз»/«раза» after a count.
fn times(n: u32) -> &'static str {
    match (n % 10, n % 100) {
        (2..=4, r) if !(12..=14).contains(&r) => "раза",
        _ => "раз",
    }
}

/// An entry's line of when: copied, how many times, pasted.
fn meta_line(e: &Entry, now: i64) -> String {
    let mut words = vec![days::hour_label(e.last_copied)];
    if e.copies > 1 {
        words.push(format!("скопировано {} {}", e.copies, times(e.copies)));
    }
    if e.pastes > 0 {
        let last = if e.last_pasted > 0 {
            format!(", последний — {}", days::when_label(e.last_pasted, now))
        } else {
            String::new()
        };
        words.push(format!("вставлено {} {}{last}", e.pastes, times(e.pastes)));
    }
    words.join(" · ")
}

/// The preview cut at `max` lines, and whether there is more to see.
fn preview(e: &Entry, max: usize) -> (String, bool) {
    let lines: Vec<&str> = e.preview.lines().collect();
    let mut cut = lines.len() > max;
    let mut shown = if cut {
        format!("{}\n…", lines[..max].join("\n"))
    } else {
        e.preview.clone()
    };
    if shown.chars().count() > PREVIEW_CHARS {
        shown = format!("{}…", shown.chars().take(PREVIEW_CHARS).collect::<String>());
        cut = true;
    }
    let longer = e
        .text_size()
        .is_some_and(|size| size > e.preview.len() as u64);
    (shown, cut || longer)
}

/// Roughly how tall an entry's bubble is: to keep the one chosen by keys in
/// view without measuring the feed.
fn guessed_height(e: &Entry, whole: Option<&String>, chosen: bool, max: (usize, u32)) -> f32 {
    let lines = match whole {
        Some(t) => t.lines().count(),
        None if e.image().is_some() => max.1 as usize,
        None => preview(e, max.0).0.lines().count(),
    }
    .max(1);
    // Text, the line of when, padding; the actions under the chosen one.
    let mut h = 22.0 * lines as f32 + 46.0;
    if chosen {
        h += 40.0;
    }
    h
}

/// `ms` in ms, slept on a thread of its own.
fn later(ms: u64, then: Msg) -> Task<Msg> {
    Task::perform(
        clipd::off_thread(move || std::thread::sleep(std::time::Duration::from_millis(ms))),
        move |_| then.clone(),
    )
}

/// One bounded wake-up per second while a history window exists. All daemon
/// I/O is off-thread and only one live refresh may be in flight. Closing the
/// window drops the receiver and stops this worker within one interval.
fn live_updates() -> Subscription<()> {
    fn events() -> impl iced::futures::Stream<Item = ()> {
        let (mut sender, receiver) = iced::futures::channel::mpsc::channel(1);
        std::thread::spawn(move || {
            while !sender.is_closed() {
                std::thread::sleep(std::time::Duration::from_secs(1));
                let _ = sender.try_send(());
            }
        });
        receiver
    }
    Subscription::run(events)
}

fn dim(theme: &iced::Theme) -> text::Style {
    text::Style {
        color: Some(
            theme
                .extended_palette()
                .background
                .base
                .text
                .scale_alpha(0.6),
        ),
    }
}

fn danger(theme: &iced::Theme) -> text::Style {
    text::Style {
        color: Some(crate::appearance::error_text(theme)),
    }
}

/// A section's small title, as the builder's.
fn label(t: &str) -> Element<'_, Msg> {
    text(t.to_uppercase()).size(11).style(dim).into()
}

/// A bubble: every other one a shade apart, to tell them apart at a glance.
fn card(theme: &iced::Theme, chosen: bool, odd: bool) -> container::Style {
    let p = theme.extended_palette();
    container::Style {
        background: Some(
            if odd {
                p.background.weaker.color
            } else {
                p.background.weak.color
            }
            .into(),
        ),
        border: iced::Border {
            color: if chosen {
                p.primary.base.color
            } else {
                p.background.strong.color
            },
            width: if chosen { 2.0 } else { 1.0 },
            radius: 10.0.into(),
        },
        ..container::Style::default()
    }
}

fn pill(theme: &iced::Theme) -> container::Style {
    let p = theme.extended_palette();
    container::Style {
        background: Some(p.background.strong.color.scale_alpha(0.5).into()),
        border: iced::border::rounded(10),
        ..container::Style::default()
    }
}

fn mono<'a>(t: impl text::IntoFragment<'a>) -> iced::widget::Text<'a> {
    text(t).font(Font::MONOSPACE)
}

impl Clip {
    fn active_history(&self) -> String {
        if self.secrets {
            format!("@secrets:{}", self.history)
        } else if self.favorites {
            format!("@favorites:{}", self.history)
        } else {
            self.history.clone()
        }
    }

    fn switch_shelf(&mut self) -> Task<Msg> {
        self.image_preview = None;
        self.full_images.clear();
        self.entries.clear();
        self.selected = None;
        self.whole.clear();
        self.whole_loading.clear();
        self.thumbs.clear();
        self.moving = None;
        self.deleting = None;
        self.secreting = None;
        self.copying_secret = None;
        self.copying = None;
        self.clear_secret_editor();
        self.transferring_secret = None;
        self.error = None;
        self.notice = None;
        self.typed += 1;
        self.search()
    }

    fn clear_secret_editor(&mut self) {
        self.editing_secret = None;
        self.edited_label.clear();
        self.edited_password.clear();
    }

    fn type_timing(&self) -> Result<Timing, String> {
        let timing = Timing {
            start_ms: self
                .type_start
                .parse()
                .map_err(|_| "Начальная задержка: 0–5000 мс")?,
            between_ms: self
                .type_between
                .parse()
                .map_err(|_| "Между символами: 1–5000 мс")?,
            hold_ms: self
                .type_hold
                .parse()
                .map_err(|_| "Удержание клавиши: 1–1000 мс")?,
        };
        timing.valid().then_some(timing).ok_or_else(|| {
            "Задержки: начало 0–5000, между символами 1–5000, удержание 1–1000 мс".into()
        })
    }

    fn type_save(&mut self) {
        if let Ok(timing) = self.type_timing() {
            if let Err(why) = clip_type::save(timing, self.type_mode, self.type_lines) {
                self.error = Some(why);
            }
        }
    }

    pub fn new(history: String, can_paste: bool, socket: PathBuf) -> Self {
        let (timing, type_mode, type_lines) = clip_type::load();
        Self {
            history,
            manager: false,
            tabs: Vec::new(),
            tabs_loading: false,
            tabs_error: None,
            targets: vec![ClipboardTarget::Host],
            available_targets: vec![ClipboardTarget::Host],
            targets_loading: false,
            targets_error: None,
            target: ClipboardTarget::Host,
            target_available: true,
            favorites: false,
            secrets: false,
            lines: PREVIEW_LINES,
            image_lines: IMAGE_LINES,
            thumbs: HashMap::new(),
            can_paste,
            socket,
            now: now_ms(),
            entries: Vec::new(),
            older: false,
            loading: false,
            live: None,
            image_preview: None,
            full_images: HashMap::new(),
            window_width: 640.0,
            gen: 0,
            typed: 0,
            selected: None,
            words: String::new(),
            kinds: [false; 3],
            dates: Dates::default(),
            dates_open: false,
            re: None,
            builder: Builder::default(),
            builder_open: false,
            sample: text_editor::Content::new(),
            whole: HashMap::new(),
            whole_loading: HashSet::new(),
            moving: None,
            deleting: None,
            secreting: None,
            secret_label: String::new(),
            copying: None,
            copying_secret: None,
            editing_secret: None,
            edited_label: String::new(),
            edited_password: String::new(),
            transferring_secret: None,
            launch: None,
            type_enabled: false,
            type_busy: false,
            type_target: None,
            type_active: None,
            type_mode,
            type_lines,
            type_start: timing.start_ms.to_string(),
            type_between: timing.between_ms.to_string(),
            type_hold: timing.hold_ms.to_string(),
            error: None,
            notice: None,
            view: (0.0, 0.0),
        }
    }

    /// What the search asks, the dates as of `now`.
    pub fn filter(&self, now: i64) -> Result<Filter, String> {
        let (copied, pasted, around) = self.dates.bounds(now)?;
        Ok(Filter {
            words: self.words.clone(),
            re: self.re.clone(),
            types: KINDS
                .iter()
                .zip(self.kinds)
                .filter(|(_, on)| *on)
                .map(|((t, _), _)| (*t).to_owned())
                .collect(),
            copied,
            pasted,
            around,
        })
    }

    fn filtered(&self) -> bool {
        !self.words.trim().is_empty()
            || self.re.is_some()
            || self.kinds.iter().any(|k| *k)
            || self.dates.when != When::All
    }

    /// Ask a page: the newest (a new search), or older than the first shown.
    fn load(&mut self, older: bool) -> Task<Msg> {
        self.live = None;
        if older {
            // An older-page load changes the visible span a live snapshot
            // must cover. Invalidate any earlier background reply.
            self.gen += 1;
        }
        let now = now_ms();
        let filter = match self.filter(now) {
            Ok(f) => f,
            Err(why) => {
                self.error = Some(why);
                return Task::none();
            }
        };
        let before = if older {
            match self.entries.first() {
                Some(e) => Some(e.id),
                None => return Task::none(),
            }
        } else {
            None
        };
        self.now = now;
        self.loading = true;
        let request = clipd::search_request(&self.active_history(), &filter, before, PAGE);
        let socket = self.socket.clone();
        let gen = self.gen;
        Task::perform(
            clipd::off_thread(move || {
                clipd::ask_text(&socket, &request)
                    .map_err(|f| f.text())
                    .and_then(|a| clipd::parse_entries(&a))
            }),
            move |r| Msg::Loaded {
                gen,
                older,
                result: r.unwrap_or_else(|| Err("служба истории не ответила".to_owned())),
            },
        )
    }

    /// A new search: the feed from its newest again.
    fn search(&mut self) -> Task<Msg> {
        self.gen += 1;
        self.loading = false;
        self.load(false)
    }

    fn live_paused(&self) -> bool {
        self.type_busy
            || self.image_preview.is_some()
            || self.moving.is_some()
            || self.deleting.is_some()
            || self.secreting.is_some()
            || self.copying.is_some()
            || self.copying_secret.is_some()
            || self.editing_secret.is_some()
            || self.transferring_secret.is_some()
    }

    fn poll_live(&mut self) -> Task<Msg> {
        if self.loading || self.live.is_some() || self.live_paused() {
            return Task::none();
        }
        let Ok(filter) = self.filter(now_ms()) else {
            return Task::none();
        };
        self.live = Some(LiveRefresh {
            gen: self.gen,
            history: self.active_history(),
            filter,
            oldest: if self.following_newest() {
                // An idle window follows one bounded newest page instead of
                // accumulating every copy in memory for its whole lifetime.
                None
            } else {
                self.entries.first().map(|e| e.id)
            },
            before: None,
            entries: Vec::new(),
        });
        self.live_page()
    }

    fn live_page(&self) -> Task<Msg> {
        let Some(live) = &self.live else {
            return Task::none();
        };
        let request = clipd::search_request(&live.history, &live.filter, live.before, PAGE);
        let socket = self.socket.clone();
        let gen = live.gen;
        Task::perform(
            clipd::off_thread(move || {
                clipd::ask_text(&socket, &request)
                    .map_err(|f| f.text())
                    .and_then(|a| clipd::parse_entries(&a))
            }),
            move |r| Msg::LiveLoaded {
                gen,
                result: r.unwrap_or_else(|| Err("служба истории не ответила".to_owned())),
            },
        )
    }

    fn following_newest(&self) -> bool {
        self.view.0 < 24.0 && self.selected == self.entries.len().checked_sub(1)
    }

    fn live_loaded(&mut self, gen: u64, result: Result<Vec<Entry>, String>) -> Task<Msg> {
        if gen != self.gen || self.live.as_ref().is_none_or(|live| live.gen != gen) {
            return Task::none();
        }
        let Ok(page) = result else {
            // Retry after service recovery without clearing the current feed
            // or repeatedly replacing a person's validation/error message.
            self.live = None;
            return Task::none();
        };
        if self.live_paused()
            || (self.live.as_ref().is_some_and(|live| live.oldest.is_none())
                && !self.entries.is_empty()
                && !self.following_newest())
        {
            self.live = None;
            return Task::none();
        }
        let live = self.live.as_mut().unwrap();
        let before = page.last().map(|e| e.id);
        let full = page.len() >= PAGE;
        // Each background request is bounded to one page. A burst larger
        // than PAGE is followed back to the previously visible span before
        // committing it, so there is no hidden gap between old and new rows.
        let more = full
            && live
                .oldest
                .zip(before)
                .is_some_and(|(oldest, id)| id > oldest);
        if more
            && live
                .before
                .is_some_and(|previous| before.is_none_or(|id| id >= previous))
        {
            self.live = None;
            return Task::none();
        }
        live.entries.extend(page);
        live.before = before;
        if more {
            return self.live_page();
        }
        let mut live = self.live.take().unwrap();
        self.older = match live.oldest {
            Some(oldest) => live.entries.iter().any(|e| e.id < oldest) || (full && self.older),
            None => full,
        };
        // Catch-up may fetch part of an older page. Leave that part for
        // explicit upward scrolling instead of walking the entire history
        // backwards on every new copy.
        live.entries
            .retain(|e| live.oldest.is_none_or(|oldest| e.id >= oldest));
        live.entries.reverse();
        if live.entries == self.entries {
            return Task::none();
        }
        let following = self.following_newest();
        let selected = self
            .selected
            .and_then(|i| self.entries.get(i))
            .map(|e| e.id);
        let newest = self.entries.last().map(|e| e.id);
        let bottom = self.view.0 < 24.0;
        let added: f32 = live
            .entries
            .iter()
            .filter(|e| newest.is_none_or(|id| e.id > id))
            .map(|e| guessed_height(e, None, false, (self.lines, self.image_lines)) + 10.0)
            .sum();
        self.entries = live.entries;
        self.selected = selected.and_then(|id| self.entries.iter().position(|e| e.id == id));
        if following || (selected.is_none() && bottom) {
            self.selected = self.entries.len().checked_sub(1);
        }
        self.now = now_ms();
        self.whole
            .retain(|id, _| self.entries.iter().any(|e| e.id == *id));
        self.whole_loading
            .retain(|id| self.entries.iter().any(|e| e.id == *id));
        self.thumbs
            .retain(|id, _| self.entries.iter().any(|e| e.id == *id));
        let history = self.active_history();
        self.full_images
            .retain(|(at, id), _| *at == history && self.entries.iter().any(|e| e.id == *id));
        let page = self.entries.clone();
        let thumbs = self.thumbs_of(&page);
        let scroll = if bottom || added > 0.0 {
            operation::scroll_to(
                FEED,
                AbsoluteOffset {
                    x: None,
                    y: Some(if bottom { 0.0 } else { self.view.0 + added }),
                },
            )
        } else {
            Task::none()
        };
        let current = self
            .selected
            .and_then(|i| self.entries.get(i))
            .map(|e| e.id);
        let detail = if current == selected {
            Task::none()
        } else {
            self.detail_task()
        };
        Task::batch([thumbs, scroll, detail])
    }

    fn load_tabs(&mut self) -> Task<Msg> {
        if !self.manager || self.tabs_loading {
            return Task::none();
        }
        self.tabs_loading = true;
        let socket = self.socket.clone();
        Task::perform(
            clipd::off_thread(move || {
                clipd::ask_text(&socket, "histories")
                    .map_err(|f| f.text())
                    .and_then(|a| clipd::parse_histories(&a))
            }),
            |r| Msg::Tabs(r.unwrap_or_else(|| Err("служба истории не ответила".to_owned()))),
        )
    }

    fn load_targets(&mut self) -> Task<Msg> {
        if self.targets_loading {
            return Task::none();
        }
        self.targets_loading = true;
        let socket = self.socket.clone();
        Task::perform(
            clipd::off_thread(move || {
                let answer = clipd::ask_text(&socket, "instances").map_err(|e| e.text())?;
                if answer.starts_with("error\t") {
                    return Err(answer);
                }
                let mut targets = vec![ClipboardTarget::Host];
                for line in answer.lines() {
                    let (id, _) = line.split_once('\t').ok_or("неверный список контейнеров")?;
                    if id.is_empty() || id.len() > 512 || id.chars().any(char::is_control) {
                        return Err("неверное имя контейнера".to_owned());
                    }
                    targets.push(ClipboardTarget::Instance(id.to_owned()));
                }
                Ok(targets)
            }),
            |r| Msg::Targets(r.unwrap_or_else(|| Err("служба не ответила".into()))),
        )
    }

    fn copy_request_to(&self, id: u64, target: &ClipboardTarget) -> String {
        match target {
            ClipboardTarget::Host => clipd::copy_request(&self.active_history(), id),
            ClipboardTarget::Instance(instance) => format!(
                "copy-to\t{}\t{id}\t{}",
                clipd::encode(&self.active_history()),
                instance
            ),
        }
    }

    fn copy_request(&self, id: u64) -> String {
        self.copy_request_to(id, &self.target)
    }

    fn target_is_available(&self, target: &ClipboardTarget) -> bool {
        self.available_targets.contains(target)
    }

    /// Ask the daemon `request` expecting `ok[⇥value]`.
    fn ok(
        &self,
        request: String,
        then: impl Fn(Result<String, String>) -> Msg + Send + 'static,
    ) -> Task<Msg> {
        let socket = self.socket.clone();
        Task::perform(
            clipd::off_thread(move || {
                clipd::ask_text(&socket, &request)
                    .map_err(|f| f.text())
                    .and_then(|a| clipd::parse_ok(&a))
            }),
            move |r| then(r.unwrap_or_else(|| Err("служба истории не ответила".to_owned()))),
        )
    }

    /// The thumbnails of a page's PNGs not made yet, each fetched and made
    /// off the window's thread.
    fn thumbs_of(&mut self, page: &[Entry]) -> Task<Msg> {
        let height = (self.image_lines as f32 * LINE) as u32;
        let mut tasks = Vec::new();
        for e in page {
            let Some((mime, size)) = e.image() else {
                continue;
            };
            if mime != "image/png" || *size > MAX_THUMB_SOURCE || self.thumbs.contains_key(&e.id) {
                continue;
            }
            // Asked once: an answer that is an error is kept as one.
            self.thumbs.insert(e.id, Err(String::new()));
            let (id, socket, history) = (e.id, self.socket.clone(), self.active_history());
            let request = clipd::get_request(&history, id, mime);
            tasks.push(Task::perform(
                clipd::off_thread(move || {
                    clipd::ask(&socket, &request)
                        .map_err(|f| f.text())
                        .and_then(|bytes| clipd::read_got(bytes.as_slice()))
                        .and_then(|png| crate::thumb::of_png(&png, height))
                }),
                move |r| {
                    Msg::Thumb(
                        history.clone(),
                        id,
                        r.unwrap_or_else(|| Err("нет ответа".to_owned())),
                    )
                },
            ));
        }
        Task::batch(tasks)
    }

    fn entry(&self, id: u64) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Keep the chosen entry in the feed's view: from the guessed heights
    /// of the entries under it (the feed is anchored at its bottom).
    fn reveal(&self) -> Task<Msg> {
        let Some(i) = self.selected else {
            return Task::none();
        };
        let (offset, height) = self.view;
        if height <= 0.0 {
            return Task::none();
        }
        let h = |j: usize| {
            let e = &self.entries[j];
            guessed_height(
                e,
                self.whole.get(&e.id),
                self.selected == Some(j),
                (self.lines, self.image_lines),
            ) + 10.0
        };
        let below: f32 = (i + 1..self.entries.len()).map(h).sum();
        let top = below + h(i);
        let to = if below < offset {
            below - 8.0
        } else if top > offset + height {
            top - height + 8.0
        } else {
            return Task::none();
        };
        operation::scroll_to(
            FEED,
            AbsoluteOffset {
                x: None,
                y: Some(to.max(0.0)),
            },
        )
    }

    fn can_copy_for_paste(&self, id: u64) -> bool {
        self.can_copy_to(id, &self.target)
    }

    fn can_copy_to(&self, id: u64, target: &ClipboardTarget) -> bool {
        !self.secrets
            && !self.type_busy
            && self.target_is_available(target)
            && self.entry(id).is_some()
    }

    fn paste(&self, id: u64) {
        if self.can_paste && self.entry(id).is_some() {
            print!("{}", paste_line(&self.active_history(), id));
            std::process::exit(0);
        }
    }

    fn load_whole(&mut self, id: u64) -> Task<Msg> {
        if self.secrets || self.whole.contains_key(&id) || !self.whole_loading.insert(id) {
            return Task::none();
        }
        let Some(mime) = self
            .entry(id)
            .and_then(|e| e.text_type())
            .map(str::to_owned)
        else {
            self.whole_loading.remove(&id);
            return Task::none();
        };
        let history = self.active_history();
        let request = clipd::get_request(&history, id, &mime);
        let socket = self.socket.clone();
        Task::perform(
            clipd::off_thread(move || {
                clipd::ask(&socket, &request)
                    .map_err(|f| f.text())
                    .and_then(|bytes| clipd::read_got(bytes.as_slice()))
                    .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            }),
            move |r| {
                Msg::Got(
                    history.clone(),
                    id,
                    r.unwrap_or_else(|| Err("служба истории не ответила".to_owned())),
                )
            },
        )
    }

    fn fit_width(&self) -> u32 {
        const LEVELS: [u32; 6] = [640, 1280, 2560, 3840, 7680, 16_384];
        let needed = self.window_width.ceil().max(1.0) as u32;
        LEVELS
            .into_iter()
            .find(|width| *width >= needed)
            .unwrap_or(16_384)
    }

    fn ensure_fit(&mut self) -> Task<Msg> {
        let Some(preview) = self.image_preview.as_ref().filter(|p| !p.native) else {
            return Task::none();
        };
        let (history, id) = (preview.history.clone(), preview.id);
        let Some(Ok(cached)) = self.full_images.get(&(history.clone(), id)) else {
            return Task::none();
        };
        let width = self.fit_width().min(cached.source.width());
        if cached.fit_width >= width {
            return Task::none();
        }
        let source = cached.source.clone();
        Task::perform(
            clipd::off_thread(move || source.scaled(width, width)),
            move |result| {
                Msg::FitLoaded(
                    history.clone(),
                    id,
                    width,
                    result.unwrap_or_else(|| Err("обработка изображения прервана".into())),
                )
            },
        )
    }

    fn preview_native(&mut self, native: bool) -> Task<Msg> {
        let Some(preview) = &mut self.image_preview else {
            return Task::none();
        };
        preview.native = native;
        let (history, id) = (preview.history.clone(), preview.id);
        let Some(Ok(cached)) = self.full_images.get(&(history.clone(), id)) else {
            return Task::none();
        };
        if !native {
            let image = (
                cached.fit.clone(),
                cached.source.width(),
                cached.source.height(),
            );
            if let Some(preview) = &mut self.image_preview {
                preview.image = Some(Ok(image));
            }
            return self.ensure_fit();
        }
        if let Some(full) = &cached.full {
            let image = Some(Ok((
                full.clone(),
                cached.source.width(),
                cached.source.height(),
            )));
            if let Some(preview) = &mut self.image_preview {
                preview.image = image;
            }
            return Task::none();
        }
        let source = cached.source.clone();
        Task::perform(clipd::off_thread(move || source.full()), move |result| {
            Msg::NativeLoaded(
                history.clone(),
                id,
                result.unwrap_or_else(|| Err("обработка изображения прервана".into())),
            )
        })
    }

    fn preview_image(&mut self, id: u64, expanded: bool) -> Task<Msg> {
        if self.secrets || self.type_busy {
            return Task::none();
        }
        let Some((mime, size)) = self.entry(id).and_then(Entry::image).cloned() else {
            return Task::none();
        };
        self.selected = self.entries.iter().position(|e| e.id == id);
        let history = self.active_history();
        self.full_images
            .retain(|(at, cached), _| *at == history && *cached == id);
        let cached = self.full_images.get(&(history.clone(), id)).map(|cached| {
            cached
                .as_ref()
                .map(|cached| {
                    (
                        cached.fit.clone(),
                        cached.source.width(),
                        cached.source.height(),
                    )
                })
                .map_err(Clone::clone)
        });
        let error = if mime != "image/png" {
            Some(ui(UiKey::PreviewUnsupported).to_owned())
        } else if size > MAX_THUMB_SOURCE {
            Some(ui(UiKey::PreviewTooLarge).to_owned())
        } else {
            None
        };
        self.image_preview = Some(ImagePreview {
            id,
            history: history.clone(),
            image: error.clone().map(Err).or(cached),
            native: false,
            expanded,
        });
        if error.is_some() {
            return Task::none();
        }
        if self.image_preview.as_ref().unwrap().image.is_some() {
            return self.ensure_fit();
        }
        let fit_width = self.fit_width();
        let socket = self.socket.clone();
        let request = clipd::get_request(&history, id, &mime);
        Task::perform(
            clipd::off_thread(move || {
                clipd::ask(&socket, &request)
                    .map_err(|e| e.text())
                    .and_then(|bytes| clipd::read_got(bytes.as_slice()))
                    .and_then(|png| {
                        let source = Arc::new(crate::thumb::decode(&png)?);
                        let width = fit_width.min(source.width());
                        let fit = source.scaled(width, width)?;
                        Ok((source, fit, width))
                    })
            }),
            move |r| {
                Msg::PreviewLoaded(
                    history.clone(),
                    id,
                    r.unwrap_or_else(|| Err(ui(UiKey::HistoryUnavailable).into())),
                )
            },
        )
    }

    fn detail_task(&mut self) -> Task<Msg> {
        let Some(e) = self.selected.and_then(|i| self.entries.get(i)) else {
            self.image_preview = None;
            return Task::none();
        };
        if e.image().is_some() {
            self.preview_image(e.id, false)
        } else {
            self.image_preview = None;
            if e.text_type().is_some() {
                self.load_whole(e.id)
            } else {
                Task::none()
            }
        }
    }

    pub fn update(&mut self, msg: Msg) -> Task<Msg> {
        match msg {
            Msg::Appearance => {}
            Msg::Preview(id) => return self.preview_image(id, true),
            Msg::PreviewLoaded(history, id, result) => {
                let image = result.map(|(source, fit, fit_width)| {
                    let handle =
                        iced::widget::image::Handle::from_rgba(fit.width, fit.height, fit.rgba);
                    CachedImage {
                        source,
                        fit: handle,
                        fit_width,
                        full: None,
                    }
                });
                let current = image
                    .as_ref()
                    .map(|cached| {
                        (
                            cached.fit.clone(),
                            cached.source.width(),
                            cached.source.height(),
                        )
                    })
                    .map_err(Clone::clone);
                self.full_images.insert((history.clone(), id), image);
                if let Some(preview) = self
                    .image_preview
                    .as_mut()
                    .filter(|p| p.id == id && p.history == history)
                {
                    if preview.native {
                        return self.preview_native(true);
                    }
                    preview.image = Some(current);
                }
            }
            Msg::FitLoaded(history, id, width, result) => {
                let mut current = None;
                match result {
                    Ok(fit) => {
                        let handle =
                            iced::widget::image::Handle::from_rgba(fit.width, fit.height, fit.rgba);
                        if let Some(Ok(cached)) = self.full_images.get_mut(&(history.clone(), id)) {
                            if cached.fit_width <= width {
                                cached.fit = handle;
                                cached.fit_width = width;
                                current = Some((
                                    cached.fit.clone(),
                                    cached.source.width(),
                                    cached.source.height(),
                                ));
                            }
                        }
                    }
                    Err(why) => {
                        if let Some(preview) = self
                            .image_preview
                            .as_mut()
                            .filter(|p| p.id == id && p.history == history && !p.native)
                        {
                            preview.image = Some(Err(why));
                        }
                    }
                }
                if let Some(preview) = self
                    .image_preview
                    .as_mut()
                    .filter(|p| p.id == id && p.history == history && !p.native)
                {
                    if let Some(image) = current {
                        preview.image = Some(Ok(image));
                    }
                }
            }
            Msg::NativeLoaded(history, id, result) => {
                let mut current = None;
                match result {
                    Ok(full) => {
                        let handle = iced::widget::image::Handle::from_rgba(
                            full.width,
                            full.height,
                            full.rgba,
                        );
                        if let Some(Ok(cached)) = self.full_images.get_mut(&(history.clone(), id)) {
                            cached.full = Some(handle);
                            current = cached
                                .full
                                .clone()
                                .map(|full| (full, cached.source.width(), cached.source.height()));
                        }
                    }
                    Err(why) => {
                        if let Some(preview) = self
                            .image_preview
                            .as_mut()
                            .filter(|p| p.id == id && p.history == history && p.native)
                        {
                            preview.image = Some(Err(why));
                        }
                    }
                }
                if let Some(preview) = self
                    .image_preview
                    .as_mut()
                    .filter(|p| p.id == id && p.history == history && p.native)
                {
                    if let Some(image) = current {
                        preview.image = Some(Ok(image));
                    }
                }
            }
            Msg::PreviewExpand => {
                if let Some(preview) = &mut self.image_preview {
                    preview.expanded = true;
                }
                return self.ensure_fit();
            }
            Msg::PreviewNative(native) => return self.preview_native(native),
            Msg::PreviewMaximize => {
                return iced::window::latest().then(|window| {
                    window.map_or_else(Task::none, |id| iced::window::maximize(id, true))
                })
            }
            Msg::PreviewClose => {
                self.image_preview = None;
                return self.detail_task();
            }
            Msg::Resized(width) => {
                self.window_width = width;
                return self.ensure_fit();
            }
            Msg::LivePoll => {
                return Task::batch([self.poll_live(), self.load_tabs(), self.load_targets()]);
            }
            Msg::LiveLoaded { gen, result } => return self.live_loaded(gen, result),
            Msg::Opened(window) => {
                let focus = iced::window::gain_focus(window);
                return if self.type_enabled {
                    focus
                } else {
                    focus.chain(operation::focus(SEARCH))
                };
            }
            Msg::Loaded { gen, older, result } => {
                if gen != self.gen {
                    return Task::none();
                }
                self.loading = false;
                match result {
                    Ok(mut page) => {
                        self.older = page.len() >= PAGE;
                        page.reverse();
                        let thumbs = self.thumbs_of(&page);
                        if older {
                            let n = page.len();
                            page.append(&mut self.entries);
                            self.entries = page;
                            self.selected = self.selected.map(|i| i + n);
                            return thumbs;
                        } else {
                            self.entries = page;
                            self.selected = self.entries.len().checked_sub(1);
                            self.whole.clear();
                            return Task::batch([
                                thumbs,
                                operation::scroll_to(
                                    FEED,
                                    AbsoluteOffset {
                                        x: None,
                                        y: Some(0.0),
                                    },
                                ),
                                self.detail_task(),
                            ]);
                        }
                    }
                    Err(why) => self.error = Some(why),
                }
            }
            Msg::Scrolled(v) => {
                self.view = (v.absolute_offset().y, v.bounds().height);
                // Near the top: the page before.
                if v.absolute_offset_reversed().y < 120.0 && self.older && !self.loading {
                    return self.load(true);
                }
            }
            Msg::Words(w) => {
                if self.secrets {
                    return Task::none();
                }
                self.words = w;
                self.gen += 1;
                self.live = None;
                self.typed += 1;
                return later(DEBOUNCE_MS, Msg::Rested(self.typed));
            }
            Msg::Rested(typed) => {
                if typed == self.typed {
                    return self.search();
                }
            }
            Msg::Select(i) => {
                if i < self.entries.len() && self.selected != Some(i) {
                    self.selected = Some(i);
                    self.moving = None;
                    self.deleting = None;
                    self.secreting = None;
                    self.copying_secret = None;
                    self.copying = None;
                    self.clear_secret_editor();
                    self.transferring_secret = None;
                    return self.detail_task();
                }
            }
            Msg::Paste(id) => {
                if self.type_enabled {
                    return self.update(Msg::TypeSend(id));
                }
                self.paste(id);
            }
            Msg::CopyForPaste(id) => {
                // Password export keeps its separate confirmation path.
                if self.can_copy_for_paste(id) {
                    let target = self.target.clone();
                    return self.ok(self.copy_request(id), move |r| {
                        Msg::CopiedForPaste(target.clone(), r)
                    });
                }
            }
            Msg::CopyToAsk(id) => {
                if !self.secrets && self.entry(id).is_some() && !self.type_busy {
                    self.copying = Some((id, self.target.clone()));
                    self.moving = None;
                    self.deleting = None;
                    self.copying_secret = None;
                }
            }
            Msg::LocalTarget(target) => {
                if let Some((_, selected)) = &mut self.copying {
                    *selected = target.clone();
                }
                if let Some((_, selected)) = &mut self.copying_secret {
                    *selected = target;
                }
            }
            Msg::CopyTo(id) => {
                let Some((entry, target)) = self.copying.clone() else {
                    return Task::none();
                };
                if entry == id && self.can_copy_to(id, &target) {
                    return self.ok(self.copy_request_to(id, &target), move |r| {
                        Msg::CopiedForPaste(target.clone(), r)
                    });
                }
            }
            Msg::CopiedForPaste(target, result) => {
                self.copying = None;
                match result {
                    Ok(_) => self.notice = Some(format!("Запись скопирована: {target}. Для вставки нажмите Ctrl+V (в терминале — Ctrl+Shift+V).")),
                    Err(why) => self.error = Some(why),
                }
            }
            Msg::Got(history, id, result) if history == self.active_history() => {
                self.whole_loading.remove(&id);
                match result {
                    Ok(t) => {
                        self.whole.insert(id, t);
                    }
                    Err(why) => self.error = Some(why),
                }
            }
            Msg::Got(_, _, _) => {}
            Msg::Thumb(history, id, made) if history == self.active_history() => {
                self.thumbs.insert(
                    id,
                    made.map(|t| iced::widget::image::Handle::from_rgba(t.width, t.height, t.rgba)),
                );
            }
            Msg::Thumb(_, _, _) => {}
            Msg::MoveAsk(id) => {
                if self.entry(id).is_none() {
                    return Task::none();
                }
                self.clear_secret_editor();
                self.transferring_secret = None;
                self.copying_secret = None;
                self.copying = None;
                self.deleting = None;
                self.moving = Some((id, None));
                let socket = self.socket.clone();
                let history = self.active_history();
                return Task::perform(
                    clipd::off_thread(move || {
                        clipd::ask_text(&socket, "histories")
                            .map_err(|f| f.text())
                            .and_then(|a| clipd::parse_histories(&a))
                    }),
                    move |r| {
                        Msg::Histories(
                            history.clone(),
                            r.unwrap_or_else(|| Err("служба истории не ответила".to_owned())),
                        )
                    },
                );
            }
            Msg::Histories(history, result) if history == self.active_history() => match result {
                Ok(mut names) => {
                    if !self.favorites {
                        names.retain(|n| *n != self.history);
                    }
                    if let Some((_, list)) = &mut self.moving {
                        *list = Some(names);
                    }
                }
                Err(why) => {
                    self.moving = None;
                    self.error = Some(why);
                }
            },
            Msg::Histories(_, _) => {}
            Msg::Tabs(result) => {
                self.tabs_loading = false;
                match result {
                    Ok(names) => {
                        self.tabs_error = None;
                        let mut names: Vec<String> = names
                            .into_iter()
                            .map(|name| crate::clipboard_scope::canonical_history(&name).to_owned())
                            .collect();
                        self.history =
                            crate::clipboard_scope::canonical_history(&self.history).to_owned();
                        names.push("host".to_owned());
                        names.push(self.history.clone());
                        names.sort();
                        names.dedup();
                        self.tabs = names;
                    }
                    Err(why) => {
                        if self.tabs_error.as_deref() != Some(why.as_str()) {
                            self.error = Some(why.clone());
                        }
                        self.tabs_error = Some(why);
                    }
                }
            }
            Msg::Switch(history) => {
                if self.type_busy {
                    return Task::none();
                }
                if !self.manager || !self.tabs.contains(&history) || self.history == history {
                    return Task::none();
                }
                self.history = history;
                self.favorites = false;
                self.secrets = false;
                return self.switch_shelf();
            }
            Msg::Shelf(favorites) => {
                if !self.secrets && self.favorites == favorites {
                    return Task::none();
                }
                self.favorites = favorites;
                self.secrets = false;
                return self.switch_shelf();
            }
            Msg::Secrets => {
                if self.secrets {
                    return Task::none();
                }
                self.secrets = true;
                self.favorites = false;
                self.words.clear();
                self.re = None;
                self.builder_open = false;
                return self.switch_shelf();
            }
            Msg::Targets(result) => {
                self.targets_loading = false;
                match result {
                    Ok(mut targets) => {
                        self.targets_error = None;
                        self.available_targets = targets.clone();
                        self.target_available = self.target_is_available(&self.target);
                        if !self.target_available {
                            targets.push(self.target.clone());
                            if self
                                .copying_secret
                                .as_ref()
                                .is_some_and(|(_, target)| *target == self.target)
                            {
                                self.copying_secret = None;
                            }
                        }
                        for target in [&self.copying, &self.copying_secret]
                            .into_iter()
                            .filter_map(|draft| draft.as_ref().map(|(_, target)| target))
                        {
                            if !targets.contains(target) {
                                targets.push(target.clone());
                            }
                        }
                        self.targets = targets;
                    }
                    Err(why) => {
                        if self.targets_error.as_deref() != Some(why.as_str()) {
                            self.error = Some(why.clone());
                        }
                        self.targets_error = Some(why);
                    }
                }
            }
            Msg::Target(target) => {
                if self.targets.contains(&target) && self.target_is_available(&target) {
                    self.copying_secret = None;
                    self.copying = None;
                    if !self.target_available {
                        self.targets.retain(|candidate| candidate != &self.target);
                    }
                    self.target_available = true;
                    self.target = target;
                }
            }
            Msg::Favorite(id) => {
                if self.favorites || self.secrets || self.entry(id).is_none() {
                    return Task::none();
                }
                let history = self.history.clone();
                return self.ok(clipd::favorite_request(&history, id), move |r| {
                    Msg::Favorited(history.clone(), r)
                });
            }
            Msg::Favorited(history, result) if history == self.history => match result {
                Ok(_) => self.notice = Some("Добавлено в избранное этого буфера".to_owned()),
                Err(why) => self.error = Some(why),
            },
            Msg::Favorited(_, _) => {}
            Msg::SecretAsk(id) => {
                if !self.favorites && !self.secrets && self.entry(id).is_some() {
                    self.secreting = Some(id);
                    self.secret_label.clear();
                }
            }
            Msg::SecretLabel(label) => self.secret_label = label,
            Msg::SecretYes(id) => {
                if self.secreting != Some(id) || self.favorites || self.secrets {
                    return Task::none();
                }
                let history = self.history.clone();
                return self.ok(
                    clipd::secret_request(&history, id, &self.secret_label),
                    move |r| Msg::Secreted(history.clone(), id, r),
                );
            }
            Msg::Secreted(history, id, result)
                if history == self.history && !self.favorites && !self.secrets =>
            {
                self.secreting = None;
                match result {
                    Ok(_) => {
                        self.entries.retain(|e| e.id != id);
                        self.whole.remove(&id);
                        self.whole_loading.remove(&id);
                        self.thumbs.remove(&id);
                        self.full_images.remove(&(history.clone(), id));
                        self.selected = None;
                        self.notice = Some("Перемещено в пароли этого буфера".to_owned());
                        return self.search();
                    }
                    Err(why) => self.error = Some(why),
                }
            }
            Msg::Secreted(_, _, _) => {}
            Msg::CopySecretAsk(id) => {
                if self.secrets && self.entry(id).is_some() && !self.type_busy {
                    self.copying_secret = Some((id, self.target.clone()));
                    self.copying = None;
                }
            }
            Msg::CopySecretYes(id) => {
                let Some((entry, target)) = self.copying_secret.clone() else {
                    return Task::none();
                };
                if entry != id
                    || !self.secrets
                    || !self.target_is_available(&target)
                    || self.type_busy
                    || self.entry(id).is_none()
                {
                    return Task::none();
                }
                return self.ok(self.copy_request_to(id, &target), move |r| {
                    Msg::CopiedSecret(target.clone(), r)
                });
            }
            Msg::CopiedSecret(target, result) => {
                self.copying_secret = None;
                self.copying = None;
                match result {
                    Ok(_) => {
                        self.notice = Some(format!(
                            "Пароль скопирован: {target}. Автоматической вставки нет."
                        ))
                    }
                    Err(why) => self.error = Some(why),
                }
            }
            Msg::EditSecret(id) => {
                if self.secrets {
                    if let Some(entry) = self.entry(id) {
                        self.edited_label = entry
                            .preview
                            .strip_prefix("Пароль: ")
                            .unwrap_or("")
                            .to_owned();
                        self.edited_password.clear();
                        self.editing_secret = Some(id);
                        self.moving = None;
                        self.transferring_secret = None;
                        self.copying_secret = None;
                        self.copying = None;
                        self.deleting = None;
                    }
                }
            }
            Msg::EditedLabel(value) => self.edited_label = value,
            Msg::EditedPassword(value) => self.edited_password = value,
            Msg::SaveSecret(id) => {
                if !self.secrets || self.editing_secret != Some(id) {
                    return Task::none();
                }
                let history = self.history.clone();
                let request = clipd::edit_secret_request(
                    &history,
                    id,
                    &self.edited_label,
                    &self.edited_password,
                );
                self.clear_secret_editor();
                return self.ok(request, move |r| Msg::SavedSecret(history.clone(), r));
            }
            Msg::SavedSecret(history, result) if self.secrets && history == self.history => {
                match result {
                    Ok(_) => {
                        self.notice = Some("Пароль сохранён".into());
                        return self.search();
                    }
                    Err(why) => self.error = Some(why),
                }
            }
            Msg::SavedSecret(_, _) => {}
            Msg::TransferSecret(id, to) => {
                if self.secrets
                    && to != self.history
                    && self.entry(id).is_some()
                    && self.moving.as_ref().is_some_and(|(entry, names)| {
                        *entry == id && names.as_ref().is_some_and(|n| n.contains(&to))
                    })
                {
                    self.transferring_secret = Some((id, to));
                    self.moving = None;
                }
            }
            Msg::TransferSecretYes(id) => {
                if !self.secrets {
                    return Task::none();
                }
                let Some((pending, to)) = self.transferring_secret.take() else {
                    return Task::none();
                };
                if pending != id {
                    return Task::none();
                }
                let history = self.history.clone();
                let request = clipd::move_secret_request(&history, id, &to);
                return self.ok(request, move |r| {
                    Msg::TransferredSecret(history.clone(), r.map(|_| to.clone()))
                });
            }
            Msg::TransferredSecret(history, result) if self.secrets && history == self.history => {
                match result {
                    Ok(to) => {
                        self.notice = Some(format!("Пароль перенесён в буфер «{to}»"));
                        return self.search();
                    }
                    Err(why) => self.error = Some(why),
                }
            }
            Msg::TransferredSecret(_, _) => {}
            Msg::Typing(enabled) => {
                if !self.type_busy {
                    self.type_enabled = enabled;
                }
            }
            Msg::TypeMode(mode) => {
                self.type_mode = mode;
                self.type_save();
            }
            Msg::TypeLines(lines) => {
                self.type_lines = lines;
                self.type_save();
            }
            Msg::TypeDelay(which, text) => {
                if text.len() <= 5 && text.chars().all(|c| c.is_ascii_digit()) {
                    match which {
                        "start" => self.type_start = text,
                        "between" => self.type_between = text,
                        "hold" => self.type_hold = text,
                        _ => {}
                    }
                    self.type_save();
                }
            }
            Msg::TypePick => {
                if self.type_busy {
                    return Task::none();
                }
                self.type_busy = true;
                self.error = None;
                self.type_target = None;
                return iced::window::latest().map(Msg::TypePickWindow);
            }
            Msg::TypePickWindow(window) => {
                let Some(window) = window else {
                    self.type_busy = false;
                    return Task::none();
                };
                let launch = self.launch;
                let work = Task::perform(
                    clipd::off_thread(move || {
                        std::thread::sleep(std::time::Duration::from_millis(150));
                        clip_type::choose(launch)
                    }),
                    move |r| {
                        Msg::TypeChosen(
                            window,
                            r.unwrap_or_else(|| Err("Выбор окна прерван".into())),
                        )
                    },
                );
                // Wayland cannot hide an existing winit surface. Close just
                // this window; the daemon keeps its state and opens it again
                // once the point has been selected.
                return iced::window::close(window).chain(work);
            }
            Msg::TypeChosen(_window, result) => {
                self.type_busy = false;
                match result {
                    Ok(target) => {
                        self.type_target = Some(target);
                        self.notice =
                            Some("Точка выбрана. Выберите запись и нажмите «Напечатать»".into());
                    }
                    Err(why) => self.error = Some(why),
                }
                let (_, open) = iced::window::open(clip_window_settings());
                return open.map(Msg::Opened);
            }
            Msg::TypeSend(id) => {
                if self.type_busy {
                    return Task::none();
                }
                if self.type_target.is_none() {
                    self.error = Some("Сначала выберите точку ввода в окне".into());
                    return Task::none();
                }
                if let Err(why) = self.type_timing() {
                    self.error = Some(why);
                    return Task::none();
                }
                if self.entry(id).and_then(Entry::text_type).is_none() {
                    self.error = Some("Посимвольный ввод доступен только для текста".into());
                    return Task::none();
                }
                self.type_busy = true;
                self.error = None;
                self.notice = None;
                return iced::window::latest().map(move |window| Msg::TypeSendWindow(window, id));
            }
            Msg::TypeSendWindow(window, id) => {
                let Some(window) = window else {
                    self.type_busy = false;
                    return Task::none();
                };
                let Some(target) = self.type_target else {
                    self.type_busy = false;
                    return Task::none();
                };
                let Some(mime) = self.entry(id).and_then(Entry::text_type).map(str::to_owned)
                else {
                    self.type_busy = false;
                    return Task::none();
                };
                let Ok(timing) = self.type_timing() else {
                    self.type_busy = false;
                    return Task::none();
                };
                let (socket, history, mode, lines) = (
                    self.socket.clone(),
                    self.active_history(),
                    self.type_mode,
                    self.type_lines,
                );
                self.type_active = Some(target);
                let work = Task::perform(
                    clipd::off_thread(move || {
                        std::thread::sleep(std::time::Duration::from_millis(150));
                        clip_type::type_entry(
                            target,
                            clip_type::Entry {
                                socket: &socket,
                                history: &history,
                                id,
                                mime: &mime,
                            },
                            timing,
                            mode,
                            lines,
                        )
                    }),
                    move |r| Msg::Typed(window, r.unwrap_or_else(|| Err("Ввод прерван".into()))),
                );
                return iced::window::close(window).chain(work);
            }
            Msg::Typed(_window, result) => {
                self.type_busy = false;
                self.type_active = None;
                match result {
                    Ok(()) => self.notice = Some("Запись напечатана в выбранном окне".into()),
                    Err(why) => {
                        self.error = Some(why);
                        self.type_target = None;
                    }
                }
                let (_, open) = iced::window::open(clip_window_settings());
                return open.map(Msg::Opened);
            }
            Msg::TypeCancel => {
                if let Some(target) = self.type_active {
                    return Task::perform(
                        clipd::off_thread(move || clip_type::cancel(target)),
                        |r| {
                            Msg::TypeCanceled(
                                r.unwrap_or_else(|| Err("Не удалось остановить ввод".into())),
                            )
                        },
                    );
                }
            }
            Msg::TypeCanceled(result) => {
                if let Err(why) = result {
                    self.error = Some(why);
                }
            }
            Msg::MoveTo(id, to) => {
                if self.secrets {
                    return Task::none();
                }
                let request = clipd::move_request(&self.active_history(), id, &to);
                return self.ok(request, move |r| {
                    Msg::Moved(r.map(|_| format!("Скопировано в историю «{to}»")))
                });
            }
            Msg::Moved(result) => {
                self.moving = None;
                match result {
                    Ok(said) => self.notice = Some(said),
                    Err(why) => self.error = Some(why),
                }
            }
            Msg::DeleteAsk(id) => {
                self.clear_secret_editor();
                self.transferring_secret = None;
                self.moving = None;
                self.copying = None;
                self.deleting = Some(id);
            }
            Msg::DeleteYes(id) => {
                let history = self.active_history();
                return self.ok(clipd::delete_request(&history, id), move |r| {
                    Msg::Deleted(history.clone(), id, r)
                });
            }
            Msg::Deleted(history, id, result) if history == self.active_history() => {
                self.deleting = None;
                match result {
                    Ok(_) => {
                        self.full_images.remove(&(history.clone(), id));
                        if let Some(i) = self.entries.iter().position(|e| e.id == id) {
                            self.entries.remove(i);
                            self.whole.remove(&id);
                            self.whole_loading.remove(&id);
                            self.selected = match self.selected {
                                Some(s) if s > i => Some(s - 1),
                                Some(s) if s == i => (!self.entries.is_empty())
                                    .then(|| i.min(self.entries.len() - 1)),
                                s => s,
                            };
                            return self.detail_task();
                        }
                    }
                    Err(why) => self.error = Some(why),
                }
            }
            Msg::Deleted(_, _, _) => {}
            Msg::Cancel => {
                self.clear_secret_editor();
                self.transferring_secret = None;
                self.moving = None;
                self.deleting = None;
                self.secreting = None;
                self.copying_secret = None;
                self.copying = None;
            }
            Msg::Close => std::process::exit(1),
            Msg::Key(press) => return self.key(press),
            Msg::Dismiss => {
                self.error = None;
                self.notice = None;
            }
            Msg::DatesOpen => {
                self.dates_open = !self.dates_open;
                self.builder_open = false;
            }
            Msg::DateOf(of) => {
                self.dates.of = of;
                return self.dates_changed();
            }
            Msg::When(when) => {
                self.dates.when = when;
                return self.dates_changed();
            }
            Msg::Day(t) => {
                self.dates.day = t;
                return self.dates_changed();
            }
            Msg::At(t) => {
                self.dates.at = t;
                return self.dates_changed();
            }
            Msg::Hours(t) => {
                self.dates.hours = t;
                return self.dates_changed();
            }
            Msg::Kind(i, on) => {
                if let Some(k) = self.kinds.get_mut(i) {
                    *k = on;
                }
                return self.search();
            }
            Msg::ClearAll => {
                self.words.clear();
                self.re = None;
                self.kinds = [false; 3];
                self.dates.when = When::All;
                return self.search();
            }
            Msg::BuilderOpen => {
                self.builder_open = !self.builder_open;
                self.dates_open = false;
            }
            Msg::Add(tag) => self.builder.add(tag),
            Msg::Remove(i) => self.builder.remove(i),
            Msg::Shift(i, by) => self.builder.shift(i, by),
            Msg::Chars(i, t) => {
                if let Some(b) = self.builder.blocks.get_mut(i) {
                    match &mut b.kind {
                        Kind::Text(s) | Kind::OneOf(s) | Kind::NoneOf(s) => *s = t,
                        _ => {}
                    }
                }
            }
            Msg::From(i, t) | Msg::To(i, t) if !t.chars().all(|c| c.is_ascii_digit()) => {
                let _ = (i, t);
            }
            Msg::From(i, t) => {
                if let Some(Kind::Number(from, _, _)) =
                    self.builder.blocks.get_mut(i).map(|b| &mut b.kind)
                {
                    *from = t;
                }
            }
            Msg::To(i, t) => {
                if let Some(Kind::Number(_, to, _)) =
                    self.builder.blocks.get_mut(i).map(|b| &mut b.kind)
                {
                    *to = t;
                }
            }
            Msg::Alone(i, on) => {
                if let Some(Kind::Number(_, _, alone)) =
                    self.builder.blocks.get_mut(i).map(|b| &mut b.kind)
                {
                    *alone = on;
                }
            }
            Msg::Letters(i, a) => {
                if let Some(b) = self.builder.blocks.get_mut(i) {
                    b.kind = Kind::Letter(a);
                }
            }
            Msg::Times(i, t) => {
                if let Some(b) = self.builder.blocks.get_mut(i) {
                    b.times = t;
                }
            }
            Msg::N(i, t) | Msg::M(i, t) if !t.chars().all(|c| c.is_ascii_digit()) => {
                let _ = (i, t);
            }
            Msg::N(i, t) => {
                if let Some(b) = self.builder.blocks.get_mut(i) {
                    b.n = t;
                }
            }
            Msg::M(i, t) => {
                if let Some(b) = self.builder.blocks.get_mut(i) {
                    b.m = t;
                }
            }
            Msg::Lazy(i, on) => {
                if let Some(b) = self.builder.blocks.get_mut(i) {
                    b.lazy = on;
                }
            }
            Msg::Flag(i, on) => match i {
                0 => self.builder.any_case = on,
                1 => self.builder.every_line = on,
                _ => self.builder.dot_all = on,
            },
            Msg::Sample(action) => {
                self.sample.perform(action);
                self.builder.sample = self.sample.text();
            }
            Msg::Apply => {
                let p = self.builder.pattern();
                if !p.is_empty() && !matches!(self.builder.try_it(), Tried::Broken(_)) {
                    self.re = Some(p);
                    self.builder_open = false;
                    return self.search();
                }
            }
            Msg::Unapply => {
                self.re = None;
                return self.search();
            }
        }
        Task::none()
    }

    fn dates_changed(&mut self) -> Task<Msg> {
        // A date half typed searches nothing yet, and says nothing yet.
        if self.dates.bounds(now_ms()).is_err() {
            return Task::none();
        }
        self.search()
    }

    pub fn key(&mut self, press: Press) -> Task<Msg> {
        if self.image_preview.is_some() {
            if press == Press::Escape {
                self.image_preview = None;
                return self.detail_task();
            }
            return Task::none();
        }
        match press {
            Press::Escape => {
                if self.type_busy {
                    return self.update(Msg::TypeCancel);
                }
                if self.deleting.is_some()
                    || self.moving.is_some()
                    || self.secreting.is_some()
                    || self.copying.is_some()
                    || self.copying_secret.is_some()
                    || self.editing_secret.is_some()
                    || self.transferring_secret.is_some()
                {
                    self.deleting = None;
                    self.moving = None;
                    self.secreting = None;
                    self.copying_secret = None;
                    self.copying = None;
                    self.clear_secret_editor();
                    self.transferring_secret = None;
                } else if self.builder_open {
                    self.builder_open = false;
                } else if self.dates_open {
                    self.dates_open = false;
                } else {
                    std::process::exit(1);
                }
            }
            Press::Search => {
                self.builder_open = false;
                return operation::focus(SEARCH);
            }
            // The builder's own fields take the arrows and Enter.
            _ if self.builder_open => {}
            // Editing fields own Enter and the arrows; never turn them into
            // an implicit paste or a different selected password.
            _ if self.editing_secret.is_some() => {}
            Press::Up | Press::Down => {
                if self.entries.is_empty() {
                    return Task::none();
                }
                let last = self.entries.len() - 1;
                let next = match (self.selected, press) {
                    (None, _) => last,
                    (Some(i), Press::Up) => i.saturating_sub(1),
                    (Some(i), _) => (i + 1).min(last),
                };
                if self.selected != Some(next) {
                    self.moving = None;
                    self.deleting = None;
                    self.secreting = None;
                    self.copying_secret = None;
                    self.copying = None;
                    self.transferring_secret = None;
                }
                self.selected = Some(next);
                let reveal = self.reveal();
                // At the oldest shown: the page before, as a scroll up would.
                let detail = self.detail_task();
                if press == Press::Up && next == 0 && self.older && !self.loading {
                    return Task::batch([reveal, self.load(true), detail]);
                }
                return Task::batch([reveal, detail]);
            }
            Press::Enter => {
                if self.deleting.is_none()
                    && self.moving.is_none()
                    && self.secreting.is_none()
                    && self.copying.is_none()
                    && self.copying_secret.is_none()
                    && self.editing_secret.is_none()
                    && self.transferring_secret.is_none()
                {
                    if let Some(e) = self.selected.and_then(|i| self.entries.get(i)) {
                        return self.update(Msg::Paste(e.id));
                    }
                }
            }
        }
        Task::none()
    }

    pub fn view(&self) -> Element<'_, Msg> {
        if let Some(preview) = &self.image_preview {
            if preview.expanded {
                return self.view_image_preview(preview);
            }
        }
        let mut page = column![].spacing(8).padding(12);
        if self.manager {
            let mut tabs = row![label("Буферы")].spacing(5).align_y(Alignment::Center);
            for name in &self.tabs {
                let label = if name == "host" {
                    "Хост"
                } else {
                    name.as_str()
                };
                tabs = tabs.push(
                    button(text(label).size(13))
                        .style(if *name == self.history {
                            crate::appearance::primary_button
                        } else {
                            button::secondary
                        })
                        .on_press(Msg::Switch(name.clone())),
                );
            }
            page = page.push(tabs.wrap().vertical_spacing(6));
        }
        page = page.push(
            row![
                button(text("История").size(13))
                    .style(if self.favorites || self.secrets {
                        button::secondary
                    } else {
                        crate::appearance::primary_button
                    })
                    .on_press(Msg::Shelf(false)),
                button(text("Избранное").size(13))
                    .style(if self.favorites {
                        crate::appearance::primary_button
                    } else {
                        button::secondary
                    })
                    .on_press(Msg::Shelf(true)),
                button(text("Пароли").size(13))
                    .style(if self.secrets {
                        crate::appearance::primary_button
                    } else {
                        button::secondary
                    })
                    .on_press(Msg::Secrets),
                container(text("")).width(Length::Fill),
                button(text("✕").size(16))
                    .padding([4, 10])
                    .style(button::secondary)
                    .on_press(Msg::Close),
            ]
            .spacing(6)
            .align_y(Alignment::Center),
        );
        page = page.push(
            checkbox(self.type_enabled)
                .label("Ввод по символам")
                .on_toggle(Msg::Typing),
        );
        if self.type_enabled {
            page = page.push(self.view_typing());
        }
        if !self.secrets {
            page = page.push(
                text("Копирование заменяет только выбранный активный буфер. «Хост» — общая история рабочего стола и настоящего дома (main и всех его сетей). Переключение вкладок ничего не копирует.")
                    .size(12)
                    .style(dim)
                    .wrapping(iced::widget::text::Wrapping::WordOrGlyph),
            );
        }
        if self.secrets {
            page = page.push(
                row![
                    text("Копировать в:"),
                    pick_list(self.targets.as_slice(), Some(&self.target), Msg::Target),
                ]
                .spacing(8)
                .align_y(Alignment::Center),
            );
        }
        if !self.target_available {
            page = page.push(text(ui(UiKey::TargetUnavailable)).size(13).style(danger));
        }
        if let Some(why) = &self.error {
            page = page.push(
                row![
                    text(format!("⚠ {why}"))
                        .size(14)
                        .style(danger)
                        .width(Length::Fill),
                    button(text("✕").size(12))
                        .style(button::text)
                        .on_press(Msg::Dismiss),
                ]
                .align_y(Alignment::Center),
            );
        } else if let Some(said) = &self.notice {
            page = page.push(
                row![
                    text(said.as_str()).size(14).width(Length::Fill),
                    button(text("✕").size(12))
                        .style(button::text)
                        .on_press(Msg::Dismiss),
                ]
                .align_y(Alignment::Center),
            );
        }
        if !self.secrets {
            let search = row![
                button(text("📅").size(16))
                    .padding([6, 10])
                    .style(if self.dates_open {
                        crate::appearance::primary_button
                    } else {
                        button::secondary
                    })
                    .on_press(Msg::DatesOpen),
                text_input("Поиск по истории — слова, через пробел", &self.words)
                    .id(SEARCH)
                    .on_input(Msg::Words)
                    .padding(8)
                    .size(15),
                button(text("⋯").size(16))
                    .padding([6, 12])
                    .style(if self.builder_open {
                        crate::appearance::primary_button
                    } else {
                        button::secondary
                    })
                    .on_press(Msg::BuilderOpen),
            ]
            .spacing(6)
            .align_y(Alignment::Center);
            page = page.push(
                container(search)
                    .padding(8)
                    .width(Length::Fill)
                    .style(|theme| card(theme, false, false)),
            );
        }
        if self.dates_open {
            page = page.push(self.view_dates());
        }
        if let Some(line) = self.filters_line() {
            page = page.push(line);
        }
        page = page.push(if self.builder_open {
            self.view_builder()
        } else {
            self.view_workspace()
        });
        if self.secrets {
            page = page.push(
                text(if self.type_enabled {
                    "Пароли скрыты. Посимвольный ввод отправляет запись прямо в выбранное окно."
                } else {
                    "Пароли скрыты. Обычная вставка и копирование используют текущий буфер обмена."
                })
                .size(12)
                .style(dim),
            );
        }
        page.into()
    }

    fn view_typing(&self) -> Element<'_, Msg> {
        let field = |title: &'static str, value: &str, tag: &'static str| {
            column![
                text(title).size(12),
                text_input("мс", value)
                    .size(13)
                    .padding(5)
                    .on_input(move |s| Msg::TypeDelay(tag, s)),
            ]
            .spacing(3)
            .width(Length::Fixed(160.0))
        };
        let mut controls = column![
            row![
                button(
                    text(if self.type_target.is_some() {
                        "Выбрать другую точку…"
                    } else {
                        "Выбрать точку ввода…"
                    })
                    .size(13)
                )
                .on_press_maybe((!self.type_busy).then_some(Msg::TypePick)),
                pick_list(TYPE_MODES.as_slice(), Some(self.type_mode), Msg::TypeMode).text_size(13),
            ]
            .spacing(8),
            pick_list(
                &[
                    clip_type::LineBreaks::Reject,
                    clip_type::LineBreaks::Spaces,
                    clip_type::LineBreaks::Enter
                ][..],
                Some(self.type_lines),
                Msg::TypeLines,
            )
            .text_size(13),
            text(if self.type_active.is_some() {
                "Идёт ввод в выбранное окно. Кнопка остановки и Esc прерывают его."
            } else if self.type_target.is_some() {
                "Точка выбрана. Выберите текст или пароль и нажмите «Напечатать»."
            } else {
                "Менеджер скроется. Нажмите на нужное поле в подсвеченном окне; Esc — отмена."
            })
            .size(12),
            row![
                field("Перед началом, мс", &self.type_start, "start"),
                field("Между символами, мс", &self.type_between, "between"),
                field("Удержание, мс", &self.type_hold, "hold"),
            ]
            .spacing(8),
        ]
        .spacing(6);
        if self.type_active.is_some() {
            controls = controls.push(
                button(text("Остановить ввод · Esc").size(13))
                    .style(button::danger)
                    .on_press(Msg::TypeCancel),
            );
        }
        if self.type_mode == TypeMode::Keycodes {
            controls = controls.push(
                text("Физические клавиши рассчитаны на раскладку US в целевом окне.").size(12),
            );
        }
        controls.into()
    }

    /// What the feed is filtered by, with the way back.
    fn filters_line(&self) -> Option<Element<'_, Msg>> {
        let mut said = Vec::new();
        if let Some(d) = self.dates.words() {
            said.push(d);
        }
        let kinds: Vec<&str> = KINDS
            .iter()
            .zip(self.kinds)
            .filter(|(_, on)| *on)
            .map(|((_, w), _)| *w)
            .collect();
        if !kinds.is_empty() {
            said.push(format!("только {}", kinds.join(", ")));
        }
        if let Some(re) = &self.re {
            // A long one cut: it is all in the builder.
            let shown: String = re.chars().take(48).collect();
            let more = if shown.len() < re.len() { "…" } else { "" };
            said.push(format!("шаблон /{shown}{more}/"));
        }
        if said.is_empty() {
            return None;
        }
        Some(
            row![
                text(format!("Фильтр: {}", said.join(" · ")))
                    .size(13)
                    .style(dim)
                    .width(Length::Fill),
                button(text("Сбросить").size(13))
                    .style(button::text)
                    .on_press(Msg::ClearAll),
            ]
            .align_y(Alignment::Center)
            .into(),
        )
    }

    fn view_workspace(&self) -> Element<'_, Msg> {
        let feed = container(self.view_feed())
            .width(Length::FillPortion(2))
            .height(Length::Fill);
        let details = container(self.view_details())
            .width(Length::FillPortion(3))
            .height(Length::Fill);
        if self.window_width >= 900.0 {
            row![feed, details].spacing(12).height(Length::Fill).into()
        } else {
            column![feed, details]
                .spacing(12)
                .height(Length::Fill)
                .into()
        }
    }

    fn view_details(&self) -> Element<'_, Msg> {
        let Some(e) = self.selected.and_then(|i| self.entries.get(i)) else {
            return container(text("Выберите запись").style(dim))
                .center(Length::Fill)
                .into();
        };
        let content: Element<'_, Msg> = if e.image().is_some() {
            match self.image_preview.as_ref().filter(|p| p.id == e.id) {
                Some(preview) => match &preview.image {
                    Some(Ok((handle, width, height))) => column![
                        row![
                            button(ui(UiKey::PreviewOpen)).on_press(Msg::PreviewExpand),
                            button(if preview.native {
                                ui(UiKey::PreviewFit)
                            } else {
                                ui(UiKey::PreviewNative)
                            })
                            .on_press(Msg::PreviewNative(!preview.native)),
                        ]
                        .spacing(8),
                        text(format!("{width} × {height}")).size(12).style(dim),
                        iced::widget::image::viewer(handle.clone())
                            .width(Length::Fill)
                            .height(Length::Fill)
                            .content_fit(if preview.native {
                                iced::ContentFit::None
                            } else {
                                iced::ContentFit::Contain
                            })
                            .min_scale(0.05)
                            .max_scale(20.0),
                    ]
                    .spacing(6)
                    .height(Length::Fill)
                    .into(),
                    Some(Err(why)) => container(text(why).style(danger))
                        .center(Length::Fill)
                        .into(),
                    None => container(text(ui(UiKey::PreviewLoading)).style(dim))
                        .center(Length::Fill)
                        .into(),
                },
                None => container(text(ui(UiKey::PreviewLoading)).style(dim))
                    .center(Length::Fill)
                    .into(),
            }
        } else {
            let text_content = if let Some(whole) = self.whole.get(&e.id) {
                whole.clone()
            } else {
                preview(e, self.lines).0
            };
            scrollable(
                text(text_content)
                    .size(15)
                    .wrapping(iced::widget::text::Wrapping::WordOrGlyph),
            )
            .height(Length::Fill)
            .into()
        };
        container(
            column![label("Выбранная запись"), content, self.actions(e)]
                .spacing(10)
                .height(Length::Fill),
        )
        .padding(12)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(|theme| card(theme, false, false))
        .into()
    }

    fn view_feed(&self) -> Element<'_, Msg> {
        let mut feed = column![].spacing(10).padding([4, 14]);
        if self.older {
            feed = feed.push(
                container(
                    text(if self.loading {
                        "Загрузка…"
                    } else {
                        "Прокрутите выше — там ещё"
                    })
                    .size(12)
                    .style(dim),
                )
                .center_x(Length::Fill),
            );
        } else if !self.entries.is_empty() {
            feed = feed
                .push(container(text("Начало истории").size(12).style(dim)).center_x(Length::Fill));
        }
        let mut day = None;
        for (i, e) in self.entries.iter().enumerate() {
            let this = days::day_start(e.last_copied);
            if day != Some(this) {
                day = Some(this);
                feed = feed.push(
                    container(
                        container(text(days::day_label(e.last_copied, self.now)).size(12))
                            .padding([3, 12])
                            .style(pill),
                    )
                    .center_x(Length::Fill),
                );
            }
            feed = feed.push(self.bubble(i, e));
        }
        if self.entries.is_empty() {
            let said = if self.loading {
                "Загрузка…"
            } else if self.error.is_some() {
                ""
            } else if self.filtered() {
                "Ничего не найдено"
            } else {
                if self.secrets {
                    "Паролей нет: отметьте текстовую запись в истории"
                } else if self.favorites {
                    "Избранное пусто: отметьте важную запись в истории"
                } else {
                    "История пуста: здесь появится всё, что копируют в этом контейнере"
                }
            };
            feed = feed.push(
                container(text(said).size(14).style(dim))
                    .center_x(Length::Fill)
                    .padding(40),
            );
        }
        scrollable(feed)
            .id(FEED)
            .anchor_bottom()
            .on_scroll(Msg::Scrolled)
            .height(Length::Fill)
            .width(Length::Fill)
            .into()
    }

    fn bubble<'a>(&'a self, i: usize, e: &'a Entry) -> Element<'a, Msg> {
        let chosen = self.selected == Some(i);
        let mut body = column![].spacing(6);
        if self.secrets {
            body = body.push(
                text(format!("●●●●●●●● · {}", e.preview))
                    .size(15)
                    .wrapping(iced::widget::text::Wrapping::WordOrGlyph),
            );
        } else if let Some((mime, size)) = e.image() {
            // A PNG as its thumbnail (`thumb`); any other image, or one not
            // made yet, said.
            let kind = mime.strip_prefix("image/").unwrap_or(mime);
            match self.thumbs.get(&e.id) {
                Some(Ok(handle)) => {
                    body = body.push(
                        button(
                            iced::widget::image(handle.clone())
                                .height(Length::Shrink)
                                .content_fit(iced::ContentFit::None),
                        )
                        .style(button::text)
                        .padding(0)
                        .on_press(Msg::Preview(e.id)),
                    );
                }
                _ => {
                    body = body
                        .push(text(format!("🖼 картинка {kind} · {}", size_words(*size))).size(15));
                    body = body.push(button(ui(UiKey::PreviewOpen)).on_press(Msg::Preview(e.id)));
                }
            }
        } else {
            let (shown, _) = preview(e, self.lines);
            body = body.push(
                text(shown)
                    .size(15)
                    .wrapping(iced::widget::text::Wrapping::WordOrGlyph),
            );
        }
        body = body.push(
            text(meta_line(e, self.now))
                .size(12)
                .style(dim)
                .wrapping(iced::widget::text::Wrapping::WordOrGlyph),
        );
        let bubble = container(body)
            .padding([8, 12])
            .width(Length::Fill)
            .max_width(900)
            .style(move |t| card(t, chosen, i % 2 == 1));
        mouse_area(bubble).on_press(Msg::Select(i)).into()
    }

    fn view_image_preview<'a>(&'a self, preview: &'a ImagePreview) -> Element<'a, Msg> {
        let controls = row![
            button(ui(UiKey::PreviewBack)).on_press(Msg::PreviewClose),
            button(if preview.native {
                ui(UiKey::PreviewFit)
            } else {
                ui(UiKey::PreviewNative)
            })
            .on_press(Msg::PreviewNative(!preview.native)),
            button(ui(UiKey::PreviewMaximize)).on_press(Msg::PreviewMaximize),
            container(text("")).width(Length::Fill),
            button(text("✕").size(16))
                .padding([4, 10])
                .style(button::secondary)
                .on_press(Msg::Close),
        ]
        .spacing(8)
        .align_y(Alignment::Center);
        let content: Element<'a, Msg> = match &preview.image {
            Some(Ok((handle, width, height))) => column![
                text(format!("{width} × {height} · {}", ui(UiKey::PreviewHelp))).size(12),
                iced::widget::image::viewer(handle.clone())
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .content_fit(if preview.native {
                        iced::ContentFit::None
                    } else {
                        iced::ContentFit::Contain
                    })
                    .filter_method(iced::widget::image::FilterMethod::Nearest)
                    .min_scale(0.05)
                    .max_scale(20.0),
            ]
            .spacing(8)
            .into(),
            Some(Err(why)) => container(text(why)).center(Length::Fill).into(),
            None => container(text(ui(UiKey::PreviewLoading)))
                .center(Length::Fill)
                .into(),
        };
        column![controls, content]
            .spacing(10)
            .padding(12)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn actions<'a>(&'a self, e: &'a Entry) -> Element<'a, Msg> {
        if self.editing_secret == Some(e.id) {
            return column![
                text("Изменить метку или задать новый пароль. Текущий пароль не раскрывается.")
                    .size(13),
                text_input("Метка (не сам пароль)", &self.edited_label)
                    .on_input(Msg::EditedLabel)
                    .size(13),
                text_input(
                    "Новый пароль; пусто — оставить прежний",
                    &self.edited_password
                )
                .secure(true)
                .on_input(Msg::EditedPassword)
                .size(13),
                row![
                    button(text("Сохранить").size(13)).on_press(Msg::SaveSecret(e.id)),
                    button(text("Отмена").size(13)).on_press(Msg::Cancel),
                ]
                .spacing(8),
            ]
            .spacing(6)
            .into();
        }
        if let Some((id, to)) = &self.transferring_secret {
            if *id == e.id {
                return column![
                    text(format!("Перенести пароль в буфер «{to}» и удалить отсюда? Доступ будет у приложений этого буфера после вашей вставки. Совпадающие записи его истории и избранного будут скрыты.")).size(13),
                    row![
                        button(text("Перенести пароль").size(13)).style(button::danger)
                            .on_press(Msg::TransferSecretYes(e.id)),
                        button(text("Отмена").size(13)).on_press(Msg::Cancel),
                    ].spacing(8),
                ].spacing(6).into();
            }
        }
        if let Some((id, target)) = &self.copying_secret {
            if *id == e.id {
                return column![
                    text(format!(
                        "Пароль станет доступен приложениям выбранного буфера: {target}. Копировать?"
                    ))
                    .size(13),
                    row![
                        pick_list(self.targets.as_slice(), Some(target), Msg::LocalTarget),
                        button(text("Копировать пароль").size(13))
                            .style(button::danger)
                            .on_press_maybe(
                                self.target_is_available(target)
                                    .then_some(Msg::CopySecretYes(e.id)),
                            ),
                        button(text("Отмена").size(13)).on_press(Msg::Cancel),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                ]
                .spacing(8)
                .into();
            }
        }
        if self.secreting == Some(e.id) {
            return column![
                text("Сохранить как пароль и убрать совпадающие записи из истории и избранного этого буфера?").size(13),
                text_input(
                    "Метка, например «Почта» (не сам пароль)",
                    &self.secret_label
                )
                .on_input(Msg::SecretLabel)
                .size(13),
                row![
                    button(text("Сохранить как пароль").size(13))
                        .style(button::danger)
                        .on_press(Msg::SecretYes(e.id)),
                    button(text("Отмена").size(13)).on_press(Msg::Cancel),
                ]
                .spacing(8),
            ]
            .spacing(6)
            .into();
        }
        if self.deleting == Some(e.id) {
            return row![
                text(if self.secrets {
                    "Удалить пароль?"
                } else if self.favorites {
                    "Убрать из избранного?"
                } else {
                    "Удалить эту запись из истории?"
                })
                .size(13),
                button(
                    text(if self.secrets || self.favorites {
                        "Убрать"
                    } else {
                        "Удалить"
                    })
                    .size(13)
                )
                .style(button::danger)
                .on_press(Msg::DeleteYes(e.id)),
                button(text("Отмена").size(13))
                    .style(button::secondary)
                    .on_press(Msg::Cancel),
            ]
            .spacing(8)
            .align_y(Alignment::Center)
            .into();
        }
        if let Some((id, target)) = &self.copying {
            if *id == e.id {
                return row![
                    text("Копировать в:").size(13),
                    pick_list(self.targets.as_slice(), Some(target), Msg::LocalTarget),
                    button(text("Копировать").size(13))
                        .style(crate::appearance::primary_button)
                        .on_press_maybe(
                            self.target_is_available(target)
                                .then_some(Msg::CopyTo(e.id)),
                        ),
                    button(text("Отмена").size(13)).on_press(Msg::Cancel),
                ]
                .spacing(8)
                .align_y(Alignment::Center)
                .wrap()
                .into();
            }
        }
        if let Some((id, names)) = &self.moving {
            if *id == e.id {
                let mut line = row![text(if self.secrets {
                    "Перенести пароль в:"
                } else {
                    "Скопировать в:"
                })
                .size(13)]
                .spacing(6)
                .align_y(Alignment::Center);
                match names {
                    None => line = line.push(text("…").size(13)),
                    Some(names) if names.is_empty() => {
                        line = line.push(text("других историй нет").size(13).style(dim))
                    }
                    Some(names) => {
                        for n in names {
                            line = line.push(
                                button(text(n.as_str()).size(13))
                                    .style(button::secondary)
                                    .on_press(if self.secrets {
                                        Msg::TransferSecret(e.id, n.clone())
                                    } else {
                                        Msg::MoveTo(e.id, n.clone())
                                    }),
                            );
                        }
                    }
                }
                line = line.push(
                    button(text("Отмена").size(13))
                        .style(button::text)
                        .on_press(Msg::Cancel),
                );
                return line.wrap().into();
            }
        }
        let mut line = row![].spacing(8).align_y(Alignment::Center);
        if !self.secrets {
            line = line.push(
                row![
                    text("В:").size(13),
                    pick_list(self.targets.as_slice(), Some(&self.target), Msg::Target),
                    button(text("Скопировать в выбранный буфер").size(13))
                        .style(crate::appearance::primary_button)
                        .on_press_maybe(
                            self.can_copy_for_paste(e.id)
                                .then_some(Msg::CopyForPaste(e.id)),
                        ),
                ]
                .spacing(8)
                .align_y(Alignment::Center),
            );
        }
        if self.can_paste || self.type_enabled {
            line = line.push(
                button(
                    text(if self.type_enabled {
                        "Напечатать  ⏎"
                    } else {
                        "Вставить  ⏎"
                    })
                    .size(13),
                )
                .style(crate::appearance::primary_button)
                .on_press_maybe(
                    (!self.type_busy && (!self.type_enabled || e.text_type().is_some()))
                        .then_some(Msg::Paste(e.id)),
                ),
            );
        }
        if self.secrets {
            line = line.push(
                button(text("Скопировать пароль в выбранный буфер…").size(13))
                    .style(button::secondary)
                    .on_press_maybe((!self.type_busy).then_some(Msg::CopySecretAsk(e.id))),
            );
        }
        if !self.favorites && !self.secrets {
            line = line.push(
                button(text("☆ В избранное").size(13))
                    .style(button::secondary)
                    .on_press(Msg::Favorite(e.id)),
            );
            if e.text_type().is_some() {
                line = line.push(
                    button(text("🔒 В пароли…").size(13))
                        .style(button::secondary)
                        .on_press(Msg::SecretAsk(e.id)),
                );
            }
        }
        if self.secrets {
            line = line.push(
                button(text("Изменить…").size(13))
                    .style(button::secondary)
                    .on_press(Msg::EditSecret(e.id)),
            );
        }
        if !self.secrets {
            line = line.push(
                button(text("Копировать в…").size(13))
                    .style(button::secondary)
                    .on_press(Msg::CopyToAsk(e.id)),
            );
        }
        line = line.push(
            button(
                text(if self.secrets {
                    "Перенести пароль…"
                } else {
                    "В историю…"
                })
                .size(13),
            )
            .style(button::secondary)
            .on_press(Msg::MoveAsk(e.id)),
        );
        line.push(
            button(
                text(if self.favorites {
                    "Убрать"
                } else {
                    "Удалить"
                })
                .size(13),
            )
            .style(button::secondary)
            .on_press(Msg::DeleteAsk(e.id)),
        )
        .wrap()
        .into()
    }

    fn view_dates(&self) -> Element<'_, Msg> {
        let choice = |label: &'static str, on: bool, msg: Msg| {
            button(text(label).size(13))
                .padding([4, 10])
                .style(if on {
                    crate::appearance::primary_button
                } else {
                    button::secondary
                })
                .on_press(msg)
        };
        let of = self.dates.of;
        let when = self.dates.when;
        let mut panel = column![
            row![
                choice(
                    "скопировано",
                    of == DateOf::Copied,
                    Msg::DateOf(DateOf::Copied)
                ),
                choice(
                    "вставлено",
                    of == DateOf::Pasted,
                    Msg::DateOf(DateOf::Pasted)
                ),
            ]
            .spacing(6),
            row![
                choice("когда угодно", when == When::All, Msg::When(When::All)),
                choice("сегодня", when == When::Today, Msg::When(When::Today)),
                choice("вчера", when == When::Yesterday, Msg::When(When::Yesterday)),
                choice("за неделю", when == When::Week, Msg::When(When::Week)),
                choice("в день…", when == When::Day, Msg::When(When::Day)),
                choice("около…", when == When::Around, Msg::When(When::Around)),
            ]
            .spacing(6)
            .wrap(),
        ]
        .spacing(8);
        match when {
            When::Day => {
                panel = panel.push(
                    row![
                        text("день").size(13),
                        text_input("ДД.ММ.ГГГГ", &self.dates.day)
                            .on_input(Msg::Day)
                            .width(140)
                            .padding(5),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                )
            }
            When::Around => {
                panel = panel.push(
                    row![
                        text("около").size(13),
                        text_input("ДД.ММ.ГГГГ ЧЧ:ММ", &self.dates.at)
                            .on_input(Msg::At)
                            .width(180)
                            .padding(5),
                        text("±").size(13),
                        text_input("2", &self.dates.hours)
                            .on_input(Msg::Hours)
                            .width(60)
                            .padding(5),
                        text("ч").size(13),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                )
            }
            _ => {}
        }
        if let Err(why) = self.dates.bounds(self.now) {
            panel = panel.push(text(why).size(12).style(danger));
        }
        let mut kinds = row![text("что:").size(13)]
            .spacing(10)
            .align_y(Alignment::Center);
        for (i, (_, word)) in KINDS.iter().enumerate() {
            kinds = kinds.push(
                checkbox(self.kinds[i])
                    .label(*word)
                    .size(16)
                    .text_size(13)
                    .on_toggle(move |on| Msg::Kind(i, on)),
            );
        }
        panel = panel.push(kinds.wrap());
        container(panel)
            .padding(10)
            .width(Length::Fill)
            .style(|t| card(t, false, false))
            .into()
    }

    fn view_builder(&self) -> Element<'_, Msg> {
        let b = &self.builder;
        let mut page = column![row![
            text("Конструктор шаблона").size(18).width(Length::Fill),
            button(text("Закрыть  Esc").size(13))
                .style(button::secondary)
                .on_press(Msg::BuilderOpen),
        ]
        .align_y(Alignment::Center)]
        .spacing(10)
        .padding([4, 14]);

        page = page.push(label("Добавить блок"));
        for (group, tags) in pattern::PALETTE {
            let mut chips = row![].spacing(6);
            for tag in tags.iter().copied() {
                chips = chips.push(
                    button(text(format!("+ {}", tag.name())).size(13))
                        .padding([5, 10])
                        .style(button::secondary)
                        .on_press(Msg::Add(tag)),
                );
            }
            page = page.push(
                column![
                    text(group).size(11).style(dim),
                    chips.wrap().vertical_spacing(6)
                ]
                .spacing(4),
            );
        }

        page = page.push(label("Последовательность"));
        if b.blocks.is_empty() {
            page = page.push(
                container(
                    text("Пока пусто — добавьте первый блок кнопкой выше")
                        .size(13)
                        .style(dim),
                )
                .center_x(Length::Fill)
                .padding(16)
                .style(|t| card(t, false, false)),
            );
        }
        for (i, block) in b.blocks.iter().enumerate() {
            page = page.push(self.view_block(i, block));
        }

        // The result: the pattern, its flags, whether it compiles.
        let tried = b.try_it();
        let pattern = b.pattern();
        let mut out = column![row![
            mono("/").style(dim),
            mono(if pattern.is_empty() {
                "пусто".to_owned()
            } else {
                pattern.clone()
            })
            .width(Length::Fill),
            mono("/").style(dim),
        ]
        .spacing(2)]
        .spacing(8);
        out = out.push(
            row![
                checkbox(b.any_case)
                    .label("без учёта регистра")
                    .text_size(13)
                    .size(16)
                    .on_toggle(|on| Msg::Flag(0, on)),
                checkbox(b.every_line)
                    .label("^ и $ на каждой строке")
                    .text_size(13)
                    .size(16)
                    .on_toggle(|on| Msg::Flag(1, on)),
                checkbox(b.dot_all)
                    .label("точка включает переносы")
                    .text_size(13)
                    .size(16)
                    .on_toggle(|on| Msg::Flag(2, on)),
            ]
            .spacing(14)
            .wrap(),
        );
        if let Tried::Broken(why) = &tried {
            out = out.push(
                text(format!("Ошибка в шаблоне: {why}"))
                    .size(12)
                    .style(danger),
            );
        }
        page = page.push(
            container(out)
                .padding(12)
                .width(Length::Fill)
                .style(|t| card(t, false, false)),
        );

        page = page.push(label("Что это означает"));
        let words = b.explain();
        if words.is_empty() {
            page = page.push(text("добавьте блоки выше").size(13).style(dim));
        } else {
            let mut list = column![].spacing(4);
            for (i, w) in words.into_iter().enumerate() {
                list = list.push(
                    row![
                        mono(format!("{}.", i + 1)).size(12).style(dim),
                        text(w).size(14)
                    ]
                    .spacing(8),
                );
            }
            for f in b.flags_words() {
                list = list.push(text(format!("— {f}")).size(13).style(dim));
            }
            page = page.push(list);
        }

        page = page.push(label("Проверка на своём тексте"));
        page = page.push(
            text_editor(&self.sample)
                .placeholder("Вставьте сюда текст, чтобы проверить совпадения…")
                .on_action(Msg::Sample)
                .font(Font::MONOSPACE)
                .size(13)
                .height(90),
        );
        if let Tried::Found(found) = &tried {
            let spans: Vec<_> = pattern::pieces(&b.sample, found)
                .into_iter()
                .map(|(piece, hit)| {
                    let s = span(piece).font(Font::MONOSPACE);
                    if hit {
                        s.background(Color::from_rgba(0.2, 0.31, 0.48, 0.25))
                            .color(Color::from_rgb(0.2, 0.31, 0.48))
                    } else {
                        s
                    }
                })
                .collect();
            page = page.push(
                container(rich_text::<(), _, _, _>(spans).size(13))
                    .padding(10)
                    .width(Length::Fill)
                    .style(|t| card(t, false, false)),
            );
            page = page.push(mono(pattern::count_words(found.len())).size(12).style(dim));
        }

        let usable = !pattern.is_empty() && !matches!(tried, Tried::Broken(_));
        let mut buttons = row![button(text("Искать по шаблону").size(14))
            .padding([6, 14])
            .style(crate::appearance::primary_button)
            .on_press_maybe(usable.then_some(Msg::Apply))]
        .spacing(8);
        if self.re.is_some() {
            buttons = buttons.push(
                button(text("Искать без шаблона").size(14))
                    .padding([6, 14])
                    .style(button::secondary)
                    .on_press(Msg::Unapply),
            );
        }
        page = page.push(buttons);
        scrollable(page)
            .height(Length::Fill)
            .width(Length::Fill)
            .into()
    }

    fn view_block<'a>(&'a self, i: usize, block: &'a pattern::Block) -> Element<'a, Msg> {
        let small = |t: &'static str| text(t).size(11).style(dim);
        let icon = |t: &'static str, msg: Msg| {
            button(text(t).size(12))
                .padding([2, 8])
                .style(button::secondary)
                .on_press(msg)
        };
        let mut card_body = column![row![
            mono(format!("{}. {}", i + 1, block.kind.tag().name()))
                .size(13)
                .width(Length::Fill),
            icon("↑", Msg::Shift(i, -1)),
            icon("↓", Msg::Shift(i, 1)),
            icon("✕", Msg::Remove(i)),
        ]
        .spacing(4)
        .align_y(Alignment::Center)]
        .spacing(8);
        let field =
            |name: &'static str, value: &'a str, msg: fn(usize, String) -> Msg, width: f32| {
                column![
                    small(name),
                    text_input("", value)
                        .on_input(move |t| msg(i, t))
                        .font(Font::MONOSPACE)
                        .size(13)
                        .padding(5)
                        .width(width),
                ]
                .spacing(3)
            };
        match &block.kind {
            Kind::Text(t) => card_body = card_body.push(field("какой текст", t, Msg::Chars, 220.0)),
            Kind::OneOf(t) => {
                card_body = card_body.push(field("какие символы", t, Msg::Chars, 220.0))
            }
            Kind::NoneOf(t) => {
                card_body = card_body.push(field("какие символы исключить", t, Msg::Chars, 220.0))
            }
            Kind::Letter(a) => {
                card_body = card_body.push(
                    column![
                        small("алфавит"),
                        pick_list(Alphabet::ALL, Some(*a), move |a| Msg::Letters(i, a))
                            .text_size(13),
                    ]
                    .spacing(3),
                )
            }
            Kind::Number(from, to, alone) => {
                card_body = card_body.push(
                    row![
                        field("от", from, Msg::From, 80.0),
                        field("до", to, Msg::To, 80.0),
                        checkbox(*alone)
                            .label("это отдельное число, не часть длинного")
                            .text_size(13)
                            .size(16)
                            .on_toggle(move |on| Msg::Alone(i, on)),
                    ]
                    .spacing(10)
                    .align_y(Alignment::End)
                    .wrap(),
                )
            }
            _ => {}
        }
        if !block.kind.is_position() {
            let mut quant = row![
                small("сколько раз:"),
                pick_list(Times::ALL, Some(block.times), move |t| Msg::Times(i, t)).text_size(13),
            ]
            .spacing(8)
            .align_y(Alignment::Center);
            let number = |value: &'a str, msg: fn(usize, String) -> Msg| {
                text_input("", value)
                    .on_input(move |t| msg(i, t))
                    .size(13)
                    .padding(5)
                    .width(56)
            };
            if matches!(
                block.times,
                Times::Exactly | Times::Between | Times::AtLeast
            ) {
                quant = quant.push(number(&block.n, Msg::N));
            }
            if block.times == Times::Between {
                quant = quant
                    .push(text("—").size(13))
                    .push(number(&block.m, Msg::M));
            }
            if block.times != Times::One {
                quant = quant.push(
                    checkbox(block.lazy)
                        .label("как можно меньше")
                        .text_size(13)
                        .size(16)
                        .on_toggle(move |on| Msg::Lazy(i, on)),
                );
            }
            card_body = card_body.push(quant.wrap());
        }
        container(card_body)
            .padding([10, 12])
            .width(Length::Fill)
            .style(|t| card(t, false, false))
            .into()
    }

    fn subscription(&self) -> Subscription<Msg> {
        Subscription::batch([
            iced::event::listen_with(|event, status, _window| match event {
                iced::Event::Keyboard(keyboard::Event::KeyPressed { key, modifiers, .. }) => {
                    let free = status == iced::event::Status::Ignored;
                    match key.as_ref() {
                        Key::Named(key::Named::Escape) => Some(Msg::Key(Press::Escape)),
                        Key::Named(key::Named::ArrowUp) => Some(Msg::Key(Press::Up)),
                        Key::Named(key::Named::ArrowDown) => Some(Msg::Key(Press::Down)),
                        // A field that took Enter (the builder's text) keeps it.
                        Key::Named(key::Named::Enter) if free => Some(Msg::Key(Press::Enter)),
                        Key::Character("f" | "а") if modifiers.command() => {
                            Some(Msg::Key(Press::Search))
                        }
                        Key::Character("/") if free => Some(Msg::Key(Press::Search)),
                        _ => None,
                    }
                }
                iced::Event::Window(iced::window::Event::CloseRequested) => {
                    Some(Msg::Key(Press::Escape))
                }
                iced::Event::Window(iced::window::Event::Resized(size)) => {
                    Some(Msg::Resized(size.width))
                }
                _ => None,
            }),
            crate::appearance::watch().map(|_| Msg::Appearance),
            live_updates().map(|_| Msg::LivePoll),
        ])
    }
}

/// `clip …`: the window, until an entry is pasted or it is closed.
fn clip_window_settings() -> iced::window::Settings {
    iced::window::Settings {
        size: Size::new(640.0, 760.0),
        position: iced::window::Position::Centered,
        resizable: true,
        exit_on_close_request: false,
        #[cfg(target_os = "linux")]
        platform_specific: iced::window::settings::PlatformSpecific {
            application_id: "vpn-zone-window".to_owned(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn clip_view(clip: &Clip, _window: iced::window::Id) -> Element<'_, Msg> {
    clip.view()
}

pub fn run(args: &[String]) -> iced::Result {
    let mut clipboard_instance = None;
    let mut history = None;
    let mut manager = false;
    let mut launch = None;
    let mut title = None;
    let mut lines = PREVIEW_LINES;
    let mut image_lines = IMAGE_LINES;
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        if flag == "--manager" {
            manager = true;
            continue;
        }
        let value = rest.next().cloned().unwrap_or_default();
        match flag.as_str() {
            "--history" if !value.is_empty() => history = Some(value),
            "--clipboard-instance" if !value.is_empty() => clipboard_instance = Some(value),
            "--launch" => launch = value.parse::<u32>().ok(),
            "--title" if !value.is_empty() => title = Some(value),
            "--lines" => {
                lines = value
                    .parse()
                    .ok()
                    .filter(|n| (1..=50).contains(n))
                    .unwrap_or(lines)
            }
            "--image-lines" => {
                image_lines = value
                    .parse()
                    .ok()
                    .filter(|n| (1..=30).contains(n))
                    .unwrap_or(image_lines)
            }
            _ => {}
        }
    }
    let history = history.or_else(|| manager.then(|| "host".to_owned()));
    let Some(history) = history else {
        eprintln!("vpn-zone-window clip: needs --history <name>");
        std::process::exit(2);
    };
    let history = crate::clipboard_scope::canonical_history(&history).to_owned();
    let title = title.unwrap_or_else(|| {
        if manager {
            "Буферы Cellward".to_owned()
        } else {
            format!("Буфер обмена: {history}")
        }
    });
    let can_paste = launch.is_some() && !manager;
    iced::daemon(
        move || {
            let mut clip = Clip::new(history.clone(), can_paste, clipd::socket_path());
            clip.launch = launch;
            clip.manager = manager;
            if let Some(instance) = &clipboard_instance {
                clip.target = ClipboardTarget::Instance(instance.clone());
                clip.targets.push(clip.target.clone());
            }
            clip.lines = lines;
            clip.image_lines = image_lines;
            let first = clip.search();
            let tabs = if manager {
                clip.load_tabs()
            } else {
                Task::none()
            };
            let (_, open) = iced::window::open(clip_window_settings());
            let targets = clip.load_targets();
            (
                clip,
                Task::batch([first, tabs, targets, open.map(Msg::Opened)]),
            )
        },
        Clip::update,
        clip_view,
    )
    .title(move |_: &Clip, _window| title.clone())
    .theme(|_: &Clip, _window| crate::appearance::load().theme())
    .subscription(Clip::subscription)
    .run()?;
    // Closed without a paste.
    std::process::exit(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u64, copied_at: i64) -> Entry {
        Entry {
            id,
            copied_at,
            last_copied: copied_at,
            copies: 1,
            types: vec![("text/plain".to_owned(), 3)],
            preview: format!("e{id}"),
            ..Entry::default()
        }
    }

    fn clip() -> Clip {
        Clip::new("main".to_owned(), true, PathBuf::from("/nonexistent/sock"))
    }

    #[test]
    fn live_poll_refreshes_tabs_and_targets_without_replacing_choices() {
        let mut c = clip();
        c.manager = true;
        c.tabs = vec!["main".into()];
        c.targets = vec![
            ClipboardTarget::Host,
            ClipboardTarget::Instance("chosen".into()),
        ];
        c.target = ClipboardTarget::Instance("chosen".into());
        let _ = c.update(Msg::LivePoll);
        assert!(c.live.is_some() && c.tabs_loading && c.targets_loading);
        let _ = c.update(Msg::LivePoll);
        assert!(c.tabs_loading && c.targets_loading);
        let _ = c.update(Msg::Tabs(Ok(vec!["new-history".into()])));
        let _ = c.update(Msg::Targets(Ok(vec![
            ClipboardTarget::Host,
            ClipboardTarget::Instance("chosen".into()),
            ClipboardTarget::Instance("new-target".into()),
        ])));
        assert_eq!(c.tabs, ["host", "new-history"]);
        assert_eq!(c.history, "host");
        assert_eq!(c.target, ClipboardTarget::Instance("chosen".into()));
        assert!(c.target_available);
        assert_eq!(c.targets.len(), 3);
        assert!(!c.tabs_loading && !c.targets_loading);
    }

    #[test]
    fn repeated_list_errors_do_not_reopen_a_dismissed_error_or_clear_lists() {
        let mut c = clip();
        c.manager = true;
        c.tabs = vec!["main".into()];
        c.targets = vec![
            ClipboardTarget::Host,
            ClipboardTarget::Instance("one".into()),
        ];
        c.target = ClipboardTarget::Instance("one".into());
        let _ = c.update(Msg::Tabs(Err("offline".into())));
        assert_eq!(c.error.as_deref(), Some("offline"));
        assert_eq!(c.tabs, ["main"]);
        let _ = c.update(Msg::Dismiss);
        let _ = c.update(Msg::Tabs(Err("offline".into())));
        assert_eq!(c.error, None);
        let _ = c.update(Msg::Tabs(Ok(Vec::new())));
        assert!(c.tabs_error.is_none());
        let _ = c.update(Msg::Targets(Err("offline".into())));
        assert_eq!(c.targets.len(), 2);
        assert_eq!(c.target, ClipboardTarget::Instance("one".into()));
        assert!(c.target_available);
    }

    #[test]
    fn vanished_target_is_explicit_and_never_falls_back_to_host() {
        let mut c = clip();
        c.entries.push(entry(1, 10));
        c.targets = vec![
            ClipboardTarget::Host,
            ClipboardTarget::Instance("gone".into()),
        ];
        c.target = ClipboardTarget::Instance("gone".into());
        c.copying_secret = Some((1, c.target.clone()));
        let _ = c.update(Msg::Targets(Ok(vec![ClipboardTarget::Host])));
        assert_eq!(c.target, ClipboardTarget::Instance("gone".into()));
        assert!(!c.target_available);
        assert!(c.targets.contains(&c.target));
        assert!(c.copying_secret.is_none());
        assert!(!c.can_copy_for_paste(1));
        c.secrets = true;
        let _ = c.update(Msg::CopySecretAsk(1));
        assert!(c.copying_secret.is_some());
        assert!(!c.target_is_available(&ClipboardTarget::Instance("gone".into())));
        let _ = c.update(Msg::Target(ClipboardTarget::Host));
        assert_eq!(c.target, ClipboardTarget::Host);
        assert!(c.target_available);
        assert!(!c
            .targets
            .contains(&ClipboardTarget::Instance("gone".into())));
        let _ = c.update(Msg::Targets(Ok(vec![
            ClipboardTarget::Host,
            ClipboardTarget::Instance("gone".into()),
        ])));
        let _ = c.update(Msg::Target(ClipboardTarget::Instance("gone".into())));
        c.secrets = false;
        assert!(c.target_available && c.can_copy_for_paste(1));
    }

    #[test]
    fn live_copies_preserve_selection_search_destination_and_expanded_text() {
        let mut c = clip();
        c.entries = vec![entry(1, 10), entry(2, 20)];
        c.selected = Some(0);
        c.view = (120.0, 400.0);
        c.words = "e".into();
        c.target = ClipboardTarget::Instance("chosen-instance".into());
        c.whole.insert(1, "expanded text".into());
        let _ = c.update(Msg::LivePoll);
        assert!(c.live.is_some());
        let _ = c.update(Msg::LiveLoaded {
            gen: c.gen,
            result: Ok(vec![entry(3, 30), entry(2, 20), entry(1, 10)]),
        });
        assert_eq!(
            c.entries.iter().map(|e| e.id).collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert_eq!(c.selected, Some(0));
        assert_eq!(c.words, "e");
        assert_eq!(
            c.target,
            ClipboardTarget::Instance("chosen-instance".into())
        );
        assert_eq!(c.whole.get(&1).map(String::as_str), Some("expanded text"));
    }

    #[test]
    fn live_burst_is_paged_back_to_the_visible_span_without_gaps() {
        let mut c = clip();
        c.entries = (1..=4).map(|id| entry(id, id as i64)).collect();
        c.selected = Some(1);
        c.view = (200.0, 400.0);
        let _ = c.update(Msg::LivePoll);
        let _ = c.update(Msg::LiveLoaded {
            gen: c.gen,
            result: Ok((14..=63).rev().map(|id| entry(id, id as i64)).collect()),
        });
        assert_eq!(c.entries.len(), 4, "do not commit an incomplete catch-up");
        assert_eq!(c.live.as_ref().unwrap().before, Some(14));
        let _ = c.update(Msg::LiveLoaded {
            gen: c.gen,
            result: Ok((1..=13).rev().map(|id| entry(id, id as i64)).collect()),
        });
        assert_eq!(
            c.entries.iter().map(|e| e.id).collect::<Vec<_>>(),
            (1..=63).collect::<Vec<_>>()
        );
        assert_eq!(c.selected, Some(1));
        assert!(c.live.is_none());
    }

    #[test]
    fn live_catch_up_does_not_automatically_load_older_history() {
        let mut c = clip();
        c.entries = (51..=100).map(|id| entry(id, id as i64)).collect();
        c.selected = Some(3);
        c.older = true;
        c.view = (200.0, 400.0);
        let _ = c.update(Msg::LivePoll);
        let _ = c.update(Msg::LiveLoaded {
            gen: c.gen,
            result: Ok((52..=101).rev().map(|id| entry(id, id as i64)).collect()),
        });
        let _ = c.update(Msg::LiveLoaded {
            gen: c.gen,
            result: Ok((2..=51).rev().map(|id| entry(id, id as i64)).collect()),
        });
        assert_eq!(c.entries.first().unwrap().id, 51);
        assert_eq!(c.entries.last().unwrap().id, 101);
        assert_eq!(c.entries.len(), 51);
        assert!(c.older);
    }

    #[test]
    fn idle_live_feed_follows_a_bounded_newest_page() {
        let mut c = clip();
        c.entries = (1..=50).map(|id| entry(id, id as i64)).collect();
        c.selected = Some(49);
        let _ = c.update(Msg::LivePoll);
        assert_eq!(c.live.as_ref().unwrap().oldest, None);
        let _ = c.update(Msg::LiveLoaded {
            gen: c.gen,
            result: Ok((52..=101).rev().map(|id| entry(id, id as i64)).collect()),
        });
        assert_eq!(c.entries.len(), PAGE);
        assert_eq!(c.entries.last().unwrap().id, 101);
        assert_eq!(c.selected, Some(49));
        assert!(c.older);
    }

    #[test]
    fn stale_live_replies_cannot_cross_histories_or_a_changed_search() {
        let mut c = clip();
        c.manager = true;
        c.tabs = vec!["main".into(), "other".into()];
        let _ = c.update(Msg::LivePoll);
        let old = c.gen;
        let _ = c.update(Msg::Switch("other".into()));
        let _ = c.update(Msg::LiveLoaded {
            gen: old,
            result: Ok(vec![entry(99, 99)]),
        });
        assert!(c.entries.is_empty());
        c.loading = false;
        let _ = c.update(Msg::LivePoll);
        let old = c.gen;
        let _ = c.update(Msg::Words("new query".into()));
        let _ = c.update(Msg::LiveLoaded {
            gen: old,
            result: Ok(vec![entry(99, 99)]),
        });
        assert!(c.entries.is_empty());
    }

    #[test]
    fn live_refresh_is_single_flight_pauses_for_confirmation_and_recovers() {
        let mut c = clip();
        c.entries = vec![entry(1, 1)];
        c.selected = Some(0);
        c.deleting = Some(1);
        let _ = c.update(Msg::LivePoll);
        assert!(c.live.is_none());
        c.deleting = None;
        let _ = c.update(Msg::LivePoll);
        let gen = c.live.as_ref().unwrap().gen;
        let _ = c.update(Msg::LivePoll);
        assert_eq!(c.live.as_ref().unwrap().gen, gen);
        let _ = c.update(Msg::LiveLoaded {
            gen,
            result: Err("temporarily unavailable".into()),
        });
        assert_eq!(c.entries.len(), 1);
        assert!(c.live.is_none());
        let _ = c.update(Msg::LivePoll);
        let _ = c.update(Msg::LiveLoaded {
            gen: c.gen,
            result: Ok(vec![entry(2, 2), entry(1, 1)]),
        });
        assert_eq!(c.entries.len(), 2);
    }

    #[test]
    fn large_preview_is_explicit_closes_on_escape_and_ignores_stale_histories() {
        let mut c = clip();
        let mut image = entry(1, 10);
        image.types = vec![("image/png".into(), 100)];
        c.entries = vec![image];
        let _ = c.update(Msg::Preview(1));
        assert_eq!(c.image_preview.as_ref().unwrap().id, 1);
        assert!(c.image_preview.as_ref().unwrap().image.is_none());
        let _ = c.update(Msg::PreviewLoaded(
            "other".into(),
            1,
            Err("another history's image".into()),
        ));
        assert!(c.image_preview.as_ref().unwrap().image.is_none());
        let _ = c.update(Msg::LivePoll);
        assert!(c.live.is_none(), "do not disturb an open preview");
        let _ = c.key(Press::Escape);
        assert!(!c.image_preview.as_ref().unwrap().expanded);
        let _ = c.update(Msg::PreviewLoaded(
            "main".into(),
            1,
            Err("late reply".into()),
        ));
        assert!(!c.image_preview.as_ref().unwrap().expanded);
        assert_eq!(c.entries.len(), 1);
    }

    #[test]
    fn expanded_image_reuses_the_decoded_full_size_pixels() {
        let mut c = clip();
        let mut image = entry(1, 10);
        image.types = vec![("image/png".into(), 100)];
        c.entries = vec![image];
        let _ = c.update(Msg::Preview(1));
        let _ = c.update(Msg::PreviewLoaded(
            "main".into(),
            1,
            Ok((
                Arc::new(crate::thumb::Source::from_rgba(
                    2,
                    1,
                    vec![1, 2, 3, 4, 5, 6, 7, 8],
                )),
                crate::thumb::Thumb {
                    width: 2,
                    height: 1,
                    rgba: vec![1, 2, 3, 4, 5, 6, 7, 8],
                },
                2,
            )),
        ));
        assert!(c.full_images.contains_key(&("main".into(), 1)));
        let _ = c.update(Msg::PreviewClose);
        let _ = c.update(Msg::Preview(1));
        let preview = c.image_preview.as_ref().unwrap();
        assert!(preview.expanded);
        assert!(preview.image.is_some(), "a cached image must not reload");
        assert_eq!(c.full_images.len(), 1);
    }

    #[test]
    fn full_rgba_is_allocated_only_for_native_and_reused_when_returning() {
        let mut c = clip();
        let mut image = entry(1, 10);
        image.types = vec![("image/png".into(), 100)];
        c.entries = vec![image];
        let _ = c.update(Msg::Preview(1));
        let _ = c.update(Msg::PreviewLoaded(
            "main".into(),
            1,
            Ok((
                Arc::new(crate::thumb::Source::from_rgba(
                    2,
                    1,
                    vec![1, 2, 3, 4, 5, 6, 7, 8],
                )),
                crate::thumb::Thumb {
                    width: 2,
                    height: 1,
                    rgba: vec![1, 2, 3, 4, 5, 6, 7, 8],
                },
                2,
            )),
        ));
        assert!(c.full_images.get(&("main".to_owned(), 1)).unwrap().is_ok());
        assert!(c
            .full_images
            .get(&("main".to_owned(), 1))
            .unwrap()
            .as_ref()
            .unwrap()
            .full
            .is_none());
        let _ = c.update(Msg::PreviewNative(true));
        let _ = c.update(Msg::NativeLoaded(
            "main".into(),
            1,
            Ok(crate::thumb::Thumb {
                width: 2,
                height: 1,
                rgba: vec![1, 2, 3, 4, 5, 6, 7, 8],
            }),
        ));
        assert!(c
            .full_images
            .get(&("main".to_owned(), 1))
            .unwrap()
            .as_ref()
            .unwrap()
            .full
            .is_some());
        let _ = c.update(Msg::PreviewNative(false));
        let _ = c.update(Msg::PreviewNative(true));
        assert!(c.image_preview.as_ref().unwrap().image.is_some());
        assert_eq!(c.full_images.len(), 1);
    }

    #[test]
    fn preview_never_reveals_secrets_and_is_invalidated_on_shelf_change() {
        let mut c = clip();
        let mut image = entry(1, 10);
        image.types = vec![("image/png".into(), 100)];
        c.entries = vec![image];
        c.secrets = true;
        let _ = c.update(Msg::Preview(1));
        assert!(c.image_preview.is_none());
        c.secrets = false;
        let _ = c.update(Msg::Preview(1));
        assert!(c.image_preview.is_some());
        let _ = c.update(Msg::Shelf(true));
        assert!(c.image_preview.is_none());
    }

    #[test]
    fn entry_destination_draft_is_local_and_never_uses_an_unavailable_target() {
        let mut c = clip();
        c.entries.push(entry(1, 10));
        c.available_targets
            .push(ClipboardTarget::Instance("local".into()));
        c.targets = c.available_targets.clone();
        let _ = c.update(Msg::CopyToAsk(1));
        assert_eq!(c.copying, Some((1, ClipboardTarget::Host)));
        let _ = c.update(Msg::LocalTarget(ClipboardTarget::Instance("local".into())));
        assert_eq!(
            c.copy_request_to(1, &ClipboardTarget::Instance("local".into())),
            "copy-to\tmain\t1\tlocal"
        );
        assert_eq!(c.target, ClipboardTarget::Host);
        let _ = c.update(Msg::CopyTo(1));
        assert!(c.can_copy_to(1, &ClipboardTarget::Instance("local".into())));
        let _ = c.update(Msg::CopyToAsk(1));
        let _ = c.update(Msg::LocalTarget(ClipboardTarget::Instance("gone".into())));
        assert!(!c.can_copy_to(1, &ClipboardTarget::Instance("gone".into())));
        let _ = c.update(Msg::CopyTo(1));
        assert!(c.copying.is_some(), "an unavailable target was not sent");
    }

    #[test]
    fn secret_confirmation_uses_its_own_available_target() {
        let mut c = clip();
        c.secrets = true;
        c.entries.push(entry(1, 10));
        c.available_targets
            .push(ClipboardTarget::Instance("secret-target".into()));
        c.targets = c.available_targets.clone();
        let _ = c.update(Msg::CopySecretAsk(1));
        let _ = c.update(Msg::LocalTarget(ClipboardTarget::Instance(
            "secret-target".into(),
        )));
        let _ = c.update(Msg::CopySecretYes(1));
        let _ = c.update(Msg::CopiedSecret(
            ClipboardTarget::Instance("secret-target".into()),
            Ok(String::new()),
        ));
        assert!(c
            .notice
            .as_deref()
            .is_some_and(|notice| notice.contains("secret-target")));
    }

    #[test]
    fn copy_destination_is_explicit_and_independent_of_the_history_tab() {
        let mut c = clip();
        assert_eq!(c.copy_request(7), "copy\tmain\t7");
        c.targets
            .push(ClipboardTarget::Instance("app-browser".into()));
        c.available_targets
            .push(ClipboardTarget::Instance("app-browser".into()));
        let _ = c.update(Msg::Target(ClipboardTarget::Instance("app-browser".into())));
        assert_eq!(c.copy_request(7), "copy-to\tmain\t7\tapp-browser");
        c.history = "another-history".into();
        assert_eq!(
            c.copy_request(7),
            "copy-to\tanother-history\t7\tapp-browser"
        );
        c.secrets = true;
        c.copying_secret = Some((7, c.target.clone()));
        let _ = c.update(Msg::Target(ClipboardTarget::Host));
        assert!(
            c.copying_secret.is_none(),
            "changing destination invalidates password confirmation"
        );
    }

    #[test]
    fn tray_copy_supports_images_but_never_bypasses_password_confirmation() {
        let mut c = clip();
        c.manager = true;
        c.can_paste = false;
        let mut image = entry(1, 10);
        image.types = vec![("image/png".into(), 100)];
        c.entries.push(image);
        assert!(c.can_copy_for_paste(1));
        c.manager = false;
        assert!(
            c.can_copy_for_paste(1),
            "frame history must also copy without pasting"
        );
        c.type_enabled = true;
        assert!(
            c.can_copy_for_paste(1),
            "typing mode must not remove the separate copy action"
        );
        assert!(!c.can_copy_for_paste(99));
        c.secrets = true;
        assert!(!c.can_copy_for_paste(1));
        c.secrets = false;
        c.type_busy = true;
        assert!(!c.can_copy_for_paste(1));
    }

    #[test]
    fn frame_password_copy_requires_confirmation_even_when_paste_is_available() {
        let mut c = clip();
        c.secrets = true;
        c.entries.push(entry(1, 10));
        assert!(c.can_paste);
        let _ = c.update(Msg::CopySecretYes(1));
        assert_eq!(c.copying_secret, None);
        let _ = c.update(Msg::CopySecretAsk(1));
        assert_eq!(c.copying_secret.as_ref().map(|(id, _)| id), Some(&1));
        let _ = c.update(Msg::Cancel);
        assert_eq!(c.copying_secret, None);
        c.type_busy = true;
        let _ = c.update(Msg::CopySecretAsk(1));
        assert_eq!(c.copying_secret, None);
    }

    #[test]
    fn manager_tabs_are_explicit_and_a_switch_cannot_paste() {
        let mut c = Clip::new("host".to_owned(), false, PathBuf::from("/nonexistent/sock"));
        c.manager = true;
        let _ = c.update(Msg::Tabs(Ok(vec![
            "app-helium".to_owned(),
            "host".to_owned(),
        ])));
        assert_eq!(c.tabs, ["app-helium", "host"]);
        let _ = c.update(Msg::Switch("app-helium".to_owned()));
        assert_eq!(c.history, "app-helium");
        assert!(!c.can_paste);
        let _ = c.update(Msg::Switch("unknown".to_owned()));
        assert_eq!(c.history, "app-helium");
        // A delayed answer from the host with the same entry id must never
        // be rendered as the container's text or image, nor delete its row.
        c.entries.push(entry(1, 10));
        let _ = c.update(Msg::Got("host".to_owned(), 1, Ok("host secret".to_owned())));
        let _ = c.update(Msg::Thumb(
            "host".to_owned(),
            1,
            Err("host image".to_owned()),
        ));
        let _ = c.update(Msg::Deleted("host".to_owned(), 1, Ok(String::new())));
        assert!(c.whole.is_empty());
        assert!(c.thumbs.is_empty());
        assert_eq!(c.entries.len(), 1);
        let _ = c.update(Msg::Shelf(true));
        assert_eq!(c.active_history(), "@favorites:app-helium");
        assert!(c.entries.is_empty());
        let _ = c.update(Msg::Got(
            "app-helium".to_owned(),
            1,
            Ok("ordinary history".to_owned()),
        ));
        assert!(c.whole.is_empty());
    }

    #[test]
    fn real_home_and_legacy_network_histories_form_one_manager_tab() {
        let mut c = Clip::new("main".to_owned(), false, PathBuf::from("/nonexistent/sock"));
        c.manager = true;
        let _ = c.update(Msg::Tabs(Ok(vec![
            "main".into(),
            "main:DE".into(),
            "main:NL".into(),
            "host".into(),
            "work".into(),
        ])));
        assert_eq!(c.history, "host");
        assert_eq!(c.tabs, ["host", "work"]);
        let _ = c.update(Msg::Switch("main:DE".into()));
        assert_eq!(c.history, "host");
        let _ = c.update(Msg::Switch("work".into()));
        assert_eq!(c.history, "work");
    }

    #[test]
    fn passwords_hide_contents_and_do_not_keep_a_pending_text_search() {
        let mut c = clip();
        c.words = "a secret query".into();
        c.re = Some("secret".into());
        c.builder_open = true;
        c.whole.insert(1, "revealed history text".into());
        let _ = c.update(Msg::Secrets);
        assert_eq!(c.active_history(), "@secrets:main");
        assert!(c.whole.is_empty() && c.words.is_empty() && c.re.is_none());
        assert!(!c.builder_open);
        c.entries.push(entry(1, 10));
        let _ = c.update(Msg::MoveAsk(1));
        assert!(c.whole.is_empty() && c.moving.is_some());
        let _ = c.update(Msg::Shelf(false));
        assert_eq!(c.active_history(), "main");
    }

    #[test]
    fn password_editor_never_loads_plaintext_and_clears_on_cancel_or_switch() {
        let mut c = clip();
        let _ = c.update(Msg::Secrets);
        let mut e = entry(1, 10);
        e.preview = "Пароль: Mail".into();
        c.entries.push(e);
        c.selected = Some(0);
        let _ = c.update(Msg::EditSecret(1));
        assert_eq!(c.edited_label, "Mail");
        assert!(c.edited_password.is_empty() && c.whole.is_empty());
        let _ = c.update(Msg::EditedPassword("new password".into()));
        let _ = c.key(Press::Enter);
        assert_eq!(c.editing_secret, Some(1));
        let _ = c.key(Press::Escape);
        assert!(c.editing_secret.is_none() && c.edited_password.is_empty());
        let _ = c.update(Msg::EditSecret(1));
        let _ = c.update(Msg::EditedPassword("another".into()));
        let _ = c.update(Msg::Shelf(false));
        assert!(c.editing_secret.is_none() && c.edited_password.is_empty());
    }

    #[test]
    fn secret_transfer_requires_destination_and_separate_confirmation() {
        let mut c = clip();
        let _ = c.update(Msg::Secrets);
        c.entries.push(entry(1, 10));
        let _ = c.update(Msg::TransferSecret(1, "host".into()));
        assert!(c.transferring_secret.is_none());
        let _ = c.update(Msg::MoveAsk(1));
        let _ = c.update(Msg::Histories(
            "main".into(),
            Ok(vec!["wrong shelf".into()]),
        ));
        assert_eq!(c.moving.as_ref().unwrap().1, None);
        let _ = c.update(Msg::Histories(
            "@secrets:main".into(),
            Ok(vec!["main".into(), "host".into()]),
        ));
        assert_eq!(c.moving.as_ref().unwrap().1.as_ref().unwrap(), &["host"]);
        let _ = c.update(Msg::TransferSecret(1, "host".into()));
        assert_eq!(c.transferring_secret, Some((1, "host".into())));
        let _ = c.key(Press::Enter);
        assert!(
            c.transferring_secret.is_some(),
            "Enter is not a transfer confirmation"
        );
        let _ = c.update(Msg::Cancel);
        assert!(c.transferring_secret.is_none());
    }

    #[test]
    fn the_filter_becomes_a_search() {
        let now = days::at(2026, 10, 12, 15, 0);
        let mut c = clip();
        assert_eq!(c.filter(now).unwrap(), Filter::default());
        c.words = "пароль wifi".to_owned();
        c.kinds = [false, true, false];
        c.builder.add(Tag::Digit);
        c.builder.blocks[0].times = Times::Exactly;
        c.builder.blocks[0].n = "4".to_owned();
        c.builder.any_case = true;
        let _ = c.update(Msg::Apply);
        assert_eq!(c.re.as_deref(), Some("(?i)[0-9]{4}"));
        c.dates.when = When::Today;
        let f = c.filter(now).unwrap();
        let today = (days::at(2026, 10, 12, 0, 0), days::at(2026, 10, 13, 0, 0));
        assert_eq!(f.copied, Some(today));
        assert_eq!(
            clipd::search_request("main", &f, None, PAGE),
            format!(
                "search\tmain\tq=пароль wifi\tre=(?i)[0-9]{{4}}\ttype=image/*\tcopied={}-{}\tlimit=50",
                today.0, today.1
            )
        );
        c.dates.of = DateOf::Pasted;
        c.dates.when = When::Yesterday;
        let f = c.filter(now).unwrap();
        assert_eq!(f.pasted, Some((days::at(2026, 10, 11, 0, 0), today.0)));
        assert_eq!(f.copied, None);
        c.dates.when = When::Week;
        assert_eq!(
            c.filter(now).unwrap().pasted,
            Some((days::at(2026, 10, 6, 0, 0), today.1))
        );
        c.dates.when = When::Day;
        c.dates.day = "1.10".to_owned();
        assert_eq!(
            c.filter(now).unwrap().pasted,
            Some((days::at(2026, 10, 1, 0, 0), days::at(2026, 10, 2, 0, 0)))
        );
        c.dates.day = "что-то".to_owned();
        assert!(c.filter(now).is_err());
        c.dates.when = When::Around;
        c.dates.at = "12.10.2026 14:00".to_owned();
        c.dates.hours = "1,5".to_owned();
        let at = days::at(2026, 10, 12, 14, 0);
        assert_eq!(
            c.filter(now).unwrap().pasted,
            Some((at - 5_400_000, at + 5_400_000))
        );
        c.dates.of = DateOf::Copied;
        assert_eq!(c.filter(now).unwrap().around, Some((at, 5_400_000)));
        assert_eq!(
            c.dates.words().unwrap(),
            "скопировано около 12.10.2026 14:00 ± 1,5 ч"
        );
        // A pattern that does not compile is not searched by.
        let mut d = clip();
        d.builder.add(Tag::AnyChar);
        d.builder.blocks[0].times = Times::Between;
        d.builder.blocks[0].m = "1000000".to_owned();
        let _ = d.update(Msg::Apply);
        assert_eq!(d.re, None);
    }

    #[test]
    fn pages_are_kept_oldest_first() {
        let mut c = clip();
        c.gen = 1;
        let page: Vec<Entry> = (0..PAGE as u64)
            .rev()
            .map(|id| entry(id + 100, 1000 + id as i64))
            .collect();
        let _ = c.update(Msg::Loaded {
            gen: 1,
            older: false,
            result: Ok(page),
        });
        assert_eq!(c.entries.first().unwrap().id, 100);
        assert_eq!(c.entries.last().unwrap().id, 149);
        assert!(c.older);
        assert_eq!(c.selected, Some(PAGE - 1), "the newest is chosen at open");
        // An older page goes on top; the choice stays on its entry.
        let _ = c.update(Msg::Loaded {
            gen: 1,
            older: true,
            result: Ok(vec![entry(99, 999), entry(98, 998)]),
        });
        assert_eq!(c.entries[0].id, 98);
        assert_eq!(c.entries[c.selected.unwrap()].id, 149);
        assert!(!c.older);
        // An answer of a search since replaced is dropped.
        let _ = c.update(Msg::Loaded {
            gen: 0,
            older: false,
            result: Ok(vec![]),
        });
        assert_eq!(c.entries.len(), PAGE + 2);
        let _ = c.update(Msg::Loaded {
            gen: 1,
            older: false,
            result: Err("нет".to_owned()),
        });
        assert_eq!(c.error.as_deref(), Some("нет"));
    }

    #[test]
    fn keys_move_the_choice() {
        let mut c = clip();
        let _ = c.key(Press::Up);
        assert_eq!(c.selected, None, "nothing to choose");
        c.entries = (1..=3).map(|id| entry(id, id as i64)).collect();
        let _ = c.key(Press::Down);
        assert_eq!(c.selected, Some(2), "the newest first");
        let _ = c.key(Press::Down);
        assert_eq!(c.selected, Some(2), "nothing below the newest");
        let _ = c.key(Press::Up);
        let _ = c.key(Press::Up);
        let _ = c.key(Press::Up);
        assert_eq!(c.selected, Some(0));
        let _ = c.update(Msg::Select(1));
        assert_eq!(c.selected, Some(1));
        // A question open is closed by Esc first, then the builder.
        c.deleting = Some(2);
        c.builder_open = true;
        let _ = c.key(Press::Escape);
        assert!(c.deleting.is_none() && c.builder_open);
        // The builder's fields keep the arrows.
        let _ = c.key(Press::Down);
        assert_eq!(c.selected, Some(1));
        let _ = c.key(Press::Escape);
        assert!(!c.builder_open);
        let _ = c.key(Press::Down);
        assert_eq!(c.selected, Some(2));
        // A deleted entry: the choice to its neighbour.
        let _ = c.update(Msg::Deleted("main".to_owned(), 3, Ok(String::new())));
        assert_eq!(c.selected, Some(1));
        assert_eq!(c.entries.len(), 2);
    }

    #[test]
    fn long_previews_are_compact_and_unicode_safe() {
        let mut e = entry(1, 10);
        e.preview = "https://example.com/?".to_owned() + &"parameter=value&".repeat(40);
        e.types = vec![("text/plain".into(), e.preview.len() as u64)];
        let (shown, more) = preview(&e, PREVIEW_LINES);
        assert!(more);
        assert!(shown.ends_with('…'));
        assert_eq!(shown.chars().count(), PREVIEW_CHARS + 1);
        e.preview = "🙂".repeat(PREVIEW_CHARS * 2);
        let (unicode, _) = preview(&e, PREVIEW_LINES);
        assert_eq!(unicode.chars().count(), PREVIEW_CHARS + 1);
    }

    #[test]
    fn cards_use_available_width_up_to_a_readable_limit() {
        fn sizes(node: &iced::advanced::layout::Node, out: &mut Vec<f32>) {
            out.push(node.size().width);
            for child in node.children() {
                sizes(child, out);
            }
        }

        let c = clip();
        let e = entry(1, 10);
        for (viewport, expected) in [(1200.0, 900.0), (420.0, 420.0)] {
            let mut bubble = c.bubble(0, &e);
            let mut tree = iced::advanced::widget::Tree::new(&bubble);
            let renderer = iced::Renderer::new(iced::Font::default(), iced::Pixels(16.0));
            let limits =
                iced::advanced::layout::Limits::new(Size::ZERO, Size::new(viewport, f32::INFINITY));
            let node = bubble.as_widget_mut().layout(&mut tree, &renderer, &limits);
            let mut widths = Vec::new();
            sizes(&node, &mut widths);
            assert!(
                widths.contains(&expected),
                "viewport {viewport}: expected card width {expected}, got {widths:?}"
            );
        }
    }

    #[test]
    fn workspace_switches_between_side_by_side_and_stacked_panes() {
        let mut c = clip();
        for (width, stacked) in [(1200.0, false), (600.0, true)] {
            let _ = c.update(Msg::Resized(width));
            let mut workspace = c.view_workspace();
            let mut tree = iced::advanced::widget::Tree::new(&workspace);
            let renderer = iced::Renderer::new(iced::Font::default(), iced::Pixels(16.0));
            let limits = iced::advanced::layout::Limits::new(Size::ZERO, Size::new(width, 700.0));
            let node = workspace
                .as_widget_mut()
                .layout(&mut tree, &renderer, &limits);
            let children = node.children();
            assert!(children.len() >= 2);
            let first = children[0].bounds();
            let second = children[1].bounds();
            if stacked {
                assert!(second.y > first.y, "narrow panes are not stacked");
            } else {
                assert!(second.x > first.x, "wide panes are not side by side");
            }
        }
    }

    #[test]
    fn default_destination_and_copy_action_stay_together_when_actions_wrap() {
        let mut c = clip();
        c.targets = vec![
            ClipboardTarget::Host,
            ClipboardTarget::Instance("chosen-instance".into()),
        ];
        c.target = ClipboardTarget::Instance("chosen-instance".into());
        let e = entry(1, 10);
        for width in [1200.0, 560.0] {
            let mut actions = c.actions(&e);
            let mut tree = iced::advanced::widget::Tree::new(&actions);
            let renderer = iced::Renderer::new(iced::Font::default(), iced::Pixels(16.0));
            let limits =
                iced::advanced::layout::Limits::new(Size::ZERO, Size::new(width, f32::INFINITY));
            let node = actions
                .as_widget_mut()
                .layout(&mut tree, &renderer, &limits);
            let children = node.children();
            assert!(children.len() > 1);
            if width < 900.0 {
                assert!(
                    children[1].bounds().y > children[0].bounds().y,
                    "narrow actions did not wrap"
                );
            }
            let copy_group = children[0].children();
            assert_eq!(copy_group.len(), 3);
            let destination = copy_group[1].bounds();
            let copy = copy_group[2].bounds();
            assert!(destination.x + destination.width <= copy.x);
            assert!(
                ((destination.y + destination.height / 2.0) - (copy.y + copy.height / 2.0)).abs()
                    < 0.01,
                "destination and copy action split at width {width}"
            );
        }
    }

    #[test]
    fn an_entry_is_said() {
        let now = days::at(2026, 10, 12, 15, 0);
        let mut e = entry(1, days::at(2026, 10, 12, 9, 5));
        assert_eq!(meta_line(&e, now), "09:05");
        e.copies = 3;
        e.last_copied = days::at(2026, 10, 12, 10, 0);
        e.pastes = 2;
        e.last_pasted = days::at(2026, 10, 11, 18, 30);
        assert_eq!(
            meta_line(&e, now),
            "10:00 · скопировано 3 раза · вставлено 2 раза, последний — вчера в 18:30"
        );
        assert_eq!(paste_line("main", 7), "paste\tmain\t7\n");
        assert_eq!(size_words(812), "812 Б");
        assert_eq!(size_words(3072), "3 КБ");
        assert_eq!(size_words(1_300_000), "1,2 МБ");
        e.preview = (1..=20)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let (shown, more) = preview(&e, 5);
        assert!(more);
        assert_eq!(shown.lines().count(), 6);
        e.preview = "abc".to_owned();
        e.types = vec![("text/plain".to_owned(), 3)];
        assert_eq!(preview(&e, 3), ("abc".to_owned(), false));
        e.types = vec![("text/plain".to_owned(), 5000)];
        assert!(preview(&e, 3).1, "the daemon cut it");
        assert_eq!(times(21), "раз");
        assert_eq!(times(1), "раз");
        assert_eq!(times(13), "раз");
    }
}
