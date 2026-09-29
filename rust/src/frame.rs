//! The zone frame's settings (`docs/WINDOW-FRAME.md` §0а, §11): the border's
//! colour per zone and its width, the title strip's mode (always, on hover,
//! off) and its text, the look — the style of the frame (full, soft, a tag),
//! the look of its buttons and the radius of the window's corners inside it
//! (2026-09-28, §8 «Вид рамки») —, and the switch that hides every frame —
//! for sharing the screen, where the owner wants windows without it.
//!
//! What draws it is the Wayland proxy (`crate::wl_frame`, the text
//! `crate::wl_title`); what is read here is handed to it on the command line
//! of `wl-sandbox` (`--frame`, `--frame-title`), except the switch, which the
//! supervisor reads again for every connection (`--frame-switch`): a window
//! opened after `vpn-zone frame hide` comes up without a frame even in a
//! program started before. The look rides in `--frame` too (its last three
//! fields, said only when one is not the default), so that the launch's line
//! stays what it was.
//!
//! **On the fly** (step 6 of `docs/PERMISSIONS.md` §11.15, 2026-09-29): the
//! launch's supervisor watches the settings' directory (inotify,
//! `wl_proxy::Live`) and tells its proxy the frame anew; open windows are
//! laid anew. The width first — 0 is no border at all, the title strip
//! alone where it is on.
//!
//! **Round corners** (2026-09-29, the owner: «закругление тоже пусть
//! меняется динамически… и внешнее… в идеале расчёт автоматическим по
//! закруглению niri»): the radius inside the frame, over the program's
//! corners, and the one outside it, the frame's own; each a number or
//! `niri` — niri's radius for every window (`crate::niri`), read when the
//! frame is, and again when niri's config changes. Inside, `niri` is the
//! radius that keeps the curves concentric: niri's less the border, at the
//! top less the title strip too where it takes room.
//!
//! Where a setting comes from, as for the others: Nix (`declared/`) over the
//! local one, the local one over the default. The switch has no Nix option —
//! it is flipped for a call and back, and a switch declared in Nix could not
//! be.
//!
//! None of this is a trust boundary (`docs/WINDOW-FRAME.md` §5.9): a program
//! can put a popup of its own over the border. The files are out of a zone's
//! reach all the same — `~/.config/vpn-zones` is read-only there and the
//! zones' state is hidden (`docs/LEAK-MODEL.md` §17) —, so a program cannot
//! turn its border off or paint it another zone's colour.

use std::path::{Path, PathBuf};

use crate::cli::{read_setting, DECLARED_DIR};
use crate::container::Source;

/// The per-zone colour, in the zone's directory: `#rrggbb`.
pub const COLOR_FILE: &str = "frame-color";
/// The colours declared in Nix, below `declared/`: `<zone> #rrggbb` per line.
pub const DECLARED_COLORS: &str = "frame-colors";
/// The width, a setting file of the config directory (logical pixels).
pub const WIDTH_SETTING: &str = "frame-width";
/// The switch, a setting file of the config directory: `hidden` or `shown`.
pub const SWITCH_SETTING: &str = "frames";

/// The title strip's mode, a setting file of the config directory: `always`,
/// `hover` or `off`.
pub const TITLE_SETTING: &str = "frame-title";
/// The buttons' look, a setting file of the config directory: `cellward`,
/// `gnome`, `kde`, `macos`, `windows` or `none` ([`ButtonStyle`]).
pub const BUTTONS_SETTING: &str = "frame-buttons";
/// The frame's style, a setting file of the config directory: `full`,
/// `soft` or `tag` ([`Style`]).
pub const STYLE_SETTING: &str = "frame-style";
/// The radius of the window's corners inside the frame, a setting file of
/// the config directory (logical pixels, 0 for square ones, or `niri`).
pub const RADIUS_SETTING: &str = "frame-radius";
/// The radius of the frame's own corners, outside, a setting file of the
/// config directory (logical pixels, 0 for square ones, or `niri`).
pub const OUTER_RADIUS_SETTING: &str = "frame-outer-radius";
/// The border's width while the compositor has a window fullscreen, a
/// setting file of the config directory: `same` (as outside fullscreen) or
/// logical pixels ([`Fullscreen`]).
pub const FULLSCREEN_WIDTH_SETTING: &str = "frame-fullscreen-width";
/// The title strip's mode in fullscreen: `always`, `hover` or `off`.
pub const FULLSCREEN_TITLE_SETTING: &str = "frame-fullscreen-title";
/// How long the zone's label shows on a window going fullscreen, whole
/// seconds; 0 for none.
pub const FULLSCREEN_NOTICE_SETTING: &str = "frame-fullscreen-notice";
/// How the title strip offers fullscreen: `one`, `two`, `menu` or `none`
/// ([`FullscreenButton`]).
pub const FULLSCREEN_BUTTON_SETTING: &str = "frame-fullscreen-button";
/// What a double click on the title strip does: `maximize` or `none`.
pub const DOUBLE_CLICK_SETTING: &str = "frame-double-click";

/// The most characters of one part of the title — the zone's name, the
/// container's — that are drawn; a longer one is cut, with an ellipsis.
pub const MAX_TITLE_PART: usize = 40;

/// Four logical pixels: a whole number of pixels at the usual scales (5 at
/// 1.25, 6 at 1.5, 7 at 1.75, 8 at 2), so the border meets the window
/// without a half pixel (§5.6), and seen at a glance without eating the
/// window.
pub const DEFAULT_WIDTH: i32 = 4;
/// Wider than this is not a border any more.
pub const MAX_WIDTH: i32 = 32;
/// Square corners unless asked: the owner's windows as they were.
pub const DEFAULT_RADIUS: Radius = Radius::Px(0);
/// And the frame's own.
pub const DEFAULT_OUTER_RADIUS: Radius = Radius::Px(0);
/// Rounder than this is not a corner of a window any more: 16 is the most
/// the owner asked for (2026-09-27, «0–16»).
pub const MAX_RADIUS: i32 = 16;
/// The frame's own corners: as round as the border and the radius inside
/// it together, at most.
pub const MAX_OUTER_RADIUS: i32 = 32;

/// A radius of round corners, as a setting has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Radius {
    /// Logical pixels.
    Px(i32),
    /// niri's radius for every window (`crate::niri`), logical pixels, as it
    /// was read ([`niri_radius`]); 0 where its config sets none.
    Niri(i32),
}

impl Radius {
    /// The number of pixels, or niri's as it was read.
    pub fn px(self) -> i32 {
        match self {
            Self::Px(r) | Self::Niri(r) => r,
        }
    }

    /// The setting's word: the number, or `niri`.
    pub fn word(self) -> String {
        match self {
            Self::Px(r) => r.to_string(),
            Self::Niri(_) => "niri".to_owned(),
        }
    }

    /// On `wl-sandbox --frame`: the number, or `niri` and niri's radius as
    /// it was read, `niri20` — the proxy reads no file.
    fn arg(self) -> String {
        match self {
            Self::Px(r) => r.to_string(),
            Self::Niri(r) => format!("niri{r}"),
        }
    }

    /// [`Radius::arg`] back, a number of pixels up to `max`.
    fn parse_arg(text: &str, max: i32) -> Option<Self> {
        match text.strip_prefix("niri") {
            Some(r) => whole(r, MAX_OUTER_RADIUS).map(Self::Niri),
            None => whole(text, max).map(Self::Px),
        }
    }

    /// niri's radius read again where the setting says `niri`.
    fn read(self) -> Self {
        match self {
            Self::Niri(_) => Self::Niri(niri_radius()),
            px => px,
        }
    }
}

/// A whole number of 0 to `max`, digits only.
fn whole(text: &str, max: i32) -> Option<i32> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok().filter(|r| (0..=max).contains(r))
}

/// niri's radius for every window now, whole logical pixels up to
/// [`MAX_OUTER_RADIUS`]; 0 where niri's config sets none, or there is no
/// niri's config.
pub fn niri_radius() -> i32 {
    crate::niri::corner_radius_now().map_or(0, |r| {
        r.round().clamp(0.0, f64::from(MAX_OUTER_RADIUS)) as i32
    })
}

/// A colour, 8 bits a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

impl Rgb {
    /// `#rrggbb` (or without the `#`). Nothing else: no names, no alpha — the
    /// border is opaque on purpose (§5.9), and a shorter form is one more
    /// thing to get wrong in a file nobody reads back.
    pub fn parse(text: &str) -> Option<Self> {
        let hex = text.trim();
        let hex = hex.strip_prefix('#').unwrap_or(hex);
        if hex.len() != 6 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let channel = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).ok();
        Some(Self(channel(0)?, channel(2)?, channel(4)?))
    }

    /// `#rrggbb`.
    pub fn hex(self) -> String {
        format!("#{:02x}{:02x}{:02x}", self.0, self.1, self.2)
    }

    /// The pixel of `wl_shm` format XRGB8888: a native-endian 32-bit word,
    /// the top byte unused (and set, so that nobody reads it as transparent).
    pub fn xrgb8888(self) -> [u8; 4] {
        (0xff00_0000u32 | (self.0 as u32) << 16 | (self.1 as u32) << 8 | self.2 as u32)
            .to_ne_bytes()
    }
}

/// The colour of a zone nobody gave one: its name hashed to a hue, at a
/// saturation and brightness that read as a colour on both a light and a
/// dark desktop. The same name is the same colour on every machine and
/// every run — the owner learns it — and two names are two colours more
/// often than not (the hue is 360 steps; FNV-1a spreads short names well).
pub fn default_color(zone: &str) -> Rgb {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in zone.bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hsv((hash % 360) as f64, 0.65, 0.85)
}

/// RGB to HSV: the hue in degrees (0 up to 360), the saturation and the
/// value in 0..=1. A grey has hue 0.
pub(crate) fn to_hsv(Rgb(r8, g8, b8): Rgb) -> (f64, f64, f64) {
    // Which channel is the largest, by the bytes: no float compared equal.
    let top = r8.max(g8).max(b8);
    let (r, g, b) = (
        f64::from(r8) / 255.0,
        f64::from(g8) / 255.0,
        f64::from(b8) / 255.0,
    );
    let max = f64::from(top) / 255.0;
    let d = max - f64::from(r8.min(g8).min(b8)) / 255.0;
    let h = if d <= 0.0 {
        0.0
    } else if top == r8 {
        60.0 * ((g - b) / d).rem_euclid(6.0)
    } else if top == g8 {
        60.0 * ((b - r) / d + 2.0)
    } else {
        60.0 * ((r - g) / d + 4.0)
    };
    let s = if top == 0 { 0.0 } else { d / max };
    (h.rem_euclid(360.0), s, max)
}

/// HSV (hue in degrees, the rest in 0..=1) to RGB.
pub(crate) fn hsv(h: f64, s: f64, v: f64) -> Rgb {
    let c = v * s;
    let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
    let m = v - c;
    let (r, g, b) = match h as u32 / 60 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    let byte = |f: f64| ((f + m) * 255.0).round().clamp(0.0, 255.0) as u8;
    Rgb(byte(r), byte(g), byte(b))
}

/// A zone's colour and where it comes from: Nix (`frame.colors`), the
/// zone's own file (`vpn-zone frame color`), or [`default_color`]. A value
/// that does not parse is skipped, as if it were not there.
pub fn zone_color(state: &Path, config: &Path, zone: &str) -> (Rgb, Source) {
    if let Ok(text) = crate::declared::read(&config.join(DECLARED_DIR).join(DECLARED_COLORS)) {
        let declared = text.lines().find_map(|line| {
            let (name, color) = line.trim().split_once(char::is_whitespace)?;
            (name == zone).then(|| Rgb::parse(color)).flatten()
        });
        if let Some(color) = declared {
            return (color, Source::Nix);
        }
    }
    if let Some(color) = read_setting(&state.join(zone).join(COLOR_FILE))
        .as_deref()
        .and_then(Rgb::parse)
    {
        return (color, Source::Local);
    }
    (default_color(zone), Source::Default)
}

/// A width setting file's text: `None` when absent or not a width.
fn width_file(text: Option<String>) -> Option<i32> {
    text?
        .trim()
        .parse()
        .ok()
        .filter(|w| (0..=MAX_WIDTH).contains(w))
}

/// The border's width in logical pixels and where it comes from.
pub fn width(config: &Path) -> (i32, Source) {
    let declared = crate::declared::setting(&config.join(DECLARED_DIR).join(WIDTH_SETTING));
    if let Some(w) = width_file(declared) {
        return (w, Source::Nix);
    }
    if let Some(w) = width_file(read_setting(&config.join(WIDTH_SETTING))) {
        return (w, Source::Local);
    }
    (DEFAULT_WIDTH, Source::Default)
}

/// Whether the switch hides the borders now. Only `hidden` hides: a file
/// that cannot be read, or says something else, leaves them — the border is
/// the default, and nothing a zone can reach can remove it (see above).
pub fn hidden(config: &Path) -> bool {
    // No settings' directory: nothing hides the border — never a path
    // relative to wherever this runs (review 2026-09-27: `--frame` without
    // `--frame-switch` read the working directory's `frames`).
    if !config.is_absolute() {
        return false;
    }
    let value = crate::declared::setting(&config.join(DECLARED_DIR).join(SWITCH_SETTING))
        .or_else(|| read_setting(&config.join(SWITCH_SETTING)));
    value.is_some_and(|v| v.trim() == "hidden")
}

/// Where the title strip is (`docs/WINDOW-FRAME.md` §0а: the border is
/// always there, the title may hide).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TitleMode {
    /// Along the top, inside the window: the program is told a size less
    /// the strip, as it is told one less the border.
    Always,
    /// Over the top of the program's content, only while the pointer is at
    /// the window's top edge or on the strip: it takes no room.
    Hover,
    /// No strip; the border alone.
    Off,
}

/// The owner's choice (§0а): the strip is there unless asked otherwise.
pub const DEFAULT_TITLE: TitleMode = TitleMode::Always;

impl TitleMode {
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "always" => Some(Self::Always),
            "hover" => Some(Self::Hover),
            "off" => Some(Self::Off),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::Hover => "hover",
            Self::Off => "off",
        }
    }
}

/// The title strip's mode and where it comes from. A value that is not a
/// mode is skipped, as if it were not there.
pub fn title_mode(config: &Path) -> (TitleMode, Source) {
    let file = |text: Option<String>| text.as_deref().and_then(TitleMode::parse);
    if let Some(mode) = file(crate::declared::setting(
        &config.join(DECLARED_DIR).join(TITLE_SETTING),
    )) {
        return (mode, Source::Nix);
    }
    if let Some(mode) = file(read_setting(&config.join(TITLE_SETTING))) {
        return (mode, Source::Local);
    }
    (DEFAULT_TITLE, Source::Default)
}

/// How the frame's buttons look (the owner, 2026-09-27: the four desktops'
/// looks, all equal, and the one there was): which end of the strip, which
/// order, what shape, which colours at rest, under the pointer and pressed.
/// `crate::wl_title::buttons_look` is each one's look; the drawing and the
/// hit-testing follow it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonStyle {
    /// Stage 3's: square cells of the frame's colour at the right end.
    Cellward,
    /// GNOME's (Adwaita): round buttons on a faint disc, at the right end.
    Gnome,
    /// KDE's (Breeze): glyphs alone, a disc under the pointer, at the right.
    Kde,
    /// macOS's: the traffic lights at the LEFT end — close red, then yellow,
    /// then green —, the glyphs showing under the pointer.
    Macos,
    /// Windows's: wide rectangles at the right end, close red under the
    /// pointer.
    Windows,
    /// No buttons: the strip (or the tag) with its label alone.
    None,
}

/// Stage 3's look stays the default: nothing changes for whoever does not ask.
pub const DEFAULT_BUTTONS: ButtonStyle = ButtonStyle::Cellward;

impl ButtonStyle {
    pub const ALL: [ButtonStyle; 6] = [
        Self::Cellward,
        Self::Gnome,
        Self::Kde,
        Self::Macos,
        Self::Windows,
        Self::None,
    ];

    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        Self::ALL.into_iter().find(|s| s.as_str() == text)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cellward => "cellward",
            Self::Gnome => "gnome",
            Self::Kde => "kde",
            Self::Macos => "macos",
            Self::Windows => "windows",
            Self::None => "none",
        }
    }
}

/// The frame's style (the owner, 2026-09-27: the frame is always in view and
/// must not strain the eyes; and a tag, «бирка», instead of a frame for whoever
/// prefers one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    /// The zone's colour itself, the border and the title strip: stage 2's
    /// pixels.
    Full,
    /// The zone's colour, calmer: its hue kept, less saturated and a little
    /// darker, and the border two tones across its width — darker outside,
    /// the title's tone inside (`crate::wl_title::soft_inner`).
    Soft,
    /// No border: a small tab at the top left with the label (and the
    /// buttons), the rest of the title's row clear and not in the way of the
    /// pointer.
    Tag,
}

/// Soft by default (2026-09-28): around every window, all day, the zone's
/// colour at full saturation is a lot of colour; the soft tones read as the
/// same zone at a glance (`docs/WINDOW-FRAME.md` §8 «Вид рамки»).
pub const DEFAULT_STYLE: Style = Style::Soft;

impl Style {
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "full" => Some(Self::Full),
            "soft" => Some(Self::Soft),
            "tag" => Some(Self::Tag),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Soft => "soft",
            Self::Tag => "tag",
        }
    }
}

/// A one-word setting and where it comes from, as the title's mode is read:
/// Nix, the local file, `default`. A value `parse` refuses is skipped, as if
/// it were not there.
fn word_setting<T>(
    config: &Path,
    name: &str,
    parse: impl Fn(&str) -> Option<T>,
    default: T,
) -> (T, Source) {
    let declared = crate::declared::setting(&config.join(DECLARED_DIR).join(name));
    if let Some(value) = declared.as_deref().and_then(&parse) {
        return (value, Source::Nix);
    }
    if let Some(value) = read_setting(&config.join(name)).as_deref().and_then(&parse) {
        return (value, Source::Local);
    }
    (default, Source::Default)
}

/// The frame of a window the compositor has fullscreen (the owner,
/// 2026-09-29: settings of its own; by default the border kept, no title
/// strip, and the zone's label for a moment on the way in — a program that
/// takes the whole screen could draw another zone's frame there, and the
/// label says whose it is before it can).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fullscreen {
    /// The border's width; `None` the same as outside fullscreen.
    pub width: Option<i32>,
    pub title: TitleMode,
    /// How long the title strip shows, over the content, once the window
    /// is fullscreen: whole seconds, 0 not at all.
    pub notice: u8,
}

/// Three seconds: long enough to read two words, short of what a film or a
/// game would mind at its top.
pub const DEFAULT_NOTICE: u8 = 3;
/// Longer than this is not a moment any more.
pub const MAX_NOTICE: u8 = 30;
/// The owner's choice (2026-09-29, «Кайма, строки нет»).
pub const DEFAULT_FULLSCREEN: Fullscreen = Fullscreen {
    width: None,
    title: TitleMode::Off,
    notice: DEFAULT_NOTICE,
};

/// A fullscreen width as a setting file or the command line has it: `same`
/// (`None`), or a whole number of logical pixels, 0 to [`MAX_WIDTH`].
pub fn parse_fullscreen_width(text: &str) -> Option<Option<i32>> {
    match text.trim() {
        "same" => Some(None),
        text => whole(text, MAX_WIDTH).map(Some),
    }
}

/// [`parse_fullscreen_width`] back.
pub fn fullscreen_width_word(width: Option<i32>) -> String {
    width.map_or_else(|| "same".to_owned(), |w| w.to_string())
}

/// A notice's seconds: a whole number, 0 to [`MAX_NOTICE`].
pub fn parse_notice(text: &str) -> Option<u8> {
    whole(text.trim(), i32::from(MAX_NOTICE)).and_then(|s| u8::try_from(s).ok())
}

/// How the title strip offers fullscreen (the owner, 2026-09-29: every way,
/// and the choice a setting): the compositor's own — the window takes the
/// screen — and fullscreen inside the window — the program is told it is
/// fullscreen and draws itself so, the window stays where it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FullscreenButton {
    /// One button: a left click the compositor's fullscreen, a right click
    /// the one inside the window.
    One,
    /// Two buttons, one for each.
    Two,
    /// A button for the compositor's; the one inside the window a row of
    /// the ≡'s dropdown.
    Menu,
    /// No button: fullscreen as the program itself asks for it.
    None,
}

pub const DEFAULT_FULLSCREEN_BUTTON: FullscreenButton = FullscreenButton::One;

impl FullscreenButton {
    pub const ALL: [FullscreenButton; 4] = [Self::One, Self::Two, Self::Menu, Self::None];

    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        Self::ALL.into_iter().find(|b| b.as_str() == text)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::One => "one",
            Self::Two => "two",
            Self::Menu => "menu",
            Self::None => "none",
        }
    }
}

/// What a double click on the title strip does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoubleClick {
    /// The window maximized, or back from it: what a desktop's title bar
    /// does.
    Maximize,
    /// Nothing more than two clicks.
    None,
}

pub const DEFAULT_DOUBLE_CLICK: DoubleClick = DoubleClick::Maximize;

impl DoubleClick {
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "maximize" => Some(Self::Maximize),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Maximize => "maximize",
            Self::None => "none",
        }
    }
}

/// The border's width in fullscreen and where it comes from.
pub fn fullscreen_width(config: &Path) -> (Option<i32>, Source) {
    word_setting(
        config,
        FULLSCREEN_WIDTH_SETTING,
        parse_fullscreen_width,
        DEFAULT_FULLSCREEN.width,
    )
}

/// The title strip's mode in fullscreen and where it comes from.
pub fn fullscreen_title(config: &Path) -> (TitleMode, Source) {
    word_setting(
        config,
        FULLSCREEN_TITLE_SETTING,
        TitleMode::parse,
        DEFAULT_FULLSCREEN.title,
    )
}

/// The label's seconds on the way into fullscreen and where they come from.
pub fn fullscreen_notice(config: &Path) -> (u8, Source) {
    word_setting(
        config,
        FULLSCREEN_NOTICE_SETTING,
        parse_notice,
        DEFAULT_FULLSCREEN.notice,
    )
}

/// The frame in fullscreen as the settings have it now.
pub fn fullscreen(config: &Path) -> Fullscreen {
    Fullscreen {
        width: fullscreen_width(config).0,
        title: fullscreen_title(config).0,
        notice: fullscreen_notice(config).0,
    }
}

/// The fullscreen buttons and where they come from.
pub fn fullscreen_button(config: &Path) -> (FullscreenButton, Source) {
    word_setting(
        config,
        FULLSCREEN_BUTTON_SETTING,
        FullscreenButton::parse,
        DEFAULT_FULLSCREEN_BUTTON,
    )
}

/// What a double click on the title does and where that comes from.
pub fn double_click(config: &Path) -> (DoubleClick, Source) {
    word_setting(
        config,
        DOUBLE_CLICK_SETTING,
        DoubleClick::parse,
        DEFAULT_DOUBLE_CLICK,
    )
}

/// The buttons' look and where it comes from.
pub fn buttons(config: &Path) -> (ButtonStyle, Source) {
    word_setting(config, BUTTONS_SETTING, ButtonStyle::parse, DEFAULT_BUTTONS)
}

/// The frame's style and where it comes from.
pub fn style(config: &Path) -> (Style, Source) {
    word_setting(config, STYLE_SETTING, Style::parse, DEFAULT_STYLE)
}

/// A radius inside the frame as a setting file or the command line has it:
/// a whole number of logical pixels, 0 to [`MAX_RADIUS`], or `niri` —
/// `Niri(0)` here, niri's own read by [`radius`].
pub fn parse_radius(text: &str) -> Option<Radius> {
    parse_radius_up_to(text, MAX_RADIUS)
}

/// The frame's own radius, as [`parse_radius`]: 0 to [`MAX_OUTER_RADIUS`],
/// or `niri`.
pub fn parse_outer_radius(text: &str) -> Option<Radius> {
    parse_radius_up_to(text, MAX_OUTER_RADIUS)
}

fn parse_radius_up_to(text: &str, max: i32) -> Option<Radius> {
    match text.trim() {
        "niri" => Some(Radius::Niri(0)),
        text => whole(text, max).map(Radius::Px),
    }
}

/// The radius of the window's corners inside the frame and where it comes
/// from; niri's read now where it is `niri`.
pub fn radius(config: &Path) -> (Radius, Source) {
    let (r, source) = word_setting(config, RADIUS_SETTING, parse_radius, DEFAULT_RADIUS);
    (r.read(), source)
}

/// The radius of the frame's own corners and where it comes from, as
/// [`radius`].
pub fn outer_radius(config: &Path) -> (Radius, Source) {
    let (r, source) = word_setting(
        config,
        OUTER_RADIUS_SETTING,
        parse_outer_radius,
        DEFAULT_OUTER_RADIUS,
    );
    (r.read(), source)
}

/// Whether a character may be drawn in the title: not a control character,
/// and nothing that reorders or hides text (`crate::focus::reorders` — a
/// bidi override would make one zone's name read as another's).
fn drawable(c: &char) -> bool {
    !c.is_control() && !crate::focus::reorders(*c)
}

/// A name for the title strip, fit to be drawn: only [`drawable`]
/// characters, no space at the ends, at most [`MAX_TITLE_PART`] characters
/// (a longer one is cut and ends in `…`).
pub fn title_part(name: &str) -> String {
    let clean: String = name.chars().filter(drawable).collect();
    let text = clean.trim();
    if text.chars().count() <= MAX_TITLE_PART {
        return text.to_owned();
    }
    let cut: String = text.chars().take(MAX_TITLE_PART - 1).collect();
    format!("{}…", cut.trim_end())
}

/// The title strip's text: `<zone> · <container>`, each part cleaned by
/// [`title_part`].
pub fn title_text(zone: &str, container: &str) -> String {
    format!("{} · {}", title_part(zone), title_part(container))
}

/// What came on a command line (`wl-sandbox --frame-title`), cleaned again
/// by the same rules, for the whole: two parts and the dot between.
pub fn clean_title(text: &str) -> String {
    let clean: String = text
        .chars()
        .filter(drawable)
        .take(2 * MAX_TITLE_PART + 3)
        .collect();
    clean.trim().to_owned()
}

/// What `wl-sandbox --frame` carries: the colour, the width and the title's
/// mode, the look — the buttons', the style, the corners' radius inside and
/// outside —, and the frame in fullscreen, the fullscreen buttons and the
/// double click, `rrggbb:w:mode[:buttons:style:radius[:outer[:fullscreen]]]`
/// — the last `width:title:notice:button:double-click`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    pub color: Rgb,
    pub width: i32,
    pub title: TitleMode,
    pub buttons: ButtonStyle,
    pub style: Style,
    pub radius: Radius,
    pub outer: Radius,
    pub fullscreen: Fullscreen,
    pub fullscreen_button: FullscreenButton,
    pub double_click: DoubleClick,
}

impl Frame {
    /// The zone's frame as the settings have it now.
    pub fn of_zone(state: &Path, config: &Path, zone: &str) -> Self {
        Self {
            color: zone_color(state, config, zone).0,
            width: width(config).0,
            title: title_mode(config).0,
            buttons: buttons(config).0,
            style: style(config).0,
            radius: radius(config).0,
            outer: outer_radius(config).0,
            fullscreen: fullscreen(config),
            fullscreen_button: fullscreen_button(config).0,
            double_click: double_click(config).0,
        }
    }

    /// Whether a title strip may ever show: its mode, or in fullscreen its
    /// own mode or the label on the way in.
    pub fn shows_title(&self) -> bool {
        self.title != TitleMode::Off
            || self.fullscreen.title != TitleMode::Off
            || self.fullscreen.notice > 0
    }

    /// A launch's frame: the colour of its container, when it has one of its
    /// own (`docs/PERMISSIONS.md` §11.10) — else the zone's.
    pub fn of_launch(state: &Path, config: &Path, zone: &str, container: Option<&str>) -> Self {
        let mut frame = Self::of_zone(state, config, zone);
        if let Some(color) = container.and_then(Rgb::parse) {
            frame.color = color;
        }
        frame
    }

    /// `rrggbb:w:mode`, and `:buttons:style:radius` after it when one of
    /// them — or anything after them — is not its default, `:outer` after
    /// them when it — or the fullscreen part — is not, and the fullscreen
    /// part, all five, when one of them is not: the launch's line of the
    /// common case stays the one it was before there were looks.
    pub fn to_arg(self) -> String {
        let default = (DEFAULT_BUTTONS, DEFAULT_STYLE, DEFAULT_RADIUS);
        let fullscreen = (self.fullscreen, self.fullscreen_button, self.double_click);
        let tail = if fullscreen
            == (
                DEFAULT_FULLSCREEN,
                DEFAULT_FULLSCREEN_BUTTON,
                DEFAULT_DOUBLE_CLICK,
            ) {
            String::new()
        } else {
            format!(
                ":{}:{}:{}:{}:{}",
                fullscreen_width_word(self.fullscreen.width),
                self.fullscreen.title.as_str(),
                self.fullscreen.notice,
                self.fullscreen_button.as_str(),
                self.double_click.as_str()
            )
        };
        let outer = if self.outer == DEFAULT_OUTER_RADIUS && tail.is_empty() {
            String::new()
        } else {
            format!(":{}{tail}", self.outer.arg())
        };
        let look = if (self.buttons, self.style, self.radius) == default && outer.is_empty() {
            String::new()
        } else {
            format!(
                ":{}:{}:{}{outer}",
                self.buttons.as_str(),
                self.style.as_str(),
                self.radius.arg()
            )
        };
        format!(
            "{}:{}:{}{look}",
            &self.color.hex()[1..],
            self.width,
            self.title.as_str()
        )
    }

    /// `rrggbb:w[:mode[:buttons[:style[:radius[:outer[:fullscreen]]]]]]`,
    /// the fullscreen part `width[:title[:notice[:button[:double-click]]]]`:
    /// what is left out has its default; anything more, or anything that is
    /// not what its place says, is no frame.
    pub fn parse_arg(text: &str) -> Option<Self> {
        let mut parts = text.split(':');
        let color = Rgb::parse(parts.next()?)?;
        let width: i32 = parts.next()?.parse().ok()?;
        if !(0..=MAX_WIDTH).contains(&width) {
            return None;
        }
        let title = match parts.next() {
            None => DEFAULT_TITLE,
            Some(mode) => TitleMode::parse(mode)?,
        };
        let buttons = match parts.next() {
            None => DEFAULT_BUTTONS,
            Some(look) => ButtonStyle::parse(look)?,
        };
        let style = match parts.next() {
            None => DEFAULT_STYLE,
            Some(style) => Style::parse(style)?,
        };
        let radius = match parts.next() {
            None => DEFAULT_RADIUS,
            Some(radius) => Radius::parse_arg(radius, MAX_RADIUS)?,
        };
        let outer = match parts.next() {
            None => DEFAULT_OUTER_RADIUS,
            Some(outer) => Radius::parse_arg(outer, MAX_OUTER_RADIUS)?,
        };
        let mut fullscreen = DEFAULT_FULLSCREEN;
        if let Some(w) = parts.next() {
            fullscreen.width = parse_fullscreen_width(w)?;
        }
        if let Some(mode) = parts.next() {
            fullscreen.title = TitleMode::parse(mode)?;
        }
        if let Some(notice) = parts.next() {
            fullscreen.notice = parse_notice(notice)?;
        }
        let fullscreen_button = match parts.next() {
            None => DEFAULT_FULLSCREEN_BUTTON,
            Some(button) => FullscreenButton::parse(button)?,
        };
        let double_click = match parts.next() {
            None => DEFAULT_DOUBLE_CLICK,
            Some(click) => DoubleClick::parse(click)?,
        };
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            color,
            width,
            title,
            buttons,
            style,
            radius,
            outer,
            fullscreen,
            fullscreen_button,
            double_click,
        })
    }
}

/// Everything the proxy draws a launch's frame with, as `wl-sandbox` is told
/// it: the frame, the title's text (`--frame-title`, cleaned again on the
/// way in) and the directory of the switch that hides every frame
/// (`--frame-switch`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setup {
    pub frame: Frame,
    pub title: String,
    pub switch: PathBuf,
    /// Its windows always think they have the focus (3d of
    /// `docs/PERMISSIONS.md` §11.15, `crate::wl_frame`).
    pub always_focused: bool,
    /// Where its frame comes from, for its supervisor to read it again on
    /// the fly (`--frame-state`, `--frame-zone`, `--frame-container`);
    /// `None`: only the width is read again.
    pub origin: Option<Origin>,
}

/// Where a launch's frame comes from: the zones' state directory (the
/// zone's colour), the zone, and the container whose own colour it has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub state: PathBuf,
    pub zone: String,
    pub container: Option<String>,
}

impl Setup {
    /// The frame as the settings have it now: `config` the settings'
    /// directory (the switch's); the width alone where the origin is not
    /// known.
    pub fn read_again(&self) -> Frame {
        match &self.origin {
            Some(o) => {
                let color = o
                    .container
                    .as_deref()
                    .and_then(|c| crate::container::frame_color_in(&self.switch, c));
                Frame::of_launch(&o.state, &self.switch, &o.zone, color.as_deref())
            }
            None => Frame {
                width: width(&self.switch).0,
                ..self.frame
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn dirs(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("vz-frame-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let (state, config) = (root.join("state"), root.join("config"));
        fs::create_dir_all(state.join("nl")).unwrap();
        fs::create_dir_all(config.join(DECLARED_DIR)).unwrap();
        (state, config)
    }

    #[test]
    fn a_colour_is_six_hex_digits_and_nothing_else() {
        assert_eq!(Rgb::parse("#ff8000"), Some(Rgb(255, 128, 0)));
        assert_eq!(Rgb::parse("00FF7f"), Some(Rgb(0, 255, 127)));
        assert_eq!(Rgb::parse(" #0a0b0c\n"), Some(Rgb(10, 11, 12)));
        for bad in [
            "",
            "#",
            "#fff",
            "#ff80001",
            "#ff80zz",
            "red",
            "#ff8000ff",
            "+1+2+3",
        ] {
            assert_eq!(Rgb::parse(bad), None, "{bad:?}");
        }
        assert_eq!(Rgb(255, 128, 0).hex(), "#ff8000");
        assert_eq!(
            u32::from_ne_bytes(Rgb(0x12, 0x34, 0x56).xrgb8888()),
            0xff12_3456
        );
    }

    #[test]
    fn the_default_colour_comes_from_the_name_and_stays() {
        let a = default_color("nl");
        assert_eq!(a, default_color("nl"), "not the same twice");
        assert_ne!(a, default_color("de"));
        assert_ne!(default_color("work"), default_color("home"));
        // A colour, not a grey, and neither black nor white: 0.65/0.85 in HSV.
        for zone in ["nl", "de", "offline", "work-vpn", "зона"] {
            let Rgb(r, g, b) = default_color(zone);
            let (max, min) = (r.max(g).max(b), r.min(g).min(b));
            assert_eq!(max, 217, "{zone}: {r} {g} {b}");
            assert!(max - min > 120, "{zone}: {r} {g} {b}");
        }
    }

    #[test]
    fn nix_wins_over_the_zone_file_which_wins_over_the_default() {
        let (state, config) = dirs("color");
        assert_eq!(
            zone_color(&state, &config, "nl"),
            (default_color("nl"), Source::Default)
        );
        fs::write(state.join("nl").join(COLOR_FILE), "#102030").unwrap();
        assert_eq!(
            zone_color(&state, &config, "nl"),
            (Rgb(0x10, 0x20, 0x30), Source::Local)
        );
        crate::declared::declare(
            &config.join(DECLARED_DIR).join(DECLARED_COLORS),
            "de #ffffff\nnl #ff0000\nnl2 #00ff00\n",
        );
        assert_eq!(
            zone_color(&state, &config, "nl"),
            (Rgb(255, 0, 0), Source::Nix)
        );
        // Another zone's line is not this one's, nor is a broken one.
        crate::declared::declare(
            &config.join(DECLARED_DIR).join(DECLARED_COLORS),
            "nl2 #00ff00\nnl nonsense\n",
        );
        assert_eq!(
            zone_color(&state, &config, "nl"),
            (Rgb(0x10, 0x20, 0x30), Source::Local)
        );
        fs::write(state.join("nl").join(COLOR_FILE), "blue").unwrap();
        assert_eq!(zone_color(&state, &config, "nl").1, Source::Default);
        let _ = fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn the_width_is_a_small_whole_number_and_the_switch_hides_on_hidden_only() {
        let (state, config) = dirs("width");
        assert_eq!(width(&config), (DEFAULT_WIDTH, Source::Default));
        fs::write(config.join(WIDTH_SETTING), "7").unwrap();
        assert_eq!(width(&config), (7, Source::Local));
        crate::declared::declare(&config.join(DECLARED_DIR).join(WIDTH_SETTING), "2\n");
        assert_eq!(width(&config), (2, Source::Nix));
        for bad in ["-3", "33", "wide", ""] {
            crate::declared::declare(&config.join(DECLARED_DIR).join(WIDTH_SETTING), bad);
            assert_eq!(width(&config), (7, Source::Local), "{bad:?}");
        }
        // No border at all: the title strip alone, where it is on.
        crate::declared::declare(&config.join(DECLARED_DIR).join(WIDTH_SETTING), "0");
        assert_eq!(width(&config), (0, Source::Nix));
        assert!(!hidden(&config));
        fs::write(config.join(SWITCH_SETTING), "shown").unwrap();
        assert!(!hidden(&config));
        fs::write(config.join(SWITCH_SETTING), "hidden\n").unwrap();
        assert!(hidden(&config));
        fs::write(config.join(SWITCH_SETTING), "hide").unwrap();
        assert!(!hidden(&config), "only `hidden` hides");
        // No directory given is none, not the working directory.
        assert!(!hidden(Path::new("")));
        let _ = fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn the_argument_goes_there_and_back() {
        let f = Frame {
            color: Rgb(1, 2, 255),
            width: 6,
            title: TitleMode::Hover,
            buttons: DEFAULT_BUTTONS,
            style: DEFAULT_STYLE,
            radius: DEFAULT_RADIUS,
            outer: DEFAULT_OUTER_RADIUS,
            fullscreen: DEFAULT_FULLSCREEN,
            fullscreen_button: DEFAULT_FULLSCREEN_BUTTON,
            double_click: DEFAULT_DOUBLE_CLICK,
        };
        assert_eq!(f.to_arg(), "0102ff:6:hover");
        assert_eq!(Frame::parse_arg(&f.to_arg()), Some(f));
        assert_eq!(
            Frame::parse_arg("0102ff:6"),
            Some(Frame {
                title: DEFAULT_TITLE,
                ..f
            }),
            "without a mode, the default one"
        );
        assert_eq!(Frame::parse_arg("0102ff:0").map(|f| f.width), Some(0));
        for bad in [
            "0102ff",
            "0102ff:-1",
            "0102ff:99",
            "zz02ff:4",
            ":4",
            "0102ff:x",
            "0102ff:4:sometimes",
            "0102ff:4:off:more",
            "0102ff:4:",
        ] {
            assert_eq!(Frame::parse_arg(bad), None, "{bad:?}");
        }
    }

    /// The look rides in the same argument: said when one part of it is not
    /// the default, all three then; read back part by part, what is left out
    /// its default, nonsense no frame.
    #[test]
    fn the_look_goes_there_and_back_in_the_same_argument() {
        let f = Frame {
            color: Rgb(0xff, 0, 0xff),
            width: 4,
            title: TitleMode::Always,
            buttons: ButtonStyle::Macos,
            style: Style::Tag,
            radius: Radius::Px(12),
            outer: DEFAULT_OUTER_RADIUS,
            fullscreen: DEFAULT_FULLSCREEN,
            fullscreen_button: DEFAULT_FULLSCREEN_BUTTON,
            double_click: DEFAULT_DOUBLE_CLICK,
        };
        assert_eq!(f.to_arg(), "ff00ff:4:always:macos:tag:12");
        assert_eq!(Frame::parse_arg(&f.to_arg()), Some(f));
        // One part away from its default is enough to say all three.
        let full = Frame {
            buttons: DEFAULT_BUTTONS,
            style: Style::Full,
            radius: DEFAULT_RADIUS,
            ..f
        };
        assert_eq!(full.to_arg(), "ff00ff:4:always:cellward:full:0");
        assert_eq!(Frame::parse_arg(&full.to_arg()), Some(full));
        // niri's radius rides as it was read, inside and outside; the outer
        // alone says the look before it.
        let niri = Frame {
            radius: Radius::Niri(20),
            outer: Radius::Niri(20),
            ..f
        };
        assert_eq!(niri.to_arg(), "ff00ff:4:always:macos:tag:niri20:niri20");
        assert_eq!(Frame::parse_arg(&niri.to_arg()), Some(niri));
        let outer = Frame {
            buttons: DEFAULT_BUTTONS,
            style: DEFAULT_STYLE,
            radius: DEFAULT_RADIUS,
            outer: Radius::Px(24),
            ..f
        };
        assert_eq!(outer.to_arg(), "ff00ff:4:always:cellward:soft:0:24");
        assert_eq!(Frame::parse_arg(&outer.to_arg()), Some(outer));
        for look in ButtonStyle::ALL {
            let g = Frame { buttons: look, ..f };
            assert_eq!(Frame::parse_arg(&g.to_arg()), Some(g), "{look:?}");
        }
        // Left out: the default.
        assert_eq!(
            Frame::parse_arg("ff00ff:4:always:kde"),
            Some(Frame {
                buttons: ButtonStyle::Kde,
                style: DEFAULT_STYLE,
                radius: DEFAULT_RADIUS,
                ..f
            })
        );
        assert_eq!(
            Frame::parse_arg("ff00ff:4:always:kde:full").map(|f| (f.style, f.radius)),
            Some((Style::Full, DEFAULT_RADIUS))
        );
        for bad in [
            "ff00ff:4:always:mac",
            "ff00ff:4:always:macos:round",
            "ff00ff:4:always:macos:tag:17",
            "ff00ff:4:always:macos:tag:-1",
            "ff00ff:4:always:macos:tag:3px",
            "ff00ff:4:always:macos:tag:3:4:more",
            "ff00ff:4:always::tag:3",
            "ff00ff:4:always:macos:tag:+3",
            "ff00ff:4:always:macos:tag:niri",
            "ff00ff:4:always:macos:tag:niri33",
            "ff00ff:4:always:macos:tag:niri-1",
            "ff00ff:4:always:macos:tag:3:33",
            "ff00ff:4:always:macos:tag:3:",
        ] {
            assert_eq!(Frame::parse_arg(bad), None, "{bad:?}");
        }
    }

    /// The look's settings: Nix, then the local file, then the default — a
    /// word that is not one of theirs skipped as if it were not there.
    #[test]
    fn the_look_is_nix_then_local_then_the_default() {
        let (state, config) = dirs("look");
        let declared = config.join(DECLARED_DIR);
        assert_eq!(buttons(&config), (ButtonStyle::Cellward, Source::Default));
        assert_eq!(style(&config), (Style::Soft, Source::Default));
        assert_eq!(radius(&config), (Radius::Px(0), Source::Default));
        assert_eq!(outer_radius(&config), (Radius::Px(0), Source::Default));
        fs::write(config.join(BUTTONS_SETTING), "macos\n").unwrap();
        fs::write(config.join(STYLE_SETTING), "tag").unwrap();
        fs::write(config.join(RADIUS_SETTING), "12\n").unwrap();
        assert_eq!(buttons(&config), (ButtonStyle::Macos, Source::Local));
        assert_eq!(style(&config), (Style::Tag, Source::Local));
        assert_eq!(radius(&config), (Radius::Px(12), Source::Local));
        crate::declared::declare(&declared.join(BUTTONS_SETTING), "windows");
        crate::declared::declare(&declared.join(STYLE_SETTING), "full");
        crate::declared::declare(&declared.join(RADIUS_SETTING), "16");
        assert_eq!(buttons(&config), (ButtonStyle::Windows, Source::Nix));
        assert_eq!(style(&config), (Style::Full, Source::Nix));
        assert_eq!(radius(&config), (Radius::Px(16), Source::Nix));
        // Not theirs: as if not there.
        crate::declared::declare(&declared.join(BUTTONS_SETTING), "beos");
        crate::declared::declare(&declared.join(STYLE_SETTING), "glass");
        crate::declared::declare(&declared.join(RADIUS_SETTING), "17");
        assert_eq!(buttons(&config), (ButtonStyle::Macos, Source::Local));
        assert_eq!(style(&config), (Style::Tag, Source::Local));
        assert_eq!(radius(&config), (Radius::Px(12), Source::Local));
        fs::write(config.join(RADIUS_SETTING), "-2").unwrap();
        assert_eq!(radius(&config), (Radius::Px(0), Source::Default));
        // niri's: the word kept, its radius read (none here but the
        // machine's own niri, if any: whatever it is, it is niri's).
        fs::write(config.join(OUTER_RADIUS_SETTING), "niri\n").unwrap();
        assert!(matches!(
            outer_radius(&config),
            (Radius::Niri(_), Source::Local)
        ));
        fs::write(config.join(OUTER_RADIUS_SETTING), "32").unwrap();
        assert_eq!(outer_radius(&config), (Radius::Px(32), Source::Local));
        fs::write(config.join(OUTER_RADIUS_SETTING), "33").unwrap();
        assert_eq!(outer_radius(&config), (Radius::Px(0), Source::Default));
        // Each word back to itself.
        for look in ButtonStyle::ALL {
            assert_eq!(ButtonStyle::parse(look.as_str()), Some(look));
        }
        for s in [Style::Full, Style::Soft, Style::Tag] {
            assert_eq!(Style::parse(&format!(" {}\n", s.as_str())), Some(s));
        }
        assert_eq!(parse_radius(" 0 "), Some(Radius::Px(0)));
        assert_eq!(parse_radius("16"), Some(Radius::Px(16)));
        assert_eq!(parse_radius("17"), None);
        assert_eq!(parse_radius("niri"), Some(Radius::Niri(0)));
        assert_eq!(
            parse_radius("niri20"),
            None,
            "the setting says niri, not its value"
        );
        assert_eq!(parse_outer_radius("32"), Some(Radius::Px(32)));
        for bad in ["1.5", "+3", "", "Niri", "-0"] {
            assert_eq!(parse_radius(bad), None, "{bad:?}");
        }
        assert_eq!(Radius::Niri(20).word(), "niri");
        assert_eq!(Radius::Px(7).word(), "7");
        // And a zone's frame is what they say (the radius's file says -2:
        // the default).
        let frame = Frame::of_zone(&state, &config, "nl");
        assert_eq!(
            (frame.buttons, frame.style, frame.radius, frame.outer),
            (ButtonStyle::Macos, Style::Tag, Radius::Px(0), Radius::Px(0))
        );
        fs::write(config.join(RADIUS_SETTING), "9").unwrap();
        assert_eq!(Frame::of_zone(&state, &config, "nl").radius, Radius::Px(9));
        let _ = fs::remove_dir_all(state.parent().unwrap());
    }

    /// The frame in fullscreen, its buttons and the double click ride at
    /// the end of the same argument: all five said when one is not its
    /// default (and the look and the outer radius before them), read back
    /// part by part, what is left out its default, nonsense no frame.
    #[test]
    fn the_fullscreen_part_goes_there_and_back() {
        let f = Frame::parse_arg("ff00ff:4:always").unwrap();
        assert_eq!(
            (f.fullscreen, f.fullscreen_button, f.double_click),
            (
                DEFAULT_FULLSCREEN,
                DEFAULT_FULLSCREEN_BUTTON,
                DEFAULT_DOUBLE_CLICK
            )
        );
        assert_eq!(f.to_arg(), "ff00ff:4:always", "the common line unchanged");
        let g = Frame {
            fullscreen: Fullscreen {
                width: Some(0),
                title: TitleMode::Hover,
                notice: 0,
            },
            ..f
        };
        assert_eq!(
            g.to_arg(),
            "ff00ff:4:always:cellward:soft:0:0:0:hover:0:one:maximize"
        );
        assert_eq!(Frame::parse_arg(&g.to_arg()), Some(g));
        let h = Frame {
            fullscreen_button: FullscreenButton::Menu,
            double_click: DoubleClick::None,
            ..f
        };
        assert_eq!(
            h.to_arg(),
            "ff00ff:4:always:cellward:soft:0:0:same:off:3:menu:none"
        );
        assert_eq!(Frame::parse_arg(&h.to_arg()), Some(h));
        for button in FullscreenButton::ALL {
            let g = Frame {
                fullscreen_button: button,
                ..f
            };
            assert_eq!(Frame::parse_arg(&g.to_arg()), Some(g), "{button:?}");
        }
        assert_eq!(
            Frame::parse_arg("ff00ff:4:always:cellward:soft:0:0:7").map(|f| f.fullscreen),
            Some(Fullscreen {
                width: Some(7),
                ..DEFAULT_FULLSCREEN
            }),
            "left out: the default"
        );
        for bad in [
            "ff00ff:4:always:cellward:soft:0:0:33",
            "ff00ff:4:always:cellward:soft:0:0:wide",
            "ff00ff:4:always:cellward:soft:0:0:same:never",
            "ff00ff:4:always:cellward:soft:0:0:same:off:31",
            "ff00ff:4:always:cellward:soft:0:0:same:off:-1",
            "ff00ff:4:always:cellward:soft:0:0:same:off:3:three",
            "ff00ff:4:always:cellward:soft:0:0:same:off:3:one:triple",
            "ff00ff:4:always:cellward:soft:0:0:same:off:3:one:none:more",
            "ff00ff:4:always:cellward:soft:0:0:same:off:3:one:none:",
        ] {
            assert_eq!(Frame::parse_arg(bad), None, "{bad:?}");
        }
    }

    /// The fullscreen settings, as the look's: Nix, then the local file,
    /// then the default — a value that is not one of theirs skipped.
    #[test]
    fn the_fullscreen_settings_are_nix_then_local_then_the_default() {
        let (state, config) = dirs("fullscreen");
        let declared = config.join(DECLARED_DIR);
        assert_eq!(
            DEFAULT_FULLSCREEN,
            Fullscreen {
                width: None,
                title: TitleMode::Off,
                notice: 3
            },
            "the owner's: the border kept, no strip, the label"
        );
        assert_eq!(fullscreen(&config), DEFAULT_FULLSCREEN);
        assert_eq!(
            fullscreen_button(&config),
            (FullscreenButton::One, Source::Default)
        );
        assert_eq!(
            double_click(&config),
            (DoubleClick::Maximize, Source::Default)
        );
        fs::write(config.join(FULLSCREEN_WIDTH_SETTING), "0\n").unwrap();
        fs::write(config.join(FULLSCREEN_TITLE_SETTING), "hover").unwrap();
        fs::write(config.join(FULLSCREEN_NOTICE_SETTING), "0").unwrap();
        fs::write(config.join(FULLSCREEN_BUTTON_SETTING), "two").unwrap();
        fs::write(config.join(DOUBLE_CLICK_SETTING), "none\n").unwrap();
        assert_eq!(
            fullscreen(&config),
            Fullscreen {
                width: Some(0),
                title: TitleMode::Hover,
                notice: 0
            }
        );
        assert_eq!(fullscreen_width(&config).1, Source::Local);
        assert_eq!(
            fullscreen_button(&config),
            (FullscreenButton::Two, Source::Local)
        );
        assert_eq!(double_click(&config), (DoubleClick::None, Source::Local));
        crate::declared::declare(&declared.join(FULLSCREEN_WIDTH_SETTING), "same");
        crate::declared::declare(&declared.join(FULLSCREEN_NOTICE_SETTING), "10");
        assert_eq!(fullscreen_width(&config), (None, Source::Nix));
        assert_eq!(fullscreen_notice(&config), (10, Source::Nix));
        // Not theirs: as if not there.
        crate::declared::declare(&declared.join(FULLSCREEN_NOTICE_SETTING), "31");
        assert_eq!(fullscreen_notice(&config), (0, Source::Local));
        fs::write(config.join(FULLSCREEN_TITLE_SETTING), "never").unwrap();
        assert_eq!(fullscreen_title(&config), (TitleMode::Off, Source::Default));
        fs::write(config.join(FULLSCREEN_WIDTH_SETTING), "33").unwrap();
        crate::declared::declare(&declared.join(FULLSCREEN_WIDTH_SETTING), "wide");
        assert_eq!(fullscreen_width(&config), (None, Source::Default));
        for bad in ["", "+3", "1.5", "-1", "Same"] {
            assert_eq!(parse_fullscreen_width(bad), None, "{bad:?}");
            assert_eq!(parse_notice(bad), None, "{bad:?}");
        }
        assert_eq!(parse_fullscreen_width(" same\n"), Some(None));
        assert_eq!(fullscreen_width_word(Some(6)), "6");
        assert_eq!(fullscreen_width_word(None), "same");
        // A zone's frame is what they say.
        let frame = Frame::of_zone(&state, &config, "nl");
        assert_eq!(
            (frame.fullscreen_button, frame.double_click),
            (FullscreenButton::Two, DoubleClick::None)
        );
        // A title strip may show where the mode, fullscreen's own mode or
        // its label wants one.
        let off = Frame {
            title: TitleMode::Off,
            fullscreen: Fullscreen {
                width: None,
                title: TitleMode::Off,
                notice: 0,
            },
            ..frame
        };
        assert!(!off.shows_title());
        let label = Fullscreen {
            notice: 1,
            ..off.fullscreen
        };
        assert!(Frame {
            fullscreen: label,
            ..off
        }
        .shows_title());
        let hover = Fullscreen {
            title: TitleMode::Hover,
            ..off.fullscreen
        };
        assert!(Frame {
            fullscreen: hover,
            ..off
        }
        .shows_title());
        let _ = fs::remove_dir_all(state.parent().unwrap());
    }

    /// HSV there and back: the soft look keeps a colour's hue
    /// (`crate::wl_title::soft_inner`).
    #[test]
    fn a_colour_goes_to_hsv_and_back() {
        for c in [
            Rgb(0xff, 0x00, 0xff),
            Rgb(0x12, 0x34, 0x56),
            Rgb(0xd9, 0x4c, 0x4c),
            Rgb(0x80, 0x80, 0x80),
            Rgb(0, 0, 0),
            Rgb(0xff, 0xff, 0xff),
            default_color("nl"),
            default_color("зона"),
        ] {
            let (h, s, v) = to_hsv(c);
            assert!((0.0..360.0).contains(&h), "{c:?}: {h}");
            assert!((0.0..=1.0).contains(&s) && (0.0..=1.0).contains(&v));
            assert_eq!(hsv(h, s, v), c, "{h} {s} {v}");
        }
        let (h, s, v) = to_hsv(Rgb(0xff, 0x00, 0xff));
        assert!((h - 300.0).abs() < 1e-9 && (s - 1.0).abs() < 1e-9 && (v - 1.0).abs() < 1e-9);
    }

    #[test]
    fn the_title_mode_is_nix_then_local_then_always() {
        let (state, config) = dirs("title");
        assert_eq!(title_mode(&config), (TitleMode::Always, Source::Default));
        fs::write(config.join(TITLE_SETTING), "hover\n").unwrap();
        assert_eq!(title_mode(&config), (TitleMode::Hover, Source::Local));
        crate::declared::declare(&config.join(DECLARED_DIR).join(TITLE_SETTING), "off");
        assert_eq!(title_mode(&config), (TitleMode::Off, Source::Nix));
        crate::declared::declare(&config.join(DECLARED_DIR).join(TITLE_SETTING), "never");
        assert_eq!(
            title_mode(&config),
            (TitleMode::Hover, Source::Local),
            "not a mode: as if it were not there"
        );
        let _ = fs::remove_dir_all(state.parent().unwrap());
    }

    /// The title is there to be read and believed at a glance: what a name
    /// could hide or turn around is not drawn, and nothing is endless.
    #[test]
    fn the_title_text_is_two_clean_bounded_parts() {
        assert_eq!(title_text("nl", "основной"), "nl · основной");
        // Control characters and bidi overrides go: "\u{202E}ln" reads
        // backwards, a line break would start a line of its own.
        assert_eq!(
            title_text("n\u{202E}l\n", "\u{200B}bank\u{2066}"),
            "nl · bank"
        );
        assert_eq!(title_part("  work  "), "work");
        assert_eq!(title_part("\u{7}\u{1b}[31m"), "[31m");
        // Bounded, and cut where a character ends, never inside one.
        let part = title_part(&"й".repeat(100));
        assert_eq!(part.chars().count(), MAX_TITLE_PART);
        assert!(part.ends_with('…'), "{part}");
        let exact = "x".repeat(MAX_TITLE_PART);
        assert_eq!(title_part(&exact), exact, "not cut when it fits");
        // What came on the command line is cleaned again, and bounded.
        assert_eq!(clean_title(" nl\u{202E} · a\r"), "nl · a");
        assert_eq!(
            clean_title(&"z".repeat(1000)).chars().count(),
            2 * MAX_TITLE_PART + 3
        );
    }

    /// A launch's frame is its container's colour when it has one, the
    /// zone's otherwise.
    #[test]
    fn a_launch_is_framed_in_its_containers_colour() {
        let dir = std::env::temp_dir().join(format!("vz-frame-launch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let zone = Frame::of_zone(&dir, &dir, "nl");
        let own = Frame::of_launch(&dir, &dir, "nl", Some("#102030"));
        assert_eq!(own.color, Rgb(0x10, 0x20, 0x30));
        assert_eq!(own.width, zone.width);
        assert_eq!(Frame::of_launch(&dir, &dir, "nl", None).color, zone.color);
        assert_eq!(
            Frame::of_launch(&dir, &dir, "nl", Some("nope")).color,
            zone.color
        );
    }
}
