//! The title strip's text, drawn by the Wayland proxy (`docs/WINDOW-FRAME.md`
//! §5.6, §5.10; stage 2, its second part): `<zone> · <container>` on the
//! zone's colour, as pixels the compositor is handed in `wl_shm`.
//!
//! **The font** is a file of the Nix package, named by its store path when
//! the crate is built (`VPN_ZONE_FRAME_FONT`, `package.nix`): no fontconfig,
//! no lookup of any kind at run time. The supervisor reads it before the
//! proxy is forked, the proxy lays the line out before it loads its filter
//! (`crate::wl_proxy::confine`); what it rasterizes after is only that line,
//! at a new scale. Nothing of it comes from the program: the text is the
//! launch's (`crate::frame::title_text`, cleaned of control and bidi
//! characters), the font is ours, the scale is the compositor's and bounded
//! here.
//!
//! **Crisp at any scale.** The text is rasterized at the scale the compositor
//! prefers for its surface — `wp_fractional_scale_v1` where the compositor
//! offers it to the restricted client, `wl_surface.preferred_buffer_scale`
//! where not — into a buffer of `round(logical × scale)` pixels, which
//! `wp_viewporter` gives its logical size: one device pixel per buffer pixel,
//! nothing for the compositor to resample. The strip under it is the
//! border's stretched pixel; a resize moves and stretches, it never
//! re-rasterizes (§6.3): the text keeps its width, and a window too narrow
//! for it shows its left part (the viewport's source).
//!
//! **Where the pixels live.** One memfd per launch, made and sealed before
//! the filter (the filter has no `memfd_create`), of [`SLOTS`] regions, each
//! big enough for the line at the largest scale: a region holds the line at
//! one scale, and every connection makes its `wl_shm` pool of the same memfd.
//! A region is written (`pwrite`, never mapped here) only while no buffer
//! made of it is held by the compositor: each buffer holds a [`Lease`] until
//! the compositor releases it. Four windows on four outputs of four scales
//! at once use them all; a fifth scale takes the nearest one drawn —
//! blurred, never torn.
//!
//! **The buttons** (stage 3, 2026-09-27): menu, network and close at an end
//! of the strip, drawn with the same font into [`SLOTS`] regions of their own
//! in the same memfd — the filter's one `pwrite64` descriptor writes them
//! too. A region holds the row of buttons at one scale in every state at
//! once ([`ButtonsLook::variants`]: at rest, each one under the pointer,
//! each one pressed), one image under the other: a button lit or pressed is
//! another buffer of the region, not a new raster.
//!
//! **The look** (2026-09-28, §8 «Вид рамки»): how the frame looks is one
//! value, [`Look`], made of the launch's settings (`crate::frame::Frame`):
//! the style — `full`, the zone's colour itself; `soft`, its calmer tones
//! and a border of two ([`soft_inner`], [`soft_outer`]); `tag`, no border and
//! a small tab with the label ([`tag_layout`], [`render_tag`]) —, the
//! buttons' look ([`buttons_look`]: which end, which order, the glyphs, the
//! shape, the colours at rest, under the pointer and pressed) and the radius
//! of the window's corners inside the frame ([`render_corners`], in
//! [`SLOTS`] regions of their own too). The drawing here and the layout and
//! the hit-testing in `crate::wl_frame` follow whatever it says.

#![forbid(unsafe_code)]

use std::cell::{Cell, RefCell};
use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileExt;
use std::rc::Rc;

use ab_glyph::{point, Font, FontVec, GlyphId, PxScale, ScaleFont};

use crate::frame::{ButtonStyle, Frame, Rgb, Style, MAX_RADIUS};

/// The font the package was built with (`package.nix`), if it was.
pub const FONT: Option<&str> = option_env!("VPN_ZONE_FRAME_FONT");
/// A font file larger than this is not the one the package names.
pub const MAX_FONT_BYTES: u64 = 32 << 20;

/// The strip's height, logical pixels: under the border's 4, a top band of
/// 24 — the height §11 (question 2) proposed — and a whole number of pixels
/// at 1.25, 1.5, 1.75 and 2 (25, 30, 35, 40), like the border (§5.6).
pub const HEIGHT: i32 = 20;
/// The text's size: ab_glyph's scale is the font's ascent-to-descent height.
const FONT_PX: f32 = 14.0;
/// Space before the text, logical pixels, and after it when the window is
/// too narrow for the whole of it.
pub const PAD: i32 = 8;
/// The longest line, logical pixels; what does not fit ends in `…`.
const MAX_WIDTH: f32 = 480.0;
/// The scales a line is rasterized at, in 120ths (`wp_fractional_scale_v1`):
/// 1 to 4. Above, the compositor scales the 4× one; below 1, the 1× one.
pub const MIN_SCALE: u32 = 120;
pub const MAX_SCALE: u32 = 480;
/// How many scales are held at once.
pub const SLOTS: usize = 4;

// --- THE LOOK ---------------------------------------------------------------

/// A button of the title strip, by what it does (`crate::wl_frame` acts on
/// it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Button {
    /// The launch's window menu: `cellward window-menu --pid`, which the
    /// supervisor starts.
    Menu,
    /// Another network for the container. For now the program is started
    /// again with the network chosen (`window-menu --restart`); switching it
    /// live, without the restart, is to take this button's place later.
    Network,
    /// The window's own `close`, as a server-side decoration's would be.
    Close,
}

/// A colour of the look, made from the frame's own (the zone's, or the
/// container's; in the soft style its tone, [`Look::title_color`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Paint {
    /// The frame's colour itself.
    Frame,
    /// The frame's colour moved this many percent toward white when it is a
    /// dark one (its text is white, [`ink`]), toward black when it is a light
    /// one: a shade of it that stands out on either.
    Shade(u8),
    /// A colour of its own, whatever the frame's.
    Fixed(Rgb),
}

impl Paint {
    /// The colour on a frame of colour `frame`.
    pub fn on(self, frame: Rgb) -> Rgb {
        match self {
            Self::Frame => frame,
            Self::Fixed(color) => color,
            Self::Shade(percent) => {
                let toward: u8 = if ink(frame) == WHITE { 0xff } else { 0 };
                let share = f32::from(percent.min(100)) / 100.0;
                let mix = |c: u8| {
                    (f32::from(c) + (f32::from(toward) - f32::from(c)) * share).round() as u8
                };
                Rgb(mix(frame.0), mix(frame.1), mix(frame.2))
            }
        }
    }
}

/// How a button is filled with its colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// The whole of its cell, edge to edge: buttons side by side, square-ish
    /// (cellward's 24 × 20) or wide (Windows's 32 × 20).
    Cell,
    /// A disc this many logical pixels across in the middle of its cell, on
    /// the strip's colour: Adwaita's and Breeze's round buttons, macOS's
    /// traffic lights. The whole cell is the button all the same (the
    /// pointer hits cells, [`ButtonsLook::at`]): beside the disc is not the
    /// title yet.
    Circle(i32),
}

/// When a button's glyph shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Glyphs {
    Always,
    /// While the pointer is on one of the buttons — on every one of them
    /// then: macOS's traffic lights, plain discs until the pointer comes.
    Lit,
}

/// Which end of the title strip the buttons are at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    Left,
    Right,
}

/// One button's look: what it does, its glyph, and its colour at rest,
/// under the pointer and pressed. The glyph's colour is whichever of
/// near-black and white reads better on that ([`ink`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ButtonLook {
    pub button: Button,
    pub glyph: char,
    pub rest: Paint,
    pub hover: Paint,
    pub press: Paint,
}

/// The buttons' look.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ButtonsLook {
    pub end: End,
    /// The buttons from left to right.
    pub order: &'static [ButtonLook],
    /// One button's width, logical pixels: a whole number of pixels at the
    /// usual scales (1.25, 1.5, 1.75, 2) — a multiple of 4 —, like the
    /// strip's height.
    pub width: i32,
    /// The glyphs' size (ab_glyph's scale, as the text's [`FONT_PX`]).
    pub size: f32,
    pub shape: Shape,
    /// The strip between the row and its end, logical pixels: still the
    /// title, to drag the window by.
    pub margin: i32,
    pub glyphs: Glyphs,
}

/// Which button is lit, and whether it is pressed or only under the pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lit {
    pub button: Button,
    pub pressed: bool,
}

impl ButtonsLook {
    /// The row's width, logical pixels.
    pub fn width_all(&self) -> i32 {
        self.width
            .saturating_mul(i32::try_from(self.order.len()).unwrap_or(0))
    }

    /// The button at (`x`, `y`) logical pixels from the row's top left, if
    /// any: a cell each, in the look's order.
    pub fn at(&self, x: f64, y: f64) -> Option<Button> {
        if !(0.0..f64::from(HEIGHT)).contains(&y) || x < 0.0 || self.width <= 0 {
            return None;
        }
        let cell = (x / f64::from(self.width)).floor() as usize;
        self.order.get(cell).map(|b| b.button)
    }

    /// How many images of the row a region holds: at rest, each button under
    /// the pointer, each one pressed.
    pub fn variants(&self) -> usize {
        1 + 2 * self.order.len()
    }

    /// The image of the row with `lit` lit: 0 at rest, then each button
    /// under the pointer in the look's order, then each one pressed.
    pub fn variant(&self, lit: Option<Lit>) -> usize {
        let Some(lit) = lit else {
            return 0;
        };
        match self.order.iter().position(|b| b.button == lit.button) {
            Some(at) if lit.pressed => 1 + self.order.len() + at,
            Some(at) => 1 + at,
            None => 0,
        }
    }

    /// Whether the glyphs show in the image `variant`.
    pub fn glyphs_in(&self, variant: usize) -> bool {
        match self.glyphs {
            Glyphs::Always => true,
            Glyphs::Lit => variant != 0,
        }
    }

    /// The paint of each button in the image `variant`.
    fn paints(&self, variant: usize) -> Vec<Paint> {
        let n = self.order.len();
        self.order
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if variant == 1 + i {
                    b.hover
                } else if variant == 1 + n + i {
                    b.press
                } else {
                    b.rest
                }
            })
            .collect()
    }
}

/// How a buffer of the frame keeps its pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pixels {
    /// XRGB8888, opaque: nothing of what lies under a part of the frame
    /// shows through it — the program's CSD shadow, or a strip it drew there
    /// itself (`docs/WINDOW-FRAME.md` §5.9). The border, the title strip,
    /// its text and its buttons.
    Opaque,
    /// ARGB8888, premultiplied (as `wl_shm` has it): see-through where it is
    /// clear, and so what lies under shows — the tag's round corners and the
    /// clear rest of its row, the window's round corners. §5.9's price, paid
    /// only where a look asks for it: the frame is not a trust boundary.
    Alpha,
}

/// One pixel of the pixel memfd's squares (`crate::wl_proxy::pixels`): a
/// colour, opaque, or nothing at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Square {
    Color(Rgb),
    Clear,
}

impl Square {
    /// The pixel, as the memfd holds it (native-endian).
    pub fn word(self) -> [u8; 4] {
        match self {
            Self::Color(color) => color.xrgb8888(),
            Self::Clear => [0; 4],
        }
    }

    pub fn pixels(self) -> Pixels {
        match self {
            Self::Color(_) => Pixels::Opaque,
            Self::Clear => Pixels::Alpha,
        }
    }
}

/// A pixel of `color` covering `alpha` (0 to 1) of it, ARGB8888: the colour
/// premultiplied by the alpha, as `wl_shm` (and every compositor) reads it —
/// a straight one would come out brighter than it is at the edges.
pub fn premultiplied(color: Rgb, alpha: f32) -> [u8; 4] {
    let a = alpha.clamp(0.0, 1.0);
    let byte = |c: u8| (f32::from(c) * a).round() as u32;
    let word = (((a * 255.0).round() as u32) << 24)
        | (byte(color.0) << 16)
        | (byte(color.1) << 8)
        | byte(color.2);
    word.to_ne_bytes()
}

/// How the frame looks (the owner, 2026-09-27: GNOME's buttons, KDE's,
/// macOS's traffic lights at the left end and Windows's, all equal; a softer
/// frame that does not strain the eyes; a tag, «бирка», instead of a frame;
/// windows round inside it). One value, the launch's ([`Look::of`]): the
/// drawing, the layout and the hit-testing follow it — a clear part of the
/// look does not take the pointer, nor start a move.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Look {
    /// `full`, `soft` or `tag` (`crate::frame::Style`): the colours
    /// ([`Look::squares`], [`Look::title_color`]), the border's rings
    /// ([`Look::rings`]), and whether the title is a strip or a tag.
    pub style: Style,
    pub buttons: ButtonsLook,
    /// The window's corners inside the frame, logical pixels: 0 square
    /// ([`Look::corners`]).
    pub radius: i32,
}

/// Red under the pointer for "close", as desktops have it (Adwaita's
/// `red_3`); a deeper red pressed (its `red_5`).
const CLOSE_HOVER: Rgb = Rgb(0xe0, 0x1b, 0x24);
const CLOSE_PRESS: Rgb = Rgb(0xa5, 0x1d, 0x2d);
/// Breeze's "negative" red, and deeper.
const BREEZE_RED: Rgb = Rgb(0xda, 0x44, 0x53);
const BREEZE_RED_PRESS: Rgb = Rgb(0xa8, 0x33, 0x40);
/// macOS's traffic lights, and each one deeper, pressed.
const MAC_RED: Rgb = Rgb(0xff, 0x5f, 0x57);
const MAC_RED_PRESS: Rgb = Rgb(0xbf, 0x47, 0x41);
const MAC_YELLOW: Rgb = Rgb(0xfe, 0xbc, 0x2e);
const MAC_YELLOW_PRESS: Rgb = Rgb(0xbe, 0x8d, 0x22);
const MAC_GREEN: Rgb = Rgb(0x28, 0xc8, 0x40);
const MAC_GREEN_PRESS: Rgb = Rgb(0x1e, 0x96, 0x30);
/// Windows 11's close under the pointer, and deeper.
const WIN_RED: Rgb = Rgb(0xc4, 0x2b, 0x1c);
const WIN_RED_PRESS: Rgb = Rgb(0x9b, 0x22, 0x16);

/// A button of the look: what it does, its glyph, its three paints.
const fn button(
    button: Button,
    glyph: char,
    rest: Paint,
    hover: Paint,
    press: Paint,
) -> ButtonLook {
    ButtonLook {
        button,
        glyph,
        rest,
        hover,
        press,
    }
}

/// Stage 3's buttons (`cellward`): square cells at the right end — menu,
/// network, close —, the frame's colour at rest, a shade of it under the
/// pointer and a stronger one pressed; close red. 24 wide: 30, 36, 42, 48
/// pixels at the usual scales.
pub const CELLWARD: ButtonsLook = ButtonsLook {
    end: End::Right,
    order: &[
        button(
            Button::Menu,
            '≡',
            Paint::Frame,
            Paint::Shade(22),
            Paint::Shade(38),
        ),
        button(
            Button::Network,
            '⇄',
            Paint::Frame,
            Paint::Shade(22),
            Paint::Shade(38),
        ),
        button(
            Button::Close,
            '×',
            Paint::Frame,
            Paint::Fixed(CLOSE_HOVER),
            Paint::Fixed(CLOSE_PRESS),
        ),
    ],
    width: 24,
    size: 16.0,
    shape: Shape::Cell,
    margin: 0,
    glyphs: Glyphs::Always,
};

/// GNOME's (Adwaita's window controls): round buttons at the right end, each
/// glyph on a faint disc of a shade of the strip, a stronger one under the
/// pointer and pressed; close red under the pointer.
pub const GNOME: ButtonsLook = ButtonsLook {
    end: End::Right,
    order: &[
        button(
            Button::Menu,
            '≡',
            Paint::Shade(10),
            Paint::Shade(20),
            Paint::Shade(32),
        ),
        button(
            Button::Network,
            '⇄',
            Paint::Shade(10),
            Paint::Shade(20),
            Paint::Shade(32),
        ),
        button(
            Button::Close,
            '×',
            Paint::Shade(10),
            Paint::Fixed(CLOSE_HOVER),
            Paint::Fixed(CLOSE_PRESS),
        ),
    ],
    width: 24,
    size: 13.0,
    shape: Shape::Circle(16),
    margin: 4,
    glyphs: Glyphs::Always,
};

/// KDE's (Breeze's decoration): glyphs alone on the strip at rest; under the
/// pointer a disc of the text's own colour with the glyph turned over on it,
/// pressed a lighter one; close a red disc.
pub const KDE: ButtonsLook = ButtonsLook {
    end: End::Right,
    order: &[
        button(
            Button::Menu,
            '≡',
            Paint::Frame,
            Paint::Shade(82),
            Paint::Shade(60),
        ),
        button(
            Button::Network,
            '⇄',
            Paint::Frame,
            Paint::Shade(82),
            Paint::Shade(60),
        ),
        button(
            Button::Close,
            '×',
            Paint::Frame,
            Paint::Fixed(BREEZE_RED),
            Paint::Fixed(BREEZE_RED_PRESS),
        ),
    ],
    width: 24,
    size: 13.0,
    shape: Shape::Circle(18),
    margin: 4,
    glyphs: Glyphs::Always,
};

/// macOS's traffic lights at the LEFT end: close red, then the menu yellow,
/// then the network green, small discs whose glyphs show while the pointer
/// is on one of them; pressed, deeper. Close is red under the pointer as it
/// is at rest.
pub const MACOS: ButtonsLook = ButtonsLook {
    end: End::Left,
    order: &[
        button(
            Button::Close,
            '×',
            Paint::Fixed(MAC_RED),
            Paint::Fixed(MAC_RED),
            Paint::Fixed(MAC_RED_PRESS),
        ),
        button(
            Button::Menu,
            '≡',
            Paint::Fixed(MAC_YELLOW),
            Paint::Fixed(MAC_YELLOW),
            Paint::Fixed(MAC_YELLOW_PRESS),
        ),
        button(
            Button::Network,
            '⇄',
            Paint::Fixed(MAC_GREEN),
            Paint::Fixed(MAC_GREEN),
            Paint::Fixed(MAC_GREEN_PRESS),
        ),
    ],
    width: 20,
    size: 10.0,
    shape: Shape::Circle(12),
    margin: 4,
    glyphs: Glyphs::Lit,
};

/// Windows's caption buttons: wide rectangles at the right end, a faint
/// shade under the pointer, close red.
pub const WINDOWS: ButtonsLook = ButtonsLook {
    end: End::Right,
    order: &[
        button(
            Button::Menu,
            '≡',
            Paint::Frame,
            Paint::Shade(14),
            Paint::Shade(26),
        ),
        button(
            Button::Network,
            '⇄',
            Paint::Frame,
            Paint::Shade(14),
            Paint::Shade(26),
        ),
        button(
            Button::Close,
            '×',
            Paint::Frame,
            Paint::Fixed(WIN_RED),
            Paint::Fixed(WIN_RED_PRESS),
        ),
    ],
    width: 32,
    size: 12.0,
    shape: Shape::Cell,
    margin: 0,
    glyphs: Glyphs::Always,
};

/// No buttons: an empty row, laid nowhere.
pub const NO_BUTTONS: ButtonsLook = ButtonsLook {
    end: End::Right,
    order: &[],
    width: 24,
    size: 16.0,
    shape: Shape::Cell,
    margin: 0,
    glyphs: Glyphs::Always,
};

/// The buttons' look a setting names.
pub fn buttons_look(style: ButtonStyle) -> ButtonsLook {
    match style {
        ButtonStyle::Cellward => CELLWARD,
        ButtonStyle::Gnome => GNOME,
        ButtonStyle::Kde => KDE,
        ButtonStyle::Macos => MACOS,
        ButtonStyle::Windows => WINDOWS,
        ButtonStyle::None => NO_BUTTONS,
    }
}

/// Stage 3's look, `full` with `cellward`'s buttons and square corners: the
/// one the proxy's wire tests and the VM's old pixel checks are of.
pub const LOOK: Look = Look {
    style: Style::Full,
    buttons: CELLWARD,
    radius: 0,
};

/// The soft style's tone of the title strip, the tag-less border's inner
/// ring and the round corners: the frame's colour with its hue kept, its
/// saturation to 62 % and its brightness to 94 %. The default colours
/// (`crate::frame::default_color`: saturation 0.65, brightness 0.85) come to
/// 0.40 and 0.80 — the same zone at a glance, a calmer patch to have in view
/// all day.
pub fn soft_inner(frame: Rgb) -> Rgb {
    tone(frame, 0.62, 0.94)
}

/// The soft style's outer ring: less saturated and darker still (45 %,
/// 80 %), so that the border fades toward whatever is around the window
/// instead of ending in a hard edge of colour.
pub fn soft_outer(frame: Rgb) -> Rgb {
    tone(frame, 0.45, 0.80)
}

fn tone(frame: Rgb, saturation: f64, value: f64) -> Rgb {
    let (h, s, v) = crate::frame::to_hsv(frame);
    crate::frame::hsv(h, s * saturation, v * value)
}

impl Look {
    /// The launch's look, as its settings have it.
    pub fn of(frame: &Frame) -> Self {
        Self {
            style: frame.style,
            buttons: buttons_look(frame.buttons),
            radius: frame.radius.clamp(0, MAX_RADIUS),
        }
    }

    /// The tag instead of a frame: no border, a tab with the label.
    pub fn tag(&self) -> bool {
        self.style == Style::Tag
    }

    /// The radius of the round corners drawn over the window's: none in the
    /// tag look — they are the border's colour laid over the program's
    /// corners, and without a border there is nothing for them to blend into.
    pub fn corners(&self) -> i32 {
        if self.tag() {
            0
        } else {
            self.radius.clamp(0, MAX_RADIUS)
        }
    }

    /// The title strip's colour (the tag's, the buttons' [`Paint::Frame`],
    /// the round corners'), on a frame of colour `frame`.
    pub fn title_color(&self, frame: Rgb) -> Rgb {
        match self.style {
            Style::Soft => soft_inner(frame),
            Style::Full | Style::Tag => frame,
        }
    }

    /// The squares of the pixel memfd, in order: the title's colour first —
    /// `full`'s one square is stage 2's pixel, byte for byte —, then the
    /// soft border's outer tone, or the tag's clear row.
    pub fn squares(&self, frame: Rgb) -> Vec<Square> {
        match self.style {
            Style::Full => vec![Square::Color(frame)],
            Style::Soft => vec![
                Square::Color(soft_inner(frame)),
                Square::Color(soft_outer(frame)),
            ],
            Style::Tag => vec![Square::Color(frame), Square::Clear],
        }
    }

    /// The border of `width` as rings, from the outside in: each one's
    /// width and the square it shows. `soft`: the outer tone over the outer
    /// half, the title's tone inside it — two rings nested one in the other
    /// meet at every corner on its diagonal, as a gradient across the width
    /// would, which a strip of one stretched pixel cannot. `tag`: none.
    pub fn rings(&self, width: i32) -> Vec<(i32, usize)> {
        let width = width.max(0);
        match self.style {
            Style::Full => vec![(width, 0)],
            Style::Soft if width >= 2 => vec![(width / 2, 1), (width - width / 2, 0)],
            Style::Soft => vec![(width, 0)],
            Style::Tag => Vec::new(),
        }
    }

    /// The square the title strip shows: its colour; the clear one in the
    /// tag look with its tag drawn (the tag is the text's image,
    /// [`render_tag`]) — without a font to draw it, the strip of the colour.
    pub fn title_square(&self, tag_drawn: bool) -> usize {
        if self.tag() && tag_drawn {
            1
        } else {
            0
        }
    }
}

/// The tag's top corners, logical pixels: a tab, not a box.
pub const TAG_ROUND: i32 = 6;

/// Where things are on the tag, logical pixels from its left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagLayout {
    /// The tag's width.
    pub width: i32,
    /// Where its text begins.
    pub text_x: i32,
    /// Where its buttons begin; `None` without buttons.
    pub buttons: Option<i32>,
}

/// The tag of a line `text` wide with the buttons of `look`: the line
/// between its pads and the row at the look's end of it, clear of the round
/// corners ([`TAG_ROUND`]) — the row's cells are square, and would square
/// the tab's corner off.
pub fn tag_layout(text: i32, look: &ButtonsLook) -> TagLayout {
    let text = text.max(0);
    let row = look.width_all();
    let label = PAD.saturating_add(text).saturating_add(PAD);
    if row <= 0 {
        return TagLayout {
            width: label,
            text_x: PAD,
            buttons: None,
        };
    }
    let end = look.margin.max(TAG_ROUND);
    match look.end {
        End::Right => TagLayout {
            width: label.saturating_add(row).saturating_add(end),
            text_x: PAD,
            buttons: Some(label),
        },
        End::Left => TagLayout {
            width: end.saturating_add(row).saturating_add(label),
            text_x: end.saturating_add(row).saturating_add(PAD),
            buttons: Some(end),
        },
    }
}

/// The line laid out at scale 1: each glyph and its pen position.
pub struct Line {
    glyphs: Vec<(GlyphId, f32)>,
    /// Logical pixels, rounded up.
    pub width: i32,
}

/// How many of `advances` fit into `max`: all when they do; else as many as
/// fit with `ellipsis` after them (then `true`).
pub fn fit(advances: &[f32], ellipsis: f32, max: f32) -> (usize, bool) {
    let total: f32 = advances.iter().sum();
    if total <= max {
        return (advances.len(), false);
    }
    let mut pen = 0.0;
    let mut kept = 0;
    for a in advances {
        if pen + a + ellipsis > max {
            break;
        }
        pen += a;
        kept += 1;
    }
    (kept, true)
}

/// Lay `text` out in `font` at scale 1: kerned, cut to [`MAX_WIDTH`].
pub fn lay_out(font: &FontVec, text: &str) -> Line {
    let scaled = font.as_scaled(PxScale::from(FONT_PX));
    let ids: Vec<GlyphId> = text.chars().map(|c| font.glyph_id(c)).collect();
    let advances: Vec<f32> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            let kern = ids.get(i + 1).map_or(0.0, |next| scaled.kern(*id, *next));
            scaled.h_advance(*id) + kern
        })
        .collect();
    let dots = font.glyph_id('…');
    let (kept, cut) = fit(&advances, scaled.h_advance(dots), MAX_WIDTH);
    let mut glyphs = Vec::with_capacity(kept + 1);
    let mut pen = 0.0;
    for (id, advance) in ids.iter().zip(&advances).take(kept) {
        glyphs.push((*id, pen));
        pen += advance;
    }
    if cut {
        glyphs.push((dots, pen));
        pen += scaled.h_advance(dots);
    }
    Line {
        glyphs,
        width: pen.ceil().max(0.0) as i32,
    }
}

/// A scale as the proxy uses it: 120ths, within [`MIN_SCALE`]..=[`MAX_SCALE`].
pub fn clamp_scale(scale: u32) -> u32 {
    scale.clamp(MIN_SCALE, MAX_SCALE)
}

/// `logical` pixels at `scale` (120ths), in device pixels: rounded, as
/// `wp_fractional_scale_v1` asks a buffer to be.
pub fn device(logical: i32, scale: u32) -> i32 {
    let scale = i64::from(clamp_scale(scale));
    ((i64::from(logical.max(0)) * scale + 60) / 120) as i32
}

/// The text's colour on `bg`: near-black or white, whichever stands out
/// more (the contrast ratio of WCAG: relative luminance, sRGB decoded).
pub fn ink(bg: Rgb) -> Rgb {
    let linear = |c: u8| {
        let c = f64::from(c) / 255.0;
        if c <= 0.04045 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    let Rgb(r, g, b) = bg;
    let l = 0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b);
    // Against white (1.0) and against black (0.0).
    if 1.05 / (l + 0.05) >= (l + 0.05) / 0.05 {
        WHITE
    } else {
        NEAR_BLACK
    }
}

/// The two colours of text, [`ink`]'s.
const WHITE: Rgb = Rgb(0xff, 0xff, 0xff);
const NEAR_BLACK: Rgb = Rgb(0x14, 0x14, 0x14);

/// A blend of `bg` toward `fg` by the share `c` (0 to 1) of a pixel a glyph
/// covers.
fn blend(bg: Rgb, fg: Rgb, c: f32) -> Rgb {
    let mix =
        |b: u8, f: u8, c: f32| (f32::from(b) + (f32::from(f) - f32::from(b)) * c).round() as u8;
    Rgb(mix(bg.0, fg.0, c), mix(bg.1, fg.1, c), mix(bg.2, fg.2, c))
}

/// How much of the glyphs of `line` at `scale` covers each pixel of an image
/// `w` × `h`, the line's pen starting `x0` device pixels in; its box
/// (ascent to descent) in the middle of the strip, on a whole pixel.
fn line_coverage(font: &FontVec, line: &Line, scale: u32, w: i32, h: i32, x0: f32) -> Vec<f32> {
    let s = clamp_scale(scale) as f32 / 120.0;
    let (wu, hu) = (w.max(0) as usize, h.max(0) as usize);
    let mut coverage = vec![0f32; wu * hu];
    let px = PxScale::from(FONT_PX * s);
    let scaled = font.as_scaled(px);
    let baseline =
        ((h as f32 - (scaled.ascent() - scaled.descent())) / 2.0 + scaled.ascent()).round();
    for (id, x) in &line.glyphs {
        let glyph = id.with_scale_and_position(px, point(x0 + x * s, baseline));
        let Some(outline) = font.outline_glyph(glyph) else {
            continue;
        };
        let bounds = outline.px_bounds();
        let (left, top) = (bounds.min.x as i64, bounds.min.y as i64);
        outline.draw(|gx, gy, c| {
            let (x, y) = (left + i64::from(gx), top + i64::from(gy));
            if (0..w as i64).contains(&x) && (0..h as i64).contains(&y) {
                let at = y as usize * wu + x as usize;
                coverage[at] = (coverage[at] + c).min(1.0);
            }
        });
    }
    coverage
}

/// The line at `scale`: its size in device pixels and XRGB8888 pixels
/// (native-endian words), `ink` on `bg`, opaque — like the border, nothing of
/// what lies under the strip shows through (§5.9).
pub fn render(font: &FontVec, line: &Line, scale: u32, bg: Rgb) -> (i32, i32, Vec<u8>) {
    let scale = clamp_scale(scale);
    let (w, h) = (device(line.width, scale), device(HEIGHT, scale));
    let coverage = line_coverage(font, line, scale, w, h, 0.0);
    let fg = ink(bg);
    let mut pixels = Vec::with_capacity(coverage.len() * 4);
    for c in coverage {
        pixels.extend_from_slice(&blend(bg, fg, c).xrgb8888());
    }
    (w, h, pixels)
}

/// How much of the pixel (`x`, `y`) of an image `w` wide is inside it with
/// its top corners rounded by `r` device pixels: 1 but near those corners.
fn tab_alpha(x: i32, y: i32, w: i32, r: f32) -> f32 {
    let (px, py) = (x as f32 + 0.5, y as f32 + 0.5);
    if py >= r {
        return 1.0;
    }
    let cx = if px < r {
        r
    } else if px > w as f32 - r {
        w as f32 - r
    } else {
        return 1.0;
    };
    let d = ((px - cx).powi(2) + (py - r).powi(2)).sqrt();
    (r - d + 0.5).clamp(0.0, 1.0)
}

/// The tag at `scale` ([`Look::tag`], [`tag_layout`]): the line on `bg`
/// between its pads, room for the buttons (their own surface lies over it),
/// the top corners round ([`TAG_ROUND`]) and clear outside them —
/// ARGB8888, premultiplied. Its size in device pixels, and the pixels.
pub fn render_tag(
    font: &FontVec,
    line: &Line,
    look: &ButtonsLook,
    scale: u32,
    bg: Rgb,
) -> (i32, i32, Vec<u8>) {
    let scale = clamp_scale(scale);
    let tag = tag_layout(line.width, look);
    let (w, h) = (device(tag.width, scale), device(HEIGHT, scale));
    let coverage = line_coverage(font, line, scale, w, h, device(tag.text_x, scale) as f32);
    let fg = ink(bg);
    let r = TAG_ROUND as f32 * scale as f32 / 120.0;
    let mut pixels = Vec::with_capacity(coverage.len() * 4);
    let mut covered = coverage.into_iter();
    for y in 0..h {
        for x in 0..w {
            let c = covered.next().unwrap_or(0.0);
            pixels.extend_from_slice(&premultiplied(blend(bg, fg, c), tab_alpha(x, y, w, r)));
        }
    }
    (w, h, pixels)
}

/// The window's round corners at `scale` ([`Look::corners`]): four images of
/// `radius` logical pixels square — the top left, the top right, the bottom
/// left, the bottom right corner of the window —, `color` where the
/// window's corner is cut off and clear inside the quarter circle, whose
/// edge is smoothed over a device pixel. ARGB8888, premultiplied. The side
/// of one image in device pixels, and the pixels of all four one after the
/// other.
pub fn render_corners(radius: i32, scale: u32, color: Rgb) -> (i32, i32, Vec<u8>) {
    let d = device(radius, scale);
    let r = d as f32;
    let side = d.max(0) as usize;
    let mut pixels = Vec::with_capacity(4 * side * side * 4);
    for (right, bottom) in [(false, false), (true, false), (false, true), (true, true)] {
        // The circle's centre: the corner of the image nearest the window's
        // middle.
        let (cx, cy) = (if right { 0.0 } else { r }, if bottom { 0.0 } else { r });
        for y in 0..d {
            for x in 0..d {
                let (px, py) = (x as f32 + 0.5, y as f32 + 0.5);
                let dist = ((px - cx).powi(2) + (py - cy).powi(2)).sqrt();
                pixels.extend_from_slice(&premultiplied(color, (dist - r + 0.5).clamp(0.0, 1.0)));
            }
        }
    }
    (d, d, pixels)
}

/// The row of buttons at `scale` as `look` has it, on the frame's colour
/// `frame`: the size of one image in device pixels and XRGB8888 pixels of
/// every image one under the other ([`ButtonsLook::variants`]). `glyphs`:
/// each button's glyph in `font`, in the look's order. A glyph is centred
/// in its cell on a whole pixel, so that it is as crisp as the text; a disc
/// ([`Shape::Circle`]) in the middle of its cell, its edge smoothed over a
/// device pixel into the strip's colour.
pub fn render_buttons(
    font: &FontVec,
    glyphs: &[GlyphId],
    look: &ButtonsLook,
    scale: u32,
    frame: Rgb,
) -> (i32, i32, Vec<u8>) {
    let scale = clamp_scale(scale);
    let s = scale as f32 / 120.0;
    let n = look.order.len();
    let (w, h) = (device(look.width_all(), scale), device(HEIGHT, scale));
    let (wu, hu) = (w.max(0) as usize, h.max(0) as usize);
    // Where each cell starts, in device pixels (the last entry: the end).
    let edges: Vec<i32> = (0..=n)
        .map(|i| device(look.width.saturating_mul(i as i32), scale))
        .collect();
    let cell_of: Vec<usize> = (0..w)
        .map(|x| {
            (0..n)
                .find(|&i| x >= edges[i] && x < edges[i + 1])
                .unwrap_or(0)
        })
        .collect();
    // The glyphs' coverage, the same in every image.
    let mut coverage = vec![0f32; wu * hu];
    let px = PxScale::from(look.size * s);
    for (i, id) in glyphs.iter().enumerate().take(n) {
        let (x0, x1) = (i64::from(edges[i]), i64::from(edges[i + 1]));
        let glyph = id.with_scale_and_position(px, point(0.0, 0.0));
        let Some(outline) = font.outline_glyph(glyph) else {
            continue;
        };
        let bounds = outline.px_bounds();
        let dx = ((x0 + x1) as f32 / 2.0 - (bounds.min.x + bounds.max.x) / 2.0).round() as i64;
        let dy = (h as f32 / 2.0 - (bounds.min.y + bounds.max.y) / 2.0).round() as i64;
        let (left, top) = (bounds.min.x as i64 + dx, bounds.min.y as i64 + dy);
        outline.draw(|gx, gy, c| {
            let (x, y) = (left + i64::from(gx), top + i64::from(gy));
            if (x0..x1).contains(&x) && (0..i64::from(h)).contains(&y) {
                let at = y as usize * wu + x as usize;
                coverage[at] = (coverage[at] + c).min(1.0);
            }
        });
    }
    // How much of a pixel of cell `i` its colour covers: all of it, or the
    // share inside its disc.
    let filled = |i: usize, x: usize, y: usize| -> f32 {
        match look.shape {
            Shape::Cell => 1.0,
            Shape::Circle(across) => {
                let cx = (edges[i] + edges[i + 1]) as f32 / 2.0;
                let cy = h as f32 / 2.0;
                let r = across as f32 * s / 2.0;
                let d = ((x as f32 + 0.5 - cx).powi(2) + (y as f32 + 0.5 - cy).powi(2)).sqrt();
                (r - d + 0.5).clamp(0.0, 1.0)
            }
        }
    };
    let mut pixels = Vec::with_capacity(look.variants() * wu * hu * 4);
    for variant in 0..look.variants() {
        let shown = look.glyphs_in(variant);
        // Each cell's colour in this image, and its glyph's.
        let colours: Vec<(Rgb, Rgb)> = look
            .paints(variant)
            .into_iter()
            .map(|paint| {
                let bg = paint.on(frame);
                (bg, ink(bg))
            })
            .collect();
        for y in 0..hu {
            for (x, &cell) in cell_of.iter().enumerate() {
                let Some(&(bg, fg)) = colours.get(cell) else {
                    pixels.extend_from_slice(&frame.xrgb8888());
                    continue;
                };
                let under = blend(frame, bg, filled(cell, x, y));
                let c = if shown { coverage[y * wu + x] } else { 0.0 };
                pixels.extend_from_slice(&blend(under, fg, c).xrgb8888());
            }
        }
    }
    (w, h, pixels)
}

/// The width of the line's image, logical pixels: the line, or the tag
/// around it in the tag look.
fn image_width(line: &Line, look: &Look) -> i32 {
    if look.tag() {
        tag_layout(line.width, &look.buttons).width
    } else {
        line.width
    }
}

/// The font, the line, the buttons' glyphs and the look, before the proxy
/// confines itself: what its memfd has to hold is known from them.
pub struct Prepared {
    font: FontVec,
    line: Line,
    /// Each button's glyph, in the look's order.
    glyphs: Vec<GlyphId>,
    look: Look,
}

impl Prepared {
    /// With stage 3's look ([`LOOK`]). `None` when the font is not a font,
    /// or the text draws nothing.
    pub fn new(font: Vec<u8>, text: &str) -> Option<Self> {
        Self::with_look(font, text, LOOK)
    }

    /// With the launch's look.
    pub fn with_look(font: Vec<u8>, text: &str, look: Look) -> Option<Self> {
        let font = FontVec::try_from_vec(font).ok()?;
        let line = lay_out(&font, text);
        let glyphs = look
            .buttons
            .order
            .iter()
            .map(|b| font.glyph_id(b.glyph))
            .collect();
        (line.width > 0).then_some(Self {
            font,
            line,
            glyphs,
            look,
        })
    }

    /// Bytes of one region of the line: the line (or the tag) at
    /// [`MAX_SCALE`].
    fn slot_bytes(&self) -> usize {
        device(image_width(&self.line, &self.look), MAX_SCALE) as usize
            * device(HEIGHT, MAX_SCALE) as usize
            * 4
    }

    /// Bytes of one region of the buttons: every image of the row at
    /// [`MAX_SCALE`].
    fn button_bytes(&self) -> usize {
        let look = &self.look.buttons;
        look.variants()
            * device(look.width_all(), MAX_SCALE) as usize
            * device(HEIGHT, MAX_SCALE) as usize
            * 4
    }

    /// Bytes of one region of the round corners: the four at
    /// [`MAX_SCALE`]; none with square ones.
    fn corner_bytes(&self) -> usize {
        let d = device(self.look.corners(), MAX_SCALE) as usize;
        4 * d * d * 4
    }

    /// The memfd's size: [`SLOTS`] regions of the line, then [`SLOTS`] of
    /// the buttons, then [`SLOTS`] of the corners.
    pub fn memfd_size(&self) -> usize {
        (self.slot_bytes() + self.button_bytes() + self.corner_bytes()) * SLOTS
    }
}

/// A region's scale (0: nothing drawn yet), how many buffers of it the
/// compositor holds, when it was last asked for, and the size of the image
/// drawn there.
struct Slot {
    scale: u32,
    leases: Rc<Cell<u32>>,
    used: u64,
    size: (i32, i32),
}

/// [`SLOTS`] regions of the memfd for one thing to draw, from `base` on.
struct Regions {
    base: usize,
    slot_bytes: usize,
    slots: RefCell<Vec<Slot>>,
}

impl Regions {
    fn new(base: usize, slot_bytes: usize) -> Self {
        Self {
            base,
            slot_bytes,
            slots: RefCell::new(
                (0..SLOTS)
                    .map(|_| Slot {
                        scale: 0,
                        leases: Rc::new(Cell::new(0)),
                        used: 0,
                        size: (0, 0),
                    })
                    .collect(),
            ),
        }
    }

    fn bytes(&self) -> usize {
        self.slot_bytes * SLOTS
    }
}

/// The launch's title: the line, the buttons, the round corners, the frame's
/// colour and look, and the memfd their pixels go to.
pub struct Text {
    font: FontVec,
    line: Line,
    glyphs: Vec<GlyphId>,
    bg: Rgb,
    look: Look,
    /// The memfd, to write the pixels with.
    file: File,
    /// The same memfd (another descriptor), for the pools.
    pub fd: Rc<OwnedFd>,
    /// The line's regions, first in the memfd, the buttons' after them, the
    /// corners' last.
    title: Regions,
    buttons: Regions,
    corners: Regions,
    clock: Cell<u64>,
}

/// A buffer's hold on its region: the region is not drawn over while one is
/// alive. Dropped with the buffer's handler — on `release`, or with the
/// connection.
pub struct Lease(Rc<Cell<u32>>);

impl Lease {
    fn new(count: &Rc<Cell<u32>>) -> Self {
        count.set(count.get().saturating_add(1));
        Self(count.clone())
    }

    /// Another hold on the same region: for another buffer of it (the four
    /// round corners are four buffers of one region).
    pub fn another(&self) -> Self {
        Self::new(&self.0)
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.0.set(self.0.get().saturating_sub(1));
    }
}

/// The line (or the buttons, or the corners) drawn at a scale, where it is
/// in the memfd — of the buttons and the corners, the first image, the
/// others after it, `width` × `height` pixels each.
pub struct Drawn {
    pub offset: i32,
    pub width: i32,
    pub height: i32,
    /// The scale it was drawn at: the one asked for, or the nearest one
    /// when every region is held.
    pub scale: u32,
    pub lease: Lease,
}

impl Text {
    /// `memfd` of [`Prepared::memfd_size`] bytes, and a second descriptor of
    /// it for writing. `bg`: the title's colour ([`Look::title_color`]).
    pub fn new(prepared: Prepared, bg: Rgb, memfd: OwnedFd, writer: OwnedFd) -> Self {
        let title = Regions::new(0, prepared.slot_bytes());
        let buttons = Regions::new(title.bytes(), prepared.button_bytes());
        let corners = Regions::new(title.bytes() + buttons.bytes(), prepared.corner_bytes());
        Self {
            font: prepared.font,
            line: prepared.line,
            glyphs: prepared.glyphs,
            bg,
            look: prepared.look,
            file: File::from(writer),
            fd: Rc::new(memfd),
            title,
            buttons,
            corners,
            clock: Cell::new(0),
        }
    }

    /// The descriptor the pixels are written with: the only one the proxy's
    /// filter lets `pwrite64` write to (`wl_proxy::filter`).
    pub fn writer(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    /// The look it draws.
    pub fn look(&self) -> &Look {
        &self.look
    }

    /// The width of the line's image, logical pixels: the line, or the tag.
    pub fn width(&self) -> i32 {
        image_width(&self.line, &self.look)
    }

    /// Where things are on the tag, in the tag look.
    pub fn tag(&self) -> Option<TagLayout> {
        self.look
            .tag()
            .then(|| tag_layout(self.line.width, &self.look.buttons))
    }

    /// How the line's image keeps its pixels: with the tag's round corners
    /// clear, or opaque.
    pub fn pixels(&self) -> Pixels {
        if self.look.tag() {
            Pixels::Alpha
        } else {
            Pixels::Opaque
        }
    }

    /// The pool's size: the whole memfd.
    pub fn pool_size(&self) -> i32 {
        i32::try_from(self.title.bytes() + self.buttons.bytes() + self.corners.bytes())
            .unwrap_or(i32::MAX)
    }

    /// The line at `scale` — the tag with it, in the tag look —, drawn if it
    /// is not yet: in a region nobody holds, the one asked for longest ago.
    /// `None` when nothing is drawn at all and nothing can be (every region
    /// held, or the write failed).
    pub fn at(&self, scale: u32) -> Option<Drawn> {
        self.region_at(&self.title, scale, |scale| {
            if self.look.tag() {
                render_tag(&self.font, &self.line, &self.look.buttons, scale, self.bg)
            } else {
                render(&self.font, &self.line, scale, self.bg)
            }
        })
    }

    /// The buttons at `scale`, every image of the row, as [`Text::at`] the
    /// line. Image `v` ([`ButtonsLook::variant`]) is `v × width × height ×
    /// 4` bytes after `offset`.
    pub fn buttons_at(&self, scale: u32) -> Option<Drawn> {
        self.region_at(&self.buttons, scale, |scale| {
            render_buttons(&self.font, &self.glyphs, &self.look.buttons, scale, self.bg)
        })
    }

    /// The round corners at `scale`, all four, as [`Text::at`] the line:
    /// corner `k` ([`render_corners`]' order) is `k × width × height × 4`
    /// bytes after `offset`. `None` with square corners.
    pub fn corners_at(&self, scale: u32) -> Option<Drawn> {
        let radius = self.look.corners();
        if radius <= 0 {
            return None;
        }
        self.region_at(&self.corners, scale, |scale| {
            render_corners(radius, scale, self.bg)
        })
    }

    fn region_at(
        &self,
        regions: &Regions,
        scale: u32,
        draw: impl FnOnce(u32) -> (i32, i32, Vec<u8>),
    ) -> Option<Drawn> {
        let scale = clamp_scale(scale);
        let now = self.clock.get() + 1;
        self.clock.set(now);
        let mut slots = regions.slots.borrow_mut();
        let found = slots.iter().position(|s| s.scale == scale).or_else(|| {
            let free = (0..slots.len())
                .filter(|&i| slots[i].leases.get() == 0)
                .min_by_key(|&i| slots[i].used)?;
            let (w, h, pixels) = draw(scale);
            let offset = (regions.base + free * regions.slot_bytes) as u64;
            slots[free].scale = 0;
            if pixels.len() > regions.slot_bytes || self.file.write_all_at(&pixels, offset).is_err()
            {
                return None;
            }
            debug_assert_eq!(pixels.len() % (w * h * 4).max(1) as usize, 0);
            slots[free].scale = scale;
            slots[free].size = (w, h);
            Some(free)
        });
        // Every region held: the nearest scale drawn, for the compositor to
        // scale.
        let at = found.or_else(|| {
            (0..slots.len())
                .filter(|&i| slots[i].scale != 0)
                .min_by_key(|&i| slots[i].scale.abs_diff(scale))
        })?;
        let slot = &mut slots[at];
        slot.used = now;
        Some(Drawn {
            offset: (regions.base + at * regions.slot_bytes) as i32,
            width: slot.size.0,
            height: slot.size.1,
            scale: slot.scale,
            lease: Lease::new(&slot.leases),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_fits_or_ends_in_an_ellipsis() {
        assert_eq!(fit(&[10.0, 10.0, 10.0], 5.0, 30.0), (3, false));
        assert_eq!(fit(&[10.0, 10.0, 10.0], 5.0, 29.0), (2, true));
        assert_eq!(fit(&[10.0, 10.0, 10.0], 5.0, 24.0), (1, true));
        assert_eq!(fit(&[10.0], 5.0, 4.0), (0, true));
        assert_eq!(fit(&[], 5.0, 0.0), (0, false));
    }

    #[test]
    fn device_pixels_are_rounded_and_the_scale_bounded() {
        assert_eq!(device(HEIGHT, 120), 20);
        // The strip is a whole number of pixels at the usual scales.
        for (scale, px) in [(150, 25), (180, 30), (210, 35), (240, 40)] {
            assert_eq!(device(HEIGHT, scale), px);
        }
        assert_eq!(device(101, 150), 126, "126.25 rounds down");
        assert_eq!(device(101, 180), 152, "151.5 rounds up");
        assert_eq!(device(10, 60), 10, "below 1: as at 1");
        assert_eq!(device(10, 100_000), 40, "above 4: as at 4");
        assert_eq!(device(-5, 120), 0);
    }

    #[test]
    fn the_ink_is_readable_on_the_colour() {
        assert_eq!(ink(Rgb(255, 255, 255)), Rgb(0x14, 0x14, 0x14));
        assert_eq!(ink(Rgb(255, 0, 255)), Rgb(0x14, 0x14, 0x14));
        assert_eq!(ink(Rgb(0, 0, 0)), Rgb(0xff, 0xff, 0xff));
        assert_eq!(ink(Rgb(0x30, 0x30, 0xa0)), Rgb(0xff, 0xff, 0xff));
        // Every default colour of a zone (`crate::frame::default_color`)
        // gets one or the other, and a readable one: a contrast of 3 or more.
        for zone in ["nl", "de", "work", "offline", "зона"] {
            let bg = crate::frame::default_color(zone);
            let luminance = |Rgb(r, g, b): Rgb| {
                let lin = |c: u8| {
                    let c = f64::from(c) / 255.0;
                    if c <= 0.04045 {
                        c / 12.92
                    } else {
                        ((c + 0.055) / 1.055).powf(2.4)
                    }
                };
                0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
            };
            let (a, b) = (luminance(bg), luminance(ink(bg)));
            let ratio = (a.max(b) + 0.05) / (a.min(b) + 0.05);
            assert!(ratio >= 3.0, "{zone}: {bg:?} {ratio}");
        }
    }

    /// The font the package names; a build without one (`cargo test` outside
    /// the Nix shells that set it) has nothing to draw with.
    fn font() -> Option<Vec<u8>> {
        let bytes = FONT.and_then(|path| std::fs::read(path).ok());
        if bytes.is_none() {
            eprintln!("VPN_ZONE_FRAME_FONT is not set at build time — no text to draw");
        }
        bytes
    }

    #[test]
    fn the_line_is_drawn_on_the_colour_at_every_scale() {
        let Some(bytes) = font() else { return };
        let prepared = Prepared::new(bytes, "nl · основной").expect("a font");
        let bg = Rgb(0xff, 0x00, 0xff);
        let width = prepared.line.width;
        assert!((60..300).contains(&width), "{width}");
        for scale in [120, 150, 180, 240] {
            let (w, h, pixels) = render(&prepared.font, &prepared.line, scale, bg);
            assert_eq!((w, h), (device(width, scale), device(HEIGHT, scale)));
            assert_eq!(pixels.len(), (w * h * 4) as usize);
            let words: Vec<u32> = pixels
                .chunks(4)
                .map(|p| u32::from_ne_bytes(p.try_into().unwrap()))
                .collect();
            let bg_word = u32::from_ne_bytes(bg.xrgb8888());
            let ink_word = u32::from_ne_bytes(ink(bg).xrgb8888());
            // Mostly the colour, and text in it: pixels of the ink itself.
            let on_bg = words.iter().filter(|&&p| p == bg_word).count();
            assert!(
                on_bg > words.len() / 2,
                "scale {scale}: {on_bg} of {}",
                words.len()
            );
            assert!(words.contains(&ink_word), "scale {scale}: no text");
            // Opaque, and nothing on the top and bottom rows: the text is
            // inside the strip.
            assert!(words.iter().all(|p| p >> 24 == 0xff));
            let row = |y: i32| &words[(y * w) as usize..((y + 1) * w) as usize];
            assert!(
                row(0).iter().all(|&p| p == bg_word),
                "scale {scale}: top row"
            );
            assert!(
                row(h - 1).iter().all(|&p| p == bg_word),
                "scale {scale}: bottom row"
            );
        }
    }

    #[test]
    fn a_long_line_is_cut_to_the_limit() {
        let Some(bytes) = font() else { return };
        let long = format!("{} · {}", "w".repeat(40), "m".repeat(40));
        let prepared = Prepared::new(bytes, &long).expect("a font");
        assert!(prepared.line.width as f32 <= MAX_WIDTH + 1.0);
        assert!(prepared.line.width as f32 > MAX_WIDTH - 40.0);
        let (_, dots) = prepared.line.glyphs.last().unwrap();
        assert!(*dots > 0.0);
    }

    /// The regions: a scale drawn once is reused; one held by the compositor
    /// is not drawn over; with every one held a new scale gets the nearest.
    #[test]
    fn a_region_held_by_the_compositor_is_not_drawn_over() {
        let Some(bytes) = font() else { return };
        let prepared = Prepared::new(bytes, "de · банк").expect("a font");
        let size = prepared.memfd_size();
        let dir = std::env::temp_dir().join(format!("vz-title-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("memfd");
        let file = File::create(&path).unwrap();
        file.set_len(size as u64).unwrap();
        let writer = OwnedFd::from(File::options().write(true).open(&path).unwrap());
        let text = Text::new(prepared, Rgb(0x20, 0x40, 0x80), OwnedFd::from(file), writer);
        assert_eq!(text.pool_size() as usize, size);

        let one = text.at(120).unwrap();
        let again = text.at(120).unwrap();
        assert_eq!(one.offset, again.offset, "drawn once");
        let held: Vec<Drawn> = [150, 180, 240]
            .iter()
            .map(|&s| text.at(s).unwrap())
            .collect();
        let mut offsets: Vec<i32> = held.iter().map(|d| d.offset).collect();
        offsets.push(one.offset);
        offsets.sort_unstable();
        offsets.dedup();
        assert_eq!(offsets.len(), SLOTS, "four scales, four regions");
        // All four held: 1.9 comes as the nearest drawn, 2.0.
        let near = text.at(228).unwrap();
        assert_eq!(near.scale, 240);
        drop(near);
        // 1.25 let go (its only buffer released): 1.75 is drawn there.
        let released = held[0].offset;
        drop(held);
        let fresh = text.at(210).unwrap();
        assert_eq!(fresh.scale, 210);
        assert_ne!(fresh.offset, one.offset, "the region still held");
        // And what is in the file is the line at that scale.
        let (w, h, pixels) = render(&text.font, &text.line, 210, text.bg);
        let mut got = vec![0u8; pixels.len()];
        let reader = File::open(&path).unwrap();
        reader.read_exact_at(&mut got, fresh.offset as u64).unwrap();
        assert_eq!((fresh.width, fresh.height), (w, h));
        assert_eq!(got, pixels);
        assert_eq!(fresh.offset, released, "the free one asked for longest ago");
        // The buttons: regions of their own after the line's, every image
        // of the row written there.
        let buttons = text.buttons_at(150).unwrap();
        let (bw, bh, row) = render_buttons(&text.font, &text.glyphs, &LOOK.buttons, 150, text.bg);
        assert_eq!((buttons.width, buttons.height), (bw, bh));
        assert!(
            buttons.offset as usize >= text.title.bytes(),
            "over the line's"
        );
        assert!(
            buttons.offset as usize + row.len() <= size,
            "past the memfd"
        );
        let mut got = vec![0u8; row.len()];
        reader
            .read_exact_at(&mut got, buttons.offset as u64)
            .unwrap();
        assert_eq!(got, row);
        drop((one, again, fresh, buttons));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The row of the look there is: a cell each, left to right; a point is
    /// a button only inside the row, and each state is an image of its own.
    #[test]
    fn a_point_on_the_buttons_is_the_button_of_its_cell() {
        let look = &LOOK.buttons;
        assert_eq!(look.end, End::Right);
        assert_eq!(look.width_all(), 3 * look.width);
        let at = |x: f64, y: f64| look.at(x, y);
        assert_eq!(at(-0.5, 10.0), None, "left of the row");
        assert_eq!(at(0.0, 10.0), Some(Button::Menu));
        assert_eq!(at(23.9, 0.0), Some(Button::Menu));
        assert_eq!(at(24.0, 19.9), Some(Button::Network));
        assert_eq!(at(60.0, 10.0), Some(Button::Close));
        assert_eq!(at(72.0, 10.0), None, "right of the row");
        assert_eq!(at(10.0, -0.1), None, "above it");
        assert_eq!(at(10.0, 20.0), None, "below it");
        // Images: at rest, three lit, three pressed.
        assert_eq!(look.variants(), 7);
        let lit = |button, pressed| Some(Lit { button, pressed });
        assert_eq!(look.variant(None), 0);
        assert_eq!(look.variant(lit(Button::Menu, false)), 1);
        assert_eq!(look.variant(lit(Button::Close, false)), 3);
        assert_eq!(look.variant(lit(Button::Menu, true)), 4);
        assert_eq!(look.variant(lit(Button::Close, true)), 6);
        // Close is red under the pointer, the others a shade of the frame.
        let close = look
            .order
            .iter()
            .find(|b| b.button == Button::Close)
            .unwrap();
        assert_eq!(close.hover, Paint::Fixed(CLOSE_HOVER));
        assert!(look
            .order
            .iter()
            .all(|b| b.rest == Paint::Frame && b.hover != b.rest && b.press != b.hover));
    }

    /// A shade stands out from the frame's colour either way: lighter on a
    /// dark one, darker on a light one; a fixed colour is itself.
    #[test]
    fn a_shade_is_lighter_on_dark_and_darker_on_light() {
        let dark = Rgb(0x30, 0x30, 0xa0);
        let light = Rgb(0xd0, 0xe0, 0x90);
        assert_eq!(Paint::Frame.on(dark), dark);
        assert_eq!(Paint::Fixed(CLOSE_HOVER).on(light), CLOSE_HOVER);
        let up = Paint::Shade(22).on(dark);
        assert!(up.0 > dark.0 && up.1 > dark.1 && up.2 > dark.2, "{up:?}");
        let down = Paint::Shade(22).on(light);
        assert!(
            down.0 < light.0 && down.1 < light.1 && down.2 < light.2,
            "{down:?}"
        );
        assert_eq!(Paint::Shade(0).on(light), light);
        assert_eq!(Paint::Shade(100).on(dark), WHITE);
    }

    /// Every image of the row: each cell its colour of that state, the glyph
    /// on it in the ink that reads there, and nothing on the top and bottom
    /// rows; at every usual scale, in whole pixels.
    #[test]
    fn the_buttons_are_drawn_in_every_state() {
        let Some(bytes) = font() else { return };
        let prepared = Prepared::new(bytes, "nl · основной").expect("a font");
        // The font has every glyph of the look.
        assert!(
            prepared.glyphs.iter().all(|g| g.0 != 0),
            "{:?}",
            prepared.glyphs
        );
        let frame = Rgb(0xff, 0x00, 0xff);
        let look = &LOOK.buttons;
        for scale in [120, 150, 180, 240] {
            let (w, h, pixels) =
                render_buttons(&prepared.font, &prepared.glyphs, look, scale, frame);
            assert_eq!(
                (w, h),
                (device(look.width_all(), scale), device(HEIGHT, scale))
            );
            assert_eq!(pixels.len(), look.variants() * (w * h * 4) as usize);
            let word = |v: usize, x: i32, y: i32| {
                let at = ((v as i32 * h + y) * w + x) as usize * 4;
                u32::from_ne_bytes(pixels[at..at + 4].try_into().unwrap())
            };
            let colour = |c: Rgb| u32::from_ne_bytes(c.xrgb8888());
            let cell = |i: i32| {
                (
                    device(look.width * i, scale),
                    device(look.width * (i + 1), scale),
                )
            };
            for v in 0..look.variants() {
                let paints = look.paints(v);
                for (i, paint) in paints.iter().enumerate() {
                    let (x0, x1) = cell(i as i32);
                    let bg = paint.on(frame);
                    // A corner of the cell is its colour; its glyph is there,
                    // inside the rows, blended toward its ink.
                    assert_eq!(word(v, x0, 0), colour(bg), "scale {scale} image {v}");
                    assert_eq!(word(v, x1 - 1, h - 1), colour(bg));
                    let toward_ink = |p: u32| {
                        let [b, g, r, _] = p.to_le_bytes();
                        let fg = ink(bg);
                        let d = |a: u8, b: u8| (i32::from(a) - i32::from(b)).abs();
                        d(r, fg.0) + d(g, fg.1) + d(b, fg.2)
                            < d(bg.0, fg.0) + d(bg.1, fg.1) + d(bg.2, fg.2)
                    };
                    let inked = (x0..x1)
                        .flat_map(|x| (0..h).map(move |y| (x, y)))
                        .filter(|&(x, y)| toward_ink(word(v, x, y)))
                        .count();
                    assert!(inked > 0, "scale {scale} image {v}: no glyph in cell {i}");
                    for x in x0..x1 {
                        assert_eq!(word(v, x, 0), colour(bg), "top row");
                        assert_eq!(word(v, x, h - 1), colour(bg), "bottom row");
                    }
                }
            }
            // Close lit: red; menu lit: a shade of the frame.
            let (c0, _) = cell(2);
            assert_eq!(word(3, c0, 0), colour(CLOSE_HOVER));
            assert_eq!(word(6, c0, 0), colour(CLOSE_PRESS));
            assert_eq!(word(1, 0, 0), colour(Paint::Shade(22).on(frame)));
            assert_eq!(word(0, 0, 0), colour(frame));
        }
    }

    /// Every look of the buttons (the owner, 2026-09-27: GNOME's, KDE's,
    /// macOS's and Windows's, all equal, and the one there was): its end,
    /// its order, a cell each for the pointer, close red under it.
    #[test]
    fn every_look_has_its_end_its_order_and_close_red_under_the_pointer() {
        use crate::frame::ButtonStyle;
        let order =
            |look: &ButtonsLook| -> Vec<Button> { look.order.iter().map(|b| b.button).collect() };
        let right = [Button::Menu, Button::Network, Button::Close];
        for (style, end, width) in [
            (ButtonStyle::Cellward, End::Right, 24),
            (ButtonStyle::Gnome, End::Right, 24),
            (ButtonStyle::Kde, End::Right, 24),
            (ButtonStyle::Macos, End::Left, 20),
            (ButtonStyle::Windows, End::Right, 32),
        ] {
            let look = buttons_look(style);
            assert_eq!(look.end, end, "{style:?}");
            assert_eq!(look.width, width, "{style:?}");
            // A whole number of pixels at 1.25 and 1.75, like the strip.
            assert_eq!(look.width % 4, 0, "{style:?}");
            assert_eq!(look.margin % 4, 0, "{style:?}");
            if style == ButtonStyle::Macos {
                // The traffic lights: close red first, then yellow, then
                // green, at the left end.
                assert_eq!(order(&look), [Button::Close, Button::Menu, Button::Network]);
                let lights: Vec<Paint> = look.order.iter().map(|b| b.rest).collect();
                assert_eq!(
                    lights,
                    [
                        Paint::Fixed(MAC_RED),
                        Paint::Fixed(MAC_YELLOW),
                        Paint::Fixed(MAC_GREEN)
                    ]
                );
                assert_eq!(look.glyphs, Glyphs::Lit);
            } else {
                assert_eq!(order(&look), right, "{style:?}");
                assert_eq!(look.glyphs, Glyphs::Always);
            }
            // A point is the button of its cell, in the look's order.
            for (i, b) in look.order.iter().enumerate() {
                let x0 = f64::from(width) * i as f64;
                assert_eq!(look.at(x0, 0.0), Some(b.button), "{style:?}");
                assert_eq!(look.at(x0 + f64::from(width) - 0.5, 19.5), Some(b.button));
            }
            assert_eq!(look.at(f64::from(look.width_all()), 10.0), None);
            assert_eq!(look.at(-0.5, 10.0), None);
            assert_eq!(look.at(1.0, 20.0), None);
            // Close red under the pointer, whatever the frame's colour; the
            // others not; pressed another colour than lit.
            for frame in [
                Rgb(0xff, 0, 0xff),
                Rgb(0x20, 0x30, 0x40),
                Rgb(0xf0, 0xf0, 0xe0),
            ] {
                for b in look.order {
                    let Rgb(r, g, bl) = b.hover.on(frame);
                    let red = r >= 190 && g <= 100 && bl <= 100;
                    assert_eq!(
                        red,
                        b.button == Button::Close,
                        "{style:?} {b:?} on {frame:?}"
                    );
                    assert_ne!(b.press.on(frame), b.hover.on(frame), "{style:?} {b:?}");
                }
            }
            assert_eq!(look.variants(), 7);
        }
        // None: no row at all.
        let none = buttons_look(ButtonStyle::None);
        assert_eq!((none.width_all(), none.variants()), (0, 1));
        assert_eq!(none.at(0.0, 0.0), None);
        // Stage 3's look is cellward's.
        assert_eq!(LOOK.buttons, CELLWARD);
        assert_eq!(buttons_look(crate::frame::DEFAULT_BUTTONS), CELLWARD);
    }

    /// Every look's row drawn in every state at the usual scales: a cell of
    /// the whole colour, or a disc of it on the strip's colour; a glyph in
    /// each cell — macOS's only while one of them is lit, on all of them
    /// then —; and close red under the pointer.
    #[test]
    fn every_look_draws_its_buttons_in_every_state() {
        use crate::frame::ButtonStyle;
        let Some(bytes) = font() else { return };
        let frame = Rgb(0xff, 0x00, 0xff);
        for style in ButtonStyle::ALL {
            let look = Look {
                buttons: buttons_look(style),
                ..LOOK
            };
            let prepared =
                Prepared::with_look(bytes.clone(), "nl · основной", look).expect("a font");
            assert!(
                prepared.glyphs.iter().all(|g| g.0 != 0),
                "{style:?}: {:?}",
                prepared.glyphs
            );
            let row = &look.buttons;
            if row.order.is_empty() {
                continue;
            }
            for scale in [120, 180] {
                let (w, h, pixels) =
                    render_buttons(&prepared.font, &prepared.glyphs, row, scale, frame);
                assert_eq!(
                    (w, h),
                    (device(row.width_all(), scale), device(HEIGHT, scale))
                );
                assert_eq!(pixels.len(), row.variants() * (w * h * 4) as usize);
                let word = |v: usize, x: i32, y: i32| {
                    let at = ((v as i32 * h + y) * w + x) as usize * 4;
                    let [b, g, r, _]: [u8; 4] = pixels[at..at + 4].try_into().unwrap();
                    Rgb(r, g, b)
                };
                let cell = |i: usize| {
                    (
                        device(row.width * i as i32, scale),
                        device(row.width * (i as i32 + 1), scale),
                    )
                };
                // Pixels of cell `i` in image `v` that are `colour` exactly.
                let count = |v: usize, i: usize, colour: Rgb| {
                    let (x0, x1) = cell(i);
                    (x0..x1)
                        .flat_map(|x| (0..h).map(move |y| (x, y)))
                        .filter(|&(x, y)| word(v, x, y) == colour)
                        .count()
                };
                // Most of a disc is its colour: the glyph on it and its
                // smoothed edge are not a third of it.
                let disc = |across: i32| {
                    let r = f64::from(device(across, scale)) / 2.0;
                    (std::f64::consts::PI * r * r * 0.3) as usize
                };
                for v in 0..row.variants() {
                    for (i, paint) in row.paints(v).iter().enumerate() {
                        let (x0, x1) = cell(i);
                        let bg = paint.on(frame);
                        match row.shape {
                            Shape::Cell => {
                                assert_eq!(word(v, x0, 0), bg, "{style:?} {scale} {v}");
                            }
                            Shape::Circle(across) => {
                                assert_eq!(word(v, x0, 0), frame, "{style:?}: the cell's corner");
                                let n = count(v, i, bg);
                                assert!(
                                    n >= disc(across),
                                    "{style:?} {scale} {v} {i}: {n} of {bg:?}"
                                );
                            }
                        }
                        // Nothing on the top and bottom rows but the colour
                        // and the strip's.
                        for x in x0..x1 {
                            for y in [0, h - 1] {
                                let p = word(v, x, y);
                                assert!(p == bg || p == frame, "{style:?} {v} ({x}, {y}): {p:?}");
                            }
                        }
                    }
                }
                // The glyphs: in every image, or (macOS) only in the lit
                // ones — where every cell differs from the image at rest.
                for i in 0..row.order.len() {
                    let (x0, x1) = cell(i);
                    let differs =
                        |v: usize| (x0..x1).any(|x| (0..h).any(|y| word(v, x, y) != word(0, x, y)));
                    let inked = |v: usize| {
                        let bg = row.paints(v)[i].on(frame);
                        let fg = ink(bg);
                        let d = |a: Rgb, b: Rgb| {
                            (i32::from(a.0) - i32::from(b.0)).abs()
                                + (i32::from(a.1) - i32::from(b.1)).abs()
                                + (i32::from(a.2) - i32::from(b.2)).abs()
                        };
                        (x0..x1)
                            .flat_map(|x| (0..h).map(move |y| (x, y)))
                            .filter(|&(x, y)| d(word(v, x, y), fg) * 2 < d(bg, fg))
                            .count()
                    };
                    match row.glyphs {
                        Glyphs::Always => {
                            for v in 0..row.variants() {
                                assert!(
                                    inked(v) > 0,
                                    "{style:?} {scale}: no glyph in {i}, image {v}"
                                );
                            }
                        }
                        Glyphs::Lit => {
                            assert_eq!(inked(0), 0, "{style:?}: a glyph at rest in {i}");
                            for v in 1..row.variants() {
                                assert!(differs(v), "{style:?}: no glyph in {i}, image {v}");
                            }
                        }
                    }
                }
                // Close under the pointer: its red, most of its cell or of its
                // disc.
                let at = row
                    .order
                    .iter()
                    .position(|b| b.button == Button::Close)
                    .unwrap();
                let lit = row.variant(Some(Lit {
                    button: Button::Close,
                    pressed: false,
                }));
                let red = row.order[at].hover.on(frame);
                let least = match row.shape {
                    Shape::Cell => (device(row.width, scale) * h / 2) as usize,
                    Shape::Circle(across) => disc(across),
                };
                let n = count(lit, at, red);
                assert!(n >= least, "{style:?}: close lit, {n} of {red:?}");
            }
        }
    }

    /// The soft style's tones: the zone's hue, less saturated and a little
    /// darker, the outer ring more so; the title's tone still reads its ink.
    #[test]
    fn the_soft_tones_keep_the_zones_hue() {
        let magenta = Rgb(0xff, 0x00, 0xff);
        // What tests/vm-window-looks.py looks for on the screen.
        assert_eq!(soft_inner(magenta), Rgb(240, 91, 240));
        assert_eq!(soft_outer(magenta), Rgb(204, 112, 204));
        assert_eq!(ink(soft_inner(magenta)), NEAR_BLACK);
        for zone in ["nl", "de", "work", "offline", "зона"] {
            let c = crate::frame::default_color(zone);
            let (h, s, v) = crate::frame::to_hsv(c);
            for (tone, less) in [(soft_inner(c), 0.62), (soft_outer(c), 0.45)] {
                let (th, ts, tv) = crate::frame::to_hsv(tone);
                let turn = (th - h).abs().min(360.0 - (th - h).abs());
                assert!(turn < 4.0, "{zone}: hue {h} → {th}");
                assert!((ts - s * less).abs() < 0.03, "{zone}: {ts} {s}");
                assert!(tv < v && ts < s, "{zone}: {tone:?} of {c:?}");
            }
            assert_ne!(soft_inner(c), soft_outer(c));
        }
        // A grey stays a grey.
        assert_eq!(soft_inner(Rgb(0x80, 0x80, 0x80)), Rgb(0x78, 0x78, 0x78));
    }

    /// Each style's colours and rings: `full` one ring of the colour itself
    /// (stage 2's one square), `soft` two tones nested, the outer half
    /// darker, `tag` none and a clear square for its row.
    #[test]
    fn each_style_has_its_squares_and_rings() {
        let c = Rgb(0x12, 0x80, 0xc0);
        let full = LOOK;
        let soft = Look {
            style: Style::Soft,
            ..LOOK
        };
        let tag = Look {
            style: Style::Tag,
            radius: 8,
            ..LOOK
        };
        assert_eq!(full.squares(c), [Square::Color(c)]);
        assert_eq!(full.rings(6), [(6, 0)]);
        assert_eq!((full.title_color(c), full.title_square(true)), (c, 0));
        assert_eq!(
            soft.squares(c),
            [Square::Color(soft_inner(c)), Square::Color(soft_outer(c))]
        );
        assert_eq!(soft.rings(6), [(3, 1), (3, 0)]);
        assert_eq!(soft.rings(4), [(2, 1), (2, 0)]);
        assert_eq!(soft.rings(5), [(2, 1), (3, 0)], "the inner one the wider");
        assert_eq!(soft.rings(1), [(1, 0)]);
        assert_eq!(soft.title_color(c), soft_inner(c));
        assert_eq!(tag.squares(c), [Square::Color(c), Square::Clear]);
        assert!(tag.rings(6).is_empty());
        assert_eq!((tag.title_square(true), tag.title_square(false)), (1, 0));
        // Round corners, but not on a tag.
        assert_eq!(tag.corners(), 0);
        assert_eq!(Look { radius: 8, ..soft }.corners(), 8);
        assert_eq!(Look { radius: 99, ..soft }.corners(), MAX_RADIUS);
        // The pixels: opaque, or nothing at all; premultiplied in between.
        assert_eq!(u32::from_ne_bytes(Square::Color(c).word()), 0xff12_80c0);
        assert_eq!(Square::Clear.word(), [0; 4]);
        assert_eq!(Square::Clear.pixels(), Pixels::Alpha);
        assert_eq!(u32::from_ne_bytes(premultiplied(c, 1.0)), 0xff12_80c0);
        assert_eq!(u32::from_ne_bytes(premultiplied(c, 0.0)), 0);
        assert_eq!(
            u32::from_ne_bytes(premultiplied(Rgb(200, 100, 0), 0.5)),
            0x8064_3200
        );
        // A look of the settings.
        let frame = crate::frame::Frame {
            color: c,
            width: 4,
            title: crate::frame::TitleMode::Always,
            buttons: crate::frame::ButtonStyle::Macos,
            style: Style::Soft,
            radius: 12,
        };
        assert_eq!(
            Look::of(&frame),
            Look {
                style: Style::Soft,
                buttons: MACOS,
                radius: 12
            }
        );
    }

    /// The tag: the label between its pads and the row at the look's end,
    /// clear of the round corners; without buttons, the label alone.
    #[test]
    fn the_tag_is_its_label_and_its_buttons() {
        let text = 100;
        let t = tag_layout(text, &CELLWARD);
        assert_eq!(
            t,
            TagLayout {
                width: PAD + text + PAD + 72 + TAG_ROUND,
                text_x: PAD,
                buttons: Some(PAD + text + PAD),
            }
        );
        let m = tag_layout(text, &MACOS);
        assert_eq!(
            m.buttons,
            Some(TAG_ROUND),
            "the lights first, clear of the corner"
        );
        assert_eq!(m.text_x, TAG_ROUND + 60 + PAD);
        assert_eq!(m.width, m.text_x + text + PAD);
        let g = tag_layout(text, &GNOME);
        assert_eq!(g.width, PAD + text + PAD + 72 + TAG_ROUND.max(GNOME.margin));
        assert_eq!(
            tag_layout(text, &NO_BUTTONS),
            TagLayout {
                width: PAD + text + PAD,
                text_x: PAD,
                buttons: None
            }
        );
        // The row never over a round corner.
        for look in [CELLWARD, GNOME, KDE, MACOS, WINDOWS] {
            let t = tag_layout(text, &look);
            let b = t.buttons.unwrap();
            assert!(
                b >= TAG_ROUND && b + look.width_all() <= t.width - TAG_ROUND,
                "{look:?}"
            );
        }
    }

    /// The tag's image: its colour, the text on it, the top corners round
    /// and clear outside, the bottom ones square; premultiplied.
    #[test]
    fn the_tag_is_drawn_with_round_top_corners() {
        let Some(bytes) = font() else { return };
        let look = Look {
            style: Style::Tag,
            ..LOOK
        };
        let prepared = Prepared::with_look(bytes, "nl · основной", look).expect("a font");
        let bg = Rgb(0xff, 0x00, 0xff);
        for scale in [120, 180] {
            let (w, h, pixels) =
                render_tag(&prepared.font, &prepared.line, &look.buttons, scale, bg);
            let tag = tag_layout(prepared.line.width, &look.buttons);
            assert_eq!((w, h), (device(tag.width, scale), device(HEIGHT, scale)));
            assert_eq!(pixels.len(), (w * h * 4) as usize);
            let word = |x: i32, y: i32| {
                let at = ((y * w + x) * 4) as usize;
                u32::from_ne_bytes(pixels[at..at + 4].try_into().unwrap())
            };
            let opaque = u32::from_ne_bytes(bg.xrgb8888());
            assert_eq!(word(0, 0), 0, "the top left corner clear");
            assert_eq!(word(w - 1, 0), 0, "the top right corner clear");
            assert_eq!(word(0, h - 1), opaque, "the bottom square");
            assert_eq!(word(w - 1, h - 1), opaque);
            assert_eq!(word(w / 2, 0), opaque, "the top edge between the corners");
            // Round: part of a pixel along the curve.
            let r = device(TAG_ROUND, scale);
            assert!((0..r).any(|x| (0..r).any(|y| {
                let a = word(x, y) >> 24;
                a > 0 && a < 0xff
            })));
            // Premultiplied: no channel above its alpha.
            for y in 0..h {
                for x in 0..w {
                    let [b, g, r, a] = word(x, y).to_le_bytes();
                    assert!(r <= a && g <= a && b <= a, "({x}, {y})");
                }
            }
            // The text, after the pad: its ink there, and not in the pad.
            let fg = u32::from_ne_bytes(ink(bg).xrgb8888());
            let inked: Vec<i32> = (0..w)
                .filter(|&x| (0..h).any(|y| word(x, y) == fg))
                .collect();
            assert!(!inked.is_empty(), "scale {scale}: no text");
            assert!(inked[0] >= device(tag.text_x, scale) - 1, "{inked:?}");
        }
    }

    /// The window's round corners: the colour where the window's corner is
    /// cut off, clear inside the quarter circle, each of the four a mirror
    /// of the first; the radius in device pixels at the scale.
    #[test]
    fn the_round_corners_are_clear_inside_their_quarter_circle() {
        let c = Rgb(240, 91, 240);
        let (d, d2, pixels) = render_corners(8, 120, c);
        assert_eq!((d, d2), (8, 8));
        assert_eq!(pixels.len(), 4 * 8 * 8 * 4);
        let word = |k: i32, x: i32, y: i32| {
            let at = (((k * d + y) * d + x) * 4) as usize;
            u32::from_ne_bytes(pixels[at..at + 4].try_into().unwrap())
        };
        let alpha = |k: i32, x: i32, y: i32| word(k, x, y) >> 24;
        let opaque = u32::from_ne_bytes(c.xrgb8888());
        // The top left: the window's corner cut off, its inside clear.
        assert_eq!(word(0, 0, 0), opaque);
        assert_eq!(word(0, 7, 7), 0);
        // Where the curve meets the image's far edges it touches them: the
        // last pixel there is next to nothing of the colour.
        assert!(alpha(0, 7, 0) < 0x10, "the top edge beyond the curve");
        assert!(alpha(0, 0, 7) < 0x10, "the left edge beyond the curve");
        assert_eq!(alpha(0, 3, 0), 0xff, "the top edge before it");
        // Along the diagonal, less and less of it.
        let diagonal: Vec<u32> = (0..d).map(|i| alpha(0, i, i)).collect();
        assert!(diagonal.windows(2).all(|p| p[0] >= p[1]), "{diagonal:?}");
        assert!(
            diagonal.iter().any(|&a| a > 0 && a < 0xff),
            "no smoothing: {diagonal:?}"
        );
        // The others are its mirrors: top right, bottom left, bottom right.
        for y in 0..d {
            for x in 0..d {
                assert_eq!(word(1, x, y), word(0, d - 1 - x, y), "top right ({x}, {y})");
                assert_eq!(word(2, x, y), word(0, x, d - 1 - y), "bottom left");
                assert_eq!(word(3, x, y), word(0, d - 1 - x, d - 1 - y), "bottom right");
            }
        }
        // At 1.5: 12 pixels, the same shape.
        let (d, _, pixels) = render_corners(8, 180, c);
        assert_eq!((d, pixels.len()), (12, 4 * 12 * 12 * 4));
        // None at 0.
        assert_eq!(render_corners(0, 120, c).2.len(), 0);
    }

    /// The corners' regions: after the line's and the buttons', written as
    /// drawn; none with square corners, nor in the tag look.
    #[test]
    fn the_corners_have_regions_of_their_own() {
        let Some(bytes) = font() else { return };
        let dir = std::env::temp_dir().join(format!("vz-corners-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let text_of = |look: Look, name: &str| {
            let prepared = Prepared::with_look(bytes.clone(), "nl · основной", look).unwrap();
            let size = prepared.memfd_size();
            let path = dir.join(name);
            let file = File::create(&path).unwrap();
            file.set_len(size as u64).unwrap();
            let writer = OwnedFd::from(File::options().write(true).open(&path).unwrap());
            (
                Text::new(prepared, Rgb(240, 91, 240), OwnedFd::from(file), writer),
                path,
                size,
            )
        };
        let round = Look {
            style: Style::Soft,
            radius: 8,
            ..LOOK
        };
        let (text, path, size) = text_of(round, "round");
        assert_eq!(text.pool_size() as usize, size);
        let corners = text.corners_at(180).unwrap();
        assert_eq!((corners.width, corners.height), (12, 12));
        assert!(corners.offset as usize >= text.title.bytes() + text.buttons.bytes());
        let (_, _, want) = render_corners(8, 180, Rgb(240, 91, 240));
        assert!(
            corners.offset as usize + want.len() <= size,
            "past the memfd"
        );
        let mut got = vec![0u8; want.len()];
        File::open(&path)
            .unwrap()
            .read_exact_at(&mut got, corners.offset as u64)
            .unwrap();
        assert_eq!(got, want);
        // Another hold on it: the region stays held while either is alive.
        let again = corners.lease.another();
        drop(corners);
        assert!(text
            .corners
            .slots
            .borrow()
            .iter()
            .any(|s| s.scale == 180 && s.leases.get() == 1));
        drop(again);
        assert!(text
            .corners
            .slots
            .borrow()
            .iter()
            .all(|s| s.leases.get() == 0));
        // Square: nothing; a tag: nothing, and its line is the tag, clear
        // at the corners.
        let (square, _, _) = text_of(LOOK, "square");
        assert!(square.corners_at(120).is_none());
        let tag = Look {
            style: Style::Tag,
            radius: 8,
            ..LOOK
        };
        let (tagged, _, _) = text_of(tag, "tag");
        assert!(tagged.corners_at(120).is_none());
        assert_eq!(tagged.pixels(), Pixels::Alpha);
        assert_eq!(tagged.width(), tagged.tag().unwrap().width);
        let line = tagged.at(120).unwrap();
        assert_eq!(line.width, device(tagged.width(), 120));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
