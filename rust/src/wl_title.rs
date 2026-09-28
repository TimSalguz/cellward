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
//! another buffer of the region, not a new raster. How they look — which
//! end, which order, the glyphs, the shape, the colours at rest, under the
//! pointer and pressed — is one value, [`LOOK`]; the drawing here and the
//! hit-testing in `crate::wl_frame` follow whatever it says.

#![forbid(unsafe_code)]

use std::cell::{Cell, RefCell};
use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileExt;
use std::rc::Rc;

use ab_glyph::{point, Font, FontVec, GlyphId, PxScale, ScaleFont};

use crate::frame::Rgb;

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
    /// Another network for the container: switched live, its programs
    /// running on (`window-menu --network`, stage 5 of the container
    /// design); where its instance cannot be — the main home's, a
    /// throwaway's — the program is started again with the network chosen,
    /// as this button did until then.
    Network,
    /// The window's own `close`, as a server-side decoration's would be.
    Close,
}

/// A colour of the look, made from the frame's own (the zone's, or the
/// container's).
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
    /// The whole of its cell, edge to edge: square buttons side by side
    /// (the Windows-like row). Round ones — Adwaita's and Breeze's circles,
    /// macOS's traffic lights — come with their looks.
    Cell,
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
    /// usual scales (1.25, 1.5, 1.75, 2), like the strip's height.
    pub width: i32,
    /// The glyphs' size (ab_glyph's scale, as the text's [`FONT_PX`]).
    pub size: f32,
    pub shape: Shape,
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

/// How the frame's pixels are kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pixels {
    /// XRGB8888, opaque: nothing of what lies under a part of the frame
    /// shows through it — the program's CSD shadow, or a strip it drew there
    /// itself (`docs/WINDOW-FRAME.md` §5.9). A look with round corners or a
    /// tag (see [`Look`]) needs alpha, ARGB8888, and gives that up.
    Opaque,
}

impl Pixels {
    /// One pixel of `color`, as the memfds hold it.
    pub fn word(self, color: Rgb) -> [u8; 4] {
        match self {
            Self::Opaque => color.xrgb8888(),
        }
    }
}

/// How much of the window's width the title strip takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StripWidth {
    /// All of it, between the side strips.
    Full,
}

/// How the frame looks. The owner wants several looks to choose from later
/// (2026-09-27): GNOME's (Adwaita), KDE's (Breeze), macOS's (the traffic
/// lights at the left end) and Windows's (square buttons at the right, close
/// red under the pointer); more of the border itself — a gradient, a softer
/// default that does not strain the eyes (the width is a setting already);
/// and a tag ("бирка") instead of a frame: no border, a strip only as wide as
/// its label, a round tab at the top left, the rest of the row see-through.
/// A look is then another value of this and a setting to choose it
/// (`cellward frame …`, Nix, `status --json`); the drawing, the layout and
/// the hit-testing follow the value — a see-through part must not take the
/// pointer, nor start a move. Today there is one, [`LOOK`], and the border
/// has nothing of its own in it yet: its one colour is the frame's.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Look {
    pub pixels: Pixels,
    pub strip: StripWidth,
    pub buttons: ButtonsLook,
}

/// Red under the pointer for "close", as desktops have it; a deeper red
/// pressed.
const CLOSE_HOVER: Rgb = Rgb(0xe0, 0x1b, 0x24);
const CLOSE_PRESS: Rgb = Rgb(0xa5, 0x1d, 0x2d);

/// The look there is: square buttons at the right end — menu, network,
/// close —, the frame's colour at rest, a shade of it under the pointer and a
/// stronger one pressed; close red. 24 wide: 30, 36, 42, 48 pixels at the
/// usual scales.
pub const LOOK: Look = Look {
    pixels: Pixels::Opaque,
    strip: StripWidth::Full,
    buttons: ButtonsLook {
        end: End::Right,
        order: &[
            ButtonLook {
                button: Button::Menu,
                glyph: '≡',
                rest: Paint::Frame,
                hover: Paint::Shade(22),
                press: Paint::Shade(38),
            },
            ButtonLook {
                button: Button::Network,
                glyph: '⇄',
                rest: Paint::Frame,
                hover: Paint::Shade(22),
                press: Paint::Shade(38),
            },
            ButtonLook {
                button: Button::Close,
                glyph: '×',
                rest: Paint::Frame,
                hover: Paint::Fixed(CLOSE_HOVER),
                press: Paint::Fixed(CLOSE_PRESS),
            },
        ],
        width: 24,
        size: 16.0,
        shape: Shape::Cell,
    },
};

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

/// The line at `scale`: its size in device pixels and XRGB8888 pixels
/// (native-endian words), `ink` on `bg`, opaque — like the border, nothing of
/// what lies under the strip shows through (§5.9).
pub fn render(font: &FontVec, line: &Line, scale: u32, bg: Rgb) -> (i32, i32, Vec<u8>) {
    let scale = clamp_scale(scale);
    let s = scale as f32 / 120.0;
    let (w, h) = (device(line.width, scale), device(HEIGHT, scale));
    let (wu, hu) = (w.max(0) as usize, h.max(0) as usize);
    let mut coverage = vec![0f32; wu * hu];
    let px = PxScale::from(FONT_PX * s);
    let scaled = font.as_scaled(px);
    // The line's box (ascent to descent) in the middle of the strip, on a
    // whole pixel.
    let baseline =
        ((h as f32 - (scaled.ascent() - scaled.descent())) / 2.0 + scaled.ascent()).round();
    for (id, x) in &line.glyphs {
        let glyph = id.with_scale_and_position(px, point(x * s, baseline));
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
    let fg = ink(bg);
    let mut pixels = Vec::with_capacity(wu * hu * 4);
    for c in coverage {
        pixels.extend_from_slice(&LOOK.pixels.word(blend(bg, fg, c)));
    }
    (w, h, pixels)
}

/// The row of buttons at `scale` as `look` has it, on the frame's colour
/// `frame`: the size of one image in device pixels and XRGB8888 pixels of
/// every image one under the other ([`ButtonsLook::variants`]). `glyphs`:
/// each button's glyph in `font`, in the look's order. A glyph is centred
/// in its cell on a whole pixel, so that it is as crisp as the text.
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
    let mut pixels = Vec::with_capacity(look.variants() * wu * hu * 4);
    for variant in 0..look.variants() {
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
                    pixels.extend_from_slice(&LOOK.pixels.word(frame));
                    continue;
                };
                let c = match look.shape {
                    Shape::Cell => coverage[y * wu + x],
                };
                pixels.extend_from_slice(&LOOK.pixels.word(blend(bg, fg, c)));
            }
        }
    }
    (w, h, pixels)
}

/// The font, the line and the buttons' glyphs, before the proxy confines
/// itself: what its memfd has to hold is known from them.
pub struct Prepared {
    font: FontVec,
    line: Line,
    /// Each button's glyph, in [`LOOK`]'s order.
    glyphs: Vec<GlyphId>,
}

impl Prepared {
    /// `None` when the font is not a font, or the text draws nothing.
    pub fn new(font: Vec<u8>, text: &str) -> Option<Self> {
        let font = FontVec::try_from_vec(font).ok()?;
        let line = lay_out(&font, text);
        let glyphs = LOOK
            .buttons
            .order
            .iter()
            .map(|b| font.glyph_id(b.glyph))
            .collect();
        (line.width > 0).then_some(Self { font, line, glyphs })
    }

    /// Bytes of one region of the line: the line at [`MAX_SCALE`].
    fn slot_bytes(&self) -> usize {
        device(self.line.width, MAX_SCALE) as usize * device(HEIGHT, MAX_SCALE) as usize * 4
    }

    /// Bytes of one region of the buttons: every image of the row at
    /// [`MAX_SCALE`].
    fn button_bytes(&self) -> usize {
        let look = &LOOK.buttons;
        look.variants()
            * device(look.width_all(), MAX_SCALE) as usize
            * device(HEIGHT, MAX_SCALE) as usize
            * 4
    }

    /// The memfd's size: [`SLOTS`] regions of the line, then [`SLOTS`] of
    /// the buttons.
    pub fn memfd_size(&self) -> usize {
        (self.slot_bytes() + self.button_bytes()) * SLOTS
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

/// The launch's title: the line, the buttons, the frame's colour, and the
/// memfd their pixels go to.
pub struct Text {
    font: FontVec,
    line: Line,
    glyphs: Vec<GlyphId>,
    bg: Rgb,
    /// The memfd, to write the pixels with.
    file: File,
    /// The same memfd (another descriptor), for the pools.
    pub fd: Rc<OwnedFd>,
    /// The line's regions, first in the memfd, and the buttons' after them.
    title: Regions,
    buttons: Regions,
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
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.0.set(self.0.get().saturating_sub(1));
    }
}

/// The line (or the buttons) drawn at a scale, where it is in the memfd —
/// of the buttons, the first image, the others after it, `width` ×
/// `height` pixels each.
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
    /// it for writing.
    pub fn new(prepared: Prepared, bg: Rgb, memfd: OwnedFd, writer: OwnedFd) -> Self {
        let title = Regions::new(0, prepared.slot_bytes());
        let buttons = Regions::new(title.bytes(), prepared.button_bytes());
        Self {
            font: prepared.font,
            line: prepared.line,
            glyphs: prepared.glyphs,
            bg,
            file: File::from(writer),
            fd: Rc::new(memfd),
            title,
            buttons,
            clock: Cell::new(0),
        }
    }

    /// The descriptor the pixels are written with: the only one the proxy's
    /// filter lets `pwrite64` write to (`wl_proxy::filter`).
    pub fn writer(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    /// The line's width, logical pixels.
    pub fn width(&self) -> i32 {
        self.line.width
    }

    /// The pool's size: the whole memfd.
    pub fn pool_size(&self) -> i32 {
        i32::try_from(self.title.bytes() + self.buttons.bytes()).unwrap_or(i32::MAX)
    }

    /// The line at `scale`, drawn if it is not yet: in a region nobody holds,
    /// the one asked for longest ago. `None` when nothing is drawn at all
    /// and nothing can be (every region held, or the write failed).
    pub fn at(&self, scale: u32) -> Option<Drawn> {
        self.region_at(&self.title, scale, |scale| {
            render(&self.font, &self.line, scale, self.bg)
        })
    }

    /// The buttons at `scale`, every image of the row, as [`Text::at`] the
    /// line. Image `v` ([`ButtonsLook::variant`]) is `v × width × height ×
    /// 4` bytes after `offset`.
    pub fn buttons_at(&self, scale: u32) -> Option<Drawn> {
        self.region_at(&self.buttons, scale, |scale| {
            render_buttons(&self.font, &self.glyphs, &LOOK.buttons, scale, self.bg)
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
}
