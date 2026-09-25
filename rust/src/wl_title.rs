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
        Rgb(0xff, 0xff, 0xff)
    } else {
        Rgb(0x14, 0x14, 0x14)
    }
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
    let mix =
        |b: u8, f: u8, c: f32| (f32::from(b) + (f32::from(f) - f32::from(b)) * c).round() as u8;
    let mut pixels = Vec::with_capacity(wu * hu * 4);
    for c in coverage {
        pixels.extend_from_slice(
            &Rgb(mix(bg.0, fg.0, c), mix(bg.1, fg.1, c), mix(bg.2, fg.2, c)).xrgb8888(),
        );
    }
    (w, h, pixels)
}

/// The font and the line, before the proxy confines itself: what its memfd
/// has to hold is known from them.
pub struct Prepared {
    font: FontVec,
    line: Line,
}

impl Prepared {
    /// `None` when the font is not a font, or the text draws nothing.
    pub fn new(font: Vec<u8>, text: &str) -> Option<Self> {
        let font = FontVec::try_from_vec(font).ok()?;
        let line = lay_out(&font, text);
        (line.width > 0).then_some(Self { font, line })
    }

    /// Bytes of one region: the line at [`MAX_SCALE`].
    fn slot_bytes(&self) -> usize {
        device(self.line.width, MAX_SCALE) as usize * device(HEIGHT, MAX_SCALE) as usize * 4
    }

    /// The memfd's size: [`SLOTS`] regions.
    pub fn memfd_size(&self) -> usize {
        self.slot_bytes() * SLOTS
    }
}

/// A region's scale (0: nothing drawn yet), how many buffers of it the
/// compositor holds, and when it was last asked for.
struct Slot {
    scale: u32,
    leases: Rc<Cell<u32>>,
    used: u64,
}

/// The launch's title: the line, its colour, and the memfd its pixels go to.
pub struct Text {
    font: FontVec,
    line: Line,
    bg: Rgb,
    /// The memfd, to write the pixels with.
    file: File,
    /// The same memfd (another descriptor), for the pools.
    pub fd: Rc<OwnedFd>,
    slot_bytes: usize,
    slots: RefCell<Vec<Slot>>,
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

/// The line drawn at a scale, where it is in the memfd.
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
        let slot_bytes = prepared.slot_bytes();
        Self {
            font: prepared.font,
            line: prepared.line,
            bg,
            file: File::from(writer),
            fd: Rc::new(memfd),
            slot_bytes,
            slots: RefCell::new(
                (0..SLOTS)
                    .map(|_| Slot {
                        scale: 0,
                        leases: Rc::new(Cell::new(0)),
                        used: 0,
                    })
                    .collect(),
            ),
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
        i32::try_from(self.slot_bytes * SLOTS).unwrap_or(i32::MAX)
    }

    /// The line at `scale`, drawn if it is not yet: in a region nobody holds,
    /// the one asked for longest ago. `None` when nothing is drawn at all
    /// and nothing can be (every region held, or the write failed).
    pub fn at(&self, scale: u32) -> Option<Drawn> {
        let scale = clamp_scale(scale);
        let now = self.clock.get() + 1;
        self.clock.set(now);
        let mut slots = self.slots.borrow_mut();
        let found = slots.iter().position(|s| s.scale == scale).or_else(|| {
            let free = (0..slots.len())
                .filter(|&i| slots[i].leases.get() == 0)
                .min_by_key(|&i| slots[i].used)?;
            let (w, h, pixels) = render(&self.font, &self.line, scale, self.bg);
            let offset = (free * self.slot_bytes) as u64;
            slots[free].scale = 0;
            if pixels.len() > self.slot_bytes || self.file.write_all_at(&pixels, offset).is_err() {
                return None;
            }
            debug_assert_eq!(pixels.len(), (w * h * 4) as usize);
            slots[free].scale = scale;
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
            offset: (at * self.slot_bytes) as i32,
            width: device(self.line.width, slot.scale),
            height: device(HEIGHT, slot.scale),
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
        drop((one, again, fresh));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
