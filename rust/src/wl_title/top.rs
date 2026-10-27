//! One alpha image for the whole rounded top edge: rings, title and buttons.
//! No background is painted twice, including when the title is revealed.
use super::*;

pub const MAX_WIDTH: i32 = 8192;
pub const MAX_HEIGHT: i32 = MAX_OUTER_RADIUS + MAX_BORDER + HEIGHT;
pub const TOP_SLOTS: usize = 2;
pub fn slot_bytes() -> usize {
    device(MAX_WIDTH, MAX_SCALE) as usize * device(MAX_HEIGHT, MAX_SCALE) as usize * 4
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TopSpec {
    pub width: i32,
    pub height: i32,
    pub border: i32,
    pub radius: i32,
    pub edge_height: i32,
    pub content_y: Option<i32>,
    pub visible: bool,
    pub lit: Option<Lit>,
}

impl TopSpec {
    pub fn depth(&self, x: f32, y: f32) -> f32 {
        let edge = x.min(self.width as f32 - x);
        let r = self.radius.min(self.width / 2).max(0) as f32;
        if edge < r && y < r {
            r - ((r - edge).powi(2) + (r - y).powi(2)).sqrt()
        } else {
            edge.min(y)
        }
    }

    pub fn title_at(&self, x: f32, y: f32) -> bool {
        let b = self.border as f32;
        self.visible && x >= b && x <= self.width as f32 - b && y >= b && y < b + HEIGHT as f32
    }

    pub fn input_at(&self, x: f32, y: f32) -> bool {
        let d = self.depth(x, y);
        d >= 0.0
            && ((y < self.edge_height as f32 && d < self.border as f32)
                || (self.title_at(x, y) && y >= (self.border + 2) as f32))
    }
}

pub fn render_top(text: &Text, spec: TopSpec, scale: u32) -> (i32, i32, Vec<u8>) {
    let (w, h) = (device(spec.width, scale), device(spec.height, scale));
    let s = clamp_scale(scale) as f32 / 120.0;
    let b = device(spec.border, scale);
    let row_w = (w - 2 * b).max(0);
    let row_h = device(HEIGHT, scale);
    let layout = crate::wl_frame::title_layout(spec.width - 2 * spec.border, &text.look.buttons);
    let mut row = text.bg.xrgb8888().repeat(row_w as usize * row_h as usize);
    if spec.visible {
        let (tw, th, line) = render(&text.font, &text.line, scale, text.bg);
        let tx = device(layout.text_x, scale);
        let shown = device((layout.room - 2 * PAD).max(0), scale)
            .min(tw)
            .min((row_w - tx).max(0));
        for y in 0..if shown > 0 { th.min(row_h) } else { 0 } {
            let src = (y * tw * 4) as usize;
            let dst = ((y * row_w + tx) * 4) as usize;
            row[dst..dst + shown as usize * 4]
                .copy_from_slice(&line[src..src + shown as usize * 4]);
        }
        if let Some(at) = layout.buttons {
            let (bw, bh, buttons) =
                render_buttons(&text.font, &text.glyphs, &text.look.buttons, scale, text.bg);
            let variant = text.look.buttons.variant(spec.lit);
            let base = variant * bw as usize * bh as usize * 4;
            let at = device(at, scale);
            let across = bw.min((row_w - at).max(0));
            for y in 0..bh.min(row_h) {
                let src = base + (y * bw * 4) as usize;
                let dst = ((y * row_w + at) * 4) as usize;
                row[dst..dst + across as usize * 4]
                    .copy_from_slice(&buttons[src..src + across as usize * 4]);
            }
        }
    }
    let squares = text.look.squares(text.frame);
    let mut sum = 0;
    let rings: Vec<_> = text
        .look
        .rings(spec.border)
        .into_iter()
        .filter_map(|(width, index)| {
            sum += width;
            match squares[index] {
                Square::Color(c) => Some((sum as f32, c)),
                _ => None,
            }
        })
        .collect();
    let mut pixels = vec![0; w as usize * h as usize * 4];
    let inner = spec.content_y.and_then(|y| {
        let (top, bottom) = text.look.corners();
        (top > 0).then(|| {
            let (side, _, bytes) =
                render_corners_inset(top, bottom, text.look.top_inset, scale, text.bg);
            (device(y, scale), side, bytes)
        })
    });
    for y in 0..h {
        for x in 0..w {
            let (lx, ly) = ((x as f32 + 0.5) / s, (y as f32 + 0.5) / s);
            let depth = spec.depth(lx, ly);
            let title = spec.title_at(lx, ly);
            let ring = if ly < spec.edge_height as f32 {
                rings.iter().find(|(end, _)| depth <= *end)
            } else {
                None
            };
            let mut color = if let Some((_, color)) = ring {
                *color
            } else if title {
                // Logical coverage and rounded raster origins can disagree by
                // a pixel at fractional scales. Fill the entire title region,
                // including pixels outside the rounded text/button raster.
                if x >= b && x < w - b && y >= b && y < b + row_h {
                    let at = (((y - b) * row_w + x - b) * 4) as usize;
                    let word = u32::from_ne_bytes(row[at..at + 4].try_into().unwrap());
                    Rgb((word >> 16) as u8, (word >> 8) as u8, word as u8)
                } else {
                    text.bg
                }
            } else {
                if let Some((iy, side, bytes)) = &inner {
                    if y >= *iy && y < iy + side {
                        let left = x - b;
                        let right = x - (w - b - side);
                        let src = if (0..*side).contains(&left) {
                            Some(((y - iy) * side + left) * 4)
                        } else if (0..*side).contains(&right) {
                            Some((side * side + (y - iy) * side + right) * 4)
                        } else {
                            None
                        };
                        if let Some(src) = src {
                            let at = ((y * w + x) * 4) as usize;
                            pixels[at..at + 4]
                                .copy_from_slice(&bytes[src as usize..src as usize + 4]);
                        }
                    }
                }
                continue;
            };
            let inner_cover = ((spec.border as f32 - depth) * s + 0.5).clamp(0.0, 1.0);
            // A revealed title backs the border's inner antialiased edge.
            // Blend into its background, never into transparency: these are
            // adjacent parts of one opaque surface, including fractional pixels.
            let backed = spec.visible && ly < (spec.border + HEIGHT) as f32;
            if backed && ring.is_some() && inner_cover < 1.0 {
                let mix = |edge: u8, bg: u8| {
                    (edge as f32 * inner_cover + bg as f32 * (1.0 - inner_cover)).round() as u8
                };
                color = Rgb(
                    mix(color.0, text.bg.0),
                    mix(color.1, text.bg.1),
                    mix(color.2, text.bg.2),
                );
            }
            let cover = ((depth * s + 0.5).clamp(0.0, 1.0)).min(if title || backed {
                1.0
            } else {
                inner_cover
            });
            let at = ((y * w + x) * 4) as usize;
            pixels[at..at + 4].copy_from_slice(&premultiplied(color, cover));
        }
    }
    (w, h, pixels)
}
