//! An image of the clipboard history as a small picture of its bubble.
//!
//! What is copied in a container is untrusted, and the window is the host's:
//! only PNG is decoded, by the `png` crate (no codecs of iced's or `image`'s),
//! within limits on what it may allocate and on the image's size, so a small
//! file that unpacks into gigabytes is refused, not decoded. The picture is
//! scaled down here to the height asked for; the decoded image is dropped.

use std::io::Cursor;

/// The decoder's allocations at most.
const MAX_DECODED: usize = 256 << 20;
/// An image wider or taller than this is not decoded.
const MAX_SIDE: u32 = 16_384;
/// The widest a thumbnail is drawn.
pub const MAX_WIDTH: u32 = 480;

/// A thumbnail: its size and its pixels, RGBA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thumb {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

/// `png` scaled down to `height` pixels high (never up), at most
/// [`MAX_WIDTH`] wide; `Err` says why not.
pub fn of_png(png: &[u8], height: u32) -> Result<Thumb, String> {
    decode_png(png, height, MAX_WIDTH)
}

/// A separate, explicitly opened preview keeps the original pixels. Never
/// enlarge the already reduced list thumbnail to inspect screenshot text.
pub fn full_png(png: &[u8]) -> Result<Thumb, String> {
    decode_png(png, MAX_SIDE, MAX_SIDE)
}

fn decode_png(png: &[u8], height: u32, max_width: u32) -> Result<Thumb, String> {
    let mut decoder =
        png::Decoder::new_with_limits(Cursor::new(png), png::Limits { bytes: MAX_DECODED });
    decoder.set_transformations(png::Transformations::normalize_to_color8());
    let mut reader = decoder.read_info().map_err(|e| e.to_string())?;
    let (w, h) = (reader.info().width, reader.info().height);
    if w == 0 || h == 0 || w > MAX_SIDE || h > MAX_SIDE {
        return Err(format!("картинка {w}×{h} — слишком большая"));
    }
    let size = reader
        .output_buffer_size()
        .filter(|s| *s <= MAX_DECODED)
        .ok_or("картинка слишком большая")?;
    let mut buf = vec![0; size];
    let info = reader.next_frame(&mut buf).map_err(|e| e.to_string())?;
    let channels = match info.color_type {
        png::ColorType::Grayscale => 1,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 4,
        png::ColorType::Indexed => return Err("палитра не развёрнута".to_owned()),
    };
    let pixel = |x: u32, y: u32| -> [u8; 4] {
        let at = y as usize * info.line_size + x as usize * channels;
        let p = &buf[at..at + channels];
        match channels {
            1 => [p[0], p[0], p[0], 255],
            2 => [p[0], p[0], p[0], p[1]],
            3 => [p[0], p[1], p[2], 255],
            _ => [p[0], p[1], p[2], p[3]],
        }
    };
    let (tw, th) = fit(info.width, info.height, height.max(1), max_width);
    let output_size = (tw as usize)
        .checked_mul(th as usize)
        .and_then(|n| n.checked_mul(4))
        .filter(|n| *n <= MAX_DECODED)
        .ok_or("картинка слишком большая")?;
    let mut rgba = Vec::with_capacity(output_size);
    // Each pixel of the thumbnail the mean of the block of the image under
    // it: a scaled-down screenshot keeps its text readable as a texture.
    for ty in 0..th {
        let y0 = u64::from(ty) * u64::from(info.height) / u64::from(th);
        let y1 = (u64::from(ty + 1) * u64::from(info.height) / u64::from(th)).max(y0 + 1);
        for tx in 0..tw {
            let x0 = u64::from(tx) * u64::from(info.width) / u64::from(tw);
            let x1 = (u64::from(tx + 1) * u64::from(info.width) / u64::from(tw)).max(x0 + 1);
            // At most a few samples a side: a huge image costs no more.
            let step_y = ((y1 - y0) / 4).max(1);
            let step_x = ((x1 - x0) / 4).max(1);
            let mut sum = [0u64; 4];
            let mut n = 0u64;
            let mut y = y0;
            while y < y1 {
                let mut x = x0;
                while x < x1 {
                    let p = pixel(x as u32, y as u32);
                    for (s, v) in sum.iter_mut().zip(p) {
                        *s += u64::from(v);
                    }
                    n += 1;
                    x += step_x;
                }
                y += step_y;
            }
            rgba.extend(sum.map(|s| (s / n) as u8));
        }
    }
    Ok(Thumb {
        width: tw,
        height: th,
        rgba,
    })
}

/// A `w`×`h` image's size scaled down to `height` high, no wider than
/// `max_width`, never scaled up, at least a pixel each way.
pub fn fit(w: u32, h: u32, height: u32, max_width: u32) -> (u32, u32) {
    let mut scale = f64::from(height) / f64::from(h);
    if f64::from(w) * scale > f64::from(max_width) {
        scale = f64::from(max_width) / f64::from(w);
    }
    let scale = scale.min(1.0);
    let tw = ((f64::from(w) * scale).round() as u32).max(1);
    let th = ((f64::from(h) * scale).round() as u32).max(1);
    (tw, th)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png_of(w: u32, h: u32, color: png::ColorType, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut e = png::Encoder::new(&mut out, w, h);
        e.set_color(color);
        e.set_depth(png::BitDepth::Eight);
        e.write_header().unwrap().write_image_data(data).unwrap();
        out
    }

    #[test]
    fn a_thumbnail_is_the_height_asked_and_never_larger() {
        assert_eq!(fit(1000, 500, 60, 480), (120, 60));
        assert_eq!(fit(4000, 100, 60, 480), (480, 12));
        assert_eq!(fit(20, 10, 60, 480), (20, 10), "never scaled up");
        assert_eq!(fit(1, 10_000, 60, 480), (1, 60));
    }

    #[test]
    fn full_preview_keeps_original_pixels_instead_of_enlarging_a_thumbnail() {
        let data: Vec<u8> = (0..800).map(|i| (i % 256) as u8).collect();
        let png = png_of(800, 1, png::ColorType::Grayscale, &data);
        let small = of_png(&png, 60).unwrap();
        let full = full_png(&png).unwrap();
        assert_eq!(small.width, MAX_WIDTH);
        assert_eq!((full.width, full.height), (800, 1));
        for (pixel, value) in full.rgba.chunks_exact(4).zip(data) {
            assert_eq!(pixel, &[value, value, value, 255]);
        }
    }

    #[test]
    fn a_png_is_scaled_down_as_its_mean() {
        // Left half black, right half white, 8×4, grey.
        let data: Vec<u8> = (0..4)
            .flat_map(|_| (0..8).map(|x| if x < 4 { 0 } else { 255 }))
            .collect();
        let t = of_png(&png_of(8, 4, png::ColorType::Grayscale, &data), 2).unwrap();
        assert_eq!((t.width, t.height), (4, 2));
        assert_eq!(&t.rgba[..4], &[0, 0, 0, 255]);
        assert_eq!(&t.rgba[12..16], &[255, 255, 255, 255]);
        let rgba = png_of(1, 1, png::ColorType::Rgba, &[1, 2, 3, 4]);
        assert_eq!(of_png(&rgba, 60).unwrap().rgba, [1, 2, 3, 4]);
    }

    #[test]
    fn what_is_no_png_or_too_large_is_refused() {
        assert!(of_png(b"not a png", 60).is_err());
        let wide = png_of(
            MAX_SIDE + 1,
            1,
            png::ColorType::Grayscale,
            &vec![0; (MAX_SIDE + 1) as usize],
        );
        assert!(of_png(&wide, 60).is_err());
    }
}
