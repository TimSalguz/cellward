use crate::core::image as raster;
use crate::core::{Rectangle, Size};
use crate::graphics;

use rustc_hash::{FxHashMap, FxHashSet};
use std::cell::RefCell;
use std::collections::hash_map;

#[derive(Debug)]
pub struct Pipeline {
    cache: RefCell<Cache>,
}

impl Pipeline {
    pub fn new() -> Self {
        Self {
            cache: RefCell::new(Cache::default()),
        }
    }

    pub fn load(
        &self,
        handle: &raster::Handle,
    ) -> Result<raster::Allocation, raster::Error> {
        let mut cache = self.cache.borrow_mut();
        let image = cache.allocate(handle)?;

        #[allow(unsafe_code)]
        Ok(unsafe {
            raster::allocate(handle, Size::new(image.0.width(), image.0.height()))
        })
    }

    pub fn dimensions(&self, handle: &raster::Handle) -> Option<Size<u32>> {
        let mut cache = self.cache.borrow_mut();
        let image = cache.allocate(handle).ok()?;

        Some(Size::new(image.0.width(), image.0.height()))
    }

    pub fn draw(
        &mut self,
        handle: &raster::Handle,
        filter_method: raster::FilterMethod,
        bounds: Rectangle,
        opacity: f32,
        pixels: &mut tiny_skia::PixmapMut<'_>,
        transform: tiny_skia::Transform,
        clip_mask: Option<&tiny_skia::Mask>,
        clip_bounds: Rectangle,
    ) {
        let mut cache = self.cache.borrow_mut();

        let Ok((image, source_opaque)) = cache.allocate(handle) else {
            return;
        };

        let linear = matches!(&filter_method, raster::FilterMethod::Linear);
        if !linear && opacity == 1.0 && source_opaque {
            if blit_nearest_opaque(pixels, bounds, transform, image, clip_bounds) {
                return;
            }
        }

        let width_scale = bounds.width / image.width() as f32;
        let height_scale = bounds.height / image.height() as f32;

        let transform = transform.pre_scale(width_scale, height_scale);

        let quality = match filter_method {
            raster::FilterMethod::Linear => tiny_skia::FilterQuality::Bilinear,
            raster::FilterMethod::Nearest => tiny_skia::FilterQuality::Nearest,
        };

        pixels.draw_pixmap(
            (bounds.x / width_scale) as i32,
            (bounds.y / height_scale) as i32,
            image,
            &tiny_skia::PixmapPaint {
                quality,
                opacity,
                ..Default::default()
            },
            transform,
            clip_mask,
        );
    }

    pub fn trim_cache(&mut self) {
        self.cache.borrow_mut().trim();
    }
}

fn physical_bounds(
    bounds: Rectangle,
    transform: tiny_skia::Transform,
) -> Option<(i32, i32, u32, u32)> {
    if transform.kx != 0.0
        || transform.ky != 0.0
        || transform.sx <= 0.0
        || transform.sy <= 0.0
    {
        return None;
    }
    let x0 = bounds.x * transform.sx + transform.tx;
    let y0 = bounds.y * transform.sy + transform.ty;
    let x1 = (bounds.x + bounds.width) * transform.sx + transform.tx;
    let y1 = (bounds.y + bounds.height) * transform.sy + transform.ty;
    let width = (x1 - x0).abs().ceil();
    let height = (y1 - y0).abs().ceil();
    if !x0.is_finite()
        || !y0.is_finite()
        || !width.is_finite()
        || !height.is_finite()
        || width < 1.0
        || height < 1.0
        || width > u32::MAX as f32
        || height > u32::MAX as f32
    {
        return None;
    }
    Some((x0.floor() as i32, y0.floor() as i32, width as u32, height as u32))
}

fn blit_nearest_opaque(
    pixels: &mut tiny_skia::PixmapMut<'_>,
    bounds: Rectangle,
    transform: tiny_skia::Transform,
    source: tiny_skia::PixmapRef<'_>,
    clip_bounds: Rectangle,
) -> bool {
    let Some((x, y, width, height)) = physical_bounds(bounds, transform) else {
        return false;
    };
    let left = x.max(clip_bounds.x.floor() as i32).max(0);
    let top = y.max(clip_bounds.y.floor() as i32).max(0);
    let right = (x + width as i32)
        .min((clip_bounds.x + clip_bounds.width).ceil() as i32)
        .min(pixels.width() as i32);
    let bottom = (y + height as i32)
        .min((clip_bounds.y + clip_bounds.height).ceil() as i32)
        .min(pixels.height() as i32);
    if left >= right || top >= bottom {
        return true;
    }
    let source_width = source.width() as usize;
    let source_height = source.height() as usize;
    let source = source.data();
    let destination_width = pixels.width() as i32;
    let destination = pixels.data_mut();
    for row in top..bottom {
        let source_y = ((row - y) as usize * source_height / height as usize).min(source_height - 1);
        for column in left..right {
            let source_x = ((column - x) as usize * source_width / width as usize).min(source_width - 1);
            let source_at = (source_y * source_width + source_x) * 4;
            let destination_at = (row * destination_width + column) as usize * 4;
            destination[destination_at..destination_at + 4]
                .copy_from_slice(&source[source_at..source_at + 4]);
        }
    }
    true
}

#[derive(Debug, Default)]
struct Cache {
    entries: FxHashMap<raster::Id, Option<Entry>>,
    hits: FxHashSet<raster::Id>,
}

impl Cache {
    pub fn allocate(
        &mut self,
        handle: &raster::Handle,
    ) -> Result<(tiny_skia::PixmapRef<'_>, bool), raster::Error> {
        let id = handle.id();

        if let hash_map::Entry::Vacant(entry) = self.entries.entry(id) {
            let image = match graphics::image::load(handle) {
                Ok(image) => image,
                Err(error) => {
                    let _ = entry.insert(None);

                    return Err(error);
                }
            };

            if image.width() == 0 || image.height() == 0 {
                return Err(raster::Error::Empty);
            }

            let mut buffer =
                vec![0u32; image.width() as usize * image.height() as usize];
            let mut opaque = true;

            for (i, pixel) in image.pixels().enumerate() {
                let [r, g, b, a] = pixel.0;
                opaque &= a == 255;

                buffer[i] = bytemuck::cast(
                    tiny_skia::ColorU8::from_rgba(b, g, r, a).premultiply(),
                );
            }

            let _ = entry.insert(Some(Entry {
                width: image.width(),
                height: image.height(),
                pixels: buffer,
                opaque,
            }));
        }

        let _ = self.hits.insert(id);

        Ok(self
            .entries
            .get(&id)
            .unwrap()
            .as_ref()
            .map(|entry| {
                (
                    tiny_skia::PixmapRef::from_bytes(
                        bytemuck::cast_slice(&entry.pixels),
                        entry.width,
                        entry.height,
                    )
                    .expect("Build pixmap from image bytes"),
                    entry.opaque,
                )
            })
            .expect("Image should be allocated"))
    }

    fn trim(&mut self) {
        self.entries.retain(|key, _| self.hits.contains(key));
        self.hits.clear();
    }
}

#[derive(Debug)]
struct Entry {
    width: u32,
    height: u32,
    pixels: Vec<u32>,
    opaque: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Point;

    #[test]
    fn physical_size_ignores_translation() {
        let bounds = Rectangle::new(Point::new(20.0, 30.0), Size::new(100.0, 50.0));
        let scale = tiny_skia::Transform::from_scale(2.0, 2.0);
        assert_eq!(physical_bounds(bounds, scale), Some((40, 60, 200, 100)));
        assert_eq!(
            physical_bounds(bounds, scale.post_translate(7.0, 9.0)),
            Some((47, 69, 200, 100))
        );
    }

    #[test]
    fn nearest_blit_copies_only_visible_source_pixels() {
        let source_pixels = [255u32, 0xFF00FF00, 0xFF0000FF, 0xFFFFFFFF];
        let source = tiny_skia::PixmapRef::from_bytes(
            bytemuck::cast_slice(&source_pixels),
            2,
            2,
        )
        .unwrap();
        let mut destination = tiny_skia::Pixmap::new(2, 2).unwrap();
        assert!(blit_nearest_opaque(
            &mut destination.as_mut(),
            Rectangle::new(Point::new(0.0, 0.0), Size::new(4.0, 4.0)),
            tiny_skia::Transform::identity(),
            source,
            Rectangle::new(Point::new(1.0, 1.0), Size::new(2.0, 2.0)),
        ));
        assert_eq!(destination.pixels()[5].to_color_u8().to_u32(), source_pixels[0]);
    }
}
