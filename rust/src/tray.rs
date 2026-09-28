//! The zone's mark on its programs' tray icons (owner, 2026-09-27: "поверх
//! значков — точка, полоска или цифра, обозначающая контейнер/сетевую зону").
//!
//! A tray icon is a StatusNotifierItem: the tray host asks the program for
//! its properties over the session bus (`org.freedesktop.DBus.Properties`
//! `Get`/`GetAll` on `org.kde.StatusNotifierItem`), and the program answers
//! with its picture. In a hermetic zone that answer passes the zone's bus
//! filter (`crate::bus_filter`), which knows the zone and, by the peer of the
//! connection, the container (`crate::origin`) — so the filter draws the
//! zone's colour on the picture as it goes by: a dot in the lower right
//! corner, or a bar along the bottom (`cellward tray badge dot|bar|off`). The
//! colour is the frame's (`crate::frame`): the container's own, else the
//! zone's. The tooltip gets "zone · container" as a line of its own.
//!
//! What is drawn on:
//! * `IconPixmap` and `AttentionIconPixmap`, the pictures the program sends
//!   itself — Electron and Qt send pixels, which is Claude Desktop, Discord,
//!   Telegram;
//! * `OverlayIconPixmap`, when the program sends none: an icon given by its
//!   NAME in the theme is drawn by the host from the theme, and the filter
//!   cannot draw on what it never sees; the overlay, a picture the size of
//!   the icon with only the mark on it, is how the protocol lets a host put
//!   something over it (KDE draws it; a host that ignores overlays shows such
//!   an icon unmarked — docs/HERMETICITY.md).
//!
//! Not a trust boundary, like the frame (`docs/WINDOW-FRAME.md` §5.9): the
//! program cannot remove the mark — its answer is rewritten after it, and an
//! answer the filter cannot mark (big-endian, or one that does not read)
//! reaches the tray as an error, not as an unmarked icon — but it can paint
//! a mark of another colour elsewhere in its own picture. And
//! only a hermetic zone's programs have their bus through the filter: an
//! ordinary zone's and an unconfined launch's icons are unmarked.

use std::path::Path;

use crate::cli::{read_setting, DECLARED_DIR};
use crate::container::Source;
use crate::frame::Rgb;
use crate::origin::Who;

/// The setting, a file of the config directory: `dot`, `bar` or `off`.
pub const BADGE_SETTING: &str = "tray-badge";

/// How a tray icon of a zone's program is marked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Badge {
    /// A dot of the colour in the lower right corner, with a ring that
    /// stands out on a light and a dark panel.
    Dot,
    /// A bar of the colour along the bottom.
    Bar,
    /// Not marked.
    Off,
}

/// A dot: seen on every icon, covering the least of it.
pub const DEFAULT_BADGE: Badge = Badge::Dot;

impl Badge {
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "dot" => Some(Self::Dot),
            "bar" => Some(Self::Bar),
            "off" => Some(Self::Off),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dot => "dot",
            Self::Bar => "bar",
            Self::Off => "off",
        }
    }
}

/// The badge and where it comes from: Nix (`programs.cellward.tray.badge`),
/// the local setting (`cellward tray badge`), the default. Read for every
/// answer the filter marks: a change shows at the icon's next redraw.
pub fn badge(config: &Path) -> (Badge, Source) {
    let file = |text: Option<String>| text.as_deref().and_then(Badge::parse);
    if let Some(badge) = file(crate::declared::setting(
        &config.join(DECLARED_DIR).join(BADGE_SETTING),
    )) {
        return (badge, Source::Nix);
    }
    if let Some(badge) = file(read_setting(&config.join(BADGE_SETTING))) {
        return (badge, Source::Local);
    }
    (DEFAULT_BADGE, Source::Default)
}

/// The colour of a program of `who` in `zone`: its container's frame colour,
/// else the zone's (`crate::frame::zone_color`: Nix, then the zone's own
/// setting, then the colour of its name). `zone_dir` is the zone's state
/// directory as the filter holds it — in the zone, the path to it is
/// covered.
pub fn color(zone_dir: Option<&Path>, config: &Path, zone: &str, who: &Who) -> Rgb {
    if let Who::Container(name) = who {
        if let Ok(Some((value, _))) = crate::container::own_value_in(config, name, "frame_color") {
            if let Some(color) = Rgb::parse(&value) {
                return color;
            }
        }
    }
    // Nix's word, or the colour of the name: no state directory is read.
    let (color, source) = crate::frame::zone_color(Path::new("/nonexistent"), config, zone);
    if source == Source::Nix {
        return color;
    }
    zone_dir
        .and_then(|dir| read_setting(&dir.join(crate::frame::COLOR_FILE)))
        .as_deref()
        .and_then(Rgb::parse)
        .unwrap_or(color)
}

/// "zone · container" for the tooltip, as the frame's title says it: the
/// main home is "основной"; a program whose container is not known shows
/// the zone alone.
pub fn label(zone: &str, who: &Who) -> String {
    match who {
        Who::Main => crate::frame::title_text(zone, "основной"),
        Who::Container(name) => crate::frame::title_text(zone, name),
        Who::Unknown => crate::frame::title_part(zone),
    }
}

/// The largest side of an icon that is drawn on; a larger one goes as it is
/// (a tray icon is 16–64 px, and the filter should not spend on a program
/// that sends posters).
pub const MAX_SIDE: i32 = 1024;

/// The side of the overlay picture made for an icon given by name.
pub const OVERLAY_SIDE: i32 = 32;

/// Draw `badge` of `color` on one picture: `pixels` ARGB32, four bytes a
/// pixel in network byte order, as the StatusNotifierItem specification has
/// it. `false`, and nothing drawn, for a picture that is not `width`×`height`
/// of them or is too large.
pub fn mark(width: i32, height: i32, pixels: &mut [u8], color: Rgb, badge: Badge) -> bool {
    if badge == Badge::Off
        || width <= 0
        || height <= 0
        || width > MAX_SIDE
        || height > MAX_SIDE
        || pixels.len() != (width as usize) * (height as usize) * 4
    {
        return false;
    }
    let ring = ring_color(color);
    let (w, h) = (width as usize, height as usize);
    let mut put = |x: usize, y: usize, c: Rgb| {
        let at = (y * w + x) * 4;
        pixels[at..at + 4].copy_from_slice(&[0xff, c.0, c.1, c.2]);
    };
    match badge {
        Badge::Dot => {
            // A fifth of the icon, never less than a dot a person can see.
            let r = (width.min(height) as f32 / 5.0).max(2.5);
            let cx = width as f32 - r - 0.5;
            let cy = height as f32 - r - 0.5;
            let x0 = (cx - r - 1.0).floor().max(0.0) as usize;
            let y0 = (cy - r - 1.0).floor().max(0.0) as usize;
            for y in y0..h {
                for x in x0..w {
                    let (dx, dy) = (x as f32 + 0.5 - cx, y as f32 + 0.5 - cy);
                    let d = (dx * dx + dy * dy).sqrt();
                    if d <= r - 1.0 {
                        put(x, y, color);
                    } else if d <= r {
                        put(x, y, ring);
                    }
                }
            }
        }
        Badge::Bar => {
            let t = (h / 8).max(2);
            for y in h.saturating_sub(t)..h {
                for x in 0..w {
                    put(x, y, color);
                }
            }
            // A line of the ring's colour above it, where there is room.
            if h > t + 2 {
                for x in 0..w {
                    put(x, h - t - 1, ring);
                }
            }
        }
        Badge::Off => {}
    }
    true
}

/// The overlay for an icon the host draws from the theme: transparent but
/// for the mark (see the module's words).
pub fn overlay(color: Rgb, badge: Badge) -> Vec<u8> {
    let side = OVERLAY_SIDE as usize;
    let mut pixels = vec![0u8; side * side * 4];
    mark(OVERLAY_SIDE, OVERLAY_SIDE, &mut pixels, color, badge);
    pixels
}

/// What rings the mark: dark around a light colour, white around a dark one
/// — so that it stands out on the colour of the icon under it and on either
/// kind of panel.
fn ring_color(c: Rgb) -> Rgb {
    let luminance = 0.2126 * f32::from(c.0) + 0.7152 * f32::from(c.1) + 0.0722 * f32::from(c.2);
    if luminance > 150.0 {
        Rgb(0x20, 0x20, 0x20)
    } else {
        Rgb(0xff, 0xff, 0xff)
    }
}

/// The tooltip's text with the zone's line added: the program's own text
/// first, then "zone · container" — or the line alone.
pub fn tooltip_text(own: &str, label: &str) -> String {
    if own.trim().is_empty() {
        label.to_owned()
    } else {
        format!("{own}\n{label}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pixel(pixels: &[u8], w: usize, x: usize, y: usize) -> [u8; 4] {
        let at = (y * w + x) * 4;
        [pixels[at], pixels[at + 1], pixels[at + 2], pixels[at + 3]]
    }

    #[test]
    fn the_badge_is_one_of_three_words() {
        for b in [Badge::Dot, Badge::Bar, Badge::Off] {
            assert_eq!(Badge::parse(b.as_str()), Some(b));
        }
        assert_eq!(Badge::parse(" bar\n"), Some(Badge::Bar));
        assert_eq!(Badge::parse("number"), None);
        assert_eq!(Badge::parse(""), None);
    }

    #[test]
    fn nix_over_local_over_the_default() {
        let dir = std::env::temp_dir().join(format!("vz-tray-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(DECLARED_DIR)).unwrap();
        assert_eq!(badge(&dir), (DEFAULT_BADGE, Source::Default));
        std::fs::write(dir.join(BADGE_SETTING), "bar\n").unwrap();
        assert_eq!(badge(&dir), (Badge::Bar, Source::Local));
        std::fs::write(dir.join(BADGE_SETTING), "nonsense\n").unwrap();
        assert_eq!(badge(&dir), (DEFAULT_BADGE, Source::Default));
        crate::declared::declare(&dir.join(DECLARED_DIR).join(BADGE_SETTING), "off\n");
        assert_eq!(badge(&dir), (Badge::Off, Source::Nix));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_dot_sits_in_the_lower_right_corner_with_its_ring() {
        let (w, h) = (32usize, 32usize);
        let mut pixels = vec![0u8; w * h * 4];
        let color = Rgb(0x33, 0x66, 0xff);
        assert!(mark(32, 32, &mut pixels, color, Badge::Dot));
        // The dot's middle is the colour, opaque.
        let r = 32.0f32 / 5.0;
        let c = (32.0 - r - 0.5) as usize;
        assert_eq!(pixel(&pixels, w, c, c), [0xff, 0x33, 0x66, 0xff]);
        // A dark blue gets a white ring, somewhere on its edge.
        let ringed = (0..w).any(|x| pixel(&pixels, w, x, c) == [0xff, 0xff, 0xff, 0xff]);
        assert!(ringed);
        // The rest of the icon is untouched: the upper left corner.
        assert_eq!(pixel(&pixels, w, 0, 0), [0, 0, 0, 0]);
        assert_eq!(pixel(&pixels, w, 8, 8), [0, 0, 0, 0]);
    }

    #[test]
    fn a_light_colour_gets_a_dark_ring() {
        assert_eq!(ring_color(Rgb(0xff, 0xee, 0x88)), Rgb(0x20, 0x20, 0x20));
        assert_eq!(ring_color(Rgb(0x10, 0x20, 0x80)), Rgb(0xff, 0xff, 0xff));
    }

    #[test]
    fn a_bar_runs_along_the_bottom() {
        let (w, h) = (16usize, 16usize);
        let mut pixels = vec![0u8; w * h * 4];
        let color = Rgb(0xd9, 0x4c, 0x4c);
        assert!(mark(16, 16, &mut pixels, color, Badge::Bar));
        for x in 0..w {
            assert_eq!(pixel(&pixels, w, x, h - 1), [0xff, 0xd9, 0x4c, 0x4c]);
        }
        assert_eq!(pixel(&pixels, w, 5, 0), [0, 0, 0, 0]);
    }

    #[test]
    fn a_picture_that_is_not_what_it_says_is_left_alone() {
        let mut short = vec![0u8; 15 * 16 * 4];
        assert!(!mark(16, 16, &mut short, Rgb(1, 2, 3), Badge::Dot));
        assert!(short.iter().all(|&b| b == 0));
        let mut none = Vec::new();
        assert!(!mark(0, 0, &mut none, Rgb(1, 2, 3), Badge::Dot));
        let mut huge = vec![0u8; 4];
        assert!(!mark(MAX_SIDE + 1, 1, &mut huge, Rgb(1, 2, 3), Badge::Dot));
        let mut any = vec![0u8; 16 * 16 * 4];
        assert!(!mark(16, 16, &mut any, Rgb(1, 2, 3), Badge::Off));
        assert!(any.iter().all(|&b| b == 0));
    }

    #[test]
    fn the_overlay_is_transparent_but_for_the_mark() {
        let pixels = overlay(Rgb(0x33, 0x66, 0xff), Badge::Dot);
        let side = OVERLAY_SIDE as usize;
        assert_eq!(pixels.len(), side * side * 4);
        assert_eq!(pixel(&pixels, side, 0, 0)[0], 0, "transparent corner");
        assert!(pixels.chunks(4).any(|p| p == [0xff, 0x33, 0x66, 0xff]));
    }

    #[test]
    fn the_colour_is_the_zones_own_unless_nix_says() {
        let dir = std::env::temp_dir().join(format!("vz-tray-color-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (config, zone_dir) = (dir.join("config"), dir.join("zone"));
        std::fs::create_dir_all(config.join(DECLARED_DIR)).unwrap();
        std::fs::create_dir_all(&zone_dir).unwrap();
        let who = Who::Main;
        let named = crate::frame::default_color("work");
        assert_eq!(color(Some(&zone_dir), &config, "work", &who), named);
        assert_eq!(color(None, &config, "work", &who), named);
        std::fs::write(zone_dir.join(crate::frame::COLOR_FILE), "#112233\n").unwrap();
        assert_eq!(
            color(Some(&zone_dir), &config, "work", &who),
            Rgb(0x11, 0x22, 0x33)
        );
        crate::declared::declare(
            &config
                .join(DECLARED_DIR)
                .join(crate::frame::DECLARED_COLORS),
            "work #445566\n",
        );
        assert_eq!(
            color(Some(&zone_dir), &config, "work", &who),
            Rgb(0x44, 0x55, 0x66)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_label_is_the_frames_title() {
        assert_eq!(label("work", &Who::Main), "work · основной");
        assert_eq!(label("work", &Who::Container("mail".into())), "work · mail");
        assert_eq!(label("work", &Who::Unknown), "work");
        assert_eq!(tooltip_text("", "work · mail"), "work · mail");
        assert_eq!(tooltip_text("3 new", "work · mail"), "3 new\nwork · mail");
    }
}
