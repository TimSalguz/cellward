//! The zone border's settings (`docs/WINDOW-FRAME.md` §0а, §11): its colour
//! per zone, its width, and the switch that hides every border — for sharing
//! the screen, where the owner wants windows without it.
//!
//! What draws it is the Wayland proxy (`crate::wl_frame`); what is read here
//! is handed to it on the command line of `wl-sandbox` (`--frame`), except the
//! switch, which the supervisor reads again for every connection
//! (`--frame-switch`): a window opened after `vpn-zone frame hide` comes up
//! without a border even in a program started before.
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

use std::path::Path;

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

/// Four logical pixels: a whole number of pixels at the usual scales (5 at
/// 1.25, 6 at 1.5, 7 at 1.75, 8 at 2), so the border meets the window
/// without a half pixel (§5.6), and seen at a glance without eating the
/// window.
pub const DEFAULT_WIDTH: i32 = 4;
/// Wider than this is not a border any more.
pub const MAX_WIDTH: i32 = 32;

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

/// HSV (hue in degrees, the rest in 0..=1) to RGB.
fn hsv(h: f64, s: f64, v: f64) -> Rgb {
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
    if let Ok(text) = std::fs::read_to_string(config.join(DECLARED_DIR).join(DECLARED_COLORS)) {
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

/// A width setting file: `None` when absent or not a width.
fn width_file(path: &Path) -> Option<i32> {
    read_setting(path)?
        .trim()
        .parse()
        .ok()
        .filter(|w| (1..=MAX_WIDTH).contains(w))
}

/// The border's width in logical pixels and where it comes from.
pub fn width(config: &Path) -> (i32, Source) {
    if let Some(w) = width_file(&config.join(DECLARED_DIR).join(WIDTH_SETTING)) {
        return (w, Source::Nix);
    }
    if let Some(w) = width_file(&config.join(WIDTH_SETTING)) {
        return (w, Source::Local);
    }
    (DEFAULT_WIDTH, Source::Default)
}

/// Whether the switch hides the borders now. Only `hidden` hides: a file
/// that cannot be read, or says something else, leaves them — the border is
/// the default, and nothing a zone can reach can remove it (see above).
pub fn hidden(config: &Path) -> bool {
    let value = read_setting(&config.join(DECLARED_DIR).join(SWITCH_SETTING))
        .or_else(|| read_setting(&config.join(SWITCH_SETTING)));
    value.is_some_and(|v| v.trim() == "hidden")
}

/// What `wl-sandbox --frame` carries: the colour and the width, `rrggbb:w`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    pub color: Rgb,
    pub width: i32,
}

impl Frame {
    /// The zone's border as the settings have it now.
    pub fn of_zone(state: &Path, config: &Path, zone: &str) -> Self {
        Self {
            color: zone_color(state, config, zone).0,
            width: width(config).0,
        }
    }

    pub fn to_arg(self) -> String {
        format!("{}:{}", &self.color.hex()[1..], self.width)
    }

    pub fn parse_arg(text: &str) -> Option<Self> {
        let (color, width) = text.split_once(':')?;
        let width: i32 = width.parse().ok()?;
        if !(1..=MAX_WIDTH).contains(&width) {
            return None;
        }
        Some(Self {
            color: Rgb::parse(color)?,
            width,
        })
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
        fs::write(
            config.join(DECLARED_DIR).join(DECLARED_COLORS),
            "de #ffffff\nnl #ff0000\nnl2 #00ff00\n",
        )
        .unwrap();
        assert_eq!(
            zone_color(&state, &config, "nl"),
            (Rgb(255, 0, 0), Source::Nix)
        );
        // Another zone's line is not this one's, nor is a broken one.
        fs::write(
            config.join(DECLARED_DIR).join(DECLARED_COLORS),
            "nl2 #00ff00\nnl nonsense\n",
        )
        .unwrap();
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
        fs::write(config.join(DECLARED_DIR).join(WIDTH_SETTING), "2\n").unwrap();
        assert_eq!(width(&config), (2, Source::Nix));
        for bad in ["0", "-3", "33", "wide", ""] {
            fs::write(config.join(DECLARED_DIR).join(WIDTH_SETTING), bad).unwrap();
            assert_eq!(width(&config), (7, Source::Local), "{bad:?}");
        }
        assert!(!hidden(&config));
        fs::write(config.join(SWITCH_SETTING), "shown").unwrap();
        assert!(!hidden(&config));
        fs::write(config.join(SWITCH_SETTING), "hidden\n").unwrap();
        assert!(hidden(&config));
        fs::write(config.join(SWITCH_SETTING), "hide").unwrap();
        assert!(!hidden(&config), "only `hidden` hides");
        let _ = fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn the_argument_goes_there_and_back() {
        let f = Frame {
            color: Rgb(1, 2, 255),
            width: 6,
        };
        assert_eq!(f.to_arg(), "0102ff:6");
        assert_eq!(Frame::parse_arg(&f.to_arg()), Some(f));
        for bad in [
            "0102ff",
            "0102ff:0",
            "0102ff:99",
            "zz02ff:4",
            ":4",
            "0102ff:x",
        ] {
            assert_eq!(Frame::parse_arg(bad), None, "{bad:?}");
        }
    }
}
