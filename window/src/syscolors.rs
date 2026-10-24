//! Adapted from Stillconf's syscolors.rs (MIT OR Apache-2.0): use the same
//! KDE/GTK palette sources without adding GTK or a desktop dependency.
//! Цвета системы — для темы окна «Как в системе»: фон, текст, акцент и цвета
//! «хорошо / плохо / внимание», откуда бы их ни брала система.
//!
//! Источники по порядку:
//! 1. `$XDG_CONFIG_HOME/cellward/palette.json` — свой файл палитры: его может писать
//!    шаблон темы (noctalia, matugen, stylix), и тогда окно совпадает с системой без
//!    угадывания. Формат описан в `parse_palette_file`.
//! 2. `kdeglobals` — цветовая схема KDE: её пишут Plasma, noctalia (шаблон
//!    kcolorscheme), stylix.
//! 3. Именованные цвета GTK (`@define-color window_bg_color …` в `gtk-4.0/gtk.css` и
//!    том, что он импортирует) — так их задают libadwaita-темы, noctalia, matugen.
//!
//! Под GNOME GTK идёт раньше KDE: там `kdeglobals` бывает забытым следом давно
//! поставленной KDE-программы. И любой источник, чья тёмность спорит с порталом
//! (`color-scheme` говорит «тёмная», а фон в файле светлый), пропускается — это тот же
//! случай устаревшего файла. noctalia, например, пишет в оба:
//! `kdeglobals` View `30,30,46` и GTK `window_bg_color #1e1e2e`, акцент `#cba6f7`.

use std::path::{Path, PathBuf};

/// Цвет, 0–255.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

impl Rgb {
    /// Относительная яркость (WCAG).
    pub fn luminance(self) -> f32 {
        let ch = |v: u8| {
            let v = v as f32 / 255.0;
            if v <= 0.03928 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * ch(self.0) + 0.7152 * ch(self.1) + 0.0722 * ch(self.2)
    }

    pub fn is_dark(self) -> bool {
        self.luminance() < 0.35
    }

    /// `#rgb`, `#rrggbb` (`#rrggbbaa` — прозрачность отбрасывается), `rgb(r, g, b)`,
    /// `rgba(r, g, b, a)`, `r,g,b`.
    pub fn parse(s: &str) -> Option<Rgb> {
        let s = s.trim().trim_end_matches(';').trim();
        if let Some(hex) = s.strip_prefix('#') {
            let byte = |i: usize| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok();
            return match hex.len() {
                3 => {
                    let d = |i: usize| {
                        u8::from_str_radix(hex.get(i..i + 1)?, 16)
                            .ok()
                            .map(|v| v * 17)
                    };
                    Some(Rgb(d(0)?, d(1)?, d(2)?))
                }
                6 | 8 => Some(Rgb(byte(0)?, byte(2)?, byte(4)?)),
                _ => None,
            };
        }
        let inner = s
            .strip_prefix("rgba(")
            .or_else(|| s.strip_prefix("rgb("))
            .and_then(|r| r.strip_suffix(')'))
            .unwrap_or(s);
        let parts: Vec<&str> = inner.split(',').map(str::trim).collect();
        if !(3..=4).contains(&parts.len()) {
            return None;
        }
        let n = |p: &str| {
            p.parse::<f32>()
                .ok()
                .filter(|v| (0.0..=255.0).contains(v))
                .map(|v| v.round() as u8)
        };
        Some(Rgb(n(parts[0])?, n(parts[1])?, n(parts[2])?))
    }
}

/// Откуда цвета.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    PaletteFile(PathBuf),
    Kde(PathBuf),
    Gtk(PathBuf),
}

impl Source {
    pub fn path(&self) -> &Path {
        match self {
            Source::PaletteFile(p) | Source::Kde(p) | Source::Gtk(p) => p,
        }
    }
}

/// Цвета системы. Необязательные — чего источник не задаёт; окно подставит своё.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemColors {
    pub background: Rgb,
    pub text: Rgb,
    pub accent: Option<Rgb>,
    pub success: Option<Rgb>,
    pub danger: Option<Rgb>,
    pub warning: Option<Rgb>,
    pub source: Source,
}

/// `palette.json`: обязательны `background` и `text`, остальное — по желанию.
///
/// ```json
/// { "background": "#1e1e2e", "text": "#cdd6f4", "accent": "#cba6f7",
///   "success": "#a6e3a1", "danger": "#f38ba8", "warning": "#f9e2af" }
/// ```
pub fn parse_palette_file(text: &str, path: &Path) -> Option<SystemColors> {
    let fields: serde_json::Value = serde_json::from_str(text).ok()?;
    let color = |key: &str| {
        fields
            .get(key)
            .and_then(|v| v.as_str())
            .and_then(Rgb::parse)
    };
    Some(SystemColors {
        background: color("background")?,
        text: color("text")?,
        accent: color("accent"),
        success: color("success"),
        danger: color("danger"),
        warning: color("warning"),
        source: Source::PaletteFile(path.to_owned()),
    })
}

/// Цветовая схема KDE: фон и текст — `[Colors:View]` (содержимое окна; нет — `Window`),
/// акцент — `[Colors:Selection] BackgroundNormal`, «хорошо / плохо / внимание» —
/// `ForegroundPositive / Negative / Neutral`.
pub fn parse_kdeglobals(text: &str, path: &Path) -> Option<SystemColors> {
    let mut section = "";
    let mut get: std::collections::HashMap<(String, String), Rgb> =
        std::collections::HashMap::new();
    for line in text.lines() {
        let l = line.trim();
        if let Some(name) = l.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            section = name;
            continue;
        }
        if !section.starts_with("Colors:") {
            continue;
        }
        let Some((k, v)) = l.split_once('=') else {
            continue;
        };
        if let Some(c) = Rgb::parse(v) {
            get.insert((section.to_string(), k.trim().to_string()), c);
        }
    }
    let at = |sec: &str, key: &str| {
        get.get(&(format!("Colors:{sec}"), key.to_string()))
            .copied()
    };
    let either = |key: &str| at("View", key).or_else(|| at("Window", key));
    Some(SystemColors {
        background: either("BackgroundNormal")?,
        text: either("ForegroundNormal")?,
        accent: at("Selection", "BackgroundNormal").or_else(|| either("DecorationFocus")),
        success: either("ForegroundPositive"),
        danger: either("ForegroundNegative"),
        warning: either("ForegroundNeutral"),
        source: Source::Kde(path.to_path_buf()),
    })
}

/// Именованные цвета GTK из CSS-файлов (по порядку: позднее определение важнее).
/// Значение может ссылаться на другое имя (`@window_bg_color`).
pub fn parse_gtk_css(files: &[(PathBuf, String)]) -> Option<SystemColors> {
    let mut defs: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for (_, text) in files {
        for line in text.lines() {
            let Some(rest) = line.trim().strip_prefix("@define-color") else {
                continue;
            };
            let rest = rest.trim();
            let Some((name, value)) = rest.split_once(char::is_whitespace) else {
                continue;
            };
            defs.insert(
                name.to_string(),
                value.trim().trim_end_matches(';').trim().to_string(),
            );
        }
    }
    let resolve = |name: &str| {
        let mut v = defs.get(name)?;
        for _ in 0..8 {
            match v.strip_prefix('@') {
                Some(other) => v = defs.get(other)?,
                None => return Rgb::parse(v),
            }
        }
        None
    };
    let first = |names: &[&str]| names.iter().find_map(|n| resolve(n));
    Some(SystemColors {
        background: first(&["window_bg_color", "theme_bg_color"])?,
        text: first(&["window_fg_color", "theme_fg_color"])?,
        accent: first(&["accent_bg_color", "accent_color", "theme_selected_bg_color"]),
        success: first(&["success_color", "success_bg_color"]),
        danger: first(&["error_color", "destructive_color", "error_bg_color"]),
        warning: first(&["warning_color", "warning_bg_color"]),
        source: Source::Gtk(files.last().map(|(p, _)| p.clone()).unwrap_or_default()),
    })
}

/// `gtk.css` и то, что он импортирует (`@import url("noctalia.css");`), — в порядке
/// подключения; импорты не глубже двух уровней.
fn gtk_files(css: &Path) -> Vec<(PathBuf, String)> {
    fn walk(path: &Path, depth: u8, out: &mut Vec<(PathBuf, String)>) {
        if out.len() >= 16 {
            return;
        }
        let Some(text) = read_text(path) else { return };
        if depth < 2 {
            for line in text.lines() {
                let Some(rest) = line.trim().strip_prefix("@import") else {
                    continue;
                };
                let target = rest
                    .trim()
                    .trim_end_matches(';')
                    .trim()
                    .trim_start_matches("url(")
                    .trim_end_matches(')')
                    .trim_matches(|c| c == '"' || c == '\'');
                let target = target.strip_prefix("file://").unwrap_or(target);
                let p = Path::new(target);
                let full = if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    path.parent().unwrap_or(Path::new("/")).join(p)
                };
                walk(&full, depth + 1, out);
            }
        }
        out.push((path.to_path_buf(), text));
    }
    let mut out = Vec::new();
    walk(css, 0, &mut out);
    out
}

/// Файлы, за которыми следить: поменялся любой — перечитать.
pub fn watched_files(config_home: &Path) -> Vec<PathBuf> {
    let mut files = vec![palette_file(config_home), config_home.join("kdeglobals")];
    for gtk in ["gtk-4.0/gtk.css", "gtk-3.0/gtk.css"] {
        files.push(config_home.join(gtk));
        files.extend(
            gtk_files(&config_home.join(gtk))
                .into_iter()
                .map(|(p, _)| p),
        );
    }
    files
}

/// Отметка одного файла: куда ведёт ссылка, время изменения и размер.
pub type Mark = Option<(Option<PathBuf>, std::time::SystemTime, u64)>;

/// Отметка файлов — дешёвый способ заметить смену. Куда ведёт ссылка — тоже: Home
/// Manager кладёт `~/.config/gtk-4.0/gtk.css` ссылкой в `/nix/store`, где у всех
/// файлов одно время (1970) и новая тема может совпасть по размеру.
pub fn signature(files: &[PathBuf]) -> Vec<Mark> {
    files
        .iter()
        .map(|f| {
            let link = std::fs::read_link(f).ok();
            let m = std::fs::metadata(f).ok()?;
            Some((link, m.modified().ok()?, m.len()))
        })
        .collect()
}

pub fn palette_file(config_home: &Path) -> PathBuf {
    config_home.join("cellward/palette.json")
}

/// `$XDG_CONFIG_HOME`, без неё — `~/.config`.
pub fn config_home() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
}

/// Цвета системы: первый годный источник (см. докстринг модуля). `desktop` —
/// `XDG_CURRENT_DESKTOP`; `portal_dark` — что сказал портал о тёмности.
pub fn read(config_home: &Path, desktop: &str, portal_dark: Option<bool>) -> Option<SystemColors> {
    let agrees = |c: &SystemColors| portal_dark.is_none_or(|d| d == c.background.is_dark());
    let own = palette_file(config_home);
    // Свой файл — выбор человека: портал ему не указ.
    if let Some(c) = read_text(&own).and_then(|t| parse_palette_file(&t, &own)) {
        return Some(c);
    }
    let kde = || {
        let p = config_home.join("kdeglobals");
        read_text(&p)
            .and_then(|t| parse_kdeglobals(&t, &p))
            .filter(agrees)
    };
    let gtk = || {
        ["gtk-4.0/gtk.css", "gtk-3.0/gtk.css"]
            .iter()
            .find_map(|g| parse_gtk_css(&gtk_files(&config_home.join(g))))
            .filter(agrees)
    };
    let gnome = desktop.split(':').any(|d| d.eq_ignore_ascii_case("GNOME"))
        && !desktop.split(':').any(|d| d.eq_ignore_ascii_case("KDE"));
    if gnome {
        gtk().or_else(kde)
    } else {
        kde().or_else(gtk)
    }
}

fn read_text(path: &Path) -> Option<String> {
    use std::io::Read;
    let mut text = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(256 * 1024 + 1)
        .read_to_string(&mut text)
        .ok()?;
    (text.len() <= 256 * 1024).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_sources_keep_background_text_and_accent() {
        let p = Path::new("/fixture/palette.json");
        let colors = parse_palette_file(
            r##"{ "background": "#1e1e2e", "text": "#cdd6f4", "accent": "#cba6f7" }"##,
            p,
        )
        .unwrap();
        assert_eq!(colors.background, Rgb(30, 30, 46));
        assert_eq!(colors.accent, Some(Rgb(203, 166, 247)));
        let gtk = parse_gtk_css(&[(PathBuf::from("gtk.css"), "@define-color bg #1e1e2e;\n@define-color window_bg_color @bg;\n@define-color window_fg_color #cdd6f4;\n@define-color accent_bg_color #cba6f7;".into())]).unwrap();
        assert_eq!(gtk.background, colors.background);
        assert_eq!(gtk.text, colors.text);
        assert_eq!(gtk.accent, colors.accent);
        let kde = parse_kdeglobals("[Colors:View]\nBackgroundNormal=30,30,46\nForegroundNormal=205,214,244\n[Colors:Selection]\nBackgroundNormal=203,166,247", p).unwrap();
        assert_eq!(kde.background, colors.background);
        assert_eq!(kde.accent, colors.accent);
    }

    #[test]
    fn malformed_or_cyclic_colors_do_not_produce_a_palette() {
        assert!(Rgb::parse("rgb(999,0,0)").is_none());
        assert!(parse_palette_file("{}", Path::new("palette.json")).is_none());
        assert!(parse_gtk_css(&[(
            PathBuf::from("gtk.css"),
            "@define-color window_bg_color @window_bg_color;\n@define-color window_fg_color #fff;"
                .into()
        )])
        .is_none());
    }
}
