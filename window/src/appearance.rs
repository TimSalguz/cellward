//! Window-only appearance preferences. No container or network policy lives here.
use std::path::PathBuf;

use iced::Theme;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThemeChoice {
    #[default]
    System,
    Light,
    Dark,
    CatppuccinLatte,
    CatppuccinFrappe,
    CatppuccinMacchiato,
    CatppuccinMocha,
    Nord,
    Dracula,
    GruvboxLight,
    GruvboxDark,
    SolarizedLight,
    SolarizedDark,
    TokyoNight,
    TokyoNightStorm,
    TokyoNightLight,
    KanagawaWave,
    KanagawaDragon,
    KanagawaLotus,
    Moonfly,
    Nightfly,
    Oxocarbon,
}

impl ThemeChoice {
    pub const ALL: [Self; 22] = [
        Self::System,
        Self::Light,
        Self::Dark,
        Self::CatppuccinLatte,
        Self::CatppuccinFrappe,
        Self::CatppuccinMacchiato,
        Self::CatppuccinMocha,
        Self::Nord,
        Self::Dracula,
        Self::GruvboxLight,
        Self::GruvboxDark,
        Self::SolarizedLight,
        Self::SolarizedDark,
        Self::TokyoNight,
        Self::TokyoNightStorm,
        Self::TokyoNightLight,
        Self::KanagawaWave,
        Self::KanagawaDragon,
        Self::KanagawaLotus,
        Self::Moonfly,
        Self::Nightfly,
        Self::Oxocarbon,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Light => "light",
            Self::Dark => "dark",
            Self::CatppuccinLatte => "catppuccin-latte",
            Self::CatppuccinFrappe => "catppuccin-frappe",
            Self::CatppuccinMacchiato => "catppuccin-macchiato",
            Self::CatppuccinMocha => "catppuccin-mocha",
            Self::Nord => "nord",
            Self::Dracula => "dracula",
            Self::GruvboxLight => "gruvbox-light",
            Self::GruvboxDark => "gruvbox-dark",
            Self::SolarizedLight => "solarized-light",
            Self::SolarizedDark => "solarized-dark",
            Self::TokyoNight => "tokyo-night",
            Self::TokyoNightStorm => "tokyo-night-storm",
            Self::TokyoNightLight => "tokyo-night-light",
            Self::KanagawaWave => "kanagawa-wave",
            Self::KanagawaDragon => "kanagawa-dragon",
            Self::KanagawaLotus => "kanagawa-lotus",
            Self::Moonfly => "moonfly",
            Self::Nightfly => "nightfly",
            Self::Oxocarbon => "oxocarbon",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::System => "System",
            Self::Light => "Light",
            Self::Dark => "Dark",
            Self::CatppuccinLatte => "Catppuccin Latte",
            Self::CatppuccinFrappe => "Catppuccin Frappé",
            Self::CatppuccinMacchiato => "Catppuccin Macchiato",
            Self::CatppuccinMocha => "Catppuccin Mocha",
            Self::Nord => "Nord",
            Self::Dracula => "Dracula",
            Self::GruvboxLight => "Gruvbox Light",
            Self::GruvboxDark => "Gruvbox Dark",
            Self::SolarizedLight => "Solarized Light",
            Self::SolarizedDark => "Solarized Dark",
            Self::TokyoNight => "Tokyo Night",
            Self::TokyoNightStorm => "Tokyo Night Storm",
            Self::TokyoNightLight => "Tokyo Night Light",
            Self::KanagawaWave => "Kanagawa Wave",
            Self::KanagawaDragon => "Kanagawa Dragon",
            Self::KanagawaLotus => "Kanagawa Lotus",
            Self::Moonfly => "Moonfly",
            Self::Nightfly => "Nightfly",
            Self::Oxocarbon => "Oxocarbon",
        }
    }

    pub fn from_key(key: &str) -> Self {
        Self::ALL
            .into_iter()
            .find(|choice| choice.key() == key)
            .unwrap_or_default()
    }

    /// Prefer actual desktop palette files; fall back to iced's live system
    /// light/dark detection when no semantic palette is available.
    pub fn theme(self) -> Option<Theme> {
        Some(match self {
            Self::System => return system_theme(),
            Self::Light => Theme::Light,
            Self::Dark => Theme::Dark,
            Self::CatppuccinLatte => Theme::CatppuccinLatte,
            Self::CatppuccinFrappe => Theme::CatppuccinFrappe,
            Self::CatppuccinMacchiato => Theme::CatppuccinMacchiato,
            Self::CatppuccinMocha => Theme::CatppuccinMocha,
            Self::Nord => Theme::Nord,
            Self::Dracula => Theme::Dracula,
            Self::GruvboxLight => Theme::GruvboxLight,
            Self::GruvboxDark => Theme::GruvboxDark,
            Self::SolarizedLight => Theme::SolarizedLight,
            Self::SolarizedDark => Theme::SolarizedDark,
            Self::TokyoNight => Theme::TokyoNight,
            Self::TokyoNightStorm => Theme::TokyoNightStorm,
            Self::TokyoNightLight => Theme::TokyoNightLight,
            Self::KanagawaWave => Theme::KanagawaWave,
            Self::KanagawaDragon => Theme::KanagawaDragon,
            Self::KanagawaLotus => Theme::KanagawaLotus,
            Self::Moonfly => Theme::Moonfly,
            Self::Nightfly => Theme::Nightfly,
            Self::Oxocarbon => Theme::Oxocarbon,
        })
    }
}

impl std::fmt::Display for ThemeChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

fn path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(base.join("cellward").join("appearance.conf"))
}

pub fn load() -> ThemeChoice {
    path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| {
            s.lines()
                .find_map(|line| line.strip_prefix("theme=").map(ThemeChoice::from_key))
        })
        .unwrap_or_default()
}

pub fn save(choice: ThemeChoice) -> std::io::Result<()> {
    let path = path().ok_or_else(|| std::io::Error::other("HOME and XDG_CONFIG_HOME are unset"))?;
    let dir = path.parent().expect("appearance path has a parent");
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".appearance.{}.tmp", std::process::id()));
    std::fs::write(&tmp, format!("theme={}\n", choice.key()))?;
    std::fs::rename(&tmp, path)
}

fn color(c: crate::syscolors::Rgb) -> iced::Color {
    iced::Color::from_rgb8(c.0, c.1, c.2)
}

fn palette_theme(s: crate::syscolors::SystemColors) -> Theme {
    use iced::theme::Palette;
    let base = if s.background.is_dark() {
        Palette::DARK
    } else {
        Palette::LIGHT
    };
    Theme::custom(
        format!("System ({})", s.source.path().display()),
        Palette {
            background: color(s.background),
            text: color(s.text),
            primary: s.accent.map(color).unwrap_or(base.primary),
            success: s.success.map(color).unwrap_or(base.success),
            danger: s.danger.map(color).unwrap_or(base.danger),
            warning: s
                .warning
                .filter(|c| Some(*c) != s.success)
                .map(color)
                .unwrap_or(base.warning),
        },
    )
}

fn theme_cache() -> &'static std::sync::Mutex<Option<(std::time::Instant, Option<Theme>)>> {
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<Option<(Instant, Option<Theme>)>>> = OnceLock::new();
    use std::time::Instant;
    CACHE.get_or_init(|| Mutex::new(None))
}

fn system_theme() -> Option<Theme> {
    use std::time::{Duration, Instant};
    let mut cache = theme_cache().lock().ok()?;
    if let Some((at, theme)) = &*cache {
        if at.elapsed() < Duration::from_secs(1) {
            return theme.clone();
        }
    }
    let theme = crate::syscolors::config_home().and_then(|home| {
        let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
        crate::syscolors::read(&home, &desktop, None).map(palette_theme)
    });
    *cache = Some((Instant::now(), theme.clone()));
    theme
}

fn signature() -> Vec<(PathBuf, crate::syscolors::Mark)> {
    let mut paths = path().into_iter().collect::<Vec<_>>();
    if load() == ThemeChoice::System {
        if let Some(home) = crate::syscolors::config_home() {
            paths.extend(crate::syscolors::watched_files(&home));
        }
    }
    let marks = crate::syscolors::signature(&paths);
    paths.into_iter().zip(marks).collect()
}

/// Only a changed file wakes the UI, not a periodic redraw. The worker
/// stops when the last subscriber (including a closed window) goes away.
pub fn watch() -> iced::Subscription<()> {
    fn events() -> impl iced::futures::Stream<Item = ()> {
        let (sender, receiver) = iced::futures::channel::mpsc::unbounded();
        std::thread::spawn(move || {
            let mut previous = signature();
            while !sender.is_closed() {
                std::thread::sleep(std::time::Duration::from_secs(2));
                let current = signature();
                if current != previous {
                    previous = current;
                    if let Ok(mut cache) = theme_cache().lock() {
                        *cache = None;
                    }
                    if sender.unbounded_send(()).is_err() {
                        break;
                    }
                }
            }
        });
        receiver
    }
    iced::Subscription::run(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn choices_have_unique_round_tripping_keys() {
        let mut keys = std::collections::HashSet::new();
        for choice in ThemeChoice::ALL {
            assert!(keys.insert(choice.key()));
            assert_eq!(ThemeChoice::from_key(choice.key()), choice);
        }
        assert_eq!(ThemeChoice::from_key("unknown"), ThemeChoice::System);
        assert_eq!(ThemeChoice::System.key(), "system");
    }

    #[test]
    fn the_system_theme_uses_real_colors_not_a_named_light_or_dark_palette() {
        let source = std::path::Path::new("/fixture/palette.json");
        let colors = crate::syscolors::parse_palette_file(
            r##"{ "background": "#1e1e2e", "text": "#cdd6f4", "accent": "#cba6f7" }"##,
            source,
        )
        .unwrap();
        let theme = palette_theme(colors);
        assert_eq!(
            theme.palette().background,
            iced::Color::from_rgb8(30, 30, 46)
        );
        assert_eq!(theme.palette().text, iced::Color::from_rgb8(205, 214, 244));
        assert_eq!(
            theme.palette().primary,
            iced::Color::from_rgb8(203, 166, 247)
        );
    }
}
