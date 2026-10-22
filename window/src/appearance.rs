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

    /// `None` retains iced's live system light/dark detection.
    pub fn theme(self) -> Option<Theme> {
        Some(match self {
            Self::System => return None,
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
        assert!(ThemeChoice::System.theme().is_none());
    }
}
