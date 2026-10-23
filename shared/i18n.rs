//! Shared UI vocabulary for the core and the separate window process.
//! Protocol identifiers are deliberately not translated.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Language {
    English,
    #[default]
    Russian,
}

impl Language {
    pub fn tag(self) -> &'static str {
        match self {
            Self::English => "en",
            Self::Russian => "ru",
        }
    }

    /// Unknown *explicit* locales fall back to English. The current implicit
    /// default remains Russian until every core-generated prompt is migrated.
    pub fn from_tag(tag: &str) -> Self {
        if tag.eq_ignore_ascii_case("ru") || tag.starts_with("ru_") || tag.starts_with("ru-") {
            Self::Russian
        } else {
            Self::English
        }
    }

    /// A malformed or future wire tag must not make the window chrome differ
    /// from the legacy Russian labels already serialized by the core.
    pub fn from_wire_tag(tag: &str) -> Self {
        match tag {
            "en" => Self::English,
            _ => Self::Russian,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Launch,
    Network,
    Container,
    AlwaysNetwork,
    AlwaysContainer,
    UnconfinedWarning,
    NoContainer,
    PresetOffer,
    Wait,
    Start,
    StartIn,
    Cancel,
    CloseMenu,
    Save,
    ContainerName,
    NothingToChoose,
    Permissions,
    Command,
    Program,
    TunnelSilent,
    BusyInNetwork,
    BoundToNetwork,
}

/// English is the source text; the Russian arm is the complete translation
/// of this bounded set. Dynamic values are appended separately, never parsed
/// out of translated prose.
pub fn text(language: Language, key: Key) -> &'static str {
    use Key::*;
    match (language, key) {
        (Language::English, Launch) => "Launch",
        (Language::Russian, Launch) => "Запуск",
        (Language::English, Network) => "Network",
        (Language::Russian, Network) => "Сеть",
        (Language::English, Container) => "Container",
        (Language::Russian, Container) => "Контейнер",
        (Language::English, AlwaysNetwork) => "Always use this network",
        (Language::Russian, AlwaysNetwork) => "Всегда эту сеть",
        (Language::English, AlwaysContainer) => "Always use this container",
        (Language::Russian, AlwaysContainer) => "Всегда этот контейнер",
        (Language::English, UnconfinedWarning) => {
            "⚠ No isolation or VPN — full access to host files, devices and session"
        }
        (Language::Russian, UnconfinedWarning) => {
            "⚠ Без изоляции и без VPN — полный доступ к файлам, устройствам и сеансу хоста"
        }
        (Language::English, NoContainer) => {
            "No container is used. To choose a network and container, select a network on the left."
        }
        (Language::Russian, NoContainer) => {
            "Контейнер не используется. Чтобы выбрать сеть и контейнер, нажмите сеть слева."
        }
        (Language::English, PresetOffer) => "Optional access for the selected container:",
        (Language::Russian, PresetOffer) => {
            "Дополнительный доступ для выбранного контейнера (необязательно):"
        }
        (Language::English, Wait) => "One moment…",
        (Language::Russian, Wait) => "Секунду…",
        (Language::English, Start) => "Start  Enter",
        (Language::Russian, Start) => "Запустить  Enter",
        (Language::English, StartIn) => "Start in:",
        (Language::Russian, StartIn) => "Запустить:",
        (Language::English, Cancel) => "Cancel  Esc",
        (Language::Russian, Cancel) => "Отмена  Esc",
        (Language::English, CloseMenu) => "Close menu  Esc",
        (Language::Russian, CloseMenu) => "Закрыть меню  Esc",
        (Language::English, Save) => "Save  Enter",
        (Language::Russian, Save) => "Сохранить  Enter",
        (Language::English, ContainerName) => "Container name (letters, digits, hyphen)",
        (Language::Russian, ContainerName) => "Название контейнера (буквы, цифры, дефис)",
        (Language::English, NothingToChoose) => "This container has no choices here",
        (Language::Russian, NothingToChoose) => "У этого контейнера здесь нечего выбирать",
        (Language::English, Permissions) => "Permissions",
        (Language::Russian, Permissions) => "Разрешения",
        (Language::English, Command) => "Command",
        (Language::Russian, Command) => "Команда",
        (Language::English, Program) => "Program:",
        (Language::Russian, Program) => "Программа:",
        (Language::English, TunnelSilent) => " — tunnel not responding",
        (Language::Russian, TunnelSilent) => " — туннель молчит",
        (Language::English, BusyInNetwork) => "open in network",
        (Language::Russian, BusyInNetwork) => "открыт в сети",
        (Language::English, BoundToNetwork) => "bound to network",
        (Language::Russian, BoundToNetwork) => "привязан к сети",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_unknown_language_falls_back_to_english() {
        assert_eq!(Language::from_tag("de_DE.UTF-8"), Language::English);
        assert_eq!(Language::from_tag("ru_RU.UTF-8"), Language::Russian);
        assert_eq!(Language::English.tag(), "en");
        assert_eq!(Language::from_wire_tag("de"), Language::Russian);
    }

    #[test]
    fn both_catalogues_have_every_key() {
        use Key::*;
        for key in [
            Launch,
            Network,
            Container,
            AlwaysNetwork,
            AlwaysContainer,
            UnconfinedWarning,
            NoContainer,
            PresetOffer,
            Wait,
            Start,
            StartIn,
            Cancel,
            CloseMenu,
            Save,
            ContainerName,
            NothingToChoose,
            Permissions,
            Command,
            Program,
            TunnelSilent,
            BusyInNetwork,
            BoundToNetwork,
        ] {
            assert!(!text(Language::English, key).is_empty());
            assert!(!text(Language::Russian, key).is_empty());
        }
    }
}
