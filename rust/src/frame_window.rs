//! The frame's settings in a window, from the window menu: the same rows as
//! a container's permissions (`crate::window::render_perms`), for every
//! window — what `cellward frame …` sets —, the current zone's colour and
//! the container's own frame colour. A setting Nix declares is shown, not offered.

use crate::container::Source;
use crate::tools::Tools;
use crate::window::{Perm, PermOf};
use std::ffi::OsString;

/// A container's colour kept as its zone's: no colour of its own.
const ZONE_COLOR: &str = "default";

/// The colours offered for a zone or container, by name.
const COLORS: [(&str, &str); 9] = [
    ("#D94C4C", "красный"),
    ("#E08A3C", "оранжевый"),
    ("#D9B84C", "жёлтый"),
    ("#4CA65A", "зелёный"),
    ("#3CA6A6", "бирюзовый"),
    ("#4C7AD9", "синий"),
    ("#8A5CD9", "фиолетовый"),
    ("#D94C9E", "розовый"),
    ("#808080", "серый"),
];

fn row(key: &str, label: &str, choices: &[(&str, &str)]) -> Perm {
    Perm {
        key: key.to_owned(),
        label: label.to_owned(),
        choices: choices
            .iter()
            .map(|(v, l)| ((*v).to_owned(), (*l).to_owned()))
            .collect(),
    }
}

fn setting_row(
    config: &std::path::Path,
    name: &str,
    label: &str,
    choices: &[(&str, &str)],
) -> Perm {
    let mut perm = row(name, label, choices);
    let file = match name {
        "show" => crate::frame::SWITCH_SETTING,
        "width" => crate::frame::WIDTH_SETTING,
        "style" => crate::frame::STYLE_SETTING,
        "title" => crate::frame::TITLE_SETTING,
        "buttons" => crate::frame::BUTTONS_SETTING,
        "radius" => crate::frame::RADIUS_SETTING,
        "outer-radius" => crate::frame::OUTER_RADIUS_SETTING,
        "fullscreen-button" => crate::frame::FULLSCREEN_BUTTON_SETTING,
        "double-click" => crate::frame::DOUBLE_CLICK_SETTING,
        _ => name,
    };
    let reset = if crate::declared::declares(config, file) {
        "вернуть как в Nix"
    } else {
        "сбросить настройку"
    };
    perm.choices.push(("default".into(), reset.into()));
    perm
}

/// `choices` with `now` among them: a value set by hand that none of them
/// is shown as itself.
fn with(mut perm: Perm, now: &str) -> Perm {
    if !perm.choices.iter().any(|(v, _)| v == now) {
        perm.choices.push((now.to_owned(), now.to_owned()));
    }
    perm
}

/// The rows, and the values as they are now: `(key, value, fixed)`.
/// Zone and container colours are separate: changing one must not silently
/// recolour the other.
pub fn rows(
    tools: &Tools,
    zone: Option<&str>,
    record: Option<&str>,
) -> (Vec<Perm>, Vec<(String, String, bool)>) {
    let c = &tools.config;
    let mut perms = Vec::new();
    let mut values = Vec::new();
    let mut push = |perm: Perm, now: String, fixed: bool| {
        values.push((perm.key.clone(), now.clone(), fixed));
        perms.push(with(perm, &now));
    };
    let shown = if crate::frame::hidden(c) { "off" } else { "on" };
    push(
        setting_row(
            c,
            "show",
            "Рамки окон",
            &[("on", "рисовать"), ("off", "спрятать")],
        ),
        shown.to_owned(),
        false,
    );
    let (width, _) = crate::frame::width(c);
    push(
        setting_row(
            c,
            "width",
            "Толщина",
            &[
                ("0", "0"),
                ("2", "2"),
                ("3", "3"),
                ("4", "4"),
                ("6", "6"),
                ("8", "8"),
                ("12", "12"),
            ],
        ),
        width.to_string(),
        false,
    );
    let (style, _) = crate::frame::style(c);
    push(
        setting_row(
            c,
            "style",
            "Вид",
            &[
                ("soft", "мягкая"),
                ("full", "цвет как есть"),
                ("tag", "бирка"),
            ],
        ),
        style.as_str().to_owned(),
        false,
    );
    let (title, _) = crate::frame::title_mode(c);
    push(
        setting_row(
            c,
            "title",
            "Заголовок",
            &[
                ("always", "всегда"),
                ("hover", "при наведении"),
                ("off", "нет"),
            ],
        ),
        title.as_str().to_owned(),
        false,
    );
    let (buttons, _) = crate::frame::buttons(c);
    push(
        setting_row(
            c,
            "buttons",
            "Кнопки",
            &[
                ("cellward", "свои"),
                ("gnome", "GNOME"),
                ("kde", "KDE"),
                ("macos", "macOS"),
                ("windows", "Windows"),
                ("none", "нет"),
            ],
        ),
        buttons.as_str().to_owned(),
        false,
    );
    let (radius, _) = crate::frame::radius(c);
    let radius = match radius {
        crate::frame::Radius::Px(px) => px.to_string(),
        crate::frame::Radius::Niri(_) => "niri".to_owned(),
    };
    push(
        setting_row(
            c,
            "radius",
            "Скругление окна",
            &[
                ("0", "0"),
                ("4", "4"),
                ("8", "8"),
                ("12", "12"),
                ("niri", "как у niri"),
            ],
        ),
        radius,
        false,
    );
    let (outer, _) = crate::frame::outer_radius(c);
    let outer = match outer {
        crate::frame::Radius::Px(px) => px.to_string(),
        crate::frame::Radius::Niri(_) => "niri".to_owned(),
    };
    push(
        setting_row(
            c,
            "outer-radius",
            "Скругление рамки снаружи",
            &[
                ("0", "0"),
                ("4", "4"),
                ("8", "8"),
                ("12", "12"),
                ("16", "16"),
                ("24", "24"),
                ("32", "32"),
                ("niri", "как у niri"),
            ],
        ),
        outer,
        false,
    );
    let (button, _) = crate::frame::fullscreen_button(c);
    push(
        setting_row(
            c,
            "fullscreen-button",
            "Кнопка полного экрана",
            &[
                ("one", "одна"),
                ("two", "две"),
                ("menu", "в меню ≡"),
                ("none", "нет"),
            ],
        ),
        button.as_str().to_owned(),
        false,
    );
    let (click, _) = crate::frame::double_click(c);
    push(
        setting_row(
            c,
            "double-click",
            "Двойной клик по заголовку",
            &[("maximize", "развернуть"), ("none", "ничего")],
        ),
        click.as_str().to_owned(),
        false,
    );
    if let Some(zone) = zone.filter(|z| {
        crate::cli::safe_zone_name(std::ffi::OsStr::new(z)) && tools.state.join(z).is_dir()
    }) {
        let (color, source) = crate::frame::zone_color(&tools.state, c, zone);
        let now = if source == Source::Default {
            ZONE_COLOR.to_owned()
        } else {
            color.hex().to_uppercase()
        };
        let mut choices = vec![(ZONE_COLOR, "как в Nix или по имени сети")];
        choices.extend(COLORS);
        push(
            row("zone-color", &format!("Цвет сети «{zone}»"), &choices),
            now,
            false,
        );
    }
    if let Some(record) = record.filter(|r| *r != crate::container::MAIN_RECORD) {
        let own = crate::container::load(tools, record).and_then(|c| c.frame_color);
        let now = match &own {
            Some(color) => color.value.to_uppercase(),
            None => ZONE_COLOR.to_owned(),
        };
        let mut choices = vec![(ZONE_COLOR, "вернуть как в Nix или у сети")];
        choices.extend(COLORS);
        push(
            row("color", &format!("Цвет — контейнера «{record}»"), &choices),
            now,
            false,
        );
    }
    (perms, values)
}

/// The window's request.
pub fn request(tools: &Tools, zone: Option<&str>, record: Option<&str>) -> String {
    let (perms, values) = rows(tools, zone, record);
    let of = PermOf {
        tag: "this".to_owned(),
        scope: "Вид и скругления — для всех окон; цвет сети — для всех её окон, цвет контейнера — только для него. Изменение поверх Nix действует сразу; «вернуть как в Nix» снимает его. Закрепление в Nix — отдельно в stillconf."
            .to_owned(),
        values,
    };
    let request = crate::window::render_perms("Рамка окон", &[], &perms, &of);
    format!("block\tРамка\n{request}")
}

/// The changes the window answered, made: what was done or why not, a line
/// each.
pub fn apply(
    tools: &Tools,
    zone: Option<&str>,
    record: Option<&str>,
    changes: &[(String, String)],
) -> Vec<String> {
    let mut said = Vec::new();
    for (key, value) in changes {
        let args: Vec<OsString> = match key.as_str() {
            "zone-color" => {
                let Some(zone) = zone else { continue };
                let args = vec!["color".into(), zone.into(), value.into()];
                if crate::cli::frame(tools, &args) != 0 {
                    said.push(format!("Цвет сети «{zone}» не изменён"));
                }
                continue;
            }
            "color" => {
                let Some(record) = record else { continue };
                let color = (value != ZONE_COLOR).then_some(value.as_str());
                said.push(
                    match crate::container::set_frame_color(tools, record, color) {
                        Ok(()) => format!("Цвет рамки контейнера «{record}»: {value}"),
                        Err(e) => e,
                    },
                );
                continue;
            }
            "show" => {
                if value == "default" {
                    if crate::cli::reset_frame_preview(tools, crate::frame::SWITCH_SETTING).is_err()
                    {
                        said.push("Рамки: не удалось вернуть настройку из Nix".into());
                    }
                    continue;
                }
                vec![if value == "off" { "hide" } else { "show" }.into()]
            }
            "width" | "style" | "title" | "buttons" | "radius" | "outer-radius"
            | "fullscreen-button" | "double-click" => vec![key.into(), value.into()],
            _ => continue,
        };
        if crate::cli::frame(tools, &args) != 0 {
            said.push(format!("Рамка: «{key}» не изменена"));
        }
    }
    said
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn tools_in(base: &Path) -> Tools {
        let entries: std::collections::BTreeMap<String, String> = Tools::keys()
            .iter()
            .map(|k| {
                let dir = match *k {
                    "home" | "state" | "profiles" | "sandboxes" | "config" => base.join(k),
                    other => PathBuf::from(format!("/p/{other}")),
                };
                ((*k).to_owned(), dir.to_string_lossy().into_owned())
            })
            .collect();
        Tools::from_entries(Path::new("/m.json"), &entries).unwrap()
    }

    fn value<'a>(values: &'a [(String, String, bool)], key: &str) -> &'a str {
        &values.iter().find(|(k, _, _)| k == key).unwrap().1
    }

    /// The rows say the settings as they are; a change is `cellward
    /// frame …`'s, so the next look says it; zone and container colours
    /// are independent.
    #[test]
    fn the_frames_settings_are_shown_and_changed() {
        let base = std::env::temp_dir().join(format!("vz-frame-window-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("config")).unwrap();
        std::fs::create_dir_all(base.join("state/nl")).unwrap();
        let tools = tools_in(&base);
        let (perms, values) = rows(&tools, None, None);
        assert!(perms
            .iter()
            .all(|p| p.key != "color" && p.key != "zone-color"));
        assert_eq!(perms.len(), values.len());
        assert_eq!(value(&values, "show"), "on");
        assert_eq!(value(&values, "width"), "4");
        assert_eq!(value(&values, "outer-radius"), "0");
        assert!(values.iter().all(|(_, _, fixed)| !fixed));
        let said = apply(
            &tools,
            None,
            None,
            &[
                ("width".into(), "6".into()),
                ("show".into(), "off".into()),
                ("style".into(), "tag".into()),
                ("outer-radius".into(), "12".into()),
                ("color".into(), "#D94C4C".into()),
            ],
        );
        assert!(said.is_empty(), "{said:?}");
        let (_, values) = rows(&tools, None, None);
        assert_eq!(value(&values, "width"), "6");
        assert_eq!(value(&values, "show"), "off");
        assert_eq!(value(&values, "style"), "tag");
        assert_eq!(value(&values, "outer-radius"), "12");
        assert!(apply(&tools, None, None, &[("width".into(), "99".into())])
            .iter()
            .any(|l| l.contains("width")));
        // A value set by hand is a choice of its own.
        std::fs::write(tools.config.join(crate::frame::WIDTH_SETTING), "5").unwrap();
        let (perms, _) = rows(&tools, None, None);
        let width = perms.iter().find(|p| p.key == "width").unwrap();
        assert!(width.choices.iter().any(|(v, _)| v == "5"));
        let (perms, _) = rows(&tools, None, Some("work"));
        assert!(perms.iter().any(|p| p.key == "color"));
        assert!(rows(&tools, None, Some(crate::container::MAIN_RECORD))
            .0
            .iter()
            .all(|p| p.key != "color"));
        let (perms, values) = rows(&tools, Some("nl"), None);
        assert!(perms.iter().any(|p| p.key == "zone-color"));
        assert_eq!(value(&values, "zone-color"), "default");
        assert!(apply(
            &tools,
            Some("nl"),
            None,
            &[("zone-color".into(), "#4C7AD9".into())]
        )
        .is_empty());
        assert_eq!(
            value(&rows(&tools, Some("nl"), None).1, "zone-color"),
            "#4C7AD9"
        );
        assert_eq!(
            value(&rows(&tools, Some("nl"), None).1, "outer-radius"),
            "12"
        );
        std::fs::create_dir_all(tools.config.join(crate::cli::DECLARED_DIR)).unwrap();
        crate::declared::declare(
            &tools
                .config
                .join(crate::cli::DECLARED_DIR)
                .join(crate::frame::DECLARED_COLORS),
            "nl #123456\n",
        );
        for (name, nix) in [
            (crate::frame::WIDTH_SETTING, "3"),
            (crate::frame::RADIUS_SETTING, "4"),
            (crate::frame::OUTER_RADIUS_SETTING, "8"),
            (crate::frame::TITLE_SETTING, "always"),
            (crate::frame::STYLE_SETTING, "full"),
            (crate::frame::BUTTONS_SETTING, "kde"),
            (crate::frame::FULLSCREEN_BUTTON_SETTING, "two"),
            (crate::frame::DOUBLE_CLICK_SETTING, "none"),
            (crate::frame::SWITCH_SETTING, "hidden"),
        ] {
            crate::declared::declare(&tools.config.join(crate::cli::DECLARED_DIR).join(name), nix);
        }
        let (_, values) = rows(&tools, Some("nl"), None);
        assert!(values
            .iter()
            .any(|(key, color, fixed)| key == "zone-color" && color == "#123456" && !*fixed));
        assert_eq!(value(&values, "width"), "3");
        assert_eq!(value(&values, "title"), "always");
        assert_eq!(value(&values, "show"), "off");
        assert!(apply(
            &tools,
            Some("nl"),
            None,
            &[
                ("zone-color".into(), "#D94C4C".into()),
                ("width".into(), "8".into()),
                ("radius".into(), "12".into()),
                ("outer-radius".into(), "16".into()),
                ("title".into(), "hover".into()),
                ("style".into(), "soft".into()),
                ("buttons".into(), "macos".into()),
                ("fullscreen-button".into(), "menu".into()),
                ("double-click".into(), "maximize".into()),
                ("show".into(), "on".into()),
            ]
        )
        .is_empty());
        let (_, values) = rows(&tools, Some("nl"), None);
        for (key, value) in [
            ("zone-color", "#D94C4C"),
            ("width", "8"),
            ("radius", "12"),
            ("outer-radius", "16"),
            ("title", "hover"),
            ("style", "soft"),
            ("buttons", "macos"),
            ("fullscreen-button", "menu"),
            ("double-click", "maximize"),
            ("show", "on"),
        ] {
            assert_eq!(self::value(&values, key), value);
        }
        assert!(apply(
            &tools,
            Some("nl"),
            None,
            &[
                ("zone-color".into(), "default".into()),
                ("width".into(), "default".into()),
                ("radius".into(), "default".into()),
                ("outer-radius".into(), "default".into()),
                ("title".into(), "default".into()),
                ("style".into(), "default".into()),
                ("buttons".into(), "default".into()),
                ("fullscreen-button".into(), "default".into()),
                ("double-click".into(), "default".into()),
                ("show".into(), "default".into()),
            ]
        )
        .is_empty());
        let (_, values) = rows(&tools, Some("nl"), None);
        for (key, value) in [
            ("zone-color", "#123456"),
            ("width", "3"),
            ("radius", "4"),
            ("outer-radius", "8"),
            ("title", "always"),
            ("style", "full"),
            ("buttons", "kde"),
            ("fullscreen-button", "two"),
            ("double-click", "none"),
            ("show", "off"),
        ] {
            assert_eq!(self::value(&values, key), value);
        }
        let request = request(&tools, Some("nl"), None);
        assert!(
            request.starts_with("block\tРамка\nmode\tperms\n"),
            "{request}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
