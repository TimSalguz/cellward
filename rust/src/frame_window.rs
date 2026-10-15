//! The frame's settings in a window, from the window menu: the same rows as
//! a container's permissions (`crate::window::render_perms`), for every
//! window — what `cellward frame …` sets —, and the container's own frame
//! colour. A setting Nix declares is shown, not offered.

use crate::container::Source;
use crate::tools::Tools;
use crate::window::{Perm, PermOf};
use std::ffi::OsString;

/// A container's colour kept as its zone's: no colour of its own.
const ZONE_COLOR: &str = "default";

/// The colours offered for a container, by name.
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

/// `choices` with `now` among them: a value set by hand that none of them
/// is shown as itself.
fn with(mut perm: Perm, now: &str) -> Perm {
    if !perm.choices.iter().any(|(v, _)| v == now) {
        perm.choices.push((now.to_owned(), now.to_owned()));
    }
    perm
}

/// The rows, and the values as they are now: `(key, value, fixed)`. The
/// colour's only with a container (`record`) to keep it.
pub fn rows(tools: &Tools, record: Option<&str>) -> (Vec<Perm>, Vec<(String, String, bool)>) {
    let c = &tools.config;
    let nix = |s: Source| s == Source::Nix;
    let mut perms = Vec::new();
    let mut values = Vec::new();
    let mut push = |perm: Perm, now: String, fixed: bool| {
        values.push((perm.key.clone(), now.clone(), fixed));
        perms.push(with(perm, &now));
    };
    let shown = if crate::frame::hidden(c) { "off" } else { "on" };
    push(
        row(
            "show",
            "Рамки окон",
            &[("on", "рисовать"), ("off", "спрятать")],
        ),
        shown.to_owned(),
        false,
    );
    let (width, s) = crate::frame::width(c);
    push(
        row(
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
        nix(s),
    );
    let (style, s) = crate::frame::style(c);
    push(
        row(
            "style",
            "Вид",
            &[
                ("soft", "мягкая"),
                ("full", "цвет как есть"),
                ("tag", "бирка"),
            ],
        ),
        style.as_str().to_owned(),
        nix(s),
    );
    let (title, s) = crate::frame::title_mode(c);
    push(
        row(
            "title",
            "Заголовок",
            &[
                ("always", "всегда"),
                ("hover", "при наведении"),
                ("off", "нет"),
            ],
        ),
        title.as_str().to_owned(),
        nix(s),
    );
    let (buttons, s) = crate::frame::buttons(c);
    push(
        row(
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
        nix(s),
    );
    let (radius, s) = crate::frame::radius(c);
    let radius = match radius {
        crate::frame::Radius::Px(px) => px.to_string(),
        crate::frame::Radius::Niri(_) => "niri".to_owned(),
    };
    push(
        row(
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
        nix(s),
    );
    let (button, s) = crate::frame::fullscreen_button(c);
    push(
        row(
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
        nix(s),
    );
    let (click, s) = crate::frame::double_click(c);
    push(
        row(
            "double-click",
            "Двойной клик по заголовку",
            &[("maximize", "развернуть"), ("none", "ничего")],
        ),
        click.as_str().to_owned(),
        nix(s),
    );
    if let Some(record) = record.filter(|r| *r != crate::container::MAIN_RECORD) {
        let own = crate::container::load(tools, record).and_then(|c| c.frame_color);
        let (now, fixed) = match &own {
            Some(color) => (color.value.to_uppercase(), color.source == Source::Nix),
            None => (ZONE_COLOR.to_owned(), false),
        };
        let mut choices = vec![(ZONE_COLOR, "как у сети")];
        choices.extend(COLORS);
        push(
            row("color", &format!("Цвет — контейнера «{record}»"), &choices),
            now,
            fixed,
        );
    }
    (perms, values)
}

/// The window's request.
pub fn request(tools: &Tools, record: Option<&str>) -> String {
    let (perms, values) = rows(tools, record);
    let of = PermOf {
        tag: "this".to_owned(),
        scope: "Для всех окон всех контейнеров; цвет — только этого контейнера. Сразу, у \
                открытых окон тоже"
            .to_owned(),
        values,
    };
    let request = crate::window::render_perms("Рамка окон", &[], &perms, &of);
    format!("block\tРамка\n{request}")
}

/// The changes the window answered, made: what was done or why not, a line
/// each.
pub fn apply(tools: &Tools, record: Option<&str>, changes: &[(String, String)]) -> Vec<String> {
    let mut said = Vec::new();
    for (key, value) in changes {
        let args: Vec<OsString> = match key.as_str() {
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
            "show" => vec![if value == "off" { "hide" } else { "show" }.into()],
            "width" | "style" | "title" | "buttons" | "radius" | "fullscreen-button"
            | "double-click" => vec![key.into(), value.into()],
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
    /// frame …`'s, so the next look says it; the colour only with a
    /// container to keep it.
    #[test]
    fn the_frames_settings_are_shown_and_changed() {
        let base = std::env::temp_dir().join(format!("vz-frame-window-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("config")).unwrap();
        let tools = tools_in(&base);
        let (perms, values) = rows(&tools, None);
        assert!(perms.iter().all(|p| p.key != "color"));
        assert_eq!(perms.len(), values.len());
        assert_eq!(value(&values, "show"), "on");
        assert_eq!(value(&values, "width"), "4");
        assert!(values.iter().all(|(_, _, fixed)| !fixed));
        let said = apply(
            &tools,
            None,
            &[
                ("width".into(), "6".into()),
                ("show".into(), "off".into()),
                ("style".into(), "tag".into()),
                ("color".into(), "#D94C4C".into()),
            ],
        );
        assert!(said.is_empty(), "{said:?}");
        let (_, values) = rows(&tools, None);
        assert_eq!(value(&values, "width"), "6");
        assert_eq!(value(&values, "show"), "off");
        assert_eq!(value(&values, "style"), "tag");
        assert!(apply(&tools, None, &[("width".into(), "99".into())])
            .iter()
            .any(|l| l.contains("width")));
        // A value set by hand is a choice of its own.
        std::fs::write(tools.config.join(crate::frame::WIDTH_SETTING), "5").unwrap();
        let (perms, _) = rows(&tools, None);
        let width = perms.iter().find(|p| p.key == "width").unwrap();
        assert!(width.choices.iter().any(|(v, _)| v == "5"));
        let (perms, _) = rows(&tools, Some("work"));
        assert!(perms.iter().any(|p| p.key == "color"));
        assert!(rows(&tools, Some(crate::container::MAIN_RECORD))
            .0
            .iter()
            .all(|p| p.key != "color"));
        let request = request(&tools, None);
        assert!(
            request.starts_with("block\tРамка\nmode\tperms\n"),
            "{request}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
