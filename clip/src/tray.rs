//! The one host-side StatusNotifierItem for all clipboard histories. The
//! selection recorder remains the only owner of the store and its key; the
//! tray opens an unprivileged history window when the person asks for it.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use zbus::blocking::{connection, Proxy};
use zbus::zvariant::{ObjectPath, OwnedValue, Value};

#[allow(dead_code)]
#[path = "../../shared/i18n.rs"]
mod i18n;

type Properties = HashMap<String, OwnedValue>;
type Layout = (i32, Properties, Vec<OwnedValue>);

fn menu_properties(id: i32, requested: &[String]) -> Properties {
    let mut properties = Properties::new();
    if id == 0 {
        properties.insert(
            "children-display".into(),
            Value::from("submenu").try_into().unwrap(),
        );
    } else if id == 1 {
        let locale = std::env::var("LC_ALL")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("LC_MESSAGES").ok().filter(|s| !s.is_empty()))
            .or_else(|| std::env::var("LANG").ok());
        let language = locale
            .as_deref()
            .map(i18n::Language::from_tag)
            .unwrap_or_default();
        properties.insert(
            "label".into(),
            Value::from(i18n::text(language, i18n::Key::ClipboardManager))
                .try_into()
                .unwrap(),
        );
        properties.insert("enabled".into(), true.into());
        properties.insert("visible".into(), true.into());
    }
    properties.retain(|key, _| requested.is_empty() || requested.contains(key));
    properties
}

struct Menu(Arc<Item>);

// A static dbusmenu lets the panel render the app action alongside its own
// pin/unpin controls. Pinning remains the panel's policy, not an app-side edit.
#[zbus::interface(name = "com.canonical.dbusmenu")]
impl Menu {
    #[zbus(property)]
    fn version(&self) -> u32 {
        3
    }
    #[zbus(property)]
    fn text_direction(&self) -> &str {
        "ltr"
    }
    #[zbus(property)]
    fn status(&self) -> &str {
        "normal"
    }
    #[zbus(property)]
    fn icon_theme_path(&self) -> Vec<String> {
        Vec::new()
    }

    fn get_layout(
        &self,
        parent_id: i32,
        recursion_depth: i32,
        property_names: Vec<String>,
    ) -> (u32, Layout) {
        let children = if parent_id == 0 && recursion_depth != 0 {
            vec![Value::new((
                1i32,
                menu_properties(1, &property_names),
                Vec::<OwnedValue>::new(),
            ))
            .try_into()
            .unwrap()]
        } else {
            Vec::new()
        };
        (
            1,
            (
                parent_id,
                menu_properties(parent_id, &property_names),
                children,
            ),
        )
    }

    fn get_group_properties(
        &self,
        ids: Vec<i32>,
        property_names: Vec<String>,
    ) -> Vec<(i32, Properties)> {
        ids.into_iter()
            .filter(|id| *id == 0 || *id == 1)
            .map(|id| (id, menu_properties(id, &property_names)))
            .collect()
    }

    fn get_property(&self, id: i32, name: &str) -> zbus::fdo::Result<OwnedValue> {
        menu_properties(id, &[])
            .remove(name)
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs("Unknown menu property".into()))
    }

    fn about_to_show(&self, _id: i32) -> bool {
        false
    }

    fn event(&self, id: i32, event_id: &str, _data: OwnedValue, _timestamp: u32) {
        if id == 1 && event_id == "clicked" {
            self.0.open();
        }
    }
}

struct Item {
    window: PathBuf,
    open: Mutex<Option<Child>>,
}

struct Tray(Arc<Item>);

impl Item {
    fn open(&self) {
        let Ok(mut child) = self.open.lock() else {
            return;
        };
        if child
            .as_mut()
            .is_some_and(|running| running.try_wait().ok().flatten().is_none())
        {
            return;
        }
        match Command::new(&self.window)
            .args(["clip", "--manager"])
            .spawn()
        {
            Ok(running) => *child = Some(running),
            Err(e) => eprintln!("cellward-clip: окно менеджера не открылось: {e}"),
        }
    }
}

#[zbus::interface(name = "org.kde.StatusNotifierItem")]
impl Tray {
    #[zbus(property)]
    fn category(&self) -> &str {
        "ApplicationStatus"
    }

    #[zbus(property)]
    fn id(&self) -> &str {
        "cellward-clip"
    }

    #[zbus(property)]
    fn title(&self) -> &str {
        "Буферы Cellward"
    }

    #[zbus(property)]
    fn status(&self) -> &str {
        "Active"
    }

    #[zbus(property)]
    fn icon_name(&self) -> &str {
        "edit-paste"
    }

    #[zbus(property)]
    fn item_is_menu(&self) -> bool {
        false
    }

    #[zbus(property)]
    fn menu(&self) -> ObjectPath<'static> {
        ObjectPath::try_from("/Menu").expect("fixed object path")
    }

    fn activate(&self, _x: i32, _y: i32) {
        self.0.open()
    }

    fn secondary_activate(&self, _x: i32, _y: i32) {
        // Do not turn an alternate activation into opening the manager.
    }

    fn context_menu(&self, _x: i32, _y: i32) {
        // The panel renders /Menu, including its own pinning controls.
    }
}

/// Start only after data-control and the recorder's socket are ready. A
/// missing panel is not a failure of the history: registration is retried.
pub fn start() {
    let Some(window) = std::env::var_os("CELLWARD_CLIP_WINDOW").filter(|s| !s.is_empty()) else {
        eprintln!("cellward-clip: CELLWARD_CLIP_WINDOW не задан — значок в трее выключен");
        return;
    };
    std::thread::spawn(move || {
        let name = format!("org.kde.StatusNotifierItem-{}-1", std::process::id());
        let item = Arc::new(Item {
            window: window.into(),
            open: Mutex::new(None),
        });
        let connection = match connection::Builder::session()
            .and_then(|b| {
                b.serve_at("/StatusNotifierItem", Tray(item.clone()))?
                    .serve_at("/Menu", Menu(item))
            })
            .and_then(|b| b.name(name.as_str()))
            .and_then(|b| b.build())
        {
            Ok(connection) => connection,
            Err(e) => {
                eprintln!("cellward-clip: значок в трее недоступен: {e}");
                return;
            }
        };
        loop {
            if let Ok(watcher) = Proxy::new(
                &connection,
                "org.kde.StatusNotifierWatcher",
                "/StatusNotifierWatcher",
                "org.kde.StatusNotifierWatcher",
            ) {
                let _: Result<(), _> =
                    watcher.call("RegisterStatusNotifierItem", &(name.as_str(),));
            }
            std::thread::sleep(Duration::from_secs(15));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;

    struct Bus(Child);
    impl Drop for Bus {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn panel_can_read_a_nonempty_menu_over_a_private_bus() {
        let mut bus = Bus(Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap());
        let mut address = String::new();
        BufReader::new(bus.0.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        let item = Arc::new(Item {
            window: PathBuf::from("/not-launched"),
            open: Mutex::new(None),
        });
        let server = connection::Builder::address(address.trim())
            .unwrap()
            .name("org.cellward.ClipboardTrayTest")
            .unwrap()
            .serve_at("/StatusNotifierItem", Tray(item.clone()))
            .unwrap()
            .serve_at("/Menu", Menu(item.clone()))
            .unwrap()
            .build()
            .unwrap();
        let client = connection::Builder::address(address.trim())
            .unwrap()
            .build()
            .unwrap();
        let tray = Proxy::new(
            &client,
            "org.cellward.ClipboardTrayTest",
            "/StatusNotifierItem",
            "org.kde.StatusNotifierItem",
        )
        .unwrap();
        let path: ObjectPath = tray.get_property("Menu").unwrap();
        assert_eq!(path.as_str(), "/Menu");
        assert!(!tray.get_property::<bool>("ItemIsMenu").unwrap());
        let menu = Proxy::new(
            &client,
            "org.cellward.ClipboardTrayTest",
            path,
            "com.canonical.dbusmenu",
        )
        .unwrap();
        let (revision, root): (u32, Layout) = menu
            .call("GetLayout", &(0i32, -1i32, Vec::<String>::new()))
            .unwrap();
        assert_eq!(revision, 1);
        assert_eq!(root.0, 0);
        assert_eq!(
            root.2.len(),
            1,
            "Noctalia only adds pinning to nonempty menus"
        );
        let entry = Layout::try_from(root.2.into_iter().next().unwrap()).unwrap();
        assert_eq!(entry.0, 1);
        assert!(bool::try_from(entry.1.get("enabled").unwrap()).unwrap());
        assert!(!<&str>::try_from(entry.1.get("label").unwrap())
            .unwrap()
            .is_empty());
        let groups: Vec<(i32, Properties)> = menu
            .call("GetGroupProperties", &(vec![1i32], vec!["label"]))
            .unwrap();
        assert_eq!(groups[0].1.len(), 1);
        let _: () = menu
            .call("Event", &(99i32, "clicked", Value::from(0i32), 0u32))
            .unwrap();
        assert!(
            item.open.lock().unwrap().is_none(),
            "unknown actions cannot launch a window"
        );
        drop(server);
    }
}
