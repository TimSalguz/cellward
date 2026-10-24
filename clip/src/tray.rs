//! The one host-side StatusNotifierItem for all clipboard histories. The
//! selection recorder remains the only owner of the store and its key; the
//! tray opens an unprivileged history window when the person asks for it.

use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Mutex;
use std::time::Duration;

use zbus::blocking::{connection, Proxy};
use zbus::zvariant::ObjectPath;

struct Item {
    window: PathBuf,
    open: Mutex<Option<Child>>,
}

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
impl Item {
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
        ObjectPath::try_from("/NO_DBUSMENU").expect("fixed object path")
    }

    fn activate(&self, _x: i32, _y: i32) {
        self.open()
    }

    fn secondary_activate(&self, _x: i32, _y: i32) {
        self.open()
    }

    fn context_menu(&self, _x: i32, _y: i32) {
        self.open()
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
        let connection = match connection::Builder::session()
            .and_then(|b| {
                b.serve_at(
                    "/StatusNotifierItem",
                    Item {
                        window: window.into(),
                        open: Mutex::new(None),
                    },
                )
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
