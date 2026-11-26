use clipstore::capture_dbus::{self, ImplPortal, Portal};
use clipstore::capture_portal::Registry;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

fn run(args: &[OsString]) -> u8 {
    let mut pw_dump = None;
    let mut kdialog = None;
    let mut address = None;
    let mut name = None;
    let mut implementation = false;
    let mut words = args.iter();
    while let Some(word) = words.next() {
        if word == "--impl" {
            implementation = true;
            continue;
        }
        let Some(value) = words.next() else {
            eprintln!("cellward-capture-portal: {word:?} needs a value");
            return 2;
        };
        match word.to_str() {
            Some("--pw-dump") => pw_dump = Some(PathBuf::from(value)),
            Some("--kdialog") => kdialog = Some(PathBuf::from(value)),
            Some("--address") => {
                let Some(value) = value.to_str() else {
                    eprintln!("cellward-capture-portal: --address must be UTF-8");
                    return 2;
                };
                address = Some(value.to_owned());
            }
            Some("--name") => {
                let Some(value) = value.to_str().filter(|value| !value.is_empty()) else {
                    eprintln!("cellward-capture-portal: invalid --name");
                    return 2;
                };
                name = Some(value);
            }
            _ => {
                eprintln!("cellward-capture-portal: unknown option {word:?}");
                return 2;
            }
        }
    }
    let Some(pw_dump) = pw_dump.filter(|path| path.is_absolute()) else {
        eprintln!("cellward-capture-portal: an absolute --pw-dump is required");
        return 2;
    };
    if kdialog.as_ref().is_some_and(|path| !path.is_absolute()) {
        eprintln!("cellward-capture-portal: --kdialog must be absolute");
        return 2;
    }
    let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
    else {
        eprintln!("cellward-capture-portal: XDG_RUNTIME_DIR is required");
        return 2;
    };
    let registry = Arc::new(Mutex::new(Registry::default()));
    let available = Arc::new(move || {
        capture_dbus::sources(&pw_dump).unwrap_or_else(|error| {
            eprintln!("cellward-capture-portal: cannot enumerate sources: {error}");
            Vec::new()
        })
    });
    let portal = Portal::new(
        registry.clone(),
        available.clone(),
        runtime.join("pipewire-0"),
    );
    let portal = match &kdialog {
        Some(path) => portal.with_kdialog(path.clone()),
        None => portal,
    };
    let impl_portal = ImplPortal::new(registry, available);
    let impl_portal = match &kdialog {
        Some(path) => impl_portal.with_kdialog(path.clone()),
        None => impl_portal,
    };
    let name = name.unwrap_or(if implementation {
        "org.freedesktop.impl.portal.desktop.cellward"
    } else {
        "org.cellward.Capture"
    });
    let builder = match &address {
        Some(address) => zbus::blocking::connection::Builder::address(address.as_str()),
        None => zbus::blocking::connection::Builder::session(),
    };
    let connection = if implementation {
        builder.and_then(|builder| {
            builder
                .name(name)?
                .serve_at(capture_dbus::desktop_path(), impl_portal)
        })
    } else {
        builder.and_then(|builder| {
            builder
                .name(name)?
                .serve_at(capture_dbus::desktop_path(), portal)
        })
    };
    let _connection = match connection.and_then(|builder| builder.build()) {
        Ok(connection) => connection,
        Err(error) => {
            eprintln!("cellward-capture-portal: cannot start D-Bus backend: {error}");
            return 1;
        }
    };
    eprintln!("cellward-capture-portal: {name} is ready");
    loop {
        std::thread::park();
    }
}

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    std::process::exit(i32::from(run(&args)));
}
