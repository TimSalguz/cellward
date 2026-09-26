//! Devices a container is given (`docs/PERMISSIONS.md` §11.12): what a zone
//! hides from all its programs (`zone::hide_devices`) goes into a container
//! only on purpose — like a USB device into a virtual machine, without taking
//! it from the host.
//!
//! **What is given** — [`Grant`]: a set, one switch for a kind of device
//! (`games`, `security-keys`, `phone`, `serial`), or one device by what it
//! is (`usb:<vendor>:<product>[:<serial>]`), which outlives a replug into
//! another port and another number under `/dev`.
//!
//! **How a node is told** — by udev's word on it (`/run/udev/data/c<maj>:<min>`,
//! the `E:` lines) and, for a controller's raw HID node, by the HID device it
//! hangs off in sysfs: the raw node of a gamepad is the one whose HID device
//! also has the gamepad's input node. A virtual device (`/sys/devices/virtual`,
//! made through `uinput` — a key remapper's, anybody's) is never a gamepad
//! of the set.
//!
//! The launch lists the host's nodes and picks the given ones ([`granted`]);
//! `profile-run --device` takes the zone's cover off exactly those in the
//! launch's own mount namespace, and checks each once more there
//! ([`Pass`]): its number, and udev's vendor and product for it — a number
//! may have gone to another device in between.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

/// What a container may be given.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Grant {
    /// Gamepads: their input nodes (`ID_INPUT_JOYSTICK`, physical, no
    /// keyboard or mouse) and their raw HID nodes.
    Games,
    /// Security keys (FIDO): raw HID nodes udev calls `ID_SECURITY_TOKEN`.
    SecurityKeys,
    /// Phones: USB device nodes with an adb or an MTP/PTP interface.
    Phone,
    /// Serial adapters: `ttyUSB*`, `ttyACM*`.
    Serial,
    /// Virtual machines: `/dev/kvm`, `vhost-net`, `vhost-vsock` and
    /// `net/tun` (a VM's network through a tap of its own).
    Vm,
    /// One USB device, every node of it: vendor and product (four lowercase
    /// hex digits each), and its serial where it has one.
    Usb {
        vendor: String,
        product: String,
        serial: Option<String>,
    },
}

/// The sets, by their words.
pub const SETS: [(&str, Grant); 5] = [
    ("games", Grant::Games),
    ("security-keys", Grant::SecurityKeys),
    ("phone", Grant::Phone),
    ("serial", Grant::Serial),
    ("vm", Grant::Vm),
];

/// The nodes of [`Grant::Vm`], below `/dev`.
const VM_NODES: [&str; 4] = ["kvm", "vhost-net", "vhost-vsock", "net/tun"];

/// Four hex digits, lowercase — udev's `ID_VENDOR_ID`/`ID_MODEL_ID`.
fn hex4(word: &str) -> Option<String> {
    (word.len() == 4 && word.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| word.to_ascii_lowercase())
}

impl Grant {
    /// A grant's word: a set's name, or `usb:<vendor>:<product>[:<serial>]`.
    /// Anything else is none.
    pub fn parse(word: &str) -> Option<Self> {
        let word = word.trim();
        if let Some((_, grant)) = SETS.iter().find(|(name, _)| *name == word) {
            return Some(grant.clone());
        }
        let mut parts = word.strip_prefix("usb:")?.splitn(3, ':');
        let vendor = hex4(parts.next()?)?;
        let product = hex4(parts.next()?)?;
        // Only a serial a pass can carry (`serial_word`): one it could not
        // would be checked by the number and the maker alone.
        let serial = match parts.next() {
            None => None,
            Some(s) if serial_word(s) => Some(s.to_owned()),
            Some(_) => return None,
        };
        Some(Self::Usb {
            vendor,
            product,
            serial,
        })
    }

    pub fn word(&self) -> String {
        match self {
            Self::Usb {
                vendor,
                product,
                serial,
            } => match serial {
                Some(serial) => format!("usb:{vendor}:{product}:{serial}"),
                None => format!("usb:{vendor}:{product}"),
            },
            set => SETS
                .iter()
                .find(|(_, g)| g == set)
                .map_or_else(String::new, |(name, _)| (*name).to_owned()),
        }
    }
}

/// A node of `/dev` a grant may cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// Its path.
    pub path: PathBuf,
    pub major: u32,
    pub minor: u32,
    /// udev's properties of it.
    pub props: HashMap<String, String>,
    /// Its device directory in sysfs, resolved; `None` where there is none.
    pub sys: Option<PathBuf>,
}

impl Node {
    fn prop(&self, key: &str) -> Option<&str> {
        self.props.get(key).map(String::as_str)
    }

    fn name(&self) -> String {
        self.path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    }

    /// A device of the machine, not one made through `uinput`: its sysfs
    /// directory is below `devices/`, and not below `devices/virtual/input/`
    /// — where `uinput` puts what anybody makes. A Bluetooth gamepad through
    /// `uhid` (`devices/virtual/misc/uhid/`) is one: `/dev/uhid` is root's.
    fn physical(&self) -> bool {
        self.sys.as_ref().is_some_and(|p| {
            let p = p.to_string_lossy();
            p.contains("/devices/") && !p.contains("/devices/virtual/input/")
        })
    }

    /// The HID device it hangs off: a raw node's own parent, an input node's
    /// grandparent (`inputN`, then the HID device).
    fn hid(&self) -> Option<PathBuf> {
        let sys = self.sys.as_ref()?;
        let up = if self.name().starts_with("hidraw") {
            sys.join("device")
        } else {
            sys.join("device").join("device")
        };
        fs::canonicalize(up).ok()
    }

    /// A keyboard's or a mouse's input node: what types or points.
    fn typing_input(&self) -> bool {
        self.prop("ID_INPUT_KEYBOARD") == Some("1") || self.prop("ID_INPUT_MOUSE") == Some("1")
    }

    /// A gamepad's input node.
    fn gamepad_input(&self) -> bool {
        let name = self.name();
        (name.starts_with("event") || name.starts_with("js"))
            && self.prop("ID_INPUT_JOYSTICK") == Some("1")
            && !self.typing_input()
            && self.physical()
    }

    /// One of [`VM_NODES`].
    fn vm(&self) -> bool {
        let parent = self.path.parent().and_then(Path::file_name);
        match self.name().as_str() {
            "tun" => parent.is_some_and(|p| p == "net"),
            name => VM_NODES.contains(&name) && parent.is_some_and(|p| p == "dev"),
        }
    }

    fn usb_device(&self) -> bool {
        self.path
            .parent()
            .and_then(Path::parent)
            .is_some_and(|p| p.ends_with("bus/usb"))
    }

    /// What `profile-run --device` checks this node by, once more, in the
    /// launch's namespace.
    pub fn pass(&self) -> Pass {
        let word = |key: &str| {
            self.prop(key)
                .map(str::to_ascii_lowercase)
                .filter(|v| hex4(v).is_some())
        };
        Pass {
            path: self.path.clone(),
            major: self.major,
            minor: self.minor,
            vendor: word("ID_VENDOR_ID"),
            product: word("ID_MODEL_ID"),
            serial: self
                .prop("ID_SERIAL_SHORT")
                .filter(|s| serial_word(s))
                .map(str::to_owned),
        }
    }
}

/// Where the nodes, udev's database and sysfs are.
#[derive(Debug, Clone, Copy)]
pub struct Places<'a> {
    pub dev: &'a Path,
    pub udev: &'a Path,
    pub sys_char: &'a Path,
}

impl Places<'static> {
    /// The machine's own.
    pub fn host() -> Self {
        Self {
            dev: Path::new("/dev"),
            udev: Path::new("/run/udev/data"),
            sys_char: Path::new("/sys/dev/char"),
        }
    }
}

/// udev's `E:` properties of the character device `major:minor`.
pub fn udev_props(udev: &Path, major: u32, minor: u32) -> HashMap<String, String> {
    fs::read_to_string(udev.join(format!("c{major}:{minor}")))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.strip_prefix("E:"))
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

/// A serial as a pass carries it: printable, and none of its separators.
fn serial_word(serial: &str) -> bool {
    !serial.is_empty()
        && serial.len() <= 128
        && serial
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b':' && b != b'=')
}

/// Whether `path` is of the kinds a grant gives: `hidraw<N>`, `ttyUSB<N>`,
/// `ttyACM<N>`, `input/event<N>`, `input/js<N>`, `bus/usb/<bus>/<device>`,
/// and [`VM_NODES`] — all below `/dev`.
pub fn grantable_path(path: &Path) -> bool {
    let numbered = |name: &str, prefixes: &[&str]| {
        prefixes.iter().any(|p| {
            name.strip_prefix(p)
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        })
    };
    let digits = |s: &str| s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit());
    let Ok(rest) = path.strip_prefix("/dev") else {
        return false;
    };
    let parts: Vec<&str> = rest.iter().filter_map(|c| c.to_str()).collect();
    if parts.len() != rest.iter().count() {
        return false;
    }
    match parts.as_slice() {
        [name] => {
            numbered(name, &["hidraw", "ttyUSB", "ttyACM"])
                || ["kvm", "vhost-net", "vhost-vsock"].contains(name)
        }
        ["net", "tun"] => true,
        ["input", name] => numbered(name, &["event", "js"]),
        ["bus", "usb", bus, device] => digits(bus) && digits(device),
        _ => false,
    }
}

/// The character device a path is, by its number: `None` for anything else.
pub fn char_device(path: &Path) -> Option<(u32, u32)> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_char_device() {
        return None;
    }
    let rdev = meta.rdev();
    Some((libc::major(rdev), libc::minor(rdev)))
}

/// The nodes a grant may cover under `places.dev`: raw HID nodes, serial
/// adapters, input nodes and USB device nodes. `stat` tells a path's number
/// (the machine's in use; a test's own).
pub fn scan(places: Places, stat: &dyn Fn(&Path) -> Option<(u32, u32)>) -> Vec<Node> {
    let dir = |d: &Path| -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = fs::read_dir(d)
            .map(|entries| entries.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        out.sort();
        out
    };
    let mut paths: Vec<PathBuf> = dir(places.dev)
        .into_iter()
        .filter(|p| {
            let name = p.file_name().unwrap_or_default().to_string_lossy();
            ["hidraw", "ttyUSB", "ttyACM"]
                .iter()
                .any(|prefix| name.starts_with(prefix))
        })
        .collect();
    paths.extend(dir(&places.dev.join("input")).into_iter().filter(|p| {
        let name = p.file_name().unwrap_or_default().to_string_lossy();
        name.starts_with("event") || name.starts_with("js")
    }));
    for bus in dir(&places.dev.join("bus/usb")) {
        paths.extend(dir(&bus));
    }
    paths.extend(
        VM_NODES
            .iter()
            .map(|n| places.dev.join(n))
            .filter(|p| p.exists()),
    );
    paths
        .into_iter()
        .filter_map(|path| {
            let (major, minor) = stat(&path)?;
            Some(Node {
                props: udev_props(places.udev, major, minor),
                sys: fs::canonicalize(places.sys_char.join(format!("{major}:{minor}"))).ok(),
                path,
                major,
                minor,
            })
        })
        .collect()
}

/// The machine's nodes ([`scan`] of [`Places::host`]).
pub fn host_nodes() -> Vec<Node> {
    scan(Places::host(), &char_device)
}

/// The nodes of `nodes` the grants give.
pub fn granted<'a>(nodes: &'a [Node], grants: &[Grant]) -> Vec<&'a Node> {
    // A gamepad's raw node: the one whose HID device has a gamepad's input
    // — and no keyboard's or mouse's: a combo receiver's raw node carries
    // the keys typed.
    let pads: HashSet<PathBuf> = if grants.contains(&Grant::Games) {
        let typing: HashSet<PathBuf> = nodes
            .iter()
            .filter(|n| n.typing_input())
            .filter_map(Node::hid)
            .collect();
        nodes
            .iter()
            .filter(|n| n.gamepad_input())
            .filter_map(Node::hid)
            .filter(|hid| !typing.contains(hid))
            .collect()
    } else {
        HashSet::new()
    };
    nodes
        .iter()
        .filter(|node| {
            let name = node.name();
            grants.iter().any(|grant| match grant {
                Grant::Games => {
                    node.gamepad_input()
                        || (name.starts_with("hidraw")
                            && node.physical()
                            && node.hid().is_some_and(|hid| pads.contains(&hid)))
                }
                Grant::SecurityKeys => {
                    name.starts_with("hidraw") && node.prop("ID_SECURITY_TOKEN") == Some("1")
                }
                Grant::Phone => {
                    node.usb_device() && {
                        let interfaces = node.prop("ID_USB_INTERFACES").unwrap_or_default();
                        interfaces.contains(":ff4201:")
                            || interfaces.contains(":060101:")
                            || node.prop("ID_MTP_DEVICE") == Some("1")
                    }
                }
                Grant::Serial => name.starts_with("ttyUSB") || name.starts_with("ttyACM"),
                Grant::Vm => node.vm(),
                Grant::Usb {
                    vendor,
                    product,
                    serial,
                } => {
                    node.prop("ID_VENDOR_ID")
                        .map(str::to_ascii_lowercase)
                        .as_deref()
                        == Some(vendor.as_str())
                        && node
                            .prop("ID_MODEL_ID")
                            .map(str::to_ascii_lowercase)
                            .as_deref()
                            == Some(product.as_str())
                        && serial
                            .as_deref()
                            .is_none_or(|s| node.prop("ID_SERIAL_SHORT") == Some(s))
                }
            })
        })
        .collect()
}

/// A device plugged in, as `cellward devices` shows it: the name a grant
/// gives it by (`None`: udev names no USB vendor and product for it), a name
/// for a person, the sets it falls into, and its nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connected {
    pub id: Option<String>,
    pub name: String,
    pub sets: Vec<String>,
    pub nodes: Vec<String>,
}

/// The devices `nodes` are, each once.
pub fn connected(nodes: &[Node]) -> Vec<Connected> {
    let in_set: Vec<(&str, Vec<&Node>)> = SETS
        .iter()
        .map(|(name, grant)| (*name, granted(nodes, std::slice::from_ref(grant))))
        .collect();
    let mut out: Vec<(Option<String>, Connected)> = Vec::new();
    for node in nodes {
        let usb = |key: &str| node.prop(key).map(str::to_ascii_lowercase);
        let id = match (usb("ID_VENDOR_ID"), usb("ID_MODEL_ID")) {
            (Some(vendor), Some(product))
                if hex4(&vendor).is_some() && hex4(&product).is_some() =>
            {
                Some(
                    Grant::Usb {
                        vendor,
                        product,
                        // A serial a grant cannot carry is left out: the
                        // device is named by its maker and model alone.
                        serial: node
                            .prop("ID_SERIAL_SHORT")
                            .filter(|s| serial_word(s))
                            .map(str::to_owned),
                    }
                    .word(),
                )
            }
            _ => None,
        };
        let sets: Vec<String> = in_set
            .iter()
            .filter(|(_, given)| given.iter().any(|n| n.path == node.path))
            .map(|(name, _)| (*name).to_owned())
            .collect();
        let path = node.path.display().to_string();
        match out.iter_mut().find(|(key, _)| key.is_some() && *key == id) {
            Some((_, device)) => {
                device.nodes.push(path);
                for set in sets {
                    if !device.sets.contains(&set) {
                        device.sets.push(set);
                    }
                }
            }
            None => {
                let words = |key: &str| node.prop(key).map(|v| v.replace('_', " "));
                let name = match (words("ID_VENDOR"), words("ID_MODEL")) {
                    (Some(vendor), Some(model)) => format!("{vendor} {model}"),
                    _ => words("ID_SERIAL").unwrap_or_else(|| node.name()),
                };
                out.push((
                    id.clone(),
                    Connected {
                        id,
                        name,
                        sets,
                        nodes: vec![path],
                    },
                ));
            }
        }
    }
    out.into_iter().map(|(_, device)| device).collect()
}

/// A node as `profile-run --device` is handed it, and checks it by:
/// `<path>=<major>:<minor>:<vendor>:<product>[:<serial>]`, `-` for a vendor
/// or product udev did not name — then the number alone is checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pass {
    pub path: PathBuf,
    pub major: u32,
    pub minor: u32,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
}

impl Pass {
    pub fn arg(&self) -> String {
        let mut arg = format!(
            "{}={}:{}:{}:{}",
            self.path.display(),
            self.major,
            self.minor,
            self.vendor.as_deref().unwrap_or("-"),
            self.product.as_deref().unwrap_or("-")
        );
        if let Some(serial) = &self.serial {
            arg.push(':');
            arg.push_str(serial);
        }
        arg
    }

    pub fn parse(arg: &str) -> Option<Self> {
        let (path, rest) = arg.rsplit_once('=')?;
        let mut parts = rest.split(':');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let word = |w: Option<&str>| match w? {
            "-" => Some(None),
            w => hex4(w).map(Some),
        };
        let vendor = word(parts.next())?;
        let product = word(parts.next())?;
        let serial = match parts.next() {
            None => None,
            Some(s) if serial_word(s) => Some(s.to_owned()),
            Some(_) => return None,
        };
        if parts.next().is_some() {
            return None;
        }
        // Only the kinds a grant covers.
        let path = PathBuf::from(path);
        grantable_path(&path).then_some(Self {
            path,
            major,
            minor,
            vendor,
            product,
            serial,
        })
    }

    /// Whether `udev` still says this number is that device.
    pub fn still(&self, udev: &Path, major: u32, minor: u32) -> bool {
        if (major, minor) != (self.major, self.minor) {
            return false;
        }
        let props = udev_props(udev, major, minor);
        let same = |key: &str, want: &Option<String>| match want {
            None => true,
            Some(want) => props.get(key).map(|v| v.to_ascii_lowercase()).as_deref() == Some(want),
        };
        let serial = match &self.serial {
            None => true,
            Some(want) => props.get("ID_SERIAL_SHORT") == Some(want),
        };
        same("ID_VENDOR_ID", &self.vendor) && same("ID_MODEL_ID", &self.product) && serial
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A machine of the test's making: nodes as plain files numbered by the
    /// test, udev's database, and sysfs's links.
    struct Machine {
        base: PathBuf,
        numbers: std::cell::RefCell<HashMap<PathBuf, (u32, u32)>>,
    }

    impl Machine {
        fn new(tag: &str) -> Self {
            let base =
                std::env::temp_dir().join(format!("vz-devices-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&base);
            for dir in [
                "dev/input",
                "dev/bus/usb/001",
                "udev",
                "sys/char",
                "sys/devices",
            ] {
                fs::create_dir_all(base.join(dir)).unwrap();
            }
            Self {
                base,
                numbers: Default::default(),
            }
        }

        /// A node at `dev/<rel>`, `major:minor`, udev's `props`, and its
        /// device in sysfs at `sys/devices/<device>` (none: `None`).
        fn node(
            &self,
            rel: &str,
            major: u32,
            minor: u32,
            props: &[(&str, &str)],
            device: Option<&str>,
        ) {
            let path = self.base.join("dev").join(rel);
            fs::write(&path, "").unwrap();
            self.numbers.borrow_mut().insert(path, (major, minor));
            let text: String = props.iter().map(|(k, v)| format!("E:{k}={v}\n")).collect();
            fs::write(self.base.join(format!("udev/c{major}:{minor}")), text).unwrap();
            if let Some(device) = device {
                let dir = self.base.join("sys/devices").join(device);
                fs::create_dir_all(&dir).unwrap();
                std::os::unix::fs::symlink(
                    &dir,
                    self.base.join(format!("sys/char/{major}:{minor}")),
                )
                .unwrap();
            }
        }

        /// `link` → `target`, both below `sys/devices`.
        fn sys_link(&self, link: &str, target: &str) {
            let target = self.base.join("sys/devices").join(target);
            fs::create_dir_all(&target).unwrap();
            let link = self.base.join("sys/devices").join(link);
            std::os::unix::fs::symlink(target, link).unwrap();
        }

        fn nodes(&self) -> Vec<Node> {
            let (dev, udev, sys) = (
                self.base.join("dev"),
                self.base.join("udev"),
                self.base.join("sys/char"),
            );
            let numbers = self.numbers.borrow();
            scan(
                Places {
                    dev: &dev,
                    udev: &udev,
                    sys_char: &sys,
                },
                &|p| numbers.get(p).copied(),
            )
        }

        fn given(&self, grants: &[Grant]) -> Vec<String> {
            let nodes = self.nodes();
            granted(&nodes, grants)
                .iter()
                .map(|n| {
                    n.path
                        .strip_prefix(self.base.join("dev"))
                        .unwrap()
                        .display()
                        .to_string()
                })
                .collect()
        }
    }

    impl Drop for Machine {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    #[test]
    fn a_grant_reads_and_writes_as_its_word() {
        for word in [
            "games",
            "security-keys",
            "phone",
            "serial",
            "vm",
            "usb:1050:0407",
            "usb:046D:c08b:ABC-1",
        ] {
            let grant = Grant::parse(word).unwrap_or_else(|| panic!("{word}"));
            assert_eq!(
                grant.word(),
                word.to_ascii_lowercase().replace("abc-1", "ABC-1")
            );
        }
        for bad in [
            "",
            "all",
            "usb:",
            "usb:105:0407",
            "usb:1050:04g7",
            "usb:1050:0407:",
            "usb:1050:0407:a b",
            // Not a serial a pass carries.
            "usb:1050:0407:a:b",
            "usb:1050:0407:a=b",
        ] {
            assert_eq!(Grant::parse(bad), None, "{bad:?}");
        }
    }

    /// Each set takes its kind and nothing else: a gamepad and its raw
    /// node, not a keyboard's, not a remapper's virtual one; a security key;
    /// a phone's USB node; serial adapters; one device by what it is.
    #[test]
    fn each_set_takes_its_kind() {
        let m = Machine::new("sets");
        let pad = "pci/usb1/1-2/1-2:1.3/0003:054C:0CE6.0005";
        m.node(
            "input/event12",
            13,
            76,
            &[("ID_INPUT_JOYSTICK", "1"), ("ID_VENDOR_ID", "054c")],
            Some("pad/event12"),
        );
        m.sys_link("pad/event12/device", "pad/input30");
        m.sys_link("pad/input30/device", pad);
        m.node(
            "hidraw5",
            244,
            5,
            &[("ID_VENDOR_ID", "054c")],
            Some("padraw/hidraw5"),
        );
        m.sys_link("padraw/hidraw5/device", pad);
        // A keyboard's raw node, and its input node — not a gamepad's.
        m.node(
            "hidraw3",
            244,
            3,
            &[("ID_VENDOR_ID", "1ea7")],
            Some("kbd/hidraw3"),
        );
        m.sys_link("kbd/hidraw3/device", "pci/usb1/1-3/0003:1EA7:0907.0001");
        m.node(
            "input/event3",
            13,
            67,
            &[("ID_INPUT_JOYSTICK", "1"), ("ID_INPUT_KEYBOARD", "1")],
            Some("kbd/event3"),
        );
        // keyd's virtual pointer, which udev calls a joystick too.
        m.node(
            "input/js0",
            13,
            0,
            &[("ID_INPUT_JOYSTICK", "1")],
            Some("virtual/input/input28/js0"),
        );
        m.node(
            "hidraw9",
            244,
            9,
            &[
                ("ID_SECURITY_TOKEN", "1"),
                ("ID_VENDOR_ID", "1050"),
                ("ID_MODEL_ID", "0407"),
            ],
            None,
        );
        m.node(
            "bus/usb/001/005",
            189,
            4,
            &[("ID_USB_INTERFACES", ":ff4201:"), ("ID_VENDOR_ID", "18d1")],
            None,
        );
        m.node(
            "bus/usb/001/006",
            189,
            5,
            &[("ID_USB_INTERFACES", ":030101:")],
            None,
        );
        m.node(
            "ttyUSB0",
            188,
            0,
            &[
                ("ID_VENDOR_ID", "1a86"),
                ("ID_MODEL_ID", "7523"),
                ("ID_SERIAL_SHORT", "X1"),
            ],
            None,
        );
        m.node("ttyACM2", 166, 2, &[], None);

        // A combo receiver: a gamepad and a keyboard on one HID device —
        // its gamepad input given, its raw node (the keys typed) not.
        let combo = "pci/usb1/1-4/0003:046D:C52B.0009";
        m.node(
            "input/event20",
            13,
            84,
            &[("ID_INPUT_JOYSTICK", "1")],
            Some("combo/event20"),
        );
        m.sys_link("combo/event20/device", "combo/input40");
        m.sys_link("combo/input40/device", combo);
        m.node(
            "input/event21",
            13,
            85,
            &[("ID_INPUT_KEYBOARD", "1")],
            Some("combo/event21"),
        );
        m.sys_link("combo/event21/device", "combo/input41");
        m.sys_link("combo/input41/device", combo);
        m.node("hidraw7", 244, 7, &[], Some("comboraw/hidraw7"));
        m.sys_link("comboraw/hidraw7/device", combo);
        // A Bluetooth LE gamepad, through uhid: not taken for uinput's.
        m.node(
            "input/event30",
            13,
            94,
            &[("ID_INPUT_JOYSTICK", "1")],
            Some("virtual/misc/uhid/0005:045E:0B13.000A/input/input50/event30"),
        );
        assert_eq!(
            m.given(&[Grant::Games]),
            ["hidraw5", "input/event12", "input/event20", "input/event30"]
        );
        assert_eq!(m.given(&[Grant::SecurityKeys]), ["hidraw9"]);
        assert_eq!(m.given(&[Grant::Phone]), ["bus/usb/001/005"]);
        assert_eq!(m.given(&[Grant::Serial]), ["ttyACM2", "ttyUSB0"]);
        let ch340 = Grant::parse("usb:1a86:7523").unwrap();
        assert_eq!(m.given(&[ch340]), ["ttyUSB0"]);
        assert!(m
            .given(&[Grant::parse("usb:1a86:7523:X2").unwrap()])
            .is_empty());
        assert!(m.given(&[]).is_empty());
    }

    /// What profile-run is handed reads back as it was, and a number that
    /// went to another device meanwhile is not that device any more.
    #[test]
    fn a_pass_is_checked_again_by_its_number_and_maker() {
        let m = Machine::new("pass");
        m.node(
            "hidraw9",
            244,
            9,
            &[("ID_VENDOR_ID", "1050"), ("ID_MODEL_ID", "0407")],
            None,
        );
        let node = m.nodes().into_iter().next().unwrap();
        let pass = node.pass();
        let arg = format!("/dev/hidraw9={}", pass.arg().rsplit_once('=').unwrap().1);
        assert_eq!(arg, "/dev/hidraw9=244:9:1050:0407");
        let back = Pass::parse(&arg).unwrap();
        let udev = m.base.join("udev");
        assert!(back.still(&udev, 244, 9));
        assert!(!back.still(&udev, 244, 8));
        fs::write(
            udev.join("c244:9"),
            "E:ID_VENDOR_ID=1ea7\nE:ID_MODEL_ID=0907\n",
        )
        .unwrap();
        assert!(!back.still(&udev, 244, 9));
        for bad in [
            "/etc/shadow=1:1:-:-",
            "/dev/../etc/x=1:1:-:-",
            "/dev/x=1:1",
            "/dev/x=a:1:-:-",
            "/dev/x=1:1:zz:-:-",
        ] {
            assert_eq!(Pass::parse(bad), None, "{bad}");
        }
        // Only the kinds a grant gives, and the serial checked too.
        for bad in [
            "/dev/uinput=10:223:-:-",
            "/dev/input=13:0:-:-",
            "/dev/snd/pcmC0D0c=116:1:-:-",
            "/dev/bus/usb/1/2=189:1:-:-",
            "/dev/hidraw9=244:9:1050:0407:a=b",
        ] {
            assert_eq!(Pass::parse(bad), None, "{bad}");
        }
        for good in [
            "/dev/hidraw9=244:9:1050:0407:ABC",
            "/dev/input/event12=13:76:-:-",
            "/dev/bus/usb/001/005=189:4:18d1:4ee7",
            "/dev/ttyACM0=166:0:-:-",
        ] {
            let pass = Pass::parse(good).unwrap_or_else(|| panic!("{good}"));
            assert_eq!(pass.arg(), good);
        }
        let with_serial = Pass::parse("/dev/hidraw9=244:9:1050:0407:ABC").unwrap();
        fs::write(
            udev.join("c244:9"),
            "E:ID_VENDOR_ID=1050\nE:ID_MODEL_ID=0407\nE:ID_SERIAL_SHORT=XYZ\n",
        )
        .unwrap();
        assert!(!with_serial.still(&udev, 244, 9));
    }

    /// `vm`: the four nodes a virtual machine needs, and nothing else.
    #[test]
    fn the_vm_set_is_kvm_vhost_and_tun() {
        let m = Machine::new("vm");
        fs::create_dir_all(m.base.join("dev/net")).unwrap();
        m.node("kvm", 10, 232, &[], None);
        m.node("vhost-net", 10, 238, &[], None);
        m.node("vhost-vsock", 10, 241, &[], None);
        m.node("net/tun", 10, 200, &[], None);
        m.node("ttyUSB0", 188, 0, &[], None);
        assert_eq!(
            m.given(&[Grant::Vm]),
            ["kvm", "vhost-net", "vhost-vsock", "net/tun"]
        );
        assert_eq!(m.given(&[Grant::Serial]), ["ttyUSB0"]);
        for path in [
            "/dev/kvm",
            "/dev/vhost-net",
            "/dev/vhost-vsock",
            "/dev/net/tun",
        ] {
            assert!(grantable_path(Path::new(path)), "{path}");
        }
        assert!(!grantable_path(Path::new("/dev/tun")));
        assert!(!grantable_path(Path::new("/dev/net/kvm")));
    }

    /// A device once, by the name a grant gives it, with the sets it falls
    /// into and every node of it.
    #[test]
    fn a_device_is_listed_once_with_its_sets_and_nodes() {
        let m = Machine::new("connected");
        let key = [
            ("ID_SECURITY_TOKEN", "1"),
            ("ID_VENDOR_ID", "1050"),
            ("ID_MODEL_ID", "0407"),
            ("ID_SERIAL_SHORT", "123"),
            ("ID_VENDOR", "Yubico"),
            ("ID_MODEL", "YubiKey_OTP+FIDO+CCID"),
        ];
        m.node("hidraw9", 244, 9, &key, None);
        m.node("bus/usb/001/007", 189, 6, &key[1..], None);
        m.node("ttyACM2", 166, 2, &[], None);
        let devices = connected(&m.nodes());
        assert_eq!(devices.len(), 2, "{devices:?}");
        let yubikey = devices.iter().find(|d| d.id.is_some()).unwrap();
        assert_eq!(yubikey.id.as_deref(), Some("usb:1050:0407:123"));
        assert_eq!(yubikey.name, "Yubico YubiKey OTP+FIDO+CCID");
        assert_eq!(yubikey.sets, ["security-keys"]);
        assert_eq!(yubikey.nodes.len(), 2);
        let serial = devices.iter().find(|d| d.id.is_none()).unwrap();
        assert_eq!(serial.sets, ["serial"]);
    }
}
