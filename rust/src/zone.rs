//! Zone life cycle: everything `vpn-zone@<name>.service` starts.
//!
//! A zone is a pair of network namespaces with a tunnel strung between them,
//! created and torn down entirely from the user's session — no root anywhere,
//! not to create one and not to run a program in one.
//!
//! ```text
//! vpn-zone-core zone-holder <name>        (systemd main process, host user)
//!  ├─ xdg-dbus-proxy ×1–2, pulse-filter    [the zone's helpers, host userns]
//!  │  (+ pipewire-context, hermetic zones)
//!  └─ fork ─ user namespace, uid 0 inside                    [holder]
//!      ├─ fork ─ net + mount namespace: THE UPLINK      [uplink.pid]
//!      │           pasta's tap, the only route to the world, and the UDP
//!      │           socket of the tunnel; awg0 is CREATED here and moves ↓
//!      ├─ pasta --netns /proc/<uplink>/ns/net                [the way out]
//!      └─ fork ─ net + mount namespace: THE APP NAMESPACE    [zone.pid]
//!                  lo and awg0 and NOTHING ELSE: the default routes into
//!                  the tunnel, its own resolv.conf, then parks forever
//! ```
//!
//! **Why two namespaces** (`docs/LEAK-MODEL.md`). A leak is impossible not
//! because a rule forbids it but because the path does not exist: the namespace
//! the programs run in has exactly two interfaces, loopback and the tunnel. No
//! LAN, no host, no route to the VPN server, and nothing for a future protocol
//! family to escape through either — there is simply nowhere to send a packet.
//! Everything that talks to the outside world lives one namespace up, where no
//! program of the user's ever runs.
//!
//! **How the tunnel can be in one namespace and its socket in another.** This
//! is a documented property of WireGuard (and of AmneziaWG, which is WireGuard
//! plus obfuscation): the UDP socket of an interface stays in the namespace the
//! interface was **created** in and does not travel with it. So awg0 is created
//! in the uplink, moved into the app namespace with `ip link set … netns …` and
//! configured there — the encrypted packets are born in the uplink and leave
//! through pasta, while the app namespace never sees the endpoint at all.
//!
//! **Two kinds of tunnel, one contour.** A zone is either a kernel
//! WireGuard/AmneziaWG one (its config has an `[Interface]` section) or an
//! OpenConnect one (`[OpenConnect]`, [`crate::openconnect`]). The wall stands in
//! the same place either way — what changes is only what stays behind it. With
//! WireGuard it is a UDP socket; with OpenConnect it is a whole client process:
//! the TLS session, the gateway's address and every packet still wrapped in it
//! live one namespace up, and what arrives in the app namespace is a bare tun
//! device with an address on it. The uplink creates and moves the device in
//! both cases; for OpenConnect it makes the tun in advance, for the client to
//! attach to, because the client runs without a single capability
//! ([`CLIENT_ID`]), and moves it once the client's `--script` — which is us,
//! `vpn-zone-core oc-script` — has written down what the gateway said. A tun
//! device and the descriptor attached to it are separate things, so the client
//! goes on reading and writing packets from the uplink after the interface has
//! left it.
//!
//! **The endpoint is resolved before either namespace exists.** `wg setconf`
//! resolves `Endpoint` itself, through `getaddrinfo`, and retries for a minute
//! and a half before giving up — in the app namespace, where there is no
//! network until the tunnel is up, a hostname would hang the zone. The holder
//! therefore resolves every endpoint while it is still in the host's network
//! and writes literal addresses into the text `setconf` gets.
//!
//! **Why this is possible without root at all** (verified on niri and KWin):
//! unprivileged user namespaces are allowed by the kernel; `/etc/subuid` hands
//! the user a range of extra uids, which is where the zone's "root" comes from
//! (`newuidmap` has `cap_setuid` for exactly this); the amneziawg kernel module
//! lets an interface be created inside such a namespace, so the tunnel is a
//! real one and not a userspace emulation; and the way out is pasta (passt),
//! the same userspace network stack rootless podman runs on.
//!
//! **The double mapping.** Inside the zone we must be uid 0: capabilities are
//! lost on `execve` when the uid is not zero (measured: with an identity
//! mapping `CapEff=0`), and then the kernel refuses to create the interface —
//! and `ip`, `awg` and `wg` are all `execve`d from here. But the user's real uid
//! is mapped a SECOND time, onto itself, so that a program entering the zone
//! through `nsenter --preserve-credentials` runs under the real uid and sees
//! `$HOME` as usual. Podman does exactly this in its keep-id mode.
//! (`docs/GOTCHAS.md` §1)
//!
//! Both namespaces belong to that one user namespace, which is what lets the
//! uplink move an interface into the app namespace: moving a link needs
//! CAP_NET_ADMIN in both, and uid 0 of the owning user namespace has it in
//! every namespace that user namespace owns.
//!
//! **Why the namespaces are separate processes.** pasta stays in the host's
//! network and attaches from the outside through `--netns /proc/<pid>/ns/net`,
//! so the namespace it serves has to belong to another process than the one
//! running pasta. (`docs/GOTCHAS.md` §2)
//!
//! **Kill switch.** Each namespace lives exactly as long as the process parked
//! at the end of its setup; the holder supervises both and takes the whole zone
//! down (pasta included) as soon as either dies. On the systemd side
//! `KillMode=control-group` (the default) does the same to everything that was
//! running inside.
//!
//! And when the holder is gone while programs are still running, the app
//! namespace survives — the programs hold it — but the uplink does not: nothing
//! is left inside it, so the kernel destroys it, and WireGuard's own reaction to
//! its creating namespace going away is to turn the carrier off and close the
//! sockets. awg0 stays where it is and drops every packet. Fail-closed by
//! construction, with nothing to fall back to.
//!
//! **The second echelon.** Both namespaces also get an nftables ruleset, and it
//! is insurance, not the load-bearing wall (`docs/LEAK-MODEL.md`): the app
//! namespace may send nothing except through the tunnel, the uplink nothing
//! except the tunnel's own packets to the endpoint we resolved. Neither rule has
//! anything to do today — there is no other interface in the app namespace, and
//! nothing but the tunnel runs in the uplink — which is exactly the point: the
//! day a mistake puts an interface or a process where none belongs, the packets
//! stop instead of leaving quietly. nftables missing or refused by the kernel is
//! a loud warning and a zone that comes up anyway.
//!
//! **No PID namespace in a zone**, and that is deliberate: `zone.pid` has to
//! name the app-namespace process the way the HOST sees it — `vpn-zone
//! run`/`status` `nsenter` into it by that number — and the uplink hands the
//! interface over by that same host pid, while pasta is given the uplink's.
//! All three are host pids only as long as no pid namespace is created. A
//! zone is transport now (the container design of 2026-09-27): the programs
//! run in their containers' instances, and those have one — their holder
//! makes it, forks the instance's pid 1 into it (`crate::init`), and writes
//! down pid 1's HOST pid as the instance's. Every pid a keeper, a holder or
//! a zone's holder holds is a host pid; only the space's own processes (its
//! device guard, its runtime watcher, its bus filter) number by the
//! instance's namespace, and they read its `/proc`.

use std::borrow::Cow;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, ToSocketAddrs};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::thread;
use std::time::Duration;

use crate::config::{Endpoint, EndpointHost, Family, WgConfig};
use crate::hostif::{self, HostIfConfig};
use crate::openconnect::{self, OcConfig};
use crate::profile::{exit_code_of, home_dir};
use crate::seccomp;
use crate::sys;
use crate::sysuplink::{self, SysUplinkConfig};

/// Where the zones live, below `$HOME`. The bash CLI computes the same path.
pub(crate) const STATE_SUBDIR: &str = ".local/state/vpn-zones";
/// Where the settings are, below `$HOME` — the same as the CLI's `config`.
const CONFIG_SUBDIR: &str = ".config/vpn-zones";
/// What a zone keeps of the project's state directory, and whether it may
/// write there: the throwaway containers' layers (the programs' own data) and
/// the launch registry, which `profile-run` reads to know whether it is the
/// last tenant of a throwaway container.
const ZONE_KEEPS: [(&str, bool); 2] = [(crate::launch::THROWAWAY_DIR, true), (".running", false)];
/// Under the home, what the host acts on and a zone may read but not write:
/// the settings (`declared/`, the broker's "always", the pins' neighbours)
/// and the launcher shims the session runs.
pub(crate) const READ_ONLY_IN_ZONES: [&str; 2] = [CONFIG_SUBDIR, ".local/share/vpn-zones"];

/// Files of one zone. This set is a contract: `vpn-zone` (bash), the desktop
/// picker and the smoke test all read them by these names.
const CONFIG: &str = "config.conf";
const OFFLINE: &str = "offline";
/// The APP namespace, the one `nsenter` targets. Programs run here.
const PID: &str = "zone.pid";
/// When the process of [`PID`] started, and in which boot
/// ([`sys::process_stamp`]): with it the
/// number names this holder and not whoever gets the number after it. The
/// file outlives a stop until the next start, and the number is reused.
const START: &str = "zone.start";
/// The uplink namespace: pasta attaches to it and `vpn-zone gc` recognises a
/// stray pasta by the number in its command line.
const UPLINK_PID: &str = "uplink.pid";
const READY: &str = "ready";
/// The holder's word to the uplink that pasta is done with its namespace
/// (`PastaWord`, `wait_for_default_route`).
const PASTA_DONE: &str = "pasta.done";
const STATUS: &str = "status";
const STATUS_TMP: &str = "status.tmp";
/// The zone's own resolv.conf, in its directory: what the doctor holds the
/// file its probe reads to (D2).
pub(crate) const RESOLV: &str = "resolv.conf";
/// What the zone's own resolv.conf is bound over: the name itself, a chain of
/// symlinks on NixOS or not (`crate::rebind`, D2 — until 2026-09-28 the
/// mount went where the chain ended, `sys::link_target`).
const ETC_RESOLV: &str = "/etc/resolv.conf";
/// The zone's own copy of the NSS configuration, and what it is bound over
/// (the name itself, like resolv.conf).
const NSSWITCH: &str = "nsswitch.conf";
const ETC_NSSWITCH: &str = "/etc/nsswitch.conf";
/// Directories holding a unix socket through which a daemon in the HOST's
/// network answers name lookups. Every one of them is covered by a tmpfs inside
/// the zone — see `hide_host_resolvers`, where the reason is written down.
///
/// Grouped, because the first entry is a pair: `/var/run` is a symlink to
/// `/run` on any modern system, so hiding either name hides the one directory
/// and there is nothing left to do in that group. The groups themselves are
/// independent and each is hidden on its own.
pub(crate) const RESOLVER_DIRS: [&[&str]; 3] = [
    // nscd, or the nsncd NixOS runs in its place.
    &["/run/nscd", "/var/run/nscd"],
    // systemd-resolved: `io.systemd.Resolve`, the varlink socket nss-resolve
    // talks to, and `io.systemd.Resolve.Monitor` next to it.
    &["/run/systemd/resolve"],
    // avahi, i.e. nss-mdns — it would put the name onto the host's LAN.
    &["/run/avahi-daemon"],
];
/// The config with the wg-quick directives taken out and every `Endpoint`
/// turned into a literal address, i.e. what `setconf` gets.
const STRIPPED: &str = ".stripped.conf";

/// The tunnel is always called `awg0`, whatever carries it — either kernel
/// module, or the OpenConnect client, which is told the name with
/// `--interface`. `vpn-zone status`, `vpn-zone check`, the smoke test and, more
/// importantly, the app namespace's own `oifname "awg0" accept` rule all look
/// for that one name; the rule is loaded BEFORE the tunnel arrives, so a
/// backend that brought its own name would have its packets dropped by the
/// second echelon. One name for every kind of zone is the invariant, and the
/// name is historical rather than descriptive.
pub(crate) const TUN_IFACE: &str = "awg0";
/// Name of pasta's interface inside the uplink namespace. Given explicitly
/// because pasta otherwise copies the name of the host's outbound interface —
/// and if the host is itself under a VPN and that interface is called `awg0`,
/// the name would collide with the zone's own tunnel. (`docs/GOTCHAS.md` §2)
const PASTA_IFACE: &str = "hostif";
/// wg-quick's default, used when the config carries no `MTU`.
pub(crate) const DEFAULT_MTU: u32 = 1420;
/// The IPv4 address and gateway a host-interface zone gets on its side of
/// pasta. Its own, not a copy of the host interface's: pasta takes those from
/// the interface's DEFAULT route, and the interfaces such a zone is for — a
/// LAN next to the uplink, a system VPN routed from a table of its own — often
/// have none, and pasta then refuses IPv4 altogether. pasta translates sockets,
/// not addresses: what the other end sees is the host interface's address
/// either way. A /30 at the far end of 10/8, so that it collides with a
/// network somebody wants to reach as rarely as a private range can.
///
/// The prefix goes separately (`-n`): older pasta refuses `ADDR/PREFIX` in
/// `-a` ("Invalid address").
pub(crate) const HOSTIF_GUEST4: &str = "10.255.255.253";
pub(crate) const HOSTIF_PREFIX4: &str = "30";
pub(crate) const HOSTIF_GATEWAY4: &str = "10.255.255.254";

/// The zone's filtered session bus, in its state directory.
const SESSION_BUS_PROXY: &str = "session-bus";
/// The bus filter in front of it (`crate::bus_filter`), what the zone gets as
/// its `bus`.
const SESSION_BUS_FILTER: &str = "session-bus-filter";
/// The sound server's control socket as the zone gets it (`pulse_filter`).
const PULSE_FILTER: &str = "pulse-filter";

/// Is the session bus at `socket` a hermetic zone's filtered one — the zone's
/// filter (or, from before it, its proxy) bound over it? Read from the mount
/// table (`/proc/self/mountinfo`), which says what is really there rather than
/// what a variable claims.
pub fn bus_is_zones_filter(mountinfo: &str, socket: &Path) -> bool {
    crate::doctor::mount_root_at(mountinfo, &socket.to_string_lossy()).is_some_and(|root| {
        [SESSION_BUS_PROXY, SESSION_BUS_FILTER]
            .iter()
            .any(|name| root.ends_with(&format!("/{name}")))
    })
}
/// The same, and nothing older: the zone's bus FILTER bound over the socket.
/// The proxy alone would hand the portal's links to the host (LEAK-MODEL §2),
/// which is what `seal_runtime` refuses to bind; the socket inventory holds a
/// hermetic zone to this (`crate::sockets`).
pub fn bus_is_zones_bus_filter(mountinfo: &str, socket: &Path) -> bool {
    crate::doctor::mount_root_at(mountinfo, &socket.to_string_lossy())
        .is_some_and(|root| root.ends_with(&format!("/{SESSION_BUS_FILTER}")))
}
/// Is the sound server's socket at `socket` the zone's filter bound over it
/// (`seal_runtime`)? Read from the mount table, as [`bus_is_zones_filter`].
pub fn pulse_is_zones_filter(mountinfo: &str, socket: &Path) -> bool {
    crate::doctor::mount_root_at(mountinfo, &socket.to_string_lossy())
        .is_some_and(|root| root.ends_with(&format!("/{PULSE_FILTER}")))
}
/// Is the PipeWire socket at `socket` the zone's restricted one — the
/// security context's socket (`crate::pw_context`) bound over it — and not
/// the host's raw `pipewire-0`? Read from the mount table, as
/// [`bus_is_zones_filter`].
pub fn pipewire_is_zones_context(mountinfo: &str, socket: &Path) -> bool {
    crate::doctor::mount_root_at(mountinfo, &socket.to_string_lossy())
        .is_some_and(|root| root.ends_with(&format!("/{}", crate::pw_context::SOCKET)))
}
/// Where the host's runtime directory is held for the zone's lifetime, to bind
/// entries from — below a tmpfs only the zone's root may enter, because the
/// hold has everything, the compositor's own socket included.
const HOST_RUNTIME: &str = ".host-runtime";
/// The hold's subdirectory the host's runtime directory is bound at.
const HOST_RUNTIME_HELD: &str = "r";
/// What of the runtime directory a hermetic zone keeps: the sound servers and
/// the document portal's files. Not `bus` (the filtered one is bound instead),
/// not `systemd/` (the manager's private socket — a process outside the zone),
/// not `gnupg/`, `ssh-agent`, `keyring/`, `at-spi/` — and not the compositor's
/// socket, which no zone gets (`compositor_private`).
/// (`pulse` is listed as the sound server it is, but never bound as the
/// host's: the zone's `pulse/native` is the filter's — `pulse_filter`. Nor is
/// `pipewire-0`, unless the zone is an audio manager: the zone's is the
/// restricted one of `pw_context`.)
const RUNTIME_KEPT: [&str; 3] = ["pipewire-0", "pulse", "doc"];
/// Ours, below the runtime directory: the broker's socket and the restricted
/// Wayland sockets. Never bound whole — one zone must not reach another zone's
/// sockets —, only the broker and the zone's own Wayland directory.
const OURS: &str = "vpn-zones";

/// Entries of the runtime directory NO zone gets, hermetic or not, created
/// before the zone or after it (`docs/LEAK-MODEL.md` §13):
///
/// * the compositor's own sockets, `wayland-*`: the screen, the clipboard, a
///   virtual keyboard and pointer — a command typed into a terminal of the
///   host. A zone's programs get a restricted socket made by `wl-sandbox`
///   outside the zone, in `vpn-zones/wayland/<zone>/`;
/// * compositors' IPC, which spawn processes on the host: niri's
///   `niri.<display>.<pid>.sock`, sway's `sway-ipc.*`, Hyprland's `hypr/`, i3's
///   `i3/`.
pub fn compositor_private(name: &str) -> bool {
    name.starts_with("wayland-")
        || (name.starts_with("niri.") && name.ends_with(".sock"))
        || name.starts_with("sway-ipc.")
        || name == "hypr"
        || name == "i3"
}

/// Entries of the runtime directory that are a desktop shell's own IPC, which
/// no zone gets either (`docs/THREAT-MODEL.md` W7, 2026-09-28): a hermetic
/// one never did (its runtime directory is an allow-list), an ordinary one
/// had them bound back with the rest. What they answer is the shell's, and
/// the shell runs on the host, outside every zone — what it is asked to do
/// it does there, in the host's network, a program started included:
///
/// * `quickshell/`: Quickshell's instances (`by-id/`, `by-pid/`, `by-path/`),
///   each with its `ipc.sock` — `qs ipc call` runs the functions the shell's
///   configuration exposes (noctalia, DankMaterialShell, caelestia are
///   Quickshell configurations);
/// * `astal/`: Astal's and AGS's instances, `<name>.sock` — a request to the
///   shell's own handler;
/// * `ironbar-ipc.sock`: ironbar's;
/// * `eww-server_*`: eww's daemon — its variables go into the commands its
///   widgets run.
///
/// A named list, as [`compositor_private`] is: a shell that keeps its IPC
/// elsewhere, or on the session bus (KWin's scripting, AGS 1), is not
/// covered by it — an ordinary zone has the whole bus by design
/// (`docs/LEAK-MODEL.md` §1); a hermetic one is the zone for that.
pub fn shell_private(name: &str) -> bool {
    name == "quickshell"
        || name == "astal"
        || name == "ironbar-ipc.sock"
        || name.starts_with("eww-server_")
}

/// Is this entry of the host's runtime directory bound into a zone?
///
/// A hermetic zone keeps what [`RUNTIME_KEPT`] names and nothing else — the
/// host's raw `pipewire-0` only with `raw_pipewire` (`vpn-zone
/// audio-manager`): otherwise the zone's `pipewire-0` is the restricted one
/// (`pw_context`), and the host's must not come in over it, not even when
/// PipeWire restarts and makes its socket anew (the watcher asks this too).
/// An ordinary zone keeps everything — its session bus and `systemd --user`
/// are open by design (`docs/LEAK-MODEL.md` §1), and so the raw `pipewire-0`
/// — except [`compositor_private`] and [`shell_private`]. [`OURS`] is bound
/// piece by piece, never as it is.
pub fn runtime_entry_kept(name: &str, hermetic: bool, raw_pipewire: bool) -> bool {
    // `pulse`: never the host's — the zone gets the filter's socket there.
    // PipeWire's manager socket, `pipewire-0-manager`, never: it is the
    // unrestricted one, meant for the session manager — every client killed,
    // every stream moved (review 2026-09-25, third round).
    if compositor_private(name)
        || shell_private(name)
        || name == OURS
        || name == "pulse"
        || (name.starts_with("pipewire-") && name.ends_with("-manager"))
    {
        return false;
    }
    if hermetic && name == "pipewire-0" {
        return raw_pipewire;
    }
    !hermetic || RUNTIME_KEPT.contains(&name)
}

/// What a program in a hermetic zone may ask of the session bus: the portals,
/// notifications, tray icons, media players, input methods, the screensaver
/// inhibitor (the owner's decision C4). Not `org.freedesktop.systemd1` —
/// starting a process outside the zone —, not the Secret Service, not other
/// programs' interfaces.
///
/// Wildcards: a `.*` suffix as in xdg-dbus-proxy itself, and `-*` for OWN
/// only — our patch of it (`module/patches/xdg-dbus-proxy-own-prefix.patch`),
/// without which the stock proxy refuses the rule and does not start at all.
/// Tray icons need it: Qt and older Electron register theirs as
/// `org.kde.StatusNotifierItem-<pid>-<n>`, the Electron of today (Claude
/// Desktop 2.110, 2026-09-27: "Failed to get the ownership of
/// org.freedesktop.StatusNotifierItem-13-1") as
/// `org.freedesktop.StatusNotifierItem-<pid>-<n>`, and they show nothing if
/// they may not own that name (owner, 2026-09-24 and again 2026-09-27: no tray
/// icon from Claude Desktop in a hermetic zone). `--own=org.kde.*` would do it
/// too — and let the program take `org.kde.kwalletd6` and collect other
/// programs' passwords; `--own=org.freedesktop.*` would take the portals' and
/// the notification daemon's names.
///
/// The portals by name, not `org.freedesktop.portal.*`: that subtree has
/// `org.freedesktop.portal.Flatpak` in it too, whose whole job is starting
/// processes outside the caller's sandbox, and whatever portal service a
/// host adds later. Named: the desktop portal (every interface a program
/// uses: file chooser, OpenURI — answered by the bus filter —, screenshots and
/// screencasts on the user's say-so, settings, notifications) and the document
/// portal a chosen file travels through.
pub const PORTALS: [&str; 2] = [
    "--talk=org.freedesktop.portal.Desktop",
    "--talk=org.freedesktop.portal.Documents",
];

/// Input methods by their portals only (review 2026-09-25, third round):
/// `org.fcitx.Fcitx5` is fcitx5's whole controller — `Configure` starts a
/// program on the host, `OpenX11Connection("host:0")` has the host's fcitx5
/// open a TCP connection anywhere, `SetAddonsState` and `SetConfig` switch on
/// cloud pinyin, which fetches from the host's network — and when fcitx5
/// stands in for IBus, `org.freedesktop.IBus` is the same. The portals expose
/// `CreateInputContext` and contexts guarded by their owner; typing works
/// through them as it does in Flatpak.
pub const SESSION_BUS_RULES: [&str; 25] = [
    "--filter",
    PORTALS[0],
    PORTALS[1],
    DESKTOP_SERVICES[0],
    DESKTOP_SERVICES[1],
    DESKTOP_SERVICES[2],
    DESKTOP_SERVICES[3],
    DESKTOP_SERVICES[4],
    DESKTOP_SERVICES[5],
    DESKTOP_SERVICES[6],
    DESKTOP_SERVICES[7],
    DESKTOP_SERVICES[8],
    TRAY_ITEM_NAMES[0],
    TRAY_ITEM_NAMES[1],
    // A media player's name to take, and only that: our proxy's `.*` for
    // OWN (module/patches) — upstream, OWN on the subtree was talk to every
    // host player's whole connection (host Firefox's `OpenURL`).
    "--own=org.mpris.MediaPlayer2.*",
    "--talk=org.freedesktop.portal.IBus",
    INPUT_METHOD_PORTAL[0],
    INPUT_METHOD_PORTAL[1],
    INPUT_METHOD_PORTAL[2],
    SCREEN_SAVER[0],
    SCREEN_SAVER[1],
    SCREEN_SAVER[2],
    SCREEN_SAVER[3],
    SCREEN_SAVER[4],
    SCREEN_SAVER[5],
];

/// The notification daemon and the tray's watcher by their own interfaces
/// only (review 2026-09-27) — the calls: xdg-dbus-proxy passes every
/// broadcast of a name that has call rules, and the `--broadcast` lines
/// only say which ones are wanted. `--talk` to a name is talk to the whole
/// connection that owns it: mako's `fr.emersion.Mako.ListHistory` read every
/// notification of the host and of the other zones, `InvokeAction` set off a
/// host program's action; dunst has `org.dunstproject.cmd0`; on KDE and GNOME
/// the owner is the shell itself.
pub const DESKTOP_SERVICES: [&str; 9] = [
    "--call=org.freedesktop.Notifications=org.freedesktop.Notifications.*@/org/freedesktop/Notifications",
    "--call=org.freedesktop.Notifications=org.freedesktop.DBus.Introspectable.Introspect@/org/freedesktop/Notifications",
    "--broadcast=org.freedesktop.Notifications=org.freedesktop.Notifications.*@/org/freedesktop/Notifications",
    "--call=org.kde.StatusNotifierWatcher=org.kde.StatusNotifierWatcher.*@/StatusNotifierWatcher",
    "--call=org.kde.StatusNotifierWatcher=org.freedesktop.DBus.Properties.Get@/StatusNotifierWatcher",
    "--call=org.kde.StatusNotifierWatcher=org.freedesktop.DBus.Properties.GetAll@/StatusNotifierWatcher",
    "--call=org.kde.StatusNotifierWatcher=org.freedesktop.DBus.Introspectable.Introspect@/StatusNotifierWatcher",
    "--broadcast=org.kde.StatusNotifierWatcher=org.kde.StatusNotifierWatcher.*@/StatusNotifierWatcher",
    // The shell and the tray read each other's properties this way too.
    "--broadcast=org.kde.StatusNotifierWatcher=org.freedesktop.DBus.Properties.*@/StatusNotifierWatcher",
];

/// fcitx5's portal by its interfaces only: fcitx5 owns
/// `org.freedesktop.portal.Fcitx` itself, and talk to it was talk to its
/// controller — `Configure` starts a program on the host (see
/// [`SESSION_BUS_RULES`]).
pub const INPUT_METHOD_PORTAL: [&str; 3] = [
    "--call=org.freedesktop.portal.Fcitx=org.fcitx.Fcitx.InputMethod1.*@/org/freedesktop/portal/inputmethod",
    "--call=org.freedesktop.portal.Fcitx=org.fcitx.Fcitx.InputContext1.*@/org/freedesktop/portal/inputcontext/*",
    "--broadcast=org.freedesktop.portal.Fcitx=org.fcitx.Fcitx.InputContext1.*@/org/freedesktop/portal/inputcontext/*",
];

/// Keeping the screen awake, and nothing else of the screensaver's owner
/// (the shell, on KDE): at either path it answers on. Introspection too: Qt's
/// `QDBusInterface` asks for it first, and is no interface without it.
pub const SCREEN_SAVER: [&str; 6] = [
    "--call=org.freedesktop.ScreenSaver=org.freedesktop.ScreenSaver.Inhibit@/org/freedesktop/ScreenSaver",
    "--call=org.freedesktop.ScreenSaver=org.freedesktop.ScreenSaver.UnInhibit@/org/freedesktop/ScreenSaver",
    "--call=org.freedesktop.ScreenSaver=org.freedesktop.DBus.Introspectable.Introspect@/org/freedesktop/ScreenSaver",
    "--call=org.freedesktop.ScreenSaver=org.freedesktop.ScreenSaver.Inhibit@/ScreenSaver",
    "--call=org.freedesktop.ScreenSaver=org.freedesktop.ScreenSaver.UnInhibit@/ScreenSaver",
    "--call=org.freedesktop.ScreenSaver=org.freedesktop.DBus.Introspectable.Introspect@/ScreenSaver",
];

/// Tray icons' names, owned and nothing more (see [`SESSION_BUS_RULES`]): the
/// KDE spelling and the freedesktop one — the same protocol, and the watcher
/// takes an item by either.
pub const TRAY_ITEM_NAMES: [&str; 2] = [
    "--own=org.kde.StatusNotifierItem-*",
    "--own=org.freedesktop.StatusNotifierItem-*",
];

/// The host's system bus.
pub(crate) const SYSTEM_BUS: &str = "/run/dbus/system_bus_socket";
/// The zone's filtered system bus, in its state directory.
const SYSTEM_BUS_PROXY: &str = "system-bus";

/// What a program in a zone may ask of the system bus (the owner's decision
/// B2, `docs/HERMETICITY.md` §7). Everything else — NetworkManager (the
/// machine's real interfaces, SSIDs and addresses), hostname1, resolve1 (a
/// resolver in the host's network), machined, timedate1 — is filtered out:
/// de-anonymisation without a single packet.
///
/// * UPower whole: battery state, read by players and browsers;
/// * login1 only to inhibit sleep and to read properties — not the list of
///   sessions, not power management.
pub const SYSTEM_BUS_RULES: [&str; 6] = [
    "--filter",
    "--talk=org.freedesktop.UPower",
    "--call=org.freedesktop.login1=org.freedesktop.login1.Manager.Inhibit@/org/freedesktop/login1",
    "--call=org.freedesktop.login1=org.freedesktop.DBus.Properties.Get@/org/freedesktop/login1",
    "--call=org.freedesktop.login1=org.freedesktop.DBus.Properties.GetAll@/org/freedesktop/login1",
    "--call=org.freedesktop.login1=org.freedesktop.DBus.Introspectable.Introspect@/org/freedesktop/login1",
];

/// pasta's doors that nothing here uses, shut. Its defaults open four:
///
/// * `-t auto`, `-u auto` — every port bound in the uplink is bound on the
///   HOST as well and forwarded in: the tunnel's own UDP socket got a port on
///   every address of the machine, reachable from the LAN;
/// * `-T auto`, `-U auto` — every port bound on the host's loopback is offered
///   on the uplink's loopback, and the uplink's filter accepts `lo`: the
///   OpenConnect client running there could talk to any local service of the
///   host;
/// * the gateway address maps to the host's loopback (`--no-map-gw` shuts it).
///
/// The tunnel needs none of them: its packets are flows it starts itself, and
/// pasta tracks those without any forwarding. (`docs/GOTCHAS.md` §2)
pub(crate) const PASTA_CLOSED: [&str; 9] = [
    "-t",
    "none",
    "-u",
    "none",
    "-T",
    "none",
    "-U",
    "none",
    "--no-map-gw",
];
/// Resolvers for a config without `DNS=`: public ones, reached through the
/// tunnel. (`docs/GOTCHAS.md` §3)
const DEFAULT_RESOLVERS: [&str; 2] = ["1.1.1.1", "9.9.9.9"];

/// Name of the table both namespaces get, so that `nft list ruleset` inside a
/// zone says whose rules these are.
const NFT_TABLE: &str = "vpnzone";

/// How often the tunnel state is mirrored into the `status` file. Five seconds
/// is the compromise the bash version settled on: the handshake shows up almost
/// at once and the load is nil.
pub(crate) const STATUS_PERIOD: Duration = Duration::from_secs(5);
/// When to report the first handshake to the journal.
pub(crate) const HANDSHAKE_AFTER: Duration = Duration::from_secs(4);

/// Handshake bytes between the holder and its user-namespace child.
const SYNC_OK: u8 = b'1';
const SYNC_FAIL: u8 = b'0';

/// Which tool speaks to the interface the uplink built. The app namespace does
/// not try the kernel modules itself — the interface is already there by the
/// time it hears about it — so the uplink says which of the two it got.
const TOOL_AWG: u8 = b'a';
const TOOL_WG: u8 = b'w';
/// The tunnel came from the OpenConnect client: the interface is already in the
/// app namespace and the facts about it are in the plan file the uplink wrote
/// from what the client's script said. (`crate::openconnect`)
const TOOL_OC: u8 = b'o';
/// pasta attached to the app namespace itself, going out through an interface
/// of the host (`crate::hostif`).
const TOOL_HOSTIF: u8 = b'h';
/// pasta, started by the system-zone service in a system zone's network, has
/// attached to the app namespace (`docs/SYSTEM.md` §7b).
const TOOL_SYSZONE: u8 = b's';
/// The system tier's run directory: its root service's socket and the system
/// zones' state. Hidden in every zone (`hide_system_tier`).
pub(crate) const SYSTEM_TIER_DIR: &str = "/run/vpn-zones";
/// The system zone's resolvers, as the service said them, one per line: what
/// the app namespace's resolv.conf is written from.
const SYS_RESOLVERS: &str = "system-resolvers";

/// Absolute paths of the tools the zone drives. Absolute because part of this
/// code runs inside a namespace where `PATH` can be anything; Nix substitutes
/// them into the unit's `ExecStart`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tools {
    pub ip: PathBuf,
    pub awg: PathBuf,
    pub wg: PathBuf,
    pub pasta: PathBuf,
    /// What carries a container's instance out through the zone
    /// (`crate::bridge`, stage 2 of the container design of 2026-09-27):
    /// `passt --fd`, from the same package as pasta. A zone started without
    /// it ends every attach at once — passt not there — and says so.
    pub passt: PathBuf,
    /// The second echelon (`docs/LEAK-MODEL.md`). Optional in the sense that a
    /// zone without it still comes up — loudly, and on its topology alone.
    pub nft: PathBuf,
    /// The userspace client of an `[OpenConnect]` zone. Only such a zone runs
    /// it; a WireGuard one never looks at this path.
    pub openconnect: PathBuf,
    /// The filter in front of the system bus (`docs/HERMETICITY.md` §7, B2).
    pub dbus_proxy: PathBuf,
    /// What a hermetic zone's bus filter asks the broker to open a program's
    /// link with (`crate::bus_filter`): `xdg-open`.
    pub opener: PathBuf,
    /// What the sound filter asks the person with when a program of the
    /// zone would record the microphone (`crate::microphone`).
    pub kdialog: PathBuf,
    /// The launch window, for the sound filter's questions (guarded,
    /// `crate::window::question`); empty: kdialog.
    pub window: PathBuf,
    /// The command line's path in the profile (the manifest's `runner`): the
    /// `Exec` of the zone's entry for the portal (`desktop::render_zone_entry`),
    /// which GLib loads only when it finds the program it names.
    pub runner: PathBuf,
}

impl Default for Tools {
    /// Bare names, i.e. "find them on `PATH`". Only used when a flag was left
    /// out — running the holder by hand, out of a `nix-shell`.
    fn default() -> Self {
        Self {
            ip: PathBuf::from("ip"),
            awg: PathBuf::from("awg"),
            wg: PathBuf::from("wg"),
            pasta: PathBuf::from("pasta"),
            passt: PathBuf::from("passt"),
            nft: PathBuf::from("nft"),
            openconnect: PathBuf::from("openconnect"),
            dbus_proxy: PathBuf::from("xdg-dbus-proxy"),
            opener: PathBuf::from("xdg-open"),
            kdialog: PathBuf::from("kdialog"),
            window: PathBuf::new(),
            runner: PathBuf::from("cellward"),
        }
    }
}

/// What `zone-holder` was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// Name of the zone, i.e. the directory below the state directory. An
    /// `OsString` because it is part of a path.
    pub name: OsString,
    pub tools: Tools,
}

/// Everything that can be wrong with the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgError {
    /// No zone name, or an empty one.
    MissingName,
    /// A `--tool` flag without its path.
    MissingValue(String),
    UnknownFlag(String),
    /// More than one zone name. Almost always a quoting accident.
    ExtraArguments,
}

impl std::fmt::Display for ArgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingName => write!(f, "need a zone name"),
            Self::MissingValue(flag) => write!(f, "{flag} needs a path"),
            Self::UnknownFlag(flag) => write!(f, "unknown flag: {flag}"),
            Self::ExtraArguments => write!(f, "only one zone name is accepted"),
        }
    }
}

impl std::error::Error for ArgError {}

impl Args {
    /// Parse `[--ip P] [--awg P] [--wg P] [--pasta P] [--passt P] [--nft P]
    /// [--openconnect P] [--dbus-proxy P] [--opener P] [--kdialog P]
    /// [--runner P] <name>`.
    ///
    /// Only `--`-prefixed words are flags, so a zone name is free to start with
    /// a single dash. The order does not matter, but the unit puts the tool
    /// paths first and `%i` last.
    pub fn parse(argv: &[OsString]) -> Result<Self, ArgError> {
        let mut tools = Tools::default();
        let mut name: Option<OsString> = None;
        let mut rest = argv.iter();

        while let Some(arg) = rest.next() {
            if !arg.as_bytes().starts_with(b"--") {
                if name.is_some() {
                    return Err(ArgError::ExtraArguments);
                }
                name = Some(arg.clone());
                continue;
            }
            let flag = arg.to_string_lossy().into_owned();
            let slot = match flag.as_str() {
                "--ip" => &mut tools.ip,
                "--awg" => &mut tools.awg,
                "--wg" => &mut tools.wg,
                "--pasta" => &mut tools.pasta,
                "--passt" => &mut tools.passt,
                "--nft" => &mut tools.nft,
                "--openconnect" => &mut tools.openconnect,
                "--dbus-proxy" => &mut tools.dbus_proxy,
                "--opener" => &mut tools.opener,
                "--kdialog" => &mut tools.kdialog,
                "--window" => &mut tools.window,
                "--runner" => &mut tools.runner,
                _ => return Err(ArgError::UnknownFlag(flag)),
            };
            let value = rest
                .next()
                .ok_or_else(|| ArgError::MissingValue(flag.clone()))?;
            *slot = PathBuf::from(value);
        }

        let name = name
            .filter(|n| !n.is_empty())
            .ok_or(ArgError::MissingName)?;
        Ok(Self { name, tools })
    }
}

/// One zone: its name, its directory and the tools it drives.
struct Zone {
    name: OsString,
    dir: PathBuf,
    /// The user's home: the project's settings and shims under it are made
    /// read-only in the zone ([`hide_project_state`]).
    home: PathBuf,
    tools: Tools,
    /// Hermetic (`docs/HERMETICITY.md` §7 C): the runtime directory closed,
    /// the session bus filtered, the broker as the one way out. Decided once,
    /// when the zone comes up, so the bus proxy and the sealed runtime
    /// directory cannot disagree about it.
    hermetic: bool,
    /// The host's Nix daemon in reach (`hermetic::nix_daemon`); off by default.
    nix_daemon: bool,
    /// What the host runs from the home left writable in a hermetic zone
    /// (`hermetic::host_files_writable`); read-only by default.
    host_files_writable: bool,
    /// The host's raw PipeWire socket in a hermetic zone
    /// (`hermetic::audio_manager`); off by default: the restricted one.
    audio_manager: bool,
    /// Not a zone but a container's instance (`crate::instance`, the
    /// container design of 2026-09-27): the same space for its programs —
    /// every cover, the helpers, its own `/dev` —, set up by the same code,
    /// with the differences [`InstanceInfo`] names. `None`: a zone, exactly
    /// as before.
    instance: Option<InstanceInfo>,
}

/// What makes a space a container's instance and not a zone
/// (`crate::instance`). Its `Zone` is named by the instance's id and lives
/// in the instance's directory; what differs:
///
/// * the zone-level settings it came up with, and the switches read live
///   (microphone, screen cast), are its network's — the zone's directory of
///   `network`, not its own ([`Zone::settings_dir`]);
/// * its holder writes `instance.pid`/`instance.start` — its pid 1's host
///   pid (stage 3, `crate::init`) —, not `zone.pid`;
/// * of the project's state it keeps its own throwaway layer and nothing
///   else — never the registry (`.running`), which names every container's
///   programs; of the containers' storage, its own container's alone
///   ([`hide_container_storage`]);
/// * `/sys/fs/cgroup`, which names every unit and scope of the user's, is
///   covered ([`cover_cgroupfs`]);
/// * its helpers are told whose its programs are (`--container`) and its
///   user namespace (`--userns`): the instance is the container.
#[derive(Debug, Clone)]
struct InstanceInfo {
    id: String,
    network: String,
    /// The network's zone directory: where its zone-level settings are.
    network_dir: PathBuf,
    who: crate::origin::Who,
    /// Its own container's storage (`instance::Plan::storage`).
    storage: Option<PathBuf>,
    /// Its user namespace, once there is one: for the helpers.
    userns: Option<(u64, u64)>,
}

impl Zone {
    /// For messages only — a directory name may be any byte string.
    fn name(&self) -> Cow<'_, str> {
        self.name.to_string_lossy()
    }

    /// The name the zone-level settings of this space are kept under: the
    /// zone's own, an instance's network's.
    fn settings_name(&self) -> String {
        match &self.instance {
            Some(instance) => instance.network.clone(),
            None => self.name().into_owned(),
        }
    }

    /// Where those settings are: the zone's directory, an instance's
    /// network's.
    fn settings_dir(&self) -> &Path {
        match &self.instance {
            Some(instance) => &instance.network_dir,
            None => &self.dir,
        }
    }

    /// Its directory of restricted Wayland sockets below
    /// `wl_sandbox::SOCKET_DIR`: the zone's name, an instance's key.
    fn wayland_dir(&self) -> String {
        match &self.instance {
            Some(instance) => crate::instance::key(&instance.id),
            None => self.name().into_owned(),
        }
    }

    /// What of the project's state stays in reach inside ([`hide_project_state`]),
    /// and whether writable: [`ZONE_KEEPS`] for a zone; for an instance its
    /// own throwaway layer, where it has one, and nothing else.
    fn keeps(&self) -> Vec<(String, bool)> {
        match &self.instance {
            None => ZONE_KEEPS
                .iter()
                .map(|(name, writable)| ((*name).to_owned(), *writable))
                .collect(),
            Some(instance) => instance
                .storage
                .as_deref()
                .and_then(|storage| storage.strip_prefix(self.home.join(STATE_SUBDIR)).ok())
                .map(|rel| vec![(rel.to_string_lossy().into_owned(), true)])
                .unwrap_or_default(),
        }
    }

    fn path(&self, file: &str) -> PathBuf {
        self.dir.join(file)
    }

    /// A zone with this marker has no network at all: no tunnel, no uplink, no
    /// pasta, just loopback. That is what makes "no internet until it is
    /// explicitly given" possible — the program runs, but a route out does not
    /// physically exist. (`docs/GOTCHAS.md` §2)
    fn is_offline(&self) -> bool {
        self.path(OFFLINE).exists()
    }

    /// `ip …`, with the tool's own diagnostics passed through to the journal.
    fn ip(&self, args: &[&str]) -> Result<(), String> {
        run_tool(&self.tools.ip, args, false)
    }

    /// `ip … 2>/dev/null`: for the calls whose failure is expected and handled.
    fn ip_quiet(&self, args: &[&str]) -> Result<(), String> {
        run_tool(&self.tools.ip, args, true)
    }

    /// First line of `ip …` output, empty if the call failed.
    fn ip_line(&self, args: &[&str]) -> String {
        tool_output(&self.tools.ip, args)
            .unwrap_or_default()
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    }

    /// Load the second echelon into the CURRENT network namespace.
    ///
    /// Never fatal, and that is a decision rather than laziness
    /// (`docs/LEAK-MODEL.md`): the filter insures the topology, the topology
    /// does not lean on the filter. An old kernel, a kernel without the
    /// `nf_tables` module loaded (it cannot be autoloaded from inside an
    /// unprivileged user namespace) or no `nft` at all must not cost the user
    /// the zone — but it must be impossible to miss in the journal, because a
    /// zone whose second echelon is off is a zone one mistake away from a leak.
    fn seal(&self, side: &str, ruleset: &str) {
        if let Err(e) = feed_nft(&self.tools.nft, ruleset) {
            eprintln!(
                "zone {}: {side}: nftables second echelon is OFF ({e}) — the zone is up and \
                 still hermetic by construction, but nothing insures it against a mistake",
                self.name()
            );
        }
    }
}

/// Run the holder. Returns the exit code for the process.
pub fn run(args: Args) -> u8 {
    let Some(home) = home_dir() else {
        eprintln!("zone-holder: no $HOME and no passwd entry — cannot find the zone directory");
        return 1;
    };
    let dir = home.join(STATE_SUBDIR).join(&args.name);
    let config = home.join(CONFIG_SUBDIR);
    let label = args.name.to_string_lossy().into_owned();
    // The list of containers launched into the zone since it came up
    // (`launched-containers`), which a previous build kept: nothing is
    // launched into a zone's own namespaces since stage 5 of the container
    // design, and nothing reads it — the last run's goes.
    let _ = fs::remove_file(dir.join("launched-containers"));
    let (hermetic, _) = crate::hermetic::zone_setting(&dir, &config, &label);
    let (nix_daemon, _) = crate::hermetic::nix_daemon(&dir, &config, &label);
    let (host_files_writable, _) = crate::hermetic::host_files_writable(&dir, &config, &label);
    let (audio_manager, _) = crate::hermetic::audio_manager(&dir, &config, &label);
    let zone = Zone {
        dir,
        home,
        name: args.name,
        tools: args.tools,
        hermetic,
        nix_daemon,
        host_files_writable,
        audio_manager,
        instance: None,
    };

    // A directory is a zone if it has a config or the offline marker; anything
    // else is a typo, and starting a namespace for it would only confuse.
    if !zone.path(CONFIG).exists() && !zone.is_offline() {
        eprintln!(
            "zone {}: neither {} nor an offline marker",
            zone.name(),
            zone.path(CONFIG).display()
        );
        return 1;
    }
    // Leftovers of a previous run would make `vpn-zone up` and the picker
    // believe this zone is already up.
    let _ = fs::remove_file(zone.path(PID));
    let _ = fs::remove_file(zone.path(START));
    // And the previous run's liveness: shown until this run's first write,
    // it said "connected" of a tunnel not there yet (review).
    let _ = fs::remove_file(zone.path(STATUS));
    let _ = fs::remove_file(zone.path(UPLINK_PID));
    let _ = fs::remove_file(zone.path(READY));
    let _ = fs::remove_file(zone.path(PASTA_DONE));
    // And the last run's bridge (`crate::bridge`): a launch that found its
    // socket would take this run for one that carries instances before it
    // does.
    let _ = fs::remove_file(zone.path(crate::bridge::SOCKET));
    let _ = fs::remove_file(zone.path(crate::bridge::RULE_MARK));
    // What this run comes up with, before it is up: `status --json` names what
    // has changed since (`hermetic::APPLIED`). The last run's goes first — a
    // note that cannot be written leaves "not known", never a stale one.
    let _ = fs::remove_file(zone.path(crate::hermetic::APPLIED));
    if let Err(e) = crate::hermetic::note_applied(
        &zone.dir,
        &[
            ("hermetic", zone.hermetic),
            ("nix_daemon", zone.nix_daemon),
            ("host_files_writable", zone.host_files_writable),
            ("audio_manager", zone.audio_manager),
        ],
    ) {
        eprintln!(
            "zone {}: cannot note its settings ({e}) — status cannot tell what needs a restart",
            zone.name()
        );
    }
    prepare_host(&zone, &label);

    let ids = match Ids::current() {
        Ok(ids) => ids,
        Err(e) => {
            eprintln!("zone {}: {e}", zone.name());
            return 1;
        }
    };

    match hold(&zone, &ids, runs_a_client(&zone)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("zone {}: {e}", zone.name());
            1
        }
    }
}

/// What a zone — or a container's instance — needs of the host before its
/// namespaces exist, made as the user: what its space keeps in reach, what it
/// covers (a directory made after it came up would not be covered), and the
/// portal's entry of `label`, the zone's name (an instance's network's).
fn prepare_host(zone: &Zone, label: &str) {
    // What the zone keeps of the project's state has to exist before the zone
    // hides the rest (`hide_project_state`): a directory created afterwards
    // would not be seen in there. As the user, so that the host keeps writing
    // into them.
    // (An instance's own throwaway layer is there already: the launch made
    // it before it started the instance.)
    if zone.instance.is_none() {
        if let Some(state) = zone.dir.parent() {
            for (name, _) in ZONE_KEEPS {
                let _ = fs::create_dir_all(state.join(name));
            }
        }
    }
    for dir in READ_ONLY_IN_ZONES {
        let _ = fs::create_dir_all(zone.home.join(dir));
    }
    // IBus's places, covered in every zone (`hide_input_methods`) — where
    // they are: one made after the zone came up, by the host's IBus starting
    // for the first time, would put its address and its private bus's socket
    // in the zone's sight.
    for dir in input_method_places(&zone.home) {
        if fs::symlink_metadata(&dir).is_err() {
            use std::os::unix::fs::DirBuilderExt;
            let _ = fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir);
        }
    }
    // Container storage, covered in the zone (`hide_container_storage`): it
    // has to exist to be covered — a directory a program of the zone made
    // there afterwards would be one the host takes for a container.
    for dir in crate::home_layer::STORAGE {
        let _ = fs::create_dir_all(zone.home.join(dir));
    }
    // The zone's entry for the portal (`desktop::zone_app_id`, LEAK-MODEL
    // §23), here on the host and before the zone has a program: the portal
    // takes the id a bus filter registers only with `<id>.desktop` there to
    // be found — else the zone's programs stay a nameless host application to
    // it. For every zone: a sandbox in a zone that is not hermetic registers
    // too (`fs_sandbox`). Sync keeps it while the zone is there.
    match crate::desktop::write_zone_entry(&zone.home, label, &zone.tools.runner.to_string_lossy())
    {
        Ok(_) => {}
        Err(e) => eprintln!(
            "zone {}: no entry for the portal ({e}) — the portal will not know its programs \
             by the zone's name",
            zone.name()
        ),
    }
    // The session's own entry points, when the zone is to have them
    // read-only: a directory that is not there cannot be, and a program would
    // make it (`protect_host_files`).
    if zone.hermetic && !zone.host_files_writable {
        for dir in ENTRY_POINTS {
            let path = zone.home.join(dir);
            if fs::symlink_metadata(&path).is_err() {
                use std::os::unix::fs::DirBuilderExt;
                let _ = fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&path);
            }
        }
        // The associations too, empty where there are none: a file a program
        // of the zone made would be the host's choice of what opens links.
        let mimeapps = zone.home.join(".config/mimeapps.list");
        if fs::symlink_metadata(&mimeapps).is_err() {
            let _ = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&mimeapps);
        }
    }
}

// --- THE DOUBLE MAPPING ------------------------------------------------------

/// The ids the mapping is built from.
struct Ids {
    uid: u32,
    gid: u32,
    /// First range of `/etc/subuid` for this user: the zone's uid 0 comes from
    /// its beginning.
    subuid: u64,
    subgid: u64,
}

impl Ids {
    fn current() -> Result<Self, String> {
        // SAFETY: getuid/getgid take no arguments and cannot fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let user =
            user_name(uid).ok_or_else(|| "no passwd entry for the current uid".to_string())?;
        Ok(Self {
            uid,
            gid,
            subuid: first_subid("/etc/subuid", &user, uid)?,
            subgid: first_subid("/etc/subgid", &user, gid)?,
        })
    }
}

/// The host ids every zone's way out runs under: the zone's uid 0 and gid 0,
/// i.e. the start of the user's subordinate ranges. pasta is started by the
/// holder as uid 0 inside the zone's user namespace, so every socket a zone's
/// traffic leaves the host by is owned by these — which a host firewall can
/// match (`meta skuid`) without knowing anything about user units. (The
/// OpenConnect client runs as [`CLIENT_ID`], but its sockets are in the
/// uplink's network, not the host's: what reaches the host is pasta's.)
pub fn uplink_owner() -> Option<(u64, u64)> {
    Ids::current().ok().map(|ids| (ids.subuid, ids.subgid))
}

fn user_name(uid: libc::uid_t) -> Option<String> {
    // SAFETY: getpwuid returns a pointer into a static buffer, read here before
    // anything else can call into the passwd machinery again.
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() || (*pw).pw_name.is_null() {
            return None;
        }
        Some(CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned())
    }
}

/// Start of the first range belonging to this user.
///
/// Without a range a rootless zone is impossible in principle, so this is
/// checked explicitly and said out loud rather than left to a confusing
/// `newuidmap` failure. (`docs/GOTCHAS.md` §1)
fn first_subid(file: &str, user: &str, id: u32) -> Result<u64, String> {
    let text = fs::read_to_string(file).map_err(|e| format!("cannot read {file}: {e}"))?;
    for line in text.lines() {
        let mut fields = line.split(':');
        let (Some(owner), Some(start)) = (fields.next(), fields.next()) else {
            continue;
        };
        // shadow accepts the login name or the numeric id in the first field.
        let owner = owner.trim();
        if owner != user && !owner.parse::<u32>().is_ok_and(|o| o == id) {
            continue;
        }
        return start
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("{file}: the range of {user} does not start with a number"));
    }
    Err(format!(
        "no range for {user} in {file} — a rootless zone is impossible without one"
    ))
}

/// How many ids the first range of this user in a subordinate-id file's
/// `text` has (its third field) — the range [`first_subid`] starts from.
/// `None` when there is no such range or it does not say.
pub fn subid_count_in(text: &str, user: &str, id: u32) -> Option<u64> {
    text.lines().find_map(|line| {
        let mut fields = line.split(':');
        let owner = fields.next()?.trim();
        if owner != user && !owner.parse::<u32>().is_ok_and(|o| o == id) {
            return None;
        }
        let _start = fields.next()?;
        Some(fields.next()?.trim().parse::<u64>().ok())
    })?
}

/// The uid and the gid the OpenConnect client runs as inside its zone's user
/// namespace; on the host it is the second id of the user's subordinate
/// ranges. Mapped only into an `[OpenConnect]` zone ([`runs_a_client`]).
///
/// Not the zone's uid 0, and that is the whole point of it (review
/// 2026-09-27). Uid 0 owns every namespace of the zone: a client running as it
/// could unload the uplink's filter and talk to anything pasta reaches, enter
/// the app namespace and route the zone's traffic around the tunnel, lift the
/// covers — a client the gateway subverted would take the zone apart from the
/// inside. This id owns nothing, has no capabilities anywhere, and is nobody
/// else: not the user the zone's programs run as, not the root the zone's own
/// processes run as. What it may do is what [`spawn_openconnect`] gives it —
/// a tun made for it in advance, a directory of its own.
const CLIENT_ID: u32 = 1;

/// Whether the zone's config is an `[OpenConnect]` one, i.e. whether its user
/// namespace needs [`CLIENT_ID`]. [`prepare`] reads the config again and is
/// what decides; a config that cannot be read or parsed here is answered no,
/// and fails there with its own message. (A config turned into an
/// OpenConnect one in between gets a client that cannot become its id, and
/// the zone does not come up.)
fn runs_a_client(zone: &Zone) -> bool {
    fs::read(zone.path(CONFIG))
        .ok()
        .and_then(|raw| WgConfig::parse(&raw).ok())
        .is_some_and(|cfg| openconnect::is_openconnect(&cfg))
}

/// Write the ranges into the child's namespace.
///
/// `newuidmap`/`newgidmap` are looked up on `PATH` on purpose: on NixOS the
/// setuid wrappers live in `/run/wrappers/bin`, on a Debian-ish CI runner in
/// `/usr/bin` — hardcoding either would break the other. util-linux's `unshare`
/// (what this replaces) did the same `execvp`.
fn map_ids(pid: libc::pid_t, ids: &Ids, client: bool) -> Result<(), String> {
    map_range("newuidmap", pid, ids.subuid, ids.uid, client, false)?;
    map_range("newgidmap", pid, ids.subgid, ids.gid, client, true)
}

/// The arguments of `newuidmap`/`newgidmap` (`gids`): `<pid>` and then
/// `<inside> <outside> <count>` per range. Uid 0 inside comes from the
/// subordinate range, the real id is mapped onto itself, and an OpenConnect
/// zone's client gets [`CLIENT_ID`] from the next subordinate id.
///
/// And the bridge's passt (`crate::bridge`, stage 2 of the container design
/// of 2026-09-27), in every zone: the third subordinate id — as uid
/// [`crate::bridge::BRIDGE_ID`], what the zone's refusal of its local
/// addresses is keyed on (`meta skuid`), and as a gid mapped onto itself.
/// Not 2 for the group: the ping range of a network namespace is one range
/// of gids, kept by its two ends as the host's ids and taken only when they
/// are in order both inside and out (`ping_range`) — the user's group and
/// gid 2 → subgid+2 are in one order inside and the other outside, and no
/// range would hold both. Mapped onto itself, it is in the same order either
/// way, and passt's echo sockets work as the user's do.
fn map_args(
    pid: libc::pid_t,
    sub: u64,
    id: u32,
    client: bool,
    gids: bool,
) -> Result<Vec<String>, String> {
    let mut args = vec![
        pid.to_string(),
        "0".to_string(),
        sub.to_string(),
        "1".to_string(),
        id.to_string(),
        id.to_string(),
        "1".to_string(),
    ];
    if client {
        if id == CLIENT_ID {
            return Err(format!(
                "your own id is {CLIENT_ID}, the one an OpenConnect zone's client runs as \
                 inside the zone — the two cannot share it"
            ));
        }
        args.extend([
            CLIENT_ID.to_string(),
            (sub + u64::from(CLIENT_ID)).to_string(),
            "1".to_string(),
        ]);
    }
    let bridge = sub + u64::from(crate::bridge::BRIDGE_ID);
    let inside = if gids {
        bridge
    } else {
        u64::from(crate::bridge::BRIDGE_ID)
    };
    if u64::from(id) == inside {
        return Err(format!(
            "your own id is {inside}, the one a zone's bridge runs as inside the zone — the \
             two cannot share it"
        ));
    }
    args.extend([inside.to_string(), bridge.to_string(), "1".to_string()]);
    Ok(args)
}

fn map_range(
    tool: &str,
    pid: libc::pid_t,
    sub: u64,
    id: u32,
    client: bool,
    gids: bool,
) -> Result<(), String> {
    let status = Command::new(tool)
        .args(map_args(pid, sub, id, client, gids)?)
        .status()
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                format!("{tool} is not on PATH (package uidmap) — a rootless zone needs it")
            } else {
                format!("cannot run {tool}: {e}")
            }
        })?;
    if !status.success() {
        return Err(format!(
            "{tool} failed ({status}) — check your ranges in /etc/subuid and /etc/subgid (a \
             zone takes the first three ids of each: its root, an OpenConnect client, the \
             bridge that carries containers)"
        ));
    }
    Ok(())
}

// --- PROCESS 1: THE HOLDER ---------------------------------------------------

/// The user-namespace child, so that a signal can be passed on to it.
static USERNS_CHILD: AtomicI32 = AtomicI32::new(0);
/// The two namespaces and pasta, from the point of view of the holder.
static ZONE_CHILD: AtomicI32 = AtomicI32::new(0);
static UPLINK_CHILD: AtomicI32 = AtomicI32::new(0);
static PASTA_CHILD: AtomicI32 = AtomicI32::new(0);
/// Did the shutdown start with a TERM/INT of our own?
static ASKED_TO_STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn forward_signal(sig: libc::c_int) {
    ASKED_TO_STOP.store(true, Ordering::SeqCst);
    let pid = USERNS_CHILD.load(Ordering::SeqCst);
    if pid > 0 {
        // SAFETY: kill(2) is async-signal-safe and takes no pointers.
        unsafe { libc::kill(pid, sig) };
    }
}

extern "C" fn stop_zone(_sig: libc::c_int) {
    ASKED_TO_STOP.store(true, Ordering::SeqCst);
    for slot in [&PASTA_CHILD, &UPLINK_CHILD, &ZONE_CHILD] {
        let pid = slot.load(Ordering::SeqCst);
        if pid > 0 {
            // SAFETY: as above.
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
    }
}

/// A zone taken down on request exited cleanly, whatever the signal did to the
/// exit status.
///
/// Without this `systemctl --user stop vpn-zone@x` would leave the unit in the
/// `failed` state: the zone process dies of SIGTERM, which turns into the exit
/// code 143, and systemd counts only a *signalled* main process as a clean
/// stop. A zone that died on its own still reports its real code — that is the
/// difference worth keeping.
fn stopped_cleanly(code: u8) -> u8 {
    if ASKED_TO_STOP.load(Ordering::SeqCst) {
        0
    } else {
        code
    }
}

fn on_term_and_int(handler: extern "C" fn(libc::c_int)) {
    let handler = handler as libc::sighandler_t;
    // SAFETY: signal(2) with a plain function pointer; the handlers only touch
    // atomics and call kill(2).
    unsafe {
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }
}

fn default_signals() {
    // SAFETY: as above; SIG_DFL is the disposition every child starts from.
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
        libc::signal(libc::SIGINT, libc::SIG_DFL);
    }
}

/// Fork off the user namespace, map the ids into it from the outside, wait.
///
/// The mapping has to be written by a process that is still in the PARENT
/// namespace and can execute the setuid helpers, which is why this dance exists
/// at all: the child unshares and blocks, we map, the child carries on.
fn hold(zone: &Zone, ids: &Ids, client: bool) -> Result<u8, String> {
    let (unshared_r, unshared_w) = sys::pipe().map_err(|e| format!("cannot create a pipe: {e}"))?;
    let (mapped_r, mapped_w) = sys::pipe().map_err(|e| format!("cannot create a pipe: {e}"))?;

    // SAFETY: single-threaded at this point, so the child may allocate and
    // print before it goes its own way.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("cannot fork: {}", io::Error::last_os_error()));
    }
    if pid == 0 {
        drop(unshared_r);
        drop(mapped_w);
        let code = holder(zone, unshared_w, mapped_r);
        // _exit, not exit: the parent's atexit handlers and buffers are not
        // ours to run twice.
        // SAFETY: _exit never returns and touches nothing of ours.
        unsafe { libc::_exit(libc::c_int::from(code)) };
    }
    drop(unshared_w);
    drop(mapped_r);
    USERNS_CHILD.store(pid, Ordering::SeqCst);
    // The unit is `Type=notify`: `systemctl start` — `cellward up`, a launch
    // into a zone that is down — returns when the zone is ready, however long
    // its setup takes (no clock of ours; the unit has no start timeout), or
    // when it failed: this process ends then. `ready` is this run's — the last
    // run's was removed before (`run`) — and it is written by the zone's own
    // process, in the zone's directory this one sees too.
    {
        let ready = zone.path(READY);
        thread::spawn(move || {
            if sys::wait_for_entry(&ready, None, Path::is_file) {
                crate::system::notify_ready();
            }
        });
    }
    // systemd stops the unit by signalling THIS process; without passing it on,
    // the zone would survive its own holder.
    on_term_and_int(forward_signal);

    let mut byte = [0u8; 1];
    let mut unshared = File::from(unshared_r);
    if unshared.read_exact(&mut byte).is_err() || byte[0] != SYNC_OK {
        let _ = reap(pid);
        return Err("the zone could not get a user namespace of its own".to_string());
    }

    if let Err(e) = map_ids(pid, ids, client) {
        // Dropping the write end is the child's signal to give up.
        drop(mapped_w);
        let _ = reap(pid);
        return Err(e);
    }
    // The helpers, before the holder goes on: its namespaces bind their
    // sockets in as one of their first steps.
    let mut helpers = Helpers::start(zone);
    let mut mapped = File::from(mapped_w);
    if mapped.write_all(&[SYNC_OK]).is_err() {
        let _ = reap(pid);
        helpers.stop();
        return Err("the zone stopped listening before the mapping was done".to_string());
    }
    drop(mapped);

    // The holder's end is the zone's end; a helper's is only that helper's.
    let code = loop {
        let (dead, code) = wait_any();
        if dead == pid || dead == -1 {
            break code;
        }
        helpers.died(zone, dead);
    };
    helpers.stop();
    Ok(stopped_cleanly(code))
}

/// The zone's helpers on the host: the filtered system bus, a hermetic zone's
/// session bus, the sound filter, a hermetic zone's PipeWire security context
/// — started by the unit's own process, in the HOST's user namespace, and
/// never by the holder.
///
/// Why not by the holder (review 2026-09-25): a process the holder starts as
/// the user lives in the zone's user namespace, with the very uid and no
/// capabilities, the same as the zone's programs — and `exec` makes it
/// dumpable again. The kernel then lets a program of the zone read it through
/// `/proc/<pid>/`: its `root` is the host's file system as the host sees it
/// (the zone's covers are in the zone's mount namespace, not in the helper's),
/// with the session bus, `pulse/native` unfiltered, the compositor's socket
/// and the zone's microphone setting in reach. A process of the host's user
/// namespace is not readable from a zone's (`cap_ptrace_access_check`:
/// another namespace wants `CAP_SYS_PTRACE` over it — LEAK-MODEL §16), and
/// neither is what it starts: the sound filter's kdialog.
///
/// What they lose by it is the zone's `setgroups(0)`: they keep the unit's
/// supplementary groups, which the sound server and the two buses do not
/// judge a client by — and the bus proxies pass only their allow-lists.
struct Helpers {
    system_bus: libc::pid_t,
    session_bus: libc::pid_t,
    pulse: libc::pid_t,
    pipewire: libc::pid_t,
}

impl Helpers {
    fn start(zone: &Zone) -> Self {
        let pid = |child: Option<Child>| child.map_or(0, |c| c.id() as libc::pid_t);
        // The filtered system bus: without one the zone closes it altogether
        // (`seal_system_bus`).
        let system_bus = pid(start_system_bus_proxy(zone));
        // A hermetic zone's session bus the same way.
        let session_bus = if zone.hermetic {
            pid(start_proxy(
                zone,
                &format!("unix:path={}", host_runtime_dir(zone).join("bus").display()),
                SESSION_BUS_PROXY,
                &SESSION_BUS_RULES,
                "session bus",
            ))
        } else {
            0
        };
        // The sound server through a filter, for every zone (`pulse_filter`).
        let pulse = pid(start_pulse_filter(zone));
        // PipeWire through a security context and WirePlumber's policy, for a
        // hermetic zone that is not an audio manager (`pw_context`); the
        // others keep the raw socket (`runtime_entry_kept`).
        let pipewire = if zone.hermetic && !zone.audio_manager {
            pid(start_pipewire_context(zone))
        } else {
            0
        };
        Self {
            system_bus,
            session_bus,
            pulse,
            pipewire,
        }
    }

    /// A helper died on its own. No reason to take the zone down: the bind
    /// to its socket stays, and connecting to a dead socket is refused — what
    /// it served is simply gone for the zone, which is closed, not open.
    fn died(&mut self, zone: &Zone, dead: libc::pid_t) {
        let what = if dead == self.system_bus {
            self.system_bus = 0;
            "the system bus proxy died — the zone has no system bus now"
        } else if dead == self.session_bus {
            self.session_bus = 0;
            "the session bus proxy died — the zone has no session bus now"
        } else if dead == self.pulse {
            self.pulse = 0;
            "the sound filter died — the zone has no sound server now"
        } else if dead == self.pipewire {
            self.pipewire = 0;
            "the PipeWire context died — the zone's pipewire-0 refuses everything now"
        } else {
            return;
        };
        if !ASKED_TO_STOP.load(Ordering::SeqCst) {
            eprintln!("zone {}: {what}", zone.name());
        }
    }

    /// Nothing may outlive the zone.
    fn stop(&mut self) {
        for pid in [
            &mut self.system_bus,
            &mut self.session_bus,
            &mut self.pulse,
            &mut self.pipewire,
        ] {
            kill_and_reap(*pid);
            *pid = 0;
        }
    }
}

/// Wait for a child, retrying on `EINTR` (our own signal handlers cause it).
fn reap(pid: libc::pid_t) -> u8 {
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: `status` is a valid pointer for the duration of the call.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == -1 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        break;
    }
    exit_code_of(status)
}

/// Wait for the FIRST of our children to die: pid and its exit code. `-1` means
/// there is nothing left to wait for, which can only happen if everything
/// managed to die before we got here.
fn wait_any() -> (libc::pid_t, u8) {
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: `status` is a valid pointer for the duration of the call.
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid == -1 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return (-1, 1);
        }
        return (pid, exit_code_of(status));
    }
}

/// TERM a child and collect it, tolerating one that is already gone.
fn kill_and_reap(pid: libc::pid_t) {
    if pid <= 0 {
        return;
    }
    // SAFETY: kill(2) takes no pointers; the pid is still ours to signal
    // because it has not been waited for yet.
    unsafe { libc::kill(pid, libc::SIGTERM) };
    let _ = reap(pid);
}

// --- PROCESS 2: INSIDE THE USER NAMESPACE ------------------------------------

/// Create the user namespace, wait for the mapping, become uid 0, supervise.
fn holder(zone: &Zone, unshared_w: OwnedFd, mapped_r: OwnedFd) -> u8 {
    // The parent's handlers are meaningless here (they name the parent's
    // child), and the processes forked below inherit whatever we have.
    default_signals();

    // SAFETY: unshare(2) takes no pointers.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
        eprintln!(
            "zone {}: cannot create a user namespace ({}) — unprivileged user namespaces \
             are probably disabled in the kernel",
            zone.name(),
            io::Error::last_os_error()
        );
        let mut unshared = File::from(unshared_w);
        let _ = unshared.write_all(&[SYNC_FAIL]);
        return 1;
    }
    let mut unshared = File::from(unshared_w);
    if unshared.write_all(&[SYNC_OK]).is_err() {
        return 1;
    }
    drop(unshared);

    let mut byte = [0u8; 1];
    let mut mapped = File::from(mapped_r);
    if mapped.read_exact(&mut byte).is_err() || byte[0] != SYNC_OK {
        // The parent has already said what went wrong.
        return 1;
    }
    drop(mapped);

    // uid 0 inside: without it `ip`/`awg` lose their capabilities on execve and
    // the kernel refuses to create the interface. Group first, as always.
    // SAFETY: both take no pointers; we hold every capability in the namespace
    // we have just created.
    if unsafe { libc::setgid(0) } != 0 || unsafe { libc::setuid(0) } != 0 {
        eprintln!(
            "zone {}: cannot become uid 0 inside the namespace ({})",
            zone.name(),
            io::Error::last_os_error()
        );
        return 1;
    }
    // setuid() cleared the dumpable flag, and both namespace processes forked
    // below inherit it. A non-dumpable process hides its /proc/<pid>/ns/* behind
    // a CAP_SYS_PTRACE check that pasta then fails: it has to open the uplink's
    // netns through /proc, gets EACCES and dies on the spot — silently, since
    // passt logs to syslog when stderr is not a terminal. The same check would
    // stop `nsenter` from entering the zone. util-linux's `unshare --setuid`
    // (what this dance replaces) sets dumpable back for exactly this reason, so
    // parity requires it. The exposure is unchanged from the bash version:
    // same-user processes may ptrace the zone.
    // SAFETY: prctl with these arguments takes no pointers.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) };

    match supervise(zone) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("zone {}: {e}", zone.name());
            1
        }
    }
}

// --- CONTAINER INSTANCES -----------------------------------------------------
//
// A container's instance (`crate::instance`, the container design of
// 2026-09-27) is a zone's space without its network: the same covers, the
// same helpers, its own `/dev`, set up by the same code — `zone_setup` in
// instance mode ([`InstanceInfo`]) —, held by processes of its own:
//
// ```text
// vpn-zone-core container-holder <id>     (systemd main process, host user)
//  ├─ the helpers, as a zone's (`Helpers`)            [host user namespace]
//  └─ fork ─ user namespace, uid 0 = subuid+3, then exec `--inner`   [H]
//      └─ unshare(pid), fork ─ PID 1 (`crate::init`)      [instance.pid]
//          │  net + mount + IPC namespaces, the pid namespace's /proc
//          └─ fork ─ THE SPACE: covers, /dev, guard, bus filter
// ```
//
// Stage 3 (2026-09-27, X4): the pid namespace, and the pid 1 its end ends —
// with every program of the instance. `instance.pid` is pid 1's host pid.
//
// Stage 1 gives an instance no way out (lo only): every launch whose network
// is `offline` runs in one, and the `offline` zone is never started for it.

/// The ids of an instance's user namespace, as `newuidmap`/`newgidmap` take
/// them: its root is the user's [`crate::instance::ROOT_ID`]th subordinate
/// id and the user's own id is mapped onto itself (J3 of the design). Not a
/// zone's root, the first subordinate id: a zone's holder is dumpable on
/// purpose ([`holder`]), and any process of the same host uid may trace it —
/// a process of an instance that got out of hand would have been every
/// zone's root, the one that holds the tunnel's keys.
pub fn instance_map_args(pid: libc::pid_t, sub: u64, id: u32) -> Vec<String> {
    vec![
        pid.to_string(),
        "0".to_string(),
        (sub + u64::from(crate::instance::ROOT_ID)).to_string(),
        "1".to_string(),
        id.to_string(),
        id.to_string(),
        "1".to_string(),
    ]
}

/// Write the instance's ids into the user namespace of `pid`
/// ([`instance_map_args`]), from the outside, as [`map_ids`] does a zone's.
fn map_instance(pid: libc::pid_t, ids: &Ids) -> Result<(), String> {
    for (tool, sub, id) in [
        ("newuidmap", ids.subuid, ids.uid),
        ("newgidmap", ids.subgid, ids.gid),
    ] {
        let status = Command::new(tool)
            .args(instance_map_args(pid, sub, id))
            .status()
            .map_err(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    format!("{tool} is not on PATH (package uidmap) — an instance needs it")
                } else {
                    format!("cannot run {tool}: {e}")
                }
            })?;
        if !status.success() {
            return Err(format!(
                "{tool} failed ({status}) — an instance takes the first {} ids of your ranges \
                 in /etc/subuid and /etc/subgid",
                crate::instance::SUBORDINATE_IDS
            ));
        }
    }
    Ok(())
}

/// Whether the user's subordinate ranges have the ids an instance takes —
/// the first [`crate::instance::SUBORDINATE_IDS`] —, said before
/// `newuidmap` fails less clearly.
fn instance_ranges(ids: &Ids) -> Result<(), String> {
    let user = user_name(ids.uid).ok_or("no passwd entry for the current uid")?;
    for (file, id) in [("/etc/subuid", ids.uid), ("/etc/subgid", ids.gid)] {
        let text = fs::read_to_string(file).map_err(|e| format!("cannot read {file}: {e}"))?;
        match subid_count_in(&text, &user, id) {
            Some(count) if count >= crate::instance::SUBORDINATE_IDS => {}
            count => {
                return Err(format!(
                    "{file}: the range of {user} has {} ids — a container's instance takes the \
                     first {} of it (0 a zone's root, 1 an OpenConnect client, 2 a bridge, 3 an \
                     instance's root)",
                    count.map_or_else(|| "?".to_owned(), |c| c.to_string()),
                    crate::instance::SUBORDINATE_IDS
                ))
            }
        }
    }
    Ok(())
}

/// The tool flags of `vpn-zone-core zone-holder`, as [`Args::parse`] reads
/// them back: what the keeper passes on to its own re-exec. An empty path
/// is the flag left out: its default.
fn tool_flags(tools: &Tools) -> Vec<OsString> {
    let mut out: Vec<OsString> = Vec::new();
    for (flag, path) in [
        ("--ip", &tools.ip),
        ("--awg", &tools.awg),
        ("--wg", &tools.wg),
        ("--pasta", &tools.pasta),
        ("--passt", &tools.passt),
        ("--nft", &tools.nft),
        ("--openconnect", &tools.openconnect),
        ("--dbus-proxy", &tools.dbus_proxy),
        ("--opener", &tools.opener),
        ("--kdialog", &tools.kdialog),
        ("--window", &tools.window),
        ("--runner", &tools.runner),
    ] {
        if !path.as_os_str().is_empty() {
            out.push(OsString::from(flag));
            out.push(path.as_os_str().to_os_string());
        }
    }
    out
}

/// A zone-level setting in the text [`crate::hermetic::note_applied`]
/// wrote: `true` only where it says so.
fn frozen(text: &str, name: &str) -> bool {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .any(|(key, value)| key.trim() == name && value.trim() == "true")
}

/// The instance's `Zone`: named by its id, in its directory, with the
/// settings `applied` (the text of [`crate::instance::SETTINGS`]).
fn instance_zone(tools: Tools, home: PathBuf, plan: &crate::instance::Plan, applied: &str) -> Zone {
    let state = home.join(STATE_SUBDIR);
    Zone {
        name: OsString::from(&plan.id),
        dir: crate::instance::dir(&state, &plan.id),
        tools,
        hermetic: frozen(applied, "hermetic"),
        nix_daemon: frozen(applied, "nix_daemon"),
        host_files_writable: frozen(applied, "host_files_writable"),
        audio_manager: frozen(applied, "audio_manager"),
        instance: Some(InstanceInfo {
            id: plan.id.clone(),
            network: plan.network.clone(),
            network_dir: state.join(&plan.network),
            who: plan.who.clone(),
            storage: plan.storage.clone(),
            userns: None,
        }),
        home,
    }
}

/// The instance's directory, the user's alone (0700), with its id in it —
/// refused when it holds another id's: two ids of one key
/// (`crate::instance::key`) would share it.
fn own_instance_dir(dir: &Path, id: &str) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("cannot create {}: {e}", dir.display())),
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("cannot close {}: {e}", dir.display()))?;
    let file = dir.join(crate::instance::ID);
    match fs::read_to_string(&file) {
        Ok(held) if held.trim() != id => Err(format!(
            "{} is instance {}'s — the two ids share a key; rename the container",
            dir.display(),
            held.trim()
        )),
        Ok(_) => Ok(()),
        Err(_) => write_private(&file, format!("{id}\n").as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", file.display())),
    }
}

/// `vpn-zone-core container-holder <id>`: the keeper of a container's
/// instance (`crate::instance`), `vpn-zone-container@<id>.service`'s main
/// process — in the host's user namespace, like a zone's holder. It makes
/// the instance's directory and freezes the network's settings, starts the
/// helpers, has its space made ([`hold_instance`]), and keeps it for as long
/// as its programs run ([`keep`]).
pub fn run_instance(tools: Tools, home: PathBuf, plan: crate::instance::Plan) -> u8 {
    let id = plan.id.clone();
    let state = home.join(STATE_SUBDIR);
    let config = home.join(CONFIG_SUBDIR);
    let dir = crate::instance::dir(&state, &id);
    if let Err(e) = own_instance_dir(&dir, &id) {
        eprintln!("instance {id}: {e}");
        return 1;
    }
    // Leftovers of a previous run would make a launch believe this one up.
    for file in [
        crate::instance::PID,
        crate::instance::START,
        READY,
        crate::instance::SPACE_READY,
        crate::instance::CONTROL,
        crate::instance::USERNS,
        crate::instance::EXIT,
        crate::instance::REATTACH,
        crate::instance::RESOLV,
        crate::pw_context::STATE_FILE,
        crate::epoch::FILE,
        crate::epoch::LIVE_SWITCH,
    ] {
        let _ = fs::remove_file(dir.join(file));
    }
    // Its `resolv.conf` before its space binds it (`instance_ground`): the
    // constant forwarder alone, until an attach says what else — written
    // over in place then, never replaced (the space holds this file). An
    // offline instance's too (stage 4): a live switch gives it a zone.
    let resolv = dir.join(crate::instance::RESOLV);
    if let Err(e) = fs::write(&resolv, crate::bridge::resolv_text(false, &[])) {
        eprintln!("instance {id}: cannot write {} ({e})", resolv.display());
        return 1;
    }
    // The zone-level settings, frozen for the instance's life: its covers
    // and helpers are made by them once, and `status --json` names what has
    // changed since (`restart_needed`). Its container's own over its
    // network's (stage 5 of the container design, 2026-09-28): the main
    // home's and a throwaway's are the network's.
    let settings = crate::hermetic::start_settings_for(
        &state.join(&plan.network),
        &config,
        &plan.network,
        &plan.who,
    );
    let applied: String = settings
        .iter()
        .map(|(name, on)| format!("{name}={on}\n"))
        .collect();
    let written = crate::hermetic::note_applied(&dir, &settings).and_then(|()| {
        write_private(
            &dir.join(crate::instance::NETWORK),
            format!("{}\n", plan.network).as_bytes(),
        )
    });
    if let Err(e) = written {
        eprintln!("instance {id}: cannot write its settings ({e})");
        return 1;
    }
    let mut zone = instance_zone(tools, home, &plan, &applied);
    prepare_host(&zone, &plan.network);
    let ids = match Ids::current().and_then(|ids| instance_ranges(&ids).map(|()| ids)) {
        Ok(ids) => ids,
        Err(e) => {
            eprintln!("instance {id}: {e}");
            return 1;
        }
    };
    match hold_instance(&mut zone, &ids, &plan) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("instance {id}: {e}");
            1
        }
    }
}

/// How an instance's keeping ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    /// Its last program ended, and no launch was on its way in.
    Idle,
    /// Stopped (TERM or INT): `systemctl stop`, a logout, `cellward
    /// container stop`.
    Asked,
    /// Its pid 1 killed (`cellward container kill`, stage 3): everything in
    /// its pid namespace ended with it, at once.
    Killed,
    /// Its space ended by itself: nothing holds its covers any more.
    Broken,
}

/// The holder's exit code when its pid 1 was killed (128 + SIGKILL, as
/// `exit_code_of` gives it and `stopped_cleanly` passes it on): the
/// instance was killed, not broken ([`Ending::Killed`]).
const KILLED: u8 = 128 + libc::SIGKILL as u8;

/// The keeper's wake-up pipe's write end, for its signal handlers.
static WAKE: AtomicI32 = AtomicI32::new(-1);
/// A child of the keeper's has ended.
static CHILD_ENDED: AtomicBool = AtomicBool::new(false);

fn wake() {
    let fd = WAKE.load(Ordering::SeqCst);
    if fd >= 0 {
        let byte = 1u8;
        // SAFETY: write(2) of one byte from a valid address; async-signal-safe.
        unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) };
    }
}

extern "C" fn keeper_asked_to_stop(_sig: libc::c_int) {
    ASKED_TO_STOP.store(true, Ordering::SeqCst);
    wake();
}

extern "C" fn keeper_child_ended(_sig: libc::c_int) {
    CHILD_ENDED.store(true, Ordering::SeqCst);
    wake();
}

/// Fork off the instance's user namespace, map its ids from the outside,
/// start the helpers, wait for its space to be ready, and keep it.
fn hold_instance(zone: &mut Zone, ids: &Ids, plan: &crate::instance::Plan) -> Result<u8, String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot find our own binary: {e}"))?;
    let (unshared_r, unshared_w) = sys::pipe().map_err(|e| format!("cannot create a pipe: {e}"))?;
    let (mapped_r, mapped_w) = sys::pipe().map_err(|e| format!("cannot create a pipe: {e}"))?;
    // SAFETY: single-threaded at this point, so the child may allocate and
    // print before it goes its own way.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("cannot fork: {}", io::Error::last_os_error()));
    }
    if pid == 0 {
        drop(unshared_r);
        drop(mapped_w);
        let code = instance_user_namespace(zone, &exe, unshared_w, mapped_r);
        // SAFETY: _exit never returns and touches nothing of ours.
        unsafe { libc::_exit(libc::c_int::from(code)) };
    }
    drop(unshared_w);
    drop(mapped_r);
    let mut byte = [0u8; 1];
    let mut unshared = File::from(unshared_r);
    if unshared.read_exact(&mut byte).is_err() || byte[0] != SYNC_OK {
        let _ = reap(pid);
        return Err("the instance could not get a user namespace of its own".to_string());
    }
    let userns = map_instance(pid, ids).and_then(|()| {
        crate::place::ns_key(Path::new(&format!("/proc/{pid}/ns/user")))
            .ok_or_else(|| "cannot read the instance's user namespace".to_string())
    });
    let userns = match userns {
        Ok(userns) => userns,
        Err(e) => {
            // Dropping the write end is the child's signal to give up.
            drop(mapped_w);
            let _ = reap(pid);
            return Err(e);
        }
    };
    // What its programs are known by (`crate::place`), and its helpers told.
    let _ = write_private(
        &zone.path(crate::instance::USERNS),
        format!("{}\n", crate::place::key_text(userns)).as_bytes(),
    );
    if let Some(info) = zone.instance.as_mut() {
        info.userns = Some(userns);
    }
    // The helpers, before the space is made: it binds their sockets in as
    // one of its first steps.
    let mut helpers = Helpers::start(zone);
    let mut mapped = File::from(mapped_w);
    if mapped.write_all(&[SYNC_OK]).is_err() {
        let _ = reap(pid);
        helpers.stop();
        return Err("the instance stopped listening before the mapping was done".to_string());
    }
    drop(mapped);
    // The space set up, or the end of the one making it: waited for as long
    // as that takes (the unit has no start timeout; `systemctl stop` ends a
    // stuck one).
    let state = zone.home.join(STATE_SUBDIR);
    let set_up = sys::pidfd_open(pid).is_some_and(|h| {
        sys::wait_for_entry(
            &zone.path(crate::instance::SPACE_READY),
            Some(&h),
            Path::is_file,
        )
    });
    let space = if set_up {
        crate::instance::space(&state, &plan.id)
    } else {
        None
    };
    let give_up = |helpers: &mut Helpers, why: String| {
        // SAFETY: kill(2) of our own child, not reaped yet.
        unsafe { libc::kill(pid, libc::SIGTERM) };
        let _ = reap(pid);
        helpers.stop();
        Err(why)
    };
    let Some(space) = space else {
        return give_up(&mut helpers, "its space did not come up".to_string());
    };
    // Its way out (stage 2 of the container design): attached before the
    // instance is ready, so that a launch that finds it ready finds it
    // going out — or refused to come up, with the zone's reason.
    // Its epoch wall (stage 4, `crate::epoch`): the cgroup its programs are
    // put in, and whether it can be switched live — before its way out, whose
    // relay loads the wall once there is one.
    let epochs = Epochs::start(zone, &plan.id, &state, space);
    let mut transport = Transport::new(zone, plan, &state, space, epochs);
    if let Err(e) = transport.first() {
        return give_up(&mut helpers, e);
    }
    if let Err(e) = touch(&zone.path(READY)) {
        transport.close();
        return give_up(&mut helpers, format!("cannot create {READY}: {e}"));
    }
    if crate::instance::up(&state, &plan.id).is_none() {
        transport.close();
        return give_up(&mut helpers, "its space did not come up".to_string());
    }
    crate::system::notify_ready();
    let exit = transport.describe();
    println!("instance {}: up, {} ({exit})", plan.id, plan.network);
    let who = plan.who.word();
    if let Err(e) = crate::journal::append(
        &state,
        "instance-start",
        &[
            ("instance", plan.id.as_str()),
            ("network", plan.network.as_str()),
            ("container", who.as_str()),
            ("exit", exit.as_str()),
        ],
    ) {
        eprintln!("instance {}: journal: {e}", plan.id);
    }

    let (mut ending, space_gone) = keep(zone, pid, space, userns, &mut helpers, &mut transport);
    if ending == Ending::Broken {
        eprintln!(
            "instance {}: its space ended by itself — its programs are ended with it",
            plan.id
        );
    }
    // An instance ending ends its programs (the design's stop semantics):
    // TERM, and waited for — systemd's own stop timeout is the one clock.
    // Their way out goes after them, before the space. (Its pid 1's end
    // would end them too — KILL, with no word: they are asked first.)
    if ending != Ending::Idle {
        end_programs(userns, space);
    }
    transport.close();
    if !space_gone {
        // SAFETY: kill(2) of our own child, not reaped yet.
        unsafe { libc::kill(pid, libc::SIGTERM) };
        // A kill: `cellward container kill` kills the pid 1, and the ends
        // of its programs may look like the last one's (an idle end) and
        // its stop of the unit like a stop, before the holder's end is
        // seen. The holder's code says it (KILL passed on).
        if reap(pid) == KILLED && ending != Ending::Broken {
            ending = Ending::Killed;
        }
    }
    let why = match ending {
        Ending::Idle => {
            println!("instance {}: its last program ended — it stops", plan.id);
            "idle"
        }
        Ending::Asked => "stop",
        Ending::Killed => {
            println!(
                "instance {}: killed — its programs ended with its pid namespace",
                plan.id
            );
            "kill"
        }
        Ending::Broken => "broken",
    };
    helpers.stop();
    // A throwaway's layer and records: nothing of it outlives it.
    for path in &plan.erase {
        let _ = sys::remove_tree(path);
    }
    if let Err(e) = crate::journal::append(
        &state,
        "instance-stop",
        &[("instance", plan.id.as_str()), ("why", why)],
    ) {
        eprintln!("instance {}: journal: {e}", plan.id);
    }
    let _ = sys::remove_tree(&zone.dir);
    Ok(u8::from(ending == Ending::Broken))
}

/// The instance's user namespace, until the keeper has mapped its ids; then
/// uid 0 in it, and an `exec` of ourselves (`container-holder --inner`),
/// which makes it this process's own (J3 of the design): a process's memory
/// belongs to the user namespace it was exec'd in, and only a process with
/// `CAP_SYS_PTRACE` there — the host's user, its owner — may read one that
/// is not dumpable. Returns only when something failed.
fn instance_user_namespace(zone: &Zone, exe: &Path, unshared_w: OwnedFd, mapped_r: OwnedFd) -> u8 {
    default_signals();
    // SAFETY: unshare(2) takes no pointers.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
        eprintln!(
            "instance {}: cannot create a user namespace ({})",
            zone.name(),
            io::Error::last_os_error()
        );
        let _ = File::from(unshared_w).write_all(&[SYNC_FAIL]);
        return 1;
    }
    if File::from(unshared_w).write_all(&[SYNC_OK]).is_err() {
        return 1;
    }
    let mut byte = [0u8; 1];
    if File::from(mapped_r).read_exact(&mut byte).is_err() || byte[0] != SYNC_OK {
        return 1;
    }
    // SAFETY: both take no pointers; we hold every capability in the
    // namespace just made.
    if unsafe { libc::setgid(0) } != 0 || unsafe { libc::setuid(0) } != 0 {
        eprintln!(
            "instance {}: cannot become uid 0 inside it ({})",
            zone.name(),
            io::Error::last_os_error()
        );
        return 1;
    }
    let mut argv: Vec<OsString> = vec![
        exe.as_os_str().to_os_string(),
        OsString::from("container-holder"),
        OsString::from("--inner"),
    ];
    argv.extend(tool_flags(&zone.tools));
    argv.push(zone.name.clone());
    let e = crate::profile::exec_command(&argv);
    eprintln!(
        "instance {}: cannot exec {} ({e})",
        zone.name(),
        exe.display()
    );
    1
}

/// `vpn-zone-core container-holder --inner <id>`: [`hold_instance`]'s
/// child once it is uid 0 of the instance's user namespace and exec'd in
/// it (H). Not dumpable from its first step (the zones' holders are, for
/// pasta and `nsenter`; an instance has neither): nothing of the instance's
/// may read it, the host's user may.
///
/// Since stage 3 (`docs/THREAT-MODEL.md` X4) it makes the instance's pid
/// namespace, and forks its pid 1 into it (`crate::init`, I), which makes
/// the network, mount and IPC namespaces and forks the space (K) — and
/// writes down I's HOST pid as the instance's (`instance.pid`): every
/// reader of an instance is on the host, and I is a member of every one of
/// its namespaces. `unshare(CLONE_NEWPID)` and glibc's `fork`, not a raw
/// `clone(2)` with the flags: glibc keeps the thread's id in the thread's
/// own block, and a raw clone leaves the parent's there — `raise`, `abort`
/// and error-checking mutexes would name a thread the child's namespace
/// does not have. This process forks nothing else: whatever it forked now
/// would be in the instance's namespace, and after I's end nothing can be.
///
/// The stop signals and SIGCHLD are blocked across the fork: I starts with
/// them blocked and takes them with `sigwaitinfo` — pid 1 of a namespace is
/// never delivered a signal it has no handler for, and a blocked one is
/// never dropped. I waits for this process's word before it forks the
/// space: the space's `space-ready` is then always read after
/// `instance.pid` was written.
pub fn run_instance_inner(tools: Tools, home: PathBuf, plan: crate::instance::Plan) -> u8 {
    // SAFETY: prctl with these arguments takes no pointers.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    let dir = crate::instance::dir(&home.join(STATE_SUBDIR), &plan.id);
    let applied = match fs::read_to_string(dir.join(crate::instance::SETTINGS)) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("instance {}: cannot read its settings ({e})", plan.id);
            return 1;
        }
    };
    let zone = instance_zone(tools, home, &plan, &applied);
    let (go_r, go_w) = match sys::pipe() {
        Ok(pipe) => pipe,
        Err(e) => {
            eprintln!("instance {}: cannot create a pipe ({e})", plan.id);
            return 1;
        }
    };
    let waited = crate::init::waited_set();
    let before = match crate::init::block(&waited) {
        Ok(mask) => mask,
        Err(e) => {
            eprintln!("instance {}: cannot block its signals ({e})", plan.id);
            return 1;
        }
    };
    // SAFETY: unshare(2) takes no pointers.
    if unsafe { libc::unshare(libc::CLONE_NEWPID) } != 0 {
        eprintln!(
            "instance {}: cannot create a pid namespace ({})",
            plan.id,
            io::Error::last_os_error()
        );
        return 1;
    }
    // SAFETY: single-threaded here.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        eprintln!(
            "instance {}: cannot fork: {}",
            plan.id,
            io::Error::last_os_error()
        );
        return 1;
    }
    if pid == 0 {
        drop(go_w);
        let code = crate::init::run(&plan.id, go_r, || zone_main(&zone, None));
        // SAFETY: _exit never returns and touches nothing of ours.
        unsafe { libc::_exit(libc::c_int::from(code)) };
    }
    drop(go_r);
    // The keeper stops the instance by signalling this process; it is
    // passed on to pid 1, from outside its namespace — and the namespace
    // goes with pid 1.
    USERNS_CHILD.store(pid, Ordering::SeqCst);
    on_term_and_int(forward_signal);
    // SAFETY: signal(2) with a plain function pointer, as `on_term_and_int`.
    unsafe {
        libc::signal(
            libc::SIGHUP,
            forward_signal as extern "C" fn(libc::c_int) as libc::sighandler_t,
        )
    };
    crate::init::set_mask(&before);
    let noted = note_instance_pid(&dir, pid).and_then(|()| {
        File::from(go_w)
            .write_all(&[SYNC_OK])
            .map_err(|e| format!("cannot give its pid 1 the word: {e}"))
    });
    if let Err(e) = noted {
        eprintln!("instance {}: {e}", plan.id);
        // SAFETY: kill(2) of our own child, not reaped yet: KILL, which pid
        // 1 of a namespace gets from its parent's.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let _ = reap(pid);
        return 1;
    }
    let code = loop {
        let (dead, code) = wait_any();
        if dead == pid || dead == -1 {
            break code;
        }
    };
    // Its pid 1 killed is said as it is, asked to stop or not: the keeper
    // tells a kill from a stop by it (`Ending::Killed`).
    if code == KILLED {
        return code;
    }
    stopped_cleanly(code)
}

/// The instance's process as the host numbers it — its pid 1, `pid` —
/// written into its directory `dir`: its start first, so that whoever sees
/// the number sees its start too (`crate::instance::up`).
fn note_instance_pid(dir: &Path, pid: libc::pid_t) -> Result<(), String> {
    let stamp = sys::process_stamp(pid).ok_or("cannot read its pid 1's start time")?;
    fs::write(dir.join(crate::instance::START), format!("{stamp}\n"))
        .map_err(|e| format!("cannot write {}: {e}", crate::instance::START))?;
    fs::write(dir.join(crate::instance::PID), format!("{pid}\n"))
        .map_err(|e| format!("cannot write {}: {e}", crate::instance::PID))
}

/// Keep the instance for as long as it has programs: its space held, its
/// helpers' ends said (as in a zone), and a look at who is in it whenever
/// something happens — a launch rings the doorbell
/// ([`crate::instance::CONTROL`]) once its program is in, or could not get
/// there; a program it knows of ends. No clock. When the last one is gone
/// and no launch holds the lock ([`crate::instance::LOCK`]: shared from its
/// look at the instance until its program is in), it ends
/// ([`Ending::Idle`]) — and not before a first launch has rung.
/// `(how it ended, whether the space is gone and reaped)`.
///
/// And its way out (stage 2 of the container design, [`Transport`]): the
/// zone's word that its passt ended, or the relay's end, cuts it; the
/// zone's directory is watched while it is cut, and a zone that comes back
/// as the one that carried it is attached again; the doorbell with
/// [`crate::instance::REATTACH`] left is the person's word to attach it to
/// the zone as it is now. What the keeper starts itself — its space and its
/// relay — is never taken for a program of the instance.
fn keep(
    zone: &Zone,
    holder: libc::pid_t,
    space: libc::pid_t,
    userns: (u64, u64),
    helpers: &mut Helpers,
    transport: &mut Transport,
) -> (Ending, bool) {
    // SAFETY: getpid(2) takes no arguments and cannot fail.
    let keeper = unsafe { libc::getpid() };
    let (wake_r, wake_w) = match sys::pipe() {
        Ok(pipe) => pipe,
        Err(e) => {
            eprintln!("instance {}: cannot create a pipe ({e})", zone.name());
            return (Ending::Broken, false);
        }
    };
    for fd in [wake_r.as_raw_fd(), wake_w.as_raw_fd()] {
        // SAFETY: fcntl on a descriptor we own.
        unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
    }
    WAKE.store(wake_w.as_raw_fd(), Ordering::SeqCst);
    let stop = keeper_asked_to_stop as extern "C" fn(libc::c_int) as libc::sighandler_t;
    let child = keeper_child_ended as extern "C" fn(libc::c_int) as libc::sighandler_t;
    // SAFETY: signal(2) with plain function pointers; the handlers only
    // touch atomics and write(2).
    unsafe {
        libc::signal(libc::SIGTERM, stop);
        libc::signal(libc::SIGINT, stop);
        libc::signal(libc::SIGCHLD, child);
    }
    // A child that ended before the handler: looked for at once.
    CHILD_ENDED.store(true, Ordering::SeqCst);
    // The doorbell, bound through the directory's descriptor: its path may
    // be longer than a socket's. Without it the instance never ends by
    // itself — said.
    let held = sys::open_dir(&zone.dir).ok();
    let doorbell = held.as_ref().and_then(|dir| {
        let path = format!(
            "/proc/self/fd/{}/{}",
            dir.as_raw_fd(),
            crate::instance::CONTROL
        );
        let bound = std::os::unix::net::UnixListener::bind(&path).and_then(|l| {
            use std::os::unix::fs::PermissionsExt;
            l.set_nonblocking(true)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            Ok(l)
        });
        match bound {
            Ok(l) => Some(l),
            Err(e) => {
                eprintln!(
                    "instance {}: no doorbell ({e}) — it ends only when stopped",
                    zone.name()
                );
                None
            }
        }
    });
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(zone.path(crate::instance::LOCK))
        .ok();
    let mut members: Vec<(i32, OwnedFd)> = Vec::new();
    // Its programs outside the current epoch at the last look (stage 4).
    let mut outside: Vec<i32> = Vec::new();
    // Connections to the control socket not closed yet (stage 4): a ring
    // closes at once, a request says one line first.
    let mut pending: Vec<(std::os::unix::net::UnixStream, Vec<u8>)> = Vec::new();
    let mut armed = false;
    let mut space_gone = false;
    // How the holder ended: KILL passed on from its pid 1 is a kill.
    let mut holder_code = 0u8;
    let pollin = |fd: RawFd| libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ending = loop {
        if ASKED_TO_STOP.load(Ordering::SeqCst) {
            break Ending::Asked;
        }
        let mut fds: Vec<libc::pollfd> = Vec::with_capacity(members.len() + 5);
        fds.push(pollin(wake_r.as_raw_fd()));
        fds.push(pollin(doorbell.as_ref().map_or(-1, AsRawFd::as_raw_fd)));
        let way = fds.len();
        fds.extend(transport.polled());
        let first_member = fds.len();
        fds.extend(members.iter().map(|(_, fd)| pollin(fd.as_raw_fd())));
        let first_pending = fds.len();
        fds.extend(pending.iter().map(|(conn, _)| libc::pollfd {
            fd: conn.as_raw_fd(),
            events: libc::POLLIN | libc::POLLRDHUP,
            revents: 0,
        }));
        // A child's end whose word an attach's wait took from the pipe:
        // looked at now, not waited for.
        let timeout = if CHILD_ENDED.load(Ordering::SeqCst) {
            0
        } else {
            -1
        };
        // SAFETY: a valid array of pollfd and its length.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        if rc < 0 {
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                // No memory for the poll: looked at again in a moment.
                thread::sleep(sys::LOOK_AGAIN);
            }
            continue;
        }
        if fds[0].revents != 0 {
            let mut buf = [0u8; 64];
            // SAFETY: read(2) into a buffer of the length passed.
            while unsafe { libc::read(wake_r.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) } > 0
            {
            }
        }
        if CHILD_ENDED.swap(false, Ordering::SeqCst) {
            loop {
                let mut status: libc::c_int = 0;
                // SAFETY: `status` is a valid pointer for the duration of the call.
                let dead = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
                if dead <= 0 {
                    break;
                }
                if dead == holder {
                    space_gone = true;
                    holder_code = exit_code_of(status);
                } else {
                    helpers.died(zone, dead);
                }
            }
            if space_gone {
                break if holder_code == KILLED {
                    Ending::Killed
                } else {
                    Ending::Broken
                };
            }
        }
        transport.handle(&fds[way..first_member], wake_r.as_raw_fd());
        let mut look = false;
        if fds[1].revents != 0 {
            if let Some(doorbell) = &doorbell {
                while let Ok((rung, _)) = doorbell.accept() {
                    // Heard until it says a line or closes; a flood of
                    // connections is not kept — a ring needs none.
                    if pending.len() < PENDING_MAX && rung.set_nonblocking(true).is_ok() {
                        pending.push((rung, Vec::new()));
                    }
                }
            }
            look = true;
            armed = true;
            transport.reattach(wake_r.as_raw_fd());
        }
        // Requests (stage 4): each ready connection read; a whole line is
        // answered — a live switch, with the programs as they are now.
        let mut heard: Vec<bool> = fds[first_pending..]
            .iter()
            .map(|p| p.revents != 0)
            .collect();
        // Those just accepted were not polled yet: heard at the next turn.
        heard.resize(pending.len(), false);
        let mut requests = Vec::new();
        let mut kept = Vec::new();
        for ((conn, mut said), ready) in pending.drain(..).zip(heard) {
            if !ready {
                kept.push((conn, said));
                continue;
            }
            match read_request(&conn, &mut said) {
                Some(Heard::Line(line)) => requests.push((conn, line)),
                Some(Heard::More) => kept.push((conn, said)),
                None => {}
            }
        }
        pending = kept;
        for (conn, line) in requests {
            let now = || crate::place::members(userns, Some(keeper), Some(space));
            answer_request(transport, conn, &line, &now, wake_r.as_raw_fd());
            look = true;
        }
        let ended: Vec<bool> = fds[first_member..first_pending]
            .iter()
            .map(|p| p.revents != 0)
            .collect();
        if ended.contains(&true) {
            let mut at = 0;
            let mut outside_ended = false;
            members.retain(|(pid, _)| {
                let gone = ended[at];
                at += 1;
                outside_ended |= gone && outside.contains(pid);
                !gone
            });
            // The last program outside the epoch may be gone (stage 4): looked
            // at again, for the live switch's note.
            look |= members.is_empty() || outside_ended;
        }
        if !look {
            continue;
        }
        members = crate::place::members(userns, Some(keeper), Some(space));
        if members.is_empty() && armed && lock.as_ref().is_some_and(lock_exclusive_now) {
            // Nobody on the way in (a launch holds the lock shared until its
            // program is in): looked at once more, and nobody is in.
            members = crate::place::members(userns, Some(keeper), Some(space));
            if members.is_empty() {
                break Ending::Idle;
            }
            if let Some(lock) = &lock {
                // SAFETY: flock(2) on a descriptor we hold.
                unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) };
            }
        }
        outside = transport.epochs.look(&members);
    };
    WAKE.store(-1, Ordering::SeqCst);
    if doorbell.is_some() {
        let _ = fs::remove_file(zone.path(crate::instance::CONTROL));
    }
    // The lock stays taken to the keeper's end after an idle one: no launch
    // gets in while the instance goes; one waiting finds it gone, and
    // starts it again.
    std::mem::forget(lock);
    (ending, space_gone)
}

/// The lock taken exclusively, now or not at all.
fn lock_exclusive_now(lock: &File) -> bool {
    // SAFETY: flock(2) on a descriptor we hold.
    unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

/// How many connections to the control socket are heard at once (stage 4):
/// a ring closes at once, a request is one line.
const PENDING_MAX: usize = 16;
/// The longest request line.
const REQUEST_LINE_MAX: usize = 256;

/// What a connection to the control socket said so far.
enum Heard {
    /// A whole line.
    Line(String),
    /// Nothing whole yet.
    More,
}

/// What is there to read on a control connection; `None`: it closed with no
/// line — a launch's ring — or says more than a request does.
fn read_request(conn: &std::os::unix::net::UnixStream, said: &mut Vec<u8>) -> Option<Heard> {
    let mut reader: &std::os::unix::net::UnixStream = conn;
    let mut buf = [0u8; 128];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return None,
            Ok(n) => {
                said.extend_from_slice(&buf[..n]);
                if let Some(at) = said.iter().position(|b| *b == b'\n') {
                    return String::from_utf8(said[..at].to_vec()).ok().map(Heard::Line);
                }
                if said.len() > REQUEST_LINE_MAX {
                    return None;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Some(Heard::More),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
}

/// Whether the peer of a control connection is the user in the host's user
/// namespace — this process's — and nothing else (P1 of the live switch): a
/// program of a zone or of an instance runs as the user as well, in a user
/// namespace of its own. Its path is covered in every zone and instance
/// besides; this holds where that would not.
fn from_host(conn: &std::os::unix::net::UnixStream) -> bool {
    // SAFETY: getuid(2) takes no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
    if crate::bridge::peer_uid(conn.as_raw_fd()) != Some(uid) {
        return false;
    }
    let Some(peer) = crate::origin::Peer::of(conn.as_raw_fd()) else {
        return false;
    };
    let ours = fs::read_link("/proc/self/ns/user").ok();
    ours.is_some() && peer.ns("user") == ours
}

/// Text on one line of an answer.
fn one_line(text: &str) -> String {
    text.replace(['\n', '\r'], " ")
}

/// The programs among `members` that still hold one of the UDP sockets
/// `inodes` a switch's break saw: muted by the epoch's wall for good — an
/// unconnected socket gets one error and sends on into nothing —, until the
/// program makes a new one or is restarted.
fn muted(members: &[(i32, OwnedFd)], inodes: &[u32]) -> Vec<(i32, String)> {
    if inodes.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (pid, _) in members {
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        let holds = fds.flatten().any(|fd| {
            fs::read_link(fd.path())
                .ok()
                .and_then(|link| crate::sockdiag::socket_inode(&link.to_string_lossy()))
                .is_some_and(|inode| inodes.contains(&inode))
        });
        if holds {
            let name = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
            out.push((*pid, name.trim().to_owned()));
        }
    }
    out
}

/// A request on the instance's control socket (stage 4, `crate::switch`):
/// `SWITCH <network>`, answered in lines and the connection closed —
/// `REFUSED <code> <text>` (nothing touched), `FAILED <step> <text>` (cut,
/// bound to the network asked for), or `DONE <network> epoch=<N> <the
/// break's tally>` and a `MUTED <pid> <name>` for each program that still
/// holds a UDP socket of the network before. `members_now`: the instance's
/// programs, looked at when asked.
fn answer_request(
    transport: &mut Transport,
    conn: std::os::unix::net::UnixStream,
    line: &str,
    members_now: &dyn Fn() -> Vec<(i32, OwnedFd)>,
    wake: RawFd,
) {
    let _ = conn.set_nonblocking(false);
    let reply = match crate::switch::parse_request(line) {
        None => "REFUSED request not a request this socket takes\n".to_owned(),
        Some(to) => {
            let members = members_now();
            match transport.switch(to, from_host(&conn), &members, wake) {
                Switched::Refused(r) => format!("REFUSED {} {}\n", r.code, one_line(&r.text)),
                Switched::Failed { phase, why } => {
                    format!("FAILED {} {}\n", phase.word(), one_line(&why))
                }
                Switched::Done { epoch, tally } => {
                    let mut text = format!("DONE {to} epoch={epoch} {}\n", tally.word());
                    for (pid, name) in muted(&members_now(), &tally.udp_inodes) {
                        text.push_str(&format!("MUTED {pid} {}\n", one_line(&name)));
                    }
                    text
                }
            }
        }
    };
    let mut out: &std::os::unix::net::UnixStream = &conn;
    let _ = out.write_all(reply.as_bytes());
}

/// Every program of the instance whose user namespace is `userns` ended:
/// TERM (and CONT, for one stopped), waited for, and looked for again —
/// what forked meanwhile goes the same way. What the keeper started — its
/// holder, its pid 1 (`space`) and its space, its relay — is spared: the
/// keeper ends it after them; an orphan pid 1 adopted is a program
/// (`crate::place::members`). No clock: a program that does not end is
/// ended by systemd's stop timeout of the unit — the one clock (O10 of the
/// design): its KILL reaches the pid 1, and the kernel ends the rest.
///
/// One that has ended and is still listed is a zombie nobody has reaped:
/// its end is had, and it is not waited for again — it was, in a busy
/// loop, until its parent reaped it. A launch's `profile-run` is the child
/// of a process outside the instance (its waiter, `crate::enter`), which a
/// terminal's `^Z` stops with it: that parent is continued to reap it
/// (`sys::continue_reaper`, review 2026-09-28) — the instance's pid 1 ends
/// only once every process of its namespace is reaped.
fn end_programs(userns: (u64, u64), space: libc::pid_t) {
    // SAFETY: getpid(2) takes no arguments and cannot fail.
    let keeper = unsafe { libc::getpid() };
    loop {
        let (ended, live): (Vec<_>, Vec<_>) =
            crate::place::members(userns, Some(keeper), Some(space))
                .into_iter()
                .partition(|(_, fd)| sys::pidfd_wait(fd, std::time::Duration::ZERO));
        for (pid, fd) in &ended {
            sys::continue_reaper(*pid, fd);
        }
        if live.is_empty() {
            return;
        }
        for (_, fd) in &live {
            sys::pidfd_signal(fd, libc::SIGTERM);
            sys::pidfd_signal(fd, libc::SIGCONT);
        }
        for (_, fd) in &live {
            sys::pidfd_wait_end(fd);
        }
    }
}

/// The epoch wall of a container instance, as its keeper holds it (stage 4
/// of the container design of 2026-09-27, `crate::epoch`): the cgroup its
/// programs are in, and whether it can be switched live — written down for
/// `status` ([`crate::epoch::LIVE_SWITCH`]) whenever that changes.
struct Epochs {
    /// The instance's directory.
    dir: PathBuf,
    /// Its current epoch; `None`: no delegated cgroup of its unit's (a keeper
    /// run by hand) — no epochs and no live switch.
    now: Option<crate::epoch::Epoch>,
    /// A named container's instance: one that may change its network. Not
    /// `<c>:<net>`, `main:<net>` or a throwaway (P7 of the design).
    kind_ok: bool,
    /// What its start found: its cgroup, nft's `socket cgroupv2` and the
    /// kernel's `SOCK_DESTROY` in its namespace — or the first that failed.
    found: Result<(), &'static str>,
    /// Its note as last written.
    noted: Option<crate::epoch::LiveSwitch>,
    /// Its programs outside the current epoch at the last look.
    outside: usize,
    /// Every program in the current epoch, and its wall the one to attach
    /// with: false from a new epoch's start until it is whole — a switch
    /// that failed half-way leaves programs in two epochs, and nothing
    /// attaches before a new epoch that is whole.
    whole: bool,
}

impl Epochs {
    /// At the instance's start, its space up: the unit's cgroup found
    /// (`<unit>/infra` is the keeper's own, `DelegateSubgroup=infra`), its
    /// first epoch made there and written down for its launches, and the
    /// relay's probe run in its namespaces (`bridge::probe`). Nothing of it
    /// is fatal: without it the instance is as in stage 3, and cannot be
    /// switched live.
    fn start(zone: &Zone, id: &str, state: &Path, space: i32) -> Self {
        let dir = zone.dir.clone();
        let _ = fs::remove_file(dir.join(crate::epoch::FILE));
        let unit = crate::instance::unit_name(id).and_then(|name| {
            let own = fs::read_to_string("/proc/self/cgroup").ok()?;
            crate::epoch::unit_of(&own, &name)
        });
        let Some(unit) = unit else {
            println!(
                "instance {id}: no delegated cgroup of its unit's — its programs stay where they \
                 are started, and it cannot change its network while they run"
            );
            return Self::noted(dir, id, None, Err("cgroup"));
        };
        let first = crate::epoch::Epoch::of(&unit, 1);
        let made = match crate::epoch::make(&first) {
            Err(e) if e.kind() != io::ErrorKind::AlreadyExists => Err(e),
            _ => {
                crate::epoch::freeze(&first, false).and_then(|()| crate::epoch::write(&dir, &first))
            }
        };
        if let Err(e) = made {
            eprintln!(
                "instance {id}: cannot make its programs' cgroup {} ({e}) — it cannot change its \
                 network while they run",
                first.path
            );
            return Self::noted(dir, id, None, Err("cgroup"));
        }
        let probed = match (
            std::env::current_exe(),
            sys::pidfd_open(space).filter(|_| crate::instance::space(state, id) == Some(space)),
        ) {
            (Ok(core), Some(pidfd)) => {
                let line = crate::bridge::probe(
                    &core,
                    &zone.tools.nft,
                    &pidfd,
                    crate::relay::Wall::probed(&first),
                );
                println!("instance {id}: its live switch's probe: {line}");
                crate::epoch::probe_verdict(&line)
            }
            _ => Err("cgroup"),
        };
        Self::noted(dir, id, Some(first), probed)
    }

    /// Its note written as its start found it, with no program in yet.
    fn noted(
        dir: PathBuf,
        id: &str,
        now: Option<crate::epoch::Epoch>,
        found: Result<(), &'static str>,
    ) -> Self {
        let mut epochs = Self {
            dir,
            now,
            kind_ok: !id.contains(':'),
            found,
            noted: None,
            outside: 0,
            whole: true,
        };
        epochs.note(0);
        epochs
    }

    /// Whether a new epoch can be made now: epochs, what its start found,
    /// and every program in the current one at the last look.
    fn renewable(&self) -> bool {
        self.now.is_some() && self.found.is_ok() && self.outside == 0
    }

    /// The note rewritten when what it says changed: `outside` programs of
    /// the instance run outside the current epoch.
    fn note(&mut self, outside: usize) {
        let live = crate::epoch::live_switch(self.kind_ok, self.found, outside);
        if self.noted.as_ref() == Some(&live) {
            return;
        }
        if let Err(e) = crate::epoch::write_live(&self.dir, &live) {
            eprintln!("cannot note whether the instance can be switched live ({e})");
        }
        self.noted = Some(live);
    }

    /// After a look at the instance's programs (`place::members`): those not
    /// in the current epoch — launched from a login session's scope, which
    /// the kernel does not let move (`crate::epoch`) —, and the note.
    fn look(&mut self, members: &[(i32, OwnedFd)]) -> Vec<i32> {
        let outside: Vec<i32> = match &self.now {
            Some(epoch) => members
                .iter()
                .map(|(pid, _)| *pid)
                .filter(|pid| {
                    !epoch.holds(
                        &fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default(),
                    )
                })
                .collect(),
            None => Vec::new(),
        };
        self.outside = outside.len();
        self.note(outside.len());
        outside
    }

    /// The wall the instance's rules carry now (`relay::Wall::of`): none
    /// before its first switch.
    fn wall(&self) -> Option<crate::relay::Wall> {
        self.now.as_ref().and_then(crate::relay::Wall::of)
    }
}

/// A container instance's way out, as its keeper holds it (stage 2 of the
/// container design of 2026-09-27, `crate::bridge`): the link to its zone
/// while it has one; why not while it has none ([`crate::instance::Exit`],
/// noted in its directory for `status`); and what it was carried by — the
/// zone's fingerprint and the last addresses —, which a zone that comes
/// back is held to. It goes out through its zone or nowhere, and is never
/// moved to another network by anything but the person: since stage 4 the
/// person may, live ([`Transport::switch`]).
struct Transport {
    id: String,
    network: String,
    state: PathBuf,
    /// The user's settings: a switch binds the container there (stage 4).
    config: PathBuf,
    /// The instance's directory.
    dir: PathBuf,
    /// Its space's host pid: what the relay joins.
    space: i32,
    ip: PathBuf,
    nft: PathBuf,
    link: Option<crate::bridge::Link>,
    /// Why there is no link, while there is none.
    why: &'static str,
    /// The fingerprint of the zone that carried it.
    fp: Option<u64>,
    /// The zone's app namespace's process that carried it: a zone that
    /// comes back is another process — the same one never re-attaches the
    /// instance by itself (its passt or the relay ended, and a relay that
    /// ends at once would end again and again).
    zone_pid: Option<i32>,
    previous: Option<crate::bridge::GuestPlan>,
    /// The zone's directory, watched while the instance is cut from it.
    watch: Option<sys::Inotify>,
    /// Its epoch wall (stage 4).
    epochs: Epochs,
    /// The search domains its programs have now (its `resolv.conf`): a
    /// switch keeps them (O8 of the design).
    search: Vec<String>,
    /// The instance's lock, a descriptor of its own: taken exclusively for
    /// a new epoch — a launch holds it shared until its program is placed.
    lock: Option<File>,
}

/// How a live switch ended ([`Transport::switch`]).
enum Switched {
    /// Not made; nothing touched.
    Refused(crate::switch::Refusal),
    /// Made: its epoch, and what its break did.
    Done {
        epoch: u32,
        tally: crate::sockdiag::Tally,
    },
    /// Failed at a step from the cut on: the instance is cut, bound to the
    /// new network (G7).
    Failed {
        phase: crate::switch::Phase,
        why: String,
    },
}

impl Transport {
    fn new(
        zone: &Zone,
        plan: &crate::instance::Plan,
        state: &Path,
        space: i32,
        epochs: Epochs,
    ) -> Self {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(zone.path(crate::instance::LOCK))
            .ok();
        Self {
            id: plan.id.clone(),
            network: plan.network.clone(),
            state: state.to_path_buf(),
            config: zone.home.join(CONFIG_SUBDIR),
            dir: zone.dir.clone(),
            space,
            ip: zone.tools.ip.clone(),
            nft: zone.tools.nft.clone(),
            link: None,
            why: "offline",
            fp: None,
            zone_pid: None,
            previous: None,
            watch: None,
            epochs,
            search: Vec::new(),
            lock,
        }
    }

    /// Its space held by a pidfd, while it is the process that wrote its
    /// number.
    fn space_pidfd(&self) -> Option<OwnedFd> {
        sys::pidfd_open(self.space)
            .filter(|_| crate::instance::space(&self.state, &self.id) == Some(self.space))
    }

    /// Its `resolv.conf` rewritten in place: its space holds the file
    /// (`instance_ground`), and a new one would not be the one bound.
    fn write_resolv(&self, text: &str) {
        let written = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(self.dir.join(crate::instance::RESOLV))
            .and_then(|mut file| file.write_all(text.as_bytes()));
        if let Err(e) = written {
            eprintln!(
                "instance {}: cannot write its resolv.conf ({e}) — names may not resolve",
                self.id
            );
        }
    }

    /// Its network noted where launches, the broker and `status` read it
    /// ([`crate::instance::NETWORK`]) — in place, as its space may hold the
    /// file (stage 4).
    fn note_network(&self) {
        let written = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(self.dir.join(crate::instance::NETWORK))
            .and_then(|mut file| file.write_all(format!("{}\n", self.network).as_bytes()));
        if let Err(e) = written {
            eprintln!("instance {}: cannot note its network ({e})", self.id);
        }
    }

    /// A switch under way or failed, noted for `status`
    /// ([`crate::instance::SWITCH`]); `None`: none.
    fn note_switch(&self, state: Option<(&str, &str, &str)>) {
        let noted = match state {
            Some((state, from, to)) => crate::epoch::write_whole(
                &self.dir,
                crate::instance::SWITCH,
                &format!("{state} {from} {to}\n"),
            ),
            None => match fs::remove_file(self.dir.join(crate::instance::SWITCH)) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            },
        };
        if let Err(e) = noted {
            eprintln!("instance {}: cannot note its switch ({e})", self.id);
        }
    }

    /// `f` with the instance's lock taken exclusively, as long as that
    /// takes: a launch holds it shared only until its program is placed.
    fn with_lock<T>(&mut self, f: impl FnOnce(&mut Self) -> T) -> T {
        let fd = self.lock.as_ref().map(AsRawFd::as_raw_fd);
        if let Some(fd) = fd {
            // SAFETY: flock(2) on a descriptor we hold.
            while unsafe { libc::flock(fd, libc::LOCK_EX) } != 0
                && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
            {}
        }
        let out = f(self);
        if let Some(fd) = fd {
            // SAFETY: flock(2) on a descriptor we hold.
            unsafe { libc::flock(fd, libc::LOCK_UN) };
        }
        out
    }

    fn offline(&self) -> bool {
        self.network == OFFLINE
    }

    /// For its journal and its keeper's word.
    fn describe(&self) -> String {
        match &self.link {
            Some(link) => format!(
                "out through {} as {}{}",
                self.network,
                link.plan.a4,
                link.plan
                    .a6
                    .map(|a| format!(" and {a}"))
                    .unwrap_or_default()
            ),
            None if self.offline() => "loopback only".to_owned(),
            None => format!("cut: {}", self.why),
        }
    }

    /// Its exit noted where `status` reads it ([`crate::instance::EXIT`]).
    fn note(&self) {
        let exit = match &self.link {
            Some(_) => crate::instance::Exit::Through(self.network.clone()),
            None => crate::instance::Exit::Cut(self.why.to_owned()),
        };
        let path = self.dir.join(crate::instance::EXIT);
        if let Err(e) = write_private(&path, exit.text().as_bytes()) {
            eprintln!("instance {}: cannot note its way out ({e})", self.id);
        }
    }

    fn journal(&self, event: &str, fields: &[(&str, &str)]) {
        let mut all = vec![
            ("instance", self.id.as_str()),
            ("zone", self.network.as_str()),
        ];
        all.extend_from_slice(fields);
        if let Err(e) = crate::journal::append(&self.state, event, &all) {
            eprintln!("instance {}: journal: {e}", self.id);
        }
    }

    /// Attached through its zone's bridge (`bridge::attach`): the relay
    /// started, the `resolv.conf` its space holds rewritten in place (the
    /// constant forwarders, the zone's search domains), the exit noted.
    /// `expect`: the fingerprint of the zone that carried it — a return;
    /// `None`: the first attach, or the person's word.
    fn attach(
        &mut self,
        expect: Option<u64>,
        wake: Option<RawFd>,
    ) -> Result<(), crate::bridge::NoLink> {
        use crate::bridge::NoLink;
        // A new epoch that did not complete (stage 4): its programs may be in
        // two, and no wall to attach with holds them all.
        if !self.epochs.whole {
            return Err(NoLink::Failed(
                "its last new epoch did not complete — it attaches after one that does".to_owned(),
            ));
        }
        let zone_dir = self.state.join(&self.network);
        let Some(zone_pid) = crate::cli::zone_up(&self.state, OsStr::new(&self.network)) else {
            return Err(NoLink::Failed(format!("zone {} is not up", self.network)));
        };
        if !crate::bridge::carries(&zone_dir) {
            return Err(NoLink::Failed(format!(
                "zone {} carries no container: it runs a previous build — restart it",
                self.network
            )));
        }
        let space = self
            .space_pidfd()
            .ok_or_else(|| NoLink::Failed("its space is gone".to_owned()))?;
        let core = std::env::current_exe()
            .map_err(|e| NoLink::Failed(format!("cannot find our own binary: {e}")))?;
        let tools = crate::bridge::RelayTools {
            core: &core,
            ip: &self.ip,
            nft: &self.nft,
        };
        let stop = || ASKED_TO_STOP.load(Ordering::SeqCst);
        let link = crate::bridge::attach(
            &zone_dir,
            &self.id,
            &space,
            self.previous,
            expect,
            self.epochs.wall(),
            &tools,
            wake,
            &stop,
        )?;
        self.write_resolv(&crate::bridge::resolv_text(link.v6, &link.search));
        self.search = link.search.clone();
        self.previous = Some(link.plan);
        self.fp = Some(link.fp);
        self.zone_pid = Some(zone_pid);
        self.link = Some(link);
        self.why = "";
        self.watch = None;
        self.note();
        let exit = self.describe();
        println!("instance {}: {exit}", self.id);
        self.journal("attach", &[("exit", exit.as_str())]);
        Ok(())
    }

    /// Its first way out, as the instance comes up: none for an offline
    /// one; through its zone, or the instance does not come up.
    fn first(&mut self) -> Result<(), String> {
        if self.offline() {
            self.why = "offline";
            self.note();
            return Ok(());
        }
        self.attach(None, None)
            .map_err(|e| format!("no way out through zone {}: {e}", self.network))
    }

    /// Cut: the link dropped — the zone kills its passt, the relay is
    /// killed, the tap goes with it —, the programs left with loopback and
    /// the unreachable defaults, and the zone's directory watched for its
    /// return.
    fn cut(&mut self, why: &'static str, wake: RawFd) {
        let Some(link) = self.link.take() else {
            return;
        };
        link.close();
        self.why = why;
        self.note();
        println!(
            "instance {}: cut from zone {} ({why}) — its programs go on with no way out",
            self.id, self.network
        );
        self.journal("cut", &[("why", why)]);
        self.watch_zone(wake);
    }

    /// The zone's directory watched for its return (its `ready`, its
    /// bridge's socket appearing), and looked at once: it may be back
    /// already.
    fn watch_zone(&mut self, wake: RawFd) {
        self.watch = sys::Inotify::watch(&self.state.join(&self.network)).ok();
        if self.watch.is_none() {
            eprintln!(
                "instance {}: cannot watch zone {} — only `cellward container reattach` \
                 attaches it again",
                self.id, self.network
            );
        }
        self.zone_back(wake);
    }

    /// The zone may be back: attached again when it is the one that carried
    /// the instance (its fingerprint, as in stage 2); left cut, until the
    /// person says, when it is another — never moved to another exit as a
    /// side effect (I1, THREAT-MODEL N9). Stage 4 (O3 of the design): with
    /// its epochs whole and every program in the current one, attached as a
    /// new epoch — every socket of before muted by the wall and broken, as
    /// in a switch to the same network. Until the review of 2026-09-28 such
    /// an instance was attached whatever the zone came back as: a zone
    /// re-created with another provider, or its config edited, took every
    /// container it had carried out through the new exit without a word of
    /// the person's.
    fn zone_back(&mut self, wake: RawFd) {
        use crate::bridge::NoLink;
        if self.link.is_some() || self.offline() || self.why == "zone-changed" {
            return;
        }
        let zone_dir = self.state.join(&self.network);
        let Some(now) = crate::cli::zone_up(&self.state, OsStr::new(&self.network)) else {
            return;
        };
        // The very process that carried it: not back — going, or with its
        // passt or the relay ended. Only the person re-attaches then.
        if Some(now) == self.zone_pid || !crate::bridge::carries(&zone_dir) {
            return;
        }
        if self.epochs.renewable() {
            println!(
                "instance {}: zone {} is back — a new epoch, then attached if it is the one \
                 that carried it",
                self.id, self.network
            );
            self.renew_and_attach(wake, self.fp);
            return;
        }
        match self.attach(self.fp, Some(wake)) {
            Ok(()) => println!(
                "instance {}: zone {} is back as it was — attached again",
                self.id, self.network
            ),
            Err(NoLink::Changed(fp)) => self.zone_changed(fp),
            Err(NoLink::Stopped) => {}
            Err(NoLink::Failed(e)) => {
                self.why = "attach-failed";
                self.note();
                eprintln!("instance {}: not attached again: {e}", self.id);
            }
        }
    }

    /// The zone came back as another one (fingerprint `fp`): the instance
    /// stays cut, and its zone is no longer watched — only the person's
    /// `cellward container reattach` attaches it.
    fn zone_changed(&mut self, fp: u64) {
        self.why = "zone-changed";
        self.watch = None;
        self.note();
        eprintln!(
            "instance {}: zone {} came back as another one (fingerprint {fp:016x}) — it stays \
             cut; `cellward container reattach` attaches it",
            self.id, self.network
        );
        self.journal("cut", &[("why", "zone-changed")]);
    }

    /// The person's word (`cellward container reattach`): its mark taken
    /// and, cut, the instance attached to its zone as the zone is now — as a
    /// new epoch when it can be (stage 4).
    fn reattach(&mut self, wake: RawFd) {
        if fs::remove_file(self.dir.join(crate::instance::REATTACH)).is_err() {
            return;
        }
        if self.offline() || self.link.is_some() {
            return;
        }
        if self.epochs.renewable() {
            self.renew_and_attach(wake, None);
            return;
        }
        match self.attach(None, Some(wake)) {
            Ok(()) => self.journal("reattach", &[]),
            Err(crate::bridge::NoLink::Stopped) => {}
            Err(e) => {
                self.why = "attach-failed";
                self.note();
                eprintln!("instance {}: not attached: {e}", self.id);
                if self.watch.is_none() {
                    self.watch = sys::Inotify::watch(&self.state.join(&self.network)).ok();
                }
            }
        }
    }

    // --- THE LIVE SWITCH (stage 4, `crate::switch`, `crate::epoch`) ---------

    /// A new epoch: taken with the instance's lock held exclusively and no
    /// way out — the next epoch's cgroup made, both frozen, every program
    /// moved into the next (`epoch::move_all`, until the old one has
    /// nobody), the old one removed; every socket that may reach out
    /// destroyed and the rules closed to loopback (`frame-relay --seal`);
    /// the programs thawed. A failure says at which step: the instance stays
    /// cut, and attaches again only after a new epoch that is whole.
    fn renew(
        &mut self,
        wake: RawFd,
    ) -> Result<crate::sockdiag::Tally, (crate::switch::Phase, String)> {
        use crate::switch::Phase;
        let Some(now) = self.epochs.now.clone() else {
            return Err((
                Phase::Epoch,
                "it has no epochs (no delegated cgroup)".to_owned(),
            ));
        };
        let Some(next) = now.next() else {
            return Err((Phase::Epoch, "no epoch after the last".to_owned()));
        };
        self.epochs.whole = false;
        let stop = || ASKED_TO_STOP.load(Ordering::SeqCst);
        if let Err(e) = crate::epoch::make(&next) {
            return Err((Phase::Epoch, format!("cannot make {} ({e})", next.path)));
        }
        let thaw = |epoch: &crate::epoch::Epoch| {
            if let Err(e) = crate::epoch::freeze(epoch, false) {
                eprintln!(
                    "instance {}: cannot thaw {} ({e}) — its programs stay frozen until it is \
                     stopped",
                    self.id, epoch.path
                );
            }
        };
        let moved = crate::epoch::freeze(&next, true)
            .and_then(|()| crate::epoch::freeze(&now, true))
            .map_err(crate::epoch::Gave::Io)
            .and_then(|()| crate::epoch::move_all(&now, &next, Some(wake), &stop));
        if let Err(e) = moved {
            thaw(&now);
            thaw(&next);
            return Err((
                Phase::Epoch,
                format!("its programs were not all moved into {} ({e})", next.path),
            ));
        }
        if let Err(e) = crate::epoch::remove(&now) {
            eprintln!(
                "instance {}: cannot remove the old epoch {} ({e})",
                self.id, now.path
            );
        }
        if let Err(e) = crate::epoch::write(&self.dir, &next) {
            eprintln!("instance {}: cannot note its epoch ({e})", self.id);
        }
        let sealed = match (std::env::current_exe(), self.space_pidfd()) {
            (Ok(core), Some(space)) => crate::bridge::seal(&core, &self.nft, &space),
            (Err(e), _) => Err(format!("cannot find our own binary: {e}")),
            (_, None) => Err("its space is gone".to_owned()),
        };
        thaw(&next);
        self.epochs.now = Some(next);
        let tally = sealed.map_err(|e| (Phase::Seal, e))?;
        for (what, count) in [
            ("TCP", tally.tcp),
            ("UDP", tally.udp),
            ("missed", tally.missed),
            ("not destroyable", tally.unsupported),
            ("refused", tally.failed),
        ] {
            if count > 0 {
                println!("instance {}: {what} sockets broken: {count}", self.id);
            }
        }
        self.epochs.whole = true;
        Ok(tally)
    }

    /// A new epoch, then the attach — as one, under the instance's lock: a
    /// zone's return, the person's `reattach` (stage 4). `expect`: the
    /// fingerprint the zone must have (a zone's return, [`Transport::
    /// zone_back`]) — another one leaves the instance cut, in its new epoch,
    /// with nothing attached (`bridge::attach` refuses it before its relay
    /// starts); `None`: the zone as it is now (the person's word). The new
    /// epoch comes first all the same: the zone's answer that tells its
    /// fingerprint is the attach itself, and no way out is attached before
    /// the wall of a new epoch. Its journal: `reattach` with the epoch; what
    /// failed leaves it cut.
    fn renew_and_attach(&mut self, wake: RawFd, expect: Option<u64>) {
        use crate::bridge::NoLink;
        let done = self.with_lock(|t| {
            let tally = t
                .renew(wake)
                .map_err(|(phase, why)| NoLink::Failed(format!("{}: {why}", phase.word())))?;
            t.attach(expect, Some(wake))?;
            Ok::<_, NoLink>(tally)
        });
        match done {
            Ok(tally) => {
                let epoch = self.epochs.now.as_ref().map_or(0, |e| e.n).to_string();
                let (tcp, udp) = (tally.tcp.to_string(), tally.udp.to_string());
                self.journal(
                    "reattach",
                    &[
                        ("epoch", epoch.as_str()),
                        ("tcp", tcp.as_str()),
                        ("udp", udp.as_str()),
                    ],
                );
            }
            Err(_) if ASKED_TO_STOP.load(Ordering::SeqCst) => {}
            Err(NoLink::Changed(fp)) => self.zone_changed(fp),
            Err(e) => {
                self.why = "attach-failed";
                self.note();
                eprintln!("instance {}: not attached again: {e}", self.id);
                if self.watch.is_none() {
                    self.watch = sys::Inotify::watch(&self.state.join(&self.network)).ok();
                }
            }
        }
    }

    /// What the network a switch asks for is ([`crate::switch::Target`]).
    fn target(&self, to: &str) -> crate::switch::Target {
        use crate::switch::Target;
        if to == OFFLINE {
            return Target::Offline;
        }
        if to == crate::launch::UNCONFINED || to == crate::launch::UNCONFINED_ALIAS {
            return Target::Unconfined;
        }
        let dir = self.state.join(to);
        if !crate::instance::valid_network(to) || !dir.join(CONFIG).is_file() {
            return Target::Unknown;
        }
        Target::Zone {
            up: crate::cli::zone_up(&self.state, OsStr::new(to)).is_some(),
            carries: crate::bridge::carries(&dir),
            search: crate::bridge::search_in(
                &fs::read_to_string(dir.join(RESOLV)).unwrap_or_default(),
            ),
        }
    }

    /// A live switch to `to`, asked on the control socket: its
    /// preconditions first (`switch::refusal` — a refusal touches nothing);
    /// then, with the instance's lock held exclusively — launches wait —,
    /// the switch itself ([`Transport::switch_taken`]). `members`: its
    /// programs, looked at now.
    fn switch(
        &mut self,
        to: &str,
        from_host: bool,
        members: &[(i32, OwnedFd)],
        wake: RawFd,
    ) -> Switched {
        let from = self.network.clone();
        self.epochs.look(members);
        let target = self.target(to);
        let container = crate::instance::container_of(&self.id).map(str::to_owned);
        let facts = crate::switch::Facts {
            from_host,
            declared: container
                .as_deref()
                .is_some_and(|c| crate::container::network_declared_in(&self.config, c)),
            named: !self.id.contains(':'),
            live: self.epochs.noted.as_ref(),
            outside: self.epochs.outside,
            locked: from != OFFLINE
                && self
                    .state
                    .join(&from)
                    .join(crate::launch::NO_ESCAPE)
                    .exists(),
            target: &target,
            search_now: &self.search,
        };
        if let Some(refusal) = crate::switch::refusal(&facts) {
            println!(
                "instance {}: no switch from {from} to {to} ({}): {}",
                self.id, refusal.code, refusal.text
            );
            self.journal(
                "switch-refused",
                &[("from", from.as_str()), ("to", to), ("why", refusal.code)],
            );
            return Switched::Refused(refusal);
        }
        self.with_lock(|t| t.switch_taken(to, &from, container.as_deref(), wake))
    }

    /// The switch, its preconditions met and the lock held (§5.3 of the
    /// design). Bound to `to` first, whatever becomes of it (G7): its
    /// container's setting, the ask of its next start, its programs' records,
    /// the instance's note. Then the cut (G1: the old relay killed and
    /// reaped, its tap gone with it — before anything of the new), a new
    /// epoch with its break ([`Transport::renew`]: G3, G4; G2 — nothing but
    /// loopback and the unreachable defaults meanwhile), and the new way out
    /// with its rules walled by the new epoch (`to` a zone; `offline`: none).
    fn switch_taken(
        &mut self,
        to: &str,
        from: &str,
        container: Option<&str>,
        wake: RawFd,
    ) -> Switched {
        use crate::switch::Phase;
        if let Some(name) = container {
            if let Err(e) = crate::container::write_network_in(&self.config, name, to) {
                eprintln!(
                    "instance {}: cannot bind the container to {to} ({e})",
                    self.id
                );
            }
            let records = self.state.join(".running").join(name);
            if let Err(e) = crate::registry::retarget(&records, from, to) {
                eprintln!(
                    "instance {}: its launches' records stay in {from} ({e})",
                    self.id
                );
            }
        }
        if let Err(e) = crate::instance::ask_network(&self.state, &self.id, to) {
            eprintln!(
                "instance {}: cannot note its next start's network ({e})",
                self.id
            );
        }
        self.note_switch(Some(("cutting", from, to)));
        if let Some(link) = self.link.take() {
            link.close();
        }
        self.watch = None;
        self.network = to.to_owned();
        self.fp = None;
        self.zone_pid = None;
        self.why = "switching";
        self.note();
        self.note_network();
        println!("instance {}: cut from {from} — switching to {to}", self.id);
        self.journal("switch-cut", &[("from", from), ("to", to)]);
        let tally = match self.renew(wake) {
            Ok(tally) => tally,
            Err((phase, why)) => return self.switch_failed(phase, from, to, why),
        };
        if to == OFFLINE {
            self.why = "offline";
            self.search.clear();
            self.write_resolv(&crate::bridge::resolv_text(false, &[]));
            self.note();
        } else {
            self.note_switch(Some(("attaching", from, to)));
            if let Err(e) = self.attach(None, Some(wake)) {
                if self.why == "switching" {
                    self.why = "attach-failed";
                }
                self.note();
                if self.watch.is_none() {
                    self.watch = sys::Inotify::watch(&self.state.join(&self.network)).ok();
                }
                return self.switch_failed(Phase::Attach, from, to, e.to_string());
            }
        }
        self.note_switch(None);
        let epoch = self.epochs.now.as_ref().map_or(0, |e| e.n);
        let (epoch_text, tcp, udp, missed) = (
            epoch.to_string(),
            tally.tcp.to_string(),
            tally.udp.to_string(),
            tally.missed.to_string(),
        );
        println!(
            "instance {}: switched from {from} to {to} (epoch {epoch})",
            self.id
        );
        self.journal(
            "switch",
            &[
                ("from", from),
                ("to", to),
                ("epoch", epoch_text.as_str()),
                ("tcp", tcp.as_str()),
                ("udp", udp.as_str()),
                ("missed", missed.as_str()),
            ],
        );
        Switched::Done { epoch, tally }
    }

    /// A switch that failed from the cut on: cut, bound to `to` (G7) — said,
    /// noted and journalled.
    fn switch_failed(
        &mut self,
        phase: crate::switch::Phase,
        from: &str,
        to: &str,
        why: String,
    ) -> Switched {
        eprintln!(
            "instance {}: the switch from {from} to {to} failed at its {} ({why}) — it stays \
             cut, in {to}",
            self.id,
            phase.word()
        );
        if self.why == "switching" {
            self.why = "switch-failed";
            self.note();
        }
        self.note_switch(Some(("failed", from, to)));
        self.journal(
            "switch-failed",
            &[
                ("from", from),
                ("to", to),
                ("phase", phase.word()),
                ("why", why.as_str()),
            ],
        );
        Switched::Failed { phase, why }
    }

    /// What the keeper polls for it, in the order [`Transport::handle`]
    /// reads them back: the link's request and relay, the zone's
    /// directory while cut.
    fn polled(&self) -> Vec<libc::pollfd> {
        let mut out = Vec::new();
        if let Some(link) = &self.link {
            out.push(libc::pollfd {
                fd: link.control.as_raw_fd(),
                events: libc::POLLIN | libc::POLLRDHUP,
                revents: 0,
            });
            out.push(libc::pollfd {
                fd: link.relay_fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        if let Some(watch) = &self.watch {
            out.push(libc::pollfd {
                fd: watch.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        out
    }

    /// What happened to it ([`Transport::polled`]'s answers): the zone's
    /// side ended — the zone, or its passt, which the zone says — or the
    /// relay did: cut, `zone-down` either way (the zone's word and the
    /// relay's end come at nearly one moment, in either order); the zone's
    /// directory changed — perhaps back.
    fn handle(&mut self, polled: &[libc::pollfd], wake: RawFd) {
        let mut at = 0;
        if let Some(link) = &self.link {
            let control = polled.get(at).map_or(0, |p| p.revents);
            let relay = polled.get(at + 1).map_or(0, |p| p.revents);
            at += 2;
            if (control != 0 && link.zone_ended()) || relay != 0 {
                self.cut("zone-down", wake);
                return;
            }
        }
        if self.watch.is_some() && polled.get(at).is_some_and(|p| p.revents != 0) {
            let names = match self.watch.as_ref().map(sys::Inotify::names) {
                Some(Ok(names)) => names,
                _ => {
                    self.watch = None;
                    return;
                }
            };
            if names
                .iter()
                .any(|name| name == READY || name == crate::bridge::SOCKET)
            {
                self.zone_back(wake);
            }
        }
    }

    /// At the instance's end: its link dropped.
    fn close(&mut self) {
        if let Some(link) = self.link.take() {
            link.close();
        }
        self.watch = None;
    }
}

/// `/sys/fs/cgroup` covered in an instance, by an empty read-only tmpfs: it
/// names every unit and scope of the user's (`vpn-zone@nl.service`,
/// `app-firefox@….scope`), which zones and containers run and the programs
/// in them — what a program of one container must not learn of the others
/// (as X4 of `docs/THREAT-MODEL.md` for `/proc`). Nothing a program needs is
/// there: its own limits are read in `/proc`. Fatal.
fn cover_cgroupfs(zone: &Zone) -> Result<(), String> {
    let dir = Path::new("/sys/fs/cgroup");
    if !dir.is_dir() {
        return Ok(());
    }
    sys::mount(
        OsStr::new("tmpfs"),
        dir,
        "tmpfs",
        libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "mode=0555,size=4k",
    )
    .map_err(|e| format!("cannot cover {}: {e}", dir.display()))?;
    println!("instance {}: the host's cgroups covered", zone.name());
    Ok(())
}

/// Which kind of tunnel this zone carries, decided once by [`prepare`] and read
/// by both namespaces afterwards.
///
/// The decision itself is one question asked of the config file: is there an
/// `[OpenConnect]` section? The two shapes cannot be confused — a WireGuard
/// config has no such section, and a file that has one but does not parse is
/// refused by `vpn-zone add` before a zone exists at all.
pub enum Backend {
    /// Kernel WireGuard or AmneziaWG. The uplink creates the interface itself
    /// and hands it down; the transport socket stays where it was created.
    Wg(WgConfig),
    /// A userspace OpenConnect client running in the uplink, as an id of its
    /// own with no capabilities. The uplink makes the interface for it and
    /// hands it down once the client's `--script` says the session is up; the
    /// TLS session stays with the process, which never leaves the uplink.
    Oc(Box<OcZone>),
    /// No tunnel and no uplink: pasta attaches to the app namespace and binds
    /// everything it sends to one interface of the host.
    HostIf(HostIfConfig),
    /// No tunnel of its own and no uplink: pasta, started by the system-zone
    /// service in a SYSTEM zone's network, attaches to the app namespace —
    /// the system zone's tunnel is this zone's way out (docs/SYSTEM.md §7b).
    SysZone(SysUplinkConfig),
}

/// An OpenConnect zone, ready to be started.
pub struct OcZone {
    pub cfg: OcConfig,
    /// The gateway's address, resolved in the HOST's network before either
    /// namespace exists — the same rule the WireGuard endpoint follows, and for
    /// the same two reasons: the uplink has no resolver of its own, and its
    /// filter would not let a lookup out even if it had one. The client is then
    /// told the answer with `--resolve`, so it never asks either.
    pub addr: IpAddr,
}

impl Backend {
    /// What the uplink's filter may talk to.
    ///
    /// For WireGuard this is every endpoint of the config, with its port. For
    /// OpenConnect it is the gateway's address and NO port, which is one
    /// dimension wider on purpose: the transport is TLS on the configured port
    /// but the client also tries DTLS on whatever UDP port the server
    /// advertises, and that number is not known until the session exists. The
    /// rule that matters is unchanged — this namespace may talk to the VPN
    /// gateway and to nothing else in the world.
    fn sockets(&self) -> Vec<EndpointSocket> {
        match self {
            Self::Wg(cfg) => endpoint_sockets(cfg),
            Self::Oc(oc) => vec![EndpointSocket {
                addr: oc.addr,
                port: None,
            }],
            // No uplink exists to be filtered.
            Self::HostIf(_) | Self::SysZone(_) => Vec::new(),
        }
    }
}

/// What the app namespace is handed: the backend, the pipe it reports its own
/// existence on, and the pipe the tunnel arrives through.
struct ZoneLinks<'a> {
    backend: &'a Backend,
    ready_w: OwnedFd,
    moved_r: OwnedFd,
    /// Rules the zone's filter takes before its own (a host-interface zone's
    /// refusal of the host's addresses, [`host_address_rules`]).
    first: Vec<String>,
    /// The config this run came up with, hashed: the first half of the
    /// zone's fingerprint (`bridge::fingerprint`).
    config_seed: u64,
}

/// What the uplink is handed: the backend, the host pid of the app namespace to
/// hand the interface to, and its three pipe ends.
struct UplinkLinks<'a> {
    backend: &'a Backend,
    zone_pid: libc::pid_t,
    ready_w: OwnedFd,
    zone_up_r: OwnedFd,
    moved_w: OwnedFd,
}

/// Start both namespaces and pasta, then live exactly as long as all of them.
///
/// The order is forced by what each step needs from the one before it: the app
/// namespace goes first because the uplink has to know its pid; the uplink then
/// reports its own namespace so pasta can attach to it from out here; and the
/// uplink waits for the app namespace to say it exists before handing the
/// interface over. Everything else is barriers on pipes, so a failure anywhere
/// shows up as an EOF on the other side instead of a timeout.
fn supervise(zone: &Zone) -> Result<u8, String> {
    // Read the config and resolve its endpoints HERE: this is the last place
    // with the host's network and the host's resolver. An offline zone has no
    // config at all — and no uplink, and no pasta.
    let (cfg, config_seed) = if zone.is_offline() {
        (None, 0)
    } else {
        let (backend, seed) = prepare(zone)?;
        (Some(backend), seed)
    };
    // A host-interface zone's pasta is in the host's network: the host's own
    // addresses, taken here where they can be seen.
    let first = match &cfg {
        Some(Backend::HostIf(_)) => host_address_rules(&host_addresses()),
        _ => Vec::new(),
    };

    // The buses' proxies and the sound filter are up already: the unit's own
    // process started them, out of the zone's user namespace (`Helpers`).

    let (uplink_up_r, uplink_up_w) =
        sys::pipe().map_err(|e| format!("cannot create a pipe: {e}"))?;
    let (zone_up_r, zone_up_w) = sys::pipe().map_err(|e| format!("cannot create a pipe: {e}"))?;
    let (moved_r, moved_w) = sys::pipe().map_err(|e| format!("cannot create a pipe: {e}"))?;

    // SAFETY: single-threaded at this point (the status mirror thread is
    // started by the app namespace, after the fork).
    let zone_pid = unsafe { libc::fork() };
    if zone_pid < 0 {
        return Err(format!("cannot fork: {}", io::Error::last_os_error()));
    }
    if zone_pid == 0 {
        drop(uplink_up_r);
        drop(uplink_up_w);
        drop(zone_up_r);
        drop(moved_w);
        let links = cfg.as_ref().map(|backend| ZoneLinks {
            backend,
            ready_w: zone_up_w,
            moved_r,
            first,
            config_seed,
        });
        let code = zone_main(zone, links);
        // SAFETY: _exit never returns and touches nothing of ours.
        unsafe { libc::_exit(libc::c_int::from(code)) };
    }
    ZONE_CHILD.store(zone_pid, Ordering::SeqCst);
    // From here on TERM/INT means "tear the zone down", the trap the bash holder
    // had. Installed as soon as there is anything to tear down, and not after
    // the last child is up: a stop arriving during the setup below would
    // otherwise kill this process and leave the namespaces orphaned. The
    // children reset it to the default disposition first thing.
    on_term_and_int(stop_zone);
    // The app namespace has its two ends now; a copy left open here would keep
    // a pipe from ever reaching EOF, and EOF is how the other side learns that
    // this one has died.
    drop(zone_up_w);
    drop(moved_r);

    let mut uplink_pid = 0;
    let mut pasta: Option<Child> = None;
    if let Some(Backend::HostIf(host)) = cfg.as_ref() {
        // No uplink: nobody is on the other end of its pipe.
        drop(uplink_up_r);
        drop(uplink_up_w);
        if let Err(e) = wait_for_app_namespace(zone_up_r) {
            kill_and_reap(zone_pid);
            return Err(e);
        }
        let netns = format!("/proc/{zone_pid}/ns/net");
        // IPv6 bound to the interface, or no IPv6 in the zone at all: never
        // IPv6 left free to go out wherever the host routes it.
        let v6_usable = hostif::ipv6_usable(
            &host.interface,
            &fs::read_to_string("/proc/net/if_inet6").unwrap_or_default(),
            &fs::read_to_string("/proc/net/ipv6_route").unwrap_or_default(),
        );
        let v6_args: Vec<&str> = if v6_usable {
            vec!["--outbound-if6", host.interface.as_str()]
        } else {
            println!(
                "zone {}: {} has no usable IPv6 — the zone gets none",
                zone.name(),
                host.interface
            );
            vec!["-4"]
        };
        // Its word that it is done (`PastaWord`), heard before the zone is
        // told: the zone then looks at the route once.
        let word = PastaWord::new();
        match word
            .as_ref()
            .map_err(|e| io::Error::other(format!("no directory for its pid file: {e}")))
            .and_then(|word| {
                Command::new(&zone.tools.pasta)
                    .arg("--netns")
                    .arg(&netns)
                    .args(["--config-net", "-q", "-I", TUN_IFACE, "-f"])
                    .arg("-P")
                    .arg(word.path())
                    .args([
                        "-a",
                        HOSTIF_GUEST4,
                        "-n",
                        HOSTIF_PREFIX4,
                        "-g",
                        HOSTIF_GATEWAY4,
                    ])
                    // The template interface too, explicitly: older pasta takes it
                    // from the host's default route rather than from --outbound-if*,
                    // and refuses the whole thing ("External interface not usable")
                    // when that route is not on the interface asked for.
                    .arg("-i")
                    .arg(&host.interface)
                    .arg("--outbound-if4")
                    .arg(&host.interface)
                    .args(&v6_args)
                    .args(PASTA_CLOSED)
                    .spawn()
            }) {
            Ok(mut child) => {
                PASTA_CHILD.store(child.id() as i32, Ordering::SeqCst);
                // The interface deleted or renamed: pasta down at once, and the
                // zone with it — not TCP by the host's routes (hostif.rs).
                let name = zone.name().to_string();
                let interface = host.interface.clone();
                let held = sys::pidfd_open(child.id() as i32);
                let watched = held
                    .ok_or_else(|| io::Error::other("no pidfd"))
                    .and_then(|fd| {
                        hostif::watch_interface(&host.interface, move || {
                            eprintln!(
                            "zone {name}: {interface} is gone — the zone goes down rather than \
                             out by the host's routes"
                        );
                            sys::pidfd_signal(&fd, libc::SIGKILL);
                        })
                    });
                match watched {
                    Ok(()) => {
                        let done = word.as_ref().is_ok_and(|word| word.wait(&mut child));
                        pasta = Some(child);
                        if !done {
                            // EOF instead of the byte: pasta ended before it
                            // was done, and says why itself.
                            drop(moved_w);
                            eprintln!(
                                "zone {}: pasta ended before its interface was ready",
                                zone.name()
                            );
                        } else if let Err(e) = tell_the_zone(moved_w, TOOL_HOSTIF) {
                            eprintln!("zone {}: {e}", zone.name());
                        }
                    }
                    Err(e) => {
                        // Unwatched, the day the interface goes the zone leaks:
                        // it does not come up (EOF instead of the byte).
                        let _ = child.kill();
                        let _ = child.wait();
                        drop(moved_w);
                        eprintln!(
                            "zone {}: cannot watch {} ({e}) — the zone has no way out",
                            zone.name(),
                            host.interface
                        );
                    }
                }
            }
            Err(e) => {
                // The zone gets EOF instead of the byte and refuses to come up:
                // a host-interface zone without pasta has no way out at all,
                // and saying "up" would be a lie.
                drop(moved_w);
                eprintln!(
                    "zone {}: cannot start pasta ({e}) — the zone has no way out",
                    zone.name()
                );
            }
        }
    } else if let Some(Backend::SysZone(sys)) = cfg.as_ref() {
        // No uplink here either: the system-zone service starts pasta in the
        // system zone's network and attaches it to the app namespace. What we
        // run is the watcher that holds that way out; it stands where pasta
        // stands for the other kinds — its end is the zone's end, and
        // stopping it lets go of the way out.
        drop(uplink_up_r);
        drop(uplink_up_w);
        if let Err(e) = wait_for_app_namespace(zone_up_r) {
            kill_and_reap(zone_pid);
            return Err(e);
        }
        match start_system_uplink(&sys.zone, zone_pid) {
            Ok((child, resolvers)) => {
                PASTA_CHILD.store(child.id() as i32, Ordering::SeqCst);
                pasta = Some(child);
                let told = fs::write(zone.path(SYS_RESOLVERS), resolvers.join("\n"))
                    .map_err(|e| format!("cannot write {SYS_RESOLVERS}: {e}"))
                    .and_then(|()| tell_the_zone(moved_w, TOOL_SYSZONE));
                if let Err(e) = told {
                    eprintln!("zone {}: {e}", zone.name());
                }
            }
            Err(e) => {
                // EOF instead of the byte: the zone refuses to come up rather
                // than say "up" with no way out.
                drop(moved_w);
                eprintln!(
                    "zone {}: no way out through the system zone {} — {e}",
                    zone.name(),
                    sys.zone
                );
            }
        }
    } else if let Some(backend) = cfg.as_ref() {
        // SAFETY: as above.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            let e = io::Error::last_os_error();
            kill_and_reap(zone_pid);
            return Err(format!("cannot fork: {e}"));
        }
        if pid == 0 {
            // The app namespace's ends are already closed here: the holder let
            // go of them before this fork.
            drop(uplink_up_r);
            let code = uplink_main(
                zone,
                UplinkLinks {
                    backend,
                    zone_pid,
                    ready_w: uplink_up_w,
                    zone_up_r,
                    moved_w,
                },
            );
            // SAFETY: as above.
            unsafe { libc::_exit(libc::c_int::from(code)) };
        }
        uplink_pid = pid;
        UPLINK_CHILD.store(pid, Ordering::SeqCst);
        drop(uplink_up_w);
        drop(zone_up_r);
        drop(moved_w);

        // The uplink's namespace exists once it says so, and there is nothing
        // for pasta to attach to before that. The pid is the one we know
        // first-hand — no pid namespace is created anywhere.
        let mut byte = [0u8; 1];
        let mut ready = File::from(uplink_up_r);
        if ready.read_exact(&mut byte).is_err() || byte[0] != SYNC_OK {
            kill_and_reap(pid);
            kill_and_reap(zone_pid);
            return Err("the uplink namespace did not come up".to_string());
        }
        drop(ready);

        let netns = format!("/proc/{pid}/ns/net");
        // Its word that it is done (`PastaWord`), passed on to the uplink as
        // `PASTA_DONE` (`wait_for_default_route`).
        let _ = fs::remove_file(zone.path(PASTA_DONE));
        let word = PastaWord::new();
        match word
            .as_ref()
            .map_err(|e| io::Error::other(format!("no directory for its pid file: {e}")))
            .and_then(|word| {
                Command::new(&zone.tools.pasta)
                    .arg("--netns")
                    .arg(&netns)
                    .args(["--config-net", "-q", "-I", PASTA_IFACE, "-f"])
                    .arg("-P")
                    .arg(word.path())
                    .args(PASTA_CLOSED)
                    .spawn()
            }) {
            Ok(mut child) => {
                PASTA_CHILD.store(child.id() as i32, Ordering::SeqCst);
                // Ended first: `wait_any` below sees it, and takes the zone
                // down.
                if word.as_ref().is_ok_and(|word| word.wait(&mut child)) {
                    if let Err(e) = touch(&zone.path(PASTA_DONE)) {
                        eprintln!(
                            "zone {}: cannot tell the uplink pasta is done: {e}",
                            zone.name()
                        );
                    }
                }
                pasta = Some(child);
            }
            Err(e) => {
                // The uplink waits for pasta's route as long as it takes:
                // without pasta that is for ever, so the zone goes now.
                kill_and_reap(pid);
                kill_and_reap(zone_pid);
                return Err(format!(
                    "cannot start pasta ({e}) — the zone has no way out"
                ));
            }
        }
    } else {
        // An offline zone: nobody is on the other end of any of these.
        drop(uplink_up_r);
        drop(uplink_up_w);
        drop(zone_up_r);
        drop(moved_w);
    }

    // Either namespace dying is the end of the zone: without the uplink the
    // tunnel has no transport, and without the app namespace there is nothing
    // left to serve. pasta counts too — a zone whose way out is gone is a zone
    // that only pretends to work.
    let pasta_pid = pasta.as_ref().map_or(0, |c| c.id() as i32);
    let (dead, code) = wait_any();
    if !ASKED_TO_STOP.load(Ordering::SeqCst) {
        let what = if dead == zone_pid {
            "the zone"
        } else if dead == uplink_pid {
            "the uplink"
        } else if dead == pasta_pid {
            "pasta"
        } else {
            "a child"
        };
        eprintln!("zone {}: {what} died — taking the zone down", zone.name());
    }

    // Nothing may outlive the zone: a stray pasta would keep an interface on a
    // dead namespace and `vpn-zone gc` would have to clean up after us, and a
    // surviving uplink would keep a namespace nobody can reach any more.
    for pid in [pasta_pid, uplink_pid, zone_pid] {
        if pid != dead {
            kill_and_reap(pid);
        }
    }
    // pasta is signalled and collected by pid like the other two, because
    // `wait_any` above may already have collected it — `Child::wait` would then
    // fail on a pid that is no longer ours. Dropping the `Child` does nothing to
    // the process (std has no `Drop` for it), which is exactly what we want.
    drop(pasta);

    Ok(stopped_cleanly(code))
}

/// Read the config, resolve every `Endpoint` and write the text `setconf` gets.
///
/// All of it happens in the HOST's network, before any namespace exists: see
/// the note on `getaddrinfo` in the module docs. A name that does not resolve
/// is fatal on purpose — the alternative is `wg setconf` retrying DNS for a
/// minute and a half inside a namespace that has none, and then failing anyway.
fn prepare(zone: &Zone) -> Result<(Backend, u64), String> {
    let raw = fs::read(zone.path(CONFIG)).map_err(|e| format!("cannot read {CONFIG}: {e}"))?;
    // The config as this run reads it, for the zone's fingerprint
    // (`bridge::fingerprint`): the very bytes it comes up with.
    let seed = crate::bridge::config_seed(&raw);
    prepare_backend(zone, &raw).map(|backend| (backend, seed))
}

/// [`prepare`] of the config's bytes.
fn prepare_backend(zone: &Zone, raw: &[u8]) -> Result<Backend, String> {
    let mut cfg = WgConfig::parse(raw).map_err(|e| format!("{CONFIG}: {e}"))?;
    if openconnect::is_openconnect(&cfg) {
        return prepare_openconnect(zone, &cfg);
    }
    if hostif::is_host_interface(&cfg) {
        let host = HostIfConfig::from_ini(&cfg).map_err(|e| format!("{CONFIG}: {e}"))?;
        // Here, in the host's network: an interface that is not there is a
        // zone that cannot go anywhere, and that is said now rather than
        // after a namespace that pretends to be up.
        if !Path::new("/sys/class/net").join(&host.interface).exists() {
            return Err(format!(
                "the host has no interface {} — a host-interface zone goes out through it or \
                 nowhere",
                host.interface
            ));
        }
        println!(
            "zone {}: out through the host's interface {} (not encrypted by this zone)",
            zone.name(),
            host.interface
        );
        return Ok(Backend::HostIf(host));
    }
    if sysuplink::is_system_zone(&cfg) {
        let sys = SysUplinkConfig::from_ini(&cfg).map_err(|e| format!("{CONFIG}: {e}"))?;
        println!(
            "zone {}: out through the tunnel of the system zone {}",
            zone.name(),
            sys.zone
        );
        return Ok(Backend::SysZone(sys));
    }
    if !cfg.dropped_empty.is_empty() {
        // Recent Amnezia writes junk-packet parameters and fills only some of
        // them; `setconf` rejects the whole file on such a line. Dropping them
        // is what keeps the zone coming up at all, so say which ones went.
        let keys: Vec<&str> = cfg.dropped_empty.iter().map(|d| d.key.as_str()).collect();
        println!(
            "zone {}: dropped empty config lines: {}",
            zone.name(),
            keys.join(", ")
        );
    }

    let endpoints = cfg.resolve_endpoints(resolve_endpoint);
    if endpoints.is_empty() {
        eprintln!(
            "zone {}: no Endpoint in the config — the tunnel has nowhere to go",
            zone.name()
        );
    }
    for endpoint in &endpoints {
        if endpoint.addr.is_none() {
            return Err(format!(
                "cannot resolve the endpoint {} (line {}) — it has to be an address by the \
                 time the tunnel is configured, because the zone has no DNS of its own until \
                 the tunnel is up",
                endpoint.raw, endpoint.line
            ));
        }
    }

    // `setconf` understands protocol keys only, so it gets a stripped copy.
    // 0600: it carries the private key.
    write_private(&zone.path(STRIPPED), cfg.to_setconf().as_bytes())
        .map_err(|e| format!("cannot write {STRIPPED}: {e}"))?;
    Ok(Backend::Wg(cfg))
}

/// The same work for an `[OpenConnect]` zone: check the config, check the
/// password file, resolve the gateway — all of it here, in the host's network,
/// before a namespace exists.
///
/// **Why the gateway is resolved here and not by the client.** The uplink has
/// the host's `/etc/resolv.conf` but not the host's network: its filter lets
/// out packets to the gateway and nothing else, so a lookup from in there would
/// be dropped, and a lookup that somehow got through a host resolver's socket
/// would be a leak of exactly the kind this project measures. The client is
/// therefore told the answer with `--resolve` and never asks — the same trick,
/// with the same reasoning, as writing literal addresses into the text
/// `wg setconf` gets.
fn prepare_openconnect(zone: &Zone, ini: &WgConfig) -> Result<Backend, String> {
    let cfg = OcConfig::from_ini(ini).map_err(|e| format!("{CONFIG}: {e}"))?;
    // Checked, not read: the password itself is read once, in the uplink, right
    // before it is handed to the client (`spawn_openconnect`).
    cfg.check_password_file()
        .map_err(|e| format!("{CONFIG}: {e}"))?;

    let addr = match cfg.server_literal() {
        Some(addr) => addr,
        None => {
            let port = cfg.port.unwrap_or(443);
            let addrs: Vec<IpAddr> = (cfg.server.as_str(), port)
                .to_socket_addrs()
                .map_err(|e| {
                    format!(
                        "cannot resolve the gateway {} ({e}) — it has to be an address by the \
                         time the zone starts, because the uplink has no resolver of its own",
                        cfg.server
                    )
                })?
                .map(|a| a.ip())
                .collect();
            // v4 first, as everywhere else in this file. A name that resolves
            // ONLY to IPv6 is refused rather than half-supported: `--resolve`
            // takes `HOST:IP` and cannot express a v6 address unambiguously, so
            // the client would be handed a mangled one. Writing the literal
            // into `Server =` works and is what the message asks for.
            match addrs.iter().copied().find(IpAddr::is_ipv4) {
                Some(addr) => addr,
                None if addrs.is_empty() => {
                    return Err(format!("the gateway {} resolved to nothing", cfg.server))
                }
                None => {
                    return Err(format!(
                        "the gateway {} resolves only to IPv6; write that address into Server = \
                         instead — `--resolve` cannot carry one unambiguously",
                        cfg.server
                    ))
                }
            }
        }
    };

    // A plan left over from a previous run would make the uplink believe the
    // tunnel is already up the moment it looks.
    let _ = fs::remove_file(zone.path(openconnect::PLAN_FILE));
    Ok(Backend::Oc(Box::new(OcZone { cfg, addr })))
}

// --- PROCESS 3: THE UPLINK ---------------------------------------------------

/// The uplink: pasta's namespace, and the namespace the tunnel is born in.
///
/// A WireGuard zone parks here forever, because the tunnel is a kernel object
/// and there is nothing left to supervise. An OpenConnect zone waits on the
/// client instead: the client's exit becomes this process's exit, the holder
/// sees the uplink die and takes the whole zone down with it. No retry, no
/// fallback, nothing to fall back TO — the app namespace has one interface and
/// it is about to disappear.
fn uplink_main(zone: &Zone, links: UplinkLinks<'_>) -> u8 {
    default_signals();
    match uplink_setup(zone, links) {
        Ok(None) => park(),
        Ok(Some(mut client)) => {
            let code = match client.wait() {
                Ok(status) => {
                    eprintln!(
                        "zone {}: the openconnect client exited ({status}) — the tunnel is gone",
                        zone.name()
                    );
                    status.code().map_or(1, |c| c as u8)
                }
                Err(e) => {
                    eprintln!("zone {}: cannot wait for openconnect: {e}", zone.name());
                    1
                }
            };
            // A client that quit on its own leaves a zone that cannot work,
            // whatever it thought of its own exit — this path is never reached
            // on a `systemctl stop`, which signals us straight to death.
            if code == 0 {
                1
            } else {
                code
            }
        }
        Err(e) => {
            eprintln!("zone {}: uplink: {e}", zone.name());
            1
        }
    }
}

/// Bring the uplink up; the answer is the process this namespace now lives as
/// long as, if there is one.
fn uplink_setup(zone: &Zone, links: UplinkLinks<'_>) -> Result<Option<Child>, String> {
    let UplinkLinks {
        backend,
        zone_pid,
        ready_w,
        zone_up_r,
        moved_w,
    } = links;

    // IPC too (review 2026-09-27, second opinion): the host's System V
    // objects and POSIX queues are no business of a client's.
    // SAFETY: unshare(2) takes no pointers.
    if unsafe { libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWNS | libc::CLONE_NEWIPC) } != 0 {
        return Err(format!(
            "cannot create the net+mount+IPC namespace: {}",
            io::Error::last_os_error()
        ));
    }
    // Private propagation: nothing the uplink side ever mounts (a resolver of
    // its own, a userspace client's state — ROADMAP M4) may travel to the host.
    sys::mount(
        OsStr::new("none"),
        Path::new("/"),
        "",
        libc::MS_REC | libc::MS_PRIVATE,
        "",
    )
    .map_err(|e| format!("cannot make the mount tree private: {e}"))?;
    // The host's resolvers are not the uplink's either: a whole third-party
    // client runs here (OpenConnect), and a name it looks up — a redirect, a
    // portal's gateway list — would be asked of the host's resolved over its
    // socket, in the host's network (review 2026-09-24). The endpoint was
    // resolved before this namespace existed; nothing here needs a resolver.
    for group in RESOLVER_DIRS {
        hide_first(group)?;
    }
    // And no NSS module talking to a daemon of the host's, as in the zone.
    // Not kept over the name after the host replaces it (`rebind::keep`):
    // nothing here looks a name up — the client has a root of its own.
    own_nsswitch(zone);
    // Nor anything else of the host's a client has no business with: the
    // system bus (resolve1 looks names up in the host's network), the
    // session's runtime directory (the compositor's raw socket and IPC, which
    // start programs on the host), /tmp (the session's listening sockets). A
    // VPN client is a network-facing program a server may try to subvert
    // (review 2026-09-25). This /tmp is writable by uid 0 only: the one
    // directory an OpenConnect client may write is its own, made in it
    // ([`client_dir`]), and a /tmp of 1777 would let the client swap that
    // directory for a link to anywhere uid 0 may read.
    // /dev/shm and /dev/mqueue are the host's too: files the session shares
    // by path, and its queues, which open(2) reaches by name whatever IPC
    // namespace the opener is in.
    let runtime = host_runtime_dir(zone);
    for (dir, options) in [
        (Path::new("/run/dbus"), "mode=0755,size=16k"),
        (runtime.as_path(), "mode=0700,size=16k"),
        (Path::new("/tmp"), "mode=0755,size=64m"),
        (Path::new("/dev/shm"), "mode=1777,size=16m"),
        (Path::new("/dev/mqueue"), "mode=0755,size=16k"),
    ] {
        if dir.is_dir() {
            sys::mount(
                OsStr::new("tmpfs"),
                dir,
                "tmpfs",
                libc::MS_NOSUID | libc::MS_NODEV,
                options,
            )
            .map_err(|e| format!("cannot close {} for the uplink: {e}", dir.display()))?;
        }
    }
    // And what every zone hides from its programs, hidden from the client as
    // well — the least trusted program of all, whatever the gateway made of
    // it (review 2026-09-27, second opinion: the uplink covered less than the
    // zone). The Nix daemon ALWAYS, whatever the zone's own setting says for
    // its programs: a fixed-output derivation fetches any address in the
    // host's network, around the tunnel and around this namespace's filter.
    // The system tier's service. systemd's services under /run/systemd, which
    // answer over varlink to whoever connects.
    hide_nix_daemon(zone)?;
    hide_system_tier(zone)?;
    seal_run().map_err(|e| format!("uplink: {e}"))?;

    // SAFETY: getpid(2) takes no arguments and cannot fail.
    let pid = unsafe { libc::getpid() };
    fs::write(zone.path(UPLINK_PID), format!("{pid}\n"))
        .map_err(|e| format!("cannot write {UPLINK_PID}: {e}"))?;
    zone.ip(&["link", "set", "lo", "up"])?;

    // --- THE SECOND ECHELON, BEFORE THERE IS ANYTHING TO FILTER ---
    // Loaded before pasta is even told about this namespace, so that connectivity
    // never exists here unfiltered. The rules cost the setup nothing: everything
    // below (waiting for a route, creating the interface, handing it over) is
    // netlink, which no filter hook of the `inet` family ever sees.
    //
    // What it buys: this namespace may send exactly the tunnel's own packets to
    // the endpoint, and nothing else. That mattered in theory while only the
    // kernel ran here; with an OpenConnect zone a whole third-party client runs
    // in this namespace, and the rule is what says it may talk to its gateway
    // and to nowhere else — no DNS, no update check, no second server.
    //
    // For that client the rule is not an insurance but the only wall
    // (review 2026-09-25, third round): pasta gives this namespace the whole
    // internet, and nothing in the topology keeps a userspace client to one
    // gateway, as the kernel's WireGuard socket keeps itself to its peer. So
    // an OpenConnect zone whose rule does not load does not come up.
    if matches!(backend, Backend::Oc(_)) {
        feed_nft(&zone.tools.nft, &uplink_ruleset(&backend.sockets())).map_err(|e| {
            format!(
                "the uplink's filter did not load ({e}) — an OpenConnect client would \
                 reach the whole internet from here, so the zone does not come up"
            )
        })?;
    } else {
        zone.seal("uplink", &uplink_ruleset(&backend.sockets()));
    }

    // The holder is waiting for this to attach pasta to us.
    let mut ready = File::from(ready_w);
    ready
        .write_all(&[SYNC_OK])
        .map_err(|e| format!("cannot report the namespace to the holder: {e}"))?;
    drop(ready);

    // Wait for pasta to configure the way out: until it has, there is no route
    // at all and the tunnel would have nothing to send through. Then look,
    // once.
    wait_for_default_route(zone);
    let out = default_route(zone, Family::V4);
    let Some(dev) = out.dev else {
        // The dump tells apart "pasta never attached" (lo only) from "attached
        // but configured differently" (a tap exists, the routes do not).
        for what in [
            ["-o", "link", "show"],
            ["-4", "addr", "show"],
            ["-4", "route", "show"],
        ] {
            eprintln!(
                "zone {}: uplink: ip {}:\n{}",
                zone.name(),
                what.join(" "),
                zone.ip_line(&what)
            );
        }
        return Err("pasta gave us no route out".to_string());
    };

    // --- THE TUNNEL IS BORN HERE, AND THAT IS THE WHOLE POINT ---
    // Whichever backend builds it. A WireGuard interface keeps its UDP socket
    // in the namespace it was CREATED in, whatever namespace it is moved to
    // afterwards; an OpenConnect tun keeps its whole client. Either way the app
    // namespace gets an interface whose packets leave through pasta, and needs
    // neither a route to the gateway nor any interface besides the tunnel.
    match backend {
        Backend::Wg(cfg) => {
            let tool = create_tunnel(zone, cfg)?;
            println!(
                "zone {}: uplink is up (default dev {dev}), tunnel created",
                zone.name()
            );

            // The interface can only be handed to a namespace that exists.
            wait_for_app_namespace(zone_up_r)?;

            // A host pid, because no pid namespace is created anywhere; `ip`
            // opens /proc/<pid>/ns/net behind it. Both namespaces belong to our
            // user namespace, where we are uid 0 — which is what makes the move
            // allowed.
            let target = zone_pid.to_string();
            zone.ip(&["link", "set", TUN_IFACE, "netns", target.as_str()])?;

            // Now the app namespace may configure it — and it has to be told
            // which of the two tools speaks to what we built.
            tell_the_zone(moved_w, tool)?;
            Ok(None)
        }
        Backend::Oc(oc) => {
            // The client gets no capabilities (`CLIENT_ID`), so what it needs
            // them for is done here, first: the tun it attaches to, and the
            // one directory it may write.
            let dir = client_dir()?;
            tun_for_the_client()?;
            println!(
                "zone {}: uplink is up (default dev {dev}), starting openconnect to {}",
                zone.name(),
                oc.cfg.server
            );

            let mut client = spawn_openconnect(zone, oc, &dir)?;
            // Its script writes the plan once the session is up; the move and
            // the handing over are ours, as on the WireGuard path.
            let handed = wait_for_plan(&dir, &mut client).and_then(|plan| {
                wait_for_app_namespace(zone_up_r)?;
                hand_over(zone, zone_pid, &plan)
            });
            if let Err(e) = handed {
                // Nothing may outlive a failed setup: an orphaned client would
                // hold this namespace open with a live session in it.
                let _ = client.kill();
                let _ = client.wait();
                return Err(e);
            }
            tell_the_zone(moved_w, TOOL_OC)?;
            Ok(Some(client))
        }
        // `supervise` never starts an uplink for these.
        Backend::HostIf(_) => Err("a host-interface zone has no uplink".to_string()),
        Backend::SysZone(_) => {
            Err("a zone through a system zone has no uplink of its own".to_string())
        }
    }
}

/// Start `xdg-dbus-proxy` in front of the host's system bus, listening in the
/// zone's directory, and wait for its socket. `None` when the host has no
/// system bus, the proxy cannot start, or it ends before its socket is there — the zone
/// then closes the system bus altogether ([`seal_system_bus`]).
fn start_system_bus_proxy(zone: &Zone) -> Option<Child> {
    if fs::symlink_metadata(SYSTEM_BUS).is_err() {
        return None;
    }
    start_proxy(
        zone,
        &format!("unix:path={SYSTEM_BUS}"),
        SYSTEM_BUS_PROXY,
        &SYSTEM_BUS_RULES,
        "system bus",
    )
}

/// Start `xdg-dbus-proxy` for `address`, listening at `socket_name` in the
/// zone's directory, and wait for its socket.
fn start_proxy(
    zone: &Zone,
    address: &str,
    socket_name: &str,
    rules: &[&str],
    what: &str,
) -> Option<Child> {
    let socket = zone.path(socket_name);
    let _ = fs::remove_file(&socket);
    // As the user, and from the unit's own process (`Helpers`): never as the
    // holder, whose uid 0 is a subordinate uid on the host — the bus would see
    // a stranger connect, while a program in the zone presents the user's uid,
    // and through a proxy of the wrong uid every call fails. The zone's
    // directory belongs to the user; `.uid` says so, not only the caller.
    let (uid, gid) = match fs::metadata(&zone.dir) {
        Ok(meta) => {
            use std::os::unix::fs::MetadataExt;
            (meta.uid(), meta.gid())
        }
        Err(e) => {
            eprintln!(
                "zone {}: cannot read {} ({e}) — no {what} proxy",
                zone.name(),
                zone.dir.display()
            );
            return None;
        }
    };
    let mut child = match Command::new(&zone.tools.dbus_proxy)
        .arg(address)
        .arg(&socket)
        .args(rules)
        .stdout(Stdio::null())
        .uid(uid)
        .gid(gid)
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!(
                "zone {}: cannot start {} ({e}) — the zone gets no {what}",
                zone.name(),
                zone.tools.dbus_proxy.display()
            );
            return None;
        }
    };
    if socket_up(&socket, &mut child) {
        return Some(child);
    }
    eprintln!(
        "zone {}: the {what} proxy ended before its socket was there — the zone gets no {what}",
        zone.name()
    );
    let _ = child.kill();
    let _ = child.wait();
    None
}

/// What an instance's helpers on the host are told of it (`crate::instance`):
/// whose its programs are (`--container`) and their user namespace
/// (`--userns`) — its sockets are bound into its space alone —, and its
/// `network` file (`--network-file`): the zone whose microphone setting
/// counts is the network it is in now, which a live switch changes (review
/// 2026-09-28; `--zone` is only the one it came up in). Nothing for a
/// zone's.
fn instance_helper_args(zone: &Zone) -> Vec<OsString> {
    let Some(instance) = &zone.instance else {
        return Vec::new();
    };
    let mut args = vec![
        OsString::from("--container"),
        OsString::from(instance.who.word()),
        OsString::from("--network-file"),
        zone.path(crate::instance::NETWORK).into_os_string(),
    ];
    if let Some(key) = instance.userns {
        args.push(OsString::from("--userns"));
        args.push(OsString::from(crate::place::key_text(key)));
    }
    args
}

/// The sound filter (`pulse_filter`), on the host — from the unit's own
/// process, in the host's user namespace (`Helpers`) — as the user: listening
/// in the zone's directory, passing on to the host's `pulse/native`. `None` when
/// the host has no sound server there. It is told the zone, where its
/// microphone setting is (`crate::microphone`) and where the containers are,
/// whose own settings come first (`crate::origin`): it reads them for every
/// record stream, and asks with kdialog in the environment it inherits — the unit's,
/// whose `WAYLAND_DISPLAY`/`DISPLAY` say whether there is anyone to ask.
fn start_pulse_filter(zone: &Zone) -> Option<Child> {
    let upstream = host_runtime_dir(zone).join("pulse").join("native");
    if fs::symlink_metadata(&upstream).is_err() {
        return None;
    }
    let socket = zone.path(PULSE_FILTER);
    let _ = fs::remove_file(&socket);
    let (uid, gid) = {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(&zone.dir).ok()?;
        (meta.uid(), meta.gid())
    };
    let exe = std::env::current_exe().ok()?;
    let mut child = match Command::new(exe)
        .arg("pulse-filter")
        .arg("--listen")
        .arg(&socket)
        .arg("--upstream")
        .arg(&upstream)
        .arg("--zone")
        .arg(zone.settings_name())
        .arg("--zone-dir")
        .arg(zone.settings_dir())
        // An instance's filter: whose its programs are, and their user
        // namespace — the socket is theirs alone.
        .args(instance_helper_args(zone))
        .arg("--config")
        .arg(zone.home.join(CONFIG_SUBDIR))
        .arg("--profiles")
        .arg(zone.home.join(crate::container::PROFILES_SUBDIR))
        .arg("--kdialog")
        .arg(&zone.tools.kdialog)
        .args(
            (!zone.tools.window.as_os_str().is_empty())
                .then(|| [OsStr::new("--window"), zone.tools.window.as_os_str()])
                .into_iter()
                .flatten(),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .uid(uid)
        .gid(gid)
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!(
                "zone {}: cannot start the sound filter ({e}) — no sound in the zone",
                zone.name()
            );
            return None;
        }
    };
    if socket_up(&socket, &mut child) {
        return Some(child);
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

/// A hermetic zone's PipeWire socket (`crate::pw_context`), on the host — from
/// the unit's own process, in the host's user namespace (`Helpers`) — as the
/// user: listening in the zone's directory, handed to the host's PipeWire as
/// a security context once WirePlumber's policy of vpn-zones is there, and
/// closing what connects until then. Started whether or not PipeWire is up:
/// it waits for the daemon, and the zone's socket exists from the start.
/// `None` when it cannot start — the zone then has no `pipewire-0` at all.
fn start_pipewire_context(zone: &Zone) -> Option<Child> {
    let upstream = host_runtime_dir(zone).join("pipewire-0");
    let socket = zone.path(crate::pw_context::SOCKET);
    let _ = fs::remove_file(&socket);
    let _ = fs::remove_file(zone.path(crate::pw_context::STATE_FILE));
    let (uid, gid) = {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(&zone.dir).ok()?;
        (meta.uid(), meta.gid())
    };
    let exe = std::env::current_exe().ok()?;
    // An instance's context: its own key and state (`--app-id`,
    // `--state-dir`) — its network's would be every instance's of it.
    let own: Vec<OsString> = match &zone.instance {
        Some(instance) => vec![
            OsString::from("--app-id"),
            OsString::from(format!("instance:{}", instance.id)),
            OsString::from("--state-dir"),
            zone.dir.clone().into_os_string(),
        ],
        None => Vec::new(),
    };
    let mut child = match Command::new(exe)
        .arg("pipewire-context")
        .arg("--listen")
        .arg(&socket)
        .arg("--upstream")
        .arg(&upstream)
        .arg("--zone")
        .arg(zone.settings_name())
        .arg("--zone-dir")
        .arg(zone.settings_dir())
        .args(own)
        .args(instance_helper_args(zone))
        .arg("--config")
        .arg(zone.home.join(CONFIG_SUBDIR))
        .arg("--profiles")
        .arg(zone.home.join(crate::container::PROFILES_SUBDIR))
        .arg("--instance")
        .arg(std::process::id().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .uid(uid)
        .gid(gid)
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!(
                "zone {}: cannot start the PipeWire context ({e}) — no pipewire-0 in the zone",
                zone.name()
            );
            return None;
        }
    };
    if socket_up(&socket, &mut child) {
        return Some(child);
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

/// The session bus filter of a hermetic zone (`crate::bus_filter`, LEAK-MODEL
/// §2), in front of its proxy: in the app namespace — so that the broker knows
/// the zone by its network namespace — and as the user, like the proxy. A link
/// a program hands the portal goes to the broker with the container of the
/// program's connection (`crate::links`); the broker believes that word from
/// this filter alone, a child of this very process (`broker::is_zones_filter`)
/// — which is why it is started here and nowhere else. It dies with this
/// process (`PR_SET_PDEATHSIG`), which is the zone.
/// Unlike the `Helpers` it lives in the zone's user namespace, beside the
/// zone's programs: that is why it makes itself not dumpable first thing and
/// starts nothing (`--via-broker`) — what it started would be dumpable again.
fn start_session_filter(zone: &Zone) {
    let upstream = zone.path(SESSION_BUS_PROXY);
    if fs::symlink_metadata(&upstream).is_err() {
        return;
    }
    let socket = zone.path(SESSION_BUS_FILTER);
    let _ = fs::remove_file(&socket);
    let (uid, gid) = match fs::metadata(&zone.dir) {
        Ok(meta) => {
            use std::os::unix::fs::MetadataExt;
            (meta.uid(), meta.gid())
        }
        Err(e) => {
            eprintln!(
                "zone {}: cannot read {} ({e}) — no session bus filter",
                zone.name(),
                zone.dir.display()
            );
            return;
        }
    };
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            eprintln!(
                "zone {}: cannot find our own binary ({e}) — no session bus filter",
                zone.name()
            );
            return;
        }
    };
    let mut child = match Command::new(exe)
        .arg("bus-filter")
        .arg("--listen")
        .arg(&socket)
        .arg("--upstream")
        .arg(&upstream)
        .arg("--opener")
        .arg(&zone.tools.opener)
        .arg("--via-broker")
        .arg(zone.settings_name())
        // Who each program's connection is to the portal (LEAK-MODEL §23):
        // the zone, registered by the filter before the program's first call
        // passes; the entry that names it was written as the zone came up.
        .arg("--portal-app")
        .arg(crate::desktop::zone_app_id(&zone.settings_name()))
        // A container's connections go by the container's own id where its
        // entry is there (`desktop::container_app_id`, written by sync).
        .arg("--applications")
        .arg(zone.home.join(".local/share/applications"))
        // The zone's screen cast switch (`crate::screencast`), read for every
        // call through descriptors the filter opens before its socket
        // appears — the project's state is covered right after that
        // (`hide_project_state`).
        .arg("--zone")
        .arg(zone.settings_name())
        .arg("--zone-dir")
        .arg(zone.settings_dir())
        // An instance's filter is told whose its programs are: the instance
        // is the container, and no registry is read for it. And its
        // `network` file, held with the rest before the covering: the screen
        // cast switch read, and the zone's id a new connection goes to the
        // portal with, are the network's it is in now — a live switch
        // changes it (review 2026-09-28).
        .args(
            zone.instance
                .as_ref()
                .map(|instance| {
                    [
                        OsString::from("--container"),
                        OsString::from(instance.who.word()),
                        OsString::from("--network-file"),
                        zone.path(crate::instance::NETWORK).into_os_string(),
                    ]
                })
                .into_iter()
                .flatten(),
        )
        .arg("--config")
        .arg(zone.home.join(CONFIG_SUBDIR))
        // The containers' data, held before the zone covers it too: a
        // program's container is read for each connection (`crate::origin`).
        .arg("--profiles")
        .arg(zone.home.join(crate::container::PROFILES_SUBDIR))
        // Where the broker's socket is: the zone's runtime directory, once it
        // is sealed a moment from now.
        .env("XDG_RUNTIME_DIR", host_runtime_dir(zone))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .uid(uid)
        .gid(gid)
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!(
                "zone {}: cannot start the session bus filter ({e})",
                zone.name()
            );
            return;
        }
    };
    if socket_up(&socket, &mut child) {
        return;
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Whether a helper just started has its socket up: waited for as long as
/// that takes, or until the helper ends without it. No clock: on a loaded
/// machine a helper comes up late, and a deadline would take the zone's bus
/// or sound away exactly there. A helper that hangs before its socket holds
/// the zone's start — `cellward up` waits for it, and says what it waits for
/// only in the journal; stopping the zone ends it.
fn socket_up(socket: &Path, child: &mut Child) -> bool {
    sys::wait_for_child_entry(socket, child, |p| fs::symlink_metadata(p).is_ok())
}

/// The host's runtime directory of the zone's user.
fn host_runtime_dir(zone: &Zone) -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) {
        return PathBuf::from(dir);
    }
    use std::os::unix::fs::MetadataExt;
    let uid = fs::metadata(&zone.dir).map_or(0, |m| m.uid());
    PathBuf::from(format!("/run/user/{uid}"))
}

/// Bind the socket at `from` — one of ours, in the zone's directory — over `to`.
///
/// The zone's directory is the user's, and a program with the user's `$HOME`
/// can put a symlink where a socket is expected: `mount(2)` follows it, and the
/// zone would get whatever it pointed at — the host's own system or session
/// bus (review 2026-09-25). So the socket is opened without following links,
/// checked to BE a socket and the user's, and bound through that descriptor.
fn bind_socket(from: &Path, to: &Path, owner: u32) -> Result<(), String> {
    let c = std::ffi::CString::new(from.as_os_str().as_bytes())
        .map_err(|_| format!("a NUL in {}", from.display()))?;
    // SAFETY: a NUL-terminated path and flags; the descriptor is ours.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "{}: {}",
            from.display(),
            io::Error::last_os_error()
        ));
    }
    // SAFETY: just opened, owned from here.
    let held = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: stat is plain data filled in by the kernel.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid descriptor and a stat buffer.
    if unsafe { libc::fstat(held.as_raw_fd(), &mut st) } != 0 {
        return Err(format!(
            "{}: {}",
            from.display(),
            io::Error::last_os_error()
        ));
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFSOCK || st.st_uid != owner {
        return Err(format!(
            "{} is not the user's socket — not bound into the zone",
            from.display()
        ));
    }
    if !to.exists() {
        if let Some(dir) = to.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(to)
            .map_err(|e| format!("cannot create {}: {e}", to.display()))?;
    }
    let source = PathBuf::from(format!("/proc/self/fd/{}", held.as_raw_fd()));
    sys::mount(source.as_os_str(), to, "", libc::MS_BIND, "")
        .map_err(|e| format!("cannot bind {}: {e}", from.display()))
}

/// Bind `from` over a placeholder at `to`, replacing whatever was bound there:
/// a socket the host recreated is a new inode, and the old bind leads nowhere.
fn bind_entry(from: &Path, to: &Path) -> Result<(), String> {
    let target = std::ffi::CString::new(to.as_os_str().as_bytes())
        .map_err(|_| format!("a NUL in {}", to.display()))?;
    // `to` is in the zone's runtime directory, which its programs write: a
    // link put there must not take the bind anywhere else (review 2026-09-25,
    // third round). Not followed here, and the mount goes onto what was
    // opened without following one.
    if fs::symlink_metadata(to).is_ok_and(|m| m.file_type().is_symlink()) {
        let _ = fs::remove_file(to);
    }
    // SAFETY: a NUL-terminated path; the flags take no pointers. Until
    // nothing is bound there any more.
    while unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH | libc::UMOUNT_NOFOLLOW) } == 0 {
    }
    let is_dir = fs::metadata(from)
        .map_err(|e| format!("{}: {e}", from.display()))?
        .is_dir();
    match fs::symlink_metadata(to) {
        Ok(meta) if meta.is_dir() != is_dir => {
            if meta.is_dir() {
                let _ = fs::remove_dir(to);
            } else {
                let _ = fs::remove_file(to);
            }
        }
        _ => {}
    }
    if is_dir {
        fs::create_dir_all(to)
    } else {
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .custom_flags(libc::O_NOFOLLOW)
            .open(to)
            .map(|_| ())
    }
    .map_err(|e| format!("cannot create {}: {e}", to.display()))?;
    // SAFETY: a NUL-terminated path and constant flags.
    let fd = unsafe {
        libc::open(
            target.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "cannot open {}: {}",
            to.display(),
            io::Error::last_os_error()
        ));
    }
    // SAFETY: a descriptor just opened and owned by nobody else.
    let held = unsafe { OwnedFd::from_raw_fd(fd) };
    let meta = fs::metadata(format!("/proc/self/fd/{fd}"))
        .map_err(|e| format!("cannot look at {}: {e}", to.display()))?;
    if meta.is_dir() != is_dir {
        return Err(format!("{} changed under the bind", to.display()));
    }
    let point = PathBuf::from(format!("/proc/self/fd/{}", held.as_raw_fd()));
    sys::mount(
        from.as_os_str(),
        &point,
        "",
        libc::MS_BIND | libc::MS_REC,
        "",
    )
    .map_err(|e| format!("cannot bind {}: {e}", from.display()))
}

/// The zone's runtime directory (`docs/HERMETICITY.md` §2,
/// `docs/LEAK-MODEL.md` §13), for EVERY zone: a tmpfs of its own over the
/// user's, with the entries [`runtime_entry_kept`] allows bound back, the
/// broker's socket, the zone's own directory of restricted Wayland sockets
/// and — in a hermetic zone — the filtered session bus as `bus`.
///
/// Built from a hold of the host's directory that stays for the zone's
/// lifetime, below a tmpfs of mode 0700 owned by the zone's root: programs run
/// as the user and never get there. A watcher binds what the host creates
/// later — pipewire or dbus restarted, gpg-agent started — so a zone does not
/// lose its sound or its bus to a restart; what [`runtime_entry_kept`] refuses
/// is refused then too. Fatal when the directory cannot be closed at all: a
/// zone that hands out the compositor's socket is worse than no zone.
fn seal_runtime(zone: &Zone) -> Result<(), String> {
    let runtime = host_runtime_dir(zone);
    if fs::symlink_metadata(&runtime).is_err() {
        return Ok(());
    }
    let (uid, gid) = {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(&zone.dir)
            .map_err(|e| format!("cannot read the zone's directory: {e}"))?;
        (meta.uid(), meta.gid())
    };
    let hold = zone.path(HOST_RUNTIME);
    fs::create_dir_all(&hold).map_err(|e| format!("cannot create {}: {e}", hold.display()))?;
    sys::mount(OsStr::new("tmpfs"), &hold, "tmpfs", 0, "mode=0700,size=64k")
        .map_err(|e| format!("cannot close {}: {e}", hold.display()))?;
    let held = hold.join(HOST_RUNTIME_HELD);
    fs::create_dir_all(&held).map_err(|e| format!("cannot create {}: {e}", held.display()))?;
    sys::mount(
        runtime.as_os_str(),
        &held,
        "",
        libc::MS_BIND | libc::MS_REC,
        "",
    )
    .map_err(|e| format!("cannot hold {}: {e}", runtime.display()))?;

    // Our directories on the host, owned by the user: the zone's Wayland
    // directory has to exist before it can be bound, and wl-sandbox (the
    // user, on the host) creates its sockets in it.
    let wayland_host = held
        .join(crate::wl_sandbox::SOCKET_DIR)
        .join(zone.wayland_dir());
    fs::create_dir_all(&wayland_host)
        .map_err(|e| format!("cannot create {}: {e}", wayland_host.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        let mut dir = wayland_host.clone();
        while dir != held {
            let _ = std::os::unix::fs::chown(&dir, Some(uid), Some(gid));
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
            if !dir.pop() {
                break;
            }
        }
    }

    // The watch first, the listing second: nothing created in between is lost.
    let watch = crate::sys::Inotify::watch(&held).ok();

    sys::mount(
        OsStr::new("tmpfs"),
        &runtime,
        "tmpfs",
        0,
        &format!("mode=0700,uid={uid},gid={gid},size=16m"),
    )
    .map_err(|e| format!("cannot close {}: {e}", runtime.display()))?;
    // Shared, in the zone's otherwise private tree: a container's launch
    // takes a copy of the zone's mount namespace as a slave (`launch::
    // entry_argv`), and what the watcher below binds here later — a socket
    // or a directory the host creates after the zone came up; in an ordinary
    // zone PipeWire and the bus after the host restarts them — reaches its
    // programs too. Slave: nothing a container mounts comes back. (A mount
    // the host makes later on such a directory — the document portal's FUSE
    // — does not come along, into the zone or its containers: the zone's
    // tree is private from the host's.)
    sys::mount(OsStr::new("none"), &runtime, "", libc::MS_SHARED, "")
        .map_err(|e| format!("cannot share {}: {e}", runtime.display()))?;

    let mut kept = Vec::new();
    for entry in fs::read_dir(&held).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if runtime_entry_kept(&name, zone.hermetic, zone.audio_manager) {
            match bind_entry(&entry.path(), &runtime.join(&name)) {
                Ok(()) => kept.push(name),
                // Skipped is hidden: what could not be bound is simply not there.
                Err(e) => eprintln!("zone {}: {e} — not in the zone", zone.name()),
            }
        }
    }
    let wayland_zone = runtime
        .join(crate::wl_sandbox::SOCKET_DIR)
        .join(zone.wayland_dir());
    bind_entry(&wayland_host, &wayland_zone)?;
    // Read-only in the zone (review 2026-09-25): the sockets of every launch
    // of the zone are in it, and a program of one launch could otherwise
    // unlink another's `wl-sandbox-<pid>` and listen there itself — the next
    // connection of that launch (a new window, a dialog) would come to it,
    // keys and clipboard with it. connect(2) needs no write access to the
    // directory, unlink and bind do (EROFS). `wl-sandbox` makes its sockets
    // through the host's path, which stays writable. Through the bind's own
    // descriptor, not the path: the path is in the zone's runtime directory.
    let bound = sys::open_dir(&wayland_zone)
        .map_err(|e| format!("cannot open {}: {e}", wayland_zone.display()))?;
    sys::remount_read_only(Path::new(&format!("/proc/self/fd/{}", bound.as_raw_fd())))
        .map_err(|e| format!("cannot make {} read-only: {e}", wayland_zone.display()))?;
    drop(bound);
    kept.push(format!(
        "{}/{}",
        crate::wl_sandbox::SOCKET_DIR,
        zone.wayland_dir()
    ));
    // The scratch directories of the zone's sandboxes, with their bus filters
    // (`fs_sandbox::SCRATCH_SUBDIR`): in the zone's runtime directory, which no
    // other zone sees — they used to be in the shared /tmp. Made here, the
    // user's and closed, because `vpn-zones/` in the zone is ours and the
    // sandbox runs as the user.
    let scratch = runtime.join(crate::fs_sandbox::SCRATCH_SUBDIR);
    {
        use std::os::unix::fs::PermissionsExt;
        fs::create_dir_all(&scratch)
            .and_then(|()| std::os::unix::fs::chown(&scratch, Some(uid), Some(gid)))
            .and_then(|()| fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700)))
            .map_err(|e| format!("cannot create {}: {e}", scratch.display()))?;
    }
    let broker = held.join(crate::broker::SOCKET);
    if fs::symlink_metadata(&broker).is_ok() {
        bind_entry(&broker, &runtime.join(crate::broker::SOCKET))?;
        kept.push("broker".to_owned());
    }
    // The sound server's control socket, through the filter: never the host's
    // own, where a client may make the host connect out (`pulse_filter`). No
    // filter, no sound — the zone is not given the raw one.
    let pulse = zone.path(PULSE_FILTER);
    if fs::symlink_metadata(&pulse).is_ok() {
        let dir = runtime.join("pulse");
        fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let _ = std::os::unix::fs::chown(&dir, Some(uid), Some(gid));
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
        bind_socket(&pulse, &dir.join("native"), uid)?;
        kept.push("pulse (filtered)".to_owned());
    }
    // A hermetic zone's `pipewire-0`: the security context's socket
    // (`pw_context`), never the host's raw one — unless the zone is an audio
    // manager, which kept the host's above and is said so. No context, no
    // PipeWire: the pulse path stays.
    if zone.hermetic && !zone.audio_manager {
        let context = zone.path(crate::pw_context::SOCKET);
        if fs::symlink_metadata(&context).is_ok() {
            bind_socket(&context, &runtime.join("pipewire-0"), uid)?;
            kept.push("pipewire-0 (restricted)".to_owned());
        } else {
            eprintln!(
                "zone {}: no PipeWire context — no pipewire-0 in the zone (sound through pulse only)",
                zone.name()
            );
        }
    } else if zone.hermetic {
        eprintln!(
            "zone {}: AUDIO MANAGER — the host's raw pipewire-0 in a hermetic zone: every stream \
             and device of the host (cellward audio-manager {} off)",
            zone.name(),
            zone.name()
        );
    }
    if zone.hermetic {
        // The filter, never the proxy behind it: the proxy alone would hand
        // the portal's links to the host (LEAK-MODEL §2). No filter, no bus —
        // said out loud.
        let filter = zone.path(SESSION_BUS_FILTER);
        if fs::symlink_metadata(&filter).is_ok() {
            bind_socket(&filter, &runtime.join("bus"), uid)?;
            kept.push("bus (filtered)".to_owned());
        } else if fs::symlink_metadata(zone.path(SESSION_BUS_PROXY)).is_ok() {
            eprintln!(
                "zone {}: the session bus filter is not up — the zone gets no session bus",
                zone.name()
            );
        }
    }
    println!(
        "zone {}: {} runtime ({})",
        zone.name(),
        if zone.hermetic { "hermetic" } else { "sealed" },
        kept.join(", ")
    );

    match watch {
        Some(watch) => {
            let hermetic = zone.hermetic;
            let raw_pipewire = zone.audio_manager;
            let name = zone.name().into_owned();
            // The hold is below the zone's directory, which is covered a
            // moment later (`hide_project_state`): the watcher goes on
            // through a descriptor, by our pid, as the holder does.
            let held = match sys::open_dir(&held) {
                Ok(fd) => {
                    // SAFETY: getpid(2) takes no arguments and cannot fail.
                    let pid = unsafe { libc::getpid() };
                    PathBuf::from(format!("/proc/{pid}/fd/{}", fd.into_raw_fd()))
                }
                Err(e) => return Err(format!("cannot open {}: {e}", held.display())),
            };
            thread::spawn(move || loop {
                let names = match watch.names() {
                    Ok(names) => names,
                    Err(e) => {
                        eprintln!("zone {name}: the runtime watch ended ({e})");
                        return;
                    }
                };
                for entry in names {
                    if !runtime_entry_kept(&entry, hermetic, raw_pipewire) {
                        continue;
                    }
                    if let Err(e) = bind_entry(&held.join(&entry), &runtime.join(&entry)) {
                        eprintln!("zone {name}: {e} — not in the zone");
                    }
                }
            });
        }
        None => eprintln!(
            "zone {}: no watch on {} — what the host creates later stays outside the zone",
            zone.name(),
            runtime.display()
        ),
    }
    Ok(())
}

/// In the zone's mount namespace: the proxy's socket over the host's system
/// bus, or — no proxy — nothing at all over `/run/dbus`. Never the host's bus
/// as it is. Fatal when neither can be done: a zone that promises a filtered
/// system bus and hands out the whole one is worse than no zone.
fn seal_system_bus(zone: &Zone) -> Result<(), String> {
    if fs::symlink_metadata(SYSTEM_BUS).is_err() {
        return Ok(());
    }
    let proxy = zone.path(SYSTEM_BUS_PROXY);
    let owner = {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(&zone.dir).map(|m| m.uid()).unwrap_or(u32::MAX)
    };
    if fs::symlink_metadata(&proxy).is_ok()
        && bind_socket(&proxy, Path::new(SYSTEM_BUS), owner).is_ok()
    {
        println!(
            "zone {}: system bus filtered (UPower, login1 inhibit/read)",
            zone.name()
        );
        return Ok(());
    }
    let dir = Path::new(SYSTEM_BUS)
        .parent()
        .unwrap_or(Path::new("/run/dbus"));
    sys::mount(OsStr::new("tmpfs"), dir, "tmpfs", 0, "mode=0755,size=64k").map_err(|e| {
        format!(
            "cannot close the system bus at {}: {e} — the zone would see all of it",
            dir.display()
        )
    })?;
    eprintln!(
        "zone {}: no system bus proxy — the system bus is closed in the zone",
        zone.name()
    );
    Ok(())
}

/// The temporary directories a hermetic zone gets of its own
/// (`docs/LEAK-MODEL.md` §15): `/tmp`, `/var/tmp` and `/dev/shm`, each an empty
/// tmpfs of mode 1777 in the zone's mount namespace, as Flatpak gives an app.
///
/// What they hid is the host's, and all of it same-user: listening sockets —
/// tmux's server in `/tmp/tmux-<uid>/` (`tmux -S … run-shell` runs a command
/// on the host, in the host's network), a VPN client's IPC to a root service,
/// Chromium's `SingletonSocket` —, JACK's sockets and other programs' shared
/// memory in `/dev/shm`. Our own things no longer live there: throwaway
/// containers moved to the state directory and the sandboxes' bus filters to
/// the runtime directory, so nothing of ours needs the host's `/tmp` in here.
///
/// The price, as with Flatpak: a file the host put into `/tmp` is not seen by
/// a program of the zone, and the zone's `/tmp` is memory, emptied when the
/// zone goes down. Fatal when it cannot be done: a hermetic zone that shares
/// the host's sockets is not hermetic.
fn private_tmp(zone: &Zone) -> Result<(), String> {
    for dir in PRIVATE_TMP {
        let dir = Path::new(dir);
        if !dir.is_dir() {
            continue;
        }
        sys::mount(
            OsStr::new("tmpfs"),
            dir,
            "tmpfs",
            libc::MS_NOSUID | libc::MS_NODEV,
            "mode=1777",
        )
        .map_err(|e| {
            format!(
                "cannot give the zone a {} of its own: {e} — it would share the host's sockets",
                dir.display()
            )
        })?;
    }
    // Said where the programs see it and cannot forge it (see the constant).
    // Not fatal: without the mark a sandbox keeps a /tmp of its own, as
    // before.
    if let Err(e) = touch(Path::new(PRIVATE_TMP_MARK)) {
        eprintln!(
            "zone {}: cannot mark its /tmp as its own ({e}) — its sandboxes keep one each",
            zone.name()
        );
    }
    println!(
        "zone {}: /tmp, /var/tmp and /dev/shm of its own",
        zone.name()
    );
    Ok(())
}

/// What [`private_tmp`] covers.
const PRIVATE_TMP: [&str; 3] = ["/tmp", "/var/tmp", "/dev/shm"];

/// How the programs of a zone or an instance see that their `/tmp` is their
/// own ([`private_tmp`]): this file in it, the keeper's — its root's, in a
/// sticky `/tmp`, so a program, which runs as the user, can neither make one
/// nor replace it; in the host's `/tmp` a program could only make one of
/// its own, which is no mark. A sandbox takes such a `/tmp` for the
/// container's launches to share (`fs_sandbox::Layout::share_tmp`); a `/tmp`
/// that is the host's (an ordinary zone's) it never does. In `/tmp` itself
/// and not in the runtime directory: a launch's view of that one is its own
/// (the VM check of 2026-09-28 found a mark there unseen).
pub const PRIVATE_TMP_MARK: &str = "/tmp/.cellward-private-tmp";

/// Where a zone keeps the host's devtmpfs: below a directory of the zone's
/// own `/dev` that only the zone's root enters (0700) — no program of the
/// zone, nor the root of a user namespace one makes, in whose view that
/// owner is nobody. The zone's watch looks at it; `profile-run` gives a
/// launch the nodes it is let from it.
pub const DEVTMPFS: &str = "/dev/.cellward/devtmpfs";

/// The directories of the devtmpfs the zone's watch could not watch, a line
/// each: `profile-run` gives nothing below them — a device gone there would
/// stay bound. Beside [`DEVTMPFS`], out of the programs' reach too.
const UNWATCHED: &str = "/dev/.cellward/unwatched";

/// [`UNWATCHED`]'s directories.
pub(crate) fn unwatched() -> Vec<PathBuf> {
    fs::read_to_string(UNWATCHED)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// A `/dev` of the zone's own: a tmpfs with the basics and the GPU
/// ([`allowed_node`]) bound in from the devtmpfs, the terminals of its own,
/// and nothing else (owner, 2026-09-26: default-deny).
///
/// How it came to this. logind gives the session's user an ACL on the
/// devices of the seat — `/dev/snd/*`, `/dev/video*`, `uinput`, `hidraw*`,
/// `/dev/input`, `/dev/bus/usb`… (the `uaccess` tag) — and a program of a
/// zone is that user: it opened the microphone past PipeWire (review
/// 2026-09-25), made a virtual keyboard that typed into any window of the
/// host (audit 2026-09-26). Covering them one by one missed what nobody
/// listed (`kvm`, `vhost-*`, `net/tun`, `kmsg`, all open to everyone), and
/// a cover is a mount: a program that made a mount namespace of its own —
/// private, as `unshare` makes it — saw a device plugged in later bare, on
/// the one devtmpfs every namespace shares (review 2026-09-26). On a tmpfs
/// of the zone's a device plugged in later appears nowhere at all.
///
/// And the terminals: the host's devpts shows every terminal of the host's,
/// and a program of a zone is the user who owns them — it could read what is
/// typed into one, or write a fake password prompt into it. The zone's own
/// instance holds only the terminals opened in the zone; a program started
/// into the zone from a terminal of the host keeps that terminal, but has no
/// name for it (`tty`: "not a tty" — as in Flatpak).
///
/// What a launch is let — a device its container is given, the cameras —
/// `profile-run` binds from [`DEVTMPFS`] onto an empty stand-in in its own
/// mount namespace (`profile::give_devices`, `profile::give_capture`). When
/// the device goes, the watch unlinks the stand-in, and the kernel takes
/// every bind on it away with it, in every namespace (`device_guard`
/// follows the rest). Fatal: a zone that cannot have it is not started.
fn own_dev(zone: &Zone) -> Result<(), String> {
    let dev = Path::new("/dev");
    let fail = |what: &str, e: io::Error| {
        format!("{what}: {e} — the zone's programs would reach the host's devices")
    };
    // What stays of the host's `/dev`: the devtmpfs, and the mounts on it a
    // program uses — shared memory (the zone's own in a hermetic zone,
    // [`private_tmp`]), message queues, huge pages. Taken before the tmpfs
    // goes over them.
    let devtmpfs = sys::clone_tree(dev).map_err(|e| fail("cannot take hold of /dev", e))?;
    let dev_id = {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(dev)
            .map_err(|e| fail("cannot read /dev", e))?
            .dev()
    };
    let mut kept: Vec<(OsString, OwnedFd)> = Vec::new();
    for entry in fs::read_dir(dev)
        .map_err(|e| fail("cannot read /dev", e))?
        .flatten()
    {
        use std::os::unix::fs::MetadataExt;
        let name = entry.file_name();
        let path = entry.path();
        let other_fs = fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir() && m.dev() != dev_id);
        // Not the host's message queues: an mqueue mount is the IPC namespace
        // of whoever mounted it, and the zone has one of its own (below).
        if other_fs && name != "pts" && name != "mqueue" {
            let tree = sys::clone_tree(&path)
                .map_err(|e| fail(&format!("cannot take hold of {}", path.display()), e))?;
            kept.push((name, tree));
        }
    }
    sys::mount(
        OsStr::new("tmpfs"),
        dev,
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
        "mode=0755,size=1m",
    )
    .map_err(|e| fail("cannot give the zone a /dev of its own", e))?;
    // The devtmpfs, where only the zone's root goes.
    {
        use std::os::unix::fs::DirBuilderExt;
        let parent = Path::new(DEVTMPFS).parent().unwrap_or(dev);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(parent)
            .and_then(|()| fs::create_dir(DEVTMPFS))
            .map_err(|e| fail("cannot make a place for the devtmpfs", e))?;
    }
    sys::attach_tree(&devtmpfs, Path::new(DEVTMPFS))
        .map_err(|e| fail("cannot keep the devtmpfs", e))?;
    for (name, tree) in &kept {
        let path = dev.join(name);
        fs::create_dir(&path)
            .and_then(|()| sys::attach_tree(tree, &path))
            .map_err(|e| fail(&format!("cannot keep {}", path.display()), e))?;
    }
    // The terminals of its own.
    let pts = dev.join("pts");
    fs::create_dir(&pts).map_err(|e| fail("cannot make /dev/pts", e))?;
    sys::mount(
        OsStr::new("devpts"),
        &pts,
        "devpts",
        libc::MS_NOSUID | libc::MS_NOEXEC,
        "newinstance,ptmxmode=0666,mode=0620",
    )
    .map_err(|e| fail("cannot give the zone terminals of its own", e))?;
    std::os::unix::fs::symlink("pts/ptmx", dev.join("ptmx"))
        .map_err(|e| fail("cannot link /dev/ptmx", e))?;
    // POSIX message queues of its own, in its own IPC namespace (review
    // 2026-09-27: the host's /dev/mqueue was kept, and with it the host's
    // queues). mq_open does not need it mounted: a failure leaves only the
    // listing out.
    let mqueue = dev.join("mqueue");
    let mounted = fs::create_dir(&mqueue).and_then(|()| {
        sys::mount(
            OsStr::new("mqueue"),
            &mqueue,
            "mqueue",
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            "",
        )
    });
    if let Err(e) = mounted {
        eprintln!(
            "zone {}: no /dev/mqueue of its own ({e}) — its queues are not listed there",
            zone.name()
        );
    }
    // The basics and the GPU, from the devtmpfs; its links as they are
    // there (`fd`, `stdin`…, `log`), and the standard ones where it has none.
    let host = Path::new(DEVTMPFS);
    for entry in fs::read_dir(host)
        .map_err(|e| fail("cannot read the devtmpfs", e))?
        .flatten()
    {
        let name = entry.file_name();
        let (from, to) = (entry.path(), dev.join(&name));
        let Ok(meta) = fs::symlink_metadata(&from) else {
            continue;
        };
        if name == "ptmx" || fs::symlink_metadata(&to).is_ok() {
            continue;
        }
        if meta.file_type().is_symlink() {
            if let Ok(target) = fs::read_link(&from) {
                let _ = std::os::unix::fs::symlink(target, &to);
            }
        } else if is_device(&meta) && allowed_node(&to) {
            give_node(&from, &to, &|_, _| true)
                .map_err(|e| fail(&format!("cannot give {}", to.display()), e))?;
        } else if meta.is_dir() && name == "dri" {
            give_dri().map_err(|e| fail("cannot give /dev/dri", e))?;
        }
    }
    for (name, target) in [
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
    ] {
        let link = dev.join(name);
        if fs::symlink_metadata(&link).is_err() {
            let _ = std::os::unix::fs::symlink(target, link);
        }
    }
    // Shared: every launch is a slave copy, and gets what is given the zone
    // later (a GPU node loaded after it came up).
    sys::mount(OsStr::new("none"), dev, "", libc::MS_SHARED, "")
        .map_err(|e| fail("cannot share /dev", e))?;

    let host_id = {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(host)
            .map_err(|e| fail("cannot read the devtmpfs", e))?
            .dev()
    };
    let watch = sys::DirWatch::new().map_err(|e| fail("no watch on the devtmpfs", e))?;
    let mut watcher = DeviceWatch {
        name: zone.name().into_owned(),
        watch,
        dev: host_id,
        known: Default::default(),
        unwatched: Default::default(),
        guard: crate::device_guard::start(zone.name().into_owned()),
    };
    // Fatal here: a directory not watched is one where a device given and
    // gone would stay given (out of watches: raise
    // fs.inotify.max_user_watches).
    let failed = watcher.watch_tree(host);
    if !failed.is_empty() {
        return Err(format!(
            "{} — a device given and gone would stay given",
            failed.join("; ")
        ));
    }
    thread::spawn(move || loop {
        match watcher.watch.events() {
            Ok(events) => {
                for event in events {
                    watcher.handle(event);
                }
            }
            Err(e) => {
                // Not given up: what happened meanwhile is looked at as
                // after an overflow.
                eprintln!("zone {}: the device watch failed ({e})", watcher.name);
                thread::sleep(Duration::from_secs(1));
                watcher.handle(sys::DirEvent::Overflow);
            }
        }
    });
    println!(
        "zone {}: a /dev of its own — the basics and the GPU — and terminals of its own",
        zone.name()
    );
    Ok(())
}

/// `from`, a node of the devtmpfs, bound at `to` of a `/dev` of the zone's
/// onto an empty stand-in of the zone's root, if `check` takes its number —
/// `false` when it is not given. The node is opened once and checked, and
/// what was opened is what is bound (`sys::clone_file`); one unlinked by the
/// time it is bound is taken off again — the zone's watch may have missed
/// its stand-in. The stand-in and every directory above it that is missing
/// are made the zone root's (`profile-run` makes them with its fsuid 0 —
/// [`crate::profile`]), with their modes set, not the umask's; one there
/// already must be the root's and what it should be — nothing a program put.
pub(crate) fn give_node(
    from: &Path,
    to: &Path,
    check: &dyn Fn(u32, u32) -> bool,
) -> io::Result<bool> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let node: OwnedFd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(from)?
        .into();
    let meta = File::from(node.try_clone()?).metadata()?;
    let rdev = meta.rdev();
    if !is_device(&meta) || !check(libc::major(rdev), libc::minor(rdev)) {
        return Ok(false);
    }
    let foreign = || io::Error::new(io::ErrorKind::PermissionDenied, "not the zone's");
    let roots = |p: &Path, dir: bool| {
        fs::symlink_metadata(p).is_ok_and(|m| {
            m.uid() == 0
                && if dir {
                    m.is_dir()
                } else {
                    m.file_type().is_file()
                }
        })
    };
    // The directories between `/dev` and it, from the top: each the root's,
    // made where missing.
    let mut dirs: Vec<&Path> = to
        .ancestors()
        .skip(1)
        .take_while(|dir| *dir != Path::new("/dev"))
        .collect();
    dirs.reverse();
    for dir in dirs {
        match fs::create_dir(dir) {
            Ok(()) => {
                owned_by_root(dir)?;
                fs::set_permissions(dir, fs::Permissions::from_mode(0o755))?;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        if !roots(dir, true) {
            return Err(foreign());
        }
    }
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o000)
        .custom_flags(libc::O_NOFOLLOW)
        .open(to)
    {
        Ok(_) => owned_by_root(to)?,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    // A stand-in, or a node bound here already (an allowed one, a device
    // given twice): anything else — a link, a directory — is not ours.
    let bound_already = fs::symlink_metadata(to).is_ok_and(|m| is_device(&m));
    if !roots(to, false) && !bound_already {
        return Err(foreign());
    }
    sys::attach_tree(&sys::clone_file(&node)?, to)?;
    if File::from(node.try_clone()?).metadata()?.nlink() == 0 {
        if let Ok(c) = std::ffi::CString::new(to.as_os_str().as_bytes()) {
            // SAFETY: a NUL-terminated path and constant flags.
            unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH | libc::UMOUNT_NOFOLLOW) };
        }
        return Ok(false);
    }
    Ok(true)
}

/// `path` the zone root's, where it is not already.
fn owned_by_root(path: &Path) -> io::Result<()> {
    std::os::unix::fs::lchown(path, Some(0), Some(0))
}

/// `/dev/dri` of the devtmpfs bound at the zone's own — again, where it was
/// there before: the directory of a driver loaded again, of a GPU plugged
/// in, is another directory, and a bind of the old one shows it empty.
fn give_dri() -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let (from, to) = (Path::new(DEVTMPFS).join("dri"), Path::new("/dev/dri"));
    if let Ok(c) = std::ffi::CString::new(to.as_os_str().as_bytes()) {
        // SAFETY: a NUL-terminated path and constant flags; until nothing is
        // mounted there.
        while unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH | libc::UMOUNT_NOFOLLOW) } == 0 {}
    }
    if !from.is_dir() {
        return Ok(());
    }
    if fs::symlink_metadata(to).is_err() {
        fs::create_dir(to)?;
        fs::set_permissions(to, fs::Permissions::from_mode(0o755))?;
    }
    sys::mount(from.as_os_str(), to, "", libc::MS_BIND, "")
}

/// The nodes of `/dev` every program of a zone keeps: what any program
/// takes for granted — `null`, `zero`, `full`, `random`, `urandom`, `tty`
/// (its own terminal) —, `fuse` (an AppImage mounts itself), `ntsync`
/// (Wine's and Proton's locks, nothing shared), and the GPU: `dri/*` and
/// NVIDIA's `nvidia<N>`, `nvidiactl`, `nvidia-modeset`, `nvidia-uvm`,
/// `nvidia-uvm-tools` — nothing draws without them. (`ptmx` is the zone's
/// own terminals'.) Anything else a container is given by a grant.
pub(crate) fn allowed_node(path: &Path) -> bool {
    let Ok(rel) = path.strip_prefix("/dev") else {
        return false;
    };
    let parts: Vec<&str> = rel.iter().map(|c| c.to_str().unwrap_or("")).collect();
    match parts.as_slice() {
        [name] => {
            matches!(
                *name,
                "null"
                    | "zero"
                    | "full"
                    | "random"
                    | "urandom"
                    | "tty"
                    | "ptmx"
                    | "fuse"
                    | "ntsync"
                    | "nvidiactl"
                    | "nvidia-modeset"
                    | "nvidia-uvm"
                    | "nvidia-uvm-tools"
            ) || name
                .strip_prefix("nvidia")
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        }
        ["dri", name] => !name.is_empty(),
        _ => false,
    }
}

/// Whether a node at `path` may have been in a program's reach — given to a
/// container (`devices::grantable_path`), or a camera's — and so is followed
/// after it goes (`device_guard`).
fn guarded_path(path: &Path) -> bool {
    crate::devices::grantable_path(path)
        || (path.parent() == Some(Path::new("/dev"))
            && path
                .file_name()
                .is_some_and(|n| is_capture_node(&n.to_string_lossy())))
}

/// The watch over the devtmpfs a zone keeps for as long as it is up.
struct DeviceWatch {
    name: String,
    watch: sys::DirWatch,
    /// The devtmpfs's device: a mount on it (the host's `pts`, `shm`) is not
    /// looked into.
    dev: u64,
    /// Each node a program may have had ([`guarded_path`]), by its path in
    /// the zone's `/dev`, as it was.
    known: std::collections::HashMap<PathBuf, crate::device_guard::Seen>,
    /// The directories of the devtmpfs not watched ([`UNWATCHED`]).
    unwatched: std::collections::BTreeSet<PathBuf>,
    /// The worker that looks into the zone's programs.
    guard: std::sync::mpsc::Sender<crate::device_guard::Job>,
}

/// A path of the devtmpfs as the zone's `/dev` names it.
fn in_zone_dev(host: &Path) -> Option<PathBuf> {
    host.strip_prefix(DEVTMPFS)
        .ok()
        .map(|rel| Path::new("/dev").join(rel))
}

impl DeviceWatch {
    fn handle(&mut self, event: sys::DirEvent) {
        match event {
            sys::DirEvent::Appeared(host) => {
                let Ok(meta) = fs::symlink_metadata(&host) else {
                    return;
                };
                if meta.is_dir() {
                    for e in self.watch_tree(&host) {
                        eprintln!("zone {}: {e}", self.name);
                    }
                    // The GPU's directory made again (a driver loaded, a
                    // GPU plugged in): the zone's bind shows the old one.
                    if host == Path::new(DEVTMPFS).join("dri") {
                        if let Err(e) = give_dri() {
                            eprintln!("zone {}: cannot give /dev/dri: {e}", self.name);
                        }
                    }
                } else if is_device(&meta) {
                    self.appeared(&host);
                }
            }
            sys::DirEvent::Gone(host) => {
                if let Some(path) = in_zone_dev(&host) {
                    self.gone(path);
                }
            }
            sys::DirEvent::Overflow => self.rescan(),
        }
    }

    /// A node there: a basic one or the GPU's given to the zone — one loaded
    /// after it came up —; one a program may be given, told to the worker.
    fn appeared(&mut self, host: &Path) {
        let Some(path) = in_zone_dev(host) else {
            return;
        };
        let root_level = path.parent() == Some(Path::new("/dev"));
        if root_level && allowed_node(&path) && fs::symlink_metadata(&path).is_err() {
            if let Err(e) = give_node(host, &path, &|_, _| true) {
                eprintln!("zone {}: cannot give {}: {e}", self.name, path.display());
            }
        }
        if guarded_path(&path) {
            if let Some(seen) = crate::device_guard::seen(host) {
                self.known.insert(path.clone(), seen.clone());
                let _ = self
                    .guard
                    .send(crate::device_guard::Job::Appeared(path, seen));
            }
        }
    }

    /// A node gone: its stand-in in the zone's `/dev` unlinked, which takes
    /// every bind on it away in every namespace; one a program may have had,
    /// told to the worker.
    fn gone(&mut self, path: PathBuf) {
        if path == Path::new("/dev/dri") {
            if let Err(e) = give_dri() {
                eprintln!("zone {}: cannot take /dev/dri back: {e}", self.name);
            }
            return;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else {
            return self.follow_gone(path);
        };
        // A basic node or the GPU's is bound here too: off first — a
        // mount point of this namespace is not unlinked.
        if is_device(&meta) {
            if let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) {
                // SAFETY: a NUL-terminated path and constant flags.
                unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH | libc::UMOUNT_NOFOLLOW) };
            }
        }
        // Never a link or a directory of ours: the stand-in alone.
        if is_device(&meta) || meta.file_type().is_file() {
            if let Err(e) = fs::remove_file(&path) {
                eprintln!(
                    "zone {}: cannot take {} back: {e}",
                    self.name,
                    path.display()
                );
            }
        }
        self.follow_gone(path);
    }

    /// Told to the worker, if a program may have had it.
    fn follow_gone(&mut self, path: PathBuf) {
        if guarded_path(&path) {
            let seen = self.known.remove(&path);
            let _ = self.guard.send(crate::device_guard::Job::Gone(path, seen));
        }
    }

    /// `dir` of the devtmpfs and every directory below it watched — each
    /// before it is listed, so nothing that appears meanwhile is lost — and
    /// the nodes in them looked at. What failed, `/dev:` first for the top.
    fn watch_tree(&mut self, dir: &Path) -> Vec<String> {
        use std::os::unix::fs::MetadataExt;
        let mut failed = Vec::new();
        let mut dirs = vec![dir.to_path_buf()];
        while let Some(dir) = dirs.pop() {
            match fs::symlink_metadata(&dir) {
                Ok(meta) if meta.dev() == self.dev => {}
                _ => continue,
            }
            if let Err(e) = self.watch.add(&dir) {
                if e.raw_os_error() != Some(libc::ENOENT) {
                    failed.push(format!("no watch on {} ({e})", dir.display()));
                    self.unwatched.insert(dir);
                }
                continue;
            }
            self.unwatched.remove(&dir);
            for entry in fs::read_dir(&dir).into_iter().flatten().flatten() {
                let path = entry.path();
                let Ok(meta) = fs::symlink_metadata(&path) else {
                    continue;
                };
                if meta.is_dir() {
                    dirs.push(path);
                } else if is_device(&meta) {
                    self.appeared(&path);
                }
            }
        }
        let list: String = self
            .unwatched
            .iter()
            .map(|d| format!("{}\n", d.display()))
            .collect();
        if fs::read_to_string(UNWATCHED).unwrap_or_default() != list {
            if let Err(e) = fs::write(UNWATCHED, list) {
                failed.push(format!("cannot note what is not watched: {e}"));
            }
        }
        failed
    }

    /// What happened is not known: a node followed and not the same any
    /// more is gone, what is there looked at again.
    fn rescan(&mut self) {
        use std::os::unix::fs::MetadataExt;
        let gone: Vec<PathBuf> = self
            .known
            .iter()
            .filter(|(path, seen)| {
                let host = Path::new(DEVTMPFS).join(path.strip_prefix("/dev").unwrap_or(path));
                !fs::symlink_metadata(host)
                    .is_ok_and(|m| (m.dev(), m.ino()) == (seen.dev, seen.ino))
            })
            .map(|(path, _)| path.clone())
            .collect();
        for path in gone {
            self.gone(path);
        }
        for e in self.watch_tree(Path::new(DEVTMPFS)) {
            eprintln!("zone {}: {e}", self.name);
        }
    }
}

/// A device node, character or block.
fn is_device(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    let kind = meta.file_type();
    kind.is_char_device() || kind.is_block_device()
}

/// The nodes of video capture — what the camera setting gives: a camera's
/// `video<N>`, `media<N>`, its sensor's `v4l-subdev<N>`; `v4l-touch<N>`
/// (a touch panel's raw frames), `radio<N>`, `vbi<N>`, `swradio<N>`.
pub(crate) fn is_capture_node(name: &str) -> bool {
    [
        "video",
        "media",
        "v4l-subdev",
        "v4l-touch",
        "radio",
        "vbi",
        "swradio",
    ]
    .iter()
    .any(|prefix| {
        name.strip_prefix(prefix)
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    })
}

/// A tmpfs over `/tmp/.X11-unix` in the zone's mount namespace
/// (`docs/HERMETICITY.md` §7, A). Created first when the host has none, so
/// that an X server started in the zone never puts its socket into the shared
/// `/tmp`, where every other zone could connect to it. Fatal when it cannot be
/// done: the promise is that no zone program reaches a foreign X server.
fn hide_x11(zone: &Zone) -> Result<(), String> {
    let dir = Path::new(crate::x11::X11_DIR);
    if !dir.is_dir() {
        fs::create_dir_all(dir)
            .and_then(|()| {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(dir, fs::Permissions::from_mode(0o1777))
            })
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    sys::mount(OsStr::new("tmpfs"), dir, "tmpfs", 0, "mode=1777,size=64k").map_err(|e| {
        format!(
            "cannot hide {}: {e} — programs in the zone would reach the host's X server",
            dir.display()
        )
    })?;
    println!("zone {}: host X11 hidden", zone.name());
    Ok(())
}

/// `/run/vpn-zones` out of reach, for every zone: the system tier's root
/// service listens there, and every request it takes — a zone added, a
/// program run in a system zone, a user zone's way out — is a way out of this
/// zone that the kernel would not stop, because the helper acts outside it
/// (`docs/LEAK-MODEL.md` §13, found by review). The zone's users are in the
/// group that may reach it; the zone must not be. Fatal when it cannot be
/// hidden: a zone with a door out is worse than no zone. A host without the
/// system tier has no such directory, and nothing to hide.
fn hide_system_tier(zone: &Zone) -> Result<(), String> {
    let dir = Path::new(SYSTEM_TIER_DIR);
    if !dir.is_dir() {
        return Ok(());
    }
    sys::mount(OsStr::new("tmpfs"), dir, "tmpfs", 0, "mode=0755,size=16k").map_err(|e| {
        format!(
            "cannot hide {}: {e} — programs in the zone would reach the system tier's service",
            dir.display()
        )
    })?;
    println!("zone {}: the system tier's service hidden", zone.name());
    Ok(())
}

/// The Nix daemon out of reach (review 2026-09-25, third round): it builds
/// and fetches in the host's network, and a fixed-output derivation fetches
/// whatever address a program names — from any zone, an offline one too.
/// A zone that needs it is let (`vpn-zone nix-daemon <zone> on`, or
/// `programs.cellward.nixDaemon` in Nix). Fatal when it cannot be hidden.
fn hide_nix_daemon(zone: &Zone) -> Result<(), String> {
    let dir = Path::new(NIX_DAEMON_DIR);
    if !dir.is_dir() {
        return Ok(());
    }
    sys::mount(OsStr::new("tmpfs"), dir, "tmpfs", 0, "mode=0755,size=16k").map_err(|e| {
        format!(
            "cannot hide {}: {e} — programs in the zone would have the host's Nix daemon fetch \
             for them",
            dir.display()
        )
    })?;
    println!("zone {}: the Nix daemon hidden", zone.name());
    Ok(())
}

/// Where the Nix daemon listens.
pub(crate) const NIX_DAEMON_DIR: &str = "/nix/var/nix/daemon-socket";

/// What of `/run/systemd` a zone keeps: the journal's sockets (a program
/// logs), `system/` (`sd_booted()`: "is this systemd"), and logind's state
/// files (`sd_session_*`, `sd_uid_*` read them).
const RUN_SYSTEMD_KEPT: [&str; 5] = ["journal", "system", "seats", "sessions", "users"];

/// Daemons under /run that answer whoever connects, and that no zone needs:
/// dhcpcd's unprivileged socket (the host's interfaces, addresses and
/// leases), sshd on a unix socket (a login on the host without a network, for
/// a key a program without a sandbox reads in `~/.ssh`).
const RUN_HIDDEN: [&str; 2] = ["/run/dhcpcd", "/run/ssh-unix-local"];

/// `/run/systemd` by an allow-list, and the daemons of [`RUN_HIDDEN`] out of
/// reach (review 2026-09-25: found by `vpn-zone doctor`'s inventory,
/// `docs/LEAK-MODEL.md` §18). systemd's services answer over varlink there,
/// open to everyone — `io.systemd.Hostname` the machine's name, model and id,
/// `io.systemd.Network` its interfaces and addresses: what the system bus
/// filter keeps from a zone, past it; and what systemd adds there next is out
/// of reach from the start. A tmpfs over the directory, and back what a
/// program uses ([`RUN_SYSTEMD_KEPT`]), bound whole, so that a restarted
/// journal's new sockets are in reach again. For every zone and for the
/// system tier's commands (`crate::sysrun`), in the current mount namespace.
pub(crate) fn seal_run() -> Result<(), String> {
    let dir = Path::new("/run/systemd");
    if dir.is_dir() {
        let kept = sys::open_dir(dir).map_err(|e| format!("cannot open {}: {e}", dir.display()))?;
        sys::mount(
            OsStr::new("tmpfs"),
            dir,
            "tmpfs",
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            "mode=0755,size=64k",
        )
        .map_err(|e| format!("cannot close {}: {e}", dir.display()))?;
        for name in RUN_SYSTEMD_KEPT {
            let from = PathBuf::from(format!("/proc/self/fd/{}/{name}", kept.as_raw_fd()));
            if !from.is_dir() {
                continue;
            }
            let to = dir.join(name);
            fs::create_dir(&to).map_err(|e| format!("cannot create {}: {e}", to.display()))?;
            sys::mount(from.as_os_str(), &to, "", libc::MS_BIND | libc::MS_REC, "")
                .map_err(|e| format!("cannot bind {} back: {e}", to.display()))?;
        }
    }
    for dir in RUN_HIDDEN {
        let dir = Path::new(dir);
        if !dir.is_dir() {
            continue;
        }
        sys::mount(OsStr::new("tmpfs"), dir, "tmpfs", 0, "mode=0755,size=16k")
            .map_err(|e| format!("cannot hide {}: {e}", dir.display()))?;
    }
    Ok(())
}

/// IBus's private bus out of reach (review 2026-09-25, third round): it
/// listens on a socket by path in `$XDG_CACHE_HOME/ibus` and writes its
/// address to `~/.config/ibus/bus`, both in the home a program has — past
/// the session bus's rules, which the network namespace does not cut for a
/// socket by path. A tmpfs over both; programs take the IBus portal
/// (`IBUS_USE_PORTAL`, set by the launch). Fatal when it cannot be done.
fn hide_input_methods(zone: &Zone) -> Result<(), String> {
    for dir in input_method_places(&zone.home) {
        if !dir.is_dir() || fs::symlink_metadata(&dir).is_ok_and(|m| m.file_type().is_symlink()) {
            continue;
        }
        sys::mount(
            OsStr::new("tmpfs"),
            &dir,
            "tmpfs",
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            "mode=0700,size=16k",
        )
        .map_err(|e| {
            format!(
                "cannot hide {}: {e} — IBus's private bus would be in reach",
                dir.display()
            )
        })?;
    }
    Ok(())
}

/// Where IBus keeps its addresses and its private bus's socket, below the
/// home: the default cache, `XDG_CACHE_HOME`'s, and the config.
fn input_method_places(home: &Path) -> Vec<PathBuf> {
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(".cache"));
    let mut places = vec![home.join(".cache/ibus"), home.join(".config/ibus")];
    if cache.join("ibus") != places[0] {
        places.push(cache.join("ibus"));
    }
    places
}

/// The session's own entry points below the home: created when missing before
/// a hermetic zone comes up (`run`), so that they can be read-only in it.
///
/// The sound server's among them (review 2026-09-25): the zones' PipeWire
/// policy is a WirePlumber script, and WirePlumber looks for its scripts in
/// `~/.local/share/wireplumber/scripts` BEFORE the system's (XDG_DATA_HOME
/// ahead of XDG_DATA_DIRS), and for its fragments in `~/.config/wireplumber`
/// first — a fragment of the same name replaces the system's. A zone that
/// could write there would put its own `vpn-zones/policy.lua` in, marker and
/// all, and every hermetic zone's socket would be handed out with everything
/// granted at WirePlumber's next start; a `pw-module` component or a
/// PipeWire fragment would load native code into the host's daemon. Only
/// "where it exists" would leave the NixOS host, where nothing is there,
/// open to the very first write. `~/.local/state/wireplumber` holds the
/// default devices and the streams' remembered targets: the host's routing.
const ENTRY_POINTS: [&str; 12] = [
    ".config/autostart",
    ".config/systemd",
    ".config/environment.d",
    ".config/user-tmpfiles.d",
    ".local/share/applications",
    ".local/share/dbus-1",
    ".local/share/systemd",
    ".local/share/user-tmpfiles.d",
    ".config/pipewire",
    ".config/wireplumber",
    ".local/share/wireplumber",
    ".local/state/wireplumber",
];

/// What the host runs from the home besides [`ENTRY_POINTS`], read-only in a
/// hermetic zone where it exists: the compositors' and the shells' configs,
/// tools that run what their config names, browsers' native-messaging hosts —
/// not a program's own data (a browser's profile is not here).
const HOST_RUNS_IN_ZONES: &[&str] = &[
    // Which program the host opens links and files with (review 2026-09-27);
    // the one under .local/share/applications is covered with its directory.
    ".config/mimeapps.list",
    ".local/share/flatpak/exports",
    ".local/bin",
    ".local/state/nix",
    ".local/state/home-manager",
    ".config/plasma-workspace",
    ".config/niri",
    ".config/sway",
    ".config/hypr",
    ".config/river",
    ".config/labwc",
    ".config/i3",
    ".config/uwsm",
    ".config/fish",
    ".config/zsh",
    ".config/nushell",
    ".config/xonsh",
    ".config/home-manager",
    ".config/nixpkgs",
    ".config/nix",
    ".config/direnv",
    ".local/share/direnv",
    ".config/xdg-desktop-portal",
    ".config/git",
    ".ssh",
    ".gnupg",
    ".docker",
    ".config/containers",
    ".mozilla/native-messaging-hosts",
    ".config/chromium/NativeMessagingHosts",
    ".config/google-chrome/NativeMessagingHosts",
    ".config/BraveSoftware/Brave-Browser/NativeMessagingHosts",
    ".config/vivaldi/NativeMessagingHosts",
    ".local/share/kio/servicemenus",
    ".local/share/kservices5",
    ".local/share/kservices6",
    ".local/share/nautilus/scripts",
    ".local/share/nemo/actions",
    ".profile",
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".zshenv",
    ".zshrc",
    ".zprofile",
    ".zlogin",
    ".zlogout",
    ".login",
    ".cshrc",
    ".tcshrc",
    ".xprofile",
    ".xsession",
    ".xsessionrc",
    ".xinitrc",
    ".pam_environment",
    ".inputrc",
];

/// What the host runs from the home, read-only in a hermetic zone (owner,
/// 2026-09-25; `docs/LEAK-MODEL.md` §9): without a sandbox a program has the
/// home, and a line in `~/.bashrc`, an entry in `~/.config/autostart`, a
/// launcher in `~/.local/share/applications` is code the host starts later —
/// outside the zone, around its tunnel. A zone that has to write there is let
/// (`vpn-zone host-files <zone> writable`, or
/// `programs.cellward.hostFilesWritable` in Nix).
///
/// A symlink cannot be covered — a mount follows it, and the link itself
/// stays a name in a directory the program can write: home-manager's
/// dotfiles in the home itself (`~/.zshrc` → the store) are left as they are,
/// and said so. A directory home-manager fills with links is covered whole.
/// Fatal when a real one cannot be made read-only.
fn protect_host_files(zone: &Zone) -> Result<(), String> {
    pin_parents(zone)?;
    let mut covered = 0;
    let mut links = Vec::new();
    for entry in ENTRY_POINTS.iter().chain(HOST_RUNS_IN_ZONES) {
        let path = zone.home.join(entry);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => links.push(*entry),
            Ok(_) => {
                sys::mount(
                    path.as_os_str(),
                    &path,
                    "",
                    libc::MS_BIND | libc::MS_REC,
                    "",
                )
                .and_then(|()| sys::remount_read_only(&path))
                .map_err(|e| format!("cannot make {} read-only: {e}", path.display()))?;
                covered += 1;
            }
            Err(_) => {}
        }
    }
    println!(
        "zone {}: {covered} of the host's startup places read-only{}",
        zone.name(),
        if links.is_empty() {
            String::new()
        } else {
            format!("; links, which a mount cannot cover: {}", links.join(", "))
        }
    );
    Ok(())
}

/// The directories between the home and every place a hermetic zone covers,
/// each made a mount point of itself: a mount point is neither renamed nor
/// removed in its namespace (EBUSY). A cover holds the directory it is on,
/// not its name: `mv ~/.config ~/.config.old` took the covers along, and a
/// new `~/.config/autostart/` was the host's at its next login — or a
/// `~/.local/state/vpn-zones` of the zone's making, where the host looks for
/// its own (review 2026-09-27). Only where the host's startup places are
/// read-only: elsewhere `~/.bashrc` is the zone's to write anyway. The price:
/// a rename across one of these is EXDEV, as between two disks — a file
/// moved from the home into `~/.local/share/Trash` among them; programs copy
/// then, or say they cannot. Shallow first, and recursive: what is mounted
/// below stays. A link is left, and said so: a mount follows it.
fn pin_parents(zone: &Zone) -> Result<(), String> {
    let mut places: Vec<PathBuf> = ENTRY_POINTS
        .iter()
        .chain(HOST_RUNS_IN_ZONES)
        .chain(READ_ONLY_IN_ZONES.iter())
        .chain(crate::home_layer::STORAGE.iter())
        .map(|p| zone.home.join(p))
        .collect();
    places.extend(input_method_places(&zone.home));
    // The state directory: a zone's is its directory's parent, an
    // instance's two levels up (`.instances/<key>`).
    match zone.instance {
        Some(_) => places.push(zone.home.join(STATE_SUBDIR)),
        None => places.extend(zone.dir.parent().map(Path::to_path_buf)),
    }
    // Component-wise order: a directory before those below it.
    let mut parents = std::collections::BTreeSet::new();
    for place in &places {
        let Ok(rel) = place.strip_prefix(&zone.home) else {
            continue;
        };
        let mut dir = zone.home.clone();
        let components: Vec<_> = rel.components().collect();
        for component in &components[..components.len().saturating_sub(1)] {
            dir.push(component);
            parents.insert(dir.clone());
        }
    }
    let mut links = Vec::new();
    for dir in parents {
        match fs::symlink_metadata(&dir) {
            Ok(meta) if meta.file_type().is_symlink() => links.push(dir.display().to_string()),
            Ok(meta) if meta.is_dir() => {
                sys::mount(dir.as_os_str(), &dir, "", libc::MS_BIND | libc::MS_REC, "")
                    .map_err(|e| format!("cannot pin {}: {e}", dir.display()))?;
            }
            _ => {}
        }
    }
    if !links.is_empty() {
        eprintln!(
            "zone {}: links, which a mount cannot pin — a program of the zone can rename them: {}",
            zone.name(),
            links.join(", ")
        );
    }
    Ok(())
}

/// The containers' storage out of the zone's reach (review 2026-09-26): each
/// container's data is its own — a browser profile, a sandbox's home — and a
/// program of the zone read every one of them, and wrote them, code they run
/// included. The real storage is kept in [`crate::home_layer::KEPT_STORAGE`]
/// — inside the project's state, whose tmpfs is the zone's own, a directory
/// 0700 of the zone's root that no program of the zone enters — and both
/// storage directories are covered with a tmpfs. A container launched into
/// the zone gets its own directory back from there, in its own mount
/// namespace (`profile-run --storage`). After [`hide_project_state`], whose
/// tmpfs this lives in. Fatal: a zone that cannot do it would show every
/// container's data.
fn hide_container_storage(zone: &Zone) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    let kept = zone.home.join(crate::home_layer::KEPT_STORAGE);
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&kept)
        .map_err(|e| format!("cannot create {}: {e}", kept.display()))?;
    // The throwaway containers' too: given back to the zone by
    // `hide_project_state` (`ZONE_KEEPS`), and from there into the keep —
    // each launch gets its own back (`profile-run --storage`), no program
    // sees another's (review 2026-09-27: every zone read every zone's).
    // An instance is one container: its own storage is kept and no other's
    // — not even out of the programs' reach (`InstanceInfo`).
    let own = zone
        .instance
        .as_ref()
        .map(|instance| instance.storage.as_deref());
    for (dir, kind) in crate::home_layer::STORAGE
        .iter()
        .copied()
        .chain([crate::home_layer::THROWAWAY_STORAGE])
        .zip(["profiles", "sandboxes", "throwaway"])
    {
        let dir = zone.home.join(dir);
        if !dir_there(&dir)? {
            continue;
        }
        let keep = kept.join(kind);
        fs::create_dir(&keep).map_err(|e| format!("cannot create {}: {e}", keep.display()))?;
        match own {
            None => sys::mount(dir.as_os_str(), &keep, "", libc::MS_BIND | libc::MS_REC, "")
                .map_err(|e| format!("cannot keep {}: {e}", dir.display()))?,
            Some(storage) => {
                let name = storage
                    .filter(|s| s.parent() == Some(dir.as_path()))
                    .and_then(Path::file_name);
                if let Some(name) = name {
                    let (from, to) = (dir.join(name), keep.join(name));
                    fs::create_dir(&to)
                        .map_err(|e| format!("cannot create {}: {e}", to.display()))?;
                    sys::mount(from.as_os_str(), &to, "", libc::MS_BIND | libc::MS_REC, "")
                        .map_err(|e| format!("cannot keep {}: {e}", from.display()))?;
                }
            }
        }
        sys::mount(
            OsStr::new("tmpfs"),
            &dir,
            "tmpfs",
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            "mode=0755,size=64k",
        )
        .map_err(|e| format!("cannot hide {}: {e}", dir.display()))?;
    }
    Ok(())
}

/// The project's own state out of the zone's reach (review 2026-09-25,
/// third round). `~/.local/state/vpn-zones` holds what the host trusts about
/// zones — which namespace is which zone (`zone.pid`, `zone.start`), which is
/// locked, what was pinned, the raw sockets behind the zone's filters, every
/// zone's private key — and a program here has the home: it could tell the
/// broker it is another zone, or connect past the bus filter to the proxy
/// behind it. A tmpfs over the directory, and back only what a launch needs
/// inside ([`ZONE_KEEPS`]); the settings and the shims read-only
/// ([`READ_ONLY_IN_ZONES`]). Fatal: a zone that cannot do it has a way out.
///
/// Returns the zone as this process goes on reaching it: its directory is
/// `/proc/<our pid>/fd/N` of a descriptor opened before the tmpfs, kept for
/// good — by pid and not `self`, so that the tools it starts (`wg setconf`
/// reads a file there) reach it too. Nobody else here can use it: this
/// process and its children are the zone's uid 0, and a program here,
/// another user of the namespace, cannot open another user's `/proc/<pid>/fd`.
fn hide_project_state(zone: &Zone) -> Result<Zone, String> {
    let own =
        sys::open_dir(&zone.dir).map_err(|e| format!("cannot open {}: {e}", zone.dir.display()))?;
    // An instance's directory is `.instances/<key>` below the state.
    let state = match zone.instance {
        Some(_) => zone.home.join(STATE_SUBDIR),
        None => zone
            .dir
            .parent()
            .ok_or("the zone's directory has no parent")?
            .to_path_buf(),
    };
    let keeps = zone.keeps();
    let keeps: Vec<(&str, bool)> = keeps.iter().map(|(n, w)| (n.as_str(), *w)).collect();
    seal_project_state(&state, &zone.home, &keeps)?;
    println!("zone {}: the project's state hidden", zone.name());
    // SAFETY: getpid(2) takes no arguments and cannot fail.
    let pid = unsafe { libc::getpid() };
    Ok(Zone {
        name: zone.name.clone(),
        dir: PathBuf::from(format!("/proc/{pid}/fd/{}", own.into_raw_fd())),
        home: zone.home.clone(),
        tools: zone.tools.clone(),
        hermetic: zone.hermetic,
        nix_daemon: zone.nix_daemon,
        host_files_writable: zone.host_files_writable,
        audio_manager: zone.audio_manager,
        instance: zone.instance.clone(),
    })
}

/// A tmpfs over `state`, with `keep` bound back (writable or not), and
/// [`READ_ONLY_IN_ZONES`] under `home` made read-only — in the current mount
/// namespace. Shared with the system tier's commands (`crate::sysrun`), which
/// keep nothing.
pub(crate) fn seal_project_state(
    state: &Path,
    home: &Path,
    keep: &[(&str, bool)],
) -> Result<(), String> {
    if dir_there(state)? {
        let kept =
            sys::open_dir(state).map_err(|e| format!("cannot open {}: {e}", state.display()))?;
        sys::mount(
            OsStr::new("tmpfs"),
            state,
            "tmpfs",
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            "mode=0755,size=64k",
        )
        .map_err(|e| format!("cannot hide {}: {e}", state.display()))?;
        for (name, writable) in keep {
            let from = PathBuf::from(format!("/proc/self/fd/{}/{name}", kept.as_raw_fd()));
            if !from.is_dir() {
                continue;
            }
            let to = state.join(name);
            // All the way down: an instance keeps `.throwaway/<its layer>`.
            fs::create_dir_all(&to).map_err(|e| format!("cannot create {}: {e}", to.display()))?;
            sys::mount(from.as_os_str(), &to, "", libc::MS_BIND | libc::MS_REC, "")
                .map_err(|e| format!("cannot bind {} back: {e}", to.display()))?;
            if !writable {
                sys::remount_read_only(&to)
                    .map_err(|e| format!("cannot make {} read-only: {e}", to.display()))?;
            }
        }
    }
    for dir in READ_ONLY_IN_ZONES {
        let dir = home.join(dir);
        if !dir_there(&dir)? {
            continue;
        }
        sys::mount(dir.as_os_str(), &dir, "", libc::MS_BIND | libc::MS_REC, "")
            .and_then(|()| sys::remount_read_only(&dir))
            .map_err(|e| format!("cannot make {} read-only: {e}", dir.display()))?;
    }
    Ok(())
}

/// Is there a directory to cover? Only "no such thing" is a no: a path that
/// cannot be looked at — a home of 0700 to a process with no capability to
/// pass it — is one nobody knows is not there, and a cover skipped for it
/// is the state in sight of whoever can look (review 2026-09-27: the system
/// tier's command, the user once it is theirs).
pub(crate) fn dir_there(path: &Path) -> Result<bool, String> {
    match fs::metadata(path) {
        Ok(meta) => Ok(meta.is_dir()),
        // Nothing there, or a file where a directory would be on the way:
        // no directory, surely.
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                || e.raw_os_error() == Some(libc::ENOTDIR) =>
        {
            Ok(false)
        }
        Err(e) => Err(format!("cannot look at {}: {e}", path.display())),
    }
}

/// Wait for the app namespace to say it exists.
fn wait_for_app_namespace(zone_up_r: OwnedFd) -> Result<(), String> {
    let mut zone_up = File::from(zone_up_r);
    let mut byte = [0u8; 1];
    if zone_up.read_exact(&mut byte).is_err() || byte[0] != SYNC_OK {
        return Err("the app namespace never came up".to_string());
    }
    Ok(())
}

/// Wait for pasta to create and configure its interface in this namespace,
/// then see that it did: the link up and a default route through it.
///
/// The byte that says which backend it is comes once pasta has said it is
/// done — the holder's own pasta ([`PastaWord`]), or a system zone's, done
/// before the service answered — so the route is looked at once: pasta done
/// without one is a failure now, not a wait for ever.
fn wait_for_pasta_link(zone: &Zone) -> Result<(), String> {
    let route =
        tool_output(&zone.tools.ip, &["-4", "route", "show", "default"]).unwrap_or_default();
    let route6 =
        tool_output(&zone.tools.ip, &["-6", "route", "show", "default"]).unwrap_or_default();
    let through = |text: &str| {
        text.lines()
            .map(parse_default_route)
            .any(|r| r.dev.as_deref() == Some(TUN_IFACE))
    };
    if through(&route) || through(&route6) {
        return Ok(());
    }
    Err(format!(
        "pasta brought up {TUN_IFACE} with no default route through it — is the host's interface \
         up, with a route?"
    ))
}

/// Ask the system-zone service for the way out through `system`
/// (docs/SYSTEM.md §7b). The asking is done by our own binary, `system-uplink`,
/// which then holds the connection for as long as it runs: its first line
/// says whether the way out is there, and with it the system zone's resolvers.
fn start_system_uplink(system: &str, zone_pid: i32) -> Result<(Child, Vec<String>), String> {
    let mut child = Command::new("/proc/self/exe")
        .arg("system-uplink")
        .arg(system)
        .arg(zone_pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start the watcher: {e}"))?;
    let mut line = String::new();
    if let Some(out) = child.stdout.take() {
        let _ = BufReader::new(out).read_line(&mut line);
    }
    let line = line.trim_end();
    if let Some(resolvers) = line.strip_prefix("OK") {
        return Ok((
            child,
            resolvers.split_whitespace().map(str::to_owned).collect(),
        ));
    }
    let _ = child.kill();
    let _ = child.wait();
    Err(line
        .strip_prefix("ERR ")
        .unwrap_or("the watcher said nothing")
        .to_owned())
}

/// Hand the app namespace the one byte that says which backend built the
/// tunnel it is now looking at.
fn tell_the_zone(moved_w: OwnedFd, tool: u8) -> Result<(), String> {
    let mut moved = File::from(moved_w);
    moved
        .write_all(&[tool])
        .map_err(|e| format!("cannot tell the zone about the tunnel: {e}"))
}

/// The one directory the OpenConnect client may write, in the uplink's own
/// `/tmp` (a tmpfs of this mount namespace that only uid 0 writes): where its
/// script writes the plan, and its `$HOME`.
const CLIENT_DIR: &str = "/tmp/openconnect";

/// Most a plan may take. A real one is a few lines; this is only a bound on
/// what the client can make the uplink read.
const PLAN_MAX: u64 = 64 * 1024;

/// Make [`CLIENT_DIR`], the client's and nobody else's.
fn client_dir() -> Result<PathBuf, String> {
    use std::os::unix::fs::DirBuilderExt;
    let dir = PathBuf::from(CLIENT_DIR);
    // Not recursive: the /tmp under it was mounted a moment ago, so a
    // directory that is already there is something else's.
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| format!("cannot make {CLIENT_DIR} for the client: {e}"))?;
    std::os::unix::fs::chown(&dir, Some(CLIENT_ID), Some(CLIENT_ID))
        .map_err(|e| format!("cannot give {CLIENT_DIR} to the client: {e}"))?;
    Ok(dir)
}

/// Make the tunnel's tun here, persistent and owned by [`CLIENT_ID`], for the
/// client to attach to.
///
/// Making a tun asks for CAP_NET_ADMIN over this namespace, which the client
/// does not have; ATTACHING to one that exists asks only that the caller be
/// its owner (`tun_not_capable`, drivers/net/tun.c). So uid 0 makes the device
/// and gives it away, and `openconnect --interface awg0` finds it by name: its
/// `TUNSETIFF` attaches instead of creating. Persistent, so that closing this
/// descriptor does not take the device away before the client has one of its
/// own.
///
/// Persistence costs nothing the zone relies on. The device goes with the
/// namespace it ends up in, as every device of a kind that can be deleted does.
/// Without the client's queue it takes packets and drops them, so a client
/// that dies leaves the app namespace a route into nothing, and the zone goes
/// down behind it anyway ([`uplink_main`]). And nothing else can attach to it:
/// in the app namespace nobody is its owner or has capabilities there.
fn tun_for_the_client() -> Result<(), String> {
    use std::os::fd::AsRawFd;
    let tun = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .map_err(|e| format!("cannot open /dev/net/tun: {e}"))?;
    // SAFETY: an all-zero ifreq is a valid one: an empty name, no flags.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (to, from) in req.ifr_name.iter_mut().zip(TUN_IFACE.bytes()) {
        *to = from as libc::c_char;
    }
    req.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
    let fd = tun.as_raw_fd();
    let done = |what: &str, rc: libc::c_int| {
        if rc < 0 {
            Err(format!(
                "cannot make {TUN_IFACE} for the client ({what}): {}",
                io::Error::last_os_error()
            ))
        } else {
            Ok(())
        }
    };
    // SAFETY: TUNSETIFF reads the ifreq and writes the name back into it; it
    // lives past the call. The other two take plain integers.
    done("TUNSETIFF", unsafe {
        libc::ioctl(fd, libc::TUNSETIFF, std::ptr::from_mut(&mut req))
    })?;
    done("TUNSETOWNER", unsafe {
        libc::ioctl(fd, libc::TUNSETOWNER, libc::c_ulong::from(CLIENT_ID))
    })?;
    let on: libc::c_ulong = 1;
    done("TUNSETPERSIST", unsafe {
        libc::ioctl(fd, libc::TUNSETPERSIST, on)
    })
}

/// Whether a program at `path` can be run by an id that owns none of the
/// directories on the way: each one searchable by others, the file executable
/// by them. The client's `--script` is this binary, and the client has no
/// other way to reach it.
fn runnable_by_anyone(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let searchable = path
        .ancestors()
        .skip(1)
        .filter(|dir| !dir.as_os_str().is_empty())
        .all(|dir| fs::metadata(dir).is_ok_and(|m| m.mode() & 0o001 != 0));
    searchable && fs::metadata(path).is_ok_and(|m| m.mode() & 0o001 != 0)
}

/// Where the client's root is put together: a directory in the uplink's own
/// /tmp, which the client's mount namespace makes a tmpfs of and moves into.
const CLIENT_ROOT: &str = "/tmp/openconnect-root";

/// Trees of the host the client's root takes whole, where the host has them:
/// the store, the system's own programs and libraries (what `/bin/sh` and a
/// distribution's `openconnect` need on a host that is not NixOS), and the
/// places a system CA store lives. One that is a link (`/bin` → `usr/bin` on a
/// merged-/usr system, `/etc/static` on NixOS) is made the same link there.
const CLIENT_ROOT_TREES: [&str; 12] = [
    "/nix/store",
    "/bin",
    "/sbin",
    "/usr",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/etc/ssl",
    "/etc/pki",
    "/etc/ca-certificates",
    "/etc/static",
];

/// The device nodes the client has: the basics, and the tun it attaches to.
const CLIENT_DEVICES: [&str; 6] = [
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
    "/dev/net/tun",
];

/// One step of putting the client's root together, each a single system call
/// on paths made beforehand: between fork and exec nothing may be allocated.
enum RootStep {
    Dir(CString),
    /// An empty file, for a file to be bound onto.
    File(CString),
    Link {
        target: CString,
        at: CString,
    },
    Bind {
        from: CString,
        to: CString,
    },
}

/// The client's root, planned: what [`enter_client_root`] does in the child.
struct ClientRoot {
    root: CString,
    steps: Vec<RootStep>,
    /// Where the client starts: its own directory.
    home: CString,
    dot: CString,
    slash: CString,
}

fn c_path(path: &Path) -> Result<CString, String> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("{} has a NUL in it", path.display()))
}

/// Plan the client's root: EMPTY, and then only what the client needs — the
/// trees of [`CLIENT_ROOT_TREES`], the devices of [`CLIENT_DEVICES`], its
/// directory `dir`, and `files` (the programs it runs and the CA files it is
/// named, by their real paths) where no tree already holds them.
///
/// This is the other way round from every other mount namespace of a zone,
/// and on purpose (review 2026-09-27, second opinion): those are a copy of
/// the host with what is known to be dangerous covered, and each daemon a host
/// adds is in reach until somebody notices — the uplink had the Nix daemon in
/// reach of the client that way. Here what is not named is not there: no
/// `/home`, no `/run`, no `/var`, no `/proc`, no socket of anybody's.
fn client_root(root: &Path, dir: &Path, files: &[PathBuf]) -> Result<ClientRoot, String> {
    use std::collections::BTreeSet;
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .mode(0o755)
        .create(root)
        .map_err(|e| format!("cannot make {}: {e}", root.display()))?;
    let inside = |path: &Path| root.join(path.strip_prefix("/").unwrap_or(path));

    let mut steps = Vec::new();
    let mut made: BTreeSet<PathBuf> = BTreeSet::new();
    // Every directory above `path` in the root, top down, each once.
    let mut parents = |path: &Path, steps: &mut Vec<RootStep>| -> Result<(), String> {
        let mut above: Vec<&Path> = path.ancestors().skip(1).collect();
        above.reverse();
        for dir in above {
            if dir == Path::new("/") || !made.insert(dir.to_path_buf()) {
                continue;
            }
            steps.push(RootStep::Dir(c_path(&inside(dir))?));
        }
        Ok(())
    };

    let mut trees: Vec<&Path> = Vec::new();
    for tree in CLIENT_ROOT_TREES.map(Path::new) {
        let Ok(meta) = fs::symlink_metadata(tree) else {
            continue;
        };
        parents(tree, &mut steps)?;
        if meta.file_type().is_symlink() {
            let target = fs::read_link(tree)
                .map_err(|e| format!("cannot read the link {}: {e}", tree.display()))?;
            steps.push(RootStep::Link {
                target: c_path(&target)?,
                at: c_path(&inside(tree))?,
            });
        } else if meta.is_dir() {
            steps.push(RootStep::Dir(c_path(&inside(tree))?));
            steps.push(RootStep::Bind {
                from: c_path(tree)?,
                to: c_path(&inside(tree))?,
            });
            trees.push(tree);
        }
    }
    for device in CLIENT_DEVICES.map(Path::new) {
        if fs::symlink_metadata(device).is_err() {
            continue;
        }
        parents(device, &mut steps)?;
        steps.push(RootStep::File(c_path(&inside(device))?));
        steps.push(RootStep::Bind {
            from: c_path(device)?,
            to: c_path(&inside(device))?,
        });
    }
    parents(dir, &mut steps)?;
    steps.push(RootStep::Dir(c_path(&inside(dir))?));
    steps.push(RootStep::Bind {
        from: c_path(dir)?,
        to: c_path(&inside(dir))?,
    });
    for file in files {
        if trees.iter().any(|tree| file.starts_with(tree)) {
            continue;
        }
        parents(file, &mut steps)?;
        steps.push(RootStep::File(c_path(&inside(file))?));
        steps.push(RootStep::Bind {
            from: c_path(file)?,
            to: c_path(&inside(file))?,
        });
    }
    Ok(ClientRoot {
        root: c_path(root)?,
        steps,
        home: c_path(dir)?,
        dot: c_path(Path::new("."))?,
        slash: c_path(Path::new("/"))?,
    })
}

/// Say on stderr which step of the client's root failed: the error itself
/// comes back to the uplink as a bare errno. Only `write(2)`, as between fork
/// and exec it must be.
///
/// # Safety
/// Between fork and exec: touches nothing but fd 2.
unsafe fn root_failed(what: &[u8], path: &CStr) {
    let prefix = b"openconnect client root: ";
    let path = path.to_bytes();
    let parts: [&[u8]; 5] = [prefix, what, b" ", path, b"\n"];
    for part in parts {
        libc::write(2, part.as_ptr().cast(), part.len());
    }
}

/// Move into the client's root: a mount namespace of its own, a tmpfs, the
/// planned steps, `pivot_root`, the old root let go of, and the client's own
/// directory as the working one. Runs as uid 0 of the zone, before the client
/// becomes its own id. Nothing here allocates.
///
/// # Safety
/// Between fork and exec in a child that is still uid 0 of the zone.
unsafe fn enter_client_root(root: &ClientRoot) -> io::Result<()> {
    let fail = |what: &[u8], path: &CStr| {
        let e = io::Error::last_os_error();
        root_failed(what, path);
        Err(e)
    };
    if libc::unshare(libc::CLONE_NEWNS) != 0 {
        return fail(b"unshare", &root.root);
    }
    let tmpfs = b"tmpfs\0";
    let options = b"mode=0755,size=1m\0";
    if libc::mount(
        tmpfs.as_ptr().cast(),
        root.root.as_ptr(),
        tmpfs.as_ptr().cast(),
        libc::MS_NOSUID | libc::MS_NODEV,
        options.as_ptr().cast(),
    ) != 0
    {
        return fail(b"tmpfs", &root.root);
    }
    for step in &root.steps {
        match step {
            RootStep::Dir(path) => {
                if libc::mkdir(path.as_ptr(), 0o755) != 0 {
                    return fail(b"mkdir", path);
                }
            }
            RootStep::File(path) => {
                let fd = libc::open(
                    path.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                    0o644,
                );
                if fd < 0 {
                    return fail(b"create", path);
                }
                libc::close(fd);
            }
            RootStep::Link { target, at } => {
                if libc::symlink(target.as_ptr(), at.as_ptr()) != 0 {
                    return fail(b"symlink", at);
                }
            }
            RootStep::Bind { from, to } => {
                if libc::mount(
                    from.as_ptr(),
                    to.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND | libc::MS_REC,
                    std::ptr::null(),
                ) != 0
                {
                    return fail(b"bind", from);
                }
            }
        }
    }
    // pivot_root(".", "."): the old root ends up mounted over the new one and
    // is let go of at once (pivot_root(2), the runc way). Then the working
    // directory is set anew: one left in the old tree would keep all of it
    // in reach through "..".
    if libc::chdir(root.root.as_ptr()) != 0 {
        return fail(b"chdir", &root.root);
    }
    if libc::syscall(libc::SYS_pivot_root, root.dot.as_ptr(), root.dot.as_ptr()) != 0 {
        return fail(b"pivot_root", &root.root);
    }
    if libc::umount2(root.dot.as_ptr(), libc::MNT_DETACH) != 0 {
        return fail(b"umount", &root.dot);
    }
    if libc::chdir(root.slash.as_ptr()) != 0 || libc::chdir(root.home.as_ptr()) != 0 {
        return fail(b"chdir", &root.home);
    }
    Ok(())
}

/// The real path of a program named by path or found on `PATH`, as the
/// client's root holds it.
fn real_program(program: &Path) -> Result<PathBuf, String> {
    let found = if program.components().count() > 1 {
        Some(program.to_path_buf())
    } else {
        std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join(program))
                .find(|candidate| candidate.is_file())
        })
    };
    let found = found.ok_or_else(|| {
        format!(
            "{} is not there — an [OpenConnect] zone needs the openconnect client",
            program.display()
        )
    })?;
    fs::canonicalize(&found).map_err(|e| format!("cannot find {}: {e}", found.display()))
}

/// Start the OpenConnect client in the uplink namespace.
///
/// Every argument here is either forced or checked, and that is the point: the
/// user's config can add flags only from an allowlist
/// ([`crate::openconnect`]), and the ones that decide where the tunnel ends up
/// are ours.
///
/// * `--script` is this very binary. Replacing it would replace the only thing
///   that puts the interface behind the wall, which is why `Args =` cannot
///   name it.
/// * `--interface awg0` gives every zone one interface name, so that the app
///   namespace's `oifname "awg0" accept` — loaded long before the tunnel
///   arrives — keeps meaning what it says.
/// * `--non-inter` because a zone is started by a systemd unit and there is no
///   terminal to ask anything on; a prompt would hang the zone instead of
///   failing it.
/// * `--no-external-auth` so that authentication never tries to open a browser
///   OUTSIDE the zone — the exact move `docs/LEAK-MODEL.md` spends a section on.
/// * No `--disable-ipv6` (it was there until 2026-09-27): IPv6 the gateway
///   gives goes into the tunnel like IPv4, and without it the app namespace
///   closes the family (`configure_oc`). The client's own transport is IPv4 —
///   `--resolve` names the gateway by the address resolved above.
/// * `--resolve` hands over the address resolved in the host's network, so the
///   client never needs a resolver in a namespace that has none.
/// * `--passwd-on-stdin` with the password written on one line and the pipe
///   closed. Not a command-line argument: `/proc/<pid>/cmdline` is world
///   readable, and not an environment variable either, for the same reason.
///
/// And the environment is BUILT rather than inherited
/// ([`crate::openconnect::client_env`]): `openconnect` honours `https_proxy`
/// and its relatives, and a zone must not be one stray session variable away
/// from talking to somebody else.
///
/// And it runs as [`CLIENT_ID`], without a single capability: the gateway can
/// make it do whatever a subverted client does, and nothing of that reaches
/// past the tun it was given and the directory `dir`.
fn spawn_openconnect(zone: &Zone, oc: &OcZone, dir: &Path) -> Result<Child, String> {
    let cfg = &oc.cfg;
    let password = cfg.read_password().map_err(|e| format!("{CONFIG}: {e}"))?;

    // `openconnect` runs its `--script` through `/bin/sh -c`, so the string is
    // shell-parsed. Store paths never contain anything a shell would look at,
    // but a hand-run holder might, and a mangled script is a tunnel nobody
    // moves anywhere.
    let exe = std::env::current_exe()
        .map_err(|e| format!("cannot find my own path for --script: {e}"))?;
    let exe = exe.to_str().ok_or_else(|| {
        "my own path is not UTF-8, and openconnect's --script goes through a shell".to_string()
    })?;
    if exe.contains(|c: char| c.is_whitespace() || "'\"\\$`;&|<>()*?[]{}#~!".contains(c)) {
        return Err(format!(
            "my own path ({exe}) has shell characters in it, and openconnect's --script is \
             shell-parsed"
        ));
    }
    // A holder run by hand out of a home directory: the client, an id of its
    // own, could not run its script, and every connection would fail at the
    // last step. Said now, and plainly.
    if !runnable_by_anyone(Path::new(exe)) {
        return Err(format!(
            "the openconnect client runs as an id of its own, and it cannot run {exe} as its \
             --script: every directory on the way has to be searchable by others"
        ));
    }

    // By their real paths: the client's root holds the trees they live in, or
    // the files themselves, and nothing it would find on a PATH.
    let program = real_program(&zone.tools.openconnect)?;
    let mut cmd = Command::new(&program);
    cmd.arg(format!("--protocol={}", cfg.protocol))
        .arg("--interface")
        .arg(TUN_IFACE)
        .arg("--script")
        .arg(format!("{exe} oc-script"))
        .arg("--non-inter")
        .arg("--no-external-auth");
    if cfg.server_literal().is_none() {
        cmd.arg(format!("--resolve={}:{}", cfg.server, oc.addr));
    }
    if let Some(pin) = &cfg.server_cert {
        cmd.arg(format!("--servercert={pin}"));
    }
    if let Some(user) = &cfg.user {
        cmd.arg(format!("--user={user}"));
    }
    if let Some(group) = &cfg.authgroup {
        cmd.arg(format!("--authgroup={group}"));
    }
    if password.is_some() {
        cmd.arg("--passwd-on-stdin");
    }
    for extra in &cfg.extra {
        cmd.arg(extra);
    }
    cmd.arg(cfg.server_arg());

    // THE CLIENT STARTS WITH AN EMPTY ENVIRONMENT, not with ours. `openconnect`
    // honours `https_proxy` and its relatives, so an environment carried in
    // from the user's session could point the client at a proxy instead of at
    // the gateway; the uplink's filter would drop that packet, but a zone
    // should not have to be rescued by its second echelon from its own
    // start-up. What survives, and why, is `openconnect::CLIENT_ENV_KEPT`; the
    // rest is what the script needs and nobody else sets.
    let mut env = openconnect::client_env(std::env::vars_os(), dir, cfg.mtu);
    // The CA files by their real paths too: `/etc/ssl/certs/…` on NixOS and
    // `/nix/var/nix/profiles/…` under a Nix installed elsewhere are links, and
    // the client's root has no `/nix/var`.
    let mut files = vec![program.clone(), PathBuf::from(exe)];
    for (key, value) in &mut env {
        if !["SSL_CERT_FILE", "NIX_SSL_CERT_FILE"]
            .iter()
            .any(|name| key.as_os_str() == OsStr::new(name))
        {
            continue;
        }
        if let Ok(real) = fs::canonicalize(value.as_os_str()) {
            *value = real.clone().into_os_string();
            files.push(real);
        }
    }
    cmd.env_clear().envs(env);
    let root = client_root(Path::new(CLIENT_ROOT), dir, &files)?;
    cmd.stdin(if password.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });

    // And the sandbox's blocklist of syscalls, nested user namespaces
    // included: the client builds no sandbox of its own, and a user namespace
    // of its own is the one place it could hold capabilities again — over
    // nothing of the zone's, but it is kernel surface the client has no use
    // for. Built here; loaded in the child, where nothing may be allocated.
    // No filter, no client: this is the part of the zone a gateway talks to.
    let filter = seccomp::Filter::build(seccomp::FilterOptions { deny_userns: true })
        .and_then(|f| f.instructions())
        .map_err(|e| format!("cannot build the client's seccomp filter: {e}"))?;
    let filter_len = u16::try_from(filter.len())
        .map_err(|_| "the client's seccomp filter is too long to load".to_string())?;
    // And the socket families of a network namespace only: vsock would be a
    // way past the uplink's filter, which sees none of it.
    let families = seccomp::Filter::zone_sockets()
        .and_then(|f| f.instructions())
        .map_err(|e| format!("cannot build the client's socket filter: {e}"))?;
    let families_len = u16::try_from(families.len())
        .map_err(|_| "the client's socket filter is too long to load".to_string())?;

    // SAFETY: getpid(2) takes no arguments and cannot fail.
    let uplink = unsafe { libc::getpid() };
    // SAFETY: pre_exec runs between fork and execve in the child; every call
    // here takes plain integers, a null pointer or a pointer to memory that
    // lives through the call, allocates nothing and is async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            // WHAT THE CLIENT SEES: a root of its own, with nothing in it but
            // what it needs (`client_root`). Done while still uid 0: mounts
            // want the zone's capabilities, which go with the change of ids.
            enter_client_root(&root)?;
            // WHO THE CLIENT IS: `CLIENT_ID`, with no supplementary groups —
            // the user's groups of the host would still open what they open —
            // and, by the kernel's rule for a uid that leaves 0, with no
            // capabilities left. Each step checked: a client that stayed uid 0
            // is the zone's namespaces in a gateway's hands.
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setresgid(CLIENT_ID, CLIENT_ID, CLIENT_ID) != 0
                || libc::setresuid(CLIENT_ID, CLIENT_ID, CLIENT_ID) != 0
            {
                return Err(io::Error::last_os_error());
            }
            // Nor any way back up through something setuid or file-capable.
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            // THE CLIENT MUST NOT OUTLIVE THIS PROCESS. The uplink is killed
            // with a plain signal and its default disposition, so no handler of
            // ours runs on the way out; without this the client would go on
            // holding the uplink namespace open, with a live VPN session in
            // it, after the zone is gone. After the change of ids, which
            // clears it; and an uplink already gone is no uplink to follow.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != uplink {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            // Last: the filter holds from here to the client's end, and
            // no_new_privs above is what lets an unprivileged process load it.
            let program = libc::sock_fprog {
                len: filter_len,
                filter: filter.as_ptr().cast_mut(),
            };
            if libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                std::ptr::from_ref(&program),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            let program = libc::sock_fprog {
                len: families_len,
                filter: families.as_ptr().cast_mut(),
            };
            if libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                std::ptr::from_ref(&program),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            format!(
                "{} is not there — an [OpenConnect] zone needs the openconnect client",
                zone.tools.openconnect.display()
            )
        } else {
            // Also what a failed change of ids says: the zone's user namespace
            // without the client's id in it.
            format!(
                "cannot run {} as the client's own id: {e}",
                zone.tools.openconnect.display()
            )
        }
    })?;
    if let Some(password) = password {
        let Some(mut stdin) = child.stdin.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("openconnect was given no stdin to read the password from".to_string());
        };
        // One line, then EOF: `--non-inter` means nothing else will be asked.
        let written = stdin
            .write_all(password.as_bytes())
            .and_then(|()| stdin.write_all(b"\n"));
        drop(stdin);
        if let Err(e) = written {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("cannot hand the password to openconnect: {e}"));
        }
    }
    Ok(child)
}

/// Wait for the client's script to say the tunnel is up, and read what it
/// wrote.
///
/// The plan file appearing IS the report — the script writes it by rename, so
/// a reader sees the whole file or none of it. The wait ends early if the
/// client dies, which is the ordinary failure: a wrong password, a refused
/// certificate, an unreachable gateway. Otherwise as long as it takes — no
/// clock: a corporate gateway with a slow authentication step is ordinary, and
/// giving up on a connection that was about to succeed costs the user the zone
/// (this was two minutes). A client that hangs is ended by stopping the zone.
fn wait_for_plan(dir: &Path, client: &mut Child) -> Result<openconnect::Plan, String> {
    let path = dir.join(openconnect::PLAN_FILE);
    if sys::wait_for_child_entry(&path, client, Path::exists) {
        return read_plan(&path);
    }
    match client.wait() {
        Ok(status) => Err(format!(
            "openconnect exited ({status}) before the tunnel was up — the messages above are \
             its own"
        )),
        Err(e) => Err(format!("cannot check on openconnect: {e}")),
    }
}

/// The plan as the client's script wrote it, read as something the client
/// wrote: no link followed, nothing but a regular file, not much of it, and
/// nothing it cannot say as a [`openconnect::Plan`].
fn read_plan(path: &Path) -> Result<openconnect::Plan, String> {
    let file = fs::OpenOptions::new()
        .read(true)
        // A fifo would hold the uplink up for as long as the client liked.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("cannot open the client's plan {}: {e}", path.display()))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot look at the client's plan: {e}"))?;
    if !meta.is_file() || meta.len() > PLAN_MAX {
        return Err(format!(
            "the client's plan {} is not a plan-sized file",
            path.display()
        ));
    }
    let mut text = String::new();
    file.take(PLAN_MAX)
        .read_to_string(&mut text)
        .map_err(|e| format!("cannot read the client's plan: {e}"))?;
    openconnect::Plan::parse(&text)
}

/// Move the tunnel into the app namespace, then give the app namespace the
/// plan.
///
/// The ORDER is the whole of it: the app namespace configures the interface
/// from the plan the moment [`tell_the_zone`] wakes it, so the interface has to
/// be down there first. And the plan it gets is the one parsed here, written
/// anew — the client's file itself never reaches it. The write is a rename over
/// a temporary file: a reader sees the whole file or none of it.
fn hand_over(zone: &Zone, zone_pid: libc::pid_t, plan: &openconnect::Plan) -> Result<(), String> {
    // The move names the device this uplink made, whatever the plan says; a
    // plan about another one is a client that did not attach to it.
    if plan.iface != TUN_IFACE {
        return Err(format!(
            "the client reports {} and not the {TUN_IFACE} made for it",
            plan.iface
        ));
    }
    // A host pid, as on the WireGuard path.
    let target = zone_pid.to_string();
    zone.ip(&["link", "set", TUN_IFACE, "netns", target.as_str()])?;

    let path = zone.path(openconnect::PLAN_FILE);
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, plan.to_text())
        .and_then(|()| fs::rename(&tmp, &path))
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    println!(
        "zone {}: {TUN_IFACE} moved into the app namespace, address {}, mtu {}",
        zone.name(),
        plan.address,
        plan.mtu
    );
    Ok(())
}

/// Create the tunnel interface; the answer says which tool configures it.
///
/// The ordinary path is the kernel amneziawg module (it understands plain
/// WireGuard configs too). No module (a system without Amnezia, CI): a config
/// WITHOUT obfuscation parameters is carried by the in-tree wireguard module and
/// `wg`; with them we fail loudly — such a tunnel cannot be built without the
/// module, and degrading silently would be a lie.
fn create_tunnel(zone: &Zone, cfg: &WgConfig) -> Result<u8, String> {
    if zone
        .ip_quiet(&["link", "add", TUN_IFACE, "type", "amneziawg"])
        .is_ok()
    {
        return Ok(TOOL_AWG);
    }
    if cfg.is_obfuscated() {
        return Err(
            "the amneziawg module is unavailable and an obfuscated config cannot be carried \
             without it"
                .to_string(),
        );
    }
    zone.ip(&["link", "add", TUN_IFACE, "type", "wireguard"])?;
    println!(
        "zone {}: no amneziawg module — using the in-tree wireguard",
        zone.name()
    );
    Ok(TOOL_WG)
}

// --- PROCESS 4: THE APP NAMESPACE --------------------------------------------

/// The namespace programs run in: lo, the tunnel, and nothing else ever.
fn zone_main(zone: &Zone, links: Option<ZoneLinks<'_>>) -> u8 {
    default_signals();
    if let Err(e) = zone_setup(zone, links) {
        eprintln!("zone {}: {e}", zone.name());
        return 1;
    }
    park()
}

/// Hold the namespace until somebody kills us. The zone dies with this process,
/// which is exactly what makes it a kill switch.
fn park() -> ! {
    loop {
        // SAFETY: pause(2) takes no arguments; TERM and INT are left at their
        // default action, so this really is "until killed".
        unsafe { libc::pause() };
    }
}

fn zone_setup(zone: &Zone, links: Option<ZoneLinks<'_>>) -> Result<(), String> {
    // An IPC namespace too (review 2026-09-27): System V shared memory and
    // message queues go by number, and the zone's programs are the user's
    // uid — an X client's MIT-SHM segment on the host, the pixels of its
    // windows, was one `shmat` away. An instance's space is in them already
    // (stage 3): its pid 1 made them, and mounted the pid namespace's
    // `/proc` in the mount namespace before it forked this process
    // (`crate::init`).
    // SAFETY: unshare(2) takes no pointers.
    if zone.instance.is_none()
        && unsafe { libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWNS | libc::CLONE_NEWIPC) }
            != 0
    {
        return Err(format!(
            "cannot create the net+mount+IPC namespace: {}",
            io::Error::last_os_error()
        ));
    }
    // Private propagation, or every mount below (resolv.conf, the tmpfs over
    // nscd) would travel back to the host.
    sys::mount(
        OsStr::new("none"),
        Path::new("/"),
        "",
        libc::MS_REC | libc::MS_PRIVATE,
        "",
    )
    .map_err(|e| format!("cannot make the mount tree private: {e}"))?;

    // Only now: the file's appearance means "the namespaces exist", and this is
    // the number `vpn-zone run`/`status` enter by. An instance's is its pid
    // 1's host pid, written by its holder (`instance.pid`, stage 3): this
    // process's own number is its pid namespace's, which no reader of the
    // instance's directory shares.
    if zone.instance.is_none() {
        // SAFETY: getpid(2) takes no arguments and cannot fail.
        let pid = unsafe { libc::getpid() };
        // The start time first: whoever sees the new number sees its start too.
        let stamp = sys::process_stamp(pid).ok_or("cannot read our own start time")?;
        fs::write(zone.path(START), format!("{stamp}\n"))
            .map_err(|e| format!("cannot write {START}: {e}"))?;
        fs::write(zone.path(PID), format!("{pid}\n"))
            .map_err(|e| format!("cannot write {PID}: {e}"))?;
    }
    // Which build runs the zone: an update leaves it running (keep-old), and
    // status/doctor/watch tell the person it is left on the previous one.
    crate::build::record(&zone.dir);
    zone.ip(&["link", "set", "lo", "up"])?;
    allow_ping(zone);

    // BEFORE the offline branch, and deliberately so: an "offline" zone that
    // still sees the host's resolver sockets is not offline at all. A program
    // in it cannot open a connection, but it can have any name looked up by a
    // daemon in the HOST's network — which tells the outside world what it is
    // looking for and carries out with it anything that can be spelled into a
    // hostname. The policy "an unknown program gets no network" is only true
    // once these are gone.
    // The system's own services under /run first — before the resolvers,
    // whose directory is below /run/systemd.
    seal_run().map_err(|e| format!("zone {}: {e}", zone.name()))?;
    hide_host_resolvers(zone)?;
    // The space's `/etc` a shared mount of its own before anything is laid
    // in it (`crate::rebind`, D2): its own `nsswitch.conf` and `resolv.conf`,
    // laid there again when the host replaces them, reach every launch's
    // copy. Not fatal: without it a re-lay reaches the space and the
    // launches made after it, and one before goes on with the host's file —
    // names still only through the tunnel.
    if let Err(e) = crate::rebind::share(Path::new("/etc")) {
        eprintln!(
            "zone {}: /etc not shared with its launches ({e}) — a resolv.conf the host \
             replaces is laid again for the launches made after it only",
            zone.name()
        );
    }
    // The same hole closed as a class rather than by a list of sockets.
    // Kept over the name from the end of the setup (`rebind::keep`).
    let mut owns: Vec<crate::rebind::Own> = own_nsswitch(zone).into_iter().collect();
    // resolve1 is on the system bus too, and NetworkManager tells a program
    // which networks the machine is really on.
    seal_system_bus(zone)?;
    // A hermetic zone's session bus through the filter that answers the
    // portal's OpenURI — started in here, in the zone, before the runtime
    // directory binds its socket in.
    if zone.hermetic {
        start_session_filter(zone);
    }
    // Every zone: no compositor socket and no compositor IPC; a hermetic one
    // also no systemd --user and no whole session bus, and the broker.
    seal_runtime(zone)?;
    // A hermetic zone's temporary directories are its own: the host's /tmp
    // holds listening sockets nobody meant for a zone — a tmux server, whose
    // `run-shell` runs on the host, a VPN client's IPC to a root service — and
    // the filters of other zones' sandboxes. BEFORE the X11 tmpfs, which then
    // lands inside the new /tmp.
    if zone.hermetic {
        private_tmp(zone)?;
    }
    // One X server shows every client everything: the host's is out of reach,
    // and so are the X servers of other zones — /tmp is shared, this tmpfs
    // is not. A container with the x11 permission runs its own satellite, and
    // its socket lands in here.
    hide_x11(zone)?;
    own_dev(zone)?;
    // The system tier's directory, with its root service's socket: a helper
    // outside that acts for whoever asks. A zone through a system zone keeps
    // that zone's status, through a descriptor opened before it goes.
    // Kept open for good: this process holds the zone until it dies.
    let system_status: Option<RawFd> = match links.as_ref().map(|l| l.backend) {
        Some(Backend::SysZone(sys)) => {
            File::open(Path::new(crate::system::RUN_DIR).join(&sys.zone))
                .ok()
                .map(IntoRawFd::into_raw_fd)
        }
        _ => None,
    };
    hide_system_tier(zone)?;
    if !zone.nix_daemon {
        hide_nix_daemon(zone)?;
    }
    hide_input_methods(zone)?;
    if zone.hermetic && !zone.host_files_writable {
        protect_host_files(zone)?;
    }
    // The project's own state, last among the covers: from here on the zone's
    // directory is reached through a descriptor.
    let zone = &hide_project_state(zone)?;
    hide_container_storage(zone)?;
    if zone.instance.is_some() {
        cover_cgroupfs(zone)?;
    }

    let Some(ZoneLinks {
        backend,
        ready_w,
        moved_r,
        first,
        config_seed,
    }) = links
    else {
        // An offline zone gets no rules, and needs none: loopback is the only
        // interface there will ever be, and `oifname "lo" accept` over an empty
        // namespace would say nothing that the empty namespace does not.
        //
        // Nor does it get a resolv.conf of its own: with the sockets above
        // hidden, whatever the host's file names is unreachable from a
        // namespace that has only loopback, and a name here simply does not
        // resolve. Which is what offline has to mean.
        //
        // A container's instance (stage 2 of the container design): no rules
        // here either — its relay loads them with each attach
        // (`crate::relay`) —, and with a zone for its network the ground its
        // taps stand on ([`instance_ground`]). `ready` is its keeper's to
        // write, once its way out is attached: this says the space is set up.
        if let Some(instance) = &zone.instance {
            // Every instance since stage 4, an offline one too: its network
            // can be switched live to a zone, and its programs find the
            // ground a zone's taps stand on — the constant forwarders in
            // the file they read, the unreachable defaults.
            owns.push(instance_ground(zone)?);
            if let Err(e) = note_network_inside(zone) {
                eprintln!(
                    "instance {}: its programs cannot read which network it is in ({e})",
                    zone.name()
                );
            }
            // Its files kept over the host's names (D2) before a launch can
            // come: the space is ready once this is said.
            crate::rebind::keep(format!("instance {}", zone.name()), owns);
            let done = zone.path(crate::instance::SPACE_READY);
            touch(&done).map_err(|e| format!("cannot create {}: {e}", done.display()))?;
            println!(
                "instance {}: its space is set up (network {})",
                zone.name(),
                instance.network
            );
            return Ok(());
        }
        crate::rebind::keep(format!("zone {}", zone.name()), owns);
        touch(&zone.path(READY)).map_err(|e| format!("cannot create {READY}: {e}"))?;
        println!("zone {}: no network (loopback only)", zone.name());
        return Ok(());
    };

    // --- THE SECOND ECHELON, BEFORE THE TUNNEL EVEN ARRIVES ---
    // The rule names the interface (`oifname`) and not its index, so it does not
    // need awg0 to exist yet — which is why this can go first, and why it keeps
    // working if the interface is ever recreated. Everything below is netlink
    // (setconf, addresses, routes) and runs regardless: no filter hook of the
    // `inet` family sees a netlink message.
    //
    // Today this rule has nothing to stop: the namespace has lo and the tunnel
    // and no third interface can appear in it (the programs inside hold no
    // capabilities over it). That is precisely what makes it worth having — the
    // day a change of ours puts an interface here by mistake, the packets stop
    // instead of quietly leaving through it.
    zone.seal("zone", &app_ruleset_with(&first));

    // The uplink is waiting for this before it hands the interface over.
    let mut ready = File::from(ready_w);
    ready
        .write_all(&[SYNC_OK])
        .map_err(|e| format!("cannot report the namespace to the uplink: {e}"))?;
    drop(ready);

    // --- THE TUNNEL ARRIVES ---
    // Created in the uplink and moved in here, so its transport socket stays
    // over there. Everything below runs over netlink in the CURRENT namespace,
    // which is why it has to happen after the move and not before it.
    let mut moved = File::from(moved_r);
    let mut byte = [0u8; 1];
    if moved.read_exact(&mut byte).is_err() {
        return Err("the uplink died before it could hand the tunnel over".to_string());
    }
    drop(moved);
    // Both backends end here with the same two answers: what the zone's
    // resolv.conf should say, and what its status mirror should watch. What
    // differs is only who put the address on the interface.
    let (dns, search, mirror) = match byte[0] {
        TOOL_AWG | TOOL_WG => {
            let Backend::Wg(cfg) = backend else {
                return Err(
                    "the uplink built a WireGuard tunnel for a zone that is not one".to_string(),
                );
            };
            let wgtool: &Path = if byte[0] == TOOL_AWG {
                zone.tools.awg.as_path()
            } else {
                zone.tools.wg.as_path()
            };
            configure_wg(zone, cfg, wgtool)?;
            (cfg.dns(), None, Mirror::Wg(wgtool.to_path_buf()))
        }
        TOOL_OC => {
            // The facts come from the file the uplink wrote after the move —
            // so by the time this byte arrives, the interface is already down
            // here.
            let path = zone.path(openconnect::PLAN_FILE);
            let plan = fs::read_to_string(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))
                .and_then(|text| openconnect::Plan::parse(&text))?;
            configure_oc(zone, &plan)?;
            let dns: Vec<String> = plan.dns.iter().map(ToString::to_string).collect();
            (dns, plan.search.clone(), Mirror::Oc)
        }
        TOOL_HOSTIF => {
            let Backend::HostIf(host) = backend else {
                return Err("pasta was attached to a zone that is not a host-interface one".into());
            };
            wait_for_pasta_link(zone)?;
            let dns: Vec<String> = host.dns.iter().map(ToString::to_string).collect();
            (dns, None, Mirror::HostIf(host.interface.clone()))
        }
        TOOL_SYSZONE => {
            let Backend::SysZone(sys) = backend else {
                return Err(
                    "pasta was attached to a zone that is not one through a system \
                            zone"
                        .into(),
                );
            };
            wait_for_pasta_link(zone)?;
            // Addresses only: they go into resolv.conf as they are.
            let dns: Vec<String> = fs::read_to_string(zone.path(SYS_RESOLVERS))
                .unwrap_or_default()
                .lines()
                .filter_map(|l| l.trim().parse::<IpAddr>().ok())
                .map(|ip| ip.to_string())
                .collect();
            (dns, None, Mirror::SysZone(sys.zone.clone(), system_status))
        }
        _ => return Err("the uplink could not build the tunnel".to_string()),
    };

    // --- THE ZONE'S DNS ---
    // The other half of `hide_host_resolvers`: with no daemon left to ask,
    // glibc goes to the servers named here — and they are reachable only
    // through the tunnel. The bind mount is visible inside the zone only: the
    // rest of the system keeps its own /etc/resolv.conf.
    let (text, defaulted) = resolv_conf_with_search(&dns, search.as_deref());
    if defaulted {
        println!(
            "zone {}: nobody named a resolver — taking {} (through the tunnel)",
            zone.name(),
            DEFAULT_RESOLVERS.join(" and ")
        );
    }
    fs::write(zone.path(RESOLV), &text).map_err(|e| format!("cannot write {RESOLV}: {e}"))?;
    owns.push(bind_resolv(zone)?);
    // Kept over the host's names (D2). Nothing is launched into a zone's own
    // namespaces since stage 5 — its bridge's passt is told its resolvers
    // (`--dns-host`) and reads none —, but the doctor's probe and a program
    // a previous build left here read the file: the zone's, then too.
    crate::rebind::keep(format!("zone {}", zone.name()), owns);

    // The bridge (`crate::bridge`, stage 2 of the container design of
    // 2026-09-27): what carries a container's instance out through this
    // zone. Its refusal of the zone's own addresses and its socket before
    // `ready`, so that a zone found ready carries instances — or says why
    // it does not to each that asks.
    let bridge = open_bridge(zone, &first, &text, search.as_deref(), config_seed);

    // THE PROFILE IS NOT MOUNTED HERE, AND THAT MATTERS. The first version
    // stacked the data layer right here, over the whole zone — and the profile
    // ended up welded to the VPN: set a browser up in zone "nl", have the
    // server blocked, and the environment goes away with it. The profile is now
    // a separate thing, mounted when the program starts (`crate::profile`), so
    // the same one can be used in another zone or with no VPN at all.
    touch(&zone.path(READY)).map_err(|e| format!("cannot create {READY}: {e}"))?;
    println!(
        "zone {} is up: {}",
        zone.name(),
        zone.ip_line(&["-br", "-4", "addr", "show", TUN_IFACE])
    );
    if let Some((listener, carrier)) = bridge {
        thread::spawn(move || crate::bridge::serve(listener, carrier));
    }

    start_status_mirror(zone, mirror.clone());

    match mirror {
        Mirror::Wg(wgtool) => {
            // The first handshake is the sign that a config is alive — printing
            // it to the journal answers "is this .conf still worth anything?"
            // straight away.
            thread::sleep(HANDSHAKE_AFTER);
            let handshakes =
                tool_output(&wgtool, &["show", TUN_IFACE, "latest-handshakes"]).unwrap_or_default();
            if handshake_seen(&handshakes) {
                println!("zone {}: handshake done — the tunnel is alive", zone.name());
            } else {
                eprintln!(
                    "zone {}: no handshake. Either the config is dead or the server is \
                     unreachable",
                    zone.name()
                );
            }
        }
        Mirror::HostIf(interface) => {
            println!(
                "zone {}: going out through the host's interface {interface}",
                zone.name()
            );
        }
        Mirror::SysZone(system, _) => {
            println!(
                "zone {}: going out through the tunnel of the system zone {system}",
                zone.name()
            );
        }
        Mirror::Oc => {
            // The same question, already answered: an OpenConnect zone only
            // gets this far because the client authenticated and handed the
            // tunnel over, and it takes the zone down with it the moment it
            // stops.
            println!(
                "zone {}: the openconnect client is connected — the tunnel is alive",
                zone.name()
            );
        }
    }
    Ok(())
}

/// Where an instance's programs read the network it is in now (stage 4):
/// `cellward/network` in their runtime directory — its own tmpfs
/// (`seal_runtime`); `/run` itself is the host's.
pub const NETWORK_INSIDE: &str = "cellward/network";

/// The instance's network for its programs (stage 4 of the container
/// design): its directory's `network`, bound read-only at
/// [`NETWORK_INSIDE`] in the runtime directory. Its keeper rewrites that
/// file in place with each switch (`Transport::note_network`): a program
/// reads the network it is in now there — `VPN_ZONE_CURRENT` in its
/// environment stays the network it was launched into.
fn note_network_inside(zone: &Zone) -> Result<(), String> {
    let target = host_runtime_dir(zone).join(NETWORK_INSIDE);
    if let Some(dir) = target.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    touch(&target).map_err(|e| format!("cannot create {}: {e}", target.display()))?;
    let from = zone.path(crate::instance::NETWORK);
    sys::mount(from.as_os_str(), &target, "", libc::MS_BIND, "")
        .map_err(|e| format!("cannot bind {}: {e}", target.display()))?;
    sys::remount_read_only(&target).map_err(|e| format!("cannot close {}: {e}", target.display()))
}

/// What an instance with a zone for its network has before any attach
/// (stage 2 of the container design, 2026-09-27): the unreachable defaults
/// of both families at the highest metric, under the routes each attach
/// puts on its tap — while there is no tap, a connection and a name fail at
/// once instead of waiting for a route —, and the `resolv.conf` its keeper
/// wrote (`bridge::resolv_text`: the constant forwarders, never a real
/// resolver) bound over the system's: the keeper rewrites it in place with
/// each attach, and programs see the new text in the same file. The file
/// comes back for the space to keep over the name (`rebind::keep`, D2).
fn instance_ground(zone: &Zone) -> Result<crate::rebind::Own, String> {
    let unreachable = [
        "route",
        "add",
        "unreachable",
        "default",
        "metric",
        "4294967295",
    ];
    if zone.ip_quiet(&unreachable).is_err() {
        eprintln!(
            "instance {}: no unreachable IPv4 default — without a tap a connection fails as \
             no route is found",
            zone.name()
        );
    }
    let six: Vec<&str> = std::iter::once("-6").chain(unreachable).collect();
    let _ = zone.ip_quiet(&six);
    // IPv4 multicast nowhere (the file transfer test, vm87, 2026-09-28): a
    // program's LAN discovery — mDNS, LocalSend, KDE Connect, SSDP — went
    // into the tunnel, where the VPN's provider read the announcements, a
    // device's name among them. A route more specific than any tap's default
    // wins under every attach, and a send fails at once. IPv6 multicast has
    // no route in here already. Not fatal: without it the announcements go
    // into the tunnel, never around it.
    if zone
        .ip_quiet(&["route", "add", "unreachable", "224.0.0.0/4"])
        .is_err()
    {
        eprintln!(
            "instance {}: no unreachable route for multicast — a program's LAN discovery goes \
             into the tunnel",
            zone.name()
        );
    }
    bind_resolv(zone)
}

/// The space's `resolv.conf` (its directory's [`RESOLV`]) bound over the
/// name `/etc/resolv.conf` itself, and returned for the space to keep there
/// (`rebind::keep`).
///
/// ON THE NAME, NOT WHERE IT LEADS (`crate::rebind`, `docs/THREAT-MODEL.md`
/// D2, 2026-09-28). `mount(2)` follows the symlinks of its target, and on
/// NixOS that path is a chain ending in /run/systemd/resolve/stub-resolv.conf
/// — inside the tmpfs that has just hidden the host's resolved, where the
/// last link dangles: the bind used to be made there, over a file created
/// for it (`sys::link_target`). A host that renamed anything along its chain
/// then took the space's file away. Attached without following
/// (`move_mount`), it covers the name whatever the host made it — a link, a
/// plain file, a link that leads nowhere in here —, and only a replacement
/// of the name itself detaches it: that one the space lays over again. A
/// host with no `/etc/resolv.conf` at all fails the space, as it always did.
fn bind_resolv(zone: &Zone) -> Result<crate::rebind::Own, String> {
    let own = crate::rebind::Own::open(&zone.path(RESOLV), Path::new(ETC_RESOLV))
        .map_err(|e| format!("cannot open its {RESOLV}: {e}"))?;
    own.lay()
        .map_err(|e| format!("cannot bind {RESOLV} over {ETC_RESOLV}: {e}"))?;
    Ok(own)
}

/// A zone's bridge, once the zone is set up (`crate::bridge`, stage 2 of
/// the container design of 2026-09-27): its rules reloaded with the refusal
/// of every address of its own to passt ([`bridge_refusal_rules`], after
/// `first` and before the accepts), the mark once they are in, its socket
/// bound — the user's, 0600: the instance's keeper, the user, asks — and
/// what it carries with: the resolvers its `resolv_conf` names (those this
/// zone's own programs ask), its search domains, whether it has IPv6, and
/// its fingerprint. `None`: no socket, said — a launch into the zone is
/// refused then, as into a zone of a previous build (stage 5: never into
/// the zone's own namespaces). Without the
/// rule or passt's group the socket is there and refuses every request
/// with the reason: fail-closed, and the person is told why.
fn open_bridge(
    zone: &Zone,
    first: &[String],
    resolv_conf: &str,
    search: Option<&str>,
    config_seed: u64,
) -> Option<(std::os::unix::net::UnixListener, crate::bridge::Carrier)> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let socket = zone.path(crate::bridge::SOCKET);
    let mark = zone.path(crate::bridge::RULE_MARK);
    let _ = fs::remove_file(&socket);
    let _ = fs::remove_file(&mark);
    // Every address of this namespace as it is now, the tunnel's included:
    // a connection there is delivered in the zone itself.
    let addresses = tool_output(&zone.tools.ip, &["-j", "addr", "show"])
        .and_then(|text| {
            crate::bridge::local_addresses(&text)
                .ok_or_else(|| "`ip -j addr` gave no list of addresses".to_owned())
        })
        .and_then(|addresses| {
            let mut rules = first.to_vec();
            rules.extend(bridge_refusal_rules(crate::bridge::BRIDGE_ID, &addresses));
            feed_nft(&zone.tools.nft, &replacing_table(&app_ruleset_with(&rules)))
        })
        .and_then(|()| touch(&mark).map_err(|e| format!("cannot mark it: {e}")));
    let ruled = match addresses {
        Ok(()) => true,
        Err(e) => {
            eprintln!(
                "zone {}: the bridge's refusal of the zone's own addresses is not loaded ({e}) — \
                 the zone carries no container",
                zone.name()
            );
            false
        }
    };
    let gid =
        crate::bridge::bridge_gid(&fs::read_to_string("/proc/self/gid_map").unwrap_or_default());
    if gid.is_none() {
        eprintln!(
            "zone {}: its user namespace has no group for the bridge — it carries no container",
            zone.name()
        );
    }
    let owner = match fs::metadata(&zone.dir) {
        Ok(meta) => (meta.uid(), meta.gid()),
        Err(e) => {
            eprintln!("zone {}: no bridge ({e})", zone.name());
            return None;
        }
    };
    let listener = match std::os::unix::net::UnixListener::bind(&socket) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!(
                "zone {}: no bridge ({e}) — a launch into it is refused",
                zone.name()
            );
            return None;
        }
    };
    let owned = std::os::unix::fs::chown(&socket, Some(owner.0), Some(owner.1))
        .and_then(|()| fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)));
    if let Err(e) = owned {
        eprintln!(
            "zone {}: no bridge — its socket is not the user's ({e})",
            zone.name()
        );
        let _ = fs::remove_file(&socket);
        return None;
    }
    let servers: Vec<IpAddr> = crate::doctor::nameservers(resolv_conf)
        .iter()
        .filter_map(|server| server.parse().ok())
        .collect();
    let resolver4 = servers.iter().find_map(|server| match server {
        IpAddr::V4(a) => Some(*a),
        IpAddr::V6(_) => None,
    });
    let resolver6 = servers.iter().find_map(|server| match server {
        IpAddr::V6(a) => Some(*a),
        IpAddr::V4(_) => None,
    });
    let search: Vec<String> = search
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let v6 = zone_carries_v6(zone);
    let fp = crate::bridge::fingerprint(config_seed, resolver4, resolver6, &search);
    if ruled && gid.is_some() {
        println!(
            "zone {}: carries containers (IPv6 {}, fingerprint {fp:016x})",
            zone.name(),
            if v6 { "too" } else { "not" }
        );
    }
    Some((
        listener,
        crate::bridge::Carrier {
            zone: zone.name().into_owned(),
            passt: zone.tools.passt.clone(),
            owner: owner.0,
            gid,
            ruled,
            v6,
            resolver4,
            resolver6,
            search,
            fp,
        },
    ))
}

/// Whether the zone carries IPv6: its default route of the family goes
/// into its way out, `awg0` (`close_or_tunnel_v6`; a host-interface or a
/// system zone's pasta names its interface so too), and is no unreachable
/// one.
fn zone_carries_v6(zone: &Zone) -> bool {
    let into = format!("dev {TUN_IFACE}");
    tool_output(&zone.tools.ip, &["-6", "route", "show", "default"]).is_ok_and(|text| {
        text.lines()
            .any(|line| !line.starts_with("unreachable") && line.contains(&into))
    })
}

/// Put the WireGuard config onto the interface the uplink handed down.
fn configure_wg(zone: &Zone, cfg: &WgConfig, wgtool: &Path) -> Result<(), String> {
    // Not through `run_tool`: the path of the stripped config is a path, and
    // squeezing it through a `&str` would mangle a `$HOME` that is not UTF-8.
    let setconf = Command::new(wgtool)
        .arg("setconf")
        .arg(TUN_IFACE)
        .arg(zone.path(STRIPPED))
        .status()
        .map_err(|e| format!("cannot run {}: {e}", wgtool.display()))?;
    if !setconf.success() {
        return Err(format!("{} setconf failed ({setconf})", wgtool.display()));
    }

    // Every address, both families: a v6-only `Address` used to kill the zone
    // on `ip -4 addr add`, and a v6 address in a mixed list used to be dropped
    // silently — which is an IPv6 leak.
    let mut tunnel_v6 = false;
    for addr in cfg.addresses() {
        let raw = addr.raw.as_str();
        match addr.family {
            Family::V6 => {
                if zone
                    .ip_quiet(&["-6", "addr", "add", raw, "dev", TUN_IFACE])
                    .is_ok()
                {
                    tunnel_v6 = true;
                } else {
                    eprintln!(
                        "zone {}: the v6 address {} did not apply — IPv6 will be closed here",
                        zone.name(),
                        addr.raw
                    );
                }
            }
            Family::V4 => zone.ip(&["-4", "addr", "add", raw, "dev", TUN_IFACE])?,
        }
    }
    let mtu = cfg.mtu().unwrap_or(DEFAULT_MTU).to_string();
    zone.ip(&["link", "set", TUN_IFACE, "mtu", mtu.as_str(), "up"])?;
    default_into_tunnel(zone)?;
    close_or_tunnel_v6(zone, tunnel_v6)
}

/// Put the gateway's answer onto the tun the OpenConnect client handed down.
///
/// A `/32` and nothing else, which is what the upstream `vpnc-script` does with
/// a point-to-point device too. The netmask the gateway may also have sent is
/// deliberately unused: it would only add an on-link route for a network the
/// default route below already covers, and the split-include list it belongs to
/// is ignored on purpose (`crate::openconnect`).
fn configure_oc(zone: &Zone, plan: &openconnect::Plan) -> Result<(), String> {
    // The name is an invariant, not a detail: the app namespace's filter was
    // loaded minutes ago and names `awg0`. A client that produced anything else
    // would have its packets dropped by our own second echelon, silently.
    if plan.iface != TUN_IFACE {
        return Err(format!(
            "the client built {} instead of {TUN_IFACE} — the app namespace's filter names \
             {TUN_IFACE} and was loaded before the tunnel arrived",
            plan.iface
        ));
    }
    let addr = format!("{}/32", plan.address);
    let mtu = plan.mtu.to_string();
    zone.ip(&["-4", "addr", "replace", addr.as_str(), "dev", TUN_IFACE])?;
    zone.ip(&["link", "set", TUN_IFACE, "mtu", mtu.as_str(), "up"])?;
    default_into_tunnel(zone)?;
    // IPv6 as the gateway gave it (2026-09-27): a /128 on the tunnel and the
    // family's default into it, the same way as a WireGuard config with a v6
    // address. None, or an address the kernel will not take: the family ends
    // here, and IPv4 works on — there is no second interface for IPv6 to
    // take either way.
    let tunnel_v6 = plan.address6.is_some_and(|a6| {
        let a6 = format!("{a6}/128");
        let applied = zone
            .ip_quiet(&[
                "-6",
                "addr",
                "replace",
                a6.as_str(),
                "dev",
                TUN_IFACE,
                "nodad",
            ])
            .is_ok();
        if !applied {
            eprintln!(
                "zone {}: the gateway's v6 address {a6} did not apply — IPv6 is closed here",
                zone.name()
            );
        }
        applied
    });
    close_or_tunnel_v6(zone, tunnel_v6)
}

/// THERE IS NO ROUTE AROUND THE TUNNEL, AND THERE MUST NOT BE.
///
/// The old one-namespace layout needed a /32 to the VPN server through pasta's
/// interface, or the tunnel's own packets would have been wrapped into the
/// tunnel — and that route was visible to the programs, together with pasta's
/// interface and everything else reachable through it. Here the encrypted
/// packets are born in the uplink and leave by ITS default route; this namespace
/// has one interface besides loopback and one route, and both lead into the
/// tunnel. For OpenConnect that is also where the gateway's split-include list
/// goes: a zone routes everything, or it is not a zone.
fn default_into_tunnel(zone: &Zone) -> Result<(), String> {
    zone.ip(&["route", "replace", "default", "dev", TUN_IFACE])
}

/// Ping without raw sockets: the kernel's ICMP echo sockets, for the user's
/// own groups in the zone (`net.ipv4.ping_group_range`, one per network
/// namespace, and "nobody" — `1 0` — in a new one; it covers IPv6 too).
/// Without it `ping` asks for CAP_NET_RAW, which a program in a zone does not
/// have and must not get (the owner, 2026-09-25: "missing cap_net_raw").
/// Nothing is opened by it: an echo socket sends echo requests the kernel
/// builds itself, by this namespace's routes — into the tunnel like
/// everything else here, or nowhere in an offline zone. Best effort: a
/// kernel that refuses leaves ping as it was, and says so.
fn allow_ping(zone: &Zone) {
    let Some(range) = ping_range(&fs::read_to_string("/proc/self/gid_map").unwrap_or_default())
    else {
        return;
    };
    if let Err(e) = fs::write("/proc/sys/net/ipv4/ping_group_range", &range) {
        eprintln!(
            "zone {}: ping stays without echo sockets (ping_group_range {range}: {e})",
            zone.name()
        );
    }
}

/// The user's own groups in the user namespace whose `gid_map` this is: the
/// lines mapped to themselves (`100 100 1` — the zone's root is some
/// subordinate id instead). As `lowest highest`: the kernel keeps both ends
/// as the host's ids and takes a range only when those are in order as
/// well, so a range over every line (`0 100`, the root being 100000
/// outside) is empty — the first try, found by the VM test. Lines mapped to
/// themselves are in the same order either way: the user's group and the
/// bridge's passt's (`map_args`, stage 2 of the container design), from the
/// lowest to the highest of them. What lies between is no process's of the
/// app namespace but the zone's root, which needs no echo socket.
pub fn ping_range(gid_map: &str) -> Option<String> {
    let own: Vec<(u64, u64)> = gid_map
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace().map(str::parse::<u64>);
            let (Some(Ok(inside)), Some(Ok(outside)), Some(Ok(count))) =
                (fields.next(), fields.next(), fields.next())
            else {
                return None;
            };
            (inside == outside && count > 0).then(|| (inside, inside + count - 1))
        })
        .collect();
    let low = own.iter().map(|(low, _)| *low).min()?;
    let high = own.iter().map(|(_, high)| *high).max()?;
    Some(format!("{low} {high}"))
}

/// --- IPv6: INTO THE TUNNEL OR NOWHERE AT ALL ---
///
/// A packet of ANY family must have no path around the tunnel
/// (`docs/LEAK-MODEL.md`). Here that is the topology's doing rather than a
/// rule's: with no other interface there is nothing to leak through even
/// without a single route. The unreachable default is belt and braces — it
/// turns "no route to host" into an immediate error instead of a timeout, and
/// it costs nothing. No sysctl is touched any more: switching the family off was
/// a way to plug a hole that no longer exists.
fn close_or_tunnel_v6(zone: &Zone, tunnel_v6: bool) -> Result<(), String> {
    match v6_plan(Path::new("/proc/net/if_inet6").exists(), tunnel_v6) {
        V6Plan::NoKernel => {}
        V6Plan::IntoTunnel => zone.ip(&["-6", "route", "replace", "default", "dev", TUN_IFACE])?,
        V6Plan::CloseDefault => {
            // THE TYPE COMES BEFORE THE PREFIX. `ip -6 route replace default
            // unreachable` is not a route at all: iproute2 parses "default" as
            // the prefix, then finds a route type with nothing behind it and
            // exits with "Command line is not complete" — measured. The old
            // one-namespace code had the words in that order, so its v6
            // fallback had never once worked; it went unnoticed because the
            // sysctl branch above it usually won. Errors stay quiet: this is
            // belt and braces over a namespace that has no second interface to
            // leak through anyway.
            let _ = zone.ip_quiet(&["-6", "route", "replace", "unreachable", "default"]);
        }
    }
    Ok(())
}

/// What the status mirror watches, which is the one thing the two backends do
/// not have in common.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Mirror {
    /// `awg show` / `wg show`, by the path of the tool that speaks to the
    /// interface.
    Wg(PathBuf),
    /// There is no `show` for an OpenConnect tunnel: liveness is the interface
    /// being there and up, and the client — which the uplink is waiting on —
    /// still running.
    Oc,
    /// The same question for pasta's interface, which goes out through the
    /// named interface of the host.
    HostIf(String),
    /// pasta's interface for the link, and the named system zone's own mirror
    /// for the tunnel behind it — `wg show` output, read by the group
    /// vpn-zones, so `vpn-zone check` answers from the handshake as for any
    /// WireGuard zone. Read through a descriptor of its run directory opened
    /// before `/run/vpn-zones` was hidden here (`hide_system_tier`).
    SysZone(String, Option<RawFd>),
}

/// Mirror the tunnel's state into the zone's `status` file.
///
/// `wg show` needs netlink privileges, and programs (and `vpn-zone status`)
/// enter the zone under the ordinary uid and see nothing at all — so the state
/// is written from in here, where the privileges are. It has to be this
/// namespace and not the uplink: `show` reads the interface over netlink in the
/// CURRENT namespace, and the interface lives here — and for an OpenConnect zone
/// the interface is the only thing there is to read. The rename is what makes a
/// reader see either the old file or the new one, never half of one.
/// (`docs/GOTCHAS.md` §4)
fn start_status_mirror(zone: &Zone, mirror: Mirror) {
    let status = zone.path(STATUS);
    let tmp = zone.path(STATUS_TMP);
    let ip = zone.tools.ip.clone();
    thread::spawn(move || loop {
        let text = match &mirror {
            Mirror::Wg(tool) => tool_output(tool, &["show", TUN_IFACE]).ok(),
            Mirror::Oc => Some(oc_mirror(
                &tool_output(&ip, &["-o", "link", "show", TUN_IFACE]).unwrap_or_default(),
                &tool_output(&ip, &["-br", "-4", "addr", "show", TUN_IFACE]).unwrap_or_default(),
            )),
            Mirror::HostIf(interface) => Some(link_mirror(
                &format!("host interface {interface}"),
                &tool_output(&ip, &["-o", "link", "show", TUN_IFACE]).unwrap_or_default(),
                &tool_output(&ip, &["-br", "-4", "addr", "show", TUN_IFACE]).unwrap_or_default(),
            )),
            Mirror::SysZone(system, dir) => {
                let own = link_mirror(
                    &format!("system zone {system}"),
                    &tool_output(&ip, &["-o", "link", "show", TUN_IFACE]).unwrap_or_default(),
                    &tool_output(&ip, &["-br", "-4", "addr", "show", TUN_IFACE])
                        .unwrap_or_default(),
                );
                // Our link up: the rest is the tunnel's, and the tunnel is
                // the system zone's. Our link down: that says it all.
                let tunnel = own
                    .contains("connected: yes")
                    .then(|| fs::read_to_string(format!("/proc/self/fd/{}/status", (*dir)?)).ok())
                    .flatten()
                    .filter(|t| !t.trim().is_empty());
                // Our link up and the system zone's tunnel saying nothing — it
                // is stopped, or restarting: not "connected" (review; the file
                // is deleted on down and on restart).
                Some(match tunnel {
                    Some(tunnel) => tunnel,
                    None if own.contains("connected: yes") => format!(
                        "interface: {TUN_IFACE}\n  backend: system zone {system}\n  \
                         disconnected: the system zone's tunnel says nothing\n"
                    ),
                    None => own,
                })
            }
        };
        if let Some(text) = text {
            if fs::write(&tmp, text).is_ok() {
                let _ = fs::rename(&tmp, &status);
            }
        }
        thread::sleep(STATUS_PERIOD);
    });
}

/// The status file of an OpenConnect zone, as a pure function of two `ip`
/// dumps.
///
/// `vpn-zone check` reads this file and answers "is the tunnel alive". For
/// WireGuard the answer is the handshake line; here it is the `connected:` line
/// below, and it is written only when the interface is BOTH present and up —
/// which for this backend really is the whole question, because the client
/// dying takes the interface and then the zone with it.
pub fn oc_mirror(link: &str, addr: &str) -> String {
    link_mirror("openconnect", link, addr)
}

/// [`oc_mirror`] for any backend whose liveness is its interface being there
/// and up.
pub fn link_mirror(backend: &str, link: &str, addr: &str) -> String {
    // The flags, and only the flags. `ip -o link show` prints them between
    // angle brackets — `<POINTOPOINT,NOARP,UP,LOWER_UP>` — and a substring
    // search for "UP" would find LOWER_UP, NO-CARRIER and half the operstates
    // as well.
    let up = link
        .split_once('<')
        .and_then(|(_, rest)| rest.split_once('>'))
        .is_some_and(|(flags, _)| flags.split(',').any(|flag| flag == "UP"));
    let mut text = format!("interface: {TUN_IFACE}\n  backend: {backend}\n");
    if link.trim().is_empty() {
        text.push_str("  disconnected: the tunnel interface is gone\n");
        return text;
    }
    if !up {
        text.push_str("  disconnected: the tunnel interface is down\n");
        return text;
    }
    // The word `check` greps for. Deliberately not "latest handshake": there is
    // no handshake here and pretending otherwise would be a lie in a file a
    // human reads.
    text.push_str("  connected: yes\n");
    let addr = addr.split_whitespace().nth(2).unwrap_or("").trim();
    if !addr.is_empty() {
        text.push_str("  address: ");
        text.push_str(addr);
        text.push('\n');
    }
    text
}

/// Close every resolver of the HOST off from the zone.
///
/// The topology cannot do this one. A name is resolved by asking a daemon over
/// a UNIX SOCKET, and a socket is not an interface: it has no route to remove,
/// no interface to leave by and no packet for a filter to see. The daemon on
/// the other end sits in the host's network and answers from there — so with
/// the socket in reach, `getaddrinfo` inside a zone goes around the tunnel no
/// matter how hermetic the namespace is, and swapping resolv.conf does not cure
/// it either.
///
/// Both known leaks are real, both were measured on a live zone:
///
/// * **nsncd** (`/run/nscd/socket`), which NixOS runs: `getent` answered while
///   awg0 still had RX=0 — the query had never touched the tunnel.
/// * **systemd-resolved** (`/run/systemd/resolve/io.systemd.Resolve`), which
///   nss-resolve talks varlink to. NixOS puts `resolve` FIRST in
///   `/etc/nsswitch.conf`, ahead of `dns`, so with resolved enabled EVERY
///   lookup in the zone went to the host's resolver: a leak test run in a
///   browser inside a zone named the user's real ISP as the resolver, while
///   `curl ifconfig.me` in the same zone correctly showed the VPN's address.
///   `resolvectl status` from inside the zone answering at all is the tell.
///
/// avahi (nss-mdns) is here for the same reason before anyone measures it: it
/// would put the name onto the host's LAN.
///
/// A tmpfs over the directory hides the socket inside the zone only, and the
/// zone's mount tree is private — the daemons keep serving the rest of the
/// system exactly as before. glibc then finds nothing to ask, nss-resolve
/// answers UNAVAIL (which is precisely the case `[!UNAVAIL=return]` in
/// nsswitch.conf falls through) and the `dns` module goes to the servers in the
/// zone's own resolv.conf — through the tunnel.
///
/// A failure here is fatal to the zone, and that is the fail-closed rule: a
/// zone that comes up while its programs resolve names in the host's network is
/// worse than no zone, because it looks exactly like a working one.
/// (`docs/GOTCHAS.md` §3, `docs/LEAK-MODEL.md`)
fn hide_host_resolvers(zone: &Zone) -> Result<(), String> {
    let mut hidden: Vec<&str> = Vec::new();
    for group in RESOLVER_DIRS {
        if let Some(dir) = hide_first(group)? {
            hidden.push(dir);
        }
    }
    // One line, and it is worth its place in the journal: this is where the
    // question "could a name have gone around the tunnel?" is answered.
    println!(
        "zone {}: host resolvers hidden ({})",
        zone.name(),
        if hidden.is_empty() {
            "none running".to_string()
        } else {
            hidden.join(", ")
        }
    );
    Ok(())
}

/// Bind the zone's own `nsswitch.conf`: the host's, with `hosts:` reduced to
/// `files dns`.
///
/// Hiding the resolver sockets (`hide_host_resolvers`) is a LIST — nscd,
/// systemd-resolved, avahi — and a list goes stale with the next NSS module
/// that talks to a daemon of the host's (`mymachines` asks machined over the
/// system bus, a future one asks something else). With `hosts: files dns` in
/// the zone no module but the plain resolver is ever loaded for a name, and the
/// plain resolver reads the zone's resolv.conf, i.e. goes into the tunnel.
/// Every other database (`passwd`, `group`, …) stays as the host has it: user
/// lookups are not a network channel. (`docs/LEAK-MODEL.md` §3)
///
/// Not fatal, and deliberately so, like the nftables echelon: the sockets are
/// already hidden, so a failure here costs the class-wide insurance, not the
/// zone's hermeticity — and it has to be impossible to miss in the journal.
///
/// Bound on the name `/etc/nsswitch.conf` itself, not where its links lead
/// (`crate::rebind`, `docs/THREAT-MODEL.md` D2, 2026-09-28): NixOS replaces
/// `/etc/static` with every switch, and a bind at the end of the chain was
/// left behind by the first one. The zone's copy comes back for the space
/// to keep over the name (`rebind::keep`); `None` when there is none.
fn own_nsswitch(zone: &Zone) -> Option<crate::rebind::Own> {
    // The host's text, wherever its links lead: what the copy is made of.
    let target = sys::link_target(Path::new(ETC_NSSWITCH));
    let Ok(host) = fs::read_to_string(&target) else {
        // No nsswitch.conf at all: glibc's built-in default has no daemon
        // module for hosts, and there is nothing to bind over.
        return None;
    };
    let path = zone.path(NSSWITCH);
    let result = fs::write(&path, zone_nsswitch(&host))
        .map_err(|e| format!("cannot write {NSSWITCH}: {e}"))
        .and_then(|()| {
            crate::rebind::Own::open(&path, Path::new(ETC_NSSWITCH))
                .map_err(|e| format!("cannot open {NSSWITCH}: {e}"))
        })
        .and_then(|own| match own.lay() {
            Ok(_) => Ok(own),
            Err(e) => Err(format!("cannot bind it over {ETC_NSSWITCH}: {e}")),
        });
    match result {
        Ok(own) => {
            println!("zone {}: hosts in nsswitch.conf is files dns", zone.name());
            Some(own)
        }
        Err(e) => {
            eprintln!(
                "zone {}: the zone's own nsswitch.conf is OFF ({e}) — the host's resolver \
                 sockets are hidden, but a new NSS module talking to a host daemon would not be",
                zone.name()
            );
            None
        }
    }
}

/// The host's `nsswitch.conf` with every `hosts:` line replaced by
/// `hosts: files dns` (and one added when there was none). Comments and every
/// other database are kept as they are.
pub fn zone_nsswitch(host: &str) -> String {
    let mut out = String::new();
    let mut replaced = false;
    for line in host.lines() {
        let is_hosts = line
            .trim_start()
            .strip_prefix("hosts")
            .is_some_and(|rest| rest.trim_start().starts_with(':'));
        if is_hosts {
            if !replaced {
                out.push_str("hosts: files dns\n");
                replaced = true;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if !replaced {
        out.push_str("hosts: files dns\n");
    }
    out
}

/// Cover the first of `dirs` that exists with an empty tmpfs, and say which.
pub(crate) fn hide_first<'a>(dirs: &[&'a str]) -> Result<Option<&'a str>, String> {
    for &dir in dirs {
        let path = Path::new(dir);
        if !path.is_dir() {
            continue;
        }
        sys::mount(OsStr::new("tmpfs"), path, "tmpfs", 0, "mode=0755,size=64k").map_err(|e| {
            format!("cannot hide the host's resolver at {dir}: {e} — the zone would leak DNS")
        })?;
        return Ok(Some(dir));
    }
    Ok(None)
}

// --- PURE HELPERS (the testable half) ----------------------------------------

/// The `dev`/`via` of a default route.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DefaultRoute {
    pub dev: Option<String>,
    pub via: Option<String>,
}

/// Read a route line BY KEYWORD, never by field number.
///
/// pasta's default route looks like `default dev hostif scope link` (no via),
/// an ordinary network's like `default via 192.168.1.1 dev enp4s0 …`. Positional
/// parsing picked up the word "link" instead of the interface name in the second
/// case — verified, and the zone was then declared routeless while it was not.
/// (`docs/GOTCHAS.md` §2)
pub fn parse_default_route(line: &str) -> DefaultRoute {
    let mut route = DefaultRoute::default();
    let mut words = line.split_whitespace();
    while let Some(word) = words.next() {
        if word == "dev" && route.dev.is_none() {
            route.dev = words.next().map(str::to_string);
        } else if word == "via" && route.via.is_none() {
            route.via = words.next().map(str::to_string);
        }
    }
    route
}

/// What to do about IPv6 in the app namespace, as a pure decision.
///
/// Shorter than it used to be, and that is the point: there is no "switch the
/// family off" case any more. IPv6 could leak while the zone had pasta's
/// interface in it; now the only interface besides loopback is the tunnel, so
/// the choice is between routing v6 into it and leaving it with no default at
/// all. The endpoint plays no part either — its family is the uplink's business.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V6Plan {
    /// A kernel without IPv6 at all: nothing to do.
    NoKernel,
    /// The tunnel carries v6, so the v6 default goes into it.
    IntoTunnel,
    /// No v6 in the tunnel: close the default and let the family end here.
    CloseDefault,
}

pub fn v6_plan(kernel_has_v6: bool, tunnel_has_v6: bool) -> V6Plan {
    if !kernel_has_v6 {
        V6Plan::NoKernel
    } else if tunnel_has_v6 {
        V6Plan::IntoTunnel
    } else {
        V6Plan::CloseDefault
    }
}

// --- THE SECOND ECHELON: THE TWO RULESETS ------------------------------------

/// One endpoint as the uplink's filter sees it: an address the tunnel may talk
/// to and, when the config bothered to say so, the port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointSocket {
    pub addr: IpAddr,
    pub port: Option<u16>,
}

/// Every endpoint of a config that has already been through
/// [`WgConfig::resolve_endpoints`] — in file order, without duplicates.
///
/// An endpoint that is still a NAME cannot get this far (`prepare` refuses to
/// start a zone whose endpoint did not resolve) and is skipped rather than
/// guessed at: a filter built out of an address nobody has would be a filter
/// that lies.
pub fn endpoint_sockets(cfg: &WgConfig) -> Vec<EndpointSocket> {
    let mut out: Vec<EndpointSocket> = Vec::new();
    for section in &cfg.sections {
        for entry in &section.entries {
            if !entry.key.eq_ignore_ascii_case("Endpoint") {
                continue;
            }
            let Some(endpoint) = Endpoint::parse(&entry.value) else {
                continue;
            };
            let EndpointHostKind::Literal(addr) = endpoint_host_kind(&endpoint) else {
                continue;
            };
            let socket = EndpointSocket {
                addr,
                port: endpoint.port,
            };
            // Several peers of one server are one rule, not three.
            if !out.contains(&socket) {
                out.push(socket);
            }
        }
    }
    out
}

/// Neighbour discovery, without which a v6 endpoint is simply unreachable.
///
/// pasta hands the namespace a v6 default `via fe80::1`, and the kernel cannot
/// send a single packet there before it has resolved that address — with an
/// ICMPv6 neighbour solicitation, which the output hook sees like any other
/// packet. Drop it and the tunnel never gets off the ground. IPv4 needs no such
/// exception: ARP is not in the `inet` family at all (it has a family of its
/// own), so an `inet` filter never touches it.
///
/// Nothing can be smuggled out this way: these three types are link-local
/// multicast, and the only thing on that link is pasta.
const NDP_RULE: &str =
    "icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept";

/// The app namespace's ruleset: out through the tunnel, or nowhere.
///
/// `oifname` and not `oif` on purpose. `oif` is resolved to an interface INDEX
/// when the rule is loaded, which would mean the rule has to be loaded after the
/// tunnel has arrived and would silently stop matching if the interface were
/// ever recreated; `oifname` compares the name every time, so the ruleset can go
/// in before the tunnel does and keeps meaning what it says afterwards.
pub fn app_ruleset() -> String {
    app_ruleset_with(&[])
}

/// The host's own addresses, from where the host's network is seen: every
/// interface's IPv4 and IPv6 ones ([`refusable`] says which).
fn host_addresses() -> Vec<std::net::IpAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let mut out = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills the pointer with a list freed below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return out;
    }
    let mut at = list;
    while !at.is_null() {
        // SAFETY: a node of the list getifaddrs made, alive until freeifaddrs.
        let node = unsafe { &*at };
        let addr = if node.ifa_addr.is_null() {
            None
        } else {
            // SAFETY: a non-null sockaddr of the node, read as the family it
            // says it is.
            match i32::from(unsafe { (*node.ifa_addr).sa_family }) {
                libc::AF_INET => {
                    let sin = unsafe { &*(node.ifa_addr as *const libc::sockaddr_in) };
                    Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                        sin.sin_addr.s_addr,
                    ))))
                }
                libc::AF_INET6 => {
                    let sin6 = unsafe { &*(node.ifa_addr as *const libc::sockaddr_in6) };
                    Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
                }
                _ => None,
            }
        };
        if let Some(addr) = addr.filter(|a| refusable(*a) && !out.contains(a)) {
            out.push(addr);
        }
        at = node.ifa_next;
    }
    // SAFETY: the list getifaddrs made, freed once.
    unsafe { libc::freeifaddrs(list) };
    out
}

/// Whether a host address goes into [`host_address_rules`]: not loopback,
/// which the zone's own is anyway; not multicast; and not an IPv6 link-local
/// one — a zone cannot name the host's link with a scope, and pasta answers
/// neighbour discovery for the zone from such addresses, which a refusal
/// would cut.
fn refusable(addr: std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(a) => !a.is_loopback() && !a.is_multicast(),
        std::net::IpAddr::V6(a) => {
            !a.is_loopback() && !a.is_multicast() && (a.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}

/// A host-interface zone's refusal of the host's own addresses (audit
/// 2026-09-27). Its pasta runs in the host's network and gives the zone an
/// address of its own, so a connection to one of the host's is delivered
/// locally — to a DNS forwarder, a proxy, Tor, sshd — and what that service
/// sends goes out by the host's routes, not by the interface chosen. The
/// addresses the host has when the zone comes up; one it gets later is not
/// among them. IPv6 as well as IPv4 (second opinion, 2026-09-27: only IPv4
/// was refused, and a zone whose interface has IPv6 gets it).
pub fn host_address_rules(addresses: &[std::net::IpAddr]) -> Vec<String> {
    addresses
        .iter()
        .map(|a| match a {
            std::net::IpAddr::V4(a) => format!("ip daddr {a} reject with icmpx admin-prohibited"),
            std::net::IpAddr::V6(a) => {
                format!("ip6 daddr {a} reject with icmpx admin-prohibited")
            }
        })
        .collect()
}

/// [`app_ruleset`] with rules of the caller's first — a system zone's refusal
/// of what its user zones' pasta sends to its own addresses.
pub fn app_ruleset_with(first: &[String]) -> String {
    let mut rules = first.to_vec();
    rules.push("oifname \"lo\" accept".to_string());
    rules.push(format!("oifname \"{TUN_IFACE}\" accept"));
    output_table(&rules)
}

/// A zone's refusal, ahead of [`app_ruleset_with`]'s accepts, of every
/// local address to the passt that carries a container instance
/// (`crate::bridge`, the container design of 2026-09-27): the loopback of
/// both families, IPv6's link-local range, and the app namespace's own
/// addresses (`addresses`, its tunnel's). A connection there is delivered in
/// the zone itself — to a program of the zone's own, a resolver, a proxy —
/// and not by the zone's way out. Keyed on passt's uid as the app
/// namespace's user namespace sees it (`bridge::BRIDGE_ID`): passt's own
/// nested user namespace does not change its kuid.
///
/// Core `nf_tables` only — `meta skuid`, the address payloads and anonymous
/// sets — and no `fib`: what every zone's second echelon needs loaded
/// anyway. An expression in a module of its own is one more module a host
/// may lack, or may not load on a user namespace's request (the VM probe
/// saw `nft_socket` autoloaded from one; `docs/GOTCHAS.md` §14), and the
/// zone refuses to carry instances without this rule. Addresses inside the
/// ranges named already are left out of the sets: an anonymous interval set
/// takes no overlap.
pub fn bridge_refusal_rules(uid: u32, addresses: &[IpAddr]) -> Vec<String> {
    let mut four = vec!["127.0.0.0/8".to_string()];
    let mut six = vec!["::1".to_string(), "fe80::/10".to_string()];
    for address in addresses {
        let (list, text) = match address {
            IpAddr::V4(a) if !a.is_loopback() => (&mut four, a.to_string()),
            IpAddr::V6(a) if !a.is_loopback() && (a.segments()[0] & 0xffc0) != 0xfe80 => {
                (&mut six, a.to_string())
            }
            _ => continue,
        };
        if !list.contains(&text) {
            list.push(text);
        }
    }
    vec![
        format!("meta skuid {uid} ip daddr {{ {} }} drop", four.join(", ")),
        format!("meta skuid {uid} ip6 daddr {{ {} }} drop", six.join(", ")),
    ]
}

/// A container instance's output ruleset (the container design of
/// 2026-09-27, §3.1), loaded by its relay into the instance's network
/// namespace: out through its tap from its own address of this attach, or
/// not at all. Neighbour discovery as in every namespace here ([`NDP_RULE`]).
///
/// `epoch`, from the live switch on (stage 4): the cgroup of this epoch's
/// programs, as `(level, path)` — the path absolute, as `/proc/<pid>/cgroup`
/// has it, the level its depth. A socket's cgroup is fixed when the socket
/// is made, so a socket of an earlier epoch never matches again, whatever
/// its address — the wall that holds where destroying sockets cannot
/// (`crate::sockdiag`). `socket cgroupv2` is `nft_socket`'s, not core
/// `nf_tables`': a host that does not load it has no live switch.
///
/// A path nft could not take as it is — not absolute, a quote, a control
/// character — is refused rather than escaped.
pub fn instance_ruleset(
    epoch: Option<(u32, &str)>,
    a4: std::net::Ipv4Addr,
    a6: Option<std::net::Ipv6Addr>,
) -> Result<String, String> {
    let cgroup = match epoch {
        None => String::new(),
        Some((level, path)) => {
            let relative = path
                .strip_prefix('/')
                // nft takes a quoted string as it is, a unit name's `\x2d`
                // included; only a quote would end it.
                .filter(|p| !p.is_empty() && !p.contains('"') && !p.contains(char::is_control))
                .ok_or_else(|| format!("a cgroup nft cannot name: {path:?}"))?;
            format!(" socket cgroupv2 level {level} \"{relative}\"")
        }
    };
    let mut rules = vec![
        "oifname \"lo\" accept".to_string(),
        NDP_RULE.to_string(),
        format!("oifname \"{TUN_IFACE}\" ip saddr {a4}{cgroup} accept"),
    ];
    // Stage 4: `epoch` goes with a live switch, and a switch's epoch is
    // where the rules say it: its programs' sockets pass, and nothing else
    // of the instance's does.
    if let Some(a6) = a6 {
        rules.push(format!(
            "oifname \"{TUN_IFACE}\" ip6 saddr {a6}{cgroup} accept"
        ));
    }
    Ok(output_table(&rules))
}

/// A container instance's ruleset between a switch's cut and its next
/// attach, and for good after a switch to `offline` (stage 4, `frame-relay
/// --seal`): loopback, and nothing else.
pub fn instance_closed_ruleset() -> String {
    output_table(&["oifname \"lo\" accept".to_string()])
}

/// The uplink's ruleset: the tunnel's own packets to the endpoint, and nothing
/// else.
///
/// The addresses are literals we resolved ourselves in the host's network
/// before any namespace existed, so there is nothing here to escape or to look
/// up. No DNS rule and no ICMP rule either, for the same reason: by the time
/// this namespace exists, every name in the config is already an address.
///
/// A config whose endpoints are all unusable ends up with a loopback-only
/// ruleset, which is the fail-closed answer to a tunnel that has nowhere to go —
/// and the holder has already said so out loud.
pub fn uplink_ruleset(endpoints: &[EndpointSocket]) -> String {
    let mut rules = vec!["oifname \"lo\" accept".to_string()];
    let mut needs_ndp = false;
    for endpoint in endpoints {
        let (family, addr) = match endpoint.addr {
            IpAddr::V4(addr) => ("ip", addr.to_string()),
            IpAddr::V6(addr) => {
                needs_ndp = true;
                ("ip6", addr.to_string())
            }
        };
        // A port is what the config wrote; without one `setconf` would have
        // rejected the endpoint anyway, so the rule stays as wide as the
        // address and no wider.
        rules.push(match endpoint.port {
            Some(port) => format!("{family} daddr {addr} udp dport {port} accept"),
            None => format!("{family} daddr {addr} accept"),
        });
    }
    if needs_ndp {
        rules.push(NDP_RULE.to_string());
    }
    output_table(&rules)
}

/// A ruleset of [`output_table`]'s in place of the table that is there, in
/// one `nft -f` transaction: the table made when there is none, emptied,
/// and filled anew — never the old rules and the new side by side, never a
/// moment with neither (stage 2 of the container design: a zone's rules
/// with its refusal to the bridge added once its addresses are known, an
/// instance's with each attach's own addresses).
pub(crate) fn replacing_table(ruleset: &str) -> String {
    format!("table inet {NFT_TABLE}\nflush table inet {NFT_TABLE}\n{ruleset}")
}

/// Wrap accept rules into the one table and chain both namespaces get.
///
/// Only `output` is filtered. There is no point in an input chain: the app
/// namespace can be reached from the tunnel alone, the uplink from pasta alone,
/// and neither of those becomes safer for being filtered here — what this is
/// about is packets LEAVING somewhere they should not.
fn output_table(rules: &[String]) -> String {
    let mut text = String::new();
    text.push_str("table inet ");
    text.push_str(NFT_TABLE);
    text.push_str(" {\n");
    text.push_str("\tchain output {\n");
    text.push_str("\t\ttype filter hook output priority filter; policy drop;\n");
    for rule in rules {
        text.push_str("\t\t");
        text.push_str(rule);
        text.push('\n');
    }
    text.push_str("\t}\n");
    text.push_str("}\n");
    text
}

/// The zone's `/etc/resolv.conf` and whether the default had to be used.
///
/// A config without `DNS=` used to leave the zone with the host's resolv.conf,
/// where the resolver is a local one (192.168.1.1, or the 127.0.0.53 stub) that
/// cannot be reached from inside: names simply stopped resolving, and it looked
/// like "there is internet but nothing opens". (`docs/GOTCHAS.md` §3)
pub fn resolv_conf(dns: &[String]) -> (String, bool) {
    resolv_conf_with_search(dns, None)
}

/// The same, plus the `search` line an OpenConnect gateway asks for.
///
/// A search domain is what makes a corporate zone usable at all (`wiki` has to
/// mean `wiki.corp.example.org`), and it opens no channel: the extra query goes
/// to the same resolvers, which are reachable only through the tunnel. What
/// the gateway may NOT do is write a line of its own — the domain is checked
/// for being a domain long before it gets here (`crate::openconnect`), and the
/// resolvers are checked for being addresses.
pub fn resolv_conf_with_search(dns: &[String], search: Option<&str>) -> (String, bool) {
    let mut servers: Vec<&str> = dns
        .iter()
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .collect();
    let defaulted = servers.is_empty();
    if defaulted {
        servers = DEFAULT_RESOLVERS.to_vec();
    }
    let mut text = String::new();
    for server in servers {
        text.push_str("nameserver ");
        text.push_str(server);
        text.push('\n');
    }
    if let Some(search) = search.filter(|s| !s.is_empty()) {
        text.push_str("search ");
        text.push_str(search);
        text.push('\n');
    }
    (text, defaulted)
}

/// Host of an endpoint: an address we already have, or a name to resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointHostKind {
    Literal(IpAddr),
    Name(String),
}

/// Tell a literal from a name.
///
/// The distinction is the parser's ([`crate::config::Endpoint`]), which makes it
/// by counting colons and never by "does it contain letters" — hex digits are
/// letters too, and that test used to send v6 endpoints down the hostname path.
pub fn endpoint_host_kind(endpoint: &Endpoint) -> EndpointHostKind {
    match &endpoint.host {
        EndpointHost::V4(addr) => EndpointHostKind::Literal(IpAddr::V4(*addr)),
        EndpointHost::V6(addr) => EndpointHostKind::Literal(IpAddr::V6(*addr)),
        EndpointHost::Name(name) => EndpointHostKind::Name(name.clone()),
    }
}

/// Address of the endpoint, resolving the name if there is one.
///
/// v4 first and v6 only if there is no v4 — the order `getent ahostsv4` then
/// `ahostsv6` gave. This has to happen before either namespace exists, while
/// the resolver is still the host's.
pub(crate) fn resolve_endpoint(endpoint: &Endpoint) -> Option<IpAddr> {
    match endpoint_host_kind(endpoint) {
        EndpointHostKind::Literal(addr) => Some(addr),
        EndpointHostKind::Name(name) => {
            let port = endpoint.port.unwrap_or(0);
            let addrs: Vec<IpAddr> = (name.as_str(), port)
                .to_socket_addrs()
                .ok()?
                .map(|a| a.ip())
                .collect();
            addrs
                .iter()
                .copied()
                .find(IpAddr::is_ipv4)
                .or_else(|| addrs.first().copied())
        }
    }
}

/// Has the peer ever answered? `wg show <if> latest-handshakes` prints
/// `<peer>\t<unix seconds>`, and a zero means "never".
///
/// Deliberately different from the bash version, which piped this into
/// `awk '{exit ($2>0)?0:1}'`: on EMPTY input awk exits 0, so a failing `show`
/// was reported as a successful handshake. Nothing reads this but a human
/// looking at the journal, and a human should not be told a dead tunnel is
/// alive.
pub fn handshake_seen(text: &str) -> bool {
    text.lines().filter(|l| !l.trim().is_empty()).any(|line| {
        line.split_whitespace()
            .nth(1)
            .and_then(|f| f.parse::<u64>().ok())
            .is_some_and(|seconds| seconds > 0)
    })
}

// --- SMALL PLUMBING ----------------------------------------------------------

pub(crate) fn run_tool(tool: &Path, args: &[&str], quiet: bool) -> Result<(), String> {
    let status = Command::new(tool)
        .args(args)
        .stderr(if quiet {
            Stdio::null()
        } else {
            Stdio::inherit()
        })
        .status()
        .map_err(|e| format!("cannot run {}: {e}", tool.display()))?;
    if !status.success() {
        return Err(format!(
            "{} {} failed ({status})",
            tool.display(),
            args.join(" ")
        ));
    }
    Ok(())
}

pub(crate) fn tool_output(tool: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new(tool)
        .args(args)
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {}: {e}", tool.display()))?;
    if !out.status.success() {
        return Err(format!(
            "{} {} failed ({})",
            tool.display(),
            args.join(" "),
            out.status
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Hand a ruleset to `nft -f -` on stdin.
///
/// On stdin and not in a file: the ruleset is generated, it has no business
/// existing on disk, and a file would need a directory that both namespaces can
/// write to. nft's own diagnostics go to the journal untouched — when a ruleset
/// is refused, the line and the reason are the only things worth having.
pub(crate) fn feed_nft(nft: &Path, ruleset: &str) -> Result<(), String> {
    let mut child = Command::new(nft)
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                format!("{} is not there", nft.display())
            } else {
                format!("cannot run {}: {e}", nft.display())
            }
        })?;
    // Taken out of the child so the pipe closes at the end of this statement:
    // `nft -f -` reads to EOF and would wait for one forever.
    let fed = match child.stdin.take() {
        Some(mut pipe) => pipe
            .write_all(ruleset.as_bytes())
            .map_err(|e| format!("cannot hand the ruleset to nft: {e}")),
        None => Err("nft was given no stdin".to_string()),
    };
    // Reap first, report second: a child that died on its own must not be left
    // behind just because the write end noticed it first.
    let status = child
        .wait()
        .map_err(|e| format!("cannot wait for {}: {e}", nft.display()))?;
    fed?;
    if !status.success() {
        return Err(format!("{} -f - failed ({status})", nft.display()));
    }
    Ok(())
}

/// Wait for pasta to be done with the uplink namespace — the holder's word
/// ([`PASTA_DONE`], passed on from [`PastaWord`]), as long as it takes:
/// pasta that ends instead takes the zone down (`supervise`), this process
/// with it. What it did is looked at after, once (`uplink_setup`): no route
/// then is a failure, not a wait for ever (a host with no IPv4 default route,
/// or one outside the main table, when pasta took its copy).
fn wait_for_default_route(zone: &Zone) {
    sys::wait_for_entry(&zone.path(PASTA_DONE), None, Path::exists);
}

/// pasta's word that it is done: its pid file, which it writes "once
/// initialisation is done" — the namespace configured (`sys::written`). In a
/// directory of its own under `/tmp`, made here: pasta runs as this
/// process's user of the zone's namespace with every capability dropped
/// (its `isolate_initial`), and the zone's directory, in the host user's
/// home, is out of its reach; `/tmp` is not, and the directory is this user's
/// (`mkdtemp`, 0700) — pasta's too. Gone with this.
struct PastaWord {
    dir: PathBuf,
}

impl PastaWord {
    fn new() -> io::Result<Self> {
        use std::os::unix::ffi::OsStringExt;
        let mut template = b"/tmp/vpn-zone-pasta.XXXXXX\0".to_vec();
        // SAFETY: a writable NUL-terminated template ending in six Xs.
        let made = unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) };
        if made.is_null() {
            return Err(io::Error::last_os_error());
        }
        template.pop();
        Ok(Self {
            dir: PathBuf::from(std::ffi::OsString::from_vec(template)),
        })
    }

    fn path(&self) -> PathBuf {
        self.dir.join("pasta.pid")
    }

    /// As long as it takes: `true` once pasta says it is done, `false` when
    /// it ended first.
    fn wait(&self, pasta: &mut Child) -> bool {
        sys::wait_for_child_entry(&self.path(), pasta, sys::written)
    }
}

impl Drop for PastaWord {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn default_route(zone: &Zone, family: Family) -> DefaultRoute {
    let family = match family {
        Family::V4 => "-4",
        Family::V6 => "-6",
    };
    parse_default_route(&zone.ip_line(&["-o", family, "route", "show", "default"]))
}

fn touch(path: &Path) -> io::Result<()> {
    File::create(path)?;
    Ok(())
}

/// Create (or replace) a file only its owner may read.
///
/// Replaced and not truncated: the mode is only applied when the file is
/// created, and a leftover from an older version would keep its old, wider
/// permissions while holding the private key.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let _ = fs::remove_file(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host-interface zone refuses the host's own addresses, before its
    /// own accepts (audit 2026-09-27).
    #[test]
    fn a_host_interface_zone_refuses_the_hosts_addresses_first() {
        let first = host_address_rules(&["192.168.1.1".parse().unwrap()]);
        let rules = app_ruleset_with(&first);
        let reject = rules.find("ip daddr 192.168.1.1 reject").unwrap();
        let accept = rules.find("oifname \"lo\" accept").unwrap();
        assert!(reject < accept, "{rules}");
        assert!(host_address_rules(&[]).is_empty());
        // IPv6 too, as `ip6`.
        let v6 = host_address_rules(&["2001:db8::1".parse().unwrap()]);
        assert_eq!(
            v6,
            ["ip6 daddr 2001:db8::1 reject with icmpx admin-prohibited"]
        );
        assert!(app_ruleset_with(&v6).contains("ip6 daddr 2001:db8::1 reject"));
    }

    /// A ruleset put in place of the table that is there: made when there
    /// is none, emptied, filled — one text, one transaction (stage 2).
    #[test]
    fn a_table_is_replaced_whole() {
        let rules = app_ruleset_with(&bridge_refusal_rules(2, &[]));
        let text = replacing_table(&rules);
        assert!(text
            .starts_with("table inet vpnzone\nflush table inet vpnzone\ntable inet vpnzone {\n"));
        assert!(text.ends_with(&rules));
        // The refusal before the accepts, loopback's too.
        let drop4 = text.find("meta skuid 2 ip daddr").unwrap();
        let lo = text.find("oifname \"lo\" accept").unwrap();
        assert!(drop4 < lo, "{text}");
    }

    /// Which host addresses are refused: not loopback, multicast or IPv6
    /// link-local.
    #[test]
    fn the_hosts_refusable_addresses() {
        for yes in ["192.168.1.1", "10.0.0.2", "2001:db8::5", "fd00::1"] {
            assert!(refusable(yes.parse().unwrap()), "{yes}");
        }
        for no in ["127.0.0.1", "224.0.0.1", "::1", "fe80::1", "ff02::1"] {
            assert!(!refusable(no.parse().unwrap()), "{no}");
        }
    }

    /// An OpenConnect zone's user namespace gets one id more, the client's,
    /// from the next subordinate id (review 2026-09-27); every zone gets the
    /// bridge's, the third (stage 2 of the container design): uid 2, and as
    /// a gid the subordinate id itself.
    #[test]
    fn only_an_openconnect_zone_maps_the_clients_id() {
        assert_eq!(
            map_args(42, 100_000, 1000, false, false).unwrap(),
            ["42", "0", "100000", "1", "1000", "1000", "1", "2", "100002", "1"]
        );
        assert_eq!(
            map_args(42, 100_000, 1000, true, false).unwrap(),
            [
                "42", "0", "100000", "1", "1000", "1000", "1", "1", "100001", "1", "2", "100002",
                "1"
            ]
        );
        assert_eq!(
            map_args(42, 100_000, 100, false, true).unwrap(),
            ["42", "0", "100000", "1", "100", "100", "1", "100002", "100002", "1"]
        );
        // A user whose own id is the client's cannot have both.
        assert!(map_args(42, 100_000, CLIENT_ID, true, false).is_err());
        assert!(map_args(42, 100_000, CLIENT_ID, false, false).is_ok());
        // Nor one whose own id is the bridge's.
        assert!(map_args(42, 100_000, 2, false, false).is_err());
        assert!(map_args(42, 100_000, 2, false, true).is_ok());
        assert!(map_args(42, 100_000, 100_002, false, true).is_err());
    }

    /// The ping range a zone mapped so writes takes the user's group and
    /// passt's, in one order inside and out (stage 2, 2026-09-27).
    #[test]
    fn a_zones_ping_range_takes_the_bridge_too() {
        let uids = map_args(42, 100_000, 1000, true, true).unwrap();
        let gid_map: String = uids[1..]
            .chunks(3)
            .map(|line| format!("{} {} {}\n", line[0], line[1], line[2]))
            .collect();
        assert_eq!(ping_range(&gid_map).as_deref(), Some("1000 100002"));
        assert_eq!(crate::bridge::bridge_gid(&gid_map), Some(100_002));
    }

    /// An instance's root is the fourth subordinate id, never a zone's
    /// (J3 of the container design): the user's own id onto itself as in a
    /// zone.
    #[test]
    fn an_instances_root_is_not_a_zones() {
        assert_eq!(
            instance_map_args(42, 100_000, 1000),
            ["42", "0", "100003", "1", "1000", "1000", "1"]
        );
        assert_ne!(
            instance_map_args(42, 100_000, 1000)[2],
            map_args(42, 100_000, 1000, true, false).unwrap()[2]
        );
    }

    #[test]
    fn a_ranges_count_is_its_third_field() {
        let text = "bob:200000:65536\nalice:100000:3\n1000:300000:65536\n";
        assert_eq!(subid_count_in(text, "alice", 1001), Some(3));
        assert_eq!(subid_count_in(text, "bob", 1002), Some(65536));
        // By the numeric id too, as shadow reads it.
        assert_eq!(subid_count_in(text, "carol", 1000), Some(65536));
        assert_eq!(subid_count_in(text, "dave", 1003), None);
        assert_eq!(subid_count_in("alice:100000\n", "alice", 1001), None);
        assert_eq!(subid_count_in("alice:100000:x\n", "alice", 1001), None);
    }

    fn tools_with_every_path() -> Tools {
        Tools {
            ip: PathBuf::from("/t/ip"),
            awg: PathBuf::from("/t/awg"),
            wg: PathBuf::from("/t/wg"),
            pasta: PathBuf::from("/t/pasta"),
            passt: PathBuf::from("/t/passt"),
            nft: PathBuf::from("/t/nft"),
            openconnect: PathBuf::from("/t/openconnect"),
            dbus_proxy: PathBuf::from("/t/xdg-dbus-proxy"),
            opener: PathBuf::from("/t/opener"),
            kdialog: PathBuf::from("/t/kdialog"),
            window: PathBuf::from("/t/window"),
            runner: PathBuf::from("/t/cellward"),
        }
    }

    /// The keeper's re-exec gets the very tools it was given, read back by
    /// the parser the unit's line is read with; one left out stays out.
    #[test]
    fn the_keepers_tools_survive_its_re_exec() {
        let tools = tools_with_every_path();
        let mut argv = tool_flags(&tools);
        argv.push(OsString::from("work"));
        let parsed = Args::parse(&argv).unwrap();
        assert_eq!(parsed.tools, tools);
        assert_eq!(parsed.name, OsString::from("work"));
        let without_window = Tools {
            window: PathBuf::new(),
            ..tools_with_every_path()
        };
        let flags = tool_flags(&without_window);
        assert!(!flags.contains(&OsString::from("--window")));
        let mut argv = flags;
        argv.push(OsString::from(":tmp:vpn-profile-x"));
        assert_eq!(Args::parse(&argv).unwrap().tools, without_window);
    }

    #[test]
    fn frozen_settings_are_read_as_written() {
        let text = "hermetic=true\nnix_daemon=false\nhost_files_writable=true\n";
        assert!(frozen(text, "hermetic"));
        assert!(!frozen(text, "nix_daemon"));
        assert!(frozen(text, "host_files_writable"));
        // Not there, or not `true`: off.
        assert!(!frozen(text, "audio_manager"));
        assert!(!frozen("hermetic=yes\n", "hermetic"));
    }

    fn zone_for(instance: Option<InstanceInfo>) -> Zone {
        Zone {
            name: OsString::from("nl"),
            dir: PathBuf::from("/h/.local/state/vpn-zones/nl"),
            home: PathBuf::from("/h"),
            tools: tools_with_every_path(),
            hermetic: true,
            nix_daemon: false,
            host_files_writable: false,
            audio_manager: false,
            instance,
        }
    }

    /// A zone resolves exactly as before the instances: its own name and
    /// directory for its settings and its Wayland sockets, and the keeps it
    /// always had — pinned, so that the instance mode changes nothing of it.
    #[test]
    fn a_zone_is_what_it_was_and_an_instance_its_networks() {
        let zone = zone_for(None);
        assert_eq!(zone.settings_name(), "nl");
        assert_eq!(
            zone.settings_dir(),
            Path::new("/h/.local/state/vpn-zones/nl")
        );
        assert_eq!(zone.wayland_dir(), "nl");
        assert_eq!(
            zone.keeps(),
            vec![
                (".throwaway".to_owned(), true),
                (".running".to_owned(), false)
            ]
        );
        assert!(instance_helper_args(&zone).is_empty());

        let info = |id: &str, storage: Option<&str>| InstanceInfo {
            id: id.to_owned(),
            network: "offline".to_owned(),
            network_dir: PathBuf::from("/h/.local/state/vpn-zones/offline"),
            who: crate::instance::who_of(id),
            storage: storage.map(PathBuf::from),
            userns: Some((4, 4_026_532_000)),
        };
        let work = zone_for(Some(info(
            "work",
            Some("/h/.local/state/vpn-profiles/work"),
        )));
        assert_eq!(work.settings_name(), "offline");
        assert_eq!(
            work.settings_dir(),
            Path::new("/h/.local/state/vpn-zones/offline")
        );
        assert_eq!(work.wayland_dir(), crate::instance::key("work"));
        // Its storage is not the project's state: nothing of that is kept,
        // `.running` least of all.
        assert!(work.keeps().is_empty());
        assert_eq!(
            instance_helper_args(&work),
            [
                "--container",
                "work",
                "--network-file",
                "/h/.local/state/vpn-zones/nl/network",
                "--userns",
                "4:4026532000"
            ]
            .map(OsString::from)
            .to_vec()
        );
        // A throwaway keeps its own layer, writable, and nothing else.
        let tmp = zone_for(Some(info(
            ":tmp:vpn-profile-x",
            Some("/h/.local/state/vpn-zones/.throwaway/vpn-profile-x"),
        )));
        assert_eq!(
            tmp.keeps(),
            vec![(".throwaway/vpn-profile-x".to_owned(), true)]
        );
        assert_eq!(instance_helper_args(&tmp)[1], "?");
        let main = zone_for(Some(info("main:offline", None)));
        assert!(main.keeps().is_empty());
        assert_eq!(instance_helper_args(&main)[1], "main");
    }

    /// The client's root takes the devices, its directory and the files it is
    /// named, and nothing of the host that is not asked for (review
    /// 2026-09-27, second opinion): no `/home`, `/run`, `/var`, `/proc`.
    #[test]
    fn the_clients_root_has_only_what_it_is_given() {
        let base = std::env::temp_dir().join(format!("oc-root-{}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        let root = base.join("root");
        let own = base.join("own");
        fs::create_dir_all(&own).unwrap();
        let named = base.join("elsewhere/program");
        fs::create_dir_all(named.parent().unwrap()).unwrap();
        fs::write(&named, b"").unwrap();
        let plan = client_root(&root, &own, &[named.clone(), PathBuf::from("/usr/bin/env")]);
        let _ = fs::remove_dir_all(&base);
        let plan = plan.unwrap();

        let inside = |p: &Path| root.join(p.strip_prefix("/").unwrap());
        let binds: Vec<(PathBuf, PathBuf)> = plan
            .steps
            .iter()
            .filter_map(|step| match step {
                RootStep::Bind { from, to } => Some((
                    PathBuf::from(OsStr::from_bytes(from.as_bytes())),
                    PathBuf::from(OsStr::from_bytes(to.as_bytes())),
                )),
                _ => None,
            })
            .collect();
        let bound = |from: &Path| binds.iter().any(|(f, t)| f == from && *t == inside(from));
        assert!(bound(Path::new("/dev/null")), "{binds:?}");
        assert!(bound(own.as_path()), "{binds:?}");
        assert!(bound(named.as_path()), "{binds:?}");
        // A file a tree already holds is not bound again.
        if Path::new("/usr").is_dir() && !fs::symlink_metadata("/usr").unwrap().is_symlink() {
            assert!(bound(Path::new("/usr")));
            assert!(!binds.iter().any(|(f, _)| f == Path::new("/usr/bin/env")));
        }
        // (The two given here live wherever the temporary directory is — a
        // nix-shell's is under /run.)
        for never in ["/home", "/run", "/var", "/proc", "/sys", "/root"] {
            assert!(
                !binds
                    .iter()
                    .filter(|(f, _)| *f != own && *f != named)
                    .any(|(f, _)| f.starts_with(never)),
                "{never} in the client's root: {binds:?}"
            );
        }
        // Every step lands inside the root.
        for (_, to) in &binds {
            assert!(to.starts_with(&root), "{to:?}");
        }
        assert_eq!(plan.home.as_bytes(), own.as_os_str().as_bytes());
    }

    /// The client's `--script` has to be reachable by an id that owns none
    /// of the way to it.
    #[test]
    fn a_script_under_a_closed_directory_is_not_runnable_by_the_client() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("oc-runnable-{}", std::process::id()));
        let closed = base.join("closed");
        fs::create_dir_all(&closed).unwrap();
        let exe = closed.join("core");
        fs::write(&exe, b"").unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&closed, fs::Permissions::from_mode(0o755)).unwrap();
        // Whether the temporary directory's own way is open (a nix-shell's is
        // under a runtime directory that is not) decides the open case.
        let reachable = runnable_by_anyone(&base);
        let open = runnable_by_anyone(&exe);
        fs::set_permissions(&closed, fs::Permissions::from_mode(0o700)).unwrap();
        let shut = runnable_by_anyone(&exe);
        fs::set_permissions(&closed, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o750)).unwrap();
        let private = runnable_by_anyone(&exe);
        let _ = fs::remove_dir_all(&base);
        assert_eq!(open, reachable);
        assert!(!shut);
        assert!(!private);
    }

    /// The user's own groups, the line mapped to itself: a range over the
    /// zone's root too would be empty to the kernel (100000 > 100 outside).
    #[test]
    fn ping_is_for_the_groups_of_the_zone() {
        assert_eq!(
            ping_range("         0     100000          1\n       100        100          1\n")
                .as_deref(),
            Some("100 100")
        );
        assert_eq!(
            ping_range("0 100000 1\n100 100 3\n").as_deref(),
            Some("100 102")
        );
        assert_eq!(
            ping_range("0 1000 65536\n"),
            None,
            "nothing of the user's own"
        );
        assert_eq!(ping_range(""), None);
        assert_eq!(ping_range("100 100 0\nbroken\n"), None);
    }

    #[test]
    fn no_zone_gets_the_compositor_or_its_ipc() {
        for name in [
            "wayland-1",
            "wayland-1.lock",
            "niri.wayland-1.1798.sock",
            "sway-ipc.1000.4242.sock",
            "hypr",
            "i3",
            "vpn-zones",
        ] {
            for raw in [false, true] {
                assert!(!runtime_entry_kept(name, false, raw), "{name}");
                assert!(!runtime_entry_kept(name, true, raw), "{name}");
            }
        }
        // An ordinary zone keeps the rest, the bus and systemd --user included;
        // a hermetic one only the sound servers and the document portal.
        for name in [
            "bus",
            "systemd",
            "gnupg",
            "pipewire-0",
            "noctalia-wayland-1.sock",
        ] {
            assert!(runtime_entry_kept(name, false, false), "{name}");
        }
        assert!(runtime_entry_kept("doc", true, false));
        // The host's raw PipeWire: an ordinary zone keeps it (it has
        // systemd --user anyway), a hermetic one only as an audio manager —
        // its own is the restricted socket of `pw_context`.
        assert!(runtime_entry_kept("pipewire-0", false, false));
        assert!(!runtime_entry_kept("pipewire-0", true, false));
        assert!(runtime_entry_kept("pipewire-0", true, true));
        // The sound server's control socket is never the host's own: every
        // zone gets the filter's in its place (`pulse_filter`).
        assert!(!runtime_entry_kept("pulse", true, false));
        assert!(!runtime_entry_kept("pulse", false, false));
        // A camera's nodes, and nothing that merely starts like one.
        assert!(is_capture_node("video0") && is_capture_node("media12"));
        for capture in ["v4l-subdev3", "v4l-touch0", "radio1", "vbi0", "swradio2"] {
            assert!(is_capture_node(capture), "{capture}");
        }
        assert!(
            !is_capture_node("video")
                && !is_capture_node("videox")
                && !is_capture_node("vhost-net")
        );
        // Default-deny: the basics and the GPU kept, whatever else there is
        // covered — by no list of names, so a device nobody thought of too.
        for kept in [
            "/dev/null",
            "/dev/zero",
            "/dev/full",
            "/dev/random",
            "/dev/urandom",
            "/dev/tty",
            "/dev/ptmx",
            "/dev/fuse",
            "/dev/ntsync",
            "/dev/dri/card1",
            "/dev/dri/renderD128",
            "/dev/nvidia0",
            "/dev/nvidiactl",
            "/dev/nvidia-modeset",
            "/dev/nvidia-uvm",
        ] {
            assert!(allowed_node(Path::new(kept)), "{kept}");
        }
        for hidden in [
            "/dev/kvm",
            "/dev/vhost-net",
            "/dev/vhost-vsock",
            "/dev/net/tun",
            "/dev/vfio/vfio",
            "/dev/kmsg",
            "/dev/uinput",
            "/dev/udmabuf",
            "/dev/tty1",
            "/dev/console",
            "/dev/hidraw0",
            "/dev/input/event3",
            "/dev/bus/usb/001/002",
            "/dev/nvidia-caps/nvidia-cap2",
            "/dev/nvidiax",
            "/dev/snd/pcmC0D0c",
            "/dev/sda",
            "/dev/weird0",
            "/dev/nullx",
            "/devnull",
            "/tmp/null",
        ] {
            assert!(!allowed_node(Path::new(hidden)), "{hidden}");
        }
        // Watched after they go: what a grant or the camera may have given.
        for guarded in [
            "/dev/hidraw3",
            "/dev/video0",
            "/dev/input/js0",
            "/dev/bus/usb/001/002",
        ] {
            assert!(guarded_path(Path::new(guarded)), "{guarded}");
        }
        for not in ["/dev/tty1", "/dev/sda", "/dev/weird0"] {
            assert!(!guarded_path(Path::new(not)), "{not}");
        }
        // PipeWire's unrestricted socket, for the session manager: no zone,
        // an audio manager neither.
        for raw in [false, true] {
            assert!(!runtime_entry_kept("pipewire-0-manager", false, raw));
            assert!(!runtime_entry_kept("pipewire-0-manager", true, raw));
        }
        for name in ["bus", "systemd", "gnupg", "niri", "pipewire-1"] {
            assert!(!runtime_entry_kept(name, true, true), "{name}");
        }
        // A name that only looks like niri's is not hidden by accident.
        assert!(runtime_entry_kept("niri-config.kdl", false, false));
    }

    /// W7 (2026-09-28): a shell's own IPC in the runtime directory is out of
    /// every zone's, an ordinary one's too — and only what is named.
    #[test]
    fn no_zone_gets_a_shells_ipc() {
        for name in [
            "quickshell",
            "astal",
            "ironbar-ipc.sock",
            "eww-server_5f1c0a8e2b",
        ] {
            assert!(shell_private(name), "{name}");
            for raw in [false, true] {
                assert!(!runtime_entry_kept(name, false, raw), "{name}");
                assert!(!runtime_entry_kept(name, true, raw), "{name}");
            }
        }
        for name in [
            "quickshell-cache",
            "astal.conf",
            "eww",
            "ironbar",
            "bus",
            "doc",
        ] {
            assert!(!shell_private(name), "{name}");
        }
        assert!(runtime_entry_kept("quickshell-cache", false, false));
    }

    #[test]
    fn where_the_sound_server_loads_code_from_is_made_before_it_is_covered() {
        // The zones' PipeWire policy is a WirePlumber script: a place it is
        // looked for that a zone could write — or make, being missing — is a
        // policy of the zone's own (review 2026-09-25). Created beforehand,
        // then covered: an entry point, not "where it exists".
        for dir in [
            ".config/pipewire",
            ".config/wireplumber",
            ".local/share/wireplumber",
            ".local/state/wireplumber",
        ] {
            assert!(ENTRY_POINTS.contains(&dir), "{dir}");
            assert!(!HOST_RUNS_IN_ZONES.contains(&dir), "{dir} twice");
        }
    }

    fn argv(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn tool_paths_are_flags_and_the_zone_name_is_positional() {
        let parsed = Args::parse(&argv(&[
            "--ip",
            "/n/ip",
            "--awg",
            "/n/awg",
            "--wg",
            "/n/wg",
            "--pasta",
            "/n/pasta",
            "--nft",
            "/n/nft",
            "--openconnect",
            "/n/openconnect",
            "--dbus-proxy",
            "/n/xdg-dbus-proxy",
            "--opener",
            "/n/xdg-open",
            "--kdialog",
            "/n/kdialog",
            "--runner",
            "/p/bin/cellward",
            "nl",
        ]))
        .unwrap();
        assert_eq!(parsed.tools.kdialog, PathBuf::from("/n/kdialog"));
        assert_eq!(parsed.tools.runner, PathBuf::from("/p/bin/cellward"));
        assert_eq!(parsed.name, OsString::from("nl"));
        assert_eq!(parsed.tools.ip, PathBuf::from("/n/ip"));
        assert_eq!(parsed.tools.awg, PathBuf::from("/n/awg"));
        assert_eq!(parsed.tools.wg, PathBuf::from("/n/wg"));
        assert_eq!(parsed.tools.pasta, PathBuf::from("/n/pasta"));
        assert_eq!(parsed.tools.nft, PathBuf::from("/n/nft"));
        assert_eq!(parsed.tools.openconnect, PathBuf::from("/n/openconnect"));
        assert_eq!(parsed.tools.dbus_proxy, PathBuf::from("/n/xdg-dbus-proxy"));
        assert_eq!(parsed.tools.opener, PathBuf::from("/n/xdg-open"));
    }

    #[test]
    fn bus_rules_use_only_wildcards_the_proxy_accepts() {
        for rule in SYSTEM_BUS_RULES
            .iter()
            .chain(SESSION_BUS_RULES.iter())
            .filter(|r| r.contains('='))
        {
            let name = rule
                .split_once('=')
                .map(|(_, rest)| rest.split('=').next().unwrap_or(rest))
                .unwrap_or("");
            // `-*` only on OWN, and only with our patched proxy.
            let bare = match name.strip_suffix("-*") {
                Some(b) => {
                    assert!(rule.starts_with("--own="), "{rule}");
                    b
                }
                None => name.strip_suffix(".*").unwrap_or(name),
            };
            assert!(!bare.contains('*'), "{rule}");
            assert!(
                bare.split('.').count() >= 2
                    && bare
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-'),
                "{rule}"
            );
        }
        assert!(!SESSION_BUS_RULES.iter().any(|r| r.contains("systemd1")));
        assert!(!SESSION_BUS_RULES.iter().any(|r| r.contains("secrets")));
        // Owning a whole org.kde.* would own KWallet's name as well.
        assert!(!SESSION_BUS_RULES.contains(&"--own=org.kde.*"));
        // And a whole org.freedesktop.* the portals' and the notifications'.
        assert!(!SESSION_BUS_RULES.contains(&"--own=org.freedesktop.*"));
        for tray in TRAY_ITEM_NAMES {
            assert!(SESSION_BUS_RULES.contains(&tray), "{tray}");
        }
    }

    #[test]
    fn the_system_bus_filter_names_what_is_allowed_and_nothing_else() {
        assert_eq!(SYSTEM_BUS_RULES[0], "--filter");
        let talks: Vec<&str> = SYSTEM_BUS_RULES
            .iter()
            .filter(|r| r.starts_with("--talk=") || r.starts_with("--own="))
            .copied()
            .collect();
        assert_eq!(talks, ["--talk=org.freedesktop.UPower"]);
        // login1: calls only, and only these.
        for rule in SYSTEM_BUS_RULES.iter().filter(|r| r.contains("login1")) {
            assert!(rule.starts_with("--call=org.freedesktop.login1="), "{rule}");
            assert!(
                rule.contains("Manager.Inhibit@")
                    || rule.contains("DBus.Properties.Get")
                    || rule.contains("Introspectable.Introspect@"),
                "{rule}"
            );
        }
        for denied in [
            "NetworkManager",
            "hostname1",
            "resolve1",
            "machine1",
            "timedate1",
        ] {
            assert!(
                !SYSTEM_BUS_RULES.iter().any(|r| r.contains(denied)),
                "{denied}"
            );
        }
    }

    #[test]
    fn missing_flags_fall_back_to_the_path() {
        let parsed = Args::parse(&argv(&["nl"])).unwrap();
        assert_eq!(parsed.tools, Tools::default());
        assert_eq!(parsed.tools.ip, PathBuf::from("ip"));

        // Order is free, and a name may start with a single dash.
        let parsed = Args::parse(&argv(&["-nl", "--pasta", "/n/pasta"])).unwrap();
        assert_eq!(parsed.name, OsString::from("-nl"));
        assert_eq!(parsed.tools.pasta, PathBuf::from("/n/pasta"));
    }

    #[test]
    fn broken_command_lines_are_rejected() {
        assert_eq!(Args::parse(&argv(&[])), Err(ArgError::MissingName));
        assert_eq!(Args::parse(&argv(&[""])), Err(ArgError::MissingName));
        assert_eq!(
            Args::parse(&argv(&["--ip", "/n/ip"])),
            Err(ArgError::MissingName)
        );
        assert_eq!(
            Args::parse(&argv(&["--ip"])),
            Err(ArgError::MissingValue("--ip".to_string()))
        );
        assert_eq!(
            Args::parse(&argv(&["--wat", "x", "nl"])),
            Err(ArgError::UnknownFlag("--wat".to_string()))
        );
        assert_eq!(
            Args::parse(&argv(&["nl", "de"])),
            Err(ArgError::ExtraArguments)
        );
    }

    #[test]
    fn both_shapes_of_default_route_are_read_by_keyword() {
        // pasta: no gateway, and "link" sits where a positional parser used to
        // look for the interface name.
        let pasta = parse_default_route("default dev hostif scope link");
        assert_eq!(pasta.dev.as_deref(), Some("hostif"));
        assert_eq!(pasta.via, None);

        let lan = parse_default_route(
            "default via 192.168.1.1 dev enp4s0 proto dhcp src 192.168.1.42 metric 100",
        );
        assert_eq!(lan.dev.as_deref(), Some("enp4s0"));
        assert_eq!(lan.via.as_deref(), Some("192.168.1.1"));

        let v6 = parse_default_route("default via fe80::1 dev hostif metric 1024 pref medium");
        assert_eq!(v6.dev.as_deref(), Some("hostif"));
        assert_eq!(v6.via.as_deref(), Some("fe80::1"));

        // No route at all: both fields empty, and the uplink fails loudly.
        assert_eq!(parse_default_route(""), DefaultRoute::default());
    }

    #[test]
    fn ipv6_is_either_tunnelled_or_left_without_a_default() {
        // A kernel without v6: nothing to do.
        assert_eq!(v6_plan(false, false), V6Plan::NoKernel);
        assert_eq!(v6_plan(false, true), V6Plan::NoKernel);
        // The tunnel carries v6 — the default goes into it.
        assert_eq!(v6_plan(true, true), V6Plan::IntoTunnel);
        // It does not: no default at all. There is nothing else in this
        // namespace for the family to leak through, so no sysctl is needed.
        assert_eq!(v6_plan(true, false), V6Plan::CloseDefault);
    }

    #[test]
    fn the_zone_resolves_hosts_with_files_and_dns_only() {
        let nixos = "\
passwd:    files systemd
group:     files [success=merge] systemd
# a comment about hosts: mdns
hosts:     mymachines resolve [!UNAVAIL=return] files myhostname dns
networks:  files
";
        let zone = zone_nsswitch(nixos);
        assert!(zone.contains("\nhosts: files dns\n"), "{zone}");
        assert!(!zone.contains("resolve"), "{zone}");
        assert!(!zone.contains("mymachines"), "{zone}");
        // Everything else stays, the comment included.
        assert!(zone.starts_with("passwd:    files systemd\n"), "{zone}");
        assert!(zone.contains("# a comment about hosts: mdns\n"), "{zone}");
        assert!(zone.contains("networks:  files\n"), "{zone}");
        // No hosts line: one is added. Two: one remains.
        assert!(zone_nsswitch("passwd: files\n").ends_with("hosts: files dns\n"));
        assert_eq!(
            zone_nsswitch("hosts: mdns dns\nhosts: resolve\n"),
            "hosts: files dns\n"
        );
        // "hostsfoo:" is not a hosts line.
        assert!(zone_nsswitch("hostsfoo: x\n").contains("hostsfoo: x\n"));
    }

    #[test]
    fn resolv_conf_falls_back_to_public_resolvers() {
        let (text, defaulted) = resolv_conf(&[]);
        assert!(defaulted);
        assert_eq!(text, "nameserver 1.1.1.1\nnameserver 9.9.9.9\n");

        let (text, defaulted) = resolv_conf(&["10.8.1.1".to_string(), "fd00::1".to_string()]);
        assert!(!defaulted);
        assert_eq!(text, "nameserver 10.8.1.1\nnameserver fd00::1\n");

        // A DNS= line of nothing but separators is the same as no line at all.
        let (_, defaulted) = resolv_conf(&[String::new()]);
        assert!(defaulted);
    }

    #[test]
    fn a_gateways_search_domain_becomes_one_more_line_and_no_more() {
        let (text, _) =
            resolv_conf_with_search(&["10.5.0.1".to_string()], Some("corp.example.org"));
        assert_eq!(text, "nameserver 10.5.0.1\nsearch corp.example.org\n");

        // No domain, no line — and an empty one is no domain.
        let (text, _) = resolv_conf_with_search(&["10.5.0.1".to_string()], None);
        assert_eq!(text, "nameserver 10.5.0.1\n");
        let (text, _) = resolv_conf_with_search(&["10.5.0.1".to_string()], Some(""));
        assert_eq!(text, "nameserver 10.5.0.1\n");

        // A gateway that names no resolver at all still gets the project's
        // default ones — reachable through the tunnel and nowhere else.
        let (text, defaulted) = resolv_conf_with_search(&[], Some("corp.example.org"));
        assert!(defaulted);
        assert_eq!(
            text,
            "nameserver 1.1.1.1\nnameserver 9.9.9.9\nsearch corp.example.org\n"
        );
    }

    #[test]
    fn the_openconnect_mirror_says_connected_only_while_the_interface_is_up() {
        let up = "5: awg0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1412 qdisc fq_codel \
                  state UNKNOWN mode DEFAULT group default qlen 500\\    link/none";
        let addr = "awg0             UNKNOWN        10.5.0.7/32";
        assert_eq!(
            oc_mirror(up, addr),
            "interface: awg0\n  backend: openconnect\n  connected: yes\n  address: 10.5.0.7/32\n"
        );

        // Down, and gone, are different answers and neither of them says
        // "connected" — which is the word `vpn-zone check` looks for.
        let down = "5: awg0: <POINTOPOINT,MULTICAST,NOARP> mtu 1412 qdisc noop state DOWN mode \
                    DEFAULT group default qlen 500\\    link/none";
        assert!(oc_mirror(down, "").contains("disconnected: the tunnel interface is down"));
        assert!(!oc_mirror(down, "").contains("connected: yes"));
        assert!(oc_mirror("", "").contains("disconnected: the tunnel interface is gone"));

        // LOWER_UP without UP is not up: a substring search for "UP" would have
        // said otherwise.
        let carrier_only = "5: awg0: <POINTOPOINT,NOARP,LOWER_UP> mtu 1412 state DOWN";
        assert!(oc_mirror(carrier_only, "").contains("disconnected"));

        // An interface that is up but has no address yet is still connected;
        // the address line is simply absent.
        assert_eq!(
            oc_mirror(up, "awg0             UNKNOWN"),
            "interface: awg0\n  backend: openconnect\n  connected: yes\n"
        );
    }

    #[test]
    fn an_openconnect_uplink_may_talk_to_its_gateway_and_to_nothing_else() {
        let backend = Backend::Oc(Box::new(OcZone {
            cfg: OcConfig::parse(b"[OpenConnect]\nServer = vpn.example.org:4443\n").unwrap(),
            addr: "198.51.100.7".parse().unwrap(),
        }));
        // No port in the rule, and that is the one place this backend is wider
        // than WireGuard's: DTLS goes to a UDP port the server picks, and the
        // number is not known before the session exists. What the rule says is
        // still "this gateway and nothing else in the world".
        assert_eq!(
            uplink_ruleset(&backend.sockets()),
            concat!(
                "table inet vpnzone {\n",
                "\tchain output {\n",
                "\t\ttype filter hook output priority filter; policy drop;\n",
                "\t\toifname \"lo\" accept\n",
                "\t\tip daddr 198.51.100.7 accept\n",
                "\t}\n",
                "}\n",
            )
        );

        // And a WireGuard zone's rules are unchanged by any of this.
        let wg = Backend::Wg(
            WgConfig::parse_str(
                "[Interface]\nPrivateKey = k\n[Peer]\nEndpoint = 198.51.100.7:51820\n",
            )
            .unwrap(),
        );
        assert!(uplink_ruleset(&wg.sockets()).contains("ip daddr 198.51.100.7 udp dport 51820"));
    }

    /// A guard over a security invariant rather than over an algorithm: every
    /// entry in this table is a measured DNS leak (`docs/GOTCHAS.md` §3), and
    /// dropping one gives every program in every zone a resolver in the host's
    /// network back. The behaviour itself is asserted where it can be — inside
    /// a VM with systemd-resolved running (`tests/vm.nix`).
    #[test]
    fn every_known_host_resolver_socket_is_in_the_table() {
        let all: Vec<&str> = RESOLVER_DIRS
            .iter()
            .flat_map(|g| g.iter().copied())
            .collect();
        for must in [
            // nsncd, what NixOS runs.
            "/run/nscd",
            // systemd-resolved's varlink socket: nss-resolve, and `resolve`
            // comes BEFORE `dns` in nsswitch.conf.
            "/run/systemd/resolve",
            // nss-mdns.
            "/run/avahi-daemon",
        ] {
            assert!(all.contains(&must), "{must} is no longer hidden from zones");
        }
    }

    #[test]
    fn endpoint_literals_are_told_from_names() {
        let literal = endpoint_host_kind(&Endpoint::parse("198.51.100.7:51820").unwrap());
        assert_eq!(
            literal,
            EndpointHostKind::Literal("198.51.100.7".parse::<IpAddr>().unwrap())
        );

        // Bracketed and bare v6 literals: neither must end up as a hostname,
        // hex digits or not.
        let bracketed = endpoint_host_kind(&Endpoint::parse("[fd00::1]:51820").unwrap());
        assert_eq!(
            bracketed,
            EndpointHostKind::Literal("fd00::1".parse::<IpAddr>().unwrap())
        );
        let bare = endpoint_host_kind(&Endpoint::parse("fd00:dead:beef::1").unwrap());
        assert_eq!(
            bare,
            EndpointHostKind::Literal("fd00:dead:beef::1".parse::<IpAddr>().unwrap())
        );

        let name = endpoint_host_kind(&Endpoint::parse("vpn.example.org:51820").unwrap());
        assert_eq!(name, EndpointHostKind::Name("vpn.example.org".to_string()));
    }

    #[test]
    fn a_literal_endpoint_survives_the_resolver_unchanged() {
        // What `prepare` does to a config that needs no DNS at all: the text
        // handed to `setconf` must still carry the very same endpoint.
        let text = "[Interface]\n\
                    PrivateKey = U1lOVEhFVElDLUtFWS1BLURPLU5PVC1VU0UtMDAwMDAwMDA9\n\
                    [Peer]\n\
                    Endpoint = 198.51.100.7:51820\n";
        let mut cfg = WgConfig::parse_str(text).unwrap();
        let resolved = cfg.resolve_endpoints(resolve_endpoint);
        assert_eq!(resolved.len(), 1);
        assert_eq!(
            resolved[0].addr,
            Some("198.51.100.7".parse::<IpAddr>().unwrap())
        );
        assert!(cfg.to_setconf().contains("Endpoint = 198.51.100.7:51820"));
    }

    #[test]
    fn a_handshake_needs_a_nonzero_timestamp() {
        assert!(handshake_seen("peerkey\t1758000000\n"));
        assert!(!handshake_seen("peerkey\t0\n"));
        // Several peers, one of them alive.
        assert!(handshake_seen("a\t0\nb\t1758000000\n"));
        // Empty output is "no handshake", not "success" — the bash pipeline
        // used to report the opposite.
        assert!(!handshake_seen(""));
        assert!(!handshake_seen("\n \n"));
        assert!(!handshake_seen("nonsense\n"));
    }

    #[test]
    fn the_app_ruleset_lets_nothing_out_but_the_tunnel() {
        // `oifname`, not `oif`: the rule must not depend on an interface index
        // that does not exist yet when the ruleset is loaded.
        assert_eq!(
            app_ruleset(),
            concat!(
                "table inet vpnzone {\n",
                "\tchain output {\n",
                "\t\ttype filter hook output priority filter; policy drop;\n",
                "\t\toifname \"lo\" accept\n",
                "\t\toifname \"awg0\" accept\n",
                "\t}\n",
                "}\n",
            )
        );
    }

    /// The zone's refusal of its local addresses to the bridge's passt: the
    /// loopback and link-local ranges always, the tunnel's addresses, no
    /// overlap and no repeat, ahead of the accepts (the container design of
    /// 2026-09-27; core nf_tables only).
    #[test]
    fn the_bridge_is_refused_every_local_address_first() {
        let addresses: Vec<IpAddr> = [
            "10.99.0.2",
            "fd99::2",
            "127.0.0.1",
            "::1",
            "fe80::1234",
            "10.99.0.2",
        ]
        .iter()
        .map(|a| a.parse().unwrap())
        .collect();
        let rules = bridge_refusal_rules(2, &addresses);
        assert_eq!(
            rules,
            [
                "meta skuid 2 ip daddr { 127.0.0.0/8, 10.99.0.2 } drop",
                "meta skuid 2 ip6 daddr { ::1, fe80::/10, fd99::2 } drop",
            ]
        );
        // Nothing but core expressions: no fib, no socket match.
        for rule in &rules {
            assert!(!rule.contains("fib") && !rule.contains("socket"), "{rule}");
        }
        assert_eq!(
            bridge_refusal_rules(2, &[]),
            [
                "meta skuid 2 ip daddr { 127.0.0.0/8 } drop",
                "meta skuid 2 ip6 daddr { ::1, fe80::/10 } drop",
            ]
        );
        let ruleset = app_ruleset_with(&rules);
        let drop = ruleset.find("meta skuid 2 ip daddr").unwrap();
        let accept = ruleset.find("oifname \"lo\" accept").unwrap();
        assert!(drop < accept, "{ruleset}");
    }

    /// A container instance's ruleset: out through the tap from this
    /// attach's addresses only, and with an epoch from that epoch's cgroup
    /// only (the container design of 2026-09-27, §3.1).
    #[test]
    fn an_instance_goes_out_from_its_own_address_only() {
        let a4: std::net::Ipv4Addr = "10.254.3.4".parse().unwrap();
        let a6: std::net::Ipv6Addr = "fd63:656c:6c77::1:2".parse().unwrap();
        assert_eq!(
            instance_ruleset(None, a4, None).unwrap(),
            concat!(
                "table inet vpnzone {\n",
                "\tchain output {\n",
                "\t\ttype filter hook output priority filter; policy drop;\n",
                "\t\toifname \"lo\" accept\n",
                "\t\ticmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept\n",
                "\t\toifname \"awg0\" ip saddr 10.254.3.4 accept\n",
                "\t}\n",
                "}\n",
            )
        );
        let path = "/user.slice/user-1000.slice/user@1000.service/app.slice/\
                    vpn-zone-container@work\\x2d2.service/e3";
        assert_eq!(
            instance_ruleset(Some((6, path)), a4, Some(a6)).unwrap(),
            concat!(
                "table inet vpnzone {\n",
                "\tchain output {\n",
                "\t\ttype filter hook output priority filter; policy drop;\n",
                "\t\toifname \"lo\" accept\n",
                "\t\ticmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept\n",
                "\t\toifname \"awg0\" ip saddr 10.254.3.4 socket cgroupv2 level 6 ",
                "\"user.slice/user-1000.slice/user@1000.service/app.slice/",
                "vpn-zone-container@work\\x2d2.service/e3\" accept\n",
                "\t\toifname \"awg0\" ip6 saddr fd63:656c:6c77::1:2 socket cgroupv2 level 6 ",
                "\"user.slice/user-1000.slice/user@1000.service/app.slice/",
                "vpn-zone-container@work\\x2d2.service/e3\" accept\n",
                "\t}\n",
                "}\n",
            )
        );
        for bad in ["", "/", "relative/e1", "/a\"b/e1", "/a\nb/e1"] {
            assert!(
                instance_ruleset(Some((2, bad)), a4, None).is_err(),
                "{bad:?}"
            );
        }
    }

    /// Between a switch's cut and its next attach (stage 4): loopback, and
    /// no tap's accept at all — and a relay's walled rules replace it whole.
    #[test]
    fn a_switchs_break_closes_an_instance_to_loopback() {
        let closed = instance_closed_ruleset();
        assert!(closed.contains("policy drop;"), "{closed}");
        assert!(closed.contains("oifname \"lo\" accept"), "{closed}");
        assert!(!closed.contains(TUN_IFACE), "{closed}");
        assert!(
            replacing_table(&closed).starts_with("table inet vpnzone\nflush table inet vpnzone\n")
        );
    }

    #[test]
    fn the_uplink_ruleset_opens_the_tunnel_transport_and_nothing_else() {
        let v4 = [EndpointSocket {
            addr: "198.51.100.7".parse().unwrap(),
            port: Some(51820),
        }];
        assert_eq!(
            uplink_ruleset(&v4),
            concat!(
                "table inet vpnzone {\n",
                "\tchain output {\n",
                "\t\ttype filter hook output priority filter; policy drop;\n",
                "\t\toifname \"lo\" accept\n",
                "\t\tip daddr 198.51.100.7 udp dport 51820 accept\n",
                "\t}\n",
                "}\n",
            )
        );

        // No endpoint at all: loopback only. A tunnel with nowhere to go is
        // already fatal-ish (the holder says so), and the answer to "which
        // packets may leave" is "none" rather than "all of them".
        let empty = uplink_ruleset(&[]);
        assert!(empty.contains("policy drop;"));
        assert!(empty.contains("oifname \"lo\" accept"));
        assert!(!empty.contains("daddr"));
    }

    #[test]
    fn a_v6_endpoint_brings_neighbour_discovery_with_it() {
        // Without the ND exception the kernel cannot even resolve pasta's
        // fe80::1, and a v6 tunnel never sends its first packet. v4 needs no
        // counterpart: ARP is not in the `inet` family.
        let v6 = [EndpointSocket {
            addr: "2001:db8::1".parse().unwrap(),
            port: Some(443),
        }];
        assert_eq!(
            uplink_ruleset(&v6),
            concat!(
                "table inet vpnzone {\n",
                "\tchain output {\n",
                "\t\ttype filter hook output priority filter; policy drop;\n",
                "\t\toifname \"lo\" accept\n",
                "\t\tip6 daddr 2001:db8::1 udp dport 443 accept\n",
                "\t\ticmpv6 type { nd-router-solicit, nd-neighbor-solicit, \
                 nd-neighbor-advert } accept\n",
                "\t}\n",
                "}\n",
            )
        );

        // Two families, one ND rule.
        let both = uplink_ruleset(&[
            EndpointSocket {
                addr: "198.51.100.7".parse().unwrap(),
                port: Some(51820),
            },
            EndpointSocket {
                addr: "2001:db8::1".parse().unwrap(),
                port: Some(51820),
            },
        ]);
        assert_eq!(both.matches("icmpv6 type").count(), 1);
        assert!(both.contains("ip daddr 198.51.100.7 udp dport 51820 accept"));
        assert!(both.contains("ip6 daddr 2001:db8::1 udp dport 51820 accept"));

        // An endpoint written without a port: the rule is as wide as the
        // address and no wider.
        let portless = uplink_ruleset(&[EndpointSocket {
            addr: "198.51.100.7".parse().unwrap(),
            port: None,
        }]);
        assert!(portless.contains("\t\tip daddr 198.51.100.7 accept\n"));
        assert!(!portless.contains("dport"));
    }

    #[test]
    fn endpoints_of_the_config_become_the_uplinks_rules() {
        let text = "[Interface]\n\
                    PrivateKey = U1lOVEhFVElDLUtFWS1BLURPLU5PVC1VU0UtMDAwMDAwMDA9\n\
                    [Peer]\n\
                    Endpoint = 198.51.100.7:51820\n\
                    [Peer]\n\
                    Endpoint = 198.51.100.7:51820\n\
                    [Peer]\n\
                    Endpoint = [2001:db8::1]:51820\n\
                    [Peer]\n\
                    Endpoint = vpn.example.org:51820\n";
        let cfg = WgConfig::parse_str(text).unwrap();
        // Two peers behind one server are one rule; a name that never got
        // resolved is left out rather than guessed at.
        assert_eq!(
            endpoint_sockets(&cfg),
            vec![
                EndpointSocket {
                    addr: "198.51.100.7".parse().unwrap(),
                    port: Some(51820),
                },
                EndpointSocket {
                    addr: "2001:db8::1".parse().unwrap(),
                    port: Some(51820),
                },
            ]
        );

        // And a config that has no peers at all yields no rules.
        let bare = WgConfig::parse_str("[Interface]\nListenPort = 51820\n").unwrap();
        assert!(endpoint_sockets(&bare).is_empty());
    }
}
