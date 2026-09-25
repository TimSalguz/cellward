//! `vpn-zone-core` — the helper commands the bash `vpn-zone` script delegates
//! to. Two of them used to be Python scripts in `module/` and one a C program
//! there; there is no Python and no C in this project any more.
//!
//! Argument parsing is done by hand, as in `vpn-zone-seccomp`: a handful of
//! verbs with fixed positional arguments do not need a CLI framework, and both
//! `profile-run` and `wl-sandbox` sit on the startup path of every program
//! launched into a zone.

use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

use vpn_zone::{
    bus_filter, console, desktop, dnsfwd, egress, fs_sandbox, openconnect, profile, sysrun, system,
    wl_sandbox, zone,
};

const USAGE: &str = "\
vpn-zone-core — helper commands of cellward

Usage:
  vpn-zone-core zone-holder [--ip P] [--awg P] [--wg P] [--pasta P] [--nft P]
                            [--openconnect P] [--dbus-proxy P] [--opener P]
                            [--kdialog P] <name>
        Bring the zone up and hold it: a user namespace with the double id
        mapping, a net+mount namespace with the tunnel in it, and pasta as the
        way out. Runs until killed, and the zone dies with it — that is the
        kill switch. This is the ExecStart of vpn-zone@<name>.service; the tool
        paths are substituted by Nix and default to a PATH lookup. The zone is
        a WireGuard/AmneziaWG one or an OpenConnect one, depending on whether
        its config has an [OpenConnect] section.

  vpn-zone-core system-zone <ns-up|ns-down|up|down> [--ip P] [--awg P] [--wg P]
                            [--nft P] [--config P] <name>
        A system zone (docs/SYSTEM.md), as root: ns-up makes the namespace
        /run/netns/vz-<name> with lo and the second echelon in it; up creates
        the tunnel in the host's namespace, moves it in as awg0, configures it,
        writes the zone's resolv.conf and then mirrors its state into
        /run/vpn-zones/system/<name>/ until killed; down deletes the tunnel and
        leaves lo alone; ns-down removes the namespace. The ExecStart and
        ExecStop lines of vpn-zone-system-ns-<name> and vpn-zone-system-<name>.
        The config is /var/lib/vpn-zones/system/<name>/config.conf unless
        --config names another file.

  vpn-zone-core system-run <zone> [--] <command> [args…]
        A console program in a system zone, as the calling user (docs/SYSTEM.md
        §7); what `vpn-zone-sys` runs. The program gets the zone's network and
        resolvers and no way to change them; its exit code is this command's.

  vpn-zone-core system-run-service
        The other end of `system-run`, as root: one connection on descriptor 0
        (vpn-zone-sysrun@.service, Accept=yes). Not meant to be run by hand.

  vpn-zone-core egress <apply|open|remove> [--nft P] [--enforce]
                       [--user NAME]… [--group NAME]…
        The host egress policy (docs/SYSTEM.md §9), as root: programs of users
        outside every zone are logged, and with --enforce refused; root, system
        users, the uplinks of user zones (the first ids of /etc/subuid and
        /etc/subgid) and the named users and groups go out. `open` keeps the
        table and lifts the restriction — the emergency key; `apply` puts it
        back.

  vpn-zone-core system-uplink <system zone> <pid>
        A user zone's way out through a system zone (docs/SYSTEM.md §7b),
        asked for the namespaces of <pid> — what the zone's holder runs. Prints
        `OK <resolvers>` or `ERR <why>`, then holds the way out until pasta
        ends or this is stopped. Not meant to be run by hand.

  vpn-zone-core dns-forward [--resolv FILE] [--upstream ADDR[:PORT]]…
        The host's names through a zone (docs/SYSTEM.md §9c): forward DNS
        queries on the sockets systemd passes (vpn-zones-dns.socket, in the
        host's network) to the resolvers of --resolv (read again per query)
        or --upstream, asking from this process's own network — the zone's.
        Nothing is parsed but the ID. Not meant to be run by hand.

  vpn-zone-core console [--login]
        The TTY console (docs/SYSTEM.md §7a): the network of the console's
        system zone, a terminal in it with one key, the plain zone when the
        VPN does not come up, the admin tool, the emergency key, the plain
        console. With --login (what the login shell runs) it shows up only on
        a virtual terminal, outside any zone, for a user of the zone.

  vpn-zone-core oc-script
        The vpnc-script of an [OpenConnect] zone, and nothing else's: this is
        what the zone's openconnect is started with as its --script. It takes
        no arguments — openconnect passes everything in the environment, and
        the zone adds VPN_ZONE_OC_DIR, VPN_ZONE_OC_NETNS_PID, VPN_ZONE_OC_IP
        and VPN_ZONE_OC_MTU to it. On `connect` it moves the tunnel interface
        into the zone's app namespace and writes down what the gateway said;
        the app namespace does the configuring. Not meant to be run by hand.

  vpn-zone-core profile-run [--cwd DIR] <profiledir> <zone> <ephemeral 0|1> <regdir> -- cmd...
        Stack the container's overlay layers over the XDG directories, change
        into DIR (falling back to $HOME and /), drop the ambient capabilities
        and run the command. Called from `cellward run`, already inside the
        zone's namespaces. An empty <profiledir> means the main profile: no
        layers are stacked. With <ephemeral> = 1 the command
        is run as a child and the container is removed after the last program
        living in it is gone.

  vpn-zone-core sync <state_dir> <home> <runner> <picker> [<systemctl>]
        Regenerate the .desktop entries for the zones. <runner> and <picker>
        are the paths that end up in the generated Exec lines.

  vpn-zone-core wl-sandbox <app-id> [--zone <zone>] [--no-proxy]
                           [--frame <rrggbb>:<width> [--frame-switch <dir>]] -- cmd...
        Run the command on a Wayland socket of its own, registered with the
        compositor as a sandbox (wp_security_context_v1): no screen capture,
        no background clipboard reads, no input emulation, no list of other
        windows. The socket goes into $XDG_RUNTIME_DIR/vpn-zones/wayland/<zone>/
        (--zone <zone> after <app-id>; unconfined without it), the directory a
        zone gets bound in. A confined proxy listens there and passes the
        program's connections on to the compositor, whose own sandbox socket
        is in $XDG_RUNTIME_DIR/vpn-zones/wl-up/ (docs/WINDOW-FRAME.md);
        --no-proxy lets the compositor listen on the zone's socket itself.
        --frame: the proxy draws a border of that colour and width (logical
        pixels) around the program's windows; the `frames` setting of the
        --frame-switch directory hides it for connections made while it says
        `hidden`.
        Without the protocol — an older compositor, an X11 session —
        the command is run as it is, with a warning on stderr.

  vpn-zone-core fs-sandbox [--bwrap P] [--dbus-proxy P] [--kdialog P]
                           [--xwayland P] [--opener P]
                           <app-id> [--name <sandbox>] -- cmd...
        Run the command in a bwrap sandbox where $HOME is gone: a tmpfs takes
        its place and only what the user allowed sticks out, everything else
        goes through the portals (/.flatpak-info). The session bus is filtered
        by xdg-dbus-proxy behind bus-filter, which opens the program's links
        with the opener (xdg-open) in the zone instead of the host's portal
        (LEAK-MODEL §2), XDG_RUNTIME_DIR is a tmpfs with the sockets bound in
        by name, a seccomp filter is loaded, and with the x11 permission the
        sandbox gets an xwayland-satellite of its own. The permissions are
        asked once with kdialog and remembered in
        ~/.config/vpn-zones/fs-perms/<app-id>; with --name they belong to the
        named sandbox and its persistent home instead. Tool paths are
        substituted by Nix and default to a PATH lookup.

  vpn-zone-core bus-filter --listen S --upstream S --opener P
        Internal: the sandbox's session bus in front of xdg-dbus-proxy. The
        portal's OpenURI is answered here and the link handed to the opener in
        the zone; OpenFile, OpenDirectory, ComposeEmail and file: links are
        answered as cancelled; everything else is passed on as it is.

  vpn-zone-core fs-sandbox-x11 [--xwayland P] <:display> -- cmd...
        Internal: what fs-sandbox runs INSIDE the sandbox when the x11
        permission is granted. Starts the X server (whose socket has to appear
        in the sandbox's own /tmp), waits a second for it and becomes the
        program.

  vpn-zone-core --help

Exit codes:
  0    success
  1    the pass failed
  2    bad usage
  127  the program could not be started (profile-run, wl-sandbox, fs-sandbox)
  *    otherwise profile-run, wl-sandbox and fs-sandbox report the exit code of
       the program itself (128 + N if it was killed by signal N)
";

/// Bad command line.
const EXIT_USAGE: u8 = 2;

fn main() -> ExitCode {
    // `args_os`, not `args`: a launcher can hand a file name through a `%U`
    // field code, and file names are bytes. `std::env::args()` panics on
    // anything that is not UTF-8, which would turn "open this file" into a
    // crash.
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let verb = args.first().map(|a| a.to_string_lossy().into_owned());

    match verb.as_deref() {
        Some("--help" | "-h" | "help") => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some("zone-holder") => match zone::Args::parse(&args[1..]) {
            Ok(parsed) => ExitCode::from(zone::run(parsed)),
            Err(e) => {
                eprintln!("vpn-zone-core zone-holder: {e}");
                eprint!("{USAGE}");
                ExitCode::from(EXIT_USAGE)
            }
        },
        Some("system-zone") => match system::Args::parse(&args[1..]) {
            Ok(parsed) => ExitCode::from(system::run(&parsed)),
            Err(e) => {
                eprintln!("vpn-zone-core system-zone: {e}");
                eprint!("{USAGE}");
                ExitCode::from(EXIT_USAGE)
            }
        },
        Some("egress") => match egress::Args::parse(&args[1..]) {
            Ok(parsed) => ExitCode::from(egress::run(&parsed)),
            Err(e) => {
                eprintln!("vpn-zone-core egress: {e}");
                ExitCode::from(EXIT_USAGE)
            }
        },
        Some("dns-forward") => match dnsfwd::Args::parse(&args[1..]) {
            Ok(parsed) => ExitCode::from(dnsfwd::run(parsed)),
            Err(e) => {
                eprintln!("vpn-zone-core dns-forward: {e}");
                ExitCode::from(EXIT_USAGE)
            }
        },
        Some("console") => ExitCode::from(console::run(&args[1..])),
        Some("system-run") => ExitCode::from(sysrun::client(&args[1..])),
        Some("system-run-service") => ExitCode::from(sysrun::broker()),
        Some("system-uplink") => ExitCode::from(sysrun::uplink_main(&args[1..])),
        Some("oc-script") => {
            let env = openconnect::environment();
            match openconnect::Args::from_env(&args[1..], &env) {
                Ok(parsed) => ExitCode::from(openconnect::run(&parsed, &env)),
                Err(e) => {
                    eprintln!("vpn-zone-core oc-script: {e}");
                    eprint!("{USAGE}");
                    ExitCode::from(EXIT_USAGE)
                }
            }
        }
        Some("profile-run") => match profile::Args::parse(&args[1..]) {
            Ok(parsed) => ExitCode::from(profile::run(parsed)),
            Err(e) => {
                eprintln!("vpn-zone-core profile-run: {e}");
                eprint!("{USAGE}");
                ExitCode::from(EXIT_USAGE)
            }
        },
        // The inside half of `vpn-zone doctor`, run in a zone's namespaces.
        // A launch's own X server in a zone (docs/HERMETICITY.md §7, A).
        Some("x11-run") => match vpn_zone::x11::Args::parse(&args[1..]) {
            Ok(parsed) => ExitCode::from(vpn_zone::x11::run(parsed)),
            Err(e) => {
                eprintln!("vpn-zone-core x11-run: {e}");
                eprint!("{USAGE}");
                ExitCode::from(EXIT_USAGE)
            }
        },
        Some("doctor-probe") => ExitCode::from(vpn_zone::doctor::probe_main(&args[1..])),
        Some("wl-sandbox") => match wl_sandbox::Args::parse(&args[1..]) {
            Ok(parsed) => ExitCode::from(wl_sandbox::run(parsed)),
            Err(e) => {
                eprintln!("vpn-zone-core wl-sandbox: {e}");
                eprint!("{USAGE}");
                ExitCode::from(EXIT_USAGE)
            }
        },
        Some("fs-sandbox") => match fs_sandbox::Args::parse(&args[1..]) {
            Ok(parsed) => ExitCode::from(fs_sandbox::run(parsed)),
            Err(e) => {
                eprintln!("vpn-zone-core fs-sandbox: {e}");
                eprint!("{USAGE}");
                ExitCode::from(EXIT_USAGE)
            }
        },
        Some("pulse-filter") => match vpn_zone::pulse_filter::Args::parse(&args[1..]) {
            Ok(parsed) => ExitCode::from(vpn_zone::pulse_filter::run(&parsed)),
            Err(e) => {
                eprintln!("vpn-zone-core pulse-filter: {e}");
                eprint!("{USAGE}");
                ExitCode::from(EXIT_USAGE)
            }
        },
        Some("pipewire-context") => match vpn_zone::pw_context::Args::parse(&args[1..]) {
            Ok(parsed) => ExitCode::from(vpn_zone::pw_context::run(&parsed)),
            Err(e) => {
                eprintln!("vpn-zone-core pipewire-context: {e}");
                eprint!("{USAGE}");
                ExitCode::from(EXIT_USAGE)
            }
        },
        Some("bus-filter") => match bus_filter::Args::parse(&args[1..]) {
            Ok(parsed) => ExitCode::from(bus_filter::run(&parsed)),
            Err(e) => {
                eprintln!("vpn-zone-core bus-filter: {e}");
                eprint!("{USAGE}");
                ExitCode::from(EXIT_USAGE)
            }
        },
        Some("fs-sandbox-x11") => match fs_sandbox::X11Args::parse(&args[1..]) {
            Ok(parsed) => ExitCode::from(fs_sandbox::run_x11(parsed)),
            Err(e) => {
                eprintln!("vpn-zone-core fs-sandbox-x11: {e}");
                eprint!("{USAGE}");
                ExitCode::from(EXIT_USAGE)
            }
        },
        Some("sync") => {
            let rest = &args[1..];
            // The fifth, `systemctl`, reloads the session bus when a shadow
            // D-Bus service changed; a wrapper that predates it passes four.
            if !matches!(rest.len(), 4 | 5) {
                eprintln!(
                    "vpn-zone-core sync: need <state_dir> <home> <runner> <picker> [<systemctl>]"
                );
                eprint!("{USAGE}");
                return ExitCode::from(EXIT_USAGE);
            }
            ExitCode::from(desktop::sync(
                Path::new(&rest[0]),
                Path::new(&rest[1]),
                &rest[2].to_string_lossy(),
                &rest[3].to_string_lossy(),
                rest.get(4).map(Path::new),
            ))
        }
        Some(other) => {
            eprintln!("vpn-zone-core: unknown command: {other}");
            eprint!("{USAGE}");
            ExitCode::from(EXIT_USAGE)
        }
        None => {
            eprint!("{USAGE}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}
