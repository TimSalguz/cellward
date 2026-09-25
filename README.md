# vpn-zones

Читать по-русски: [README.ru.md](README.ru.md) · Development plan: [ROADMAP.md](ROADMAP.md)
· Design: [architecture](docs/ARCHITECTURE.md), [leak model](docs/LEAK-MODEL.md),
[the system tier](docs/SYSTEM.md), [containers by default](docs/CONTAINERS.md),
[launcher entries](docs/LAUNCHERS.md), [per-container certificates](docs/CERTIFICATES.md),
[zone hermeticity](docs/HERMETICITY.md)

Launch programs with a choice of network, data container and sandbox — straight
from the app's launcher entry. The user tier runs entirely as your user: root is
not needed either to create a zone or to launch, and no system configuration
changes are required. An optional [system tier](#the-system-tier-optional) — a
NixOS module — holds zones from boot for services, NixOS containers and the
text console, and can close the host's own network to everything outside a zone.

You click a launcher entry — it asks which network to run in (through which VPN,
without VPN, or with no network at all) and in which environment (shared with
the system, a separate data container, or a sandbox). The choice is remembered
and can be pinned.

## What it does

Three independent layers, each enabled on its own.

**Network.** A zone is a network namespace brought up as your user: a tunnel
inside, `pasta` from passt facing outward. Two kinds of tunnel are supported —
kernel WireGuard/AmneziaWG, and OpenConnect (Cisco AnyConnect and ocserv, and
through `Protocol =` also GlobalProtect, Pulse, F5, Fortinet and Array). There
can be any number of zones, each with its own config. There are built-in
`unconfined` and `offline` options. `unconfined` (called `direct` until
2026-09; the old name still works) is the host's own network with nothing of a
zone around the program: no VPN, the host's resolver, session bus and
`systemd --user`. `offline` means the literal absence of a route, not a
firewall rule.

Zones are **hermetic by default** (since 2026-09): a program in a zone has no
`systemd --user` and a filtered session bus — portals, notifications, tray
icons, media players and input methods get through, starting a process outside
the zone does not. A program that opens something in another network (a link,
another program) goes through the broker, which asks which network, and
remembers "Always" for a program you trust. `vpn-zone hermetic <zone> off`
gives a zone the host's session back.

**Data.** Five modes:

| mode | program's home | what it sees |
|---|---|---|
| main | your real `$HOME` | everything as usual |
| container | overlayfs on top of the XDG directories | sees your settings, writes to a layer |
| per-app sandbox | persistent, this program only | nothing of yours |
| named sandbox | persistent, shared | programs launched in it |
| throwaway sandbox | tmpfs, wiped on exit | nothing of yours |

The container exists first and foremost to break up singletons: without it, a
browser launched a second time simply hands its window to the already running
process — and the traffic goes through the old network while looking perfectly
normal.

**Isolation.** The compositor can tell clients apart via
`wp_security_context_v1`: programs launched through the tagged socket are not
given screen capture, background clipboard reading, keyboard and mouse
emulation, or the list of other windows. Measured before and after — 47
protocols versus 33.

Separately there is a filesystem sandbox on `bwrap`: an empty directory instead
of `$HOME`, the bus through `xdg-dbus-proxy` (no Secret Service), and a
`/.flatpak-info` planted inside — GTK/Qt/Chromium use it to figure out they are
in a sandbox and start going through the portals for files and the camera on
their own. If a program needs X11, it gets its own `xwayland-satellite` so it
cannot see other windows.

## Requirements

- a compositor supporting `wp_security_context_v1` — tested on **niri** and
  **KWin**; Mutter (GNOME) does not have the protocol, so the compositor
  isolation layer will not work;
- unprivileged user namespaces (`kernel.unprivileged_userns_clone`);
- a range in `/etc/subuid` and `/etc/subgid` for your user — NixOS hands them
  out to regular users by default;
- `/dev/net/tun` with read and write access (this is all an OpenConnect zone
  needs — no kernel module and no root: the client creates its tun inside the
  zone's own user namespace);
- for WireGuard zones — the `wireguard` or `amneziawg` kernel module;
- working XDG portals (for the filesystem sandbox).

Check readiness:

```sh
sysctl kernel.unprivileged_userns_clone   # 1
grep "^$USER:" /etc/subuid                 # range exists
ls -l /dev/net/tun                         # crw-rw-rw-
```

## Supported environments

Most of the project does not depend on the desktop at all: the zones and the
tunnel, DNS, the data containers, the filesystem sandbox with its seccomp
filter, the `.desktop` interception (a freedesktop standard) and the portals —
any backend will do. Two things do depend on it: the compositor layer and the
dialogs.

| environment | state |
|---|---|
| **Plasma 6, Wayland** | every layer, out of the box |
| **niri / sway / wlroots, Wayland** | every layer — the development platform |
| **GNOME, Wayland** | works, minus the compositor layer: Mutter has no `wp_security_context_v1`, so `wl-sandbox` starts the program unrestricted and says so on stderr. Mitigating: Mutter hands out no `wlr-screencopy`, `data-control`, `virtual-keyboard` or `foreign-toplevel` either — most of what that layer takes away does not exist there. Dialogs are Qt and look foreign |
| **any X11 session** | the network and the filesystem are isolated, the display is NOT: the host's X socket is reachable from inside a zone, and one client there sees every window, keystroke and clipboard on the machine. Not recommended |
| **not NixOS** | same logic, different packaging: nix plus standalone home-manager (a plain package is planned), unprivileged userns (on Ubuntu 24.04 also `sysctl kernel.apparmor_restrict_unprivileged_userns=0`), subuid/subgid, and `amneziawg` through DKMS — or the in-tree `wireguard`, which is supported as a fallback |

Check the compositor:

```sh
wayland-info | grep -i security_context   # the protocol is there
```

The picker asks in a window of its own, `vpn-zone-window` (the network and the
container side by side, keyboard-driven, the system's light or dark scheme);
the other dialogs are `kdialog`, installed by the module itself, so no KDE
session is needed — only the binary. Where the window is missing the picker
asks with `kdialog` too. Naming the degraded layer in `vpn-zone doctor` instead
of on stderr alone is on the roadmap.

## Installation

```nix
{
  inputs.vpn-zones.url = "github:TimSalguz/vpn-zones";

  # in home-manager
  imports = [ inputs.vpn-zones.homeModules.default ];
  programs.vpn-zones.enable = true;
}
```

After a rebuild, the launcher gets the entries "Add VPN zone", "Remove VPN
zone", "Cut off a VPN zone", "Create container", "Remove profile (container)",
"VPN zone containers" (a window with every container, its network, programs and
granted directories), "VPN zone settings" and "Reset app networks".

What should always be so can be declared instead of clicked — containers, their
networks and programs, the defaults:

```nix
programs.vpn-zones = {
  enable = true;
  defaults.network = "offline";              # an unknown program gets no internet
  containers.work = {
    home = "private";                        # a home of its own
    network = "nl";                          # launches in another network are refused
    apps = [ "firefox" ];                    # launched in it without a question
    permissions.paths = [ "~/Downloads" ];
  };
  pathShims.enable = true;                   # typed in a terminal — through the picker too
};
```

`vpn-zone status --json` shows every value with where it came from (Nix, set
locally, or the default).

## How to use it

Create a zone: the **"Add VPN zone"** entry → pick a `.conf` → give it a name.
The system tells you whether the handshake went through — that is, whether the
config is alive.

### A corporate zone: OpenConnect

A zone whose config has an `[OpenConnect]` section is carried by the
`openconnect` client instead of a kernel tunnel — Cisco AnyConnect and ocserv
out of the box, and GlobalProtect, Pulse, F5, Fortinet or Array through
`Protocol =`. Everything else about the zone is unchanged, which is the point:
the corporate VPN lives inside it, an RDP client or a browser runs in it, and
the host and every other program never see the tunnel.

Write the config yourself and add it like any other (the launcher entry is for
`.conf` files of the WireGuard kind):

```ini
[OpenConnect]
Server     = vpn.example.com          ; host, or host:port — no scheme, no path
Protocol   = anyconnect               ; default; nc | gp | pulse | f5 | fortinet | array
User       = alice
AuthGroup  = Employees                ; the "realm"/"domain" dropdown, if the server has one
ServerCert = pin-sha256:HXXQ…=        ; pin the certificate; without it, the system CA store
                                      ; (pin-sha256: or sha256: — never sha1:)
PasswordFile = /home/alice/.config/vpn-zones/secrets/work.pass
MTU        = 1300                     ; optional, wins over what the gateway offers
Args       = --no-dtls --os=linux-64  ; optional, from an allowlist
```

```sh
chmod 600 ~/.config/vpn-zones/secrets/work.pass   # required, and checked
vpn-zone add work ~/work-vpn.conf
vpn-zone up work && vpn-zone run work -- remmina
```

The password file stays where you put it — `vpn-zone rm` deletes the zone and
its copy of the config, but never a file outside the zone's directory. Unlike a
WireGuard private key, which lives inside the config and goes with the zone,
this one is yours to keep or remove.

#### Why the format is ours and not the native one

`openconnect` does have a native way to write settings down — two, in fact.
Neither works as "a config you can accept from someone":

- **`--config=FILE`** is not a description of a VPN but **a command line folded
  into a file**: "long-format options as would be accepted on the command line,
  but without the two leading dashes". Anything may go in it, including
  `--script`, `--csd-wrapper`, `--external-browser` and `--no-system-trust`. To
  accept such a file is to accept an arbitrary command to run and an arbitrary
  trust decision along with it;
- **`--xmlconfig=FILE`** is the AnyConnect XML profile the gateway itself hands
  out. It describes a list of gateways and a client policy, holds no
  credentials, and is not a zone: it supplements the settings rather than being
  them.

So the `[OpenConnect]` section is **a subset of the native options**, chosen so
that the file cannot be turned into an executable one. `Args` takes an allowlist
of fifteen flags, and each one must be a single `--flag=value` chunk: allow a
flag and its value to be written separately and `Args = --useragent --script`
would smuggle the forbidden one in as its neighbour's value. Trust is decided
in exactly one way — `ServerCert`.

#### The password: why a file, and why not for long

`PasswordFile` exists for one reason: a zone is started by a systemd unit with
no terminal, so the client runs with `--non-inter` and there is nobody to ask.
The file must be `0600` and yours, which is checked both on `add` and on every
start, and its contents are read once in the uplink right before they go to the
client **on stdin**: `--passwd` is not an option, because `/proc/<pid>/cmdline`
is world readable.

The right home for a corporate password, though, is neither a file nor a secret
encrypted to the machine's key. A sops-style secret is decrypted by the machine
**itself, without a human, on every boot**: that is exactly right for a service
password and exactly wrong for a person's, which is usually also the domain and
mail password — so a stolen disk becomes a stolen account with no second factor
behind it. And where there is 2FA or a one-time code there is nothing to store
at all: the code lives half a minute.

Hence the decision (ROADMAP M4): store nothing by default and ask at start —
**in a window of ours, not a terminal** — keeping everything except the password
and the one-time code; "remember the password" means the session keyring, which
your login opens, not the machine's boot. Showing a terminal running
`openconnect`, which asks for all of this anyway, would be the easiest thing of
all — but then the zone is brought up by a person rather than by our code, and
both the certificate pin and the allowlist are bypassed: the two things the
format exists for.

`ServerCert` is what a corporate CA the system does not know needs; a gateway
with a publicly trusted certificate needs none. `openconnect` itself also
accepts a `sha1:` pin; a zone config does not, because a pin IS the whole trust
decision and SHA-1 has not been collision-resistant for years. To learn the
fingerprint, let the client tell you — it prints the exact `pin-sha256:` string,
and the module puts it on your `PATH` for this one purpose:

```sh
openconnect --non-inter vpn.example.com   # prints "--servercert pin-sha256:…"
```

What such a zone deliberately does **not** do, all of it for one reason —
a zone routes everything into the tunnel and has no second interface to route
anything else through (`docs/LEAK-MODEL.md`):

- **split tunnelling.** The gateway's split-include list is ignored and counted
  in the journal. What the gateway does with traffic it did not ask for is its
  own business;
- **split DNS.** The gateway's resolvers and its one default domain go into the
  zone's `resolv.conf`; a per-domain resolver would be a second path by another
  name;
- **IPv6**, which is not requested at all (`--disable-ipv6`) and closed in the
  zone, as for a WireGuard config without a v6 address;
- **interactive 2FA/OTP.** A zone is started by a systemd unit with no terminal
  to ask on, so the client runs `--non-inter`. The config format leaves room for
  it (ROADMAP M4);
- **turning certificate checking off.** There is no way to spell it — not
  through `ServerCert`, which must be a fingerprint, and not through `Args`,
  which is an allowlist that does not contain `--no-system-trust`,
  `--allow-insecure-crypto`, `--script`, `--csd-wrapper` or
  `--external-browser`.

### A network through an interface of the host

A zone whose config has a `[HostInterface]` section has no tunnel of its own:
its programs go out through one interface of the host — a second uplink, a
modem, a VPN the system itself brought up — and through nothing else.

```ini
[HostInterface]
Interface = enp4s0
DNS = 192.168.1.1
```

Every socket is bound to that interface, so when it goes down the zone is
offline, not rerouted; a missing interface is a zone that refuses to come up.
Such a zone does **not** encrypt anything: `status --json` calls it
`host-interface`. The zone's side of it is `10.255.255.253/30`, whatever the
host's addresses are.

Then just launch programs from the launcher. The same from the terminal:

```sh
vpn-zone add <zone> <file.conf>                # a zone from an AmneziaWG/WireGuard/OpenConnect config
vpn-zone add <zone> --system <system zone>     # a zone through a system zone's tunnel
vpn-zone list                                  # zones and their state
vpn-zone up <zone> / down <zone>
vpn-zone check <zone>                          # is the tunnel alive
vpn-zone doctor [<zone>] [--json]              # what is really closed, checked inside the zone
vpn-zone journal [--json] [<N>]                # unconfined launches and the broker's decisions
vpn-zone kill <zone>                           # cut a zone off now: its programs killed, the zone down
vpn-zone container grant sb:<name> <dir> [--for 2h]  # a directory for a home of its own, for a while
vpn-zone watch [--json]                        # are the tunnels alive (a timer runs it and notifies)
vpn-zone status --bar                          # one JSON line for waybar and similar bars
vpn-zone focused [--json|--bar|--watch]        # the zone and container of the focused window (niri, sway)
vpn-zone window-menu                           # its menu: pin the network, restart with a choice, close, cut off
vpn-zone launch <id> [-- args]                 # a launcher entry through the picker (key bindings)
vpn-zone run <zone> -- firefox                 # run in a zone
vpn-zone run <zone> --profile work -- firefox  # + data container
vpn-zone run <zone> --sandbox work -- firefox  # + named sandbox
vpn-zone run <zone> --fs-sandbox -- firefox    # + throwaway sandbox
vpn-zone run <zone> --tmp-profile -- firefox   # one-off container

vpn-zone profile create|list|rm <name>
vpn-zone sandbox create|list|rm <name>
vpn-zone perms list|reset <app|--all>          # granted file accesses
vpn-zone lock|unlock <zone>                    # forbid leaving for other networks
vpn-zone x11 <zone> on|off                     # an X server of their own for the zone's programs
vpn-zone hermetic <zone> on|off|default        # no systemd --user, a filtered session bus, the broker
vpn-zone hermetic --default on|off             # for zones without a setting of their own (on since 2026-09)
vpn-zone default-profile ask|main|own|<name>
vpn-zone mode picker|per-zone|both|off         # how launcher entries behave (per-zone, both: deprecated)
vpn-zone default offline|unconfined|<zone>     # what the picker offers an unknown program
vpn-zone pins / forget <program|--all>         # programs pinned to a network, and unpinning
vpn-zone container list|show|set|assign|merge  # containers: network, programs, X11, merging two
vpn-zone trust add|list|rm <container> …       # a root certificate for one container only
```

**Which zone is this window in.** The menu of the focused window goes on a key
of the compositor, its zone into the panel. With home-manager the module writes
the compositor's part:

```nix
programs.vpn-zones.desktop = {
  windowMenu.key = "Mod+Shift+Z";   # niri's notation; null — no key
  floatWindows = true;              # the launch window and the menu float (default)
  niri.enable = true;               # ~/.config/niri/vpn-zones.kdl
  niri.includeInConfig = true;      # append `include "vpn-zones.kdl"` to a config.kdl
                                    # home-manager writes as text
  sway.enable = true;               # ~/.config/sway/vpn-zones.conf (included by
                                    # home-manager's sway module by itself)
};
```

Without home-manager, the same by hand:

```kdl
// niri, config.kdl
binds {
    Mod+Shift+Z { spawn "vpn-zone" "window-menu"; }
}
window-rule {
    match app-id="^vpn-zone-window$"
    open-floating true
}
```

An included file is read where its `include` stands: at the end of config.kdl
it overrides a binding of the same key above it.

```jsonc
// waybar: a line per focus change, a class per zone to colour by
"custom/vpn-zone": { "exec": "vpn-zone focused --watch", "return-type": "json" }
```

The network of a window is the network namespace of its own process — the pid
the compositor has from the kernel —, compared with the host's and the zones';
the container comes from the nearest launch up its parents, when that launch
is certainly still running (its start time on record) and in the same network.
A program that detached from its launch shows its network with the container
unknown. Nothing trusts the window's title; the bar line escapes markup.

## The system tier (optional)

Everything above is the user tier: a session, your user, no root. The system
tier is a NixOS module on top of it — zones held by systemd from boot, for what
has no session:

- **services and NixOS containers in a zone**
  (`services.<unit>.zone`, `containers.<name>.zone`): the service gets the
  zone's namespace and resolv.conf, with nscd, resolved and the system bus hidden;
- **plain zones** (`kind = "plain"`): no tunnel, out through the host's network
  by pasta — "directly", but still a namespace with nothing of the host's;
- **the host's own services through a zone**: the Nix daemon's downloads
  (`host.nix`), the clock (`host.time`), the host's name lookups (`host.dns`);
- **the host egress policy** (`egress`): `audit` logs which programs outside
  every zone went to the network, `enforce` cuts them off, `strict` keeps root
  and the system's users to the local network as well — what has to go further
  goes through a zone;
- **one VPN, one connection**: a user zone can have no tunnel of its own and go
  through a system zone's (`vpn-zone add <name> --system <zone>`);
- **the TTY console** (`console`): logging in on a text console lands in a menu
  with a network already — a terminal in a VPN zone, a plain fallback when the
  VPN does not come up;
- **an off switch**: `vpn-zones-off` puts everything back on the host's network
  with no rebuild and no network, and survives a reboot; `vpn-zones-on` undoes it.

```nix
# NixOS
imports = [ inputs.vpn-zones.nixosModules.default ];
services.vpn-zones.system = {
  enable = true;
  users = [ "alice" ];               # may see the zones' state and add zones on the spot
  zones.direct0.kind = "plain";      # "directly"
  host.nix = "direct0";
  host.time = "direct0";
  egress = { enable = true; mode = "audit"; };   # watch first, then enforce
};
```

```sh
vpn-zone-sys <zone> -- <command>          # a console program in a system zone (the zone's users)
vpn-zone-sys --add <zone> <file.conf>     # a system zone on the spot (system.users)
vpn-zones-off / vpn-zones-on              # everything off (wheel, password) and back on
systemctl start vpn-zones-egress-open     # lift the egress policy for 15 minutes (wheel)
```

A zone's key never goes into Nix: `configFile` names a file at run time (a
decrypted secret, say), or the config is put in
`/var/lib/vpn-zones/system/<zone>/`. What it does, what it does not, and every
decision on the way: [docs/SYSTEM.md](docs/SYSTEM.md).

## What this does not replace

Flatpak. Its syscall filter is what the one here is modelled on, and it also
has its own runtime and ready-made rules for thousands of applications.
Here packages come from nixpkgs (no duplication and no runtime),
but the rules for each program have to be worked out on your own — though you
can peek at the same program's manifest on Flathub, in the `finish-args`
section.

What is missing here and what you should know:

- the sandbox does carry a seccomp filter now, modelled on flatpak's base set
  (terminal injection via `TIOCSTI`, `ptrace`, keyrings, `perf_event_open`, the
  new mount API); nested user namespaces are left allowed on purpose, otherwise
  Chromium and Electron applications would not start;
- the filesystem sandbox is enabled explicitly and needs tuning for each
  specific program;
- a zone isolates the network, not the files: without a sandbox the program
  sees your entire `$HOME`;
- tested on one machine and one set of programs.

## How it works inside

The subtleties that took the most time are commented in detail in
`module/default.nix`. The least obvious ones:

- a zone is **two** network namespaces, not one: connectivity (pasta and the
  tunnel's UDP socket) lives in the uplink one, while the namespace programs run
  in has nothing but loopback and the tunnel — a leak of any protocol family is
  impossible there because no path exists (`docs/LEAK-MODEL.md`). The interface
  is created in the uplink and moved down, because a WireGuard socket stays in
  the namespace the interface was born in;
- an **OpenConnect** zone is the same wall with a different thing behind it: the
  whole client process stays in the uplink, together with the TLS session and
  the gateway's address, and what moves down is a bare tun. A tun device and the
  descriptor attached to it are separate things, so the client keeps reading and
  writing packets after the interface has left its namespace — and it may create
  that tun without root because `TUNSETIFF` asks for `CAP_NET_ADMIN` in the user
  namespace that owns the network namespace, which is ours;
- on top of that topology, and only as insurance against a mistake of ours,
  both namespaces get an **nftables ruleset**: nothing leaves the app namespace
  except through the tunnel, and nothing leaves the uplink except the tunnel's
  own packets to the server. A kernel that will not have it costs a warning in
  the journal, not the zone — the topology is what carries the weight;
- the zone holder needs a **double uid mapping**: `0:<subuid>:1` (otherwise
  capabilities are lost on `execve` and the interface cannot be created) plus
  `<uid>:<uid>:1` (otherwise the program does not see its `$HOME`);
- an overlayfs `upperdir` cannot live on an overlayfs — hence the separate
  storage directories;
- `mount(8)` does not work as non-root even with `CAP_SYS_ADMIN`, so mounting
  is done by calling `libc.mount` directly;
- name resolution goes to a daemon over a **unix socket**, which no route and
  no packet filter can stop: NixOS runs `nsncd`, and with `systemd-resolved`
  enabled glibc asks it first of all (`resolve` stands before `dns` in
  `nsswitch.conf`). Both sockets are hidden inside a zone — without that,
  names resolve past the tunnel and a leak test names your real ISP;
- Amnezia configs come in CRLF, and recent ones also with empty `I1`–`I5`
  parameters, on which `awg setconf` rejects the whole file;
- the session bus filter is `xdg-dbus-proxy` with one small patch of ours
  (`module/patches/`): its wildcards are only `org.kde.*`-shaped, and a tray
  icon of Electron or Qt must own `org.kde.StatusNotifierItem-<pid>-<n>` —
  owning all of `org.kde.*` would own KWallet's name too, so `--own=NAME-*`
  owns that prefix and nothing more;
- the system tier's services join a zone through a systemd generator, not
  through their unit files — that is why `vpn-zones-off` returns them to the
  host's network without a rebuild; the host egress policy tells programs apart
  by the owner of the socket in nftables. Its allowances are added on top of a
  table `nft` loads by itself, so our code failing leaves the host more closed;
  a table that does not load at all is a failed unit, and the host is as it was
  without the policy (`docs/SYSTEM.md`).

## License

MIT.
