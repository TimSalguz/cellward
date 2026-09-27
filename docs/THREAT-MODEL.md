# Threat model

Русская версия: [THREAT-MODEL.ru.md](THREAT-MODEL.ru.md) · The analysis channel by channel:
[LEAK-MODEL.md](LEAK-MODEL.md) (in Russian) · Related: [HERMETICITY.md](HERMETICITY.md),
[CONTAINERS.md](CONTAINERS.md), [PERMISSIONS.md](PERMISSIONS.md) §11 (in Russian),
[SYSTEM.md](SYSTEM.md) §10, [CERTIFICATES.md](CERTIFICATES.md) §5

**Status: 2026-09-27.** It describes the code as of that day, the OpenConnect client's empty
root and a new program's own home included.
This page is the summary; LEAK-MODEL is the analysis of each channel. Where the two disagree,
the code and CHANGELOG decide, and one of them needs fixing.

## 1. What is protected, from whom, and how a claim is made

cellward protects three things:

1. **which network a program's traffic and name lookups take**: a program in a zone reaches
   the world only through the zone's way out, and has no network when that way out is gone;
2. **the separation of identities**: a container is in one network at a time;
3. **the host's session and files** from programs in zones, as far as each row below says.

**The adversary** is a program started in a zone or a container, hostile or compromised,
running as the same Unix user: the user tier is rootless, and a zone's programs are the user's
uid inside the zone's user namespace. Also the VPN gateway of an OpenConnect zone, and anyone
watching the network outside.

**Trusted:** the kernel, the compositor, the host (root, the user's session outside the
zones, the Nix store, the system configuration), and the person who answers the questions.

**Kinds of claim** (the "Proof" column):

- **C, by construction:** the path does not exist: there is no interface, no socket in the
  mount namespace, or a kernel rule forbids it. "By what" names the mechanism.
- **A test ID** (§7): a VM or smoke test that plays the evil host and must fail to get
  through. The project's rule (LEAK-MODEL, "Открытые каналы") is that a channel counts as
  closed when a test breaks it, not when reasoning says there is nowhere to go. IDs starting
  with `u` are Rust tests of the code (`cargo test`, unit and crate tests). They are weaker:
  they test the code, not a running system.
- **no test:** said out loud. §6 lists these rows.
- **non-goal:** §5.

In the table, "ordinary zone" means a zone with `hermetic off` (zones are hermetic by
default), and "sandbox" means a container with a home of its own (bwrap). A running zone is
checked from inside with `cellward doctor` (vm35, vm20). It looks at links, routes,
`nsswitch.conf` and resolver sockets, and names every unix socket the zone's programs can
reach.

## 2. Strength of each layer

- **Network: strong.** A zone's app namespace holds `lo` and the tunnel and nothing else.
  A packet of any protocol family has no other interface to take, and the uplink, which does
  have one, sends only the tunnel's transport. This holds by construction, and tests with a
  real peer and a packet capture try to break it (N1–N9). The limits: metadata (N15), a
  device with a network of its own (N14), and, in an ordinary zone, a hostile program that
  asks the host to act for it (P1).
- **Files: only with the sandbox.** A zone without a sandbox sees the whole home (F1). A
  hermetic zone makes the host's startup places read-only from a list (F2). That narrows
  persistence but is not a boundary. A home of its own is.
- **Desktop: as strong as the compositor.** Screen, input and clipboard isolation is
  `wp_security_context_v1` plus the hidden list of our Wayland proxy (W3). Without the
  protocol a zone gets no Wayland at all (W4). The compositor itself sees everything
  (a non-goal), and frames and titles are labels, not proof (W8).
- **Kernel surface: partial.** The sandbox has a seccomp blocklist modelled on Flatpak's, and
  nested user namespaces stay allowed because Chromium and Electron need them (K1). A zone
  program without a sandbox has every system call an unprivileged user with user namespaces
  has (K2). The shared kernel is the project's one concession (ARCHITECTURE §1).
- **Host: not a goal.** The host, its root, the session outside the zones and the compositor
  are trusted. Launch interception routes programs; it does not confine them (L5). The system
  tier's egress policy is a backstop for the host's own programs (H5), not a defence of the
  host.

## 3. What each kind of launch promises

Every launch has a network (a zone, `offline` or `unconfined`) and a home (a home of its
own, a layer over the real home, or the main home). The kinds of zone are WireGuard/AmneziaWG,
OpenConnect, a host interface, and a system zone's tunnel. They differ only in what carries
the traffic, and they promise the same, except that a host-interface zone encrypts nothing.
It is shown as `host-interface` everywhere.

| launch | promises | does not promise |
|---|---|---|
| `unconfined` | nothing about the network; its kind of home still applies | anything else: it has the host's network, resolver, session bus and `systemd --user` |
| `offline` zone | no network at all, names included (N13, D1), plus what every zone gets | what an ordinary or a hermetic zone does not, by its setting |
| ordinary zone, no sandbox | the N and D rows and "every zone gets" below, against leaks by mistake | anything against a hostile program: it has `systemd --user`, the whole session bus and the portals (P1–P6), the host's `/tmp` (X1), the raw PipeWire socket (A2, A3), the whole home (F1, F2) |
| hermetic zone (the default), no sandbox | the network rows against a hostile program too, plus "hermetic adds" | the home: readable, and writable except the host's startup places (F1, F2); host `/proc` (X4), signals (X5), `machine-id` (I3) |
| any zone with a home of its own | plus "the sandbox adds" | `/sys`, `/etc`, `/nix/store` (I4); the kernel surface (K1) |
| layer over the home | writes stay in the layer; other containers' data is not visible (H4) | reads of the real home (F4) |
| main home | nothing about files | the same identity in every network (I2) |
| system zone: a service, a NixOS container, `vpn-zone-sys` | the network rows (sys1, sys10); the resolvers and, by default, the system bus hidden; see SYSTEM §10 | the Nix daemon for services, unless `InaccessiblePaths` (H1) |

**Every zone gets:** an app namespace with `lo` and the tunnel; the nftables insurance; the
host's resolvers hidden, and its own `resolv.conf` and `nsswitch.conf`; its own runtime
directory without the raw Wayland socket or compositor IPC; Wayland only through a
restricted socket; no host X server; a filtered system bus and an allow-list over `/run/systemd`; its own
`/dev` and devpts; its own IPC namespace; the Nix daemon and the system tier's socket hidden;
cellward's state hidden and its settings read-only; other containers' storage hidden; the
PulseAudio filter; the session's supplementary groups dropped; its helpers (bus proxies,
sound filter) run in the host's user namespace.

**Hermetic adds:** no `systemd --user`; the session bus through `xdg-dbus-proxy` and our
filter (portals from a list, `OpenURI` to the broker, no Secret Service); the broker as the
only way into another network; its own `/tmp`, `/var/tmp` and `/dev/shm`; PipeWire only
through a restricted context (the raw socket only in a zone declared an audio manager); the
host's startup files read-only, unless `host-files writable`.

**The sandbox adds:** an empty home plus granted paths; its own pid and IPC namespaces;
seccomp; a bus filter and proxy of its own; a `machine-id` of its own; X11 only as its own
satellite, when granted.

## 4. The table

| ID | Threat | Protected | By what | Proof |
|---|---|---|---|---|
| | **Network** | | | |
| N1 | IPv4 traffic around the tunnel | yes | the app namespace has only `lo` and the tunnel; there is nothing else to route to | C · vm1 vm2 vm8 sm1 sm13 |
| N2 | IPv6 around the tunnel | yes | the same topology: IPv6 goes into the tunnel when it carries it (WireGuard with a v6 address, OpenConnect when the gateway gives one), and a tunnel without it leaves no v6 default route | C · vm3 vm36 vm37 sm2 sm15 |
| N3 | The LAN and the host's own addresses, from a tunnel zone | yes | no route to them in the app namespace; the uplink filter lets out only the endpoint | C · br1 sys1; kernel-WireGuard user zone: **no test** |
| N4 | Host loopback services through pasta (port mirroring, gateway mapping) | yes | pasta runs with `-t/-u/-T/-U none` and `--no-map-gw` | vm7 sys9 |
| N5 | Programs see the route to the endpoint or the tunnel's socket | yes | the tunnel is made in the uplink and moved down; its socket stays in the uplink | C · vm4 sm3 |
| N6 | A zone program re-routes, adds an interface or unloads the filter | yes | no capabilities, and no rights in the zone's user namespace; a nested one owns only new, empty namespaces | C · vm38 sys2 sys3 |
| N7 | A regression of ours adds a way out | insurance | nftables in the app namespace: `policy drop`, only `lo` and `awg0` | vm5 sm4 |
| N8 | The uplink sends anything but the tunnel's transport | yes | uplink ruleset: the endpoint's address and port (OpenConnect: the gateway's address, any port) | vm6 vm8 sm5 sm17 sys6 |
| N9 | The tunnel or its holder dies while programs run | yes, fail-closed | the uplink namespace dies with the holder; the interface stays and drops everything | C · vm39 sys10 br3 br4 sm19 vm24 up1 |
| N10 | A host-interface zone falls back to the host's routes | yes | every socket is bound to the interface (patched pasta); the zone goes down when the interface does | vm22 vm23 vm24 vm25 |
| N11 | A host-interface zone goes out through a host service (proxy, Tor, sshd on a host address) | partly | the filter refuses the host's IPv4 and IPv6 (global, ULA) addresses as they are at zone start; later ones are not listed | vm22 vm40 |
| N12 | A user zone through a system zone reaches that zone's services, or goes around its tunnel | yes | its pasta runs as `vpn-zones-bridge`, which the system zone refuses to every local address, both families; IPv6 passed on only when the system zone's network carries it | br1 br2 br3 br4 br5 |
| N13 | An offline zone reaches anything | yes | loopback only; the resolvers are hidden before the offline branch | C · vm26 vm10 sm7 |
| N14 | A device granted to a container brings its own network (a phone's adb or modem, an ESP32, an LTE modem) | no | a warning when such a device is granted | — |
| N15 | Metadata: the endpoint's name is resolved in the host's network; DNS content is readable at the tunnel's exit | no | a literal endpoint address avoids the first; DoT/DoH is planned (M3) | — |
| N16 | A socket family no network namespace holds: `AF_VSOCK` to the host's or a VM's vsock services (a guest's sshd since systemd 256), around the tunnel | yes for 64-bit programs · 32-bit: **no** | a seccomp allow-list of families in every launch into a zone and for the OpenConnect client (`AF_UNIX`, `AF_INET`, `AF_INET6`, `AF_NETLINK`, `AF_PACKET`); x86's 32-bit `socketcall` cannot be filtered by family and passes | vm45 u14 |
| | **DNS** | | | |
| D1 | The host's resolver answers over a unix socket (nscd/nsncd, resolved's varlink, avahi) | yes | tmpfs over their directories in every zone (the zone fails if this fails); the zone's own `nsswitch.conf`: `hosts: files dns` | vm9 vm10 vm11 sm6 sys1 |
| D2 | The host's `resolv.conf` inside a zone | partly | the zone's own file is bound in; a host that replaces its file by rename detaches the bind, but queries still have only the tunnel | vm12; rename: **no test** |
| D3 | Host network facts over the system bus (`resolve1`, NetworkManager, `hostname1`) or systemd's varlink and dhcpcd's sockets | yes | a system bus proxy per zone; `/run/systemd` covered, with an allow-list bound back | vm13 vm20 vm41 |
| D4 | The OpenConnect client resolves a name through the host's resolver | yes | the gateway is resolved beforehand and passed with `--resolve`; the client's root has no `/run` at all | C · sm20 |
| | **OpenConnect: the client and the gateway** | | | |
| O1 | A client the gateway subverted takes the zone: unloads the uplink filter, enters the app namespace, lifts covers | yes | an id of its own (the second subordinate uid), no capabilities or groups, `no_new_privs`, seccomp refusing nested user namespaces | sm18 |
| O2 | A subverted client reaches host daemons (Nix daemon, system tier, varlink), IPC or `/dev/shm` | yes | the uplink hides them and has its own IPC, `/dev/shm` and `/dev/mqueue`; the client `pivot_root`s into an empty root of its own | sm16 sm20 |
| O3 | A subverted client reads host files | partly | its root holds only `/nix/store`, `/usr`, `/lib*`, the CA stores and its own directory; the store is world-readable (on NixOS, the system's configuration too) | sm20 |
| O4 | The client talks to anything but its gateway | yes | uplink filter: the gateway's address only | sm17 |
| O5 | The config or the environment steers the client (`--script`, `--csd-wrapper`, `--external-browser`, `--no-system-trust`, a `sha1:` pin, proxy variables) | yes | `Args` is an allow-list of single `--flag=value` chunks; the pin must be SHA-256; the environment is built from scratch | u2 |
| O6 | The gateway pushes split routes, split DNS, IPv6, or its own lines into `resolv.conf` | yes | split lists are ignored, since there is no second interface; IPv6 only into the tunnel, closed when not given or not an address; resolvers and domain are validated | u1 sm14 sm15 |
| | **Session bus, portals, system bus** | | | |
| P1 | `systemd --user` (`StartTransientUnit`) starts a process outside the zone | hermetic: yes · ordinary: **no** | no `systemd/private`; the filtered bus refuses `systemd1` | vm18; vm15 shows an ordinary zone keeps both |
| P2 | The `OpenURI` portal opens a link on the host (the home address, an identity link) | hermetic, sandbox: yes · ordinary: **no** | the bus filter answers `OpenURI` and gives the link to the broker; `file:`, `OpenFile`, `OpenDirectory` are refused | vm21 |
| P3 | Portals that grant a "host app" without a dialog (DynamicLauncher, Screenshot, Location, Camera, Secret, RemoteDesktop) or act in the host's network | hermetic, sandbox: yes · ordinary: **no** | an allow-list of portal interfaces; ProxyResolver and NetworkMonitor answered by the filter | vm21 u3 |
| P4 | Posing as a host app (`org.freedesktop.host.portal.Registry`); the Background portal writing an autostart entry | hermetic, sandbox: yes | the `org.freedesktop.host.` tree is refused; the filter registers the connection as `cellward.zone.<id>`/`cellward.c.<id>` itself; `RequestBackground` is answered by the filter | u3 |
| P5 | The Secret Service (every password in the keyring); `flatpak-spawn --host` | hermetic, sandbox: yes · ordinary: **no** | neither name is in the proxy's allow-list | C · vm42 |
| P6 | Other programs' bus APIs (a host player's `OpenURL`, a notification daemon's history); notifications with links or remote icons | hermetic: yes · ordinary: **no** | calls pass by name and interface only; MPRIS names can be owned, never talked through; `Notify` is rewritten | vm21 |
| P7 | Input methods (fcitx `Configure` runs a program on the host; IBus's private bus) | hermetic: yes · ordinary: IBus only | IBus's places covered in every zone; hermetic: the input-method portals only (`IBUS_USE_PORTAL=1`) | vm18 vm20 |
| P8 | A helper's `/proc/<pid>/root` leads to the unfiltered bus or `pulse/native` | yes | the bus proxies, the sound filter and the question windows run in the host's user namespace | vm17 vm18 |
| P9 | The system bus (NetworkManager, `hostname1`, `machined`, logind's sessions) | yes | a filtering proxy per zone: UPower, and logind's `Inhibit` and properties only | vm13 |
| P10 | The Settings portal gives the host's settings (a fingerprint) | no | allowed on purpose | — |
| | **Desktop: compositor, X11, screen, clipboard** | | | |
| W1 | Compositor IPC (`niri msg action spawn` runs on the host; the window list; window screenshots) | yes | the runtime directory is sealed; IPC sockets are never bound back; `NIRI_SOCKET`, `SWAYSOCK` and the like removed | vm15 vm16 vm18 |
| W2 | The raw Wayland socket | yes | only a restricted socket per launch, served by a confined proxy; the compositor's listener is in a directory no zone has | vm15 vm16 |
| W3 | Screen capture, keyboard and pointer emulation, background clipboard, other windows, through Wayland protocols | yes, with `wp_security_context_v1` | the security context, plus the proxy's fixed hidden list; a hidden global cannot be bound by its number | vm16 u5 |
| W4 | A compositor without `wp_security_context_v1` (GNOME's Mutter) | degraded, not open | in a zone the raw socket is not there, so there is no Wayland; `unconfined` gets it unrestricted | C · **no test** |
| W5 | The allow-list by binary name (`obs`, `copyq`) unlocks the full protocols | yes | a launch into a zone is always restricted; for `unconfined` a name counts only for the program the system's profiles give under it, or a path entry's file | C (`launch.rs`) · vm43 u13 |
| W6 | Another process of the zone uses a launch's proxy, or puts its own socket in its place | yes | the proxy passes on only its supervisor's descendants (`SO_PEERPIDFD`); the socket directory is read-only | vm16 |
| W7 | Compositor or shell IPC outside the runtime directory or over the bus (Wayfire in `/tmp`, quickshell, KWin) | hermetic: yes · ordinary: **no** | hermetic: its own `/tmp`, a runtime directory by allow-list, the filtered bus | C · **no test** |
| W8 | A window draws another zone's frame and title | no | the frame is a label, not a boundary; the trusted one is the panel's (`cellward focused`: window pid → network namespace, from the kernel) | win1 |
| W9 | The host's X server (every window, key and clipboard) | yes | tmpfs over `/tmp/.X11-unix`, no `DISPLAY`; its abstract socket belongs to the host's network namespace | vm14 vm19 |
| W10 | One launch's X server, seen from another launch or zone | partly | a satellite per launch; `x11-run` binds its socket in the launch's own `/tmp/.X11-unix`, none abstract; clients of one server see each other | vm16 (own socket); across launches: **no test** |
| W11 | The pixels of host X clients, through their MIT-SHM segments | yes | an IPC namespace per zone | vm18 |
| W12 | The Screenshot portal (non-interactive, no dialog) | hermetic, sandbox: yes · ordinary: **no** | refused by the filter's allow-list | u3 |
| W13 | A screen cast remembered and restarted without a dialog | hermetic, sandbox: yes · ordinary: **no** | `persist_mode`/`restore_token` pass only with `screencast yes` and a portal that knows the connection by name | u4 |
| W14 | A whole-screen cast shows other zones' windows; the frame names the zone | no | the person picks in the portal's dialog; `cellward frame hide` | — |
| W15 | Clipboard and drag-and-drop between zones, through the focused window | no, by design | ordinary Wayland focus rules; reading in the background is W3 | — |
| W16 | A key typed on answers "yes" to a question a zone raised (microphone, broker) | yes | the question window takes nothing until the person has been still with it focused for 1.5 s; Enter refuses | u8 |
| | **Sound, camera, devices** | | | |
| A1 | The host's sound server made to connect out or listen (`LOAD_MODULE` of `module-tunnel-sink`, `module-rtp-send`) | yes | the PulseAudio filter: an allow-list of commands | vm17 u12 |
| A2 | Recording what the host plays (a monitor) | pulse: yes · PipeWire: hermetic yes, ordinary and audio-manager zones **no** | the filter refuses monitors and trusts the server's word on the source; hermetic: a restricted PipeWire context and our WirePlumber policy | vm17 au1 au2 au5 au6 |
| A3 | The microphone without permission | partly | yes/no/ask per container on the pulse path and, in hermetic zones, on PipeWire; ordinary zones bypass it (raw `pipewire-0`, `systemd --user`) | vm17 au3 au4 |
| A4 | Cameras | yes, per launch | no camera in the zone's `/dev`; bound only into a launch whose container is allowed them | vm18 |
| A5 | Devices the session's ACL opens (`/dev/snd`, `uinput`, `rfkill`, `hidraw`, `kvm`, `net/tun`, `kmsg`), devices plugged in later, the host's terminals | yes | the zone's own `/dev` (a tmpfs with the basics and the GPU only) and its own devpts | vm18 |
| A6 | A granted device's number taken by another device | yes | the holder removes the binds and kills programs that still hold the old node | vm18 |
| A7 | A granted board reflashed into a keyboard (`serial`, `usb:`) | no | granting is the person's decision; the sets are marked dangerous | — |
| A8 | Playing to a network sink the host has loaded (RAOP, RTP); the shared sample cache | no | open (LEAK-MODEL §17) | — |
| | **Processes, IPC, temporary files** | | | |
| X1 | The host's `/tmp` and `/dev/shm`: listening sockets (tmux `run-shell`, a VPN client's IPC, single-instance sockets), other sandboxes' bus filters | hermetic: yes · ordinary: **no** (`doctor` names them) | its own `/tmp`, `/var/tmp`, `/dev/shm`; the filters moved into the runtime directory | vm19 |
| X2 | The host's abstract unix sockets | yes | they belong to the network namespace; a sandbox in the host's network: a Landlock scope (Linux 6.12+) | vm19 vm32 |
| X3 | `/proc/<pid>/root`, `cwd`, `fd`, `environ` of the host's session processes | yes | the kernel's ptrace rules across user namespaces; `vpn-zone-sys` gets a user namespace of its own | vm15 vm17 vm18 sys4 |
| X4 | `/proc/<pid>/cmdline` of host processes (which zones and profiles are in use) | sandbox: yes · zone: **no** | zones have no pid namespace; the sandbox has its own | sandbox: C · **no test** |
| X5 | Signals to the host's processes of the same user (killing the compositor) | yes (Linux 6.12+) | each launch into a zone is a Landlock domain of its own with `LANDLOCK_SCOPE_SIGNAL`: it signals itself and what it starts, nothing else — another launch of the same zone neither; the sandbox also cannot name host pids | vm44 |
| X6 | The host's System V IPC and POSIX message queues | yes | an IPC namespace per zone, per uplink and per sandbox | vm18 sm16 |
| X7 | The session's supplementary groups (docker, libvirt, input) | yes | dropped for zone programs | vm18 |
| X8 | Exhausting memory, CPU or processes | no | limits per zone are planned (ROADMAP §17) | — |
| X9 | `TIOCSTI` into the host terminal a program was started from | sandbox: yes · zone: **no** | seccomp in the sandbox; a zone program keeps that terminal, and the kernel's `legacy_tiocsti` decides | u6 |
| | **Helpers outside the zone** | | | |
| H1 | The Nix daemon: a fixed-output build fetches any URL from the host's network | yes, unless `nix-daemon on` | hidden in every zone and always in the OpenConnect uplink; system tier: hidden from containers and `vpn-zone-sys`, optional for services | vm18 vm20 sm16 sys2 |
| H2 | The system tier's service (add a system zone, run in one, around the zone's tunnel) | yes | `/run/vpn-zones` hidden in user zones; `VZP1` accepted only from a zone's root; per-zone user lists | br2 sys5 |
| H3 | cellward's own state and settings (every zone's key, `zone.pid`, the registry, raw sockets behind the filters, `broker-always`, `declared/`) | yes | tmpfs over `~/.local/state/vpn-zones` in every zone; `~/.config/vpn-zones` and `~/.local/share/vpn-zones` read-only | vm18 sm10 |
| H4 | Other containers' data | yes | container storage is covered in zones; a launch gets back its own | vm33 vm18 |
| H5 | Programs outside every zone reach the network | only with the system tier's egress policy | nftables by socket owner (`enforce`, `strict`) | sys7 sys8 ho1 |
| | **Files and the host's startup files** | | | |
| F1 | A zone program reads the home (`~/.ssh`, browser profiles, other programs' data) | own home: yes · otherwise **no** | the sandbox: an empty home plus granted paths | sm8 sm10 |
| F2 | A zone program writes what the host runs later (`~/.bashrc`, autostart, launcher entries, user units, compositor configs, `mimeapps.list`) | hermetic: partly · ordinary: **no** · own home: yes | read-only covers from a list, their parent directories pinned | vm18 |
| F3 | A path grant opens a socket directory or cellward's state; a grant outlives its term | yes | an allow-list of places, checked as written and as resolved at every launch; expiry detaches the bind in running programs | sm10 sm11 u10 |
| F4 | A layer container reads the real home | no, by design | a layer keeps writes out of the real home, not reads | vm34 |
| | **Certificates** | | | |
| T1 | An extra root CA reaches the host or another container | yes | bound in one launch's mount namespace; the variables name the system path; NSS databases written only where proven private | vm27 sm12 |
| T2 | A trust layer that cannot be applied | yes, fail-closed | the launch stops | C · **no test** |
| T3 | A container that trusts an inspection CA has its TLS read | no, the person's choice | `acknowledgeRisk` is required and the warning shown | — |
| | **Identity and fingerprint** | | | |
| I1 | One container (a browser profile) used in two networks | yes (own home, layer) | one network at a time; changing it is an action of its own; running programs keep their network | vm31 u9 |
| I2 | The main home used in two networks | no | `main` is one identity by definition; the launch window says so | — |
| I3 | `machine-id` | sandbox: yes · zone: **no** | a persistent one per named sandbox, a new one for each throwaway sandbox | sm9 |
| I4 | `/sys` (DMI), `/etc`, the host name, installed software (`/nix/store`), the frame colour | no | `/sys`, `/etc` and `/nix/store` are readable in the sandbox too | — |
| | **Launch paths: the broker and the picker** | | | |
| L1 | A zone program starts something in another network | hermetic: only through the broker · ordinary: **no** (P1) | the same container without a question, otherwise a window on the host; "always" only for store paths; the command pinned by path | vm18 u7 |
| L2 | The broker is told a false container | yes | a container is believed only from the zone's bus filter; otherwise read from the launch ancestry | vm21 |
| L3 | A program seen for the first time | partly (defaults) | the network is `offline` unless changed; its own home is preselected, and taken by a launch without a window | vm30 sm21 u11 |
| L4 | Launches around the picker: entries programs write, autostart, D-Bus activation | yes | entries taken over in place; shadow D-Bus service files | vm28 vm29 vm30 |
| L5 | Other launches around the picker (`DBusActivatable` without `Exec`, the user's own `dbus-1/services`, a key binding that calls the program, scripts, other host programs) | no | interception is routing, not a boundary; the host is trusted | — |
| | **Kernel surface** | | | |
| K1 | System calls from a sandbox | partly | a Flatpak-like seccomp blocklist (TIOCSTI, ptrace, keyrings, perf, io_uring, userfaultfd, the new mount API); nested user namespaces allowed | u6 |
| K2 | System calls from a zone program without a sandbox | partly | only the socket-family filter of N16 and the signal scope of X5; the GPU, `fuse` and `ntsync` nodes are there | — |

Notes:

- **N3, N9.** For a kernel WireGuard/AmneziaWG user zone, fail-closed rests on the kernel
  destroying the uplink namespace along with its holder (GOTCHAS §2); vm39 kills the zone
  under a running program. An OpenConnect gateway that gives out another address on reconnect
  leaves the zone dead, not open (LEAK-MODEL, OpenConnect item 11).
- **N8.** A kernel without `nf_tables` costs a warning, not the zone, because the topology
  carries the weight. The exception is OpenConnect, whose zone does not come up without the
  uplink filter.
- **O1–O3.** LEAK-MODEL, OpenConnect item 15. The client can still talk to its gateway, which
  is the party that subverted it anyway.
- **A3, A4.** Containers of one zone share its user namespace: a program outside a sandbox
  reaches another launch's devices through `/proc/<pid>/root/dev`. The microphone and camera
  are settings between containers of one zone, not walls. On the PipeWire path `ask` is a
  refusal.
- **F2.** The lists are `ENTRY_POINTS` and `HOST_RUNS_IN_ZONES` in `rust/src/zone.rs`: an
  enumeration. It does not cover home-manager's links in the home's root, or a file that does
  not exist yet, other than the entry points made beforehand.
- **H3.** A program of the same user outside every zone can still write `declared/` and
  `broker-always`. That is the host, a non-goal.
- **W13.** In a sandbox of an ordinary zone, `screencast no` does not apply; nothing is
  remembered there either.
- **Tested only in a hermetic zone:** the IPC namespace, the own `/dev` and the dropped groups
  apply to every zone, but vm18 checks them in the hermetic one.

## 5. Non-goals

| Non-goal | What it means here |
|---|---|
| A kernel exploit | the kernel is shared; a zone is a set of namespaces, not a VM (ARCHITECTURE §1) |
| An evil or buggy compositor | it sees every window and key; W1–W3 rely on it doing what it says |
| A compromised host | root, the user's session outside the zones, the Nix store and the system configuration are trusted |
| An escape from the browser's own sandbox | not prevented or detected; the escaped code has what its container and zone give, as this table says |
| A same-uid program outside the sandbox | a host program, or a zone program without a sandbox, can read and change a sandbox's data on disk and the whole home; only other containers' data is hidden from zones (H4) |
| Programs of one zone against each other | one user namespace, one `/tmp`, one set of abstract sockets: per-container settings are not walls (PERMISSIONS §11.10) |
| The person's answer | a "yes" or a grant is taken as meant; W16 guards only against keys typed on |
| Traffic analysis; the VPN provider | what leaves through the tunnel is the provider's to see |

## 6. Rows with no test

These are the gaps. Each is a claim made by construction, or none at all, that no VM or
smoke test tries to break:

- **N3:** the LAN, for a kernel WireGuard/AmneziaWG user zone (covered for system zones and
  zones through them);
- **D2:** the host replacing `resolv.conf` by rename;
- **W4:** a compositor without the security context gives a zone no Wayland;
- **W7:** compositor and shell IPC outside the runtime directory;
- **W10:** one launch's X satellite against another's (ROADMAP: "X11 в зоне против злого соседа");
- **X4:** `/proc/<pid>/cmdline`, sandboxed and not;
- **T2:** a trust layer that cannot be applied stops the launch (CERTIFICATES §6 item 7
  describes this test; none exists).

Rows with Rust tests only and no VM or smoke test: O5, P4, W12, W13, W16, X9, K1, and P3
apart from DynamicLauncher and the two network portals.

## 7. Tests referenced

`tests/vm.nix`, by subtest:

- vm1 "hermeticity: exactly lo and awg0 in the app-ns"
- vm2 "v4 default route through the tunnel"
- vm3 "no IPv6 path out (config has no v6)"
- vm4 "route to the endpoint goes INTO the tunnel (no loop by design)"
- vm5 "second echelon, app-ns: output drops everything but awg0"
- vm6 "second echelon, uplink: only tunnel transport may leave"
- vm7 "uplink: pasta mirrors none of the host's loopback ports"
- vm8 "the leak capture is empty", "the obfuscated tunnel's leak capture is empty"
- vm9 "no DNS leak: the NSS path stays inside the tunnel"
- vm10 "an offline zone cannot reach the host's resolver either"
- vm11 "the zone's own nsswitch.conf: hosts is files dns, the host's is untouched"
- vm12 "zone DNS defaults to 1.1.1.1 (config has no DNS=)", "DNS from the config: resolv.conf points into the tunnel and answers"
- vm13 "system bus in a zone: hostname1 and ListSessions refused, login1 readable"
- vm14 "x11 in a zone: the host's socket is hidden and DISPLAY is gone"
- vm15 "compositor IPC and raw socket: out of reach of an ordinary zone"
- vm16 "headless sway: a zone program gets restricted Wayland and no IPC"
- vm17 "pulse: a zone cannot load a module or record a monitor; the microphone by permission"
- vm18 "hermetic zone: no systemd --user, a filtered bus, the broker as the door"
- vm19 "hermetic zone: the host's /tmp, /dev/shm and abstract sockets are out of reach"
- vm20 "doctor: every socket a zone can reach is named, the zone's own are not"
- vm21 "sandbox: a link through the portal opens in the zone, a file: link not at all"
- vm22 "host-interface zone: out through eth1 only"
- vm23 "host-interface zone bound to another interface cannot reach eth1's network"
- vm24 "host-interface zone: its interface deleted, the zone goes down"
- vm25 "host-interface zone: a missing interface refuses to come up"
- vm26 "picker offline branch: zone via systemctl --user, lo-only"
- vm27 "trust: the host and the container next door do not", "trust: a leaked environment gives the host nothing", "trust: a sandbox's links do not lead its roots into the host's database"
- vm28 "user entries: a foreign one is taken over, a symlink is not, and both come back"
- vm29 "D-Bus activation: the shadow service starts the program through the picker"
- vm30 "autostart: taken over, and an unassigned program starts offline in its own home"
- vm31 "declared: the container runs in its network only, trusting its declared CA"
- vm32 "one name: the main home, a change of kind, one container a launch" (its Landlock part runs on Linux 6.12+ only)
- vm33 "zone: container storage covered, a container's own given back"
- vm34 "layer container: the whole home under its layer, grants in the real one"
- vm35 "doctor: a zone passes, the host's own namespace does not"
- vm36 "IPv6 through the tunnel: the v6 default goes into awg0", "IPv6 aimed at the server's real address goes into the tunnel, not around it"
- vm37 "IPv6 through the tunnel: TCP and ping, the server sees the tunnel's v6 address", "IPv6 through the tunnel: DNS over v6, from the config, answers inside"
- vm38 "a zone's program cannot touch the routes, the tunnel or the filter"
- vm39 "the zone killed under a running program: it fails closed"
- vm40 "host-interface zone: IPv6 bound to eth1, the host's other v6 addresses refused" (in `tests/vm-hostif.py`)
- vm41 "system bus in a zone: resolve1 refused, it names in the host's network" (in `tests/vm-promise-resolve1.py`)
- vm42 "hermetic zone: the keyring and flatpak's host command are out of reach" (in `tests/vm-promise-keyring.py`)
- vm43 "a launch into a zone is restricted whatever its program is called" (in `tests/vm-promise-wayland.py`)
- vm44 "a zone's program cannot signal the host's processes of the user" (in `tests/vm-promise-signals.py`; skipped before Linux 6.12)
- vm45 "a zone's program cannot reach the host over vsock" (in `tests/vm-promise-vsock.py`)

`tests/vm-audio.nix`: au1 "the zone's pipewire-0 is the restricted one, never the host's" ·
au2 "a sink's monitor records nothing" · au3 "the microphone as the zone's switch says" ·
au4 "the microphone by the container of each client" · au5 "PipeWire restarts: the restricted
socket comes back, the raw one never" · au6 "an audio manager gets the raw socket, loudly"

`tests/vm-window.nix`: win1 "the focused window's zone and program; the hotkey menu"

`tests/vm-system.nix`: sys1 "a service in the zone: the tunnel's network and the tunnel's
names" · sys2 "a NixOS container in the zone: the same network, no way to change it" ·
sys3 "a user's program in the zone: as the user, without privileges" · sys4 "the session is
out of reach through /proc, not only where it lies" · sys5 "the zone's list of users is the
only way in" · sys6 "nothing but the tunnel's UDP left eth1 towards the server" · sys7 "the
host has no network for a user's program outside the zones" · sys8 "our binary failing leaves
the host more closed, never open" · sys9 "a plain zone: its own namespace, out through the
host, nothing of the host's" · sys10 "the tunnel stops: lo alone, the consumers keep running
and reach nothing"

`tests/vm-bridge.nix`: br1 "a user zone through the system zone: one tunnel for both tiers" ·
br2 "from inside a user zone, no door to the system tier (review)" · br3 "it fails closed with
the tunnel, and lets go of its pasta when down" · br4 "the system zone made anew: the user zone
follows, without a restart" · br5 "IPv6 through the system zone: out through its tunnel, not into it"

`tests/vm-uplink.nix`: up1 "a tunnel zone through the wrong interface stays closed, never takes
the other"

`tests/vm-host.nix`: ho1 "strict: root keeps the local network and nothing beyond"

`tests/integration/smoke.sh`, by step (the names are in Russian):

- sm1 «Внутри зоны: РОВНО два линка — lo и awg0, больше ничего» (exactly two links)
- sm2 «Внутри зоны: IPv6 без пути наружу (конфиг без v6)» (no IPv6 way out)
- sm3 «Внутри зоны: маршрут до endpoint (192.0.2.1) идёт В ТУННЕЛЬ» (endpoint route into the tunnel)
- sm4 «Внутри зоны: второй эшелон — output policy drop, выпускать только в awg0» (app filter)
- sm5 «Внутри аплинка: второй эшелон — наружу только транспорт туннеля» (uplink filter)
- sm6 «Внутри зоны: свой nsswitch.conf — hosts: files dns» (own nsswitch.conf)
- sm7 «Внутри offline-зоны: только lo, default route отсутствует» (offline: lo only)
- sm8 «Песочница ФС: дом пуст, маркер хоста не виден, /nix/store виден» (sandbox home empty)
- sm9 «Песочница ФС: machine-id свой — постоянный у именованной, новый у одноразовой» (own machine-id)
- sm10 «Песочница ФС: выданный каталог виден и пишется, состояние vpn-zones — нет, и через symlink тоже» (grants; state hidden)
- sm11 «Песочница ФС: истёкший срок забирает каталог и у запущенной программы» (grant expiry)
- sm12 «Доверенный сертификат: соседний контейнер и хост — не доверяют» (CA not trusted next door)
- sm13 «Зона OpenConnect: в app-ns РОВНО два линка — lo и awg0»
- sm14 «Зона OpenConnect: DNS и search — от шлюза, а не от хоста»
- sm15 «Зона OpenConnect: IPv6 от шлюза — через туннель, и только через него» (address, default, resolver, TCP to the gateway over v6)
- sm16 «Зона OpenConnect: в uplink-ns закрыто то же, что в зоне» (Nix daemon, IPC, `/dev/mqueue`, `/dev/shm`)
- sm17 «Зона OpenConnect: второй эшелон аплинка — только адрес шлюза»
- sm18 «Зона OpenConnect: клиент — отдельный id без прав» (uid, capabilities, groups, `no_new_privs`, seccomp, `nft delete` refused)
- sm19 «Зона OpenConnect: смерть клиента валит зону» (client dies, zone goes)
- sm20 «Зона OpenConnect: у клиента свой корень, и в нём только нужное» (no `/home`, `/run`, `/var`, `/proc`, `/sys`, Nix daemon)
- sm21 «Пикер без графики: программе, которой контейнер не выбирали, — свой дом» (the real home's marker not seen)

Rust tests (`cargo test`):

- u1 `rust/src/openconnect.rs`: `connect_takes_the_address_the_mtu_and_the_resolvers_and_nothing_else`, `what_the_gateway_says_cannot_write_a_line_of_its_own`
- u2 `rust/src/openconnect.rs`: `extra_arguments_are_an_allowlist_and_a_shape`, `only_a_real_fingerprint_may_pin_the_server`, `the_client_starts_with_an_environment_we_built_and_not_the_users`
- u3 `rust/src/bus_filter.rs`: `only_the_named_portal_interfaces_get_through`, `the_doors_are_known_by_member_and_interface`, `the_programs_own_register_is_refused_after_ours`
- u4 `rust/src/dbus_wire.rs`: `a_screen_cast_is_not_remembered`; `rust/src/bus_filter.rs`: `the_screen_cast_switch_is_read_for_every_call`, `yes_is_ask_where_the_portal_does_not_know_the_zone`
- u5 `rust/src/wl_proxy.rs`: `hidden_protocols_are_not_in_the_build`, `a_hidden_global_cannot_be_bound_by_its_number`
- u6 `rust/tests/seccomp_cli.rs`: `selftest_passes`, `selftest_passes_with_denied_userns`; `rust/tests/fs_sandbox_cli.rs`: `the_filter_reaches_bwrap_on_the_descriptor_it_names`
- u7 `rust/src/broker.rs`: `always_is_kept_for_programs_of_the_store_only`, `the_program_asked_about_is_pinned_by_its_path`, `always_is_never_offered_for_what_runs_any_command`
- u8 `window/src/main.rs`: `a_guarded_window_takes_nothing_until_the_person_is_still`, `a_question_takes_no_answer_typed_on`
- u9 `rust/src/container.rs`: `a_container_is_never_in_two_networks_at_once`, `a_bound_container_runs_in_its_network_only`
- u10 `rust/src/container.rs`: `the_state_of_this_project_is_never_granted`, `a_grant_is_resolved_before_anything_is_created`
- u11 `rust/src/picker.rs`: `a_program_seen_for_the_first_time_gets_a_home_of_its_own`
- u12 `rust/src/pulse_filter.rs`: `module_loading_is_refused_and_answered_as_the_server_would`, `recording_a_monitor_is_refused_before_the_server_sees_it`
- u13 `rust/src/launch.rs`: `a_name_on_the_list_is_only_the_program_the_system_gives_under_it`
- u14 `rust/src/seccomp.rs`: `the_zone_socket_filter_builds`
