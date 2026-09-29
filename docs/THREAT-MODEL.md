# Threat model

Русская версия: [THREAT-MODEL.ru.md](THREAT-MODEL.ru.md) · The analysis channel by channel:
[LEAK-MODEL.md](LEAK-MODEL.md) (in Russian) · Related: [HERMETICITY.md](HERMETICITY.md),
[CONTAINERS.md](CONTAINERS.md), [PERMISSIONS.md](PERMISSIONS.md) §11 (in Russian),
[SYSTEM.md](SYSTEM.md) §10, [CERTIFICATES.md](CERTIFICATES.md) §5

**Status: 2026-09-28.** It describes the code as of that day, the OpenConnect client's empty
root, a new program's own home, a container's focus policy (W17), a space's `resolv.conf`
laid again after the host's rename (D2), shells' IPC out of every runtime directory (W7)
and steps 0 and 1 of the split between a network's and a container's permissions (N23,
W18, H7–H10, L6) included.
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
| `offline` (a container's instance since 2026-09-27) | no network at all, names included (N13, D1), plus what every zone gets — per container: its own network, IPC, mount and pid namespaces, apart from every other container (X10, X4) | what an ordinary or a hermetic zone does not, by its setting |
| ordinary zone, no sandbox | the N and D rows and "every zone gets" below, against leaks by mistake | anything against a hostile program: it has `systemd --user`, the whole session bus and the portals (P1–P6), the host's `/tmp` (X1), the raw PipeWire socket (A2, A3), the whole home (F1, F2) |
| hermetic zone (the default), no sandbox | the network rows against a hostile program too, plus "hermetic adds" | the home: readable, and writable except the host's startup places (F1, F2); signals before Linux 6.12 (X5), `machine-id` (I3) |
| any zone with a home of its own | plus "the sandbox adds" | `/sys`, `/etc`, `/nix/store` (I4); the kernel surface (K1) |
| layer over the home | writes stay in the layer; other containers' data is not visible (H4) | reads of the real home (F4) |
| main home | nothing about files | the same identity in every network (I2) |
| system zone: a service, a NixOS container, `vpn-zone-sys` | the network rows (sys1, sys10); the resolvers and, by default, the system bus hidden; see SYSTEM §10 | the Nix daemon for services, unless `InaccessiblePaths` (H1) |

**Every zone gets:** an app namespace with `lo` and the tunnel — since 2026-09-27 a launch
runs beside it, in its container's instance, whose only way out is the zone's bridge
(N17), and whose pid namespace is its own (X4) — since 2026-09-28 (stage 5) never in the
zone's own namespaces, and a zone that cannot carry the instance (a previous build's) is
refused until restarted; the nftables insurance; the host's resolvers hidden, and its own `resolv.conf` and `nsswitch.conf`; its own runtime
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

**A throwaway container** (a one-off with an empty home, a temporary layer over the home)
is hermetic, without the Nix daemon, the host's startup files writable or the raw PipeWire,
whatever its network gives its containers (2026-09-28, H8).

## 4. The table

| ID | Threat | Protected | By what | Proof |
|---|---|---|---|---|
| | **Network** | | | |
| N1 | IPv4 traffic around the tunnel | yes | the app namespace has only `lo` and the tunnel; there is nothing else to route to | C · vm1 vm2 vm8 sm1 sm13 |
| N2 | IPv6 around the tunnel | yes | the same topology: IPv6 goes into the tunnel when it carries it (WireGuard with a v6 address, OpenConnect when the gateway gives one), and a tunnel without it leaves no v6 default route | C · vm3 vm36 vm37 sm2 sm15 |
| N3 | The LAN and the host's own addresses, from a tunnel zone; the LAN's discovery (a multicast or a broadcast: mDNS, LocalSend, KDE Connect) | yes | no route to them in the app namespace but into the tunnel, and no interface on the LAN for a multicast or a broadcast (an IPv4 one goes into the tunnel, like any packet); the uplink filter lets out only the endpoint | C · vm47 vm87 br1 sys1 |
| N4 | Host loopback services through pasta (port mirroring, gateway mapping) | yes | pasta runs with `-t/-u/-T/-U none` and `--no-map-gw` | vm7 sys9 |
| N5 | Programs see the route to the endpoint or the tunnel's socket | yes | the tunnel is made in the uplink and moved down; its socket stays in the uplink | C · vm4 sm3 |
| N6 | A zone program re-routes, adds an interface or unloads the filter | yes | no capabilities, and no rights in the zone's user namespace; a nested one owns only new, empty namespaces | C · vm38 sys2 sys3 |
| N7 | A regression of ours adds a way out | insurance | nftables in the app namespace: `policy drop`, only `lo` and `awg0` | vm5 sm4 |
| N8 | The uplink sends anything but the tunnel's transport | yes | uplink ruleset: the endpoint's address and port (OpenConnect: the gateway's address, any port) | vm6 vm8 sm5 sm17 sys6 |
| N9 | The tunnel or its holder dies while programs run | yes, fail-closed | the uplink namespace dies with the holder; the interface stays and drops everything. A container's instance is cut when its zone ends (2026-09-27): its tap goes, `lo` and unreachable default routes are left, its programs live on; it is attached again only to the same zone (the same config and resolvers, by the zone's fingerprint) — as a new epoch where one can be made (stage 4) —, another one waits for `cellward container reattach`: never moved to another exit as a side effect (for a while stage 4 attached an instance that could make a new epoch to whatever zone came back; review 2026-09-28) | C · vm39 sys10 br3 br4 sm19 vm24 up1 vm63 vm64 vm65 |
| N10 | A host-interface zone falls back to the host's routes | yes | every socket is bound to the interface (patched pasta); the zone goes down when the interface does | vm22 vm23 vm24 vm25 |
| N11 | A host-interface zone goes out through a host service (proxy, Tor, sshd on a host address) | partly | the filter refuses the host's IPv4 and IPv6 (global, ULA) addresses as they are at zone start; later ones are not listed | vm22 vm40 |
| N12 | A user zone through a system zone reaches that zone's services, or goes around its tunnel | yes | its pasta runs as `vpn-zones-bridge`, which the system zone refuses to every local address, both families; IPv6 passed on only when the system zone's network carries it | br1 br2 br3 br4 br5 |
| N13 | An offline zone, or an offline container's instance, reaches anything | yes | loopback only; the resolvers are hidden before the offline branch — the same code for an instance (2026-09-27) | C · vm26 vm10 vm53 sm7 sm24 |
| N14 | A device granted to a container brings its own network (a phone's adb or modem, an ESP32, an LTE modem) | no | a warning when such a device is granted | — |
| N15 | Metadata: the endpoint's name is resolved in the host's network; DNS content is readable at the tunnel's exit | no | a literal endpoint address avoids the first; DoT/DoH is planned (M3) | — |
| N16 | A socket family no network namespace holds: `AF_VSOCK` to the host's or a VM's vsock services (a guest's sshd since systemd 256), around the tunnel | yes for 64-bit programs · 32-bit: **no** | a seccomp allow-list of families in every launch into a zone and for the OpenConnect client (`AF_UNIX`, `AF_INET`, `AF_INET6`, `AF_NETLINK`, `AF_PACKET`); x86's 32-bit `socketcall` cannot be filtered by family and passes | vm45 u14 |
| N17 | A container's instance reaches its zone's own services (a listener on the zone's address or loopback), or goes out other than through the zone's tunnel | yes | the only way out of the instance is a `passt --fd` its zone runs for it in the zone's app namespace (2026-09-27), as the bridge's own id (the zone's third subordinate uid): the zone's filter refuses that id every local address and loopback, both families, and the zone does not carry an instance without the rule; passt maps nothing to the zone's loopback (`--no-map-gw`, `--map-guest-addr none`) and takes nothing in; the instance's relay runs under a seccomp allow-list | C · vm60 vm61 vm62 vm22 sm26 |
| N18 | A container's instance ends while its programs run: stopped, killed, logged out of, its keeper or its pid 1 dead | yes: its programs end with it | its programs are in its pid namespace (2026-09-27, stage 3): its keeper asks them to end (TERM) and waits, and its pid 1's end takes whatever is left with the namespace — the kernel's doing, at once; a TERM ignored is ended by `cellward container kill` or systemd's own stop timeout. A launch a terminal stopped (`^Z`) holds its program, killed, as a zombie outside the namespace's reach — its parent is the launch's waiter, a host process — and the namespace's end with it: the keeper and `cellward kill` continue such a stopped parent so that it reaps (review 2026-09-28: `cellward kill <zone>` waited for it for good, before the zone itself was cut). A container's commands (`stop`, `kill`, `reattach`, `set … --restart`) act on that container's instances only, never on another's in a network of its name (review 2026-09-28). Nothing of an instance outlives it, offline or with a way out | vm57 vm72 vm73 vm82 sm25 u17 |
| N19 | A container's network switched live (`cellward container set <c> network <net>`, stage 4, 2026-09-27): a connection or a socket of the old network goes on in the new one — TCP, connected or unconnected UDP (QUIC and its migration), an `SO_REUSEPORT` group, a ping socket, an IPv6 socket with the old source; or both ways out at once, or anything out between them | yes: every socket made before the switch · **no**: a program launched from a login session (tty, ssh) while it runs — the switch is refused; what a program carries itself (cookies, TLS tickets, QUIC tokens, a new socket resuming the old session) | the old way out is cut and its relay reaped before anything of the new; the programs are frozen and moved into the next epoch's cgroup, every socket that may reach out destroyed (`SOCK_DESTROY`, programs notice), and the instance's rules let out only a socket born in the new epoch (`socket cgroupv2`, a socket's cgroup is fixed at its birth) from the new address; loopback and unreachable defaults alone in between; any failure after the cut leaves it cut, in the new network, never back in the old | C · vm78 vm79 vm80 vm81 vm83 u18 |
| N20 | The old network's DNS after a switch: a program's cached resolver, or its short names searched in the old network's domains | yes | the instance's `resolv.conf` names only the constant forwarders (`10.254.255.253`, `fd63:656c:6c77::53`) the current zone's passt answers — a switch changes who answers, not what a program asked; a switch between zones whose search domains differ is refused | vm78 u18 |
| N21 | A switch as a side effect: a program of a zone or of an instance, the broker, a launch, a zone's return or a change of Nix moves a container to another network | yes | the only door is the instance's control socket, which answers a peer of the host's user namespace only and is covered in every zone and instance; the broker has no such verb; a zone that comes back re-attaches the instance only when it is the same zone (its fingerprint: the config and the resolvers; as a new epoch), never another — another waits for `cellward container reattach` (N9); a network declared in Nix is changed there | vm76 vm77 u18 |
| N22 | A connection from outside reaches a program that listens in a zone: from the LAN to the host's address, or from the tunnel's far end to the zone's address (a file-sharing program's receiver, a development server on `0.0.0.0`) | yes: nothing comes in · an inbound port for a service in a zone: not implemented (ROADMAP) | the program's socket is in its container's instance, whose network namespace no address of the host's or of the zone's leads to: the instance's passt takes nothing in (`-t none -u none`), so a connection to the zone's address ends in the zone's app namespace, where nothing listens, and one to the host's address in the host's, where nothing of the instance's is | C · vm87 |
| N23 | A live switch carries an instance's start settings into a network that would give its container less: not hermetic, the Nix daemon (which fetches in the host's network), the host's startup files writable, the host's raw PipeWire | yes (review 2026-09-28) | an instance's covers and helpers are made once, by the settings it came up with (its note); a switch keeps them, so one is refused (`settings`, each setting named) when any of them is open where the new network would give its container the safe value; `--restart` closes the programs, and the instance comes up in the new network with its settings | vm88 u21 |
| N24 | A program in the host's own network (`host`, 2e of `docs/PERMISSIONS.md` §11.15) reaches the host's own services: a listener on the host's address, found by the host's routes | yes | its container's instance goes out through the `host` zone as through any zone (its passt, the zone's refusal of its local addresses to it), and the zone's pasta, in the host's network like a host-interface zone's, is refused every address of the host's, both families, before its accepts; pasta maps nothing to the host's loopback (`--no-map-gw`) and takes nothing in; only DNS asked at the zone's gateway goes to the host's resolver (`--dns-forward`) | vm89 |
| N25 | A program «without isolation» (`--no-isolation`, the built-in record `open`, 2e of `docs/PERMISSIONS.md` §11.15) in a VPN network goes around its tunnel | partly | its instance's only way out is still its network's passt; the ways around a network — the host's session, the Nix daemon, the host's startup files — stay closed where the network does not tolerate them (`hermetic::tolerance`), whatever the record asks; **every device is given**, so a device with a network of its own (a phone's modem, a USB network card) is a way out, as N14 says — the person's explicit choice | vm90 |
| | **DNS** | | | |
| D1 | The host's resolver answers over a unix socket (nscd/nsncd, resolved's varlink, avahi) | yes | tmpfs over their directories in every zone (the zone fails if this fails); the zone's own `nsswitch.conf`: `hosts: files dns` | vm9 vm10 vm11 sm6 sys1 |
| D2 | The host's `resolv.conf` inside a zone or a container's instance, after the host replaces its file by rename (NetworkManager, resolvconf, openresolv) | yes · between the host's rename and the re-lay: **no** (through the tunnel only) | the space's own file (and its `nsswitch.conf`) is bound over the name `/etc/resolv.conf` itself, not where its links lead (2026-09-28): a rename down the host's chain does not reach it; a replacement of the name itself detaches it, and the space, watching `/etc` (inotify, no clock), lays it there again — its `/etc` shared, every launch a slave copy, so a program launched before the rename gets it too; nothing reaches the host's resolver or leaves around the tunnel; `doctor` holds the nameservers a space sees to the ones it was given | vm12 vm48 vm85 vm86 u19 |
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
| W4 | A compositor without `wp_security_context_v1` (GNOME's Mutter; cage in the test) | degraded, not open | in a zone the raw socket is not there, so there is no Wayland; `unconfined` gets it unrestricted | C · vm49 |
| W5 | The allow-list by binary name (`obs`, `copyq`) unlocks the full protocols | yes | a launch into a zone is always restricted; for `unconfined` a name counts only for the program the system's profiles give under it, or a path entry's file | C (`launch.rs`) · vm43 u13 |
| W6 | Another process of the zone uses a launch's proxy, or puts its own socket in its place | yes | the proxy passes on only its supervisor's descendants (`SO_PEERPIDFD`); the socket directory is read-only | vm16 |
| W7 | Compositor or shell IPC that W1's list does not name: outside the runtime directory, in a directory of its own there, or over the bus (Wayfire in `/tmp`, quickshell's directory, KWin's scripting) | hermetic: yes · ordinary: the runtime directory yes, `/tmp` and the bus **no** | hermetic: its own `/tmp`, a runtime directory by allow-list, the filtered bus; every zone and instance (2026-09-28): shells' own IPC kept out of the runtime directory by a named list (`quickshell/`, `astal/`, `ironbar-ipc.sock`, `eww-server_*`, kanshi's `fr.emersion.kanshi.*`), `WAYFIRE_SOCKET` dropped from a launch; an ordinary zone shares the host's `/tmp` (Wayfire's socket by its path) and the whole bus by design | C · vm50 u20; vm51 shows an ordinary zone kept out of a shell's directory and not told Wayfire's socket, and still reaching Wayfire in `/tmp` and KWin on the bus |
| W8 | A window draws another zone's frame and title | no | the frame is a label, not a boundary; the trusted one is the panel's (`cellward focused`: window pid → network namespace, from the kernel) | win1 |
| W9 | The host's X server (every window, key and clipboard) | yes | tmpfs over `/tmp/.X11-unix`, no `DISPLAY`; its abstract socket belongs to the host's network namespace | vm14 vm19 |
| W10 | One launch's X server, seen from another launch or zone | partly | a satellite per launch; `x11-run` binds its socket in the launch's own `/tmp/.X11-unix`, none abstract; the `/proc/<pid>/root` of its processes is closed to another zone by its user namespace and, on Linux 6.12+, to another launch by its Landlock domain, which also keeps the clients off an abstract name another launch took; clients of one server see each other | vm16 vm52 |
| W11 | The pixels of host X clients, through their MIT-SHM segments | yes | an IPC namespace per zone | vm18 |
| W12 | The Screenshot portal (non-interactive, no dialog) | hermetic, sandbox: yes · ordinary: **no** | refused by the filter's allow-list | u3 |
| W13 | A screen cast remembered and restarted without a dialog | hermetic, sandbox: yes · ordinary: **no** | `persist_mode`/`restore_token` pass only with `screencast yes` and a portal that knows the connection by name | u4 |
| W14 | A whole-screen cast shows other zones' windows; the frame names the zone | no | the person picks in the portal's dialog; `cellward frame hide` | — |
| W15 | Clipboard and drag-and-drop between zones, through the focused window | no, by design | ordinary Wayland focus rules; reading in the background is W3 | — |
| W16 | A key typed on answers "yes" to a question a zone raised (microphone, broker) | yes | the question window takes nothing until the person has been still with it focused for 1.5 s; Enter refuses | u8 |
| W17 | A zone's program takes the keyboard focus (`xdg_activation_v1`), and the keys typed for another window go to it — a password typed into the browser; or takes it again and again from one click | `input` (the default): once per input event of the person · `notify`, `ask`: yes · `allow`: **no** · a new window focused as it opens: the compositor's | the proxy counts each `activate` by the serial its token was made from (else by the token's string) and passes only the first; under `notify` and `ask` none passes, and the focus moves through the compositor's IPC on the person's word | win2 win3 win4 u16 |
| W18 | A container that refuses X11 gets its zone's X server all the same (`zoneX11`, `cellward x11 <zone> on`): one X server shows its clients each other's windows, keys and clipboard | yes (2026-09-28) | a container's own `x11` is tri-state: its word, on or off, decides; only a container without one takes its zone's (`x11::effective`); before, the X server was the container's OR the zone's | u24 |
| | **Sound, camera, devices** | | | |
| A1 | The host's sound server made to connect out or listen (`LOAD_MODULE` of `module-tunnel-sink`, `module-rtp-send`) | yes | the PulseAudio filter: an allow-list of commands | vm17 u12 |
| A2 | Recording what the host plays (a monitor) | pulse: yes · PipeWire: hermetic yes, ordinary and audio-manager zones **no** | the filter refuses monitors and trusts the server's word on the source; hermetic: a restricted PipeWire context and our WirePlumber policy | vm17 au1 au2 au5 au6 |
| A3 | The microphone without permission | partly | yes/no/ask per container on the pulse path and, in hermetic zones, on PipeWire — for a container's instance, the word of the network it is in now: a live switch moves its helpers with it, and a stream the new network does not allow ends (review 2026-09-28; so does the screen cast's switch); ordinary zones bypass it (raw `pipewire-0`, `systemd --user`) | vm17 au3 au4 u18 |
| A4 | Cameras | yes, per launch | no camera in the zone's `/dev`; bound only into a launch whose container is allowed them | vm18 |
| A5 | Devices the session's ACL opens (`/dev/snd`, `uinput`, `rfkill`, `hidraw`, `kvm`, `net/tun`, `kmsg`), devices plugged in later, the host's terminals | yes | the zone's own `/dev` (a tmpfs with the basics and the GPU only) and its own devpts | vm18 |
| A6 | A granted device's number taken by another device | yes | the holder removes the binds and kills programs that still hold the old node | vm18 |
| A7 | A granted board reflashed into a keyboard (`serial`, `usb:`) | no | granting is the person's decision; the sets are marked dangerous | — |
| A8 | Playing to a network sink the host has loaded (RAOP, RTP); the shared sample cache | no | open (LEAK-MODEL §17) | — |
| | **Processes, IPC, temporary files** | | | |
| X1 | The host's `/tmp` and `/dev/shm`: listening sockets (tmux `run-shell`, a VPN client's IPC, single-instance sockets), other sandboxes' bus filters | hermetic: yes · ordinary: **no** (`doctor` names them) | its own `/tmp`, `/var/tmp`, `/dev/shm`; the filters moved into the runtime directory | vm19 |
| X2 | The host's abstract unix sockets | yes | they belong to the network namespace — every container's instance has one of its own, offline and in a zone (2026-09-27); a sandbox in the host's network: a Landlock scope (Linux 6.12+) | vm19 vm32 vm54 vm66 |
| X3 | `/proc/<pid>/root`, `cwd`, `fd`, `environ` of the host's session processes | yes | the kernel's ptrace rules across user namespaces; `vpn-zone-sys` gets a user namespace of its own; a container's instance cannot even name a host process: its pid namespace (X4) | vm15 vm17 vm18 sys4 vm70 |
| X4 | `/proc/<pid>/cmdline` of host processes and of other containers' (which zones and containers are in use, the arguments, URLs and paths programs were given), and `/proc/<pid>/net` of any of them (their network's sockets and addresses: no ptrace check guards it) | yes: every container's instance, offline and in a zone; the sandbox; `vpn-zone-sys` (2026-09-28) · **no**: `unconfined`, a program a previous build launched into a zone's own namespaces before the update (`doctor`: `programs`; nothing is launched there since stage 5), an instance an earlier build started (until restarted: `doctor`, `restart_needed`) | each container's instance has a pid namespace of its own (stage 3 of the container design, 2026-09-27): its pid 1 mounts the namespace's own `/proc`, and every launch into the instance joins it — a program sees its own container's processes and no one else's, neither the host's nor another container's; the sandbox has its own, and so does a `vpn-zone-sys` command (stage 5: its pid 1 mounts the namespace's `/proc` and forks it). An instance's `/sys/fs/cgroup`, which names every unit and scope, is covered. Global counters (`/proc/loadavg`, `/proc/stat`) and a pid a program is told (`WAYLAND_DISPLAY` names the supervisor's) stay. A pid lock of the main home (Chromium's `SingletonLock`, Firefox's `lock`) names a pid of one side only: an application of the main home is refused into an instance while it runs outside it, and unconfined while it runs in an instance of the real home (review 2026-09-28); one started on the host past cellward is not checked | C · vm70 vm71 vm44 sm28 sys4 u17 |
| X5 | Signals to the host's processes of the same user (killing the compositor) | yes (Linux 6.12+) | each launch into a zone is a Landlock domain of its own with `LANDLOCK_SCOPE_SIGNAL`: it signals itself and what it starts, nothing else — another launch of the same container neither; the sandbox and, since stage 3 of the container design (2026-09-27), a container's instance also cannot name host pids: a host number means nobody, or somebody else, in their pid namespace (X4) | vm44 vm69 |
| X6 | The host's System V IPC and POSIX message queues | yes | an IPC namespace per zone, per uplink, per sandbox and per container's instance | vm18 sm16 vm54 |
| X7 | The session's supplementary groups (docker, libvirt, input) | yes | dropped for zone programs | vm18 |
| X8 | Exhausting memory, CPU or processes | no | limits per zone are planned (ROADMAP §17) | — |
| X9 | `TIOCSTI` into the host terminal a program was started from | sandbox: yes · zone: **no** | seccomp in the sandbox; a zone program keeps that terminal, and the kernel's `legacy_tiocsti` decides | u6 |
| X10 | Another container's loopback services, abstract sockets, System V IPC and `/tmp` (a container reaching another) | yes · `/tmp` in an ordinary network: **no** (X1) | each container runs in its own instance: network, IPC and mount namespaces of its own — offline since stage 1 of the container design, in a zone since stage 2 (2026-09-27); since stage 5 (2026-09-28) never in a zone's own namespaces: a launch into a zone of a previous build still running (no bridge) is refused with its restart, and `doctor` names what a previous build left running there | vm53 vm54 vm66 vm68 vm84 |
| | **Helpers outside the zone** | | | |
| H1 | The Nix daemon: a fixed-output build fetches any URL from the host's network (and, the user trusted by the daemon, anything root does: H9) | yes, unless `nix-daemon on` | hidden in every zone and always in the OpenConnect uplink; system tier: hidden from containers and `vpn-zone-sys`, optional for services | vm18 vm20 sm16 sys2 |
| H2 | The system tier's service (add a system zone, run in one, around the zone's tunnel) | yes | `/run/vpn-zones` hidden in user zones; `VZP1` accepted only from a zone's root; per-zone user lists | br2 sys5 |
| H3 | cellward's own state and settings (every zone's key, `zone.pid`, the instances' `.instances/` with their control sockets, the registry, raw sockets behind the filters, `broker-always`, `declared/`) | yes | tmpfs over `~/.local/state/vpn-zones` in every zone and every container's instance — an instance keeps its own throwaway layer and never the registry; `~/.config/vpn-zones` and `~/.local/share/vpn-zones` read-only | vm18 sm10 vm56 |
| H4 | Other containers' data | yes | container storage is covered in zones; a launch gets back its own | vm33 vm18 |
| H5 | Programs outside every zone reach the network | only with the system tier's egress policy | nftables by socket owner (`enforce`, `strict`) | sys7 sys8 ho1 |
| H6 | A file in `declared/` speaks in Nix's name (a file chooser a zone's program steers, a program of the host): `hermetic-default off`, a container bound to `unconfined`, the CLI refusing to change it | yes | a declaration counts only when the file, every link followed, is in the Nix store, as home-manager's links are; a plain file or a link elsewhere is ignored with a warning, and the local value or the default applies | vm46 u15 |
| H7 | A container's own word that closes — hermetic on; the Nix daemon, the host's startup files, the raw PipeWire, the cameras off; the microphone or the screen cast `no` rather than `ask` rather than `yes` — ignored because its network's value declared in Nix opens it | yes (review 2026-09-28) | a local word stricter than the network's declared one wins over it, a looser one does not; the container's own declared word wins both ways; `hermetic.default` counts as the network's declared value | u22 |
| H8 | A throwaway container (a one-off, a temporary layer over the home) or a program whose container is not known takes its network's Nix daemon, host files, audio manager or want of hermeticity | yes (review 2026-09-28) | a throwaway's instance comes up with the safe values whatever its network says (`hermetic::value_for`: hermetic, none of the others); the microphone's `yes` is `ask` for it | u23 |
| H9 | The Nix daemon given to a program (`nix_daemon`) while the user, or a group of the user's (`@wheel` too), is in nix.conf's `trusted-users`: the daemon obeys a trusted user in all that makes a build — its sandbox off, a substituter or a `post-build-hook` of its own —, so the program can do what the host's root does | **no** — the host's configuration; `doctor` warns | `doctor` reads `/etc/nix/nix.conf` as Nix does (`include`, `!include`, `extra-trusted-users`, `root` unset) and warns (`nix-trusted`) when a running instance, a container's own word or a network gives the daemon and the user is trusted; the way out: the user and its groups out of `trusted-users` (`allowed-users` is enough to build), or the Nix daemon off | u26 |
| H10 | A container's own word opens a way around its network — no hermeticity (the host's `systemd --user`), the Nix daemon, the host's startup files writable — in a network that does not tolerate it: `offline`, a strict zone, a locked one; the network cannot say no | yes (step 1 of the permission model, 2026-09-28) | a way around the network is open only where the container asks for it and its network tolerates it (`hermetic::explain`); a network tolerates it by its own setting (`hermetic` off, `nixDaemon`, `hostFilesWritable`, the zone's marker), `offline` none whatever is set (refused by the CLI, warned by the module), a locked zone no host session; a container without a word of its own asks for what its network says; `cellward explain` names each decision's words, `status` what a network tolerates (`networks[].tolerates`) | u27 |
| | **Files and the host's startup files** | | | |
| F1 | A zone program reads the home (`~/.ssh`, browser profiles, other programs' data) | own home: yes · otherwise **no** | the sandbox: an empty home plus granted paths | sm8 sm10 |
| F2 | A zone program writes what the host runs later (`~/.bashrc`, autostart, launcher entries, user units, compositor configs, `mimeapps.list`) | hermetic: partly · ordinary: **no** · own home: yes | read-only covers from a list, their parent directories pinned | vm18 |
| F3 | A path grant opens a socket directory or cellward's state; a grant outlives its term | yes | an allow-list of places, checked as written and as resolved at every launch; expiry detaches the bind in running programs | sm10 sm11 u10 |
| F4 | A layer container reads the real home | no, by design | a layer keeps writes out of the real home, not reads | vm34 |
| | **Certificates** | | | |
| T1 | An extra root CA reaches the host or another container | yes | bound in one launch's mount namespace; the variables name the system path; NSS databases written only where proven private | vm27 sm12 |
| T2 | A trust layer that cannot be applied | yes, fail-closed | the launch stops | C · sm22 |
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
| L6 | A container of a locked zone that is not hermetic starts something in another network through `systemd --user`, around the broker that keeps the lock | yes: a launch, a live switch, an attach (2026-09-28) · **no**: an instance attached there before the lock, not hermetic — named, and `doctor` fails | the lock holds a hermetic instance only: a launch into a locked zone, a live switch into it (`locked-target`) and an instance's attach to it (its first, a zone's return, `reattach`) are refused for an instance that came up, or would come up there, not hermetic; `cellward lock`, `status` (`networks[].lock_not_held_by`) and `doctor` (`lock`) name what runs there or is bound to it that is not | vm88 u25 |
| | **Kernel surface** | | | |
| K1 | System calls from a sandbox | partly | a Flatpak-like seccomp blocklist (TIOCSTI, ptrace, keyrings, perf, io_uring, userfaultfd, the new mount API, `pidfd_getfd`); nested user namespaces allowed; a filter that cannot be built stops the launch, never a sandbox without one | u6 |
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
  `broker-always`. That is the host, a non-goal. Since 2026-09-27 what it writes into
  `declared/` is not Nix's word (H6); it can still remove home-manager's link, or point it
  at another file of the store.
- **D2.** NetworkManager, `resolvconf` and openresolv write the file anew and rename it into
  place, and the kernel detaches every mount on the old name in every other mount namespace.
  Until 2026-09-28 the space's file was bound where the chain of links ended and went with
  any rename along it; the space then read the host's file until it restarted: the host's
  resolvers, a fingerprint of its network, names asked of them through the tunnel (a resolver
  on the host's loopback is the space's own loopback, where nothing answers). Now
  (`rust/src/rebind.rs`) the file is attached to the name `/etc/resolv.conf` itself
  (`move_mount` without following it), and only a replacement of the name detaches it; the
  space's process watches `/etc` and lays the file there again on that event. **The window**
  is the host's rename to the re-lay, one wake-up and one mount: a lookup that falls into it
  asks the host's resolvers through the tunnel, as before, never around it. A name the host
  removed and has not made anew leaves the space without a `resolv.conf` (glibc asks its own
  loopback) until it does. A layout the rename cannot touch at all — the space's own `/etc`
  of links into the host's — was weighed and left: it breaks what reads the links of `/etc`
  (the time zone from `/etc/localtime`'s target), freezes `/etc/static` at the generation the
  space came up with and misses what the host adds later, each needing a watch of its own
  that fails in the open when it falls behind. `doctor` (`resolv`) holds the nameservers a
  space sees to those it was given, and names the restart as the way out. The system tier's
  consumers (`/etc/netns/vz-<name>/resolv.conf`, bound by systemd) are not covered by this.
- **W10.** Across zones the user namespaces keep `/proc/<pid>/root` closed (X3). Within a zone
  it is the launch's Landlock domain (X5): on a kernel before 6.12 a program of the zone
  reaches another launch's X server through its process, and can take the abstract name its
  clients try first. Programs of one zone are not walls to each other (§5).
- **W13.** In a sandbox of an ordinary zone, `screencast no` does not apply; nothing is
  remembered there either.
- **W17.** The policy is the container's (`cellward container set <c> focus`,
  `containers.<name>.focus` in Nix), for programs started after it is set, and the proxy's:
  a launch without the proxy (`wayland-proxy off`, its fallback) has the compositor's rules
  alone. `input` keeps a bounded count; a program that makes more than a thousand tokens,
  and asks with as many strings, within the few seconds a compositor keeps a token (niri:
  ten) can get a second change of the focus out of one click. A NEW window focused as it
  opens is the compositor's policy, which the proxy does not see: niri's window rule
  `open-focused false` closes that, for programs outside containers too. The question of
  `ask` takes the focus itself, guarded as W16 (keys typed on are lost, never answers).
- **K1.** Allowed on purpose: `modify_ldt` (Wine's LDT entries: 16-bit programs; Flatpak
  refuses it only without `multiarch`, and the sandbox is always multiarch),
  `process_vm_readv`/`process_vm_writev` (wineserver's `ReadProcessMemory` and
  `WriteProcessMemory`) and `kcmp` (Mesa, before Linux 6.10). What reaches into another
  process is held to the sandbox's own by its pid namespace, where nothing outside has a
  number, and by the kernel's ptrace-mode checks, which want `CAP_SYS_PTRACE` in the target's
  user namespace for a process outside the caller's. Refusing them would wall the program off
  from itself only. `pidfd_getfd`, which no desktop program uses, answers `ENOSYS`
  (LEAK-MODEL §26).
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
| Programs of one container against each other | one instance, one user namespace, one pid namespace, one `/tmp`, one set of abstract sockets: per-program settings are not walls (PERMISSIONS §11.10). Containers are apart (X10): each runs in its own instance, offline and in a zone |
| The person's answer | a "yes" or a grant is taken as meant; W16 guards only against keys typed on |
| Traffic analysis; the VPN provider | what leaves through the tunnel is the provider's to see |

## 6. Rows with no test

These are the gaps. Each is a claim made by construction, or none at all, that no VM or
smoke test tries to break:

- none: X4 (`/proc/<pid>/cmdline` of the host's processes) was the last, and got vm70,
  vm71 and sm28 with stage 3 of the container design (2026-09-27).

Rows whose "no" is itself tested, so that closing it shows: P1 (vm15) and W7 (vm51).

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
- vm10 "an offline instance cannot reach the host's resolver either"
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
- vm26 "picker offline branch: an instance via systemctl --user, lo-only"
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
- vm44 "a zone's program neither sees nor signals the host's processes of the user" (in `tests/vm-promise-signals.py`, as is vm69)
- vm45 "a zone's program cannot reach the host over vsock" (in `tests/vm-promise-vsock.py`)
- vm46 "declared: a plain file or a link out of the store is not Nix's word" (in `tests/vm-promise-declared.py`)
- vm47 "a tunnel zone reaches neither the LAN nor the host's own addresses" (in `tests/vm-promise-lan.py`)
- vm48 "the host's resolv.conf replaced by rename: its own laid again in the zone and the instance, names through the tunnel's DNS" (in `tests/vm-promise-resolv-rename.py`, as are vm85 and vm86)
- vm49 "a compositor without the security context: no Wayland in a zone, all of it unconfined" (in `tests/vm-promise-no-context.py`)
- vm50 "hermetic zone: a shell's IPC in /tmp, in the runtime directory and on the bus is out of reach" (in `tests/vm-promise-shell-ipc.py`)
- vm51 "ordinary zone: a shell's directory out of reach and WAYFIRE_SOCKET gone; /tmp and the bus still in reach" (in `tests/vm-promise-shell-ipc.py`)
- vm52 "one launch's X server: out of reach of another launch and of another zone" (in `tests/vm-promise-x11.py`; its `/proc` and abstract-name parts need Linux 6.12)
- vm53 "an offline launch runs in its container's instance: loopback only, apart" (in `tests/vm-instance-offline.py`, as are vm54–vm59)
- vm54 "two containers' instances share no /tmp, no abstract socket, no System V IPC"
- vm55 "the broker: the same container starts, another one is a person's to say"
- vm56 "an instance's own processes: the fourth subordinate id, out of its programs' reach"
- vm57 "cellward container kill ends every program of the container at once"
- vm58 "an instance ends with its last program, by that event alone"
- vm59 "a throwaway container is erased when its instance ends"
- vm60 "stage 2: the zone's bridge carries a sibling namespace, and refuses it the zone's own addresses" (in `tests/vm-probe-container-ns.py`)
- vm61 "a zone carries an instance: a namespace of its own, out through the zone" (in `tests/vm-instance-bridge.py`, as are vm62–vm68)
- vm62 "an instance reaches nothing that listens in its zone"
- vm63 "the zone's end cuts the instance: its programs live on, with no way out"
- vm64 "the zone back as it was: attached again, with new addresses"
- vm65 "the zone back as another one: cut until the person says"
- vm66 "a launch into the zone runs in its container's instance, not in the zone"
- vm67 "the instance ends with its program, and its zone's passt with it"
- vm68 "a zone of a previous build (no bridge): refused, and the person told its restart"
- vm69 "a program sees another launch of its container, and cannot signal it (X5)" (skipped before Linux 6.12)
- vm70 "an instance's program sees its own container's processes, no one else's" (in `tests/vm-promise-pidns.py`, as are vm71–vm75)
- vm71 "a host process's /proc/<pid>/net is out of an instance's reach"
- vm72 "stopping an instance ends its programs, and reaches no timeout"
- vm73 "a program that ignores TERM ends on cellward container kill"
- vm74 "a daemon forked twice stays in its launch's tree, under profile-run"
- vm75 "an orphan pid 1 adopts is reaped, and counted as a program"
- vm76 "switch: every refusal leaves A attached, its sockets as they were" (in `tests/vm-switch.py`, as are vm77–vm82)
- vm77 "switch: no program reaches the control socket, and the broker has no switch verb"
- vm78 "switch: A to B live — programs stay, nothing of A goes on in B, DNS follows"
- vm79 "switch: the gap — nothing but loopback while the next zone has not answered"
- vm80 "switch: back to B from a cut instance; B stopped while bound — no fallback"
- vm81 "switch: B back — a new epoch; a socket of the one before stays mute"
- vm82 "switch: the keeper killed in the middle — the instance and its programs gone"
- vm83 "an instance's programs are in its epoch; one from a login session holds the switch" (in `tests/vm-instance-offline.py`)
- vm84 "doctor: no program in a zone's own namespaces, and one put there is named" (in `tests/vm-instance-bridge.py`)
- vm85 "the host's resolv.conf a plain file: bound on the name, laid again after the rename"
- vm86 "doctor: the nameservers an instance sees are its own; the host's in their stead fail, with the way out"
- vm87 "file transfer without zones: both ways between the machines, from their LAN addresses", "file transfer in a tunnel zone: through the tunnel only, nothing comes in, no LAN discovery", "file transfer in a hermetic zone: the same; two containers meet only in a granted directory", "file transfer offline: nothing moves" (in `tests/vm-promise-transfer.py`)
- vm88 "switch: settings frozen wider than B's, or not hermetic into a locked zone — refused; --restart goes" (in `tests/vm-switch.py`)
- vm89 "the host's network: made when wanted, the host's routes and resolver" (in `tests/vm-hostif.py`)
- vm90 "without isolation: every device, the protected list written, the network's word on its bypasses holds" (in `tests/vm-protect.py`)

`tests/vm-audio.nix`: au1 "the zone's pipewire-0 is the restricted one, never the host's" ·
au2 "a sink's monitor records nothing" · au3 "the microphone as the zone's switch says" ·
au4 "the microphone by the container of each client" · au5 "PipeWire restarts: the restricted
socket comes back, the raw one never" · au6 "an audio manager gets the raw socket, loudly"

`tests/vm-window.nix`: win1 "the focused window's zone and program; the hotkey menu" ·
win2 "focus input: asking again after one click moves the focus once" · win3 "focus allow:
every request of that click moves the focus" · win4 "focus notify: no request moves the
focus; the person is told" (the last three in `tests/vm-window-focus.py`) · win5 "close
reaches a daemon the program left, through the pid namespace"

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
- sm22 «Доверенный сертификат: слой не лёг — программа не запускается» (an unreadable stored certificate)
- sm23 «Экземпляр: корень — четвёртый подчинённый id, не корень зон» (a container's instance, its keeper started without systemd)
- sm24 «Запуск offline в экземпляр: только lo, своя сеть, зона offline не нужна» (lo only, the registry out of sight)
- sm25 «Экземпляр останавливается сигналом держателю, и его программы — с ним» (a stopped instance ends its programs)
- sm26 «Запуск в зону — в экземпляре контейнера: своя сеть, lo и tap, выход через зону» (a launch into a zone, in its container's instance)
- sm27 «Зона OpenConnect везёт экземпляр: search шлюза в его resolv.conf, выход через туннель» (an OpenConnect zone carries an instance)
- sm28 «Экземпляр: своё пространство pid, процессов хоста в /proc не видно (X4)» (a host process's command line not seen, `/proc/1` the instance's holder)

Rust tests (`cargo test`):

- u1 `rust/src/openconnect.rs`: `connect_takes_the_address_the_mtu_and_the_resolvers_and_nothing_else`, `what_the_gateway_says_cannot_write_a_line_of_its_own`
- u2 `rust/src/openconnect.rs`: `extra_arguments_are_an_allowlist_and_a_shape`, `only_a_real_fingerprint_may_pin_the_server`, `the_client_starts_with_an_environment_we_built_and_not_the_users`
- u3 `rust/src/bus_filter.rs`: `only_the_named_portal_interfaces_get_through`, `the_doors_are_known_by_member_and_interface`, `the_programs_own_register_is_refused_after_ours`
- u4 `rust/src/dbus_wire.rs`: `a_screen_cast_is_not_remembered`; `rust/src/bus_filter.rs`: `the_screen_cast_switch_is_read_for_every_call`, `yes_is_ask_where_the_portal_does_not_know_the_zone`
- u5 `rust/src/wl_proxy.rs`: `hidden_protocols_are_not_in_the_build`, `a_hidden_global_cannot_be_bound_by_its_number`
- u6 `rust/tests/seccomp_cli.rs`: `selftest_passes`, `selftest_passes_with_denied_userns`; `rust/tests/fs_sandbox_cli.rs`: `the_filter_reaches_bwrap_on_the_descriptor_it_names`; `rust/src/fs_sandbox.rs`: `the_sandboxs_filter_is_a_program_on_a_private_descriptor`, `an_empty_program_is_a_refusal_and_not_a_sandbox_without_a_filter`; `rust/src/seccomp.rs`: `the_filter_carries_the_pidfd_getfd_rule`, `what_wine_and_mesa_need_is_not_refused`
- u7 `rust/src/broker.rs`: `always_is_kept_for_programs_of_the_store_only`, `the_program_asked_about_is_pinned_by_its_path`, `always_is_never_offered_for_what_runs_any_command`
- u8 `window/src/main.rs`: `a_guarded_window_takes_nothing_until_the_person_is_still`, `a_question_takes_no_answer_typed_on`
- u9 `rust/src/container.rs`: `a_container_is_never_in_two_networks_at_once`, `a_bound_container_runs_in_its_network_only`
- u10 `rust/src/container.rs`: `the_state_of_this_project_is_never_granted`, `a_grant_is_resolved_before_anything_is_created`
- u11 `rust/src/picker.rs`: `a_program_seen_for_the_first_time_gets_a_home_of_its_own`
- u12 `rust/src/pulse_filter.rs`: `module_loading_is_refused_and_answered_as_the_server_would`, `recording_a_monitor_is_refused_before_the_server_sees_it`
- u13 `rust/src/launch.rs`: `a_name_on_the_list_is_only_the_program_the_system_gives_under_it`
- u14 `rust/src/seccomp.rs`: `the_zone_socket_filter_builds`
- u15 `rust/src/declared.rs`: `a_link_into_the_store_is_declared`, `a_plain_file_or_a_link_elsewhere_is_not_declared`, `a_held_directory_is_read_as_held`; `rust/tests/vpn_zone_cli.rs`: `a_plain_file_in_declared_is_not_nixs_word`
- u16 `rust/src/wl_focus.rs`: `one_input_event_is_one_change_of_the_focus`, `a_forgotten_serial_is_still_used_up`, `a_forgotten_token_of_the_launch_is_used_up`; `rust/src/wl_proxy.rs`: `input_passes_one_activate_per_input_event`, `notify_sends_the_byte_and_no_activate`, `allow_passes_every_activate`
- u17 `rust/src/init.rs`: `a_stop_from_outside_ends_the_space_then_pid_1`, `a_stop_from_inside_is_nothing`, `the_space_ending_by_itself_is_a_failure`; `rust/src/profile.rs`: `the_subreaper_says_the_main_programs_end_once`, `a_signal_goes_to_the_program_and_the_orphans_it_adopted`; `rust/src/enter.rs`: `the_main_programs_status_is_read_back`; `rust/src/place.rs`: `an_orphan_pid_1_adopted_is_a_program`; `rust/src/launch.rs`: `the_main_home_guard_finds_the_program_outside_the_instance`, `an_instance_of_the_real_home_is_known_by_its_id_or_its_container`; `rust/src/doctor.rs`: `an_instances_programs_see_its_processes_alone`; `rust/src/dbus_wire.rs`: `no_hint_carries_a_pid`; `rust/src/sys.rs`: `a_zombie_under_a_stopped_parent_has_its_parent_continued`; `rust/src/kill.rs`: `a_container_is_not_named_by_a_network_of_its_name`
- u18 `rust/src/switch.rs`: `every_precondition_refuses_alone`, `the_look_now_decides_whether_a_program_is_outside`, `every_failure_after_the_cut_ends_offline_and_never_on_the_old_network`, `a_request_is_its_word_and_a_network`; `rust/src/epoch.rs`: `the_wall_stands_from_the_second_epoch_on`, `a_process_is_in_its_epoch_by_its_cgroup_line`, `whether_it_can_be_switched_says_the_first_reason`; `rust/src/zone.rs`: `an_instance_goes_out_from_its_own_address_only`, `a_switchs_break_closes_an_instance_to_loopback`; `rust/src/sockdiag.rs`: `a_switch_breaks_what_may_reach_out_and_spares_the_rest`; `rust/src/relay.rs`: `the_probe_leaves_nothing_behind`; `rust/src/registry.rs`: `a_switch_moves_the_records_of_its_network_only`; `rust/src/profile.rs`: `a_term_goes_to_the_whole_tree_below`; `rust/src/microphone.rs`: `an_instances_filter_follows_the_network_it_is_in_now`, `an_instances_pipewire_follows_the_network_it_is_in_now`; `rust/src/screencast.rs`: `an_instances_filter_follows_the_network_it_is_in_now`; `rust/src/bus_filter.rs`: `an_app_id_is_checked_and_passed`
- u19 `rust/src/rebind.rs`: `a_name_is_laid_when_it_leads_to_the_spaces_own_file`, `the_spaces_own_file_is_a_regular_file_and_not_a_link`, `an_event_concerns_the_name_it_is_about_and_no_other`, `the_hosts_rename_over_the_name_wakes_the_watch`; `rust/src/doctor.rs`: `a_space_sees_the_nameservers_it_was_given_or_fails`
- u20 `rust/src/zone.rs`: `no_zone_gets_a_shells_ipc`; `rust/src/sockets.rs`: `what_the_project_promises_closed_fails_and_the_rest_warns`
- u21 `rust/src/switch.rs`: `every_precondition_refuses_alone`; `rust/src/hermetic.rs`: `frozen_settings_wider_than_a_networks_are_named`; `rust/src/status.rs`: `an_instances_frozen_settings_are_its_note`
- u22 `rust/src/hermetic.rs`: `a_containers_own_setting_is_taken_in_the_cameras_order`, `a_local_word_closes_under_nix_and_never_opens`; `rust/src/microphone.rs`: `a_local_word_closes_under_nix_and_never_opens`, `a_container_has_its_own_setting_and_nix_is_never_overridden`; `rust/src/container.rs`: `a_containers_camera_is_its_own_and_nix_is_not_overridden`
- u23 `rust/src/hermetic.rs`: `a_throwaway_comes_up_safe_whatever_its_network_says`
- u24 `rust/src/x11.rs`: `a_containers_own_x11_decides_and_off_refuses_the_zones`; `rust/tests/vpn_zone_cli.rs`: `a_container_with_x11_gets_its_own_x_server_in_zones_only`
- u25 `rust/tests/vpn_zone_cli.rs`: `a_locked_zone_refuses_a_container_that_is_not_hermetic`; `rust/src/doctor.rs`: `a_locked_zones_containers_that_are_not_hermetic_are_named`; `rust/src/switch.rs`: `every_precondition_refuses_alone`
- u26 `rust/src/doctor.rs`: `nix_confs_trusted_users_are_read_as_nix_reads_them`, `the_nix_daemon_of_a_trusted_user_is_named`
- u27 `rust/src/hermetic.rs`: `a_way_around_the_network_needs_both_words`; `rust/tests/vpn_zone_cli.rs`: `explain_says_who_asked_and_what_the_network_tolerates`, `a_networks_restart_needed_is_its_instances`
