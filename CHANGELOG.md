# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Changed (system tier)
- A user zone through a system zone follows the system zone being made anew
  (its namespace unit restarted, vpn-zones off and on): the service starts
  its pasta in the new namespace once the way out there is up, with no
  restart of the user zone; in between the zone has no way out at all.

### Added
- A user zone through a system zone (`docs/SYSTEM.md` §7b): `[SystemZone]
  Name = <zone>`, or `vpn-zone add <zone> --system <system zone>`. No tunnel
  of its own: the system-zone service starts pasta in the system zone's
  network, as the user, attached to the user zone — one VPN, one tunnel, for
  services and programs, graphical ones included, with everything a user
  zone has. `vpn-zone add` with a config whose key is a system zone's makes
  such a zone by itself instead of a second tunnel. `status --json`: kind
  `system-zone` and a new key `system_zone` on every network; the picker
  names the system zone. `tests/vm-bridge.nix`.

### Security
- `host.dns` with NetworkManager and resolved: NetworkManager's
  `systemd-resolved` key (true by default) still sent every connection's
  resolvers to resolved under `dns = "none"`, so part of the host's names
  could go to the router around the zone. Now `dns = "default"`,
  `rc-manager = "unmanaged"`, `systemd-resolved = false`; with networkd, a
  network that would hand resolved its resolvers does not build. dhcpcd's
  `nohook resolv.conf` landed inside an `interface` block and held for one
  interface only: the hook is now skipped from `/etc/dhcpcd.enter-hook`. A
  NetworkManager host in `tests/vm-host.nix` checks it, and no link of any
  test host may have a resolver of its own.

### Changed (system tier)
- A plain zone's resolvers are the router's, as the host knows them
  (NetworkManager's copy, resolved's upstreams, /etc/resolv.conf), followed
  as the network changes; the public ones only when the host knows none.
  The host's DNS forwarder does the same when vpn-zones are off.

### Added (system tier)
- The host's names through a zone: `host.dns = "<zone>"`. A forwarder
  (`vpn-zone-core dns-forward`) gets UDP and TCP sockets on 127.0.0.60:53
  from systemd in the host's network and asks from the zone's; resolved (or
  /etc/resolv.conf) points there alone, DHCP's resolvers are ignored. Off, it
  asks the same addresses from the host. `zones.<z>.dns`: a zone's own
  resolvers. `docs/SYSTEM.md` §9c.

### Added (system tier)
- `egress.mode = "strict"`: the host itself loses the internet too — root
  and the system's users keep the local network (`egress.localNetworks`,
  checked when the system is built) and DHCP. `host.nix` and `host.time` put
  the Nix daemon and systemd-timesyncd into a zone (a plain one is
  "directly", a VPN one hides them); the daemon does not wait for the tunnel.
  NetworkManager's connectivity check is turned off under `strict`; `nixbld`
  is no longer allowed by default there. Build warnings name what `strict`
  would cut off. `docs/SYSTEM.md` §9b, `tests/vm-host.nix`.

### Changed
- The namespace unit of a system zone (`vpn-zone-system-ns@`) has no default
  dependencies (after the local file systems and tmpfiles only), so early-boot services can be
  attached to a zone.

### Added (system tier)
- The off switch: `vpn-zones-off` turns vpn-zones off entirely with no
  rebuild and no network — the policy's table goes, attached services restart
  on the host's network, zones stop, and a flag in `/var/lib/vpn-zones` keeps
  it so across reboots; `vpn-zones-on` turns it back. Plain systemd units, no
  binary of ours; `services.vpn-zones.system.switchGroup` (`wheel`) may use
  them without a password; `[x]` in the TTY console; `vpnzones=off` on the
  kernel command line for one boot. `docs/SYSTEM.md` §9a.

### Changed
- Services are attached to system zones by a systemd generator (a drop-in in
  `/run`), not in their unit definitions, so the switch can detach them.

### Fixed
- The user-tier VM test waits for the broker instead of racing it.

### Security
- The host egress policy fails closed when this project's binary fails: its
  restriction is printed when the system is built and loaded by `nft` alone;
  `vpn-zone-core egress allow` only adds allowances afterwards, and its failure
  leaves the host more closed, never open. The emergency key closes the host
  again from the same file. New verbs `egress print` and `egress allow`.

### Added (system tier)
- One VPN, added once: `vpn-zone-sys --add <zone> <config.conf>` (or
  `--plain`) makes a system zone on the spot — no rebuild, no root for the
  user — and the same private key again answers which zone it already is
  instead of a second tunnel. `vpn-zone-sys --up <zone>`.
  `services.vpn-zones.system.users`: who may add zones.
- Rescue paths: the emergency key deletes the policy's table with `nft` alone;
  `vpnzones.egress=off` on the kernel command line keeps the policy from
  loading. `docs/SYSTEM.md` §9a.

### Changed
- System zones are instances of templates: `vpn-zone-system-ns@<zone>` and
  `vpn-zone-system@<zone>`; the holder reads a zone's settings itself.
- The TTY console brings a zone up through the system-zone service, not polkit.

### Added (system tier)
- The TTY console: `services.vpn-zones.system.console`. Logging in on a text
  console lands in a small menu with a network already — a terminal in the
  console's system zone with one key, the plain fallback zone when the VPN
  does not come up, an admin tool, the emergency key, the plain console. Shown
  in interactive login shells on a virtual terminal only, for the zone's users;
  every failure ends in the ordinary shell. The zones' users may start their
  zones (polkit). `rust/src/console.rs`, `docs/SYSTEM.md` §7a.

### Added (system tier)
- Plain system zones: `services.vpn-zones.system.zones.<name>.kind = "plain"` —
  a namespace of its own that goes out through the host's network by pasta
  (as the system user `vpn-zones-plain`), not encrypted, with the host's
  loopback and port forwarding shut. The way a program goes out directly once
  the host egress policy is enforced, and the TTY console's fallback when the
  VPN cannot come up. `system_networks[].kind` is `plain` for them.

### Added (system tier, ROADMAP M10 stage 5)
- The host without a network of its own: `services.vpn-zones.system.egress`
  (`audit` by default, `enforce`). An nftables table of its own lets out root,
  system and dynamic users, the uplinks of user zones (the first ids of
  `/etc/subuid`/`/etc/subgid`), system zones' tunnels (by a mark: their kernel
  socket has no owner) and the named users and groups; a user's program
  outside every zone is logged as `vpn-zones-egress: … UID=`, and refused under
  `enforce`. Survives a firewall that flushes every table. An emergency key,
  `vpn-zones-egress-open.service`, lifts it for 15 minutes; `wheel` may turn it
  (polkit, which the module turns on). `rust/src/egress.rs`, `docs/SYSTEM.md` §9.

### Changed
- A system zone's tunnel marks its encrypted packets with `FwMark = 0x767a`,
  replacing any `FwMark` of the config.

### Added (system tier, ROADMAP M10 stage 4)
- `vpn-zone-sys <zone> [--] <command>`: a user's console program in a system
  zone, for the users in `services.vpn-zones.system.zones.<zone>.users`. A
  socket-activated service (`vpn-zone-sysrun@`, one unit per launch) learns who
  asks from the kernel, enters the zone, hides the host's resolvers, the system
  bus and the session's sockets, drops to the user with `NO_NEW_PRIVS` and runs
  the command; the pty is the client's own. `rust/src/sysrun.rs`,
  `docs/SYSTEM.md` §7.

### Security (system tier)
- Services in a system zone get the zone's `nsswitch.conf` (`hosts: files dns`,
  written by `ns-up`) and no `/run/avahi-daemon`, as user zones have had: a
  `.local` name went to the host's LAN through nss-mdns.

### Added (system tier, ROADMAP M10 — not built or run yet)
- `nixosModules.default` (`module/nixos.nix`): system zones held by systemd
  from boot — `services.vpn-zones.system.zones.<name>` — and services and NixOS
  containers attached to them (`…system.services.<unit>.zone`,
  `…system.containers.<name>.zone`). Optional; without it everything stays
  rootless. Design: `docs/SYSTEM.md`; the target picture:
  `docs/ARCHITECTURE.md`.
- `vpn-zone-core system-zone ns-up|ns-down|up|down <name>` (`rust/src/system.rs`):
  the namespace `/run/netns/vz-<name>` with `lo` and the second echelon; the
  tunnel created in the host's namespace and moved in as `awg0`; the zone's
  resolv.conf written in place; `READY=1` to systemd; the status mirror in
  `/run/vpn-zones/system/<name>/` for the group `vpn-zones`.
- `vpn-zone status --json`: a top-level `system_networks` array (additive,
  schema 1).
- A service in a system zone gets `/run/nscd`, resolved's varlink socket and by
  default the system bus hidden; a NixOS container gets its own user namespace
  and no access to the host's Nix daemon socket, which nixpkgs binds into every
  container and through which the host downloads whatever it is asked to.
- `tests/vm-system.nix` and a `vm-system` CI job.

### Changed
- The crate's derivation moved to `package.nix`, shared by both modules. Same
  text, same store path.

### Security (compositor sockets, LEAK-MODEL §13)
- No zone gets the compositor's own `wayland-*` socket or the IPC of niri,
  sway, Hyprland or i3 any more — through them a program in a zone could have
  the compositor spawn a process on the host, or type into a host terminal
  with a virtual keyboard. Every zone's runtime directory is a tmpfs with
  entries bound back: a hermetic zone keeps pipewire, pulse and doc; an
  ordinary zone everything else, the session bus and `systemd --user`
  included. Entries the host creates later (a restarted pipewire or dbus) are
  bound in by a watcher; refused names stay refused.
- `wl-sandbox` wraps the whole launch and runs on the host; the restricted
  socket lives in `$XDG_RUNTIME_DIR/vpn-zones/wayland/<zone>/` and
  `WAYLAND_DISPLAY` points there. `fs-sandbox` now gets that socket instead of
  the compositor's own one.
- `vpn-zone doctor`: `wayland-raw` and `compositor-ipc` checks; `session-bus`
  is reported filtered only when the bound bus is the zone's proxy.

### Changed (compositor restriction in zones)
- In a zone the Wayland restriction always applies: the built-in allowlist,
  `~/.config/vpn-zones/wayland-allow` and `vpn-zone wayland-sandbox off` apply
  to `unconfined` launches only. A screenshot tool or a clipboard manager that
  needs the full protocols has to run unconfined. With a compositor without
  `wp_security_context_v1` a program in a zone gets no Wayland at all.
- `NIRI_SOCKET`, `SWAYSOCK`, `I3SOCK`, `HYPRLAND_INSTANCE_SIGNATURE` are
  dropped from launches into a zone. `wl-sandbox` takes `--zone <zone>`.

### Changed (kill exit codes)
- `vpn-zone kill` exit codes are a contract now: 0 cut off, 1 programs killed
  but the zone not down, 2 the zone is not up, 3 refused (nothing touched).
  "Not up" and "refused" were both 1.

### Added (grants with a term)
- `vpn-zone container grant sb:<name> <dir> --for 30m|2h|7d` and a term
  choice in the GUI. A grant past its term is absent from every launch; for
  programs already running a user timer runs `vpn-zone container expire`,
  which detaches the directory in their mount namespaces. `revoke` now does
  that at once too, instead of "from the next launch".
- Journal events `grant`, `revoke`, `grant-expired`; `status --json` and
  `container show --json`: `permissions.paths[]` gains `expires` (additive).

### Added (cut a zone off)
- `vpn-zone kill <zone>` and the «Оборвать VPN-зону» launcher entry
  (`vpn-zone-gui kill`): every program in the zone's network namespace is
  frozen, the zone goes down, the frozen programs are killed — for a
  remote-access session that has to end now. The zone's own processes are
  left to `systemctl stop`; signals go through pidfds; a "zone" whose
  namespace is the host's is refused. Recorded in the journal as `kill`.

### Added (unconfined in sight)
- A journal of what was let out of containment: every launch into
  `unconfined` (`launch-unconfined`: app, container, program, pid) and every
  decision of the broker (`broker`: origin zone, target, app, started or
  refused and why). JSON lines in `~/.local/state/vpn-zones/.journal` (0600,
  rotated at 1 MiB into `.journal.1`); `vpn-zone journal [--json] [<N>]`
  reads it (`{"schema_version": 1, "events": [...]}`).
- `status --bar`: programs running unconfined right now are marked in the text
  (`⚠N`) and named in the tooltip; the object gains `"unconfined": N`
  (additive; `class` is unchanged).

### Changed (breaking, with the old name kept)
- The built-in network `direct` is now `unconfined`: the name says that nothing
  of a zone is around the program — no VPN, the host's resolver, session bus,
  `systemd --user` and X server. `direct` stays an alias everywhere a network
  name is read — `vpn-zone run`, `vpn-zone default`, `container set … network`,
  `defaults.network` and `containers.<n>.network` in Nix, pins, `.last`,
  settings and registry records written before — and is never written again.
  The picker and the GUI call it «Без ограничений — сеть хоста, без VPN и без
  изоляции зоны».
- `status --json` (schema_version 1): the built-in entry of `networks[]` is
  `{"name": "unconfined", "kind": "unconfined", "aliases": ["direct"], …}`,
  every entry has `aliases` (additive), and `defaults.network.value`,
  `containers[].network.value`, `apps[].network.value` and the live launches'
  `network` say `unconfined` where they said `direct`. A consumer matching
  `direct` must accept `unconfined` (or read `aliases`).
- Migration: a zone the user had named `unconfined` is no longer entered — a
  launch into it is refused instead of silently using the host's network, the
  picker does not offer it and `vpn-zone doctor` fails on it. Rename its
  directory in `~/.local/state/vpn-zones/`. `vpn-zone add` refuses the name.

### Added (hermetic switches)
- `programs.vpn-zones.hermetic.default` and `hermetic.exceptions` (zones set
  opposite to the default; the default is required with them), and locally
  `vpn-zone hermetic --default on|off` and
  `vpn-zone hermetic <zone> on|off|default`. The default is still off.
- `status --json`: `defaults.hermetic` (additive); `networks[].hermetic` now
  names `nix` when the value comes from the module.

### Changed
- `vpn-zone hermetic <zone> off` writes `off` into the zone's marker instead of
  removing it, so that it holds against a default that is on; `default`
  removes it. A marker left by the prototype (empty) still means on.

### Added (egress marker)
- `status --json` carries `uplink_owner`: the host uid and gid every zone's way
  out runs under (the zone's uid 0, the start of the user's subordinate
  ranges), for a host egress policy matching `meta skuid` (additive).

### Added (hermetic zones — prototype, off by default)
- `vpn-zone hermetic <zone> on|off` (takes effect at the zone's next start):
  the zone's runtime directory is a tmpfs of its own with only the Wayland,
  PipeWire and PulseAudio sockets and the document portal bound back; the
  session bus is a filter (portals, notifications, tray, MPRIS, IBus/fcitx,
  the screensaver inhibitor — not `systemd1`, not the Secret Service);
  `systemd --user` is out of reach. A launch out of such a zone goes through
  the broker (`vpn-zone-broker` user service): into the same zone at once,
  into another network only after a person says yes, never from a locked
  zone. `status --json` networks carry `hermetic` as `{value, source}`;
  `doctor` reports the session bus as filtered. The owner's decision C, as the
  prototype that is proven before it becomes the default.

### Added (X11 per zone)
- `vpn-zone x11 <zone> on|off` and `programs.vpn-zones.zoneX11 = [ names ]`:
  every program launched into such a zone gets an X server of its own
  (`x11-run`), without any container — Steam in a zone for someone who runs
  zones only. The host's X server stays out of reach. `status --json`
  networks carry `x11` as `{value, source}` (`null` for `direct` and
  `offline`'s built-in entry; additive).

### Security (X11 closed in zones)
- A zone hides `/tmp/.X11-unix` behind a tmpfs of its own, and a launch into a
  zone carries no `DISPLAY` or `XAUTHORITY`: the host's X server — every
  client of which sees the windows, the keyboard and the clipboard of all the
  others — and the X servers of other zones are out of reach (the owner's
  decision A). A container with `x11` — `vpn-zone container set <c> x11 on` or
  `programs.vpn-zones.containers.<name>.permissions.x11` — gets an
  `xwayland-satellite` of its own in zones (`vpn-zone-core x11-run`, started
  inside `wl-sandbox` and taken down with the program); a sandbox is told the
  same and starts its own. `container show --json` carries `x11` as
  `{value, source}` (additive). **Behaviour change:** X11-only programs in a
  zone (Steam, some Electron builds) need a container with `x11`.

### Security (the system bus in zones is filtered)
- Every zone gets its own `xdg-dbus-proxy` in front of the system bus, bound
  over `/run/dbus/system_bus_socket` in the zone's mount namespace: UPower
  whole, login1 only `Inhibit` and reading properties; NetworkManager,
  hostname1, resolve1, machined and timedate1 are filtered out (the owner's
  decision B2). A zone whose proxy cannot start has no system bus at all
  (tmpfs over `/run/dbus`); a proxy that dies leaves the zone without one.
  `zone-holder` takes `--dbus-proxy`. `doctor` reports the system bus as
  filtered or closed. **Behaviour change:** NetworkManager applets and
  anything asking hostname1 inside a zone stop getting answers.

### Added (JSON)
- `status --json` networks carry `interface`: the host interface of a
  `host-interface` network, `null` for every other kind (additive, schema
  version 1). `docs/CONTAINERS.md` §9 now states the keys to join on:
  containers by `selector`, networks by `name`, programs by launcher key.

### Added (PATH shims, opt-in)
- `programs.vpn-zones.pathShims.enable` (off by default): for every program
  assigned to a container, `sync` writes `~/.local/share/vpn-zones/bin/<program>`,
  which goes through the picker like a click on the entry, and the directory is
  put on the session's PATH. The shim calls the real program found outside its
  own directory, never itself; a file of that name that is not a shim is left
  alone. A convenience, not a boundary.

### Changed (a machine-id of the sandbox's own)
- A sandbox no longer shows the host's `/etc/machine-id`, one identifier shared
  by every zone and sandbox of the machine: a named sandbox gets one of its own,
  kept in its directory, and a throwaway sandbox a new one at every launch.
  **Behaviour change:** programs that register a device by machine-id (some
  launchers and sync clients) see a new device once per named sandbox.

### Added (containers in the GUI)
- A «Контейнеры VPN-зон» launcher entry (`vpn-zone-gui containers`): pick a
  container, then change its network, merge it into another container of the
  same kind (asking again before foreign root certificates are accepted), or
  grant a home of its own a directory from a chooser and take one back. Every
  change goes through `vpn-zone container`, whose refusals are shown as they
  are.

### Added (tunnel watch)
- `vpn-zone watch [--json]`, run every minute by a user timer
  (`programs.vpn-zones.tunnelWatch.enable`, on by default): a tunnel that sends
  into silence — the transmitted counter grows, the received one does not, and
  the last handshake is older than 180 s or never happened — is dead after two
  looks in a row, and a notification says so once; another one says when it
  answers again. OpenConnect and host-interface zones are judged by their
  mirror's `connected`/`disconnected`.
- `status --json` networks carry `handshake_age_s`, `rx_bytes` and `tx_bytes`
  (additive, schema version 1).
- `vpn-zone status --bar`: one JSON line for a status bar (waybar's
  `return-type: json`): the zones that are up, a dead tunnel marked, and a
  class of `none`, `up` or `dead`. Reads only the mirrors and the watcher's
  memory, so a bar can poll it often.
- The picker's network menu says "— туннель не отвечает" next to a zone the
  watcher found dead, and names a host-interface network "Через интерфейс: …
  (без шифрования)" instead of calling it a VPN.

### Fixed (a granted directory that does not exist)
- A sandbox granted `~/Downloads`, `~/Documents` or `~/Pictures` that does not
  exist no longer fails to start: the directory is bound with `--bind-try`, and
  the launch says which one is missing. Nothing is created in the real home.

### Added (networks through an interface of the host)
- A zone whose config has a `[HostInterface]` section (`Interface =`, optional
  literal `DNS =`) goes out through that interface of the host and nothing
  else: no uplink, pasta attached to the app namespace with every socket bound
  to the interface (`--outbound-if4/-if6`), its interface named `awg0` so the
  zone's filter, `doctor` and `check` apply unchanged, no port forwarding, an
  address of its own (`10.255.255.253/30`). A missing interface is a zone that
  refuses to come up. Not encrypted by the zone: `status --json` reports the
  kind `host-interface` (the owner's decision of 2026-09-17).

### Security (pasta's port forwarding shut)
- The uplink's pasta is started with `-t none -u none -T none -U none
  --no-map-gw`. Its defaults bound every port of the uplink — the tunnel's own
  UDP socket — on every address of the host and forwarded it in, offered every
  port of the host's loopback on the uplink's loopback (which the uplink's
  filter accepts), and mapped the gateway address to the host's loopback. The
  tunnel's own flows need none of it.

### Changed (lossless launcher keys, with migration)
- **The memory key of a launcher entry no longer loses characters.** Two
  entries whose names differed only in characters outside `[A-Za-z0-9._-]`
  (`Игра` and `Мама`, `a b` and `a_b`) shared one key — one network pin, one
  container, one sandbox home — and the second program silently went where the
  first had been sent. Such a key now carries the FNV-1a hash of the name
  (`Zen_Browser-a5ffb3fa`); plain ASCII ids do not change. **State migration:**
  the first `sync` moves pins, last choices, labels, file permissions and the
  own sandbox of a key that belonged to one entry to its new key; memory of a
  key that several entries shared is dropped, and those programs ask again.
  Declared `containers.<name>.apps`, `container assign` and `launch` use the
  same keys (`docs/LAUNCHERS.md` §3.4).

### Changed (web apps are children of their browser)
- An entry that opens a web app of a Chromium-family browser (`--app-id=`,
  `--app=`) is launched under the id of that browser's entry, like a Steam game
  under Steam's: the running browser opens the window in its own network and
  profile, so a pin of the web app's own promised a choice nobody could honour.
  No clones and no label of its own; without a browser entry it stays a
  program of its own.

### Added (doctor)
- `vpn-zone doctor [<zone>…] [--json]`: system readiness (user namespaces,
  `newuidmap`, subordinate ids, `/dev/net/tun`, the tools of the manifest), the
  context it runs in (a zone, a sandbox), and a probe run INSIDE every zone that
  is up — only `lo` and `awg0`, default routes into the tunnel only, `hosts:
  files dns`, no host resolver socket in reach — plus the tunnel's liveness.
  The channels `docs/LEAK-MODEL.md` lists as open (session bus, `systemd
  --user`, system bus, X11) are reported as warnings every time. Exit code 1
  when a promised property does not hold; `--json` carries `schema_version`
  and a level per check.

### Changed (D-Bus activation goes through the picker)
- A `DBusActivatable=true` program intercepted by the picker now also gets a
  shadow session service in `~/.local/share/dbus-1/services/` with the same bus
  name, starting it through the picker: activation by name (`gapplication
  launch`, notification actions, "open with", other programs) started it in the
  host's network, uncontained. Only intercepted entries with well-formed names;
  a user's own service file is never overwritten; `mode off` removes ours.
  `vpn-zone-core sync` takes an optional fifth argument, `systemctl`, to reload
  the session bus when a shadow changed (`docs/CONTAINERS.md` §5.3).

### Added (launch by id)
- `vpn-zone launch <id> [-- <arguments>]`: a launcher entry started through the
  picker by its id, the way a click starts it — for compositor key bindings
  (`spawn "vpn-zone" "launch" "firefox"`) and scripts. The program's own entry
  is used (a taken-over one from its backup, our picker entries skipped), field
  codes are filled like a launcher fills them, `VPN_ZONE_DRYRUN=1` prints the
  command, and the shells complete the ids (`docs/CONTAINERS.md` §5.1).

### Changed (XDG autostart goes through the picker)
- **The user's `~/.config/autostart` entries are taken over in place**, like
  the user's launcher entries: a program that switched its own autostart on
  started at login in the host's network, uncontained. Now it starts where it
  was put — its pinned or assigned container, that container's network or its
  network pin — and what nobody chose is the closed variant: `offline`, a home
  of its own, no dialog of any kind, and a notification saying so. The last
  choice and the global network default are not used unasked. Originals are
  kept in `~/.local/state/vpn-zones/.adopted-autostart/`; `vpn-zone mode off`
  or the new option `programs.vpn-zones.autostart.unassigned = "as-is"` (local
  file `~/.config/vpn-zones/autostart`) gives them back byte for byte.
  Symlinks, disabled entries and `/etc/xdg/autostart` are not touched
  (`docs/CONTAINERS.md` §5.2, the owner's decision of 2026-09-17).

### Added (path grants and merging containers)
- `vpn-zone container grant|revoke sb:<sandbox> <dir>` and
  `programs.vpn-zones.containers.<name>.permissions.paths`: a directory of the
  real home or of a data disk (`/mnt`, `/media`, `/run/media`, `/srv`) seen
  read-write by the programs of a home of their own — a Wine prefix, a Steam
  library. An allow-list: sockets (`/run`, `/tmp`), `/etc`, the home itself and
  the state of vpn-zones (zone keys) are never granted, checked as written and
  as resolved, in the CLI and again by `fs-sandbox` at every launch.
  `container show --json` lists them under `permissions.paths` (additive,
  schema version 1).
- `vpn-zone container merge <from> <into> [--yes]`: containers of one kind are
  merged — what `<into>` has is kept, conflicting versions from `<from>` go to a
  fresh `.merged-from-<from>/`, programs are reassigned, certificates new to
  `<into>` need `--yes`, permissions are not copied, `<from>` is kept. Refused
  while either runs and for containers declared in Nix.

### Changed (invariant: foreign entries in the user's applications directory)
- **Entries programs write into `~/.local/share/applications` are now taken
  over in place** — Steam games, browser web apps, Wine entries and, above
  all, the `userapp-*` entries a browser or a messenger writes when it makes
  itself the default handler. `mimeapps.list` sends links to exactly those
  files, so until now every link opened from a host program started the
  browser uncontained, in the direct network, although the browser's own
  system entry was intercepted. The original bytes are kept in
  `~/.local/state/vpn-zones/.adopted/` before anything is written, the entry is
  rewritten like a picker shadow (`X-VPNZone=adopted`), a program that rewrites
  its entry has it taken over again, and `vpn-zone mode off` or
  `interception.userEntries = "leave"` gives every original back byte for
  byte. Symlinks (home-manager, Nix) are never touched. This changes the
  written invariant "foreign files there are never rewritten"
  (`docs/LAUNCHERS.md` §3.2, the owner's decision of 2026-09-17).
- Desktop sync passes run one at a time (a lock in the state directory) and
  write entries, backups and restored originals through a rename: the path
  unit starts a pass on the very write of another pass, and a pass that read a
  half-written entry kept the fragment as the original.

### Security (a zone's own nsswitch.conf)
- A zone binds its own `/etc/nsswitch.conf`, the host's with `hosts:` reduced
  to `files dns`. Hiding the host's resolver sockets was a list (nscd,
  systemd-resolved, avahi) that the next NSS module talking to a host daemon
  would not be on — `mymachines` already asks machined over the system bus.
  Now no module but the plain resolver is loaded for a name inside a zone, and
  it reads the zone's resolv.conf. Other databases stay as the host has them. A
  failure is a loud warning, like the nftables echelon: the sockets are still
  hidden. Checked in the smoke and VM tests.

### Added (containers as identities: network binding, Nix options, JSON state)
- **A container can be bound to one network**: `vpn-zone container set
  <container> network <network|ask>`. `vpn-zone run` then refuses a bound
  container in any other network (and names the way out), and refuses ANY
  container — bound or not — in a second network while its programs run in a
  first: one identity, one network at a time (`docs/CONTAINERS.md` I1, I2).
  The picker takes a bound container's network as the answer, above a network
  pin. **Behaviour change:** starting a program of a data container in network
  B while another program of the same container runs in A is now refused;
  before, only the same program warned.
- `vpn-zone container list|show|set|assign|unassign`: containers with their
  network, programs and trusted certificates, and where each value comes from.
- `vpn-zone status --json`: the whole state for configuration tools —
  `schema_version` and `{value, source: nix|local|default}` for every
  settable value, plus runtime facts (networks up and alive, running
  programs). `container list|show --json` print parts of it.
- **home-manager options** — `programs.vpn-zones.defaults.{network,container}`,
  `launcher.mode`, `compositorRestriction.enable` and
  `containers.<name>.{home, network, apps, trust.{certificates,
  acknowledgeRisk}}`. The module writes `~/.config/vpn-zones/declared/`; the
  runtime reads it first, and the CLI and the GUI refuse to change a value
  declared there instead of writing a file that would change nothing.
  Declared certificates are checked at BUILD time (exactly one certificate per
  file, `CA:TRUE`); assertions catch a certificate without `acknowledgeRisk`, a
  program assigned to two containers and an unusable container name. The
  activation creates the directories of declared containers.

### Added (extra root certificates per container)
- `vpn-zone trust add|list|rm|reset`: a root certificate — a national CA, a
  corporate inspection root, a test CA — trusted by the programs of ONE data
  container or named sandbox, and by nothing else: not the host, not the
  container next door (`docs/CERTIFICATES.md`). `add` takes exactly one
  certificate with `basicConstraints CA:TRUE`, shows subject, issuer, validity
  and fingerprint with a loud warning and asks for the container's name.
- At launch `profile-run` binds the host's bundle plus the container's roots
  over the file every bundle path resolves to (on NixOS one store file, which
  NSS also reads through p11-kit), points `SSL_CERT_FILE` and its relatives at
  the SYSTEM path so a leaked variable is harmless, and installs the roots into
  the container's own NSS databases with `certutil` — never into one it cannot
  prove to be the container's. A bundle that cannot be laid down stops the
  launch. The manifest gains `openssl` and `certutil`.
- Covered by the smoke test (Ubuntu layout) and the VM test (NixOS store
  layout, p11-kit, and an environment pushed into the user manager).

### Fixed
- `vpn-zone run <zone>` with no command started nothing after the working
  directory fix put `profile-run` between `nsenter` and the program; it starts
  a shell again.

### Deprecated
- **Per-zone launcher clones** (`vpn-zone mode per-zone` and `both`). A clone
  is "this program, in that network" on every click — exactly how one identity
  ends up in two networks — and clones grow as programs × zones. `vpn-zone
  mode`, `vpn-zone sync` in those modes and the GUI settings now say so;
  nothing is removed yet. The replacement is the single intercepted entry and,
  later, per-container entries (`docs/LAUNCHERS.md` §4).

### Changed (design)
- `docs/CONTAINERS.md` and `docs/LAUNCHERS.md` carry the owner's decisions of
  2026-09-17: a container's network changes explicitly and can be a host
  interface as well as a zone, every program gets a home of its own with a way
  to merge two containers, entries in the user's applications directory are
  taken over in place, unassigned autostart starts offline with a
  notification, and the JSON state carries `schema_version` and the origin of
  every value.

### Added (design proposals, not implemented)
- `docs/CONTAINERS.md` (+ `.ru.md`): "everything in containers by default" —
  a container as one identity with exactly one network, interception of
  launches outside the launcher, the limits of what is possible without root,
  module options and a `--json` state schema for configuration tools.
- `docs/LAUNCHERS.md` (+ `.ru.md`): how launcher entries are generated and
  launched, the problems found (including handlers hidden with `NoDisplay` and
  foreign entries in the user directory that bypass the picker), and a
  proposal for retiring per-zone clones.
- `docs/CERTIFICATES.md` (+ `.ru.md`): extra root certificates trusted by the
  chosen containers only — never by the host or another container.
- `docs/LEAK-MODEL.md`: launches around the picker and trusted roots as
  channels, with the invariants the implementation must hold.

### Fixed (launches around the picker through hidden handlers; Steam games)
- **Links and files opened through a hidden handler started the program
  around the picker.** Entries with `NoDisplay=true` were skipped as a whole,
  and those are exactly the ones URL and file associations go through
  (`okularApplication_pdf`, `codium-url-handler`, …): the program started
  without its container, in the host's network. Such entries are now
  intercepted — kept hidden, never cloned — under the id of the visible entry
  of the same program. A hidden system helper with no program of its own in
  the menu is left alone.
- **Steam game entries are no longer treated as programs.** An entry whose
  command hands a URL to a program that another visible entry starts and
  claims the scheme of (`Exec=steam steam://rungameid/…` next to
  `steam.desktop`) is a child: no per-zone clones (the menu no longer grows as
  games × zones), and in picker mode it launches under the client's id, so the
  click is routed by the running client and the conflict check sees one
  program. Stale clones of such entries are swept by the next sync.

### Fixed (`direct` dropped the container, the sandbox and the compositor restriction)
- **Choosing "Прямой интернет" in the picker silently threw away every layer
  but the network.** The picker became the command itself for `direct`, so
  what `vpn-zone run` adds on the way never happened: the container or
  filesystem sandbox that had just been chosen, pinned or set as the default
  (`default-profile own` included) was not applied — the program got the whole
  `$HOME` — the Wayland restriction was not applied although it is on by
  default, and no record reached the launch registry, so "already running in
  another network" never knew about programs in the direct network. From
  inside a LOCKED zone the picker's own `systemd-run` also went straight past
  the lock. `direct` now goes through `vpn-zone run direct` like every other
  network; only the namespace step differs. A container there gets a user and
  mount namespace of its own from `unshare --map-current-user --keep-caps
  --mount` (no network namespace — direct is the host's network), so a data
  container works with `direct` for the first time instead of being ignored.
  Covered by unit tests of the new `entry_argv`, the picker scenarios and a
  smoke step that checks the layer, the host netns and the private userns.
- A program opened through delegation (a link clicked in a zone) carried
  `VPN_ZONE_DELEGATED=1` for the rest of its life, so the NEXT link clicked in
  it skipped the delegation and died in `nsenter` with "reassociate to
  namespaces failed". The guard is now removed from the environment once it has
  been checked.
- `vpn-zone add` refuses the names `direct` and `offline`: they are the
  picker's built-in choices, and a zone called `direct` could never be entered.
- **A program started into a zone opened in `/` instead of where it was
  started from** — a terminal showed `/` in its prompt. `nsenter` does
  `chdir("/")` when it joins a mount namespace. Every launch that enters a
  namespace now ends in `vpn-zone-core profile-run --cwd <dir>` (with an empty
  layer directory for the main profile), which changes into the caller's
  directory AFTER stacking the container's layers — `nsenter --wd` would have
  pinned the program to the directory under the overlay — and falls back to
  `$HOME` and `/` when that directory does not exist in the zone's mount tree.
  `profile-run` accepts the new optional leading `--cwd`; older command lines
  parse as before.
- **Two launcher entries for one single-instance binary did not see each
  other** in the "already running in another network" check: a Steam game's
  shortcut and Steam, firefox and its private-window entry, two Telegram
  variants. The registry key is the launcher id, so the second launch handed
  its work to the process already up — in that process's network — without a
  word. Every record is now also filed under the binary name
  (`.running/<container>/.by-binary/<binary>`, swept by `gc`), and the warning
  checks both. Routing a click on a running program still goes by the id only.
  When what is handed over is a link (`steam://…`, `https://…`) the warning
  says so, instead of promising that "the window will open".

### Added (a second kind of zone: OpenConnect)
- **A zone can now be carried by the `openconnect` client instead of a kernel
  tunnel** — Cisco AnyConnect and ocserv by default, and through `Protocol =`
  also GlobalProtect, Pulse, F5, Fortinet and Array (ROADMAP M4). A config with
  an `[OpenConnect]` section makes such a zone; everything else about a zone is
  unchanged, which is the whole point: the corporate VPN lives inside it, an RDP
  client runs in it, and the host never sees the tunnel
  (`rust/src/openconnect.rs`, `rust/src/zone.rs`).
- **The wall stands where it stood.** The client runs in the uplink namespace,
  creates its tun there through `/dev/net/tun` and runs `vpn-zone-core
  oc-script` as its `--script`; the script moves that tun into the app
  namespace and writes down what the gateway said, and the app namespace
  configures it with the same code a WireGuard zone uses. The TLS session, the
  gateway's address and every packet still wrapped in it stay one namespace up.
  A tun device and the descriptor attached to it are separate things, so the
  client goes on working after the interface has left its namespace — the same
  property WireGuard's UDP socket has, reached from the other side.
- No root and no kernel module: `TUNSETIFF` asks for `CAP_NET_ADMIN` in the
  user namespace that OWNS the network namespace, and inside the zone's own
  user namespace we are uid 0. All the device node needs to be is `crw-rw-rw-`.
- **What such a zone deliberately does not do**, all of it for one reason — a
  zone routes everything into the tunnel and has no second interface to route
  anything else through: split tunnelling (`CISCO_SPLIT_INC_*` is ignored and
  counted in the journal), split DNS, IPv6 (not even requested:
  `--disable-ipv6`), and interactive 2FA/OTP (a zone has no terminal to ask on,
  so the client runs `--non-inter`). Each is written down in
  `docs/LEAK-MODEL.md` with the reasoning rather than left to be discovered.
- **There is no way to spell "trust anything".** `ServerCert =` is a fingerprint
  pin (`pin-sha256:`/`sha256:`/`sha1:`, checked for being one) and without it
  the system CA store decides — that is the whole set of options. `Args =` is
  an allowlist of flags in `--flag=value` shape only, and it contains neither
  `--no-system-trust` nor `--allow-insecure-crypto`; nor `--script`,
  `--csd-wrapper` or `--external-browser`, which would replace the thing that
  puts the tunnel behind the wall or run a program of the server's choosing.
- Two more things a config cannot spell. `ServerCert` takes `pin-sha256:` or
  `sha256:` but **not** `sha1:`, which `openconnect` itself accepts: a pin is the
  whole trust decision for a zone that has one, and SHA-1 has not been
  collision-resistant for years. And the client is started with an environment
  built from scratch rather than inherited — `openconnect` honours
  `https_proxy` and its relatives, and a zone should not be one stray session
  variable away from talking to a proxy instead of its gateway. Four variables
  survive, each for a written reason: `PATH`, `HOME` and
  `SSL_CERT_FILE`/`NIX_SSL_CERT_FILE`, which is where the system CA store is.
- `PasswordFile =` must be absolute, non-empty and readable by nobody else
  (0600, checked at `vpn-zone add` and again at start). It is read once, in the
  uplink, and handed to the client on stdin — never on a command line
  (`/proc/<pid>/cmdline` is world readable) and never in the environment.
- Fail-closed, point by point: the gateway is resolved in the host's network
  before any namespace exists and handed over with `--resolve`, so nothing looks
  a name up from a namespace that has no resolver; the uplink's nftables rule is
  `ip daddr <gateway> accept` and nothing else; the client is spawned with
  `PR_SET_PDEATHSIG` so it cannot outlive the namespace it holds; the uplink
  waits on the client instead of parking, so the client's exit takes the whole
  zone down; and `disconnect` tears nothing down because the device dies with
  the client's descriptor and takes the app namespace's only route with it.
- The CI smoke test now runs a real ocserv on the runner with a certificate and
  a password generated on the fly, puts an OpenConnect zone in front of it and
  asserts the same invariants as for a WireGuard zone — exactly two links in the
  app namespace, both routes into the tunnel, the gateway's resolvers and search
  domain, no tunnel left in the uplink — plus a TCP connection through the
  tunnel and "kill the client, the zone is gone".

### Fixed (DNS leak: the host's resolvers were reachable from inside a zone)
- **Every name looked up inside a zone could be resolved by the HOST's
  systemd-resolved, around the tunnel.** nss-resolve talks varlink over
  `/run/systemd/resolve/io.systemd.Resolve`, a unix socket that no route and
  no packet filter can stop, and NixOS puts `resolve` ahead of `dns` in
  `nsswitch.conf` — so with resolved enabled this was the path of every
  lookup, while the traffic itself correctly went through the tunnel. Measured
  on a live zone: a browser leak test named the user's real ISP as the
  resolver while `curl ifconfig.me` in the same zone showed the VPN's address.
  The zone now hides every directory holding a host resolver's socket behind
  an empty tmpfs of its own — nscd/nsncd (as before), systemd-resolved and
  avahi (nss-mdns) — and a failure to do so takes the zone down instead of
  bringing it up leaking (`rust/src/zone.rs`, `hide_host_resolvers`).
- The hiding now happens **before** the offline branch: an offline zone used
  to keep the host's resolver sockets, which is a way out of a zone whose
  entire point is that there is none — a name is a channel, and data can be
  spelled into one.
- The zone's `resolv.conf` bind mount follows the symlink chain by hand and
  creates the file it lands on when it is missing. On NixOS the target is
  `/run/systemd/resolve/stub-resolv.conf`, i.e. inside the tmpfs that has just
  hidden resolved: without this the mount would fail with a bare ENOENT and
  take the zone with it (`sys::link_target`).
- The filesystem sandbox passes in the resolv.conf **file** and no longer its
  directory: `--ro-bind-try /run/systemd/resolve` handed every sandboxed
  program the host resolver's socket. Names still resolve inside; the socket
  does not come with them (`rust/src/fs_sandbox.rs`).
- Regression coverage in the VM test: the machine now runs systemd-resolved
  with a resolver of its own answering `leaktest.internal` with an address the
  tunnel's resolver never returns, so one `getent` inside the zone says whose
  resolver answered. Asserted for a live tunnel and for an offline zone, plus
  "the host's own resolution is untouched".

### Added
- A NixOS VM test (`tests/vm.nix`): a qemu machine with a real systemd user
  session and the home-manager module, plus a second VM acting as a live
  WireGuard peer. Covers what the CI smoke cannot — `vpn-zone up/down` through
  the `vpn-zone@` unit, the unit autostart inside `vpn-zone run`, the picker's
  offline branch, a real handshake/`vpn-zone check`, DNS through the tunnel,
  and a tcpdump leak watch on the uplink. Pins are shared with the harness via
  `tests/pins.nix`.
- AmneziaWG coverage in the VM test: both VMs now load the out-of-tree
  `amneziawg` kernel module, so the zone holder takes its ordinary `ip link
  add … type amneziawg` branch instead of the wireguard fallback (which stays
  covered by the CI smoke, whose runner has no such module). Asserted on a
  plain config against a stock WireGuard peer (wire compatibility), and on a
  new zone with real obfuscation — Jc/Jmin/Jmax, S1/S2, H1–H4 — against a
  second server interface carrying the same parameters: handshake seen by
  `vpn-zone check`, TCP through the tunnel, and an empty leak capture.

### Added (shell completion)
- Tab completion for zsh and bash, installed by the module. Context-aware:
  zone names where a zone is expected, profile/sandbox names after
  `--profile`/`--sandbox`, subcommands, pinned programs for `forget`, file
  completion where a path belongs. The rules live in the crate as the hidden
  `vpn-zone _complete` verb (a pure, tested function); the shell scripts only
  ask and insert.

### Changed (dialogs name the program)
- The file-access dialog of the sandbox and the "already running in another
  network" warning now name the program with the human-readable label the
  picker remembered (`.labels/<key>`), falling back to the raw id — and the
  access dialog says the name in the question body, not only the window
  title: with two programs starting at once, two anonymous dialogs are how
  permissions get granted to the wrong one. New `--label` flag on
  `vpn-zone-core fs-sandbox`; old invocations without it behave as before.

### Fixed (zone readiness)
- `vpn-zone up` right after a `down` could report «поднята» before the tunnel
  existed, and the unit autostart inside `vpn-zone run` (and the picker) could
  fail instantly with «зона не поднимается»: readiness was judged by the bare
  `ready` file, which survives a stop until the NEXT holder start cleans it
  up. Readiness now requires the marker AND a live zone process. Found by the
  VM test on its first pass over the systemd path.

### Fixed (launch-flow audit of the picker and `run`)
- Pinned sandboxes ("… — always" with a named or per-app sandbox) were erased
  by pin validation on the very next launch.
- Choosing a throwaway container via "Change container…" was silently lost on
  the re-exec: the program opened in the previous persistent container.
- After "Ask for the network again", a separately pinned container was ignored
  for that launch.
- A locked (no-escape) zone dropped `--profile` but not the sandbox flags, so
  opening a link from inside such a zone failed silently.
- Launching through the picker with no graphical session silently did nothing;
  it now falls back to the remembered/default choice with a note on stderr.
- The conflict warning named the wrapper (`wl-sandbox`) instead of the program,
  shared one "don't ask again" key across all sandboxed apps, and the
  delegated launch from inside a zone lost `VPN_ZONE_APPID` (separate
  permission sets and registry entries for the same app).
- A failed `systemctl --user start` or a failed profile/sandbox creation
  killed the whole launch under `set -e` after all dialogs had been answered;
  both now degrade with a message instead.
- Cosmetics: "Change container (now: …)" showed the last choice instead of the
  pinned one; the reset dialog's notification showed the entry key instead of
  the program's name.

### Changed
- **The picker and the GUI are Rust now — THE END OF BASH.** The last two
  pieces of shell logic in the project are gone: the four-hundred-line
  `vpn-zone-pick` and the six `writeShellScriptBin` wrappers behind the launcher
  entries. What replaces them is two more binaries in the crate,
  `vpn-zone-pick` (`rust/src/picker.rs`) and `vpn-zone-gui`
  (`rust/src/gui.rs`), plus the `kdialog`/`notify-send` shapes they share
  (`rust/src/dialog.rs`). Parity is the point, again: the same three levels of
  memory in the same files under `~/.local/state/vpn-zones`, the same menu
  entries in the same order with the same Russian texts, the same
  `VPN_ZONE_ASK` / `VPN_ZONE_PROFILE` hand-over across the re-exec of "⚙
  Сменить контейнер", the same `.desktop` argument shapes (`--id`, `--label`,
  and the legacy leading label), and the same `vpn-zone run` command line at the
  end of it. `module/default.nix` went from 1279 lines to 520 and holds no logic
  at all any more — three two-line wrappers that point `VPN_ZONE_TOOLS` at the
  manifest and `exec` a binary.
  What changed underneath:
  - **the decision is a pure function now.** "Which network, which container"
    is computed from a snapshot of the memory (`Memory` → `net_step`,
    `container_without_dialog`, `Container::from_selector`), so every branch of
    the machine — including all ten fixed in the launch-flow audit above — is a
    test case instead of a click. The menus are pure functions too, asserted
    entry by entry, because their ORDER is what a person navigates by;
  - **end-to-end scenarios run in CI.** `rust/tests/picker_cli.rs` drives the
    real binary against a fake manifest, a `kdialog` that answers from a queue
    and a `vpn-zone` that records its arguments: a fresh program, a pinned
    network, "change container" through the re-exec, unpinning, a cancel, no
    graphical session, and a program that is already running. The invariant
    asserted every time is the one the audit was about — each scenario ends
    either in a recorded `exec` or in an explicit cancel, never in silence.
    `rust/tests/vpn_zone_gui_cli.rs` does the same for the six shortcuts;
  - **the six shortcuts are one binary with six verbs**, and their `.desktop`
    entries call it directly: `Exec=env VPN_ZONE_TOOLS=… …/vpn-zone-gui add`.
    Those entries are written by home-manager and rewritten on every switch, so
    a store path in them cannot go stale — unlike the entries our own `sync`
    generates, which keep the profile paths of `vpn-zone` and `vpn-zone-pick`
    for exactly that reason;
  - **`notify-send` joined the manifest** (`notify-send` key) — it is the one
    tool only the GUI runs.

  Three deliberate behaviour differences, all small:
  - the "занят сетью …" note in the container menu now actually appears. It was
    read out of a container's `inuse` file, which nothing has written for a long
    time; the launch registry — the same source `vpn-zone profile list` uses —
    answers it as well now, and the `inuse` file is still read first;
  - `vpn-zone-gui add` calls the CLI through the profile path like every other
    dialog, where the shell version of that one wrapper used the store path;
  - a memory file that cannot be written (a full disk, a permission) is a line
    on stderr instead of the end of the launch. Under `set -e` the shell died
    there, silently, after every dialog had been answered.
- **The `vpn-zone` command line is Rust now.** The seven-hundred-line
  `writeShellScriptBin vpn-zone` of `module/default.nix` is gone; the crate
  grew a third binary of the same name (`rust/src/cli.rs` for the verbs,
  `rust/src/launch.rs` for `run`, `rust/src/registry.rs` for the launch
  registry). Parity is the point: the same verbs and flags, the same Russian
  messages word for word, the same exit codes (`check` still answers 0 alive /
  1 no handshake / 2 zone down / 3 state unknown, and it is meant to be
  scripted against), the same files under `~/.local/state/vpn-zones`, and the
  same registry format `pid zone selector` written under the same `flock` on
  the same `.lock` file — so the picker and the GUI wrappers, which are still
  shell, keep working through the same profile path without a change.
  What changed underneath:
  - **tool paths arrive in a manifest instead of being interpolated.** String
    interpolation by Nix is the one thing a compiled binary cannot do, and
    absolute paths are mandatory (part of what is started runs inside a
    namespace where `PATH` can be anything). Nix now writes them into a small
    flat JSON in the store and a two-line `writeShellScriptBin` wrapper points
    `VPN_ZONE_TOOLS` at it and execs the binary. The parser is written out by
    hand — the format is ours and flat, and it is read on the startup path of
    every program launched into a zone — and a missing key is a loud error
    naming it, never a silent default;
  - **the CLI no longer depends on `PATH` at all.** The wrapper carries no
    `PATH` of its own, and `du`, `mktemp`, `pgrep`, `flock`, `sed`, `grep`,
    `awk` and `basename` are gone from the runtime: sizes, temporary
    directories, the process scan, the locking and the parsing are code now,
    with unit tests for the parts that used to be one-liners (the `run`
    argument grammar, the app-id extraction with all its traps, the registry
    rewrite and gc criteria, the manifest parser, the `check` handshake
    scan);
  - **packaging:** the crate's `bin/vpn-zone` would collide with the wrapper of
    the same name in `home.packages`, so the crate no longer goes into the
    profile whole — a small symlink farm (`vpn-zone-helpers`) puts
    `vpn-zone-core` and `vpn-zone-seccomp` there, and the CLI comes through the
    wrapper.

  Four deliberate behaviour differences, all small:
  - `vpn-zone add` validates the config with the crate's parser instead of
    grepping for `[Interface]`. A file that cannot be parsed (or is not UTF-8)
    is refused right there, with the reason, instead of producing a zone that
    fails to start later. Everything that parsed before still parses;
  - `vpn-zone status` exits 0 for a zone whose `status` mirror does not exist
    yet. The shell version exited 1 there by accident — a trailing
    `[ -f … ] && { … }` was the last command of the branch;
  - directory sizes in `profile list` and `sandbox list` come from our own
    tree walk rather than `du -sh`. Same accounting (512-byte blocks, hard
    links counted once, symlinks not followed) and the same round-up
    formatting, but the last digit may differ from `du` in odd cases;
  - a missing or broken manifest is a new failure mode of its own: exit code 2
    with a message naming the file. `vpn-zone --help` deliberately works
    without one.
- The filesystem sandbox is Rust now. The two-hundred-line `vpn-fs-sandbox`
  shell script of `module/default.nix` is gone; `vpn-zone run --fs-sandbox` (and
  `--sandbox <name>`) calls `vpn-zone-core fs-sandbox` instead, with the tool
  paths substituted by Nix (`--bwrap/--dbus-proxy/--kdialog/--xwayland`) exactly
  as the zone holder takes `--ip/--pasta`. Behaviour is deliberately unchanged:
  the same permission files in `~/.config/vpn-zones/fs-perms/<app-id>` (old
  space-separated ones included) and the same shared `perms` of a named sandbox,
  the same `kdialog` checklist with the same wording, the same bwrap operations
  in the same order, the same `/.flatpak-info`, the same filtered session bus,
  the same GPU nodes, the same `mimeapps.list` read-only bind, the same
  `xwayland-satellite` on a random `:100`–`:499`, and the same exit code
  (128 + N for a signalled program). What changed underneath: the bwrap argument
  list is now a pure function with unit tests asserting the ORDER of the
  operations (a tmpfs listed after the bind it should hide would silently undo
  it, and nothing about a launched program shows that); the permission files are
  parsed and written by tested code; and the sandbox's own X server is started
  by an internal `vpn-zone-core fs-sandbox-x11` subcommand instead of an inline
  `bash -c`, so there is no shell inside the sandbox any more. One cosmetic
  difference: an empty permission set is written as an empty file rather than a
  lone newline, which is what `vpn-zone perms list` renders as "nothing".
- A zone is now **two** network namespaces instead of one, the gateway layout of
  `docs/LEAK-MODEL.md`. Connectivity lives in the uplink namespace — pasta
  attaches there, and the tunnel's UDP socket stays there — while programs run in
  an app namespace that has loopback and the tunnel and nothing else. The
  interface is created in the uplink (a WireGuard socket stays in the namespace
  the interface was *born* in, whatever namespace it is later moved to), handed
  down with `ip link set awg0 netns <pid>` and configured there, because netlink
  works on the current namespace. The contract towards the outside is unchanged:
  `zone.pid` still names the app namespace, which is what `vpn-zone run`/`status`
  `nsenter` into, and `ready`, `status`, `resolv.conf`, `config.conf` and the
  offline marker keep their meaning. New file in the zone directory:
  `uplink.pid`. `vpn-zone gc` needs no change — it recognises a stray pasta by
  the `/proc/<pid>/ns/net` in its command line, and that pid is now the uplink's.
  An offline zone is unaffected: still one namespace with loopback and no pasta.
- Endpoints are resolved before either namespace exists, and the text handed to
  `setconf` carries literal addresses. `wg setconf` resolves `Endpoint` itself
  and retries DNS for about ninety seconds before failing — in a namespace that
  has no network until the tunnel it is configuring is up, a hostname would hang
  the zone and then fail anyway. A name that cannot be resolved is now a loud
  error instead of a zone that comes up without a route. `WgConfig` grew
  `resolve_endpoints` for this (v6 gets brackets only when a port follows), with
  unit tests; the rest of the parser API is untouched.
- The life cycle of a zone is Rust now. The two shell scripts of
  `module/default.nix` — `zoneHolder` (the user namespace with its double id
  mapping, and pasta) and `zoneInit` (tunnel, routes, IPv6, DNS, the state
  mirror) — are gone; the unit starts `vpn-zone-core zone-holder <name>`
  instead, with the tool paths substituted by Nix
  (`--ip/--awg/--wg/--pasta`). Parity is deliberate and the architecture is
  unchanged: the same one-namespace model, the same pasta arguments, the same
  files in the zone directory (`zone.pid`, `ready`, `status`, `resolv.conf`),
  the same `KillMode=control-group` kill switch. What changed underneath is
  that the config is now read by the tested parser of `rust/src/config.rs`
  instead of a `sed`/`grep` pipeline, that `ip`/`awg`/`wg`/`pasta` are exec'd
  directly instead of being interpolated into a shell, that the id mapping is
  done with an explicit fork plus `newuidmap`/`newgidmap` instead of
  `unshare(1)`, and that the holder passes TERM/INT on to the zone so a zone
  cannot outlive its holder even without systemd. Two small deliberate
  differences: an empty `wg show latest-handshakes` is now reported as "no
  handshake" (the old `awk` pipeline reported success on empty input), and the
  stripped config handed to `setconf` is written with mode 0600 because it
  carries the private key. The bash `vpn-zone` CLI, the picker and the GUI
  wrappers are untouched.
- C is gone: `wl-sandbox` is now a subcommand of `vpn-zone-core`
  (`vpn-zone-core wl-sandbox <app-id> -- cmd...`) instead of a C program built
  from `module/wl-sandbox.c` with `wayland-scanner`. The behaviour it
  implements is unchanged — a socket of its own registered with the compositor
  through `wp_security_context_v1`, the close-fd switch held open for the
  lifetime of the program, `WAYLAND_SOCKET` unset so the inherited descriptor
  cannot override `WAYLAND_DISPLAY`, and a loud fallback to an unrestricted
  launch whenever any of that fails. Two deliberate differences: the command
  must now be separated by `--` (the C version took it without a separator,
  and `vpn-zone run` was updated accordingly), and a program killed by a
  signal is reported as `128 + signal` instead of a flat `1`, matching
  `profile-run`. No libwayland is linked in: the wire protocol is spoken from
  Rust, so the derivation needs no Wayland `buildInputs`.
- Python is gone: both helper scripts are now subcommands of the Rust
  `vpn-zone-core` binary — `profile-run` (the overlayfs layers of a data
  container, the ambient-capability drop and the life cycle of a throwaway
  one) and `sync` (the `.desktop` generator). Behaviour is unchanged, every
  quirk of `docs/GOTCHAS.md` §5 and §10 is now covered by unit tests, and the
  bash side keeps calling them with the same arguments. The project no longer
  depends on `python3` at all.

### Security
- **A second echelon: nftables in both namespaces of a zone** (ROADMAP M3,
  `docs/LEAK-MODEL.md`). The topology stays the load-bearing wall — a leak is
  impossible because the path does not exist — and the filter is what insures it
  against a mistake of ours:
  - in the app namespace, an `output` chain with `policy drop` and two accepts,
    `oifname "lo"` and `oifname "awg0"`. Today it has nothing to stop; the day a
    change puts a third interface there, the packets stop instead of leaving
    through it quietly. `oifname` and not `oif` on purpose: names are matched at
    run time, so the ruleset goes in before the tunnel has even arrived and
    keeps meaning what it says afterwards;
  - in the uplink, the same `policy drop` with loopback and *one rule per
    endpoint*: `ip daddr <server> udp dport <port> accept` (`ip6 daddr` for a v6
    endpoint). The uplink exists to carry the tunnel and nothing else, so that
    is all it may send — no DNS, no ICMP, no "quick check against the network".
    The addresses are the literals the holder resolved in the host's network
    before either namespace existed, so there is nothing to look up here. A v6
    endpoint additionally accepts ICMPv6 neighbour discovery, without which the
    kernel could not resolve pasta's `fe80::1` and the tunnel would never send
    its first packet; IPv4 needs no counterpart, because ARP is not in the
    `inet` family at all;
  - an offline zone gets no rules and needs none — loopback is the only
    interface it will ever have.
  Nothing about this is load-bearing, and it says so out loud: no `nft`, an old
  kernel or a kernel whose `nf_tables` module is not loaded (it cannot be
  autoloaded from inside an unprivileged user namespace) is a loud
  `second echelon is OFF` in the journal and a zone that comes up anyway. The
  path to `nft` arrives by flag, like `ip`/`awg`/`wg`/`pasta`
  (`--nft`, substituted into the unit's `ExecStart`), and the ruleset is
  generated by a pure function with unit tests. Programs inside a zone cannot
  read the rules, let alone flush them: nfnetlink wants CAP_NET_ADMIN even to
  list, and they enter under the ordinary uid with no capabilities at all.
- The seccomp filter of the filesystem sandbox is built **in process** instead
  of by a subprocess. The sandbox used to run `vpn-zone-seccomp export`, redirect
  its stdout into a file and open that file as descriptor 34 from the shell;
  now `crate::seccomp` is called as a library and the compiled program is handed
  to bwrap on an inherited descriptor (`dup2` in `pre_exec`, which clears
  `FD_CLOEXEC` as a side effect). One fork and one temporary file are gone from
  the startup path of every sandboxed program, and so is the window in which a
  half-written file could have been handed to `--seccomp`. The filter itself is
  unchanged, and a filter that cannot be built is still a warning on stderr and
  a sandbox without it.
- The bus proxy is now killed when the sandbox is **signalled**, not only when
  the program exits normally. In the shell version the `trap` lived in a
  subshell that a TERM could take out on its own, leaving `xdg-dbus-proxy`
  running with nobody to collect it. bwrap's `--die-with-parent` never covered
  it: the proxy is our process, not bwrap's.
- A leak out of a zone is now impossible by construction rather than forbidden
  by a rule. The namespace programs run in has exactly two interfaces, loopback
  and the tunnel, so:
  - the host's LAN is not reachable from a zone at all — there is no interface
    to reach it through, and no rule to get wrong;
  - any protocol family is fail-closed for the same reason, including families
    nobody has invented yet. The IPv6 patch of M0 is gone with the hole it
    plugged: the family is no longer switched off through a sysctl, v6 either
    goes into the tunnel or is left without a default route;
  - the /32 (or /128) route to the VPN server has disappeared from the zone
    together with the interface it pointed through. The encrypted packets are
    born in the uplink namespace and leave by *its* default route, so the
    programs never see the endpoint, and the smoke test now asserts the opposite
    of what it used to: inside the zone, the route to the endpoint must go
    through the tunnel;
  - the kill switch is topology now. Programs keep the app namespace alive after
    the holder is gone, but nothing keeps the *uplink* namespace alive; the
    kernel destroys it, and WireGuard reacts to its creating namespace going
    away by turning the carrier off and closing the sockets. The interface stays
    and drops every packet.
  Unchanged, and worth repeating: this closes the network. Unix sockets of the
  compositor, the bus and X11 are not affected by topology and stay the business
  of the wl-sandbox / fs-sandbox / dbus-proxy layers, and the nsncd leak is still
  closed by hiding its socket under a tmpfs — a socket has no route to remove.
- IPv6 no longer bypasses the tunnel. Previously only the IPv4 default route
  went into the tunnel while pasta still provided the zone with full IPv6
  connectivity to the host — all IPv6 traffic of zone apps went around the
  VPN whenever the host had IPv6. Now: if the config has an IPv6 `Address`,
  the v6 default route goes through the tunnel too; if the endpoint itself is
  IPv6-only, the v6 default is replaced with `unreachable` (only the /128 to
  the server stays); otherwise IPv6 is disabled inside the zone entirely
  (per-netns sysctl, the host is untouched). Fail-closed in every branch.
- Configs without `DNS=` no longer silently keep the host resolv.conf, whose
  local resolver is unreachable through the tunnel (names just stopped
  resolving). The zone now gets public resolvers (1.1.1.1, 9.9.9.9) reached
  via the tunnel, with a note in the zone log.

### Removed
- The last `writeShellScriptBin`s that held any logic: `vpn-zone-pick` and the
  six GUI wrappers (`vpn-zone-add-gui`, `vpn-zone-remove-gui`,
  `vpn-zone-profile-add-gui`, `vpn-zone-profile-rm-gui`,
  `vpn-zone-settings-gui`, `vpn-zone-forget-gui`). What is left in
  `module/default.nix` is three wrappers of two lines each — `vpn-zone`,
  `vpn-zone-pick` (both of which must own their name in the profile, because
  the generated shortcuts point at those paths) and `vpn-zone-sync` — plus the
  packaging. With them went the last runtime uses of `grep`, `sed`, `basename`,
  `cat`, `ls`, `du` and `sleep`: the module no longer references coreutils,
  gnused or gnugrep for anything but the `env` in a `.desktop` line.

### Added
- Seccomp filter in the filesystem sandbox. It now compiles a BPF
  program with libseccomp and hands it to `bwrap --seccomp`: terminal injection
  (`ioctl` `TIOCSTI`/`TIOCLINUX`), `ptrace`, the keyring calls, `syslog`,
  `perf_event_open`, `acct`, `quotactl`, `uselib`, the NUMA calls and any
  `personality` other than `PER_LINUX` are refused with `EPERM`, while the new
  mount API and `clone3` answer `ENOSYS` so that libc takes its older path.
  Nested user namespaces are deliberately *not* blocked: without zypak or a
  setuid `chrome-sandbox`, Chromium and Electron applications build their own
  and refuse to start otherwise (`vpn-zone-seccomp export --deny-userns` for
  programs that do not need theirs). If the filter cannot be built the sandbox
  starts without it and says so on stderr.
- A Rust crate in `rust/` — the first piece of the Rust core (ROADMAP M1/M2):
  the filter generator `vpn-zone-seccomp` (`export`, `selftest`) and a
  WireGuard/AmneziaWG config parser with unit tests for every quirk in
  `docs/GOTCHAS.md` §4 (CRLF, empty `I1`–`I5`, the three endpoint shapes,
  address families, `setconf` stripping) — the parser the zones now run on
  (see the zone life cycle above).
- Fallback to the in-tree `wireguard` kernel module and `wg(8)` when
  `amneziawg` is unavailable and the config has no obfuscation parameters
  (Jc/Jmin/Jmax/S1/S2/H1–H4/I1–I5). Configs *with* obfuscation fail loudly
  instead of silently degrading.
- IPv6 endpoints: `[addr]:port` literals and v6-only hostnames now work — the
  route to the server is added via the host's v6 default route. Previously the
  bracket form was mis-parsed on the last colon and hostname resolution was
  IPv4-only.
- All `Address` entries are now applied, both families — previously only the
  first one; a v6-only `Address` used to kill the zone on `ip -4 addr add`.

### Fixed
- A D-Bus proxy that did not come up took the whole program down with it. The
  filesystem sandbox bound the proxy socket unconditionally, so when
  `xdg-dbus-proxy` failed to start or exited before creating it — no session bus
  at all, a tty login, a CI runner — bwrap failed with "Can't find source path"
  and nothing started. The intent was always soft degradation: no bus is a
  degradation, no program is a bug. The bind is now skipped and the missing bus
  reported on stderr, while `DBUS_SESSION_BUS_ADDRESS` keeps pointing inside the
  runtime tmpfs, where there is nothing — the program must not find the *real*
  bus in any outcome. The five-second wait for the socket now also ends as soon
  as the proxy is seen to have exited, instead of being paid on every launch.
- `/run/current-system` is bound with `--ro-bind-try`. It exists only on NixOS,
  and a missing source is a hard bwrap failure, so the sandbox could not run on
  a machine that has a nix store but no NixOS system profile — which is what the
  CI runner is, and what a nix-on-Debian install is.
- The IPv6 fallback route was a syntax error and had never worked:
  `ip -6 route replace default unreachable` puts the route type after the
  prefix, which iproute2 rejects with "Command line is not complete" (exit 255).
  The type goes first — `replace unreachable default`. It went unnoticed because
  the `disable_ipv6` sysctl branch above it usually won; the sysctl is gone now
  and this is the branch that runs.
- Launch-registry updates are serialized with `flock`: two concurrent launches
  of the same app could lose each other's records (read → rewrite → rename
  without locking), and `gc` could erase a record of an app that had just
  started.
- Registry entries carrying a container/sandbox selector no longer confuse the
  "already running in another network" check, the profile list, and the
  pinned-list dialog: `read -r pid z` was gluing the selector onto the zone
  name, so "same zone + sandbox" looked like a different network.
- `gc` removes abandoned throwaway containers in `/tmp` by checking for live
  PIDs in the registry instead of the registry directory's existence — after a
  hard kill the directory stayed forever and so did the garbage.
- `vpn-zone-pick`: the `fsflag` array was used before initialization on the
  "join a running temporary container" path (it only worked thanks to
  bash ≥ 4.4 treating an empty `"${arr[@]}"` as non-fatal under `set -u`).
