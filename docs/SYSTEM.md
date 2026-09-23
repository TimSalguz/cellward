# The system tier (M10): zones held by the system

Related: [ARCHITECTURE.md](ARCHITECTURE.md) §3, [LEAK-MODEL.md](LEAK-MODEL.md)

**Status, 2026-09-23.** Stages 1–3 (system zones, services and NixOS containers in them) are
in `main`, with `tests/vm-system.nix` green locally and in CI. Stage 4 (a user's console
program in a system zone, §7) is in `main` too; stage 5 (the host egress policy, §9) is on
the branch `feat/host-egress`, green in the same VM test.

## 1. What it is

A system zone is the same zone as a user one — a namespace with `lo` and a tunnel, the
tunnel created outside and moved in — held by systemd from boot instead of by a session.
Its uplink is the host's network, so there is no pasta and no user namespace: root creates
the interface in the host's namespace and moves it into `/run/netns/vz-<name>`.

What joins it: system services (`NetworkNamespacePath=`) and NixOS containers
(`containers.<name>.networkNamespace`). Programs of a user can't yet (stage 4, the broker).

Stages 1–3 carry WireGuard/AmneziaWG zones only. OpenConnect and host-interface configs are
refused with a message; they need the uplink to be a namespace of its own and come later.

### 1a. Plain zones

`zones.<name>.kind = "plain"`: the same namespace, no tunnel. pasta attaches to it and
carries its connections out through the host's own network — not encrypted by the zone, but
still a namespace of its own: `lo` and pasta's interface (named `awg0`, so the second echelon
applies unchanged), its own resolv.conf (the public resolvers, as for a config without
`DNS =`), and nothing of the host's — pasta's port forwarding in both directions and its
mapping of the gateway to the host's loopback are shut (`PASTA_CLOSED`, the same as user
zones). pasta runs as the system user `vpn-zones-plain`, not as root and not as its default
`nobody`: the host's egress policy (§9) lets system users out and knows this one by name. It
keeps exactly two capabilities, CAP_SYS_ADMIN and CAP_NET_ADMIN, as ambient ones set by the
holder before exec — what it needs to enter a namespace the host's user namespace owns and
configure its interface. Not `--runas`: pasta changes its uid first, which clears every
capability, and then cannot enter the namespace (the VM test's "Couldn't switch to pasta
namespaces").

What it is for: the TTY console's second step when the VPN cannot come up (ARCHITECTURE §4),
and the way a program goes out directly once the host has no network of its own —
`vpn-zone-sys <plain zone> -- <command>`.

## 2. Names and files

- Zone name: `[a-z0-9][a-z0-9-]{0,11}`, not `unconfined`, `direct` or `offline`. Twelve,
  because the host-side interface is `vz-<name>` and interface names stop at 15.
- Namespace: `vz-<name>`, i.e. `/run/netns/vz-<name>`. The prefix keeps the namespaces
  apart from anybody else's `ip netns add`.
- Interface: created as `vz-<name>` in the host's namespace (so it can't collide with an
  `awg0` somebody else is creating there at the same moment), renamed to `awg0` once inside.
  Inside, a system zone looks exactly like a user zone's app namespace, and the same
  ruleset and the same smoke assertion apply unchanged.

| Path | Mode | What |
|---|---|---|
| `/var/lib/vpn-zones/system/<name>/config.conf` | 0600 root, dir 0700 | the config, unless `configFile` points elsewhere |
| `/run/vpn-zones/system/<name>/` | 0750 root:vpn-zones | the zone's run directory |
| `…/setconf.conf` | 0600 root | the stripped config `setconf` reads (private key inside) |
| `…/ready` | 0640 | the zone is up |
| `…/status` | 0640 root:vpn-zones | `awg show awg0`, every 5 s; no private key in it |
| `/etc/netns/vz-<name>/resolv.conf` | 0644 | the zone's resolvers; rewritten **in place** because consumers bind it |
| `/etc/vpn-zones/system-zones` | from the module | declared zone names, one per line, for `status --json` |

Members of the group `vpn-zones` can read the status; that is what makes
`vpn-zone status --json` report a system zone's tunnel without root.

## 3. Units

- `vpn-zone-system-ns-<name>.service` — `vpn-zone-core system-zone ns-up <name>`:
  the namespace, `lo` up, the app ruleset (second echelon) loaded before anything else, an
  empty resolv.conf. `Type=oneshot`, `RemainAfterExit`, **`restartIfChanged = false`**: the
  namespace must survive switches, because every consumer bound to it would otherwise be cut
  off or restarted by every update of this package. `ExecStop` = `ns-down`.
- `vpn-zone-system-<name>.service` — `vpn-zone-core system-zone up <name>`, the holder.
  `Type=notify`, `BindsTo=` and `After=` the namespace unit, `After=network-online.target`.
  Sets the zone up (§4), says `READY=1` — so whatever is ordered after it starts with the
  tunnel and the zone's resolv.conf in place — then mirrors the status until stopped. `ExecStopPost` = `down`: the tunnel
  interface is deleted, the namespace stays with `lo` alone. `Restart=on-failure` after
  10 s: at boot the endpoint may not resolve yet.

Consumers bind to the **namespace** unit and only order after the holder: a tunnel going
down leaves them running with no way out (fail-closed, and downloads resume later); the
namespace going away stops them, because a process in a deleted namespace is cut off for
good.

## 4. `up`, step by step

1. Read the config (`--config P`, else the state directory), drop `\r`, parse with the same
   `config.rs`. OpenConnect or host-interface → refuse. Empty keys dropped and named, as
   in a user zone.
2. Resolve every endpoint **here, in the host's network**, and write literal addresses into
   the stripped config (`setconf.conf`, 0600). Unresolvable → fail, and systemd retries.
3. Delete leftovers: `vz-<name>` in the host's namespace, `awg0` in the zone's.
4. `ip link add vz-<name> type amneziawg`, falling back to `wireguard` for a config without
   obfuscation (the same choice as a user zone's `create_tunnel`).
5. `ip link set vz-<name> netns vz-<name>`; inside: rename to `awg0`.
6. `ip netns exec vz-<name> awg setconf awg0 setconf.conf` — the UDP socket stays in the
   host's namespace, where the interface was created.
7. Addresses of both families, MTU, up; default route into `awg0`; IPv6 into the tunnel or
   an unreachable default (`v6_plan`, shared with user zones).
8. resolv.conf from `DNS =` (or the public resolvers through the tunnel, as a user zone
   does), written in place.
9. `ready` and `READY=1` to systemd; after 4 s the handshake is looked at and said in the
   journal; the status mirror runs until the unit stops.

## 5. Services in a system zone (stage 2)

`services.vpn-zones.system.services.<unit> = "<zone>";` sets on `systemd.services.<unit>`:

- `NetworkNamespacePath=/run/netns/vz-<zone>`;
- `BindReadOnlyPaths=/etc/netns/vz-<zone>/resolv.conf:/etc/resolv.conf` — without the `-`:
  no resolv.conf, and the unit fails instead of resolving through the host;
- `InaccessiblePaths=-/run/nscd -/run/systemd/resolve/io.systemd.Resolve` — both are unix
  sockets and cross namespaces: glibc asks nscd first, nss-resolve asks resolved over
  varlink, and either would resolve names through the host around the tunnel. The `-`
  because a host may run neither;
- with `systemBus = false` (the default): `InaccessiblePaths=-/run/dbus/system_bus_socket` —
  resolved's `org.freedesktop.resolve1` answers name lookups over the system bus too;
- `BindReadOnlyPaths=/etc/netns/vz-<zone>/nsswitch.conf:/etc/nsswitch.conf` — the host's
  file with `hosts: files dns`, written by `ns-up`: no NSS module but the plain resolver is
  ever asked for a name, which is the insurance a user zone has too (`zone_nsswitch`);
- `InaccessiblePaths=-/run/avahi-daemon` as well: nss-mdns would put a `.local` name onto the
  host's LAN;
- `bindsTo`/`after` the namespace unit, `wants`/`after` the holder.

The unit is still the person's; only its network changes.

## 6. NixOS containers in a system zone (stage 3)

`services.vpn-zones.system.containers.<container> = "<zone>";` sets on
`containers.<container>`:

- the network: **not** `containers.<container>.networkNamespace`. nspawn joins a network
  namespace from inside the container's new user namespace, and the zone's belongs to the
  host's — `Failed to join network namespace: Operation not permitted` under
  `privateUsers = "pick"` (found by `tests/vm-system.nix`). Instead systemd enters the zone
  before nspawn runs — `NetworkNamespacePath=/run/netns/vz-<zone>` on `container@<container>`
  — and nspawn, given no network flags, shares the network it was started in. An assertion
  keeps `privateNetwork`, `networkNamespace`, `interfaces`, `macvlans` and `extraVeths`
  unset;
- `privateUsers = mkDefault "pick"`: the container's root has no capability in the user
  namespace that owns the zone's network namespace (the host's), so it can't add a route or
  an interface. An assertion refuses `"no"` and `"identity"` for a container in a zone, and
  `enableTun` or `CAP_NET_ADMIN` in `additionalCapabilities`;
- `extraFlags`:
  - `--resolv-conf=off` and `--bind-ro=/etc/netns/vz-<zone>/resolv.conf:/etc/resolv.conf`:
    nixpkgs' start script copies the host's resolv.conf into every container root, and the
    zone's file goes over it. The container runs its own nscd in its own `/run`, so the
    host's sockets aren't there;
  - `--inaccessible=/nix/var/nix/daemon-socket`: nixpkgs binds the **host's** Nix daemon
    socket into every container (conditioned on the host's daemon, not the container's), and
    any user there can ask the daemon for a fixed-output derivation — a download from any
    URL, made by the host in the host's network. This is a channel of every NixOS container,
    not only ours;
- `systemd.services."container@<container>"`: `NetworkNamespacePath`, `bindsTo`/`after`
  the namespace unit, `wants`/`after` the holder.

## 7. A user's program in a system zone (stage 4)

`vpn-zone-sys <zone> [--] <command>`, for the users listed in
`services.vpn-zones.system.zones.<zone>.users`. Console programs only for now (the use the
TTY console of ARCHITECTURE §4 needs); graphical ones need the session sealing user zones
have.

A system zone's namespace belongs to the host's user namespace; entering it takes
`CAP_SYS_ADMIN` there, which no program of a user has. So a small service does the entering
(`rust/src/sysrun.rs`):

- **The socket** `/run/vpn-zones/sysrun.sock`, `SOCK_SEQPACKET`, `0660 root:vpn-zones`,
  `Accept=yes`: **one unit per launch** (`vpn-zone-sysrun@…`), so every launch is visible in
  `systemctl`, stops with its unit, and nothing it leaves behind outlives it. The group gets
  the zones' users (`users.groups.vpn-zones.members`); the per-zone list is checked by the
  service itself.
- **Who asks** comes from the kernel (`SO_PEERCRED`), never from the request. Root is
  refused (it has `ip netns exec`, and root in the zone's namespace could route around the
  tunnel).
- **What root does:** enters the zone's network namespace, makes a mount namespace of its
  own — the host's resolvers hidden (the same list as a user zone: nscd, resolved, avahi),
  the zone's resolv.conf and nsswitch.conf bound in, the system bus hidden unless
  `systemBus`, an empty `/run/user/<uid>` over the session's sockets — then drops to the
  user's groups, gid and uid and sets `NO_NEW_PRIVS`: `sudo` inside would be root in the
  zone's namespace.
- **What root does not do:** interpret the request. The command, its directory and its
  environment are applied after the privileges are gone, as the user; the zone's name is
  checked like any zone name before it becomes a path.
- **The terminal** is the client's: it makes a pty, sends only the slave, and relays. The
  command gets the slave as its controlling terminal, so Ctrl-C, job control and the window
  size work without a signal passing through root. Without a terminal, the client's 0, 1 and
  2 are passed. The client gone, the command gets SIGHUP and SIGTERM.
- The request is one datagram: `VZS1\0`, zone, mode, cwd, argc, argv…, envc, env…, each
  NUL-ended, at most 64 KiB; the answer is `EXIT <code>` or `ERR <why>`.

## 7a. The TTY console

`services.vpn-zones.system.console = { enable = true; zone = "nl"; fallback = "direct"; }` —
ARCHITECTURE §4: fell into a text console, logged in, and there is a network already, with
nothing to type and nothing to know.

```
  vpn-zones — консоль · alice
    сеть: nl — туннель жив (tunnel alive)
    [Enter] терминал с интернетом (zone nl)
    [n]     Настройки и откат                ← console.admin, if set
    [p]     напрямую, без VPN (zone direct)  ← only when nl has no live tunnel
    [k]     аварийный ключ …                 ← the egress policy's key (§9)
    [q]     обычная консоль, без сети
```

- **When it shows up.** The login shell runs `vpn-zone-core console --login` once per login
  (`environment.loginShellInit`), in interactive shells only — a display manager starts a
  session with `bash -l -c …`, often on a VT, and the console must not stand in front of the
  compositor. The program then decides: a virtual terminal (`/dev/ttyN`, not a pty, not a
  serial line), outside any zone, a user of the console's zone. Anybody else gets the
  ordinary login.
- **The network.** A zone that is down is started — the zone's users may start its holder
  (a polkit rule the module writes per zone) — and a tunnel is waited for up to 15 s. Alive
  means a handshake within WireGuard's session limit, or for a plain zone its interface up.
- **The keys.** Enter: a login shell in the zone through `vpn-zone-sys`, and back to the menu
  when it ends; `p`: the same in the plain `fallback` zone, offered when the zone has no live
  tunnel; `n`: the admin tool on the host; `k`: the emergency key; `q`: the ordinary shell of
  the host. The shell runs as a process of its own, not inside the console: the client's
  relay would leave a thread blocked on the terminal that would take the next key meant for
  the menu.
- **It never locks anybody out.** Every failure ends in the host's ordinary shell, which under
  the egress policy has no network but has everything to repair with — and the key.

## 8. State for tools

`vpn-zone status --json` gets a top-level `system_networks` array — additive, schema 1. A
separate array and not entries in `networks`: a tool that doesn't know the difference would
offer a system zone as a network for a program container, which can't use it.

```json
"system_networks": [
  {"name":"vpn1","netns":"/run/netns/vz-vpn1","kind":"wireguard","source":"nix",
   "up":true,"tunnel_alive":true,"handshake_age_s":12,"rx_bytes":1024,"tx_bytes":2048,
   "readable":true}
]
```

`readable: false` means the reader isn't in the group `vpn-zones`: the run directory is
closed to them, so `up`, `tunnel_alive` and the counters are `null`.

## 9. The host without a network of its own (stage 5)

`services.vpn-zones.system.egress = { enable = true; mode = "audit" | "enforce"; }` —
ARCHITECTURE §2, «страховка»: a user's program that runs outside every zone does not reach
the network, however it was started.

- **One table, one unit.** `inet vpnzones_egress`, an `output` chain at priority −160 (after
  conntrack, before a DPI bypass's mangle), loaded by `vpn-zones-egress.service` with
  `vpn-zone-core egress apply` in one transaction (`destroy table` + the new one). Rolling
  back a generation removes it with everything else.
- **By the socket's owner, not by cgroup.** Out: root and system users (uid < 1000),
  systemd's dynamic users (61184–65519), the first uid and gid of every `/etc/subuid` and
  `/etc/subgid` range (the uplinks of user zones: pasta runs as uid 0 of the zone's user
  namespace), `allowUsers`, `allowGroups` (`nixbld` by default), established and related
  traffic, loopback, the kernel's neighbour discovery and IGMP. A system zone's tunnel is
  let out by its mark: its UDP socket is the kernel's own, has no file and so no owner, and
  the holder writes `FwMark = 0x767a` into what `setconf` gets (`system::TUNNEL_MARK`,
  replacing any the config had) — found by the VM test, where the first handshake was
  refused. Everything in a zone never passes this hook. Anybody else: a rate-limited
  `vpn-zones-egress: … UID=<uid>` line in the kernel log, and in `enforce` `reject with
  icmpx admin-prohibited` — the program fails at once instead of hanging.
  Cgroup sets (`NFTSet=`) were the other design: systemd fills them when a unit starts, and
  every flushing firewall reload empties them — a policy that silently stops recognising
  what it allows.
- **`audit` first.** The same rules, logged and let through: a machine is watched before it
  is locked.
- **A firewall that flushes.** With `networking.nftables.flushRuleset` the NixOS firewall
  deletes every table on start and reload; the policy's unit is then `PartOf` it and
  reloads with it (`ReloadPropagatedFrom`). Without flushing it is left alone.
- **The emergency key.** `vpn-zones-egress-open.service` keeps the table and lifts the
  restriction for `emergency.minutes` (15), then puts it back — also when stopped earlier.
  `emergency.group` (`wheel`) may start and stop it without a password — through polkit,
  which the module therefore turns on (NixOS has it off by default; the VM test found the
  key refused without it). The TTY console of ARCHITECTURE §4 turns it with one key.
- **What it does not close.** Names: a blocked program still resolves them through the
  host's nscd or resolved, which are the system's and go out — the connection is refused,
  the question already left. Moving the host's own resolver into a system zone is the
  answer, and a later step. And root: root can unload anything; the policy is about
  programs of users.

## 10. Leak channels of the system tier

1. **Routes around the tunnel** — none: `lo` and `awg0` only; the second echelon is loaded
   into the namespace before the tunnel arrives.
2. **DNS** — the zone's resolv.conf bound over the consumer's; nscd, resolved's varlink
   socket and (by default) the system bus hidden from services; containers have their own
   `/run`.
3. **Degradation** — the holder stopping deletes `awg0`: `lo` alone. A holder killed
   without its `ExecStopPost` leaves a working tunnel — not a leak.
4. **The host's Nix daemon** — hidden from containers (§6). Services: a service running as
   a user may reach the daemon socket; hiding it is `InaccessiblePaths` too, offered but not
   forced (some services legitimately build).
5. **One zone is one network** — everything in a zone shares its `lo` and abstract unix
   sockets. Separation means separate zones.
6. **The endpoint** — resolved in the host's network, as for user zones (LEAK-MODEL §5).
7. **A user's program** (§7) gets the same hiding as a service plus the session's sockets:
   the bus and the compositor are how a program asks the host to open something, in the
   host's network.
8. **The host side has no second echelon** — a system zone's uplink is the host's network
   itself, and a ruleset there would be the host's firewall. Filtering the host's egress is
   stage 5 (§9); a zone's tunnel passes it by its mark.

## 11. Tests

- **Rust** (`system.rs`, `status.rs`): the name check; the paths; the argument parser;
  refusing OpenConnect, host-interface and configs without `[Interface]`; the declared list
  trusting no name; the `system_networks` entry for a closed, a down and an up zone. The
  command sequence of `up` itself is covered by the VM test only — it is `ip` calls, and a
  fake `ip` would test the fake.
- **VM `tests/vm-system.nix`:** `machine` with the NixOS module and a zone `sz` whose config
  is written at run time; `server` a WireGuard peer with HTTP and DNS on its tunnel address;
  `machine` also serves HTTP on its LAN address, which must never be reached from the zone:
  1. `ip -n vz-sz -o link` shows exactly `lo` and `awg0`; the ruleset is there;
  2. a service attached to `sz` fetches the tunnel's HTTP and resolves a name only the
     tunnel's DNS knows; it can't reach the LAN HTTP;
  3. the same service, with nscd and resolved running on the host, gets the tunnel's answer
     for a name the host's resolver answers differently;
  4. a NixOS container attached to `sz`: the same two checks, `ip link add` refused inside,
     the daemon socket inaccessible;
  5. stopping the holder: `ip -n vz-sz -o link` is `lo` alone, the service and the container
     keep running and reach nothing; starting it: the HTTP answers again;
  6. restarting the namespace unit restarts the service and the container, and they are in
     the new namespace (checked by a per-namespace sysctl: inode numbers are reused);
  7. `vpn-zone-sys` as a listed user: the tunnel's network and names, the user's uid,
     `NoNewPrivs: 1` and no capabilities, `lo` and `awg0` only, `ip link add` refused, the
     zone's nsswitch, the command's exit code, a pty with a terminal, the launch in the
     journal; a user of another zone and a user outside the group are refused;
  8. a plain zone: `lo` and `awg0`, pasta as `vpn-zones-plain`, the server sees the machine,
     the host's loopback unreachable by the gateway and by `127.0.0.1`, the public resolvers,
     `connected: yes` in the status, and alice out through it while the policy refuses her
     directly; stopping it leaves `lo` alone;
  9. the egress policy, enforced from boot under a firewall that flushes every table: root
     and a `DynamicUser` service reach the LAN, a user outside the zones is refused at once
     and named in the kernel log, the same user through her zone is not; `systemctl reload`
     and `restart nftables` leave the policy in place; the emergency key opens and closes
     the host for a member of `wheel` and is refused to anybody else. Everything before
     step 9 runs under the enforced policy too.
  10. the TTY console: alice logs in on tty1, the menu says the tunnel is alive, Enter gives
     a shell in `sz` that reaches the tunnel, `q` a host shell that does not reach the LAN;
     with the server's WireGuard down and the zone restarted, the menu says there is no
     tunnel and `p` gives a shell in the plain zone that reaches the LAN;
