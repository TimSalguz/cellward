# The system tier (M10): zones held by the system

Related: [ARCHITECTURE.md](ARCHITECTURE.md) §3, [LEAK-MODEL.md](LEAK-MODEL.md)

**Status: design of stages 1–3, 2026-09-23.** Stage 1 (system zones), stage 2 (services in
them) and stage 3 (NixOS containers in them) are written on the branch `feat/system-zones`
and have **not been built or run yet**: no `cargo`, no VM test. Everything below that names a
file or a function describes that branch.

## 1. What it is

A system zone is the same zone as a user one — a namespace with `lo` and a tunnel, the
tunnel created outside and moved in — held by systemd from boot instead of by a session.
Its uplink is the host's network, so there is no pasta and no user namespace: root creates
the interface in the host's namespace and moves it into `/run/netns/vz-<name>`.

What joins it: system services (`NetworkNamespacePath=`) and NixOS containers
(`containers.<name>.networkNamespace`). Programs of a user can't yet (stage 4, the broker).

Stages 1–3 carry WireGuard/AmneziaWG zones only. OpenConnect and host-interface configs are
refused with a message; they need the uplink to be a namespace of its own and come later.

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
  `BindsTo=` and `After=` the namespace unit, `After=network-online.target`. Sets the zone
  up (§4), then mirrors the status until stopped. `ExecStopPost` = `down`: the tunnel
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
9. `ready`; after 4 s the handshake is looked at and said in the journal; the status mirror
   runs until the unit stops.

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
- `bindsTo`/`after` the namespace unit, `wants`/`after` the holder.

The unit is still the person's; only its network changes.

## 6. NixOS containers in a system zone (stage 3)

`services.vpn-zones.system.containers.<container> = "<zone>";` sets on
`containers.<container>`:

- `networkNamespace = "/run/netns/vz-<zone>"` (exclusive with `privateNetwork` and
  `interfaces` — the nixpkgs module asserts it);
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
- `systemd.services."container@<container>"`: `bindsTo`/`after` the namespace unit,
  `wants`/`after` the holder.

## 7. State for tools

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

## 8. Leak channels of the system tier

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
7. **The host side has no second echelon** — a system zone's uplink is the host's network
   itself, and a ruleset there would be the host's firewall. Filtering the host's egress is
   stage 5, the backstop.

## 9. Tests

- **Rust:** the name check; the argument parser; the plan of `up` as data (which commands,
  in which order, for v4, v4+v6, obfuscated and plain configs); refusing OpenConnect and
  host-interface; the `system_networks` document with and without read access.
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
     the new namespace.
