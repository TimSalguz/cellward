# Target architecture: everything in containers by default

Russian: [ARCHITECTURE.ru.md](ARCHITECTURE.ru.md) · Related: [LEAK-MODEL.md](LEAK-MODEL.md),
[CONTAINERS.md](CONTAINERS.md), [SYSTEM.md](SYSTEM.md) (the system tier, M10)

**Status: the target picture, 2026-09-23.** This is where the project is going. Each part
below says whether it exists; anything not marked as done is a plan.

## 1. The goal and the one concession

Every program and every service gets exactly what it needs: its own files, one network,
the devices it was given. Everything else is closed by default; exceptions are explicit and
visible. Leaks are impossible by construction rather than forbidden by a rule
([LEAK-MODEL.md](LEAK-MODEL.md)).

The strongest isolation is a virtual machine per program (Qubes OS, Spectrum OS). That is
deliberately not the design: one GPU, games and audio latency don't survive a VM for
everything. The boundary is therefore **kernel namespaces**, and the kernel is shared. That
is the one concession. The shape is borrowed from Qubes anyway: the host is an empty
control room, work happens in compartments, and the network reaches compartments through
separate gateways.

## 2. Five concepts

```
┌──────────────────────────── HOST (the control room) ─────────────────────────────┐
│  kernel, systemd, compositor, nix-daemon, the cellward engine, a config tool     │
│  no network of its own: only zone uplinks and allow-listed services go out       │
│                                                                                  │
│  GATEKEEPER ← launcher, compositor binds, links, D-Bus, autostart, terminal,     │
│     │         a typed command, a launch from a script                            │
│     ▼         "who is this, where does it go?" → remembered / declared / asked   │
│  ┌─ program container ───┐ ┌─ terminal container ─┐ ┌─ service / NixOS system ─┐  │
│  │ bwrap: own home,      │ │ everything typed in  │ │ systemd sandbox or       │  │
│  │ folders, bus filter   │ │ it inherits it       │ │ nspawn                   │  │
│  └──────────┬────────────┘ └──────────┬───────────┘ └────────────┬─────────────┘  │
│             ▼                         ▼                          ▼                │
│  ═══ ZONES: exactly two paths in each — lo and the zone's one way out ═══        │
│   offline │ unconfined │ WireGuard/AmneziaWG │ OpenConnect │ host interface       │
│   user zones (held by the session)          system zones (held by systemd)        │
└──────────────────────────────────────────────────────────────────────────────────┘
```

1. **A zone — which network.** A namespace with `lo` and one way out. The tunnel is
   created in an uplink and moved in, so its socket and the server's address are never
   visible to programs. *Exists* for the user tier.
2. **A container — what a program sees.** A home, granted folders, devices, trusted
   certificates, a filtered bus, a Wayland socket of its own. One idea, three runtimes:
   - a desktop program — bwrap (*exists*, [CONTAINERS.md](CONTAINERS.md));
   - a single service — its own unit with systemd's sandboxing (*not yet*, M10);
   - a whole system with its own services and users — nspawn, NixOS `containers.<name>`
     (*not yet*, M10).
   Any container attaches to any zone of its tier, one at a time.
3. **The gatekeeper — who decides.** Every way of starting something ends in one place
   that knows which container and which zone a program gets. An unknown program is asked
   about once and remembered. **Inside a container everything inherits**: `ls | grep` in a
   terminal asks nothing because the terminal already is in a container. *Partly exists*
   (§5).
4. **Requests at run time.** As on Android: a file, the camera, the microphone — a system
   dialog carrying the program's name. Files *already* work this way (portals). The
   network can't by construction: a namespace is chosen at launch, and changing it is a
   restart.
5. **The backstop.** The host has no network by default: only zone uplinks and
   allow-listed services go out. Whatever slips past the gatekeeper still has no network.
   Plus the journal of who went where and when (*the journal exists*, the egress policy
   doesn't yet).

## 3. Two tiers, one zone

| | User tier | System tier |
|---|---|---|
| Module | home-manager (`homeModules.default`) | NixOS (`nixosModules.default`) |
| Privileges | none | root |
| Zone holder | the user's `vpn-zone@<name>`, lives with the session | the system's `vpn-zone-system-<name>`, lives from boot |
| Uplink | a namespace of its own behind pasta | the host's network |
| App namespace | owned by the zone's user namespace | `/run/netns/vz-<name>` |
| Config | `~/.local/state/vpn-zones/<name>/config.conf` | `/var/lib/vpn-zones/system/<name>/config.conf`, or a path to a secret |
| Who attaches | the user's programs | services, NixOS containers; programs through a broker (later) |

**Everything else is shared:** the config format and its parser (`config.rs`), resolving the
endpoint in the host's network before configuring, the tunnel created outside and moved in,
`lo` + `awg0` and nothing else inside, the same second-echelon ruleset, the same resolv.conf
from `DNS =`, the same smoke assertion ("exactly two links"), one `cellward status --json`.

**What can't be unified, and the person sees it:**
- A service can't live in a user zone: that zone dies with the session.
- A user's program can't enter a system zone without root: `setns` into a namespace owned
  by root needs privileges. A tiny broker is needed — enter the namespace, drop to the
  user, run the ordinary cellward launch with its sandbox. It is a new attack surface, so
  it is minimal, comes only with the system module, and admits only those it was told to.

The user tier doesn't depend on the system tier. Without the NixOS module everything stays
rootless, as it is today.

## 4. The host and the console (TTY)

The host is where administration happens: `nixos-rebuild`, the configuration tool, rollback.
Once the backstop of §2 is on, **the host's shell has no network, on a TTY as anywhere
else.** That is intended:

- administration keeps working: the shell doesn't download, nix-daemon does, and it is
  allow-listed. Rebuilds, rollbacks and garbage collection work from a TTY;
- a network on a TTY is had the way it is had everywhere: `cellward run <zone> -- bash`
  (the systemd user manager starts for a TTY login too, so user zones work there), or a
  system zone through the broker;
- an emergency key: "open the host for 15 minutes", a unit that reverts on its own;
- `strict` takes the host's own services off the network too: root keeps the LAN, and the
  Nix daemon and the clock go through a zone of their own (plain = directly, or a VPN);
- an off switch: `vpn-zones-off` turns everything off in place — no rebuild, which could
  need the very network the policy keeps away — until `vpn-zones-on`;
- it can't become a trap: the policy is a unit, and booting an older generation from the
  boot menu removes it with everything else.

## 5. Where the question is asked

| How something starts | How it is caught | State |
|---|---|---|
| Launcher, links (`xdg-open`), D-Bus activation, autostart | intercepted entries, shadow services | **done** (M8) |
| Compositor binds | `cellward launch <id>` instead of the program | **mechanism done**, the bind is the person's |
| A terminal | the terminal itself starts in a container with a network; what is typed inherits | **pieces exist** (`overlay` home), not put together |
| A program typed in a terminal | PATH shims; a shell hook before the line runs | **shims done** (`pathShims.enable`), no hook |
| A launch from a script, a file manager, another program | fanotify `FAN_OPEN_EXEC_PERM` as root: the exec waits for the daemon | **not yet**, last |

The kernel can **allow or deny an exec, not redirect it**. "Into a container" on the last
row therefore means: the original call fails and the program starts again in the container.
Fine for an interactive launch, not for a script.

## 6. Controlling execs is not isolation

- bash has a network of its own: `exec 3<>/dev/tcp/host/80` needs no new binary. So do
  `python -c` and every interpreter;
- an exec through the loader (`ld-linux.so ./program`) or from a `memfd` never opens the
  file for execution and passes the check;
- a dead fanotify daemon lets everything through: this layer is fail-open by nature.

The gatekeeper is therefore **a convenience layer**: it routes and suggests. The boundary is
held by namespaces (a container's network and files) and by the host's egress policy. The
gatekeeper's exceptions are **packages in the store, not names**: anybody can put a
`~/bin/bash` (the same lesson as the Wayland allow-list by binary name, LEAK-MODEL §8).

## 7. What exists and what doesn't

| Part | State |
|---|---|
| User zones, gateway topology, second echelon, hermeticity | done |
| Program containers, launch interception, per-container trust | done, M8 tails |
| Machine-readable state and declarative options | done (`status --json`, home-manager) |
| System zones | done (M10, stage 1) |
| Services and NixOS containers in system zones | done (M10, stages 2–3) |
| Broker: a user's program in a system zone | console programs done (`vpn-zone-sys`), graphical ones M10 stage 4 |
| The host without a network by default | done (M10 stage 5: `egress`, `audit` first); the host's resolver next |
| The TTY console: a network right after login | done (`console`, SYSTEM.md §7a) |
| A terminal in a container, the shell hook | M10, stage 6 |
| The gatekeeper for launches from scripts (fanotify) | M10, stage 7, after measurements |
| Camera and microphone asked at run time | M8, tail |

## 8. Who does what

cellward is the engine of both tiers: the code, the modules, the leak checks, one leak
model. A configuration tool (nix_cm) is only a window: it reads `cellward status --json` and
writes module options, as it already does for program containers. Hermeticity is checked in
one place — here.

One rule about keys for both tiers: **zone keys are never declared in Nix.** A system zone is
local state (`/var/lib/vpn-zones/system/`), as a user zone is the user's. A path to a secret
(sops-nix, agenix) is an optional road for those who want reproducibility; then only an
encrypted file is in the repository.
