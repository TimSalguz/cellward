# Containers by default (M8) — design

Russian: [CONTAINERS.ru.md](CONTAINERS.ru.md) · Related: [LAUNCHERS.md](LAUNCHERS.md)
(launcher entries), [CERTIFICATES.md](CERTIFICATES.md) (per-container trust),
[LEAK-MODEL.md](LEAK-MODEL.md), [GOTCHAS.md](GOTCHAS.md)

**Status: proposal (2026-09-17).** Nothing described here as "new" exists yet
unless it is marked as done. The owner decides the open questions at the end
before any of it is implemented.

## 1. Summary

Today a launch is three independent choices made on every click: a network
(zone, direct, offline), a data container (main, overlay profile, throwaway)
and a filesystem sandbox (none, per-app, named, throwaway). This design turns
the three into one thing, a **container**:

> A container is a named identity: a home, a set of permissions, a set of
> trusted certificates **and exactly one network**. A program instance runs in
> exactly one container. Programs are assigned to containers, not to networks.

Consequences, in order of importance:

1. **Identity cannot be split across networks** ([LEAK-MODEL](LEAK-MODEL.md)
   "Open channels" §4). A container bound to zone `nl` never runs in `direct`:
   the picker does not offer it and `vpn-zone run` refuses it.
2. **No layer is silently dropped.** Every launch takes the same road, whether
   the network is a zone, `direct` or `offline`. The `direct` bug fixed on
   `fix/launch-path` (the picker dropped the container, the sandbox and the
   compositor restriction) is the class of bug this removes by construction.
3. **Launches from outside the launcher end up in the right container**: D-Bus
   activation, autostart, compositor key bindings, links from other programs
   (§5).
4. **Per-zone launcher clones become unnecessary**; the per-container view
   replaces them ([LAUNCHERS.md](LAUNCHERS.md) §4). Nothing is deleted before
   the owner agrees.
5. **Everything is declarative** through module options, with a
   machine-readable state output for nix_cm (§8, §9).

## 2. What exists today

| concept | where it lives | what it isolates |
|---|---|---|
| zone | `~/.local/state/vpn-zones/<zone>/` + `vpn-zone@<zone>` | network (app-ns: `lo` + tunnel only) |
| `direct` | nothing | nothing (host network) |
| `offline` | a zone with a marker, created on demand | everything network, incl. host resolvers |
| overlay container ("profile") | `~/.local/state/vpn-profiles/<name>/` | XDG dirs (`.config`, `.local/share`, `.cache`, `.mozilla`, `.pki`) |
| throwaway container | `/tmp/vpn-profile-*` | same, erased after the last tenant |
| named sandbox | `~/.local/state/vpn-sandboxes/<name>/{home,perms}` | whole home, bus, runtime dir, seccomp, X11 |
| per-app sandbox | a named sandbox called `app-<key>` | same |
| throwaway sandbox | tmpfs | same, erased on exit |
| compositor restriction | `wl-sandbox`, on by default | screen capture, input emulation, background clipboard |

What the picker remembers is per program: `.pinned`/`.last` (network) and
`.pinnedprofile`/`.lastprofile` (container). The two axes are independent,
which is exactly what lets one program's identity travel between networks.

## 3. The model

### 3.1 Container

```
container = {
  name        unique; the selector is what the registry already uses
  home        overlay | private | throwaway-overlay | throwaway-private
  network     <zone> | direct | offline | ask
  permissions filesystem {downloads, documents, pictures, home}, x11,
              compositor {restricted | full}, (later) bus names, devices
  trust       extra CA certificates (CERTIFICATES.md)
  apps        programs assigned here (launcher ids)
  source      declared (Nix, read-only) | local (CLI/GUI)
}
```

- **`home`** maps one-to-one onto what exists: `overlay` is today's profile,
  `private` is today's named sandbox (and the per-app `app-<key>` one),
  the throwaway kinds are today's `--tmp-profile` and `--fs-sandbox`. Data
  directories stay where they are; they are part of the contract
  ([GOTCHAS](GOTCHAS.md) §5).
- **`network = ask`** is the compatibility value: the network question is asked
  on every launch, exactly as now. Every container that exists today migrates
  to `ask`. A container created by the new GUI binds its network at creation.
- **The main home is not a container.** "No container" stays available (host
  tools, terminals that run `sudo`), is shown as such, and cannot hold trust or
  a binding.

### 3.2 Invariants

- **I1. One network per container.** A container with a bound network is
  launched into that network only. `vpn-zone run <other> --profile <c>` is a
  refusal with the way out named ("контейнер `c` привязан к сети `nl`;
  перепривязать: `vpn-zone container set c network <сеть>`"), never a silent
  launch.
- **I2. One container per program instance.** Already true by construction
  (the registry records the selector); the conflict check also looks at the
  binary (done on `fix/launch-path`).
- **I3. Every layer on every road.** Network, home, permissions, trust and the
  compositor restriction are applied by one code path (`vpn-zone run` →
  `entry_argv` → `profile-run`), for zones, `direct` and `offline` alike.
- **I4. Unknown means offline.** A program with no assignment still gets the
  "no network until given" default ([GOTCHAS](GOTCHAS.md) §2); with
  `defaults.container = own` it also gets its own private home.
- **I5. Fail closed.** A container bound to a zone that no longer exists does
  not start in another network; a trust layer that cannot be applied stops the
  launch ([CERTIFICATES.md](CERTIFICATES.md) §4).

### 3.3 Per-launch runtime (the order is the specification)

```
[nsenter -U -n -m -t <zone>]  or  [unshare -U --map-current-user --keep-caps]   (direct)
  └─ unshare --mount --propagation private           always, when anything is mounted
      └─ vpn-zone-core profile-run --cwd <dir> …
           1. home layer: overlay slots (missing lower dirs created empty, 0700)
           2. runtime hermeticity (§6, phase 4): tmpfs over /run/user/<uid>,
              sockets back by name; tmpfs over /tmp/.X11-unix
           3. trust layer: bundle binds, NSS databases (CERTIFICATES.md)
           4. chdir <dir> → $HOME → /            (done: fix/launch-path)
           5. drop ambient capabilities
           6. exec: wl-sandbox → fs-sandbox (bwrap) → program
```

Every mount happens in the launch's own mount namespace, never in the zone's:
two containers in one zone must not see each other's layers or certificates.
bwrap binds recursively, so what steps 1–3 mounted is what the sandbox sees.

## 4. Choosing a container

Resolution order for a launch of program `P`:

1. a running instance of `P` (by launcher id): the same container — clicking a
   running program means "raise the window" ([GOTCHAS](GOTCHAS.md) §11);
2. a **declared** assignment (`programs.vpn-zones.apps.P.container`);
3. a **local** pin (`.pinnedprofile`, and `.pinned` for `ask` containers);
4. the question.

The question becomes container-first. A sketch of the menu (texts are
illustrative, the final ones go through i18n):

```
Where should «Firefox» run?
  🔒 work — VPN nl · own home
  📁 personal — direct · layer over your home
  ⚠ gov — VPN ru · own home · EXTRA ROOT CERTIFICATE
  ── one-off ──
  Offline, throwaway sandbox
  VPN nl, throwaway sandbox
  No container · direct            (shown last, plain)
  ── ──
  ➕ New container…                 (name, home kind, network — bound)
  Always: …                         (pins the program to the chosen container)
```

The existing network-first dialog stays available for `ask` containers and for
"no container", so nothing a user relies on today disappears.

## 5. Launches outside the launcher

Interception is **default routing, not a security boundary**. A process on the
host can always `exec` a store path directly; the host user is trusted. The
boundary is the container → outside direction (§6). The table lists every way
a program gets started and what routes it.

| path | today | proposal | phase |
|---|---|---|---|
| launcher entry (menus, fuzzel/rofi, KRunner, noctalia) | picker shadow entry in `~/.local/share/applications` | unchanged; container-first question | 1 |
| entries the user dir already holds (Steam games, `userapp-*` of messengers, web apps, Wine) | **not intercepted**: foreign files are never rewritten | owner's decision, see [LAUNCHERS.md](LAUNCHERS.md) §3.2 | 3 |
| child entries (`steam steam://rungameid/…`) | cloned per zone as separate programs | routed to the parent's container | 1 |
| `xdg-open`, `gio open`, `kde-open`, "open with" | resolve to a `.desktop` → the shadow entry | unchanged | — |
| D-Bus activation (`DBusActivatable=true`, `gapplication launch`) | `DBusActivatable=false` in the shadow; the service file still activates around it | shadow session service files in `$XDG_DATA_HOME/dbus-1/services/<id>.service` for intercepted ids only; never for portal or system names | 3 |
| XDG autostart (`~/.config/autostart`, systemd-xdg-autostart-generator) | runs uncontained | shadow entries in `~/.config/autostart` for **assigned** programs only; no dialogs at login; unassigned ones listed by `doctor` | 3 |
| compositor key bindings (niri `spawn`, KWin shortcuts) | only if the binding itself calls `vpn-zone-pick` | `vpn-zone launch <launcher-id> [args]` reads the entry's own `Exec` (no command duplicated in the compositor config); a module option exposes the command line | 3 |
| shell | uncontained | opt-in PATH shims for assigned programs (`~/.local/share/vpn-zones/shims`), with a recursion guard; never a boundary | 3 |
| portal `OpenURI`/`OpenFile` from a host program | the portal launches the handler's entry → shadow → picker | unchanged | — |
| portal `OpenURI` from a container | same, but the origin is lost: a link from a zone may open in a direct browser | broker (§6.2) | 4 |
| a link or program opened from inside a zone (`vpn-zone run` in a zone) | delegated through `systemd --user` (`launch.rs` step 1) | the same door, but guarded: broker (§6.2) | 4 |
| `systemd-run --user`, `systemctl --user` from inside a zone | reachable: a process can start anything outside | runtime hermeticity (§6.1) | 4 |
| `flatpak run`, `flatpak-spawn --host` | flatpak's own sandbox; `--host` escapes over the session bus | private containers already filter the bus; overlay containers get it with §6.1 | 4 |
| programs started by other host programs | uncontained | out of scope (host is trusted); `doctor` names it | — |

### 5.1 Child entries

An entry is a **child** when its command hands a URL to another program:
`Exec=steam steam://rungameid/<id>`. Detection: an argument is a URL whose
scheme some other entry claims as `x-scheme-handler/<scheme>`, and both entries
start the same program. A child is never cloned per zone and, in picker mode,
uses the parent's launcher id: the running client decides where the game runs,
and the game is its child — its network is the client's ([GOTCHAS](GOTCHAS.md)
§10a). "A network per game" is impossible while the client owns the launch;
the honest UI is "Steam's container".

### 5.2 The launch command for bindings

`vpn-zone launch <launcher-id> [-- extra args]` finds the entry by id in the
same source directories `sync` reads, takes its `Exec` (field codes filled from
the extra arguments), and becomes the picker for it. A compositor binding then
names the program once:

```kdl
Mod+B { spawn "vpn-zone" "launch" "firefox"; }
```

## 6. The outward boundary (phase 4)

These are M3 items; containers make them per-container defaults instead of
global switches.

### 6.1 Runtime hermeticity

In the launch's mount namespace: tmpfs over `/run/user/<uid>` with only the
Wayland socket (already restricted), PipeWire, PulseAudio and the broker socket
bound back; tmpfs over `/tmp/.X11-unix` plus `unset DISPLAY`
([LEAK-MODEL](LEAK-MODEL.md) §7); optionally tmpfs over `/run/dbus`. Private
containers already have all of it through bwrap. Overlay containers get it as
the default once the broker exists — before that it would break opening links,
which is exactly what the delegation path serves today.

### 6.2 Broker

One socket per container, bound into its runtime directory. One verb: "open
this" (a URI, a file handed over by fd, or a launcher id). On the host side the
broker knows the origin container, so the decision is:

- target program assigned to the **same** container → start it there, no
  dialog;
- a locked container → only the same container;
- otherwise → the picker, with the origin in the question ("a link from `work`
  (VPN nl)").

Inside the container, three entry points reach it:

1. `xdg-open` and `$BROWSER` resolve to the broker client (a bind over the
   store path of `xdg-open` in the launch's mount namespace);
2. the delegation in `launch.rs` step 1 goes to the broker instead of
   `systemd-run`;
3. portals: private containers stop getting `OpenURI`/`OpenFile` through the
   bus proxy (`--call` rules per portal interface instead of the blanket
   `--talk=org.freedesktop.portal.*`). GTK, Qt and Firefox under
   `/.flatpak-info` call the portal and do not fall back to `xdg-open`, so a
   portal-compatible front for `OpenURI` is needed before this switch.
   **Open research item**, prototype in the VM before any promise.

## 7. Limits without root

What cannot be done as an unprivileged user, and why. Each item is a
constraint on this design, not a to-do.

- **No global interception of `exec`.** fanotify permission events, LSM and
  eBPF hooks need `CAP_SYS_ADMIN`/`CAP_BPF` in the initial user namespace.
  seccomp user notification would need `NO_NEW_PRIVS` on the whole session,
  which breaks every setuid helper (`sudo`, and `newuidmap`, which zones depend
  on), and still does not reach the children of `systemd --user`.
- **No per-process network policy on the host.** cgroup BPF and `net_cls` need
  root. A network is only ever a namespace.
- **A running process cannot be moved** into another network or container.
  `setns` acts on the caller; a program started outside stays outside until it
  is restarted.
- **Host files cannot change, only views of them.** Every change of `/etc`
  (bundles, `nsswitch.conf`, browser policies) is a bind or tmpfs in our own
  mount namespace, and a mount point has to exist already: nothing can be
  created inside root-owned directories.
- **The host session bus cannot be filtered for host programs**, only for
  containers, through a proxy.
- **Kernel modules** (`amneziawg`, `nf_tables`) cannot be loaded from a user
  namespace, and `/etc/subuid` needs the administrator once.
- **Programs with compiled-in trust or their own runtime** (Flatpak runtimes,
  Steam's pressure-vessel, AppImages, `webpki-roots`) cannot be given a trust
  layer from outside ([CERTIFICATES.md](CERTIFICATES.md) §2).

## 8. Declarative configuration (module options)

For nix_cm, whose rule is "program settings only through module options":
options in, JSON out (§9), no parsing of our files on its side.

```nix
programs.vpn-zones = {
  enable = true;

  launcher.mode = "picker";              # picker | per-zone | both | off
  defaults = {
    network = "offline";                 # offline | direct | <zone>
    container = "ask";                   # ask | main | own | <container>
  };
  compositorRestriction.enable = true;

  containers.work = {
    home = "private";                    # overlay | private
    network = "nl";                      # <zone> | direct | offline | "ask"
    apps = [ "firefox" "org.telegram.desktop" ];
    permissions = {
      filesystem = [ "downloads" ];      # downloads | documents | pictures | home
      x11 = false;
    };
    trust = {                            # CERTIFICATES.md
      certificates = [ ./certs/some-root-ca.pem ];
      acknowledgeRisk = true;            # required when certificates is non-empty
    };
  };

  interception = {
    dbusActivation = false;              # phase 3
    autostart = false;                   # phase 3
    userEntries = "leave";               # leave | take-over — LAUNCHERS.md §3.2
  };
};
```

- Declared values are written by home-manager into
  `~/.config/vpn-zones/declared/` (read-only store links) and **take
  precedence** over local state. The CLI and the GUI show them as "set in
  Nix" and refuse to change them instead of failing on a read-only file.
- Zones themselves are not declared: a zone config is a private key and must
  never enter the Nix store. A declared container naming a zone that does not
  exist is a launch-time refusal (I5), not an evaluation error.
- Assertions at evaluation time: `trust.certificates != []` requires
  `acknowledgeRisk`; one program in two containers' `apps` is an error;
  `permissions.filesystem` on an `overlay` home is a warning (it does not
  apply).

## 9. Machine-readable state

`vpn-zone status --json` prints everything; `vpn-zone container list --json`
and `vpn-zone container show <name> --json` print subsets of the same schema.
Additive changes only within a `version`.

```json
{
  "version": 1,
  "defaults": { "network": "offline", "container": "ask",
                "launcher_mode": "picker", "compositor_restriction": true },
  "zones": [
    { "name": "nl", "backend": "amneziawg", "up": true, "locked": false,
      "handshake_age_s": 42 }
  ],
  "containers": [
    { "name": "work", "selector": "sb:work", "home": "private",
      "source": "declared", "network": "nl",
      "apps": ["firefox"],
      "permissions": { "filesystem": ["downloads"], "x11": false,
                       "compositor": "restricted" },
      "trust": { "extra": [ { "sha256": "…", "subject": "CN=…",
                              "not_after": "2030-01-01T00:00:00Z",
                              "source": "declared" } ] },
      "running": [ { "app": "firefox", "pid": 1234, "zone": "nl" } ] }
  ],
  "apps": [
    { "id": "firefox", "label": "Firefox", "container": "sb:work",
      "source": "declared" }
  ]
}
```

The JSON is written by hand like the manifest parser is read by hand (no
`serde`): the schema is ours and flat enough. Its only consumer-visible
contract is this document; a test pins every key.

## 10. Where can a packet or a DNS query go around the tunnel now?

Asked for every piece, as the project rules require.

- **Container binding (I1).** Removes a path rather than adding one: an
  identity can no longer be taken into another network by a click.
- **`direct` containers** (done). No network namespace by definition — the
  program uses the host's network and the host's resolvers, and says so in
  the name. The user namespace is new; it grants no capability over the host
  netns.
- **Per-launch mount namespace.** No network change; mounts are private to the
  launch.
- **`vpn-zone launch`, PATH shims, autostart and D-Bus shadows.** They only
  start the picker or `vpn-zone run`; no new socket, no new route.
- **Broker.** A new unix socket inside the container — a door with a guard:
  one verb, and a human decides anything that crosses containers. It replaces
  the unguarded `systemd --user` path, which is strictly wider.
- **JSON output.** Names zones and containers to any process of the user.
  Inside a private container the state directory is not visible at all;
  inside an overlay container the whole home is readable already
  ([LEAK-MODEL](LEAK-MODEL.md) §9) — nothing new is disclosed.
- **Trust layer.** Not a network path, but a MITM channel; its own analysis is
  [CERTIFICATES.md](CERTIFICATES.md) §5.

## 11. Phases and tests

Every phase ends with a VM test that is red before and green after
([LEAK-MODEL](LEAK-MODEL.md): "a channel is closed when a test opens it").

| phase | content | proof |
|---|---|---|
| 0 | launch-path fixes: `direct` keeps its layers, working directory, conflict by id and binary (**done**, `fix/launch-path`); child entries | smoke: layer + host netns + own userns in `direct`; `pwd` and a file only in the upper layer |
| 1 | container entity, network binding (I1), container-first picker, `vpn-zone container …`, `status --json`, module options, migration to `network = ask` | CLI/picker scenario tests; VM: a bound container refuses another network; JSON schema test |
| 2 | trust layer ([CERTIFICATES.md](CERTIFICATES.md)) | VM: synthetic CA trusted in container A only |
| 3 | `vpn-zone launch`, D-Bus and autostart shadows, child entries in picker mode, user-dir entries (per owner's decision), PATH shims | VM: activation via `gdbus call`/`gapplication launch` lands in the container |
| 4 | runtime hermeticity, broker, X11 closure | VM "evil host": a `systemd --user` that counts `StartTransientUnit`, a portal that logs callers, an HTTP beacon |

## 12. Open questions for the owner

1. Bind the network into containers (I1) — and migrate existing containers to
   `ask` (compatible) or ask the user once per container?
2. `defaults.container`: keep `ask`, or make `own` (every new program gets its
   own private home) the default for new installs?
3. Foreign entries in `~/.local/share/applications` (Steam games, `userapp-*`,
   web apps, Wine): leave them uncontained, or take them over in place with a
   backup ([LAUNCHERS.md](LAUNCHERS.md) §3.2)? This changes a written invariant
   ("foreign files are never rewritten").
4. Autostart of an unassigned program: start as is (today), start offline
   without a dialog, or not start and notify?
5. Per-zone clones: deprecate now and remove after the container view lands
   ([LAUNCHERS.md](LAUNCHERS.md) §4)?
6. The unmerged `feat/openconnect-backend`: merge first, or rebase it after
   this work?
