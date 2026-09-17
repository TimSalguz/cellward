# Runtime hermeticity of a zone — design and decisions to take

Русская версия: [HERMETICITY.ru.md](HERMETICITY.ru.md) · Related:
[LEAK-MODEL.md](LEAK-MODEL.md) ("open channels"), [CONTAINERS.md](CONTAINERS.md)
§6, ROADMAP M3 (hermeticity, broker, X11).

**Status: decided (the owner, 2026-09-17), implementation in progress** — see
§7 for the decisions. `vpn-zone doctor` reports every channel below as `warn`
until it is closed.

## 1. What is open today

A program started in a zone WITHOUT a sandbox (no `--sandbox`/`--fs-sandbox`)
sees, in the zone's mount namespace, what every host program sees:

| channel | what it gives a program in the zone | LEAK-MODEL |
|---|---|---|
| `/run/user/<uid>/bus` (session bus) | `org.freedesktop.systemd1` → `StartTransientUnit`: any process OUTSIDE the zone, in the host's network; portals (`OpenURI` opens a link on the host); Secret Service (every password in the keyring); every other program's D-Bus API | §1, §2 |
| `/run/user/<uid>/systemd/private` | the same `systemd --user`, without D-Bus | §1 |
| `/run/dbus/system_bus_socket` | NetworkManager (real interfaces, SSIDs, addresses), hostname1, resolve1, machined: de-anonymisation without a packet | §3 |
| `/tmp/.X11-unix/X*`, `DISPLAY` | the host's X server: keyboard, screen and clipboard of the whole machine | §7 |

The network topology cannot close any of them: they are Unix sockets, not
interfaces. Only the mount namespace can, and the sandbox already does it for
sandboxed programs — the measured cost there is "portals, notifications, tray
only".

## 2. The shape of the fix

In the zone's mount namespace (once, at zone start, so that every program in
the zone gets it — not per launch):

1. **tmpfs over `/run/user/<uid>`**, with bound back: the Wayland socket (the
   restricted one of `wl-sandbox` stays per launch), PipeWire, PulseAudio,
   and two sockets of ours: a **filtered session bus** (`xdg-dbus-proxy`) and
   the **broker**. `systemd/private` is not bound back.
2. **tmpfs over `/tmp/.X11-unix`** and `DISPLAY` unset in the launch
   environment; a container granted `x11` gets its own `xwayland-satellite`
   (decision A).
3. **The system bus**: one of B1–B3 below.

## 3. Decision C — the session bus and the broker

A filter with the rules of the sandbox (`portal.*`, `Notifications`,
`StatusNotifierWatcher`) applied to EVERY program of a zone breaks, measured
by what those programs use the bus for:

| breaks | who notices |
|---|---|
| Secret Service / KWallet / GNOME Keyring | browsers fall back to an unencrypted password store or ask for a password; mail and chat clients lose saved logins |
| MPRIS (`org.mpris.MediaPlayer2.*` needs `--own`) | media keys and the shell's player widget do not see players in the zone |
| IBus / fcitx5 input methods | typing in a second layout through an input method stops working in zone programs |
| KDE global shortcuts (`org.kde.kglobalaccel`) | shortcuts registered by zone programs do nothing |
| dconf / GSettings writes (`ca.desrt.dconf`) | GTK programs cannot save settings (they fall back to memory) |
| `systemd --user` | **by design** — including today's delegation of a launch out of a zone (`launch.rs` step 1), hence the broker |
| D-Bus activation of other programs | a zone program cannot start a host program by name — also by design |

Each row can be allowed back per container (`permissions.dbus`, like
Flatpak's `finish-args`) — except `systemd1`, which is the escape itself.

**The broker** replaces the delegation: one socket per zone, one verb —
"open this" (a URI, a file passed by descriptor, a launcher id). The host side
knows which zone asked, and answers:

- the target is assigned to the same container → start it there, no dialog;
- the zone is locked → only the same container;
- otherwise → the picker, with "asked by zone X" in the question.

Inside the zone `xdg-open`/`$BROWSER` resolve to the broker client, and the
portal's `OpenURI`/`OpenFile` are filtered out of the bus proxy (`--call`
rules) so that GTK/Qt fall back to `xdg-open`. Firefox and GTK under
`/.flatpak-info` call the portal and do NOT fall back — a portal-compatible
front for `OpenURI` is needed first; that is the research part.

**Proposed order** (nix-cm-eb recommends it too): a prototype behind a
per-zone flag `hermetic = true`, OFF by default, proven in the VM by an "evil
host" — a `systemd --user` path that counts `StartTransientUnit` calls, a
portal that logs its callers, a beacon on the host's loopback — before it
becomes a default, with the table above as the list of what the owner accepts.

## 4. Decision B — the system bus

| option | how | cost |
|---|---|---|
| B1 | tmpfs over `/run/dbus` in the zone | UPower (battery), logind inhibitors (a player keeping the screen on), NetworkManager applets inside zones stop working |
| **B2 (recommended)** | `xdg-dbus-proxy` for the system bus: `login1` and `UPower` allowed, `NetworkManager`, `hostname1`, `resolve1`, `machined`, `timedate1` denied | one proxy process per zone, started and supervised by the zone holder like pasta |
| B3 | as is, `warn` in `doctor` | NetworkManager answers "which networks is this machine on" to any zone program |

## 5. Decision A — X11

| option | behaviour |
|---|---|
| **А (recommended)** | closed by default in zones; a container with the `x11` permission gets its own `xwayland-satellite`, like the sandbox |
| Б | closed by default; an explicit `x11 = "host"` hole per container |
| В | as is until А is implemented |

## 6. What is not in question

- The sandbox already has all of this and keeps it.
- Environment variables are not a boundary (`unset DBUS_SESSION_BUS_ADDRESS`
  changes nothing: socket paths are well known). Only the mount closes.
- None of it is a network change: no packet goes anywhere new; what changes is
  which host services a zone program can ask to act for it.

## 7. Decisions (the owner, 2026-09-17)

- **A — X11: option А — implemented.** Closed in zones by default: tmpfs over
  `/tmp/.X11-unix` in the zone's mount namespace and no `DISPLAY` in a launch.
  A container with the `x11` permission gets its own `xwayland-satellite`.
  There is no `x11 = "host"` hole. The same per zone, for zones without
  containers: `vpn-zone x11 <zone> on` or `zoneX11 = [ "<zone>" ]`.
- **B — the system bus: B2, narrowed — implemented.** `xdg-dbus-proxy` per zone; `UPower`
  allowed; `login1` only `Inhibit` and reading properties — no session list,
  no power management; `NetworkManager`, `hostname1`, `resolve1`, `machined`,
  `timedate1` denied.
- **C — the session bus and the broker.** The prototype first, behind a
  per-zone flag `hermetic`, proven by an evil host in the VM — **the prototype
  is implemented** (`vpn-zone hermetic <zone> on`); what follows is not yet.
  Then:
  1. `hermetic` becomes the default; switching it off is explicit and per
     zone (a zone whose programs legitimately drive `systemd --user`, such as
     one running agents that start VM checks with `systemd-run --user`).
     **The switches are implemented, the default is not flipped yet:**
     `hermetic.default` and `hermetic.exceptions` in the module,
     `vpn-zone hermetic --default on|off` and
     `vpn-zone hermetic <zone> on|off|default` locally. What wins: a zone in
     `hermetic.exceptions` (the opposite of `hermetic.default`, which the
     module requires with it), then the zone's own setting, then
     `hermetic.default`, then the local default, then off. Only `off` opens
     anything: the prototype's empty marker, an unreadable one and any other
     content mean on. The holder decides once, when the zone comes up;
     `status --json` shows `defaults.hermetic` and `networks[].hermetic`, each
     with its source;
  2. bus permissions come from the program's Flathub manifest
     (`finish-args`: `--talk-name`, `--own-name`, `--system-talk-name`) when
     it has one, so that the filter does not break known programs;
     `permissions.dbus` is for the rest;
  3. the Secret Service the way Flatpak's Secret portal does it: a key of the
     container's own, never the host's whole keyring;
  4. MPRIS and input methods (IBus, fcitx) allowed by default; dconf writes
     and KDE global shortcuts by a per-container permission.
- `own` for everything (decision №2 of CONTAINERS §12) is a sandbox, i.e.
  Flatpak-like isolation without `hermetic`; the flag closes the rest: overlay
  containers, the main profile, launches without a sandbox.
