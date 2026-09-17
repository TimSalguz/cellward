# Launcher entries: how they work, what is broken, what becomes of them

Russian: [LAUNCHERS.ru.md](LAUNCHERS.ru.md) · Related:
[CONTAINERS.md](CONTAINERS.md) · Specification of past traps:
[GOTCHAS.md](GOTCHAS.md) §1, §5, §10, §11, §13

**Status (2026-09-17):** §2 is a review of the code; the items marked *done*
are in `main`. §3.2 and §4 carry the owner's decisions of 2026-09-17.

## 1. How it works today

### 1.1 Generation (`rust/src/desktop.rs`, `vpn-zone-core sync`)

1. **Sources**, in priority order: `~/.local/share/applications`,
   `/etc/profiles/per-user/<user>/share/applications`,
   `/run/current-system/sw/share/applications`, then every
   `$XDG_DATA_DIRS/applications`. The first file of a given name wins.
2. **Candidates**: `Type=Application` with a non-empty `Exec`, not
   `NoDisplay`/`Hidden`, not named `vpn-zone-*`, not carrying `X-VPNZone`.
3. **Picker mode** (default): for every candidate that came from a system
   directory, a file **of the same name** in `~/.local/share/applications`
   shadows it (the XDG precedence rule). The copy keeps every key, including
   `MimeType` and the field codes; `Exec` becomes `vpn-zone-pick --id <file
   name without .desktop> -- <original Exec>`; `DBusActivatable=false` and
   `X-VPNZone=picker` are added, `TryExec` is dropped. The human-readable name
   goes to `~/.local/state/vpn-zones/.labels/<id>` — never into `Exec`, because
   some launchers split `Exec` on spaces without honouring quotes.
4. **Per-zone mode**: for every candidate (the user directory included) and
   every zone, `vpn-zone-<zone>-<name>.desktop` with `Name=… (<zone>)`,
   `Exec=vpn-zone run <zone> -- <Exec without field codes>` and no
   `MimeType`. `both` does both.
5. **Cleanup**: our files (marker present, not a symlink) that were not
   produced by this pass are removed. Foreign files and symlinks are never
   touched; a file is written only when its content changed (a path unit
   watches the directory).
6. **Triggers**: home-manager activation, a timer (2 min after login, then
   every 30 min), a path unit on the three main source directories, and
   `vpn-zone mode`/`rm`.

### 1.2 Launch chain

```
launcher → vpn-zone-pick --id K -- cmd
  memory: running instance (.running) → pin (.pinned/.pinnedprofile)
          → last choice (.last/.lastprofile) → defaults
  dialogs: network, then (on request or when pinned-but-free) container
  → vpn-zone run <net> [--profile P | --tmp-profile [--join D]]
                       [--sandbox S | --fs-sandbox] -- cmd
      delegation out of a zone / lock → container → wrappers
      (wl-sandbox, fs-sandbox) → conflict warning → zone start
      → registry → exec: nsenter | unshare → profile-run → program
```

## 2. Problems found

| # | problem | effect | status |
|---|---|---|---|
| L1 | **"direct" skipped `vpn-zone run`**: the picker became the command | the chosen/pinned/default container or sandbox was dropped (whole `$HOME`), no Wayland restriction, no registry record, a locked zone's lock bypassed | **done** |
| L2 | `nsenter` does `chdir("/")` | a terminal started into a zone opens in `/` (§1) | **done** |
| L3 | conflict key = launcher id **or** binary | two entries for one single-instance binary (Steam game and Steam, firefox and firefox-private) did not warn; link hand-over had the wrong text (§5) | **done** |
| L4 | `VPN_ZONE_DELEGATED` stayed in the program's environment | the second link clicked in a program opened by delegation died in `nsenter` | **done** |
| L5 | child entries (`Exec=steam steam://rungameid/…`) treated as programs | per-zone mode: games × zones clones (about a hundred on a real desktop), each promising a network choice the client ignores (§10) | **done** |
| L6 | **`NoDisplay=true` entries are never intercepted** | URL and file handlers are exactly the entries hidden from menus (`x-scheme-handler/…`, "open with" helpers): a link opened through one starts the program uncontained, around the picker. Ten such scheme handlers in the system directories of a real desktop | **done**: intercepted under the id of the visible entry of the same program; helpers without one are left alone |
| L7 | **foreign entries in `~/.local/share/applications` are never intercepted** | Steam games, browser web apps, Wine, anything created through the DynamicLauncher portal — and the `userapp-*` entries programs write when they make themselves the default handler. On a real desktop `mimeapps.list` sends `http`, `https` and `tg` to such entries: **every link opened from any host program starts the browser (or the messenger) uncontained, in the direct network**, although the same program's system entry is intercepted | decided: take-over in place (§3.2); the most consequential item of this table |
| L8 | the id is sanitised lossily (`[A-Za-z0-9._-]`, the rest → `_`) | two non-ASCII entry names of equal length collide (`Игра.desktop`, `Мода.desktop` → `____`): shared pins, labels, registry and sandbox home — one program starts in the other's network or container | proposal: append a short hash when sanitising lost characters; migrate old keys once |
| L9 | per-zone clones carry no launcher id | sandbox permissions and registry keyed by the binary, different from picker mode (the "two permission sets for Discord" trap, §6); `Desktop Action`s are dropped | moot if clones are deprecated (§4) |
| L10 | D-Bus activation goes around the shadow | `DBusActivatable=false` only helps launchers that honour it; the app's session service file still activates it (`gapplication launch`, GNOME "open with") | phase 3 ([CONTAINERS.md](CONTAINERS.md) §5) |
| L11 | autostart is not intercepted | programs in `~/.config/autostart` or `/etc/xdg/autostart` start uncontained at login | phase 3 |
| L12 | the label comes from the untranslated `Name` | dialogs say "Firefox" where the menu says the localised name | M6 |

The path unit also misses `$XDG_DATA_DIRS` directories (Flatpak exports):
new Flatpak apps are picked up by the timer, up to 30 minutes later. Minor,
listed so it is not rediscovered.

## 3. Proposed fixes

### 3.1 Child entries (L5)

An entry is a child when an argument of its `Exec` is a URL whose scheme is
claimed (`MimeType=x-scheme-handler/<scheme>`) by **another** candidate that
starts the same program (the same first command word after wrappers). Steam:
`steam.desktop` has `Exec=steam %U` and `x-scheme-handler/steam`; every game
entry has `Exec=steam steam://rungameid/<id>`.

- per-zone mode: no clones for children (cleanup removes the existing ones);
- picker mode, when the child can be intercepted: `--id <parent id>`, so the
  running client's record routes the click and the conflict check applies;
- the menu stays honest: a game runs in the client's container, and the UI
  says "Steam's container" rather than offering a network per game.

### 3.2 Foreign entries in the user directory (L7) — take-over

**Decision (owner, 2026-09-17): everything in containers, these entries
included.** The invariant today is that foreign files in
`~/.local/share/applications` are never rewritten ([GOTCHAS](GOTCHAS.md) §10);
it exists because the first sync that ignored it erased the entries Nix puts
there. The shadowing trick cannot help: no directory has higher precedence than
this one. Pointing `mimeapps.list` at the intercepted entry is not a fix
either: that file is user state, not configuration — the user's own "always
open with" choices live there, and programs rewrite it whenever they make
themselves the default handler.

**The method: take over in place, keep the original, re-take on rewrite.**

1. A candidate is a **regular file** (never a symlink — home-manager's and
   Nix's entries stay untouched), not ours, with a usable `Exec`.
2. Its exact bytes are stored in `~/.local/state/vpn-zones/.adopted/<name>`
   together with a hash of the rewritten version.
3. The entry is rewritten the way a shadow is (`Exec` through the picker,
   `DBusActivatable=false`, `X-VPNZone=adopted`), everything else kept.
4. A path unit already watches the directory: when a program writes its entry
   again, the file no longer matches the stored hash, the new bytes replace
   the stored original and the entry is taken over again.
5. `vpn-zone mode off`, removal of the program, or `interception.userEntries =
   "leave"` put every original back byte for byte.

| kind of entry | who writes it, and when | how it is taken over | cost and residual risk |
|---|---|---|---|
| Steam games (`Exec=steam steam://rungameid/…`) | Steam, when a shortcut is created | a child: launched under Steam's id, no clones | rewritten rarely; while Steam runs the game lands in Steam's container anyway (the pipe in the shared home) |
| browser web apps (`chromium --app-id=…`, `--profile-directory=`) | the browser, on install and on update | a child of the browser (the same single-instance process opens it) | rewritten on browser updates; between the rewrite and the re-take (well under a second, path unit) a click would start it uncontained |
| `userapp-*` of messengers and browsers made default handlers | the program itself, **at every start** | its own launcher id if the program has no visible entry, otherwise the program's id | the most frequent rewrite. Each start of the program un-takes it until the path unit re-takes it; a link clicked in that window would open uncontained. The program already running at that moment makes it land in the running instance instead. Acceptable only with the re-take; documented, and `doctor` shows the count of re-takes |
| Wine (`wine-extension-*`, `wine-protocol-*`, per-program entries) | `winemenubuilder`, on every prefix update | its own id; the prefix path from `WINEPREFIX=` in `Exec` is offered as a path grant | a private home without the prefix cannot start the program at all — hence the grant; many small entries per prefix |
| hand-written entries of the user | the user | as any entry | the user's own file changes; the original is kept and `leave` restores it |

The take-over is a **change of a written invariant**: it lands in a commit of
its own with this reasoning, behind `interception.userEntries` (default
`take-over` once the VM test on a desktop like the owner's passes).

### 3.3 `NoDisplay` handlers (L6)

Done. In picker mode, `NoDisplay=true` entries that declare a `MimeType` are
intercepted under the id of the visible entry of the same program and keep
`NoDisplay=true` in the shadow; no clones. A hidden entry with no visible entry
of its program is a system helper (an OAuth callback, a settings URL handler)
and is left alone — intercepting it would put a network dialog in the middle
of a login. `Hidden=true` stays excluded (it means "deleted").

### 3.4 Lossy ids (L8)

`key = sanitize(name)` when nothing was lost, otherwise `sanitize(name) + "-" +
first 8 hex digits of a hash of the name`. On the first launch under the new
key the picker moves `.pinned`, `.pinnedprofile`, `.last`, `.lastprofile` and
`.labels` from the old key if exactly one entry maps to it; with a collision it
drops the ambiguous memory and asks again. Sandbox homes `app-<old key>` are
renamed the same way.

## 4. What becomes of launcher entries

The owner's thought was that per-zone entries are no longer needed once every
program lives in a container with its network. Assessment, and the decision
(owner, 2026-09-17: **deprecate now**):

- **Per-zone clones contradict the container model.** Their whole purpose is
  "this program, in that network" — a per-click network choice, which is how
  one identity ends up in two networks ([CONTAINERS.md](CONTAINERS.md) I1).
  They also scale as programs × zones: about a hundred on a real desktop.
- **The single intercepted entry stays.** It is the mechanism of "containers by
  default": whatever starts a program through its entry goes through the
  picker, and the picker resolves the container without a dialog once the
  program is assigned.
- **Per-container entries replace clones where they are wanted**: only for a
  program assigned to two or more containers ("Firefox — work", "Firefox —
  personal"), generated from assignments, never as a product.
  `Exec=vpn-zone launch <id> --container <c>`; `MimeType` only on the program's
  main entry.

Steps:

1. **now**: `vpn-zone mode per-zone|both`, `vpn-zone sync` in those modes and
   the GUI settings say the mode is deprecated and why; nothing is removed;
2. with the container model (phase 1): per-container entries; the GUI stops
   offering `per-zone`;
3. once the per-container view is in use: per-zone generation is removed, with
   a CHANGELOG entry and a migration that deletes our clones (they carry our
   marker).
