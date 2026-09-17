# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

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
