# A zone's home: a layer over the real one

Status: design, 2026-09-26 (the owner's decisions of that day). Russian:
[HOME-LAYER.ru.md](HOME-LAYER.ru.md).

## 1. Why

A program in a zone without a sandbox has the whole home, read and write
(`docs/LEAK-MODEL.md` §9). The network is the zone's, but a file is a file:
a line in `~/.bashrc`, an entry in `~/.config/autostart`, a launcher, a git
hook, an extension in a browser profile, a `.envrc` — each is code the host
runs later, outside the zone and around its tunnel. `protect_host_files`
(hermetic zones) covers the best-known places read-only, but a list of
dangerous places is never complete (Kate's external tools, VS Code's tasks,
a Firefox profile…). What does not leak is a home the zone cannot change.

## 2. What

Every zone mounts, in its own mount namespace, an overlay over the home:

```
lower  = the real home (read-only through the overlay)
upper  = ~/.local/state/vpn-zones/<zone>/home/upper   (the zone's layer)
work   = ~/.local/state/vpn-zones/<zone>/home/work
```

- The zone sees the whole home as it is, and everything it writes stays in
  its layer. The real home is not written by a zone at all — not a dotfile,
  not an autostart entry, not a project, unless it is shared (§3).
- The layer lives in the zone's own directory, which the zone does not see
  (`hide_project_state` covers the state after the overlay is mounted). It
  outlives the zone: a program's data written in the zone is there next
  time.
- A file the host changes later is seen by the zone as changed — unless the
  zone has written it: then the zone keeps its copy (copy-up is whole-file,
  once).
- Mounts below the home (another disk under `~/mnt`, a FUSE mount) are not
  seen through an overlay; they are bound back on top as they are.

## 3. Shared paths

A path can be given to a zone through the layer: its writes reach the real
home. None by default (the owner's answer): what a zone made is taken out by
the person (§4). A zone that works on real files — the one Claude sessions
run in, editing projects — gets its paths explicitly:

```nix
programs.cellward.home.shared.nix-zone-desktop = [
  "Projects" "Programming" "Configurations" ".claude" ".claude.json"
];
```

or `cellward home <zone> share <path>` / `unshare <path>` / `list`. A path
is relative to the home, below it, and the allow-list rules of
`permissions.paths` apply (`container::forbidden_path`: not the home itself,
not the project's state or config). What a shared path holds is still a
bridge: a zone that edits a flake the person later builds as root runs code
as root. That is trust in the zone, not something a mount can decide.

Container storage (`~/.local/state/vpn-profiles`, `~/.local/state/vpn-sandboxes`)
is always shared: a container's data belongs to the container, not to the
zone it happens to run in — otherwise its data would fork per zone. Its
policy files (`container.conf`, `paths`, `perms`, `trust/`) are therefore not
kept there any more but in `~/.config/vpn-zones/containers/<name>/`, which is
not shared: a zone can change its own view of them, never the host's
(review 2026-09-25, P1).

## 4. Taking files out

`cellward files <zone>` (and «Файлы зоны» in the window menu) opens the
zone's layer in the host's file manager — on the host, not in the zone.
Moving a file out is the person's act. `cellward home <zone> reset` empties
the layer of a zone that is down.

## 5. The old behaviour

`programs.cellward.home.layer.<zone> = false` (or `cellward home <zone>
passthrough`) gives a zone the real home again, with a warning in `doctor`
and `status`. For a zone that must write the real home everywhere and is
trusted to.

## 6. Order in the holder

The overlay is mounted in the app mount namespace before anything else is
bound below the home (runtime sealing binds nothing there; the read-only
covers of `READ_ONLY_IN_ZONES` and `protect_host_files` then land on the
overlay, and `hide_project_state` last):

1. open the real home and the layer directories (descriptors);
2. `mount -t overlay` over the home, `userxattr` (a user namespace);
3. bind back mounts found below the home in `mountinfo`;
4. bind the shared paths, from the real home's descriptor;
5. the rest as before.

Unprivileged overlayfs needs Linux 5.11; a kernel that refuses the mount
leaves the zone with the real home and says so (`doctor`: fail). The layer
inside the lower layer is accepted by the kernel (tested on 7.2, btrfs and
tmpfs; the VM test checks the CI kernel).

## 7. Not in this step

- Saving through the file chooser portal into the real home, per operation
  (the owner's idea): the portal returns a real path to a program that is
  not a Flatpak, and the program then writes it inside the zone — into the
  layer. Doing it needs the bus filter to hand out document-portal paths;
  later, if taking files out by hand is not enough.
- A view of what a zone changed against the real home (a diff).
