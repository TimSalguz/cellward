# Filesystem views and the launch dialog

The launch dialog has one final confirmation, with a fixed header and footer.
Environment, Permissions and Files are pages of the same draft. Merely browsing
or cancelling changes no policy. Filesystem confirmation is applied by the host
picker, before entering the container; an application-controlled environment
variable cannot suppress the permission question. Older GUI/CLI paths retain
the fallback question. Existing legacy filesystem grants are displayed and
preserved, including a legacy whole-home grant; they must never be described as
a private home. X11 belongs to Permissions, not Files.

## Base home and nested exceptions

- Private: the container's own persistent home; ordinary host home is absent.
- Layer: ordinary host files can be read; writes go to a persistent home layer.
- Real home: ordinary host files are read and written directly. Network/session
  isolation still applies. This is different from an unconfined host process.

For private and layer homes, explicit folder rules can be nested arbitrarily:

```
~/Projects                  overlay
~/Projects/shared           rw
~/Projects/shared/cache     overlay
~/Projects/reference        ro
```

`ro` reads host files without host writes; `rw` writes to real host files;
`overlay` reads the real folder and stores changes in this container's separate
persistent layer. `inherit` removes the explicit rule. The closest ancestor rule
then applies, otherwise the base home does. Parents mount before children, and
all sources are resolved before parent mounts hide them. Mutable folder layers
and the whole-home layer are mounted once by the container instance. Launches
bind that same view, preserving shared directory caches and changes between
programs. They do not independently mount overlays over the same upper/work
([kernel restriction](https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html#sharing-and-copying-layers)).
Real/read-only source views are also pinned by the holder before the base HOME
overlay is mounted. Otherwise a nested “Real” rule could accidentally bind a
directory from the HOME overlay and fail to write through to the host.
Source descriptors remain pinned across mount replacement. Old instances that
do not supply the expected shared layer are refused rather than falling back.

Policies live in the host-owned container policy's `folder-rules` file; data
live in the container data's `folder-layers/<identity>/{upper,work}`. Identity
files prevent a hash collision from silently sharing two folders' layers.
Folders may be chosen in the built-in browser, including hidden folders, or by
an exact absolute/`~/` path. There is no grant of the whole `.config` tree:
a specific safe application folder such as `~/.config/my-app` can be selected.
Host execution paths and Cellward state are excluded, including symlink aliases
and installations using nondefault directories. Nix path grants cannot be
silently overridden. A missing source or failed rule mount stops the launch.

Rules are persistent and container-wide, not per-program or launch-only.
A new read-only/real rule in a private home can apply to subsequent launches.
With a layer HOME, new sources must first be pinned by a restarted holder.
Changing the mode of an already pinned view or adding an overlay view also
requires stopping and restarting the instance so its holder prepares that
view; it cannot silently degrade to direct host writes. Already-running programs retain their
mounts and open descriptors; stop the container to revoke those too. Removing a
rule does not erase layer data, copies, or files already written to the host.
Whole-home merge is not a merge of individual folder layers. An overlay is not
a snapshot or a live synchronization protocol for concurrently modified host
files; those semantics need a separate design.

CLI: `cellward container folder NAME ro|rw|overlay|inherit PATH`.
The container panel can edit/remove existing rules; the launch Files page also
adds rules. Changing the base home requires stopping its programs and respects
Nix ownership. A real-home conversion requires removing explicit folder rules.

## Full hiding: required next stage, not implemented

The requested Hide mode must return ENOENT for the entry and omit its name from
directory enumeration. An empty/read-only bind mount does NOT satisfy this, and
is deliberately not exposed as Hide. A simple overlay whiteout is insufficient
for an otherwise read/write real parent: it changes where sibling writes go.
A filtered filesystem view must preserve sibling semantics.

Acceptance requirements:

- Enumeration, lookup/open/O_PATH/stat/statx/readlink and recursive traversal
  agree; guessed hidden paths also return ENOENT.
- Directory size, link count, inode/device identity and timestamps reflect the
  visible view. Hidden sibling changes must not change observable directory
  metadata or deliver watch events. Hard-link metadata counts visible aliases.
- Recursive sizes count visible data. Filesystem capacity/free-space requires a
  defined per-view quota/accounting model; host disk usage must not be mistaken
  for visible data size, nor replaced by fabricated writable capacity.
- Symlink aliases, rename/link operations, file handles, FD passing, inherited
  descriptors and races cannot bypass the view. Rules cannot be read back from
  an app-visible policy file to discover hidden names.
- `/proc` already uses the container's PID namespace (checked by doctor).
  Old instances without their own PID namespace are now refused at entry.
  Nevertheless own mountinfo/mounts, helper command lines/environments/FDs and
  filesystem source names must be audited so they do not publish hidden names
  or underlying layer paths. This is separate from hiding host processes.
- Tests must compare two host trees differing only in hidden entries, across
  enumeration, direct lookups, metadata, watches and allowed sibling writes.
  Test native and X11 apps, private/layer homes, nested overrides and restart.

This is confidentiality of the filesystem view, not a guarantee that arbitrary
code cannot detect a container. Kernel/filesystem behavior, timing, host resource
pressure and names mentioned inside explicitly shared file contents remain
outside an absolute indistinguishability promise.

## Reproducing the holder lifecycle test

`nix-build tests/vm-window.nix -A test --arg foldersOnly true` runs the
private/overlay-home scenarios without the graphical scenarios. It checks
concurrent visibility, host-visible Real writes, private nested overlays,
read-only denial and persistence after stopping/restarting the instance.
`tests/run-folder-shared-smoke.py` provides the faster user/mount-namespace
check and independently inspects the original host directories afterward.

## File access overview

The settings panel has a separate Files tab (`vpn-zone-window panel --tab files`).
It lists every loaded persistent container, its base home view, explicit legacy
real-directory grants with Nix/local provenance, nested folder rules, and policy
read failures. It shows configured policy, not an audit of live mounts. Existing
container actions remain on Containers; the overview is read-only. Unknown
provenance from an older core stays unknown. Nested rules are local policy.
The tab bar wraps on narrow windows instead of forcing new tabs offscreen.

The full-hide metadata requirement includes file sizes where files are exposed
through a transformed view, directory sizes, allocated blocks, visible link
counts, inode/device identifiers, timestamps, xattrs and filesystem/watch events.
For an ordinary fully visible file, report its actual logical size; do not
fabricate sizes that disagree with readable data. For a hidden file, metadata
lookup must fail with ENOENT. For a filtered parent, derive metadata from the
visible view and define stable inode/timestamp semantics. Host statfs capacity
is not a directory size and needs a separate quota/accounting contract.
These are acceptance requirements, not features of the current mount rules.
