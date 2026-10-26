# The clipboard by container

A program reads its own running container's CLIPBOARD and PRIMARY. Ordinary
copies stay in memory in that instance's private broker scope. They are not
published to the desktop clipboard and cannot be observed by host clipboard
managers such as CopyQ. Another launch in the same instance shares those
selections; another instance does not. Changing the instance's network keeps
its selections; stopping its holder clears both.

The manager's **Copy to** selector explicitly chooses a running instance or
the shared host clipboard. Changing history tabs does not transfer anything.
The history window opened from a frame starts with that exact instance as
the destination. Images use the same transfer path as text. Password copies
require confirmation and carry the secret hint, so they are not recorded
again. Restoring an ordinary history entry also does not create a new copy
event in history.

`cellward-clipboard.service` supplies active selections independently of
`programs.cellward.clipboard.history`. The optional `cellward-clip.service`
records private selections directly from scoped broker endpoints; it does
not mirror them through the desktop. The controller authenticates host peers
by credentials, a live peer pidfd and matching user/pid/mount namespaces.
Confined proxies receive only an already-bound data socket and change eventfd,
not the registration socket. Broker failure clears offers and never enables
the host clipboard as a fallback. A private launch requires its proxy.

**Upgrade:** already-running programs retain their old proxies. Restart them
through the updated launcher to get private active selections. History paste
refuses an unverified isolated target rather than exporting to the host.
Unconfined programs continue to use the desktop clipboard.

## Legacy proxies (programs started before this update)

The Wayland proxy of each launch (`rust/src/clip.rs`, `wl_frame.rs`):

- **Marks what its program copies.** A `wl_data_source` and a primary
  selection source get one more type, `application/x-cellward-clip-<secret>`:
  the secret of the launch's instance (`$XDG_RUNTIME_DIR/vpn-zones/clip/`,
  made at its first launch, readable by the user alone). No request for that
  type is answered, a program's own marks are dropped, and no program under a
  proxy sees a mark.
- **Reads the mark of what is offered.** An offer with the instance's mark is
  the program's own; any other is foreign.
- **Lets a foreign offer be read** within two seconds of a paste the person
  made: Ctrl+V, Ctrl+Shift+V, Shift+Insert — by the keyboard's own keymap,
  whatever the layout — or a middle click for the primary selection; and when
  it is dragged onto the program. The offered types stay visible: a program
  knows there is something to paste.
- **Leaves data-control closed.** Unrestricted background access to the host
  clipboard is not offered to containers.

## Reverse X11 copies without keyboard focus

Cellward's private Satellite has an opt-in fallback:
an X11 owner that has never received a Wayland keyboard serial can publish
its CLIPBOARD or PRIMARY to the private instance. Serial zero is consumed
locally, not forwarded to the host compositor. Existing keyboard serials
continue to work. Reinstalling the same local source must not cancel it; source
destruction/cancellation invalidates its offers.

`tests/clipboard-reverse-smoke.py` verifies the reverse path on a private
headless sway, with and without a frame. An unmapped Xlib owner replaces
synthetic text and valid PNG three times while a native terminal keeps
focus. A regular Wayland data-device reader checks the exact bytes by hash;
a late reader receives the current offer too. Clearing the X11 selection
and killing an active owner leave no stale payload. A foreign replacement
remains unreadable in the background and becomes readable after Ctrl+V.
A trusted data-control observer of the private compositor and a separate
confined launch confirm that the local copy reaches neither of them. The
actual desktop clipboard is never accessed. These runs peaked at 375 and
378 MiB sampled process-group RSS; forward-paste regressions also passed
with the patched Satellite (300 MiB).

This is not a cross-launch instance broker and does not solve global CopyQ
capture of ordinary focused copies. PRIMARY is unchanged. No actual Codex
session or complete desktop VM was used for these graphical regressions.
On 2026-10-25 the offline, single-job/no-debug/no-incremental core build
completed with 1057 MiB sampled process-group peak RSS. The test binary
compiled at 1410 MiB; the full suite passed (1028 tests, 5 ignored), with
115 MiB during execution. Patched Satellite compiled after selecting native
64-bit XCB (443 MiB for the final compile/link step). Its initial dependency
build peaked at 699 MiB before a wrong-architecture link failure.
The per-process limits and watchdog are in `tests/run-memory-guard.py`;
the preferable hard aggregate cgroup runner is `tests/run-limited.py`, but
the current container cannot start user-systemd services. Early attempts
with smaller per-process limits aborted on allocation rather than removing
the limits. The windowless reverse path is verified, not full active-buffer
isolation between instances.

## X11 CLI paste in a native Wayland terminal

The private broker supplies both CLIPBOARD and PRIMARY to a launch's
Xwayland Satellite, including windowless X11 readers in a different launch
of the same instance. Large text and PNG transfers include X11 INCR.
It does not expose host data-control or the host X server.
`tests/private-clipboard-smoke.py --satellite … --x11 …` checks this direction;
`clipboard-reverse-smoke.py --private-broker … [--primary]` checks X11 copies
in the other direction. The earlier legacy relay diagnosis remains in
[the bridge diagnosis](CLIPBOARD-BRIDGE-DIAGNOSIS.md).

## Boundaries

- A paste gesture alone does not import a foreign selection. Transfer it
  explicitly with the host manager first.
- Host applications can read the shared desktop selection. Private instance
  copies are not published there. The host user/administrator remains trusted.

## The host manager

Independent active selections are enabled by default for new isolated
launches. See [the broker implementation and validation](PRIVATE-CLIPBOARD-BROKER.md).

With `clipboard.history = true`, the recorder also owns one host tray icon.
Its click opens `vpn-zone-window clip --manager`: the host and each history
that has been created appear as tabs. The manager can browse and explicitly
**copy** an entry into another history; switching tabs or copying between
histories does not set an active selection. The separate **Copy to selected
clipboard** action replaces the chosen live destination. The source history
entry remains where it was.
The frame-opened window stays scoped to its own launch and offers paste only
there. The tray opens one window at a time; closing it does not stop the
recorder, and the next click reopens it. Empty containers with no history yet
do not appear until they copy something.
Each buffer has **History**, **Favourites**, and **Passwords** tabs. "☆ Add to favourites"
stores an encrypted copy below that buffer's hidden `.favorites` directory;
deleting the original history entry does not delete the favourite. Removing
the favourite leaves the original alone. From a launch's frame, a favourite
can be pasted into that launch by the same explicit action as a history
entry. Opening either tab never sets a Wayland selection.
Marking a text clip as a password confirms its removal from ordinary history
and saves it encrypted under that buffer's `.secrets` directory with a label.
Matching text copies in this buffer's history and favourites are also
removed, including copies with other text MIME types and HTML. Other buffers
are untouched. Deletion is logical; old encrypted records leave the disk
when their segments are merged. This is neither secure media erasure nor
clearing the source application's clipboard.
The list hides its contents. Explicit paste from a launch, or confirmed copy
from the host manager, uses the selected private or host selection. Character
typing is a separate action that does not change a clipboard. Text search and ordinary cross-buffer moves of
passwords are disabled.
"Edit…" changes the label and optionally the password without revealing the
current contents. An empty new-password field keeps the previous text.
Copy/paste timestamps are preserved, and matching ordinary copies of the
new password are removed from this buffer as well.
"Transfer password…" requires a destination and separate confirmation. The
entry is durably saved in the destination's encrypted password shelf before
the source is deleted; matching ordinary destination copies are removed.
The current clipboard stays unchanged. If the password already exists there,
its destination label is kept. A failure between saving and deletion can
leave both copies, rather than deleting the only durable password.
Copying an already-marked password in the same buffer is omitted from normal
history even when its text MIME representations change. Neither the current
selection nor counts or entry ids are changed by this match. An explicit
clipboard copy also offers `x-kde-passwordManagerHint` for other managers
which respect it.

The shared host clipboard remains readable by unproxied host programs.
Exporting a history entry to **Host** therefore exposes it to those programs;
copying to an instance does not. Ordinary container copies remain private
even when a host clipboard manager is running. No entry is silently
transferred between histories or active scopes. Already-running legacy
proxies must be restarted before relying on the new boundary.

## The history

### Storage and the container boundary

The host daemon stores history in
`$HOME/.local/state/vpn-zones/.clipboard/`:

- `key` — the common master key, mode 0600;
- `<container>/` and `host/` — encrypted ordinary histories;
- `.favorites/<container>/` — encrypted favourites;
- `.secrets/<container>/` — encrypted password shelves.

The store's top-level directory is 0700. More importantly, the **whole
`vpn-zones` state directory is covered by the container's mount policy**;
the allowlist does not bind `.clipboard` back. This applies to real-home
containers too, not just private homes. Sharing the host uid makes 0600
alone insufficient. The history's host socket remains
`$XDG_RUNTIME_DIR/cellward-clip.sock`; it must not be mounted into containers.
An unconfined host program is trusted and can still read this user's files.

Before this change, history and its key lived together in
`$XDG_STATE_HOME/cellward-clip` (default `~/.local/state/cellward-clip`). A
real-home container could read both: encrypted-at-rest did **not** prevent
cross-container history access in that mode. No claim is made that anybody
actually read them.

After updating, stop the old daemon and start the new one (normally the
user service restart does this). The daemon moves the **entire** old directory
to the protected location using an atomic no-replace rename; it does not
copy, merge, erase, or regenerate the key. It refuses to start if both stores
exist, if paths are unsafe, or if a cross-filesystem rename would be required.
Custom XDG state locations are migration sources only: a new arbitrary path
would bypass the fixed container mount protection. Check the daemon's journal
if migration fails. The running old binary does not gain protection merely
because source code was updated.
Restart affected containers as well to close any descriptors opened before
migration. Moving the store cannot revoke previously opened files or erase
copies already made elsewhere.

The migration and locking have library tests; the actual keeper cover is
tested by `zone::tests::clipboard_store_is_hidden_by_the_real_state_mount_policy`
in a private user/mount namespace, using synthetic data. This is not a full VM
or a test of every explicit file grant. User-created backups or copies outside
the protected state are not covered automatically.

The store and search (`clip/`, crate `clipstore`; its format, its measurements
and what its index leaks are in its `lib.rs`) and the recorder are built:
`programs.cellward.clipboard.history = true` runs `cellward-clip daemon`, the
only holder of the key and the histories; `cellward-clip histories` and
`cellward-clip list <history>` ask it on its socket. A password manager's copy
(`x-kde-passwordManagerHint`) and a throwaway container's are not kept. The
window: `vpn-zone-window clip --history <h> [--launch <pid>]` — it asks the
daemon on the same socket, holds no key, and pastes nothing itself: Enter
prints `paste⇥<history>⇥<id>` for the command that opened it. A PNG is drawn
as a thumbnail `clipboard.window.imageLines` of text high (3), decoded by the
`png` crate alone within limits on its size and memory — what a container
copied is untrusted on the host; other images are named. A text shows
`clipboard.window.textLines` (3) of the ten lines the recorder keeps as its
preview. Opened from the frame's ≡ («Вставить из истории буфера…») or the
window menu.

A clipboard manager of cellward's own, by container: each container's copies
in a history of its own, the host's in one of its own; a copy goes to another
container only when the person moves it there in the window.

- **What records.** One daemon on the host, `cellward clipd`, watching the
  compositor's selection through `data-control` (still closed to containers).
  The mark on what a launch copied names its instance, so its container; an
  unmarked selection is the host's.
- **What is kept.** Every copy: its types and contents (text, images, files'
  URIs), when it was copied, and every time it was pasted through the window.
  No limit but the disk's.
- **Encrypted at rest.** Contents with a key of the user's (a file of the
  state directory, 0600; a TPM-sealed one next). The search index holds no
  plain text: its terms are keyed hashes of trigrams.
- **Search.** Immutable segments, memory-mapped (`memmap2`), each with an FST
  from hashed trigram to its entries; new copies in a small segment merged
  into larger ones. A query: words, a pattern built from blocks (text, digit,
  number in a range, one of, start and end of line, word boundary — said in
  words and tried live), a type, a container, and dates — copied or pasted on
  a day, at an hour, around a date.
- **The window.** Opened from the frame (📋) or a key, on the container of the
  window it belongs to: the history as a messenger shows its messages, newest
  at the bottom, images inline, a date between days; Enter pastes into the
  program (the daemon sets both selections with a mark of its own, which it
  does not keep again; the launch's proxy presses Shift+Insert in that
  program's connection once the program has the selection and the focus —
  Ctrl+V quotes the next key in a terminal); «Скопировать в…» copies an entry
  to another container's history after an explicit target choice.

## Character input

In the tray manager or a frame's history window, enable **Character input**
and choose **Select input point**. The manager closes its window temporarily;
Cellward windows become white. Click the intended field. The manager returns
with its previous tab; select a text or password and choose **Type**. A frame
window restricts targets to its launch; the host manager can explicitly pick
another container's window.

The proxy retains the target window and local coordinates, sends a left
click, then key presses and releases only into that launch's connection.
Changing compositor focus cannot redirect the events to another application.
No clipboard selection is set. The original keymap and modifiers are restored
on completion or cancellation. The Stop button or Escape in the manager
cancels input; Escape during target selection removes the white overlay.
Closing or resizing the window invalidates the target. A point can be reused
for other entries for five minutes; choosing another replaces it.

**Unicode** uses a temporary keymap on this connection for non-Latin text and
emoji. **Physical keys (US)** sends ordinary evdev codes and needs a US layout
in the target. Newlines become Return and tabs become Tab. Initial delay,
inter-character delay and key-hold time are configurable in milliseconds and
saved in `$XDG_CONFIG_HOME/cellward/typing.conf` (normally
`~/.config/cellward/typing.conf`).

Only updated launches using the Cellward Wayland proxy can be selected;
restart existing applications after upgrading. Unproxied host windows are not
targets. Each operation allows 32 KiB / 8192 characters and, in Unicode mode,
232 distinct characters. Other control characters are refused.

### Further work

- **stillconf.** Add a separate clipboard page with a control for
  `programs.cellward.clipboard.history = true`; keep the default unchanged.
- A compositor-level separation of host and container selections; history
  tabs alone cannot provide that isolation.

### Client readiness and Qt startup

A newly registered Wayland data device receives no synthetic selection until
its client is ready. A normal compositor selection/focus event establishes
that boundary. Cellward consumes that event as readiness only: host data is
never imported. Windowless readers, including the bundled Xwayland Satellite,
explicitly signal readiness with `application/x-cellward-private-ready` after
installing their handlers. This control MIME is never stored as clipboard data.

This fixes AyuGram/Qt crashing during platform initialization: an immediate
`selection(nil)` could reach Qt before its platform integration existed. The
regression test starts the installed AyuGram on a private headless compositor,
with empty and populated private buffers, and revokes the broker afterwards.
Both CLIPBOARD and PRIMARY remain scoped to the same container instance.
