# The clipboard by container

A program reads what its own container copied freely. What was copied
elsewhere — in another container, on the host — it reads only when the
person pastes it.

## How

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
- **Leaves data-control closed.** Reading the clipboard without focus is not
  offered to containers at all.

## Not covered yet

- A paste from a program's own menu of a foreign selection gives nothing. A
  button of the frame that pastes is next.
- A program of the host that is not proxied reads every selection and every
  mark, as before.

## The host manager (in progress)

With `clipboard.history = true`, the recorder also owns one host tray icon.
Its click opens `vpn-zone-window clip --manager`: the host and each history
that has been created appear as tabs. The manager can browse and explicitly
**copy** an entry into another history; switching tabs or copying an entry
does not set the system selection. The source entry remains where it was.
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
from the host manager, still uses the ordinary selection; it is not yet a
protected typing channel. Text search and ordinary cross-buffer moves of
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

The host is not a security boundary. An unproxied host program can read the
compositor's current selection, including one a container just copied;
the tabbed history does not grant it access to the stored histories, but it
cannot make the host's Wayland selection private. No entry is silently
transferred between histories. A true host/container clipboard boundary
would require host applications to use the same proxy or compositor support
for separate selections.

## The history

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
