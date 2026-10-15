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

## The history (in progress)

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
  Ctrl+V quotes the next key in a terminal); «Перенести в…» moves a copy to
  another container's history, confirmed.

### Planned: typing and secrets

- **Typing.** For fields that refuse a paste: the proxy types the entry into
  the program's connection with a delay set in ms — not a compositor's
  virtual keyboard, so nothing typed reaches another program whatever the
  focus does. The target is chosen on the window itself: it dims under the
  proxy's overlay, the person clicks the field, the proxy passes that click
  to the program and keeps its keyboard focus until the typing ends.
  Characters missing from the keymap: a keymap of that connection for the
  typing.
- **Secrets.** An entry marked a secret leaves the history for its
  container's secrets: hidden preview, typing only, never in the
  selection. A later copy of the same contents (keyed hash) is not kept and
  leaves no trace — no count, no gap in numbers — so copying guesses does not
  tell which one is a secret. Nor does it change anything a program sees:
  the selection is left as it is, never cleared or replaced on a match — a
  program copying guesses and pasting them back would see which one
  vanished. The selection is cleared only when the person marks an entry, of
  contents the program had anyway. Nothing in a container reaches the
  daemon's socket. Moving a
  secret to another container: from its menu, confirmed.
