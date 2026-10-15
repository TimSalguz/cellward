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

## Next: the history

Encrypted at rest, kept apart per container, opened by a key; no limit on how
much is kept; a search that answers instantly over tens of millions of
entries (an index on disk, read through `mmap`), by date and by a query built
from blocks — text, digits, ranges, starts and ends — with the expression
shown in words and tried live.
