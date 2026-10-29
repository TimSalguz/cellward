# Clipboard and screenshot UX: next steps

This plan separates implemented changes from follow-up work. The development
branch contains resilient capture, live history, full PNG inspection, confirmed
cross-container paste, private screenshot controls, and the container-specific
launch warning fix. Installing the branch and checking the user's actual
Firefox/Ayugram sessions remain separate steps; isolated tests do not establish
that the installed desktop is fixed.

## Primary workflow: paste into the application

The agreed cross-container path is ordinary Ctrl+C in the source, Ctrl+V in the
destination, preview, Enter. Confirmation completes insertion into the original
target window. History tabs, Copy to and a second Copy action are unnecessary
for this path. Repeated pastes of that clip within the destination are direct.
Escape cancels the transfer.
The real home across all network zones also counts as one container: pastes
between its network holders require neither a preview nor Enter.

Further interface work, not implemented yet:

- Show an explicit source → destination and text or a large image. For older
  clips, open history directly from this window with the destination already
  selected; highlighting a row does not transfer data, Enter confirms it.
- Show a short waiting state while the latest copy is being read. Explain
  failures by phase: capture, transfer or focus restoration. Never silently
  replace a failed new copy with an older successful one.
- History is an additional path for older clips, not a required intermediary.
  An open history updates automatically, preserving search and selected row.
- Offer explicit confirmed export for unconfined desktop applications. An
  ordinary in-container Ctrl+V must not publish private content to the host.

Do not blame CopyQ/Noctalia without evidence. In the new private path, container
copies are not published to the desktop selection, so a host manager is not a
transfer intermediary. That does not establish the behaviour of older proxies,
already-running applications or the X11 path. Compare those paths with and
without a manager in a separately agreed session.

Short diagnostic messages in the branch distinguish preparation failure,
capture wait timeout, rejected commit, lost target, changed selection and loss
of the metadata channel. Messages occur on failed attempt completion or channel
disconnection, not every poll. No text, URLs, container labels or pixels are
logged.

## Work queue

| Priority | Work | Acceptance |
| --- | --- | --- |
| P0 | Validate the updated runtime with real applications | After an explicitly authorized update and application restart, Firefox context-menu copy and Ctrl+C, Ayugram text, images, and repeated cross-container paste work. An already open history updates; the desktop/Noctalia selection stays unchanged. |
| P1 | Image preview before cross-container paste | Show the actual PNG beside the source/destination, with zoom and pan. Enter confirms the same frozen revision; Escape changes nothing. Secret-marked copies never reveal a preview. Unsupported formats get an honest description, not an unrelated thumbnail. |
| P1 | Private window capture on niri | Use a backend that returns the selected window's pixels without writing the desktop clipboard. Respect protected content and compositor capture policy. Missing geometry, occlusion and other windows must not silently produce the wrong image. Keep explicit frozen-region selection until such a backend is verified. |
| P1 | Clearer transfer identity | Show container and application; add network when useful. Equal history names must not make two containers look identical. Use trusted launch identity, sanitize application-supplied labels and avoid exposing internal scope tokens. |
| P1 | Diagnose capture failures and frame freezes | Opt-in diagnostics record request timing, completion counts and focus/frame transitions. Never record clipboard contents, URLs, passwords or screenshot pixels. A failed copy should be distinguishable from a successfully captured previous selection. |
| P2 | More convenient history navigation | Explore keyboard-first selection, temporary pinning, and preview beside the selected row. Preserve search and selection while new clips arrive. Keep secrets out of passive previews and automatic exports. |

The isolated-window capture item also excludes background showing through
desktop opacity: the current output-crop backend cannot provide that guarantee.
Its acceptance test places a contrasting unrelated window behind the target.
Application alpha must be preserved or flattened against an explicit solid
background, not against other desktop content.

## Screenshot inspection: implemented in this iteration

The frozen-region editor supports wheel zoom around the pointer, middle-button
dragging, and `0` to fit the image again. Zoom and pan change only the view.
Selection and PNG encoding continue to use original frozen pixels. The image
cannot be panned completely out of view. Moving/zooming does not transfer data;
Enter remains the explicit copy, under the existing focus guard.

Tests must include a fast drag with batched pointer events, original-pixel crops
after zoom/pan, reset to fit, and unchanged private/desktop selections until
confirmation. Adding an external image service, background OCR, desktop-wide
Ctrl+V interception, or automatic sharing between containers is outside this
iteration.
