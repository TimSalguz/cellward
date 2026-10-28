# Clipboard and screenshot UX: next steps

This plan separates implemented changes from follow-up work. The development
branch contains resilient capture, live history, full PNG inspection, confirmed
cross-container paste, private screenshot controls, and the container-specific
launch warning fix. Installing the branch and checking the user's actual
Firefox/Ayugram sessions remain separate steps; isolated tests do not establish
that the installed desktop is fixed.

## Recommended order

| Priority | Work | Acceptance |
| --- | --- | --- |
| P0 | Validate the updated runtime with real applications | After an explicitly authorized update and application restart, Firefox context-menu copy and Ctrl+C, Ayugram text, images, and repeated cross-container paste work. An already open history updates; the desktop/Noctalia selection stays unchanged. |
| P1 | Image preview before cross-container paste | Show the actual PNG beside the source/destination, with zoom and pan. Enter confirms the same frozen revision; Escape changes nothing. Secret-marked copies never reveal a preview. Unsupported formats get an honest description, not an unrelated thumbnail. |
| P1 | Private window capture on niri | Use a backend that returns the selected window's pixels without writing the desktop clipboard. Respect protected content and compositor capture policy. Missing geometry, occlusion and other windows must not silently produce the wrong image. Keep explicit frozen-region selection until such a backend is verified. |
| P1 | Clearer transfer identity | Show container and application; add network when useful. Equal history names must not make two containers look identical. Use trusted launch identity, sanitize application-supplied labels and avoid exposing internal scope tokens. |
| P1 | Diagnose capture failures and frame freezes | Opt-in diagnostics record request timing, completion counts and focus/frame transitions. Never record clipboard contents, URLs, passwords or screenshot pixels. A failed copy should be distinguishable from a successfully captured previous selection. |
| P2 | More convenient history navigation | Explore keyboard-first selection, temporary pinning, and preview beside the selected row. Preserve search and selection while new clips arrive. Keep secrets out of passive previews and automatic exports. |

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
