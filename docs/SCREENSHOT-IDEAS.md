# Private frame screenshots

The frame provides three controls: `▧` (visible window), `⌗` (region) and
`◎` (hover, freeze, then region).
The host helper captures PNG pixels to memory before opening the editor. The
editor selects only from that immutable image; Enter confirms the private copy,
Escape cancels. All modes require confirmation in the trusted host editor:
the confined proxy's request alone must never export screen pixels to an app.

Wheel zooms around the pointer, middle-button dragging pans, and `0` restores
fit. Selection stays in original image coordinates, including after zoom/pan;
the encoded crop is never a resampled view. See the prioritized
[UX follow-up plan](CLIPBOARD-UX.md).

For hover capture only the originating window is shaded. Its shade has an empty
input region, so real pointer motion reaches the application. The proxy consumes
both halves of the first left click, removes the shade and waits for compositor
processing before asking the host to capture. Escape on that window cancels;
the mode also expires. It injects no input into another application.

The selected PNG becomes a new ordinary copy in the originating launch's live
private scope. Its existing history policy applies. No image is written to disk
or to the desktop clipboard, and no screen-capture protocol is granted to the
container. A dead source, failed capture, oversized image, editor cancellation
or broker refusal must preserve the previous selection.

The visible-window path currently has verified geometry only through Sway IPC.
Other compositors use the region editor on a full frozen frame rather than
guessing a window position. In particular, niri's native screenshot action is
unsuitable for private copies because it also writes the desktop clipboard.
The host tools manifest pins `grim`; older manifests without it fail closed.
Niri's clipboard behaviour is documented in its
[screenshot actions](https://github.com/niri-wm/niri/blob/main/docs/wiki/Configuration%3A-Key-Bindings.md#screenshot-screenshot-screen-screenshot-window).

`tests/screenshot-smoke.py` exercises the real frame, capture helper, editor and
broker on an isolated Sway. A synthetic Wayland subsurface tooltip disappears on
pointer leave, so the test checks capture before editor focus, removal of the
shade, consumption of both click halves, exact frozen-image crops, cancellation,
source exit and an unchanged desktop clipboard. Window tests also cover batched
pointer coordinates and confirmation with real focus after the guard interval.

Original requirements and further refinements:

- Freeze a captured frame **before** opening selection UI. Area/window selection
  must crop that immutable frame, not capture a later moment after interaction.
- Offer window-only capture, including a shortcut and optionally a frame button.
- Allow capture of client contents without Cellward's border, buttons or hover
  panel; distinguish client geometry from the decorated window and compositor
  shadows. Respect scale, transforms and multiple outputs.
- Avoid focus changes, hover reveals and shortcut effects changing the captured
  moment. A frame-button press can itself change hover/pressed state: define
  whether the pre-press frame or client-only image is used, rather than promise
  perfect timing without compositor support.
- Keep screenshot destinations explicit: file, the chosen container's active
  clipboard, or host export. Do not broadcast images to every clipboard or
  automatically add sensitive screenshots to history.
- Use the host's authorized capture/portal path; do not grant ordinary container
  applications unrestricted screen capture. Check fullscreen, overview and
  protected-content behaviour. A compositor-level freeze may need niri support;
  a frozen selection overlay alone does not freeze other applications.
