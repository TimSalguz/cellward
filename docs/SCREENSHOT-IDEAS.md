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

For a launch through the current proxy, `▧` reads the selected window's
committed root `wl_surface` directly. The SHM pool and attached `wl_buffer`
stay owned by the proxy; the host editor receives a bounded memfd copy, not a
compositor screenshot. This path needs no focused-window query, output
geometry, crop or screen-capture protocol, and Cellward's own frame is not part
of the source surface. `tests/vm-niri-question.py` checks this path and rejects
frame-coloured pixels in the captured image.

This first direct backend accepts ARGB8888 and XRGB8888 SHM buffers within the
documented size bounds. An unsupported buffer fails closed: it never falls back
to the desktop. The root surface does not include separately owned popups or a
composition of application subsurfaces. Those cases, non-SHM buffers and alpha
presentation remain follow-up work, not claimed support.

The frame menu also toggles root-surface recording. A dedicated agent requests
frames over its own proxy channel at 30 FPS, so an encoder cannot interleave
with screenshots or block the main Wayland channel. Host ffmpeg writes H.264
(yuv420p, veryfast) with no audio to a new `~/Videos/cellward-*.mp4`; existing
files are never overwritten. Stop is cooperative: no new frame is requested and
ffmpeg finalizes the MP4 index. A size change mid-stream and an unsupported
buffer fail without substituting desktop pixels. Recording has the same root
surface, subsurface and non-SHM limitations as a still capture.

For a capture broker, the agent also has a raw-fd mode instead of MP4 encoding.
Each frame has a `CFR1` header (dimensions, stride, format and generation),
followed by tightly packed BGRA rows without stride padding. This is the
broker's internal transport, not a desktop-capture protocol.

A separate frame-menu item publishes the same root surface as the PipeWire node
`cellward_capture`. Its `cellward.capture.id` property holds the compositor-
independent container-scope id, or a unique launch id for a legacy launch
without one. GStreamer receives tightly packed BGRA frames;
`rawvideoparse` assembles complete frames across short pipe reads, and
`pipewiresink` supplies I420 to the consumer. The manifest pins `gst-launch` and
every plugin instead of searching `PATH`. `tests/vm-niri-question.py` selects
this item and receives frames with a real `pipewiresrc`.

`cellward-capture-portal` already implements `org.freedesktop.portal.ScreenCast`
v6: session and Request.Response lifecycles, `pipewire-serial`,
`OpenPipeWireRemote` and `Session.Close`. One active source is accepted directly;
several require `multiple` or an exact `cellward_capture_id`, never an implicit
first container. `pw-dump` output is capped at 4 MiB and both its path and
`gst-launch` are pinned rather than found through `PATH`. The end-to-end test
uses a private `dbus-daemon`, never the system portal. The `--impl` variant
implements the synchronous `org.freedesktop.impl.portal.ScreenCast` API suitable
for activation through xdg-desktop-portal. The source is still started from the
frame first; a `.portal` file and a container picker are the next stages.

Region and hover captures intentionally keep the composited screen view and use
the manifest-pinned `grim`. In particular, niri's native screenshot action is
unsuitable for private copies because it also writes the desktop clipboard.
The desired complete isolated-window mode must additionally capture owned
popups and subsurfaces without the desktop, unrelated windows, Cellward frame
or compositor decorations. Application alpha must be preserved explicitly or
flattened against a chosen solid background, never against desktop pixels.
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
