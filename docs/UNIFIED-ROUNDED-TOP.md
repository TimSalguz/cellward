# Rounded top edge: unified image

The rounded-frame path draws the top border, its outer and inner corner caps,
the title background, label and buttons into one premultiplied-alpha image.
The old top strip and top corner buffers are not attached underneath it;
there are no text/button child surfaces in this path. This removes the
overlapping decoration backgrounds exposed by compositor opacity. Other frame edges,
menus and permission panels remain separate surfaces.

## Remaining compositor-opacity limitation (2026-10-26)

This does **not** flatten the application's contents together with the frame.
In hover mode the unified decoration is still above the application's surface.
Niri applies window-rule opacity to each surface independently, as documented
in [its window rules](https://github.com/niri-wm/niri/wiki/Configuration%3A-Window-Rules).
Consequently application text/background can show through a fully opaque
hover image, while a neighbouring frame area outside the app blends against
the desktop. A visible tone boundary can remain even with a single decoration
image. The soft style's intentionally different border tones are another,
separate source of colour variation.

Reproduced in nested niri at opacity 0.65 with `tests/frame-corners-smoke.py`.
The opacity screenshots are evidence of the remaining limitation, not proof
that all opacity seams are fixed. Real double-clicks in normal always/hover
mode at 1/4 px widths are covered by `--double-click`.

A complete solution must compose the application and decorations as a group
before applying opacity, or avoid covering app content through an explicit
layout choice. Do not silently disable user opacity, repaint the application's
buffer, or introduce a CPU screenshot/copy path into the general proxy,
especially before the planned game/latency checks. Keep this issue open until
there is a tested renderer/compositor integration; additional coloured masks
do not solve it.

Button positions are calculated from the unshortened window width. Radius
clips pixels, not button positions. Extreme radii can therefore clip part of
a button; transparent areas are not clickable. Hover reveals the same whole
rounded top, not an inset rectangular background. Its first two content pixels
remain available to the application's own fullscreen toolbar.

A title click in hover mode keeps the panel available for the double-click
interval plus 100 ms. A compositor move grab can report pointer-leave on the
first click; it must not remove the target of the second. The hold expires via
the proxy's event-loop timer; it does not permanently pin the panel.

Buffers are cached by complete geometry, visibility, button state and scale,
with leases preventing writes over buffers still held by the compositor.
Busy buffers cause a timed retry, never reuse/stretch of another geometry.
The sparse memfd reserves bounded space for two images, not every button
variant at full-window width. Actual pixels are rendered only on demand.
The composite path supports up to 8192 logical pixels of width; larger windows
and font-less launches retain the legacy bounded renderer. Crossing that
limit rebuilds the surface topology. The plain square-frame and tag paths
are unchanged.

Verification covers premultiplied alpha at fractional scales, narrow widths,
busy-cache behaviour, absence of overlapping top surfaces on the wire, and a
double-click after synthetic pointer-leave. The nested-niri smoke checks
1/4 px frames, always/hover modes, menu dismissal without click-through,
the first hover title click, and close-button hit testing at its fixed anchor.
It also captures opacity-0.65 screenshots for visual inspection.
