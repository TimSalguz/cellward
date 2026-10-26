# Rounded top edge: unified image

The rounded-frame path draws the top border, its outer and inner corner caps,
the title background, label and buttons into one premultiplied-alpha image.
The old top strip and top corner buffers are not attached underneath it;
there are no text/button child surfaces in this path. This removes the
overlapping backgrounds exposed by compositor opacity. Other frame edges,
menus and permission panels remain separate surfaces.

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
