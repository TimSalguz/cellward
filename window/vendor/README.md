# Vendored crates

`iced_tiny_skia` 0.14.1, as published, with three changes marked `cellward:`:

- `src/layer.rs`: a text's damage is expanded by `TEXT_OVERHANG` (2 px), as a
  quad's is by one: its glyphs' antialiased edges and overhangs reach past its
  layout bounds, and a changed text left them on the screen
  (iced-rs/iced#2665).
- `src/lib.rs`: the damage is rounded outward to whole pixels before it is
  cleared: at a fractional scale an edge pixel partly covered by a glyph was
  not cleared by the unantialiased fill.
- `src/window/compositor.rs`: changing the number or bounds of layers damages
  the whole viewport, because translated primitives can extend beyond their
  layer's previous and current clip rectangles.

Drop it when iced has all three.
