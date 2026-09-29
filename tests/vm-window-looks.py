"""tests/vm-window.nix, continued: the frame's looks (rust/src/wl_title.rs,
`Look`; docs/WINDOW-FRAME.md §8, «Вид рамки»), on a real compositor: the
soft style next to the full one, round corners inside the frame, the tag
instead of a frame, and each look of the buttons. Each is a screenshot in
the test's output (CI uploads them), and its pixels are checked.

Executed by the main test script with exec(), in its globals: machine,
alice, display, swaysock, find, view, shot, settled, framed, border, width,
title; POINTER, the command of tests/vm-pointer.py. The pixel checks before
this file are of the `full` style (the main script sets it); this one sets
what each subtest shows, and puts the defaults back at the end. A look is
every open window's at once (step 6 of docs/PERMISSIONS.md §11.15): the
window opened before a change takes it on the fly.
"""

fifo = "/tmp/vm-looks-pointer"

# The soft tones of the zone's #ff00ff (wl_title::soft_inner, soft_outer:
# its hue kept, 62 % and 45 % of its saturation, 94 % and 80 % of its
# brightness) — the numbers its unit test pins.
soft_inner = (240, 91, 240)
soft_outer = (204, 112, 204)
# Close under the pointer: red in every look (the owner, 2026-09-27).
close_red = {
    "cellward": (0xE0, 0x1B, 0x24),
    "gnome": (0xE0, 0x1B, 0x24),
    "kde": (0xDA, 0x44, 0x53),
    "macos": (0xFF, 0x5F, 0x57),
    "windows": (0xC4, 0x2B, 0x1C),
}


def aim(*words):
    alice(f"echo {' '.join(str(w) for w in words)} > {fifo}")
    machine.sleep(0.4)


def near(a, b, slack=3):
    return a is not None and all(abs(p - q) <= slack for p, q in zip(a, b))


def node(app_id):
    return find(json.loads(alice(f"SWAYSOCK={swaysock} swaymsg -t get_tree -r")), app_id)


def listed(app_id):
    return (
        f"su -l alice -c 'SWAYSOCK={swaysock} swaymsg -t get_tree' "
        f"| grep -q '\"app_id\": *\"{app_id}\"'"
    )


def launch(app_id, x, y, w=560, h=360):
    """foot in the zone, floating at (x, y), w × h: its frame in the look
    the settings say now."""
    alice(
        f"systemd-run --user --unit=vm-{app_id} --setenv=WAYLAND_DISPLAY={display} "
        f"cellward run offline -- foot --app-id {app_id}"
    )
    machine.wait_until_succeeds(listed(app_id), timeout=60)
    alice(
        f"SWAYSOCK={swaysock} swaymsg '[app_id={app_id}] floating enable, "
        f"resize set {w} {h}, move position {x} {y}'"
    )
    machine.sleep(2)


def stop(app_id):
    alice(f"systemctl --user stop vm-{app_id} || true")
    machine.wait_until_fails(listed(app_id), timeout=30)


def drag(fx, fy, tx, ty):
    aim("move", fx, fy)
    aim("press")
    machine.sleep(1)
    aim("move", tx, ty)
    machine.sleep(1)
    aim("release")
    machine.sleep(1)


output = json.loads(alice(f"SWAYSOCK={swaysock} swaymsg -t get_outputs -r"))[0]["rect"]
alice(
    f"systemd-run --user --unit=vmpointer-looks --setenv=WAYLAND_DISPLAY={display} "
    f"{POINTER} {fifo} {output['width']} {output['height']}"
)
machine.wait_until_succeeds(
    f"su -l alice -c 'SWAYSOCK={swaysock} swaymsg -t get_inputs' | grep -q '\"type\": *\"pointer\"'",
    timeout=30,
)
machine.wait_until_succeeds(f"test -p {fifo}", timeout=30)
aim("move", 5, 5)

def soft(at, x, y, w, h):
    """The soft style on the window at (x, y, w, h): two tones across the
    border, the title strip the inner one with the text on it, foot's
    content inside."""
    # Two tones across the border's width of 6, three pixels each: the
    # outer one darker, the inner one the title's; on every side.
    middle = y + h // 2
    for d in range(3):
        for got, want, where in [
            (at(x + d, middle), soft_outer, "left, outside"),
            (at(x + 3 + d, middle), soft_inner, "left, inside"),
            (at(x + w - 1 - d, middle), soft_outer, "right, outside"),
            (at(x + w - 4 - d, middle), soft_inner, "right, inside"),
            (at(x + w // 2, y + d), soft_outer, "top, outside"),
            (at(x + w // 2, y + 3 + d), soft_inner, "top, inside"),
            (at(x + w // 2, y + h - 1 - d), soft_outer, "bottom, outside"),
            (at(x + w // 2, y + h - 4 - d), soft_inner, "bottom, inside"),
        ]:
            assert near(got, want), (where, d, got, want)
    # The corners where the rings meet: outside the outer tone, inside the
    # inner one — on the diagonal.
    assert near(at(x, y), soft_outer), at(x, y)
    assert near(at(x + 4, y + 4), soft_inner), at(x + 4, y + 4)
    assert near(at(x + 1, y + 4), soft_outer), at(x + 1, y + 4)
    # The title strip is the inner tone, 20 high, the text on it; foot's
    # content right under it and inside the border — no zone colour there.
    for r in (y + width, y + width + title - 1):
        assert near(at(x + w // 2, r), soft_inner), (r, at(x + w // 2, r))
    text = [
        (c, r)
        for c in range(x + width, x + w // 2)
        for r in range(y + width, y + width + title)
        if not near(at(c, r), soft_inner, 8)
    ]
    assert len(text) > 100, f"no text on the soft title: {len(text)}"
    for c, r in [(x + width + 2, middle), (x + w // 2, y + width + title + 2)]:
        assert not near(at(c, r), soft_inner, 30), ("the frame inside", c, r, at(c, r))
    assert at(x + 1, middle) != border and at(x + w // 2, y + width + 1) != border


with subtest("looks: the full style, and the soft one on the fly"):
    # `full` is still the local setting of the checks before.
    launch("look-full", 40, 60)
    aim("move", 5, 5)
    machine.sleep(1)
    at = shot("frame-full")
    x, y, w, h = view("look-full")
    framed(at, x, y, w, h, top=width + title)
    alice("cellward frame style soft")
    out = alice("cellward status --json")
    assert '"frame_style":{"value":"soft","source":"local"}' in out, out
    # The open window takes it; one opened now has it from the start.
    launch("look-soft", 660, 60)
    aim("move", 5, 5)

    def both_soft(at):
        for app in ("look-full", "look-soft"):
            soft(at, *view(app))

    settled("frame-full-soft", both_soft)
    stop("look-full")
    stop("look-soft")

with subtest("looks: round corners inside the frame"):
    alice("cellward frame radius 12")
    out = alice("cellward status --json")
    assert '"frame_radius":{"value":12,"source":"local"}' in out, out
    launch("look-round", 100, 100)
    aim("move", 5, 5)
    machine.sleep(1)
    at = shot("frame-radius")
    x, y, w, h = view("look-round")
    # The program's content: inside the border, under the title.
    cx, cy = x + width, y + width + title
    cw, ch = w - 2 * width, h - 2 * width - title
    for (px, py), (dx, dy) in [
        ((cx, cy), (1, 1)),
        ((cx + cw - 1, cy), (-1, 1)),
        ((cx, cy + ch - 1), (1, -1)),
        ((cx + cw - 1, cy + ch - 1), (-1, -1)),
    ]:
        # The content's very corner is cut off, the frame's colour; on the
        # diagonal, past the curve, the content is foot's again.
        for k in (0, 1):
            got = at(px + k * dx, py + k * dy)
            assert near(got, soft_inner), ("cut off", px, py, k, got)
        inside = at(px + 8 * dx, py + 8 * dy)
        assert not near(inside, soft_inner, 30), ("not round", px, py, inside)
        # Along the edges beyond the radius, foot's.
        along = at(px + 16 * dx, py)
        assert not near(along, soft_inner, 30), ("the corner too long", px, py, along)
    # Square again on the fly: the content's very corners are foot's.
    alice("cellward frame radius default")

    def square(at):
        x, y, w, h = view("look-round")
        cx, cy = x + width, y + width + title
        cw, ch = w - 2 * width, h - 2 * width - title
        for px, py in [(cx, cy), (cx + cw - 1, cy), (cx, cy + ch - 1), (cx + cw - 1, cy + ch - 1)]:
            got = at(px, py)
            assert not near(got, soft_inner, 30), ("still round", px, py, got)

    settled("frame-radius-square", square)
    stop("look-round")

with subtest("looks: the tag instead of a frame; beside it a press is not the frame's"):
    alice("cellward frame style tag")
    launch("look-tag", 200, 200)
    aim("move", 5, 5)
    machine.sleep(1)
    at = shot("frame-tag")
    x, y, w, h = view("look-tag")
    row = y + title // 2 + 2
    # No border: foot's content from the window's edges, under the row.
    for c, r in [(x + 1, y + h // 2), (x + w - 2, y + h // 2), (x + w // 2, y + h - 2)]:
        assert at(c, r) != border, ("a border", c, r)
    # The tag at the row's left end, in the zone's colour, the top left
    # corner round (clear), the bottom one square; narrower than the row.
    ends = [c for c in range(x, x + w) if at(c, row) == border]
    assert ends and ends[0] == x, ends[:5]
    tag_right = max(ends)
    assert 100 < tag_right - x < w // 2, (x, tag_right, w)
    assert at(x, y) != border, "the tag's corner not round"
    assert at(x, y + title - 1) == border
    # The text on it.
    inked = [c for c in range(x, tag_right) if at(c, row) != border]
    assert len(inked) > 10, inked
    # Beside the tag: clear, not the zone's colour.
    for c in (tag_right + 20, x + w - 40):
        assert at(c, row) != border, ("the row not clear", c)
    # A press beside the tag is not the frame's: nothing moves.
    before = node("look-tag")["rect"]
    drag(x + w - 40, row, x + w - 120, row + 60)
    after = node("look-tag")["rect"]
    assert (after["x"], after["y"]) == (before["x"], before["y"]), (before, after)
    # On the tag: moved, as by a title strip.
    drag(x + 4, row, x + 64, row + 40)
    moved = node("look-tag")["rect"]
    shift = (moved["x"] - before["x"], moved["y"] - before["y"])
    assert abs(shift[0] - 60) <= 1 and abs(shift[1] - 40) <= 1, (before, moved)
    # Its × (cellward's: the last of the row, before the tag's round end),
    # red under the pointer; clicked, foot closes.
    x, y, w, h = view("look-tag")
    aim("move", 5, 5)
    machine.sleep(1)
    at = shot("frame-tag-moved")
    tag_right = max(c for c in range(x, x + w) if at(c, y + title // 2 + 2) == border)
    close = (tag_right + 1 - 6 - 24, tag_right + 1 - 6)
    aim("move", (close[0] + close[1]) // 2, y + title // 2)
    machine.sleep(1)
    at = shot("frame-tag-close-lit")
    assert near(at(close[0] + 2, y + 2), close_red["cellward"]), at(close[0] + 2, y + 2)
    aim("press")
    aim("release")
    machine.wait_until_fails(listed("look-tag"), timeout=30)
    alice("cellward frame style full")

# Each look of the buttons (the owner, 2026-09-27): where the row is, close
# red under the pointer, and (macOS, Windows) that × still closes.
buttons_of = {
    # look: its end, a button's width, the margin at the end, a disc's
    # width (none: the whole cell)
    "gnome": ("right", 24, 4, 16),
    "kde": ("right", 24, 4, 18),
    "macos": ("left", 20, 4, 12),
    "windows": ("right", 32, 0, None),
}
for name, (end, cell, margin, disc) in buttons_of.items():
    with subtest(f"looks: the buttons of {name}"):
        alice(f"cellward frame buttons {name}")
        launch(f"look-{name}", 100, 100, 640, 400)
        aim("move", 5, 5)
        machine.sleep(1)
        x, y, w, h = view(f"look-{name}")
        left, right, top = x + width, x + w - width, y + width
        if end == "right":
            row = (right - margin - 3 * cell, right - margin)
            close = (row[1] - cell, row[1])
        else:
            row = (left + margin, left + margin + 3 * cell)
            close = (row[0], row[0] + cell)
        red = close_red[name]

        def count(at, cells, want, slack=2):
            return sum(
                1
                for c in range(*cells)
                for r in range(top, top + title)
                if near(at(c, r), want, slack)
            )

        def marks(at, cells):
            """Pixels of `cells` that are not the zone's colour: buttons."""
            return sum(1 for c in range(*cells) for r in range(top, top + title) if at(c, r) != border)

        def inked(at, cells):
            """Pixels of `cells` darker in red than the lights and the zone's
            colour ever are (all 0xFF or near it): a glyph's, its ink
            near-black."""
            return sum(1 for c in range(*cells) for r in range(top, top + title) if at(c, r)[0] < 200)

        at = shot(f"frame-buttons-{name}")
        framed(at, x, y, w, h, top=width + title)
        # The row where the look puts it, and nothing of it at the other end.
        assert marks(at, row) > 20, (name, "no buttons at their end")
        if end == "right":
            # Between the text and the row, the strip alone.
            assert at(row[0] - 3, top + title // 2) == border
            assert marks(at, (right - margin, right)) == 0, "past the row"
        else:
            assert marks(at, (right - 3 * 24, right)) == 0, "buttons at the right"
            # The traffic lights at rest: red, yellow, green discs, no glyph.
            for k, colour in enumerate([red, (0xFE, 0xBC, 0x2E), (0x28, 0xC8, 0x40)]):
                cells = (row[0] + k * cell, row[0] + (k + 1) * cell)
                n = count(at, cells, colour)
                assert n > 40, (name, k, n)
            dark = inked(at, close)
            assert dark == 0, ("a glyph at rest", dark)
        if end == "right":
            assert count(at, close, red) == 0, "close red at rest"
        # Under the pointer: close red — most of its disc, or of its cell.
        aim("move", (close[0] + close[1]) // 2, top + title // 2)
        machine.sleep(1)
        at = shot(f"frame-buttons-{name}-close-lit")
        least = int(3.14 * (disc / 2) ** 2 * 0.4) if disc else cell * title // 2
        n = count(at, close, red)
        assert n >= least, (name, "close not red under the pointer", n, least)
        if end == "left":
            # The glyph shows now, on this light and the others.
            dark = inked(at, close)
            assert dark > 3, ("no glyph under the pointer", dark)
        if name in ("macos", "windows"):
            # Hit where the look draws it: × closes the program.
            aim("press")
            aim("release")
            machine.wait_until_fails(listed(f"look-{name}"), timeout=30)
        else:
            aim("move", 5, 5)
            stop(f"look-{name}")

alice("cellward frame buttons default")
alice("cellward frame style default")
out = alice("cellward status --json")
assert '"frame_style":{"value":"soft","source":"default"}' in out, out
assert '"frame_buttons":{"value":"cellward","source":"default"}' in out, out
alice("systemctl --user stop vmpointer-looks")
