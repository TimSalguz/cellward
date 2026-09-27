"""tests/vm-window.nix, continued: the frame's buttons, dragging by the title
and resizing by the border (rust/src/wl_frame.rs; docs/WINDOW-FRAME.md §8,
"Этап 3"), with a pointer on a real compositor.

Executed by the main test script with exec(), in its globals: machine,
alice, display, swaysock, find, view, shot, framed, border, width, title;
POINTER, the command of tests/vm-pointer.py. Headless sway has no input
device, so no pointer: that script holds a virtual one on the seat, and
this one moves and clicks it through a FIFO.
"""

# The look there is (rust/src/wl_title.rs, LOOK): menu, network, close at
# the right end of the title strip, 24 wide each; close red under the
# pointer, the others a shade of the frame's colour — on magenta, whose
# text is near-black, 22 % toward black.
button_w = 24
close_lit = (0xE0, 0x1B, 0x24)
shade_lit = (199, 0, 199)
fifo = "/tmp/vm-pointer"


def pointer(*words):
    alice(f"echo {' '.join(str(w) for w in words)} > {fifo}")
    machine.sleep(0.4)


def click(px, py):
    pointer("move", px, py)
    pointer("press")
    pointer("release")


def node(app_id):
    tree = json.loads(alice(f"SWAYSOCK={swaysock} swaymsg -t get_tree -r"))
    return find(tree, app_id)


def cells(x, y, w):
    """The top left of each button's cell, left to right: the row ends
    where the right border begins, under the top border."""
    right = x + w - width
    return [(right - (3 - i) * button_w, y + width) for i in range(3)]


def glyph(at, cx, cy):
    """How many pixels of a cell are not its own colour (its top-left
    one): the glyph on it."""
    bg = at(cx, cy)
    return sum(
        1 for c in range(cx, cx + button_w) for r in range(cy, cy + title) if at(c, r) != bg
    )


def near(a, b, slack=2):
    return a is not None and all(abs(p - q) <= slack for p, q in zip(a, b))


output = json.loads(alice(f"SWAYSOCK={swaysock} swaymsg -t get_outputs -r"))[0]["rect"]
alice(
    f"systemd-run --user --unit=vmpointer --setenv=WAYLAND_DISPLAY={display} "
    f"{POINTER} {fifo} {output['width']} {output['height']}"
)
machine.wait_until_succeeds(
    f"su -l alice -c 'SWAYSOCK={swaysock} swaymsg -t get_inputs' | grep -q '\"type\": *\"pointer\"'",
    timeout=30,
)
machine.wait_until_succeeds(f"test -p {fifo}", timeout=30)

with subtest("the frame's buttons: at the right end of the title, lit under the pointer"):
    alice(
        f"systemd-run --user --unit=vmbtn --setenv=WAYLAND_DISPLAY={display} "
        "cellward run offline -- foot --app-id btn"
    )
    machine.wait_until_succeeds(
        f"su -l alice -c 'SWAYSOCK={swaysock} swaymsg -t get_tree' | grep -q '\"app_id\": *\"btn\"'",
        timeout=60,
    )
    alice(
        f"SWAYSOCK={swaysock} swaymsg '[app_id=btn] floating enable, resize set 640 400, "
        "move position 100 100'"
    )
    # The pointer away from the window: nothing lit.
    pointer("move", 5, 5)
    machine.sleep(2)
    x, y, w, h = view("btn")
    at = shot("frame-buttons")
    framed(at, x, y, w, h, top=width + title)
    menu, network, close = cells(x, y, w)
    for cell in (menu, network, close):
        assert at(*cell) == border, (cell, at(*cell))
        assert glyph(at, *cell) > 8, f"no glyph on the button at {cell}"
    # Between the text and the row, the strip is its colour alone.
    assert at(menu[0] - 3, menu[1] + title // 2) == border

    # Under the pointer: close red; then the menu a shade of the colour,
    # and close back to it.
    pointer("move", close[0] + button_w // 2, close[1] + title // 2)
    machine.sleep(1)
    at = shot("frame-buttons-close-lit")
    assert near(at(*close), close_lit), at(*close)
    assert at(*menu) == border and at(*network) == border
    assert glyph(at, *close) > 8
    pointer("move", menu[0] + button_w // 2, menu[1] + title // 2)
    machine.sleep(1)
    at = shot("frame-buttons-menu-lit")
    assert near(at(*menu), shade_lit), at(*menu)
    assert at(*close) == border, at(*close)

with subtest("the frame's ≡ opens the window menu of that launch"):
    sup = node("btn")["pid"]
    click(menu[0] + button_w // 2, menu[1] + title // 2)
    # The supervisor had systemd --user start it, for its own pid.
    machine.wait_until_succeeds(
        f"journalctl --no-pager | grep -F 'window-menu --pid {sup}'", timeout=30
    )
    machine.wait_until_succeeds("pgrep -x vpn-zone-window", timeout=30)
    unit = alice(f"systemctl --user show -p ExecStart cellward-window-menu-{sup}")
    assert f"window-menu --pid {sup}" in unit and "--restart" not in unit, unit
    machine.sleep(2)
    alice(f"WAYLAND_DISPLAY={display} grim /tmp/frame-buttons-menu.png")
    machine.copy_from_vm("/tmp/frame-buttons-menu.png", "")
    alice(f"WAYLAND_DISPLAY={display} wtype -s 400 -k Escape")
    machine.wait_until_fails("pgrep -x vpn-zone-window", timeout=15)
    # Its unit gone with it: the next menu of the launch may start.
    machine.wait_until_fails(
        f"su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 systemctl --user is-active -q "
        f"cellward-window-menu-{sup}'",
        timeout=30,
    )
    assert node("btn") is not None, "the menu did something"

with subtest("the frame's ⇄ asks for the restart with a network chosen"):
    click(network[0] + button_w // 2, network[1] + title // 2)
    machine.wait_until_succeeds(
        f"journalctl --no-pager | grep -F 'window-menu --pid {sup} --restart'", timeout=30
    )
    # It asks first whether to close the program: not answered — the menu
    # and its question are ended, and the program stays.
    machine.sleep(3)
    alice(f"systemctl --user kill cellward-window-menu-{sup} || true")
    machine.wait_until_fails(
        f"su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 systemctl --user is-active -q "
        f"cellward-window-menu-{sup}'",
        timeout=30,
    )
    assert node("btn") is not None, "restarted without a yes"
    machine.succeed(f"test -e /proc/{sup}")

with subtest("dragging the title moves the window; its border resizes it"):
    x, y, w, h = view("btn")
    before = node("btn")["rect"]
    tx, ty = x + 60, y + width + title // 2
    pointer("move", tx, ty)
    pointer("press")
    machine.sleep(1)
    pointer("move", tx + 120, ty + 60)
    machine.sleep(1)
    pointer("release")
    machine.sleep(1)
    after = node("btn")["rect"]
    moved = (after["x"] - before["x"], after["y"] - before["y"])
    assert abs(moved[0] - 120) <= 1 and abs(moved[1] - 60) <= 1, (before, after)

    # The right border: wider, as far as the pointer went (foot keeps to
    # whole cells, in height too), the left edge where it was.
    x, y, w, h = view("btn")
    ex, ey = x + w - width // 2, y + h // 2
    pointer("move", ex, ey)
    pointer("press")
    machine.sleep(1)
    pointer("move", ex + 80, ey)
    machine.sleep(1)
    pointer("release")
    machine.sleep(2)
    x2, y2, w2, h2 = view("btn")
    assert 40 <= w2 - w <= 100 and abs(h2 - h) <= 24 and x2 == x, ((x, y, w, h), (x2, y2, w2, h2))
    # The corner: both edges.
    cx, cy = x2 + w2 - width // 2, y2 + h2 - width // 2
    pointer("move", cx, cy)
    pointer("press")
    machine.sleep(1)
    pointer("move", cx + 60, cy + 60)
    machine.sleep(1)
    pointer("release")
    machine.sleep(2)
    x3, y3, w3, h3 = view("btn")
    assert w3 - w2 >= 30 and h3 - h2 >= 30, ((x2, y2, w2, h2), (x3, y3, w3, h3))
    # And the frame follows: all round, at the new size.
    pointer("move", 5, 5)
    machine.sleep(1)
    framed(shot("frame-buttons-resized"), x3, y3, w3, h3, top=width + title)

with subtest("the frame's × closes the program, as its own close would"):
    x, y, w, h = view("btn")
    close = cells(x, y, w)[2]
    click(close[0] + button_w // 2, close[1] + title // 2)
    machine.wait_until_fails(
        f"su -l alice -c 'SWAYSOCK={swaysock} swaymsg -t get_tree' | grep -q '\"app_id\": *\"btn\"'",
        timeout=30,
    )
    machine.wait_until_fails(f"test -e /proc/{sup}", timeout=30)
    alice("systemctl --user stop vmpointer")
