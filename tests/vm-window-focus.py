"""tests/vm-window.nix, continued: a container's focus policy
(rust/src/wl_focus.rs; docs/WINDOW-FRAME.md §8, «Фокус»), on a real
compositor.

A program in a zone (tests/vm-activate.py) asks for the focus back every
time it loses it, each time with a new token of the one click it had — what
Qt's requestActivate() does, and what took the owner's focus over and over
(Telegram opening an image). sway honours such a token when told to focus on
activation (`focus_on_window_activation focus`): the `allow` subtest shows
it, so what `input` and `notify` hold back is the proxy's doing.

Executed by the main test script with exec(), in its globals: machine,
alice, display, swaysock, find, view; POINTER, the command of
tests/vm-pointer.py; ACTIVATE, the command of tests/vm-activate.py.
"""

fifo = "/tmp/vm-focus-pointer"


def aim(*words):
    alice(f"echo {' '.join(str(w) for w in words)} > {fifo}")
    machine.sleep(0.4)


def focused():
    """The app id of the window sway has focused."""

    def walk(node):
        if node.get("focused") and node.get("app_id"):
            return node["app_id"]
        for child in node.get("nodes", []) + node.get("floating_nodes", []):
            found = walk(child)
            if found:
                return found
        return None

    return walk(json.loads(alice(f"SWAYSOCK={swaysock} swaymsg -t get_tree -r")))


def shown(app_id):
    machine.wait_until_succeeds(
        f"su -l alice -c 'SWAYSOCK={swaysock} swaymsg -t get_tree' | grep -q '\"app_id\": *\"{app_id}\"'",
        timeout=60,
    )


def said(line):
    machine.wait_until_succeeds(f"journalctl --no-pager | grep -qF '{line}'", timeout=30)


def to_other():
    alice(f"SWAYSOCK={swaysock} swaymsg '[app_id=other] focus'")


def wait_focused(app_id, seconds=30):
    for _ in range(seconds * 2):
        if focused() == app_id:
            return
        machine.sleep(0.5)
    assert False, f"{app_id} is not focused: {focused()}"


def click_on(app_id):
    x, y, w, h = view(app_id)
    aim("move", x + w // 2, y + h // 2)
    aim("press")
    aim("release")


def start(app_id, *container):
    """The program in the offline zone, in `container` when one is named."""
    args = " ".join(container)
    alice(
        f"systemd-run --user --unit=vm-{app_id} --setenv=WAYLAND_DISPLAY={display} "
        f"cellward run offline {args} -- {ACTIVATE} {app_id}"
    )
    shown(app_id)
    # Clicked: focused by the click itself, and a serial of the person's.
    click_on(app_id)
    said(f"{app_id}: click ")
    wait_focused(app_id)


def stop(app_id):
    alice(f"systemctl --user stop vm-{app_id}")
    machine.wait_until_fails(
        f"su -l alice -c 'SWAYSOCK={swaysock} swaymsg -t get_tree' | grep -q '\"app_id\": *\"{app_id}\"'",
        timeout=30,
    )


# A window of the host to take the focus to, and a pointer for the clicks
# (the buttons' one is stopped by now). sway focuses a window that asks
# with a valid token; by default it only marks it urgent.
alice(f"systemd-run --user --unit=vm-other --setenv=WAYLAND_DISPLAY={display} foot --app-id other")
shown("other")
output = json.loads(alice(f"SWAYSOCK={swaysock} swaymsg -t get_outputs -r"))[0]["rect"]
alice(
    f"systemd-run --user --unit=vmpointer-focus --setenv=WAYLAND_DISPLAY={display} "
    f"{POINTER} {fifo} {output['width']} {output['height']}"
)
machine.wait_until_succeeds(f"test -p {fifo}", timeout=30)
alice(f"SWAYSOCK={swaysock} swaymsg focus_on_window_activation focus")

with subtest("focus input: asking again after one click moves the focus once"):
    start("act-input")
    # Taken away: it asks with the click's serial, and gets it back.
    to_other()
    said("act-input: synced 1")
    wait_focused("act-input")
    # Taken away again: it asks again with the same click — the proxy
    # drops that, and the focus stays where the person put it.
    to_other()
    said("act-input: synced 2")
    machine.sleep(1)
    assert focused() == "other", focused()
    # A new click is a new input event: one more change.
    click_on("act-input")
    wait_focused("act-input")
    to_other()
    said("act-input: synced 3")
    wait_focused("act-input")
    stop("act-input")

with subtest("focus allow: every request of that click moves the focus"):
    alice("cellward container create focus-allow --home main")
    alice("cellward container set focus-allow focus allow")
    out = alice("cellward container show focus-allow --json")
    assert '"focus":{"value":"allow","source":"local"}' in out, out
    start("act-allow", "--container", "focus-allow")
    to_other()
    said("act-allow: synced 1")
    wait_focused("act-allow")
    # The same click again: the compositor honours it too — what `input`
    # held back above was the proxy's doing.
    to_other()
    said("act-allow: synced 2")
    wait_focused("act-allow")
    stop("act-allow")

with subtest("focus notify: no request moves the focus; the person is told"):
    alice("cellward container create focus-notify --home main")
    alice("cellward container set focus-notify focus notify")
    start("act-notify", "--container", "focus-notify")
    sup = find(json.loads(alice(f"SWAYSOCK={swaysock} swaymsg -t get_tree -r")), "act-notify")["pid"]
    to_other()
    said("act-notify: synced 1")
    # The supervisor had systemd --user start the notice, for its own pid.
    machine.wait_until_succeeds(
        f"journalctl --no-pager | grep -F 'window-focus --pid {sup}'", timeout=30
    )
    machine.sleep(1)
    assert focused() == "other", focused()
    stop("act-notify")

alice("systemctl --user stop vmpointer-focus vm-other")
