# exec()'d by tests/vm.nix inside the hermetic zone's subtest (hp, alice,
# in_zone, TRAY_ITEM, PY are there). The zone's mark on its programs' tray
# icons (crate::tray, vm53): a tray host on the host asks the icon of a
# program in the zone for its properties, and the picture comes back with
# the zone's colour drawn in the lower right corner and "zone · container"
# in the tooltip; with the badge off, as the program sent it.
import json

with subtest("hermetic zone: a tray icon carries the zone's mark (vm53)"):
    item = "org.kde.StatusNotifierItem-4343-1"
    alice("cellward frame color vmherm '#3366ff'")
    # The redirections on setsid itself: a `sh -c` in between would keep the
    # driver's pipe open for as long as the item runs, and the call would
    # never return (docs/GOTCHAS.md, "a background process in a VM test").
    in_zone(hp, f"sh -c 'setsid -f {PY} {TRAY_ITEM} {item} </dev/null >/dev/null 2>&1'")
    ask = (
        f"busctl --user --timeout=5 --json=short call {item} /StatusNotifierItem "
        "org.freedesktop.DBus.Properties GetAll s org.kde.StatusNotifierItem"
    )
    machine.wait_until_succeeds(
        "su -l alice -c "
        + shlex.quote(f"export XDG_RUNTIME_DIR=/run/user/1000; {ask} >/dev/null"),
        timeout=60,
    )

    def props():
        return json.loads(alice(ask))["data"][0]

    p = props()
    w, h, px = p["IconPixmap"]["data"][0]
    assert (w, h) == (16, 16), (w, h)
    at = (12 * 16 + 12) * 4
    assert px[at : at + 4] == [0xFF, 0x33, 0x66, 0xFF], px[at : at + 4]
    assert px[0:4] == [0, 0, 0, 0], "the rest of the icon is the program's"
    tip = p["ToolTip"]["data"]
    assert tip[3].startswith("own text\n") and "vmherm" in tip[3], tip
    # A bar: the bottom row is the colour.
    alice("cellward tray badge bar")
    px = props()["IconPixmap"]["data"][0][2]
    last = (15 * 16 + 3) * 4
    assert px[last : last + 4] == [0xFF, 0x33, 0x66, 0xFF], px[last : last + 4]
    # Off: the picture as the program sent it, the tooltip too.
    alice("cellward tray badge off")
    p = props()
    assert all(b == 0 for b in p["IconPixmap"]["data"][0][2])
    assert p["ToolTip"]["data"][3] == "own text", p["ToolTip"]
    alice("cellward tray badge default")
    alice("cellward frame color vmherm default")
    machine.succeed(f"pkill -u alice -f '[v]m-tray-item.py {item}'")
