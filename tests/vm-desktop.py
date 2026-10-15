"""tests/vm-desktop.nix: a desktop as people have it — niri nested in
headless sway, hermetic containers, a real Firefox — driven by a real
pointer. Executed by the test script with exec(), with POINTER (the command
of tests/vm-pointer.py) in its globals.
"""

import base64
import gzip
import json
import shlex
import traceback

FAILED = []
# `ONLY` (in the driver's environment, set by the .nix's `only`): run only
# the scenarios whose names contain it.
import os

ONLY = os.environ.get("VM_DESKTOP_ONLY", "")


def wanted(name):
    return ONLY in name


def alice(cmd, check=True):
    full = "su -l alice -c " + shlex.quote("export XDG_RUNTIME_DIR=/run/user/1000; " + cmd)
    if check:
        return machine.succeed(full)
    return machine.execute(full)[1]


def scenario(name):
    """A subtest that, on failure, is noted and leaves the machine to the
    next one — with the journal of the moment printed."""

    class Scenario:
        def __enter__(self):
            self.cm = subtest(name)
            self.cm.__enter__()

        def __exit__(self, kind, value, tb):
            if kind is not None:
                FAILED.append(name)
                print(f"!!! {name}: {value!r}")
                traceback.print_exception(kind, value, tb)
                print(alice("journalctl --user --no-pager -n 120 -o cat", check=False))
            self.cm.__exit__(None, None, None)
            return True

    return Scenario()


machine.wait_for_unit("multi-user.target")
machine.wait_for_unit("home-manager-alice.service")
machine.wait_for_unit("user@1000.service")

alice(
    "systemd-run --user --unit=vmsway "
    "--setenv=WLR_BACKENDS=headless --setenv=WLR_LIBINPUT_NO_DEVICES=1 "
    "--setenv=WLR_RENDERER=pixman --setenv=WLR_HEADLESS_OUTPUTS=1 "
    "sway -c /etc/vm-desktop/sway.conf"
)
machine.wait_until_succeeds("ls /run/user/1000/sway-ipc.*.sock", timeout=60)
sway = machine.succeed("ls /run/user/1000 | grep -E '^wayland-[0-9]+$' | head -1").strip()
swaysock = machine.succeed("ls /run/user/1000/sway-ipc.*.sock").strip()

# To watch (tests/vm-desktop.nix, `vnc`, `record`), view-only — a click of
# the watcher's would land in a scenario: the screen sway shows —
# niri's window over all of it.
if os.environ.get("VM_DESKTOP_VNC"):
    alice(f"systemd-run --user --unit=vmvnc --setenv=WAYLAND_DISPLAY={sway} wayvnc --disable-input 0.0.0.0 5900")
    machine.wait_until_succeeds("ss -ltn | grep -q ':5900 '", timeout=30)
    print("VNC: localhost:5901 on the driver's machine")
if os.environ.get("VM_DESKTOP_RECORD"):
    alice(
        f"systemd-run --user --unit=vmrec --setenv=WAYLAND_DISPLAY={sway} "
        "wf-recorder -r 10 -f /tmp/desktop.mp4"
    )

NIRI = (
    'output "winit" {\n    scale 1.0\n}\n'
    "layout {\n    gaps 8\n    focus-ring {\n        off\n    }\n"
    "    border {\n        off\n    }\n"
    "    default-column-width { proportion 0.5; }\n}\n"
    "prefer-no-csd\n"
    "animations {\n    off\n}\n"
    "hotkey-overlay {\n    skip-at-startup\n}\n"
)
alice(
    "mkdir -p ~/.config/niri && printf %s " + shlex.quote(NIRI) + " > ~/.config/niri/config.kdl"
)
alice(f"systemd-run --user --unit=vmniri --setenv=WAYLAND_DISPLAY={sway} --setenv=LIBGL_ALWAYS_SOFTWARE=1 niri")
machine.wait_until_succeeds("ls /run/user/1000 | grep -qE '^niri\\..*\\.sock$'", timeout=90)
nested = machine.succeed(
    f"ls /run/user/1000 | grep -E '^wayland-[0-9]+$' | grep -vx {sway} | head -1"
).strip()
niri_socket = machine.succeed("ls /run/user/1000/niri.*.sock").strip()
NIRI_MSG = f"NIRI_SOCKET={niri_socket} niri msg"


def windows():
    return json.loads(alice(f"{NIRI_MSG} --json windows"))


def titles():
    return [(w["app_id"], w["title"], w["pid"]) for w in windows()]


class Shot:
    def __init__(self, pixels, w, h):
        self.pixels = pixels
        self.size = (w, h)

    def __call__(self, x, y):
        w, h = self.size
        if not (0 <= x < w and 0 <= y < h):
            return None
        i = (y * w + x) * 3
        return tuple(self.pixels[i : i + 3])


def shot(name):
    """niri's screen: a PNG in the output to look at, a PPM to read."""
    alice(f"WAYLAND_DISPLAY={nested} grim /tmp/{name}.png")
    png = base64.b64decode(machine.succeed(f"base64 -w0 /tmp/{name}.png"))
    (machine.out_dir / f"{name}.png").write_bytes(png)
    alice(f"WAYLAND_DISPLAY={nested} grim -t ppm /tmp/{name}.ppm")
    packed = machine.succeed(f"gzip -c /tmp/{name}.ppm | base64 -w0")
    ppm = gzip.decompress(base64.b64decode(packed))
    magic, size, _depth, pixels = ppm.split(b"\n", 3)
    w, h = map(int, size.split())
    return Shot(pixels, w, h)


output = json.loads(alice(f"SWAYSOCK={swaysock} swaymsg -t get_outputs -r"))[0]["rect"]
FIFO = "/tmp/vm-desktop-pointer"
alice(
    f"systemd-run --user --unit=vmpointer --setenv=WAYLAND_DISPLAY={sway} "
    f"{POINTER} {FIFO} {output['width']} {output['height']}"
)
machine.wait_until_succeeds(f"test -p {FIFO}", timeout=30)


def pointer(*words):
    alice(f"echo {' '.join(str(w) for w in words)} > {FIFO}")
    machine.sleep(0.15)


def click(x, y, rest=0.0):
    """As a person clicks: onto the spot, (`rest` seconds), press, release —
    one command, so that no shell of the test's stands between them."""
    alice(
        f"echo move {x} {y} > {FIFO}; sleep {rest}; "
        f"echo press > {FIFO}; sleep 0.05; echo release > {FIFO}"
    )
    machine.sleep(0.2)


def run(unit, args, env=""):
    alice(
        f"systemd-run --user --unit={unit} --setenv=WAYLAND_DISPLAY={nested} "
        # As a Wayland session says of itself: Qt 5 picks X11 without it.
        f"--setenv=XDG_SESSION_TYPE=wayland {env} "
        f"cellward run {args}"
    )


def unit_active(unit):
    return alice(f"systemctl --user is-active {unit}", check=False).strip() == "active"


def firefox_mains():
    """Firefox's main processes (not its content processes)."""
    out = machine.execute("pgrep -u alice -a firefox | grep -v -- -contentproc || true")[1]
    return [line for line in out.splitlines() if "firefox" in line and "crashhelper" not in line]


peer.wait_for_unit("permission-http.service")
machine.wait_until_succeeds("curl --fail http://192.0.2.2:8080/", timeout=60)


# --- 1. Firefox twice in the container it runs in ---------------------------

if wanted('Firefox: a second launch into the same container opens a window there'):
    with scenario("Firefox: a second launch into the same container opens a window there"):
        alice("cellward container create ffbox --home private")
        alice("install -Dm600 /dev/null /home/alice/.config/vpn-zones/containers/ffbox/perms")
        run("ff-a", "offline --container ffbox -- firefox --new-window about:blank")
        machine.wait_until_succeeds(
            f"su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 {NIRI_MSG} --json windows' | grep -q firefox",
            timeout=120,
        )
        machine.sleep(5)
        shot("ff-same-1")
        run("ff-b", "offline --container ffbox -- firefox --new-window about:blank")
        machine.sleep(15)
        shot("ff-same-2")
        print("windows:", titles())
        print("ff-b active:", unit_active("ff-b"))
        print(alice("journalctl --user --no-pager -u ff-b -o cat | tail -30", check=False))
        ff = [t for t in titles() if t[0] == "firefox"]
        assert not unit_active("ff-b"), "the second launch is still running (a dialog of its own?)"
        assert len(ff) == 2, ff

alice("systemctl --user stop ff-a ff-b", check=False)
machine.sleep(3)


# --- 2. The real home, open in another network --------------------------------


def second_menu_action(at):
    """The guarded launch window's second entry: under its highlighted
    first one (blue), wherever niri put the window."""
    points = []
    w, h = at.size
    for y in range(h):
        for x in range(0, w, 2):
            red, green, blue = at(x, y)
            if 50 < red < 150 and 50 < green < 150 and blue > 180:
                points.append((x, y))
    assert len(points) > 500, "the guarded menu's selected entry not found"
    xs, ys = zip(*points)
    return (min(xs) + max(xs)) // 2, max(ys) + 19


def settled(name, check, tries=20):
    for n in range(tries):
        at = shot(name)
        try:
            return check(at)
        except AssertionError:
            if n == tries - 1:
                raise
            machine.sleep(1)


if wanted('Firefox with the real home open in another network: opened there'):
    with scenario("Firefox with the real home open in another network: opened there"):
        run("ff-main-off", "offline -- firefox --new-window about:blank", env="--setenv=VPN_ZONE_APPID=firefox")
        machine.wait_until_succeeds(
            f"su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 {NIRI_MSG} --json windows' | grep -q firefox",
            timeout=120,
        )
        machine.sleep(5)
        run("ff-main-host", "host -- firefox --new-window about:blank", env="--setenv=VPN_ZONE_APPID=firefox")
        machine.wait_until_succeeds("pgrep -x vpn-zone-window", timeout=60)
        machine.sleep(2)
        x, y = settled("ff-main-other-net-asked", second_menu_action)
        print("windows:", titles())
        click(x, y, rest=2.5)
        machine.sleep(12)
        shot("ff-main-other-net-opened")
        print("windows:", titles())
        print(alice("journalctl --user --no-pager -u ff-main-host -o cat | tail -30", check=False))
        ff = [t for t in titles() if t[0] == "firefox"]
        assert not any(t[1] == "Close Firefox" for t in ff), ff
        assert len(ff) == 2, ff
        assert not unit_active("ff-main-host"), "the launch is still running"

alice("systemctl --user stop ff-main-off ff-main-host", check=False)
machine.sleep(3)


# --- 3. The permission panel, clicked as people click -------------------------


def panel_buttons(at):
    """The panel's two buttons on the screen: on a row under the title, two
    runs of one colour, each 60 to 300 pixels, apart by a short gap of one
    other colour (the panel's) — ((l, r), (l, r)), y. Rows of text have
    glyphs in their gaps."""
    w, h = at.size
    found = []
    for y in range(40, min(260, h)):
        runs = []
        start, colour = 0, at(0, y)
        for x in range(1, min(w, 900) + 1):
            c = at(x, y) if x < min(w, 900) else None
            if c != colour:
                runs.append((start, x - 1, colour))
                start, colour = x, c
        for a, gap, b in zip(runs, runs[1:], runs[2:]):
            if (
                a[2] == b[2]
                and gap[2] != a[2]
                and 4 <= gap[1] - gap[0] + 1 <= 20
                and all(60 <= r[1] - r[0] + 1 <= 300 for r in (a, b))
            ):
                found.append((((a[0], a[1]), (b[0], b[1])), y))
    assert found, "no panel"
    spans = found[len(found) // 2][0]
    rows = [y for s, y in found if s == spans]
    return spans, rows[len(rows) // 2]


def requested(path):
    return f"journalctl -u permission-http --no-pager | grep -F 'GET /{path}'"


def cell_of(at, span, y):
    """A button's pixels, a row near its top and the rows through its
    words — to well past its right end found: the seconds are written at
    the end of its words, and what is beyond the panel stays as it was."""
    l, _ = span
    return [at(c, yy) for c in range(l + 1, l + 250) for yy in range(y - 6, y + 6)]


def panel_round(tag, launch, path):
    """`launch` brings a program up that asks for the network at `path`; its
    panel clicked as people click: at once — none of it an answer, its
    buttons locked with the seconds left on them —, then once the
    countdown is over: open, and the click answers."""
    pointer("move", 5, 5)
    launch()
    spans, y = settled(f"{tag}-panel", panel_buttons, tries=40)
    allow = ((spans[1][0] + spans[1][1]) // 2, y)
    print(tag, "buttons", spans, "row", y)
    # A click at once starts the countdown again: locked, with its seconds.
    click(*allow, rest=0.2)
    locked = cell_of(shot(f"{tag}-locked"), spans[1], y)
    assert peer.execute(requested(path))[0] != 0, "a click too soon answered"
    machine.sleep(1.2)
    second = cell_of(shot(f"{tag}-locked-later"), spans[1], y)
    machine.sleep(2.5)
    open_ = cell_of(shot(f"{tag}-open"), spans[1], y)
    print(tag, "locked changes:", locked != second, "opened:", locked != open_)
    assert locked != second, "no seconds counted down on the button"
    assert locked != open_ and second != open_, "the buttons did not open"
    click(*allow, rest=0.1)
    peer.wait_until_succeeds(requested(path), timeout=20)
    shot(f"{tag}-answered")


def panel_up(name):
    try:
        panel_buttons(shot(name))
        return True
    except AssertionError:
        return False


if wanted("the permission panel on Firefox's window (own X server), as a person clicks"):
    with scenario("the permission panel on Firefox's window (own X server), as a person clicks"):
        alice("cellward container create fx11 --home private")
        alice("install -Dm600 /dev/null /home/alice/.config/vpn-zones/containers/fx11/perms")
        # Its own X server: the container's word (2026-10-15).
        alice("cellward container set fx11 x11 on")
        panel_round(
            "ff",
            lambda: run("ff-net", "host --container fx11 -- firefox --new-window http://192.0.2.2:8080/ff"),
            "ff",
        )
        print(alice("journalctl --user --no-pager -o cat | grep -iE 'netask|question|вопрос|panel' | tail -40", check=False))

alice("systemctl --user stop ff-net", check=False)
machine.sleep(3)

if wanted('the permission panel on foot (Wayland), as a person clicks'):
    with scenario("the permission panel on foot (Wayland), as a person clicks"):
        command = (
            "sleep 4; exec 3<>/dev/tcp/192.0.2.2/8080; "
            "printf 'GET /foot HTTP/1.0\\r\\nHost: peer\\r\\n\\r\\n' >&3; cat <&3; sleep 600"
        )
        panel_round(
            "foot",
            lambda: run("foot-net", f"host -- foot --app-id foot-net bash -c {shlex.quote(command)}",
                        env="--setenv=VPN_ZONE_APPID=foot-net"),
            "foot",
        )

alice("systemctl --user stop foot-net", check=False)

# --- 4. A running single-instance program, launched again from the menu ------


def focused():
    out = alice(f"{NIRI_MSG} --json focused-window", check=False)
    try:
        w = json.loads(out)
        return w and (w["app_id"], w["title"])
    except ValueError:
        return None


alice(
    f"systemd-run --user --unit=vmbar --setenv=WAYLAND_DISPLAY={nested} "
    "waybar -c /etc/vm-desktop/waybar.json"
)
machine.sleep(3)

if wanted('AyuGram running, launched again from the menu: its window comes'):
    with scenario("AyuGram running, launched again from the menu: its window comes"):
        alice("cellward container create tg --home private")
        alice("install -Dm600 /dev/null /home/alice/.config/vpn-zones/containers/tg/perms")
        run("tg-a", "offline --container tg -- AyuGram --", env="--setenv=VPN_ZONE_APPID=com.ayugram.desktop")
        machine.wait_until_succeeds(
            f"su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 {NIRI_MSG} --json windows' | grep -qiE 'ayugram|telegram'",
            timeout=120,
        )
        machine.sleep(8)
        shot("tg-1")
        print(machine.succeed("ps -eo pid,ppid,args --forest | grep -iE 'ayugram' | grep -v grep | cut -c1-200 || true"))
        # (Closed, Telegram goes to the tray only once logged in — not here:
        # with no account it quits. Behind another window instead.)
        # Something else in front of it.
        alice(f"systemd-run --user --unit=tg-other --setenv=WAYLAND_DISPLAY={nested} foot --app-id other")
        machine.sleep(4)
        print("focused before:", focused())
        print(alice("find ~/.local/state/vpn-zones/.running -type f | while read f; do echo \"$f: $(cat \"$f\")\"; done", check=False))
        print(machine.succeed("ps -eo pid,ppid,user,args --forest | grep -iE 'ayugram|waybar|profile-run|1257' | grep -v grep | cut -c1-200 || true"))
        print(alice("journalctl --user --no-pager -u vmbar -u tg-a -o cat | tail -25", check=False))
        print(alice("busctl --user list | grep -iE 'StatusNotifier|ayugram' || true", check=False))
        # Seen handing a launch over before: the menu starts it where it runs,
        # with no question (rust/src/picker.rs, HANDOVER).
        alice("mkdir -p ~/.local/state/vpn-zones/.handover && touch ~/.local/state/vpn-zones/.handover/com.ayugram.desktop")
        alice(
            f"systemd-run --user --unit=tg-menu --setenv=WAYLAND_DISPLAY={nested} "
        # A session's launcher has its compositor's IPC (niri hands it its
        # NIRI_SOCKET).
        f"--setenv=NIRI_SOCKET={niri_socket} "
            "vpn-zone-pick --id com.ayugram.desktop -- AyuGram --"
        )
        machine.sleep(10)
        shot("tg-2")
        print("windows:", titles())
        print("focused after:", focused())
        print("tg-menu active:", unit_active("tg-menu"))
        print(alice("journalctl --user --no-pager -u tg-menu -u tg-a -o cat | tail -40", check=False))
        print(alice("journalctl --user --no-pager -o cat | grep -iE 'activat|focus|urgent' | tail -20", check=False))
        tg = [t for t in titles() if "ayugram" in t[0].lower() or "telegram" in t[0].lower()]
        assert len(tg) == 1, tg
        assert not unit_active("tg-menu"), "the second launch still runs"
        assert tg[0][0] == (focused() or ("",))[0], focused()

alice("systemctl --user stop tg-a tg-other tg-menu", check=False)

# --- 4b. A program in the tray, launched again from the menu -----------------

if wanted("KeePassXC in the tray, launched again from the menu: its window comes back"):
    with scenario("KeePassXC in the tray, launched again from the menu: its window comes back"):
        alice("pgrep -x waybar || systemd-run --user --unit=vmbar2 "
              f"--setenv=WAYLAND_DISPLAY={nested} waybar -c /etc/vm-desktop/waybar.json")
        alice("cellward container create kp --home private")
        alice("install -Dm600 /dev/null /home/alice/.config/vpn-zones/containers/kp/perms")
        ini = "[GUI]\nShowTrayIcon=true\nMinimizeOnClose=true\nMinimizeToTray=true\nMinimizeOnStartup=false\n"
        alice(
            "mkdir -p ~/.local/state/vpn-profiles/kp/home/.config/keepassxc && printf "
            + shlex.quote(ini)
            + " > ~/.local/state/vpn-profiles/kp/home/.config/keepassxc/keepassxc.ini"
        )
        run("kp-a", "offline --container kp -- keepassxc", env="--setenv=VPN_ZONE_APPID=org.keepassxc.KeePassXC")
        machine.wait_until_succeeds(
            f"su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 {NIRI_MSG} --json windows' | grep -qi keepassxc",
            timeout=120,
        )
        machine.sleep(5)
        shot("kp-1")
        print(alice("busctl --user list | grep -iE 'StatusNotifier' || true", check=False))
        kp = next(w for w in windows() if "keepassxc" in w["app_id"].lower())
        alice(f"{NIRI_MSG} action close-window --id {kp['id']}")
        machine.sleep(4)
        shot("kp-tray")
        print("windows after close:", titles(), "kp-a active:", unit_active("kp-a"))
        assert unit_active("kp-a"), "KeePassXC quit instead of going to the tray"
        assert not any("keepassxc" in t[0].lower() for t in titles()), "its window stayed"
        alice(f"systemd-run --user --unit=kp-other --setenv=WAYLAND_DISPLAY={nested} foot --app-id other2")
        machine.sleep(3)
        alice("mkdir -p ~/.local/state/vpn-zones/.handover && touch ~/.local/state/vpn-zones/.handover/org.keepassxc.KeePassXC")
        alice(
            f"systemd-run --user --unit=kp-menu --setenv=WAYLAND_DISPLAY={nested} "
            f"--setenv=NIRI_SOCKET={niri_socket} "
            "--setenv=XDG_SESSION_TYPE=wayland "
            "vpn-zone-pick --id org.keepassxc.KeePassXC -- keepassxc"
        )
        machine.sleep(10)
        shot("kp-back")
        print("windows:", titles(), "focused:", focused(), "kp-menu active:", unit_active("kp-menu"))
        print(alice("journalctl --user --no-pager -u kp-menu -o cat | tail -20", check=False))
        assert any("keepassxc" in t[0].lower() for t in titles()), "its window did not come back"
        assert "keepassxc" in str(focused()).lower(), focused()
        assert not unit_active("kp-menu")
    alice("systemctl --user stop kp-a kp-other kp-menu", check=False)


# --- 5. A throwaway container: open, joined, and gone with its programs ---

TW = "Throwaway containers: a second program joins the open one, a new one is empty"


def tw_alive(unit, seconds=6):
    machine.sleep(seconds)
    return unit_active(unit)


if wanted(TW):
    with scenario(TW):
        for app in ["tw-a", "tw-b", "tw-c", "tw-d", "tw-e"]:
            alice(f"install -Dm600 /dev/null ~/.config/vpn-zones/fs-perms/{app}")
        # Each foot lives on only while its home is what it should be.
        run(
            "tw-a",
            "offline --fs-sandbox -- foot --app-id tw-a sh -c 'echo hi > ~/joined; sleep 600'",
            env="--setenv=VPN_ZONE_APPID=tw-a",
        )
        machine.wait_until_succeeds(
            f"su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 {NIRI_MSG} --json windows' | grep -q tw-a",
            timeout=120,
        )
        record = alice("cat ~/.local/state/vpn-zones/.running/__main__/tw-a").split()
        print("tw-a record:", record)
        assert record[2].startswith("__fs__:"), record
        name = record[2].split(":", 1)[1]
        run(
            "tw-b",
            f"offline --fs-sandbox --join {name} -- foot --app-id tw-b sh -c 'test -e ~/joined && sleep 600'",
            env="--setenv=VPN_ZONE_APPID=tw-b",
        )
        assert tw_alive("tw-b"), "the joined program did not see the open one's home"
        run(
            "tw-c",
            "offline --fs-sandbox -- foot --app-id tw-c sh -c '! test -e ~/joined && sleep 600'",
            env="--setenv=VPN_ZONE_APPID=tw-c",
        )
        assert tw_alive("tw-c"), "a new throwaway container saw another one's home"
        shot("tw-open")

        # The launch window: the open one offered to join, by its programs.
        alice(
            f"systemd-run --user --unit=tw-pick --setenv=WAYLAND_DISPLAY={nested} "
            f"--setenv=NIRI_SOCKET={niri_socket} "
            "vpn-zone-pick --id tw-e -- foot --app-id tw-e"
        )
        machine.sleep(6)
        shot("tw-window")
        alice("systemctl --user stop tw-pick", check=False)

        # Again, for a program that hands a launch over: asked, there or new.
        alice("mkdir -p ~/.local/state/vpn-zones/.handover && touch ~/.local/state/vpn-zones/.handover/tw-a")
        alice(
            f"systemd-run --user --unit=tw-again --setenv=WAYLAND_DISPLAY={nested} "
            f"--setenv=NIRI_SOCKET={niri_socket} "
            "vpn-zone-pick --id tw-a -- foot --app-id tw-a sh -c 'sleep 600'"
        )
        machine.sleep(6)
        shot("tw-again")
        assert unit_active("tw-again"), "no question for a program open in a throwaway container"
        alice("systemctl --user stop tw-again", check=False)

        # Its home goes with its last program.
        alice("systemctl --user stop tw-a tw-b", check=False)
        machine.wait_until_fails(
            f"su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 systemctl --user list-units --plain "
            f"--no-legend vpn-zone-container@*' | grep -F ':fs:{name.split('-')[0]}'",
            timeout=60,
        )
        run(
            "tw-d",
            f"offline --fs-sandbox --join {name} -- foot --app-id tw-d sh -c '! test -e ~/joined && sleep 600'",
            env="--setenv=VPN_ZONE_APPID=tw-d",
        )
        assert tw_alive("tw-d"), "the home of a throwaway container outlived its programs"
    alice("systemctl --user stop tw-a tw-b tw-c tw-d tw-pick tw-again", check=False)
    machine.sleep(3)


# --- 6. The permissions in the launch window ---------------------------------

PW = "Permissions in the launch window: changed there, kept in the container, shown again"


def blue_boxes(at):
    """The window's blue (primary) buttons: (left, top, right, bottom). A
    button's rows above and below its text are blue from edge to edge; the
    rows of one button share its edges and lie within its height."""
    w, h = at.size
    blue = lambda p: p is not None and 50 < p[0] < 150 and 50 < p[1] < 150 and p[2] > 180
    boxes = []
    for y in range(h):
        x = 0
        while x < w:
            if not blue(at(x, y)):
                x += 1
                continue
            start = x
            while x < w and blue(at(x, y)):
                x += 1
            if x - start < 30:
                continue
            for box in boxes:
                if abs(box[0] - start) <= 2 and abs(box[2] - (x - 1)) <= 2 and y - box[1] <= 18:
                    box[3] = y
                    break
            else:
                boxes.append([start, y, x - 1, y])
    return [b for b in boxes if b[3] - b[1] >= 6]


def perm_rows(boxes):
    """The chosen buttons of the permissions: one a row, all starting where
    the choices of every row start."""
    lefts = [b[0] for b in boxes]
    left = max(set(lefts), key=lefts.count)
    return sorted([b for b in boxes if b[0] == left], key=lambda b: b[1])


if wanted(PW):
    with scenario(PW):
        alice("cellward container create pwbox --home private")
        alice("install -Dm600 /dev/null ~/.config/vpn-zones/containers/pwbox/perms")
        alice("mkdir -p ~/.local/state/vpn-zones/.lastprofile && echo pwbox > ~/.local/state/vpn-zones/.lastprofile/pw-a")
        # As a launcher starts it: the program outlives the picker, which
        # ends once its window is up (a unit's end would take it along).
        pick = (
            f"systemd-run --user --unit={{unit}} -p KillMode=process --setenv=WAYLAND_DISPLAY={nested} "
            f"--setenv=NIRI_SOCKET={niri_socket} --setenv=XDG_SESSION_TYPE=wayland "
            "vpn-zone-pick --id pw-a -- foot --app-id pw-a sh -c 'sleep 600'"
        )
        alice(pick.format(unit="pw-pick-1"))
        machine.sleep(6)
        at = shot("pw-window-1")
        boxes = sorted(blue_boxes(at), key=lambda b: b[1])
        print("blue boxes:", boxes)
        # The rows of the permissions: right of their names; the button to
        # start: the lowest.
        launch = boxes[-1]
        # The first row of the permissions, the X server's: its chosen
        # button the topmost of those that start where the choices do.
        rows = perm_rows(boxes)
        assert rows, boxes
        x11 = rows[0]
        # «вкл.»: the choice right after «как у всех».
        click(x11[2] + 20, (x11[1] + x11[3]) // 2, rest=0.3)
        machine.sleep(1)
        shot("pw-window-1-on")
        click((launch[0] + launch[2]) // 2, (launch[1] + launch[3]) // 2, rest=0.3)
        machine.wait_until_succeeds(
            f"su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 {NIRI_MSG} --json windows' | grep -q pw-a",
            timeout=120,
        )
        print(alice("cat ~/.config/vpn-zones/containers/pwbox/*.conf 2>/dev/null; ls ~/.config/vpn-zones/containers/pwbox/", check=False))
        alice("grep -rqx 'x11 = true' ~/.config/vpn-zones/containers/pwbox/")
        print(alice("journalctl --user --no-pager -u pw-pick-1 -o cat | tail -5", check=False))
        # Again: the window shows it as it is now.
        alice(pick.format(unit="pw-pick-2"))
        machine.sleep(6)
        at = shot("pw-window-2")
        rows2 = sorted(
            [b for b in blue_boxes(at) if b[3] - b[1] < 30 and b[1] > x11[1] - 10],
            key=lambda b: b[1],
        )
        print("rows again:", rows2)
        assert rows2[0][0] > x11[2], "X11 is not shown on as it was set"
        # The window it opened goes with it: the unit keeps its processes.
        alice("systemctl --user kill pw-pick-2", check=False)
        machine.wait_until_fails("pgrep -x vpn-zone-window", timeout=30)
        # The frame's ☰ of its window: the program, its container, under
        # their headings; the container's permissions window from there.
        sup = next(w["pid"] for w in windows() if w["app_id"] == "pw-a")
        alice(f"systemd-run --user --unit=pw-menu --setenv=WAYLAND_DISPLAY={nested} cellward window-menu --pid {sup}")
        machine.wait_until_succeeds("pgrep -x vpn-zone-window", timeout=30)
        machine.sleep(3)
        shot("pw-menu")
        # restart, close, then the container's: its permissions.
        alice(f"WAYLAND_DISPLAY={nested} wtype -s 400 -k 3 -k Return")
        machine.sleep(4)
        shot("pw-perms")
        print(alice("pgrep -a vpn-zone-window || true", check=False))
        print(alice("journalctl --user --no-pager -u pw-menu -o cat | tail -20", check=False))
        machine.succeed("pgrep -x vpn-zone-window")
        alice(f"WAYLAND_DISPLAY={nested} wtype -s 400 -k Escape")
        machine.wait_until_fails("pgrep -x vpn-zone-window", timeout=30)
    alice("systemctl --user stop pw-pick-1 pw-pick-2 pw-menu", check=False)
    machine.sleep(3)


# --- 7. A launch from a program of another launch ---------------------------

NESTED = "A program under the proxy starts another through cellward: its window comes"

if wanted(NESTED):
    with scenario(NESTED):
        # As a file manager opens a file in another program: a shell under
        # the proxy runs `cellward run`, with the restricted socket in its
        # WAYLAND_DISPLAY.
        run(
            "nest-outer",
            "unconfined -- foot --app-id nest-outer sh -c "
            "'sleep 3; cellward run unconfined -- foot --app-id nest-inner; sleep 600'",
            env="--setenv=VPN_ZONE_APPID=nest-outer",
        )
        machine.wait_until_succeeds(
            f"su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 {NIRI_MSG} --json windows' | grep -q nest-inner",
            timeout=60,
        )
        shot("nest")
        print(alice("journalctl --user --no-pager -o cat | grep -F 'outside this launch' | tail -5", check=False))
        machine.fail(
            "su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 journalctl --user --no-pager -o cat' "
            "| grep -F 'outside this launch'"
        )
    alice("systemctl --user stop nest-outer", check=False)
    machine.sleep(2)


# --- 8. The clipboard by container ---------------------------------------------

CLIP = "The clipboard by container: another container's copy only when pasted"

if wanted(CLIP):
    with scenario(CLIP):
        # Two containers of the real home: what they write is seen here.
        alice("cellward container create clipb --home main")
        run("clip-a", "offline -- sh -c 'echo secret-a | wl-copy; sleep 600'",
            env="--setenv=VPN_ZONE_APPID=clip-a")
        machine.sleep(6)
        # The host, not proxied: as before.
        assert "secret-a" in alice(f"WAYLAND_DISPLAY={nested} wl-paste", check=False)
        # Its own container: read freely.
        run("clip-a2", "offline -- sh -c 'sleep 2; wl-paste > ~/clip-a.txt; sleep 600'",
            env="--setenv=VPN_ZONE_APPID=clip-a2")
        # Another container, nobody pasting: nothing.
        run("clip-b", "offline --container clipb -- sh -c 'sleep 2; wl-paste > ~/clip-b.txt 2>&1; sleep 600'",
            env="--setenv=VPN_ZONE_APPID=clip-b")
        machine.sleep(10)
        a = alice("cat ~/clip-a.txt", check=False)
        b = alice("cat ~/clip-b.txt", check=False)
        print("own:", repr(a), "foreign:", repr(b))
        assert "secret-a" in a, a
        assert "secret-a" not in b, b
        # Another container, the person pasting into its terminal.
        run("clip-b2", "offline --container clipb -- foot --app-id clipb2 sh -c "
            "'read x; echo \"$x\" > ~/clip-b2.txt; sleep 600'",
            env="--setenv=VPN_ZONE_APPID=clip-b2")
        machine.wait_until_succeeds(
            f"su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 {NIRI_MSG} --json windows' | grep -q clipb2",
            timeout=60,
        )
        win = next(w for w in windows() if w["app_id"] == "clipb2")
        alice(f"{NIRI_MSG} action focus-window --id {win['id']}")
        machine.sleep(2)
        alice(f"WAYLAND_DISPLAY={nested} wtype -M ctrl -M shift -k v -m shift -m ctrl")
        machine.sleep(1)
        alice(f"WAYLAND_DISPLAY={nested} wtype -k Return")
        machine.wait_until_succeeds("grep -q secret-a /home/alice/clip-b2.txt", timeout=20)
        shot("clip-pasted")
    alice("systemctl --user stop clip-a clip-a2 clip-b clip-b2", check=False)
    machine.sleep(2)


# --- 9. Whose a browser's connection is ----------------------------------------

CH = "Chromium's connection: the question names the program"

if wanted(CH):
    with scenario(CH):
        alice("cellward container create chbox --home private")
        alice("install -Dm600 /dev/null /home/alice/.config/vpn-zones/containers/chbox/perms")
        run(
            "ch-net",
            "host --container chbox -- chromium --no-first-run --ozone-platform=wayland "
            "--password-store=basic http://192.0.2.2:8080/ch",
            env="--setenv=VPN_ZONE_APPID=chromium-browser",
        )
        machine.sleep(25)
        shot("ch-question")
        traffic = alice("cellward traffic --connections 2>&1 | tail -30", check=False)
        print(traffic)
        assert "192.0.2.2:8080 · Chromium" in traffic, "the connection is nobody's"
        print(machine.succeed("ps -u alice -o pid,ppid,comm,args --forest | grep -iE 'chrom|vpn-zone|vz-' | grep -v grep | cut -c1-200"))
        print(alice("journalctl --user --no-pager -o cat | grep -iE 'неизвестн|unknown|owner' | tail -20", check=False))
    alice("systemctl --user stop ch-net", check=False)
    machine.sleep(3)


# --- 10. Programs in a layer over the home and in a home of their own ------

for home in ["overlay", "private"]:
    for program, cmd, app in [
        ("TeamSpeak", "TeamSpeak", "teamspeak"),
        ("Firefox", "firefox --new-window about:blank", "firefox"),
    ]:
        name = f"{program} in a container with the home {home}: it starts and stays"
        if not wanted(name) or (program == "TeamSpeak" and machine.execute("command -v TeamSpeak")[0] != 0):
            continue
        with scenario(name):
            box = f"{app}-{home}"
            alice(f"cellward container create {box} --home {home}")
            alice(f"install -Dm600 /dev/null /home/alice/.config/vpn-zones/containers/{box}/perms")
            if program == "TeamSpeak":
                # CEF: X11 only — with no X server of its container it ends at once.
                run(f"nox-{box}", f"offline --container {box} -- {cmd}", env=f"--setenv=VPN_ZONE_APPID={app}")
                machine.sleep(15)
                print("without X11, still running:", unit_active(f"nox-{box}"))
                print(alice(f"journalctl --user --no-pager -u nox-{box} -o cat | grep -iE 'display|X server' | head -3", check=False))
                alice(f"cellward container set {box} x11 on")
            unit = f"run-{box}"
            run(unit, f"offline --container {box} -- {cmd}", env=f"--setenv=VPN_ZONE_APPID={app}")
            try:
                machine.wait_until_succeeds(
                    f"su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 {NIRI_MSG} --json windows' | grep -qi '{app}'",
                    timeout=120,
                )
            finally:
                shot(f"{box}-1")
                print(alice(f"journalctl --user --no-pager -u {unit} -o cat | tail -40", check=False))
            machine.sleep(15)
            shot(f"{box}-2")
            assert unit_active(unit), f"{program} ended"
            assert any(app in t[0].lower() for t in titles()), titles()
            alice(f"systemctl --user stop {unit}", check=False)
            machine.sleep(3)

# --- 11. The cellward window's connections, a tree ------------------------------

TREE = "The cellward window's connections: a tree by program, a site blocked from its row"


def runs_at(at, y, x0, x1):
    """A row of the screen as runs of one colour: (from, to, colour)."""
    out = []
    start, colour = x0, at(x0, y)
    for x in range(x0 + 1, x1 + 1):
        c = at(x, y) if x < x1 else None
        if c != colour:
            out.append((start, x - 1, colour))
            start, colour = x, c
    return out


def spans_down(found):
    """Points found row by row, one per thing: rows next to each other at
    about the same x are one thing — its middle."""
    things = []
    for x, y in sorted(found, key=lambda p: (p[1], p[0])):
        if things and y - things[-1][2] <= 2 and abs(x - things[-1][0]) <= 6:
            things[-1][2] = y
        else:
            things.append([x, y, y])
    return [(x, (top + bottom) // 2) for x, top, bottom in things]


def block_buttons(at):
    """The ⊘ buttons: in the right quarter, below the tabs, runs of one
    colour not the page's, 20 to 40 pixels wide — top to bottom."""
    w, h = at.size
    page = at(w - 3, h - 3)
    found = []
    for y in range(110, h):
        for a, b, c in runs_at(at, y, w * 3 // 4, w - 20):
            if c != page and 20 <= b - a + 1 <= 40:
                found.append(((a + b) // 2, y))
    buttons = spans_down(found)
    assert len(buttons) >= 2, f"no ⊘ buttons: {buttons}"
    return buttons


def danger_button(at):
    """The confirmation's «Блокировать»: a red run 60 pixels wide or more."""
    w, h = at.size
    found = []
    for y in range(110, h):
        for a, b, (r, g, bl) in runs_at(at, y, 0, w - 1):
            if r > 150 and g < 110 and bl < 110 and b - a + 1 >= 60:
                found.append(((a + b) // 2, y))
    assert found, "no «Блокировать»"
    return spans_down(found)[0]


if wanted(TREE):
    with scenario(TREE):
        # Real containers and the real `container net … block`; the
        # connections are made up — names a DNS answer would have given, in
        # a VM with no DNS — by a `cellward` in front of the real one that
        # adds them to what `_panel` says and passes every other command on.
        real = alice("readlink -f $(command -v cellward)").strip()
        alice("cellward container create treebox --home private")
        alice("cellward container create app-chat --home private")
        flows = [
            # (instance, proto, remote, port, name, who, out, in, ago)
            ("treebox", "tcp", "203.0.113.10", "443", "www.youtube.com", "Browser", 41_000_000, 1_181_116_006, 2),
            ("treebox", "udp", "203.0.113.11", "443", "rr4sn-2o.googlevideo.com", "Browser", 900_000, 106_954_752, 5),
            ("treebox", "udp", "203.0.113.12", "443", "rr2---sn-abcdefgh.googlevideo.com", "Browser", 300_000, 52_428_800, 9),
            ("treebox", "tcp", "203.0.113.13", "443", "i.ytimg.com", "Browser", 20_000, 4_194_304, 30),
            ("treebox", "tcp", "203.0.113.14", "443", "github.com", "Browser", 9_000, 104_448, 12),
            ("treebox", "tcp", "203.0.113.15", "443", "api.github.com", "Browser", 3_000, 20_480, 40),
            ("treebox", "tcp", "198.51.100.7", "8443", "", "Browser", 1_000, 5_530, 75),
            ("treebox", "udp", "2001:db8::53", "443", "", "Browser", 2_000, 3_000, 130),
            ("treebox", "tcp", "203.0.113.20", "443", "updates.example.org", "Updater", 500, 0, 600),
            ("app-chat", "udp", "198.51.100.40", "9987", "", "Chat", 3_145_728, 276_824_064, 1),
            ("app-chat", "tcp", "203.0.113.30", "443", "voice.example.net", "Chat", 50_000, 400_000, 20),
            ("app-chat", "tcp", "203.0.113.31", "443", "", "", 0, 0, 300),
        ]
        lines = [
            "instance\ttreebox\ttreebox\toffline\t45000000\t1350000000\tNOW",
            "instance\tapp-chat\tapp-chat\toffline\t3200000\t277000000\tNOW",
        ]
        for i, proto, remote, port, name, who, out, inb, ago in flows:
            lines.append(f"flow\t{i}\t{proto}\t{remote}\t{port}\t{name}\t{who}\t{out}\t{inb}\tNOW-{ago}")
        data = base64.b64encode(("\n".join(lines) + "\n").encode()).decode()
        machine.succeed(f"echo {data} | base64 -d > /tmp/tree.panel && chmod 644 /tmp/tree.panel")
        fake = (
            "#!/bin/sh\n"
            'if [ "$1" = _panel ]; then\n'
            f"  {real} _panel | grep -v '^instance\\|^flow'\n"
            # NOW, NOW-<seconds>: when, from the clock of the moment.
            "  awk -F'\\t' -v OFS='\\t' -v now=$(date +%s) "
            "'{ for (i = 1; i <= NF; i++) if ($i ~ /^NOW/) { sub(/^NOW-?/, \"\", $i); $i = now - $i } print }' "
            "/tmp/tree.panel\n"
            "  exit 0\n"
            "fi\n"
            'echo "$*" >> /tmp/tree-calls\n'
            f'exec {real} "$@"\n'
        )
        machine.succeed(
            f"echo {base64.b64encode(fake.encode()).decode()} | base64 -d > /tmp/tree-cellward "
            "&& chmod 755 /tmp/tree-cellward && touch /tmp/tree-calls && chmod 666 /tmp/tree-calls"
        )
        print(alice("/tmp/tree-cellward _panel | grep -E '^(instance|flow|container)'"))
        tools = alice(f"grep -m1 -o '/nix/store/[^ \"]*-vpn-zone-tools.json' {real}").strip()
        win = machine.succeed(f"grep -o '\"window\": *\"[^\"]*\"' {tools}").strip().split('"')[3]
        pointer("move", 5, 5)
        alice(
            f"systemd-run --user --unit=vmtree --setenv=WAYLAND_DISPLAY={nested} "
            f"{win} panel --cellward /tmp/tree-cellward --tab network"
        )
        machine.wait_until_succeeds(
            f"su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 {NIRI_MSG} --json windows' | grep -q '\"cellward\"'",
            timeout=60,
        )
        tree_win = next(w for w in windows() if w["app_id"] == "cellward")
        alice(f"{NIRI_MSG} action focus-window --id {tree_win['id']}")
        alice(f"{NIRI_MSG} action fullscreen-window")
        machine.sleep(4)
        buttons = settled("tree", block_buttons)
        print("⊘ buttons:", buttons)
        # The second site of the browser (googlevideo.com): unfolded by a
        # click on its name, left of its «… назад».
        x, y = buttons[1]
        click(x - 260, y, rest=0.3)
        machine.sleep(2)
        buttons = settled("tree-site", block_buttons)
        print("⊘ buttons, the site unfolded:", buttons)
        # The first site's ⊘: asked on its row, nothing done yet.
        x, y = buttons[0]
        click(x, y, rest=0.6)
        machine.sleep(2)
        bx, by = settled("tree-asked", danger_button)
        assert "block" not in alice("cat /tmp/tree-calls"), "blocked before it was confirmed"
        click(bx, by, rest=0.3)
        machine.wait_until_succeeds("grep -q 'container net treebox block youtube.com' /tmp/tree-calls", timeout=20)
        machine.sleep(3)
        shot("tree-blocked")
        out = alice(f"{real} _panel | grep '^block'")
        print(out)
        assert "block\ttreebox\tyoutube.com\tlocal" in out, out
        # The container's page: what is blocked for it, to unblock.
        names = [l.split("\t")[1] for l in alice(f"{real} _panel").splitlines() if l.startswith("container\t")]
        downs = " ".join(["-k Down"] * (names.index("treebox") + 1))
        alice(f"WAYLAND_DISPLAY={nested} wtype -s 400 -k Right {downs}")
        machine.sleep(2)
        shot("tree-container-page")
        print(alice("cat /tmp/tree-calls"))
    alice("systemctl --user stop vmtree", check=False)
    machine.sleep(2)


if os.environ.get("VM_DESKTOP_RECORD"):
    alice("systemctl --user kill -s INT vmrec", check=False)
    # Done once its file stops growing (it writes the index last).
    machine.wait_until_succeeds(
        "test -s /tmp/desktop.mp4 && a=$(stat -c %s /tmp/desktop.mp4) && sleep 2 "
        "&& test \"$a\" = \"$(stat -c %s /tmp/desktop.mp4)\"",
        timeout=60,
    )
    machine.copy_from_vm("/tmp/desktop.mp4", "")

print("FAILED:", FAILED)
# Every scenario ran, with its screenshots kept; any one failed fails the test.
# (A run of some scenarios only keeps its screenshots whatever came of them.)
assert not FAILED or ONLY, FAILED
