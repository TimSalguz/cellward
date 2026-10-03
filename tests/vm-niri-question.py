"""Real pointer input to permission panels on niri, nested in headless sway.

Use the supervisor's question socket to isolate input from network ownership.
The pointer and keyboard belong to the outer compositor: niri receives real
input through its winit backend, without needing an input-injection protocol.
"""

import json

outer = machine.succeed("ls /run/user/1000/sway-ipc.*.sock").strip()
niri_socket = machine.succeed("ls /run/user/1000/niri.*.sock").strip()
niri_cmd = f"NIRI_SOCKET={niri_socket} niri msg --json"
windows = json.loads(alice(f"{niri_cmd} windows"))
supervisor = next(w["pid"] for w in windows if w["app_id"] == "niri-foot")
output = json.loads(alice(f"SWAYSOCK={outer} swaymsg -t get_outputs -r"))[0]["rect"]
fifo = "/tmp/niri-question-pointer"
alice(
    f"systemd-run --user --unit=niri-question-pointer --setenv=WAYLAND_DISPLAY={sway} "
    f"{POINTER} {fifo} {output['width']} {output['height']}"
)
machine.wait_until_succeeds(f"test -p {fifo}", timeout=30)


def pointer(*words):
    alice(f"echo {' '.join(str(w) for w in words)} > {fifo}")
    machine.sleep(0.2)


def question(name):
    payload = "Network access?\0Deny\0Allow...".encode()
    code = (
        "import socket; s=socket.socket(socket.AF_UNIX); "
        f"s.connect('/run/user/1000/vpn-zones/ask/{supervisor}'); "
        f"s.sendall({(len(payload).to_bytes(2, 'little') + payload)!r}); "
        "s.settimeout(30); reply=s.recv(512); "
        f"open('/tmp/{name}.reply', 'wb').write(reply)"
    )
    python = POINTER.split()[0]
    alice(f"systemd-run --user --unit={name} {python} -c {shlex.quote(code)}")


def panel_buttons(at):
    # Prompt cells have a stable background, distinct from both foot and
    # the frame. Locate horizontal runs; glyphs lie above this scanline.
    runs = []
    w, h = at.size
    for y in range(y0 + 25, min(y0 + 220, h)):
        start = None
        row = []
        for x in range(w):
            if at(x, y) == (227, 2, 227):
                if start is None:
                    start = x
            elif start is not None:
                if x - start > 30:
                    row.append((start, x - 1))
                start = None
        if len(row) == 2:
            runs.append((row, y))
    assert runs, "permission panel buttons not found"
    return runs[-1]


with subtest("niri routes a deliberate pointer click to the permission panel"):
    pointer("move", 5, 5)
    question("niri-panel-deny")
    buttons, row = settled("niri-question", panel_buttons)
    left, right = buttons[0]
    pointer("move", (left + right) // 2, row)
    machine.sleep(2.5)
    pointer("press")
    pointer("release")
    machine.wait_until_succeeds("test -s /tmp/niri-panel-deny.reply", timeout=15)
    reply = machine.succeed("cat /tmp/niri-panel-deny.reply").strip()
    assert reply == "n" + nested, reply

with subtest("niri routes the permission panel's Allow button to the launch window"):
    pointer("move", 5, 5)
    question("niri-panel-allow")
    buttons, row = settled("niri-question-more", panel_buttons)
    left, right = buttons[1]
    pointer("move", (left + right) // 2, row)
    # Opening the separate guarded window must work with a normal click.
    pointer("press")
    pointer("release")
    machine.wait_until_succeeds("test -s /tmp/niri-panel-allow.reply", timeout=15)
    reply = machine.succeed("cat /tmp/niri-panel-allow.reply").strip()
    assert reply == "m" + nested, reply

with subtest("an unanswered panel hands off on niri, never silently denies or allows"):
    pointer("move", 5, 5)
    question("niri-panel-fallback")
    machine.wait_until_succeeds("test -s /tmp/niri-panel-fallback.reply", timeout=25)
    reply = machine.succeed("cat /tmp/niri-panel-fallback.reply").strip()
    assert reply == "m" + nested, reply

# The main-home guard correctly refuses foot in two networks at once.
# Finish the offline input probe before opening its host-network instance.
alice("systemctl --user stop vmfoot")
peer.wait_for_unit("permission-http.service")
peer.wait_until_succeeds("curl --fail http://192.0.2.2:8080/allowed", timeout=30)


def requested(path):
    return f"journalctl -u permission-http --no-pager | grep -F 'GET /{path} HTTP'"


def network_question(unit, path):
    # Unique launch keys avoid inheriting a previous program's session answer.
    command = (
        "sleep 4; exec 3<>/dev/tcp/192.0.2.2/8080; "
        f"printf 'GET /{path} HTTP/1.0\\r\\nHost: peer\\r\\n\\r\\n' >&3; "
        "cat <&3; sleep 600"
    )
    alice(
        f"systemd-run --user --unit={unit} --setenv=WAYLAND_DISPLAY={nested} "
        f"--setenv=VPN_ZONE_APPID={unit} "
        f"cellward run host -- foot --app-id {unit} bash -c {shlex.quote(command)}"
    )
    # Leave the panel unanswered: the supervisor must open a real guarded
    # question even when its caller's systemd environment has no display.
    machine.wait_until_succeeds("pgrep -x vpn-zone-window", timeout=90)
    win = machine.succeed("pgrep -x vpn-zone-window").strip()
    env = machine.succeed(f"tr '\\0' '\\n' < /proc/{win}/environ")
    assert f"WAYLAND_DISPLAY={nested}" in env.splitlines()
    peer.fail(requested(path))


with subtest("real TCP remains held until niri's guarded question is explicitly allowed"):
    network_question("niri-net-allow", "allowed?from=container")
    # The peer probe above requested another path; it cannot satisfy this.
    alice(f"WAYLAND_DISPLAY={sway} wtype -s 2000 -k Down -s 2000 -k Return")
    machine.wait_until_fails("pgrep -x vpn-zone-window", timeout=20)
    peer.wait_until_succeeds(requested("allowed?from=container"), timeout=30)
    alice("systemctl --user stop niri-net-allow")

with subtest("closing the network question keeps actual TCP closed"):
    network_question("niri-net-close", "closed")
    alice(f"WAYLAND_DISPLAY={sway} wtype -k Escape")
    machine.wait_until_fails("pgrep -x vpn-zone-window", timeout=20)
    machine.sleep(3)
    peer.fail(requested("closed"))
    alice("systemctl --user stop niri-net-close")

alice("systemctl --user stop niri-question-pointer")
