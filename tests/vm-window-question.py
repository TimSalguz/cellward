"""tests/vm-window.nix, continued: the network question on the program's own
window (docs/FIREWALL.md §4.3.1, the owner's decision of 2026-09-29).

A program in the host's own network opens a connection its rules ask
about; the instance's keeper asks on the launch's socket of questions, its
supervisor hands the question to the Wayland proxy, and the proxy shows a
panel under the window's title: «Запретить», «Разрешить, пока
работает», and «Разрешить всегда». A click too soon is none; after the
countdown «Запретить» is the answer, a rule, and «Разрешить, пока
работает» one for this run. (A
program with no window is asked in the launch window: tests/vm-niri-question.py.)

Executed by the main test script with exec(), in its globals: machine,
alice, display, swaysock, find, view, shot, width, title; POINTER, the
command of tests/vm-pointer.py.
"""

fifo = "/tmp/vm-pointer-q"
# A rule of the container's record (rust/src/netrules.rs), in the config.
RULES = "/home/alice/.config/vpn-zones/"
DENIED = "grep -rEq '^net_deny *= *[^ ]' " + RULES


def qpointer(*words):
    alice(f"echo {' '.join(str(w) for w in words)} > {fifo}")
    machine.sleep(0.4)


def fast_click(x, y):
    """One ordered pointer batch, before the panel's guard expires."""
    alice(f"printf 'move {x} {y}\\npress\\nrelease\\n' > {fifo}")


def panel_of(before, after, x, y, w):
    """The panel's box on the screen: where `after` differs from `before`
    under the title strip, within the window's width and a panel's
    height."""
    top = y + width + title
    changed = [
        (c, r)
        for r in range(top, top + 200)
        for c in range(x, x + w)
        if after(c, r) != before(c, r)
    ]
    if len(changed) < 2000:
        return None
    cs = [c for c, _ in changed]
    rs = [r for _, r in changed]
    return min(cs), min(rs), max(cs), max(rs)


def buttons_of(at, box):
    """The panel's two upper buttons and one lower button as
    (left, right, row), detected against the panel's own colour."""
    x0, y0, x1, y1 = box
    bg = at(x0 + 3, y0 + 3)
    def at_row(row):
        runs, start = [], None
        for c in range(x0 + 2, x1 - 1):
            inside = at(c, row) != bg
            if inside and start is None:
                start = c
            if not inside and start is not None:
                runs.append((start, c - 1, row))
                start = None
        if start is not None:
            runs.append((start, x1 - 2, row))
        return [r for r in runs if r[1] - r[0] > 30]

    upper = at_row(y1 - 60)
    lower = at_row(y1 - 26)
    assert len(upper) == 2 and len(lower) == 1, (upper, lower, box)
    return upper + lower


def ask_window(app_id, target):
    """A foot in the host's network whose shell connects to `target` a
    while after its window is up; its window floating, known place."""
    alice(
        f"systemd-run --user --unit=vm{app_id} --setenv=WAYLAND_DISPLAY={display} "
        f"cellward run host -- foot --app-id {app_id} bash -c "
        f"'sleep 4; exec 3<>/dev/tcp/{target}/80 && echo CONNECTED || echo REFUSED; sleep 600'"
    )
    machine.wait_until_succeeds(
        f"su -l alice -c 'SWAYSOCK={swaysock} swaymsg -t get_tree' "
        f"| grep -q '\"app_id\": *\"{app_id}\"'",
        timeout=90,
    )
    alice(
        f"SWAYSOCK={swaysock} swaymsg '[app_id={app_id}] floating enable, "
        "resize set 640 400, move position 100 100, focus'"
    )
    qpointer("move", 5, 5)
    for _ in range(20):
        x, y, w, h = view(app_id)
        # The sway command can return before the move/resize is visible.
        # Without the geometry check x=y=0 and the pointer at (5, 5)
        # makes an otherwise blank screenshot look non-empty.
        if x >= 100 and y >= 100:
            before = shot(f"question-{app_id}-before")
            if before(x + w // 2, y + h // 2) != (0, 0, 0):
                return x, y, w, h, before
        machine.sleep(0.2)
    raise AssertionError("the program's window was not drawn")


def await_panel(name, before, x, y, w):
    for _ in range(60):
        at = shot(name)
        box = panel_of(before, at, x, y, w)
        if box is not None:
            return at, box
        machine.sleep(1)
    raise AssertionError("no panel on the program's window")


output = json.loads(alice(f"SWAYSOCK={swaysock} swaymsg -t get_outputs -r"))[0]["rect"]
alice(
    f"systemd-run --user --unit=vmpointerq --setenv=WAYLAND_DISPLAY={display} "
    f"{POINTER} {fifo} {output['width']} {output['height']}"
)
machine.wait_until_succeeds(f"test -p {fifo}", timeout=30)

with subtest("the network question is a panel on the program's window; a hasty click is none"):
    x, y, w, h, before = ask_window("askq", "192.0.2.10")
    at, box = await_panel("question-panel", before, x, y, w)
    x0, y0, x1, y1 = box
    panel_sample = (x0 + 5, y0 + 5)
    panel_color = at(*panel_sample)
    deny, more, always = buttons_of(at, box)
    # Click promptly: namespace and process diagnostics below can take
    # longer than the guard when QEMU runs without KVM.
    fast_click((deny[0] + deny[1]) // 2, deny[2])
    machine.sleep(2)
    machine.fail("pgrep -x vpn-zone-window")
    assert shot("question-hasty")(*panel_sample) == panel_color, "the panel went"
    # The proxy that shows it is in namespaces of its own, its root empty
    # (rust/src/wl_proxy.rs `isolate`).
    tree = json.loads(alice(f"SWAYSOCK={swaysock} swaymsg -t get_tree -r"))
    sup = find(tree, "askq")["pid"]
    proxy = machine.succeed(f"pgrep -P {sup} -x vz-wl-proxy").split()[0]
    for ns in ["user", "net", "mnt", "ipc", "uts"]:
        own = machine.succeed(f"readlink /proc/{proxy}/ns/{ns}").strip()
        its = machine.succeed(f"readlink /proc/{sup}/ns/{ns}").strip()
        assert own != its, (ns, own, its)
    assert machine.succeed(f"ls -A /proc/{proxy}/root/").strip() == "", "the host's tree"
    # Under the title strip, in the window's middle.
    assert y0 >= y + width + title - 1, (box, y)
    assert abs((x0 + x1) / 2 - (x + w / 2)) <= 4, (box, x, w)
    # «Запретить» after the guard: the answer — a rule, and no network.
    qpointer("move", (deny[0] + deny[1]) // 2, deny[2])
    machine.sleep(2.5)
    qpointer("press")
    qpointer("release")
    machine.wait_until_succeeds(DENIED, timeout=30)
    assert shot("question-answered")(*panel_sample) != panel_color, "the panel stayed"
    machine.fail("pgrep -x vpn-zone-window")
    alice("systemctl --user stop vmaskq")

with subtest("«Разрешить, пока работает» answers on the panel after its countdown: no second window"):
    # The rule of the last subtest is the program's: this one is asked
    # about anew once it is gone.
    alice(f"grep -rlE '^net_deny *=' {RULES} | xargs -r sed -i -E '/^net_deny *=/d'")
    machine.fail(DENIED)
    x, y, w, h, before = ask_window("askr", "192.0.2.11")
    at, box = await_panel("question-panel-2", before, x, y, w)
    x0, y0, x1, y1 = box
    panel_sample = (x0 + 5, y0 + 5)
    panel_color = at(*panel_sample)
    deny, more, always = buttons_of(at, box)
    # Too soon: nothing, and the panel stays — no launch window either,
    # however long it is up (no hand-over by time, 2026-10-15).
    fast_click((more[0] + more[1]) // 2, more[2])
    machine.sleep(2)
    assert shot("question-allow-hasty")(*panel_sample) == panel_color, "the panel went"
    # After its countdown: the answer — for this run, no rule kept.
    machine.sleep(2.5)
    qpointer("press")
    qpointer("release")
    machine.sleep(2)
    assert shot("question-allowed")(*panel_sample) != panel_color, "the panel stayed"
    machine.fail("pgrep -x vpn-zone-window")
    machine.fail(DENIED)
    machine.fail("grep -rEq '^net_allow *= *[^ ]' " + RULES)
    alice("systemctl --user stop vmaskr")
    alice("systemctl --user stop vmpointerq")
