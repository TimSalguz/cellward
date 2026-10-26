"""Executed by vm-window.nix --arg clipboardOnly true, history disabled."""
import hashlib
import json


def clipboard_start(unit, command):
    return alice(
        f"systemd-run --user --unit={unit} --setenv=WAYLAND_DISPLAY={display} " + command
    )


def clipboard_status(container, name, network="offline"):
    command = f"cellward run {network} --container {container} -- cat /tmp/{name}.json"
    try:
        return json.loads(alice(command))
    except Exception:
        return None


def clipboard_body(container, name, mime, network="offline"):
    status = clipboard_status(container, name, network)
    return status and status["bodies"].get(mime)


def clipboard_holder(container):
    key = 0xCBF29CE484222325
    for byte in container.encode():
        key = ((key ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return alice(f"cat {state}/.instances/i-{key:016x}/instance.pid").strip()


with subtest("default launches use private CLIPBOARD and PRIMARY without history"):
    alice("cellward container create vmclip --home layer")
    alice("cellward container create vmclipother --home layer")
    reader = f"python3 {clipboard_fixtures}/clipboard-reverse-smoke.py reader"
    clipboard_start("clip-observer", f"{reader} /tmp/clip-host.json yes")
    clipboard_start("clip-same", f"cellward run offline --container vmclip -- {reader} /tmp/clip-same.json")
    clipboard_start("clip-primary", f"cellward run offline --container vmclip -- {reader} /tmp/clip-primary.json no yes")
    clipboard_start("clip-other", f"cellward run offline --container vmclipother -- {reader} /tmp/clip-other.json")
    clipboard_start("clip-owner", f"cellward run offline --container vmclip -- python3 {clipboard_fixtures}/private-clipboard-smoke.py owner")
    machine.wait_until_succeeds("su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 systemctl --user is-active cellward-clipboard.service'", timeout=60)
    # Import only the fixture payload definitions on the driver, not its main.
    import importlib.util
    spec = importlib.util.spec_from_file_location("clip_fixture", f"{clipboard_fixtures}/private-clipboard-smoke.py")
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    expected = {mime: {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
                for mime, payload in (("text/plain", fixture.TEXT), ("image/png", fixture.PNG))}
    import time
    deadline = time.monotonic() + 90
    while True:
        if all(clipboard_body("vmclip", name, mime) == body
               for name in ("clip-same", "clip-primary") for mime, body in expected.items()):
            break
        assert time.monotonic() < deadline, "container readers did not receive their own text/PNG"
        machine.sleep(1)
    assert clipboard_status("vmclipother", "clip-other")["types"] == []
    assert json.loads(machine.succeed("cat /tmp/clip-host.json"))["types"] == []
    machine.fail(f"test -e {state}/.clipboard")
    holder = clipboard_holder("vmclip")

with subtest("network switch preserves the same active clipboard"):
    alice("cellward up host")
    alice("cellward container set vmclip network host --yes")
    assert clipboard_holder("vmclip") == holder, "network switch replaced the instance holder"
    for name in ("clip-same", "clip-primary"):
        for mime, body in expected.items():
            assert clipboard_body("vmclip", name, mime, "host") == body
    assert json.loads(machine.succeed("cat /tmp/clip-host.json"))["types"] == []

with subtest("disabling history leaves active isolation enabled and no disk store"):
    # No history service exists in this VM: the active broker is independent.
    alice("systemctl --user is-active cellward-clipboard.service")
    machine.fail("su -l alice -c 'XDG_RUNTIME_DIR=/run/user/1000 systemctl --user is-active cellward-clip.service'")
    machine.fail(f"test -e {state}/.clipboard")

for unit in ("clip-owner", "clip-same", "clip-primary", "clip-other", "clip-observer"):
    alice(f"systemctl --user stop {unit}.service")
print("PASS: actual default container launches, native CLIPBOARD/PRIMARY, host/foreign isolation, network switch, history disabled")
