#!/usr/bin/env python3
"""Compare Satellite MIME forwarding directly and behind Cellward on private sway.

Only synthetic offers are used. The desktop's clipboard is never accessed.
"""
import argparse
import ctypes as c
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


def probe(display, library, output):
    x = c.CDLL(library)
    P, L = c.c_void_p, c.c_ulong
    for name, args, ret in [
        ("XOpenDisplay", [c.c_char_p], P), ("XDefaultRootWindow", [P], L),
        ("XCreateSimpleWindow", [P, L, c.c_int, c.c_int, c.c_uint, c.c_uint, c.c_uint, L, L], L),
        ("XMapWindow", [P, L], c.c_int), ("XFlush", [P], c.c_int),
        ("XInternAtom", [P, c.c_char_p, c.c_int], L),
        ("XConvertSelection", [P, L, L, L, L, L], c.c_int),
        ("XPending", [P], c.c_int), ("XNextEvent", [P, P], c.c_int),
        ("XGetWindowProperty", [P, L, L, c.c_long, c.c_long, c.c_int, L, c.POINTER(L), c.POINTER(c.c_int), c.POINTER(L), c.POINTER(L), c.POINTER(P)], c.c_int),
        ("XGetAtomName", [P, L], P), ("XFree", [P], c.c_int),
    ]:
        f = getattr(x, name)
        f.argtypes, f.restype = args, ret
    d = x.XOpenDisplay(display.encode())
    assert d, "test X display unavailable"
    w = x.XCreateSimpleWindow(d, x.XDefaultRootWindow(d), 0, 0, 400, 300, 0, 0, 0)
    x.XMapWindow(d, w)
    x.XFlush(d)
    atom = lambda s: x.XInternAtom(d, s.encode(), 0)
    image_request = False
    while True:
        target = "image/png" if image_request else "TARGETS"
        x.XConvertSelection(d, atom("CLIPBOARD"), atom(target), atom("PROBE"), w, 0)
        x.XFlush(d)
        until = time.monotonic() + 1
        while time.monotonic() < until:
            if not x.XPending(d):
                time.sleep(.02)
                continue
            event = (c.c_long * 24)()
            x.XNextEvent(d, c.byref(event))
            if c.cast(event, c.POINTER(c.c_int))[0] != 31:
                continue
            typ, fmt, n, left, data = L(), c.c_int(), L(), L(), P()
            x.XGetWindowProperty(d, w, atom("PROBE"), 0, 4096, 1, 0, c.byref(typ), c.byref(fmt), c.byref(n), c.byref(left), c.byref(data))
            names = []
            if not image_request and data and fmt.value == 32:
                for a in c.cast(data, c.POINTER(L))[:n.value]:
                    p = x.XGetAtomName(d, a)
                    if p:
                        names.append(c.string_at(p).decode(errors="replace"))
                        x.XFree(p)
            if image_request:
                body = c.string_at(data, n.value) if data and fmt.value == 8 else b""
                Path(output + ".body").write_text(json.dumps({"bytes": len(body), "matches": body == b"synthetic clipboard payload"}))
            else:
                Path(output).write_text(json.dumps(names))
            if data:
                x.XFree(data)
            break
        image_request = not image_request
        time.sleep(.1)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for tool in ["core", "sway", "satellite", "wl-copy", "xkbcommon", "x11", "foot"]:
        p.add_argument("--" + tool, required=True)
    args = p.parse_args()
    spec = importlib.util.spec_from_file_location("typing_smoke", Path(__file__).with_name("typing-smoke.py"))
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    root = Path(tempfile.mkdtemp(prefix="cellward-clipboard-bridge-"))
    print(f"Artifacts: {root}", flush=True)
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime), XDG_CONFIG_HOME=str(root / "config"), XDG_STATE_HOME=str(root / "state"), WLR_BACKENDS="headless", WLR_RENDERER="pixman", WLR_LIBINPUT_NO_DEVICES="1", DBUS_SESSION_BUS_ADDRESS=f"unix:path={root}/no-bus")
    for key in ["WAYLAND_DISPLAY", "WAYLAND_SOCKET", "SWAYSOCK", "DISPLAY"]:
        env.pop(key, None)
    config = root / "sway.conf"
    config.write_text('output * mode 800x600\nseat seat0 fallback true\ndefault_border none\n')
    processes, logs = [], []

    def start(cmd, name, payload=None):
        log = open(root / (name + ".log"), "wb")
        logs.append(log)
        proc = subprocess.Popen(cmd, env=env, stdout=log, stderr=log, stdin=subprocess.PIPE if payload is not None else None, start_new_session=True)
        processes.append(proc)
        if payload is not None:
            proc.stdin.write(payload)
            proc.stdin.close()
        return proc

    try:
        start([args.sway, "--unsupported-gpu", "-c", str(config)], "sway")
        env["WAYLAND_DISPLAY"] = helper.wait_for(lambda: next((f.name for f in runtime.glob("wayland-*") if not f.name.endswith(".lock")), None))
        vk = helper.keyboard(env, args.xkbcommon)
        for mode in ["direct", "proxy"]:
            number = next(n for n in range(390, 490) if not Path(f"/tmp/.X11-unix/X{n}").exists() and not Path(f"/tmp/.X{n}-lock").exists())
            command = [args.satellite, f":{number}"]
            if mode == "proxy":
                command = [args.core, "wl-sandbox", "clipboard-test", "--frame", "ff00ff:1:always", "--", *command]
            sat = start(command, mode + "-satellite")
            helper.wait_for(lambda: Path(f"/tmp/.X11-unix/X{number}").exists())
            output = root / (mode + "-targets.json")
            client = start([sys.executable, __file__, "probe", f":{number}", args.x11, str(output)], mode + "-probe")
            helper.wait_for(output.exists)
            time.sleep(.5)
            for mime in ["text/plain", "image/png", "application/x-cellward-test-binary"]:
                copy = start([args.wl_copy, "--foreground", "--type", mime], mode + "-" + mime.replace("/", "-"), b"synthetic clipboard payload")
                def offered():
                    try:
                        return mime in json.loads(output.read_text())
                    except (ValueError, FileNotFoundError):
                        return False
                helper.wait_for(offered)
                print(f"{mode}: {mime} reaches focused X11 window", flush=True)
                if mime == "image/png":
                    body_path = Path(str(output) + ".body")
                    time.sleep(.5)
                    body = lambda: json.loads(body_path.read_text())
                    if mode == "proxy":
                        assert not body()["matches"], "foreign clipboard was read without a paste gesture"
                        import struct
                        helper.packet(vk, 6, 2, struct.pack("=IIII", 4, 0, 0, 0))
                        helper.packet(vk, 6, 1, struct.pack("=III", 1, 47, 1))
                        time.sleep(.05)
                        helper.packet(vk, 6, 1, struct.pack("=III", 2, 47, 0))
                        helper.packet(vk, 6, 2, struct.pack("=IIII", 0, 0, 0, 0))
                    helper.wait_for(lambda: body()["matches"])
                    print(f"{mode}: image transfer bytes match" + (" after Ctrl+V; background read blocked" if mode == "proxy" else ""), flush=True)
                copy.terminate()
                copy.wait(timeout=3)
            text_copy = start([args.wl_copy, "--foreground", "--type", "text/plain"], mode + "-before-focus", b"synthetic clipboard payload")
            helper.wait_for(lambda: "text/plain" in json.loads(output.read_text()))
            native = start([args.foot, "--app-id", "clipboard-native", "sh", "-c", "sleep 60"], mode + "-native")
            time.sleep(1)
            image_copy = start([args.wl_copy, "--foreground", "--type", "image/png"], mode + "-unfocused-image", b"synthetic clipboard payload")
            time.sleep(1)
            assert "image/png" not in json.loads(output.read_text()), "unexpected X11 update while native Wayland window is focused"
            print(f"{mode}: Wayland focus leaves X11 offer stale (terminal/CLI scenario)", flush=True)
            os.killpg(native.pid, signal.SIGTERM)
            native.wait(timeout=3)
            helper.wait_for(lambda: "image/png" in json.loads(output.read_text()))
            print(f"{mode}: focusing X11 restores current image offer", flush=True)
            image_copy.terminate()
            image_copy.wait(timeout=3)
            text_copy.terminate()
            text_copy.wait(timeout=3)
            os.killpg(client.pid, signal.SIGTERM)
            client.wait(timeout=3)
            os.killpg(sat.pid, signal.SIGTERM)
            sat.wait(timeout=3)
        vk.close()
    finally:
        for proc in reversed(processes):
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
        for log in logs:
            log.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "probe":
        probe(*sys.argv[2:])
    else:
        main()
