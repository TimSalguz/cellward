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
import struct
import zlib
import hashlib


def png_chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def png(rgb):
    return (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + png_chunk(b"IDAT", zlib.compress(b"\0" + bytes(rgb))) + png_chunk(b"IEND", b""))


PNG = png((64, 64, 64))
UPDATED_PNG = png((32, 96, 128))


def report(path, value):
    path = Path(path)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(value))
    temp.replace(path)


def probe(display, library, output, mapping="mapped"):
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
    if mapping == "mapped":
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
                report(output + ".body", {"bytes": len(body), "matches": body == PNG,
                                          "sha256": hashlib.sha256(body).hexdigest()})
            else:
                report(output, names)
            if data:
                x.XFree(data)
            break
        image_request = not image_request
        time.sleep(.1)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for tool in ["core", "sway", "swaymsg", "satellite", "wl-copy", "xkbcommon", "x11", "foot"]:
        p.add_argument("--" + tool, required=True)
    p.add_argument("--relay", action="store_true", help="also verify a terminal and Satellite within one launch")
    p.add_argument("--only-shared", action="store_true", help="run only same-launch regression cases")
    p.add_argument("--alacritty", help="use Alacritty instead of foot for the native terminal")
    args = p.parse_args()
    spec = importlib.util.spec_from_file_location("typing_smoke", Path(__file__).with_name("typing-smoke.py"))
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    root = Path(tempfile.mkdtemp(prefix="cellward-clipboard-bridge-"))
    print(f"Artifacts: {root}", flush=True)
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime), XDG_CONFIG_HOME=str(root / "config"), XDG_STATE_HOME=str(root / "state"), WLR_BACKENDS="headless", WLR_RENDERER="pixman", WLR_LIBINPUT_NO_DEVICES="1", LIBGL_ALWAYS_SOFTWARE="1", LP_NUM_THREADS="1", DBUS_SESSION_BUS_ADDRESS=f"unix:path={root}/no-bus")
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

    def focused(app_id):
        tree = json.loads(subprocess.check_output([args.swaymsg, "-t", "get_tree"], env=env))
        def walk(node):
            if node.get("focused") and node.get("app_id") == app_id:
                return True
            return any(walk(n) for n in node.get("nodes", []) + node.get("floating_nodes", []))
        return walk(tree)

    def terminal(app_id):
        if args.alacritty:
            return [args.alacritty, "--class", app_id, "-e", "sh", "-c", "sleep 60"]
        return [args.foot, "--app-id", app_id, "sh", "-c", "sleep 60"]

    try:
        start([args.sway, "--unsupported-gpu", "-c", str(config)], "sway")
        env["WAYLAND_DISPLAY"] = helper.wait_for(lambda: next((f.name for f in runtime.glob("wayland-*") if not f.name.endswith(".lock")), None))
        env["SWAYSOCK"] = str(helper.wait_for(lambda: next(runtime.glob("sway-ipc*.sock"), None)))
        vk = helper.keyboard(env, args.xkbcommon)
        modes = ([] if args.only_shared else ["direct", "proxy"]) + (["shared-proxy", "shared-proxy-unframed"] if args.relay else [])
        assert modes, "--only-shared requires --relay"
        for mode in modes:
            shared = mode.startswith("shared-proxy")
            control = root / mode
            control.mkdir()
            number = next(n for n in range(390, 490) if not Path(f"/tmp/.X11-unix/X{n}").exists() and not Path(f"/tmp/.X{n}-lock").exists())
            command = [args.satellite, f":{number}"]
            if mode == "proxy":
                command = [args.core, "wl-sandbox", "clipboard-test", "--frame", "ff00ff:1:always", "--", *command]
            elif shared:
                frame = [] if mode.endswith("unframed") else ["--frame", "ff00ff:1:always"]
                command = [args.core, "wl-sandbox", "clipboard-shared", *frame, "--",
                           sys.executable, __file__, "launch", args.satellite, f":{number}", json.dumps(terminal("clipboard-native")), str(control)]
            sat = start(command, mode + "-satellite")
            helper.wait_for(lambda: Path(f"/tmp/.X11-unix/X{number}").exists())
            if shared:
                (control / "native-go").touch()
                helper.wait_for(lambda: (control / "native-started").exists())
                helper.wait_for(lambda: focused("clipboard-native"))
            output = root / (mode + "-targets.json")
            client = start([sys.executable, __file__, "probe", f":{number}", args.x11, str(output), "unmapped" if shared else "mapped"], mode + "-probe")
            helper.wait_for(output.exists)
            time.sleep(.5)
            for mime in ["text/plain", "image/png", "application/x-cellward-test-binary"]:
                copy = start([args.wl_copy, "--foreground", "--type", mime], mode + "-" + mime.replace("/", "-"), PNG if mime == "image/png" else b"synthetic clipboard payload")
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
                    if mode != "direct":
                        assert body()["bytes"] == 0, "foreign clipboard was read without a paste gesture"
                        helper.packet(vk, 6, 2, struct.pack("=IIII", 4, 0, 0, 0))
                        helper.packet(vk, 6, 1, struct.pack("=III", 1, 47, 1))
                        time.sleep(.05)
                        helper.packet(vk, 6, 1, struct.pack("=III", 2, 47, 0))
                        helper.packet(vk, 6, 2, struct.pack("=IIII", 0, 0, 0, 0))
                    helper.wait_for(lambda: body()["matches"])
                    print(f"{mode}: image transfer bytes match" + (" after Ctrl+V; background read blocked" if mode != "direct" else ""), flush=True)
                copy.terminate()
                copy.wait(timeout=3)
            text_copy = start([args.wl_copy, "--foreground", "--type", "text/plain"], mode + "-before-focus", b"synthetic clipboard payload")
            helper.wait_for(lambda: "text/plain" in json.loads(output.read_text()))
            if shared:
                (control / "native-go").touch()
                helper.wait_for(lambda: (control / "native-started").exists())
                native = None
            else:
                native = start(terminal("clipboard-native"), mode + "-native")
            time.sleep(1)
            native_focused = lambda: focused("clipboard-native")
            helper.wait_for(native_focused)
            image_copy = start([args.wl_copy, "--foreground", "--type", "image/png"], mode + "-unfocused-image", UPDATED_PNG)
            time.sleep(1)
            if shared:
                helper.wait_for(lambda: "image/png" in json.loads(output.read_text()))
                body_path = Path(str(output) + ".body")
                time.sleep(2.1)
                assert json.loads(body_path.read_text())["bytes"] == 0, "relay allowed a foreign background payload read"
                helper.packet(vk, 6, 2, struct.pack("=IIII", 4 | 1, 0, 0, 0))
                helper.packet(vk, 6, 1, struct.pack("=III", 3, 47, 1))
                time.sleep(.05)
                helper.packet(vk, 6, 1, struct.pack("=III", 4, 47, 0))
                helper.packet(vk, 6, 2, struct.pack("=IIII", 0, 0, 0, 0))
                helper.wait_for(lambda: json.loads(body_path.read_text())["sha256"] == hashlib.sha256(UPDATED_PNG).hexdigest())
                assert native_focused(), "paste test accidentally focused an X11 window"
                print(f"{mode}: native-terminal Ctrl+Shift+V permits current X11 image; no X11 focus needed", flush=True)
                other = start([args.core, "wl-sandbox", "unrelated-launch", "--frame", "00ff00:1:always", "--",
                               *terminal("clipboard-unrelated")], mode + "-other")
                helper.wait_for(lambda: focused("clipboard-unrelated"))
                time.sleep(2.5)
                helper.packet(vk, 6, 2, struct.pack("=IIII", 4 | 1, 0, 0, 0))
                helper.packet(vk, 6, 1, struct.pack("=III", 5, 47, 1))
                time.sleep(.05)
                helper.packet(vk, 6, 1, struct.pack("=III", 6, 47, 0))
                helper.packet(vk, 6, 2, struct.pack("=IIII", 0, 0, 0, 0))
                time.sleep(.5)
                assert json.loads(body_path.read_text())["bytes"] == 0, "another launch's gesture authorized this X11 bridge"
                print(f"{mode}: another launch's paste does not authorize X11 reads", flush=True)
                os.killpg(other.pid, signal.SIGTERM)
                other.wait(timeout=3)
                (control / "native-stop").touch()
                helper.wait_for(lambda: (control / "native-stopped").exists())
            else:
                assert "image/png" not in json.loads(output.read_text()), "unexpected X11 update while native Wayland window is focused"
                print(f"{mode}: Wayland focus leaves X11 offer stale (terminal/CLI scenario)", flush=True)
                os.killpg(native.pid, signal.SIGTERM)
                native.wait(timeout=3)
            if not shared:
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
    elif len(sys.argv) > 1 and sys.argv[1] == "launch":
        satellite, display, native_command, root = sys.argv[2:]
        root = Path(root)
        child = subprocess.Popen([satellite, display])
        while not (root / "native-go").exists():
            assert child.poll() is None, "Satellite ended"
            time.sleep(.05)
        native = subprocess.Popen(json.loads(native_command))
        (root / "native-started").touch()
        while not (root / "native-stop").exists():
            assert native.poll() is None, "native terminal ended"
            time.sleep(.05)
        native.terminate()
        native.wait(timeout=3)
        (root / "native-stopped").touch()
        child.wait()
    else:
        main()
