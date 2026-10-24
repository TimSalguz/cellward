#!/usr/bin/env python3
"""Exercise target selection and input on an isolated headless sway, no VM.

Needs sway, swaymsg, foot and libxkbcommon on this machine. All sockets,
configuration and terminal output live in one temporary directory.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

PREFIX = b"\0cellward-type-1"


def wait_for(check, timeout=15):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        value = check()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("timed out waiting for test condition")


def packet(sock, obj, opcode, data=b"", fd=None):
    wire = struct.pack("=II", obj, ((len(data) + 8) << 16) | opcode) + data
    ancillary = [] if fd is None else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", fd))]
    sock.sendmsg([wire], ancillary)


def wl_string(text):
    data = text.encode() + b"\0"
    return struct.pack("=I", len(data)) + data + b"\0" * (-len(data) % 4)


def keyboard(env, library):
    """Hold a virtual US keyboard so headless sway has keyboard capability."""
    lib = ctypes.CDLL(library)
    lib.xkb_context_new.argtypes = [ctypes.c_int]
    lib.xkb_context_new.restype = ctypes.c_void_p
    lib.xkb_keymap_new_from_names.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
    lib.xkb_keymap_new_from_names.restype = ctypes.c_void_p
    lib.xkb_keymap_get_as_string.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.xkb_keymap_get_as_string.restype = ctypes.c_char_p
    context = lib.xkb_context_new(0)
    keymap = lib.xkb_keymap_new_from_names(context, None, 0)
    assert context and keymap
    text = lib.xkb_keymap_get_as_string(keymap, 1) + b"\0"
    sock = socket.socket(socket.AF_UNIX)
    sock.connect(str(Path(env["XDG_RUNTIME_DIR"]) / env["WAYLAND_DISPLAY"]))
    packet(sock, 1, 1, struct.pack("=I", 2))
    packet(sock, 1, 0, struct.pack("=I", 3))
    received = b""
    names = {}
    done = False
    while not done:
        received += sock.recv(65536)
        while len(received) >= 8:
            obj, word = struct.unpack_from("=II", received)
            size, opcode = word >> 16, word & 0xFFFF
            if len(received) < size:
                break
            data, received = received[8:size], received[size:]
            if obj == 2 and opcode == 0:
                name, length = struct.unpack_from("=II", data)
                names[data[8:8 + length - 1].decode()] = name
            if obj == 3 and opcode == 0:
                done = True
    for interface, new in [("wl_seat", 4), ("zwp_virtual_keyboard_manager_v1", 5)]:
        packet(sock, 2, 0, struct.pack("=I", names[interface]) + wl_string(interface) + struct.pack("=II", 1, new))
    packet(sock, 5, 0, struct.pack("=II", 4, 6))
    fd = os.memfd_create("typing-test-keymap")
    os.write(fd, text)
    packet(sock, 6, 0, struct.pack("=II", 1, len(text)), fd)
    os.close(fd)
    return sock


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", required=True)
    parser.add_argument("--sway", default="sway")
    parser.add_argument("--swaymsg", default="swaymsg")
    parser.add_argument("--foot", default="foot")
    parser.add_argument("--xkbcommon", default="libxkbcommon.so.0")
    parser.add_argument("--grim")
    parser.add_argument("--window", help="also exercise the actual clipboard manager UI")
    parser.add_argument("--gui-only", action="store_true")
    parser.add_argument("--frame-history", action="store_true", help="exercise the launch-bound history window instead of the tray manager")
    parser.add_argument("--fonts", help="small font directory to avoid scanning the host font collection")
    args = parser.parse_args()
    if args.gui_only and not args.window:
        parser.error("--gui-only requires --window")
    root = Path(tempfile.mkdtemp(prefix="cellward-typing-smoke-"))
    print(f"Artifacts: {root}", flush=True)
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    processes = []
    files = []
    env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime), WLR_BACKENDS="headless",
               WLR_RENDERER="pixman", WLR_LIBINPUT_NO_DEVICES="1", XDG_CONFIG_HOME=str(root / "config"),
               XDG_STATE_HOME=str(root / "state"), DBUS_SESSION_BUS_ADDRESS=f"unix:path={root}/no-bus")
    env.pop("WAYLAND_SOCKET", None)
    env.pop("SWAYSOCK", None)
    env.pop("WAYLAND_DISPLAY", None)
    if args.fonts:
        fonts = root / "fonts.conf"
        fonts.write_text(f'<?xml version="1.0"?><!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd"><fontconfig><dir>{args.fonts}</dir><cachedir>{root}/font-cache</cachedir></fontconfig>')
        env["FONTCONFIG_FILE"] = str(fonts)
    config = root / "sway.conf"
    config.write_text('output * mode 1200x900\noutput * bg #202020 solid_color\nseat seat0 fallback true\ndefault_border none\nfocus_follows_mouse no\nfor_window [app_id="other-.*"] floating enable\nfor_window [app_id="vpn-zone-window"] floating enable\n')

    def start(command, name):
        log = open(root / f"{name}.log", "wb")
        files.append(log)
        process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        processes.append(process)
        return process

    def msg(*words):
        return subprocess.check_output([args.swaymsg, *words], env=env, text=True)

    def windows():
        def walk(node):
            if node.get("app_id"):
                yield node
            for n in node.get("nodes", []) + node.get("floating_nodes", []):
                yield from walk(n)
        return list(walk(json.loads(msg("-t", "get_tree"))))

    def connect(pid, payload):
        stream = socket.socket(socket.AF_UNIX)
        stream.settimeout(15)
        stream.connect(str(runtime / "vpn-zones/ask" / str(pid)))
        stream.sendall(struct.pack("<H", len(payload)) + payload)
        return stream

    try:
        start([args.sway, "--unsupported-gpu", "-c", str(config)], "sway")
        env["SWAYSOCK"] = str(wait_for(lambda: next(runtime.glob("sway-ipc*.sock"), None)))
        env["WAYLAND_DISPLAY"] = wait_for(lambda: next((p.name for p in runtime.glob("wayland-*") if not p.name.endswith(".lock")), None))
        vk = keyboard(env, args.xkbcommon)
        fifo = root / "pointer.fifo"
        start([sys.executable, str(Path(__file__).with_name("vm-pointer.py")), str(fifo), "1200", "900"], "pointer")
        wait_for(fifo.exists)
        pointer = open(fifo, "w", buffering=1)
        files.append(pointer)
        reader = "import sys,time; open(sys.argv[1],'wb').write(sys.stdin.buffer.readline()); time.sleep(60)"
        for mode, text in ([] if args.gui_only else [(0, "Ab Я🙂\n"), (1, "Ab! 12\n"), (2, "0123456789\n")]):
            output = root / f"typed-{mode}.txt"
            terminal = start([str(Path(args.core).resolve()), "wl-sandbox", f"typing-{mode}", "--frame", "ff00ff:4:always", "--",
                              args.foot, "--app-id", f"typing-target-{mode}", sys.executable, "-c", reader, str(output)], f"target-{mode}")
            marker = wait_for(lambda: next((p for p in (runtime / "vpn-zones/ask").glob("*.typing")), None) if (runtime / "vpn-zones/ask").exists() else None)
            pid = int(marker.stem)
            target = wait_for(lambda: next((w for w in windows() if w["app_id"] == f"typing-target-{mode}"), None))
            token = 100 + mode
            selection = connect(pid, PREFIX + b"\0" + struct.pack("<Q", token))
            time.sleep(0.2)
            (root / f"selection-tree-{mode}.json").write_text(msg("-t", "get_tree"))
            (root / f"selection-inputs-{mode}.json").write_text(msg("-t", "get_inputs"))
            if args.grim:
                subprocess.run([args.grim, str(root / f"selection-{mode}.png")], env=env, check=True)
            rect = target["rect"]
            pointer.write(f"move {rect['x'] + rect['width'] // 2} {rect['y'] + rect['height'] // 2}\n")
            time.sleep(0.1)
            pointer.write("press\nrelease\n")
            assert selection.recv(1) == b"y", "the overlay did not select its point"
            selection.close()
            # The chosen window need not have compositor focus while typing.
            other_output = root / f"other-{mode}.txt"
            other = start([args.foot, "--app-id", f"other-{mode}", sys.executable, "-c", reader, str(other_output)], f"other-{mode}")
            wait_for(lambda: any(w["app_id"] == f"other-{mode}" for w in windows()))
            request = PREFIX + b"\1" + struct.pack("<QHHHB", token, 100, 150 if mode == 2 else 20, 5, min(mode, 1) if mode != 2 else 0) + text.encode()
            run = connect(pid, request)
            if mode != 2:
                # Previously only a pre-start focus change was exercised.
                # Enter/leave while keys are already being emitted must not
                # cancel the run or deliver the suffix to another window.
                time.sleep(0.12)
                msg(f"[con_id={target['id']}]", "focus")
                time.sleep(0.08)
                msg(f"[app_id=other-{mode}]", "focus")
            if mode == 2:
                time.sleep(0.4)
                cancel = connect(pid, PREFIX + b"\2" + struct.pack("<Q", token))
                assert cancel.recv(1) == b"y", "cancel request was refused"
                cancel.close()
                assert run.recv(1) == b"n", "in-progress input was not canceled"
                msg(f"[con_id={target['id']}]", "focus")
                time.sleep(0.1)
                # A physical US 'a' and Return prove the old keymap returned.
                for key in [30, 28]:
                    for down in [1, 0]:
                        packet(vk, 6, 1, struct.pack("=III", int(time.monotonic() * 1000) & 0xFFFFFFFF, key, down))
                        time.sleep(0.02)
            else:
                reply = run.recv(1)
                assert reply == b"y", f"typing did not complete: {reply!r}"
            run.close()
            wait_for(lambda: output.exists() and output.stat().st_size)
            actual = output.read_bytes()
            if mode == 2:
                assert actual.endswith(b"a\n") and len(actual) < len(text), f"cancel or restored keymap failed: {actual!r}"
                assert text.encode().startswith(actual[:-2]), f"wrong canceled prefix: {actual!r}"
            else:
                assert actual == text.encode(), f"wrong characters: {actual!r}"
            assert not other_output.exists() or other_output.stat().st_size == 0, "typing reached the wrong window"
            # A wrong token cannot redirect or consume the remembered point.
            stale = connect(pid, PREFIX + b"\1" + struct.pack("<QHHHB", token + 999, 0, 1, 1, 0) + b"x")
            assert stale.recv(1) != b"y", "an unrelated target token was accepted"
            stale.close()
            if mode != 2:
                again = connect(pid, PREFIX + b"\1" + struct.pack("<QHHHB", token, 0, 1, 1, 0) + b" ")
                assert again.recv(1) == b"y", "the remembered point could not be reused"
                again.close()
            canceled = connect(pid, PREFIX + b"\2" + struct.pack("<Q", token))
            assert canceled.recv(1) == b"y"
            canceled.close()
            stale = connect(pid, request)
            assert stale.recv(1) != b"y", "a canceled point was reused"
            stale.close()
            print(f"mode {mode}: {'cancellation restores the keymap' if mode == 2 else 'correct text across focus change; point remembered'}, stale target refused", flush=True)
            for process in [terminal, other]:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
            wait_for(lambda: not marker.exists())
        if args.window:
            output = root / "gui-typed.txt"
            terminal = start([str(Path(args.core).resolve()), "wl-sandbox", "typing-gui", "--frame", "ff00ff:4:always", "--",
                              args.foot, "--app-id", "typing-gui", sys.executable, "-c", reader, str(output)], "gui-target")
            wait_for(lambda: any(w["app_id"] == "typing-gui" for w in windows()))
            daemon = socket.socket(socket.AF_UNIX)
            daemon.bind(str(runtime / "cellward-clip.sock"))
            daemon.listen()
            daemon.settimeout(0.2)
            stop = threading.Event()
            requests = []
            text = "Manager Я🙂\n"
            def serve():
                while not stop.is_set():
                    try:
                        client, _ = daemon.accept()
                    except socket.timeout:
                        continue
                    with client:
                        data = b""
                        while b"\n" not in data:
                            chunk = client.recv(4096)
                            if not chunk:
                                break
                            data += chunk
                        line = data.decode().strip()
                        requests.append(line)
                        if line == "histories":
                            client.sendall(b"host\n")
                        elif line.startswith("search\t"):
                            label = "Пароль: Test account" if "@secrets:" in line else "GUI input"
                            client.sendall(f"1\t1000\t1000\t1\t0\t0\ttext/plain:{len(text.encode())}\t{label}\n".encode())
                        elif line.startswith("get\t"):
                            client.sendall(f"ok\t{len(text.encode())}\n".encode() + text.encode())
                        else:
                            client.sendall(b"error\tunexpected test request\n")
            server = threading.Thread(target=serve, daemon=True)
            server.start()
            gui_marker = wait_for(lambda: next((runtime / "vpn-zones/ask").glob("*.typing"), None))
            gui_args = ["--history", "host", "--launch", gui_marker.stem] if args.frame_history else ["--manager"]
            manager = start([str(Path(args.window).resolve()), "clip", *gui_args], "manager")
            manager_window = wait_for(lambda: next((w for w in windows() if w["app_id"] == "vpn-zone-window"), None))
            time.sleep(0.3)
            manager_window = next(w for w in windows() if w["app_id"] == "vpn-zone-window")
            def click(x, y):
                pointer.write(f"move {x} {y}\n")
                time.sleep(0.05)
                pointer.write("press\n")
                time.sleep(0.03)
                pointer.write("release\n")
                time.sleep(0.2)
            def screenshot(name):
                if args.grim:
                    subprocess.run([args.grim, str(root / f"{name}.png")], env=env, check=True)
            screenshot("manager-start")
            (root / "manager-tree.json").write_text(json.dumps(manager_window, indent=2))
            rect = dict(manager_window["rect"])
            rect["x"] += (rect["width"] - manager_window["window_rect"]["width"]) // 2
            rect["y"] += rect["height"] - manager_window["window_rect"]["height"] - 1
            tab_offset = -36 if args.frame_history else 0
            click(rect["x"] + 25, rect["y"] + 95 + tab_offset)
            screenshot("manager-typing-controls")
            click(rect["x"] + 110, rect["y"] + 126 + tab_offset)
            wait_for(lambda: not any(w["app_id"] == "vpn-zone-window" for w in windows()))
            time.sleep(0.3)
            screenshot("manager-point-overlay")
            click(600, 450)
            wait_for(lambda: any(w["app_id"] == "vpn-zone-window" for w in windows()))
            time.sleep(0.2)
            screenshot("manager-point-chosen")
            click(rect["x"] + 225, rect["y"] + 63 + tab_offset)
            screenshot("manager-password-selected")
            for key in [103, 28]:
                for down in [1, 0]:
                    packet(vk, 6, 1, struct.pack("=III", int(time.monotonic() * 1000) & 0xFFFFFFFF, key, down))
                    time.sleep(0.05)
            wait_for(lambda: output.exists() and output.stat().st_size)
            assert output.read_bytes() == text.encode(), "manager typed wrong contents"
            assert any(line.startswith("get\t@secrets:host\t") for line in requests), "password tab was not used"
            assert not any(line.startswith("select\t") for line in requests), "typing changed the clipboard selection"
            time.sleep(0.2)
            screenshot("manager-typed")
            stop.set()
            server.join(timeout=2)
            daemon.close()
            print("manager UI: point selected, window reopened, entry typed without clipboard mutation", flush=True)
        vk.close()
        print("typing smoke passed", flush=True)
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
        for file in files:
            file.close()
        # Keep failure logs and outputs for review; callers can remove this
        # exact temporary directory after inspecting it.


if __name__ == "__main__":
    main()
