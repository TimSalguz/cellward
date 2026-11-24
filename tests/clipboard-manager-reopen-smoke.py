#!/usr/bin/env python3
"""Reactivate the real tray-owned manager on the current private-sway workspace."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time


def wait_for(test, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = test()
        if value:
            return value
        time.sleep(.05)
    raise AssertionError("condition timed out")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("window", "clip", "sway", "swaymsg", "grim", "busctl", "dbus-daemon", "font"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="cellward-clip-reopen-"))
    print("Artifacts:", root, flush=True)
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    home = root / "home"
    home.mkdir()
    fonts = root / "fonts.conf"
    fonts.write_text("<fontconfig><dir>" + str(Path(args.font).resolve().parent)
                     + "</dir><cachedir>" + str(root / "font-cache") + "</cachedir></fontconfig>")
    bus = root / "bus"
    env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime), HOME=str(home),
               XDG_CONFIG_HOME=str(root / "config"), XDG_STATE_HOME=str(root / "state"),
               FONTCONFIG_FILE=str(fonts), WLR_BACKENDS="headless", WLR_RENDERER="pixman",
               WLR_LIBINPUT_NO_DEVICES="1", LP_NUM_THREADS="1", LIBGL_ALWAYS_SOFTWARE="1",
               DBUS_SESSION_BUS_ADDRESS=f"unix:path={bus}", CELLWARD_CLIP_WINDOW=args.window)
    for name in ("WAYLAND_DISPLAY", "WAYLAND_SOCKET", "SWAYSOCK", "NIRI_SOCKET", "DISPLAY"):
        env.pop(name, None)
    env["PATH"] = str(Path(args.swaymsg).resolve().parent) + ":" + env.get("PATH", "")
    processes, logs = [], []

    def start(command, name):
        log = open(root / (name + ".log"), "wb")
        logs.append(log)
        child = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                                 stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        processes.append(child)
        return child

    def msg(*command):
        return subprocess.check_output([args.swaymsg, *command], env=env, text=True)

    def windows():
        def walk(node, workspace=None):
            if node.get("type") == "workspace":
                workspace = node.get("name")
            if node.get("app_id"):
                yield node, workspace
            for child in node.get("nodes", []) + node.get("floating_nodes", []):
                yield from walk(child, workspace)
        return list(walk(json.loads(msg("-t", "get_tree", "-r"))))

    def managers():
        return [(window, workspace) for window, workspace in windows()
                if window.get("app_id") == "vpn-zone-window" and window.get("name") == "Буферы Cellward"]

    def activate():
        subprocess.run([args.busctl, f"--address=unix:path={bus}", "call",
                        f"org.kde.StatusNotifierItem-{daemon.pid}-1", "/StatusNotifierItem",
                        "org.kde.StatusNotifierItem", "Activate", "ii", "0", "0"],
                       env=env, check=True, stdout=subprocess.DEVNULL, timeout=5)

    try:
        config = root / "sway.conf"
        config.write_text("output * mode 1000x700\noutput * bg #202020 solid_color\n"
                          "seat seat0 fallback true\ndefault_border none\nfocus_follows_mouse no\n")
        start([args.sway, "--unsupported-gpu", "-c", str(config)], "sway")
        env["WAYLAND_DISPLAY"] = wait_for(lambda: next((p.name for p in runtime.glob("wayland-*")
                                                       if not p.name.endswith(".lock")), None))
        env["SWAYSOCK"] = str(wait_for(lambda: next(runtime.glob("sway-ipc*.sock"), None)))
        start([args.dbus_daemon, "--session", "--nofork", f"--address=unix:path={bus}"], "dbus")
        wait_for(bus.exists)
        daemon = start([args.clip, "daemon"], "clipd")
        wait_for((runtime / "cellward-clip.sock").exists)
        activate()
        first, first_workspace = wait_for(lambda: next((m for m in managers() if m[0].get("focused")), None))
        assert first_workspace == "1"
        time.sleep(.4)
        subprocess.run([args.grim, str(root / "first-open.png")], env=env, check=True)
        msg("workspace 2")
        wait_for(lambda: managers() and not managers()[0][0].get("focused"))
        activate()
        second, second_workspace = wait_for(lambda: next((m for m in managers() if m[0].get("focused")), None))
        assert second["id"] == first["id"], "reinvocation opened another manager window"
        assert second["pid"] == first["pid"], "reinvocation started another manager process"
        assert second_workspace == "2", f"manager stayed on workspace {second_workspace}"
        assert len(managers()) == 1
        subprocess.run([args.grim, str(root / "after-reopen.png")], env=env, check=True)
        print("PASS: tray reactivation moves and focuses the same manager on the current workspace", flush=True)
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        for process in reversed(processes):
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        for log in logs:
            log.close()


if __name__ == "__main__":
    main()
