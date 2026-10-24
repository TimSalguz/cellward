#!/usr/bin/env python3
"""Inspect thin rounded frames on real nested niri, without a VM or host IPC.

Requires a core built with VPN_ZONE_FRAME_FONT. Launches only private processes;
screenshots and logs stay in the printed temporary directory.
"""
import argparse
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import sys


def wait_for(fn, timeout=20):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = fn()
        if value:
            return value
        time.sleep(0.1)
    raise AssertionError("timed out waiting for nested compositor")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for tool in ["core", "sway", "swaymsg", "niri", "foot", "grim", "fonts"]:
        p.add_argument(f"--{tool}", required=True)
    p.add_argument("--hover-edge", type=int, default=2, choices=range(1, 13))
    p.add_argument("--resize-corner", type=int, default=16, choices=range(65))
    args = p.parse_args()
    root = Path(tempfile.mkdtemp(prefix="cellward-corners-"))
    print(f"Artifacts: {root}", flush=True)
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime), XDG_CONFIG_HOME=str(root / "config"),
               XDG_STATE_HOME=str(root / "state"), WLR_BACKENDS="headless", WLR_RENDERER="pixman",
               WLR_LIBINPUT_NO_DEVICES="1", LIBGL_ALWAYS_SOFTWARE="1",
               DBUS_SESSION_BUS_ADDRESS=f"unix:path={root}/no-bus")
    for key in ["WAYLAND_DISPLAY", "WAYLAND_SOCKET", "SWAYSOCK", "NIRI_SOCKET"]:
        env.pop(key, None)
    fontconfig = root / "fonts.conf"
    fontconfig.write_text(f'<?xml version="1.0"?><!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd"><fontconfig><dir>{args.fonts}</dir><cachedir>{root}/font-cache</cachedir></fontconfig>')
    env["FONTCONFIG_FILE"] = str(fontconfig)
    processes, logs = [], []

    def start(command, name):
        log = open(root / f"{name}.log", "wb")
        logs.append(log)
        proc = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        processes.append(proc)
        return proc

    try:
        sway = root / "sway.conf"
        sway.write_text("output * mode 1200x900\noutput * bg #202020 solid_color\nseat seat0 fallback true\ndefault_border none\n")
        start([args.sway, "--unsupported-gpu", "-c", str(sway)], "sway")
        env["SWAYSOCK"] = str(wait_for(lambda: next(runtime.glob("sway-ipc*.sock"), None)))
        env["WAYLAND_DISPLAY"] = wait_for(lambda: next((p.name for p in runtime.glob("wayland-*") if not p.name.endswith(".lock")), None))
        outer_display = env["WAYLAND_DISPLAY"]
        fifo = root / "pointer.fifo"
        start([sys.executable, str(Path(__file__).with_name("vm-pointer.py")), str(fifo), "1200", "900"], "pointer")
        wait_for(fifo.exists)
        pointer = open(fifo, "w", buffering=1)
        logs.append(pointer)
        time.sleep(0.2)
        niri = root / "niri.kdl"
        niri.write_text('output "winit" { scale 1.0; }\nlayout { gaps 30; focus-ring { off; }; border { off; }; default-column-width { fixed 640; }; }\nprefer-no-csd\nanimations { off; }\nhotkey-overlay { skip-at-startup; }\nwindow-rule { geometry-corner-radius 32; clip-to-geometry true; }\n')
        env["NIRI_CONFIG"] = str(niri)
        start([args.niri, "-c", str(niri)], "niri")
        env["NIRI_SOCKET"] = str(wait_for(lambda: next(runtime.glob("niri.*.sock"), None)))
        env["WAYLAND_DISPLAY"] = wait_for(lambda: next((p.name for p in runtime.glob("wayland-*") if not p.name.endswith(".lock") and p.name != outer_display), None))
        for mode in ["always", "hover"]:
            for width in [1, 4]:
                name = f"corners-{mode}-{width}"
                terminal = start([str(Path(args.core).resolve()), "wl-sandbox", name, "--frame",
                                  f"ff00ff:{width}:{mode}:cellward:full:niri32:niri32:same:hover:3:one:maximize:{args.hover_edge}:{args.resize_corner}",
                                  "--frame-title", f"Network: test | Container: {name}", "--",
                                  args.foot, "--app-id", name, "--font", "DejaVu Sans Mono:size=14",
                                  "sh", "-c", "printf 'Thin rounded frame\n'; sleep 120"], name)
                def mapped():
                    raw = subprocess.check_output([args.niri, "msg", "-j", "windows"], env=env)
                    return any(w.get("app_id") == name for w in json.loads(raw))
                wait_for(mapped)
                time.sleep(0.5)
                subprocess.run([args.grim, str(root / f"{name}.png")], env=env, check=True)
                ppm = subprocess.check_output([args.grim, "-t", "ppm", "-"], env=env)
                magic, size, depth, pixels = ppm.split(b"\n", 3)
                assert magic == b"P6" and depth == b"255"
                sw, sh = map(int, size.split())
                def pixel(x, y):
                    at = (y * sw + x) * 3
                    return tuple(pixels[at:at + 3])
                assert pixels.count(bytes((255, 0, 255))) > 100, "the frame was not drawn"
                xs = [x for x in range(sw) if pixel(x, sh // 2) == (255, 0, 255)]
                assert len(xs) == 2 * width, f"expected {width}px on both sides, got {len(xs)}"
                left, right = min(xs), max(xs)
                ys = [y for y in range(sh) if pixel((left + right) // 2, y) == (255, 0, 255)]
                bottom = max(ys) + 1
                if width == 1:
                    # This lies on the 31px inner arc, outside the old
                    # 16px image: that cap left this part unpainted.
                    red, green, blue = pixel(left + 3, bottom - 20)
                    assert red > 100 and blue > 100 and green < 40, "thin inner arc is missing"
                top = min(ys)
                # Reveal the hover row, then target the newly reclaimed
                # edge of the close cell (outside the old radius-sized inset).
                pointer.write(f"move {(left + right) // 2} {top + width + args.hover_edge - 1}\n")
                time.sleep(0.2)
                safe = math.ceil(32 - math.sqrt(32 * 32 - (32 - width) ** 2))
                x, y = right + 1 - safe - 2, top + width + 10
                pointer.write(f"move {x} {y}\n")
                time.sleep(0.3)
                subprocess.run([args.grim, str(root / f"{name}-close-hover.png")], env=env, check=True)
                pointer.write("press\nrelease\n")
                terminal.wait(timeout=10)
                print(f"{name}: frame drawn, new button position accepts real click; screenshots saved", flush=True)
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
    main()
