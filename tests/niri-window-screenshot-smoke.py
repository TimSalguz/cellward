#!/usr/bin/env python3
"""Capture one of two synthetic floating windows on a private nested niri.

The scenario uses only synthetic pixels and a synthetic clipboard marker. Logs,
capture and metadata stay in the printed artifact directory.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time


def wait_for(fn, timeout=20):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = fn()
        if value:
            return value
        time.sleep(0.1)
    raise AssertionError("timed out waiting for nested compositor")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for tool in ["niri", "sway", "foot", "grim", "wl-copy", "wl-paste"]:
        parser.add_argument(f"--{tool}", required=True)
    parser.add_argument("--artifacts", type=Path, default=Path(__file__).parents[1])
    args = parser.parse_args()
    args.artifacts.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="s-", dir=args.artifacts))
    print(f"Artifacts: {root}", flush=True)
    runtime = args.artifacts
    env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime), XDG_CONFIG_HOME=str(root / "config"),
               XDG_STATE_HOME=str(root / "state"), WLR_BACKENDS="headless", WLR_RENDERER="pixman",
               WLR_LIBINPUT_NO_DEVICES="1", LIBGL_ALWAYS_SOFTWARE="1",
               DBUS_SESSION_BUS_ADDRESS=f"unix:path={root}/no-bus")
    for key in ["WAYLAND_DISPLAY", "WAYLAND_SOCKET", "SWAYSOCK", "NIRI_SOCKET"]:
        env.pop(key, None)
    processes, logs = [], []

    def start(command, name, stdin=None):
        log = open(root / f"{name}.log", "wb")
        logs.append(log)
        proc = subprocess.Popen(command, env=env, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        processes.append(proc)
        if stdin is not None:
            proc.stdin.write(stdin)
            proc.stdin.close()
        return proc

    def niri_msg(*command):
        return json.loads(subprocess.check_output([args.niri, "msg", "--json", *command], env=env))

    def action(*command):
        subprocess.run([args.niri, "msg", "action", *command], env=env, check=True,
                       stdout=subprocess.DEVNULL)

    def window_rect(window, workspace, outputs):
        if window.get("workspace_id") != workspace["id"] or not workspace.get("is_active"):
            return None
        output = outputs[workspace["output"]]["logical"]
        layout = window["layout"]
        tile = layout.get("tile_pos_in_workspace_view")
        if tile is None:
            return None
        offset = layout["window_offset_in_tile"]
        width, height = layout["window_size"]
        return (output["x"] + tile[0] + offset[0], output["y"] + tile[1] + offset[1], width, height)

    def exact_geometry():
        focused = niri_msg("focused-window")
        windows = niri_msg("windows")
        workspace = next(w for w in niri_msg("workspaces") if w["id"] == focused["workspace_id"])
        outputs = niri_msg("outputs")
        rect = window_rect(focused, workspace, outputs)
        if rect is None:
            return None
        x, y, width, height = rect
        output = outputs[workspace["output"]]["logical"]
        if (x < output["x"] or y < output["y"] or x + width > output["x"] + output["width"]
                or y + height > output["y"] + output["height"] or x % 1 or y % 1):
            return None
        for other in windows:
            if other["id"] == focused["id"] or other.get("workspace_id") != workspace["id"]:
                continue
            other_rect = window_rect(other, workspace, outputs)
            if other_rect is None:
                if other.get("is_floating") or not focused.get("is_floating"):
                    return None
                continue
            ox, oy, ow, oh = other_rect
            if x < ox + ow and ox < x + width and y < oy + oh and oy < y + height:
                return None
        return f"{int(x)},{int(y)} {width}x{height}"

    def capture():
        focused = niri_msg("focused-window")
        direct_log = open(root / "direct-capture.log", "wb")
        logs.append(direct_log)
        direct = subprocess.run([args.grim, "-T", str(focused["id"]), "-t", "ppm", "-"], env=env,
                                stdout=subprocess.PIPE, stderr=direct_log, timeout=10)
        if direct.returncode == 0 and direct.stdout.startswith(b"P6\n"):
            return direct.stdout, "toplevel"
        geometry = exact_geometry()
        if geometry is None:
            raise AssertionError("exact niri capture is unavailable; refusing an unbounded capture")
        region_log = open(root / "region-capture.log", "wb")
        logs.append(region_log)
        region = subprocess.run([args.grim, "-g", geometry, "-t", "ppm", "-"], env=env,
                                stdout=subprocess.PIPE, stderr=region_log, timeout=10, check=True)
        return region.stdout, "ipc-rectangle"

    try:
        sway_config = root / "sway.conf"
        sway_config.write_text("output * mode 900x500\noutput * bg #202020 solid_color\ndefault_border none\n")
        start([args.sway, "--unsupported-gpu", "-c", str(sway_config)], "sway")
        outer_display = wait_for(lambda: next((p.name for p in runtime.glob("wayland-*")
                                               if not p.name.endswith(".lock")), None))
        env["WAYLAND_DISPLAY"] = outer_display
        niri_config = root / "niri.kdl"
        niri_config.write_text("""output "winit" { scale 1.0; }
layout { gaps 0; focus-ring { off; }; border { off; }; }
prefer-no-csd
animations { off; }
hotkey-overlay { skip-at-startup; }
screenshot-path null
window-rule { open-floating true; default-column-width { fixed 320; }; default-window-height { fixed 240; }; }
""")
        env["NIRI_CONFIG"] = str(niri_config)
        start([args.niri, "-c", str(niri_config)], "niri")
        env["NIRI_SOCKET"] = str(wait_for(lambda: next(runtime.glob("niri.*.sock"), None)))
        env["WAYLAND_DISPLAY"] = wait_for(lambda: next((p.name for p in runtime.glob("wayland-*")
            if not p.name.endswith(".lock") and p.name != outer_display), None))

        marker = b"synthetic-niri-window-capture-marker"
        start([args.wl_copy, "--foreground", "--type", "text/plain"], "clipboard-owner", marker)
        time.sleep(0.2)
        for name, color in [("shot-red", "ff0000"), ("shot-blue", "0000ff")]:
            start([args.foot, "--app-id", name, "-o", f"colors-dark.background={color}",
                   "-o", f"colors-dark.foreground={color}", "-o", f"colors-light.background={color}",
                   "-o", f"colors-light.foreground={color}", "sh", "-c", "sleep 120"], name)
            wait_for(lambda name=name: any(w.get("app_id") == name for w in niri_msg("windows")))
        windows = niri_msg("windows")
        red = next(w for w in windows if w.get("app_id") == "shot-red")
        blue = next(w for w in windows if w.get("app_id") == "shot-blue")
        action("move-floating-window", "--id", str(red["id"]), "--x", "40", "--y", "40")
        action("move-floating-window", "--id", str(blue["id"]), "--x", "500", "--y", "40")
        action("focus-window", "--id", str(red["id"]))
        wait_for(lambda: niri_msg("focused-window").get("id") == red["id"])
        time.sleep(0.5)

        ppm, source = capture()
        (root / "selected-window.ppm").write_bytes(ppm)
        magic, size, depth, pixels = ppm.split(b"\n", 3)
        assert magic == b"P6" and depth == b"255"
        width, height = map(int, size.split())
        assert (width, height) == tuple(red["layout"]["window_size"]), (width, height)
        assert (width, height) != (900, 500), "whole desktop was captured"
        red_count = sum(pixels[at:at + 3] == bytes((255, 0, 0)) for at in range(0, len(pixels), 3))
        blue_count = sum(pixels[at:at + 3] == bytes((0, 0, 255)) for at in range(0, len(pixels), 3))
        assert red_count > width * height * 99 // 100, "selected synthetic window was not captured cleanly"
        assert blue_count == 0, "pixels of the other window leaked into the capture"
        clipboard = subprocess.check_output([args.wl_paste, "--no-newline"], env=env)
        assert clipboard == marker, "capture changed the compositor clipboard"

        fallback_rejected = False
        action("focus-window", "--id", str(blue["id"]))
        action("toggle-window-floating")
        wait_for(lambda: not niri_msg("focused-window")["is_floating"])
        if exact_geometry() is None:
            try:
                capture()
            except AssertionError:
                fallback_rejected = True
            else:
                raise AssertionError("capture without exact geometry did not fail")
            clipboard = subprocess.check_output([args.wl_paste, "--no-newline"], env=env)
            assert clipboard == marker, "rejected capture changed the compositor clipboard"

        (root / "result.json").write_text(json.dumps({
            "source": source, "width": width, "height": height,
            "other_window_pixels": blue_count, "clipboard_unchanged": True,
            "unknown_geometry_rejected": fallback_rejected,
        }, indent=2) + "\n")
        print(f"PASS: {source}; exact {width}x{height}; no other-window pixels; "
              f"clipboard unchanged; unknown geometry rejected={fallback_rejected}", flush=True)
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
