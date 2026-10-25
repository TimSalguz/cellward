"""Guest-only measurement: process spawn to a mapped compositor surface.

This includes polling overhead; it is not a GPU-present timestamp. Closing the
dialog must never launch the requested program. No host clipboard or app data.
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def mapped(node):
    return node.get("app_id") == "vpn-zone-window" or any(
        mapped(child)
        for child in node.get("nodes", []) + node.get("floating_nodes", [])
    )


if len(sys.argv) > 1:
    source = Path(sys.argv[1]).resolve(strict=True)
    stress = Path.home() / ".local/share/fonts/cellward-startup-stress"
    stress.mkdir(parents=True, exist_ok=True)
    for index in range(1000):
        entry = stress / f"font-{index}.ttf"
        if not entry.is_symlink():
            entry.symlink_to(source)

samples = []
with open("/tmp/cellward-startup.trace", "w") as trace:
    for attempt in range(3):
        started = time.monotonic()
        process = subprocess.Popen(
            ["vpn-zone-pick", "--label", "Startup benchmark", "--id", "startup-benchmark",
             "--", "touch", "/tmp/startup-must-not-run"],
            env=dict(os.environ, CELLWARD_TRACE_STARTUP="1"),
            stdout=trace, stderr=trace, start_new_session=True,
        )
        try:
            while time.monotonic() - started < 30:
                assert process.poll() is None, "picker exited before showing a window"
                tree = subprocess.check_output(["swaymsg", "-t", "get_tree", "-r"])
                if mapped(json.loads(tree)):
                    samples.append(round(1000 * (time.monotonic() - started), 1))
                    break
                time.sleep(0.02)
            else:
                raise AssertionError("picker did not map within 30 seconds")
            subprocess.run(["swaymsg", '[app_id="vpn-zone-window"] kill'], check=True)
            assert process.wait(timeout=10) == 0
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=10)
        assert not Path("/tmp/startup-must-not-run").exists()
result = {"process_to_mapped_surface_ms": samples, "first_run_in_guest": True}
Path("/tmp/cellward-startup.json").write_text(json.dumps(result))
print(json.dumps(result))
