#!/usr/bin/env python3
"""Restore real hidden SNI windows through the picker on a private session bus."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
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
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", required=True)
    parser.add_argument("--picker", required=True)
    parser.add_argument("--sway", default="sway")
    parser.add_argument("--swaymsg", default="swaymsg")
    parser.add_argument("--foot", default="foot")
    parser.add_argument("--dbus-daemon", default="dbus-daemon")
    parser.add_argument("--dbus-proxy", help="also exercise the real xdg-dbus-proxy path")
    parser.add_argument("--unshare", help="give each source its own user/mount/PID namespaces")
    parser.add_argument("--fixture", default=str(Path(__file__).with_name("tray-sni-fixture.py")))
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="cellward-tray-restore-"))
    print(f"Artifacts: {root}", flush=True)
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime), WLR_BACKENDS="headless",
               WLR_RENDERER="pixman", WLR_LIBINPUT_NO_DEVICES="1",
               XDG_CONFIG_HOME=str(root / "config"), XDG_STATE_HOME=str(root / "state"),
               DBUS_SESSION_BUS_ADDRESS=f"unix:path={root}/bus")
    for key in ("NIRI_SOCKET", "SWAYSOCK", "WAYLAND_DISPLAY", "WAYLAND_SOCKET", "VPN_ZONE_ASK", "VPN_ZONE_PROFILE"):
        env.pop(key, None)
    env["PATH"] = str(Path(args.swaymsg).resolve().parent) + ":" + env.get("PATH", "")
    processes, logs = [], []

    def start(command, name, values=None):
        log = open(root / (name + ".log"), "wb")
        logs.append(log)
        child = subprocess.Popen(command, env=values or env, stdout=log,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        processes.append(child)
        return child

    def msg(*args):
        return subprocess.check_output([options.swaymsg, *args], env=env, text=True)

    options = args

    def windows():
        def walk(node):
            if node.get("app_id"):
                yield node
            for child in node.get("nodes", []) + node.get("floating_nodes", []):
                yield from walk(child)
        return list(walk(json.loads(msg("-t", "get_tree", "-r"))))

    def window(label):
        return next((w for w in windows() if w["app_id"] == "tray-source-" + label), None)

    def pick():
        result = subprocess.run([args.picker, "--id", "tray-test", "--label", "Tray fixture",
                                 "--", "/run/current-system/sw/bin/true"], env=env,
                                capture_output=True, text=True, timeout=20)
        (root / "picker.log").write_text(result.stdout + result.stderr)
        assert result.returncode == 0, result.stdout + result.stderr

    def record(name, pid, selector):
        path = root / "state/.running" / name / "tray-test"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{pid} host {selector}\n")
        started = root / "state/.running/.started" / str(pid)
        started.parent.mkdir(parents=True, exist_ok=True)
        stat = Path(f"/proc/{pid}/stat").read_text()
        stamp = stat[stat.rfind(")") + 1:].split()[19]
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        started.write_text(f"{stamp} {boot}\n")
        return path

    try:
        config = root / "sway.conf"
        config.write_text("output * mode 1000x700\noutput * bg #202020 solid_color\n"
                          "seat seat0 fallback true\ndefault_border none\nfocus_follows_mouse no\n")
        start([args.sway, "-c", str(config)], "sway")
        env["SWAYSOCK"] = str(wait_for(lambda: next(runtime.glob("sway-ipc.*.sock"), None)))
        env["WAYLAND_DISPLAY"] = wait_for(lambda: next((p.name for p in runtime.glob("wayland-*") if not p.name.endswith(".lock")), None))
        start([args.dbus_daemon, "--session", "--nofork", f"--address=unix:path={root}/bus"], "dbus")
        wait_for((root / "bus").exists)
        start([sys.executable, args.fixture, "--socket", str(root / "bus"), "--root", str(root), "--watcher"], "watcher")
        wait_for((root / "ready-watcher").exists)
        upstream = root / "bus"
        if args.dbus_proxy:
            upstream = root / "proxy-bus"
            proxy = start([args.dbus_proxy, f"unix:path={root}/bus", str(upstream), "--filter",
                "--own=org.kde.StatusNotifierItem-*", "--own=org.freedesktop.StatusNotifierItem-*",
                "--talk=org.kde.StatusNotifierWatcher", "--talk=org.freedesktop.StatusNotifierWatcher"], "xdg-proxy")
            wait_for(upstream.exists)
            assert proxy.poll() is None, "xdg-dbus-proxy exited"
        if not args.unshare:
            start([args.core, "bus-filter", "--listen", str(root / "filtered-bus"),
                   "--upstream", str(upstream), "--opener", "/nonexistent"], "filter")
            wait_for((root / "filtered-bus").exists)
        launcher = root / "namespace-launcher.py"
        launcher.write_text("import os,subprocess,sys,time\n"
            "core,listen,upstream=sys.argv[1:4]\n"
            "f=subprocess.Popen([core,'bus-filter','--listen',listen,'--upstream',upstream,'--opener','/nonexistent'])\n"
            "while not os.path.exists(listen):\n"
            " assert f.poll() is None, 'filter exited'\n"
            " time.sleep(.01)\n"
            "os.execv(sys.argv[4],sys.argv[4:])\n")
        sources = {}
        for label in ("a", "b"):
            filtered = root / ("filtered-" + label if args.unshare else "filtered-bus")
            values = dict(env, DBUS_SESSION_BUS_ADDRESS=f"unix:path={filtered}")
            command = [args.core, "wl-sandbox", "tray-" + label,
                "--frame", "789abc:2:always", "--", sys.executable, args.fixture,
                "--socket", str(filtered), "--root", str(root),
                "--label", label, "--object", "/Custom/Tray" if label == "a" else "/StatusNotifierItem",
                "--foot", args.foot]
            if args.unshare:
                command = command[:6] + [args.unshare, "--user", "--map-current-user", "--keep-caps",
                    "--mount", "--propagation", "private", "--pid", "--fork", "--kill-child=SIGKILL", "--mount-proc",
                    sys.executable, str(launcher), args.core, str(filtered), str(upstream), *command[6:]]
            sources[label] = start(command, "source-" + label, values)
            wait_for((root / ("ready-" + label)).exists)
        assert not window("a") and not window("b"), "fixture was not hidden"
        keys = "home state profiles sandboxes config runner picker core systemctl systemd-run nsenter unshare ip kdialog notify-send bwrap dbus-proxy xwayland openssl certutil opener window busctl secret-tool nft".split()
        tools = {key: "/nonexistent" for key in keys}
        tools.update(home=str(root / "home"), state=str(root / "state"),
                     profiles=str(root / "profiles"), sandboxes=str(root / "sandboxes"),
                     config=str(root / "config"), core=str(Path(args.core).resolve()), picker=str(Path(args.picker).resolve()))
        for key in ("home", "state", "profiles", "sandboxes", "config"):
            Path(tools[key]).mkdir(parents=True, exist_ok=True)
        policies = root / "config/containers"
        policies.mkdir(parents=True, exist_ok=True)
        (policies / ".layout").write_text("2")
        for name in ("work-a", "work-b"):
            path = policies / name
            path.mkdir()
            (path / "container.conf").write_text("home = private\n")
        # The stub supplies only the user's menu choice. The actual picker,
        # process identities, D-Bus transport, filter and compositor are real.
        answer = root / "answer.py"
        foreign = root / "state/.running/0-foreign/tray-test"
        foreign.parent.mkdir(parents=True)
        # Only A exists when the picker reads its launch state. B is inserted
        # after the dialog opens, before its There reply: a first-PID lookup
        # would now restore the wrong instance.
        b_record = record("z-unused", sources["b"].pid, "work-b")
        b_text = b_record.read_text()
        b_record.unlink()
        record("work-a", sources["a"].pid, "work-a")
        answer.write_text(f"#!{sys.executable}\nimport sys\nfrom pathlib import Path\n"
                          f"request=sys.stdin.read()\nPath({str(root / 'question.txt')!r}).write_text(request)\n"
                          "assert 'there' in request, request\n"
                          f"Path({str(foreign)!r}).write_text({b_text!r})\n"
                          "print('action\\tthere')\n")
        answer.chmod(0o700)
        tools["window"] = str(answer)
        manifest = root / "tools.json"
        manifest.write_text(json.dumps(tools))
        env["VPN_ZONE_TOOLS"] = str(manifest)
        pick()
        wait_for(lambda: window("a"))
        assert (root / "activated-a").read_text() == "1"
        assert not (root / "activated-b").exists(), "a different instance was restored"
        assert next(w for w in windows() if w.get("focused"))["app_id"] == "tray-source-a"
        print("hidden custom-path item restored; wrong container ignored", flush=True)
        foreign.unlink()
        # Visible windows are focused without another Activate or a new copy.
        start([args.foot, "--app-id", "tray-other", "sleep", "120"], "other")
        wait_for(lambda: any(w["app_id"] == "tray-other" for w in windows()))
        pick()
        assert (root / "activated-a").read_text() == "1"
        assert len([w for w in windows() if w["app_id"] == "tray-source-a"]) == 1
        assert next(w for w in windows() if w.get("focused"))["app_id"] == "tray-source-a"
        print("visible window focused without activation or another window", flush=True)
        foreign.unlink()
        msg(f"[con_id={window('a')['id']}] kill")
        wait_for(lambda: not window("a"))
        pick()
        wait_for(lambda: window("a"))
        assert (root / "activated-a").read_text() == "2"
        assert not (root / "activated-b").exists()
        print("repeated restore works; application received no process descriptors", flush=True)
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
    print("tray restore smoke passed", flush=True)


if __name__ == "__main__":
    main()
