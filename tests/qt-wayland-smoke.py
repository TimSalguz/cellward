#!/usr/bin/env python3
"""Compare a fresh Qt application's startup directly, proxied and privately.

Only the private headless compositor and disposable application profiles are
used. The application runs in an empty network namespace, with no real bus.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('core', 'broker', 'sway', 'app', 'unshare'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('typing_smoke', Path(__file__).with_name('typing-smoke.py'))
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    root = Path(tempfile.mkdtemp(prefix='cellward-qt-wayland-'))
    print('Artifacts:', root, flush=True)
    runtime = root / 'runtime'
    runtime.mkdir(mode=0o700)
    env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime), HOME=str(root),
               XDG_CONFIG_HOME=str(root / 'config'), XDG_STATE_HOME=str(root / 'state'),
               XDG_DATA_HOME=str(root / 'data'), XDG_CACHE_HOME=str(root / 'cache'),
               WLR_BACKENDS='headless', WLR_RENDERER='pixman', WLR_LIBINPUT_NO_DEVICES='1',
               QT_QPA_PLATFORM='wayland', QT_QUICK_BACKEND='software', QT_OPENGL='software',
               LIBGL_ALWAYS_SOFTWARE='1', LP_NUM_THREADS='1',
               DBUS_SESSION_BUS_ADDRESS=f'unix:path={root}/no-bus', WAYLAND_DEBUG='1')
    for key in ('WAYLAND_DISPLAY', 'WAYLAND_SOCKET', 'SWAYSOCK', 'DISPLAY'):
        env.pop(key, None)
    children, logs = [], []

    def start(command, name):
        log = open(root / f'{name}.log', 'wb')
        logs.append(log)
        child = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                                 stdout=log, stderr=log, start_new_session=True)
        children.append(child)
        return child

    try:
        config = root / 'sway.conf'
        config.write_text('output * mode 800x600\nseat seat0 fallback true\ndefault_border none\n')
        start([args.sway, '--unsupported-gpu', '-c', str(config)], 'sway')
        env['WAYLAND_DISPLAY'] = helper.wait_for(lambda: next((p.name for p in runtime.glob('wayland-*') if not p.name.endswith('.lock')), None))
        broker = start([args.broker, 'broker'], 'broker')
        helper.wait_for(lambda: (runtime / 'cellward-clipboard/control.sock').exists())
        holder = start(['sleep', '120'], 'holder')
        stat = Path(f'/proc/{holder.pid}/stat').read_text()
        stamp = stat[stat.rfind(')') + 1:].split()[19]
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        binding = ['--clipboard-scope', 'qt-test', f'{holder.pid}:{stamp} {boot}']
        results = {}
        for mode in ('direct', 'legacy', 'private', 'private-filled'):
            if mode == 'private-filled':
                start([args.core, 'wl-sandbox', 'qt-source', *binding, '--', sys.executable,
                       str(Path(__file__).with_name('private-clipboard-smoke.py')), 'owner'], 'source')
                seed = root / 'seed.json'
                start([args.core, 'wl-sandbox', 'qt-reader', *binding, '--', sys.executable,
                       str(Path(__file__).with_name('clipboard-reverse-smoke.py')), 'reader', str(seed)], 'reader')
                def seeded():
                    try:
                        return json.loads(seed.read_text())['bodies'].get('image/png')
                    except (FileNotFoundError, ValueError):
                        return None
                helper.wait_for(seeded)
            work = root / mode
            work.mkdir()
            app = [args.unshare, '--user', '--map-current-user', '--net', args.app,
                   '-many', '-noupdate', '-workdir', str(work)]
            command = app if mode == 'direct' else [args.core, 'wl-sandbox', f'qt-{mode}',
                       *(binding if mode.startswith('private') else []), '--', *app]
            child = start(command, mode)
            deadline = time.monotonic() + 5
            while child.poll() is None and time.monotonic() < deadline:
                time.sleep(.1)
            results[mode] = child.poll()
            print(f'{mode}: {"alive" if child.poll() is None else "exit " + str(child.returncode)}', flush=True)
            if mode == 'private-filled' and child.poll() is None:
                broker.terminate()
                broker.wait(timeout=3)
                time.sleep(.5)
                assert child.poll() is None, 'Qt crashed when its private selection was revoked'
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                child.wait(timeout=5)
        assert results['direct'] is None, 'direct Qt startup failed; inspect direct.log before blaming proxy'
        assert results['legacy'] is None, 'legacy Qt proxy startup failed'
        assert results['private'] is None, 'private Qt proxy startup failed'
        assert results['private-filled'] is None, 'private Qt startup with an existing selection failed'
    finally:
        for child in reversed(children):
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
        for child in reversed(children):
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
        for log in logs:
            log.close()


if __name__ == '__main__':
    main()
