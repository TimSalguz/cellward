#!/usr/bin/env python3
"""Render Files panel at fractional scales on an isolated headless compositor."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time


def wait(test):
    until = time.monotonic() + 20
    while time.monotonic() < until:
        value = test()
        if value:
            return value
        time.sleep(.05)
    raise AssertionError('condition timed out')


def main():
    p = argparse.ArgumentParser()
    for key in ('window', 'sway', 'swaymsg', 'grim'):
        p.add_argument('--' + key, required=True)
    args = p.parse_args()
    root = Path(tempfile.mkdtemp(prefix='cellward-files-panel-'))
    runtime = root/'runtime'
    runtime.mkdir(mode=0o700)
    host = root/'home'
    (host/'project'/'reference').mkdir(parents=True)
    (host/'.config'/'example').mkdir(parents=True)
    data = (f'host-home\t{host}\ncontainer\twork\tprivate\thost\t789abc\n'
            f'folder-rule\twork\toverlay\t{host}/project\n'
            f'folder-rule\twork\tro\t{host}/project/reference\n'
            f'path\twork\t{host}/shared\t0\npath-source\twork\t{host}/shared\tnix\n'
            'container\tother\tlayer\toffline\t789abc\n')
    fixture = root/'cellward'
    fixture.write_text('#!/usr/bin/env python3\nimport sys\n'
                       f'print({data!r} if sys.argv[1:]==["_panel"] else "",end="")\n')
    fixture.chmod(0o700)
    conf = root/'sway.conf'
    conf.write_text('output * mode 960x720\nseat * fallback true\ndefault_border none\n')
    env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime), WLR_BACKENDS='headless',
               WLR_RENDERER='pixman', WLR_LIBINPUT_NO_DEVICES='1',
               HOME=str(host), XDG_CONFIG_HOME=str(root/'config'))
    for key in ('NIRI_SOCKET', 'SWAYSOCK', 'WAYLAND_DISPLAY', 'WAYLAND_SOCKET', 'DISPLAY', 'VPN_ZONE_ASK', 'DBUS_SESSION_BUS_ADDRESS'):
        env.pop(key, None)
    children = []
    logs = []

    def start(command, label):
        log = open(root/(label+'.log'), 'wb')
        logs.append(log)
        child = subprocess.Popen(command, env=env, stdout=log, stderr=log, start_new_session=True)
        children.append(child)
        return child

    def msg(*words):
        return subprocess.check_output([args.swaymsg, *words], env=env, text=True)

    def windows():
        def walk(n):
            if n.get('app_id') == 'cellward':
                yield n
            for child in n.get('nodes', []) + n.get('floating_nodes', []):
                yield from walk(child)
        return list(walk(json.loads(msg('-t', 'get_tree', '-r'))))

    print(f'Artifacts: {root}', flush=True)
    try:
        start([args.sway, '-c', str(conf)], 'sway')
        env['SWAYSOCK'] = str(wait(lambda: next(runtime.glob('sway-ipc.*.sock'), None)))
        env['WAYLAND_DISPLAY'] = wait(lambda: next((x.name for x in runtime.glob('wayland-*') if not x.name.endswith('.lock')), None))
        panel = start([args.window, 'panel', '--cellward', str(fixture), '--tab', 'files'], 'panel')
        wait(windows)
        for scale in (1, 1.25, 1.5, 1.75, 2):
            msg('output', 'HEADLESS-1', 'scale', str(scale))
            time.sleep(.4)
            assert panel.poll() is None, 'panel exited'
            subprocess.run([args.grim, str(root/f'files-{scale}.png')], env=env, check=True)
            (root/f'tree-{scale}.json').write_text(msg('-t', 'get_tree', '-r'))
        print('panel stayed mapped at 100/125/150/175/200%; screenshots saved', flush=True)
    finally:
        for child in reversed(children):
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
        for child in reversed(children):
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
        for log in logs:
            log.close()


if __name__ == '__main__':
    main()
