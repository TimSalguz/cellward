#!/usr/bin/env python3
"""Physical paste → real trusted preview → Enter on an isolated compositor.

Uses temporary scopes, a private broker, a terminal and the real menu window.
The systemd adapter executes only this fixture's helper in the same process
group; it never contacts the user's service manager or clipboard.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('core', 'broker', 'window', 'sway', 'swaymsg', 'foot', 'font', 'xkbcommon'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    tests = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location('typing', tests / 'typing-smoke.py')
    wire = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wire)
    root = Path(tempfile.mkdtemp(prefix='cellward-paste-smoke-'))
    print('Artifacts:', root, flush=True)
    runtime = root / 'runtime'
    runtime.mkdir(mode=0o700)
    fonts = root / 'fonts.conf'
    fonts.write_text(f'<fontconfig><dir>{Path(args.font).parent}</dir><cachedir>{root}/font-cache</cachedir></fontconfig>')
    env = dict(os.environ, HOME=str(root), XDG_RUNTIME_DIR=str(runtime),
               XDG_CONFIG_HOME=str(root / 'config'), XDG_STATE_HOME=str(root / 'state'),
               FONTCONFIG_FILE=str(fonts), WLR_BACKENDS='headless', WLR_RENDERER='pixman',
               WLR_LIBINPUT_NO_DEVICES='1', LP_NUM_THREADS='1', LIBGL_ALWAYS_SOFTWARE='1',
               DBUS_SESSION_BUS_ADDRESS=f'unix:path={root}/no-bus')
    for key in ('WAYLAND_DISPLAY', 'WAYLAND_SOCKET', 'SWAYSOCK', 'NIRI_SOCKET', 'DISPLAY'):
        env.pop(key, None)
    env['PATH'] = str(Path(args.swaymsg).parent) + ':' + env.get('PATH', '')
    adapter = root / 'systemd-adapter'
    adapter.write_text(f'#!{sys.executable}\nimport os,sys,json,pathlib\na=sys.argv[sys.argv.index("--")+1:]\np=pathlib.Path({str(root)!r}) / ("unit-"+str(os.getpid()))\np.with_suffix(".tmp").write_text(json.dumps(a))\np.with_suffix(".tmp").rename(p.with_suffix(".json"))\n')
    adapter.chmod(0o700)
    keys = re.findall(r'"([a-z-]+)"', (tests.parent / 'rust/src/tools.rs').read_text().split('const KEYS:')[1].split('];')[0])
    manifest = {key: '/bin/false' for key in keys}
    manifest.update({key: str(root / key) for key in ('home', 'state', 'profiles', 'sandboxes', 'config')})
    manifest.update({'core': str(Path(args.core).resolve()), 'window': str(Path(args.window).resolve()),
                     'systemd-run': str(adapter)})
    tools = root / 'tools.json'
    tools.write_text(json.dumps(manifest))
    env['VPN_ZONE_TOOLS'] = str(tools)
    children, logs = [], []
    stop = threading.Event()

    def start(command, name):
        log = open(root / (name + '.log'), 'wb')
        logs.append(log)
        child = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        children.append(child)
        return child

    def msg(*words):
        return subprocess.check_output([args.swaymsg, *words], env=env, text=True, timeout=5)

    def windows():
        def walk(node):
            if node.get('app_id'):
                yield node
            for child in node.get('nodes', []) + node.get('floating_nodes', []):
                yield from walk(child)
        return list(walk(json.loads(msg('-t', 'get_tree'))))

    def scope(name, holder):
        stamp = Path(f'/proc/{holder.pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        return ['--clipboard-scope', name, f'{holder.pid}:{stamp} {boot}']

    def key(code, modifiers=0):
        wire.packet(vk, 6, 2, struct.pack('=IIII', modifiers, 0, 0, 0))
        for down in (1, 0):
            wire.packet(vk, 6, 1, struct.pack('=III', int(time.monotonic() * 1000) & 0xffffffff, code, down))
            time.sleep(.03)
        wire.packet(vk, 6, 2, struct.pack('=IIII', 0, 0, 0, 0))

    def menu():
        return next((w for w in windows() if w['app_id'] == 'vpn-zone-window'), None)

    def copied(text, epoch):
        control.write_text(json.dumps({'epoch': epoch, 'types': {'text/plain': text}}))
        # Allow the synthetic owner to announce its copy. Completion itself
        # is deliberately asynchronous and must be awaited by the paste path.
        time.sleep(.15)

    def units():
        seen = set()
        while not stop.wait(.02):
            for request in root.glob('unit-*.json'):
                if request not in seen:
                    seen.add(request)
                    # The real user manager is outside the application launch;
                    # preserve that authentication boundary in this fixture.
                    start(json.loads(request.read_text()), request.stem)

    worker = threading.Thread(target=units)
    worker.start()

    try:
        config = root / 'sway.conf'
        config.write_text('output * mode 1000x800\nseat seat0 fallback true\ndefault_border none\n')
        start([args.sway, '--unsupported-gpu', '-c', str(config)], 'sway')
        env['WAYLAND_DISPLAY'] = wire.wait_for(lambda: next((p.name for p in runtime.glob('wayland-*') if not p.name.endswith('.lock')), None))
        env['SWAYSOCK'] = str(wire.wait_for(lambda: next(runtime.glob('sway-ipc*.sock'), None)))
        vk = wire.keyboard(env, args.xkbcommon)
        start([args.broker, 'broker'], 'broker')
        wire.wait_for(lambda: (runtime / 'cellward-clipboard/control.sock').exists())
        source_holder = start(['sleep', '120'], 'source-holder')
        target_holder = start(['sleep', '120'], 'target-holder')
        output = root / 'pasted.txt'
        script = ('import os,sys,tty; tty.setraw(0); f=open(sys.argv[1],"ab",buffering=0); '
                  'exec("while True:\\n f.write(os.read(0,65536))")')
        target = start([args.core, 'wl-sandbox', 'paste-target', *scope('paste-target', target_holder),
                        '--frame', 'ff00ff:4:always', '--', args.foot, '--app-id', 'paste-target',
                        sys.executable, '-c', script, str(output)], 'target')
        node = wire.wait_for(lambda: next((w for w in windows() if w['app_id'] == 'paste-target'), None))
        control = root / 'copy.json'
        control.write_text(json.dumps({'epoch': 1, 'types': {'text/plain': 'FIRST synthetic link'}}))
        start([args.core, 'wl-sandbox', 'paste-source', *scope('paste-source', source_holder), '--',
               sys.executable, str(tests / 'private-clipboard-smoke.py'), 'fault-owner', str(control)], 'source')
        time.sleep(.5)
        msg(f"[con_id={node['id']}]", 'focus')
        key(47, 5)  # Ctrl+Shift+V, preserved for terminals.
        wire.wait_for(menu)
        time.sleep(.7)
        assert not output.read_bytes(), 'content or shortcut reached target before confirmation'
        key(1)  # Esc cancels without transfer or key injection.
        wire.wait_for(lambda: not menu())
        time.sleep(.2)
        assert not output.read_bytes(), 'cancelled paste reached target'
        msg(f"[con_id={node['id']}]", 'focus')
        key(47, 5)
        wire.wait_for(menu)
        time.sleep(.7)
        key(28)
        wire.wait_for(lambda: b'FIRST synthetic link' in output.read_bytes())
        assert output.read_bytes() == b'FIRST synthetic link', output.read_bytes()
        print('preview blocks original chord; Esc cancels; Enter transfers and replays Ctrl+Shift+V once', flush=True)
        # Already imported selection: ordinary subsequent paste needs no transfer.
        key(47, 5)
        wire.wait_for(lambda: output.read_bytes() == b'FIRST synthetic link' * 2)
        assert not menu(), 'same-scope paste opened an unnecessary transfer dialog'
        copied('SECOND synthetic link', 2)
        key(47, 5)
        wire.wait_for(menu)
        time.sleep(.7)
        copied('THIRD synthetic link', 3)
        key(28)
        wire.wait_for(lambda: not menu())
        time.sleep(.5)
        assert output.read_bytes() == b'FIRST synthetic link' * 2, 'confirmation substituted a newer clipboard'
        print('repeat paste stays local; changed source invalidates frozen confirmation', flush=True)
        control.write_text(json.dumps({'epoch': 4, 'types': {'TEXT': 'stall', 'text/plain': 'SLOW synthetic link'}}))
        time.sleep(.15)
        msg(f"[con_id={node['id']}]", 'focus')
        key(47, 5)
        wire.wait_for(menu)
        time.sleep(.7)
        assert output.read_bytes() == b'FIRST synthetic link' * 2
        key(28)
        wire.wait_for(lambda: output.read_bytes().endswith(b'SLOW synthetic link'))
        assert output.read_bytes() == b'FIRST synthetic link' * 2 + b'SLOW synthetic link'
        print('fast paste waits for new capture despite a stalled legacy MIME', flush=True)
        before = output.read_bytes()
        control.write_text(json.dumps({'epoch': 5, 'types': {'text/plain': 'SYNTHETIC password', 'x-kde-passwordManagerHint': 'secret'}}))
        time.sleep(.2)
        key(47, 5)
        wire.wait_for(menu)
        time.sleep(.7)
        key(28)
        # The second dialog defaults to Cancel and uses the ordinary guard.
        time.sleep(1.8)
        assert output.read_bytes() == before, 'secret bypassed separate consent'
        key(108)  # Down: select the explicit private transfer.
        time.sleep(1.7)
        key(28)
        wire.wait_for(lambda: output.read_bytes() == before + b'SYNTHETIC password')
        print('private content requires separate guarded confirmation', flush=True)
        vk.close()
    finally:
        stop.set()
        worker.join()
        for child in reversed(children):
            child.terminate()
        for child in reversed(children):
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        for log in logs:
            log.close()


if __name__ == '__main__':
    main()
