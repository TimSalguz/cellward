#!/usr/bin/env python3
"""Real history UI on private sway: live arrival, original-image preview, Escape.

The daemon is a deterministic socket fixture. No desktop clipboard or user
history is opened. All children inherit the runner's process group.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('window', 'sway', 'swaymsg', 'grim', 'wtype', 'xkbcommon', 'font'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('typing_smoke', Path(__file__).with_name('typing-smoke.py'))
    wire = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wire)
    root = Path(tempfile.mkdtemp(prefix='cellward-clip-live-ui-'))
    print('Artifacts:', root, flush=True)
    runtime = root / 'runtime'
    runtime.mkdir(mode=0o700)
    fonts = root / 'fonts.conf'
    fonts.write_text('<fontconfig><dir>' + str(Path(args.font).resolve().parent)
                     + '</dir><cachedir>' + str(root / 'font-cache') + '</cachedir></fontconfig>')
    env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime), HOME=str(root),
               XDG_CONFIG_HOME=str(root / 'config'), XDG_STATE_HOME=str(root / 'state'),
               FONTCONFIG_FILE=str(fonts), WLR_BACKENDS='headless', WLR_RENDERER='pixman',
               WLR_LIBINPUT_NO_DEVICES='1', LP_NUM_THREADS='1', LIBGL_ALWAYS_SOFTWARE='1',
               DBUS_SESSION_BUS_ADDRESS=f'unix:path={root}/no-bus')
    for name in ('WAYLAND_DISPLAY', 'WAYLAND_SOCKET', 'SWAYSOCK', 'DISPLAY'):
        env.pop(name, None)
    children, logs = [], []
    stop = threading.Event()
    daemon = socket.socket(socket.AF_UNIX)
    daemon.bind(str(runtime / 'cellward-clip.sock'))
    daemon.listen()
    daemon.settimeout(.2)
    requests = []
    epoch = [False]

    def chunk(name, data):
        return struct.pack('>I', len(data)) + name + data + struct.pack('>I', zlib.crc32(name + data))

    color = bytes((240, 20, 180))
    png = (b'\x89PNG\r\n\x1a\n'
           + chunk(b'IHDR', struct.pack('>IIBBBBB', 800, 400, 8, 2, 0, 0, 0))
           + chunk(b'IDAT', zlib.compress((b'\0' + color * 800) * 400)) + chunk(b'IEND', b''))

    def server():
        while not stop.is_set():
            try:
                client, _ = daemon.accept()
            except socket.timeout:
                continue
            with client:
                client.settimeout(2)
                data = b''
                while b'\n' not in data:
                    part = client.recv(4096)
                    if not part:
                        break
                    data += part
                request = data.decode().strip()
                requests.append(request)
                if request == 'histories':
                    answer = b'host\n'
                elif request == 'instances':
                    answer = b''
                elif request.startswith('search\thost\t'):
                    answer = b'1\t1700000000000\t1700000000000\t1\t0\t0\ttext/plain:12\tInitial clip\n'
                    if epoch[0]:
                        answer = f'2\t1700000001000\t1700000001000\t1\t0\t0\timage/png:{len(png)}\tScreenshot\n'.encode() + answer
                elif request == 'get\thost\t2\timage/png':
                    answer = f'ok\t{len(png)}\n'.encode() + png
                else:
                    answer = b'error\tunexpected test request\n'
                client.sendall(answer)

    worker = threading.Thread(target=server, daemon=True)
    worker.start()

    def start(command, name):
        log = open(root / (name + '.log'), 'wb')
        logs.append(log)
        child = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        children.append(child)
        return child

    def pixels():
        raw = subprocess.check_output([args.grim, '-t', 'ppm', '-'], env=env, timeout=5)
        head, size, maximum, body = raw.split(b'\n', 3)
        assert head == b'P6' and maximum == b'255'
        width, height = map(int, size.split())
        assert len(body) == width * height * 3
        positions = [i // 3 for i in range(0, len(body), 3) if body[i:i + 3] == color]
        return width, positions

    try:
        config = root / 'sway.conf'
        config.write_text('output * mode 800x900\nseat seat0 fallback true\ndefault_border none\n')
        start([args.sway, '--unsupported-gpu', '-c', str(config)], 'sway')
        env['WAYLAND_DISPLAY'] = wire.wait_for(lambda: next((p.name for p in runtime.glob('wayland-*') if not p.name.endswith('.lock')), None))
        env['SWAYSOCK'] = str(wire.wait_for(lambda: next(runtime.glob('sway-ipc*.sock'), None)))
        vk = wire.keyboard(env, args.xkbcommon)
        fifo = root / 'pointer.fifo'
        start([sys.executable, str(Path(__file__).with_name('vm-pointer.py')), str(fifo), '800', '900'], 'pointer')
        wire.wait_for(fifo.exists)
        window = start([args.window, 'clip', '--manager'], 'window')
        wire.wait_for(lambda: any(r.startswith('search\thost\t') for r in requests))
        time.sleep(.3)
        before = len(requests)
        epoch[0] = True
        # No key or pointer input: the new row must be fetched automatically.
        wire.wait_for(lambda: 'get\thost\t2\timage/png' in requests[before:], timeout=6)
        width, small = wire.wait_for(lambda: (p if (p := pixels())[1] else None))
        subprocess.run([args.grim, str(root / 'live-image.png')], env=env, check=True)
        middle = small[len(small) // 2]
        with open(fifo, 'w') as pointer:
            pointer.write(f'move {middle % width} {middle // width}\npress\nrelease\n')
        wire.wait_for(lambda: requests.count('get\thost\t2\timage/png') >= 2)
        _, large = wire.wait_for(lambda: (p if len((p := pixels())[1]) > len(small) * 4 else None))
        subprocess.run([args.grim, str(root / 'original-image-preview.png')], env=env, check=True)
        assert len(large) > len(small) * 4, 'preview enlarged only the list thumbnail'
        subprocess.run([args.wtype, '-k', 'Escape'], env=env, check=True, timeout=5)
        time.sleep(.2)
        assert window.poll() is None, 'Escape closed the manager instead of the preview'
        search_count = sum(r.startswith('search\t') for r in requests)
        wire.wait_for(lambda: sum(r.startswith('search\t') for r in requests) > search_count, timeout=4)
        assert not any(r.startswith(('copy\t', 'copy-to\t', 'select\t')) for r in requests)
        vk.close()
        print('PASS: open manager updates without input; original PNG opens large; Escape returns; polling resumes; no clipboard mutation', flush=True)
    finally:
        stop.set()
        worker.join(timeout=3)
        daemon.close()
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
        for child in reversed(children):
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        for log in logs:
            log.close()


if __name__ == '__main__':
    main()
