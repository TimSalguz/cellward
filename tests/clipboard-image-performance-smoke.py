#!/usr/bin/env python3
"""Profile large synthetic clipboard images on private sway, never user history."""
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
    parser.add_argument('--width', type=int, default=1280)
    parser.add_argument('--height', type=int, default=900)
    parser.add_argument('--image-width', type=int, default=2560)
    parser.add_argument('--image-height', type=int, default=1440)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('typing_smoke', Path(__file__).with_name('typing-smoke.py'))
    wire = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wire)
    root = Path(tempfile.mkdtemp(prefix='cellward-clip-image-perf-'))
    print('Artifacts:', root, flush=True)
    timings = open(root / 'timings.jsonl', 'w')
    started = time.monotonic()

    def mark(name, **values):
        timings.write(json.dumps({'name': name, 'at': time.monotonic() - started, **values}) + '\n')
        timings.flush()

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
    for name in ('WAYLAND_DISPLAY', 'WAYLAND_SOCKET', 'SWAYSOCK', 'NIRI_SOCKET', 'DISPLAY'):
        env.pop(name, None)
    children, logs = [], []
    stop = threading.Event()
    daemon = socket.socket(socket.AF_UNIX)
    daemon.bind(str(runtime / 'cellward-clip.sock'))
    daemon.listen()
    daemon.settimeout(.2)
    requests = []

    def chunk(name, data):
        return struct.pack('>I', len(data)) + name + data + struct.pack('>I', zlib.crc32(name + data))

    color = bytes((240, 20, 180))
    image_width, image_height = args.image_width, args.image_height
    png = (b'\x89PNG\r\n\x1a\n'
           + chunk(b'IHDR', struct.pack('>IIBBBBB', image_width, image_height, 8, 2, 0, 0, 0))
           + chunk(b'IDAT', zlib.compress((b'\0' + color * image_width) * image_height, 1))
           + chunk(b'IEND', b''))
    mark('synthetic_png', width=image_width, height=image_height, bytes=len(png))

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
                    answer = b'app-one\trunning\n'
                elif request.startswith('search\thost\t'):
                    answer = f'2\t1700000001000\t1700000001000\t1\t0\t0\timage/png:{len(png)}\tScreenshot\n'.encode()
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
        raw = subprocess.check_output([args.grim, '-t', 'ppm', '-'], env=env, timeout=10)
        head, size, maximum, body = raw.split(b'\n', 3)
        assert head == b'P6' and maximum == b'255'
        width, height = map(int, size.split())
        assert len(body) == width * height * 3
        return width, height, body.count(color), body.find(color) // 3

    def shot(name):
        subprocess.run([args.grim, str(root / (name + '.png'))], env=env, check=True)

    def pointer(text):
        with open(fifo, 'w') as output:
            output.write(text)

    try:
        config = root / 'sway.conf'
        config.write_text(f'output * mode {args.width}x{args.height}\nseat seat0 fallback true\ndefault_border none\n')
        start([args.sway, '--unsupported-gpu', '-c', str(config)], 'sway')
        env['WAYLAND_DISPLAY'] = wire.wait_for(lambda: next((p.name for p in runtime.glob('wayland-*') if not p.name.endswith('.lock')), None))
        env['SWAYSOCK'] = str(wire.wait_for(lambda: next(runtime.glob('sway-ipc*.sock'), None)))
        vk = wire.keyboard(env, args.xkbcommon)
        output_width, output_height, _, _ = pixels()
        fifo = root / 'pointer.fifo'
        start([sys.executable, str(Path(__file__).with_name('vm-pointer.py')), str(fifo), str(output_width), str(output_height)], 'pointer')
        wire.wait_for(fifo.exists)
        window = start([args.window, 'clip', '--manager', '--clipboard-instance', 'app-one'], 'window')
        wire.wait_for(lambda: 'get\thost\t2\timage/png' in requests, timeout=10)
        wire.wait_for(lambda: pixels()[2] > 0, timeout=10)
        time.sleep(.3)
        shot('inline')
        mark('inline_ready')
        _, _, small, _ = pixels()
        mark('expanded_click')
        preview_x = 640 if output_width >= 900 else 150
        preview_y = 285 if output_width >= 900 else 585
        pointer(f'move {preview_x} {preview_y}\npress\nrelease\n')
        wire.wait_for(lambda: requests.count('get\thost\t2\timage/png') >= 2, timeout=15)
        wire.wait_for(lambda: pixels()[2] > small * 1.2, timeout=15)
        time.sleep(.5)
        shot('expanded')
        mark('expanded_ready')
        pointer(f'move {output_width // 2} {output_height // 2}\nwheel 1\n')
        time.sleep(.5)
        shot('zoom')
        mark('zoom_ready')
        pointer(f'move {output_width // 2} {output_height // 2}\npress\nmove {output_width // 2 + 160} {output_height // 2 + 100}\nrelease\n')
        time.sleep(.5)
        shot('pan')
        mark('pan_ready')
        pointer('move 190 25\npress\nrelease\n')
        time.sleep(.5)
        shot('native')
        mark('native_ready')
        subprocess.run([args.wtype, '-k', 'Escape'], env=env, check=True, timeout=5)
        time.sleep(.5)
        shot('after-preview')
        mark('preview_closed')
        decoded = requests.count('get\thost\t2\timage/png')
        pointer(f'move {preview_x} {preview_y}\npress\nrelease\n')
        time.sleep(.7)
        assert requests.count('get\thost\t2\timage/png') == decoded, 'cached reopen fetched again'
        shot('cached-reopen')
        mark('cached_reopen')
        subprocess.run([args.wtype, '-k', 'Escape'], env=env, check=True, timeout=5)
        time.sleep(.3)
        pointer(f'move {output_width - 28} 60\npress\nrelease\n')
        wire.wait_for(lambda: window.poll() is not None)
        assert window.returncode == 1
        assert not any(r.startswith(('copy\t', 'copy-to\t', 'select\t')) for r in requests)
        vk.close()
        mark('pass')
        print('PASS: large synthetic inline/expanded/zoom/pan/native/close/cached reopen; no clipboard mutation', flush=True)
    finally:
        timings.close()
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
