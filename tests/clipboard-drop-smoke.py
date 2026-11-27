#!/usr/bin/env python3
"""Real Wayland drag-and-drop between isolated scopes on a private Sway.

Uses only synthetic text, links, paths, PNG and binary payloads. Hover must not
read the source; a foreign drop needs the real trusted preview; same-scope drops
stay direct. The target compares complete MIME payloads, not a text-only fallback.
"""
import argparse
import array
import base64
import importlib.util
import json
import os
from pathlib import Path
import random
import re
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wire = load('typing_smoke', 'typing-smoke.py')
reverse = load('reverse_smoke', 'clipboard-reverse-smoke.py')
TEXT = 'Synthetic dragged text: практиче-ctrlshiftc-2026'.encode()
LINK = b'https://example.test/a?q=1#fragment'
URI_LIST = b'file:///tmp/synthetic%20file.txt\r\nhttps://example.test/a?q=1#fragment\r\n'
BINARY = b'\x00\xff\x10\x00synthetic-drag-binary\xfe'
pixels = random.Random(19).randbytes(32 * 32 * 3)
PNG = (b'\x89PNG\r\n\x1a\n'
       + reverse.fixtures.png_chunk(b'IHDR', struct.pack('>IIBBBBB', 32, 32, 8, 2, 0, 0, 0))
       + reverse.fixtures.png_chunk(b'IDAT', zlib.compress(b''.join(
           b'\0' + pixels[row * 96:(row + 1) * 96] for row in range(32))))
       + reverse.fixtures.png_chunk(b'IEND', b''))
PAYLOADS = {
    'text/plain;charset=utf-8': TEXT,
    'text/html': b'<a href="' + LINK + b'">synthetic link</a>',
    'text/uri-list': URI_LIST,
    'image/png': PNG,
    'application/x-synthetic-binary': BINARY,
}


def save(path, value):
    path = Path(path)
    path.with_suffix('.tmp').write_text(json.dumps(value))
    path.with_suffix('.tmp').replace(path)


def app(role, output, app_id):
    """Small raw Wayland source/target; no toolkit or host clipboard is used."""
    sock = socket.socket(socket.AF_UNIX)
    sock.connect(str(Path(os.environ['XDG_RUNTIME_DIR']) / os.environ['WAYLAND_DISPLAY']))
    send = lambda obj, op, body=b'', fd=None: wire.packet(sock, obj, op, body, fd)
    send(1, 1, struct.pack('=I', 2))
    send(1, 0, struct.pack('=I', 3))
    names, received, fds = {}, b'', []
    initialized, painted = False, False
    width, height, next_buffer = 480, 320, 14
    sources = set()
    report = {'send_requests': 0, 'completed': 0, 'cancelled': 0, 'drops': 0,
              'presses': 0, 'start_drags': 0, 'offers': 0, 'enters': 0, 'leaves': 0,
              'drop_events': 0, 'performed': 0, 'actions': [], 'bodies': {}}
    offers, current_offer, enter_serial = {}, None, None
    drop_offer = None
    buffers = set()
    incoming, receiving = {}, None
    save(output, report)

    def buffer(w, h):
        nonlocal next_buffer
        pool, image = next_buffer, next_buffer + 1
        next_buffer += 2
        fd = os.memfd_create('synthetic-drop-pixels')
        data = bytes((30, 100, 180, 255) if role == 'source' else (80, 150, 60, 255)) * w * h
        os.ftruncate(fd, len(data))
        os.pwrite(fd, data, 0)
        send(5, 0, struct.pack('=II', pool, len(data)), fd)
        os.close(fd)
        send(pool, 0, struct.pack('=IIIIII', image, 0, w, h, w * 4, 1))
        send(pool, 1)
        buffers.add(image)
        return image

    def paint():
        nonlocal painted
        image = buffer(width, height)
        send(11, 1, struct.pack('=III', image, 0, 0))
        send(11, 2, struct.pack('=IIII', 0, 0, width, height))
        send(11, 6)
        painted = True

    def start_drag(serial):
        nonlocal next_buffer
        source = next_buffer
        next_buffer += 1
        sources.add(source)
        send(8, 0, struct.pack('=I', source))
        for mime in PAYLOADS:
            send(source, 0, wire.wl_string(mime))
        send(source, 2, struct.pack('=I', 1))
        send(10, 0, struct.pack('=IIII', source, 11, 0, serial))

    def accept_current():
        nonlocal enter_serial
        if current_offer is None or enter_serial is None or current_offer not in offers:
            return
        preferred = next((mime for mime in offers[current_offer]['types'] if mime in PAYLOADS), None)
        if preferred:
            send(current_offer, 0, struct.pack('=I', enter_serial) + wire.wl_string(preferred))
            send(current_offer, 4, struct.pack('=II', 1, 1))
            report['accepted'] = report.get('accepted', 0) + 1
            save(output, report)
            enter_serial = None

    def receive_next():
        nonlocal receiving, drop_offer
        if drop_offer is None or drop_offer not in offers:
            return
        types = offers[drop_offer]['types']
        done = set(report['bodies'])
        remaining = [mime for mime in types if mime in PAYLOADS and mime not in done]
        if not remaining:
            report['drops'] += 1
            save(output, report)
            send(drop_offer, 3)
            drop_offer = None
            return
        mime = remaining[0]
        read, write = os.pipe()
        send(drop_offer, 1, wire.wl_string(mime), write)
        os.close(write)
        incoming[read] = [mime, bytearray()]
        receiving = read

    while True:
        watched = [sock] + list(incoming)
        ready, _, _ = select.select(watched, [], [], .1)
        for fd in ready:
            if fd == sock:
                continue
            mime, data = incoming[fd]
            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                continue
            if chunk:
                data.extend(chunk)
                continue
            os.close(fd)
            del incoming[fd]
            receiving = None
            report['bodies'][mime] = base64.b64encode(bytes(data)).decode()
            save(output, report)
            receive_next()
        if sock not in ready:
            continue
        data, ancillary, flags, _ = sock.recvmsg(65536, socket.CMSG_SPACE(64 * 4))
        if not data:
            return
        assert not flags & socket.MSG_CTRUNC
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                received_fds = array.array('i')
                received_fds.frombytes(payload)
                fds.extend(received_fds)
        received += data
        while len(received) >= 8:
            obj, word = struct.unpack_from('=II', received)
            size, op = word >> 16, word & 65535
            if len(received) < size:
                break
            body, received = received[8:size], received[size:]
            if obj == 1 and op == 0:
                raise AssertionError('Wayland protocol error: ' + repr(body))
            if obj == 2 and op == 0:
                name, length = struct.unpack_from('=II', body)
                names[body[8:8 + length - 1].decode()] = name
            if obj == 3 and op == 0 and not initialized:
                for interface, ident, version in [
                    ('wl_compositor', 4, 4), ('wl_shm', 5, 1), ('xdg_wm_base', 6, 1),
                    ('wl_seat', 7, 5), ('wl_data_device_manager', 8, 3),
                ]:
                    send(2, 0, struct.pack('=I', names[interface]) + wire.wl_string(interface)
                         + struct.pack('=II', version, ident))
                send(7, 0, struct.pack('=I', 9))
                send(8, 1, struct.pack('=II', 10, 7))
                send(4, 0, struct.pack('=I', 11))
                send(6, 2, struct.pack('=II', 12, 11))
                send(12, 1, struct.pack('=I', 13))
                send(13, 3, wire.wl_string(app_id))
                send(13, 2, wire.wl_string('Synthetic drop ' + role))
                send(11, 6)
                initialized = True
            if obj == 6 and op == 0:
                send(6, 3, body)
            if obj == 13 and op == 0:
                w, h = struct.unpack_from('=ii', body)
                if w > 0 and h > 0:
                    width, height = w, h
            if obj == 12 and op == 0:
                send(12, 4, body)
                paint()
            if obj == 9 and op == 3 and role == 'source':
                serial, _, _, state = struct.unpack_from('=IIII', body)
                if state:
                    report['presses'] += 1
                    report['start_drags'] += 1
                    save(output, report)
                    start_drag(serial)
            if obj in sources and op == 1:
                length = struct.unpack_from('=I', body)[0]
                mime = body[4:4 + length - 1].decode()
                fd = fds.pop(0)
                report['send_requests'] += 1
                save(output, report)
                try:
                    payload = PAYLOADS[mime]
                    while payload:
                        payload = payload[os.write(fd, payload):]
                except BrokenPipeError:
                    pass
                finally:
                    os.close(fd)
            if obj in sources and op in (2, 3, 4):
                report['cancelled' if op == 2 else 'performed' if op == 3 else 'completed'] += 1
                save(output, report)
            if obj in sources and op == 5:
                report['actions'].append(struct.unpack_from('=I', body)[0])
                save(output, report)
            if obj == 10 and op == 0 and role == 'target':
                offer = struct.unpack_from('=I', body)[0]
                offers[offer] = {'types': []}
                report['offers'] += 1
                save(output, report)
            if obj == 10 and op == 1 and role == 'target':
                enter_serial = struct.unpack_from('=I', body)[0]
                current_offer = struct.unpack_from('=I', body, 16)[0]
                report['enters'] += 1
                report['offered_types'] = offers[current_offer]['types'].copy()
                save(output, report)
                accept_current()
            if obj == 10 and op == 2:
                current_offer = None
                report['leaves'] += 1
                save(output, report)
            if obj == 10 and op == 4 and role == 'target':
                drop_offer = current_offer
                report['drop_events'] += 1
                save(output, report)
                receive_next()
            if obj in offers and op == 0:
                length = struct.unpack_from('=I', body)[0]
                offers[obj]['types'].append(body[4:4 + length - 1].decode())
                accept_current()
            if obj in offers and op == 2:
                report['actions'].append(struct.unpack_from('=I', body)[0])
                save(output, report)
            if obj in buffers and op == 0:
                buffers.remove(obj)
                send(obj, 0)


def read_report(path):
    try:
        return json.loads(Path(path).read_text())
    except (FileNotFoundError, ValueError):
        return {}


def decoded(report):
    return {mime: base64.b64decode(data) for mime, data in report.get('bodies', {}).items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('core', 'broker', 'window', 'sway', 'swaymsg', 'font', 'xkbcommon'):
        parser.add_argument('--' + name)
    parser.add_argument('mode', choices=['smoke', 'source', 'target'])
    parser.add_argument('output', nargs='?')
    parser.add_argument('app_id', nargs='?')
    args = parser.parse_args()
    if args.mode in ('source', 'target'):
        app(args.mode, args.output, args.app_id or ('drop-' + args.mode))
        return
    for name in ('core', 'broker', 'window', 'sway', 'swaymsg', 'font', 'xkbcommon'):
        if getattr(args, name) is None:
            parser.error('--' + name + ' is required for smoke')

    root = Path(tempfile.mkdtemp(prefix='cellward-drop-smoke-'))
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
    keys = re.findall(r'"([a-z-]+)"', (Path(__file__).parents[1] / 'rust/src/tools.rs').read_text().split('const KEYS:')[1].split('];')[0])
    manifest = {key: '/bin/false' for key in keys}
    manifest.update({key: str(root / key) for key in ('home', 'state', 'profiles', 'sandboxes', 'config')})
    manifest.update({'core': str(Path(args.core).resolve()), 'window': str(Path(args.window).resolve()),
                     'systemd-run': str(adapter)})
    tools = root / 'tools.json'
    tools.write_text(json.dumps(manifest))
    env['VPN_ZONE_TOOLS'] = str(tools)
    children, logs, stop = [], [], threading.Event()

    def start(command, name):
        log = open(root / (name + '.log'), 'wb')
        logs.append(log)
        child = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        children.append(child)
        return child

    def units():
        seen = set()
        while not stop.wait(.02):
            for request in root.glob('unit-*.json'):
                if request not in seen:
                    seen.add(request)
                    start(json.loads(request.read_text()), request.stem)

    def msg(*words):
        return subprocess.check_output([args.swaymsg, *words], env=env, text=True, timeout=5)

    def windows():
        def walk(node):
            if node.get('app_id'):
                yield node
            for child in node.get('nodes', []) + node.get('floating_nodes', []):
                yield from walk(child)
        return list(walk(json.loads(msg('-t', 'get_tree'))))

    def window(app_id):
        return next((w for w in windows() if w['app_id'] == app_id), None)

    def menu():
        return window('vpn-zone-window')

    def scope(name, holder):
        stamp = Path(f'/proc/{holder.pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        return ['--clipboard-scope', name, f'{holder.pid}:{stamp} {boot}']

    def key(code):
        for down in (1, 0):
            wire.packet(vk, 6, 1, struct.pack('=III', int(time.monotonic() * 1000) & 0xffffffff, code, down))
            time.sleep(.03)

    def pointer(text):
        with open(fifo, 'w') as output:
            output.write(text + '\n')

    def center(app_id):
        rect = window(app_id)['rect']
        return rect['x'] + rect['width'] // 2, rect['y'] + rect['height'] // 2

    def drag(destination):
        before = read_report(source_json).get('send_requests', 0)
        save(root / 'last-drag.json', {'source': window('drop-source'), 'target': window(destination),
                                      'source_report': read_report(source_json)})
        sx, sy = center('drop-source')
        tx, ty = center(destination)
        pointer(f'move {sx} {sy}')
        time.sleep(.15)
        pointer('press')
        time.sleep(.2)
        for step in range(1, 6):
            pointer(f'move {sx + (tx - sx) * step // 5} {sy + (ty - sy) * step // 5}')
            time.sleep(.08)
        time.sleep(.3)
        assert not menu(), 'hover opened a transfer preview'
        assert read_report(source_json).get('send_requests', 0) == before, 'hover read source payload'
        pointer('release')

    worker = threading.Thread(target=units)
    worker.start()
    try:
        config = root / 'sway.conf'
        config.write_text('output * mode 1200x800\nseat seat0 fallback true\ndefault_border none\n')
        start([args.sway, '--unsupported-gpu', '-c', str(config)], 'sway')
        env['WAYLAND_DISPLAY'] = wire.wait_for(lambda: next((p.name for p in runtime.glob('wayland-*') if not p.name.endswith('.lock')), None))
        env['SWAYSOCK'] = str(wire.wait_for(lambda: next(runtime.glob('sway-ipc*.sock'), None)))
        fifo = root / 'pointer.fifo'
        start([sys.executable, str(Path(__file__).with_name('vm-pointer.py')), str(fifo), '1200', '800'], 'pointer')
        wire.wait_for(lambda: fifo.exists())
        vk = wire.keyboard(env, args.xkbcommon)
        start([args.broker, 'broker'], 'broker')
        wire.wait_for(lambda: (runtime / 'cellward-clipboard/control.sock').exists())
        holder_a = start(['sleep', '180'], 'holder-a')
        holder_b = start(['sleep', '180'], 'holder-b')
        source_json, same_json, foreign_json = root / 'source.json', root / 'same.json', root / 'foreign.json'
        direct = os.environ.get('CELLWARD_DROP_DIRECT_FIXTURE') == '1'
        def sandbox(name, binding):
            return [] if direct else [args.core, 'wl-sandbox', name, *binding, '--']
        start([*sandbox('drop-source', scope('drop-a', holder_a)),
               sys.executable, __file__, 'source', str(source_json)], 'source')
        start([*sandbox('drop-same', scope('drop-a', holder_a)),
               sys.executable, __file__, 'target', str(same_json), 'drop-same'], 'same')
        start([*sandbox('drop-foreign', scope('drop-b', holder_b)),
               sys.executable, __file__, 'target', str(foreign_json), 'drop-foreign'], 'foreign')
        for app_id, x, y in [('drop-source', 20, 20), ('drop-same', 500, 20), ('drop-foreign', 500, 450)]:
            wire.wait_for(lambda: window(app_id))
            msg(f'[app_id="{app_id}"]', 'floating enable')
            msg(f'[app_id="{app_id}"]', 'resize set 400 300')
            msg(f'[app_id="{app_id}"]', f'move position {x} {y}')
        time.sleep(1)
        drag('drop-same')
        wire.wait_for(lambda: read_report(same_json).get('drops') == 1)
        assert not menu(), 'same-scope drop opened a transfer preview'
        assert decoded(read_report(same_json)) == PAYLOADS, 'same-scope MIME payload changed'
        wire.wait_for(lambda: read_report(source_json).get('completed') == 1)
        print('same-scope real DnD preserves text, link, URI list, PNG and binary without a prompt', flush=True)

        drag('drop-foreign')
        wire.wait_for(menu)
        time.sleep(.5)
        assert read_report(foreign_json).get('drops', 0) == 0, 'foreign target received before confirmation'
        key(1)
        wire.wait_for(lambda: not menu())
        time.sleep(.3)
        assert read_report(foreign_json).get('drops', 0) == 0, 'cancelled foreign drop reached target'
        wire.wait_for(lambda: read_report(source_json).get('cancelled') == 1)
        print('foreign drop captures only after release and Escape prevents target receive', flush=True)

        drag('drop-foreign')
        wire.wait_for(menu)
        time.sleep(.5)
        key(28)
        wire.wait_for(lambda: read_report(foreign_json).get('drops') == 1)
        assert decoded(read_report(foreign_json)) == PAYLOADS, 'confirmed foreign MIME payload changed'
        assert not menu()
        wire.wait_for(lambda: read_report(source_json).get('completed') == 2)
        print('confirmed foreign real DnD replays the complete frozen MIME set', flush=True)

        drag('drop-foreign')
        wire.wait_for(menu)
        time.sleep(.5)
        key(28)
        wire.wait_for(lambda: read_report(foreign_json).get('drops') == 2)
        assert decoded(read_report(foreign_json)) == PAYLOADS, 'reused source changed a MIME payload'
        print('a fresh Wayland data source completes a second foreign drag', flush=True)
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
