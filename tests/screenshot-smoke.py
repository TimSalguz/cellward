#!/usr/bin/env python3
"""Three frame screenshot actions on private sway, real crop UI and broker.

Only synthetic pixels are recorded as test artifacts. Checks immutable crops,
click swallowing, Escape, private destination and unchanged desktop selection.
"""
import argparse
import array
import importlib.util
import json
import os
from pathlib import Path
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


def target(control, output):
    """A real subsurface tooltip, deterministic paint and direct input counters."""
    spec = importlib.util.spec_from_file_location('wire', Path(__file__).with_name('typing-smoke.py'))
    wire = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wire)
    sock = socket.socket(socket.AF_UNIX)
    sock.connect(str(Path(os.environ['XDG_RUNTIME_DIR']) / os.environ['WAYLAND_DISPLAY']))
    send = lambda obj, op, body=b'', fd=None: wire.packet(sock, obj, op, body, fd)
    send(1, 1, struct.pack('=I', 2))
    send(1, 0, struct.pack('=I', 3))
    names, received, initialized = {}, b'', False
    width, height, next_id, painted = 640, 420, 100, False
    changed, tooltip = False, False
    report = {'motions': 0, 'presses': 0, 'releases': 0}

    def save():
        p = Path(output)
        p.with_suffix('.tmp').write_text(json.dumps(report))
        p.with_suffix('.tmp').replace(p)

    def buffer(w, h, color):
        nonlocal next_id
        pool, image = next_id, next_id + 1
        next_id += 2
        fd = os.memfd_create('synthetic-screenshot-pixels')
        pixels = bytes(color) * w * h
        os.ftruncate(fd, len(pixels))
        os.pwrite(fd, pixels, 0)
        send(5, 0, struct.pack('=II', pool, len(pixels)), fd)
        os.close(fd)
        send(pool, 0, struct.pack('=IIIIII', image, 0, w, h, w * 4, 1))
        send(pool, 1)
        return image

    def paint():
        nonlocal painted
        image = buffer(width, height, (40, 40, 210, 255) if changed else (180, 180, 180, 255))
        send(10, 1, struct.pack('=III', image, 0, 0))
        send(10, 2, struct.pack('=IIII', 0, 0, width, height))
        send(10, 6)
        painted = True

    def show():
        nonlocal tooltip
        if tooltip or changed:
            return
        tooltip = True
        image = buffer(180, 50, (230, 220, 10, 255))
        send(30, 1, struct.pack('=III', image, 0, 0))
        send(30, 2, struct.pack('=IIII', 0, 0, 180, 50))
        send(30, 6)
        send(10, 6)

    save()
    while True:
        new = Path(control).exists()
        if initialized and painted and new != changed:
            changed = new
            tooltip = False
            send(30, 1, struct.pack('=III', 0, 0, 0))
            send(30, 6)
            paint()
        if not select.select([sock], [], [], .05)[0]:
            continue
        data, ancillary, _, _ = sock.recvmsg(65536, socket.CMSG_SPACE(64 * 4))
        if not data:
            return
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                for fd in array.array('i', payload):
                    os.close(fd)
        received += data
        while len(received) >= 8:
            obj, word = struct.unpack_from('=II', received)
            length, op = word >> 16, word & 65535
            if len(received) < length:
                break
            body, received = received[8:length], received[length:]
            if obj == 1 and op == 0:
                raise AssertionError('Wayland protocol error: ' + repr(body))
            if obj == 2 and op == 0:
                name, size = struct.unpack_from('=II', body)
                names[body[8:8 + size - 1].decode()] = name
            if obj == 3 and op == 0 and not initialized:
                for interface, ident, version in [('wl_compositor', 4, 4), ('wl_shm', 5, 1),
                    ('wl_subcompositor', 6, 1), ('xdg_wm_base', 7, 1), ('wl_seat', 8, 5)]:
                    send(2, 0, struct.pack('=I', names[interface]) + wire.wl_string(interface) + struct.pack('=II', version, ident))
                send(8, 0, struct.pack('=I', 9))
                send(8, 1, struct.pack('=I', 11))
                send(4, 0, struct.pack('=I', 10))
                send(7, 2, struct.pack('=II', 20, 10))
                send(20, 1, struct.pack('=I', 21))
                send(21, 3, wire.wl_string('screenshot-target'))
                send(21, 2, wire.wl_string('Synthetic screenshot target'))
                send(4, 0, struct.pack('=I', 30))
                send(6, 1, struct.pack('=III', 31, 30, 10))
                send(31, 1, struct.pack('=ii', 80, 100))
                send(31, 5)
                send(4, 1, struct.pack('=I', 32))
                send(30, 5, struct.pack('=I', 32))
                send(32, 0)
                send(10, 6)
                initialized = True
            if obj == 7 and op == 0:
                send(7, 3, body)
            if obj == 21 and op == 0:
                w, h = struct.unpack_from('=ii', body)
                if w > 0 and h > 0:
                    width, height = w, h
            if obj == 20 and op == 0:
                send(20, 4, body)
                paint()
            if obj == 9 and op in (0, 2):
                report['motions'] += 1
                show()
                save()
            if obj == 9 and op == 1 and tooltip:
                tooltip = False
                send(30, 1, struct.pack('=III', 0, 0, 0))
                send(30, 6)
                send(10, 6)
            if obj == 9 and op == 3:
                report['presses' if struct.unpack_from('=I', body, 12)[0] else 'releases'] += 1
                save()
            if obj >= 100 and obj % 2 and op == 0:
                send(obj, 0)  # wl_buffer.release → destroy; new buffers use new ids.


def decode_png(data):
    at, packed, size, channels = 8, b'', None, None
    while at < len(data):
        length = struct.unpack_from('>I', data, at)[0]
        name, body = data[at + 4:at + 8], data[at + 8:at + 8 + length]
        if name == b'IHDR':
            w, h, depth, color, _, _, interlace = struct.unpack('>IIBBBBB', body)
            assert depth == 8 and color in (2, 6) and interlace == 0
            size, channels = (w, h), 3 if color == 2 else 4
        if name == b'IDAT':
            packed += body
        at += 12 + length
    raw, previous, output = zlib.decompress(packed), bytearray(size[0] * channels), bytearray()
    stride, at = len(previous), 0
    for _ in range(size[1]):
        mode, row = raw[at], bytearray(raw[at + 1:at + stride + 1])
        at += stride + 1
        for x in range(stride):
            a, b, c = (row[x - channels] if x >= channels else 0), previous[x], (previous[x - channels] if x >= channels else 0)
            if mode == 1:
                prediction = a
            elif mode == 2:
                prediction = b
            elif mode == 3:
                prediction = (a + b) // 2
            elif mode == 4:
                p = a + b - c
                prediction = min((a, b, c), key=lambda value: abs(p - value))
            else:
                assert mode == 0
                prediction = 0
            row[x] = (row[x] + prediction) & 255
        for x in range(0, stride, channels):
            output.extend(row[x:x + 3])
        previous = row
    return (*size, bytes(output))


def is_crop(original, result):
    w, h, rgb = decode_png(original)
    cw, ch, crop = decode_png(result)
    if cw > w or ch > h:
        return False
    rows = [crop[y * cw * 3:(y + 1) * cw * 3] for y in range(ch)]
    anchor = max(range(ch), key=lambda y: len(set(rows[y][x:x + 3] for x in range(0, cw * 3, 3))))
    for y in range(h):
        line = rgb[y * w * 3:(y + 1) * w * 3]
        start = 0
        while (x := line.find(rows[anchor], start)) >= 0:
            start = x + 1
            if x % 3 or y < anchor or y - anchor + ch > h:
                continue
            if all(rgb[((y - anchor + dy) * w * 3 + x):((y - anchor + dy) * w * 3 + x + cw * 3)] == row for dy, row in enumerate(rows)):
                return True
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('core', 'broker', 'window', 'sway', 'swaymsg', 'foot', 'font', 'xkbcommon', 'grim', 'wl-copy'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    tests = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location('typing', tests / 'typing-smoke.py')
    wire = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wire)
    root = Path(tempfile.mkdtemp(prefix='cellward-screenshot-smoke-'))
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
    grab = root / 'grim-adapter'
    grab.write_text(f'#!{sys.executable}\nimport subprocess,sys,pathlib,os\nr=subprocess.run([{args.grim!r},*sys.argv[1:]],stdout=subprocess.PIPE)\nif r.returncode: sys.exit(r.returncode)\np=pathlib.Path({str(root)!r}) / ("frozen-"+str(os.getpid())+".png")\np.write_bytes(r.stdout)\nsys.stdout.buffer.write(r.stdout)\n')
    grab.chmod(0o700)
    ui = root / 'window-adapter'
    ui.write_text(f'#!{sys.executable}\nimport os,sys\nos.dup2(os.open({str(root / "editor.log")!r},os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600),2)\nos.execv({args.window!r},[{args.window!r},*sys.argv[1:]])\n')
    ui.chmod(0o700)
    keys = re.findall(r'"([a-z-]+)"', (tests.parent / 'rust/src/tools.rs').read_text().split('const KEYS:')[1].split('];')[0])
    manifest = {key: '/bin/false' for key in keys}
    manifest.update({key: str(root / key) for key in ('home', 'state', 'profiles', 'sandboxes', 'config')})
    manifest.update({'core': str(Path(args.core).resolve()), 'window': str(ui), 'systemd-run': str(adapter), 'grim': str(grab)})
    tools = root / 'tools.json'
    tools.write_text(json.dumps(manifest))
    env['VPN_ZONE_TOOLS'] = str(tools)
    children, logs, stop = [], [], threading.Event()

    def start(command, name, payload=None):
        log = open(root / (name + '.log'), 'wb')
        logs.append(log)
        child = subprocess.Popen(command, env=env, stdin=subprocess.PIPE if payload else subprocess.DEVNULL, stdout=log, stderr=log)
        children.append(child)
        if payload:
            child.stdin.write(payload)
            child.stdin.close()
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

    def editor():
        return next((w for w in windows() if w['app_id'] == 'cellward-screenshot'), None)

    def wait_editor():
        window = wire.wait_for(editor)
        wire.wait_for(lambda: editor()['rect']['width'] >= 900)
        msg(f"[con_id={window['id']}]", 'focus')
        time.sleep(.2)
        return window

    def key(code):
        for down in (1, 0):
            wire.packet(vk, 6, 1, struct.pack('=III', int(time.monotonic() * 1000) & 0xffffffff, code, down))
            time.sleep(.03)

    def move(x, y):
        pointer.write(f'move {x} {y}\n')
        time.sleep(.1)

    def click(x, y):
        move(x, y)
        pointer.write('press\nrelease\n')
        time.sleep(.2)

    def button(mode):
        node = next(w for w in windows() if w['app_id'] == 'screenshot-target')
        rect = node['rect']
        from_right = {'window': 84, 'area': 60, 'hover': 36}[mode]
        click(rect['x'] + rect['width'] - 4 - from_right, rect['y'] + 14)

    def exact(sock, length):
        body = b''
        while len(body) < length:
            part = sock.recv(length - len(body))
            assert part, 'clipboard socket closed'
            body += part
        return body

    def query(sock, body):
        sock.sendall(struct.pack('<I', len(body)) + body)
        return exact(sock, struct.unpack('<I', exact(sock, 4))[0])

    def scoped(name):
        sock = socket.socket(socket.AF_UNIX)
        sock.settimeout(5)
        sock.connect(str(runtime / 'cellward-clipboard/control.sock'))
        body = b'L' + struct.pack('<H', len(name)) + name.encode()
        sock.sendall(struct.pack('<I', len(body)) + body)
        head, ancillary, _, _ = sock.recvmsg(4, socket.CMSG_SPACE(4))
        assert len(head) == 4 and exact(sock, struct.unpack('<I', head)[0]) == b'\0'
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                for fd in array.array('i', payload):
                    os.close(fd)
        return sock

    def snapshot():
        with scoped('screenshot-target') as sock:
            answer = query(sock, b'\1\0')
            assert answer[0] == 0
            if answer[1] == 0:
                return 0, None
            revision = struct.unpack_from('<Q', answer, 2)[0]
            mime = b'image/png'
            answer = query(sock, b'\3\0' + struct.pack('<QH', revision, len(mime)) + mime)
            assert answer[0] == 0
            length = struct.unpack_from('<I', answer, 1)[0]
            return revision, answer[5:5 + length]

    worker = threading.Thread(target=units)
    worker.start()
    try:
        config = root / 'sway.conf'
        config.write_text('output * mode 1000x800\nseat seat0 fallback true\ndefault_border none\n')
        start([args.sway, '--unsupported-gpu', '-c', str(config)], 'sway')
        env['WAYLAND_DISPLAY'] = wire.wait_for(lambda: next((p.name for p in runtime.glob('wayland-*') if not p.name.endswith('.lock')), None))
        env['SWAYSOCK'] = str(wire.wait_for(lambda: next(runtime.glob('sway-ipc*.sock'), None)))
        vk = wire.keyboard(env, args.xkbcommon)
        fifo = root / 'pointer.fifo'
        start([sys.executable, str(tests / 'vm-pointer.py'), str(fifo), '1000', '800'], 'pointer')
        wire.wait_for(fifo.exists)
        pointer = open(fifo, 'w', buffering=1)
        logs.append(pointer)
        start([args.broker, 'broker'], 'broker')
        wire.wait_for(lambda: (runtime / 'cellward-clipboard/control.sock').exists())
        sentinel = b'synthetic desktop clipboard must survive screenshots'
        start([args.wl_copy, '--foreground', '--type', 'text/plain'], 'desktop-owner', sentinel)
        start([sys.executable, str(tests / 'clipboard-reverse-smoke.py'), 'reader', str(root / 'desktop.json'), 'yes'], 'desktop-reader')
        wire.wait_for(lambda: (root / 'desktop.json').exists())
        before_host = json.loads((root / 'desktop.json').read_text())
        holder = start(['sleep', '180'], 'holder')
        stamp = Path(f'/proc/{holder.pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        control, mouse = root / 'redraw', root / 'mouse.bin'
        source = start([args.core, 'wl-sandbox', 'screenshot-target', '--clipboard-scope', 'screenshot-target', f'{holder.pid}:{stamp} {boot}',
               '--frame', 'ff00ff:4:always', '--frame-title', 'Synthetic screenshot target', '--',
               sys.executable, __file__, 'app', str(control), str(mouse)], 'target')
        node = wire.wait_for(lambda: next((w for w in windows() if w['app_id'] == 'screenshot-target'), None))
        wire.wait_for(mouse.exists)
        time.sleep(.4)
        button('window')
        wait_editor()
        assert snapshot() == (0, None), 'window screenshot bypassed trusted preview'
        key(1)
        wire.wait_for(lambda: not editor())
        assert snapshot() == (0, None), 'Escape changed private clipboard'
        button('window')
        wait_editor()
        time.sleep(1.8)
        key(28)
        wire.wait_for(lambda: snapshot()[1] is not None)
        assert decode_png(snapshot()[1])[:2] == (1000, 800), 'window image has wrong geometry'
        wire.wait_for(lambda: not editor())
        previous = snapshot()[0]
        button('area')
        wait_editor()
        frozen = max(root.glob('frozen-*.png'), key=lambda p: p.stat().st_mtime_ns).read_bytes()
        control.touch()
        move(500, 400)
        pointer.write('wheel -5\n')
        time.sleep(.2)
        key(11)  # 0 restores fit without changing the frozen image.
        pointer.write('wheel -5\n')
        time.sleep(.2)
        pointer.write('press middle\n')
        move(580, 440)
        pointer.write('release middle\n')
        move(100, 120)
        pointer.write('press\n')
        move(900, 700)
        pointer.write('release\n')
        time.sleep(1.8)
        (root / 'selection-tree.json').write_text(msg('-t', 'get_tree'))
        subprocess.run([args.grim, str(root / 'selection.png')], env=env, check=True)
        key(28)
        wire.wait_for(lambda: not editor())
        revision, png = wire.wait_for(lambda: value if (value := snapshot())[0] != previous else None)
        assert 250 < decode_png(png)[0] < 650 and 150 < decode_png(png)[1] < 500, 'zoomed drag did not map to original pixels'
        assert is_crop(frozen, png), 'region was recaptured after the live image changed'
        (root / 'region.png').write_bytes(png)
        print('window preview/Escape preserve clipboard; region crops immutable pre-editor pixels', flush=True)
        control.unlink()
        # Restart the synthetic paint state without restarting its window.
        # The hover test only needs actual motion delivery and click isolation.
        motions = json.loads(mouse.read_text())['motions']
        button('hover')
        move(400, 400)
        wire.wait_for(lambda: json.loads(mouse.read_text())['motions'] > motions)
        baseline = json.loads(mouse.read_text())
        pointer.write('press\nrelease\n')
        wait_editor()
        frozen = max(root.glob('frozen-*.png'), key=lambda p: p.stat().st_mtime_ns).read_bytes()
        _, _, pixels = decode_png(frozen)
        assert any(pixels[i:i + 3] == bytes((10, 220, 230)) for i in range(0, len(pixels), 3)), 'hover tooltip disappeared before capture'
        assert any(pixels[i:i + 3] == bytes((180, 180, 180)) for i in range(0, len(pixels), 3)), 'shade remained in frozen pixels'
        after = json.loads(mouse.read_text())
        assert after['presses'] == baseline['presses'] and after['releases'] == baseline['releases'], 'freezing click reached application'
        assert snapshot()[0] == revision, 'hover screenshot bypassed confirmation'
        move(100, 120)
        pointer.write('press\n')
        move(900, 700)
        pointer.write('release\n')
        time.sleep(1.8)
        key(28)
        wire.wait_for(lambda: snapshot()[0] != revision)
        assert is_crop(frozen, snapshot()[1]), 'hover selection used a different frame'
        assert json.loads((root / 'desktop.json').read_text()) == before_host, 'screenshot leaked to desktop clipboard'
        print('hover forwards motion, swallows freezing press/release, copies only after confirmation; desktop untouched', flush=True)
        revision = snapshot()[0]
        wire.wait_for(lambda: not editor())
        button('area')
        wait_editor()
        source.terminate()
        source.wait(timeout=5)
        wire.wait_for(lambda: not editor(), timeout=5)
        assert snapshot()[0] == revision, 'closed source changed selection'
        print('source exit closes editor and preserves previous private selection', flush=True)
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
    if sys.argv[1:2] == ['app']:
        target(*sys.argv[2:])
    else:
        main()
