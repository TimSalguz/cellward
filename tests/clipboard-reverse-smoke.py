#!/usr/bin/env python3
"""Windowless X11 copy -> native Wayland, on a private headless compositor.

All data is synthetic. Never connect to the desktop's display/clipboard.
Children deliberately inherit one process group, for run-memory-guard.py.
"""
import ctypes as c
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wire = load('typing_smoke', 'typing-smoke.py')
fixtures = load('bridge_smoke', 'clipboard-bridge-smoke.py')


def digest(body):
    return {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}


def payload(epoch):
    return f'synthetic X11 clipboard {epoch}'.encode(), fixtures.png((epoch, 64, 96))


def owner(display, library, control):
    """Tiny X11 selection owner; its window is NEVER mapped or focused."""
    x, P, L = c.CDLL(library), c.c_void_p, c.c_ulong
    class Request(c.Structure):
        _fields_ = [('type', c.c_int), ('serial', L), ('send_event', c.c_int),
                    ('display', P), ('owner', L), ('requestor', L),
                    ('selection', L), ('target', L), ('property', L), ('time', L)]
    class Notify(c.Structure):
        _fields_ = [('type', c.c_int), ('serial', L), ('send_event', c.c_int),
                    ('display', P), ('requestor', L), ('selection', L),
                    ('target', L), ('property', L), ('time', L)]
    for name, args, result in [
        ('XOpenDisplay', [c.c_char_p], P), ('XDefaultRootWindow', [P], L),
        ('XCreateSimpleWindow', [P, L, c.c_int, c.c_int, c.c_uint, c.c_uint, c.c_uint, L, L], L),
        ('XInternAtom', [P, c.c_char_p, c.c_int], L), ('XFlush', [P], c.c_int),
        ('XSetSelectionOwner', [P, L, L, L], c.c_int),
        ('XPending', [P], c.c_int), ('XNextEvent', [P, P], c.c_int),
        ('XChangeProperty', [P, L, L, L, c.c_int, c.c_int, P, c.c_int], c.c_int),
        ('XSendEvent', [P, L, c.c_int, L, P], c.c_int),
    ]:
        f = getattr(x, name)
        f.argtypes, f.restype = args, result
    display = x.XOpenDisplay(display.encode())
    assert display, 'private X11 server unavailable'
    atom = lambda text: x.XInternAtom(display, text.encode(), 0)
    clipboard, targets = atom('PRIMARY' if os.environ.get('CELLWARD_TEST_PRIMARY') == '1' else 'CLIPBOARD'), atom('TARGETS')
    mimes = {atom('UTF8_STRING'): 'text', atom('text/plain'): 'text',
             atom('text/plain;charset=utf-8'): 'text', atom('image/png'): 'png'}
    epoch = None
    while True:
        requested = json.loads(Path(control).read_text())['epoch']
        if requested != epoch:
            epoch = requested
            window = x.XCreateSimpleWindow(display, x.XDefaultRootWindow(display), 0, 0, 1, 1, 0, 0, 0)
            x.XSetSelectionOwner(display, clipboard, window if epoch else 0, 0)
            x.XFlush(display)
        while x.XPending(display):
            event = (c.c_long * 24)()
            x.XNextEvent(display, c.byref(event))
            if c.cast(event, c.POINTER(c.c_int))[0] != 30:
                continue
            request = Request.from_buffer(event)
            prop = request.property or request.target
            success = False
            if request.target == targets:
                values = (L * (len(mimes) + 1))(targets, *mimes)
                x.XChangeProperty(display, request.requestor, prop, atom('ATOM'), 32, 0, values, len(values))
                success = True
            elif request.target in mimes and epoch:
                text, png = payload(epoch)
                body = png if mimes[request.target] == 'png' else text
                data = c.create_string_buffer(body)
                x.XChangeProperty(display, request.requestor, prop, request.target, 8, 0, data, len(body))
                success = True
            response = (c.c_long * 24)()
            notify = Notify.from_buffer(response)
            notify.type, notify.display, notify.requestor = 31, display, request.requestor
            notify.selection, notify.target, notify.time = request.selection, request.target, request.time
            notify.property = prop if success else 0
            x.XSendEvent(display, request.requestor, 0, 0, c.byref(response))
            x.XFlush(display)
        time.sleep(.01)


def reader(output, control='no', primary='no'):
    """Ordinary wl_data_device, not data-control, and no visible surface."""
    control = control == 'yes'
    primary = primary == 'yes' or (not control and os.environ.get('CELLWARD_TEST_PRIMARY') == '1')
    sock = socket.socket(socket.AF_UNIX)
    sock.connect(str(Path(os.environ['XDG_RUNTIME_DIR']) / os.environ['WAYLAND_DISPLAY']))
    send = lambda obj, op, data=b'', fd=None: wire.packet(sock, obj, op, data, fd)
    send(1, 1, struct.pack('=I', 2))
    send(1, 0, struct.pack('=I', 3))
    names, offers, pending = {}, {}, {}
    buffered, current, result, bound, last = b'', None, {}, False, 0
    while True:
        readable, _, _ = select.select([sock, *pending], [], [], .05)
        if sock in readable:
            data = sock.recv(65536)
            if not data:
                return
            buffered += data
            while len(buffered) >= 8:
                obj, word = struct.unpack_from('=II', buffered)
                size, op = word >> 16, word & 65535
                assert size >= 8
                if len(buffered) < size:
                    break
                data, buffered = buffered[8:size], buffered[size:]
                if obj == 1 and op == 0:
                    raise AssertionError('Wayland protocol error: ' + repr(data))
                if obj == 2 and op == 0:
                    name, length = struct.unpack_from('=II', data)
                    names[data[8:8 + length - 1].decode()] = name
                if obj == 3 and op == 0 and not bound:
                    manager = (('zwlr_data_control_manager_v1', 2 if primary else 1) if control else
                               ('zwp_primary_selection_device_manager_v1', 1) if primary else ('wl_data_device_manager', 3))
                    for interface, ident, version in [('wl_seat', 4, 1), (manager[0], 5, manager[1])]:
                        send(2, 0, struct.pack('=I', names[interface]) + wire.wl_string(interface) + struct.pack('=II', version, ident))
                    send(5, 1, struct.pack('=II', 6, 4))
                    bound = True
                    fixtures.report(output, {'types': [], 'bodies': {}})
                if obj == 6 and op == 0:
                    offers[struct.unpack('=I', data)[0]] = []
                if obj in offers and op == 0:
                    length = struct.unpack_from('=I', data)[0]
                    offers[obj].append(data[4:4 + length - 1].decode())
                if obj == 6 and op == (3 if control and primary else 1 if control or primary else 5):
                    old = current
                    current = struct.unpack('=I', data)[0] or None
                    result = {'types': offers.get(current, []), 'bodies': {}}
                    fixtures.report(output, result)
                    if old is not None and old != current:
                        send(old, 1 if control or primary else 2)
                        offers.pop(old, None)
        for fd in list(pending):
            ident, mime, body, started = pending[fd]
            if fd in readable:
                part = os.read(fd, 65536)
                if part:
                    pending[fd] = ident, mime, body + part, started
                    continue
            elif time.monotonic() - started < 2:
                continue
            os.close(fd)
            pending.pop(fd)
            if ident == current:
                result['bodies'][mime] = digest(body)
                fixtures.report(output, result)
        if current and not pending and time.monotonic() - last > .1:
            for mime in ('text/plain', 'image/png'):
                if mime in offers[current]:
                    read, write = os.pipe2(os.O_CLOEXEC)
                    send(current, 0 if control or primary else 1, wire.wl_string(mime), write)
                    os.close(write)
                    pending[read] = current, mime, b'', time.monotonic()
            last = time.monotonic()


def launch(satellite, display, foot, output):
    processes = [subprocess.Popen([satellite, display]),
                 subprocess.Popen([foot, '--app-id', 'reverse-native', 'sh', '-c', 'sleep 120']),
                 subprocess.Popen([sys.executable, __file__, 'reader', output])]
    try:
        late = False
        while True:
            assert all(p.poll() is None for p in processes), 'launch child exited'
            assert all(os.getpgid(p.pid) == os.getpgrp() for p in processes), 'child escaped memory guard'
            if not late and Path(output).with_name('late-go').exists():
                processes.append(subprocess.Popen([sys.executable, __file__, 'reader', str(Path(output).with_name('late.json'))]))
                late = True
            time.sleep(.05)
    finally:
        for p in processes:
            if p.poll() is None:
                p.terminate()
        for p in processes:
            p.wait()


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    for tool in ('core', 'satellite', 'sway', 'swaymsg', 'foot', 'x11', 'xkbcommon', 'wl-copy'):
        parser.add_argument('--' + tool, required=True)
    parser.add_argument('--unframed', action='store_true')
    parser.add_argument('--private-broker', help='exercise the instance-scoped controller instead of the legacy relay')
    parser.add_argument('--primary', action='store_true', help='test X11 PRIMARY with the private controller')
    args = parser.parse_args()
    if args.primary and not args.private_broker:
        parser.error('--primary requires --private-broker')
    root = Path(tempfile.mkdtemp(prefix='cellward-clipboard-reverse-'))
    print('Artifacts:', root, flush=True)
    runtime = root / 'runtime'
    runtime.mkdir(mode=0o700)
    env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime), HOME=str(root),
               XDG_CONFIG_HOME=str(root / 'config'), XDG_STATE_HOME=str(root / 'state'),
               WLR_BACKENDS='headless', WLR_RENDERER='pixman', WLR_LIBINPUT_NO_DEVICES='1',
               LP_NUM_THREADS='1', LIBGL_ALWAYS_SOFTWARE='1', CELLWARD_X11_CLIPBOARD_FALLBACK='1',
               DBUS_SESSION_BUS_ADDRESS=f'unix:path={root}/no-bus')
    if args.primary:
        env['CELLWARD_TEST_PRIMARY'] = '1'
    for name in ('DISPLAY', 'WAYLAND_DISPLAY', 'WAYLAND_SOCKET', 'SWAYSOCK'):
        env.pop(name, None)
    config = root / 'sway.conf'
    config.write_text('output * mode 800x600\nseat seat0 fallback true\ndefault_border none\n')
    children, logs = [], []
    def start(command, name, body=None):
        log = open(root / (name + '.log'), 'wb')
        logs.append(log)
        p = subprocess.Popen(command, env=env, stdout=log, stderr=log,
                             stdin=subprocess.PIPE if body is not None else None)
        children.append(p)
        assert os.getpgid(p.pid) == os.getpgrp()
        if body is not None:
            p.stdin.write(body)
            p.stdin.close()
        return p
    def status(name):
        try:
            return json.loads((root / name).read_text())
        except (FileNotFoundError, ValueError):
            return {'types': [], 'bodies': {}}
    def body(name, mime):
        return status(name)['bodies'].get(mime)
    def binding(instance):
        if not args.private_broker:
            return []
        stat = Path('/proc/self/stat').read_text()
        stamp = stat[stat.rfind(')') + 1:].split()[19]
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        return ['--clipboard-scope', instance, f'{os.getpid()}:{stamp} {boot}']
    try:
        start([args.sway, '--unsupported-gpu', '-c', str(config)], 'sway')
        env['WAYLAND_DISPLAY'] = wire.wait_for(lambda: next((p.name for p in runtime.glob('wayland-*') if not p.name.endswith('.lock')), None))
        env['SWAYSOCK'] = str(wire.wait_for(lambda: next(runtime.glob('sway-ipc*.sock'), None)))
        keyboard = wire.keyboard(env, args.xkbcommon)
        if args.private_broker:
            start([args.private_broker, 'broker'], 'broker')
            wire.wait_for(lambda: (runtime / 'cellward-clipboard/control.sock').exists())
        # Trusted observer of the PRIVATE compositor, never the real desktop.
        # Confined readers below use only the ordinary wl_data_device path.
        start([sys.executable, __file__, 'reader', str(root / 'host.json'), 'yes', 'yes' if args.primary else 'no'], 'host-reader')
        sentinel = b'synthetic private-compositor host sentinel'
        primary_args = ['--primary'] if args.primary else []
        start([args.wl_copy, *primary_args, '--foreground', '--type', 'text/plain'], 'host-owner', sentinel)
        wire.wait_for(lambda: body('host.json', 'text/plain') == digest(sentinel))
        number = next(n for n in range(490, 590) if not Path(f'/tmp/.X11-unix/X{n}').exists() and not Path(f'/tmp/.X{n}-lock').exists())
        frame = [] if args.unframed else ['--frame', 'ff00ff:1:always']
        start([args.core, 'wl-sandbox', 'reverse-main', *frame, *binding('reverse-main'), '--',
               sys.executable, __file__, 'launch', args.satellite, f':{number}', args.foot, str(root / 'local.json')], 'launch')
        wire.wait_for(lambda: Path(f'/tmp/.X11-unix/X{number}').exists())
        other = start([args.core, 'wl-sandbox', 'reverse-other', *binding('reverse-other'), '--', sys.executable, __file__, 'reader', str(root / 'other.json')], 'other-launch')
        wire.wait_for(lambda: (root / 'other.json').exists())
        def focused():
            tree = json.loads(subprocess.check_output([args.swaymsg, '-t', 'get_tree'], env=env))
            def walk(node):
                return ((node.get('focused') and node.get('app_id') == 'reverse-native')
                        or any(walk(n) for n in node.get('nodes', []) + node.get('floating_nodes', [])))
            return walk(tree)
        wire.wait_for(focused)
        control = root / 'owner-control.json'
        fixtures.report(control, {'epoch': 1})
        source = start([sys.executable, __file__, 'owner', f':{number}', args.x11, str(control)], 'x11-owner')
        for epoch in (1, 2, 3):
            fixtures.report(control, {'epoch': epoch})
            text, png = payload(epoch)
            wire.wait_for(lambda: body('local.json', 'text/plain') == digest(text))
            wire.wait_for(lambda: body('local.json', 'image/png') == digest(png))
            assert focused(), 'X11 unexpectedly received keyboard focus'
            assert body('host.json', 'text/plain') == digest(sentinel), 'X11 copy escaped to host'
            assert body('other.json', 'text/plain') != digest(text), 'X11 copy escaped to another launch'
            assert body('other.json', 'image/png') != digest(png)
            assert other.poll() is None, 'other launch observer died'
            if epoch == 2:
                (root / 'late-go').touch()
            if epoch >= 2:
                wire.wait_for(lambda: body('late.json', 'text/plain') == digest(text))
                wire.wait_for(lambda: body('late.json', 'image/png') == digest(png))
            print(f'epoch {epoch}: current text/PNG reach native reader; host/other launch unchanged', flush=True)
        fixtures.report(control, {'epoch': 0})
        if args.private_broker:
            # The eager broker owns accepted bytes independently of the X11
            # selection owner, as a clipboard manager does. Owner disappearance
            # must not erase a committed copy or reopen the host selection.
            time.sleep(.2)
            assert body('local.json', 'text/plain') == digest(payload(3)[0])
        else:
            wire.wait_for(lambda: all(v['bytes'] == 0 for v in status('local.json')['bodies'].values()))
        fixtures.report(control, {'epoch': 4})
        text, png = payload(4)
        wire.wait_for(lambda: body('local.json', 'text/plain') == digest(text))
        wire.wait_for(lambda: body('local.json', 'image/png') == digest(png))
        source.terminate()
        source.wait(timeout=3)
        if args.private_broker:
            time.sleep(.2)
            assert body('local.json', 'text/plain') == digest(text)
            assert body('local.json', 'image/png') == digest(png)
        else:
            wire.wait_for(lambda: all(v['bytes'] == 0 for v in status('local.json')['bodies'].values()))
        assert body('host.json', 'text/plain') == digest(sentinel)
        replacement = b'synthetic foreign replacement'
        start([args.wl_copy, *primary_args, '--foreground', '--type', 'text/plain'], 'host-replacement', replacement)
        wire.wait_for(lambda: body('host.json', 'text/plain') == digest(replacement))
        if args.private_broker:
            time.sleep(.3)
            assert body('local.json', 'text/plain') == digest(text), 'host selection replaced private scope'
            assert not status('other.json')['types'], 'host selection reached foreign scope'
            print(f'private X11 {"PRIMARY" if args.primary else "CLIPBOARD"}: text/PNG, late reader, owner exit; host selection never imported or replaced', flush=True)
            return
        wire.wait_for(lambda: 'text/plain' in status('local.json')['types'])
        time.sleep(2.2)
        assert body('local.json', 'text/plain')['bytes'] == 0, 'foreign background access bypassed paste gate'
        wire.packet(keyboard, 6, 2, struct.pack('=IIII', 4, 0, 0, 0))
        wire.packet(keyboard, 6, 1, struct.pack('=III', 1, 47, 1))
        time.sleep(.05)
        wire.packet(keyboard, 6, 1, struct.pack('=III', 2, 47, 0))
        wire.packet(keyboard, 6, 2, struct.pack('=IIII', 0, 0, 0, 0))
        wire.wait_for(lambda: body('local.json', 'text/plain') == digest(replacement))
        print('clear/source exit and foreign replacement: no stale bytes; paste gate restored', flush=True)
        keyboard.close()
    finally:
        for p in reversed(children):
            if p.poll() is None:
                p.terminate()
        for p in reversed(children):
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        for log in logs:
            log.close()


if __name__ == '__main__':
    if sys.argv[1:2] == ['owner']:
        owner(*sys.argv[2:])
    elif sys.argv[1:2] == ['reader']:
        reader(*sys.argv[2:])
    elif sys.argv[1:2] == ['launch']:
        launch(*sys.argv[2:])
    else:
        main()
