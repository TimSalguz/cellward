#!/usr/bin/env python3
"""Private compositor only: scope sharing, text/PNG, host and foreign isolation."""
import argparse
import array
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
import random
import zlib


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wire = load('typing_smoke', 'typing-smoke.py')
reverse = load('reverse_smoke', 'clipboard-reverse-smoke.py')
TEXT = b'synthetic private clipboard large text\n' * 8192
pixels = random.Random(7).randbytes(256 * 256 * 3)
PNG = (b'\x89PNG\r\n\x1a\n'
       + reverse.fixtures.png_chunk(b'IHDR', struct.pack('>IIBBBBB', 256, 256, 8, 2, 0, 0, 0))
       + reverse.fixtures.png_chunk(b'IDAT', zlib.compress(b''.join(
           b'\0' + pixels[row * 768:(row + 1) * 768] for row in range(256))))
       + reverse.fixtures.png_chunk(b'IEND', b''))


def owner(control=None):
    sock = socket.socket(socket.AF_UNIX)
    sock.connect(str(Path(os.environ['XDG_RUNTIME_DIR']) / os.environ['WAYLAND_DISPLAY']))
    send = lambda obj, op, body=b'': wire.packet(sock, obj, op, body)
    send(1, 1, struct.pack('=I', 2))
    send(1, 0, struct.pack('=I', 3))
    names, buffered, fds = {}, b'', []
    initialized, epoch, next_source = False, None, 20
    sources, stalled = {}, []

    def command():
        nonlocal epoch, next_source
        if not initialized or control is None:
            return
        try:
            spec = json.loads(Path(control).read_text())
        except (FileNotFoundError, ValueError):
            return
        if spec['epoch'] == epoch:
            return
        epoch = spec['epoch']
        # An existing proxy sees repeated copies, not a fresh launch per test.
        source = next_source
        next_source += 1
        primary = spec.get('primary', False)
        send(8 if primary else 5, 0, struct.pack('=I', source))
        sources[source] = spec
        for mime in spec['types']:
            send(source, 0, wire.wl_string(mime))
        send(9 if primary else 6, 0 if primary else 1, struct.pack('=II', source, 0))

    while True:
        command()
        if not select.select([sock], [], [], .05)[0]:
            continue
        data, ancillary, flags, _ = sock.recvmsg(65536, socket.CMSG_SPACE(64 * 4))
        if not data:
            return
        assert not flags & socket.MSG_CTRUNC
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                received = array.array('i')
                received.frombytes(payload)
                fds.extend(received)
        buffered += data
        while len(buffered) >= 8:
            obj, word = struct.unpack_from('=II', buffered)
            size, op = word >> 16, word & 65535
            if len(buffered) < size:
                break
            body, buffered = buffered[8:size], buffered[size:]
            if obj == 1 and op == 0:
                raise AssertionError('Wayland error: ' + repr(body))
            if obj == 2 and op == 0:
                name, length = struct.unpack_from('=II', body)
                names[body[8:8 + length - 1].decode()] = name
            if obj == 3 and op == 0:
                for interface, ident, version in [('wl_seat', 4, 1), ('wl_data_device_manager', 5, 3),
                                                   ('zwp_primary_selection_device_manager_v1', 8, 1)]:
                    send(2, 0, struct.pack('=I', names[interface]) + wire.wl_string(interface) + struct.pack('=II', version, ident))
                send(5, 1, struct.pack('=II', 6, 4))
                send(8, 1, struct.pack('=II', 9, 4))
                initialized = True
                if control is None:
                    for manager, device, source, primary in [(5, 6, 7, False), (8, 9, 10, True)]:
                        send(manager, 0, struct.pack('=I', source))
                        sources[source] = {'types': {'text/plain': 'large', 'image/png': 'png'}}
                        for mime in sources[source]['types']:
                            send(source, 0, wire.wl_string(mime))
                        send(device, 0 if primary else 1, struct.pack('=II', source, 0))
            if obj in sources and op == (0 if sources[obj].get('primary', obj == 10) else 1):
                length = struct.unpack_from('=I', body)[0]
                mime = body[4:4 + length - 1].decode()
                fd = fds.pop(0)
                spec = sources[obj]
                kind = spec['types'][mime]
                payload = (TEXT if kind == 'large' else PNG if kind == 'png'
                           else b'unfinished prefix' if kind == 'stall'
                           else kind.encode())
                try:
                    while payload:
                        payload = payload[os.write(fd, payload):]
                    if kind == 'stall':
                        stalled.append(fd)
                        fd = None
                except BrokenPipeError:
                    pass
                finally:
                    if fd is not None:
                        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('core', 'broker', 'sway', 'wl-copy'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--without-history', action='store_true')
    parser.add_argument('--satellite')
    parser.add_argument('--x11')
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix='cellward-private-clipboard-'))
    print('Artifacts:', root, flush=True)
    runtime = root / 'runtime'
    runtime.mkdir(mode=0o700)
    env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime), HOME=str(root),
               XDG_CONFIG_HOME=str(root / 'config'), XDG_STATE_HOME=str(root / 'state'),
               DBUS_SESSION_BUS_ADDRESS=f'unix:path={root}/no-bus',
               CELLWARD_X11_CLIPBOARD_FALLBACK='1',
               WLR_BACKENDS='headless', WLR_RENDERER='pixman', WLR_LIBINPUT_NO_DEVICES='1',
               LP_NUM_THREADS='1', LIBGL_ALWAYS_SOFTWARE='1')
    for name in ('DISPLAY', 'WAYLAND_DISPLAY', 'WAYLAND_SOCKET', 'SWAYSOCK'):
        env.pop(name, None)
    children, logs = [], []

    def start(command, name, payload=None):
        log = open(root / (name + '.log'), 'wb')
        logs.append(log)
        child = subprocess.Popen(command, env=env, stdout=log, stderr=log,
                                 stdin=subprocess.PIPE if payload else subprocess.DEVNULL)
        children.append(child)
        if payload:
            child.stdin.write(payload)
            child.stdin.close()
        return child

    def status(name):
        try:
            return json.loads((root / name).read_text())
        except (FileNotFoundError, ValueError):
            return {'types': [], 'bodies': {}}

    def body(name, mime):
        return status(name)['bodies'].get(mime)

    def ask(request):
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(5)
            sock.connect(str(runtime / 'cellward-clip.sock'))
            sock.sendall(request.encode() + b'\n')
            answer = b''
            while part := sock.recv(65536):
                answer += part
            return answer.decode()

    def scope(instance, holder):
        stat = Path(f'/proc/{holder.pid}/stat').read_text()
        stamp = stat[stat.rfind(')') + 1:].split()[19]
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        return ['--clipboard-scope', instance, f'{holder.pid}:{stamp} {boot}']

    def reader(name, binding, primary=False):
        return start([args.core, 'wl-sandbox', name, *binding, '--', sys.executable,
                      str(Path(__file__).with_name('clipboard-reverse-smoke.py')), 'reader', str(root / name),
                      'no', 'yes' if primary else 'no'], name)

    try:
        config = root / 'sway.conf'
        config.write_text('output * mode 800x600\nseat seat0 fallback true\n')
        start([args.sway, '--unsupported-gpu', '-c', str(config)], 'sway')
        env['WAYLAND_DISPLAY'] = wire.wait_for(lambda: next((p.name for p in runtime.glob('wayland-*') if not p.name.endswith('.lock')), None))
        broker = start([args.broker, 'broker'], 'broker')
        wire.wait_for(lambda: (runtime / 'cellward-clipboard/control.sock').exists())
        if not args.without_history:
            start([args.broker, 'daemon'], 'history')
            wire.wait_for(lambda: (runtime / 'cellward-clip.sock').exists())
        holder = start(['sleep', '120'], 'holder')
        foreign_holder = start(['sleep', '120'], 'foreign-holder')
        binding = scope('synthetic-main', holder)
        start([sys.executable, str(Path(__file__).with_name('clipboard-reverse-smoke.py')),
               'reader', str(root / 'host.json'), 'yes'], 'host-reader')
        sentinel = b'private compositor host sentinel'
        start([args.wl_copy, '--foreground', '--type', 'text/plain'], 'host-owner', sentinel)
        wire.wait_for(lambda: body('host.json', 'text/plain') == reverse.digest(sentinel))
        reader('same.json', binding)
        reader('primary.json', binding, primary=True)
        reader('other.json', scope('synthetic-other', foreign_holder))
        reader('other-primary.json', scope('synthetic-other', foreign_holder), primary=True)
        source = start([args.core, 'wl-sandbox', 'owner', *binding, '--', sys.executable,
                        __file__, 'owner'], 'owner')
        for mime, payload in [('text/plain', TEXT), ('image/png', PNG)]:
            wire.wait_for(lambda: body('same.json', mime) == reverse.digest(payload))
            wire.wait_for(lambda: body('primary.json', mime) == reverse.digest(payload))
        reader('late.json', binding)
        for mime, payload in [('text/plain', TEXT), ('image/png', PNG)]:
            wire.wait_for(lambda: body('late.json', mime) == reverse.digest(payload))
        time.sleep(.3)
        assert status('other.json')['types'] == [], 'foreign instance saw an offer'
        assert status('other-primary.json')['types'] == [], 'foreign instance saw PRIMARY'
        assert body('host.json', 'text/plain') == reverse.digest(sentinel), 'host clipboard changed'
        assert source.poll() is None, 'private source exited'
        if args.satellite:
            assert args.x11, '--satellite requires --x11'
            number = next(n for n in range(490, 590) if not Path(f'/tmp/.X11-unix/X{n}').exists()
                          and not Path(f'/tmp/.X{n}-lock').exists())
            start([args.core, 'wl-sandbox', 'private-satellite', *binding, '--',
                   args.satellite, f':{number}'], 'satellite')
            wire.wait_for(lambda: Path(f'/tmp/.X11-unix/X{number}').exists())
            for selection in ('CLIPBOARD', 'PRIMARY'):
                output = root / f'x11-{selection}.json'
                start([sys.executable, str(Path(__file__).with_name('x11-selection-reader.py')),
                       f':{number}', args.x11, str(output), selection], f'x11-reader-{selection}')
                for mime, payload in [('text/plain', TEXT), ('image/png', PNG)]:
                    wire.wait_for(lambda: status(output.name).get(mime) == reverse.digest(payload))
            assert body('host.json', 'text/plain') == reverse.digest(sentinel)
            assert status('other.json')['types'] == []
            print('PASS: native text/PNG reach windowless X11 CLIPBOARD and PRIMARY readers, including INCR', flush=True)
        # History reads the broker directly; explicit manager copy transfers
        # an entry to a selected container without touching the host.
        if not args.without_history:
            recorded = wire.wait_for(lambda: ask('list\tmain\t20') or None)
            entry = recorded.splitlines()[0].split('\t')[0]
            assert entry.isdigit(), recorded
            assert ask(f'copy-to\tmain\t{entry}\tsynthetic-other') == 'ok\n'
            for mime, payload in [('text/plain', TEXT), ('image/png', PNG)]:
                wire.wait_for(lambda: body('other.json', mime) == reverse.digest(payload))
            assert body('host.json', 'text/plain') == reverse.digest(sentinel)
            assert ask(f'copy-to\tmain\t{entry}\tmissing-instance').startswith('error\t')
        else:
            assert not (root / '.local/state/vpn-zones/.clipboard').exists(), 'active broker created disk history'
        # A single long-lived proxy must survive Firefox/GTK-style partial
        # offers, recover on subsequent copies and preserve history policy.
        control = root / 'fault-command.json'
        faulty = start([args.core, 'wl-sandbox', 'fault-owner', *binding, '--',
                        sys.executable, __file__, 'fault-owner', str(control)], 'fault-owner')
        epoch = 0

        def copy_fault(types, primary=False):
            nonlocal epoch
            epoch += 1
            control.write_text(json.dumps({'epoch': epoch, 'types': types, 'primary': primary}))

        def history_count():
            return len(ask('list\tmain\t100').splitlines())

        copy_fault({'TEXT': 'stall', 'text/plain': 'copy with stalled TEXT', 'image/png': 'png'})
        wire.wait_for(lambda: body('same.json', 'text/plain') == reverse.digest(b'copy with stalled TEXT'))
        assert 'TEXT' not in status('same.json')['types'], 'incomplete alias was published'
        wire.wait_for(lambda: body('same.json', 'image/png') == reverse.digest(PNG))
        if not args.without_history:
            wire.wait_for(lambda: 'copy with stalled TEXT' in ask('list\tmain\t100'))
        copy_fault({'text/plain;charset=utf-8': 'stall', 'text/plain': 'plain fallback'})
        wire.wait_for(lambda: body('same.json', 'text/plain') == reverse.digest(b'plain fallback'))
        assert 'text/plain;charset=utf-8' not in status('same.json')['types']
        if not args.without_history:
            wire.wait_for(lambda: 'plain fallback' in ask('list\tmain\t100'))
        copy_fault({'text/plain': 'valid MIME fallback', 'application/x-invalid\n': 'must not be read'})
        wire.wait_for(lambda: body('same.json', 'text/plain') == reverse.digest(b'valid MIME fallback'))
        if not args.without_history:
            wire.wait_for(lambda: 'valid MIME fallback' in ask('list\tmain\t100'))
        # A completely failed copy must not replace a good active selection.
        copy_fault({'text/plain': 'stall'})
        time.sleep(1.5)
        assert body('same.json', 'text/plain') == reverse.digest(b'valid MIME fallback')
        for hint in ('x-kde-passwordManagerHint', 'application/x-cellward-restored'):
            before = history_count() if not args.without_history else 0
            text = 'synthetic confidential ' + hint
            copy_fault({'text/plain': text, hint: 'stall'})
            wire.wait_for(lambda: body('same.json', 'text/plain') == reverse.digest(text.encode()))
            assert hint in status('same.json')['types'], 'failed policy hint was lost'
            if not args.without_history:
                time.sleep(.4)
                assert history_count() == before, 'secret/restored copy entered history'
        # A slow PRIMARY source cannot hold up an explicit CLIPBOARD copy.
        copy_fault({'text/plain': 'stall'}, primary=True)
        time.sleep(.2)
        copy_fault({'text/plain': 'recovered copy'})
        wire.wait_for(lambda: body('same.json', 'text/plain') == reverse.digest(b'recovered copy'), timeout=.7)
        assert faulty.poll() is None, 'faults terminated the proxy/source'
        if not args.without_history:
            wire.wait_for(lambda: 'recovered copy' in ask('list\tmain\t100'))
        # Preserve the original assertions below after restoring both channels.
        copy_fault({'text/plain': 'large', 'image/png': 'png'}, primary=True)
        wire.wait_for(lambda: body('primary.json', 'text/plain') == reverse.digest(TEXT))
        copy_fault({'text/plain': 'large', 'image/png': 'png'})
        wire.wait_for(lambda: body('same.json', 'text/plain') == reverse.digest(TEXT))
        assert body('host.json', 'text/plain') == reverse.digest(sentinel)
        print('PASS: stalled aliases/preferred MIME, failed-copy recovery, independent PRIMARY, secret/restored hints and history', flush=True)
        # A host update must not become an implicit import, even on a paste key.
        replacement = b'host replacement must stay outside'
        start([args.wl_copy, '--foreground', '--type', 'text/plain'], 'host-update', replacement)
        wire.wait_for(lambda: body('host.json', 'text/plain') == reverse.digest(replacement))
        time.sleep(.3)
        assert body('same.json', 'text/plain') == reverse.digest(TEXT)
        holder.terminate()
        holder.wait(timeout=3)
        wire.wait_for(lambda: status('same.json')['types'] == [])
        wire.wait_for(lambda: status('primary.json')['types'] == [])
        assert body('host.json', 'text/plain') == reverse.digest(replacement)
        # Existing proxies must stay closed after the controller disappears.
        broker.terminate()
        broker.wait(timeout=3)
        wire.wait_for(lambda: status('other.json')['types'] == [])
        time.sleep(.2)
        assert status('other.json')['types'] == []
        assert status('other-primary.json')['types'] == []
        marker = root / 'must-not-start'
        refused = start([args.core, 'wl-sandbox', 'broker-down', *scope('synthetic-other', foreign_holder),
                         '--', sys.executable, '-c',
                         'from pathlib import Path; Path(' + repr(str(marker)) + ').touch()'], 'broker-down')
        assert refused.wait(timeout=5) != 0, 'broker failure fell back to an unrestricted launch'
        assert not marker.exists(), 'program ran without a private clipboard'
        print('PASS: CLIPBOARD/PRIMARY text/PNG shared across launches; host/foreign isolated; owner exit and broker failure closed', flush=True)
    finally:
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
    if sys.argv[1:] == ['owner']:
        owner()
    elif sys.argv[1:2] == ['fault-owner']:
        owner(sys.argv[2])
    else:
        main()
