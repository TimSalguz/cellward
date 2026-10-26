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


def owner():
    sock = socket.socket(socket.AF_UNIX)
    sock.connect(str(Path(os.environ['XDG_RUNTIME_DIR']) / os.environ['WAYLAND_DISPLAY']))
    send = lambda obj, op, body=b'': wire.packet(sock, obj, op, body)
    send(1, 1, struct.pack('=I', 2))
    send(1, 0, struct.pack('=I', 3))
    names, buffered, fds = {}, b'', []
    while True:
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
                send(5, 0, struct.pack('=I', 7))
                for mime in ('text/plain', 'image/png'):
                    send(7, 0, wire.wl_string(mime))
                send(6, 1, struct.pack('=II', 7, 0))
                send(8, 1, struct.pack('=II', 9, 4))
                send(8, 0, struct.pack('=I', 10))
                for mime in ('text/plain', 'image/png'):
                    send(10, 0, wire.wl_string(mime))
                send(9, 0, struct.pack('=II', 10, 0))
            if obj in (7, 10) and op == (1 if obj == 7 else 0):
                length = struct.unpack_from('=I', body)[0]
                mime = body[4:4 + length - 1].decode()
                fd = fds.pop(0)
                try:
                    payload = {'text/plain': TEXT, 'image/png': PNG}[mime]
                    while payload:
                        payload = payload[os.write(fd, payload):]
                finally:
                    os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('core', 'broker', 'sway', 'wl-copy'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--without-history', action='store_true')
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix='cellward-private-clipboard-'))
    print('Artifacts:', root, flush=True)
    runtime = root / 'runtime'
    runtime.mkdir(mode=0o700)
    env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime), HOME=str(root),
               XDG_CONFIG_HOME=str(root / 'config'), XDG_STATE_HOME=str(root / 'state'),
               DBUS_SESSION_BUS_ADDRESS=f'unix:path={root}/no-bus',
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
    else:
        main()
