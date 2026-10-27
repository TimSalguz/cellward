#!/usr/bin/env python3
"""Generate synthetic, non-secret protocol seeds in a supplied directory."""
from pathlib import Path
import struct
import sys

root = Path(sys.argv[1])
for name in ('dbus', 'pulse', 'typing', 'wayland'):
    (root / name).mkdir(parents=True, exist_ok=True)

# D-Bus header fields are aligned structs (byte, variant).
def dbus(signature, body):
    fields = bytearray()
    for code, typ, value in [(1, 'o', '/org/freedesktop/portal/desktop'),
                             (2, 's', 'org.freedesktop.portal.OpenURI'),
                             (3, 's', 'OpenURI'), (8, 'g', signature)]:
        fields.extend(b'\0' * (-len(fields) % 8))
        fields.extend(bytes([code, 1]) + typ.encode() + b'\0')
        if typ == 'g':
            fields.extend(bytes([len(value)]) + value.encode() + b'\0')
        else:
            fields.extend(b'\0' * (-len(fields) % 4))
            fields.extend(struct.pack('<I', len(value)) + value.encode() + b'\0')
    header = b'l\x01\0\x01' + struct.pack('<III', len(body), 1, len(fields)) + fields
    return header + b'\0' * (-len(header) % 8) + body

body = bytearray()
for word in ('', 'https://example.invalid/'):
    body.extend(b'\0' * (-len(body) % 4))
    body.extend(struct.pack('<I', len(word)) + word.encode() + b'\0')
(root/'dbus'/'portal').write_bytes(dbus('ss', body))
(root/'dbus'/'empty').write_bytes(dbus('', b''))
(root/'dbus'/'bad-length').write_bytes(b'l\x01\0\x01' + b'\xff'*12)
for name, payload in [('integers', b'L'+struct.pack('>I', 1)+b'L'+struct.pack('>I', 2)),
                      ('string', b'texample.invalid\0'), ('bad-array', b'x\xff\xff\xff\xff')]:
    (root/'pulse'/name).write_bytes(struct.pack('>IIIII', len(payload), 0xffffffff, 0, 0, 0)+payload)
# Request encodings are produced by the target's round-trip exploration too.
(root/'typing'/'empty').write_bytes(b'')
(root/'typing'/'zeros').write_bytes(b'\0'*32)

prefix = b'\0cellward-type-1'
(root/'typing'/'select').write_bytes(prefix + b'\0' + struct.pack('<Q', 42))
(root/'typing'/'cancel').write_bytes(prefix + b'\2' + struct.pack('<Q', 42))
for name, flag, text in [('unicode', 0, 'hello ☕'), ('keycodes', 1, 'hello'), ('newline', 2, 'line1\nline2')]:
    (root/'typing'/name).write_bytes(prefix + b'\1' + struct.pack('<QHHHB', 42, 300, 30, 10, flag) + text.encode())

def wl(obj, opcode, body):
    return struct.pack('<II', obj, ((len(body)+8)<<16) | opcode) + body
registry = wl(1, 1, struct.pack('<I', 2))
(root/'wayland'/'registry').write_bytes(registry)
(root/'wayland'/'sync').write_bytes(wl(1, 0, struct.pack('<I', 3)))
interface = b'wl_compositor\0'
bind = struct.pack('<II', 1, len(interface)) + interface + b'\0'*(-len(interface)%4) + struct.pack('<II', 6, 3)
(root/'wayland'/'surface').write_bytes(registry + wl(2, 0, bind) + wl(3, 0, struct.pack('<I', 4)))
(root/'wayland'/'bad-length').write_bytes(struct.pack('<II', 1, 0xffff0000))
